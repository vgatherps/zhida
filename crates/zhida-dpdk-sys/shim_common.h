// Common macros and inline helpers for zhida shim
//
// DESIGN: Tail Call CFG Control
//
// 1. ALWAYS-INLINE HELPERS - do actual computation, no slow calls
// 2. TAIL-CALLABLE FUNCTIONS - manage CFG via MUSTTAIL, never call-and-return

#ifndef ZHIDA_SHIM_COMMON_H
#define ZHIDA_SHIM_COMMON_H

#include <rte_config.h>
#undef RTE_MBUF_REFCNT_ATOMIC // Non-atomic refcount for single-threaded

#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <stdio.h>
#include <stdlib.h>

//=============================================================================
// Macros
//=============================================================================

#if !defined(ZHIDA_ASSUME_CHECKED)
#define ASSUME(cond)                                                           \
  do {                                                                         \
    if (!(cond))                                                               \
      __builtin_unreachable();                                                 \
  } while (0)
#else
#define ASSUME(cond)                                                           \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "ASSUME failed: %s at %s:%d\n", #cond, __FILE__,         \
              __LINE__);                                                       \
      abort();                                                                 \
    }                                                                          \
  } while (0)
#endif

#if defined(__clang__)
#define MUSTTAIL [[clang::musttail]]
#else
#define MUSTTAIL
#endif

#define ZHIDA_PRIV_SIZE 8

//=============================================================================
// Refcount helpers
//=============================================================================

__attribute__((noreturn, cold, noinline)) static inline void
zhida_refcnt_overflow(void) {
  fprintf(stderr, "FATAL: mbuf refcnt overflow (would exceed UINT16_MAX)\n");
  abort();
}

// Increment refcnt. On overflow (wrap to 0), we abort unconditionally.
// The increment-then-check order means refcnt is briefly 0 before abort,
// but since we abort immediately this is fine - no code path continues.
__attribute__((always_inline)) static inline void
zhida_refcnt_inc(struct rte_mbuf *m) {
  ASSUME(m != NULL);
  m->refcnt += 1;
  if (__builtin_expect(m->refcnt == 0, 0)) {
    zhida_refcnt_overflow();
  }
}

// Returns true if was last ref (should free), false otherwise (decremented)
__attribute__((always_inline)) static inline bool
zhida_refcnt_dec_check(struct rte_mbuf *m) {
  ASSUME(m != NULL);
  uint16_t refcnt = m->refcnt;
  ASSUME(refcnt >= 1);
  refcnt -= 1;
  if (__builtin_expect(refcnt == 0, 1)) {
    return true;
  }
  m->refcnt = refcnt;
  return false;
}

//=============================================================================
// Cache helpers
//=============================================================================

// Get cache from priv_data (first 8 bytes after rte_mbuf struct)
__attribute__((always_inline)) static inline struct rte_mempool_cache *
zhida_cache_get_fast(struct rte_mbuf *m) {
  ASSUME(m != NULL);
  struct rte_mempool_cache *cache =
      *(struct rte_mempool_cache **)((char *)m + sizeof(struct rte_mbuf));
  ASSUME(cache != NULL);
  return cache;
}

// Try to put mbuf into cache. Returns true on success.
// Clears m->next only on success (flush path needs it).
__attribute__((always_inline)) static inline bool
zhida_cache_try_put(struct rte_mempool_cache *cache, struct rte_mbuf *m) {
  ASSUME(cache != NULL);
  ASSUME(m != NULL);
  ASSUME(cache->flushthresh > 0);
  if (__builtin_expect(cache->len < cache->flushthresh, 1)) {
    m->next = NULL;
    cache->objs[cache->len++] = m;
    return true;
  }
  return false;
}

// Flush cache and put mbuf. Cold path.
__attribute__((noinline)) static inline void
zhida_cache_flush_and_put(struct rte_mempool_cache *cache, struct rte_mbuf *m) {
  ASSUME(cache != NULL);
  ASSUME(m != NULL);
  ASSUME(m->pool != NULL);
  rte_mempool_ops_enqueue_bulk(m->pool, cache->objs, cache->len);
  m->next = NULL;
  cache->len = 1;
  cache->objs[0] = m;
}

// Pop from cache, returns NULL if empty
__attribute__((always_inline)) static inline struct rte_mbuf *
zhida_cache_pop(struct rte_mempool *mp, struct rte_mempool_cache *cache) {
  ASSUME(cache != NULL);
  if (__builtin_expect(cache->len > 0, 1)) {
    struct rte_mbuf *m = (struct rte_mbuf *)cache->objs[--cache->len];
    ASSUME(m != NULL);
    ASSUME(m->pool == mp);
    ASSUME(m->refcnt == 1);
    return m;
  }
  return NULL;
}

//=============================================================================
// Chain helpers
//=============================================================================

__attribute__((always_inline)) static inline struct rte_mbuf *
__lastseg_walk(struct rte_mbuf *m) {
  ASSUME(m != NULL);
  while (m->next != NULL)
    m = m->next;
  return m;
}

//=============================================================================
// Alloc helper (used by clone)
//=============================================================================

// Alloc without reset - for clone where attach sets all fields
__attribute__((always_inline)) static inline struct rte_mbuf *
zhida_pktmbuf_alloc_noreset(struct rte_mempool *mp,
                            struct rte_mempool_cache *cache) {
  ASSUME(mp != NULL);
  ASSUME(cache != NULL);
  struct rte_mbuf *m = zhida_cache_pop(mp, cache);
  if (__builtin_expect(m != NULL, 1))
    return m;
  // Slow path: refill from backend
  int ret = rte_mempool_ops_dequeue_bulk(mp, cache->objs, cache->size + 1);
  if (__builtin_expect(ret < 0, 0)) {
    ret = rte_mempool_ops_dequeue_bulk(mp, (void **)&m, 1);
    if (ret < 0)
      return NULL;
    ASSUME(m != NULL);
    ASSUME(m->pool == mp);
    ASSUME(m->refcnt == 1);
    return m;
  }
  cache->len = cache->size;
  m = (struct rte_mbuf *)cache->objs[cache->size];
  ASSUME(m != NULL);
  ASSUME(m->pool == mp);
  ASSUME(m->refcnt == 1);
  return m;
}

#endif // ZHIDA_SHIM_COMMON_H
