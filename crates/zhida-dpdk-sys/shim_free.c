// Free operations - single-segment, chain-walking, indirect, minimal
//
// All paths use musttail for clean CFG. Functions tail-call each other
// so they must stay in the same compilation unit.

#include "shim_common.h"

//=============================================================================
// Forward declarations (musttail chain)
//=============================================================================

static void zhida_pktmbuf_free_direct_check(struct rte_mbuf *m);
static void zhida_pktmbuf_pool_put(struct rte_mbuf *m);
static void zhida_pktmbuf_pool_put_flush(struct rte_mbuf *m);
static void zhida_pktmbuf_free_slow(struct rte_mbuf *m);
static void zhida_pktmbuf_free_chain_slow(struct rte_mbuf *m);
static void zhida_pktmbuf_free_chain_flush(struct rte_mbuf *m);
static void zhida_pktmbuf_free_indirect_detach(struct rte_mbuf *m);
static void zhida_pktmbuf_free_indirect_put(struct rte_mbuf *m);
static void zhida_pktmbuf_free_indirect_flush(struct rte_mbuf *m);
static void zhida_pktmbuf_free_underlying_flush(struct rte_mbuf *md);
static void zhida_pktmbuf_free_minimal_flush(struct rte_mbuf *m);

//=============================================================================
// Single-segment free
//=============================================================================

__attribute__((nonnull(1))) void zhida_pktmbuf_free_seg(struct rte_mbuf *m) {
  if (zhida_refcnt_dec_check(m)) {
    MUSTTAIL return zhida_pktmbuf_free_direct_check(m);
  }
}

__attribute__((noinline)) static void
zhida_pktmbuf_free_direct_check(struct rte_mbuf *m) {
  if (__builtin_expect(RTE_MBUF_DIRECT(m), 1)) {
    MUSTTAIL return zhida_pktmbuf_pool_put(m);
  }
  MUSTTAIL return zhida_pktmbuf_free_slow(m);
}

__attribute__((noinline)) static void
zhida_pktmbuf_pool_put(struct rte_mbuf *m) {
  m->nb_segs = 1;
  struct rte_mempool_cache *cache = zhida_cache_get_fast(m);
  if (zhida_cache_try_put(cache, m)) {
    return;
  }
  MUSTTAIL return zhida_pktmbuf_pool_put_flush(m);
}

__attribute__((noinline)) static void
zhida_pktmbuf_pool_put_flush(struct rte_mbuf *m) {
  struct rte_mempool_cache *cache = zhida_cache_get_fast(m);
  zhida_cache_flush_and_put(cache, m);
}

__attribute__((noinline)) static void
zhida_pktmbuf_free_slow(struct rte_mbuf *m) {
  m = rte_pktmbuf_prefree_seg(m);
  if (m != NULL) {
    MUSTTAIL return zhida_pktmbuf_pool_put(m);
  }
}

//=============================================================================
// Chain-walking free
//=============================================================================

void zhida_pktmbuf_free(struct rte_mbuf *m) {
  if (m == NULL)
    return;
  struct rte_mbuf *next = m->next;

  if (!zhida_refcnt_dec_check(m)) {
    if (next != NULL) {
      MUSTTAIL return zhida_pktmbuf_free(next);
    }
    return;
  }

  if (__builtin_expect(!RTE_MBUF_DIRECT(m), 0)) {
    MUSTTAIL return zhida_pktmbuf_free_chain_slow(m);
  }

  m->nb_segs = 1;
  struct rte_mempool_cache *cache = zhida_cache_get_fast(m);

  if (zhida_cache_try_put(cache, m)) {
    if (next != NULL) {
      MUSTTAIL return zhida_pktmbuf_free(next);
    }
    return;
  }

  MUSTTAIL return zhida_pktmbuf_free_chain_flush(m);
}

__attribute__((noinline)) static void
zhida_pktmbuf_free_chain_flush(struct rte_mbuf *m) {
  struct rte_mbuf *next = m->next;
  struct rte_mempool_cache *cache = zhida_cache_get_fast(m);
  zhida_cache_flush_and_put(cache, m);

  if (next != NULL) {
    MUSTTAIL return zhida_pktmbuf_free(next);
  }
}

//=============================================================================
// Indirect mbuf free (part of chain-walking)
//=============================================================================

__attribute__((noinline, hot, nonnull(1), aligned(16))) static void
zhida_pktmbuf_free_chain_slow(struct rte_mbuf *m) {
  ASSUME(m != NULL);
  ASSUME(!RTE_MBUF_HAS_EXTBUF(m));
  ASSUME(!RTE_MBUF_DIRECT(m));

  struct rte_mbuf *md = rte_mbuf_from_indirect(m);
  ASSUME(md != NULL);
  ASSUME(md != m);

  uint16_t refcnt = md->refcnt;
  ASSUME(refcnt >= 1);

  if (refcnt > 1) {
    md->refcnt = refcnt - 1;
    MUSTTAIL return zhida_pktmbuf_free_indirect_detach(m);
  }

  ASSUME(RTE_MBUF_DIRECT(md));
  md->nb_segs = 1;
  struct rte_mempool_cache *md_cache = zhida_cache_get_fast(md);
  if (__builtin_expect(md_cache->len < md_cache->flushthresh, 1)) {
    md->next = NULL;
    md_cache->objs[md_cache->len++] = md;
    MUSTTAIL return zhida_pktmbuf_free_indirect_detach(m);
  }

  md->next = m;
  MUSTTAIL return zhida_pktmbuf_free_underlying_flush(md);
}

__attribute__((noinline)) static void
zhida_pktmbuf_free_underlying_flush(struct rte_mbuf *md) {
  struct rte_mbuf *m = md->next;
  struct rte_mempool_cache *cache = zhida_cache_get_fast(md);
  zhida_cache_flush_and_put(cache, md);
  MUSTTAIL return zhida_pktmbuf_free_indirect_detach(m);
}

__attribute__((noinline)) static void
zhida_pktmbuf_free_indirect_detach(struct rte_mbuf *m) {
  m->buf_addr = (char *)m + sizeof(struct rte_mbuf) + ZHIDA_PRIV_SIZE;
  m->buf_iova =
      rte_mempool_virt2iova(m) + sizeof(struct rte_mbuf) + ZHIDA_PRIV_SIZE;
  m->buf_len = m->pool->elt_size - sizeof(struct rte_mbuf) - ZHIDA_PRIV_SIZE;
  m->ol_flags = 0;
  m->nb_segs = 1;

  MUSTTAIL return zhida_pktmbuf_free_indirect_put(m);
}

__attribute__((noinline)) static void
zhida_pktmbuf_free_indirect_put(struct rte_mbuf *m) {
  struct rte_mbuf *next = m->next;
  struct rte_mempool_cache *cache = zhida_cache_get_fast(m);

  if (__builtin_expect(cache->len < cache->flushthresh, 1)) {
    m->next = NULL;
    cache->objs[cache->len++] = m;
    if (next != NULL) {
      MUSTTAIL return zhida_pktmbuf_free(next);
    }
    return;
  }

  MUSTTAIL return zhida_pktmbuf_free_indirect_flush(m);
}

__attribute__((noinline)) static void
zhida_pktmbuf_free_indirect_flush(struct rte_mbuf *m) {
  struct rte_mbuf *next = m->next;
  struct rte_mempool_cache *cache = zhida_cache_get_fast(m);
  zhida_cache_flush_and_put(cache, m);

  if (next != NULL) {
    MUSTTAIL return zhida_pktmbuf_free(next);
  }
}

//=============================================================================
// Minimal free (skips refcount/chain/indirect checks)
//=============================================================================

__attribute__((nonnull(1))) void
zhida_pktmbuf_free_minimal(struct rte_mbuf *m) {
  ASSUME(m != NULL);
  ASSUME(m->refcnt == 1);
  ASSUME(m->nb_segs == 1);
  ASSUME(m->next == NULL);
  ASSUME(RTE_MBUF_DIRECT(m));
  ASSUME(!RTE_MBUF_HAS_EXTBUF(m));
  struct rte_mempool_cache *cache = zhida_cache_get_fast(m);
  if (zhida_cache_try_put(cache, m)) {
    return;
  }
  MUSTTAIL return zhida_pktmbuf_free_minimal_flush(m);
}

__attribute__((noinline)) static void
zhida_pktmbuf_free_minimal_flush(struct rte_mbuf *m) {
  struct rte_mempool_cache *cache = zhida_cache_get_fast(m);
  zhida_cache_flush_and_put(cache, m);
}
