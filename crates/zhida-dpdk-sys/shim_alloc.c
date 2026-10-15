// Alloc operations and cache initialization

#include "shim_common.h"
#include <rte_errno.h>

//=============================================================================
// Cache pointer management
//=============================================================================

__attribute__((nonnull(1, 2))) void
zhida_set_cache_ptr(struct rte_mbuf *m, struct rte_mempool_cache *cache) {
  *(struct rte_mempool_cache **)((char *)m + sizeof(struct rte_mbuf)) = cache;
}

__attribute__((nonnull(1))) struct rte_mempool_cache *
zhida_get_pool_cache(struct rte_mempool *mp) {
  unsigned lcore_id = rte_lcore_id();
  if (lcore_id == LCORE_ID_ANY)
    return NULL;
  return rte_mempool_default_cache(mp, lcore_id);
}

unsigned zhida_lcore_id(void) { return rte_lcore_id(); }

int zhida_errno(void) { return rte_errno; }

void zhida_mempool_cache_flush(struct rte_mempool_cache *cache,
                               struct rte_mempool *mp) {
  rte_mempool_cache_flush(cache, mp);
}

__attribute__((nonnull(1))) const char *
zhida_mempool_ops_name(const struct rte_mempool *mp) {
  return rte_mempool_get_ops(mp->ops_index)->name;
}

static void zhida_set_cache_ptr_cb(struct rte_mempool *mp
                                   __attribute__((unused)),
                                   void *opaque, void *obj,
                                   unsigned idx __attribute__((unused))) {
  struct rte_mempool_cache *cache = (struct rte_mempool_cache *)opaque;
  struct rte_mbuf *m = (struct rte_mbuf *)obj;
  zhida_set_cache_ptr(m, cache);
}

__attribute__((nonnull(1, 2))) void
zhida_pool_init_cache_ptrs(struct rte_mempool *mp,
                           struct rte_mempool_cache *cache) {
  rte_mempool_obj_iter(mp, zhida_set_cache_ptr_cb, cache);
}

//=============================================================================
// Alloc with precomputed cache
//=============================================================================

static struct rte_mbuf *
zhida_pktmbuf_alloc_refill(struct rte_mempool *mp,
                           struct rte_mempool_cache *cache);

__attribute__((always_inline)) static inline void
zhida_pktmbuf_reset(struct rte_mbuf *m) {
  rte_pktmbuf_reset(m);
}

__attribute__((nonnull(1, 2), hot, aligned(16))) struct rte_mbuf *
zhida_pktmbuf_alloc_fast(struct rte_mempool *mp,
                         struct rte_mempool_cache *cache) {
  ASSUME(mp != NULL);
  ASSUME(cache != NULL);
  if (__builtin_expect(cache->len > 0, 1)) {
    struct rte_mbuf *m = (struct rte_mbuf *)cache->objs[--cache->len];
    ASSUME(m != NULL);
    ASSUME(m->pool == mp);
    zhida_pktmbuf_reset(m);
    return m;
  }
  MUSTTAIL return zhida_pktmbuf_alloc_refill(mp, cache);
}

__attribute__((noinline)) static struct rte_mbuf *
zhida_pktmbuf_alloc_refill(struct rte_mempool *mp,
                           struct rte_mempool_cache *cache) {
  int ret = rte_mempool_ops_dequeue_bulk(mp, cache->objs, cache->size + 1);
  if (__builtin_expect(ret < 0, 0)) {
    struct rte_mbuf *m;
    ret = rte_mempool_ops_dequeue_bulk(mp, (void **)&m, 1);
    if (ret < 0)
      return NULL;
    zhida_pktmbuf_reset(m);
    return m;
  }
  cache->len = cache->size;
  struct rte_mbuf *m = (struct rte_mbuf *)cache->objs[cache->size];
  zhida_pktmbuf_reset(m);
  return m;
}

//=============================================================================
// Header-segment prepend
//=============================================================================

// Fresh direct segment h from head's own pool (cache from head's priv slot, as
// free does), linked in front of head. h carries len bytes at the end of its
// buffer (data_off = buf_len - len), DPDK's header-copy metadata from head
// (__rte_pktmbuf_copy_hdr, ol_flags without INDIRECT/EXTERNAL, as
// rte_pktmbuf_copy), and the packet totals. No field of head's chain is written.
// Limits are checked before allocating, so refusal allocates nothing.
__attribute__((nonnull(1), cold)) struct rte_mbuf *
zhida_pktmbuf_prepend_seg(struct rte_mbuf *head, uint16_t len) {
  if ((uint32_t)head->nb_segs + 1 > RTE_MBUF_MAX_NB_SEGS)
    return NULL;
  if (len > rte_pktmbuf_data_room_size(head->pool))
    return NULL;

  struct rte_mbuf *h =
      zhida_pktmbuf_alloc_fast(head->pool, zhida_cache_get_fast(head));
  if (h == NULL)
    return NULL;

  __rte_pktmbuf_copy_hdr(h, head);
  h->ol_flags = head->ol_flags & ~(RTE_MBUF_F_INDIRECT | RTE_MBUF_F_EXTERNAL);
  h->data_off = h->buf_len - len;
  h->data_len = len;
  h->pkt_len = head->pkt_len + len;
  h->nb_segs = head->nb_segs + 1;
  h->next = head;
  return h;
}

// Compatibility wrapper
__attribute__((nonnull(1))) struct rte_mbuf *
zhida_pktmbuf_alloc(struct rte_mempool *mp) {
  return rte_pktmbuf_alloc(mp);
}
