// Clone and attach operations

#include "shim_common.h"

//=============================================================================
// Attach helpers
//=============================================================================

__attribute__((nonnull(1, 2))) void zhida_pktmbuf_attach(struct rte_mbuf *mi,
                                                         struct rte_mbuf *md) {
  rte_pktmbuf_attach(mi, md);
}

// DPDK's field copy pattern + overflow check. Returns underlying direct mbuf.
__attribute__((always_inline)) static inline struct rte_mbuf *
zhida_pktmbuf_attach_fast(struct rte_mbuf *__restrict mi,
                          struct rte_mbuf *__restrict md) {
  ASSUME(mi != md);
  ASSUME(!RTE_MBUF_HAS_EXTBUF(md));

  struct rte_mbuf *m_direct = rte_mbuf_from_indirect(md);
  zhida_refcnt_inc(m_direct);

  mi->priv_size = md->priv_size;
  mi->ol_flags = md->ol_flags | RTE_MBUF_F_INDIRECT;

  mi->port = md->port;
  mi->vlan_tci = md->vlan_tci;
  mi->vlan_tci_outer = md->vlan_tci_outer;
  mi->tx_offload = md->tx_offload;
  mi->hash = md->hash;
  mi->packet_type = md->packet_type;

  mi->data_off = md->data_off;
  mi->data_len = md->data_len;
  mi->buf_iova = md->buf_iova;
  mi->buf_addr = md->buf_addr;
  mi->buf_len = md->buf_len;

  mi->next = NULL;
  mi->pkt_len = mi->data_len;
  mi->nb_segs = 1;

  return m_direct;
}

// Attach variant that skips next/pkt_len/nb_segs (caller sets them)
__attribute__((always_inline)) static inline void
zhida_pktmbuf_attach_for_clone(struct rte_mbuf *__restrict mi,
                               struct rte_mbuf *__restrict md) {
  ASSUME(mi != md);
  ASSUME(!RTE_MBUF_HAS_EXTBUF(md));

  struct rte_mbuf *m_direct = rte_mbuf_from_indirect(md);
  zhida_refcnt_inc(m_direct);

  mi->priv_size = md->priv_size;
  mi->ol_flags = md->ol_flags | RTE_MBUF_F_INDIRECT;

  mi->port = md->port;
  mi->vlan_tci = md->vlan_tci;
  mi->vlan_tci_outer = md->vlan_tci_outer;
  mi->tx_offload = md->tx_offload;
  mi->hash = md->hash;
  mi->packet_type = md->packet_type;

  mi->data_off = md->data_off;
  mi->data_len = md->data_len;
  mi->buf_iova = md->buf_iova;
  mi->buf_addr = md->buf_addr;
  mi->buf_len = md->buf_len;
}

//=============================================================================
// Clone chain with indirect mbufs (DPDK loop pattern)
//=============================================================================

// Forward declaration for free on failure
extern void zhida_pktmbuf_free(struct rte_mbuf *m);

__attribute__((nonnull(1, 2, 3))) struct rte_mbuf *
zhida_pktmbuf_clone(struct rte_mbuf *md, struct rte_mempool *mp,
                    struct rte_mempool_cache *cache) {
  struct rte_mbuf *mc, *mi, **prev;
  uint32_t pktlen;
  uint16_t nseg;

  ASSUME(md != NULL);
  ASSUME(mp != NULL);
  ASSUME(cache != NULL);

  mc = zhida_pktmbuf_alloc_noreset(mp, cache);
  if (__builtin_expect(mc == NULL, 0))
    return NULL;

  mi = mc;
  prev = &mi->next;
  pktlen = md->pkt_len;
  nseg = 0;

  do {
    nseg++;
    zhida_pktmbuf_attach_fast(mi, md);
    *prev = mi;
    prev = &mi->next;
  } while ((md = md->next) != NULL &&
           (mi = zhida_pktmbuf_alloc_noreset(mp, cache)) != NULL);

  *prev = NULL;
  mc->nb_segs = nseg;
  mc->pkt_len = pktlen;

  if (__builtin_expect(md != NULL, 0)) {
    zhida_pktmbuf_free(mc);
    return NULL;
  }

  return mc;
}

//=============================================================================
// into_indirect_head: consume chain, return new chain with indirect head
//=============================================================================

__attribute__((always_inline)) static inline struct rte_mbuf *
zhida_pktmbuf_into_indirect_head_finish(struct rte_mbuf *indirect,
                                        struct rte_mbuf *m) {
  ASSUME(indirect != m);

  struct rte_mbuf *tail_chain = m->next;
  uint16_t nb_segs = m->nb_segs;
  uint32_t pkt_len = m->pkt_len;

  struct rte_mbuf *m_direct = zhida_pktmbuf_attach_fast(indirect, m);
  ASSUME(m_direct != NULL);
  ASSUME(m_direct->refcnt >= 2);

  indirect->next = tail_chain;
  indirect->nb_segs = nb_segs;
  indirect->pkt_len = pkt_len;

  m->next = NULL;
  m->nb_segs = 1;

  m_direct->refcnt--;

  return indirect;
}

__attribute__((nonnull(1, 2, 3))) struct rte_mbuf *
zhida_pktmbuf_into_indirect_head(struct rte_mbuf *m, struct rte_mempool *mp,
                                 struct rte_mempool_cache *cache) {
  ASSUME(m != NULL);
  ASSUME(mp != NULL);
  ASSUME(cache != NULL);
  ASSUME(m->refcnt >= 1);
  ASSUME(m->nb_segs >= 1);
  ASSUME(!RTE_MBUF_HAS_EXTBUF(m));

  struct rte_mbuf *indirect = zhida_pktmbuf_alloc_noreset(mp, cache);
  if (__builtin_expect(indirect == NULL, 0))
    return NULL;

  return zhida_pktmbuf_into_indirect_head_finish(indirect, m);
}

//=============================================================================
// clone_indirect_head: clone head as indirect, share tail segments
//=============================================================================

__attribute__((always_inline)) static inline struct rte_mbuf *
zhida_pktmbuf_clone_indirect_head_finish(struct rte_mbuf *indirect,
                                         struct rte_mbuf *m) {
  uint16_t nb_segs = m->nb_segs;
  uint32_t pkt_len = m->pkt_len;
  struct rte_mbuf *tail = m->next;

  zhida_pktmbuf_attach_for_clone(indirect, m);

  indirect->next = tail;
  indirect->nb_segs = nb_segs;
  indirect->pkt_len = pkt_len;

  while (tail != NULL) {
    zhida_refcnt_inc(tail);
    tail = tail->next;
  }

  return indirect;
}

__attribute__((nonnull(1, 2, 3))) struct rte_mbuf *
zhida_pktmbuf_clone_indirect_head(struct rte_mbuf *m, struct rte_mempool *mp,
                                  struct rte_mempool_cache *cache) {
  ASSUME(m != NULL);
  ASSUME(mp != NULL);
  ASSUME(cache != NULL);
  ASSUME(m->refcnt >= 1);
  ASSUME(m->nb_segs >= 1);
  ASSUME(!RTE_MBUF_HAS_EXTBUF(m));

  struct rte_mbuf *indirect = zhida_pktmbuf_alloc_noreset(mp, cache);
  if (__builtin_expect(indirect == NULL, 0))
    return NULL;

  return zhida_pktmbuf_clone_indirect_head_finish(indirect, m);
}
