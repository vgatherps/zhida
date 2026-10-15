// Chain operations - safe, unchecked
//
// An append writes lastseg(head)->next, head->nb_segs, head->pkt_len and resets
// tail->pkt_len to tail->data_len.
//
// OWNERSHIP RULE (safe): every segment's refcnt counts each owner
// whose chain walk passes it (Clone/share_all/clone_indirect_head increment
// every segment they walk) plus each indirect attached to it. All walks through
// head's chain end at lastseg, so lastseg->refcnt == 1 means no other owner
// reaches any segment of head's chain: its link and head metadata are ours.
// Assumed, not checked: tail is a reference the caller owns independently of
// head and its chain shares no segment with head's chain. Under that
// assumption no cycle forms; without it, chain_safe(p, p) with one reference
// passes the refcnt checks and sets p->next = p. A tail whose refcnt != 1 is reached
// by another owner, so its pkt_len may only be "reset" when that is a no-op.
// Rejection writes nothing.

#include "shim_common.h"

// Segment-count sum in 32 bits: a uint16_t sum wraps before the comparison.
__attribute__((always_inline)) static inline uint32_t
__chain_total_segs(const struct rte_mbuf *head, const struct rte_mbuf *tail) {
  return (uint32_t)head->nb_segs + (uint32_t)tail->nb_segs;
}

__attribute__((always_inline)) static inline bool
__chain_owned(const struct rte_mbuf *lastseg, const struct rte_mbuf *tail) {
  return lastseg->refcnt == 1 &&
         (tail->refcnt == 1 || tail->pkt_len == tail->data_len);
}

// total_segs <= RTE_MBUF_MAX_NB_SEGS and each data_len <= UINT16_MAX bound the
// pkt_len sum by UINT16_MAX * UINT16_MAX < 2^32 for valid metadata.
__attribute__((always_inline)) static inline void
__chain_link_owned(struct rte_mbuf *head, struct rte_mbuf *lastseg,
                   struct rte_mbuf *tail, uint32_t total_segs) {
  lastseg->next = tail;
  head->nb_segs = (uint16_t)total_segs;
  head->pkt_len += tail->pkt_len;
  if (tail->pkt_len != tail->data_len)
    tail->pkt_len = tail->data_len;
}

__attribute__((hot, nonnull(1, 2), aligned(16))) int
zhida_pktmbuf_chain_safe(struct rte_mbuf *head, struct rte_mbuf *tail) {
  uint32_t total_segs = __chain_total_segs(head, tail);
  if (__builtin_expect(total_segs > RTE_MBUF_MAX_NB_SEGS, 0))
    return -EOVERFLOW;

  struct rte_mbuf *lastseg = __lastseg_walk(head);

  if (__builtin_expect(!__chain_owned(lastseg, tail), 0))
    return -1;

  __chain_link_owned(head, lastseg, tail, total_segs);
  return 0;
}

__attribute__((hot, nonnull(1, 2), aligned(16))) int
zhida_pktmbuf_chain(struct rte_mbuf *head, struct rte_mbuf *tail) {
  uint32_t total_segs = __chain_total_segs(head, tail);
  if (__builtin_expect(total_segs > RTE_MBUF_MAX_NB_SEGS, 0))
    return -EOVERFLOW;

  struct rte_mbuf *lastseg = __lastseg_walk(head);
  lastseg->next = tail;
  head->nb_segs = (uint16_t)total_segs;
  head->pkt_len += tail->pkt_len;
  tail->pkt_len = tail->data_len;

  return 0;
}

__attribute__((nonnull(1))) struct rte_mbuf *
zhida_pktmbuf_lastseg(struct rte_mbuf *m) {
  return rte_pktmbuf_lastseg(m);
}

__attribute__((nonnull(1))) uint16_t
zhida_mbuf_refcnt_update(struct rte_mbuf *m, int16_t delta) {
  return rte_mbuf_refcnt_update(m, delta);
}
