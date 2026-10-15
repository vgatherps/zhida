// Raw DPDK wrappers for benchmark comparison
//
// These call standard DPDK functions directly (sans our optimizations).
// Used to verify we're at least as fast as vanilla DPDK.
// Note: RTE_MBUF_REFCNT_ATOMIC is undef'd so these also use non-atomic refcount.

#include "shim_common.h"

__attribute__((nonnull(1))) struct rte_mbuf *
dpdk_raw_pktmbuf_alloc(struct rte_mempool *mp) {
  return rte_pktmbuf_alloc(mp);
}

void dpdk_raw_pktmbuf_free(struct rte_mbuf *m) { rte_pktmbuf_free(m); }

void dpdk_raw_pktmbuf_free_seg(struct rte_mbuf *m) { rte_pktmbuf_free_seg(m); }

__attribute__((nonnull(1, 2))) struct rte_mbuf *
dpdk_raw_pktmbuf_clone(struct rte_mbuf *md, struct rte_mempool *mp) {
  return rte_pktmbuf_clone(md, mp);
}

__attribute__((nonnull(1, 2))) int
dpdk_raw_pktmbuf_chain(struct rte_mbuf *head, struct rte_mbuf *tail) {
  return rte_pktmbuf_chain(head, tail);
}

__attribute__((nonnull(1))) struct rte_mbuf *
dpdk_raw_pktmbuf_lastseg(struct rte_mbuf *m) {
  return rte_pktmbuf_lastseg(m);
}

__attribute__((nonnull(1))) uint16_t
dpdk_raw_mbuf_refcnt_update(struct rte_mbuf *m, int16_t delta) {
  return rte_mbuf_refcnt_update(m, delta);
}

__attribute__((nonnull(1, 2))) void
dpdk_raw_pktmbuf_attach(struct rte_mbuf *mi, struct rte_mbuf *md) {
  rte_pktmbuf_attach(mi, md);
}

// Packet manipulation - these are what the fuzzer should use for "DPDK" path
__attribute__((nonnull(1))) int
dpdk_raw_pktmbuf_trim(struct rte_mbuf *m, uint16_t len) {
  return rte_pktmbuf_trim(m, len);
}

__attribute__((nonnull(1))) char *
dpdk_raw_pktmbuf_adj(struct rte_mbuf *m, uint16_t len) {
  return rte_pktmbuf_adj(m, len);
}

__attribute__((nonnull(1))) char *
dpdk_raw_pktmbuf_prepend(struct rte_mbuf *m, uint16_t len) {
  return rte_pktmbuf_prepend(m, len);
}

// Attach `buf` (`len` bytes; shared info is carved from its end) as external
// storage of a direct mbuf with refcnt 1. free_cb runs once the last reference
// to the external buffer is released. Returns 0, or -1 if `len` is too small.
__attribute__((nonnull(1, 2))) int
dpdk_raw_pktmbuf_attach_extbuf(struct rte_mbuf *m, void *buf, uint16_t len,
                               rte_mbuf_extbuf_free_callback_t free_cb,
                               void *opaque) {
  uint16_t buf_len = len;
  struct rte_mbuf_ext_shared_info *shinfo =
      rte_pktmbuf_ext_shinfo_init_helper(buf, &buf_len, free_cb, opaque);
  if (shinfo == NULL)
    return -1;
  rte_pktmbuf_attach_extbuf(m, buf, RTE_BAD_IOVA, buf_len, shinfo);
  return 0;
}
