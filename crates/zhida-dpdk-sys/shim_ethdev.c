#include <rte_ethdev.h>
#include <rte_net.h>
#include <rte_ring.h>

uint16_t dpdk_raw_eth_rx_burst(uint16_t port, uint16_t queue,
                             struct rte_mbuf **packets, uint16_t count) {
    return rte_eth_rx_burst(port, queue, packets, count);
}

uint16_t dpdk_raw_eth_tx_burst(uint16_t port, uint16_t queue,
                             struct rte_mbuf **packets, uint16_t count) {
    return rte_eth_tx_burst(port, queue, packets, count);
}

uint16_t dpdk_raw_eth_tx_prepare(uint16_t port, uint16_t queue,
                               struct rte_mbuf **packets, uint16_t count) {
    return rte_eth_tx_prepare(port, queue, packets, count);
}

int dpdk_raw_net_intel_cksum_prepare(struct rte_mbuf *m) {
    return rte_net_intel_cksum_prepare(m);
}

unsigned int dpdk_raw_ring_enqueue_burst(struct rte_ring *ring,
                                       void *const *objects, unsigned int count,
                                       unsigned int *free_space) {
    return rte_ring_enqueue_burst(ring, objects, count, free_space);
}

unsigned int dpdk_raw_ring_dequeue_burst(struct rte_ring *ring, void **objects,
                                       unsigned int count, unsigned int *available) {
    return rte_ring_dequeue_burst(ring, objects, count, available);
}
