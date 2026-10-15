//! The net_ring PMD alone, with no Port code in between: what `Port::open`'s
//! safety contract and `Port` cleanup rely on. TX takes only a front prefix of
//! the offered packets, bursts return ring order, and stop leaves queued
//! packets on the rings.

use std::ffi::c_void;
use std::ptr::{null, null_mut, NonNull};

use zhida_test_kit::ring_port::RingPort;
use zhida_test_kit::with_eal;
use zhida_buffer::{Mbuf, PoolConfig, PoolManager};
use zhida_dpdk_sys::*;

/// One started net_ring port with 8-slot rings, configured raw with RX from a
/// production pool. `owned` holds the test's packets in order. Fields drop in
/// order: packets, then the fixture, then the pool.
struct Raw {
    owned: Vec<Mbuf>,
    fixture: RingPort,
    pool: PoolManager,
}

impl Raw {
    fn new() -> Self {
        with_eal(|_| {});
        let pool = unsafe {
            PoolManager::new_production(PoolConfig {
                name: c"ethdev_pool",
                count: 63,
                cache_size: 8,
                data_room_size: RTE_PKTMBUF_HEADROOM as u16 + 2048,
                socket_id: -1,
            })
        }
        .unwrap();
        let fixture = RingPort::new("ethdev", 8, 8);
        let port = fixture.port_id();
        let conf: rte_eth_conf = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { rte_eth_dev_configure(port, 1, 1, &conf) }, 0);
        assert_eq!(unsafe { rte_eth_rx_queue_setup(port, 0, 8, 0, null(), pool.pool()) }, 0);
        assert_eq!(unsafe { rte_eth_tx_queue_setup(port, 0, 8, 0, null()) }, 0);
        assert_eq!(unsafe { rte_eth_dev_start(port) }, 0);
        Self {
            owned: Vec::with_capacity(16),
            fixture,
            pool,
        }
    }

    fn allocate(&mut self, count: u8, base: u8) -> Vec<*mut rte_mbuf> {
        let mut identities = Vec::with_capacity(count as usize);
        for value in base..base + count {
            let mut packet = self.pool.alloc_with_len(4).unwrap();
            packet
                .data_mut()
                .copy_from_slice(&[value, 0x55, 0xaa, value]);
            identities.push(packet.as_ptr());
            self.owned.push(packet);
        }
        identities
    }

    /// Offer every owned packet to TX (`raw_ring`: enqueue on the RX ring
    /// instead); the unaccepted suffix stays owned, in order.
    fn tx(&mut self, raw_ring: bool) -> usize {
        let mut raw = [null_mut(); 16];
        let count = self.owned.len();
        assert!(count <= raw.len());
        assert!(self.owned.capacity() >= raw.len());
        for (slot, packet) in raw.iter_mut().zip(self.owned.drain(..)) {
            *slot = packet.into_raw().as_ptr();
        }
        let accepted = unsafe {
            if raw_ring {
                dpdk_raw_ring_enqueue_burst(
                    self.fixture.rx_ring(),
                    raw.as_ptr().cast(),
                    count as u32,
                    null_mut(),
                ) as usize
            } else {
                dpdk_raw_eth_tx_burst(self.fixture.port_id(), 0, raw.as_mut_ptr(), count as u16)
                    as usize
            }
        };
        // Fixed capacity was reserved before transfer; restore suffix before assertions.
        for &packet in &raw[accepted..count] {
            self.owned
                .push(unsafe { Mbuf::from_raw(NonNull::new_unchecked(packet)) });
        }
        accepted
    }

    /// Move everything on the TX ring to the RX ring, in order.
    fn loop_back(&self) {
        let mut raw = [null_mut::<c_void>(); 8];
        let count = unsafe {
            dpdk_raw_ring_dequeue_burst(self.fixture.tx_ring(), raw.as_mut_ptr(), 8, null_mut())
        };
        let moved = unsafe {
            dpdk_raw_ring_enqueue_burst(self.fixture.rx_ring(), raw.as_ptr(), count, null_mut())
        };
        assert_eq!(moved, count);
    }

    fn rx(&mut self, count: u16) -> usize {
        let mut raw = [null_mut(); 16];
        assert!(usize::from(count) <= raw.len());
        assert!(self.owned.len() + usize::from(count) <= self.owned.capacity());
        let received =
            unsafe { dpdk_raw_eth_rx_burst(self.fixture.port_id(), 0, raw.as_mut_ptr(), count) };
        // Acquire every returned owner before inspecting pointers or bytes.
        for &packet in &raw[..received as usize] {
            self.owned
                .push(unsafe { Mbuf::from_raw(NonNull::new_unchecked(packet)) });
        }
        received as usize
    }

    fn check_owned(&self, identities: &[*mut rte_mbuf], base: u8) {
        assert_eq!(self.owned.len(), identities.len());
        for (offset, (packet, identity)) in self.owned.iter().zip(identities).enumerate() {
            assert_eq!(packet.as_ptr(), *identity);
            assert_eq!(
                packet.data(),
                &[base + offset as u8, 0x55, 0xaa, base + offset as u8]
            );
        }
    }

    fn stop(&self) {
        assert_eq!(unsafe { rte_eth_dev_stop(self.fixture.port_id()) }, 0);
    }

    /// Stop and close the device, free what the rings still hold, release the
    /// vdev and rings; then the pool must be idle. Returns the ring packets freed.
    fn close(self) -> usize {
        let Self {
            owned,
            fixture,
            pool,
        } = self;
        drop(owned);
        assert_eq!(unsafe { rte_eth_dev_stop(fixture.port_id()) }, 0);
        assert_eq!(unsafe { rte_eth_dev_close(fixture.port_id()) }, 0);
        let drained = fixture.drain();
        fixture.close();
        assert_eq!(pool.in_use_count(), 0);
        drained
    }
}

#[zhida_test_support::pinned_test]
fn real_ring_bursts_transfer_only_prefix_and_preserve_fifo() {
    let mut raw = Raw::new();
    assert_eq!(raw.tx(false), 0);
    assert_eq!(raw.rx(0), 0);
    assert_eq!(raw.rx(8), 0);
    let identities = raw.allocate(9, 10);
    assert_eq!(raw.tx(false), 7);
    raw.check_owned(&identities[7..], 17);
    assert_eq!(raw.pool.in_use_count(), 9);
    assert_eq!(raw.tx(false), 0);
    raw.check_owned(&identities[7..], 17);
    // Keep the rejected suffix owned while adopting the accepted prefix.
    let suffix = raw.owned.drain(..).collect::<Vec<_>>();
    raw.loop_back();
    assert_eq!(raw.rx(4), 4);
    raw.check_owned(&identities[..4], 10);
    raw.owned.clear();
    assert_eq!(raw.rx(8), 3);
    raw.check_owned(&identities[4..7], 14);
    raw.owned.clear();
    raw.owned.extend(suffix);
    assert_eq!(raw.tx(false), 2);
    raw.loop_back();
    assert_eq!(raw.rx(8), 2);
    raw.check_owned(&identities[7..], 17);
    raw.owned.clear();
    assert_eq!(raw.rx(8), 0);
    assert_eq!(raw.pool.in_use_count(), 0);
    let identities = raw.allocate(7, 30);
    assert_eq!(raw.tx(true), 7);
    assert_eq!(raw.rx(8), 7);
    raw.check_owned(&identities, 30);
    raw.owned.clear();
    assert_eq!(raw.pool.in_use_count(), 0);
    raw.allocate(3, 50);
    assert_eq!(raw.tx(true), 3);
    assert_eq!(raw.pool.in_use_count(), 3);
    assert_eq!(raw.close(), 3);
}

#[zhida_test_support::pinned_test]
fn stopped_ring_keeps_queued_packets_until_raw_drain() {
    let mut raw = Raw::new();
    raw.allocate(7, 10);
    assert_eq!(raw.tx(false), 7);
    assert_eq!(raw.pool.in_use_count(), 7);
    raw.stop();
    assert_eq!(raw.pool.in_use_count(), 7);
    assert_eq!(raw.close(), 7);
}
