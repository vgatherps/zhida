//! Ring-PMD transfer timings against the raw DPDK burst reference.
//!
//! One iteration is one batch of `BATCH` frames of `FRAME` bytes on one
//! net_ring port. Owned and raw runs share the port, rings, pool settings,
//! producer and drain; only the burst step differs.
//!
//! ring_tx: allocate the batch, transfer it to TX queue 0, then the ring peer
//! dequeues and frees every packet.
//! ring_rx: inside the timed loop for both runs, a test-only producer allocates
//! the batch from the port's own RX pool (found by name), copies the frame
//! bytes and enqueues it on the RX ring; the burst then receives it and every
//! packet is dropped through the zhida destructor.

use std::collections::VecDeque;
use std::ffi::{c_void, CStr};
use std::hint::black_box;
use std::ptr::{null_mut, NonNull};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use dpdk_smoltcp::{Eal, PortConfig, RxBurst};
use zhida_buffer::{Mbuf, PoolConfig, PoolManager};
use zhida_dpdk_sys::*;

use zhida_test_kit::ring_port::RingPort;
use zhida_test_kit::{wire, with_eal};

const BATCH: usize = 32;
const FRAME: u16 = 64;
const RING_SIZE: u32 = 64;
const FRAME_BYTES: [u8; FRAME as usize] = [0x5a; FRAME as usize];

/// Test-only producer: one batch from the port's own RX pool onto its RX ring.
fn produce_rx(ring: *mut rte_ring, rx_pool: *mut rte_mempool) {
    let mut raw = [null_mut::<c_void>(); BATCH];
    for slot in &mut raw {
        *slot = wire::copy_into(rx_pool, &FRAME_BYTES).cast();
    }
    let queued =
        unsafe { dpdk_raw_ring_enqueue_burst(ring, raw.as_ptr(), BATCH as u32, null_mut()) };
    assert_eq!(queued as usize, BATCH);
}

fn pool(name: &CStr) -> PoolConfig<'_> {
    PoolConfig {
        name,
        count: 511,
        cache_size: 64,
        data_room_size: RTE_PKTMBUF_HEADROOM as u16 + 2048,
        socket_id: -1,
    }
}

/// Ring peer: dequeue and free exactly one accepted batch.
fn peer_drain(ring: *mut rte_ring) {
    let mut raw = [null_mut::<c_void>(); BATCH];
    let count =
        unsafe { dpdk_raw_ring_dequeue_burst(ring, raw.as_mut_ptr(), BATCH as u32, null_mut()) };
    assert_eq!(count as usize, BATCH);
    for &packet in &raw {
        unsafe { dpdk_raw_pktmbuf_free(packet.cast()) };
    }
}

/// The fixture's port with 64 descriptors and bursts of `BATCH` each way and
/// `pool` sizes.
fn bench_config(defaults: PortConfig<'_>) -> PortConfig<'_> {
    PortConfig {
        rx_descriptors: 64,
        tx_descriptors: 64,
        rx_burst: BATCH as u16,
        tx_burst: BATCH as u16,
        rx_pool: pool(defaults.rx_pool.name),
        tx_pool: pool(defaults.tx_pool.name),
        ..defaults
    }
}

fn ring_transfers(c: &mut Criterion) {
    with_eal(|eal| ring_bench(c, eal));
}

fn ring_bench(c: &mut Criterion, eal: &Eal) {
    let fixture = RingPort::new("bench_ring", RING_SIZE, RING_SIZE);
    let rings = [fixture.rx_ring(), fixture.tx_ring()];
    let port_id = fixture.port_id();
    let mut port = fixture.open_with(eal, bench_config(fixture.config()));
    let raw_pool = unsafe { PoolManager::new_production(pool(c"bench_raw_tx")) }.unwrap();

    let mut group = c.benchmark_group("ring_tx");
    group.throughput(Throughput::Elements(BATCH as u64));
    group.bench_function("raw_eth_tx_burst", |b| {
        let mut raw = [null_mut::<rte_mbuf>(); BATCH];
        b.iter(|| {
            for slot in &mut raw {
                *slot = raw_pool.alloc_with_len(FRAME).unwrap().into_raw().as_ptr();
            }
            let accepted =
                unsafe { dpdk_raw_eth_tx_burst(port_id, 0, raw.as_mut_ptr(), BATCH as u16) };
            assert_eq!(black_box(accepted) as usize, BATCH);
            peer_drain(rings[1]);
        });
    });
    group.bench_function("owned_tx_burst", |b| {
        let mut pending = VecDeque::with_capacity(BATCH);
        b.iter(|| {
            for _ in 0..BATCH {
                pending.push_back(port.alloc_tx(FRAME).unwrap());
            }
            let accepted = port.tx_burst(&mut pending).unwrap();
            assert_eq!(black_box(accepted), BATCH);
            peer_drain(rings[1]);
        });
    });
    group.finish();

    let rx_pool = fixture.rx_pool();
    let mut group = c.benchmark_group("ring_rx");
    group.throughput(Throughput::Elements(BATCH as u64));
    group.bench_function("raw_eth_rx_burst", |b| {
        let mut raw = [null_mut::<rte_mbuf>(); BATCH];
        b.iter(|| {
            produce_rx(rings[0], rx_pool);
            let received =
                unsafe { dpdk_raw_eth_rx_burst(port_id, 0, raw.as_mut_ptr(), BATCH as u16) };
            assert_eq!(black_box(received) as usize, BATCH);
            for &packet in &raw {
                drop(unsafe { Mbuf::from_raw(NonNull::new_unchecked(packet)) });
            }
        });
    });
    group.bench_function("owned_rx_burst", |b| {
        let mut staged = VecDeque::with_capacity(BATCH);
        b.iter(|| {
            produce_rx(rings[0], rx_pool);
            let burst = port.rx_burst(&mut staged).unwrap();
            assert_eq!(
                black_box(burst),
                RxBurst {
                    accepted: BATCH,
                    rejected: 0,
                    rx_ipv4_checksum_bad: 0,
                }
            );
            staged.clear();
        });
    });
    group.finish();

    assert_eq!(raw_pool.in_use_count(), 0);
    drop(raw_pool);
    port.try_close().unwrap();
    fixture.close();
}

criterion_group!(benches, ring_transfers);
criterion_main!(benches);
