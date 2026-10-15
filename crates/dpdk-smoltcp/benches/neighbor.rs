//! Neighbor resolution with P on-link peers, P in `PEERS`, group "neighbor".
//!
//! neighbor/resolve/P and neighbor/again/P are untimed reports: connect all
//! P sockets from a cold cache, then reconnect them with the same cache.
//! Each report gives ARP requests, elapsed virtual milliseconds and turns.
//! neighbor/connect_all/P times one reconnect of all P sockets and A turns
//! until every peer's RST has closed its socket. Throughput element = one
//! connection attempt, P per iteration; P = 1024 uses 10 samples. The virtual
//! clock advances across iterations and never goes backwards.
//!
//! The responder and connect drive come from `zhida_test_kit::peers`.
//! Setup uses one Pair, A with P slots and a /16, B with one unused slot.
//! Both Ports have 64-slot rings, RX bursts of 32 and 127-packet TX pools.
//! RX pools cover the reserve and A's P sockets of 256 bytes. A stages and
//! keeps pending 32 frames. B is never turned, and neither link
//! forwards anything. Setup checks idle pools, empty links, socket slots and
//! Closed states. Each connect must enter SynSent. The responder drains A's
//! TX once per turn, answers peer ARP requests and SYNs, and rejects every
//! other frame. It checks at most 32 replies per pass and one RST per peer.
//! Each turn must consume all prior replies, leave no staged or pending
//! frames, and send exactly what is drained. Completion checks P RST replies,
//! every socket Closed and idle pools. Drives fail after 10,000 turns or
//! 3600 seconds of virtual time. Close checks empty links, drained TX and
//! idle pools before closing the Pair.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::socket::tcp::State;
use dpdk_smoltcp::smoltcp::wire::Ipv4Cidr;
use dpdk_smoltcp::{rx_pool_count, rx_reserve};
use dpdk_smoltcp::{Eal, StackConfig};

use zhida_test_kit::many;
use zhida_test_kit::pair::{tcp_socket_sized, Pair, Side, T0};
use zhida_test_kit::peers::{assert_idle, connect_all};
use zhida_test_kit::with_eal;

const PEERS: [usize; 5] = [1, 8, 9, 64, 1024];

fn assert_links_unused(pair: &Pair) {
    for link in [&pair.a_to_b, &pair.b_to_a] {
        assert_eq!(
            (link.pool_empty, link.ring_full, link.dropped, link.held),
            (0, 0, 0, 0)
        );
    }
}

fn setup(eal: &Eal, p: usize) -> (Pair, Vec<TcpHandle>) {
    let names = [format!("nbr{p}a"), format!("nbr{p}b")];
    let configs = [
        StackConfig {
            max_udp_sockets: 0,
            ipv4: Ipv4Cidr::new(Side::A.ip(), 16),
            rx_staging: 32,
            tx_pending: 32,
            ..many::config(Side::A, p)
        },
        many::config(Side::B, 1),
    ];
    let mut pair = Pair::with_ports(
        eal,
        [&names[0], &names[1]],
        configs,
        T0,
        64,
        |side, port| {
            port.rx_burst = 32;
            port.rx_pool.count = rx_pool_count(
                rx_reserve(
                    port.rx_descriptors,
                    configs[side.index()].rx_staging,
                    port.rx_pool.cache_size,
                ),
                port.mtu,
                std::iter::repeat(256).take(if side == Side::A { p } else { 0 }),
            );
            port.tx_pool.count = 127;
        },
    );
    assert_eq!(pair.in_use(), [(0, 0); 2]);
    assert_links_unused(&pair);
    assert_eq!(pair.a.poll_at(), None);
    assert_eq!(pair.b.poll_at(), None);
    let handles: Vec<_> = (0..p)
        .map(|i| {
            let handle = pair.a.add_tcp(tcp_socket_sized(256)).unwrap();
            assert_eq!(handle.to_string(), format!("#{i}"));
            assert_eq!(pair.a.tcp_mut(&handle).state(), State::Closed);
            handle
        })
        .collect();
    assert_eq!(handles.len(), p);
    assert!(pair.a.add_tcp(tcp_socket_sized(256)).is_err());
    (pair, handles)
}

fn benches(c: &mut Criterion) {
    with_eal(|eal| {
        for p in PEERS {
            let (mut pair, handles) = setup(eal, p);
            let mut now = pair.now();
            for report in ["resolve", "again"] {
                let (arps, elapsed, turns) = connect_all(&mut pair, &handles, &mut now);
                eprintln!(
                    "neighbor/{report}/{p}: arp requests {arps}, virtual time {} ms, turns {turns}",
                    elapsed.total_millis()
                );
            }
            let mut group = c.benchmark_group("neighbor");
            group.throughput(Throughput::Elements(p as u64));
            if p == 1024 {
                group.sample_size(10);
            }
            group.bench_function(BenchmarkId::new("connect_all", p), |b| {
                b.iter(|| black_box(connect_all(&mut pair, &handles, &mut now)));
            });
            group.finish();
            assert_links_unused(&pair);
            for side in [Side::A, Side::B] {
                assert_eq!(
                    pair.drain_tx(side, |_| panic!("frame left on {side:?} TX")),
                    0
                );
            }
            assert_idle(&pair);
            assert_eq!(pair.close(), 0);
        }
    });
}

criterion_group!(neighbor, benches);
criterion_main!(neighbor);
