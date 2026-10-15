//! Pending frames survive refused flushes and keep their order.

use zhida_test_kit::pair::drain_bytes;
use dpdk_smoltcp::smoltcp::wire::{
    ArpOperation, ArpPacket, EthernetAddress, EthernetFrame, EthernetProtocol, TcpControl,
    ETHERNET_HEADER_LEN, IPV4_HEADER_LEN, TCP_HEADER_LEN,
};
use dpdk_smoltcp::{rx_pool_count, rx_reserve};
use dpdk_smoltcp::{Eal, Sent, StackConfig, Turn, UdpConfig};

use zhida_test_kit::{many, pair, wire, with_eal};
use pair::{config, establish, segment, Dir, Pair, Side, T0};
use wire::Link;

const BUDGET: usize = 32;
const MTU: u16 = 256;

const IDLE: Turn = Turn {
    rx_received: 0,
    rx_rejected: 0,
    rx_ipv4_checksum_bad: 0,
    rx_processed: 0,
    rx_staged: 0,
    rx_blocked: false,
    tx_accepted: 0,
    tx_pending: 0,
};

fn new_pair(eal: &Eal, names: [&str; 2], pending: usize) -> Pair {
    let configs = [Side::A, Side::B].map(|side| StackConfig {
        max_udp_sockets: 1,
        tx_pending: pending,
        ..config(side)
    });
    Pair::with_ports(eal, names, configs, T0, 16, |side, port| {
        port.mtu = MTU;
        port.rx_pool.count = rx_pool_count(
            rx_reserve(
                port.rx_descriptors,
                configs[side.index()].rx_staging,
                port.rx_pool.cache_size,
            ),
            port.mtu,
            std::iter::repeat(4096).take(configs[side.index()].max_sockets),
        )
        .checked_add(1)
        .expect("UDP receive slot fits the RX pool");
    })
}

fn fill_tx_ring(pair: &mut Pair) {
    let udp = pair.a
        .add_udp(UdpConfig {
            port: 5000,
            rx_queue: 1,
            tx_checksum: false,
            broadcast: false,
        })
        .unwrap();
    for _ in 0..15 {
        pair.a
            .udp_send(&udp, Some((Side::B.ip(), 5000).into()), b"ring")
            .unwrap();
        assert_eq!(pair.a.flush(), Ok(Sent { tx_accepted: 1, tx_pending: 0 }));
    }
    pair.a.remove_udp(udp);
}

fn forward(link: &mut Link) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    link.forward_with(|frame| frames.push(frame.to_vec()));
    frames
}

fn payloads(frames: &[Vec<u8>], src: Side) -> Vec<Vec<u8>> {
    frames
        .iter()
        .map(|frame| segment(frame, src).payload.to_vec())
        .collect()
}

// The SYN-ACK advertises the peer MSS; the final ACK has the negotiated
// option size that reduces the payload in each full data segment.
fn data_mss(handshake: &[(Dir, Vec<u8>)]) -> usize {
    let syn_ack = handshake
        .iter()
        .rev()
        .filter(|(dir, _)| *dir == Dir::BToA)
        .map(|(_, frame)| segment(frame, Side::B))
        .find(|tcp| tcp.max_seg_size.is_some())
        .expect("B sent a SYN-ACK");
    let ack = handshake
        .iter()
        .rev()
        .filter(|(dir, _)| *dir == Dir::AToB)
        .map(|(_, frame)| segment(frame, Side::A))
        .find(|tcp| tcp.max_seg_size.is_none())
        .expect("A sent the final ACK");
    assert!(ack.payload.is_empty());
    assert_eq!(ack.control, TcpControl::None);
    assert!(ack.ack_number.is_some());
    assert_eq!(syn_ack.max_seg_size, Some(MTU - 40));
    assert_eq!(syn_ack.window_len, 4096);
    let options = ack
        .header_len()
        .checked_sub(TCP_HEADER_LEN)
        .expect("TCP header");
    usize::from(syn_ack.max_seg_size.unwrap())
        .checked_sub(options)
        .expect("MSS includes room for TCP options")
}

fn assert_segments(frames: &[Vec<u8>], src: Side, data: &[u8], mss: usize) {
    let expected: Vec<_> = data.chunks(mss).map(<[u8]>::to_vec).collect();
    assert_eq!(payloads(frames, src), expected);
    let mut next = segment(&frames[0], src).seq_number;
    for frame in frames {
        let tcp = segment(frame, src);
        assert_eq!(tcp.seq_number, next);
        next = next + tcp.payload.len();
    }
}

#[zhida_test_support::pinned_test]
fn template_acks_keep_exact_tx_pool_counts() {
    with_eal(|eal| {
        const CONNECTIONS: u16 = 4;
        for pending in [usize::from(CONNECTIONS), 1] {
            let configs = [Side::A, Side::B].map(|side| StackConfig {
                max_udp_sockets: 0,
                tx_pending: pending,
                ..many::config(side, usize::from(CONNECTIONS))
            });
            let mut pair =
                Pair::with_ports(eal, ["eq7a", "eq7b"], configs, T0, 16, |side, port| {
                    port.mtu = MTU;
                    port.rx_pool.count = rx_pool_count(
                        rx_reserve(
                            port.rx_descriptors,
                            configs[side.index()].rx_staging,
                            port.rx_pool.cache_size,
                        ),
                        port.mtu,
                        std::iter::repeat(4096).take(configs[side.index()].max_sockets),
                    );
                });
            let conns = many::open(&mut pair, 0..CONNECTIONS, 4096);
            let now = pair.now();
            for conn in &conns {
                pair.a.tcp_mut(&conn.client).set_ack_delay(None);
                pair.b.tcp_mut(&conn.server).set_ack_delay(None);
            }
            for conn in &conns {
                assert_eq!(pair.b.tcp_mut(&conn.server).send_slice(b"w"), Ok(1));
                assert_eq!(pair.b.send().unwrap().tx_accepted, 1);
                let warm = forward(&mut pair.b_to_a);
                assert_eq!(warm.len(), 1);
                let tcp = segment(&warm[0], Side::B);
                assert_eq!(tcp.payload, b"w");
                assert_eq!(
                    tcp.src_port,
                    many::SERVER_BASE.checked_add(conn.id).unwrap()
                );
                assert_eq!(tcp.max_seg_size, None);
                assert_eq!(tcp.window_scale, None);
                assert!(!tcp.sack_permitted);
                assert_eq!(tcp.sack_ranges, [None; 3]);
                assert_eq!(pair.a.receive(now, BUDGET).unwrap().rx_processed, 1);
                let data = drain_bytes(pair.a.tcp_mut(&conn.client)).unwrap();
                assert_eq!(data.len(), 1);
                assert_eq!(&data, b"w");
                assert_eq!(pair.a.send().unwrap().tx_accepted, 1);
                assert_eq!(pair.a_to_b.forward(), 1);
                assert_eq!(pair.b.receive(now, BUDGET).unwrap().rx_processed, 1);
                assert_eq!(pair.b.tcp(&conn.server).send_queue(), 0);
            }

            let mut expected = Vec::new();
            for conn in &conns {
                assert_eq!(pair.a.tcp_mut(&conn.client).send_slice(b"x"), Ok(1));
                assert_eq!(pair.a.send().unwrap().tx_accepted, 1);
                let frames = forward(&mut pair.a_to_b);
                assert_eq!(frames.len(), 1);
                let tcp = segment(&frames[0], Side::A);
                assert_eq!(tcp.payload, b"x");
                expected.push((tcp.src_port, tcp.seq_number + 1));
            }
            assert_eq!(pair.in_use()[0].1, 0);
            assert_eq!(
                pair.b.receive(now, BUDGET),
                Ok(Turn {
                    rx_received: usize::from(CONNECTIONS),
                    rx_processed: usize::from(CONNECTIONS),
                    ..IDLE
                })
            );
            for conn in &conns {
                assert_eq!(pair.b.tcp(&conn.server).recv_queue(), 1);
            }
            // Each server holds its "x" in the received frame until the app reads it.
            assert_eq!(pair.in_use()[1].0, u32::from(CONNECTIONS));
            for conn in &conns {
                let x = drain_bytes(pair.b.tcp_mut(&conn.server)).unwrap();
                assert_eq!(x.len(), 1);
                assert_eq!(&x, b"x");
            }
            assert_eq!(pair.in_use()[1].0, 0);
            let mut acks = Vec::new();
            let mut remaining = usize::from(CONNECTIONS);
            while remaining > 0 {
                let queued = remaining.min(pending);
                assert_eq!(
                    pair.b.send(),
                    Ok(Sent {
                        tx_accepted: queued,
                        tx_pending: 0,
                    })
                );
                assert_eq!(pair.in_use()[1], (0, u32::try_from(queued).unwrap()));
                assert_eq!(
                    pair.drain_tx(Side::B, |frame| {
                        let tcp = segment(frame, Side::B);
                        assert_eq!(tcp.control, TcpControl::None);
                        assert!(tcp.payload.is_empty());
                        assert_eq!(
                            frame.len(),
                            ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + tcp.header_len()
                        );
                        acks.push((tcp.dst_port, tcp.ack_number.unwrap()));
                    }),
                    queued
                );
                assert_eq!(pair.in_use()[1], (0, 0));
                assert_eq!(acks, expected[..acks.len()]);
                remaining = remaining.checked_sub(queued).unwrap();
            }
            assert_eq!(acks, expected);
            assert_eq!(pair.b.send(), Ok(Sent { tx_accepted: 0, tx_pending: 0 }));
            for conn in &conns {
                pair.a.tcp_mut(&conn.client).abort();
                pair.b.tcp_mut(&conn.server).abort();
            }
            let expected_rsts: Vec<_> = conns
                .iter()
                .map(|conn| {
                    (
                        many::SERVER_BASE.checked_add(conn.id).unwrap(),
                        many::CLIENT_BASE.checked_add(conn.id).unwrap(),
                    )
                })
                .collect();
            let mut rsts = Vec::new();
            let mut remaining = usize::from(CONNECTIONS);
            while remaining > 0 {
                let queued = remaining.min(pending);
                assert_eq!(
                    pair.b.send(),
                    Ok(Sent {
                        tx_accepted: queued,
                        tx_pending: 0,
                    })
                );
                assert_eq!(pair.in_use()[1], (0, u32::try_from(queued).unwrap()));
                assert_eq!(
                    pair.drain_tx(Side::B, |frame| {
                        let tcp = segment(frame, Side::B);
                        assert_eq!(tcp.control, dpdk_smoltcp::smoltcp::wire::TcpControl::Rst);
                        assert!(tcp.payload.is_empty());
                        rsts.push((tcp.src_port, tcp.dst_port));
                    }),
                    queued
                );
                assert_eq!(pair.in_use()[1], (0, 0));
                assert_eq!(rsts, expected_rsts[..rsts.len()]);
                remaining = remaining.checked_sub(queued).unwrap();
            }
            assert_eq!(rsts, expected_rsts);
            assert_eq!(pair.b.send(), Ok(Sent { tx_accepted: 0, tx_pending: 0 }));
            assert_eq!(pair.in_use(), [(0, 0); 2]);
            for conn in conns {
                pair.a.remove_tcp(conn.client);
                pair.b.remove_tcp(conn.server);
            }
            assert_eq!(pair.in_use(), [(0, 0); 2]);
            assert_eq!(pair.close(), 0);
        }
    });
}

#[zhida_test_support::pinned_test]
fn send_backpressure_resumes_same_socket() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["eq3a", "eq3b"], 2);
        let ([a, b], handshake) = establish(&mut pair, Side::A);
        let mss = data_mss(&handshake);
        let data = pair::pattern(5 * mss, 3);
        fill_tx_ring(&mut pair);
        assert_eq!(pair.a.tcp_mut(&a).send_slice(&data), Ok(data.len()));
        assert_eq!(pair.a.send(), Ok(Sent { tx_accepted: 0, tx_pending: 2 }));
        assert_eq!(pair.a.send(), Ok(Sent { tx_accepted: 0, tx_pending: 2 }));
        let now = pair.now();
        assert_eq!(pair.a.poll_at(), Some(now));
        assert_eq!(pair.drain_tx(Side::A, |_| {}), 15);
        assert_eq!(pair.in_use()[0].1, 2);
        assert_eq!(pair.a.send(), Ok(Sent { tx_accepted: 2, tx_pending: 0 }));
        assert_eq!(pair.a.poll_at(), Some(now));
        assert_eq!(pair.a.send(), Ok(Sent { tx_accepted: 2, tx_pending: 0 }));
        assert_eq!(pair.a.poll_at(), Some(now));
        assert_eq!(pair.a.send(), Ok(Sent { tx_accepted: 1, tx_pending: 0 }));
        assert_eq!(pair.in_use()[0].1, 5);
        let frames = forward(&mut pair.a_to_b);
        assert_segments(&frames, Side::A, &data, mss);
        assert_eq!(pair.in_use()[0].1, 0);
        assert_eq!(pair.b.receive(now, BUDGET).unwrap().rx_processed, 5);
        let received = drain_bytes(pair.b.tcp_mut(&b)).unwrap();
        assert_eq!(received.len(), data.len());
        assert_eq!(received, data);
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn receive_blocks_on_full_pending_queue() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["eq4a", "eq4b"], 2);
        let ([a, b], handshake) = establish(&mut pair, Side::A);
        let mss = data_mss(&handshake);
        fill_tx_ring(&mut pair);
        let data = pair::pattern(2 * mss, 4);
        assert_eq!(pair.a.tcp_mut(&a).send_slice(&data), Ok(data.len()));
        assert_eq!(pair.a.send(), Ok(Sent { tx_accepted: 0, tx_pending: 2 }));
        assert_eq!(pair.b.tcp_mut(&b).send_slice(b"request"), Ok(7));
        assert_eq!(pair.b.send().unwrap().tx_accepted, 1);
        assert_eq!(pair.b_to_a.forward(), 1);
        let now = pair.now();
        assert_eq!(
            pair.a.receive(now, BUDGET),
            Ok(Turn {
                rx_received: 1,
                rx_staged: 1,
                rx_blocked: true,
                tx_pending: 2,
                ..IDLE
            })
        );
        assert_eq!(pair.in_use()[0].0, 1);
        assert_eq!(pair.a.tcp(&a).recv_queue(), 0);
        assert_eq!(pair.drain_tx(Side::A, |_| {}), 15);
        assert_eq!(pair.a.flush(), Ok(Sent { tx_accepted: 2, tx_pending: 0 }));
        assert_eq!(pair.drain_tx(Side::A, |_| {}), 2);
        assert_eq!(
            pair.a.receive(now, BUDGET),
            Ok(Turn { rx_processed: 1, ..IDLE })
        );
        assert_eq!(pair.in_use()[0].0, 1);
        let received = drain_bytes(pair.a.tcp_mut(&a)).unwrap();
        assert_eq!(received.len(), 7);
        assert_eq!(&received, b"request");
        assert_eq!(pair.in_use()[0].0, 0);
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn into_port_returns_unflushed_frames() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["eq5a", "eq5b"], 32);
        let ([a, _b], handshake) = establish(&mut pair, Side::A);
        let mss = data_mss(&handshake);
        let data = pair::pattern(3 * mss, 5);
        fill_tx_ring(&mut pair);
        assert_eq!(pair.a.tcp_mut(&a).send_slice(&data), Ok(data.len()));
        assert_eq!(pair.a.send(), Ok(Sent { tx_accepted: 0, tx_pending: 3 }));
        assert_eq!(pair.in_use()[0].1, 18);
        assert_eq!(pair.drain_tx(Side::A, |_| {}), 15);
        assert_eq!(pair.in_use()[0].1, 3);
        assert_eq!(pair.drain_tx(Side::A, |_| {}), 0);
        // close calls into_port before it checks both pools on each side are 0.
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn receive_pushes_refused_frames_before_ingress() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["eq8a", "eq8b"], 1);
        let ([a, _b], handshake) = establish(&mut pair, Side::A);
        let mss = data_mss(&handshake);
        let data = pair::pattern(mss, 8);
        fill_tx_ring(&mut pair);
        assert_eq!(pair.a.tcp_mut(&a).send_slice(&data), Ok(data.len()));
        assert_eq!(pair.a.send(), Ok(Sent { tx_accepted: 0, tx_pending: 1 }));
        let request = zhida_test_kit::ring_port::arp(
            ArpOperation::Request,
            EthernetAddress::BROADCAST,
            (Side::B.mac(), Side::B.ip()),
            (Side::A.mac(), Side::A.ip()),
        );
        pair.inject(Side::A, &[request]);
        assert_eq!(pair.drain_tx(Side::A, |_| {}), 15);
        let now = pair.now();
        assert_eq!(
            pair.a.receive(now, BUDGET),
            Ok(Turn { rx_received: 1, rx_processed: 1, tx_accepted: 2, ..IDLE })
        );
        let mut frames = Vec::new();
        assert_eq!(pair.drain_tx(Side::A, |frame| frames.push(frame.to_vec())), 2);
        assert_segments(&frames[..1], Side::A, &data, mss);
        let ethernet = EthernetFrame::new_checked(&frames[1][..]).unwrap();
        assert_eq!(ethernet.ethertype(), EthernetProtocol::Arp);
        let reply = ArpPacket::new_checked(ethernet.payload()).unwrap();
        assert_eq!(reply.operation(), ArpOperation::Reply);
        assert_eq!(pair.a.send(), Ok(Sent { tx_accepted: 0, tx_pending: 0 }));
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn flush_with_nothing_pending() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["eq6a", "eq6b"], 32);
        let before = pair.in_use();
        let empty = Sent {
            tx_accepted: 0,
            tx_pending: 0,
        };
        assert_eq!(pair.a.flush(), Ok(empty));
        assert_eq!(pair.a.flush(), Ok(empty));
        assert_eq!(pair.b.flush(), Ok(empty));
        assert_eq!(pair.a_to_b.forward(), 0);
        assert_eq!(pair.b_to_a.forward(), 0);
        assert_eq!(pair.in_use(), before);
        assert_eq!(pair.close(), 0);
    });
}
