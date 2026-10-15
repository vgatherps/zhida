//! Two Stacks over net_ring at IP MTU 9000, a 9000/1500 pair, and the pool
//! room check `Port::open` applies at MTU 9000.

use zhida_test_kit::pair::drain_bytes;
use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::socket::tcp::{self, State};
use dpdk_smoltcp::smoltcp::iface::PathMtu;
use dpdk_smoltcp::smoltcp::phy::ChecksumCapabilities;
use dpdk_smoltcp::smoltcp::wire::{
    ArpOperation, EthernetFrame, EthernetProtocol, IpEndpoint, Ipv4Address, Ipv4Cidr,
    Ipv4Packet, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber, ETHERNET_HEADER_LEN, IPV4_HEADER_LEN,
    TCP_HEADER_LEN,
};
use dpdk_smoltcp::rx_reserve;
use dpdk_smoltcp::{Eal, Port, PortError};
use zhida_dpdk_sys::RTE_PKTMBUF_HEADROOM;

use zhida_test_kit::pair::{
    config, establish_sized, pattern, segment, tcp_frame_between, tcp_socket_sized, App, Dir, Pair,
    Side, CLIENT_PORT, SERVER_PORT, T0, BUDGET,
};
use zhida_test_kit::ring_port::{arp, resize, RingPort};
use zhida_test_kit::with_eal;

/// IP MTU and pool data room after headroom.
type Size = (u16, u16);

/// 9216 is 9000 + 26 (Ethernet header, FCS and two VLAN tags) rounded up to
/// a multiple of 1 KiB, so a NIC that sizes RX buffers in 1 KiB steps still
/// receives the whole frame in one buffer.
const JUMBO: Size = (9000, 9216);
/// `RingPort::config`'s MTU and room.
const STANDARD: Size = (1500, 2048);
/// More than 2 x MSS 8960, so a window holds two full jumbo segments.
const BUFFER: usize = 32 * 1024;
const TRANSFER: usize = 256 * 1024;
/// Ring slots and pool packets per side: a window of standard-MTU segments plus
/// its ACKs fits a ring, so the links drop nothing.
const RING: u32 = 64;
const POOL: u32 = 127;

/// A Pair whose Ports have `sizes`, A then B.
fn sized_pair(eal: &Eal, names: [&str; 2], sizes: [Size; 2]) -> Pair {
    sized_pair_with_mss_cap(eal, names, sizes, None)
}

fn sized_pair_with_mss_cap(
    eal: &Eal,
    names: [&str; 2],
    sizes: [Size; 2],
    cap: Option<u16>,
) -> Pair {
    sized_pair_with_paths(eal, names, sizes, cap, [&[], &[]])
}

fn sized_pair_with_paths(
    eal: &Eal,
    names: [&str; 2],
    sizes: [Size; 2],
    cap: Option<u16>,
    paths: [&[PathMtu]; 2],
) -> Pair {
    let mut configs = [config(Side::A), config(Side::B)];
    configs[0].paths = paths[0];
    configs[1].paths = paths[1];
    Pair::with_ports(eal, names, configs, T0, RING, |side, port| {
        let (mtu, room) = sizes[side.index()];
        resize(port, mtu, room);
        let mut socket = tcp_socket_sized(BUFFER);
        socket.mss_cap = cap;
        let reserve = rx_reserve(
            port.rx_descriptors,
            configs[side.index()].rx_staging,
            port.rx_pool.cache_size,
        );
        let count = reserve.checked_add(tcp::rx_mbuf_budget(&socket, usize::from(port.mtu))).unwrap();
        port.rx_pool.count = u32::try_from(count).unwrap();
        port.tx_pool.count = POOL;
    })
}

/// The MSS options of the SYN and SYN-ACK in `establish_sized`'s frames,
/// which follow the ARP request and reply.
fn handshake_mss(frames: &[(Dir, Vec<u8>)], client: Side) -> [Option<u16>; 2] {
    let server = client.other();
    assert_eq!((frames[2].0, frames[3].0), (client.dir(), server.dir()));
    let syn = segment(&frames[2].1, client);
    let syn_ack = segment(&frames[3].1, server);
    assert_eq!(
        (
            syn.control,
            syn.ack_number.is_some(),
            syn_ack.control,
            syn_ack.ack_number.is_some()
        ),
        (TcpControl::Syn, false, TcpControl::Syn, true)
    );
    [syn.max_seg_size, syn_ack.max_seg_size]
}

/// `from` sends `data` and the other side reads all of it. Returns the
/// (payload, TCP header) lengths of every data segment `from` sent.
fn transfer(
    pair: &mut Pair,
    handles: &[TcpHandle; 2],
    from: Side,
    data: &[u8],
) -> Vec<(usize, usize)> {
    let to = from.other();
    let mut sizes = Vec::new();
    let mut written = 0;
    let mut read = Vec::with_capacity(data.len());
    pair.drive(
        |dir, frame| {
            if dir != from.dir() {
                return;
            }
            let tcp = segment(frame, from);
            if !tcp.payload.is_empty() {
                assert_eq!(
                    frame.len(),
                    ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + tcp.header_len() + tcp.payload.len()
                );
                sizes.push((tcp.payload.len(), tcp.header_len()));
            }
        },
        |a, b| {
            let (sender, receiver) = from.pick(a, b);
            let sent = sender
                .tcp_mut(&handles[from.index()])
                .send_slice(&data[written..])
                .unwrap();
            written += sent;
            let buffer = drain_bytes(receiver.tcp_mut(&handles[to.index()])).unwrap();
            let got = buffer.len();
            read.extend_from_slice(&buffer[..got]);
            if read.len() == data.len() {
                App::Done
            } else if sent + got > 0 {
                App::Moved
            } else {
                App::Idle
            }
        },
    );
    assert!(read == data, "received bytes differ");
    sizes
}

/// No segment exceeds the negotiated MSS; at least one fills it without TCP options.
fn assert_segments(sizes: &[(usize, usize)], mss: usize) {
    assert!(!sizes.is_empty(), "no data segment");
    let mut saw_full = false;
    for &(payload, header) in sizes {
        assert_eq!(header, TCP_HEADER_LEN);
        assert!(payload <= mss, "segment of {payload} bytes over {mss}");
        saw_full |= payload == mss;
    }
    assert!(saw_full, "no full segment: {sizes:?}");
}

fn assert_no_drops(pair: &Pair) {
    for link in [&pair.a_to_b, &pair.b_to_a] {
        assert_eq!((link.pool_empty, link.ring_full), (0, 0));
    }
}

#[zhida_test_support::pinned_test]
fn jumbo_pair_negotiates_8960_and_sends_full_segments() {
    with_eal(|eal| {
        let mut pair = sized_pair(eal, ["jmba", "jmbb"], [JUMBO, JUMBO]);
        let (handles, frames) = establish_sized(&mut pair, Side::A, BUFFER);
        // MSS = IP MTU 9000 - 20 - 20 on both sides.
        let offers = handshake_mss(&frames, Side::A);
        assert_eq!(offers, [Some(8960), Some(8960)]);
        let mss = usize::from(offers.into_iter().map(Option::unwrap).min().unwrap());
        for (from, seed) in [(Side::A, 1), (Side::B, 2)] {
            let sizes = transfer(&mut pair, &handles, from, &pattern(TRANSFER, seed));
            // A full segment is a 9014-byte frame: the whole MTU.
            assert_segments(&sizes, mss);
        }
        assert_no_drops(&pair);
        pair.close();
    });
}

#[zhida_test_support::pinned_test]
fn jumbo_pair_mss_cap_limits_both_directions() {
    with_eal(|eal| {
        let mut pair = sized_pair_with_mss_cap(eal, ["jmca", "jmcb"], [JUMBO, JUMBO], Some(1460));
        let mut socket = tcp_socket_sized(BUFFER);
        socket.mss_cap = Some(1460);
        let server = pair.b.add_tcp(socket).unwrap();
        pair.b.listen(&server, SERVER_PORT).unwrap();
        let mut socket = tcp_socket_sized(BUFFER);
        socket.mss_cap = Some(1460);
        let client = pair.a.add_tcp(socket).unwrap();
        pair.a
            .connect(&client, IpEndpoint::new(Side::B.ip().into(), SERVER_PORT), CLIENT_PORT)
            .unwrap();
        let handles = [client, server];
        let [client, server] = &handles;
        let mut frames = Vec::new();
        pair.drive(
            |dir, frame| frames.push((dir, frame.to_vec())),
            |a, b| {
                if a.tcp(&client).state() == State::Established
                    && b.tcp(&server).state() == State::Established
                {
                    App::Done
                } else {
                    App::Idle
                }
            },
        );
        assert_eq!(handshake_mss(&frames, Side::A), [Some(1460), Some(1460)]);
        for (from, seed) in [(Side::A, 5), (Side::B, 6)] {
            let sizes = transfer(&mut pair, &handles, from, &pattern(TRANSFER, seed));
            assert_segments(&sizes, 1460);
        }
        assert_eq!(
            [
                pair.a.tcp(&client).rx_refused_segments(),
                pair.b.tcp(&server).rx_refused_segments(),
            ],
            [0, 0]
        );
        assert_no_drops(&pair);
        pair.close();
    });
}

#[zhida_test_support::pinned_test]
fn mismatched_mss_respects_smaller_limit() {
    with_eal(|eal| {
        let mut pair = sized_pair(eal, ["jmma", "jmmb"], [JUMBO, STANDARD]);
        let (handles, frames) = establish_sized(&mut pair, Side::A, BUFFER);
        let offers = handshake_mss(&frames, Side::A);
        assert_eq!(offers, [Some(8960), Some(1460)]);
        let mss = usize::from(offers.into_iter().map(Option::unwrap).min().unwrap());
        // A sends no more than B's MSS allows; B no more than its own MTU.
        let mut short_from_b = 0;
        for (from, seed) in [(Side::A, 3), (Side::B, 4)] {
            let sizes = transfer(&mut pair, &handles, from, &pattern(TRANSFER, seed));
            assert_segments(&sizes, mss);
            if from == Side::B {
                short_from_b = sizes.iter().filter(|&&(payload, _)| payload < mss).count();
            }
        }
        // A's window is 6 frames x 1460 B and assumes full-sized segments. B's short segments
        // (its TX ring wrap, window-cut heads and tails) each hold a whole frame, and
        // never-shrink keeps edges promised at 0 held frames, so some in-window segments are
        // refused and retransmitted; the transfer still completes byte-exact (U54: short
        // segments holding whole frames accepted). The bound is not a receive-window
        // invariant: a full-sized segment refused again before A drains would count twice,
        // and `sizes` includes B's retransmissions. It is a tripwire for this deterministic
        // run, where every refusal traced to a short segment eating a frame. The count moves
        // with how Cubic paces B (5 before the Cubic window changes, 6 after; the extra one is
        // a 473 B tail after a 987 B head in a 6 x 1460 B flight), so it is not pinned.
        let refused = pair.a.tcp(&handles[0]).rx_refused_segments();
        assert!(refused > 0 && usize::try_from(refused).unwrap() <= short_from_b,
            "A refused {refused} segments; B sent {short_from_b} short segments");
        assert_eq!(pair.b.tcp(&handles[1]).rx_refused_segments(), 0);
        assert_no_drops(&pair);
        pair.close();
    });
}

/// At MTU 9000 RX needs 9216 usable bytes, while TX needs 9014. One byte
/// below either limit, with the other pool valid, fails before pool creation.
#[zhida_test_support::pinned_test]
fn jumbo_room_too_small_rejected() {
    with_eal(|eal| {
        let fixture = RingPort::new("jroom", 16, 16);
        let (mtu, room) = JUMBO;
        for short_rx in [true, false] {
            let mut config = fixture.config();
            resize(&mut config, mtu, room);
            let expected = if short_rx {
                config.rx_pool.data_room_size = RTE_PKTMBUF_HEADROOM as u16 + room - 1;
                PortError::InvalidSettings(
                    "RX usable room must be at least ceil1024(MTU + 26) for single-segment RX",
                )
            } else {
                config.tx_pool.data_room_size = RTE_PKTMBUF_HEADROOM as u16 + mtu + 14 - 1;
                PortError::InvalidSettings("pool room cannot hold the frame")
            };
            let error = unsafe { Port::open(eal, config) }.unwrap_err();
            assert_eq!(
                (error.cause, error.rollback_error, error.retained.is_none()),
                (expected, None, true),
                "short RX room: {short_rx}"
            );
            assert!(!fixture.pools_exist());
        }
        fixture.close();
    });
}

fn host_path(addr: Ipv4Address, mtu: u16) -> PathMtu {
    PathMtu { prefix: Ipv4Cidr::new(addr, 32), mtu }
}

fn establish_with_app_cap(pair: &mut Pair, cap: u16) -> ([TcpHandle; 2], Vec<(Dir, Vec<u8>)>) {
    let server = pair.b.add_tcp(tcp_socket_sized(BUFFER)).unwrap();
    pair.b.listen(&server, SERVER_PORT).unwrap();
    let mut socket = tcp_socket_sized(BUFFER);
    socket.mss_cap = Some(cap);
    let client = pair.a.add_tcp(socket).unwrap();
    pair.a.connect(&client, IpEndpoint::new(Side::B.ip().into(), SERVER_PORT), CLIENT_PORT)
        .unwrap();
    let handles = [client, server];
    let mut frames = Vec::new();
    pair.drive(
        |dir, frame| frames.push((dir, frame.to_vec())),
        |a, b| {
            if a.tcp(&handles[0]).state() == State::Established
                && b.tcp(&handles[1]).state() == State::Established
            {
                App::Done
            } else {
                App::Idle
            }
        },
    );
    (handles, frames)
}

#[zhida_test_support::pinned_test]
fn path_rule_caps_active_syn_mss_and_segments() {
    with_eal(|eal| {
        let paths = [host_path(Side::B.ip(), 1500)];
        let mut pair = sized_pair_with_paths(eal, ["pmtua", "pmtub"], [JUMBO, JUMBO], None, [&paths, &[]]);
        let (handles, frames) = establish_sized(&mut pair, Side::A, BUFFER);
        assert_eq!(handshake_mss(&frames, Side::A), [Some(1460), Some(8960)]);
        for (from, seed) in [(Side::A, 7), (Side::B, 8)] {
            assert_segments(&transfer(&mut pair, &handles, from, &pattern(TRANSFER, seed)), 1460);
        }
        assert_no_drops(&pair);
        pair.close();
    });
}

#[zhida_test_support::pinned_test]
fn app_cap_stricter_than_path_wins() {
    with_eal(|eal| {
        let paths = [host_path(Side::B.ip(), 1500)];
        for (cap, expected) in [(1000, 1000), (4000, 1460)] {
            let mut pair = sized_pair_with_paths(
                eal, ["pmcapa", "pmcapb"], [JUMBO, JUMBO], Some(cap), [&paths, &[]],
            );
            let (handles, frames) = establish_with_app_cap(&mut pair, cap);
            assert_eq!(handshake_mss(&frames, Side::A), [Some(expected), Some(8960)]);
            assert_segments(
                &transfer(&mut pair, &handles, Side::A, &pattern(TRANSFER, 9)),
                usize::from(expected),
            );
            assert_no_drops(&pair);
            pair.close();
        }
    });
}

#[zhida_test_support::pinned_test]
fn reconnect_reclassifies() {
    with_eal(|eal| {
        let c = Ipv4Address::new(10, 0, 0, 3);
        let paths = [host_path(Side::B.ip(), 1500), host_path(c, 4000)];
        let mut pair = sized_pair_with_paths(eal, ["pmrea", "pmreb"], [JUMBO, JUMBO], None, [&paths, &[]]);
        let client = pair.a.add_tcp(tcp_socket_sized(BUFFER)).unwrap();
        for (dst, expected) in [(Side::B.ip(), 1460), (c, 3960), (Side::B.ip(), 1460)] {
            pair.inject(Side::A, &[arp(
                ArpOperation::Reply, Side::A.mac(), (Side::B.mac(), dst),
                (Side::A.mac(), Side::A.ip()),
            )]);
            pair.a.connect(&client, IpEndpoint::new(dst.into(), SERVER_PORT), CLIENT_PORT)
                .unwrap();
            let now = pair.now();
            pair.a.turn(now, BUDGET).unwrap();
            let mut offers = Vec::new();
            pair.drain_tx(Side::A, |frame| {
                let eth = EthernetFrame::new_checked(frame).unwrap();
                assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);
                let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
                assert_eq!((ip.src_addr(), ip.dst_addr()), (Side::A.ip(), dst));
                let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
                let repr = TcpRepr::parse(
                    &tcp, &Side::A.ip().into(), &dst.into(), &ChecksumCapabilities::default(),
                ).unwrap();
                assert_eq!((repr.control, repr.ack_number), (TcpControl::Syn, None));
                offers.push(repr.max_seg_size);
            });
            assert_eq!(offers, [Some(expected)]);
            pair.a.tcp_mut(&client).abort();
            assert_eq!(pair.a.tcp(&client).state(), State::Closed);
            let now = pair.now();
            pair.a.turn(now, BUDGET).unwrap();
            assert_eq!(pair.drain_tx(Side::A, |_| {}), 1);
        }
        assert_no_drops(&pair);
        pair.close();
    });
}

#[zhida_test_support::pinned_test]
fn longest_prefix_wins_and_subnet_is_implicit() {
    with_eal(|eal| {
        let default = PathMtu { prefix: "0.0.0.0/0".parse().unwrap(), mtu: 1500 };
        let rules = [default, host_path(Side::B.ip(), 4000)];
        for (paths, expected) in [(&rules[..1], 8960), (&rules[..], 3960)] {
            let mut pair = sized_pair_with_paths(eal, ["pmlpa", "pmlpb"], [JUMBO, JUMBO], None, [paths, &[]]);
            let (_, frames) = establish_sized(&mut pair, Side::A, BUFFER);
            assert_eq!(handshake_mss(&frames, Side::A), [Some(expected), Some(8960)]);
            assert_no_drops(&pair);
            pair.close();
        }
    });
}

#[zhida_test_support::pinned_test]
fn empty_paths_keep_port_mtu() {
    with_eal(|eal| {
        let mut pair = sized_pair_with_paths(eal, ["pmempa", "pmempb"], [JUMBO, JUMBO], None, [&[], &[]]);
        let (handles, frames) = establish_sized(&mut pair, Side::A, BUFFER);
        assert_eq!(handshake_mss(&frames, Side::A), [Some(8960), Some(8960)]);
        assert_segments(&transfer(&mut pair, &handles, Side::A, &pattern(TRANSFER, 10)), 8960);
        assert_no_drops(&pair);
        pair.close();
    });
}

#[zhida_test_support::pinned_test]
fn path_rule_window_uses_capped_frame_bytes() {
    with_eal(|eal| {
        let paths = [host_path(Side::B.ip(), 1500)];
        let mut pair = sized_pair_with_paths(eal, ["pmwina", "pmwinb"], [JUMBO, JUMBO], None, [&paths, &[]]);
        let budget = tcp::rx_mbuf_budget(&tcp_socket_sized(BUFFER), 9000);
        assert_eq!(budget, 6);
        let (handles, frames) = establish_sized(&mut pair, Side::A, BUFFER);
        assert_eq!(pair.a.tcp(&handles[0]).rx_frame_cap(), budget);
        let syn = segment(&frames[2].1, Side::A);
        assert_eq!(frames[4].0, Side::A.dir());
        let ack = segment(&frames[4].1, Side::A);
        assert_eq!(ack.control, TcpControl::None);
        assert!(ack.ack_number.is_some());
        let expected = budget.checked_mul(1460).unwrap().min(BUFFER);
        assert_eq!(expected, 8760);
        assert_eq!(usize::from(ack.window_len) << syn.window_scale.unwrap(), expected);
        assert_no_drops(&pair);
        pair.close();
    });
}

#[zhida_test_support::pinned_test]
fn path_rule_caps_passive_synack_mss_from_syn_source() {
    with_eal(|eal| {
        let paths = [host_path(Side::A.ip(), 1500)];
        for (cap, expected) in [(None, 1460), (Some(1000), 1000)] {
            let mut pair = sized_pair_with_paths(
                eal, ["pmpasa", "pmpasb"], [JUMBO, JUMBO], cap, [&[], &paths],
            );
            let mut socket = tcp_socket_sized(BUFFER);
            socket.mss_cap = cap;
            let budget = tcp::rx_mbuf_budget(&socket, 9000);
            let server = pair.b.add_tcp(socket).unwrap();
            pair.b.listen(&server, SERVER_PORT).unwrap();
            let client = pair.a.add_tcp(tcp_socket_sized(BUFFER)).unwrap();
            pair.a.connect(&client, IpEndpoint::new(Side::B.ip().into(), SERVER_PORT), CLIENT_PORT)
                .unwrap();
            let handles = [client, server];
            let mut frames = Vec::new();
            pair.drive(
                |dir, frame| frames.push((dir, frame.to_vec())),
                |a, b| {
                    if a.tcp(&handles[0]).state() == State::Established
                        && b.tcp(&handles[1]).state() == State::Established
                    {
                        App::Done
                    } else {
                        App::Idle
                    }
                },
            );
            assert_eq!(handshake_mss(&frames, Side::A), [Some(8960), Some(expected)]);
            assert_eq!(pair.b.tcp(&handles[1]).rx_frame_cap(), budget);
            let syn_ack = segment(&frames[3].1, Side::B);
            let window = budget.checked_mul(usize::from(expected))
                .expect("receive window exceeds usize").min(BUFFER);
            assert_eq!(usize::from(syn_ack.window_len), window);
            for (from, seed) in [(Side::A, 11), (Side::B, 12)] {
                assert_segments(
                    &transfer(&mut pair, &handles, from, &pattern(TRANSFER, seed)),
                    usize::from(expected),
                );
            }
            assert_no_drops(&pair);
            pair.close();
        }
    });
}

fn listener_reply(
    pair: &mut Pair,
    src: Ipv4Address,
    ack_number: Option<TcpSeqNumber>,
) -> (TcpControl, Option<u16>) {
    let syn = TcpRepr {
        src_port: CLIENT_PORT,
        dst_port: SERVER_PORT,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(7000),
        ack_number,
        window_len: 32768,
        window_scale: None,
        max_seg_size: Some(8960),
        sack_permitted: true,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };
    pair.inject(Side::B, &[
        arp(
            ArpOperation::Reply, Side::B.mac(), (Side::A.mac(), src),
            (Side::B.mac(), Side::B.ip()),
        ),
        tcp_frame_between((Side::A.mac(), src), (Side::B.mac(), Side::B.ip()), &syn),
    ]);
    let now = pair.now();
    pair.b.turn(now, BUDGET).unwrap();
    let mut replies = Vec::new();
    pair.drain_tx(Side::B, |frame| {
        let eth = EthernetFrame::new_checked(frame).unwrap();
        assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);
        assert_eq!((eth.src_addr(), eth.dst_addr()), (Side::B.mac(), Side::A.mac()));
        let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
        assert_eq!((ip.src_addr(), ip.dst_addr()), (Side::B.ip(), src));
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let repr = TcpRepr::parse(
            &tcp, &Side::B.ip().into(), &src.into(), &ChecksumCapabilities::default(),
        ).unwrap();
        assert_eq!((repr.src_port, repr.dst_port), (SERVER_PORT, CLIENT_PORT));
        if let Some(ack_number) = ack_number {
            assert_eq!(repr.seq_number, ack_number);
        } else {
            assert_eq!(repr.ack_number, Some(syn.seq_number + 1));
        }
        replies.push((repr.control, repr.max_seg_size));
    });
    assert_eq!(replies.len(), 1);
    replies[0]
}

#[zhida_test_support::pinned_test]
fn listener_reuse_reclassifies() {
    with_eal(|eal| {
        let c = Ipv4Address::new(10, 0, 0, 3);
        let paths = [host_path(Side::A.ip(), 1500)];
        let mut pair = sized_pair_with_paths(
            eal, ["pmlrea", "pmlreb"], [JUMBO, JUMBO], None, [&[], &paths],
        );
        let server = pair.b.add_tcp(tcp_socket_sized(BUFFER)).unwrap();
        for (src, expected) in [(Side::A.ip(), 1460), (c, 8960), (Side::A.ip(), 1460)] {
            pair.b.listen(&server, SERVER_PORT).unwrap();
            assert_eq!(pair.b.tcp(&server).state(), State::Listen);
            assert_eq!(listener_reply(&mut pair, src, None), (TcpControl::Syn, Some(expected)));
            assert_eq!(pair.b.tcp(&server).state(), State::SynReceived);
            pair.b.tcp_mut(&server).abort();
            assert_eq!(pair.b.tcp(&server).state(), State::Closed);
            let now = pair.now();
            pair.b.turn(now, BUDGET).unwrap();
            assert_eq!(pair.drain_tx(Side::B, |_| {}), 1);
        }
        assert_no_drops(&pair);
        pair.close();
    });
}

#[zhida_test_support::pinned_test]
fn invalid_syn_leaves_listener_unchanged() {
    with_eal(|eal| {
        let x = Ipv4Address::new(10, 0, 0, 3);
        let paths = [host_path(x, 1500)];
        let mut pair = sized_pair_with_paths(
            eal, ["pminva", "pminvb"], [JUMBO, JUMBO], None, [&[], &paths],
        );
        let server = pair.b.add_tcp(tcp_socket_sized(BUFFER)).unwrap();
        pair.b.listen(&server, SERVER_PORT).unwrap();
        // accepts() rejects a SYN carrying an ACK in Listen, so the interface sends RST.
        assert_eq!(
            listener_reply(&mut pair, x, Some(TcpSeqNumber(9000))),
            (TcpControl::Rst, None),
        );
        assert_eq!(pair.b.tcp(&server).state(), State::Listen);
        assert_eq!(pair.b.tcp(&server).local_endpoint(), None);
        assert_eq!(pair.b.tcp(&server).remote_endpoint(), None);
        assert_eq!(listener_reply(&mut pair, Side::A.ip(), None), (TcpControl::Syn, Some(8960)));
        assert_eq!(pair.b.tcp(&server).state(), State::SynReceived);
        pair.b.tcp_mut(&server).abort();
        let now = pair.now();
        pair.b.turn(now, BUDGET).unwrap();
        assert_eq!(pair.drain_tx(Side::B, |_| {}), 1);
        pair.b.remove_tcp(server);
        let fresh = pair.b.add_tcp(tcp_socket_sized(BUFFER)).unwrap();
        pair.b.listen(&fresh, SERVER_PORT).unwrap();
        assert_eq!(listener_reply(&mut pair, x, None), (TcpControl::Syn, Some(1460)));
        assert_eq!(pair.b.tcp(&fresh).state(), State::SynReceived);
        assert_no_drops(&pair);
        pair.close();
    });
}
