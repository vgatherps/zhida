//! Frames a test builds and moves itself: `tcp_frame` emits what smoltcp's
//! wire parser reads back, `Pair::inject` and `Pair::drain_tx` reach a
//! Stack's rings without the peer, a full RX ring fails `Pair::inject`
//! without leaking, and `Pair::with_ports` RX bursts let one turn take more
//! than the default 8 frames.

use std::panic::{catch_unwind, AssertUnwindSafe};

use zhida_test_kit::pair::{config, new_pair, segment, tcp_frame, Pair, Side, T0};
use zhida_test_kit::ring_port::{self, frame};
use zhida_test_kit::with_eal;
use dpdk_smoltcp::smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol, IpAddress,
    IpProtocol, Ipv4Packet, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
};
use dpdk_smoltcp::{rx_pool_count, rx_reserve, Turn};

/// A's ARP request for B's address.
fn arp_request() -> Vec<u8> {
    ring_port::arp(
        ArpOperation::Request,
        EthernetAddress::BROADCAST,
        (Side::A.mac(), Side::A.ip()),
        (EthernetAddress([0; 6]), Side::B.ip()),
    )
}

/// B's reply to `arp_request`.
fn assert_arp_reply(frame: &[u8]) {
    let eth = EthernetFrame::new_checked(frame).unwrap();
    assert_eq!(
        (eth.src_addr(), eth.dst_addr(), eth.ethertype()),
        (Side::B.mac(), Side::A.mac(), EthernetProtocol::Arp)
    );
    let arp = ArpRepr::parse(&ArpPacket::new_checked(eth.payload()).unwrap()).unwrap();
    assert_eq!(
        arp,
        ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: Side::B.mac(),
            source_protocol_addr: Side::B.ip(),
            target_hardware_addr: Side::A.mac(),
            target_protocol_addr: Side::A.ip(),
        }
    );
}

/// (received, processed, accepted), with nothing staged, blocked or pending.
fn counts(turn: &Turn) -> (usize, usize, usize) {
    assert_eq!(
        (
            turn.rx_rejected,
            turn.rx_staged,
            turn.rx_blocked,
            turn.tx_pending
        ),
        (0, 0, false, 0),
        "{turn:?}"
    );
    (turn.rx_received, turn.rx_processed, turn.tx_accepted)
}

#[zhida_test_support::pinned_test]
fn tcp_frame_parses_back_to_its_segment() {
    let payload = *b"abc";
    let segments = [
        TcpRepr {
            src_port: 1234,
            dst_port: 80,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(7_000),
            ack_number: Some(TcpSeqNumber(9)),
            window_len: 512,
            window_scale: None,
            max_seg_size: Some(1460),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        },
        TcpRepr {
            src_port: 80,
            dst_port: 1234,
            control: TcpControl::Rst,
            seq_number: TcpSeqNumber(-5),
            ack_number: None,
            window_len: 0,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        },
        TcpRepr {
            src_port: 4321,
            dst_port: 8080,
            control: TcpControl::None,
            seq_number: TcpSeqNumber(100),
            ack_number: Some(TcpSeqNumber(200)),
            window_len: 1024,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &payload,
        },
    ];
    for (src, repr) in [Side::A, Side::B, Side::A].into_iter().zip(&segments) {
        let dst = src.other();
        let frame = tcp_frame(src, repr);

        let eth = EthernetFrame::new_checked(&frame[..]).unwrap();
        assert_eq!(
            (eth.src_addr(), eth.dst_addr(), eth.ethertype()),
            (src.mac(), dst.mac(), EthernetProtocol::Ipv4)
        );
        let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
        assert!(ip.verify_checksum());
        assert_eq!(
            (ip.src_addr(), ip.dst_addr(), ip.next_header()),
            (src.ip(), dst.ip(), IpProtocol::Tcp)
        );
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.verify_checksum(&IpAddress::Ipv4(src.ip()), &IpAddress::Ipv4(dst.ip())));
        assert_eq!(
            (
                tcp.src_port(),
                tcp.dst_port(),
                tcp.seq_number(),
                tcp.window_len()
            ),
            (
                repr.src_port,
                repr.dst_port,
                repr.seq_number,
                repr.window_len
            )
        );
        assert_eq!(
            (tcp.syn(), tcp.rst(), tcp.fin(), tcp.ack()),
            (
                repr.control == TcpControl::Syn,
                repr.control == TcpControl::Rst,
                false,
                repr.ack_number.is_some()
            )
        );
        if let Some(ack) = repr.ack_number {
            assert_eq!(tcp.ack_number(), ack);
        }
        assert_eq!(tcp.payload(), repr.payload);

        assert_eq!(segment(&frame, src), *repr);
    }
}

#[zhida_test_support::pinned_test]
fn inject_and_drain_tx_reach_one_stack_without_the_peer() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["kfia", "kfib"]);
        let now = pair.now();
        assert_eq!(
            pair.drain_tx(Side::B, |_| panic!("frame before any turn")),
            0
        );

        pair.inject(Side::B, &[arp_request()]);
        assert_eq!(counts(&pair.b.turn(now, 8).unwrap()), (1, 1, 1));
        let mut replies = Vec::new();
        assert_eq!(
            pair.drain_tx(Side::B, |frame| replies.push(frame.to_vec())),
            1
        );
        assert_eq!(pair.drain_tx(Side::B, |_| panic!("TX ring not drained")), 0);
        assert_arp_reply(&replies[0]);

        // An ACK to a port with no socket: smoltcp answers one RST whose
        // sequence number is the ACK's acknowledgment number.
        let ack = tcp_frame(
            Side::A,
            &TcpRepr {
                src_port: 49_152,
                dst_port: 80,
                control: TcpControl::None,
                seq_number: TcpSeqNumber(1_000),
                ack_number: Some(TcpSeqNumber(2_000)),
                window_len: 1024,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None; 3],
                timestamp: None,
                payload: &[],
            },
        );
        pair.inject(Side::B, &[ack]);
        assert_eq!(counts(&pair.b.turn(now, 8).unwrap()), (1, 1, 1));
        let drained = pair.drain_tx(Side::B, |frame| {
            let rst = segment(frame, Side::B);
            assert_eq!(
                (rst.src_port, rst.dst_port, rst.control, rst.seq_number),
                (80, 49_152, TcpControl::Rst, TcpSeqNumber(2_000))
            );
        });
        assert_eq!(drained, 1);

        // A saw neither reply, and nothing is left to move.
        let round = pair.round(|dir, frame| panic!("{dir:?} {frame:02x?}"));
        assert_eq!((round.a.rx_received, round.a_to_b, round.b_to_a), (0, 0, 0));
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn with_ports_rx_burst_lets_one_turn_take_more_than_eight_frames() {
    with_eal(|eal| {
        // Default Ports: RX bursts of 8, so 12 requests take two turns.
        let mut pair = new_pair(eal, ["kfda", "kfdb"]);
        let now = pair.now();
        pair.inject(Side::B, &vec![arp_request(); 12]);
        for expected in [8, 4] {
            let turn = pair.b.turn(now, 32).unwrap();
            assert_eq!(
                (turn.rx_received, turn.rx_processed, turn.tx_accepted),
                (expected, expected, expected)
            );
            assert_eq!(pair.drain_tx(Side::B, assert_arp_reply), expected);
        }
        assert_eq!(pair.close(), 0);

        // RX bursts of 32: one turn takes all 20, and draining its replies
        // takes more than one 16-frame dequeue.
        let configs = [config(Side::A), config(Side::B)];
        let mut pair = Pair::with_ports(eal, ["kfwa", "kfwb"], configs, T0, 64, |side, port| {
            port.rx_burst = 32;
            port.rx_pool.count = rx_pool_count(
                rx_reserve(
                    port.rx_descriptors,
                    configs[side.index()].rx_staging,
                    port.rx_pool.cache_size,
                ),
                port.mtu,
                [],
            );
        });
        let now = pair.now();
        pair.inject(Side::B, &vec![arp_request(); 20]);
        assert_eq!(counts(&pair.b.turn(now, 32).unwrap()), (20, 20, 20));
        assert_eq!(pair.drain_tx(Side::B, assert_arp_reply), 20);
        assert_eq!(pair.drain_tx(Side::B, |_| panic!("TX ring not drained")), 0);
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn pair_inject_into_a_full_rx_ring_frees_the_frame_it_refused() {
    with_eal(|eal| {
        // B's RX ring holds 15.
        let pair = new_pair(eal, ["kffa", "kffb"]);
        let frames: Vec<_> = (0..16).map(frame).collect();
        let payload = catch_unwind(AssertUnwindSafe(|| pair.inject(Side::B, &frames))).unwrap_err();
        let message = match payload.downcast::<String>() {
            Ok(message) => *message,
            Err(payload) => payload.downcast_ref::<&str>().unwrap().to_string(),
        };
        assert!(message.contains("RX ring full"), "{message}");
        assert_eq!(pair.in_use(), [(0, 0), (15, 0)]);
        assert_eq!(pair.close(), 15);
    });
}
