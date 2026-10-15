//! Stack connections omit TCP timestamps; caller time still controls timers.

use zhida_test_kit::pair::drain_bytes;
use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::socket::tcp::{self, State};
use dpdk_smoltcp::smoltcp::time::{Duration, Instant};
use dpdk_smoltcp::smoltcp::wire::{
    ArpOperation, EthernetAddress, EthernetFrame, EthernetProtocol, IpEndpoint, TcpControl,
    TcpRepr, TcpSeqNumber, TcpTimestampRepr,
};

use zhida_test_kit::{pair, wire, with_eal};
use zhida_test_kit::ring_port::arp;
use pair::{ceil_ms, config, segment, tcp_socket_sized, Dir, Pair, Side, CLIENT_PORT, SERVER_PORT, T0};
use wire::Verdict;

const BUDGET: usize = 32;
/// Upstream `ACK_DELAY_DEFAULT`.
const ACK_DELAY: Duration = Duration::from_millis(10);
/// Default socket RTO.
const RTO: Duration = Duration::from_millis(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    dir: Dir,
    control: TcpControl,
    len: usize,
    ts: Option<TcpTimestampRepr>,
}

fn stamp(dir: Dir, control: TcpControl, len: usize) -> Stamp {
    Stamp {
        dir,
        control,
        len,
        ts: None,
    }
}

fn ms(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

/// The TCP segment's stamp; `None` for ARP.
fn observe(dir: Dir, frame: &[u8]) -> Option<Stamp> {
    if EthernetFrame::new_checked(frame).unwrap().ethertype() == EthernetProtocol::Arp {
        return None;
    }
    let src = match dir {
        Dir::AToB => Side::A,
        Dir::BToA => Side::B,
    };
    let tcp = segment(frame, src);
    Some(Stamp {
        dir,
        control: tcp.control,
        len: tcp.payload.len(),
        ts: tcp.timestamp,
    })
}

/// A turns at `at[0]`, A→B, B turns at `at[1]`, B→A: each Stack on its own
/// clock. Returns every delivered TCP segment's stamp. Nothing stays pending,
/// so each segment leaves in the turn that built it.
fn round(pair: &mut Pair, at: [Instant; 2]) -> Vec<Stamp> {
    let mut stamps = Vec::new();
    let a = pair.a.turn(at[0], BUDGET).unwrap();
    pair.a_to_b.forward_with(|frame| stamps.extend(observe(Dir::AToB, frame)));
    let b = pair.b.turn(at[1], BUDGET).unwrap();
    pair.b_to_a.forward_with(|frame| stamps.extend(observe(Dir::BToA, frame)));
    assert_eq!((a.tx_pending, b.tx_pending), (0, 0));
    stamps
}

/// A connects with `client` from CLIENT_PORT to a listener on B. Returns the
/// handles, A then B.
fn connect(pair: &mut Pair, client: tcp::Config) -> [TcpHandle; 2] {
    let b = pair.b.add_tcp(tcp_socket_sized(4096)).unwrap();
    pair.b.listen(&b, SERVER_PORT).unwrap();
    let a = pair.a.add_tcp(client).unwrap();
    pair.a
        .connect(&a, IpEndpoint::new(Side::B.ip().into(), SERVER_PORT), CLIENT_PORT)
        .unwrap();
    [a, b]
}

/// Rounds at `at(k)` for round k = 0, 1, ... until both sockets are
/// Established; returns the stamps and the next k.
fn establish(
    pair: &mut Pair,
    handles: &[TcpHandle; 2],
    at: impl Fn(u64) -> [Instant; 2],
) -> (Vec<Stamp>, u64) {
    let mut stamps = Vec::new();
    for k in 0..8 {
        stamps.extend(round(pair, at(k)));
        if pair.a.tcp(&handles[0]).state() == State::Established
            && pair.b.tcp(&handles[1]).state() == State::Established
        {
            return (stamps, k + 1);
        }
    }
    panic!("not established after 8 rounds");
}

/// `ping` from A and `pong` from B, both queued before one round at `at`.
fn exchange(pair: &mut Pair, handles: &[TcpHandle; 2], at: [Instant; 2]) -> Vec<Stamp> {
    assert_eq!(pair.a.tcp_mut(&handles[0]).send_slice(b"ping"), Ok(4));
    assert_eq!(pair.b.tcp_mut(&handles[1]).send_slice(b"pong"), Ok(4));
    round(pair, at)
}

#[zhida_test_support::pinned_test]
fn stack_connections_never_negotiate_timestamps() {
    with_eal(|eal| {
        let mut pair = Pair::new(eal, ["tsna", "tsnb"], [config(Side::A), config(Side::B)], T0);
        let handles = connect(&mut pair, tcp_socket_sized(4096));
        // Round k at T0 + k ms on both.
        let (mut stamps, k) = establish(&mut pair, &handles, |k| [T0 + ms(k); 2]);
        assert_eq!(k, 3);
        stamps.extend(exchange(&mut pair, &handles, [T0 + ms(10); 2]));
        assert_eq!(
            stamps,
            [
                // Round 0 resolves ARP; round 1 offers and accepts.
                stamp(Dir::AToB, TcpControl::Syn, 0),
                stamp(Dir::BToA, TcpControl::Syn, 0),
                stamp(Dir::AToB, TcpControl::None, 0),
                stamp(Dir::AToB, TcpControl::Psh, 4),
                stamp(Dir::BToA, TcpControl::Psh, 4),
            ]
        );
        // B's pong, still on A's RX ring.
        assert_eq!(pair.close(), 1);
    });
}

fn timer_segments(stamps: Vec<Stamp>) -> Vec<(Dir, TcpControl, usize)> {
    stamps
        .into_iter()
        .map(|stamp| (stamp.dir, stamp.control, stamp.len))
        .collect()
}

#[zhida_test_support::pinned_test]
fn caller_time_controls_retransmission_and_delayed_ack() {
    with_eal(|eal| {
        // Timers use the full caller time, including times beyond 2^32 ms.
        let w = Instant::from_millis((1i64 << 32) + 5_000);
        let mut pair = Pair::new(eal, ["tsta", "tstb"], [config(Side::A), config(Side::B)], w);
        let handles = connect(&mut pair, tcp_socket_sized(4096));
        // Establish without advancing caller time.
        establish(&mut pair, &handles, |_| [w; 2]);

        // B acknowledges at its delayed-ACK deadline.
        let sent = w + ms(7);
        assert_eq!(pair.a.tcp_mut(&handles[0]).send_slice(b"hello"), Ok(5));
        assert_eq!(
            timer_segments(round(&mut pair, [sent; 2])),
            [(Dir::AToB, TcpControl::Psh, 5)]
        );
        assert!(matches!(pair.b.poll_at(), Some(p) if p > sent && p <= ceil_ms(sent + ACK_DELAY)));
        assert_eq!(round(&mut pair, [sent + ACK_DELAY - ms(1); 2]), []);
        assert_eq!(
            timer_segments(round(&mut pair, [sent + ACK_DELAY; 2])),
            [(Dir::BToA, TcpControl::None, 0)]
        );

        // A retransmits at its RTO deadline.
        let mut dropped = false;
        pair.a_to_b.impair(move |_| {
            if dropped {
                Verdict::Deliver
            } else {
                dropped = true;
                Verdict::Drop
            }
        });
        let sent = w + ms(20);
        assert_eq!(pair.a.tcp_mut(&handles[0]).send_slice(b"world"), Ok(5));
        assert_eq!(round(&mut pair, [sent; 2]), []);
        assert_eq!(pair.a_to_b.dropped, 1);
        assert!(matches!(pair.a.poll_at(), Some(p) if p > sent && p <= ceil_ms(sent + RTO)));
        assert_eq!(round(&mut pair, [sent + RTO - ms(1); 2]), []);
        assert_eq!(
            timer_segments(round(&mut pair, [sent + RTO; 2])),
            [(Dir::AToB, TcpControl::Psh, 5)]
        );
        assert_eq!(pair.close(), 0);
    });
}

/// A peer offers timestamps in its SYN, then completes the connection.
#[zhida_test_support::pinned_test]
fn stack_declines_peer_timestamp_offer() {
    with_eal(|eal| {
        let mut pair = Pair::new(eal, ["tspa", "tspb"], [config(Side::A), config(Side::B)], T0);
        let b = pair.b.add_tcp(tcp_socket_sized(4096)).unwrap();
        pair.b.listen(&b, SERVER_PORT).unwrap();
        let peer_isn = TcpSeqNumber(7000);
        let mut peer = TcpRepr {
            src_port: CLIENT_PORT,
            dst_port: SERVER_PORT,
            control: TcpControl::Syn,
            seq_number: peer_isn,
            ack_number: None,
            window_len: 4096,
            window_scale: None,
            max_seg_size: Some(1460),
            sack_permitted: true,
            sack_ranges: [None; 3],
            timestamp: Some(TcpTimestampRepr::new(900, 0)),
            payload: &[],
        };
        pair.inject(Side::B, &[
            arp(
                ArpOperation::Request,
                EthernetAddress::BROADCAST,
                (Side::A.mac(), Side::A.ip()),
                (EthernetAddress([0; 6]), Side::B.ip()),
            ),
            pair::tcp_frame(Side::A, &peer),
        ]);
        pair.b.turn(T0, BUDGET).unwrap();
        let mut replies = Vec::new();
        let sent = pair.drain_tx(Side::B, |frame| {
            if EthernetFrame::new_checked(frame).unwrap().ethertype() == EthernetProtocol::Ipv4 {
                replies.push(frame.to_vec());
            }
        });
        assert_eq!(sent, 2);
        assert_eq!(replies.len(), 1);
        let syn_ack = segment(&replies[0], Side::B);
        assert_eq!(
            (syn_ack.control, syn_ack.ack_number, syn_ack.timestamp),
            (TcpControl::Syn, Some(peer_isn + 1), None)
        );
        peer.control = TcpControl::None;
        peer.seq_number = peer_isn + 1;
        peer.ack_number = Some(syn_ack.seq_number + 1);
        peer.max_seg_size = None;
        peer.sack_permitted = false;
        peer.timestamp = None;
        pair.inject(Side::B, &[pair::tcp_frame(Side::A, &peer)]);
        pair.b.turn(T0, BUDGET).unwrap();
        assert_eq!(pair.b.tcp(&b).state(), State::Established);
        assert_eq!(pair.b.tcp_mut(&b).send_slice(b"pong"), Ok(4));
        pair.b.turn(T0 + ms(1), BUDGET).unwrap();
        replies.clear();
        pair.drain_tx(Side::B, |frame| replies.push(frame.to_vec()));
        assert_eq!(replies.len(), 1);
        let data = segment(&replies[0], Side::B);
        assert_eq!((data.payload, data.timestamp), (&b"pong"[..], None));
        peer.control = TcpControl::Psh;
        peer.ack_number = Some(data.seq_number + 4);
        peer.payload = b"ping";
        pair.inject(Side::B, &[pair::tcp_frame(Side::A, &peer)]);
        pair.b.turn(T0 + ms(2), BUDGET).unwrap();
        pair.b.turn(T0 + ms(2) + ACK_DELAY, BUDGET).unwrap();
        replies.clear();
        pair.drain_tx(Side::B, |frame| replies.push(frame.to_vec()));
        assert_eq!(replies.len(), 1);
        let ack = segment(&replies[0], Side::B);
        assert_eq!(
            (ack.control, ack.ack_number, ack.payload, ack.timestamp),
            (TcpControl::None, Some(peer_isn + 5), &[][..], None)
        );
        let received = drain_bytes(pair.b.tcp_mut(&b)).unwrap();
        assert_eq!(received.len(), 4);
        assert_eq!(&received, b"ping");
        assert_eq!(pair.close(), 0);
    });
}
