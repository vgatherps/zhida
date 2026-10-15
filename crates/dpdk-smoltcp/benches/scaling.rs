//! Cost against the number of TCP sockets on each Stack, criterion groups
//! "scaling", "scaling_poll_at", "scaling_ingress", "scaling_active" and
//! "scaling_churn". N, per Stack, in `COUNTS` unless stated; every Stack has
//! `max_sockets` N.
//!
//! round_low/N, round_mid/N, round_high/N: established_tcp_turn's round
//! (benches/stack.rs, `established::Established`) over a Pair, with N-1 idle
//! filler connections besides the active one (kit `many`: each its own port
//! pair, 256-byte buffers, Established, nothing queued). round_low connects
//! the active connection first, so it holds slot 0 on both Stacks; round_mid
//! opens N/2 fillers, then the active connection, then the rest, and checks
//! it holds slot N/2 on both; round_high opens the fillers first and checks
//! the active connection holds slot N-1 on both. The fillers are checked
//! quiet (no deadline, a round moves no frame) before warmup, and every timed
//! round asserts exactly the active connection's frames, so they send
//! nothing. Throughput element = one forwarded frame (`SEGMENTS` data
//! segments + 1 ACK per round), as in established_tcp_turn.
//! round_capacity/N: the same round on Stacks with N slots and only the
//! active connection. N = 1 runs round_low only (all four cases coincide).
//!
//! scaling_poll_at idle/N, deadlines/N, spread/N: one `Stack::poll_at` on B
//! of the round_low Pair after its round bench, first with no deadline.
//! deadlines sends one byte per server with a 60 s RTO, drains those frames
//! without forwarding to A, and leaves them unacknowledged. This replaces the
//! old one-hour inactivity timeout workload; RTO is capped at 60 s.
//! Untimed ACKs cancel all timers before spread sends another byte per server
//! with RTO 60 s - slot ms. Each socket's deadline is read while only its
//! timer is armed, then all timers are armed and the earliest must match.
//! These eight deadline/spread cases need a new benchmark baseline.
//!
//! scaling_ingress miss/N, syn_rst/N: B of a Pair with N-1 fillers in slots
//! 0..N-2, checked quiet as for round_*, and told A's MAC by an untimed ARP
//! request, so its replies need no address resolution, also at N = 1. Frames
//! go straight onto B's RX ring as A's, B's sent frames straight off its TX
//! ring (A never sees them), and each step is one B turn at the Pair's time
//! that must receive and process the one frame and send exactly the stated
//! frames. miss: an ACK (no options) from A's `CLIENT_PORT` to B's
//! `SERVER_PORT`, where no socket listens; no socket takes it and smoltcp
//! answers one RST (checked untimed: ports, its sequence number is the ACK's
//! acknowledgment number). syn_rst, after miss: a listener on `SERVER_PORT`
//! is added in slot N-1 (checked); a SYN from the same client port, one
//! SYN-ACK out (checked untimed: ports, acknowledges the SYN), then an RST
//! with the next sequence number, nothing out, and the listener is back in
//! Listen. Afterwards the fillers are checked quiet again. Throughput element
//! = one ACK (miss), one SYN + RST pair (syn_rst).
//!
//! scaling_active round/A/N (N in `ACTIVE_COUNTS`, A in 1 and 64) and rto/N
//! (N in `RTO_COUNTS`): one Pair per N with N connections (kit `many`,
//! 256-byte buffers), connection i in slot i on both Stacks (checked), every
//! server acknowledging at once (ACK delay off, so a round leaves nothing
//! outstanding at the fixed time), all checked quiet. Its Stacks stage and
//! keep pending 32 frames, the kit's Pair turn budget (`pair::BUDGET`), and
//! its Ports take RX bursts of 32 with 64-slot rings, so every turn takes
//! all the peer's turn sent and no frame waits on or drops at a full ring
//! (the kit default's RX bursts of 8 and 15-frame rings would drop). In
//! round/A/N the active connections are the last of each N/A consecutive
//! slots (A = 1: slot N-1); the rest are quiet fillers. One round, all
//! timed: each active client writes one 64-byte message, Pair rounds at the
//! fixed time run until one moves nothing (failing after `MAX_ROUNDS`), and
//! each active server reads its message; the rounds must carry exactly A
//! segments A→B and A ACKs B→A. rto/N is that round with all N active (each
//! write arms the client's retransmission timer, each ACK stops it)
//! followed by `Stack::poll_at` on A, which must be None; from N = 10240 it
//! takes criterion's minimum 10 samples. Untimed before each case: one round
//! in which every server's read must equal the message, then the Pair
//! checked quiet; for rto first a message on connection 0 alone, after
//! whose first Pair round (segment out, ACK back but not yet taken) A's
//! `poll_at` must be a future time, the armed retransmission timer. After
//! each case, quiet again. Throughput element = one delivered message.
//!
//! rto_expiry/N, N = 64 and 10240: send on every connection and drop its
//! ACK, then time only A's turn at `poll_at` that retransmits 32 messages;
//! earlier `poll_at` wakes at timer-wheel boundaries send nothing and their
//! time is discarded. Forwarding, recovery and a fresh acknowledged round to
//! reset the RTT estimator are untimed. Throughput element = one
//! retransmission.
//!
//! scaling_active pressure/N, N = `PRESSURE_N`: a Stack sends at most
//! `tx_pending` frames per turn. Its pending TX queue is flushed to the Port
//! only at the start and end of a turn, so once it holds `tx_pending`
//! frames smoltcp egress gets no transmit token and stops at the refusal,
//! having visited slots from 0. (With the kit's default Ports the rings bind
//! first: at most 15 frames leave a Stack per round, and the peer takes 8 per
//! turn.) Here both Stacks have `tx_pending` and RX staging 64 and turn with
//! budget 64, and the Ports take RX bursts of 64 with 128-slot rings, so
//! `tx_pending` is the limit. N connections set up as above, with 1024-byte
//! buffers; each client keeps 256 bytes queued, refilled once B has
//! acknowledged them, so it sends them as one segment and B's window never
//! closes. One turn: A's turn (takes the previous turn's 64 ACKs, sends
//! exactly 64 segments, one from each of 64 clients), A→B, B's turn (takes
//! the 64, sends 64 ACKs), B→A; then each server that received reads its
//! 256 bytes and each client acknowledged this turn refills. One iteration,
//! all timed, is `PRESSURE_TURNS` turns; throughput element = one segment.
//! Untimed, the first turn must send from slots 0..63, every read equal to
//! the refilled bytes. After the bench an untimed window of
//! `PRESSURE_TURNS` turns, reads checked the same way, counts segments per
//! client and prints the min and max: fairness is reported, not asserted,
//! beyond a positive total. Today's egress scan from slot 0 gives a fixed
//! pattern: clients 0..63 send in one turn and 64..127 in the next, because
//! a client refills only after the turn that brings its ACK, so in that
//! turn its queue is empty and the scan passes it; 128..1023 never send.
//! The line reads min 0, max 32, total 4096.
//!
//! scaling_churn remove_add_low/N, remove_add_high/N: `Stack::remove_tcp`
//! then `Stack::add_tcp` of the same Closed socket, on a Stack whose N slots
//! all hold Closed sockets; the freed slot (0 for low, N-1 for high) is the
//! only free one, so `add_tcp` returns it. Throughput element = one
//! remove + add. N = 1 runs remove_add_low only (the two coincide).

use std::hint::black_box;
use std::slice;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::socket::tcp::State;
use dpdk_smoltcp::smoltcp::time::Duration;
use dpdk_smoltcp::smoltcp::wire::{
    ArpOperation, EthernetAddress, TcpControl, TcpRepr, TcpSeqNumber,
};
use dpdk_smoltcp::{rx_pool_count, rx_reserve};
use dpdk_smoltcp::{Eal, StackConfig};

use zhida_test_kit::many::{self, assert_quiet, Conn};
use zhida_test_kit::pair::{
    pattern, segment, tcp_frame, tcp_socket_sized, Pair, Side, BUDGET, CLIENT_PORT, MAX_ROUNDS,
    SERVER_PORT, T0,
};
use zhida_test_kit::wire::Verdict;
use zhida_test_kit::{ring_port, with_eal};
use established::{expected_turn, turn_counts, Established, SEGMENTS, TCP_BUFFER};

mod established;

const COUNTS: [usize; 4] = [1, 64, 1024, 10_240];
/// Filler socket buffers each way; fillers carry no data.
const FILLER_BUFFER: usize = 256;
/// The poll_at deadlines case's RTO.
const DEADLINE: Duration = Duration::from_secs(60);
/// scaling_active round/A/N connection counts.
const ACTIVE_COUNTS: [usize; 2] = [1024, 10_240];
/// scaling_active rto/N connection counts; a superset of `ACTIVE_COUNTS`.
const RTO_COUNTS: [usize; 3] = [64, 1024, 10_240];
/// rto/N from this N takes criterion's minimum 10 samples.
const RTO_FEW_SAMPLES: usize = 10_240;
/// Bytes each active client writes per round.
const MESSAGE: usize = 64;
/// scaling_active pressure: connections, the Stacks' `tx_pending` (the
/// per-turn send limit), turns per iteration and in the fairness window,
/// bytes each client keeps queued, socket buffers each way.
const PRESSURE_N: usize = 1024;
const PRESSURE_PENDING: usize = 64;
const PRESSURE_TURNS: usize = 64;
const PRESSURE_QUEUE: usize = 256;
const PRESSURE_BUFFER: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Case {
    Low,
    Mid,
    High,
    Capacity,
}

impl Case {
    fn name(self) -> &'static str {
        match self {
            Case::Low => "round_low",
            Case::Mid => "round_mid",
            Case::High => "round_high",
            Case::Capacity => "round_capacity",
        }
    }
}

/// A Pair named after `tag` and `n` (unique among live fixtures), `n` slots
/// per Stack, an active socket of `active_buffer` bytes and 256-byte fillers.
fn new_pair(eal: &Eal, tag: &str, n: usize, active_buffer: usize) -> Pair {
    let names = [format!("{tag}{n}a"), format!("{tag}{n}b")];
    let configs = [many::config(Side::A, n), many::config(Side::B, n)];
    Pair::with_ports(
        eal,
        [&names[0], &names[1]],
        configs,
        T0,
        16,
        |side, port| {
            port.rx_pool.count = rx_pool_count(
                rx_reserve(
                    port.rx_descriptors,
                    configs[side.index()].rx_staging,
                    port.rx_pool.cache_size,
                ),
                port.mtu,
                std::iter::once(active_buffer).chain(
                    std::iter::repeat(FILLER_BUFFER)
                        .take(n.checked_sub(1).expect("at least one socket")),
                ),
            );
        },
    )
}

fn assert_slot(handle: &TcpHandle, slot: usize) {
    assert_eq!(handle.to_string(), format!("#{slot}"));
}

/// A Pair with `n` slots per Stack, its active connection warmed up and,
/// unless `Capacity`, `n - 1` filler connections.
fn setup(eal: &Eal, case: Case, n: usize) -> (Pair, Established, Vec<Conn>) {
    let tag = match case {
        Case::Low => "scl",
        Case::Mid => "scm",
        Case::High => "sch",
        Case::Capacity => "scc",
    };
    let mut pair = new_pair(eal, tag, n, TCP_BUFFER);
    let fillers = (n - 1) as u16;
    let connect_at = |pair: &mut Pair, slot| {
        let active = Established::connect(pair);
        for handle in &active.handles {
            assert_slot(handle, slot);
        }
        active
    };
    let (mut active, fillers) = match case {
        Case::Low => {
            let active = connect_at(&mut pair, 0);
            (active, many::open(&mut pair, 0..fillers, FILLER_BUFFER))
        }
        Case::Mid => {
            let half = (n / 2) as u16;
            let mut below = many::open(&mut pair, 0..half, FILLER_BUFFER);
            let active = connect_at(&mut pair, n / 2);
            below.extend(many::open(&mut pair, half..fillers, FILLER_BUFFER));
            (active, below)
        }
        Case::High => {
            let fillers = many::open(&mut pair, 0..fillers, FILLER_BUFFER);
            (connect_at(&mut pair, n - 1), fillers)
        }
        Case::Capacity => (connect_at(&mut pair, 0), Vec::new()),
    };
    assert_quiet(&mut pair, &fillers);
    active.warm_up(&mut pair, |_, _| {});
    (pair, active, fillers)
}

/// `dropped`: the frames each link's impairment must have dropped, A→B then
/// B→A; no link may lose a frame otherwise.
fn close(pair: Pair, dropped: [u64; 2]) {
    for (link, dropped) in [&pair.a_to_b, &pair.b_to_a].into_iter().zip(dropped) {
        assert_eq!((link.pool_empty, link.ring_full, link.dropped), (0, 0, dropped));
    }
    pair.close();
}

fn scaling_benches(c: &mut Criterion, eal: &Eal) {
    for n in COUNTS {
        let cases: &[Case] = if n == 1 {
            &[Case::Low]
        } else {
            &[Case::Low, Case::Mid, Case::High, Case::Capacity]
        };
        for &case in cases {
            let (mut pair, mut active, fillers) = setup(eal, case, n);
            let mut group = c.benchmark_group("scaling");
            group.throughput(Throughput::Elements(SEGMENTS as u64 + 1));
            group.bench_function(BenchmarkId::new(case.name(), n), |b| {
                b.iter(|| active.round(&mut pair));
            });
            group.finish();
            if case == Case::Low {
                let servers = fillers.iter().map(|conn| &conn.server);
                poll_at_benches(
                    c,
                    &mut pair,
                    servers.chain([&active.handles[1]]).collect(),
                    n,
                );
            }
            close(pair, [0, 0]);
        }
    }
}

/// Send one byte on B, keeping its peer out of the turn so the RTO stays armed.
/// Return the peer ACK that cancels this byte's timer.
fn arm_deadline(pair: &mut Pair, server: &TcpHandle, rto: Duration) -> Vec<u8> {
    pair.b.tcp_mut(&server).set_rto(rto);
    assert_eq!(pair.b.tcp_mut(&server).send_slice(b"x"), Ok(1));
    let now = pair.now();
    let turn = pair.b.turn(now, BUDGET).unwrap();
    assert_eq!(turn_counts(&turn), expected_turn(0, 1));
    let mut ack = None;
    assert_eq!(pair.drain_tx(Side::B, |frame| {
        let tcp = segment(frame, Side::B);
        assert_eq!(tcp.payload, b"x");
        ack = Some(tcp_frame(Side::A, &TcpRepr {
            src_port: tcp.dst_port,
            dst_port: tcp.src_port,
            control: TcpControl::None,
            seq_number: tcp.ack_number.unwrap(),
            ack_number: Some(tcp.seq_number + 1),
            window_len: 1024,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        }));
    }), 1);
    ack.unwrap()
}

/// `servers`: every socket on B.
fn poll_at_benches(c: &mut Criterion, pair: &mut Pair, mut servers: Vec<&TcpHandle>, n: usize) {
    let mut group = c.benchmark_group("scaling_poll_at");
    assert_eq!(pair.b.poll_at(), None);
    group.bench_function(BenchmarkId::new("idle", n), |b| {
        b.iter(|| black_box(pair.b.poll_at()));
    });
    let mut acks = Vec::new();
    for &server in &servers {
        acks.push(arm_deadline(pair, server, DEADLINE));
    }
    let deadline = pair.b.poll_at().expect("socket deadlines");
    assert!(deadline > pair.now(), "{deadline} is not a future deadline");
    group.bench_function(BenchmarkId::new("deadlines", n), |b| {
        b.iter(|| black_box(pair.b.poll_at()));
    });
    for ack in &acks {
        b_takes(pair, slice::from_ref(ack), 0, |_| {});
    }
    assert_eq!(pair.b.poll_at(), None);
    servers.sort_by_key(|handle| {
        handle.to_string().strip_prefix('#').unwrap().parse::<usize>().unwrap()
    });
    let spread = |slot: usize| DEADLINE - Duration::from_millis(slot as u64);
    let earliest = servers.iter().enumerate().map(|(slot, &server)| {
        assert_slot(server, slot);
        let ack = arm_deadline(pair, server, spread(slot));
        let own = pair.b.poll_at().expect("socket deadline");
        b_takes(pair, slice::from_ref(&ack), 0, |_| {});
        assert_eq!(pair.b.poll_at(), None);
        own
    }).min().unwrap();
    for (slot, &server) in servers.iter().enumerate() {
        arm_deadline(pair, server, spread(slot));
    }
    assert_eq!(pair.b.poll_at(), Some(earliest));
    assert!(earliest > pair.now(), "{earliest} is not a future deadline");
    group.bench_function(BenchmarkId::new("spread", n), |b| {
        b.iter(|| black_box(pair.b.poll_at()));
    });
    group.finish();
}

/// A TCP segment, no options or payload, from A's `CLIENT_PORT` to B's
/// `SERVER_PORT`.
fn from_client(control: TcpControl, seq: i32, ack: Option<i32>) -> Vec<u8> {
    tcp_frame(
        Side::A,
        &TcpRepr {
            src_port: CLIENT_PORT,
            dst_port: SERVER_PORT,
            control,
            seq_number: TcpSeqNumber(seq),
            ack_number: ack.map(TcpSeqNumber),
            window_len: 1024,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        },
    )
}

/// `frames` onto B's RX ring, then one B turn that must take them all and
/// send `sent` frames, which `inspect` sees as they come off B's TX ring.
fn b_takes(pair: &mut Pair, frames: &[Vec<u8>], sent: usize, inspect: impl FnMut(&[u8])) {
    pair.inject(Side::B, frames);
    let now = pair.now();
    let turn = pair.b.turn(now, BUDGET).unwrap();
    assert_eq!(
        turn_counts(black_box(&turn)),
        expected_turn(frames.len(), sent)
    );
    assert_eq!(pair.drain_tx(Side::B, inspect), sent);
}

fn ingress_benches(c: &mut Criterion, eal: &Eal, n: usize) {
    let mut pair = new_pair(eal, "sci", n, FILLER_BUFFER);
    let fillers = many::open(&mut pair, 0..(n - 1) as u16, FILLER_BUFFER);
    assert_quiet(&mut pair, &fillers);
    let arp = ring_port::arp(
        ArpOperation::Request,
        EthernetAddress::BROADCAST,
        (Side::A.mac(), Side::A.ip()),
        (EthernetAddress([0; 6]), Side::B.ip()),
    );
    b_takes(&mut pair, slice::from_ref(&arp), 1, |_| {});

    let mut group = c.benchmark_group("scaling_ingress");
    group.throughput(Throughput::Elements(1));
    let ack = [from_client(TcpControl::None, 1_000, Some(2_000))];
    b_takes(&mut pair, &ack, 1, |frame| {
        let rst = segment(frame, Side::B);
        assert_eq!(
            (rst.src_port, rst.dst_port, rst.control, rst.seq_number),
            (
                SERVER_PORT,
                CLIENT_PORT,
                TcpControl::Rst,
                TcpSeqNumber(2_000)
            )
        );
    });
    group.bench_function(BenchmarkId::new("miss", n), |b| {
        b.iter(|| b_takes(&mut pair, &ack, 1, |_| {}));
    });

    let listener = pair.b.add_tcp(tcp_socket_sized(FILLER_BUFFER)).unwrap();
    assert_slot(&listener, n - 1);
    pair.b.listen(&listener, SERVER_PORT).unwrap();
    let syn = [from_client(TcpControl::Syn, 7_000, None)];
    let rst = [from_client(TcpControl::Rst, 7_001, None)];
    let syn_rst = |pair: &mut Pair, syn_ack: &mut dyn FnMut(&[u8])| {
        b_takes(pair, &syn, 1, syn_ack);
        b_takes(pair, &rst, 0, |_| {});
        assert_eq!(pair.b.tcp_mut(&listener).state(), State::Listen);
    };
    syn_rst(&mut pair, &mut |frame| {
        let syn_ack = segment(frame, Side::B);
        assert_eq!(
            (
                syn_ack.src_port,
                syn_ack.dst_port,
                syn_ack.control,
                syn_ack.ack_number
            ),
            (
                SERVER_PORT,
                CLIENT_PORT,
                TcpControl::Syn,
                Some(TcpSeqNumber(7_001))
            )
        );
    });
    group.bench_function(BenchmarkId::new("syn_rst", n), |b| {
        b.iter(|| syn_rst(&mut pair, &mut |_| {}));
    });
    group.finish();
    assert_quiet(&mut pair, &fillers);
    close(pair, [0, 0]);
}

/// A Pair like `new_pair` whose Stacks stage and keep pending `burst`
/// frames and whose Ports take RX bursts of `burst`, with `2 * burst`-slot
/// rings and TX pools of `4 * burst - 1` packets. RX pools cover the reserve
/// and `n` sockets of `buffer` bytes. Turns with ingress budget `burst` take
/// everything the peer's turn sent, and no ring fills.
fn burst_pair(eal: &Eal, tag: &str, n: usize, burst: usize, buffer: usize) -> Pair {
    let names = [format!("{tag}{n}a"), format!("{tag}{n}b")];
    let config = |side| StackConfig {
        max_udp_sockets: 0,
        rx_staging: burst,
        tx_pending: burst,
        ..many::config(side, n)
    };
    let configs = [config(Side::A), config(Side::B)];
    let pool = 4 * burst as u32 - 1;
    Pair::with_ports(
        eal,
        [&names[0], &names[1]],
        configs,
        T0,
        2 * burst as u32,
        |side, port| {
            port.rx_burst = burst as u16;
            port.rx_pool.count = rx_pool_count(
                rx_reserve(
                    port.rx_descriptors,
                    configs[side.index()].rx_staging,
                    port.rx_pool.cache_size,
                ),
                port.mtu,
                std::iter::repeat(buffer).take(n),
            );
            port.tx_pool.count = pool;
        },
    )
}

/// A `burst_pair` with `n` connections of `buffer`-byte sockets, connection
/// i in slot i on both Stacks, every server acknowledging at once (no
/// delayed ACK), all quiet.
fn active_pair(eal: &Eal, tag: &str, n: usize, burst: usize, buffer: usize) -> (Pair, Vec<Conn>) {
    let mut pair = burst_pair(eal, tag, n, burst, buffer);
    let conns = many::open(&mut pair, 0..n as u16, buffer);
    for (slot, conn) in conns.iter().enumerate() {
        assert_slot(&conn.client, slot);
        assert_slot(&conn.server, slot);
        pair.b.tcp_mut(&conn.server).set_ack_delay(None);
    }
    assert_quiet(&mut pair, &conns);
    (pair, conns)
}

/// Pair rounds until one moves nothing; returns the frames each link moved.
/// Fails after `MAX_ROUNDS` rounds.
fn until_quiet(pair: &mut Pair) -> (usize, usize) {
    let mut frames = (0, 0);
    for _ in 0..MAX_ROUNDS {
        let round = pair.round(|_, _| {});
        frames.0 += round.a_to_b;
        frames.1 += round.b_to_a;
        if !round.moved() {
            return frames;
        }
    }
    panic!(
        "Pair still moving frames after {MAX_ROUNDS} rounds at {}",
        pair.now()
    );
}

fn write_all(pair: &mut Pair, active: &[&Conn], message: &[u8]) {
    for conn in active {
        let written = pair.a.tcp_mut(&conn.client).send_slice(message);
        assert_eq!(written, Ok(message.len()));
    }
}

/// Each `active` server reads `sink.len()` bytes into `sink`, which `check`
/// then sees.
fn read_all(pair: &mut Pair, active: &[&Conn], sink: &mut [u8], mut check: impl FnMut(&[u8])) {
    for conn in active {
        let mut read = 0usize;
        while let Some(frame) = pair.b.tcp_mut(&conn.server).recv().unwrap() {
            let end = read.checked_add(frame.payload().len()).expect("read bytes");
            sink[read..end].copy_from_slice(frame.payload());
            read = end;
        }
        assert_eq!(read, sink.len());
        check(black_box(&*sink));
    }
}

/// The scaling_active round: each `active` client writes `message`, rounds
/// until quiet carry one segment per message and one ACK back, each server
/// reads it, seen by `check`.
fn active_round(
    pair: &mut Pair,
    active: &[&Conn],
    message: &[u8],
    sink: &mut [u8],
    check: impl FnMut(&[u8]),
) {
    write_all(pair, active, message);
    assert_eq!(until_quiet(pair), (active.len(), active.len()));
    read_all(pair, active, sink, check);
}

/// Only A's turn that retransmits counts: `poll_at` can first report
/// timer-wheel boundaries at which nothing is due; A turns at each, must
/// send nothing, and that time is discarded. Original delivery, ACK loss,
/// remaining retransmissions and recovery are untimed.
fn rto_expiry_round(
    pair: &mut Pair,
    conns: &[Conn],
    message: &[u8],
    sink: &mut [u8],
) -> std::time::Duration {
    let dropped = pair.b_to_a.dropped;
    pair.b_to_a.impair(|_| Verdict::Drop);
    let borrowed: Vec<_> = conns.iter().collect();
    write_all(pair, &borrowed, message);
    let mut sequences = vec![None; conns.len()];
    let mut frames = (0, 0);
    for round in 0..MAX_ROUNDS {
        let last = pair.round(|dir, frame| {
            if dir == Side::A.dir() {
                let tcp = segment(frame, Side::A);
                assert_eq!(tcp.payload, message);
                assert!(sequences[client_id(frame)].replace(tcp.seq_number).is_none());
            }
        });
        frames.0 += last.a_to_b;
        frames.1 += last.b_to_a;
        if !last.moved() {
            break;
        }
        assert!(round + 1 < MAX_ROUNDS, "original flight did not finish");
    }
    assert_eq!(frames, (conns.len(), conns.len()));
    assert_eq!(pair.b_to_a.dropped - dropped, conns.len() as u64);
    assert!(sequences.iter().all(Option::is_some));
    pair.b_to_a.impair(|_| Verdict::Deliver);
    let mut early = pair.now();
    let (deadline, turn, elapsed) = (0..MAX_ROUNDS)
        .find_map(|_| {
            let at = pair.a.poll_at().expect("retransmission deadline");
            assert!(at > early, "poll_at {at} not after {early}");
            let start = std::time::Instant::now();
            let turn = black_box(pair.a.turn(at, BUDGET).unwrap());
            let elapsed = start.elapsed();
            if turn.tx_accepted == 0 {
                early = at;
                None
            } else {
                Some((at, turn, elapsed))
            }
        })
        .expect("no retransmission");
    assert_eq!(turn.tx_accepted, BUDGET.min(conns.len()));
    let sent = pair.a_to_b.forward_with(|frame| {
        let tcp = segment(frame, Side::A);
        assert_eq!(Some(tcp.seq_number), sequences[client_id(frame)]);
        assert_eq!(tcp.payload, message);
    });
    assert_eq!(sent, turn.tx_accepted);
    let received = pair.b.turn(deadline, BUDGET).unwrap();
    assert_eq!(received.rx_processed, sent);
    assert_eq!(pair.b_to_a.forward(), sent);
    pair.round_at(deadline, |_, _| {});
    until_quiet(pair);
    read_all(pair, &borrowed, sink, |read| assert_eq!(read, message));
    for conn in conns {
        assert_eq!(pair.a.tcp(&conn.client).send_queue(), 0);
        assert_eq!(pair.b.tcp(&conn.server).recv_queue(), 0);
    }
    assert_quiet(pair, conns);
    active_round(pair, &borrowed, message, sink, |read| assert_eq!(read, message));
    assert_quiet(pair, conns);
    elapsed
}

fn active_benches(c: &mut Criterion, eal: &Eal, n: usize) {
    let (mut pair, conns) = active_pair(eal, "sca", n, BUDGET, FILLER_BUFFER);
    let borrowed: Vec<_> = conns.iter().collect();
    let message = pattern(MESSAGE, 3);
    let mut sink = [0; MESSAGE];
    let is_message = |read: &[u8]| assert_eq!(read, &message[..]);
    let mut group = c.benchmark_group("scaling_active");
    let counts: &[usize] = if ACTIVE_COUNTS.contains(&n) {
        &[1, 64]
    } else {
        &[]
    };
    for &a in counts {
        let active: Vec<&Conn> = (1..=a).map(|i| &conns[i * n / a - 1]).collect();
        active_round(&mut pair, &active, &message, &mut sink, is_message);
        assert_quiet(&mut pair, &conns);
        group.throughput(Throughput::Elements(a as u64));
        group.bench_function(BenchmarkId::new(format!("round/{a}"), n), |b| {
            b.iter(|| active_round(&mut pair, &active, &message, &mut sink, |_| {}));
        });
        assert_quiet(&mut pair, &conns);
    }
    if RTO_COUNTS.contains(&n) {
        let probe = &borrowed[..1];
        write_all(&mut pair, probe, &message);
        let first = pair.round(|_, _| {});
        assert_eq!((first.a_to_b, first.b_to_a), (1, 1));
        let rto = pair.a.poll_at().expect("retransmission timer");
        assert!(rto > pair.now(), "{rto} is not a future deadline");
        assert_eq!(until_quiet(&mut pair), (0, 0));
        read_all(&mut pair, probe, &mut sink, is_message);
        assert_quiet(&mut pair, &conns);
        active_round(&mut pair, &borrowed, &message, &mut sink, is_message);
        assert_eq!(pair.a.poll_at(), None);
        assert_quiet(&mut pair, &conns);
        group.throughput(Throughput::Elements(n as u64));
        if n >= RTO_FEW_SAMPLES {
            group.sample_size(10);
        }
        group.bench_function(BenchmarkId::new("rto", n), |b| {
            b.iter(|| {
                active_round(&mut pair, &borrowed, &message, &mut sink, |_| {});
                assert_eq!(black_box(pair.a.poll_at()), None);
            });
        });
        assert_quiet(&mut pair, &conns);
    }
    // Each rto_expiry round drops the ACK of every connection's original send.
    let mut expiry_rounds = 0u64;
    if [64, 10_240].contains(&n) {
        group.throughput(Throughput::Elements(BUDGET.min(n) as u64));
        rto_expiry_round(&mut pair, &conns, &message, &mut sink);
        expiry_rounds += 1;
        group.bench_function(BenchmarkId::new("rto_expiry", n), |b| {
            b.iter_custom(|iters| {
                let mut elapsed = std::time::Duration::ZERO;
                for _ in 0..iters {
                    elapsed = elapsed
                        .checked_add(rto_expiry_round(&mut pair, &conns, &message, &mut sink))
                        .expect("total retransmission duration");
                    expiry_rounds += 1;
                }
                elapsed
            });
        });
        assert_quiet(&mut pair, &conns);
    }
    group.finish();
    close(pair, [0, expiry_rounds * n as u64]);
}

/// The connection id of an A→B frame from a `many` client: its TCP source
/// port, after 14 Ethernet and 20 IPv4 header bytes (smoltcp sends no IPv4
/// options), less `CLIENT_BASE`.
fn client_id(frame: &[u8]) -> usize {
    usize::from(u16::from_be_bytes([frame[34], frame[35]]) - many::CLIENT_BASE)
}

/// The pressure Pair's connections and application side; clients by
/// connection id.
struct Pressure {
    conns: Vec<Conn>,
    payload: Vec<u8>,
    sink: Vec<u8>,
    /// Clients whose segment went out this turn.
    sent: Vec<usize>,
    /// Clients whose segment went out the turn before, acknowledged by now.
    acked: Vec<usize>,
}

impl Pressure {
    /// One turn: A's turn takes `acks` ACKs and sends `PRESSURE_PENDING`
    /// segments, A→B, B's turn takes them all and acknowledges each, B→A;
    /// then each server that received reads its `PRESSURE_QUEUE` bytes,
    /// which must equal `payload` when `verify`, and each client B
    /// acknowledged refills them.
    fn turn(&mut self, pair: &mut Pair, acks: usize, verify: bool) {
        let now = pair.now();
        let turn_a = pair.a.turn(now, PRESSURE_PENDING).unwrap();
        std::mem::swap(&mut self.sent, &mut self.acked);
        self.sent.clear();
        let sent = &mut self.sent;
        let a_to_b = pair
            .a_to_b
            .forward_with(|frame| sent.push(client_id(frame)));
        let turn_b = pair.b.turn(now, PRESSURE_PENDING).unwrap();
        let b_to_a = pair.b_to_a.forward();
        let expected = expected_turn(PRESSURE_PENDING, PRESSURE_PENDING);
        assert_eq!(
            turn_counts(black_box(&turn_a)),
            expected_turn(acks, PRESSURE_PENDING)
        );
        assert_eq!(turn_counts(black_box(&turn_b)), expected);
        assert_eq!((a_to_b, b_to_a), (PRESSURE_PENDING, PRESSURE_PENDING));
        for &id in &self.sent {
            let mut read = 0usize;
            while let Some(frame) = pair.b.tcp_mut(&self.conns[id].server).recv().unwrap() {
                let end = read.checked_add(frame.payload().len()).expect("read bytes");
                self.sink[read..end].copy_from_slice(frame.payload());
                read = end;
            }
            assert_eq!(read, PRESSURE_QUEUE);
            if verify {
                assert_eq!(self.sink, self.payload, "connection {id}");
            }
        }
        black_box(&*self.sink);
        for &id in &self.acked {
            let written = pair
                .a
                .tcp_mut(&self.conns[id].client)
                .send_slice(&self.payload);
            assert_eq!(written, Ok(PRESSURE_QUEUE));
        }
    }
}

fn pressure_bench(c: &mut Criterion, eal: &Eal) {
    let n = PRESSURE_N;
    let (mut pair, conns) = active_pair(eal, "scp", n, PRESSURE_PENDING, PRESSURE_BUFFER);
    let payload = pattern(PRESSURE_QUEUE, 5);
    write_all(&mut pair, &conns.iter().collect::<Vec<_>>(), &payload);
    let mut pressure = Pressure {
        conns,
        payload,
        sink: vec![0; PRESSURE_QUEUE],
        sent: Vec::with_capacity(PRESSURE_PENDING),
        acked: Vec::with_capacity(PRESSURE_PENDING),
    };
    pressure.turn(&mut pair, 0, true);
    assert_eq!(pressure.sent, (0..PRESSURE_PENDING).collect::<Vec<_>>());

    let mut group = c.benchmark_group("scaling_active");
    group.throughput(Throughput::Elements(
        (PRESSURE_TURNS * PRESSURE_PENDING) as u64,
    ));
    group.bench_function(BenchmarkId::new("pressure", n), |b| {
        b.iter(|| {
            for _ in 0..PRESSURE_TURNS {
                pressure.turn(&mut pair, PRESSURE_PENDING, false);
            }
        });
    });
    group.finish();

    let mut segments = vec![0u32; n];
    for _ in 0..PRESSURE_TURNS {
        pressure.turn(&mut pair, PRESSURE_PENDING, true);
        for &id in &pressure.sent {
            segments[id] += 1;
        }
    }
    let total: u32 = segments.iter().sum();
    assert!(total > 0);
    let (min, max) = (
        segments.iter().min().unwrap(),
        segments.iter().max().unwrap(),
    );
    eprintln!(
        "scaling_active/pressure/{n}: segments per socket over {PRESSURE_TURNS} turns: \
         min {min}, max {max}, total {total}"
    );
    close(pair, [0, 0]);
}

fn churn_benches(c: &mut Criterion, eal: &Eal, n: usize) {
    let mut pair = new_pair(eal, "scr", n, FILLER_BUFFER);
    let mut handles: Vec<Option<TcpHandle>> = (0..n)
        .map(|_| Some(pair.b.add_tcp(tcp_socket_sized(FILLER_BUFFER)).unwrap()))
        .collect();
    let mut group = c.benchmark_group("scaling_churn");
    group.throughput(Throughput::Elements(1));
    let cases = [("remove_add_low", 0), ("remove_add_high", n - 1)];
    for (name, index) in cases.into_iter().take(if n == 1 { 1 } else { 2 }) {
        let handle = &mut handles[index];
        let slot = handle.as_ref().unwrap().to_string();
        group.bench_function(BenchmarkId::new(name, n), |b| {
            // Dropping the removed socket's buffers is now timed; building the fresh socket is not.
            b.iter_batched(
                || tcp_socket_sized(FILLER_BUFFER),
                |socket| {
                    pair.b.remove_tcp(handle.take().unwrap());
                    *handle = Some(black_box(pair.b.add_tcp(socket).unwrap()));
                },
                BatchSize::SmallInput,
            );
        });
        assert_eq!(handle.as_ref().unwrap().to_string(), slot);
    }
    group.finish();
    close(pair, [0, 0]);
}

fn benches(c: &mut Criterion) {
    with_eal(|eal| {
        scaling_benches(c, eal);
        for n in COUNTS {
            churn_benches(c, eal, n);
            ingress_benches(c, eal, n);
        }
        for n in RTO_COUNTS {
            active_benches(c, eal, n);
        }
        pressure_bench(c, eal);
    });
}

criterion_group!(scaling, benches);
criterion_main!(scaling);
