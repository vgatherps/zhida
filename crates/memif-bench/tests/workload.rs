//! The benchmark workloads between two Stacks over one memif connection in
//! one thread: peer = memif server, client = memif client. Neither end posts
//! RX slots before its Stack runs: the peer's first frame (the ARP reply)
//! crosses only because the client's `Stack::receive` ran `rx_burst` first, so
//! every passing test here confirms no extra posting is needed. Once the
//! client reports done it is never polled again; the peer must still reach
//! Closed, so the client's final ACK went out before it said done.
//!
//! Every Port, and every Stack, Client or Peer owning one, is held in
//! `ManuallyDrop` until the ordered close: a test that panics leaks them
//! rather than closing a Port while its memif link is up.

use zhida_test_kit::pair::drain_bytes;
mod common;

use std::fmt::Debug;
use std::mem::ManuallyDrop;
use std::time::{Duration, Instant};

use common::{close_pair, names, End, Names};
use dpdk_smoltcp::smoltcp::socket::tcp::{self, State};
use dpdk_smoltcp::smoltcp::time::Instant as NetInstant;
use dpdk_smoltcp::smoltcp::wire::{EthernetAddress, IpEndpoint, Ipv4Address, Ipv4Cidr};
use dpdk_smoltcp::{
    rx_pool_count, rx_reserve, Port, Stack, StackConfig, DEFAULT_NEIGHBOR_CAPACITY,
};
use memif_bench::memif::MemifVdev;
use memif_bench::workload::{
    fill_pattern, port_config, Client, ClientReport, Counters, Peer, PeerMode, PeerReport, Shape, PEER_PORT,
};

const RING: u8 = 10;
const CONNECT: Duration = Duration::from_secs(2);
/// The library's own run deadline; each side then reports itself invalid.
const RUN: Duration = Duration::from_secs(20);
/// The test loop's bound, past the library deadline.
const TEST: Duration = Duration::from_secs(25);

struct Run {
    names: Names,
    client_vdev: MemifVdev,
    peer_vdev: MemifVdev,
    client: ManuallyDrop<Client>,
    peer: ManuallyDrop<Peer>,
}

/// The value a constructor that hands the Port back on `Err` built, never
/// dropped; on `Err` leak the Port and panic.
fn built<T, E: Debug>(result: Result<T, (Port, E)>) -> ManuallyDrop<T> {
    match result {
        Ok(value) => ManuallyDrop::new(value),
        Err((port, error)) => {
            std::mem::forget(port);
            panic!("{error:?}");
        }
    }
}

fn end(vdev: MemifVdev, port: Port) -> End {
    End { vdev, port: ManuallyDrop::new(port) }
}

fn start(tag: &str, shape: Shape, mode: PeerMode) -> Run {
    let names = names(tag);
    let conns = shape.conns();
    let (server, client) = common::open_pair(&names, RING, |id, rx, tx| port_config(id, conns, rx, tx));
    let now = Instant::now();
    let peer = built(Peer::new(
        ManuallyDrop::into_inner(server.port),
        mode,
        conns,
        RUN,
        2,
        now,
    ));
    let client_side = built(Client::new(
        ManuallyDrop::into_inner(client.port),
        shape,
        CONNECT,
        RUN,
        1,
        now,
    ));
    Run { names, client_vdev: client.vdev, peer_vdev: server.vdev, client: client_side, peer }
}

/// Poll the client until it is done, never after, and the peer until it is.
fn drive(run: &mut Run) {
    let deadline = Instant::now() + TEST;
    let (mut client_done, mut peer_done) = (false, false);
    while !(client_done && peer_done) {
        let now = Instant::now();
        assert!(now < deadline, "client done {client_done}, peer done {peer_done} at the test deadline");
        if !client_done {
            client_done = run.client.poll(now).unwrap();
        }
        if !peer_done {
            peer_done = run.peer.poll(now).unwrap();
        }
    }
}

/// `drive`, recording both reports after each loop iteration (client poll,
/// then peer poll); index 0 is before the first. At these sizes every burst
/// takes all that waits, so the client's poll `i` receives what the peer
/// sent in its poll `i - 1`, and the peer's poll `i` what the client sent in
/// its poll `i`.
fn trace(run: &mut Run) -> Vec<(ClientReport, PeerReport)> {
    let deadline = Instant::now() + TEST;
    let mut reports = vec![(run.client.report(), run.peer.report())];
    let (mut client_done, mut peer_done) = (false, false);
    while !(client_done && peer_done) {
        let now = Instant::now();
        assert!(now < deadline, "client done {client_done}, peer done {peer_done} at the test deadline");
        if !client_done {
            client_done = run.client.poll(now).unwrap();
        }
        if !peer_done {
            peer_done = run.peer.poll(now).unwrap();
        }
        reports.push((run.client.report(), run.peer.report()));
    }
    reports
}

/// The first index whose reports satisfy `at`.
fn first(reports: &[(ClientReport, PeerReport)], at: impl Fn(&ClientReport, &PeerReport) -> bool) -> usize {
    reports.iter().position(|(client, peer)| at(client, peer)).expect("reached in the trace")
}

/// Close the client's Port first, then the peer's behind the barrier.
fn finish(run: Run) {
    let client = end(run.client_vdev, ManuallyDrop::into_inner(run.client).into_port());
    let peer = end(run.peer_vdev, ManuallyDrop::into_inner(run.peer).into_port());
    close_pair(client, peer, &run.names);
}

fn run_valid(tag: &str, shape: Shape, mode: PeerMode) -> (ClientReport, PeerReport) {
    let mut run = start(tag, shape, mode);
    drive(&mut run);
    let (client, peer) = (run.client.report(), run.peer.report());
    assert_eq!(client.failure, None, "{}", client.to_json());
    assert_eq!(peer.failure, None, "{}", peer.to_json());
    finish(run);
    (client, peer)
}

/// A Stack with one socket slot at 10.0.0.`host`, built by hand in place of
/// the library's client or peer.
fn bare_stack(port: Port, host: u8) -> ManuallyDrop<Stack> {
    let config = StackConfig {
        max_udp_sockets: 0,
        ethernet: EthernetAddress([0x02, 0, 0, 0, 0, host]),
        ipv4: Ipv4Cidr::new(Ipv4Address::new(10, 0, 0, host), 24),
        random_seed: u64::from(host),
        neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
        segments_per_visit: 1,
        max_sockets: 1,
        rx_staging: 32,
        tx_pending: 32,
        gateway: None,
        paths: &[],
    };
    built(Stack::new(port, config, NetInstant::ZERO))
}

fn bare_socket() -> tcp::Config {
    tcp::Config { rx_capacity: 8192, tx_capacity: 8192, mss_cap: None }
}

fn net_time(origin: Instant, now: Instant) -> NetInstant {
    NetInstant::from_micros((now - origin).as_micros() as i64)
}

#[zhida_test_support::pinned_test]
fn pingpong_echoes_every_byte() {
    for (tag, message) in [("pp64", 64), ("pp1448", 1448)] {
        let (rounds, warmup) = (200, 20);
        let shape = Shape::PingPong { conns: 1, message, rounds, warmup };
        let (client, peer) = run_valid(tag, shape, PeerMode::Echo);
        assert_eq!(client.conn_rounds, [rounds]);
        assert_eq!(client.rtt_ns.len(), rounds);
        assert!(client.counters.frames_rx >= rounds as u64, "{}", client.to_json());
        assert!(client.counters.frames_tx >= rounds as u64, "{}", client.to_json());
        assert_eq!(peer.bytes, (warmup + rounds) * message);
    }
}

/// 4000 bytes span several segments; 100 000 exceed both 64 KiB socket
/// buffers, so the peer echoes only what its send buffer has room for.
#[zhida_test_support::pinned_test]
fn pingpong_messages_span_segments_and_socket_buffers() {
    for (tag, message, rounds) in [("pp4000", 4000, 10), ("pp100k", 100_000, 3)] {
        let warmup = 1;
        let shape = Shape::PingPong { conns: 1, message, rounds, warmup };
        let (client, peer) = run_valid(tag, shape, PeerMode::Echo);
        assert_eq!(client.conn_rounds, [rounds]);
        assert_eq!(peer.bytes, (warmup + rounds) * message);
    }
}

#[zhida_test_support::pinned_test]
fn parallel_connections_all_finish() {
    let shape = Shape::PingPong { conns: 4, message: 64, rounds: 100, warmup: 0 };
    let (client, peer) = run_valid("par4", shape, PeerMode::Echo);
    assert_eq!(client.conn_rounds, [100; 4]);
    assert_eq!(client.rtt_ns.len(), 400);
    assert_eq!(peer.bytes, 4 * 100 * 64);
}

/// With warmup, and with more connections (40) than a 32-frame burst, so
/// both Stacks' tx_pending is the connection count.
#[zhida_test_support::pinned_test]
fn parallel_with_warmup_and_more_connections_than_a_burst() {
    for (tag, conns, rounds, warmup) in [("parw", 4, 20, 5), ("par40", 40, 5, 1)] {
        let shape = Shape::PingPong { conns, message: 64, rounds, warmup };
        let (client, peer) = run_valid(tag, shape, PeerMode::Echo);
        assert_eq!(client.conn_rounds, vec![rounds; conns]);
        assert_eq!(client.rtt_ns.len(), conns * rounds);
        assert_eq!(peer.bytes, conns * (warmup + rounds) * 64);
    }
}

#[zhida_test_support::pinned_test]
fn bulk_sink_receives_exact_bytes() {
    let (bytes, warmup) = (1 << 20, 64 << 10);
    let mut run = start("bulk", Shape::Bulk { bytes, warmup }, PeerMode::Sink);
    drive(&mut run);
    let (client, peer) = (run.client.report(), run.peer.report());
    assert_eq!(client.failure, None, "{}", client.to_json());
    assert_eq!(peer.failure, None, "{}", peer.to_json());
    assert_eq!(client.bytes, bytes);
    assert_eq!(peer.bytes, warmup + bytes);
    assert_eq!(run.client.socket(0).send_queue(), 0);
    finish(run);
}

#[zhida_test_support::pinned_test]
fn bulk_poll_sends_two_pending_queues() {
    let names = names("bulk2send");
    let bytes = 64 * 1024;
    let mss = 512;
    let pending = 32;
    assert!(bytes / mss > 2 * pending);
    let mut socket = tcp::Config { rx_capacity: bytes, tx_capacity: bytes, mss_cap: None };
    socket.mss_cap = Some(mss as u16);
    let (server, client) = common::open_pair(&names, RING, |id, rx, tx| {
        let mut config = port_config(id, 1, rx, tx);
        if rx == names.server_rx.as_c_str() {
            config.rx_pool.count = u32::try_from(
                rx_reserve(config.rx_descriptors, 32, config.rx_pool.cache_size)
                    .checked_add(tcp::rx_mbuf_budget(&socket, usize::from(config.mtu)))
                    .expect("peer RX pool count fits usize"),
            ).expect("peer RX pool count fits u32");
        }
        config
    });
    let origin = Instant::now();
    let mut client_side = built(Client::new(
        ManuallyDrop::into_inner(client.port),
        Shape::Bulk { bytes, warmup: 0 },
        CONNECT,
        RUN,
        1,
        origin,
    ));
    let mut stack = bare_stack(ManuallyDrop::into_inner(server.port), 2);
    let handle = stack.add_tcp(socket).unwrap_or_else(|_| panic!("free slot and RX budget"));
    stack.listen(&handle, PEER_PORT).unwrap();
    let deadline = origin + TEST;
    let now = loop {
        let now = Instant::now();
        assert!(now < deadline, "not established at the test deadline");
        assert!(!client_side.poll(now).unwrap());
        if client_side.socket(0).state() == State::Established {
            break now;
        }
        stack.turn(net_time(origin, now), 32).unwrap();
    };
    let report = client_side.report();
    assert_eq!(report.failure, None, "{}", report.to_json());
    assert_eq!(report.counters, Counters {
        frames_tx: (2 * pending) as u64,
        turns: 1,
        ..Counters::default()
    });
    assert_eq!(client_side.socket(0).send_queue(), bytes);
    let mut received = 0;
    for _ in 0..2 {
        let turn = stack.receive(net_time(origin, now), 32).unwrap();
        assert_eq!(turn.rx_received, pending);
        assert_eq!(turn.rx_rejected, 0);
        assert!(!turn.rx_blocked);
        received += drain_bytes(stack.tcp_mut(&handle)).unwrap().len();
    }
    assert_eq!(received, 2 * pending * mss);
    let client = end(client.vdev, ManuallyDrop::into_inner(client_side).into_port());
    close_pair(client, end(server.vdev, ManuallyDrop::into_inner(stack).into_port()), &names);
}

#[zhida_test_support::pinned_test]
fn udp_stream_reports_delivery_and_loss() {
    for (tag, size, warmup) in [
        ("udp64", 64, 20),
        ("udp1472", 1472, 20),
        ("udp64nw", 64, 0),
        ("udp1472nw", 1472, 0),
    ] {
        let count = 1000;
        let shape = Shape::UdpStream {
            size,
            count,
            warmup,
        };
        let mut run = start(tag, shape, PeerMode::UdpSink { size, warmup });
        let deadline = Instant::now() + TEST;
        let mut client_done = false;
        loop {
            let now = Instant::now();
            assert!(now < deadline, "UDP run did not finish");
            if !client_done {
                client_done = run.client.poll(now).unwrap();
            }
            let peer_idle = run.peer.poll(now).unwrap();
            if client_done && peer_idle {
                break;
            }
        }
        let (client, peer) = (run.client.report(), run.peer.report());
        assert_eq!(client.failure, None, "{}", client.to_json());
        assert_eq!(peer.failure, None, "{}", peer.to_json());
        assert_eq!(client.sent, count);
        assert_eq!(peer.delivered, client.sent);
        assert_eq!(client.sent.checked_sub(peer.delivered).unwrap(), 0);
        assert_eq!(peer.warmup_delivered, warmup);
        assert_eq!(peer.reordered, 0);
        assert_eq!(peer.rx_dropped_full, 0);
        assert_eq!(peer.udp_counters, dpdk_smoltcp::UdpCounters::default());
        assert!(client.elapsed_ns > 0);
        let json = client.to_json();
        let pps: f64 = json
            .split_once("\"sent_pps\":")
            .unwrap()
            .1
            .split(',')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(pps > 0.0, "{json}");
        finish(run);
    }
}

#[zhida_test_support::pinned_test]
fn udp_sink_receives_after_an_idle_poll() {
    let shape = Shape::UdpStream {
        size: 64,
        count: 1,
        warmup: 0,
    };
    let mut run = start(
        "udpidle",
        shape,
        PeerMode::UdpSink {
            size: 64,
            warmup: 0,
        },
    );
    let now = Instant::now() + Duration::from_millis(60);
    assert!(run.peer.poll(now).unwrap());
    let mut done = false;
    for _ in 0..10 {
        done = run.client.poll(now).unwrap();
        run.peer.poll(now).unwrap();
        if done {
            break;
        }
    }
    assert!(done, "{}", run.client.report().to_json());
    assert_eq!(run.client.report().sent, 1);
    assert_eq!(run.peer.report().delivered, 1);
    assert!(!run.peer.poll(now + Duration::from_millis(49)).unwrap());
    assert!(run.peer.poll(now + Duration::from_millis(50)).unwrap());
    assert_eq!(run.client.report().failure, None);
    assert_eq!(run.peer.report().failure, None);
    finish(run);
}

#[test]
fn udp_shape_validation() {
    for size in [7, 1473] {
        let shape = Shape::UdpStream {
            size,
            count: 1000,
            warmup: 20,
        };
        assert_eq!(shape.validate(), Err("size must be 8..=1472"));
    }
    for size in [8, 1472] {
        assert_eq!(
            Shape::UdpStream {
                size,
                count: 1,
                warmup: 0
            }
            .validate(),
            Ok(())
        );
    }
    assert!(Shape::UdpStream {
        size: 64,
        count: 1,
        warmup: u64::MAX
    }
    .validate()
    .is_err());
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_memif-bench"))
        .args([
            "client", "--shape", "udp", "--size", "64", "--count", "1000", "--warmup", "20",
            "--mode", "echo", "--cpu", "0", "--socket", "s",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("--mode does not apply here"));
}

/// Each measured round is one data segment each way, the client's request
/// carrying the ACK of the previous echo: a counted SYN, ARP, FIN or warmup
/// frame would make either count exceed the rounds.
#[zhida_test_support::pinned_test]
fn measured_counters_exclude_warmup_and_close() {
    let rounds = 100;
    let shape = Shape::PingPong { conns: 1, message: 64, rounds, warmup: 100 };
    let (client, _) = run_valid("window", shape, PeerMode::Echo);
    assert_eq!(client.counters.frames_tx, rounds as u64, "{}", client.to_json());
    assert_eq!(client.counters.frames_rx, rounds as u64, "{}", client.to_json());
}

/// Every connection completes exactly warmup + rounds: the peer read exactly
/// that many requests, and after done no client socket holds an unsent
/// request or an unread echo.
#[zhida_test_support::pinned_test]
fn split_client_completes_exact_rounds() {
    let (rounds, warmup) = (50, 4);
    for (tag, conns, message) in [("exact1", 1, 1448), ("exact3", 3, 64)] {
        let mut run = start(tag, Shape::PingPong { conns, message, rounds, warmup }, PeerMode::Echo);
        drive(&mut run);
        let (client, peer) = (run.client.report(), run.peer.report());
        assert_eq!(client.failure, None, "{}", client.to_json());
        assert_eq!(peer.failure, None, "{}", peer.to_json());
        assert_eq!(client.conn_rounds, vec![rounds; conns]);
        assert_eq!(client.rtt_ns.len(), conns * rounds);
        assert_eq!(peer.bytes, conns * (warmup + rounds) * message);
        for conn in 0..conns {
            let socket = run.client.socket(conn);
            assert_eq!((socket.send_queue(), socket.recv_queue()), (0, 0), "connection {conn}");
        }
        finish(run);
    }
}

/// The measured window runs from the client poll that writes the first
/// measured requests (the peer reads them in its poll of the same
/// iteration) to the poll that sees the last echo. Every poll in it counts as
/// a turn; the counted frames are exactly what the client sent in those
/// polls, as the peer received it, and what it received in the polls after
/// the first, as the peer sent it: one echo per measured round.
#[zhida_test_support::pinned_test]
fn split_client_preserves_frame_counts() {
    let (conns, message, rounds, warmup) = (4, 64, 20, 5);
    let mut run = start("split", Shape::PingPong { conns, message, rounds, warmup }, PeerMode::Echo);
    let reports = trace(&mut run);
    let (client, peer) = reports.last().unwrap().clone();
    assert_eq!(client.failure, None, "{}", client.to_json());
    assert_eq!(peer.failure, None, "{}", peer.to_json());
    let opened = first(&reports, |_, peer| peer.bytes > conns * warmup * message);
    let closed = first(&reports, |client, _| client.elapsed_ns > 0);
    let peer_rx = reports[closed - 1].1.counters.frames_rx - reports[opened - 1].1.counters.frames_rx;
    let peer_tx = reports[closed - 1].1.counters.frames_tx - reports[opened - 1].1.counters.frames_tx;
    let counted = client.counters;
    assert_eq!(counted.turns, (closed - opened + 1) as u64, "{}", client.to_json());
    assert_eq!(counted.frames_tx, peer_rx, "{}", client.to_json());
    assert_eq!(counted.frames_rx, peer_tx, "{}", client.to_json());
    assert_eq!(counted.frames_rx, (conns * rounds) as u64, "{}", client.to_json());
    assert!(counted.frames_tx >= (conns * rounds) as u64, "{}", client.to_json());
    finish(run);
}

/// The poll whose step enters Measured counts its send (the first measured
/// request of each connection) but not its receive (the last warmup echo).
/// The poll whose step sees the last echo counts its receive (the last
/// echoes) but not its send (each connection's FIN). Nothing after it counts.
#[zhida_test_support::pinned_test]
fn split_client_warmup_and_close_boundaries() {
    let (conns, message, rounds, warmup) = (2, 64, 5, 3);
    let mut run = start("bounds", Shape::PingPong { conns, message, rounds, warmup }, PeerMode::Echo);
    let reports = trace(&mut run);
    let (client, peer) = reports.last().unwrap();
    assert_eq!(client.failure, None, "{}", client.to_json());
    assert_eq!(peer.failure, None, "{}", peer.to_json());
    let peer_sent = |i: usize| reports[i].1.counters.frames_tx - reports[i - 1].1.counters.frames_tx;
    let peer_received = |i: usize| reports[i].1.counters.frames_rx - reports[i - 1].1.counters.frames_rx;

    let opened = first(&reports, |client, _| client.counters != Counters::default());
    assert_eq!(opened, first(&reports, |_, peer| peer.bytes > conns * warmup * message));
    assert_eq!(reports[opened].1.bytes, conns * (warmup + 1) * message);
    assert!(peer_sent(opened - 1) >= 1, "the opening poll received a warmup echo");
    let expected = Counters { frames_tx: conns as u64, turns: 1, ..Counters::default() };
    assert_eq!(reports[opened].0.counters, expected);
    assert!(reports[opened].0.rtt_ns.is_empty());

    let closed = first(&reports, |client, _| client.elapsed_ns > 0);
    let (before, after) = (reports[closed - 1].0.counters, reports[closed].0.counters);
    let last_echoes = reports[closed].0.rtt_ns.len() - reports[closed - 1].0.rtt_ns.len();
    assert!(last_echoes >= 1);
    assert_eq!(peer_sent(closed - 1), last_echoes as u64);
    let expected = Counters {
        frames_rx: before.frames_rx + last_echoes as u64,
        turns: before.turns + 1,
        ..before
    };
    assert_eq!(after, expected);
    assert_eq!(peer_received(closed), conns as u64, "the closing poll sent each connection's FIN");
    assert!(reports[closed..].iter().all(|(client, _)| client.counters == after));
    finish(run);
}

/// The client aborts one of its sockets mid-run through the socket API. The
/// poll that sees it stops the run and still sends, so the abort's RST
/// reaches the peer, whose next poll fails on the reset, not its deadline.
/// The abort comes before the peer echoes the request just sent: no segment
/// for the aborted socket reaches the client, whose reply RST would leave
/// from `receive` whether or not the stopping poll sends.
#[zhida_test_support::pinned_test]
fn abort_makes_run_invalid() {
    let shape = Shape::PingPong { conns: 2, message: 64, rounds: 1000, warmup: 0 };
    let mut run = start("abort", shape, PeerMode::Echo);
    let deadline = Instant::now() + TEST;
    loop {
        let now = Instant::now();
        assert!(now < deadline, "no progress at the test deadline");
        assert!(!run.client.poll(now).unwrap(), "{}", run.client.report().to_json());
        if run.client.report().conn_rounds[0] >= 5 {
            break;
        }
        run.peer.poll(now).unwrap();
    }
    run.client.socket(0).abort();
    let now = Instant::now();
    assert!(run.client.poll(now).unwrap());
    let client = run.client.report();
    let reason = client.failure.as_deref().unwrap_or_default();
    assert_eq!(reason, "connection 0: unexpected state CLOSED after ESTABLISHED", "{}", client.to_json());
    assert!(run.peer.poll(now).unwrap(), "{}", run.peer.report().to_json());
    let peer = run.peer.report();
    let reason = peer.failure.as_deref().unwrap_or_default();
    assert!(reason.ends_with(": unexpected state CLOSED after ESTABLISHED"), "{}", peer.to_json());
    finish(run);
}

/// A hand-built client Stack sends the sink stream with one byte flipped; the
/// peer's own check of the bytes it received makes its report invalid.
#[zhida_test_support::pinned_test]
fn peer_detects_corrupted_byte() {
    let names = names("corrupt");
    let (server, client) = common::open_pair(&names, RING, |id, rx, tx| {
        let mut config = port_config(id, 1, rx, tx);
        if rx == names.client_rx.as_c_str() {
            config.rx_pool.count = rx_pool_count(
                rx_reserve(config.rx_descriptors, 32, config.rx_pool.cache_size),
                config.mtu,
                [8192],
            );
        }
        config
    });
    let origin = Instant::now();
    let mut peer = built(Peer::new(
        ManuallyDrop::into_inner(server.port),
        PeerMode::Sink,
        1,
        RUN,
        2,
        origin,
    ));
    let mut stack = bare_stack(ManuallyDrop::into_inner(client.port), 1);
    let handle = stack.add_tcp(bare_socket()).unwrap_or_else(|_| panic!("free slot"));
    let remote = IpEndpoint::new(Ipv4Address::new(10, 0, 0, 2).into(), PEER_PORT);
    stack.connect(&handle, remote, 40000).unwrap();
    let mut stream = vec![0; 4096];
    fill_pattern(&mut stream, 0, 0);
    stream[1000] ^= 1;
    let (mut written, mut peer_done) = (false, false);
    let deadline = origin + TEST;
    while !peer_done {
        let now = Instant::now();
        assert!(now < deadline, "peer not done at the test deadline");
        stack.turn(net_time(origin, now), 32).unwrap();
        let socket = stack.tcp_mut(&handle);
        if !written && socket.state() == State::Established {
            assert_eq!(socket.send_slice(&stream).unwrap(), stream.len());
            socket.close();
            written = true;
        }
        peer_done = peer.poll(now).unwrap();
    }
    let report = peer.report();
    assert_eq!(report.failure.as_deref(), Some("connection 0: sink bytes differ"), "{}", report.to_json());
    assert_eq!(report.bytes, stream.len());
    assert_eq!(peer.socket(0).state(), State::Closed);
    let client = end(client.vdev, ManuallyDrop::into_inner(stack).into_port());
    close_pair(client, end(server.vdev, ManuallyDrop::into_inner(peer).into_port()), &names);
}

/// A hand-built peer Stack echoes with the first byte flipped; the client's
/// own comparison makes its report invalid, though every round completes.
#[zhida_test_support::pinned_test]
fn client_detects_corrupted_echo() {
    let names = names("badecho");
    let rounds = 3;
    let shape = Shape::PingPong { conns: 1, message: 64, rounds, warmup: 0 };
    let (server, client) = common::open_pair(&names, RING, |id, rx, tx| {
        let mut config = port_config(id, 1, rx, tx);
        if rx == names.server_rx.as_c_str() {
            config.rx_pool.count = rx_pool_count(
                rx_reserve(config.rx_descriptors, 32, config.rx_pool.cache_size),
                config.mtu,
                [8192],
            );
        }
        config
    });
    let origin = Instant::now();
    let mut client_side = built(Client::new(
        ManuallyDrop::into_inner(client.port),
        shape,
        CONNECT,
        RUN,
        1,
        origin,
    ));
    let mut stack = bare_stack(ManuallyDrop::into_inner(server.port), 2);
    let handle = stack.add_tcp(bare_socket()).unwrap_or_else(|_| panic!("free slot"));
    stack.listen(&handle, PEER_PORT).unwrap();
    let (mut flipped, mut client_done) = (false, false);
    let deadline = origin + TEST;
    while !client_done {
        let now = Instant::now();
        assert!(now < deadline, "client not done at the test deadline");
        stack.turn(net_time(origin, now), 32).unwrap();
        let socket = stack.tcp_mut(&handle);
        if socket.can_recv() {
            let mut scratch = drain_bytes(socket).unwrap();
            let read = scratch.len();
            if !flipped {
                scratch[0] ^= 1;
                flipped = true;
            }
            assert_eq!(socket.send_slice(&scratch[..read]).unwrap(), read);
        }
        if socket.state() == State::CloseWait {
            socket.close();
        }
        client_done = client_side.poll(now).unwrap();
    }
    let report = client_side.report();
    assert_eq!(report.failure.as_deref(), Some("connection 0 round 0: echoed bytes differ"), "{}", report.to_json());
    assert_eq!(report.conn_rounds, [rounds]);
    let client = end(client.vdev, ManuallyDrop::into_inner(client_side).into_port());
    close_pair(client, end(server.vdev, ManuallyDrop::into_inner(stack).into_port()), &names);
}

/// A hand-built client Stack sends one request. The peer's echo leaves in the
/// `poll` that received it, counted as one turn: the client's next turn gets
/// the echo without the peer polling again.
#[zhida_test_support::pinned_test]
fn peer_echo_leaves_in_the_poll_that_received_the_request() {
    let names = names("onepoll");
    let (server, client) = common::open_pair(&names, RING, |id, rx, tx| {
        let mut config = port_config(id, 1, rx, tx);
        if rx == names.client_rx.as_c_str() {
            config.rx_pool.count = rx_pool_count(
                rx_reserve(config.rx_descriptors, 32, config.rx_pool.cache_size),
                config.mtu,
                [8192],
            );
        }
        config
    });
    let origin = Instant::now();
    let mut peer = built(Peer::new(
        ManuallyDrop::into_inner(server.port),
        PeerMode::Echo,
        1,
        RUN,
        2,
        origin,
    ));
    let mut stack = bare_stack(ManuallyDrop::into_inner(client.port), 1);
    let handle = stack.add_tcp(bare_socket()).unwrap_or_else(|_| panic!("free slot"));
    let remote = IpEndpoint::new(Ipv4Address::new(10, 0, 0, 2).into(), PEER_PORT);
    stack.connect(&handle, remote, 40000).unwrap();
    let deadline = origin + TEST;
    while stack.tcp(&handle).state() != State::Established || peer.socket(0).state() != State::Established {
        let now = Instant::now();
        assert!(now < deadline, "not established at the test deadline");
        stack.turn(net_time(origin, now), 32).unwrap();
        peer.poll(now).unwrap();
    }

    let request = b"echo me in this poll";
    assert_eq!(stack.tcp_mut(&handle).send_slice(request).unwrap(), request.len());
    let now = Instant::now();
    assert_eq!(stack.turn(net_time(origin, now), 32).unwrap().tx_accepted, 1);
    let before = peer.report().counters;
    assert!(!peer.poll(now).unwrap());
    let after = peer.report().counters;
    assert_eq!(
        (after.turns, after.frames_rx, after.frames_tx),
        (before.turns + 1, before.frames_rx + 1, before.frames_tx + 1)
    );
    assert_eq!(stack.turn(net_time(origin, now), 32).unwrap().rx_received, 1);
    let echoed = drain_bytes(stack.tcp_mut(&handle)).unwrap();
    assert_eq!(echoed.len(), request.len());
    assert_eq!(&echoed[..request.len()], request);

    stack.tcp_mut(&handle).close();
    let mut peer_done = false;
    while !peer_done {
        let now = Instant::now();
        assert!(now < deadline, "peer not done at the test deadline");
        stack.turn(net_time(origin, now), 32).unwrap();
        peer_done = peer.poll(now).unwrap();
    }
    let report = peer.report();
    assert_eq!(report.failure, None, "{}", report.to_json());
    assert_eq!(report.bytes, request.len());
    assert_eq!(stack.tcp(&handle).state(), State::TimeWait);
    let client = end(client.vdev, ManuallyDrop::into_inner(stack).into_port());
    close_pair(client, end(server.vdev, ManuallyDrop::into_inner(peer).into_port()), &names);
}

/// After done, every client socket is in TimeWait with nothing left to send
/// and every peer socket Closed; the ordered close frees all four pools.
#[zhida_test_support::pinned_test]
fn client_and_peer_close_cleanly() {
    let conns = 2;
    let shape = Shape::PingPong { conns, message: 64, rounds: 10, warmup: 0 };
    let mut run = start("close", shape, PeerMode::Echo);
    drive(&mut run);
    assert_eq!(run.client.report().failure, None);
    assert_eq!(run.peer.report().failure, None);
    for conn in 0..conns {
        let socket = run.client.socket(conn);
        assert_eq!((socket.state(), socket.send_queue()), (State::TimeWait, 0));
        assert_eq!(run.peer.socket(conn).state(), State::Closed);
    }
    finish(run);
}
