//! Wire trace of one deterministic two-Stack scenario: 16 connections (kit
//! `many`), request/reply exchanges of mixed sizes four connections at a
//! time, three scripted drops, then FIN close through TIME-WAIT, all on the
//! Pair's caller-driven clock. Every frame each Link takes off its sender's
//! ring is one line of tests/trace/sixteen.txt (dropped ones included); the
//! test compares the run with that file line by line. A change that alters
//! what goes on the wire, or when, shows up as a diff of that file; rerun with
//! ZHIDA_TRACE_BLESS=1 to rewrite it.

use zhida_test_kit::pair::drain_bytes;
use std::cell::RefCell;
use std::fmt::Write;
use std::rc::Rc;

use dpdk_smoltcp::smoltcp::socket::tcp::{RecvError, State};
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetFrame, EthernetProtocol, TcpControl,
};
use dpdk_smoltcp::Stack;

use zhida_test_kit::many::{self, Conn, CLIENT_BASE, SERVER_BASE};
use zhida_test_kit::pair::{pattern, segment, App, Dir, Pair, Side, IDLE_ROUNDS, MAX_ROUNDS, T0};
use zhida_test_kit::wire::Verdict;
use zhida_test_kit::with_eal;

const CONNECTIONS: u16 = 16;
const BUFFER: usize = 4096;
/// Connections exchanging at once. A group's requests take 1 + 1 + 2 + 3
/// segments and its replies 2 + 1 + 2 + 1 (`request`, `reply`), so fewer than
/// 8 frames, a receiver's RX burst, reach it per round; the test asserts no
/// link ring overflowed.
const GROUP: usize = 4;
const TRACE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/trace/sixteen.txt");

/// (direction, connection, n): that connection's n-th frame with payload in
/// that direction, counting retransmissions, is dropped.
const DROPS: [(Dir, u16, usize); 3] = [(Dir::AToB, 5, 1), (Dir::AToB, 10, 2), (Dir::BToA, 13, 1)];

fn request(id: u16) -> Vec<u8> {
    let len = [1, 700, 1460, 3000][usize::from(id) % 4] + usize::from(id);
    pattern(len, 2 * u32::from(id))
}

fn reply(id: u16) -> Vec<u8> {
    let len = [2000, 1, 1461, 600][usize::from(id) % 4] + 2 * usize::from(id);
    pattern(len, 2 * u32::from(id) + 1)
}

#[derive(Default)]
struct Trace {
    lines: Vec<String>,
    now: Option<Instant>,
    /// Payload frames seen per (direction, connection), once drops apply.
    payload_frames: Vec<(Dir, u16, usize)>,
    dropping: bool,
}

impl Trace {
    /// Records `frame` from `dir`'s sender and decides its fate.
    fn frame(&mut self, dir: Dir, frame: &[u8]) -> Verdict {
        let now = self.now.expect("frame outside a traced round");
        let mut line = format!("{} t={}us ", label(dir), now.total_micros());
        let src = if dir == Dir::AToB { Side::A } else { Side::B };
        let eth = EthernetFrame::new_checked(frame).unwrap();
        if eth.ethertype() == EthernetProtocol::Arp {
            let ArpRepr::EthernetIpv4 {
                operation,
                source_protocol_addr,
                target_protocol_addr,
                ..
            } = ArpRepr::parse(&ArpPacket::new_checked(eth.payload()).unwrap()).unwrap()
            else {
                unreachable!()
            };
            let operation = match operation {
                ArpOperation::Request => "request",
                ArpOperation::Reply => "reply",
                ArpOperation::Unknown(_) => "unknown",
            };
            write!(
                line,
                "arp {operation} {source_protocol_addr}>{target_protocol_addr}"
            )
            .unwrap();
            self.lines.push(line);
            return Verdict::Deliver;
        }
        let tcp = segment(frame, src);
        let flags = match tcp.control {
            TcpControl::None => "",
            TcpControl::Psh => "P",
            TcpControl::Syn => "S",
            TcpControl::Fin => "F",
            TcpControl::Rst => "R",
            TcpControl::SynFin => "SF",
        };
        let ack = if tcp.ack_number.is_some() { "." } else { "" };
        write!(
            line,
            "{}>{} {flags}{ack} seq={} ack={} len={} win={}",
            tcp.src_port,
            tcp.dst_port,
            tcp.seq_number.0 as u32,
            tcp.ack_number.map_or(0, |ack| ack.0 as u32),
            tcp.payload.len(),
            tcp.window_len,
        )
        .unwrap();
        for (left, right) in tcp.sack_ranges.iter().flatten() {
            write!(line, " sack={left}-{right}").unwrap();
        }
        let mut verdict = Verdict::Deliver;
        if self.dropping && !tcp.payload.is_empty() {
            let id = match dir {
                Dir::AToB => tcp.src_port - CLIENT_BASE,
                Dir::BToA => tcp.src_port - SERVER_BASE,
            };
            let seen = match self
                .payload_frames
                .iter_mut()
                .find(|(d, i, _)| (*d, *i) == (dir, id))
            {
                Some((_, _, seen)) => seen,
                None => {
                    self.payload_frames.push((dir, id, 0));
                    &mut self.payload_frames.last_mut().unwrap().2
                }
            };
            *seen += 1;
            if DROPS.contains(&(dir, id, *seen)) {
                line.push_str(" drop");
                verdict = Verdict::Drop;
            }
        }
        self.lines.push(line);
        verdict
    }
}

fn label(dir: Dir) -> &'static str {
    match dir {
        Dir::AToB => "A>B",
        Dir::BToA => "B>A",
    }
}

/// `Pair::drive`, with each round's time stored in `trace` before the round:
/// rounds until `app` returns Done; a round in which nothing moved and `app`
/// was idle moves the clock to the earliest Stack deadline.
fn drive(
    pair: &mut Pair,
    trace: &RefCell<Trace>,
    mut app: impl FnMut(&mut Stack, &mut Stack) -> App,
) {
    let mut at = pair.now();
    let mut idle = 0;
    for round in 0.. {
        assert!(round < MAX_ROUNDS, "not done after {round} rounds at {at}");
        trace.borrow_mut().now = Some(at);
        let last = pair.round_at(at, |_, _| {});
        match app(&mut pair.a, &mut pair.b) {
            App::Done => return,
            App::Moved => idle = 0,
            App::Idle if last.moved() => idle = 0,
            App::Idle => {
                idle += 1;
                assert!(idle < IDLE_ROUNDS, "no progress for {idle} rounds at {at}");
                if let Some(deadline) = [pair.a.poll_at(), pair.b.poll_at()]
                    .into_iter()
                    .flatten()
                    .min()
                {
                    at = at.max(deadline);
                }
            }
        }
    }
}

/// Each client sends its `request`; each server, once it has read the whole
/// request, sends its `reply`; done when every reply is read and both
/// directions are acknowledged.
fn exchange(pair: &mut Pair, trace: &RefCell<Trace>, group: &[Conn]) {
    for conn in group {
        let request = request(conn.id);
        assert_eq!(
            pair.a.tcp_mut(&conn.client).send_slice(&request),
            Ok(request.len())
        );
    }
    let mut got = vec![(Vec::new(), Vec::new()); group.len()];
    drive(pair, trace, |a, b| {
        let mut moved = false;
        let mut done = true;
        for (conn, (requested, replied)) in group.iter().zip(&mut got) {
            let server = b.tcp_mut(&conn.server);
            let buffer = drain_bytes(server).unwrap();
            let read = buffer.len();
            if read > 0 {
                requested.extend_from_slice(&buffer[..read]);
                if requested.len() == request(conn.id).len() {
                    let reply = reply(conn.id);
                    assert_eq!(server.send_slice(&reply), Ok(reply.len()));
                }
                moved = true;
            }
            let server_sent = server.send_queue() == 0;
            let client = a.tcp_mut(&conn.client);
            let buffer = drain_bytes(client).unwrap();
            let read = buffer.len();
            replied.extend_from_slice(&buffer[..read]);
            moved |= read > 0;
            done &=
                server_sent && client.send_queue() == 0 && replied.len() == reply(conn.id).len();
        }
        match (done, moved) {
            (true, _) => App::Done,
            (false, true) => App::Moved,
            (false, false) => App::Idle,
        }
    });
    for (conn, (requested, replied)) in group.iter().zip(&got) {
        assert!(
            *requested == request(conn.id),
            "connection {} request",
            conn.id
        );
        assert!(*replied == reply(conn.id), "connection {} reply", conn.id);
    }
}

/// The clients close; each server closes once it reads the end; done when
/// both ends are Closed, the clients after TIME-WAIT.
fn close(pair: &mut Pair, trace: &RefCell<Trace>, group: &[Conn]) {
    for conn in group {
        pair.a.tcp_mut(&conn.client).close();
    }
    drive(pair, trace, |a, b| {
        let mut moved = false;
        for conn in group {
            let server = b.tcp_mut(&conn.server);
            if server.state() == State::CloseWait {
                assert!(matches!(server.recv(), Err(RecvError::Finished)));
                server.close();
                moved = true;
            }
        }
        let closed = group.iter().all(|conn| {
            a.tcp(&conn.client).state() == State::Closed
                && b.tcp(&conn.server).state() == State::Closed
        });
        match (closed, moved) {
            (true, _) => App::Done,
            (false, true) => App::Moved,
            (false, false) => App::Idle,
        }
    });
}

#[zhida_test_support::pinned_test]
fn sixteen_connection_wire_trace_matches_committed() {
    let lines = with_eal(|eal| {
        let capacity = usize::from(CONNECTIONS);
        let configs = [
            many::config(Side::A, capacity),
            many::config(Side::B, capacity),
        ];
        let mut pair = Pair::new(eal, ["tra", "trb"], configs, T0);
        let trace = Rc::new(RefCell::new(Trace::default()));
        for (link, dir) in [(&mut pair.a_to_b, Dir::AToB), (&mut pair.b_to_a, Dir::BToA)] {
            let trace = Rc::clone(&trace);
            link.impair(move |frame| trace.borrow_mut().frame(dir, frame));
        }

        // many::open drives with Pair::drive, which keeps no trace time; the
        // handshakes must not move the clock, so T0 is every frame's time.
        trace.borrow_mut().now = Some(T0);
        let conns = many::open(&mut pair, 0..CONNECTIONS, BUFFER);
        assert_eq!(pair.now(), T0, "opening moved the clock");

        trace.borrow_mut().dropping = true;
        for group in conns.chunks(GROUP) {
            exchange(&mut pair, &trace, group);
        }
        for group in conns.chunks(GROUP) {
            close(&mut pair, &trace, group);
        }
        assert_eq!((pair.a_to_b.dropped, pair.b_to_a.dropped), (2, 1));
        for link in [&pair.a_to_b, &pair.b_to_a] {
            assert_eq!((link.ring_full, link.pool_empty, link.held), (0, 0, 0));
        }
        assert_eq!(pair.close(), 0);
        let lines = std::mem::take(&mut trace.borrow_mut().lines);
        lines
    });

    let mut text = lines.join("\n");
    text.push('\n');
    if std::env::var("ZHIDA_TRACE_BLESS").as_deref() == Ok("1") {
        std::fs::write(TRACE, &text).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(TRACE).unwrap();
    for (index, (got, want)) in text.lines().zip(committed.lines()).enumerate() {
        assert_eq!(got, want, "trace line {}", index + 1);
    }
    assert_eq!(
        text.lines().count(),
        committed.lines().count(),
        "trace length"
    );
}
