//! The v1 benchmark shapes between two Zhida Stacks, one Port each. The
//! client connects and measures; the peer echoes or sinks. Each side's `poll`
//! is `Stack::receive`, its application step, then `Stack::send` (twice if
//! the first fills the pending queue), so ingress replies are pushed before
//! the step and application replies leave in the same poll. One thread can
//! drive both sides. UDP polls receive, send datagrams in place, then flush.
//! The sink receives and flushes its ARP replies.

use std::ffi::CStr;
use std::time::{Duration, Instant};

use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::socket::tcp::{self, State};
use dpdk_smoltcp::smoltcp::time::{Duration as NetDuration, Instant as NetInstant};
use dpdk_smoltcp::smoltcp::wire::{EthernetAddress, IpEndpoint, Ipv4Address, Ipv4Cidr};
use dpdk_smoltcp::{
    rx_pool_count, rx_reserve, Offloads, Port, PortConfig, Sent, Stack, StackConfig, StackError,
    Turn, UdpConfig, UdpCounters, UdpHandle, UdpSendError, DEFAULT_NEIGHBOR_CAPACITY,
};
use zhida_buffer::PoolConfig;
use zhida_dpdk_sys::RTE_PKTMBUF_HEADROOM;

use crate::memif::BUFFER_SIZE;

pub const PEER_PORT: u16 = 5000;
const CLIENT_PORT_BASE: u16 = 40000;
const CLIENT_HOST: u8 = 1;
const PEER_HOST: u8 = 2;
const SOCKET_BUFFER: usize = 64 * 1024;
/// smoltcp's default, set explicitly.
const ACK_DELAY: NetDuration = NetDuration::from_millis(10);
const RX_STAGING: usize = 32;
const BURST: u16 = 32;
const POOL_CACHE: u32 = 8;
/// Mbufs one lcore's mempool cache can hold.
const CACHE_SLACK: u32 = POOL_CACHE * 3 / 2;
const FRAME: u16 = 1514;
const NOTE: &str = "frames include memif's copy of every frame on both sides";
/// The peer delays the ACK of the last segment when at most one MSS is
/// unacknowledged (smoltcp 0.14.0 tcp.rs:2258-2262, 2401-2403).
const BULK_NOTE: &str = "; elapsed can include one delayed ACK of the last segment (<= 10 ms)";
/// The sink is idle after 50 ms without a datagram. The caller waits for sender completion too.
const UDP_IDLE: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// `conns` connections; each writes a `message`-byte message and waits
    /// for all of it to come back, `warmup` untimed rounds then `rounds`.
    PingPong { conns: usize, message: usize, rounds: usize, warmup: usize },
    /// One connection writes `warmup` untimed bytes, then `bytes` measured.
    Bulk { bytes: usize, warmup: usize },
    /// One-way datagrams, with untimed warmup before the measured count.
    UdpStream {
        size: usize,
        count: u64,
        warmup: u64,
    },
}

impl Shape {
    pub fn conns(&self) -> usize {
        match *self {
            Shape::PingPong { conns, .. } => conns,
            Shape::Bulk { .. } | Shape::UdpStream { .. } => 1,
        }
    }

    /// Bounds keep local ports in u16 and `message_key` fields disjoint.
    /// `Client::new` refuses a shape this rejects.
    pub fn validate(&self) -> Result<(), &'static str> {
        match *self {
            Shape::PingPong { conns, message, rounds, warmup } => {
                if conns == 0 || conns > usize::from(u16::MAX - CLIENT_PORT_BASE) + 1 {
                    Err("conns must be 1..=25536")
                } else if !(8..=8 << 16).contains(&message) {
                    Err("message must be 8..=512 KiB: a shorter one cannot hold a whole pattern word, the only part unique to its connection and round")
                } else if rounds == 0 || warmup.checked_add(rounds).is_none_or(|n| n as u64 > u64::from(u32::MAX)) {
                    Err("rounds must be positive and warmup + rounds below 2^32")
                } else {
                    Ok(())
                }
            }
            Shape::Bulk { bytes: 0, .. } => Err("bytes must be positive"),
            Shape::Bulk { .. } => Ok(()),
            Shape::UdpStream {
                size,
                count,
                warmup,
            } => {
                if !(8..=1472).contains(&size) {
                    Err("size must be 8..=1472")
                } else if warmup.checked_add(count).is_none() {
                    Err("warmup + count must fit u64")
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerMode {
    Echo,
    Sink,
    UdpSink { size: usize, warmup: u64 },
}

fn tx_pending(conns: usize) -> usize {
    conns.max(32)
}

/// Send again after the first flush if the first send filled the pending queue.
/// The second send also covers a stopping poll's RST.
fn send_poll(stack: &mut Stack, conns: usize) -> Result<Sent, StackError> {
    let first = stack.send()?;
    if first.tx_accepted.checked_add(first.tx_pending).expect("send frame count exceeds usize")
        < tx_pending(conns)
    {
        return Ok(first);
    }
    let second = stack.send()?;
    Ok(Sent {
        tx_accepted: first.tx_accepted.checked_add(second.tx_accepted)
            .expect("poll TX count exceeds usize"),
        tx_pending: second.tx_pending,
    })
}

/// Port settings for a side with `conns` connections of 64 KiB receive buffers.
/// The RX pool covers the driver reserve and socket budgets. The TX pool
/// covers 64 descriptors and every pending slot, with cache slack;
/// copy TX frees accepted mbufs.
pub fn port_config<'a>(port_id: u16, conns: usize, rx_pool: &'a CStr, tx_pool: &'a CStr) -> PortConfig<'a> {
    let headroom = RTE_PKTMBUF_HEADROOM as u16;
    let pool = |name, need: usize, data_room_size| PoolConfig {
        name,
        count: 64 + need as u32 + CACHE_SLACK,
        cache_size: POOL_CACHE,
        data_room_size,
        socket_id: -1,
    };
    PortConfig {
        port_id,
        mtu: 1500,
        // memif ignores descriptor counts; its ring depth is `rsize`.
        rx_descriptors: 64,
        tx_descriptors: 64,
        rx_burst: BURST,
        tx_burst: BURST,
        queue_socket: -1,
        rx_pool: PoolConfig {
            name: rx_pool,
            count: rx_pool_count(
                rx_reserve(64, RX_STAGING, POOL_CACHE),
                1500,
                std::iter::repeat(SOCKET_BUFFER).take(conns),
            ),
            cache_size: POOL_CACHE,
            data_room_size: headroom + BUFFER_SIZE,
            socket_id: -1,
        },
        tx_pool: pool(tx_pool, tx_pending(conns), headroom + FRAME),
        offloads: Offloads::default(),
    }
}

fn stack(
    port: Port,
    host: u8,
    conns: usize,
    udp: bool,
    random_seed: u64,
) -> Result<Stack, (Port, StackError)> {
    let config = StackConfig {
        max_udp_sockets: usize::from(udp),
        ethernet: EthernetAddress([0x02, 0, 0, 0, 0, host]),
        ipv4: Ipv4Cidr::new(Ipv4Address::new(10, 0, 0, host), 24),
        random_seed,
        neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
        segments_per_visit: 1,
        max_sockets: conns,
        rx_staging: RX_STAGING,
        tx_pending: tx_pending(conns),
        gateway: None,
        paths: &[],
    };
    Stack::new(port, config, NetInstant::ZERO)
}

fn udp_config(port: u16) -> UdpConfig {
    UdpConfig {
        port,
        rx_queue: usize::try_from(rx_pool_count(0, 1500, [SOCKET_BUFFER]))
            .expect("one socket RX budget fits usize"),
        tx_checksum: true,
        broadcast: false,
    }
}

fn socket() -> tcp::Config {
    tcp::Config { rx_capacity: SOCKET_BUFFER, tx_capacity: SOCKET_BUFFER, mss_cap: None }
}

/// `now` in microseconds since `origin`; negative before it, which
/// `Stack::receive` refuses as time going backwards.
fn net_time(origin: Instant, now: Instant) -> NetInstant {
    match now.checked_duration_since(origin) {
        Some(since) => NetInstant::from_micros(since.as_micros() as i64),
        None => NetInstant::from_micros(-((origin - now).as_micros() as i64)),
    }
}

/// Word `index` of stream `key`: the splitmix64 output for `key + index`.
/// Every step is a bijection, so distinct sums never give the same word, and
/// every output byte depends on every input bit. Ping-pong keys keep their
/// low 16 bits clear for the index (`message_key`).
fn pattern_word(key: u64, index: u64) -> u64 {
    let mut z = (key + index).wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Bytes `start..start + len` of the pattern stream keyed `key`, in pieces of
/// at most one word (`pattern_word`).
fn pattern_pieces(key: u64, start: u64, len: usize, mut each: impl FnMut(usize, &[u8])) {
    let mut done = 0;
    while done < len {
        let position = start + done as u64;
        let word = pattern_word(key, position / 8).to_le_bytes();
        let from = (position % 8) as usize;
        let n = (8 - from).min(len - done);
        each(done, &word[from..from + n]);
        done += n;
    }
}

/// Fill `dst` with pattern bytes from `start` of stream `key`. The bulk
/// stream is key 0, offset = stream offset.
pub fn fill_pattern(dst: &mut [u8], key: u64, start: u64) {
    pattern_pieces(key, start, dst.len(), |at, piece| {
        dst[at..at + piece.len()].copy_from_slice(piece)
    });
}

fn pattern_matches(src: &[u8], key: u64, start: u64) -> bool {
    let mut equal = true;
    pattern_pieces(key, start, src.len(), |at, piece| {
        equal &= src[at..at + piece.len()] == *piece
    });
    equal
}

/// Ping-pong message `round` of connection `conn`: its own word keys, so a
/// word from another connection or round never matches.
fn message_key(conn: usize, round: usize) -> u64 {
    (conn as u64) << 48 | (round as u64) << 16
}

/// Enqueue pattern bytes `from..to` of stream `key`; returns how many fit.
fn send_pattern(socket: &mut tcp::Socket<'static>, key: u64, from: usize, to: usize) -> usize {
    let mut at = from;
    while at < to {
        let n = socket
            .send(|buf| {
                let n = buf.len().min(to - at);
                fill_pattern(&mut buf[..n], key, at as u64);
                (n, n)
            })
            .expect("sending socket is Established");
        if n == 0 {
            break;
        }
        at += n;
    }
    at - from
}

/// Dequeue received bytes up to stream position `to`, checking them against
/// stream `key` from `from`. Returns the count and whether all matched.
fn recv_pattern(
    socket: &mut tcp::Socket<'static>,
    pending: &mut Option<(tcp::TcpFrame, usize)>,
    key: u64,
    from: usize,
    to: usize,
) -> (usize, bool) {
    let (mut at, mut equal) = (from, true);
    while at < to && (pending.is_some() || socket.can_recv()) {
        if pending.is_none() {
            *pending = Some((socket.recv().expect("can_recv: data is buffered").unwrap(), 0));
        }
        let (frame, offset) = pending.as_mut().unwrap();
        let count = (frame.payload().len() - *offset)
            .min(to.checked_sub(at).expect("received up to to"));
        equal &= pattern_matches(&frame.payload()[*offset..*offset + count], key, at as u64);
        *offset = offset.checked_add(count).expect("pattern frame offset exceeds usize");
        at = at.checked_add(count).expect("received stream position exceeds usize");
        if *offset == frame.payload().len() {
            *pending = None;
        }
    }
    (at - from, equal)
}

const CLIENT_PATH: [State; 7] = [
    State::SynSent,
    State::Established,
    State::FinWait1,
    State::FinWait2,
    State::Closing,
    State::TimeWait,
    State::Closed,
];
const PEER_PATH: [State; 6] = [
    State::Listen,
    State::SynReceived,
    State::Established,
    State::CloseWait,
    State::LastAck,
    State::Closed,
];

/// Move a socket last seen in `seen` to `now`. States only move forward along
/// `path`, and its last state, Closed, only from the one before it: Closed
/// from any other state is a reset or abort.
fn advance(path: &[State], seen: &mut State, now: State) -> Result<(), String> {
    let index = |state| path.iter().position(|&p| p == state);
    let legal = match (index(*seen), index(now)) {
        (Some(from), Some(to)) => to >= from && (to + 1 < path.len() || from + 2 >= path.len()),
        _ => false,
    };
    if !legal {
        return Err(format!("unexpected state {now} after {seen}"));
    }
    *seen = now;
    Ok(())
}

/// Sums of the counters of `poll`s, each one `Stack::receive` followed by
/// the application step and `send` for TCP (twice if the first fills the pending
/// queue) or `flush` for UDP. The peer counts every poll. The client counts
/// its measured window: RX frames (`rx_received`,
/// `rx_rejected`) iff the phase before the step is Measured; TX frames
/// (`received.tx_accepted + sent.tx_accepted`) iff the phase after the step is.
/// So the first measured writes and the last echoes count; the last warmup
/// echoes and the closing FINs don't. A poll counts toward `turns` iff either
/// half counted. Counter values compare only between runs counted under this
/// rule; timing (ns per round trip, RTT, elapsed) does not depend on it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    pub frames_rx: u64,
    pub frames_tx: u64,
    pub turns: u64,
    /// Counted polls that received and sent nothing, counted halves or not.
    pub idle_turns: u64,
    pub rx_rejected: u64,
}

impl Counters {
    fn add(&mut self, received: &Turn, sent: &Sent, count_received: bool, count_sent: bool) {
        if !(count_received || count_sent) {
            return;
        }
        if count_received {
            self.frames_rx += received.rx_received as u64;
            self.rx_rejected += received.rx_rejected as u64;
        }
        if count_sent {
            self.frames_tx += received.tx_accepted as u64 + sent.tx_accepted as u64;
        }
        self.turns += 1;
        self.idle_turns +=
            u64::from(received.rx_received == 0 && received.tx_accepted == 0 && sent.tx_accepted == 0);
    }

    fn frames(&self) -> u64 {
        self.frames_rx + self.frames_tx
    }

    fn json(&self) -> String {
        format!(
            "\"frames_rx\":{},\"frames_tx\":{},\"frames\":{},\"turns\":{},\"idle_turns\":{},\"rx_rejected\":{}",
            self.frames_rx, self.frames_tx, self.frames(), self.turns, self.idle_turns, self.rx_rejected
        )
    }
}

fn json_str(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            ch if u32::from(ch) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(ch))),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn validity_json(failure: &Option<String>, note: &str) -> String {
    let reason = failure.as_deref().map_or("null".to_string(), json_str);
    format!("\"valid\":{},\"reason\":{reason},\"note\":{}", failure.is_none(), json_str(note))
}

fn ratio(numerator: f64, denominator: f64) -> String {
    if denominator == 0.0 {
        return "null".to_string();
    }
    format!("{:.3}", numerator / denominator)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Connect,
    Warmup,
    Measured,
    Closing,
    Done,
}

struct Conn {
    handle: TcpHandle,
    seen: State,
    round: usize,
    /// Bytes of the current message (ping-pong) or of the stream (bulk).
    written: usize,
    echoed: usize,
    started: Instant,
    pending: Option<(tcp::TcpFrame, usize)>,
}

/// The measuring side: connects, warms up, measures, closes.
pub struct Client {
    stack: Stack,
    origin: Instant,
    shape: Shape,
    conns: Vec<Conn>,
    udp: Option<UdpHandle>,
    udp_sent: u64,
    phase: Phase,
    connect_by: Instant,
    finish_by: Instant,
    start: Option<Instant>,
    end: Option<Instant>,
    counters: Counters,
    /// Preallocated to the measured round count.
    rtt_ns: Vec<u64>,
    /// Bulk: stream bytes the peer acknowledged.
    acked: usize,
    failure: Option<String>,
}

impl Client {
    /// Connect every connection of `shape` at `now`; the run fails unless all
    /// are established by `now + connect_timeout` and done by
    /// `now + run_timeout`. An invalid shape returns the Port unchanged.
    pub fn new(
        port: Port,
        shape: Shape,
        connect_timeout: Duration,
        run_timeout: Duration,
        random_seed: u64,
        now: Instant,
    ) -> Result<Self, (Port, StackError)> {
        if let Err(reason) = shape.validate() {
            return Err((port, StackError::InvalidConfig(reason)));
        }
        let is_udp = matches!(shape, Shape::UdpStream { .. });
        let mut stack = stack(port, CLIENT_HOST, shape.conns(), is_udp, random_seed)?;
        let udp = is_udp.then(|| {
            stack
                .add_udp(udp_config(CLIENT_PORT_BASE))
                .expect("one UDP socket and its RX budget")
        });
        let remote = IpEndpoint::new(Ipv4Address::new(10, 0, 0, PEER_HOST).into(), PEER_PORT);
        let conns = (0..if is_udp { 0 } else { shape.conns() })
            .map(|c| {
                let handle = stack
                    .add_tcp(socket())
                    .unwrap_or_else(|_| panic!("max_sockets is the connection count"));
                stack.tcp_mut(&handle).set_ack_delay(Some(ACK_DELAY));
                stack
                    .connect(&handle, remote, CLIENT_PORT_BASE + c as u16)
                    .expect("unicast peer, unused local port");
                Conn { handle, seen: State::SynSent, round: 0, written: 0, echoed: 0, started: now, pending: None }
            })
            .collect();
        let samples = match shape {
            Shape::PingPong { conns, rounds, .. } => conns * rounds,
            Shape::Bulk { .. } | Shape::UdpStream { .. } => 0,
        };
        Ok(Self {
            stack,
            origin: now,
            shape,
            conns,
            udp,
            udp_sent: 0,
            phase: if is_udp {
                Phase::Warmup
            } else {
                Phase::Connect
            },
            connect_by: now + connect_timeout,
            finish_by: now + run_timeout,
            start: None,
            end: None,
            counters: Counters::default(),
            rtt_ns: Vec::with_capacity(samples),
            acked: 0,
            failure: None,
        })
    }

    /// Receive at `now` and push ingress replies, then run the client step
    /// and send. A request written in reply to an echo leaves in the poll
    /// that received the echo. A poll that stops the run (unexpected state,
    /// deadline) skips the step but
    /// still sends, so e.g. an aborted socket's RST leaves. `Ok(true)` once
    /// done; the client then needs no more polls.
    pub fn poll(&mut self, now: Instant) -> Result<bool, StackError> {
        if self.phase == Phase::Done {
            return Ok(true);
        }
        let received = self.stack.receive(net_time(self.origin, now), RX_STAGING)?;
        let before = self.phase;
        if received.rx_rejected != 0 {
            self.failure.get_or_insert(format!("{} frames rejected", received.rx_rejected));
        }
        if let Shape::UdpStream {
            size,
            count,
            warmup,
        } = self.shape
        {
            let measured_before = self.start.is_some();
            if now >= self.finish_by {
                self.stop("deadline passed".to_owned());
            } else {
                self.udp_stream(size, count, warmup);
            }
            let sent = self.stack.flush()?;
            self.counters
                .add(&received, &sent, measured_before, self.start.is_some());
            if self.phase == Phase::Warmup && self.udp_sent == warmup && sent.tx_pending == 0 {
                self.phase = Phase::Measured;
            }
            let total = warmup.checked_add(count).expect("validated UDP count");
            if self.phase != Phase::Done && self.udp_sent == total && sent.tx_pending == 0 {
                self.end = self.start.map(|_| Instant::now());
                self.phase = Phase::Done;
            }
            return Ok(self.phase == Phase::Done);
        }
        let stack = &mut self.stack;
        let unexpected = self.conns.iter_mut().enumerate().find_map(|(c, conn)| {
            let state = stack.tcp(&conn.handle).state();
            advance(&CLIENT_PATH, &mut conn.seen, state).err().map(|e| format!("connection {c}: {e}"))
        });
        let late = now >= self.finish_by || (self.phase == Phase::Connect && now >= self.connect_by);
        let stop = unexpected.or_else(|| late.then(|| format!("deadline passed in phase {:?}", self.phase)));
        if let Some(reason) = stop {
            self.stop(reason);
        } else {
            match self.phase {
                Phase::Connect if self.conns.iter().all(|conn| conn.seen == State::Established) => {
                    self.phase = Phase::Warmup;
                    self.step();
                }
                Phase::Connect => {}
                Phase::Warmup | Phase::Measured => self.step(),
                Phase::Closing | Phase::Done => {}
            }
        }
        let sent = send_poll(&mut self.stack, self.conns.len())?;
        self.counters.add(&received, &sent, before == Phase::Measured, self.phase == Phase::Measured);
        if self.phase == Phase::Closing && self.closed(&sent) {
            self.phase = Phase::Done;
        }
        Ok(self.phase == Phase::Done)
    }

    fn stop(&mut self, reason: String) {
        self.failure.get_or_insert(reason);
        self.phase = Phase::Done;
    }

    fn step(&mut self) {
        match self.shape {
            Shape::PingPong { message, rounds, warmup, .. } => {
                self.pingpong(message, warmup, rounds);
                if self.phase == Phase::Warmup && self.conns.iter().all(|conn| conn.round == warmup) {
                    self.phase = Phase::Measured;
                    self.pingpong(message, warmup, rounds);
                }
            }
            Shape::Bulk { bytes, warmup } => self.bulk(bytes, warmup),
            Shape::UdpStream { .. } => unreachable!("UDP has its own poll step"),
        }
    }

    fn udp_stream(&mut self, size: usize, count: u64, warmup: u64) {
        let total = if self.phase == Phase::Warmup {
            warmup
        } else {
            warmup.checked_add(count).expect("validated UDP count")
        };
        let handle = self.udp.as_ref().expect("UDP shape has a socket");
        let remote = IpEndpoint::new(Ipv4Address::new(10, 0, 0, PEER_HOST).into(), PEER_PORT);
        while self.udp_sent < total {
            let sequence = self.udp_sent;
            let start = &mut self.start;
            match self.stack.udp_send_with(&handle, Some(remote), size, |buf| {
                if sequence >= warmup {
                    start.get_or_insert_with(Instant::now);
                }
                buf[..8].copy_from_slice(&sequence.to_le_bytes());
                fill_pattern(&mut buf[8..], 0, 8);
            }) {
                Ok(()) => self.udp_sent = self.udp_sent.checked_add(1).expect("UDP sent count"),
                Err(UdpSendError::WouldBlock | UdpSendError::NeighborPending) => break,
                Err(error) => {
                    self.stop(format!("UDP send: {error:?}"));
                    break;
                }
            }
        }
    }

    fn pingpong(&mut self, message: usize, warmup: usize, rounds: usize) {
        let measured = self.phase == Phase::Measured;
        let target = if measured { warmup + rounds } else { warmup };
        let mut last_echo = None;
        for (c, conn) in self.conns.iter_mut().enumerate() {
            let socket = self.stack.tcp_mut(&conn.handle);
            while conn.round < target {
                let key = message_key(c, conn.round);
                if measured && conn.round == warmup && conn.written == 0 {
                    conn.started = Instant::now();
                    self.start.get_or_insert(conn.started);
                }
                conn.written += send_pattern(socket, key, conn.written, message);
                let (read, equal) = recv_pattern(socket, &mut conn.pending, key, conn.echoed, conn.written);
                conn.echoed += read;
                if !equal {
                    let reason = format!("connection {c} round {}: echoed bytes differ", conn.round);
                    self.failure.get_or_insert(reason);
                }
                if conn.echoed < message {
                    break;
                }
                if measured {
                    let echoed = Instant::now();
                    self.rtt_ns.push((echoed - conn.started).as_nanos() as u64);
                    // One clock read per round trip: this echo starts the next round.
                    conn.started = echoed;
                    last_echo = Some(echoed);
                }
                (conn.round, conn.written, conn.echoed) = (conn.round + 1, 0, 0);
            }
        }
        if let Some(end) = last_echo {
            if self.conns.iter().all(|conn| conn.round == target) {
                self.finish(end);
            }
        }
    }

    fn bulk(&mut self, bytes: usize, warmup: usize) {
        let conn = &mut self.conns[0];
        let socket = self.stack.tcp_mut(&conn.handle);
        if self.phase == Phase::Warmup {
            conn.written += send_pattern(socket, 0, conn.written, warmup);
            self.acked = conn.written - socket.send_queue();
            if self.acked < warmup {
                return;
            }
            self.phase = Phase::Measured;
            self.start = Some(Instant::now());
        }
        let total = warmup + bytes;
        conn.written += send_pattern(socket, 0, conn.written, total);
        self.acked = conn.written - socket.send_queue();
        if self.acked == total {
            self.finish(Instant::now());
        }
    }

    /// End the measured window at `end` and close every connection.
    fn finish(&mut self, end: Instant) {
        self.end = Some(end);
        self.phase = Phase::Closing;
        for conn in &self.conns {
            self.stack.tcp_mut(&conn.handle).close();
        }
    }

    /// Every socket TimeWait or Closed and nothing left pending after this
    /// poll's send, so the ACK of the peer's FIN reached the PMD: a FIN
    /// without payload returns from `process` (smoltcp 0.14.0 tcp.rs:2206-2208)
    /// before the delayed-ACK timer is armed (tcp.rs:2255), so that ACK leaves
    /// in the same poll's send. Relies on the v1 peer never sending data with
    /// its FIN (echo closes after the client stopped writing and every echo
    /// arrived; sink sends nothing), which would delay the ACK by ACK_DELAY.
    fn closed(&self, sent: &Sent) -> bool {
        self.conns.iter().all(|conn| matches!(conn.seen, State::TimeWait | State::Closed))
            && sent.tx_pending == 0
    }

    /// Panics if `conn` is not a connection index.
    pub fn socket(&mut self, conn: usize) -> &mut tcp::Socket<'static> {
        self.stack.tcp_mut(&self.conns[conn].handle)
    }

    pub fn report(&self) -> ClientReport {
        let warmup = match self.shape {
            Shape::PingPong { warmup, .. } | Shape::Bulk { warmup, .. } => warmup,
            Shape::UdpStream { .. } => 0,
        };
        let mut rtt_ns = self.rtt_ns.clone();
        rtt_ns.sort_unstable();
        ClientReport {
            shape: self.shape,
            elapsed_ns: match (self.start, self.end) {
                (Some(start), Some(end)) => (end - start).as_nanos() as u64,
                _ => 0,
            },
            conn_rounds: self.conns.iter().map(|conn| conn.round.saturating_sub(warmup)).collect(),
            bytes: self.acked.saturating_sub(warmup),
            sent: match self.shape {
                Shape::UdpStream { warmup, .. } if self.udp_sent >= warmup => self
                    .udp_sent
                    .checked_sub(warmup)
                    .expect("measured UDP sent count"),
                _ => 0,
            },
            rtt_ns,
            counters: self.counters,
            failure: self.failure.clone(),
        }
    }

    pub fn into_port(self) -> Port {
        self.stack.into_port()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientReport {
    pub shape: Shape,
    /// Measured window: first measured write to the last round's echo
    /// (ping-pong) or the last byte acknowledged (bulk; can include one
    /// delayed ACK, `BULK_NOTE`). UDP runs from the first measured datagram's
    /// fill to the flush that empties the pending queue after the last send.
    pub elapsed_ns: u64,
    /// Ping-pong: measured rounds each connection completed.
    pub conn_rounds: Vec<usize>,
    /// Bulk: measured bytes acknowledged.
    pub bytes: usize,
    /// UDP: measured datagrams queued for transmission.
    pub sent: u64,
    /// Ping-pong: one sample per measured round, ascending.
    pub rtt_ns: Vec<u64>,
    /// Measured window only.
    pub counters: Counters,
    /// `None` when valid.
    pub failure: Option<String>,
}

impl ClientReport {
    pub fn to_json(&self) -> String {
        let elapsed = self.elapsed_ns as f64;
        let (workload, note) = match self.shape {
            Shape::PingPong { conns, message, rounds, warmup } => {
                let round_trips: usize = self.conn_rounds.iter().sum();
                let rank = |p: usize| match self.rtt_ns.len() {
                    0 => "null".to_string(),
                    n => self.rtt_ns[(n * p).div_ceil(100) - 1].to_string(),
                };
                let workload = format!(
                    "\"shape\":\"{}\",\"conns\":{conns},\"message\":{message},\"rounds\":{rounds},\"warmup\":{warmup},\"elapsed_ns\":{},\"round_trips\":{round_trips},\"ns_per_round_trip_amortized\":{},\"rtt_p50_ns\":{},\"rtt_p99_ns\":{},\"rtt_max_ns\":{}",
                    if conns == 1 { "pingpong" } else { "parallel" },
                    self.elapsed_ns,
                    ratio(elapsed, round_trips as f64),
                    rank(50),
                    rank(99),
                    rank(100),
                );
                (workload, NOTE.to_owned())
            }
            Shape::Bulk { bytes, warmup } => {
                let workload = format!(
                    "\"shape\":\"bulk\",\"bytes\":{bytes},\"warmup\":{warmup},\"elapsed_ns\":{},\"bytes_acked\":{}",
                    self.elapsed_ns, self.bytes
                );
                (workload, format!("{NOTE}{BULK_NOTE}"))
            }
            Shape::UdpStream {
                size,
                count,
                warmup,
            } => {
                let workload = format!(
                    "\"shape\":\"udp\",\"size\":{size},\"count\":{count},\"warmup\":{warmup},\"sent\":{},\"elapsed_ns\":{},\"sent_pps\":{}",
                    self.sent, self.elapsed_ns, ratio(self.sent as f64 * 1e9, elapsed)
                );
                (workload, NOTE.to_owned())
            }
        };
        let frames = self.counters.frames() as f64;
        format!(
            "{{\"side\":\"client\",{workload},{},\"ns_per_frame\":{},\"frames_per_sec\":{},{}}}",
            self.counters.json(),
            ratio(elapsed, frames),
            ratio(frames * 1e9, elapsed),
            validity_json(&self.failure, &note)
        )
    }
}

struct PeerConn {
    handle: TcpHandle,
    seen: State,
    bytes: usize,
    pending: Option<(tcp::TcpFrame, usize)>,
}

/// The other side: `conns` listeners on `PEER_PORT`, each taking one
/// connection, echoing or sinking until the client closes.
///
/// The peer cannot tell a reset in LastAck from the final ACK: both move the
/// socket to Closed (smoltcp 0.14.0 tcp.rs:1895, 2040). Only the client
/// report catches it: the client sends a reset only when it aborts or for a
/// segment that matches no socket, and its own path requires TimeWait before
/// Closed. A run is valid only if both reports are.
pub struct Peer {
    stack: Stack,
    origin: Instant,
    mode: PeerMode,
    conns: Vec<PeerConn>,
    udp: Option<UdpHandle>,
    last_datagram: Instant,
    highest_sequence: Option<u64>,
    delivered: u64,
    warmup_delivered: u64,
    reordered: u64,
    finish_by: Instant,
    counters: Counters,
    failure: Option<String>,
    done: bool,
}

impl Peer {
    /// Listen at `now`; the run fails unless done by `now + run_timeout`.
    pub fn new(
        port: Port,
        mode: PeerMode,
        conns: usize,
        run_timeout: Duration,
        random_seed: u64,
        now: Instant,
    ) -> Result<Self, (Port, StackError)> {
        let is_udp = matches!(mode, PeerMode::UdpSink { .. });
        if let PeerMode::UdpSink { size, .. } = mode {
            if !(8..=1472).contains(&size) || conns != 1 {
                return Err((
                    port,
                    StackError::InvalidConfig("UDP sink needs size 8..=1472 and conns 1"),
                ));
            }
        }
        let mut stack = stack(port, PEER_HOST, conns, is_udp, random_seed)?;
        let udp = is_udp.then(|| {
            stack
                .add_udp(udp_config(PEER_PORT))
                .expect("one UDP socket and its RX budget")
        });
        let conns = (0..if is_udp { 0 } else { conns })
            .map(|_| {
                let handle = stack
                    .add_tcp(socket())
                    .unwrap_or_else(|_| panic!("max_sockets is the connection count"));
                stack.tcp_mut(&handle).set_ack_delay(Some(ACK_DELAY));
                stack.listen(&handle, PEER_PORT).expect("nonzero port");
                PeerConn { handle, seen: State::Listen, bytes: 0, pending: None }
            })
            .collect();
        Ok(Self {
            stack,
            origin: now,
            mode,
            conns,
            udp,
            last_datagram: now,
            highest_sequence: None,
            delivered: 0,
            warmup_delivered: 0,
            reordered: 0,
            finish_by: now + run_timeout,
            counters: Counters::default(),
            failure: None,
            done: false,
        })
    }

    /// Receive at `now` and push ingress replies, then serve every connection
    /// and send. An echo of data received in this poll leaves in it.
    /// Counted as one turn.
    /// `Ok(true)` once every connection was established and is Closed, or the
    /// run failed. For UDP, true also means no datagram for 50 ms. Keep polling
    /// until the sender is done; an idle UDP poll does not stop reception.
    pub fn poll(&mut self, now: Instant) -> Result<bool, StackError> {
        if self.done {
            return Ok(true);
        }
        let received = self.stack.receive(net_time(self.origin, now), RX_STAGING)?;
        if received.rx_rejected != 0 {
            self.failure.get_or_insert(format!("{} frames rejected", received.rx_rejected));
        }
        if let PeerMode::UdpSink { size, warmup } = self.mode {
            let handle = self.udp.as_ref().expect("UDP sink has a socket");
            while let Some(datagram) = self.stack.udp_mut(&handle).recv() {
                self.last_datagram = now;
                let payload = datagram.payload();
                if payload.len() != size {
                    self.failure
                        .get_or_insert(format!("UDP size {} differs from {size}", payload.len()));
                    continue;
                }
                let sequence = u64::from_le_bytes(payload[..8].try_into().expect("sequence word"));
                if !pattern_matches(&payload[8..], 0, 8) {
                    self.failure
                        .get_or_insert(format!("UDP sequence {sequence}: sink bytes differ"));
                }
                if self
                    .highest_sequence
                    .is_some_and(|highest| sequence < highest)
                {
                    self.reordered = self.reordered.checked_add(1).expect("UDP reordered count");
                }
                self.highest_sequence = Some(
                    self.highest_sequence
                        .map_or(sequence, |highest| highest.max(sequence)),
                );
                if sequence < warmup {
                    self.warmup_delivered = self
                        .warmup_delivered
                        .checked_add(1)
                        .expect("UDP warmup delivery count");
                } else {
                    self.delivered = self.delivered.checked_add(1).expect("UDP delivery count");
                }
            }
            let sent = self.stack.flush()?;
            self.counters.add(&received, &sent, true, true);
            if now >= self.finish_by {
                self.failure.get_or_insert("deadline passed".to_owned());
            }
            self.done = self.failure.is_some();
            return Ok(self.done || now.duration_since(self.last_datagram) >= UDP_IDLE);
        }
        for (c, conn) in self.conns.iter_mut().enumerate() {
            let socket = self.stack.tcp_mut(&conn.handle);
            if let Err(reason) = advance(&PEER_PATH, &mut conn.seen, socket.state()) {
                self.failure.get_or_insert(format!("connection {c}: {reason}"));
                self.done = true;
                continue;
            }
            if matches!(conn.seen, State::Established | State::CloseWait) {
                match self.mode {
                    PeerMode::Echo => conn.bytes += echo(socket, &mut conn.pending),
                    PeerMode::Sink => {
                        let (read, equal) = recv_pattern(socket, &mut conn.pending, 0, conn.bytes, usize::MAX);
                        conn.bytes += read;
                        if !equal {
                            self.failure.get_or_insert(format!("connection {c}: sink bytes differ"));
                        }
                    }
                    PeerMode::UdpSink { .. } => unreachable!("UDP has its own poll step"),
                }
            }
            // EOF seen and, for echo, every byte read is queued to send. The
            // FIN leaves in this poll's send, so the client's ACK can close the
            // socket before the next poll: record the state close() moved to.
            if conn.seen == State::CloseWait && socket.recv_queue() == 0 && conn.pending.is_none() {
                socket.close();
                advance(&PEER_PATH, &mut conn.seen, socket.state())
                    .expect("close in CloseWait moves to LastAck");
            }
        }
        let sent = send_poll(&mut self.stack, self.conns.len())?;
        self.counters.add(&received, &sent, true, true);
        if !self.done && now >= self.finish_by {
            self.failure.get_or_insert("deadline passed".to_string());
            self.done = true;
        }
        self.done |= self.conns.iter().all(|conn| conn.seen == State::Closed);
        Ok(self.done)
    }

    /// Panics if `conn` is not a connection index.
    pub fn socket(&mut self, conn: usize) -> &tcp::Socket<'static> {
        self.stack.tcp(&self.conns[conn].handle)
    }

    pub fn report(&self) -> PeerReport {
        PeerReport {
            mode: self.mode,
            conns: if self.udp.is_some() {
                1
            } else {
                self.conns.len()
            },
            bytes: self.conns.iter().map(|conn| conn.bytes).sum(),
            delivered: self.delivered,
            warmup_delivered: self.warmup_delivered,
            reordered: self.reordered,
            rx_dropped_full: self
                .udp
                .as_ref()
                .map_or(0, |handle| self.stack.udp(&handle).stats().rx_dropped_full),
            udp_counters: self.stack.udp_counters(),
            counters: self.counters,
            failure: self.failure.clone(),
        }
    }

    pub fn into_port(self) -> Port {
        self.stack.into_port()
    }
}

/// Echo up to the free send space, retaining any unread frame bytes for the next poll.
fn echo(socket: &mut tcp::Socket<'static>, pending: &mut Option<(tcp::TcpFrame, usize)>) -> usize {
    let mut echoed = 0usize;
    loop {
        let room = socket.send_capacity().checked_sub(socket.send_queue())
            .expect("send queue exceeds capacity");
        if room == 0 {
            return echoed;
        }
        if pending.is_none() {
            if !socket.can_recv() {
                return echoed;
            }
            *pending = Some((socket.recv().expect("can_recv: data is buffered").unwrap(), 0));
        }
        let (frame, offset) = pending.as_mut().unwrap();
        let read = room.min(frame.payload().len() - *offset);
        let sent = socket.send_slice(&frame.payload()[*offset..*offset + read])
            .expect("Established or CloseWait");
        assert_eq!(sent, read, "send buffer had room for every byte read");
        *offset = offset.checked_add(read).expect("echo frame offset exceeds usize");
        echoed = echoed.checked_add(read).expect("echo count exceeds usize");
        if *offset == frame.payload().len() {
            *pending = None;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerReport {
    pub mode: PeerMode,
    pub conns: usize,
    /// Bytes read from the client.
    pub bytes: usize,
    /// UDP: received datagrams at or above the warmup sequence boundary.
    pub delivered: u64,
    pub warmup_delivered: u64,
    pub reordered: u64,
    pub rx_dropped_full: u64,
    pub udp_counters: UdpCounters,
    /// Whole run, construction to done.
    pub counters: Counters,
    /// `None` when valid. A reset during the peer's close is invisible here
    /// (see `Peer`): a run is valid only if the client report is valid too.
    pub failure: Option<String>,
}

impl PeerReport {
    pub fn to_json(&self) -> String {
        let mode = match self.mode {
            PeerMode::Echo => "echo",
            PeerMode::Sink => "sink",
            PeerMode::UdpSink { size, warmup } => {
                return format!(
                    "{{\"side\":\"peer\",\"mode\":\"udp-sink\",\"size\":{size},\"warmup\":{warmup},\"delivered\":{},\"warmup_delivered\":{},\"reordered\":{},\"rx_dropped_full\":{},\"rx_no_port\":{},\"rx_checksum_bad\":{},\"rx_malformed\":{},\"rx_not_unicast\":{},{},{}}}",
                    self.delivered, self.warmup_delivered, self.reordered, self.rx_dropped_full,
                    self.udp_counters.rx_no_port, self.udp_counters.rx_checksum_bad,
                    self.udp_counters.rx_malformed, self.udp_counters.rx_not_unicast,
                    self.counters.json(), validity_json(&self.failure, NOTE)
                );
            }
        };
        format!(
            "{{\"side\":\"peer\",\"mode\":\"{mode}\",\"conns\":{},\"bytes\":{},{},{}}}",
            self.conns,
            self.bytes,
            self.counters.json(),
            validity_json(&self.failure, NOTE)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_shorter_than_one_pattern_word_are_rejected() {
        let shape = |message| Shape::PingPong { conns: 1, message, rounds: 1, warmup: 0 };
        for message in [0, 1, 7, (8 << 16) + 1] {
            assert!(shape(message).validate().unwrap_err().starts_with("message must be 8..=512 KiB"));
        }
        for message in [8, 8 << 16] {
            assert_eq!(shape(message).validate(), Ok(()));
        }
    }

    #[zhida_test_support::pinned_test]
    fn pattern_drain_retains_bytes_past_the_requested_position() {
        zhida_test_kit::with_eal(|eal| {
            use zhida_test_kit::pair::{self, App, Side};
            let mut pair = pair::new_pair(eal, ["patpenda", "patpendb"]);
            let ([client, server], _) = pair::establish(&mut pair, Side::A);
            let mut payload = [0; 64];
            fill_pattern(&mut payload, 7, 0);
            assert_eq!(pair.a.tcp_mut(&client).send_slice(&payload), Ok(payload.len()));
            pair.drive(|_, _| {}, |_, b| {
                if b.tcp(&server).recv_queue() == payload.len() { App::Done } else { App::Idle }
            });
            let socket = pair.b.tcp_mut(&server);
            let mut pending = None;
            assert_eq!(recv_pattern(socket, &mut pending, 7, 0, 17), (17, true));
            assert_eq!(socket.recv_queue(), 0);
            assert_eq!(socket.held_frames().count(), 1);
            assert_eq!(recv_pattern(socket, &mut pending, 7, 17, 64), (47, true));
            assert!(pending.is_none());
            assert_eq!(socket.held_frames().count(), 0);
            assert_eq!(pair.close(), 0);
        });
    }

    #[zhida_test_support::pinned_test]
    fn echo_drain_retains_bytes_until_send_space_is_free() {
        zhida_test_kit::with_eal(|eal| {
            use zhida_test_kit::pair::{self, App, Side};
            let mut pair = pair::new_pair(eal, ["echpenda", "echpendb"]);
            let ([client, server], _) = pair::establish(&mut pair, Side::A);
            let payload = pair::pattern(64, 41);
            assert_eq!(pair.a.tcp_mut(&client).send_slice(&payload), Ok(payload.len()));
            pair.drive(|_, _| {}, |_, b| {
                if b.tcp(&server).recv_queue() == payload.len() { App::Done } else { App::Idle }
            });
            let prefix = vec![0xa5; 4096 - 4];
            let socket = pair.b.tcp_mut(&server);
            assert_eq!(socket.send_slice(&prefix), Ok(prefix.len()));
            let mut pending = None;
            assert_eq!(echo(socket, &mut pending), 4);
            assert_eq!(socket.send_queue(), 4096);
            assert_eq!(socket.recv_queue(), 0);
            assert_eq!(socket.held_frames().count(), 1);
            let mut received = Vec::new();
            let mut echoed = 4;
            pair.drive(|_, _| {}, |a, b| {
                let bytes = pair::drain_bytes(a.tcp_mut(&client)).unwrap();
                received.extend_from_slice(&bytes);
                let sent = echo(b.tcp_mut(&server), &mut pending);
                echoed += sent;
                if received.len() == prefix.len() + payload.len() { App::Done }
                else if sent > 0 || !bytes.is_empty() { App::Moved } else { App::Idle }
            });
            assert_eq!(echoed, payload.len());
            assert_eq!(&received[..prefix.len()], prefix.as_slice());
            assert_eq!(&received[prefix.len()..], payload.as_slice());
            assert!(pending.is_none());
            assert_eq!(pair.b.tcp(&server).held_frames().count(), 0);
            assert_eq!(pair.close(), 0);
        });
    }

}
