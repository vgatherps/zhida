//! Test-only driver: two Stacks on net_ring Ports joined by copying links, on
//! one counter clock; plus the addressing and TCP helpers two-stack tests share.

use dpdk_smoltcp::smoltcp::phy::ChecksumCapabilities;
use dpdk_smoltcp::smoltcp::socket::tcp::{self, State};
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, IpAddress, IpEndpoint,
    IpProtocol, Ipv4Address, Ipv4Cidr, Ipv4Packet, Ipv4Repr, TcpPacket, TcpRepr,
};
use dpdk_smoltcp::{rx_pool_count, rx_reserve};
use dpdk_smoltcp::{
    Eal, Port, PortConfig, Stack, StackConfig, TcpHandle, Turn, DEFAULT_NEIGHBOR_CAPACITY,
};
use zhida_dpdk_sys::{rte_mempool, rte_ring};

use crate::ring_port::RingPort;
use crate::wire::{self, Link};

/// Ingress budget of every Pair turn.
pub const BUDGET: usize = 32;
/// Consecutive rounds without progress that fail a Pair drive or `Rounds`.
pub const IDLE_ROUNDS: u32 = 16;
/// Rounds that fail a Pair drive, or the lifetime of a `Rounds`, whatever
/// progress they made.
pub const MAX_ROUNDS: u32 = 100_000;

/// Drain every queued frame in order, returning an error only when no bytes were read.
pub fn drain_bytes(socket: &mut tcp::Socket<'_>) -> Result<Vec<u8>, tcp::RecvError> {
    let mut bytes = Vec::new();
    loop {
        match socket.recv() {
            Ok(Some(frame)) => bytes.extend_from_slice(frame.payload()),
            Ok(None) => return Ok(bytes),
            Err(error) if bytes.is_empty() => return Err(error),
            Err(_) => return Ok(bytes),
        }
    }
}

/// Round `t` up to a whole millisecond, leaving whole milliseconds unchanged.
/// Panics if the rounded time cannot be represented by `Instant`.
pub fn ceil_ms(t: Instant) -> Instant {
    let micros = t.total_micros();
    let remainder = micros.rem_euclid(1000);
    let rounded = if remainder == 0 {
        micros
    } else {
        micros
            .checked_add(1000 - remainder)
            .expect("rounded time exceeds Instant")
    };
    Instant::from_micros(rounded)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    AToB,
    BToA,
}

/// What the application did in one round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum App {
    Moved,
    Idle,
    Done,
}

/// What one round did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Round {
    pub a: Turn,
    pub b: Turn,
    /// Frames each link took off its sender's ring.
    pub a_to_b: usize,
    pub b_to_a: usize,
}

impl Round {
    /// Whether a turn received, processed or sent a frame, or a link moved one.
    pub fn moved(&self) -> bool {
        moved(&self.a) || moved(&self.b) || self.a_to_b + self.b_to_a > 0
    }
}

/// No Drop of its own, so `close` can take it apart. Fields drop in declaration
/// order: the links free held copies, the rings are drained so each Port finds
/// its pools idle, the Stacks close their Ports, and only then do the fixtures
/// release vdevs and rings.
pub struct Pair {
    pub a_to_b: Link,
    pub b_to_a: Link,
    drain_first: DrainFirst,
    pub a: Stack,
    pub b: Stack,
    now: Instant,
    /// Each open Port's RX pool, A then B, looked up once.
    rx_pools: [*mut rte_mempool; 2],
    fixtures: [RingPort; 2],
}

/// Frees every frame on the four rings when dropped.
struct DrainFirst([*mut rte_ring; 4]);

impl Drop for DrainFirst {
    fn drop(&mut self) {
        for ring in self.0 {
            wire::drain_ring(ring);
        }
    }
}

impl Pair {
    /// `names` are short and unique among live fixtures; rings hold 15 and TX pools 63.
    /// Each RX pool covers its Stack's reserve and `max_sockets` sockets with
    /// receive buffers up to 8688 bytes (6 * (1500 - 52)). Larger buffers need
    /// counts from `rx_pool_count` passed through `with_pools` or `with_ports`.
    pub fn new(eal: &Eal, names: [&str; 2], configs: [StackConfig<'_>; 2], now: Instant) -> Self {
        const SMALL: usize = 6 * (1500 - 52);
        Self::with_ports(eal, names, configs, now, 16, |side, port| {
            let stack = configs[side.index()];
            port.rx_pool.count = rx_pool_count(
                rx_reserve(
                    port.rx_descriptors,
                    stack.rx_staging,
                    port.rx_pool.cache_size,
                ),
                port.mtu,
                std::iter::repeat(SMALL).take(stack.max_sockets),
            );
        })
    }

    /// `new` with RX and TX rings of `ring` slots (holding `ring - 1`; a power
    /// of two) and RX and TX pools of `rx_pool` and `tx_pool` packets per side.
    pub fn with_pools(
        eal: &Eal,
        names: [&str; 2],
        configs: [StackConfig<'_>; 2],
        now: Instant,
        ring: u32,
        rx_pool: u32,
        tx_pool: u32,
    ) -> Self {
        Self::with_ports(eal, names, configs, now, ring, |_, config| {
            config.rx_pool.count = rx_pool;
            config.tx_pool.count = tx_pool;
        })
    }

    /// `new` with RX and TX rings of `ring` slots (holding `ring - 1`; a power
    /// of two) and each side's `RingPort::config` changed by `adjust`.
    pub fn with_ports(
        eal: &Eal,
        names: [&str; 2],
        configs: [StackConfig<'_>; 2],
        now: Instant,
        ring: u32,
        adjust: impl Fn(Side, &mut PortConfig<'_>),
    ) -> Self {
        Self::with_opened_ports(eal, names, configs, now, ring, adjust, |_, _| {})
    }

    /// `with_ports` with `opened` called for each Port after open and before
    /// Stack creation.
    pub fn with_opened_ports(
        eal: &Eal,
        names: [&str; 2],
        configs: [StackConfig<'_>; 2],
        now: Instant,
        ring: u32,
        adjust: impl Fn(Side, &mut PortConfig<'_>),
        opened: impl Fn(Side, &mut Port),
    ) -> Self {
        let fixtures = names.map(|name| RingPort::new(name, ring, ring));
        let [a, b] = [Side::A, Side::B].map(|side| {
            let fixture = &fixtures[side.index()];
            let mut config = fixture.config();
            adjust(side, &mut config);
            let mut port = fixture.open_with(eal, config);
            opened(side, &mut port);
            match Stack::new(port, configs[side.index()], now) {
                Ok(stack) => stack,
                Err((_, error)) => panic!("{error}"),
            }
        });
        let [first, second] = &fixtures;
        Self {
            a_to_b: first.link_to(second),
            b_to_a: second.link_to(first),
            drain_first: DrainFirst([first.rx_ring, first.tx_ring, second.rx_ring, second.tx_ring]),
            a,
            b,
            now,
            rx_pools: fixtures.each_ref().map(RingPort::rx_pool),
            fixtures,
        }
    }

    /// The time of the latest round or `turn_until_sent` turn.
    pub fn now(&self) -> Instant {
        self.now
    }

    /// Copy every frame into `side`'s RX pool and enqueue it on its RX ring,
    /// as its peer's link would; a full RX ring fails after freeing the copy
    /// it refused.
    pub fn inject(&self, side: Side, frames: &[Vec<u8>]) {
        self.fixtures[side.index()].inject_from(self.rx_pools[side.index()], frames);
    }

    /// Take every frame off `side`'s TX ring, in order, each seen by `inspect`
    /// and then freed; returns how many. Allocates nothing.
    pub fn drain_tx(&self, side: Side, inspect: impl FnMut(&[u8])) -> usize {
        wire::drain_ring_with(self.fixtures[side.index()].tx_ring, inspect)
    }

    /// (RX, TX) pool packets in use, A then B.
    pub fn in_use(&self) -> [(u32, u32); 2] {
        self.fixtures.each_ref().map(RingPort::in_use)
    }

    /// A turn, A→B, B turn, B→A, all at `now()`. `observe` sees every
    /// delivered frame.
    pub fn round(&mut self, mut observe: impl FnMut(Dir, &[u8])) -> Round {
        let a = self.a.turn(self.now, BUDGET).unwrap();
        let a_to_b = self.a_to_b.forward_with(|frame| observe(Dir::AToB, frame));
        let b = self.b.turn(self.now, BUDGET).unwrap();
        let b_to_a = self.b_to_a.forward_with(|frame| observe(Dir::BToA, frame));
        Round {
            a,
            b,
            a_to_b,
            b_to_a,
        }
    }

    /// Move the clock to `at`, which must not be earlier, then `round`.
    pub fn round_at(&mut self, at: Instant, observe: impl FnMut(Dir, &[u8])) -> Round {
        assert!(at >= self.now, "round_at {at} before {}", self.now);
        self.now = at;
        self.round(observe)
    }

    /// Turn only `side` at its production `poll_at` times until it sends a frame.
    /// Advance `now` through early wakeups without forwarding either link.
    /// Panics if no frame is sent by `bound`, or after `MAX_ROUNDS` turns.
    pub fn turn_until_sent(&mut self, side: Side, bound: Instant) -> Turn {
        assert!(bound >= self.now, "bound {bound} before {}", self.now);
        for _ in 0..MAX_ROUNDS {
            let (stack, _) = side.pick(&mut self.a, &mut self.b);
            let at = stack
                .poll_at()
                .expect("no deadline before a frame was sent");
            assert!(at >= self.now, "poll_at {at} before {}", self.now);
            assert!(
                at <= bound,
                "no frame sent by {bound}; next poll_at is {at}"
            );
            self.now = at;
            let turn = stack.turn(at, BUDGET).unwrap();
            if turn.tx_accepted > 0 {
                return turn;
            }
            assert!(at < bound, "no frame sent by {bound}");
        }
        panic!("no frame sent after {MAX_ROUNDS} turns at {}", self.now);
    }

    /// `drive_rounds` with an `app` that ignores the round.
    pub fn drive(
        &mut self,
        observe: impl FnMut(Dir, &[u8]),
        mut app: impl FnMut(&mut Stack, &mut Stack) -> App,
    ) {
        self.drive_rounds(observe, |_, a, b| app(a, b));
    }

    /// A `round`, then `app` with what it did, until `app` returns `Done`. A
    /// round in which no turn received, processed or sent a frame, no link
    /// moved a frame and `app` was idle moves the clock to the earliest stack
    /// deadline, never backwards; `IDLE_ROUNDS` such rounds in a row fail, as
    /// does round `MAX_ROUNDS`.
    pub fn drive_rounds(
        &mut self,
        mut observe: impl FnMut(Dir, &[u8]),
        mut app: impl FnMut(&Round, &mut Stack, &mut Stack) -> App,
    ) {
        let mut idle = 0;
        for round in 0.. {
            assert!(round < MAX_ROUNDS, "drive not done after {round} rounds at {}", self.now);
            let last = self.round(&mut observe);
            match app(&last, &mut self.a, &mut self.b) {
                App::Done => return,
                App::Moved => idle = 0,
                App::Idle if last.moved() => idle = 0,
                App::Idle => {
                    idle += 1;
                    assert!(idle < IDLE_ROUNDS, "no progress for {idle} rounds at {}", self.now);
                    let deadline =
                        [self.a.poll_at(), self.b.poll_at()].into_iter().flatten().min();
                    if let Some(at) = deadline {
                        self.now = self.now.max(at);
                    }
                }
            }
        }
    }

    /// Free both links' held frames, return both Stacks to Ports and free
    /// every frame still on the four rings; then every pool must be empty and
    /// the Ports close. Returns the held and ring frames freed.
    pub fn close(self) -> usize {
        let Self {
            a,
            b,
            mut a_to_b,
            mut b_to_a,
            drain_first,
            fixtures,
            ..
        } = self;
        // close counts the ring frames itself, and frees the rings.
        std::mem::forget(drain_first);
        let held = usize::from(a_to_b.free_held()) + usize::from(b_to_a.free_held());
        let ports = [a.into_port(), b.into_port()];
        let mut drained = 0;
        for fixture in &fixtures {
            drained += fixture.drain();
            assert_eq!(fixture.in_use(), (0, 0));
            fixture.assert_returned_exactly_once();
        }
        for port in ports {
            port.try_close().unwrap();
        }
        for fixture in fixtures {
            fixture.close();
        }
        held + drained
    }
}

fn moved(turn: &Turn) -> bool {
    turn.rx_received
        + turn.rx_rejected
        + turn.rx_ipv4_checksum_bad
        + turn.rx_processed
        + turn.tx_accepted
        > 0
}

pub const T0: Instant = Instant::from_millis_const(5_000);
pub const SERVER_PORT: u16 = 80;
pub const CLIENT_PORT: u16 = 49152;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    A,
    B,
}

impl Side {
    pub fn index(self) -> usize {
        self as usize
    }

    pub fn other(self) -> Side {
        match self {
            Side::A => Side::B,
            Side::B => Side::A,
        }
    }

    pub fn mac(self) -> EthernetAddress {
        EthernetAddress([0x02, 0, 0, 0, 0, 0x0a + self as u8])
    }

    pub fn ip(self) -> Ipv4Address {
        Ipv4Address::new(10, 0, 0, 1 + self as u8)
    }

    /// Direction of frames this side sends.
    pub fn dir(self) -> Dir {
        match self {
            Side::A => Dir::AToB,
            Side::B => Dir::BToA,
        }
    }

    /// This side's stack out of A and B.
    pub fn pick<'s>(self, a: &'s mut Stack, b: &'s mut Stack) -> (&'s mut Stack, &'s mut Stack) {
        match self {
            Side::A => (a, b),
            Side::B => (b, a),
        }
    }
}

/// One socket, RX staging and TX pending 32, seed per side.
pub fn config(side: Side) -> StackConfig<'static> {
    StackConfig {
        max_udp_sockets: 0,
        ethernet: side.mac(),
        ipv4: Ipv4Cidr::new(side.ip(), 24),
        gateway: None,
        paths: &[],
        random_seed: 1 + side as u64,
        neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
        segments_per_visit: 1,
        max_sockets: 1,
        rx_staging: 32,
        tx_pending: 32,
    }
}

pub fn new_pair(eal: &Eal, names: [&str; 2]) -> Pair {
    Pair::new(eal, names, [config(Side::A), config(Side::B)], T0)
}

/// Cubic, `size`-byte buffers each way.
pub fn tcp_socket_sized(size: usize) -> tcp::Config {
    tcp::Config { rx_capacity: size, tx_capacity: size, mss_cap: None }
}

/// `establish_sized` with 4 KiB buffers.
pub fn establish(pair: &mut Pair, client: Side) -> ([TcpHandle; 2], Vec<(Dir, Vec<u8>)>) {
    establish_sized(pair, client, 4096)
}

/// `client` connects to a listener on the other side, both with `size`-byte
/// buffers; drives until both sockets are Established. Returns the handles by
/// side and every delivered frame in order.
pub fn establish_sized(
    pair: &mut Pair,
    client: Side,
    size: usize,
) -> ([TcpHandle; 2], Vec<(Dir, Vec<u8>)>) {
    let server = client.other();
    let (client_stack, server_stack) = client.pick(&mut pair.a, &mut pair.b);
    let server_handle = server_stack.add_tcp(tcp_socket_sized(size)).unwrap();
    server_stack.listen(&server_handle, SERVER_PORT).unwrap();
    let client_handle = client_stack.add_tcp(tcp_socket_sized(size)).unwrap();
    client_stack
        .connect(&client_handle, IpEndpoint::new(server.ip().into(), SERVER_PORT), CLIENT_PORT)
        .unwrap();
    let handles = match client {
        Side::A => [client_handle, server_handle],
        Side::B => [server_handle, client_handle],
    };

    let mut frames = Vec::new();
    pair.drive(
        |dir, frame| frames.push((dir, frame.to_vec())),
        |a, b| {
            let established = |stack: &mut Stack, handle| {
                stack.tcp(handle).state() == State::Established
            };
            if established(a, &handles[0]) && established(b, &handles[1]) {
                App::Done
            } else {
                App::Idle
            }
        },
    );
    (handles, frames)
}

/// The TCP segment in `frame`, checking its Ethernet and IPv4 headers.
pub fn segment(frame: &[u8], src: Side) -> TcpRepr<'_> {
    let dst = src.other();
    let eth = EthernetFrame::new_checked(frame).unwrap();
    assert_eq!(
        (eth.src_addr(), eth.dst_addr(), eth.ethertype()),
        (src.mac(), dst.mac(), EthernetProtocol::Ipv4)
    );
    let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
    let ip_repr = Ipv4Repr::parse(&ip, &ChecksumCapabilities::default()).unwrap();
    assert_eq!(
        (ip_repr.src_addr, ip_repr.dst_addr, ip_repr.next_header),
        (src.ip(), dst.ip(), IpProtocol::Tcp)
    );
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    TcpRepr::parse(
        &tcp,
        &IpAddress::Ipv4(src.ip()),
        &IpAddress::Ipv4(dst.ip()),
        &ChecksumCapabilities::default(),
    )
    .unwrap()
}

/// The frame `src` sends to the other side carrying `tcp`, as `segment`
/// reads it.
pub fn tcp_frame(src: Side, tcp: &TcpRepr<'_>) -> Vec<u8> {
    let dst = src.other();
    tcp_frame_between((src.mac(), src.ip()), (dst.mac(), dst.ip()), tcp)
}

/// One Ethernet frame carrying `tcp` between the given MAC and IPv4 addresses.
pub fn tcp_frame_between(
    src: (EthernetAddress, Ipv4Address),
    dst: (EthernetAddress, Ipv4Address),
    tcp: &TcpRepr<'_>,
) -> Vec<u8> {
    let caps = ChecksumCapabilities::default();
    let eth = EthernetRepr {
        src_addr: src.0,
        dst_addr: dst.0,
        ethertype: EthernetProtocol::Ipv4,
    };
    let ip = Ipv4Repr {
        src_addr: src.1,
        dst_addr: dst.1,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    let mut bytes = vec![0; eth.buffer_len() + ip.buffer_len() + tcp.buffer_len()];
    let mut frame = EthernetFrame::new_unchecked(&mut bytes);
    eth.emit(&mut frame);
    let mut packet = Ipv4Packet::new_unchecked(frame.payload_mut());
    ip.emit(&mut packet, &caps);
    tcp.emit(
        &mut TcpPacket::new_unchecked(packet.payload_mut()),
        &IpAddress::Ipv4(src.1),
        &IpAddress::Ipv4(dst.1),
        &caps,
    );
    bytes
}

/// Deterministic bytes, different per `seed`.
pub fn pattern(len: usize, seed: u32) -> Vec<u8> {
    (0..len as u32)
        .map(|i| (i.wrapping_add(seed).wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect()
}

/// Rounds over two Stacks the caller holds through borrows (a session may hold
/// either Stack), joined by a Pair's links: turn A, A→B, turn B, B→A.
pub struct Rounds {
    now: Instant,
    rounds: u32,
    idle: u32,
}

impl Rounds {
    /// Starting at `now`, which must not be before the Stacks' last turn.
    pub fn new(now: Instant) -> Self {
        Self {
            now,
            rounds: 0,
            idle: 0,
        }
    }

    /// The time of the current round.
    pub fn now(&self) -> Instant {
        self.now
    }

    /// One round at the current time. Returns whether a turn received,
    /// processed or sent a frame, or a link moved one.
    pub fn round(
        &mut self,
        a: &mut Stack,
        a_to_b: &mut Link,
        b: &mut Stack,
        b_to_a: &mut Link,
    ) -> bool {
        self.round_with(a, a_to_b, b_to_a, |now| {
            moved(&b.turn(now, BUDGET).unwrap())
        })
    }

    /// `round` with B's turn done by `turn_b`, which gets the round's time and
    /// returns whether it moved anything.
    pub fn round_with(
        &mut self,
        a: &mut Stack,
        a_to_b: &mut Link,
        b_to_a: &mut Link,
        turn_b: impl FnOnce(Instant) -> bool,
    ) -> bool {
        assert!(
            self.rounds < MAX_ROUNDS,
            "not done after {} rounds at {}",
            self.rounds,
            self.now
        );
        self.rounds += 1;
        let turn_a = a.turn(self.now, BUDGET).unwrap();
        let forward_a = a_to_b.forward();
        assert_lossless(a_to_b, "A→B");
        let moved_b = turn_b(self.now);
        let forward_b = b_to_a.forward();
        assert_lossless(b_to_a, "B→A");
        moved(&turn_a) || moved_b || forward_a + forward_b > 0
    }

    /// Ends a round: when neither the round nor the caller made progress,
    /// moves the clock to the earliest Stack deadline, never backwards, and
    /// fails after `IDLE_ROUNDS` such rounds in a row.
    pub fn settle(&mut self, progress: bool, a: &mut Stack, b: &mut Stack) {
        if progress {
            self.idle = 0;
            return;
        }
        self.idle += 1;
        assert!(
            self.idle < IDLE_ROUNDS,
            "no progress for {} rounds at {}",
            self.idle,
            self.now
        );
        if let Some(at) = [a.poll_at(), b.poll_at()].into_iter().flatten().min() {
            self.now = self.now.max(at);
        }
    }
}

/// The link dropped and held nothing.
pub fn assert_lossless(link: &Link, name: &str) {
    assert_eq!(
        [link.ring_full, link.pool_empty, link.dropped, link.held],
        [0; 4],
        "{name} link [ring_full, pool_empty, dropped, held]"
    );
}
