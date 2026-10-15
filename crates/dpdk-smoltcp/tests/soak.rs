use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Instant as WallInstant;

use zhida_test_kit::pair::{self, Pair, Side};
use zhida_test_kit::wire::{Link, Verdict};
use zhida_test_kit::with_eal;
use dpdk_smoltcp::smoltcp::socket::tcp::State;
use dpdk_smoltcp::smoltcp::time::{Duration, Instant};
use dpdk_smoltcp::smoltcp::wire::{
    ArpOperation, ArpPacket, EthernetFrame, EthernetProtocol, IpEndpoint, IpProtocol, Ipv4Packet,
};
use dpdk_smoltcp::{Stack, StackConfig, TcpHandle, UdpConfig, UdpHandle, UdpSendError};

const BULK_MIN: u64 = (1u64 << 32) + (1 << 20);
const BUFFER: usize = 64 * 1024;
const UDP_PORT: u16 = 1234;
const RECONNECT_PORT: u16 = 8080;
const RECONNECT_CLIENT: u16 = 49153;
/// Rounds of traffic between idle gaps. Counted in rounds, not wall time, so the seed alone fixes
/// the workload; wall time only decides at which gap the run finishes.
const GAP_ROUNDS: u64 = 4_000_000;
static VIRTUAL_MICROS: AtomicI64 = AtomicI64::new(0);

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        mix(self.0)
    }

    fn below(&mut self, limit: u64) -> u64 {
        self.next() % limit
    }
}

fn mix(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn byte(offset: u64, seed: u64) -> u8 {
    (offset
        .wrapping_add(seed)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        >> 56) as u8
}

fn fill(bytes: &mut [u8], offset: u64, seed: u64) {
    for (index, value) in bytes.iter_mut().enumerate() {
        *value = byte(offset.checked_add(index as u64).unwrap(), seed);
    }
}

fn check(bytes: &[u8], offset: u64, seed: u64) {
    for (index, &value) in bytes.iter().enumerate() {
        let at = offset.checked_add(index as u64).unwrap();
        assert_eq!(value, byte(at, seed), "payload differs at offset {at}");
    }
}

#[derive(Default, Debug)]
struct Impairment {
    // Drop, duplicate and hold counts, TCP then UDP.
    counts: [[u64; 3]; 2],
    holding: bool,
}

fn impair(link: &mut Link, seed: u64, stats: Rc<RefCell<Impairment>>, enabled: Rc<Cell<bool>>) {
    let mut rng = Rng(seed);
    link.impair(move |bytes| {
        let eth = EthernetFrame::new_checked(bytes).unwrap();
        let protocol = if eth.ethertype() == EthernetProtocol::Ipv4 {
            match Ipv4Packet::new_checked(eth.payload())
                .unwrap()
                .next_header()
            {
                IpProtocol::Tcp => Some(0),
                IpProtocol::Udp => Some(1),
                _ => None,
            }
        } else {
            None
        };
        let mut stats = stats.borrow_mut();
        let verdict = if let Some(protocol) = protocol.filter(|_| enabled.get()) {
            let (verdict, counter) = match rng.below(10_000) {
                0..=99 => (Verdict::Drop, Some(0)),
                100..=149 => (Verdict::Duplicate, Some(1)),
                150..=249 if !stats.holding => (Verdict::Hold, Some(2)),
                _ => (Verdict::Deliver, None),
            };
            if let Some(counter) = counter {
                stats.counts[protocol][counter] =
                    stats.counts[protocol][counter].checked_add(1).unwrap();
            }
            verdict
        } else {
            Verdict::Deliver
        };
        match verdict {
            Verdict::Hold => stats.holding = true,
            Verdict::Deliver | Verdict::Duplicate => stats.holding = false,
            Verdict::Drop => {}
        }
        verdict
    });
}

fn round(pair: &mut Pair, at: Instant, arp: &mut [u64; 2]) -> bool {
    VIRTUAL_MICROS.store(at.total_micros(), Ordering::Relaxed);
    let result = pair.round_at(at, |dir, bytes| {
        let eth = EthernetFrame::new_checked(bytes).unwrap();
        if eth.ethertype() == EthernetProtocol::Arp
            && ArpPacket::new_checked(eth.payload()).unwrap().operation() == ArpOperation::Request
        {
            let index = match dir {
                pair::Dir::AToB => 0,
                pair::Dir::BToA => 1,
            };
            arp[index] = arp[index].checked_add(1).unwrap();
        }
    });
    for link in [&pair.a_to_b, &pair.b_to_a] {
        assert_eq!(link.pool_empty, 0);
        assert_eq!(link.ring_full, 0);
    }
    result.moved()
}

struct Stream {
    seed: u64,
    accepted: u64,
    received: u64,
}

impl Stream {
    fn new(seed: u64) -> Self {
        Self {
            seed,
            accepted: 0,
            received: 0,
        }
    }

    fn send(&mut self, stack: &mut Stack, handle: &TcpHandle, end: u64) {
        if self.accepted == end || !stack.tcp(handle).can_send() {
            return;
        }
        let count = stack
            .tcp_mut(handle)
            .send(|bytes| {
                let count = bytes
                    .len()
                    .min(usize::try_from(end.checked_sub(self.accepted).unwrap()).unwrap());
                fill(&mut bytes[..count], self.accepted, self.seed);
                (count, count)
            })
            .unwrap();
        self.accepted = self.accepted.checked_add(count as u64).unwrap();
    }

    fn receive(&mut self, stack: &mut Stack, handle: &TcpHandle) {
        while stack.tcp(handle).can_recv() {
            let frame = stack.tcp_mut(handle).recv().unwrap().unwrap();
            let bytes = frame.payload();
            assert!(!bytes.is_empty());
            check(bytes, self.received, self.seed);
            self.received = self.received.checked_add(bytes.len() as u64).unwrap();
            assert!(self.received <= self.accepted);
        }
    }
}

struct Datagrams {
    handles: [UdpHandle; 2],
    seeds: [u64; 2],
    sent: [u64; 2],
    received: [u64; 2],
}

fn udp_length(sequence: u64, seed: u64) -> usize {
    8 + 1 + (mix(sequence ^ seed) % 1400) as usize
}

impl Datagrams {
    fn send(&mut self, pair: &mut Pair, side: Side, count: u64) {
        let index = side.index();
        let (stack, _) = side.pick(&mut pair.a, &mut pair.b);
        for _ in 0..count {
            let sequence = self.sent[index];
            let seed = self.seeds[index];
            match stack.udp_send_with(
                &self.handles[index],
                Some(IpEndpoint::new(side.other().ip().into(), UDP_PORT)),
                udp_length(sequence, seed),
                |bytes| {
                    bytes[..8].copy_from_slice(&sequence.to_le_bytes());
                    fill(&mut bytes[8..], 0, mix(sequence ^ seed));
                },
            ) {
                Ok(()) => self.sent[index] = sequence.checked_add(1).unwrap(),
                Err(UdpSendError::NeighborPending | UdpSendError::WouldBlock) => break,
                Err(error) => panic!("UDP send: {error:?}"),
            }
        }
    }

    fn receive(&mut self, pair: &mut Pair) {
        for side in [Side::A, Side::B] {
            let index = side.other().index();
            let (stack, _) = side.pick(&mut pair.a, &mut pair.b);
            while let Some(datagram) = stack.udp_mut(&self.handles[side.index()]).recv() {
                assert_eq!(
                    datagram.src(),
                    IpEndpoint::new(side.other().ip().into(), UDP_PORT)
                );
                assert_eq!(datagram.dst_addr(), side.ip());
                let bytes = datagram.payload();
                assert!(bytes.len() >= 8);
                let sequence = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                assert!(sequence < self.sent[index]);
                assert_eq!(bytes.len(), udp_length(sequence, self.seeds[index]));
                check(&bytes[8..], 0, mix(sequence ^ self.seeds[index]));
                self.received[index] = self.received[index].checked_add(1).unwrap();
            }
        }
    }

    fn account(&self, pair: &Pair, impairment: &[Rc<RefCell<Impairment>>; 2]) {
        for (index, stack) in [&pair.b, &pair.a].into_iter().enumerate() {
            let counters = stack.udp_counters();
            let stats = stack.udp(&self.handles[1 - index]).stats();
            // The link only drops, duplicates and holds frames, so every receive error other than a
            // full queue is a stack bug and would otherwise hide inside the subtraction below.
            assert_eq!(
                [
                    counters.rx_no_port,
                    counters.rx_checksum_bad,
                    counters.rx_malformed,
                    counters.rx_not_unicast,
                    stats.rx_dropped_peer,
                ],
                [0; 5],
                "UDP direction {index} receive errors"
            );
            let receiver_drops = stats.rx_dropped_full;
            let [dropped, duplicated, _] = impairment[index].borrow().counts[1];
            let expected = self.sent[index]
                .checked_sub(dropped)
                .unwrap()
                .checked_add(duplicated)
                .unwrap()
                .checked_sub(receiver_drops)
                .unwrap();
            assert!(self.received[index] > 0, "UDP direction {index} delivered nothing");
            assert_eq!(self.received[index], expected, "UDP direction {index}");
            assert_eq!(stats.rx_delivered, self.received[index]);
            assert_eq!(stack.udp(&self.handles[1 - index]).rx_queued(), 0);
        }
    }
}

enum Phase {
    Idle,
    Connecting,
    Exchange,
    Closing { peer: Side, peer_closed: bool },
}

struct Reconnect {
    handles: [TcpHandle; 2],
    streams: [Stream; 2],
    lengths: [u64; 2],
    phase: Phase,
    cycles: u64,
}

impl Reconnect {
    fn tick(&mut self, pair: &mut Pair, rng: &mut Rng, start: bool, close: bool) {
        match &mut self.phase {
            Phase::Idle if start => {
                self.streams = [Stream::new(rng.next()), Stream::new(rng.next())];
                self.lengths = [1 + rng.below(256 * 1024), 1 + rng.below(256 * 1024)];
                pair.b.listen(&self.handles[1], RECONNECT_PORT).unwrap();
                pair.a
                    .connect(
                        &self.handles[0],
                        IpEndpoint::new(Side::B.ip().into(), RECONNECT_PORT),
                        RECONNECT_CLIENT,
                    )
                    .unwrap();
                self.phase = Phase::Connecting;
            }
            Phase::Idle => {}
            Phase::Connecting => {
                if pair.a.tcp(&self.handles[0]).state() == State::Established
                    && pair.b.tcp(&self.handles[1]).state() == State::Established
                {
                    self.phase = Phase::Exchange;
                }
            }
            Phase::Exchange => {
                self.streams[0].send(&mut pair.a, &self.handles[0], self.lengths[0]);
                self.streams[1].send(&mut pair.b, &self.handles[1], self.lengths[1]);
                self.streams[0].receive(&mut pair.b, &self.handles[1]);
                self.streams[1].receive(&mut pair.a, &self.handles[0]);
                let complete = (0..2).all(|index| {
                    self.streams[index].accepted == self.lengths[index]
                        && self.streams[index].received == self.lengths[index]
                });
                if close
                    && complete
                    && pair.a.tcp(&self.handles[0]).send_queue() == 0
                    && pair.b.tcp(&self.handles[1]).send_queue() == 0
                {
                    let side = if rng.below(2) == 0 { Side::A } else { Side::B };
                    let (stack, _) = side.pick(&mut pair.a, &mut pair.b);
                    let socket = stack.tcp_mut(&self.handles[side.index()]);
                    if self.cycles.checked_add(1).unwrap() % 50 == 0 {
                        socket.abort();
                    } else {
                        socket.close();
                    }
                    self.phase = Phase::Closing {
                        peer: side.other(),
                        peer_closed: false,
                    };
                }
            }
            Phase::Closing { peer, peer_closed } => {
                // Close the other half even if impairment lost the first FIN or RST.
                if !*peer_closed {
                    let (stack, _) = peer.pick(&mut pair.a, &mut pair.b);
                    stack.tcp_mut(&self.handles[peer.index()]).close();
                    *peer_closed = true;
                }
                let closed = [&pair.a, &pair.b]
                    .into_iter()
                    .enumerate()
                    .all(|(index, stack)| {
                        stack.tcp(&self.handles[index]).state() == State::Closed
                            && stack.tcp(&self.handles[index]).local_endpoint().is_none()
                    });
                if closed {
                    self.cycles = self.cycles.checked_add(1).unwrap();
                    self.phase = Phase::Idle;
                }
            }
        }
    }
}

#[derive(Default)]
struct Retransmits {
    last: [[u64; 2]; 2],
    total: [u64; 2],
}

impl Retransmits {
    fn record(&mut self, pair: &Pair, bulk: &[TcpHandle; 2], reconnect: &[TcpHandle; 2]) {
        for (flow, handles) in [bulk, reconnect].into_iter().enumerate() {
            for (side, stack) in [&pair.a, &pair.b].into_iter().enumerate() {
                let current = stack.tcp(&handles[side]).retransmits();
                let previous = self.last[flow][side];
                let added = if current < previous {
                    current
                } else {
                    current - previous
                };
                self.total[side] = self.total[side].checked_add(added).unwrap();
                self.last[flow][side] = current;
            }
        }
    }
}

fn summary(
    label: &str,
    started: WallInstant,
    now: Instant,
    bulk: &Stream,
    reconnect: &Reconnect,
    udp: &Datagrams,
    stats: &[Rc<RefCell<Impairment>>; 2],
    arp: [u64; 2],
    retransmits: &Retransmits,
    gaps: u64,
) {
    let counts = stats.each_ref().map(|stats| {
        let counts = stats.borrow().counts;
        std::array::from_fn::<_, 3, _>(|index| {
            counts[0][index].checked_add(counts[1][index]).unwrap()
        })
    });
    println!(
        "{label} seconds={:.3} virtual_us={} bulk={} accepted={} cycles={} UDP_sent={:?} UDP_received={:?} drops_dups_holds={counts:?} ARP={arp:?} idle_gaps={gaps} retransmits={:?}",
        started.elapsed().as_secs_f64(), now.total_micros(), bulk.received, bulk.accepted,
        reconnect.cycles, udp.sent, udp.received, retransmits.total,
    );
}

#[test]
#[ignore]
fn two_stacks_soak() {
    let seed = std::env::var("SOAK_SEED")
        .unwrap_or_else(|_| "1".into())
        .parse::<u64>()
        .unwrap();
    let seconds = std::env::var("SOAK_SECONDS")
        .unwrap_or_else(|_| "600".into())
        .parse::<u64>()
        .unwrap();
    println!("soak seed={seed} SOAK_SECONDS={seconds}");
    VIRTUAL_MICROS.store(pair::T0.total_micros(), Ordering::Relaxed);
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        eprintln!(
            "soak failure seed={seed} virtual_us={}",
            VIRTUAL_MICROS.load(Ordering::Relaxed)
        );
        previous_hook(info);
    }));
    with_eal(|eal| run(eal, seed, seconds));
}

/// No RX mbuf held and at most one TX mbuf per side: an unused TX token's packet
/// stays as the Device's spare until `into_port`.
fn drained(pair: &Pair) -> bool {
    pair.in_use().iter().all(|&(rx, tx)| rx == 0 && tx <= 1)
}

fn run(eal: &dpdk_smoltcp::Eal, seed: u64, seconds: u64) {
    let mut rng = Rng(seed);
    let configs = [Side::A, Side::B].map(|side| StackConfig {
        max_sockets: 2,
        max_udp_sockets: 1,
        tx_pending: 16,
        rx_staging: 128,
        random_seed: rng.next(),
        ..pair::config(side)
    });
    let mut pair = Pair::with_ports(
        eal,
        ["soaka", "soakb"],
        configs,
        pair::T0,
        1024,
        |_, port| {
            port.rx_pool.count = 8191;
            port.tx_pool.count = 1023;
            port.rx_burst = 64;
            port.tx_burst = 32;
        },
    );
    let stats = std::array::from_fn(|_| Rc::new(RefCell::new(Impairment::default())));
    let enabled = Rc::new(Cell::new(true));
    impair(
        &mut pair.a_to_b,
        rng.next(),
        Rc::clone(&stats[0]),
        Rc::clone(&enabled),
    );
    impair(
        &mut pair.b_to_a,
        rng.next(),
        Rc::clone(&stats[1]),
        Rc::clone(&enabled),
    );
    let bulk_handles = [&mut pair.a, &mut pair.b]
        .map(|stack| stack.add_tcp(pair::tcp_socket_sized(BUFFER)).unwrap());
    pair.b.listen(&bulk_handles[1], pair::SERVER_PORT).unwrap();
    pair.a
        .connect(
            &bulk_handles[0],
            IpEndpoint::new(Side::B.ip().into(), pair::SERVER_PORT),
            pair::CLIENT_PORT,
        )
        .unwrap();
    let mut bulk = Stream::new(rng.next());
    let mut reconnect = Reconnect {
        handles: [&mut pair.a, &mut pair.b]
            .map(|stack| stack.add_tcp(pair::tcp_socket_sized(BUFFER)).unwrap()),
        streams: [Stream::new(0), Stream::new(0)],
        lengths: [0; 2],
        phase: Phase::Idle,
        cycles: 0,
    };
    let mut udp = Datagrams {
        handles: [&mut pair.a, &mut pair.b].map(|stack| {
            stack
                .add_udp(UdpConfig {
                    port: UDP_PORT,
                    rx_queue: 128,
                    tx_checksum: true,
                    broadcast: false,
                })
                .unwrap()
        }),
        seeds: [rng.next(), rng.next()],
        sent: [0; 2],
        received: [0; 2],
    };
    let started = WallInstant::now();
    let mut progress_at = 60;
    let mut segment_rounds = 0u64;
    // Decided once when a segment's rounds run out: Some(true) finishes, Some(false) idles a gap.
    let mut segment_end = None;
    let mut gaps = 0u64;
    let mut arp = [0; 2];
    let mut retransmits = Retransmits::default();
    let mut quiet = 0;
    loop {
        if segment_end.is_none() && segment_rounds >= GAP_ROUNDS {
            segment_end = Some(
                started.elapsed().as_secs() >= seconds
                    && bulk.received >= BULK_MIN
                    && reconnect.cycles >= 1000
                    && gaps > 0,
            );
        }
        let pause = segment_end.is_some();
        let finish = segment_end == Some(true);
        segment_rounds = segment_rounds.checked_add(1).unwrap();
        let elapsed = started.elapsed().as_secs();
        let at = pair.now() + Duration::from_millis(10);
        let moved = round(&mut pair, at, &mut arp);
        retransmits.record(&pair, &bulk_handles, &reconnect.handles);
        bulk.receive(&mut pair.b, &bulk_handles[1]);
        udp.receive(&mut pair);
        reconnect.tick(&mut pair, &mut rng, !finish, !pause || finish);
        if !pause {
            bulk.send(&mut pair.a, &bulk_handles[0], u64::MAX);
        }
        if !pause || stats.iter().any(|stats| stats.borrow().holding) {
            for side in [Side::A, Side::B] {
                udp.send(&mut pair, side, 1 + rng.below(3));
            }
        }
        let reconnect_idle = if finish {
            matches!(reconnect.phase, Phase::Idle)
        } else {
            matches!(reconnect.phase, Phase::Exchange)
                && (0..2).all(|index| reconnect.streams[index].received == reconnect.lengths[index])
                && pair.a.tcp(&reconnect.handles[0]).send_queue() == 0
                && pair.b.tcp(&reconnect.handles[1]).send_queue() == 0
        };
        let idle = pause
            && reconnect_idle
            && bulk.received == bulk.accepted
            && pair.a.tcp(&bulk_handles[0]).send_queue() == 0
            && drained(&pair)
            && !moved
            && pair.a.poll_at().is_none()
            && pair.b.poll_at().is_none();
        if elapsed >= progress_at && pause && !idle {
            println!(
                "soak not idle: phase={} reconnect_idle={reconnect_idle} bulk_pending={} bulk_send_queue={} in_use={:?} moved={moved} poll_at=[{:?}, {:?}] states=[{}, {}] reconnect_states=[{}, {}]",
                match reconnect.phase {
                    Phase::Idle => "idle",
                    Phase::Connecting => "connecting",
                    Phase::Exchange => "exchange",
                    Phase::Closing { .. } => "closing",
                },
                bulk.accepted - bulk.received,
                pair.a.tcp(&bulk_handles[0]).send_queue(),
                pair.in_use(),
                pair.a.poll_at(),
                pair.b.poll_at(),
                pair.a.tcp(&bulk_handles[0]).state(),
                pair.b.tcp(&bulk_handles[1]).state(),
                pair.a.tcp(&reconnect.handles[0]).state(),
                pair.b.tcp(&reconnect.handles[1]).state(),
            );
        }
        if elapsed >= progress_at {
            summary(
                "soak progress",
                started,
                pair.now(),
                &bulk,
                &reconnect,
                &udp,
                &stats,
                arp,
                &retransmits,
                gaps,
            );
            progress_at = progress_at.checked_add(60).unwrap();
        }
        quiet = if idle { quiet + 1 } else { 0 };
        if quiet < 2 {
            continue;
        }
        if finish {
            break;
        }
        assert_eq!(pair.a.tcp(&bulk_handles[0]).state(), State::Established);
        assert_eq!(pair.b.tcp(&bulk_handles[1]).state(), State::Established);
        assert_eq!(pair.a.tcp(&reconnect.handles[0]).state(), State::Established);
        assert_eq!(pair.b.tcp(&reconnect.handles[1]).state(), State::Established);
        let before = arp;
        let at = pair.now() + Duration::from_secs(61);
        VIRTUAL_MICROS.store(at.total_micros(), Ordering::Relaxed);
        pair.a.receive(at, pair::BUDGET).unwrap();
        pair.b.receive(at, pair::BUDGET).unwrap();
        // Both probe before either can learn from its peer's ARP request.
        udp.send(&mut pair, Side::A, 1);
        udp.send(&mut pair, Side::B, 1);
        for _ in 0..3 {
            round(&mut pair, at, &mut arp);
            udp.receive(&mut pair);
        }
        for index in 0..2 {
            assert!(
                arp[index] > before[index],
                "side {index} did not re-ARP after idle"
            );
        }
        assert_eq!(pair.a.tcp(&bulk_handles[0]).state(), State::Established);
        assert_eq!(pair.b.tcp(&bulk_handles[1]).state(), State::Established);
        assert_eq!(pair.a.tcp(&reconnect.handles[0]).state(), State::Established);
        assert_eq!(pair.b.tcp(&reconnect.handles[1]).state(), State::Established);
        gaps = gaps.checked_add(1).unwrap();
        segment_rounds = 0;
        segment_end = None;
        quiet = 0;
    }
    assert!(started.elapsed().as_secs() >= seconds);
    assert_eq!(bulk.received, bulk.accepted);
    assert!(bulk.received >= BULK_MIN);
    assert!(bulk.received > 1u64 << 32);
    assert!(reconnect.cycles >= 1000);
    assert!(gaps > 0);

    enabled.set(false);
    pair.a.tcp_mut(&bulk_handles[0]).close();
    pair.b.tcp_mut(&bulk_handles[1]).close();
    loop {
        let at = pair.now() + Duration::from_millis(10);
        round(&mut pair, at, &mut arp);
        retransmits.record(&pair, &bulk_handles, &reconnect.handles);
        udp.receive(&mut pair);
        if started.elapsed().as_secs() >= progress_at {
            summary(
                "soak progress",
                started,
                pair.now(),
                &bulk,
                &reconnect,
                &udp,
                &stats,
                arp,
                &retransmits,
                gaps,
            );
            progress_at = progress_at.checked_add(60).unwrap();
        }
        if [&pair.a, &pair.b]
            .into_iter()
            .enumerate()
            .all(|(index, stack)| stack.tcp(&bulk_handles[index]).state() == State::Closed)
            && drained(&pair)
        {
            break;
        }
    }
    udp.account(&pair, &stats);
    assert!(!pair.a_to_b.free_held());
    assert!(!pair.b_to_a.free_held());
    for (index, link) in [&pair.a_to_b, &pair.b_to_a].into_iter().enumerate() {
        let counts = stats[index].borrow().counts;
        assert_eq!(
            link.dropped,
            counts[0][0].checked_add(counts[1][0]).unwrap()
        );
        assert_eq!(link.held, counts[0][2].checked_add(counts[1][2]).unwrap());
    }
    summary(
        "soak final",
        started,
        pair.now(),
        &bulk,
        &reconnect,
        &udp,
        &stats,
        arp,
        &retransmits,
        gaps,
    );
    let [bulk_a, bulk_b] = bulk_handles;
    let [reconnect_a, reconnect_b] = reconnect.handles;
    let [udp_a, udp_b] = udp.handles;
    for (stack, bulk, reconnect, udp) in [
        (&mut pair.a, bulk_a, reconnect_a, udp_a),
        (&mut pair.b, bulk_b, reconnect_b, udp_b),
    ] {
        stack.remove_tcp(bulk);
        stack.remove_tcp(reconnect);
        stack.remove_udp(udp);
    }
    assert!(drained(&pair));
    // Pair::close checks both pools are fully idle once the Stacks return their Ports.
    assert_eq!(pair.close(), 0, "a frame remained on a ring");
}
