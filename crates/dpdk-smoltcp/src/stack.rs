use std::fmt;
use std::io::Read;

use smoltcp::iface::{
    Config, DropQueue, Interface, NoRoute, PathMtu, PathMtus, PollIngressSingleResult, PollResult,
    SocketHandle, TcpCounters, TcpSet, TcpStorage, UdpAddError, UdpConfig, UdpCounters, UdpSendError, UdpSet,
    UdpSocket,
};
use smoltcp::phy::HeldFrames;
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv4Cidr,
};

use crate::device::Device;
use crate::handle::{TcpHandle, UdpHandle};
use crate::port::{Port, PortError};
use crate::rx_pool::{rx_reserve, tx_reserve};

/// Default number of on-link neighbors the ARP cache holds.
pub const DEFAULT_NEIGHBOR_CAPACITY: usize = 256;

/// Read the interface PRNG seed from OS entropy.
pub fn os_random_seed() -> std::io::Result<u64> {
    let mut bytes = [0; 8];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

#[derive(Debug, Clone, Copy)]
pub struct StackConfig<'a> {
    pub ethernet: EthernetAddress,
    /// The interface address and its connected subnet.
    pub ipv4: Ipv4Cidr,
    /// Default IPv4 route for destinations outside `ipv4`'s subnet; None
    /// reaches on-link peers only. Must be a unicast address inside that
    /// subnet other than our own, its network address and its broadcast
    /// address (a /31 has neither, RFC 3021).
    pub gateway: Option<Ipv4Address>,
    /// Per-destination path MTUs. Longest prefix wins. The interface subnet
    /// gets an implicit Port-MTU rule unless an explicit same-prefix rule replaces it.
    /// Results are clamped to the Port IP MTU; unmatched destinations use that MTU.
    /// Empty paths give every destination the Port IP MTU.
    /// TCP connects cap MSS at path MTU minus 40. Copied at `Stack::new`.
    pub paths: &'a [PathMtu],
    /// Interface PRNG seed, including the TCP ISN secret. Production callers
    /// use [`os_random_seed`]; tests and library benchmarks may fix it.
    pub random_seed: u64,
    /// How many on-link neighbors the ARP cache holds.
    /// [`DEFAULT_NEIGHBOR_CAPACITY`] is 256. When the cache is full, a new
    /// neighbor evicts the one that expires first.
    pub neighbor_capacity: usize,
    /// How many frames a socket may send in a row while other sockets have frames to send.
    /// A socket alone sends while it has segments ready. 1 keeps strict one-segment interleave.
    pub segments_per_visit: usize,
    pub max_sockets: usize,
    /// How many UDP sockets may be added. Zero disables UDP sockets.
    pub max_udp_sockets: usize,
    pub rx_staging: usize,
    /// Capacity of the Stack's pending TX frame queue: frames built but not
    /// yet accepted by the PMD.
    pub tx_pending: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackError {
    InvalidConfig(&'static str),
    IpMtuBelowIpv4Minimum { mtu: u16 },
    TxPoolTooSmall { count: usize, required: usize },
    TimeWentBackwards { last: Instant, now: Instant },
    Port(PortError),
}

impl fmt::Display for StackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for StackError {}

/// `add_tcp` refused the socket; each variant returns the config it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddTcpError {
    /// Every socket slot is in use (`StackConfig::max_sockets`).
    SocketsFull(tcp::Config),
    /// The RX pool cannot back this socket's receive budget beside the sockets already added.
    RxPoolTooSmall {
        config: tcp::Config,
        required: usize,
        pool: usize,
    },
}

impl fmt::Display for AddTcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SocketsFull(_) => write!(f, "stack has no free socket slot"),
            Self::RxPoolTooSmall { required, pool, .. } => {
                write!(
                    f,
                    "RX pool has {pool} mbufs; adding this socket requires {required}"
                )
            }
        }
    }
}

impl std::error::Error for AddTcpError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddUdpError {
    Full,
    PortInUse,
    InvalidConfig(&'static str),
    RxPoolTooSmall { required: usize, pool: usize },
}

/// Outcome of one `Stack::turn` or `Stack::receive`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Turn {
    /// Packets this turn's RX burst staged.
    pub rx_received: usize,
    /// Unsupported packets this turn's RX burst released.
    pub rx_rejected: usize,
    /// Frames released because the NIC reported a bad IPv4 header checksum
    /// with the RX checksum profile on (see `RxBurst::rx_ipv4_checksum_bad`).
    pub rx_ipv4_checksum_bad: usize,
    /// Staged packets handed to smoltcp this turn.
    pub rx_processed: usize,
    /// Packets still staged after ingress.
    pub rx_staged: usize,
    /// Ingress stopped with packets staged because no reply capacity (pending
    /// slot and TX packet) was available; not set when the budget ran out.
    /// An empty TX pool also blocks receive, because Device::receive takes
    /// a TX reservation first.
    pub rx_blocked: bool,
    /// Packets the PMD accepted across this call's flushes.
    pub tx_accepted: usize,
    /// Packets still pending after this call.
    pub tx_pending: usize,
}

/// Outcome of one `Stack::send` or `Stack::flush`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sent {
    /// Packets the PMD accepted in the final flush.
    pub tx_accepted: usize,
    /// Packets still pending after it.
    pub tx_pending: usize,
}

/// smoltcp interface, sockets and device over one owned Port, driven by
/// caller-supplied time.
///
/// Socket handles own their sockets and queue cleanup when dropped.
/// Handles may outlive the Stack; dropping them afterwards is harmless.
pub struct Stack {
    iface: Interface,
    /// Exactly `max_sockets` slots, never grown.
    sockets: TcpSet<'static>,
    udp: UdpSet,
    removed_held: Vec<HeldFrames>,
    dropped: DropQueue,
    dropped_tcp: Vec<SocketHandle>,
    dropped_udp: Vec<smoltcp::iface::UdpHandle>,
    rx_wakes: Vec<SocketHandle>,
    max_sockets: usize,
    rx_pool_count: usize,
    rx_reserve: usize,
    ip_mtu: u16,
    rx_budget_held: usize,
    /// Holds every staged and pending packet; its Port drops after them.
    device: Device,
    now: Instant,
}

impl Stack {
    /// Validate `config`, then build the interface at time `now` with one IPv4
    /// address. Invalid config, or `now` before `Instant::ZERO`, returns the
    /// Port unchanged with `InvalidConfig`.
    /// IP MTU below 68 returns the Port with `IpMtuBelowIpv4Minimum`.
    /// A TX pool below `tx_reserve` returns the Port with `TxPoolTooSmall`.
    /// The negotiated TX descriptor count bounds sent mbufs held by NIC PMDs.
    /// Test PMDs such as net_ring ignore that count and queue sent mbufs into
    /// an attached ring instead; their bound is the ring's capacity.
    ///
    /// smoltcp encodes "poll now" as `Instant::ZERO`, which `poll_at`
    /// normalization relies on; the monotonic rule of `turn` and `receive`
    /// keeps every later time at or above this start. Times near `i64::MAX`
    /// microseconds overflow upstream timer arithmetic.
    pub fn new(port: Port, config: StackConfig<'_>, now: Instant) -> Result<Self, (Port, StackError)> {
        if let Err(reason) = validate(&config) {
            return Err((port, StackError::InvalidConfig(reason)));
        }
        if now < Instant::ZERO {
            return Err((port, StackError::InvalidConfig("start time must be >= 0")));
        }
        let mtu = port
            .frame_capacity()
            .checked_sub(14)
            .expect("Ethernet header fits");
        if mtu < 68 {
            return Err((port, StackError::IpMtuBelowIpv4Minimum { mtu }));
        }
        let paths = match PathMtus::new(config.paths, config.ipv4, mtu) {
            Ok(paths) => paths,
            Err(reason) => return Err((port, StackError::InvalidConfig(reason))),
        };
        let count = port.tx_pool_count();
        let required = tx_reserve(port.descriptor_counts().1, config.tx_pending);
        if count < required {
            return Err((port, StackError::TxPoolTooSmall { count, required }));
        }
        let rx_pool_count = port.rx_pool_count();
        let rx_reserve = rx_reserve(
            port.descriptor_counts().0,
            config.rx_staging,
            port.rx_pool_cache_size(),
        );
        let mut device = Device::new(port, config.rx_staging, config.tx_pending);
        let mut iface_config = Config::new(config.ethernet.into());
        iface_config.random_seed = config.random_seed;
        iface_config.neighbor_capacity = config.neighbor_capacity;
        iface_config.segments_per_visit = config.segments_per_visit;
        let mut iface = Interface::new(iface_config, &mut device, now);
        iface.update_ip_addrs(|addrs| {
            // The address list starts empty and holds at least one entry.
            addrs.push(IpCidr::Ipv4(config.ipv4)).unwrap();
        });
        iface.set_ipv4_gateway(config.gateway);
        iface.set_path_mtus(paths);
        let mut storage = Vec::with_capacity(config.max_sockets);
        storage.resize_with(config.max_sockets, || TcpStorage::EMPTY);
        Ok(Self {
            iface,
            sockets: TcpSet::new(storage),
            udp: UdpSet::new(config.max_udp_sockets),
            removed_held: Vec::new(),
            dropped: DropQueue::with_capacity(config.max_sockets, config.max_udp_sockets),
            dropped_tcp: Vec::with_capacity(config.max_sockets),
            dropped_udp: Vec::with_capacity(config.max_udp_sockets),
            rx_wakes: Vec::with_capacity(config.max_sockets),
            max_sockets: config.max_sockets,
            rx_pool_count,
            rx_reserve,
            ip_mtu: mtu,
            rx_budget_held: 0,
            device,
            now,
        })
    }

    /// One bounded turn at `now`: flush pending, one RX burst, maintenance, up
    /// to `ingress_budget` received packets, egress passes until one reports no
    /// socket progress or queues no frame, flush.
    ///
    /// `now` earlier than the previous `new`/`turn`/`receive`
    /// time returns
    /// `TimeWentBackwards` without doing any work; equal times are allowed, so
    /// times stay >= 0.
    ///
    /// `receive` then `send` runs the same steps plus one flush between
    /// ingress and egress when frames are pending. Without TX backpressure both
    /// put the same frames on the wire with the same combined counters. When
    /// the pending queue or the TX ring is full, that flush can let more frames
    /// through in the same loop iteration: `tx_accepted` and `tx_pending`
    /// differ, and so can a later call's `rx_blocked`.
    ///
    /// Panics if `Port::alloc_tx` does: its TX done cleanup failing with an
    /// error other than `-ENOTSUP`. With `Offloads::tx_tcp_checksum` or
    /// `Offloads::tx_udp_checksum` on, also panics when a queued frame fails
    /// TX checksum preparation
    /// (see [`Offloads::tx_tcp_checksum`](crate::Offloads::tx_tcp_checksum) and
    /// [`Offloads::tx_udp_checksum`](crate::Offloads::tx_udp_checksum)).
    ///
    /// A panic unwinding out of `turn` leaves the Stack unusable: drop it or
    /// call `into_port`, nothing else.
    pub fn turn(&mut self, now: Instant, ingress_budget: usize) -> Result<Turn, StackError> {
        let mut turn = self.ingress(now, ingress_budget)?;
        turn.tx_accepted += self.egress()?;
        turn.tx_pending = self.device.pending();
        Ok(turn)
    }

    /// The first half of a turn, so the application can reply in the same
    /// loop iteration: `receive`, then read and write sockets, then `send`.
    /// At `now`: flush pending, one RX burst, maintenance, up to
    /// `ingress_budget` received packets, then flush again if frames are
    /// pending. Frames smoltcp built while processing received packets (RST,
    /// immediate and challenge ACKs, ARP replies) are thus offered to the PMD
    /// before the application step. Egress does not run: what sockets want to
    /// send, including what the application writes, waits for `send`.
    ///
    /// Time rules as `turn`. The extra flush when frames are pending is the
    /// one difference from `turn`, which runs egress before its final flush:
    /// under TX backpressure (pending queue or TX ring full) `receive` then
    /// `send` can let more frames through in this loop iteration than `turn`,
    /// with different `tx_accepted` and `tx_pending`, and so a different
    /// `rx_blocked` in a later call.
    ///
    /// Panics if `Port::alloc_tx` does: its TX done cleanup failing with an
    /// error other than `-ENOTSUP`. With `Offloads::tx_tcp_checksum` or
    /// `Offloads::tx_udp_checksum` on, also panics when a queued frame fails
    /// TX checksum preparation
    /// (see [`Offloads::tx_tcp_checksum`](crate::Offloads::tx_tcp_checksum) and
    /// [`Offloads::tx_udp_checksum`](crate::Offloads::tx_udp_checksum)).
    ///
    /// A panic unwinding out of `receive` leaves the Stack unusable: drop it
    /// or call `into_port`, nothing else.
    pub fn receive(&mut self, now: Instant, ingress_budget: usize) -> Result<Turn, StackError> {
        let mut turn = self.ingress(now, ingress_budget)?;
        if turn.tx_pending != 0 {
            turn.tx_accepted += self.device.flush().map_err(StackError::Port)?;
            turn.tx_pending = self.device.pending();
        }
        Ok(turn)
    }

    /// The second half of a turn: egress passes until one reports no socket
    /// progress or queues no frame, then flush. Whatever the application
    /// wrote to sockets since `receive` leaves here. Frames smoltcp builds in
    /// egress (SYN-ACK, retransmissions, expired delayed ACKs, window updates)
    /// also leave only here, after the application step: keep
    /// that step short, or connection setup and retransmissions wait for it.
    ///
    /// Runs at the time of the last `new`, `turn` or `receive`.
    /// Needs no preceding `receive` and may repeat; with nothing to send it
    /// sends nothing.
    ///
    /// Panics if `Port::alloc_tx` does: its TX done cleanup failing with an
    /// error other than `-ENOTSUP`. With `Offloads::tx_tcp_checksum` or
    /// `Offloads::tx_udp_checksum` on, also panics when a queued frame fails
    /// TX checksum preparation
    /// (see [`Offloads::tx_tcp_checksum`](crate::Offloads::tx_tcp_checksum) and
    /// [`Offloads::tx_udp_checksum`](crate::Offloads::tx_udp_checksum)).
    ///
    /// A panic unwinding out of `send` leaves the Stack unusable: drop it or
    /// call `into_port`, nothing else.
    pub fn send(&mut self) -> Result<Sent, StackError> {
        self.tidy();
        let tx_accepted = self.egress()?;
        Ok(Sent {
            tx_accepted,
            tx_pending: self.device.pending(),
        })
    }

    /// Push every pending frame to the PMD, burst after burst while it accepts
    /// everything offered. The unaccepted suffix stays pending in order;
    /// `tx_accepted` counts accepted frames and `tx_pending` counts that suffix.
    /// Retry on the caller's bounded cadence when frames remain pending.
    /// Builds no frames and does not change time; time rules are in [`Self::turn`].
    ///
    /// TX checksum preparation happens here. With `Offloads::tx_tcp_checksum`
    /// or `Offloads::tx_udp_checksum` on, panics when a queued frame fails preparation
    /// (see [`Offloads::tx_tcp_checksum`](crate::Offloads::tx_tcp_checksum) and
    /// [`Offloads::tx_udp_checksum`](crate::Offloads::tx_udp_checksum)).
    /// Unlike receive and send calls, this call does not use `Port::alloc_tx`
    /// or its TX done cleanup, so it cannot panic from that cleanup.
    ///
    /// A panic unwinding out of `flush` leaves the Stack unusable: drop it or
    /// call `into_port`, nothing else.
    pub fn flush(&mut self) -> Result<Sent, StackError> {
        let tx_accepted = self.device.flush().map_err(StackError::Port)?;
        Ok(Sent {
            tx_accepted,
            tx_pending: self.device.pending(),
        })
    }

    /// Resolve the configured gateway's Ethernet address. If it is not cached,
    /// queue one ARP request when the gateway is not rate-limited and TX
    /// capacity is available. The request leaves on the next flush.
    /// `Err(NoRoute)` when `StackConfig::gateway` is `None`.
    pub fn resolve_gateway(&mut self) -> Result<Option<EthernetAddress>, NoRoute> {
        self.iface.resolve_gateway(&mut self.device)
    }

    fn set_now(&mut self, now: Instant) -> Result<(), StackError> {
        if now < self.now {
            return Err(StackError::TimeWentBackwards {
                last: self.now,
                now,
            });
        }
        self.now = now;
        Ok(())
    }

    /// Time check, flush, one RX burst, maintenance, then ingress.
    fn ingress(&mut self, now: Instant, ingress_budget: usize) -> Result<Turn, StackError> {
        self.set_now(now)?;
        self.tidy();
        let tx_accepted = self.device.flush().map_err(StackError::Port)?;
        let burst = self.device.rx_burst().map_err(StackError::Port)?;
        self.iface.poll_maintenance(now);

        let mut rx_processed = 0;
        let mut rx_blocked = false;
        while rx_processed < ingress_budget {
            match self.iface.poll_ingress_single_udp(
                now,
                &mut self.device,
                &mut self.sockets,
                &mut self.udp,
            ) {
                PollIngressSingleResult::None => {
                    rx_blocked = self.device.staged() != 0;
                    break;
                }
                PollIngressSingleResult::PacketProcessed
                | PollIngressSingleResult::SocketStateChanged => {}
            }
            rx_processed += 1;
        }

        Ok(Turn {
            rx_received: burst.accepted,
            rx_rejected: burst.rejected,
            rx_ipv4_checksum_bad: burst.rx_ipv4_checksum_bad,
            rx_processed,
            rx_staged: self.device.staged(),
            rx_blocked,
            tx_accepted,
            tx_pending: self.device.pending(),
        })
    }

    /// Egress passes at the stored time, then flush; returns the frames the
    /// PMD accepted.
    fn egress(&mut self) -> Result<usize, StackError> {
        // Every pass that continues the loop queued a frame into the
        // fixed-capacity pending queue, so at most capacity + 1 passes run. A
        // pass can report a change without queueing anything: smoltcp drops an
        // IPv4 packet larger than the IP MTU without using the TX token, and a
        // socket may then want the same send again at this time.
        // Stop after a send when the next pass would do nothing.
        loop {
            let pending = self.device.pending();
            if self
                .iface
                .poll_egress(self.now, &mut self.device, &mut self.sockets)
                == PollResult::None
            {
                break;
            }
            if self.device.pending() == pending {
                break;
            }
            if self.iface.egress_idle(&self.sockets) {
                break;
            }
        }
        self.device.flush().map_err(StackError::Port)
    }

    /// When sockets next want a turn, evaluated at the latest time given
    /// to `new`, `turn` or `receive`; a deadline already past is reported as
    /// that time, as is a socket with a segment ready to send. `None`: no
    /// socket deadline. Socket timers live in a millisecond timer wheel: the
    /// result is the next wheel boundary or ready/due socket, never later than
    /// the earliest socket deadline rounded up to a whole millisecond, and may
    /// be earlier (a turn at a boundary can find nothing due).
    ///
    /// A non-empty DropQueue, or a dropped socket that reached CLOSED, reports
    /// the current time so the next turn processes or frees it.
    /// It does not cover frames staged or pending in the Stack. When the last
    /// `turn` or `receive` reported `rx_staged > 0` without
    /// `rx_blocked`, the ingress budget ran out: call it again promptly. When
    /// an ingress call reported `rx_blocked`, or a call reported `tx_pending > 0`,
    /// the next call progresses only once the PMD accepts frames or frees TX
    /// packets: retry on the caller's own bounded cadence, independent of this
    /// deadline. Pending frames leave through `flush`, or the flush inside
    /// `turn`, `receive` or `send`. When a call reported `tx_pending > 0`, call
    /// `flush` until nothing is pending, then `send`: `send` runs egress before
    /// its flush, so a full pending queue lets it only flush. An ordinary TCP
    /// sender refused by the full queue stays due now and is served first on
    /// retry; a refused dropped socket's zero-window probe is rescheduled.
    /// An ARP probe owed for a stale neighbor is not covered by this deadline.
    /// After freeing capacity, `send` or `turn` retries that probe in egress.
    pub fn poll_at(&mut self) -> Option<Instant> {
        if !self.dropped.is_empty() || self.sockets.has_reapable() {
            return Some(self.now);
        }
        self.iface
            .poll_at(self.now, &mut self.sockets)
            .map(|at| at.max(self.now))
    }

    /// Build a TCP socket from `config` and admit it. Returns the config when all
    /// `max_sockets` slots are occupied or the RX pool cannot back the socket's
    /// receive budget, `tcp::rx_mbuf_budget(&config, ip_mtu)`, beside the RX reserve
    /// and every socket already added.
    /// Held TCP frames and UDP datagrams from removed sockets count until dropped.
    /// Connections never use TCP timestamps.
    /// A dropped connection holds its slot until it closes; `SocketsFull` is
    /// returned until then. If it closes during a call, the next tidying call
    /// frees the slot.
    ///
    /// # Panics
    /// If `config.rx_capacity` exceeds 1 GiB or `config.mss_cap` is `Some(0)`.
    pub fn add_tcp(&mut self, config: tcp::Config) -> Result<TcpHandle, AddTcpError> {
        self.tidy();
        // Upstream `add` pushes a new slot when none is free.
        if self.sockets.len() == self.max_sockets {
            return Err(AddTcpError::SocketsFull(config));
        }
        let budget = tcp::rx_mbuf_budget(&config, usize::from(self.ip_mtu));
        let held = self
            .rx_budget_held
            .checked_add(budget)
            .expect("RX socket budgets exceed usize");
        let required = self.required_rx_pool(budget);
        if required > self.rx_pool_count {
            return Err(AddTcpError::RxPoolTooSmall {
                config,
                required,
                pool: self.rx_pool_count,
            });
        }
        let handle = self.sockets.add_admitted(
            &config,
            usize::from(self.ip_mtu),
            self.dropped.clone(),
        );
        self.rx_budget_held = held;
        Ok(TcpHandle {
            raw: handle,
            queue: self.dropped.clone(),
        })
    }

    fn required_rx_pool(&mut self, budget: usize) -> usize {
        let mut held_by_removed = 0usize;
        self.removed_held.retain(|held| {
            let count = held.count();
            held_by_removed = held_by_removed
                .checked_add(count)
                .expect("removed frame counts exceed usize");
            count != 0
        });
        self.rx_reserve
            .checked_add(self.rx_budget_held)
            .and_then(|count| count.checked_add(held_by_removed))
            .and_then(|count| count.checked_add(budget))
            .expect("RX pool requirement exceeds usize")
    }

    /// Bind one local UDP port exclusively. The RX pool must back `rx_queue`
    /// datagrams beside the RX reserve and every TCP and UDP socket's budget.
    /// Held TCP frames and UDP datagrams from removed sockets count until dropped.
    pub fn add_udp(&mut self, config: UdpConfig) -> Result<UdpHandle, AddUdpError> {
        self.tidy();
        let required = self.required_rx_pool(config.rx_queue);
        if required > self.rx_pool_count {
            return Err(AddUdpError::RxPoolTooSmall {
                required,
                pool: self.rx_pool_count,
            });
        }
        let handle = self.udp.add(config).map_err(|error| match error {
            UdpAddError::Full => AddUdpError::Full,
            UdpAddError::PortInUse => AddUdpError::PortInUse,
            UdpAddError::InvalidConfig(reason) => AddUdpError::InvalidConfig(reason),
        })?;
        self.rx_budget_held = self
            .rx_budget_held
            .checked_add(config.rx_queue)
            .expect("RX socket budgets exceed usize");
        Ok(UdpHandle {
            raw: handle,
            queue: self.dropped.clone(),
        })
    }

    /// Read-only access to a UDP socket.
    pub fn udp(&self, handle: &UdpHandle) -> &UdpSocket {
        self.udp.get(self.udp_raw(handle))
    }

    /// Change a UDP socket.
    /// Replacing the socket through this reference is unsupported:
    /// its receive budget is charged at `add_udp`.
    pub fn udp_mut(&mut self, handle: &UdpHandle) -> &mut UdpSocket {
        let raw = self.udp_raw(handle);
        self.udp.get_mut(raw)
    }

    /// Write one datagram in place at this Stack's current time.
    /// `to` may be omitted for a connected socket. Errors return before `fill` runs.
    /// The frame joins TCP frames in the shared pending FIFO in call order and
    /// leaves on `flush`, or the flush inside `turn`, `receive` or `send`.
    ///
    /// `WouldBlock` means the pending queue or TX pool is full: flush, then retry.
    /// Flush at least every `StackConfig::tx_pending` sends. A full pending queue
    /// also blocks ingress (`Turn::rx_blocked`) if the PMD refuses its frames;
    /// `receive` and `turn` flush first but can remain blocked if TX cannot progress.
    /// A send loop must call `receive` or `turn` to take ARP replies and advance time.
    pub fn udp_send_with(
        &mut self,
        handle: &UdpHandle,
        to: Option<IpEndpoint>,
        len: usize,
        fill: impl FnOnce(&mut [u8]),
    ) -> Result<(), UdpSendError> {
        let raw = self.udp_raw(handle);
        let target = self.iface.udp_target(&self.udp, raw, to, len)?;
        self.iface
            .udp_send(&mut self.device, &mut self.udp, target, fill)
    }

    /// Copy one datagram into the shared pending FIFO, in call order with TCP frames.
    /// `WouldBlock` means flush, then retry; flush at least every
    /// `StackConfig::tx_pending` sends because a full queue also blocks ingress
    /// (`Turn::rx_blocked`). `receive` and `turn` flush before ingress.
    /// A send loop must call `receive` or `turn` to take ARP replies and advance time.
    pub fn udp_send(
        &mut self,
        handle: &UdpHandle,
        to: Option<IpEndpoint>,
        payload: &[u8],
    ) -> Result<(), UdpSendError> {
        self.udp_send_with(handle, to, payload.len(), |buffer| {
            buffer.copy_from_slice(payload)
        })
    }

    /// Free queued datagrams and release the socket's RX budget.
    /// Datagrams the application still holds count against admission until dropped.
    pub fn remove_udp(&mut self, handle: UdpHandle) {
        self.udp_raw(&handle);
        self.remove_udp_raw(handle.into_raw());
    }

    fn remove_udp_raw(&mut self, handle: smoltcp::iface::UdpHandle) {
        let budget = self.udp.get(handle).config().rx_queue;
        let held = self.udp.remove(handle);
        self.rx_budget_held = self
            .rx_budget_held
            .checked_sub(budget)
            .expect("removed socket's RX budget was held");
        if held.count() != 0 {
            self.removed_held.push(held);
        }
    }

    /// TCP segments rejected by software checksum verification.
    pub fn tcp_counters(&self) -> TcpCounters {
        self.sockets.counters()
    }

    /// Receive counters for all UDP ports, including ports with no socket.
    pub fn udp_counters(&self) -> UdpCounters {
        self.udp.counters()
    }

    /// IPv4 packets rejected before transport processing.
    pub fn ipv4_dropped(&self) -> u64 {
        self.iface.ipv4_dropped()
    }

    /// Read-only access to a socket, including retransmits, loss_events and congestion_window. Marks nothing.
    pub fn tcp(&self, handle: &TcpHandle) -> &tcp::Socket<'static> {
        self.sockets.get(self.tcp_raw(handle))
    }

    /// Change a socket and schedule a readiness check before the next
    /// `poll_at` call or egress pass. No public API hands out an owned socket, so
    /// this reference cannot be overwritten with a new one; swapping it with a
    /// socket held by another `TcpSet` or Stack is unsupported.
    pub fn tcp_mut(&mut self, handle: &TcpHandle) -> &mut tcp::Socket<'static> {
        let raw = self.tcp_raw(handle);
        self.sockets.get_mut(raw)
    }

    /// `tcp::Socket::connect` with this interface's context; refuses a live exact tuple.
    /// A failed connect leaves the socket unchanged.
    pub fn connect<T: Into<IpEndpoint>, U: Into<IpListenEndpoint>>(
        &mut self,
        handle: &TcpHandle,
        remote: T,
        local: U,
    ) -> Result<(), tcp::ConnectError> {
        let raw = self.tcp_raw(handle);
        let remote = remote.into();
        let local = self.sockets.get(raw).connect_local_endpoint(
            self.iface.context(),
            remote,
            local.into(),
        )?;
        if self.sockets.iter().any(|(_, socket)| {
            !matches!(socket.state(), tcp::State::Closed | tcp::State::Listen)
                && socket.local_endpoint() == Some(local)
                && socket.remote_endpoint() == Some(remote)
        }) {
            return Err(tcp::ConnectError::AddressInUse);
        }
        let socket = self.sockets.get_mut(raw);
        socket.connect(self.iface.context(), remote, local)?;
        Ok(())
    }

    /// `tcp::Socket::listen`. A failed listen leaves the socket unchanged.
    pub fn listen<T: Into<IpListenEndpoint>>(
        &mut self,
        handle: &TcpHandle,
        local: T,
    ) -> Result<(), tcp::ListenError> {
        let raw = self.tcp_raw(handle);
        let socket = self.sockets.get_mut(raw);
        socket.listen(local)?;
        Ok(())
    }

    /// Remove the socket immediately, freeing its slot and RX budget.
    /// Discards unread received bytes and sends nothing on the wire.
    /// Frames the application still holds count against admission until dropped.
    pub fn remove_tcp(&mut self, handle: TcpHandle) {
        self.tcp_raw(&handle);
        self.tidy();
        self.remove_tcp_raw(handle.into_raw());
    }

    fn remove_tcp_raw(&mut self, handle: SocketHandle) {
        let (held, budget) = self.sockets.remove(handle);
        if held.count() != 0 {
            self.removed_held.push(held);
        }
        self.rx_budget_held = self
            .rx_budget_held
            .checked_sub(budget)
            .expect("removed socket's RX budget was held");
    }

    fn tcp_raw(&self, handle: &TcpHandle) -> SocketHandle {
        assert!(
            handle.queue.same(&self.dropped),
            "TCP handle belongs to another Stack"
        );
        handle.raw
    }

    fn udp_raw(&self, handle: &UdpHandle) -> smoltcp::iface::UdpHandle {
        assert!(
            handle.queue.same(&self.dropped),
            "UDP handle belongs to another Stack"
        );
        handle.raw
    }

    fn tidy(&mut self) {
        if self.dropped.is_empty() && !self.sockets.has_reapable() {
            return;
        }
        self.dropped
            .drain_into(&mut self.dropped_tcp, &mut self.dropped_udp, &mut self.rx_wakes);
        for raw in self.rx_wakes.drain(..) {
            self.sockets.rx_woken(raw);
        }
        for &raw in &self.dropped_tcp {
            self.sockets.orphan(raw, self.now);
        }
        self.dropped_tcp.clear();
        for index in 0..self.dropped_udp.len() {
            self.remove_udp_raw(self.dropped_udp[index]);
        }
        self.dropped_udp.clear();
        self.sockets.take_reapable(|raw| self.dropped_tcp.push(raw));
        for index in 0..self.dropped_tcp.len() {
            self.remove_tcp_raw(self.dropped_tcp[index]);
        }
        self.dropped_tcp.clear();
    }

    /// Drop sockets, interface and every staged and pending packet, then
    /// return the Port for `Port::try_close`.
    pub fn into_port(self) -> Port {
        let Self {
            iface,
            sockets,
            udp,
            device,
            ..
        } = self;
        drop((iface, sockets, udp));
        device.into_port()
    }
}

fn validate(config: &StackConfig<'_>) -> Result<(), &'static str> {
    if !config.ethernet.is_unicast() {
        return Err("Ethernet address must be unicast");
    }
    if !IpAddress::Ipv4(config.ipv4.address()).is_unicast() {
        return Err("IPv4 address must be unicast");
    }
    if let Some(gateway) = config.gateway {
        if !IpAddress::Ipv4(gateway).is_unicast() {
            return Err("gateway must be unicast");
        }
        if !config.ipv4.contains_addr(&gateway) {
            return Err("gateway must be inside the IPv4 subnet");
        }
        if gateway == config.ipv4.address() {
            return Err("gateway must not be our IPv4 address");
        }
        // /31 and /32 have neither (RFC 3021); smoltcp's broadcast() is None.
        if let Some(broadcast) = config.ipv4.broadcast() {
            if gateway == config.ipv4.network().address() {
                return Err("gateway must not be the subnet's network address");
            }
            if gateway == broadcast {
                return Err("gateway must not be the subnet's broadcast address");
            }
        }
    }
    if config.max_sockets == 0 {
        return Err("max_sockets must be positive");
    }
    if config.neighbor_capacity == 0 {
        return Err("neighbor_capacity must be > 0");
    }
    if config.segments_per_visit == 0 {
        return Err("segments_per_visit must be positive");
    }
    if config.rx_staging == 0 {
        return Err("rx_staging must be positive");
    }
    if config.tx_pending == 0 {
        return Err("tx_pending must be positive");
    }
    Ok(())
}
