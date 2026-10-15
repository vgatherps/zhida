// Heads up! Before working on this file you should read, at least, RFC 793 and
// the parts of RFC 1122 that discuss TCP, as well as RFC 7323 for some of the TCP options.
// Consult RFC 7414 when implementing a new feature.

use core::fmt::Display;
use core::fmt;

use crate::phy::{HeldFrames, PacketMeta, RxBuf};
use crate::socket::{Context, PollAt};
use crate::storage::RingBuffer;
use crate::time::{Duration, Instant};
use crate::wire::{
    IpAddress, IpEndpoint, IpListenEndpoint, IpProtocol, IpRepr, TCP_HEADER_LEN, TcpControl,
    TcpRepr, TcpSeqNumber,
};

mod congestion;
mod rx_buffer;
#[cfg_attr(not(test), allow(dead_code))]
mod rx_store;

use congestion::cubic::Cubic;
pub(crate) use rx_buffer::RxBuffer;
pub use rx_buffer::TcpFrame;
use rx_store::Decision;

/// What a TCP socket is built from. Sockets exist only inside a [`crate::iface::TcpSet`], which
/// builds them with [`crate::iface::TcpSet::add_admitted`]. `rx_capacity` and `mss_cap` decide the
/// RX frame budget ([`rx_mbuf_budget`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Receive byte capacity, at most 1 GiB: the largest window advertised. Received payload
    /// stays in RX frames; no byte ring is allocated.
    pub rx_capacity: usize,
    /// Bytes of the transmit ring, which keeps unacknowledged data.
    pub tx_capacity: usize,
    /// Cap on the advertised MSS and outgoing segment payloads, never `Some(0)`. It also sets
    /// the per-frame bytes of the RX frame budget.
    pub mss_cap: Option<u16>,
}

/// RX mbufs a socket built from `config` is admitted with:
/// max(ceil(rx_capacity / min(ip_mtu - 40, mss_cap)), 6).
/// An IPv4 TCP segment without options has 40 bytes of headers. Six
/// mbufs cover small receive buffers and short segments.
///
/// Panics if `ip_mtu` is below IPv4's minimum of 68 bytes or `mss_cap` is `Some(0)`.
pub fn rx_mbuf_budget(config: &Config, ip_mtu: usize) -> usize {
    assert!(config.mss_cap != Some(0), "MSS cap must not be zero");
    rx_mbuf_budget_for_payload(config.rx_capacity, rx_frame_bytes(ip_mtu, config.mss_cap))
}

fn rx_frame_bytes(ip_mtu: usize, mss_cap: Option<u16>) -> usize {
    assert!(ip_mtu >= 68, "IP MTU must be at least 68 bytes");
    ip_mtu.checked_sub(40).expect("IP MTU is at least 68")
        .min(mss_cap.map_or(usize::MAX, usize::from))
}

fn rx_mbuf_budget_for_payload(recv_capacity: usize, payload: usize) -> usize {
    let whole = recv_capacity / payload;
    let rounded = whole
        .checked_add(usize::from(recv_capacity % payload != 0))
        .expect("RX mbuf budget exceeds usize");
    rounded.max(6)
}

macro_rules! tcp_trace {
    ($($arg:expr),*) => (net_log!(trace, $($arg),*));
}

/// Error returned by [`Socket::listen`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ListenError {
    InvalidState,
    Unaddressable,
}

impl Display for ListenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ListenError::InvalidState => write!(f, "invalid state"),
            ListenError::Unaddressable => write!(f, "unaddressable destination"),
        }
    }
}

impl core::error::Error for ListenError {}

/// Error returned by [`Socket::connect`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ConnectError {
    InvalidState,
    Unaddressable,
    AddressInUse,
}

impl Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ConnectError::InvalidState => write!(f, "invalid state"),
            ConnectError::Unaddressable => write!(f, "unaddressable destination"),
            ConnectError::AddressInUse => write!(f, "address in use"),
        }
    }
}

impl core::error::Error for ConnectError {}

/// Error returned by [`Socket::send`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SendError {
    InvalidState,
}

impl Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SendError::InvalidState => write!(f, "invalid state"),
        }
    }
}

impl core::error::Error for SendError {}

/// Error returned by [`Socket::recv`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RecvError {
    InvalidState,
    Finished,
}

impl Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RecvError::InvalidState => write!(f, "invalid state"),
            RecvError::Finished => write!(f, "operation finished"),
        }
    }
}

impl core::error::Error for RecvError {}

/// A TCP socket ring buffer.
pub type SocketBuffer<'a> = RingBuffer<'a, u8>;

/// The state of a TCP socket, according to [RFC 793].
///
/// [RFC 793]: https://tools.ietf.org/html/rfc793
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            State::Closed => write!(f, "CLOSED"),
            State::Listen => write!(f, "LISTEN"),
            State::SynSent => write!(f, "SYN-SENT"),
            State::SynReceived => write!(f, "SYN-RECEIVED"),
            State::Established => write!(f, "ESTABLISHED"),
            State::FinWait1 => write!(f, "FIN-WAIT-1"),
            State::FinWait2 => write!(f, "FIN-WAIT-2"),
            State::CloseWait => write!(f, "CLOSE-WAIT"),
            State::Closing => write!(f, "CLOSING"),
            State::LastAck => write!(f, "LAST-ACK"),
            State::TimeWait => write!(f, "TIME-WAIT"),
        }
    }
}

const DEFAULT_RTO: Duration = Duration::from_millis(300);
const MAX_RTO: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy)]
struct SmoothedRtt {
    sent_at: Instant,
    // Using u32 instead of Duration to save space (Duration is i64)
    /// Smoothed RTT
    srtt: u32,
    sent_seq: TcpSeqNumber,
    max_seq_sent: TcpSeqNumber,
    /// true if we have made at least one rtt measurement.
    have_measurement: bool,
    sampling: bool,
    max_seq_sent_valid: bool,
    rto_count: u8,
}

impl Default for SmoothedRtt {
    fn default() -> Self {
        Self {
            sent_at: Instant::ZERO,
            srtt: 0, // ignored, will be overwritten on first measurement.
            sent_seq: TcpSeqNumber(0),
            max_seq_sent: TcpSeqNumber(0),
            have_measurement: false,
            sampling: false,
            max_seq_sent_valid: false,
            rto_count: 0,
        }
    }
}

impl SmoothedRtt {
    #[cfg(test)]
    fn timestamp(&self) -> Option<(Instant, TcpSeqNumber)> {
        if self.sampling {
            Some((self.sent_at, self.sent_seq))
        } else {
            None
        }
    }

    #[cfg(test)]
    fn max_seq_sent(&self) -> Option<TcpSeqNumber> {
        if self.max_seq_sent_valid {
            Some(self.max_seq_sent)
        } else {
            None
        }
    }

    fn smoothed_rtt(&self) -> u32 {
        if self.have_measurement { self.srtt } else { 0 }
    }

    fn sample(&mut self, new_rtt: u32) {
        if self.have_measurement {
            // RFC 6298 (2.3) When a subsequent RTT measurement R' is made, a host MUST set (...)
            self.srtt = (self.srtt * 7 + new_rtt).div_ceil(8);
        } else {
            // RFC 6298 (2.2) When the first RTT measurement R is made, the host MUST set (...)
            self.have_measurement = true;
            self.srtt = new_rtt;
        }

        self.rto_count = 0;
        tcp_trace!("rtte: sample={:?} srtt={:?}", new_rtt, self.srtt);
    }

    fn on_send(&mut self, timestamp: Instant, seq: TcpSeqNumber) {
        if !self.max_seq_sent_valid || seq > self.max_seq_sent {
            self.max_seq_sent = seq;
            self.max_seq_sent_valid = true;
            if !self.sampling {
                self.sent_at = timestamp;
                self.sent_seq = seq;
                self.sampling = true;
                tcp_trace!("rtte: sampling at seq={:?}", seq);
            }
        }
    }

    fn on_ack(&mut self, timestamp: Instant, seq: TcpSeqNumber) {
        if self.sampling && seq >= self.sent_seq {
            self.sample((timestamp - self.sent_at).total_millis() as u32);
            self.sampling = false;
        }
    }

    fn on_rto(&mut self) {
        self.rto_count = self.rto_count.checked_add(1).expect("RTT expiry count overflow");
        if self.rto_count == 3 {
            self.rto_count = 0;
            self.have_measurement = false;
            tcp_trace!("rtte: three expiries without a sample, clearing srtt");
        }
    }

    fn on_retransmit(&mut self) {
        if self.sampling {
            tcp_trace!("rtte: abort sampling due to retransmit");
        }
        self.sampling = false;
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Timer {
    Idle,
    Retransmit {
        expires_at: Instant,
    },
    FastRetransmit,
    ZeroWindowProbe {
        expires_at: Instant,
        // The expiry for this pending probe already advanced backoff.
        backoff_applied: bool,
    },
    Close {
        expires_at: Instant,
    },
}

const ACK_DELAY_DEFAULT: Duration = Duration::from_millis(10);
const CLOSE_DELAY: Duration = Duration::from_millis(10_000);
const ORPHAN_FIN_WAIT_2_TIMEOUT: Duration = Duration::from_secs(60);
const ORPHAN_RETRIES: u32 = 8;

impl Timer {
    fn new() -> Timer {
        Timer::Idle
    }

    fn should_retransmit(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::Retransmit { expires_at } if timestamp >= expires_at => true,
            Timer::FastRetransmit => true,
            _ => false,
        }
    }

    fn should_close(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::Close { expires_at } if timestamp >= expires_at => true,
            _ => false,
        }
    }

    fn should_zero_window_probe(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::ZeroWindowProbe { expires_at, .. } if timestamp >= expires_at => true,
            _ => false,
        }
    }

    fn poll_at(&self) -> PollAt {
        match *self {
            Timer::Idle => PollAt::Ingress,
            Timer::ZeroWindowProbe { expires_at, .. } => PollAt::Time(expires_at),
            Timer::Retransmit { expires_at, .. } => PollAt::Time(expires_at),
            Timer::FastRetransmit => PollAt::Now,
            Timer::Close { expires_at } => PollAt::Time(expires_at),
        }
    }

    fn set_for_idle(&mut self) {
        *self = Timer::Idle
    }

    fn set_for_retransmit(&mut self, timestamp: Instant, delay: Duration) {
        match *self {
            Timer::Idle
            | Timer::FastRetransmit
            | Timer::Retransmit { .. }
            | Timer::ZeroWindowProbe { .. } => {
                *self = Timer::Retransmit {
                    expires_at: timestamp + delay,
                }
            }
            Timer::Close { .. } => (),
        }
    }

    fn set_for_fast_retransmit(&mut self) {
        *self = Timer::FastRetransmit
    }

    fn set_for_close(&mut self, timestamp: Instant) {
        *self = Timer::Close {
            expires_at: timestamp + CLOSE_DELAY,
        }
    }

    fn set_for_orphan_fin_wait_2(&mut self, timestamp: Instant) {
        *self = Timer::Close {
            expires_at: timestamp + ORPHAN_FIN_WAIT_2_TIMEOUT,
        }
    }

    fn set_for_zero_window_probe(&mut self, timestamp: Instant, delay: Duration) {
        *self = Timer::ZeroWindowProbe {
            expires_at: timestamp + delay,
            backoff_applied: false,
        }
    }

    fn is_idle(&self) -> bool {
        matches!(self, Timer::Idle)
    }

    fn is_zero_window_probe(&self) -> bool {
        matches!(self, Timer::ZeroWindowProbe { .. })
    }

    fn is_retransmit(&self) -> bool {
        matches!(self, Timer::Retransmit { .. } | Timer::FastRetransmit)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum AckDelayTimer {
    Idle,
    Waiting(Instant),
    Immediate,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
enum AckKind {
    Idle,
    Waiting,
    Immediate,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct Tuple {
    local: IpEndpoint,
    remote: IpEndpoint,
}

/// RFC 6528: a keyed tuple hash plus the interface clock in 4 microsecond ticks.
fn initial_seq_no(secret: [u64; 2], tuple: Tuple, now: Instant) -> TcpSeqNumber {
    use core::hash::Hasher;

    #[allow(deprecated)]
    let mut hash = core::hash::SipHasher::new_with_keys(secret[0], secret[1]);
    for endpoint in [tuple.local, tuple.remote] {
        match endpoint.addr {
            IpAddress::Ipv4(addr) => hash.write(&addr.octets()),
        }
        hash.write(&endpoint.port.to_be_bytes());
    }
    let clock = (now.total_micros() / 4) as u32;
    TcpSeqNumber((hash.finish() as u32).wrapping_add(clock) as i32)
}

impl Display for Tuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.local, self.remote)
    }
}

#[derive(Debug)]
pub(crate) struct PendingRxCommit {
    kept: core::ops::Range<usize>,
    payload_start: usize,
    payload_len: usize,
}

/// A Transmission Control Protocol socket.
///
/// A TCP socket may passively listen for connections or actively connect to another endpoint.
/// Note that, for listening sockets, there is no "backlog"; to be able to simultaneously
/// accept several connections, as many sockets must be allocated, or any new connection
/// attempts will be reset.
#[derive(Debug)]
#[repr(C)]
pub struct Socket<'a> {
    /// The IPv4 time-to-live value used in outgoing packets.
    hop_limit: Option<core::num::NonZeroU8>,
    /// The number of packets received directly after
    /// each other which have the same ACK number.
    local_rx_dup_acks: u8,
    ack_delay_enabled: bool,
    rx_fin_received: bool,
    in_rto_loss_episode: bool,
    /// Whether or not the remote supports selective ACK as described in RFC 2018.
    remote_has_sack: bool,
    timer: Timer,
    /// Delayed ack timer. If set, packets containing exclusively
    /// ACK or window updates (ie, no data) won't be sent until expiry.
    ack_at: Instant,
    /// The sequence number corresponding to the beginning of the transmit buffer.
    /// I.e. an ACK(local_seq_no+n) packet removes n bytes from the transmit buffer.
    local_seq_no: TcpSeqNumber,
    /// The sequence number corresponding to the beginning of the receive buffer.
    /// I.e. userspace reading n bytes adds n to remote_seq_no.
    remote_seq_no: TcpSeqNumber,
    /// The next sequence number to send from the transmit buffer: the end of the
    /// last segment sent, rewound to local_seq_no by a retransmission timeout.
    /// I.e. in an idle socket, local_seq_no+tx_buffer.len().
    remote_last_seq: TcpSeqNumber,
    /// The highest sequence number sent: the end of the furthest segment sent,
    /// zero window probe byte included. A retransmission timeout leaves it.
    remote_max_seq: TcpSeqNumber,
    /// The last acknowledgement number sent.
    /// I.e. in an idle socket, remote_seq_no+rx_buffer.len().
    remote_last_ack: Option<TcpSeqNumber>,
    /// The last advertised receive window in bytes, including unscaled SYN windows.
    remote_last_win_bytes: u32,
    /// The remote window size, relative to local_seq_no
    /// I.e. we're allowed to send octets until local_seq_no+remote_win_len
    remote_win_len: u32,
    state: State,
    ack_kind: AckKind,
    /// The sending window scaling factor advertised to remotes which support RFC 1323.
    /// It is zero if the window <= 64KiB and/or the remote does not support it.
    remote_win_shift: u8,
    /// If a fast retransmit needs to occur
    pending_fast_retransmit: bool,
    /// Whether remote_last_ack is a peer SYN marker rather than a sent ACK.
    remote_last_ack_is_marker: bool,
    local_rx_last_seq_valid: bool,
    local_rx_last_ack_valid: bool,
    recover_valid: bool,
    /// Current 4-tuple (local and remote endpoints).
    tuple: Option<Tuple>,
    /// The receive window scaling factor for remotes which support RFC 1323, None if unsupported.
    remote_win_scale: Option<u8>,
    /// The maximum number of data octets that the remote side may receive.
    remote_mss: u16,
    connection_mss_cap: Option<core::num::NonZeroU16>,
    /// Largest accepted send window, after scaling.
    max_snd_wnd: u32,
    /// Sequence number of the segment that last updated the send window (SND.WL1).
    remote_win_seq: TcpSeqNumber,
    rx_fin_seq: Option<TcpSeqNumber>,
    /// The sequence number of the last packet received, used for sACK
    local_rx_last_seq: TcpSeqNumber,
    /// The ACK number of the last packet received.
    local_rx_last_ack: TcpSeqNumber,
    recover: TcpSeqNumber,
    rto_us: u32,
    rto_backoff: u32,
    /// Admission fixes the frame count; otherwise the receive context supplies it.
    /// Segment bytes follow our advertised MSS and the peer MSS.
    rx_mbuf_cap: u32,
    rx_seg_bytes: u32,
    tx_buffer: SocketBuffer<'a>,
    rtte: SmoothedRtt,
    /// The congestion control algorithm.
    congestion_controller: Cubic,
    rx_buffer: RxBuffer,
    /// Duration for Delayed ACK in microseconds.
    ack_delay_us: u64,
    retransmits: u64,
    loss_events: u64,
    initial_window: usize,
    /// Address passed to listen(). Listen address is set when listen() is called and
    /// used every time the socket is reset back to the LISTEN state.
    listen_endpoint: IpListenEndpoint,
    /// Acknowledged sequence space, excluding a passive-open SYN.
    bytes_acked: u64,
    /// Receive MSS estimate (Linux icsk_ack.rcv_mss): grows from full in-order payloads,
    /// capped at our advertised MSS. Initialized from the send MSS and receive window,
    /// clamped to 88..=536. More unacknowledged bytes while the delayed-ACK timer runs
    /// sends the ACK at once.
    rcv_mss: usize,
    /// Next permitted challenge ACK or duplicate-SYN SYN-ACK resend (500 ms per socket).
    challenge_ack_timer: Instant,
    pub(crate) rx_refused_segments: u32,
    mss_cap: Option<core::num::NonZeroU16>,
    orphaned: bool,
    /// An acceptable peer RST closed this connection; cleared by reset().
    reset_by_peer: bool,
}

#[cfg(test)]
pub(crate) fn socket_field_offsets() -> &'static [(&'static str, usize)] {
    use core::mem::offset_of;

    &[
        ("hop_limit", offset_of!(Socket<'static>, hop_limit)),
        ("local_rx_dup_acks", offset_of!(Socket<'static>, local_rx_dup_acks)),
        ("ack_delay_enabled", offset_of!(Socket<'static>, ack_delay_enabled)),
        ("rx_fin_received", offset_of!(Socket<'static>, rx_fin_received)),
        ("in_rto_loss_episode", offset_of!(Socket<'static>, in_rto_loss_episode)),
        ("remote_has_sack", offset_of!(Socket<'static>, remote_has_sack)),
        ("timer", offset_of!(Socket<'static>, timer)),
        ("ack_at", offset_of!(Socket<'static>, ack_at)),
        ("local_seq_no", offset_of!(Socket<'static>, local_seq_no)),
        ("remote_seq_no", offset_of!(Socket<'static>, remote_seq_no)),
        ("remote_last_seq", offset_of!(Socket<'static>, remote_last_seq)),
        ("remote_max_seq", offset_of!(Socket<'static>, remote_max_seq)),
        ("remote_last_ack", offset_of!(Socket<'static>, remote_last_ack)),
        ("remote_last_win_bytes", offset_of!(Socket<'static>, remote_last_win_bytes)),
        ("remote_win_len", offset_of!(Socket<'static>, remote_win_len)),
        ("state", offset_of!(Socket<'static>, state)),
        ("ack_kind", offset_of!(Socket<'static>, ack_kind)),
        ("remote_win_shift", offset_of!(Socket<'static>, remote_win_shift)),
        ("pending_fast_retransmit", offset_of!(Socket<'static>, pending_fast_retransmit)),
        ("remote_last_ack_is_marker", offset_of!(Socket<'static>, remote_last_ack_is_marker)),
        ("local_rx_last_seq_valid", offset_of!(Socket<'static>, local_rx_last_seq_valid)),
        ("local_rx_last_ack_valid", offset_of!(Socket<'static>, local_rx_last_ack_valid)),
        ("recover_valid", offset_of!(Socket<'static>, recover_valid)),
        ("tuple", offset_of!(Socket<'static>, tuple)),
        ("remote_win_scale", offset_of!(Socket<'static>, remote_win_scale)),
        ("remote_mss", offset_of!(Socket<'static>, remote_mss)),
        ("connection_mss_cap", offset_of!(Socket<'static>, connection_mss_cap)),
        ("max_snd_wnd", offset_of!(Socket<'static>, max_snd_wnd)),
        ("remote_win_seq", offset_of!(Socket<'static>, remote_win_seq)),
        ("rx_fin_seq", offset_of!(Socket<'static>, rx_fin_seq)),
        ("local_rx_last_seq", offset_of!(Socket<'static>, local_rx_last_seq)),
        ("local_rx_last_ack", offset_of!(Socket<'static>, local_rx_last_ack)),
        ("recover", offset_of!(Socket<'static>, recover)),
        ("rto_us", offset_of!(Socket<'static>, rto_us)),
        ("rto_backoff", offset_of!(Socket<'static>, rto_backoff)),
        ("rx_mbuf_cap", offset_of!(Socket<'static>, rx_mbuf_cap)),
        ("rx_seg_bytes", offset_of!(Socket<'static>, rx_seg_bytes)),
        ("tx_buffer", offset_of!(Socket<'static>, tx_buffer)),
        ("rtte", offset_of!(Socket<'static>, rtte)),
        ("congestion_controller", offset_of!(Socket<'static>, congestion_controller)),
        ("rx_buffer", offset_of!(Socket<'static>, rx_buffer)),
        ("ack_delay_us", offset_of!(Socket<'static>, ack_delay_us)),
        ("retransmits", offset_of!(Socket<'static>, retransmits)),
        ("loss_events", offset_of!(Socket<'static>, loss_events)),
        ("initial_window", offset_of!(Socket<'static>, initial_window)),
        ("listen_endpoint", offset_of!(Socket<'static>, listen_endpoint)),
        ("bytes_acked", offset_of!(Socket<'static>, bytes_acked)),
        ("rcv_mss", offset_of!(Socket<'static>, rcv_mss)),
        ("challenge_ack_timer", offset_of!(Socket<'static>, challenge_ack_timer)),
        ("rx_refused_segments", offset_of!(Socket<'static>, rx_refused_segments)),
        ("mss_cap", offset_of!(Socket<'static>, mss_cap)),
        ("reset_by_peer", offset_of!(Socket<'static>, reset_by_peer)),
    ]
}

const DEFAULT_MSS: usize = 536;

/// Minimum MSS we accept from the remote, same value as Linux's `TCP_MIN_SND_MSS`.
const MIN_REMOTE_MSS: usize = 48;

/// The window shift we advertise for a receive buffer of `rx_capacity` bytes: the smallest
/// that lets the 16-bit window field cover the buffer, at most 14 (RFC 7323 2.3).
fn rx_win_shift(rx_capacity: usize) -> u8 {
    let bits = usize::BITS - rx_capacity.leading_zeros();
    (bits.clamp(16, 30) - 16) as u8
}

impl<'a> Socket<'a> {
    #[allow(unused_comparisons)] // small usize platforms always pass rx_capacity check
    /// Create a socket using the given buffers. Outside this crate sockets come only from
    /// [`crate::iface::TcpSet::add_admitted`].
    pub(crate) fn new<T>(rx_buffer: RxBuffer, tx_buffer: T) -> Socket<'a>
    where
        T: Into<SocketBuffer<'a>>,
    {
        let tx_buffer = tx_buffer.into();
        let rx_capacity = rx_buffer.capacity;

        // From RFC 1323:
        // [...] the above constraints imply that 2 * the max window size must be less
        // than 2**31 [...] Thus, the shift count must be limited to 14 (which allows
        // windows of 2**30 = 1 Gbyte).
        #[cfg(not(target_pointer_width = "16"))] // Prevent overflow
        if rx_capacity > (1 << 30) {
            panic!("receiving buffer too large, cannot exceed 1 GiB")
        }

        Socket {
            state: State::Closed,
            timer: Timer::new(),
            rtte: SmoothedRtt::default(),
            rto_us: DEFAULT_RTO.total_micros() as u32,
            rto_backoff: 0,
            tx_buffer,
            rx_buffer,
            rx_mbuf_cap: 0,
            rx_seg_bytes: 0,
            rx_refused_segments: 0,
            rx_fin_received: false,
            rx_fin_seq: None,
            hop_limit: None,
            mss_cap: None,
            orphaned: false,
            reset_by_peer: false,
            connection_mss_cap: None,
            initial_window: 1_048_576,
            listen_endpoint: IpListenEndpoint::default(),
            tuple: None,
            local_seq_no: TcpSeqNumber::default(),
            remote_seq_no: TcpSeqNumber::default(),
            remote_last_seq: TcpSeqNumber::default(),
            remote_max_seq: TcpSeqNumber::default(),
            remote_last_ack: None,
            remote_last_ack_is_marker: false,
            remote_last_win_bytes: 0,
            remote_win_len: 0,
            max_snd_wnd: 0,
            bytes_acked: 0,
            remote_win_seq: TcpSeqNumber::default(),
            remote_win_shift: rx_win_shift(rx_capacity),
            remote_win_scale: None,
            remote_has_sack: false,
            remote_mss: u16::try_from(DEFAULT_MSS).expect("default MSS exceeds u16"),
            rcv_mss: DEFAULT_MSS,
            local_rx_last_ack: TcpSeqNumber(0),
            local_rx_last_ack_valid: false,
            local_rx_last_seq: TcpSeqNumber(0),
            local_rx_last_seq_valid: false,
            local_rx_dup_acks: 0,
            pending_fast_retransmit: false,
            recover: TcpSeqNumber(0),
            recover_valid: false,
            retransmits: 0,
            loss_events: 0,
            in_rto_loss_episode: false,
            ack_delay_us: ACK_DELAY_DEFAULT.total_micros(),
            ack_delay_enabled: true,
            ack_at: Instant::ZERO,
            ack_kind: AckKind::Idle,
            challenge_ack_timer: Instant::from_secs(0),
            congestion_controller: Cubic::new(),
        }
    }

    /// Build a socket from `config`. Panics if `rx_capacity` exceeds 1 GiB or `mss_cap` is
    /// `Some(0)`.
    pub(crate) fn from_config(config: &Config) -> Socket<'a> {
        let mut socket = Socket::new(
            RxBuffer::new(config.rx_capacity),
            SocketBuffer::new(alloc::vec![0; config.tx_capacity]),
        );
        socket.set_mss_cap(config.mss_cap);
        socket
    }

    fn local_rx_last_seq(&self) -> Option<TcpSeqNumber> {
        if self.local_rx_last_seq_valid {
            Some(self.local_rx_last_seq)
        } else {
            None
        }
    }

    fn set_local_rx_last_seq(&mut self, v: Option<TcpSeqNumber>) {
        (self.local_rx_last_seq, self.local_rx_last_seq_valid) = match v {
            Some(seq) => (seq, true),
            None => (TcpSeqNumber(0), false),
        };
    }

    fn local_rx_last_ack(&self) -> Option<TcpSeqNumber> {
        if self.local_rx_last_ack_valid {
            Some(self.local_rx_last_ack)
        } else {
            None
        }
    }

    fn set_local_rx_last_ack(&mut self, v: Option<TcpSeqNumber>) {
        (self.local_rx_last_ack, self.local_rx_last_ack_valid) = match v {
            Some(seq) => (seq, true),
            None => (TcpSeqNumber(0), false),
        };
    }

    fn recover(&self) -> Option<TcpSeqNumber> {
        if self.recover_valid {
            Some(self.recover)
        } else {
            None
        }
    }

    fn set_recover(&mut self, v: Option<TcpSeqNumber>) {
        (self.recover, self.recover_valid) = match v {
            Some(seq) => (seq, true),
            None => (TcpSeqNumber(0), false),
        };
    }

    fn ack_delay_timer(&self) -> AckDelayTimer {
        match self.ack_kind {
            AckKind::Idle => AckDelayTimer::Idle,
            AckKind::Waiting => AckDelayTimer::Waiting(self.ack_at),
            AckKind::Immediate => AckDelayTimer::Immediate,
        }
    }

    fn set_ack_delay_timer(&mut self, timer: AckDelayTimer) {
        (self.ack_at, self.ack_kind) = match timer {
            AckDelayTimer::Idle => (Instant::ZERO, AckKind::Idle),
            AckDelayTimer::Waiting(at) => (at, AckKind::Waiting),
            AckDelayTimer::Immediate => (Instant::ZERO, AckKind::Immediate),
        };
    }

    /// Return the ACK delay duration.
    ///
    /// See also the [set_ack_delay](#method.set_ack_delay) method.
    pub fn ack_delay(&self) -> Option<Duration> {
        self.ack_delay_enabled.then(|| Duration::from_micros(self.ack_delay_us))
    }

    fn recv_window(&self) -> usize {
        self.recv_window_within(self.rx_buffer.capacity)
    }

    fn recv_window_within(&self, byte_window: usize) -> usize {
        assert!(self.rx_mbuf_cap != 0 && self.rx_seg_bytes != 0,
            "RX frame cap and segment bytes must be known");
        let out_of_order_span = self.rx_buffer.store.out_of_order_span();
        let free_frames = (self.rx_mbuf_cap as usize)
            .checked_sub(self.rx_buffer.store.held())
            .expect("stored frames exceed RX mbuf cap")
            .checked_sub(self.rx_buffer.shared.held.get())
            .expect("app-held frames exceed RX mbuf cap");
        let hole_frames = self.rx_buffer.store.out_of_order_hole_frames(self.rx_seg_bytes as usize);
        let frame_window = free_frames
            .saturating_sub(hole_frames)
            .checked_mul(self.rx_seg_bytes as usize)
            .expect("RX frame window exceeds usize")
            .checked_add(out_of_order_span)
            .expect("RX window exceeds usize");
        byte_window.min(frame_window)
    }

    /// Return the current window field value, including scaling according to RFC 1323.
    ///
    /// Used in internal calculations as well as packet generation.
    #[inline]
    fn scaled_window(&self) -> u16 {
        self.scaled_window_with_last(self.last_scaled_window())
    }

    #[inline]
    fn scaled_window_with_last(&self, last_window: Option<u16>) -> u16 {
        let byte_window = self.rx_buffer.capacity;
        let window = self.recv_window_within(byte_window) >> self.remote_win_shift;
        let byte_window = byte_window >> self.remote_win_shift;
        let window =
            last_window.map_or(window, |last| window.max((last as usize).min(byte_window)));
        u16::try_from(window).unwrap_or(u16::MAX)
    }

    /// Return the last window field value, including scaling according to RFC 1323.
    ///
    /// Used in internal calculations as well as packet generation.
    ///
    /// Unlike `remote_last_win_bytes`, we take into account new packets received (but not acknowledged)
    /// since the last window update and adjust the window length accordingly. This ensures a fair
    /// comparison between the last window length and the new window length we're going to
    /// advertise.
    #[inline]
    fn last_scaled_window(&self) -> Option<u16> {
        if self.remote_last_ack_is_marker {
            return None;
        }
        let last_ack = self.remote_last_ack?;
        let next_ack = self.remote_seq_no + self.rx_buffer.store.in_order_len();

        let last_win = self.remote_last_win_bytes as usize;
        let last_win_adjusted = if last_ack + last_win < next_ack {
            0
        } else {
            last_ack + last_win - next_ack
        };

        let shift = self.remote_win_shift;
        let rounded = (last_win_adjusted >> shift)
            + usize::from(last_win_adjusted & ((1usize << shift) - 1) != 0);
        Some(u16::try_from(rounded).unwrap_or(u16::MAX))
    }

    /// Set the ACK delay duration.
    ///
    /// By default, the ACK delay is set to 10ms.
    ///
    /// # Panics
    /// If the delay exceeds 60 s (the retransmission timeout cap): the TCP timer
    /// wheel only holds deadlines that close to the current time.
    pub fn set_ack_delay(&mut self, duration: Option<Duration>) {
        if let Some(duration) = duration {
            assert!(
                duration <= MAX_RTO,
                "ACK delay {duration} must not exceed {MAX_RTO}"
            );
        }
        self.ack_delay_us = duration.map_or(0, |duration| duration.total_micros());
        self.ack_delay_enabled = duration.is_some();
    }

    /// Send an owed ACK at the next egress instead of after the ACK delay.
    ///
    /// If in-order data has been received but not yet acknowledged, the next egress sends
    /// the ACK (alone, or on outgoing data). Otherwise this does nothing.
    pub fn ack_now(&mut self) {
        if self.ack_to_transmit() {
            self.set_ack_delay_timer(AckDelayTimer::Immediate);
        }
    }

    /// Set the IPv4 time-to-live value used in outgoing packets.
    ///
    /// A socket without an explicitly set hop limit value uses the default [IANA recommended]
    /// value (64).
    ///
    /// # Panics
    ///
    /// This function panics if a hop limit value of 0 is given. See [RFC 1122 § 3.2.1.7].
    ///
    /// [IANA recommended]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
    /// [RFC 1122 § 3.2.1.7]: https://tools.ietf.org/html/rfc1122#section-3.2.1.7
    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) {
        // A host MUST NOT send a datagram with a hop limit value of 0
        if let Some(0) = hop_limit {
            panic!("the time-to-live value of a packet must not be zero")
        }

        self.hop_limit = hop_limit.and_then(core::num::NonZeroU8::new)
    }

    /// Cap the advertised MSS and outgoing segment payloads for the next connection.
    /// The cap survives reset and reconnect. `None` removes it; the local MTU and peer
    /// MSS still limit payloads. Admitted sockets take it from [`Config::mss_cap`].
    ///
    /// # Panics
    ///
    /// This function panics if `cap` is `Some(0)`.
    pub(crate) fn set_mss_cap(&mut self, cap: Option<u16>) {
        assert!(cap != Some(0), "MSS cap must not be zero");
        self.mss_cap = cap.and_then(core::num::NonZeroU16::new);
    }

    /// RX mbufs needed to admit this socket using its MSS cap; see [`rx_mbuf_budget`].
    /// Panics if `ip_mtu` is below 68.
    pub(crate) fn rx_mbuf_budget(&self, ip_mtu: usize) -> usize {
        rx_mbuf_budget_for_payload(
            self.recv_capacity(),
            rx_frame_bytes(ip_mtu, self.mss_cap.map(core::num::NonZeroU16::get)),
        )
    }

    /// Return the socket's admitted RX frame count.
    pub fn rx_frame_cap(&self) -> usize {
        self.rx_mbuf_cap as usize
    }

    /// Fix the socket's RX frame count and per-frame bytes using its configured cap.
    /// The count survives reset and reconnect; per-frame bytes follow each connection.
    /// Panics if the app still holds received frames, `ip_mtu` is below 68,
    /// or the frame count exceeds u32.
    /// Use [`crate::iface::TcpSet::add_admitted`] after the pool has admitted
    /// [`rx_mbuf_budget`].
    pub(crate) fn set_rx_mbuf_budget(&mut self, ip_mtu: usize) {
        assert_eq!(self.rx_buffer.shared.held.get(), 0,
            "socket admitted while the app still holds its received frames");
        self.rx_mbuf_cap = u32::try_from(self.rx_mbuf_budget(ip_mtu))
            .expect("RX mbuf cap exceeds u32");
        self.rx_seg_bytes = u32::try_from(rx_frame_bytes(
            ip_mtu, self.mss_cap.map(core::num::NonZeroU16::get),
        ))
            .expect("RX segment bytes exceed u32");
    }

    /// Set Cubic's initial congestion window in bytes. The default is 1 MiB.
    ///
    /// Set this before connect or listen. It applies when the handshake learns the
    /// send MSS and survives reset and reconnect. The peer's advertised window
    /// still limits how much data can be sent.
    ///
    /// # Panics
    ///
    /// This function panics if `bytes` is zero.
    pub fn set_initial_window(&mut self, bytes: usize) {
        assert!(bytes > 0);
        self.initial_window = bytes;
    }

    /// Set the base retransmission timeout. The default is 300 milliseconds.
    ///
    /// The new value applies when the next retransmission or probe timer is armed
    /// and survives reset and reconnect. Timeout backoff is capped at 60 seconds.
    ///
    /// # Panics
    ///
    /// This function panics if `rto` is zero or exceeds 60 seconds.
    pub fn set_rto(&mut self, rto: Duration) {
        assert!(rto > Duration::ZERO && rto <= MAX_RTO);
        self.rto_us = rto.total_micros() as u32;
    }

    fn retransmission_timeout(&self) -> Duration {
        // Even a one-microsecond RTO reaches the cap after 26 doublings.
        let micros = u64::from(self.rto_us)
            .checked_mul(1u64 << self.rto_backoff.min(26))
            .expect("RTO duration overflow");
        Duration::from_micros(micros.min(MAX_RTO.total_micros()))
    }

    /// Return the listen endpoint
    #[inline]
    pub fn listen_endpoint(&self) -> IpListenEndpoint {
        self.listen_endpoint
    }

    /// Return the local endpoint, or None if not connected.
    #[inline]
    pub fn local_endpoint(&self) -> Option<IpEndpoint> {
        Some(self.tuple?.local)
    }

    /// Return the remote endpoint, or None if not connected.
    #[inline]
    pub fn remote_endpoint(&self) -> Option<IpEndpoint> {
        Some(self.tuple?.remote)
    }

    /// Successful emissions occupying sequence space and starting below the
    /// highest sequence number sent.
    /// Counts data, SYN, FIN and repeated probe bytes once before TSO splitting.
    /// Failed emissions and pure ACKs count nothing.
    /// Kept until `reset()` runs: listen/connect, TIME-WAIT expiry, or a peer reset
    /// that re-arms Listen. Abort and other closes keep the count until then.
    pub fn retransmits(&self) -> u64 {
        self.retransmits
    }

    /// Fast-retransmit entries plus the first RTO expiry since SND.UNA advanced.
    /// Further RTO expiries share the episode until an ACK advances SND.UNA.
    /// Kept until `reset()` runs: listen/connect, TIME-WAIT expiry, or a peer reset
    /// that re-arms Listen. Abort and other closes keep the count until then.
    pub fn loss_events(&self) -> u64 {
        self.loss_events
    }

    /// Cubic's current congestion window, in bytes.
    pub fn congestion_window(&self) -> usize {
        self.congestion_controller.window()
    }

    /// Cubic's slow-start threshold, in bytes; usize::MAX before loss.
    pub fn ssthresh(&self) -> usize {
        self.congestion_controller.ssthresh()
    }

    /// Return the connection state, in terms of the TCP state machine.
    #[inline]
    pub fn state(&self) -> State {
        self.state
    }

    /// Whether an acceptable RST from the peer closed the connection (false after connect/listen).
    #[inline]
    pub fn reset_by_peer(&self) -> bool {
        self.reset_by_peer
    }

    pub(crate) fn reset(&mut self) {
        self.rx_buffer.store.clear();
        self.rx_fin_received = false;
        self.reset_protocol();
    }

    pub(crate) fn finish_time_wait(&mut self) {
        if self.orphaned {
            self.reset();
        } else {
            self.reset_protocol();
        }
    }

    fn reset_protocol(&mut self) {
        self.state = State::Closed;
        self.orphaned = false;
        self.reset_by_peer = false;
        self.connection_mss_cap = self.mss_cap;
        self.timer = Timer::new();
        self.rtte = SmoothedRtt::default();
        self.rto_backoff = 0;
        self.tx_buffer.clear();
        self.rx_refused_segments = 0;
        self.rx_fin_seq = None;
        self.listen_endpoint = IpListenEndpoint::default();
        self.tuple = None;
        self.local_seq_no = TcpSeqNumber::default();
        self.remote_seq_no = TcpSeqNumber::default();
        self.remote_last_seq = TcpSeqNumber::default();
        self.remote_max_seq = TcpSeqNumber::default();
        self.remote_last_ack = None;
        self.remote_last_ack_is_marker = false;
        self.remote_last_win_bytes = 0;
        self.remote_win_len = 0;
        self.max_snd_wnd = 0;
        self.bytes_acked = 0;
        self.remote_win_seq = TcpSeqNumber::default();
        self.remote_win_scale = None;
        self.remote_win_shift = rx_win_shift(self.rx_buffer.capacity);
        self.remote_mss = u16::try_from(DEFAULT_MSS).expect("default MSS exceeds u16");
        self.rcv_mss = DEFAULT_MSS;
        self.remote_has_sack = false;
        self.set_local_rx_last_seq(None);
        self.set_local_rx_last_ack(None);
        self.local_rx_dup_acks = 0;
        self.pending_fast_retransmit = false;
        self.set_recover(None);
        self.retransmits = 0;
        self.loss_events = 0;
        self.in_rto_loss_episode = false;
        self.set_ack_delay_timer(AckDelayTimer::Idle);
        self.challenge_ack_timer = Instant::from_secs(0);
        self.congestion_controller = Cubic::new();
    }

    /// Start listening on the given endpoint.
    ///
    /// This function returns `Err(Error::InvalidState)` if the socket was already open
    /// (see [is_open](#method.is_open)), and `Err(Error::Unaddressable)`
    /// if the port in the given endpoint is zero.
    pub fn listen<T>(&mut self, local_endpoint: T) -> Result<(), ListenError>
    where
        T: Into<IpListenEndpoint>,
    {
        let local_endpoint = local_endpoint.into();
        if local_endpoint.port == 0 {
            return Err(ListenError::Unaddressable);
        }

        if self.is_open() {
            // If we were already listening to same endpoint there is nothing to do; exit early.
            //
            // In the past listening on an socket that was already listening was an error,
            // however this makes writing an acceptor loop with multiple sockets impossible.
            // Without this early exit, if you tried to listen on a socket that's already listening you'll
            // immediately get an error. The only way around this is to abort the socket first
            // before listening again, but this means that incoming connections can actually
            // get aborted between the abort() and the next listen().
            if matches!(self.state, State::Listen) && self.listen_endpoint == local_endpoint {
                return Ok(());
            } else {
                return Err(ListenError::InvalidState);
            }
        }

        self.reset();
        self.listen_endpoint = local_endpoint;
        self.tuple = None;
        self.set_state(State::Listen);
        Ok(())
    }

    /// Connect to a given endpoint.
    ///
    /// The local port must be provided explicitly. Assuming `fn get_ephemeral_port() -> u16`
    /// allocates a port between 49152 and 65535, a connection may be established as follows:
    ///
    /// ```no_run
    /// # {
    /// # use smoltcp::socket::tcp::{RxBuffer, Socket, SocketBuffer};
    /// # use smoltcp::iface::Interface;
    /// # use smoltcp::wire::IpAddress;
    /// #
    /// # fn get_ephemeral_port() -> u16 {
    /// #     49152
    /// # }
    /// #
    /// # let mut socket = Socket::new(
    /// #     RxBuffer::new(1200),
    /// #     SocketBuffer::new(vec![0; 1200])
    /// # );
    /// #
    /// # let mut iface: Interface = todo!();
    /// #
    /// socket.connect(
    ///     iface.context(),
    ///     (IpAddress::v4(10, 0, 0, 1), 80),
    ///     get_ephemeral_port()
    /// ).unwrap();
    /// # }
    /// ```
    ///
    /// The local address may optionally be provided.
    ///
    /// This function returns an error if the socket was open; see [is_open](#method.is_open).
    /// It also returns an error if the local or remote port is zero, or if the remote address
    /// is unspecified.
    pub fn connect<T, U>(
        &mut self,
        cx: &mut Context,
        remote_endpoint: T,
        local_endpoint: U,
    ) -> Result<(), ConnectError>
    where
        T: Into<IpEndpoint>,
        U: Into<IpListenEndpoint>,
    {
        let remote_endpoint: IpEndpoint = remote_endpoint.into();
        let local_endpoint: IpListenEndpoint = local_endpoint.into();

        let local_endpoint = self.connect_local_endpoint(cx, remote_endpoint, local_endpoint)?;

        self.reset();
        let tuple = Tuple {
            local: local_endpoint,
            remote: remote_endpoint,
        };
        self.tuple = Some(tuple);
        self.set_connection_mss_cap(cx, remote_endpoint.addr);
        self.update_rx_mbuf_budget(cx);
        self.set_state(State::SynSent);

        let seq = Self::random_seq_no(cx, tuple);
        self.local_seq_no = seq;
        self.remote_last_seq = seq;
        self.remote_max_seq = seq;
        Ok(())
    }

    /// Validate a connect and resolve its local endpoint without changing the socket.
    pub fn connect_local_endpoint(
        &self,
        cx: &Context,
        remote_endpoint: IpEndpoint,
        local_endpoint: IpListenEndpoint,
    ) -> Result<IpEndpoint, ConnectError> {
        if self.is_open() {
            return Err(ConnectError::InvalidState);
        }
        if remote_endpoint.port == 0 || remote_endpoint.addr.is_unspecified() {
            return Err(ConnectError::Unaddressable);
        }
        if local_endpoint.port == 0 {
            return Err(ConnectError::Unaddressable);
        }

        // If local address is not provided, choose it automatically.
        let local_endpoint = IpEndpoint {
            addr: match local_endpoint.addr {
                Some(addr) => {
                    if addr.is_unspecified() {
                        return Err(ConnectError::Unaddressable);
                    }
                    addr
                }
                None => cx
                    .get_source_address(&remote_endpoint.addr)
                    .ok_or(ConnectError::Unaddressable)?,
            },
            port: local_endpoint.port,
        };

        if local_endpoint.addr.version() != remote_endpoint.addr.version() {
            return Err(ConnectError::Unaddressable);
        }

        Ok(local_endpoint)
    }

    #[cfg(test)]
    fn random_seq_no(_cx: &mut Context, _tuple: Tuple) -> TcpSeqNumber {
        TcpSeqNumber(10000)
    }

    #[cfg(not(test))]
    fn random_seq_no(cx: &mut Context, tuple: Tuple) -> TcpSeqNumber {
        initial_seq_no(cx.tcp_isn_secret, tuple, cx.now())
    }

    /// Close the transmit half of the full-duplex connection.
    /// In SYN-RECEIVED, reset the connection because the peer is not synchronized for a FIN.
    ///
    /// Note that there is no corresponding function for the receive half of the full-duplex
    /// connection; only the remote end can close it. If you no longer wish to receive any
    /// data and would like to reuse the socket right away, use [abort](#method.abort).
    pub fn close(&mut self) {
        match self.state {
            // In the LISTEN state there is no established connection.
            State::Listen => self.set_state(State::Closed),
            // In the SYN-SENT state the remote endpoint is not yet synchronized and, upon
            // receiving an RST, will abort the connection.
            State::SynSent => self.set_state(State::Closed),
            // In SYN-RECEIVED, reset because the peer is not synchronized for a FIN.
            State::SynReceived => self.abort(),
            // In the ESTABLISHED and CLOSE-WAIT states the transmit half
            // of the connection is open, and needs to be explicitly closed with a FIN.
            State::Established => self.set_state(State::FinWait1),
            State::CloseWait => self.set_state(State::LastAck),
            // In the FIN-WAIT-1, FIN-WAIT-2, CLOSING, LAST-ACK, TIME-WAIT and CLOSED states,
            // the transmit half of the connection is already closed, and no further
            // action is needed.
            State::FinWait1
            | State::FinWait2
            | State::Closing
            | State::TimeWait
            | State::LastAck
            | State::Closed => (),
        }
    }

    pub(crate) fn orphan(&mut self, now: Instant) {
        if self.recv_queue() > 0
            && matches!(self.state, State::SynReceived | State::Established | State::FinWait1
                        | State::FinWait2 | State::CloseWait | State::Closing | State::LastAck)
        {
            self.discard_received();
            self.abort();
        } else if self.state == State::SynSent {
            // Linux tcp_close: SYN-SENT goes to CLOSED without sending anything.
            self.reset();
        } else {
            self.close();
        }
        self.orphaned = true;
        if self.state == State::FinWait2 {
            self.timer.set_for_orphan_fin_wait_2(now);
        }
    }

    /// Aborts the connection, if any.
    ///
    /// This function instantly closes the socket. One reset packet will be sent to the remote
    /// endpoint.
    ///
    /// In terms of the TCP state machine, the socket may be in any state and is moved to
    /// the `CLOSED` state.
    pub fn abort(&mut self) {
        self.set_state(State::Closed);
    }

    /// Return whether the socket is passively listening for incoming connections.
    ///
    /// In terms of the TCP state machine, the socket must be in the `LISTEN` state.
    #[inline]
    pub fn is_listening(&self) -> bool {
        match self.state {
            State::Listen => true,
            _ => false,
        }
    }

    /// Return whether the socket is open.
    ///
    /// This function returns true if the socket will process incoming or dispatch outgoing
    /// packets. Note that this does not mean that it is possible to send or receive data through
    /// the socket; for that, use [can_send](#method.can_send) or [can_recv](#method.can_recv).
    ///
    /// In terms of the TCP state machine, the socket must not be in the `CLOSED`
    /// or `TIME-WAIT` states.
    #[inline]
    pub fn is_open(&self) -> bool {
        match self.state {
            State::Closed => false,
            State::TimeWait => false,
            _ => true,
        }
    }

    /// Return whether a connection is active.
    ///
    /// This function returns true if the socket is actively exchanging packets with
    /// a remote endpoint. Note that this does not mean that it is possible to send or receive
    /// data through the socket; for that, use [can_send](#method.can_send) or
    /// [can_recv](#method.can_recv).
    ///
    /// If a connection is established, [abort](#method.close) will send a reset to
    /// the remote endpoint.
    ///
    /// In terms of the TCP state machine, the socket must not be in the `CLOSED`, `TIME-WAIT`,
    /// or `LISTEN` state.
    #[inline]
    pub fn is_active(&self) -> bool {
        match self.state {
            State::Closed => false,
            State::TimeWait => false,
            State::Listen => false,
            _ => true,
        }
    }

    /// Return whether the transmit half of the full-duplex connection is open.
    ///
    /// This function returns true if it's possible to send data and have it arrive
    /// to the remote endpoint. However, it does not make any guarantees about the state
    /// of the transmit buffer, and even if it returns true, [send](#method.send) may
    /// not be able to enqueue any octets.
    ///
    /// In terms of the TCP state machine, the socket must be in the `ESTABLISHED` or
    /// `CLOSE-WAIT` state.
    #[inline]
    pub fn may_send(&self) -> bool {
        match self.state {
            State::Established => true,
            // In CLOSE-WAIT, the remote endpoint has closed our receive half of the connection
            // but we still can transmit indefinitely.
            State::CloseWait => true,
            _ => false,
        }
    }

    /// Return whether the receive half of the full-duplex connection is open.
    ///
    /// This function returns true if it's possible to receive data from the remote endpoint.
    /// It will return true while there is data in the receive buffer, and if there isn't,
    /// as long as the remote endpoint has not closed the connection.
    ///
    /// In terms of the TCP state machine, the socket must be in the `ESTABLISHED`,
    /// `FIN-WAIT-1`, or `FIN-WAIT-2` state, or have data in the receive buffer instead.
    #[inline]
    pub fn may_recv(&self) -> bool {
        match self.state {
            State::Established => true,
            // In FIN-WAIT-1/2, we have closed our transmit half of the connection but
            // we still can receive indefinitely.
            State::FinWait1 | State::FinWait2 => true,
            // If we have something in the receive buffer, we can receive that.
            _ if self.can_recv() => true,
            _ => false,
        }
    }

    /// Check whether the transmit half of the full-duplex connection is open
    /// (see [may_send](#method.may_send)), and the transmit buffer is not full.
    #[inline]
    pub fn can_send(&self) -> bool {
        if !self.may_send() {
            return false;
        }

        !self.tx_buffer.is_full()
    }

    /// Return the maximum number of bytes inside the recv buffer.
    #[inline]
    pub fn recv_capacity(&self) -> usize {
        self.rx_buffer.capacity
    }

    /// Return bytes beyond the in-order data the peer may still send,
    /// counting frame overhead.
    /// Returns 0 until the socket has a frame budget: admitted, or after connect or an accepted SYN.
    #[inline]
    pub fn recv_room(&self) -> usize {
        if self.rx_mbuf_cap == 0 {
            0
        } else {
            self.recv_window()
        }
    }

    /// Return the number of segments dropped because their frame would exceed the held-frame cap.
    pub fn rx_refused_segments(&self) -> u32 {
        self.rx_refused_segments
    }

    /// Return the maximum number of bytes inside the transmit buffer.
    #[inline]
    pub fn send_capacity(&self) -> usize {
        self.tx_buffer.capacity()
    }

    /// Check whether the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        self.rx_buffer.store.in_order_len() > 0
    }

    fn send_impl<'b, F, R>(&'b mut self, f: F) -> Result<R, SendError>
    where
        F: FnOnce(&'b mut SocketBuffer<'a>) -> (usize, R),
    {
        if !self.may_send() {
            return Err(SendError::InvalidState);
        }

        #[cfg(test)]
        let old_length = self.tx_buffer.len();
        let (size, result) = f(&mut self.tx_buffer);
        if size > 0 {
            #[cfg(test)]
            tcp_trace!(
                "tx buffer: enqueueing {} octets (now {})",
                size,
                old_length + size
            );
        }
        Ok(result)
    }

    /// Call `f` with the largest contiguous slice of octets in the transmit buffer,
    /// and enqueue the amount of elements returned by `f`.
    ///
    /// This function returns `Err(SendError::InvalidState)` if the transmit half of
    /// the connection is not open; see [may_send](#method.may_send).
    pub fn send<'b, F, R>(&'b mut self, f: F) -> Result<R, SendError>
    where
        F: FnOnce(&'b mut [u8]) -> (usize, R),
    {
        self.send_impl(|tx_buffer| tx_buffer.enqueue_many_with(f))
    }

    /// Enqueue a sequence of octets to be sent, and fill it from a slice.
    ///
    /// This function returns the amount of octets actually enqueued, which is limited
    /// by the amount of free space in the transmit buffer; down to zero.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8]) -> Result<usize, SendError> {
        self.send_impl(|tx_buffer| {
            let size = tx_buffer.enqueue_slice(data);
            (size, size)
        })
    }

    fn recv_error_check(&mut self) -> Result<(), RecvError> {
        // We may have received some data inside the initial SYN, but until the connection
        // is fully open we must not dequeue any data, as it may be overwritten by e.g.
        // another (stale) SYN. (We do not support TCP Fast Open.)
        if !self.may_recv() {
            if self.rx_fin_received {
                return Err(RecvError::Finished);
            }
            return Err(RecvError::InvalidState);
        }

        Ok(())
    }

    /// Schedule a readiness check when an application-held receive frame is dropped.
    pub(crate) fn set_rx_wake(
        &mut self,
        queue: crate::iface::DropQueue,
        handle: crate::iface::SocketHandle,
    ) {
        *self.rx_buffer.shared.wake.borrow_mut() = Some((queue, handle));
    }

    /// Stop receive frame drops from scheduling readiness checks for this socket.
    pub(crate) fn clear_rx_wake(&mut self) {
        *self.rx_buffer.shared.wake.borrow_mut() = None;
    }

    pub(crate) fn clear_rx_wake_queued(&mut self) {
        self.rx_buffer.shared.wake_queued.set(false);
    }

    /// Frames the app still holds; they keep their RX pool buffers until dropped.
    pub fn held_frames(&self) -> HeldFrames {
        HeldFrames::new(self.rx_buffer.shared.clone())
    }

    /// Drain the next whole in-order frame, or return None when no data is queued.
    /// Frames keep occupying the socket's RX frame budget until dropped.
    /// After a FIN, queued frames are drained before returning RecvError::Finished.
    /// Other closed receive states return RecvError::InvalidState.
    #[inline(always)]
    pub fn recv(&mut self) -> Result<Option<TcpFrame>, RecvError> {
        self.recv_error_check()?;
        let Some(frame) = self.rx_buffer.store.pop_front() else {
            return Ok(None);
        };
        self.remote_seq_no += frame.len();
        self.rx_buffer.shared.hold();
        Ok(Some(TcpFrame { frame, shared: self.rx_buffer.shared.clone() }))
    }

    /// Return the amount of octets queued in the transmit buffer.
    ///
    /// Note that the Berkeley sockets interface does not have an equivalent of this API.
    pub fn send_queue(&self) -> usize {
        self.tx_buffer.len()
    }

    /// Number of octets transmitted but not yet ACKed.
    fn flight_size(&self) -> usize {
        self.remote_last_seq - self.local_seq_no
    }

    /// The MSS we advertise: what our IP MTU and connection cap allow for TCP payload.
    fn local_mss(&self, cx: &Context) -> usize {
        let ip_header_len = match self.tuple.unwrap().local.addr {
            IpAddress::Ipv4(_) => crate::wire::IPV4_HEADER_LEN,
        };
        cx.ip_mtu()
            .checked_sub(ip_header_len + TCP_HEADER_LEN)
            .expect("interface MTU too small for TCP")
            .min(self.connection_mss_cap.map(core::num::NonZeroU16::get)
                .map_or(usize::MAX, usize::from))
    }

    fn set_connection_mss_cap(&mut self, cx: &Context, remote: IpAddress) {
        self.connection_mss_cap = self.mss_cap;
        {
            let path = cx.path_ip_mtu(&remote);
            if path < cx.ip_mtu() {
                let cap = path.checked_sub(crate::wire::IPV4_HEADER_LEN + TCP_HEADER_LEN)
                    .expect("path MTU too small for TCP");
                let cap = u16::try_from(cap).expect("path MSS exceeds u16");
                self.connection_mss_cap = core::num::NonZeroU16::new(
                    self.mss_cap.map_or(cap, |app| app.get().min(cap)),
                );
            }
        }
    }

    fn update_rx_mbuf_budget(&mut self, cx: &Context) {
        let payload = rx_frame_bytes(
            cx.ip_mtu(), self.connection_mss_cap.map(core::num::NonZeroU16::get),
        )
            .min(self.local_mss(cx));
        if self.rx_mbuf_cap == 0 {
            self.rx_mbuf_cap = u32::try_from(rx_mbuf_budget_for_payload(self.recv_capacity(), payload))
                .expect("RX mbuf cap exceeds u32");
        }
        self.rx_seg_bytes = u32::try_from(payload.min(usize::from(self.remote_mss)))
            .expect("RX segment bytes exceed u32");
    }

    /// Payload bytes of a full-sized segment (SMSS): the smaller of what our MTU and
    /// the remote's MSS allow.
    fn effective_mss(&self, cx: &Context) -> usize {
        self.local_mss(cx).min(usize::from(self.remote_mss))
    }

    fn cwnd_remaining(&self) -> usize {
        self.congestion_controller
            .window()
            .saturating_sub(self.flight_size())
    }

    /// Sequence number of a segment that occupies no sequence space: the highest
    /// sequence number sent, or the right edge of the remote window if the window
    /// shrank below it by at least one unit of the remote's window scale (Linux
    /// tcp_acceptable_seq; Linux measures the unit by its own receive scale, but the
    /// remote's scale is what rounds the edge it advertises). A zero window gets no
    /// such tolerance: the highest sequence sent then passes the edge by a zero
    /// window probe byte, which Linux never sends, and the remote drops a segment
    /// past its zero window. Not remote_last_seq: after a retransmission timeout it
    /// can be below the remote's RCV.NXT, and the remote would drop the segment
    /// without reading its ACK.
    fn acceptable_seq(&self) -> TcpSeqNumber {
        let win_right_edge = self.local_seq_no + self.remote_win_len as usize;
        let scale_unit = 1usize << self.remote_win_scale.unwrap_or(0);
        if self.remote_max_seq <= win_right_edge
            || (self.remote_win_len != 0
                && self.remote_max_seq - win_right_edge < scale_unit)
        {
            self.remote_max_seq
        } else {
            win_right_edge
        }
    }

    /// Return the number of in-order octets queued in the receive buffer.
    /// This includes all queued frames, including bytes appended into them.
    ///
    /// Note that the Berkeley sockets interface does not have an equivalent of this API.
    pub fn recv_queue(&self) -> usize {
        self.rx_buffer.store.in_order_len()
    }

    pub(crate) fn discard_received(&mut self) {
        self.remote_seq_no += self.rx_buffer.store.in_order_len();
        self.rx_buffer.store.clear();
    }

    fn set_state(&mut self, state: State) {
        if self.state != state {
            tcp_trace!("state={}=>{}", self.state, state);
        }

        self.state = state;
        if state == State::Closed {
            self.set_recover(None);
            self.pending_fast_retransmit = false;
        }
    }

    pub(crate) fn reply(ip_repr: &IpRepr, repr: &TcpRepr) -> (IpRepr, TcpRepr<'static>) {
        let reply_repr = TcpRepr {
            src_port: repr.dst_port,
            dst_port: repr.src_port,
            control: TcpControl::None,
            seq_number: TcpSeqNumber(0),
            ack_number: None,
            window_len: 0,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        let ip_reply_repr = IpRepr::new(
            ip_repr.dst_addr(),
            ip_repr.src_addr(),
            IpProtocol::Tcp,
            reply_repr.buffer_len(),
            64,
        );
        (ip_reply_repr, reply_repr)
    }

    pub(crate) fn rst_reply(ip_repr: &IpRepr, repr: &TcpRepr) -> (IpRepr, TcpRepr<'static>) {
        debug_assert!(repr.control != TcpControl::Rst);

        let (ip_reply_repr, mut reply_repr) = Self::reply(ip_repr, repr);

        // See https://www.snellman.net/blog/archive/2016-02-01-tcp-rst/ for explanation
        // of why we sometimes send an RST and sometimes an RST|ACK
        reply_repr.control = TcpControl::Rst;
        reply_repr.seq_number = repr.ack_number.unwrap_or_default();
        if repr.control == TcpControl::Syn && repr.ack_number.is_none() {
            reply_repr.ack_number = Some(repr.seq_number + repr.segment_len());
        }

        (ip_reply_repr, reply_repr)
    }

    fn sack_ranges(&self) -> impl Iterator<Item = (TcpSeqNumber, TcpSeqNumber)> + '_ {
        let ack = self.remote_seq_no + self.rx_buffer.store.in_order_len();
        let mut ranges = self.rx_buffer.store.out_of_order_ranges()
            .map(move |(left, right)| (ack + left, ack + right)).peekable();
        let mut fin_seq = self.rx_fin_seq;
        core::iter::from_fn(move || {
            let Some(&(left, right)) = ranges.peek() else {
                return fin_seq.take().map(|seq| (seq, seq + 1));
            };
            if let Some(seq) = fin_seq {
                if seq + 1 < left {
                    fin_seq = None;
                    return Some((seq, seq + 1));
                }
                if seq <= right {
                    fin_seq = None;
                    ranges.next();
                    let mut right = right.max(seq + 1);
                    while let Some(&(next_left, next_right)) = ranges.peek()
                        && next_left <= right
                    {
                        ranges.next();
                        right = right.max(next_right);
                    }
                    return Some((left.min(seq), right));
                }
            }
            ranges.next()
        })
    }

    /// SACK blocks for an ACK, empty unless the peer negotiated SACK. A D-SACK range
    /// (RFC 2883) comes first, then the held range containing the latest received segment
    /// (RFC 2018), else the lowest held range, then the other held ranges in sequence order,
    /// up to the three blocks the option holds. Only wholly duplicate segments get a D-SACK;
    /// a segment that is partly duplicate and partly new gets none, unlike Linux.
    fn sack_blocks(&self, dsack: Option<(TcpSeqNumber, TcpSeqNumber)>) -> [Option<(u32, u32)>; 3] {
        let mut blocks = [None; 3];
        if !self.remote_has_sack {
            return blocks;
        }
        let block = |(left, right): (TcpSeqNumber, TcpSeqNumber)| Some((left.0 as u32, right.0 as u32));
        let mut next = 0;
        if let Some(range) = dsack {
            blocks[0] = block(range);
            next = 1;
        }
        if self.rx_buffer.store.out_of_order_span() == 0 && self.rx_fin_seq.is_none() {
            return blocks;
        }
        let first = self
            .local_rx_last_seq()
            .and_then(|seq| self.sack_ranges().find(|&(left, right)| left <= seq && seq <= right))
            .or_else(|| self.sack_ranges().next());
        let rest = self.sack_ranges().filter(|&range| Some(range) != first);
        for (slot, range) in blocks[next..].iter_mut().zip(first.into_iter().chain(rest)) {
            *slot = block(range);
        }
        blocks
    }

    /// Builds a pure-ACK (or SACK) reply to `repr` and advances the socket's
    /// idea of what it has acknowledged.
    ///
    /// `remote_last_ack`/`remote_last_win_bytes` are only advanced when `cx` can
    /// currently resolve a next hop for the reply's destination. Interface
    /// dispatch for this synchronous ingress-triggered reply has no
    /// confirmed-send callback (unlike the queued egress path, which updates
    /// these fields only after `TxToken::consume` runs, see `dispatch`
    /// below): without this check, dispatch_ip's neighbor-missing drop (an
    /// immediate `Err` before any transmit, whenever the peer isn't already
    /// in the neighbor cache: a connection's first reply before ARP
    /// resolves, or any later reply after the entry was evicted for
    /// capacity) still left the socket believing it ACKed data it never put
    /// on the wire. A TxToken still failing after this check, or the
    /// neighbor expiring in the race window between the check and the
    /// actual send, isn't covered. Nor is retry: a dropped reply whose
    /// ack_number/window_len don't move the needle (a challenge ACK or an
    /// out-of-order FIN ack) leaves nothing for
    /// `ack_to_transmit` to notice later, so it isn't resent until some
    /// other segment arrives; that's unchanged from before this gate, since
    /// smoltcp has no general pending-reply retry queue for this path.
    fn ack_reply(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
        dsack: Option<(TcpSeqNumber, TcpSeqNumber)>,
    ) -> (IpRepr, TcpRepr<'static>) {
        let (mut ip_reply_repr, mut reply_repr) = Self::reply(ip_repr, repr);

        // From RFC 793:
        // [...] an empty acknowledgment segment containing the current send-sequence number
        // and an acknowledgment indicating the next sequence number expected
        // to be received.
        reply_repr.seq_number = self.acceptable_seq();
        reply_repr.ack_number = Some(self.remote_seq_no + self.rx_buffer.store.in_order_len());

        // From RFC 1323:
        // The window field [...] of every outgoing segment, with the exception of SYN
        // segments, is right-shifted by [advertised scale value] bits[...]
        reply_repr.window_len = self.scaled_window();

        if cx.has_neighbor(&ip_reply_repr.dst_addr()) {
            self.remote_last_ack = reply_repr.ack_number;
            self.remote_last_ack_is_marker = false;
            self.remote_last_win_bytes = u32::from(reply_repr.window_len) << self.remote_win_shift;
        }
        // This reply carries our ACK but leaves the delayed-ACK timer alone; only egress
        // dispatch resets it. If the timer was Immediate, the next small in-order segment is
        // ACKed at once instead of after the delay: at most one early pure ACK. Accepted, since
        // clearing it here would add work to every reply.

        // RFC 2018: the first SACK block covers the segment that triggered this ACK, unless
        // that segment advanced the acknowledgment number.
        reply_repr.sack_ranges = self.sack_blocks(dsack);

        // Since the sACK option may have changed the length of the payload, update that.
        ip_reply_repr.set_payload_len(reply_repr.buffer_len());
        (ip_reply_repr, reply_repr)
    }

    fn challenge_ack_allowed(&mut self, cx: &mut Context) -> bool {
        if cx.now() < self.challenge_ack_timer {
            return false;
        }

        self.challenge_ack_timer = cx.now() + Duration::from_millis(500);
        true
    }

    #[cold]
    fn challenge_ack_reply(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        if !self.challenge_ack_allowed(cx) {
            return None;
        }

        Some(self.ack_reply(cx, ip_repr, repr, None))
    }

    fn out_of_window_reply(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        // Data and FIN consume sequence space and need ACKs to recover from
        // lost ACKs or window probes. SYN challenge ACKs remain rate-limited.
        if repr.control == TcpControl::Fin
            || (!repr.payload.is_empty()
                && matches!(repr.control, TcpControl::None | TcpControl::Psh))
        {
            // Data entirely below RCV.NXT is a duplicate: report it as D-SACK (RFC 2883).
            // Not in TIME-WAIT, whose Linux ACK carries no SACK option.
            let end = repr.seq_number + repr.payload.len();
            let dsack = (!repr.payload.is_empty()
                && self.state != State::TimeWait
                && end <= self.remote_seq_no + self.rx_buffer.store.in_order_len())
                .then_some((repr.seq_number, end));
            return Some(self.ack_reply(cx, ip_repr, repr, dsack));
        }

        self.challenge_ack_reply(cx, ip_repr, repr)
    }

    pub(crate) fn time_wait_accepts_syn(&self, repr: &TcpRepr) -> bool {
        if self.state != State::TimeWait
            || !matches!(repr.control, TcpControl::Syn | TcpControl::SynFin)
            || repr.ack_number.is_some()
        {
            return false;
        }
        self.remote_seq_no + self.rx_buffer.store.in_order_len() < repr.seq_number
    }

    pub(crate) fn accepts(&self, _cx: &mut Context, ip_repr: &IpRepr, repr: &TcpRepr) -> bool {
        if self.state == State::Closed {
            return false;
        }

        // If we're still listening for SYNs and the packet has an ACK or a RST,
        // it cannot be destined to this socket, but another one may well listen
        // on the same local endpoint.
        if self.state == State::Listen
            && (repr.ack_number.is_some() || repr.control == TcpControl::Rst)
        {
            return false;
        }

        if let Some(tuple) = &self.tuple {
            // Reject packets not matching the 4-tuple
            ip_repr.dst_addr() == tuple.local.addr
                && repr.dst_port == tuple.local.port
                && ip_repr.src_addr() == tuple.remote.addr
                && repr.src_port == tuple.remote.port
        } else {
            // We're listening, reject packets not matching the listen endpoint.
            let addr_ok = match self.listen_endpoint.addr {
                Some(addr) => ip_repr.dst_addr() == addr,
                None => true,
            };
            addr_ok && repr.dst_port != 0 && repr.dst_port == self.listen_endpoint.port
        }
    }

    fn receive_fin(&mut self, cx: &mut Context, ack_of_fin: bool) {
        self.remote_seq_no += 1;
        self.rx_fin_received = true;
        self.rx_fin_seq = None;
        match self.state {
            State::SynReceived | State::Established => self.set_state(State::CloseWait),
            State::FinWait1 if !ack_of_fin => self.set_state(State::Closing),
            State::FinWait1 | State::FinWait2 => {
                self.set_state(State::TimeWait);
                self.timer.set_for_close(cx.now());
            }
            _ => unreachable!(),
        }
    }

    pub(crate) fn commit_rx(&mut self, mut frame: RxBuf, pending: PendingRxCommit) {
        let start = pending
            .payload_start
            .checked_sub(frame.as_slice().as_ptr() as usize)
            .expect("TCP payload starts before its frame");
        let end = start
            .checked_add(pending.payload_len)
            .expect("TCP payload range overflow");
        assert!(end <= frame.len(), "TCP payload ends outside its frame");
        let kept_start = start
            .checked_add(pending.kept.start)
            .expect("TCP payload range overflow");
        let kept_end = start
            .checked_add(pending.kept.end)
            .expect("TCP payload range overflow");
        frame.narrow(kept_start..kept_end);
        self.rx_buffer.store.attach(frame);
    }

    fn truncate_at_fin(&mut self, fin_offset: Option<usize>) {
        if let Some(offset) = fin_offset {
            self.rx_buffer.store.truncate_from(offset);
        }
    }

    pub(crate) fn process(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
    ) -> (Option<(IpRepr, TcpRepr<'static>)>, Option<PendingRxCommit>) {
        // The segment changes the state the threshold was computed from; the socket is now
        // dirty and its next poll_at re-arms it.
        self.rx_buffer.shared.wake_at_held.set(usize::MAX);
        let mut pending = None;
        let reply = self.process_inner(cx, ip_repr, repr, &mut pending);
        (reply, pending)
    }

    fn process_inner(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
        pending: &mut Option<PendingRxCommit>,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        debug_assert!(self.accepts(cx, ip_repr, repr));

        if repr.control == TcpControl::SynFin
            && !matches!(self.state, State::TimeWait | State::Established | State::FinWait1
                         | State::FinWait2 | State::CloseWait | State::Closing | State::LastAck)
        {
            return None;
        }

        if matches!(repr.control, TcpControl::Syn | TcpControl::SynFin) {
            if self.time_wait_accepts_syn(repr) {
                return Some(self.ack_reply(cx, ip_repr, repr, None));
            }
            match self.state {
                State::TimeWait => {
                    if repr.ack_number.is_some() {
                        self.timer.set_for_close(cx.now());
                    }
                    return self.challenge_ack_reply(cx, ip_repr, repr);
                }
                State::Established | State::FinWait1 | State::FinWait2
                | State::CloseWait | State::Closing | State::LastAck => {
                    return self.challenge_ack_reply(cx, ip_repr, repr);
                }
                State::SynReceived if repr.ack_number.is_none()
                    && repr.seq_number + 1 == self.remote_seq_no => {
                    if self.challenge_ack_allowed(cx) {
                        self.remote_last_seq = self.local_seq_no;
                        self.rtte.on_retransmit();
                        self.timer.set_for_idle();
                    }
                    return None;
                }
                _ => {}
            }
        }

        let window_start = self.remote_seq_no + self.rx_buffer.store.in_order_len();
        let window_end = if let Some(last_ack) = self.remote_last_ack {
            last_ack + (self.remote_last_win_bytes as usize)
        } else {
            window_start
        };
        let segment_start = repr.seq_number;
        let segment_end = repr.seq_number + repr.payload.len();

        if repr.control == TcpControl::Rst
            && matches!(self.state, State::SynReceived | State::Established | State::FinWait1
                        | State::FinWait2 | State::CloseWait | State::Closing | State::LastAck
                        | State::TimeWait)
        {
            // SYN-RECEIVED uses Linux tcp_in_window (tcp_minisocks.c:27-34), whose right
            // edge is exclusive. The six established-socket states use tcp_sequence
            // (tcp_input.c:4496-4504), which includes it via after().
            let window_update = self.remote_last_ack
                .map(|ack| ack + usize::from(self.remote_last_ack_is_marker))
                .unwrap_or(window_start);
            let segment_in_window = segment_end >= window_update
                && if self.state == State::SynReceived {
                    segment_start < window_end
                } else {
                    segment_start <= window_end
                };
            // Linux also accepts the peer's FIN sequence in these three states.
            let at_peer_fin = matches!(self.state, State::CloseWait | State::Closing | State::LastAck)
                && segment_start == window_start - 1;
            let at_sack_end = segment_in_window && self.state != State::TimeWait && self.remote_has_sack && {
                let mut highest_end = self.rx_buffer.store.out_of_order_ranges().last()
                    .map(|(_, right)| window_start + right);
                if let Some(fin_seq) = self.rx_fin_seq {
                    let fin_end = fin_seq + 1;
                    highest_end = Some(highest_end.map_or(fin_end, |end| end.max(fin_end)));
                }
                highest_end == Some(segment_start)
            };
            if segment_start == window_start || at_peer_fin || at_sack_end {
                tcp_trace!("received RST");
                if self.state == State::SynReceived && self.listen_endpoint.port != 0 {
                    let listen_endpoint = self.listen_endpoint;
                    self.reset();
                    self.listen_endpoint = listen_endpoint;
                    self.set_state(State::Listen);
                } else {
                    // Linux does not reset a TIME-WAIT connection; our own close came first.
                    self.reset_by_peer = self.state != State::TimeWait;
                    self.set_state(State::Closed);
                    self.tuple = None;
                }
                return None;
            }
            if self.state == State::TimeWait {
                return None;
            }
            if segment_in_window {
                return self.challenge_ack_reply(cx, ip_repr, repr);
            }
            return None;
        }

        if self.state == State::TimeWait {
            if repr.payload.is_empty() && repr.control != TcpControl::Fin
                && repr.seq_number == window_start
            {
                self.timer.set_for_close(cx.now());
                return None;
            }
            if repr.ack_number.is_some() {
                self.timer.set_for_close(cx.now());
            }
            return self.out_of_window_reply(cx, ip_repr, repr);
        }

        // Consider how much the sequence number space differs from the transmit buffer space.
        let (sent_syn, sent_fin) = match self.state {
            // Linux tcp_check_req validates the handshake ACK before sequence.
            State::SynReceived if repr.control != TcpControl::Rst
                && repr.ack_number.is_some_and(|ack| ack != self.local_seq_no + 1) =>
            {
                net_debug!("unacceptable ACK in response to SYN|ACK");
                return Some(Self::rst_reply(ip_repr, repr));
            }
            // In SYN-SENT or SYN-RECEIVED, we've just sent a SYN.
            State::SynSent | State::SynReceived => (true, false),
            // In FIN-WAIT-1, LAST-ACK, or CLOSING, we've just sent a FIN.
            State::FinWait1 | State::LastAck | State::Closing => (false, true),
            // In all other states we've already got acknowledgements for
            // all of the control flags we sent.
            _ => (false, false),
        };

        if !matches!(self.state, State::Listen | State::SynSent) {
            if repr.ack_number.is_none() && repr.control != TcpControl::Rst {
                net_debug!("expecting an ACK");
                return None;
            }
            // https://www.rfc-editor.org/rfc/rfc9293.html#name-segment-acceptability-tests
            let segment_in_window = match (
                segment_start == segment_end,
                window_start == window_end,
            ) {
                (true, _) if segment_end == window_start - 1 => {
                    net_debug!(
                        "received a keep-alive or window probe packet, will send an ACK"
                    );
                    false
                }
                (true, true) => {
                    if window_start == segment_start {
                        true
                    } else {
                        net_debug!(
                            "zero-length segment not inside zero-length window, will send an ACK."
                        );
                        false
                    }
                }
                (true, false) => {
                    // Linux tcp_sequence accepts zero-length segments at the right edge.
                    if window_start <= segment_start && segment_start <= window_end {
                        true
                    } else {
                        net_debug!("zero-length segment not inside window, will send an ACK.");
                        false
                    }
                }
                (false, true) => {
                    net_debug!(
                        "non-zero-length segment with zero receive window, will only send an ACK"
                    );
                    false
                }
                (false, false) => {
                    if (window_start <= segment_start && segment_start < window_end)
                        || (window_start < segment_end && segment_end <= window_end)
                    {
                        true
                    } else {
                        net_debug!(
                            "segment not in receive window ({}..{} not intersecting {}..{}), will send challenge ACK",
                            segment_start,
                            segment_end,
                            window_start,
                            window_end
                        );
                        false
                    }
                }
            };

            if !segment_in_window {
                // Out-of-window RSTs are silently dropped, per RFC 9293
                // (3.10.7.4) and RFC 5961 (3.2): no reply is sent, and the
                // TIME-WAIT timer is not refreshed. RST senders don't
                // need a reply to make progress.
                if repr.control == TcpControl::Rst {
                    net_debug!("dropping out-of-window RST");
                    return None;
                }

                return self.out_of_window_reply(cx, ip_repr, repr);
            }
        }

        // Reject unacceptable acknowledgements.
        let mut old_ack = false;
        match (self.state, repr.control, repr.ack_number) {
            // An RST received in response to initial SYN is acceptable if it acknowledges
            // the initial SYN.
            (State::SynSent, TcpControl::Rst, None) => {
                net_debug!("unacceptable RST (expecting RST|ACK) in response to initial SYN");
                return None;
            }
            (State::SynSent, TcpControl::Rst, Some(ack_number)) => {
                if ack_number != self.local_seq_no + 1 {
                    net_debug!("unacceptable RST|ACK in response to initial SYN");
                    return None;
                }
            }
            // Any other RST need only have a valid sequence number.
            (_, TcpControl::Rst, _) => (),
            // The initial SYN cannot contain an acknowledgement.
            (State::Listen, _, None) => (),
            // This case is handled in `accepts()`.
            (State::Listen, _, Some(_)) => unreachable!(),
            // SYN|ACK in the SYN-SENT state must have the exact ACK number.
            (State::SynSent, TcpControl::Syn, Some(ack_number)) => {
                if ack_number != self.local_seq_no + 1 {
                    net_debug!("unacceptable SYN|ACK in response to initial SYN");
                    return Some(Self::rst_reply(ip_repr, repr));
                }
            }
            // TCP simultaneous open.
            // This is required by RFC 9293, which states "A TCP implementation MUST support
            // simultaneous open attempts (MUST-10)."
            (State::SynSent, TcpControl::Syn, None) => (),
            // ACKs in the SYN-SENT state are invalid.
            (State::SynSent, TcpControl::None, Some(ack_number)) => {
                // If the sequence number matches, ignore it instead of RSTing.
                // I'm not sure why, I think it may be a workaround for broken TCP
                // servers, or a defense against reordering. Either way, if Linux
                // does it, we do too.
                if ack_number == self.local_seq_no + 1 {
                    net_debug!(
                        "expecting a SYN|ACK, received an ACK with the right ack_number, ignoring."
                    );
                    return None;
                }

                net_debug!(
                    "expecting a SYN|ACK, received an ACK with the wrong ack_number, sending RST."
                );
                return Some(Self::rst_reply(ip_repr, repr));
            }
            // Anything else in the SYN-SENT state is invalid.
            (State::SynSent, _, _) => {
                net_debug!("expecting a SYN|ACK");
                return None;
            }
            // Every packet after the initial SYN must be an acknowledgement.
            (_, _, None) => {
                net_debug!("expecting an ACK");
                return None;
            }
            // SYN-RECEIVED ACKs were checked before receive-window validation.
            (State::SynReceived, _, Some(_)) => (),
            // ACKs must not pass the highest sequence number sent, zero window probe
            // byte included. Old ACKs still carry valid payload (Linux tcp_ack old_ack).
            (_, _, Some(ack_number)) => {
                // Acceptable ACK range (both inclusive)
                let mut ack_min = self.local_seq_no;
                let ack_max = self.remote_max_seq;

                // If we have sent a SYN, it MUST be acknowledged.
                if sent_syn {
                    ack_min += 1;
                }

                if ack_number < ack_min {
                    let max_window = (self.max_snd_wnd as u64).min(self.bytes_acked) as usize;
                    if ack_number < self.local_seq_no - max_window {
                        return self.challenge_ack_reply(cx, ip_repr, repr);
                    }
                    net_debug!(
                        "duplicate ACK ({} not in {}...{})",
                        ack_number,
                        ack_min,
                        ack_max
                    );
                    old_ack = true;
                } else if ack_number > ack_max {
                    net_debug!(
                        "unacceptable ACK ({} not in {}...{})",
                        ack_number,
                        ack_min,
                        ack_max
                    );
                    return self.challenge_ack_reply(cx, ip_repr, repr);
                }
            }
        }

        if self.orphaned && matches!(self.state, State::FinWait1 | State::FinWait2)
            && ((!repr.payload.is_empty() && segment_end > window_start)
                || (repr.control == TcpControl::Fin && segment_start > window_start))
        {
            let reply = Self::rst_reply(ip_repr, repr);
            self.reset();
            return Some(reply);
        }

        let (mut payload, payload_offset) = match self.state {
            // In LISTEN and SYN-SENT states, we have not yet synchronized with the remote end.
            State::Listen | State::SynSent => (&[][..], 0),
            _ => {
                let overlap_start = window_start.max(segment_start);
                let overlap_end = window_end.min(segment_end);

                // the checks done above imply this.
                debug_assert!(overlap_start <= overlap_end);

                self.set_local_rx_last_seq(Some(repr.seq_number));

                (
                    &repr.payload[overlap_start - segment_start..overlap_end - segment_start],
                    overlap_start - window_start,
                )
            }
        };

        // Compute the amount of acknowledged octets, removing the SYN and FIN bits
        // from the sequence space.
        let mut ack_len = 0;
        let mut ack_of_fin = false;
        let mut ack_all = false;
        if !old_ack && repr.control != TcpControl::Rst
            && let Some(ack_number) = repr.ack_number
        {
            // Sequence number corresponding to the first byte in `tx_buffer`.
            // This normally equals `local_seq_no`, but is 1 higher if we have sent a SYN,
            // as the SYN occupies 1 sequence number "before" the data.
            let tx_buffer_start_seq = self.local_seq_no + (sent_syn as usize);

            if ack_number >= tx_buffer_start_seq {
                ack_len = ack_number - tx_buffer_start_seq;

                // We could've sent data before the FIN, so only remove FIN from the sequence
                // space if all of that data is acknowledged.
                if sent_fin && self.tx_buffer.len() + 1 == ack_len {
                    ack_len -= 1;
                    tcp_trace!("received ACK of FIN");
                    ack_of_fin = true;
                }

                ack_all = self.remote_max_seq <= ack_number;
            }
        }

        // Disregard control flags we don't care about or shouldn't act on yet.
        let mut control = repr.control;
        control = control.quash_psh();
        let mut out_of_order_fin = false;
        let previous_fin_seq = self.rx_fin_seq;

        if self.rx_fin_received
            || matches!(self.state, State::CloseWait | State::Closing | State::LastAck | State::TimeWait)
        {
            payload = &[];
            if control == TcpControl::Fin {
                control = TcpControl::None;
            }
        } else if control == TcpControl::Fin {
            if segment_end > window_end {
                control = TcpControl::None;
            } else if matches!(self.state, State::SynReceived | State::Established | State::FinWait1 | State::FinWait2) {
                if window_start < segment_start {
                    out_of_order_fin = true;
                    control = TcpControl::None;
                    let covered = self.rx_buffer.store.out_of_order_ranges().any(|(left, right)|
                        window_start + left <= segment_start && segment_end + 1 <= window_start + right);
                    if covered {
                        payload = &[];
                    } else {
                        self.rx_fin_seq = Some(self.rx_fin_seq.map_or(segment_end, |seq| seq.min(segment_end)));
                    }
                } else {
                    self.rx_fin_seq = None;
                }
            }
        }

        if let Some(fin_seq) = self.rx_fin_seq {
            let payload_start = window_start + payload_offset;
            let before_fin = if payload_start < fin_seq { fin_seq - payload_start } else { 0 };
            payload = &payload[..payload.len().min(before_fin)];
        }

        let offset = self
            .rx_buffer
            .store
            .in_order_len()
            .checked_add(payload_offset)
            .expect("TCP receive offset overflow");
        let decision = if payload.is_empty() {
            None
        } else {
            Some(
                self.rx_buffer
                    .store
                    .decide(offset, payload.len(), (self.rx_mbuf_cap as usize)
                        .checked_sub(self.rx_buffer.shared.held.get())
                        .expect("app-held frames exceed RX mbuf cap")),
            )
        };
        let refused = matches!(decision, Some(Decision::Refused));
        if refused {
            // A statistic the peer can drive; it must never panic the stack.
            self.rx_refused_segments = self.rx_refused_segments.saturating_add(1);
            payload = &[];
            if control == TcpControl::Fin {
                control = TcpControl::None;
            }
            self.rx_fin_seq = previous_fin_seq;
            out_of_order_fin = false;
        }
        let mut fin_offset = None;

        // Validate and update the state.
        match (self.state, control) {
            // RSTs are not accepted in the LISTEN state.
            (State::Listen, TcpControl::Rst) => return None,

            // RSTs in any other state close the socket.
            (_, TcpControl::Rst) => {
                tcp_trace!("received RST");
                self.reset_by_peer = self.state != State::TimeWait;
                self.set_state(State::Closed);
                self.tuple = None;
                return None;
            }

            // SYN packets in the LISTEN state change it to SYN-RECEIVED.
            (State::Listen, TcpControl::Syn) => {
                tcp_trace!("received SYN");
                if let Some(max_seg_size) = repr.max_seg_size {
                    // Treat a zero MSS as if the option were absent, like Linux does.
                    if max_seg_size != 0 {
                        self.remote_mss = u16::try_from((max_seg_size as usize).max(MIN_REMOTE_MSS))
                            .expect("peer MSS clamped to minimum exceeds u16");
                    }
                }

                let tuple = Tuple {
                    local: IpEndpoint::new(ip_repr.dst_addr(), repr.dst_port),
                    remote: IpEndpoint::new(ip_repr.src_addr(), repr.src_port),
                };
                self.tuple = Some(tuple);
                self.local_seq_no = Self::random_seq_no(cx, tuple);
                self.remote_seq_no = repr.seq_number + 1;
                self.remote_win_seq = repr.seq_number;
                self.remote_last_seq = self.local_seq_no;
                self.remote_max_seq = self.local_seq_no;
                self.remote_has_sack = repr.sack_permitted;
                self.remote_win_scale = repr.window_scale;
                // Remote doesn't support window scaling, don't do it.
                if self.remote_win_scale.is_none() {
                    self.remote_win_shift = 0;
                }
                self.set_connection_mss_cap(cx, ip_repr.src_addr());
                self.update_rx_mbuf_budget(cx);
                self.congestion_controller.set_mss(self.effective_mss(cx));
                self.congestion_controller.set_initial_window(self.initial_window);
                // Initialize the SYN window without adding it to the ACK-age bound.
                self.remote_win_len = u32::from(repr.window_len);
                self.congestion_controller.set_remote_window(self.remote_win_len as usize);
                self.rcv_mss = self.local_mss(cx)
                    .min(self.effective_mss(cx))
                    .min(self.recv_window() / 2)
                    .min(DEFAULT_MSS)
                    .max(88);
                self.set_state(State::SynReceived);
                self.timer.set_for_idle();
            }

            // ACK packets in the SYN-RECEIVED state change it to ESTABLISHED.
            (State::SynReceived, TcpControl::None) => {
                self.congestion_controller.on_handshake(cx.now(), self.initial_window);
                self.set_state(State::Established);
            }

            // FIN packets in the SYN-RECEIVED state change it to CLOSE-WAIT.
            // It's not obvious from RFC 793 that this is permitted, but
            // 7th and 8th steps in the "SEGMENT ARRIVES" event describe this behavior.
            (State::SynReceived, TcpControl::Fin) => {
                self.congestion_controller.on_handshake(cx.now(), self.initial_window);
                fin_offset = Some(segment_end - self.remote_seq_no);
                self.receive_fin(cx, ack_of_fin);
            }

            // SYN|ACK packets in the SYN-SENT state change it to ESTABLISHED.
            // SYN packets in the SYN-SENT state change it to SYN-RECEIVED.
            (State::SynSent, TcpControl::Syn) => {
                if repr.ack_number.is_some() {
                    tcp_trace!("received SYN|ACK");
                } else {
                    tcp_trace!("received SYN");
                }
                if let Some(max_seg_size) = repr.max_seg_size {
                    // Treat a zero MSS as if the option were absent, like Linux does.
                    if max_seg_size != 0 {
                        self.remote_mss = u16::try_from((max_seg_size as usize).max(MIN_REMOTE_MSS))
                            .expect("peer MSS clamped to minimum exceeds u16");
                    }
                }

                self.remote_seq_no = repr.seq_number + 1;
                self.remote_win_seq = repr.seq_number;
                self.remote_last_seq = self.local_seq_no + 1;
                self.remote_max_seq = self.local_seq_no + 1;
                self.remote_last_ack = Some(repr.seq_number);
                self.remote_last_ack_is_marker = true;
                self.remote_has_sack = repr.sack_permitted;
                self.remote_win_scale = repr.window_scale;
                // Remote doesn't support window scaling, don't do it.
                if self.remote_win_scale.is_none() {
                    self.remote_win_shift = 0;
                }
                self.update_rx_mbuf_budget(cx);
                self.congestion_controller.set_mss(self.effective_mss(cx));
                self.rcv_mss = self.local_mss(cx)
                    .min(self.effective_mss(cx))
                    .min(self.recv_window() / 2)
                    .min(DEFAULT_MSS)
                    .max(88);

                if repr.ack_number.is_some() {
                    self.congestion_controller.on_handshake(cx.now(), self.initial_window);
                    self.set_state(State::Established);
                } else {
                    self.set_state(State::SynReceived);
                }
            }

            (State::Established, TcpControl::None) => {}

            // FIN packets in ESTABLISHED state indicate the remote side has closed.
            (State::Established, TcpControl::Fin) => {
                fin_offset = Some(segment_end - self.remote_seq_no);
                self.receive_fin(cx, ack_of_fin);
            }

            // ACK packets in FIN-WAIT-1 state change it to FIN-WAIT-2, if we've already
            // sent everything in the transmit buffer. If not, they reset the retransmit timer.
            (State::FinWait1, TcpControl::None) => {
                if ack_of_fin {
                    self.set_state(State::FinWait2);
                    if self.orphaned {
                        self.timer.set_for_orphan_fin_wait_2(cx.now());
                    }
                }
            }

            // FIN packets in FIN-WAIT-1 state change it to CLOSING, or to TIME-WAIT
            // if they also acknowledge our FIN.
            (State::FinWait1, TcpControl::Fin) => {
                fin_offset = Some(segment_end - self.remote_seq_no);
                self.receive_fin(cx, ack_of_fin);
            }

            (State::FinWait2, TcpControl::None) => {}

            // FIN packets in FIN-WAIT-2 state change it to TIME-WAIT.
            (State::FinWait2, TcpControl::Fin) => {
                fin_offset = Some(segment_end - self.remote_seq_no);
                self.receive_fin(cx, ack_of_fin);
            }

            // ACK packets in CLOSING state change it to TIME-WAIT.
            (State::Closing, TcpControl::None) => {
                if ack_of_fin {
                    self.set_state(State::TimeWait);
                    self.timer.set_for_close(cx.now());
                }
            }

            (State::CloseWait, TcpControl::None) => {}

            // ACK packets in LAST-ACK state change it to CLOSED.
            (State::LastAck, TcpControl::None) => {
                if ack_of_fin {
                    // Clear the remote endpoint, or we'll send an RST there.
                    self.set_state(State::Closed);
                    self.tuple = None;
                }
            }

            _ => {
                net_debug!("unexpected packet {}", repr);
                return None;
            }
        }

        // RFC 1323: The window field (SEG.WND) in the header of every incoming segment, with the
        // exception of SYN segments, is left-shifted by Snd.Wind.Scale bits before updating SND.WND.
        let scale = match repr.control {
            TcpControl::Syn => 0,
            _ => self.remote_win_scale.unwrap_or(0),
        };
        let new_remote_win_len = u32::from(repr.window_len) << (scale as usize);
        let mut is_window_update = false;
        if !old_ack
            && (repr.ack_number.is_some_and(|ack_number| ack_number > self.local_seq_no)
                || repr.seq_number > self.remote_win_seq
                || (repr.seq_number == self.remote_win_seq
                    && (new_remote_win_len > self.remote_win_len || new_remote_win_len == 0)))
        {
            is_window_update = new_remote_win_len != self.remote_win_len;
            if self.remote_win_len == 0 && new_remote_win_len != 0 {
                self.rto_backoff = 0;
            }
            self.remote_win_len = new_remote_win_len;
            self.max_snd_wnd = self.max_snd_wnd.max(new_remote_win_len);
            self.remote_win_seq = repr.seq_number;

            self.congestion_controller
                .set_remote_window(new_remote_win_len as usize);
        }

        if ack_len > 0 {
            // Dequeue acknowledged octets.
            debug_assert!(self.tx_buffer.len() >= ack_len);
            tcp_trace!(
                "tx buffer: dequeueing {} octets (now {})",
                ack_len,
                self.tx_buffer.len() - ack_len
            );
            self.tx_buffer.dequeue_allocated(ack_len);
        }

        if !old_ack && let Some(ack_number) = repr.ack_number {

            match self.local_rx_last_ack() {
                // Duplicate ACK if payload empty and ACK doesn't move send window ->
                // Increment duplicate ACK count, notify congestion controller and
                // set for retransmit if we just received the third duplicate ACK
                Some(last_rx_ack)
                    if repr.payload.is_empty()
                        && last_rx_ack == ack_number
                        && ack_number < self.remote_last_seq
                        && !is_window_update =>
                {
                    // Increment duplicate ACK count
                    self.local_rx_dup_acks = self.local_rx_dup_acks.saturating_add(1);

                    net_debug!(
                        "received duplicate ACK for seq {} (duplicate nr {}{})",
                        ack_number,
                        self.local_rx_dup_acks,
                        if self.local_rx_dup_acks == u8::MAX {
                            "+"
                        } else {
                            ""
                        }
                    );

                    if self.local_rx_dup_acks == 3 && self.recover().is_none() {
                        self.timer.set_for_fast_retransmit();
                        net_debug!("started fast retransmit");
                    }

                    // Notify of duplicate ACK
                    let in_flight = self.flight_size();
                    let smss = self.effective_mss(cx);
                    self.congestion_controller
                        .on_dup_ack(cx.now(), smss, in_flight);
                }

                // No duplicate ACK means we reset the duplicate ACK count
                // and notify the congestion controller of the fresh ACK
                _ => {
                    if self.local_rx_dup_acks > 0 {
                        self.local_rx_dup_acks = 0;
                        net_debug!("reset duplicate ACK count");
                    }
                    self.set_local_rx_last_ack(Some(ack_number));

                    // Notify of fresh ACK
                    self.rtte.on_ack(cx.now(), ack_number);
                    let new_flight_size = self.flight_size().saturating_sub(ack_len);
                    self.congestion_controller.on_ack(
                        cx.now(),
                        ack_len,
                        new_flight_size,
                        &self.rtte,
                    );
                }
            };

            // We've processed everything in the incoming segment, so advance the local
            // sequence number past it.
            let acked = ack_number - self.local_seq_no
                - usize::from(sent_syn && self.listen_endpoint.port != 0);
            self.bytes_acked = self.bytes_acked.checked_add(acked as u64)
                .expect("acknowledged byte count overflow");
            if ack_number > self.local_seq_no {
                self.rto_backoff = 0;
                self.in_rto_loss_episode = false;
                self.pending_fast_retransmit = self.recover().is_some_and(|recover| ack_number < recover);
            }
            if self.recover().is_some_and(|recover| ack_number >= recover) {
                self.set_recover(None);
            }
            self.local_seq_no = ack_number;

            // During retransmission, if an earlier segment got lost but later was
            // successfully received, self.local_seq_no can move past self.remote_last_seq.
            // Do not attempt to retransmit the latter segments; not only this is pointless
            // in theory but also impossible in practice, since they have been already
            // deallocated from the buffer.
            if self.remote_last_seq < self.local_seq_no {
                self.remote_last_seq = self.local_seq_no
            }
            // An acceptable ACK may cover sequence space never sent: ISN + 1 in
            // SYN-RECEIVED if the SYN|ACK was not emitted. Keep SND.UNA at or below
            // the highest sequence number sent.
            if self.remote_max_seq < self.local_seq_no {
                self.remote_max_seq = self.local_seq_no
            }
        }

        // update timers.
        match self.timer {
            Timer::Retransmit { .. } | Timer::FastRetransmit => {
                if ack_all {
                    // RFC 6298: (5.2) ACK of all outstanding data turn off the retransmit timer.
                    self.timer.set_for_idle();
                } else if ack_len > 0 {
                    // (5.3) ACK of new data in ESTABLISHED state restart the retransmit timer.
                    let rto = self.retransmission_timeout();
                    self.timer.set_for_retransmit(cx.now(), rto);
                }
            }
            Timer::Idle if !old_ack && self.local_seq_no < self.remote_max_seq => {
                let rto = self.retransmission_timeout();
                self.timer.set_for_retransmit(cx.now(), rto);
            }
            _ => {}
        }

        // start/stop the Zero Window Probe timer.
        if self.remote_win_len == 0
            && !self.tx_buffer.is_empty()
            && (self.timer.is_idle() || ack_len > 0)
        {
            let delay = self.retransmission_timeout();
            tcp_trace!("starting zero-window-probe timer for t+{}", delay);
            self.timer.set_for_zero_window_probe(cx.now(), delay);
        }
        if self.remote_win_len != 0 && self.timer.is_zero_window_probe() {
            tcp_trace!("stopping zero-window-probe timer");
            if self.local_seq_no < self.remote_max_seq {
                let rto = self.retransmission_timeout();
                self.timer.set_for_retransmit(cx.now(), rto);
            } else {
                self.timer.set_for_idle();
            }
        }

        let payload_len = payload.len();
        if payload_len == 0 {
            self.truncate_at_fin(fin_offset);
            return if refused || out_of_order_fin {
                Some(self.ack_reply(cx, ip_repr, repr, None))
            } else {
                None
            };
        }

        let out_of_order_was_empty = fin_offset.is_some()
            || (self.rx_buffer.store.out_of_order_span() == 0 && self.rx_fin_seq.is_none());
        let in_order_len = self.rx_buffer.store.in_order_len();

        // Receive MSS estimate, before the delayed-ACK decision below uses it.
        if repr.payload.len() > self.rcv_mss
            && segment_start <= window_start
            && window_start < segment_end
        {
            self.rcv_mss = repr.payload.len().min(self.local_mss(cx)).max(self.rcv_mss);
        }

        let mut dsack = None;
        match decision {
            Some(decision @ Decision::New(_)) => {
                let kept = decision.kept().unwrap();
                self.rx_buffer.store.place(offset, decision);
                *pending = Some(PendingRxCommit {
                    kept: kept.start.checked_sub(offset).unwrap()
                        ..kept.end.checked_sub(offset).unwrap(),
                    payload_start: payload.as_ptr() as usize,
                    payload_len,
                });
            }
            Some(decision @ Decision::Append(_)) => {
                self.rx_buffer.store.append(offset, decision, payload);
            }
            Some(Decision::Duplicate(_)) => {
                // Every byte is already held out of order: D-SACK it (RFC 2883).
                let start = window_start + payload_offset;
                dsack = Some((start, start + payload_len));
            }
            Some(Decision::Refused) | None => {}
        }

        let mut contig_len = self.rx_buffer.store.in_order_len()
            .checked_sub(in_order_len)
            .expect("in-order bytes decreased during placement");
        if let Some(fin_seq) = self.rx_fin_seq {
            contig_len = contig_len.min(fin_seq - window_start);
        }

        if self.rx_fin_seq == Some(window_start + contig_len) {
            fin_offset = Some(self.rx_fin_seq.unwrap() - self.remote_seq_no);
            self.receive_fin(cx, ack_of_fin);
        }
        self.truncate_at_fin(fin_offset);

        // Handle delayed acks
        if let Some(ack_delay) = self.ack_delay()
            && self.ack_to_transmit()
        {
            self.set_ack_delay_timer(match self.ack_delay_timer() {
                AckDelayTimer::Idle => {
                    tcp_trace!("starting delayed ack timer");
                    AckDelayTimer::Waiting(cx.now() + ack_delay)
                }
                AckDelayTimer::Waiting(_) if self.immediate_ack_to_transmit() => {
                    tcp_trace!("delayed ack timer already started, forcing expiry");
                    AckDelayTimer::Immediate
                }
                timer @ AckDelayTimer::Waiting(_) => {
                    tcp_trace!("waiting until delayed ack timer expires");
                    timer
                }
                AckDelayTimer::Immediate => {
                    tcp_trace!("delayed ack timer already force-expired");
                    AckDelayTimer::Immediate
                }
            });
        }

        // Per RFC 5681, we should send an immediate ACK when either:
        //  1) an out-of-order segment is received, or
        //  2) a segment arrives that fills in all or part of a gap in sequence space.
        if self.rx_buffer.store.out_of_order_span() != 0 || !out_of_order_was_empty {
            // Note that we change the transmitter state here.
            // This is fine because smoltcp assumes that it can always transmit zero or one
            // packets for every packet it receives.
            tcp_trace!("ACKing incoming segment");
            Some(self.ack_reply(cx, ip_repr, repr, dsack))
        } else {
            None
        }
    }

    fn seq_to_transmit(&self, cx: &Context) -> bool {
        // Fast retransmits should always send, even if later congestion checks would disallow
        if self.pending_fast_retransmit {
            return true;
        }

        // Have we sent data that hasn't been ACKed yet?
        let data_in_flight = self.remote_last_seq != self.local_seq_no;

        // If we want to send a SYN and we haven't done so, do it!
        if matches!(self.state, State::SynSent | State::SynReceived) && !data_in_flight {
            return true;
        }

        // max sequence number we can send.
        let max_send_seq =
            self.local_seq_no + core::cmp::min(self.remote_win_len as usize, self.tx_buffer.len());

        // Max amount of octets we can send.
        let capped_send_seq = if max_send_seq >= self.remote_last_seq {
            max_send_seq - self.remote_last_seq
        } else {
            0
        };

        // compare max bytes allowed by cwnd with max bytes allowed by remote
        let max_send = capped_send_seq.min(self.cwnd_remaining());

        // Can we send at least 1 octet?
        let can_send = max_send != 0;

        // Do we have to send a FIN?
        let want_fin = match self.state {
            State::FinWait1 => true,
            State::Closing => true,
            State::LastAck => true,
            _ => false,
        };

        // Can we actually send the FIN? We can send it if:
        // 1. We have unsent data that fits in the remote window.
        // 2. We have no unsent data.
        // This condition matches only if #2, because #1 is already covered by can_data and we're ORing them.
        let can_fin = want_fin && self.remote_last_seq == self.local_seq_no + self.tx_buffer.len();

        can_send || can_fin
    }

    fn delayed_ack_expired(&self, timestamp: Instant) -> bool {
        match self.ack_delay_timer() {
            AckDelayTimer::Idle => true,
            AckDelayTimer::Waiting(t) => t <= timestamp,
            AckDelayTimer::Immediate => true,
        }
    }

    fn ack_to_transmit(&self) -> bool {
        if let Some(remote_last_ack) = self.remote_last_ack {
            remote_last_ack < self.remote_seq_no + self.rx_buffer.store.in_order_len()
        } else {
            false
        }
    }

    /// Return whether to send ACK immediately due to the amount of unacknowledged data.
    ///
    /// RFC 9293 states "An ACK SHOULD be generated for at least every second full-sized segment or
    /// 2*RMSS bytes of new data (where RMSS is the MSS specified by the TCP endpoint receiving the
    /// segments to be acknowledged, or the default value if not specified) (SHLD-19)."
    ///
    /// Note that the RFC above only says "at least 2*RMSS bytes", which is not a hard requirement.
    /// In practice, we follow the Linux kernel's empirical value of sending an ACK for every RMSS
    /// byte of new data, with RMSS its receive MSS estimate (`rcv_mss`). For details, see
    /// <https://elixir.bootlin.com/linux/v6.11.4/source/net/ipv4/tcp_input.c#L5747>.
    fn immediate_ack_to_transmit(&self) -> bool {
        if let Some(remote_last_ack) = self.remote_last_ack {
            remote_last_ack + self.rcv_mss
                < self.remote_seq_no + self.rx_buffer.store.in_order_len()
        } else {
            false
        }
    }

    /// Return whether we should send ACK immediately due to significant window updates.
    ///
    /// ACKs with significant window updates should be sent immediately to let the sender know that
    /// more data can be sent. According to the Linux kernel implementation, "significant" means
    /// doubling the receive window. The Linux kernel implementation can be found at
    /// <https://elixir.bootlin.com/linux/v6.9.9/source/net/ipv4/tcp.c#L1472>.
    fn window_to_update(&self) -> bool {
        match self.state {
            State::Established | State::FinWait1 | State::FinWait2 => {
                let Some(last_win) = self.last_scaled_window() else {
                    return false;
                };
                // The new window is at most the byte window, so a byte window below twice the
                // last one cannot be a doubling, whatever the frame window is.
                if (self.rx_buffer.capacity >> self.remote_win_shift) / 2 < usize::from(last_win) {
                    return false;
                }
                let new_win = self.scaled_window_with_last(Some(last_win));
                new_win > 0 && new_win / 2 >= last_win
            }
            _ => false,
        }
    }

    /// The largest app-held frame count at which `window_to_update` holds, everything else
    /// as now; `usize::MAX` when no count does. The window grows as held frames drop, so a
    /// drop that reaches this count makes a window update due.
    fn rx_wake_at_held(&self) -> usize {
        const NEVER: usize = usize::MAX;
        if !matches!(self.state, State::Established | State::FinWait1 | State::FinWait2)
            || self.rx_buffer.shared.held.get() == 0
        {
            return NEVER;
        }
        let Some(last_win) = self.last_scaled_window() else {
            return NEVER;
        };
        // window_to_update: new_win > 0 && new_win / 2 >= last_win, new_win a u16.
        let needed = (2 * usize::from(last_win)).max(1);
        if needed > usize::from(u16::MAX) || self.rx_buffer.capacity >> self.remote_win_shift < needed {
            return NEVER;
        }
        let needed_bytes = needed << self.remote_win_shift;
        let unstored = (self.rx_mbuf_cap as usize)
            .checked_sub(self.rx_buffer.store.held())
            .expect("stored frames exceed RX mbuf cap");
        let span = self.rx_buffer.store.out_of_order_span();
        let missing = match needed_bytes.checked_sub(span) {
            None | Some(0) => return unstored,
            Some(missing) => missing,
        };
        let frames = missing.div_ceil(self.rx_seg_bytes as usize);
        unstored
            .checked_sub(self.rx_buffer.store.out_of_order_hole_frames(self.rx_seg_bytes as usize) + frames)
            .unwrap_or(NEVER)
    }

    pub(crate) fn dispatch<F, E>(&mut self, cx: &mut Context, emit: F) -> Result<(), E>
    where
        F: FnOnce(&mut Context, PacketMeta, (IpRepr, TcpRepr)) -> Result<(), E>,
    {
        if self.tuple.is_none() {
            return Ok(());
        }

        // NOTE(unwrap): we check tuple is not None above.
        let tuple = self.tuple.unwrap();

        // Check if the interface still has our source IP address.
        // If not (e.g. the interface's IP changed), reset the socket.
        // We use reset() instead of set_state(Closed) to avoid sending
        // an RST packet with the now-invalid source IP.
        if !cx.has_ip_addr(tuple.local.addr) {
            net_debug!("source IP address no longer available, closing socket");
            self.reset();
            return Ok(());
        }

        if self.timer.should_close(cx.now()) {
            tcp_trace!("close timer expired");
            if self.state == State::TimeWait {
                self.finish_time_wait();
            } else {
                self.reset();
            }
            return Ok(());
        }

        if self.remote_win_len == 0 && !self.tx_buffer.is_empty() && self.timer.is_idle() {
            let delay = self.retransmission_timeout();
            tcp_trace!("starting zero-window-probe timer for t+{}", delay);
            self.timer.set_for_zero_window_probe(cx.now(), delay);
        }

        // Check if any state needs to be changed because of a timer.
        if self.timer.should_retransmit(cx.now()) {
            if let Timer::Retransmit { .. } = self.timer {
                if self.orphaned && self.rto_backoff >= ORPHAN_RETRIES {
                    self.reset();
                    return Ok(());
                }
                // If a retransmit timer expired, we should resend data starting at the last ACK.
                net_debug!("retransmitting after rto");

                // Inform the congestion controller that we're retransmitting and should enter the slow start state
                let in_flight = self.flight_size();
                self.congestion_controller.on_rto(cx.now(), in_flight);
                self.set_recover(None);
                self.pending_fast_retransmit = false;
                if !self.in_rto_loss_episode {
                    self.loss_events = self.loss_events.checked_add(1).expect("loss event count overflow");
                    self.in_rto_loss_episode = true;
                }

                // Rewind "last sequence number sent", as if we never
                // had sent them. This will cause all data in the queue
                // to be sent again.
                self.remote_last_seq = self.local_seq_no;

                self.rto_backoff = self
                    .rto_backoff
                    .checked_add(1)
                    .expect("RTO backoff overflow");
                self.rtte.on_rto();
            } else {
                // If a fast rentrasmit timer expired, we should resend only the earliest unAcked segment
                net_debug!("retransmitting for fast-retransmit");

                // Inform the congestion controller that we're doing a fast retransmit and should enter the fast recovery state
                let in_flight = self.flight_size();
                self.congestion_controller.on_loss(cx.now(), in_flight);
                self.set_recover(Some(self.remote_max_seq));
                self.loss_events = self.loss_events.checked_add(1).expect("loss event count overflow");

                self.pending_fast_retransmit = true;
            }

            // Clear the expired retransmit timer. With a closed window, keep
            // probing so a lost window update cannot stall queued data.
            if matches!(self.timer, Timer::Retransmit { .. })
                && self.remote_win_len == 0 && !self.tx_buffer.is_empty()
            {
                self.timer = Timer::ZeroWindowProbe {
                    expires_at: cx.now(),
                    backoff_applied: true,
                };
            } else {
                self.timer.set_for_idle();
            }

            // Inform RTTE, so that it can avoid bogus measurements.
            self.rtte.on_retransmit();
        }

        if let Timer::ZeroWindowProbe { expires_at, backoff_applied } = &mut self.timer
            && cx.now() >= *expires_at && !*backoff_applied
        {
            if self.orphaned && self.rto_backoff >= ORPHAN_RETRIES {
                self.reset();
                return Ok(());
            }
            self.rto_backoff = self.rto_backoff.checked_add(1)
                .expect("RTO backoff overflow");
            *backoff_applied = true;
        }

        // Decide whether we're sending a packet.
        if self.seq_to_transmit(cx) {
            // If we have data to transmit and it fits into partner's window, do it.
            tcp_trace!("outgoing segment will send data or flags");
        } else if self.ack_to_transmit() && self.delayed_ack_expired(cx.now()) {
            // If we have data to acknowledge, do it.
            tcp_trace!("outgoing segment will acknowledge");
        } else if self.window_to_update() {
            // If we have window length increase to advertise, do it.
            tcp_trace!("outgoing segment will update window");
        } else if self.state == State::Closed {
            // If we need to abort the connection, do it.
            tcp_trace!("outgoing segment will abort connection");
        } else if self.timer.should_zero_window_probe(cx.now()) {
            tcp_trace!("sending zero-window probe");
        } else {
            return Ok(());
        }

        // Construct the lowered IP representation.
        // We might need this to calculate the MSS, so do it early.
        let mut ip_repr = IpRepr::new(
            tuple.local.addr,
            tuple.remote.addr,
            IpProtocol::Tcp,
            0,
            self.hop_limit.map(core::num::NonZeroU8::get).unwrap_or(64),
        );

        // Construct the basic TCP representation, an empty ACK packet.
        // We'll adjust this to be more specific as needed.
        let mut repr = TcpRepr {
            src_port: tuple.local.port,
            dst_port: tuple.remote.port,
            control: TcpControl::None,
            seq_number: self.remote_last_seq,
            ack_number: Some(self.remote_seq_no + self.rx_buffer.store.in_order_len()),
            window_len: self.scaled_window(),
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };

        let mut is_zero_window_probe = false;
        let mut is_fast_retransmit = false;

        let packet_meta = PacketMeta::default();

        match self.state {
            // We transmit an RST in the CLOSED state. If we ended up in the CLOSED state
            // with a specified endpoint, it means that the socket was aborted.
            State::Closed => {
                repr.control = TcpControl::Rst;
                // The highest sequence number sent: remote_last_seq can be below the
                // remote's RCV.NXT after a retransmission timeout. Linux uses
                // tcp_acceptable_seq; its window clamp is skipped because before
                // synchronization (an abort in SYN-SENT) the send window is unknown (0)
                // and would pull the RST below the remote's RCV.NXT.
                repr.seq_number = self.remote_max_seq;
            }

            // We never transmit anything in the LISTEN state.
            State::Listen => return Ok(()),

            // We transmit a SYN in the SYN-SENT state.
            // We transmit a SYN|ACK in the SYN-RECEIVED state.
            State::SynSent | State::SynReceived => {
                repr.control = TcpControl::Syn;
                repr.seq_number = self.local_seq_no;
                // window len must NOT be scaled in SYNs.
                let window = if self.state == State::SynSent {
                    let per_frame = (self.rx_seg_bytes as usize).min(MIN_REMOTE_MSS);
                    self.recv_window().min((self.rx_mbuf_cap as usize)
                        .checked_mul(per_frame).expect("SYN receive window exceeds usize"))
                } else {
                    self.recv_window()
                };
                repr.window_len = u16::try_from(window).unwrap_or(u16::MAX);
                if self.state == State::SynSent {
                    repr.ack_number = None;
                    repr.window_scale = Some(self.remote_win_shift);
                    repr.sack_permitted = true;
                } else {
                    repr.sack_permitted = self.remote_has_sack;
                    repr.window_scale = self.remote_win_scale.map(|_| self.remote_win_shift);
                }
            }

            // We transmit data in all states where we may have data in the buffer,
            // or the transmit half of the connection is still open.
            State::Established
            | State::FinWait1
            | State::Closing
            | State::CloseWait
            | State::LastAck => {
                // Extract as much data as the remote side can receive in this packet
                // from the transmit buffer.

                // Maximum size we're allowed to send. This can be limited by 4 factors:
                // 1. remote window
                // 2. MSS the remote is willing to accept, probably determined by their MTU
                // 3. MSS we can send, determined by our MTU.
                // 4. Our congestion window
                let effective_mss = self.effective_mss(cx);

                let offset = if self.pending_fast_retransmit {
                    let size = effective_mss.min(self.tx_buffer.len());
                    repr.seq_number = self.local_seq_no;
                    repr.payload = self.tx_buffer.get_allocated(0, size);

                    is_fast_retransmit = true;

                    0
                } else {
                    // Right edge of window, ie the max sequence number we're allowed to send.
                    let win_right_edge = self.local_seq_no + self.remote_win_len as usize;

                    // Max amount of octets we're allowed to send according to the remote window.
                    let mut win_limit = if win_right_edge >= self.remote_last_seq {
                        win_right_edge - self.remote_last_seq
                    } else {
                        // This can happen if we've sent some data and later the remote side
                        // has shrunk its window so that data is no longer inside the window.
                        // This should be very rare and is strongly discouraged by the RFCs,
                        // but it does happen in practice.
                        // http://www.tcpipguide.com/free/t_TCPWindowManagementIssues.htm
                        0
                    };

                    // To send a zero-window-probe, force the window limit to at least 1 byte.
                    if win_limit == 0 && self.timer.should_zero_window_probe(cx.now()) {
                        win_limit = 1;
                        is_zero_window_probe = true;
                    }

                    // Maximum size we're allowed to send. This can be limited by 4 factors:
                    // 1. remote window
                    // 2. congestion window
                    // 3. MSS the remote is willing to accept, probably determined by their MTU
                    // 4. MSS we can send, determined by our MTU.

                    let device_limit = effective_mss;

                    let size = if is_zero_window_probe {
                        // Zero-window probes are exempt from the congestion window: they
                        // are sent precisely when normal transmission is impossible, and
                        // an empty segment elicits no reply, so capping the probe to a
                        // zero length would stall the connection if a window update from
                        // the remote got lost.
                        win_limit.min(device_limit)
                    } else {
                        win_limit.min(device_limit).min(self.cwnd_remaining())
                    };

                    let offset = self.flight_size();
                    repr.payload = self.tx_buffer.get_allocated(offset, size);

                    offset
                };

                // If we've sent everything we had in the buffer, follow it with the PSH or FIN
                // flags, depending on whether the transmit half of the connection is open.
                if offset + repr.payload.len() == self.tx_buffer.len() {
                    match self.state {
                        State::FinWait1 | State::LastAck | State::Closing => {
                            repr.control = TcpControl::Fin
                        }
                        State::Established | State::CloseWait if !repr.payload.is_empty() => {
                            repr.control = TcpControl::Psh
                        }
                        _ => (),
                    }
                }
            }

            // In FIN-WAIT-2 and TIME-WAIT states we may only transmit ACKs for incoming data or FIN
            State::FinWait2 | State::TimeWait => {}
        }

        if !is_zero_window_probe && repr.is_empty() {
            // A pure ACK or window update. A zero window probe with no byte to carry
            // keeps the send cursor's sequence number: past the closed window, it
            // draws an ACK from the remote.
            repr.seq_number = self.acceptable_seq();
        }

        // Trace a summary of what will be sent.
        if !repr.payload.is_empty() {
            tcp_trace!(
                "tx buffer: sending {} octets at offset {}",
                repr.payload.len(),
                self.flight_size()
            );
        }
        if repr.control != TcpControl::None || repr.payload.is_empty() {
            let flags = match (repr.control, repr.ack_number) {
                (TcpControl::Syn, None) => "SYN",
                (TcpControl::Syn, Some(_)) => "SYN|ACK",
                (TcpControl::Fin, Some(_)) => "FIN|ACK",
                (TcpControl::Rst, Some(_)) => "RST|ACK",
                (TcpControl::Psh, Some(_)) => "PSH|ACK",
                (TcpControl::None, Some(_)) => "ACK",
                _ => "<unreachable>",
            };
            tcp_trace!("sending {}", flags);
        }

        if repr.control == TcpControl::Syn {
            // Fill the MSS option. See RFC 6691 for an explanation of this calculation.
            repr.max_seg_size = Some(self.local_mss(cx) as u16);
        }
        // Only segments without payload: data is sized to the MSS with no room for options.
        if repr.payload.is_empty() && matches!(repr.control, TcpControl::None | TcpControl::Fin) {
            repr.sack_ranges = self.sack_blocks(None);
        }

        // Actually send the packet. If this succeeds, it means the packet is in
        // the device buffer, and its transmission is imminent. If not, we might have
        // a number of problems, e.g. we need neighbor discovery.
        //
        // Bailing out if the packet isn't placed in the device buffer allows us
        // to not waste time waiting for the retransmit timer on packets that we know
        // for sure will not be successfully transmitted.
        ip_repr.set_payload_len(repr.buffer_len());
        let result = emit(cx, packet_meta, (ip_repr, repr));
        if self.orphaned && self.state == State::Closed {
            self.tuple = None;
        }
        if result.is_err() && self.orphaned && repr.segment_len() > 0 {
            let delay = self.retransmission_timeout();
            if is_zero_window_probe {
                self.timer.set_for_zero_window_probe(cx.now(), delay);
            } else if !self.timer.is_retransmit() {
                self.timer.set_for_retransmit(cx.now(), delay);
            }
        }
        result?;
        if repr.segment_len() > 0 && repr.seq_number < self.remote_max_seq {
            self.retransmits = self.retransmits.checked_add(1).expect("retransmit count overflow");
        }

        // Reset delayed-ack timer
        match self.ack_delay_timer() {
            AckDelayTimer::Idle => {}
            AckDelayTimer::Waiting(_) => {
                tcp_trace!("stop delayed ack timer")
            }
            AckDelayTimer::Immediate => {
                tcp_trace!("stop delayed ack timer (was force-expired)")
            }
        }
        // Field writes, not set_ack_delay_timer: repr.payload still borrows tx_buffer.
        self.ack_kind = AckKind::Idle;
        self.ack_at = Instant::ZERO;

        // Only now: if the emit failed, the next dispatch resends the hole, since the
        // fast retransmit timer that set the flag has already been cleared.
        if is_fast_retransmit {
            self.pending_fast_retransmit = false;
        }

        // A zero window probe byte counts: the remote may accept and acknowledge it.
        // A pure ACK never ends past the highest sequence number sent.
        self.remote_max_seq = self
            .remote_max_seq
            .max(repr.seq_number + repr.segment_len());

        // We've sent a packet successfully, so we can update the internal state now.
        self.remote_last_ack = repr.ack_number;
        self.remote_last_ack_is_marker = false;
        self.remote_last_win_bytes = if repr.control == TcpControl::Syn {
            u32::from(repr.window_len)
        } else {
            u32::from(repr.window_len) << self.remote_win_shift
        };

        // Leave the rest of the state intact if sending a zero-window probe.
        if is_zero_window_probe {
            self.rtte.on_send(cx.now(), repr.seq_number + repr.segment_len());
            self.rtte.on_retransmit();
            let delay = self.retransmission_timeout();
            self.timer.set_for_zero_window_probe(cx.now(), delay);
            return Ok(());
        }

        if repr.segment_len() > 0 {
            // Use max() so a fast-retransmit segment (whose seq_number is local_seq_no,
            // well behind the current frontier) doesn't rewind the send cursor. A pure
            // ACK must not move it either: it carries the highest sequence number
            // sent, which is ahead of the cursor after a retransmission timeout.
            self.remote_last_seq = self
                .remote_last_seq
                .max(repr.seq_number + repr.segment_len());
            self.rtte
                .on_send(cx.now(), repr.seq_number + repr.segment_len());
            self.congestion_controller
                .post_transmit(cx.now(), repr.segment_len());
        }

        if repr.segment_len() > 0 && !self.timer.is_retransmit() {
            // RFC 6298 (5.1) Every time a packet containing data is sent (including a
            // retransmission), if the timer is not running, start it running
            // so that it will expire after RTO seconds.
            let rto = self.retransmission_timeout();
            self.timer.set_for_retransmit(cx.now(), rto);
        }

        if self.state == State::Closed {
            // When aborting a connection, forget about it after sending a single RST packet.
            self.tuple = None;
        }

        Ok(())
    }

    pub(crate) fn poll_at(&self, cx: &mut Context) -> PollAt {
        let (poll_at, wake_at_held) = self.poll_at_read(cx);
        self.rx_buffer.shared.wake_at_held.set(wake_at_held);
        poll_at
    }

    #[allow(clippy::if_same_then_else)]
    pub(crate) fn poll_at_read(&self, cx: &Context) -> (PollAt, usize) {
        // The logic here mirrors the beginning of dispatch() closely.
        if self.tuple.is_none() {
            // No one to talk to, nothing to transmit.
            (PollAt::Ingress, usize::MAX)
        } else if self.remote_win_len == 0 && !self.tx_buffer.is_empty() && self.timer.is_idle() {
            // Dispatch must arm the first probe from the caller's current time.
            (PollAt::Now, usize::MAX)
        } else if self.state == State::Closed {
            // Socket was aborted, we have an RST packet to transmit.
            (PollAt::Now, usize::MAX)
        } else if self.seq_to_transmit(cx) {
            // We have a data or flag packet to transmit.
            (PollAt::Now, usize::MAX)
        } else {
            let want_ack = self.ack_to_transmit();

            let delayed_ack_poll_at = match (want_ack, self.ack_delay_timer()) {
                (false, _) => PollAt::Ingress,
                (true, AckDelayTimer::Idle) => PollAt::Now,
                (true, AckDelayTimer::Waiting(t)) => PollAt::Time(t),
                (true, AckDelayTimer::Immediate) => PollAt::Now,
            };
            // An ACK due now and a significantly raised receive window both answer Now; the ACK
            // check goes first because it computes no window.
            if delayed_ack_poll_at == PollAt::Now || self.window_to_update() {
                return (PollAt::Now, usize::MAX);
            }

            // We wait for the earliest of our timers to fire.
            let poll_at = *[self.timer.poll_at(), delayed_ack_poll_at]
                .iter()
                .min()
                .unwrap_or(&PollAt::Ingress);
            (poll_at, self.rx_wake_at_held())
        }
    }
}

impl<'a> fmt::Write for Socket<'a> {
    fn write_str(&mut self, slice: &str) -> fmt::Result {
        let slice = slice.as_bytes();
        if self.send_slice(slice) == Ok(slice.len()) {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

#[cfg(test)]
#[test]
fn smoothed_rtt_size() {
    assert_eq!(core::mem::size_of::<SmoothedRtt>(), 24);
}

#[cfg(test)]
#[test]
fn rtt_sampling_round_trips() {
    let mut rtte = SmoothedRtt::default();
    assert_eq!(rtte.smoothed_rtt(), 0);
    assert_eq!(rtte.timestamp(), None);
    assert_eq!(rtte.max_seq_sent(), None);

    let first_send = Instant::from_millis(10);
    rtte.on_send(first_send, TcpSeqNumber(0));
    assert_eq!(rtte.timestamp(), Some((first_send, TcpSeqNumber(0))));
    assert_eq!(rtte.max_seq_sent(), Some(TcpSeqNumber(0)));

    rtte.on_send(Instant::from_millis(20), TcpSeqNumber(-1));
    assert_eq!(rtte.timestamp(), Some((first_send, TcpSeqNumber(0))));
    assert_eq!(rtte.max_seq_sent(), Some(TcpSeqNumber(0)));
    rtte.on_ack(Instant::from_millis(30), TcpSeqNumber(-1));
    assert_eq!(rtte.smoothed_rtt(), 0);
    assert_eq!(rtte.timestamp(), Some((first_send, TcpSeqNumber(0))));

    rtte.on_ack(Instant::from_millis(60), TcpSeqNumber(0));
    assert_eq!(rtte.smoothed_rtt(), 50);
    assert_eq!(rtte.timestamp(), None);
    assert_eq!(rtte.max_seq_sent(), Some(TcpSeqNumber(0)));

    let second_send = Instant::from_millis(100);
    rtte.on_send(second_send, TcpSeqNumber(1));
    rtte.on_send(Instant::from_millis(110), TcpSeqNumber(2));
    assert_eq!(rtte.timestamp(), Some((second_send, TcpSeqNumber(1))));
    assert_eq!(rtte.max_seq_sent(), Some(TcpSeqNumber(2)));
    rtte.on_retransmit();
    assert_eq!(rtte.timestamp(), None);
    assert_eq!(rtte.max_seq_sent(), Some(TcpSeqNumber(2)));
    rtte.on_ack(Instant::from_millis(160), TcpSeqNumber(2));
    assert_eq!(rtte.smoothed_rtt(), 50);
    assert_eq!(rtte.timestamp(), None);
    rtte.on_send(Instant::from_millis(170), TcpSeqNumber(2));
    assert_eq!(rtte.timestamp(), None);
    assert_eq!(rtte.max_seq_sent(), Some(TcpSeqNumber(2)));

    let third_send = Instant::from_millis(200);
    rtte.on_send(third_send, TcpSeqNumber(3));
    assert_eq!(rtte.timestamp(), Some((third_send, TcpSeqNumber(3))));
    rtte.on_ack(Instant::from_millis(250), TcpSeqNumber(4));
    assert_eq!(rtte.smoothed_rtt(), 50);
    assert_eq!(rtte.timestamp(), None);

    rtte.on_rto();
    assert_eq!(rtte.smoothed_rtt(), 50);
    rtte.on_rto();
    assert_eq!(rtte.smoothed_rtt(), 50);
    rtte.on_rto();
    assert_eq!(rtte.smoothed_rtt(), 0);
    assert_eq!(rtte.timestamp(), None);
    assert_eq!(rtte.max_seq_sent(), Some(TcpSeqNumber(3)));
}

#[cfg(test)]
#[test]
fn socket_size_matches_main() {
    let main_size = 408;
    let size = core::mem::size_of::<Socket<'static>>();
    assert_eq!(size, main_size);
}

// TODO: TCP should work for all features. For now, we only test with the IP feature. We could do
// it for other features as well with rstest, however, this means we have to modify a lot of the
// tests in here, which I didn't had the time for at the moment.
#[cfg(all(test, feature = "medium-ip"))]
mod test {
    use super::*;
    use crate::config::IFACE_MAX_ADDR_COUNT;
    use crate::wire::{IpCidr, IpRepr, TcpTimestampRepr};
    use std::ops::{Deref, DerefMut};
    use std::vec::Vec;

    #[test]
    fn seq_options_round_trip() {
        let mut s = socket_established();
        for v in [
            None,
            Some(TcpSeqNumber(i32::MIN)),
            Some(TcpSeqNumber(i32::MAX)),
            Some(TcpSeqNumber(0)),
            None,
        ] {
            s.set_local_rx_last_seq(v);
            assert_eq!(s.local_rx_last_seq(), v);
            s.set_local_rx_last_ack(v);
            assert_eq!(s.local_rx_last_ack(), v);
            s.set_recover(v);
            assert_eq!(s.recover(), v);
        }
    }

    #[test]
    fn ack_delay_timer_round_trips() {
        let mut s = socket_established();
        for timer in [
            AckDelayTimer::Idle,
            AckDelayTimer::Immediate,
            AckDelayTimer::Waiting(Instant::ZERO),
            AckDelayTimer::Waiting(Instant::from_micros(i64::MAX)),
        ] {
            s.set_ack_delay_timer(timer);
            assert_eq!(s.ack_delay_timer(), timer);
        }
    }

    #[test]
    fn rx_mbuf_budget_covers_receive_capacity() {
        let budget = |rx_capacity, mss_cap, ip_mtu| {
            rx_mbuf_budget(&Config { rx_capacity, tx_capacity: 0, mss_cap }, ip_mtu)
        };
        assert_eq!(budget(4096, None, 1500), 6);
        assert_eq!(budget(65536, None, 1500), 45);
        assert_eq!(budget(262144, None, 1500), 180);
        assert_eq!(budget(65536, None, 9000), 8);
        assert_eq!(budget(6 * 1460, None, 1500), 6);
        assert_eq!(budget(7 * 1460, None, 1500), 7);
        assert_eq!(budget(7 * 1460 + 1, None, 1500), 8);
        assert_eq!(budget(8 * 8960, None, 9000), 8);
        assert_eq!(budget(6 * 28, None, 68), 6);
        assert_eq!(budget(6 * 28 + 1, None, 68), 7);
        assert_eq!(budget(0, None, 1500), 6);
        assert_eq!(budget(usize::MAX, None, 68), usize::MAX / 28 + 1);
        // The cap sets per-frame bytes only when it is below MTU - 40.
        assert_eq!(budget(65536, Some(1460), 9000), 45);
        assert_eq!(budget(65536, Some(100), 1500), 656);
        assert_eq!(budget(65536, Some(9000), 1500), 45);
    }

    #[test]
    #[should_panic(expected = "IP MTU must be at least 68 bytes")]
    fn rx_mbuf_budget_refuses_ip_mtu_below_ipv4_minimum() {
        rx_mbuf_budget(&Config { rx_capacity: 4096, tx_capacity: 0, mss_cap: None }, 67);
    }

    #[test]
    #[should_panic(expected = "MSS cap must not be zero")]
    fn rx_mbuf_budget_refuses_zero_mss_cap() {
        rx_mbuf_budget(&Config { rx_capacity: 4096, tx_capacity: 0, mss_cap: Some(0) }, 1500);
    }

    #[test]
    fn from_config_matches_config_and_its_budget() {
        let config = Config { rx_capacity: 65536, tx_capacity: 1000, mss_cap: Some(100) };
        let s = Socket::from_config(&config);
        assert_eq!(s.recv_capacity(), 65536);
        assert_eq!(s.send_capacity(), 1000);
        assert_eq!(s.mss_cap, core::num::NonZeroU16::new(100));
        assert_eq!(s.rx_mbuf_budget(1500), rx_mbuf_budget(&config, 1500));
        assert_eq!(s.rx_frame_cap(), 0);
    }

    // =========================================================================================//
    // Constants
    // =========================================================================================//

    const LOCAL_PORT: u16 = 80;
    const REMOTE_PORT: u16 = 49500;
    const LISTEN_END: IpListenEndpoint = IpListenEndpoint {
        addr: None,
        port: LOCAL_PORT,
    };
    const TUPLE: Tuple = Tuple {
        local: LOCAL_END,
        remote: REMOTE_END,
    };
    const LOCAL_SEQ: TcpSeqNumber = TcpSeqNumber(10000);
    const REMOTE_SEQ: TcpSeqNumber = TcpSeqNumber(-10001);

    #[test]
    fn isn_depends_on_secret_and_each_tuple_component() {
        let now = Instant::from_millis(10);
        let secret = [1, 2];
        let first = initial_seq_no(secret, TUPLE, now);
        assert_ne!(first, initial_seq_no([3, 4], TUPLE, now));
        assert_ne!(first, initial_seq_no([1, 3], TUPLE, now));
        for tuple in [
            Tuple {
                local: IpEndpoint {
                    port: LOCAL_PORT + 1,
                    ..TUPLE.local
                },
                ..TUPLE
            },
            Tuple {
                remote: IpEndpoint {
                    port: REMOTE_PORT + 1,
                    ..TUPLE.remote
                },
                ..TUPLE
            },
            Tuple {
                local: IpEndpoint {
                    addr: TUPLE.remote.addr,
                    ..TUPLE.local
                },
                ..TUPLE
            },
            Tuple {
                remote: IpEndpoint {
                    addr: TUPLE.local.addr,
                    ..TUPLE.remote
                },
                ..TUPLE
            },
        ] {
            assert_ne!(first, initial_seq_no(secret, tuple, now));
        }
    }

    #[test]
    fn isn_clock_ticks_every_four_microseconds_and_wraps() {
        let isn = |micros| initial_seq_no([1, 2], TUPLE, Instant::from_micros(micros)).0 as u32;
        assert_eq!(isn(3), isn(0));
        assert_eq!(isn(4).wrapping_sub(isn(0)), 1);
        assert_eq!(isn(1000).wrapping_sub(isn(0)), 250);
        let clock_wrap = (1_i64 << 32) * 4;
        assert_eq!(isn(clock_wrap), isn(0));
        assert_eq!(
            isn(clock_wrap + 500).wrapping_sub(isn(clock_wrap - 500)),
            250
        );
        // Force the final ISN, including its hash offset, across u32::MAX.
        let before_wrap = i64::from(u32::MAX.wrapping_sub(isn(0))) * 4;
        assert_eq!(isn(before_wrap), u32::MAX);
        assert_eq!(isn(before_wrap + 1000), 249);
    }

    use crate::wire::Ipv4Address as IpvXAddress;
    use crate::wire::Ipv4Repr as IpvXRepr;
    use IpRepr::Ipv4 as IpReprIpvX;

    const LOCAL_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 1);
    const REMOTE_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 2);
    const OTHER_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 3);

    const BASE_MSS: u16 = 1460;

    const LOCAL_END: IpEndpoint = IpEndpoint {
        addr: IpAddress::Ipv4(LOCAL_ADDR),
        port: LOCAL_PORT,
    };
    const REMOTE_END: IpEndpoint = IpEndpoint {
        addr: IpAddress::Ipv4(REMOTE_ADDR),
        port: REMOTE_PORT,
    };

    const SEND_IP_TEMPL: IpRepr = IpReprIpvX(IpvXRepr {
        src_addr: LOCAL_ADDR,
        dst_addr: REMOTE_ADDR,
        next_header: IpProtocol::Tcp,
        payload_len: 20,
        hop_limit: 64,
    });
    const SEND_TEMPL: TcpRepr<'static> = TcpRepr {
        src_port: REMOTE_PORT,
        dst_port: LOCAL_PORT,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(0),
        ack_number: Some(TcpSeqNumber(0)),
        window_len: 256,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };
    const _RECV_IP_TEMPL: IpRepr = IpReprIpvX(IpvXRepr {
        src_addr: LOCAL_ADDR,
        dst_addr: REMOTE_ADDR,
        next_header: IpProtocol::Tcp,
        payload_len: 20,
        hop_limit: 64,
    });
    const RECV_TEMPL: TcpRepr<'static> = TcpRepr {
        src_port: LOCAL_PORT,
        dst_port: REMOTE_PORT,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(0),
        ack_number: Some(TcpSeqNumber(0)),
        window_len: 64,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    // =========================================================================================//
    // Helper functions
    // =========================================================================================//

    struct TestSocket {
        socket: Socket<'static>,
        cx: Context,
    }

    impl Deref for TestSocket {
        type Target = Socket<'static>;
        fn deref(&self) -> &Self::Target {
            &self.socket
        }
    }

    impl DerefMut for TestSocket {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.socket
        }
    }

    #[track_caller]
    fn send(
        socket: &mut TestSocket,
        timestamp: Instant,
        repr: &TcpRepr,
    ) -> Option<TcpRepr<'static>> {
        send_frame(
            socket,
            timestamp,
            repr,
            RxBuf::from_vec(repr.payload.to_vec()),
        )
    }

    #[track_caller]
    fn send_frame(
        socket: &mut TestSocket,
        timestamp: Instant,
        repr: &TcpRepr,
        frame: RxBuf,
    ) -> Option<TcpRepr<'static>> {
        socket.cx.set_now(timestamp);

        let ip_repr = IpReprIpvX(IpvXRepr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        });
        net_trace!("send: {}", repr);

        assert!(socket.socket.accepts(&mut socket.cx, &ip_repr, repr));

        let repr = TcpRepr {
            payload: frame.as_slice(),
            ..*repr
        };
        let (reply, pending) = socket.socket.process(&mut socket.cx, &ip_repr, &repr);
        if let Some(pending) = pending {
            socket.socket.commit_rx(frame, pending);
        }
        match reply {
            Some((_ip_repr, repr)) => {
                net_trace!("recv: {}", repr);
                Some(repr)
            }
            None => None,
        }
    }

    #[track_caller]
    fn recv<F>(socket: &mut TestSocket, timestamp: Instant, mut f: F)
    where
        F: FnMut(Result<TcpRepr, ()>),
    {
        socket.cx.set_now(timestamp);

        let mut sent = 0;
        let result = socket
            .socket
            .dispatch(&mut socket.cx, |_, _, (ip_repr, tcp_repr)| {
                assert_eq!(ip_repr.next_header(), IpProtocol::Tcp);
                assert_eq!(ip_repr.src_addr(), LOCAL_ADDR.into());
                assert_eq!(ip_repr.dst_addr(), REMOTE_ADDR.into());
                assert_eq!(ip_repr.payload_len(), tcp_repr.buffer_len());

                net_trace!("recv: {}", tcp_repr);
                sent += 1;
                Ok(f(Ok(tcp_repr)))
            });
        match result {
            Ok(()) => assert_eq!(sent, 1, "Exactly one packet should be sent"),
            Err(e) => f(Err(e)),
        }
    }

    #[track_caller]
    fn recv_nothing(socket: &mut TestSocket, timestamp: Instant) {
        socket.cx.set_now(timestamp);

        let mut fail = false;
        let result: Result<(), ()> = socket.socket.dispatch(&mut socket.cx, |_, _, _| {
            fail = true;
            Ok(())
        });
        if fail {
            panic!("Should not send a packet")
        }

        assert_eq!(result, Ok(()))
    }

    #[collapse_debuginfo(yes)]
    macro_rules! send {
        ($socket:ident, $repr:expr) =>
            (send!($socket, time 0, $repr));
        ($socket:ident, $repr:expr, $result:expr) =>
            (send!($socket, time 0, $repr, $result));
        ($socket:ident, time $time:expr, $repr:expr) =>
            (send!($socket, time $time, $repr, None));
        ($socket:ident, time $time:expr, $repr:expr, $result:expr) =>
            (assert_eq!(send(&mut $socket, Instant::from_millis($time), &$repr), $result));
    }

    #[collapse_debuginfo(yes)]
    macro_rules! recv {
        ($socket:ident, [$( $repr:expr ),*]) => ({
            $( recv!($socket, Ok($repr)); )*
            recv_nothing!($socket)
        });
        ($socket:ident, time $time:expr, [$( $repr:expr ),*]) => ({
            $( recv!($socket, time $time, Ok($repr)); )*
            recv_nothing!($socket, time $time)
        });
        ($socket:ident, $result:expr) =>
            (recv!($socket, time 0, $result));
        ($socket:ident, time $time:expr, $result:expr) =>
            (recv(&mut $socket, Instant::from_millis($time), |result| {
                // Most of the time we don't care about the PSH flag.
                let result = result.map(|mut repr| {
                    repr.control = repr.control.quash_psh();
                    repr
                });
                assert_eq!(result, $result)
            }));
        ($socket:ident, time $time:expr, $result:expr, exact) =>
            (recv(&mut $socket, Instant::from_millis($time), |repr| assert_eq!(repr, $result)));
    }

    #[collapse_debuginfo(yes)]
    macro_rules! recv_nothing {
        ($socket:ident) => (recv_nothing!($socket, time 0));
        ($socket:ident, time $time:expr) => (recv_nothing(&mut $socket, Instant::from_millis($time)));
    }

    #[collapse_debuginfo(yes)]
    macro_rules! sanity {
        ($socket1:expr, $socket2:expr) => {{
            let (s1, s2) = ($socket1, $socket2);
            assert_eq!(s1.state, s2.state, "state");
            assert_eq!(s1.tuple, s2.tuple, "tuple");
            assert_eq!(s1.local_seq_no, s2.local_seq_no, "local_seq_no");
            assert_eq!(s1.remote_seq_no, s2.remote_seq_no, "remote_seq_no");
            assert_eq!(s1.remote_last_seq, s2.remote_last_seq, "remote_last_seq");
            assert_eq!(s1.remote_max_seq, s2.remote_max_seq, "remote_max_seq");
            assert_eq!(s1.remote_last_ack, s2.remote_last_ack, "remote_last_ack");
            assert_eq!(s1.remote_last_ack_is_marker, s2.remote_last_ack_is_marker,
                       "remote_last_ack_is_marker");
            assert_eq!(s1.remote_last_win_bytes, s2.remote_last_win_bytes, "remote_last_win_bytes");
            assert_eq!(s1.remote_win_len, s2.remote_win_len, "remote_win_len");
            assert_eq!(s1.timer, s2.timer, "timer");
        }};
    }

    fn drain_bytes(socket: &mut Socket) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            match socket.recv() {
                Ok(Some(frame)) => bytes.extend_from_slice(frame.payload()),
                Ok(None) | Err(RecvError::Finished) => return bytes,
                Err(error) => panic!("receive failed: {error}"),
            }
        }
    }

    fn drain_frames(socket: &mut Socket, count: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for _ in 0..count {
            let frame = socket.recv().unwrap().expect("missing in-order frame");
            bytes.extend_from_slice(frame.payload());
        }
        bytes
    }

    fn socket() -> TestSocket {
        socket_with_buffer_sizes(64, 64)
    }

    fn socket_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let (iface, _, _) = crate::tests::setup(crate::phy::Medium::Ip);

        let rx_buffer = RxBuffer::new(rx_len);
        let tx_buffer = SocketBuffer::new(vec![0; tx_len]);
        let mut socket = Socket::new(rx_buffer, tx_buffer);
        socket.set_ack_delay(None);
        TestSocket {
            socket,
            cx: iface.inner,
        }
    }

    fn receive_window_socket(ip_mtu: usize, capacity: usize) -> TestSocket {
        use crate::phy::{Device, DeviceCapabilities};

        struct MtuDevice(crate::tests::TestingDevice, usize);
        impl Device for MtuDevice {
            type RxToken<'a> = crate::tests::RxToken;
            type TxToken<'a> = crate::tests::TxToken<'a>;

            fn capabilities(&self) -> DeviceCapabilities {
                DeviceCapabilities {
                    max_transmission_unit: self.1,
                    ..self.0.capabilities()
                }
            }

            fn receive(&mut self, now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
                self.0.receive(now)
            }

            fn transmit(&mut self, now: Instant) -> Option<Self::TxToken<'_>> {
                self.0.transmit(now)
            }
        }

        let mut device = MtuDevice(crate::tests::TestingDevice::new(crate::phy::Medium::Ip), ip_mtu);
        let mut iface = crate::iface::Interface::new(
            crate::iface::Config::new(crate::wire::HardwareAddress::Ip),
            &mut device,
            Instant::ZERO,
        );
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(LOCAL_ADDR.into(), 24)).unwrap();
        });
        let mut s = socket_with_buffer_sizes(64, capacity);
        s.cx = iface.inner;
        s.set_rx_mbuf_budget(ip_mtu);
        s
    }

    fn open_receive_window(mut s: &mut TestSocket, active: bool, peer_mss: Option<u16>) -> u16 {
        if active {
            s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
            recv(s, Instant::ZERO, |result| {
                assert_eq!(result.unwrap().control, TcpControl::Syn);
            });
        } else {
            s.listen(LISTEN_END).unwrap();
        }
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: active.then_some(LOCAL_SEQ + 1),
            max_seg_size: peer_mss,
            window_scale: Some(1),
            ..SEND_TEMPL
        });
        let mut window = None;
        recv(s, Instant::ZERO, |result| {
            let reply = result.unwrap();
            assert_eq!(reply.ack_number, Some(REMOTE_SEQ + 1));
            assert_eq!(reply.control, if active { TcpControl::None } else { TcpControl::Syn });
            window = Some(reply.window_len);
        });
        if !active {
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            });
        }
        assert_eq!(s.state(), State::Established);
        window.unwrap()
    }

    #[test]
    fn peer_mss_48_preserves_unscaled_handshake_right_edge() {
        for active in [false, true] {
            let mut s = receive_window_socket(9000, 65536);
            let window = open_receive_window(&mut s, active, Some(48));
            assert_eq!(s.rx_mbuf_cap, 8);
            assert_eq!(s.remote_win_shift, 1);
            assert_eq!(window, if active { 192 } else { 384 });
            let ack = receive_window_segment(&mut s, 0, b"a");
            assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 2));
            assert_eq!(ack.window_len, 192);
            assert_eq!(ack.ack_number.unwrap() + (usize::from(ack.window_len) << 1),
                REMOTE_SEQ + 1 + 385);
            assert_eq!(s.rx_seg_bytes, 48);
            assert_eq!(s.rx_refused_segments(), 0);
        }
    }

    #[test]
    fn active_syn_window_is_bounded_before_peer_mss_is_known() {
        let mut s = receive_window_socket(9000, 65536);
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        recv(&mut s, Instant::ZERO, |result| {
            let syn = result.unwrap();
            assert_eq!(syn.window_len, 384);
            assert_eq!(syn.max_seg_size, Some(8960));
        });
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1),
            max_seg_size: Some(48),
            window_scale: Some(1),
            ..SEND_TEMPL
        });
        assert!(s.remote_last_ack_is_marker);
        // The peer SYN sequence is not an ACK we sent, so it cannot preserve the SYN window.
        assert_eq!(s.last_scaled_window(), None);
        recv(&mut s, Instant::ZERO, |result| {
            assert_eq!(result.unwrap().window_len, 192);
        });
        assert!(!s.remote_last_ack_is_marker);
    }

    #[test]
    fn jumbo_receive_window_uses_peer_mss_at_every_ack() {
        for active in [false, true] {
            let mut s = receive_window_socket(9000, 32768);
            let window = open_receive_window(&mut s, active, Some(1460));
            assert_eq!(window, 6 * 1460);
            for index in 0..6 {
                let ack = receive_window_segment(&mut s, index * 1460, &[0; 1460]);
                let available = (6 - s.rx_buffer.store.held()) * 1460;
                assert_eq!(usize::from(ack.window_len), available);
                assert_eq!(s.rx_seg_bytes, 1460);
                assert_eq!(s.rx_mbuf_cap, 6);
                assert_eq!(s.rx_refused_segments(), 0);
            }
        }
    }

    #[test]
    fn out_of_order_receive_window_excludes_reserved_frame() {
        for active in [false, true] {
            let mut s = receive_window_socket(9000, 32768);
            assert_eq!(open_receive_window(&mut s, active, Some(1460)), 8760);
            assert_eq!(s.rx_mbuf_cap, 6);
            assert_eq!(s.rx_seg_bytes, 1460);
            let payload = [0xa5; 1460];
            for index in 1..=5 {
                let offset = index * payload.len();
                assert!(offset + payload.len() <= s.remote_last_win_bytes as usize);
                let ack = receive_window_segment(&mut s, offset, &payload);
                assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1));
                assert_eq!(s.rx_buffer.store.held(), index);
                assert_eq!(s.rx_buffer.store.out_of_order_len(), index * 1460);
                // The span includes the 1460-byte hole; the reserve adds no room past it.
                assert_eq!(s.recv_room(), 8760);
                assert_eq!(s.scaled_window_with_last(None), 8760);
                assert_eq!(ack.window_len, 8760);
                assert_eq!(s.rx_refused_segments(), 0);
                let duplicate = receive_window_segment(&mut s, offset, &payload);
                assert_eq!(duplicate.ack_number, ack.ack_number);
                assert_eq!(duplicate.window_len, ack.window_len);
                assert_eq!(s.rx_buffer.store.held(), index);
                assert_eq!(s.rx_refused_segments(), 0);
            }
            let ack = receive_window_segment(&mut s, 8760, &[0x5a; 648]);
            assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1));
            assert_eq!(ack.window_len, 8760);
            assert_eq!(s.rx_buffer.store.held(), 5);
            assert_eq!(s.rx_refused_segments(), 0);

            let ack = receive_window_segment(&mut s, 0, &payload);
            assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1 + 8760));
            assert_eq!(ack.window_len, 0);
            assert_eq!(s.rx_buffer.store.held(), 6);
            assert_eq!(s.rx_buffer.store.out_of_order_len(), 0);
            assert_eq!(s.rx_refused_segments(), 0);
            let output = drain_bytes(&mut s);
            assert_eq!(output.len(), 8760);
            assert_eq!(output, [0xa5; 8760]);
            assert_eq!(s.recv_room(), 8760);
        }
    }

    #[test]
    fn out_of_order_receive_window_reaches_last_view_plus_free_frames() {
        for active in [false, true] {
            let mut s = receive_window_socket(9000, 32768);
            assert_eq!(open_receive_window(&mut s, active, Some(1460)), 8760);
            let payload = [0xa5; 1460];
            receive_window_segment(&mut s, 0, &payload);
            let prefix = drain_bytes(&mut s);
            assert_eq!(prefix.len(), 1460);
            assert_eq!(prefix, payload);
            for index in 2..=3 {
                let ack = receive_window_segment(&mut s, index * 1460, &payload);
                assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1 + 1460));
                assert_eq!(s.rx_buffer.store.held(), index - 1);
            }
            // RCV.NXT is 1460, the last view ends at 5840, and three free frames
            // remain beyond the reserve: (5840 - 1460) + 3 * 1460 = 8760.
            assert_eq!(s.recv_room(), 8760);
            assert_eq!(s.remote_last_ack.unwrap() + s.remote_last_win_bytes as usize,
                REMOTE_SEQ + 1 + 10220);
            for index in 4..=6 {
                let offset = index * 1460;
                assert!(REMOTE_SEQ + 1 + offset + payload.len()
                    <= s.remote_last_ack.unwrap() + s.remote_last_win_bytes as usize);
                let ack = receive_window_segment(&mut s, offset, &payload);
                assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1 + 1460));
                assert_eq!(ack.window_len, 8760);
                assert_eq!(s.rx_refused_segments(), 0);
            }
            assert_eq!(s.rx_buffer.store.held(), 5);
            let ack = receive_window_segment(&mut s, 1460, &payload);
            assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1 + 10220));
            assert_eq!(ack.window_len, 0);
            assert_eq!(s.rx_buffer.store.held(), 6);
            assert_eq!(s.rx_refused_segments(), 0);
            let output = drain_bytes(&mut s);
            assert_eq!(output.len(), 8760);
            assert_eq!(output, [0xa5; 8760]);
            assert_eq!(s.recv_room(), 8760);
        }
    }

    #[test]
    fn multi_hole_receive_window_keeps_both_hole_frames() {
        for active in [false, true] {
            let mut s = receive_window_socket(9000, 32768);
            assert_eq!(open_receive_window(&mut s, active, Some(1460)), 8760);
            let payload = [0xa5; 1460];
            for index in [1, 3, 4, 5] {
                let ack = receive_window_segment(&mut s, index * 1460, &payload);
                assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1));
                assert_eq!(s.recv_room(), 8760);
                assert_eq!(ack.window_len, 8760);
                assert_eq!(s.rx_refused_segments(), 0);
            }
            assert_eq!(s.rx_buffer.store.held(), 4);
            // Segment 6 starts at the right edge, leaving frames for holes 0 and 2.
            let ack = receive_window_segment(&mut s, 6 * 1460, &payload);
            assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1));
            assert_eq!(ack.window_len, 8760);
            assert_eq!(s.rx_buffer.store.held(), 4);
            assert_eq!(s.rx_refused_segments(), 0);

            // Fill the later hole first while the front frame remains reserved.
            let ack = receive_window_segment(&mut s, 2 * 1460, &payload);
            assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1));
            assert_eq!(ack.window_len, 8760);
            assert_eq!(s.rx_buffer.store.held(), 5);
            assert_eq!(s.rx_refused_segments(), 0);
            let ack = receive_window_segment(&mut s, 0, &payload);
            assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1 + 8760));
            assert_eq!(ack.window_len, 0);
            assert_eq!(s.rx_buffer.store.held(), 6);
            assert_eq!(s.rx_refused_segments(), 0);
            let output = drain_bytes(&mut s);
            assert_eq!(output.len(), 8760);
            assert_eq!(output, [0xa5; 8760]);
            assert_eq!(s.recv_room(), 8760);
            recv(&mut s, Instant::ZERO, |result| {
                let ack = result.unwrap();
                assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1 + 8760));
                assert_eq!(ack.window_len, 8760);
            });
            let ack = receive_window_segment(&mut s, 6 * 1460, &payload);
            assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1 + 10220));
            assert_eq!(s.recv_queue(), 1460);
            assert_eq!(s.rx_refused_segments(), 0);
        }
    }

    #[test]
    fn two_segment_hole_window_stores_every_in_window_segment() {
        // Six frames of 1460 bytes; the app holds nothing. Segments 0 and 1 are lost.
        let mut s = receive_window_socket(9000, 32768);
        assert_eq!(open_receive_window(&mut s, true, Some(1460)), 8760);
        let payload = [0xa5; 1460];
        let edge = |s: &TestSocket| s.remote_last_ack.unwrap() + s.remote_last_win_bytes as usize;
        for index in [2, 3, 4, 5, 0, 1] {
            // A one-frame-per-gap charge grew the right edge to segment 7 (byte 10220).
            assert_eq!(edge(&s), REMOTE_SEQ + 1 + 8760, "before segment {index}");
            receive_window_segment(&mut s, index * 1460, &payload);
            assert_eq!(s.rx_buffer.shared.held.get(), 0);
            assert_eq!(
                s.rx_refused_segments(), 0,
                "full-size segment {index} inside the advertised window was refused \
                 (store holds {} of {} frames)",
                s.rx_buffer.store.held(), s.rx_mbuf_cap,
            );
        }
        assert_eq!(s.recv_queue(), 8760);
    }

    #[test]
    fn gap_of_k_segments_costs_k_frames_and_one_more_byte_costs_another() {
        // Six frames of 1460 bytes; one out-of-order segment after a gap.
        for (gap, window) in [(2 * 1460, 8760), (2 * 1460 + 1, 5 * 1460 + 1)] {
            let mut s = receive_window_socket(9000, 32768);
            assert_eq!(open_receive_window(&mut s, true, Some(1460)), 8760);
            receive_window_segment(&mut s, gap, &[0xa5; 1460]);
            assert_eq!(s.rx_buffer.store.out_of_order_hole_frames(1460), gap.div_ceil(1460));
            assert_eq!(s.recv_window(), window, "gap {gap}");
        }
    }

    #[test]
    fn out_of_order_receive_window_includes_812_byte_hole() {
        let mut s = receive_window_socket(9000, 32768);
        assert_eq!(open_receive_window(&mut s, true, Some(1460)), 8760);
        receive_window_segment(&mut s, 0, &[0xa5; 648]);
        let prefix = drain_bytes(&mut s);
        assert_eq!(prefix.len(), 648);
        assert_eq!(prefix, [0xa5; 648]);
        for index in 1..=5 {
            let ack = receive_window_segment(&mut s, index * 1460, &[0xa5; 1460]);
            assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1 + 648));
            // The span is 812 + index * 1460, with (5 - index) free frames
            // beyond the reserve: 812 + 5 * 1460 = 8112.
            assert_eq!(s.recv_room(), 8112);
            assert_eq!(ack.window_len, 8112);
            assert_eq!(s.rx_buffer.store.held(), index);
            assert_eq!(s.rx_refused_segments(), 0);
        }
        let ack = receive_window_segment(&mut s, 8760, &[0x5a; 648]);
        assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1 + 648));
        assert_eq!(ack.window_len, 8112);
        assert_eq!(s.rx_buffer.store.held(), 5);
        assert_eq!(s.rx_refused_segments(), 0);
        let ack = receive_window_segment(&mut s, 648, &[0xa5; 812]);
        assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1 + 8760));
        assert_eq!(ack.window_len, 0);
        assert_eq!(s.rx_refused_segments(), 0);
        let output = drain_bytes(&mut s);
        assert_eq!(output.len(), 8112);
        assert_eq!(output, [0xa5; 8112]);
        assert_eq!(s.recv_room(), 8760);
    }

    #[test]
    fn out_of_order_receive_window_with_no_free_frames() {
        let mut s = receive_window_socket(9000, 32768);
        assert_eq!(open_receive_window(&mut s, true, Some(1460)), 8760);
        for index in 1..=5 {
            receive_window_segment(&mut s, index * 1460, &[0xa5; 1460]);
        }
        let ack = receive_window_segment(&mut s, 0, &[0xa5; 812]);
        assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1 + 812));
        assert_eq!(ack.window_len, 7948);
        assert_eq!(s.rx_buffer.store.held(), 6);
        assert_eq!(s.rx_buffer.store.out_of_order_len(), 7300);
        // The last view ends 648 + 7300 bytes beyond RCV.NXT; no free frame adds room.
        assert_eq!(s.recv_room(), 7948);
        assert_eq!(s.rx_refused_segments(), 0);
        let prefix = drain_bytes(&mut s);
        assert_eq!(prefix.len(), 812);
        assert_eq!(prefix, [0xa5; 812]);
        assert_eq!(s.rx_buffer.store.held(), 5);
        assert_eq!(s.recv_room(), 7948);
        let ack = receive_window_segment(&mut s, 812, &[0xa5; 648]);
        assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1 + 8760));
        assert_eq!(ack.window_len, 0);
        assert_eq!(s.rx_refused_segments(), 0);
        let output = drain_bytes(&mut s);
        assert_eq!(output.len(), 7948);
        assert_eq!(output, [0xa5; 7948]);
        assert_eq!(s.recv_room(), 8760);
    }

    #[test]
    fn receive_window_without_hole_keeps_all_free_frames() {
        for active in [false, true] {
            let mut s = receive_window_socket(9000, 32768);
            assert_eq!(open_receive_window(&mut s, active, Some(1460)), 8760);
            assert_eq!(s.recv_room(), 8760);
            for index in 0..6 {
                let ack = receive_window_segment(&mut s, index * 1460, &[0; 1460]);
                let available = (5 - index) * 1460;
                assert_eq!(s.rx_buffer.store.out_of_order_len(), 0);
                assert_eq!(s.recv_room(), available);
                assert_eq!(usize::from(ack.window_len), available);
                assert_eq!(s.rx_refused_segments(), 0);
            }
            assert_eq!(drain_bytes(&mut s), vec![0; 8760]);
            assert_eq!(s.recv_room(), 8760);
        }
    }

    #[test]
    fn peer_mss_above_ours_keeps_known_peer_window_numbers() {
        for active in [false, true] {
            let mut s = receive_window_socket(1500, 4096);
            assert_eq!(open_receive_window(&mut s, active, Some(9000)), 4096);
            assert_eq!(s.rx_seg_bytes, u32::from(BASE_MSS));
            let ack = receive_window_segment(&mut s, 0, &[0; 1460]);
            assert_eq!(ack.window_len, 4096);
            assert_eq!(s.rx_refused_segments(), 0);
        }
    }

    #[test]
    fn missing_or_zero_peer_mss_receive_window_survives_reconnect() {
        for active in [false, true] {
            let mut s = receive_window_socket(9000, 32768);
            for peer_mss in [Some(48), None, Some(0), Some(1460)] {
                let bytes = match peer_mss {
                    Some(48) => 48,
                    Some(1460) => 1460,
                    _ => 536,
                };
                assert_eq!(usize::from(open_receive_window(&mut s, active, peer_mss)), 6 * bytes);
                assert_eq!(s.rx_seg_bytes as usize, bytes);
                let ack = receive_window_segment(&mut s, 0, &vec![0; bytes]);
                assert_eq!(usize::from(ack.window_len), 5 * bytes);
                assert_eq!(s.rx_mbuf_cap, 6);
                assert_eq!(s.rx_refused_segments(), 0);
                s.abort();
                recv(&mut s, Instant::ZERO, |result| {
                    assert_eq!(result.unwrap().control, TcpControl::Rst);
                });
            }
        }
    }

    fn connect_with_mss_cap(s: &mut TestSocket, advertised_mss: u16, peer_mss: u16) {
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        recv(s, Instant::ZERO, |result| {
            let syn = result.unwrap();
            assert_eq!(syn.control, TcpControl::Syn);
            assert_eq!(syn.ack_number, None);
            assert_eq!(syn.max_seg_size, Some(advertised_mss));
        });
        assert_eq!(
            send(s, Instant::ZERO, &TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(peer_mss),
                window_len: 4096,
                ..SEND_TEMPL
            }),
            None
        );
        recv(s, Instant::ZERO, |result| {
            let ack = result.unwrap();
            assert_eq!(ack.control, TcpControl::None);
            assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1));
            assert!(ack.payload.is_empty());
        });
        assert_eq!(s.state(), State::Established);
    }

    #[test]
    fn capped_receive_window_tracks_available_frames() {
        for (cap, frames, bytes) in [(Some(512), 8, 512), (None, 6, 1460)] {
            let mut s = socket_with_buffer_sizes(4096, 4096);
            s.set_mss_cap(cap);
            let mss = cap.unwrap_or(BASE_MSS);
            connect_with_mss_cap(&mut s, mss, BASE_MSS);
            let payload = vec![0xa5; mss as usize];
            for index in 0..2 {
                send!(s, TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + index * payload.len(),
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &payload,
                    ..SEND_TEMPL
                });
                recv(&mut s, Instant::ZERO, |result| {
                    let ack = result.unwrap();
                    assert_eq!(ack.window_len as usize, 4096usize
                        .min((frames - index - 1) * bytes));
                });
            }
            assert_eq!(s.rx_mbuf_cap as usize, frames);
            assert_eq!(s.rx_seg_bytes as usize, bytes);
            assert_eq!(s.rx_buffer.store.held(), 2);
        }
    }

    #[test]
    fn capped_receive_allowance_is_known_at_handshake() {
        for active in [true, false] {
            let mut s = socket_with_buffer_sizes(4096, 4096);
            s.set_mss_cap(Some(512));
            if active {
                s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
            } else {
                s.listen(LISTEN_END).unwrap();
                send!(s, TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: REMOTE_SEQ,
                    ack_number: None,
                    max_seg_size: Some(BASE_MSS),
                    ..SEND_TEMPL
                });
            }
            recv(&mut s, Instant::ZERO, |result| {
                let syn = result.unwrap();
                assert_eq!(syn.control, TcpControl::Syn);
                assert_eq!(syn.max_seg_size, Some(512));
                // Active SYN: 8 frames x 48 B; passive SYN-ACK: 8 x 512 B.
                assert_eq!(syn.window_len, if active { 384 } else { 4096 });
            });
            assert_eq!(s.rx_mbuf_cap, 8);
            assert_eq!(s.rx_seg_bytes, 512);
        }
    }

    #[test]
    fn receive_mbuf_budget_uses_configured_mss_cap_at_jumbo_mtu() {
        let mut s = socket_with_buffer_sizes(4096, 32768);
        assert_eq!(s.rx_mbuf_budget(9000), 6);
        s.set_mss_cap(Some(1460));
        assert_eq!(s.rx_mbuf_budget(9000), 23);
        assert_eq!(s.rx_mbuf_budget(1500), 23);
        s.set_mss_cap(Some(9000));
        assert_eq!(s.rx_mbuf_budget(9000), 6);
    }

    #[test]
    fn standalone_receive_frame_count_fixed_at_first_handshake() {
        let mut s = socket_with_buffer_sizes(4096, 4096);
        for (cap, frames, bytes) in [(Some(512), 8, 512), (Some(256), 8, 256), (None, 8, 1460)] {
            s.set_mss_cap(cap);
            connect_with_mss_cap(&mut s, cap.unwrap_or(BASE_MSS), BASE_MSS);
            assert_eq!(s.rx_mbuf_cap, frames);
            assert_eq!(s.rx_seg_bytes, bytes);
            assert_eq!(s.recv_room(), 4096.min(8 * bytes as usize));
            s.abort();
            recv(&mut s, Instant::ZERO, |result| {
                assert_eq!(result.unwrap().control, TcpControl::Rst);
            });
        }
    }

    #[test]
    fn recv_frames_carry_arrival_timestamps_in_order() {
        let mut s = socket_established_with_buffer_sizes(64, 4096);
        for (offset, payload, stamp) in [(3, b"def", 1), (6, b"ghi", 0), (0, b"abc", 3)] {
            let mut frame = RxBuf::from_vec(payload.to_vec());
            frame.set_rx_timestamp(stamp);
            send_frame(
                &mut s,
                Instant::ZERO,
                &TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload,
                    ..SEND_TEMPL
                },
                frame,
            );
        }
        let mut received = Vec::new();
        while let Some(frame) = s.recv().unwrap() {
            received.push((frame.payload().to_vec(), frame.rx_timestamp()));
        }
        assert_eq!(
            received,
            vec![
                (b"abc".to_vec(), 3),
                (b"def".to_vec(), 1),
                (b"ghi".to_vec(), 0)
            ]
        );
        assert_eq!(s.recv_queue(), 0);
    }

    #[test]
    #[should_panic(expected = "socket admitted while the app still holds its received frames")]
    fn admission_with_app_held_frame_panics() {
        let mut s = socket_established();
        receive_window_segment(&mut s, 0, b"abc");
        let _frame = s.recv().unwrap().unwrap();
        s.abort();
        s.set_rx_mbuf_budget(1500);
    }

    #[test]
    fn admission_after_received_frame_dropped() {
        let mut s = socket_established();
        receive_window_segment(&mut s, 0, b"abc");
        let frame = s.recv().unwrap().unwrap();
        assert_eq!(s.rx_buffer.shared.held.get(), 1);
        drop(frame);
        s.abort();
        s.set_rx_mbuf_budget(1500);
        assert_eq!(s.rx_buffer.shared.held.get(), 0);
        assert_eq!(s.rx_frame_cap(), s.rx_mbuf_budget(1500));
        assert_eq!(s.recv_room(), s.recv_capacity());
    }

    #[test]
    fn recv_room_zero_until_accepted_syn() {
        let mut s = socket();
        assert_eq!(s.rx_frame_cap(), 0);
        assert_eq!(s.recv_room(), 0);
        s.listen(LISTEN_END).unwrap();
        assert_eq!(s.rx_frame_cap(), 0);
        assert_eq!(s.recv_room(), 0);
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::SynReceived);
        let room = s.recv_room();
        assert!(room > 0);
        recv(&mut s, Instant::ZERO, |result| {
            let syn_ack = result.unwrap();
            assert_eq!(syn_ack.control, TcpControl::Syn);
            assert_eq!(syn_ack.ack_number, Some(REMOTE_SEQ + 1));
            assert_eq!(usize::from(syn_ack.window_len), room);
        });
        assert_eq!(s.recv_room(), room);
    }

    #[test]
    fn closed_socket_cap_lowered_after_admission_keeps_rx_frame_count() {
        let mut s = socket_with_buffer_sizes(64, 4096);
        assert_eq!(s.state(), State::Closed);
        s.set_mss_cap(Some(100));
        let budget = s.rx_mbuf_budget(1500);
        s.set_rx_mbuf_budget(1500);
        s.set_mss_cap(Some(64));
        assert_eq!(s.rx_mbuf_cap as usize, budget);
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        assert_eq!(s.state(), State::SynSent);
        assert_eq!(s.rx_frame_cap(), budget);
    }

    #[test]
    fn cap_lowered_after_admission_keeps_frame_count_across_connections() {
        for active in [true, false] {
            let mut s = socket_with_buffer_sizes(4096, 4096);
            assert_eq!(s.rx_mbuf_budget(1500), 6);
            s.set_rx_mbuf_budget(1500);
            for cap in [512, 256] {
                s.set_mss_cap(Some(cap));
                if active {
                    s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
                } else {
                    s.listen(LISTEN_END).unwrap();
                    send!(s, TcpRepr {
                        control: TcpControl::Syn,
                        seq_number: REMOTE_SEQ,
                        ack_number: None,
                        max_seg_size: Some(BASE_MSS),
                        ..SEND_TEMPL
                    });
                }
                s.set_mss_cap(Some(128));
                recv(&mut s, Instant::ZERO, |result| {
                    let syn = result.unwrap();
                    assert_eq!(syn.control, TcpControl::Syn);
                    assert_eq!(syn.max_seg_size, Some(cap));
                    // Active SYN: 6 frames x 48 B; passive SYN-ACK: 6 x cap.
                    assert_eq!(syn.window_len, if active { 288 } else { 6 * cap });
                });
                if active {
                    send!(s, TcpRepr {
                        control: TcpControl::Syn,
                        seq_number: REMOTE_SEQ,
                        ack_number: Some(LOCAL_SEQ + 1),
                        max_seg_size: Some(BASE_MSS),
                        ..SEND_TEMPL
                    });
                    recv(&mut s, Instant::ZERO, |result| {
                        assert_eq!(result.unwrap().window_len, 6 * cap);
                    });
                } else {
                    send!(s, TcpRepr {
                        seq_number: REMOTE_SEQ + 1,
                        ack_number: Some(LOCAL_SEQ + 1),
                        ..SEND_TEMPL
                    });
                }
                let payload = vec![0xa5; cap as usize];
                send!(s, TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &payload,
                    ..SEND_TEMPL
                });
                recv(&mut s, Instant::ZERO, |result| {
                    assert_eq!(result.unwrap().window_len, 5 * cap);
                });
                assert_eq!(s.rx_mbuf_cap, 6);
                assert_eq!(s.rx_seg_bytes, u32::from(cap));
                assert_eq!(s.rx_buffer.store.held(), 1);
                s.abort();
                recv(&mut s, Instant::ZERO, |result| {
                    assert_eq!(result.unwrap().control, TcpControl::Rst);
                });
            }
        }
    }

    #[test]
    fn closed_and_listening_readmission_uses_configured_cap() {
        for listening in [true, false] {
            let mut s = socket_with_buffer_sizes(4096, 4096);
            s.set_mss_cap(Some(512));
            s.set_rx_mbuf_budget(1500);
            if listening {
                s.listen(LISTEN_END).unwrap();
            }
            for (cap, frames, bytes) in [(Some(256), 16, 256), (None, 6, 1460)] {
                s.set_mss_cap(cap);
                assert_eq!(s.rx_mbuf_budget(1500), frames);
                s.set_rx_mbuf_budget(1500);
                assert_eq!(s.rx_mbuf_cap as usize, frames);
                assert_eq!(s.rx_seg_bytes, bytes);
            }
        }
    }

    fn send_mss_cap_payload(s: &mut TestSocket, mss: usize) {
        let data = vec![0xa5; mss * 2];
        assert_eq!(s.send_slice(&data), Ok(data.len()));
        for offset in [0, mss] {
            recv(s, Instant::ZERO, |result| {
                let segment = result.unwrap();
                assert_eq!(segment.seq_number, LOCAL_SEQ + 1 + offset);
                assert_eq!(segment.payload, &data[offset..offset + mss]);
            });
        }
        recv_nothing(s, Instant::ZERO);
    }

    #[test]
    fn connect_mss_cap_limits_syn_and_payload() {
        let mut s = socket_with_buffer_sizes(4096, 4096);
        s.set_mss_cap(Some(512));
        connect_with_mss_cap(&mut s, 512, BASE_MSS);
        send_mss_cap_payload(&mut s, 512);
    }

    #[test]
    fn peer_mss_below_cap_still_wins() {
        let mut s = socket_with_buffer_sizes(4096, 4096);
        s.set_mss_cap(Some(512));
        connect_with_mss_cap(&mut s, 512, 256);
        send_mss_cap_payload(&mut s, 256);
    }

    #[test]
    fn local_mtu_below_cap_still_wins() {
        let mut s = socket_with_buffer_sizes(4096, 4096);
        s.set_mss_cap(Some(9000));
        connect_with_mss_cap(&mut s, BASE_MSS, 9000);
        send_mss_cap_payload(&mut s, BASE_MSS as usize);
    }

    #[test]
    fn mss_cap_applies_to_listen() {
        let mut s = socket_with_buffer_sizes(4096, 4096);
        s.set_mss_cap(Some(512));
        s.listen(LISTEN_END).unwrap();
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_len: 4096,
            ..SEND_TEMPL
        });
        recv(&mut s, Instant::ZERO, |result| {
            let syn_ack = result.unwrap();
            assert_eq!(syn_ack.control, TcpControl::Syn);
            assert_eq!(syn_ack.ack_number, Some(REMOTE_SEQ + 1));
            assert_eq!(syn_ack.max_seg_size, Some(512));
        });
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 4096,
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::Established);
        send_mss_cap_payload(&mut s, 512);
        recv(&mut s, Instant::from_millis(300), |result| {
            assert_eq!(result.unwrap().payload, &[0xa5; 512]);
        });
        assert_eq!(s.congestion_controller.window(), 512);
    }

    #[test]
    fn mss_cap_set_after_listen_applies_to_accepted_connection() {
        let mut s = socket_with_buffer_sizes(4096, 4096);
        s.listen(LISTEN_END).unwrap();
        s.set_mss_cap(Some(512));
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_len: 4096,
            ..SEND_TEMPL
        });
        s.set_mss_cap(Some(256));
        recv(&mut s, Instant::ZERO, |result| {
            let syn_ack = result.unwrap();
            assert_eq!(syn_ack.control, TcpControl::Syn);
            assert_eq!(syn_ack.ack_number, Some(REMOTE_SEQ + 1));
            assert_eq!(syn_ack.max_seg_size, Some(512));
        });
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 4096,
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::Established);
        send_mss_cap_payload(&mut s, 512);
        recv(&mut s, Instant::from_millis(300), |result| {
            assert_eq!(result.unwrap().payload, &[0xa5; 512]);
        });
        assert_eq!(s.congestion_controller.window(), 512);
    }

    #[test]
    fn mss_cap_persists_across_reconnect() {
        let mut s = socket_with_buffer_sizes(4096, 4096);
        s.set_mss_cap(Some(512));
        for _ in 0..2 {
            connect_with_mss_cap(&mut s, 512, BASE_MSS);
            send_mss_cap_payload(&mut s, 512);
            s.abort();
        }
    }

    #[test]
    fn mss_cap_change_applies_to_next_connection() {
        let mut s = socket_with_buffer_sizes(4096, 4096);
        s.set_mss_cap(Some(512));
        connect_with_mss_cap(&mut s, 512, BASE_MSS);
        s.set_mss_cap(Some(256));
        send_mss_cap_payload(&mut s, 512);
        s.abort();
        connect_with_mss_cap(&mut s, 256, BASE_MSS);
        s.set_mss_cap(None);
        send_mss_cap_payload(&mut s, 256);
        s.abort();
        connect_with_mss_cap(&mut s, BASE_MSS, BASE_MSS);
        send_mss_cap_payload(&mut s, BASE_MSS as usize);
    }

    #[test]
    #[should_panic(expected = "MSS cap must not be zero")]
    fn set_mss_cap_zero_panics() {
        socket().set_mss_cap(Some(0));
    }

    #[test]
    #[should_panic(expected = "ACK delay 60.001s must not exceed 60.000s")]
    fn set_ack_delay_above_max_rto_panics() {
        socket().set_ack_delay(Some(MAX_RTO + Duration::from_millis(1)));
    }

    #[test]
    fn mss_cap_limits_retransmission() {
        let mut s = socket_with_buffer_sizes(4096, 4096);
        s.set_mss_cap(Some(512));
        connect_with_mss_cap(&mut s, 512, BASE_MSS);
        s.send_slice(&[0xa5; 1024]).unwrap();
        let lengths = [512, 512].as_slice();
        let mut offset = 0;
        for &len in lengths {
            let mut emitted = false;
            s.socket
                .dispatch(&mut s.cx, |_, _, (_, segment)| {
                    emitted = true;
                    assert_eq!(segment.seq_number, LOCAL_SEQ + 1 + offset);
                    assert_eq!(segment.payload, &[0xa5; 1024][..len]);
                    Ok::<_, ()>(())
                })
                .unwrap();
            assert!(emitted);
            offset += len;
        }
        recv_nothing!(s);
        s.cx.set_now(Instant::from_millis(300));
        let mut emitted = false;
        s.socket
            .dispatch(&mut s.cx, |_, _, (_, segment)| {
                emitted = true;
                assert_eq!(segment.seq_number, LOCAL_SEQ + 1);
                assert_eq!(segment.payload, &[0xa5; 512]);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(emitted);
        assert_eq!(s.congestion_controller.window(), 512);
        recv_nothing!(s, time 300);
    }

    fn socket_syn_received_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_with_buffer_sizes(tx_len, rx_len);
        s.state = State::SynReceived;
        s.tuple = Some(TUPLE);
        s.local_seq_no = LOCAL_SEQ;
        s.remote_seq_no = REMOTE_SEQ + 1;
        s.remote_last_seq = LOCAL_SEQ;
        s.remote_max_seq = LOCAL_SEQ;
        s.remote_win_len = 256;
        s.max_snd_wnd = 256;
        s.remote_win_seq = REMOTE_SEQ;
        s.socket.update_rx_mbuf_budget(&s.cx);
        s
    }

    fn socket_syn_received() -> TestSocket {
        socket_syn_received_with_buffer_sizes(64, 64)
    }

    fn socket_syn_sent_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_with_buffer_sizes(tx_len, rx_len);
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        s
    }

    fn socket_syn_sent() -> TestSocket {
        socket_syn_sent_with_buffer_sizes(64, 64)
    }

    fn socket_established_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_syn_received_with_buffer_sizes(tx_len, rx_len);
        s.state = State::Established;
        s.local_seq_no = LOCAL_SEQ + 1;
        s.bytes_acked = 1;
        s.remote_last_seq = LOCAL_SEQ + 1;
        s.remote_max_seq = LOCAL_SEQ + 1;
        s.remote_last_ack = Some(REMOTE_SEQ + 1);
        s.remote_last_win_bytes = u32::from(s.scaled_window()) << s.remote_win_shift;
        s
    }

    fn hold_rx_frames(s: &mut TestSocket, count: usize) -> Vec<TcpFrame> {
        let ack_delay = s.ack_delay();
        s.set_ack_delay(None);
        let mut frames = Vec::new();
        for _ in 0..count {
            let next = s.remote_seq_no;
            let peer_window = u16::try_from(s.remote_win_len).unwrap();
            assert_eq!(send(s, Instant::ZERO, &TcpRepr {
                seq_number: next,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: peer_window,
                payload: b"x",
                ..SEND_TEMPL
            }), None);
            recv(s, Instant::ZERO, |result| {
                let ack = result.unwrap();
                assert_eq!(ack.ack_number, Some(next + 1));
                assert!(ack.payload.is_empty());
            });
            frames.push(s.recv().unwrap().unwrap());
            assert_eq!(frames.last().unwrap().payload(), b"x");
        }
        s.set_ack_delay(ack_delay);
        assert_eq!(s.recv_queue(), 0);
        assert_eq!(s.rx_buffer.shared.held.get(), frames.len());
        frames
    }

    fn socket_with_held_rx_frames(
        rx_len: usize,
        next: TcpSeqNumber,
        count: usize,
    ) -> (TestSocket, Vec<TcpFrame>) {
        let mut s = socket_established_with_buffer_sizes(64, rx_len);
        s.remote_seq_no = next - count;
        s.remote_last_ack = Some(next - count);
        let frames = hold_rx_frames(&mut s, count);
        assert_eq!(s.remote_seq_no, next);
        (s, frames)
    }

    fn socket_with_mbuf_window(shift: u8) -> TestSocket {
        let mut s = socket_established_with_buffer_sizes(64, 65536);
        assert_eq!(s.cx.ip_mtu(), 1500);
        // This peer advertises MSS 1460; the frame-budget tests use that allowance.
        s.remote_mss = BASE_MSS;
        s.socket.update_rx_mbuf_budget(&s.cx);
        s.remote_win_shift = shift;
        s.remote_last_win_bytes = u32::from(u16::try_from(65536usize >> shift).unwrap_or(u16::MAX)) << shift;
        s
    }

    #[test]
    fn last_scaled_window_rounds_up_for_every_shift() {
        for shift in [0, 1, 7, 14] {
            let mut s = socket_established();
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: b"abc",
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.recv_queue(), 3);
            s.remote_win_shift = shift;
            s.remote_last_win_bytes = 4 << shift;
            let unit = 1usize << shift;
            let last_window = s.remote_last_win_bytes as usize;
            let next_ack = s.remote_seq_no + s.recv_queue();
            for window in [0, 4 * unit, 4 * unit + 1, 4 * unit - 1, 65536 * unit + 1] {
                s.remote_last_ack = Some(next_ack + window - last_window);
                let expected = u16::try_from((window + unit - 1) / unit).unwrap_or(u16::MAX);
                assert_eq!(
                    s.last_scaled_window(),
                    Some(expected),
                    "shift {shift}, adjusted window {window}"
                );
            }
        }
    }

    #[test]
    fn window_to_update_matches_full_window_check() {
        // [byte window below twice the last window, doubling only in bytes, doubling]
        let mut kinds = [0usize; 3];
        for shift in [0u8, 3] {
            for (in_order, out_of_order, cap) in [
                (0, 0, 4),
                (6, 0, 4),
                (6, 4, 4),
                (2, 0, 3),
                (40, 0, 8),
            ] {
                let mut s = socket_established_with_buffer_sizes(64, 64);
                s.remote_win_shift = shift;
                s.rx_mbuf_cap = cap;
                s.rx_seg_bytes = 10;
                for (offset, len) in [(0, in_order), (in_order + 5, out_of_order)] {
                    if len > 0 {
                        let decision = s.rx_buffer.store.decide(offset, len, 8);
                        s.rx_buffer.store.place(offset, decision);
                        s.rx_buffer.store.attach(RxBuf::from_vec(vec![0; len]));
                    }
                }
                assert_eq!(s.rx_buffer.store.in_order_len(), in_order);
                assert_eq!(s.rx_buffer.store.out_of_order_len(), out_of_order);
                s.remote_last_ack = Some(s.remote_seq_no);
                for last in 0..=64u16 {
                    s.remote_last_win_bytes = u32::from(last) << shift;
                    let last_window = s.last_scaled_window().unwrap();
                    let new_window = s.scaled_window_with_last(Some(last_window));
                    let expected = new_window > 0 && new_window / 2 >= last_window;
                    assert_eq!(
                        s.window_to_update(),
                        expected,
                        "shift {shift}, held {in_order}+{out_of_order}, cap {cap}, last {last}"
                    );
                    let kind = if (s.rx_buffer.capacity >> shift) / 2 < usize::from(last_window) {
                        0
                    } else {
                        1 + usize::from(expected)
                    };
                    kinds[kind] += 1;
                }
            }
        }
        assert!(kinds.iter().all(|&count| count > 0), "{kinds:?}");
        let mut s = socket_established();
        s.remote_last_ack = None;
        assert!(!s.window_to_update());
    }

    #[test]
    fn rx_wake_at_held_is_the_largest_held_count_with_window_update() {
        // [no held count updates, some do]
        let mut kinds = [0usize; 2];
        for shift in [0u8, 3, 7] {
            // (RX capacity, in-order bytes, out-of-order pieces x bytes, frame cap, segment bytes)
            for (capacity, in_order, (pieces, out_of_order), cap, seg) in [
                (64, 0, (0, 0), 8, 10),
                (200, 6, (0, 0), 16, 10),
                (200, 6, (1, 4), 16, 10),
                (200, 40, (0, 0), 12, 10),
                (1000, 3, (2, 20), 40, 10),
                (1000, 3, (2, 20), 40, 4),
                (1000, 3, (2, 20), 40, 10),
                (1 << 24, 0, (1, 30), 1000, 1460),
            ] {
                let mut s = socket_established_with_buffer_sizes(64, capacity);
                s.remote_win_shift = shift;
                s.rx_mbuf_cap = cap;
                s.rx_seg_bytes = seg;
                let mut offset = 0;
                for len in core::iter::once(in_order).chain(core::iter::repeat_n(out_of_order, pieces)) {
                    if len > 0 {
                        let decision = s.rx_buffer.store.decide(offset, len, 8);
                        s.rx_buffer.store.place(offset, decision);
                        s.rx_buffer.store.attach(RxBuf::from_vec(vec![0; len]));
                    }
                    offset += len + 5;
                }
                // Each gap is 5 bytes.
                assert_eq!(
                    s.rx_buffer.store.out_of_order_hole_frames(seg as usize),
                    pieces * 5usize.div_ceil(seg as usize)
                );
                s.remote_last_ack = Some(s.remote_seq_no);
                let unstored = cap as usize - s.rx_buffer.store.held();
                let lasts = (0..=200u32).chain([16383, 16384, 32766, 32767, 32768]);
                for last in lasts.filter(|&last| (last as usize) << shift <= capacity) {
                    s.remote_last_win_bytes = last << shift;
                    s.rx_buffer.shared.held.set(unstored);
                    let wake_at = s.rx_wake_at_held();
                    for held in 0..=unstored {
                        s.rx_buffer.shared.held.set(held);
                        assert_eq!(
                            s.window_to_update(),
                            wake_at != usize::MAX && held <= wake_at,
                            "shift {shift}, capacity {capacity}, stored {in_order}+{pieces}x{out_of_order}, \
                             cap {cap}, seg {seg}, last {last}, held {held}, wake_at {wake_at}"
                        );
                    }
                    kinds[usize::from(wake_at != usize::MAX)] += 1;
                }
                s.rx_buffer.shared.held.set(0);
                assert_eq!(s.rx_wake_at_held(), usize::MAX);
            }
        }
        assert!(kinds.iter().all(|&count| count > 0), "{kinds:?}");
    }

    /// Drained wakes: handles pushed since the last drain.
    #[cfg(feature = "udp-set")]
    fn drain_wakes(queue: &crate::iface::DropQueue) -> Vec<crate::iface::SocketHandle> {
        let mut wakes = Vec::new();
        queue.drain_into(&mut Vec::new(), &mut Vec::new(), &mut wakes);
        wakes
    }

    /// Every frame held, the last ACK advertised a zero window, and a quiet poll_at armed the
    /// wake at one frame below the cap. Returns the socket, its frames and the next peer seq.
    #[cfg(feature = "udp-set")]
    fn zero_window_with_wake(
        queue: &crate::iface::DropQueue,
        handle: crate::iface::SocketHandle,
    ) -> (TestSocket, Vec<TcpFrame>, TcpSeqNumber) {
        let seq = REMOTE_SEQ + 1 + 5;
        let (mut s, mut frames) = socket_with_held_rx_frames(3, seq, 5);
        s.set_rx_wake(queue.clone(), handle);
        send!(s, TcpRepr {
            seq_number: seq,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abc"[..],
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(seq + 3),
            window_len: 0,
            ..RECV_TEMPL
        }]);
        frames.push(s.recv().unwrap().unwrap());
        assert_eq!(frames.len(), s.rx_frame_cap());
        assert_ne!(s.socket.poll_at(&mut s.cx), PollAt::Now);
        assert_eq!(s.rx_buffer.shared.wake_at_held.get(), frames.len() - 1);
        (s, frames, seq + 3)
    }

    #[test]
    #[cfg(feature = "udp-set")]
    fn add_admitted_registers_frame_drop_wake() {
        let mut set = crate::iface::TcpSet::new(vec![]);
        let queue = crate::iface::DropQueue::with_capacity(1, 0);
        let handle = set.add_admitted(
            &Config { rx_capacity: 64, tx_capacity: 64, mss_cap: None },
            1500,
            queue.clone(),
        );
        let shared = set.get(handle).rx_buffer.shared.clone();
        let wake = shared.wake.borrow();
        assert_eq!(wake.as_ref().map(|(_, handle)| *handle), Some(handle));
        assert!(wake.as_ref().unwrap().0.same(&queue));
    }

    #[test]
    #[cfg(feature = "udp-set")]
    fn remove_clears_frame_drop_wake() {
        let mut set = crate::iface::TcpSet::new(vec![]);
        let placeholder = set.add(Socket::new(RxBuffer::new(64), SocketBuffer::new(vec![0; 64])));
        let queue = crate::iface::DropQueue::with_capacity(2, 0);
        let (s, mut frames, _) = zero_window_with_wake(&queue, placeholder);
        let handle = set.add(s.socket);
        set.get_mut(handle).set_rx_wake(queue.clone(), handle);
        let (held, _) = set.remove(handle);
        frames.pop();
        assert!(drain_wakes(&queue).is_empty(), "removed socket must not queue a wake");
        assert_eq!(held.count(), frames.len());
    }

    #[test]
    #[cfg(feature = "udp-set")]
    fn frame_drop_wakes_socket_only_when_window_update_becomes_due() {
        let mut set = crate::iface::TcpSet::new(vec![]);
        let handle = set.add(Socket::new(RxBuffer::new(64), SocketBuffer::new(vec![0; 64])));
        let queue = crate::iface::DropQueue::with_capacity(1, 0);

        let (mut s, mut frames, _) = zero_window_with_wake(&queue, handle);
        frames.pop();
        assert!(s.window_to_update());
        assert_eq!(drain_wakes(&queue), [handle]);
        // Held back up to the cap (as a recv of a stored frame would) and down to the due
        // count again before the wake was handled: the queued wake is not pushed twice.
        let shared = s.rx_buffer.shared.clone();
        shared.held.set(shared.held.get() + 1);
        frames.pop();
        assert_eq!(shared.held.get(), shared.wake_at_held.get());
        assert!(drain_wakes(&queue).is_empty(), "one queued wake per socket");
        shared.held.set(shared.held.get() - 1);
        frames.pop();
        assert!(drain_wakes(&queue).is_empty(), "drops past the due count push nothing");
        s.clear_rx_wake_queued();
        drop(frames);
        assert!(drain_wakes(&queue).is_empty(), "drops past the due count push nothing");

        // One frame held under a large window: dropping it cannot double the window.
        let mut s = socket_established();
        s.set_rx_wake(queue.clone(), handle);
        let frames = hold_rx_frames(&mut s, 1);
        assert_ne!(s.socket.poll_at(&mut s.cx), PollAt::Now);
        assert_eq!(s.rx_buffer.shared.wake_at_held.get(), usize::MAX);
        drop(frames);
        assert!(!s.window_to_update());
        assert!(drain_wakes(&queue).is_empty());

        // A segment after arming (here an RST, which closes the socket) disarms the wake
        // until the next poll_at: the drop pushes nothing.
        let (mut s, mut frames, next) = zero_window_with_wake(&queue, handle);
        send!(s, TcpRepr {
            control: TcpControl::Rst,
            seq_number: next,
            ack_number: None,
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Closed);
        assert_eq!(s.rx_buffer.shared.wake_at_held.get(), usize::MAX);
        frames.pop();
        assert!(drain_wakes(&queue).is_empty());
    }

    #[test]
    fn poll_at_answers_now_for_due_ack_or_window_update() {
        let later = Instant::from_millis(50);
        for (unread, last_win, ack_timer, ack_due, window_update) in [
            (0, 64, AckDelayTimer::Idle, false, false),
            (4, 64, AckDelayTimer::Idle, true, false),
            (4, 64, AckDelayTimer::Immediate, true, false),
            (4, 64, AckDelayTimer::Waiting(later), false, false),
            (0, 10, AckDelayTimer::Waiting(later), false, true),
            (4, 10, AckDelayTimer::Waiting(later), false, true),
            (4, 10, AckDelayTimer::Idle, true, true),
        ] {
            let mut s = socket_established_with_buffer_sizes(64, 64);
            if unread > 0 {
                let decision = s.rx_buffer.store.decide(0, unread, 8);
                s.rx_buffer.store.place(0, decision);
                s.rx_buffer.store.attach(RxBuf::from_vec(vec![0; unread]));
            }
            s.remote_last_ack = Some(s.remote_seq_no);
            s.remote_last_win_bytes = last_win;
            s.set_ack_delay_timer(ack_timer);
            assert_eq!(s.ack_to_transmit(), unread > 0);
            assert_eq!(s.window_to_update(), window_update);
            let expected = if ack_due || window_update {
                PollAt::Now
            } else if unread > 0 {
                s.timer.poll_at().min(PollAt::Time(later))
            } else {
                s.timer.poll_at().min(PollAt::Ingress)
            };
            assert_eq!(
                s.socket.poll_at(&mut s.cx),
                expected,
                "unread {unread}, last window {last_win}, {ack_timer:?}"
            );
        }
    }

    fn receive_window_segment(
        s: &mut TestSocket,
        offset: usize,
        payload: &[u8],
    ) -> TcpRepr<'static> {
        let reply = send(
            s,
            Instant::from_millis(0),
            &TcpRepr {
                seq_number: REMOTE_SEQ + 1 + offset,
                ack_number: Some(LOCAL_SEQ + 1),
                payload,
                ..SEND_TEMPL
            },
        );
        reply.unwrap_or_else(|| {
            let mut ack = None;
            recv(s, Instant::from_millis(0), |reply| {
                let reply = reply.unwrap();
                assert!(reply.payload.is_empty());
                ack = Some(TcpRepr {
                    payload: &[],
                    ..reply
                });
            });
            ack.unwrap()
        })
    }

    #[test]
    fn window_counts_mbufs_when_segments_pack_poorly() {
        let mut s = socket_with_mbuf_window(2);
        let segment = [0; 1100];
        for index in 0..20 {
            let ack = receive_window_segment(&mut s, index * 1100, &segment);
            assert_eq!(ack.window_len, ((65536 - (index + 1) * 1100) >> 2) as u16);
        }
        assert_eq!(s.rx_buffer.store.held(), 20);
        assert_eq!(drain_frames(&mut s, 10), vec![0; 11000]);
        assert_eq!(s.rx_buffer.store.held(), 10);
        assert_eq!(s.recv_room(), 51100);
        let ack = receive_window_segment(&mut s, 0, &segment);
        assert_eq!(ack.window_len, 51100 >> 2);
        assert!(usize::from(ack.window_len) < (65536 - s.recv_queue()) >> 2);
        let promised_edge = ack.ack_number.unwrap() + (usize::from(ack.window_len) << 2);
        for index in 20..55 {
            let last = s.remote_last_ack.unwrap() + s.remote_last_win_bytes as usize;
            let ack = receive_window_segment(&mut s, index * 1100, &segment);
            assert_eq!(
                ack.ack_number.unwrap() + (usize::from(ack.window_len) << 2),
                last
            );
        }
        assert_eq!(s.rx_buffer.store.held(), 45);
        assert_eq!(s.recv_queue(), 49500);
        assert_eq!(s.recv_room(), 0);
        let ack = receive_window_segment(&mut s, 60500, &segment);
        assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1 + 60500));
        assert_eq!(
            ack.ack_number.unwrap() + (usize::from(ack.window_len) << 2),
            promised_edge
        );
        assert_eq!(s.rx_refused_segments(), 1);
        assert_eq!(drain_bytes(&mut s), vec![0; 49500]);
        assert_eq!(s.rx_buffer.store.held(), 0);
        let ack = receive_window_segment(&mut s, 0, &segment);
        assert_eq!(ack.window_len, (65536usize >> 2) as u16);
        assert!(ack.ack_number.unwrap() + (usize::from(ack.window_len) << 2) > promised_edge);
    }

    #[test]
    fn full_mss_out_of_order_frames_keep_advertised_window() {
        let mut s = socket_with_mbuf_window(2);
        for index in 0..20 {
            receive_window_segment(&mut s, index * 1100, &[0; 1100]);
        }
        assert_eq!(drain_frames(&mut s, 10), vec![0; 11000]);
        let previous = receive_window_segment(&mut s, 0, &[0; 1100]);
        assert_eq!(previous.ack_number, Some(REMOTE_SEQ + 1 + 22000));
        for index in 1..=3 {
            let ack = receive_window_segment(&mut s, 22000 + index * 1460, &[0; 1460]);
            assert_eq!(ack.ack_number, previous.ack_number);
            assert_eq!(ack.window_len, previous.window_len);
        }
        assert_eq!(s.rx_buffer.store.out_of_order_len(), 3 * 1460);
        assert_eq!(s.rx_refused_segments(), 0);
    }

    #[test]
    fn window_counts_ooo_bytes_inside_window() {
        let mut s = socket_with_mbuf_window(2);
        for index in 0..20 {
            receive_window_segment(&mut s, index * 1100, &[0; 1100]);
        }
        assert_eq!(drain_frames(&mut s, 10), vec![0; 11000]);
        let ack = receive_window_segment(&mut s, 24000, &[0; 500]);
        assert_eq!(s.rx_buffer.store.held(), 11);
        assert_eq!(s.recv_queue(), 11000);
        assert_eq!(s.rx_buffer.store.out_of_order_len(), 500);
        // The span is 24500 - 22000, plus (45 - 11 - 2) * 1460 free-frame bytes: the
        // 2000-byte gap needs two 1460-byte frames.
        assert_eq!(s.recv_room(), 49220);
        assert_eq!(ack.window_len, 49220 >> 2);
        assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1 + 22000));
        assert_eq!(s.rx_refused_segments(), 0);
    }

    #[test]
    fn right_edge_holds_across_unaligned_acks() {
        let mut s = socket_with_mbuf_window(1);
        for index in 0..20 {
            receive_window_segment(&mut s, index * 1100, &[0; 1100]);
        }
        assert_eq!(drain_frames(&mut s, 10), vec![0; 11000]);
        let ack = receive_window_segment(&mut s, 0, &[0; 1100]);
        assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1 + 22000));
        assert_eq!(ack.window_len, 25550);
        let mut edge = ack.ack_number.unwrap() + (usize::from(ack.window_len) << 1);
        assert_eq!(edge, REMOTE_SEQ + 1 + 73100);
        for index in 0..3 {
            let ack = receive_window_segment(&mut s, 22000 + index * 1101, &[0; 1101]);
            assert_eq!(
                ack.ack_number,
                Some(REMOTE_SEQ + 1 + 22000 + (index + 1) * 1101)
            );
            let next_edge = ack.ack_number.unwrap() + (usize::from(ack.window_len) << 1);
            assert!(next_edge >= edge);
            assert_eq!(next_edge, REMOTE_SEQ + 1 + 73101 + index);
            edge = next_edge;
        }
    }

    #[test]
    fn no_window_update_when_edge_unchanged_after_unaligned_fill() {
        let mut s = socket_with_mbuf_window(1);
        for index in 0..20 {
            receive_window_segment(&mut s, index * 1100, &[0; 1100]);
        }
        assert_eq!(drain_frames(&mut s, 10), vec![0; 11000]);
        let ack = receive_window_segment(&mut s, 0, &[0; 1100]);
        let edge = ack.ack_number.unwrap() + (usize::from(ack.window_len) << 1);
        assert_eq!(edge, REMOTE_SEQ + 1 + 73100);
        for index in 0..34 {
            receive_window_segment(&mut s, 22000 + index * 1460, &[0; 1460]);
        }
        assert_eq!(s.rx_buffer.store.held(), 44);
        assert_eq!(s.recv_room(), 1460);
        assert_eq!(
            s.remote_last_ack.unwrap() + s.remote_last_win_bytes as usize,
            edge
        );

        s.set_ack_delay(Some(Duration::from_millis(10)));
        send!(
            s,
            time 100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 71640,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 1459],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.remote_seq_no + s.recv_queue(), edge - 1);
        assert_eq!(s.rx_buffer.store.held(), 45);
        assert_eq!(s.recv_room(), 0);
        assert!(s.rx_buffer.capacity >= 2);
        assert_eq!(s.scaled_window(), 1);
        assert!(!s.window_to_update());
        assert_eq!(s.last_scaled_window(), Some(1));
        assert_eq!(
            s.ack_delay_timer(),
            AckDelayTimer::Waiting(Instant::from_millis(110))
        );
        recv_nothing!(s, time 100);
        recv_nothing!(s, time 109);
        recv!(
            s,
            time 110,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(edge - 1),
                window_len: 1,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn right_edge_never_retracts_by_a_unit() {
        use rand::{Rng, SeedableRng, rngs::StdRng};

        let mut saw_ooo = false;
        let mut saw_frame_bound = false;
        let mut reads = 0;
        for shift in 0..=2 {
            for seed in [1, 7, 0x12345678, 0xabcdef01] {
                let mut s = socket_with_mbuf_window(shift);
                let mut rng = StdRng::seed_from_u64(seed);
                let mut edge = REMOTE_SEQ + 1 + s.remote_last_win_bytes as usize;
                for index in 0..20 {
                    let ack = receive_window_segment(&mut s, index * 1100, &[0; 1100]);
                    let next_edge =
                        ack.ack_number.unwrap() + (usize::from(ack.window_len) << shift);
                    assert!(next_edge >= edge);
                    edge = next_edge;
                }
                assert_eq!(drain_frames(&mut s, 10), vec![0; 11000]);
                assert_eq!(s.recv_room(), 51100);
                for _ in 0..1000 {
                    if rng.gen_ratio(1, 4) {
                        for _ in 0..rng.gen_range(0..=2) {
                            let Some(frame) = s.recv().unwrap() else { break; };
                            reads += frame.payload().len();
                        }
                    }
                    let next_ack = s.remote_seq_no + s.recv_queue();
                    let offset = next_ack - (REMOTE_SEQ + 1)
                        + if rng.gen_ratio(1, 3) {
                            rng.gen_range(64..=1448)
                        } else {
                            0
                        };
                    let len = rng.gen_range(64..=1448);
                    let ack = receive_window_segment(&mut s, offset, &vec![0; len]);
                    let next_edge =
                        ack.ack_number.unwrap() + (usize::from(ack.window_len) << shift);
                    assert!(next_edge >= edge, "seed {seed}, offset {offset}, len {len}");
                    edge = next_edge;
                    assert!(s.rx_buffer.store.held() <= 45);
                    saw_ooo |= s.rx_buffer.store.out_of_order_len() > 0;
                    saw_frame_bound |= s.recv_room() < 65536 - s.recv_queue();
                }
            }
        }
        assert!(saw_ooo);
        assert!(saw_frame_bound);
        assert!(reads > 0);
    }

    #[test]
    fn cap_refusal_sends_dup_ack_keeps_state() {
        let mut s = socket_with_mbuf_window(2);
        let cap = s.rx_mbuf_budget(s.cx.ip_mtu());
        for index in 0..cap {
            receive_window_segment(&mut s, index * 1100, &[b'a'; 1100]);
        }
        let previous_ack = s.remote_last_ack.unwrap();
        let previous_window = s.remote_last_win_bytes;
        assert!(previous_window >= 1100);
        assert_eq!(s.recv_room(), 0);
        let state = s.state();
        let remote_seq = s.remote_seq_no;
        let local_seq = s.local_seq_no;
        let ranges: Vec<_> = s.rx_buffer.store.ranges().collect();
        let reply = send(
            &mut s,
            Instant::ZERO,
            &TcpRepr {
                seq_number: previous_ack,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[b'z'; 1100],
                ..SEND_TEMPL
            },
        )
        .unwrap();
        assert_eq!(reply.ack_number, Some(previous_ack));
        assert_eq!(u32::from(reply.window_len) << s.remote_win_shift, previous_window);
        assert!(reply.payload.is_empty());
        assert_eq!(s.rx_refused_segments(), 1);
        assert_eq!(s.state(), state);
        assert_eq!(s.remote_seq_no, remote_seq);
        assert_eq!(s.local_seq_no, local_seq);
        assert_eq!(s.rx_buffer.store.ranges().collect::<Vec<_>>(), ranges);
        assert_eq!(s.rx_buffer.store.held(), cap);
        assert_eq!(s.recv_queue(), cap * 1100);
        assert_eq!(s.rx_buffer.store.out_of_order_len(), 0);
        assert!(!s.rx_fin_received);
        assert_eq!(s.rx_fin_seq, None);
        let bytes = drain_bytes(&mut s);
        assert_eq!(bytes.len(), cap * 1100);
        assert_eq!(bytes, vec![b'a'; cap * 1100]);
    }

    #[test]
    fn refused_segment_counter_saturates() {
        let mut s = socket_with_mbuf_window(2);
        let cap = s.rx_mbuf_budget(s.cx.ip_mtu());
        for index in 0..cap {
            receive_window_segment(&mut s, index * 1100, &[b'a'; 1100]);
        }
        assert_eq!(s.rx_buffer.store.held(), cap);
        assert_eq!(s.recv_room(), 0);
        let previous_ack = s.remote_last_ack.unwrap();
        let previous_window = s.remote_last_win_bytes;
        assert!(previous_window >= 1100);
        s.rx_refused_segments = u32::MAX;
        let reply = send(
            &mut s,
            Instant::ZERO,
            &TcpRepr {
                seq_number: previous_ack,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[b'z'; 1100],
                ..SEND_TEMPL
            },
        )
        .unwrap();
        assert_eq!(reply.ack_number, Some(previous_ack));
        assert_eq!(u32::from(reply.window_len) << s.remote_win_shift, previous_window);
        assert!(reply.payload.is_empty());
        assert_eq!(s.rx_refused_segments(), u32::MAX);
        assert_eq!(s.rx_buffer.store.held(), cap);
        assert_eq!(s.recv_queue(), cap * 1100);
    }

    #[test]
    fn full_segments_window_counts_frames() {
        for shift in 0..=2 {
            let mut s = socket_with_mbuf_window(shift);
            let mut offset = 0;
            while offset < 65536 {
                let len = 1460.min(65536 - offset);
                let ack = receive_window_segment(&mut s, offset, &vec![0; len]);
                offset += len;
                let room = ((45 - s.rx_buffer.store.held()) * 1460).min(65536);
                assert_eq!(s.recv_room(), room);
                // The last 1296-byte segment uses the last frame of a 1460-byte window.
                // The window never shrinks, so the ACK still offers the other 164 bytes.
                let advertised = if offset == 65536 { 164 } else { room };
                assert_eq!(ack.window_len, (advertised >> shift) as u16);
            }
            assert_eq!(s.rx_buffer.store.held(), 45);
            assert_eq!(drain_frames(&mut s, 10), vec![0; 14600]);
            let ack = receive_window_segment(&mut s, 0, &[0; 1460]);
            assert_eq!(s.recv_room(), 14600);
            assert_eq!(ack.window_len, (14600 >> shift) as u16);
            assert_eq!(s.rx_refused_segments(), 0);
        }
    }

    #[test]
    fn syn_windows_follow_peer_mss_availability() {
        for capacity in [64usize, 65536, 1048576] {
            // ceil(capacity / 1460), at least 6 frames; SYN uses 48 B per frame.
            let frames = capacity.div_ceil(1460).max(6);
            let active_window = u16::try_from(capacity.min(frames * 48)).unwrap();
            // Without a peer MSS option, SYN-ACK uses the default 536 B per frame.
            let passive_window = u16::try_from(capacity.min(frames * 536)).unwrap_or(u16::MAX);
            let mut active = socket_syn_sent_with_buffer_sizes(64, capacity);
            recv(&mut active, Instant::ZERO, |reply| {
                let reply = reply.unwrap();
                assert_eq!(reply.control, TcpControl::Syn);
                assert_eq!(reply.ack_number, None);
                assert_eq!(reply.window_len, active_window);
            });
            let mut passive = socket_with_buffer_sizes(64, capacity);
            passive.listen(LISTEN_END).unwrap();
            assert_eq!(
                send(
                    &mut passive,
                    Instant::ZERO,
                    &TcpRepr {
                        control: TcpControl::Syn,
                        seq_number: REMOTE_SEQ,
                        ack_number: None,
                        window_scale: Some(0),
                        ..SEND_TEMPL
                    },
                ),
                None
            );
            recv(&mut passive, Instant::ZERO, |reply| {
                let reply = reply.unwrap();
                assert_eq!(reply.control, TcpControl::Syn);
                assert_eq!(reply.ack_number, Some(REMOTE_SEQ + 1));
                assert_eq!(reply.window_len, passive_window);
            });
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn debug_poll_at_scan_preserves_receive_wake_threshold() {
        let (mut iface, _, _) = crate::tests::setup(crate::phy::Medium::Ip);
        let socket = socket().socket;
        let shared = socket.rx_buffer.shared.clone();
        let mut sockets = crate::iface::TcpSet::new(vec![]);
        sockets.add(socket);
        iface.classify_dirty(&mut sockets, Instant::ZERO);
        shared.wake_at_held.set(17);
        assert_eq!(iface.poll_at(Instant::ZERO, &mut sockets), None);
        assert_eq!(shared.wake_at_held.get(), 17);
    }

    fn socket_established() -> TestSocket {
        socket_established_with_buffer_sizes(64, 64)
    }

    fn socket_fin_wait_1() -> TestSocket {
        let mut s = socket_established();
        s.state = State::FinWait1;
        s
    }

    fn socket_fin_wait_2() -> TestSocket {
        let mut s = socket_fin_wait_1();
        s.state = State::FinWait2;
        s.local_seq_no = LOCAL_SEQ + 1 + 1;
        s.bytes_acked = 2;
        s.remote_last_seq = LOCAL_SEQ + 1 + 1;
        s.remote_max_seq = LOCAL_SEQ + 1 + 1;
        s
    }

    fn socket_closing() -> TestSocket {
        let mut s = socket_fin_wait_1();
        s.state = State::Closing;
        s.remote_last_seq = LOCAL_SEQ + 1 + 1;
        s.remote_max_seq = LOCAL_SEQ + 1 + 1;
        s.remote_seq_no = REMOTE_SEQ + 1 + 1;
        s.timer = Timer::Retransmit {
            expires_at: Instant::from_millis_const(300),
        };
        s
    }

    fn check_orphan_fin_retry_limit(mut s: TestSocket) {
        s.orphan(Instant::ZERO);
        let state = s.state();
        let seq = s.local_seq_no;
        if state != State::Closing {
            recv(&mut s, Instant::ZERO, |reply| {
                let reply = reply.unwrap();
                assert_eq!(reply.control, TcpControl::Fin);
                assert_eq!(reply.seq_number, seq);
            });
        } else {
            recv(&mut s, Instant::ZERO, |reply| {
                let reply = reply.unwrap();
                assert_eq!(reply.control, TcpControl::None);
                assert_eq!(reply.ack_number, Some(REMOTE_SEQ + 2));
            });
        }
        for expiry in 1..=8 {
            let Timer::Retransmit { expires_at } = s.timer else { panic!("expected RTO") };
            recv_nothing(&mut s, expires_at - Duration::from_micros(1));
            recv(&mut s, expires_at, |reply| {
                let reply = reply.unwrap();
                assert_eq!(reply.control, TcpControl::Fin);
                assert_eq!(reply.seq_number, seq);
                assert!(reply.payload.is_empty());
            });
            assert_eq!(s.rto_backoff, expiry);
            assert_eq!(s.state(), state);
            assert_eq!(s.remote_endpoint(), Some(REMOTE_END));
        }
        let Timer::Retransmit { expires_at } = s.timer else { panic!("expected RTO") };
        recv_nothing(&mut s, expires_at);
        assert_eq!(s.state(), State::Closed);
        assert_eq!(s.remote_endpoint(), None);
        recv_nothing(&mut s, expires_at);
    }

    fn check_failed_orphan_emit(mut s: TestSocket, orphaned: bool, probe: bool) {
        if probe {
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            });
            s.send_slice(b"abc").unwrap();
        }
        if orphaned {
            s.orphan(Instant::ZERO);
        }
        let state = s.state();
        let mut now = Instant::ZERO;
        for expiry in 0..=ORPHAN_RETRIES {
            s.cx.set_now(now);
            let result = s.socket.dispatch(&mut s.cx, |_, _, (_, repr)| {
                assert!(repr.segment_len() > 0);
                Err::<(), _>(())
            });
            if probe && expiry == 0 {
                assert_eq!(result, Ok(()));
            } else {
                assert_eq!(result, Err(()));
            }
            assert_eq!(s.state(), state);
            assert_eq!(s.remote_endpoint(), Some(REMOTE_END));
            if !orphaned && !probe {
                assert!(s.timer.is_idle());
                now += Duration::from_secs(300);
                continue;
            }
            now = match s.timer {
                Timer::Retransmit { expires_at } if !probe => expires_at,
                Timer::ZeroWindowProbe { expires_at, .. } if probe => expires_at,
                _ => panic!("failed emit did not arm the orphan timer"),
            };
            assert!(now > s.cx.now(), "failed emit did not re-arm the orphan timer");
        }
        s.cx.set_now(now);
        let result = s.socket.dispatch(&mut s.cx, |_, _, _| Err::<(), _>(()));
        if orphaned {
            assert_eq!(result, Ok(()));
            assert_eq!(s.state(), State::Closed);
            assert_eq!(s.remote_endpoint(), None);
        } else {
            assert_eq!(s.state(), state);
            assert_eq!(s.remote_endpoint(), Some(REMOTE_END));
        }
    }

    #[test]
    fn orphan_failed_emit_fin_wait_1() {
        for orphaned in [true, false] {
            check_failed_orphan_emit(socket_fin_wait_1(), orphaned, false);
        }
    }

    #[test]
    fn orphan_failed_emit_last_ack() {
        for orphaned in [true, false] {
            check_failed_orphan_emit(socket_last_ack(), orphaned, false);
        }
    }

    #[test]
    fn orphan_failed_emit_after_sent_fin() {
        let mut s = socket_fin_wait_1();
        s.orphan(Instant::ZERO);
        recv(&mut s, Instant::ZERO, |reply| {
            assert_eq!(reply.unwrap().control, TcpControl::Fin);
        });
        for expiry in 1..=ORPHAN_RETRIES {
            let Timer::Retransmit { expires_at } = s.timer else { panic!("expected RTO") };
            s.cx.set_now(expires_at);
            assert_eq!(s.socket.dispatch(&mut s.cx, |_, _, (_, repr)| {
                assert_eq!(repr.control, TcpControl::Fin);
                Err::<(), _>(())
            }), Err(()));
            assert_eq!(s.rto_backoff, expiry);
            assert_eq!(s.state(), State::FinWait1);
            assert_eq!(s.remote_endpoint(), Some(REMOTE_END));
        }
        let Timer::Retransmit { expires_at } = s.timer else { panic!("expected RTO") };
        recv_nothing(&mut s, expires_at);
        assert_eq!(s.state(), State::Closed);
        assert_eq!(s.remote_endpoint(), None);
    }

    #[test]
    fn orphan_failed_emit_data() {
        for orphaned in [true, false] {
            let mut s = socket_established();
            s.send_slice(b"abc").unwrap();
            s.close();
            check_failed_orphan_emit(s, orphaned, false);
        }
    }

    #[test]
    fn owned_failed_emit_zero_window_probe_keeps_expired_timer() {
        let mut s = socket_established();
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        });
        s.send_slice(b"abc").unwrap();
        recv_nothing(&mut s, Instant::ZERO);
        let Timer::ZeroWindowProbe { expires_at, .. } = s.timer else { panic!("expected probe timer") };
        for retry in 0..10 {
            s.cx.set_now(expires_at + Duration::from_secs(retry));
            assert_eq!(s.socket.dispatch(&mut s.cx, |_, _, (_, repr)| {
                assert_eq!(repr.payload, b"a");
                Err::<(), _>(())
            }), Err(()));
            assert_eq!(s.rto_backoff, 1);
            assert_eq!(s.timer, Timer::ZeroWindowProbe { expires_at, backoff_applied: true });
            assert_eq!(s.state(), State::Established);
            assert_eq!(s.remote_endpoint(), Some(REMOTE_END));
        }
    }

    #[test]
    fn orphan_failed_emit_zero_window_probe() {
        check_failed_orphan_emit(socket_established(), true, true);
    }

    #[test]
    fn orphan_regression_fin_wait_1_retry_limit() {
        check_orphan_fin_retry_limit(socket_fin_wait_1());
    }

    #[test]
    fn orphan_already_past_retry_limit_closes_at_next_expiry() {
        let mut s = socket_fin_wait_1();
        s.rto_backoff = 12;
        s.orphan(Instant::ZERO);
        recv(&mut s, Instant::ZERO, |reply| {
            assert_eq!(reply.unwrap().control, TcpControl::Fin);
        });
        let Timer::Retransmit { expires_at } = s.timer else { panic!("expected RTO") };
        recv_nothing(&mut s, expires_at);
        assert_eq!(s.state(), State::Closed);
        assert_eq!(s.remote_endpoint(), None);
    }

    #[test]
    fn orphan_regression_last_ack_retry_limit() {
        check_orphan_fin_retry_limit(socket_last_ack());
    }

    #[test]
    fn orphan_regression_closing_retry_limit() {
        check_orphan_fin_retry_limit(socket_closing());
    }

    #[test]
    fn orphan_regression_zero_window_retry_limit() {
        let mut s = socket_established();
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        });
        assert_eq!(s.send_slice(b"abc"), Ok(3));
        s.orphan(Instant::ZERO);
        recv_nothing(&mut s, Instant::ZERO);
        for expiry in 1..=8 {
            let Timer::ZeroWindowProbe { expires_at, .. } = s.timer else { panic!("expected probe timer") };
            recv_nothing(&mut s, expires_at - Duration::from_micros(1));
            recv(&mut s, expires_at, |reply| {
                let reply = reply.unwrap();
                assert_eq!(reply.seq_number, LOCAL_SEQ + 1);
                assert_eq!(reply.payload, b"a");
            });
            assert_eq!(s.rto_backoff, expiry);
            assert_eq!(s.send_queue(), 3);
            assert_eq!(s.state(), State::FinWait1);
        }
        let Timer::ZeroWindowProbe { expires_at, .. } = s.timer else { panic!("expected probe timer") };
        recv_nothing(&mut s, expires_at);
        assert_eq!(s.state(), State::Closed);
        assert_eq!(s.remote_endpoint(), None);
        recv_nothing(&mut s, expires_at);
    }

    #[test]
    fn orphan_regression_lost_fin_data_rst_reply() {
        let mut s = socket_established();
        s.orphan(Instant::ZERO);
        recv(&mut s, Instant::ZERO, |reply| {
            assert_eq!(reply.unwrap().seq_number, LOCAL_SEQ + 1);
        });
        assert_eq!(s.remote_last_seq, LOCAL_SEQ + 2);
        let reply = send(&mut s, Instant::from_millis(1), &TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: b"new",
            ..SEND_TEMPL
        }).expect("new data must receive an immediate RST");
        assert_eq!(reply.control, TcpControl::Rst);
        assert_eq!(reply.seq_number, LOCAL_SEQ + 1);
        assert_eq!(reply.ack_number, None);
        assert_eq!(s.state(), State::Closed);
        assert_eq!(s.remote_endpoint(), None);
        recv_nothing(&mut s, Instant::from_millis(1));
    }

    fn check_orphan_out_of_order_fin(mut s: TestSocket) {
        if s.state() == State::FinWait1 {
            recv(&mut s, Instant::ZERO, |reply| {
                assert_eq!(reply.unwrap().control, TcpControl::Fin);
            });
        }
        s.orphan(Instant::ZERO);
        let reply = send(&mut s, Instant::from_millis(1), &TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 6,
            ack_number: Some(LOCAL_SEQ + 2),
            ..SEND_TEMPL
        }).expect("out-of-order FIN must receive an immediate RST");
        assert_eq!(reply.control, TcpControl::Rst);
        assert_eq!(reply.seq_number, LOCAL_SEQ + 2);
        assert_eq!(s.state(), State::Closed);
        assert_eq!(s.remote_endpoint(), None);
        recv_nothing(&mut s, Instant::from_millis(1));
    }

    #[test]
    fn orphan_regression_fin_wait_2_out_of_order_fin() {
        check_orphan_out_of_order_fin(socket_fin_wait_2());
    }

    #[test]
    fn orphan_regression_fin_wait_1_out_of_order_fin() {
        check_orphan_out_of_order_fin(socket_fin_wait_1());
    }

    #[test]
    fn orphan_regression_in_order_fin_keeps_normal_close() {
        for fin_wait_2 in [false, true] {
            for ack_fin in [false, true] {
                let mut s = if fin_wait_2 { socket_fin_wait_2() } else { socket_fin_wait_1() };
                if !fin_wait_2 {
                    recv(&mut s, Instant::ZERO, |reply| {
                        assert_eq!(reply.unwrap().control, TcpControl::Fin);
                    });
                }
                s.orphan(Instant::ZERO);
                let ack = if fin_wait_2 || ack_fin { LOCAL_SEQ + 2 } else { LOCAL_SEQ + 1 };
                send!(s, time 1, TcpRepr {
                    control: TcpControl::Fin,
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(ack),
                    ..SEND_TEMPL
                });
                assert_eq!(s.state(), if fin_wait_2 || ack_fin { State::TimeWait } else { State::Closing });
                assert_eq!(s.remote_endpoint(), Some(REMOTE_END));
                recv(&mut s, Instant::from_millis(1), |reply| {
                    let reply = reply.unwrap();
                    assert_eq!(reply.control, TcpControl::None);
                    assert_eq!(reply.ack_number, Some(REMOTE_SEQ + 2));
                });
            }
        }
    }

    #[test]
    fn orphan_regression_owned_out_of_order_fin_keeps_dup_ack() {
        let mut s = socket_fin_wait_2();
        let reply = send(&mut s, Instant::ZERO, &TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 6,
            ack_number: Some(LOCAL_SEQ + 2),
            ..SEND_TEMPL
        }).unwrap();
        assert_eq!(reply.control, TcpControl::None);
        assert_eq!(reply.ack_number, Some(REMOTE_SEQ + 1));
        assert_eq!(s.state(), State::FinWait2);
        assert_eq!(s.remote_endpoint(), Some(REMOTE_END));
    }

    #[test]
    fn orphan_regression_abort_emit_failure_forgets_tuple() {
        for orphaned in [false, true] {
            let mut s = socket_established();
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"unread",
                ..SEND_TEMPL
            });
            if orphaned {
                s.orphan(Instant::ZERO);
            } else {
                s.abort();
            }
            let mut attempts = 0;
            assert_eq!(s.socket.dispatch(&mut s.cx, |_, _, (_, repr)| {
                attempts += 1;
                assert_eq!(repr.control, TcpControl::Rst);
                Err(())
            }), Err(()));
            assert_eq!(attempts, 1);
            assert_eq!(s.state(), State::Closed);
            assert_eq!(s.remote_endpoint(), if orphaned { None } else { Some(REMOTE_END) });
            if !orphaned {
                recv(&mut s, Instant::ZERO, |reply| {
                    assert_eq!(reply.unwrap().control, TcpControl::Rst);
                });
                assert_eq!(s.remote_endpoint(), None);
            }
            recv_nothing(&mut s, Instant::ZERO);
        }
    }

    #[test]
    fn orphan_regression_close_before_failed_window_update() {
        let mut s = socket_established();
        let count = s.rx_frame_cap();
        let mut held = Vec::new();
        for index in 0..count {
            let len = if index == 0 { 64 - (count - 1) } else { 1 };
            let next = s.remote_seq_no;
            send!(s, TcpRepr {
                seq_number: next,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 64][..len],
                ..SEND_TEMPL
            });
            held.push(s.recv().unwrap().unwrap());
        }
        recv(&mut s, Instant::ZERO, |reply| {
            assert_eq!(reply.unwrap().window_len, 0);
        });
        s.close();
        recv(&mut s, Instant::ZERO, |reply| {
            assert_eq!(reply.unwrap().control, TcpControl::Fin);
        });
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 65,
            ack_number: Some(LOCAL_SEQ + 2),
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::FinWait2);
        assert_eq!(held.iter().flat_map(|frame| frame.payload().iter().copied()).collect::<Vec<_>>(), vec![0; 64]);
        drop(held);
        assert!(s.window_to_update());
        s.orphan(Instant::ZERO);
        assert_eq!(s.socket.dispatch(&mut s.cx, |_, _, _| Err::<(), _>(())), Err(()));
        assert!(s.window_to_update());
        s.cx.set_now(Instant::from_millis(60_001));
        let mut attempts = 0;
        let result = s.socket.dispatch(&mut s.cx, |_, _, _| {
            attempts += 1;
            Err(())
        });
        assert_eq!(attempts, 0, "expired close timer must not emit a window update");
        assert_eq!(result, Ok(()));
        assert_eq!(s.state(), State::Closed);
        assert_eq!(s.remote_endpoint(), None);
        recv_nothing(&mut s, Instant::from_millis(60_001));
    }

    #[test]
    fn orphan_established_sends_fin() {
        let mut s = socket_established();
        assert!(!s.orphaned);
        s.orphan(Instant::ZERO);
        assert!(s.orphaned);
        assert_eq!(s.state(), State::FinWait1);
        recv(&mut s, Instant::ZERO, |reply| {
            let reply = reply.unwrap();
            assert_eq!(reply.control, TcpControl::Fin);
            assert_eq!(reply.seq_number, LOCAL_SEQ + 1);
            assert!(reply.payload.is_empty());
        });
        recv_nothing(&mut s, Instant::ZERO);
    }

    #[test]
    fn orphan_unread_data_sends_one_rst() {
        for state in [State::SynReceived, State::Established, State::FinWait1,
                      State::FinWait2, State::CloseWait, State::Closing, State::LastAck]
        {
            let mut s = socket_established();
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"unread",
                ..SEND_TEMPL
            });
            assert_eq!(s.recv_queue(), 6);
            s.state = state;
            s.orphan(Instant::ZERO);
            assert_eq!(s.state(), State::Closed);
            assert_eq!(s.recv_queue(), 0);
            assert_eq!(s.remote_endpoint(), Some(REMOTE_END));
            recv(&mut s, Instant::ZERO, |reply| {
                assert_eq!(reply.unwrap().control, TcpControl::Rst);
            });
            assert_eq!(s.remote_endpoint(), None);
            recv_nothing(&mut s, Instant::ZERO);
        }
    }

    #[test]
    fn orphan_listen_closes_without_segment() {
        let mut s = socket();
        s.listen(LISTEN_END).unwrap();
        s.orphan(Instant::ZERO);
        assert_eq!(s.state(), State::Closed);
        assert!(s.orphaned);
        recv_nothing(&mut s, Instant::ZERO);
    }

    #[test]
    fn orphan_syn_sent_closes_without_sending() {
        let mut s = socket_syn_sent();
        s.orphan(Instant::ZERO);
        assert_eq!(s.state(), State::Closed);
        assert_eq!(s.remote_endpoint(), None);
        recv_nothing(&mut s, Instant::ZERO);
    }

    #[test]
    fn orphan_syn_received_sends_one_rst() {
        let mut s = socket_syn_received();
        s.listen_endpoint = LISTEN_END;
        s.orphan(Instant::ZERO);
        assert_eq!(s.state(), State::Closed);
        recv(&mut s, Instant::ZERO, |reply| {
            assert_eq!(reply.unwrap().control, TcpControl::Rst);
        });
        assert_eq!(s.remote_endpoint(), None);
        recv_nothing(&mut s, Instant::ZERO);
    }

    #[test]
    fn orphan_close_wait_sends_fin() {
        let mut s = socket_close_wait();
        s.orphan(Instant::ZERO);
        assert_eq!(s.state(), State::LastAck);
        recv(&mut s, Instant::ZERO, |reply| {
            let reply = reply.unwrap();
            assert_eq!(reply.control, TcpControl::Fin);
            assert!(reply.payload.is_empty());
        });
        recv_nothing(&mut s, Instant::ZERO);
    }

    #[test]
    fn orphan_fin_wait_new_data_sends_one_rst() {
        for fin_wait_2 in [false, true] {
            for seq in [REMOTE_SEQ, REMOTE_SEQ + 1, REMOTE_SEQ + 4] {
                let mut s = if fin_wait_2 { socket_fin_wait_2() } else { socket_fin_wait_1() };
                s.orphan(Instant::ZERO);
                let ack = s.local_seq_no;
                let reply = send(&mut s, Instant::ZERO, &TcpRepr {
                    seq_number: seq,
                    ack_number: Some(ack),
                    payload: b"new",
                    ..SEND_TEMPL
                }).unwrap();
                assert_eq!(reply.control, TcpControl::Rst);
                assert_eq!(reply.seq_number, ack);
                assert_eq!(reply.ack_number, None);
                assert_eq!(s.state(), State::Closed);
                assert_eq!(s.recv_queue(), 0);
                assert_eq!(s.remote_endpoint(), None);
                recv_nothing(&mut s, Instant::ZERO);
            }
        }
    }

    #[test]
    fn owned_fin_wait_2_queues_new_data() {
        let mut s = socket_fin_wait_2();
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 2),
            payload: b"new",
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::FinWait2);
        assert_eq!(s.recv_queue(), 3);
        assert_eq!(drain_bytes(&mut s), b"new");
    }

    #[test]
    fn orphan_fin_wait_retransmission_sends_ack() {
        for fin_wait_2 in [false, true] {
            let mut s = if fin_wait_2 { socket_fin_wait_2() } else { socket_fin_wait_1() };
            s.orphan(Instant::ZERO);
            let state = s.state();
            let ack = s.local_seq_no;
            let reply = send(&mut s, Instant::ZERO, &TcpRepr {
                seq_number: REMOTE_SEQ - 2,
                ack_number: Some(ack),
                payload: b"old",
                ..SEND_TEMPL
            }).unwrap();
            assert_eq!(reply.control, TcpControl::None);
            assert_eq!(reply.ack_number, Some(REMOTE_SEQ + 1));
            assert_eq!(s.state(), state);
            assert_eq!(s.recv_queue(), 0);
            assert_eq!(s.remote_endpoint(), Some(REMOTE_END));
            if !fin_wait_2 {
                recv(&mut s, Instant::ZERO, |reply| {
                    assert_eq!(reply.unwrap().control, TcpControl::Fin);
                });
            }
            recv_nothing(&mut s, Instant::ZERO);
        }
    }

    #[test]
    fn orphan_fin_ack_arms_fin_wait_2_timeout() {
        let mut s = socket_established();
        s.orphan(Instant::from_millis(30));
        recv(&mut s, Instant::from_millis(30), |reply| {
            assert_eq!(reply.unwrap().control, TcpControl::Fin);
        });
        send!(s, time 40, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 2),
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::FinWait2);
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Time(Instant::from_millis(60_040)));
        recv_nothing(&mut s, Instant::from_millis(60_039));
        assert_eq!(s.state(), State::FinWait2);
        recv_nothing(&mut s, Instant::from_millis(60_040));
        assert_eq!(s.state(), State::Closed);
        assert_eq!(s.remote_endpoint(), None);
        assert!(!s.orphaned);
    }

    #[test]
    fn orphan_fin_wait_2_arms_timeout_from_drop() {
        let mut s = socket_fin_wait_2();
        s.orphan(Instant::from_millis(70));
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Time(Instant::from_millis(60_070)));
        recv_nothing(&mut s, Instant::from_millis(60_069));
        assert_eq!(s.state(), State::FinWait2);
        recv_nothing(&mut s, Instant::from_millis(60_070));
        assert_eq!(s.state(), State::Closed);
        assert_eq!(s.remote_endpoint(), None);
    }

    #[test]
    fn orphan_fin_wait_2_peer_fin_uses_time_wait_delay() {
        let mut s = socket_fin_wait_2();
        s.orphan(Instant::from_millis(100));
        send!(s, time 200, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 2),
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::TimeWait);
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(10_200)));
        recv(&mut s, Instant::from_millis(200), |reply| {
            let reply = reply.unwrap();
            assert_eq!(reply.control, TcpControl::None);
            assert_eq!(reply.ack_number, Some(REMOTE_SEQ + 2));
        });
        recv_nothing(&mut s, Instant::from_millis(10_199));
        assert_eq!(s.state(), State::TimeWait);
        recv_nothing(&mut s, Instant::from_millis(10_200));
        assert_eq!(s.state(), State::Closed);
        assert_eq!(s.remote_endpoint(), None);
    }

    #[test]
    fn owned_fin_wait_2_keeps_waiting() {
        let mut s = socket_fin_wait_2();
        recv_nothing(&mut s, Instant::from_secs(120));
        assert_eq!(s.state(), State::FinWait2);
        assert_eq!(s.remote_endpoint(), Some(REMOTE_END));
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Ingress);
    }

    #[test]
    fn orphan_fin_wait_2_ack_and_probes_keep_deadline() {
        let mut s = socket_fin_wait_2();
        s.set_ack_delay(Some(Duration::from_millis(10)));
        s.orphan(Instant::from_millis(100));
        let deadline = PollAt::Time(Instant::from_millis(60_100));
        for at in 200..206 {
            for window in [0, 256] {
                send!(s, time at, TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 2),
                    window_len: window,
                    ..SEND_TEMPL
                });
                assert_eq!(s.socket.poll_at(&mut s.cx), deadline);
            }
            let reply = send(&mut s, Instant::from_millis(at), &TcpRepr {
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 2),
                ..SEND_TEMPL
            });
            if let Some(reply) = reply {
                assert_eq!(reply.control, TcpControl::None);
            }
            assert_eq!(s.socket.poll_at(&mut s.cx), deadline);
            recv_nothing(&mut s, Instant::from_millis(at));
        }
        recv_nothing(&mut s, Instant::from_millis(60_100));
        assert_eq!(s.state(), State::Closed);
    }

    #[test]
    fn reset_clears_orphaned() {
        let mut s = socket_established();
        s.orphan(Instant::ZERO);
        assert!(s.orphaned);
        s.reset();
        assert!(!s.orphaned);
    }

    fn socket_time_wait(from_closing: bool) -> TestSocket {
        let mut s = socket_fin_wait_2();
        s.state = State::TimeWait;
        s.remote_seq_no = REMOTE_SEQ + 1 + 1;
        if from_closing {
            s.remote_last_ack = Some(REMOTE_SEQ + 1 + 1);
        }
        s.timer = Timer::Close {
            expires_at: Instant::from_secs(1) + CLOSE_DELAY,
        };
        s
    }

    fn socket_close_wait() -> TestSocket {
        let mut s = socket_established();
        s.state = State::CloseWait;
        s.remote_seq_no = REMOTE_SEQ + 1 + 1;
        s.remote_last_ack = Some(REMOTE_SEQ + 1 + 1);
        s
    }

    fn socket_last_ack() -> TestSocket {
        let mut s = socket_close_wait();
        s.state = State::LastAck;
        s
    }

    fn socket_recved() -> TestSocket {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 64,
                ..RECV_TEMPL
            }]
        );
        s
    }

    #[test]
    fn poll_at_matches_states() {
        let time = |millis| PollAt::Time(Instant::from_millis(millis));
        let states: &[(&str, fn() -> TestSocket, PollAt)] = &[
            ("closed", socket, PollAt::Ingress),
            ("listen", socket_listen, PollAt::Ingress),
            ("syn sent", socket_syn_sent, PollAt::Now),
            ("syn received", socket_syn_received, PollAt::Now),
            ("established", socket_established, PollAt::Ingress),
            ("fin wait 1", socket_fin_wait_1, PollAt::Now),
            ("fin wait 2", socket_fin_wait_2, PollAt::Ingress),
            ("closing", socket_closing, time(300)),
            ("close wait", socket_close_wait, PollAt::Ingress),
            ("last ack", socket_last_ack, PollAt::Now),
            ("time wait", || socket_time_wait(true), time(11000)),
        ];
        let mut rows = Vec::new();
        for &(name, make, quiet) in states {
            for case in [
                "quiet",
                "data",
                "window full",
                "zero window, data queued, timer idle",
                "fast retransmit",
                "retransmit",
                "window update",
                "ACK idle",
            ] {
                let mut s = make();
                s.remote_last_ack = Some(s.remote_seq_no);
                s.remote_last_win_bytes = 64;
                let has_tuple = s.tuple.is_some();
                let mut expected = quiet;
                match case {
                    "quiet" => {}
                    "data" | "window full" => {
                        assert_eq!(s.tx_buffer.enqueue_slice(b"abcdef"), 6);
                        s.remote_last_seq = s.local_seq_no;
                        s.remote_win_len = 64;
                        expected = PollAt::Now;
                        if case == "window full" {
                            s.remote_last_seq = s.local_seq_no + 3;
                            s.remote_win_len = 3;
                            expected = match name {
                                "closing" => time(300),
                                "time wait" => time(11000),
                                _ => PollAt::Ingress,
                            };
                        }
                    }
                    "fast retransmit" => {
                        s.timer = Timer::FastRetransmit;
                        expected = PollAt::Now;
                    }
                    "zero window, data queued, timer idle" => {
                        assert_eq!(s.tx_buffer.enqueue_slice(b"abcdef"), 6);
                        s.remote_win_len = 0;
                        s.timer = Timer::Idle;
                        expected = PollAt::Now;
                    }
                    "retransmit" => {
                        s.timer = Timer::Retransmit {
                            expires_at: Instant::from_millis(100),
                        };
                        if quiet != PollAt::Now {
                            expected = time(100);
                        }
                    }
                    "window update" => {
                        s.remote_last_win_bytes = 0;
                        let window_update = matches!(
                            s.state(),
                            State::Established | State::FinWait1 | State::FinWait2
                        );
                        assert_eq!(s.window_to_update(), window_update);
                        if window_update {
                            expected = PollAt::Now;
                        } else if matches!(s.state(), State::SynSent | State::SynReceived) {
                            // Sent handshake flags wait for the RTO, without a window update.
                            s.remote_last_seq = s.local_seq_no + 1;
                            s.timer = Timer::Retransmit {
                                expires_at: Instant::from_millis(100),
                            };
                            expected = time(100);
                        }
                    }
                    "ACK idle" => {
                        let decision = s.rx_buffer.store.decide(0, 1, 6);
                        s.rx_buffer.store.place(0, decision);
                        s.rx_buffer.store.attach(RxBuf::from_vec(b"a".to_vec()));
                        assert_eq!(s.rx_buffer.store.in_order_len(), 1);
                        assert_eq!(s.ack_delay_timer(), AckDelayTimer::Idle);
                        expected = PollAt::Now;
                    }
                    _ => unreachable!(),
                }
                if !has_tuple {
                    expected = PollAt::Ingress;
                }
                rows.push((std::format!("{name}: {case}"), s, expected));
            }
            {
                let mut s = make();
                s.remote_last_ack = Some(s.remote_seq_no);
                s.remote_last_win_bytes = 64;
                assert_eq!(s.tx_buffer.enqueue_slice(b"abcdef"), 6);
                s.remote_last_seq = s.local_seq_no + 3;
                s.remote_win_len = 64;
                s.congestion_controller.set_mss(3);
                s.congestion_controller.on_rto(Instant::ZERO, 6);
                let expected = match name {
                    "closing" => time(300),
                    "time wait" => time(11000),
                    _ => PollAt::Ingress,
                };
                rows.push((std::format!("{name}: cwnd full"), s, expected));
            }
        }
        for &(name, make, quiet) in &states[4..] {
            if !matches!(
                name,
                "established" | "fin wait 1" | "fin wait 2" | "close wait"
            ) {
                continue;
            }
            for delay in ["idle", "waiting", "expired", "immediate"] {
                let mut s = if name == "close wait" {
                    socket_established()
                } else {
                    make()
                };

                if delay != "idle" {
                    s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
                }
                s.rcv_mss = 1;
                let seq = s.remote_seq_no;
                let ack = s.local_seq_no;
                send!(
                    s,
                    TcpRepr {
                        control: if name == "close wait" && delay != "immediate" {
                            TcpControl::Fin
                        } else {
                            TcpControl::None
                        },
                        seq_number: seq,
                        ack_number: Some(ack),
                        payload: b"a",
                        ..SEND_TEMPL
                    }
                );
                if delay == "immediate" {
                    send!(
                        s,
                        TcpRepr {
                            control: if name == "close wait" {
                                TcpControl::Fin
                            } else {
                                TcpControl::None
                            },
                            seq_number: seq + 1,
                            ack_number: Some(ack),
                            payload: b"b",
                            ..SEND_TEMPL
                        }
                    );
                }
                if delay == "expired" {
                    s.cx.set_now(Instant::from_millis(20));
                }
                let timer = match delay {
                    "idle" => AckDelayTimer::Idle,
                    "immediate" => AckDelayTimer::Immediate,
                    _ => AckDelayTimer::Waiting(Instant::from_millis(10)),
                };
                assert_eq!(s.ack_delay_timer(), timer, "{name}: ACK {delay}");
                let expected = if matches!(delay, "idle" | "immediate") || quiet == PollAt::Now {
                    PollAt::Now
                } else {
                    time(10)
                };
                rows.push((std::format!("{name}: ACK {delay}"), s, expected));
            }
        }
        let mut aborted = socket_established();
        aborted.abort();
        assert_eq!(aborted.state(), State::Closed);
        assert!(aborted.tuple.is_some());
        rows.push(("aborted".into(), aborted, PollAt::Now));
        for (name, mut s, expected) in rows {
            let poll_at = s.socket.poll_at(&mut s.cx);
            assert_eq!(poll_at, expected, "{name}");
        }
    }

    // =========================================================================================//
    // Tests for the CLOSED state.
    // =========================================================================================//
    #[test]
    fn test_closed_reject() {
        let mut s = socket();
        assert_eq!(s.state, State::Closed);

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_closed_reject_after_listen() {
        let mut s = socket();
        s.listen(LOCAL_END).unwrap();
        s.close();

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_closed_close() {
        let mut s = socket();
        s.close();
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the LISTEN state.
    // =========================================================================================//
    fn socket_listen() -> TestSocket {
        let mut s = socket();
        s.state = State::Listen;
        s.listen_endpoint = LISTEN_END;
        s
    }

    #[test]
    fn test_listen_sack_option() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                sack_permitted: false,
                ..SEND_TEMPL
            }
        );
        assert!(!s.remote_has_sack);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );

        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                sack_permitted: true,
                ..SEND_TEMPL
            }
        );
        assert!(s.remote_has_sack);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn rx_buffer_new_keeps_capacity_and_window_shift() {
        for capacity in [64, 65535, 65536, 1 << 20, 256 << 10] {
            let mut s = socket_syn_sent_with_buffer_sizes(64, capacity);
            assert_eq!(s.recv_capacity(), capacity);
            let shift = rx_win_shift(capacity);
            assert_eq!(s.remote_win_shift, shift);
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: None,
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(shift),
                    // ceil(capacity / 1460), at least 6 frames, x 48 B for active SYN.
                    window_len: u16::try_from(
                        capacity.min(capacity.div_ceil(1460).max(6) * 48),
                    ).unwrap(),
                    sack_permitted: true,
                    ..RECV_TEMPL
                }]
            );
        }
    }

    #[test]
    fn test_listen_syn_win_scale_buffers() {
        for (buffer_size, shift_amt) in &[
            (64, 0),
            (128, 0),
            (1024, 0),
            (65535, 0),
            (65536, 1),
            (65537, 1),
            (131071, 1),
            (131072, 2),
            (524287, 3),
            (524288, 4),
            (655350, 4),
            (1048576, 5),
            ((1 << 30) - 1, 14),
            (1 << 30, 14),
        ] {
            let mut s = socket_with_buffer_sizes(64, *buffer_size);
            s.state = State::Listen;
            s.listen_endpoint = LISTEN_END;
            assert_eq!(s.remote_win_shift, *shift_amt);
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: REMOTE_SEQ,
                    ack_number: None,
                    window_scale: Some(0),
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.remote_win_shift, *shift_amt);
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: Some(REMOTE_SEQ + 1),
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(*shift_amt),
                    // ceil(buffer_size / 1460), at least 6 frames, x 536 B default peer MSS.
                    window_len: u16::try_from(
                        (*buffer_size).min(buffer_size.div_ceil(1460).max(6) * 536),
                    ).unwrap_or(u16::MAX),
                    ..RECV_TEMPL
                }]
            );
        }
    }

    #[test]
    fn passive_scaled_window_waits_for_handshake_ack() {
        let mut s = socket_with_buffer_sizes(64, 524287);
        s.listen(LISTEN_END).unwrap();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.remote_win_shift, 3);
        assert_eq!(s.rx_mbuf_cap, 360);
        assert_eq!(s.rx_seg_bytes, 536);
        recv!(
            s,
            Ok(TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(3),
                window_len: 65535,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.remote_last_win_bytes, 65535);
        recv_nothing!(s);
        assert_eq!(s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(300)));
        recv_nothing!(s, time 299);
        send!(
            s,
            time 299,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        recv!(
            s,
            time 299,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                // 360 free frames x 536 B, divided by scale 8.
                window_len: 24120,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.remote_last_win_bytes, 192960);
    }

    #[test]
    fn test_listen_syn_tiny_mss_is_clamped() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(10),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynReceived);
        assert_eq!(usize::from(s.remote_mss), MIN_REMOTE_MSS);
    }

    #[test]
    fn test_listen_syn_zero_mss_is_ignored() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynReceived);
        assert_eq!(usize::from(s.remote_mss), DEFAULT_MSS);
    }

    #[test]
    fn test_listen_sanity() {
        let mut s = socket();
        s.listen(LOCAL_PORT).unwrap();
        sanity!(s, socket_listen());
    }

    #[test]
    fn test_listen_validation() {
        let mut s = socket();
        assert_eq!(s.listen(0), Err(ListenError::Unaddressable));
    }

    #[test]
    fn test_listen_twice() {
        let mut s = socket();
        assert_eq!(s.listen(80), Ok(()));
        // multiple calls to listen are okay if its the same local endpoint and the state is still in listening
        assert_eq!(s.listen(80), Ok(()));
        s.set_state(State::SynReceived); // state change, simulate incoming connection
        assert_eq!(s.listen(80), Err(ListenError::InvalidState));
    }

    #[test]
    fn test_listen_syn() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.remote_win_seq, REMOTE_SEQ);
        sanity!(s, socket_syn_received());
    }

    #[test]
    fn test_listen_syn_reject_ack() {
        let mut s = socket_listen();

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ),
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));

        assert_eq!(s.state, State::Listen);
    }

    #[test]
    fn test_listen_rst() {
        let mut s = socket_listen();
        let tcp_repr = TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
        assert_eq!(s.state, State::Listen);
    }

    #[test]
    fn test_listen_close() {
        let mut s = socket_listen();
        s.close();
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the SYN-RECEIVED state.
    // =========================================================================================//

    #[test]
    fn test_syn_received_duplicate_syn_resends_identical_syn_ack() {
        for seq in [REMOTE_SEQ, TcpSeqNumber(-1)] {
            let mut s = socket_listen();
            s.set_rto(Duration::from_millis(1000));
            let syn = TcpRepr {
                control: TcpControl::Syn,
                seq_number: seq,
                ack_number: None,
                window_scale: Some(2),
                sack_permitted: true,
                ..SEND_TEMPL
            };
            send!(s, syn);
            let syn_ack = TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(seq + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            };
            recv!(s, [syn_ack.clone()]);
            send!(s, syn);
            recv!(s, [syn_ack.clone()]);
            send!(s, syn);
            recv_nothing!(s);
            send!(s, time 499, syn);
            recv_nothing!(s, time 499);
            send!(s, time 500, syn);
            recv!(s, time 500, [syn_ack]);
            assert_eq!(s.state, State::SynReceived);
        }
    }

    #[test]
    fn test_syn_received_duplicate_syn_cancels_rtt_sample() {
        let mut s = socket_syn_received();
        recv!(s, [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }]);
        assert!(s.rtte.timestamp().is_some());
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        });
        assert!(s.rtte.timestamp().is_none());
        recv!(s, [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }]);
        send!(s, time 100, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Established);
        assert!(!s.rtte.have_measurement);
        assert_eq!(s.retransmission_timeout(), Duration::from_millis(300));
    }

    #[test]
    fn test_syn_received_duplicate_syn_restarts_timer_on_emission() {
        let mut s = socket_syn_received();
        s.set_rto(Duration::from_millis(1000));
        let syn_ack = TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        };
        recv!(s, [syn_ack.clone()]);
        send!(s, time 100, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        });
        assert!(!s.timer.is_retransmit());
        s.cx.set_now(Instant::from_millis(200));
        assert_eq!(s.socket.dispatch(&mut s.cx, |_, _, (_, repr)| {
            assert_eq!(repr, syn_ack);
            Err(())
        }), Err(()));
        assert!(!s.timer.is_retransmit());
        recv!(s, time 300, [syn_ack]);
        assert_eq!(s.timer, Timer::Retransmit {
            expires_at: Instant::from_millis(1300),
        });
        assert_eq!(s.retransmission_timeout(), Duration::from_millis(1000));
        send!(s, time 400, TcpRepr {
            seq_number: REMOTE_SEQ + 256,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        recv_nothing!(s, time 400);
        assert_eq!(s.timer, Timer::Retransmit {
            expires_at: Instant::from_millis(1300),
        });
    }

    #[test]
    fn test_syn_received_different_syn_isn_ignored() {
        let mut s = socket_syn_received();
        recv!(s, [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }]);
        let timer = s.timer;
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ + 1,
            ack_number: None,
            ..SEND_TEMPL
        });
        recv_nothing!(s);
        assert_eq!(s.state, State::SynReceived);
        assert_eq!(s.timer, timer);
        assert!(s.rtte.timestamp().is_some());
        assert_eq!(s.challenge_ack_timer, Instant::from_millis(0));
    }

    #[test]
    fn test_syn_received_ack() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established());
    }

    #[test]
    fn test_syn_received_ack_too_low() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ), // wrong
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::SynReceived);
    }

    #[test]
    fn test_syn_received_ack_too_high() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2), // wrong
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 2,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::SynReceived);
    }

    #[test]
    fn test_syn_received_fin() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6 + 1),
                window_len: 64,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::CloseWait);

        let mut s2 = socket_close_wait();
        s2.remote_last_ack = Some(REMOTE_SEQ + 1 + 6 + 1);
        s2.remote_last_win_bytes = 64;
        sanity!(s, s2);
    }

    #[test]
    fn test_syn_received_rst() {
        let mut s = socket_syn_received();
        s.listen_endpoint = LISTEN_END;
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Listen);
        assert_eq!(s.listen_endpoint, LISTEN_END);
        assert_eq!(s.tuple, None);
        // Back to Listen, not closed: no peer reset to report.
        assert!(!s.reset_by_peer());
    }

    #[test]
    fn test_syn_received_rst_not_at_rcv_nxt_challenge_ack() {
        let mut s = socket_syn_received_with_buffer_sizes(65535, 65535);
        s.listen_endpoint = LISTEN_END;
        let window = u16::try_from(s.recv_room()).unwrap();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: window,
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + usize::from(window) - 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 32767,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: window,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        assert!(!s.reset_by_peer());
        recv_nothing!(s);
    }

    #[test]
    fn test_syn_received_rst_outside_window_silent() {
        let mut s = socket_syn_received_with_buffer_sizes(65535, 65535);
        s.listen_endpoint = LISTEN_END;
        let window = u16::try_from(s.recv_room()).unwrap();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: window,
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + usize::from(window),
                ack_number: None,
                window_len: 32767,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        recv_nothing!(s);
    }

    /// A listener whose SYN-RECEIVED ends in an RST serves the next client as a fresh
    /// listener: window scale is negotiated again and the previous client's MSS is
    /// forgotten.
    #[test]
    fn test_syn_received_rst_then_syn_renegotiates() {
        let mut s = socket_with_buffer_sizes(64, 131072);
        s.socket.listen(LISTEN_END).unwrap();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(600),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_len: 54000, // 90 frames x 600 B peer MSS.
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Listen);

        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                window_scale: Some(7),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_len: 48240, // 90 frames x 536 B default peer MSS.
                window_scale: Some(2),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(usize::from(s.remote_mss), DEFAULT_MSS);
    }

    /// SYN-ACK retransmissions back off the RTO; after an RST in SYN-RECEIVED the next
    /// client's SYN-ACK is retransmitted after the initial 1 s again.
    #[test]
    fn test_syn_received_rst_then_syn_initial_rto() {
        let mut s = socket();
        s.socket.listen(LISTEN_END).unwrap();
        let syn = TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        };
        let syn_ack = TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        };
        send!(s, time 0, syn);
        recv!(s, time 0, [syn_ack]);
        recv!(s, time 300, [syn_ack]);
        recv_nothing!(s, time 899);
        recv!(s, time 900, [syn_ack]);
        send!(
            s,
            time 1000,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Listen);

        send!(s, time 1200, syn);
        recv!(s, time 1200, [syn_ack]);
        recv_nothing!(s, time 1499);
        recv!(s, time 1500, [syn_ack]);
    }

    #[test]
    fn window_scale_14_max_window_fits() {
        const WINDOW: usize = 1_073_725_440;
        let mut s = socket_with_buffer_sizes(WINDOW + 1, 64);
        s.set_initial_window(WINDOW + 1);
        s.listen(LISTEN_END).unwrap();
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            window_len: 65535,
            window_scale: Some(14),
            max_seg_size: Some(BASE_MSS),
            ..SEND_TEMPL
        });
        assert_eq!(s.remote_win_len, 65535);
        recv(&mut s, Instant::ZERO, |result| {
            assert_eq!(result.unwrap().control, TcpControl::Syn);
        });
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 65535,
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_win_len as usize, WINDOW);
        assert_eq!(s.max_snd_wnd as usize, WINDOW);
        assert_eq!(s.send(|buffer| (buffer.len(), buffer.len())), Ok(WINDOW + 1));
        let mut sent = 0;
        while sent < WINDOW {
            recv(&mut s, Instant::ZERO, |result| {
                let repr = result.unwrap();
                assert_eq!(repr.seq_number, LOCAL_SEQ + 1 + sent);
                assert_eq!(repr.payload.len(), (WINDOW - sent).min(usize::from(BASE_MSS)));
                sent += repr.payload.len();
            });
        }
        assert_eq!(sent, WINDOW);
        assert_eq!(s.flight_size(), WINDOW);
        assert!(s.cwnd_remaining() > 0);
        assert!(!s.socket.seq_to_transmit(&mut s.cx));
        recv_nothing!(s);
    }

    #[test]
    fn fresh_connection_sends_up_to_min_peer_window_and_initial_window() {
        for (window, scale, initial, expected) in [
            (32768, 0, None, 32768),
            (32768, 6, None, 1_048_576),
            (32768, 0, Some(3000), 3000),
        ] {
            let mut s = socket_with_buffer_sizes(2_097_152, 8192);
            if let Some(bytes) = initial {
                s.set_initial_window(bytes);
            }
            s.socket.listen(LISTEN_END).unwrap();
            send!(s, TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                window_len: window,
                window_scale: Some(scale),
                max_seg_size: Some(BASE_MSS),
                ..SEND_TEMPL
            });
            recv(&mut s, Instant::ZERO, |result| {
                assert_eq!(result.unwrap().control, TcpControl::Syn);
            });
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: window,
                ..SEND_TEMPL
            });
            assert_eq!(s.send_slice(&vec![0; 2_097_152]), Ok(2_097_152));
            let mut sent = 0;
            loop {
                let mut len = 0;
                s.socket
                    .dispatch(&mut s.cx, |_, _, (_, repr)| {
                        assert_eq!(repr.seq_number, LOCAL_SEQ + 1 + sent);
                        len = repr.payload.len();
                        assert_eq!(len, (expected - sent).min(BASE_MSS as usize));
                        Ok::<(), ()>(())
                    })
                    .unwrap();
                if len == 0 {
                    break;
                }
                sent += len;
            }
            assert_eq!(sent, expected);
            recv_nothing!(s);
        }
    }

    #[test]
    fn peer_window_limits_flight_without_reducing_initial_cwnd() {
        const WINDOW: usize = 65536;
        const INITIAL: usize = 1_048_576;
        let mut s = socket_with_buffer_sizes(2_097_152, 8192);
        s.listen(LISTEN_END).unwrap();
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            window_len: 1024,
            window_scale: Some(6),
            max_seg_size: Some(BASE_MSS),
            ..SEND_TEMPL
        });
        recv(&mut s, Instant::ZERO, |result| {
            assert_eq!(result.unwrap().control, TcpControl::Syn);
        });
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 1024,
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::Established);
        assert_eq!(s.congestion_window(), INITIAL);
        assert_eq!(s.remote_win_len as usize, WINDOW);
        assert_eq!(s.send_slice(&vec![0; 2_097_152]), Ok(2_097_152));
        assert_eq!(flight(&mut s, 0), WINDOW);
        assert_eq!(s.flight_size(), WINDOW);
        let mut prior = 0;
        for acked in [usize::from(BASE_MSS), 2 * usize::from(BASE_MSS), WINDOW] {
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + acked),
                window_len: 1024,
                ..SEND_TEMPL
            });
            assert_eq!(s.congestion_window(), INITIAL);
            assert_eq!(s.flight_size(), WINDOW - (acked - prior));
            assert_eq!(flight(&mut s, 0), acked - prior);
            assert_eq!(s.flight_size(), WINDOW);
            assert!(!s.socket.seq_to_transmit(&mut s.cx));
            recv_nothing!(s);
            prior = acked;
        }
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + WINDOW),
            window_len: 32768,
            ..SEND_TEMPL
        });
        assert_eq!(s.congestion_window(), INITIAL);
        assert_eq!(s.remote_win_len as usize, 2_097_152);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + WINDOW + usize::from(BASE_MSS)),
            window_len: 32768,
            ..SEND_TEMPL
        });
        assert_eq!(s.congestion_window(), INITIAL + usize::from(BASE_MSS));
    }

    #[test]
    fn google_fr_four_packet_initial_window_and_repair() {
        let mut s = socket_with_buffer_sizes(131072, 131072);
        s.socket.listen(LISTEN_END).unwrap();
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            window_len: 32792,
            window_scale: Some(7),
            max_seg_size: Some(BASE_MSS),
            ..SEND_TEMPL
        });
        recv(&mut s, Instant::ZERO, |result| {
            assert_eq!(result.unwrap().control, TcpControl::Syn);
        });
        let ack = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 257,
            ..SEND_TEMPL
        };
        send!(s, ack);
        for index in 0..4 {
            let time = index * 10;
            send!(s, time time, TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 1 + index as usize * BASE_MSS as usize,
                payload: &[0; 1460],
                ..ack
            });
            assert_eq!(s.send_slice(&[0; 1460]), Ok(1460));
            recv(&mut s, Instant::from_millis(time), |result| {
                let repr = result.unwrap();
                assert_eq!(
                    repr.seq_number,
                    LOCAL_SEQ + 1 + index as usize * BASE_MSS as usize
                );
                assert_eq!(
                    repr.ack_number,
                    Some(REMOTE_SEQ + 1 + (index as usize + 1) * BASE_MSS as usize)
                );
                assert_eq!(repr.payload.len(), BASE_MSS as usize);
            });
        }
        let dup_ack = TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 5840,
            ..ack
        };
        for index in 0..3 {
            send!(s, time 130, dup_ack);
            if index < 2 {
                recv_nothing!(s, time 130);
            }
        }
        recv(&mut s, Instant::from_millis(130), |result| {
            let repr = result.unwrap();
            assert_eq!(repr.seq_number, LOCAL_SEQ + 1);
            assert_eq!(repr.payload.len(), BASE_MSS as usize);
            assert_eq!(repr.control, TcpControl::None);
        });
        send!(s, time 230, TcpRepr {
            ack_number: Some(LOCAL_SEQ + 1 + 5840),
            ..dup_ack
        });
        assert_eq!(s.send_queue(), 0);
        recv_nothing!(s, time 230);
    }

    /// Payload bytes of the segments `dispatch` sends at `time` until it sends no more data.
    fn flight(s: &mut TestSocket, time: i64) -> usize {
        s.cx.set_now(Instant::from_millis(time));
        let mut total = 0;
        loop {
            let mut len = 0;
            s.socket
                .dispatch(&mut s.cx, |_, _, (_, repr)| {
                    len = repr.payload.len();
                    Ok::<(), ()>(())
                })
                .unwrap();
            if len == 0 {
                return total;
            }
            total += len;
        }
    }

    /// Accepts a connection on a listening socket and queues 8 KiB to send.
    fn accept_and_queue(mut s: &mut TestSocket) {
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                window_len: 65535,
                max_seg_size: Some(BASE_MSS),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            Ok(TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_len: 8192,
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 65535,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.send_slice(&[0; 8192]), Ok(8192));
    }

    /// A listener reused after a connection whose congestion window grew starts the next
    /// connection with its configured initial window, not the grown one.
    #[test]
    fn test_reused_listener_first_flight_is_initial_window() {
        let mut s = socket_with_buffer_sizes(8192, 8192);
        s.set_initial_window(2048);
        s.socket.listen(LISTEN_END).unwrap();

        accept_and_queue(&mut s);
        assert_eq!(flight(&mut s, 0), 2048);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 2048),
                window_len: 65535,
                ..SEND_TEMPL
            }
        );
        // Slow start adds the 2048 acknowledged bytes.
        assert_eq!(flight(&mut s, 0), 4096);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);

        s.socket.listen(LISTEN_END).unwrap();
        accept_and_queue(&mut s);
        assert_eq!(flight(&mut s, 0), 2048);
    }

    /// A socket that connects again sends a fresh SYN with its original option offers.
    #[test]
    fn test_reconnect_syn_starts_fresh_connection() {
        let mut s = socket();
        let syn = TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        };
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        recv!(s, [syn]);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);

        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        recv!(s, [syn]);
    }

    /// listen() after a connection leaves no per-connection state from it: the dup-ACK
    /// tracking, the pending fast retransmit, and the SACK state.
    #[test]
    fn test_listen_after_connection_clears_connection_state() {
        let mut s = socket_established();
        s.remote_has_sack = true;
        s.send_slice(b"abc").unwrap();
        recv!(
            s,
            time 0,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abc"[..],
                ..RECV_TEMPL
            })
        );
        // Data then two duplicate ACKs.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"x"[..],
                ..SEND_TEMPL
            }
        );
        for _ in 0..2 {
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    ..SEND_TEMPL
                }
            );
        }
        assert_eq!(s.local_rx_dup_acks, 2);
        assert_eq!(s.local_rx_last_ack(), Some(LOCAL_SEQ + 1));
        assert!(s.local_rx_last_seq().is_some());
        // Set directly: however it was left pending, the next connection must not start
        // with a fast retransmit.
        s.pending_fast_retransmit = true;
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);

        s.socket.listen(LISTEN_END).unwrap();
        assert_eq!(s.local_rx_dup_acks, 0);
        assert_eq!(s.local_rx_last_ack(), None);
        assert_eq!(s.local_rx_last_seq(), None);
        assert!(!s.pending_fast_retransmit);
        assert!(!s.remote_has_sack);
    }

    /// Accepts a connection whose SYN carries `mss` (None: no MSS option) and
    /// queues `len` bytes, peer window 65535, with a configured initial window.
    fn accept_with_mss(mss: Option<u16>, len: usize, initial_window: usize) -> TestSocket {
        let mut s = socket_with_buffer_sizes(16384, 4096);
        s.set_initial_window(initial_window);
        s.socket.listen(LISTEN_END).unwrap();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                window_len: 65535,
                max_seg_size: mss,
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            Ok(TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                // 6 frames x min(our 1460 B MSS, peer MSS or default 536 B).
                window_len: 4096.min(6 * mss.map_or(536, |mss| mss.min(BASE_MSS))),
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 65535,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.send_slice(&vec![0; len]), Ok(len));
        s
    }

    /// A SYN without MSS leaves the send MSS at 536 (RFC 9293 3.7.1). After an RTO,
    /// Cubic's one-segment window is 536 bytes.
    #[test]
    fn test_rto_window_is_effective_mss_without_mss_option() {
        let mut s = accept_with_mss(None, 2048, 2048);
        assert_eq!(flight(&mut s, 0), 2048);
        assert_eq!(flight(&mut s, 300), DEFAULT_MSS);
    }

    /// In fast recovery each further duplicate ACK lets one more full 1460-byte segment out.
    #[test]
    fn test_fast_recovery_dup_ack_credit_is_effective_mss() {
        let mut s = accept_with_mss(Some(BASE_MSS), 16384, 2048);
        assert_eq!(flight(&mut s, 0), 2048);
        let dup_ack = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 65535,
            ..SEND_TEMPL
        };
        for _ in 0..3 {
            send!(s, dup_ack);
        }
        assert_eq!(s.local_rx_dup_acks, 3);
        // The fast retransmit and the new data the recovery window allows.
        flight(&mut s, 0);
        send!(s, dup_ack);
        assert_eq!(flight(&mut s, 0), BASE_MSS as usize);
    }

    /// Slow start credits all acknowledged bytes even when the peer MSS exceeds ours.
    #[test]
    fn cubic_grows_by_acknowledged_bytes_with_larger_peer_mss() {
        let mut s = accept_with_mss(Some(8960), 16384, 2048);
        assert_eq!(flight(&mut s, 0), 2048);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 2048),
                window_len: 65535,
                ..SEND_TEMPL
            }
        );
        assert_eq!(flight(&mut s, 0), 4096);
    }

    /// After an RTO, Cubic's window is one segment of our send size (1460), whatever the
    /// peer's larger MSS (8960).
    #[test]
    fn rto_cwnd_is_effective_mss() {
        let mut s = accept_with_mss(Some(8960), 4096, 2048);
        assert_eq!(flight(&mut s, 0), 2048);
        assert_eq!(flight(&mut s, 300), BASE_MSS as usize);
    }

    #[test]
    fn cubic_loss_uses_seventy_percent_of_flight() {
        for (initial, threshold) in [(12000, 8400), (2048, 2920)] {
            let mut s = accept_with_mss(Some(BASE_MSS), 16384, initial);
            assert_eq!(flight(&mut s, 0), initial);
            let ack = TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 65535,
                ..SEND_TEMPL
            };
            for _ in 0..3 {
                send!(s, ack);
            }
            recv(&mut s, Instant::ZERO, |result| {
                let repr = result.unwrap();
                assert_eq!(repr.seq_number, LOCAL_SEQ + 1);
                assert_eq!(repr.payload.len(), BASE_MSS as usize);
            });
            assert_eq!(
                s.congestion_controller.window(),
                threshold + 3 * BASE_MSS as usize
            );
            send!(s, TcpRepr {
                ack_number: Some(LOCAL_SEQ + 1 + initial),
                ..ack
            });
            assert_eq!(s.congestion_controller.window(), threshold);
        }
    }

    #[test]
    fn cubic_partial_window_ack_credits_acknowledged_bytes() {
        let mut s = accept_with_mss(Some(BASE_MSS), 16384, 4096);
        assert_eq!(flight(&mut s, 0), 4096);
        for (acked, window, allowance) in [(512, 4608, 1024), (2048, 6144, 3072)] {
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + acked),
                window_len: 65535,
                ..SEND_TEMPL
            });
            assert_eq!(s.congestion_controller.window(), window);
            assert_eq!(flight(&mut s, 0), allowance);
        }
    }

    #[test]
    fn cubic_idle_preserves_window() {
        let mut s = accept_with_mss(Some(BASE_MSS), 4096, 4096);
        assert_eq!(flight(&mut s, 0), 4096);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 4096),
            window_len: 65535,
            ..SEND_TEMPL
        });
        assert_eq!(s.congestion_controller.window(), 8192);
        assert_eq!(s.send_queue(), 0);
        recv_nothing!(s, time 10000);
        s.send_slice(&[0; 8192]).unwrap();
        assert_eq!(flight(&mut s, 10000), 8192);
        assert_eq!(s.congestion_controller.window(), 8192);
    }

    #[test]
    fn handshake_rto_active_restarts_slow_start() {
        for peer_mss in [None, Some(536), Some(1024), Some(8960)] {
            let mut s = socket_with_buffer_sizes(8192, 8192);
            s.socket
                .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
                .unwrap();
            for time in [0, 300] {
                recv(&mut s, Instant::from_millis(time), |result| {
                    let repr = result.unwrap();
                    assert_eq!(repr.control, TcpControl::Syn);
                    assert_eq!(repr.seq_number, LOCAL_SEQ);
                    assert!(repr.payload.is_empty());
                });
            }
            send!(s, time 300, TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 65535,
                max_seg_size: peer_mss,
                ..SEND_TEMPL
            });
            assert_eq!(s.state(), State::Established);
            let mss = peer_mss.unwrap_or(DEFAULT_MSS as u16).min(BASE_MSS) as usize;
            s.congestion_controller.assert_handshake_restart(mss);
            recv(&mut s, Instant::from_millis(300), |result| {
                let repr = result.unwrap();
                assert_eq!(repr.control, TcpControl::None);
                assert!(repr.payload.is_empty());
            });
            assert_eq!(s.send_slice(&[0; 8192]), Ok(8192));
            recv(&mut s, Instant::from_millis(300), |result| {
                let repr = result.unwrap();
                assert_eq!(repr.seq_number, LOCAL_SEQ + 1);
                assert_eq!(repr.payload.len(), mss);
            });
            recv_nothing!(s, time 300);
            assert_eq!(s.congestion_controller.window(), mss);
            send!(s, time 300, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + mss),
                window_len: 65535,
                ..SEND_TEMPL
            });
            assert_eq!(s.congestion_controller.window(), 2 * mss);
            assert_eq!(flight(&mut s, 300), 2 * mss);
        }
    }

    #[test]
    fn handshake_rto_passive_restarts_slow_start() {
        for peer_mss in [None, Some(536), Some(1024), Some(8960)] {
            let mut s = socket_with_buffer_sizes(8192, 8192);
            s.listen(LISTEN_END).unwrap();
            send!(s, TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                window_len: 65535,
                max_seg_size: peer_mss,
                ..SEND_TEMPL
            });
            assert_eq!(s.state(), State::SynReceived);
            for time in [0, 300] {
                recv(&mut s, Instant::from_millis(time), |result| {
                    let repr = result.unwrap();
                    assert_eq!(repr.control, TcpControl::Syn);
                    assert_eq!(repr.seq_number, LOCAL_SEQ);
                    assert_eq!(repr.ack_number, Some(REMOTE_SEQ + 1));
                    assert!(repr.payload.is_empty());
                });
            }
            assert_eq!(s.loss_events(), 1);
            assert_eq!(s.retransmits(), 1);
            send!(s, time 300, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 65535,
                ..SEND_TEMPL
            });
            assert_eq!(s.state(), State::Established);
            let mss = peer_mss.unwrap_or(DEFAULT_MSS as u16).min(BASE_MSS) as usize;
            s.congestion_controller.assert_handshake_restart(mss);
            assert_eq!(s.send_slice(&[0; 8192]), Ok(8192));
            assert_eq!(flight(&mut s, 300), mss);
            send!(s, time 300, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + mss),
                window_len: 65535,
                ..SEND_TEMPL
            });
            assert_eq!(s.congestion_window(), 2 * mss);
            assert_eq!(flight(&mut s, 300), 2 * mss);
        }
    }

    #[test]
    fn cubic_fix_simultaneous_open_after_handshake_rto_restarts_slow_start() {
        let mut s = socket_with_buffer_sizes(8192, 8192);
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        for time in [0, 300] {
            recv(&mut s, Instant::from_millis(time), |result| {
                let repr = result.unwrap();
                assert_eq!(repr.control, TcpControl::Syn);
                assert_eq!(repr.seq_number, LOCAL_SEQ);
                assert_eq!(repr.ack_number, None);
            });
        }
        assert_eq!(s.loss_events(), 1);
        assert_eq!(s.retransmits(), 1);
        send!(s, time 300, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            window_len: 65535,
            max_seg_size: Some(536),
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::SynReceived);
        recv(&mut s, Instant::from_millis(300), |result| {
            let repr = result.unwrap();
            assert_eq!(repr.control, TcpControl::Syn);
            assert_eq!(repr.ack_number, Some(REMOTE_SEQ + 1));
        });
        send!(s, time 300, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 65535,
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::Established);
        s.congestion_controller.assert_handshake_restart(536);
    }

    #[test]
    fn cubic_fix_passive_fin_completes_handshake_with_and_without_rto() {
        for lost in [false, true] {
            let mut s = socket_with_buffer_sizes(8192, 8192);
            s.set_initial_window(3000);
            s.listen(LISTEN_END).unwrap();
            send!(s, TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                window_len: 65535,
                max_seg_size: Some(536),
                ..SEND_TEMPL
            });
            recv(&mut s, Instant::ZERO, |result| {
                let repr = result.unwrap();
                assert_eq!(repr.control, TcpControl::Syn);
                assert_eq!(repr.ack_number, Some(REMOTE_SEQ + 1));
            });
            let time = if lost { 300 } else { 0 };
            if lost {
                recv(&mut s, Instant::from_millis(time), |result| {
                    assert_eq!(result.unwrap().control, TcpControl::Syn);
                });
            }
            send!(s, time time, TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 65535,
                ..SEND_TEMPL
            });
            assert_eq!(s.state(), State::CloseWait);
            assert_eq!(s.loss_events(), u64::from(lost));
            assert_eq!(s.retransmits(), u64::from(lost));
            if lost {
                s.congestion_controller.assert_handshake_restart(536);
            } else {
                assert_eq!(s.congestion_window(), 3000);
            }
        }
    }

    #[test]
    fn passive_without_handshake_rto_keeps_configured_initial_window() {
        for initial in [2048, 3000, 1_048_576] {
            let s = accept_with_mss(Some(BASE_MSS), 0, initial);
            assert_eq!(s.state(), State::Established);
            assert_eq!(s.congestion_window(), initial);
            assert_eq!(s.loss_events(), 0);
            assert_eq!(s.retransmits(), 0);
        }
    }

    #[test]
    fn active_without_syn_loss_sends_full_initial_window() {
        let mut s = socket_with_buffer_sizes(2_097_152, 8192);
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        recv(&mut s, Instant::ZERO, |result| {
            assert_eq!(result.unwrap().control, TcpControl::Syn);
        });
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 32768,
            window_scale: Some(6),
            max_seg_size: Some(BASE_MSS),
            ..SEND_TEMPL
        });
        recv(&mut s, Instant::ZERO, |result| {
            assert!(result.unwrap().payload.is_empty());
        });
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 32768,
            ..SEND_TEMPL
        });
        assert_eq!(s.send_slice(&vec![0; 2_097_152]), Ok(2_097_152));
        assert_eq!(flight(&mut s, 0), 1_048_576);
        recv_nothing!(s);
    }

    #[test]
    fn set_initial_window_persists_across_reconnect() {
        let mut s = socket_with_buffer_sizes(8192, 8192);
        s.set_initial_window(3000);
        for _ in 0..2 {
            s.socket
                .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
                .unwrap();
            recv(&mut s, Instant::ZERO, |result| {
                assert_eq!(result.unwrap().control, TcpControl::Syn);
            });
            send!(s, TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 65535,
                max_seg_size: Some(BASE_MSS),
                ..SEND_TEMPL
            });
            recv(&mut s, Instant::ZERO, |result| {
                assert!(result.unwrap().payload.is_empty());
            });
            s.send_slice(&[0; 8192]).unwrap();
            assert_eq!(flight(&mut s, 0), 3000);
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 3000),
                window_len: 65535,
                ..SEND_TEMPL
            });
            assert_eq!(s.congestion_controller.window(), 6000);
            send!(s, TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            });
            assert_eq!(s.state(), State::Closed);
        }
    }

    #[test]
    #[should_panic]
    fn set_initial_window_rejects_zero() {
        socket().set_initial_window(0);
    }

    /// Accepts a connection, delayed ACK on (10 ms), whose SYN carries MSS `peer_mss` and
    /// no TS or wscale; 16 KiB receive buffer.
    fn accept_delayed_ack(peer_mss: u16) -> TestSocket {
        accept_delayed_ack_with_rx_size(peer_mss, 16384)
    }

    fn accept_delayed_ack_with_rx_size(peer_mss: u16, rx_len: usize) -> TestSocket {
        let mut s = socket_with_buffer_sizes(64, rx_len);
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        s.socket.listen(LISTEN_END).unwrap();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                window_len: 65535,
                max_seg_size: Some(peer_mss),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            Ok(TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                // ceil(rx_len / 1460), at least 6 frames, x min(our MSS, peer MSS).
                window_len: rx_len.min(
                    rx_len.div_ceil(1460).max(6) * usize::from(peer_mss.min(BASE_MSS)),
                ) as u16,
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 65535,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        s
    }

    #[test]
    fn rcv_mss_init_peer_mss_200() {
        let mut s = accept_delayed_ack(200);
        for n in 0..2 {
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + n * 200,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &[0; 200],
                    ..SEND_TEMPL
                }
            );
            if n == 0 {
                recv_nothing!(s);
            }
        }
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 401),
                // 10 free frames x 200 B peer MSS.
                window_len: 2000,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.rcv_mss, 200);
    }

    #[test]
    fn rcv_mss_init_half_receive_window() {
        let mut s = accept_delayed_ack_with_rx_size(BASE_MSS, 512);
        for n in 0..2 {
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + n * 256,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &[0; 256],
                    ..SEND_TEMPL
                }
            );
            if n == 0 {
                recv!(s, [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 257),
                window_len: 512,
                ..RECV_TEMPL
            }]);
            }
        }
        recv!(
            s,
            time 10,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 513),
                window_len: 512,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.rcv_mss, 256);
    }

    #[test]
    fn rcv_mss_init_floor_88() {
        let s = accept_delayed_ack_with_rx_size(48, 64);
        assert_eq!(s.rcv_mss, 88);
    }

    #[test]
    fn rcv_mss_init_syn_ack() {
        for (peer_mss, rx_len, expected) in [
            (200, 16384, 200),
            (BASE_MSS, 512, 256),
            (48, 64, 88),
            (8960, 16384, DEFAULT_MSS),
        ] {
            let mut s = socket_with_buffer_sizes(64, rx_len);
            s.socket
                .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
                .unwrap();
            recv(&mut s, Instant::ZERO, |result| {
                assert_eq!(result.unwrap().control, TcpControl::Syn);
            });
            let local_seq = s.local_seq_no;
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: REMOTE_SEQ,
                    ack_number: Some(local_seq + 1),
                    max_seg_size: Some(peer_mss),
                    ..SEND_TEMPL
                }
            );
            recv(&mut s, Instant::ZERO, |result| {
                let ack = result.unwrap();
                assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1));
                // ceil(rx_len / 1460), at least 6 frames, x min(our MSS, peer MSS).
                let window = rx_len.min(
                    rx_len.div_ceil(1460).max(6) * usize::from(peer_mss.min(BASE_MSS)),
                );
                assert_eq!(ack.window_len, window as u16);
            });
            assert_eq!(s.rcv_mss, expected);
        }
    }

    #[test]
    fn rcv_mss_measure_full_overlapping_payload() {
        let mut s = accept_delayed_ack(BASE_MSS);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 1000],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            time 10,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1001),
                window_len: 16060,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            time 10,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 1460],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            time 20,
            [TcpRepr {
                window_len: 15600,
                ..ack_of_segments(1)
            }]
        );
        for (offset, payload) in [(1460, &[0; 600][..]), (2060, &[0; 700][..])] {
            send!(
                s,
                time 20,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload,
                    ..SEND_TEMPL
                }
            );
            recv_nothing!(s, time 20);
        }
        assert_eq!(s.rcv_mss, 1460);
        recv!(
            s,
            time 30,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2761),
                window_len: 14300,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn rcv_mss_measure_ignores_out_of_order() {
        let mut s = accept_delayed_ack(BASE_MSS);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 101,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 1460],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: 16384,
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 100],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1561),
                window_len: 14824,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.rcv_mss, 536);
    }

    #[test]
    fn rcv_mss_measure_before_window_clip_and_cap() {
        let mut s = accept_delayed_ack_with_rx_size(BASE_MSS, 512);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 1600],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.recv_queue(), 512);
        assert_eq!(s.rcv_mss, BASE_MSS as usize);
    }

    /// The peer's `n`-th full segment (from 0), BASE_MSS bytes.
    fn full_segment(n: usize) -> TcpRepr<'static> {
        const DATA: [u8; BASE_MSS as usize] = [0; BASE_MSS as usize];
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + n * BASE_MSS as usize,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 65535,
            payload: &DATA,
            ..SEND_TEMPL
        }
    }

    /// Our ACK of the peer's first `n` full segments, none read by the app.
    fn ack_of_segments(n: usize) -> TcpRepr<'static> {
        TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + n * BASE_MSS as usize),
            window_len: 16384usize.min((12 - n) * BASE_MSS as usize) as u16,
            ..RECV_TEMPL
        }
    }

    /// A peer whose MSS (8960) exceeds ours (1460) sends full 1460-byte segments: the
    /// second one is acknowledged at once, as RFC 9293 3.8.6.3 (an ACK for at least every
    /// second full-sized segment) and Linux do. The threshold is the largest segment
    /// received, not the peer's MSS.
    #[test]
    fn peer_mss_above_local_acks_every_second_segment() {
        let mut s = accept_delayed_ack(8960);
        for pair in 0..2 {
            send!(s, time 0, full_segment(2 * pair));
            recv_nothing!(s, time 0);
            send!(s, time 0, full_segment(2 * pair + 1));
            recv!(s, time 0, [ack_of_segments(2 * pair + 2)]);
        }
    }

    /// One full segment alone waits for the delayed-ACK timer.
    #[test]
    fn single_full_segment_acked_by_delayed_ack_timer() {
        let mut s = accept_delayed_ack(8960);
        send!(s, time 0, full_segment(0));
        recv_nothing!(s, time 0);
        recv_nothing!(s, time 9);
        recv!(s, time 10, [ack_of_segments(1)]);
    }

    /// A reply the app writes before the delayed-ACK timer expires carries the ACK.
    #[test]
    fn reply_carries_the_delayed_ack() {
        let mut s = accept_delayed_ack(8960);
        send!(s, time 0, full_segment(0));
        s.send_slice(b"pong").unwrap();
        recv!(
            s,
            time 0,
            [TcpRepr {
                payload: &b"pong"[..],
                ..ack_of_segments(1)
            }]
        );
    }

    #[test]
    fn test_syn_received_no_window_scaling() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: None,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_scale: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.remote_win_shift, 0);
        assert_eq!(s.remote_win_scale, None);
    }

    #[test]
    fn test_syn_received_window_scaling() {
        for scale in 0..14 {
            let mut s = socket_listen();
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: REMOTE_SEQ,
                    ack_number: None,
                    window_scale: Some(scale),
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.state(), State::SynReceived);
            assert_eq!(s.tuple, Some(TUPLE));
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: Some(REMOTE_SEQ + 1),
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(0),
                    ..RECV_TEMPL
                }]
            );
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    window_scale: None,
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.remote_win_scale, Some(scale));
        }
    }

    #[test]
    fn test_syn_received_close_before_synack() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        s.close();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state(), State::Closed);
        assert_eq!(s.tuple, None);
    }

    #[test]
    fn test_syn_received_close_after_synack() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state(), State::SynReceived);
        s.close();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state(), State::Closed);
        assert_eq!(s.tuple, None);

        let ack = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        };
        let ip_repr = IpRepr::new(
            REMOTE_ADDR.into(),
            LOCAL_ADDR.into(),
            IpProtocol::Tcp,
            ack.buffer_len(),
            64,
        );
        assert!(!s.socket.accepts(&mut s.cx, &ip_repr, &ack));
        assert_eq!(s.state(), State::Closed);
        recv_nothing!(s);
    }

    // =========================================================================================//
    // Tests for the SYN-SENT state.
    // =========================================================================================//

    #[test]
    fn test_connect_validation() {
        let mut s = socket();
        assert_eq!(
            s.socket
                .connect(&mut s.cx, REMOTE_END, (IpvXAddress::UNSPECIFIED, 0)),
            Err(ConnectError::Unaddressable)
        );
        assert_eq!(
            s.socket
                .connect(&mut s.cx, REMOTE_END, (IpvXAddress::UNSPECIFIED, 1024)),
            Err(ConnectError::Unaddressable)
        );
        assert_eq!(
            s.socket
                .connect(&mut s.cx, (IpvXAddress::UNSPECIFIED, 0), LOCAL_END),
            Err(ConnectError::Unaddressable)
        );
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END)
            .expect("Connect failed with valid parameters");
        assert_eq!(s.tuple, Some(TUPLE));
    }

    #[test]
    fn test_connect() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tuple, Some(TUPLE));
    }

    #[test]
    fn test_connect_synack_tiny_mss_is_clamped() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(10),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(usize::from(s.remote_mss), MIN_REMOTE_MSS);
    }

    #[test]
    fn test_connect_synack_zero_mss_is_ignored() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(0),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(usize::from(s.remote_mss), DEFAULT_MSS);
    }

    #[test]
    fn test_connect_unspecified_local() {
        let mut s = socket();
        assert_eq!(s.socket.connect(&mut s.cx, REMOTE_END, 80), Ok(()));
    }

    #[test]
    fn test_connect_specified_local() {
        let mut s = socket();
        assert_eq!(
            s.socket.connect(&mut s.cx, REMOTE_END, (REMOTE_ADDR, 80)),
            Ok(())
        );
    }

    #[test]
    fn test_connect_twice() {
        let mut s = socket();
        assert_eq!(s.socket.connect(&mut s.cx, REMOTE_END, 80), Ok(()));
        assert_eq!(
            s.socket.connect(&mut s.cx, REMOTE_END, 80),
            Err(ConnectError::InvalidState)
        );
    }

    #[test]
    fn test_syn_sent_sanity() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        sanity!(s, socket_syn_sent());
    }

    #[test]
    fn test_poll_at_after_syn_ack_before_syn_dispatch() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
    }

    #[test]
    fn test_syn_sent_syn_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s, time 1000);
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_win_seq, REMOTE_SEQ);
        sanity!(s, socket_established());
    }

    #[test]
    fn test_syn_sent_syn_ack_rst_at_peer_isn_dropped() {
        for peer_isn in [REMOTE_SEQ, TcpSeqNumber(-1), TcpSeqNumber(i32::MAX)] {
            let mut s = socket();
            s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
            recv!(s, [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]);
            send!(s, TcpRepr {
                control: TcpControl::Syn,
                seq_number: peer_isn,
                ack_number: Some(LOCAL_SEQ + 1),
                window_scale: Some(0),
                ..SEND_TEMPL
            });
            assert_eq!(s.state, State::Established);
            assert_eq!(s.remote_last_ack, Some(peer_isn));
            assert_eq!(s.remote_seq_no, peer_isn + 1);
            let timer = s.timer;
            let listen_endpoint = s.listen_endpoint;
            send!(s, TcpRepr {
                control: TcpControl::Rst,
                seq_number: peer_isn,
                ack_number: None,
                ..SEND_TEMPL
            });
            assert_eq!(s.state, State::Established);
            assert_eq!(s.tuple, Some(TUPLE));
            assert_eq!(s.listen_endpoint, listen_endpoint);
            assert_eq!(s.timer, timer);
            assert_eq!(s.remote_last_ack, Some(peer_isn));
            assert_eq!(s.challenge_ack_timer, Instant::from_secs(0));
            recv!(s, [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(peer_isn + 1),
                ..RECV_TEMPL
            }]);
            s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
            send!(s, TcpRepr {
                seq_number: peer_isn + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            });
            recv_nothing!(s);
            let data = drain_bytes(&mut s);
            assert_eq!(data.len(), 1);
            assert_eq!(data, *b"a");
            assert_eq!(s.remote_last_ack, Some(peer_isn + 1));
            assert_eq!(s.remote_seq_no, peer_isn + 2);
            send!(s, TcpRepr {
                control: TcpControl::Rst,
                seq_number: peer_isn + 1,
                ack_number: None,
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(peer_isn + 2),
                ..RECV_TEMPL
            }));
            assert_eq!(s.state, State::Established);
            assert_eq!(s.tuple, Some(TUPLE));
        }
    }

    #[test]
    fn test_syn_sent_syn_received_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );

        // A SYN packet changes the SYN-SENT state to SYN-RECEIVED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynReceived);
        assert_eq!(s.remote_win_seq, REMOTE_SEQ);

        // The socket will then send a SYN|ACK packet.
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s);

        // The socket may retransmit the SYN|ACK packet.
        recv!(
            s,
            time 300,
            Ok(TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                ..RECV_TEMPL
            })
        );

        // An ACK packet changes the SYN-RECEIVED state to ESTABLISHED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established());
    }

    #[test]
    fn test_syn_sent_syn_ack_not_incremented() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ), // WRONG
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_syn_received_rst() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );

        // A SYN packet changes the SYN-SENT state to SYN-RECEIVED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynReceived);

        // A RST packet changes the SYN-RECEIVED state to CLOSED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
        assert!(s.reset_by_peer());
    }

    #[test]
    fn test_syn_sent_rst() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
        assert!(s.reset_by_peer());
    }

    #[test]
    fn test_syn_sent_rst_no_ack() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynSent);
        assert!(!s.reset_by_peer());
    }

    #[test]
    fn test_syn_sent_rst_bad_ack() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: Some(TcpSeqNumber(1234)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None, // Unexpected
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1), // Correct
                ..SEND_TEMPL
            }
        );

        // It should trigger no response and change no state
        recv!(s, []);
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack_seq_1() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ), // WRONG
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ, // matching the ack_number of the unexpected ack
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );

        // It should trigger a RST, and change no state
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack_seq_2() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 123456), // WRONG
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 123456, // matching the ack_number of the unexpected ack
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );

        // It should trigger a RST, and change no state
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_close() {
        let mut s = socket();
        s.close();
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_syn_sent_sack_option() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                sack_permitted: true,
                ..SEND_TEMPL
            }
        );
        assert!(s.remote_has_sack);

        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                sack_permitted: false,
                ..SEND_TEMPL
            }
        );
        assert!(!s.remote_has_sack);
    }

    #[test]
    fn test_syn_sent_win_scale_buffers() {
        for (buffer_size, shift_amt) in &[
            (64, 0),
            (128, 0),
            (1024, 0),
            (65535, 0),
            (65536, 1),
            (65537, 1),
            (131071, 1),
            (131072, 2),
            (524287, 3),
            (524288, 4),
            (655350, 4),
            (1048576, 5),
            ((1 << 30) - 1, 14),
            (1 << 30, 14),
        ] {
            let mut s = socket_with_buffer_sizes(64, *buffer_size);
            s.local_seq_no = LOCAL_SEQ;
            assert_eq!(s.remote_win_shift, *shift_amt);
            s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: None,
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(*shift_amt),
                    // ceil(buffer_size / 1460), at least 6 frames, x 48 B for active SYN.
                    window_len: u16::try_from(
                        (*buffer_size).min(buffer_size.div_ceil(1460).max(6) * 48),
                    ).unwrap_or(u16::MAX),
                    sack_permitted: true,
                    ..RECV_TEMPL
                }]
            );
        }
    }

    #[test]
    fn test_syn_sent_syn_ack_no_window_scaling() {
        let mut s = socket_syn_sent_with_buffer_sizes(1048576, 1048576);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                // scaling does NOT apply to the window value in SYN packets
                window_len: 34512, // 719 frames x 48 B for active SYN.
                window_scale: Some(5),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.remote_win_shift, 5);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: None,
                window_len: 42,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_win_shift, 0);
        assert_eq!(s.remote_win_scale, None);
        assert_eq!(s.remote_win_len, 42);
    }

    #[test]
    fn test_syn_sent_syn_ack_window_scaling() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(7),
                window_len: 42,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_win_scale, Some(7));
        // scaling does NOT apply to the window value in SYN packets
        assert_eq!(s.remote_win_len, 42);
    }

    // =========================================================================================//
    // Tests for the ESTABLISHED state.
    // =========================================================================================//

    #[test]
    fn test_rx_payload_held_without_copy() {
        let mut s = socket_established();
        let frame = RxBuf::from_vec(b"abc".to_vec());
        let pointer = frame.as_slice().as_ptr();
        assert_eq!(
            send_frame(
                &mut s,
                Instant::ZERO,
                &TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: b"abc",
                    ..SEND_TEMPL
                },
                frame
            ),
            None
        );
        assert_eq!(s.recv_queue(), 3);
        {
            let frame = s.recv().unwrap().unwrap();
            let bytes = frame.payload();
            assert_eq!(bytes, b"abc");
            assert_eq!(bytes.as_ptr(), pointer);
        }
    }

    #[test]
    fn drain_returns_whole_frames_in_order() {
        let mut s = socket_established_with_buffer_sizes(64, 4096);
        let payloads = [vec![b'a'; 65], vec![b'b'; 90], vec![b'c'; 120]];
        let mut offset = 0;
        for payload in &payloads {
            receive_window_segment(&mut s, offset, payload);
            offset += payload.len();
        }
        let mut queued = offset;
        for payload in &payloads {
            let mut frame = s.recv().unwrap().unwrap();
            assert_eq!(frame.payload(), payload);
            queued -= payload.len();
            assert_eq!(s.recv_queue(), queued);
            frame.payload_mut().make_ascii_uppercase();
            assert!(frame.payload().iter().all(u8::is_ascii_uppercase));
        }
        assert!(s.recv().unwrap().is_none());
    }

    #[test]
    fn drain_after_append() {
        let mut s = socket_established_with_buffer_sizes(64, 4096);
        let first = vec![b'a'; DEFAULT_MSS];
        let (_, releases) = send_counted_append_frame(&mut s, 0, &first, 80, TcpControl::None);
        for offset in [DEFAULT_MSS, DEFAULT_MSS + 40] {
            let (_, appended) = send_counted_append_frame(
                &mut s, offset, &[b'b'; 40], 0, TcpControl::None,
            );
            assert_eq!(appended.get(), 1);
        }
        let frame = s.recv().unwrap().unwrap();
        let mut expected = first;
        expected.extend_from_slice(&[b'b'; 80]);
        assert_eq!(frame.payload(), expected);
        assert_eq!(s.recv_queue(), 0);
        assert!(s.recv().unwrap().is_none());
        assert_eq!(releases.get(), 0);
        drop(frame);
        assert_eq!(releases.get(), 1);
    }

    #[test]
    fn app_held_frames_close_window_and_reopen_on_drop() {
        let capacity = 6 * usize::from(BASE_MSS);
        let mut s = receive_window_socket(1500, capacity);
        assert_eq!(open_receive_window(&mut s, true, Some(BASE_MSS)), capacity as u16);
        assert_eq!(s.rx_frame_cap(), 6);
        for index in 0..6 {
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1 + index * usize::from(BASE_MSS),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 1460],
                ..SEND_TEMPL
            });
        }
        let mut frames = Vec::new();
        for _ in 0..6 {
            frames.push(s.recv().unwrap().unwrap());
        }
        assert_eq!(s.recv_queue(), 0);
        assert_eq!(s.rx_buffer.shared.held.get(), 6);
        assert_eq!(s.recv_room(), 0);
        assert!(s.ack_to_transmit());
        recv(&mut s, Instant::ZERO, |result| {
            assert_eq!(result.unwrap().window_len, 0);
        });
        drop(frames);
        assert_eq!(s.recv_room(), capacity.min(6 * s.rx_seg_bytes as usize));
        assert!(s.window_to_update());
        recv(&mut s, Instant::ZERO, |result| {
            let ack = result.unwrap();
            assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1 + capacity));
            assert_eq!(usize::from(ack.window_len), capacity);
        });
        recv_nothing!(s);
    }

    #[test]
    fn app_held_frames_refuse_in_window_segment_until_drop() {
        let mut s = receive_window_socket(1500, 4096);
        assert_eq!(open_receive_window(&mut s, true, Some(BASE_MSS)), 4096);
        for index in 0..6 {
            receive_window_segment(&mut s, index * 100, &[b'a'; 100]);
        }
        let previous_ack = s.remote_last_ack.unwrap();
        assert!(s.remote_last_win_bytes >= 100);
        let mut frames = Vec::new();
        for _ in 0..6 {
            frames.push(s.recv().unwrap().unwrap());
        }
        assert_eq!(s.rx_frame_cap(), 6);
        assert_eq!(s.rx_buffer.store.held(), 0);
        assert_eq!(s.rx_buffer.shared.held.get(), 6);
        let ack = receive_window_segment(&mut s, 600, &[b'z'; 100]);
        assert_eq!(s.rx_refused_segments(), 1);
        assert_eq!(ack.ack_number, Some(previous_ack));
        assert_eq!(s.recv_queue(), 0);
        drop(frames);
        let ack = receive_window_segment(&mut s, 600, &[b'z'; 100]);
        assert_eq!(ack.ack_number, Some(previous_ack + 100));
        assert_eq!(s.rx_refused_segments(), 1);
        assert_eq!(drain_bytes(&mut s), vec![b'z'; 100]);
    }

    #[test]
    fn held_frames_survive_reset() {
        let mut s = socket_established_with_buffer_sizes(64, 4096);
        receive_window_segment(&mut s, 0, &[b'a'; 100]);
        let frame = s.recv().unwrap().unwrap();
        s.abort();
        assert_eq!(s.rx_buffer.shared.held.get(), 1);
        s.reset();
        assert_eq!(s.rx_buffer.shared.held.get(), 1);
        assert_eq!(frame.payload(), &[b'a'; 100]);
        let held = s.rx_buffer.shared.clone();
        drop(s);
        assert_eq!(held.held.get(), 1);
        drop(frame);
        assert_eq!(held.held.get(), 0);
    }

    #[test]
    fn test_recv_returns_front_segment() {
        let mut s = socket_established();
        for (seq, payload) in [(REMOTE_SEQ + 1, &b"abc"[..]), (REMOTE_SEQ + 4, &b"def"[..])] {
            send!(
                s,
                TcpRepr {
                    seq_number: seq,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload,
                    ..SEND_TEMPL
                }
            );
        }
        let first = s.recv().unwrap().unwrap();
        assert_eq!(first.payload(), b"abc");
        assert_eq!(s.recv_queue(), 3);
        let second = s.recv().unwrap().unwrap();
        assert_eq!(second.payload(), b"def");
        assert!(s.recv().unwrap().is_none());
        assert_eq!(s.recv_queue(), 0);
    }

    #[test]
    fn pure_ack_at_right_edge_updates_send_state() {
        let mut s = socket_established();
        assert_eq!(s.send_slice(b"sent"), Ok(4));
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"sent",
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.send_queue(), 4);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_max_seq, LOCAL_SEQ + 5);
        assert_eq!(s.remote_win_len, 256);
        let window = s.remote_last_win_bytes as usize;
        assert!(window > 0);
        let right_edge = s.remote_last_ack.unwrap() + window;
        assert_eq!(right_edge, s.remote_seq_no + window);
        send!(
            s,
            time 10,
            TcpRepr {
                seq_number: right_edge,
                ack_number: Some(LOCAL_SEQ + 5),
                window_len: 42,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.send_queue(), 0);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 5);
        assert_eq!(s.remote_win_len, 42);
        recv_nothing!(s, time 10);
    }

    #[test]
    fn pure_ack_at_right_edge_after_cap_refusal_updates_send_state() {
        let mut s = socket_established();
        let cap = s.rx_mbuf_budget(s.cx.ip_mtu());
        for index in 0..cap {
            receive_window_segment(&mut s, index, b"a");
        }
        assert_eq!(s.rx_buffer.store.held(), cap);
        assert_eq!(s.recv_room(), 0);
        assert_eq!(s.send_slice(b"sent"), Ok(4));
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + cap),
                window_len: 63,
                payload: b"sent",
                ..RECV_TEMPL
            }]
        );
        let next_seq = s.remote_last_ack.unwrap();
        let window = s.remote_last_win_bytes as usize;
        assert!(window > 0);
        assert_eq!(next_seq, s.remote_seq_no + s.rx_buffer.store.in_order_len());
        send!(
            s,
            time 10,
            TcpRepr {
                seq_number: next_seq,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"z",
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 5,
                ack_number: Some(next_seq),
                window_len: u16::try_from(s.remote_last_win_bytes >> s.remote_win_shift).unwrap(),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.rx_refused_segments(), 1);
        assert_eq!(s.recv_queue(), cap);
        assert_eq!(s.rx_buffer.store.held(), cap);
        assert_eq!(s.send_queue(), 4);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_max_seq, LOCAL_SEQ + 5);
        assert_eq!(s.remote_win_len, 256);
        send!(
            s,
            time 20,
            TcpRepr {
                seq_number: next_seq + window,
                ack_number: Some(LOCAL_SEQ + 5),
                window_len: 42,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.send_queue(), 0);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 5);
        assert_eq!(s.remote_win_len, 42);
        assert_eq!(s.rx_refused_segments(), 1);
        assert_eq!(s.recv_queue(), cap);
        assert_eq!(s.rx_buffer.store.held(), cap);
        recv_nothing!(s, time 20);
    }

    #[test]
    fn data_fin_at_cap_refused_without_eof_peer_ack_processed() {
        let mut s = socket_established();
        let cap = s.rx_mbuf_budget(s.cx.ip_mtu());
        for index in 0..cap {
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + index,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: b"a",
                    ..SEND_TEMPL
                }
            );
        }
        assert_eq!(s.rx_buffer.store.held(), cap);
        assert_eq!(s.send_slice(b"sent"), Ok(4));
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + cap),
                window_len: (64 - cap) as u16,
                payload: b"sent",
                ..RECV_TEMPL
            }]
        );
        let reply = send(
            &mut s,
            Instant::from_millis(10),
            &TcpRepr {
                seq_number: REMOTE_SEQ + 1 + cap,
                ack_number: Some(LOCAL_SEQ + 5),
                control: TcpControl::Fin,
                payload: b"z",
                ..SEND_TEMPL
            },
        )
        .unwrap();
        assert_eq!(reply.ack_number, Some(REMOTE_SEQ + 1 + cap));
        assert_eq!(reply.window_len, (64 - cap) as u16);
        assert_eq!(s.send_queue(), 0);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 5);
        assert_eq!(s.state(), State::Established);
        assert!(!s.rx_fin_received);
        assert_eq!(s.rx_fin_seq, None);
        assert_eq!(s.rx_refused_segments(), 1);
        assert_eq!(s.recv_queue(), cap);
        let bytes = drain_bytes(&mut s);
        assert_eq!(bytes.len(), cap);
        assert_eq!(&bytes[..cap], vec![b'a'; cap]);
        assert!(s.recv().unwrap().is_none());
    }

    fn send_counted_append_frame(
        s: &mut TestSocket,
        offset: usize,
        payload: &[u8],
        room: usize,
        control: TcpControl,
    ) -> (
        Option<TcpRepr<'static>>,
        alloc::rc::Rc<core::cell::Cell<usize>>,
    ) {
        let releases = alloc::rc::Rc::new(core::cell::Cell::new(0));
        let reply = send_frame(
            s,
            Instant::ZERO,
            &TcpRepr {
                seq_number: REMOTE_SEQ + 1 + offset,
                ack_number: Some(LOCAL_SEQ + 1),
                payload,
                control,
                ..SEND_TEMPL
            },
            RxBuf::counted_frame(payload.to_vec(), room, releases.clone()),
        );
        (reply, releases)
    }

    #[test]
    fn small_in_order_segments_append_into_one_frame() {
        let mut s = socket_established_with_buffer_sizes(64, 1024);
        let payload: Vec<u8> = (0..200).map(|index| (index % 251) as u8).collect();
        let mut releases = Vec::new();
        for (index, bytes) in payload.chunks(50).enumerate() {
            let offset = index.checked_mul(50).unwrap();
            let (reply, count) =
                send_counted_append_frame(&mut s, offset, bytes, 1024, TcpControl::None);
            assert_eq!(reply, None);
            assert_eq!(count.get(), usize::from(index != 0));
            releases.push(count);
            assert_eq!(releases[0].get(), 0);
        }
        assert_eq!(s.recv_queue(), 200);
        assert_eq!(s.rx_buffer.store.held(), 1);
        let output = drain_bytes(&mut s);
        assert_eq!(output.len(), 200);
        assert_eq!(output.as_slice(), payload);
        assert!(releases.iter().all(|count| count.get() == 1));
        drop(s);
        assert!(releases.iter().all(|count| count.get() == 1));
    }

    #[test]
    fn append_keeps_window_and_cap_accounting() {
        let buffer = 3usize.checked_mul(8).unwrap().checked_mul(1448).unwrap();
        for shift in [0u8, 3] {
            let mut s = socket_established_with_buffer_sizes(64, buffer);
            // This peer advertises MSS 1460, matching the frame allowance below.
            s.remote_mss = BASE_MSS;
            s.socket.update_rx_mbuf_budget(&s.cx);
            assert_eq!(s.cx.ip_mtu(), 1500);
            s.remote_win_shift = shift;
            s.remote_last_win_bytes = 1024;
            for index in 0usize..4 {
                let (reply, _) = send_counted_append_frame(
                    &mut s,
                    index.checked_mul(50).unwrap(),
                    &[b'a'; 50],
                    1024,
                    TcpControl::None,
                );
                assert_eq!(reply, None);
            }
            assert_eq!(s.rx_buffer.store.held(), 1);
            assert_eq!(s.recv_queue(), 200);
            // 1500 - 40 = 1460 bytes per frame; ceil(34752 / 1460) = 24 frames.
            // One stored frame leaves 23 * 1460 bytes, below the capacity.
            // The prior 1024-byte window leaves an 824-byte floor, below the frame window.
            let segment_bytes = 1500usize.checked_sub(40).unwrap();
            let cap = (buffer / segment_bytes)
                .checked_add(usize::from(buffer % segment_bytes != 0))
                .unwrap()
                .max(6);
            let byte_window = buffer;
            let frame_window = cap
                .checked_sub(1)
                .unwrap()
                .checked_mul(segment_bytes)
                .unwrap();
            let expected = u16::try_from(byte_window.min(frame_window) >> shift).unwrap();
            recv(&mut s, Instant::ZERO, |reply| {
                let reply = reply.unwrap();
                assert_eq!(reply.window_len, expected);
                assert_eq!(reply.ack_number, Some(REMOTE_SEQ + 201));
            });
        }

        let mut s = socket_established_with_buffer_sizes(64, 1024);
        for index in 0usize..6 {
            let room = if index == 5 { 1024 } else { 0 };
            let (reply, _) = send_counted_append_frame(
                &mut s,
                index.checked_mul(50).unwrap(),
                &[b'a'; 50],
                room,
                TcpControl::None,
            );
            assert_eq!(reply, None);
        }
        assert_eq!(s.rx_mbuf_cap, 6);
        assert_eq!(s.rx_buffer.store.held(), s.rx_mbuf_cap as usize);
        let refused = s.rx_refused_segments();
        let (reply, releases) =
            send_counted_append_frame(&mut s, 300, &[b'b'; 50], 0, TcpControl::None);
        assert_eq!(reply, None);
        assert_eq!(releases.get(), 1);
        assert_eq!(s.rx_buffer.store.held(), 6);
        assert_eq!(s.rx_refused_segments(), refused);
        assert_eq!(s.recv_queue(), 350);
        recv(&mut s, Instant::ZERO, |reply| {
            assert_eq!(reply.unwrap().ack_number, Some(REMOTE_SEQ + 351));
        });
    }

    #[test]
    fn retransmission_appends_only_its_new_bytes() {
        // Eligibility counts the bytes the socket stores: a 100-byte retransmission whose
        // first 40 bytes were already received appends its 60 new bytes.
        let mut s = socket_established_with_buffer_sizes(64, 1024);
        let payload: Vec<u8> = (0..100).map(|index| index as u8).collect();
        let (reply, first) =
            send_counted_append_frame(&mut s, 0, &payload[..40], 1024, TcpControl::None);
        assert_eq!(reply, None);
        let (reply, overlap) =
            send_counted_append_frame(&mut s, 0, &payload, 0, TcpControl::None);
        assert_eq!(reply, None);
        assert_eq!((first.get(), overlap.get()), (0, 1));
        assert_eq!(s.rx_buffer.store.held(), 1);
        assert_eq!(s.recv_queue(), 100);
        let output = drain_bytes(&mut s);
        assert_eq!(output.len(), 100);
        assert_eq!(output.as_slice(), payload);
        assert_eq!(first.get(), 1);
    }

    #[test]
    fn fin_after_appended_data() {
        let mut s = socket_established_with_buffer_sizes(64, 1024);
        let (reply, first) =
            send_counted_append_frame(&mut s, 0, b"abc", rx_store::APPEND_MAX, TcpControl::None);
        assert_eq!(reply, None);
        let (reply, second) = send_counted_append_frame(&mut s, 3, b"def", 0, TcpControl::None);
        assert_eq!(reply, None);
        assert_eq!((first.get(), second.get()), (0, 1));
        assert_eq!(s.rx_buffer.store.held(), 1);
        let (reply, fin) = send_counted_append_frame(&mut s, 6, b"", 0, TcpControl::Fin);
        assert_eq!(reply, None);
        assert_eq!(fin.get(), 1);
        assert_eq!(s.state(), State::CloseWait);
        recv(&mut s, Instant::ZERO, |reply| {
            assert_eq!(reply.unwrap().ack_number, Some(REMOTE_SEQ + 8));
        });
        let output = drain_bytes(&mut s);
        assert_eq!(output.len(), 6);
        assert_eq!(&output, b"abcdef");
        assert_eq!(first.get(), 1);
        assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
    }

    #[test]
    fn fin_on_last_appended_segment() {
        let mut s = socket_established_with_buffer_sizes(64, 1024);
        let (reply, first) =
            send_counted_append_frame(&mut s, 0, b"abc", rx_store::APPEND_MAX, TcpControl::None);
        assert_eq!(reply, None);
        let (reply, last) = send_counted_append_frame(&mut s, 3, b"def", 0, TcpControl::Fin);
        assert_eq!(reply, None);
        assert_eq!((first.get(), last.get()), (0, 1));
        assert_eq!(s.rx_buffer.store.held(), 1);
        assert_eq!(s.state(), State::CloseWait);
        recv(&mut s, Instant::ZERO, |reply| {
            assert_eq!(reply.unwrap().ack_number, Some(REMOTE_SEQ + 8));
        });
        let output = drain_bytes(&mut s);
        assert_eq!(output.len(), 6);
        assert_eq!(&output, b"abcdef");
        assert_eq!(first.get(), 1);
        assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
    }

    #[test]
    fn rst_closed_socket_reads_held_bytes() {
        let mut s = socket_established();
        let releases = alloc::rc::Rc::new(core::cell::Cell::new(0));
        assert_eq!(
            send_frame(
                &mut s,
                Instant::ZERO,
                &TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: b"abc",
                    ..SEND_TEMPL
                },
                RxBuf::counted_frame(b"abc".to_vec(), 0, releases.clone()),
            ),
            None
        );
        assert_eq!(s.rx_buffer.store.held(), 1);
        assert_eq!(releases.get(), 0);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 4,
                ack_number: Some(LOCAL_SEQ + 1),
                control: TcpControl::Rst,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Closed);
        assert_eq!(s.rx_buffer.store.held(), 1);
        assert_eq!(releases.get(), 0);
        assert_eq!(
            s.recv().map(|frame| frame.unwrap().payload().to_vec()),
            Ok(b"abc".to_vec())
        );
        assert_eq!(s.recv_queue(), 0);
        assert_eq!(s.rx_buffer.store.held(), 0);
        assert_eq!(releases.get(), 1);
        drop(s);
        assert_eq!(releases.get(), 1);
    }

    fn held_trailing_frame(
        s: &mut TestSocket,
        payload: &[u8],
    ) -> alloc::rc::Rc<core::cell::Cell<usize>> {
        let releases = alloc::rc::Rc::new(core::cell::Cell::new(0));
        let frame = RxBuf::counted_frame(payload.to_vec(), 0, releases.clone());
        let reply = send_frame(
            s,
            Instant::ZERO,
            &TcpRepr {
                seq_number: REMOTE_SEQ + 4,
                ack_number: Some(LOCAL_SEQ + 1),
                payload,
                ..SEND_TEMPL
            },
            frame,
        )
        .unwrap();
        assert_eq!(reply.ack_number, Some(REMOTE_SEQ + 1));
        assert_eq!(releases.get(), 0);
        releases
    }

    #[test]
    fn fin_releases_views_past_fin() {
        let mut s = socket_established();
        let releases = held_trailing_frame(&mut s, b"def");
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                control: TcpControl::Fin,
                ..SEND_TEMPL
            }
        );
        assert_eq!(releases.get(), 1);
        assert_eq!(s.recv_queue(), 0);
        assert_eq!(s.rx_buffer.store.held(), 0);
        assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
        drop(s);
        assert_eq!(releases.get(), 1);
    }

    fn data_fin_drops_trailing(payload: &[u8]) {
        let mut s = socket_established();
        let releases = held_trailing_frame(&mut s, payload);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                control: TcpControl::Fin,
                payload: b"abcdef",
                ..SEND_TEMPL
            }
        );
        assert_eq!(releases.get(), 1);
        assert_eq!(s.recv_queue(), 6);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 8),
                window_len: 64,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(
            s.recv().map(|frame| frame.unwrap().payload().to_vec()),
            Ok(b"abcdef".to_vec())
        );
        assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
        drop(s);
        assert_eq!(releases.get(), 1);
    }

    #[test]
    fn data_fin_releases_trailing_ooo_view() {
        data_fin_drops_trailing(b"def");
    }

    #[test]
    fn data_fin_before_held_view_drops_bytes_past_fin() {
        data_fin_drops_trailing(b"defghi");
    }

    #[test]
    fn fin_after_hole_fill_with_pending_view() {
        let mut s = socket_established();
        let reply = send(
            &mut s,
            Instant::ZERO,
            &TcpRepr {
                seq_number: REMOTE_SEQ + 4,
                ack_number: Some(LOCAL_SEQ + 1),
                control: TcpControl::Fin,
                payload: b"def",
                ..SEND_TEMPL
            },
        )
        .unwrap();
        assert_eq!(reply.ack_number, Some(REMOTE_SEQ + 1));
        let frame = RxBuf::from_vec(b"abc".to_vec());
        let repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: frame.as_slice(),
            ..SEND_TEMPL
        };
        let ip_repr = IpReprIpvX(IpvXRepr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        });
        let (reply, pending) = s.socket.process(&mut s.cx, &ip_repr, &repr);
        let (_, reply) = reply.unwrap();
        assert_eq!(reply.ack_number, Some(REMOTE_SEQ + 8));
        assert!(s.rx_buffer.store.has_pending());
        assert_eq!(s.recv_queue(), 6);
        s.commit_rx(frame, pending.unwrap());
        let bytes = drain_bytes(&mut s);
        assert_eq!(bytes.len(), 6);
        assert_eq!(&bytes, b"abcdef");
        assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
    }

    #[test]
    fn reset_releases_held_frames() {
        let mut s = socket_established();
        let releases = held_trailing_frame(&mut s, b"def");
        let in_order = alloc::rc::Rc::new(core::cell::Cell::new(0));
        send_frame(
            &mut s,
            Instant::ZERO,
            &TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"abc",
                ..SEND_TEMPL
            },
            RxBuf::counted_frame(b"abc".to_vec(), 0, in_order.clone()),
        )
        .unwrap();
        assert_eq!((releases.get(), in_order.get()), (0, 0));
        s.reset();
        assert_eq!((releases.get(), in_order.get()), (1, 1));
        assert_eq!(s.recv_queue(), 0);
        assert_eq!(s.rx_buffer.store.held(), 0);
        drop(s);
        assert_eq!((releases.get(), in_order.get()), (1, 1));
    }

    #[test]
    fn process_holds_pending_view_until_attach() {
        let mut s = socket_established();
        let reply = send(
            &mut s,
            Instant::ZERO,
            &TcpRepr {
                seq_number: REMOTE_SEQ + 4,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"def",
                ..SEND_TEMPL
            },
        )
        .unwrap();
        assert_eq!(reply.ack_number, Some(REMOTE_SEQ + 1));
        assert_eq!(s.recv_queue(), 0);

        let frame = RxBuf::from_vec(b"abc".to_vec());
        let data_ptr = frame.as_slice().as_ptr();
        let repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: frame.as_slice(),
            ..SEND_TEMPL
        };
        let ip_repr = IpReprIpvX(IpvXRepr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        });
        let (reply, pending) = s.socket.process(&mut s.cx, &ip_repr, &repr);
        let (_, reply) = reply.unwrap();
        assert_eq!(reply.control, TcpControl::None);
        assert_eq!(reply.ack_number, Some(REMOTE_SEQ + 7));
        assert_eq!(s.recv_queue(), 6);
        assert!(pending.is_some());
        assert!(s.rx_buffer.store.has_pending());

        s.commit_rx(frame, pending.unwrap());
        assert!(!s.rx_buffer.store.has_pending());
        {
            let frame = s.recv().unwrap().unwrap();
            assert_eq!(frame.payload().as_ptr(), data_ptr);
            assert_eq!(frame.payload(), b"abc");
        }
        assert_eq!(s.recv_queue(), 3);
        assert_eq!(
            s.recv().map(|frame| frame.unwrap().payload().to_vec()),
            Ok(b"def".to_vec())
        );
        assert_eq!(s.recv_queue(), 0);
    }

    #[test]
    fn test_established_recv() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 64,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(
            s.recv().map(|frame| frame.unwrap().payload().to_vec()),
            Ok(b"abcdef".to_vec())
        );
    }

    fn setup_rfc2018_cases(rx_len: usize) -> (TestSocket, Vec<u8>) {
        // This is a utility function used by the tests for RFC 2018 cases. It configures a socket
        // in a particular way suitable for those cases.
        //
        // RFC 2018: Assume the left window edge is 5000 and that the data transmitter sends [...]
        // segments, each containing 500 data bytes.
        let mut s = socket_established_with_buffer_sizes(4000, rx_len);
        // This peer advertises MSS 1460 and sends 500-byte segments.
        s.remote_mss = BASE_MSS;
        s.socket.update_rx_mbuf_budget(&s.cx);
        s.remote_has_sack = true;
        let frame_window = s.rx_frame_cap()
            .checked_sub(1).expect("RX frame budget is empty")
            .checked_mul(usize::from(BASE_MSS)).expect("RX frame window exceeds usize");
        let window = u16::try_from(rx_len.min(frame_window)).unwrap();

        // create a segment that is 500 bytes long
        let mut segment: Vec<u8> = Vec::with_capacity(500);

        // move the last ack to 5000 by sending ten of them
        for _ in 0..50 {
            segment.extend_from_slice(b"abcdefghij")
        }
        for offset in (0..5000).step_by(500) {
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &segment,
                    ..SEND_TEMPL
                }
            );
            recv!(
                s,
                [TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1 + offset + 500),
                    window_len: window,
                    ..RECV_TEMPL
                }]
            );
            let frame = s.recv().unwrap().unwrap();
            assert_eq!(frame.payload().len(), 500);
            assert_eq!(frame.payload(), segment.as_slice());
        }
        assert_eq!(s.remote_last_win_bytes, u32::from(window));
        (s, segment)
    }

    #[test]
    fn test_established_rfc2018_cases() {
        let (s, segment) = setup_rfc2018_cases(4000);
        check_rfc2018_cases(s, segment, true);
    }

    #[test]
    fn test_established_rfc2018_cases_with_larger_capacity() {
        let (mut s, segment) = setup_rfc2018_cases(16000);
        assert_eq!(s.recv_queue(), 0);
        s.remote_win_shift = 2;
        // The previous advertised window promises 14000 bytes.
        s.remote_last_win_bytes = 3500 << 2;
        assert_eq!(s.rx_mbuf_budget(s.cx.ip_mtu()), 11);
        assert_eq!(s.rx_frame_cap(), 11);
        assert_eq!(s.scaled_window(), 4000);
        check_rfc2018_cases(s, segment, false);
    }

    fn check_rfc2018_cases(mut s: TestSocket, segment: Vec<u8>, capped: bool) {
        // RFC 2018:
        //
        // Case 2: The first segment is dropped but the remaining 7 are received.
        //
        // Upon receiving each of the last seven packets, the data receiver will return a TCP ACK
        // segment that acknowledges sequence number 5000 and contains a SACK option specifying one
        // block of queued data:
        //
        //   Triggering   ACK      Left Edge  Right Edge
        //   Segment
        //
        //   5000         (lost)
        //   5500         5000     5500       6000
        //   6000         5000     5500       6500
        //   6500         5000     5500       7000
        //   7000         5000     5500       7500
        //   7500         5000     5500       8000
        //   8000         5000     5500       8500
        //   8500         5000     5500       9000
        //
        let expected_windows = if capped {
            [4000; 6]
        } else {
            [3535; 6]
        };
        for (offset, window_len) in (500..3500).step_by(500).zip(expected_windows) {
            let retained = if capped { offset.min(2500) } else { offset };
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset + 5000,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &segment,
                    ..SEND_TEMPL
                },
                Some(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1 + 5000),
                    window_len,
                    sack_ranges: [
                        Some((
                            REMOTE_SEQ.0 as u32 + 1 + 5500,
                            REMOTE_SEQ.0 as u32
                                + 1
                                + 5500
                                + retained as u32
                        )),
                        None,
                        None
                    ],
                    ..RECV_TEMPL
                })
            );
            assert_eq!(s.rx_refused_segments(), u32::from(capped && offset == 3000));
            assert_eq!(s.rx_buffer.store.held(), retained / 500);
            assert_eq!(s.rx_buffer.store.out_of_order_len(), retained);
        }
    }

    #[test]
    fn test_m11_six_out_of_order_segments_are_kept() {
        let mut s = socket_established_with_buffer_sizes(64, 65536);
        s.remote_has_sack = true;
        let bytes = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let first = receive_window_segment(&mut s, 0, &bytes[..2]);
        let ack_number = REMOTE_SEQ + 3;
        assert_eq!(first.ack_number, Some(ack_number));
        for index in 0..6 {
            let offset = 4 + index * 4;
            let reply = receive_window_segment(&mut s, offset, &bytes[offset..offset + 2]);
            assert_eq!(reply.ack_number, Some(ack_number));
            assert_eq!(s.recv_queue(), 2);
            assert_eq!(s.rx_buffer.store.out_of_order_len(), (index + 1) * 2,
                "out-of-order segment {} was not kept", index + 1);
            assert_eq!(s.rx_buffer.store.held(), index + 2);
            assert_eq!(s.rx_refused_segments(), 0);
        }
        for index in 0..6 {
            let offset = 2 + index * 4;
            let reply = receive_window_segment(&mut s, offset, &bytes[offset..offset + 2]);
            assert_eq!(reply.ack_number, Some(ack_number + (index + 1) * 4));
        }
        let received = drain_bytes(&mut s);
        assert_eq!(received.len(), bytes.len());
        assert_eq!(&received, bytes);
        assert_eq!(s.recv_queue(), 0);
        assert_eq!(s.rx_buffer.store.held(), 0);
    }

    #[test]
    fn test_sack_third_of_six_ranges_and_merge() {
        let mut s = socket_established_with_buffer_sizes(64, 65536);
        s.remote_has_sack = true;
        let seq = REMOTE_SEQ + 1;
        let bytes = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        receive_window_segment(&mut s, 0, &bytes[..2]);
        for offset in (4..26).step_by(4) {
            receive_window_segment(&mut s, offset, &bytes[offset..offset + 2]);
        }
        assert_eq!(s.rx_buffer.store.out_of_order_ranges().count(), 6);

        let reply = receive_window_segment(&mut s, 13, &bytes[13..15]);
        assert_eq!(reply.ack_number, Some(seq + 2));
        assert_eq!(reply.sack_ranges, [
            Some(((seq + 12).0 as u32, (seq + 15).0 as u32)),
            Some(((seq + 4).0 as u32, (seq + 6).0 as u32)),
            Some(((seq + 8).0 as u32, (seq + 10).0 as u32)),
        ]);
        assert_eq!(s.rx_buffer.store.out_of_order_ranges().count(), 6);

        let reply = receive_window_segment(&mut s, 15, &bytes[15..16]);
        assert_eq!(reply.ack_number, Some(seq + 2));
        assert_eq!(reply.sack_ranges, [
            Some(((seq + 12).0 as u32, (seq + 18).0 as u32)),
            Some(((seq + 4).0 as u32, (seq + 6).0 as u32)),
            Some(((seq + 8).0 as u32, (seq + 10).0 as u32)),
        ]);
        assert_eq!(s.rx_buffer.store.out_of_order_ranges().collect::<Vec<_>>(),
            vec![(2, 4), (6, 8), (10, 16), (18, 20), (22, 24)]);
        assert_eq!(s.recv_queue(), 2);
        assert_eq!(s.rx_refused_segments(), 0);
    }

    #[test]
    fn test_sack_lowest_range_after_ack_advances_with_six_ranges() {
        let mut s = socket_established_with_buffer_sizes(64, 65536);
        s.remote_has_sack = true;
        let seq = REMOTE_SEQ + 1;
        let bytes = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        receive_window_segment(&mut s, 0, &bytes[..2]);
        for offset in (4..26).step_by(4) {
            receive_window_segment(&mut s, offset, &bytes[offset..offset + 2]);
        }
        assert_eq!(s.rx_buffer.store.out_of_order_ranges().count(), 6);

        let reply = receive_window_segment(&mut s, 2, &bytes[2..4]);
        assert_eq!(reply.ack_number, Some(seq + 6));
        assert_eq!(reply.sack_ranges, [
            Some(((seq + 8).0 as u32, (seq + 10).0 as u32)),
            Some(((seq + 12).0 as u32, (seq + 14).0 as u32)),
            Some(((seq + 16).0 as u32, (seq + 18).0 as u32)),
        ]);
        assert_eq!(s.rx_buffer.store.out_of_order_ranges().count(), 5);
        assert_eq!(s.recv_queue(), 6);
    }

    // RFC 2018: the first block holds the latest segment; the free blocks repeat the
    // other held ranges (here in sequence order), so one lost ACK loses no range.
    #[test]
    fn sack_repeats_earlier_blocks_after_latest() {
        let mut s = socket_established_with_buffer_sizes(64, 65536);
        s.remote_has_sack = true;
        let seq = REMOTE_SEQ + 1;
        let block = |l: usize, r: usize| Some(((seq + l).0 as u32, (seq + r).0 as u32));
        let reply = receive_window_segment(&mut s, 2, b"x");
        assert_eq!(reply.sack_ranges, [block(2, 3), None, None]);
        let reply = receive_window_segment(&mut s, 6, b"y");
        assert_eq!(reply.ack_number, Some(seq));
        assert_eq!(reply.sack_ranges, [block(6, 7), block(2, 3), None]);
        let reply = receive_window_segment(&mut s, 10, b"z");
        assert_eq!(reply.sack_ranges, [block(10, 11), block(2, 3), block(6, 7)]);
        let reply = receive_window_segment(&mut s, 4, b"w");
        assert_eq!(reply.sack_ranges, [block(4, 5), block(2, 3), block(6, 7)]);
    }

    // RFC 2883, Linux tcp_send_dupack/tcp_dsack_set: data entirely below RCV.NXT is
    // reported as the first SACK block.
    #[test]
    fn duplicate_segment_below_ack_gets_dsack_block() {
        let mut s = socket_recved();
        s.remote_has_sack = true;
        let reply = send(&mut s, Instant::ZERO, &TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        }).expect("duplicate segment must draw an immediate ACK");
        assert_eq!(reply.ack_number, Some(REMOTE_SEQ + 7));
        assert_eq!(reply.sack_ranges,
            [Some(((REMOTE_SEQ + 1).0 as u32, (REMOTE_SEQ + 7).0 as u32)), None, None]);
    }

    // RFC 2883 4.1.2: a duplicate of held out-of-order data is the D-SACK block, followed
    // by the held range that contains it.
    #[test]
    fn duplicate_of_held_out_of_order_data_gets_dsack_then_its_range() {
        let mut s = socket_established_with_buffer_sizes(64, 65536);
        s.remote_has_sack = true;
        let seq = REMOTE_SEQ + 1;
        let block = |l: usize, r: usize| Some(((seq + l).0 as u32, (seq + r).0 as u32));
        receive_window_segment(&mut s, 2, b"abcd");
        receive_window_segment(&mut s, 10, b"k");
        let reply = receive_window_segment(&mut s, 3, b"bc");
        assert_eq!(reply.ack_number, Some(seq));
        assert_eq!(reply.sack_ranges, [block(3, 5), block(2, 6), block(10, 11)]);
        assert_eq!(s.rx_buffer.store.held(), 2);
    }

    #[test]
    fn no_sack_blocks_without_negotiated_sack() {
        let mut s = socket_recved();
        assert!(!s.remote_has_sack);
        let reply = send(&mut s, Instant::ZERO, &TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        }).expect("duplicate segment must draw an immediate ACK");
        assert_eq!(reply.sack_ranges, [None; 3]);
        for offset in [8, 12, 8] {
            let reply = receive_window_segment(&mut s, offset, b"x");
            assert_eq!(reply.ack_number, Some(REMOTE_SEQ + 7));
            assert_eq!(reply.sack_ranges, [None; 3]);
        }
    }

    // A pure ACK built on egress (here the delayed ACK for in-order data, sent while
    // out-of-order ranges are held) carries the same blocks, without D-SACK.
    #[test]
    fn egress_ack_carries_sack_blocks_only_with_sack() {
        for sack in [true, false] {
            let mut s = socket_established_with_buffer_sizes(64, 65536);
            s.remote_has_sack = sack;
            let seq = REMOTE_SEQ + 1;
            assert!(send(&mut s, Instant::ZERO, &TcpRepr {
                seq_number: seq,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"ab"[..],
                ..SEND_TEMPL
            }).is_none());
            for (offset, len) in [(4, 2), (8, 2)] {
                let decision = s.rx_buffer.store.decide(offset, len, 8);
                s.rx_buffer.store.place(offset, decision);
                s.rx_buffer.store.attach(RxBuf::from_vec(vec![0; len]));
            }
            s.ack_now();
            let mut sent = None;
            recv(&mut s, Instant::ZERO, |reply| sent = Some(reply.unwrap().sack_ranges));
            let expected = if sack {
                [Some(((seq + 4).0 as u32, (seq + 6).0 as u32)),
                 Some(((seq + 8).0 as u32, (seq + 10).0 as u32)), None]
            } else {
                [None; 3]
            };
            assert_eq!(sent, Some(expected), "sack {sack}");
        }
    }

    #[test]
    fn test_window_with_six_out_of_order_holes() {
        for (segment_bytes, expected_window) in [(536usize, 24120usize), (1460, 65536)] {
            let mut s = socket_with_mbuf_window(2);
            s.remote_has_sack = true;
            s.remote_mss = u16::try_from(segment_bytes).expect("test MSS exceeds u16");
            s.socket.update_rx_mbuf_budget(&s.cx);
            s.remote_last_win_bytes = u32::try_from(expected_window).expect("test window exceeds u32");
            let payload = vec![0x5a; segment_bytes];
            let mut reply = None;
            for index in 0..6 {
                let offset = (2 * index + 1) * segment_bytes;
                reply = Some(receive_window_segment(&mut s, offset, &payload));
                assert_eq!(reply.as_ref().unwrap().ack_number, Some(REMOTE_SEQ + 1));
            }
            assert_eq!(s.rx_mbuf_cap, 45);
            assert_eq!(s.rx_seg_bytes as usize, segment_bytes);
            assert_eq!(s.rx_buffer.store.held(), 6);
            assert_eq!(s.rx_buffer.store.out_of_order_hole_frames(segment_bytes), 6);
            assert_eq!(s.rx_buffer.store.out_of_order_span(), 12 * segment_bytes);
            let free_frames = (s.rx_mbuf_cap as usize)
                .checked_sub(s.rx_buffer.store.held()).expect("held frames exceed cap");
            let window = free_frames
                .checked_sub(s.rx_buffer.store.out_of_order_hole_frames(segment_bytes))
                .expect("holes exceed free frames")
                .checked_mul(segment_bytes).expect("frame window exceeds usize")
                .checked_add(s.rx_buffer.store.out_of_order_span()).expect("window exceeds usize")
                .min(s.recv_capacity());
            assert_eq!(window, expected_window);
            assert_eq!(s.recv_window(), window);
            assert_eq!(reply.unwrap().window_len,
                u16::try_from(window >> s.remote_win_shift).expect("window field exceeds u16"));
            assert_eq!(s.recv_queue(), 0);
            assert_eq!(s.rx_refused_segments(), 0);
        }
    }

    #[test]
    fn test_fifth_out_of_order_range_is_kept() {
        let mut s = socket_established();
        s.remote_has_sack = true;
        let block = |offset: usize| Some(((REMOTE_SEQ + 1 + offset).0 as u32,
                                          (REMOTE_SEQ + 2 + offset).0 as u32));
        // The latest segment's range, then the lowest earlier ones.
        for offset in [2, 4, 6, 8, 10] {
            let mut sack_ranges = [block(offset), None, None];
            for (slot, earlier) in sack_ranges[1..].iter_mut().zip((2..offset).step_by(2)) {
                *slot = block(earlier);
            }
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1 + offset,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"x"[..],
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                sack_ranges,
                ..RECV_TEMPL
            }));
        }
        assert_eq!(s.rx_buffer.store.out_of_order_ranges().collect::<Vec<_>>(),
            vec![(2, 3), (4, 5), (6, 7), (8, 9), (10, 11)]);
        assert_eq!(s.rx_buffer.store.out_of_order_len(), 5);
        assert_eq!(s.rx_buffer.store.held(), 5);
        assert_eq!(s.rx_refused_segments(), 0);
        assert_eq!(s.recv_queue(), 0);
    }

    #[test]
    fn test_established_sack_no_overflow_on_near_max_seqnumber() {
        let mut s = socket_established();
        s.remote_has_sack = true;
        s.remote_seq_no = TcpSeqNumber(-4);
        s.remote_last_ack = Some(TcpSeqNumber(-4));

        // Send an out-of-order segment 10 bytes past the expected sequence,
        // creating a 10-byte hole at the front of the store.
        send!(
            s,
            TcpRepr {
                seq_number: TcpSeqNumber(-4 + 10),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"AAAAAAAAAA"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(TcpSeqNumber(-4)),
                window_len: 64,
                sack_ranges: [
                    Some(((-4_i32 + 10) as u32, (-4_i32 + 20) as u32,)),
                    None,
                    None,
                ],
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_established_sliding_window_recv() {
        let mut s = socket_established();
        // Update our scaling parameters for a TCP with a scaled buffer.
        assert_eq!(s.rx_buffer.store.in_order_len(), 0);
        s.rx_buffer = RxBuffer::new(262143);
        s.remote_win_scale = Some(0);
        s.remote_last_win_bytes = 65535 << 2;
        s.remote_win_shift = 2;

        // Create a TCP segment that will mostly fill an IP frame.
        let mut segment: Vec<u8> = Vec::with_capacity(1400);
        for _ in 0..100 {
            segment.extend_from_slice(b"abcdefghijklmn")
        }
        assert_eq!(segment.len(), 1400);

        // Send the frame
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            }
        );

        // Ensure that the received window size is shifted right by 2.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1400),
                window_len: 65185,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send() {
        let mut s = socket_established();
        // First roundtrip after establishing.
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx_buffer.len(), 6);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
        // Second roundtrip.
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
    }

    #[test]
    fn test_established_send_no_ack_send() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send_buf_gt_win() {
        let mut data = [0; 32];
        for (i, elem) in data.iter_mut().enumerate() {
            *elem = i as u8
        }

        let mut s = socket_established();
        s.remote_win_len = 16;
        s.send_slice(&data[..]).unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &data[0..16],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send_window_shrink() {
        let mut s = socket_established();

        // 6 octets fit on the remote side's window, so we send them.
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx_buffer.len(), 6);

        println!(
            "local_seq_no={} remote_win_len={} remote_last_seq={}",
            s.local_seq_no, s.remote_win_len, s.remote_last_seq
        );

        // - Peer doesn't ack them yet
        // - Sends data so we need to reply with an ACK
        // - ...AND and sends a window announcement that SHRINKS the window, so data we've
        //   previously sent is now outside the window. Yes, this is allowed by TCP.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 3,
                payload: &b"xyzxyz"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 6);

        println!(
            "local_seq_no={} remote_win_len={} remote_last_seq={}",
            s.local_seq_no, s.remote_win_len, s.remote_last_seq
        );

        // More data should not get sent since it doesn't fit in the window. The ACK
        // carries the shrunk window's right edge: the highest sequence number sent
        // is past it (Linux tcp_acceptable_seq).
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 3,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 64,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_receive_partially_outside_window() {
        let mut s = socket_established();

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        {
            let frame = s.recv().unwrap().unwrap();
            let data = frame.payload();
            assert_eq!(data, b"abc");
        }

        // Peer decides to retransmit (perhaps because the ACK was lost)
        // and also pushed data.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );

        {
            let frame = s.recv().unwrap().unwrap();
            let data = frame.payload();
            assert_eq!(data, b"def");
        }
    }

    #[test]
    fn test_established_receive_partially_outside_window_fin() {
        let mut s = socket_established();

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        {
            let frame = s.recv().unwrap().unwrap();
            let data = frame.payload();
            assert_eq!(data, b"abc");
        }

        // Peer decides to retransmit (perhaps because the ACK was lost)
        // and also pushed data, and sent a FIN.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                control: TcpControl::Fin,
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );

        {
            let frame = s.recv().unwrap().unwrap();
            let data = frame.payload();
            assert_eq!(data, b"def");
        }

        // We should accept the FIN, because even though the last packet was partially
        // outside the receive window, there is no hole after placing its data in the store.
        assert_eq!(s.state, State::CloseWait);
    }

    #[test]
    fn test_established_send_wrap() {
        let mut s = socket_established();
        let local_seq_start = TcpSeqNumber(i32::MAX - 1);
        s.local_seq_no = local_seq_start + 1;
        s.remote_last_seq = local_seq_start + 1;
        s.remote_max_seq = local_seq_start + 1;
        s.send_slice(b"abc").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: local_seq_start + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_no_ack() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_established_bad_ack() {
        let mut s = socket_established();
        // ACK before acknowledged sequence space.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(TcpSeqNumber(LOCAL_SEQ.0 - 1)),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        // Data not yet transmitted.
        send!(
            s,
            time 500,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 10),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
    }

    #[test]
    fn test_old_ack_keeps_reordered_payload() {
        for (seq, old_distance) in [(LOCAL_SEQ + 1, 3), (TcpSeqNumber(1), 3)] {
            let mut s = socket_established();
            s.local_seq_no = seq;
            s.remote_last_seq = seq;
            s.remote_max_seq = seq;
            s.send_slice(b"xyz").unwrap();
            recv!(s, [TcpRepr {
                seq_number: seq,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"xyz"[..],
                ..RECV_TEMPL
            }]);
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 4,
                ack_number: Some(seq + 3),
                window_len: 400,
                payload: &b"def"[..],
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: seq + 3,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }));
            let last_ack = s.local_rx_last_ack();
            let dup_acks = s.local_rx_dup_acks;
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(seq + 3 - old_distance),
                window_len: 0,
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: seq + 3,
                ack_number: Some(REMOTE_SEQ + 7),
                window_len: 64,
                ..RECV_TEMPL
            }));
            assert_eq!(s.local_seq_no, seq + 3);
            assert_eq!(s.remote_win_len, 400);
            assert_eq!(s.remote_win_seq, REMOTE_SEQ + 4);
            assert_eq!(s.local_rx_last_ack(), last_ack);
            assert_eq!(s.local_rx_dup_acks, dup_acks);
            assert_eq!(
                s.remote_seq_no + s.rx_buffer.store.in_order_len(),
                REMOTE_SEQ + 7
            );
            let data = drain_bytes(&mut s);
            assert_eq!(data.len(), 6);
            assert_eq!(&data, b"abcdef");
        }
    }

    fn socket_with_acked_scaled_window(seq: TcpSeqNumber) -> TestSocket {
        let mut s = socket_syn_sent_with_buffer_sizes(512, 64);
        s.local_seq_no = seq - 1;
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(seq),
            window_scale: Some(2),
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            seq_number: seq,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]);
        s.send_slice(&[0; 512]).unwrap();
        for (offset, window_len) in [(0, 100), (256, 1)] {
            recv!(s, [TcpRepr {
                seq_number: seq + offset,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; 256],
                ..RECV_TEMPL
            }]);
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(seq + offset + 256),
                window_len,
                ..SEND_TEMPL
            });
        }
        assert_eq!(s.remote_win_len, 4);
        s
    }

    #[test]
    fn test_old_ack_lower_bound_scaled_max_window() {
        for seq in [LOCAL_SEQ + 1, TcpSeqNumber(1), TcpSeqNumber(i32::MAX - 1)] {
            for distance in [400, 401] {
                let mut s = socket_with_acked_scaled_window(seq);
                let segment = TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(seq + 512 - distance),
                    window_len: 65535,
                    payload: b"abc",
                    ..SEND_TEMPL
                };
                let reply = send(&mut s, Instant::from_millis(0), &segment);
                assert_eq!(reply, if distance == 400 { None } else { Some(TcpRepr {
                    seq_number: seq + 512,
                    ack_number: Some(REMOTE_SEQ + 1),
                    ..RECV_TEMPL
                }) });
                assert_eq!(s.recv_queue(), if distance == 400 { 3 } else { 0 });
                assert_eq!(s.local_seq_no, seq + 512);
                assert_eq!(s.remote_win_len, 4);
                assert_eq!(s.max_snd_wnd, 400);
                assert_eq!(s.bytes_acked, 513);
                assert_eq!(s.state, State::Established);
                assert_eq!(s.tuple, Some(TUPLE));
            }
        }
    }

    #[test]
    fn test_passive_open_max_snd_wnd_uses_scaled_final_ack() {
        let mut s = socket_listen();
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            window_len: 65535,
            window_scale: Some(7),
            ..SEND_TEMPL
        });
        assert_eq!(s.remote_win_len, 65535);
        let seq = s.local_seq_no + 1;
        recv!(s, [TcpRepr {
            control: TcpControl::Syn,
            seq_number: seq - 1,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(seq),
            window_len: 1,
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_win_len, 128);
        assert_eq!(s.max_snd_wnd, 128);
    }

    #[test]
    fn test_passive_open_syn_window_does_not_relax_old_ack_bound() {
        let mut s = socket_listen();
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            window_len: 4,
            ..SEND_TEMPL
        });
        let seq = s.local_seq_no + 1;
        recv!(s, [TcpRepr {
            control: TcpControl::Syn,
            seq_number: seq - 1,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(seq),
            window_len: 1,
            ..SEND_TEMPL
        });
        for offset in 0..2 {
            s.send_slice(b"x").unwrap();
            recv!(s, [TcpRepr {
                seq_number: seq + offset,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"x",
                ..RECV_TEMPL
            }]);
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(seq + offset + 1),
                window_len: 1,
                ..SEND_TEMPL
            });
        }
        assert_eq!(s.bytes_acked, 2);
        let old_ack_number = s.local_seq_no - 2;
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(old_ack_number),
            payload: b"a",
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: seq + 2,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.recv_queue(), 0);
        assert_eq!(s.max_snd_wnd, 1);
        assert_eq!(s.local_seq_no, seq + 2);
    }

    #[test]
    fn test_old_ack_lower_bound_acked_bytes() {
        for distance in [3, 4] {
            let mut s = socket_listen();
            send!(s, TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            });
            let seq = s.local_seq_no + 1;
            recv!(s, [TcpRepr {
                control: TcpControl::Syn,
                seq_number: seq - 1,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]);
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(seq),
                ..SEND_TEMPL
            });
            s.send_slice(b"xyz").unwrap();
            recv!(s, [TcpRepr {
                seq_number: seq,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"xyz",
                ..RECV_TEMPL
            }]);
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(seq + 3),
                ..SEND_TEMPL
            });
            let reply = send(&mut s, Instant::from_millis(0), &TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(seq + 3 - distance),
                payload: b"abc",
                ..SEND_TEMPL
            });
            assert_eq!(reply, if distance == 3 { None } else { Some(TcpRepr {
                seq_number: seq + 3,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }) });
            assert_eq!(s.recv_queue(), if distance == 3 { 3 } else { 0 });
            assert_eq!(s.local_seq_no, seq + 3);
        }
    }

    #[test]
    fn test_old_ack_lower_bound_shared_challenge_limit() {
        let mut s = socket_with_acked_scaled_window(LOCAL_SEQ + 1);
        let ack = TcpRepr {
            seq_number: LOCAL_SEQ + 513,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        };
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ + 1,
            ..SEND_TEMPL
        }, Some(ack.clone()));
        let segment = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 112),
            payload: b"abc",
            ..SEND_TEMPL
        };
        send!(s, time 499, segment.clone());
        assert_eq!(s.recv_queue(), 0);
        send!(s, time 500, segment, Some(ack));
        assert_eq!(s.recv_queue(), 0);
        assert_eq!(s.challenge_ack_timer, Instant::from_millis(1000));
    }

    #[test]
    fn test_out_of_window_data_bad_ack_bypasses_challenge_limit() {
        let mut s = socket_with_acked_scaled_window(LOCAL_SEQ + 1);
        let una = s.local_seq_no;
        let ack = TcpRepr {
            seq_number: una,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        };
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ - 1,
            ack_number: None,
            payload: b"x",
            ..SEND_TEMPL
        });
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(una - 401),
            ..SEND_TEMPL
        }, Some(ack.clone()));
        assert_eq!(s.challenge_ack_timer, Instant::from_millis(500));
        for ack_number in [una - 401, s.remote_max_seq + 1] {
            send!(s, time 100, TcpRepr {
                seq_number: REMOTE_SEQ - 1,
                ack_number: Some(ack_number),
                payload: b"x",
                ..SEND_TEMPL
            }, Some(ack.clone()));
            assert_eq!(s.challenge_ack_timer, Instant::from_millis(500));
            assert_eq!(s.recv_queue(), 0);
            assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
            assert_eq!(s.local_seq_no, una);
        }
    }

    #[test]
    fn test_old_ack_lower_bound_half_sequence_space() {
        for seq in [TcpSeqNumber(1), TcpSeqNumber(i32::MAX)] {
            let mut s = socket_with_acked_scaled_window(seq);
            let una = s.local_seq_no;
            s.send_slice(b"x").unwrap();
            recv!(s, [TcpRepr {
                seq_number: una,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"x",
                ..RECV_TEMPL
            }]);
            for (time, ack_number) in [(0, TcpSeqNumber(una.0.wrapping_add(i32::MIN))),
                                       (500, una + 2)] {
                send!(s, time time, TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(ack_number),
                    payload: b"abc",
                    ..SEND_TEMPL
                }, Some(TcpRepr {
                    seq_number: una + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    ..RECV_TEMPL
                }));
                assert_eq!(s.recv_queue(), 0);
                assert_eq!(s.local_seq_no, una);
                assert_eq!(s.send_queue(), 1);
            }
        }
    }

    #[test]
    fn test_old_ack_pure_synchronized_silent() {
        for mut s in [socket_established(), socket_fin_wait_1(), socket_fin_wait_2(),
                      socket_close_wait(), socket_closing(), socket_last_ack(),
                      socket_time_wait(true)] {
            let state = s.state;
            if matches!(state, State::FinWait1 | State::LastAck) {
                let remote_seq = s.remote_seq_no;
                recv!(s, [TcpRepr {
                    control: TcpControl::Fin,
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(remote_seq),
                    ..RECV_TEMPL
                }]);
            }
            let una = s.local_seq_no;
            let remote_seq = s.remote_seq_no;
            send!(s, TcpRepr {
                seq_number: remote_seq,
                ack_number: Some(una - 1),
                ..SEND_TEMPL
            });
            assert_eq!(s.challenge_ack_timer, Instant::from_millis(0));
            assert_eq!(s.local_seq_no, una);
            assert_eq!(s.state, state);
            assert_eq!(s.tuple, Some(TUPLE));
        }
    }

    #[test]
    fn test_old_ack_payload_is_received() {
        let mut s = socket_established();
        send!(s, time 50, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ),
            payload: b"abc",
            ..SEND_TEMPL
        });
        let data = drain_bytes(&mut s);
        assert_eq!(data.len(), 3);
        assert_eq!(&data, b"abc");
        recv!(s, time 50, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 4),
            ..RECV_TEMPL
        }]);
        recv_nothing!(s, time 100);
        recv_nothing!(s, time 200);
        recv_nothing!(s, time 250);
        assert_eq!(s.state, State::Established);
    }

    #[test]
    fn test_old_ack_fin_closes_receive_half() {
        let mut s = socket_established();
        send!(s, time 50, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::CloseWait);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_win_len, 256);
    }

    #[test]
    fn test_old_ack_out_of_order_payload_is_buffered() {
        for old_ack in [true, false] {
            let mut s = socket_established();
            s.remote_seq_no = TcpSeqNumber(100);
            s.remote_last_ack = Some(TcpSeqNumber(100));
            s.local_seq_no = TcpSeqNumber(200);
            s.remote_last_seq = TcpSeqNumber(200);
            s.remote_max_seq = TcpSeqNumber(200);
            send!(s, time 50, TcpRepr {
                seq_number: TcpSeqNumber(101),
                ack_number: Some(TcpSeqNumber(if old_ack { 199 } else { 200 })),
                payload: b"x",
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: TcpSeqNumber(200),
                ack_number: Some(TcpSeqNumber(100)),
                ..RECV_TEMPL
            }));
            assert_eq!(s.recv_queue(), 0);
            assert_eq!(s.remote_seq_no, TcpSeqNumber(100));
            assert_eq!(s.local_seq_no, TcpSeqNumber(200));
            assert_eq!(s.rx_buffer.store.out_of_order_ranges().collect::<Vec<_>>(), vec![(1, 2)]);
        }
    }

    #[test]
    fn test_current_ack_fin_closes_receive_half() {
        let mut s = socket_established();
        send!(s, time 50, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::CloseWait);
    }

    #[test]
    fn test_old_ack_payload_after_fin_discarded() {
        for state in [State::CloseWait, State::Closing, State::LastAck, State::TimeWait] {
            let mut s = socket_established();
            if matches!(state, State::Closing | State::TimeWait) {
                s.close();
                recv!(s, [TcpRepr {
                    control: TcpControl::Fin,
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    ..RECV_TEMPL
                }]);
            }
            send!(s, TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + if state == State::TimeWait { 2 } else { 1 }),
                ..SEND_TEMPL
            });
            let una = s.local_seq_no;
            let sent = s.remote_last_seq;
            recv!(s, [TcpRepr {
                seq_number: sent,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]);
            if state == State::LastAck {
                s.close();
                recv!(s, [TcpRepr {
                    control: TcpControl::Fin,
                    seq_number: una,
                    ack_number: Some(REMOTE_SEQ + 2),
                    ..RECV_TEMPL
                }]);
            }
            let sent = s.remote_last_seq;
            send!(s, time 100, TcpRepr {
                seq_number: REMOTE_SEQ + 2,
                ack_number: Some(una - 1),
                payload: b"late",
                ..SEND_TEMPL
            }, if state == State::TimeWait { Some(TcpRepr {
                seq_number: sent,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }) } else { None });
            assert_eq!(s.recv_queue(), 0);
            assert!(!s.can_recv());
            assert_eq!(s.remote_seq_no, REMOTE_SEQ + 2);
            assert_eq!(s.local_seq_no, una);
            assert_eq!(s.state, state);
            assert_eq!(s.tuple, Some(TUPLE));
            assert_eq!(s.challenge_ack_timer, Instant::from_millis(0));
            recv_nothing!(s, time 100);
        }
    }

    #[test]
    fn test_old_ack_keeps_fin_and_payload() {
        let mut s = socket_established();
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ),
            window_len: 0,
            payload: &b"abc"[..],
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::CloseWait);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_win_len, 256);
        assert!(s.rx_fin_received);
        assert_eq!(
            s.remote_seq_no + s.rx_buffer.store.in_order_len(),
            REMOTE_SEQ + 5
        );
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 5),
            window_len: 64,
            ..RECV_TEMPL
        }]);
        let data = drain_bytes(&mut s);
        assert_eq!(data.len(), 3);
        assert_eq!(&data, b"abc");
        assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
    }

    #[test]
    fn test_syn_in_time_wait_challenge_ack() {
        for seq in [REMOTE_SEQ + 1, REMOTE_SEQ + 2 + 65535] {
            let mut s = socket_syn_received_with_buffer_sizes(65535, 65535);
            send!(s, time 100, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 32767,
                ..SEND_TEMPL
            });
            s.close();
            recv!(s, time 100, [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: 24120,
                ..RECV_TEMPL
            }]);
            send!(s, time 200, TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                window_len: 32767,
                ..SEND_TEMPL
            });
            recv!(s, time 200, [TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 2),
                window_len: 24120,
                ..RECV_TEMPL
            }]);
            send!(s, time 300, TcpRepr {
                control: TcpControl::Syn,
                seq_number: seq,
                ack_number: Some(LOCAL_SEQ),
                window_len: 32767,
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 2),
                window_len: 24120,
                ..RECV_TEMPL
            }));
            assert_eq!(s.state(), State::TimeWait);
            assert_eq!(s.tuple, Some(TUPLE));
            assert_eq!(s.local_seq_no, LOCAL_SEQ + 2);
            assert_eq!(s.remote_win_len, 32767);
            send!(s, time 1400, TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                window_len: 32767,
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 2),
                window_len: 24120,
                ..RECV_TEMPL
            }));
            assert_eq!(s.state(), State::TimeWait);
        }
    }

    #[test]
    fn test_syn_fin_in_time_wait_challenge_ack() {
        for seq in [REMOTE_SEQ + 2, REMOTE_SEQ + 2 + 65535] {
            let mut s = socket_syn_received_with_buffer_sizes(65535, 65535);
            send!(s, time 100, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 32767,
                ..SEND_TEMPL
            });
            s.close();
            recv!(s, time 100, [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: 24120,
                ..RECV_TEMPL
            }]);
            send!(s, time 200, TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                window_len: 32767,
                ..SEND_TEMPL
            });
            recv!(s, time 200, [TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 2),
                window_len: 24120,
                ..RECV_TEMPL
            }]);
            let time_wait_timer = s.timer;
            send!(s, time 300, TcpRepr {
                control: TcpControl::SynFin,
                seq_number: seq,
                ack_number: None,
                window_len: 32767,
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 2),
                window_len: 24120,
                ..RECV_TEMPL
            }));
            assert_eq!(s.state(), State::TimeWait);
            if seq == REMOTE_SEQ + 2 {
                assert_eq!(s.timer, time_wait_timer);
            }
        }
    }

    #[test]
    fn test_time_wait_accepts_syn_fin() {
        let s = socket_time_wait(false);
        let window_start = REMOTE_SEQ + 1 + 1;
        for control in [TcpControl::Syn, TcpControl::SynFin] {
            let at_rcv_nxt = TcpRepr {
                control,
                seq_number: window_start,
                ack_number: None,
                window_len: 32767,
                ..SEND_TEMPL
            };
            assert!(!s.time_wait_accepts_syn(&at_rcv_nxt));

            let past_rcv_nxt = TcpRepr {
                control,
                seq_number: window_start + 65535,
                ack_number: None,
                window_len: 32767,
                ..SEND_TEMPL
            };
            assert!(s.time_wait_accepts_syn(&past_rcv_nxt));
        }
    }

    #[test]
    fn test_window_update_reordered_gap_keeps_window_open() {
        for seq in [REMOTE_SEQ + 1, TcpSeqNumber(i32::MAX - 1), TcpSeqNumber(-2)] {
            let mut s = socket_established();
            s.remote_seq_no = seq;
            s.remote_last_ack = Some(seq);
            s.remote_win_seq = seq - 1;
            send!(s, TcpRepr {
                seq_number: seq + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 400,
                payload: &b"def"[..],
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq),
                ..RECV_TEMPL
            }));
            assert_eq!(s.remote_win_len, 400);
            send!(s, TcpRepr {
                seq_number: seq,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq + 6),
                window_len: 64,
                ..RECV_TEMPL
            }));
            assert_eq!(s.remote_win_len, 400);
            assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
            assert_eq!(s.remote_win_seq, seq + 3);
            assert_eq!(s.remote_seq_no + s.rx_buffer.store.in_order_len(), seq + 6);
            let data = drain_bytes(&mut s);
            assert_eq!(data.len(), 6);
            assert_eq!(&data, b"abcdef");
        }
    }

    #[test]
    fn test_window_update_same_seq_only_grows() {
        let mut s = socket_established();
        for window_len in [400, 500, 500, 300, 0] {
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len,
                ..SEND_TEMPL
            });
            assert_eq!(s.remote_win_len, match window_len {
                400 => 400,
                0 => 0,
                _ => 500,
            });
        }
    }

    #[test]
    fn test_window_update_new_ack_overrides_earlier_seq() {
        for seq in [LOCAL_SEQ + 1, TcpSeqNumber(i32::MAX - 1), TcpSeqNumber(-2)] {
            let mut s = socket_established();
            s.local_seq_no = seq;
            s.remote_last_seq = seq;
            s.remote_max_seq = seq;
            s.send_slice(b"abc").unwrap();
            recv!(s, [TcpRepr {
                seq_number: seq,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abc"[..],
                ..RECV_TEMPL
            }]);
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 4,
                ack_number: Some(seq),
                window_len: 400,
                ..SEND_TEMPL
            });
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(seq + 3),
                window_len: 0,
                ..SEND_TEMPL
            });
            assert_eq!(s.local_seq_no, seq + 3);
            assert_eq!(s.remote_win_len, 0);
            assert_eq!(s.remote_win_seq, REMOTE_SEQ + 1);
            assert_eq!(s.send_queue(), 0);
        }
    }

    #[test]
    fn test_reset_clears_send_window_sequence() {
        let mut s = socket_established();
        s.reset();
        assert_eq!(s.remote_win_seq, TcpSeqNumber::default());
    }

    #[test]
    fn test_reset_clears_old_ack_lower_bound() {
        let mut s = socket_with_acked_scaled_window(LOCAL_SEQ + 1);
        assert_eq!(s.max_snd_wnd, 400);
        assert_eq!(s.bytes_acked, 513);
        s.reset();
        assert_eq!(s.max_snd_wnd, 0);
        assert_eq!(s.bytes_acked, 0);
    }

    #[test]
    fn test_established_bad_seq() {
        let mut s = socket_established();
        // Data outside of receive window.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);

        // Challenge ACKs are rate-limited, we don't get a second one immediately.
        send!(
            s,
            time 100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        // If we wait a bit, we do get a new one.
        send!(
            s,
            time 2000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_old_data_ack_not_rate_limited() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 64,
                ..RECV_TEMPL
            }]
        );
        {
            let frame = s.recv().unwrap().unwrap();
            let data = frame.payload();
            assert_eq!(data, b"abcdef");
        }
        // The remote retransmits data we already acknowledged, e.g. because
        // the ACK above was lost. Each retransmission must elicit a duplicate
        // ACK, even within the challenge ACK rate limit window: withholding it
        // strands the remote in retransmission backoff.
        send!(
            s,
            time 100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            time 200,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_bad_seq_rst_dropped_silently() {
        let mut s = socket_established();
        // Out-of-window RSTs are silently dropped, per RFC 9293 (3.10.7.4)
        // and RFC 5961 (3.2): no challenge ACK, no state change.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);

        // A payload doesn't make it eligible for the data segment exemption
        // from challenge ACK rate limiting either: still no reply.
        send!(
            s,
            time 100,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
    }

    #[test]
    fn test_bad_seq_syn_with_data_rate_limited() {
        let mut s = socket_established();
        // An out-of-window SYN carrying data must not be exempt from challenge
        // ACK rate limiting: RFC 5961 (4.2) says challenge ACKs sent in
        // response to SYNs should be throttled.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );

        // The second one within the rate limit window gets no reply.
        send!(
            s,
            time 100,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
    }

    #[test]
    fn test_established_full_payload_when_remote_mss_limited() {
        const MSS: usize = 64;
        let mut s = socket_established_with_buffer_sizes(MSS + 12, 64);
        s.remote_mss = u16::try_from(MSS).expect("test MSS exceeds u16");
        s.socket.update_rx_mbuf_budget(&s.cx);
        s.send_slice(&[0; MSS + 12]).unwrap();
        recv!(
            s,
            [
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &[0; MSS],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + MSS,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &[0; 12],
                    ..RECV_TEMPL
                }
            ]
        );
    }

    #[test]
    fn test_established_full_payload_when_local_mss_limited() {
        const MSS: usize = BASE_MSS as usize;
        let mut s = socket_established_with_buffer_sizes(MSS + 12, 64);
        s.remote_mss = 9999;
        s.socket.update_rx_mbuf_budget(&s.cx);
        s.remote_win_len = 9999;
        s.send_slice(&[0; MSS + 12]).unwrap();
        recv!(
            s,
            [
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &[0; MSS],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + MSS,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &[0; 12],
                    ..RECV_TEMPL
                }
            ]
        );
    }

    #[test]
    fn test_established_tiny_mss_makes_progress() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(10),
                window_scale: Some(0),
                timestamp: Some(TcpTimestampRepr::new(500, 1)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(usize::from(s.remote_mss), MIN_REMOTE_MSS);

        s.send_slice(&[0; 64]).unwrap();
        recv!(
            s,
            [
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &[0; MIN_REMOTE_MSS],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + (MIN_REMOTE_MSS),
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &[0; 64 - (MIN_REMOTE_MSS)],
                    ..RECV_TEMPL
                }
            ]
        );
    }

    #[test]
    fn test_established_fin() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::CloseWait);
        sanity!(s, socket_close_wait());
    }

    #[test]
    fn test_established_fin_after_missing() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::Established);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6 + 6 + 1),
                window_len: 64,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::CloseWait);
        assert!(s.rx_fin_received);
        assert_eq!(s.recv_queue(), 12);
    }

    #[test]
    fn test_fin_after_six_out_of_order_holes() {
        let mut s = socket_established_with_buffer_sizes(64, 65536);
        s.remote_has_sack = true;
        let seq = REMOTE_SEQ + 1;
        let bytes = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        receive_window_segment(&mut s, 0, &bytes[..2]);
        for offset in (4..26).step_by(4) {
            let reply = receive_window_segment(&mut s, offset, &bytes[offset..offset + 2]);
            assert_eq!(reply.ack_number, Some(seq + 2));
        }
        assert_eq!(s.rx_buffer.store.out_of_order_hole_frames(s.rx_seg_bytes as usize), 6);
        assert_eq!(s.rx_buffer.store.held(), 7);
        let reply = send(&mut s, Instant::from_millis(0), &TcpRepr {
            control: TcpControl::Fin,
            seq_number: seq + bytes.len(),
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }).unwrap();
        assert_eq!(reply.ack_number, Some(seq + 2));
        assert_eq!(reply.sack_ranges, [
            Some(((seq + 24).0 as u32, (seq + 27).0 as u32)),
            Some(((seq + 4).0 as u32, (seq + 6).0 as u32)),
            Some(((seq + 8).0 as u32, (seq + 10).0 as u32)),
        ]);
        assert_eq!(s.rx_fin_seq, Some(seq + 26));
        assert!(!s.rx_fin_received);
        assert_eq!(s.state, State::Established);

        for index in 0..6 {
            let offset = 2 + index * 4;
            let reply = receive_window_segment(&mut s, offset, &bytes[offset..offset + 2]);
            if index < 5 {
                assert_eq!(reply.ack_number, Some(seq + offset + 4));
                assert_eq!(s.rx_fin_seq, Some(seq + 26));
                assert!(!s.rx_fin_received);
                assert_eq!(s.state, State::Established);
            } else {
                assert_eq!(reply.ack_number, Some(seq + 27));
                assert_eq!(reply.sack_ranges, [None, None, None]);
            }
        }
        assert_eq!(s.state, State::CloseWait);
        assert!(s.rx_fin_received);
        assert_eq!(s.rx_fin_seq, None);
        assert_eq!(s.rx_buffer.store.out_of_order_span(), 0);
        let received = drain_bytes(&mut s);
        assert_eq!(received.len(), bytes.len());
        assert_eq!(&received, bytes);
        assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
        assert_eq!(s.rx_buffer.store.held(), 0);
    }

    #[test]
    fn test_fin_truncates_view_crossing_fin() {
        let mut s = socket_established();
        let seq = REMOTE_SEQ + 1;
        let reply = receive_window_segment(&mut s, 3, b"defXYZ");
        assert_eq!(reply.ack_number, Some(seq));
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: seq,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: b"abcde",
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(seq + 6),
            window_len: 64,
            ..RECV_TEMPL
        }]);
        assert_eq!(s.state, State::CloseWait);
        assert_eq!(s.recv_queue(), 5);
        let data = drain_bytes(&mut s);
        assert_eq!(data.len(), 5);
        assert_eq!(&data[..5], b"abcde");
        assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
    }

    #[test]
    fn test_fin_purges_out_of_order_data_past_fin() {
        let mut s = socket_established();
        let seq = REMOTE_SEQ + 1;
        send!(s, TcpRepr {
            seq_number: seq + 3,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: b"defXYZ",
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(seq),
            ..RECV_TEMPL
        }));
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: seq,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: b"abc",
            ..SEND_TEMPL
        });
        assert_eq!(s.recv_queue(), 3);
        assert_eq!(s.rx_buffer.store.out_of_order_span(), 0);
        assert_eq!(s.state, State::CloseWait);
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(seq + 4),
            window_len: 64,
            ..RECV_TEMPL
        }]);
        let data = drain_bytes(&mut s);
        assert_eq!(data.len(), 3);
        assert_eq!(&data[..3], b"abc");
        assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
    }

    fn check_data_after_fin_ack(state: State) {
        let mut s = socket_established();
        s.send_slice(b"abc").unwrap();
        if state == State::Closing {
            s.close();
        }
        recv!(s, [TcpRepr {
            control: if state == State::Closing { TcpControl::Fin } else { TcpControl::None },
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"abc",
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + if state == State::Closing { 5 } else { 4 },
            ack_number: Some(REMOTE_SEQ + 2),
            ..RECV_TEMPL
        }]);
        if state == State::LastAck {
            s.close();
            recv!(s, [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 4,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]);
        }
        let tuple = s.tuple;
        let listen_endpoint = s.listen_endpoint;
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 2,
            ack_number: Some(LOCAL_SEQ + 3),
            payload: b"late",
            ..SEND_TEMPL
        });
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 3);
        assert_eq!(s.send_queue(), 1);
        assert_eq!(s.recv_queue(), 0);
        assert!(!s.can_recv());
        assert_eq!(
            s.remote_seq_no + s.rx_buffer.store.in_order_len(),
            REMOTE_SEQ + 2
        );
        assert_eq!(s.state, state);
        assert_eq!(s.tuple, tuple);
        assert_eq!(s.listen_endpoint, listen_endpoint);
        recv_nothing!(s);
    }

    #[test]
    fn test_close_wait_data_after_fin_ack() {
        check_data_after_fin_ack(State::CloseWait);
    }

    #[test]
    fn test_last_ack_data_after_fin_ack() {
        check_data_after_fin_ack(State::LastAck);
    }

    #[test]
    fn test_last_ack_echo_discards_payload_after_fin_with_partial_ack() {
        let mut s = socket_established_with_buffer_sizes(256, 256);
        let data = [0x07; 100];
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 256,
            payload: &data,
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::CloseWait);
        assert!(s.rx_fin_received);
        assert_eq!(s.recv_queue(), 100);

        let echo = drain_bytes(&mut s);
        assert_eq!(echo.len(), 100);
        assert_eq!(echo, data);
        assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
        assert_eq!(s.send_slice(&echo), Ok(100));
        s.close();
        recv!(s, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 102),
            window_len: 256,
            payload: &echo,
            ..RECV_TEMPL
        }]);
        assert_eq!((s.state, s.recv_queue(), s.send_queue()), (State::LastAck, 0, 100));
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);

        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 102,
            ack_number: Some(LOCAL_SEQ + 11),
            window_len: 256,
            payload: &[0xab; 20],
            ..SEND_TEMPL
        });
        assert_eq!((s.state, s.recv_queue(), s.send_queue()), (State::LastAck, 0, 90));
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 11);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 102);
        assert_eq!(s.rx_buffer.store.out_of_order_span(), 0);
        assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
        recv_nothing!(s);
    }

    #[test]
    fn test_closing_data_after_fin_ack() {
        check_data_after_fin_ack(State::Closing);
    }

    #[test]
    fn test_fin_payload_truncated_at_right_edge() {
        let (mut s, _frames) = socket_with_held_rx_frames(64, REMOTE_SEQ + 1, 5);
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &[0; 65],
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Established);
        assert!(!s.rx_fin_received);
        assert_eq!(s.recv_queue(), 64);
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 64),
            window_len: 0,
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_fin_payload_ending_at_window_edge_is_consumed() {
        for seq in [TcpSeqNumber(100), TcpSeqNumber(-64)] {
            for len in [64, 1024] {
                let mut s = socket_established_with_buffer_sizes(64, len);
                s.remote_mss = BASE_MSS;
                s.socket.update_rx_mbuf_budget(&s.cx);
                s.remote_seq_no = seq - 5;
                s.remote_last_ack = Some(seq - 5);
                let _frames = hold_rx_frames(&mut s, 5);
                let data = vec![42; len];
                send!(s, TcpRepr {
                    control: TcpControl::Fin,
                    seq_number: seq,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &data,
                    ..SEND_TEMPL
                });
                assert_eq!(s.state, State::CloseWait);
                assert!(s.rx_fin_received);
                assert_eq!(s.rx_fin_seq, None);
                assert_eq!(s.recv_queue(), len);
                recv!(s, [TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(seq + len + 1),
                    window_len: 0,
                    ..RECV_TEMPL
                }]);
                let received = drain_bytes(&mut s);
                assert_eq!(received.len(), len);
                assert_eq!(received, data);
                assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
            }
        }
    }

    #[test]
    fn test_out_of_order_fin_at_window_edge_does_not_authorize_rst() {
        for seq in [TcpSeqNumber(100), TcpSeqNumber(-64)] {
            let mut s = socket_established();
            s.remote_seq_no = seq;
            s.remote_last_ack = Some(seq);
            s.remote_has_sack = true;
            send!(s, TcpRepr {
                control: TcpControl::Fin,
                seq_number: seq + 61,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"abc",
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq),
                sack_ranges: [Some(((seq + 61).0 as u32, (seq + 65).0 as u32)), None, None],
                ..RECV_TEMPL
            }));
            send!(s, TcpRepr {
                control: TcpControl::Rst,
                seq_number: seq + 65,
                ack_number: None,
                ..SEND_TEMPL
            });
            assert_eq!(s.state, State::Established);
            assert_eq!(s.tuple, Some(TUPLE));
            assert_eq!(s.rx_fin_seq, Some(seq + 64));
            assert_eq!(s.rx_buffer.store.out_of_order_ranges().collect::<Vec<_>>(), vec![(61, 64)]);
        }
    }

    #[test]
    fn test_lower_out_of_order_fin_replaces_retained_fin() {
        for seq in [TcpSeqNumber(100), TcpSeqNumber(-3)] {
            for sack in [false, true] {
                let mut s = socket_established();
                s.remote_seq_no = seq;
                s.remote_last_ack = Some(seq);
                s.remote_has_sack = sack;
                for offset in [6, 3] {
                    let reply = send(&mut s, Instant::from_millis(0), &TcpRepr {
                        control: TcpControl::Fin,
                        seq_number: seq + offset,
                        ack_number: Some(LOCAL_SEQ + 1),
                        ..SEND_TEMPL
                    }).unwrap();
                    assert_eq!(reply.ack_number, Some(seq));
                }
                let reply = send(&mut s, Instant::from_millis(0), &TcpRepr {
                    seq_number: seq,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: b"abc",
                    ..SEND_TEMPL
                }).unwrap();
                assert_eq!(s.state, State::CloseWait);
                assert_eq!(reply.ack_number, Some(seq + 4));
                assert_eq!(reply.sack_ranges, [None, None, None]);
                assert!(s.rx_fin_received);
                assert_eq!(s.rx_fin_seq, None);
                assert_eq!(s.rx_buffer.store.out_of_order_span(), 0);
                assert_eq!(s.recv_queue(), 3);
                let data = drain_bytes(&mut s);
                assert_eq!(data.len(), 3);
                assert_eq!(&data[..3], b"abc");
                assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
                recv_nothing!(s);
            }
        }
    }

    #[test]
    fn test_lower_out_of_order_fin_changes_rst_end() {
        for seq in [TcpSeqNumber(100), TcpSeqNumber(-3)] {
            let mut s = socket_established();
            s.remote_seq_no = seq;
            s.remote_last_ack = Some(seq);
            s.remote_has_sack = true;
            for offset in [6, 3] {
                let reply = send(&mut s, Instant::from_millis(0), &TcpRepr {
                    control: TcpControl::Fin,
                    seq_number: seq + offset,
                    ack_number: Some(LOCAL_SEQ + 1),
                    ..SEND_TEMPL
                }).unwrap();
                assert_eq!(reply.ack_number, Some(seq));
            }
            let reply = send(&mut s, Instant::from_millis(0), &TcpRepr {
                seq_number: seq,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"abc",
                ..SEND_TEMPL
            }).unwrap();
            assert_eq!(reply.ack_number, Some(seq + 4));
            let reply = send(&mut s, Instant::from_millis(0), &TcpRepr {
                control: TcpControl::Rst,
                seq_number: seq + 7,
                ack_number: None,
                ..SEND_TEMPL
            });
            assert_eq!(s.state, State::CloseWait);
            assert_eq!(s.tuple, Some(TUPLE));
            assert_eq!(s.rx_fin_seq, None);
            assert_eq!(s.rx_buffer.store.out_of_order_span(), 0);
            assert_eq!(reply, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq + 4),
                window_len: 64,
                ..RECV_TEMPL
            }));
        }
    }

    #[test]
    fn test_lower_out_of_order_fin_caps_data() {
        for seq in [TcpSeqNumber(100), TcpSeqNumber(-3)] {
            let mut s = socket_established();
            s.remote_seq_no = seq;
            s.remote_last_ack = Some(seq);
            send!(s, TcpRepr {
                seq_number: seq + 4,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"ef",
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq),
                ..RECV_TEMPL
            }));
            for offset in [6, 3] {
                send!(s, TcpRepr {
                    control: TcpControl::Fin,
                    seq_number: seq + offset,
                    ack_number: Some(LOCAL_SEQ + 1),
                    ..SEND_TEMPL
                }, Some(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(seq),
                    ..RECV_TEMPL
                }));
            }
            send!(s, TcpRepr {
                seq_number: seq + 2,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"cXXXX",
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq),
                ..RECV_TEMPL
            }));
            let reply = send(&mut s, Instant::from_millis(0), &TcpRepr {
                seq_number: seq,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"ab",
                ..SEND_TEMPL
            }).unwrap();
            assert_eq!(reply.ack_number, Some(seq + 4));
            assert_eq!(s.state, State::CloseWait);
            assert_eq!(s.rx_buffer.store.out_of_order_span(), 0);
            let data = drain_bytes(&mut s);
            assert_eq!(data.len(), 3);
            assert_eq!(&data[..3], b"abc");
            assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
        }
    }

    #[test]
    fn test_in_order_fin_replaces_retained_out_of_order_fin() {
        for seq in [TcpSeqNumber(100), TcpSeqNumber(-4)] {
            let mut s = socket_established();
            s.remote_seq_no = seq;
            s.remote_last_ack = Some(seq);
            let listen_endpoint = s.listen_endpoint;
            send!(s, TcpRepr {
                seq_number: seq + 9,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"xyz",
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq),
                ..RECV_TEMPL
            }));
            let _ = send(&mut s, Instant::from_millis(0), &TcpRepr {
                control: TcpControl::Fin,
                seq_number: seq + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            });
            assert_eq!(s.rx_fin_seq, Some(seq + 6));
            send!(s, TcpRepr {
                control: TcpControl::Fin,
                seq_number: seq,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            });
            assert_eq!(s.state, State::CloseWait);
            assert!(s.rx_fin_received);
            assert_eq!(s.rx_fin_seq, None);
            assert_eq!(s.rx_buffer.store.out_of_order_span(), 0);
            assert_eq!(s.recv_queue(), 0);
            assert_eq!(s.tuple, Some(TUPLE));
            assert_eq!(s.listen_endpoint, listen_endpoint);
            recv!(s, [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq + 1),
                ..RECV_TEMPL
            }]);
            assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
        }
    }

    fn check_out_of_order_fin_covered_by_data(offset: usize, payload: &[u8]) {
        for seq in [TcpSeqNumber(100), TcpSeqNumber(-4)] {
            let mut s = socket_established();
            s.remote_seq_no = seq;
            s.remote_last_ack = Some(seq);
            send!(s, TcpRepr {
                seq_number: seq + 4,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"efghij",
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq),
                ..RECV_TEMPL
            }));
            let _ = send(&mut s, Instant::from_millis(0), &TcpRepr {
                control: TcpControl::Fin,
                seq_number: seq + offset,
                ack_number: Some(LOCAL_SEQ + 1),
                payload,
                ..SEND_TEMPL
            });
            assert_eq!(s.rx_fin_seq, None);
            send!(s, TcpRepr {
                seq_number: seq,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"abcd",
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq + 10),
                window_len: 64,
                ..RECV_TEMPL
            }));
            assert_eq!(s.state, State::Established);
            assert!(!s.rx_fin_received);
            let data = drain_bytes(&mut s);
            assert_eq!(data.len(), 10);
            assert_eq!(&data, b"abcdefghij");
        }
    }

    #[test]
    fn test_bare_out_of_order_fin_covered_by_data_is_duplicate() {
        check_out_of_order_fin_covered_by_data(6, b"");
    }

    #[test]
    fn test_out_of_order_fin_segment_covered_by_data_is_duplicate() {
        check_out_of_order_fin_covered_by_data(4, b"XXXXX");
    }

    #[test]
    fn test_bare_out_of_order_fin_immediate_ack_and_sack() {
        for sack in [false, true] {
            for seq in [TcpSeqNumber(100), TcpSeqNumber(-3)] {
                let mut s = socket_established();
                s.remote_seq_no = seq;
                s.remote_last_ack = Some(seq);
                s.remote_has_sack = sack;
                send!(s, TcpRepr {
                    control: TcpControl::Fin,
                    seq_number: seq + 3,
                    ack_number: Some(LOCAL_SEQ + 1),
                    ..SEND_TEMPL
                }, Some(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(seq),
                    sack_ranges: [if sack { Some(((seq + 3).0 as u32, (seq + 4).0 as u32)) } else { None }, None, None],
                    ..RECV_TEMPL
                }));
                assert_eq!(s.state, State::Established);
                assert_eq!(s.rx_fin_seq, Some(seq + 3));
                assert_eq!(s.rx_buffer.store.out_of_order_span(), 0);
                recv_nothing!(s);
            }
        }
    }

    #[test]
    fn test_out_of_order_fin_payload_sack_includes_fin() {
        for seq in [TcpSeqNumber(100), TcpSeqNumber(-4)] {
            let mut s = socket_established();
            s.remote_seq_no = seq;
            s.remote_last_ack = Some(seq);
            s.remote_has_sack = true;
            send!(s, TcpRepr {
                control: TcpControl::Fin,
                seq_number: seq + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"def",
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq),
                sack_ranges: [Some(((seq + 3).0 as u32, (seq + 7).0 as u32)), None, None],
                ..RECV_TEMPL
            }));
            assert_eq!(s.rx_fin_seq, Some(seq + 6));
        }
    }

    #[test]
    fn test_bare_out_of_order_fin_gap_fill_acks_immediately() {
        for seq in [TcpSeqNumber(100), TcpSeqNumber(-3)] {
            let mut s = socket_established();
            s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
            s.remote_seq_no = seq;
            s.remote_last_ack = Some(seq);
            let _ = send(&mut s, Instant::from_millis(0), &TcpRepr {
                control: TcpControl::Fin,
                seq_number: seq + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            });
            send!(s, TcpRepr {
                seq_number: seq,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"abc",
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq + 4),
                window_len: 64,
                ..RECV_TEMPL
            }));
            assert_eq!(s.state, State::CloseWait);
            assert_eq!(s.recv_queue(), 3);
            assert_eq!(s.rx_fin_seq, None);
            assert_eq!(s.rx_buffer.store.out_of_order_span(), 0);
            recv_nothing!(s);
        }
    }

    #[test]
    fn test_bare_out_of_order_fin_sack_merges_or_stands_alone() {
        for (data_offset, payload, fin_offset, left, right, second) in [
            (3, &b"def"[..], 6, 3, 7, None),
            (9, &b"jkl"[..], 3, 3, 4, Some((9, 12))),
            (3, &b"de"[..], 6, 6, 7, Some((3, 5))),
        ] {
            let seq = TcpSeqNumber(100);
            let mut s = socket_established();
            s.remote_seq_no = seq;
            s.remote_last_ack = Some(seq);
            s.remote_has_sack = true;
            let _ = send(&mut s, Instant::from_millis(0), &TcpRepr {
                seq_number: seq + data_offset,
                ack_number: Some(LOCAL_SEQ + 1),
                payload,
                ..SEND_TEMPL
            });
            let _ = send(&mut s, Instant::from_millis(0), &TcpRepr {
                control: TcpControl::Fin,
                seq_number: seq + fin_offset,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            });
            send!(s, TcpRepr {
                control: TcpControl::Rst,
                seq_number: seq + 1,
                ack_number: None,
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq),
                sack_ranges: [
                    Some(((seq + left).0 as u32, (seq + right).0 as u32)),
                    second.map(|(left, right)| ((seq + left).0 as u32, (seq + right).0 as u32)),
                    None,
                ],
                ..RECV_TEMPL
            }));
            assert_eq!(s.state, State::Established);
        }
    }

    #[test]
    fn test_bare_out_of_order_fin_sack_fallback_selects_lowest_range() {
        let seq = TcpSeqNumber(100);
        let mut s = socket_established();
        s.remote_seq_no = seq;
        s.remote_last_ack = Some(seq);
        s.remote_has_sack = true;
        let _ = send(&mut s, Instant::from_millis(0), &TcpRepr {
            seq_number: seq + 9,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: b"jkl",
            ..SEND_TEMPL
        });
        let _ = send(&mut s, Instant::from_millis(0), &TcpRepr {
            control: TcpControl::Fin,
            seq_number: seq + 3,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, TcpRepr {
            seq_number: seq,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: b"a",
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(seq + 1),
            window_len: 64,
            sack_ranges: [Some((103, 104)), Some((109, 112)), None],
            ..RECV_TEMPL
        }));
        assert_eq!(s.rx_fin_seq, Some(seq + 3));
        assert_eq!(s.state, State::Established);
    }

    #[test]
    fn test_out_of_order_fin_caps_merged_data() {
        for seq in [REMOTE_SEQ + 1, TcpSeqNumber(-4)] {
            let mut s = socket_established();
            s.remote_seq_no = seq;
            s.remote_last_ack = Some(seq);
            send!(s, TcpRepr {
                seq_number: seq + 4,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"ef",
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq),
                ..RECV_TEMPL
            }));
            send!(s, TcpRepr {
                control: TcpControl::Fin,
                seq_number: seq + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq),
                ..RECV_TEMPL
            }));
            send!(s, TcpRepr {
                seq_number: seq + 5,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"fXXXX",
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq),
                ..RECV_TEMPL
            }));
            send!(s, TcpRepr {
                seq_number: seq,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"abcd",
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq + 7),
                window_len: 64,
                ..RECV_TEMPL
            }));
            assert_eq!(s.state, State::CloseWait);
            assert_eq!(s.rx_buffer.store.out_of_order_span(), 0);
            let data = drain_bytes(&mut s);
            assert_eq!(data.len(), 6);
            assert_eq!(&data[..6], b"abcdef");
            assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
        }
    }

    #[test]
    fn test_out_of_order_fin_discards_later_data() {
        let mut s = socket_established();
        let seq = REMOTE_SEQ + 1;
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: seq + 6,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(seq),
            ..RECV_TEMPL
        }));
        send!(s, TcpRepr {
            seq_number: seq + 7,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: b"late",
            ..SEND_TEMPL
        });
        assert_eq!(s.rx_buffer.store.out_of_order_span(), 0);
        send!(s, TcpRepr {
            seq_number: seq,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: b"abcdeflate",
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(seq + 7),
            window_len: 64,
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::CloseWait);
        assert_eq!(s.recv_queue(), 6);
        recv_nothing!(s);
    }

    #[test]
    fn test_established_send_fin() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_rst() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_synchronized_syn_without_ack_challenge_ack() {
        for mut s in [socket_established(), socket_fin_wait_1(), socket_fin_wait_2(),
                      socket_close_wait(), socket_last_ack(), socket_closing(),
                      socket_time_wait(true)] {
            for offset in [0, 1, 63, 64, 256] {
                let state = s.state;
                let timer = s.timer;
                let seq = s.remote_seq_no + s.rx_buffer.store.in_order_len();
                let local_seq = s.remote_max_seq;
                let window = s.remote_win_len;
                send!(s, time offset as i64 * 500, TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: seq + offset,
                    ack_number: None,
                    window_len: 0,
                    payload: b"ignored",
                    ..SEND_TEMPL
                }, Some(TcpRepr {
                    seq_number: local_seq,
                    ack_number: Some(seq),
                    ..RECV_TEMPL
                }));
                assert_eq!(s.state, state);
                assert_eq!(s.timer, timer);
                assert_eq!(s.tuple, Some(TUPLE));
                assert_eq!(s.remote_win_len, window);
                assert_eq!((s.recv_queue(), s.send_queue()), (0, 0));
                assert_eq!(s.remote_seq_no, seq);
                assert_eq!(s.remote_max_seq, local_seq);
            }
        }
    }

    #[test]
    fn test_established_syn_ack_preserves_buffers_and_window() {
        let mut s = socket_established();
        s.send_slice(b"tx").unwrap();
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"tx",
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: b"rx",
            ..SEND_TEMPL
        });
        let timer = s.timer;
        s.remote_win_len = 1;
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ + 3,
            ack_number: Some(LOCAL_SEQ + 3),
            window_len: 0,
            payload: b"ignored",
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 2,
            ack_number: Some(REMOTE_SEQ + 3),
            window_len: 64,
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Established);
        assert_eq!(s.timer, timer);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
        assert_eq!(s.remote_win_len, 1);
        assert_eq!((s.recv_queue(), s.send_queue()), (2, 2));
        assert_eq!(s.recv().unwrap().unwrap().payload(), b"rx");
        assert_eq!(s.tx_buffer.get_allocated(0, 2), b"tx");
        assert_eq!((s.recv_queue(), s.send_queue()), (0, 2));
    }

    #[test]
    fn test_synchronized_syn_ack_below_snd_una_challenge_ack() {
        for mut s in [socket_established(), socket_time_wait(true)] {
            let state = s.state;
            let timer = s.timer;
            let seq = s.remote_seq_no;
            let local_seq = s.local_seq_no;
            send!(s, time 2000, TcpRepr {
                control: TcpControl::Syn,
                seq_number: seq,
                ack_number: Some(local_seq - 1),
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: local_seq,
                ack_number: Some(seq),
                ..RECV_TEMPL
            }));
            assert_eq!(s.state, state);
            if state == State::TimeWait {
                assert_eq!(s.timer, Timer::Close {
                    expires_at: Instant::from_millis(2000) + CLOSE_DELAY,
                });
            } else {
                assert_eq!(s.timer, timer);
            }
        }
    }

    #[test]
    fn test_established_syn_challenge_ack_500ms_boundary() {
        let mut s = socket_established();
        let syn = TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        };
        let ack = TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        };
        send!(s, time 0, syn, Some(ack.clone()));
        send!(s, time 499, syn);
        recv_nothing!(s, time 499);
        send!(s, time 500, syn, Some(ack));
    }

    #[test]
    fn test_time_wait_in_window_ack_restarts_timer() {
        let mut s = socket_time_wait(true);
        send!(s, time 2000, TcpRepr {
            seq_number: REMOTE_SEQ + 3,
            ack_number: Some(LOCAL_SEQ + 2),
            window_len: 0,
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 2,
            ack_number: Some(REMOTE_SEQ + 2),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::TimeWait);
        assert_eq!(s.remote_win_len, 256);
        assert_eq!(s.timer, Timer::Close {
            expires_at: Instant::from_millis(2000) + CLOSE_DELAY,
        });
        send!(s, time 2499, TcpRepr {
            seq_number: REMOTE_SEQ + 3,
            ack_number: Some(LOCAL_SEQ + 2),
            ..SEND_TEMPL
        });
        assert_eq!(s.timer, Timer::Close {
            expires_at: Instant::from_millis(2499) + CLOSE_DELAY,
        });
        send!(s, time 2500, TcpRepr {
            seq_number: REMOTE_SEQ + 3,
            ack_number: Some(LOCAL_SEQ + 2),
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 2,
            ack_number: Some(REMOTE_SEQ + 2),
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_time_wait_fin_and_data_not_rate_limited() {
        for (control, payload) in [(TcpControl::Fin, &b""[..]),
                                   (TcpControl::None, &b"data"[..]),
                                   (TcpControl::Psh, &b"data"[..]),
                                   (TcpControl::Fin, &b"data"[..])] {
            for ack_number in [None, Some(LOCAL_SEQ + 2)] {
                let mut s = socket_time_wait(true);
                let ack = TcpRepr {
                    seq_number: LOCAL_SEQ + 2,
                    ack_number: Some(REMOTE_SEQ + 2),
                    ..RECV_TEMPL
                };
                send!(s, TcpRepr {
                    seq_number: REMOTE_SEQ + 256,
                    ack_number: Some(LOCAL_SEQ + 2),
                    ..SEND_TEMPL
                }, Some(ack.clone()));
                let timer = s.timer;
                let segment = TcpRepr {
                    control,
                    seq_number: REMOTE_SEQ + 2,
                    ack_number,
                    payload,
                    ..SEND_TEMPL
                };
                send!(s, time 100, segment.clone(), Some(ack.clone()));
                assert_eq!(s.timer, if ack_number.is_some() {
                    Timer::Close {
                        expires_at: Instant::from_millis(100) + CLOSE_DELAY,
                    }
                } else {
                    timer
                });
                assert_eq!(s.challenge_ack_timer, Instant::from_millis(500));
                send!(s, time 499, segment.clone(), Some(ack.clone()));
                send!(s, time 500, segment, Some(ack));
                assert_eq!(s.state, State::TimeWait);
                assert_eq!(s.remote_seq_no, REMOTE_SEQ + 2);
                assert_eq!(s.recv_queue(), 0);
                assert_eq!(s.remote_win_len, 256);
                assert_eq!(s.timer, if ack_number.is_some() {
                    Timer::Close {
                        expires_at: Instant::from_millis(500) + CLOSE_DELAY,
                    }
                } else {
                    timer
                });
                assert_eq!(s.challenge_ack_timer, Instant::from_millis(500));
            }
        }
    }

    #[test]
    fn test_time_wait_bare_ack_at_rcv_nxt_restarts_timer() {
        for ack_number in [Some(LOCAL_SEQ + 2), Some(LOCAL_SEQ - 1),
                           Some(LOCAL_SEQ + 1000)] {
            let mut s = socket_time_wait(true);
            send!(s, time 2000, TcpRepr {
                seq_number: REMOTE_SEQ + 2,
                ack_number,
                window_len: 0,
                ..SEND_TEMPL
            });
            recv_nothing!(s, time 2000);
            assert_eq!(s.state, State::TimeWait);
            assert_eq!(s.timer, Timer::Close {
                expires_at: Instant::from_millis(2000) + CLOSE_DELAY,
            });
            assert_eq!(s.remote_win_len, 256);
            assert_eq!(s.challenge_ack_timer, Instant::from_millis(0));
        }
    }

    #[test]
    fn test_time_wait_flagless_fin_does_not_restart_timer() {
        let mut s = socket_time_wait(true);
        let timer = s.timer;
        send!(s, time 2000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 2,
            ack_number: None,
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 2,
            ack_number: Some(REMOTE_SEQ + 2),
            ..RECV_TEMPL
        }));
        assert_eq!(s.timer, timer);
        assert_eq!(s.state, State::TimeWait);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 2);
        assert_eq!(s.recv_queue(), 0);
        assert_eq!(s.challenge_ack_timer, Instant::from_millis(0));
        recv_nothing!(s, time 11_000);
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_time_wait_fin_then_pure_acks_share_rate_limit() {
        let mut s = socket_time_wait(true);
        let ack = TcpRepr {
            seq_number: LOCAL_SEQ + 2,
            ack_number: Some(REMOTE_SEQ + 2),
            ..RECV_TEMPL
        };
        send!(s, time 2000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 2,
            ack_number: None,
            ..SEND_TEMPL
        }, Some(ack.clone()));
        let segment = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 2),
            ..SEND_TEMPL
        };
        send!(s, time 2100, segment.clone(), Some(ack.clone()));
        assert_eq!(s.timer, Timer::Close {
            expires_at: Instant::from_millis(2100) + CLOSE_DELAY,
        });
        assert_eq!(s.challenge_ack_timer, Instant::from_millis(2600));
        send!(s, time 2200, segment.clone());
        assert_eq!(s.timer, Timer::Close {
            expires_at: Instant::from_millis(2200) + CLOSE_DELAY,
        });
        send!(s, time 2599, segment.clone());
        assert_eq!(s.challenge_ack_timer, Instant::from_millis(2600));
        send!(s, time 2600, segment, Some(ack));
    }

    #[test]
    fn test_time_wait_flagless_non_rst_shares_ack_rate_limit() {
        for control in [TcpControl::None, TcpControl::Psh] {
            let mut s = socket_time_wait(true);
            let ack = TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            };
            send!(s, time 2000, TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 2,
                ack_number: None,
                ..SEND_TEMPL
            }, Some(ack.clone()));
            let timer = s.timer;
            let segment = TcpRepr {
                control,
                seq_number: REMOTE_SEQ + 3,
                ack_number: None,
                ..SEND_TEMPL
            };
            send!(s, time 2100, segment.clone(), Some(ack.clone()));
            send!(s, time 2200, segment.clone());
            send!(s, time 2599, segment.clone());
            assert_eq!(s.timer, timer);
            assert_eq!(s.challenge_ack_timer, Instant::from_millis(2600));
            send!(s, time 2600, segment, Some(ack));
            assert_eq!(s.timer, timer);
        }
    }

    #[test]
    fn test_time_wait_flagless_at_rcv_nxt_restarts_timer() {
        for control in [TcpControl::None, TcpControl::Psh] {
            let mut s = socket_time_wait(true);
            send!(s, time 2000, TcpRepr {
                control,
                seq_number: REMOTE_SEQ + 2,
                ack_number: None,
                window_len: 0,
                ..SEND_TEMPL
            });
            recv_nothing!(s, time 2000);
            assert_eq!(s.state, State::TimeWait);
            assert_eq!(s.timer, Timer::Close {
                expires_at: Instant::from_millis(2000) + CLOSE_DELAY,
            });
            assert_eq!(s.remote_win_len, 256);
            assert_eq!(s.challenge_ack_timer, Instant::from_millis(0));
        }
    }

    #[test]
    fn test_time_wait_flagless_out_of_sequence_does_not_restart_timer() {
        let mut s = socket_time_wait(true);
        let timer = s.timer;
        send!(s, time 2000, TcpRepr {
            seq_number: REMOTE_SEQ + 3,
            ack_number: None,
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 2,
            ack_number: Some(REMOTE_SEQ + 2),
            ..RECV_TEMPL
        }));
        assert_eq!(s.timer, timer);
        assert_eq!(s.challenge_ack_timer, Instant::from_millis(2500));
    }

    #[test]
    fn test_time_wait_bare_ack_at_rcv_nxt_extends_deadline() {
        let mut s = socket_fin_wait_2();
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 2),
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 2,
            ack_number: Some(REMOTE_SEQ + 2),
            ..RECV_TEMPL
        }]);
        assert_eq!(s.state, State::TimeWait);
        assert_eq!(s.timer, Timer::Close {
            expires_at: Instant::from_millis(0) + CLOSE_DELAY,
        });
        send!(s, time 9000, TcpRepr {
            seq_number: REMOTE_SEQ + 2,
            ack_number: Some(LOCAL_SEQ + 2),
            ..SEND_TEMPL
        });
        recv_nothing!(s, time 10_001);
        assert_eq!(s.state, State::TimeWait);
        assert_eq!(s.timer, Timer::Close {
            expires_at: Instant::from_millis(9000) + CLOSE_DELAY,
        });
        recv_nothing!(s, time 18_999);
        assert_eq!(s.state, State::TimeWait);
        recv_nothing!(s, time 19_000);
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_out_of_window_fin_not_rate_limited() {
        let mut s = socket_established();
        let ack = TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        };
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 256,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }, Some(ack.clone()));
        send!(s, time 100, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 256,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }, Some(ack));
        assert_eq!(s.state, State::Established);
        assert_eq!(s.challenge_ack_timer, Instant::from_millis(500));
    }

    #[test]
    fn test_synchronized_rst_in_window_challenge_ack() {
        for mut s in [socket_established(), socket_fin_wait_1(), socket_fin_wait_2(),
                      socket_close_wait(), socket_closing(), socket_last_ack()] {
            let state = s.state;
            let timer = s.timer;
            let seq = s.remote_seq_no + s.rx_buffer.store.in_order_len();
            let local_seq = s.remote_last_seq;
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Rst,
                    seq_number: seq + 1,
                    ack_number: Some(LOCAL_SEQ + 1000),
                    ..SEND_TEMPL
                },
                Some(TcpRepr {
                    seq_number: local_seq,
                    ack_number: Some(seq),
                    ..RECV_TEMPL
                })
            );
            assert_eq!(s.state, state);
            assert_eq!(s.timer, timer);
            assert_eq!(s.tuple, Some(TUPLE));
        }
    }

    fn check_rst_window_right_edge(seq: TcpSeqNumber) {
        for shift in [0, 2] {
            for mut s in [socket_established(), socket_fin_wait_1(), socket_fin_wait_2(),
                          socket_close_wait(), socket_closing(), socket_last_ack()] {
                s.remote_seq_no = seq;
                s.remote_last_ack = Some(seq);
                s.remote_win_shift = shift;
                s.remote_last_win_bytes = 64;
                let state = s.state;
                let timer = s.timer;
                let listen_endpoint = s.listen_endpoint;
                let local_seq = s.remote_max_seq;
                send!(s, TcpRepr {
                    control: TcpControl::Rst,
                    seq_number: seq + 64,
                    ack_number: Some(LOCAL_SEQ + 1000),
                    ..SEND_TEMPL
                }, Some(TcpRepr {
                    seq_number: local_seq,
                    ack_number: Some(seq),
                    window_len: 64 >> shift,
                    ..RECV_TEMPL
                }));
                assert_eq!(s.state, state);
                assert_eq!(s.timer, timer);
                assert_eq!(s.tuple, Some(TUPLE));
                assert_eq!(s.listen_endpoint, listen_endpoint);
                assert_eq!(s.rx_buffer.store.in_order_len(), 0);
                assert_eq!(s.challenge_ack_timer, Instant::from_millis(500));
            }
        }
    }

    #[test]
    fn test_rst_window_right_edge_challenge_ack() {
        check_rst_window_right_edge(TcpSeqNumber(100));
    }

    #[test]
    fn test_rst_window_right_edge_wrap_challenge_ack() {
        for seq in [TcpSeqNumber(-32), TcpSeqNumber(-1), TcpSeqNumber(i32::MAX - 32)] {
            check_rst_window_right_edge(seq);
        }
    }

    fn check_rst_window_delayed_ack(seq: TcpSeqNumber) {
        for (rst_seq, payload) in [(seq + 2, &[][..]), (seq, &[][..]), (seq - 1, &b"a"[..])] {
            let mut s = socket_established();
            s.remote_seq_no = seq;
            s.remote_last_ack = Some(seq);
            s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
            send!(s, TcpRepr {
                seq_number: seq,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            });
            recv_nothing!(s);
            assert_eq!(s.remote_last_ack, Some(seq));
            assert_eq!(s.remote_last_win_bytes, 64);
            assert_eq!(s.remote_seq_no + s.rx_buffer.store.in_order_len(), seq + 3);
            send!(s, TcpRepr {
                control: TcpControl::Rst,
                seq_number: rst_seq,
                ack_number: None,
                payload,
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq + 3),
                window_len: 64,
                ..RECV_TEMPL
            }));
            assert_eq!(s.state, State::Established);
            assert_eq!(s.tuple, Some(TUPLE));
            assert_eq!(s.rx_buffer.store.in_order_len(), 3);
        }
    }

    #[test]
    fn test_rst_window_delayed_ack_challenge_ack() {
        check_rst_window_delayed_ack(TcpSeqNumber(100));
    }

    #[test]
    fn test_rst_window_delayed_ack_wrap_challenge_ack() {
        check_rst_window_delayed_ack(TcpSeqNumber(-2));
    }

    #[test]
    fn test_rst_window_delayed_ack_right_edge() {
        for seq in [TcpSeqNumber(100), TcpSeqNumber(-2), TcpSeqNumber(i32::MAX - 2)] {
            for shift in [0, 2] {
                for (offset, expected) in [(64, Some(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(seq + 3),
                    window_len: 64 >> shift,
                    ..RECV_TEMPL
                })), (65, None)] {
                    let mut s = socket_established();
                    s.remote_seq_no = seq;
                    s.remote_last_ack = Some(seq);
                    s.remote_win_shift = shift;
                    s.remote_last_win_bytes = 64;
                    s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
                    send!(s, TcpRepr {
                        seq_number: seq,
                        ack_number: Some(LOCAL_SEQ + 1),
                        payload: &b"abc"[..],
                        ..SEND_TEMPL
                    });
                    recv_nothing!(s);
                    assert_eq!(s.remote_last_ack, Some(seq));
                    assert_eq!(s.remote_last_win_bytes, 64);
                    assert_eq!(s.remote_seq_no + s.rx_buffer.store.in_order_len(), seq + 3);
                    let timer = s.timer;
                    let listen_endpoint = s.listen_endpoint;
                    send!(s, TcpRepr {
                        control: TcpControl::Rst,
                        seq_number: seq + offset,
                        ack_number: None,
                        ..SEND_TEMPL
                    }, expected);
                    assert_eq!(s.state, State::Established);
                    assert_eq!(s.tuple, Some(TUPLE));
                    assert_eq!(s.listen_endpoint, listen_endpoint);
                    assert_eq!(s.timer, timer);
                    assert_eq!(s.rx_buffer.store.in_order_len(), 3);
                    let data = drain_bytes(&mut s);
                    assert_eq!(data.len(), 3);
                    assert_eq!(data, *b"abc");
                }
            }
        }
    }

    fn check_rst_window_zero_window_payload(seq: TcpSeqNumber) {
        let (mut s, _frames) = socket_with_held_rx_frames(3, seq, 5);
        send!(s, TcpRepr {
            seq_number: seq,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abc"[..],
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(seq + 3),
            window_len: 0,
            ..RECV_TEMPL
        }]);
        assert_eq!(s.remote_last_ack, Some(seq + 3));
        assert_eq!(s.remote_last_win_bytes, 0);
        assert_eq!(s.recv_room(), 0);
        assert_eq!(s.rx_buffer.store.held() + s.rx_buffer.shared.held.get(), s.rx_frame_cap());
        send!(s, TcpRepr {
            control: TcpControl::Rst,
            seq_number: seq + 2,
            ack_number: None,
            payload: &b"a"[..],
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(seq + 3),
            window_len: 0,
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Established);
        assert_eq!(s.tuple, Some(TUPLE));
        assert_eq!(s.rx_buffer.store.in_order_len(), 3);
        recv_nothing!(s);
    }

    #[test]
    fn test_rst_window_zero_window_payload_challenge_ack() {
        check_rst_window_zero_window_payload(TcpSeqNumber(100));
    }

    #[test]
    fn test_rst_window_zero_window_payload_wrap_challenge_ack() {
        check_rst_window_zero_window_payload(TcpSeqNumber(-2));
    }

    #[test]
    fn test_rst_window_outside_dropped_silently() {
        for seq in [TcpSeqNumber(100), TcpSeqNumber(-32)] {
            for (rst_seq, payload) in [(seq + 65, &[][..]), (seq + 65, &b"a"[..]),
                                       (seq - 1, &[][..]), (seq - 2, &b"a"[..])] {
                let mut s = socket_established();
                s.remote_seq_no = seq;
                s.remote_last_ack = Some(seq);
                let timer = s.timer;
                send!(s, TcpRepr {
                    control: TcpControl::Rst,
                    seq_number: rst_seq,
                    ack_number: None,
                    payload,
                    ..SEND_TEMPL
                });
                assert_eq!(s.state, State::Established);
                assert_eq!(s.timer, timer);
                assert_eq!(s.tuple, Some(TUPLE));
                assert_eq!(s.remote_last_ack, Some(seq));
                assert_eq!(s.challenge_ack_timer, Instant::from_secs(0));
                recv_nothing!(s);
            }
        }
    }

    #[test]
    fn test_rst_window_without_last_ack_payload_challenge_ack() {
        let mut s = socket_established();
        s.remote_seq_no = TcpSeqNumber(100);
        s.remote_last_ack = None;
        s.remote_last_win_bytes = 0;
        send!(s, TcpRepr {
            control: TcpControl::Rst,
            seq_number: TcpSeqNumber(99),
            ack_number: None,
            payload: &b"a"[..],
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(TcpSeqNumber(100)),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Established);
        assert_eq!(s.tuple, Some(TUPLE));
        assert_eq!(s.rx_buffer.store.in_order_len(), 0);
    }

    fn socket_with_out_of_order_data(sack: bool, seq: TcpSeqNumber, high_offset: usize) -> TestSocket {
        let mut s = socket_syn_sent();
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: seq - 1,
            ack_number: Some(LOCAL_SEQ + 1),
            sack_permitted: sack,
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(seq),
            ..RECV_TEMPL
        }]);
        assert_eq!(s.remote_has_sack, sack);
        for offset in [high_offset, 3] {
            let range = ((seq + offset).0 as u32, (seq + offset + 3).0 as u32);
            send!(s, TcpRepr {
                seq_number: seq + offset,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq),
                sack_ranges: match (sack, offset) {
                    (false, _) => [None; 3],
                    (true, 3) => [Some(range), Some(((seq + high_offset).0 as u32,
                                                     (seq + high_offset + 3).0 as u32)), None],
                    (true, _) => [Some(range), None, None],
                },
                ..RECV_TEMPL
            }));
        }
        assert_eq!(s.rx_buffer.store.out_of_order_ranges().collect::<Vec<_>>(), vec![(3, 6), (high_offset, high_offset + 3)]);
        s
    }

    #[test]
    fn test_established_rst_at_sack_end_outside_window_is_dropped() {
        for seq in [TcpSeqNumber(100), TcpSeqNumber(-8)] {
            let mut s = socket_with_out_of_order_data(true, seq, 9);
            s.remote_last_win_bytes = 11;
            let timer = s.timer;
            send!(s, TcpRepr {
                control: TcpControl::Rst,
                seq_number: seq + 12,
                ack_number: None,
                ..SEND_TEMPL
            });
            assert_eq!(s.state, State::Established);
            assert_eq!(s.tuple, Some(TUPLE));
            assert_eq!(s.timer, timer);
            assert_eq!(s.challenge_ack_timer, Instant::from_millis(0));
        }
    }

    #[test]
    fn test_fin_wait_2_rst_at_retained_fin_end_outside_window_is_dropped() {
        let mut s = socket_fin_wait_2_with_out_of_order_fin(b"abc");
        s.remote_last_win_bytes = 6;
        let timer = s.timer;
        send!(s, TcpRepr {
            control: TcpControl::Rst,
            seq_number: TcpSeqNumber(107),
            ack_number: None,
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::FinWait2);
        assert_eq!(s.tuple, Some(TUPLE));
        assert_eq!(s.timer, timer);
        assert_eq!(s.challenge_ack_timer, Instant::from_millis(0));
    }

    #[test]
    fn test_established_rst_at_highest_sack_end() {
        for seq in [REMOTE_SEQ + 1, TcpSeqNumber(-8)] {
            for high_offset in [9, 61] {
                let mut s = socket_with_out_of_order_data(true, seq, high_offset);
                send!(s, TcpRepr {
                    control: TcpControl::Rst,
                    seq_number: seq + high_offset + 3,
                    ack_number: None,
                    ..SEND_TEMPL
                });
                assert_eq!(s.state, State::Closed);
                assert_eq!(s.tuple, None);
            }
        }
    }

    fn socket_fin_wait_2_with_out_of_order_fin(payload: &[u8]) -> TestSocket {
        let mut s = socket_fin_wait_2();
        s.remote_seq_no = TcpSeqNumber(100);
        s.remote_last_ack = Some(TcpSeqNumber(100));
        s.remote_has_sack = true;
        let reply = Some(TcpRepr {
            seq_number: LOCAL_SEQ + 2,
            ack_number: Some(TcpSeqNumber(100)),
            sack_ranges: [Some((103, (TcpSeqNumber(103) + payload.len() + 1).0 as u32)), None, None],
            ..RECV_TEMPL
        });
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: TcpSeqNumber(103),
            ack_number: Some(LOCAL_SEQ + 2),
            payload,
            ..SEND_TEMPL
        }, reply);
        assert_eq!(s.state, State::FinWait2);
        s
    }

    #[test]
    fn test_fin_wait_2_rst_at_out_of_order_fin_end() {
        let mut s = socket_fin_wait_2_with_out_of_order_fin(b"abc");
        send!(s, TcpRepr {
            control: TcpControl::Rst,
            seq_number: TcpSeqNumber(107),
            ack_number: None,
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Closed);
        assert_eq!(s.tuple, None);
    }

    #[test]
    fn test_fin_wait_2_rst_at_out_of_order_data_end_challenge_ack() {
        let mut s = socket_fin_wait_2_with_out_of_order_fin(b"abc");
        let timer = s.timer;
        send!(s, TcpRepr {
            control: TcpControl::Rst,
            seq_number: TcpSeqNumber(106),
            ack_number: None,
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 2,
            ack_number: Some(TcpSeqNumber(100)),
            sack_ranges: [Some((103, 107)), None, None],
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::FinWait2);
        assert_eq!(s.tuple, Some(TUPLE));
        assert_eq!(s.timer, timer);
    }

    #[test]
    fn test_fin_wait_2_rst_at_bare_out_of_order_fin_end() {
        let mut s = socket_fin_wait_2_with_out_of_order_fin(b"");
        send!(s, TcpRepr {
            control: TcpControl::Rst,
            seq_number: TcpSeqNumber(104),
            ack_number: None,
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Closed);
        assert_eq!(s.tuple, None);
    }

    #[test]
    fn test_close_wait_rst_after_fin_purges_out_of_order_data() {
        for rst_seq in [TcpSeqNumber(106), TcpSeqNumber(107)] {
            let mut s = socket_established();
            s.remote_seq_no = TcpSeqNumber(100);
            s.remote_last_ack = Some(TcpSeqNumber(100));
            s.remote_has_sack = true;
            send!(s, TcpRepr {
                seq_number: TcpSeqNumber(103),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"abc",
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(TcpSeqNumber(100)),
                sack_ranges: [Some((103, 106)), None, None],
                ..RECV_TEMPL
            }));
            send!(s, TcpRepr {
                control: TcpControl::Fin,
                seq_number: TcpSeqNumber(100),
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            });
            assert_eq!(s.rx_buffer.store.out_of_order_span(), 0);
            recv!(s, [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(TcpSeqNumber(101)),
                ..RECV_TEMPL
            }]);
            send!(s, TcpRepr {
                control: TcpControl::Rst,
                seq_number: rst_seq,
                ack_number: None,
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(TcpSeqNumber(101)),
                ..RECV_TEMPL
            }));
            assert_eq!(s.state, State::CloseWait);
            assert_eq!(s.tuple, Some(TUPLE));
        }
    }

    #[test]
    fn test_established_rst_at_highest_range_end_without_sack() {
        for seq in [REMOTE_SEQ + 1, TcpSeqNumber(-8)] {
            let mut s = socket_with_out_of_order_data(false, seq, 9);
            send!(s, TcpRepr {
                control: TcpControl::Rst,
                seq_number: seq + 12,
                ack_number: None,
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq),
                ..RECV_TEMPL
            }));
            assert_eq!(s.state, State::Established);
            assert_eq!(s.tuple, Some(TUPLE));
        }
    }

    #[test]
    fn test_established_rst_at_other_sack_seq_challenge_ack() {
        for offset in [6, 11, 13] {
            let seq = REMOTE_SEQ + 1;
            let mut s = socket_with_out_of_order_data(true, seq, 9);
            send!(s, TcpRepr {
                control: TcpControl::Rst,
                seq_number: seq + offset,
                ack_number: Some(LOCAL_SEQ + 1000),
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(seq),
                sack_ranges: [
                    Some(((seq + 3).0 as u32, (seq + 6).0 as u32)),
                    Some(((seq + 9).0 as u32, (seq + 12).0 as u32)),
                    None,
                ],
                ..RECV_TEMPL
            }));
            assert_eq!(s.state, State::Established);
            assert_eq!(s.tuple, Some(TUPLE));
        }
    }

    #[test]
    fn test_established_rst_challenge_ack_rate_limit() {
        let mut s = socket_established();
        let rst = TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 2,
            ack_number: None,
            ..SEND_TEMPL
        };
        let ack = TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        };
        send!(s, time 0, rst, Some(ack.clone()));
        send!(s, time 499, rst);
        assert_eq!(s.state, State::Established);
        recv_nothing!(s, time 499);
        send!(s, time 500, rst, Some(ack));
        assert_eq!(s.state, State::Established);
    }

    #[test]
    fn test_established_rst_exact_seq_wrap() {
        for seq in [TcpSeqNumber(-2), TcpSeqNumber(-1), TcpSeqNumber(0)] {
            let mut s = socket_established();
            s.remote_seq_no = seq - 3;
            s.remote_last_ack = Some(seq - 3);
            send!(s, TcpRepr {
                seq_number: seq - 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            });
            assert_eq!(s.remote_seq_no + s.rx_buffer.store.in_order_len(), seq);
            send!(s, TcpRepr {
                control: TcpControl::Rst,
                seq_number: seq,
                ack_number: None,
                ..SEND_TEMPL
            });
            assert_eq!(s.state, State::Closed);
            assert_eq!(s.tuple, None);
        }
    }

    #[test]
    fn test_established_rst_zero_receive_window() {
        for offset in [1, 0] {
            let (mut s, _frames) = socket_with_held_rx_frames(3, REMOTE_SEQ + 1, 5);
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            });
            recv!(s, [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 4),
                window_len: 0,
                ..RECV_TEMPL
            }]);
            assert_eq!(s.recv_room(), 0);
            send!(s, TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 4 + offset,
                ack_number: None,
                ..SEND_TEMPL
            });
            assert_eq!(s.state, if offset == 0 { State::Closed } else { State::Established });
            recv_nothing!(s);
        }
    }

    #[test]
    fn test_close_wait_rst_at_peer_fin() {
        let mut s = socket_close_wait();
        let seq = s.remote_seq_no - 1;
        send!(s, TcpRepr {
            control: TcpControl::Rst,
            seq_number: seq,
            ack_number: None,
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Closed);
        assert_eq!(s.tuple, None);
    }

    #[test]
    fn test_last_ack_rst_at_peer_fin() {
        let mut s = socket_last_ack();
        let seq = s.remote_seq_no - 1;
        send!(s, TcpRepr {
            control: TcpControl::Rst,
            seq_number: seq,
            ack_number: Some(LOCAL_SEQ + 1000),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Closed);
        assert_eq!(s.tuple, None);
    }

    #[test]
    fn test_closing_rst_at_peer_fin() {
        let mut s = socket_closing();
        let seq = s.remote_seq_no - 1;
        send!(s, TcpRepr {
            control: TcpControl::Rst,
            seq_number: seq,
            ack_number: None,
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Closed);
        assert_eq!(s.tuple, None);
    }

    #[test]
    fn test_rst_before_rcv_nxt_without_peer_fin() {
        for mut s in [socket_established(), socket_fin_wait_1(), socket_fin_wait_2()] {
            let state = s.state;
            let timer = s.timer;
            let seq = s.remote_seq_no + s.rx_buffer.store.in_order_len();
            send!(s, TcpRepr {
                control: TcpControl::Rst,
                seq_number: seq - 1,
                ack_number: None,
                ..SEND_TEMPL
            });
            assert_eq!(s.state, state);
            assert_eq!(s.timer, timer);
            assert_eq!(s.tuple, Some(TUPLE));
        }
    }

    #[test]
    fn test_time_wait_rst_exact_seq() {
        for from_closing in [false, true] {
            let mut s = socket_time_wait(from_closing);
            let seq = s.remote_seq_no + s.rx_buffer.store.in_order_len();
            send!(s, TcpRepr {
                control: TcpControl::Rst,
                seq_number: seq,
                ack_number: None,
                ..SEND_TEMPL
            });
            assert_eq!(s.state, State::Closed);
            assert_eq!(s.tuple, None);
            // Our close came first: a TIME-WAIT RST is not a peer reset.
            assert!(!s.reset_by_peer());
        }
    }

    #[test]
    fn test_time_wait_rst_other_seq_ignored() {
        for offset in [1, 63, 64] {
            for from_closing in [false, true] {
                let mut s = socket_time_wait(from_closing);
                if !from_closing {
                    recv!(s, [TcpRepr {
                        seq_number: LOCAL_SEQ + 1 + 1,
                        ack_number: Some(REMOTE_SEQ + 1 + 1),
                        ..RECV_TEMPL
                    }]);
                }
                let timer = s.timer;
                let seq = s.remote_seq_no + s.rx_buffer.store.in_order_len();
                send!(s, time 500, TcpRepr {
                    control: TcpControl::Rst,
                    seq_number: seq + offset,
                    ack_number: Some(LOCAL_SEQ + 1000),
                    ..SEND_TEMPL
                });
                assert_eq!(s.state, State::TimeWait);
                assert_eq!(s.timer, timer);
                assert_eq!(s.challenge_ack_timer, Instant::from_secs(0));
                recv_nothing!(s, time 500);
            }
        }
    }

    #[test]
    fn test_established_rst_no_ack() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        sanity!(s, socket_fin_wait_1());
    }

    #[test]
    fn test_established_abort() {
        let mut s = socket_established();
        s.abort();
        assert_eq!(s.state, State::Closed);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_abort_after_rto_rst_carries_highest_seq_sent() {
        let mut s = socket_established_rto_resent_first_of_two();
        s.abort();
        // The peer holds all 12 bytes: an RST below RCV.NXT would be dropped.
        recv!(s, time 310, [TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 12,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_syn_sent_abort_rst_follows_syn() {
        let mut s = socket_syn_sent();
        recv!(s, [TcpRepr {
            control:        TcpControl::Syn,
            seq_number:     LOCAL_SEQ,
            ack_number:     None,
            max_seg_size:   Some(BASE_MSS),
            window_scale:   Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }]);
        s.abort();
        // The send window is still unknown (0); the RST goes right after the SYN.
        recv(&mut s, Instant::from_millis(0), |repr| {
            let repr = repr.unwrap();
            assert_eq!((repr.control, repr.seq_number), (TcpControl::Rst, LOCAL_SEQ + 1));
        });
    }

    #[test]
    fn test_established_rst_bad_seq() {
        let mut s = socket_established();
        // Out-of-window RSTs are dropped silently, per RFC 9293 (3.10.7.4)
        // and RFC 5961 (3.2).
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ, // Wrong seq
                ack_number: None,
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.state, State::Established);

        // An RST at RCV.NXT resets the connection.
        send!(
            s,
            time 2000,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1, // Correct seq
                ack_number: None,
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_bad_seq_challenge_ack_updated() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ, // Wrong seq
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );

        assert_eq!(s.state, State::Established);

        // Send something to advance seq by 1
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1, // correct seq
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // Send the wrong seq again, check that the challenge ack is correctly updated
        // The ack number must be updated even if we don't call dispatch on the socket
        // See https://github.com/smoltcp-rs/smoltcp/issues/338
        send!(
            s,
            time 2000,
            TcpRepr {
                seq_number: REMOTE_SEQ, // Wrong seq
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2), // this has changed
                window_len: 64,
                ..RECV_TEMPL
            })
        );
    }

    // =========================================================================================//
    // Tests for the FIN-WAIT-1 state.
    // =========================================================================================//

    #[test]
    fn test_fin_wait_1_fin_ack() {
        let mut s = socket_fin_wait_1();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        sanity!(s, socket_fin_wait_2());
    }

    #[test]
    fn test_fin_wait_1_fin_fin() {
        let mut s = socket_fin_wait_1();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);
        sanity!(s, socket_closing());
    }

    #[test]
    fn test_fin_wait_1_fin_with_data_queued() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef123456").unwrap();
        s.close();
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait1);
    }

    #[test]
    fn test_fin_wait_1_recv() {
        let mut s = socket_fin_wait_1();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait1);
        {
            let frame = s.recv().unwrap().unwrap();
            let data = frame.payload();
            assert_eq!(data, b"abc");
        }
    }

    #[test]
    fn test_fin_wait_1_close() {
        let mut s = socket_fin_wait_1();
        s.close();
        assert_eq!(s.state, State::FinWait1);
    }

    // =========================================================================================//
    // Tests for the FIN-WAIT-2 state.
    // =========================================================================================//

    #[test]
    fn test_fin_wait_2_fin() {
        let mut s = socket_fin_wait_2();
        send!(s, time 1_000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::TimeWait);
        sanity!(s, socket_time_wait(false));
    }

    #[test]
    fn test_fin_wait_2_recv() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        {
            let frame = s.recv().unwrap().unwrap();
            let data = frame.payload();
            assert_eq!(data, b"abc");
        }
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_fin_wait_2_close() {
        let mut s = socket_fin_wait_2();
        s.close();
        assert_eq!(s.state, State::FinWait2);
    }

    // =========================================================================================//
    // Tests for the CLOSING state.
    // =========================================================================================//

    #[test]
    fn test_closing_ack_fin() {
        let mut s = socket_closing();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(s, time 1_000, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::TimeWait);
        sanity!(s, socket_time_wait(true));
    }

    #[test]
    fn test_closing_close() {
        let mut s = socket_closing();
        s.close();
        assert_eq!(s.state, State::Closing);
    }

    // =========================================================================================//
    // Tests for the TIME-WAIT state.
    // =========================================================================================//

    #[test]
    fn test_time_wait_from_fin_wait_2_ack() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_time_wait_from_closing_no_ack() {
        let mut s = socket_time_wait(true);
        recv!(s, []);
    }

    #[test]
    fn test_time_wait_close() {
        let mut s = socket_time_wait(false);
        s.close();
        assert_eq!(s.state, State::TimeWait);
    }

    #[test]
    fn test_time_wait_retransmit() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(s, time 5_000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(
            s.timer,
            Timer::Close {
                expires_at: Instant::from_secs(5) + CLOSE_DELAY
            }
        );
    }

    #[test]
    fn owned_time_wait_expiry_keeps_received_frames_and_eof() {
        for reopen in [None, Some(false), Some(true)] {
            let mut s = socket_established();
            s.close();
            assert_eq!(s.state(), State::FinWait1);
            recv!(s, time 1000, [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]);
            send!(s, time 1000, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                payload: b"abc",
                ..SEND_TEMPL
            });
            send!(s, time 1000, TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 4,
                ack_number: Some(LOCAL_SEQ + 2),
                payload: b"def",
                ..SEND_TEMPL
            });
            assert_eq!(s.state(), State::TimeWait);
            recv!(s, time 1000, [TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 8),
                ..RECV_TEMPL
            }]);
            recv_nothing!(s, time 11_001);
            assert_eq!(s.state(), State::Closed);
            assert_eq!(s.tuple, None);
            assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Ingress);
            assert_eq!(s.recv_queue(), 6);
            match reopen {
                None => {
                    for bytes in [b"abc", b"def"] {
                        let frame = s.recv().unwrap().unwrap();
                        assert_eq!(frame.payload(), bytes);
                    }
                    assert!(matches!(s.recv(), Err(RecvError::Finished)));
                }
                Some(listen) => {
                    if listen {
                        s.listen(LOCAL_PORT).unwrap();
                    } else {
                        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
                    }
                    assert_eq!(s.recv_queue(), 0);
                    assert!(!s.rx_fin_received);
                }
            }
        }
    }

    #[test]
    fn test_time_wait_timeout() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::TimeWait);
        recv_nothing!(s, time 60_000);
        assert_eq!(s.state, State::Closed);
    }

    fn peer_rst(s: &mut TestSocket) {
        assert_eq!(send(s, Instant::from_millis(0), &TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }), None);
    }

    #[test]
    fn reset_by_peer_after_established_rst() {
        let mut s = socket_established();
        assert!(!s.reset_by_peer());
        peer_rst(&mut s);
        assert_eq!(s.state, State::Closed);
        assert!(s.reset_by_peer());
    }

    #[test]
    fn reset_by_peer_false_after_last_ack_completes() {
        let mut s = socket_last_ack();
        recv!(s, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Closed);
        assert!(!s.reset_by_peer());
    }

    #[test]
    fn reset_by_peer_false_after_time_wait_expiry() {
        let mut s = socket_time_wait(false);
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]);
        recv_nothing!(s, time 60_000);
        assert_eq!(s.state, State::Closed);
        assert!(!s.reset_by_peer());
    }

    #[test]
    fn reset_by_peer_false_after_local_abort() {
        let mut s = socket_established();
        s.abort();
        assert_eq!(s.state, State::Closed);
        assert!(!s.reset_by_peer());
    }

    #[test]
    fn reset_by_peer_cleared_by_connect_and_listen() {
        let mut s = socket_established();
        peer_rst(&mut s);
        assert!(s.reset_by_peer());
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        assert!(!s.reset_by_peer());

        let mut s = socket_established();
        peer_rst(&mut s);
        assert!(s.reset_by_peer());
        s.listen(LISTEN_END).unwrap();
        assert!(!s.reset_by_peer());
    }

    // =========================================================================================//
    // Tests for the CLOSE-WAIT state.
    // =========================================================================================//

    #[test]
    fn test_close_wait_ack() {
        let mut s = socket_close_wait();
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_close_wait_close() {
        let mut s = socket_close_wait();
        s.close();
        assert_eq!(s.state, State::LastAck);
        sanity!(s, socket_last_ack());
    }

    // =========================================================================================//
    // Tests for the LAST-ACK state.
    // =========================================================================================//
    #[test]
    fn test_last_ack_fin_ack() {
        let mut s = socket_last_ack();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::LastAck);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_last_ack_ack_not_of_fin() {
        let mut s = socket_last_ack();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::LastAck);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::LastAck);

        // ACK received of fin: socket should change to Closed.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_last_ack_duplicate_ack_no_challenge_ack() {
        let mut s = socket_last_ack();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::LastAck);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::LastAck);
        recv_nothing!(s);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_last_ack_fast_retransmit_after_triple_duplicate_ack() {
        let mut s = socket_established();
        s.remote_mss = 3;
        s.socket.update_rx_mbuf_budget(&s.cx);
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::CloseWait);
        s.send_slice(b"aaaBBBcccDDD").unwrap();
        s.close();
        assert_eq!(s.state, State::LastAck);

        for (offset, payload) in [(0, b"aaa"), (3, b"BBB"), (6, b"ccc"), (9, b"DDD")] {
            recv!(s, time 0, Ok(TcpRepr {
                control: if offset == 9 { TcpControl::Fin } else { TcpControl::None },
                seq_number: LOCAL_SEQ + 1 + offset,
                ack_number: Some(REMOTE_SEQ + 2),
                payload: &payload[..],
                window_len: 63,
                ..RECV_TEMPL
            }));
        }
        assert_eq!(s.timer, Timer::Retransmit {
            expires_at: Instant::from_millis(300),
        });
        recv_nothing!(s, time 9);

        for at in [10, 15, 20] {
            send!(s, time at, TcpRepr {
                seq_number: REMOTE_SEQ + 2,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            });
        }
        assert_eq!(s.local_rx_dup_acks, 3);
        recv!(s, time 20, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 2),
            payload: b"aaa",
            window_len: 63,
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::LastAck);
    }

    #[test]
    fn test_last_ack_window_reopen_sends_data_immediately() {
        let mut s = socket_established();
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::CloseWait);
        s.send_slice(b"abc").unwrap();
        s.close();
        assert_eq!(s.state, State::LastAck);
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 2),
            ..RECV_TEMPL
        }));
        assert_eq!(s.remote_win_len, 0);
        assert_eq!(s.remote_max_seq, LOCAL_SEQ + 1);
        recv_nothing!(s, time 299);
        recv!(s, time 300, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 2),
            payload: b"a",
            ..RECV_TEMPL
        }));
        assert_eq!(s.rto_backoff, 1);
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(900)));

        send!(s, time 310, TcpRepr {
            seq_number: REMOTE_SEQ + 2,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 3,
            ..SEND_TEMPL
        });
        assert_eq!(s.remote_win_len, 3);
        assert_eq!(s.rto_backoff, 0);
        recv!(s, time 310, Ok(TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 2),
            payload: b"abc",
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::LastAck);
    }

    // A partial ACK in LAST-ACK (ack_len > 0 but not FIN ACK) advances SND.UNA
    // without a challenge ACK; the FIN will be retransmitted by the timer.
    #[test]
    fn test_last_ack_partial_ack_no_challenge_ack() {
        // Build a LAST-ACK socket that has one byte of data still unacknowledged
        // before the FIN.  We manually wire the state so we can send a partial ACK.
        let mut s = socket_last_ack();
        // Push one byte into the tx buffer to simulate data that preceded the FIN.
        let _ = s.tx_buffer.enqueue_slice(b"x");
        // Mark it as already sent (remote_last_seq is past the data byte and the FIN).
        s.remote_last_seq = LOCAL_SEQ + 1 + 1 + 1; // data(1) + FIN(1)
        s.remote_max_seq = LOCAL_SEQ + 1 + 1 + 1;

        // Remote ACKs just the data byte, not the FIN (partial ACK).
        // ack_number = local_seq_no + 1  =>  ack_len = 1, ack_of_fin = false.
        // Per RFC 9293, a valid partial ACK should advance SND.UNA normally;
        // no challenge ACK should be emitted.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1), // acks the data byte, not FIN
                ..SEND_TEMPL
            }
        );
        // State remains LAST-ACK; FIN retransmission is handled by the timer.
        assert_eq!(s.state, State::LastAck);
        // SND.UNA has advanced to the partial ACK number.
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1 + 1);
    }

    #[test]
    fn test_last_ack_close() {
        let mut s = socket_last_ack();
        s.close();
        assert_eq!(s.state, State::LastAck);
    }

    // =========================================================================================//
    // Tests for transitioning through multiple states.
    // =========================================================================================//

    #[test]
    fn test_listen() {
        let mut s = socket();
        s.listen(LISTEN_END).unwrap();
        assert_eq!(s.state, State::Listen);
    }

    #[test]
    fn test_three_way_handshake() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_remote_close() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        s.close();
        assert_eq!(s.state, State::LastAck);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_local_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_simultaneous_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                // due to reordering, this is logically located...
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        // ... at this point
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_simultaneous_close_combined_fin_ack() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_simultaneous_close_raced() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);

        // Socket receives FIN before it has a chance to send its own FIN
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);

        // FIN + ack-of-FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::Closing);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_simultaneous_close_raced_with_data() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state, State::FinWait1);

        // Socket receives FIN before it has a chance to send its own data+FIN
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);

        // data + FIN + ack-of-FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::Closing);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_fin_with_data() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        )
    }

    #[test]
    fn test_mutual_close_with_data_1() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_mutual_close_with_data_2() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::TimeWait);
    }

    // =========================================================================================//
    // Tests for retransmission on packet loss.
    // =========================================================================================//

    #[test]
    fn test_duplicate_seq_ack() {
        let mut s = socket_recved();
        // remote retransmission
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 64,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_data_retransmit() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 1050);
        recv!(s, time 1300, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_congestion_window_limits_data_in_flight() {
        let mut s = socket_established_with_buffer_sizes(8192, 64);
        s.remote_win_len = 65535;
        s.remote_mss = 1024;
        s.socket.update_rx_mbuf_budget(&s.cx);

        let data = [b'x'; 8192];
        s.send_slice(&data[..]).unwrap();

        // This fixture uses the pre-handshake Cubic window of 2048 bytes: only two
        // 1024-byte segments may be in flight, the rest must wait for ACKs.
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1024,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);

        // ACKing one segment frees congestion window space and grows
        // cwnd (slow start), allowing further segments out.
        send!(s, time 10, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1024),
            window_len: 65535,
            ..SEND_TEMPL
        });
        recv!(s, time 10, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 2048,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_congestion_window_doesnt_limit_fast_retransmit() {
        let mut s = socket_established_with_buffer_sizes(8192, 64);
        s.remote_win_len = 65535;
        s.remote_mss = 1024;
        s.socket.update_rx_mbuf_budget(&s.cx);

        // Normal ACK of previously received segment
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 65535,
            ..SEND_TEMPL
        });

        let data = [b'x'; 8192];
        s.send_slice(&data[..]).unwrap();

        // The pre-handshake Cubic window is 2048 bytes, allowing 2 segments
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));

        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1024,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);

        // Send three duplicate ACKS, treating the first segment as lost
        send!(s, time 10, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 65535,
            ..SEND_TEMPL
        });
        send!(s, time 10, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 65535,
            ..SEND_TEMPL
        });
        send!(s, time 10, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 65535,
            ..SEND_TEMPL
        });

        // A fast retrnasmit should be sent and not be blocked by congestion control
        recv!(s, time 20, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_data_retransmit_bursts() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.socket.update_rx_mbuf_budget(&s.cx);
        s.send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        recv_nothing!(s, time 0);

        recv_nothing!(s, time 50);

        recv!(s, time 300, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 450, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        recv_nothing!(s, time 500);
    }

    #[test]
    fn test_data_retransmit_bursts_half_ack() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.socket.update_rx_mbuf_budget(&s.cx);
        s.send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        // Acknowledge the first packet
        send!(s, time 5, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        // The second packet should be re-sent.
        recv!(s, time 305, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);

        recv_nothing!(s, time 355);
    }

    #[test]
    fn test_retransmit_timer_restart_on_partial_ack() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.socket.update_rx_mbuf_budget(&s.cx);
        s.send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        // Acknowledge the first packet
        send!(s, time 600, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        // The ACK of the first packet should restart the retransmit timer and delay a retransmission.
        recv_nothing!(s, time 899);
        // The second packet should be re-sent.
        recv!(s, time 900, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
    }

    #[test]
    fn ack_at_replay_cursor_below_highest_sent_keeps_recovering() {
        let mut s = socket_established_rto_resent_first_of_two();
        let mut receiver = socket_established();
        receiver.remote_seq_no = LOCAL_SEQ + 1;
        receiver.remote_last_ack = Some(LOCAL_SEQ + 1);
        send!(receiver, time 1000, TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: b"abcdef",
            ..SEND_TEMPL
        });
        assert_eq!(s.remote_last_seq, LOCAL_SEQ + 7);
        assert_eq!(s.remote_max_seq, LOCAL_SEQ + 13);
        recv(&mut receiver, Instant::from_millis(1010), |reply| {
            let ack = reply.unwrap().ack_number.unwrap();
            assert_eq!(ack, LOCAL_SEQ + 7);
            send!(s, time 1010, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(ack),
                ..SEND_TEMPL
            });
        });
        assert_eq!(s.send_queue(), 6);
        recv(&mut s, Instant::from_millis(1010), |reply| {
            let data = reply.unwrap();
            assert_eq!(data.seq_number, LOCAL_SEQ + 7);
            assert_eq!(data.payload, b"012345");
            send!(receiver, time 1010, TcpRepr {
                seq_number: data.seq_number,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: data.payload,
                ..SEND_TEMPL
            });
        });
        recv(&mut receiver, Instant::from_millis(1020), |reply| {
            let ack = reply.unwrap().ack_number.unwrap();
            assert_eq!(ack, LOCAL_SEQ + 13);
            send!(s, time 1020, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(ack),
                ..SEND_TEMPL
            });
        });
        assert_eq!(s.send_queue(), 0);
        recv_nothing!(s, time 4000);
        let bytes = drain_bytes(&mut receiver);
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[..12], b"abcdef012345");
        assert!(receiver.recv().unwrap().is_none());
    }

    #[test]
    fn failed_emit_preserves_retransmit_work() {
        let mut s = socket_fast_retransmit_emit_failed();
        assert!(s.pending_fast_retransmit);
        assert_eq!(s.remote_last_seq, LOCAL_SEQ + 13);
        assert_eq!(s.remote_max_seq, LOCAL_SEQ + 13);
        assert_eq!(s.rtte.timestamp(), None);
        assert_eq!(s.rtte.max_seq_sent(), Some(LOCAL_SEQ + 13));
        let result = s.socket.dispatch(&mut s.cx, |_, _, (_, repr)| {
            assert_eq!(repr.seq_number, LOCAL_SEQ + 1);
            assert_eq!(repr.payload, b"aaa");
            Err(())
        });
        assert_eq!(result, Err(()));
        assert!(s.pending_fast_retransmit);
        assert_eq!(s.remote_last_seq, LOCAL_SEQ + 13);
        assert_eq!(s.remote_max_seq, LOCAL_SEQ + 13);
        assert_eq!(s.rtte.timestamp(), None);
        assert_eq!(s.rtte.max_seq_sent(), Some(LOCAL_SEQ + 13));
        recv!(s, time 20, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"aaa",
            ..RECV_TEMPL
        }));
        assert!(!s.pending_fast_retransmit);
        assert_eq!(s.remote_last_seq, LOCAL_SEQ + 13);
        assert_eq!(s.rtte.timestamp(), None);
    }

    #[test]
    fn receiver_sack_offer_and_block_survive() {
        let mut active = socket_syn_sent();
        recv(&mut active, Instant::ZERO, |reply| {
            let syn = reply.unwrap();
            assert_eq!(syn.control, TcpControl::Syn);
            assert_eq!(syn.ack_number, None);
            assert!(syn.sack_permitted);
        });
        let mut s = socket_listen();
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            sack_permitted: true,
            ..SEND_TEMPL
        });
        recv(&mut s, Instant::ZERO, |reply| {
            let syn_ack = reply.unwrap();
            assert_eq!(syn_ack.control, TcpControl::Syn);
            assert_eq!(syn_ack.ack_number, Some(REMOTE_SEQ + 1));
            assert!(syn_ack.sack_permitted);
        });
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::Established);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 4,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: b"def",
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            sack_ranges: [Some(((REMOTE_SEQ + 4).0 as u32, (REMOTE_SEQ + 7).0 as u32)), None, None],
            ..RECV_TEMPL
        }));
        assert_eq!(s.recv_queue(), 0);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: b"abc",
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 7),
            window_len: 64,
            ..RECV_TEMPL
        }));
        let bytes = drain_bytes(&mut s);
        assert_eq!(bytes.len(), 6);
        assert_eq!(&bytes[..6], b"abcdef");
        assert!(s.recv().unwrap().is_none());
    }

    #[test]
    fn test_data_retransmit_bursts_half_ack_close() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.socket.update_rx_mbuf_budget(&s.cx);
        s.send_slice(b"abcdef012345").unwrap();
        s.close();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        // Acknowledge the first packet
        send!(s, time 5, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        // The second packet should be re-sent.
        recv!(s, time 305, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);

        recv_nothing!(s, time 355);
    }

    /// Established with Cubic and a 6-byte MSS: "abcdef012345" goes out as two
    /// segments, then the retransmission timeout collapses cwnd to one MSS and
    /// resends "abcdef" alone. The peer holds all 12 bytes (its ACKs were lost).
    fn socket_established_rto_resent_first_of_two() -> TestSocket {
        let mut s = socket_established();
        s.congestion_controller.set_mss(6);
        s.remote_mss = 6;
        s.socket.update_rx_mbuf_budget(&s.cx);
        s.send_slice(b"abcdef012345").unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 300, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }]);
        s
    }

    #[test]
    fn test_pure_ack_after_rto_carries_highest_seq_sent() {
        let mut s = socket_established_rto_resent_first_of_two();
        // The peer's data, acknowledging nothing new: our ACK of it must be
        // at or above the peer's RCV.NXT (LOCAL_SEQ + 1 + 12), or the peer
        // drops it without reading its ACK.
        send!(s, time 310, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload:    &b"xyz"[..],
            ..SEND_TEMPL
        });
        recv!(s, time 310, [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 12,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            window_len: 61,
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_ack_reply_after_rto_carries_highest_seq_sent() {
        let mut s = socket_established_rto_resent_first_of_two();
        // Out-of-order data from the peer draws an immediate ACK reply.
        send!(s, time 310, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 3,
            ack_number: Some(LOCAL_SEQ + 1),
            payload:    &b"xyz"[..],
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 12,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_pure_ack_after_shrink_within_one_window_scale_unit_carries_highest_seq_sent() {
        let mut s = socket_established();
        s.remote_win_scale = Some(1);
        s.send_slice(b"abcde").unwrap();
        recv!(s, time 0, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcde"[..],
            ..RECV_TEMPL
        }]);
        // The peer's window, in 2-byte units, now ends one byte short of what
        // was sent: rounding of the scaled window, not a shrink.
        send!(s, time 10, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 2,
            payload:    &b"xyz"[..],
            ..SEND_TEMPL
        });
        recv!(s, time 10, [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 5,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            window_len: 64,
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_zero_window_probe_without_data_keeps_send_cursor_seq() {
        let mut s = socket_established();
        s.remote_mss = 3;
        s.socket.update_rx_mbuf_budget(&s.cx);
        s.send_slice(b"abcdef").unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 3,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"def"[..],
            ..RECV_TEMPL
        }));
        // The peer takes "abc" and closes its window; "def" stays in flight.
        send!(s, time 10, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 3),
            window_len: 0,
            ..SEND_TEMPL
        });
        // The probe has no unsent byte to carry. It goes out at the send cursor,
        // past the closed window, so the peer answers it with an ACK; at the
        // window's edge it would be acceptable and draw nothing.
        recv!(s, time 310, [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_pure_ack_after_refused_probe_byte_is_at_zero_window_edge() {
        let mut s = socket_established();
        s.remote_win_scale = Some(7);
        s.send_slice(b"abc").unwrap();
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        });
        recv!(s, time 300, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"a"[..],
            ..RECV_TEMPL
        }]);
        // The peer refuses the probe byte (its window stays 0) and sends data. Its
        // RCV.NXT is LOCAL_SEQ + 1 with a zero window: our ACK must be there, not at
        // the probe byte's end, which is within one window-scale unit of the edge.
        send!(s, time 310, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            payload:    &b"xyz"[..],
            ..SEND_TEMPL
        });
        recv!(s, time 310, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            window_len: 64,
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_zero_window_probe_byte_ack_accepted() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        });
        recv!(s, time 300, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"a"[..],
            ..RECV_TEMPL
        }]);
        // The peer takes the probe byte and its window is full again: the ACK
        // covers sent sequence space, so it is processed, not challenged.
        send!(s, time 310, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            window_len: 0,
            ..SEND_TEMPL
        });
        assert_eq!(s.send_queue(), 5);
        recv_nothing!(s, time 310);
    }

    #[test]
    fn test_ack_of_unsent_data_draws_challenge_ack() {
        let mut s = socket_established();
        s.remote_win_len = 1;
        s.send_slice(b"ab").unwrap();
        recv!(s, time 0, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"a"[..],
            ..RECV_TEMPL
        }]);
        // The ACK covers "b", which was never sent: challenge ACK, queue intact.
        send!(s, time 10, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 2),
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.send_queue(), 2);
    }

    #[test]
    fn test_send_data_after_syn_ack_retransmit() {
        let mut s = socket_syn_received();
        recv!(s, time 50, Ok(TcpRepr {
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }));
        recv!(s, time 350, Ok(TcpRepr { // retransmit
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        )
    }

    #[test]
    fn test_established_retransmit_for_dup_ack() {
        let mut s = socket_established();
        // Duplicate ACKs do not replace the retransmission timer
        s.send_slice(b"abc").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
        // Retransmit timer is on because all data was sent
        assert_eq!(s.tx_buffer.len(), 3);
        // ACK nothing new
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Retransmit
        recv!(s, time 1300, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_retransmit_reset_after_ack() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_queue_during_retransmission() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.socket.update_rx_mbuf_budget(&s.cx);
        s.send_slice(b"abcdef123456ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        })); // this one is dropped
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        })); // this one is received
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        })); // also dropped
        recv!(s, time 1300, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        })); // retransmission
        send!(s, time 1305, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            ..SEND_TEMPL
        }); // acknowledgement of both segments
        recv!(s, time 1310, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        })); // retransmission of only unacknowledged data
    }

    #[test]
    fn test_close_wait_retransmit_reset_after_ack() {
        let mut s = socket_close_wait();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_fin_wait_1_retransmit_reset_after_ack() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        s.close();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_fast_retransmit_after_triple_duplicate_ack() {
        let mut s = socket_established();
        s.remote_mss = 3;
        s.socket.update_rx_mbuf_budget(&s.cx);

        // Normal ACK of previously received segment
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // Send a long string of text divided into several packets
        // because of previously received "window_len"
        s.send_slice(b"aaaBBBcccDDDeeeFFF").unwrap();

        // This packet is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaa"[..],
            ..RECV_TEMPL
        }));

        // These packets arrive
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 3,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"BBB"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (3 * 2),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ccc"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1015, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (3 * 3),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"DDD"[..],
            ..RECV_TEMPL
        }));

        // Duplicate ACKs trigger fast rentramsit after 3rd successive one
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1055, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1060, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // Fast retransmit should have triggered
        recv!(s, time 1100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaa"[..],
            ..RECV_TEMPL
        }));

        // Transmission should continue as normal after re-transitting the first segment
        recv!(s, time 1105, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (3 * 4),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"eee"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1110, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (3 * 5),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"FFF"[..],
            ..RECV_TEMPL
        }));

        // ACK all received segments
        send!(s, time 1120, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (3 * 5)),
            ..SEND_TEMPL
        });
    }

    /// Established with a 3-byte MSS: "aaaBBBcccDDD" is in flight, "aaa" lost.
    /// Three duplicate ACKs start a fast retransmit, whose emit fails at time 20.
    fn socket_fast_retransmit_emit_failed() -> TestSocket {
        let mut s = socket_established();
        s.remote_mss = 3;
        s.socket.update_rx_mbuf_budget(&s.cx);
        s.send_slice(b"aaaBBBcccDDD").unwrap();
        for (offset, payload) in [(0, b"aaa"), (3, b"BBB"), (6, b"ccc"), (9, b"DDD")] {
            recv!(s, time 0, Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1 + offset,
                ack_number: Some(REMOTE_SEQ + 1),
                payload:    &payload[..],
                ..RECV_TEMPL
            }));
        }
        // The first ACK of LOCAL_SEQ + 1 is fresh, the next three are duplicates.
        for _ in 0..4 {
            send!(s, time 10, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            });
        }
        // The device takes no packet.
        s.cx.set_now(Instant::from_millis(20));
        let result: Result<(), ()> = s.socket.dispatch(&mut s.cx, |_, _, _| Err(()));
        assert_eq!(result, Err(()));
        s
    }

    fn partial_ack(s: &mut TestSocket, ack: TcpSeqNumber) {
        let now = s.cx.now().max(Instant::from_millis(30));
        assert_eq!(send(s, now, &TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(ack),
            ..SEND_TEMPL
        }), None);
    }

    #[test]
    fn partial_ack_retransmits_next_hole_immediately() {
        let mut s = socket_fast_retransmit_emit_failed();
        recv!(s, time 20, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"aaa",
            ..RECV_TEMPL
        }));
        partial_ack(&mut s, LOCAL_SEQ + 7);
        assert_eq!(s.send_queue(), 6);
        recv!(s, time 30, [TcpRepr {
            seq_number: LOCAL_SEQ + 7,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"ccc",
            ..RECV_TEMPL
        }]);
    }

    fn socket_data_and_standalone_fin_lost() -> TestSocket {
        let mut s = socket_established();
        s.remote_mss = 3;
        s.socket.update_rx_mbuf_budget(&s.cx);
        s.send_slice(b"aaaBBBcccDDD").unwrap();
        for offset in [0, 3, 6, 9] {
            recv!(s, time 0, Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1 + offset,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"aaaBBBcccDDD"[offset..offset + 3],
                ..RECV_TEMPL
            }));
        }
        s.close();
        recv!(s, time 0, Ok(TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 13,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        // The first data segment and FIN are lost; the other three elicit duplicate ACKs.
        for _ in 0..4 {
            send!(s, time 10, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            });
        }
        s
    }

    #[test]
    fn partial_ack_repairs_standalone_fin_immediately() {
        let mut s = socket_data_and_standalone_fin_lost();
        recv!(s, time 20, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"aaa",
            ..RECV_TEMPL
        }));
        partial_ack(&mut s, LOCAL_SEQ + 13);
        assert_eq!(s.send_queue(), 0);
        assert_eq!(s.recover(), Some(LOCAL_SEQ + 14));
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(330)));
        recv!(s, time 30, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 13,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]);
        assert_eq!((s.retransmits(), s.loss_events()), (2, 1));
        partial_ack(&mut s, LOCAL_SEQ + 14);
        assert_eq!(s.state(), State::FinWait2);
        assert_eq!(s.recover(), None);
        assert!(s.timer.is_idle());
    }

    #[test]
    fn partial_ack_after_failed_data_repair_arms_fin_timer() {
        let mut s = socket_data_and_standalone_fin_lost();
        s.cx.set_now(Instant::from_millis(20));
        assert_eq!(s.socket.dispatch(&mut s.cx, |_, _, (_, repr)| {
            assert_eq!(repr.seq_number, LOCAL_SEQ + 1);
            assert_eq!(repr.payload, b"aaa");
            Err(())
        }), Err(()));
        // The reordered original segment fills the hole, leaving only FIN unacknowledged.
        partial_ack(&mut s, LOCAL_SEQ + 13);
        assert_eq!(s.send_queue(), 0);
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(330)));
        for _ in 0..2 {
            assert_eq!(s.socket.dispatch(&mut s.cx, |_, _, (_, repr)| {
                assert_eq!(repr.control, TcpControl::Fin);
                assert_eq!(repr.seq_number, LOCAL_SEQ + 13);
                assert!(repr.payload.is_empty());
                Err(())
            }), Err(()));
            assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(330)));
            assert_eq!((s.retransmits(), s.loss_events()), (0, 1));
        }
        recv!(s, time 30, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 13,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]);
        assert_eq!((s.retransmits(), s.loss_events()), (1, 1));
    }

    #[test]
    fn pure_acks_during_zero_window_probe_do_not_count_as_retransmits() {
        let mut s = socket_zero_window(DEFAULT_RTO);
        recv!(s, time 300, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"a",
            ..RECV_TEMPL
        }));
        assert_eq!(s.retransmits(), 0);
        for offset in 0..3 {
            send!(s, time 310, TcpRepr {
                seq_number: REMOTE_SEQ + 1 + offset,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                payload: b"x",
                ..SEND_TEMPL
            });
            recv!(s, time 310, [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2 + offset),
                window_len: 64,
                ..RECV_TEMPL
            }]);
            assert_eq!(s.retransmits(), 0);
        }
        recv!(s, time 900, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 4),
            window_len: 64,
            payload: b"a",
            ..RECV_TEMPL
        }));
        assert_eq!(s.retransmits(), 1);
    }

    #[test]
    fn partial_ack_does_not_cut_cubic_again() {
        let mut s = socket_fast_retransmit_emit_failed();
        partial_ack(&mut s, LOCAL_SEQ + 7);
        let window = s.congestion_controller.window();
        for _ in 0..3 {
            partial_ack(&mut s, LOCAL_SEQ + 7);
        }
        assert_eq!(s.socket.dispatch(&mut s.cx, |_, _, _| Ok::<_, ()>(())), Ok(()));
        assert_eq!(s.congestion_controller.window(), window);
    }

    #[test]
    fn partial_ack_failed_emit_preserves_new_hole() {
        let mut s = socket_fast_retransmit_emit_failed();
        partial_ack(&mut s, LOCAL_SEQ + 7);
        for _ in 0..2 {
            assert_eq!(s.socket.dispatch(&mut s.cx, |_, _, (_, repr)| {
                assert_eq!(repr.seq_number, LOCAL_SEQ + 7);
                assert_eq!(repr.payload, b"ccc");
                Err(())
            }), Err(()));
        }
        recv!(s, time 30, [TcpRepr {
            seq_number: LOCAL_SEQ + 7,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"ccc",
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn recovery_boundary_wraps_with_tcp_sequence_numbers() {
        let mut s = socket_established();
        let una = TcpSeqNumber(-7);
        s.local_seq_no = una;
        s.remote_last_seq = una;
        s.remote_max_seq = una;
        s.remote_mss = 3;
        s.socket.update_rx_mbuf_budget(&s.cx);
        s.send_slice(b"aaaBBBcccDDD").unwrap();
        for offset in [0, 3, 6, 9] {
            recv!(s, Ok(TcpRepr {
                seq_number: una + offset,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"aaaBBBcccDDD"[offset..offset + 3],
                ..RECV_TEMPL
            }));
        }
        for _ in 0..4 {
            partial_ack(&mut s, una);
        }
        recv!(s, time 30, Ok(TcpRepr {
            seq_number: una,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"aaa",
            ..RECV_TEMPL
        }));
        partial_ack(&mut s, una + 6);
        recv!(s, time 30, [TcpRepr {
            seq_number: una + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"ccc",
            ..RECV_TEMPL
        }]);
        partial_ack(&mut s, una + 12);
        recv_nothing!(s, time 30);
        assert_eq!(s.send_queue(), 0);
    }

    #[test]
    fn ack_reaching_recover_allows_next_loss_episode() {
        let mut s = socket_fast_retransmit_emit_failed();
        partial_ack(&mut s, LOCAL_SEQ + 13);
        assert_eq!(s.recover(), None);
        assert_eq!(s.loss_events(), 1);
        s.send_slice(b"eeeFFFgggHHH").unwrap();
        for offset in [0, 3, 6, 9] {
            recv!(s, time 30, Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 13 + offset,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"eeeFFFgggHHH"[offset..offset + 3],
                ..RECV_TEMPL
            }));
        }
        for _ in 0..3 {
            partial_ack(&mut s, LOCAL_SEQ + 13);
        }
        recv!(s, time 30, [TcpRepr {
            seq_number: LOCAL_SEQ + 13,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"eee",
            ..RECV_TEMPL
        }]);
        assert_eq!(s.recover(), Some(LOCAL_SEQ + 25));
        assert_eq!(s.loss_events(), 2);
    }

    #[test]
    fn rto_clears_recover() {
        let mut s = socket_fast_retransmit_emit_failed();
        assert_eq!(s.recover(), Some(LOCAL_SEQ + 13));
        recv!(s, time 20, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"aaa",
            ..RECV_TEMPL
        }));
        assert_eq!(s.socket.dispatch(&mut s.cx, |_, _, _| Err::<(), _>(())), Ok(()));
        s.cx.set_now(Instant::from_millis(320));
        assert_eq!(s.socket.dispatch(&mut s.cx, |_, _, _| Err::<(), _>(())), Err(()));
        assert_eq!(s.recover(), None);
        assert!(!s.pending_fast_retransmit);
        partial_ack(&mut s, LOCAL_SEQ + 7);
        assert!(!s.pending_fast_retransmit);
    }

    #[test]
    fn failed_emit_does_not_increment_retransmits() {
        let mut s = socket_fast_retransmit_emit_failed();
        assert_eq!(s.retransmits(), 0);
        assert_eq!(s.loss_events(), 1);
        for _ in 0..2 {
            assert_eq!(s.socket.dispatch(&mut s.cx, |_, _, _| Err::<(), _>(())), Err(()));
            assert_eq!(s.retransmits(), 0);
            assert_eq!(s.loss_events(), 1);
        }
        recv!(s, time 20, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"aaa",
            ..RECV_TEMPL
        }));
        assert_eq!(s.retransmits(), 1);
    }

    #[test]
    fn partial_ack_repairs_share_one_loss_event() {
        let mut s = socket_fast_retransmit_emit_failed();
        for (offset, payload) in [(0, b"aaa"), (6, b"ccc")] {
            if offset != 0 {
                partial_ack(&mut s, LOCAL_SEQ + 1 + offset);
            }
            recv!(s, time 30, Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1 + offset,
                ack_number: Some(REMOTE_SEQ + 1),
                payload,
                ..RECV_TEMPL
            }));
            assert_eq!(s.loss_events(), 1);
        }
        partial_ack(&mut s, LOCAL_SEQ + 13);
        assert_eq!(s.recover(), None);
        assert_eq!(s.retransmits(), 2);
        assert_eq!(s.loss_events(), 1);
    }

    #[test]
    fn repeated_rto_expiries_share_one_episode() {
        let mut s = socket_established();
        s.send_slice(b"abc").unwrap();
        for time in [0, 300, 900, 2100] {
            recv!(s, time time, Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"abc",
                ..RECV_TEMPL
            }));
            assert_eq!(s.loss_events(), u64::from(time != 0));
        }
        assert_eq!(s.retransmits(), 3);
    }

    #[test]
    fn new_ack_allows_a_new_rto_episode() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        for time in [0, 300] {
            recv!(s, time time, Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"abcdef",
                ..RECV_TEMPL
            }));
        }
        partial_ack(&mut s, LOCAL_SEQ + 4);
        assert_eq!(s.loss_events(), 1);
        recv!(s, time 600, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 4,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"def",
            ..RECV_TEMPL
        }));
        assert_eq!(s.loss_events(), 2);
        assert_eq!(s.retransmits(), 2);
    }

    #[test]
    fn connection_reset_clears_counters() {
        let mut s = socket_fast_retransmit_emit_failed();
        recv!(s, time 20, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"aaa",
            ..RECV_TEMPL
        }));
        assert_eq!((s.retransmits(), s.loss_events()), (1, 1));
        s.abort();
        assert_eq!(s.recover(), None);
        assert!(!s.pending_fast_retransmit);
        s.listen(LOCAL_PORT).unwrap();
        assert_eq!((s.retransmits(), s.loss_events()), (0, 0));
        assert!(!s.in_rto_loss_episode);
        assert_eq!(s.congestion_window(), s.congestion_controller.window());
    }

    #[test]
    fn syn_fin_and_repeated_probe_emissions_count_as_retransmits() {
        for state in [State::SynSent, State::SynReceived, State::FinWait1] {
            let mut s = match state {
                State::SynSent => socket_syn_sent(),
                State::SynReceived => socket_syn_received(),
                _ => socket_established(),
            };
            if state == State::FinWait1 {
                s.close();
            }
            let control = if state == State::FinWait1 { TcpControl::Fin } else { TcpControl::Syn };
            for time in [0, 300, 900] {
                recv(&mut s, Instant::from_millis(time), |result| {
                    assert_eq!(result.unwrap().control, control);
                });
                assert_eq!(s.retransmits(), match time { 0 => 0, 300 => 1, _ => 2 });
                assert_eq!(s.loss_events(), u64::from(time != 0));
            }
        }
        let mut s = socket_zero_window(DEFAULT_RTO);
        for (time, retransmits) in [(300, 0), (900, 1), (2100, 2)] {
            recv(&mut s, Instant::from_millis(time), |result| {
                let repr = result.unwrap();
                assert_eq!(repr.seq_number, LOCAL_SEQ + 1);
                assert_eq!(repr.payload, b"a");
            });
            assert_eq!(s.retransmits(), retransmits);
            assert_eq!(s.loss_events(), 0);
        }
    }

    #[test]
    fn rto_episode_survives_peer_window_reopening() {
        let mut s = socket_established();
        s.send_slice(b"abc").unwrap();
        for time in [0, 300] {
            recv!(s, time time, Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"abc",
                ..RECV_TEMPL
            }));
        }
        for window_len in [0, 256] {
            send!(s, time 300, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len,
                ..SEND_TEMPL
            });
        }
        assert_eq!(s.rto_backoff, 0);
        recv!(s, time 900, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"abc",
            ..RECV_TEMPL
        }));
        assert_eq!(s.loss_events(), 1);
        assert_eq!(s.retransmits(), 2);
    }

    #[test]
    fn peer_reset_clears_recover() {
        let mut s = socket_fast_retransmit_emit_failed();
        send!(s, time 30, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: None,
            control: TcpControl::Rst,
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::Closed);
        assert_eq!(s.recover(), None);
        assert!(!s.pending_fast_retransmit);
    }

    #[test]
    fn test_fast_retransmit_survives_failed_emit() {
        let mut s = socket_fast_retransmit_emit_failed();
        // With no further input, the next dispatch resends the hole.
        recv!(s, time 20, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaa"[..],
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_fast_retransmit_pending_cleared_by_ack_of_new_data() {
        let mut s = socket_fast_retransmit_emit_failed();
        // The peer acknowledges everything and closes its window.
        send!(s, time 30, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 12),
            window_len: 0,
            ..SEND_TEMPL
        });
        // Nothing goes into the zero window (the first zero-window probe is due
        // one RTO, at least 1 s, after time zero).
        s.send_slice(b"eee").unwrap();
        recv_nothing!(s, time 30);
    }

    #[test]
    fn test_reset_clears_pending_fast_retransmit() {
        let mut s = socket_fast_retransmit_emit_failed();
        assert!(s.pending_fast_retransmit);
        s.reset();
        assert!(!s.pending_fast_retransmit);
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection_with_data() {
        let mut s = socket_established();

        s.send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // Normal ACK of previously received segment
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // First duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Second duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.local_rx_dup_acks, 2, "duplicate ACK counter is not set");

        // This packet has content, hence should not be detected
        // as a duplicate ACK and should reset the duplicate ACK count
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"xxxxxx"[..],
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 3,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 64,
                ..RECV_TEMPL
            }]
        );

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when receiving data"
        );
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection_with_window_update() {
        let mut s = socket_established();

        s.send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // Normal ACK of previously received segment
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // First duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Second duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.local_rx_dup_acks, 2, "duplicate ACK counter is not set");

        // This packet has a window update, hence should not be detected
        // as a duplicate ACK and should reset the duplicate ACK count
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 400,
                ..SEND_TEMPL
            }
        );

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when receiving a window update"
        );
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.socket.update_rx_mbuf_budget(&s.cx);

        // Normal ACK of previously received segment
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // First duplicate, should not be counted as there is nothing to resend
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is set but wound not transmit data"
        );

        // Send a long string of text divided into several packets
        // because of small remote_mss
        s.send_slice(b"xxxxxxyyyyyywwwwwwzzzzzz").unwrap();

        // This packet is reordered in network
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"xxxxxx"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"yyyyyy"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 2),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"wwwwww"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1015, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 3),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"zzzzzz"[..],
            ..RECV_TEMPL
        }));

        // First duplicate ACK
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Second duplicate ACK
        send!(s, time 1055, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Reordered packet arrives which should reset duplicate ACK count
        send!(s, time 1060, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (6 * 3)),
            ..SEND_TEMPL
        });

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when receiving ACK which updates send window"
        );

        // ACK all received segments
        send!(s, time 1120, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (6 * 4)),
            ..SEND_TEMPL
        });
    }

    #[test]
    fn test_fast_retransmit_dup_acks_counter() {
        let mut s = socket_established();

        s.send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // A lot of retransmits happen here
        s.local_rx_dup_acks = u8::MAX - 1;

        // Send 3 more ACKs, which could overflow local_rx_dup_acks,
        // but intended behaviour is that we saturate the bounds
        // of local_rx_dup_acks
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(
            s.local_rx_dup_acks,
            u8::MAX,
            "duplicate ACK count should not overflow but saturate"
        );
    }

    #[test]
    fn test_fast_retransmit_zero_window() {
        let mut s = socket_established();

        send!(s, time 1000, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        s.send_slice(b"abc").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // 3 dup acks
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0, // boom
            ..SEND_TEMPL
        });

        // even though we're in "fast retransmit", we shouldn't
        // force-send anything because the remote's window is full.
        recv_nothing!(s);
    }

    #[test]
    fn test_retransmit_exponential_backoff() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));

        let expected_retransmission_instant = s.retransmission_timeout().total_millis() as i64;
        recv_nothing!(s, time expected_retransmission_instant - 1);
        recv!(s, time expected_retransmission_instant, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));

        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(900)));

        // "current time" is expected_retransmission_instant, and we want to wait 2 * retransmission timeout
        let expected_retransmission_instant = 3 * expected_retransmission_instant;

        recv_nothing!(s, time expected_retransmission_instant - 1);
        recv!(s, time expected_retransmission_instant, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(2100)));
    }

    #[test]
    fn test_data_retransmit_ack_more_than_expected() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.socket.update_rx_mbuf_budget(&s.cx);
        s.send_slice(b"aaaaaabbbbbbcccccc").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaaaaa"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"bbbbbb"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 12,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"cccccc"[..],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);

        recv_nothing!(s, time 50);

        // retransmit timer expires, we want to retransmit all 3 packets
        // but we only manage to retransmit 2 (due to e.g. lack of device buffer space)
        assert!(s.timer.is_retransmit());
        recv!(s, time 300, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaaaaa"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 300, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"bbbbbb"[..],
            ..RECV_TEMPL
        }));

        // ack first packet.
        send!(
            s,
            time 900,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );

        // this should keep retransmit timer on, because there's
        // still unacked data.
        assert!(s.timer.is_retransmit());

        // ack all three packets.
        // This might confuse the TCP stack because after the retransmit
        // it "thinks" the 3rd packet hasn't been transmitted yet, but it is getting acked.
        send!(
            s,
            time 900,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 18),
                ..SEND_TEMPL
            }
        );

        // this should exit retransmit mode.
        assert!(!s.timer.is_retransmit());
        // and consider all data ACKed.
        assert!(s.tx_buffer.is_empty());
        recv_nothing!(s, time 1500);
    }

    #[test]
    fn test_retransmit_fin() {
        let mut s = socket_established();
        s.close();
        recv!(s, time 0, Ok(TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));

        recv_nothing!(s, time 299);
        recv!(s, time 300, Ok(TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_retransmit_fin_wait() {
        let mut s = socket_fin_wait_1();
        // we send FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        // remote also sends FIN, does NOT ack ours.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // we ack it
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::None,
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]
        );

        // we haven't got an ACK for our FIN, we should retransmit.
        recv_nothing!(s, time 299);
        recv!(
            s,
            time 300,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s, time 899);
        recv!(
            s,
            time 900,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]
        );
    }

    // =========================================================================================//
    // Tests for window management.
    // =========================================================================================//

    #[test]
    fn test_maximum_segment_size() {
        let mut s = socket_listen();
        s.tx_buffer = SocketBuffer::new(vec![0; 32767]);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(1000),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 32767,
                ..SEND_TEMPL
            }
        );
        s.send_slice(&[0; 1200][..]).unwrap();
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; 1000][..],
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_drain_does_not_clip_next_frame_to_unread_byte_room() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        // The immediate-ACK threshold (RMSS) is the receive MSS estimate.
        s.rcv_mss = 32;

        // The receive window doubles relative to the unacknowledged right edge.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 32],
                ..SEND_TEMPL
            }
        );
        recv!(s, [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 33),
                window_len: 64,
                ..RECV_TEMPL
            }]);

        // One byte of data waits for the delayed ACK timer.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 33,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 1],
                ..SEND_TEMPL
            }
        );
        recv_nothing!(s);

        // Draining the first frame leaves the one-byte frame queued.
        drop(s.recv().unwrap().unwrap());
        recv_nothing!(s);

        // Another 32 bytes fit in the frame window without clipping.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 34,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 32],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 66),
                window_len: 64,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_close_wait_no_window_update() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[1, 2, 3, 4],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);

        // we ack the FIN, with the reduced window size.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 6),
                window_len: 64,
                ..RECV_TEMPL
            })
        );

        assert_eq!(drain_bytes(&mut s).len(), 4);

        // check that we do NOT send a window update even if it has changed.
        recv_nothing!(s);
    }

    #[test]
    fn test_time_wait_no_window_update() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                payload: &[1, 2, 3, 4],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);

        // we ack the FIN, with the reduced window size.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 6),
                window_len: 64,
                ..RECV_TEMPL
            })
        );

        assert_eq!(drain_bytes(&mut s).len(), 4);

        // check that we do NOT send a window update even if it has changed.
        recv_nothing!(s);
    }

    // =========================================================================================//
    // Tests for flow control.
    // =========================================================================================//

    #[test]
    fn test_psh_transmit() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.socket.update_rx_mbuf_budget(&s.cx);
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }), exact);
    }

    #[test]
    fn test_psh_receive() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 64,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_ack() {
        let (mut s, _frames) = socket_with_held_rx_frames(6, REMOTE_SEQ + 1, 5);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.recv_room(), 0);
        assert_eq!(s.recv_queue(), 6);
        recv_nothing!(s);
    }

    #[test]
    fn test_zero_window_ack_not_rate_limited() {
        let (mut s, _frames) = socket_with_held_rx_frames(6, REMOTE_SEQ + 1, 5);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.recv_room(), 0);
        assert_eq!(s.recv_queue(), 6);
        recv_nothing!(s);
        // Repeated data in a zero window must be ACKed without challenge ACK rate limiting.
        send!(
            s,
            time 100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_zero_window_fin() {
        let (mut s, _frames) = socket_with_held_rx_frames(6, REMOTE_SEQ + 1, 5);
        s.set_ack_delay(None);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );

        // FIN at RCV.NXT is accepted even with a zero receive window.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[],
                control: TcpControl::Fin,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);

        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 7),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn recv_room_counts_frames() {
        let mut s = socket_established_with_buffer_sizes(8, 8);
        assert_eq!(s.recv_room(), s.recv_capacity());
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"abcdef",
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.recv_room(), 8);
        let frame = s.recv().unwrap().unwrap();
        assert_eq!(frame.payload(), b"abcdef");
        assert_eq!(s.recv_room(), 8);
        assert_eq!(s.recv_queue(), 0);
        drop(frame);
        assert_eq!(s.recv_room(), 8);
    }

    #[test]
    fn drain_closed_socket() {
        let mut s = socket();
        assert_eq!(s.recv().unwrap_err(), RecvError::InvalidState);
    }

    #[test]
    fn finished_only_after_drain() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"abc",
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::CloseWait);
        let frame = s.recv().unwrap().unwrap();
        assert_eq!(frame.payload(), b"abc");
        assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
    }

    #[test]
    fn test_fill_peer_window() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.socket.update_rx_mbuf_budget(&s.cx);
        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        recv!(
            s,
            [
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"abcdef"[..],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + 6,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"123456"[..],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + 6 + 6,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"!@#$%^"[..],
                    ..RECV_TEMPL
                }
            ]
        );
    }

    #[test]
    fn test_announce_window_after_read() {
        let (mut s, mut frames) = socket_with_held_rx_frames(6, REMOTE_SEQ + 1, 5);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 3,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.remote_last_win_bytes, 3);
        assert_eq!(s.recv_room(), 0);
        drop(s.recv().unwrap().unwrap());
        assert!(s.window_to_update());
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            window_len: 6,
            ..RECV_TEMPL
        }]);
        // Release another frame so both gap-fill frames fit.
        drop(frames.pop().unwrap());
        assert_eq!(s.remote_last_win_bytes as usize, s.rx_buffer.capacity);
        // Provoke immediate ACK to test that `process` updates `remote_last_win_bytes`
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"def"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 6,
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 9),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.remote_last_win_bytes, 0);
        assert_eq!(s.recv_room(), 0);
        drop(s.recv().unwrap().unwrap());
        assert!(s.window_to_update());
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 9),
            window_len: 6,
            ..RECV_TEMPL
        }]);
    }

    // =========================================================================================//
    // Tests for zero-window probes.
    // =========================================================================================//

    #[test]
    fn default_rto_first_deadline_is_three_hundred_ms() {
        let mut s = socket_syn_sent();
        recv(&mut s, Instant::from_millis(40), |result| {
            assert_eq!(result.unwrap().control, TcpControl::Syn);
        });
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(340)));
        recv_nothing!(s, time 339);
        recv(&mut s, Instant::from_millis(340), |result| {
            assert_eq!(result.unwrap().control, TcpControl::Syn);
        });
    }

    #[test]
    fn default_rto_backoff_deadlines_are_300_900_2100() {
        let mut s = socket_established();
        s.send_slice(b"abc").unwrap();
        for (at, deadline) in [(0, 300), (300, 900), (900, 2100), (2100, 4500)] {
            recv(&mut s, Instant::from_millis(at), |result| {
                let repr = result.unwrap();
                assert_eq!(repr.seq_number, LOCAL_SEQ + 1);
                assert_eq!(repr.payload, b"abc");
            });
            assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(deadline)));
            recv_nothing(&mut s, Instant::from_millis(deadline - 1));
        }
    }

    #[test]
    fn ack_after_forty_ms_prevents_retransmission() {
        let mut s = socket_established();
        s.send_slice(b"abc").unwrap();
        recv(&mut s, Instant::ZERO, |result| {
            assert_eq!(result.unwrap().payload, b"abc");
        });
        send!(s, time 40, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 4),
            ..SEND_TEMPL
        });
        assert_eq!(s.send_queue(), 0);
        assert!(s.timer.is_idle());
        for at in [300, 900, 2100] {
            recv_nothing(&mut s, Instant::from_millis(at));
        }
    }

    fn socket_zero_window(rto: Duration) -> TestSocket {
        let mut s = socket_established();
        s.set_rto(rto);
        s.send_slice(b"abc").unwrap();
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        });
        s
    }

    #[test]
    fn set_rto_applies_to_syn_synack_data_fin_and_probe() {
        for state in [State::SynSent, State::SynReceived, State::Established, State::FinWait1] {
            let mut s = match state {
                State::SynSent => socket_syn_sent(),
                State::SynReceived => socket_syn_received(),
                _ => socket_established(),
            };
            s.set_rto(Duration::from_millis(700));
            if state == State::Established {
                s.send_slice(b"abc").unwrap();
            } else if state == State::FinWait1 {
                s.close();
            }
            recv(&mut s, Instant::ZERO, |result| {
                let repr = result.unwrap();
                assert_eq!(repr.control, match state {
                    State::SynSent | State::SynReceived => TcpControl::Syn,
                    State::FinWait1 => TcpControl::Fin,
                    _ => TcpControl::Psh,
                });
            });
            assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(700)));
        }
        let mut s = socket_zero_window(Duration::from_millis(700));
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(700)));
        s.set_rto(Duration::from_millis(400));
        recv_nothing!(s, time 699);
        recv(&mut s, Instant::from_millis(700), |result| {
            assert_eq!(result.unwrap().payload, b"a");
        });
        assert_eq!(s.rto_backoff, 1);
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(1500)));
    }

    #[test]
    fn rto_backoff_caps_at_sixty_seconds() {
        for probe in [false, true] {
            let mut s = if probe {
                socket_zero_window(Duration::from_secs(30))
            } else {
                let mut s = socket_established();
                s.set_rto(Duration::from_secs(30));
                s.send_slice(b"abc").unwrap();
                recv(&mut s, Instant::ZERO, |result| {
                    assert_eq!(result.unwrap().payload, b"abc");
                });
                s
            };
            for (index, at) in [30_000, 90_000, 150_000, 210_000].into_iter().enumerate() {
                recv_nothing(&mut s, Instant::from_millis(at - 1));
                recv(&mut s, Instant::from_millis(at), |result| {
                    assert_eq!(result.unwrap().payload, if probe { &b"a"[..] } else { &b"abc"[..] });
                });
                assert_eq!(s.rto_backoff, (index + 1) as u32);
                assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(at + 60_000)));
            }
        }
    }

    #[test]
    fn probe_backoff_counts_expiry_once_even_if_emit_fails() {
        let mut s = socket_zero_window(Duration::from_millis(700));
        for at in [700, 710] {
            s.cx.set_now(Instant::from_millis(at));
            assert_eq!(s.socket.dispatch(&mut s.cx, |_, _, (_, repr)| {
                assert_eq!(repr.payload, b"a");
                Err(())
            }), Err(()));
            assert_eq!(s.rto_backoff, 1);
            assert!(matches!(s.timer, Timer::ZeroWindowProbe { backoff_applied: true, .. }));
            assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(700)));
        }
        recv(&mut s, Instant::from_millis(720), |result| {
            assert_eq!(result.unwrap().payload, b"a");
        });
        assert_eq!(s.rto_backoff, 1);
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(2120)));
        recv_nothing!(s, time 2119);
    }

    #[test]
    fn failed_probe_expiry_still_counts_backoff() {
        let mut s = socket_established();
        s.send_slice(b"abc").unwrap();
        recv!(s, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"abc",
            ..RECV_TEMPL
        }));
        let ack = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 2),
            window_len: 0,
            ..SEND_TEMPL
        };
        send!(s, time 100, ack);
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(400)));
        s.cx.set_now(Instant::from_millis(400));
        assert_eq!(s.socket.dispatch(&mut s.cx, |_, _, _| Err(())), Err(()));
        for _ in 0..3 {
            send!(s, time 410, ack);
        }
        recv!(s, time 410, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 2,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"bc",
            ..RECV_TEMPL
        }));
        assert_eq!(s.timer, Timer::Retransmit {
            expires_at: Instant::from_millis(1010),
        });
        assert_eq!(s.rto_backoff, 1);
    }

    #[test]
    fn window_reopen_with_outstanding_data_rearms_retransmit() {
        let mut s = socket_established();
        s.send_slice(b"a").unwrap();
        recv!(s, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"a",
            ..RECV_TEMPL
        }));
        s.send_slice(b"bc").unwrap();
        recv!(s, time 10, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 2,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"bc",
            ..RECV_TEMPL
        }));
        send!(s, time 100, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 2),
            window_len: 0,
            ..SEND_TEMPL
        });
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(400)));
        send!(s, time 200, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 2),
            window_len: 3,
            ..SEND_TEMPL
        });
        recv_nothing!(s, time 499);
        recv!(s, time 500, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 2,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"bc",
            ..RECV_TEMPL
        }));
        assert_eq!(s.rto_backoff, 1);
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(1100)));
    }

    #[test]
    fn probe_byte_resend_does_not_sample_rtt() {
        let mut s = socket_zero_window(DEFAULT_RTO);
        for at in [300, 900] {
            recv!(s, time at, Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"a",
                ..RECV_TEMPL
            }));
        }
        send!(s, time 1000, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 1,
            ..SEND_TEMPL
        });
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"a",
            ..RECV_TEMPL
        }));
        assert_eq!(s.rtte.timestamp(), None);
        send!(s, time 1100, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 2),
            window_len: 1,
            ..SEND_TEMPL
        });
        assert!(!s.rtte.have_measurement);
        recv!(s, time 1100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 2,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"b",
            ..RECV_TEMPL
        }));
        send!(s, time 1150, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 3),
            window_len: 1,
            ..SEND_TEMPL
        });
        assert!(s.rtte.have_measurement);
        assert_eq!(s.rtte.srtt, 50);
    }

    #[test]
    fn duplicate_ack_does_not_reset_probe_backoff() {
        let mut s = socket_zero_window(Duration::from_millis(700));
        recv(&mut s, Instant::from_millis(700), |result| {
            assert_eq!(result.unwrap().payload, b"a");
        });
        send!(s, time 710, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        });
        assert_eq!(s.rto_backoff, 1);
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(2100)));
        recv_nothing!(s, time 2099);
        recv(&mut s, Instant::from_millis(2100), |result| {
            assert_eq!(result.unwrap().payload, b"a");
        });
        send!(s, time 2110, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 2),
            window_len: 0,
            ..SEND_TEMPL
        });
        assert_eq!(s.rto_backoff, 0);
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(2810)));
    }

    #[test]
    fn accepted_window_reopening_resets_backoff() {
        let mut s = socket_zero_window(Duration::from_millis(700));
        recv(&mut s, Instant::from_millis(700), |result| {
            assert_eq!(result.unwrap().payload, b"a");
        });
        send!(s, time 710, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ),
            window_len: 6,
            ..SEND_TEMPL
        });
        assert_eq!(s.remote_win_len, 0);
        assert_eq!(s.rto_backoff, 1);
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(2100)));
        send!(s, time 720, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 6,
            ..SEND_TEMPL
        });
        assert_eq!(s.remote_win_len, 6);
        assert_eq!(s.rto_backoff, 0);
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(1420)));
        recv(&mut s, Instant::from_millis(720), |result| {
            assert_eq!(result.unwrap().payload, b"abc");
        });
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(1420)));
        recv(&mut s, Instant::from_millis(1420), |result| {
            assert_eq!(result.unwrap().payload, b"abc");
        });
        send!(s, time 1430, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 12,
            ..SEND_TEMPL
        });
        assert_eq!(s.remote_win_len, 12);
        assert_eq!(s.rto_backoff, 1);
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(2820)));
    }

    #[test]
    fn rto_expiry_with_probe_counts_one_backoff() {
        for fail_emit in [false, true] {
            let mut s = socket_established();
            s.set_rto(Duration::from_millis(700));
            s.send_slice(b"abc").unwrap();
            recv(&mut s, Instant::ZERO, |result| {
                assert_eq!(result.unwrap().payload, b"abc");
            });
            send!(s, time 100, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            });
            recv_nothing!(s, time 699);
            if fail_emit {
                for at in [700, 710] {
                    s.cx.set_now(Instant::from_millis(at));
                    assert_eq!(s.socket.dispatch(&mut s.cx, |_, _, (_, repr)| {
                        assert_eq!(repr.payload, b"a");
                        Err(())
                    }), Err(()));
                    assert_eq!(s.rto_backoff, 1);
                    assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(700)));
                }
            }
            let at = if fail_emit { 720 } else { 700 };
            recv(&mut s, Instant::from_millis(at), |result| {
                assert_eq!(result.unwrap().payload, b"a");
            });
            assert_eq!(s.rto_backoff, 1);
            assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(at + 1400)));
            recv(&mut s, Instant::from_millis(at + 1400), |result| {
                assert_eq!(result.unwrap().payload, b"a");
            });
            assert_eq!(s.rto_backoff, 2);
            assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(at + 4200)));
        }
    }

    #[test]
    fn test_zero_window_echo_ack_after_read() {
        for rx_len in [1024, 16384] {
            let mut s = socket_with_buffer_sizes(1024, rx_len);
            s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
            s.socket.listen(LISTEN_END).unwrap();
            send!(s, TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                ..SEND_TEMPL
            });
            recv!(s, Ok(TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: rx_len as u16,
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }));
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            });

            let held_count = if rx_len == 1024 {
                s.rx_frame_cap().checked_sub(1).expect("RX frame budget is empty")
            } else {
                0
            };
            let _frames = hold_rx_frames(&mut s, held_count);
            let data_seq = s.remote_seq_no;
            send!(s, time 1200, TcpRepr {
                seq_number: data_seq,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                payload: &[0; 1024],
                ..SEND_TEMPL
            });
            assert_eq!(s.ack_delay_timer(),
                       AckDelayTimer::Waiting(Instant::from_millis(1210)));
            assert!(!s.delayed_ack_expired(s.cx.now()));
            assert!(!s.socket.seq_to_transmit(&mut s.cx));
            assert!(!s.window_to_update());
            recv_nothing!(s, time 1200);
            assert_eq!(s.recv_room() == 0, rx_len == 1024);

            let echo = drain_bytes(&mut s);
            assert_eq!(echo.len(), 1024);
            assert_eq!(s.send_slice(&echo), Ok(1024));

            assert!(s.timer.is_idle());
            assert_eq!(s.last_scaled_window(), Some(rx_len as u16 - 1024));
            assert_eq!(s.scaled_window(), rx_len as u16);
            assert_eq!(s.window_to_update(), rx_len == 1024);
            assert_eq!(s.ack_delay_timer(),
                       AckDelayTimer::Waiting(Instant::from_millis(1210)));
            assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);

            let ack = TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(data_seq + 1024),
                window_len: rx_len as u16,
                ..RECV_TEMPL
            };
            if rx_len == 1024 {
                recv!(s, time 1200, Ok(ack));
                assert_eq!(s.ack_delay_timer(), AckDelayTimer::Idle);
                assert!(!s.ack_to_transmit());
                assert!(!s.window_to_update());
            } else {
                recv_nothing!(s, time 1200);
                assert_eq!(s.socket.poll_at(&mut s.cx),
                           PollAt::Time(Instant::from_millis(1210)));
                recv_nothing!(s, time 1209);
                recv!(s, time 1210, Ok(ack));
            }
            assert_eq!(s.timer, Timer::ZeroWindowProbe {
                expires_at: Instant::from_millis(1500),
                backoff_applied: false,
            });
            assert_eq!(s.socket.poll_at(&mut s.cx),
                       PollAt::Time(Instant::from_millis(1500)));
            recv_nothing!(s, time 1210);
            assert_eq!(s.remote_last_seq, LOCAL_SEQ + 1);
            assert_eq!(s.send_queue(), 1024);

            if rx_len == 1024 {
                send!(s, time 1300, TcpRepr {
                    seq_number: data_seq + 1024,
                    ack_number: Some(LOCAL_SEQ + 1),
                    window_len: 0,
                    payload: &[0; 1024],
                    ..SEND_TEMPL
                });
                assert_eq!(s.send_capacity() - s.send_queue(), 0);
                assert_eq!(s.recv_room(), 0);
                assert_eq!(s.scaled_window(), 0);
                assert!(!s.window_to_update());
                assert_eq!(s.socket.poll_at(&mut s.cx),
                           PollAt::Time(Instant::from_millis(1310)));
                recv_nothing!(s, time 1309);
                recv!(s, time 1310, Ok(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(data_seq + 2048),
                    window_len: 0,
                    ..RECV_TEMPL
                }));
            }
            let ack_number = s.remote_last_ack;
            let window_len = s.scaled_window();
            recv!(s, time 1500, [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number,
                window_len,
                payload: &[0],
                ..RECV_TEMPL
            }]);
            assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(2100)));
        }
    }

    #[test]
    fn test_zero_window_probe_enter_on_win_update() {
        let mut s = socket_established();

        assert!(!s.timer.is_zero_window_probe());

        s.send_slice(b"abcdef123456!@#$%^").unwrap();

        assert!(!s.timer.is_zero_window_probe());

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        assert!(s.timer.is_zero_window_probe());
    }

    #[test]
    fn test_zero_window_probe_enter_on_send() {
        let mut s = socket_established();

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        assert!(!s.timer.is_zero_window_probe());

        s.send_slice(b"abcdef123456!@#$%^").unwrap();

        assert!(s.timer.is_idle());
        recv_nothing!(s);
        assert!(s.timer.is_zero_window_probe());
    }

    #[test]
    fn test_zero_window_probe_first_dispatch_uses_current_time() {
        let mut s = socket_established();
        send!(s, time 100_000, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        });
        s.send_slice(b"abc").unwrap();
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
        recv_nothing!(s, time 100_000);
        assert_eq!(s.timer, Timer::ZeroWindowProbe {
            expires_at: Instant::from_millis(100_300),
            backoff_applied: false,
        });
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Time(Instant::from_millis(100_300)));
        recv_nothing!(s, time 100_299);
        recv!(s, time 100_300, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"a"[..],
            ..RECV_TEMPL
        }]);
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(100_900)));
    }

    #[test]
    fn test_zero_window_probe_after_retransmit_timeout() {
        let mut s = socket_established();
        s.send_slice(b"abc").unwrap();
        recv!(s, time 100_000, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"abc"[..],
            ..RECV_TEMPL
        }]);
        send!(s, time 100_100, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        });
        assert!(s.timer.is_retransmit());
        recv_nothing!(s, time 100_299);
        recv!(s, time 100_300, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"a"[..],
            ..RECV_TEMPL
        }]);
        assert_eq!(s.timer, Timer::ZeroWindowProbe {
            expires_at: Instant::from_millis(100_900),
            backoff_applied: false,
        });
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Time(Instant::from_millis(100_900)));
        recv_nothing!(s, time 100_899);
        recv!(s, time 100_900, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"a"[..],
            ..RECV_TEMPL
        }]);
        assert_eq!(s.timer, Timer::ZeroWindowProbe {
            expires_at: Instant::from_millis(102_100),
            backoff_applied: false,
        });
        recv_nothing!(s, time 102_099);
        recv!(s, time 102_100, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"a"[..],
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_zero_window_probe_exit() {
        let mut s = socket_established();

        s.send_slice(b"abcdef123456!@#$%^").unwrap();

        assert!(!s.timer.is_zero_window_probe());

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        assert!(s.timer.is_zero_window_probe());

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 6,
                ..SEND_TEMPL
            }
        );

        assert!(!s.timer.is_zero_window_probe());
    }

    #[test]
    fn test_zero_window_probe_exit_ack() {
        let mut s = socket_established();

        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            time 300,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(900)));

        send!(
            s,
            time 310,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                window_len: 6,
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            time 310,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"bcdef1"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_probe_not_capped_by_cwnd() {
        let mut s = socket_established_with_buffer_sizes(8192, 64);
        s.remote_win_len = 65535;
        s.remote_mss = 1024;
        s.socket.update_rx_mbuf_budget(&s.cx);

        let data = [b'x'; 4096];
        s.send_slice(&data[..]).unwrap();

        // The pre-handshake Cubic window is 2048: two segments fill the congestion window
        // exactly, leaving cwnd_remaining() == 0.
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1024,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);

        // The remote closes its window without acknowledging anything new, so
        // no congestion window space is freed either.
        send!(s, time 10, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        });

        // Arm the probe timer. (Set directly because the ACK above carries no
        // new data; in real traffic this state is reached e.g. when the
        // controller shrinks cwnd below the flight size while probing.)
        s.set_rto(Duration::from_millis(100));
        s.timer
            .set_for_zero_window_probe(Instant::from_millis(10), Duration::from_millis(100));

        // The probe must carry 1 byte of data past the window edge even though
        // the congestion window is exhausted: an empty probe occupies no
        // sequence space and elicits no reply, so the connection would stall
        // if the remote's window update got lost.
        recv!(s, time 110, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 2048,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1],
            ..RECV_TEMPL
        }));
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(310)));
    }

    #[test]
    fn test_zero_window_probe_backoff_nack_reply() {
        let mut s = socket_established();
        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 299);
        recv!(
            s,
            time 300,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(900)));
        send!(
            s,
            time 400,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 899);
        recv!(
            s,
            time 900,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(2100)));
        send!(
            s,
            time 1000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 2099);
        recv!(
            s,
            time 2100,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(4500)));
    }

    #[test]
    fn test_zero_window_probe_backoff_no_reply() {
        let mut s = socket_established();
        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 299);
        recv!(
            s,
            time 300,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(900)));

        recv_nothing!(s, time 899);
        recv!(
            s,
            time 900,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(2100)));
    }

    #[test]
    fn test_zero_window_probe_shift() {
        let mut s = socket_established();

        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 299);
        recv!(
            s,
            time 300,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(900)));

        recv_nothing!(s, time 899);
        recv!(
            s,
            time 900,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.timer.poll_at(), PollAt::Time(Instant::from_millis(2100)));

        // ack the ZWP byte, but still advertise zero window.
        // this should restart the ZWP timer.
        send!(
            s,
            time 1000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        // ZWP should be sent at 1000+300 = 1300
        recv_nothing!(s, time 1299);
        recv!(
            s,
            time 1300,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"b"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_responds_to_keep_alive() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
    }

    // =========================================================================================//
    // Tests for time-to-live configuration.
    // =========================================================================================//

    #[test]
    fn test_set_hop_limit() {
        let mut s = socket_syn_received();

        s.set_hop_limit(Some(0x2a));
        assert_eq!(
            s.socket.dispatch(&mut s.cx, |_, _, (ip_repr, _)| {
                assert_eq!(ip_repr.hop_limit(), 0x2a);
                Ok::<_, ()>(())
            }),
            Ok(())
        );

        // assert that user-configurable settings are kept,
        // see https://github.com/smoltcp-rs/smoltcp/issues/601.
        s.reset();
        assert_eq!(s.hop_limit.map(core::num::NonZeroU8::get), Some(0x2a));
    }

    #[test]
    #[should_panic(expected = "the time-to-live value of a packet must not be zero")]
    fn test_set_hop_limit_zero() {
        let mut s = socket_syn_received();
        s.set_hop_limit(Some(0));
    }

    // =========================================================================================//
    // Tests for reassembly.
    // =========================================================================================//

    #[test]
    fn test_out_of_order() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"def"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert!(s.recv().unwrap().is_none());
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 64,
                ..RECV_TEMPL
            })
        );
        {
            let frame = s.recv().unwrap().unwrap();
            let buffer = frame.payload();
            assert_eq!(buffer, b"abcdef");
        }
    }

    /// `REMOTE_ADDR` is on-link but nothing resolved its hardware address
    /// (the interface's neighbor cache starts empty), so an immediate reply
    /// built by `ack_reply` can never actually be dispatched here.
    #[test]
    fn test_immediate_ack_reply_does_not_commit_state_without_a_resolvable_neighbor() {
        let mut s = socket_established();
        let (iface, _, _) = crate::tests::setup(crate::phy::Medium::Ethernet);
        s.cx = iface.inner;

        // Open a hole so the next, gap-filling segment takes the immediate
        // "ACKing incoming segment" path in `process` (store had
        // out-of-order data), the same path a RFC 5961 challenge ACK or an
        // out-of-order FIN uses.
        send(
            &mut s,
            Instant::from_millis(0),
            &TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"def"[..],
                ..SEND_TEMPL
            },
        );

        let before_ack = s.remote_last_ack;
        let before_win = s.remote_last_win_bytes;
        assert_eq!(before_ack, Some(REMOTE_SEQ + 1));

        let reply = send(
            &mut s,
            Instant::from_millis(0),
            &TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
        );
        // The would-be reply is still computed correctly...
        assert_eq!(
            reply,
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 64,
                ..RECV_TEMPL
            })
        );
        // ...but since it can't be dispatched (no resolved neighbor), the
        // socket must not believe it already ACKed the 6 bytes.
        assert_eq!(s.remote_last_ack, before_ack);
        assert_eq!(s.remote_last_win_bytes, before_win);
    }

    #[test]
    fn test_buffer_wraparound_rx() {
        let mut s = socket_established();
        s.rx_buffer = RxBuffer::new(6);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        {
            let frame = s.recv().unwrap().unwrap();
            let buffer = frame.payload();
            assert_eq!(buffer, b"abc");
        }
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"defghi"[..],
                ..SEND_TEMPL
            }
        );
        let data = drain_bytes(&mut s);
        assert_eq!(data.len(), 6);
        assert_eq!(data, &b"defghi"[..]);
    }

    #[test]
    fn test_buffer_wraparound_tx() {
        let mut s = socket_established();

        s.tx_buffer = SocketBuffer::new(vec![b'.'; 9]);
        assert_eq!(s.send_slice(b"xxxyyy"), Ok(6));
        assert_eq!(s.tx_buffer.dequeue_many(3), &b"xxx"[..]);
        assert_eq!(s.tx_buffer.len(), 3);

        // "abcdef" not contiguous in tx buffer
        assert_eq!(s.send_slice(b"abcdef"), Ok(6));
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"yyyabc"[..],
                ..RECV_TEMPL
            })
        );
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"def"[..],
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_wrapped_remainder_respects_window_and_cwnd() {
        for limit_by_cwnd in [false, true] {
            let mut s = socket_established_with_buffer_sizes(9, 64);

            // Keep three bytes in flight so the next write wraps the tx buffer.
            assert_eq!(s.send_slice(b"xxxxxx"), Ok(6));
            recv!(
                s,
                Ok(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"xxxxxx"[..],
                    ..RECV_TEMPL
                })
            );
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 4),
                    window_len: if limit_by_cwnd { 256 } else { 6 },
                    ..SEND_TEMPL
                }
            );
            if limit_by_cwnd {
                s.congestion_controller.set_mss(6);
                s.congestion_controller.on_rto(Instant::ZERO, 3);
            }

            assert_eq!(s.send_slice(b"abcdef"), Ok(6));
            assert_eq!(s.tx_buffer.get_allocated(3, 6), b"abc");
            assert_eq!(s.tx_buffer.get_allocated(6, 3), b"def");
            recv!(
                s,
                Ok(TcpRepr {
                    seq_number: LOCAL_SEQ + 7,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"abc"[..],
                    ..RECV_TEMPL
                })
            );
            assert_eq!(s.flight_size(), 6);
            if limit_by_cwnd {
                assert_eq!(s.cwnd_remaining(), 0);
                assert!(s.remote_win_len as usize > s.flight_size());
            } else {
                assert_eq!(s.remote_win_len as usize, s.flight_size());
                assert!(s.cwnd_remaining() > 0);
            }
            recv_nothing!(s);

            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 10),
                    window_len: 1,
                    ..SEND_TEMPL
                }
            );
            recv!(
                s,
                [TcpRepr {
                    seq_number: LOCAL_SEQ + 10,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"d"[..],
                    ..RECV_TEMPL
                }]
            );
        }
    }

    // =========================================================================================//
    // Tests for graceful vs ungraceful rx close
    // =========================================================================================//

    #[test]
    fn test_rx_close_fin() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        {
            let frame = s.recv().unwrap().unwrap();
            let data = frame.payload();
            assert_eq!(data, b"abc");
        }
        assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
    }

    #[test]
    fn test_rx_close_fin_in_fin_wait_1() {
        let mut s = socket_fin_wait_1();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);
        {
            let frame = s.recv().unwrap().unwrap();
            let data = frame.payload();
            assert_eq!(data, b"abc");
        }
        assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
    }

    #[test]
    fn test_rx_close_fin_in_fin_wait_2() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        {
            let frame = s.recv().unwrap().unwrap();
            let data = frame.payload();
            assert_eq!(data, b"abc");
        }
        assert_eq!(s.recv().unwrap_err(), RecvError::Finished);
    }

    #[test]
    fn test_rx_close_fin_with_hole() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"ghi"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 64,
                ..RECV_TEMPL
            })
        );
        {
            let frame = s.recv().unwrap().unwrap();
            let data = frame.payload();
            assert_eq!(data, b"abc");
        }
        assert!(s.recv().unwrap().is_none());
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Error must be `Illegal` even if we've received a FIN,
        // because we are missing data.
        assert_eq!(s.recv().unwrap_err(), RecvError::InvalidState);
    }

    #[test]
    fn test_rx_close_rst() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        {
            let frame = s.recv().unwrap().unwrap();
            let data = frame.payload();
            assert_eq!(data, b"abc");
        }
        assert_eq!(s.recv().unwrap_err(), RecvError::InvalidState);
    }

    #[test]
    fn test_rx_close_rst_with_hole() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"ghi"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 64,
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        {
            let frame = s.recv().unwrap().unwrap();
            let data = frame.payload();
            assert_eq!(data, b"abc");
        }
        assert_eq!(s.recv().unwrap_err(), RecvError::InvalidState);
    }

    // =========================================================================================//
    // Tests for delayed ACK
    // =========================================================================================//

    #[test]
    fn test_delayed_ack() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        // After 10ms, it is sent.
        recv!(s, time 11, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            window_len: 64,
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_delayed_ack_win() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        // Reading the data off the buffer should cause a window update.
        {
            let frame = s.recv().unwrap().unwrap();
            let data = frame.payload();
            assert_eq!(data, b"abc");
        }

        // However, no ACK or window update is immediately sent.
        recv_nothing!(s);

        // After 10ms, it is sent.
        recv!(s, time 11, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_delayed_ack_reply() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        {
            let frame = s.recv().unwrap().unwrap();
            let data = frame.payload();
            assert_eq!(data, b"abc");
        }

        s.send_slice(&b"xyz"[..]).unwrap();

        // Writing data to the socket causes ACK to not be delayed,
        // because it is immediately sent with the data.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                payload: &b"xyz"[..],
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_delayed_ack_every_rmss() {
        let mut s = socket_established_with_buffer_sizes(DEFAULT_MSS * 2, DEFAULT_MSS * 2);
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; DEFAULT_MSS - 1],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + (DEFAULT_MSS - 1),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // The receive window doubles relative to the unacknowledged right edge.
        recv!(s, [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + DEFAULT_MSS),
                window_len: (DEFAULT_MSS * 2) as u16,
                ..RECV_TEMPL
            }]);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + DEFAULT_MSS,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // The last byte is acknowledged when the delayed ACK timer expires.
        recv!(
            s,
            time 10,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + (DEFAULT_MSS + 1)),
                window_len: (DEFAULT_MSS * 2) as u16,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_delayed_ack_every_rmss_or_more() {
        let mut s = socket_established_with_buffer_sizes(DEFAULT_MSS * 2, DEFAULT_MSS * 2);
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; DEFAULT_MSS],
                ..SEND_TEMPL
            }
        );

        // The receive window doubles relative to the unacknowledged right edge.
        recv!(s, [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + DEFAULT_MSS),
                window_len: (DEFAULT_MSS * 2) as u16,
                ..RECV_TEMPL
            }]);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + DEFAULT_MSS,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + (DEFAULT_MSS + 1),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"b"[..],
                ..SEND_TEMPL
            }
        );

        // The last two bytes are acknowledged when the delayed ACK timer expires.
        recv!(
            s,
            time 10,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + (DEFAULT_MSS + 2)),
                window_len: (DEFAULT_MSS * 2) as u16,
                ..RECV_TEMPL
            })
        );
    }

    // =========================================================================================//
    // Tests for prompt sending (no Nagle hold; subject only to window/cwnd)
    // =========================================================================================//

    #[test]
    fn test_full_segment_sent_promptly() {
        const EFFECTIVE_MSS: usize = 64;

        let mut s = socket_established_with_buffer_sizes(256, 64);
        s.remote_mss = u16::try_from(EFFECTIVE_MSS).expect("test MSS exceeds u16");
        s.socket.update_rx_mbuf_budget(&s.cx);

        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );

        s.send_slice(&[0; EFFECTIVE_MSS]).unwrap();
        recv!(
            s,
            time 0,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; EFFECTIVE_MSS],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_final_packet_in_stream_sent_promptly() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.socket.update_rx_mbuf_budget(&s.cx);
        s.send_slice(b"abcdef0").unwrap();
        s.socket.close();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"0"[..],
            ..RECV_TEMPL
        }), exact);
    }

    // =========================================================================================//
    // Tests for packet filtering.
    // =========================================================================================//

    #[test]
    fn test_doesnt_accept_wrong_port() {
        let mut s = socket_established();
        s.rx_buffer = RxBuffer::new(6);

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            dst_port: LOCAL_PORT + 1,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            src_port: REMOTE_PORT + 1,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_doesnt_accept_wrong_ip() {
        let mut s = socket_established();

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        };

        let ip_repr = IpReprIpvX(IpvXRepr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(s.socket.accepts(&mut s.cx, &ip_repr, &tcp_repr));

        let ip_repr_wrong_src = IpReprIpvX(IpvXRepr {
            src_addr: OTHER_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(!s.socket.accepts(&mut s.cx, &ip_repr_wrong_src, &tcp_repr));

        let ip_repr_wrong_dst = IpReprIpvX(IpvXRepr {
            src_addr: REMOTE_ADDR,
            dst_addr: OTHER_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(!s.socket.accepts(&mut s.cx, &ip_repr_wrong_dst, &tcp_repr));
    }

    // =========================================================================================//
    // Timer tests
    // =========================================================================================//

    #[test]
    fn test_timer_retransmit() {
        const RTO: Duration = Duration::from_millis(100);
        let mut r = Timer::new();
        assert!(!r.should_retransmit(Instant::from_secs(1)));
        r.set_for_retransmit(Instant::from_millis(1000), RTO);
        assert!(!r.should_retransmit(Instant::from_millis(1000)));
        assert!(!r.should_retransmit(Instant::from_millis(1050)));
        assert!(r.should_retransmit(Instant::from_millis(1101)));
        r.set_for_retransmit(Instant::from_millis(1101), RTO);
        assert!(!r.should_retransmit(Instant::from_millis(1101)));
        assert!(!r.should_retransmit(Instant::from_millis(1150)));
        assert!(!r.should_retransmit(Instant::from_millis(1200)));
        assert!(r.should_retransmit(Instant::from_millis(1301)));
        r.set_for_idle();
        assert!(!r.should_retransmit(Instant::from_millis(1350)));
    }

    #[test]
    fn smoothed_rtt_initializes_then_uses_existing_weight() {
        let mut r = SmoothedRtt::default();
        assert!(!r.have_measurement);
        for (index, (sample, expected)) in [(101, 101), (102, 102), (109, 103), (9, 92)]
            .into_iter()
            .enumerate()
        {
            let sent_at = Instant::from_millis(index as i64 * 1000);
            let seq = LOCAL_SEQ + index + 1;
            r.on_send(sent_at, seq);
            r.on_ack(sent_at + Duration::from_millis(sample), seq);
            assert!(r.have_measurement);
            assert_eq!(r.srtt, expected);
            assert_eq!(r.timestamp(), None);
        }
    }

    #[test]
    fn fixed_rto_ignores_slow_ack_samples() {
        for (rto, deadline) in [
            (Duration::from_millis(1000), 1600),
            (Duration::from_millis(700), 1300),
        ] {
            let mut s = socket_established();
            s.set_rto(rto);
            s.remote_mss = 6;
            s.socket.update_rx_mbuf_budget(&s.cx);
            s.send_slice(b"abcdef012345").unwrap();
            for offset in [0, 6] {
                recv(&mut s, Instant::ZERO, |result| {
                    let repr = result.unwrap();
                    assert_eq!(repr.seq_number, LOCAL_SEQ + 1 + offset);
                    assert_eq!(repr.payload, &b"abcdef012345"[offset..offset + 6]);
                });
            }
            send!(s, time 600, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 7),
                ..SEND_TEMPL
            });
            assert_eq!(s.rtte.srtt, 600);
            assert_eq!(s.timer, Timer::Retransmit {
                expires_at: Instant::from_millis(deadline),
            });
            recv_nothing!(s, time deadline - 1);
            recv!(s, time deadline, Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 7,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"012345",
                ..RECV_TEMPL
            }));
        }
    }

    #[test]
    fn retransmitted_segment_does_not_sample_rtt() {
        for state in [State::SynSent, State::SynReceived, State::Established, State::FinWait1] {
            let mut s = match state {
                State::SynSent => socket_syn_sent(),
                State::SynReceived => socket_syn_received(),
                _ => socket_established(),
            };
            if state == State::Established {
                s.send_slice(b"abcdef").unwrap();
            } else if state == State::FinWait1 {
                s.close();
            }
            let mut ack = LOCAL_SEQ;
            recv(&mut s, Instant::ZERO, |result| {
                let repr = result.unwrap();
                ack = repr.seq_number + repr.segment_len();
            });
            assert!(s.rtte.timestamp().is_some());
            recv(&mut s, Instant::from_millis(1000), |result| {
                let repr = result.unwrap();
                assert_eq!(repr.seq_number + repr.segment_len(), ack);
            });
            assert_eq!(s.rtte.timestamp(), None);
            send!(s, time 1100, TcpRepr {
                control: if state == State::SynSent { TcpControl::Syn } else { TcpControl::None },
                seq_number: if state == State::SynSent { REMOTE_SEQ } else { REMOTE_SEQ + 1 },
                ack_number: Some(ack),
                ..SEND_TEMPL
            });
            assert!(!s.rtte.have_measurement, "{state}");
        }
    }

    #[test]
    fn rto_backoff_resets_on_snd_una_progress() {
        for state in [State::SynSent, State::SynReceived, State::Established, State::FinWait1] {
            let mut s = match state {
                State::SynSent => socket_syn_sent(),
                State::SynReceived => socket_syn_received(),
                _ => socket_established(),
            };
            s.set_rto(Duration::from_millis(1000));
            if state == State::Established {
                s.send_slice(b"abcdef").unwrap();
            } else if state == State::FinWait1 {
                s.close();
            }
            let mut ack = LOCAL_SEQ;
            for time in [0, 1000, 3000] {
                recv(&mut s, Instant::from_millis(time), |result| {
                    let repr = result.unwrap();
                    ack = repr.seq_number + repr.segment_len();
                });
            }
            assert_eq!(s.timer, Timer::Retransmit {
                expires_at: Instant::from_millis(7000),
            });
            if state == State::Established {
                for stale_ack in [LOCAL_SEQ, LOCAL_SEQ + 1] {
                    send!(s, time 3100, TcpRepr {
                        seq_number: REMOTE_SEQ + 1,
                        ack_number: Some(stale_ack),
                        window_len: 256,
                        ..SEND_TEMPL
                    });
                    assert_eq!(s.retransmission_timeout(), Duration::from_millis(4000));
                    assert_eq!(s.timer, Timer::Retransmit {
                        expires_at: Instant::from_millis(7000),
                    });
                }
                send!(s, time 3150, TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 4),
                    ..SEND_TEMPL
                });
                assert_eq!(s.local_seq_no, LOCAL_SEQ + 4);
                assert_eq!(s.rto_backoff, 0);
                assert_eq!(s.timer, Timer::Retransmit {
                    expires_at: Instant::from_millis(4150),
                });
            }
            send!(s, time 3200, TcpRepr {
                control: if state == State::SynSent { TcpControl::Syn } else { TcpControl::None },
                seq_number: if state == State::SynSent { REMOTE_SEQ } else { REMOTE_SEQ + 1 },
                ack_number: Some(ack),
                ..SEND_TEMPL
            });
            assert_eq!(s.local_seq_no, ack);
            assert_eq!(s.retransmission_timeout(), Duration::from_millis(1000), "{state}");
        }
    }

    #[test]
    fn fixed_rto_emit_failure_does_not_backoff_twice() {
        let mut s = socket_established();
        s.set_rto(Duration::from_millis(1000));
        s.send_slice(b"abcdef").unwrap();
        recv!(s, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"abcdef",
            ..RECV_TEMPL
        }));
        for time in [1000, 1100] {
            s.cx.set_now(Instant::from_millis(time));
            assert_eq!(s.socket.dispatch(&mut s.cx, |_, _, (_, repr)| {
                assert_eq!(repr.seq_number, LOCAL_SEQ + 1);
                assert_eq!(repr.payload, b"abcdef");
                Err(())
            }), Err(()));
            assert!(!s.timer.is_retransmit());
            assert_eq!(s.rtte.timestamp(), None);
            assert_eq!(s.retransmission_timeout(), Duration::from_millis(2000));
        }
        recv!(s, time 1200, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"abcdef",
            ..RECV_TEMPL
        }));
        assert_eq!(s.timer, Timer::Retransmit {
            expires_at: Instant::from_millis(3200),
        });
        recv_nothing!(s, time 3199);
        recv!(s, time 3200, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"abcdef",
            ..RECV_TEMPL
        }));
        assert_eq!(s.timer, Timer::Retransmit {
            expires_at: Instant::from_millis(7200),
        });
    }

    #[test]
    fn ack_delay_round_trips_every_value() {
        let mut s = socket();
        for delay in [
            Some(Duration::ZERO),
            Some(Duration::from_millis(10)),
            Some(MAX_RTO),
            None,
        ] {
            s.set_ack_delay(delay);
            assert_eq!(s.ack_delay(), delay);
        }
        assert_eq!(s.ack_delay_us, 0);
    }

    #[test]
    fn rto_at_cap_backoff_matches() {
        let mut s = socket();
        s.set_rto(MAX_RTO);
        for backoff in [0, 1, 26, 40] {
            s.rto_backoff = backoff;
            assert_eq!(s.retransmission_timeout(), Duration::from_micros(60_000_000));
        }
        s.set_rto(Duration::from_micros(1));
        for (backoff, expected_us) in [(0, 1), (1, 2), (26, 60_000_000), (40, 60_000_000)] {
            s.rto_backoff = backoff;
            assert_eq!(s.retransmission_timeout(), Duration::from_micros(expected_us));
        }
    }

    #[test]
    fn set_rto_panics_outside_range() {
        for rto in [Duration::ZERO, MAX_RTO + Duration::from_micros(1), Duration::MAX] {
            assert!(std::panic::catch_unwind(|| socket().set_rto(rto)).is_err());
        }
        for rto in [Duration::from_micros(1), MAX_RTO] {
            let mut s = socket();
            s.set_rto(rto);
            assert_eq!(Duration::from_micros(u64::from(s.rto_us)), rto);
        }
    }

    #[test]
    fn set_rto_applies_at_next_arm_and_survives_reconnect() {
        let mut s = socket_established();
        s.set_rto(Duration::from_millis(1000));
        s.send_slice(b"abcdef").unwrap();
        recv(&mut s, Instant::ZERO, |result| {
            assert_eq!(result.unwrap().payload, b"abcdef");
        });
        s.set_rto(Duration::from_micros(300_001));
        assert_eq!(s.timer, Timer::Retransmit {
            expires_at: Instant::from_millis(1000),
        });
        recv(&mut s, Instant::from_millis(1000), |result| {
            assert_eq!(result.unwrap().payload, b"abcdef");
        });
        assert_eq!(s.rto_backoff, 1);
        assert_eq!(s.timer, Timer::Retransmit {
            expires_at: Instant::from_micros(1_600_002),
        });
        send!(s, time 1100, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 7),
            ..SEND_TEMPL
        });
        s.close();
        recv(&mut s, Instant::from_millis(1200), |result| {
            assert_eq!(result.unwrap().control, TcpControl::Fin);
        });
        assert_eq!(s.timer, Timer::Retransmit {
            expires_at: Instant::from_micros(1_500_001),
        });
        s.reset();
        assert_eq!(s.rto_backoff, 0);
        s.listen(LOCAL_PORT).unwrap();
        send!(s, time 2000, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        });
        recv(&mut s, Instant::from_millis(2000), |result| {
            assert_eq!(result.unwrap().control, TcpControl::Syn);
        });
        assert_eq!(s.timer, Timer::Retransmit {
            expires_at: Instant::from_micros(2_300_001),
        });
        s.abort();
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END.port).unwrap();
        recv(&mut s, Instant::from_millis(3000), |result| {
            assert_eq!(result.unwrap().control, TcpControl::Syn);
        });
        assert_eq!(s.timer, Timer::Retransmit {
            expires_at: Instant::from_micros(3_300_001),
        });
        assert_eq!(Duration::from_micros(u64::from(s.rto_us)), Duration::from_micros(300_001));
    }

    #[test]
    fn fixed_rto_caps_and_discards_smoothed_rtt_after_three_expiries() {
        let mut s = socket_established();
        s.send_slice(b"abc").unwrap();
        recv(&mut s, Instant::ZERO, |result| {
            assert_eq!(result.unwrap().payload, b"abc");
        });
        send!(s, time 101, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 4),
            ..SEND_TEMPL
        });
        assert_eq!(s.rtte.srtt, 101);
        s.set_rto(Duration::from_micros(1));
        s.send_slice(b"def").unwrap();
        recv(&mut s, Instant::from_millis(200), |result| {
            assert_eq!(result.unwrap().payload, b"def");
        });
        let mut expires_at = Instant::from_micros(200_001);
        let delays = [
            2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768,
            65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608,
            16777216, 33554432, 60_000_000,
        ];
        for (index, delay) in delays.into_iter()
            .chain(core::iter::repeat_n(60_000_000, 54))
            .enumerate()
        {
            recv_nothing(&mut s, expires_at - Duration::from_micros(1));
            recv(&mut s, expires_at, |result| {
                let repr = result.unwrap();
                assert_eq!(repr.seq_number, LOCAL_SEQ + 4);
                assert_eq!(repr.payload, b"def");
            });
            expires_at += Duration::from_micros(delay);
            assert_eq!(s.timer, Timer::Retransmit { expires_at });
            assert_eq!(s.rto_backoff, (index + 1) as u32);
            assert_eq!(s.rtte.have_measurement, index < 2);
            assert_eq!(s.rtte.srtt, 101);
            assert_eq!(s.rtte.timestamp(), None);
        }
    }

    #[test]
    fn smoothed_rtt_clears_after_three_expiries() {
        let mut s = socket_established();
        s.send_slice(b"a").unwrap();
        recv(&mut s, Instant::ZERO, |result| {
            assert_eq!(result.unwrap().payload, b"a");
        });
        send!(s, time 100, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 2),
            ..SEND_TEMPL
        });
        assert!(s.rtte.have_measurement);
        assert_eq!(s.rtte.srtt, 100);
        s.send_slice(b"b").unwrap();
        for at in [200, 500, 1100] {
            recv(&mut s, Instant::from_millis(at), |result| {
                assert_eq!(result.unwrap().payload, b"b");
            });
            assert!(s.rtte.have_measurement);
        }
        send!(s, time 1200, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 3),
            ..SEND_TEMPL
        });
        s.send_slice(b"c").unwrap();
        recv(&mut s, Instant::from_millis(1200), |result| {
            assert_eq!(result.unwrap().payload, b"c");
        });
        send!(s, time 1400, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 4),
            ..SEND_TEMPL
        });
        assert_eq!(s.rtte.srtt, 113);
        s.send_slice(b"d").unwrap();
        for (index, at) in [1500, 1800, 2400, 3600].into_iter().enumerate() {
            recv(&mut s, Instant::from_millis(at), |result| {
                assert_eq!(result.unwrap().payload, b"d");
            });
            assert_eq!(s.rtte.have_measurement, index < 3);
            if index > 0 {
                assert_eq!(s.rtte.timestamp(), None);
            }
        }
        send!(s, time 3700, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 5),
            ..SEND_TEMPL
        });
        assert!(!s.rtte.have_measurement);
        s.send_slice(b"e").unwrap();
        recv(&mut s, Instant::from_millis(3800), |result| {
            assert_eq!(result.unwrap().payload, b"e");
        });
        send!(s, time 3850, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 6),
            ..SEND_TEMPL
        });
        assert!(s.rtte.have_measurement);
        assert_eq!(s.rtte.srtt, 50);
    }

    #[test]
    fn socket_always_uses_cubic() {
        for (configured, initial, threshold) in [(None, 1_048_576, 734_003), (Some(12000), 12000, 8400)] {
            let mut s = socket_with_buffer_sizes(2_097_152, 8192);
            if let Some(bytes) = configured {
                s.set_initial_window(bytes);
            }
            for _ in 0..2 {
                s.socket.listen(LISTEN_END).unwrap();
                assert_eq!(s.congestion_controller.window(), 2048);
                send!(s, TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: REMOTE_SEQ,
                    ack_number: None,
                    window_len: 32768,
                    window_scale: Some(6),
                    max_seg_size: Some(BASE_MSS),
                    ..SEND_TEMPL
                });
                recv(&mut s, Instant::ZERO, |result| {
                    assert_eq!(result.unwrap().control, TcpControl::Syn);
                });
                let ack = TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    window_len: 32768,
                    ..SEND_TEMPL
                };
                send!(s, ack);
                assert_eq!(s.state(), State::Established);
                assert_eq!(s.congestion_controller.window(), initial);
                assert_eq!(s.send_slice(&vec![0; 2_097_152]), Ok(2_097_152));
                assert_eq!(flight(&mut s, 0), initial);
                for _ in 0..3 {
                    send!(s, ack);
                }
                recv(&mut s, Instant::ZERO, |result| {
                    let repr = result.unwrap();
                    assert_eq!(repr.seq_number, LOCAL_SEQ + 1);
                    assert_eq!(repr.payload.len(), BASE_MSS as usize);
                });
                assert_eq!(
                    s.congestion_controller.window(),
                    threshold + 3 * BASE_MSS as usize
                );
                send!(s, TcpRepr {
                    ack_number: Some(LOCAL_SEQ + 1 + initial),
                    ..ack
                });
                assert_eq!(s.congestion_controller.window(), threshold);
                send!(s, TcpRepr {
                    control: TcpControl::Rst,
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: None,
                    ..SEND_TEMPL
                });
                assert_eq!(s.state(), State::Closed);
            }
        }
    }

    // =========================================================================================//
    // Timestamp removal and peer probe tests
    // =========================================================================================//

    #[test]
    fn active_and_passive_open_never_offer_timestamps() {
        for passive in [false, true] {
            let mut s = socket();
            for _ in 0..2 {
                if passive {
                    s.listen(LOCAL_PORT).unwrap();
                    send!(s, TcpRepr {
                        control: TcpControl::Syn,
                        seq_number: REMOTE_SEQ,
                        ack_number: None,
                        timestamp: Some(TcpTimestampRepr::new(500, 0)),
                        ..SEND_TEMPL
                    });
                } else {
                    s.socket
                .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
                .unwrap();
                }
                let mut local_seq = TcpSeqNumber(0);
                recv(&mut s, Instant::ZERO, |result| {
                    let syn = result.unwrap();
                    assert_eq!(syn.control, TcpControl::Syn);
                    assert_eq!(syn.timestamp, None);
                    assert_eq!(syn.ack_number, passive.then_some(REMOTE_SEQ + 1));
                    local_seq = syn.seq_number + 1;
                });
                send!(s, TcpRepr {
                    control: if passive { TcpControl::None } else { TcpControl::Syn },
                    seq_number: REMOTE_SEQ + usize::from(passive),
                    ack_number: Some(local_seq),
                    timestamp: Some(TcpTimestampRepr::new(500, 1)),
                    ..SEND_TEMPL
                });
                assert_eq!(s.state(), State::Established);
                if !passive {
                    recv(&mut s, Instant::ZERO, |result| {
                        assert_eq!(result.unwrap().timestamp, None);
                    });
                }
                s.abort();
            }
        }
    }

    #[test]
    fn peer_timestamp_offer_is_ignored() {
        let mut s = socket_listen();
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            timestamp: Some(TcpTimestampRepr::new(500, 0)),
            ..SEND_TEMPL
        });
        recv(&mut s, Instant::ZERO, |result| {
            let syn_ack = result.unwrap();
            assert_eq!(syn_ack.control, TcpControl::Syn);
            assert_eq!(syn_ack.timestamp, None);
        });
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            timestamp: Some(TcpTimestampRepr::new(500, 1)),
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::Established);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            timestamp: Some(TcpTimestampRepr::new(400, 1)),
            payload: b"abc",
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 4),
            window_len: 64,
            ..RECV_TEMPL
        }]);
        let bytes = drain_bytes(&mut s);
        assert_eq!(bytes.len(), 3);
        assert_eq!(&bytes, b"abc");
        s.close();
        recv(&mut s, Instant::ZERO, |result| {
            let fin = result.unwrap();
            assert_eq!(fin.control, TcpControl::Fin);
            assert_eq!(fin.timestamp, None);
        });
    }

    #[test]
    fn full_segment_payload_is_mtu_minus_40() {
        for remote_mss in [1460, 9999, 512] {
            let mut s = socket_established_with_buffer_sizes(1460, 64);
            assert_eq!(s.cx.ip_mtu(), 1500);
            s.remote_mss = remote_mss;
            s.socket.update_rx_mbuf_budget(&s.cx);
            s.remote_win_len = 4096;
            s.send_slice(&[0; 1460]).unwrap();
            recv(&mut s, Instant::ZERO, |result| {
                let data = result.unwrap();
                assert_eq!(data.payload.len(), usize::from(remote_mss).min(1460));
                assert_eq!(data.header_len(), 20);
                assert_eq!(data.timestamp, None);
                assert_eq!(data.seq_number, LOCAL_SEQ + 1);
            });
        }
    }

    #[test]
    fn peer_probe_ack_survives_timestamp_removal() {
        for payload in [&b""[..], &b"x"[..]] {
            let mut s = socket_established();
            send!(s, TcpRepr {
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                timestamp: Some(TcpTimestampRepr::new(500, 1)),
                payload,
                ..SEND_TEMPL
            }, Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }));
            assert_eq!(s.recv_queue(), 0);
            assert_eq!(s.state(), State::Established);
        }
    }

    #[test]
    fn test_syn_received_bad_ack_precedes_window_check() {
        let mut s = socket_listen();
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(100),
            ack_number: None,
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(TcpSeqNumber(101)),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }]);
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.remote_win_shift, 0);

        send!(s, time 1000, TcpRepr {
            seq_number: TcpSeqNumber(100),
            ack_number: Some(LOCAL_SEQ),
            payload: b"x",
            ..SEND_TEMPL
        }, Some(TcpRepr {
            control: TcpControl::Rst,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            window_len: 0,
            ..RECV_TEMPL
        }));
        assert_eq!(s.state(), State::SynReceived);

        send!(s, time 2000, TcpRepr {
            seq_number: TcpSeqNumber(101),
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::Established);
    }

    // =========================================================================================//
    // Tests for source IP address change.
    // =========================================================================================//

    #[test]
    fn test_established_close_on_src_ip_change() {
        let mut s = socket_established();

        // Verify socket is working normally
        s.send_slice(b"abc").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abc"[..],
                ..RECV_TEMPL
            }]
        );

        // Simulate interface IP change - remove the socket's source IP
        // and add a different one.
        let mut new_addrs = heapless::Vec::<IpCidr, IFACE_MAX_ADDR_COUNT>::new();
        new_addrs.push(IpCidr::new(OTHER_ADDR.into(), 24)).unwrap();
        s.cx.set_ip_addrs(new_addrs);

        // The socket's source IP is no longer on the interface.
        // When dispatch() runs, it should detect this and reset the socket
        // silently (no RST sent, since that would use the invalid source IP).
        s.send_slice(b"def").unwrap();
        recv_nothing!(s);
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn send_into_zero_window_arms_probe_from_current_dispatch_time() {
        let mut s = socket_established();
        send!(s, time 100, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        });
        recv_nothing!(s, time 10_000);
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Ingress);
        assert_eq!(s.send_slice(b"abc"), Ok(3));
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
        recv_nothing!(s, time 20_000);
        assert_eq!(s.timer, Timer::ZeroWindowProbe {
            expires_at: Instant::from_millis(20_300),
            backoff_applied: false,
        });
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Time(Instant::from_millis(20_300)));
        recv_nothing!(s, time 20_299);
        recv!(s, time 20_300, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"a",
            ..RECV_TEMPL
        }]);
        assert_eq!(s.send_queue(), 3);
        assert_eq!(s.state(), State::Established);
    }

    #[test]
    fn idle_established_socket_has_no_liveness_deadline() {
        let mut s = socket_established();
        for millis in [0, 300, 60_000, 3_600_000] {
            s.cx.set_now(Instant::from_millis(millis));
            assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Ingress);
            assert_eq!(s.state(), State::Established);
        }
    }

    #[test]
    fn silent_peer_retries_beyond_fifteen_expiries() {
        let mut s = socket_established();
        assert_eq!(s.send_slice(b"x"), Ok(1));
        let expected = TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"x",
            ..RECV_TEMPL
        };
        recv!(s, time 0, [expected.clone()]);
        let mut now = Instant::ZERO;
        for expiry in 1..=20 {
            let delay = s.retransmission_timeout();
            assert!(delay <= Duration::from_secs(60));
            now += delay;
            recv_nothing(&mut s, now - Duration::from_micros(1));
            recv(&mut s, now, |result| {
                let mut actual = result.unwrap();
                actual.control = actual.control.quash_psh();
                assert_eq!(actual, expected);
            });
            assert_eq!(s.rto_backoff, expiry);
            assert_eq!(s.timer.poll_at(), PollAt::Time(now + s.retransmission_timeout()));
            assert_eq!(s.state(), State::Established);
            assert_eq!(s.send_queue(), 1);
            if expiry >= 8 {
                assert_eq!(s.retransmission_timeout(), Duration::from_secs(60));
            }
        }
    }

    #[test]
    fn time_wait_close_deadline_is_retained() {
        let mut s = socket_established();
        s.close();
        recv!(s, time 1000, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]);
        send!(s, time 1000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 2),
            ..SEND_TEMPL
        });
        recv!(s, time 1000, [TcpRepr {
            seq_number: LOCAL_SEQ + 2,
            ack_number: Some(REMOTE_SEQ + 2),
            ..RECV_TEMPL
        }]);
        assert_eq!(s.state(), State::TimeWait);
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Time(Instant::from_millis(11_000)));
        recv_nothing!(s, time 10_999);
        assert_eq!(s.state(), State::TimeWait);
        recv_nothing!(s, time 11_000);
        assert_eq!(s.state(), State::Closed);
        assert_eq!(s.tuple, None);
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Ingress);
    }

    #[test]
    fn idle_socket_never_sends_own_keep_alive() {
        let mut s = socket_established();
        for millis in [0, 100, 300, 60_000, 3_600_000] {
            recv_nothing!(s, time millis);
            assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Ingress);
            assert_eq!(s.state(), State::Established);
            assert_eq!(s.remote_max_seq, LOCAL_SEQ + 1);
        }
    }

    #[test]
    fn test_responds_to_one_byte_peer_keep_alive() {
        let mut s = socket_established();
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &[0],
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.recv_queue(), 0);
        assert_eq!(s.state(), State::Established);
    }

    #[test]
    fn peer_keep_alive_and_zero_window_probe_are_acked() {
        for zero_window in [false, true] {
            let (mut s, _frames) = if zero_window {
                socket_with_held_rx_frames(64, REMOTE_SEQ + 1, 5)
            } else {
                (socket_established(), Vec::new())
            };
            let next = if zero_window {
                send!(s, TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &[7; 64],
                    ..SEND_TEMPL
                });
                recv!(s, [TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 65),
                    window_len: 0,
                    ..RECV_TEMPL
                }]);
                REMOTE_SEQ + 65
            } else {
                REMOTE_SEQ + 1
            };
            assert_eq!(s.recv_room(), if zero_window { 0 } else { 64 });
            let window_len = if zero_window { 0 } else { 64 };
            let probes: &[&[u8]] = if zero_window { &[b"\x00"] } else { &[b"", b"\x00"] };
            for &payload in probes {
                send!(s, time 100, TcpRepr {
                    seq_number: if zero_window { next } else { next - 1 },
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload,
                    ..SEND_TEMPL
                }, Some(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(next),
                    window_len,
                    ..RECV_TEMPL
                }));
                assert_eq!(s.recv_queue(), if zero_window { 64 } else { 0 });
                assert_eq!(s.remote_seq_no + s.recv_queue(), next);
                assert_eq!(s.state(), State::Established);
                recv_nothing!(s, time 100);
            }
        }
    }
}
