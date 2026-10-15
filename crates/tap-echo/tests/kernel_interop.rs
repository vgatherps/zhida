//! A Linux kernel TCP client talks to Zhida's EchoServer through kernel
//! socket -> kernel tap netdev -> net_tap PMD -> Port -> Stack, and back. An
//! AF_PACKET capture on the netdev records each connection's segments. Needs
//! CAP_NET_ADMIN, CAP_NET_RAW and /dev/net/tun; sets an IPv4 address and the
//! MTU on the test netdev in the caller's network namespace. The loss tests
//! also run `tc` (iproute2) to add and remove filters on that
//! netdev. The gateway tests run Zhida as the client of a kernel listener
//! outside its subnet, adding that address to the netdev with `ip` (iproute2).

use std::ffi::CStr;
use std::fs;
use std::io::{self, Read, Write};
use std::mem;
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::panic::{self, panic_any, resume_unwind};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, ScopedJoinHandle};
use std::time::{Duration, Instant, SystemTime};

use zhida_test_kit::tap::{ifindex, TapVdev};
use zhida_test_kit::wire::{in_use, pool_exists};
use zhida_test_kit::with_eal;
use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::socket::tcp::{self, State};
use dpdk_smoltcp::smoltcp::time::Instant as StackInstant;
use dpdk_smoltcp::smoltcp::wire::{EthernetAddress, Ipv4Address, Ipv4Cidr};
use dpdk_smoltcp::{
    rx_pool_count, rx_reserve, Eal, Offloads, Port, PortConfig, Stack, StackConfig,
    DEFAULT_NEIGHBOR_CAPACITY,
};
use tap_echo::{serve, EchoServer};
use zhida_buffer::PoolConfig;
use zhida_dpdk_sys::{rte_eth_conf, rte_eth_dev_conf_get, RTE_PKTMBUF_HEADROOM};

const VDEV: &CStr = c"net_tap_kern";
const IFACE: &CStr = c"cdtap_kern";
const RX_POOL: &CStr = c"kern_rx";
const TX_POOL: &CStr = c"kern_tx";

const KERNEL_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
const ZHIDA_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const ECHO_PORT: u16 = 8080;
const ECHO_BUFFER: usize = 128 * 1024;

const TRANSFER: usize = 1 << 20;
const MAX_CHUNK: usize = 64 * 1024;
const SEED: u64 = 0x9e37_79b9_7f4a_7c15;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const DEADLINE: Duration = Duration::from_secs(30);

const ACK_LOSS_TRANSFER: usize = 4 << 20;
/// After filter installation the client may write all but the last 2 MiB;
/// those bytes stay held until the loss thread releases the full transfer.
/// This exceeds the kernel's doubled 256 KiB receive buffer plus Zhida's
/// echo in flight, so data remains for the second phase and writing has not
/// finished while the keepalive test holds its writer, however fast Zhida
/// echoes.
const ACK_LOSS_RESERVE: usize = 2 << 20;
/// Initial write limit and echo count that triggers filter installation.
/// The writer cannot pass this count until installation returns.
const ACK_LOSS_AFTER: usize = 256 * 1024;
/// Filter installation raises the write limit to the transfer minus its
/// reserve. Pure ACKs are dropped first for `ACK_LOSS_STREAMING`, while the
/// client still reads and writes, so both directions carry data under the loss, and
/// then for two phases of `ACK_LOSS_PHASE`. In the first phase the client
/// stops writing, so once its queued data is sent the kernel acknowledges
/// Zhida's echo with pure ACKs alone; 1.5 s is longer than
/// `ZHIDA_RTO`, so Zhida times out. In the second the client writes
/// again with its reserve released but stops reading, so once the kernel's
/// receive buffer is full Zhida can send nothing and acknowledges the
/// kernel's data with pure ACKs alone; 1.5 s is longer than Linux's minimum
/// RTO, 200 ms (TCP_RTO_MIN), so Linux times out.
const ACK_LOSS_PHASE: Duration = Duration::from_millis(1500);
/// The base RTO of Zhida's sockets unless a test sets another
/// (`tcp::Socket::set_rto`; default 300 ms). RTT samples do not change it;
/// each expiry doubles it, up to 60 s, until SND.UNA advances
/// (`retransmission_timeout`). Zero-window probes use the same RTO and
/// backoff.
const ZHIDA_RTO: Duration = Duration::from_millis(300);
/// Allowance when comparing capture times against an RTO. smoltcp times the
/// RTO on turn time, the capture stamps each frame when the PMD writes it,
/// and the delay between the two varies per turn on a shared CPU, so a resend
/// exactly one RTO later can be captured slightly under one RTO after the
/// original. The elapsed-time check is therefore supporting evidence, not an
/// exact minimum; see `zhida_timeout_retransmissions` for why fast
/// retransmit cannot fire in the loss window at all.
const CAPTURE_SLACK: Duration = Duration::from_millis(100);
/// Long enough for both directions to send data on a single shared CPU once
/// the `tc` processes that added the filters are done.
const ACK_LOSS_STREAMING: Duration = Duration::from_millis(50);
/// Filters removed to the last echoed byte read. Lossless, 4 MiB echoes in
/// well under a second, and the loss window lasts 3.05 s. Zhida's RTO
/// enters the window at `ZHIDA_RTO`, 300 ms (nothing expired before it),
/// and doubles only on expiry, retransmission or zero-window probe alike: the
/// first three expiries are at least 0.3, 0.6 and 1.2 s apart, 2.1 s
/// together, and a fourth would come at least 2.4 s after the third, so at
/// most three fall inside the window and the RTO is at most 2.4 s when the
/// filters go. Zhida's next retransmission or probe, carrying its ACK, is
/// then due within 2.4 s of removal and is no longer dropped; Linux's RTO
/// starts at 200 ms. In practice the window update the kernel sends once the
/// client reads again ends the loss sooner. 10 s covers that and the rest of
/// the echo with room for a shared CPU.
const ACK_LOSS_RECOVERY: Duration = Duration::from_secs(10);
/// The kernel client's budget for the whole echo, well past the window and
/// `ACK_LOSS_RECOVERY`, so a slow recovery fails on that bound with the
/// capture record printed, not here.
const ACK_LOSS_ECHO_DEADLINE: Duration = Duration::from_secs(50);
/// serve_client's deadline: the echo budget, then time for the close, or for
/// the RST a failing client sends, to reach Zhida.
const ACK_LOSS_DEADLINE: Duration = Duration::from_secs(60);
/// Socket timeout: how often the client's threads check the echo deadline.
const POLL: Duration = Duration::from_millis(100);
/// How often the client's paused threads check whether to resume.
const PAUSED_POLL: Duration = Duration::from_millis(1);

// tcpi_options bits from linux/tcp.h.
const TCPI_OPT_TIMESTAMPS: u8 = 1;
const TCPI_OPT_SACK: u8 = 2;
const TCPI_OPT_WSCALE: u8 = 4;

/// IP MTU and the data room after headroom of both pools.
#[derive(Debug, Clone, Copy)]
struct PortSize {
    mtu: u16,
    room: u16,
}

const STANDARD: PortSize = PortSize {
    mtu: 1500,
    room: 2048,
};
/// 9216 is 9000 + 26 (Ethernet header, FCS and two VLAN tags) rounded up to
/// a multiple of 1 KiB, so a NIC that sizes RX buffers in 1 KiB steps still
/// receives the whole frame in one buffer.
const JUMBO: PortSize = PortSize {
    mtu: 9000,
    room: 9216,
};

fn port_config(
    port_id: u16,
    size: PortSize,
    recv_capacities: impl IntoIterator<Item = usize>,
) -> PortConfig<'static> {
    let pool = |name, count| PoolConfig {
        name,
        count,
        cache_size: 8,
        data_room_size: RTE_PKTMBUF_HEADROOM as u16 + size.room,
        socket_id: -1,
    };
    PortConfig {
        port_id,
        mtu: size.mtu,
        rx_descriptors: 16,
        tx_descriptors: 16,
        rx_burst: 32,
        tx_burst: 32,
        queue_socket: -1,
        rx_pool: pool(
            RX_POOL,
            rx_pool_count(rx_reserve(16, 32, 8), size.mtu, recv_capacities),
        ),
        tx_pool: pool(TX_POOL, 127),
        offloads: Offloads::default(),
    }
}

fn stack_config() -> StackConfig<'static> {
    let [a, b, c, d] = ZHIDA_ADDR.octets();
    StackConfig {
        max_udp_sockets: 0,
        ethernet: EthernetAddress([0x02, 0, 0, 0, 0, 0x01]),
        ipv4: Ipv4Cidr::new(Ipv4Address::new(a, b, c, d), 24),
        gateway: None,
        paths: &[],
        random_seed: 1,
        neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
        segments_per_visit: 1,
        max_sockets: 2,
        rx_staging: 32,
        tx_pending: 32,
    }
}

/// Open a Port on the tap vdev.
fn open(eal: &Eal, tap: &TapVdev, size: PortSize) -> Port {
    unsafe { Port::open(eal, port_config(tap.port_id(), size, [ZHIDA_BUFFER])) }.unwrap()
}

/// After `open` with `size`: the ethdev runs at `size.mtu`, the kernel side
/// is still at the 1500 net_tap created it with, and is then set to match.
fn sync_kernel_mtu(tap: &TapVdev, size: PortSize) {
    // SAFETY: rte_eth_conf is plain data; all-zero bytes are a valid value.
    let mut conf: rte_eth_conf = unsafe { mem::zeroed() };
    // SAFETY: the port is open on this EAL thread; `conf` is writable.
    assert_eq!(unsafe { rte_eth_dev_conf_get(tap.port_id(), &mut conf) }, 0);
    assert_eq!(conf.rxmode.mtu, u32::from(size.mtu));
    assert_eq!(tap.kernel_mtu(), 1500);
    tap.set_kernel_mtu(u32::from(size.mtu));
    assert_eq!(tap.kernel_mtu(), u32::from(size.mtu));
}

/// Close the Port, remove the vdev, and check the netdev and both pools are gone.
fn close(port: Port, tap: TapVdev) {
    port.try_close().unwrap();
    tap.close();
    for name in [RX_POOL, TX_POOL] {
        assert!(!pool_exists(name));
    }
}

/// Give the kernel side of the tap netdev `KERNEL_ADDR`/24.
fn set_kernel_address() {
    // SAFETY: socket(2) takes no pointers; the result is checked before use.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0, "socket(AF_INET): {}", io::Error::last_os_error());
    // SAFETY: `fd` is a freshly opened descriptor nothing else owns.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    set_ipv4(&socket, libc::SIOCSIFADDR, "SIOCSIFADDR", KERNEL_ADDR);
    set_ipv4(&socket, libc::SIOCSIFNETMASK, "SIOCSIFNETMASK", NETMASK);
}

fn set_ipv4(socket: &OwnedFd, request: libc::Ioctl, name: &str, addr: Ipv4Addr) {
    // SAFETY: ifreq is plain data; all-zero bytes are a valid value.
    let mut ifreq: libc::ifreq = unsafe { mem::zeroed() };
    let iface = IFACE.to_bytes();
    assert!(iface.len() < ifreq.ifr_name.len());
    for (dst, &src) in ifreq.ifr_name.iter_mut().zip(iface) {
        *dst = src as libc::c_char;
    }
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(addr).to_be(),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: sockaddr_in and sockaddr are both 16-byte plain-data structs; the
    // kernel reads ifru_addr as sockaddr_in for AF_INET.
    ifreq.ifr_ifru.ifru_addr = unsafe { mem::transmute::<libc::sockaddr_in, libc::sockaddr>(sin) };
    // SAFETY: both requests take a `struct ifreq *`; `ifreq` is valid and
    // writable for the call.
    let rc = unsafe { libc::ioctl(socket.as_raw_fd(), request, &mut ifreq) };
    assert_eq!(rc, 0, "{name}: {}", io::Error::last_os_error());
}

/// TCP options and parameters the kernel client negotiated with Zhida.
#[derive(Debug)]
struct Negotiated {
    options: u8,
    /// Window shift Zhida advertised in its SYN-ACK.
    snd_wscale: u8,
    /// Window shift the kernel advertised.
    rcv_wscale: u8,
    snd_mss: u32,
    /// The kernel's own MSS, less the timestamp option once negotiated.
    advmss: u32,
}

fn negotiated(stream: &TcpStream) -> Negotiated {
    // SAFETY: tcp_info is plain integers; all-zero bytes are a valid value.
    let mut info: libc::tcp_info = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    // SAFETY: the descriptor is an open TCP socket; `info` and `len` are a
    // writable tcp_info and its size.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&mut info as *mut libc::tcp_info).cast(),
            &mut len,
        )
    };
    assert_eq!(rc, 0, "TCP_INFO: {}", io::Error::last_os_error());
    let end = mem::offset_of!(libc::tcp_info, tcpi_advmss) + mem::size_of::<u32>();
    assert!(len as usize >= end);
    // Kernel bitfields `tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4`; the first
    // is the low nibble on little-endian targets.
    const _: () = assert!(cfg!(target_endian = "little"));
    Negotiated {
        options: info.tcpi_options,
        snd_wscale: info.tcpi_snd_rcv_wscale & 0x0f,
        rcv_wscale: info.tcpi_snd_rcv_wscale >> 4,
        snd_mss: info.tcpi_snd_mss,
        advmss: info.tcpi_advmss,
    }
}

/// Deterministic xorshift bytes.
fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// Write sizes 1..=MAX_CHUNK in a fixed pseudo-random sequence.
fn chunk(call: usize) -> usize {
    call.wrapping_mul(7919) % MAX_CHUNK + 1
}

/// The Linux defaults the negotiation assertion depends on are on in this
/// network namespace, so the client's SYN offers timestamps, SACK and window
/// scaling.
fn assert_linux_offers_tcp_options() {
    for name in ["tcp_timestamps", "tcp_sack", "tcp_window_scaling"] {
        let path = format!("/proc/sys/net/ipv4/{name}");
        let text = fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
        let value: u32 = text.trim().parse().unwrap();
        assert_ne!(value, 0, "{path} is 0: the client would not offer it");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    ToZhida,
    ToKernel,
}

// TCP header flag bits.
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

/// Header fields of one TCP segment between `KERNEL_ADDR` and
/// `ZHIDA_ADDR:ECHO_PORT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Segment {
    direction: Direction,
    kernel_port: u16,
    flags: u8,
    seq: u32,
    ack: u32,
    /// Payload bytes, from the IP total length.
    len: u32,
    /// The MSS option, if the captured options hold a well-formed one.
    mss: Option<u16>,
    /// Whether the captured options hold a well-formed timestamp option.
    timestamps: bool,
}

/// The segment in one captured IPv4 packet if it travels between
/// `KERNEL_ADDR` and `ZHIDA_ADDR:ECHO_PORT`. `pkttype` is the AF_PACKET
/// `sll_pkttype`: PACKET_OUTGOING for a packet the kernel sent, PACKET_HOST
/// for one it received. `ip` starts at the IP header and may be cut off after
/// the fixed TCP header; options cut off or malformed give `mss` None and
/// `timestamps` false.
fn segment(pkttype: u8, ip: &[u8]) -> Option<Segment> {
    let direction = match pkttype {
        libc::PACKET_OUTGOING => Direction::ToZhida,
        libc::PACKET_HOST => Direction::ToKernel,
        _ => return None,
    };
    if ip.len() < 20 || ip[0] >> 4 != 4 || i32::from(ip[9]) != libc::IPPROTO_TCP {
        return None;
    }
    let ip_header = usize::from(ip[0] & 0x0f) * 4;
    let tcp = ip.get(ip_header..ip_header + 20)?;
    let address = |at: usize| Ipv4Addr::new(ip[at], ip[at + 1], ip[at + 2], ip[at + 3]);
    let port = |at: usize| u16::from_be_bytes([tcp[at], tcp[at + 1]]);
    let word = |at: usize| u32::from_be_bytes([tcp[at], tcp[at + 1], tcp[at + 2], tcp[at + 3]]);
    let (source, destination) = ((address(12), port(0)), (address(16), port(2)));
    let (kernel, zhida) = match direction {
        Direction::ToZhida => (source, destination),
        Direction::ToKernel => (destination, source),
    };
    if kernel.0 != KERNEL_ADDR || zhida != (ZHIDA_ADDR, ECHO_PORT) {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    let tcp_header = usize::from(tcp[12] >> 4) * 4;
    let len = total
        .checked_sub(ip_header + tcp_header)
        .expect("IP total length covers both headers");
    let options_end = (ip_header + tcp_header).min(ip.len());
    let options = ip.get(ip_header + 20..options_end).unwrap_or(&[]);
    Some(Segment {
        direction,
        kernel_port: kernel.1,
        flags: tcp[13],
        seq: word(4),
        ack: word(8),
        len: u32::try_from(len).unwrap(),
        mss: mss_option(options),
        timestamps: has_timestamps(options),
    })
}

/// The option of `wanted` kind in captured TCP `options`, with its kind and
/// length bytes. None when absent, or when it or an option before it is
/// malformed or cut off.
fn find_option(mut options: &[u8], wanted: u8) -> Option<&[u8]> {
    while let [kind, rest @ ..] = options {
        match kind {
            // End of option list.
            0 => return None,
            // No-operation.
            1 => options = rest,
            _ => {
                let len = usize::from(*rest.first()?);
                if len < 2 {
                    return None;
                }
                let option = options.get(..len)?;
                if *kind == wanted {
                    return Some(option);
                }
                options = &options[len..];
            }
        }
    }
    None
}

/// The MSS option (kind 2, length 4) in captured TCP `options`.
fn mss_option(options: &[u8]) -> Option<u16> {
    let option = find_option(options, 2)?;
    (option.len() == 4).then(|| u16::from_be_bytes([option[2], option[3]]))
}

/// Whether captured TCP `options` hold a timestamp option (kind 8, length 10).
fn has_timestamps(options: &[u8]) -> bool {
    find_option(options, 8).is_some_and(|option| option.len() == 10)
}

/// A captured segment and the time the kernel stamped its packet.
#[derive(Debug, Clone, Copy)]
struct Captured {
    at: SystemTime,
    segment: Segment,
}

/// One packet `Capture::receive` returned.
struct Received {
    /// AF_PACKET `sll_pkttype`.
    pkttype: u8,
    /// AF_PACKET `sll_protocol`, network byte order.
    protocol: u16,
    /// Bytes of it in the buffer.
    length: usize,
    at: SystemTime,
}

/// The SCM_TIMESTAMPNS time `recvmsg` returned with `message`.
fn timestamp(message: &libc::msghdr) -> SystemTime {
    // SAFETY: `message` came back from recvmsg with its control buffer intact;
    // CMSG_FIRSTHDR and CMSG_NXTHDR return null or a header inside it.
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        // SAFETY: `header` is non-null and inside the control buffer.
        let (level, kind) = unsafe { ((*header).cmsg_level, (*header).cmsg_type) };
        if level == libc::SOL_SOCKET && kind == libc::SCM_TIMESTAMPNS {
            // SAFETY: an SCM_TIMESTAMPNS payload is a timespec, not
            // necessarily aligned.
            let time = unsafe {
                libc::CMSG_DATA(header)
                    .cast::<libc::timespec>()
                    .read_unaligned()
            };
            let since_epoch = Duration::new(
                u64::try_from(time.tv_sec).unwrap(),
                u32::try_from(time.tv_nsec).unwrap(),
            );
            return SystemTime::UNIX_EPOCH + since_epoch;
        }
        // SAFETY: as for CMSG_FIRSTHDR.
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
    panic!("captured packet without SCM_TIMESTAMPNS");
}

fn segments(captured: &[Captured]) -> Vec<Segment> {
    captured.iter().map(|c| c.segment).collect()
}

#[derive(Debug, PartialEq, Eq)]
enum Close {
    /// A FIN from each side, the kernel acknowledged Zhida's FIN, no RST.
    Clean,
    /// The first RST captured, by direction.
    Reset(Direction),
    /// No RST, but a FIN or the kernel's ACK of Zhida's FIN is missing.
    Incomplete {
        kernel_fin: bool,
        zhida_fin: bool,
        zhida_fin_acked: bool,
    },
}

/// How the connection whose segments these are, in capture order, closed.
/// Only a kernel ACK captured after Zhida's first FIN acknowledges it.
fn close_kind(segments: &[Segment]) -> Close {
    if let Some(reset) = segments.iter().find(|s| s.flags & RST != 0) {
        return Close::Reset(reset.direction);
    }
    let fin = |direction| {
        segments
            .iter()
            .position(|s| s.direction == direction && s.flags & FIN != 0)
    };
    let kernel_fin = fin(Direction::ToZhida).is_some();
    let zhida_fin = fin(Direction::ToKernel);
    let zhida_fin_acked = zhida_fin.is_some_and(|at| {
        let fin = segments[at];
        let after_fin = fin.seq.wrapping_add(fin.len).wrapping_add(1);
        segments[at + 1..].iter().any(|s| {
            s.direction == Direction::ToZhida && s.flags & ACK != 0 && s.ack == after_fin
        })
    });
    if kernel_fin && zhida_fin_acked {
        Close::Clean
    } else {
        Close::Incomplete {
            kernel_fin,
            zhida_fin: zhida_fin.is_some(),
            zhida_fin_acked,
        }
    }
}

/// setsockopt(2) of `level` `option` (`name` in the failure message) to
/// `value`, a plain-data option value; failure fails the test.
fn set_socket_option<T>(
    fd: &impl AsRawFd,
    level: libc::c_int,
    option: libc::c_int,
    name: &str,
    value: &T,
) {
    // SAFETY: `value` points to a T and its size is passed.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            option,
            (value as *const T).cast(),
            mem::size_of::<T>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "{name}: {}", io::Error::last_os_error());
}

/// IPv4 and TCP headers, options included, fit in 120 bytes.
const CAPTURED_BYTES: usize = 120;
/// Forced past net.core.rmem_max (CAP_NET_ADMIN); the worker drains the
/// socket every serve iteration.
const CAPTURE_RCVBUF: libc::c_int = 16 << 20;

/// AF_PACKET socket bound to `IFACE` for every protocol, seeing packets in
/// both directions: `open` keeps IPv4 headers (datagram socket, no Ethernet
/// header), `frames` keeps every Ethernet frame's start (raw socket). Only
/// ETH_P_ALL sockets see packets the kernel sends (dev_queue_xmit_nit walks
/// ptype_all).
///
/// The segments that decide `Close::Clean` are in the record before serve can
/// stop. Serve stops only once Zhida's socket is back in Listen. EchoServer
/// closes only in CloseWait, which Zhida reached by processing the kernel's
/// FIN, so the socket then left LastAck by processing the kernel's ACK of
/// Zhida's FIN, or an RST. Zhida processes a segment only after the PMD
/// read it from the tap, and the kernel hands each frame it sends to packet
/// taps before the tap driver queues it for the PMD (dev_queue_xmit_nit
/// precedes ndo_start_xmit). The kernel sent that ACK only after its TCP took
/// in Zhida's FIN, which reached packet taps first (__netif_receive_skb_core
/// runs them before ip_rcv). This holds however late the kernel delivers.
///
/// Any other segment Zhida sent, such as a late RST, is in the record if the
/// PMD wrote it before serve stopped: a frame the PMD writes reaches packet
/// taps inside that write (tun_get_user -> tun_rx_batched -> netif_receive_skb;
/// net_tap sets no IFF_NAPI, tun's rx_batched starts at 0) unless receive
/// steering defers it, which `assert_no_receive_steering` rules out. The
/// record cannot include output Zhida's last turn left in tx_pending, which
/// never reaches the wire, or anything the kernel sends after the final drain.
struct Capture {
    fd: OwnedFd,
}

impl Capture {
    fn open() -> Self {
        Self::bind(libc::SOCK_DGRAM)
    }

    fn frames() -> Self {
        Self::bind(libc::SOCK_RAW)
    }

    fn bind(kind: libc::c_int) -> Self {
        let index = ifindex(IFACE);
        assert_ne!(index, 0);
        // Protocol 0: nothing is queued until bind names a protocol and IFACE.
        // SAFETY: socket(2) takes no pointers; the result is checked before use.
        let raw = unsafe { libc::socket(libc::AF_PACKET, kind | libc::SOCK_CLOEXEC, 0) };
        assert!(
            raw >= 0,
            "socket(AF_PACKET): {}",
            io::Error::last_os_error()
        );
        // SAFETY: `raw` is a freshly opened descriptor nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        set_socket_option(
            &fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            "SO_RCVBUFFORCE",
            &CAPTURE_RCVBUF,
        );
        // Every packet comes with the time the kernel stamped it: on receipt
        // from the PMD (netif_receive_skb) or when handing a sent one to packet
        // taps (dev_queue_xmit_nit).
        let on: libc::c_int = 1;
        set_socket_option(
            &fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPNS,
            "SO_TIMESTAMPNS",
            &on,
        );
        // SAFETY: sockaddr_ll is plain data; all-zero bytes are a valid value.
        let mut address: libc::sockaddr_ll = unsafe { mem::zeroed() };
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        address.sll_ifindex = index as i32;
        // SAFETY: `address` is a valid sockaddr_ll and its size is passed.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_ll).cast(),
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "bind(AF_PACKET): {}", io::Error::last_os_error());
        Self { fd }
    }

    /// Append the segment of every queued IPv4 packet `segment` accepts, with
    /// its kernel timestamp, without blocking.
    fn drain_into(&self, captured: &mut Vec<Captured>) {
        let mut buffer = [0u8; CAPTURED_BYTES];
        while let Some(packet) = self.receive(&mut buffer) {
            if packet.protocol != (libc::ETH_P_IP as u16).to_be() {
                continue;
            }
            if let Some(segment) = segment(packet.pkttype, &buffer[..packet.length]) {
                captured.push(Captured {
                    at: packet.at,
                    segment,
                });
            }
        }
    }

    /// Append every queued frame of a `frames` capture, without blocking.
    fn drain_frames(&self, frames: &mut Vec<Frame>) {
        let mut buffer = [0u8; ETHERNET_HEADER + CAPTURED_BYTES];
        while let Some(packet) = self.receive(&mut buffer) {
            frames.push(Frame {
                pkttype: packet.pkttype,
                bytes: buffer[..packet.length].to_vec(),
            });
        }
    }

    /// The next queued packet, cut to `buffer`, or None if none is queued.
    fn receive(&self, buffer: &mut [u8]) -> Option<Received> {
        // Room for one SCM_TIMESTAMPNS message, u64-aligned as cmsghdr needs.
        let mut control = [0u64; 8];
        loop {
            // SAFETY: sockaddr_ll is plain data; all-zero bytes are a valid value.
            let mut from: libc::sockaddr_ll = unsafe { mem::zeroed() };
            let mut iov = libc::iovec {
                iov_base: buffer.as_mut_ptr().cast(),
                iov_len: buffer.len(),
            };
            // SAFETY: msghdr is plain data; all-zero bytes are a valid value.
            let mut message: libc::msghdr = unsafe { mem::zeroed() };
            message.msg_name = (&mut from as *mut libc::sockaddr_ll).cast();
            message.msg_namelen = mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = mem::size_of_val(&control);
            // SAFETY: every pointer in `message` is valid and writable for the
            // length beside it.
            let n = unsafe {
                libc::recvmsg(
                    self.fd.as_raw_fd(),
                    &mut message,
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                )
            };
            if n < 0 {
                let error = io::Error::last_os_error();
                match error.kind() {
                    io::ErrorKind::WouldBlock => return None,
                    io::ErrorKind::Interrupted => continue,
                    _ => panic!("recvmsg(AF_PACKET): {error}"),
                }
            }
            assert_eq!(message.msg_flags & libc::MSG_CTRUNC, 0, "control truncated");
            return Some(Received {
                pkttype: from.sll_pkttype,
                protocol: from.sll_protocol,
                // MSG_TRUNC: `n` is the packet length, possibly over the buffer.
                length: usize::try_from(n).unwrap().min(buffer.len()),
                at: timestamp(&message),
            });
        }
    }

    /// Packets dropped for lack of receive buffer since open or the previous
    /// call (reading the statistics resets them).
    fn drops(&self) -> u32 {
        // SAFETY: tpacket_stats is plain integers; all-zero bytes are a valid value.
        let mut stats: libc::tpacket_stats = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::tpacket_stats>() as libc::socklen_t;
        // SAFETY: `stats` and `len` are a writable tpacket_stats and its size.
        let rc = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                (&mut stats as *mut libc::tpacket_stats).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "PACKET_STATISTICS: {}", io::Error::last_os_error());
        stats.tp_drops
    }
}

/// The PMD's writes reach packet taps synchronously only if
/// netif_receive_skb delivers directly. get_rps_cpu (net/core/dev.c) sends a
/// frame to a CPU backlog instead when its RX queue has an RPS CPU mask
/// (rps_cpus, which a new netdev inherits from net.core.rps_default_mask) or
/// an RFS flow table (rps_flow_cnt, used once net.core.rps_sock_flow_entries
/// is set). Both must be empty on every RX queue of `IFACE`.
fn assert_no_receive_steering() {
    let queues = format!("/sys/class/net/{}/queues", IFACE.to_str().unwrap());
    let entries = fs::read_dir(&queues).unwrap_or_else(|error| panic!("{queues}: {error}"));
    let mut rx_queues = 0;
    for entry in entries {
        let entry = entry.unwrap();
        if !entry.file_name().to_string_lossy().starts_with("rx-") {
            continue;
        }
        let queue = entry.path();
        rx_queues += 1;
        let read = |knob: &str| {
            let path = queue.join(knob);
            let text = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            (path, text.trim().to_owned())
        };
        // A hex CPU bitmap in comma-separated 32-bit groups.
        let (path, mask) = read("rps_cpus");
        assert!(
            mask.chars().all(|c| c == '0' || c == ','),
            "{} is {mask}: RPS would defer capture past the final drain",
            path.display()
        );
        let (path, flows) = read("rps_flow_cnt");
        assert_eq!(
            flows,
            "0",
            "{}: RFS would defer capture past the final drain",
            path.display()
        );
    }
    assert_ne!(rx_queues, 0, "no RX queue under {queues}");
}

/// `serve_client_configured` with `STANDARD` Port size, no offloads and the
/// default RTO.
fn serve_client<T: Send + 'static>(
    deadline: Duration,
    client: impl FnOnce() -> T + Send + 'static,
) -> (T, Vec<Captured>) {
    serve_client_configured(deadline, STANDARD, Offloads::default(), None, client)
}

/// Runs EchoServer on a fresh net_tap Port of `size` with `offloads`, the
/// kernel side at the same MTU, while `client` runs on its own thread, until
/// the client has returned and every listener is back in Listen (Zhida's
/// socket reached Closed and EchoServer listened again), failing after
/// `deadline`. `rto`, if any, is set on every listener before the client
/// starts; it survives each relisten. Returns the client's result and every
/// segment between the kernel and the echo port captured meanwhile, in
/// capture order. Tears down the Port with pools at 0; on a failure,
/// unwinding drops the Port and then removes the vdev.
fn serve_client_configured<T: Send + 'static>(
    deadline: Duration,
    size: PortSize,
    offloads: Offloads,
    rto: Option<Duration>,
    client: impl FnOnce() -> T + Send + 'static,
) -> (T, Vec<Captured>) {
    with_eal(|eal| {
        // Declared before the Port, so a failure drops the Port first.
        let tap = TapVdev::new(VDEV, IFACE);
        let mut config = port_config(tap.port_id(), size, [ECHO_BUFFER; 2]);
        config.offloads = offloads;
        let port = unsafe { Port::open(eal, config) }.unwrap();
        sync_kernel_mtu(&tap, size);
        set_kernel_address();
        let capture = Capture::open();
        assert_no_receive_steering();
        let start = Instant::now();
        let mut stack = Stack::new(port, stack_config(), StackInstant::ZERO)
            .map_err(|(_, error)| error)
            .unwrap();
        // Two listeners: smoltcp 0.14 has no accept backlog (a listening
        // socket becomes the connection), so with one a SYN in the same turn
        // as the previous connection's final ACK or RST is refused with RST.
        // Linux queues it in the listen backlog. Temporary until Zhida's
        // smoltcp fork.
        let mut echo = EchoServer::new(&mut stack, ECHO_PORT, 2, ECHO_BUFFER).unwrap();
        let listener_count = echo.handles().len();
        if let Some(rto) = rto {
            for handle in echo.handles() {
                stack.tcp_mut(handle).set_rto(rto.into());
            }
        }

        let mut captured = Vec::new();
        let client = thread::spawn(client);
        serve(&mut stack, &mut echo, start, |stack, echo| {
            assert!(
                start.elapsed() < deadline,
                "client not finished and connection not closed within {deadline:?}"
            );
            capture.drain_into(&mut captured);
            client.is_finished()
                && (0..listener_count)
                    .all(|slot| stack.tcp(&echo.handles()[slot]).state() == State::Listen)
        })
        .unwrap();
        capture.drain_into(&mut captured);
        assert_eq!(capture.drops(), 0, "capture dropped packets");
        let result = match client.join() {
            Ok(result) => result,
            Err(panic) => resume_unwind(panic),
        };

        drop(echo);
        let port = stack.into_port();
        if offloads.tx_tcp_checksum {
            let mut stats: zhida_dpdk_sys::rte_eth_stats = unsafe { mem::zeroed() };
            assert_eq!(
                unsafe { zhida_dpdk_sys::rte_eth_stats_get(tap.port_id(), &mut stats) },
                0
            );
            assert_eq!(
                stats.oerrors, 0,
                "net_tap TX errors with TCP checksum offload"
            );
        }
        // net_tap holds one RX buffer per descriptor while started; nothing else.
        assert_eq!(in_use(RX_POOL), u32::from(port.descriptor_counts().0));
        assert_eq!(in_use(TX_POOL), 0);
        close(port, tap);
        (result, captured)
    })
}

fn connect() -> TcpStream {
    let server = SocketAddr::V4(SocketAddrV4::new(ZHIDA_ADDR, ECHO_PORT));
    let stream = TcpStream::connect_timeout(&server, CONNECT_TIMEOUT).expect("connect");
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    stream
}

#[zhida_test_support::pinned_test]
fn kernel_echo_with_held_rx() {
    with_eal(|eal| {
        const BUFFER: usize = 8192;
        const BYTES: usize = 64 * 1024;
        let tap = TapVdev::new(VDEV, IFACE);
        let port =
            unsafe { Port::open(eal, port_config(tap.port_id(), STANDARD, [BUFFER])) }.unwrap();
        let descriptors = u32::from(port.descriptor_counts().0);
        sync_kernel_mtu(&tap, STANDARD);
        set_kernel_address();
        let start = Instant::now();
        let mut config = stack_config();
        config.max_sockets = 1;
        let mut stack = Stack::new(port, config, StackInstant::ZERO)
            .map_err(|(_, error)| error)
            .unwrap();
        let mut echo = EchoServer::new(&mut stack, ECHO_PORT, 1, BUFFER).unwrap();
        let cap = tcp::rx_mbuf_budget(&tcp::Config { rx_capacity: BUFFER, tx_capacity: BUFFER, mss_cap: None }, usize::from(STANDARD.mtu));
        let client = thread::spawn(|| {
            let mut stream = connect();
            let data = payload(BYTES, SEED);
            let mut writer = stream.try_clone().unwrap();
            let echoed = thread::scope(|scope| {
                let data = &data;
                let write = scope.spawn(move || {
                    writer.write_all(data).expect("write");
                    writer.shutdown(Shutdown::Write).expect("shutdown write");
                });
                let mut echoed = Vec::new();
                stream.read_to_end(&mut echoed).expect("read echo");
                if let Err(panic) = write.join() {
                    resume_unwind(panic);
                }
                echoed
            });
            assert_echoed(&echoed, &data);
        });
        let mut next_read = Duration::from_millis(20);
        let mut max_held = 0u32;
        let mut read = 0usize;
        loop {
            let elapsed = start.elapsed();
            assert!(elapsed < DEADLINE, "slow kernel echo did not finish");
            let now = StackInstant::from_micros(
                i64::try_from(elapsed.as_micros()).expect("elapsed time fits i64"),
            );
            let turn = stack.turn(now, 32).unwrap();
            assert_eq!(
                (turn.rx_rejected, turn.rx_ipv4_checksum_bad, turn.rx_staged),
                (0, 0, 0)
            );
            let held = in_use(RX_POOL)
                .checked_sub(descriptors)
                .expect("net_tap keeps its RX descriptor buffers");
            max_held = max_held.max(held);
            assert!(
                held as usize <= cap,
                "socket holds {held} RX mbufs; cap is {cap}"
            );
            if elapsed >= next_read {
                let before = stack.tcp(&echo.handles()[0]).recv_queue();
                echo.step(&mut stack);
                let consumed = before
                    .checked_sub(stack.tcp(&echo.handles()[0]).recv_queue())
                    .expect("app step does not receive new bytes");
                assert!(consumed <= BUFFER);
                read = read.checked_add(consumed).expect("read bytes fit usize");
                next_read = elapsed + Duration::from_millis(20);
                let held = in_use(RX_POOL)
                    .checked_sub(descriptors)
                    .expect("net_tap keeps its RX descriptor buffers");
                assert!(held as usize <= cap);
            }
            if client.is_finished() && stack.tcp(&echo.handles()[0]).state() == State::Listen {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        if let Err(panic) = client.join() {
            resume_unwind(panic);
        }
        assert_eq!(read, BYTES);
        assert!(max_held > 0);
        drop(echo);
        let port = stack.into_port();
        assert_eq!(in_use(RX_POOL), descriptors);
        assert_eq!(in_use(TX_POOL), 0);
        close(port, tap);
    });
}

fn local_port(stream: &TcpStream) -> u16 {
    stream.local_addr().unwrap().port()
}

fn assert_echoed(echoed: &[u8], sent: &[u8]) {
    assert_eq!(echoed.len(), sent.len(), "echoed byte count");
    if let Some(at) = echoed.iter().zip(sent).position(|(a, b)| a != b) {
        panic!(
            "echoed byte {at} is {:#04x}, sent {:#04x}",
            echoed[at], sent[at]
        );
    }
}

struct Transfer {
    kernel_port: u16,
    negotiated: Negotiated,
    /// Connected to echo fully read.
    elapsed: Duration,
}

/// `echo_one_mebibyte_checked` checking nothing.
fn echo_one_mebibyte() -> Transfer {
    echo_one_mebibyte_checked(|_| {})
}

/// Connect and pass what was negotiated to `check`; then write `TRANSFER`
/// bytes on a second thread and shut down writing, reading the echo to EOF on
/// this one. The echo must equal what was written.
fn echo_one_mebibyte_checked(check: impl FnOnce(&Negotiated)) -> Transfer {
    let mut stream = connect();
    let connected = Instant::now();
    let negotiated = negotiated(&stream);
    check(&negotiated);
    let mut writer = stream.try_clone().unwrap();
    let data = payload(TRANSFER, SEED);
    let echoed = thread::scope(|scope| {
        let data = &data;
        let write = scope.spawn(move || {
            let mut sent = 0;
            let mut call = 0;
            while sent < data.len() {
                call += 1;
                let end = data.len().min(sent + chunk(call));
                writer.write_all(&data[sent..end]).expect("write");
                sent = end;
            }
            writer.shutdown(Shutdown::Write).expect("shutdown write");
        });
        let mut echoed = Vec::with_capacity(TRANSFER);
        stream.read_to_end(&mut echoed).expect("read echo");
        if let Err(panic) = write.join() {
            resume_unwind(panic);
        }
        echoed
    });
    let elapsed = connected.elapsed();
    assert_echoed(&echoed, &data);
    Transfer {
        kernel_port: local_port(&stream),
        negotiated,
        elapsed,
    }
}

/// Echo a few KiB, then close while Established with SO_LINGER {on, 0}, so
/// the kernel sends an RST instead of a FIN. Returns the client port.
fn exchange_then_abort() -> u16 {
    let mut stream = connect();
    let data = payload(4096, SEED);
    stream.write_all(&data).expect("write");
    let mut echoed = vec![0; data.len()];
    stream.read_exact(&mut echoed).expect("read echo");
    assert_echoed(&echoed, &data);
    reset_on_close(&stream);
    local_port(&stream)
}

/// SO_LINGER {on, 0}: closing `stream` sends an RST instead of a FIN.
fn reset_on_close(stream: &TcpStream) {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    set_socket_option(
        stream,
        libc::SOL_SOCKET,
        libc::SO_LINGER,
        "SO_LINGER",
        &linger,
    );
}

/// The qdisc each direction's packets meet on `IFACE`: the kernel's packets to
/// Zhida the root qdisc, Zhida's packets to the kernel the ingress qdisc.
/// net_tap creates both when it opens, for its rte_flow support (built when
/// linux/pkt_cls.h has TCA_FLOWER_ACT, drivers/net/tap/meson.build:23-24):
/// after tap_nl_init opens its netlink socket (rte_eth_tap.c:2090),
/// eth_dev_tap_create adds multiq 1: as root and ingress ffff:
/// (qdisc_create_multiq, qdisc_create_ingress; rte_eth_tap.c:2120-2129 in
/// DPDK 25.11.3). The filters go on those, since a clsact qdisc cannot be
/// added beside an ingress one. multiq drops a packet its filter answers
/// TC_ACT_SHOT for (multiq_classify, net/sched/sch_multiq.c:38-48 in Linux
/// v6.12).
const TC_PARENTS: [(Direction, &str); 2] =
    [(Direction::ToZhida, "1:"), (Direction::ToKernel, "ffff:")];
/// Priority of the drop filters, by which they are listed and deleted.
const TC_PREF: &str = "1";

/// The TCP segments a `tcp_filter` program matches.
#[derive(Clone, Copy)]
enum Matched {
    /// TCP flags exactly ACK and no payload.
    PureAck,
    /// A pure ACK whose acknowledgment number is the given one.
    PureAckOf(u32),
    /// A segment with payload whose sequence number is the given one.
    Data(u32),
}

/// Classic BPF program, in `tc ... bpf bytecode` form ("count,code jt jf k,..."),
/// matching a `matched` segment of the connection between
/// `KERNEL_ADDR:kernel_port` and `ZHIDA_ADDR:ECHO_PORT` travelling
/// `direction`. The payload length is IP total length - IHL * 4 - data
/// offset * 4. It returns -1 for a match, which runs the filter's action, and
/// 0 otherwise.
///
/// Offsets count from the Ethernet header in both directions: cls_bpf runs at
/// egress with skb->data at the MAC header, and at ingress pushes skb->data
/// back to it first (cls_bpf_classify, net/sched/cls_bpf.c:97-102 in v6.12).
/// The test confirms this: a match needs EtherType 0x0800 at offset 12, where
/// a network-header base would read the first half of the IP source address,
/// 192.0 = 0xc000, so the drop counts it asserts nonzero in each direction
/// could not occur with any other base.
fn tcp_filter(direction: Direction, kernel_port: u16, matched: Matched) -> String {
    use libc::{
        BPF_ABS, BPF_ADD, BPF_ALU, BPF_AND, BPF_B, BPF_H, BPF_IND, BPF_JEQ, BPF_JMP, BPF_JSET,
        BPF_K, BPF_LD, BPF_LDX, BPF_MISC, BPF_MSH, BPF_RET, BPF_RSH, BPF_SUB, BPF_TAX, BPF_W,
        BPF_X,
    };
    enum Step {
        /// Run `code` with operand `k`.
        Do(u32, u32),
        /// Jump comparing A with `k`: continue if true, no match if false.
        Pass(u32, u32),
        /// Jump comparing A with `k`: no match if true, continue if false.
        Fail(u32, u32),
    }
    use Step::{Do, Fail, Pass};
    /// The IP header follows the 14-byte Ethernet header.
    const IP: u32 = 14;
    // Address offsets in the IP header, port offsets in the TCP header.
    let (kernel_address, zhida_address, kernel_port_at, zhida_port_at) = match direction {
        Direction::ToZhida => (12, 16, 0, 2),
        Direction::ToKernel => (16, 12, 2, 0),
    };
    let mut steps = vec![
        // A = EtherType, IPv4 only.
        Do(BPF_LD | BPF_H | BPF_ABS, 12),
        Pass(BPF_JMP | BPF_JEQ | BPF_K, libc::ETH_P_IP as u32),
        // A = IP protocol, TCP only.
        Do(BPF_LD | BPF_B | BPF_ABS, IP + 9),
        Pass(BPF_JMP | BPF_JEQ | BPF_K, libc::IPPROTO_TCP as u32),
        // A = the kernel's IP address, then Zhida's.
        Do(BPF_LD | BPF_W | BPF_ABS, IP + kernel_address),
        Pass(BPF_JMP | BPF_JEQ | BPF_K, u32::from(KERNEL_ADDR)),
        Do(BPF_LD | BPF_W | BPF_ABS, IP + zhida_address),
        Pass(BPF_JMP | BPF_JEQ | BPF_K, u32::from(ZHIDA_ADDR)),
        // A = IP flags and fragment offset: a later fragment has no TCP header.
        Do(BPF_LD | BPF_H | BPF_ABS, IP + 6),
        Fail(BPF_JMP | BPF_JSET | BPF_K, 0x1fff),
        // X = 4 * (IP byte 0 & 0xf), the IP header length, so X + IP is the
        // TCP header.
        Do(BPF_LDX | BPF_B | BPF_MSH, IP),
        // A = the kernel's TCP port, then Zhida's.
        Do(BPF_LD | BPF_H | BPF_IND, IP + kernel_port_at),
        Pass(BPF_JMP | BPF_JEQ | BPF_K, u32::from(kernel_port)),
        Do(BPF_LD | BPF_H | BPF_IND, IP + zhida_port_at),
        Pass(BPF_JMP | BPF_JEQ | BPF_K, u32::from(ECHO_PORT)),
    ];
    if let Matched::PureAck | Matched::PureAckOf(_) = matched {
        // A = TCP flags (TCP byte 13): exactly ACK.
        steps.extend([
            Do(BPF_LD | BPF_B | BPF_IND, IP + 13),
            Pass(BPF_JMP | BPF_JEQ | BPF_K, u32::from(ACK)),
        ]);
    }
    match matched {
        Matched::PureAck => {}
        // A = the acknowledgment number (TCP bytes 8-11).
        Matched::PureAckOf(ack) => steps.extend([
            Do(BPF_LD | BPF_W | BPF_IND, IP + 8),
            Pass(BPF_JMP | BPF_JEQ | BPF_K, ack),
        ]),
        // A = the sequence number (TCP bytes 4-7).
        Matched::Data(seq) => steps.extend([
            Do(BPF_LD | BPF_W | BPF_IND, IP + 4),
            Pass(BPF_JMP | BPF_JEQ | BPF_K, seq),
        ]),
    }
    steps.extend([
        // A = TCP byte 12, data offset in the high nibble; masking it and
        // shifting right by 2 gives the offset * 4, the TCP header length.
        Do(BPF_LD | BPF_B | BPF_IND, IP + 12),
        Do(BPF_ALU | BPF_AND | BPF_K, 0xf0),
        Do(BPF_ALU | BPF_RSH | BPF_K, 2),
        // X = A = TCP header length + IP header length.
        Do(BPF_ALU | BPF_ADD | BPF_X, 0),
        Do(BPF_MISC | BPF_TAX, 0),
        // A = IP total length - both headers = TCP payload length.
        Do(BPF_LD | BPF_H | BPF_ABS, IP + 2),
        Do(BPF_ALU | BPF_SUB | BPF_X, 0),
    ]);
    steps.push(match matched {
        Matched::PureAck | Matched::PureAckOf(_) => Pass(BPF_JMP | BPF_JEQ | BPF_K, 0),
        Matched::Data(_) => Fail(BPF_JMP | BPF_JEQ | BPF_K, 0),
    });
    // After the steps: return -1 (match), then return 0 (no match).
    let no_match = steps.len() + 1;
    let mut program = (steps.len() + 2).to_string();
    for (at, step) in steps.iter().enumerate() {
        // Jump offsets count instructions skipped after this one.
        let skip = u8::try_from(no_match - at - 1).unwrap();
        let (code, jt, jf, k) = match *step {
            Do(code, k) => (code, 0, 0, k),
            Pass(code, k) => (code, 0, skip, k),
            Fail(code, k) => (code, skip, 0, k),
        };
        program += &format!(",{code} {jt} {jf} {k}");
    }
    let ret = BPF_RET | BPF_K;
    program += &format!(",{ret} 0 0 {},{ret} 0 0 0", u32::MAX);
    program
}

/// Runs `tc` with `args`; a missing binary or any failure fails the test.
fn tc(args: &[&str]) -> String {
    run("tc", args)
}

/// Runs `program` with `args`; a missing binary or any failure fails the test.
fn run(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("{program} {}: {error}", args.join(" ")));
    assert!(
        output.status.success(),
        "{program} {}: {}: {}",
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// The drop filters installed so far, by parent. Dropping them deletes
/// them best effort, so a failure while they are installed does not leave
/// them behind; `remove` deletes them and fails the test if `tc` does.
struct DropFilters {
    parents: Vec<&'static str>,
}

impl DropFilters {
    /// Drop every pure ACK of the connection from `kernel_port` travelling
    /// one of `directions`. The capture still records the dropped ones
    /// Zhida sends (packet taps run before the ingress qdisc in
    /// __netif_receive_skb_core) but not the kernel's (the root qdisc
    /// enqueues in __dev_queue_xmit, before dev_queue_xmit_nit in xmit_one).
    fn install(kernel_port: u16, directions: &[Direction]) -> Self {
        let mut filters = Self {
            parents: Vec::new(),
        };
        for (direction, _) in TC_PARENTS {
            if directions.contains(&direction) {
                filters.add(direction, kernel_port, Matched::PureAck, &["drop"]);
            }
        }
        filters
    }

    /// Run the tc `action` on each `matched` segment of the connection from
    /// `kernel_port` travelling `direction`. One filter per direction.
    fn add(&mut self, direction: Direction, kernel_port: u16, matched: Matched, action: &[&str]) {
        let iface = IFACE.to_str().unwrap();
        let parent = tc_parent(direction);
        let program = tcp_filter(direction, kernel_port, matched);
        let mut args = vec![
            "filter", "add", "dev", iface, "parent", parent, "pref", TC_PREF, "protocol", "all",
            "bpf", "bytecode", &program, "action",
        ];
        args.extend_from_slice(action);
        tc(&args);
        self.parents.push(parent);
    }

    fn remove(mut self) {
        while let Some(&parent) = self.parents.last() {
            tc(&delete_filter(parent));
            self.parents.pop();
        }
    }
}

impl Drop for DropFilters {
    fn drop(&mut self) {
        for parent in self.parents.drain(..) {
            // Best effort: the outcome is ignored while the failure unwinds.
            let _ = Command::new("tc").args(delete_filter(parent)).output();
        }
    }
}

/// The qdisc parent `direction`'s packets meet on `IFACE`.
fn tc_parent(direction: Direction) -> &'static str {
    TC_PARENTS.iter().find(|(d, _)| *d == direction).unwrap().1
}

/// `tc` arguments deleting the drop filter under `parent`.
fn delete_filter(parent: &str) -> [&str; 8] {
    [
        "filter",
        "del",
        "dev",
        IFACE.to_str().unwrap(),
        "parent",
        parent,
        "pref",
        TC_PREF,
    ]
}

/// Packets the filter under `parent` has dropped so far.
fn filter_drops(parent: &str) -> u64 {
    let iface = IFACE.to_str().unwrap();
    let stats = tc(&[
        "-s", "filter", "show", "dev", iface, "parent", parent, "pref", TC_PREF,
    ]);
    // The drop action's "Sent <bytes> bytes <packets> pkt (dropped <packets>, ...".
    let counts: Vec<u64> = stats
        .split("(dropped ")
        .skip(1)
        .map(|rest| rest[..rest.find(',').unwrap()].parse().unwrap())
        .collect();
    assert_eq!(counts.len(), 1, "one drop action under {parent}:\n{stats}");
    counts[0]
}

/// TcpExt counter: the kernel's TCP retransmission timeouts. tcp_retransmit_timer
/// counts each expiry with the peer's window open (net/ipv4/tcp_timer.c:588
/// in Linux v6.12) and tcp_syn_ack_timeout each SYN-ACK timeout (736); a
/// tail loss probe does not count.
const TCP_TIMEOUTS: &str = "TCPTimeouts";
/// TcpExt counter: data segments the kernel received although it already held
/// all of their data, as a retransmission of data it acknowledged delivers.
/// tcp_send_dupack counts one when tcp_sequence rejects it as old
/// (net/ipv4/tcp_input.c:5096 in Linux v7.0) and tcp_data_queue when it
/// passes that check (5720).
const DELAYED_ACK_LOST: &str = "DelayedACKLost";
/// TcpExt counter: keepalive probes the kernel sent (tcp_keepalive_timer ->
/// tcp_write_wakeup -> tcp_xmit_probe_skb, net/ipv4/tcp_timer.c:841 and
/// tcp_output.c:4537-4538 in Linux v7.0).
const TCP_KEEPALIVE: &str = "TCPKeepAlive";
/// TcpExt counter: answers to out-of-window ACKs the kernel skipped for its
/// rate limit, one per net.ipv4.tcp_invalid_ratelimit (tcp_validate_incoming,
/// net/ipv4/tcp_input.c:6394-6397 in Linux v7.0).
const TCP_ACK_SKIPPED_SEQ: &str = "TCPACKSkippedSeq";

/// TcpExt `counter` from /proc/net/netstat, so far in this network namespace.
fn tcp_ext(counter: &str) -> u64 {
    const PATH: &str = "/proc/net/netstat";
    let text = fs::read_to_string(PATH).unwrap_or_else(|error| panic!("{PATH}: {error}"));
    // A "TcpExt:" line of names, then one of values in the same order.
    let mut lines = text.lines().filter(|line| line.starts_with("TcpExt:"));
    let (names, values) = (lines.next().unwrap(), lines.next().unwrap());
    let at = names
        .split_whitespace()
        .position(|name| name == counter)
        .unwrap_or_else(|| panic!("no {counter} in {PATH}"));
    values.split_whitespace().nth(at).unwrap().parse().unwrap()
}

/// Bytes each data-loss test moves one way.
const DATA_LOSS_TRANSFER: usize = 4 << 20;
/// tc gact action for the data-loss filter: its first match is dropped, the
/// second passes, and so on alternately (gact_determ drops the matches whose
/// count is not a multiple of 2, net/sched/act_gact.c). The filter matches
/// one sequence number, so it drops the first send of that segment and lets
/// its first retransmission through.
const DROP_FIRST_SEND: [&str; 6] = ["gact", "drop", "random", "determ", "pass", "2"];

/// Sequence number of the first payload byte `direction`'s sender puts on
/// the connection from `kernel_port`: its SYN's (or SYN-ACK's) + 1.
fn first_payload_seq(captured: &[Captured], direction: Direction, kernel_port: u16) -> u32 {
    let syn = captured
        .iter()
        .map(|captured| captured.segment)
        .find(|segment| {
            segment.direction == direction
                && segment.kernel_port == kernel_port
                && segment.flags & SYN != 0
        })
        .unwrap_or_else(|| panic!("no SYN captured travelling {direction:?}"));
    syn.seq.wrapping_add(1)
}

/// Linux's TCP_INFO total retransmissions on `stream`.
fn total_retransmits(stream: &TcpStream) -> u32 {
    // SAFETY: tcp_info is plain data; all-zero bytes are a valid value.
    let mut info: libc::tcp_info = unsafe { mem::zeroed() };
    let mut len = libc::socklen_t::try_from(mem::size_of_val(&info)).unwrap();
    // SAFETY: `info` and `len` are writable and `len` is the size of `info`.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&raw mut info).cast(),
            &mut len,
        )
    };
    assert_eq!(result, 0, "TCP_INFO: {}", io::Error::last_os_error());
    let end = mem::offset_of!(libc::tcp_info, tcpi_total_retrans) + mem::size_of::<u32>();
    assert!(
        usize::try_from(len).unwrap() >= end,
        "TCP_INFO of {len} bytes"
    );
    info.tcpi_total_retrans
}

/// What one `data_loss_transfer` counted.
struct DataLoss {
    /// Sends of the first data segment the tc filter dropped.
    data_dropped: u64,
    /// Linux's pure ACKs of the first data segment's sequence number dropped
    /// on their way to Zhida (Zhida sending only).
    acks_dropped: u64,
    linux_retransmits: u32,
    /// Linux's segments resending the dropped send, which the capture shows
    /// covering it exactly once (Linux sending only).
    linux_resent: u32,
    linux_timeouts: u64,
    zhida_retransmits: u64,
    zhida_losses: u64,
    /// Turns that started after Zhida's RTO with its cwnd below ssthresh
    /// and grew it (Zhida sending only).
    slow_start_turns: u32,
}

/// Moves `DATA_LOSS_TRANSFER` bytes travelling `direction` between a Linux
/// client and one Zhida socket with production defaults; a tc filter drops
/// the first send of the first data segment. When Zhida sends, Linux's pure
/// ACKs of that segment's sequence number (its duplicate ACKs while the
/// segment is missing) are dropped too, so Zhida gets no fast retransmit:
/// its RTO resends the segment, and Linux, which held the rest of the flight,
/// acknowledges it all at once. Asserts the bytes arrive exactly, within
/// `DEADLINE`, and, after every turn starting after Zhida's RTO with cwnd
/// below ssthresh, that cwnd is at most ssthresh + 4 MSS: Linux's
/// tcp_slow_start stops at ssthresh, and one turn may take a few more ACKs in
/// congestion avoidance.
fn data_loss_transfer(direction: Direction) -> DataLoss {
    with_eal(|eal| {
        let tap = TapVdev::new(VDEV, IFACE);
        let port = unsafe { Port::open(eal, port_config(tap.port_id(), STANDARD, [ECHO_BUFFER])) }
            .unwrap();
        sync_kernel_mtu(&tap, STANDARD);
        set_kernel_address();
        let capture = Capture::open();
        assert_no_receive_steering();
        let start = Instant::now();
        let mut stack = Stack::new(port, stack_config(), StackInstant::ZERO)
            .map_err(|(_, error)| error)
            .unwrap();
        let handle = stack
            .add_tcp(tcp::Config { rx_capacity: ECHO_BUFFER, tx_capacity: ECHO_BUFFER, mss_cap: None })
            .unwrap();
        stack.listen(&handle, ECHO_PORT).unwrap();
        let timeouts = tcp_ext(TCP_TIMEOUTS);
        let (connected, connection) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let client = thread::spawn(move || {
            let mut stream = connect();
            connected.send(local_port(&stream)).unwrap();
            released.recv_timeout(DEADLINE).unwrap();
            let data = payload(DATA_LOSS_TRANSFER, SEED);
            let mut received = Vec::new();
            match direction {
                Direction::ToKernel => {
                    stream
                        .read_to_end(&mut received)
                        .expect("read Zhida's bytes");
                    assert_echoed(&received, &data);
                }
                Direction::ToZhida => {
                    stream.write_all(&data).expect("write to Zhida");
                    stream.shutdown(Shutdown::Write).unwrap();
                    stream
                        .read_to_end(&mut received)
                        .expect("read Zhida's FIN");
                    assert!(received.is_empty(), "Zhida sent {} bytes", received.len());
                }
            }
            total_retransmits(&stream)
        });
        let data = payload(DATA_LOSS_TRANSFER, SEED);
        // IPv4 and TCP headers without options.
        let mss = usize::from(STANDARD.mtu) - 40;
        let mut captured = Vec::new();
        let mut filters = None;
        let mut dropped = None;
        let mut release = Some(release);
        let mut sent = 0;
        let mut received = Vec::new();
        let mut rto = false;
        let mut slow_start_turns = 0;
        loop {
            assert!(
                start.elapsed() < DEADLINE,
                "transfer {direction:?} not finished within {DEADLINE:?}"
            );
            let socket = stack.tcp(&handle);
            let (cwnd, ssthresh, losses) = (
                socket.congestion_window(),
                socket.ssthresh(),
                socket.loss_events(),
            );
            stack.turn(stack_now(start), 32).unwrap();
            let socket = stack.tcp(&handle);
            if rto && cwnd < ssthresh {
                let cap = ssthresh
                    .checked_add(4 * mss)
                    .expect("ssthresh + 4 MSS fits usize");
                let after = socket.congestion_window();
                assert!(
                    after <= cap,
                    "post-RTO slow start passed ssthresh in one turn: cwnd {cwnd} before, \
                     {after} after, ssthresh {ssthresh}, cap {cap}"
                );
                if after > cwnd {
                    slow_start_turns += 1;
                }
            }
            if direction == Direction::ToKernel && !rto && socket.loss_events() > losses {
                assert_eq!(
                    socket.congestion_window(),
                    mss,
                    "Zhida's first loss is not an RTO"
                );
                rto = true;
            }
            capture.drain_into(&mut captured);
            if filters.is_none() && socket.state() == State::Established {
                if let Ok(kernel_port) = connection.try_recv() {
                    let seq = first_payload_seq(&captured, direction, kernel_port);
                    let mut installed = DropFilters {
                        parents: Vec::new(),
                    };
                    installed.add(direction, kernel_port, Matched::Data(seq), &DROP_FIRST_SEND);
                    if direction == Direction::ToKernel {
                        installed.add(
                            Direction::ToZhida,
                            kernel_port,
                            Matched::PureAckOf(seq),
                            &["drop"],
                        );
                    }
                    filters = Some(installed);
                    dropped = Some((kernel_port, seq));
                    release.take().unwrap().send(()).unwrap();
                }
            }
            if filters.is_some() {
                let socket = stack.tcp_mut(&handle);
                match direction {
                    Direction::ToKernel => {
                        if sent < data.len() && socket.may_send() {
                            let queued = socket.send_slice(&data[sent..]).unwrap();
                            sent = sent.checked_add(queued).expect("sent bytes fit usize");
                        }
                        if sent == data.len() && socket.may_send() {
                            socket.close();
                        }
                    }
                    Direction::ToZhida => {
                        while socket.can_recv() {
                            let frame = socket.recv().unwrap().unwrap();
                            received.extend_from_slice(frame.payload());
                        }
                        if socket.state() == State::CloseWait {
                            socket.close();
                        }
                    }
                }
            }
            if client.is_finished()
                && matches!(stack.tcp(&handle).state(), State::TimeWait | State::Closed)
            {
                break;
            }
        }
        let elapsed = start.elapsed();
        let linux_retransmits = match client.join() {
            Ok(retransmits) => retransmits,
            Err(panic) => resume_unwind(panic),
        };
        if direction == Direction::ToZhida {
            assert_echoed(&received, &data);
        }
        let data_dropped = filter_drops(tc_parent(direction));
        let acks_dropped = match direction {
            Direction::ToKernel => filter_drops(tc_parent(Direction::ToZhida)),
            Direction::ToZhida => 0,
        };
        filters.unwrap().remove();
        capture.drain_into(&mut captured);
        assert_eq!(capture.drops(), 0, "capture dropped packets");
        let (kernel_port, seq) = dropped.unwrap();
        let linux_resent = match direction {
            Direction::ToZhida => linux_resends(&captured, kernel_port, seq),
            Direction::ToKernel => 0,
        };
        let socket = stack.tcp(&handle);
        let loss = DataLoss {
            data_dropped,
            acks_dropped,
            linux_retransmits,
            linux_resent,
            linux_timeouts: tcp_ext(TCP_TIMEOUTS)
                .checked_sub(timeouts)
                .expect("TCPTimeouts only grows"),
            zhida_retransmits: socket.retransmits(),
            zhida_losses: socket.loss_events(),
            slow_start_turns,
        };
        println!(
            "{direction:?}: {elapsed:?}, data dropped {data_dropped}, ACKs dropped \
             {acks_dropped}, Linux retransmits {linux_retransmits} (resent {linux_resent}) \
             TCPTimeouts +{}, Zhida retransmits {} loss events {}, post-RTO slow-start \
             turns {slow_start_turns}",
            loss.linux_timeouts, loss.zhida_retransmits, loss.zhida_losses,
        );
        drop(handle);
        close(stack.into_port(), tap);
        loss
    })
}

/// Linux's data segments to Zhida captured before `first_data`, the first
/// captured one: the capture runs after the root qdisc, so it never saw the
/// dropped send of the bytes from `seq` up to `first_data`, only Linux's
/// resends of them. Asserts those cover the dropped bytes in order exactly
/// once and returns how many there were.
fn linux_resends(captured: &[Captured], kernel_port: u16, seq: u32) -> u32 {
    let data: Vec<Segment> = captured
        .iter()
        .map(|captured| captured.segment)
        .filter(|segment| {
            segment.direction == Direction::ToZhida
                && segment.kernel_port == kernel_port
                && segment.len > 0
        })
        .collect();
    let first_data = data.first().expect("Linux sent data").seq;
    assert!(
        after(first_data, seq),
        "the first send at {seq} was captured"
    );
    let mut next = seq;
    let mut resends = 0;
    for segment in data.iter().filter(|segment| after(first_data, segment.seq)) {
        assert_eq!(
            segment.seq, next,
            "Linux resent the dropped bytes out of order or twice"
        );
        next = next.wrapping_add(segment.len);
        resends += 1;
    }
    assert_eq!(
        next, first_data,
        "Linux's resends end at {next}, not at {first_data}"
    );
    resends
}

/// Linux sends; the first send of its first data segment (one GSO packet of
/// one or more MSS at the qdisc) is dropped. Zhida receives every byte in
/// order and Linux resends exactly the dropped bytes, once, without an RTO.
#[zhida_test_support::pinned_test]
fn linux_sender_recovers_a_dropped_data_segment() {
    let loss = data_loss_transfer(Direction::ToZhida);
    assert_eq!(loss.data_dropped, 1);
    assert!(loss.linux_resent > 0);
    assert_eq!(loss.linux_retransmits, loss.linux_resent);
    assert_eq!(loss.linux_timeouts, 0);
    assert_eq!((loss.zhida_retransmits, loss.zhida_losses), (0, 0));
}

/// Zhida sends; its first data segment's first send and Linux's duplicate
/// ACKs for it are dropped, so Zhida's RTO resends it and Linux then
/// acknowledges the whole flight it held. Zhida's cwnd restarts from one
/// MSS and must stop near ssthresh rather than jump back to the whole flight.
#[zhida_test_support::pinned_test]
fn zhida_sender_rto_against_linux_holding_the_flight_stops_slow_start_at_ssthresh() {
    let loss = data_loss_transfer(Direction::ToKernel);
    assert_eq!(loss.data_dropped, 1);
    assert!(loss.acks_dropped > 0, "Linux sent no duplicate ACK");
    assert_eq!(
        (loss.zhida_losses, loss.zhida_retransmits),
        (1, 1),
        "one RTO, resending the dropped segment once"
    );
    assert!(
        loss.slow_start_turns > 0,
        "no turn grew cwnd in post-RTO slow start"
    );
    assert_eq!((loss.linux_retransmits, loss.linux_timeouts), (0, 0));
}

/// Every filter under both parents, net_tap's included.
fn tc_filters() -> [String; 2] {
    let iface = IFACE.to_str().unwrap();
    TC_PARENTS.map(|(_, parent)| tc(&["filter", "show", "dev", iface, "parent", parent]))
}

struct LossWindow {
    /// Taken before the first filter is added and after the last is deleted.
    before_add: SystemTime,
    after_delete: SystemTime,
    /// Both filters in place from `from` (the last added) to `until` (before
    /// the first is deleted).
    from: SystemTime,
    until: SystemTime,
    /// Pure ACKs dropped, [to Zhida, to the kernel], read just after `until`.
    dropped: [u64; 2],
    removed: Instant,
    /// The client's written byte count sampled at the start of the second
    /// phase, while its writer was paused.
    written_by_second_phase: usize,
    /// Kernel TCP timeouts from before the first filter was added to after
    /// the last was deleted, and from the start of the second phase to then.
    linux_timeouts: u64,
    linux_timeouts_second_phase: u64,
}

/// Reading/writing pauses and the byte count the writer may not pass.
/// Loss tests start at `ACK_LOSS_AFTER`, allow all but `ACK_LOSS_RESERVE`
/// after filter installation, then release the full transfer.
/// Default is unlimited.
struct Paused {
    reading: AtomicBool,
    writing: AtomicBool,
    write_limit: AtomicUsize,
}

impl Default for Paused {
    fn default() -> Self {
        Self {
            reading: AtomicBool::new(false),
            writing: AtomicBool::new(false),
            write_limit: AtomicUsize::new(usize::MAX),
        }
    }
}

/// Releases the full transfer when dropped, also on an early return or panic.
/// The initial limit must already be set before the writer starts.
struct WriteLimitHeld<'a> {
    write_limit: &'a AtomicUsize,
    full: usize,
}

impl Drop for WriteLimitHeld<'_> {
    fn drop(&mut self) {
        self.write_limit.store(self.full, Ordering::SeqCst);
    }
}

/// Whether `pause` is set, after sleeping `PAUSED_POLL` if so.
fn wait_while(pause: &AtomicBool) -> bool {
    let paused = pause.load(Ordering::SeqCst);
    if paused {
        thread::sleep(PAUSED_POLL);
    }
    paused
}

/// The writer starts limited to `ACK_LOSS_AFTER`. Once `start` receives,
/// install the filters, then allow all but `ACK_LOSS_RESERVE` bytes to be written.
/// Drop every pure ACK of the connection from
/// `kernel_port` for `ACK_LOSS_STREAMING` and then two `ACK_LOSS_PHASE`s, the
/// client not writing in the first phase and writing again with its reserve
/// released but not reading in the second, then remove the filters, leaving
/// net_tap's as they were. `written` is the bytes the client has written. None
/// if `start` disconnected without receiving.
fn pure_ack_loss(
    kernel_port: u16,
    start: Receiver<()>,
    paused: &Paused,
    written: &AtomicUsize,
) -> Option<LossWindow> {
    let write_limit_held = WriteLimitHeld {
        write_limit: &paused.write_limit,
        full: ACK_LOSS_TRANSFER,
    };
    start.recv().ok()?;
    let before = tc_filters();
    let timeouts = tcp_ext(TCP_TIMEOUTS);
    let before_add = SystemTime::now();
    let filters = DropFilters::install(kernel_port, &[Direction::ToZhida, Direction::ToKernel]);
    let from = SystemTime::now();
    paused
        .write_limit
        .store(ACK_LOSS_TRANSFER - ACK_LOSS_RESERVE, Ordering::SeqCst);
    thread::sleep(ACK_LOSS_STREAMING);
    paused.writing.store(true, Ordering::SeqCst);
    thread::sleep(ACK_LOSS_PHASE);
    paused.reading.store(true, Ordering::SeqCst);
    // Sampled, not synchronized with the writer: a write it was already in
    // when paused returns within POLL and stores its count, normally long
    // before this read 1.5 s later.
    let written_by_second_phase = written.load(Ordering::SeqCst);
    let second_phase_timeouts = tcp_ext(TCP_TIMEOUTS);
    drop(write_limit_held);
    paused.writing.store(false, Ordering::SeqCst);
    thread::sleep(ACK_LOSS_PHASE);
    let until = SystemTime::now();
    let dropped = TC_PARENTS.map(|(_, parent)| filter_drops(parent));
    filters.remove();
    let removed = Instant::now();
    let after_delete = SystemTime::now();
    let timeouts_after = tcp_ext(TCP_TIMEOUTS);
    let linux_timeouts = timeouts_after - timeouts;
    let linux_timeouts_second_phase = timeouts_after - second_phase_timeouts;
    paused.reading.store(false, Ordering::SeqCst);
    assert_eq!(tc_filters(), before, "net_tap's filters changed");
    Some(LossWindow {
        before_add,
        after_delete,
        from,
        until,
        dropped,
        removed,
        written_by_second_phase,
        linux_timeouts,
        linux_timeouts_second_phase,
    })
}

/// Whether a read or write on the client's socket only ran out its POLL
/// timeout (or a signal interrupted it) and should be retried. SO_RCVTIMEO
/// and SO_SNDTIMEO expiry is EAGAIN on Linux (socket(7)), WouldBlock in Rust;
/// ETIMEDOUT means the kernel aborted the connection (keepalive or
/// retransmission limit) and fails the test.
fn timed_out(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

fn joined<T>(handle: ScopedJoinHandle<'_, T>) -> T {
    handle.join().unwrap_or_else(|panic| resume_unwind(panic))
}

/// Write `data` in `chunk` sizes, holding off while `paused` or at `write_limit`
/// (capped at `data.len()`). Raising the limit resumes writing: loss tests hold
/// at the start trigger, then before the reserve, then allow the full transfer.
/// Stop at `deadline` or shut down writing once all is written. Keep `written`
/// at the bytes written so far and return that count.
fn write_until(
    writer: &mut TcpStream,
    data: &[u8],
    paused: &AtomicBool,
    write_limit: &AtomicUsize,
    written: &AtomicUsize,
    deadline: Instant,
) -> usize {
    let mut sent = 0;
    let mut call = 0;
    while sent < data.len() && Instant::now() < deadline {
        if wait_while(paused) {
            continue;
        }
        let limit = write_limit.load(Ordering::SeqCst).min(data.len());
        if sent >= limit {
            thread::sleep(PAUSED_POLL);
            continue;
        }
        call += 1;
        let end = limit.min(sent + chunk(call));
        match writer.write(&data[sent..end]) {
            Ok(n) => {
                sent += n;
                written.store(sent, Ordering::SeqCst);
            }
            Err(error) if timed_out(&error) => {}
            Err(error) => panic!("write: {error}"),
        }
    }
    if sent == data.len() {
        writer.shutdown(Shutdown::Write).expect("shutdown write");
    }
    sent
}

#[test]
fn write_until_obeys_write_limit() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut writer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut reader, _) = listener.accept().unwrap();
    writer.set_write_timeout(Some(POLL)).unwrap();
    reader.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    let data = payload(4096, SEED);
    let limits = [137, 1029];
    let paused = Paused {
        write_limit: AtomicUsize::new(limits[0]),
        ..Paused::default()
    };
    let written = AtomicUsize::new(0);
    let deadline = Instant::now() + IO_TIMEOUT;
    let (received, events) = mpsc::channel();
    thread::scope(|scope| {
        // Release before scoped joins if an assertion panics while the writer is held.
        let release = WriteLimitHeld {
            write_limit: &paused.write_limit,
            full: data.len(),
        };
        let write = scope.spawn(|| {
            write_until(
                &mut writer,
                &data,
                &paused.writing,
                &paused.write_limit,
                &written,
                deadline,
            )
        });
        let read = scope.spawn(move || {
            let mut bytes = Vec::new();
            let mut buffer = [0; 512];
            loop {
                let n = reader.read(&mut buffer).unwrap();
                if n == 0 {
                    received.send(0).unwrap();
                    return bytes;
                }
                bytes.extend_from_slice(&buffer[..n]);
                received.send(bytes.len()).unwrap();
            }
        });
        let mut count = 0;
        for limit in limits {
            paused.write_limit.store(limit, Ordering::SeqCst);
            while count < limit {
                count = events.recv_timeout(IO_TIMEOUT).unwrap();
                assert_ne!(count, 0, "EOF before full data");
                assert!(count <= limit, "writer passed limit {limit}: {count}");
            }
            assert_eq!(count, limit);
            assert_eq!(
                events.recv_timeout(POLL),
                Err(mpsc::RecvTimeoutError::Timeout),
                "data or EOF while held at {limit}"
            );
            assert_eq!(written.load(Ordering::SeqCst), limit);
        }
        // An unlimited limit must be capped at data.len().
        paused.write_limit.store(usize::MAX, Ordering::SeqCst);
        loop {
            let next = events.recv_timeout(IO_TIMEOUT).unwrap();
            if next == 0 {
                assert_eq!(count, data.len(), "EOF before full data");
                break;
            }
            count = next;
        }
        assert_eq!(joined(write), data.len());
        assert_eq!(joined(read), data);
        drop(release);
    });
    // The writer stream is still open: EOF above came from shutdown(Write).
    assert_eq!(written.load(Ordering::SeqCst), data.len());
}

/// The client's send buffer in the pure-ACK loss test (the kernel doubles it;
/// socket(7)): small, so once the client stops writing its queued data is
/// soon sent.
const ACK_LOSS_SNDBUF: libc::c_int = 32 * 1024;
/// The client's receive buffer in the pure-ACK loss test, doubled likewise:
/// past Zhida's 128 KiB of echo in flight, so while the client reads
/// Zhida never waits for the kernel's window to reopen, which only a pure
/// ACK would announce; but well under the echo still to come when the client
/// stops reading, so the kernel's window then closes.
const ACK_LOSS_RCVBUF: libc::c_int = 256 * 1024;

/// What the echo client reads from its loss thread's report.
trait LossReport: Send {
    /// How the failure message labels `dropped`.
    const DROPPED: &'static str;
    /// The pure ACKs the filters dropped.
    fn dropped(&self) -> String;
    /// Taken just after the last filter was deleted.
    fn removed(&self) -> Instant;
}

impl LossReport for LossWindow {
    const DROPPED: &'static str = "[to Zhida, to the kernel]";

    fn dropped(&self) -> String {
        format!("{:?}", self.dropped)
    }

    fn removed(&self) -> Instant {
        self.removed
    }
}

struct AckLossEcho<W> {
    kernel_port: u16,
    window: W,
    /// Filters removed to the last echoed byte read.
    recovery: Duration,
}

/// Write `ACK_LOSS_TRANSFER` bytes on one thread while reading the echo on
/// this one, through a stream `configure` sets up after its buffer sizes.
/// Initially write only `ACK_LOSS_AFTER` bytes. Once that many have echoed,
/// `loss` runs on a third thread: it installs pure-ACK `tc` filters, then allows
/// writing up to `ACK_LOSS_TRANSFER - ACK_LOSS_RESERVE`. The remaining bytes
/// stay held until the loss thread releases the full transfer. It pauses
/// reading or writing through `Paused`, and removes the filters. The echo must equal
/// what was written, arrive after the filters are removed and end with
/// Zhida's FIN within `ACK_LOSS_ECHO_DEADLINE`; otherwise the client resets
/// the connection and panics with the bytes written and echoed and the pure
/// ACKs dropped.
///
/// While the client reads and writes, every ACK Zhida sends rides on data:
/// EchoServer echoes whatever arrives. Pausing one side at a time leaves the
/// other's data to be acknowledged by pure ACKs alone.
fn echo_through_pure_ack_loss<W: LossReport>(
    configure: impl FnOnce(&TcpStream),
    loss: impl FnOnce(u16, Receiver<()>, &Paused, &AtomicUsize) -> Option<W> + Send,
) -> AckLossEcho<W> {
    let deadline = Instant::now() + ACK_LOSS_ECHO_DEADLINE;
    let mut stream = connect();
    set_socket_option(
        &stream,
        libc::SOL_SOCKET,
        libc::SO_RCVBUF,
        "SO_RCVBUF",
        &ACK_LOSS_RCVBUF,
    );
    set_socket_option(
        &stream,
        libc::SOL_SOCKET,
        libc::SO_SNDBUF,
        "SO_SNDBUF",
        &ACK_LOSS_SNDBUF,
    );
    configure(&stream);
    stream.set_read_timeout(Some(POLL)).unwrap();
    stream.set_write_timeout(Some(POLL)).unwrap();
    let kernel_port = local_port(&stream);
    let mut writer = stream.try_clone().unwrap();
    let data = payload(ACK_LOSS_TRANSFER, SEED);
    let paused = Paused {
        write_limit: AtomicUsize::new(ACK_LOSS_AFTER),
        ..Paused::default()
    };
    let progress = AtomicUsize::new(0);
    let (start, started) = mpsc::channel();
    let (written, echoed, delivered, eof, window) = thread::scope(|scope| {
        let (data, paused, progress) = (&data, &paused, &progress);
        let write = scope.spawn(move || {
            write_until(
                &mut writer,
                data,
                &paused.writing,
                &paused.write_limit,
                progress,
                deadline,
            )
        });
        let loss = scope.spawn(move || loss(kernel_port, started, paused, progress));
        let mut start = Some(start);
        let mut echoed = Vec::with_capacity(ACK_LOSS_TRANSFER);
        let mut delivered = None;
        let mut eof = false;
        let mut buffer = vec![0; MAX_CHUNK];
        while !eof && Instant::now() < deadline {
            if wait_while(&paused.reading) {
                continue;
            }
            match stream.read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(n) => {
                    echoed.extend_from_slice(&buffer[..n]);
                    if echoed.len() >= ACK_LOSS_AFTER {
                        if let Some(start) = start.take() {
                            start.send(()).unwrap();
                        }
                    }
                    if echoed.len() >= data.len() && delivered.is_none() {
                        delivered = Some(Instant::now());
                    }
                }
                Err(error) if timed_out(&error) => {}
                Err(error) => panic!("read echo: {error}"),
            }
        }
        // Lets the loss thread return if it never started.
        drop(start);
        (joined(write), echoed, delivered, eof, joined(loss))
    });
    if !eof || echoed.len() != data.len() {
        reset_on_close(&stream);
        drop(stream);
        panic!(
            "within {ACK_LOSS_ECHO_DEADLINE:?}: wrote {written} of {ACK_LOSS_TRANSFER} bytes, \
             echoed {}, EOF {eof}; pure ACKs dropped {}: {}",
            echoed.len(),
            W::DROPPED,
            window.map_or("loss never started".to_owned(), |w| w.dropped()),
        );
    }
    assert_echoed(&echoed, &data);
    let window = window.expect("loss started once ACK_LOSS_AFTER bytes echoed");
    let recovery = delivered
        .unwrap()
        .checked_duration_since(window.removed())
        .expect("the echo completed while pure ACKs were dropped");
    AckLossEcho {
        kernel_port,
        window,
        recovery,
    }
}

/// Whether sequence number `a` is after `b`, modulo 2^32.
fn after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// A data segment that starts below the end of the data already sent its
/// way, and when the byte it starts with was first captured.
#[derive(Debug, Clone, Copy)]
struct Retransmission {
    captured: Captured,
    first_sent: SystemTime,
}

impl Retransmission {
    fn since_first_sent(&self) -> Duration {
        self.captured.at.duration_since(self.first_sent).unwrap()
    }
}

/// Data segments travelling `direction` that start below the end of the data
/// already sent that way: retransmissions.
fn retransmissions(captured: &[Captured], direction: Direction) -> Vec<Retransmission> {
    // The end of each stretch of new data, in sending order, and when it was
    // sent; the last end is the end of the data sent so far.
    let mut sent: Vec<(u32, SystemTime)> = Vec::new();
    let mut found = Vec::new();
    for c in captured.iter().filter(|c| c.segment.direction == direction) {
        let s = c.segment;
        if s.len == 0 {
            continue;
        }
        if sent.last().is_some_and(|&(end, _)| after(end, s.seq)) {
            // The stretch holding s.seq is the first that ends after it.
            let at = sent.partition_point(|&(end, _)| !after(end, s.seq));
            found.push(Retransmission {
                captured: *c,
                first_sent: sent[at].1,
            });
        }
        let end = s.seq.wrapping_add(s.len);
        if sent
            .last()
            .is_none_or(|&(sent_end, _)| after(end, sent_end))
        {
            sent.push((end, c.at));
        }
    }
    found
}

/// The `retransmissions` of Zhida's data that smoltcp's retransmission
/// timeout sent, among those in the loss window. smoltcp resends data on a
/// timeout, on fast retransmit, or as a zero-window probe. Fast retransmit
/// needs three duplicate ACKs, and smoltcp counts only ACKs without payload
/// as duplicates (socket/tcp.rs:2099-2103); every pure ACK the kernel sends
/// in the window is dropped, so fast retransmit cannot fire there.
///
/// A zero-window probe repeats a sequence range, possibly a timeout later: it
/// forces the window to one byte (2659-2661) and sends that byte alone (2703)
/// at remote_last_seq, which it leaves unchanged (2810-2812), so each later
/// probe resends it; the probe delay starts at the RTO (2197-2199). One-byte
/// segments are excluded for that; a timeout resend of one byte could only
/// make the count lower.
///
/// Supporting evidence that a resend is a timeout: on expiry smoltcp resends
/// from SND.UNA (remote_last_seq rewound to local_seq_no, 2477-2488; segments
/// start at remote_last_seq, 2563). Its timer starts when data is sent while
/// it is not running (2838-2844) and restarts on an ACK of new data that
/// leaves data outstanding (2180-2182); either way the byte at SND.UNA is then
/// in flight or in the segment being sent, so the timer runs from no earlier
/// than that byte's first transmission. It runs at least `ZHIDA_RTO`, the
/// smallest base RTO any test here gives Zhida, which only backoff raises,
/// so the first segment of the resend comes at least that long after its
/// first byte was first sent, measured on capture times less `CAPTURE_SLACK`.
fn zhida_timeout_retransmissions(found: &[Retransmission]) -> Vec<Retransmission> {
    found
        .iter()
        .filter(|r| {
            r.captured.segment.len != 1 && r.since_first_sent() >= ZHIDA_RTO - CAPTURE_SLACK
        })
        .copied()
        .collect()
}

/// Pure ACKs travelling `direction` whose sequence number, the sender's
/// SND.NXT, is below the highest acknowledgment number the peer had sent,
/// the peer's RCV.NXT: the sender's SND.NXT is behind data the peer holds.
fn stale_pure_acks(captured: &[Captured], direction: Direction) -> Vec<Captured> {
    let mut peer_rcv_nxt: Option<u32> = None;
    let mut found = Vec::new();
    for c in captured {
        let s = c.segment;
        if s.direction != direction {
            if s.flags & ACK != 0 && peer_rcv_nxt.is_none_or(|next| after(s.ack, next)) {
                peer_rcv_nxt = Some(s.ack);
            }
        } else if s.flags == ACK
            && s.len == 0
            && peer_rcv_nxt.is_some_and(|next| after(next, s.seq))
        {
            found.push(*c);
        }
    }
    found
}

/// Payload bytes travelling `direction` captured in `from..to`.
fn data_sent_between(
    captured: &[Captured],
    direction: Direction,
    from: SystemTime,
    to: SystemTime,
) -> u32 {
    captured
        .iter()
        .filter(|c| c.segment.direction == direction && from <= c.at && c.at < to)
        .map(|c| c.segment.len)
        .sum()
}

/// Every captured segment belongs to the client's one connection.
fn assert_one_connection(segments: &[Segment], kernel_port: u16) {
    assert!(!segments.is_empty(), "no segment captured");
    assert!(
        segments.iter().all(|s| s.kernel_port == kernel_port),
        "segments of another connection captured"
    );
}

#[zhida_test_support::pinned_test]
fn tap_kernel_echo_with_tx_checksum_offload() {
    let offloads = Offloads {
        tx_tcp_checksum: true,
        tx_udp_checksum: false,
        ..Offloads::default()
    };
    let (transfer, captured) =
        serve_client_configured(DEADLINE, STANDARD, offloads, None, echo_one_mebibyte);
    let segments = segments(&captured);
    assert_one_connection(&segments, transfer.kernel_port);
    assert_eq!(close_kind(&segments), Close::Clean);
}

#[zhida_test_support::pinned_test]
fn linux_client_echoes_one_mebibyte_through_net_tap() {
    assert_linux_offers_tcp_options();
    let (transfer, captured) = serve_client(DEADLINE, echo_one_mebibyte);
    let segments = segments(&captured);

    let n = &transfer.negotiated;
    // print! here would land in the capture of whichever test spawned the
    // shared pinned worker; libtest never captures a direct stdout write.
    let record = format!(
        "kernel interop: options {:#04x} (timestamps {}, sack {}, wscale {}), \
         snd_wscale {}, rcv_wscale {}, snd_mss {}, transfer {:?}, {} segments captured\n",
        n.options,
        n.options & TCPI_OPT_TIMESTAMPS != 0,
        n.options & TCPI_OPT_SACK != 0,
        n.options & TCPI_OPT_WSCALE != 0,
        n.snd_wscale,
        n.rcv_wscale,
        n.snd_mss,
        transfer.elapsed,
        segments.len(),
    );
    io::stdout().write_all(record.as_bytes()).unwrap();
    assert_one_connection(&segments, transfer.kernel_port);
    assert_eq!(close_kind(&segments), Close::Clean);
    // Zhida's SYN-ACK to a Linux SYN offering MSS, SACK-permitted,
    // timestamps and window scale (smoltcp 0.14 socket/tcp.rs): SACK-permitted
    // echoed (1922, 2610); window scale = bit length of the 128 KiB RX
    // buffer (18) - 16 = 2 (587, 608, 905-906, 924, 1923, 2611); timestamps
    // off: the Stack installs no TSval generator (Stack::add_tcp), so the
    // SYN-ACK carries no timestamp option and the kernel sends none after.
    assert_eq!(n.options, TCPI_OPT_SACK | TCPI_OPT_WSCALE);
    assert_timestamps_only_on_kernel_syn(&segments);
    assert_eq!(n.snd_wscale, 2);
    // Zhida's SYN-ACK advertises MSS 1460: port_config's MTU 1500 gives
    // Port::frame_capacity 1514 (crates/dpdk-smoltcp/src/port.rs 339), which
    // Device reports as max_transmission_unit (device.rs 86), and smoltcp
    // fills the option with IP MTU 1500 - 20 - 20 (tcp.rs 2777-2780).
    let syn_acks: Vec<_> = segments
        .iter()
        .filter(|s| s.direction == Direction::ToKernel && s.flags & (SYN | ACK) == SYN | ACK)
        .map(|s| s.mss)
        .collect();
    assert!(!syn_acks.is_empty(), "no SYN-ACK captured");
    assert!(syn_acks.iter().all(|&mss| mss == Some(1460)), "SYN-ACK MSS {syn_acks:?}");
    // snd_mss 1460: the kernel sends at most the smaller of Zhida's 1460 and
    // its own 1500-byte MTU less 40, the same 1460, with no timestamp option
    // to subtract. It cannot tell which bound applied; the SYN-ACK check
    // above does.
    assert_eq!(n.snd_mss, 1460);
}

/// Only the kernel's SYN carries the timestamp option: Zhida declines it,
/// so no later segment either way carries one.
fn assert_timestamps_only_on_kernel_syn(segments: &[Segment]) {
    for s in segments {
        let kernel_syn = s.direction == Direction::ToZhida && s.flags & (SYN | ACK) == SYN;
        assert_eq!(s.timestamps, kernel_syn, "timestamp option presence on {s:?}");
    }
}

/// Zhida at MTU 9000 with the kernel side set to 9000
/// (`serve_client_configured` checks both MTUs before the client starts): both
/// ends advertise MSS 8960, checked before any data is written, and a 1 MiB
/// echo, more than 100 segments' worth at 8960 bytes each way, arrives intact.
#[zhida_test_support::pinned_test]
fn kernel_jumbo_echo() {
    assert_linux_offers_tcp_options();
    let (transfer, captured) = serve_client_configured(DEADLINE, JUMBO, Offloads::default(), None, || {
        // Bound before connect. The kernel's SYN reaches packet taps as it is
        // sent and Zhida's SYN-ACK before the kernel's TCP takes it in, so
        // both are queued here once connect returns. Closed after the check.
        let handshake = Capture::open();
        echo_one_mebibyte_checked(move |n| {
            let mut captured = Vec::new();
            handshake.drain_into(&mut captured);
            let segments = segments(&captured);
            let mss = |direction, flags| -> Vec<Option<u16>> {
                segments
                    .iter()
                    .filter(|s| s.direction == direction && s.flags & (SYN | ACK) == flags)
                    .map(|s| s.mss)
                    .collect()
            };
            // IP MTU 9000 - 20 - 20 from each end.
            for (name, mss) in [
                ("SYN", mss(Direction::ToZhida, SYN)),
                ("SYN-ACK", mss(Direction::ToKernel, SYN | ACK)),
            ] {
                assert!(!mss.is_empty(), "no {name} captured");
                assert!(mss.iter().all(|&mss| mss == Some(8960)), "{name} MSS {mss:?}");
            }
            assert_eq!(n.options & TCPI_OPT_TIMESTAMPS, 0);
            // The kernel reports its own MSS, 8960, with no timestamp option
            // to subtract.
            assert_eq!(n.advmss, 8960);
            // The smaller of Zhida's 8960 and the kernel's own limit at
            // MTU 9000, also 8960.
            assert_eq!(n.snd_mss, 8960);
        })
    });
    let segments = segments(&captured);
    assert_one_connection(&segments, transfer.kernel_port);
    assert_eq!(close_kind(&segments), Close::Clean);
    assert_timestamps_only_on_kernel_syn(&segments);
    // Each side sends at most 8960, and does send full segments of it.
    for direction in [Direction::ToZhida, Direction::ToKernel] {
        let lens: Vec<u32> = segments
            .iter()
            .filter(|s| s.direction == direction && s.len > 0)
            .map(|s| s.len)
            .collect();
        assert!(lens.iter().all(|&len| len <= 8960), "{direction:?} segment over 8960: {lens:?}");
        assert!(lens.iter().any(|&len| len == 8960), "{direction:?} no full segment: {lens:?}");
    }
}

#[zhida_test_support::pinned_test]
fn linux_client_reset_is_seen_and_server_relistens() {
    let (kernel_port, captured) = serve_client(DEADLINE, exchange_then_abort);
    let segments = segments(&captured);
    assert_one_connection(&segments, kernel_port);
    assert_eq!(close_kind(&segments), Close::Reset(Direction::ToZhida));
}

/// Linux and Zhida both time out with every pure ACK lost both ways after
/// data was streaming both ways, and recover once the loss stops.
#[zhida_test_support::pinned_test]
fn linux_bidirectional_bulk_recovers_from_pure_ack_loss() {
    let (echo, captured) = serve_client(ACK_LOSS_DEADLINE, || {
        echo_through_pure_ack_loss(|_| {}, pure_ack_loss)
    });
    let window = &echo.window;
    let in_window = |at: SystemTime| window.from <= at && at <= window.until;
    let since_start = |at: SystemTime| at.duration_since(window.from).unwrap();
    let retransmitted_in_window = |direction| -> Vec<Retransmission> {
        retransmissions(&captured, direction)
            .into_iter()
            .filter(|r| in_window(r.captured.at))
            .collect()
    };
    let zhida_retransmissions = retransmitted_in_window(Direction::ToKernel);
    let zhida_timeouts = zhida_timeout_retransmissions(&zhida_retransmissions);
    let linux_retransmissions = retransmitted_in_window(Direction::ToZhida);
    let stale_acks = stale_pure_acks(&captured, Direction::ToKernel);
    let stale_acks_after = stale_acks
        .iter()
        .filter(|c| c.at > window.after_delete)
        .count();
    let stale_acks: Vec<&Captured> = stale_acks.iter().filter(|c| in_window(c.at)).collect();
    // Every pure ACK Zhida sent while a filter could drop it; the capture
    // sees them before the ingress qdisc does.
    let pure_acks_to_kernel = captured
        .iter()
        .filter(|c| {
            let s = c.segment;
            s.direction == Direction::ToKernel
                && s.flags == ACK
                && s.len == 0
                && window.before_add <= c.at
                && c.at <= window.after_delete
        })
        .count();
    let streaming = [Direction::ToZhida, Direction::ToKernel].map(|direction| {
        data_sent_between(
            &captured,
            direction,
            window.from,
            window.from + ACK_LOSS_STREAMING,
        )
    });
    // Uncaptured, as for the options record. The kernel's pure ACKs never
    // reach the capture while dropped, so the stale count in the window is a
    // lower bound.
    let record = format!(
        "pure-ACK loss [to Zhida, to the kernel]: data bytes sent in the first \
         {ACK_LOSS_STREAMING:?} {streaming:?}; pure ACKs dropped {:?}, Zhida pure ACKs \
         captured while filtered {pure_acks_to_kernel}; client had written {} of \
         {ACK_LOSS_TRANSFER} bytes at the second phase; in the loss window Zhida \
         retransmitted {} times, {} on timeout (first {:?} after loss start, {:?} after its \
         first byte, {:?} bytes), and sent at least {} pure ACKs below the kernel's RCV.NXT \
         (first {:?}); Linux retransmitted {} times (first {:?}), TCPTimeouts +{} (+{} in the \
         second phase); after the filters were deleted Zhida sent {stale_acks_after} pure \
         ACKs below the kernel's RCV.NXT; filters removed to full echo {:?}; {} segments \
         captured\n",
        window.dropped,
        window.written_by_second_phase,
        zhida_retransmissions.len(),
        zhida_timeouts.len(),
        zhida_timeouts.first().map(|r| since_start(r.captured.at)),
        zhida_timeouts
            .first()
            .map(Retransmission::since_first_sent),
        zhida_timeouts.first().map(|r| r.captured.segment.len),
        stale_acks.len(),
        stale_acks.first().map(|c| since_start(c.at)),
        linux_retransmissions.len(),
        linux_retransmissions
            .first()
            .map(|r| since_start(r.captured.at)),
        window.linux_timeouts,
        window.linux_timeouts_second_phase,
        echo.recovery,
        captured.len(),
    );
    io::stdout().write_all(record.as_bytes()).unwrap();

    assert!(
        streaming.iter().all(|&bytes| bytes > 0),
        "data bytes sent in the first {ACK_LOSS_STREAMING:?} of the loss \
         [to Zhida, to the kernel]: {streaming:?}"
    );
    assert!(
        window.dropped.iter().all(|&n| n > 0),
        "pure ACKs dropped [to Zhida, to the kernel]: {:?}",
        window.dropped
    );
    // A filter that dropped anything else of Zhida's would count more.
    assert!(
        window.dropped[1] <= pure_acks_to_kernel as u64,
        "{} dropped toward the kernel, but Zhida sent only {pure_acks_to_kernel} pure ACKs \
         while filtered",
        window.dropped[1]
    );
    assert!(
        window.written_by_second_phase < ACK_LOSS_TRANSFER,
        "the client had written all {ACK_LOSS_TRANSFER} bytes before the second phase"
    );
    // By construction, given the client still had data to write: in the
    // second phase the echo fills the kernel's receive window within
    // milliseconds at these rates, after which Zhida can acknowledge the
    // kernel's data only with pure ACKs, all dropped, so Linux's RTO (200 ms
    // at least) expires within the 1.5 s phase. Zhida announces its own
    // window closing only in pure ACKs, so Linux does not see a zero window
    // and takes the counted timeout path.
    assert!(
        window.linux_timeouts_second_phase >= 1,
        "Linux did not time out in the second phase (TCPTimeouts +{} over the window)",
        window.linux_timeouts
    );
    assert!(
        !zhida_timeouts.is_empty(),
        "no Zhida timeout retransmission while pure ACKs were dropped; \
         retransmissions: {zhida_retransmissions:?}"
    );
    assert!(
        echo.recovery < ACK_LOSS_RECOVERY,
        "filters removed to full echo {:?}, over {ACK_LOSS_RECOVERY:?}",
        echo.recovery
    );
    let segments = segments(&captured);
    assert_one_connection(&segments, echo.kernel_port);
    assert_eq!(close_kind(&segments), Close::Clean);
}

/// TCP_KEEPIDLE and TCP_KEEPINTVL of the stale-ACK test's client, in seconds.
/// The kernel's first keepalive comes this long after the last segment it
/// accepted from Zhida, and the next ones this long apart
/// (tcp_keepalive_timer, net/ipv4/tcp_timer.c:820-843 in Linux v7.0).
const STALE_ACK_KEEPALIVE_SECS: libc::c_int = 2;
/// TCP_KEEPCNT of that client: the kernel resets the connection once this many
/// keepalives in a row go unanswered, checking before each next one
/// (tcp_keepalive_timer), so at the earliest 2 + 25 * 2 = 52 s after the last
/// segment it accepted, past `ACK_LOSS_ECHO_DEADLINE`: a failing run ends on
/// that deadline with the bytes echoed. Set, not left to
/// net.ipv4.tcp_keepalive_probes, also because the keepalives the filter
/// drops count as unanswered.
const STALE_ACK_KEEPALIVE_PROBES: libc::c_int = 25;
/// Zhida's base RTO in the stale-ACK test, set on its listeners: its
/// timeouts after the last new data then come 1 s and 3 s later (backoff
/// doubles it), so the kernel's keepalive, 2 s after that data
/// (`STALE_ACK_KEEPALIVE_SECS`), falls 1 s from each. With the 300 ms default
/// they would come 0.3, 0.9 and 2.1 s after that data: the keepalive would
/// follow two timeouts and lead the third by 0.1 s.
const STALE_ACK_RTO: Duration = Duration::from_secs(1);
/// Bound on waiting for Zhida's first timeout retransmission to reach the
/// kernel once the client stops writing. It is due `STALE_ACK_RTO` after
/// Zhida's timer last started (nothing expired before, so no backoff),
/// which is about when the client stopped.
const STALE_ACK_RTO_WAIT: Duration = Duration::from_secs(5);
/// Bound on waiting for the kernel's two keepalives after the filter is
/// removed, due within 2 * `STALE_ACK_KEEPALIVE_SECS` = 4 s.
const STALE_ACK_KEEPALIVE_WAIT: Duration = Duration::from_secs(8);
/// From the second keepalive to the client writing again: Zhida answers a
/// keepalive in the turn that reads it, so its answer precedes the client's
/// next data.
const STALE_ACK_ANSWER: Duration = Duration::from_millis(100);
/// Filter removed to the last echoed byte read. The client writes again with
/// its reserve released only after the second keepalive following removal,
/// at most 4 s plus `STALE_ACK_ANSWER` later; lossless, the rest of
/// `ACK_LOSS_TRANSFER` then echoes in well under a second. 10 s leaves room
/// for a shared CPU.
const STALE_ACK_RECOVERY: Duration = Duration::from_secs(10);

/// SO_KEEPALIVE on, with `STALE_ACK_KEEPALIVE_SECS` and
/// `STALE_ACK_KEEPALIVE_PROBES`.
fn stale_ack_keepalive(stream: &TcpStream) {
    let on: libc::c_int = 1;
    set_socket_option(
        stream,
        libc::SOL_SOCKET,
        libc::SO_KEEPALIVE,
        "SO_KEEPALIVE",
        &on,
    );
    let tcp = libc::IPPROTO_TCP;
    let secs = &STALE_ACK_KEEPALIVE_SECS;
    set_socket_option(stream, tcp, libc::TCP_KEEPIDLE, "TCP_KEEPIDLE", secs);
    set_socket_option(stream, tcp, libc::TCP_KEEPINTVL, "TCP_KEEPINTVL", secs);
    let probes = &STALE_ACK_KEEPALIVE_PROBES;
    set_socket_option(stream, tcp, libc::TCP_KEEPCNT, "TCP_KEEPCNT", probes);
}

/// Whether TcpExt `counter` reaches `target` by `deadline`, polled every
/// `PAUSED_POLL`; a reading taken after the deadline does not count.
fn tcp_ext_reaches(counter: &str, target: u64, deadline: Instant) -> bool {
    loop {
        let reached = tcp_ext(counter) >= target;
        let in_time = Instant::now() <= deadline;
        if reached || !in_time {
            return reached && in_time;
        }
        thread::sleep(PAUSED_POLL);
    }
}

/// Holds the client's writer off until dropped, also when the loss thread
/// panics, so the client runs on and the panic surfaces when it finishes
/// instead of at `ACK_LOSS_ECHO_DEADLINE`.
struct WriterHeld<'a>(&'a AtomicBool);

impl<'a> WriterHeld<'a> {
    fn new(writing: &'a AtomicBool) -> Self {
        writing.store(true, Ordering::SeqCst);
        Self(writing)
    }
}

impl Drop for WriterHeld<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

struct StaleAckWindow {
    /// The filter in place from `from` to `until`.
    from: SystemTime,
    until: SystemTime,
    /// Pure ACKs to Zhida dropped, read just after `until`.
    dropped: u64,
    /// Every filter under both parents before the filter was added and with it
    /// in place.
    filters_before: [String; 2],
    filters_installed: [String; 2],
    removed: Instant,
    /// The client stopping writing to the kernel taking in Zhida's timeout
    /// retransmission; None if not within `STALE_ACK_RTO_WAIT`.
    retransmission_received: Option<Duration>,
    /// Whether the kernel sent two keepalives within `STALE_ACK_KEEPALIVE_WAIT`
    /// of the filter being removed.
    keepalives_after_removal: bool,
    /// TCPACKSkippedSeq over the whole loss.
    acks_skipped: u64,
}

impl LossReport for StaleAckWindow {
    const DROPPED: &'static str = "to Zhida";

    fn dropped(&self) -> String {
        self.dropped.to_string()
    }

    fn removed(&self) -> Instant {
        self.removed
    }
}

/// The writer starts limited to `ACK_LOSS_AFTER`. Once `start` receives,
/// install the filter, then allow all but `ACK_LOSS_RESERVE` bytes to be written.
/// Drop the kernel's pure ACKs to Zhida (that
/// direction only) for `ACK_LOSS_STREAMING` with the client reading and
/// writing, then with the client not writing until the kernel has taken in
/// Zhida's first timeout retransmission, then remove the filter. The client
/// writes again with its reserve released only once the kernel has sent two
/// keepalives after that, and `STALE_ACK_ANSWER` later. None if `start`
/// disconnected without receiving.
fn stale_ack_loss(
    kernel_port: u16,
    start: Receiver<()>,
    paused: &Paused,
    _written: &AtomicUsize,
) -> Option<StaleAckWindow> {
    let write_limit_held = WriteLimitHeld {
        write_limit: &paused.write_limit,
        full: ACK_LOSS_TRANSFER,
    };
    start.recv().ok()?;
    let filters_before = tc_filters();
    let skipped = tcp_ext(TCP_ACK_SKIPPED_SEQ);
    let filter = DropFilters::install(kernel_port, &[Direction::ToZhida]);
    let from = SystemTime::now();
    paused
        .write_limit
        .store(ACK_LOSS_TRANSFER - ACK_LOSS_RESERVE, Ordering::SeqCst);
    let filters_installed = tc_filters();
    thread::sleep(ACK_LOSS_STREAMING);
    let retransmissions = tcp_ext(DELAYED_ACK_LOST);
    let writer_held = WriterHeld::new(&paused.writing);
    let stopped = Instant::now();
    // The kernel counts DelayedACKLost and queues its duplicate ACK, which the
    // filter drops, in the same softirq, microseconds apart; this thread polls
    // every millisecond and then runs `tc`, which takes milliseconds, to
    // delete the filter. Were that ACK ever let through, Zhida would catch
    // up before the kernel's keepalive, which `keepalive_answer` rejects,
    // failing the test, not passing it.
    let retransmission_received = tcp_ext_reaches(
        DELAYED_ACK_LOST,
        retransmissions + 1,
        stopped + STALE_ACK_RTO_WAIT,
    )
    .then(|| stopped.elapsed());
    let until = SystemTime::now();
    // The kernel's packets to Zhida meet the root qdisc.
    let dropped = filter_drops(TC_PARENTS[0].1);
    filter.remove();
    let removed = Instant::now();
    // Right after removal, before any other `tc` run. A keepalive sent between
    // the deletion and this read is not counted: the client then waits for
    // one more, a keepalive interval later.
    let keepalives = tcp_ext(TCP_KEEPALIVE);
    assert_eq!(tc_filters(), filters_before, "net_tap's filters changed");
    let keepalives_after_removal = tcp_ext_reaches(
        TCP_KEEPALIVE,
        keepalives + 2,
        removed + STALE_ACK_KEEPALIVE_WAIT,
    );
    thread::sleep(STALE_ACK_ANSWER);
    drop(write_limit_held);
    drop(writer_held);
    Some(StaleAckWindow {
        from,
        until,
        dropped,
        filters_before,
        filters_installed,
        removed,
        retransmission_received,
        keepalives_after_removal,
        acks_skipped: tcp_ext(TCP_ACK_SKIPPED_SEQ) - skipped,
    })
}

/// The kernel's first keepalive captured at or after a time, Zhida's answer
/// to it, and Zhida's timeout retransmission before it.
#[derive(Debug, Clone, Copy)]
struct KeepaliveAnswer {
    /// Zhida's last data segment before the keepalive.
    resend: Captured,
    keepalive: Captured,
    answer: Captured,
}

/// The `KeepaliveAnswer` in `captured`, if it shows Zhida answering the
/// kernel's keepalive at or after the kernel's RCV.NXT while a retransmission
/// timeout had left Zhida's resend point below it:
/// - the keepalive is the kernel's first pure ACK captured at or after `from`
///   one below the end of everything the kernel had sent (Linux sends a
///   keepalive at SND.UNA - 1 with nothing unacknowledged,
///   tcp_xmit_probe_skb); its ACK number is the kernel's RCV.NXT;
/// - Zhida's last data segment before it is one of `timeouts`: the resend
///   point is that segment's end;
/// - no kernel segment is captured between that resend and the keepalive, so
///   no ACK of the kernel's reached Zhida in between;
/// - the resend ends below the keepalive's ACK number;
/// - Zhida's next segment after the keepalive is a pure ACK at or after
///   that ACK number.
///
/// Otherwise the first check that fails.
fn keepalive_answer(
    captured: &[Captured],
    from: SystemTime,
    timeouts: &[Retransmission],
) -> Result<KeepaliveAnswer, String> {
    let from_kernel = |c: &Captured| c.segment.direction == Direction::ToZhida;
    let mut kernel_snd_nxt: Option<u32> = None;
    let mut keepalive_at = None;
    for (i, c) in captured.iter().enumerate().filter(|(_, c)| from_kernel(c)) {
        let s = c.segment;
        if c.at >= from
            && s.flags == ACK
            && s.len == 0
            && kernel_snd_nxt == Some(s.seq.wrapping_add(1))
        {
            keepalive_at = Some(i);
            break;
        }
        let control = u32::from(s.flags & SYN != 0) + u32::from(s.flags & FIN != 0);
        let end = s.seq.wrapping_add(s.len).wrapping_add(control);
        if kernel_snd_nxt.is_none_or(|next| after(end, next)) {
            kernel_snd_nxt = Some(end);
        }
    }
    let at = keepalive_at.ok_or("the kernel sent no keepalive")?;
    let keepalive = captured[at];
    let k = keepalive.segment;
    let resend_at = captured[..at]
        .iter()
        .rposition(|c| !from_kernel(c) && c.segment.len > 0)
        .ok_or("Zhida sent no data before the keepalive")?;
    let resend = captured[resend_at];
    let r = resend.segment;
    if !timeouts
        .iter()
        .any(|t| t.captured.at == resend.at && t.captured.segment == r)
    {
        return Err(format!(
            "Zhida's last data segment before the keepalive {k:?} is not a timeout \
             retransmission: {r:?}"
        ));
    }
    if let Some(between) = captured[resend_at + 1..at].iter().find(|c| from_kernel(c)) {
        return Err(format!(
            "the kernel sent {:?} between Zhida's timeout retransmission {r:?} and its \
             keepalive {k:?}",
            between.segment
        ));
    }
    if !after(k.ack, r.seq.wrapping_add(r.len)) {
        return Err(format!(
            "Zhida's timeout retransmission {r:?} reaches the keepalive's ACK number {k:?}"
        ));
    }
    let answer_at = captured[at + 1..]
        .iter()
        .position(|c| !from_kernel(c))
        .map(|i| at + 1 + i)
        .ok_or("Zhida did not answer the keepalive")?;
    if let Some(between) = captured[at + 1..answer_at].iter().find(|c| from_kernel(c)) {
        return Err(format!(
            "the kernel sent {:?} between its keepalive {k:?} and Zhida's answer",
            between.segment
        ));
    }
    let answer = captured[answer_at];
    let a = answer.segment;
    if !(a.flags == ACK && a.len == 0 && !after(k.ack, a.seq)) {
        return Err(format!(
            "Zhida's answer to the keepalive {k:?} is not a pure ACK at or after its ACK \
             number: {a:?}"
        ));
    }
    Ok(KeepaliveAnswer {
        resend,
        keepalive,
        answer,
    })
}

/// After smoltcp's retransmission timeout rewinds Zhida's resend point
/// (remote_last_seq) to SND.UNA, below data Linux already holds, Zhida's
/// pure ACKs still carry a sequence number at or after Linux's RCV.NXT: the
/// highest sequence number sent, clamped to Linux's window, as Linux's own
/// tcp_acceptable_seq does. Linux checks the sequence number before the ACK
/// field (tcp_rcv_established -> tcp_validate_incoming -> tcp_sequence), so a
/// pure ACK below RCV.NXT would be discarded as old, its ACK unread.
///
/// Only a segment Zhida answers without processing its ACK can draw a pure
/// ACK while the resend point is behind: any in-window segment from Linux
/// carries Linux's RCV.NXT, and smoltcp processes that ACK, which moves the
/// resend point up to it, before it acknowledges anything. Linux's
/// keepalives are pure ACKs at SND.UNA - 1 (tcp_xmit_probe_skb), one byte
/// below Zhida's receive window, which smoltcp answers with an ACK without
/// processing theirs, at most one a second.
///
/// So the client turns the kernel's keepalive on. Pure ACKs to Zhida are
/// dropped while both sides stream for `ACK_LOSS_STREAMING`; then the client
/// stops writing, so the kernel acknowledges Zhida's echo with pure ACKs
/// alone and Zhida times out, `STALE_ACK_RTO` after its last new data,
/// retransmitting from SND.UNA. Once the kernel has that retransmission, the
/// filter goes. Zhida's next timeout is two RTOs, 2 s, later (backoff
/// doubles it, `retransmission_timeout`), and nothing else of the kernel's
/// reaches Zhida before the kernel's next keepalive: the client still does
/// not write, and the kernel sends a keepalive only with nothing
/// unacknowledged and nothing queued, `STALE_ACK_KEEPALIVE_SECS` (2 s) after
/// the last segment it accepted from Zhida, that same last new data
/// (tcp_timer.c:820-843). So it comes about 1 s after removal and 1 s before
/// Zhida's next timeout, with Zhida's resend point still below the
/// kernel's RCV.NXT, and Zhida answers it at or after that RCV.NXT
/// (`keepalive_answer`). No pure ACK of Zhida's is ever below the kernel's
/// RCV.NXT. After the kernel's next keepalive the client writes again and the
/// echo completes.
#[zhida_test_support::pinned_test]
fn zhida_pure_ack_after_its_retransmission_timeout_is_not_below_linux_rcv_nxt() {
    let (echo, captured) = serve_client_configured(
        ACK_LOSS_DEADLINE,
        STANDARD,
        Offloads::default(),
        Some(STALE_ACK_RTO),
        || echo_through_pure_ack_loss(stale_ack_keepalive, stale_ack_loss),
    );
    let window = &echo.window;
    let since_start = |at: SystemTime| at.duration_since(window.from).unwrap();
    let zhida_timeouts =
        zhida_timeout_retransmissions(&retransmissions(&captured, Direction::ToKernel));
    let stale_acks = stale_pure_acks(&captured, Direction::ToKernel);
    let answer = keepalive_answer(&captured, window.until, &zhida_timeouts);
    let streaming = [Direction::ToZhida, Direction::ToKernel].map(|direction| {
        data_sent_between(
            &captured,
            direction,
            window.from,
            window.from + ACK_LOSS_STREAMING,
        )
    });
    let shown = |c: Captured| {
        let s = c.segment;
        format!(
            "{:?} flags {:#04x} seq {} ack {} len {}",
            since_start(c.at),
            s.flags,
            s.seq,
            s.ack,
            s.len
        )
    };
    let shown_answer = match &answer {
        Ok(a) => format!(
            "resend [{}], keepalive [{}], answer [{}]",
            shown(a.resend),
            shown(a.keepalive),
            shown(a.answer)
        ),
        Err(error) => format!("keepalive answer not shown: {error}"),
    };
    // Uncaptured, as for the options record.
    let record = format!(
        "pure ACK after timeout: data bytes sent in the first {ACK_LOSS_STREAMING:?} [to \
         Zhida, to the kernel] {streaming:?}; pure ACKs to Zhida dropped {}; kernel took in \
         Zhida's timeout retransmission {:?} after the client stopped writing; filter in place \
         {:?}; Zhida timeout retransmissions {} (first {:?} after loss start, {:?} after its \
         first byte); Zhida pure ACKs below the kernel's RCV.NXT {} (first {:?}); \
         {shown_answer}; two keepalives after removal {}; TCPACKSkippedSeq +{}; filter \
         removed to full echo {:?}; {} segments captured\n",
        window.dropped,
        window.retransmission_received,
        window.until.duration_since(window.from).unwrap(),
        zhida_timeouts.len(),
        zhida_timeouts.first().map(|r| since_start(r.captured.at)),
        zhida_timeouts
            .first()
            .map(Retransmission::since_first_sent),
        stale_acks.len(),
        stale_acks.first().map(|c| since_start(c.at)),
        window.keepalives_after_removal,
        window.acks_skipped,
        echo.recovery,
        captured.len(),
    );
    io::stdout().write_all(record.as_bytes()).unwrap();

    assert!(
        streaming.iter().all(|&bytes| bytes > 0),
        "data bytes sent in the first {ACK_LOSS_STREAMING:?} of the loss \
         [to Zhida, to the kernel]: {streaming:?}"
    );
    assert!(window.dropped > 0, "no pure ACK to Zhida dropped");
    // Zhida's packets meet the ingress qdisc, which kept net_tap's filters
    // alone, so nothing of Zhida's was dropped.
    assert_eq!(
        window.filters_installed[1], window.filters_before[1],
        "a filter was added toward the kernel"
    );
    assert_ne!(
        window.filters_installed[0], window.filters_before[0],
        "no filter was added toward Zhida"
    );
    assert!(
        window.retransmission_received.is_some(),
        "the kernel took in no retransmission within {STALE_ACK_RTO_WAIT:?} of the client \
         stopping writing (TcpExt {DELAYED_ACK_LOST} unchanged)"
    );
    assert!(
        window.keepalives_after_removal,
        "the kernel did not send two keepalives within {STALE_ACK_KEEPALIVE_WAIT:?} of the \
         filter being removed (TcpExt {TCP_KEEPALIVE})"
    );
    assert_eq!(
        window.acks_skipped, 0,
        "the kernel withheld answers to out-of-window ACKs for its rate limit \
         (TcpExt {TCP_ACK_SKIPPED_SEQ})"
    );
    if let Err(error) = answer {
        panic!("{error}");
    }
    assert!(
        stale_acks.is_empty(),
        "Zhida sent pure ACKs below the kernel's RCV.NXT: {stale_acks:?}"
    );
    assert!(
        echo.recovery < STALE_ACK_RECOVERY,
        "filter removed to full echo {:?}, over {STALE_ACK_RECOVERY:?}",
        echo.recovery
    );
    let segments = segments(&captured);
    assert_one_connection(&segments, echo.kernel_port);
    assert_eq!(close_kind(&segments), Close::Clean);
}

/// What the client in `failed_run_cleans_up_for_the_next` panics with.
struct ClientFailed;

/// A client panicking with the pure-ACK filters installed deletes them while
/// it unwinds; serve_client then fails with that panic, dropping the Port and
/// removing the vdev, so the next run in this binary opens it again.
#[zhida_test_support::pinned_test]
fn failed_run_cleans_up_for_the_next() {
    let failed = panic::catch_unwind(|| {
        serve_client(DEADLINE, || {
            let before = tc_filters();
            let unwound = panic::catch_unwind(|| {
                let _filters =
                    DropFilters::install(ECHO_PORT, &[Direction::ToZhida, Direction::ToKernel]);
                panic_any(ClientFailed)
            });
            assert!(unwound.is_err_and(|panic| panic.is::<ClientFailed>()));
            assert_eq!(tc_filters(), before, "filters left after the panic");
            panic_any(ClientFailed)
        })
    })
    .unwrap_err();
    assert!(
        failed.is::<ClientFailed>(),
        "serve_client failed with something other than the client's panic"
    );
    assert_eq!(ifindex(IFACE), 0, "{IFACE:?} left after the failure");

    let (kernel_port, captured) = serve_client(DEADLINE, exchange_then_abort);
    let segments = segments(&captured);
    assert_one_connection(&segments, kernel_port);
    assert_eq!(close_kind(&segments), Close::Reset(Direction::ToZhida));
}

/// Outside Zhida's /24. The kernel owns it as a /32 on `IFACE` beside
/// `KERNEL_ADDR`, so it goes with the netdev when the vdev is removed, on a
/// failure too.
const OFF_SUBNET_ADDR: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const OFF_SUBNET_PORT: u16 = 9000;
const ZHIDA_CLIENT_PORT: u16 = 49152;
const OFF_SUBNET_TRANSFER: usize = 256 * 1024;
const ZHIDA_BUFFER: usize = 64 * 1024;
const INGRESS_BUDGET: usize = 32;
/// Between turns in which nothing moved.
const IDLE_SLEEP: Duration = Duration::from_millis(1);
/// How long the gateway-less connect is driven. The SYN never leaves:
/// each failed dispatch silences the socket for DISCOVERY_SILENT_TIME (1 s,
/// iface/socket_meta.rs:46), after which smoltcp tries again, so 3 s covers
/// at least two retries.
const NO_ROUTE_WINDOW: Duration = Duration::from_secs(3);
const NO_ROUTE_TURN_SLEEP: Duration = Duration::from_millis(10);

const ETHERNET_HEADER: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;

/// The start of one Ethernet frame on `IFACE`.
#[derive(Debug)]
struct Frame {
    /// AF_PACKET `sll_pkttype`.
    pkttype: u8,
    bytes: Vec<u8>,
}

/// An Ethernet/IPv4 ARP packet.
#[derive(Debug, Clone, Copy)]
struct Arp {
    operation: u16,
    sender_mac: EthernetAddress,
    sender: Ipv4Addr,
    target: Ipv4Addr,
}

#[derive(Debug, Clone, Copy)]
struct Tcp {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    flags: u8,
    seq: u32,
    ack: u32,
    /// Payload bytes, from the IP total length.
    len: u32,
}

impl Frame {
    /// Zhida wrote it through the PMD: the kernel received it rather than
    /// sent it.
    fn from_zhida(&self) -> bool {
        self.pkttype != libc::PACKET_OUTGOING
    }

    fn destination(&self) -> EthernetAddress {
        EthernetAddress::from_bytes(&self.bytes[..6])
    }

    fn ethertype(&self) -> u16 {
        u16::from_be_bytes([self.bytes[12], self.bytes[13]])
    }

    fn arp(&self) -> Option<Arp> {
        if self.ethertype() != ETHERTYPE_ARP {
            return None;
        }
        let arp = self.bytes.get(ETHERNET_HEADER..ETHERNET_HEADER + 28)?;
        let address = |at: usize| Ipv4Addr::new(arp[at], arp[at + 1], arp[at + 2], arp[at + 3]);
        Some(Arp {
            operation: u16::from_be_bytes([arp[6], arp[7]]),
            sender_mac: EthernetAddress::from_bytes(&arp[8..14]),
            sender: address(14),
            target: address(24),
        })
    }

    fn tcp(&self) -> Option<Tcp> {
        if self.ethertype() != ETHERTYPE_IPV4 {
            return None;
        }
        let ip = &self.bytes[ETHERNET_HEADER..];
        if ip.len() < 20 || i32::from(ip[9]) != libc::IPPROTO_TCP {
            return None;
        }
        let ip_header = usize::from(ip[0] & 0x0f) * 4;
        let tcp = ip.get(ip_header..ip_header + 20)?;
        let address = |at: usize| Ipv4Addr::new(ip[at], ip[at + 1], ip[at + 2], ip[at + 3]);
        let word = |at: usize| u32::from_be_bytes([tcp[at], tcp[at + 1], tcp[at + 2], tcp[at + 3]]);
        let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
        let len = total
            .checked_sub(ip_header + usize::from(tcp[12] >> 4) * 4)
            .expect("IP total length covers both headers");
        Some(Tcp {
            source: address(12),
            destination: address(16),
            flags: tcp[13],
            seq: word(4),
            ack: word(8),
            len: u32::try_from(len).unwrap(),
        })
    }
}

/// A frame capture and every frame drained from it so far.
struct Recording {
    capture: Capture,
    frames: Vec<Frame>,
}

impl Recording {
    /// Drain the capture; returns every frame so far.
    fn record(&mut self) -> &[Frame] {
        self.capture.drain_frames(&mut self.frames);
        &self.frames
    }
}

/// Zhida has sent an ACK covering a FIN from `OFF_SUBNET_ADDR`.
fn kernel_fin_acked(frames: &[Frame]) -> bool {
    let tcp = |from_zhida: bool| {
        frames
            .iter()
            .filter(move |f| f.from_zhida() == from_zhida)
            .filter_map(Frame::tcp)
    };
    let Some(fin) = tcp(false).find(|t| t.source == OFF_SUBNET_ADDR && t.flags & FIN != 0) else {
        return false;
    };
    let after_fin = fin.seq.wrapping_add(fin.len).wrapping_add(1);
    tcp(true).any(|t| t.flags & ACK != 0 && t.ack == after_fin)
}

fn stack_now(start: Instant) -> StackInstant {
    StackInstant::from_micros(i64::try_from(start.elapsed().as_micros()).unwrap())
}

/// Zhida (`stack_config` with `gateway`) on a fresh net_tap Port connects
/// one socket from `ZHIDA_CLIENT_PORT` to a kernel listener on
/// `OFF_SUBNET_ADDR`; `drive` then runs the Stack, given the socket, the
/// listener, the Stack's start time and the frame recording, to be drained
/// every turn. Returns its result and every frame captured on `IFACE`
/// meanwhile. Tears down the Port with pools at 0; on a failure, unwinding
/// drops the Port and then removes the vdev, and with it `OFF_SUBNET_ADDR`.
fn connect_off_subnet<T>(
    gateway: Option<Ipv4Address>,
    drive: impl FnOnce(&mut Stack, TcpHandle, TcpListener, Instant, &mut Recording) -> T,
) -> (T, Vec<Frame>) {
    with_eal(|eal| {
        // Declared before the Port, so a failure drops the Port first.
        let tap = TapVdev::new(VDEV, IFACE);
        let port = open(eal, &tap, STANDARD);
        set_kernel_address();
        let off_subnet = format!("{OFF_SUBNET_ADDR}/32");
        run(
            "ip",
            &[
                "address",
                "add",
                &off_subnet,
                "dev",
                IFACE.to_str().unwrap(),
            ],
        );
        let listener = TcpListener::bind(SocketAddrV4::new(OFF_SUBNET_ADDR, OFF_SUBNET_PORT))
            .expect("bind the off-subnet listener");
        let mut recording = Recording {
            capture: Capture::frames(),
            frames: Vec::new(),
        };
        assert_no_receive_steering();
        let start = Instant::now();
        let config = StackConfig {
            max_udp_sockets: 0,
            gateway,
            ..stack_config()
        };
        let mut stack = Stack::new(port, config, StackInstant::ZERO)
            .map_err(|(_, error)| error)
            .unwrap();
        let handle = stack
            .add_tcp(tcp::Config { rx_capacity: ZHIDA_BUFFER, tx_capacity: ZHIDA_BUFFER, mss_cap: None })
            .unwrap();
        stack
            .connect(
                &handle,
                (OFF_SUBNET_ADDR, OFF_SUBNET_PORT),
                ZHIDA_CLIENT_PORT,
            )
            .unwrap();

        let result = drive(&mut stack, handle, listener, start, &mut recording);
        recording.record();
        assert_eq!(recording.capture.drops(), 0, "capture dropped packets");

        let port = stack.into_port();
        // net_tap holds one RX buffer per descriptor while started; nothing else.
        assert_eq!(in_use(RX_POOL), u32::from(port.descriptor_counts().0));
        assert_eq!(in_use(TX_POOL), 0);
        close(port, tap);
        (result, recording.frames)
    })
}

/// `call` again while it fails with EINTR: signals reach the kernel-side
/// thread while the Stack runs (its read failed with EINTR in a run).
fn uninterrupted<T>(mut call: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match call() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

/// Accepts one connection from Zhida's client port, echoes
/// `OFF_SUBNET_TRANSFER` bytes, reads Zhida's FIN, then closes it.
fn echo_once(listener: TcpListener) {
    listener.set_nonblocking(true).unwrap();
    let started = Instant::now();
    let mut stream = loop {
        match uninterrupted(|| listener.accept()) {
            Ok((stream, peer)) => {
                let zhida = SocketAddrV4::new(ZHIDA_ADDR, ZHIDA_CLIENT_PORT);
                assert_eq!(peer, SocketAddr::V4(zhida));
                break stream;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(
                    started.elapsed() < CONNECT_TIMEOUT,
                    "no connection within {CONNECT_TIMEOUT:?}"
                );
                thread::sleep(IDLE_SLEEP);
            }
            Err(error) => panic!("accept: {error}"),
        }
    };
    stream.set_nonblocking(false).unwrap();
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    let mut buffer = vec![0; MAX_CHUNK];
    let mut echoed = 0;
    while echoed < OFF_SUBNET_TRANSFER {
        let n = uninterrupted(|| stream.read(&mut buffer)).expect("read");
        assert_ne!(n, 0, "EOF after {echoed} bytes");
        stream.write_all(&buffer[..n]).expect("write");
        echoed += n;
    }
    let n = uninterrupted(|| stream.read(&mut buffer)).expect("read");
    assert_eq!(n, 0, "data past the transfer");
}

/// Zhida 192.0.2.2/24 with gateway 192.0.2.1 reaches a kernel listener on
/// 198.51.100.1, outside its subnet: it asks ARP for the gateway only, sends
/// every segment to the gateway's MAC, gets its bytes echoed, and the
/// connection closes with a FIN each way. Zhida closes first, so its
/// discarded socket, not the kernel, holds TIME-WAIT for the fixed 4-tuple and
/// a rerun within a minute in the same namespace connects afresh.
///
/// Temporary until Zhida's smoltcp fork: smoltcp 0.14 ignores ARP whose
/// sender IP is outside our subnet (iface/interface/ipv4.rs:288), while RFC
/// 826's receiver algorithm answers any request for its own address
/// whatever the sender's address, as Linux does. A gateway-side host that
/// ARPs for 192.0.2.2 from another source address, such as 198.51.100.1,
/// therefore gets no answer. This exchange works because Linux learns
/// Zhida's MAC from Zhida's own ARP request for the gateway.
#[zhida_test_support::pinned_test]
fn zhida_reaches_off_subnet_kernel_through_gateway() {
    let data = payload(OFF_SUBNET_TRANSFER, SEED);
    let (echoed, frames) = connect_off_subnet(
        Some(KERNEL_ADDR),
        |stack, handle, listener, start, recording| {
            thread::scope(|scope| {
                let mut kernel = Some(scope.spawn(move || echo_once(listener)));
                let mut sent = 0;
                let mut echoed = Vec::with_capacity(data.len());
                let mut closed = false;
                loop {
                    assert!(
                        start.elapsed() < DEADLINE,
                        "echo and close not done within {DEADLINE:?}: {:?}, {} bytes echoed",
                        stack.tcp(&handle).state(),
                        echoed.len()
                    );
                    let turn = stack.turn(stack_now(start), INGRESS_BUDGET).unwrap();
                    let fin_acked = kernel_fin_acked(recording.record());
                    if kernel.as_ref().is_some_and(|k| k.is_finished()) {
                        joined(kernel.take().unwrap());
                    }
                    let socket = stack.tcp_mut(&handle);
                    let mut moved = false;
                    if sent < data.len() && socket.can_send() {
                        let n = socket.send_slice(&data[sent..]).unwrap();
                        sent += n;
                        moved |= n != 0;
                    }
                    if sent == data.len() && !closed {
                        socket.close();
                        closed = true;
                        moved = true;
                    }
                    while socket.can_recv() {
                        let frame = socket.recv().unwrap().unwrap();
                        echoed.extend_from_slice(frame.payload());
                        moved = true;
                    }
                    match socket.state() {
                        State::Closed => panic!("connection closed without TIME-WAIT"),
                        // TIME-WAIT alone does not prove Zhida's ACK of the
                        // kernel's FIN left: smoltcp may delay it (ack_delay,
                        // 10 ms by default). Once it is captured the kernel's
                        // socket is closed, so a rerun's SYN on this 4-tuple
                        // finds no LAST-ACK socket.
                        State::TimeWait if kernel.is_none() && fin_acked => break,
                        _ => {}
                    }
                    if turn.rx_received == 0 && turn.tx_accepted == 0 && !moved {
                        thread::sleep(IDLE_SLEEP);
                    }
                }
                echoed
            })
        },
    );
    assert_echoed(&echoed, &data);

    let requests: Vec<Arp> = frames
        .iter()
        .filter(|f| f.from_zhida())
        .filter_map(Frame::arp)
        .filter(|a| a.operation == ARP_REQUEST)
        .collect();
    assert!(!requests.is_empty(), "Zhida sent no ARP request");
    assert!(
        requests.iter().all(|a| a.target == KERNEL_ADDR),
        "Zhida asked ARP for more than the gateway: {requests:?}"
    );
    let gateway_macs: Vec<EthernetAddress> = frames
        .iter()
        .filter(|f| !f.from_zhida())
        .filter_map(Frame::arp)
        .filter(|a| a.operation == ARP_REPLY && a.sender == KERNEL_ADDR)
        .map(|a| a.sender_mac)
        .collect();
    let gateway_mac = *gateway_macs
        .first()
        .expect("no kernel ARP reply for the gateway");
    assert!(gateway_macs.iter().all(|&mac| mac == gateway_mac));

    let mut from_zhida = Vec::new();
    for frame in frames.iter().filter(|f| f.from_zhida()) {
        if frame.arp().is_some() {
            continue;
        }
        let tcp = frame
            .tcp()
            .unwrap_or_else(|| panic!("Zhida sent neither ARP nor TCP: {frame:?}"));
        assert_eq!(tcp.destination, OFF_SUBNET_ADDR, "{tcp:?}");
        assert_eq!(frame.destination(), gateway_mac, "{tcp:?}");
        from_zhida.push(tcp);
    }
    let from_kernel: Vec<Tcp> = frames
        .iter()
        .filter(|f| !f.from_zhida())
        .filter_map(Frame::tcp)
        .filter(|t| t.source == OFF_SUBNET_ADDR)
        .collect();
    for (side, segments) in [("Zhida", &from_zhida), ("kernel", &from_kernel)] {
        assert!(
            segments.iter().any(|t| t.flags & FIN != 0),
            "no FIN from the {side}"
        );
        assert!(
            segments.iter().all(|t| t.flags & RST == 0),
            "RST from the {side}"
        );
    }
}

/// Without a gateway the same connect never leaves Zhida: smoltcp finds no
/// route to 198.51.100.1 before it picks a neighbor (lookup_hardware_addr,
/// iface/interface/mod.rs:1127-1129), so it sends neither the SYN nor an ARP
/// request, and the socket stays in SynSent.
#[zhida_test_support::pinned_test]
fn zhida_without_gateway_sends_nothing_off_subnet() {
    let ((turns, tx_accepted), frames) =
        connect_off_subnet(None, |stack, handle, _listener, start, recording| {
            let mut turns = 0;
            let mut tx_accepted = 0;
            while start.elapsed() < NO_ROUTE_WINDOW {
                let turn = stack.turn(stack_now(start), INGRESS_BUDGET).unwrap();
                recording.record();
                tx_accepted += turn.tx_accepted;
                turns += 1;
                assert_eq!(stack.tcp(&handle).state(), State::SynSent);
                thread::sleep(NO_ROUTE_TURN_SLEEP);
            }
            (turns, tx_accepted)
        });
    assert_eq!(tx_accepted, 0, "PMD accepted frames over {turns} turns");
    let sent: Vec<&Frame> = frames.iter().filter(|f| f.from_zhida()).collect();
    assert!(sent.is_empty(), "Zhida sent over {turns} turns: {sent:?}");
}

fn hand_built(direction: Direction, flags: u8, seq: u32, ack: u32, len: u32) -> Segment {
    Segment {
        direction,
        kernel_port: 40000,
        flags,
        seq,
        ack,
        len,
        mss: None,
        timestamps: false,
    }
}

#[test]
fn close_kind_classifies_hand_built_captures() {
    use Direction::{ToZhida as K, ToKernel as C};
    let incomplete = |kernel_fin, zhida_fin, zhida_fin_acked| Close::Incomplete {
        kernel_fin,
        zhida_fin,
        zhida_fin_acked,
    };
    // The kernel's FIN is at 1000, Zhida's at 5000.
    let kernel_fin = hand_built(K, FIN | ACK, 1000, 5000, 0);
    let zhida_fin = hand_built(C, FIN | ACK, 5000, 1001, 0);
    let fin_acked = hand_built(K, ACK, 1001, 5001, 0);
    let cases = [
        (
            "clean",
            vec![kernel_fin, zhida_fin, fin_acked],
            Close::Clean,
        ),
        (
            "Zhida closes first",
            vec![
                hand_built(C, FIN | ACK, 5000, 1000, 0),
                hand_built(K, FIN | ACK, 1000, 5001, 0),
            ],
            Close::Clean,
        ),
        (
            "no kernel FIN",
            vec![zhida_fin, fin_acked],
            incomplete(false, true, true),
        ),
        (
            "no Zhida FIN",
            vec![kernel_fin, hand_built(C, ACK, 5000, 1001, 0)],
            incomplete(true, false, false),
        ),
        (
            "no ACK of Zhida's FIN",
            vec![kernel_fin, zhida_fin],
            incomplete(true, true, false),
        ),
        (
            "matching ACK only before Zhida's FIN",
            vec![hand_built(K, FIN | ACK, 1000, 5001, 0), zhida_fin],
            incomplete(true, true, false),
        ),
        (
            "ACK of the FIN's sequence number, not past it",
            vec![kernel_fin, zhida_fin, hand_built(K, ACK, 1001, 5000, 0)],
            incomplete(true, true, false),
        ),
        (
            "matching ack field without the ACK flag",
            vec![kernel_fin, zhida_fin, hand_built(K, 0, 1001, 5001, 0)],
            incomplete(true, true, false),
        ),
        (
            "matching ack field from Zhida",
            vec![kernel_fin, zhida_fin, hand_built(C, ACK, 5001, 5001, 0)],
            incomplete(true, true, false),
        ),
        (
            "Zhida's FIN carries 100 bytes",
            vec![
                kernel_fin,
                hand_built(C, FIN | ACK, 5000, 1001, 100),
                hand_built(K, ACK, 1001, 5101, 0),
            ],
            Close::Clean,
        ),
        (
            "data-carrying FIN, only the data acknowledged",
            vec![
                kernel_fin,
                hand_built(C, FIN | ACK, 5000, 1001, 100),
                hand_built(K, ACK, 1001, 5100, 0),
            ],
            incomplete(true, true, false),
        ),
        (
            "FIN past the sequence wrap",
            vec![
                kernel_fin,
                hand_built(C, FIN | ACK, 0xffff_fff0, 1001, 0x20),
                hand_built(K, ACK, 1001, 0x11, 0),
            ],
            Close::Clean,
        ),
        (
            "FIN at the last sequence number",
            vec![
                kernel_fin,
                hand_built(C, FIN | ACK, u32::MAX, 1001, 0),
                hand_built(K, ACK, 1001, 0, 0),
            ],
            Close::Clean,
        ),
        (
            "kernel resets",
            vec![
                hand_built(K, ACK, 1000, 5000, 100),
                hand_built(K, RST | ACK, 1100, 5000, 0),
            ],
            Close::Reset(K),
        ),
        (
            "Zhida resets",
            vec![hand_built(C, RST | ACK, 5000, 1000, 0)],
            Close::Reset(C),
        ),
        (
            "RST after both FINs and the ACK",
            vec![
                kernel_fin,
                zhida_fin,
                fin_acked,
                hand_built(C, RST, 5001, 0, 0),
            ],
            Close::Reset(C),
        ),
        (
            "kernel RST after its FIN",
            vec![kernel_fin, hand_built(K, RST, 1001, 0, 0)],
            Close::Reset(K),
        ),
        (
            "first RST decides the direction",
            vec![
                hand_built(C, RST, 5000, 0, 0),
                hand_built(K, RST, 1000, 0, 0),
            ],
            Close::Reset(C),
        ),
    ];
    for (name, segments, expected) in cases {
        assert_eq!(close_kind(&segments), expected, "{name}");
    }
}

#[test]
fn segment_reads_headers_with_options() {
    // Kernel 192.0.2.1:40000 -> Zhida 192.0.2.2:8080, FIN|ACK, 10 payload
    // bytes not captured. IHL 6 (router alert option), TCP data offset 8 (NOP,
    // NOP, timestamps).
    #[rustfmt::skip]
    let sent: [u8; 56] = [
        0x46, 0x00, 0x00, 66, // version 4, IHL 6; total length 24 + 32 + 10
        0x00, 0x00, 0x40, 0x00, // id; DF
        64, 6, 0x00, 0x00, // TTL; TCP; checksum
        192, 0, 2, 1,
        192, 0, 2, 2,
        0x94, 0x04, 0x00, 0x00, // router alert
        0x9c, 0x40, 0x1f, 0x90, // ports 40000 -> 8080
        0x01, 0x02, 0x03, 0x04, // seq
        0xff, 0xff, 0xff, 0xfe, // ack
        0x80, 0x11, 0x01, 0xf5, // data offset 8; FIN|ACK; window
        0x00, 0x00, 0x00, 0x00, // checksum; urgent pointer
        0x01, 0x01, 0x08, 0x0a, // NOP, NOP, timestamps
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x02,
    ];
    assert_eq!(
        segment(libc::PACKET_OUTGOING, &sent),
        Some(Segment {
            direction: Direction::ToZhida,
            kernel_port: 40000,
            flags: FIN | ACK,
            seq: 0x0102_0304,
            ack: 0xffff_fffe,
            len: 10,
            mss: None,
            timestamps: true,
        })
    );

    // Zhida 192.0.2.2:8080 -> kernel 192.0.2.1:40000, RST|ACK, no options.
    #[rustfmt::skip]
    let received: [u8; 40] = [
        0x45, 0x00, 0x00, 40,
        0x00, 0x00, 0x00, 0x00,
        64, 6, 0x00, 0x00,
        192, 0, 2, 2,
        192, 0, 2, 1,
        0x1f, 0x90, 0x9c, 0x40,
        0x00, 0x00, 0x00, 0x07,
        0x00, 0x00, 0x00, 0x09,
        0x50, 0x14, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(
        segment(libc::PACKET_HOST, &received),
        Some(Segment {
            direction: Direction::ToKernel,
            kernel_port: 40000,
            flags: RST | ACK,
            seq: 7,
            ack: 9,
            len: 0,
            mss: None,
            timestamps: false,
        })
    );
    assert_eq!(segment(libc::PACKET_BROADCAST, &received), None);
    let mut other_port = received;
    other_port[21] = 0x91;
    assert_eq!(segment(libc::PACKET_HOST, &other_port), None);
}

#[test]
fn segment_reads_the_mss_option_of_a_syn_ack() {
    // Zhida 192.0.2.2:8080 -> kernel 192.0.2.1:40000, SYN|ACK, with
    // Zhida's options as fuzz/packetdrill/scripts/handshake-linux-options.pkt
    // 60 records them: mss 1460, wscale 2, sackOK, TS val 100 ecr 1000, eol.
    #[rustfmt::skip]
    let syn_ack: [u8; 60] = [
        0x45, 0x00, 0x00, 60,
        0x00, 0x00, 0x00, 0x00,
        64, 6, 0x00, 0x00,
        192, 0, 2, 2,
        192, 0, 2, 1,
        0x1f, 0x90, 0x9c, 0x40,
        0x00, 0x00, 0x00, 0x07,
        0x00, 0x00, 0x00, 0x01,
        0xa0, 0x12, 0xff, 0xff, // data offset 10; SYN|ACK; window
        0x00, 0x00, 0x00, 0x00,
        0x02, 0x04, 0x05, 0xb4, // mss 1460
        0x03, 0x03, 0x02, // wscale 2
        0x04, 0x02, // sackOK
        0x08, 0x0a, 0x00, 0x00, 0x00, 100, 0x00, 0x00, 0x03, 0xe8, // TS
        0x00, // eol
    ];
    let expected = Segment {
        direction: Direction::ToKernel,
        kernel_port: 40000,
        flags: SYN | ACK,
        seq: 7,
        ack: 1,
        len: 0,
        mss: Some(1460),
        timestamps: true,
    };
    assert_eq!(segment(libc::PACKET_HOST, &syn_ack), Some(expected));
    let without_timestamps = Segment { timestamps: false, ..expected };
    let without_mss = Segment { mss: None, ..without_timestamps };

    // The capture cut off inside the MSS option, or after only its kind:
    // the header fields still parse.
    for captured in [42, 41] {
        assert_eq!(segment(libc::PACKET_HOST, &syn_ack[..captured]), Some(without_mss));
    }
    // Cut off after it: later options are not needed for the MSS.
    assert_eq!(segment(libc::PACKET_HOST, &syn_ack[..44]), Some(without_timestamps));
    // Cut off inside the timestamp option.
    assert_eq!(segment(libc::PACKET_HOST, &syn_ack[..58]), Some(without_timestamps));

    // The 20 option bytes start with `options`, NOPs after.
    let with_options = |options: &[u8]| {
        let mut packet = syn_ack;
        packet[40..].fill(0x01);
        packet[40..40 + options.len()].copy_from_slice(options);
        packet
    };
    // MSS after a NOP and another option.
    let later = with_options(&[0x01, 0x03, 0x03, 0x02, 0x02, 0x04, 0x05, 0xb4]);
    assert_eq!(segment(libc::PACKET_HOST, &later), Some(without_timestamps));

    let past_header = [[0x01; 19].as_slice(), &[0x08]].concat();
    for options in [
        // An MSS option of length 3.
        &[0x02, 0x03, 0x05, 0xb4][..],
        // An option length below 2 before the MSS option.
        &[0x03, 0x01, 0x02, 0x04, 0x05, 0xb4],
        // End of options before it.
        &[0x00, 0x02, 0x04, 0x05, 0xb4],
        // An option running past the TCP header.
        &past_header,
    ] {
        assert_eq!(
            segment(libc::PACKET_HOST, &with_options(options)),
            Some(without_mss),
            "options {options:02x?}"
        );
    }

    // Data offset 6: 4 option bytes, then 4 captured payload bytes that look
    // like an MSS option. Options end at the TCP header, not the capture.
    for options in [[0x01, 0x01, 0x01, 0x01], [0x01, 0x01, 0x01, 0x02]] {
        #[rustfmt::skip]
        let mut packet: [u8; 48] = [
            0x45, 0x00, 0x00, 48,
            0x00, 0x00, 0x00, 0x00,
            64, 6, 0x00, 0x00,
            192, 0, 2, 2,
            192, 0, 2, 1,
            0x1f, 0x90, 0x9c, 0x40,
            0x00, 0x00, 0x00, 0x07,
            0x00, 0x00, 0x00, 0x01,
            0x60, 0x10, 0xff, 0xff, // data offset 6; ACK
            0x00, 0x00, 0x00, 0x00,
            0, 0, 0, 0, // options
            0x02, 0x04, 0x05, 0xb4, // payload
        ];
        packet[40..44].copy_from_slice(&options);
        let parsed = segment(libc::PACKET_HOST, &packet);
        assert_eq!(
            parsed.map(|s| (s.flags, s.len, s.mss)),
            Some((ACK, 4, None)),
            "options {options:02x?}"
        );
    }

    // IHL 6 (router alert): the options start after the longer IP header.
    let mut ihl_6 = [0u8; 64];
    ihl_6[..20].copy_from_slice(&syn_ack[..20]);
    ihl_6[0] = 0x46;
    ihl_6[3] = 64;
    ihl_6[20..24].copy_from_slice(&[0x94, 0x04, 0x00, 0x00]);
    ihl_6[24..].copy_from_slice(&syn_ack[20..]);
    assert_eq!(segment(libc::PACKET_HOST, &ihl_6), Some(expected));
}

fn at_ms(ms: u64, segment: Segment) -> Captured {
    Captured {
        at: SystemTime::UNIX_EPOCH + Duration::from_millis(ms),
        segment,
    }
}

#[test]
fn retransmissions_and_stale_pure_acks_are_found_from_the_capture() {
    use Direction::{ToZhida as K, ToKernel as C};
    let captured = [
        at_ms(0, hand_built(C, ACK, 1000, 1, 100)),
        at_ms(1, hand_built(K, ACK, 1, 1100, 100)),
        at_ms(2, hand_built(C, ACK, 1100, 101, 100)),
        // The kernel's RCV.NXT is 1200.
        at_ms(3, hand_built(K, ACK, 101, 1200, 0)),
        // RTO: 1000 resent, SND.NXT rewound to 1100.
        at_ms(4, hand_built(C, ACK, 1000, 101, 100)),
        at_ms(5, hand_built(C, ACK, 1100, 101, 0)),
        // Not pure ACKs, though below 1200.
        at_ms(6, hand_built(C, ACK | FIN, 1100, 101, 0)),
        at_ms(7, hand_built(C, ACK | PSH, 1100, 101, 0)),
        // The kernel resends; its own pure ACK above was at Zhida's RCV.NXT.
        at_ms(8, hand_built(K, ACK, 1, 1200, 100)),
        at_ms(9, hand_built(C, ACK, 1200, 101, 50)),
        at_ms(10, hand_built(C, ACK, 1250, 101, 0)),
    ];
    let at = |found: Vec<Captured>| -> Vec<SystemTime> { found.iter().map(|c| c.at).collect() };
    let resent = |found: Vec<Retransmission>| -> Vec<(SystemTime, SystemTime)> {
        found
            .iter()
            .map(|r| (r.captured.at, r.first_sent))
            .collect()
    };
    let ms = |ms| SystemTime::UNIX_EPOCH + Duration::from_millis(ms);
    assert_eq!(resent(retransmissions(&captured, C)), [(ms(4), ms(0))]);
    assert_eq!(at(stale_pure_acks(&captured, C)), [ms(5)]);
    assert_eq!(resent(retransmissions(&captured, K)), [(ms(8), ms(1))]);
    assert!(stale_pure_acks(&captured, K).is_empty());

    // Across the sequence wrap.
    let wrapped = [
        at_ms(0, hand_built(C, ACK, 0xffff_ff00, 1, 0x100)),
        at_ms(1, hand_built(K, ACK, 1, 0, 0)),
        at_ms(2, hand_built(C, ACK, 0, 1, 10)),
        at_ms(3, hand_built(C, ACK, 0xffff_ff80, 1, 0x80)),
        at_ms(4, hand_built(K, ACK, 1, 10, 0)),
        at_ms(5, hand_built(C, ACK, 0, 1, 0)),
        at_ms(6, hand_built(C, ACK, 10, 1, 0)),
    ];
    assert_eq!(resent(retransmissions(&wrapped, C)), [(ms(3), ms(0))]);
    assert_eq!(at(stale_pure_acks(&wrapped, C)), [ms(5)]);
}

#[test]
fn zhida_timeout_retransmissions_need_the_minimum_rto_and_more_than_a_byte() {
    use Direction::ToKernel as C;
    let captured = [
        at_ms(0, hand_built(C, ACK, 1000, 1, 100)),
        at_ms(150, hand_built(C, ACK, 1100, 1, 100)),
        // A timeout resends from SND.UNA, first sent at 0; captured within
        // CAPTURE_SLACK of ZHIDA_RTO.
        at_ms(285, hand_built(C, ACK, 1000, 1, 100)),
        // The rest of that resend: first sent at 150, too recently.
        at_ms(301, hand_built(C, ACK, 1100, 1, 100)),
        at_ms(340, hand_built(C, ACK, 1150, 1, 50)),
        // Zero-window probes: the same byte, the second over ZHIDA_RTO later.
        at_ms(400, hand_built(C, ACK, 1200, 1, 1)),
        at_ms(750, hand_built(C, ACK, 1200, 1, 1)),
    ];
    let ms = |ms| SystemTime::UNIX_EPOCH + Duration::from_millis(ms);
    let found = retransmissions(&captured, C);
    let resent: Vec<_> = found
        .iter()
        .map(|r| (r.captured.at, r.first_sent))
        .collect();
    assert_eq!(
        resent,
        [
            (ms(285), ms(0)),
            (ms(301), ms(150)),
            (ms(340), ms(150)),
            (ms(750), ms(400)),
        ]
    );
    let timeouts: Vec<_> = zhida_timeout_retransmissions(&found)
        .iter()
        .map(|r| r.captured.at)
        .collect();
    assert_eq!(timeouts, [ms(285)]);
}

#[test]
fn data_sent_between_counts_payload_one_way_in_a_half_open_interval() {
    use Direction::{ToZhida as K, ToKernel as C};
    let captured = [
        at_ms(0, hand_built(K, ACK, 1, 1000, 100)),
        at_ms(5, hand_built(K, ACK, 101, 1000, 200)),
        at_ms(5, hand_built(C, ACK, 1000, 301, 400)),
        at_ms(6, hand_built(K, ACK, 301, 1400, 0)),
        at_ms(10, hand_built(K, ACK, 301, 1400, 800)),
    ];
    let ms = |ms| SystemTime::UNIX_EPOCH + Duration::from_millis(ms);
    assert_eq!(data_sent_between(&captured, K, ms(0), ms(10)), 300);
    assert_eq!(data_sent_between(&captured, C, ms(0), ms(10)), 400);
    assert_eq!(data_sent_between(&captured, K, ms(1), ms(11)), 1000);
}

#[test]
fn keepalive_answer_needs_a_timeout_resend_below_the_keepalives_ack() {
    use Direction::{ToZhida as K, ToKernel as C};
    let ms = |ms| SystemTime::UNIX_EPOCH + Duration::from_millis(ms);
    // The kernel writes 300 bytes (1..301). Zhida echoes 200 (1000..1200);
    // the kernel's pure ACKs of them are dropped. Its SND.NXT is 301, so its
    // keepalives are at 300, acknowledging 1200.
    let start = [
        at_ms(0, hand_built(K, ACK | PSH, 1, 1000, 300)),
        at_ms(1, hand_built(C, ACK, 1000, 301, 100)),
        at_ms(2, hand_built(C, ACK, 1100, 301, 100)),
    ];
    // Timeout: 1000 resent alone.
    let resend = at_ms(1002, hand_built(C, ACK, 1000, 301, 100));
    let keepalive = at_ms(2000, hand_built(K, ACK, 300, 1200, 0));
    let answer = at_ms(2001, hand_built(C, ACK, 1200, 301, 0));
    let trace = |parts: &[&[Captured]]| parts.concat();
    let found_in = |captured: Vec<Captured>| {
        let timeouts = zhida_timeout_retransmissions(&retransmissions(&captured, C));
        keepalive_answer(&captured, ms(1500), &timeouts)
    };
    let rejected = |captured: Vec<Captured>, expected: &str| {
        let error = found_in(captured).unwrap_err();
        assert!(
            error.contains(expected),
            "expected {expected:?}, got {error:?}"
        );
    };

    let found = found_in(trace(&[&start, &[resend, keepalive, answer]])).unwrap();
    assert_eq!(
        [found.resend, found.keepalive, found.answer].map(|c| c.at),
        [ms(1002), ms(2000), ms(2001)]
    );

    // An answer at the resend point, below the kernel's RCV.NXT.
    let stale = at_ms(2001, hand_built(C, ACK, 1100, 301, 0));
    rejected(
        trace(&[&start, &[resend, keepalive, stale]]),
        "is not a pure ACK at or after",
    );
    rejected(
        trace(&[&start, &[resend, keepalive]]),
        "did not answer the keepalive",
    );
    // The kernel's pure ACK at its SND.NXT is not a keepalive, nor is a
    // keepalive before `from`.
    let at_snd_nxt = at_ms(2000, hand_built(K, ACK, 301, 1200, 0));
    rejected(
        trace(&[&start, &[resend, at_snd_nxt, answer]]),
        "no keepalive",
    );
    let early = at_ms(1400, hand_built(K, ACK, 300, 1200, 0));
    rejected(trace(&[&start, &[resend, early, answer]]), "no keepalive");
    // The kernel's duplicate ACK of the resend reached Zhida first.
    let dupack = at_ms(1003, hand_built(K, ACK, 301, 1200, 0));
    rejected(
        trace(&[&start, &[resend, dupack, keepalive, answer]]),
        "between Zhida's timeout retransmission",
    );
    // A kernel segment between the keepalive and Zhida's answer: the answer
    // may be to that segment instead.
    let ordinary = at_ms(2000, hand_built(K, ACK, 301, 1200, 0));
    let second = at_ms(2000, hand_built(K, ACK, 300, 1200, 0));
    rejected(
        trace(&[&start, &[resend, keepalive, ordinary, second, answer]]),
        "between its keepalive",
    );
    // Zhida's last data before the keepalive is new data, not a resend.
    let new_data = at_ms(1500, hand_built(C, ACK | PSH, 1200, 301, 50));
    rejected(
        trace(&[&start, &[resend, new_data, keepalive, answer]]),
        "is not a timeout retransmission",
    );
    // The resend covers everything the kernel holds.
    let whole = at_ms(1002, hand_built(C, ACK, 1000, 301, 200));
    rejected(
        trace(&[&start, &[whole, keepalive, answer]]),
        "reaches the keepalive's ACK number",
    );
}

#[test]
fn timed_out_retries_poll_timeouts_and_interrupts_only() {
    let errno = io::Error::from_raw_os_error;
    assert!(timed_out(&errno(libc::EAGAIN)));
    assert!(timed_out(&errno(libc::EINTR)));
    // A keepalive or retransmission abort.
    assert!(!timed_out(&errno(libc::ETIMEDOUT)));
    assert!(!timed_out(&errno(libc::ECONNRESET)));
}
