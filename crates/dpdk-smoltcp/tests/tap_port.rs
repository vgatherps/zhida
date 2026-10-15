//! A net_tap Port exchanging real frames with an AF_PACKET socket on the
//! kernel side of its tap netdev. Needs CAP_NET_ADMIN, CAP_NET_RAW and
//! /dev/net/tun.

use std::collections::VecDeque;
use std::ffi::CStr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use zhida_test_kit::tap::{ifindex, TapVdev};
use zhida_test_kit::wire::{in_use, pool_exists};
use zhida_test_kit::with_eal;
use dpdk_smoltcp::smoltcp::phy::ChecksumCapabilities;
use dpdk_smoltcp::smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, IpAddress, IpProtocol,
    Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
    UdpPacket, UdpRepr,
};
use dpdk_smoltcp::{device_info, port_by_name, Eal, Offloads, Packet, Port, PortConfig, PortError};
use zhida_buffer::PoolConfig;
use zhida_dpdk_sys::RTE_PKTMBUF_HEADROOM;

const PORT_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
const TESTER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];
const MARKER_TYPE: [u8; 2] = [0x88, 0xb5];
const DEADLINE: Duration = Duration::from_secs(2);
/// After the expected frames, no further marker frame may arrive within this.
const QUIET: Duration = Duration::from_millis(200);

struct Names {
    vdev: &'static CStr,
    iface: &'static CStr,
    rx_pool: &'static CStr,
    tx_pool: &'static CStr,
}

fn config(port_id: u16, names: &Names) -> PortConfig<'static> {
    let pool = |name| PoolConfig {
        name,
        count: 63,
        cache_size: 8,
        data_room_size: RTE_PKTMBUF_HEADROOM as u16 + 2048,
        socket_id: -1,
    };
    PortConfig {
        port_id,
        mtu: 1500,
        rx_descriptors: 16,
        tx_descriptors: 16,
        rx_burst: 8,
        tx_burst: 8,
        queue_socket: -1,
        rx_pool: pool(names.rx_pool),
        tx_pool: pool(names.tx_pool),
        offloads: Offloads::default(),
    }
}

#[zhida_test_support::pinned_test]
fn device_info_reports_net_tap_driver_mac_and_mtu_limits() {
    let names = Names {
        vdev: c"net_tap_info",
        iface: c"cdtap_info",
        rx_pool: c"tap_info_rx",
        tx_pool: c"tap_info_tx",
    };
    with_eal(|eal| {
        let tap = TapVdev::new(names.vdev, names.iface);
        let info = device_info(eal, tap.port_id()).unwrap();
        assert_eq!(info.driver_name, "net_tap");
        assert_eq!(info.mac, [0x02, 0, 0, 0, 0, 0xfe]);
        assert!(info.min_mtu <= 1500);
        assert!(1500 <= info.max_mtu);
        assert_eq!(
            info.rx_capa & (RX_OFFLOAD_IPV4_CKSUM | RX_OFFLOAD_UDP_CKSUM | RX_OFFLOAD_TCP_CKSUM),
            RX_OFFLOAD_IPV4_CKSUM | RX_OFFLOAD_UDP_CKSUM | RX_OFFLOAD_TCP_CKSUM
        );
        assert_eq!(
            info.tx_capa & (TX_OFFLOAD_UDP_CKSUM | TX_OFFLOAD_TCP_CKSUM),
            TX_OFFLOAD_UDP_CKSUM | TX_OFFLOAD_TCP_CKSUM
        );
        assert!(matches!(
            device_info(eal, u16::MAX - 1),
            Err(PortError::Dpdk {
                operation: "rte_eth_dev_info_get",
                ..
            })
        ));
        tap.close();
    });
}

#[zhida_test_support::pinned_test]
fn port_by_name_finds_vdev_and_rejects_unknown() {
    let names = Names {
        vdev: c"net_tap_by_name",
        iface: c"cdtap_by_name",
        rx_pool: c"tap_by_name_rx",
        tx_pool: c"tap_by_name_tx",
    };
    with_eal(|eal| {
        let first = TapVdev::new(names.vdev, names.iface);
        let second = TapVdev::new(c"net_tap_by_name2", c"cdtap_by_name2");
        assert_ne!(first.port_id(), second.port_id());
        assert_eq!(
            port_by_name(eal, names.vdev.to_str().unwrap()),
            Some(first.port_id())
        );
        assert_eq!(
            port_by_name(eal, "net_tap_by_name2"),
            Some(second.port_id())
        );
        assert_eq!(port_by_name(eal, "net_tap_absent"), None);
        assert_eq!(port_by_name(eal, "net_tap\0absent"), None);
        second.close();
        first.close();
    });
}

/// Create the tap vdev (kernel netdev `names.iface`, no persist) and open a
/// Port on it; the vdev is returned first so it drops after the Port.
fn open(eal: &Eal, names: &Names) -> (TapVdev, Port) {
    let tap = TapVdev::new(names.vdev, names.iface);
    let port = unsafe { Port::open(eal, config(tap.port_id(), names)) }.unwrap();
    (tap, port)
}

/// Close the Port, remove the vdev, and check the netdev and both pools are gone.
fn close(tap: TapVdev, port: Port, names: &Names) {
    port.try_close().unwrap();
    tap.close();
    for name in [names.rx_pool, names.tx_pool] {
        assert!(!pool_exists(name));
    }
}

/// Ethernet frame of `len` bytes, EtherType 0x88B5, payload distinct per `marker`.
fn frame(dst: [u8; 6], src: [u8; 6], len: usize, marker: u8) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len);
    bytes.extend_from_slice(&dst);
    bytes.extend_from_slice(&src);
    bytes.extend_from_slice(&MARKER_TYPE);
    bytes.extend((0..len - 14).map(|offset| marker.wrapping_add(offset as u8)));
    bytes
}

fn to_port(len: usize, marker: u8) -> Vec<u8> {
    frame(PORT_MAC, TESTER_MAC, len, marker)
}

fn to_kernel(len: usize, marker: u8) -> Vec<u8> {
    frame(TESTER_MAC, PORT_MAC, len, marker)
}

fn is_marker(bytes: &[u8]) -> bool {
    bytes.get(12..14) == Some(&MARKER_TYPE[..])
}

/// Poll `rx_burst` until at least `limit` marker frames are staged or `until`
/// passes; returns them in arrival order. Other frames (kernel IPv6 noise) are
/// dropped. Every burst must reject nothing.
fn poll_markers(port: &mut Port, limit: usize, until: Instant) -> Vec<Packet> {
    let mut staged = VecDeque::with_capacity(16);
    let mut markers = Vec::new();
    while markers.len() < limit && Instant::now() < until {
        let burst = port.rx_burst(&mut staged).unwrap();
        assert_eq!(burst.rejected, 0);
        markers.extend(staged.drain(..).filter(|packet| is_marker(packet.data())));
        if burst.accepted == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    markers
}

/// Exactly `count` marker frames within the deadline, then none during the
/// quiet interval nor in the final drain after it.
fn receive_markers(port: &mut Port, count: usize) -> Vec<Packet> {
    let markers = poll_markers(port, count, Instant::now() + DEADLINE);
    assert_eq!(markers.len(), count, "marker frames received by the Port");
    let mut extra = poll_markers(port, 1, Instant::now() + QUIET);
    extra.extend(drain_markers(port));
    assert!(
        extra.is_empty(),
        "extra marker frame at the Port: {:02x?}",
        extra.first().map(|packet| packet.data())
    );
    markers
}

/// Call `rx_burst` until it returns nothing; returns the marker frames staged.
/// Other frames are dropped; every burst must reject nothing.
fn drain_markers(port: &mut Port) -> Vec<Packet> {
    let deadline = Instant::now() + DEADLINE;
    let mut staged = VecDeque::with_capacity(16);
    let mut markers = Vec::new();
    loop {
        assert!(Instant::now() < deadline, "RX never went idle");
        let burst = port.rx_burst(&mut staged).unwrap();
        assert_eq!(burst.rejected, 0);
        if burst.accepted == 0 {
            return markers;
        }
        markers.extend(staged.drain(..).filter(|packet| is_marker(packet.data())));
    }
}

/// Poll until `rx_burst` returns nothing; no marker frame may arrive. An empty
/// burst makes pmd_rx_burst record the current RX trigger as seen, so the next
/// frame is read only after its own signal.
fn poll_until_idle(port: &mut Port) {
    assert!(
        drain_markers(port).is_empty(),
        "marker frame before sending"
    );
}

fn send_from_port(port: &mut Port, frames: &[Vec<u8>]) {
    let mut pending = VecDeque::with_capacity(frames.len());
    for bytes in frames {
        let mut packet = port.alloc_tx(bytes.len() as u16).unwrap();
        packet.data_mut().copy_from_slice(bytes);
        pending.push_back(packet);
    }
    assert_eq!(port.tx_burst(&mut pending), Ok(frames.len()));
}

/// AF_PACKET SOCK_RAW socket bound to one netdev, receiving every protocol.
struct KernelSide {
    fd: OwnedFd,
}

impl KernelSide {
    fn bind(iface: &CStr) -> Self {
        let index = ifindex(iface);
        assert_ne!(index, 0);
        let protocol = (libc::ETH_P_ALL as u16).to_be();
        // SAFETY: plain syscall; the result is checked before use.
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                i32::from(protocol),
            )
        };
        assert!(raw >= 0, "socket: {}", std::io::Error::last_os_error());
        // SAFETY: `raw` is a fresh descriptor owned by nothing else.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: sockaddr_ll is plain data; all-zero is a valid value.
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_protocol = protocol;
        address.sll_ifindex = index as i32;
        // SAFETY: `address` is a valid sockaddr_ll and its size is passed.
        let bound = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_ll).cast(),
                size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        assert_eq!(bound, 0, "bind: {}", std::io::Error::last_os_error());
        Self { fd }
    }

    fn send(&self, bytes: &[u8]) {
        // SAFETY: `bytes` is valid for reads of its length.
        let sent =
            unsafe { libc::send(self.fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len(), 0) };
        assert_eq!(
            sent,
            bytes.len() as isize,
            "send: {}",
            std::io::Error::last_os_error()
        );
    }

    /// One queued frame without blocking, skipping outgoing and non-marker
    /// frames; `None` once the socket queue is empty.
    fn take_marker(&self) -> Option<(Vec<u8>, u8)> {
        let mut buffer = [0u8; 2048];
        loop {
            // SAFETY: sockaddr_ll is plain data; all-zero is a valid value.
            let mut from: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut from_len = size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            // SAFETY: `buffer` and `from` are valid for writes of the lengths passed.
            let len = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                    (&mut from as *mut libc::sockaddr_ll).cast(),
                    &mut from_len,
                )
            };
            if len < 0 {
                let error = std::io::Error::last_os_error();
                match error.kind() {
                    std::io::ErrorKind::WouldBlock => return None,
                    // The tap PMD's RX trigger is a real-time signal to this process.
                    std::io::ErrorKind::Interrupted => continue,
                    _ => panic!("recvfrom: {error}"),
                }
            }
            let bytes = &buffer[..len as usize];
            if from.sll_pkttype != libc::PACKET_OUTGOING && is_marker(bytes) {
                return Some((bytes.to_vec(), from.sll_pkttype));
            }
        }
    }

    /// Next marker frame and its pkttype before `until`. `None` only after a
    /// final nonblocking drain past `until` found none.
    fn next_marker(&self, until: Instant) -> Option<(Vec<u8>, u8)> {
        loop {
            if let Some(marker) = self.take_marker() {
                return Some(marker);
            }
            let remaining = until.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let mut poll = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd.
            let ready = unsafe { libc::poll(&mut poll, 1, remaining.as_millis().max(1) as i32) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                // The tap PMD's RX trigger is a real-time signal to this process.
                assert_eq!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted,
                    "poll: {error}"
                );
            }
        }
    }

    /// Exactly `count` marker frames (with pkttype) within the deadline, then
    /// none during the quiet interval nor in the final drain after it.
    fn receive_markers(&self, count: usize) -> Vec<(Vec<u8>, u8)> {
        let deadline = Instant::now() + DEADLINE;
        let markers: Vec<_> = (0..count)
            .map(|index| {
                self.next_marker(deadline).unwrap_or_else(|| {
                    panic!("{index} of {count} marker frames on the kernel side")
                })
            })
            .collect();
        let extra = self.next_marker(Instant::now() + QUIET);
        assert!(
            extra.is_none(),
            "extra marker frame on the kernel side: {extra:02x?}"
        );
        markers
    }
}

#[zhida_test_support::pinned_test]
fn tap_port_exchanges_frames_with_kernel_netdev() {
    let names = Names {
        vdev: c"net_tap_xchg",
        iface: c"cdtap_xchg",
        rx_pool: c"tap_xchg_rx",
        tx_pool: c"tap_xchg_tx",
    };
    with_eal(|eal| {
        let (tap, mut port) = open(eal, &names);
        // tap_rx_queue_setup holds one RX buffer per descriptor while started.
        let rx_held = u32::from(port.descriptor_counts().0);
        assert_eq!(in_use(names.rx_pool), rx_held);
        assert_eq!(in_use(names.tx_pool), 0);
        let kernel = KernelSide::bind(names.iface);

        // Kernel → Port after the PMD has gone idle: the frame must arrive on its
        // own RX trigger, not on the burst tap_rx_queue_setup forces. The second idle
        // poll consumes the trigger of any late kernel noise frame.
        poll_until_idle(&mut port);
        std::thread::sleep(Duration::from_millis(50));
        poll_until_idle(&mut port);
        let after_idle = to_port(60, 0x08);
        kernel.send(&after_idle);
        let packets = receive_markers(&mut port, 1);
        assert_eq!(packets[0].data(), &after_idle[..]);
        drop(packets);

        // Kernel → Port: each frame once, exact bytes, in send order.
        let inbound = [to_port(60, 0x10), to_port(1514, 0x20)];
        for bytes in &inbound {
            kernel.send(bytes);
        }
        let packets = receive_markers(&mut port, 2);
        let received: Vec<_> = packets
            .iter()
            .map(|packet| packet.data().to_vec())
            .collect();
        assert_eq!(received, inbound);
        assert_eq!(in_use(names.rx_pool), rx_held + 2);
        drop(packets);
        assert_eq!(in_use(names.rx_pool), rx_held);

        // 20 frames queued at once span several 8-packet bursts. All are held:
        // 16 PMD buffers + 20 received fit the 63-buffer RX pool.
        // All 20 are queued before the first rx_burst, so pmd_rx_burst returns
        // full bursts until the queue empties.
        let queued: Vec<_> = (0..20).map(|index| to_port(60, 0x80 + index)).collect();
        for bytes in &queued {
            kernel.send(bytes);
        }
        let packets = receive_markers(&mut port, queued.len());
        let received: Vec<_> = packets
            .iter()
            .map(|packet| packet.data().to_vec())
            .collect();
        assert_eq!(received, queued);
        assert_eq!(in_use(names.rx_pool), rx_held + 20);
        drop(packets);
        assert_eq!(in_use(names.rx_pool), rx_held);

        // Port → kernel: pmd_tx_burst frees on acceptance; the netdev sees
        // frames addressed to another host.
        let outbound = [to_kernel(60, 0x30), to_kernel(1514, 0x40)];
        send_from_port(&mut port, &outbound);
        assert_eq!(in_use(names.tx_pool), 0);
        let expected: Vec<_> = outbound
            .iter()
            .map(|bytes| (bytes.clone(), libc::PACKET_OTHERHOST))
            .collect();
        assert_eq!(kernel.receive_markers(2), expected);

        drop(kernel);
        close(tap, port, &names);
    });
}

#[zhida_test_support::pinned_test]
fn tap_port_close_refuses_while_a_received_packet_is_held() {
    let names = Names {
        vdev: c"net_tap_held",
        iface: c"cdtap_held",
        rx_pool: c"tap_held_rx",
        tx_pool: c"tap_held_tx",
    };
    with_eal(|eal| {
        let (tap, mut port) = open(eal, &names);
        let kernel = KernelSide::bind(names.iface);
        let inbound = to_port(60, 0x50);
        kernel.send(&inbound);
        let held = receive_markers(&mut port, 1);
        assert_eq!(held[0].data(), &inbound[..]);
        drop(kernel);

        // Stopped and closed (tap_dev_close freed its RX buffers and the netdev is
        // gone); only the held packet keeps the pools alive.
        let (port, error) = port.try_close().unwrap_err();
        assert_eq!(error, PortError::OutstandingBuffers { rx: 1, tx: 0 });
        assert_eq!(ifindex(names.iface), 0);

        drop(held);
        close(tap, port, &names);
    });
}

#[zhida_test_support::pinned_test]
fn tap_port_recreates_the_same_vdev_after_uninit() {
    let names = Names {
        vdev: c"net_tap_again",
        iface: c"cdtap_again",
        rx_pool: c"tap_again_rx",
        tx_pool: c"tap_again_tx",
    };
    with_eal(|eal| {
        for round in 0..3u8 {
            let (tap, mut port) = open(eal, &names);
            let kernel = KernelSide::bind(names.iface);

            let inbound = to_port(60, 0x60 + round);
            kernel.send(&inbound);
            let received = receive_markers(&mut port, 1);
            assert_eq!(received[0].data(), &inbound[..]);
            drop(received);

            let outbound = to_kernel(60, 0x70 + round);
            send_from_port(&mut port, std::slice::from_ref(&outbound));
            assert_eq!(
                kernel.receive_markers(1),
                [(outbound, libc::PACKET_OTHERHOST)]
            );

            drop(kernel);
            close(tap, port, &names);
        }
    });
}

// RTE_BIT64 values from rte_ethdev.h.
const RX_OFFLOAD_IPV4_CKSUM: u64 = 1 << 1;
const RX_OFFLOAD_UDP_CKSUM: u64 = 1 << 2;
const RX_OFFLOAD_TCP_CKSUM: u64 = 1 << 3;
const TX_OFFLOAD_UDP_CKSUM: u64 = 1 << 2;
const TX_OFFLOAD_TCP_CKSUM: u64 = 1 << 3;

/// net_tap advertises IPv4/TCP/UDP checksum offloads in both directions. A Port
/// opened with `offloads` configures exactly `(rx, tx)` and still exchanges
/// frames with the kernel.
fn checksum_profile_opens(names: &Names, offloads: Offloads, expected: (u64, u64)) {
    with_eal(|eal| {
        let tap = TapVdev::new(names.vdev, names.iface);
        let config = PortConfig {
            offloads,
            ..config(tap.port_id(), names)
        };
        let mut port = unsafe { Port::open(eal, config) }.unwrap();
        let mut conf: zhida_dpdk_sys::rte_eth_conf = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { zhida_dpdk_sys::rte_eth_dev_conf_get(tap.port_id(), &mut conf) },
            0
        );
        assert_eq!((conf.rxmode.offloads, conf.txmode.offloads), expected);

        let kernel = KernelSide::bind(names.iface);
        let inbound = to_port(60, 0x80);
        kernel.send(&inbound);
        let received = receive_markers(&mut port, 1);
        assert_eq!(received[0].data(), &inbound[..]);
        drop(received);
        let outbound = to_kernel(60, 0x81);
        send_from_port(&mut port, std::slice::from_ref(&outbound));
        assert_eq!(
            kernel.receive_markers(1),
            [(outbound, libc::PACKET_OTHERHOST)]
        );
        drop(kernel);
        close(tap, port, names);
    });
}

#[zhida_test_support::pinned_test]
fn rx_checksum_profile_opens() {
    let names = Names {
        vdev: c"net_tap_rxck",
        iface: c"cdtap_rxck",
        rx_pool: c"tap_rxck_rx",
        tx_pool: c"tap_rxck_tx",
    };
    let offloads = Offloads {
        rx_timestamp: false,
        rx_checksum: true,
        tx_tcp_checksum: false,
        tx_udp_checksum: false,
    };
    checksum_profile_opens(
        &names,
        offloads,
        (RX_OFFLOAD_IPV4_CKSUM | RX_OFFLOAD_UDP_CKSUM | RX_OFFLOAD_TCP_CKSUM, 0),
    );
}

fn checksum_segment() -> Vec<u8> {
    let caps = ChecksumCapabilities::default();
    let src = Ipv4Address::new(10, 0, 0, 2);
    let dst = Ipv4Address::new(10, 0, 0, 1);
    let eth = EthernetRepr {
        src_addr: EthernetAddress(TESTER_MAC),
        dst_addr: EthernetAddress(PORT_MAC),
        ethertype: EthernetProtocol::Ipv4,
    };
    let tcp = TcpRepr {
        src_port: 49152,
        dst_port: 80,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(1),
        ack_number: None,
        window_len: 65535,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: b"checksum",
    };
    let ip = Ipv4Repr {
        src_addr: src,
        dst_addr: dst,
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
        &IpAddress::Ipv4(src),
        &IpAddress::Ipv4(dst),
        &caps,
    );
    bytes
}

#[zhida_test_support::pinned_test]
fn tap_rx_checksum_stages_injected_bad_segment() {
    let names = Names {
        vdev: c"net_tap_rx_bad",
        iface: c"cdtap_rx_bad",
        rx_pool: c"tap_rx_bad_rx",
        tx_pool: c"tap_rx_bad_tx",
    };
    with_eal(|eal| {
        let tap = TapVdev::new(names.vdev, names.iface);
        let config = PortConfig {
            offloads: Offloads {
                rx_timestamp: false,
                rx_checksum: true,
                tx_tcp_checksum: false,
                tx_udp_checksum: false,
            },
            ..config(tap.port_id(), &names)
        };
        let mut port = unsafe { Port::open(eal, config) }.unwrap();
        let kernel = KernelSide::bind(names.iface);
        poll_until_idle(&mut port);
        let rx_held = u32::from(port.descriptor_counts().0);
        assert_eq!(in_use(names.rx_pool), rx_held);
        let good = checksum_segment();
        let mut bad = good.clone();
        bad[14 + 20 + 16] ^= 1;
        let frame = EthernetFrame::new_checked(&good[..]).unwrap();
        let ip = Ipv4Packet::new_checked(frame.payload()).unwrap();
        assert!(ip.verify_checksum());
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into()));
        let frame = EthernetFrame::new_checked(&bad[..]).unwrap();
        let ip = Ipv4Packet::new_checked(frame.payload()).unwrap();
        assert!(ip.verify_checksum());
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(!tcp.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into()));

        kernel.send(&good);
        kernel.send(&bad);
        let mut staged = VecDeque::with_capacity(16);
        let mut received = Vec::new();
        let mut checksum_bad = 0;
        let deadline = Instant::now() + DEADLINE;
        let mut quiet_until = None;
        loop {
            let burst = port.rx_burst(&mut staged).unwrap();
            assert_eq!(burst.rejected, 0);
            checksum_bad += burst.rx_ipv4_checksum_bad;
            for packet in staged.drain(..) {
                if packet.data().get(..14) == good.get(..14) {
                    assert_eq!(
                        packet.data(),
                        &[&good, &bad][received.len()][..],
                        "unexpected TCP frame staged"
                    );
                    received.push(packet);
                }
            }
            assert!(received.len() <= 2);
            assert_eq!(checksum_bad, 0);
            if received.len() == 2 && checksum_bad == 0 && quiet_until.is_none() {
                quiet_until = Some(Instant::now() + QUIET);
            }
            if let Some(until) = quiet_until {
                if Instant::now() >= until && burst.accepted + burst.rx_ipv4_checksum_bad == 0 {
                    break;
                }
            }
            assert!(
                Instant::now() < deadline,
                "TCP frames missing"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(received.len(), 2);
        assert_eq!(checksum_bad, 0);
        assert_eq!(in_use(names.rx_pool), rx_held + 2);
        drop(received);
        assert_eq!(in_use(names.rx_pool), rx_held);
        drop(kernel);
        close(tap, port, &names);
    });
}

#[zhida_test_support::pinned_test]
fn tx_checksum_profile_opens() {
    let names = Names {
        vdev: c"net_tap_txck",
        iface: c"cdtap_txck",
        rx_pool: c"tap_txck_rx",
        tx_pool: c"tap_txck_tx",
    };
    let offloads = Offloads {
        rx_timestamp: false,
        rx_checksum: false,
        tx_tcp_checksum: true,
        tx_udp_checksum: false,
    };
    checksum_profile_opens(&names, offloads, (0, TX_OFFLOAD_TCP_CKSUM));
}

#[zhida_test_support::pinned_test]
fn tx_udp_checksum_profile_opens() {
    let names = Names {
        vdev: c"net_tap_txudpck",
        iface: c"cdtap_txudpck",
        rx_pool: c"tap_txudpck_rx",
        tx_pool: c"tap_txudpck_tx",
    };
    let offloads = Offloads {
        rx_timestamp: false,
        rx_checksum: false,
        tx_tcp_checksum: false,
        tx_udp_checksum: true,
    };
    checksum_profile_opens(&names, offloads, (0, TX_OFFLOAD_UDP_CKSUM));
}

fn checksum_datagram() -> Vec<u8> {
    let caps = ChecksumCapabilities::default();
    let udp = UdpRepr {
        src_port: 49152,
        dst_port: 1234,
    };
    let payload = b"UDP checksum";
    let ip = Ipv4Repr {
        src_addr: Ipv4Address::new(10, 0, 0, 2),
        dst_addr: Ipv4Address::new(10, 0, 0, 1),
        next_header: IpProtocol::Udp,
        payload_len: udp.header_len() + payload.len(),
        hop_limit: 64,
    };
    let eth = EthernetRepr {
        src_addr: EthernetAddress(TESTER_MAC),
        dst_addr: EthernetAddress(PORT_MAC),
        ethertype: EthernetProtocol::Ipv4,
    };
    let mut bytes = vec![0; eth.buffer_len() + ip.buffer_len() + ip.payload_len];
    let mut frame = EthernetFrame::new_unchecked(&mut bytes);
    eth.emit(&mut frame);
    let mut packet = Ipv4Packet::new_unchecked(frame.payload_mut());
    ip.emit(&mut packet, &caps);
    udp.emit(
        &mut UdpPacket::new_unchecked(packet.payload_mut()),
        &ip.src_addr.into(),
        &ip.dst_addr.into(),
        payload.len(),
        |out| out.copy_from_slice(payload),
        &caps,
    );
    bytes
}

#[zhida_test_support::pinned_test]
fn tap_rx_checksum_udp_verdicts() {
    let names = Names {
        vdev: c"net_tap_rx_udpck",
        iface: c"cdtap_rx_udpck",
        rx_pool: c"tap_rx_udpck_rx",
        tx_pool: c"tap_rx_udpck_tx",
    };
    with_eal(|eal| {
        let tap = TapVdev::new(names.vdev, names.iface);
        let config = PortConfig {
            offloads: Offloads {
                rx_timestamp: false,
                rx_checksum: true,
                tx_tcp_checksum: false,
                tx_udp_checksum: false,
            },
            ..config(tap.port_id(), &names)
        };
        let mut port = unsafe { Port::open(eal, config) }.unwrap();
        let kernel = KernelSide::bind(names.iface);
        poll_until_idle(&mut port);
        let rx_held = u32::from(port.descriptor_counts().0);
        assert_eq!(in_use(names.rx_pool), rx_held);
        let good = checksum_datagram();
        let ip = Ipv4Packet::new_checked(&good[14..]).unwrap();
        assert!(ip.verify_checksum());
        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        assert_ne!(udp.checksum(), 0);
        assert!(udp.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into()));
        let mut bad = good.clone();
        bad[40] ^= 1;
        let ip = Ipv4Packet::new_checked(&bad[14..]).unwrap();
        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        assert_ne!(udp.checksum(), 0);
        assert!(!udp.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into()));
        let mut zero = good.clone();
        zero[40..42].fill(0);
        kernel.send(&good);
        kernel.send(&bad);
        kernel.send(&zero);
        let mut staged = VecDeque::with_capacity(16);
        let mut received = Vec::new();
        let mut checksum_bad = 0;
        let deadline = Instant::now() + DEADLINE;
        let mut quiet_until = None;
        loop {
            let burst = port.rx_burst(&mut staged).unwrap();
            assert_eq!(burst.rejected, 0);
            checksum_bad += burst.rx_ipv4_checksum_bad;
            for packet in staged.drain(..) {
                if packet.data().get(..14) == good.get(..14) {
                    let expected = [&good, &bad, &zero][received.len()];
                    assert_eq!(packet.data(), &expected[..], "unexpected UDP frame staged");
                    received.push(packet);
                }
            }
            assert!(received.len() <= 3);
            assert_eq!(checksum_bad, 0);
            if received.len() == 3 && checksum_bad == 0 && quiet_until.is_none() {
                quiet_until = Some(Instant::now() + QUIET);
            }
            if let Some(until) = quiet_until {
                if Instant::now() >= until && burst.accepted + burst.rx_ipv4_checksum_bad == 0 {
                    break;
                }
            }
            assert!(Instant::now() < deadline, "UDP frames missing");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(received.len(), 3);
        assert_eq!(checksum_bad, 0);
        assert_eq!(in_use(names.rx_pool), rx_held + 3);
        drop(received);
        assert_eq!(in_use(names.rx_pool), rx_held);
        drop(kernel);
        close(tap, port, &names);
    });
}
