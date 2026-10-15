//! net_af_packet supplies kernel receive timestamps through the real Port and
//! Stack UDP path. Needs root with CAP_NET_ADMIN and CAP_NET_RAW.

use std::ffi::CString;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::time::{Duration, Instant};

use zhida_test_kit::{tap::ifindex, with_eal};
use dpdk_smoltcp::smoltcp::phy::ChecksumCapabilities;
use dpdk_smoltcp::smoltcp::time::Instant as StackInstant;
use dpdk_smoltcp::smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, IpEndpoint, IpProtocol,
    Ipv4Address, Ipv4Cidr, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr,
};
use dpdk_smoltcp::{
    Offloads, Port, PortConfig, Stack, StackConfig, UdpConfig, DEFAULT_NEIGHBOR_CAPACITY,
};
use zhida_buffer::PoolConfig;
use zhida_dpdk_sys::{
    rte_eth_dev_get_port_by_name, rte_vdev_init, rte_vdev_uninit, RTE_PKTMBUF_HEADROOM,
};

const PORT: u16 = 1234;
const PEER_PORT: u16 = 4321;
const ZHIDA_MAC: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x01]);
const BURST: usize = 8;
const DEADLINE: Duration = Duration::from_secs(10);

fn ip(args: &[&str]) {
    let output = Command::new("ip").args(args).output().expect("ip");
    assert!(
        output.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct VethPair {
    iface: String,
    peer: String,
}

impl VethPair {
    fn new(pid: u32, peer_ip: Ipv4Addr) -> Self {
        let iface = format!("cdafp{pid}a");
        let peer = format!("cdafp{pid}b");
        ip(&["link", "add", &iface, "type", "veth", "peer", "name", &peer]);
        let pair = Self { iface, peer };
        ip(&["link", "set", "dev", &pair.iface, "up"]);
        ip(&["link", "set", "dev", &pair.peer, "up"]);
        ip(&[
            "address",
            "add",
            &format!("{peer_ip}/30"),
            "dev",
            &pair.peer,
        ]);
        pair
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        let output = Command::new("ip")
            .args(["link", "delete", "dev", &self.iface])
            .output();
        if !std::thread::panicking() {
            let output = output.expect("ip link delete");
            assert!(
                output.status.success(),
                "ip link delete {}: {}",
                self.iface,
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

struct AfPacketVdev {
    name: CString,
    port_id: u16,
    closed: bool,
}

impl AfPacketVdev {
    fn new(pid: u32, iface: &str) -> Self {
        let name = CString::new(format!("net_af_packet{pid}")).unwrap();
        let args = CString::new(format!("iface={iface}")).unwrap();
        // SAFETY: both C strings are valid for the call; EAL is initialized.
        let rc = unsafe { rte_vdev_init(name.as_ptr(), args.as_ptr()) };
        assert_eq!(
            rc, 0,
            "rte_vdev_init failed for net_af_packet PMD (rc={rc}); ensure the af_packet PMD is installed and loadable"
        );
        let mut vdev = Self {
            name,
            port_id: u16::MAX,
            closed: false,
        };
        // SAFETY: the name is valid and port_id is writable for the call.
        assert_eq!(
            unsafe { rte_eth_dev_get_port_by_name(vdev.name.as_ptr(), &mut vdev.port_id) },
            0
        );
        vdev
    }

    fn close(mut self) {
        // SAFETY: the Port has closed, and this thread owns the vdev.
        assert_eq!(unsafe { rte_vdev_uninit(self.name.as_ptr()) }, 0);
        self.closed = true;
    }
}

impl Drop for AfPacketVdev {
    fn drop(&mut self) {
        if !self.closed {
            // SAFETY: declared before its Port, so the Port drops first.
            unsafe { rte_vdev_uninit(self.name.as_ptr()) };
            if !std::thread::panicking() {
                panic!("net_af_packet vdev dropped without close");
            }
        }
    }
}

fn realtime_ns() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: time is valid for writes of one timespec.
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut time) },
        0,
        "clock_gettime(CLOCK_REALTIME): {}",
        std::io::Error::last_os_error()
    );
    u64::try_from(time.tv_sec)
        .unwrap()
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(u64::try_from(time.tv_nsec).unwrap()))
        .unwrap()
}

fn peer_socket(iface: &str) -> OwnedFd {
    let iface = CString::new(iface).unwrap();
    let index = ifindex(&iface);
    assert_ne!(index, 0);
    let protocol = (libc::ETH_P_IP as u16).to_be();
    // SAFETY: socket takes no pointers; its result is checked before use.
    let raw = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
    assert!(
        raw >= 0,
        "socket(AF_PACKET): {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: raw is a fresh descriptor owned by nothing else.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: sockaddr_ll is plain data; zero is a valid initial value.
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = protocol;
    address.sll_ifindex = i32::try_from(index).unwrap();
    // SAFETY: address is valid for reads of the supplied sockaddr_ll size.
    assert_eq!(
        unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&address as *const libc::sockaddr_ll).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        },
        0,
        "bind(AF_PACKET): {}",
        std::io::Error::last_os_error()
    );
    socket
}

fn udp_frame(src: Ipv4Address, dst: Ipv4Address, payload: &[u8]) -> Vec<u8> {
    let caps = ChecksumCapabilities::default();
    let eth = EthernetRepr {
        src_addr: EthernetAddress([0x02, 0, 0, 0, 0, 0x02]),
        dst_addr: ZHIDA_MAC,
        ethertype: EthernetProtocol::Ipv4,
    };
    let udp = UdpRepr {
        src_port: PEER_PORT,
        dst_port: PORT,
    };
    let ip = Ipv4Repr {
        src_addr: src,
        dst_addr: dst,
        next_header: IpProtocol::Udp,
        payload_len: udp.header_len() + payload.len(),
        hop_limit: 64,
    };
    let mut bytes = vec![0; eth.buffer_len() + ip.buffer_len() + ip.payload_len];
    let mut frame = EthernetFrame::new_unchecked(&mut bytes);
    eth.emit(&mut frame);
    let mut packet = Ipv4Packet::new_unchecked(frame.payload_mut());
    ip.emit(&mut packet, &caps);
    udp.emit(
        &mut UdpPacket::new_unchecked(packet.payload_mut()),
        &src.into(),
        &dst.into(),
        payload.len(),
        |buffer| buffer.copy_from_slice(payload),
        &caps,
    );
    bytes
}

#[zhida_test_support::pinned_test]
fn af_packet_hardware_mode_opens_and_stamps() {
    with_eal(|eal| {
        let pid = std::process::id();
        let subnet = u16::try_from(pid % 16_384).unwrap();
        let third = (subnet / 64) as u8;
        let fourth = ((subnet % 64) * 4) as u8;
        let zhida_ip = Ipv4Address::new(198, 19, third, fourth + 1);
        let peer_ip = Ipv4Addr::new(198, 19, third, fourth + 2);
        let pair = VethPair::new(pid, peer_ip);
        let vdev = AfPacketVdev::new(pid, &pair.iface);
        let rx_pool = CString::new(format!("afp{pid}_rx")).unwrap();
        let tx_pool = CString::new(format!("afp{pid}_tx")).unwrap();
        let pool = |name| PoolConfig {
            name,
            count: 63,
            cache_size: 8,
            data_room_size: RTE_PKTMBUF_HEADROOM as u16 + 2048,
            socket_id: -1,
        };
        let config = PortConfig {
            port_id: vdev.port_id,
            mtu: 1500,
            rx_descriptors: 16,
            tx_descriptors: 16,
            rx_burst: BURST as u16,
            tx_burst: BURST as u16,
            queue_socket: -1,
            rx_pool: pool(rx_pool.as_c_str()),
            tx_pool: pool(tx_pool.as_c_str()),
            offloads: Offloads {
                rx_timestamp: true,
                ..Offloads::default()
            },
        };
        // SAFETY: this thread exclusively owns the fresh vdev. net_af_packet
        // supplies direct, single-segment mbufs and closes before the veth pair.
        let port = unsafe { Port::open(eal, config) }.unwrap();
        let config = StackConfig {
            ethernet: ZHIDA_MAC,
            ipv4: Ipv4Cidr::new(zhida_ip, 30),
            gateway: None,
            paths: &[],
            random_seed: 1,
            neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
            segments_per_visit: 1,
            max_sockets: 1,
            max_udp_sockets: 1,
            rx_staging: BURST,
            tx_pending: BURST,
        };
        let mut stack = Stack::new(port, config, StackInstant::ZERO)
            .map_err(|(_, error)| error)
            .unwrap();
        let handle = stack
            .add_udp(UdpConfig {
                port: PORT,
                rx_queue: 5,
                tx_checksum: true,
                broadcast: false,
            })
            .unwrap();
        let kernel = peer_socket(&pair.peer);
        let peer = IpEndpoint::new(peer_ip.into(), PEER_PORT);
        let frames: Vec<_> = (0..5u8)
            .map(|index| udp_frame(peer_ip, zhida_ip, &[index]))
            .collect();
        let start = Instant::now();
        let before = realtime_ns();
        for frame in &frames {
            // SAFETY: frame is valid for reads of its length.
            let sent = unsafe {
                libc::send(
                    kernel.as_raw_fd(),
                    frame.as_ptr().cast(),
                    frame.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            assert_eq!(
                sent,
                frame.len() as isize,
                "send(AF_PACKET): {}",
                std::io::Error::last_os_error()
            );
        }
        let mut stamps = Vec::with_capacity(5);
        while stamps.len() < 5 {
            let elapsed = start.elapsed();
            assert!(
                elapsed < DEADLINE,
                "received only {} of 5 UDP datagrams",
                stamps.len()
            );
            let now = StackInstant::from_micros(i64::try_from(elapsed.as_micros()).unwrap());
            let turn = stack.turn(now, BURST).unwrap();
            assert_eq!(turn.rx_rejected, 0);
            assert_eq!(turn.rx_ipv4_checksum_bad, 0);
            while let Some(datagram) = stack.udp_mut(&handle).recv() {
                assert_eq!(datagram.src(), peer);
                assert_eq!(datagram.payload(), [stamps.len() as u8]);
                stamps.push(datagram.rx_timestamp());
            }
            if stamps.len() < 5 {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let after = realtime_ns();
        assert_eq!(stamps.len(), 5);
        for &stamp in &stamps {
            assert_ne!(
                stamp, 0,
                "net_af_packet delivered a UDP datagram without a timestamp"
            );
            assert!(
                (before..=after).contains(&stamp),
                "timestamp {stamp} outside CLOCK_REALTIME interval {before}..={after}"
            );
        }
        // Stamp order is not checked: the kernel stamps a frame before it claims the ring slot,
        // so two CPUs delivering veth frames at once can put a later stamp into the ring first.
        drop(kernel);
        stack.into_port().try_close().unwrap();
        vdev.close();
        drop(pair);
    });
}
