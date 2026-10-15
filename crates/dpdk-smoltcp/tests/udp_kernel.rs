//! Linux kernel UDP sockets exchange datagrams with a Stack through net_tap.
//! Needs CAP_NET_ADMIN, CAP_NET_RAW and /dev/net/tun. Each test assigns an
//! IPv4 address and MTU to its own tap netdev.

use std::ffi::CStr;
use std::io;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::time::{Duration, Instant};

use zhida_test_kit::tap::{ifindex, TapVdev};
use zhida_test_kit::wire::{in_use, pool_exists};
use zhida_test_kit::with_eal;
use dpdk_smoltcp::smoltcp::time::Instant as StackInstant;
use dpdk_smoltcp::smoltcp::wire::{
    EthernetAddress, EthernetFrame, IpAddress, IpEndpoint, IpProtocol, Ipv4Address, Ipv4Cidr,
    Ipv4Packet, UdpPacket,
};
use dpdk_smoltcp::{
    Eal, Offloads, Port, PortConfig, Stack, StackConfig, UdpConfig, UdpDatagram, UdpHandle,
    UdpSendError, DEFAULT_NEIGHBOR_CAPACITY,
};
use zhida_buffer::PoolConfig;
use zhida_dpdk_sys::RTE_PKTMBUF_HEADROOM;

const KERNEL_ADDR: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const ZHIDA_ADDR: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
const PORT: u16 = 1234;
const BURST: usize = 32;
const DEADLINE: Duration = Duration::from_secs(10);
const QUIET: Duration = Duration::from_millis(200);

struct Names {
    vdev: &'static CStr,
    iface: &'static CStr,
    rx_pool: &'static CStr,
    tx_pool: &'static CStr,
}

fn with_stack(eal: &Eal, names: Names, test: impl FnOnce(&mut Stack, Instant)) {
    with_stack_gateway(eal, names, None, Offloads::default(), test);
}

fn with_stack_offloads(
    eal: &Eal,
    names: Names,
    offloads: Offloads,
    test: impl FnOnce(&mut Stack, Instant),
) {
    with_stack_gateway(eal, names, None, offloads, test);
}

fn with_stack_gateway(
    eal: &Eal,
    names: Names,
    gateway: Option<Ipv4Address>,
    offloads: Offloads,
    test: impl FnOnce(&mut Stack, Instant),
) {
    let tap = TapVdev::new(names.vdev, names.iface);
    let pool = |name, count| PoolConfig {
        name,
        count,
        cache_size: 8,
        data_room_size: RTE_PKTMBUF_HEADROOM as u16 + 2048,
        socket_id: -1,
    };
    let config = PortConfig {
        port_id: tap.port_id(),
        mtu: 1500,
        rx_descriptors: 16,
        tx_descriptors: 16,
        rx_burst: 32,
        tx_burst: 32,
        queue_socket: -1,
        rx_pool: pool(names.rx_pool, 255),
        tx_pool: pool(names.tx_pool, 127),
        offloads,
    };
    // SAFETY: this thread owns the new tap and its Port. net_tap uses real
    // direct mbufs; the tap outlives Port close.
    let port = unsafe { Port::open(eal, config) }.unwrap();
    tap.set_kernel_mtu(1500);
    assert_eq!(tap.kernel_mtu(), 1500);
    set_kernel_address(names.iface);
    let [a, b, c, d] = ZHIDA_ADDR.octets();
    let config = StackConfig {
        ethernet: EthernetAddress([0x02, 0, 0, 0, 0, 0x01]),
        ipv4: Ipv4Cidr::new(Ipv4Address::new(a, b, c, d), 24),
        gateway,
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
    test(&mut stack, Instant::now());
    let port = stack.into_port();
    assert_eq!(in_use(names.rx_pool), u32::from(port.descriptor_counts().0));
    assert_eq!(in_use(names.tx_pool), 0);
    port.try_close().unwrap();
    tap.close();
    for name in [names.rx_pool, names.tx_pool] {
        assert!(!pool_exists(name));
    }
}

#[zhida_test_support::pinned_test]
fn kernel_off_subnet_peer_through_gateway() {
    with_eal(|eal| {
        let iface = c"cdudp_gateway";
        let names = Names {
            vdev: c"net_tap_udpk_gateway",
            iface,
            rx_pool: c"udpk_gateway_rx",
            tx_pool: c"udpk_gateway_tx",
        };
        let [a, b, c, d] = KERNEL_ADDR.octets();
        with_stack_gateway(
            eal,
            names,
            Some(Ipv4Address::new(a, b, c, d)),
            Offloads::default(),
            |stack, start| {
                let remote = Ipv4Addr::new(198, 51, 100, 7);
                let address = format!("{remote}/32");
                let output = Command::new("ip")
                    .args(["address", "add", &address, "dev", iface.to_str().unwrap()])
                    .output()
                    .expect("ip address add");
                assert!(
                    output.status.success(),
                    "ip address add: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let kernel = UdpSocket::bind((remote, 0)).unwrap();
                kernel.set_nonblocking(true).unwrap();
                let peer = endpoint(kernel.local_addr().unwrap());
                let handle = add_udp(stack, true);
                send_zhida(stack, start, &handle, Some(peer), b"to remote");
                recv_kernel(stack, start, &kernel, b"to remote");
                send_kernel(stack, start, &kernel, b"from remote");
                let datagram = recv_zhida(stack, start, &handle);
                assert_eq!(datagram.src(), peer);
                assert_eq!(datagram.payload(), b"from remote");
                send_zhida(
                    stack,
                    start,
                    &handle,
                    Some(datagram.src()),
                    datagram.payload(),
                );
                drop(datagram);
                recv_kernel(stack, start, &kernel, b"from remote");
                assert_eq!(stack.udp(&handle).stats().rx_delivered, 1);
                assert_eq!(stack.udp(&handle).rx_queued(), 0);
                assert_eq!(stack.udp_counters().rx_checksum_bad, 0);
                assert_kernel_quiet(stack, start, &kernel);
            },
        );
    });
}

struct UdpCapture(OwnedFd);

impl UdpCapture {
    fn bind(iface: &CStr) -> Self {
        let protocol = (libc::ETH_P_IP as u16).to_be();
        // Protocol 0 receives nothing until bind names the interface and ETH_P_IP,
        // so no frame from another interface is queued first.
        // SAFETY: socket takes no pointers; its result is checked before use.
        let raw = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        assert!(raw >= 0, "socket(AF_PACKET): {}", io::Error::last_os_error());
        // SAFETY: raw is a fresh descriptor with no other owner.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let index = ifindex(iface);
        assert_ne!(index, 0);
        // SAFETY: sockaddr_ll is plain data and zero is a valid initial value.
        let mut address: libc::sockaddr_ll = unsafe { mem::zeroed() };
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_protocol = protocol;
        address.sll_ifindex = index as i32;
        // SAFETY: address is valid for reads of the supplied sockaddr_ll size.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_ll).cast(),
                mem::size_of_val(&address) as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "bind(AF_PACKET): {}", io::Error::last_os_error());
        Self(fd)
    }

    fn verify_next(&self, stack: &mut Stack, start: Instant, peer: IpEndpoint, payload: &[u8]) {
        let mut buffer = [0u8; 2048];
        loop {
            turn(stack, start);
            // SAFETY: buffer is valid for writes of its length.
            let len = unsafe {
                libc::recv(
                    self.0.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if len < 0 {
                let error = io::Error::last_os_error();
                match error.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => continue,
                    _ => panic!("UDP capture recv: {error}"),
                }
            }
            let eth = EthernetFrame::new_checked(&buffer[..len as usize]).unwrap();
            let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
            if ip.src_addr().octets() != ZHIDA_ADDR.octets() || ip.next_header() != IpProtocol::Udp {
                continue;
            }
            assert!(ip.verify_checksum());
            assert_eq!(IpAddress::Ipv4(ip.dst_addr()), peer.addr);
            let udp = UdpPacket::new_checked(ip.payload()).unwrap();
            assert_eq!(udp.src_port(), PORT);
            assert_eq!(udp.dst_port(), peer.port);
            assert_eq!(udp.payload(), payload);
            assert_ne!(udp.checksum(), 0);
            assert!(udp.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into()));
            return;
        }
    }
}

fn set_kernel_address(iface: &CStr) {
    // SAFETY: socket takes no pointers; its result is checked before use.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0, "socket(AF_INET): {}", io::Error::last_os_error());
    // SAFETY: fd is a fresh descriptor with no other owner.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    for (request, addr) in [
        (libc::SIOCSIFADDR, KERNEL_ADDR),
        (libc::SIOCSIFNETMASK, Ipv4Addr::new(255, 255, 255, 0)),
    ] {
        // SAFETY: ifreq is plain data and zero is a valid initial value.
        let mut ifreq: libc::ifreq = unsafe { mem::zeroed() };
        let bytes = iface.to_bytes();
        assert!(bytes.len() < ifreq.ifr_name.len());
        for (dst, &src) in ifreq.ifr_name.iter_mut().zip(bytes) {
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
        // SAFETY: both structs are 16 bytes; this ioctl reads an IPv4 sockaddr.
        ifreq.ifr_ifru.ifru_addr =
            unsafe { mem::transmute::<libc::sockaddr_in, libc::sockaddr>(sin) };
        // SAFETY: both requests take a writable ifreq pointer.
        let rc = unsafe { libc::ioctl(socket.as_raw_fd(), request, &mut ifreq) };
        assert_eq!(rc, 0, "ioctl {request}: {}", io::Error::last_os_error());
    }
}

fn kernel_socket() -> UdpSocket {
    let socket = UdpSocket::bind((KERNEL_ADDR, 0)).unwrap();
    socket.set_nonblocking(true).unwrap();
    socket
}

fn zhida_address() -> SocketAddr {
    (ZHIDA_ADDR, PORT).into()
}

fn endpoint(address: SocketAddr) -> IpEndpoint {
    let SocketAddr::V4(address) = address else {
        panic!("expected an IPv4 socket");
    };
    let [a, b, c, d] = address.ip().octets();
    IpEndpoint::new(Ipv4Address::new(a, b, c, d).into(), address.port())
}

fn add_udp(stack: &mut Stack, tx_checksum: bool) -> UdpHandle {
    stack
        .add_udp(UdpConfig {
            port: PORT,
            rx_queue: BURST,
            tx_checksum,
            broadcast: false,
        })
        .unwrap()
}

fn turn(stack: &mut Stack, start: Instant) {
    let elapsed = start.elapsed();
    assert!(elapsed < DEADLINE, "UDP exchange exceeded {DEADLINE:?}");
    let now = StackInstant::from_micros(i64::try_from(elapsed.as_micros()).unwrap());
    let result = stack.turn(now, BURST).unwrap();
    assert_eq!(result.rx_rejected, 0);
    assert_eq!(result.rx_ipv4_checksum_bad, 0);
    std::thread::yield_now();
}

fn send_kernel(stack: &mut Stack, start: Instant, socket: &UdpSocket, payload: &[u8]) {
    loop {
        turn(stack, start);
        match socket.send_to(payload, zhida_address()) {
            Ok(len) => {
                assert_eq!(len, payload.len());
                return;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("kernel send_to: {error}"),
        }
    }
}

fn recv_zhida(stack: &mut Stack, start: Instant, handle: &UdpHandle) -> UdpDatagram {
    loop {
        turn(stack, start);
        if let Some(datagram) = stack.udp_mut(&handle).recv() {
            return datagram;
        }
    }
}

fn send_zhida(
    stack: &mut Stack,
    start: Instant,
    handle: &UdpHandle,
    to: Option<IpEndpoint>,
    payload: &[u8],
) {
    loop {
        turn(stack, start);
        match stack.udp_send(&handle, to, payload) {
            Ok(()) => return,
            Err(UdpSendError::NeighborPending | UdpSendError::WouldBlock) => {}
            Err(error) => panic!("Zhida udp_send: {error:?}"),
        }
    }
}

fn recv_kernel(stack: &mut Stack, start: Instant, socket: &UdpSocket, payload: &[u8]) {
    let mut buffer = [0; 2048];
    loop {
        turn(stack, start);
        match socket.recv_from(&mut buffer) {
            Ok((len, src)) => {
                assert_eq!(src, zhida_address());
                assert_eq!(&buffer[..len], payload);
                return;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("kernel recv_from: {error}"),
        }
    }
}

fn assert_kernel_quiet(stack: &mut Stack, start: Instant, socket: &UdpSocket) {
    let until = Instant::now()
        .checked_add(QUIET)
        .expect("quiet deadline exceeds Instant");
    let mut buffer = [0; 2048];
    while Instant::now() < until {
        turn(stack, start);
        match socket.recv_from(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            result => panic!("unexpected kernel receive: {result:?}"),
        }
    }
}

fn payloads() -> Vec<Vec<u8>> {
    let mut result = vec![vec![0x01], vec![0x02; 1472]];
    for sequence in 0u32..200 {
        let size = [4, 17, 64, 511, 1024, 1472][usize::try_from(sequence).unwrap() % 6];
        let mut payload = vec![u8::try_from(sequence).unwrap(); size];
        payload[..4].copy_from_slice(&sequence.to_be_bytes());
        result.push(payload);
    }
    result
}

#[zhida_test_support::pinned_test]
fn kernel_to_zhida_datagrams() {
    with_eal(|eal| {
        let names = Names {
            vdev: c"net_tap_udpk_rx",
            iface: c"cdudp_rx",
            rx_pool: c"udpk_rx_rx",
            tx_pool: c"udpk_rx_tx",
        };
        with_stack(eal, names, |stack, start| {
            let handle = add_udp(stack, true);
            let kernel = kernel_socket();
            let src = endpoint(kernel.local_addr().unwrap());
            let payloads = payloads();
            for payload in &payloads {
                send_kernel(stack, start, &kernel, payload);
                let datagram = recv_zhida(stack, start, &handle);
                assert_eq!(datagram.src(), src);
                assert_eq!(datagram.payload(), payload);
                drop(datagram);
            }
            let stats = stack.udp(&handle).stats();
            assert_eq!(stats.rx_delivered, u64::try_from(payloads.len()).unwrap());
            assert_eq!(stats.rx_dropped_full, 0);
            assert_eq!(stats.rx_dropped_peer, 0);
            assert_eq!(stack.udp(&handle).rx_queued(), 0);
            assert_eq!(stack.udp_counters().rx_checksum_bad, 0);
        });
    });
}

#[zhida_test_support::pinned_test]
fn offload_kernel_to_zhida_and_back() {
    with_eal(|eal| {
        for (tx_checksum, names) in [
            (true, Names {
                vdev: c"net_tap_udpk_off_on",
                iface: c"cdudp_off_on",
                rx_pool: c"udpk_off_on_rx",
                tx_pool: c"udpk_off_on_tx",
            }),
            (false, Names {
                vdev: c"net_tap_udpk_off_no",
                iface: c"cdudp_off_no",
                rx_pool: c"udpk_off_no_rx",
                tx_pool: c"udpk_off_no_tx",
            }),
        ] {
            let iface = names.iface;
            let offloads = Offloads {
                rx_timestamp: false,
                rx_checksum: true,
                tx_tcp_checksum: true,
                tx_udp_checksum: true,
            };
            with_stack_offloads(eal, names, offloads, |stack, start| {
                let handle = add_udp(stack, tx_checksum);
                let kernel = kernel_socket();
                let peer = endpoint(kernel.local_addr().unwrap());
                let payloads = payloads();
                for payload in &payloads {
                    send_kernel(stack, start, &kernel, payload);
                    let datagram = recv_zhida(stack, start, &handle);
                    assert_eq!(datagram.src(), peer);
                    assert_eq!(datagram.payload(), payload);
                    drop(datagram);
                }
                assert_eq!(stack.udp(&handle).stats().rx_delivered, payloads.len() as u64);
                assert_eq!(stack.udp(&handle).rx_queued(), 0);
                let capture = UdpCapture::bind(iface);
                for payload in &payloads {
                    send_zhida(stack, start, &handle, Some(peer), payload);
                    recv_kernel(stack, start, &kernel, payload);
                    capture.verify_next(stack, start, peer, payload);
                }
                assert_eq!(stack.udp_counters().rx_checksum_bad, 0);
                assert_kernel_quiet(stack, start, &kernel);
            });
        }
    });
}

#[zhida_test_support::pinned_test]
fn zhida_to_kernel_datagrams() {
    with_eal(|eal| {
        let names = Names {
            vdev: c"net_tap_udpk_tx",
            iface: c"cdudp_tx",
            rx_pool: c"udpk_tx_rx",
            tx_pool: c"udpk_tx_tx",
        };
        with_stack(eal, names, |stack, start| {
            let handle = add_udp(stack, true);
            let kernel = kernel_socket();
            let to = Some(endpoint(kernel.local_addr().unwrap()));
            for payload in payloads() {
                send_zhida(stack, start, &handle, to, &payload);
                recv_kernel(stack, start, &kernel, &payload);
            }
            assert_kernel_quiet(stack, start, &kernel);
        });
    });
}

#[zhida_test_support::pinned_test]
fn kernel_zero_checksum_accepted() {
    with_eal(|eal| {
        let names = Names {
            vdev: c"net_tap_udpk_zrx",
            iface: c"cdudp_zrx",
            rx_pool: c"udpk_zrx_rx",
            tx_pool: c"udpk_zrx_tx",
        };
        with_stack(eal, names, |stack, start| {
            let handle = add_udp(stack, true);
            let kernel = kernel_socket();
            let enabled: libc::c_int = 1;
            // SAFETY: SO_NO_CHECK takes a pointer to a c_int of this length.
            let rc = unsafe {
                libc::setsockopt(
                    kernel.as_raw_fd(),
                    libc::SOL_SOCKET,
                    11,
                    (&enabled as *const libc::c_int).cast(),
                    mem::size_of_val(&enabled) as libc::socklen_t,
                )
            };
            assert_eq!(rc, 0, "SO_NO_CHECK: {}", io::Error::last_os_error());
            let payload = b"kernel checksum zero";
            assert_eq!(stack.udp_counters().rx_checksum_bad, 0);
            send_kernel(stack, start, &kernel, payload);
            let datagram = recv_zhida(stack, start, &handle);
            assert_eq!(datagram.src(), endpoint(kernel.local_addr().unwrap()));
            assert_eq!(datagram.payload(), payload);
            drop(datagram);
            assert_eq!(stack.udp(&handle).stats().rx_delivered, 1);
            assert_eq!(stack.udp_counters().rx_checksum_bad, 0);
        });
    });
}

#[zhida_test_support::pinned_test]
fn offload_kernel_zero_checksum_accepted() {
    with_eal(|eal| {
        let names = Names {
            vdev: c"net_tap_udpk_off_zrx",
            iface: c"cdudp_off_zrx",
            rx_pool: c"udpk_off_zrx_rx",
            tx_pool: c"udpk_off_zrx_tx",
        };
        let offloads = Offloads {
            rx_timestamp: false,
            rx_checksum: true,
            tx_tcp_checksum: false,
            tx_udp_checksum: false,
        };
        with_stack_offloads(eal, names, offloads, |stack, start| {
            let handle = add_udp(stack, true);
            let kernel = kernel_socket();
            let enabled: libc::c_int = 1;
            // SAFETY: SO_NO_CHECK takes a pointer to a c_int of this length.
            let rc = unsafe {
                libc::setsockopt(
                    kernel.as_raw_fd(),
                    libc::SOL_SOCKET,
                    11,
                    (&enabled as *const libc::c_int).cast(),
                    mem::size_of_val(&enabled) as libc::socklen_t,
                )
            };
            assert_eq!(rc, 0, "SO_NO_CHECK: {}", io::Error::last_os_error());
            let payload = b"kernel checksum zero";
            assert_eq!(stack.udp_counters().rx_checksum_bad, 0);
            send_kernel(stack, start, &kernel, payload);
            let datagram = recv_zhida(stack, start, &handle);
            assert_eq!(datagram.src(), endpoint(kernel.local_addr().unwrap()));
            assert_eq!(datagram.payload(), payload);
            drop(datagram);
            assert_eq!(stack.udp(&handle).stats().rx_delivered, 1);
            assert_eq!(stack.udp_counters().rx_checksum_bad, 0);
        });
    });
}

#[zhida_test_support::pinned_test]
fn zhida_zero_checksum_accepted_by_kernel() {
    with_eal(|eal| {
        let names = Names {
            vdev: c"net_tap_udpk_ztx",
            iface: c"cdudp_ztx",
            rx_pool: c"udpk_ztx_rx",
            tx_pool: c"udpk_ztx_tx",
        };
        with_stack(eal, names, |stack, start| {
            let handle = add_udp(stack, false);
            let kernel = kernel_socket();
            let payload = b"Zhida checksum zero";
            send_zhida(
                stack,
                start,
                &handle,
                Some(endpoint(kernel.local_addr().unwrap())),
                payload,
            );
            recv_kernel(stack, start, &kernel, payload);
            assert_kernel_quiet(stack, start, &kernel);
        });
    });
}

#[zhida_test_support::pinned_test]
fn connected_zhida_socket_echo() {
    with_eal(|eal| {
        let names = Names {
            vdev: c"net_tap_udpk_echo",
            iface: c"cdudp_echo",
            rx_pool: c"udpk_echo_rx",
            tx_pool: c"udpk_echo_tx",
        };
        with_stack(eal, names, |stack, start| {
            let handle = add_udp(stack, true);
            let kernel = kernel_socket();
            let peer = endpoint(kernel.local_addr().unwrap());
            stack.udp_mut(&handle).connect(peer).unwrap();
            let payloads = payloads();
            for payload in &payloads {
                send_kernel(stack, start, &kernel, payload);
                let datagram = recv_zhida(stack, start, &handle);
                assert_eq!(datagram.src(), peer);
                assert_eq!(datagram.payload(), payload);
                send_zhida(stack, start, &handle, None, datagram.payload());
                drop(datagram);
                recv_kernel(stack, start, &kernel, payload);
            }
            let other = kernel_socket();
            assert_ne!(other.local_addr().unwrap(), kernel.local_addr().unwrap());
            send_kernel(stack, start, &other, b"wrong peer");
            while stack.udp(&handle).stats().rx_dropped_peer == 0 {
                turn(stack, start);
            }
            let stats = stack.udp(&handle).stats();
            assert_eq!(stats.rx_dropped_peer, 1);
            assert_eq!(stats.rx_dropped_full, 0);
            assert_eq!(stats.rx_delivered, u64::try_from(payloads.len()).unwrap());
            assert!(stack.udp_mut(&handle).recv().is_none());
            assert_kernel_quiet(stack, start, &other);
            assert_kernel_quiet(stack, start, &kernel);
        });
    });
}

#[zhida_test_support::pinned_test]
fn closed_port_no_icmp() {
    with_eal(|eal| {
        let names = Names {
            vdev: c"net_tap_udpk_closed",
            iface: c"cdudp_closed",
            rx_pool: c"udpk_closed_rx",
            tx_pool: c"udpk_closed_tx",
        };
        with_stack(eal, names, |stack, start| {
            let kernel = kernel_socket();
            kernel.connect(zhida_address()).unwrap();
            let payload = b"closed port";
            loop {
                turn(stack, start);
                match kernel.send(payload) {
                    Ok(len) => {
                        assert_eq!(len, payload.len());
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!("connected kernel send: {error}"),
                }
            }
            while stack.udp_counters().rx_no_port == 0 {
                turn(stack, start);
            }
            assert_eq!(stack.udp_counters().rx_no_port, 1);
            assert_kernel_quiet(stack, start, &kernel);
            kernel.set_nonblocking(false).unwrap();
            kernel.set_read_timeout(Some(QUIET)).unwrap();
            let mut buffer = [0; 2048];
            let error = kernel.recv(&mut buffer).unwrap_err();
            assert!(
                matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ),
                "closed port recv returned {error} instead of a timeout"
            );
            assert_ne!(error.raw_os_error(), Some(libc::ECONNREFUSED));
        });
    });
}

#[zhida_test_support::pinned_test]
fn oversize_refused() {
    with_eal(|eal| {
        let names = Names {
            vdev: c"net_tap_udpk_large",
            iface: c"cdudp_large",
            rx_pool: c"udpk_large_rx",
            tx_pool: c"udpk_large_tx",
        };
        with_stack(eal, names, |stack, start| {
            let handle = add_udp(stack, true);
            let kernel = kernel_socket();
            let to = Some(endpoint(kernel.local_addr().unwrap()));
            send_zhida(stack, start, &handle, to, b"warm");
            recv_kernel(stack, start, &kernel, b"warm");
            assert_eq!(
                stack.udp_send(&handle, to, &[0x5a; 1473]),
                Err(UdpSendError::TooLarge)
            );
            assert_kernel_quiet(stack, start, &kernel);
        });
    });
}
