use zhida_test_kit::pair::{config, drain_bytes, pattern, tcp_socket_sized, Side, BUDGET, T0};
use zhida_test_kit::ring_port::{resize, RingPort};
use zhida_test_kit::with_eal;
use dpdk_smoltcp::smoltcp::iface::PathMtu;
use dpdk_smoltcp::smoltcp::phy::ChecksumCapabilities;
use dpdk_smoltcp::smoltcp::socket::tcp::{self, State};
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, IpEndpoint, IpProtocol, Ipv4Address,
    Ipv4Cidr, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr,
};
use dpdk_smoltcp::{rx_reserve, Eal, Stack, TcpHandle, UdpConfig, UdpSendError};

const A: usize = 0;
const B: usize = 1;
const C: usize = 2;
const BUFFER: usize = 32 * 1024;
const TRANSFER: usize = 64 * 1024;
const ROUNDS: usize = 100_000;
const UDP_PORT: u16 = 1234;

fn ip(node: usize) -> Ipv4Address {
    Ipv4Address::new(10, 0, 0, 11 + u8::try_from(node).unwrap())
}

fn mac(node: usize) -> EthernetAddress {
    EthernetAddress([2, 0, 0, 0, 0, 21 + u8::try_from(node).unwrap()])
}

fn endpoint(node: usize, port: u16) -> IpEndpoint {
    IpEndpoint::new(ip(node).into(), port)
}

struct Frame {
    from: usize,
    to: usize,
    bytes: Vec<u8>,
    dropped: bool,
}

struct Network {
    stacks: [Stack; 3],
    rings: [RingPort; 3],
    now: Instant,
    capture: Vec<Frame>,
}

impl Network {
    fn new(eal: &Eal, names: [&str; 3]) -> Self {
        let rings = names.map(|name| RingPort::new(name, 64, 64));
        let paths = [PathMtu { prefix: Ipv4Cidr::new(ip(C), 32), mtu: 1500 }];
        let stacks = [A, B, C].map(|node| {
            let mut stack = config(Side::A);
            stack.ethernet = mac(node);
            stack.ipv4 = Ipv4Cidr::new(ip(node), 24);
            stack.random_seed = 11 + u64::try_from(node).unwrap();
            stack.max_sockets = 4;
            stack.max_udp_sockets = 2;
            stack.paths = if node == A { &paths } else { &[] };
            let mut port = rings[node].config();
            resize(&mut port, 9000, 9216);
            let reserve = rx_reserve(port.rx_descriptors, stack.rx_staging, port.rx_pool.cache_size);
            let tcp = tcp::rx_mbuf_budget(&tcp_socket_sized(BUFFER), 9000)
                .checked_mul(stack.max_sockets).expect("TCP budget overflow");
            let count = reserve.checked_add(tcp).and_then(|n| n.checked_add(16))
                .expect("RX pool count overflow");
            port.rx_pool.count = u32::try_from(count).unwrap();
            port.tx_pool.count = 127;
            match Stack::new(rings[node].open_with(eal, port), stack, T0) {
                Ok(stack) => stack,
                Err((_, error)) => panic!("{error}"),
            }
        });
        Self { stacks, rings, now: T0, capture: Vec::new() }
    }

    fn step(&mut self, mut drop_frame: impl FnMut(&Frame) -> bool) {
        for from in [A, B, C] {
            self.stacks[from].turn(self.now, BUDGET).unwrap();
            for bytes in self.rings[from].take_tx() {
                let eth = EthernetFrame::new_checked(bytes.as_slice()).unwrap();
                assert_eq!(eth.src_addr(), mac(from));
                let dst = eth.dst_addr();
                if dst == EthernetAddress::BROADCAST {
                    assert_eq!(eth.ethertype(), EthernetProtocol::Arp);
                } else {
                    assert!([A, B, C].into_iter().any(|node| mac(node) == dst));
                }
                for to in [A, B, C] {
                    if to == from || (dst != mac(to) && dst != EthernetAddress::BROADCAST) {
                        continue;
                    }
                    let mut frame = Frame { from, to, bytes: bytes.clone(), dropped: false };
                    frame.dropped = drop_frame(&frame);
                    if !frame.dropped {
                        self.rings[to].inject(std::slice::from_ref(&frame.bytes));
                    }
                    self.capture.push(frame);
                }
            }
        }
        self.now = Instant::from_micros(self.now.total_micros().checked_add(1000)
            .expect("clock overflow"));
    }

    fn connect(&mut self, client: usize, server: usize, port: u16) -> [(usize, TcpHandle); 2] {
        let listener = self.stacks[server].add_tcp(tcp_socket_sized(BUFFER)).unwrap();
        self.stacks[server].listen(&listener, port).unwrap();
        let active = self.stacks[client].add_tcp(tcp_socket_sized(BUFFER)).unwrap();
        self.stacks[client].connect(&active, endpoint(server, port), port.checked_add(10_000)
            .expect("client port overflow")).unwrap();
        [(client, active), (server, listener)]
    }

    fn close(self) {
        let ports = self.stacks.map(Stack::into_port);
        for ring in &self.rings {
            ring.drain();
            assert_eq!(ring.in_use(), (0, 0));
            ring.assert_returned_exactly_once();
        }
        for port in ports {
            port.try_close().unwrap();
        }
        for ring in self.rings {
            ring.close();
        }
    }
}

fn segment(frame: &Frame) -> Option<TcpRepr<'_>> {
    let eth = EthernetFrame::new_checked(frame.bytes.as_slice()).unwrap();
    if eth.ethertype() != EthernetProtocol::Ipv4 {
        return None;
    }
    let packet = Ipv4Packet::new_checked(eth.payload()).unwrap();
    let caps = ChecksumCapabilities::default();
    let repr = Ipv4Repr::parse(&packet, &caps).unwrap();
    assert_eq!((repr.src_addr, repr.dst_addr), (ip(frame.from), ip(frame.to)));
    if repr.next_header != IpProtocol::Tcp {
        return None;
    }
    let tcp = TcpPacket::new_checked(packet.payload()).unwrap();
    Some(TcpRepr::parse(&tcp, &ip(frame.from).into(), &ip(frame.to).into(), &caps).unwrap())
}

fn establish(net: &mut Network, connections: &[[(usize, TcpHandle); 2]]) {
    for _ in 0..ROUNDS {
        net.step(|_| false);
        if connections.iter().flatten().all(|(node, handle)| {
            net.stacks[*node].tcp(handle).state() == State::Established
        }) {
            return;
        }
    }
    panic!("TCP handshakes did not complete");
}

fn transfer(
    net: &mut Network,
    connections: &[[(usize, TcpHandle); 2]],
    directions: usize,
    mut drop_frame: impl FnMut(&Frame) -> bool,
) {
    let streams = connections.len().checked_mul(directions).expect("stream count overflow");
    let data: Vec<_> = (0..streams).map(|i| pattern(TRANSFER, 1 + u32::try_from(i).unwrap()))
        .collect();
    let mut written = vec![0usize; streams];
    let mut received = vec![Vec::new(); streams];
    for _ in 0..ROUNDS {
        for (connection, ends) in connections.iter().enumerate() {
            for direction in 0..directions {
                let i = connection.checked_mul(directions).and_then(|n| n.checked_add(direction))
                    .expect("stream index overflow");
                let (from, sender) = &ends[direction];
                let (to, receiver) = &ends[1 - direction];
                let sent = net.stacks[*from].tcp_mut(sender).send_slice(&data[i][written[i]..]).unwrap();
                written[i] = written[i].checked_add(sent).expect("sent byte count overflow");
                received[i].extend_from_slice(&drain_bytes(net.stacks[*to].tcp_mut(receiver)).unwrap());
                assert!(received[i].len() <= data[i].len());
            }
        }
        if received.iter().zip(&data).all(|(got, sent)| got.len() == sent.len()) {
            assert_eq!(received, data);
            return;
        }
        net.step(&mut drop_frame);
    }
    panic!("TCP transfers did not complete");
}

#[zhida_test_support::pinned_test]
fn one_stack_mixed_tcp_mss_active_and_passive() {
    with_eal(|eal| {
        let mut net = Network::new(eal, ["mixma", "mixmb", "mixmc"]);
        let connections = [
            net.connect(A, B, 8001), net.connect(A, C, 8002),
            net.connect(B, A, 8003), net.connect(C, A, 8004),
        ];
        establish(&mut net, &connections);
        for [(client, active), (server, passive)] in &connections {
            let client_port = net.stacks[*client].tcp(active).local_endpoint().unwrap().port;
            let server_port = net.stacks[*server].tcp(passive).local_endpoint().unwrap().port;
            for (from, to, src_port, dst_port, ack) in [
                (*client, *server, client_port, server_port, false),
                (*server, *client, server_port, client_port, true),
            ] {
                let offers: Vec<_> = net.capture.iter().filter(|f| f.from == from && f.to == to)
                    .filter_map(segment).filter(|tcp| {
                        tcp.control == TcpControl::Syn && tcp.ack_number.is_some() == ack
                            && (tcp.src_port, tcp.dst_port) == (src_port, dst_port)
                    }).map(|tcp| tcp.max_seg_size).collect();
                assert_eq!(offers, [Some(if from == A && to == C { 1460 } else { 8960 })]);
            }
        }
        transfer(&mut net, &connections, 2, |_| false);
        for frame in &net.capture {
            assert!(!frame.dropped);
            if frame.from == C || frame.to == C {
                assert!(frame.bytes.len() <= 1514, "oversized frame involving C");
            }
            if let Some(tcp) = segment(frame) {
                if !tcp.payload.is_empty() {
                    let cap = if frame.from == C || frame.to == C { 1460 } else { 8960 };
                    assert!(tcp.payload.len() <= cap);
                }
            }
        }
        for ends in &connections {
            for direction in 0..2 {
                let (from, handle) = &ends[direction];
                let (to, _) = &ends[1 - direction];
                let port = net.stacks[*from].tcp(handle).local_endpoint().unwrap().port;
                let cap = if *from == C || *to == C { 1460 } else { 8960 };
                assert!(net.capture.iter().filter(|f| f.from == *from && f.to == *to)
                    .filter_map(segment).any(|tcp| tcp.src_port == port && tcp.payload.len() == cap),
                    "no full-sized segment {from}->{to} on port {port}");
            }
        }
        net.close();
    });
}

#[zhida_test_support::pinned_test]
fn mixed_retransmission_keeps_cap() {
    with_eal(|eal| {
        let mut net = Network::new(eal, ["mixra", "mixrb", "mixrc"]);
        let connections = [net.connect(A, B, 8101), net.connect(A, C, 8102)];
        establish(&mut net, &connections);
        let mut dropped = [false; 3];
        transfer(&mut net, &connections, 1, |frame| {
            if frame.from != A || dropped[frame.to] {
                return false;
            }
            let cap = if frame.to == C { 1460 } else { 8960 };
            if segment(frame).is_some_and(|tcp| tcp.payload.len() == cap) {
                dropped[frame.to] = true;
                true
            } else {
                false
            }
        });
        assert_eq!(dropped, [false, true, true]);
        for to in [B, C] {
            let losses: Vec<_> = net.capture.iter().enumerate()
                .filter(|(_, f)| f.from == A && f.to == to && f.dropped).collect();
            assert_eq!(losses.len(), 1);
            let (index, lost) = losses[0];
            let lost = segment(lost).unwrap();
            assert!(net.capture[index + 1..].iter()
                .filter(|f| f.from == A && f.to == to && !f.dropped)
                .filter_map(segment).any(|tcp| {
                    tcp.seq_number == lost.seq_number && !tcp.payload.is_empty()
                        && lost.payload.starts_with(tcp.payload)
                }), "dropped segment was not retransmitted to {to}");
            let cap = if to == C { 1460 } else { 8960 };
            for tcp in net.capture.iter().filter(|f| f.from == A && f.to == to)
                .filter_map(segment)
            {
                assert!(tcp.payload.len() <= cap, "oversized segment to {to}");
            }
        }
        net.close();
    });
}

#[zhida_test_support::pinned_test]
fn mixed_udp_destinations() {
    with_eal(|eal| {
        let mut net = Network::new(eal, ["mixua", "mixub", "mixuc"]);
        let udp_config = |port| UdpConfig {
            port, rx_queue: 8, tx_checksum: true, broadcast: false,
        };
        let handles = net.stacks.each_mut().map(|stack| stack.add_udp(udp_config(UDP_PORT)).unwrap());
        for to in [B, C] {
            assert_eq!(net.stacks[A].udp_send(&handles[A], Some(endpoint(to, UDP_PORT)), &[1]),
                Err(UdpSendError::NeighborPending));
            for _ in 0..3 {
                net.step(|_| false);
            }
        }
        for (sequence, to) in [B, C, B, C, B, C].into_iter().enumerate() {
            if sequence == 1 {
                let before = net.capture.len();
                assert_eq!(net.stacks[A].udp_send(&handles[A], Some(endpoint(C, UDP_PORT)), &[7; 1473]),
                    Err(UdpSendError::TooLarge));
                for _ in 0..2 {
                    net.step(|_| false);
                }
                assert_eq!(net.capture.len(), before, "oversized UDP send put frames on wire");
                assert!(net.stacks[C].udp_mut(&handles[C]).recv().is_none());
            }
            let size = if to == B { 8972 } else { 1472 };
            let payload = pattern(size, 20 + u32::try_from(sequence).unwrap());
            let before = net.capture.len();
            assert_eq!(net.stacks[A].udp_send(&handles[A], Some(endpoint(to, UDP_PORT)), &payload), Ok(()));
            for _ in 0..2 {
                net.step(|_| false);
            }
            assert_eq!(net.capture.len(), before + 1);
            let frame = &net.capture[before];
            assert_eq!((frame.from, frame.to, frame.dropped), (A, to, false));
            assert_eq!(frame.bytes.len(), size + 42);
            let datagram = net.stacks[to].udp_mut(&handles[to]).recv().unwrap();
            assert_eq!(datagram.src(), endpoint(A, UDP_PORT));
            assert_eq!(datagram.dst_addr(), ip(to));
            assert_eq!(datagram.payload(), payload.as_slice());
            drop(datagram);
            for node in [B, C] {
                assert!(net.stacks[node].udp_mut(&handles[node]).recv().is_none());
            }
        }
        let connected = net.stacks[A].add_udp(udp_config(UDP_PORT + 1)).unwrap();
        net.stacks[A].udp_mut(&connected).connect(endpoint(C, UDP_PORT)).unwrap();
        let before = net.capture.len();
        assert_eq!(net.stacks[A].udp_send(&connected, None, &[8; 1473]), Err(UdpSendError::TooLarge));
        for _ in 0..2 {
            net.step(|_| false);
        }
        assert_eq!(net.capture.len(), before);
        assert!(net.stacks[C].udp_mut(&handles[C]).recv().is_none());
        net.close();
    });
}
