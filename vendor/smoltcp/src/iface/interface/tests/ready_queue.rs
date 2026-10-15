use super::*;
use crate::iface::SocketHandle;
use crate::socket::tcp;
use crate::tests::TestingDevice;
use crate::time::Duration;

const LOCAL: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
const REMOTE: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
const REMOTE_HARDWARE: EthernetAddress = EthernetAddress([2, 0, 0, 0, 0, 1]);
const START: Instant = Instant::from_millis_const(100);

fn connect(iface: &mut Interface, sockets: &mut TcpSet<'static>, port: u16) -> SocketHandle {
    let mut socket = tcp::Socket::new(
        tcp::RxBuffer::new(4096),
        tcp::SocketBuffer::new(vec![0; 4096]),
    );
    socket.set_ack_delay(None);
    socket
        .connect(iface.context(), (REMOTE, 65000), (LOCAL, port))
        .unwrap();
    sockets.add(socket)
}

fn segment(port: u16, control: TcpControl, seq: i32, ack: TcpSeqNumber) -> TcpRepr<'static> {
    TcpRepr {
        src_port: 65000,
        dst_port: port,
        control,
        seq_number: TcpSeqNumber(seq),
        ack_number: Some(ack),
        window_len: 4096,
        window_scale: None,
        max_seg_size: Some(512),
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    }
}

fn receive(iface: &mut Interface, sockets: &mut TcpSet, device: &mut TestingDevice, tcp: TcpRepr) {
    receive_at(iface, sockets, device, START, tcp);
}

fn receive_at(
    iface: &mut Interface,
    sockets: &mut TcpSet,
    device: &mut TestingDevice,
    now: Instant,
    tcp: TcpRepr,
) {
    queue_segment(iface, device, tcp);
    assert_eq!(
        iface.poll_ingress_single(now, device, sockets),
        PollIngressSingleResult::SocketStateChanged
    );
}

fn queue_segment(iface: &Interface, device: &mut TestingDevice, tcp: TcpRepr) {
    let ip = Ipv4Repr {
        src_addr: REMOTE,
        dst_addr: LOCAL,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    let mut bytes = vec![0; ip.buffer_len() + tcp.buffer_len()];
    ip.emit(
        &mut Ipv4Packet::new_unchecked(&mut bytes),
        &ChecksumCapabilities::default(),
    );
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut bytes[ip.buffer_len()..]),
        &REMOTE.into(),
        &LOCAL.into(),
        &ChecksumCapabilities::default(),
    );
    if device.capabilities().medium == Medium::Ethernet {
        let mut frame = vec![0; EthernetFrame::<&[u8]>::buffer_len(bytes.len())];
        let mut ethernet = EthernetFrame::new_unchecked(&mut frame);
        ethernet.set_src_addr(REMOTE_HARDWARE);
        ethernet.set_dst_addr(iface.inner.hardware_addr.ethernet_or_panic());
        ethernet.set_ethertype(EthernetProtocol::Ipv4);
        ethernet.payload_mut().copy_from_slice(&bytes);
        device.rx_queue.push_back(frame);
    } else {
        device.rx_queue.push_back(bytes);
    }
}

fn take_tcp(device: &mut TestingDevice) -> (u16, TcpControl, TcpSeqNumber, Vec<u8>) {
    let bytes = device.tx_queue.pop_front().unwrap();
    let ethernet;
    let ip_bytes = if device.capabilities().medium == Medium::Ethernet {
        ethernet = EthernetFrame::new_checked(&bytes).unwrap();
        assert_eq!(ethernet.ethertype(), EthernetProtocol::Ipv4);
        ethernet.payload()
    } else {
        bytes.as_slice()
    };
    let ip = Ipv4Packet::new_checked(ip_bytes).unwrap();
    assert!(ip.verify_checksum());
    let tcp = TcpRepr::parse(
        &TcpPacket::new_checked(ip.payload()).unwrap(),
        &LOCAL.into(),
        &REMOTE.into(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();
    (
        tcp.src_port,
        tcp.control,
        tcp.seq_number,
        tcp.payload.to_vec(),
    )
}

fn establish(
    iface: &mut Interface,
    sockets: &mut TcpSet<'static>,
    device: &mut TestingDevice,
    port: u16,
) -> (SocketHandle, TcpSeqNumber) {
    let handle = connect(iface, sockets, port);
    iface.poll_egress(START, device, sockets);
    let (sent_port, control, seq, payload) = take_tcp(device);
    assert_eq!((sent_port, control), (port, TcpControl::Syn));
    assert!(payload.is_empty());
    receive(
        iface,
        sockets,
        device,
        segment(port, TcpControl::Syn, 100, seq + 1),
    );
    assert_eq!(sockets.get(handle).state(), tcp::State::Established);
    iface.poll_egress(START, device, sockets);
    let (sent_port, control, _, payload) = take_tcp(device);
    assert_eq!((sent_port, control), (port, TcpControl::None));
    assert!(payload.is_empty());
    assert_eq!(iface.poll_at(START, sockets), None);
    (handle, seq + 1)
}

fn send_for_rto(
    iface: &mut Interface,
    sockets: &mut TcpSet,
    device: &mut TestingDevice,
    handle: SocketHandle,
    rto: Duration,
) {
    sockets.get_mut(handle).set_rto(rto);
    assert_eq!(sockets.get_mut(handle).send_slice(b"x"), Ok(1));
    iface.poll_egress(START, device, sockets);
    assert_eq!(take_tcp(device).3, b"x");
    assert!(device.tx_queue.is_empty());
}

fn idle_sockets(iface: &mut Interface, sockets: &mut TcpSet<'static>, device: &mut TestingDevice) {
    for port in 1234..1334 {
        establish(iface, sockets, device, port);
    }
    sockets.dispatches.clear();
}

struct RefusingDevice {
    inner: TestingDevice,
    remaining: usize,
}

impl Device for RefusingDevice {
    type RxToken<'a> = <TestingDevice as Device>::RxToken<'a>;
    type TxToken<'a> = <TestingDevice as Device>::TxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        self.inner.capabilities()
    }

    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.inner.receive(timestamp)
    }

    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        self.inner.transmit(timestamp)
    }
}

#[test]
fn egress_idle_means_next_pass_does_nothing() {
    for scenario in [
        "burst", "refused", "bounded", "parked", "touched", "source", "due",
    ] {
        let medium = if scenario == "parked" {
            Medium::Ethernet
        } else {
            Medium::Ip
        };
        let (mut iface, mut sockets, mut device) = setup(medium);
        let handle = if scenario == "parked" {
            connect(&mut iface, &mut sockets, 1234)
        } else {
            establish(&mut iface, &mut sockets, &mut device, 1234).0
        };
        match scenario {
            "burst" | "bounded" => {
                if scenario == "bounded" {
                    let other = establish(&mut iface, &mut sockets, &mut device, 1235).0;
                    sockets.get_mut(other).send_slice(&[2; 3 * 512]).unwrap();
                }
                sockets.get_mut(handle).send_slice(&[1; 3 * 512]).unwrap();
            }
            "due" => {
                send_for_rto(&mut iface, &mut sockets, &mut device, handle, Duration::from_millis(20));
            }
            "refused" => {
                sockets.get_mut(handle).send_slice(&[1; 512]).unwrap();
            }
            _ => {}
        }
        let mut device = RefusingDevice {
            inner: device,
            remaining: if matches!(scenario, "refused" | "due") { 0 } else { usize::MAX },
        };
        let now = if scenario == "due" {
            START + Duration::from_millis(20)
        } else {
            START
        };
        iface.poll_egress(now, &mut device, &mut sockets);
        match scenario {
            "burst" => assert_eq!(device.inner.tx_queue.len(), 3),
            "refused" => assert_eq!(sockets.ready_len(), 1),
            "bounded" => {
                assert_eq!(iface.segments_per_visit, 1);
                assert_eq!(device.inner.tx_queue.len(), 2);
                assert_eq!(sockets.dirty_list, vec![0, 1]);
            }
            "parked" => assert_eq!(sockets.waiting, vec![0]),
            "touched" => {
                sockets.get_mut(handle);
                assert_eq!(sockets.dirty_list, vec![0]);
            }
            "source" => {
                iface.update_ip_addrs(|addrs| addrs.clear());
                assert_eq!(sockets.get(handle).state(), tcp::State::Established);
                let classified = sockets.classify_calls;
                assert_eq!(iface.poll_at(now, &mut sockets), None);
                assert_eq!(sockets.classify_calls, classified);
            }
            "due" => {
                assert_eq!(iface.poll_at(now, &mut sockets), Some(Instant::ZERO));
                assert_eq!(sockets.stored_deadline(0), PollAt::Now);
                assert_eq!(sockets.ready_len(), 1);
                assert!(sockets.dirty_list.is_empty());
                assert!(sockets.waiting.is_empty());
                assert!(!sockets.egress_idle());
            }
            _ => unreachable!(),
        }
        let idle = iface.egress_idle(&sockets);
        assert_eq!(idle, matches!(scenario, "burst" | "source"), "{scenario}");
        let before = (
            sockets.dispatches.len(),
            sockets.classify_calls,
            device.inner.tx_queue.len(),
            sockets.ready_len(),
            sockets.dirty_list.clone(),
        );
        let contents = std::format!("{sockets:?}");
        let result = iface.poll_egress(now, &mut device, &mut sockets);
        let after = (
            sockets.dispatches.len(),
            sockets.classify_calls,
            device.inner.tx_queue.len(),
            sockets.ready_len(),
            sockets.dirty_list.clone(),
        );
        if idle || scenario == "parked" {
            assert_eq!(result, PollResult::None, "{scenario}");
            assert_eq!(before, after, "{scenario}");
            assert_eq!(contents, std::format!("{sockets:?}"), "{scenario}");
        } else {
            assert_ne!(before, after, "{scenario} must do work on the second pass");
        }
    }
}

#[test]
fn one_classify_per_round_trip() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
    sockets.classify_calls = 0;
    assert_eq!(sockets.get_mut(handle).send_slice(&[1; 64]), Ok(64));
    iface.poll_egress(START, &mut device, &mut sockets);
    let send_calls = sockets.classify_calls;
    let frames = device.tx_queue.len();
    assert_eq!(
        iface.poll_egress(START, &mut device, &mut sockets),
        PollResult::None
    );
    assert_eq!(sockets.classify_calls, send_calls);
    assert_eq!(device.tx_queue.len(), frames);
    let (port, _, sent_seq, payload) = take_tcp(&mut device);
    assert_eq!((port, sent_seq), (1234, seq));
    assert_eq!(payload, [1; 64]);
    sockets.classify_calls = 0;
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        segment(1234, TcpControl::None, 101, seq + 64),
    );
    assert_eq!(sockets.classify_calls, 0);
    iface.poll_egress(START, &mut device, &mut sockets);
    let ack_calls = sockets.classify_calls;
    assert_eq!(sockets.get(handle).send_queue(), 0);
    assert!(device.tx_queue.is_empty());
    std::println!("classify calls: send={send_calls}, ACK={ack_calls}");
    assert!(send_calls <= 2, "send classified {send_calls} times");
    assert!(ack_calls <= 1, "ACK classified {ack_calls} times");
}

#[test]
fn busy_connection_does_not_rescan() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let connections: Vec<_> = (1234..1298)
        .map(|port| establish(&mut iface, &mut sockets, &mut device, port))
        .collect();
    assert_eq!(sockets.len(), 64);
    let (handle, mut seq) = connections[0];
    sockets.slot_visits = 0;
    sockets.dispatches.clear();
    for _ in 0..10 {
        assert_eq!(sockets.get_mut(handle).send_slice(&[1; 64]), Ok(64));
        iface.poll_egress(START, &mut device, &mut sockets);
        let (port, _, sent_seq, payload) = take_tcp(&mut device);
        assert_eq!((port, sent_seq), (1234, seq));
        assert_eq!(payload, [1; 64]);
        assert!(device.tx_queue.is_empty());
        seq += 64;
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            segment(1234, TcpControl::None, 101, seq),
        );
        assert_eq!(sockets.get(handle).send_queue(), 0);
    }
    assert_eq!(sockets.dispatches, vec![0; 10]);
    std::println!("busy connection slot visits: {}", sockets.slot_visits);
    assert!(sockets.slot_visits <= 10 * 8, "{} visits", sockets.slot_visits);
}

#[test]
fn ingress_sync_keeps_deadline_dirty() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
    sockets.classify_calls = 0;
    sockets.get_mut(handle).send_slice(&[1; 64]).unwrap();
    for _ in 0..2 {
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            segment(1234, TcpControl::None, 101, seq),
        );
        assert_eq!(sockets.classify_calls, 0);
        assert_eq!(sockets.dirty_list, vec![0]);
    }
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.classify_calls, 2);
    assert_eq!(take_tcp(&mut device).3, [1; 64]);
    assert_eq!(
        iface.poll_egress(START, &mut device, &mut sockets),
        PollResult::None
    );
    assert_eq!(sockets.classify_calls, 2);
    assert!(device.tx_queue.is_empty());
}

#[test]
fn ingress_sync_visits_each_dirty_slot_once() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
    sockets.get_mut(handle);
    sockets.slot_visits = 0;
    sockets.classify_calls = 0;
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        segment(1234, TcpControl::None, 101, seq),
    );
    assert_eq!(sockets.slot_visits, 1);
    assert_eq!(sockets.classify_calls, 0);
    assert_eq!(sockets.dirty_list, vec![0]);
    assert_eq!(sockets.get(handle).state(), tcp::State::Established);
    assert!(device.tx_queue.is_empty());
}

#[test]
#[cfg(feature = "udp-set")]
fn ingress_does_not_resync_processed_sockets() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
    iface.inner.neighbor_cache.fill(
        REMOTE.into(), HardwareAddress::Ethernet(REMOTE_HARDWARE), START,
    );
    let connections: Vec<_> = (1234..1298)
        .map(|port| establish(&mut iface, &mut sockets, &mut device, port))
        .collect();
    assert!(sockets.dirty_list.is_empty());
    for (index, &(_, seq)) in connections.iter().enumerate() {
        queue_segment(&iface, &mut device,
            segment(1234 + index as u16, TcpControl::None, 101, seq));
    }
    sockets.slot_visits = 0;
    sockets.classify_calls = 0;
    sockets.dispatches.clear();
    let mut udp = crate::iface::UdpSet::new(0);
    for _ in 0..connections.len() {
        assert_eq!(
            iface.poll_ingress_single_udp(START, &mut device, &mut sockets, &mut udp),
            PollIngressSingleResult::SocketStateChanged
        );
    }
    assert_eq!(sockets.dirty_list, (0..64).collect::<Vec<_>>());
    assert_eq!(sockets.classify_calls, 0);
    assert!(sockets.dispatches.is_empty());
    assert!(device.rx_queue.is_empty());
    assert!(device.tx_queue.is_empty());
    for &(handle, _) in &connections {
        assert_eq!(sockets.get(handle).state(), tcp::State::Established);
    }
    assert_eq!(sockets.slot_visits, 0);
}

#[rstest]
#[case::get_mut(false)]
#[case::iter_mut(true)]
#[cfg(feature = "udp-set")]
fn ingress_syncs_app_relisten_of_already_dirty_socket(#[case] use_iterator: bool) {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
    let mut udp = crate::iface::UdpSet::new(0);
    queue_segment(&iface, &mut device, segment(1234, TcpControl::None, 101, seq));
    assert_eq!(
        iface.poll_ingress_single_udp(START, &mut device, &mut sockets, &mut udp),
        PollIngressSingleResult::SocketStateChanged
    );
    assert_eq!(sockets.dirty_list, vec![0]);
    if use_iterator {
        let (returned_handle, socket) = sockets.iter_mut().next().unwrap();
        assert_eq!(returned_handle, handle);
        socket.abort();
        socket.listen(1235).unwrap();
    } else {
        sockets.get_mut(handle).abort();
        sockets.get_mut(handle).listen(1235).unwrap();
    }
    assert_eq!(sockets.dirty_list, vec![0]);
    sockets.classify_calls = 0;
    sockets.dispatches.clear();
    queue_segment(&iface, &mut device, TcpRepr {
        ack_number: None,
        ..segment(1235, TcpControl::Syn, 200, seq)
    });
    assert_eq!(
        iface.poll_ingress_single_udp(START, &mut device, &mut sockets, &mut udp),
        PollIngressSingleResult::SocketStateChanged
    );
    assert_eq!(sockets.get(handle).state(), tcp::State::SynReceived);
    assert_eq!(sockets.get(handle).local_endpoint().unwrap().port, 1235);
    assert_eq!(sockets.classify_calls, 0);
    assert!(device.tx_queue.is_empty());
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![0]);
    let (port, control, _, payload) = take_tcp(&mut device);
    assert_eq!((port, control), (1235, TcpControl::Syn));
    assert!(payload.is_empty());
    assert!(device.tx_queue.is_empty());
}

#[test]
fn poll_at_classifies_without_admitting() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, _) = establish(&mut iface, &mut sockets, &mut device, 1234);
    sockets.classify_calls = 0;
    sockets.get_mut(handle).send_slice(&[1; 64]).unwrap();
    assert_eq!(iface.poll_at(START, &mut sockets), Some(Instant::ZERO));
    assert_eq!(sockets.classify_calls, 1);
    assert_eq!(sockets.ready_len(), 0);
    assert_eq!(iface.poll_at(START, &mut sockets), Some(Instant::ZERO));
    assert_eq!(sockets.classify_calls, 1);
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.classify_calls, 2);
    assert_eq!(take_tcp(&mut device).3, [1; 64]);
    assert_eq!(
        iface.poll_egress(START, &mut device, &mut sockets),
        PollResult::None
    );
    assert_eq!(sockets.classify_calls, 2);
    assert!(device.tx_queue.is_empty());
}

#[test]
fn waiting_dirty_socket_classified_once() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
    let handle = connect(&mut iface, &mut sockets, 1234);
    iface.poll_egress(START, &mut device, &mut sockets);
    device.tx_queue.clear();
    assert_eq!(sockets.waiting, vec![0]);
    sockets
        .get_mut(handle)
        .set_rto(Duration::from_secs(3));
    sockets.classify_calls = 0;
    assert_eq!(
        iface.poll_at(START, &mut sockets),
        Some(Instant::from_millis(1024))
    );
    assert_eq!(sockets.classify_calls, 1);
    sockets.classify_calls = 0;
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.classify_calls, 0);
    assert!(device.tx_queue.is_empty());
}

#[test]
fn ipv4_refresh_revives_neighbor_and_releases_waiting_syn() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
    iface
        .inner
        .neighbor_cache
        .fill_with_expiration(REMOTE.into(), REMOTE_HARDWARE.into(), START);
    assert!(matches!(
        iface.inner.neighbor_cache.lookup(&REMOTE.into(), START),
        NeighborAnswer::Stale { .. }
    ));
    let now = START + Duration::from_millis(3_000);
    assert_eq!(
        iface.inner.neighbor_cache.lookup(&REMOTE.into(), now),
        NeighborAnswer::NotFound
    );
    connect(&mut iface, &mut sockets, 1234);
    iface.poll_egress(now, &mut device, &mut sockets);
    assert_eq!(sockets.waiting.len(), 1);
    device.tx_queue.clear();

    let ip = Ipv4Repr {
        src_addr: REMOTE,
        dst_addr: LOCAL,
        next_header: IpProtocol::Unknown(253),
        payload_len: 0,
        hop_limit: 64,
    };
    let mut bytes = vec![0; EthernetFrame::<&[u8]>::buffer_len(ip.buffer_len())];
    let mut ethernet = EthernetFrame::new_unchecked(&mut bytes);
    ethernet.set_src_addr(REMOTE_HARDWARE);
    ethernet.set_dst_addr(iface.inner.hardware_addr.ethernet_or_panic());
    ethernet.set_ethertype(EthernetProtocol::Ipv4);
    ip.emit(
        &mut Ipv4Packet::new_unchecked(ethernet.payload_mut()),
        &ChecksumCapabilities::default(),
    );
    device.rx_queue.push_back(bytes);
    iface.poll_ingress_single(now, &mut device, &mut sockets);
    iface.poll_egress(now, &mut device, &mut sockets);
    assert_eq!(
        device.tx_queue.len(),
        1,
        "revived neighbor must release SYN immediately"
    );
    let (port, control, _, payload) = take_tcp(&mut device);
    assert_eq!((port, control), (1234, TcpControl::Syn));
    assert!(payload.is_empty());
    assert!(sockets.waiting.is_empty());
    iface.poll_at(now, &mut sockets);
}

#[rstest::rstest]
#[case(1, false)]
#[case(64, false)]
#[case(1, true)]
#[case(64, true)]
fn waiting_sockets_rescan_only_on_neighbor_change_or_deadline(
    #[case] count: u16,
    #[case] reply: bool,
) {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
    for port in 1234..1234 + count {
        connect(&mut iface, &mut sockets, port);
    }
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.waiting.len(), usize::from(count));
    let silent_until = START + crate::iface::socket_meta::Meta::DISCOVERY_SILENT_TIME;
    for index in 0..usize::from(count) {
        assert_eq!(sockets.stored_deadline(index), PollAt::Time(silent_until));
    }
    let changes = iface.inner.neighbor_cache.changes();
    device.tx_queue.clear();
    sockets.dispatches.clear();
    for millis in 1..=5 {
        let now = START + Duration::from_millis(millis);
        sockets.classify_calls = 0;
        iface.poll_egress(now, &mut device, &mut sockets);
        assert_eq!(sockets.classify_calls, 0, "egress with {count} waiters");
        assert_eq!(
            iface.poll_at(now, &mut sockets),
            Some(Instant::from_millis(1024))
        );
        assert_eq!(sockets.classify_calls, 0, "poll_at with {count} waiters");
        assert_eq!(iface.inner.neighbor_cache.changes(), changes);
        assert!(sockets.dispatches.is_empty());
        assert!(device.tx_queue.is_empty());
    }
    if reply {
        let local_hardware = iface.inner.hardware_addr.ethernet_or_panic();
        let arp = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: REMOTE_HARDWARE,
            source_protocol_addr: REMOTE,
            target_hardware_addr: local_hardware,
            target_protocol_addr: LOCAL,
        };
        let mut bytes = vec![0; EthernetFrame::<&[u8]>::buffer_len(arp.buffer_len())];
        let mut ethernet = EthernetFrame::new_unchecked(&mut bytes);
        ethernet.set_src_addr(REMOTE_HARDWARE);
        ethernet.set_dst_addr(local_hardware);
        ethernet.set_ethertype(EthernetProtocol::Arp);
        arp.emit(&mut ArpPacket::new_unchecked(ethernet.payload_mut()));
        device.rx_queue.push_back(bytes);
        let now = START + Duration::from_millis(6);
        iface.poll_ingress_single(now, &mut device, &mut sockets);
        assert_ne!(iface.inner.neighbor_cache.changes(), changes);
        iface.poll_egress(now, &mut device, &mut sockets);
        assert_eq!(sockets.dispatches, (0..usize::from(count)).collect::<Vec<_>>());
        for port in 1234..1234 + count {
            let (sent_port, control, _, payload) = take_tcp(&mut device);
            assert_eq!((sent_port, control), (port, TcpControl::Syn));
            assert!(payload.is_empty());
        }
        assert!(sockets.waiting.is_empty());
    } else {
        iface.poll_egress(silent_until - Duration::from_millis(1), &mut device, &mut sockets);
        assert_eq!(sockets.classify_calls, 0);
        assert!(device.tx_queue.is_empty());
        iface.poll_at(silent_until, &mut sockets);
        iface.poll_egress(silent_until, &mut device, &mut sockets);
        assert_eq!(sockets.dispatches, (0..usize::from(count)).collect::<Vec<_>>());
        assert_eq!(device.tx_queue.len(), 1);
        let bytes = device.tx_queue.pop_front().unwrap();
        let ethernet = EthernetFrame::new_checked(&bytes).unwrap();
        assert_eq!(ethernet.ethertype(), EthernetProtocol::Arp);
        assert_eq!(
            ArpRepr::parse(&ArpPacket::new_checked(ethernet.payload()).unwrap()).unwrap(),
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Request,
                source_hardware_addr: iface.inner.hardware_addr.ethernet_or_panic(),
                source_protocol_addr: LOCAL,
                target_hardware_addr: EthernetAddress::BROADCAST,
                target_protocol_addr: REMOTE,
            }
        );
        assert_eq!(iface.inner.neighbor_cache.changes(), changes);
        for index in 0..usize::from(count) {
            assert_eq!(
                sockets.stored_deadline(index),
                PollAt::Time(silent_until + crate::iface::socket_meta::Meta::DISCOVERY_SILENT_TIME)
            );
        }
    }
    assert!(device.tx_queue.is_empty());
}

#[test]
fn due_timer_and_dirty_sockets_admitted_in_slot_order() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let handles: Vec<_> = (1234..1237)
        .map(|port| establish(&mut iface, &mut sockets, &mut device, port).0)
        .collect();
    sockets.get_mut(handles[0]).send_slice(&[1; 64]).unwrap();
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(take_tcp(&mut device).0, 1234);
    assert_eq!(
        iface.poll_at(START, &mut sockets),
        Some(Instant::from_millis(384))
    );
    for index in [2, 1] {
        sockets
            .get_mut(handles[index])
            .send_slice(&[1; 64])
            .unwrap();
    }
    sockets.dispatches.clear();
    iface.poll_egress(START + Duration::from_millis(300), &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![0, 1, 2]);
    for port in [1234, 1235, 1236] {
        assert_eq!(take_tcp(&mut device).0, port);
    }
    assert!(device.tx_queue.is_empty());
}

#[test]
fn idle_sockets_not_dispatched() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    idle_sockets(&mut iface, &mut sockets, &mut device);
    let (active, _) = establish(&mut iface, &mut sockets, &mut device, 1334);
    for handle in sockets.iter().map(|(handle, _)| handle).collect::<Vec<_>>() {
        assert_eq!(sockets.get_mut(handle).state(), tcp::State::Established);
    }
    sockets.dispatches.clear();
    sockets.get_mut(active).send_slice(b"abc").unwrap();
    iface.poll(START, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![100]);
    assert_eq!(take_tcp(&mut device).3, b"abc");
    assert!(device.tx_queue.is_empty());
}

#[test]
fn refused_socket_retried_first() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let handles: Vec<_> = (1234..1237)
        .map(|port| establish(&mut iface, &mut sockets, &mut device, port).0)
        .collect();
    for handle in handles {
        sockets.get_mut(handle).send_slice(&[1; 1024]).unwrap();
    }
    let mut device = RefusingDevice {
        inner: device,
        remaining: 1,
    };
    sockets.dispatches.clear();
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![0, 1]);
    assert_eq!(take_tcp(&mut device.inner).0, 1234);
    sockets.dispatches.clear();
    device.remaining = 3;
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![1, 2, 0]);
    for port in [1235, 1236, 1234] {
        assert_eq!(take_tcp(&mut device.inner).0, port);
    }
}

#[test]
fn still_ready_socket_goes_to_tail() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let a = establish(&mut iface, &mut sockets, &mut device, 1234).0;
    let b = establish(&mut iface, &mut sockets, &mut device, 1235).0;
    for handle in [a, b] {
        sockets.get_mut(handle).send_slice(&[1; 1536]).unwrap();
    }
    sockets.dispatches.clear();
    for _ in 0..3 {
        iface.poll_egress(START, &mut device, &mut sockets);
        for port in [1234, 1235] {
            let (sent_port, _, _, payload) = take_tcp(&mut device);
            assert_eq!(sent_port, port);
            assert_eq!(payload.len(), 512);
        }
        assert!(device.tx_queue.is_empty());
    }
    assert_eq!(sockets.dispatches, vec![0, 1, 0, 1, 0, 1]);
}

#[test]
fn parked_socket_resumes_when_neighbor_learned() {
    let take_relevant_frames = |device: &mut TestingDevice| {
        device
            .tx_queue
            .drain(..)
            .filter(|bytes| {
                let ethernet = EthernetFrame::new_checked(bytes).unwrap();
                match ethernet.ethertype() {
                    EthernetProtocol::Arp => true,
                    EthernetProtocol::Ipv4 => {
                        Ipv4Packet::new_checked(ethernet.payload())
                            .unwrap()
                            .next_header()
                            == IpProtocol::Tcp
                    }
                    _ => false,
                }
            })
            .collect::<Vec<_>>()
    };
    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
    connect(&mut iface, &mut sockets, 1234);
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![0]);
    let frames = take_relevant_frames(&mut device);
    assert_eq!(frames.len(), 1);
    let ethernet = EthernetFrame::new_checked(&frames[0]).unwrap();
    assert_eq!(ethernet.ethertype(), EthernetProtocol::Arp);
    assert_eq!(
        ArpRepr::parse(&ArpPacket::new_checked(ethernet.payload()).unwrap()).unwrap(),
        ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: iface.inner.hardware_addr.ethernet_or_panic(),
            source_protocol_addr: LOCAL,
            target_hardware_addr: EthernetAddress::BROADCAST,
            target_protocol_addr: REMOTE,
        }
    );
    assert_eq!(
        iface.poll_at(START, &mut sockets),
        Some(Instant::from_millis(1024))
    );
    sockets.dispatches.clear();
    let learned = START + Duration::from_millis(1);
    iface.poll(learned, &mut device, &mut sockets);
    assert!(sockets.dispatches.is_empty());
    assert!(take_relevant_frames(&mut device).is_empty());
    iface.inner.neighbor_cache.fill(
        REMOTE.into(),
        HardwareAddress::Ethernet(EthernetAddress([2, 0, 0, 0, 0, 1])),
        learned,
    );
    iface.poll(learned, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![0]);
    let frames = take_relevant_frames(&mut device);
    assert_eq!(frames.len(), 1);
    let ethernet = EthernetFrame::new_checked(&frames[0]).unwrap();
    assert_eq!(ethernet.ethertype(), EthernetProtocol::Ipv4);
    let ip = Ipv4Packet::new_checked(ethernet.payload()).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(tcp.syn());
    assert_eq!(tcp.src_port(), 1234);
    assert!(sockets.waiting.is_empty());
}

#[test]
fn reconnect_to_cached_neighbor_sends_syn_without_old_neighbor_silence() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
    let handle = connect(&mut iface, &mut sockets, 1234);
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.waiting, vec![0]);
    assert_eq!(device.tx_queue.len(), 1);
    let bytes = device.tx_queue.pop_front().unwrap();
    let ethernet = EthernetFrame::new_checked(&bytes).unwrap();
    assert_eq!(ethernet.ethertype(), EthernetProtocol::Arp);
    assert_eq!(
        ArpRepr::parse(&ArpPacket::new_checked(ethernet.payload()).unwrap()).unwrap(),
        ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: iface.inner.hardware_addr.ethernet_or_panic(),
            source_protocol_addr: LOCAL,
            target_hardware_addr: EthernetAddress::BROADCAST,
            target_protocol_addr: REMOTE,
        }
    );
    assert_eq!(
        iface.poll_at(START, &mut sockets),
        Some(Instant::from_millis(1024))
    );

    let peer_b = Ipv4Address::new(192, 168, 1, 3);
    let peer_b_hardware = EthernetAddress([2, 0, 0, 0, 0, 2]);
    iface.inner.neighbor_cache.fill(
        peer_b.into(),
        HardwareAddress::Ethernet(peer_b_hardware),
        START,
    );
    let socket = sockets.get_mut(handle);
    socket.abort();
    socket
        .connect(iface.context(), (peer_b, 65000), (LOCAL, 1234))
        .unwrap();
    iface.poll_egress(START, &mut device, &mut sockets);

    assert_eq!(device.tx_queue.len(), 1, "reconnected SYN must leave at START");
    let bytes = device.tx_queue.pop_front().unwrap();
    let ethernet = EthernetFrame::new_checked(&bytes).unwrap();
    assert_eq!(ethernet.ethertype(), EthernetProtocol::Ipv4);
    assert_eq!(ethernet.dst_addr(), peer_b_hardware);
    let ip = Ipv4Packet::new_checked(ethernet.payload()).unwrap();
    assert!(ip.verify_checksum());
    assert_eq!((ip.src_addr(), ip.dst_addr()), (LOCAL, peer_b));
    assert_eq!(ip.next_header(), IpProtocol::Tcp);
    let tcp = TcpRepr::parse(
        &TcpPacket::new_checked(ip.payload()).unwrap(),
        &LOCAL.into(),
        &peer_b.into(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();
    assert_eq!(tcp.control, TcpControl::Syn);
    assert_eq!((tcp.src_port, tcp.dst_port), (1234, 65000));
    assert!(tcp.payload.is_empty());
    assert!(sockets.waiting.is_empty());
    assert_eq!(sockets.get(handle).state(), tcp::State::SynSent);
    assert_eq!(
        iface.poll_at(START, &mut sockets),
        Some(Instant::from_millis(384))
    );
    assert!(device.tx_queue.is_empty());
}

#[test]
fn address_change_leaves_idle_sockets_established() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    idle_sockets(&mut iface, &mut sockets, &mut device);
    iface.update_ip_addrs(|addrs| addrs.clear());
    assert_eq!(
        iface.poll(START, &mut device, &mut sockets),
        PollResult::None
    );
    assert!(sockets.dispatches.is_empty());
    for (_, socket) in sockets.iter() {
        assert_eq!(socket.state(), tcp::State::Established);
    }
    assert!(device.tx_queue.is_empty());
    assert_eq!(iface.poll_at(START, &mut sockets), None);
}

#[test]
fn parked_socket_resets_on_queued_data_after_address_removal() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
    iface.poll(START, &mut device, &mut sockets);
    device.tx_queue.clear();
    iface.inner.neighbor_cache.fill(
        REMOTE.into(),
        HardwareAddress::Ethernet(REMOTE_HARDWARE),
        START,
    );
    let (handle, seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
    sockets.get_mut(handle).send_slice(b"abc").unwrap();
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(take_tcp(&mut device).3, b"abc");
    iface.inner.neighbor_cache.flush();
    let retry = START + Duration::from_secs(1);
    sockets.dispatches.clear();
    iface.poll_egress(retry, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![0]);
    assert_eq!(sockets.waiting, vec![0]);
    let bytes = device.tx_queue.pop_front().unwrap();
    let ethernet = EthernetFrame::new_checked(&bytes).unwrap();
    assert_eq!(ethernet.ethertype(), EthernetProtocol::Arp);
    assert!(device.tx_queue.is_empty());

    let ack_at = retry + Duration::from_millis(1);
    receive_at(
        &mut iface,
        &mut sockets,
        &mut device,
        ack_at,
        segment(1234, TcpControl::None, 101, seq + 3),
    );
    assert_eq!(sockets.get(handle).send_queue(), 0);
    assert_eq!(
        sockets.get(handle).poll_at(iface.context()),
        PollAt::Ingress
    );
    let silent_until = retry + Duration::from_secs(1);
    assert_eq!(
        iface.poll_at(ack_at, &mut sockets),
        Some(Instant::from_millis(2048))
    );
    iface.update_ip_addrs(|addrs| addrs.retain(|addr| addr.address() != LOCAL.into()));
    sockets.dispatches.clear();
    iface.poll(ack_at, &mut device, &mut sockets);
    assert!(sockets.dispatches.is_empty());
    assert_eq!(sockets.get(handle).state(), tcp::State::Established);
    assert!(device.tx_queue.is_empty());

    let after_silence = silent_until + Duration::from_millis(1);
    assert_eq!(iface.poll_at(after_silence, &mut sockets), None);
    iface.poll(after_silence, &mut device, &mut sockets);
    assert!(sockets.dispatches.is_empty());
    assert_eq!(sockets.get(handle).state(), tcp::State::Established);
    assert!(device.tx_queue.is_empty());
    sockets.get_mut(handle).send_slice(b"next").unwrap();
    iface.poll_egress(after_silence, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![0]);
    assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
    assert!(device.tx_queue.is_empty());
}

#[test]
fn now_is_due_at_negative_time() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let now = Instant::from_millis(-100);
    iface.poll(now, &mut device, &mut sockets);
    assert!(device.tx_queue.is_empty());
    connect(&mut iface, &mut sockets, 1234);
    assert_eq!(
        iface.poll_at(now, &mut sockets),
        Some(Instant::from_millis(0))
    );
    iface.poll(now, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![0]);
    let (port, control, _, payload) = take_tcp(&mut device);
    assert_eq!((port, control), (1234, TcpControl::Syn));
    assert!(payload.is_empty());
    assert!(device.tx_queue.is_empty());
}

fn check_close_timer_after_idle_wheel(now: Instant, fresh: bool, poll_at_first: bool) {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
    sockets.get_mut(handle).close();
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(take_tcp(&mut device).1, TcpControl::Fin);
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        segment(1234, TcpControl::Fin, 101, seq + 1),
    );
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(take_tcp(&mut device).1, TcpControl::None);
    assert_eq!(sockets.get(handle).state(), tcp::State::TimeWait);
    let (socket, _) = sockets.take(handle);
    let mut sockets = TcpSet::new(Vec::new());
    if !fresh {
        iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    }
    let handle = sockets.add(socket);
    receive_at(
        &mut iface,
        &mut sockets,
        &mut device,
        now,
        segment(1234, TcpControl::None, 102, seq + 1),
    );
    let deadline = now + Duration::from_secs(10);
    assert_eq!(sockets.get(handle).poll_at(iface.context()), PollAt::Time(deadline));
    if poll_at_first {
        let at = iface.poll_at(now, &mut sockets).unwrap();
        assert!(at > now && at <= deadline, "poll_at returned {at} at {now}");
        assert_eq!(sockets.ready_len(), 0);
    } else {
        iface.poll_egress(now, &mut device, &mut sockets);
    }
    assert!(device.tx_queue.is_empty());
    sockets.dispatches.clear();
    let before = deadline - Duration::from_micros(1);
    iface.poll_egress(before, &mut device, &mut sockets);
    assert_eq!(sockets.get(handle).state(), tcp::State::TimeWait);
    assert!(sockets.dispatches.is_empty());
    assert_eq!(iface.poll_at(before, &mut sockets), Some(deadline));
    assert_eq!(iface.poll_at(deadline, &mut sockets), Some(deadline));
    assert_eq!(sockets.ready_len(), 0);
    iface.poll_egress(deadline, &mut device, &mut sockets);
    assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
    assert_eq!(sockets.dispatches, [0]);
    assert!(device.tx_queue.is_empty());
    assert_eq!(iface.poll_at(deadline, &mut sockets), None);
    iface.poll_egress(deadline + Duration::from_millis(1), &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, [0]);
}

#[test]
fn close_timer_after_wheel_idle_from_zero_uses_caller_time() {
    for poll_at_first in [false, true] {
        check_close_timer_after_idle_wheel(Instant::from_millis(2_000_000), false, poll_at_first);
    }
}

#[test]
fn close_timer_added_to_fresh_set_at_large_time_uses_caller_time() {
    for poll_at_first in [false, true] {
        check_close_timer_after_idle_wheel(Instant::from_millis(1_000_000_000), true, poll_at_first);
    }
}

#[test]
fn poll_at_after_advance_stays_between_now_and_rounded_earliest_deadline() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let first = establish(&mut iface, &mut sockets, &mut device, 1234).0;
    let second = establish(&mut iface, &mut sockets, &mut device, 1235).0;
    let first_rto = Duration::from_micros(40_250);
    let second_rto = Duration::from_micros(60_750);
    send_for_rto(&mut iface, &mut sockets, &mut device, first, first_rto);
    send_for_rto(&mut iface, &mut sockets, &mut device, second, second_rto);
    assert_eq!(
        sockets.get(first).poll_at(iface.context()),
        PollAt::Time(START + first_rto)
    );
    assert_eq!(
        sockets.get(second).poll_at(iface.context()),
        PollAt::Time(START + second_rto)
    );
    assert_eq!(iface.poll_at(START, &mut sockets), Some(Instant::from_millis(128)));
    let rounded_earliest = START + Duration::from_millis(41);
    for now in [
        START + Duration::from_micros(40_001),
        START + Duration::from_micros(40_999),
    ] {
        let at = iface.poll_at(now, &mut sockets).unwrap();
        assert!(at >= now, "poll_at returned {at} before {now}");
        assert!(
            at <= rounded_earliest,
            "poll_at returned {at} after {rounded_earliest}"
        );
    }
    assert!(device.tx_queue.is_empty());
}

#[test]
fn timers_fire_among_idle_sockets() {
    for timer in ["RTO", "delayed ACK", "configured RTO", "TIME-WAIT"] {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        idle_sockets(&mut iface, &mut sockets, &mut device);
        let (handle, seq) = establish(&mut iface, &mut sockets, &mut device, 1334);
        let delay = match timer {
            "RTO" => {
                sockets.get_mut(handle).send_slice(b"abc").unwrap();
                iface.poll_egress(START, &mut device, &mut sockets);
                assert_eq!(take_tcp(&mut device).3, b"abc");
                Duration::from_millis(300)
            }
            "delayed ACK" => {
                sockets
                    .get_mut(handle)
                    .set_ack_delay(Some(Duration::from_millis(20)));
                receive(
                    &mut iface,
                    &mut sockets,
                    &mut device,
                    TcpRepr {
                        payload: b"a",
                        ..segment(1334, TcpControl::Psh, 101, seq)
                    },
                );
                Duration::from_millis(20)
            }
            "configured RTO" => {
                send_for_rto(&mut iface, &mut sockets, &mut device, handle, Duration::from_millis(300));
                Duration::from_millis(300)
            }
            "TIME-WAIT" => {
                sockets.get_mut(handle).close();
                iface.poll_egress(START, &mut device, &mut sockets);
                assert_eq!(take_tcp(&mut device).1, TcpControl::Fin);
                receive(
                    &mut iface,
                    &mut sockets,
                    &mut device,
                    segment(1334, TcpControl::Fin, 101, seq + 1),
                );
                iface.poll_egress(START, &mut device, &mut sockets);
                assert_eq!(take_tcp(&mut device).1, TcpControl::None);
                assert_eq!(sockets.get(handle).state(), tcp::State::TimeWait);
                Duration::from_secs(10)
            }
            _ => unreachable!(),
        };
        let deadline = START + delay;
        assert_eq!(
            iface.poll_at(START, &mut sockets),
            Some(Instant::from_millis(match timer {
                "RTO" => 384,
                "delayed ACK" => 120,
                "configured RTO" => 384,
                "TIME-WAIT" => 9216,
                _ => unreachable!(),
            })),
            "{timer}"
        );
        assert!(device.tx_queue.is_empty(), "{timer}");
        sockets.dispatches.clear();
        let before = deadline - Duration::from_micros(1);
        iface.poll(before, &mut device, &mut sockets);
        assert!(sockets.dispatches.is_empty(), "{timer}");
        assert!(device.tx_queue.is_empty(), "{timer}");
        assert_eq!(
            iface.poll_at(before, &mut sockets),
            Some(deadline),
            "{timer}"
        );
        iface.poll(deadline, &mut device, &mut sockets);
        assert_eq!(sockets.dispatches, vec![100], "{timer}");
        if timer == "TIME-WAIT" {
            assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
            assert!(device.tx_queue.is_empty());
            assert_eq!(iface.poll_at(deadline, &mut sockets), None);
        } else {
            let (port, control, sent_seq, payload) = take_tcp(&mut device);
            assert_eq!(
                (port, control),
                (
                    1334,
                    if matches!(timer, "RTO" | "configured RTO") {
                        TcpControl::Psh
                    } else {
                        TcpControl::None
                    }
                )
            );
            match timer {
                "RTO" => {
                    assert_eq!(sent_seq, seq);
                    assert_eq!(payload, b"abc");
                }
                "delayed ACK" => assert!(payload.is_empty()),
                "configured RTO" => {
                    assert_eq!(sent_seq, seq);
                    assert_eq!(payload, b"x");
                }
                _ => unreachable!(),
            }
            assert!(device.tx_queue.is_empty());
        }
    }
}

#[test]
fn remove_queued_socket_before_slot_reuse() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let a = establish(&mut iface, &mut sockets, &mut device, 1234).0;
    let b = establish(&mut iface, &mut sockets, &mut device, 1235).0;
    for handle in [a, b] {
        sockets.get_mut(handle).send_slice(&[1; 1024]).unwrap();
    }
    iface.poll_egress(START, &mut device, &mut sockets);
    device.tx_queue.clear();
    let (mut removed, _) = sockets.take(a);
    removed.abort();
    removed.listen(1234).unwrap();
    let reused = sockets.add(removed);
    assert_ne!(reused, a);
    sockets.dispatches.clear();
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![1]);
    assert_eq!(take_tcp(&mut device).0, 1235);
    assert!(device.tx_queue.is_empty());
}

#[test]
fn queued_socket_with_refreshed_idle_deadline_is_not_dispatched() {
    let (mut iface, mut sockets, device) = setup(Medium::Ip);
    let handle = connect(&mut iface, &mut sockets, 1234);
    let mut device = RefusingDevice {
        inner: device,
        remaining: 0,
    };
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![0]);
    let socket = sockets.get_mut(handle);
    socket.abort();
    socket.listen(1234).unwrap();
    sockets.dispatches.clear();
    device.remaining = 1;
    iface.poll_egress(START, &mut device, &mut sockets);
    assert!(sockets.dispatches.is_empty());
    assert!(device.inner.tx_queue.is_empty());
    assert_eq!(iface.poll_at(START, &mut sockets), None);
}

#[test]
fn address_change_only_admits_due_sockets_after_device_refusal() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let a = establish(&mut iface, &mut sockets, &mut device, 1234).0;
    let b = establish(&mut iface, &mut sockets, &mut device, 1235).0;
    establish(&mut iface, &mut sockets, &mut device, 1236);
    for handle in [a, b] {
        sockets.get_mut(handle).send_slice(&[1; 1024]).unwrap();
    }
    iface.update_ip_addrs(|_| {});
    let mut device = RefusingDevice {
        inner: device,
        remaining: 1,
    };
    sockets.dispatches.clear();
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![0, 1]);
    sockets.dispatches.clear();
    device.remaining = 3;
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![1, 0]);
    assert_eq!(sockets.get(a).state(), tcp::State::Established);
    assert_eq!(sockets.get(b).state(), tcp::State::Established);
    assert_eq!(device.inner.tx_queue.len(), 3);
}

#[test]
fn disabling_any_ip_leaves_idle_socket_until_queued_data() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, _) = establish(&mut iface, &mut sockets, &mut device, 1234);
    iface.set_any_ip(true);
    iface.update_ip_addrs(|addrs| addrs.clear());
    iface.poll(START, &mut device, &mut sockets);
    assert_eq!(sockets.get(handle).state(), tcp::State::Established);
    sockets.dispatches.clear();
    iface.set_any_ip(false);
    iface.poll(START, &mut device, &mut sockets);
    assert!(sockets.dispatches.is_empty());
    assert_eq!(sockets.get(handle).state(), tcp::State::Established);
    assert!(device.tx_queue.is_empty());
    sockets.get_mut(handle).send_slice(b"next").unwrap();
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![0]);
    assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
    assert!(device.tx_queue.is_empty());
}

#[test]
fn dirty_sockets_readmitted_in_slot_order() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (a, a_seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
    let (b, b_seq) = establish(&mut iface, &mut sockets, &mut device, 1235);
    let (c, c_seq) = establish(&mut iface, &mut sockets, &mut device, 1236);
    for handle in [b, c] {
        assert_eq!(sockets.get_mut(handle).send_slice(&[1; 1024]), Ok(1024));
    }
    sockets.dispatches.clear();
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![1, 2]);
    for (port, seq) in [(1235, b_seq), (1236, c_seq)] {
        let (sent_port, control, sent_seq, payload) = take_tcp(&mut device);
        assert_eq!(
            (sent_port, control, sent_seq),
            (port, TcpControl::None, seq)
        );
        assert_eq!(payload, [1; 512]);
    }
    assert!(device.tx_queue.is_empty());
    assert_eq!(sockets.get_mut(a).send_slice(&[1; 512]), Ok(512));
    sockets.dispatches.clear();
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![0, 1, 2]);
    for (port, seq) in [(1234, a_seq), (1235, b_seq + 512), (1236, c_seq + 512)] {
        let (sent_port, control, sent_seq, payload) = take_tcp(&mut device);
        assert_eq!((sent_port, control, sent_seq), (port, TcpControl::Psh, seq));
        assert_eq!(payload, [1; 512]);
    }
    assert!(device.tx_queue.is_empty());
}

#[test]
fn dirty_due_and_timer_sockets_admitted_together_in_slot_order() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (low, low_seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
    let timer = establish(&mut iface, &mut sockets, &mut device, 1235).0;
    let (high, high_seq) = establish(&mut iface, &mut sockets, &mut device, 1236);
    send_for_rto(&mut iface, &mut sockets, &mut device, timer, Duration::from_millis(20));
    assert_eq!(
        iface.poll_at(START, &mut sockets),
        Some(Instant::from_millis(120))
    );
    sockets.get_mut(high).send_slice(b"high").unwrap();
    sockets.get_mut(low).send_slice(b"low").unwrap();
    assert_eq!(sockets.dirty_list, vec![2, 0]);
    sockets.dispatches.clear();
    iface.poll_egress(Instant::from_millis(120), &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![0, 1, 2]);
    let (port, control, seq, payload) = take_tcp(&mut device);
    assert_eq!((port, control, seq), (1234, TcpControl::Psh, low_seq));
    assert_eq!(payload, b"low");
    let (port, control, _, payload) = take_tcp(&mut device);
    assert_eq!((port, control), (1235, TcpControl::Psh));
    assert_eq!(payload, b"x");
    let (port, control, seq, payload) = take_tcp(&mut device);
    assert_eq!((port, control, seq), (1236, TcpControl::Psh, high_seq));
    assert_eq!(payload, b"high");
    assert!(device.tx_queue.is_empty());
}

#[test]
fn dirty_socket_due_before_wheel_advances_admitted_once() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
    sockets
        .get_mut(handle)
        .set_ack_delay(Some(Duration::from_millis(20)));
    send_for_rto(&mut iface, &mut sockets, &mut device, handle, Duration::from_millis(25));
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        TcpRepr {
            payload: b"a",
            ..segment(1234, TcpControl::Psh, 101, seq)
        },
    );
    assert_eq!(sockets.dirty_list, vec![0]);
    assert_eq!(
        sockets.get(handle).poll_at(iface.context()),
        PollAt::Time(Instant::from_millis(120))
    );
    sockets.dispatches.clear();
    let now = Instant::from_millis(120);
    iface.poll_egress(now, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![0]);
    let (port, control, sent_seq, payload) = take_tcp(&mut device);
    assert_eq!((port, control, sent_seq), (1234, TcpControl::None, seq + 1));
    assert!(payload.is_empty());
    assert!(device.tx_queue.is_empty());
    assert_eq!(
        sockets.get(handle).poll_at(iface.context()),
        PollAt::Time(Instant::from_millis(125))
    );
    assert_eq!(
        iface.poll_at(now, &mut sockets),
        Some(Instant::from_millis(125))
    );
    iface.poll_egress(now, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![0]);
    assert!(device.tx_queue.is_empty());
}

#[test]
fn address_removal_resets_idle_socket_on_queued_data() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, _) = establish(&mut iface, &mut sockets, &mut device, 1234);
    iface.update_ip_addrs(|addrs| addrs.clear());
    sockets.dispatches.clear();
    iface.poll_egress(START, &mut device, &mut sockets);
    assert!(sockets.dispatches.is_empty());
    assert_eq!(sockets.get(handle).state(), tcp::State::Established);
    assert!(device.tx_queue.is_empty());
    sockets.get_mut(handle).send_slice(b"abc").unwrap();
    assert_eq!(sockets.dirty_list, vec![0]);
    assert_eq!(sockets.get(handle).poll_at(iface.context()), PollAt::Now);
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![0]);
    assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
    assert!(device.tx_queue.is_empty());
    assert_eq!(iface.poll_at(START, &mut sockets), None);
}

#[test]
fn dropped_dispatch_ends_lone_socket_visit() {
    // The dropped SYN rearms its RTO; the future deadline ends this visit.
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let handle = connect(&mut iface, &mut sockets, 1234);
    sockets.get_mut(handle).set_rto(Duration::from_millis(1));
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(take_tcp(&mut device).1, TcpControl::Syn);
    iface.inner.caps.max_transmission_unit = 40;
    sockets.dispatches.clear();
    for (elapsed, next) in [(1, 3), (3, 7)] {
        let now = START + Duration::from_millis(elapsed);
        assert_eq!(
            iface.poll_egress(now, &mut device, &mut sockets),
            PollResult::SocketStateChanged
        );
        assert_eq!(sockets.dispatches, vec![0]);
        assert!(device.tx_queue.is_empty());
        assert_eq!(sockets.get(handle).poll_at(iface.context()), PollAt::Time(START + Duration::from_millis(next)));
        assert_eq!(sockets.get(handle).state(), tcp::State::SynSent);
        sockets.dispatches.clear();
    }
}

#[test]
fn lone_socket_sends_its_window_in_one_visit() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
    assert_eq!(
        sockets.get_mut(handle).send_slice(&[1; 4 * 512]),
        Ok(4 * 512)
    );
    sockets.dispatches.clear();
    assert_eq!(
        iface.poll_egress(START, &mut device, &mut sockets),
        PollResult::SocketStateChanged
    );
    assert_eq!(device.tx_queue.len(), 4);
    for frame in 0..4 {
        let (port, control, sent_seq, payload) = take_tcp(&mut device);
        assert_eq!((port, sent_seq), (1234, seq + frame * 512));
        assert_eq!(
            control,
            if frame == 3 {
                TcpControl::Psh
            } else {
                TcpControl::None
            }
        );
        assert_eq!(payload, [1; 512]);
    }
    assert_eq!(sockets.dispatches, vec![0; 4]);
    assert_eq!(
        iface.poll_egress(START, &mut device, &mut sockets),
        PollResult::None
    );
    assert_eq!(sockets.dispatches, vec![0; 4]);
    assert!(device.tx_queue.is_empty());
    assert_eq!(
        iface.poll_at(START, &mut sockets),
        Some(Instant::from_millis(384))
    );
}

#[test]
fn lone_burst_stores_deadline() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, _) = establish(&mut iface, &mut sockets, &mut device, 1234);
    assert_eq!(
        sockets.get_mut(handle).send_slice(&[1; 4 * 512]),
        Ok(4 * 512)
    );
    sockets.dispatches.clear();
    assert_eq!(
        iface.poll_egress(START, &mut device, &mut sockets),
        PollResult::SocketStateChanged
    );
    assert_eq!(device.tx_queue.len(), 4);
    assert_eq!(sockets.dispatches, vec![0; 4]);
    assert!(sockets.dirty_list.is_empty());
    let deadline = sockets.get(handle).poll_at(&mut iface.inner);
    assert!(matches!(deadline, PollAt::Time(time) if time > START));
    assert_eq!(sockets.stored_deadline(0), deadline);
    device.tx_queue.clear();
    sockets.classify_calls = 0;
    assert_eq!(
        iface.poll_egress(START, &mut device, &mut sockets),
        PollResult::None
    );
    assert_eq!(sockets.classify_calls, 0);
    assert_eq!(sockets.dispatches, vec![0; 4]);
    assert!(device.tx_queue.is_empty());
}

#[test]
fn visit_end_after_pure_ack_stores_deadline() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
    let mut data = segment(1234, TcpControl::None, 101, seq);
    data.payload = b"a";
    receive(&mut iface, &mut sockets, &mut device, data);
    assert_eq!(sockets.get(handle).recv_queue(), 1);
    sockets.dispatches.clear();
    assert_eq!(
        iface.poll_egress(START, &mut device, &mut sockets),
        PollResult::SocketStateChanged
    );
    assert_eq!(device.tx_queue.len(), 1);
    let ip = Ipv4Packet::new_checked(device.tx_queue.front().unwrap()).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(tcp.ack());
    assert_eq!(tcp.ack_number(), TcpSeqNumber(102));
    let (port, control, sent_seq, payload) = take_tcp(&mut device);
    assert_eq!((port, control, sent_seq), (1234, TcpControl::None, seq));
    assert!(payload.is_empty());
    assert!(device.tx_queue.is_empty());
    assert_eq!(sockets.dispatches, vec![0]);
    let deadline = sockets.get(handle).poll_at(&mut iface.inner);
    assert_eq!(deadline, PollAt::Ingress);
    assert_eq!(sockets.stored_deadline(0), deadline);
    assert!(sockets.dirty_list.is_empty());
}

#[test]
fn visit_end_after_fin_stores_retransmit_deadline() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
    assert_eq!(sockets.get(handle).send_queue(), 0);
    sockets.get_mut(handle).close();
    sockets.dispatches.clear();
    assert_eq!(
        iface.poll_egress(START, &mut device, &mut sockets),
        PollResult::SocketStateChanged
    );
    assert_eq!(device.tx_queue.len(), 1);
    let (port, control, sent_seq, payload) = take_tcp(&mut device);
    assert_eq!((port, control, sent_seq), (1234, TcpControl::Fin, seq));
    assert!(payload.is_empty());
    assert!(device.tx_queue.is_empty());
    assert_eq!(sockets.dispatches, vec![0]);
    let deadline = sockets.get(handle).poll_at(&mut iface.inner);
    assert!(matches!(deadline, PollAt::Time(time) if time > START));
    assert_eq!(sockets.stored_deadline(0), deadline);
    assert!(sockets.dirty_list.is_empty());
}

#[test]
fn visit_end_with_peer_window_full_stores_deadline() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
    let mut window = segment(1234, TcpControl::None, 101, seq);
    window.window_len = 1024;
    receive(&mut iface, &mut sockets, &mut device, window);
    assert_eq!(
        sockets.get_mut(handle).send_slice(&[1; 4 * 512]),
        Ok(4 * 512)
    );
    sockets.dispatches.clear();
    assert_eq!(
        iface.poll_egress(START, &mut device, &mut sockets),
        PollResult::SocketStateChanged
    );
    assert_eq!(device.tx_queue.len(), 2);
    for frame in 0..2 {
        let (port, control, sent_seq, payload) = take_tcp(&mut device);
        assert_eq!((port, control), (1234, TcpControl::None));
        assert_eq!(sent_seq, seq + frame * 512);
        assert_eq!(payload, [1; 512]);
    }
    assert!(device.tx_queue.is_empty());
    assert_eq!(sockets.get(handle).send_queue(), 4 * 512);
    assert_eq!(sockets.dispatches, vec![0; 2]);
    let deadline = sockets.get(handle).poll_at(&mut iface.inner);
    assert!(matches!(deadline, PollAt::Time(time) if time > START));
    assert_eq!(sockets.stored_deadline(0), deadline);
    assert!(sockets.dirty_list.is_empty());
}

#[test]
fn segment_cap_end_reclassifies() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    iface.segments_per_visit = 2;
    let (a, a_seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
    let (b, b_seq) = establish(&mut iface, &mut sockets, &mut device, 1235);
    for (handle, port, seq, byte) in [(a, 1234, a_seq, 1), (b, 1235, b_seq, 2)] {
        let mut window = segment(port, TcpControl::None, 101, seq);
        window.window_len = 1024;
        receive(&mut iface, &mut sockets, &mut device, window);
        assert_eq!(
            sockets.get_mut(handle).send_slice(&[byte; 4 * 512]),
            Ok(4 * 512)
        );
    }
    sockets.dispatches.clear();
    assert_eq!(
        iface.poll_egress(START, &mut device, &mut sockets),
        PollResult::SocketStateChanged
    );
    assert_eq!(device.tx_queue.len(), 4);
    assert_eq!(sockets.dispatches, vec![0, 0, 1, 1]);
    for (index, handle, port, seq, byte) in [(0, a, 1234, a_seq, 1), (1, b, 1235, b_seq, 2)] {
        for frame in 0..2 {
            let (sent_port, control, sent_seq, payload) = take_tcp(&mut device);
            assert_eq!((sent_port, control), (port, TcpControl::None));
            assert_eq!(sent_seq, seq + frame * 512);
            assert_eq!(payload, [byte; 512]);
        }
        assert_eq!(sockets.get(handle).send_queue(), 4 * 512);
        let deadline = sockets.get(handle).poll_at(&mut iface.inner);
        assert!(matches!(deadline, PollAt::Time(time) if time > START));
        assert_eq!(sockets.stored_deadline(index), deadline);
    }
    assert!(device.tx_queue.is_empty());
    assert!(sockets.dirty_list.is_empty());
}

#[test]
fn address_removal_resets_socket_only_when_retransmit_timer_fires() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, _) = establish(&mut iface, &mut sockets, &mut device, 1234);
    sockets.get_mut(handle).send_slice(&[1; 512]).unwrap();
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(take_tcp(&mut device).3, [1; 512]);
    let PollAt::Time(deadline) = sockets.get(handle).poll_at(&mut iface.inner) else {
        panic!("sending must arm the retransmit timer");
    };
    let boundary = iface.poll_at(START, &mut sockets).unwrap();
    assert!(boundary <= deadline);
    assert_eq!(sockets.stored_deadline(0), PollAt::Time(deadline));
    sockets.dispatches.clear();
    iface.update_ip_addrs(|addrs| addrs.clear());
    assert_eq!(
        iface.poll_egress(START, &mut device, &mut sockets),
        PollResult::None
    );
    assert!(sockets.dispatches.is_empty());
    assert_eq!(sockets.get(handle).state(), tcp::State::Established);
    assert!(sockets.dirty_list.is_empty());
    assert_eq!(sockets.stored_deadline(0), PollAt::Time(deadline));
    assert_eq!(
        sockets.get(handle).poll_at(&mut iface.inner),
        PollAt::Time(deadline)
    );
    assert_eq!(iface.poll_at(START, &mut sockets), Some(boundary));
    let now = deadline + Duration::from_millis(1);
    assert_eq!(iface.poll_at(now, &mut sockets), Some(deadline));
    assert_eq!(
        sockets.get(handle).poll_at(&mut iface.inner),
        PollAt::Time(deadline)
    );
    sockets.dispatches.clear();
    assert_eq!(
        iface.poll_egress(now, &mut device, &mut sockets),
        PollResult::None
    );
    assert_eq!(sockets.dispatches, vec![0]);
    assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
    assert!(device.tx_queue.is_empty());
    let next_deadline = sockets.get(handle).poll_at(&mut iface.inner);
    assert_eq!(next_deadline, PollAt::Ingress);
    assert_eq!(sockets.stored_deadline(0), next_deadline);
    assert_eq!(iface.poll_at(now, &mut sockets), None);
}

#[test]
fn segments_per_visit_bounds_burst_while_others_wait() {
    for a_segments in [4, 1] {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        iface.segments_per_visit = 2;
        let (a, a_seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
        let (b, b_seq) = establish(&mut iface, &mut sockets, &mut device, 1235);
        assert_eq!(
            sockets.get_mut(a).send_slice(&vec![1; a_segments * 512]),
            Ok(a_segments * 512)
        );
        assert_eq!(sockets.get_mut(b).send_slice(&[2; 4 * 512]), Ok(4 * 512));
        sockets.dispatches.clear();
        let expected: &[&[usize]] = if a_segments == 4 {
            &[&[0, 0, 1, 1], &[0, 0, 1, 1]]
        } else {
            &[&[0, 1, 1, 1, 1], &[]]
        };
        let mut sent = [0, 0];
        let mut dispatches = Vec::new();
        for (pass_number, pass) in expected.iter().enumerate() {
            let classify_calls = sockets.classify_calls;
            assert_eq!(
                iface.poll_egress(START, &mut device, &mut sockets),
                if pass.is_empty() {
                    PollResult::None
                } else {
                    PollResult::SocketStateChanged
                }
            );
            if pass.is_empty() {
                assert_eq!(sockets.classify_calls, classify_calls);
            }
            dispatches.extend_from_slice(pass);
            assert_eq!(sockets.dispatches, dispatches);
            assert_eq!(
                sockets.dirty_list.contains(&0),
                a_segments == 4 && pass_number == 0
            );
            assert_eq!(device.tx_queue.len(), pass.len());
            for &index in *pass {
                let (port, control, seq, payload) = take_tcp(&mut device);
                let (expected_port, first_seq, segments) = if index == 0 {
                    (1234, a_seq, a_segments)
                } else {
                    (1235, b_seq, 4)
                };
                assert_eq!((port, seq), (expected_port, first_seq + sent[index] * 512));
                sent[index] += 1;
                assert_eq!(
                    control,
                    if sent[index] as usize == segments {
                        TcpControl::Psh
                    } else {
                        TcpControl::None
                    }
                );
                assert_eq!(payload, vec![index as u8 + 1; 512]);
            }
            assert!(device.tx_queue.is_empty());
        }
        assert_eq!(
            sockets.dispatches,
            if a_segments == 4 {
                vec![0, 0, 1, 1, 0, 0, 1, 1]
            } else {
                vec![0, 1, 1, 1, 1]
            }
        );
        assert_eq!(sent, [a_segments, 4]);
        let classify_calls = sockets.classify_calls;
        assert_eq!(
            iface.poll_egress(START, &mut device, &mut sockets),
            PollResult::None
        );
        assert_eq!(sockets.classify_calls, classify_calls);
        assert_eq!(sockets.dispatches, dispatches);
        assert!(device.tx_queue.is_empty());
    }
}

#[test]
fn burst_stops_at_device_refusal() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
    assert_eq!(
        sockets.get_mut(handle).send_slice(&[1; 4 * 512]),
        Ok(4 * 512)
    );
    sockets.dispatches.clear();
    let mut device = RefusingDevice {
        inner: device,
        remaining: 2,
    };
    assert_eq!(
        iface.poll_egress(START, &mut device, &mut sockets),
        PollResult::SocketStateChanged
    );
    assert_eq!(device.inner.tx_queue.len(), 2);
    assert_eq!(sockets.dispatches, vec![0; 3]);
    assert_eq!(sockets.ready_len(), 1);
    let mut device = device.inner;
    assert_eq!(
        iface.poll_egress(START, &mut device, &mut sockets),
        PollResult::SocketStateChanged
    );
    assert_eq!(sockets.dispatches, vec![0; 5]);
    assert_eq!(device.tx_queue.len(), 4);
    for frame in 0..4 {
        let (port, control, sent_seq, payload) = take_tcp(&mut device);
        assert_eq!((port, sent_seq), (1234, seq + frame * 512));
        assert_eq!(
            control,
            if frame == 3 {
                TcpControl::Psh
            } else {
                TcpControl::None
            }
        );
        assert_eq!(payload, [1; 512]);
    }
    assert_eq!(
        iface.poll_egress(START, &mut device, &mut sockets),
        PollResult::None
    );
    assert_eq!(sockets.dispatches, vec![0; 5]);
    assert!(device.tx_queue.is_empty());
}

#[test]
fn parked_socket_allows_lone_socket_to_burst() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
    iface.poll(START, &mut device, &mut sockets);
    device.tx_queue.clear();
    let parked = tcp::Socket::new(
        tcp::RxBuffer::new(4096),
        tcp::SocketBuffer::new(vec![0; 4096]),
    );
    let parked = sockets.add(parked);
    iface.inner.neighbor_cache.fill(
        REMOTE.into(),
        HardwareAddress::Ethernet(REMOTE_HARDWARE),
        START,
    );
    let (active, seq) = establish(&mut iface, &mut sockets, &mut device, 1235);
    sockets
        .get_mut(parked)
        .connect(
            iface.context(),
            (Ipv4Address::new(192, 168, 1, 3), 65000),
            (LOCAL, 1234),
        )
        .unwrap();
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.waiting, vec![0]);
    let bytes = device.tx_queue.pop_front().unwrap();
    assert_eq!(
        EthernetFrame::new_checked(&bytes).unwrap().ethertype(),
        EthernetProtocol::Arp
    );
    assert!(device.tx_queue.is_empty());
    assert_eq!(
        sockets.get_mut(active).send_slice(&[1; 4 * 512]),
        Ok(4 * 512)
    );
    iface.inner.neighbor_cache.fill(
        REMOTE.into(),
        HardwareAddress::Ethernet(REMOTE_HARDWARE),
        START,
    );
    sockets.dispatches.clear();
    assert_eq!(
        iface.poll_egress(START, &mut device, &mut sockets),
        PollResult::SocketStateChanged
    );
    assert_eq!(sockets.dispatches, vec![1; 4]);
    assert!(sockets.dirty_list.is_empty());
    assert_eq!(sockets.waiting, vec![0]);
    assert_eq!(device.tx_queue.len(), 4);
    for frame in 0..4 {
        let (port, control, sent_seq, payload) = take_tcp(&mut device);
        assert_eq!((port, sent_seq), (1235, seq + frame * 512));
        assert_eq!(
            control,
            if frame == 3 {
                TcpControl::Psh
            } else {
                TcpControl::None
            }
        );
        assert_eq!(payload, [1; 512]);
    }
    assert!(device.tx_queue.is_empty());
    assert_eq!(
        iface.poll_egress(START, &mut device, &mut sockets),
        PollResult::None
    );
    assert_eq!(sockets.dispatches, vec![1; 4]);
    assert!(device.tx_queue.is_empty());
}

#[test]
fn two_ready_sockets_keep_strict_interleave_by_default() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (a, a_seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
    let (b, b_seq) = establish(&mut iface, &mut sockets, &mut device, 1235);
    for handle in [a, b] {
        assert_eq!(
            sockets.get_mut(handle).send_slice(&[1; 3 * 512]),
            Ok(3 * 512)
        );
    }
    sockets.dispatches.clear();
    let mut frames = 0;
    while iface.poll_egress(START, &mut device, &mut sockets) != PollResult::None {
        for (port, seq) in [(1234, a_seq), (1235, b_seq)] {
            let (sent_port, control, sent_seq, payload) = take_tcp(&mut device);
            assert_eq!((sent_port, sent_seq), (port, seq + frames * 512));
            assert_eq!(
                control,
                if frames == 2 {
                    TcpControl::Psh
                } else {
                    TcpControl::None
                }
            );
            assert_eq!(payload, [1; 512]);
        }
        assert!(device.tx_queue.is_empty());
        frames += 1;
    }
    assert_eq!(frames, 3);
    assert!(device.tx_queue.is_empty());
    assert_eq!(sockets.dispatches, vec![0, 1, 0, 1, 0, 1]);
}

#[test]
fn pumping_socket_pass_cost() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
    sockets.slot_visits = 0;
    sockets.dispatches.clear();
    assert_eq!(
        sockets.get_mut(handle).send_slice(&[1; 4 * 512]),
        Ok(4 * 512)
    );
    let mut frames = 0;
    let mut passes = 0;
    loop {
        passes += 1;
        let classify_calls = sockets.classify_calls;
        let result = iface.poll_egress(START, &mut device, &mut sockets);
        if result == PollResult::None {
            assert_eq!(sockets.classify_calls, classify_calls);
            assert!(device.tx_queue.is_empty());
            break;
        }
        assert_eq!(result, PollResult::SocketStateChanged);
        assert_eq!(passes, 1);
        assert_eq!(device.tx_queue.len(), 4);
        while !device.tx_queue.is_empty() {
            assert!(frames < 4);
            let (port, control, sent_seq, payload) = take_tcp(&mut device);
            assert_eq!((port, sent_seq), (1234, seq + frames * 512));
            assert_eq!(
                control,
                if frames == 3 {
                    TcpControl::Psh
                } else {
                    TcpControl::None
                }
            );
            assert_eq!(payload, [1; 512]);
            frames += 1;
        }
        assert_eq!(frames, 4);
    }
    assert_eq!(frames, 4);
    assert_eq!(passes, 2);
    assert_eq!(sockets.dispatches, vec![0; 4]);
    std::println!(
        "frames={frames}, passes={passes}, slot visits={}",
        sockets.slot_visits
    );
    assert!(sockets.slot_visits <= 5, "{} visits", sockets.slot_visits);
}

#[test]
fn one_busy_socket_costs_no_slot_walk() {
    let mut visits = Vec::new();
    for slot_count in [64, 10240] {
        let (mut iface, _, mut device) = setup(Medium::Ip);
        let mut sockets = TcpSet::new(
            (0..slot_count)
                .map(|_| crate::iface::TcpStorage::EMPTY)
                .collect::<Vec<_>>(),
        );
        let (handle, mut seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
        assert_eq!(sockets.slot_count(), slot_count);
        sockets.slot_visits = 0;
        for turn in 0..50 {
            let now = START + Duration::from_millis(turn);
            assert_eq!(sockets.get_mut(handle).send_slice(b"request"), Ok(7));
            iface.poll_egress(now, &mut device, &mut sockets);
            let (port, _, sent_seq, payload) = take_tcp(&mut device);
            assert_eq!((port, sent_seq), (1234, seq));
            assert_eq!(payload, b"request");
            assert!(device.tx_queue.is_empty());
            let classify_calls = sockets.classify_calls;
            assert_eq!(
                iface.poll_egress(now, &mut device, &mut sockets),
                PollResult::None
            );
            assert_eq!(sockets.classify_calls, classify_calls);
            assert!(device.tx_queue.is_empty());
            iface.poll_at(now, &mut sockets);
            seq += 7;
            receive_at(
                &mut iface,
                &mut sockets,
                &mut device,
                now,
                TcpRepr {
                    payload: b"reply",
                    ..segment(1234, TcpControl::Psh, 101 + turn as i32 * 5, seq)
                },
            );
            assert_eq!(sockets.get(handle).send_queue(), 0);
            let mut reply = Vec::new();
            while let Some(frame) = sockets.get_mut(handle).recv().unwrap() {
                reply.extend_from_slice(frame.payload());
            }
            assert_eq!(reply.len(), 5);
            assert_eq!(&reply, b"reply");
            iface.poll_egress(now, &mut device, &mut sockets);
            let (port, control, _, payload) = take_tcp(&mut device);
            assert_eq!((port, control), (1234, TcpControl::None));
            assert!(payload.is_empty());
            assert!(device.tx_queue.is_empty());
            let classify_calls = sockets.classify_calls;
            assert_eq!(
                iface.poll_egress(now, &mut device, &mut sockets),
                PollResult::None
            );
            assert_eq!(sockets.classify_calls, classify_calls);
            assert!(device.tx_queue.is_empty());
            assert_eq!(iface.poll_at(now, &mut sockets), None);
        }
        std::println!(
            "slots={slot_count}, turns=50, slot visits={}",
            sockets.slot_visits
        );
        visits.push((slot_count, sockets.slot_visits));
    }
    for (slot_count, count) in visits {
        assert!(count <= 50 * 10, "{count} visits for {slot_count} slots");
    }
}

#[test]
fn expired_timers_admitted_in_slot_order() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let a = establish(&mut iface, &mut sockets, &mut device, 1234).0;
    let b = establish(&mut iface, &mut sockets, &mut device, 1235).0;
    send_for_rto(&mut iface, &mut sockets, &mut device, a, Duration::from_millis(20));
    send_for_rto(&mut iface, &mut sockets, &mut device, b, Duration::from_millis(10));
    assert_eq!(
        iface.poll_at(START, &mut sockets),
        Some(Instant::from_millis(110))
    );
    sockets.dispatches.clear();
    iface.poll_egress(Instant::from_millis(120), &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![0, 1]);
    for port in [1234, 1235] {
        let (sent_port, control, _, payload) = take_tcp(&mut device);
        assert_eq!((sent_port, control), (port, TcpControl::Psh));
        assert_eq!(payload, b"x");
    }
    assert!(device.tx_queue.is_empty());
}

#[test]
fn unqueued_future_deadline_stays_on_wheel_after_device_refusal() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let a = establish(&mut iface, &mut sockets, &mut device, 1234).0;
    let b = establish(&mut iface, &mut sockets, &mut device, 1235).0;
    send_for_rto(&mut iface, &mut sockets, &mut device, b, Duration::from_micros(300_500));
    sockets.get_mut(a).send_slice(b"abc").unwrap();
    let mut device = RefusingDevice {
        inner: device,
        remaining: 0,
    };
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.ready_len(), 1);
    sockets.get_mut(a).abort();
    sockets.get_mut(a).listen(1234).unwrap();
    assert_eq!(
        iface.poll_at(START, &mut sockets),
        Some(Instant::from_millis(384))
    );
    assert_eq!(sockets.ready_len(), 1);
    device.remaining = 2;
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.ready_len(), 0);
    assert_eq!(
        iface.poll_at(START, &mut sockets),
        Some(Instant::from_millis(384))
    );
    assert!(device.inner.tx_queue.is_empty());
}

#[test]
fn queued_future_deadline_stays_exact_after_device_refusal() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let a = establish(&mut iface, &mut sockets, &mut device, 1234).0;
    let (b, seq) = establish(&mut iface, &mut sockets, &mut device, 1235);
    send_for_rto(&mut iface, &mut sockets, &mut device, b, Duration::from_micros(300_500));
    sockets.get_mut(a).send_slice(b"a").unwrap();
    sockets.get_mut(b).send_slice(b"y").unwrap();
    let mut device = RefusingDevice {
        inner: device,
        remaining: 0,
    };
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.ready_len(), 2);
    sockets.get_mut(a).abort();
    sockets.get_mut(a).listen(1234).unwrap();
    receive(&mut iface, &mut sockets, &mut device.inner, TcpRepr {
        window_len: 0,
        ..segment(1235, TcpControl::None, 101, seq)
    });
    assert_eq!(sockets.get(a).state(), tcp::State::Listen);
    assert_eq!(sockets.get(b).state(), tcp::State::Established);
    assert_eq!(sockets.get(b).send_queue(), 2);
    assert_eq!(
        iface.poll_at(START, &mut sockets),
        Some(Instant::from_micros(400_500))
    );
    assert_eq!(sockets.ready_len(), 2);
    device.remaining = 2;
    sockets.dispatches.clear();
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(sockets.ready_len(), 0);
    assert!(sockets.dispatches.is_empty());
    assert!(device.inner.tx_queue.is_empty());
    assert_eq!(
        iface.poll_at(START, &mut sockets),
        Some(Instant::from_millis(384))
    );
}

#[test]
fn simultaneous_rto_expiry_admitted_without_due_list_visits() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let connections: Vec<_> = (1234..1298)
        .map(|port| establish(&mut iface, &mut sockets, &mut device, port))
        .collect();
    for &(handle, _) in &connections {
        send_for_rto(
            &mut iface,
            &mut sockets,
            &mut device,
            handle,
            Duration::from_millis(20),
        );
    }
    sockets.slot_visits = 0;
    sockets.dispatches.clear();
    iface.poll_egress(Instant::from_millis(120), &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, (0..64).collect::<Vec<_>>());
    for (index, &(_, seq)) in connections.iter().enumerate() {
        let (port, control, sent_seq, payload) = take_tcp(&mut device);
        assert_eq!(
            (port, control, sent_seq),
            (1234 + u16::try_from(index).unwrap(), TcpControl::Psh, seq)
        );
        assert_eq!(payload, b"x");
    }
    assert!(device.tx_queue.is_empty());
    // 64 wheel expiry visits, 64 expired-entry checks, 64 ready admissions; no due-list visits.
    assert_eq!(sockets.slot_visits, 192);
}

#[test]
fn simultaneous_rto_expiry_polled_before_egress_keeps_slot_order() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let connections: Vec<_> = (1234..1298)
        .map(|port| establish(&mut iface, &mut sockets, &mut device, port))
        .collect();
    for &(handle, _) in &connections {
        send_for_rto(
            &mut iface,
            &mut sockets,
            &mut device,
            handle,
            Duration::from_millis(20),
        );
    }
    let now = Instant::from_millis(120);
    sockets.slot_visits = 0;
    assert_eq!(iface.poll_at(now, &mut sockets), Some(now));
    // 64 wheel expiry visits, 64 expired-entry checks, 64 due-list deadline reads.
    assert_eq!(sockets.slot_visits, 192);
    sockets.slot_visits = 0;
    sockets.dispatches.clear();
    iface.poll_egress(now, &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, (0..64).collect::<Vec<_>>());
    for (index, &(_, seq)) in connections.iter().enumerate() {
        let (port, control, sent_seq, payload) = take_tcp(&mut device);
        assert_eq!(
            (port, control, sent_seq),
            (1234 + u16::try_from(index).unwrap(), TcpControl::Psh, seq)
        );
        assert_eq!(payload, b"x");
    }
    assert!(device.tx_queue.is_empty());
    // 64 due-list deadline checks and 64 ready admissions after poll_at expired the wheel.
    assert_eq!(sockets.slot_visits, 128);
}

#[test]
fn rto_deadlines_preserve_timer_queue_order() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let handles: Vec<_> = (1234..1237)
        .map(|port| establish(&mut iface, &mut sockets, &mut device, port))
        .collect();
    for index in [2, 0, 1] {
        send_for_rto(&mut iface, &mut sockets, &mut device, handles[index].0,
            Duration::from_millis([30, 10, 20][index]));
    }
    assert_eq!(iface.poll_at(START, &mut sockets), Some(Instant::from_millis(110)));
    sockets.dispatches.clear();
    iface.poll_egress(Instant::from_millis(130), &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![0, 1, 2]);
    for (index, &(_, seq)) in handles.iter().enumerate() {
        let (port, control, sent_seq, payload) = take_tcp(&mut device);
        assert_eq!((port, control, sent_seq), (1234 + index as u16, TcpControl::Psh, seq));
        assert_eq!(payload, b"x");
        assert_eq!(sockets.get(handles[index].0).state(), tcp::State::Established);
    }
    assert!(device.tx_queue.is_empty());
}

#[test]
fn rto_deadline_cancellation_removes_idle_socket() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, seq) = establish(&mut iface, &mut sockets, &mut device, 1234);
    send_for_rto(&mut iface, &mut sockets, &mut device, handle, Duration::from_millis(20));
    assert_eq!(iface.poll_at(START, &mut sockets), Some(Instant::from_millis(120)));
    receive_at(&mut iface, &mut sockets, &mut device, Instant::from_millis(110),
        segment(1234, TcpControl::None, 101, seq + 1));
    assert_eq!(sockets.get(handle).send_queue(), 0);
    assert_eq!(iface.poll_at(Instant::from_millis(110), &mut sockets), None);
    sockets.dispatches.clear();
    iface.poll_egress(Instant::from_millis(200), &mut device, &mut sockets);
    assert!(sockets.dispatches.is_empty());
    assert!(device.tx_queue.is_empty());
    assert_eq!(iface.poll_at(Instant::from_millis(200), &mut sockets), None);
    assert_eq!(sockets.get(handle).state(), tcp::State::Established);
}
