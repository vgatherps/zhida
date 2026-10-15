use super::*;

#[rstest]
#[case::request(ArpOperation::Request, Ipv4Address::new(192, 168, 1, 3))]
#[case::reply(ArpOperation::Reply, Ipv4Address::new(192, 168, 1, 2))]
fn non_gratuitous_arp_ignores_cached_neighbor(
    #[case] operation: ArpOperation,
    #[case] target_protocol_addr: Ipv4Address,
) {
    let (mut iface, _, _) = setup(Medium::Ethernet);
    let peer = Ipv4Address::new(192, 168, 1, 2);
    let old_mac = EthernetAddress([4; 6]);
    let new_mac = EthernetAddress([6; 6]);
    iface
        .inner
        .neighbor_cache
        .fill(peer.into(), old_mac.into(), Instant::ZERO);
    let changes = iface.inner.neighbor_cache.changes();
    let arp = ArpRepr::EthernetIpv4 {
        operation,
        source_hardware_addr: new_mac,
        source_protocol_addr: peer,
        target_hardware_addr: EthernetAddress::BROADCAST,
        target_protocol_addr,
    };
    let mut bytes = vec![0; EthernetFrame::<&[u8]>::buffer_len(arp.buffer_len())];
    let mut frame = EthernetFrame::new_unchecked(&mut bytes);
    frame.set_src_addr(new_mac);
    frame.set_dst_addr(EthernetAddress::BROADCAST);
    frame.set_ethertype(EthernetProtocol::Arp);
    arp.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()));
    let frame = EthernetFrame::new_checked(bytes.as_slice()).unwrap();
    assert_eq!(iface.inner.process_arp(Instant::ZERO, &frame), None);
    assert_eq!(
        (
            iface.inner.neighbor_cache.lookup(&peer.into(), Instant::ZERO),
            iface.inner.neighbor_cache.changes(),
        ),
        (NeighborAnswer::Found(old_mac.into()), changes)
    );
}

#[rstest]
#[case(ArpOperation::Request)]
#[case(ArpOperation::Reply)]
fn garp_updates_cached_neighbor(#[case] operation: ArpOperation) {
    let (mut iface, _, _) = setup(Medium::Ethernet);
    let peer = Ipv4Address::new(192, 168, 1, 2);
    let old_mac = EthernetAddress([4; 6]);
    let new_mac = EthernetAddress([6; 6]);
    iface
        .inner
        .neighbor_cache
        .fill(peer.into(), old_mac.into(), Instant::ZERO);
    let arp = ArpRepr::EthernetIpv4 {
        operation,
        source_hardware_addr: new_mac,
        source_protocol_addr: peer,
        target_hardware_addr: new_mac,
        target_protocol_addr: peer,
    };
    let mut bytes = vec![0; EthernetFrame::<&[u8]>::buffer_len(arp.buffer_len())];
    let mut frame = EthernetFrame::new_unchecked(&mut bytes);
    frame.set_src_addr(new_mac);
    frame.set_dst_addr(EthernetAddress::BROADCAST);
    frame.set_ethertype(EthernetProtocol::Arp);
    arp.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()));
    let frame = EthernetFrame::new_checked(bytes.as_slice()).unwrap();
    assert_eq!(iface.inner.process_arp(Instant::ZERO, &frame), None);
    assert_eq!(
        iface.inner.neighbor_cache.lookup(&peer.into(), Instant::ZERO),
        NeighborAnswer::Found(new_mac.into())
    );
}

#[rstest]
#[case(ArpOperation::Request, Ipv4Address::new(192, 168, 1, 2), false)]
#[case(ArpOperation::Reply, Ipv4Address::new(192, 168, 1, 2), false)]
#[case(ArpOperation::Request, Ipv4Address::new(10, 0, 0, 2), true)]
#[case(ArpOperation::Reply, Ipv4Address::new(10, 0, 0, 2), true)]
fn garp_ignores_uncached_or_off_network_neighbor(
    #[case] operation: ArpOperation,
    #[case] peer: Ipv4Address,
    #[case] cached: bool,
) {
    let (mut iface, _, _) = setup(Medium::Ethernet);
    let old_mac = EthernetAddress([4; 6]);
    let new_mac = EthernetAddress([6; 6]);
    if cached {
        iface
            .inner
            .neighbor_cache
            .fill(peer.into(), old_mac.into(), Instant::ZERO);
    }
    let arp = ArpRepr::EthernetIpv4 {
        operation,
        source_hardware_addr: new_mac,
        source_protocol_addr: peer,
        target_hardware_addr: new_mac,
        target_protocol_addr: peer,
    };
    let mut bytes = vec![0; EthernetFrame::<&[u8]>::buffer_len(arp.buffer_len())];
    let mut frame = EthernetFrame::new_unchecked(&mut bytes);
    frame.set_src_addr(new_mac);
    frame.set_dst_addr(EthernetAddress::BROADCAST);
    frame.set_ethertype(EthernetProtocol::Arp);
    arp.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()));
    let frame = EthernetFrame::new_checked(bytes.as_slice()).unwrap();
    assert_eq!(iface.inner.process_arp(Instant::ZERO, &frame), None);
    assert_eq!(
        iface.inner.neighbor_cache.lookup(&peer.into(), Instant::ZERO),
        if cached {
            NeighborAnswer::Found(old_mac.into())
        } else {
            NeighborAnswer::NotFound
        }
    );
}

fn connect_unresolved_peer(
    iface: &mut Interface,
    sockets: &mut TcpSet<'static>,
    peer: Ipv4Address,
    port: u16,
) {
    use crate::socket::tcp;

    let mut socket = tcp::Socket::new(tcp::RxBuffer::new(64), tcp::SocketBuffer::new(vec![0; 64]));
    socket
        .connect(
            iface.context(),
            (peer, 65000),
            (Ipv4Address::new(192, 168, 1, 1), port),
        )
        .unwrap();
    sockets.add(socket);
}

fn assert_arp_request(bytes: &[u8], peer: Ipv4Address) {
    let frame = EthernetFrame::new_checked(bytes).unwrap();
    let local_hw = EthernetAddress([2; 6]);
    assert_eq!(frame.src_addr(), local_hw);
    assert_eq!(frame.dst_addr(), EthernetAddress::BROADCAST);
    assert_eq!(frame.ethertype(), EthernetProtocol::Arp);
    assert_eq!(
        ArpRepr::parse(&ArpPacket::new_checked(frame.payload()).unwrap()).unwrap(),
        ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: local_hw,
            source_protocol_addr: Ipv4Address::new(192, 168, 1, 1),
            target_hardware_addr: EthernetAddress::BROADCAST,
            target_protocol_addr: peer,
        }
    );
}

#[test]
fn parallel_peers_each_get_arp() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
    let peers = [
        Ipv4Address::new(192, 168, 1, 2),
        Ipv4Address::new(192, 168, 1, 3),
        Ipv4Address::new(192, 168, 1, 4),
    ];
    for (index, peer) in peers.iter().enumerate() {
        connect_unresolved_peer(&mut iface, &mut sockets, *peer, 1234 + index as u16);
    }

    iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(device.tx_queue.len(), 3);
    let mut targets = Vec::new();
    for bytes in &device.tx_queue {
        let frame = EthernetFrame::new_checked(bytes.as_slice()).unwrap();
        let packet = ArpPacket::new_checked(frame.payload()).unwrap();
        let target = Ipv4Address::from_octets(packet.target_protocol_addr().try_into().unwrap());
        assert_arp_request(bytes, target);
        targets.push(target);
    }
    targets.sort();
    assert_eq!(targets.as_slice(), &peers);
}

#[test]
fn same_peer_rate_limited() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
    let peer = Ipv4Address::new(192, 168, 1, 2);
    connect_unresolved_peer(&mut iface, &mut sockets, peer, 1234);
    iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(device.tx_queue.len(), 1);
    assert_arp_request(&device.tx_queue.pop_front().unwrap(), peer);

    connect_unresolved_peer(&mut iface, &mut sockets, peer, 1235);
    sockets.dispatches.clear();
    iface.poll_egress(Instant::from_millis(100), &mut device, &mut sockets);
    assert_eq!(sockets.dispatches, vec![1]);
    assert!(device.tx_queue.is_empty());
    iface.poll_egress(Instant::from_millis(999), &mut device, &mut sockets);
    assert!(device.tx_queue.is_empty());
    iface.poll_egress(Instant::from_millis(1_000), &mut device, &mut sockets);
    assert_eq!(device.tx_queue.len(), 1);
    assert_arp_request(&device.tx_queue.pop_front().unwrap(), peer);
}

#[test]
fn garp_request_resolves_pending_neighbor() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
    let peer = Ipv4Address::new(192, 168, 1, 2);
    let peer_mac = EthernetAddress([4; 6]);
    connect_unresolved_peer(&mut iface, &mut sockets, peer, 1234);
    iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(device.tx_queue.len(), 1);
    assert_arp_request(&device.tx_queue.pop_front().unwrap(), peer);
    let timestamp = Instant::from_millis(100);
    assert_eq!(
        iface.inner.neighbor_cache.lookup(&peer.into(), timestamp),
        NeighborAnswer::RateLimited
    );
    let changes = iface.inner.neighbor_cache.changes();
    let arp = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: peer_mac,
        source_protocol_addr: peer,
        target_hardware_addr: EthernetAddress::BROADCAST,
        target_protocol_addr: peer,
    };
    let mut bytes = vec![0; EthernetFrame::<&[u8]>::buffer_len(arp.buffer_len())];
    let mut frame = EthernetFrame::new_unchecked(&mut bytes);
    frame.set_src_addr(peer_mac);
    frame.set_dst_addr(EthernetAddress::BROADCAST);
    frame.set_ethertype(EthernetProtocol::Arp);
    arp.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()));
    device.rx_queue.push_back(bytes);
    assert_eq!(
        iface.poll_ingress_single(timestamp, &mut device, &mut sockets),
        PollIngressSingleResult::SocketStateChanged
    );
    assert!(device.rx_queue.is_empty());
    assert!(device.tx_queue.is_empty());
    assert_eq!(
        iface.inner.neighbor_cache.lookup(&peer.into(), timestamp),
        NeighborAnswer::Found(peer_mac.into())
    );
    assert_eq!(iface.inner.neighbor_cache.changes(), changes + 1);
    iface.poll_egress(timestamp, &mut device, &mut sockets);
    assert_eq!(device.tx_queue.len(), 1);
    let bytes = device.tx_queue.pop_front().unwrap();
    let frame = EthernetFrame::new_checked(bytes.as_slice()).unwrap();
    assert_eq!(frame.dst_addr(), peer_mac);
    assert_eq!(frame.ethertype(), EthernetProtocol::Ipv4);
    let ip = Ipv4Packet::new_checked(frame.payload()).unwrap();
    assert_eq!(ip.dst_addr(), peer);
    assert_eq!(ip.next_header(), IpProtocol::Tcp);
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(tcp.syn());
}

mod stale_neighbors {
    use super::*;
    use crate::iface::SocketHandle;
    use crate::socket::tcp;
    use crate::tests::TestingDevice;

    const LOCAL: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const PEER: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const LOCAL_MAC: EthernetAddress = EthernetAddress([2; 6]);
    const PEER_MAC: EthernetAddress = EthernetAddress([4; 6]);

    struct LimitedDevice {
        inner: TestingDevice,
        tx_left: Option<usize>,
    }

    impl Device for LimitedDevice {
        type RxToken<'a> = <TestingDevice as Device>::RxToken<'a>;
        type TxToken<'a> = <TestingDevice as Device>::TxToken<'a>;

        fn capabilities(&self) -> DeviceCapabilities {
            self.inner.capabilities()
        }

        fn receive(&mut self, now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            self.inner.receive(now)
        }

        fn transmit(&mut self, now: Instant) -> Option<Self::TxToken<'_>> {
            if let Some(left) = &mut self.tx_left {
                if *left == 0 {
                    return None;
                }
                *left = left.checked_sub(1).expect("TX token count underflow");
            }
            self.inner.transmit(now)
        }
    }

    struct Connection {
        iface: Interface,
        sockets: TcpSet<'static>,
        device: LimitedDevice,
        handle: SocketHandle,
        seq: TcpSeqNumber,
    }

    impl Connection {
        fn new() -> Self {
            let (iface, sockets, device) = setup(Medium::Ethernet);
            Self::establish(iface, sockets, device)
        }

        fn with_capacity(capacity: usize) -> Self {
            let mut device = TestingDevice::new(Medium::Ethernet);
            let mut config = Config::new(LOCAL_MAC.into());
            config.neighbor_capacity = capacity;
            let mut iface = Interface::new(config, &mut device, Instant::ZERO);
            iface.update_ip_addrs(|addrs| addrs.push(IpCidr::new(LOCAL.into(), 24)).unwrap());
            Self::establish(iface, TcpSet::new(vec![]), device)
        }

        fn establish(
            iface: Interface,
            mut sockets: TcpSet<'static>,
            device: TestingDevice,
        ) -> Self {
            let mut socket =
                tcp::Socket::new(tcp::RxBuffer::new(64), tcp::SocketBuffer::new(vec![0; 64]));
            // The timelines retransmit at 1 s after the first unacknowledged send.
            socket.set_rto(crate::time::Duration::from_millis(1_000));
            let handle = sockets.add(socket);
            let mut conn = Self {
                iface,
                sockets,
                device: LimitedDevice {
                    inner: device,
                    tx_left: None,
                },
                handle,
                seq: TcpSeqNumber(0),
            };
            conn.arp_reply(0);
            conn.sockets
                .get_mut(handle)
                .connect(conn.iface.context(), (PEER, 65000), (LOCAL, 1234))
                .unwrap();
            conn.egress(0);
            let bytes = conn.device.inner.tx_queue.pop_front().unwrap();
            let eth = EthernetFrame::new_checked(&bytes).unwrap();
            let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
            let syn = TcpPacket::new_checked(ip.payload()).unwrap();
            assert!(syn.syn());
            conn.seq = syn.seq_number() + 1;
            assert!(conn.device.inner.tx_queue.is_empty());
            let tcp = TcpRepr {
                src_port: 65000,
                dst_port: 1234,
                control: TcpControl::Syn,
                seq_number: TcpSeqNumber(100),
                ack_number: Some(conn.seq),
                window_len: 4096,
                window_scale: None,
                max_seg_size: Some(512),
                sack_permitted: false,
                sack_ranges: [None; 3],
                timestamp: None,
                payload: &[],
            };
            let ip = Ipv4Repr {
                src_addr: PEER,
                dst_addr: LOCAL,
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            };
            let caps = ChecksumCapabilities::default();
            let mut bytes =
                vec![0; EthernetFrame::<&[u8]>::buffer_len(ip.buffer_len() + tcp.buffer_len())];
            let mut eth = EthernetFrame::new_unchecked(&mut bytes);
            eth.set_src_addr(PEER_MAC);
            eth.set_dst_addr(LOCAL_MAC);
            eth.set_ethertype(EthernetProtocol::Ipv4);
            ip.emit(&mut Ipv4Packet::new_unchecked(eth.payload_mut()), &caps);
            tcp.emit(
                &mut TcpPacket::new_unchecked(&mut eth.payload_mut()[ip.buffer_len()..]),
                &PEER.into(),
                &LOCAL.into(),
                &caps,
            );
            conn.ingress(0, bytes);
            assert_eq!(conn.sockets.get(handle).state(), tcp::State::Established);
            conn.egress(0);
            conn.take_data(&[], 0);
            assert!(conn.device.inner.tx_queue.is_empty());
            assert!(conn.sockets.item_at_mut(0).unwrap().meta.next_hop.is_some());
            conn
        }

        fn ingress(&mut self, millis: i64, bytes: Vec<u8>) {
            self.device.inner.rx_queue.push_back(bytes);
            assert_eq!(
                self.iface.poll_ingress_single(
                    Instant::from_millis(millis),
                    &mut self.device,
                    &mut self.sockets,
                ),
                PollIngressSingleResult::SocketStateChanged
            );
            assert!(self.device.inner.rx_queue.is_empty());
            assert!(self.device.inner.tx_queue.is_empty());
        }

        fn arp_reply(&mut self, millis: i64) {
            let arp = ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr: PEER_MAC,
                source_protocol_addr: PEER,
                target_hardware_addr: LOCAL_MAC,
                target_protocol_addr: LOCAL,
            };
            let mut bytes = vec![0; EthernetFrame::<&[u8]>::buffer_len(arp.buffer_len())];
            let mut eth = EthernetFrame::new_unchecked(&mut bytes);
            eth.set_src_addr(PEER_MAC);
            eth.set_dst_addr(LOCAL_MAC);
            eth.set_ethertype(EthernetProtocol::Arp);
            arp.emit(&mut ArpPacket::new_unchecked(eth.payload_mut()));
            self.ingress(millis, bytes);
        }

        fn egress(&mut self, millis: i64) {
            self.iface.poll_egress(
                Instant::from_millis(millis),
                &mut self.device,
                &mut self.sockets,
            );
        }

        fn send(&mut self, millis: i64, data: &[u8]) {
            assert_eq!(
                self.sockets.get_mut(self.handle).send_slice(data),
                Ok(data.len())
            );
            self.egress(millis);
        }

        fn take_data(&mut self, payload: &[u8], offset: usize) {
            let bytes = self
                .device
                .inner
                .tx_queue
                .pop_front()
                .expect("missing TCP frame");
            let eth = EthernetFrame::new_checked(&bytes).unwrap();
            assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);
            assert_eq!((eth.src_addr(), eth.dst_addr()), (LOCAL_MAC, PEER_MAC));
            let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
            assert_eq!((ip.src_addr(), ip.dst_addr()), (LOCAL, PEER));
            assert!(ip.verify_checksum());
            let tcp = TcpRepr::parse(
                &TcpPacket::new_checked(ip.payload()).unwrap(),
                &LOCAL.into(),
                &PEER.into(),
                &ChecksumCapabilities::default(),
            )
            .unwrap();
            assert_eq!((tcp.src_port, tcp.dst_port), (1234, 65000));
            assert_eq!(tcp.seq_number, self.seq + offset);
            assert_eq!(tcp.ack_number, Some(TcpSeqNumber(101)));
            assert_eq!(
                tcp.control,
                if payload.is_empty() {
                    TcpControl::None
                } else {
                    TcpControl::Psh
                }
            );
            assert_eq!(tcp.payload, payload);
        }

        fn take_probe(&mut self) {
            assert_arp_request(
                &self
                    .device
                    .inner
                    .tx_queue
                    .pop_front()
                    .expect("missing ARP request"),
                PEER,
            );
            assert!(self.device.inner.tx_queue.is_empty());
        }

        fn assert_stale_send(&mut self) {
            let meta = &self.sockets.item_at_mut(0).unwrap().meta;
            assert!(meta.next_hop.is_none());
            assert!(!meta.is_waiting());
        }
    }

    #[test]
    fn garp_changes_tcp_template_destination() {
        let mut conn = Connection::new();
        conn.send(1, b"a");
        conn.take_data(b"a", 0);
        assert!(
            conn.sockets
                .item_at_mut(0)
                .unwrap()
                .meta
                .tcp_template
                .is_some()
        );
        assert_eq!(
            conn.sockets.item_at_mut(0).unwrap().meta.next_hop,
            Some((conn.iface.inner.neighbor_cache.changes(), PEER_MAC))
        );
        let new_mac = EthernetAddress([6; 6]);
        let arp = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: new_mac,
            source_protocol_addr: PEER,
            target_hardware_addr: new_mac,
            target_protocol_addr: PEER,
        };
        let mut bytes = vec![0; EthernetFrame::<&[u8]>::buffer_len(arp.buffer_len())];
        let mut frame = EthernetFrame::new_unchecked(&mut bytes);
        frame.set_src_addr(new_mac);
        frame.set_dst_addr(EthernetAddress::BROADCAST);
        frame.set_ethertype(EthernetProtocol::Arp);
        arp.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()));
        conn.ingress(2, bytes);
        conn.send(3, b"b");
        let bytes = conn
            .device
            .inner
            .tx_queue
            .pop_front()
            .expect("missing TCP frame");
        let frame = EthernetFrame::new_checked(bytes.as_slice()).unwrap();
        assert_eq!(frame.dst_addr(), new_mac);
        let ip = Ipv4Packet::new_checked(frame.payload()).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!(tcp.payload(), b"b");
        assert_eq!(tcp.seq_number(), conn.seq + 1);
        assert_generic_frame(&mut conn.iface, &bytes);
        assert!(conn.device.inner.tx_queue.is_empty());
    }

    #[test]
    fn kept_mac_dropped_when_pending_evicts_peer() {
        let mut conn = Connection::with_capacity(1);
        conn.send(1, b"a");
        conn.take_data(b"a", 0);
        assert!(conn.device.inner.tx_queue.is_empty());
        assert!(conn.sockets.item_at_mut(0).unwrap().meta.next_hop.is_some());
        assert!(
            conn.sockets
                .item_at_mut(0)
                .unwrap()
                .meta
                .tcp_template
                .is_some()
        );
        let other = Ipv4Address::new(192, 168, 1, 3);
        connect_unresolved_peer(&mut conn.iface, &mut conn.sockets, other, 1235);
        conn.egress(2);
        assert_eq!(conn.device.inner.tx_queue.len(), 1);
        assert_arp_request(&conn.device.inner.tx_queue.pop_front().unwrap(), other);
        let other_handle = conn.sockets.iter().nth(1).unwrap().0;
        conn.sockets.remove(other_handle);
        conn.send(63_001, b"b");
        conn.take_probe();
        assert!(conn.sockets.item_at_mut(0).unwrap().meta.next_hop.is_none());
        assert!(conn.sockets.item_at_mut(0).unwrap().meta.is_waiting());
        assert_eq!(conn.sockets.get(conn.handle).send_queue(), 2);
    }

    #[test]
    fn alternating_unresolved_peers_bounded_arp() {
        let mut device = TestingDevice::new(Medium::Ethernet);
        let mut config = Config::new(LOCAL_MAC.into());
        config.neighbor_capacity = 1;
        let mut iface = Interface::new(config, &mut device, Instant::ZERO);
        iface.update_ip_addrs(|addrs| addrs.push(IpCidr::new(LOCAL.into(), 24)).unwrap());
        let mut sockets = TcpSet::new(vec![]);
        let other = Ipv4Address::new(192, 168, 1, 3);
        for millis in [0, 1, 2, 3, 998, 999, 1_000, 1_001, 1_002, 1_999, 2_000] {
            let peer = if millis % 2 == 0 { PEER } else { other };
            connect_unresolved_peer(&mut iface, &mut sockets, peer, 1234 + millis as u16);
            iface.poll_egress(Instant::from_millis(millis), &mut device, &mut sockets);
            if millis % 1_000 == 0 {
                assert_eq!(device.tx_queue.len(), 1);
                let bytes = device.tx_queue.pop_front().unwrap();
                let eth = EthernetFrame::new_checked(&bytes).unwrap();
                let arp = ArpPacket::new_checked(eth.payload()).unwrap();
                let target =
                    Ipv4Address::from_octets(arp.target_protocol_addr().try_into().unwrap());
                assert!(target == PEER || target == other);
                assert_arp_request(&bytes, target);
            } else {
                assert!(device.tx_queue.is_empty());
            }
        }
    }

    #[test]
    fn deferred_probe_dropped_when_fresh() {
        let mut conn = Connection::new();
        conn.device.tx_left = Some(1);
        conn.send(60_000, b"a");
        conn.take_data(b"a", 0);
        assert_eq!(conn.iface.inner.probe_owed, Some(PEER));
        assert!(!conn.iface.egress_idle(&conn.sockets));
        conn.arp_reply(60_500);
        conn.egress(60_500);
        assert_eq!(conn.iface.inner.probe_owed, None);
        assert!(conn.device.inner.tx_queue.is_empty());
        assert!(conn.iface.egress_idle(&conn.sockets));
        conn.device.tx_left = Some(1);
        conn.egress(60_501);
        assert!(conn.device.inner.tx_queue.is_empty());
        assert_eq!(conn.device.tx_left, Some(1));
        assert!(conn.iface.egress_idle(&conn.sockets));
    }

    #[test]
    fn one_way_stream_no_pending_at_expiry() {
        let mut conn = Connection::new();
        conn.send(60_000, b"a");
        conn.take_data(b"a", 0);
        conn.take_probe();
        conn.assert_stale_send();
        conn.send(60_500, b"b");
        conn.take_data(b"b", 1);
        assert!(conn.device.inner.tx_queue.is_empty());
        conn.assert_stale_send();
        conn.send(61_000, b"c");
        conn.take_data(b"abc", 0);
        conn.take_probe();
        conn.assert_stale_send();
        conn.arp_reply(61_001);
        conn.send(61_002, b"d");
        conn.take_data(b"d", 3);
        assert!(conn.device.inner.tx_queue.is_empty());
        assert_eq!(
            conn.sockets.item_at_mut(0).unwrap().meta.next_hop,
            Some((conn.iface.inner.neighbor_cache.changes(), PEER_MAC))
        );
    }

    #[test]
    fn stale_ends_after_three_seconds() {
        let mut conn = Connection::new();
        conn.send(60_000, b"a");
        conn.take_data(b"a", 0);
        conn.take_probe();
        conn.send(61_000, b"b");
        conn.take_data(b"ab", 0);
        conn.take_probe();
        conn.send(62_000, b"c");
        conn.take_data(b"c", 2);
        conn.take_probe();
        conn.send(63_000, b"d");
        conn.take_probe();
        assert!(conn.sockets.item_at_mut(0).unwrap().meta.is_waiting());
        assert_eq!(conn.sockets.get(conn.handle).send_queue(), 4);
    }

    #[test]
    fn probe_owed_when_tx_full() {
        let mut conn = Connection::new();
        conn.device.tx_left = Some(1);
        conn.send(60_000, b"a");
        conn.take_data(b"a", 0);
        assert!(conn.device.inner.tx_queue.is_empty());
        conn.assert_stale_send();
        assert_eq!(conn.iface.inner.probe_owed, Some(PEER));
        assert!(!conn.iface.egress_idle(&conn.sockets));
        assert_eq!(
            conn.iface
                .inner
                .neighbor_cache
                .lookup(&PEER.into(), Instant::from_millis(60_000)),
            NeighborAnswer::Stale {
                hardware_addr: PEER_MAC.into(),
                probe: true
            }
        );
        conn.device.tx_left = Some(1);
        conn.egress(60_000);
        conn.take_probe();
        assert_eq!(conn.iface.inner.probe_owed, None);
        assert!(conn.iface.egress_idle(&conn.sockets));
        assert_eq!(
            conn.iface
                .inner
                .neighbor_cache
                .lookup(&PEER.into(), Instant::from_millis(60_000)),
            NeighborAnswer::Stale {
                hardware_addr: PEER_MAC.into(),
                probe: false
            }
        );
    }
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case(Medium::Ethernet)]
fn test_unknown_protocol_with_payload_no_reply(#[case] medium: Medium) {
    let (mut iface, mut sockets, _) = setup(medium);
    let payload = [0x5a; 600];
    let repr = Ipv4Repr {
        src_addr: Ipv4Address::new(127, 0, 0, 2),
        dst_addr: Ipv4Address::new(127, 0, 0, 1),
        next_header: IpProtocol::Unknown(0x0c),
        payload_len: payload.len(),
        hop_limit: 64,
    };
    let mut bytes = vec![0; repr.buffer_len() + payload.len()];
    repr.emit(
        &mut Ipv4Packet::new_unchecked(&mut bytes[..]),
        &ChecksumCapabilities::default(),
    );
    bytes[repr.buffer_len()..].copy_from_slice(&payload);
    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv4Packet::new_checked(&bytes[..]).unwrap(),
            #[cfg(feature = "udp-set")]
            None,
        ),
        None
    );
}

#[rstest]
#[case(Medium::Ethernet)]
fn test_any_ip_accept_arp(#[case] medium: Medium) {
    let mut buffer = [0u8; 64];
    #[allow(non_snake_case)]
    fn ETHERNET_FRAME_ARP(buffer: &mut [u8]) -> &[u8] {
        let ethernet_repr = EthernetRepr {
            src_addr: EthernetAddress::from_bytes(&[0x02, 0x02, 0x02, 0x02, 0x02, 0x03]),
            dst_addr: EthernetAddress::from_bytes(&[0x02, 0x02, 0x02, 0x02, 0x02, 0x02]),
            ethertype: EthernetProtocol::Arp,
        };
        let frame_repr = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: EthernetAddress::from_bytes(&[
                0x02, 0x02, 0x02, 0x02, 0x02, 0x03,
            ]),
            source_protocol_addr: Ipv4Address::from_octets([192, 168, 1, 2]),
            target_hardware_addr: EthernetAddress::from_bytes(&[
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            ]),
            target_protocol_addr: Ipv4Address::from_octets([192, 168, 1, 3]),
        };
        let mut frame = EthernetFrame::new_unchecked(&mut buffer[..]);
        ethernet_repr.emit(&mut frame);

        let mut frame = ArpPacket::new_unchecked(&mut buffer[ethernet_repr.buffer_len()..]);
        frame_repr.emit(&mut frame);

        &buffer[..ethernet_repr.buffer_len() + frame_repr.buffer_len()]
    }

    let (mut iface, mut sockets, _) = setup(medium);

    assert!(
        iface
            .inner
            .process_ethernet(
                &mut sockets,
                PacketMeta::default(),
                ETHERNET_FRAME_ARP(buffer.as_mut()),
                #[cfg(feature = "udp-set")]
                None,
            )
            .is_none()
    );

    // Accept any IP address
    iface.set_any_ip(true);

    assert!(
        iface
            .inner
            .process_ethernet(
                &mut sockets,
                PacketMeta::default(),
                ETHERNET_FRAME_ARP(buffer.as_mut()),
                #[cfg(feature = "udp-set")]
                None,
            )
            .is_some()
    );
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case(Medium::Ethernet)]
fn test_no_icmp_no_unicast(#[case] medium: Medium) {
    let (mut iface, mut sockets, _) = setup(medium);

    // Unknown Ipv4 Protocol
    //
    // Because the destination is the broadcast address
    // this should not trigger and Destination Unreachable
    // response. See RFC 1122 § 3.2.2.
    let repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
        dst_addr: Ipv4Address::BROADCAST,
        next_header: IpProtocol::Unknown(0x0c),
        payload_len: 0,
        hop_limit: 0x40,
    });

    let mut bytes = vec![0u8; 54];
    repr.emit(&mut bytes, &ChecksumCapabilities::default());
    let frame = Ipv4Packet::new_unchecked(&bytes[..]);

    // Ensure that the unknown protocol frame does not trigger an
    // ICMP error response when the destination address is a
    // broadcast address

    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &frame,
            #[cfg(feature = "udp-set")]
            None,
        ),
        None
    );
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case(Medium::Ethernet)]
fn test_unknown_protocol_without_payload_no_reply(#[case] medium: Medium) {
    let (mut iface, mut sockets, _device) = setup(medium);

    // Unknown Ipv4 Protocol with no payload
    let repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x02),
        dst_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
        next_header: IpProtocol::Unknown(0x0c),
        payload_len: 0,
        hop_limit: 0x40,
    });

    let mut bytes = vec![0u8; 34];
    repr.emit(&mut bytes, &ChecksumCapabilities::default());
    let frame = Ipv4Packet::new_unchecked(&bytes[..]);

    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &frame,
            #[cfg(feature = "udp-set")]
            None,
        ),
        None
    );
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case(Medium::Ethernet)]
fn test_local_subnet_broadcasts(#[case] medium: Medium) {
    let (mut iface, _, _device) = setup(medium);
    iface.update_ip_addrs(|addrs| {
        addrs.iter_mut().next().map(|addr| {
            *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(192, 168, 1, 23), 24));
        });
    });

    assert!(
        iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(255, 255, 255, 255))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(255, 255, 255, 254))
    );
    assert!(
        iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 168, 1, 255))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 168, 1, 254))
    );

    iface.update_ip_addrs(|addrs| {
        addrs.iter_mut().next().map(|addr| {
            *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(192, 168, 23, 24), 16));
        });
    });
    assert!(
        iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(255, 255, 255, 255))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(255, 255, 255, 254))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 168, 23, 255))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 168, 23, 254))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 168, 255, 254))
    );
    assert!(
        iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 168, 255, 255))
    );

    iface.update_ip_addrs(|addrs| {
        addrs.iter_mut().next().map(|addr| {
            *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(192, 168, 23, 24), 8));
        });
    });
    assert!(
        iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(255, 255, 255, 255))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(255, 255, 255, 254))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 23, 1, 255))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 23, 1, 254))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 255, 255, 254))
    );
    assert!(
        iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 255, 255, 255))
    );
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(all(feature = "medium-ip", feature = "auto-icmp-echo-reply"))]
#[case(Medium::Ethernet)]
#[cfg(feature = "auto-icmp-echo-reply")]
fn test_unicast_echo_reply(#[case] medium: Medium) {
    let (mut iface, mut sockets, _) = setup(medium);
    let data = [0x5a; 57];
    let icmp = Icmpv4Repr::EchoRequest {
        ident: 0x1234,
        seq_no: 0xabcd,
        data: &data,
    };
    let ip = Ipv4Repr {
        src_addr: Ipv4Address::new(127, 0, 0, 2),
        dst_addr: iface.ipv4_addr().unwrap(),
        next_header: IpProtocol::Icmp,
        hop_limit: 31,
        payload_len: icmp.buffer_len(),
    };
    let caps = ChecksumCapabilities::default();
    let mut bytes = vec![0; ip.buffer_len() + ip.payload_len];
    ip.emit(&mut Ipv4Packet::new_unchecked(&mut bytes[..]), &caps);
    icmp.emit(
        &mut Icmpv4Packet::new_unchecked(&mut bytes[ip.buffer_len()..]),
        &caps,
    );
    let expected_icmp = Icmpv4Repr::EchoReply {
        ident: 0x1234,
        seq_no: 0xabcd,
        data: &data,
    };
    let expected_ip = Ipv4Repr {
        src_addr: ip.dst_addr,
        dst_addr: ip.src_addr,
        next_header: IpProtocol::Icmp,
        hop_limit: 64,
        payload_len: expected_icmp.buffer_len(),
    };
    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv4Packet::new_checked(&bytes[..]).unwrap(),
            #[cfg(feature = "udp-set")]
            None,
        ),
        Some(Packet::new_ipv4(expected_ip, IpPayload::Icmpv4(expected_icmp)))
    );
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(all(feature = "medium-ip", feature = "auto-icmp-echo-reply"))]
#[case(Medium::Ethernet)]
#[cfg(feature = "auto-icmp-echo-reply")]
fn test_broadcast_echo_no_reply(#[case] medium: Medium) {
    let (mut iface, mut sockets, _) = setup(medium);
    let data = [0x5a; 57];
    let icmp = Icmpv4Repr::EchoRequest {
        ident: 0x1234,
        seq_no: 0xabcd,
        data: &data,
    };
    let caps = ChecksumCapabilities::default();
    for dst_addr in [
        Ipv4Address::new(192, 168, 1, 255),
        Ipv4Address::BROADCAST,
        Ipv4Address::new(224, 0, 0, 1),
    ] {
        let ip = Ipv4Repr {
            src_addr: Ipv4Address::new(192, 168, 1, 2),
            dst_addr,
            next_header: IpProtocol::Icmp,
            hop_limit: 64,
            payload_len: icmp.buffer_len(),
        };
        let mut bytes = vec![0; ip.buffer_len() + ip.payload_len];
        ip.emit(&mut Ipv4Packet::new_unchecked(&mut bytes[..]), &caps);
        icmp.emit(
            &mut Icmpv4Packet::new_unchecked(&mut bytes[ip.buffer_len()..]),
            &caps,
        );
        assert_eq!(
            iface.inner.process_ipv4(
                &mut sockets,
                PacketMeta::default(),
                HardwareAddress::default(),
                &Ipv4Packet::new_checked(&bytes[..]).unwrap(),
                #[cfg(feature = "udp-set")]
                None,
            ),
            None,
            "echo request to {dst_addr} must not get a reply"
        );
    }
}

#[rstest]
#[case(Medium::Ethernet)]
fn test_handle_valid_arp_request(#[case] medium: Medium) {
    let (mut iface, mut sockets, _device) = setup(medium);

    let mut eth_bytes = vec![0u8; 42];

    let local_ip_addr = Ipv4Address::new(0x7f, 0x00, 0x00, 0x01);
    let remote_ip_addr = Ipv4Address::new(0x7f, 0x00, 0x00, 0x02);
    let local_hw_addr = EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

    let repr = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: remote_hw_addr,
        source_protocol_addr: remote_ip_addr,
        target_hardware_addr: EthernetAddress::default(),
        target_protocol_addr: local_ip_addr,
    };

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(EthernetAddress::BROADCAST);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Arp);
    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
    repr.emit(&mut packet);

    // Ensure an ARP Request for us triggers an ARP Reply
    assert_eq!(
        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            #[cfg(feature = "udp-set")]
            None,
        ),
        Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: local_hw_addr,
            source_protocol_addr: local_ip_addr,
            target_hardware_addr: remote_hw_addr,
            target_protocol_addr: remote_ip_addr
        }))
    );

    // Ensure the address of the requester was entered in the cache
    assert_eq!(
        iface.inner.lookup_hardware_addr(
            MockTxToken,
            &IpAddress::Ipv4(remote_ip_addr),
            None,
        ),
        Ok((HardwareAddress::Ethernet(remote_hw_addr), MockTxToken))
    );
}

#[test]
#[allow(unsafe_code)]
fn ingress_takes_each_frame_once_via_into_buf() {
    use core::cell::Cell;
    use core::ptr::NonNull;
    use std::boxed::Box;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use crate::phy::RxBuf;
    use crate::socket::tcp;
    use crate::tests::TestingDevice;

    #[derive(Default)]
    struct Counts {
        takes: Cell<usize>,
        releases: Cell<usize>,
    }

    struct FrameStorage {
        bytes: Vec<u8>,
        counts: Rc<Counts>,
    }

    struct CountingRxToken(FrameStorage);

    impl RxToken for CountingRxToken {
        fn into_buf(self) -> RxBuf {
            unsafe fn release(owner: NonNull<()>) {
                // SAFETY: into_buf transfers this Box<FrameStorage> to the callback.
                let storage = unsafe { Box::from_raw(owner.cast::<FrameStorage>().as_ptr()) };
                storage.counts.releases.set(
                    storage
                        .counts
                        .releases
                        .get()
                        .checked_add(1)
                        .expect("release count overflow"),
                );
            }

            self.0.counts.takes.set(
                self.0
                    .counts
                    .takes
                    .get()
                    .checked_add(1)
                    .expect("take count overflow"),
            );
            let storage = Box::leak(Box::new(self.0));
            let data = NonNull::new(storage.bytes.as_mut_ptr()).unwrap();
            let len = storage.bytes.len();
            let owner = NonNull::from(storage).cast();
            // SAFETY: the vector owns this range exclusively until release drops its box.
            unsafe { RxBuf::from_raw_parts(owner, release, data, len, 0) }
        }
    }

    struct CountingDevice {
        inner: TestingDevice,
        queue: VecDeque<CountingRxToken>,
    }

    impl Device for CountingDevice {
        type RxToken<'a> = CountingRxToken;
        type TxToken<'a> = crate::tests::TxToken<'a>;

        fn capabilities(&self) -> DeviceCapabilities {
            self.inner.capabilities()
        }

        fn receive(
            &mut self,
            timestamp: Instant,
        ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            let rx = self.queue.pop_front()?;
            let tx = self.inner.transmit(timestamp).unwrap();
            Some((rx, tx))
        }

        fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>> {
            self.inner.transmit(timestamp)
        }
    }

    let (mut iface, mut sockets, inner) = setup(Medium::Ethernet);
    let local_ip = Ipv4Address::new(192, 168, 1, 1);
    let remote_ip = Ipv4Address::new(192, 168, 1, 2);
    let local_hw = EthernetAddress([2; 6]);
    let remote_hw = EthernetAddress([0x52, 0x54, 0, 0, 0, 1]);
    let arp = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: remote_hw,
        source_protocol_addr: remote_ip,
        target_hardware_addr: EthernetAddress::default(),
        target_protocol_addr: local_ip,
    };
    let mut arp_bytes = vec![0; EthernetFrame::<&[u8]>::header_len() + arp.buffer_len()];
    let mut frame = EthernetFrame::new_unchecked(&mut arp_bytes);
    EthernetRepr {
        src_addr: remote_hw,
        dst_addr: EthernetAddress::BROADCAST,
        ethertype: EthernetProtocol::Arp,
    }
    .emit(&mut frame);
    arp.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()));

    let syn = TcpRepr {
        src_port: 65000,
        dst_port: 1234,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(100),
        ack_number: None,
        window_len: 64,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };
    let ip = Ipv4Repr {
        src_addr: remote_ip,
        dst_addr: local_ip,
        next_header: IpProtocol::Tcp,
        payload_len: syn.buffer_len(),
        hop_limit: 64,
    };
    let eth = EthernetRepr {
        src_addr: remote_hw,
        dst_addr: local_hw,
        ethertype: EthernetProtocol::Ipv4,
    };
    let mut syn_bytes = vec![0; eth.buffer_len() + ip.buffer_len() + syn.buffer_len()];
    let mut frame = EthernetFrame::new_unchecked(&mut syn_bytes);
    eth.emit(&mut frame);
    let mut packet = Ipv4Packet::new_unchecked(frame.payload_mut());
    let caps = ChecksumCapabilities::default();
    ip.emit(&mut packet, &caps);
    syn.emit(
        &mut TcpPacket::new_unchecked(packet.payload_mut()),
        &remote_ip.into(),
        &local_ip.into(),
        &caps,
    );

    let counts = [Rc::new(Counts::default()), Rc::new(Counts::default())];
    let queue = [arp_bytes, syn_bytes]
        .into_iter()
        .zip(&counts)
        .map(|(bytes, counts)| {
            CountingRxToken(FrameStorage {
                bytes,
                counts: counts.clone(),
            })
        })
        .collect();
    let mut device = CountingDevice {
        inner,
        queue: VecDeque::new(),
    };
    let mut listener =
        tcp::Socket::new(tcp::RxBuffer::new(64), tcp::SocketBuffer::new(vec![0; 64]));
    listener.listen(1234).unwrap();
    let handle = sockets.add(listener);

    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    device.inner.tx_queue.clear();
    device.queue = queue;
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    for counts in &counts {
        assert_eq!(counts.takes.get(), 1);
        assert_eq!(counts.releases.get(), 1);
    }
    assert!(device.queue.is_empty());
    assert_eq!(device.inner.tx_queue.len(), 2);
    assert_eq!(sockets.get(handle).state(), tcp::State::SynReceived);

    let arp_reply = device.inner.tx_queue.pop_front().unwrap();
    let frame = EthernetFrame::new_checked(arp_reply.as_slice()).unwrap();
    assert_eq!(frame.src_addr(), local_hw);
    assert_eq!(frame.dst_addr(), remote_hw);
    assert_eq!(frame.ethertype(), EthernetProtocol::Arp);
    assert_eq!(
        ArpRepr::parse(&ArpPacket::new_checked(frame.payload()).unwrap()).unwrap(),
        ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: local_hw,
            source_protocol_addr: local_ip,
            target_hardware_addr: remote_hw,
            target_protocol_addr: remote_ip,
        }
    );

    let syn_ack = device.inner.tx_queue.pop_front().unwrap();
    let frame = EthernetFrame::new_checked(syn_ack.as_slice()).unwrap();
    assert_eq!(frame.src_addr(), local_hw);
    assert_eq!(frame.dst_addr(), remote_hw);
    assert_eq!(frame.ethertype(), EthernetProtocol::Ipv4);
    let ip_packet = Ipv4Packet::new_checked(frame.payload()).unwrap();
    let ip = Ipv4Repr::parse(&ip_packet, &caps).unwrap();
    assert_eq!(ip.src_addr, local_ip);
    assert_eq!(ip.dst_addr, remote_ip);
    assert_eq!(ip.next_header, IpProtocol::Tcp);
    let tcp_packet = TcpPacket::new_checked(ip_packet.payload()).unwrap();
    let tcp = TcpRepr::parse(&tcp_packet, &local_ip.into(), &remote_ip.into(), &caps).unwrap();
    assert_eq!(tcp.src_port, 1234);
    assert_eq!(tcp.dst_port, 65000);
    assert_eq!(tcp.control, TcpControl::Syn);
    assert_eq!(tcp.ack_number, Some(TcpSeqNumber(101)));
    assert!(tcp.payload.is_empty());
    assert_generic_frame(&mut iface, &syn_ack);
}

#[rstest]
#[case(Medium::Ethernet)]
fn test_handle_off_subnet_arp_request(#[case] medium: Medium) {
    let (mut iface, mut sockets, _device) = setup(medium);

    let mut eth_bytes = vec![0u8; 42];

    let local_ip_addr = Ipv4Address::new(0x7f, 0x00, 0x00, 0x01);
    let remote_ip_addr = Ipv4Address::new(10, 0, 0, 2);
    let local_hw_addr = EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

    let repr = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: remote_hw_addr,
        source_protocol_addr: remote_ip_addr,
        target_hardware_addr: EthernetAddress::default(),
        target_protocol_addr: local_ip_addr,
    };

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(EthernetAddress::BROADCAST);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Arp);
    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
    repr.emit(&mut packet);

    // Ensure an ARP Request for us from outside our subnet triggers an ARP Reply
    assert_eq!(
        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            #[cfg(feature = "udp-set")]
            None,
        ),
        Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: local_hw_addr,
            source_protocol_addr: local_ip_addr,
            target_hardware_addr: remote_hw_addr,
            target_protocol_addr: remote_ip_addr
        }))
    );

    // Ensure the off-subnet requester was NOT entered in the cache
    assert!(
        !iface
            .inner
            .neighbor_cache
            .lookup(&IpAddress::Ipv4(remote_ip_addr), iface.inner.now)
            .found()
    );
}

#[rstest]
#[case(Medium::Ethernet)]
fn test_handle_other_arp_request(#[case] medium: Medium) {
    let (mut iface, mut sockets, _device) = setup(medium);

    let mut eth_bytes = vec![0u8; 42];

    let remote_ip_addr = Ipv4Address::new(0x7f, 0x00, 0x00, 0x02);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

    let repr = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: remote_hw_addr,
        source_protocol_addr: remote_ip_addr,
        target_hardware_addr: EthernetAddress::default(),
        target_protocol_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x03),
    };

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(EthernetAddress::BROADCAST);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Arp);
    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
    repr.emit(&mut packet);

    // Ensure an ARP Request for someone else does not trigger an ARP Reply
    assert_eq!(
        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            #[cfg(feature = "udp-set")]
            None,
        ),
        None
    );

    // Ensure the address of the requester was NOT entered in the cache
    assert_eq!(
        iface.inner.lookup_hardware_addr(
            MockTxToken,
            &IpAddress::Ipv4(remote_ip_addr),
            None,
        ),
        Err(DispatchError::NeighborPending)
    );
}

#[rstest]
#[case(Medium::Ethernet)]
fn test_arp_flush_after_update_ip(#[case] medium: Medium) {
    let (mut iface, mut sockets, _device) = setup(medium);

    let mut eth_bytes = vec![0u8; 42];

    let local_ip_addr = Ipv4Address::new(0x7f, 0x00, 0x00, 0x01);
    let remote_ip_addr = Ipv4Address::new(0x7f, 0x00, 0x00, 0x02);
    let local_hw_addr = EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

    let repr = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: remote_hw_addr,
        source_protocol_addr: remote_ip_addr,
        target_hardware_addr: EthernetAddress::default(),
        target_protocol_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
    };

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(EthernetAddress::BROADCAST);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Arp);
    {
        let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
        repr.emit(&mut packet);
    }

    // Ensure an ARP Request for us triggers an ARP Reply
    assert_eq!(
        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            #[cfg(feature = "udp-set")]
            None,
        ),
        Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: local_hw_addr,
            source_protocol_addr: local_ip_addr,
            target_hardware_addr: remote_hw_addr,
            target_protocol_addr: remote_ip_addr
        }))
    );

    // Ensure the address of the requester was entered in the cache
    assert_eq!(
        iface.inner.lookup_hardware_addr(
            MockTxToken,
            &IpAddress::Ipv4(remote_ip_addr),
            None,
        ),
        Ok((HardwareAddress::Ethernet(remote_hw_addr), MockTxToken))
    );

    // Update IP addrs to trigger ARP cache flush
    let local_ip_addr_new = Ipv4Address::new(0x7f, 0x00, 0x00, 0x01);
    iface.update_ip_addrs(|addrs| {
        addrs.iter_mut().next().map(|addr| {
            *addr = IpCidr::Ipv4(Ipv4Cidr::new(local_ip_addr_new, 24));
        });
    });

    // ARP cache flush after address change
    assert!(!iface.inner.has_neighbor(&IpAddress::Ipv4(remote_ip_addr)));
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case(Medium::Ethernet)]
fn get_source_address(#[case] medium: Medium) {
    let (mut iface, _, _) = setup(medium);

    const OWN_UNIQUE_LOCAL_ADDR1: Ipv4Address = Ipv4Address::new(172, 18, 1, 2);
    const OWN_UNIQUE_LOCAL_ADDR2: Ipv4Address = Ipv4Address::new(172, 24, 24, 14);

    // List of addresses of the interface:
    //   172.18.1.2/24
    //   172.24.24.14/24
    iface.update_ip_addrs(|addrs| {
        addrs.clear();

        addrs
            .push(IpCidr::Ipv4(Ipv4Cidr::new(OWN_UNIQUE_LOCAL_ADDR1, 24)))
            .unwrap();
        addrs
            .push(IpCidr::Ipv4(Ipv4Cidr::new(OWN_UNIQUE_LOCAL_ADDR2, 24)))
            .unwrap();
    });

    // List of addresses we test:
    //   172.18.1.254 -> 172.18.1.2
    //   172.24.24.12 -> 172.24.24.14
    //   172.24.23.254 -> 172.18.1.2
    const UNIQUE_LOCAL_ADDR1: Ipv4Address = Ipv4Address::new(172, 18, 1, 254);
    const UNIQUE_LOCAL_ADDR2: Ipv4Address = Ipv4Address::new(172, 24, 24, 12);
    const UNIQUE_LOCAL_ADDR3: Ipv4Address = Ipv4Address::new(172, 24, 23, 254);

    assert_eq!(
        iface.inner.get_source_address_ipv4(&UNIQUE_LOCAL_ADDR1),
        Some(OWN_UNIQUE_LOCAL_ADDR1)
    );

    assert_eq!(
        iface.inner.get_source_address_ipv4(&UNIQUE_LOCAL_ADDR2),
        Some(OWN_UNIQUE_LOCAL_ADDR2)
    );
    assert_eq!(
        iface.inner.get_source_address_ipv4(&UNIQUE_LOCAL_ADDR3),
        Some(OWN_UNIQUE_LOCAL_ADDR1)
    );
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case(Medium::Ethernet)]
fn get_source_address_empty_interface(#[case] medium: Medium) {
    let (mut iface, _, _) = setup(medium);

    iface.update_ip_addrs(|ips| ips.clear());

    // List of addresses we test:
    //   172.18.1.254 -> None
    //   172.24.24.12 -> None
    //   172.24.23.254 -> None
    const UNIQUE_LOCAL_ADDR1: Ipv4Address = Ipv4Address::new(172, 18, 1, 254);
    const UNIQUE_LOCAL_ADDR2: Ipv4Address = Ipv4Address::new(172, 24, 24, 12);
    const UNIQUE_LOCAL_ADDR3: Ipv4Address = Ipv4Address::new(172, 24, 23, 254);

    assert_eq!(
        iface.inner.get_source_address_ipv4(&UNIQUE_LOCAL_ADDR1),
        None
    );
    assert_eq!(
        iface.inner.get_source_address_ipv4(&UNIQUE_LOCAL_ADDR2),
        None
    );
    assert_eq!(
        iface.inner.get_source_address_ipv4(&UNIQUE_LOCAL_ADDR3),
        None
    );
}

use crate::wire::ipv4::HEADER_LEN;
#[cfg(feature = "medium-ip")]
const CHECKSUM_SRC: Ipv4Address = Ipv4Address::new(127, 0, 0, 2);
#[cfg(feature = "medium-ip")]
const CHECKSUM_DST: Ipv4Address = Ipv4Address::new(127, 0, 0, 1);

/// IPv4 packet CHECKSUM_SRC -> CHECKSUM_DST with correct header checksum.
#[cfg(feature = "medium-ip")]
fn ipv4_packet_bytes(next_header: IpProtocol, payload: &[u8]) -> Vec<u8> {
    let repr = Ipv4Repr {
        src_addr: CHECKSUM_SRC,
        dst_addr: CHECKSUM_DST,
        next_header,
        payload_len: payload.len(),
        hop_limit: 64,
    };
    let mut bytes = vec![0u8; repr.buffer_len() + payload.len()];
    repr.emit(
        &mut Ipv4Packet::new_unchecked(&mut bytes[..]),
        &ChecksumCapabilities::default(),
    );
    bytes[repr.buffer_len()..].copy_from_slice(payload);
    bytes
}

/// Unicast echo request with valid IPv4 and ICMP checksums.
#[cfg(all(feature = "medium-ip", feature = "auto-icmp-echo-reply"))]
fn icmp_echo_request_bytes() -> Vec<u8> {
    let icmp = Icmpv4Repr::EchoRequest {
        ident: 0x1234,
        seq_no: 0xabcd,
        data: &[0x5a; 57],
    };
    let mut bytes = vec![0u8; icmp.buffer_len()];
    icmp.emit(
        &mut Icmpv4Packet::new_unchecked(&mut bytes[..]),
        &ChecksumCapabilities::default(),
    );
    ipv4_packet_bytes(IpProtocol::Icmp, &bytes)
}

#[cfg(feature = "medium-ip")]
fn corrupt_ipv4_checksum(bytes: &mut [u8]) {
    let mut packet = Ipv4Packet::new_unchecked(bytes);
    let checksum = packet.checksum();
    packet.set_checksum(checksum ^ 1);
    assert!(!packet.verify_checksum());
}

/// Protocol of the stack's reply to `bytes` received with `meta`; `None` when dropped.
#[cfg(feature = "medium-ip")]
fn ipv4_reply_protocol(meta: PacketMeta, bytes: &[u8]) -> Option<IpProtocol> {
    let (mut iface, mut sockets, _device) = setup(Medium::Ip);
    iface
        .inner
        .process_ipv4(
            &mut sockets,
            meta,
            HardwareAddress::default(),
            &Ipv4Packet::new_unchecked(bytes),
            #[cfg(feature = "udp-set")]
            None,
        )
        .map(|reply| reply.ip_repr().next_header())
}

/// SYN to a port with no socket: when accepted, the stack answers with RST.
#[cfg(feature = "medium-ip")]
fn tcp_syn_bytes() -> Vec<u8> {
    let tcp = TcpRepr {
        src_port: 4242,
        dst_port: 4243,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(0),
        ack_number: None,
        window_len: 256,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };
    let mut tcp_bytes = vec![0u8; tcp.buffer_len()];
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut tcp_bytes[..]),
        &CHECKSUM_SRC.into(),
        &CHECKSUM_DST.into(),
        &ChecksumCapabilities::default(),
    );
    ipv4_packet_bytes(IpProtocol::Tcp, &tcp_bytes)
}

#[cfg(feature = "medium-ip")]
fn ipv4_ip_reply(bytes: &[u8]) -> bool {
    let (mut iface, mut sockets, _device) = setup(Medium::Ip);
    iface
        .inner
        .process_ip(
            &mut sockets,
            PacketMeta::default(),
            bytes,
            #[cfg(feature = "udp-set")]
            None,
        )
        .is_some()
}

#[cfg(feature = "medium-ip")]
fn ipv4_ethernet_reply(bytes: &[u8]) -> bool {
    let (mut iface, mut sockets, _device) = setup(Medium::Ethernet);
    let mut eth_bytes = vec![0u8; EthernetFrame::<&[u8]>::buffer_len(bytes.len())];
    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes[..]);
    frame.set_dst_addr(iface.inner.hardware_addr.ethernet_or_panic());
    frame.set_src_addr(EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]));
    frame.set_ethertype(EthernetProtocol::Ipv4);
    frame.payload_mut().copy_from_slice(bytes);
    iface
        .inner
        .process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            #[cfg(feature = "udp-set")]
            None,
        )
        .is_some()
}

#[rstest]
#[case::ip(ipv4_ip_reply, &[1, 19])]
#[case::ethernet(ipv4_ethernet_reply, &[0, 1, 19])]
#[cfg(feature = "medium-ip")]
fn malformed_ipv4_lengths_dropped(
    #[case] reply: fn(&[u8]) -> bool,
    #[case] truncated_lengths: &[usize],
) {
    let good = tcp_syn_bytes();
    assert!(reply(&good));

    for &len in truncated_lengths {
        assert!(!reply(&good[..len]), "IPv4 buffer length {len}");
    }

    let mut bytes = good.clone();
    let mut packet = Ipv4Packet::new_unchecked(&mut bytes[..]);
    packet.set_header_len(16);
    packet.fill_checksum();
    assert!(!reply(&bytes), "IPv4 IHL 4");

    let mut bytes = good.clone();
    // Fill the checksum before truncating the 60-byte header.
    bytes.resize(60, 0);
    let mut packet = Ipv4Packet::new_unchecked(&mut bytes[..]);
    packet.set_header_len(60);
    packet.fill_checksum();
    bytes.truncate(good.len());
    assert!(!reply(&bytes), "IPv4 IHL 15 exceeds the buffer");

    for total_len in [19, good.len() as u16 + 1] {
        let mut bytes = good.clone();
        let mut packet = Ipv4Packet::new_unchecked(&mut bytes[..]);
        packet.set_total_len(total_len);
        packet.fill_checksum();
        assert!(!reply(&bytes), "IPv4 total length {total_len}");
    }
}

#[rstest]
#[case::ip(ipv4_ip_reply)]
#[case::ethernet(ipv4_ethernet_reply)]
#[cfg(feature = "medium-ip")]
fn malformed_tcp_lengths_dropped(#[case] reply: fn(&[u8]) -> bool) {
    let good = tcp_syn_bytes();
    assert!(reply(&good));

    for tcp_len in 0..20 {
        let mut bytes = good.clone();
        bytes.truncate(HEADER_LEN + tcp_len);
        let total_len = bytes.len() as u16;
        let mut packet = Ipv4Packet::new_unchecked(&mut bytes[..]);
        packet.set_total_len(total_len);
        packet.fill_checksum();
        assert!(!reply(&bytes), "{tcp_len}-byte TCP segment");
    }

    for header_len in [16, 60] {
        let mut bytes = good.clone();
        let mut packet = TcpPacket::new_unchecked(&mut bytes[HEADER_LEN..]);
        packet.set_header_len(header_len);
        packet.fill_checksum(&CHECKSUM_SRC.into(), &CHECKSUM_DST.into());
        Ipv4Packet::new_unchecked(&mut bytes[..]).fill_checksum();
        assert!(!reply(&bytes), "TCP header length {header_len}");
    }
}

#[rstest]
#[case::ip(ipv4_ip_reply)]
#[case::ethernet(ipv4_ethernet_reply)]
#[cfg(feature = "medium-ip")]
fn trailing_bytes_after_ipv4_total_length_still_answered(#[case] reply: fn(&[u8]) -> bool) {
    let mut bytes = tcp_syn_bytes();
    assert!(reply(&bytes));

    bytes.extend_from_slice(&[0xa5; 8]);
    assert!(reply(&bytes));
}

#[cfg(feature = "medium-ip")]
fn corrupt_tcp_checksum(bytes: &mut [u8]) {
    let mut packet = TcpPacket::new_unchecked(&mut bytes[HEADER_LEN..]);
    let checksum = packet.checksum();
    packet.set_checksum(checksum ^ 1);
    assert!(!packet.verify_checksum(&CHECKSUM_SRC.into(), &CHECKSUM_DST.into()));
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "auto-icmp-echo-reply"))]
fn default_meta_verifies_ipv4_checksum() {
    let good = icmp_echo_request_bytes();
    assert_eq!(
        ipv4_reply_protocol(PacketMeta::default(), &good),
        Some(IpProtocol::Icmp)
    );

    let mut corrupt = good;
    corrupt_ipv4_checksum(&mut corrupt);
    assert_eq!(ipv4_reply_protocol(PacketMeta::default(), &corrupt), None);
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "auto-icmp-echo-reply"))]
fn meta_verified_accepts_corrupt_checksum_ipv4() {
    let mut bytes = icmp_echo_request_bytes();
    corrupt_ipv4_checksum(&mut bytes);
    let meta = PacketMeta {
        ipv4_checksum_verified: true,
        ..PacketMeta::default()
    };
    assert_eq!(ipv4_reply_protocol(meta, &bytes), Some(IpProtocol::Icmp));
}

/// The transport-layer flag does not vouch for the IPv4 header.
#[test]
#[cfg(all(feature = "medium-ip", feature = "auto-icmp-echo-reply"))]
fn meta_unverified_drops_corrupt_checksum_ipv4() {
    let mut bytes = icmp_echo_request_bytes();
    corrupt_ipv4_checksum(&mut bytes);
    let meta = PacketMeta {
        l4_checksum_verified: true,
        ..PacketMeta::default()
    };
    assert_eq!(ipv4_reply_protocol(meta, &bytes), None);
}

#[test]
#[cfg(feature = "medium-ip")]
fn default_meta_verifies_tcp_checksum() {
    let good = tcp_syn_bytes();
    assert_eq!(
        ipv4_reply_protocol(PacketMeta::default(), &good),
        Some(IpProtocol::Tcp)
    );

    let mut corrupt = good;
    corrupt_tcp_checksum(&mut corrupt);
    assert_eq!(ipv4_reply_protocol(PacketMeta::default(), &corrupt), None);
}

#[test]
#[cfg(feature = "medium-ip")]
fn meta_verified_accepts_corrupt_checksum_tcp() {
    let mut bytes = tcp_syn_bytes();
    corrupt_tcp_checksum(&mut bytes);
    let meta = PacketMeta {
        l4_checksum_verified: true,
        ..PacketMeta::default()
    };
    assert_eq!(ipv4_reply_protocol(meta, &bytes), Some(IpProtocol::Tcp));
}

/// The IPv4 header flag does not vouch for the TCP checksum.
#[test]
#[cfg(feature = "medium-ip")]
fn meta_unverified_drops_corrupt_checksum_tcp() {
    let mut bytes = tcp_syn_bytes();
    corrupt_tcp_checksum(&mut bytes);
    let meta = PacketMeta {
        ipv4_checksum_verified: true,
        ..PacketMeta::default()
    };
    assert_eq!(ipv4_reply_protocol(meta, &bytes), None);
}

const PROBER_MAC: EthernetAddress = EthernetAddress([0x52, 0x54, 0, 0, 0, 7]);

// RFC 5227 probe: sender IP 0.0.0.0 asking for our address.
fn arp_probe(operation: ArpOperation) -> Vec<u8> {
    let arp = ArpRepr::EthernetIpv4 {
        operation,
        source_hardware_addr: PROBER_MAC,
        source_protocol_addr: Ipv4Address::UNSPECIFIED,
        target_hardware_addr: EthernetAddress([0; 6]),
        target_protocol_addr: Ipv4Address::new(192, 168, 1, 1),
    };
    let mut bytes = vec![0; EthernetFrame::<&[u8]>::buffer_len(arp.buffer_len())];
    let mut frame = EthernetFrame::new_unchecked(&mut bytes);
    frame.set_src_addr(PROBER_MAC);
    frame.set_dst_addr(EthernetAddress::BROADCAST);
    frame.set_ethertype(EthernetProtocol::Arp);
    arp.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()));
    bytes
}

// Linux arp_process answers a duplicate-address probe for a local address.
#[test]
fn arp_probe_from_unspecified_sender_gets_reply() {
    let (mut iface, _, _) = setup(Medium::Ethernet);
    let bytes = arp_probe(ArpOperation::Request);
    let frame = EthernetFrame::new_checked(bytes.as_slice()).unwrap();
    assert_eq!(
        iface.inner.process_arp(Instant::ZERO, &frame),
        Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]),
            source_protocol_addr: Ipv4Address::new(192, 168, 1, 1),
            target_hardware_addr: PROBER_MAC,
            target_protocol_addr: Ipv4Address::UNSPECIFIED,
        }))
    );
}

#[test]
fn arp_from_unspecified_sender_leaves_cache_unchanged() {
    let (mut iface, _, _) = setup(Medium::Ethernet);
    let changes = iface.inner.neighbor_cache.changes();
    for (operation, answered) in [(ArpOperation::Request, true), (ArpOperation::Reply, false)] {
        let bytes = arp_probe(operation);
        let frame = EthernetFrame::new_checked(bytes.as_slice()).unwrap();
        assert_eq!(iface.inner.process_arp(Instant::ZERO, &frame).is_some(), answered);
    }
    assert_eq!(iface.inner.neighbor_cache.changes(), changes);
}
