use super::*;
use crate::iface::SocketHandle;
use crate::socket::tcp;
use crate::tests::TestingDevice;
use core::sync::atomic::Ordering;

const LOCAL: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
const PEER: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
const LOCAL_MAC: EthernetAddress = EthernetAddress([2, 0, 0, 0, 0, 1]);
const PEER_MAC: EthernetAddress = EthernetAddress([2, 0, 0, 0, 0, 2]);
const NEW_MAC: EthernetAddress = EthernetAddress([2, 0, 0, 0, 0, 3]);

struct Peer {
    iface: Interface,
    sockets: TcpSet<'static>,
    device: TestingDevice,
    local: Ipv4Address,
    local_port: u16,
    remote: Ipv4Address,
    remote_port: u16,
    mac: EthernetAddress,
    handle: SocketHandle,
    ack: TcpSeqNumber,
    frames: Vec<Vec<u8>>,
}

fn tcp_frame(remote: Ipv4Address, mac: EthernetAddress, tcp: TcpRepr) -> Vec<u8> {
    tcp_frame_to(LOCAL, LOCAL_MAC, remote, mac, tcp)
}

fn tcp_frame_to(
    local: Ipv4Address,
    local_mac: EthernetAddress,
    remote: Ipv4Address,
    mac: EthernetAddress,
    tcp: TcpRepr,
) -> Vec<u8> {
    let ip = Ipv4Repr {
        src_addr: remote,
        dst_addr: local,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    let caps = ChecksumCapabilities::default();
    let mut bytes = vec![0; EthernetFrame::<&[u8]>::buffer_len(ip.buffer_len() + tcp.buffer_len())];
    let mut eth = EthernetFrame::new_unchecked(&mut bytes);
    eth.set_src_addr(mac);
    eth.set_dst_addr(local_mac);
    eth.set_ethertype(EthernetProtocol::Ipv4);
    ip.emit(&mut Ipv4Packet::new_unchecked(eth.payload_mut()), &caps);
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut eth.payload_mut()[ip.buffer_len()..]),
        &remote.into(),
        &local.into(),
        &caps,
    );
    bytes
}

fn reply(control: TcpControl, ack: TcpSeqNumber) -> TcpRepr<'static> {
    TcpRepr {
        src_port: 80,
        dst_port: 40000,
        control,
        seq_number: TcpSeqNumber(100),
        ack_number: Some(ack),
        window_len: 4096,
        window_scale: None,
        max_seg_size: Some(512),
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    }
}

impl Peer {
    fn new(capacity: usize, remote: Ipv4Address, gateway: Option<Ipv4Address>) -> Self {
        Self::configured(capacity, remote, gateway, |_, _| {})
    }

    fn configured(
        capacity: usize,
        remote: Ipv4Address,
        gateway: Option<Ipv4Address>,
        configure: impl FnOnce(&mut Interface, &mut tcp::Socket<'static>),
    ) -> Self {
        Self::configured_with_syn(capacity, remote, gateway, configure, |_| {})
    }

    fn configured_with_syn(
        capacity: usize,
        remote: Ipv4Address,
        gateway: Option<Ipv4Address>,
        configure: impl FnOnce(&mut Interface, &mut tcp::Socket<'static>),
        configure_syn: impl FnOnce(&mut TcpRepr<'static>),
    ) -> Self {
        let mut device = TestingDevice::new(Medium::Ethernet);
        let mut config = Config::new(LOCAL_MAC.into());
        config.neighbor_capacity = capacity;
        let mut iface = Interface::new(config, &mut device, Instant::ZERO);
        iface.update_ip_addrs(|addrs| addrs.push(IpCidr::new(LOCAL.into(), 24)).unwrap());
        if let Some(gateway) = gateway {
            iface.set_ipv4_gateway(Some(gateway));
        }
        let mut sockets = TcpSet::new(vec![]);
        let mut socket = tcp::Socket::new(
            tcp::RxBuffer::new(4096),
            tcp::SocketBuffer::new(vec![0; 4096]),
        );
        socket.set_ack_delay(None);
        configure(&mut iface, &mut socket);
        let handle = sockets.add(socket);
        let mut peer = Self {
            iface,
            sockets,
            device,
            local: LOCAL,
            local_port: 40000,
            remote,
            remote_port: 80,
            mac: PEER_MAC,
            handle,
            ack: TcpSeqNumber(0),
            frames: Vec::new(),
        };
        peer.arp(0, gateway.unwrap_or(remote), PEER_MAC);
        peer.connect_with_syn(0, configure_syn);
        peer
    }

    fn ingress(&mut self, millis: i64, bytes: Vec<u8>) {
        self.device.rx_queue.push_back(bytes);
        assert_eq!(
            self.iface.poll_ingress_single(
                Instant::from_millis(millis),
                &mut self.device,
                &mut self.sockets
            ),
            PollIngressSingleResult::SocketStateChanged,
        );
        assert!(self.device.rx_queue.is_empty());
        assert!(self.device.tx_queue.is_empty());
    }

    fn arp(&mut self, millis: i64, ip: Ipv4Address, mac: EthernetAddress) {
        let arp = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: mac,
            source_protocol_addr: ip,
            target_hardware_addr: LOCAL_MAC,
            target_protocol_addr: LOCAL,
        };
        let mut bytes = vec![0; EthernetFrame::<&[u8]>::buffer_len(arp.buffer_len())];
        let mut eth = EthernetFrame::new_unchecked(&mut bytes);
        eth.set_src_addr(mac);
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

    fn take_tcp(&mut self, control: TcpControl, payload: &[u8]) -> TcpSeqNumber {
        let bytes = self.device.tx_queue.pop_front().expect("missing TCP frame");
        let eth = EthernetFrame::new_checked(&bytes).unwrap();
        assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);
        assert_eq!(
            (eth.src_addr(), eth.dst_addr()),
            (self.iface.hardware_addr().ethernet_or_panic(), self.mac)
        );
        let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
        assert!(ip.verify_checksum());
        assert_eq!((ip.src_addr(), ip.dst_addr()), (self.local, self.remote));
        let mut caps = ChecksumCapabilities::ignored();
        let packet = TcpPacket::new_checked(ip.payload()).unwrap();
        if self.iface.inner.caps.checksum.tcp.tx() {
            caps.tcp = crate::phy::Checksum::Both;
        } else {
            assert_eq!(packet.checksum(), 0);
        }
        let tcp = TcpRepr::parse(&packet, &self.local.into(), &self.remote.into(), &caps).unwrap();
        assert_eq!(
            (tcp.src_port, tcp.dst_port),
            (self.local_port, self.remote_port)
        );
        assert_eq!((tcp.control, tcp.payload), (control, payload));
        let ack = tcp.seq_number + tcp.segment_len();
        self.frames.push(bytes);
        ack
    }

    fn take_generic_tcp(&mut self, control: TcpControl, payload: &[u8]) -> TcpSeqNumber {
        let ack = self.take_tcp(control, payload);
        assert_generic_frame(&mut self.iface, self.frames.last().unwrap());
        ack
    }

    fn frame(&self, tcp: TcpRepr) -> Vec<u8> {
        tcp_frame_to(
            self.local,
            self.iface.hardware_addr().ethernet_or_panic(),
            self.remote,
            self.mac,
            tcp,
        )
    }

    fn connect(&mut self, millis: i64) {
        self.connect_with_syn(millis, |_| {});
    }

    fn connect_with_syn(&mut self, millis: i64, configure_syn: impl FnOnce(&mut TcpRepr<'static>)) {
        self.sockets
            .get_mut(self.handle)
            .connect(
                self.iface.context(),
                (self.remote, self.remote_port),
                (self.local, self.local_port),
            )
            .unwrap();
        self.egress(millis);
        let ack = self.take_generic_tcp(TcpControl::Syn, &[]);
        if self.sockets.item_at_mut(0).unwrap().meta.next_hop.is_some() {
            assert!(self.sockets.item_at_mut(0).unwrap().meta.tcp_template.is_some());
        }
        assert!(self.device.tx_queue.is_empty());
        let mut syn = self.reply(TcpControl::Syn, ack);
        configure_syn(&mut syn);
        self.ingress(millis, self.frame(syn));
        assert_eq!(
            self.sockets.get(self.handle).state(),
            tcp::State::Established
        );
        self.egress(millis);
        self.ack = self.take_generic_tcp(TcpControl::None, &[]);
        assert!(self.device.tx_queue.is_empty());
    }

    fn send(&mut self, millis: i64) {
        assert_eq!(
            self.sockets
                .get_mut(self.handle)
                .send_slice(&[0x5a])
                .unwrap(),
            1
        );
        self.egress(millis);
    }

    fn acknowledge(&mut self, millis: i64) {
        let mut tcp = self.reply(TcpControl::None, self.ack);
        tcp.seq_number = TcpSeqNumber(101);
        self.ingress(millis, self.frame(tcp));
        assert_eq!(self.sockets.get(self.handle).send_queue(), 0);
    }

    fn reply(&self, control: TcpControl, ack: TcpSeqNumber) -> TcpRepr<'static> {
        let mut tcp = reply(control, ack);
        tcp.src_port = self.remote_port;
        tcp.dst_port = self.local_port;
        tcp
    }

    fn take_arp_request(&mut self, target: Ipv4Address) {
        let bytes = self
            .device
            .tx_queue
            .pop_front()
            .expect("missing ARP request");
        let eth = EthernetFrame::new_checked(&bytes).unwrap();
        assert_eq!(eth.ethertype(), EthernetProtocol::Arp);
        assert_eq!(eth.dst_addr(), EthernetAddress::BROADCAST);
        assert_eq!(
            ArpRepr::parse(&ArpPacket::new_checked(eth.payload()).unwrap()).unwrap(),
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Request,
                source_hardware_addr: LOCAL_MAC,
                source_protocol_addr: LOCAL,
                target_hardware_addr: EthernetAddress::BROADCAST,
                target_protocol_addr: target,
            }
        );
        assert!(self.device.tx_queue.is_empty());
    }

    fn lookups(&self) -> usize {
        self.iface
            .inner
            .neighbor_cache
            .lookup_calls
            .load(Ordering::Relaxed)
    }
}

#[test]
fn established_frames_use_template() {
    let mut peer = Peer::new(2, PEER, None);
    assert_eq!(peer.frames.len(), 2);
    assert_eq!(peer.iface.inner.template_frames, 1);
    let payload = vec![0x5a; 1536];
    assert_eq!(
        peer.sockets
            .get_mut(peer.handle)
            .send_slice(&payload)
            .unwrap(),
        payload.len()
    );
    peer.egress(1);
    for control in [TcpControl::None, TcpControl::None, TcpControl::Psh] {
        peer.ack = peer.take_tcp(control, &payload[..512]);
    }
    assert!(peer.device.tx_queue.is_empty());
    assert_eq!(peer.iface.inner.template_frames, peer.frames.len() - 1);
    peer.acknowledge(2);
    peer.egress(2);
    assert!(peer.device.tx_queue.is_empty());
    assert_eq!(peer.iface.inner.template_frames, 4);
    for frame in &peer.frames {
        assert_generic_frame(&mut peer.iface, frame);
    }
}

#[test]
fn passive_handshake_seeds_template_for_first_data() {
    let mut peer = Peer::new(2, PEER, None);
    peer.sockets.get_mut(peer.handle).abort();
    peer.egress(1);
    peer.take_generic_tcp(TcpControl::Rst, &[]);
    peer.sockets.get_mut(peer.handle).listen((LOCAL, 40000)).unwrap();
    peer.sockets.item_at_mut(0).unwrap().meta.tcp_template = None;
    let mut syn = peer.reply(TcpControl::Syn, TcpSeqNumber(0));
    syn.ack_number = None;
    peer.ingress(2, peer.frame(syn));
    let before = peer.iface.inner.template_frames;
    peer.egress(2);
    let ack = peer.take_generic_tcp(TcpControl::Syn, &[]);
    assert_eq!(peer.iface.inner.template_frames, before);
    assert!(peer.sockets.item_at_mut(0).unwrap().meta.tcp_template.is_some());
    let mut ack = peer.reply(TcpControl::None, ack);
    ack.seq_number = TcpSeqNumber(101);
    ack.max_seg_size = None;
    peer.ingress(3, peer.frame(ack));
    assert_eq!(peer.sockets.get(peer.handle).state(), tcp::State::Established);
    peer.send(3);
    peer.take_generic_tcp(TcpControl::Psh, &[0x5a]);
    assert_eq!(peer.iface.inner.template_frames, before + 1);
    assert!(peer.device.tx_queue.is_empty());
}

#[test]
fn challenge_ack_uses_template_and_unknown_flow_reset_stays_generic() {
    let mut peer = Peer::new(2, PEER, None);
    let before = peer.iface.inner.template_frames;
    let mut syn = peer.reply(TcpControl::Syn, TcpSeqNumber(0));
    syn.ack_number = None;
    peer.device.rx_queue.push_back(peer.frame(syn));
    peer.iface.poll_ingress_single(
        Instant::from_millis(1), &mut peer.device, &mut peer.sockets,
    );
    peer.take_generic_tcp(TcpControl::None, &[]);
    assert_eq!(peer.iface.inner.template_frames, before + 1);
    assert_eq!(peer.sockets.get(peer.handle).state(), tcp::State::Established);
    assert!(peer.sockets.pending_rx_attach.is_none());
    assert!(peer.device.tx_queue.is_empty());
    syn.dst_port = 40001;
    peer.device.rx_queue.push_back(peer.frame(syn));
    peer.iface.poll_ingress_single(
        Instant::from_millis(2), &mut peer.device, &mut peer.sockets,
    );
    let bytes = peer.device.tx_queue.pop_front().unwrap();
    assert_generic_frame(&mut peer.iface, &bytes);
    let ip = Ipv4Packet::new_checked(&bytes[14..]).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(tcp.rst() && tcp.ack());
    assert_eq!(tcp.src_port(), 40001);
    assert_eq!(peer.iface.inner.template_frames, before + 1);
    assert!(peer.device.tx_queue.is_empty());
}

#[test]
fn ingress_reply_rebuilds_template_in_winning_slot() {
    let mut peer = Peer::new(2, PEER, None);
    let (socket, _) = peer.sockets.take(peer.handle);
    let unrelated = peer.sockets.add(tcp::Socket::new(
        tcp::RxBuffer::new(64), tcp::SocketBuffer::new(vec![0; 64]),
    ));
    peer.sockets.get_mut(unrelated).listen(40001).unwrap();
    peer.handle = peer.sockets.add(socket);
    assert!(peer.sockets.item_at_mut(1).unwrap().meta.tcp_template.is_none());
    let before = peer.iface.inner.template_frames;
    let mut syn = peer.reply(TcpControl::Syn, TcpSeqNumber(0));
    syn.ack_number = None;
    peer.device.rx_queue.push_back(peer.frame(syn));
    peer.iface.poll_ingress_single(
        Instant::from_millis(1), &mut peer.device, &mut peer.sockets,
    );
    peer.take_generic_tcp(TcpControl::None, &[]);
    assert_eq!(peer.iface.inner.template_frames, before + 1);
    assert!(peer.sockets.item_at_mut(1).unwrap().meta.tcp_template.is_some());
    assert!(peer.sockets.item_at_mut(0).unwrap().meta.tcp_template.is_none());
    assert!(peer.sockets.pending_tcp_reply.is_none());
    assert!(peer.device.tx_queue.is_empty());
    peer.send(2);
    peer.take_generic_tcp(TcpControl::Psh, &[0x5a]);
    assert_eq!(peer.iface.inner.template_frames, before + 2);
}

/// The gateway's entry expires at 60 s and no egress pass ran since. An
/// out-of-order segment from the routed peer gets an immediate ACK from the
/// socket. First use starts the 3 s stale window: the ACK uses the old gateway
/// MAC and egress sends its ARP probe. After that window, only ARP goes out.
#[test]
fn ingress_reply_after_gateway_expiry_sends_arp() {
    let remote = Ipv4Address::new(198, 51, 100, 2);
    for (millis, ack_sent) in [(61_000, true), (64_000, false), (70_000, true)] {
        let mut peer = Peer::new(2, remote, Some(PEER));
        if !ack_sent {
            assert_eq!(
                peer.iface
                    .inner
                    .neighbor_cache
                    .lookup(&PEER.into(), Instant::from_millis(61_000)),
                NeighborAnswer::Stale {
                    hardware_addr: PEER_MAC.into(),
                    probe: true,
                }
            );
        }
        let mut tcp = peer.reply(TcpControl::None, peer.ack);
        tcp.seq_number = TcpSeqNumber(111);
        tcp.max_seg_size = None;
        tcp.payload = &[0x5a; 4];
        peer.device.rx_queue.push_back(peer.frame(tcp));
        peer.iface.poll_ingress_single(
            Instant::from_millis(millis), &mut peer.device, &mut peer.sockets,
        );
        if ack_sent {
            peer.take_tcp(TcpControl::None, &[]);
            assert!(peer.device.tx_queue.is_empty());
            peer.egress(millis);
        }
        peer.take_arp_request(PEER);
    }
}

#[test]
fn kept_mac_skips_lookup_for_several_segments() {
    let mut peer = Peer::new(2, PEER, None);
    let lookups = peer.lookups();
    assert!(lookups > 0);
    let payload = vec![0x5a; 1536];
    assert_eq!(
        peer.sockets
            .get_mut(peer.handle)
            .send_slice(&payload)
            .unwrap(),
        payload.len()
    );
    peer.egress(1);
    for _ in 0..2 {
        peer.take_tcp(TcpControl::None, &payload[..512]);
    }
    peer.take_tcp(TcpControl::Psh, &payload[..512]);
    assert!(peer.device.tx_queue.is_empty());
    assert_eq!(peer.lookups(), lookups);
}

#[test]
fn arp_mac_change_updates_next_segment() {
    let mut peer = Peer::new(2, PEER, None);
    peer.send(1);
    peer.ack = peer.take_tcp(TcpControl::Psh, &[0x5a]);
    peer.acknowledge(2);
    peer.arp(3, PEER, NEW_MAC);
    peer.mac = NEW_MAC;
    peer.send(3);
    peer.take_tcp(TcpControl::Psh, &[0x5a]);
    assert!(peer.device.tx_queue.is_empty());
}

#[test]
fn expired_entry_sends_arp() {
    let mut peer = Peer::new(2, PEER, None);
    peer.send(60_001);
    peer.take_tcp(TcpControl::Psh, &[0x5a]);
    peer.take_arp_request(PEER);
    peer.egress(63_001);
    peer.take_arp_request(PEER);
}

#[test]
fn received_packet_refreshes_entry_past_original_expiry() {
    let mut peer = Peer::new(2, PEER, None);
    peer.acknowledge(10_000);
    let lookups = peer.lookups();
    peer.send(60_000);
    peer.take_tcp(TcpControl::Psh, &[0x5a]);
    assert!(peer.device.tx_queue.is_empty());
    assert!(peer.lookups() <= lookups + 1);
}

#[test]
fn revived_entry_expires_again() {
    let mut peer = Peer::new(2, PEER, None);
    peer.egress(60_000);
    assert!(peer.device.tx_queue.is_empty());
    peer.acknowledge(61_000);
    peer.send(61_000);
    peer.take_tcp(TcpControl::Psh, &[0x5a]);
    assert!(peer.device.tx_queue.is_empty());
    peer.send(121_000);
    peer.take_tcp(TcpControl::Psh, &[0x5a; 2]);
    peer.take_arp_request(PEER);
    peer.egress(124_000);
    peer.take_arp_request(PEER);
}

#[test]
fn evicted_entry_sends_arp() {
    let mut peer = Peer::new(1, PEER, None);
    peer.arp(1, Ipv4Address::new(192, 168, 1, 3), NEW_MAC);
    peer.send(1);
    peer.take_arp_request(PEER);
}

#[test]
fn unchanged_ip_addresses_flush_entry() {
    let mut peer = Peer::new(2, PEER, None);
    peer.iface.update_ip_addrs(|_| {});
    peer.send(1);
    peer.take_arp_request(PEER);
}

#[test]
fn route_change_uses_second_gateway() {
    let remote = Ipv4Address::new(198, 51, 100, 2);
    let gateway2 = Ipv4Address::new(192, 168, 1, 3);
    let mut peer = Peer::new(2, remote, Some(PEER));
    peer.arp(1, gateway2, NEW_MAC);
    peer.send(1);
    peer.ack = peer.take_tcp(TcpControl::Psh, &[0x5a]);
    peer.acknowledge(2);
    peer.iface.set_ipv4_gateway(Some(gateway2));
    peer.mac = NEW_MAC;
    peer.send(2);
    peer.take_tcp(TcpControl::Psh, &[0x5a]);
    assert!(peer.device.tx_queue.is_empty());
}

#[test]
fn reconnect_same_slot_uses_new_peer() {
    let mut peer = Peer::new(2, PEER, None);
    let remote2 = Ipv4Address::new(192, 168, 1, 3);
    peer.arp(1, remote2, NEW_MAC);
    peer.send(1);
    peer.take_tcp(TcpControl::Psh, &[0x5a]);
    peer.sockets.get_mut(peer.handle).abort();
    peer.remote = remote2;
    peer.mac = NEW_MAC;
    peer.connect(2);
}

#[test]
fn aborted_reconnect_uses_cached_peer_mac() {
    let mut peer = Peer::new(2, PEER, None);
    let remote2 = Ipv4Address::new(192, 168, 1, 3);
    peer.arp(1, remote2, NEW_MAC);
    peer.sockets.get_mut(peer.handle).abort();
    peer.egress(1);
    peer.take_tcp(TcpControl::Rst, &[]);
    assert!(peer.device.tx_queue.is_empty());
    assert_eq!(peer.sockets.get(peer.handle).state(), tcp::State::Closed);
    assert!(peer.sockets.get(peer.handle).remote_endpoint().is_none());

    peer.remote = remote2;
    peer.mac = NEW_MAC;
    peer.sockets
        .get_mut(peer.handle)
        .connect(peer.iface.context(), (remote2, 80), (LOCAL, 40000))
        .unwrap();
    peer.sockets.get_mut(peer.handle).abort();
    peer.egress(2);
    peer.take_tcp(TcpControl::Rst, &[]);
    assert!(peer.device.tx_queue.is_empty());
}

#[test]
fn aborted_reconnect_discovers_unknown_peer() {
    let mut peer = Peer::new(2, PEER, None);
    let remote2 = Ipv4Address::new(192, 168, 1, 3);
    peer.sockets.get_mut(peer.handle).abort();
    peer.egress(1);
    peer.take_tcp(TcpControl::Rst, &[]);
    assert!(peer.device.tx_queue.is_empty());
    assert_eq!(peer.sockets.get(peer.handle).state(), tcp::State::Closed);
    assert!(peer.sockets.get(peer.handle).remote_endpoint().is_none());

    peer.sockets
        .get_mut(peer.handle)
        .connect(peer.iface.context(), (remote2, 80), (LOCAL, 40000))
        .unwrap();
    peer.sockets.get_mut(peer.handle).abort();
    peer.egress(2);
    peer.take_arp_request(remote2);
}

#[test]
fn removed_slot_uses_new_peer() {
    let mut peer = Peer::new(2, PEER, None);
    let remote2 = Ipv4Address::new(192, 168, 1, 3);
    peer.arp(1, remote2, NEW_MAC);
    peer.send(1);
    peer.take_tcp(TcpControl::Psh, &[0x5a]);
    let (mut socket, _) = peer.sockets.take(peer.handle);
    socket.abort();
    peer.handle = peer.sockets.add(socket);
    peer.remote = remote2;
    peer.mac = NEW_MAC;
    peer.connect(2);
}

mod invalidation {
    use super::*;

    impl Peer {
        fn warm(&mut self) {
            self.data(1, true);
            assert!(self.iface.inner.template_frames > 0);
        }

        fn data(&mut self, millis: i64, templated: bool) {
            let before = self.iface.inner.template_frames;
            self.send(millis);
            self.check_data(millis);
            assert_eq!(
                self.iface.inner.template_frames,
                before + usize::from(templated)
            );
        }

        fn check_data(&mut self, millis: i64) {
            self.ack = self.take_generic_tcp(TcpControl::Psh, &[0x5a]);
            assert!(self.device.tx_queue.is_empty());
            self.acknowledge(millis);
        }

        fn recover(&mut self, millis: i64) {
            let before = self.iface.inner.template_frames;
            self.arp(millis, self.remote, self.mac);
            self.egress(millis);
            self.check_data(millis);
            assert_eq!(self.iface.inner.template_frames, before + 1);
            self.data(millis + 1, true);
        }

        fn assert_window(&self, window: u16) {
            let frame = self.frames.last().unwrap();
            let ip = Ipv4Packet::new_checked(&frame[14..]).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            assert_eq!(tcp.window_len(), window);
        }

        fn assert_layout(&self, hop_limit: u8, header_len: u8) {
            let frame = self.frames.last().unwrap();
            let ip = Ipv4Packet::new_checked(&frame[14..]).unwrap();
            assert_eq!(ip.hop_limit(), hop_limit);
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            assert_eq!(tcp.header_len(), header_len);
        }
    }

    #[test]
    fn template_follows_arp_mac_change() {
        let mut peer = Peer::new(2, PEER, None);
        peer.warm();
        peer.arp(2, PEER, NEW_MAC);
        peer.mac = NEW_MAC;
        peer.data(2, true);
        peer.data(3, true);
    }

    #[test]
    fn template_dropped_on_neighbor_expiry() {
        let mut peer = Peer::new(2, PEER, None);
        peer.warm();
        let before = peer.iface.inner.template_frames;
        peer.send(60_002);
        peer.take_generic_tcp(TcpControl::Psh, &[0x5a]);
        peer.take_arp_request(PEER);
        assert_eq!(peer.iface.inner.template_frames, before + 1);
        peer.egress(63_002);
        peer.take_arp_request(PEER);
        assert_eq!(peer.iface.inner.template_frames, before + 1);
        peer.recover(63_003);
    }

    #[test]
    fn template_dropped_on_eviction() {
        let mut peer = Peer::new(1, PEER, None);
        peer.warm();
        let before = peer.iface.inner.template_frames;
        peer.arp(2, Ipv4Address::new(192, 168, 1, 3), NEW_MAC);
        peer.send(2);
        peer.take_arp_request(PEER);
        assert_eq!(peer.iface.inner.template_frames, before);
        peer.recover(3);
    }

    #[test]
    fn template_dropped_on_flush() {
        let mut peer = Peer::new(2, PEER, None);
        peer.warm();
        let before = peer.iface.inner.template_frames;
        peer.iface.update_ip_addrs(|_| {});
        peer.send(2);
        peer.take_arp_request(PEER);
        assert_eq!(peer.iface.inner.template_frames, before);
        peer.recover(3);
    }

    #[test]
    fn template_follows_route_change() {
        let remote = Ipv4Address::new(198, 51, 100, 2);
        let gateway2 = Ipv4Address::new(192, 168, 1, 3);
        let mut peer = Peer::configured(2, remote, Some(PEER), |iface, _| {
            iface
                .inner
                .neighbor_cache
                .fill(gateway2.into(), NEW_MAC.into(), Instant::ZERO);
        });
        peer.warm();
        peer.iface.set_ipv4_gateway(Some(gateway2));
        peer.mac = NEW_MAC;
        peer.data(2, true);
        peer.data(3, true);
    }

    #[test]
    fn template_follows_hardware_addr_change() {
        let mut peer = Peer::new(2, PEER, None);
        peer.warm();
        let changes = peer.iface.inner.neighbor_cache.changes();
        peer.iface.set_hardware_addr(NEW_MAC.into());
        assert_eq!(peer.iface.inner.neighbor_cache.changes(), changes);
        peer.data(2, true);
        let frame = EthernetFrame::new_checked(peer.frames.last().unwrap()).unwrap();
        assert_eq!(frame.src_addr(), NEW_MAC);
        peer.data(3, true);
    }

    #[test]
    fn template_follows_hop_limit_change() {
        let mut peer = Peer::new(2, PEER, None);
        peer.warm();
        peer.sockets.get_mut(peer.handle).set_hop_limit(Some(7));
        peer.data(2, true);
        peer.assert_layout(7, 20);
        peer.data(3, true);
        peer.assert_layout(7, 20);
        peer.sockets.get_mut(peer.handle).set_hop_limit(None);
        peer.data(4, true);
        peer.assert_layout(64, 20);
        peer.data(5, true);
        peer.assert_layout(64, 20);
    }

    #[test]
    fn unrelated_neighbor_fill_revalidates() {
        let mut peer = Peer::new(2, PEER, None);
        peer.warm();
        let changes = peer.iface.inner.neighbor_cache.changes();
        peer.arp(2, Ipv4Address::new(192, 168, 1, 3), NEW_MAC);
        assert!(peer.iface.inner.neighbor_cache.changes() > changes);
        peer.data(2, true);
        peer.data(3, true);
    }

    #[test]
    fn sack_ack_uses_template() {
        let mut peer = Peer::configured_with_syn(2, PEER, None, |_, _| {}, |syn| {
            syn.sack_permitted = true;
        });
        peer.warm();
        peer.assert_layout(64, 20);
        let before = peer.iface.inner.template_frames;
        let mut data = peer.reply(TcpControl::None, peer.ack);
        data.seq_number = TcpSeqNumber(102);
        data.max_seg_size = None;
        data.payload = b"x";
        peer.device.rx_queue.push_back(peer.frame(data));
        assert_eq!(
            peer.iface.poll_ingress_single(
                Instant::from_millis(2),
                &mut peer.device,
                &mut peer.sockets,
            ),
            PollIngressSingleResult::SocketStateChanged,
        );
        peer.take_generic_tcp(TcpControl::None, &[]);
        assert!(peer.device.rx_queue.is_empty());
        assert!(peer.device.tx_queue.is_empty());
        assert_eq!(peer.iface.inner.template_frames, before + 1);
        peer.assert_layout(64, 32);
        let frame = peer.frames.last().unwrap();
        let ip = Ipv4Packet::new_checked(&frame[14..]).unwrap();
        let tcp = TcpRepr::parse(
            &TcpPacket::new_checked(ip.payload()).unwrap(),
            &peer.local.into(),
            &peer.remote.into(),
            &ChecksumCapabilities::default(),
        )
        .unwrap();
        assert_eq!(tcp.ack_number, Some(TcpSeqNumber(101)));
        assert_eq!(tcp.sack_ranges, [Some((102, 103)), None, None]);
        assert_eq!(tcp.timestamp, None);
        peer.data(3, true);
        peer.assert_layout(64, 20);
    }

    #[test]
    fn reconnect_same_slot_new_peer_rebuilds_template() {
        for (remote, port) in [
            (Ipv4Address::new(192, 168, 1, 3), 80),
            (PEER, 81),
            (Ipv4Address::new(192, 168, 1, 3), 81),
        ] {
            let mut peer = Peer::new(2, PEER, None);
            peer.arp(0, remote, PEER_MAC);
            peer.data(0, true);
            peer.warm();
            let before = peer.iface.inner.template_frames;
            peer.sockets.get_mut(peer.handle).abort();
            peer.remote = remote;
            peer.remote_port = port;
            peer.connect(2);
            assert_eq!(peer.iface.inner.template_frames, before + 1);
            peer.data(3, true);
        }
    }

    #[test]
    fn reconnect_same_slot_new_source_rebuilds_template() {
        let local = Ipv4Address::new(192, 168, 1, 4);
        let mut peer = Peer::configured(2, PEER, None, |iface, _| {
            iface.update_ip_addrs(|addrs| {
                addrs.push(IpCidr::new(local.into(), 24)).unwrap();
            });
        });
        peer.warm();
        let before = peer.iface.inner.template_frames;
        peer.sockets.get_mut(peer.handle).abort();
        peer.local = local;
        peer.connect(2);
        assert_eq!(peer.iface.inner.template_frames, before + 1);
        peer.data(3, true);
    }

    #[test]
    fn reconnect_same_slot_new_local_port_rebuilds_template() {
        let mut peer = Peer::new(2, PEER, None);
        peer.warm();
        let before = peer.iface.inner.template_frames;
        peer.sockets.get_mut(peer.handle).abort();
        peer.local_port = 40001;
        peer.connect(2);
        assert_eq!(peer.iface.inner.template_frames, before + 1);
        peer.data(3, true);
    }

    #[test]
    fn abort_reconnect_same_tuple_matches_generic() {
        let mut peer = Peer::new(2, PEER, None);
        peer.warm();
        let before = peer.iface.inner.template_frames;
        peer.sockets.get_mut(peer.handle).abort();
        peer.connect(2);
        assert_eq!(peer.iface.inner.template_frames, before + 1);
        peer.data(3, true);
        let before = peer.iface.inner.template_frames;
        peer.sockets.get_mut(peer.handle).abort();
        peer.egress(4);
        peer.take_generic_tcp(TcpControl::Rst, &[]);
        assert!(peer.device.tx_queue.is_empty());
        assert_eq!(peer.iface.inner.template_frames, before + 1);
        assert_eq!(peer.sockets.get(peer.handle).state(), tcp::State::Closed);
    }

    #[test]
    fn relisten_renegotiates_options() {
        let mut peer = Peer::configured(2, PEER, None, |_, socket| {
            *socket = tcp::Socket::new(
                tcp::RxBuffer::new(131072),
                tcp::SocketBuffer::new(vec![0; 4096]),
            );
            socket.set_ack_delay(None);
        });
        peer.warm();
        peer.assert_layout(64, 20);
        let before = peer.iface.inner.template_frames;
        peer.sockets.get_mut(peer.handle).abort();
        peer.egress(2);
        peer.take_generic_tcp(TcpControl::Rst, &[]);
        assert_eq!(peer.iface.inner.template_frames, before + 1);
        peer.sockets
            .get_mut(peer.handle)
            .listen((LOCAL, 40000))
            .unwrap();
        let mut syn = reply(TcpControl::Syn, TcpSeqNumber(0));
        syn.ack_number = None;
        syn.window_scale = Some(7);
        syn.max_seg_size = Some(256);
        peer.ingress(3, peer.frame(syn));
        let before = peer.iface.inner.template_frames;
        peer.egress(3);
        let ack = peer.take_generic_tcp(TcpControl::Syn, &[]);
        assert_eq!(peer.iface.inner.template_frames, before);
        let frame = peer.frames.last().unwrap();
        let ip = Ipv4Packet::new_checked(&frame[14..]).unwrap();
        let tcp = TcpRepr::parse(
            &TcpPacket::new_checked(ip.payload()).unwrap(),
            &LOCAL.into(),
            &PEER.into(),
            &ChecksumCapabilities::default(),
        )
        .unwrap();
        assert_eq!(tcp.timestamp, None);
        assert_eq!(tcp.window_scale, Some(2));
        assert_eq!(tcp.window_len, 23040); // 90 frames x 256 B peer MSS.
        let mut ack = reply(TcpControl::None, ack);
        ack.seq_number = TcpSeqNumber(101);
        ack.max_seg_size = None;
        peer.ingress(4, peer.frame(ack));
        assert_eq!(
            peer.sockets.get(peer.handle).state(),
            tcp::State::Established
        );
        peer.data(4, true);
        peer.assert_layout(64, 20);
        peer.assert_window(5760); // 90 frames x 256 B, scaled by 4.
        peer.data(5, true);
        peer.assert_window(5760); // No received bytes; the same 23040 B window.
        let mut tcp = peer.reply(TcpControl::None, peer.ack);
        tcp.seq_number = TcpSeqNumber(101);
        tcp.max_seg_size = None;
        tcp.payload = b"x";
        peer.ingress(6, peer.frame(tcp));
        let before = peer.iface.inner.template_frames;
        peer.egress(6);
        peer.take_generic_tcp(TcpControl::None, &[]);
        assert!(peer.device.tx_queue.is_empty());
        assert_eq!(peer.iface.inner.template_frames, before + 1);
        peer.assert_layout(64, 20);
        peer.assert_window(5760); // Preserve 23039 B after 1 B received, rounded up / 4.
    }

    #[test]
    fn removed_slot_starts_without_template() {
        let mut peer = Peer::new(2, PEER, None);
        peer.warm();
        let before = peer.iface.inner.template_frames;
        let handle = peer.handle;
        let (mut socket, _) = peer.sockets.take(handle);
        socket.abort();
        peer.handle = peer.sockets.add(socket);
        assert_ne!(peer.handle, handle);
        assert_eq!(peer.sockets.iter().next().unwrap().0, peer.handle);
        let meta = &peer.sockets.item_at_mut(0).unwrap().meta;
        assert!(meta.tcp_template.is_none());
        peer.connect(2);
        assert_eq!(peer.iface.inner.template_frames, before + 1);
        peer.data(3, true);
    }

    #[test]
    fn oversize_frame_drops_without_emitting() {
        let mut peer = Peer::new(2, PEER, None);
        peer.warm();
        let before = peer.iface.inner.template_frames;
        let frame = peer.frames.last().unwrap();
        let eth = EthernetFrame::new_checked(frame).unwrap();
        let ip_packet = Ipv4Packet::new_checked(eth.payload()).unwrap();
        let caps = ChecksumCapabilities::default();
        let ip = Ipv4Repr::parse(&ip_packet, &caps).unwrap();
        let tcp = TcpRepr::parse(
            &TcpPacket::new_checked(ip_packet.payload()).unwrap(),
            &ip.src_addr.into(),
            &ip.dst_addr.into(),
            &caps,
        )
        .unwrap();
        let mtu = peer.iface.inner.caps.max_transmission_unit;
        assert!(crate::iface::header_template::TcpTemplate::is_eligible(
            &tcp
        ));
        peer.iface.inner.caps.max_transmission_unit = 14 + 40;
        assert!(ip.buffer_len() + tcp.buffer_len() > peer.iface.inner.caps.ip_mtu());
        let meta = &mut peer.sockets.item_at_mut(0).unwrap().meta;
        assert!(meta.tcp_template.is_some());
        peer.iface
            .inner
            .dispatch_tcp(
                peer.device.transmit(Instant::from_millis(2)).unwrap(),
                PacketMeta::default(),
                IpRepr::Ipv4(ip),
                tcp,
                &mut meta.next_hop,
                &mut meta.tcp_template,
            )
            .unwrap();
        assert!(peer.device.tx_queue.is_empty());
        assert_eq!(peer.iface.inner.template_frames, before);
        assert_eq!(
            peer.sockets.get(peer.handle).state(),
            tcp::State::Established
        );
        peer.iface.inner.caps.max_transmission_unit = mtu;
        peer.data(3, true);
        assert_eq!(peer.iface.inner.template_frames, before + 1);
        assert!(peer.device.tx_queue.is_empty());
    }

    #[test]
    fn source_address_removal_closes_silently_when_data_is_queued() {
        let mut peer = Peer::new(2, PEER, None);
        peer.warm();
        let before = peer.iface.inner.template_frames;
        peer.iface.update_ip_addrs(|addrs| addrs.clear());
        peer.sockets.dispatches.clear();
        peer.egress(2);
        assert_eq!(peer.sockets.get(peer.handle).state(), tcp::State::Established);
        assert!(peer.sockets.dispatches.is_empty());
        assert!(peer.device.tx_queue.is_empty());
        peer.sockets.get_mut(peer.handle).send_slice(b"x").unwrap();
        peer.egress(3);
        assert_eq!(peer.sockets.dispatches, vec![0]);
        assert_eq!(peer.sockets.get(peer.handle).state(), tcp::State::Closed);
        assert!(peer.sockets.get(peer.handle).remote_endpoint().is_none());
        assert!(peer.device.tx_queue.is_empty());
        assert_eq!(peer.iface.inner.template_frames, before);
    }

    #[test]
    fn burst_cap_templates_preserve_window() {
        let mut peer = Peer::configured(2, PEER, None, |iface, _| {
            iface.inner.caps.max_burst_size = Some(1);
        });
        for millis in [1, 2, 3] {
            peer.data(millis, true);
            let frame = peer.frames.last().unwrap();
            let ip = Ipv4Packet::new_checked(&frame[14..]).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            assert_eq!(tcp.window_len(), 1474);
        }
        assert_eq!(peer.iface.inner.template_frames, 4);
    }

    mod producers {
        use super::*;

        impl Peer {
            fn expect_frame(
                &mut self,
                control: TcpControl,
                seq: TcpSeqNumber,
                ack: TcpSeqNumber,
                payload: &[u8],
            ) {
                let bytes = self.device.tx_queue.pop_front().expect("missing TCP frame");
                assert_generic_frame(&mut self.iface, &bytes);
                let eth = EthernetFrame::new_checked(&bytes).unwrap();
                assert_eq!(
                    (eth.src_addr(), eth.dst_addr()),
                    (self.iface.hardware_addr().ethernet_or_panic(), self.mac)
                );
                let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
                assert_eq!((ip.src_addr(), ip.dst_addr()), (self.local, self.remote));
                let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
                assert_eq!(
                    (tcp.src_port(), tcp.dst_port()),
                    (self.local_port, self.remote_port)
                );
                assert_eq!(tcp.seq_number(), seq);
                assert_eq!(tcp.ack_number(), ack);
                assert!(tcp.ack());
                assert!(!tcp.syn());
                assert_eq!(tcp.fin(), control == TcpControl::Fin);
                assert_eq!(tcp.rst(), control == TcpControl::Rst);
                assert_eq!(tcp.psh(), control == TcpControl::Psh);
                assert!(!tcp.urg());
                assert_eq!(tcp.urgent_at(), 0);
                assert!(!tcp.ece());
                assert!(!tcp.cwr());
                assert!(!tcp.ns());
                assert_eq!(tcp.payload(), payload);
                self.frames.push(bytes);
            }

            fn expect_template_frames(&self, before: usize, count: usize) {
                assert!(self.device.tx_queue.is_empty());
                assert_eq!(
                    self.iface.inner.template_frames,
                    before.checked_add(count).expect("TCP frame count overflow")
                );
            }
        }

        #[test]
        fn rto_retransmission_uses_template() {
            let mut peer = Peer::new(2, PEER, None);
            peer.warm();
            let seq = peer.ack;
            let before = peer.iface.inner.template_frames;
            peer.send(2);
            peer.expect_frame(TcpControl::Psh, seq, TcpSeqNumber(101), &[0x5a]);
            peer.expect_template_frames(before, 1);
            for millis in (3..302).step_by(100).chain([301]) {
                peer.egress(millis);
                peer.expect_template_frames(before, 1);
            }
            for millis in 302..=402 {
                peer.egress(millis);
                if !peer.device.tx_queue.is_empty() {
                    break;
                }
                peer.expect_template_frames(before, 1);
            }
            peer.expect_frame(TcpControl::Psh, seq, TcpSeqNumber(101), &[0x5a]);
            peer.expect_template_frames(before, 2);
            assert_eq!(peer.sockets.get(peer.handle).send_queue(), 1);
        }

        #[test]
        fn fast_retransmission_uses_template() {
            let mut peer = Peer::new(2, PEER, None);
            peer.warm();
            let seq = peer.ack;
            let before = peer.iface.inner.template_frames;
            peer.send(2);
            peer.expect_frame(TcpControl::Psh, seq, TcpSeqNumber(101), &[0x5a]);
            peer.expect_template_frames(before, 1);
            for millis in 3..=5 {
                let mut ack = peer.reply(TcpControl::None, seq);
                ack.seq_number = TcpSeqNumber(101);
                ack.max_seg_size = None;
                peer.ingress(millis, peer.frame(ack));
                peer.egress(millis);
                if millis < 5 {
                    peer.expect_template_frames(before, 1);
                }
            }
            peer.expect_frame(TcpControl::Psh, seq, TcpSeqNumber(101), &[0x5a]);
            peer.expect_template_frames(before, 2);
            assert_eq!(peer.sockets.get(peer.handle).send_queue(), 1);
        }

        #[test]
        fn probe_response_preserves_template() {
            let mut peer = Peer::new(2, PEER, None);
            peer.warm();
            let seq = peer.ack;
            let before = peer.iface.inner.template_frames;
            for (index, payload) in [&b""[..], &b"\x00"[..]].into_iter().enumerate() {
                let mut probe = peer.reply(TcpControl::None, seq);
                probe.seq_number = TcpSeqNumber(100);
                probe.max_seg_size = None;
                probe.payload = payload;
                peer.device.rx_queue.push_back(peer.frame(probe));
                assert_eq!(peer.iface.poll_ingress_single(
                    Instant::from_millis(2 + index as i64), &mut peer.device, &mut peer.sockets
                ), PollIngressSingleResult::SocketStateChanged);
                assert!(peer.device.rx_queue.is_empty());
                peer.egress(2 + index as i64);
                peer.expect_frame(TcpControl::None, seq, TcpSeqNumber(101), &[]);
                peer.expect_template_frames(before, index + 1);
                assert_eq!(peer.sockets.get(peer.handle).recv_queue(), 0);
            }
            assert_eq!(peer.sockets.get(peer.handle).send_queue(), 0);
            peer.data(4, true);
            peer.expect_template_frames(before, 3);
        }

        #[test]
        fn zero_window_probe_uses_template() {
            let mut peer = Peer::new(2, PEER, None);
            peer.warm();
            let seq = peer.ack;
            let before = peer.iface.inner.template_frames;
            let mut ack = peer.reply(TcpControl::None, seq);
            ack.seq_number = TcpSeqNumber(101);
            ack.max_seg_size = None;
            ack.window_len = 0;
            peer.ingress(2, peer.frame(ack));
            assert_eq!(peer.sockets.get_mut(peer.handle).send_slice(b"abc"), Ok(3));
            for millis in (2..302).step_by(100).chain([301]) {
                peer.egress(millis);
                peer.expect_template_frames(before, 0);
            }
            for millis in 302..=402 {
                peer.egress(millis);
                if !peer.device.tx_queue.is_empty() {
                    break;
                }
                peer.expect_template_frames(before, 0);
            }
            peer.expect_frame(TcpControl::None, seq, TcpSeqNumber(101), b"a");
            peer.expect_template_frames(before, 1);
            assert_eq!(peer.sockets.get(peer.handle).send_queue(), 3);
        }

        #[test]
        fn window_update_uses_template() {
            let mut peer = Peer::new(2, PEER, None);
            peer.warm();
            let seq = peer.ack;
            let before = peer.iface.inner.template_frames;
            let payload = [0x35; 1024];
            for n in 0..4 {
                let mut data = peer.reply(TcpControl::Psh, seq);
                data.seq_number = TcpSeqNumber(101) + n * payload.len();
                data.max_seg_size = None;
                data.payload = &payload;
                peer.ingress(2, peer.frame(data));
                peer.egress(2);
                peer.expect_frame(TcpControl::None, seq, data.seq_number + payload.len(), &[]);
                // Each free frame allows 512 bytes.
                peer.assert_window(
                    u16::try_from(4096usize.min((5 - n) * 512))
                        .unwrap(),
                );
                peer.expect_template_frames(before, n + 1);
            }
            assert_eq!(peer.sockets.get(peer.handle).recv_queue(), 4096);
            let mut received = Vec::new();
            while let Some(frame) = peer.sockets.get_mut(peer.handle).recv().unwrap() {
                received.extend_from_slice(frame.payload());
            }
            assert_eq!(received.len(), 4096);
            assert_eq!(received, [0x35; 4096]);
            peer.egress(3);
            peer.expect_frame(TcpControl::None, seq, TcpSeqNumber(4197), &[]);
            peer.assert_window(3072); // All 6 frames free x 512 B peer MSS.
            peer.expect_template_frames(before, 5);
            assert_eq!(peer.sockets.get(peer.handle).recv_queue(), 0);
        }

        #[test]
        fn fin_and_time_wait_ack_use_template() {
            let mut peer = Peer::new(2, PEER, None);
            peer.warm();
            let seq = peer.ack;
            let before = peer.iface.inner.template_frames;
            peer.sockets.get_mut(peer.handle).close();
            peer.egress(2);
            peer.expect_frame(TcpControl::Fin, seq, TcpSeqNumber(101), &[]);
            peer.expect_template_frames(before, 1);
            assert_eq!(peer.sockets.get(peer.handle).state(), tcp::State::FinWait1);
            let mut fin = peer.reply(TcpControl::Fin, seq + 1);
            fin.seq_number = TcpSeqNumber(101);
            fin.max_seg_size = None;
            peer.ingress(3, peer.frame(fin));
            assert_eq!(peer.sockets.get(peer.handle).state(), tcp::State::TimeWait);
            peer.egress(3);
            peer.expect_frame(TcpControl::None, seq + 1, TcpSeqNumber(102), &[]);
            peer.expect_template_frames(before, 2);
            assert_eq!(peer.sockets.get(peer.handle).state(), tcp::State::TimeWait);
        }

        #[test]
        fn abort_rst_uses_template() {
            let mut peer = Peer::new(2, PEER, None);
            peer.warm();
            let seq = peer.ack;
            let before = peer.iface.inner.template_frames;
            peer.sockets.get_mut(peer.handle).abort();
            assert_eq!(peer.sockets.get(peer.handle).state(), tcp::State::Closed);
            peer.egress(2);
            peer.expect_frame(TcpControl::Rst, seq, TcpSeqNumber(101), &[]);
            peer.expect_template_frames(before, 1);
            peer.egress(3);
            peer.expect_template_frames(before, 1);
        }

        #[test]
        fn scaled_window_frames_match_generic() {
            let mut peer = Peer::configured_with_syn(
                2,
                PEER,
                None,
                |_, socket| {
                    *socket = tcp::Socket::new(
                        tcp::RxBuffer::new(131072),
                        tcp::SocketBuffer::new(vec![0; 4096]),
                    );
                    socket.set_ack_delay(None);
                },
                |syn| syn.window_scale = Some(7),
            );
            peer.warm();
            peer.assert_window(11520); // 90 frames x 512 B peer MSS, scaled by 4.
            let seq = peer.ack;
            let before = peer.iface.inner.template_frames;
            let mut data = peer.reply(TcpControl::Psh, seq);
            data.seq_number = TcpSeqNumber(101);
            data.max_seg_size = None;
            data.payload = b"rx";
            peer.ingress(2, peer.frame(data));
            peer.egress(2);
            peer.expect_frame(TcpControl::None, seq, TcpSeqNumber(103), &[]);
            peer.assert_window(11520); // Preserve 46078 B after 2 B received, rounded up / 4.
            peer.assert_layout(64, 20);
            peer.expect_template_frames(before, 1);
            let mut ack = peer.reply(TcpControl::None, seq);
            ack.seq_number = TcpSeqNumber(103);
            ack.max_seg_size = None;
            ack.window_len = 1;
            peer.ingress(3, peer.frame(ack));
            let payload = [0x6b; 129];
            assert_eq!(
                peer.sockets.get_mut(peer.handle).send_slice(&payload),
                Ok(payload.len())
            );
            peer.egress(3);
            peer.expect_frame(TcpControl::None, seq, TcpSeqNumber(103), &payload[..128]);
            peer.assert_window(11520); // Sending payload leaves the receive window unchanged.
            peer.assert_layout(64, 20);
            peer.expect_template_frames(before, 2);
            peer.egress(4);
            peer.expect_template_frames(before, 2);
        }

        #[test]
        fn tiny_mss_frames_match_generic() {
            let mut peer = Peer::configured_with_syn(
                2,
                PEER,
                None,
                |_, _| {},
                |syn| syn.max_seg_size = Some(48),
            );
            peer.warm();
            peer.assert_layout(64, 20);
            let seq = peer.ack;
            let before = peer.iface.inner.template_frames;
            let payload: Vec<u8> = (0..89).collect();
            assert_eq!(
                peer.sockets.get_mut(peer.handle).send_slice(&payload),
                Ok(payload.len())
            );
            peer.egress(2);
            for (offset, len, control) in [
                (0, 48, TcpControl::None),
                (48, 41, TcpControl::Psh),
            ] {
                peer.expect_frame(
                    control,
                    seq + offset,
                    TcpSeqNumber(101),
                    &payload[offset..offset + len],
                );
                peer.assert_layout(64, 20);
                let frame = peer.frames.last().unwrap();
                let ip = Ipv4Packet::new_checked(&frame[14..]).unwrap();
                let tcp = TcpRepr::parse(
                    &TcpPacket::new_checked(ip.payload()).unwrap(),
                    &peer.local.into(),
                    &peer.remote.into(),
                    &ChecksumCapabilities::default(),
                )
                .unwrap();
                assert_eq!(tcp.timestamp, None);
            }
            peer.expect_template_frames(before, 2);
        }

        #[test]
        fn offload_caps_frames_match_generic() {
            let mut peer = Peer::configured(2, PEER, None, |iface, _| {
                iface.inner.caps.checksum.tcp = crate::phy::Checksum::Rx;
            });
            peer.warm();
            let seq = peer.ack;
            let before = peer.iface.inner.template_frames;
            peer.send(2);
            peer.expect_frame(TcpControl::Psh, seq, TcpSeqNumber(101), &[0x5a]);
            peer.expect_template_frames(before, 1);
            let mut data = peer.reply(TcpControl::Psh, seq + 1);
            data.seq_number = TcpSeqNumber(101);
            data.max_seg_size = None;
            data.payload = b"rx";
            peer.ingress(3, peer.frame(data));
            peer.egress(3);
            peer.expect_frame(TcpControl::None, seq + 1, TcpSeqNumber(103), &[]);
            peer.expect_template_frames(before, 2);
            for frame in &peer.frames {
                let ip = Ipv4Packet::new_checked(&frame[14..]).unwrap();
                let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
                assert_eq!(tcp.checksum(), 0);
            }
        }
    }
}
