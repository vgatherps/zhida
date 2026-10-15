use super::*;
use alloc::rc::Rc;
use core::cell::Cell;
use std::collections::VecDeque;

use crate::iface::{PathMtu, PathMtus, UdpConfig, UdpHandle, UdpSendError, UdpSet};
use crate::phy::{Checksum, RxBuf};
use crate::socket::tcp;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

const LOCAL: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
const REMOTE: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
const PORT: u16 = 1234;
const PEER_PORT: u16 = 4321;
const ETH_LEN: usize = EthernetFrame::<&[u8]>::header_len();
const IP_LEN: usize = 20;
const LOCAL_MAC: EthernetAddress = EthernetAddress([2; 6]);
const REMOTE_MAC: EthernetAddress = EthernetAddress([4; 6]);

struct FrameToken {
    frame: RxBuf,
    meta: PacketMeta,
}

impl RxToken for FrameToken {
    fn into_buf(self) -> RxBuf {
        self.frame
    }

    fn meta(&self) -> PacketMeta {
        self.meta
    }
}

struct ReplyToken<'a>(&'a mut Vec<Vec<u8>>);

impl TxToken for ReplyToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut bytes = vec![0xa5; len];
        let result = f(&mut bytes);
        self.0.push(bytes);
        result
    }
}

struct UdpDevice {
    rx: VecDeque<FrameToken>,
    tx: Vec<Vec<u8>>,
    releases: Rc<Cell<usize>>,
    caps: DeviceCapabilities,
    tx_left: Option<usize>,
}

impl Device for UdpDevice {
    type RxToken<'a> = FrameToken;
    type TxToken<'a> = ReplyToken<'a>;

    fn receive(&mut self, _: Instant) -> Option<(FrameToken, ReplyToken<'_>)> {
        let rx = self.rx.pop_front()?;
        Some((rx, ReplyToken(&mut self.tx)))
    }

    fn transmit(&mut self, _: Instant) -> Option<ReplyToken<'_>> {
        if let Some(left) = &mut self.tx_left {
            if *left == 0 {
                return None;
            }
            *left = left.checked_sub(1).expect("TX token count underflow");
        }
        Some(ReplyToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.caps.clone()
    }
}

struct Test {
    iface: Interface,
    tcp: TcpSet<'static>,
    udp: UdpSet,
    handle: UdpHandle,
    device: UdpDevice,
}

impl Test {
    fn new(capacity: usize) -> Self {
        Self::with_config(UdpConfig {
            port: PORT,
            rx_queue: capacity,
            tx_checksum: true,
            broadcast: false,
        })
    }

    fn with_config(config: UdpConfig) -> Self {
        let (iface, tcp, device) = setup(Medium::Ethernet);
        let mut udp = UdpSet::new(1);
        let handle = udp.add(config).unwrap();
        Self {
            iface,
            tcp,
            udp,
            handle,
            device: UdpDevice {
                rx: VecDeque::new(),
                tx: Vec::new(),
                releases: Rc::new(Cell::new(0)),
                caps: device.capabilities(),
                tx_left: None,
            },
        }
    }

    fn with_path_mtus(rules: &[PathMtu]) -> Self {
        let mut test = Self::new(1);
        let mtu = 9000usize.checked_add(ETH_LEN).expect("device MTU overflow");
        test.device.caps.max_transmission_unit = mtu;
        test.iface.inner.caps.max_transmission_unit = mtu;
        test.iface.set_path_mtus(
            PathMtus::new(rules, Ipv4Cidr::new(LOCAL, 24), 9000).unwrap(),
        );
        test
    }

    fn receive(&mut self, bytes: Vec<u8>, verified: bool) -> usize {
        let ptr = bytes.as_ptr() as usize;
        self.device.rx.push_back(FrameToken {
            frame: RxBuf::counted_frame(bytes, 0, self.device.releases.clone()),
            meta: PacketMeta {
                l4_checksum_verified: verified,
                ..PacketMeta::default()
            },
        });
        assert_eq!(
            self.iface.poll_ingress_single_udp(
                Instant::ZERO,
                &mut self.device,
                &mut self.tcp,
                &mut self.udp,
            ),
            PollIngressSingleResult::SocketStateChanged,
        );
        assert!(self.udp.pending_rx_attach.is_none());
        ptr
    }

    fn recv(&mut self) -> Option<crate::iface::UdpDatagram> {
        self.udp.get_mut(self.handle).recv()
    }

    fn send(
        &mut self,
        to: Option<IpEndpoint>,
        len: usize,
        fill: impl FnOnce(&mut [u8]),
    ) -> Result<(), UdpSendError> {
        let target = self.iface.udp_target(&self.udp, self.handle, to, len)?;
        self.iface
            .udp_send(&mut self.device, &mut self.udp, target, fill)
    }
}

fn ethernet(ip: Vec<u8>) -> Vec<u8> {
    let mut bytes = vec![0; ETH_LEN + ip.len()];
    let mut frame = EthernetFrame::new_unchecked(&mut bytes[..]);
    EthernetRepr {
        src_addr: EthernetAddress([0x02, 0, 0, 0, 0, 2]),
        dst_addr: EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]),
        ethertype: EthernetProtocol::Ipv4,
    }
    .emit(&mut frame);
    frame.payload_mut().copy_from_slice(&ip);
    bytes
}

fn datagram(payload: &[u8], dst: Ipv4Address, src_port: u16) -> Vec<u8> {
    let udp = UdpRepr {
        src_port,
        dst_port: PORT,
    };
    let ip = Ipv4Repr {
        src_addr: REMOTE,
        dst_addr: dst,
        next_header: IpProtocol::Udp,
        payload_len: udp.header_len() + payload.len(),
        hop_limit: 64,
    };
    let mut bytes = vec![0; ip.buffer_len() + ip.payload_len];
    ip.emit(
        &mut Ipv4Packet::new_unchecked(&mut bytes[..]),
        &ChecksumCapabilities::default(),
    );
    udp.emit(
        &mut UdpPacket::new_unchecked(&mut bytes[ip.buffer_len()..]),
        &REMOTE.into(),
        &dst.into(),
        payload.len(),
        |out| out.copy_from_slice(payload),
        &ChecksumCapabilities::default(),
    );
    ethernet(bytes)
}

fn udp_packet(bytes: &mut [u8]) -> UdpPacket<&mut [u8]> {
    UdpPacket::new_unchecked(&mut bytes[ETH_LEN + IP_LEN..])
}

#[test]
fn ipv4_drops_before_udp_counted() {
    let mut test = Test::new(1);
    test.iface.inner.caps.checksum.ipv4 = Checksum::Rx;
    let good = datagram(b"payload!", LOCAL, PEER_PORT);
    let mut fragment = good.clone();
    let mut ip = Ipv4Packet::new_unchecked(&mut fragment[ETH_LEN..]);
    ip.set_more_frags(true);
    ip.fill_checksum();
    test.receive(fragment, false);
    assert_eq!(test.iface.ipv4_dropped(), 1);
    assert_eq!(test.udp.counters(), crate::iface::UdpCounters::default());
    assert_eq!(test.udp.get(test.handle).stats(), Default::default());
    assert!(test.recv().is_none());

    let mut corrupt = good.clone();
    let mut ip = Ipv4Packet::new_unchecked(&mut corrupt[ETH_LEN..]);
    ip.set_checksum(ip.checksum() ^ 1);
    test.receive(corrupt, false);
    assert_eq!(test.iface.ipv4_dropped(), 2);
    assert_eq!(test.udp.counters(), crate::iface::UdpCounters::default());
    assert_eq!(test.udp.get(test.handle).stats(), Default::default());
    assert!(test.recv().is_none());

    test.receive(good.clone(), false);
    assert_eq!(test.iface.ipv4_dropped(), 2);
    assert_eq!(test.recv().unwrap().payload(), b"payload!");

    let mut offset = good.clone();
    let mut ip = Ipv4Packet::new_unchecked(&mut offset[ETH_LEN..]);
    ip.set_frag_offset(8);
    ip.fill_checksum();
    test.receive(offset, false);
    assert_eq!(test.iface.ipv4_dropped(), 3);

    for length in [0, 1, 19] {
        test.receive(good[..ETH_LEN + length].to_vec(), false);
    }
    assert_eq!(test.iface.ipv4_dropped(), 6);

    let mut malformed = good.clone();
    let mut ip = Ipv4Packet::new_unchecked(&mut malformed[ETH_LEN..]);
    ip.set_header_len(16);
    ip.fill_checksum();
    test.receive(malformed, false);
    assert_eq!(test.iface.ipv4_dropped(), 7);

    test.receive(
        datagram(b"other", Ipv4Address::new(192, 168, 1, 3), PEER_PORT),
        false,
    );
    assert_eq!(test.iface.ipv4_dropped(), 7);
    let mut bad_udp = good;
    udp_packet(&mut bad_udp).payload_mut()[0] ^= 1;
    test.receive(bad_udp, false);
    assert_eq!(test.iface.ipv4_dropped(), 7);
    assert_eq!(test.udp.counters().rx_checksum_bad, 1);
}

#[test]
fn datagram_delivered_payload_src_dst() {
    let mut test = Test::new(2);
    let mut bytes = datagram(b"helloEXTRA", LOCAL, PEER_PORT);
    let mut packet = udp_packet(&mut bytes);
    packet.set_len((UDP_HEADER_LEN + 5) as u16);
    packet.fill_checksum(&REMOTE.into(), &LOCAL.into());
    bytes.extend_from_slice(&[0xa5; 4]);
    let original_len = bytes.len();
    let ptr = test.receive(bytes, false);
    let mut received = test.recv().unwrap();
    assert_eq!(received.payload(), b"hello");
    assert_eq!(received.src(), IpEndpoint::new(REMOTE.into(), PEER_PORT));
    assert_eq!(received.dst_addr(), LOCAL);
    assert_eq!(
        received.payload().as_ptr() as usize,
        ptr + ETH_LEN + IP_LEN + UDP_HEADER_LEN
    );
    assert!(
        (received.payload().as_ptr() as usize) + received.payload().len() <= ptr + original_len
    );
    received.payload_mut()[0] = b'H';
    assert_eq!(received.payload(), b"Hello");
    assert_eq!(test.udp.get(test.handle).stats().rx_delivered, 1);
    assert!(test.device.tx.is_empty());
}

#[test]
fn zero_checksum_accepted() {
    let mut test = Test::new(1);
    let mut bytes = datagram(b"zero", LOCAL, PEER_PORT);
    udp_packet(&mut bytes).set_checksum(0);
    test.receive(bytes, false);
    assert_eq!(test.recv().unwrap().payload(), b"zero");
    assert_eq!(test.udp.counters().rx_checksum_bad, 0);
}

#[test]
fn bad_checksum_counted() {
    let mut test = Test::new(1);
    let mut bytes = datagram(b"bad", LOCAL, PEER_PORT);
    udp_packet(&mut bytes).payload_mut()[0] ^= 1;
    test.receive(bytes, false);
    assert!(test.recv().is_none());
    assert_eq!(test.udp.counters().rx_checksum_bad, 1);
    assert_eq!(test.device.releases.get(), 1);
    assert!(test.device.tx.is_empty());
}

#[test]
fn good_verdict_skips_verify() {
    let mut test = Test::new(1);
    let mut bytes = datagram(b"bad", LOCAL, PEER_PORT);
    udp_packet(&mut bytes).payload_mut()[0] ^= 1;
    test.receive(bytes, true);
    assert_eq!(test.recv().unwrap().payload(), b"cad");
    assert_eq!(test.udp.counters().rx_checksum_bad, 0);
}

#[test]
fn malformed_length_counted() {
    let mut test = Test::new(1);
    for len in [7, 100] {
        let mut bytes = datagram(b"bad", LOCAL, PEER_PORT);
        udp_packet(&mut bytes).set_len(len);
        test.receive(bytes, true);
    }
    assert!(test.recv().is_none());
    assert_eq!(test.udp.counters().rx_malformed, 2);
    assert_eq!(test.udp.counters().rx_checksum_bad, 0);
    assert_eq!(test.device.releases.get(), 2);
}

#[test]
fn closed_port_counted_no_reply() {
    let mut test = Test::new(1);
    test.udp.remove(test.handle);
    test.receive(datagram(b"closed", LOCAL, PEER_PORT), false);
    assert_eq!(test.udp.counters().rx_no_port, 1);
    assert!(test.device.tx.is_empty());
    assert_eq!(test.device.releases.get(), 1);
}

#[test]
fn connected_drops_other_peer_counted() {
    let mut test = Test::new(1);
    test.udp
        .get_mut(test.handle)
        .connect(IpEndpoint::new(REMOTE.into(), PEER_PORT))
        .unwrap();
    test.receive(datagram(b"other", LOCAL, PEER_PORT + 1), false);
    assert!(test.recv().is_none());
    assert_eq!(test.udp.get(test.handle).stats().rx_dropped_peer, 1);
    assert_eq!(test.device.releases.get(), 1);
    test.receive(datagram(b"peer", LOCAL, PEER_PORT), false);
    assert_eq!(test.recv().unwrap().payload(), b"peer");
}

#[test]
fn broadcast_delivered() {
    let mut test = Test::new(1);
    for dst in [Ipv4Address::BROADCAST, Ipv4Address::new(192, 168, 1, 255)] {
        test.receive(datagram(b"broadcast", dst, PEER_PORT), false);
        let received = test.recv().unwrap();
        assert_eq!(received.payload(), b"broadcast");
        assert_eq!(received.dst_addr(), dst);
        drop(received);
    }
    assert!(!test.udp.get(test.handle).config().broadcast);
    assert_eq!(test.udp.get(test.handle).stats().rx_delivered, 2);
}

#[test]
fn multicast_dst_counted() {
    let mut test = Test::new(1);
    for (dst, mac) in [
        (
            Ipv4Address::new(224, 0, 0, 1),
            EthernetAddress([1, 0, 0x5e, 0, 0, 1]),
        ),
        (
            Ipv4Address::new(239, 1, 1, 1),
            EthernetAddress([1, 0, 0x5e, 1, 1, 1]),
        ),
    ] {
        let mut bytes = datagram(b"multicast", dst, PEER_PORT);
        EthernetFrame::new_unchecked(&mut bytes[..]).set_dst_addr(mac);
        test.receive(bytes, false);
    }
    assert!(test.recv().is_none());
    assert_eq!(test.udp.counters().rx_not_unicast, 2);
    assert_eq!(test.device.releases.get(), 2);
    assert!(test.device.tx.is_empty());
}

// IPv4 input drops TCP and ICMP to non-unicast destinations; UDP must still reach the set.
#[test]
fn non_unicast_udp_passes_ip_filter() {
    let mut test = Test::new(1);
    test.receive(datagram(b"bcast", Ipv4Address::BROADCAST, PEER_PORT), false);
    assert_eq!(test.recv().unwrap().payload(), b"bcast");
    let mut bytes = datagram(b"mcast", Ipv4Address::new(239, 1, 1, 1), PEER_PORT);
    EthernetFrame::new_unchecked(&mut bytes[..]).set_dst_addr(EthernetAddress([1, 0, 0x5e, 1, 1, 1]));
    test.receive(bytes, false);
    assert_eq!(test.udp.counters().rx_not_unicast, 1);
}

#[test]
fn queue_full_drops_newest_counted() {
    let mut test = Test::new(1);
    test.receive(datagram(b"first", LOCAL, PEER_PORT), false);
    test.receive(datagram(b"second", LOCAL, PEER_PORT), false);
    assert_eq!(test.udp.get(test.handle).rx_queued(), 1);
    assert_eq!(test.udp.get(test.handle).stats().rx_delivered, 1);
    assert_eq!(test.udp.get(test.handle).stats().rx_dropped_full, 1);
    assert_eq!(test.device.releases.get(), 1);
    assert_eq!(test.recv().unwrap().payload(), b"first");
}

#[test]
fn held_datagram_keeps_credit() {
    let mut test = Test::new(1);
    test.receive(datagram(b"held", LOCAL, PEER_PORT), false);
    let held = test.recv().unwrap();
    assert_eq!(test.udp.get(test.handle).rx_queued(), 0);
    test.receive(datagram(b"blocked", LOCAL, PEER_PORT), false);
    assert!(test.recv().is_none());
    assert_eq!(test.udp.get(test.handle).stats().rx_dropped_full, 1);
    assert_eq!(test.device.releases.get(), 1);
    drop(held);
    assert_eq!(test.device.releases.get(), 2);
    test.receive(datagram(b"next", LOCAL, PEER_PORT), false);
    assert_eq!(test.recv().unwrap().payload(), b"next");
    assert_eq!(test.udp.get(test.handle).stats().rx_delivered, 2);
}

#[test]
fn drop_releases_once() {
    let mut test = Test::new(1);
    test.receive(datagram(b"owned", LOCAL, PEER_PORT), false);
    let received = test.recv().unwrap();
    assert_eq!(test.device.releases.get(), 0);
    drop(received);
    assert_eq!(test.device.releases.get(), 1);
    test.udp.remove(test.handle);
    assert_eq!(test.device.releases.get(), 1);
}

#[test]
fn fifo_order() {
    let mut test = Test::new(3);
    for payload in [b"one", b"two", b"tri"] {
        test.receive(datagram(payload, LOCAL, PEER_PORT), false);
    }
    assert_eq!(test.udp.get(test.handle).rx_queued(), 3);
    assert_eq!(test.recv().unwrap().payload(), b"one");
    test.receive(datagram(b"four", LOCAL, PEER_PORT), false);
    for payload in [b"two".as_slice(), b"tri", b"four"] {
        assert_eq!(test.recv().unwrap().payload(), payload);
    }
    assert!(test.recv().is_none());
    assert_eq!(test.device.releases.get(), 4);
}

fn tcp_frame(
    control: TcpControl,
    seq: TcpSeqNumber,
    ack: Option<TcpSeqNumber>,
    payload: &[u8],
) -> Vec<u8> {
    let tcp = TcpRepr {
        src_port: PEER_PORT,
        dst_port: PORT,
        control,
        seq_number: seq,
        ack_number: ack,
        window_len: 64,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload,
    };
    let ip = Ipv4Repr {
        src_addr: REMOTE,
        dst_addr: LOCAL,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    let mut bytes = vec![0; ip.buffer_len() + tcp.buffer_len()];
    ip.emit(
        &mut Ipv4Packet::new_unchecked(&mut bytes[..]),
        &ChecksumCapabilities::default(),
    );
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut bytes[ip.buffer_len()..]),
        &REMOTE.into(),
        &LOCAL.into(),
        &ChecksumCapabilities::default(),
    );
    ethernet(bytes)
}

#[test]
fn tcp_unaffected() {
    let mut test = Test::new(1);
    let mut socket = tcp::Socket::new(tcp::RxBuffer::new(64), tcp::SocketBuffer::new(vec![0; 64]));
    socket.set_ack_delay(None);
    socket.listen(PORT).unwrap();
    let handle = test.tcp.add(socket);
    test.receive(datagram(b"udp", LOCAL, PEER_PORT), false);
    test.receive(
        tcp_frame(TcpControl::Syn, TcpSeqNumber(100), None, &[]),
        false,
    );
    assert_eq!(test.tcp.get(handle).state(), tcp::State::SynReceived);
    test.iface.inner.neighbor_cache.fill(
        REMOTE.into(),
        EthernetAddress([0x02, 0, 0, 0, 0, 2]).into(),
        Instant::ZERO,
    );
    test.iface
        .poll_egress(Instant::ZERO, &mut test.device, &mut test.tcp);
    assert_eq!(test.device.tx.len(), 1);
    let eth = EthernetFrame::new_checked(&test.device.tx[0][..]).unwrap();
    let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
    let synack = TcpPacket::new_checked(ip.payload()).unwrap();
    let ack = synack.seq_number() + 1;
    test.receive(
        tcp_frame(TcpControl::None, TcpSeqNumber(101), Some(ack), b"tcp"),
        false,
    );
    assert_eq!(test.tcp.get(handle).state(), tcp::State::Established);
    let mut payload = Vec::new();
    while let Some(frame) = test.tcp.get_mut(handle).recv().unwrap() {
        payload.extend_from_slice(frame.payload());
    }
    assert_eq!(payload.len(), 3);
    assert_eq!(&payload, b"tcp");
    assert_eq!(test.recv().unwrap().payload(), b"udp");
    assert_eq!(test.udp.get(test.handle).stats().rx_delivered, 1);
    assert_eq!(test.udp.counters(), crate::iface::UdpCounters::default());
}

fn send_frame(dst: Ipv4Address, mac: EthernetAddress, payload: &[u8], checksum: bool) -> Vec<u8> {
    let mut caps = ChecksumCapabilities::default();
    if !checksum {
        caps.udp = Checksum::None;
    }
    send_frame_caps(dst, mac, payload, &caps)
}

fn send_frame_caps(
    dst: Ipv4Address,
    mac: EthernetAddress,
    payload: &[u8],
    caps: &ChecksumCapabilities,
) -> Vec<u8> {
    send_frame_caps_port(dst, mac, PEER_PORT, payload, caps)
}

fn send_frame_caps_port(
    dst: Ipv4Address,
    mac: EthernetAddress,
    dst_port: u16,
    payload: &[u8],
    caps: &ChecksumCapabilities,
) -> Vec<u8> {
    let udp = UdpRepr {
        src_port: PORT,
        dst_port,
    };
    let ip = Ipv4Repr {
        src_addr: LOCAL,
        dst_addr: dst,
        next_header: IpProtocol::Udp,
        payload_len: udp.header_len() + payload.len(),
        hop_limit: 64,
    };
    let mut bytes = vec![0; EthernetFrame::<&[u8]>::buffer_len(ip.buffer_len() + ip.payload_len)];
    let mut eth = EthernetFrame::new_unchecked(&mut bytes[..]);
    EthernetRepr {
        src_addr: LOCAL_MAC,
        dst_addr: mac,
        ethertype: EthernetProtocol::Ipv4,
    }
    .emit(&mut eth);
    ip.emit(&mut Ipv4Packet::new_unchecked(eth.payload_mut()), caps);
    udp.emit(
        &mut UdpPacket::new_unchecked(&mut eth.payload_mut()[ip.buffer_len()..]),
        &LOCAL.into(),
        &dst.into(),
        payload.len(),
        |out| out.copy_from_slice(payload),
        caps,
    );
    bytes
}

fn resolve(test: &mut Test, addr: Ipv4Address, mac: EthernetAddress) {
    test.iface
        .inner
        .neighbor_cache
        .fill(addr.into(), mac.into(), test.iface.inner.now);
}

#[test]
fn udp_template_matches_wire_emitter() {
    for ipv4_checksum in [Checksum::Both, Checksum::Rx] {
        for udp_checksum in [Checksum::Both, Checksum::Rx] {
            for tx_checksum in [true, false] {
                for len in [0, 1, 2, 3, 63, 64, 65, 1471, 1472] {
                    let mut test = Test::with_config(UdpConfig {
                        port: PORT,
                        rx_queue: 1,
                        tx_checksum,
                        broadcast: false,
                    });
                    test.iface.inner.caps.checksum.ipv4 = ipv4_checksum;
                    test.iface.inner.caps.checksum.udp = udp_checksum;
                    resolve(&mut test, REMOTE, REMOTE_MAC);
                    let caps = ChecksumCapabilities {
                        ipv4: ipv4_checksum,
                        udp: if tx_checksum && udp_checksum.tx() {
                            Checksum::Both
                        } else {
                            Checksum::None
                        },
                        ..ChecksumCapabilities::default()
                    };
                    let payload: Vec<u8> = (0..len).map(|n| (n % 251) as u8).collect();
                    assert!(test.udp.get(test.handle).template.is_none());
                    let lookups = test.iface.inner.neighbor_cache
                        .lookup_calls
                        .load(core::sync::atomic::Ordering::Relaxed);
                    for expected_count in [0, 1] {
                        let mut called = 0;
                        assert_eq!(
                            test.send(
                                Some(IpEndpoint::new(REMOTE.into(), PEER_PORT)),
                                len,
                                |out| {
                                    called += 1;
                                    assert_eq!(out.len(), len);
                                    out.copy_from_slice(&payload);
                                },
                            ),
                            Ok(())
                        );
                        assert_eq!(called, 1);
                        assert_eq!(test.udp.template_frames, expected_count);
                        assert!(test.udp.get(test.handle).template.is_some());
                        assert_eq!(
                            test.iface.inner.neighbor_cache
                                .lookup_calls
                                .load(core::sync::atomic::Ordering::Relaxed),
                            lookups.checked_add(1).unwrap()
                        );
                    }
                    assert_eq!(test.device.tx.len(), 2);
                    assert_eq!(test.device.tx[0], test.device.tx[1]);
                    assert_eq!(
                        test.device.tx[1],
                        send_frame_caps(REMOTE, REMOTE_MAC, &payload, &caps)
                    );
                }
            }
        }
    }
}

#[test]
fn udp_template_checksums_match_generic_random() {
    let mut test = Test::new(1);
    resolve(&mut test, REMOTE, REMOTE_MAC);
    let mut rng = ChaCha8Rng::seed_from_u64(0x8742_abcd_1234_5678);
    let mut payload = [0; 1472];
    let iterations = 10_000usize;
    for _ in 0..iterations {
        let len = rng.gen_range(0..=payload.len());
        rng.fill(&mut payload[..len]);
        assert_eq!(
            test.send(
                Some(IpEndpoint::new(REMOTE.into(), PEER_PORT)),
                len,
                |out| out.copy_from_slice(&payload[..len]),
            ),
            Ok(())
        );
        assert_eq!(test.device.tx.len(), 1);
        assert_eq!(
            test.device.tx.pop().unwrap(),
            send_frame(REMOTE, REMOTE_MAC, &payload[..len], true)
        );
    }
    assert_eq!(test.udp.template_frames, iterations.checked_sub(1).unwrap());
}

#[test]
fn udp_template_computed_zero_checksum_is_ffff() {
    let mut test = Test::new(1);
    resolve(&mut test, REMOTE, REMOTE_MAC);
    let mut payload = [0; 2];
    let bytes = send_frame(REMOTE, REMOTE_MAC, &payload, true);
    let sum = UdpPacket::new_checked(&bytes[ETH_LEN + IP_LEN..])
        .unwrap()
        .checksum();
    assert_ne!(sum, 0xffff);
    payload.copy_from_slice(&sum.to_be_bytes());
    for expected_count in [0, 1] {
        assert_eq!(
            test.send(
                Some(IpEndpoint::new(REMOTE.into(), PEER_PORT)),
                payload.len(),
                |out| out.copy_from_slice(&payload),
            ),
            Ok(())
        );
        assert_eq!(test.udp.template_frames, expected_count);
    }
    assert_eq!(test.device.tx.len(), 2);
    assert_eq!(test.device.tx[0], test.device.tx[1]);
    let udp = UdpPacket::new_checked(&test.device.tx[1][ETH_LEN + IP_LEN..]).unwrap();
    assert_eq!(udp.checksum(), 0xffff);
    assert!(udp.verify_checksum(&LOCAL.into(), &REMOTE.into()));
    assert_eq!(
        test.device.tx[1],
        send_frame(REMOTE, REMOTE_MAC, &payload, true)
    );
}

#[test]
fn garp_changes_udp_template_destination() {
    let mut test = Test::new(1);
    resolve(&mut test, REMOTE, REMOTE_MAC);
    let peer = Some(IpEndpoint::new(REMOTE.into(), PEER_PORT));
    let payload = b"mac";
    for expected_count in [0, 1] {
        assert_eq!(
            test.send(peer, payload.len(), |out| out.copy_from_slice(payload)),
            Ok(())
        );
        assert_eq!(test.udp.template_frames, expected_count);
        assert_eq!(
            test.device.tx,
            vec![send_frame(REMOTE, REMOTE_MAC, payload, true)]
        );
        test.device.tx.clear();
    }
    assert!(test.udp.get(test.handle).template.is_some());
    let new_mac = EthernetAddress([6; 6]);
    test.receive(
        arp_frame(
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Request,
                source_hardware_addr: new_mac,
                source_protocol_addr: REMOTE,
                target_hardware_addr: EthernetAddress::BROADCAST,
                target_protocol_addr: REMOTE,
            },
            new_mac,
            EthernetAddress::BROADCAST,
        ),
        false,
    );
    assert!(test.device.tx.is_empty());
    for expected_count in [1, 2] {
        assert_eq!(
            test.send(peer, payload.len(), |out| out.copy_from_slice(payload)),
            Ok(())
        );
        let frame = EthernetFrame::new_checked(test.device.tx[0].as_slice()).unwrap();
        assert_eq!(frame.dst_addr(), new_mac);
        assert_eq!(
            test.device.tx,
            vec![send_frame(REMOTE, new_mac, payload, true)]
        );
        assert_eq!(test.udp.template_frames, expected_count);
        test.device.tx.clear();
    }
}

#[test]
fn template_follows_dst_mac_expiry() {
    let mut test = Test::new(1);
    let peer = Some(IpEndpoint::new(REMOTE.into(), PEER_PORT));
    let payload = b"mac";
    let second_mac = EthernetAddress([6; 6]);
    let third_mac = EthernetAddress([8; 6]);
    for (mac, counts) in [(REMOTE_MAC, [0, 1]), (second_mac, [1, 2])] {
        resolve(&mut test, REMOTE, mac);
        for expected_count in counts {
            assert_eq!(
                test.send(peer, payload.len(), |out| out.copy_from_slice(payload)),
                Ok(())
            );
            assert_eq!(test.udp.template_frames, expected_count);
            assert_eq!(
                test.device.tx,
                vec![send_frame(REMOTE, mac, payload, true)]
            );
            test.device.tx.clear();
        }
    }
    test.iface.inner.set_now(Instant::from_millis(60_000));
    for probe in [true, false] {
        assert_eq!(
            test.send(peer, payload.len(), |out| out.copy_from_slice(payload)),
            Ok(())
        );
        assert_eq!(test.udp.template_frames, 2);
        let mut expected = vec![send_frame(REMOTE, second_mac, payload, true)];
        if probe {
            expected.push(arp_request(REMOTE));
        }
        assert_eq!(test.device.tx, expected);
        let ip_packet = Ipv4Packet::new_checked(&test.device.tx[0][ETH_LEN..]).unwrap();
        let ip_repr = Ipv4Repr::parse(&ip_packet, &ChecksumCapabilities::default()).unwrap();
        assert!(
            !test.udp.get(test.handle).template.as_ref().unwrap().fits(
                test.iface.inner.neighbor_cache.changes(),
                LOCAL_MAC,
                &ip_repr,
                &UdpRepr {
                    src_port: PORT,
                    dst_port: PEER_PORT,
                },
            )
        );
        assert!(test.iface.inner.probe_owed.is_none());
        test.device.tx.clear();
    }
    test.receive(
        arp_frame(
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr: third_mac,
                source_protocol_addr: REMOTE,
                target_hardware_addr: LOCAL_MAC,
                target_protocol_addr: LOCAL,
            },
            third_mac,
            LOCAL_MAC,
        ),
        false,
    );
    assert!(test.device.tx.is_empty());
    for expected_count in [2, 3] {
        assert_eq!(
            test.send(peer, payload.len(), |out| out.copy_from_slice(payload)),
            Ok(())
        );
        assert_eq!(test.udp.template_frames, expected_count);
        assert_eq!(
            test.device.tx,
            vec![send_frame(REMOTE, third_mac, payload, true)]
        );
        test.device.tx.clear();
    }
}

#[test]
fn template_follows_connect_and_destination_change() {
    let mut test = Test::new(1);
    let other = Ipv4Address::new(192, 168, 1, 3);
    let other_mac = EthernetAddress([6; 6]);
    resolve(&mut test, REMOTE, REMOTE_MAC);
    resolve(&mut test, other, other_mac);
    let payload = b"destination";
    for (addr, mac, port, counts) in [
        (REMOTE, REMOTE_MAC, PEER_PORT, [0, 1]),
        (REMOTE, REMOTE_MAC, PEER_PORT + 1, [1, 2]),
        (other, other_mac, PEER_PORT, [2, 3]),
    ] {
        for expected_count in counts {
            assert_eq!(
                test.send(
                    Some(IpEndpoint::new(addr.into(), port)),
                    payload.len(),
                    |out| out.copy_from_slice(payload),
                ),
                Ok(())
            );
            assert_eq!(test.udp.template_frames, expected_count);
            assert_eq!(
                test.device.tx,
                vec![send_frame_caps_port(
                    addr,
                    mac,
                    port,
                    payload,
                    &ChecksumCapabilities::default(),
                )]
            );
            test.device.tx.clear();
        }
    }
    test.udp
        .get_mut(test.handle)
        .connect(IpEndpoint::new(REMOTE.into(), PEER_PORT))
        .unwrap();
    assert!(test.udp.get(test.handle).template.is_some());
    for expected_count in [3, 4] {
        assert_eq!(
            test.send(None, payload.len(), |out| out.copy_from_slice(payload)),
            Ok(())
        );
        assert_eq!(test.udp.template_frames, expected_count);
        assert_eq!(
            test.device.tx,
            vec![send_frame(REMOTE, REMOTE_MAC, payload, true)]
        );
        test.device.tx.clear();
    }
    let config = *test.udp.get(test.handle).config();
    test.udp.remove(test.handle);
    test.handle = test.udp.add(config).unwrap();
    assert!(test.udp.get(test.handle).template.is_none());
    assert_eq!(test.udp.get(test.handle).peer(), None);
    for expected_count in [4, 5] {
        assert_eq!(
            test.send(
                Some(IpEndpoint::new(REMOTE.into(), PEER_PORT)),
                payload.len(),
                |out| out.copy_from_slice(payload),
            ),
            Ok(())
        );
        assert_eq!(test.udp.template_frames, expected_count);
        assert_eq!(
            test.device.tx,
            vec![send_frame(REMOTE, REMOTE_MAC, payload, true)]
        );
        test.device.tx.clear();
    }
}

#[test]
fn template_not_built_for_broadcast() {
    let mut test = Test::with_config(UdpConfig {
        port: PORT,
        rx_queue: 1,
        tx_checksum: true,
        broadcast: true,
    });
    let dst = Ipv4Address::new(192, 168, 1, 255);
    let payload = b"broadcast";
    for _ in 0..2 {
        assert_eq!(
            test.send(
                Some(IpEndpoint::new(dst.into(), PEER_PORT)),
                payload.len(),
                |out| out.copy_from_slice(payload),
            ),
            Ok(())
        );
        assert_eq!(test.udp.template_frames, 0);
        assert!(test.udp.get(test.handle).template.is_none());
        assert_eq!(
            test.device.tx,
            vec![send_frame(dst, EthernetAddress::BROADCAST, payload, true)]
        );
        test.device.tx.clear();
    }
}

// With an IP MTU above 65535 the u16 length fields wrap on both paths; the template
// must checksum the same UDP-length range the generic emitter does.
#[test]
fn template_matches_generic_above_u16_length() {
    let mut test = Test::new(1);
    test.iface.inner.caps.max_transmission_unit = 70000;
    resolve(&mut test, REMOTE, REMOTE_MAC);
    for _ in 0..2 {
        assert_eq!(
            test.send(
                Some(IpEndpoint::new(REMOTE.into(), PEER_PORT)),
                65537,
                |out| out.fill(7),
            ),
            Ok(())
        );
    }
    assert_eq!(test.udp.template_frames, 1);
    let generic = UdpPacket::new_unchecked(&test.device.tx[0][ETH_LEN + IP_LEN..]);
    assert_eq!(generic.len(), 9);
    assert!(generic.verify_checksum(&LOCAL.into(), &REMOTE.into()));
    assert_eq!(test.device.tx[0], test.device.tx[1]);
}

#[test]
fn send_frame_bytes_match_wire_emitters() {
    for checksum in [true, false] {
        let mut test = Test::with_config(UdpConfig {
            port: PORT,
            rx_queue: 1,
            tx_checksum: checksum,
            broadcast: false,
        });
        resolve(&mut test, REMOTE, REMOTE_MAC);
        for len in [0, 1, 64, 1471, 1472] {
            let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut called = 0;
            assert_eq!(
                test.send(
                    Some(IpEndpoint::new(REMOTE.into(), PEER_PORT)),
                    len,
                    |out| {
                        called += 1;
                        assert_eq!(out.len(), len);
                        out.copy_from_slice(&payload);
                    },
                ),
                Ok(())
            );
            assert_eq!(called, 1);
            assert_eq!(test.device.tx.len(), 1);
            let bytes = test.device.tx.pop().unwrap();
            assert_eq!(bytes, send_frame(REMOTE, REMOTE_MAC, &payload, checksum));
            let eth = EthernetFrame::new_checked(&bytes[..]).unwrap();
            let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
            assert!(ip.dont_frag());
            assert!(!ip.more_frags());
            assert_eq!(ip.frag_offset(), 0);
            assert_eq!(ip.hop_limit(), 64);
            assert_eq!(ip.ident(), 0);
            assert!(ip.verify_checksum());
            let udp = UdpPacket::new_checked(ip.payload()).unwrap();
            assert_eq!(udp.payload(), payload);
            if checksum {
                assert_ne!(udp.checksum(), 0);
                assert!(udp.verify_checksum(&LOCAL.into(), &REMOTE.into()));
            } else {
                assert_eq!(udp.checksum(), 0);
            }
        }
    }
}

#[test]
fn send_device_tx_offload_writes_zero() {
    for tx_checksum in [true, false] {
        let mut test = Test::with_config(UdpConfig {
            port: PORT,
            rx_queue: 1,
            tx_checksum,
            broadcast: false,
        });
        resolve(&mut test, REMOTE, REMOTE_MAC);
        test.iface.inner.caps.checksum.udp = crate::phy::Checksum::Rx;
        let payload = b"offload";
        assert_eq!(
            test.send(
                Some(IpEndpoint::new(REMOTE.into(), PEER_PORT)),
                payload.len(),
                |out| out.copy_from_slice(payload),
            ),
            Ok(())
        );
        assert_eq!(test.device.tx.len(), 1);
        assert_eq!(
            test.device.tx.pop().unwrap(),
            send_frame(REMOTE, REMOTE_MAC, payload, false)
        );
    }
}

#[test]
fn send_computed_zero_checksum_is_ffff() {
    let mut test = Test::new(1);
    resolve(&mut test, REMOTE, REMOTE_MAC);
    let mut payload = [0; 2];
    let bytes = send_frame(REMOTE, REMOTE_MAC, &payload, true);
    let sum = UdpPacket::new_checked(&bytes[ETH_LEN + IP_LEN..])
        .unwrap()
        .checksum();
    assert_ne!(sum, 0xffff);
    payload.copy_from_slice(&sum.to_be_bytes());
    assert_eq!(
        test.send(
            Some(IpEndpoint::new(REMOTE.into(), PEER_PORT)),
            payload.len(),
            |out| out.copy_from_slice(&payload),
        ),
        Ok(())
    );
    let udp = UdpPacket::new_checked(&test.device.tx[0][ETH_LEN + IP_LEN..]).unwrap();
    assert_eq!(udp.checksum(), 0xffff);
    assert!(udp.verify_checksum(&LOCAL.into(), &REMOTE.into()));
    assert_eq!(
        test.device.tx[0],
        send_frame(REMOTE, REMOTE_MAC, &payload, true)
    );
}

#[test]
fn send_to_y_after_x_uses_y_mac() {
    let mut test = Test::new(1);
    let other = Ipv4Address::new(192, 168, 1, 3);
    let other_mac = EthernetAddress([6; 6]);
    resolve(&mut test, REMOTE, REMOTE_MAC);
    resolve(&mut test, other, other_mac);
    for (addr, mac) in [
        (REMOTE, REMOTE_MAC),
        (other, other_mac),
        (REMOTE, REMOTE_MAC),
    ] {
        assert_eq!(
            test.send(Some(IpEndpoint::new(addr.into(), PEER_PORT)), 1, |out| {
                out[0] = 7
            }),
            Ok(())
        );
        assert_eq!(
            test.device.tx.pop().unwrap(),
            send_frame(addr, mac, &[7], true)
        );
    }
}

fn arp_frame(repr: ArpRepr, src: EthernetAddress, dst: EthernetAddress) -> Vec<u8> {
    let mut bytes = vec![0; EthernetFrame::<&[u8]>::buffer_len(repr.buffer_len())];
    let mut eth = EthernetFrame::new_unchecked(&mut bytes[..]);
    EthernetRepr {
        src_addr: src,
        dst_addr: dst,
        ethertype: EthernetProtocol::Arp,
    }
    .emit(&mut eth);
    repr.emit(&mut ArpPacket::new_unchecked(eth.payload_mut()));
    bytes
}

fn arp_request(addr: Ipv4Address) -> Vec<u8> {
    arp_frame(
        ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: LOCAL_MAC,
            source_protocol_addr: LOCAL,
            target_hardware_addr: EthernetAddress::BROADCAST,
            target_protocol_addr: addr,
        },
        LOCAL_MAC,
        EthernetAddress::BROADCAST,
    )
}

fn assert_send_error(test: &mut Test, to: Option<IpEndpoint>, len: usize, error: UdpSendError) {
    let mut called = false;
    assert_eq!(
        test.send(to, len, |_| {
            called = true;
        }),
        Err(error)
    );
    assert!(!called);
    if error == UdpSendError::NeighborPending {
        let IpAddress::Ipv4(addr) = to.unwrap().addr else {
            panic!("ARP requires IPv4");
        };
        assert_eq!(test.device.tx, vec![arp_request(addr)]);
    } else {
        assert!(test.device.tx.is_empty());
    }
}

#[test]
fn fill_not_called_on_error() {
    let peer = IpEndpoint::new(REMOTE.into(), PEER_PORT);
    assert_send_error(&mut Test::new(1), None, 1, UdpSendError::NoDestination);
    let mut test = Test::new(1);
    test.udp.get_mut(test.handle).connect(peer).unwrap();
    assert_send_error(
        &mut test,
        Some(IpEndpoint::new(peer.addr, PEER_PORT + 1)),
        usize::MAX,
        UdpSendError::PeerMismatch,
    );
    for addr in [
        Ipv4Address::UNSPECIFIED,
        Ipv4Address::new(224, 0, 0, 1),
        Ipv4Address::new(239, 1, 1, 1),
        LOCAL,
        Ipv4Address::new(127, 0, 0, 1),
        Ipv4Address::BROADCAST,
        Ipv4Address::new(192, 168, 1, 255),
    ] {
        assert_send_error(
            &mut Test::new(1),
            Some(IpEndpoint::new(addr.into(), PEER_PORT)),
            usize::MAX,
            UdpSendError::Unaddressable,
        );
    }
    assert_send_error(
        &mut Test::new(1),
        Some(IpEndpoint::new(REMOTE.into(), 0)),
        1,
        UdpSendError::Unaddressable,
    );
    assert_send_error(
        &mut Test::new(1),
        Some(peer),
        usize::MAX,
        UdpSendError::TooLarge,
    );
    let off_subnet = IpEndpoint::new(IpAddress::v4(10, 0, 0, 1), PEER_PORT);
    assert_send_error(
        &mut Test::new(1),
        Some(off_subnet),
        1,
        UdpSendError::NoRoute,
    );
    assert_send_error(
        &mut Test::new(1),
        Some(peer),
        1,
        UdpSendError::NeighborPending,
    );
    let mut test = Test::new(1);
    test.device.tx_left = Some(0);
    assert_send_error(&mut test, Some(off_subnet), 1, UdpSendError::WouldBlock);
}

#[test]
fn udp_target_error_order() {
    let peer = IpEndpoint::new(REMOTE.into(), PEER_PORT);
    let mut test = Test::new(1);
    test.device.tx_left = Some(1);
    let target = |test: &Test, to, len| test.iface.udp_target(&test.udp, test.handle, to, len);
    assert_eq!(
        target(&test, None, usize::MAX),
        Err(UdpSendError::NoDestination)
    );
    assert_eq!(
        target(
            &test,
            Some(IpEndpoint::new(LOCAL.into(), PEER_PORT)),
            usize::MAX
        ),
        Err(UdpSendError::Unaddressable)
    );
    assert_eq!(target(&test, Some(peer), 1473), Err(UdpSendError::TooLarge));
    test.udp.get_mut(test.handle).connect(peer).unwrap();
    assert_eq!(
        target(
            &test,
            Some(IpEndpoint::new(peer.addr, PEER_PORT + 1)),
            usize::MAX
        ),
        Err(UdpSendError::PeerMismatch)
    );
    assert_eq!(
        target(
            &test,
            Some(IpEndpoint::new(LOCAL.into(), PEER_PORT)),
            usize::MAX
        ),
        Err(UdpSendError::PeerMismatch)
    );
    assert_eq!(target(&test, None, 1473), Err(UdpSendError::TooLarge));
    assert_eq!(test.device.tx_left, Some(1));
    assert!(test.device.tx.is_empty());
    let resolved = target(&test, None, 1472).unwrap();
    assert_eq!(
        test.iface
            .udp_send(&mut test.device, &mut test.udp, resolved, |_| {}),
        Err(UdpSendError::NeighborPending)
    );
    assert_eq!(test.device.tx_left, Some(0));
    assert_eq!(test.device.tx, vec![arp_request(REMOTE)]);
}

#[test]
fn arp_on_miss_payload_untouched() {
    let mut test = Test::new(1);
    let peer = IpEndpoint::new(REMOTE.into(), PEER_PORT);
    assert_send_error(&mut test, Some(peer), 4, UdpSendError::NeighborPending);
    test.device.tx.clear();
    let mut called = false;
    assert_eq!(
        test.send(Some(peer), 4, |_| called = true),
        Err(UdpSendError::NeighborPending)
    );
    assert!(!called);
    assert!(test.device.tx.is_empty());
    test.receive(
        arp_frame(
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr: REMOTE_MAC,
                source_protocol_addr: REMOTE,
                target_hardware_addr: LOCAL_MAC,
                target_protocol_addr: LOCAL,
            },
            REMOTE_MAC,
            LOCAL_MAC,
        ),
        false,
    );
    assert!(test.device.tx.is_empty());
    assert_eq!(
        test.send(Some(peer), 4, |out| {
            out.copy_from_slice(b"sent");
        }),
        Ok(())
    );
    assert_eq!(
        test.device.tx,
        vec![send_frame(REMOTE, REMOTE_MAC, b"sent", true)]
    );
}

#[test]
fn first_udp_send_after_idle_uses_stale_mac() {
    let mut test = Test::new(1);
    resolve(&mut test, REMOTE, REMOTE_MAC);
    test.iface.inner.set_now(Instant::from_secs(70));
    assert_eq!(
        test.send(Some(IpEndpoint::new(REMOTE.into(), PEER_PORT)), 4, |out| {
            out.copy_from_slice(b"sent")
        }),
        Ok(())
    );
    assert_eq!(
        test.device.tx,
        vec![
            send_frame(REMOTE, REMOTE_MAC, b"sent", true),
            arp_request(REMOTE)
        ]
    );
}

#[test]
fn first_udp_send_after_idle_uses_stale_gateway() {
    let mut test = Test::new(1);
    let gateway = Ipv4Address::new(192, 168, 1, 254);
    let remote = Ipv4Address::new(10, 0, 0, 1);
    test.iface.set_ipv4_gateway(Some(gateway));
    resolve(&mut test, gateway, REMOTE_MAC);
    resolve(&mut test, remote, REMOTE_MAC);
    for seconds in [30, 60, 69] {
        let mut bytes = datagram(b"in", LOCAL, PEER_PORT);
        let mut eth = EthernetFrame::new_unchecked(&mut bytes[..]);
        eth.set_src_addr(REMOTE_MAC);
        let mut ip = Ipv4Packet::new_unchecked(eth.payload_mut());
        ip.set_src_addr(remote);
        ip.fill_checksum();
        UdpPacket::new_unchecked(ip.payload_mut()).fill_checksum(&remote.into(), &LOCAL.into());
        test.device.rx.push_back(FrameToken {
            frame: RxBuf::counted_frame(bytes, 0, test.device.releases.clone()),
            meta: PacketMeta::default(),
        });
        assert_eq!(
            test.iface.poll_ingress_single_udp(
                Instant::from_secs(seconds),
                &mut test.device,
                &mut test.tcp,
                &mut test.udp,
            ),
            PollIngressSingleResult::SocketStateChanged,
        );
        assert_eq!(test.recv().unwrap().payload(), b"in");
    }
    assert_eq!(
        test.iface
            .inner
            .neighbor_cache
            .lookup(&remote.into(), Instant::from_secs(70)),
        NeighborAnswer::Found(REMOTE_MAC.into())
    );
    assert!(test.device.tx.is_empty());
    test.iface.inner.set_now(Instant::from_secs(70));
    assert_eq!(
        test.send(Some(IpEndpoint::new(remote.into(), PEER_PORT)), 4, |out| {
            out.copy_from_slice(b"sent")
        }),
        Ok(())
    );
    assert_eq!(
        test.device.tx,
        vec![
            send_frame(remote, REMOTE_MAC, b"sent", true),
            arp_request(gateway)
        ]
    );
}

#[test]
fn expiry_without_tcp_egress() {
    let mut test = Test::new(1);
    resolve(&mut test, REMOTE, REMOTE_MAC);
    let changes = test.iface.inner.neighbor_cache.changes();
    let peer = IpEndpoint::new(REMOTE.into(), PEER_PORT);
    for millis in [60_000, 60_999, 61_000, 62_999] {
        test.iface.inner.set_now(Instant::from_millis(millis));
        assert_eq!(test.send(Some(peer), 1, |out| out[0] = 9), Ok(()));
        let mut expected = vec![send_frame(REMOTE, REMOTE_MAC, &[9], true)];
        if millis != 60_999 {
            expected.push(arp_request(REMOTE));
        }
        assert_eq!(test.device.tx, expected);
        assert_eq!(test.iface.inner.neighbor_cache.changes(), changes + 1);
        assert!(test.iface.inner.probe_owed.is_none());
        test.device.tx.clear();
    }
    // Past the stale window the probe sent at 62,999 ms still silences ARP for 1 s.
    test.iface.inner.set_now(Instant::from_millis(63_000));
    let mut called = false;
    assert_eq!(
        test.send(Some(peer), 1, |_| called = true),
        Err(UdpSendError::NeighborPending)
    );
    assert!(!called);
    assert!(test.device.tx.is_empty());
    test.iface.inner.set_now(Instant::from_millis(63_999));
    assert_send_error(&mut test, Some(peer), 1, UdpSendError::NeighborPending);
}

#[test]
fn udp_parallel_peers_each_get_arp() {
    let mut test = Test::new(1);
    let mut expected = Vec::new();
    for last in [2, 3, 4] {
        let addr = Ipv4Address::new(192, 168, 1, last);
        let mut called = false;
        assert_eq!(
            test.send(Some(IpEndpoint::new(addr.into(), PEER_PORT)), 1, |_| {
                called = true
            }),
            Err(UdpSendError::NeighborPending)
        );
        assert!(!called);
        expected.push(arp_request(addr));
    }
    assert_eq!(test.device.tx, expected);
}

#[test]
fn broadcast_requires_opt_in() {
    for dst in [Ipv4Address::BROADCAST, Ipv4Address::new(192, 168, 1, 255)] {
        let to = Some(IpEndpoint::new(dst.into(), PEER_PORT));
        assert_send_error(&mut Test::new(1), to, 3, UdpSendError::Unaddressable);
        let mut test = Test::with_config(UdpConfig {
            port: PORT,
            rx_queue: 1,
            tx_checksum: true,
            broadcast: true,
        });
        assert_eq!(
            test.send(to, 3, |out| {
                out.copy_from_slice(b"all");
            }),
            Ok(())
        );
        assert_eq!(
            test.device.tx,
            vec![send_frame(dst, EthernetAddress::BROADCAST, b"all", true)]
        );
        assert!(test.iface.inner.probe_owed.is_none());
    }
}

#[test]
fn too_large_boundary() {
    let mut test = Test::new(1);
    resolve(&mut test, REMOTE, REMOTE_MAC);
    let len = test.iface.inner.ip_mtu().checked_sub(28).unwrap();
    let peer = Some(IpEndpoint::new(REMOTE.into(), PEER_PORT));
    assert_eq!(
        test.send(peer, len, |out| {
            assert_eq!(out.len(), len);
            out.fill(7);
        }),
        Ok(())
    );
    assert_eq!(
        test.device.tx,
        vec![send_frame(REMOTE, REMOTE_MAC, &vec![7; len], true)]
    );
    test.device.tx.clear();
    assert_send_error(
        &mut test,
        peer,
        len.checked_add(1).unwrap(),
        UdpSendError::TooLarge,
    );
}

#[test]
fn udp_over_path_mtu_is_too_large_before_fill() {
    let mut test = Test::with_path_mtus(&[PathMtu {
        prefix: Ipv4Cidr::new(REMOTE, 32),
        mtu: 1500,
    }]);
    resolve(&mut test, REMOTE, REMOTE_MAC);
    let counters = test.udp.counters();
    let stats = test.udp.get(test.handle).stats();
    test.device.tx_left = Some(1);
    assert_send_error(
        &mut test,
        Some(IpEndpoint::new(REMOTE.into(), PEER_PORT)),
        1473,
        UdpSendError::TooLarge,
    );
    assert_eq!(test.device.tx_left, Some(1));
    assert_eq!(test.udp.counters(), counters);
    assert_eq!(test.udp.get(test.handle).stats(), stats);
    assert_eq!(test.udp.template_frames, 0);
}

#[test]
fn udp_at_path_limit_sends() {
    let mut test = Test::with_path_mtus(&[PathMtu {
        prefix: Ipv4Cidr::new(REMOTE, 32),
        mtu: 1500,
    }]);
    resolve(&mut test, REMOTE, REMOTE_MAC);
    assert_eq!(
        test.send(Some(IpEndpoint::new(REMOTE.into(), PEER_PORT)), 1472, |out| {
            assert_eq!(out.len(), 1472);
            out.fill(7);
        }),
        Ok(())
    );
    assert_eq!(
        test.device.tx,
        vec![send_frame(REMOTE, REMOTE_MAC, &[7; 1472], true)]
    );
    let ip = Ipv4Packet::new_checked(&test.device.tx[0][ETH_LEN..]).unwrap();
    assert_eq!(ip.total_len(), 1500);
}

#[test]
fn udp_on_link_jumbo_still_sends_8972() {
    let mut test = Test::with_path_mtus(&[PathMtu {
        prefix: "0.0.0.0/0".parse().unwrap(),
        mtu: 1500,
    }]);
    resolve(&mut test, REMOTE, REMOTE_MAC);
    let peer = Some(IpEndpoint::new(REMOTE.into(), PEER_PORT));
    assert_eq!(
        test.send(peer, 8972, |out| {
            assert_eq!(out.len(), 8972);
            out.fill(7);
        }),
        Ok(())
    );
    assert_eq!(
        test.device.tx,
        vec![send_frame(REMOTE, REMOTE_MAC, &[7; 8972], true)]
    );
    let ip = Ipv4Packet::new_checked(&test.device.tx[0][ETH_LEN..]).unwrap();
    assert_eq!(ip.total_len(), 9000);
    test.device.tx.clear();
    assert_send_error(&mut test, peer, 8973, UdpSendError::TooLarge);
}

#[test]
fn connected_udp_uses_peer_path() {
    let mut test = Test::with_path_mtus(&[PathMtu {
        prefix: Ipv4Cidr::new(REMOTE, 32),
        mtu: 1500,
    }]);
    resolve(&mut test, REMOTE, REMOTE_MAC);
    let peer = IpEndpoint::new(REMOTE.into(), PEER_PORT);
    test.udp.get_mut(test.handle).connect(peer).unwrap();
    assert_send_error(&mut test, None, 1473, UdpSendError::TooLarge);
    assert_eq!(test.send(None, 1472, |out| out.fill(7)), Ok(()));
    assert_eq!(
        test.device.tx,
        vec![send_frame(REMOTE, REMOTE_MAC, &[7; 1472], true)]
    );
}

#[test]
fn udp_template_reuse_still_checked() {
    let mut test = Test::with_path_mtus(&[PathMtu {
        prefix: Ipv4Cidr::new(REMOTE, 32),
        mtu: 1500,
    }]);
    resolve(&mut test, REMOTE, REMOTE_MAC);
    let peer = Some(IpEndpoint::new(REMOTE.into(), PEER_PORT));
    for expected_count in [0, 1] {
        assert_eq!(test.send(peer, 1472, |out| out.fill(7)), Ok(()));
        assert_eq!(test.udp.template_frames, expected_count);
        assert_eq!(
            test.device.tx,
            vec![send_frame(REMOTE, REMOTE_MAC, &[7; 1472], true)]
        );
        test.device.tx.clear();
    }
    let counters = test.udp.counters();
    let stats = test.udp.get(test.handle).stats();
    assert_send_error(&mut test, peer, 1473, UdpSendError::TooLarge);
    assert_eq!(test.udp.template_frames, 1);
    assert_eq!(test.udp.counters(), counters);
    assert_eq!(test.udp.get(test.handle).stats(), stats);
}

#[test]
fn would_block_when_no_tx_token() {
    let mut test = Test::new(1);
    resolve(&mut test, REMOTE, REMOTE_MAC);
    test.device.tx_left = Some(0);
    let peer = Some(IpEndpoint::new(REMOTE.into(), PEER_PORT));
    assert_send_error(&mut test, peer, 1, UdpSendError::WouldBlock);
    test.device.tx_left = Some(1);
    assert_eq!(
        test.send(peer, 1, |out| {
            out[0] = 8;
        }),
        Ok(())
    );
    assert_eq!(
        test.device.tx,
        vec![send_frame(REMOTE, REMOTE_MAC, &[8], true)]
    );
}

#[test]
fn connected_send_uses_peer() {
    let mut test = Test::new(1);
    resolve(&mut test, REMOTE, REMOTE_MAC);
    let peer = IpEndpoint::new(REMOTE.into(), PEER_PORT);
    test.udp.get_mut(test.handle).connect(peer).unwrap();
    for to in [None, Some(peer)] {
        assert_eq!(
            test.send(to, 1, |out| {
                out[0] = 5;
            }),
            Ok(())
        );
        assert_eq!(
            test.device.tx.pop().unwrap(),
            send_frame(REMOTE, REMOTE_MAC, &[5], true)
        );
    }
}

#[test]
fn send_stale_handle_panics_before_fill() {
    let mut test = Test::new(1);
    test.udp.remove(test.handle);
    let mut called = false;
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        test.send(None, 1, |_| {
            called = true;
        })
    }))
    .is_err());
    assert!(!called);
    assert!(test.device.tx.is_empty());
}

#[test]
fn send_ipv4_checksum_follows_device_caps() {
    let mut test = Test::new(1);
    resolve(&mut test, REMOTE, REMOTE_MAC);
    test.iface.inner.caps.checksum.ipv4 = crate::phy::Checksum::None;
    assert_eq!(
        test.send(Some(IpEndpoint::new(REMOTE.into(), PEER_PORT)), 1, |out| {
            out[0] = 3
        }),
        Ok(())
    );
    let mut expected = send_frame(REMOTE, REMOTE_MAC, &[3], true);
    Ipv4Packet::new_unchecked(&mut expected[ETH_LEN..]).set_checksum(0);
    assert_eq!(test.device.tx, vec![expected]);
}

#[cfg(feature = "medium-ip")]
#[test]
#[should_panic(expected = "UDP send needs an Ethernet interface")]
fn send_panics_on_ip_medium() {
    let (mut iface, _, mut device) = setup(Medium::Ip);
    let mut udp = UdpSet::new(1);
    let handle = udp
        .add(UdpConfig {
            port: PORT,
            rx_queue: 1,
            tx_checksum: true,
            broadcast: true,
        })
        .unwrap();
    let _ = iface.udp_target(
        &udp,
        handle,
        Some(IpEndpoint::new(Ipv4Address::BROADCAST.into(), PEER_PORT)),
        1,
    );
}

#[test]
fn no_gateway_sends_on_subnet_directly() {
    let mut test = Test::new(1);
    let off_subnet = IpEndpoint::new(IpAddress::v4(198, 51, 100, 2), PEER_PORT);
    assert_send_error(&mut test, Some(off_subnet), 4, UdpSendError::NoRoute);
    let on_subnet = IpEndpoint::new(REMOTE.into(), PEER_PORT);
    assert_send_error(&mut test, Some(on_subnet), 4, UdpSendError::NeighborPending);
}

#[test]
fn gateway_sends_off_subnet_and_keeps_on_subnet_direct() {
    let mut test = Test::new(1);
    let gateway = Ipv4Address::new(192, 168, 1, 3);
    let gateway_mac = EthernetAddress([6; 6]);
    let remote = Ipv4Address::new(198, 51, 100, 2);
    let off_subnet = IpEndpoint::new(remote.into(), PEER_PORT);
    test.iface.set_ipv4_gateway(Some(gateway));
    let mut called = false;
    assert_eq!(
        test.send(Some(off_subnet), 4, |_| called = true),
        Err(UdpSendError::NeighborPending)
    );
    assert!(!called);
    assert_eq!(test.device.tx, vec![arp_request(gateway)]);
    test.device.tx.clear();
    test.receive(
        arp_frame(
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr: gateway_mac,
                source_protocol_addr: gateway,
                target_hardware_addr: LOCAL_MAC,
                target_protocol_addr: LOCAL,
            },
            gateway_mac,
            LOCAL_MAC,
        ),
        false,
    );
    assert!(test.device.tx.is_empty());
    assert_eq!(
        test.send(Some(off_subnet), 4, |out| out.copy_from_slice(b"sent")),
        Ok(())
    );
    assert_eq!(
        test.device.tx,
        vec![send_frame(remote, gateway_mac, b"sent", true)]
    );
    test.device.tx.clear();
    let on_subnet = IpEndpoint::new(REMOTE.into(), PEER_PORT);
    assert_send_error(&mut test, Some(on_subnet), 4, UdpSendError::NeighborPending);
    test.device.tx.clear();
    resolve(&mut test, REMOTE, REMOTE_MAC);
    assert_eq!(
        test.send(Some(on_subnet), 4, |out| out.copy_from_slice(b"sent")),
        Ok(())
    );
    assert_eq!(
        test.device.tx,
        vec![send_frame(REMOTE, REMOTE_MAC, b"sent", true)]
    );
}

#[test]
fn removing_gateway_invalidates_cached_udp_next_hop() {
    let mut test = Test::new(1);
    let gateway = Ipv4Address::new(192, 168, 1, 3);
    let remote = Ipv4Address::new(198, 51, 100, 2);
    let off_subnet = IpEndpoint::new(remote.into(), PEER_PORT);
    test.iface.set_ipv4_gateway(Some(gateway));
    resolve(&mut test, gateway, REMOTE_MAC);
    for _ in 0..2 {
        assert_eq!(
            test.send(Some(off_subnet), 4, |out| out.copy_from_slice(b"sent")),
            Ok(())
        );
        assert_eq!(
            test.device.tx,
            vec![send_frame(remote, REMOTE_MAC, b"sent", true)]
        );
        test.device.tx.clear();
    }
    assert_eq!(test.udp.template_frames, 1);
    test.iface.set_ipv4_gateway(None);
    assert_send_error(&mut test, Some(off_subnet), 4, UdpSendError::NoRoute);
    assert_eq!(test.udp.template_frames, 1);
}
