use super::*;
use crate::iface::{UdpConfig, UdpSet};
use crate::phy::{Checksum, RxBuf, TxChecksum};
use crate::socket::tcp;
use std::collections::VecDeque;

const LOCAL: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
const REMOTE: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
const REMOTE_MAC: EthernetAddress = EthernetAddress([2, 0, 0, 0, 0, 2]);

struct RecordingDevice {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<(PacketMeta, Vec<u8>)>,
    caps: DeviceCapabilities,
}

struct FrameRx(Vec<u8>);

impl RxToken for FrameRx {
    fn into_buf(self) -> RxBuf {
        RxBuf::from_vec(self.0)
    }
}

struct RecordingTx<'a> {
    frames: &'a mut Vec<(PacketMeta, Vec<u8>)>,
    meta: PacketMeta,
}

impl TxToken for RecordingTx<'_> {
    fn set_meta(&mut self, meta: PacketMeta) {
        self.meta = meta;
    }

    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut bytes = vec![0xa5; len];
        let result = f(&mut bytes);
        self.frames.push((self.meta, bytes));
        result
    }
}

impl Device for RecordingDevice {
    type RxToken<'a> = FrameRx;
    type TxToken<'a> = RecordingTx<'a>;

    fn receive(&mut self, _: Instant) -> Option<(FrameRx, RecordingTx<'_>)> {
        let bytes = self.rx.pop_front()?;
        Some((
            FrameRx(bytes),
            RecordingTx {
                frames: &mut self.tx,
                meta: PacketMeta::default(),
            },
        ))
    }

    fn transmit(&mut self, _: Instant) -> Option<RecordingTx<'_>> {
        Some(RecordingTx {
            frames: &mut self.tx,
            meta: PacketMeta::default(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.caps.clone()
    }
}

fn setup_recording(offload: bool) -> (Interface, TcpSet<'static>, RecordingDevice) {
    let (mut iface, sockets, device) = setup(Medium::Ethernet);
    iface.inner.caps.checksum.tcp = if offload { Checksum::Rx } else { Checksum::Both };
    iface.inner.caps.checksum.udp = if offload { Checksum::Rx } else { Checksum::Both };
    iface.inner.neighbor_cache.fill(REMOTE.into(), REMOTE_MAC.into(), Instant::ZERO);
    let device = RecordingDevice {
        rx: VecDeque::new(),
        tx: Vec::new(),
        caps: DeviceCapabilities {
            checksum: iface.inner.caps.checksum.clone(),
            ..device.capabilities()
        },
    };
    (iface, sockets, device)
}

#[track_caller]
fn assert_tcp_frames(device: &RecordingDevice, offload: bool) {
    assert!(!device.tx.is_empty());
    for (meta, frame) in &device.tx {
        let ip = Ipv4Packet::new_checked(&frame[14..]).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!(ip.next_header(), IpProtocol::Tcp);
        let expected = offload.then_some(TxChecksum::Tcp {
            ip_header_len: ip.header_len(),
            tcp_header_len: tcp.header_len(),
        });
        assert_eq!(meta.tx_checksum, expected);
        if offload {
            assert_eq!(tcp.checksum(), 0);
        } else {
            assert!(tcp.verify_checksum(&LOCAL.into(), &REMOTE.into()));
        }
    }
}

#[test]
fn tcp_handshake_and_established_template_carry_checksum_metadata() {
    for offload in [true, false] {
        let (mut iface, mut sockets, mut device) = setup_recording(offload);
        let mut socket = tcp::Socket::new(
            tcp::RxBuffer::new(4096),
            tcp::SocketBuffer::new(vec![0; 4096]),
        );
        socket.set_ack_delay(None);
        socket
            .connect(iface.context(), (REMOTE, 80), (LOCAL, 40000))
            .unwrap();
        let handle = sockets.add(socket);
        iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
        assert_tcp_frames(&device, offload);
        assert_eq!(iface.inner.template_frames, 0);
        let ip = Ipv4Packet::new_checked(&device.tx[0].1[14..]).unwrap();
        let syn = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(syn.syn());
        assert!(syn.header_len() > 20);
        let ack = syn.seq_number() + 1;
        let response = TcpRepr {
            src_port: 80,
            dst_port: 40000,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(100),
            ack_number: Some(ack),
            window_len: 4096,
            window_scale: None,
            max_seg_size: Some(512),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let ip = Ipv4Repr {
            src_addr: REMOTE,
            dst_addr: LOCAL,
            next_header: IpProtocol::Tcp,
            payload_len: response.buffer_len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0; 14 + ip.buffer_len() + ip.payload_len];
        let mut eth = EthernetFrame::new_unchecked(&mut bytes);
        eth.set_src_addr(REMOTE_MAC);
        eth.set_dst_addr(iface.inner.hardware_addr.ethernet_or_panic());
        eth.set_ethertype(EthernetProtocol::Ipv4);
        ip.emit(
            &mut Ipv4Packet::new_unchecked(eth.payload_mut()),
            &ChecksumCapabilities::default(),
        );
        response.emit(
            &mut TcpPacket::new_unchecked(&mut eth.payload_mut()[20..]),
            &REMOTE.into(),
            &LOCAL.into(),
            &ChecksumCapabilities::default(),
        );
        device.rx.push_back(bytes);
        device.tx.clear();
        iface.poll_ingress_single(Instant::ZERO, &mut device, &mut sockets);
        assert_eq!(sockets.get(handle).state(), tcp::State::Established);
        iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
        assert_tcp_frames(&device, offload);
        // The handshake-completing ACK is the first template segment (one emit path).
        assert_eq!(iface.inner.template_frames, 1);
        device.tx.clear();
        assert_eq!(sockets.get_mut(handle).send_slice(b"data"), Ok(4));
        iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
        assert_tcp_frames(&device, offload);
        assert_eq!(iface.inner.template_frames, 2);
        let ip = Ipv4Packet::new_checked(&device.tx[0].1[14..]).unwrap();
        assert_eq!(
            TcpPacket::new_checked(ip.payload()).unwrap().payload(),
            b"data"
        );
    }
}

#[test]
fn udp_direct_and_template_carry_checksum_metadata() {
    for offload in [true, false] {
        for tx_checksum in [true, false] {
            let (mut iface, _, mut device) = setup_recording(offload);
            let mut udp = UdpSet::new(1);
            let handle = udp
                .add(UdpConfig {
                    port: 40000,
                    rx_queue: 1,
                    tx_checksum,
                    broadcast: false,
                })
                .unwrap();
            for templates in [0, 1] {
                let target = iface
                    .udp_target(&udp, handle, Some(IpEndpoint::new(REMOTE.into(), 80)), 4)
                    .unwrap();
                assert_eq!(
                    iface.udp_send(&mut device, &mut udp, target, |out| out
                        .copy_from_slice(b"data")),
                    Ok(())
                );
                assert_eq!(udp.template_frames, templates);
                let (meta, bytes) = device.tx.last().unwrap();
                assert_eq!(
                    meta.tx_checksum,
                    offload.then_some(TxChecksum::Udp { ip_header_len: 20 })
                );
                let ip = Ipv4Packet::new_checked(&bytes[14..]).unwrap();
                let packet = UdpPacket::new_checked(ip.payload()).unwrap();
                assert_eq!(packet.payload(), b"data");
                if offload || !tx_checksum {
                    assert_eq!(packet.checksum(), 0);
                } else {
                    assert!(packet.verify_checksum(&LOCAL.into(), &REMOTE.into()));
                }
            }
        }
    }
}

#[test]
fn generic_icmp_and_arp_frames_carry_no_checksum_offload() {
    let (mut iface, _, mut device) = setup_recording(true);
    assert_eq!(PacketMeta::default().tx_checksum, None);
    let icmp = Icmpv4Repr::EchoReply {
        ident: 1,
        seq_no: 2,
        data: b"ping",
    };
    let ip = Ipv4Repr {
        src_addr: LOCAL,
        dst_addr: REMOTE,
        next_header: IpProtocol::Icmp,
        payload_len: icmp.buffer_len(),
        hop_limit: 64,
    };
    let mut meta = PacketMeta::default();
    meta.tx_checksum = Some(TxChecksum::Udp { ip_header_len: 20 });
    iface.inner
        .dispatch_ip(
            device.transmit(Instant::ZERO).unwrap(),
            meta,
            Packet::new_ipv4(ip, IpPayload::Icmpv4(icmp)),
            None,
        )
        .unwrap();
    iface.inner
        .dispatch_arp_request(device.transmit(Instant::ZERO).unwrap(), REMOTE)
        .unwrap();
    assert_eq!(device.tx.len(), 2);
    for (meta, _) in &device.tx {
        assert_eq!(meta.tx_checksum, None);
    }
    let ip = Ipv4Packet::new_checked(&device.tx[0].1[14..]).unwrap();
    assert!(Icmpv4Packet::new_checked(ip.payload()).unwrap().verify_checksum());
    assert_eq!(
        EthernetFrame::new_checked(&device.tx[1].1[..]).unwrap().ethertype(),
        EthernetProtocol::Arp
    );
}
