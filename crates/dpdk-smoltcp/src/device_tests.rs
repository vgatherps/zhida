use super::*;
use crate::eal::with_test_eal;
use crate::port::tests::{
    assert_no_pools, enable_rx_checksum, enable_rx_timestamp, enable_tx_tcp_checksum,
    enable_tx_udp_checksum, in_use, peer_receive, prepare_args, prepare_calls, prepare_packets,
    produce, rx_frame_bytes, tx_calls, FaultGuard, Faults, Fixture,
};
use crate::port::{Offloads, PortError};
use zhida_test_kit::pair::{self, Side};
use zhida_test_kit::pcap::{write_pcap, PcapVdev};
use smoltcp::iface::{Config, Interface, PollIngressSingleResult, TcpSet};
use smoltcp::phy::{
    Checksum, ChecksumCapabilities, Device as _, PacketMeta, RxToken as _, TxChecksum, TxToken as _,
};
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, HardwareAddress, IpAddress,
    IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr,
    TcpSeqNumber, UdpPacket, UdpRepr,
};
use std::cell::Cell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zhida_dpdk_sys::{
    RTE_MBUF_F_RX_IP_CKSUM_BAD, RTE_MBUF_F_RX_IP_CKSUM_GOOD, RTE_MBUF_F_RX_IP_CKSUM_MASK,
    RTE_MBUF_F_RX_L4_CKSUM_BAD, RTE_MBUF_F_RX_L4_CKSUM_GOOD, RTE_MBUF_F_RX_L4_CKSUM_MASK,
};

const NOW: Instant = Instant::ZERO;
const FRAME: usize = 1514;

fn open(eal: &crate::Eal, rx_staging: usize, tx_pending: usize) -> (Fixture, Device) {
    let fixture = Fixture::new();
    let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
    (fixture, Device::new(port, rx_staging, tx_pending))
}

/// Peer drains the TX ring; every buffer must be back before close.
fn finish(fixture: Fixture, device: Device) {
    let port = device.into_port();
    drop(peer_receive(&fixture, 16));
    assert_eq!(in_use(&port), (0, 0));
    port.try_close().unwrap();
    fixture.close().unwrap();
}

fn stage(fixture: &Fixture, device: &mut Device, bytes: &[u8]) {
    produce(fixture, &[rx_frame_bytes(&device.port, bytes)]);
    let staged = device.rx.len();
    assert_eq!(
        device.rx_burst().unwrap(),
        RxBurst {
            accepted: 1,
            rejected: 0,
            rx_ipv4_checksum_bad: 0
        }
    );
    assert_eq!(device.rx.len(), staged + 1);
}

fn pending(device: &Device) -> Vec<Vec<u8>> {
    device.tx.iter().map(|p| p.data().to_vec()).collect()
}

fn send(device: &mut Device, bytes: &[u8]) {
    device
        .transmit(NOW)
        .unwrap()
        .consume(bytes.len(), |buf| buf.copy_from_slice(bytes));
}

const TCP_OFFLOAD: Option<TxChecksum> = Some(TxChecksum::Tcp {
    ip_header_len: 24,
    tcp_header_len: 32,
});

fn send_meta(device: &mut Device, bytes: &[u8], tx_checksum: Option<TxChecksum>) {
    let mut token = device.transmit(NOW).unwrap();
    let mut meta = PacketMeta::default();
    meta.tx_checksum = tx_checksum;
    token.set_meta(meta);
    token.consume(bytes.len(), |buf| buf.copy_from_slice(bytes));
}

fn checksum_syn() -> Vec<u8> {
    let caps = ChecksumCapabilities::default();
    let src = Ipv4Address::new(10, 0, 0, 2);
    let dst = Ipv4Address::new(10, 0, 0, 1);
    let eth = EthernetRepr {
        src_addr: EthernetAddress([0x02, 0, 0, 0, 0, 2]),
        dst_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
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
        payload: &[],
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

fn stage_checksum(fixture: &Fixture, device: &mut Device, bytes: &[u8], flags: u64) {
    let raw = rx_frame_bytes(&device.port, bytes);
    // SAFETY: the producer exclusively owns this live RX-pool mbuf.
    unsafe { (*raw).ol_flags = flags };
    produce(fixture, &[raw]);
    assert_eq!(
        device.rx_burst().unwrap(),
        RxBurst {
            accepted: 1,
            rejected: 0,
            rx_ipv4_checksum_bad: 0
        }
    );
}

fn checksum_meta(fixture: &Fixture, device: &mut Device, flags: u64, verified: (bool, bool)) {
    let bytes = checksum_syn();
    stage_checksum(fixture, device, &bytes, flags);
    let (rx, tx) = device.receive(NOW).unwrap();
    let mut expected = PacketMeta::default();
    expected.ipv4_checksum_verified = verified.0;
    expected.l4_checksum_verified = verified.1;
    assert_eq!(rx.meta(), expected);
    assert_eq!(rx.into_buf().as_slice(), bytes);
    drop(tx);
    assert_eq!(in_use(&device.port), (0, 1));
}

fn checksum_ingress(fixture: &Fixture, device: &mut Device, bytes: &[u8], flags: u64, reply: bool) {
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ethernet(EthernetAddress([
            0x02, 0, 0, 0, 0, 1,
        ]))),
        device,
        NOW,
    );
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(Ipv4Address::new(10, 0, 0, 1).into(), 24))
            .unwrap();
    });
    let mut sockets = TcpSet::new(Vec::new());
    let mut arp = Vec::new();
    arp.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    arp.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    arp.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0x00, 6, 4, 0, 2]);
    arp.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    arp.extend_from_slice(&[10, 0, 0, 2]);
    arp.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    arp.extend_from_slice(&[10, 0, 0, 1]);
    stage(fixture, device, &arp);
    iface.poll_ingress_single(NOW, device, &mut sockets);
    assert!(device.tx.is_empty());
    stage_checksum(fixture, device, bytes, flags);
    assert_ne!(
        iface.poll_ingress_single(NOW, device, &mut sockets),
        PollIngressSingleResult::None
    );
    assert!(device.rx.is_empty());
    assert_eq!(device.tx.len(), usize::from(reply));
    assert_eq!(in_use(&device.port).0, 0);
    if reply {
        let frame = EthernetFrame::new_checked(device.tx.front().unwrap().data()).unwrap();
        assert_eq!(frame.ethertype(), EthernetProtocol::Ipv4);
        let ip = Ipv4Packet::new_checked(frame.payload()).unwrap();
        assert!(ip.verify_checksum());
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let repr = TcpRepr::parse(
            &tcp,
            &IpAddress::Ipv4(ip.src_addr()),
            &IpAddress::Ipv4(ip.dst_addr()),
            &ChecksumCapabilities::default(),
        )
        .unwrap();
        assert_eq!(repr.control, TcpControl::Rst);
        assert_eq!((repr.src_port, repr.dst_port), (80, 49152));
        assert_eq!(repr.ack_number, Some(TcpSeqNumber(2)));
        assert_eq!(device.flush().unwrap(), 1);
        drop(peer_receive(fixture, 16));
    }
}

#[zhida_test_support::pinned_test]
fn good_skips_verify() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        enable_rx_checksum(&mut device.port);
        let good = RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD;
        checksum_meta(&fixture, &mut device, good, (true, true));
        let mut bytes = checksum_syn();
        // Ethernet (14), IPv4 (20), TCP checksum offset (16).
        bytes[14 + 20 + 16] ^= 1;
        checksum_ingress(&fixture, &mut device, &bytes, good, true);
        // Prove IPv4 GOOD independently skips the header check too.
        bytes[14 + 10] ^= 1;
        checksum_ingress(&fixture, &mut device, &bytes, good, true);
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn unknown_still_verified() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        enable_rx_checksum(&mut device.port);
        checksum_meta(&fixture, &mut device, 0, (false, false));
        checksum_meta(
            &fixture,
            &mut device,
            RTE_MBUF_F_RX_IP_CKSUM_GOOD,
            (true, false),
        );
        checksum_meta(
            &fixture,
            &mut device,
            RTE_MBUF_F_RX_L4_CKSUM_GOOD,
            (false, true),
        );
        let mut tcp_bad = checksum_syn();
        tcp_bad[14 + 20 + 16] ^= 1;
        checksum_ingress(&fixture, &mut device, &tcp_bad, 0, false);
        checksum_ingress(
            &fixture,
            &mut device,
            &tcp_bad,
            RTE_MBUF_F_RX_IP_CKSUM_GOOD,
            false,
        );
        let mut ip_bad = checksum_syn();
        ip_bad[14 + 10] ^= 1;
        checksum_ingress(&fixture, &mut device, &ip_bad, 0, false);
        checksum_ingress(
            &fixture,
            &mut device,
            &ip_bad,
            RTE_MBUF_F_RX_L4_CKSUM_GOOD,
            false,
        );
        checksum_ingress(&fixture, &mut device, &checksum_syn(), 0, true);
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn bad_l4_meta_is_not_verified() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        enable_rx_checksum(&mut device.port);
        for (flags, verified) in [
            (RTE_MBUF_F_RX_L4_CKSUM_BAD, (false, false)),
            (RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD, (true, false)),
        ] {
            checksum_meta(&fixture, &mut device, flags, verified);
        }
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn none_is_not_good_or_bad() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        enable_rx_checksum(&mut device.port);
        let none = RTE_MBUF_F_RX_IP_CKSUM_MASK | RTE_MBUF_F_RX_L4_CKSUM_MASK;
        checksum_meta(&fixture, &mut device, none, (false, false));
        checksum_meta(
            &fixture,
            &mut device,
            RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_MASK,
            (true, false),
        );
        checksum_meta(
            &fixture,
            &mut device,
            RTE_MBUF_F_RX_IP_CKSUM_MASK | RTE_MBUF_F_RX_L4_CKSUM_GOOD,
            (false, true),
        );
        let mut bytes = checksum_syn();
        bytes[14 + 20 + 16] ^= 1;
        checksum_ingress(&fixture, &mut device, &bytes, none, false);
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn profile_off_ignores_verdicts() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        let bad = RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD;
        let good = RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD;
        checksum_meta(&fixture, &mut device, bad, (false, false));
        checksum_meta(&fixture, &mut device, good, (false, false));
        checksum_ingress(&fixture, &mut device, &checksum_syn(), bad, true);
        let mut bytes = checksum_syn();
        bytes[14 + 20 + 16] ^= 1;
        checksum_ingress(&fixture, &mut device, &bytes, good, false);
        enable_rx_checksum(&mut device.port);
        checksum_meta(&fixture, &mut device, good, (true, true));
        finish(fixture, device);
    });
}

fn tcp_frame() -> Vec<u8> {
    let mut frame = vec![0; 14 + 24 + 32 + 4];
    frame[12..14].copy_from_slice(&[0x08, 0x00]);
    frame[14] = 0x46;
    frame[16..18].copy_from_slice(&60u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
    frame[30..34].copy_from_slice(&[192, 0, 2, 2]);
    frame[38..40].copy_from_slice(&49152u16.to_be_bytes());
    frame[40..42].copy_from_slice(&80u16.to_be_bytes());
    frame[50] = 0x80;
    frame[51] = 0x10;
    frame[58..70].fill(1);
    frame[70..].copy_from_slice(b"data");
    Ipv4Packet::new_unchecked(&mut frame[14..]).fill_checksum();
    frame
}

fn tx_metadata(packet: &Packet) -> (u64, u64, u64, u64) {
    mbuf_tx_metadata(packet.as_ptr())
}

fn mbuf_tx_metadata(mbuf: *mut zhida_dpdk_sys::rte_mbuf) -> (u64, u64, u64, u64) {
    unsafe {
        let raw = &*mbuf;
        let lengths = &raw.__bindgen_anon_3.__bindgen_anon_1;
        (
            raw.ol_flags(),
            lengths.l2_len(),
            lengths.l3_len(),
            lengths.l4_len(),
        )
    }
}

fn udp_frame() -> Vec<u8> {
    let caps = ChecksumCapabilities::default();
    let udp = UdpRepr {
        src_port: 49152,
        dst_port: 80,
    };
    let ip = Ipv4Repr {
        src_addr: Side::A.ip(),
        dst_addr: Side::B.ip(),
        next_header: IpProtocol::Udp,
        payload_len: udp.header_len() + 4,
        hop_limit: 64,
    };
    let mut bytes = vec![0; 14 + ip.buffer_len() + ip.payload_len];
    let mut eth = EthernetFrame::new_unchecked(&mut bytes);
    EthernetRepr {
        src_addr: Side::A.mac(),
        dst_addr: Side::B.mac(),
        ethertype: EthernetProtocol::Ipv4,
    }
    .emit(&mut eth);
    let mut packet = Ipv4Packet::new_unchecked(eth.payload_mut());
    ip.emit(&mut packet, &caps);
    udp.emit(
        &mut UdpPacket::new_unchecked(packet.payload_mut()),
        &ip.src_addr.into(),
        &ip.dst_addr.into(),
        4,
        |out| out.copy_from_slice(b"data"),
        &caps,
    );
    assert_eq!(packet.header_len(), 20);
    assert_eq!(UdpPacket::new_checked(packet.payload_mut()).unwrap().len(), 12);
    bytes
}

fn poison_tx_pool(device: &mut Device) -> Vec<*mut zhida_dpdk_sys::rte_mbuf> {
    assert!(device.tx.is_empty());
    let mut ids = Vec::new();
    if let Some(packet) = device.spare.as_mut() {
        assert_eq!(packet.data().len(), FRAME);
        packet.data_mut().fill(0xa5);
        ids.push(packet.as_ptr());
    }
    let count = 63usize.checked_sub(ids.len()).expect("TX pool capacity");
    let mut held = Vec::new();
    for _ in 0..count {
        let mut packet = device.port.alloc_tx(FRAME.try_into().unwrap()).unwrap();
        packet.data_mut().fill(0xa5);
        ids.push(packet.as_ptr());
        held.push(packet);
    }
    assert_eq!(in_use(&device.port).1, 63);
    drop(held);
    assert_eq!(in_use(&device.port).1, u32::from(device.spare.is_some()));
    ids
}

fn ones_complement_sum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut words = bytes.chunks_exact(2);
    for word in &mut words {
        sum = sum
            .checked_add(u32::from(u16::from_be_bytes([word[0], word[1]])))
            .expect("TCP checksum sum fits u32");
    }
    if let Some(&last) = words.remainder().first() {
        sum = sum
            .checked_add(u32::from(last) << 8)
            .expect("TCP checksum sum fits u32");
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & 0xffff)
            .checked_add(sum >> 16)
            .expect("TCP checksum fold fits u32");
    }
    u16::try_from(sum).expect("TCP checksum sum is folded")
}

fn capture_socket_frame(
    fixture: &Fixture,
    device: &mut Device,
    offload: bool,
    poisoned: &[*mut zhida_dpdk_sys::rte_mbuf],
) -> Vec<u8> {
    assert_eq!(device.tx.len(), 1);
    let packet = &device.tx[0];
    let raw = packet.as_ptr();
    if !poisoned.is_empty() {
        assert!(poisoned.contains(&raw));
    }
    let ip = Ipv4Packet::new_checked(&packet.data()[14..]).unwrap();
    assert!(ip.verify_checksum());
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    let l4 = u64::from(tcp.header_len());
    if offload {
        assert_eq!(tcp.checksum(), 0);
    }
    let len = packet.data().len();
    assert_eq!(len, 14 + usize::from(ip.total_len()));
    unsafe {
        assert_eq!(usize::from((*raw).data_len()), len);
        assert_eq!(usize::try_from((*raw).pkt_len()).unwrap(), len);
    }
    let metadata = if offload {
        (RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_TCP_CKSUM, 14, 20, l4)
    } else {
        (0, 0, 0, 0)
    };
    assert_eq!(tx_metadata(packet), metadata);
    let calls = prepare_calls();
    let expected_calls = calls.checked_add(u32::from(offload)).unwrap();
    let mut faults = Faults::default();
    faults.tx_accept_limit = Some(0);
    let guard = FaultGuard::new(faults);
    assert_eq!(device.flush(), Ok(0));
    assert_eq!(prepare_calls(), expected_calls);
    assert_eq!(device.flush(), Ok(0));
    assert_eq!(prepare_calls(), expected_calls);
    assert_eq!(tx_metadata(&device.tx[0]), metadata);
    if offload {
        assert_eq!(
            unsafe { zhida_dpdk_sys::dpdk_raw_net_intel_cksum_prepare(raw) },
            0
        );
        let mut ip = Ipv4Packet::new_checked(&mut device.tx[0].data_mut()[14..]).unwrap();
        let completed = !ones_complement_sum(ip.payload_mut());
        TcpPacket::new_checked(ip.payload_mut())
            .unwrap()
            .set_checksum(completed);
    }
    let bytes = device.tx[0].data().to_vec();
    drop(guard);
    assert_eq!(device.flush(), Ok(1));
    assert_eq!(prepare_calls(), expected_calls);
    let received = peer_receive(fixture, 16);
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].as_ptr(), raw);
    assert_eq!(received[0].data(), bytes);
    unsafe {
        assert_eq!(usize::from((*raw).data_len()), len);
        assert_eq!(usize::try_from((*raw).pkt_len()).unwrap(), len);
    }
    drop(received);
    assert_eq!(in_use(&device.port).1, u32::from(device.spare.is_some()));
    bytes
}

fn socket_template_frames(
    eal: &crate::Eal,
    offload: bool,
    poison: bool,
    peer_timestamps: bool,
    terminal: TcpControl,
) -> Vec<Vec<u8>> {
    use smoltcp::socket::tcp::State;
    use smoltcp::wire::{ArpOperation, ArpPacket, ArpRepr, TcpTimestampRepr};

    let (fixture, mut device) = open(eal, 4, 4);
    if offload {
        enable_tx_tcp_checksum(&mut device.port);
    }
    let mut config = Config::new(Side::A.mac().into());
    config.random_seed = 1;
    let mut iface = Interface::new(config, &mut device, NOW);
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(Side::A.ip().into(), 24)).unwrap();
    });
    let mut sockets = TcpSet::new(Vec::new());
    let handle = sockets.add_admitted(
        &pair::tcp_socket_sized(4096),
        1500,
        smoltcp::iface::DropQueue::with_capacity(1, 0),
    );
    sockets.get_mut(handle).set_ack_delay(None);
    let arp = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Reply,
        source_hardware_addr: Side::B.mac(),
        source_protocol_addr: Side::B.ip(),
        target_hardware_addr: Side::A.mac(),
        target_protocol_addr: Side::A.ip(),
    };
    let mut bytes = vec![0; 14 + arp.buffer_len()];
    let mut eth = EthernetFrame::new_unchecked(&mut bytes);
    eth.set_src_addr(Side::B.mac());
    eth.set_dst_addr(Side::A.mac());
    eth.set_ethertype(EthernetProtocol::Arp);
    arp.emit(&mut ArpPacket::new_unchecked(eth.payload_mut()));
    stage(&fixture, &mut device, &bytes);
    iface.poll_ingress_single(NOW, &mut device, &mut sockets);
    assert!(device.tx.is_empty());
    sockets
        .get_mut(handle)
        .connect(iface.context(), (Side::B.ip(), 80), (Side::A.ip(), 49152))
        .unwrap();
    iface.poll_egress(NOW, &mut device, &mut sockets);
    let syn = capture_socket_frame(&fixture, &mut device, offload, &[]);
    let syn = pair::segment(&syn, Side::A);
    assert_eq!(syn.control, TcpControl::Syn);
    let local_seq = syn.seq_number + 1;
    let mut reply = TcpRepr {
        src_port: 80,
        dst_port: 49152,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(100),
        ack_number: Some(local_seq),
        window_len: 4096,
        window_scale: None,
        max_seg_size: Some(512),
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: peer_timestamps.then(|| TcpTimestampRepr::new(456, 1234)),
        payload: &[],
    };
    stage(&fixture, &mut device, &pair::tcp_frame(Side::B, &reply));
    iface.poll_ingress_single(NOW, &mut device, &mut sockets);
    assert_eq!(sockets.get(handle).state(), State::Established);
    assert!(device.tx.is_empty());
    iface.poll_egress(NOW, &mut device, &mut sockets);
    let warm = capture_socket_frame(&fixture, &mut device, offload, &[]);
    let warm = pair::segment(&warm, Side::A);
    assert_eq!(warm.control, TcpControl::None);
    assert_eq!(warm.ack_number, Some(TcpSeqNumber(101)));
    assert!(warm.payload.is_empty());
    assert_eq!(warm.timestamp, None);

    reply.control = TcpControl::None;
    reply.seq_number = TcpSeqNumber(101);
    reply.max_seg_size = None;
    reply.payload = b"x";
    stage(&fixture, &mut device, &pair::tcp_frame(Side::B, &reply));
    iface.poll_ingress_single(NOW, &mut device, &mut sockets);
    assert!(device.tx.is_empty());
    assert_eq!(sockets.get(handle).recv_queue(), 1);
    let payload = if peer_timestamps {
        b"odd".as_slice()
    } else {
        b"even".as_slice()
    };
    let mut frames = Vec::new();
    let mut next_seq = local_seq;
    for (control, data) in [
        (TcpControl::None, b"".as_slice()),
        (TcpControl::Psh, payload),
        (terminal, b"".as_slice()),
    ] {
        assert_eq!(sockets.get(handle).state(), State::Established);
        match control {
            TcpControl::None => (),
            TcpControl::Psh => {
                assert_eq!(sockets.get_mut(handle).send_slice(data), Ok(data.len()));
            }
            TcpControl::Fin => sockets.get_mut(handle).close(),
            TcpControl::Rst => sockets.get_mut(handle).abort(),
            _ => unreachable!(),
        }
        let poisoned = if poison {
            poison_tx_pool(&mut device)
        } else {
            Vec::new()
        };
        iface.poll_egress(NOW, &mut device, &mut sockets);
        let bytes = capture_socket_frame(&fixture, &mut device, offload, &poisoned);
        assert_eq!(bytes.len(), 54 + data.len());
        let tcp = pair::segment(&bytes, Side::A);
        assert_eq!((tcp.control, tcp.payload), (control, data));
        assert_eq!(tcp.ack_number, Some(TcpSeqNumber(102)));
        assert_eq!(tcp.seq_number, next_seq);
        assert_eq!(tcp.timestamp, None);
        assert_eq!(tcp.header_len(), 20);
        next_seq = next_seq + data.len();
        frames.push(bytes);
    }
    // The socket still holds the unread "x" frame; dropping it returns that mbuf.
    drop(sockets);
    finish(fixture, device);
    frames
}

#[zhida_test_support::pinned_test]
fn template_socket_frames_complete_to_software_checksum() {
    with_test_eal(|eal| {
        for timestamps in [false, true] {
            for terminal in [TcpControl::Fin, TcpControl::Rst] {
                let software = socket_template_frames(eal, false, false, timestamps, terminal);
                let offload = socket_template_frames(eal, true, false, timestamps, terminal);
                assert_eq!(offload, software);
            }
        }
    });
}

#[zhida_test_support::pinned_test]
fn template_emit_overwrites_reused_mbuf_bytes() {
    with_test_eal(|eal| {
        for timestamps in [false, true] {
            for terminal in [TcpControl::Fin, TcpControl::Rst] {
                let software = socket_template_frames(eal, false, false, timestamps, terminal);
                let reused = socket_template_frames(eal, false, true, timestamps, terminal);
                assert_eq!(reused, software);
            }
        }
    });
}

#[zhida_test_support::pinned_test]
fn tx_metadata_and_one_prepare_for_mixed_frames() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 8);
        enable_tx_tcp_checksum(&mut device.port);
        enable_tx_udp_checksum(&mut device.port);
        let calls = prepare_calls();
        let recorded = prepare_packets().len();
        let tcp = tcp_frame();
        let udp = udp_frame();
        let mut options = udp[..34].to_vec();
        options.extend_from_slice(&[1; 4]);
        options.extend_from_slice(&udp[34..]);
        options[14] = 0x46;
        let total = u16::from_be_bytes([udp[16], udp[17]]) + 4;
        options[16..18].copy_from_slice(&total.to_be_bytes());
        Ipv4Packet::new_unchecked(&mut options[14..]).fill_checksum();
        let mut arp = vec![0; 42];
        arp[12..14].copy_from_slice(&[0x08, 0x06]);
        let mut icmp = udp.clone();
        icmp[23] = 1;
        send_meta(&mut device, &tcp, TCP_OFFLOAD);
        send_meta(&mut device, &udp, Some(TxChecksum::Udp { ip_header_len: 20 }));
        send_meta(&mut device, &options, Some(TxChecksum::Udp { ip_header_len: 24 }));
        send(&mut device, &arp);
        send(&mut device, &icmp);
        let metadata = [
            (RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_TCP_CKSUM, 14, 24, 32),
            (RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_UDP_CKSUM, 14, 20, 8),
            (RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_UDP_CKSUM, 14, 24, 8),
            (0, 0, 0, 0),
            (0, 0, 0, 0),
        ];
        for (packet, expected) in device.tx.iter().zip(metadata) {
            assert_eq!(tx_metadata(packet), expected);
        }
        let ids: Vec<_> = device.tx.iter().map(|packet| packet.as_ptr() as usize).collect();
        let mut faults = Faults::default();
        faults.tx_accept_limit = Some(0);
        let guard = FaultGuard::new(faults);
        assert_eq!(device.flush(), Ok(0));
        assert_eq!(prepare_calls(), calls + 1);
        assert_eq!(prepare_args(), (device.port.port_id(), 0, 5));
        assert_eq!(&prepare_packets()[recorded..], &[ids]);
        assert_eq!(pending(&device), [tcp, udp, options, arp, icmp]);
        assert_eq!(device.flush(), Ok(0));
        assert_eq!(prepare_calls(), calls + 1);
        drop(guard);
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn tcp_only_profile_prepares_complete_udp_without_offload() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        enable_tx_tcp_checksum(&mut device.port);
        let calls = prepare_calls();
        let frame = udp_frame();
        send(&mut device, &frame);
        let mut faults = Faults::default();
        faults.tx_accept_limit = Some(0);
        let guard = FaultGuard::new(faults);
        assert_eq!(device.flush(), Ok(0));
        assert_eq!(tx_metadata(&device.tx[0]), (0, 0, 0, 0));
        assert_eq!(device.tx[0].data(), frame);
        assert_eq!(prepare_calls(), calls + 1);
        drop(guard);
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn tx_profile_off_leaves_complete_frames_untouched() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        let frame = tcp_frame();
        let calls = prepare_calls();
        send(&mut device, &frame);
        assert_eq!(tx_metadata(&device.tx[0]), (0, 0, 0, 0));
        let mut faults = Faults::default();
        faults.tx_accept_limit = Some(0);
        let guard = FaultGuard::new(faults);
        assert_eq!(device.flush(), Ok(0));
        assert_eq!(tx_metadata(&device.tx[0]), (0, 0, 0, 0));
        assert_eq!(device.tx[0].data(), frame);
        assert_eq!(prepare_calls(), calls);
        drop(guard);
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn dropped_tx_metadata_and_spare_flags_do_not_reach_next_frame() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        enable_tx_tcp_checksum(&mut device.port);
        let mut token = device.transmit(NOW).unwrap();
        let raw = token.packet.as_ref().unwrap().as_ptr();
        let mut meta = PacketMeta::default();
        meta.tx_checksum = TCP_OFFLOAD;
        token.set_meta(meta);
        unsafe {
            (*raw).set_ol_flags(RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_TCP_CKSUM);
            (*raw).set_tx_offload_lengths(14, 24, 32);
        }
        drop(token);
        send(&mut device, b"complete frame");
        assert_eq!(device.tx[0].as_ptr(), raw);
        assert_eq!(device.tx[0].data(), b"complete frame");
        assert_eq!(tx_metadata(&device.tx[0]), (0, 0, 0, 0));
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn tx_metadata_requires_matching_port_profile() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        for (offload, protocol) in [
            (TCP_OFFLOAD, "TCP"),
            (Some(TxChecksum::Udp { ip_header_len: 20 }), "UDP"),
        ] {
            let panic = catch_unwind(AssertUnwindSafe(|| {
                send_meta(&mut device, b"frame", offload)
            })).unwrap_err();
            let message = panic.downcast_ref::<String>().unwrap();
            assert!(message.contains(&format!("port {}:", device.port.port_id())));
            assert!(message.contains(&format!("{protocol} TX offload metadata without its profile")));
            assert_eq!(device.pending(), 0);
            assert_eq!(in_use(&device.port), (0, 0));
        }
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn flush_prepares_each_range_once() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        enable_tx_tcp_checksum(&mut device.port);
        let mut faults = Faults::default();
        faults.tx_accept_limit = Some(0);
        let guard = FaultGuard::new(faults);
        let calls = prepare_calls();
        let frame = tcp_frame();
        send_meta(&mut device, &frame, TCP_OFFLOAD);
        send_meta(&mut device, &frame, TCP_OFFLOAD);
        assert_eq!(device.flush(), Ok(0));
        assert_eq!(prepare_calls(), calls + 1);
        assert_eq!(device.pending(), 2);
        assert_eq!(device.flush(), Ok(0));
        assert_eq!(prepare_calls(), calls + 1);
        assert_eq!(device.pending(), 2);
        send_meta(&mut device, &frame, TCP_OFFLOAD);
        assert_eq!(device.flush(), Ok(0));
        assert_eq!(prepare_calls(), calls + 2);
        assert_eq!(device.pending(), 3);
        drop(guard);
        assert_eq!(device.flush(), Ok(3));
        assert_eq!(prepare_calls(), calls + 2);
        assert!(device.tx.is_empty());
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn flush_prepares_once_across_partial_bursts() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        enable_tx_tcp_checksum(&mut device.port);
        let frames: Vec<_> = (1..=5u8)
            .map(|value| {
                let mut frame = tcp_frame();
                frame[70] = value;
                frame
            })
            .collect();
        for frame in &frames[..3] {
            send_meta(&mut device, frame, TCP_OFFLOAD);
        }
        let mut faults = Faults::default();
        faults.tx_accept_limit = Some(1);
        let guard = FaultGuard::new(faults);
        let calls = prepare_calls();
        let recorded = prepare_packets().len();
        let initial_ids: Vec<_> = device.tx.iter().map(|packet| packet.as_ptr() as usize).collect();
        let bursts = tx_calls();
        let metadata = (RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_TCP_CKSUM, 14, 24, 32);
        assert_eq!(device.flush(), Ok(1));
        assert_eq!(device.pending(), 2);
        assert_eq!(prepare_calls(), calls + 1);
        assert_eq!(&prepare_packets()[recorded..], &[initial_ids]);
        assert_eq!(tx_calls(), bursts + 1);
        assert_eq!(pending(&device).as_slice(), &frames[1..3]);
        send_meta(&mut device, &frames[3], TCP_OFFLOAD);
        let new_id = device.tx.back().unwrap().as_ptr() as usize;
        assert_eq!(tx_metadata(&device.tx[0]), metadata);
        assert_eq!(tx_metadata(&device.tx[1]), metadata);
        assert_eq!(tx_metadata(&device.tx[2]), metadata);
        assert_eq!(device.flush(), Ok(1));
        assert_eq!(device.pending(), 2);
        assert_eq!(prepare_calls(), calls + 2);
        assert_eq!(&prepare_packets()[recorded + 1..], &[vec![new_id]]);
        assert_eq!(tx_calls(), bursts + 2);
        assert_eq!(pending(&device).as_slice(), &frames[2..4]);
        assert_eq!(tx_metadata(&device.tx[0]), metadata);
        assert_eq!(tx_metadata(&device.tx[1]), metadata);
        drop(guard);
        assert_eq!(device.flush(), Ok(2));
        assert_eq!(prepare_calls(), calls + 2);
        assert_eq!(&prepare_packets()[recorded + 1..], &[vec![new_id]]);
        assert_eq!(tx_calls(), bursts + 3);
        assert!(device.tx.is_empty());
        send_meta(&mut device, &frames[4], TCP_OFFLOAD);
        let last_id = device.tx.back().unwrap().as_ptr() as usize;
        assert_eq!(tx_metadata(&device.tx[0]), metadata);
        faults.tx_accept_limit = Some(0);
        let guard = FaultGuard::new(faults);
        assert_eq!(device.flush(), Ok(0));
        assert_eq!(device.pending(), 1);
        assert_eq!(prepare_calls(), calls + 3);
        assert_eq!(&prepare_packets()[recorded + 2..], &[vec![last_id]]);
        assert_eq!(tx_calls(), bursts + 4);
        assert_eq!(tx_metadata(&device.tx[0]), metadata);
        drop(guard);
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn capabilities_follow_tx_profile() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        assert!(matches!(device.capabilities().checksum.tcp, Checksum::Both));
        assert!(matches!(device.capabilities().checksum.udp, Checksum::Both));
        enable_tx_udp_checksum(&mut device.port);
        let caps = device.capabilities();
        assert!(matches!(caps.checksum.udp, Checksum::Rx));
        assert!(matches!(caps.checksum.tcp, Checksum::Both));
        enable_tx_tcp_checksum(&mut device.port);
        let caps = device.capabilities();
        assert!(matches!(caps.checksum.tcp, Checksum::Rx));
        assert!(matches!(caps.checksum.udp, Checksum::Rx));
        assert!(matches!(caps.checksum.ipv4, Checksum::Both));
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn wrapped_flush_prepares_both_unprepared_parts_once() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 8);
        enable_tx_tcp_checksum(&mut device.port);
        assert_eq!(device.tx.capacity(), 8);
        let frame = tcp_frame();
        for _ in 0..6 {
            send_meta(&mut device, &frame, TCP_OFFLOAD);
        }
        let mut faults = Faults::default();
        faults.tx_accept_limit = Some(3);
        let guard = FaultGuard::new(faults);
        assert_eq!(device.flush(), Ok(3));
        drop(guard);
        assert_eq!(device.prepared, 3);
        for _ in 0..5 {
            send_meta(&mut device, &frame, TCP_OFFLOAD);
        }
        let (front, back) = device.tx.as_slices();
        assert_eq!((front.len(), back.len()), (5, 3));
        let ids: Vec<_> = device.tx.iter().skip(3)
            .map(|packet| packet.as_ptr() as usize).collect();
        faults.tx_prepare_limit = Some(2);
        let guard = FaultGuard::new(faults);
        let panic = catch_unwind(AssertUnwindSafe(|| device.flush())).unwrap_err();
        let message = panic.downcast_ref::<String>().unwrap();
        assert!(message.contains("TX checksum preparation refused at frame 4"));
        assert!(message.contains(&format!("port {}:", device.port.port_id())));
        assert!(message.contains("rte_errno"));
        assert_eq!(device.prepared, 3);
        drop(guard);
        faults.tx_prepare_limit = None;
        let calls = prepare_calls();
        let recorded = prepare_packets().len();
        faults.tx_accept_limit = Some(0);
        let guard = FaultGuard::new(faults);
        assert_eq!(device.flush(), Ok(0));
        assert_eq!(prepare_calls(), calls + 2);
        assert_eq!(
            &prepare_packets()[recorded..],
            &[ids[..2].to_vec(), ids[2..].to_vec()]
        );
        assert_eq!(device.prepared, 8);
        assert_eq!(device.flush(), Ok(0));
        assert_eq!(prepare_calls(), calls + 2);
        drop(guard);
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn prepare_refusal_panics_in_flush() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        enable_tx_tcp_checksum(&mut device.port);
        let mut arp = vec![0; 42];
        arp[12..14].copy_from_slice(&[0x08, 0x06]);
        send(&mut device, &arp);
        let frame = tcp_frame();
        send_meta(&mut device, &frame, TCP_OFFLOAD);
        let pending_before = pending(&device);
        let used = in_use(&device.port);
        let mut faults = Faults::default();
        faults.tx_prepare_limit = Some(1);
        let guard = FaultGuard::new(faults);
        let calls = prepare_calls();
        let panic = catch_unwind(AssertUnwindSafe(|| device.flush())).unwrap_err();
        let message = panic.downcast_ref::<String>().unwrap();
        assert!(message.contains(&format!("port {}:", device.port.port_id())));
        assert!(message.contains("rte_errno"));
        assert!(message.contains("TX checksum preparation refused at frame 1"));
        assert_eq!(prepare_calls(), calls + 1);
        assert_eq!(prepare_args(), (device.port.port_id(), 0, 2));
        assert_eq!(device.tx.len(), pending_before.len());
        assert_eq!(pending(&device), pending_before);
        assert_eq!(in_use(&device.port), used);
        assert!(device.spare.is_none());
        drop(guard);
        finish(fixture, device);
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn udp_prepare_refusal_panics_in_flush() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        enable_tx_udp_checksum(&mut device.port);
        let frame = udp_frame();
        send_meta(&mut device, &frame, Some(TxChecksum::Udp { ip_header_len: 20 }));
        let used = in_use(&device.port);
        let mut faults = Faults::default();
        faults.tx_prepare_refuse = true;
        let guard = FaultGuard::new(faults);
        let calls = prepare_calls();
        let panic = catch_unwind(AssertUnwindSafe(|| device.flush())).unwrap_err();
        let message = panic.downcast_ref::<String>().unwrap();
        assert!(message.starts_with(&format!("port {}:", device.port.port_id())));
        assert!(message.contains("TX checksum preparation refused at frame 0, rte_errno"));
        assert_eq!(prepare_calls(), calls + 1);
        assert_eq!(prepare_args(), (device.port.port_id(), 0, 1));
        assert_eq!(pending(&device), [frame]);
        assert_eq!(in_use(&device.port), used);
        assert!(device.spare.is_none());
        drop(guard);
        finish(fixture, device);
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn udp_frames_without_metadata_are_not_parsed() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        enable_tx_udp_checksum(&mut device.port);
        let mut mf = udp_frame();
        mf[20] = 0x20;
        let mut offset = udp_frame();
        offset[21] = 1;
        let mut truncated = udp_frame();
        truncated.truncate(41);
        let mut ipv6 = udp_frame();
        ipv6[12..14].copy_from_slice(&[0x86, 0xdd]);
        for frame in [mf, offset, truncated, ipv6] {
            let calls = prepare_calls();
            send(&mut device, &frame);
            assert_eq!(tx_metadata(&device.tx[0]), (0, 0, 0, 0));
            assert_eq!(device.flush(), Ok(1));
            assert_eq!(prepare_calls(), calls + 1);
            let received = peer_receive(&fixture, 16);
            assert_eq!(received.len(), 1);
            assert_eq!(received[0].data(), frame);
            assert_eq!(mbuf_tx_metadata(received[0].as_ptr()), (0, 0, 0, 0));
            drop(received);
            assert_eq!(in_use(&device.port), (0, 0));
        }
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn prepared_frames_return_to_pool_after_flush_panic() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        enable_tx_tcp_checksum(&mut device.port);
        let frame_a = tcp_frame();
        let mut frame_b = frame_a.clone();
        frame_b[70] = 2;
        send_meta(&mut device, &frame_a, TCP_OFFLOAD);
        send_meta(&mut device, &frame_b, TCP_OFFLOAD);
        let calls = prepare_calls();
        let bursts = tx_calls();
        let used = in_use(&device.port);
        assert_eq!(used, (0, 2));
        let mut faults = Faults::default();
        faults.tx_prepare_limit = Some(1);
        let guard = FaultGuard::new(faults);
        let panic = catch_unwind(AssertUnwindSafe(|| device.flush())).unwrap_err();
        let message = panic.downcast_ref::<String>().unwrap();
        assert!(message.contains("TX checksum preparation refused at frame 1"), "{message}");
        assert_eq!(prepare_calls(), calls + 1);
        assert_eq!(tx_calls(), bursts);
        assert_eq!(device.pending(), 2);
        assert_eq!(pending(&device), [frame_a, frame_b]);
        assert_eq!(
            tx_metadata(&device.tx[0]),
            (RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_TCP_CKSUM, 14, 24, 32)
        );
        assert_eq!(tx_metadata(&device.tx[1]), tx_metadata(&device.tx[0]));
        assert_eq!(in_use(&device.port), used);
        drop(guard);
        finish(fixture, device);
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn complete_frames_without_metadata_ignore_header_shape() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        enable_tx_tcp_checksum(&mut device.port);
        let cases = [
            (14, 0x44),
            (14, 0x4f),
            (50, 0x40),
            (50, 0xf0),
            (13, 0xdd),
            (14, 0x66),
            (20, 0x20),
            (21, 0x01),
        ];
        let mut frames = vec![vec![0; 13]];
        for (offset, value) in cases {
            let mut frame = tcp_frame();
            if offset == 13 {
                frame[12] = 0x86;
            }
            frame[offset] = value;
            if offset == 14 && value == 0x4f {
                frame.truncate(70);
            }
            frames.push(frame);
        }
        for frame in frames {
            let calls = prepare_calls();
            send(&mut device, &frame);
            assert_eq!(tx_metadata(&device.tx[0]), (0, 0, 0, 0));
            assert_eq!(device.flush(), Ok(1));
            assert_eq!(prepare_calls(), calls + 1);
            let received = peer_receive(&fixture, 16);
            assert_eq!(received.len(), 1);
            assert_eq!(received[0].data(), frame);
            assert_eq!(mbuf_tx_metadata(received[0].as_ptr()), (0, 0, 0, 0));
            drop(received);
            assert_eq!(in_use(&device.port), (0, 0));
        }
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn udp_send_with_offload_writes_zero_and_flags_frame() {
    use smoltcp::iface::{UdpConfig, UdpSet};
    use smoltcp::wire::{ArpOperation, ArpPacket, ArpRepr, IpEndpoint};

    with_test_eal(|eal| {
        for (offload, tx_checksum) in [(true, true), (true, false), (false, true)] {
            let (fixture, mut device) = open(eal, 4, 4);
            if offload {
                enable_tx_udp_checksum(&mut device.port);
            }
            let mut config = Config::new(Side::A.mac().into());
            config.random_seed = 1;
            let mut iface = Interface::new(config, &mut device, NOW);
            iface.update_ip_addrs(|addrs| {
                addrs.push(IpCidr::new(Side::A.ip().into(), 24)).unwrap();
            });
            let arp = ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr: Side::B.mac(),
                source_protocol_addr: Side::B.ip(),
                target_hardware_addr: Side::A.mac(),
                target_protocol_addr: Side::A.ip(),
            };
            let mut bytes = vec![0; 14 + arp.buffer_len()];
            let mut eth = EthernetFrame::new_unchecked(&mut bytes);
            eth.set_src_addr(Side::B.mac());
            eth.set_dst_addr(Side::A.mac());
            eth.set_ethertype(EthernetProtocol::Arp);
            arp.emit(&mut ArpPacket::new_unchecked(eth.payload_mut()));
            stage(&fixture, &mut device, &bytes);
            let mut tcp = TcpSet::new(Vec::new());
            iface.poll_ingress_single(NOW, &mut device, &mut tcp);
            assert!(device.tx.is_empty());
            let mut udp = UdpSet::new(1);
            let handle = udp
                .add(UdpConfig {
                    port: 49152,
                    rx_queue: 1,
                    tx_checksum,
                    broadcast: false,
                })
                .unwrap();
            let payload = b"datagram";
            let target = iface
                .udp_target(
                    &udp,
                    handle,
                    Some(IpEndpoint::new(Side::B.ip().into(), 80)),
                    payload.len(),
                )
                .unwrap();
            assert_eq!(
                iface.udp_send(&mut device, &mut udp, target, |out| out
                    .copy_from_slice(payload)),
                Ok(())
            );
            let expected = if offload {
                (RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_UDP_CKSUM, 14, 20, 8)
            } else {
                (0, 0, 0, 0)
            };
            assert_eq!(device.pending(), 1);
            let ip = Ipv4Packet::new_checked(&device.tx[0].data()[14..]).unwrap();
            assert!(ip.verify_checksum());
            let packet = UdpPacket::new_checked(ip.payload()).unwrap();
            assert_eq!(packet.payload(), payload);
            if offload {
                assert_eq!(packet.checksum(), 0);
            } else {
                assert_ne!(packet.checksum(), 0);
                assert!(packet.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into()));
            }
            assert_eq!(tx_metadata(&device.tx[0]), expected);
            let calls = prepare_calls();
            let mut faults = Faults::default();
            faults.tx_accept_limit = Some(0);
            let guard = FaultGuard::new(faults);
            assert_eq!(device.flush(), Ok(0));
            assert_eq!(tx_metadata(&device.tx[0]), expected);
            assert_eq!(prepare_calls(), calls + u32::from(offload));
            if offload {
                assert_eq!(prepare_args(), (device.port.port_id(), 0, 1));
                let raw = device.tx[0].as_ptr();
                assert_eq!(
                    unsafe { zhida_dpdk_sys::dpdk_raw_net_intel_cksum_prepare(raw) },
                    0
                );
                let mut ip = Ipv4Packet::new_checked(&mut device.tx[0].data_mut()[14..]).unwrap();
                let completed = !ones_complement_sum(ip.payload_mut());
                UdpPacket::new_checked(ip.payload_mut()).unwrap().set_checksum(completed);
            }
            let ip = Ipv4Packet::new_checked(&device.tx[0].data()[14..]).unwrap();
            assert!(ip.verify_checksum());
            let packet = UdpPacket::new_checked(ip.payload()).unwrap();
            assert_ne!(packet.checksum(), 0);
            assert!(packet.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into()));
            assert_eq!(packet.payload(), payload);
            drop(guard);
            assert_eq!(device.flush(), Ok(1));
            assert_eq!(prepare_calls(), calls + u32::from(offload));
            finish(fixture, device);
        }
    });
}

#[zhida_test_support::pinned_test]
fn udp_template_frames_match_generic_and_flags() {
    use smoltcp::iface::{UdpConfig, UdpSet};
    use smoltcp::wire::{ArpOperation, ArpPacket, ArpRepr, IpEndpoint};

    with_test_eal(|eal| {
        for (offload, tx_checksum) in [(true, true), (true, false), (false, true), (false, false)] {
            let (fixture, mut device) = open(eal, 4, 4);
            if offload {
                enable_tx_udp_checksum(&mut device.port);
            }
            let mut config = Config::new(Side::A.mac().into());
            config.random_seed = 1;
            let mut iface = Interface::new(config, &mut device, NOW);
            iface.update_ip_addrs(|addrs| {
                addrs.push(IpCidr::new(Side::A.ip().into(), 24)).unwrap();
            });
            let arp = ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr: Side::B.mac(),
                source_protocol_addr: Side::B.ip(),
                target_hardware_addr: Side::A.mac(),
                target_protocol_addr: Side::A.ip(),
            };
            let mut bytes = vec![0; 14 + arp.buffer_len()];
            let mut eth = EthernetFrame::new_unchecked(&mut bytes);
            eth.set_src_addr(Side::B.mac());
            eth.set_dst_addr(Side::A.mac());
            eth.set_ethertype(EthernetProtocol::Arp);
            arp.emit(&mut ArpPacket::new_unchecked(eth.payload_mut()));
            stage(&fixture, &mut device, &bytes);
            let mut tcp = TcpSet::new(Vec::new());
            iface.poll_ingress_single(NOW, &mut device, &mut tcp);
            assert!(device.tx.is_empty());
            let mut udp = UdpSet::new(1);
            let handle = udp
                .add(UdpConfig {
                    port: 49152,
                    rx_queue: 1,
                    tx_checksum,
                    broadcast: false,
                })
                .unwrap();
            let payload = b"datagram";
            for _ in 0..2 {
                let target = iface
                    .udp_target(
                        &udp,
                        handle,
                        Some(IpEndpoint::new(Side::B.ip().into(), 80)),
                        payload.len(),
                    )
                    .unwrap();
                assert_eq!(
                    iface.udp_send(&mut device, &mut udp, target, |out| out
                        .copy_from_slice(payload)),
                    Ok(())
                );
            }
            let expected = if offload {
                (RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_UDP_CKSUM, 14, 20, 8)
            } else {
                (0, 0, 0, 0)
            };
            assert_eq!(device.pending(), 2);
            assert_eq!(device.tx[0].data(), device.tx[1].data());
            for frame in &device.tx {
                let ip = Ipv4Packet::new_checked(&frame.data()[14..]).unwrap();
                assert!(ip.verify_checksum());
                let packet = UdpPacket::new_checked(ip.payload()).unwrap();
                assert_eq!(packet.payload(), payload);
                if offload || !tx_checksum {
                    assert_eq!(packet.checksum(), 0);
                } else {
                    assert_ne!(packet.checksum(), 0);
                    assert!(packet.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into()));
                }
                assert_eq!(tx_metadata(frame), expected);
            }
            let calls = prepare_calls();
            let mut faults = Faults::default();
            faults.tx_accept_limit = Some(0);
            let guard = FaultGuard::new(faults);
            assert_eq!(device.flush(), Ok(0));
            assert_eq!(device.pending(), 2);
            assert_eq!(tx_metadata(&device.tx[0]), expected);
            assert_eq!(tx_metadata(&device.tx[1]), expected);
            assert_eq!(prepare_calls(), calls + u32::from(offload));
            if offload {
                assert_eq!(prepare_args(), (device.port.port_id(), 0, 2));
            }
            drop(guard);
            assert_eq!(device.flush(), Ok(2));
            assert_eq!(prepare_calls(), calls + u32::from(offload));
            finish(fixture, device);
        }
    });
}

#[zhida_test_support::pinned_test]
fn hardware_stamp_reaches_rx_buf() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        enable_rx_timestamp(&mut device.port);
        let field = device.port.rx_timestamp_field().unwrap();
        check_rx_timestamp(&fixture, &mut device, field, true, 0xfedc_ba98_7654_3210);
        finish(fixture, device);
        assert_no_pools();
    });
}

struct PcapFiles {
    dir: PathBuf,
    rx: PathBuf,
    tx: PathBuf,
}

impl PcapFiles {
    fn new(frame: &[u8]) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "zhida-pcap-{}-{time}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let files = Self {
            rx: dir.join("rx.pcap"),
            tx: dir.join("tx.pcap"),
            dir,
        };
        write_pcap(&files.rx, &[(1, 2, frame), (3, 4, frame)]).unwrap();
        files
    }
}

impl Drop for PcapFiles {
    fn drop(&mut self) {
        let result = std::fs::remove_dir_all(&self.dir);
        if !std::thread::panicking() {
            result.unwrap();
        }
    }
}

fn check_pcap_rx_timestamp(eal: &crate::Eal, enabled: bool) {
    let bytes = udp_frame();
    let files = PcapFiles::new(&bytes);
    let pcap = PcapVdev::new(c"net_pcap_rx_timestamp", &files.rx, &files.tx);
    // SAFETY: pcap owns this newly created ethdev on the EAL owner thread;
    // Port::open preserves the production pool contract.
    let mut port = unsafe { Port::open(eal, Fixture::config_for_port(pcap.port_id())) }.unwrap();
    assert!(port.rx_timestamp_field().is_none());
    if enabled {
        enable_rx_timestamp(&mut port);
    }
    let mut device = Device::new(port, 4, 4);
    let mut offset = -1;
    let mut flag = 0;
    // SAFETY: both output pointers are valid; this retrieves the registration
    // net_pcap made at probe without enabling timestamp reads on the Port.
    assert_eq!(
        unsafe { zhida_dpdk_sys::rte_mbuf_dyn_rx_timestamp_register(&mut offset, &mut flag) },
        0
    );
    assert!(offset >= 0);
    assert_ne!(flag, 0);
    assert_eq!(
        device.rx_burst().unwrap(),
        RxBurst {
            accepted: 2,
            rejected: 0,
            rx_ipv4_checksum_bad: 0,
        }
    );
    assert_eq!(in_use(&device.port).0, 2);
    for packet in &device.rx {
        // SAFETY: the staged Packet owns this live mbuf.
        assert_ne!(unsafe { (*packet.as_ptr()).ol_flags } & flag, 0);
    }
    for (index, stamp) in [1_000_002, 3_000_004].into_iter().enumerate() {
        let (rx, tx) = device.receive(NOW).unwrap();
        let frame = rx.into_buf();
        assert_eq!(frame.rx_timestamp(), if enabled { stamp } else { 0 });
        assert_eq!(frame.as_slice(), bytes);
        drop(tx);
        assert_eq!(in_use(&device.port).0, 2 - index as u32);
        drop(frame);
        assert_eq!(in_use(&device.port).0, 1 - index as u32);
    }
    assert!(device.receive(NOW).is_none());
    assert_eq!(device.rx_burst().unwrap().accepted, 0);
    let port = device.into_port();
    assert_eq!(in_use(&port), (0, 0));
    port.try_close().unwrap();
    pcap.close();
    assert_no_pools();
}

#[zhida_test_support::pinned_test]
fn pcap_pmd_stamp_reaches_rx_buf() {
    with_test_eal(|eal| check_pcap_rx_timestamp(eal, true));
}

#[zhida_test_support::pinned_test]
fn pcap_pmd_stamp_ignored_when_off() {
    with_test_eal(|eal| check_pcap_rx_timestamp(eal, false));
}

#[zhida_test_support::pinned_test]
fn pcap_hardware_open_refused() {
    with_test_eal(|eal| {
        let files = PcapFiles::new(&udp_frame());
        let pcap = PcapVdev::new(c"net_pcap_timestamp_refused", &files.rx, &files.tx);
        let mut config = Fixture::config_for_port(pcap.port_id());
        config.offloads = Offloads {
            rx_timestamp: true,
            ..Offloads::default()
        };
        // SAFETY: pcap owns this newly created ethdev on the EAL owner thread;
        // Port::open preserves the production pool contract.
        let error = unsafe { Port::open(eal, config) }.unwrap_err();
        assert_eq!(
            error.cause,
            PortError::InvalidSettings("PMD lacks the requested RX timestamp offload")
        );
        assert!(error.retained.is_none());
        assert!(error.rollback_error.is_none());
        assert_no_pools();
        pcap.close();
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn hardware_mode_unflagged_packet_has_no_stamp() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        enable_rx_timestamp(&mut device.port);
        let field = device.port.rx_timestamp_field().unwrap();
        check_rx_timestamp(&fixture, &mut device, field, false, 0);
        finish(fixture, device);
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn off_mode_ignores_flagged_stamp() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        enable_rx_timestamp(&mut device.port);
        let field = device.port.rx_timestamp_field().unwrap();
        finish(fixture, device);

        let (fixture, mut device) = open(eal, 4, 4);
        assert!(device.port.rx_timestamp_field().is_none());
        check_rx_timestamp(&fixture, &mut device, field, true, 0);
        finish(fixture, device);
        assert_no_pools();
    });
}

fn write_rx_timestamp(
    raw: *mut zhida_dpdk_sys::rte_mbuf,
    field: crate::port::RxTimestampField,
    stamp: u64,
    flagged: bool,
) {
    // SAFETY: the test producer exclusively owns this live RX-pool mbuf. The
    // production registration supplied a field within it with u64 alignment.
    unsafe {
        raw.cast::<u8>().add(field.offset).cast::<u64>().write(stamp);
        (*raw).ol_flags = if flagged { field.flag } else { 0 };
    }
}

fn check_rx_timestamp(
    fixture: &Fixture,
    device: &mut Device,
    field: crate::port::RxTimestampField,
    flagged: bool,
    expected: u64,
) {
    let bytes = b"hardware stamp";
    let raw = rx_frame_bytes(&device.port, bytes);
    write_rx_timestamp(raw, field, 0xfedc_ba98_7654_3210, flagged);
    produce(fixture, &[raw]);
    assert_eq!(device.rx_burst().unwrap().accepted, 1);
    let (rx, tx) = device.receive(NOW).unwrap();
    let frame = rx.into_buf();
    assert_eq!(frame.rx_timestamp(), expected);
    assert_eq!(frame.as_slice(), bytes);
    drop(tx);
    assert_eq!(in_use(&device.port).0, 1);
    drop(frame);
    assert_eq!(in_use(&device.port).0, 0);
}

#[zhida_test_support::pinned_test]
fn udp_datagram_reports_hardware_stamp() {
    use crate::{Stack, StackConfig, UdpConfig, DEFAULT_NEIGHBOR_CAPACITY};
    use smoltcp::wire::Ipv4Cidr;

    with_test_eal(|eal| {
        let fixture = Fixture::new();
        // SAFETY: the fixture owns this newly created ethdev and its rings on
        // the EAL owner thread; Port::open preserves the production pool contract.
        let mut port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        enable_rx_timestamp(&mut port);
        let field = port.rx_timestamp_field().unwrap();
        let stamps = [0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210];
        let bytes = udp_frame();
        let packets = stamps.map(|stamp| {
            let raw = rx_frame_bytes(&port, &bytes);
            write_rx_timestamp(raw, field, stamp, true);
            raw
        });
        produce(&fixture, &packets);
        let config = StackConfig {
            ethernet: Side::B.mac(),
            ipv4: Ipv4Cidr::new(Side::B.ip(), 24),
            gateway: None,
            paths: &[],
            random_seed: 1,
            neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
            segments_per_visit: 1,
            max_sockets: 2,
            max_udp_sockets: 1,
            rx_staging: 8,
            tx_pending: 8,
        };
        let mut stack = match Stack::new(port, config, NOW) {
            Ok(stack) => stack,
            Err((_, error)) => panic!("{error}"),
        };
        let handle = stack
            .add_udp(UdpConfig {
                port: 80,
                rx_queue: 2,
                tx_checksum: true,
                broadcast: false,
            })
            .unwrap();
        let turn = stack.turn(NOW, 8).unwrap();
        assert_eq!((turn.rx_received, turn.rx_processed), (2, 2));
        let first = stack.udp_mut(&handle).recv().unwrap();
        let second = stack.udp_mut(&handle).recv().unwrap();
        assert_eq!(first.payload(), b"data");
        assert_eq!(second.payload(), b"data");
        assert_eq!(first.rx_timestamp(), stamps[0]);
        assert_eq!(second.rx_timestamp(), stamps[1]);
        assert_eq!(stack.udp(&handle).rx_queued(), 0);
        drop((first, second));
        let port = stack.into_port();
        assert!(peer_receive(&fixture, 16).is_empty());
        assert_eq!(in_use(&port), (0, 0));
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn rx_token_owns_exact_bytes_and_returns_buffer() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        stage(&fixture, &mut device, b"exact rx bytes");
        let (rx, tx) = device.receive(NOW).unwrap();
        assert_eq!(rx.into_buf().as_slice(), b"exact rx bytes");
        drop(tx);
        assert!(device.rx.is_empty() && device.tx.is_empty());
        // The unused reply packet stays as the spare.
        assert_eq!(in_use(&device.port), (0, 1));
        finish(fixture, device);
    });
}

fn check_tcp_rx_timestamps(eal: &crate::Eal, payloads: [&[u8]; 2], expected: &[u64]) {
    use crate::{Stack, StackConfig, DEFAULT_NEIGHBOR_CAPACITY};
    use smoltcp::socket::tcp::State;
    use smoltcp::wire::{ArpOperation, Ipv4Cidr};

    let (fixture, mut device) = open(eal, 8, 8);
    enable_rx_timestamp(&mut device.port);
    let field = device.port.rx_timestamp_field().unwrap();
    let stamps = [0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210];
    let mut reply = TcpRepr {
        src_port: 80,
        dst_port: 49152,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(100),
        ack_number: Some(TcpSeqNumber(0)),
        window_len: 4096,
        window_scale: None,
        max_seg_size: Some(512),
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };
    // Retain real RX-pool packets while the handshake supplies our sequence number.
    stage(&fixture, &mut device, &pair::tcp_frame(Side::B, &reply));
    let mut syn_ack = device.rx.pop_front().unwrap();
    let mut packets = Vec::new();
    reply.control = TcpControl::None;
    reply.max_seg_size = None;
    reply.seq_number = TcpSeqNumber(101);
    for payload in payloads {
        reply.payload = payload;
        stage(&fixture, &mut device, &pair::tcp_frame(Side::B, &reply));
        packets.push(device.rx.pop_front().unwrap());
        reply.seq_number = reply.seq_number + payload.len();
    }
    let arp = zhida_test_kit::ring_port::arp(
        ArpOperation::Reply,
        Side::A.mac(),
        (Side::B.mac(), Side::B.ip()),
        (Side::A.mac(), Side::A.ip()),
    );
    produce(&fixture, &[rx_frame_bytes(&device.port, &arp)]);
    let config = StackConfig {
        ethernet: Side::A.mac(),
        ipv4: Ipv4Cidr::new(Side::A.ip(), 24),
        gateway: None,
        paths: &[],
        random_seed: 1,
        neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
        segments_per_visit: 1,
        max_sockets: 1,
        max_udp_sockets: 0,
        rx_staging: 8,
        tx_pending: 8,
    };
    let mut stack = match Stack::new(device.into_port(), config, NOW) {
        Ok(stack) => stack,
        Err((_, error)) => panic!("{error}"),
    };
    let handle = stack.add_tcp(pair::tcp_socket_sized(4096)).unwrap();
    stack.tcp_mut(&handle).set_ack_delay(None);
    stack.connect(&handle, (Side::B.ip(), 80), 49152).unwrap();
    stack.turn(NOW, 8).unwrap();
    let sent = peer_receive(&fixture, 16);
    assert_eq!(sent.len(), 1);
    let syn = pair::segment(sent[0].data(), Side::A);
    assert_eq!(syn.control, TcpControl::Syn);
    let local_seq = syn.seq_number + 1;
    drop(sent);
    reply.control = TcpControl::Syn;
    reply.seq_number = TcpSeqNumber(100);
    reply.ack_number = Some(local_seq);
    reply.max_seg_size = Some(512);
    reply.payload = &[];
    syn_ack
        .data_mut()
        .copy_from_slice(&pair::tcp_frame(Side::B, &reply));
    let raw = syn_ack.as_ptr();
    // The fixture ring takes ownership; Stack returns this mbuf after processing it.
    std::mem::forget(syn_ack);
    produce(&fixture, &[raw]);
    stack.turn(NOW, 8).unwrap();
    assert_eq!(stack.tcp(&handle).state(), State::Established);
    drop(peer_receive(&fixture, 16));
    reply.control = TcpControl::None;
    reply.max_seg_size = None;
    reply.seq_number = TcpSeqNumber(101);
    for ((mut packet, payload), stamp) in packets.into_iter().zip(payloads).zip(stamps) {
        reply.payload = payload;
        packet
            .data_mut()
            .copy_from_slice(&pair::tcp_frame(Side::B, &reply));
        let raw = packet.as_ptr();
        write_rx_timestamp(raw, field, stamp, true);
        std::mem::forget(packet);
        produce(&fixture, &[raw]);
        let turn = stack.turn(NOW, 8).unwrap();
        assert_eq!((turn.rx_received, turn.rx_processed), (1, 1));
        drop(peer_receive(&fixture, 16));
        reply.seq_number = reply.seq_number + payload.len();
    }
    let mut stamps = Vec::new();
    let mut bytes = Vec::new();
    while let Some(frame) = stack.tcp_mut(&handle).recv().unwrap() {
        stamps.push(frame.rx_timestamp());
        bytes.extend_from_slice(frame.payload());
    }
    assert_eq!(stamps, expected);
    assert_eq!(bytes, payloads.concat());
    assert_eq!(stack.tcp(&handle).recv_queue(), 0);
    let port = stack.into_port();
    assert!(peer_receive(&fixture, 16).is_empty());
    assert_eq!(in_use(&port), (0, 0));
    port.try_close().unwrap();
    fixture.close().unwrap();
    assert_no_pools();
}

#[zhida_test_support::pinned_test]
fn tcp_views_carry_hardware_stamps() {
    with_test_eal(|eal| {
        check_tcp_rx_timestamps(
            eal,
            [&[b'a'; 200], &[b'b'; 200]],
            &[0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210],
        );
    });
}

#[zhida_test_support::pinned_test]
fn tcp_appended_segment_reports_first_stamp() {
    with_test_eal(|eal| {
        check_tcp_rx_timestamps(eal, [b"abc", b"def"], &[0x1234_5678_9abc_def0]);
    });
}

#[zhida_test_support::pinned_test]
fn rx_into_buf_releases_on_drop_without_copy() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        stage(&fixture, &mut device, b"owned rx bytes");
        let data = device.rx.front().unwrap().data().as_ptr();
        let (rx, tx) = device.receive(NOW).unwrap();
        let frame = rx.into_buf();
        assert_eq!(frame.as_slice().as_ptr(), data);
        assert_eq!(frame.as_slice(), b"owned rx bytes");
        drop(tx);
        assert_eq!(in_use(&device.port), (1, 1));
        drop(frame);
        assert_eq!(in_use(&device.port), (0, 1));
        finish(fixture, device);
    });
}

/// Buffer identity: a direct mbuf's data starts at a fixed offset in its own buffer.
fn spare_ptr(device: &Device) -> *const u8 {
    device.spare.as_ref().unwrap().data().as_ptr()
}

fn token_ptr(token: &Tx<'_>) -> *const u8 {
    token.packet.as_ref().unwrap().data().as_ptr()
}

#[zhida_test_support::pinned_test]
fn unused_tokens_hold_one_tx_buffer() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        drop(device.transmit(NOW).unwrap());
        let spare = spare_ptr(&device);
        assert_eq!(in_use(&device.port), (0, 1));
        // Over many unused tokens exactly one TX mbuf stays in use and nothing
        // is queued or leaked. A free-then-allocate per token could return the
        // same mbuf through the LIFO cache with the same count, so this does
        // not prove no allocation happens.
        for round in 0..200u8 {
            let token = device.transmit(NOW).unwrap();
            assert_eq!(token_ptr(&token), spare);
            drop(token);
            stage(&fixture, &mut device, &[round; 60]);
            let (rx, tx) = device.receive(NOW).unwrap();
            assert_eq!(token_ptr(&tx), spare);
            assert_eq!(tx.packet.as_ref().unwrap().data().len(), FRAME);
            assert_eq!(rx.into_buf().as_slice(), [round; 60]);
            drop(tx);
            assert_eq!(spare_ptr(&device), spare);
            assert!(device.tx.is_empty());
            assert_eq!(in_use(&device.port), (0, 1));
        }
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn consumed_spare_leaves_none_and_next_token_allocates() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        drop(device.transmit(NOW).unwrap());
        let spare = spare_ptr(&device);
        send(&mut device, b"uses the spare");
        assert!(device.spare.is_none());
        assert_eq!(device.tx[0].data().as_ptr(), spare);
        assert_eq!(in_use(&device.port), (0, 1));
        let token = device.transmit(NOW).unwrap();
        assert_ne!(token_ptr(&token), spare);
        assert_eq!(token.packet.as_ref().unwrap().data().len(), FRAME);
        drop(token);
        // The pending packet plus a newly allocated spare.
        assert_ne!(spare_ptr(&device), spare);
        assert_eq!(in_use(&device.port), (0, 2));
        assert_eq!(pending(&device), [b"uses the spare".to_vec()]);
        assert_eq!(device.flush().unwrap(), 1);
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn spare_returns_on_into_port_and_on_drop() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        drop(device.transmit(NOW).unwrap());
        assert!(device.spare.is_some());
        let port = device.into_port();
        assert_eq!(in_use(&port), (0, 0));
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();

        let (fixture, mut device) = open(eal, 4, 4);
        drop(device.transmit(NOW).unwrap());
        assert_eq!(in_use(&device.port), (0, 1));
        drop(device);
        assert_no_pools();
        fixture.close().unwrap();
    });
}

/// More staged and pending packets than the 8-entry mempool cache holds.
#[zhida_test_support::pinned_test]
fn into_port_returns_many_staged_and_pending_packets() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 20, 21);
        for value in 0..20u8 {
            stage(&fixture, &mut device, &[value; 60]);
            send(&mut device, &[value; 60]);
        }
        drop(device.transmit(NOW).unwrap());
        assert_eq!(in_use(&device.port), (20, 21));
        let port = device.into_port();
        assert_eq!(in_use(&port), (0, 0));
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn tx_consume_queues_exactly_len_bytes() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        let bytes: Vec<u8> = (0..60).collect();
        let token = device.transmit(NOW).unwrap();
        let seen = token.consume(60, |buf| {
            buf.copy_from_slice(&bytes);
            buf.len()
        });
        assert_eq!(seen, 60);
        assert_eq!(pending(&device), [bytes.clone()]);
        assert_eq!(device.flush().unwrap(), 1);
        let sent = peer_receive(&fixture, 16);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].data(), &bytes[..]);
        assert_eq!((sent[0].pkt_len(), sent[0].nb_segs()), (60, 1));
        drop(sent);
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn implicit_drop_releases_packets_before_port_cleanup() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        stage(&fixture, &mut device, b"staged at drop");
        send(&mut device, b"pending at drop");
        assert_eq!((device.rx.len(), device.tx.len()), (1, 1));
        assert_eq!(in_use(&device.port), (1, 1));
        drop(device);
        assert_no_pools();
        fixture.close().unwrap();
    });
}

#[zhida_test_support::pinned_test]
fn partial_flush_keeps_suffix() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        for frame in [b"first", b"secnd", b"third"] {
            send(&mut device, frame);
        }
        let mut faults = Faults::default();
        faults.tx_accept_limit = Some(1);
        let guard = FaultGuard::new(faults);
        // The PMD takes one of three: flush stops after that short call.
        let calls = tx_calls();
        assert_eq!(device.flush().unwrap(), 1);
        assert_eq!(tx_calls(), calls + 1);
        assert_eq!(pending(&device), [b"secnd".to_vec(), b"third".to_vec()]);
        drop(guard);
        assert_eq!(device.flush().unwrap(), 2);
        assert!(device.tx.is_empty());
        let sent: Vec<Vec<u8>> = peer_receive(&fixture, 16)
            .iter()
            .map(|m| m.data().to_vec())
            .collect();
        assert_eq!(sent, [b"first".to_vec(), b"secnd".to_vec(), b"third".to_vec()]);
        finish(fixture, device);
    });
}

fn frames(range: std::ops::Range<u8>) -> Vec<Vec<u8>> {
    range.map(|value| vec![value; 60]).collect()
}

#[zhida_test_support::pinned_test]
fn flush_offers_bursts_until_pending_drains() {
    with_test_eal(|eal| {
        // Bursts of two; the seven-slot TX ring takes all six frames.
        let fixture = Fixture::new();
        let mut config = fixture.config();
        config.tx_burst = 2;
        let port = unsafe { Port::open(eal, config) }.unwrap();
        let mut device = Device::new(port, 4, 6);
        for frame in frames(0..6) {
            send(&mut device, &frame);
        }
        let calls = tx_calls();
        assert_eq!(device.flush().unwrap(), 6);
        assert_eq!(tx_calls(), calls + 3);
        assert!(device.tx.is_empty());
        let sent: Vec<Vec<u8>> = peer_receive(&fixture, 16)
            .iter()
            .map(|m| m.data().to_vec())
            .collect();
        assert_eq!(sent, frames(0..6));
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn flush_stops_after_the_first_short_burst_and_keeps_suffix() {
    with_test_eal(|eal| {
        // Bursts of four into a seven-slot ring: four, then three of four.
        let (fixture, mut device) = open(eal, 4, 12);
        for frame in frames(0..12) {
            send(&mut device, &frame);
        }
        let calls = tx_calls();
        assert_eq!(device.flush().unwrap(), 7);
        assert_eq!(tx_calls(), calls + 2);
        assert_eq!(pending(&device), frames(7..12));
        let sent: Vec<Vec<u8>> = peer_receive(&fixture, 16)
            .iter()
            .map(|m| m.data().to_vec())
            .collect();
        assert_eq!(sent, frames(0..7));
        // Drained ring: four, then the last one.
        assert_eq!(device.flush().unwrap(), 5);
        assert_eq!(tx_calls(), calls + 4);
        assert!(device.tx.is_empty());
        let sent: Vec<Vec<u8>> = peer_receive(&fixture, 16)
            .iter()
            .map(|m| m.data().to_vec())
            .collect();
        assert_eq!(sent, frames(7..12));
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn callback_panic_queues_nothing_and_releases() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        let token = device.transmit(NOW).unwrap();
        let unwound = catch_unwind(AssertUnwindSafe(|| {
            token.consume(60, |buf| {
                buf.fill(1);
                panic!("callback fails");
            })
        }));
        assert!(unwound.is_err());
        stage(&fixture, &mut device, b"reply panics");
        let (rx, tx) = device.receive(NOW).unwrap();
        let unwound = catch_unwind(AssertUnwindSafe(|| {
            let frame = rx.into_buf();
            assert_eq!(frame.as_slice(), b"reply panics");
            tx.consume(60, |_| panic!("reply fails"));
        }));
        assert!(unwound.is_err());
        assert!(device.tx.is_empty() && device.rx.is_empty());
        assert_eq!(in_use(&device.port), (0, 0));
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn callback_panic_on_spare_frees_it_and_next_token_is_full_frame() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        drop(device.transmit(NOW).unwrap());
        let unwound = catch_unwind(AssertUnwindSafe(|| {
            device.transmit(NOW).unwrap().consume(60, |buf| {
                buf.fill(1);
                panic!("callback fails");
            })
        }));
        assert!(unwound.is_err());
        assert!(device.spare.is_none() && device.tx.is_empty());
        assert_eq!(in_use(&device.port), (0, 0));
        let token = device.transmit(NOW).unwrap();
        assert_eq!(token.packet.as_ref().unwrap().data().len(), FRAME);
        token.consume(FRAME, |buf| buf.fill(7));
        assert_eq!(pending(&device), [vec![7; FRAME]]);
        assert_eq!(device.flush().unwrap(), 1);
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn oversize_consume_panics_and_releases() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        let called = Cell::new(false);
        let token = device.transmit(NOW).unwrap();
        let unwound = catch_unwind(AssertUnwindSafe(|| {
            token.consume(FRAME + 1, |_| called.set(true))
        }));
        assert!(unwound.is_err());
        assert!(!called.get());
        assert!(device.tx.is_empty());
        assert_eq!(in_use(&device.port), (0, 0));
        device.transmit(NOW).unwrap().consume(FRAME, |buf| buf.fill(7));
        assert_eq!(pending(&device), [vec![7; FRAME]]);
        assert_eq!(device.flush().unwrap(), 1);
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn tx_pool_exhausted_receive_none_rx_stays_staged_then_recovers() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        stage(&fixture, &mut device, b"waits for reply buffer");
        let held: Vec<Packet> =
            std::iter::from_fn(|| device.port.alloc_tx(device.port.frame_capacity())).collect();
        assert_eq!(held.len(), 63);
        assert!(device.receive(NOW).is_none());
        assert!(device.transmit(NOW).is_none());
        assert_eq!(device.rx.len(), 1);
        assert_eq!(in_use(&device.port), (1, 63));
        drop(held);
        let (rx, tx) = device.receive(NOW).unwrap();
        assert_eq!(rx.into_buf().as_slice(), b"waits for reply buffer");
        drop(tx);
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn spare_serves_one_token_then_exhausted_pool_refuses_and_recovers() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        drop(device.transmit(NOW).unwrap());
        let held: Vec<Packet> =
            std::iter::from_fn(|| device.port.alloc_tx(device.port.frame_capacity())).collect();
        assert_eq!(held.len(), 62);
        send(&mut device, b"from the spare");
        stage(&fixture, &mut device, b"waits for reply buffer");
        assert!(device.receive(NOW).is_none());
        assert!(device.transmit(NOW).is_none());
        assert!(device.spare.is_none());
        assert_eq!(device.rx.len(), 1);
        assert_eq!(in_use(&device.port), (1, 63));
        drop(held);
        let (rx, tx) = device.receive(NOW).unwrap();
        assert_eq!(rx.into_buf().as_slice(), b"waits for reply buffer");
        tx.consume(60, |buf| buf.fill(3));
        assert_eq!(pending(&device), [b"from the spare".to_vec(), vec![3; 60]]);
        assert_eq!(device.flush().unwrap(), 2);
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn full_pending_refuses_tokens_until_flush() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 2);
        let slots = device.tx.capacity();
        // The ring takes 7 packets; the flush below must drain every slot.
        assert!((2..=7).contains(&slots));
        for value in 0..slots as u8 {
            send(&mut device, &[value; 60]);
        }
        stage(&fixture, &mut device, b"needs a slot");
        assert!(device.transmit(NOW).is_none());
        assert!(device.receive(NOW).is_none());
        assert_eq!(device.rx.len(), 1);
        assert_eq!(device.tx.capacity(), slots);
        assert_eq!(in_use(&device.port), (1, slots as u32));
        assert_eq!(device.flush().unwrap(), slots);
        let (rx, tx) = device.receive(NOW).unwrap();
        drop(rx.into_buf());
        tx.consume(60, |buf| buf.fill(9));
        assert_eq!(pending(&device), [vec![9; 60]]);
        assert_eq!(device.flush().unwrap(), 1);
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn capabilities_frame_is_mtu_plus_14() {
    with_test_eal(|eal| {
        let (fixture, device) = open(eal, 4, 4);
        let caps = device.capabilities();
        assert_eq!(caps.medium, Medium::Ethernet);
        assert_eq!((caps.max_transmission_unit, caps.ip_mtu()), (FRAME, 1500));
        assert_eq!(caps.max_burst_size, None);
        let sums = &caps.checksum;
        for sum in [sums.ipv4, sums.udp, sums.tcp, sums.icmpv4] {
            assert!(matches!(sum, Checksum::Both));
        }
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn interface_answers_arp_request_through_paired_token_exact_bytes() {
    with_test_eal(|eal| {
        let (fixture, mut device) = open(eal, 4, 4);
        let poisoned: Vec<Packet> = std::iter::from_fn(|| {
            let mut packet = device.port.alloc_tx(device.port.frame_capacity())?;
            packet.data_mut().fill(0xee);
            Some(packet)
        })
        .collect();
        assert_eq!(poisoned.len(), 63);
        drop(poisoned);

        let ours = [0x02, 0, 0, 0, 0, 0x01];
        let peer = [0x02, 0, 0, 0, 0, 0x02];
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ethernet(EthernetAddress(ours))),
            &mut device,
            NOW,
        );
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(Ipv4Address::new(10, 0, 0, 1).into(), 24))
                .unwrap();
        });
        let mut sockets = TcpSet::new(Vec::new());

        let header = |dst: [u8; 6], src: [u8; 6], op: u8| {
            let mut frame = Vec::with_capacity(14);
            frame.extend_from_slice(&dst);
            frame.extend_from_slice(&src);
            frame.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0x00, 6, 4, 0, op]);
            frame
        };
        let mut request = header([0xff; 6], peer, 1);
        request.extend_from_slice(&peer);
        request.extend_from_slice(&[10, 0, 0, 2]);
        request.extend_from_slice(&[0; 6]);
        request.extend_from_slice(&[10, 0, 0, 1]);
        let mut reply = header(peer, ours, 2);
        reply.extend_from_slice(&ours);
        reply.extend_from_slice(&[10, 0, 0, 1]);
        reply.extend_from_slice(&peer);
        reply.extend_from_slice(&[10, 0, 0, 2]);

        stage(&fixture, &mut device, &request);
        // Upstream reports SocketStateChanged for every non-empty frame (mod.rs:708).
        assert_eq!(
            iface.poll_ingress_single(NOW, &mut device, &mut sockets),
            PollIngressSingleResult::SocketStateChanged
        );
        assert!(device.rx.is_empty());
        assert_eq!(pending(&device), [reply.clone()]);
        assert_eq!(in_use(&device.port), (0, 1));
        assert_eq!(device.flush().unwrap(), 1);
        let sent = peer_receive(&fixture, 16);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].data(), &reply[..]);
        assert_eq!(sent[0].pkt_len(), 42);
        drop(sent);
        assert_eq!(
            iface.poll_ingress_single(NOW, &mut device, &mut sockets),
            PollIngressSingleResult::None
        );
        finish(fixture, device);
    });
}

#[zhida_test_support::pinned_test]
fn stack_l4_bad_verified_in_software_and_l4_good_trusted() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let mut port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        enable_rx_checksum(&mut port);
        let syn = checksum_syn();
        let raw = rx_frame_bytes(&port, &syn);
        let pool = unsafe { (*raw).pool };
        let config = crate::StackConfig {
            ethernet: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            ipv4: smoltcp::wire::Ipv4Cidr::new(Ipv4Address::new(10, 0, 0, 1), 24),
            gateway: None,
            paths: &[],
            random_seed: 1,
            neighbor_capacity: 4,
            segments_per_visit: 1,
            max_sockets: 1,
            max_udp_sockets: 1,
            rx_staging: 4,
            tx_pending: 4,
        };
        let mut stack = crate::Stack::new(port, config, NOW).map_err(|(_, e)| e).unwrap();
        let socket = smoltcp::socket::tcp::Config {
            rx_capacity: 64, tx_capacity: 64, mss_cap: None,
        };
        let handle = stack.add_tcp(socket).unwrap();
        stack.tcp_mut(&handle).set_ack_delay(None);
        stack.listen(&handle, 80).unwrap();
        let udp = stack.add_udp(smoltcp::iface::UdpConfig {
            port: 80,
            rx_queue: 1,
            tx_checksum: true,
            broadcast: false,
        }).unwrap();
        let arp = zhida_test_kit::ring_port::arp(
            smoltcp::wire::ArpOperation::Reply,
            config.ethernet,
            (EthernetAddress([0x02, 0, 0, 0, 0, 2]), Ipv4Address::new(10, 0, 0, 2)),
            (config.ethernet, config.ipv4.address()),
        );
        produce(&fixture, &[zhida_test_kit::wire::copy_into(pool, &arp)]);
        stack.turn(NOW, 4).unwrap();
        drop(peer_receive(&fixture, 16));
        produce(&fixture, &[raw]);
        stack.turn(NOW, 4).unwrap();
        let frames = peer_receive(&fixture, 16);
        let synack = frames.iter().find_map(|packet| {
            let eth = EthernetFrame::new_checked(packet.data()).unwrap();
            if eth.ethertype() != EthernetProtocol::Ipv4 { return None; }
            let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            Some(tcp.seq_number() + 1)
        }).unwrap();
        drop(frames);
        let inject = |bytes: &[u8], flags: u64| {
            let raw = zhida_test_kit::wire::copy_into(pool, bytes);
            unsafe { (*raw).ol_flags = flags };
            produce(&fixture, &[raw]);
        };
        let mut ack = syn.clone();
        let mut tcp = TcpPacket::new_unchecked(&mut ack[34..]);
        tcp.set_syn(false);
        tcp.set_ack(true);
        tcp.set_seq_number(TcpSeqNumber(2));
        tcp.set_ack_number(synack);
        tcp.fill_checksum(&Ipv4Address::new(10, 0, 0, 2).into(), &Ipv4Address::new(10, 0, 0, 1).into());
        inject(&ack, 0);
        stack.turn(NOW, 4).unwrap();
        assert_eq!(stack.tcp(&handle).state(), smoltcp::socket::tcp::State::Established);
        drop(peer_receive(&fixture, 16));
        let mut data = ack;
        data.extend_from_slice(b"abc");
        let mut ip = Ipv4Packet::new_unchecked(&mut data[14..]);
        ip.set_total_len(43);
        ip.fill_checksum();
        let mut tcp = TcpPacket::new_unchecked(ip.payload_mut());
        tcp.fill_checksum(&Ipv4Address::new(10, 0, 0, 2).into(), &Ipv4Address::new(10, 0, 0, 1).into());
        data[50] ^= 1;
        let bad = RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD;
        inject(&data, bad);
        let turn = stack.turn(NOW, 4).unwrap();
        assert_eq!((turn.rx_received, turn.rx_ipv4_checksum_bad), (1, 0));
        assert_eq!(stack.tcp(&handle).recv_queue(), 0);
        assert!(peer_receive(&fixture, 16).is_empty());
        assert_eq!(stack.tcp_counters().rx_checksum_bad, 1);
        inject(&data, RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD);
        stack.turn(NOW, 4).unwrap();
        assert_eq!(stack.tcp(&handle).recv_queue(), 3);
        let frames = peer_receive(&fixture, 16);
        assert_eq!(frames.len(), 1);
        let ip = Ipv4Packet::new_checked(&frames[0].data()[14..]).unwrap();
        assert_eq!(TcpPacket::new_checked(ip.payload()).unwrap().ack_number(), TcpSeqNumber(5));
        drop(frames);
        assert_eq!(stack.tcp_counters().rx_checksum_bad, 1);
        let mut bytes = udp_frame();
        bytes[..12].copy_from_slice(&syn[..12]);
        let mut ip = Ipv4Packet::new_unchecked(&mut bytes[14..]);
        ip.set_src_addr(Ipv4Address::new(10, 0, 0, 2));
        ip.set_dst_addr(Ipv4Address::new(10, 0, 0, 1));
        ip.fill_checksum();
        UdpPacket::new_unchecked(ip.payload_mut()).set_checksum(0);
        inject(&bytes, bad);
        stack.turn(NOW, 4).unwrap();
        assert_eq!(stack.udp_mut(&udp).recv().unwrap().payload(), b"data");
        let mut ip = Ipv4Packet::new_unchecked(&mut bytes[14..]);
        let mut packet = UdpPacket::new_unchecked(ip.payload_mut());
        packet.fill_checksum(&Ipv4Address::new(10, 0, 0, 2).into(), &Ipv4Address::new(10, 0, 0, 1).into());
        packet.payload_mut()[0] ^= 1;
        inject(&bytes, bad);
        stack.turn(NOW, 4).unwrap();
        assert!(stack.udp_mut(&udp).recv().is_none());
        assert_eq!(stack.udp_counters().rx_checksum_bad, 1);
        stack.remove_tcp(handle);
        stack.remove_udp(udp);
        let port = stack.into_port();
        drop(peer_receive(&fixture, 16));
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}
