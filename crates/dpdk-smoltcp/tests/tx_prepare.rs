use zhida_test_kit::with_eal;
use dpdk_smoltcp::smoltcp::phy::ChecksumCapabilities;
use dpdk_smoltcp::smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, IpAddress, IpProtocol,
    Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
};
use zhida_buffer::{Mbuf, PoolConfig, PoolManager};
use zhida_dpdk_sys::*;

const SRC: [u8; 4] = [192, 0, 2, 1];
const DST: [u8; 4] = [198, 51, 100, 2];
const L2_LEN: usize = 14;

fn pool() -> PoolManager {
    with_eal(|_| {});
    unsafe {
        PoolManager::new_production(PoolConfig {
            name: c"tx_prepare_pool",
            count: 63,
            cache_size: 8,
            data_room_size: RTE_PKTMBUF_HEADROOM as u16 + 2048,
            socket_id: -1,
        })
    }
    .unwrap()
}

fn tcp_frame(payload: &[u8], caps: &ChecksumCapabilities) -> Vec<u8> {
    let src = Ipv4Address::new(SRC[0], SRC[1], SRC[2], SRC[3]);
    let dst = Ipv4Address::new(DST[0], DST[1], DST[2], DST[3]);
    let eth = EthernetRepr {
        src_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
        dst_addr: EthernetAddress([0x02, 0, 0, 0, 0, 2]),
        ethertype: EthernetProtocol::Ipv4,
    };
    let tcp = TcpRepr {
        src_port: 49152,
        dst_port: 80,
        control: TcpControl::Psh,
        seq_number: TcpSeqNumber(100),
        ack_number: Some(TcpSeqNumber(200)),
        window_len: 4096,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload,
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
    ip.emit(&mut packet, caps);
    tcp.emit(
        &mut TcpPacket::new_unchecked(packet.payload_mut()),
        &IpAddress::Ipv4(src),
        &IpAddress::Ipv4(dst),
        caps,
    );
    bytes
}

fn mbuf(pool: &PoolManager, bytes: &[u8], flags: u64) -> Mbuf {
    let ip = Ipv4Packet::new_checked(&bytes[L2_LEN..]).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    let mut packet = pool
        .alloc_with_len(bytes.len().try_into().unwrap())
        .unwrap();
    packet.data_mut().copy_from_slice(bytes);
    unsafe {
        let raw = &mut *packet.as_ptr();
        raw.set_ol_flags(flags);
        raw.set_tx_offload_lengths(
            L2_LEN as u16,
            u16::from(ip.header_len()),
            u16::from(tcp.header_len()),
        );
        assert_eq!(raw.ol_flags(), flags);
    }
    packet
}

fn ones_complement_sum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut words = bytes.chunks_exact(2);
    for word in &mut words {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if let Some(&last) = words.remainder().first() {
        sum += u32::from(last) << 8;
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

#[zhida_test_support::pinned_test]
fn prepare_seed_completes_to_software_checksum() {
    let pool = pool();
    let mut offload_caps = ChecksumCapabilities::default();
    offload_caps.tcp = ChecksumCapabilities::ignored().tcp;
    for payload in [b"even".as_slice(), b"odd".as_slice()] {
        let software = tcp_frame(payload, &ChecksumCapabilities::default());
        let software_ip = Ipv4Packet::new_checked(&software[L2_LEN..]).unwrap();
        let oracle = TcpPacket::new_checked(software_ip.payload())
            .unwrap()
            .checksum();
        let offload = tcp_frame(payload, &offload_caps);
        let offload_ip = Ipv4Packet::new_checked(&offload[L2_LEN..]).unwrap();
        assert_eq!(
            TcpPacket::new_checked(offload_ip.payload())
                .unwrap()
                .checksum(),
            0
        );
        let mut packet = mbuf(
            &pool,
            &offload,
            RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_TCP_CKSUM,
        );
        assert_eq!(pool.in_use_count(), 1);
        assert_eq!(
            unsafe { dpdk_raw_net_intel_cksum_prepare(packet.as_ptr()) },
            0
        );
        let mut ip = Ipv4Packet::new_checked(&mut packet.data_mut()[L2_LEN..]).unwrap();
        let completed = !ones_complement_sum(ip.payload_mut());
        let mut tcp = TcpPacket::new_checked(ip.payload_mut()).unwrap();
        tcp.set_checksum(completed);
        assert_eq!(tcp.checksum(), oracle);
        assert_eq!(packet.data(), software.as_slice());
        drop(packet);
        assert_eq!(pool.in_use_count(), 0);
    }
}

#[zhida_test_support::pinned_test]
fn prepare_refusal_reported() {
    let pool = pool();
    let packet = pool.alloc_with_len(53).unwrap();
    assert_eq!(pool.in_use_count(), 1);
    unsafe {
        let raw = &mut *packet.as_ptr();
        raw.set_ol_flags(RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_TCP_CKSUM);
        raw.set_tx_offload_lengths(14, 20, 20);
        assert_eq!(raw.data_len(), 53);
        assert_eq!(raw.pkt_len(), 53);
    }
    assert_eq!(
        unsafe { dpdk_raw_net_intel_cksum_prepare(packet.as_ptr()) },
        -libc::ENOTSUP
    );
    drop(packet);
    assert_eq!(pool.in_use_count(), 0);
}
