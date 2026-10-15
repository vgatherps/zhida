mod ipv4;
mod next_hop;
#[cfg(feature = "medium-ip")]
mod poll_at_cache;
#[cfg(feature = "medium-ip")]
mod ready_queue;
#[cfg(feature = "medium-ip")]
mod tcp_demux;
mod template;

#[cfg(feature = "udp-set")]
mod tx_checksum;

#[cfg(feature = "udp-set")]
mod udp;

#[allow(unused)]
use std::vec::Vec;

use crate::tests::setup;

use rstest::*;

use super::*;

use crate::iface::Interface;
use crate::phy::ChecksumCapabilities;
use crate::phy::Loopback;
use crate::time::Instant;

#[allow(unused)]
fn fill_slice(s: &mut [u8], val: u8) {
    for x in s.iter_mut() {
        *x = val
    }
}

#[allow(unused)]
fn recv_all(device: &mut crate::tests::TestingDevice, timestamp: Instant) -> Vec<Vec<u8>> {
    let mut pkts = Vec::new();
    while let Some(pkt) = device.tx_queue.pop_front() {
        pkts.push(pkt)
    }
    pkts
}

#[derive(Debug, PartialEq)]
struct MockTxToken;

impl TxToken for MockTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut junk = [0; 1536];
        f(&mut junk[..len])
    }
}

struct CaptureTxToken<'a>(&'a mut Vec<u8>);

impl TxToken for CaptureTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut bytes = vec![0xa5; len];
        let result = f(&mut bytes);
        *self.0 = bytes;
        result
    }
}

fn assert_generic_frame(iface: &mut Interface, frame: &[u8]) {
    use crate::phy::Checksum;

    let eth = EthernetFrame::new_checked(frame).unwrap();
    assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);
    let ip_packet = Ipv4Packet::new_checked(eth.payload()).unwrap();
    let tcp_packet = TcpPacket::new_checked(ip_packet.payload()).unwrap();
    let mut caps = ChecksumCapabilities::ignored();
    if iface.inner.caps.checksum.ipv4.tx() {
        assert!(ip_packet.verify_checksum());
        caps.ipv4 = Checksum::Both;
    } else {
        assert_eq!(ip_packet.checksum(), 0);
    }
    if iface.inner.caps.checksum.tcp.tx() {
        assert!(
            tcp_packet.verify_checksum(&ip_packet.src_addr().into(), &ip_packet.dst_addr().into())
        );
        caps.tcp = Checksum::Both;
    } else {
        assert_eq!(tcp_packet.checksum(), 0);
    }
    let ip = Ipv4Repr::parse(&ip_packet, &caps).unwrap();
    let tcp = TcpRepr::parse(&tcp_packet, &ip.src_addr.into(), &ip.dst_addr.into(), &caps).unwrap();
    let mut generic = Vec::new();
    iface
        .inner
        .dispatch_ip(
            CaptureTxToken(&mut generic),
            PacketMeta::default(),
            Packet::new_ipv4(ip, IpPayload::Tcp(tcp)),
            None,
        )
        .unwrap();
    assert_eq!(frame, generic);
}

#[test]
#[should_panic(expected = "The hardware address does not match the medium of the interface.")]
#[cfg(feature = "medium-ip")]
fn test_new_panic() {
    let mut device = Loopback::new(Medium::Ethernet);
    let config = Config::new(HardwareAddress::Ip);
    Interface::new(config, &mut device, Instant::ZERO);
}

#[test]
fn capacity_from_config() {
    let hardware_addr = HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 1]));
    let mut config = Config::new(hardware_addr);
    config.neighbor_capacity = 2;
    let mut device = Loopback::new(Medium::Ethernet);
    let mut iface = Interface::new(config, &mut device, Instant::ZERO);
    let addresses = [
        Ipv4Address::new(192, 0, 2, 1).into(),
        Ipv4Address::new(192, 0, 2, 2).into(),
        Ipv4Address::new(192, 0, 2, 3).into(),
    ];
    for (index, address) in addresses.iter().enumerate() {
        iface.inner.neighbor_cache.fill(
            *address,
            hardware_addr,
            Instant::from_millis(index as i64),
        );
        assert_eq!(
            iface
                .inner
                .neighbor_cache
                .lookup(address, Instant::from_millis(10)),
            NeighborAnswer::Found(hardware_addr)
        );
    }
    assert_eq!(
        iface
            .inner
            .neighbor_cache
            .lookup(&addresses[0], Instant::from_millis(10)),
        NeighborAnswer::NotFound
    );
    for address in &addresses[1..] {
        assert_eq!(
            iface
                .inner
                .neighbor_cache
                .lookup(address, Instant::from_millis(10)),
            NeighborAnswer::Found(hardware_addr)
        );
    }
}

#[test]
#[should_panic(expected = "Neighbor capacity must be nonzero.")]
fn zero_neighbor_capacity_panics() {
    let hardware_addr = HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 1]));
    let mut config = Config::new(hardware_addr);
    config.neighbor_capacity = 0;
    let mut device = Loopback::new(Medium::Ethernet);
    Interface::new(config, &mut device, Instant::ZERO);
}

#[test]
#[cfg(feature = "medium-ip")]
pub fn tcp_listen_drops_unspecified_src() {
    use crate::socket::tcp;

    let (mut iface, mut sockets, _) = setup(Medium::Ip);

    let tcp_socket = tcp::Socket::new(tcp::RxBuffer::new(64), tcp::SocketBuffer::new(vec![0; 64]));
    let handle = sockets.add(tcp_socket);
    sockets.get_mut(handle).listen(1234).unwrap();

    let tcp = TcpRepr {
        src_port: 65000,
        dst_port: 1234,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(0),
        ack_number: None,
        window_len: 1024,
        window_scale: None,
        max_seg_size: Some(1460),
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    let mut tcp_bytes = vec![0u8; tcp.buffer_len()];
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut tcp_bytes),
        &Ipv4Address::UNSPECIFIED.into(),
        &Ipv4Address::new(127, 0, 0, 1).into(),
        &ChecksumCapabilities::default(),
    );

    let reply = iface.inner.process_tcp(
        &mut sockets,
        PacketMeta::default(),
        IpRepr::Ipv4(Ipv4Repr {
            src_addr: Ipv4Address::UNSPECIFIED,
            dst_addr: Ipv4Address::new(127, 0, 0, 1),
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        }),
        &tcp_bytes,
    );

    assert_eq!(reply, None);
    assert!(sockets.get_mut(handle).is_listening());
}
