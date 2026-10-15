//! Unicast ICMPv4 echo requests get replies. Broadcast requests, invalid requests,
//! and unknown IPv4 protocols are dropped. Closed UDP ports are dropped and counted.

use dpdk_smoltcp::smoltcp::phy::ChecksumCapabilities;
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::smoltcp::wire::{
    ArpOperation, EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr,
    Icmpv4Packet, Icmpv4Repr, IpProtocol, Ipv4Address, Ipv4Cidr, Ipv4Packet,
    Ipv4Repr, UdpPacket, UdpRepr,
};
use dpdk_smoltcp::{Port, Stack, StackConfig, DEFAULT_NEIGHBOR_CAPACITY};

use zhida_test_kit::{ring_port, with_eal};
use ring_port::{arp, RingPort};

const OURS: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x01]);
const OUR_IP: Ipv4Address = Ipv4Address::new(10, 0, 0, 1);
const PEER: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
const PEER_IP: Ipv4Address = Ipv4Address::new(10, 0, 0, 2);
const T0: Instant = Instant::from_millis_const(5_000);

fn stack(port: Port) -> Stack {
    let config = StackConfig {
        max_udp_sockets: 0,
        ethernet: OURS,
        ipv4: Ipv4Cidr::new(OUR_IP, 24),
        gateway: None,
        paths: &[],
        random_seed: 1,
        neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
        segments_per_visit: 1,
        max_sockets: 1,
        rx_staging: 8,
        tx_pending: 8,
    };
    match Stack::new(port, config, T0) {
        Ok(stack) => stack,
        Err((_, error)) => panic!("{error}"),
    }
}

/// One frame from the peer with unassigned IPv4 protocol 253.
fn unknown_protocol_from_peer() -> Vec<u8> {
    let caps = ChecksumCapabilities::default();
    let payload = [0x42; 16];
    let eth = EthernetRepr { src_addr: PEER, dst_addr: OURS, ethertype: EthernetProtocol::Ipv4 };
    let ip = Ipv4Repr {
        src_addr: PEER_IP,
        dst_addr: OUR_IP,
        next_header: IpProtocol::Unknown(253),
        payload_len: payload.len(),
        hop_limit: 64,
    };
    let mut bytes = vec![0; eth.buffer_len() + ip.buffer_len() + payload.len()];
    let mut frame = EthernetFrame::new_unchecked(&mut bytes);
    eth.emit(&mut frame);
    let mut packet = Ipv4Packet::new_unchecked(frame.payload_mut());
    ip.emit(&mut packet, &caps);
    packet.payload_mut().copy_from_slice(&payload);
    bytes
}

fn learn_peer(stack: &mut Stack, fixture: &RingPort) {
    fixture.inject(&[arp(
        ArpOperation::Request,
        EthernetAddress::BROADCAST,
        (PEER, PEER_IP),
        (EthernetAddress([0; 6]), OUR_IP),
    )]);
    stack.turn(T0, 8).unwrap();
    assert_eq!(fixture.take_tx().len(), 1);
}

fn echo_request(src_addr: Ipv4Address, dst_addr: Ipv4Address, corrupt: bool) -> Vec<u8> {
    let caps = ChecksumCapabilities::default();
    let data = [0x5a; 57];
    let icmp = Icmpv4Repr::EchoRequest {
        ident: 0x1234,
        seq_no: 0xabcd,
        data: &data,
    };
    let eth = EthernetRepr {
        src_addr: PEER,
        dst_addr: if dst_addr == Ipv4Address::BROADCAST || dst_addr == Ipv4Address::new(10, 0, 0, 255) {
            EthernetAddress::BROADCAST
        } else {
            OURS
        },
        ethertype: EthernetProtocol::Ipv4,
    };
    let ip = Ipv4Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Icmp,
        payload_len: icmp.buffer_len(),
        hop_limit: 31,
    };
    let mut bytes = vec![0; eth.buffer_len() + ip.buffer_len() + ip.payload_len];
    let mut frame = EthernetFrame::new_unchecked(&mut bytes);
    eth.emit(&mut frame);
    let mut packet = Ipv4Packet::new_unchecked(frame.payload_mut());
    ip.emit(&mut packet, &caps);
    let mut icmp_packet = Icmpv4Packet::new_unchecked(packet.payload_mut());
    icmp.emit(&mut icmp_packet, &caps);
    if corrupt {
        icmp_packet.set_checksum(icmp_packet.checksum() ^ 1);
    }
    bytes
}

#[zhida_test_support::pinned_test]
fn unicast_echo_reply_preserves_ident_seq_and_odd_payload() {
    with_eal(|eal| {
        let fixture = RingPort::new("icmpecho", 16, 16);
        let mut stack = stack(fixture.open(eal));
        learn_peer(&mut stack, &fixture);
        fixture.inject(&[echo_request(PEER_IP, OUR_IP, false)]);
        let turn = stack.turn(T0 + dpdk_smoltcp::smoltcp::time::Duration::from_millis(1), 8).unwrap();
        assert_eq!(turn.rx_processed, 1);
        assert_eq!(turn.tx_accepted, 1);
        let sent = fixture.take_tx();
        assert_eq!(sent.len(), 1, "expected one echo reply frame");
        let eth = EthernetFrame::new_checked(&sent[0]).unwrap();
        assert_eq!(eth.src_addr(), OURS);
        assert_eq!(eth.dst_addr(), PEER);
        assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);
        let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
        assert!(ip.verify_checksum());
        let caps = ChecksumCapabilities::default();
        let ip_repr = Ipv4Repr::parse(&ip, &caps).unwrap();
        assert_eq!(ip_repr, Ipv4Repr {
            src_addr: OUR_IP,
            dst_addr: PEER_IP,
            next_header: IpProtocol::Icmp,
            payload_len: 8 + 57,
            hop_limit: 64,
        });
        let icmp = Icmpv4Packet::new_checked(ip.payload()).unwrap();
        assert!(icmp.verify_checksum());
        assert_eq!(Icmpv4Repr::parse(&icmp, &caps).unwrap(), Icmpv4Repr::EchoReply {
            ident: 0x1234,
            seq_no: 0xabcd,
            data: &[0x5a; 57],
        });
        let port = stack.into_port();
        assert_eq!(fixture.in_use(), (0, 0));
        port.try_close().unwrap();
        fixture.close();
    });
}

#[zhida_test_support::pinned_test]
fn broadcast_invalid_checksum_and_non_unicast_source_echo_no_reply() {
    with_eal(|eal| {
        let fixture = RingPort::new("icmpignored", 16, 16);
        let mut stack = stack(fixture.open(eal));
        learn_peer(&mut stack, &fixture);
        for (src, dst, corrupt) in [
            (PEER_IP, Ipv4Address::new(10, 0, 0, 255), false),
            (PEER_IP, Ipv4Address::BROADCAST, false),
            (PEER_IP, Ipv4Address::new(10, 0, 0, 3), false),
            (PEER_IP, OUR_IP, true),
            (Ipv4Address::UNSPECIFIED, OUR_IP, false),
            (Ipv4Address::BROADCAST, OUR_IP, false),
            (Ipv4Address::new(10, 0, 0, 255), OUR_IP, false),
            (Ipv4Address::new(224, 0, 0, 1), OUR_IP, false),
        ] {
            fixture.inject(&[echo_request(src, dst, corrupt)]);
            let turn = stack.turn(T0 + dpdk_smoltcp::smoltcp::time::Duration::from_millis(1), 8).unwrap();
            assert_eq!(turn.rx_processed, 1);
            assert_eq!(turn.tx_accepted, 0, "echo {src} -> {dst}, corrupt={corrupt}");
            assert!(fixture.take_tx().is_empty(), "echo {src} -> {dst}, corrupt={corrupt}");
        }
        let port = stack.into_port();
        assert_eq!(fixture.in_use(), (0, 0));
        port.try_close().unwrap();
        fixture.close();
    });
}

#[zhida_test_support::pinned_test]
fn unknown_protocol_dropped_no_reply() {
    with_eal(|eal| {
        let fixture = RingPort::new("icmpunknown", 16, 16);
        let mut stack = stack(fixture.open(eal));

        learn_peer(&mut stack, &fixture);

        fixture.inject(&[unknown_protocol_from_peer()]);
        stack.turn(T0 + dpdk_smoltcp::smoltcp::time::Duration::from_millis(1), 8).unwrap();

        assert!(fixture.take_tx().is_empty(), "unknown protocol must not get a reply");

        let port = stack.into_port();
        assert_eq!(fixture.in_use(), (0, 0));
        port.try_close().unwrap();
        fixture.close();
    });
}

#[zhida_test_support::pinned_test]
fn closed_udp_port_dropped_counted_no_reply() {
    with_eal(|eal| {
        let fixture = RingPort::new("udpclosed", 16, 16);
        let mut stack = stack(fixture.open(eal));
        let caps = ChecksumCapabilities::default();
        let payload = b"closed port";
        let udp = UdpRepr {
            src_port: 4321,
            dst_port: 1234,
        };
        let eth = EthernetRepr {
            src_addr: PEER,
            dst_addr: OURS,
            ethertype: EthernetProtocol::Ipv4,
        };
        let ip = Ipv4Repr {
            src_addr: PEER_IP,
            dst_addr: OUR_IP,
            next_header: IpProtocol::Udp,
            payload_len: udp.header_len() + payload.len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0; eth.buffer_len() + ip.buffer_len() + ip.payload_len];
        let mut frame = EthernetFrame::new_unchecked(&mut bytes);
        eth.emit(&mut frame);
        let mut packet = Ipv4Packet::new_unchecked(frame.payload_mut());
        ip.emit(&mut packet, &caps);
        udp.emit(
            &mut UdpPacket::new_unchecked(packet.payload_mut()),
            &PEER_IP.into(),
            &OUR_IP.into(),
            payload.len(),
            |buffer| buffer.copy_from_slice(payload),
            &caps,
        );
        fixture.inject(&[bytes]);
        let turn = stack.turn(T0, 8).unwrap();
        assert_eq!(turn.rx_processed, 1);
        assert_eq!(turn.tx_accepted, 0);
        assert!(fixture.take_tx().is_empty());
        assert_eq!(stack.udp_counters().rx_no_port, 1);
        let port = stack.into_port();
        assert_eq!(fixture.in_use(), (0, 0));
        port.try_close().unwrap();
        fixture.close();
    });
}
