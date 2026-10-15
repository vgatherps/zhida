use zhida_test_kit::pair::{self, Pair, Side};
use zhida_test_kit::peers::{peer_ip, peer_mac};
use zhida_test_kit::ring_port::arp;
use zhida_test_kit::with_eal;
use dpdk_smoltcp::smoltcp::phy::ChecksumCapabilities;
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::smoltcp::wire::{
    ArpOperation, EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, IpEndpoint,
    IpProtocol, Ipv4Address, Ipv4Cidr, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr,
};
use dpdk_smoltcp::{Eal, StackConfig, UdpConfig, UdpHandle, UdpSendError};

const PORT: u16 = 1234;
const PEER_PORT: u16 = 4321;
const PEER: Ipv4Address = Ipv4Address::new(198, 51, 100, 7);
const BURST: usize = 32;
const PEERS: usize = 256;

fn new_pair(eal: &Eal, gateway: Option<Ipv4Address>, capacity: usize) -> (Pair, UdpHandle) {
    let configs = [
        StackConfig {
            ipv4: Ipv4Cidr::new(Side::A.ip(), 16),
            gateway,
            neighbor_capacity: capacity,
            max_udp_sockets: 1,
            ..pair::config(Side::A)
        },
        pair::config(Side::B),
    ];
    let mut pair = Pair::with_ports(
        eal,
        ["udprta", "udprtb"],
        configs,
        pair::T0,
        128,
        |_, port| {
            port.rx_burst = u16::try_from(BURST).unwrap();
            port.tx_burst = u16::try_from(BURST).unwrap();
            port.rx_pool.count = 255;
            port.tx_pool.count = 127;
        },
    );
    let handle = pair
        .a
        .add_udp(UdpConfig {
            port: PORT,
            rx_queue: BURST,
            tx_checksum: true,
            broadcast: false,
        })
        .unwrap();
    (pair, handle)
}

fn endpoint(ip: Ipv4Address) -> IpEndpoint {
    IpEndpoint::new(ip.into(), PEER_PORT)
}

fn now(offset: i64) -> Instant {
    Instant::from_millis(
        pair::T0
            .total_millis()
            .checked_add(offset)
            .expect("time overflow"),
    )
}

fn request(ip: Ipv4Address) -> Vec<u8> {
    arp(
        ArpOperation::Request,
        EthernetAddress::BROADCAST,
        (Side::A.mac(), Side::A.ip()),
        (EthernetAddress::BROADCAST, ip),
    )
}

fn reply(ip: Ipv4Address, mac: EthernetAddress) -> Vec<u8> {
    arp(
        ArpOperation::Reply,
        Side::A.mac(),
        (mac, ip),
        (Side::A.mac(), Side::A.ip()),
    )
}

fn resolve_gateway(pair: &mut Pair, handle: &UdpHandle) {
    assert_eq!(
        pair.a.udp_send_with(&handle, Some(endpoint(PEER)), 1, |_| {
            panic!("neighbor discovery must not fill")
        }),
        Err(UdpSendError::NeighborPending)
    );
    assert_eq!(pair.a.flush().unwrap().tx_accepted, 1);
    assert_eq!(
        pair.drain_tx(Side::A, |frame| assert_eq!(frame, request(Side::B.ip()))),
        1
    );
    pair.inject(Side::A, &[reply(Side::B.ip(), Side::B.mac())]);
    assert_eq!(pair.a.receive(pair::T0, BURST).unwrap().rx_processed, 1);
}

fn assert_datagram(frame: &[u8], dst: Ipv4Address, mac: EthernetAddress, payload: &[u8]) {
    let eth = EthernetFrame::new_checked(frame).unwrap();
    assert_eq!(
        (eth.src_addr(), eth.dst_addr(), eth.ethertype()),
        (Side::A.mac(), mac, EthernetProtocol::Ipv4)
    );
    let caps = ChecksumCapabilities::default();
    let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
    let repr = Ipv4Repr::parse(&ip, &caps).unwrap();
    assert_eq!(
        (repr.src_addr, repr.dst_addr, repr.next_header),
        (Side::A.ip(), dst, IpProtocol::Udp)
    );
    let udp = UdpPacket::new_checked(ip.payload()).unwrap();
    assert_eq!((udp.src_port(), udp.dst_port()), (PORT, PEER_PORT));
    assert_eq!(udp.payload(), payload);
    assert_ne!(udp.checksum(), 0);
    assert!(udp.verify_checksum(&Side::A.ip().into(), &dst.into()));
}

#[zhida_test_support::pinned_test]
fn off_subnet_send_uses_gateway_mac() {
    with_eal(|eal| {
        let (mut pair, handle) = new_pair(eal, Some(Side::B.ip()), PEERS);
        resolve_gateway(&mut pair, &handle);
        for dst in [PEER, Ipv4Address::new(203, 0, 113, 8)] {
            pair.a
                .udp_send(&handle, Some(endpoint(dst)), b"remote")
                .unwrap();
            assert_eq!(pair.a.flush().unwrap().tx_accepted, 1);
            assert_eq!(
                pair.drain_tx(Side::A, |frame| {
                    assert_datagram(frame, dst, Side::B.mac(), b"remote");
                }),
                1
            );
        }
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn off_subnet_receive_from_gateway_mac() {
    with_eal(|eal| {
        let (mut pair, handle) = new_pair(eal, Some(Side::B.ip()), PEERS);
        resolve_gateway(&mut pair, &handle);
        let caps = ChecksumCapabilities::default();
        let payload = b"from remote";
        let udp = UdpRepr {
            src_port: PEER_PORT,
            dst_port: PORT,
        };
        let eth = EthernetRepr {
            src_addr: Side::B.mac(),
            dst_addr: Side::A.mac(),
            ethertype: EthernetProtocol::Ipv4,
        };
        let ip = Ipv4Repr {
            src_addr: PEER,
            dst_addr: Side::A.ip(),
            next_header: IpProtocol::Udp,
            payload_len: udp
                .header_len()
                .checked_add(payload.len())
                .expect("UDP length overflow"),
            hop_limit: 64,
        };
        let len = eth
            .buffer_len()
            .checked_add(ip.buffer_len())
            .and_then(|len| len.checked_add(ip.payload_len))
            .expect("frame length overflow");
        let mut bytes = vec![0; len];
        let mut frame = EthernetFrame::new_unchecked(&mut bytes);
        eth.emit(&mut frame);
        let mut packet = Ipv4Packet::new_unchecked(frame.payload_mut());
        ip.emit(&mut packet, &caps);
        udp.emit(
            &mut UdpPacket::new_unchecked(packet.payload_mut()),
            &PEER.into(),
            &Side::A.ip().into(),
            payload.len(),
            |buffer| buffer.copy_from_slice(payload),
            &caps,
        );
        pair.inject(Side::A, &[bytes]);
        assert_eq!(pair.a.receive(pair::T0, BURST).unwrap().rx_processed, 1);
        let datagram = pair.a.udp_mut(&handle).recv().unwrap();
        assert_eq!(datagram.src(), endpoint(PEER));
        assert_eq!(datagram.payload(), payload);
        pair.a
            .udp_send(&handle, Some(datagram.src()), datagram.payload())
            .unwrap();
        drop(datagram);
        assert!(pair.a.udp_mut(&handle).recv().is_none());
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 1);
        assert_eq!(
            pair.drain_tx(Side::A, |frame| {
                assert_datagram(frame, PEER, Side::B.mac(), payload);
            }),
            1
        );
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn off_subnet_without_gateway_no_route() {
    with_eal(|eal| {
        let (mut pair, handle) = new_pair(eal, None, PEERS);
        let mut filled = false;
        assert_eq!(
            pair.a
                .udp_send_with(&handle, Some(endpoint(PEER)), 1, |_| filled = true),
            Err(UdpSendError::NoRoute)
        );
        assert!(!filled);
        assert_eq!(
            pair.a.udp_send(&handle, Some(endpoint(PEER)), b"remote"),
            Err(UdpSendError::NoRoute)
        );
        let flushed = pair.a.flush().unwrap();
        assert_eq!((flushed.tx_accepted, flushed.tx_pending), (0, 0));
        assert_eq!(
            pair.drain_tx(Side::A, |_| panic!("no route must not send")),
            0
        );
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn gateway_stale_keeps_sending() {
    with_eal(|eal| {
        let (mut pair, handle) = new_pair(eal, Some(Side::B.ip()), PEERS);
        resolve_gateway(&mut pair, &handle);
        let mut last_probe = None;
        let mut probes = 0;
        for offset in [0, 59_999, 60_000, 60_500, 61_000, 61_500, 62_000] {
            pair.a.receive(now(offset), BURST).unwrap();
            assert_eq!(
                pair.a.udp_send(&handle, Some(endpoint(PEER)), b"stream"),
                Ok(())
            );
            pair.a.flush().unwrap();
            let (mut requests, mut datagrams) = (0, 0);
            pair.drain_tx(Side::A, |frame| {
                let eth = EthernetFrame::new_checked(frame).unwrap();
                match eth.ethertype() {
                    EthernetProtocol::Arp => {
                        assert_eq!(frame, request(Side::B.ip()));
                        if let Some(last) = last_probe {
                            assert!(
                                offset.checked_sub(last).expect("probe time went backwards")
                                    >= 1000
                            );
                        }
                        last_probe = Some(offset);
                        requests += 1;
                    }
                    EthernetProtocol::Ipv4 => {
                        assert_datagram(frame, PEER, Side::B.mac(), b"stream");
                        datagrams += 1;
                    }
                    protocol => panic!("unexpected protocol {protocol:?}"),
                }
            });
            assert_eq!(datagrams, 1);
            assert_eq!(
                requests,
                usize::from(offset >= 60_000 && offset % 1000 == 0)
            );
            probes += requests;
        }
        assert_eq!(probes, 3);
        pair.inject(Side::A, &[reply(Side::B.ip(), Side::B.mac())]);
        assert_eq!(pair.a.receive(now(62_001), BURST).unwrap().rx_processed, 1);
        for offset in [62_001, 63_001, 65_000] {
            pair.a.receive(now(offset), BURST).unwrap();
            assert_eq!(
                pair.a.udp_send(&handle, Some(endpoint(PEER)), b"answered"),
                Ok(())
            );
            assert_eq!(pair.a.flush().unwrap().tx_accepted, 1);
            assert_eq!(
                pair.drain_tx(Side::A, |frame| {
                    assert_datagram(frame, PEER, Side::B.mac(), b"answered");
                }),
                1
            );
        }
        assert_eq!(pair.close(), 0);
    });
}

fn drain_peer(pair: &Pair, i: usize, payload: &[u8], replies: &mut Vec<Vec<u8>>) -> (usize, usize) {
    let (mut requests, mut datagrams) = (0, 0);
    let drained = pair.drain_tx(Side::A, |frame| {
        let eth = EthernetFrame::new_checked(frame).unwrap();
        match eth.ethertype() {
            EthernetProtocol::Arp => {
                assert_eq!(frame, request(peer_ip(i)));
                replies.push(reply(peer_ip(i), peer_mac(i)));
                requests += 1;
            }
            EthernetProtocol::Ipv4 => {
                assert_datagram(frame, peer_ip(i), peer_mac(i), payload);
                datagrams += 1;
            }
            protocol => panic!("unexpected protocol {protocol:?}"),
        }
    });
    assert_eq!(drained, requests + datagrams);
    (requests, datagrams)
}

#[zhida_test_support::pinned_test]
fn send_to_many_peers() {
    with_eal(|eal| {
        let (mut pair, handle) = new_pair(eal, None, PEERS);
        let mut replies = Vec::new();
        for i in 0..PEERS {
            let payload = [0, u8::try_from(i).unwrap()];
            assert_eq!(
                pair.a
                    .udp_send(&handle, Some(endpoint(peer_ip(i))), &payload),
                Err(UdpSendError::NeighborPending)
            );
            assert_eq!(pair.a.flush().unwrap().tx_accepted, 1);
            assert_eq!(drain_peer(&pair, i, &payload, &mut replies), (1, 0));
            pair.inject(Side::A, &replies);
            replies.clear();
            assert_eq!(pair.a.receive(pair::T0, BURST).unwrap().rx_processed, 1);
            assert_eq!(
                pair.a
                    .udp_send(&handle, Some(endpoint(peer_ip(i))), &payload),
                Ok(())
            );
            assert_eq!(pair.a.flush().unwrap().tx_accepted, 1);
            assert_eq!(drain_peer(&pair, i, &payload, &mut replies), (0, 1));
        }
        for i in 0..PEERS {
            let payload = [1, u8::try_from(i).unwrap()];
            assert_eq!(
                pair.a
                    .udp_send(&handle, Some(endpoint(peer_ip(i))), &payload),
                Ok(())
            );
            assert_eq!(pair.a.flush().unwrap().tx_accepted, 1);
            assert_eq!(drain_peer(&pair, i, &payload, &mut replies), (0, 1));
        }
        assert!(replies.is_empty());
        assert_eq!(pair.close(), 0);

        let capacity = 64;
        let (mut pair, handle) = new_pair(eal, None, capacity);
        let (mut total_requests, mut delivered, mut pending) = (0, 0, 0);
        for second in 0usize..6 {
            let mut requests = 0;
            for tick in 0usize..10 {
                let offset = second
                    .checked_mul(1000)
                    .and_then(|offset| {
                        tick.checked_mul(100)
                            .and_then(|tick| offset.checked_add(tick))
                    })
                    .expect("time overflow");
                pair.a
                    .receive(now(i64::try_from(offset).unwrap()), BURST)
                    .unwrap();
                for sequence in 0..PEERS {
                    let i = sequence
                        .checked_add(second.checked_mul(capacity).expect("peer overflow"))
                        .expect("peer overflow")
                        % PEERS;
                    let payload = [u8::try_from(second).unwrap(), u8::try_from(i).unwrap()];
                    let sent = pair
                        .a
                        .udp_send(&handle, Some(endpoint(peer_ip(i))), &payload);
                    match sent {
                        Ok(()) => delivered += 1,
                        Err(UdpSendError::NeighborPending) => pending += 1,
                        Err(UdpSendError::WouldBlock) => {}
                        result => panic!("unexpected send to peer {i}: {result:?}"),
                    }
                    pair.a.flush().unwrap();
                    let (arps, datagrams) = drain_peer(&pair, i, &payload, &mut replies);
                    assert_eq!(datagrams, usize::from(sent.is_ok()));
                    assert!(arps <= 1);
                    requests += arps;
                }
            }
            assert!(
                requests <= capacity,
                "second {second}: {requests} ARP requests"
            );
            total_requests += requests;
            let offset = second
                .checked_mul(1000)
                .and_then(|offset| offset.checked_add(999))
                .expect("time overflow");
            for frames in replies.chunks(BURST) {
                pair.inject(Side::A, frames);
                assert_eq!(
                    pair.a
                        .receive(now(i64::try_from(offset).unwrap()), BURST)
                        .unwrap()
                        .rx_processed,
                    frames.len()
                );
            }
            replies.clear();
        }
        assert!(total_requests > capacity, "no cache eviction was exercised");
        assert!(delivered > 0);
        assert!(pending > 0);
        assert_eq!(pair.close(), 0);
    });
}
