use zhida_test_kit::pair::drain_bytes;
use zhida_test_kit::pair::{self, Pair, Side};
use zhida_test_kit::ring_port::arp;
use zhida_test_kit::with_eal;
use dpdk_smoltcp::smoltcp::phy::ChecksumCapabilities;
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::smoltcp::wire::{
    ArpOperation, EthernetAddress, EthernetFrame, EthernetProtocol, IpEndpoint, IpProtocol,
    Ipv4Address, Ipv4Packet, Ipv4Repr, UdpPacket,
};
use dpdk_smoltcp::{Eal, Stack, UdpConfig, UdpCounters, UdpHandle, UdpSendError};

const PORT: u16 = 1234;
const BURST: usize = 32;

fn new_pair(eal: &Eal, names: [&str; 2]) -> (Pair, [UdpHandle; 2]) {
    new_pair_with_tx_pool(eal, names, 127)
}

fn new_pair_with_tx_pool(eal: &Eal, names: [&str; 2], tx_pool: u32) -> (Pair, [UdpHandle; 2]) {
    let configs = [Side::A, Side::B].map(|side| dpdk_smoltcp::StackConfig {
        max_udp_sockets: 2,
        ..pair::config(side)
    });
    let mut pair = Pair::with_ports(eal, names, configs, pair::T0, 128, |_, port| {
        port.rx_burst = u16::try_from(BURST).unwrap();
        port.tx_burst = u16::try_from(BURST).unwrap();
        port.rx_pool.count = 255;
        port.tx_pool.count = tx_pool;
    });
    let handles =
        [&mut pair.a, &mut pair.b].map(|stack| stack.add_udp(udp_config(true, false)).unwrap());
    (pair, handles)
}

fn udp_config(tx_checksum: bool, broadcast: bool) -> UdpConfig {
    UdpConfig {
        port: PORT,
        rx_queue: BURST,
        tx_checksum,
        broadcast,
    }
}

fn endpoint(side: Side) -> IpEndpoint {
    IpEndpoint::new(side.ip().into(), PORT)
}

fn resolve(pair: &mut Pair, handle: &UdpHandle) {
    assert_eq!(
        pair.a
            .udp_send_with(&handle, Some(endpoint(Side::B)), 1, |_| {
                panic!("ARP discovery must not fill the payload")
            }),
        Err(UdpSendError::NeighborPending)
    );
    pair.round(|_, _| {});
    pair.round(|_, _| {});
}

fn recv(stack: &mut Stack, handle: &UdpHandle, src: IpEndpoint, payload: &[u8]) {
    let datagram = stack.udp_mut(&handle).recv().unwrap();
    assert_eq!(datagram.src(), src);
    assert_eq!(datagram.payload(), payload);
    drop(datagram);
}

fn ip(frame: &[u8]) -> Ipv4Packet<&[u8]> {
    let eth = EthernetFrame::new_checked(frame).unwrap();
    assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);
    let packet = Ipv4Packet::new_checked(&frame[14..]).unwrap();
    Ipv4Repr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
    packet
}

#[zhida_test_support::pinned_test]
fn ipv4_fragment_drop_counted() {
    with_eal(|eal| {
        let (mut pair, handles) = new_pair(eal, ["udpfraga", "udpfragb"]);
        resolve(&mut pair, &handles[0]);
        pair.a
            .udp_send(&handles[0], Some(endpoint(Side::B)), b"payload!")
            .unwrap();
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 1);
        let mut frames = Vec::new();
        assert_eq!(
            pair.drain_tx(Side::A, |frame| frames.push(frame.to_vec())),
            1
        );
        let mut ip = Ipv4Packet::new_unchecked(&mut frames[0][14..]);
        ip.set_more_frags(true);
        ip.fill_checksum();
        pair.inject(Side::B, &frames);
        assert_eq!(pair.b.receive(pair::T0, BURST).unwrap().rx_processed, 1);
        assert_eq!(pair.b.ipv4_dropped(), 1);
        assert_eq!(pair.b.udp_counters(), UdpCounters::default());
        assert_eq!(pair.b.udp(&handles[1]).stats().rx_delivered, 0);
        assert!(pair.b.udp_mut(&handles[1]).recv().is_none());
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn stream_exact_bytes_order_counts() {
    with_eal(|eal| {
        for checksum in [true, false] {
            let (mut pair, mut handles) = new_pair(eal, ["udpsa", "udpsb"]);
            resolve(&mut pair, &handles[0]);
            let [a, b] = handles;
            pair.a.remove_udp(a);
            let a = pair.a.add_udp(udp_config(checksum, false)).unwrap();
            pair.b.remove_udp(b);
            let b = pair.b.add_udp(udp_config(checksum, false)).unwrap();
            handles = [a, b];
            let mut delivered = [0u64; 2];
            for side in [Side::A, Side::B] {
                let (sender, _) = side.pick(&mut pair.a, &mut pair.b);
                sender
                    .udp_send(&handles[side.index()], Some(endpoint(side.other())), b"warm")
                    .unwrap();
                pair.round(|_, _| {});
                pair.round(|_, _| {});
                let receiver_index = side.other().index();
                let (_, receiver) = side.pick(&mut pair.a, &mut pair.b);
                recv(receiver, &handles[receiver_index], endpoint(side), b"warm");
                delivered[receiver_index] += 1;
                let idle = pair.in_use();
                for size in [1, 64, 512, 1472] {
                    for batch in 0..3 {
                        for sequence in batch * BURST..(batch + 1) * BURST {
                            let payload = vec![u8::try_from(sequence).unwrap(); size];
                            let (sender, _) = side.pick(&mut pair.a, &mut pair.b);
                            sender
                                .udp_send_with(&handles[side.index()],
                                    Some(endpoint(side.other())),
                                    size,
                                    |buffer| buffer.copy_from_slice(&payload),
                                )
                                .unwrap();
                        }
                        let mut frames = 0;
                        pair.round(|dir, frame| {
                            assert_eq!(dir, side.dir());
                            let packet = ip(frame);
                            assert_eq!(
                                (packet.src_addr(), packet.dst_addr()),
                                (side.ip(), side.other().ip())
                            );
                            assert_eq!(packet.next_header(), IpProtocol::Udp);
                            let udp = UdpPacket::new_checked(packet.payload()).unwrap();
                            assert_eq!(
                                udp.payload(),
                                vec![u8::try_from(batch * BURST + frames).unwrap(); size]
                            );
                            if checksum {
                                assert_ne!(udp.checksum(), 0);
                                assert!(udp
                                    .verify_checksum(&side.ip().into(), &side.other().ip().into()));
                            } else {
                                assert_eq!(udp.checksum(), 0);
                            }
                            frames += 1;
                        });
                        assert_eq!(frames, BURST);
                        pair.round(|_, _| panic!("UDP must not generate a reply"));
                        let receiver_index = side.other().index();
                        assert_eq!(
                            pair.in_use()[receiver_index].0,
                            idle[receiver_index].0 + BURST as u32
                        );
                        let (_, receiver) = side.pick(&mut pair.a, &mut pair.b);
                        for sequence in batch * BURST..(batch + 1) * BURST {
                            recv(
                                receiver,
                                &handles[receiver_index],
                                endpoint(side),
                                &vec![u8::try_from(sequence).unwrap(); size],
                            );
                        }
                        delivered[receiver_index] += BURST as u64;
                        let stats = receiver.udp(&handles[receiver_index]).stats();
                        assert_eq!(stats.rx_delivered, delivered[receiver_index]);
                        assert_eq!(stats.rx_dropped_full, 0);
                        assert_eq!(stats.rx_dropped_peer, 0);
                        assert!(receiver.udp_mut(&handles[receiver_index]).recv().is_none());
                        assert_eq!(pair.in_use(), idle);
                    }
                }
            }
            assert_eq!(delivered, [385; 2]);
            assert_eq!(pair.a.udp_counters(), UdpCounters::default());
            assert_eq!(pair.b.udp_counters(), UdpCounters::default());
            pair::assert_lossless(&pair.a_to_b, "A to B");
            pair::assert_lossless(&pair.b_to_a, "B to A");
            assert_eq!(pair.close(), 0);
        }
    });
}

#[zhida_test_support::pinned_test]
fn first_send_arps_then_succeeds() {
    with_eal(|eal| {
        let (mut pair, handles) = new_pair(eal, ["udpfa", "udpfb"]);
        let mut filled = false;
        assert_eq!(
            pair.a
                .udp_send_with(&handles[0], Some(endpoint(Side::B)), 5, |_| filled = true),
            Err(UdpSendError::NeighborPending)
        );
        assert!(!filled);
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 1);
        assert_eq!(
            pair.a_to_b.forward_with(|frame| {
                assert_eq!(
                    frame,
                    arp(
                        ArpOperation::Request,
                        EthernetAddress::BROADCAST,
                        (Side::A.mac(), Side::A.ip()),
                        (EthernetAddress::BROADCAST, Side::B.ip())
                    )
                );
            }),
            1
        );
        pair.b.receive(pair::T0, BURST).unwrap();
        assert_eq!(
            pair.b_to_a.forward_with(|frame| {
                assert_eq!(
                    frame,
                    arp(
                        ArpOperation::Reply,
                        Side::A.mac(),
                        (Side::B.mac(), Side::B.ip()),
                        (Side::A.mac(), Side::A.ip())
                    )
                );
            }),
            1
        );
        pair.a.receive(pair::T0, BURST).unwrap();
        pair.a
            .udp_send_with(&handles[0], Some(endpoint(Side::B)), 5, |buffer| {
                filled = true;
                buffer.copy_from_slice(b"hello");
            })
            .unwrap();
        assert!(filled);
        pair.round(|_, _| {});
        recv(&mut pair.b, &handles[1], endpoint(Side::A), b"hello");
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn pending_full_would_block_and_blocks_rx_until_flush() {
    with_eal(|eal| {
        let (mut pair, handles) = new_pair_with_tx_pool(eal, ["udppfa", "udppfb"], 255);
        resolve(&mut pair, &handles[0]);
        for _ in 0..127 {
            pair.a
                .udp_send(&handles[0], Some(endpoint(Side::B)), b"ring")
                .unwrap();
            assert_eq!(pair.a.flush().unwrap().tx_accepted, 1);
        }
        for _ in 0..BURST {
            pair.a
                .udp_send(&handles[0], Some(endpoint(Side::B)), b"pending")
                .unwrap();
        }
        assert_eq!(
            pair.a
                .udp_send_with(&handles[0], Some(endpoint(Side::B)), 1, |_| {
                    panic!("full queue must not fill")
                }),
            Err(UdpSendError::WouldBlock)
        );
        pair.b
            .udp_send(&handles[1], Some(endpoint(Side::A)), b"incoming")
            .unwrap();
        pair.b.flush().unwrap();
        assert_eq!(pair.b_to_a.forward(), 1);
        let turn = pair.a.receive(pair::T0, BURST).unwrap();
        assert_eq!(
            (turn.rx_received, turn.rx_processed, turn.rx_staged),
            (1, 0, 1)
        );
        assert_eq!(turn.tx_accepted, 0);
        assert_eq!(turn.tx_pending, BURST);
        assert!(turn.rx_blocked);
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 0);
        assert_eq!(pair.drain_tx(Side::A, |_| {}), 127);
        assert_eq!(pair.a.flush().unwrap().tx_accepted, BURST);
        assert_eq!(pair.drain_tx(Side::A, |_| {}), BURST);
        pair.a
            .udp_send(&handles[0], Some(endpoint(Side::B)), b"retry")
            .unwrap();
        let turn = pair.a.receive(pair::T0, BURST).unwrap();
        assert_eq!(turn.rx_processed, 1);
        assert!(!turn.rx_blocked);
        assert_eq!(turn.tx_accepted, 1);
        assert_eq!(turn.tx_pending, 0);
        recv(&mut pair.a, &handles[0], endpoint(Side::B), b"incoming");
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 0);
        assert_eq!(
            pair.drain_tx(Side::A, |frame| {
                let packet = ip(frame);
                let udp = UdpPacket::new_checked(packet.payload()).unwrap();
                assert_eq!(udp.payload(), b"retry");
            }),
            1
        );
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn udp_tcp_share_pending_in_call_order() {
    with_eal(|eal| {
        let (mut pair, udp) = new_pair(eal, ["udporda", "udpordb"]);
        let (tcp, _) = pair::establish(&mut pair, Side::A);
        for (tcp_payload, udp_payload) in [(b"t1", b"u1"), (b"t2", b"u2"), (b"t3", b"u3")] {
            assert_eq!(pair.a.tcp_mut(&tcp[0]).send_slice(tcp_payload), Ok(2));
            assert_eq!(
                pair.a.send().unwrap().tx_accepted,
                if tcp_payload == b"t1" { 1 } else { 2 }
            );
            pair.a
                .udp_send(&udp[0], Some(endpoint(Side::B)), udp_payload)
                .unwrap();
        }
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 1);
        let mut frames = Vec::new();
        assert_eq!(
            pair.drain_tx(Side::A, |frame| frames.push(frame.to_vec())),
            6
        );
        for (index, frame) in frames.iter().enumerate() {
            let sequence = u8::try_from(index / 2 + 1).unwrap() + b'0';
            if index % 2 == 0 {
                assert_eq!(pair::segment(frame, Side::A).payload, [b't', sequence]);
            } else {
                let packet = ip(frame);
                assert_eq!(packet.next_header(), IpProtocol::Udp);
                assert_eq!(
                    UdpPacket::new_checked(packet.payload()).unwrap().payload(),
                    [b'u', sequence]
                );
            }
        }
        pair.inject(Side::B, &frames);
        assert_eq!(pair.b.receive(pair::T0, BURST).unwrap().rx_processed, 6);
        for payload in [b"u1", b"u2", b"u3"] {
            recv(&mut pair.b, &udp[1], endpoint(Side::A), payload);
        }
        let received = drain_bytes(pair.b.tcp_mut(&tcp[1])).unwrap();
        assert_eq!(received.len(), 6);
        assert_eq!(&received, b"t1t2t3");
        pair.round(|_, _| {});
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn connected_send_default_peer_and_mismatch() {
    with_eal(|eal| {
        let (mut pair, handles) = new_pair(eal, ["udpcona", "udpconb"]);
        resolve(&mut pair, &handles[0]);
        pair.a
            .udp_mut(&handles[0])
            .connect(endpoint(Side::B))
            .unwrap();
        pair.b
            .udp_mut(&handles[1])
            .connect(endpoint(Side::A))
            .unwrap();
        pair.a.udp_send(&handles[0], None, b"connected").unwrap();
        pair.round(|_, _| {});
        recv(&mut pair.b, &handles[1], endpoint(Side::A), b"connected");
        assert_eq!(
            pair.a.udp_send_with(&handles[0],
                Some(IpEndpoint::new(Side::B.ip().into(), PORT + 1)),
                1,
                |_| panic!("peer mismatch must not fill")
            ),
            Err(UdpSendError::PeerMismatch)
        );
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 0);
        let other = pair
            .a
            .add_udp(UdpConfig {
                port: PORT + 1,
                ..udp_config(true, false)
            })
            .unwrap();
        pair.a
            .udp_send(&other, Some(endpoint(Side::B)), b"other source")
            .unwrap();
        pair.round(|_, _| {});
        assert!(pair.b.udp_mut(&handles[1]).recv().is_none());
        assert_eq!(pair.b.udp(&handles[1]).stats().rx_delivered, 1);
        assert_eq!(pair.b.udp(&handles[1]).stats().rx_dropped_peer, 1);
        assert_eq!(pair.b.udp_counters(), UdpCounters::default());
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn one_way_stream_across_neighbor_expiry() {
    with_eal(|eal| {
        let (mut pair, handles) = new_pair(eal, ["udpexpa", "udpexpb"]);
        resolve(&mut pair, &handles[0]);
        pair.a
            .udp_send(&handles[0], Some(endpoint(Side::B)), &[0])
            .unwrap();
        pair.round(|dir, frame| {
            assert_eq!(dir, Side::A.dir());
            assert_eq!(ip(frame).next_header(), IpProtocol::Udp);
        });
        recv(&mut pair.b, &handles[1], endpoint(Side::A), &[0]);
        let mut replies = Vec::new();
        let mut last_probe = None;
        let mut probes = 0;
        for (sequence, offset) in [60_001, 60_501, 61_001, 61_501, 62_001]
            .into_iter()
            .enumerate()
        {
            let now = Instant::from_millis(pair::T0.total_millis().checked_add(offset).unwrap());
            pair.a.receive(now, BURST).unwrap();
            let payload = [u8::try_from(sequence + 1).unwrap()];
            assert_eq!(
                pair.a
                    .udp_send(&handles[0], Some(endpoint(Side::B)), &payload),
                Ok(())
            );
            pair.a.flush().unwrap();
            let mut datagrams = 0;
            let mut requests = 0;
            pair.a_to_b.forward_with(|frame| {
                let eth = EthernetFrame::new_checked(frame).unwrap();
                match eth.ethertype() {
                    EthernetProtocol::Arp => {
                        assert_eq!(
                            frame,
                            arp(
                                ArpOperation::Request,
                                EthernetAddress::BROADCAST,
                                (Side::A.mac(), Side::A.ip()),
                                (EthernetAddress::BROADCAST, Side::B.ip())
                            )
                        );
                        if let Some(last) = last_probe {
                            assert!(offset.checked_sub(last).unwrap() >= 1000);
                        }
                        last_probe = Some(offset);
                        requests += 1;
                    }
                    EthernetProtocol::Ipv4 => {
                        let packet = ip(frame);
                        assert_eq!(packet.next_header(), IpProtocol::Udp);
                        assert_eq!(
                            UdpPacket::new_checked(packet.payload()).unwrap().payload(),
                            payload
                        );
                        datagrams += 1;
                    }
                    protocol => panic!("unexpected protocol {protocol:?}"),
                }
            });
            assert_eq!(datagrams, 1);
            assert_eq!(requests, usize::from(sequence % 2 == 0));
            probes += requests;
            pair.b.receive(now, BURST).unwrap();
            recv(&mut pair.b, &handles[1], endpoint(Side::A), &payload);
            assert_eq!(
                pair.drain_tx(Side::B, |frame| {
                    assert_eq!(
                        frame,
                        arp(
                            ArpOperation::Reply,
                            Side::A.mac(),
                            (Side::B.mac(), Side::B.ip()),
                            (Side::A.mac(), Side::A.ip())
                        )
                    );
                    replies.push(frame.to_vec());
                }),
                requests
            );
        }
        assert_eq!(probes, 3);
        pair.inject(Side::A, &replies);
        let now = Instant::from_millis(pair::T0.total_millis().checked_add(62_002).unwrap());
        assert_eq!(pair.a.receive(now, BURST).unwrap().rx_processed, 3);
        pair.a
            .udp_send(&handles[0], Some(endpoint(Side::B)), &[6])
            .unwrap();
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 1);
        assert_eq!(
            pair.a_to_b.forward_with(|frame| {
                assert_eq!(ip(frame).next_header(), IpProtocol::Udp);
            }),
            1
        );
        pair.b.receive(now, BURST).unwrap();
        recv(&mut pair.b, &handles[1], endpoint(Side::A), &[6]);
        assert_eq!(pair.b.udp(&handles[1]).stats().rx_delivered, 7);
        assert_eq!(
            pair.drain_tx(Side::B, |_| panic!("B must send only ARP replies")),
            0
        );
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn parallel_peers_each_get_arp_udp() {
    with_eal(|eal| {
        let (mut pair, handles) = new_pair(eal, ["udp3a", "udp3b"]);
        let peers = [
            (Side::B.mac(), Side::B.ip()),
            (
                EthernetAddress([2, 0, 0, 0, 0, 12]),
                Ipv4Address::new(10, 0, 0, 3),
            ),
            (
                EthernetAddress([2, 0, 0, 0, 0, 13]),
                Ipv4Address::new(10, 0, 0, 4),
            ),
        ];
        for (_, address) in peers {
            assert_eq!(
                pair.a.udp_send_with(&handles[0],
                    Some(IpEndpoint::new(address.into(), PORT)),
                    1,
                    |_| panic!("unresolved peers must not fill")
                ),
                Err(UdpSendError::NeighborPending)
            );
        }
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 3);
        let mut requests = Vec::new();
        assert_eq!(
            pair.drain_tx(Side::A, |frame| requests.push(frame.to_vec())),
            3
        );
        for (frame, (_, address)) in requests.iter().zip(peers) {
            assert_eq!(
                frame,
                &arp(
                    ArpOperation::Request,
                    EthernetAddress::BROADCAST,
                    (Side::A.mac(), Side::A.ip()),
                    (EthernetAddress::BROADCAST, address)
                )
            );
        }
        pair.inject(Side::B, &requests[..1]);
        pair.b.receive(pair::T0, BURST).unwrap();
        assert_eq!(pair.b_to_a.forward(), 1);
        let replies: Vec<_> = peers[1..]
            .iter()
            .map(|&peer| {
                arp(
                    ArpOperation::Reply,
                    Side::A.mac(),
                    peer,
                    (Side::A.mac(), Side::A.ip()),
                )
            })
            .collect();
        pair.inject(Side::A, &replies);
        assert_eq!(pair.a.receive(pair::T0, BURST).unwrap().rx_processed, 3);
        for (index, (_, address)) in peers.iter().enumerate() {
            pair.a
                .udp_send(&handles[0],
                    Some(IpEndpoint::new((*address).into(), PORT)),
                    &[u8::try_from(index).unwrap()],
                )
                .unwrap();
        }
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 3);
        let mut index = 0;
        let mut to_b = Vec::new();
        assert_eq!(
            pair.drain_tx(Side::A, |frame| {
                let eth = EthernetFrame::new_checked(frame).unwrap();
                assert_eq!(eth.dst_addr(), peers[index].0);
                let packet = ip(frame);
                assert_eq!(packet.dst_addr(), peers[index].1);
                assert_eq!(packet.next_header(), IpProtocol::Udp);
                let udp = UdpPacket::new_checked(packet.payload()).unwrap();
                assert_eq!((udp.src_port(), udp.dst_port()), (PORT, PORT));
                assert_eq!(udp.payload(), [u8::try_from(index).unwrap()]);
                if index == 0 {
                    to_b.push(frame.to_vec());
                }
                index += 1;
            }),
            3
        );
        assert_eq!(index, 3);
        pair.inject(Side::B, &to_b);
        pair.b.receive(pair::T0, BURST).unwrap();
        recv(&mut pair.b, &handles[1], endpoint(Side::A), &[0]);
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn too_large_and_broadcast_opt_in() {
    with_eal(|eal| {
        let (mut pair, handles) = new_pair(eal, ["udpbra", "udpbrb"]);
        assert_eq!(
            pair.a
                .udp_send_with(&handles[0], Some(endpoint(Side::B)), 1473, |_| {
                    panic!("oversized datagrams must not fill")
                }),
            Err(UdpSendError::TooLarge)
        );
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 0);
        let broadcast = IpEndpoint::new(Ipv4Address::BROADCAST.into(), PORT);
        assert_eq!(
            pair.a.udp_send_with(&handles[0], Some(broadcast), 1, |_| {
                panic!("broadcast without opt-in must not fill")
            }),
            Err(UdpSendError::Unaddressable)
        );
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 0);
        let [sender, receiver] = handles;
        pair.a.remove_udp(sender);
        let sender = pair.a.add_udp(udp_config(true, true)).unwrap();
        pair.a
            .udp_send(&sender, Some(broadcast), b"broadcast")
            .unwrap();
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 1);
        assert_eq!(
            pair.a_to_b.forward_with(|frame| {
                assert_eq!(
                    EthernetFrame::new_checked(frame).unwrap().dst_addr(),
                    EthernetAddress::BROADCAST
                );
                assert_eq!(ip(frame).dst_addr(), Ipv4Address::BROADCAST);
            }),
            1
        );
        pair.b.receive(pair::T0, BURST).unwrap();
        let datagram = pair.b.udp_mut(&receiver).recv().unwrap();
        assert_eq!(datagram.src(), endpoint(Side::A));
        assert_eq!(datagram.dst_addr(), Ipv4Address::BROADCAST);
        assert_eq!(datagram.payload(), b"broadcast");
        drop(datagram);
        assert_eq!(pair.b.udp(&receiver).stats().rx_delivered, 1);
        assert_eq!(pair.b.udp_counters(), UdpCounters::default());
        assert_eq!(pair.close(), 0);
    });
}
