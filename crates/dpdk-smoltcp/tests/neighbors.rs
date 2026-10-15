use zhida_test_kit::pair::drain_bytes;
use zhida_test_kit::many;
use zhida_test_kit::pair::{self, tcp_socket_sized, Pair, Side, T0};
use zhida_test_kit::peers;
use zhida_test_kit::ring_port::{arp, RingPort};
use zhida_test_kit::with_eal;
use dpdk_smoltcp::smoltcp::phy::ChecksumCapabilities;
use dpdk_smoltcp::smoltcp::time::Duration;
use dpdk_smoltcp::smoltcp::wire::{
    ArpOperation, EthernetAddress, EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Cidr,
    Ipv4Address, Ipv4Packet, Ipv4Repr, TcpPacket, TcpRepr,
};
use dpdk_smoltcp::{rx_pool_count, rx_reserve};
use dpdk_smoltcp::{Eal, NoRoute, Stack, StackConfig, StackError, DEFAULT_NEIGHBOR_CAPACITY};

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

fn reconnect(eal: &Eal, p: usize, neighbor_capacity: usize) -> [(usize, Duration, usize); 2] {
    let names = [format!("peers{p}a"), format!("peers{p}b")];
    let configs = [
        StackConfig {
            max_udp_sockets: 0,
            ipv4: Ipv4Cidr::new(Side::A.ip(), 16),
            neighbor_capacity,
            ..many::config(Side::A, p)
        },
        many::config(Side::B, 1),
    ];
    let mut pair = Pair::with_ports(
        eal,
        [&names[0], &names[1]],
        configs,
        T0,
        64,
        |side, port| {
            port.rx_burst = 32;
            port.rx_pool.count = rx_pool_count(
                rx_reserve(
                    port.rx_descriptors,
                    configs[side.index()].rx_staging,
                    port.rx_pool.cache_size,
                ),
                port.mtu,
                std::iter::repeat(256).take(if side == Side::A { p } else { 0 }),
            );
            port.tx_pool.count = 127;
        },
    );
    let handles: Vec<_> = (0..p)
        .map(|_| pair.a.add_tcp(tcp_socket_sized(256)).unwrap())
        .collect();
    let mut now = pair.now();
    let first = peers::connect_all(&mut pair, &handles, &mut now);
    let second = peers::connect_all(&mut pair, &handles, &mut now);
    assert_eq!(pair.close(), 0);
    [first, second]
}

#[zhida_test_support::pinned_test]
fn nine_on_link_peers_keep_their_entries() {
    with_eal(|eal| {
        let [first, second] = reconnect(eal, 9, DEFAULT_NEIGHBOR_CAPACITY);
        assert_eq!(first.0, 9);
        assert_eq!(second.0, 0);
        assert_eq!(second.1, Duration::ZERO);
    });
}

#[zhida_test_support::pinned_test]
fn neighbor_capacity_bounds_the_cache() {
    with_eal(|eal| {
        let [first, second] = reconnect(eal, 5, 4);
        // Four requests fill the cache with unanswered addresses; the fifth peer
        // waits for their silence to end instead of evicting one.
        assert_eq!(first.0, 5);
        assert!(second.0 >= 1);
    });
}

#[zhida_test_support::pinned_test]
fn established_connection_uses_changed_peer_mac() {
    with_eal(|eal| {
        let mut pair = Pair::new(
            eal,
            ["nbrmaca", "nbrmacb"],
            [pair::config(Side::A), pair::config(Side::B)],
            T0,
        );
        let ([a, b], _) = pair::establish(&mut pair, Side::A);
        pair.b.tcp_mut(&b).set_ack_delay(None);
        assert_eq!(pair.a.tcp_mut(&a).send_slice(b"before").unwrap(), 6);
        let mut data_frames = 0;
        pair.drive(
            |dir, bytes| {
                if dir == pair::Dir::AToB {
                    let tcp = pair::segment(bytes, Side::A);
                    assert_eq!(tcp.payload, b"before");
                    data_frames += 1;
                }
            },
            |a_stack, _| {
                if a_stack.tcp(&a).send_queue() == 0 {
                    pair::App::Done
                } else {
                    pair::App::Idle
                }
            },
        );
        assert_eq!(data_frames, 1);
        let received = drain_bytes(pair.b.tcp_mut(&b)).unwrap();
        assert_eq!(received.len(), 6);
        assert_eq!(&received, b"before");

        let new_mac = EthernetAddress([2, 0, 0, 0, 0, 3]);
        pair.inject(
            Side::A,
            &[arp(
                ArpOperation::Reply,
                Side::A.mac(),
                (new_mac, Side::B.ip()),
                (Side::A.mac(), Side::A.ip()),
            )],
        );
        let turn = pair.a.turn(pair.now(), pair::BUDGET).unwrap();
        assert_eq!(
            (turn.rx_received, turn.rx_processed, turn.tx_accepted),
            (1, 1, 0)
        );
        assert_eq!(pair.a.tcp_mut(&a).send_slice(b"after").unwrap(), 5);
        assert_eq!(pair.a.send().unwrap().tx_accepted, 1);
        assert_eq!(
            pair.drain_tx(Side::A, |bytes| {
                let eth = EthernetFrame::new_checked(bytes).unwrap();
                assert_eq!(
                    (eth.src_addr(), eth.dst_addr(), eth.ethertype()),
                    (Side::A.mac(), new_mac, EthernetProtocol::Ipv4)
                );
                let caps = ChecksumCapabilities::default();
                let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
                let repr = Ipv4Repr::parse(&ip, &caps).unwrap();
                assert_eq!(
                    (repr.src_addr, repr.dst_addr, repr.next_header),
                    (Side::A.ip(), Side::B.ip(), IpProtocol::Tcp)
                );
                let tcp = TcpRepr::parse(
                    &TcpPacket::new_checked(ip.payload()).unwrap(),
                    &Side::A.ip().into(),
                    &Side::B.ip().into(),
                    &caps,
                )
                .unwrap();
                assert_eq!(
                    (tcp.src_port, tcp.dst_port, tcp.payload),
                    (pair::CLIENT_PORT, pair::SERVER_PORT, b"after".as_slice())
                );
            }),
            1
        );
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn zero_neighbor_capacity_is_invalid_config() {
    with_eal(|eal| {
        let fixture = RingPort::new("nbrzero", 16, 16);
        let valid = pair::config(Side::A);
        let mut port_config = fixture.config();
        port_config.rx_pool.count = rx_pool_count(
            rx_reserve(
                port_config.rx_descriptors,
                valid.rx_staging,
                port_config.rx_pool.cache_size,
            ),
            port_config.mtu,
            [],
        );
        let port = fixture.open_with(eal, port_config);
        let identity = format!("{port:?}");
        let config = StackConfig {
            max_udp_sockets: 0,
            neighbor_capacity: 0,
            ..valid
        };
        let port = match Stack::new(port, config, T0) {
            Err((port, error)) => {
                assert_eq!(
                    error,
                    StackError::InvalidConfig("neighbor_capacity must be > 0")
                );
                assert_eq!(format!("{port:?}"), identity);
                port
            }
            Ok(_) => panic!("accepted zero neighbor capacity"),
        };
        let stack = match Stack::new(port, valid, T0) {
            Ok(stack) => stack,
            Err((_, error)) => panic!("{error}"),
        };
        let port = stack.into_port();
        assert_eq!(fixture.in_use(), (0, 0));
        port.try_close().unwrap();
        fixture.close();
    });
}

fn gateway_pair(eal: &Eal, names: [&str; 2]) -> Pair {
    let a = StackConfig {
        gateway: Some(Side::B.ip()),
        ..pair::config(Side::A)
    };
    Pair::new(eal, names, [a, pair::config(Side::B)], T0)
}

#[zhida_test_support::pinned_test]
fn resolve_gateway_sends_one_request_then_mac_after_reply() {
    with_eal(|eal| {
        let mut pair = gateway_pair(eal, ["nbrresa", "nbrresb"]);
        assert_eq!(pair.a.resolve_gateway(), Ok(None));
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 1);
        assert_eq!(
            pair.drain_tx(Side::A, |frame| assert_eq!(frame, request(Side::B.ip()))),
            1
        );
        pair.inject(Side::A, &[reply(Side::B.ip(), Side::B.mac())]);
        assert_eq!(pair.a.receive(T0, pair::BUDGET).unwrap().rx_processed, 1);
        assert_eq!(pair.a.resolve_gateway(), Ok(Some(Side::B.mac())));
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn resolve_gateway_stale_entry_returns_mac_and_owes_probe() {
    with_eal(|eal| {
        let mut pair = gateway_pair(eal, ["nbrstalea", "nbrstaleb"]);
        assert_eq!(pair.a.resolve_gateway(), Ok(None));
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 1);
        assert_eq!(
            pair.drain_tx(Side::A, |frame| assert_eq!(frame, request(Side::B.ip()))),
            1
        );
        pair.inject(Side::A, &[reply(Side::B.ip(), Side::B.mac())]);
        assert_eq!(pair.a.receive(T0, pair::BUDGET).unwrap().rx_processed, 1);

        let stale = T0 + Duration::from_secs(60);
        pair.a.receive(stale, pair::BUDGET).unwrap();
        assert_eq!(pair.a.resolve_gateway(), Ok(Some(Side::B.mac())));
        assert_eq!(pair.a.send().unwrap().tx_accepted, 1);
        assert_eq!(
            pair.drain_tx(Side::A, |frame| assert_eq!(frame, request(Side::B.ip()))),
            1
        );
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn resolve_gateway_respects_one_second_silence() {
    with_eal(|eal| {
        let mut pair = gateway_pair(eal, ["nbrsila", "nbrsilb"]);
        assert_eq!(pair.a.resolve_gateway(), Ok(None));
        assert_eq!(pair.a.resolve_gateway(), Ok(None));
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 1);
        assert_eq!(
            pair.drain_tx(Side::A, |frame| assert_eq!(frame, request(Side::B.ip()))),
            1
        );

        let before = T0 + Duration::from_millis(999);
        pair.a.receive(before, pair::BUDGET).unwrap();
        assert_eq!(pair.a.resolve_gateway(), Ok(None));
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 0);
        assert_eq!(pair.drain_tx(Side::A, |_| panic!("ARP request before silence ended")), 0);

        let ready = T0 + Duration::from_secs(1);
        pair.a.receive(ready, pair::BUDGET).unwrap();
        assert_eq!(pair.a.resolve_gateway(), Ok(None));
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 1);
        assert_eq!(
            pair.drain_tx(Side::A, |frame| assert_eq!(frame, request(Side::B.ip()))),
            1
        );
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn resolve_gateway_without_gateway_is_no_route() {
    with_eal(|eal| {
        let mut pair = Pair::new(
            eal,
            ["nbrnora", "nbrnorb"],
            [pair::config(Side::A), pair::config(Side::B)],
            T0,
        );
        assert_eq!(pair.a.resolve_gateway(), Err(NoRoute));
        assert_eq!(pair.a.flush().unwrap().tx_accepted, 0);
        assert_eq!(pair.drain_tx(Side::A, |_| panic!("no route must not send")), 0);
        assert_eq!(pair.close(), 0);
    });
}
