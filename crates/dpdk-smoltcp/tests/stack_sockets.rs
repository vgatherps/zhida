use zhida_test_kit::pair::drain_bytes;
use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::phy::ChecksumCapabilities;
use dpdk_smoltcp::smoltcp::socket::tcp::{self, State};
use dpdk_smoltcp::smoltcp::time::{Duration, Instant};
use dpdk_smoltcp::smoltcp::wire::{
    ArpOperation, EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, IpAddress,
    IpEndpoint, IpProtocol, Ipv4Address, Ipv4Cidr, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket,
    TcpRepr, TcpSeqNumber, TcpTimestampRepr,
};
use dpdk_smoltcp::{rx_pool_count, rx_reserve};
use dpdk_smoltcp::{AddTcpError, Port, Stack, StackConfig, Turn, DEFAULT_NEIGHBOR_CAPACITY};

use zhida_test_kit::pair::{self, ceil_ms, App, Pair, Side};
use zhida_test_kit::{ring_port, with_eal};
use ring_port::{arp, RingPort};

const OURS: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x01]);
const OUR_IP: Ipv4Address = Ipv4Address::new(10, 0, 0, 1);
const PEER: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
const PEER_IP: Ipv4Address = Ipv4Address::new(10, 0, 0, 2);
const LOCAL_PORT: u16 = 49152;
const REMOTE_PORT: u16 = 80;
const T0: Instant = Instant::from_millis_const(5_000);

const IDLE: Turn = Turn {
    rx_received: 0,
    rx_rejected: 0,
    rx_ipv4_checksum_bad: 0,
    rx_processed: 0,
    rx_staged: 0,
    rx_blocked: false,
    tx_accepted: 0,
    tx_pending: 0,
};

fn stack(port: Port, max_sockets: usize, tx_pending: usize) -> Stack {
    let config = StackConfig {
        max_udp_sockets: 0,
        ethernet: OURS,
        ipv4: Ipv4Cidr::new(OUR_IP, 24),
        gateway: None,
        paths: &[],
        random_seed: 1,
        neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
        segments_per_visit: 1,
        max_sockets,
        rx_staging: 8,
        tx_pending,
    };
    match Stack::new(port, config, T0) {
        Ok(stack) => stack,
        Err((_, error)) => panic!("{error}"),
    }
}

fn tcp_socket() -> tcp::Config {
    pair::tcp_socket_sized(4096)
}

fn remote() -> IpEndpoint {
    IpEndpoint::new(PEER_IP.into(), REMOTE_PORT)
}

/// Our ARP request for the peer, as smoltcp emits it.
fn who_has_peer() -> Vec<u8> {
    arp(
        ArpOperation::Request,
        EthernetAddress::BROADCAST,
        (OURS, OUR_IP),
        (EthernetAddress::BROADCAST, PEER_IP),
    )
}

/// The TCP segment in one of our frames to the peer.
fn segment(frame: &[u8]) -> TcpRepr<'_> {
    let eth = EthernetFrame::new_checked(frame).unwrap();
    assert_eq!(
        (eth.src_addr(), eth.dst_addr(), eth.ethertype()),
        (OURS, PEER, EthernetProtocol::Ipv4)
    );
    let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
    let ip_repr = Ipv4Repr::parse(&ip, &ChecksumCapabilities::default()).unwrap();
    assert_eq!(
        (ip_repr.src_addr, ip_repr.dst_addr, ip_repr.next_header),
        (OUR_IP, PEER_IP, IpProtocol::Tcp)
    );
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    TcpRepr::parse(
        &tcp,
        &IpAddress::Ipv4(OUR_IP),
        &IpAddress::Ipv4(PEER_IP),
        &ChecksumCapabilities::default(),
    )
    .unwrap()
}

/// One frame from the peer carrying `tcp`.
fn from_peer(tcp: &TcpRepr<'_>) -> Vec<u8> {
    let caps = ChecksumCapabilities::default();
    let eth = EthernetRepr {
        src_addr: PEER,
        dst_addr: OURS,
        ethertype: EthernetProtocol::Ipv4,
    };
    let ip = Ipv4Repr {
        src_addr: PEER_IP,
        dst_addr: OUR_IP,
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
        &IpAddress::Ipv4(PEER_IP),
        &IpAddress::Ipv4(OUR_IP),
        &caps,
    );
    bytes
}

fn finish(fixture: RingPort, stack: Stack) {
    assert!(fixture.take_tx().is_empty());
    let port = stack.into_port();
    assert_eq!(fixture.in_use(), (0, 0));
    port.try_close().unwrap();
    fixture.close();
}

fn limited_stack(eal: &dpdk_smoltcp::Eal, fixture: &RingPort) -> (Stack, usize, usize) {
    let mut config = fixture.config();
    let reserve = rx_reserve(config.rx_descriptors, 8, config.rx_pool.cache_size);
    config.rx_pool.count = rx_pool_count(reserve, config.mtu, [4096; 2]);
    let pool = usize::try_from(config.rx_pool.count).unwrap();
    let port = fixture.open_with(eal, config);
    assert_eq!(port.descriptor_counts().0, 16);
    (stack(port, 3, 4), reserve, pool)
}

#[zhida_test_support::pinned_test]
fn sockets_full_returns_config_without_allocating_tx_ring() {
    with_eal(|eal| {
        let fixture = RingPort::new("rxtxfull", 16, 16);
        let mut stack = stack(fixture.open(eal), 1, 4);
        let _first = stack.add_tcp(tcp_socket()).unwrap();
        let config = tcp::Config {
            tx_capacity: usize::MAX,
            mss_cap: Some(536),
            ..tcp_socket()
        };
        assert_eq!(stack.add_tcp(config).unwrap_err(), AddTcpError::SocketsFull(config));
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn rx_pool_refusal_returns_config_without_allocating_tx_ring() {
    with_eal(|eal| {
        let fixture = RingPort::new("rxtxpool", 16, 16);
        let (mut stack, reserve, pool) = limited_stack(eal, &fixture);
        let config = tcp::Config {
            rx_capacity: 65536,
            tx_capacity: usize::MAX,
            mss_cap: Some(536),
        };
        assert_eq!(
            stack.add_tcp(config).unwrap_err(),
            AddTcpError::RxPoolTooSmall { config, required: reserve + 123, pool }
        );
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn add_tcp_refuses_when_rx_pool_cannot_back_budget() {
    with_eal(|eal| {
        let fixture = RingPort::new("rxcap", 16, 16);
        let (mut stack, reserve, pool) = limited_stack(eal, &fixture);
        assert_eq!(pool, reserve + 2 * 6);
        let _first = stack.add_tcp(tcp_socket()).unwrap();
        let _second = stack.add_tcp(tcp_socket()).unwrap();
        let AddTcpError::RxPoolTooSmall {
            config: socket,
            required,
            pool: actual,
        } = stack.add_tcp(tcp_socket()).unwrap_err()
        else {
            panic!("RX pool should refuse a third socket");
        };
        assert_eq!((required, actual), (reserve + 3 * 6, pool));
        assert_eq!(socket, tcp_socket());
        finish(fixture, stack);

        let fixture = RingPort::new("rxbig", 16, 16);
        let (mut stack, reserve, pool) = limited_stack(eal, &fixture);
        let AddTcpError::RxPoolTooSmall {
            config: socket,
            required,
            pool: actual,
        } = stack.add_tcp(pair::tcp_socket_sized(65536)).unwrap_err()
        else {
            panic!("RX pool should refuse a 64 KiB socket");
        };
        assert_eq!((required, actual), (reserve + 45, pool));
        assert_eq!(socket, pair::tcp_socket_sized(65536));
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn refused_config_returned_unchanged() {
    with_eal(|eal| {
        let fixture = RingPort::new("rxsame", 16, 16);
        let (mut stack, _, _) = limited_stack(eal, &fixture);
        let first = stack.add_tcp(tcp_socket()).unwrap();
        let _second = stack.add_tcp(tcp_socket()).unwrap();
        let config = tcp::Config { tx_capacity: 1234, mss_cap: Some(1460), ..tcp_socket() };
        let AddTcpError::RxPoolTooSmall { config: refused, .. } =
            stack.add_tcp(config).unwrap_err()
        else {
            panic!("RX budget should be full");
        };
        assert_eq!(refused, config);
        stack.remove_tcp(first);
        let handle = stack.add_tcp(refused).unwrap();
        stack.listen(&handle, 1003).unwrap();
        assert_eq!(stack.tcp(&handle).state(), State::Listen);
        assert_eq!(stack.tcp(&handle).listen_endpoint().port, 1003);
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn add_tcp_capped_socket_requires_more_rx_mbufs() {
    with_eal(|eal| {
        let fixture = RingPort::new("rxmss", 16, 16);
        let (mut stack, reserve, pool) = limited_stack(eal, &fixture);
        assert_eq!(pool, reserve + 12);
        let _first = stack.add_tcp(tcp_socket()).unwrap();
        let mut capped = tcp_socket();
        capped.mss_cap = Some(512);
        let AddTcpError::RxPoolTooSmall {
            config: socket,
            required,
            pool: actual,
        } = stack.add_tcp(capped).unwrap_err()
        else {
            panic!("RX pool should refuse the capped socket's eight frames");
        };
        assert_eq!((required, actual), (reserve + 6 + 8, pool));
        assert_eq!(socket, capped);
        finish(fixture, stack);

        let fixture = RingPort::new("rxmssok", 16, 16);
        let (mut stack, _, _) = limited_stack(eal, &fixture);
        let _second = stack.add_tcp(socket).unwrap();
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn listener_costs_m() {
    with_eal(|eal| {
        let fixture = RingPort::new("rxlisten", 16, 16);
        let (mut stack, reserve, pool) = limited_stack(eal, &fixture);
        let mut handles = Vec::new();
        for port in [1001, 1002] {
            let handle = stack.add_tcp(tcp_socket()).unwrap();
            stack.listen(&handle, port).unwrap();
            assert_eq!(stack.tcp(&handle).state(), State::Listen);
            handles.push(handle);
        }
        let config = tcp_socket();
        let AddTcpError::RxPoolTooSmall {
            config: socket,
            required,
            pool: actual,
        } = stack.add_tcp(config).unwrap_err()
        else {
            panic!("listeners should fill the RX budget");
        };
        assert_eq!((required, actual), (reserve + 3 * 6, pool));
        assert_eq!(socket, config);
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn remove_tcp_releases_admitted_budget_once() {
    with_eal(|eal| {
        let fixture = RingPort::new("rxonce", 16, 16);
        let mut config = fixture.config();
        let reserve = rx_reserve(config.rx_descriptors, 8, config.rx_pool.cache_size);
        config.rx_pool.count = rx_pool_count(reserve, config.mtu, [4096]);
        let pool = config.rx_pool.count as usize;
        let mut stack = stack(fixture.open_with(eal, config), 2, 4);
        let first = stack.add_tcp(tcp_socket()).unwrap();
        stack.remove_tcp(first);
        let second = stack.add_tcp(tcp_socket()).unwrap();
        let AddTcpError::RxPoolTooSmall { config, required, pool: actual } =
            stack.add_tcp(tcp_socket()).unwrap_err()
        else {
            panic!("the second socket must still charge its budget");
        };
        assert_eq!(config, tcp_socket());
        assert_eq!((required, actual), (reserve + 12, pool));
        stack.remove_tcp(second);
        let _third = stack.add_tcp(tcp_socket()).unwrap();
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn removed_tcp_frame_keeps_rx_pool_budget_until_dropped() {
    held_tcp_frame_after_removal(false);
}

#[zhida_test_support::pinned_test]
fn reaped_tcp_frame_keeps_rx_pool_budget_until_dropped() {
    held_tcp_frame_after_removal(true);
}

fn held_tcp_frame_after_removal(reap: bool) {
    with_eal(|eal| {
        let configs = [Side::A, Side::B].map(|side| StackConfig {
            max_udp_sockets: 0,
            max_sockets: 1,
            ..pair::config(side)
        });
        let reserve = rx_reserve(16, configs[0].rx_staging, 8);
        let pool = rx_pool_count(reserve, 1500, [4096]);
        let names = if reap { ["rxreapa", "rxreapb"] } else { ["rxhelda", "rxheldb"] };
        let mut pair = Pair::with_pools(eal, names, configs, pair::T0, 16, pool, 63);
        let ([client, server], _) = pair::establish(&mut pair, Side::A);
        pair.a.tcp_mut(&client).set_ack_delay(None);
        pair.b.tcp_mut(&server).set_ack_delay(None);
        assert_eq!(pair.a.tcp_mut(&client).send_slice(b"held"), Ok(4));
        pair.drive(|_, _| {}, |a, b| {
            if b.tcp(&server).recv_queue() == 4 && a.tcp(&client).send_queue() == 0 {
                App::Done
            } else {
                App::Idle
            }
        });
        let frame = pair.b.tcp_mut(&server).recv().unwrap().unwrap();
        assert_eq!(frame.payload(), b"held");
        assert_eq!(pair.b.tcp(&server).held_frames().count(), 1);
        if reap {
            pair.a.tcp_mut(&client).close();
            pair.drive(|_, _| {}, |_, b| {
                if b.tcp(&server).state() == State::CloseWait { App::Done } else { App::Idle }
            });
            drop(server);
            let mut fins = 0;
            let mut resets = 0;
            for _ in 0..8 {
                pair.round(|dir, bytes| {
                    if dir == pair::Dir::BToA {
                        match pair::segment(bytes, Side::B).control {
                            TcpControl::Fin => fins += 1,
                            TcpControl::Rst => resets += 1,
                            _ => {}
                        }
                    }
                });
            }
            assert_eq!((fins, resets), (1, 0));
            assert_eq!(pair.a.tcp(&client).state(), State::TimeWait);
        } else {
            pair.b.remove_tcp(server);
        }
        let AddTcpError::RxPoolTooSmall { config: socket, required, pool: actual } =
            pair.b.add_tcp(tcp_socket()).unwrap_err()
        else {
            panic!("the held frame must still count after removal");
        };
        assert_eq!(socket, tcp_socket());
        assert_eq!((required, actual), (reserve + 6 + 1, pool as usize));
        assert_eq!(frame.payload(), b"held");
        drop(frame);
        let _replacement = pair.b.add_tcp(socket).unwrap();
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn remove_tcp_discards_unread_rx_and_returns_budget() {
    with_eal(|eal| {
        let configs = [Side::A, Side::B].map(|side| StackConfig {
            max_udp_sockets: 0,
            max_sockets: 2,
            ..pair::config(side)
        });
        let reserve = rx_reserve(16, configs[0].rx_staging, 8);
        let pool = rx_pool_count(reserve, 1500, [4096]);
        let mut pair = Pair::with_pools(eal, ["rxrma", "rxrmb"], configs, pair::T0, 16, pool, 63);
        let (handles, _) = pair::establish(&mut pair, Side::A);
        assert_eq!(pair.a.tcp_mut(&handles[0]).send_slice(b"unread"), Ok(6));
        pair.drive(
            |_, _| {},
            |_, b| {
                if b.tcp(&handles[1]).recv_queue() == 6 {
                    App::Done
                } else {
                    App::Idle
                }
            },
        );
        pair.round(|_, _| {});
        let AddTcpError::RxPoolTooSmall {
            config: socket,
            required,
            pool: actual,
        } = pair.b.add_tcp(tcp_socket()).unwrap_err()
        else {
            panic!("the added socket should hold the whole RX budget");
        };
        assert_eq!(socket, tcp_socket());
        assert_eq!(
            (required, actual),
            (reserve + 12, usize::try_from(pool).unwrap())
        );
        let [_client, server] = handles;
        pair.b.remove_tcp(server);
        let _replacement = pair.b.add_tcp(socket).unwrap();
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn remove_tcp_frees_one_slot_full_rx_budget_and_unread_mbufs_without_sending() {
    with_eal(|eal| {
        let configs = [Side::A, Side::B].map(|side| StackConfig {
            max_udp_sockets: 0,
            max_sockets: 1,
            ..pair::config(side)
        });
        let reserve = rx_reserve(16, configs[0].rx_staging, 8);
        let pool = rx_pool_count(reserve, 1500, [4096]);
        let mut pair = Pair::with_pools(eal, ["rxrm1a", "rxrm1b"], configs, pair::T0, 16, pool, 63);
        let ([client, server], _) = pair::establish(&mut pair, Side::A);
        let idle = pair.in_use()[1].0;
        pair.b.tcp_mut(&server).set_ack_delay(None);
        assert_eq!(pair.a.tcp_mut(&client).send_slice(b"unread"), Ok(6));
        pair.drive(
            |_, _| {},
            |a, b| {
                if b.tcp(&server).recv_queue() == 6 && a.tcp(&client).send_queue() == 0 {
                    App::Done
                } else {
                    App::Idle
                }
            },
        );
        assert_eq!(pair.b.tcp(&server).state(), State::Established);
        assert_eq!(pair.in_use()[1].0, idle + 1);
        assert_eq!(pair.drain_tx(Side::B, |_| {}), 0);
        assert!(matches!(pair.b.add_tcp(tcp_socket()), Err(AddTcpError::SocketsFull(config)) if config == tcp_socket()));
        pair.b.remove_tcp(server);
        assert_eq!(pair.in_use()[1].0, idle);
        assert_eq!(pair.drain_tx(Side::B, |_| {}), 0);
        assert_eq!(pair.b.send().unwrap().tx_accepted, 0);
        assert_eq!(pair.drain_tx(Side::B, |_| {}), 0);
        let replacement = pair.b.add_tcp(tcp_socket()).unwrap();
        assert_eq!(pair.b.tcp(&replacement).recv_capacity(), 4096);
        assert_eq!(pair.close(), 0);
    });
}

/// An ARP request for our IP from a sender outside our /24 gets a reply sent
/// straight to the requester's MAC. The senders are not learned: eight of
/// them, one more than the free neighbor slots, would otherwise evict the
/// peer learned first, and the following SYN to the peer would wait behind a
/// new ARP request instead of leaving at once.
#[zhida_test_support::pinned_test]
fn arp_request_from_off_subnet_sender_is_answered_not_learned() {
    with_eal(|eal| {
        let fixture = RingPort::new("arpoff", 16, 16);
        let mut stack = stack(fixture.open(eal), 1, 8);
        fixture.inject(&[arp(
            ArpOperation::Request,
            EthernetAddress::BROADCAST,
            (PEER, PEER_IP),
            (EthernetAddress([0; 6]), OUR_IP),
        )]);
        stack.turn(T0, 8).unwrap();
        assert_eq!(
            fixture.take_tx(),
            [arp(ArpOperation::Reply, PEER, (OURS, OUR_IP), (PEER, PEER_IP))]
        );

        let senders: Vec<_> = (0..8u8)
            .map(|i| {
                (
                    EthernetAddress([0x02, 0, 0, 0, 1, i]),
                    Ipv4Address::new(192, 168, 1, 10 + i),
                )
            })
            .collect();
        let requests: Vec<_> = senders
            .iter()
            .map(|&sender| {
                arp(
                    ArpOperation::Request,
                    EthernetAddress::BROADCAST,
                    sender,
                    (EthernetAddress([0; 6]), OUR_IP),
                )
            })
            .collect();
        fixture.inject(&requests);
        stack.turn(T0 + Duration::from_millis(1), 8).unwrap();
        let replies: Vec<_> = senders
            .iter()
            .map(|&sender| arp(ArpOperation::Reply, sender.0, (OURS, OUR_IP), sender))
            .collect();
        assert_eq!(fixture.take_tx(), replies);

        let handle = stack.add_tcp(tcp_socket()).unwrap();
        stack.connect(&handle, remote(), LOCAL_PORT).unwrap();
        stack.turn(T0 + Duration::from_millis(2), 8).unwrap();
        let sent = fixture.take_tx();
        assert_eq!(sent.len(), 1);
        assert_eq!(segment(&sent[0]).control, TcpControl::Syn);
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn socket_capacity_refused_then_slot_reused() {
    with_eal(|eal| {
        let fixture = RingPort::new("cap", 16, 16);
        let mut port_config = fixture.config();
        port_config.rx_pool.count = rx_pool_count(
            rx_reserve(
                port_config.rx_descriptors,
                8,
                port_config.rx_pool.cache_size,
            ),
            port_config.mtu,
            [4096; 2],
        );
        let mut stack = stack(fixture.open_with(eal, port_config), 2, 4);
        let first = stack.add_tcp(tcp_socket()).unwrap();
        stack.listen(&first, 1001).unwrap();
        let second = stack.add_tcp(tcp_socket()).unwrap();
        stack.listen(&second, 1002).unwrap();
        let config = tcp::Config { tx_capacity: 1234, mss_cap: Some(1460), ..tcp_socket() };
        let AddTcpError::SocketsFull(refused) = stack.add_tcp(config).unwrap_err() else {
            panic!("socket slots should be full");
        };
        assert_eq!(refused, config);

        let first_slot = first.to_string();
        let first_socket = format!("{first:?}");
        stack.remove_tcp(first);
        let reused = stack.add_tcp(refused).unwrap();
        stack.listen(&reused, 1003).unwrap();
        assert_eq!(reused.to_string(), first_slot);
        assert_ne!(format!("{reused:?}"), first_socket);
        assert_eq!(stack.tcp(&reused).listen_endpoint().port, 1003);
        assert_eq!(stack.tcp(&second).listen_endpoint().port, 1002);

        // Full again: the storage did not grow.
        let AddTcpError::SocketsFull(refused) = stack.add_tcp(config).unwrap_err() else {
            panic!("socket slots should be full");
        };
        assert_eq!(refused, config);
        assert_eq!(stack.turn(T0, 8), Ok(IDLE));
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn tcp_read_leaves_socket_untouched() {
    with_eal(|eal| {
        let fixture = RingPort::new("tcpread", 16, 16);
        let mut stack = stack(fixture.open(eal), 1, 4);
        let handle = stack.add_tcp(tcp_socket()).unwrap();
        stack.listen(&handle, 1001).unwrap();

        assert_eq!(stack.tcp(&handle).state(), State::Listen);
        let read = stack.tcp(&handle) as *const tcp::Socket<'static>;
        assert!(std::ptr::eq(read, stack.tcp_mut(&handle)));
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn connect_unknown_neighbor_sends_arp_and_reports_silence_deadline() {
    with_eal(|eal| {
        let fixture = RingPort::new("silence", 16, 16);
        let mut stack = stack(fixture.open(eal), 1, 4);
        let handle = stack.add_tcp(tcp_socket()).unwrap();
        stack.connect(&handle, remote(), LOCAL_PORT).unwrap();

        // The SYN cannot leave without the peer's MAC: smoltcp sends our ARP
        // request in its place and reports no socket change for it.
        assert_eq!(
            stack.turn(T0, 8),
            Ok(Turn {
                tx_accepted: 1,
                ..IDLE
            })
        );
        assert_eq!(fixture.take_tx(), [who_has_peer()]);
        assert_eq!(stack.tcp(&handle).state(), State::SynSent);
        let silence = T0 + Duration::from_secs(1);
        assert!(matches!(stack.poll_at(), Some(p) if p > T0 && p <= ceil_ms(silence)));

        for at in [T0 + Duration::from_millis(500), silence - Duration::from_micros(1)] {
            assert_eq!(stack.turn(at, 8), Ok(IDLE));
            assert!(fixture.take_tx().is_empty());
            assert!(matches!(stack.poll_at(), Some(p) if p > at && p <= ceil_ms(silence)));
        }

        assert_eq!(
            stack.turn(silence, 8),
            Ok(Turn {
                tx_accepted: 1,
                ..IDLE
            })
        );
        assert_eq!(fixture.take_tx(), [who_has_peer()]);
        assert!(
            matches!(stack.poll_at(), Some(p) if p > silence && p <= ceil_ms(silence + Duration::from_secs(1)))
        );
        finish(fixture, stack);
    });
}

/// Connected socket `handle` reaches Established against a peer without
/// timestamps; returns (our ISN, peer ISN, our SYN's timestamp option). The
/// first turn has ingress budget 1, spent on the peer's ARP request: egress
/// still runs and sends the SYN.
fn handshake(
    fixture: &RingPort,
    stack: &mut Stack,
    handle: &TcpHandle,
) -> (TcpSeqNumber, TcpSeqNumber, Option<TcpTimestampRepr>) {
    fixture.inject(&[arp(
        ArpOperation::Request,
        EthernetAddress::BROADCAST,
        (PEER, PEER_IP),
        (EthernetAddress([0; 6]), OUR_IP),
    )]);
    assert_eq!(
        stack.turn(T0, 1),
        Ok(Turn {
            rx_received: 1,
            rx_processed: 1,
            tx_accepted: 2,
            ..IDLE
        })
    );
    let sent = fixture.take_tx();
    assert_eq!(sent.len(), 2);
    assert_eq!(
        sent[0],
        arp(ArpOperation::Reply, PEER, (OURS, OUR_IP), (PEER, PEER_IP))
    );
    let syn = segment(&sent[1]);
    assert_eq!(
        (syn.src_port, syn.dst_port, syn.control, syn.ack_number),
        (LOCAL_PORT, REMOTE_PORT, TcpControl::Syn, None)
    );
    let isn = syn.seq_number;

    let peer_isn = TcpSeqNumber(7_000);
    fixture.inject(&[from_peer(&TcpRepr {
        src_port: REMOTE_PORT,
        dst_port: LOCAL_PORT,
        control: TcpControl::Syn,
        seq_number: peer_isn,
        ack_number: Some(isn + 1),
        window_len: 65535,
        window_scale: None,
        max_seg_size: Some(512),
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    })]);
    assert_eq!(
        stack.turn(T0, 8),
        Ok(Turn {
            rx_received: 1,
            rx_processed: 1,
            tx_accepted: 1,
            ..IDLE
        })
    );
    assert_eq!(stack.tcp(&handle).state(), State::Established);
    let sent = fixture.take_tx();
    assert_eq!(sent.len(), 1);
    let ack = segment(&sent[0]);
    assert_eq!(
        (ack.control, ack.seq_number, ack.ack_number, ack.payload.len()),
        (TcpControl::None, isn + 1, Some(peer_isn + 1), 0)
    );
    (isn, peer_isn, syn.timestamp)
}

fn exhaust_and_reallocate_rx_pool(fixture: &RingPort) {
    use zhida_dpdk_sys::{dpdk_raw_pktmbuf_alloc, dpdk_raw_pktmbuf_free};

    let tx = fixture.in_use().1;
    assert_eq!(fixture.in_use(), (0, tx));
    let count = fixture.config().rx_pool.count as usize;
    let pool = fixture.rx_pool();
    for _ in 0..2 {
        let mut packets = Vec::new();
        loop {
            let packet = unsafe { dpdk_raw_pktmbuf_alloc(pool) };
            if packet.is_null() {
                break;
            }
            packets.push(packet);
        }
        assert_eq!(packets.len(), count);
        assert_eq!(fixture.in_use(), (count as u32, tx));
        for packet in packets {
            unsafe { dpdk_raw_pktmbuf_free(packet) };
        }
        assert_eq!(fixture.in_use(), (0, tx));
    }
}

fn peer_data(isn: TcpSeqNumber, peer_seq: TcpSeqNumber, payload: &[u8]) -> Vec<u8> {
    from_peer(&TcpRepr {
        src_port: REMOTE_PORT,
        dst_port: LOCAL_PORT,
        control: TcpControl::None,
        seq_number: peer_seq,
        ack_number: Some(isn + 1),
        window_len: 65535,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload,
    })
}

#[zhida_test_support::pinned_test]
fn received_segment_stays_in_rx_mbuf_until_read() {
    with_eal(|eal| {
        let fixture = RingPort::new("rxheld", 16, 16);
        let mut stack = stack(fixture.open(eal), 1, 4);
        let handle = stack.add_tcp(tcp_socket()).unwrap();
        stack.tcp_mut(&handle).set_ack_delay(None);
        stack.connect(&handle, remote(), LOCAL_PORT).unwrap();
        let (isn, peer_isn, _) = handshake(&fixture, &mut stack, &handle);
        assert_eq!(fixture.in_use(), (0, 0));
        for (index, payload) in [b"abc", b"def"].into_iter().enumerate() {
            fixture.inject(&[peer_data(isn, peer_isn + 1 + 3 * index, payload)]);
            let turn = stack.turn(T0 + Duration::from_millis(1), 8).unwrap();
            assert_eq!((turn.rx_received, turn.rx_processed), (1, 1));
            let replies = fixture.take_tx();
            assert_eq!(replies.len(), 1);
            assert_eq!(
                segment(&replies[0]).ack_number,
                Some(peer_isn + 4 + 3 * index)
            );
            assert_eq!(stack.tcp(&handle).recv_queue(), 3 * (index + 1));
            // "def" is copied into the tailroom of the frame holding "abc", and its own
            // mbuf returns to the pool during the turn.
            assert_eq!(fixture.in_use(), (1, 0));
        }
        let frame = stack.tcp_mut(&handle).recv().unwrap().unwrap();
        assert_eq!(frame.payload(), b"abcdef");
        assert_eq!(fixture.in_use(), (1, 0));
        drop(frame);
        assert_eq!(fixture.in_use(), (0, 0));
        assert_eq!(stack.tcp(&handle).recv_queue(), 0);
        exhaust_and_reallocate_rx_pool(&fixture);
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn reordered_segments_held_then_released_after_fill() {
    with_eal(|eal| {
        let fixture = RingPort::new("rxreorder", 16, 16);
        let mut stack = stack(fixture.open(eal), 1, 4);
        let handle = stack.add_tcp(tcp_socket()).unwrap();
        stack.tcp_mut(&handle).set_ack_delay(None);
        stack.connect(&handle, remote(), LOCAL_PORT).unwrap();
        let (isn, peer_isn, _) = handshake(&fixture, &mut stack, &handle);
        assert_eq!(fixture.in_use(), (0, 0));
        for (index, (offset, payload)) in [(4, b"def"), (7, b"ghi"), (1, b"abc")]
            .into_iter()
            .enumerate()
        {
            fixture.inject(&[peer_data(isn, peer_isn + offset, payload)]);
            let turn = stack.turn(T0 + Duration::from_millis(1), 8).unwrap();
            assert_eq!((turn.rx_received, turn.rx_processed), (1, 1));
            let replies = fixture.take_tx();
            assert_eq!(replies.len(), 1);
            let filled = index == 2;
            assert_eq!(
                segment(&replies[0]).ack_number,
                Some(peer_isn + if filled { 10 } else { 1 })
            );
            assert_eq!(stack.tcp(&handle).recv_queue(), if filled { 9 } else { 0 });
            assert_eq!(fixture.in_use(), (index as u32 + 1, 0));
        }
        let mut frames = Vec::new();
        while let Some(frame) = stack.tcp_mut(&handle).recv().unwrap() {
            frames.push(frame);
        }
        assert_eq!(frames.len(), 3);
        assert_eq!(frames.iter().map(|frame| frame.payload()).collect::<Vec<_>>(),
            vec![&b"abc"[..], &b"def"[..], &b"ghi"[..]]);
        assert_eq!(fixture.in_use(), (3, 0));
        let bytes: Vec<_> = frames.iter().flat_map(|frame| frame.payload().iter().copied()).collect();
        assert_eq!(bytes.len(), 9);
        assert_eq!(bytes.as_slice(), b"abcdefghi");
        drop(frames);
        assert_eq!(fixture.in_use(), (0, 0));
        exhaust_and_reallocate_rx_pool(&fixture);
        finish(fixture, stack);
    });
}

/// Established socket that has received `PING` at `T0 + 1 ms` with `receive` (no egress yet).
/// `ack_delay` is the socket's setting; the default is 10 ms.
fn received_ping(
    eal: &dpdk_smoltcp::Eal,
    name: &str,
    ack_delay: Option<Duration>,
) -> (RingPort, Stack, TcpHandle, TcpSeqNumber) {
    let fixture = RingPort::new(name, 16, 16);
    let mut stack = stack(fixture.open(eal), 1, 4);
    let handle = stack.add_tcp(tcp_socket()).unwrap();
    stack.tcp_mut(&handle).set_ack_delay(ack_delay);
    stack.connect(&handle, remote(), LOCAL_PORT).unwrap();
    let (isn, peer_isn, _) = handshake(&fixture, &mut stack, &handle);

    // Nothing received yet: nothing owed.
    stack.tcp_mut(&handle).ack_now();
    stack.send().unwrap();
    assert!(fixture.take_tx().is_empty());

    fixture.inject(&[peer_data(isn, peer_isn + 1, &PING)]);
    let turn = stack.receive(T0 + Duration::from_millis(1), 8).unwrap();
    assert_eq!((turn.rx_received, turn.rx_processed), (1, 1));
    assert!(fixture.take_tx().is_empty());
    (fixture, stack, handle, peer_isn + 1 + PING.len())
}

const PING: [u8; 100] = [7; 100];

fn assert_pure_ack(frame: &[u8], ack: TcpSeqNumber) {
    let seg = segment(frame);
    assert_eq!(
        (seg.control, seg.ack_number, seg.payload.len()),
        (TcpControl::None, Some(ack), 0)
    );
}

fn ack_now_sends_nothing(fixture: &RingPort, stack: &mut Stack, handle: &TcpHandle) {
    stack.tcp_mut(handle).ack_now();
    stack.send().unwrap();
    assert!(fixture.take_tx().is_empty());
}

fn read_ping_and_finish(fixture: RingPort, mut stack: Stack, handle: TcpHandle) {
    let frame = stack.tcp_mut(&handle).recv().unwrap().unwrap();
    assert_eq!(frame.payload(), &PING[..]);
    drop(frame);
    finish(fixture, stack);
}

#[zhida_test_support::pinned_test]
fn ack_now_sends_owed_ack_once() {
    with_eal(|eal| {
        let (fixture, mut stack, handle, acked) =
            received_ping(eal, "acknow", Some(Duration::from_millis(10)));
        // Delayed: the 10 ms timer holds the ACK.
        stack.send().unwrap();
        assert!(fixture.take_tx().is_empty());
        stack.tcp_mut(&handle).ack_now();
        stack.send().unwrap();
        let sent = fixture.take_tx();
        assert_eq!(sent.len(), 1);
        assert_pure_ack(&sent[0], acked);
        ack_now_sends_nothing(&fixture, &mut stack, &handle);
        // The cancelled delayed-ACK timer does not fire later.
        stack.turn(T0 + Duration::from_millis(20), 8).unwrap();
        assert!(fixture.take_tx().is_empty());
        read_ping_and_finish(fixture, stack, handle);
    });
}

#[zhida_test_support::pinned_test]
fn ack_now_leaves_on_turn() {
    with_eal(|eal| {
        let (fixture, mut stack, handle, acked) =
            received_ping(eal, "acknowturn", Some(Duration::from_millis(10)));
        stack.tcp_mut(&handle).ack_now();
        stack.turn(T0 + Duration::from_millis(1), 8).unwrap();
        let sent = fixture.take_tx();
        assert_eq!(sent.len(), 1);
        assert_pure_ack(&sent[0], acked);
        ack_now_sends_nothing(&fixture, &mut stack, &handle);
        read_ping_and_finish(fixture, stack, handle);
    });
}

#[zhida_test_support::pinned_test]
fn ack_now_after_delayed_ack_sent_is_noop() {
    with_eal(|eal| {
        let (fixture, mut stack, handle, acked) =
            received_ping(eal, "acknowlate", Some(Duration::from_millis(10)));
        stack.turn(T0 + Duration::from_millis(11), 8).unwrap();
        let sent = fixture.take_tx();
        assert_eq!(sent.len(), 1);
        assert_pure_ack(&sent[0], acked);
        ack_now_sends_nothing(&fixture, &mut stack, &handle);
        read_ping_and_finish(fixture, stack, handle);
    });
}

#[zhida_test_support::pinned_test]
fn ack_now_rides_on_written_data() {
    with_eal(|eal| {
        let (fixture, mut stack, handle, acked) =
            received_ping(eal, "acknowdata", Some(Duration::from_millis(10)));
        assert_eq!(stack.tcp_mut(&handle).send_slice(b"pong"), Ok(4));
        stack.tcp_mut(&handle).ack_now();
        stack.send().unwrap();
        let sent = fixture.take_tx();
        assert_eq!(sent.len(), 1);
        let seg = segment(&sent[0]);
        assert_eq!((seg.ack_number, seg.payload), (Some(acked), &b"pong"[..]));
        ack_now_sends_nothing(&fixture, &mut stack, &handle);
        read_ping_and_finish(fixture, stack, handle);
    });
}

#[zhida_test_support::pinned_test]
fn ack_now_without_ack_delay_sends_one_ack() {
    with_eal(|eal| {
        let (fixture, mut stack, handle, acked) = received_ping(eal, "acknowoff", None);
        stack.tcp_mut(&handle).ack_now();
        stack.send().unwrap();
        let sent = fixture.take_tx();
        assert_eq!(sent.len(), 1);
        assert_pure_ack(&sent[0], acked);
        ack_now_sends_nothing(&fixture, &mut stack, &handle);
        read_ping_and_finish(fixture, stack, handle);
    });
}

#[zhida_test_support::pinned_test]
fn reset_remove_unwind_return_once() {
    with_eal(|eal| {
        for (name, reset) in [("rxrstremove", true), ("rxstackdrop", false)] {
            let fixture = RingPort::new(name, 16, 16);
            let mut stack = stack(fixture.open(eal), 1, 4);
            let handle = stack.add_tcp(tcp_socket()).unwrap();
            stack.tcp_mut(&handle).set_ack_delay(None);
            stack.connect(&handle, remote(), LOCAL_PORT).unwrap();
            let (isn, peer_isn, _) = handshake(&fixture, &mut stack, &handle);
            for (offset, payload) in [(1, b"abc"), (4, b"def"), (10, b"jkl")] {
                fixture.inject(&[peer_data(isn, peer_isn + offset, payload)]);
                let turn = stack.turn(T0 + Duration::from_millis(1), 8).unwrap();
                assert_eq!((turn.rx_received, turn.rx_processed), (1, 1));
                fixture.take_tx();
            }
            assert_eq!(stack.tcp(&handle).recv_queue(), 6);
            // "def" is copied into the frame holding "abc"; "jkl" is out of order and keeps
            // its own frame.
            assert_eq!(fixture.in_use(), (2, 0));
            assert_eq!(stack.tcp(&handle).rx_refused_segments(), 0);
            if reset {
                let rst = from_peer(&TcpRepr {
                    src_port: REMOTE_PORT,
                    dst_port: LOCAL_PORT,
                    control: TcpControl::Rst,
                    seq_number: peer_isn + 7,
                    ack_number: Some(isn + 1),
                    window_len: 65535,
                    window_scale: None,
                    max_seg_size: None,
                    sack_permitted: false,
                    sack_ranges: [None; 3],
                    timestamp: None,
                    payload: &[],
                });
                fixture.inject(&[rst]);
                let turn = stack.turn(T0 + Duration::from_millis(2), 8).unwrap();
                assert_eq!((turn.rx_received, turn.rx_processed), (1, 1));
                assert!(fixture.take_tx().is_empty());
                assert_eq!(stack.tcp(&handle).state(), State::Closed);
                assert_eq!(stack.tcp(&handle).recv_queue(), 6);
                // The RST needs no reply: its unused TX packet stays as the
                // Device's spare until `into_port`.
                assert_eq!(fixture.in_use(), (2, 1));
                let bytes = drain_bytes(stack.tcp_mut(&handle)).unwrap();
                assert_eq!(bytes.len(), 6);
                assert_eq!(&bytes, b"abcdef");
                assert_eq!(fixture.in_use(), (1, 1));
                stack.remove_tcp(handle);
                assert_eq!(fixture.in_use(), (0, 1));
                exhaust_and_reallocate_rx_pool(&fixture);
                assert_eq!(fixture.in_use(), (0, 1));
            }
            let port = stack.into_port();
            assert_eq!(fixture.in_use(), (0, 0));
            exhaust_and_reallocate_rx_pool(&fixture);
            port.try_close().unwrap();
            fixture.close();
        }
    });
}

#[zhida_test_support::pinned_test]
fn turn_respects_budget_and_services_egress() {
    with_eal(|eal| {
        // Pending holds 2, the TX ring 3.
        let fixture = RingPort::new("egress", 16, 4);
        let mut stack = stack(fixture.open(eal), 1, 2);
        let handle = stack.add_tcp(tcp_socket()).unwrap();
        stack.tcp_mut(&handle).set_ack_delay(None);
        stack.connect(&handle, remote(), LOCAL_PORT).unwrap();
        let (isn, peer_isn, _) = handshake(&fixture, &mut stack, &handle);

        // Four 512-byte segments are queued and fit the peer window.
        // Egress repeats within a turn but stops at the 2 pending slots.
        let data: Vec<u8> = (0..2048).map(|i| i as u8).collect();
        assert_eq!(stack.tcp_mut(&handle).send_slice(&data), Ok(2048));
        assert_eq!(
            stack.turn(T0, 8),
            Ok(Turn {
                tx_accepted: 2,
                ..IDLE
            })
        );
        // The TX ring has 1 free entry left.
        assert_eq!(
            stack.turn(T0, 8),
            Ok(Turn {
                tx_accepted: 1,
                tx_pending: 1,
                ..IDLE
            })
        );
        assert_eq!(
            stack.turn(T0, 8),
            Ok(Turn {
                tx_pending: 1,
                ..IDLE
            })
        );
        let mut sent = fixture.take_tx();
        assert_eq!(sent.len(), 3);
        assert_eq!(
            stack.turn(T0, 8),
            Ok(Turn {
                tx_accepted: 1,
                ..IDLE
            })
        );
        sent.extend(fixture.take_tx());
        assert_eq!(sent.len(), 4);
        for (i, frame) in sent.iter().enumerate() {
            let data_segment = segment(frame);
            assert_eq!(data_segment.seq_number, isn + 1 + 512 * i);
            assert_eq!(data_segment.ack_number, Some(peer_isn + 1));
            assert_eq!(data_segment.payload, &data[512 * i..512 * (i + 1)]);
        }
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn connection_without_peer_timestamps_stays_without_them() {
    with_eal(|eal| {
        let fixture = RingPort::new("nots", 16, 16);
        let mut stack = stack(fixture.open(eal), 1, 4);
        let handle = stack.add_tcp(tcp_socket()).unwrap();
        stack.connect(&handle, remote(), LOCAL_PORT).unwrap();
        // Neither our SYN nor the peer's SYN-ACK offers timestamps.
        let (isn, peer_isn, offered) = handshake(&fixture, &mut stack, &handle);
        assert_eq!(offered, None);

        assert_eq!(stack.tcp_mut(&handle).send_slice(b"hi"), Ok(2));
        let later = T0 + Duration::from_millis(3);
        assert_eq!(
            stack.turn(later, 8),
            Ok(Turn {
                tx_accepted: 1,
                ..IDLE
            })
        );
        let sent = fixture.take_tx();
        assert_eq!(sent.len(), 1);
        let data = segment(&sent[0]);
        assert_eq!(
            (data.seq_number, data.ack_number, data.payload, data.timestamp),
            (isn + 1, Some(peer_isn + 1), &b"hi"[..], None)
        );
        finish(fixture, stack);
    });
}

/// A failed connect, a failed listen and a
/// remove/add round trip leave the live connection without them.
#[zhida_test_support::pinned_test]
fn live_socket_keeps_timestamps_off() {
    with_eal(|eal| {
        let fixture = RingPort::new("tslive", 16, 16);
        let mut stack = stack(fixture.open(eal), 1, 4);
        let handle = stack.add_tcp(tcp_socket()).unwrap();
        stack.connect(&handle, remote(), LOCAL_PORT).unwrap();
        let (isn, peer_isn, _) = handshake(&fixture, &mut stack, &handle);

        assert_eq!(
            stack.connect(&handle, remote(), LOCAL_PORT),
            Err(tcp::ConnectError::InvalidState)
        );
        assert_eq!(
            stack.listen(&handle, REMOTE_PORT),
            Err(tcp::ListenError::InvalidState)
        );

        assert_eq!(stack.tcp_mut(&handle).send_slice(b"hi"), Ok(2));
        assert_eq!(
            stack.turn(T0 + Duration::from_millis(3), 8),
            Ok(Turn {
                tx_accepted: 1,
                ..IDLE
            })
        );
        let sent = fixture.take_tx();
        assert_eq!(sent.len(), 1);
        let data = segment(&sent[0]);
        assert_eq!(
            (data.seq_number, data.ack_number, data.payload, data.timestamp),
            (isn + 1, Some(peer_isn + 1), &b"hi"[..], None)
        );
        finish(fixture, stack);
    });
}

/// A SYN from the peer's LOCAL_PORT + `client` to our REMOTE_PORT.
fn peer_syn(client: u16, seq: i32, timestamp: Option<TcpTimestampRepr>) -> Vec<u8> {
    from_peer(&TcpRepr {
        src_port: LOCAL_PORT + client,
        dst_port: REMOTE_PORT,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(seq),
        ack_number: None,
        window_len: 65535,
        window_scale: None,
        max_seg_size: Some(512),
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp,
        payload: &[],
    })
}

/// A listener added and listening through `Stack::listen` on REMOTE_PORT
/// answers a SYN without the timestamp option, leaving it in SynReceived with
/// timestamps off.
fn listener_after_client_without_timestamps(
    fixture: &RingPort,
    stack: &mut Stack,
) -> TcpHandle {
    let handle = stack.add_tcp(tcp_socket()).unwrap();
    stack.listen(&handle, REMOTE_PORT).unwrap();

    // The peer's ARP request teaches us its MAC; its SYN has no option.
    fixture.inject(&[
        arp(
            ArpOperation::Request,
            EthernetAddress::BROADCAST,
            (PEER, PEER_IP),
            (EthernetAddress([0; 6]), OUR_IP),
        ),
        peer_syn(0, 7_000, None),
    ]);
    stack.turn(T0, 8).unwrap();
    let sent = fixture.take_tx();
    assert_eq!(sent.len(), 2);
    let syn_ack = segment(&sent[1]);
    assert_eq!(
        (syn_ack.dst_port, syn_ack.control, syn_ack.ack_number, syn_ack.timestamp),
        (LOCAL_PORT, TcpControl::Syn, Some(TcpSeqNumber(7_001)), None)
    );
    assert_eq!(stack.tcp(&handle).state(), State::SynReceived);
    handle
}

/// `Stack::listen` again on REMOTE_PORT, then `next_client_gets_no_timestamps`.
fn relisten_without_timestamps(fixture: &RingPort, stack: &mut Stack, handle: &TcpHandle) {
    stack.listen(&handle, REMOTE_PORT).unwrap();
    next_client_gets_no_timestamps(fixture, stack, &handle);
}

/// The next client's timestamped SYN gets a SYN-ACK without timestamps. Then abort,
/// and the stack sends its RST.
fn next_client_gets_no_timestamps(fixture: &RingPort, stack: &mut Stack, handle: &TcpHandle) {
    fixture.inject(&[peer_syn(1, 8_000, Some(TcpTimestampRepr::new(900, 0)))]);
    stack.turn(T0 + Duration::from_millis(5), 8).unwrap();
    let sent = fixture.take_tx();
    assert_eq!(sent.len(), 1);
    let syn_ack = segment(&sent[0]);
    assert_eq!(
        (syn_ack.dst_port, syn_ack.control, syn_ack.ack_number, syn_ack.timestamp),
        (
            LOCAL_PORT + 1,
            TcpControl::Syn,
            Some(TcpSeqNumber(8_001)),
            None
        )
    );
    stack.tcp_mut(&handle).abort();
    stack.turn(T0 + Duration::from_millis(6), 8).unwrap();
    assert_eq!(fixture.take_tx().len(), 1);
}

/// After abort and `Stack::listen`, the next client's timestamp offer is declined.
#[zhida_test_support::pinned_test]
fn relisten_after_client_without_timestamps_stays_without_them() {
    with_eal(|eal| {
        let fixture = RingPort::new("tsrel", 16, 16);
        let mut stack = stack(fixture.open(eal), 1, 4);
        let handle = listener_after_client_without_timestamps(&fixture, &mut stack);

        stack.tcp_mut(&handle).abort();
        stack.turn(T0 + Duration::from_millis(1), 8).unwrap();
        let sent = fixture.take_tx();
        assert_eq!(sent.len(), 1);
        assert_eq!(segment(&sent[0]).control, TcpControl::Rst);

        relisten_without_timestamps(&fixture, &mut stack, &handle);
        finish(fixture, stack);
    });
}

/// The client's RST returns the listener to Listen. Its next SYN-ACK has no timestamps.
#[zhida_test_support::pinned_test]
fn peer_reset_in_syn_received_keeps_timestamps_off() {
    with_eal(|eal| {
        let fixture = RingPort::new("tsk2", 16, 16);
        let mut stack = stack(fixture.open(eal), 1, 4);
        let handle = listener_after_client_without_timestamps(&fixture, &mut stack);

        fixture.inject(&[from_peer(&TcpRepr {
            src_port: LOCAL_PORT,
            dst_port: REMOTE_PORT,
            control: TcpControl::Rst,
            seq_number: TcpSeqNumber(7_001),
            ack_number: None,
            window_len: 0,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        })]);
        stack.turn(T0 + Duration::from_millis(1), 8).unwrap();
        assert!(fixture.take_tx().is_empty());
        assert_eq!(stack.tcp(&handle).state(), State::Listen);
        next_client_gets_no_timestamps(&fixture, &mut stack, &handle);
        finish(fixture, stack);
    });
}

/// A reconnected socket still omits timestamps from its SYN.
#[zhida_test_support::pinned_test]
fn reconnect_offers_no_timestamps() {
    with_eal(|eal| {
        let fixture = RingPort::new("tsre", 16, 16);
        let mut stack = stack(fixture.open(eal), 1, 4);
        let handle = stack.add_tcp(tcp_socket()).unwrap();
        stack.connect(&handle, remote(), LOCAL_PORT).unwrap();
        handshake(&fixture, &mut stack, &handle);

        stack.tcp_mut(&handle).abort();
        stack.turn(T0 + Duration::from_millis(1), 8).unwrap();
        let sent = fixture.take_tx();
        assert_eq!(sent.len(), 1);
        let rst = segment(&sent[0]);
        assert_eq!((rst.control, rst.timestamp), (TcpControl::Rst, None));

        // The peer's MAC is still cached: the SYN leaves at once.
        stack.connect(&handle, remote(), LOCAL_PORT + 1).unwrap();
        stack.turn(T0 + Duration::from_millis(5), 8).unwrap();
        let sent = fixture.take_tx();
        assert_eq!(sent.len(), 1);
        let syn = segment(&sent[0]);
        assert_eq!(
            (syn.src_port, syn.control, syn.ack_number, syn.timestamp),
            (LOCAL_PORT + 1, TcpControl::Syn, None, None)
        );
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn poll_at_past_deadline_normalized_to_last_now() {
    with_eal(|eal| {
        let fixture = RingPort::new("pollat", 16, 16);
        let mut stack = stack(fixture.open(eal), 1, 4);
        assert_eq!(stack.poll_at(), None);
        let handle = stack.add_tcp(tcp_socket()).unwrap();
        stack.connect(&handle, remote(), LOCAL_PORT).unwrap();
        // smoltcp reports "now" as Instant 0, long before T0.
        assert_eq!(stack.poll_at(), Some(T0));

        // A future deadline's bucket is reported after the latest turn time.
        let later = T0 + Duration::from_secs(2);
        assert_eq!(
            stack.turn(later, 8),
            Ok(Turn {
                tx_accepted: 1,
                ..IDLE
            })
        );
        assert_eq!(fixture.take_tx(), [who_has_peer()]);
        assert!(
            matches!(stack.poll_at(), Some(p) if p > later && p <= ceil_ms(later + Duration::from_secs(1)))
        );
        finish(fixture, stack);
    });
}
