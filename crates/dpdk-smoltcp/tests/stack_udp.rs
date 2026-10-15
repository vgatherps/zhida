use std::ffi::c_void;
use std::ptr::null_mut;

use zhida_test_kit::pair::{self, App, Pair, Side};
use zhida_test_kit::ring_port::RingPort;
use zhida_test_kit::{wire, with_eal};
use dpdk_smoltcp::smoltcp::phy::ChecksumCapabilities;
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::smoltcp::wire::{
    EthernetFrame, EthernetProtocol, EthernetRepr, IpEndpoint, IpProtocol, Ipv4Cidr, Ipv4Packet,
    Ipv4Repr, UdpPacket, UdpRepr,
};
use dpdk_smoltcp::{
    rx_reserve, AddTcpError, AddUdpError, Port, PortError, Stack, StackConfig, UdpConfig,
    DEFAULT_NEIGHBOR_CAPACITY,
};
use zhida_dpdk_sys::dpdk_raw_ring_enqueue_burst;

const T0: Instant = pair::T0;
const PORT: u16 = 1234;
const PEER_PORT: u16 = 4321;

fn config(max_udp_sockets: usize) -> StackConfig<'static> {
    StackConfig {
        ethernet: Side::A.mac(),
        ipv4: Ipv4Cidr::new(Side::A.ip(), 24),
        gateway: None,
        paths: &[],
        random_seed: 1,
        neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
        segments_per_visit: 1,
        max_sockets: 2,
        max_udp_sockets,
        rx_staging: 8,
        tx_pending: 8,
    }
}

fn new_stack(port: Port, max_udp_sockets: usize) -> Stack {
    match Stack::new(port, config(max_udp_sockets), T0) {
        Ok(stack) => stack,
        Err((_, error)) => panic!("{error}"),
    }
}

fn udp_config(port: u16, rx_queue: usize) -> UdpConfig {
    UdpConfig {
        port,
        rx_queue,
        tx_checksum: true,
        broadcast: false,
    }
}

fn from_peer(src_port: u16, payload: &[u8]) -> Vec<u8> {
    let caps = ChecksumCapabilities::default();
    let udp = UdpRepr {
        src_port,
        dst_port: PORT,
    };
    let eth = EthernetRepr {
        src_addr: Side::B.mac(),
        dst_addr: Side::A.mac(),
        ethertype: EthernetProtocol::Ipv4,
    };
    let ip = Ipv4Repr {
        src_addr: Side::B.ip(),
        dst_addr: Side::A.ip(),
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
        &Side::B.ip().into(),
        &Side::A.ip().into(),
        payload.len(),
        |buffer| buffer.copy_from_slice(payload),
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

#[zhida_test_support::pinned_test]
fn udp_rx_payload_points_into_rx_mbuf() {
    with_eal(|eal| {
        let fixture = RingPort::new("udpaddr", 16, 16);
        let mut stack = new_stack(fixture.open(eal), 1);
        let handle = stack.add_udp(udp_config(PORT, 2)).unwrap();
        let bytes = from_peer(PEER_PORT, b"mbuf payload");
        let packet = wire::copy_into(fixture.rx_pool(), &bytes);
        let (start, end, payload_addr) = unsafe {
            let mbuf = &*packet;
            let start = mbuf.buf_addr as usize;
            let end = start.checked_add(usize::from(mbuf.buf_len())).unwrap();
            let payload_addr = (mbuf.data_ptr() as usize).checked_add(14 + 20 + 8).unwrap();
            (start, end, payload_addr)
        };
        let raw = [packet.cast::<c_void>()];
        let queued =
            unsafe { dpdk_raw_ring_enqueue_burst(fixture.rx_ring(), raw.as_ptr(), 1, null_mut()) };
        if queued != 1 {
            unsafe { zhida_dpdk_sys::dpdk_raw_pktmbuf_free(packet) };
        }
        assert_eq!(queued, 1);
        let turn = stack.turn(T0, 8).unwrap();
        assert_eq!((turn.rx_received, turn.rx_processed), (1, 1));
        let datagram = stack.udp_mut(&handle).recv().unwrap();
        let address = datagram.payload().as_ptr() as usize;
        assert!(address >= start);
        assert!(address.checked_add(datagram.payload().len()).unwrap() <= end);
        assert_eq!(address, payload_addr);
        assert_eq!(datagram.payload(), b"mbuf payload");
        assert_eq!(
            datagram.src(),
            IpEndpoint::new(Side::B.ip().into(), PEER_PORT)
        );
        assert_eq!(datagram.dst_addr(), Side::A.ip());
        assert_eq!(stack.udp(&handle).rx_queued(), 0);
        drop(datagram);
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn datagram_drop_returns_mbuf() {
    with_eal(|eal| {
        let fixture = RingPort::new("udpdrop", 16, 16);
        let mut stack = new_stack(fixture.open(eal), 1);
        let handle = stack.add_udp(udp_config(PORT, 2)).unwrap();
        assert_eq!(fixture.in_use().0, 0);
        fixture.inject(&[from_peer(PEER_PORT, b"held")]);
        stack.turn(T0, 8).unwrap();
        assert_eq!(fixture.in_use().0, 1);
        let datagram = stack.udp_mut(&handle).recv().unwrap();
        assert_eq!(fixture.in_use().0, 1);
        drop(datagram);
        assert_eq!(fixture.in_use().0, 0);
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn held_datagrams_make_try_close_refuse_then_succeed() {
    with_eal(|eal| {
        let fixture = RingPort::new("udpclose", 16, 16);
        let mut stack = new_stack(fixture.open(eal), 1);
        let handle = stack.add_udp(udp_config(PORT, 2)).unwrap();
        fixture.inject(&[
            from_peer(PEER_PORT, b"held"),
            from_peer(PEER_PORT, b"queued"),
        ]);
        stack.turn(T0, 8).unwrap();
        let datagram = stack.udp_mut(&handle).recv().unwrap();
        let port = stack.into_port();
        assert_eq!(fixture.in_use(), (1, 0));
        let (port, error) = port.try_close().unwrap_err();
        assert_eq!(error, PortError::OutstandingBuffers { rx: 1, tx: 0 });
        assert_eq!(datagram.payload(), b"held");
        drop(datagram);
        assert_eq!(fixture.in_use(), (0, 0));
        port.try_close().unwrap();
        fixture.close();
    });
}

#[zhida_test_support::pinned_test]
fn over_limit_dropped_counted_tcp_progresses() {
    with_eal(|eal| {
        let configs = [Side::A, Side::B].map(|side| StackConfig {
            max_udp_sockets: 1,
            ..pair::config(side)
        });
        let mut pair = Pair::with_pools(eal, ["udptcpa", "udptcpb"], configs, T0, 16, 127, 63);
        let (handles, _) = pair::establish(&mut pair, Side::A);
        let udp = pair.a.add_udp(udp_config(PORT, 2)).unwrap();
        let before = pair.in_use()[0].0;
        pair.inject(
            Side::A,
            &[from_peer(PEER_PORT, b"one"), from_peer(PEER_PORT, b"two")],
        );
        pair.round(|_, _| {});
        let first = pair.a.udp_mut(&udp).recv().unwrap();
        let second = pair.a.udp_mut(&udp).recv().unwrap();
        assert_eq!(first.payload(), b"one");
        assert_eq!(second.payload(), b"two");
        assert_eq!(pair.a.udp(&udp).rx_queued(), 0);
        assert_eq!(pair.in_use()[0].0, before + 2);
        pair.inject(Side::A, &[from_peer(PEER_PORT, b"three")]);
        let round = pair.round(|_, _| {});
        assert_eq!(round.a.rx_processed, 1);
        assert_eq!(pair.a.udp(&udp).stats().rx_dropped_full, 1);
        assert_eq!(pair.a.udp(&udp).stats().rx_delivered, 2);
        assert!(pair.a.udp_mut(&udp).recv().is_none());
        assert_eq!(pair.in_use()[0].0, before + 2);

        assert_eq!(
            pair.a.tcp_mut(&handles[0]).send_slice(b"tcp still works"),
            Ok(15)
        );
        let mut received = Vec::new();
        pair.drive(
            |_, _| {},
            |_, b| {
                if b.tcp(&handles[1]).can_recv() {
                    let bytes = pair::drain_bytes(b.tcp_mut(&handles[1])).unwrap();
                    received.extend_from_slice(&bytes);
                    return App::Moved;
                }
                if received.len() == 15 {
                    App::Done
                } else {
                    App::Idle
                }
            },
        );
        assert_eq!(received, b"tcp still works");
        assert_eq!(pair.b.tcp_mut(&handles[1]).send_slice(b"reply"), Ok(5));
        let mut reply = Vec::new();
        pair.drive(
            |_, _| {},
            |a, _| {
                if a.tcp(&handles[0]).can_recv() {
                    let bytes = pair::drain_bytes(a.tcp_mut(&handles[0])).unwrap();
                    reply.extend_from_slice(&bytes);
                    return App::Moved;
                }
                if reply.len() == 5 {
                    App::Done
                } else {
                    App::Idle
                }
            },
        );
        assert_eq!(reply, b"reply");
        assert_eq!(pair.a.udp(&udp).stats().rx_dropped_full, 1);
        drop((first, second));
        assert_eq!(pair.in_use()[0].0, before);
        pair.close();
    });
}

#[zhida_test_support::pinned_test]
fn add_udp_refused_when_pool_cannot_back_it() {
    with_eal(|eal| {
        let fixture = RingPort::new("udpcap", 16, 16);
        let port_config = fixture.config();
        let reserve = rx_reserve(
            port_config.rx_descriptors,
            8,
            port_config.rx_pool.cache_size,
        );
        let pool = usize::try_from(port_config.rx_pool.count).unwrap();
        let mut stack = new_stack(fixture.open_with(eal, port_config), 2);
        let tcp = stack.add_tcp(pair::tcp_socket_sized(4096)).unwrap();
        let udp = stack.add_udp(udp_config(PORT, 5)).unwrap();
        assert_eq!(pool, reserve + 6 + 5);
        assert_eq!(
            stack.add_udp(udp_config(PORT + 1, 1)).unwrap_err(),
            AddUdpError::RxPoolTooSmall {
                required: reserve + 6 + 5 + 1,
                pool,
            }
        );
        assert_eq!(stack.udp(&udp).config(), &udp_config(PORT, 5));
        assert_eq!(stack.tcp(&tcp).recv_capacity(), 4096);
        stack.remove_udp(udp);
        assert_eq!(
            stack.add_udp(udp_config(PORT, 6)).unwrap_err(),
            AddUdpError::RxPoolTooSmall {
                required: reserve + 6 + 6,
                pool,
            }
        );
        let udp = stack.add_udp(udp_config(PORT, 5)).unwrap();
        let AddTcpError::RxPoolTooSmall {
            required,
            pool: actual,
            config,
        } = stack.add_tcp(pair::tcp_socket_sized(4096)).unwrap_err()
        else {
            panic!("UDP budget should prevent another TCP socket");
        };
        assert_eq!((required, actual), (reserve + 6 + 5 + 6, pool));
        assert_eq!(config, pair::tcp_socket_sized(4096));
        stack.remove_tcp(tcp);
        let extra = stack.add_udp(udp_config(PORT + 1, 6)).unwrap();
        stack.remove_udp(extra);
        stack.remove_udp(udp);
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn removed_socket_held_datagrams_count_until_dropped() {
    with_eal(|eal| {
        let fixture = RingPort::new("udprm", 16, 16);
        let mut port_config = fixture.config();
        let reserve = rx_reserve(
            port_config.rx_descriptors,
            8,
            port_config.rx_pool.cache_size,
        );
        port_config.rx_pool.count = u32::try_from(reserve + 6).unwrap();
        let pool = usize::try_from(port_config.rx_pool.count).unwrap();
        let mut stack = new_stack(fixture.open_with(eal, port_config), 1);
        let old = stack.add_udp(udp_config(PORT, 6)).unwrap();
        fixture.inject(&[
            from_peer(PEER_PORT, b"held"),
            from_peer(PEER_PORT, b"queued"),
        ]);
        stack.turn(T0, 8).unwrap();
        let first = stack.udp_mut(&old).recv().unwrap();
        stack.remove_udp(old);
        assert_eq!(fixture.in_use().0, 1);
        let replacement = stack.add_udp(udp_config(PORT, 5)).unwrap();
        fixture.inject(&[from_peer(PEER_PORT, b"second")]);
        stack.turn(T0, 8).unwrap();
        let second = stack.udp_mut(&replacement).recv().unwrap();
        stack.remove_udp(replacement);
        assert_eq!(fixture.in_use().0, 2);
        for (held, datagram) in [(2, first), (1, second)] {
            assert_eq!(
                stack.add_udp(udp_config(PORT, 6)).unwrap_err(),
                AddUdpError::RxPoolTooSmall {
                    required: reserve + held + 6,
                    pool,
                }
            );
            let AddTcpError::RxPoolTooSmall {
                required,
                pool: actual,
                config,
            } = stack.add_tcp(pair::tcp_socket_sized(4096)).unwrap_err()
            else {
                panic!("held UDP datagrams should prevent TCP admission");
            };
            assert_eq!((required, actual), (reserve + held + 6, pool));
            assert_eq!(config, pair::tcp_socket_sized(4096));
            drop(datagram);
            assert_eq!(fixture.in_use().0, held as u32 - 1);
        }
        let udp = stack.add_udp(udp_config(PORT, 6)).unwrap();
        stack.remove_udp(udp);
        let tcp = stack.add_tcp(pair::tcp_socket_sized(4096)).unwrap();
        stack.remove_tcp(tcp);
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn removed_tcp_and_udp_frames_share_admission_count() {
    with_eal(|eal| {
        let configs = [Side::A, Side::B].map(|side| StackConfig {
            max_udp_sockets: 1,
            ..pair::config(side)
        });
        let reserve = rx_reserve(16, configs[0].rx_staging, 8);
        let pool = reserve.checked_add(7).unwrap();
        let mut pair = Pair::with_pools(
            eal,
            ["mixhelda", "mixheldb"],
            configs,
            T0,
            16,
            u32::try_from(pool).unwrap(),
            63,
        );
        let ([client, server], _) = pair::establish(&mut pair, Side::A);
        pair.a.tcp_mut(&client).set_ack_delay(None);
        pair.b.tcp_mut(&server).set_ack_delay(None);
        assert_eq!(pair.b.tcp_mut(&server).send_slice(b"tcp"), Ok(3));
        pair.drive(|_, _| {}, |a, b| {
            if a.tcp(&client).recv_queue() == 3 && b.tcp(&server).send_queue() == 0 {
                App::Done
            } else {
                App::Idle
            }
        });
        let frame = pair.a.tcp_mut(&client).recv().unwrap().unwrap();
        assert_eq!(frame.payload(), b"tcp");
        let udp = pair.a.add_udp(udp_config(PORT, 1)).unwrap();
        pair.inject(Side::A, &[from_peer(PEER_PORT, b"udp")]);
        pair.round(|_, _| {});
        let datagram = pair.a.udp_mut(&udp).recv().unwrap();
        assert_eq!(datagram.payload(), b"udp");
        pair.a.remove_tcp(client);
        pair.a.remove_udp(udp);
        let check_refused = |stack: &mut Stack, held| {
            assert_eq!(
                stack.add_udp(udp_config(PORT, 7)).unwrap_err(),
                AddUdpError::RxPoolTooSmall {
                    required: reserve + held + 7,
                    pool,
                }
            );
            let AddTcpError::RxPoolTooSmall {
                required,
                pool: actual,
                config,
            } = stack.add_tcp(pair::tcp_socket_sized(7 * (1500 - 40))).unwrap_err()
            else {
                panic!("held TCP and UDP frames should prevent TCP admission");
            };
            assert_eq!((required, actual), (reserve + held + 7, pool));
            assert_eq!(config, pair::tcp_socket_sized(7 * (1500 - 40)));
        };
        check_refused(&mut pair.a, 2);
        drop(frame);
        check_refused(&mut pair.a, 1);
        drop(datagram);
        let udp = pair.a.add_udp(udp_config(PORT, 7)).unwrap();
        pair.a.remove_udp(udp);
        let tcp = pair.a.add_tcp(pair::tcp_socket_sized(7 * (1500 - 40))).unwrap();
        pair.a.remove_tcp(tcp);
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn port_in_use_and_full_refused() {
    with_eal(|eal| {
        let fixture = RingPort::new("udpfull", 16, 16);
        let mut stack = new_stack(fixture.open(eal), 0);
        assert_eq!(stack.add_udp(udp_config(PORT, 1)).unwrap_err(), AddUdpError::Full);
        finish(fixture, stack);

        let fixture = RingPort::new("udpbind", 16, 16);
        let mut stack = new_stack(fixture.open(eal), 1);
        assert!(matches!(
            stack.add_udp(udp_config(0, 1)),
            Err(AddUdpError::InvalidConfig(_))
        ));
        assert!(matches!(
            stack.add_udp(udp_config(PORT, 0)),
            Err(AddUdpError::InvalidConfig(_))
        ));
        let handle = stack.add_udp(udp_config(PORT, 2)).unwrap();
        assert_eq!(
            stack.add_udp(udp_config(PORT, 2)).unwrap_err(),
            AddUdpError::PortInUse
        );
        assert_eq!(
            stack.add_udp(udp_config(PORT + 1, 2)).unwrap_err(),
            AddUdpError::Full
        );
        assert_eq!(stack.udp(&handle).config(), &udp_config(PORT, 2));
        stack.remove_udp(handle);
        let _replacement = stack.add_udp(udp_config(PORT + 1, 2)).unwrap();
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn connected_socket_drops_other_peer() {
    with_eal(|eal| {
        let fixture = RingPort::new("udppeer", 16, 16);
        let mut stack = new_stack(fixture.open(eal), 1);
        let handle = stack.add_udp(udp_config(PORT, 2)).unwrap();
        let peer = IpEndpoint::new(Side::B.ip().into(), PEER_PORT);
        stack.udp_mut(&handle).connect(peer).unwrap();
        fixture.inject(&[
            from_peer(PEER_PORT + 1, b"other"),
            from_peer(PEER_PORT, b"peer"),
        ]);
        stack.turn(T0, 8).unwrap();
        assert_eq!(stack.udp(&handle).stats().rx_dropped_peer, 1);
        assert_eq!(stack.udp(&handle).stats().rx_delivered, 1);
        assert_eq!(fixture.in_use().0, 1);
        let datagram = stack.udp_mut(&handle).recv().unwrap();
        assert_eq!(datagram.src(), peer);
        assert_eq!(datagram.payload(), b"peer");
        assert!(stack.udp_mut(&handle).recv().is_none());
        drop(datagram);
        finish(fixture, stack);
    });
}
