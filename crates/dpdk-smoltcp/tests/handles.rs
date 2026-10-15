use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};

use zhida_test_kit::pair::{
    self, establish, segment, tcp_socket_sized, App, Dir, Pair, Rounds, Side, BUDGET, CLIENT_PORT,
    SERVER_PORT, T0,
};
use zhida_test_kit::{ring_port::RingPort, with_eal};
use dpdk_smoltcp::smoltcp::socket::tcp::State;
use dpdk_smoltcp::smoltcp::time::Duration;
use dpdk_smoltcp::smoltcp::wire::{
    EthernetFrame, EthernetProtocol, IpEndpoint, IpProtocol, Ipv4Packet, TcpControl, TcpRepr,
    UdpPacket,
};
use dpdk_smoltcp::{
    rx_pool_count, rx_reserve, AddTcpError, AddUdpError, Eal, Stack, TcpHandle, UdpConfig,
};

type Frames = Vec<(Dir, Vec<u8>)>;

fn new_pair(eal: &Eal, names: [&str; 2]) -> Pair {
    let configs = [pair::config(Side::A), pair::config(Side::B)];
    Pair::with_ports(eal, names, configs, T0, 16, |side, port| {
        let reserve = rx_reserve(
            port.rx_descriptors,
            configs[side.index()].rx_staging,
            port.rx_pool.cache_size,
        );
        port.rx_pool.count = rx_pool_count(reserve, port.mtu, [4096]);
    })
}

fn tcp_segments(frames: &Frames, side: Side) -> impl Iterator<Item = TcpRepr<'_>> {
    frames.iter().filter_map(move |(dir, bytes)| {
        if *dir != side.dir() {
            return None;
        }
        let eth = EthernetFrame::new_checked(bytes.as_slice()).unwrap();
        if eth.ethertype() != EthernetProtocol::Ipv4 {
            return None;
        }
        let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
        if ip.next_header() != IpProtocol::Tcp {
            return None;
        }
        Some(segment(bytes, side))
    })
}

fn count(frames: &Frames, side: Side, control: TcpControl) -> usize {
    tcp_segments(frames, side)
        .filter(|tcp| tcp.control == control)
        .count()
}

fn round(pair: &mut Pair, frames: &mut Frames) {
    pair.round(|dir, bytes| frames.push((dir, bytes.to_vec())));
}

fn until_control(pair: &mut Pair, frames: &mut Frames, side: Side, control: TcpControl) {
    for _ in 0..32 {
        round(pair, frames);
        if count(frames, side, control) > 0 {
            return;
        }
    }
    panic!("no {control:?} from {side:?}");
}

fn assert_full(stack: &mut Stack) {
    assert!(matches!(
        stack.add_tcp(tcp_socket_sized(4096)),
        Err(AddTcpError::SocketsFull(config)) if config == tcp_socket_sized(4096)
    ));
}

fn add_after_close(stack: &mut Stack) -> TcpHandle {
    let handle = stack.add_tcp(tcp_socket_sized(4096)).unwrap();
    assert_eq!(stack.tcp(&handle).state(), State::Closed);
    assert_eq!(stack.tcp(&handle).remote_endpoint(), None);
    handle
}

fn endpoint(side: Side, port: u16) -> IpEndpoint {
    IpEndpoint::new(side.ip().into(), port)
}

fn connect_pair(eal: &Eal, names: [&str; 2]) -> Pair {
    let configs = [Side::A, Side::B].map(|side| {
        let mut config = pair::config(side);
        config.max_sockets = 3;
        config
    });
    Pair::with_ports(eal, names, configs, T0, 16, |side, port| {
        let reserve = rx_reserve(
            port.rx_descriptors,
            configs[side.index()].rx_staging,
            port.rx_pool.cache_size,
        );
        port.rx_pool.count = rx_pool_count(reserve, port.mtu, [4096; 3]);
    })
}

#[zhida_test_support::pinned_test]
fn connect_rejects_time_wait_tuple_until_expiry() {
    with_eal(|eal| {
        for orphaned in [false, true] {
            let mut pair = connect_pair(eal, ["h_tupa", "h_tupb"]);
            let ([a, b], _) = establish(&mut pair, Side::A);
            pair.b.tcp_mut(&b).set_ack_delay(None);
            pair.a.tcp_mut(&a).close();
            let mut frames = Vec::new();
            until_control(&mut pair, &mut frames, Side::A, TcpControl::Fin);
            pair.b.tcp_mut(&b).close();
            pair.drive(
                |_, _| {},
                |a_stack, b_stack| {
                    if a_stack.tcp(&a).state() == State::TimeWait
                        && b_stack.tcp(&b).state() == State::Closed
                    {
                        App::Done
                    } else {
                        App::Idle
                    }
                },
            );
            let closed_at = pair.now();
            let owned = if orphaned {
                drop(a);
                None
            } else {
                Some(a)
            };
            let replacement = pair.a.add_tcp(tcp_socket_sized(4096)).unwrap();
            let remote = endpoint(Side::B, SERVER_PORT);
            let error = pair.a
                .connect(&replacement, remote, CLIENT_PORT)
                .expect_err("TIME-WAIT tuple must reject connect");
            assert_eq!(error.to_string(), "address in use");
            assert_eq!(pair.a.tcp(&replacement).state(), State::Closed);
            assert_eq!(pair.a.tcp(&replacement).local_endpoint(), None);
            assert_eq!(pair.a.tcp(&replacement).remote_endpoint(), None);
            let different = pair.a.add_tcp(tcp_socket_sized(4096)).unwrap();
            pair.a.connect(&different, remote, CLIENT_PORT + 1).unwrap();
            pair.a.remove_tcp(different);
            pair.round_at(closed_at + Duration::from_secs(11), |_, _| {});
            if let Some(a) = owned {
                assert_eq!(pair.a.tcp(&a).state(), State::Closed);
                pair.a.remove_tcp(a);
            }
            pair.b.listen(&b, SERVER_PORT).unwrap();
            pair.a.connect(&replacement, remote, CLIENT_PORT).unwrap();
            pair.drive(
                |_, _| {},
                |a_stack, b_stack| {
                    if a_stack.tcp(&replacement).state() == State::Established
                        && b_stack.tcp(&b).state() == State::Established
                    {
                        App::Done
                    } else {
                        App::Idle
                    }
                },
            );
            pair.a.tcp_mut(&replacement).send_slice(b"reused").unwrap();
            pair.drive(
                |_, _| {},
                |_, b_stack| {
                    if b_stack.tcp(&b).can_recv() {
                        App::Done
                    } else {
                        App::Idle
                    }
                },
            );
            assert_eq!(pair::drain_bytes(pair.b.tcp_mut(&b)).unwrap(), b"reused");
            pair.a.remove_tcp(replacement);
            pair.b.remove_tcp(b);
            pair.close();
        }
    });
}

#[zhida_test_support::pinned_test]
fn connect_rejects_dirty_syn_sent_tuple_but_allows_closed_and_listener() {
    with_eal(|eal| {
        let mut pair = connect_pair(eal, ["h_dirtupa", "h_dirtupb"]);
        let a = pair.a.add_tcp(tcp_socket_sized(4096)).unwrap();
        let replacement = pair.a.add_tcp(tcp_socket_sized(4096)).unwrap();
        let remote = endpoint(Side::B, SERVER_PORT);
        pair.a.connect(&a, remote, CLIENT_PORT).unwrap();
        let error = pair.a
            .connect(&replacement, remote, endpoint(Side::A, CLIENT_PORT))
            .expect_err("dirty SYN-SENT tuple must reject connect");
        assert_eq!(error.to_string(), "address in use");
        assert_eq!(pair.a.tcp(&replacement).state(), State::Closed);
        assert_eq!(pair.a.tcp(&replacement).remote_endpoint(), None);
        pair.a.tcp_mut(&a).abort();
        assert_eq!(pair.a.tcp(&a).remote_endpoint(), Some(remote));
        pair.a.connect(&replacement, remote, CLIENT_PORT).unwrap();
        pair.a.tcp_mut(&replacement).abort();
        pair.a.listen(&a, CLIENT_PORT).unwrap();
        pair.a.connect(&replacement, remote, CLIENT_PORT).unwrap();
        pair.a.remove_tcp(a);
        pair.a.remove_tcp(replacement);
        pair.close();
    });
}

#[zhida_test_support::pinned_test]
fn drop_established_sends_fin_and_frees_slot_after_close() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["h_fina", "h_finb"]);
        let ([a, b], _) = establish(&mut pair, Side::A);
        pair.b.tcp_mut(&b).set_ack_delay(None);
        let mut frames = Vec::new();
        drop(a);
        assert_full(&mut pair.a);
        until_control(&mut pair, &mut frames, Side::A, TcpControl::Fin);
        assert_eq!(count(&frames, Side::A, TcpControl::Fin), 1);
        assert_eq!(count(&frames, Side::A, TcpControl::Rst), 0);
        assert_eq!(pair.b.tcp(&b).state(), State::CloseWait);
        assert_full(&mut pair.a);
        pair.b.tcp_mut(&b).close();
        until_control(&mut pair, &mut frames, Side::B, TcpControl::Fin);
        assert_eq!(pair.b.tcp(&b).state(), State::LastAck);
        assert_full(&mut pair.a);
        pair.drive(
            |dir, bytes| frames.push((dir, bytes.to_vec())),
            |_, b_stack| {
                if b_stack.tcp(&b).state() == State::Closed {
                    App::Done
                } else {
                    App::Idle
                }
            },
        );
        assert_eq!(count(&frames, Side::B, TcpControl::Fin), 1);
        assert!(tcp_segments(&frames, Side::A).any(|tcp| {
            tcp.control == TcpControl::None && tcp.ack_number.is_some()
        }));
        assert_full(&mut pair.a);
        let closed_at = pair.now();
        pair.round_at(closed_at + Duration::from_secs(9), |dir, bytes| {
            frames.push((dir, bytes.to_vec()));
        });
        assert_full(&mut pair.a);
        pair.round_at(closed_at + Duration::from_secs(11), |dir, bytes| {
            frames.push((dir, bytes.to_vec()));
        });
        let _replacement = add_after_close(&mut pair.a);
        assert_eq!(count(&frames, Side::A, TcpControl::Fin), 1);
        assert_eq!(count(&frames, Side::A, TcpControl::Rst), 0);
        pair.b.remove_tcp(b);
        let _b_replacement = add_after_close(&mut pair.b);
        pair.close();
    });
}

#[zhida_test_support::pinned_test]
fn drop_close_wait_frees_slot_after_fin_ack() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["h_passa", "h_passb"]);
        let ([a, b], _) = establish(&mut pair, Side::A);
        pair.a.tcp_mut(&a).set_ack_delay(None);
        pair.b.tcp_mut(&b).set_ack_delay(None);
        let mut frames = Vec::new();
        pair.a.tcp_mut(&a).close();
        until_control(&mut pair, &mut frames, Side::A, TcpControl::Fin);
        assert_eq!(pair.b.tcp(&b).state(), State::CloseWait);
        drop(b);
        assert_full(&mut pair.b);
        until_control(&mut pair, &mut frames, Side::B, TcpControl::Fin);
        assert_full(&mut pair.b);
        round(&mut pair, &mut frames);
        assert_eq!(pair.a.tcp(&a).state(), State::TimeWait);
        // The final ACK closed the dropped socket during that round; the
        // next call reaps it.
        assert_eq!(pair.b.poll_at(), Some(pair.now()));
        let _replacement = add_after_close(&mut pair.b);
        assert_eq!(count(&frames, Side::B, TcpControl::Fin), 1);
        assert_eq!(count(&frames, Side::B, TcpControl::Rst), 0);
        let fin = tcp_segments(&frames, Side::B)
            .find(|tcp| tcp.control == TcpControl::Fin)
            .unwrap();
        assert!(tcp_segments(&frames, Side::A).any(|tcp| {
            tcp.control == TcpControl::None && tcp.ack_number == Some(fin.seq_number + 1)
        }));
        pair.close();
    });
}

#[zhida_test_support::pinned_test]
fn drop_during_handshake() {
    with_eal(|eal| {
        // Linux tcp_close: a SYN-SENT socket closes without sending anything; the
        // peer's SYN-ACK then finds no socket and gets an RST.
        let mut pair = new_pair(eal, ["h_senta", "h_sentb"]);
        let a = pair.a.add_tcp(tcp_socket_sized(4096)).unwrap();
        let b = pair.b.add_tcp(tcp_socket_sized(4096)).unwrap();
        pair.b.listen(&b, SERVER_PORT).unwrap();
        pair.a.connect(&a, endpoint(Side::B, SERVER_PORT), CLIENT_PORT).unwrap();
        let mut frames = Vec::new();
        round(&mut pair, &mut frames);
        pair.b_to_a.paused = true;
        round(&mut pair, &mut frames);
        assert_eq!(pair.b.tcp(&b).state(), State::SynReceived);
        assert_eq!(pair.a.tcp(&a).state(), State::SynSent);
        drop(a);
        let _replacement = add_after_close(&mut pair.a);
        pair.b_to_a.paused = false;
        until_control(&mut pair, &mut frames, Side::A, TcpControl::Rst);
        assert_eq!(count(&frames, Side::A, TcpControl::Syn), 1);
        assert_eq!(count(&frames, Side::A, TcpControl::Fin), 0);
        pair.close();

        let mut pair = new_pair(eal, ["h_recva", "h_recvb"]);
        let a = pair.a.add_tcp(tcp_socket_sized(4096)).unwrap();
        let b = pair.b.add_tcp(tcp_socket_sized(4096)).unwrap();
        pair.b.listen(&b, SERVER_PORT).unwrap();
        pair.a.connect(&a, endpoint(Side::B, SERVER_PORT), CLIENT_PORT).unwrap();
        let mut frames = Vec::new();
        round(&mut pair, &mut frames);
        pair.b_to_a.paused = true;
        round(&mut pair, &mut frames);
        assert_eq!(pair.b.tcp(&b).state(), State::SynReceived);
        assert_eq!(pair.a.tcp(&a).state(), State::SynSent);
        drop(b);
        assert_full(&mut pair.b);
        pair.b_to_a.paused = false;
        until_control(&mut pair, &mut frames, Side::B, TcpControl::Rst);
        assert_eq!(count(&frames, Side::B, TcpControl::Rst), 1);
        assert_eq!(count(&frames, Side::B, TcpControl::Fin), 0);
        let _replacement = add_after_close(&mut pair.b);
        pair.close();
    });
}

#[zhida_test_support::pinned_test]
fn dropped_idle_handle_wakes_poll_at_and_sends_fin() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["h_wakea", "h_wakeb"]);
        let ([a, b], _) = establish(&mut pair, Side::A);
        pair.drive(|_, _| {}, |a_stack, _| {
            if a_stack.poll_at().is_none() {
                App::Done
            } else {
                App::Idle
            }
        });
        assert_eq!(pair.a.poll_at(), None);
        drop(a);
        let now = pair.now();
        assert_eq!(pair.a.poll_at(), Some(now));
        assert_eq!(pair.a.turn(now, BUDGET).unwrap().tx_accepted, 1);
        let mut frames = Vec::new();
        pair.drain_tx(Side::A, |bytes| frames.push((Dir::AToB, bytes.to_vec())));
        assert_eq!(count(&frames, Side::A, TcpControl::Fin), 1);
        pair.close();
        drop(b);
    });
}

#[zhida_test_support::pinned_test]
fn drop_listener_frees_slot() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["h_lista", "h_listb"]);
        let a = pair.a.add_tcp(tcp_socket_sized(4096)).unwrap();
        pair.a.listen(&a, SERVER_PORT).unwrap();
        drop(a);
        let _replacement = add_after_close(&mut pair.a);
        let mut frames = Vec::new();
        round(&mut pair, &mut frames);
        assert!(tcp_segments(&frames, Side::A).next().is_none());
        let b = pair.b.add_tcp(tcp_socket_sized(4096)).unwrap();
        pair.b.connect(&b, endpoint(Side::A, SERVER_PORT), CLIENT_PORT).unwrap();
        pair.drive(
            |dir, bytes| frames.push((dir, bytes.to_vec())),
            |_, b_stack| {
                if b_stack.tcp(&b).state() == State::Closed {
                    App::Done
                } else {
                    App::Idle
                }
            },
        );
        assert_eq!(count(&frames, Side::B, TcpControl::Syn), 1);
        assert_eq!(count(&frames, Side::A, TcpControl::Rst), 1);
        assert_eq!(count(&frames, Side::A, TcpControl::Fin), 0);
        pair.close();
    });
}

#[zhida_test_support::pinned_test]
fn drop_with_unread_data_sends_rst() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["h_reada", "h_readb"]);
        let ([a, b], _) = establish(&mut pair, Side::A);
        pair.a.tcp_mut(&a).set_ack_delay(None);
        let idle = pair.in_use()[0].0;
        pair.b.tcp_mut(&b).send_slice(b"unread").unwrap();
        let mut frames = Vec::new();
        pair.drive(
            |dir, bytes| frames.push((dir, bytes.to_vec())),
            |a_stack, _| {
                if a_stack.tcp(&a).recv_queue() == 6 {
                    App::Done
                } else {
                    App::Idle
                }
            },
        );
        assert!(tcp_segments(&frames, Side::B).any(|tcp| tcp.payload == b"unread"));
        assert_eq!(pair.in_use()[0].0, idle.checked_add(1).unwrap());
        frames.clear();
        drop(a);
        assert_full(&mut pair.a);
        until_control(&mut pair, &mut frames, Side::A, TcpControl::Rst);
        assert_eq!(count(&frames, Side::A, TcpControl::Rst), 1);
        assert_eq!(count(&frames, Side::A, TcpControl::Fin), 0);
        assert_eq!(pair.b.tcp(&b).state(), State::Closed);
        assert_eq!(pair.in_use()[0].0, idle);
        let _replacement = add_after_close(&mut pair.a);
        pair.close();
    });
}

#[zhida_test_support::pinned_test]
fn orphan_receiving_data_sends_rst() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["h_dataa", "h_datab"]);
        let ([a, b], _) = establish(&mut pair, Side::A);
        pair.b.tcp_mut(&b).set_ack_delay(None);
        let mut frames = Vec::new();
        drop(a);
        assert_full(&mut pair.a);
        until_control(&mut pair, &mut frames, Side::A, TcpControl::Fin);
        assert_eq!(pair.b.tcp(&b).state(), State::CloseWait);
        assert_full(&mut pair.a);
        pair.b.tcp_mut(&b).send_slice(b"after FIN").unwrap();
        until_control(&mut pair, &mut frames, Side::A, TcpControl::Rst);
        assert_eq!(count(&frames, Side::A, TcpControl::Fin), 1);
        assert_eq!(count(&frames, Side::A, TcpControl::Rst), 1);
        assert!(tcp_segments(&frames, Side::B).any(|tcp| tcp.payload == b"after FIN"));
        assert_eq!(pair.b.tcp(&b).state(), State::Closed);
        let _replacement = add_after_close(&mut pair.a);
        assert_eq!(pair.in_use()[0].0, 0);
        pair.close();
    });
}

#[zhida_test_support::pinned_test]
fn orphan_fin_wait_2_times_out() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["h_timea", "h_timeb"]);
        let ([a, b], _) = establish(&mut pair, Side::A);
        pair.b.tcp_mut(&b).set_ack_delay(None);
        let mut frames = Vec::new();
        drop(a);
        until_control(&mut pair, &mut frames, Side::A, TcpControl::Fin);
        assert_eq!(pair.b.tcp(&b).state(), State::CloseWait);
        round(&mut pair, &mut frames);
        let acked_at = pair.now();
        let fin = tcp_segments(&frames, Side::A)
            .find(|tcp| tcp.control == TcpControl::Fin)
            .unwrap();
        assert!(tcp_segments(&frames, Side::B).any(|tcp| {
            tcp.control == TcpControl::None && tcp.ack_number == Some(fin.seq_number + 1)
        }));
        assert_full(&mut pair.a);
        pair.round_at(acked_at + Duration::from_secs(59), |dir, bytes| {
            frames.push((dir, bytes.to_vec()));
        });
        assert_full(&mut pair.a);
        pair.round_at(acked_at + Duration::from_secs(60), |dir, bytes| {
            frames.push((dir, bytes.to_vec()));
        });
        let _replacement = add_after_close(&mut pair.a);
        assert_eq!(pair.b.tcp(&b).state(), State::CloseWait);
        assert_eq!(count(&frames, Side::A, TcpControl::Fin), 1);
        assert_eq!(count(&frames, Side::A, TcpControl::Rst), 0);
        pair.close();
    });
}

const UDP_PORT: u16 = 1234;

fn udp_config(rx_queue: usize) -> UdpConfig {
    UdpConfig {
        port: UDP_PORT,
        rx_queue,
        tx_checksum: true,
        broadcast: false,
    }
}

fn udp_payloads(frames: &Frames, side: Side) -> Vec<Vec<u8>> {
    frames.iter().filter_map(|(dir, bytes)| {
        if *dir != side.dir() {
            return None;
        }
        let eth = EthernetFrame::new_checked(bytes.as_slice()).unwrap();
        if eth.ethertype() != EthernetProtocol::Ipv4 {
            return None;
        }
        let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
        if ip.next_header() != IpProtocol::Udp {
            return None;
        }
        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!((udp.src_port(), udp.dst_port()), (UDP_PORT, UDP_PORT));
        assert!(udp.verify_checksum(&side.ip().into(), &side.other().ip().into()));
        Some(udp.payload().to_vec())
    }).collect()
}

#[zhida_test_support::pinned_test]
fn udp_drop_frees_port() {
    with_eal(|eal| {
        let configs = [Side::A, Side::B].map(|side| dpdk_smoltcp::StackConfig {
            max_udp_sockets: 2,
            ..pair::config(side)
        });
        let mut pair = Pair::with_ports(eal, ["h_udpa", "h_udpb"], configs, T0, 16, |side, port| {
            let reserve = rx_reserve(
                port.rx_descriptors,
                configs[side.index()].rx_staging,
                port.rx_pool.cache_size,
            );
            port.rx_pool.count = u32::try_from(reserve.checked_add(2).unwrap()).unwrap();
        });
        let a = pair.a.add_udp(udp_config(2)).unwrap();
        let b = pair.b.add_udp(udp_config(2)).unwrap();
        let mut frames = Vec::new();
        assert_eq!(pair.b.udp_send(&b, Some(endpoint(Side::A, UDP_PORT)), b"held"),
                   Err(dpdk_smoltcp::UdpSendError::NeighborPending));
        round(&mut pair, &mut frames);
        round(&mut pair, &mut frames);
        let idle = pair.in_use()[0].0;
        pair.b.udp_send(&b, Some(endpoint(Side::A, UDP_PORT)), b"held").unwrap();
        pair.b.udp_send(&b, Some(endpoint(Side::A, UDP_PORT)), b"queued").unwrap();
        round(&mut pair, &mut frames);
        round(&mut pair, &mut frames);
        assert_eq!(udp_payloads(&frames, Side::B), [b"held".to_vec(), b"queued".to_vec()]);
        assert_eq!(pair.a.udp(&a).rx_queued(), 2);
        assert_eq!(pair.in_use()[0].0, idle.checked_add(2).unwrap());
        let held = pair.a.udp_mut(&a).recv().unwrap();
        assert_eq!(held.payload(), b"held");
        drop(a);
        let replacement = pair.a.add_udp(udp_config(1)).unwrap();
        assert_eq!(pair.a.udp(&replacement).rx_queued(), 0);
        assert_eq!(pair.in_use()[0].0, idle.checked_add(1).unwrap());
        assert_eq!(held.src(), endpoint(Side::B, UDP_PORT));
        assert_eq!(held.payload(), b"held");
        pair.a.remove_udp(replacement);
        assert!(matches!(
            pair.a.add_udp(udp_config(2)),
            Err(AddUdpError::RxPoolTooSmall { .. })
        ));
        drop(held);
        assert_eq!(pair.in_use()[0].0, idle);
        let replacement = pair.a.add_udp(udp_config(2)).unwrap();
        frames.clear();
        pair.b.udp_send(&b, Some(endpoint(Side::A, UDP_PORT)), b"new binding").unwrap();
        round(&mut pair, &mut frames);
        round(&mut pair, &mut frames);
        assert_eq!(udp_payloads(&frames, Side::B), [b"new binding".to_vec()]);
        let received = pair.a.udp_mut(&replacement).recv().unwrap();
        assert_eq!(received.payload(), b"new binding");
        drop(received);
        assert_eq!(pair.in_use()[0].0, idle);
        pair.close();
    });
}

#[zhida_test_support::pinned_test]
fn stack_drop_with_live_sockets_returns_mbufs() {
    with_eal(|eal| {
        let configs = [Side::A, Side::B].map(|side| dpdk_smoltcp::StackConfig {
            max_udp_sockets: 1,
            ..pair::config(side)
        });
        let mut pair = Pair::with_ports(eal, ["h_livea", "h_liveb"], configs, T0, 16, |side, port| {
            let reserve = rx_reserve(
                port.rx_descriptors,
                configs[side.index()].rx_staging,
                port.rx_pool.cache_size,
            );
            port.rx_pool.count = rx_pool_count(reserve, port.mtu, [4096])
                .checked_add(2).unwrap();
        });
        let ([a, b], _) = establish(&mut pair, Side::A);
        let udp_a = pair.a.add_udp(udp_config(2)).unwrap();
        let udp_b = pair.b.add_udp(udp_config(2)).unwrap();
        pair.a.tcp_mut(&a).set_ack_delay(None);
        pair.b.tcp_mut(&b).set_ack_delay(None);
        let idle = pair.in_use().map(|(rx, _)| rx);
        pair.a.tcp_mut(&a).send_slice(b"tcp A").unwrap();
        pair.b.tcp_mut(&b).send_slice(b"tcp B").unwrap();
        pair.a.udp_send(&udp_a, Some(endpoint(Side::B, UDP_PORT)), b"udp A").unwrap();
        pair.b.udp_send(&udp_b, Some(endpoint(Side::A, UDP_PORT)), b"udp B").unwrap();
        let mut frames = Vec::new();
        pair.drive(
            |dir, bytes| frames.push((dir, bytes.to_vec())),
            |a_stack, b_stack| {
                if a_stack.tcp(&a).recv_queue() == 5
                    && b_stack.tcp(&b).recv_queue() == 5
                    && a_stack.udp(&udp_a).rx_queued() == 1
                    && b_stack.udp(&udp_b).rx_queued() == 1
                    && a_stack.tcp(&a).send_queue() == 0
                    && b_stack.tcp(&b).send_queue() == 0
                {
                    App::Done
                } else {
                    App::Idle
                }
            },
        );
        assert!(tcp_segments(&frames, Side::A).any(|tcp| tcp.payload == b"tcp A"));
        assert!(tcp_segments(&frames, Side::B).any(|tcp| tcp.payload == b"tcp B"));
        assert_eq!(udp_payloads(&frames, Side::A), [b"udp A".to_vec()]);
        assert_eq!(udp_payloads(&frames, Side::B), [b"udp B".to_vec()]);
        assert_eq!(
            pair.in_use().map(|(rx, _)| rx),
            idle.map(|rx| rx.checked_add(2).unwrap())
        );
        assert_full(&mut pair.a);
        assert_full(&mut pair.b);
        pair.close();
        drop((a, b, udp_a, udp_b));
    });
}

#[zhida_test_support::pinned_test]
fn plain_stack_drop_with_live_sockets_releases_pools() {
    with_eal(|eal| {
        let fixtures = ["h_plain_a", "h_plain_b"].map(|name| RingPort::new(name, 16, 16));
        let [mut a, mut b] = [Side::A, Side::B].map(|side| {
            let config = dpdk_smoltcp::StackConfig {
                max_udp_sockets: 1,
                ..pair::config(side)
            };
            let fixture = &fixtures[side.index()];
            let mut port = fixture.config();
            let reserve = rx_reserve(port.rx_descriptors, config.rx_staging, port.rx_pool.cache_size);
            port.rx_pool.count = rx_pool_count(reserve, port.mtu, [4096]).checked_add(2).unwrap();
            match Stack::new(fixture.open_with(eal, port), config, T0) {
                Ok(stack) => stack,
                Err((_, error)) => panic!("{error}"),
            }
        });
        let mut a_to_b = fixtures[0].link_to(&fixtures[1]);
        let mut b_to_a = fixtures[1].link_to(&fixtures[0]);
        let ah = a.add_tcp(tcp_socket_sized(4096)).unwrap();
        let bh = b.add_tcp(tcp_socket_sized(4096)).unwrap();
        b.listen(&bh, SERVER_PORT).unwrap();
        a.connect(&ah, endpoint(Side::B, SERVER_PORT), CLIENT_PORT).unwrap();
        let mut rounds = Rounds::new(T0);
        for _ in 0..32 {
            let moved = rounds.round(&mut a, &mut a_to_b, &mut b, &mut b_to_a);
            if a.tcp(&ah).state() == State::Established && b.tcp(&bh).state() == State::Established {
                break;
            }
            rounds.settle(moved, &mut a, &mut b);
        }
        assert_eq!(a.tcp(&ah).state(), State::Established);
        assert_eq!(b.tcp(&bh).state(), State::Established);
        let ua = a.add_udp(udp_config(2)).unwrap();
        let ub = b.add_udp(udp_config(2)).unwrap();
        a.tcp_mut(&ah).set_ack_delay(None);
        b.tcp_mut(&bh).set_ack_delay(None);
        a.tcp_mut(&ah).send_slice(b"tcp A").unwrap();
        b.tcp_mut(&bh).send_slice(b"tcp B").unwrap();
        a.udp_send(&ua, Some(endpoint(Side::B, UDP_PORT)), b"udp A").unwrap();
        b.udp_send(&ub, Some(endpoint(Side::A, UDP_PORT)), b"udp B").unwrap();
        for _ in 0..32 {
            let moved = rounds.round(&mut a, &mut a_to_b, &mut b, &mut b_to_a);
            if a.tcp(&ah).recv_queue() == 5 && b.tcp(&bh).recv_queue() == 5
                && a.udp(&ua).rx_queued() == 1 && b.udp(&ub).rx_queued() == 1
                && a.tcp(&ah).send_queue() == 0 && b.tcp(&bh).send_queue() == 0 {
                break;
            }
            rounds.settle(moved, &mut a, &mut b);
        }
        assert_eq!((a.tcp(&ah).recv_queue(), b.tcp(&bh).recv_queue()), (5, 5));
        assert_eq!((a.udp(&ua).rx_queued(), b.udp(&ub).rx_queued()), (1, 1));
        assert_eq!((a.tcp(&ah).send_queue(), b.tcp(&bh).send_queue()), (0, 0));
        drop((a_to_b, b_to_a));
        for fixture in &fixtures {
            fixture.drain();
            assert_eq!(fixture.in_use().0, 2);
        }
        drop(a);
        drop(b);
        drop((ah, bh, ua, ub));
        for fixture in fixtures {
            assert!(!fixture.pools_exist());
            fixture.close();
        }
    });
}

#[zhida_test_support::pinned_test]
#[should_panic(expected = "TCP handle belongs to another Stack")]
fn handle_from_another_stack_panics() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["h_wrongta", "h_wrongtb"]);
        let a = pair.a.add_tcp(tcp_socket_sized(4096)).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| {
            pair.b.tcp(&a);
        }));
        pair.close();
        drop(a);
        resume_unwind(result.unwrap_err());
    });
}

#[zhida_test_support::pinned_test]
#[should_panic(expected = "UDP handle belongs to another Stack")]
fn udp_handle_from_another_stack_panics() {
    with_eal(|eal| {
        let configs = [Side::A, Side::B].map(|side| dpdk_smoltcp::StackConfig {
            max_udp_sockets: 1,
            ..pair::config(side)
        });
        let mut pair = Pair::new(eal, ["h_wrongua", "h_wrongub"], configs, T0);
        let a = pair.a.add_udp(udp_config(1)).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| {
            pair.b.udp(&a);
        }));
        pair.close();
        drop(a);
        resume_unwind(result.unwrap_err());
    });
}

#[zhida_test_support::pinned_test]
fn reconnect_loop_one_slot() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["h_loopa", "h_loopb"]);
        for _ in 0..5 {
            let a = pair.a.add_tcp(tcp_socket_sized(4096)).unwrap();
            pair.a.connect(&a, endpoint(Side::B, SERVER_PORT), CLIENT_PORT).unwrap();
            let mut frames = Vec::new();
            pair.drive(
                |dir, bytes| frames.push((dir, bytes.to_vec())),
                |a_stack, _| {
                    if a_stack.tcp(&a).state() == State::Closed {
                        App::Done
                    } else {
                        App::Idle
                    }
                },
            );
            assert_eq!(count(&frames, Side::A, TcpControl::Syn), 1);
            assert_eq!(count(&frames, Side::B, TcpControl::Rst), 1);
            assert_eq!(pair.a.tcp(&a).remote_endpoint(), None);
            drop(a);
        }
        for _ in 0..3 {
            let ([a, b], _) = establish(&mut pair, Side::A);
            pair.b.tcp_mut(&b).set_ack_delay(None);
            let mut frames = Vec::new();
            drop(a);
            assert_full(&mut pair.a);
            until_control(&mut pair, &mut frames, Side::A, TcpControl::Fin);
            assert_eq!(pair.b.tcp(&b).state(), State::CloseWait);
            pair.b.tcp_mut(&b).close();
            pair.drive(
                |dir, bytes| frames.push((dir, bytes.to_vec())),
                |_, b_stack| {
                    if b_stack.tcp(&b).state() == State::Closed {
                        App::Done
                    } else {
                        App::Idle
                    }
                },
            );
            assert_eq!(count(&frames, Side::A, TcpControl::Fin), 1);
            assert_eq!(count(&frames, Side::B, TcpControl::Fin), 1);
            assert_eq!(count(&frames, Side::A, TcpControl::Rst), 0);
            assert_full(&mut pair.a);
            let closed_at = pair.now();
            pair.round_at(closed_at + Duration::from_secs(11), |dir, bytes| {
                frames.push((dir, bytes.to_vec()));
            });
            let replacement = add_after_close(&mut pair.a);
            assert_eq!(count(&frames, Side::A, TcpControl::Fin), 1);
            assert_eq!(count(&frames, Side::A, TcpControl::Rst), 0);
            pair.a.remove_tcp(replacement);
            pair.b.remove_tcp(b);
        }
        let _replacement = add_after_close(&mut pair.a);
        pair.close();
    });
}

#[zhida_test_support::pinned_test]
fn dropped_udp_is_cleaned_at_each_entry() {
    with_eal(|eal| {
        for call in 0..5 {
            let configs = [Side::A, Side::B].map(|side| dpdk_smoltcp::StackConfig {
                max_udp_sockets: 1,
                ..pair::config(side)
            });
            let mut pair = Pair::with_ports(eal, ["h_entrya", "h_entryb"], configs, T0, 16, |side, port| {
                let reserve = rx_reserve(
                    port.rx_descriptors,
                    configs[side.index()].rx_staging,
                    port.rx_pool.cache_size,
                );
                port.rx_pool.count = rx_pool_count(reserve, port.mtu, [4096])
                    .checked_add(1).unwrap();
            });
            let a = pair.a.add_udp(udp_config(1)).unwrap();
            let b = pair.b.add_udp(udp_config(1)).unwrap();
            assert_eq!(pair.b.udp_send(&b, Some(endpoint(Side::A, UDP_PORT)), b"queued"),
                       Err(dpdk_smoltcp::UdpSendError::NeighborPending));
            let mut frames = Vec::new();
            round(&mut pair, &mut frames);
            round(&mut pair, &mut frames);
            let idle = pair.in_use()[0].0;
            pair.b.udp_send(&b, Some(endpoint(Side::A, UDP_PORT)), b"queued").unwrap();
            round(&mut pair, &mut frames);
            round(&mut pair, &mut frames);
            assert_eq!(udp_payloads(&frames, Side::B), [b"queued".to_vec()]);
            assert_eq!(pair.a.udp(&a).rx_queued(), 1);
            drop(a);
            pair.a.flush().unwrap();
            pair.a.poll_at();
            assert_eq!(pair.in_use()[0].0, idle.checked_add(1).unwrap());
            let now = pair.now();
            let mut tcp = None;
            let mut udp = None;
            match call {
                0 => {
                    pair.a.turn(now, BUDGET).unwrap();
                }
                1 => {
                    pair.a.receive(now, BUDGET).unwrap();
                }
                2 => {
                    pair.a.send().unwrap();
                }
                3 => {
                    tcp = Some(pair.a.add_tcp(tcp_socket_sized(4096)).unwrap());
                }
                4 => {
                    udp = Some(pair.a.add_udp(udp_config(1)).unwrap());
                }
                _ => unreachable!(),
            }
            assert_eq!(pair.in_use()[0].0, idle);
            pair.close();
            drop((tcp, udp, b));
        }
    });
}
