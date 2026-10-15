//! 1024 established connections on one pair of Stacks (kit `many`): streams
//! stay apart, closed connections free their slots for new ones, dropped
//! segments are retransmitted, and pool use returns to its idle level.

use zhida_test_kit::pair::drain_bytes;
use dpdk_smoltcp::smoltcp::socket::tcp::{RecvError, State};
use dpdk_smoltcp::smoltcp::wire::{EthernetFrame, EthernetProtocol};

use zhida_test_kit::many::{self, assert_quiet, Conn, SERVER_BASE, WAVE};
use zhida_test_kit::pair::{pattern, segment, App, Pair, Side, T0};
use zhida_test_kit::wire::Verdict;
use zhida_test_kit::with_eal;

const CONNECTIONS: u16 = 1024;
const BUFFER: usize = 2048;
/// Full-size segment payload with timestamps (MSS 1460 less 12).
const MSS: usize = 1448;

fn exhaust_rx_pool(name: &std::ffi::CStr, count: u32) {
    use zhida_test_kit::wire::{in_use, pool_by_name};
    use zhida_dpdk_sys::{dpdk_raw_pktmbuf_alloc, dpdk_raw_pktmbuf_free};

    assert_eq!(in_use(name), 0);
    let pool = pool_by_name(name);
    for _ in 0..2 {
        let mut packets = Vec::new();
        for _ in 0..count {
            let packet = unsafe { dpdk_raw_pktmbuf_alloc(pool) };
            assert!(!packet.is_null());
            assert!(
                !packets.contains(&packet),
                "RX pool returned one mbuf twice"
            );
            packets.push(packet);
        }
        assert!(unsafe { dpdk_raw_pktmbuf_alloc(pool) }.is_null());
        assert_eq!(in_use(name), count);
        for packet in packets {
            unsafe { dpdk_raw_pktmbuf_free(packet) };
        }
        assert_eq!(in_use(name), 0);
    }
}

#[zhida_test_support::pinned_test]
fn packet_rx_full_window_64_connections() {
    with_eal(|eal| {
        const COUNT: u16 = 64;
        const CAPACITY: usize = 4096;
        let configs = [many::config(Side::A, 64), many::config(Side::B, 64)];
        let pool_count = dpdk_smoltcp::rx_pool_count(
            dpdk_smoltcp::rx_reserve(16, configs[0].rx_staging, 8),
            1500,
            [CAPACITY; 64],
        );
        let mut pair = Pair::with_ports(eal, ["full64a", "full64b"], configs, T0, 16, |_, port| {
            port.rx_pool.count = pool_count;
        });
        let conns = many::open(&mut pair, 0..COUNT, CAPACITY);
        assert_quiet(&mut pair, &conns);
        let data: Vec<_> = conns
            .iter()
            .map(|conn| {
                [
                    pattern(CAPACITY, u32::from(conn.id)),
                    pattern(CAPACITY, 64 + u32::from(conn.id)),
                ]
            })
            .collect();
        let mut zero_window = [[false; 2]; 64];
        for (conn, sent) in conns.iter().zip(&data) {
            let cap = pair.a.tcp(&conn.client).rx_frame_cap();
            assert_eq!(cap, pair.b.tcp(&conn.server).rx_frame_cap());
            for (stack, handle, payload) in [
                (&mut pair.a, &conn.client, &sent[0]),
                (&mut pair.b, &conn.server, &sent[1]),
            ] {
                for index in 0..cap {
                    let start = index * CAPACITY / cap;
                    let end = (index + 1) * CAPACITY / cap;
                    let bytes = &payload[start..end];
                    assert_eq!(stack.tcp_mut(handle).send_slice(bytes), Ok(bytes.len()));
                    assert_eq!(stack.send().unwrap().tx_accepted, 1);
                }
            }
            pair.drive(
                |dir, frame| {
                    let side = if dir == Side::A.dir() {
                        Side::A
                    } else {
                        Side::B
                    };
                    let tcp = segment(frame, side);
                    let id = if side == Side::A {
                        tcp.src_port - many::CLIENT_BASE
                    } else {
                        tcp.src_port - SERVER_BASE
                    };
                    if tcp.window_len == 0 {
                        zero_window[usize::from(id)][side.index()] = true;
                    }
                },
                |a, b| {
                    if a.tcp(&conn.client).recv_queue() == CAPACITY
                        && b.tcp(&conn.server).recv_queue() == CAPACITY
                        && a.tcp(&conn.client).send_queue() == 0
                        && b.tcp(&conn.server).send_queue() == 0
                    {
                        App::Done
                    } else {
                        App::Idle
                    }
                },
            );
            assert_no_overflow(&pair);
        }
        assert_eq!(zero_window, [[true; 2]; 64]);
        for conn in &conns {
            for (stack, handle) in [(&pair.a, &conn.client), (&pair.b, &conn.server)] {
                assert_eq!(stack.tcp(&handle).recv_room(), 0);
                assert_eq!(stack.tcp(&handle).rx_refused_segments(), 0);
            }
        }
        for (conn, sent) in conns.iter().zip(&data).take(2) {
            for (side, stack, handle) in [
                (Side::A, &mut pair.a, &conn.client),
                (Side::B, &mut pair.b, &conn.server),
            ] {
                let bytes = drain_bytes(stack.tcp_mut(&handle)).unwrap();
                assert_eq!(bytes.len(), CAPACITY);
                assert_eq!(bytes, sent[side.other().index()]);
            }
            assert_eq!(
                pair.a.tcp_mut(&conn.client).send_slice(&sent[0]),
                Ok(CAPACITY)
            );
            assert_eq!(
                pair.b.tcp_mut(&conn.server).send_slice(&sent[1]),
                Ok(CAPACITY)
            );
            let mut received = [Vec::new(), Vec::new()];
            pair.drive_rounds(
                |_, _| {},
                |round, a, b| {
                    let mut moved = false;
                    for (side, stack, handle) in [
                        (Side::A, &mut *a, &conn.client),
                        (Side::B, &mut *b, &conn.server),
                    ] {
                        let bytes = drain_bytes(stack.tcp_mut(&handle)).unwrap();
                        let read = bytes.len();
                        if read > 0 {
                            assert!(round.a.rx_received + round.b.rx_received > 0);
                        }
                        received[side.index()].extend_from_slice(&bytes[..read]);
                        moved |= read > 0;
                    }
                    for other in &conns[2..] {
                        assert_eq!(a.tcp(&other.client).recv_queue(), CAPACITY);
                        assert_eq!(b.tcp(&other.server).recv_queue(), CAPACITY);
                    }
                    if received.iter().all(|bytes| bytes.len() == CAPACITY)
                        && a.tcp(&conn.client).send_queue() == 0
                        && b.tcp(&conn.server).send_queue() == 0
                    {
                        App::Done
                    } else if moved {
                        App::Moved
                    } else {
                        App::Idle
                    }
                },
            );
            assert_eq!(received[0], sent[1]);
            assert_eq!(received[1], sent[0]);
        }
        // Each of the other 62 sockets on each side is read from a zero
        // window and sends one window update. Eight connections at a time,
        // so the updates fit one 8-frame RX burst and no RX ring overflows.
        let mut updates = [0usize; 2];
        let rest: Vec<_> = conns.iter().zip(&data).skip(2).collect();
        for wave in rest.chunks(8) {
            for &(conn, sent) in wave {
                for (side, stack, handle) in [
                    (Side::A, &mut pair.a, &conn.client),
                    (Side::B, &mut pair.b, &conn.server),
                ] {
                    let bytes = drain_bytes(stack.tcp_mut(&handle)).unwrap();
                    assert_eq!(bytes.len(), CAPACITY);
                    assert_eq!(bytes, sent[side.other().index()]);
                }
            }
            pair.drive_rounds(
                |dir, frame| {
                    let side = if dir == Side::A.dir() {
                        Side::A
                    } else {
                        Side::B
                    };
                    let tcp = segment(frame, side);
                    assert!(tcp.payload.is_empty() && tcp.window_len > 0);
                    updates[side.index()] += 1;
                },
                |round, _, _| {
                    if round.moved() {
                        App::Moved
                    } else {
                        App::Done
                    }
                },
            );
        }
        assert_eq!(updates, [usize::from(COUNT) - 2; 2]);
        assert_quiet(&mut pair, &conns);
        for conn in &conns {
            assert_eq!(pair.a.tcp(&conn.client).rx_refused_segments(), 0);
            assert_eq!(pair.b.tcp(&conn.server).rx_refused_segments(), 0);
        }
        assert_no_overflow(&pair);
        assert_eq!(pair.in_use().map(|(rx, _)| rx), [0, 0]);
        exhaust_rx_pool(c"full64a_rxp", pool_count);
        exhaust_rx_pool(c"full64b_rxp", pool_count);
        assert_eq!(pair.close(), 0);
    });
}

fn new_pair(eal: &dpdk_smoltcp::Eal, names: [&str; 2]) -> Pair {
    let capacity = usize::from(CONNECTIONS);
    Pair::new(
        eal,
        names,
        [
            many::config(Side::A, capacity),
            many::config(Side::B, capacity),
        ],
        T0,
    )
}

/// What `from` sends on connection `id`: one segment or less, its own bytes.
fn message(id: u16, from: Side) -> Vec<u8> {
    let len = 1 + usize::from(id) * 97 % MSS;
    pattern(len, 2 * u32::from(id) + from as u32)
}

/// Neither link overflowed a ring or found a pool empty.
fn assert_no_overflow(pair: &Pair) {
    for link in [&pair.a_to_b, &pair.b_to_a] {
        assert_eq!((link.ring_full, link.pool_empty), (0, 0));
    }
}

/// `WAVE` connections at a time: both ends write their `message`, then each
/// reads the other's, which must arrive whole and unchanged, until both
/// messages are acknowledged.
fn exchange(pair: &mut Pair, conns: &[&Conn]) {
    for wave in conns.chunks(WAVE) {
        let mut got = vec![[Vec::new(), Vec::new()]; wave.len()];
        for conn in wave {
            for (side, stack, handle) in [
                (Side::A, &mut pair.a, &conn.client),
                (Side::B, &mut pair.b, &conn.server),
            ] {
                let message = message(conn.id, side);
                assert_eq!(
                    stack.tcp_mut(&handle).send_slice(&message),
                    Ok(message.len())
                );
            }
        }
        pair.drive(
            |_, _| {},
            |a, b| {
                let mut moved = false;
                let mut done = true;
                for (conn, got) in wave.iter().zip(&mut got) {
                    for (side, stack, handle) in [
                        (Side::A, &mut *a, &conn.client),
                        (Side::B, &mut *b, &conn.server),
                    ] {
                        let socket = stack.tcp_mut(&handle);
                        let buffer = drain_bytes(socket).unwrap();
                        let read = buffer.len();
                        got[side.index()].extend_from_slice(&buffer[..read]);
                        moved |= read > 0;
                        done &= socket.send_queue() == 0
                            && got[side.index()].len() >= message(conn.id, side.other()).len();
                    }
                }
                match (done, moved) {
                    (true, _) => App::Done,
                    (false, true) => App::Moved,
                    (false, false) => App::Idle,
                }
            },
        );
        for (conn, got) in wave.iter().zip(&got) {
            for side in [Side::A, Side::B] {
                assert!(
                    got[side.index()] == message(conn.id, side.other()),
                    "connection {} {side:?} read other bytes",
                    conn.id
                );
            }
        }
        assert_no_overflow(pair);
    }
}

#[zhida_test_support::pinned_test]
fn thousand_connections_keep_streams_apart() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["mc1a", "mc1b"]);
        let conns = many::open(&mut pair, 0..CONNECTIONS, BUFFER);
        assert_quiet(&mut pair, &conns);
        let idle = pair.in_use();
        exchange(&mut pair, &conns.iter().collect::<Vec<_>>());
        assert_quiet(&mut pair, &conns);
        assert_eq!(pair.in_use(), idle);
        assert_eq!(pair.close(), 0);
    });
}

/// The clients of `group` abort (RST), or close (FIN both ways, the client
/// through TIME-WAIT); driven until both ends of every connection are Closed.
fn end(pair: &mut Pair, group: &[Conn], abort: bool) {
    assert!(group.len() <= WAVE);
    for conn in group {
        let client = pair.a.tcp_mut(&conn.client);
        if abort {
            client.abort();
        } else {
            client.close();
        }
    }
    pair.drive(
        |_, _| {},
        |a, b| {
            let mut moved = false;
            for conn in group {
                let server = b.tcp_mut(&conn.server);
                if server.state() == State::CloseWait {
                    assert!(matches!(server.recv(), Err(RecvError::Finished)));
                    server.close();
                    moved = true;
                }
            }
            let closed = group.iter().all(|conn| {
                a.tcp(&conn.client).state() == State::Closed
                    && b.tcp(&conn.server).state() == State::Closed
            });
            match (closed, moved) {
                (true, _) => App::Done,
                (false, true) => App::Moved,
                (false, false) => App::Idle,
            }
        },
    );
    assert_no_overflow(pair);
}

#[zhida_test_support::pinned_test]
fn thousand_connections_close_remove_and_reuse_slots() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["mc2a", "mc2b"]);
        let mut conns = many::open(&mut pair, 0..CONNECTIONS, BUFFER);
        assert_quiet(&mut pair, &conns);
        let idle = pair.in_use();

        // Every 64th connection ends, one wave per way of ending.
        let mut ending = Vec::new();
        let mut remaining = Vec::new();
        for (index, conn) in conns.into_iter().enumerate() {
            if index % 64 == 0 {
                ending.push(conn);
            } else {
                remaining.push(conn);
            }
        }
        conns = remaining;
        let (aborted, finished) = ending.split_at(WAVE);
        end(&mut pair, aborted, true);
        end(&mut pair, finished, false);
        assert_eq!(pair.in_use(), idle);
        let slots: Vec<_> = ending.iter().map(|conn| {
            (
                (conn.client.to_string(), conn.server.to_string()),
                (format!("{:?}", conn.client), format!("{:?}", conn.server)),
            )
        }).collect();
        for conn in ending {
            pair.a.remove_tcp(conn.client);
            pair.b.remove_tcp(conn.server);
        }
        assert_quiet(&mut pair, &conns);

        // New connections on new ports take the freed slots, lowest first.
        let reopened = many::open(
            &mut pair,
            CONNECTIONS..CONNECTIONS + slots.len() as u16,
            BUFFER,
        );
        for (new, old) in reopened.iter().zip(&slots) {
            assert_eq!(
                (new.client.to_string(), new.server.to_string()),
                old.0
            );
            assert_ne!(
                (format!("{:?}", new.client), format!("{:?}", new.server)),
                old.1
            );
        }
        conns.extend(reopened);
        assert_quiet(&mut pair, &conns);
        exchange(&mut pair, &conns.iter().collect::<Vec<_>>());
        assert_quiet(&mut pair, &conns);
        assert_eq!(pair.in_use(), idle);
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn thousand_connections_retransmit_dropped_segments() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["mc3a", "mc3b"]);
        let conns = many::open(&mut pair, 0..CONNECTIONS, BUFFER);
        assert_quiet(&mut pair, &conns);
        let idle = pair.in_use();

        // One wave spread over the slots; each client's first data segment
        // is dropped once.
        let lossy: Vec<&Conn> = conns
            .iter()
            .step_by(usize::from(CONNECTIONS) / WAVE)
            .collect();
        assert_eq!(lossy.len(), WAVE);
        let mut pending: Vec<u16> = lossy.iter().map(|conn| SERVER_BASE + conn.id).collect();
        pair.a_to_b.impair(move |frame| {
            if EthernetFrame::new_checked(frame).unwrap().ethertype() != EthernetProtocol::Ipv4 {
                return Verdict::Deliver;
            }
            let tcp = segment(frame, Side::A);
            match pending.iter().position(|&port| port == tcp.dst_port) {
                Some(at) if !tcp.payload.is_empty() => {
                    pending.swap_remove(at);
                    Verdict::Drop
                }
                _ => Verdict::Deliver,
            }
        });
        exchange(&mut pair, &lossy);
        assert_eq!(pair.a_to_b.dropped, WAVE as u64);

        exchange(&mut pair, &conns.iter().collect::<Vec<_>>());
        assert_eq!(pair.a_to_b.dropped, WAVE as u64);
        assert_quiet(&mut pair, &conns);
        assert_eq!(pair.in_use(), idle);
        assert_eq!(pair.close(), 0);
    });
}
