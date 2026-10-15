//! Zhida Ports on both ends of one net_memif connection (copy mode) in one
//! process: the server vdev first, then the client on the same abstract socket.
//! Every test closes both ends, client first unless stated, and checks that
//! all four pools are gone.

use zhida_test_kit::pair::drain_bytes;
mod common;

use std::collections::VecDeque;
use std::ffi::{CStr, CString};
use std::time::Instant;

use common::{close_pair, fresh_socket, names, End, Names, DEADLINE};
use zhida_test_kit::with_eal;
use dpdk_smoltcp::{Offloads, Packet, Port, PortConfig, PortError};
use memif_bench::memif::{Memif, MemifError, MemifVdev, Role, BUFFER_SIZE, MAX_SOCKET_NAME};
use zhida_buffer::PoolConfig;
use zhida_dpdk_sys::*;

use zhida_test_kit::wire;

const BURST: u16 = 32;
/// Default memif ring: 1024 descriptors.
const RING: u8 = 10;

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
fn tiny_segments_keep_memif_bulk_reserve() {
    use zhida_test_kit::pair::{self, Side, T0};
    use dpdk_smoltcp::smoltcp::socket::tcp::{self, State};
    use dpdk_smoltcp::smoltcp::wire::{
        ArpOperation, EthernetAddress, TcpControl, TcpRepr, TcpSeqNumber,
    };
    use dpdk_smoltcp::{rx_pool_count, rx_reserve, Stack};

    const CAPACITY: usize = 4096;
    // One byte above the stack's 64-byte append limit: each segment keeps its own RX mbuf.
    const SEGMENT: usize = 65;
    let cap = tcp::rx_mbuf_budget(&zhida_test_kit::pair::tcp_socket_sized(CAPACITY), 1500);
    let reserve = rx_reserve(64, usize::from(BURST), 8);
    let pool_count = rx_pool_count(reserve, 1500, [CAPACITY; 2]);
    let names = names("tinyreserve");
    let (mut server, mut client) = common::open_pair(&names, RING, |id, rx, tx| {
        let mut config = config(id, rx, tx);
        config.rx_pool.count = pool_count;
        config
    });
    let mut staged = VecDeque::with_capacity(usize::from(BURST));
    assert_eq!(client.port.rx_burst(&mut staged).unwrap().accepted, 0);
    let padding_count = reserve
        .checked_sub(31)
        .expect("reserve covers a bulk allocation");
    let mut padding = Vec::new();
    for batch in frames(padding_count).chunks(usize::from(BURST)) {
        send(&mut client, batch);
        padding.extend(receive(&mut server, batch.len()));
    }
    assert_eq!(in_use(&names.server_rx), padding_count as u32);
    let End { vdev, port } = server;
    let mut config = pair::config(Side::B);
    config.max_sockets = 2;
    let mut stack = Stack::new(std::mem::ManuallyDrop::into_inner(port), config, T0)
        .map_err(|(_, error)| error)
        .unwrap();
    let handles = [0, 1].map(|index| {
        let handle = stack.add_tcp(pair::tcp_socket_sized(CAPACITY)).unwrap();
        stack.tcp_mut(&handle).set_ack_delay(None);
        stack.listen(&handle, pair::SERVER_PORT + index).unwrap();
        handle
    });
    let arp = zhida_test_kit::ring_port::arp(
        ArpOperation::Request,
        EthernetAddress::BROADCAST,
        (Side::A.mac(), Side::A.ip()),
        (EthernetAddress::BROADCAST, Side::B.ip()),
    );
    send(&mut client, &[arp]);
    assert_eq!(stack.turn(T0, pair::BUDGET).unwrap().rx_received, 1);
    drop(receive(&mut client, 1));
    let mut peer = [TcpRepr {
        src_port: pair::CLIENT_PORT,
        dst_port: pair::SERVER_PORT,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(7000),
        ack_number: None,
        window_len: 65535,
        window_scale: None,
        max_seg_size: Some(1460),
        sack_permitted: true,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    }; 2];
    for (index, tcp) in peer.iter_mut().enumerate() {
        tcp.src_port += index as u16;
        tcp.dst_port += index as u16;
        send(&mut client, &[pair::tcp_frame(Side::A, tcp)]);
        assert_eq!(stack.turn(T0, pair::BUDGET).unwrap().rx_received, 1);
        let reply = receive(&mut client, 1);
        let syn_ack = pair::segment(reply[0].data(), Side::B);
        assert_eq!(syn_ack.control, TcpControl::Syn);
        assert_eq!(syn_ack.ack_number, Some(tcp.seq_number + 1));
        tcp.control = TcpControl::None;
        tcp.seq_number += 1;
        tcp.ack_number = Some(syn_ack.seq_number + 1);
        tcp.max_seg_size = None;
        tcp.sack_permitted = false;
        drop(reply);
        send(&mut client, &[pair::tcp_frame(Side::A, tcp)]);
        assert_eq!(stack.turn(T0, pair::BUDGET).unwrap().rx_received, 1);
        assert_eq!(stack.tcp(&handles[index]).state(), State::Established);
    }
    let data = [
        pair::pattern(cap * SEGMENT, 94),
        pair::pattern(cap * SEGMENT, 95),
    ];
    for (index, tcp) in peer.iter().enumerate() {
        // Right edge the SYN-ACK promised.
        let mut edge = CAPACITY;
        for (offset, bytes) in data[index].chunks(SEGMENT).enumerate() {
            let received = (offset + 1) * SEGMENT;
            let segment = TcpRepr {
                seq_number: tcp.seq_number + offset * SEGMENT,
                payload: bytes,
                ..*tcp
            };
            send(&mut client, &[pair::tcp_frame(Side::A, &segment)]);
            let turn = stack.turn(T0, pair::BUDGET).unwrap();
            assert_eq!((turn.rx_received, turn.rx_processed), (1, 1));
            let reply = receive(&mut client, 1);
            let ack = pair::segment(reply[0].data(), Side::B);
            assert_eq!(ack.ack_number, Some(tcp.seq_number + received));
            // The frames-only window: the field advertises the free-frame room
            // (capped at CAPACITY, not reduced by unread bytes) and never pulls
            // back the right edge, even after the sixth held frame leaves no
            // room (`recv_room` below).
            edge = edge.max(received + stack.tcp(&handles[index]).recv_room());
            assert_eq!(usize::from(ack.window_len), edge - received);
            assert_eq!(stack.tcp(&handles[index]).recv_queue(), received);
            assert_eq!(stack.tcp(&handles[index]).rx_refused_segments(), 0);
            let held = index * cap + offset + 1;
            assert_eq!(in_use(&names.server_rx) as usize, padding.len() + held);
        }
        assert_eq!(stack.tcp(&handles[index]).recv_room(), 0);
    }
    let pool = wire::pool_by_name(&names.server_rx);
    assert_eq!(avail(pool), 31);
    let probe = [frame(60, 0xee)];
    send(&mut client, &probe);
    let turn = stack.turn(T0, pair::BUDGET).unwrap();
    assert_eq!((turn.rx_received, turn.rx_processed), (0, 0));
    assert_eq!(avail(pool), 31);
    drop(
        padding
            .pop()
            .expect("one retained packet frees the 32nd mbuf"),
    );
    assert_eq!(avail(pool), 32);
    let turn = stack.turn(T0, pair::BUDGET).unwrap();
    assert_eq!(
        (turn.rx_received, turn.rx_processed, turn.rx_rejected),
        (1, 1, 0)
    );
    assert_eq!(avail(pool), 32);
    for (index, handle) in handles.into_iter().enumerate() {
        let bytes = drain_bytes(stack.tcp_mut(&handle)).unwrap();
        assert_eq!(bytes.len(), cap * SEGMENT);
        assert_eq!(bytes, data[index]);
        assert_eq!(stack.tcp(&handle).rx_refused_segments(), 0);
    }
    let port = stack.into_port();
    drop(padding);
    assert_eq!(in_use(&names.server_rx), 0);
    assert_eq!(in_use(&names.client_rx), 0);
    exhaust_rx_pool(&names.server_rx, pool_count);
    exhaust_rx_pool(&names.client_rx, pool_count);
    close_pair(
        client,
        End {
            vdev,
            port: std::mem::ManuallyDrop::new(port),
        },
        &names,
    );
}

/// 255 mbufs cover RX staging (`BURST`) + memif's 32-mbuf bulk allocation +
/// cache slack (1.5 x 8).
fn config<'a>(port_id: u16, rx: &'a CStr, tx: &'a CStr) -> PortConfig<'a> {
    let pool = |name| PoolConfig {
        name,
        count: 255,
        cache_size: 8,
        data_room_size: RTE_PKTMBUF_HEADROOM as u16 + BUFFER_SIZE,
        socket_id: -1,
    };
    PortConfig {
        port_id,
        mtu: 1500,
        rx_descriptors: 64,
        tx_descriptors: 64,
        rx_burst: BURST,
        tx_burst: BURST,
        queue_socket: -1,
        rx_pool: pool(rx),
        tx_pool: pool(tx),
        offloads: Offloads::default(),
    }
}

fn in_use(name: &CStr) -> u32 {
    unsafe { rte_mempool_in_use_count(wire::pool_by_name(name)) }
}

fn avail(pool: *mut rte_mempool) -> u32 {
    unsafe { (*pool).size - rte_mempool_in_use_count(pool) }
}

/// Open both ends; the client then posts its RX slots once.
fn open_pair(names: &Names, log2_ring_size: u8) -> (End, End) {
    let (server, mut client) = common::open_pair(names, log2_ring_size, config);
    // Copy mode: the server can send only into S2C slots the client posted,
    // and the client posts them in rx_burst.
    let mut staged = VecDeque::with_capacity(usize::from(BURST));
    let burst = client.port.rx_burst(&mut staged).unwrap();
    assert_eq!((burst.accepted, burst.rejected), (0, 0));
    (server, client)
}

/// Ethernet frame of `len` bytes, EtherType 0x88B5, payload distinct per `marker`.
fn frame(len: usize, marker: u8) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len);
    bytes.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    bytes.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    bytes.extend_from_slice(&[0x88, 0xb5]);
    bytes.extend((0..len - 14).map(|offset| marker.wrapping_add(offset as u8)));
    bytes
}

fn frames(count: usize) -> Vec<Vec<u8>> {
    (0..count).map(|i| frame(60 + i * 97 % 1455, i as u8)).collect()
}

fn packets(port: &mut End, frames: &[Vec<u8>]) -> VecDeque<Packet> {
    frames
        .iter()
        .map(|bytes| {
            let mut packet = port.port.alloc_tx(bytes.len() as u16).unwrap();
            packet.data_mut().copy_from_slice(bytes);
            packet
        })
        .collect()
}

/// Offer `frames` in one burst; all must be accepted.
fn send(port: &mut End, frames: &[Vec<u8>]) {
    let mut pending = packets(port, frames);
    assert_eq!(port.port.tx_burst(&mut pending).unwrap(), frames.len());
}

/// Poll until `count` packets arrived; every burst rejects nothing.
fn receive(port: &mut End, count: usize) -> Vec<Packet> {
    let deadline = Instant::now() + DEADLINE;
    let mut received = Vec::new();
    while received.len() < count {
        assert!(
            Instant::now() < deadline,
            "received {} of {count} frames before the deadline",
            received.len()
        );
        let mut staged = VecDeque::with_capacity(usize::from(BURST));
        let burst = port.port.rx_burst(&mut staged).unwrap();
        assert_eq!(burst.rejected, 0);
        assert_eq!(burst.accepted, staged.len());
        received.extend(staged);
    }
    assert_eq!(received.len(), count);
    received
}

fn assert_bytes(received: &[Packet], frames: &[Vec<u8>]) {
    assert_eq!(received.len(), frames.len());
    for (packet, bytes) in received.iter().zip(frames) {
        assert_eq!(packet.data(), &bytes[..]);
    }
}

#[zhida_test_support::pinned_test]
fn memif_frames_cross_in_one_process() {
    let names = names("cross");
    let (mut server, mut client) = open_pair(&names, RING);
    let sent = frames(8);
    send(&mut client, &sent);
    assert_bytes(&receive(&mut server, sent.len()), &sent);
    let back = [frame(60, 0xa0), frame(1514, 0xa1), frame(1000, 0xa2)];
    send(&mut server, &back);
    assert_bytes(&receive(&mut client, back.len()), &back);
    close_pair(client, server, &names);
}

#[zhida_test_support::pinned_test]
fn empty_tx_burst_after_connect_returns_zero() {
    let names = names("empty");
    let (mut server, mut client) = open_pair(&names, RING);
    for port in [&mut server, &mut client] {
        let mut pending = VecDeque::new();
        assert_eq!(port.port.tx_burst(&mut pending).unwrap(), 0);
        assert_eq!(port.port.tx_burst(&mut pending).unwrap(), 0);
    }
    close_pair(client, server, &names);
}

#[zhida_test_support::pinned_test]
fn memif_rx_mbufs_come_from_the_ports_rx_pool() {
    let names = names("rxpool");
    let (mut server, mut client) = open_pair(&names, RING);
    assert_eq!(in_use(&names.server_rx), 0);
    let sent = frames(5);
    send(&mut client, &sent);
    let received = receive(&mut server, sent.len());
    assert_eq!(in_use(&names.server_rx), sent.len() as u32);
    assert_bytes(&received, &sent);
    drop(received);
    assert_eq!(in_use(&names.server_rx), 0);
    close_pair(client, server, &names);
}

#[zhida_test_support::pinned_test]
fn memif_tx_accepts_front_prefix_when_ring_full() {
    let names = names("full");
    // 16 descriptors per ring.
    let (mut server, mut client) = open_pair(&names, 4);
    let sent = frames(24);
    let mut pending = packets(&mut client, &sent);
    let accepted = client.port.tx_burst(&mut pending).unwrap();
    assert_eq!(accepted, 16);
    assert!(accepted < sent.len());
    let suffix: Vec<&[u8]> = pending.iter().map(Packet::data).collect();
    let expected: Vec<&[u8]> = sent[accepted..].iter().map(Vec::as_slice).collect();
    assert_eq!(suffix, expected);
    let mut received = receive(&mut server, accepted);
    assert_eq!(client.port.tx_burst(&mut pending).unwrap(), sent.len() - accepted);
    assert!(pending.is_empty());
    received.extend(receive(&mut server, sent.len() - accepted));
    assert_bytes(&received, &sent);
    drop(received);
    close_pair(client, server, &names);
}

#[zhida_test_support::pinned_test]
fn memif_tx_buffers_return_to_pool_on_accept() {
    let names = names("txpool");
    let (mut server, mut client) = open_pair(&names, RING);
    let sent = frames(8);
    let mut pending = packets(&mut client, &sent);
    assert_eq!(in_use(&names.client_tx), sent.len() as u32);
    assert_eq!(client.port.tx_burst(&mut pending).unwrap(), sent.len());
    assert_eq!(in_use(&names.client_tx), 0);
    assert_bytes(&receive(&mut server, sent.len()), &sent);
    close_pair(client, server, &names);
}

/// Copy mode keeps no mbuf between calls: with unread frames in both rings,
/// both closes succeed and all four pools are freed. Says nothing about the
/// shared memif regions themselves.
#[zhida_test_support::pinned_test]
fn memif_close_with_unread_frames_frees_pools() {
    let names = names("unread");
    let (mut server, mut client) = open_pair(&names, RING);
    send(&mut client, &frames(8));
    send(&mut server, &frames(8));
    close_pair(client, server, &names);
}

/// Open, pass a frame each way and close a pair three times in one process,
/// reusing vdev and pool names (each pair gets a new socket name, see
/// `common::open_pair`). `server_first` picks the close order, so the other
/// end is the last device on the listener's socket.
fn reopen_pairs(tag: &str, server_first: bool) {
    let names = names(tag);
    for marker in 0..3 {
        let (mut server, mut client) = open_pair(&names, RING);
        let sent = [frame(100, marker)];
        send(&mut client, &sent);
        assert_bytes(&receive(&mut server, 1), &sent);
        send(&mut server, &sent);
        assert_bytes(&receive(&mut client, 1), &sent);
        if server_first {
            close_pair(server, client, &names);
        } else {
            close_pair(client, server, &names);
        }
    }
}

#[zhida_test_support::pinned_test]
fn memif_pairs_reopen_after_server_first_close() {
    reopen_pairs("reopen_s", true);
}

#[zhida_test_support::pinned_test]
fn memif_pairs_reopen_after_client_first_close() {
    reopen_pairs("reopen_c", false);
}

/// Socket names memif would misread are refused before any vdev exists: a
/// ',' or '=' makes memif ignore every devargs and probe a default client,
/// a longer name is truncated. Nothing is opened, so nothing to close; an
/// unexpected open is leaked.
#[zhida_test_support::pinned_test]
fn socket_names_memif_would_misread_are_rejected() {
    let names = names("badsock");
    let long = "x".repeat(MAX_SOCKET_NAME + 1);
    let cases = [
        ("a,b", "socket name contains ',' or '='"),
        ("a=b", "socket name contains ',' or '='"),
        (long.as_str(), "socket name longer than MAX_SOCKET_NAME"),
    ];
    with_eal(|eal| {
        for (socket, expected) in cases {
            let memif = Memif { vdev: &names.server, role: Role::Server, id: 0, socket, log2_ring_size: RING };
            let opened = unsafe { MemifVdev::open(eal, &memif, |id| config(id, &names.server_rx, &names.server_tx)) };
            match opened {
                Err(MemifError::Settings(reason)) => assert_eq!(reason, expected, "{socket}"),
                Ok(opened) => {
                    std::mem::forget(opened);
                    panic!("{socket} accepted");
                }
                Err(other) => panic!("{socket}: {other}"),
            }
            let mut port_id = 0;
            assert_ne!(unsafe { rte_eth_dev_get_port_by_name(names.server.as_ptr(), &mut port_id) }, 0);
        }
    });
}

/// net_memif reports a 1518-byte maximum frame and no MTU limit, so a Port
/// at MTU 9000 passes `Port::open`'s own checks and fails in
/// `rte_eth_dev_configure`, which refuses a 9018-byte frame (MTU + header +
/// FCS) above that maximum; the rollback frees both pools and the vdev then
/// removes cleanly. A bare server vdev, no client: `MemifVdev::open` keeps
/// pool rooms at memif's buffer size and would refuse these rooms first.
#[zhida_test_support::pinned_test]
fn memif_open_rejects_mtu_9000() {
    let names = names("jumbo");
    let args = CString::new(format!(
        "role=server,id=0,socket={},socket-abstract=yes,zero-copy=no",
        fresh_socket()
    ))
    .unwrap();
    with_eal(|eal| {
        assert_eq!(unsafe { rte_vdev_init(names.server.as_ptr(), args.as_ptr()) }, 0);
        let mut port_id = u16::MAX;
        assert_eq!(unsafe { rte_eth_dev_get_port_by_name(names.server.as_ptr(), &mut port_id) }, 0);
        let mut info: rte_eth_dev_info = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { rte_eth_dev_info_get(port_id, &mut info) }, 0);
        assert_eq!((info.max_rx_pktlen, info.max_mtu), (1518, u16::MAX));

        let mut config = config(port_id, &names.server_rx, &names.server_tx);
        config.mtu = 9000;
        for pool in [&mut config.rx_pool, &mut config.tx_pool] {
            pool.data_room_size = RTE_PKTMBUF_HEADROOM as u16 + 9216;
        }
        let error = unsafe { Port::open(eal, config) }.unwrap_err();
        assert_eq!(
            (error.cause, error.rollback_error, error.retained.is_none()),
            (PortError::Dpdk { operation: "rte_eth_dev_configure", code: -libc::EINVAL }, None, true)
        );
        for name in [&names.server_rx, &names.server_tx] {
            assert!(unsafe { rte_mempool_lookup(name.as_ptr()) }.is_null());
        }
        assert_eq!(unsafe { rte_vdev_uninit(names.server.as_ptr()) }, 0);
    });
}
