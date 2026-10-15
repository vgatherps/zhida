//! One receive batch per iteration, shared by the rx benches and rx_batch test.
//! A sends k in-order segments before the timer starts. For 1448-byte
//! payloads A writes the whole batch; smaller writes are sent separately.
//! The timer covers B's turn that receives them and sends one ACK, then the
//! application read of all k × seg bytes. The read looks up B's socket once and
//! drains it frame by frame: one lookup per batch, as the in-place read before
//! drain-only receive did, so the timer measures the drain, not per-frame handle
//! lookups. Forwarding and frame checks are untimed.
//! Copy reads check every byte after timing. Drain reads check every byte
//! during warmup and tests; measured reads check the stream offset, length,
//! and first and last byte of each frame before dropping it inside the timer.
//! Each iteration has a new payload seed. Setup verifies full batches with
//! checked, untimed copying reads. Both sockets use Cubic with the default
//! 1 MiB initial window and space for three batches of 1448-byte segments.
//! Draining returns every frame in order. A frame may contain several small
//! in-order segments copied into its tailroom.

use std::cell::Cell;
use std::time::{Duration, Instant};

use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::wire::{
    TcpControl, TcpSeqNumber, ETHERNET_HEADER_LEN, IPV4_HEADER_LEN, TCP_HEADER_LEN,
};
use dpdk_smoltcp::{rx_pool_count, rx_reserve};
use dpdk_smoltcp::{Eal, Turn};

use zhida_test_kit::many::{self, assert_quiet};
use zhida_test_kit::pair::{
    establish_sized, pattern, segment, App, Dir, Pair, Side, BUDGET, CLIENT_PORT, SERVER_PORT, T0,
};

/// Bytes per payload chunk in the benchmark.
pub(super) const MSS: usize = 1448;
const OFFERED_MSS: u16 = 1460;
const TCP_FLAGS: usize = 14 + 20 + 13;

#[derive(Clone, Copy)]
pub(super) enum Read {
    Copy,
    Drain,
}

impl Read {
    pub(super) fn name(self) -> &'static str {
        match self {
            Read::Copy => "copy",
            Read::Drain => "drain",
        }
    }
}

pub(super) fn setup(eal: &Eal, k: usize, buffer: usize) -> (Pair, [TcpHandle; 2]) {
    assert!(matches!(k, 1 | 8));
    let names = [format!("rx{k}a"), format!("rx{k}b")];
    let configs = [many::config(Side::A, 1), many::config(Side::B, 1)];
    let mut pair = Pair::with_ports(
        eal,
        [&names[0], &names[1]],
        configs,
        T0,
        16,
        |side, port| {
            port.rx_pool.count = rx_pool_count(
                rx_reserve(
                    port.rx_descriptors,
                    configs[side.index()].rx_staging,
                    port.rx_pool.cache_size,
                ),
                port.mtu,
                [buffer],
            );
        },
    );
    let (handles, frames) = establish_sized(&mut pair, Side::A, buffer);
    let syn_ack = segment(&frames[3].1, Side::B);
    assert_eq!(syn_ack.control, TcpControl::Syn);
    assert!(syn_ack.ack_number.is_some());
    assert_eq!(syn_ack.max_seg_size, Some(OFFERED_MSS));
    let ack = segment(&frames[4].1, Side::A);
    assert_eq!(ack.control, TcpControl::None);
    assert_eq!(ack.ack_number, Some(syn_ack.seq_number + 1));
    assert!(ack.payload.is_empty());
    let options = ack
        .header_len()
        .checked_sub(TCP_HEADER_LEN)
        .expect("TCP header");
    let send_mss = usize::from(syn_ack.max_seg_size.expect("SYN-ACK MSS"))
        .checked_sub(options)
        .expect("MSS includes room for TCP options");
    assert!(MSS <= send_mss, "payload chunk exceeds send MSS");
    for (stack, handle) in [(&mut pair.a, &handles[0]), (&mut pair.b, &handles[1])] {
        assert_eq!(handle.to_string(), "#0");
        stack.tcp_mut(&handle).set_ack_delay(None);
    }
    grow_window(&mut pair, &handles, k, send_mss);
    assert_quiet(&mut pair, &[]);
    (pair, handles)
}

fn assert_turn(turn: Turn, received: usize, sent: usize) {
    assert_eq!(
        turn,
        Turn {
            rx_received: received,
            rx_rejected: 0,
            rx_ipv4_checksum_bad: 0,
            rx_processed: received,
            rx_staged: 0,
            rx_blocked: false,
            tx_accepted: sent,
            tx_pending: 0,
        }
    );
}

fn check_data(frame: &[u8], payload: &[u8], last: bool) -> (TcpSeqNumber, TcpSeqNumber) {
    let tcp = segment(frame, Side::A);
    assert_eq!(tcp.timestamp, None);
    assert_eq!(tcp.header_len(), TCP_HEADER_LEN);
    assert_eq!(
        frame.len(),
        ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + tcp.header_len() + payload.len(),
        "A→B frame length"
    );
    assert_eq!(frame[TCP_FLAGS], if last { 0x18 } else { 0x10 });
    assert_eq!((tcp.src_port, tcp.dst_port), (CLIENT_PORT, SERVER_PORT));
    assert_eq!(
        tcp.control,
        if last {
            TcpControl::Psh
        } else {
            TcpControl::None
        }
    );
    assert!(tcp.ack_number.is_some(), "data frame has no ACK flag");
    assert_eq!(tcp.payload, payload);
    (tcp.seq_number, tcp.seq_number + payload.len())
}

fn check_ack(frame: &[u8], expected: TcpSeqNumber) {
    let tcp = segment(frame, Side::B);
    assert_eq!(tcp.timestamp, None);
    assert_eq!(tcp.header_len(), TCP_HEADER_LEN);
    assert_eq!(
        frame.len(),
        ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + tcp.header_len(),
        "B→A frame length: {frame:02x?}"
    );
    assert_eq!(frame[TCP_FLAGS], 0x10, "B→A TCP flags: {frame:02x?}");
    assert_eq!((tcp.src_port, tcp.dst_port), (SERVER_PORT, CLIENT_PORT));
    assert_eq!(tcp.control, TcpControl::None);
    assert!(
        tcp.payload.is_empty(),
        "ACK frame has payload: {frame:02x?}"
    );
    assert_eq!(tcp.ack_number, Some(expected), "B→A ACK: {frame:02x?}");
}

fn grow_window(pair: &mut Pair, handles: &[TcpHandle; 2], k: usize, send_mss: usize) {
    let [client, server] = handles;
    let batch = k.checked_mul(MSS).expect("batch bytes");
    let payload = pattern(batch, 0);
    let mut sink = vec![0; batch];
    let mut sent = 0usize;
    let mut received = 0usize;
    let mut ack = None;
    let full_segments = Cell::new(true);
    pair.drive_rounds(
        |dir, frame| match dir {
            Dir::AToB => {
                let len = segment(frame, Side::A).payload.len();
                assert!(len > 0 && len <= send_mss, "warmup data length");
                full_segments.set(full_segments.get() && len == send_mss.min(batch - sent));
                let end = sent.checked_add(len).expect("warmup sent bytes");
                let (seq, next) = check_data(frame, &payload[sent..end], end == batch);
                if let Some(expected) = ack {
                    assert_eq!(seq, expected, "warmup data sequence");
                }
                ack = Some(next);
                sent = end % batch;
            }
            Dir::BToA => check_ack(frame, ack.expect("warmup data before ACK")),
        },
        |round, a, b| {
            let mut read = 0usize;
            while b.tcp(&server).recv_queue() > 0 {
                let frame = b.tcp_mut(&server).recv().unwrap().unwrap();
                let len = frame.payload().len();
                sink[..len].copy_from_slice(frame.payload());
                assert!(len > 0, "warmup read made no progress");
                for &byte in &sink[..len] {
                    assert_eq!(byte, payload[received % batch]);
                    received = received.checked_add(1).expect("warmup received bytes");
                }
                read = read.checked_add(len).expect("warmup round bytes");
            }
            let queued = a.tcp(&client).send_queue();
            let full = full_segments.replace(true);
            let steady = round.a_to_b == k && full && read == batch && queued == batch;
            if steady {
                assert_eq!(round.b_to_a, 1, "warmup B→A ACK count");
                assert_turn(round.b, k, 1);
                return App::Done;
            }
            if queued == 0 {
                assert_eq!(a.tcp_mut(&client).send_slice(&payload), Ok(batch));
                App::Moved
            } else if read > 0 {
                App::Moved
            } else {
                App::Idle
            }
        },
    );
    assert_eq!(sent, 0);
    assert_eq!(received % batch, 0);
    let now = pair.now();
    assert_turn(pair.a.turn(now, BUDGET).unwrap(), 1, 0);
    assert_empty(pair, &handles);
}

pub(super) fn iteration(
    pair: &mut Pair,
    handles: &[TcpHandle; 2],
    style: Read,
    seg: usize,
    payload: &[u8],
    sink: &mut [u8],
    full_check: bool,
    steady_checks: bool,
) -> (Duration, usize) {
    let [client, server] = handles;
    assert!(seg > 0 && seg <= MSS, "segment payload length");
    let k = payload.len() / seg;
    assert_eq!(payload.len(), k.checked_mul(seg).expect("batch bytes"));
    assert_eq!(sink.len(), payload.len());
    let now = pair.now();
    if seg == MSS {
        assert_eq!(
            pair.a.tcp_mut(&client).send_slice(payload),
            Ok(payload.len())
        );
        assert_turn(pair.a.turn(now, BUDGET).unwrap(), 0, k);
    } else {
        for bytes in payload.chunks_exact(seg) {
            assert_eq!(pair.a.tcp_mut(&client).send_slice(bytes), Ok(seg));
            assert_turn(pair.a.turn(now, BUDGET).unwrap(), 0, 1);
        }
    }
    let mut offset = 0usize;
    let mut ack = None;
    let count = pair.a_to_b.forward_with(|frame| {
        let tcp = segment(frame, Side::A);
        let len = tcp.payload.len();
        assert!(len > 0, "empty data frame");
        if seg < MSS {
            assert_eq!(len, seg, "one frame per application write");
        } else {
            let options = tcp
                .header_len()
                .checked_sub(TCP_HEADER_LEN)
                .expect("TCP header");
            let send_mss = usize::from(OFFERED_MSS)
                .checked_sub(options)
                .expect("MSS includes room for TCP options");
            let remaining = payload.len().checked_sub(offset).expect("batch bytes left");
            assert_eq!(len, send_mss.min(remaining), "full data segment or batch tail");
        }
        let end = offset.checked_add(len).expect("data frame offset");
        let (seq, next) = check_data(
            frame,
            &payload[offset..end],
            seg < MSS || end == payload.len(),
        );
        if let Some(expected) = ack {
            assert_eq!(seq, expected, "in-order data sequence");
        }
        ack = Some(next);
        offset = end;
    });
    assert_eq!(count, k, "A→B frame count");
    assert_eq!(offset, payload.len());
    if steady_checks {
        assert_eq!(pair.in_use()[1].1, 0, "B TX pool before turn");
    }
    let mut offset = 0usize;
    let mut reads = 0usize;
    let mut valid = true;
    let start = Instant::now();
    let turn = pair.b.turn(now, BUDGET);
    let socket = pair.b.tcp_mut(&server);
    while let Some(frame) = socket.recv().unwrap() {
        let bytes = frame.payload();
        let len = bytes.len();
        assert!(len > 0, "application read made no progress");
        let end = offset.checked_add(len).expect("application read offset");
        assert!(end <= payload.len(), "application read exceeds batch");
        match style {
            Read::Copy => sink[offset..end].copy_from_slice(bytes),
            Read::Drain => {
                valid &= if full_check {
                    bytes == &payload[offset..end]
                } else {
                    bytes[0] == payload[offset] && bytes[len - 1] == payload[end - 1]
                };
            }
        }
        offset = end;
        reads = reads.checked_add(1).expect("application read count");
    }
    let elapsed = start.elapsed();
    assert_turn(turn.unwrap(), k, 1);
    assert_eq!(offset, payload.len());
    match style {
        Read::Copy => assert_eq!(sink, payload),
        Read::Drain => assert!(valid, "drained payload differs"),
    }
    let expected = ack.expect("data frames");
    let count = pair.b_to_a.forward_with(|frame| check_ack(frame, expected));
    assert_eq!(count, 1, "B→A frame count");
    assert_turn(pair.a.turn(now, BUDGET).unwrap(), 1, 0);
    assert_eq!(pair.a_to_b.forward(), 0, "extra A→B frame after ACK");
    if steady_checks {
        assert_eq!(pair.a.poll_at(), None, "A deadline after ACK");
        assert_eq!(pair.b.poll_at(), None, "B deadline after application read");
    }
    assert_empty(pair, &handles);
    (elapsed, reads)
}

fn assert_empty(pair: &Pair, handles: &[TcpHandle; 2]) {
    for (stack, handle) in [(&pair.a, &handles[0]), (&pair.b, &handles[1])] {
        let socket = stack.tcp(&handle);
        assert_eq!((socket.send_queue(), socket.recv_queue()), (0, 0));
    }
}

pub(super) fn close(pair: Pair) {
    for link in [&pair.a_to_b, &pair.b_to_a] {
        assert_eq!((link.pool_empty, link.ring_full, link.dropped), (0, 0, 0));
    }
    assert_eq!(pair.close(), 0);
}
