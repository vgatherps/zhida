//! Two stacks over impaired copying links: timers on the supplied clock, loss,
//! reordering, RST, FIN drain, TIME-WAIT, minimal pools and a paused wire.

use zhida_test_kit::pair::drain_bytes;
use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::socket::tcp::{RecvError, SendError, State};
use dpdk_smoltcp::smoltcp::time::Duration;
use dpdk_smoltcp::smoltcp::wire::{TcpControl, TcpSeqNumber};
use dpdk_smoltcp::{rx_pool_count, rx_reserve, tx_reserve};
use dpdk_smoltcp::{Stack, StackConfig, StackError, Turn};

use zhida_test_kit::ring_port::RingPort;
use zhida_test_kit::{pair, wire, with_eal};
use pair::{
    assert_lossless, ceil_ms, config, establish, establish_sized, new_pair, pattern, segment, App, Dir,
    Pair, Round, Side, T0,
};
use wire::{Link, Verdict};

/// Upstream `ACK_DELAY_DEFAULT`.
const ACK_DELAY: Duration = Duration::from_millis(10);
/// Default socket RTO.
const RTO: Duration = Duration::from_millis(300);
/// Upstream TIME-WAIT duration (`CLOSE_DELAY`).
const TIME_WAIT: Duration = Duration::from_millis(10_000);

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
fn pair_loss_reorder_mixed_sizes() {
    with_eal(|eal| {
        const CAPACITY: usize = 4096;
        let configs = [config(Side::A), config(Side::B)];
        let pool_count = rx_pool_count(rx_reserve(16, configs[0].rx_staging, 8), 1500, [CAPACITY]);
        let mut pair =
            Pair::with_ports(eal, ["mixlossa", "mixlossb"], configs, T0, 16, |_, port| {
                port.rx_pool.count = pool_count;
            });
        let (handles, _) = establish_sized(&mut pair, Side::A, CAPACITY);
        pair.b.tcp_mut(&handles[1]).set_ack_delay(None);
        let mut frames = 0;
        pair.a_to_b.impair(move |frame| {
            if segment(frame, Side::A).payload.is_empty() {
                return Verdict::Deliver;
            }
            frames += 1;
            match frames {
                1 => Verdict::Drop,
                2 => Verdict::Hold,
                _ => Verdict::Deliver,
            }
        });
        let lengths: Vec<_> = (1..=724).flat_map(|len| [len, 1449 - len]).collect();
        let data = pattern(lengths.iter().sum(), 93);
        let mut written = 0usize;
        let mut received = Vec::new();
        let mut pending = None;
        let mut delivered = Vec::new();
        for batch in lengths.chunks(4) {
            for &len in batch {
                let end = written.checked_add(len).expect("written bytes fit usize");
                assert_eq!(
                    pair.a.tcp_mut(&handles[0]).send_slice(&data[written..end]),
                    Ok(len)
                );
                written = end;
                pair.round(|dir, frame| {
                    if dir == Dir::AToB {
                        let tcp = segment(frame, Side::A);
                        if !tcp.payload.is_empty() {
                            delivered.push(tcp.seq_number);
                        }
                    }
                });
            }
            pair.drive(
                |dir, frame| {
                    if dir == Dir::AToB {
                        let tcp = segment(frame, Side::A);
                        if !tcp.payload.is_empty() {
                            delivered.push(tcp.seq_number);
                        }
                    }
                },
                |a, b| {
                    let mut bytes = [0; 257];
                    let mut read = 0usize;
                    while read < bytes.len() {
                        if pending.is_none() {
                            if !b.tcp_mut(&handles[1]).can_recv() { break; }
                            let Some(frame) = b.tcp_mut(&handles[1]).recv().unwrap() else { break; };
                            pending = Some((frame, 0));
                        }
                        let (frame, offset) = pending.as_mut().unwrap();
                        let n = (bytes.len() - read).min(frame.payload().len() - *offset);
                        bytes[read..read + n].copy_from_slice(&frame.payload()[*offset..*offset + n]);
                        *offset = offset.checked_add(n).expect("frame offset exceeds usize");
                        read = read.checked_add(n).expect("read count exceeds usize");
                        if *offset == frame.payload().len() {
                            pending = None;
                        }
                    }
                    received.extend_from_slice(&bytes[..read]);
                    if received.len() == written && a.tcp(&handles[0]).send_queue() == 0 {
                        App::Done
                    } else if read > 0 {
                        App::Moved
                    } else {
                        App::Idle
                    }
                },
            );
        }
        assert_eq!(written, data.len());
        assert_eq!(received, data);
        assert!(delivered.windows(2).any(|seq| seq[1] < seq[0]));
        assert_eq!(counts(&pair.a_to_b), (0, 0, 1, 1));
        assert_eq!(counts(&pair.b_to_a), (0, 0, 0, 0));
        pair.round(|_, _| {});
        pair.round(|_, _| {});
        assert_eq!(pair.in_use().map(|(rx, _)| rx), [0, 0]);
        exhaust_rx_pool(c"mixlossa_rxp", pool_count);
        exhaust_rx_pool(c"mixlossb_rxp", pool_count);
        assert_eq!(pair.close(), 0);
    });
}

/// (pool_empty, ring_full, dropped, held).
fn counts(link: &Link) -> (u64, u64, u64, u64) {
    (link.pool_empty, link.ring_full, link.dropped, link.held)
}

/// One delivered TCP segment, as the tests compare them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seg {
    dir: Dir,
    seq: TcpSeqNumber,
    ack: Option<TcpSeqNumber>,
    control: TcpControl,
    len: usize,
}

fn seg(dir: Dir, seq: TcpSeqNumber, ack: TcpSeqNumber, control: TcpControl, len: usize) -> Seg {
    Seg {
        dir,
        seq,
        ack: Some(ack),
        control,
        len,
    }
}

fn segs(frames: &[(Dir, Vec<u8>)]) -> Vec<Seg> {
    frames
        .iter()
        .map(|(dir, frame)| {
            let src = match dir {
                Dir::AToB => Side::A,
                Dir::BToA => Side::B,
            };
            let tcp = segment(frame, src);
            Seg {
                dir: *dir,
                seq: tcp.seq_number,
                ack: tcp.ack_number,
                control: tcp.control,
                len: tcp.payload.len(),
            }
        })
        .collect()
}

/// A connects to B; returns the handles and the next sequence numbers of A
/// and B, read off A's final handshake ACK.
fn connect(pair: &mut Pair) -> ([TcpHandle; 2], TcpSeqNumber, TcpSeqNumber) {
    let (handles, frames) = establish(pair, Side::A);
    let ack = segs(&frames[frames.len() - 1..])[0];
    assert_eq!((ack.dir, ack.control, ack.len), (Dir::AToB, TcpControl::None, 0));
    (handles, ack.seq, ack.ack.unwrap())
}

/// Drive until `done`, writing `data` from A once in the first app step;
/// returns the delivered frames.
fn write_once_until(
    pair: &mut Pair,
    handles: &[TcpHandle; 2],
    data: &[u8],
    mut done: impl FnMut(&mut Stack, &mut Stack) -> bool,
) -> Vec<(Dir, Vec<u8>)> {
    let mut frames = Vec::new();
    let mut written = false;
    pair.drive(
        |dir, frame| frames.push((dir, frame.to_vec())),
        |a, b| {
            if !written {
                assert_eq!(a.tcp_mut(&handles[0]).send_slice(data), Ok(data.len()));
                written = true;
                App::Moved
            } else if done(a, b) {
                App::Done
            } else {
                App::Idle
            }
        },
    );
    frames
}

/// Drive with an idle app until `done`; returns the delivered frames.
fn until(
    pair: &mut Pair,
    mut done: impl FnMut(&mut Stack, &mut Stack) -> bool,
) -> Vec<(Dir, Vec<u8>)> {
    let mut frames = Vec::new();
    pair.drive(
        |dir, frame| frames.push((dir, frame.to_vec())),
        |a, b| if done(a, b) { App::Done } else { App::Idle },
    );
    frames
}

/// Read everything B holds, checking it equals `expected`, then that nothing
/// more is there.
fn assert_b_reads(pair: &mut Pair, handles: &[TcpHandle; 2], expected: &[u8]) {
    let socket = pair.b.tcp_mut(&handles[1]);
    let buffer = drain_bytes(socket).unwrap();
    assert_eq!(buffer.len(), expected.len());
    assert!(buffer[..expected.len()] == *expected, "received bytes differ");
    assert!(socket.recv().unwrap().is_none());
}

fn assert_clean(pair: &Pair) {
    assert_eq!(counts(&pair.a_to_b), (0, 0, 0, 0));
    assert_eq!(counts(&pair.b_to_a), (0, 0, 0, 0));
}

/// The links lost frames only to a full RX ring, and at least one did.
fn assert_ring_overflowed(links: &[&Link]) {
    let mut ring_full = 0;
    for link in links {
        let (pool_empty, full, dropped, held) = counts(link);
        assert_eq!((pool_empty, dropped, held), (0, 0, 0));
        ring_full += full;
    }
    assert!(ring_full > 0, "no RX ring overflow");
}

#[zhida_test_support::pinned_test]
fn clock_advances_to_deadline_for_delayed_ack() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["dacka", "dackb"]);
        let (handles, a_seq, b_seq) = connect(&mut pair);
        let t = pair.now();

        let frames = write_once_until(&mut pair, &handles, b"hello", |_, b| {
            b.tcp(&handles[1]).recv_queue() == 5
        });
        assert_eq!(pair.now(), t);
        assert_eq!(segs(&frames), [seg(Dir::AToB, a_seq, b_seq, TcpControl::Psh, 5)]);
        // B's only deadline is the delayed ACK; A's is the retransmission.
        assert!(matches!(pair.b.poll_at(), Some(p) if p > t && p <= ceil_ms(t + ACK_DELAY)));
        assert!(matches!(pair.a.poll_at(), Some(p) if p > t && p <= ceil_ms(t + RTO)));

        // One microsecond before the deadline: nothing is sent.
        let early = pair.round_at(t + ACK_DELAY - Duration::from_micros(1), |dir, _| {
            panic!("{dir:?} frame before the delayed-ACK deadline")
        });
        assert_eq!((early.a_to_b, early.b_to_a), (0, 0));
        assert_eq!(pair.a.tcp(&handles[0]).send_queue(), 5);

        // Done as soon as A holds the ACK: had B sent it before the deadline,
        // the drive would end before it.
        let frames = until(&mut pair, |a, _| a.tcp(&handles[0]).send_queue() == 0);
        assert_eq!(pair.now(), ceil_ms(t + ACK_DELAY));
        assert_eq!(segs(&frames), [seg(Dir::BToA, b_seq, a_seq + 5, TcpControl::None, 0)]);
        assert_b_reads(&mut pair, &handles, b"hello");
        assert_clean(&pair);
        assert_eq!(pair.close(), 0);
    });
}

/// Drops the first A→B frame carrying payload.
fn drop_first_data(link: &mut Link) {
    let mut dropped = false;
    link.impair(move |frame| {
        if !dropped && !segment(frame, Side::A).payload.is_empty() {
            dropped = true;
            Verdict::Drop
        } else {
            Verdict::Deliver
        }
    });
}

#[zhida_test_support::pinned_test]
fn dropped_data_segment_retransmitted_deadline_only() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["ddsa", "ddsb"]);
        let (handles, a_seq, b_seq) = connect(&mut pair);
        let t = pair.now();
        drop_first_data(&mut pair.a_to_b);
        let data = pattern(1000, 3);

        // The segment sent at `t` is lost and nothing else crosses the wire,
        // so only the clock reaching A's RTO deadline brings the retransmission.
        let frames = write_once_until(&mut pair, &handles, &data, |_, b| {
            b.tcp(&handles[1]).recv_queue() != 0
        });
        assert_eq!(pair.now(), t + RTO);
        assert_eq!(segs(&frames), [seg(Dir::AToB, a_seq, b_seq, TcpControl::Psh, 1000)]);
        assert_eq!(counts(&pair.a_to_b), (0, 0, 1, 0));

        let frames = until(&mut pair, |a, _| a.tcp(&handles[0]).send_queue() == 0);
        assert_eq!(pair.now(), t + RTO + ACK_DELAY);
        assert_eq!(segs(&frames), [seg(Dir::BToA, b_seq, a_seq + 1000, TcpControl::None, 0)]);
        assert_b_reads(&mut pair, &handles, &data);
        assert_eq!(counts(&pair.a_to_b), (0, 0, 1, 0));
        assert_eq!(counts(&pair.b_to_a), (0, 0, 0, 0));
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn wan_tail_loss_delivers_exact_bytes() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["wtla", "wtlb"]);
        let (handles, a_seq, b_seq) = connect(&mut pair);
        let data = pattern(2000, 17);
        let tail_seq = a_seq + 1460;
        let mut dropped = false;
        pair.a_to_b.impair(move |frame| {
            let tcp = segment(frame, Side::A);
            if !dropped && tcp.seq_number == tail_seq && !tcp.payload.is_empty() {
                dropped = true;
                Verdict::Drop
            } else {
                Verdict::Deliver
            }
        });
        let sent_at = pair.now();
        pair.a_to_b.paused = true;
        assert_eq!(pair.a.tcp_mut(&handles[0]).send_slice(&data), Ok(data.len()));
        for _ in 0..2 {
            pair.round(|dir, _| panic!("{dir:?} frame on paused wire"));
        }
        pair.a_to_b.paused = false;
        let delivered_at = sent_at + Duration::from_millis(40);
        let mut frames = Vec::new();
        pair.round_at(delivered_at, |dir, frame| frames.push((dir, frame.to_vec())));
        assert_eq!(segs(&frames), [seg(Dir::AToB, a_seq, b_seq, TcpControl::None, 1460)]);
        assert_eq!(pair.b.tcp(&handles[1]).recv_queue(), 1460);
        assert_eq!(counts(&pair.a_to_b), (0, 0, 1, 0));

        // poll_at is a lower bound: it can report timer-wheel boundaries at
        // which nothing is due, so each sender is turned at its poll_at times
        // up to the exact deadline, and must send then and not before.
        let ack_at = delivered_at + ACK_DELAY;
        assert_eq!(pair.turn_until_sent(Side::B, ack_at).tx_accepted, 1);
        assert_eq!(pair.now(), ack_at);
        let mut frames = Vec::new();
        assert_eq!(pair.b_to_a.forward_with(|frame| frames.push((Dir::BToA, frame.to_vec()))), 1);
        assert_eq!(segs(&frames), [seg(Dir::BToA, b_seq, tail_seq, TcpControl::None, 0)]);
        pair.round(|dir, _| panic!("{dir:?} frame while accepting partial ACK"));
        assert_eq!(pair.a.tcp(&handles[0]).send_queue(), 540);

        // The partial ACK restarted A's retransmission timer: the tail leaves
        // one RTO after it.
        let retransmit_at = ack_at + RTO;
        let early = pair.round_at(retransmit_at - Duration::from_micros(1), |dir, _| {
            panic!("{dir:?} frame before the retransmission deadline")
        });
        assert_eq!(early.a.tx_accepted, 0);
        assert_eq!((early.a_to_b, early.b_to_a), (0, 0));
        assert_eq!(pair.turn_until_sent(Side::A, retransmit_at).tx_accepted, 1);
        assert_eq!(pair.now(), retransmit_at);
        let mut frames = Vec::new();
        assert_eq!(pair.a_to_b.forward_with(|frame| frames.push((Dir::AToB, frame.to_vec()))), 1);
        assert_eq!(segs(&frames), [seg(Dir::AToB, tail_seq, b_seq, TcpControl::Psh, 540)]);
        assert_eq!(segment(&frames[0].1, Side::A).payload, &data[1460..]);
        let frames = until(&mut pair, |a, _| a.tcp(&handles[0]).send_queue() == 0);
        assert_eq!(pair.now(), retransmit_at + ACK_DELAY);
        assert_eq!(segs(&frames), [seg(Dir::BToA, b_seq, a_seq + 2000, TcpControl::None, 0)]);
        assert_b_reads(&mut pair, &handles, &data);
        assert_eq!(counts(&pair.a_to_b), (0, 0, 1, 0));
        assert_eq!(counts(&pair.b_to_a), (0, 0, 0, 0));
        assert_eq!(pair.close(), 0);
    });
}

/// After an RTO, A resends one full 1460-byte segment without a runt.
#[zhida_test_support::pinned_test]
fn rto_retransmission_is_one_full_segment() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["rtoka", "rtokb"]);
        let (handles, a_seq, b_seq) = connect(&mut pair);
        let t = pair.now();
        // TCP_NODELAY: both segments of the first flight leave at once.
        let mut dropped = 0;
        pair.a_to_b.impair(move |frame| {
            if dropped < 2 && !segment(frame, Side::A).payload.is_empty() {
                dropped += 1;
                Verdict::Drop
            } else {
                Verdict::Deliver
            }
        });
        assert_eq!(pair.a.tcp_mut(&handles[0]).send_slice(&pattern(2000, 13)), Ok(2000));
        pair.round(|dir, _| panic!("{dir:?} frame delivered before the RTO"));
        assert_eq!(counts(&pair.a_to_b), (0, 0, 2, 0));
        assert!(matches!(pair.a.poll_at(), Some(p) if p > t && p <= ceil_ms(t + RTO)));

        let mut frames = Vec::new();
        pair.round_at(ceil_ms(t + RTO), |dir, frame| {
            if dir == Dir::AToB {
                frames.push((dir, frame.to_vec()));
            }
        });
        assert_eq!(segs(&frames), [seg(Dir::AToB, a_seq, b_seq, TcpControl::None, 1460)]);
        // B's ACK of the one in-order segment waits for its delayed-ACK deadline.
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn dropped_ack_recovered() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["dacka2", "dackb2"]);
        let (handles, a_seq, b_seq) = connect(&mut pair);
        let t = pair.now();
        let mut dropped = false;
        pair.b_to_a.impair(move |frame| {
            let tcp = segment(frame, Side::B);
            if !dropped && tcp.payload.is_empty() && tcp.control == TcpControl::None {
                dropped = true;
                Verdict::Drop
            } else {
                Verdict::Deliver
            }
        });
        let data = pattern(1000, 4);

        // B's delayed ACK at t + 10 ms is lost; A retransmits at its RTO and B
        // answers the duplicate segment with an immediate ACK.
        let frames = write_once_until(&mut pair, &handles, &data, |a, _| {
            a.tcp(&handles[0]).send_queue() == 0
        });
        assert_eq!(pair.now(), t + RTO);
        let data_segment = seg(Dir::AToB, a_seq, b_seq, TcpControl::Psh, 1000);
        assert_eq!(
            segs(&frames),
            [
                data_segment,
                data_segment,
                seg(Dir::BToA, b_seq, a_seq + 1000, TcpControl::None, 0),
            ]
        );
        assert_eq!(counts(&pair.b_to_a), (0, 0, 1, 0));
        assert_eq!(counts(&pair.a_to_b), (0, 0, 0, 0));
        assert_b_reads(&mut pair, &handles, &data);
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn reordered_segments_delivered_in_order() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["rsda", "rsdb"]);
        let (handles, a_seq, b_seq) = connect(&mut pair);
        let t = pair.now();
        // TCP_NODELAY: the 540-byte remainder follows the first 1460-byte
        // segment immediately, so both are in flight together.
        let mut held = false;
        pair.a_to_b.impair(move |frame| {
            if !held && !segment(frame, Side::A).payload.is_empty() {
                held = true;
                Verdict::Hold
            } else {
                Verdict::Deliver
            }
        });
        let data = pattern(2000, 5);

        let frames = write_once_until(&mut pair, &handles, &data, |a, b| {
            a.tcp(&handles[0]).send_queue() == 0 && b.tcp(&handles[1]).recv_queue() == 2000
        });
        assert_eq!(pair.now(), t);
        assert_eq!(
            segs(&frames),
            [
                seg(Dir::AToB, a_seq + 1460, b_seq, TcpControl::Psh, 540),
                seg(Dir::AToB, a_seq, b_seq, TcpControl::None, 1460),
                // Out of order: immediate duplicate ACK.
                seg(Dir::BToA, b_seq, a_seq, TcpControl::None, 0),
                // Gap filled: immediate ACK of both.
                seg(Dir::BToA, b_seq, a_seq + 2000, TcpControl::None, 0),
            ]
        );
        assert_eq!(counts(&pair.a_to_b), (0, 0, 0, 1));
        assert_eq!(counts(&pair.b_to_a), (0, 0, 0, 0));
        assert_b_reads(&mut pair, &handles, &data);
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn close_frees_held_and_ring_frames() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["cfa", "cfb"]);
        let (handles, _, _) = connect(&mut pair);
        // TCP_NODELAY: "c" goes out while "a" is unacknowledged.
        pair.a_to_b.paused = true;
        pair.b_to_a.impair(|_| Verdict::Hold);
        assert_eq!(pair.a.tcp_mut(&handles[0]).send_slice(b"a"), Ok(1));
        assert_eq!(pair.b.tcp_mut(&handles[1]).send_slice(b"b"), Ok(1));
        let round = pair.round(|_, _| panic!("nothing is delivered"));
        assert_eq!((round.a_to_b, round.b_to_a), (0, 1));
        assert_eq!(counts(&pair.b_to_a), (0, 0, 0, 1));

        // A's first segment onto B's RX ring, its second onto A's TX ring.
        pair.a_to_b.paused = false;
        assert_eq!(pair.a_to_b.forward(), 1);
        assert_eq!(pair.a.tcp_mut(&handles[0]).send_slice(b"c"), Ok(1));
        assert_eq!(pair.a.turn(pair.now(), 32).unwrap().tx_accepted, 1);
        // A: B's held segment in its RX pool, its own on its TX ring. B: A's
        // first segment on its RX ring.
        assert_eq!(pair.in_use(), [(1, 1), (1, 0)]);
        // The held copy and one frame on each of two rings.
        assert_eq!(pair.close(), 3);
    });
}

#[zhida_test_support::pinned_test]
fn rst_on_abort_closes_peer() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["rsta", "rstb"]);
        let (handles, a_seq, b_seq) = connect(&mut pair);
        let t = pair.now();

        let mut aborted = false;
        let mut frames = Vec::new();
        pair.drive(
            |dir, frame| frames.push((dir, frame.to_vec())),
            |a, b| {
                if !aborted {
                    a.tcp_mut(&handles[0]).abort();
                    assert_eq!(a.tcp(&handles[0]).state(), State::Closed);
                    aborted = true;
                    App::Moved
                } else if b.tcp(&handles[1]).state() == State::Closed {
                    App::Done
                } else {
                    App::Idle
                }
            },
        );
        assert_eq!(pair.now(), t);
        // One RST, unanswered.
        assert_eq!(segs(&frames), [seg(Dir::AToB, a_seq, b_seq, TcpControl::Rst, 0)]);
        // Upstream: a reset socket with nothing buffered reports InvalidState
        // (not Finished: no FIN was received) for recv and send.
        let socket = pair.b.tcp_mut(&handles[1]);
        assert!(matches!(socket.recv(), Err(RecvError::InvalidState)));
        assert_eq!(socket.send_slice(b"x"), Err(SendError::InvalidState));
        assert_eq!((pair.a.poll_at(), pair.b.poll_at()), (None, None));
        assert_clean(&pair);
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn data_then_close_drains_before_finished() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["fina", "finb"]);
        let (handles, _, _) = connect(&mut pair);
        let data = pattern(3000, 6);

        let mut closed = false;
        pair.drive(
            |_, _| {},
            |a, b| {
                if !closed {
                    let socket = a.tcp_mut(&handles[0]);
                    assert_eq!(socket.send_slice(&data), Ok(data.len()));
                    socket.close();
                    assert_eq!(
                        (socket.state(), socket.send_queue()),
                        (State::FinWait1, data.len())
                    );
                    closed = true;
                    App::Moved
                // Data and FIN fit the first flight, so B's ACK of the FIN is
                // still in flight when B reaches CloseWait: wait for A to take it.
                } else if b.tcp(&handles[1]).state() == State::CloseWait
                    && a.tcp(&handles[0]).state() == State::FinWait2
                {
                    App::Done
                } else {
                    App::Idle
                }
            },
        );
        // B has the FIN and every byte, none read yet.
        assert_eq!(pair.b.tcp(&handles[1]).recv_queue(), data.len());

        let socket = pair.b.tcp_mut(&handles[1]);
        let mut read = Vec::new();
        let error = loop {
            match socket.recv() {
                Ok(Some(frame)) => {
                    let mut offset = 0;
                    let mut buffer = [0; 700];
                    while offset < frame.payload().len() {
                        let count = buffer.len().min(frame.payload().len() - offset);
                        assert!(count > 0);
                        buffer[..count].copy_from_slice(&frame.payload()[offset..offset + count]);
                        read.extend_from_slice(&buffer[..count]);
                        offset = offset.checked_add(count).expect("frame offset exceeds usize");
                    }
                }
                Ok(None) => panic!("FIN socket still has buffered bytes"),
                Err(error) => break error,
            }
        };
        assert_eq!((read.len(), error), (data.len(), RecvError::Finished));
        assert!(read == data, "received bytes differ");
        assert_clean(&pair);
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn time_wait_expires_from_supplied_time() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["twa", "twb"]);
        let (handles, _, _) = connect(&mut pair);

        // A closes, B closes on seeing the FIN; done when A enters TIME-WAIT,
        // which its turn at the start of this round did.
        let mut closed = [false; 2];
        let mut frames = Vec::new();
        pair.drive(
            |dir, frame| frames.push((dir, frame.to_vec())),
            |a, b| {
                let (a, b) = (a.tcp_mut(&handles[0]), b.tcp_mut(&handles[1]));
                if !closed[0] {
                    a.close();
                    closed[0] = true;
                    App::Moved
                } else if !closed[1] && b.state() == State::CloseWait {
                    b.close();
                    closed[1] = true;
                    App::Moved
                } else if a.state() == State::TimeWait {
                    App::Done
                } else {
                    App::Idle
                }
            },
        );
        let entered = pair.now();
        let deadline = entered + TIME_WAIT;
        // Upstream starts the delayed-ACK timer only for payload, so A ACKed
        // B's bare FIN in the turn that entered TIME-WAIT, and B closed.
        let log = segs(&frames);
        let fin = |dir| *log.iter().find(|s| s.dir == dir && s.control == TcpControl::Fin).unwrap();
        let (a_fin, b_fin) = (fin(Dir::AToB), fin(Dir::BToA));
        assert_eq!(
            log.last(),
            Some(&seg(Dir::AToB, a_fin.seq + 1, b_fin.seq + 1, TcpControl::None, 0))
        );
        assert_eq!(pair.b.tcp(&handles[1]).state(), State::Closed);
        assert!(matches!(pair.a.poll_at(), Some(p) if p > entered && p <= ceil_ms(deadline)));
        assert_eq!(pair.b.poll_at(), None);

        // One microsecond before the deadline A is still in TimeWait.
        let early = pair.round_at(deadline - Duration::from_micros(1), |dir, _| {
            panic!("{dir:?} frame in TIME-WAIT")
        });
        assert_eq!((early.a_to_b, early.b_to_a), (0, 0));
        assert_eq!(pair.a.tcp(&handles[0]).state(), State::TimeWait);

        // The only deadline is TIME-WAIT's: one idle round still in TimeWait,
        // then the clock jumps there and A closes silently.
        let mut states = Vec::new();
        let frames = until(&mut pair, |a, _| {
            let state = a.tcp(&handles[0]).state();
            states.push(state);
            state == State::Closed
        });
        assert_eq!(states, [State::TimeWait, State::Closed]);
        assert_eq!(pair.now(), ceil_ms(deadline));
        assert!(frames.is_empty());
        assert_eq!(pair.a.poll_at(), None);
        assert_clean(&pair);
        assert_eq!(pair.close(), 0);
    });
}

/// Bulk socket buffers each way.
const BULK: usize = 64 * 1024;

/// Turn reports over the rounds of a bulk transfer, per side.
#[derive(Debug, Default)]
struct Pressure {
    rx_blocked: [usize; 2],
    max_tx_pending: [usize; 2],
}

impl Pressure {
    fn record(&mut self, round: &Round) {
        for (i, turn) in [round.a, round.b].iter().enumerate() {
            self.rx_blocked[i] += usize::from(turn.rx_blocked);
            self.max_tx_pending[i] = self.max_tx_pending[i].max(turn.tx_pending);
        }
    }
}

/// Everything each side can read now, appended; whether anything was.
fn read_all(
    a: &mut Stack,
    b: &mut Stack,
    handles: &[TcpHandle; 2],
    received: &mut [Vec<u8>; 2],
) -> bool {
    let mut moved = false;
    for (i, stack) in [a, b].into_iter().enumerate() {
        let socket = stack.tcp_mut(&handles[i]);
        let bytes = drain_bytes(socket).unwrap();
        moved |= !bytes.is_empty();
        received[i].extend_from_slice(&bytes);
    }
    moved
}

/// Both sides keep their send buffers full with `data` and read what
/// arrives, under `drive_rounds` (its round cap and clock rule), recording
/// every round's Turns until both have everything.
fn bulk(pair: &mut Pair, handles: &[TcpHandle; 2], data: &[Vec<u8>; 2]) -> ([Vec<u8>; 2], Pressure) {
    let mut sent = [0; 2];
    let mut received = [Vec::new(), Vec::new()];
    let mut pressure = Pressure::default();
    pair.drive_rounds(
        |_, _| {},
        |round, a, b| {
            pressure.record(round);
            let mut moved = false;
            for (i, stack) in [&mut *a, &mut *b].into_iter().enumerate() {
                let wrote = stack.tcp_mut(&handles[i]).send_slice(&data[i][sent[i]..]).unwrap();
                sent[i] += wrote;
                moved |= wrote > 0;
            }
            moved |= read_all(a, b, &handles, &mut received);
            if received[0].len() == data[1].len() && received[1].len() == data[0].len() {
                App::Done
            } else if moved {
                App::Moved
            } else {
                App::Idle
            }
        },
    );
    (received, pressure)
}

#[zhida_test_support::pinned_test]
fn bidirectional_bulk_with_minimal_pools_no_deadlock() {
    with_eal(|eal| {
        // The TX pool covers 16 descriptors and Q = 16 pending slots: 32 mbufs.
        // The RX pool is the smallest admission accepts for one 64 KiB socket.
        // Q = 16: measured, Q <= 8 never overflows a receiver's RX ring (a
        // sender's turn then fits in the ring, the receiver drains at most an
        // 8-frame burst per turn) and nothing stays pending; Q >= 9 does.
        // S = 1 is excluded: measured at Q = 16 with an 18-mbuf RX pool,
        // both directions complete but no turn ends with frames pending (max_tx_pending
        // [0, 0], 3 of 3 runs), so the pending assertion below cannot hold.
        const Q: usize = 16;
        const S: usize = 8;
        let sized = |side| StackConfig {
            max_udp_sockets: 0,
            rx_staging: S,
            tx_pending: Q,
            ..config(side)
        };
        let mut pair = Pair::with_pools(
            eal,
            ["blka", "blkb"],
            [sized(Side::A), sized(Side::B)],
            T0,
            16,
            rx_pool_count(rx_reserve(16, S, 8), 1500, [BULK]),
            tx_reserve(16, Q) as u32,
        );
        // 64 KiB buffers each way allow flights larger than one ring.
        let (handles, _) = establish_sized(&mut pair, Side::A, BULK);
        let data = [pattern(4 * BULK, 7), pattern(4 * BULK, 8)];

        let (received, pressure) = bulk(&mut pair, &handles, &data);
        assert!(received[0] == data[1], "B→A bytes differ");
        assert!(received[1] == data[0], "A→B bytes differ");
        // RX rings overflow; the links never find an RX pool empty.
        assert_ring_overflowed(&[&pair.a_to_b, &pair.b_to_a]);
        // Some turn ends with frames pending. A flush repeats bursts until
        // the ring is full, so a turn ends pending only if it queued more than
        // the 15 free slots; the ring losses keep at least one side's cwnd
        // below that. Measured max_tx_pending [A, B]: Q = 9 and 12 [0, 0];
        // Q = 16, 24, 32, 64 [0, 1]; also [0, 1] with 128 and 256 KiB buffers.
        // `bidirectional_bulk_lossless_small_rings_both_sides_stay_pending`
        // covers both sides pending.
        assert!(pressure.max_tx_pending.iter().any(|&pending| pending > 0), "{pressure:?}");
        // Ingress never blocks. Each round the link empties a side's TX ring,
        // so a turn's opening flush has 15 free slots for the <= Q = 16
        // packets the previous turn left pending and leaves <= 1; each of
        // <= S = 8 staged frames reserves one more, so pending <= 9 < Q and TX
        // in use <= 15 + 9 < P_tx.
        assert_eq!(pressure.rx_blocked, [0, 0]);
        // The bulk stops as soon as every byte arrived; the receivers' last ACKs can
        // still be on the wire then. Let them land before checking nothing is left.
        pair.drive_rounds(|_, _| {}, |last, _, _| if last.moved() { App::Moved } else { App::Done });
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn bidirectional_bulk_lossless_small_rings_both_sides_stay_pending() {
    with_eal(|eal| {
        // The TX pool covers 16 descriptors and Q = 16 pending slots: 32 mbufs.
        // The RX pool is the smallest admission accepts for one 64 KiB socket.
        // A 7-frame ring fits in one 8-frame RX burst and S = 8 staging, so
        // the receiver drains the whole ring every turn: no frame is lost,
        // the windows grow, and both sides queue more per turn than the ring
        // takes. Measured max_tx_pending [A, B], all lossless: S = 8 with
        // Q = 9 [9, 9], Q = 12 [12, 12], Q = 16 [16, 14]; S = 7 with Q = 8
        // [8, 8], Q = 32 [21, 14]. Smaller staging makes the ring overflow
        // and A's cwnd collapse (S = 6: [0, 5]; S = 4: [1, 1]). R = 3 also
        // stays pending ([16, 16]).
        const Q: usize = 16;
        const S: usize = 8;
        let sized = |side| StackConfig {
            max_udp_sockets: 0,
            rx_staging: S,
            tx_pending: Q,
            ..config(side)
        };
        let mut pair = Pair::with_pools(
            eal,
            ["bsra", "bsrb"],
            [sized(Side::A), sized(Side::B)],
            T0,
            8,
            rx_pool_count(rx_reserve(16, S, 8), 1500, [BULK]),
            tx_reserve(16, Q) as u32,
        );
        let (handles, _) = establish_sized(&mut pair, Side::A, BULK);
        let data = [pattern(4 * BULK, 7), pattern(4 * BULK, 8)];

        let (received, pressure) = bulk(&mut pair, &handles, &data);
        assert!(received[0] == data[1], "B→A bytes differ");
        assert!(received[1] == data[0], "A→B bytes differ");
        assert_lossless(&pair.a_to_b, "A→B");
        assert_lossless(&pair.b_to_a, "B→A");
        assert!(pressure.max_tx_pending.iter().all(|&pending| pending > 0), "{pressure:?}");
        // Ingress never blocks. Each round the link empties a side's TX ring,
        // so a turn's opening flush has 7 free slots and leaves <= Q - 7 = 9
        // pending; at most one ring of 7 frames arrives per round, each
        // reserving one slot, so pending <= 16 = Q and TX in use <= 7 + 16 =
        // 23 < P_tx = 32.
        assert_eq!(pressure.rx_blocked, [0, 0]);
        // The bulk stops as soon as every byte arrived; the receivers' last ACKs can
        // still be on the wire then (measured: B's ACK of A's last 7760 bytes
        // on A's RX ring). Let them land before checking nothing is left.
        pair.drive_rounds(|_, _| {}, |last, _, _| if last.moved() { App::Moved } else { App::Done });
        assert_eq!(pair.close(), 0);
    });
}

/// After each side's ACKs of the other's data are lost across both first
/// RTOs, a lossless wire lets both sides' data be acknowledged. Each RTO
/// rewinds its sender's resend point (`remote_last_seq`) to SND.UNA and
/// resends one MSS, so the resend point stays below the peer's RCV.NXT =
/// SND.UNA + 2048 while cwnd is one MSS and nothing is acknowledged. Pure ACKs
/// and ACK replies carry the highest sequence number sent instead, which the
/// peer accepts, reading their ACK.
#[zhida_test_support::pinned_test]
fn mutual_ack_loss_across_rto_recovers() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["lva", "lvb"]);
        let (handles, _, _) = connect(&mut pair);
        let t = pair.now();
        // The 2048 queued bytes fit the peer window and leave as two segments.
        let data = [pattern(2048, 11), pattern(2048, 12)];
        pair.a_to_b.paused = true;
        for (i, stack) in [&mut pair.a, &mut pair.b].into_iter().enumerate() {
            let socket = stack.tcp_mut(&handles[i]);
            assert_eq!(socket.send_slice(&data[i]), Ok(2048));
        }
        // A's segments wait on its TX ring while B's reach A, so neither
        // side's data acknowledges the other's.
        pair.round(|_, _| {});
        pair.a_to_b.paused = false;
        let drop_pure_acks = |src| {
            move |frame: &[u8]| {
                if segment(frame, src).payload.is_empty() {
                    Verdict::Drop
                } else {
                    Verdict::Deliver
                }
            }
        };
        pair.a_to_b.impair(drop_pure_acks(Side::A));
        pair.b_to_a.impair(drop_pure_acks(Side::B));
        // A's segments reach B; every pure ACK is lost, through both RTOs.
        pair.round(|_, _| {});
        pair.round_at(t + RTO, |_, _| {});
        pair.round(|_, _| {});
        assert_eq!((pair.a_to_b.dropped, pair.b_to_a.dropped), (2, 2));
        for (i, stack) in [&mut pair.a, &mut pair.b].into_iter().enumerate() {
            let socket = stack.tcp(&handles[i]);
            assert_eq!((socket.recv_queue(), socket.send_queue()), (2048, 2048));
        }

        pair.a_to_b.impair(|_| Verdict::Deliver);
        pair.b_to_a.impair(|_| Verdict::Deliver);
        let limit = t + Duration::from_secs(120);
        pair.drive(
            |_, _| {},
            |a, b| {
                let queued = |stack: &mut Stack, i: usize| stack.tcp(&handles[i]).send_queue();
                if queued(a, 0) + queued(b, 1) == 0 {
                    return App::Done;
                }
                let next = a.poll_at().into_iter().chain(b.poll_at()).min();
                assert!(next.is_some_and(|at| at <= limit), "not recovered; next deadline {next:?}");
                App::Idle
            },
        );
        let mut received = [Vec::new(), Vec::new()];
        read_all(&mut pair.a, &mut pair.b, &handles, &mut received);
        assert!(received[0] == data[1] && received[1] == data[0], "received bytes differ");
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn admission_refuses_tx_pools_for_full_ring() {
    with_eal(|eal| {
        let q1 = StackConfig {
            max_udp_sockets: 0,
            tx_pending: 1,
            ..config(Side::A)
        };
        for count in [16, 15] {
            let fixture = RingPort::new("admittx", 16, 16);
            let mut port_config = fixture.config();
            port_config.rx_pool.count =
                rx_pool_count(rx_reserve(16, q1.rx_staging, 8), 1500, [4096]);
            port_config.tx_pool.count = count;
            let port = fixture.open_with(eal, port_config);
            assert_eq!(port.descriptor_counts().1, 16);
            let port = match Stack::new(port, q1, T0) {
                Err((port, error)) => {
                    assert_eq!(
                        error,
                        StackError::TxPoolTooSmall { count: count as usize, required: 17 }
                    );
                    port
                }
                Ok(_) => panic!("accepted TX pool with {count} mbufs"),
            };
            assert_eq!(fixture.in_use(), (0, 0));
            port.try_close().unwrap();
            fixture.close();
        }
    });
}

#[zhida_test_support::pinned_test]
fn admission_full_tx_ring_still_answers() {
    with_eal(|eal| {
        let q1 = |side| StackConfig {
            max_udp_sockets: 0,
            tx_pending: 1,
            ..config(side)
        };
        let count = tx_reserve(16, 1) as u32;
        assert_eq!(count, 17);
        // The attached 16-entry ring holds 15 sent mbufs, below 16 descriptors.
        let mut pair = Pair::with_opened_ports(
            eal,
            ["afa", "afb"],
            [q1(Side::A), q1(Side::B)],
            T0,
            16,
            |side, port| {
                assert_eq!(port.tx_descriptors, 16);
                assert_eq!(port.tx_pool.cache_size, 8);
                port.rx_pool.count =
                    rx_pool_count(rx_reserve(16, q1(side).rx_staging, 8), 1500, [4096]);
                port.tx_pool.count = count;
            },
            |_, port| assert_eq!(port.descriptor_counts().1, 16),
        );
        let (handles, _, b_seq) = connect(&mut pair);
        let idle = Turn {
            rx_received: 0,
            rx_rejected: 0,
            rx_ipv4_checksum_bad: 0,
            rx_processed: 0,
            rx_staged: 0,
            rx_blocked: false,
            tx_accepted: 0,
            tx_pending: 0,
        };
        pair.a.tcp_mut(&handles[0]).set_ack_delay(None);
        pair.a_to_b.paused = true;
        for k in 0..15 {
            assert_eq!(pair.a.tcp_mut(&handles[0]).send_slice(&[k]), Ok(1));
            let round = pair.round(|_, _| panic!("nothing is delivered"));
            let sent = Turn { tx_accepted: 1, ..idle };
            assert_eq!((round.a, round.b), (sent, idle), "segment {k}");
        }
        assert_eq!(pair.in_use()[0], (0, 15));
        assert_eq!(pair.b.tcp_mut(&handles[1]).send_slice(b"b"), Ok(1));
        let round = pair.round(|_, _| {});
        assert_eq!((round.a, round.b.tx_accepted, round.b_to_a), (idle, 1, 1));
        let turn = pair.round(|_, _| panic!("nothing is delivered")).a;
        assert_eq!(
            turn,
            Turn {
                rx_received: 1,
                rx_processed: 1,
                tx_pending: 1,
                ..idle
            }
        );
        assert_eq!(pair.in_use()[0], (1, 16));
        assert_eq!(pair.a.tcp(&handles[0]).recv_queue(), 1);
        assert_eq!(pair.b.tcp(&handles[1]).send_queue(), 1);

        pair.a_to_b.paused = false;
        let mut received = [Vec::new(), Vec::new()];
        let mut ack_seen = false;
        pair.drive_rounds(
            |dir, frame| {
                if dir == Dir::AToB {
                    let tcp = segment(frame, Side::A);
                    if tcp.payload.is_empty() && tcp.ack_number == Some(b_seq + 1) {
                        assert_eq!(tcp.control, TcpControl::None);
                        ack_seen = true;
                    }
                }
            },
            |round, a, b| {
                read_all(a, b, &handles, &mut received);
                if received[0].len() == 1
                    && received[1].len() == 15
                    && a.tcp(&handles[0]).send_queue() == 0
                    && b.tcp(&handles[1]).send_queue() == 0
                    && !round.moved()
                {
                    App::Done
                } else {
                    App::Idle
                }
            },
        );
        let expected: Vec<u8> = (0..15).collect();
        assert_eq!(received, [b"b".to_vec(), expected]);
        assert!(ack_seen, "A's queued ACK did not reach B");
        assert_eq!(pair.b.tcp(&handles[1]).rx_refused_segments(), 0);
        assert_lossless(&pair.a_to_b, "A→B");
        assert_lossless(&pair.b_to_a, "B→A");
        assert_eq!(pair.close(), 0);
    });
}

const MESSAGE: usize = 16;
const MESSAGES: usize = 128;
/// Rounds with both links paused: 15 fill each TX ring, 32 fill each pending
/// queue, 3 more find both full.
const PAUSED_ROUNDS: usize = 15 + 32 + 3;

/// Both sides' message streams.
struct Messages {
    handles: [TcpHandle; 2],
    data: [Vec<u8>; 2],
    sent: [usize; 2],
    received: [Vec<u8>; 2],
}

impl Messages {
    /// Each side writes one more message while it has sent fewer than
    /// `limit`, and reads every byte that arrived. Returns whether anything
    /// moved.
    fn step(&mut self, a: &mut Stack, b: &mut Stack, limit: usize) -> bool {
        let mut moved = false;
        for (side, stack) in [(Side::A, a), (Side::B, b)] {
            let i = side.index();
            let socket = stack.tcp_mut(&self.handles[i]);
            let sent = self.sent[i];
            if sent < limit * MESSAGE {
                let message = &self.data[i][sent..sent + MESSAGE];
                assert_eq!(socket.send_slice(message), Ok(MESSAGE));
                self.sent[i] += MESSAGE;
                moved = true;
            }
            let buffer = drain_bytes(socket).unwrap();
            let read = buffer.len();
            self.received[i].extend_from_slice(&buffer[..read]);
            moved |= read > 0;
        }
        moved
    }

    fn acked(&self, a: &mut Stack, b: &mut Stack) -> bool {
        a.tcp(&self.handles[0]).send_queue() == 0 && b.tcp(&self.handles[1]).send_queue() == 0
    }
}

/// Turn `k` (from 1) of a side writing one message per round to a paused link.
fn paused_turn(k: usize) -> Turn {
    let (tx_accepted, tx_pending) = match k {
        1..=15 => (1, 0),
        16..=47 => (0, k - 15),
        _ => (0, 32),
    };
    Turn {
        rx_received: 0,
        rx_rejected: 0,
        rx_ipv4_checksum_bad: 0,
        rx_processed: 0,
        rx_staged: 0,
        rx_blocked: false,
        tx_accepted,
        tx_pending,
    }
}

#[zhida_test_support::pinned_test]
fn paused_wire_both_stacks_report_blocked_turns_finite_then_resume_completes() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["pwa", "pwb"]);
        let (handles, _, _) = connect(&mut pair);
        // A 4 KiB window carries about three full segments, too few to fill a
        // 15-entry TX ring. Each 16-byte write is one segment.
        let mut messages = Messages {
            handles,
            data: [pattern(MESSAGES * MESSAGE, 9), pattern(MESSAGES * MESSAGE, 10)],
            sent: [0; 2],
            received: [Vec::new(), Vec::new()],
        };

        // First 32 messages each way, delivered and acknowledged.
        pair.drive(
            |_, _| {},
            |a, b| {
                if messages.step(a, b, 32) {
                    App::Moved
                } else if messages.acked(a, b) {
                    App::Done
                } else {
                    App::Idle
                }
            },
        );
        assert_eq!(messages.sent, [32 * MESSAGE; 2]);
        // B's last TX token went unused (no reply needed); its packet stays as
        // B's spare.
        assert_eq!(pair.in_use(), [(0, 0), (0, 1)]);

        pair.a_to_b.paused = true;
        pair.b_to_a.paused = true;
        messages.step(&mut pair.a, &mut pair.b, MESSAGES);
        for k in 1..=PAUSED_ROUNDS {
            let round = pair.round(|_, _| panic!("paused links delivered a frame"));
            let expected = Round {
                a: paused_turn(k),
                b: paused_turn(k),
                a_to_b: 0,
                b_to_a: 0,
            };
            assert_eq!(round, expected, "paused round {k}");
            messages.step(&mut pair.a, &mut pair.b, MESSAGES);
        }
        // Each side: 15 frames on its TX ring and 32 pending.
        assert_eq!(pair.in_use(), [(0, 47); 2]);

        pair.a_to_b.paused = false;
        pair.b_to_a.paused = false;
        let round = pair.round(|_, _| {});
        let blocked = Turn {
            rx_received: 0,
            rx_rejected: 0,
            rx_ipv4_checksum_bad: 0,
            rx_processed: 0,
            rx_staged: 0,
            rx_blocked: false,
            tx_accepted: 0,
            tx_pending: 32,
        };
        // A's ring is still full when it turns; B gets A's 15 frames, stages a
        // burst of 8 and cannot process them: its own ring and pending are full.
        let expected = Round {
            a: blocked,
            b: Turn {
                rx_received: 8,
                rx_staged: 8,
                rx_blocked: true,
                ..blocked
            },
            a_to_b: 15,
            b_to_a: 15,
        };
        assert_eq!(round, expected);
        assert_eq!(pair.in_use(), [(15, 32); 2]);

        pair.drive(
            |_, _| {},
            |a, b| {
                let moved = messages.step(a, b, MESSAGES);
                if messages.received.iter().all(|bytes| bytes.len() == MESSAGES * MESSAGE) {
                    App::Done
                } else if moved {
                    App::Moved
                } else {
                    App::Idle
                }
            },
        );
        assert_eq!(messages.sent, [MESSAGES * MESSAGE; 2]);
        assert!(messages.received[0] == messages.data[1], "B→A bytes differ");
        assert!(messages.received[1] == messages.data[0], "A→B bytes differ");
        // After resume the backlog crosses at 15 frames per link per round
        // into 15-entry RX rings each peer drains 8 per turn, so both rings
        // overflow; TCP recovers the losses.
        assert_ring_overflowed(&[&pair.a_to_b]);
        assert_ring_overflowed(&[&pair.b_to_a]);
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn rto_while_wire_paused_then_resume() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["rpa", "rpb"]);
        let (handles, a_seq, _) = connect(&mut pair);
        // Each 16-byte write is its own segment, enough of them to fill A's
        // TX ring and pending queue within a 4 KiB window.
        let total = 8 + 47;
        let data = pattern(total * MESSAGE, 13);
        let mut sent = 0;
        let mut write = |a: &mut Stack, upto: usize| {
            if sent < upto * MESSAGE {
                let message = &data[sent..sent + MESSAGE];
                assert_eq!(a.tcp_mut(&handles[0]).send_slice(message), Ok(MESSAGE));
                sent += MESSAGE;
                true
            } else {
                false
            }
        };

        // Eight messages delivered, read and acknowledged. B reads as they
        // arrive.
        let mut received = Vec::new();
        pair.drive(
            |_, _| {},
            |a, b| {
                let buffer = drain_bytes(b.tcp_mut(&handles[1])).unwrap();
                let read = buffer.len();
                received.extend_from_slice(&buffer[..read]);
                if write(a, 8) || read > 0 {
                    App::Moved
                } else if received.len() == 8 * MESSAGE && a.tcp(&handles[0]).send_queue() == 0 {
                    App::Done
                } else {
                    App::Idle
                }
            },
        );
        assert_eq!(pair.b.tcp(&handles[1]).rx_refused_segments(), 0);
        assert_eq!(pair.in_use()[1].0, 0);
        let t = pair.now();

        // Paused: 47 more fill A's TX ring (15) and pending queue (32); all
        // are in flight as far as A's socket knows.
        pair.a_to_b.paused = true;
        for _ in 0..47 {
            assert!(write(&mut pair.a, total));
            pair.round(|_, _| panic!("paused link delivered a frame"));
        }
        assert_eq!(pair.in_use()[0], (0, 47));
        assert!(matches!(pair.a.poll_at(), Some(p) if p > t && p <= ceil_ms(t + RTO)));

        let full = Turn {
            rx_received: 0,
            rx_rejected: 0,
            rx_ipv4_checksum_bad: 0,
            rx_processed: 0,
            rx_staged: 0,
            rx_blocked: false,
            tx_accepted: 0,
            tx_pending: 32,
        };
        let early = pair.round_at(t + RTO - Duration::from_micros(1), |_, _| {
            panic!("paused link delivered a frame")
        });
        assert_eq!(early.a, full);
        assert!(matches!(pair.a.poll_at(), Some(p) if p > pair.now() && p <= ceil_ms(t + RTO)));
        // The RTO fires: the retransmission finds the pending queue full, so
        // the turn queues nothing and A wants to send again now.
        let expired = pair.round_at(ceil_ms(t + RTO), |_, _| panic!("paused link delivered a frame"));
        assert_eq!(expired.a, full);
        assert_eq!(pair.a.poll_at(), Some(pair.now()));
        assert_eq!(pair.in_use()[0], (0, 47));

        pair.a_to_b.paused = false;
        let mut frames = Vec::new();
        pair.drive(
            |dir, frame| {
                if dir == Dir::AToB {
                    frames.push((dir, frame.to_vec()));
                }
            },
            |a, b| {
                let buffer = drain_bytes(b.tcp_mut(&handles[1])).unwrap();
                let read = buffer.len();
                received.extend_from_slice(&buffer[..read]);
                if received.len() == data.len() && a.tcp(&handles[0]).send_queue() == 0 {
                    App::Done
                } else if read > 0 {
                    App::Moved
                } else {
                    App::Idle
                }
            },
        );
        // With the eight read before the pause, this is every message.
        assert!(received == data, "received bytes differ");
        // Delivered data segments starting below the furthest byte already
        // delivered, as (offset from the first data byte, length). The first
        // is the go-back resend from SND.UNA, queued once A's pending queue
        // had room. B's first turn after resume copies the in-order paused
        // segments it receives into one RX mbuf, so no refusal ACK reaches A
        // before the resend: it starts at the first byte after the eight
        // messages read before the pause. Segments past the gap the ring
        // overflow leaves are out of order, each holds its own RX mbuf, and B
        // refuses some of them.
        let mut furthest = a_seq + 8 * MESSAGE;
        let mut retransmitted = Vec::new();
        for s in segs(&frames).into_iter().filter(|s| s.len > 0) {
            if s.seq < furthest {
                retransmitted.push((s.seq - a_seq, s.len));
            }
            if s.seq + s.len > furthest {
                furthest = s.seq + s.len;
            }
        }
        let first = retransmitted.first().map(|&(offset, _)| offset);
        assert_eq!(first, Some(8 * MESSAGE), "{retransmitted:?}");
        assert!(pair.b.tcp(&handles[1]).rx_refused_segments() > 0);
        // On resume B's RX ring overflows; TCP recovers the losses.
        assert_ring_overflowed(&[&pair.a_to_b]);
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn fresh_connection_sends_full_peer_window_before_first_ack() {
    with_eal(|eal| {
        const WINDOW: usize = 8192;
        let mut pair = new_pair(eal, ["iwfulla", "iwfullb"]);
        let (handles, frames) = establish_sized(&mut pair, Side::A, WINDOW);
        let a_seq = segs(&frames[frames.len() - 1..])[0].seq;
        let now = pair.now();
        pair.b_to_a.paused = true;
        let data = pattern(WINDOW, 94);
        assert_eq!(pair.a.tcp_mut(&handles[0]).send_slice(&data), Ok(WINDOW));
        let mut sent = 0;
        for _ in 0..4 {
            pair.round(|dir, frame| {
                if dir == Dir::AToB {
                    let tcp = segment(frame, Side::A);
                    if !tcp.payload.is_empty() {
                        assert_eq!(tcp.seq_number, a_seq + sent);
                        assert_eq!(tcp.payload.len(), (WINDOW - sent).min(1460));
                        sent += tcp.payload.len();
                    }
                }
            });
        }
        assert_eq!(sent, WINDOW);
        assert_eq!(pair.now(), now);
        assert_eq!(pair.a.tcp(&handles[0]).send_queue(), WINDOW);
        assert_eq!(pair.b.tcp(&handles[1]).recv_queue(), WINDOW);
        let received = drain_bytes(pair.b.tcp_mut(&handles[1])).unwrap();
        assert_eq!(received.len(), WINDOW);
        assert_eq!(received, data);
        pair.b_to_a.paused = false;
        pair.drive(
            |_, _| {},
            |a, _| {
                if a.tcp(&handles[0]).send_queue() == 0 {
                    App::Done
                } else {
                    App::Idle
                }
            },
        );
        assert_lossless(&pair.a_to_b, "A→B");
        assert_lossless(&pair.b_to_a, "B→A");
        assert_eq!(pair.close(), 0);
    });
}

/// Cubic sends 40 000 bytes before an ACK. Three sequence ranges are lost once;
/// successive partial ACKs repair all three before the RTO.
#[zhida_test_support::pinned_test]
fn cubic_send_allowance_trace_with_sequence_pinned_losses() {
    with_eal(|eal| {
        let configs = [config(Side::A), config(Side::B)];
        let mut pair =
            Pair::with_ports(eal, ["cubicta", "cubictb"], configs, T0, 64, |side, port| {
                port.rx_pool.count = rx_pool_count(
                    rx_reserve(
                        port.rx_descriptors,
                        configs[side.index()].rx_staging,
                        port.rx_pool.cache_size,
                    ),
                    port.mtu,
                    [65536],
                );
            });
        let (handles, frames) = establish_sized(&mut pair, Side::A, 65536);
        pair.b.tcp_mut(&handles[1]).set_ack_delay(None);
        let a_seq = segs(&frames[frames.len() - 1..])[0].seq;
        let t = pair.now();
        let losses = [(20440, 21900), (37960, 39420), (39420, 40000)];
        let mut dropped = [false; 3];
        pair.a_to_b.impair(move |frame| {
            let tcp = segment(frame, Side::A);
            if tcp.payload.is_empty() {
                return Verdict::Deliver;
            }
            let start = tcp.seq_number - a_seq;
            let end = start + tcp.payload.len();
            for (index, &(left, right)) in losses.iter().enumerate() {
                if !dropped[index] && start < right && end > left {
                    assert_eq!((start, end), (left, right));
                    dropped[index] = true;
                    return Verdict::Drop;
                }
            }
            Verdict::Deliver
        });
        let data = pattern(40_000, 21);
        assert_eq!(pair.a.tcp_mut(&handles[0]).send_slice(&data), Ok(data.len()));
        let mut received = Vec::new();
        let mut pending = None;
        let mut trace = Vec::new();
        let fast_retransmitted = std::cell::Cell::new(false);
        pair.drive(
            |dir, frame| {
                if dir == Dir::AToB {
                    let tcp = segment(frame, Side::A);
                    if !tcp.payload.is_empty() {
                        let start = tcp.seq_number - a_seq;
                        trace.push((start, tcp.payload.len()));
                        if start == 20440 {
                            assert_eq!(tcp.payload.len(), 1460);
                            fast_retransmitted.set(true);
                        }
                    }
                }
            },
            |_, b| {
                let socket = b.tcp_mut(&handles[1]);
                let mut bytes = [0; 4096];
                let mut read = 0usize;
                while read < bytes.len() {
                    if pending.is_none() {
                        if !socket.can_recv() {
                            break;
                        }
                        pending = Some((socket.recv().unwrap().unwrap(), 0));
                    }
                    let (frame, offset) = pending.as_mut().unwrap();
                    let count = (bytes.len() - read).min(frame.payload().len() - *offset);
                    bytes[read..read + count].copy_from_slice(&frame.payload()[*offset..*offset + count]);
                    *offset = offset.checked_add(count).expect("frame offset exceeds usize");
                    read = read.checked_add(count).expect("read count exceeds usize");
                    if *offset == frame.payload().len() {
                        pending = None;
                    }
                }
                received.extend_from_slice(&bytes[..read]);
                if fast_retransmitted.get() {
                    App::Done
                } else if read > 0 {
                    App::Moved
                } else {
                    App::Idle
                }
            },
        );
        assert_eq!(pair.now(), t);
        pair.drive(
            |dir, frame| {
                if dir == Dir::AToB {
                    let tcp = segment(frame, Side::A);
                    if !tcp.payload.is_empty() {
                        trace.push((tcp.seq_number - a_seq, tcp.payload.len()));
                    }
                }
            },
            |a, b| {
                let socket = b.tcp_mut(&handles[1]);
                let mut bytes = [0; 4096];
                let mut read = 0usize;
                while read < bytes.len() {
                    if pending.is_none() {
                        if !socket.can_recv() {
                            break;
                        }
                        pending = Some((socket.recv().unwrap().unwrap(), 0));
                    }
                    let (frame, offset) = pending.as_mut().unwrap();
                    let count = (bytes.len() - read).min(frame.payload().len() - *offset);
                    bytes[read..read + count].copy_from_slice(&frame.payload()[*offset..*offset + count]);
                    *offset = offset.checked_add(count).expect("frame offset exceeds usize");
                    read = read.checked_add(count).expect("read count exceeds usize");
                    if *offset == frame.payload().len() {
                        pending = None;
                    }
                }
                received.extend_from_slice(&bytes[..read]);
                if received.len() == data.len() && a.tcp(&handles[0]).send_queue() == 0 {
                    App::Done
                } else if read > 0 {
                    App::Moved
                } else {
                    App::Idle
                }
            },
        );
        let mut expected: Vec<_> = (0..40000)
            .step_by(1460)
            .filter(|offset| ![20440, 37960, 39420].contains(offset))
            .map(|offset| (offset, (40000 - offset).min(1460)))
            .collect();
        expected.extend([(20440, 1460), (37960, 1460), (39420, 580)]);
        assert_eq!(trace, expected);
        assert_eq!(received, data);
        assert_eq!(pair.now(), t);
        assert_eq!(pair.a.tcp(&handles[0]).retransmits(), 3);
        assert_eq!(pair.a.tcp(&handles[0]).loss_events(), 1);
        assert_eq!(counts(&pair.a_to_b), (0, 0, 3, 0));
        assert_eq!(counts(&pair.b_to_a), (0, 0, 0, 0));
        assert_eq!(pair.close(), 0);
    });
}

/// The default 1 MiB Cubic window fits seven full segments. Holes at 0, 2
/// and 4 are repaired on successive cumulative ACKs at the same supplied time.
#[zhida_test_support::pinned_test]
fn burst_loss_partial_acks_repair_all_holes_before_rto() {
    with_eal(|eal| {
        const MSS: usize = 1460;
        const CAPACITY: usize = 16384;
        let configs = [config(Side::A), config(Side::B)];
        let mut pair = Pair::with_ports(eal, ["nrbursta", "nrburstb"], configs, T0, 64, |side, port| {
            port.rx_pool.count = rx_pool_count(
                rx_reserve(port.rx_descriptors, configs[side.index()].rx_staging, port.rx_pool.cache_size),
                port.mtu,
                [CAPACITY],
            );
        });
        let (handles, frames) = establish_sized(&mut pair, Side::A, CAPACITY);
        pair.b.tcp_mut(&handles[1]).set_ack_delay(None);
        let una = segs(&frames[frames.len() - 1..])[0].seq;
        let recover = una + 7 * MSS;
        let mut dropped = [false; 3];
        pair.a_to_b.impair(move |frame| {
            let tcp = segment(frame, Side::A);
            if !tcp.payload.is_empty() {
                for (index, offset) in [0, 2 * MSS, 4 * MSS].into_iter().enumerate() {
                    if tcp.seq_number == una + offset && !dropped[index] {
                        assert_eq!(tcp.payload.len(), MSS);
                        dropped[index] = true;
                        return Verdict::Drop;
                    }
                }
            }
            Verdict::Deliver
        });
        let data = pattern(7 * MSS, 43);
        assert_eq!(pair.a.tcp_mut(&handles[0]).send_slice(&data), Ok(data.len()));
        let now = pair.now();
        let mut repairs = Vec::new();
        let mut advancing_acks = Vec::new();
        let mut last_ack = una;
        for _ in 0..16 {
            pair.round_at(now, |dir, frame| {
                let tcp = segment(frame, if dir == Dir::AToB { Side::A } else { Side::B });
                if dir == Dir::AToB && !tcp.payload.is_empty() {
                    let offset = tcp.seq_number - una;
                    if [0, 2 * MSS, 4 * MSS].contains(&offset) {
                        assert_eq!(tcp.payload, &data[offset..offset + MSS]);
                        assert_eq!(last_ack, tcp.seq_number);
                        repairs.push((tcp.seq_number, tcp.payload.len()));
                    }
                } else if dir == Dir::BToA {
                    let ack = tcp.ack_number.unwrap();
                    if ack > last_ack {
                        advancing_acks.push(ack);
                        last_ack = ack;
                    }
                }
            });
            if pair.a.tcp(&handles[0]).send_queue() == 0 {
                break;
            }
        }
        assert_eq!(repairs, [(una, MSS), (una + 2 * MSS, MSS), (una + 4 * MSS, MSS)]);
        assert_eq!(advancing_acks, [una + 2 * MSS, una + 4 * MSS, recover]);
        assert_eq!(pair.now(), now);
        assert_eq!(pair.a.tcp(&handles[0]).send_queue(), 0);
        assert_eq!(pair.a.tcp(&handles[0]).retransmits(), 3);
        assert_eq!(pair.a.tcp(&handles[0]).loss_events(), 1);
        let received = drain_bytes(pair.b.tcp_mut(&handles[1])).unwrap();
        assert_eq!(received.len(), data.len());
        assert_eq!(received, data);
        assert_eq!(counts(&pair.a_to_b), (0, 0, 3, 0));
        assert_lossless(&pair.b_to_a, "B→A");
        assert_eq!(pair.close(), 0);
    });
}

struct TimedLink {
    now: dpdk_smoltcp::smoltcp::time::Instant,
    half_rtt: Duration,
    due: [std::collections::VecDeque<(dpdk_smoltcp::smoltcp::time::Instant, Vec<u8>)>; 2],
    batch_b: usize,
    drop_seq: Option<TcpSeqNumber>,
    dropped: usize,
    highest: Option<TcpSeqNumber>,
    data_sent: Vec<(dpdk_smoltcp::smoltcp::time::Instant, TcpSeqNumber, usize)>,
    received: Vec<u8>,
    total_received: usize,
    /// Bytes each new-data ACK took off A's send queue, in arrival order.
    ack_lens: Vec<usize>,
    unsent: Vec<u8>,
}

impl TimedLink {
    fn new(rtt: Duration) -> Self {
        Self {
            now: T0,
            half_rtt: Duration::from_micros(rtt.total_micros() / 2),
            due: Default::default(),
            batch_b: 1,
            drop_seq: None,
            dropped: 0,
            highest: None,
            data_sent: Vec::new(),
            received: Vec::new(),
            total_received: 0,
            ack_lens: Vec::new(),
            unsent: Vec::new(),
        }
    }

    fn step(&mut self, pair: &mut Pair, handles: &[TcpHandle; 2], send_a: bool) {
        self.now = self.due.iter().filter_map(|queue| queue.front().map(|(at, _)| *at))
            .chain([send_a.then(|| pair.a.poll_at()).flatten(), pair.b.poll_at()].into_iter().flatten())
            .min().expect("timed link has a delivery or a Stack deadline");
        for side in [Side::A, Side::B] {
            let budget = if side == Side::B { self.batch_b } else { 1 };
            let queue = &mut self.due[side.index()];
            let mut frames = Vec::new();
            while frames.len() < budget && queue.front().is_some_and(|(at, _)| *at <= self.now) {
                frames.push(queue.pop_front().unwrap().1);
            }
            pair.inject(side, &frames);
            let (stack, _) = side.pick(&mut pair.a, &mut pair.b);
            let before = stack.tcp(&handles[side.index()]).send_queue();
            let turn = stack.receive(self.now, budget).unwrap();
            assert_eq!(turn.rx_staged, 0);
            assert!(!turn.rx_blocked);
            let after = stack.tcp(&handles[side.index()]).send_queue();
            if side == Side::A && after < before {
                self.ack_lens.push(before - after);
            }
            if side == Side::B && stack.tcp(&handles[1]).can_recv() {
                let bytes = drain_bytes(stack.tcp_mut(&handles[1])).unwrap();
                let read = bytes.len();
                self.received.extend_from_slice(&bytes[..read]);
                self.total_received = self.total_received.checked_add(read).expect("received bytes fit usize");
            }
            self.drain_tx(pair, side);
            if side == Side::A && !send_a {
                continue;
            }
            loop {
                let (stack, _) = side.pick(&mut pair.a, &mut pair.b);
                let sent = stack.send().unwrap();
                let due_now = stack.poll_at() == Some(self.now);
                self.drain_tx(pair, side);
                assert_eq!(sent.tx_pending, 0, "timed link drains each TX burst");
                if !due_now || sent.tx_accepted == 0 {
                    break;
                }
            }
        }
    }

    fn drain_tx(&mut self, pair: &mut Pair, side: Side) {
        let mut frames = Vec::new();
        pair.drain_tx(side, |frame| frames.push(frame.to_vec()));
        for frame in frames {
            if side == Side::A && frame[12..14] == [0x08, 0x00] {
                let tcp = segment(&frame, side);
                let end = tcp.seq_number + tcp.segment_len();
                self.highest = Some(self.highest.map_or(end, |highest| highest.max(end)));
                if !tcp.payload.is_empty() {
                    self.data_sent.push((self.now, tcp.seq_number, tcp.payload.len()));
                    if self.drop_seq == Some(tcp.seq_number) {
                        self.drop_seq = None;
                        self.dropped += 1;
                        continue;
                    }
                }
            }
            self.due[side.other().index()].push_back((self.now + self.half_rtt, frame));
        }
    }

    /// Sends one cwnd-sized flight and receives all its ACKs; returns the bytes each
    /// ACK acknowledged. B takes up to `batch_b` frames per turn and ACKs once per
    /// turn, so the ACKs cover consecutive groups of `batch_b` segments.
    fn flight(&mut self, pair: &mut Pair, handles: &[TcpHandle; 2], bytes: &[u8]) -> Vec<usize> {
        assert!(self.received.is_empty());
        assert_eq!(pair.a.tcp(&handles[0]).send_queue(), self.unsent.len());
        let allowance = pair.a.tcp(&handles[0]).congestion_window();
        assert_eq!(bytes.len(), allowance);
        let sent = self.data_sent.len();
        let start = self.now;
        let acks = self.ack_lens.len();
        let mut queued = bytes.to_vec();
        if self.unsent.is_empty() {
            queued.extend_from_slice(&pattern(1460, 71));
        }
        assert_eq!(pair.a.tcp_mut(&handles[0]).send_slice(&queued), Ok(queued.len()));
        self.unsent.extend_from_slice(&queued);
        let remainder = self.unsent.len().checked_sub(allowance).expect("queue exceeds cwnd");
        assert!(remainder > 0);
        self.step(pair, &handles, true);
        assert_eq!(self.now, start);
        assert_eq!(self.ack_lens.len(), acks);
        assert_eq!(self.data_sent[sent..].iter().map(|(_, _, len)| len).sum::<usize>(), allowance,
            "pre-ACK flight must fill cwnd and leave the excess unsent");
        assert_eq!(pair.a.tcp(&handles[0]).send_queue(), self.unsent.len());
        // Receive this flight's ACKs before asking the sender to dispatch the next round.
        for _ in 0..10000 {
            self.step(pair, &handles, false);
            if pair.a.tcp(&handles[0]).send_queue() == remainder {
                break;
            }
            assert!(self.now < start + Duration::from_secs(10), "flight must complete before RTO");
        }
        assert_eq!(pair.a.tcp(&handles[0]).send_queue(), remainder);
        assert_eq!(self.data_sent[sent..].iter().map(|(_, _, len)| len).sum::<usize>(), allowance);
        assert_eq!(self.received, self.unsent[..allowance]);
        self.received.clear();
        self.unsent.drain(..allowance);
        assert_eq!(self.now, start + self.half_rtt * 2);
        let segments: Vec<usize> = self.data_sent[sent..].iter().map(|(_, _, len)| *len).collect();
        let expected: Vec<usize> = segments.chunks(self.batch_b).map(|group| group.iter().sum()).collect();
        assert_eq!(self.ack_lens[acks..], expected[..], "ACK cadence is controlled");
        self.data_sent.clear();
        self.ack_lens.split_off(acks)
    }
}

/// IW10 makes slow start observable; the default 1 MiB would skip this phase.
/// ACKs are per segment through slow start and loss. During regrowth B ACKs like
/// a Linux receiver with delayed ACKs: one ACK per two full segments (Linux ACKs
/// once more than one receive MSS is unacknowledged). B takes two frames per turn
/// with its delayed-ACK timer off, so an odd trailing segment is ACKed alone at
/// once instead of on the timer; every ACK then arrives exactly one RTT after
/// its data and the smoothed RTT that Cubic's target uses stays at the link RTT.
/// The oracle replays RFC 9438 per ACK. At 1 and 10 ms the Reno-friendly
/// estimate W_est outgrows the cubic curve and carries cwnd past w_max well
/// before K; at 70 ms the concave cubic approach is visible and cwnd crosses
/// w_max on the cubic curve after K.
#[zhida_test_support::pinned_test]
fn cubic_growth_and_recovery_across_rtts() {
    with_eal(|eal| {
        use dpdk_smoltcp::smoltcp::wire::IpEndpoint;
        const MSS: usize = 1460;
        const CAPACITY: usize = 512 * MSS;
        for rtt_ms in [1, 10, 70] {
            let rtt = Duration::from_millis(rtt_ms);
            let mut configs = [config(Side::A), config(Side::B)];
            for config in &mut configs {
                config.rx_staging = 256;
                config.tx_pending = 256;
            }
            let mut pair = Pair::with_ports(eal, ["cubicrtta", "cubicrttb"], configs, T0, 512, |side, port| {
                port.rx_burst = 256;
                port.tx_burst = 256;
                port.tx_pool.count = 511;
                port.rx_pool.count = rx_pool_count(
                    rx_reserve(port.rx_descriptors, configs[side.index()].rx_staging, port.rx_pool.cache_size),
                    port.mtu,
                    [CAPACITY],
                );
            });
            let a = pair.a.add_tcp(pair::tcp_socket_sized(CAPACITY)).unwrap();
            let b = pair.b.add_tcp(pair::tcp_socket_sized(CAPACITY)).unwrap();
            let handles = [a, b];
            let [a, b] = &handles;
            pair.a.tcp_mut(&a).set_initial_window(10 * MSS);
            pair.a.tcp_mut(&a).set_rto(Duration::from_secs(10));
            pair.b.tcp_mut(&b).set_rto(Duration::from_secs(10));
            pair.b.tcp_mut(&b).set_ack_delay(None);
            pair.b.listen(&b, pair::SERVER_PORT).unwrap();
            pair.a.connect(&a, IpEndpoint::new(Side::B.ip().into(), pair::SERVER_PORT), pair::CLIENT_PORT).unwrap();
            let mut link = TimedLink::new(rtt);
            for _ in 0..100 {
                link.step(&mut pair, &handles, true);
                if pair.a.tcp(&a).state() == State::Established && pair.b.tcp(&b).state() == State::Established {
                    break;
                }
            }
            assert_eq!(pair.a.tcp(&a).state(), State::Established);
            assert_eq!(pair.b.tcp(&b).state(), State::Established);
            assert_eq!(pair.a.tcp(&a).congestion_window(), 10 * MSS);
            let mut total_sent = 0usize;
            let mut series = vec![(0, 10 * MSS)];
            for segments in [10, 20, 40, 80] {
                let bytes = pattern(segments * MSS, segments as u32);
                link.flight(&mut pair, &handles, &bytes);
                total_sent = total_sent.checked_add(bytes.len()).expect("sent bytes fit usize");
                assert_eq!(pair.a.tcp(&a).congestion_window(), 2 * segments * MSS);
                series.push(((link.now - T0).total_micros(), pair.a.tcp(&a).congestion_window()));
            }
            let prior = pair.a.tcp(&a).congestion_window();
            let threshold = ((0.7 * prior as f64).floor() as usize).max(2 * MSS);
            let una = link.highest.unwrap();
            link.drop_seq = Some(una);
            let bytes = pattern(prior, 29);
            link.unsent.extend_from_slice(&bytes);
            let remainder = link.unsent.len().checked_sub(prior).expect("queue exceeds cwnd");
            assert!(remainder > 0);
            let sent = link.data_sent.len();
            let start = link.now;
            assert_eq!(pair.a.tcp_mut(&a).send_slice(&bytes), Ok(bytes.len()));
            let mut loss_at = None;
            link.step(&mut pair, &handles, true);
            assert_eq!(link.now, start);
            assert_eq!(link.data_sent[sent..].iter().map(|(_, _, len)| len).sum::<usize>(), prior,
                "pre-ACK loss flight must fill cwnd and leave the excess unsent");
            assert_eq!(pair.a.tcp(&a).send_queue(), link.unsent.len());
            for _ in 0..10000 {
                let send_a = pair.a.tcp(&a).retransmits() == 0;
                link.step(&mut pair, &handles, send_a);
                if loss_at.is_none() && pair.a.tcp(&a).loss_events() == 1 {
                    loss_at = Some(link.now);
                    assert_eq!(pair.a.tcp(&a).congestion_window(), threshold + 3 * MSS);
                }
                if pair.a.tcp(&a).send_queue() == remainder {
                    break;
                }
                assert!(link.now < start + rtt * 3, "fast repair must finish before RTO");
            }
            let loss_at = loss_at.expect("three duplicate ACKs enter fast recovery");
            assert_eq!(pair.a.tcp(&a).send_queue(), remainder);
            assert_eq!(pair.a.tcp(&a).congestion_window(), threshold);
            assert_eq!(link.data_sent[sent..].iter().filter(|(at, _, _)| *at == start)
                .map(|(_, _, len)| len).sum::<usize>(), prior);
            assert_eq!(link.highest, Some(una + prior));
            link.data_sent.clear();
            total_sent = total_sent.checked_add(bytes.len()).expect("sent bytes fit usize");
            assert_eq!(link.received, link.unsent[..prior]);
            link.received.clear();
            link.unsent.drain(..prior);
            assert_eq!(link.total_received, total_sent);
            assert_eq!(link.dropped, 1);
            assert_eq!((pair.a.tcp(&a).retransmits(), pair.a.tcp(&a).loss_events()), (1, 1));
            series.push(((link.now - T0).total_micros(), threshold));

            link.batch_b = 2;
            let k = (0.3 * prior as f64 / (0.4 * MSS as f64)).cbrt();
            let cubic = |t: f64| prior as f64 + 0.4 * MSS as f64 * (t - k).powf(3.0);
            let mut w_est = threshold as f64;
            let mut concave_samples = 0;
            let mut crossed = None;
            for round in 0..20000 {
                let cwnd = pair.a.tcp(&a).congestion_window();
                let bytes = pattern(cwnd, round as u32);
                let ack_lens = link.flight(&mut pair, &handles, &bytes);
                total_sent = total_sent.checked_add(bytes.len()).expect("sent bytes fit usize");
                let elapsed = (link.now - loss_at).total_micros() as f64 / 1_000_000.0;
                let mut expected = cwnd as f64;
                let mut cubic_branch = false;
                for &len in &ack_lens {
                    let alpha = if w_est < prior as f64 { 9.0 / 17.0 } else { 1.0 };
                    w_est += alpha * MSS as f64 * len as f64 / expected;
                    if cubic(elapsed) < w_est {
                        expected = expected.max(w_est);
                    } else {
                        cubic_branch = true;
                        let target = cubic(elapsed + rtt_ms as f64 / 1000.0).min(1.5 * expected);
                        expected += (target - expected).max(0.0) * len as f64 / expected;
                    }
                }
                let actual = pair.a.tcp(&a).congestion_window();
                assert!(actual < CAPACITY, "the peer window never limits regrowth");
                // Floating equations avoid the implementation's integer truncation
                // (under 1 byte per ACK in the cubic branch, none accumulating in the
                // W_est branch) and approximate cube root: permit 2 bytes per ACK plus
                // 1/64 MSS per round.
                let tolerance = 2.0 * ack_lens.len() as f64 + MSS as f64 / 64.0;
                assert!((actual as f64 - expected).abs() <= tolerance,
                    "RTT {rtt_ms} ms, t={elapsed}, cwnd={actual}, equation={expected}");
                if elapsed < k && cubic_branch && actual > threshold && actual < prior {
                    concave_samples += 1;
                }
                series.push(((link.now - T0).total_micros(), actual));
                assert_eq!((pair.a.tcp(&a).retransmits(), pair.a.tcp(&a).loss_events()), (1, 1));
                if actual > prior + MSS {
                    crossed = Some((elapsed, cubic_branch));
                    break;
                }
            }
            eprintln!("RTT {rtt_ms} ms, (time_us, cwnd_bytes) per RTT: {series:?}");
            let (crossed_at, by_cubic) = crossed.expect("Cubic must grow past w_max");
            if rtt_ms == 70 {
                assert!(concave_samples >= 3, "observe cubic approach below w_max");
                assert!(crossed_at > k && by_cubic, "cwnd crosses w_max on the cubic curve after K");
            } else {
                assert!(crossed_at < k && !by_cubic, "W_est carries cwnd past w_max before K");
            }
            assert_eq!(link.total_received, total_sent);
            assert!(link.received.is_empty());
            assert_eq!(pair.a.tcp(&a).send_queue(), link.unsent.len());
            for _ in 0..10000 {
                link.step(&mut pair, &handles, true);
                if pair.a.tcp(&a).send_queue() == 0 {
                    break;
                }
            }
            assert_eq!(link.received, link.unsent);
            total_sent = total_sent.checked_add(link.unsent.len()).expect("sent bytes fit usize");
            assert_eq!(link.total_received, total_sent);
            link.received.clear();
            assert_eq!(pair.a.tcp(&a).send_queue(), 0);
            assert!(link.due.iter().all(|queue| queue.is_empty()));
            assert_eq!(pair.close(), 0);
        }
    });
}
