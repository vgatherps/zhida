//! One TCP frame per iteration, Criterion group "emit", with 1, 64 or
//! 10240 established connections per Stack and the active connection in slot 0.
//! pure_ack times B's send after an untimed receive of 1448
//! bytes. recv_data_ack times B's turn that receives 1448 bytes and sends its
//! ACK. send_64 and send_1448 time A's send after the application write.
//! In steady state, pure_ack, send_64 and send_1448 reuse the spare TX
//! packet left by an untimed receive, so they time no mbuf allocation.
//! recv_data_ack starts with no spare TX packet and times one mbuf allocation.
//! pure_ack, send_64 and send_1448 include the flush of their one frame.
//! recv_data_ack includes receive and flush.
//! Setup, forwarding, frame checks and application reads are untimed.
//! Every iteration checks one data frame, one ACK and the received bytes.
//! Warmup iterations after the first also check the TX pool counts before the
//! timed call and that poll_at is None afterwards; measured iterations skip
//! those two checks, because the pool count walks every lcore's mempool cache
//! and poll_at can classify sockets, which would change what the next timed
//! call finds in cache or has to do.
//! This bench checks workload shape; tests/frames/ has the committed fixtures
//! that check header byte correctness.
//! The timer read is inside the timed region; clock times an empty region
//! with the same two Instant reads and reports their fixed cost.
//! The timer tick may be coarse in a VM; Criterion averages the per-iteration
//! samples.

use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::wire::{TcpControl, TcpSeqNumber, ETHERNET_HEADER_LEN, IPV4_HEADER_LEN};
use dpdk_smoltcp::{Eal, Sent, Turn};

use zhida_test_kit::many::{self, assert_quiet, Conn};
use zhida_test_kit::pair::{
    establish_sized, pattern, segment, Pair, Side, BUDGET, CLIENT_PORT, SERVER_PORT, T0,
};
use zhida_test_kit::with_eal;

const COUNTS: [usize; 3] = [1, 64, 10_240];
const FILLER_BUFFER: usize = 256;
const WARMUP: usize = 6;
const TCP_FLAGS: usize = 14 + 20 + 13;

#[derive(Clone, Copy)]
enum Case {
    PureAck,
    RecvDataAck,
    Send64,
    Send1448,
}

impl Case {
    fn name(self) -> &'static str {
        match self {
            Case::PureAck => "pure_ack",
            Case::RecvDataAck => "recv_data_ack",
            Case::Send64 => "send_64",
            Case::Send1448 => "send_1448",
        }
    }

    fn payload_len(self) -> usize {
        match self {
            Case::Send64 => 64,
            _ => 1448,
        }
    }
}

fn setup(eal: &Eal, case: Case, n: usize) -> (Pair, [TcpHandle; 2], Vec<Conn>) {
    let names = [format!("em{n}a"), format!("em{n}b")];
    let configs = [many::config(Side::A, n), many::config(Side::B, n)];
    let mut pair = Pair::new(eal, [&names[0], &names[1]], configs, T0);
    // Every A write lands in an empty TX ring, which resets to offset 0.
    // Whole messages keep B's RX ring copies contiguous as reads advance.
    // After a read, B's window grows from two messages to three, below the
    // update threshold.
    let buffer = case.payload_len().checked_mul(3).expect("socket buffer");
    let (handles, _) = establish_sized(&mut pair, Side::A, buffer);
    for (stack, handle) in [(&mut pair.a, &handles[0]), (&mut pair.b, &handles[1])] {
        assert_eq!(handle.to_string(), "#0");
        stack.tcp_mut(&handle).set_ack_delay(None);
    }
    let count = u16::try_from(n.checked_sub(1).expect("active connection"))
        .expect("filler connection count");
    let fillers = many::open(&mut pair, 0..count, FILLER_BUFFER);
    assert_quiet(&mut pair, &fillers);
    (pair, handles, fillers)
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

fn forward_data(pair: &mut Pair, payload: &[u8]) -> TcpSeqNumber {
    let mut ack = None;
    let count = pair.a_to_b.forward_with(|frame| {
        let tcp = segment(frame, Side::A);
        assert_eq!(
            frame.len(),
            ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + tcp.header_len() + payload.len(),
            "A→B frame length"
        );
        assert_eq!(frame[TCP_FLAGS], 0x18, "A→B TCP flags");
        assert_eq!((tcp.src_port, tcp.dst_port), (CLIENT_PORT, SERVER_PORT));
        assert_eq!(tcp.control, TcpControl::Psh);
        assert!(tcp.ack_number.is_some(), "data frame has no ACK flag");
        assert_eq!(tcp.payload, payload);
        ack = Some(tcp.seq_number + payload.len());
    });
    assert_eq!(count, 1, "A→B frame count");
    ack.expect("one data frame")
}

fn forward_ack(pair: &mut Pair, expected: TcpSeqNumber) {
    let count = pair.b_to_a.forward_with(|frame| {
        let tcp = segment(frame, Side::B);
        assert_eq!(
            frame.len(),
            ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + tcp.header_len(),
            "B→A frame length"
        );
        assert_eq!(frame[TCP_FLAGS], 0x10, "B→A TCP flags");
        assert_eq!((tcp.src_port, tcp.dst_port), (SERVER_PORT, CLIENT_PORT));
        assert_eq!(tcp.control, TcpControl::None);
        assert!(tcp.payload.is_empty(), "ACK frame has payload");
        assert_eq!(tcp.ack_number, Some(expected));
    });
    assert_eq!(count, 1, "B→A frame count");
}

fn iteration(
    pair: &mut Pair,
    handles: &[TcpHandle; 2],
    case: Case,
    payload: &[u8],
    sink: &mut [u8],
    steady_checks: bool,
) -> Duration {
    let [client, server] = handles;
    let now = pair.now();
    assert_eq!(
        pair.a.tcp_mut(&client).send_slice(payload),
        Ok(payload.len())
    );
    let (elapsed, ack) = match case {
        Case::PureAck | Case::RecvDataAck => {
            assert_turn(pair.a.turn(now, BUDGET).unwrap(), 0, 1);
            let ack = forward_data(pair, payload);
            let elapsed = match case {
                Case::PureAck => {
                    assert_turn(pair.b.receive(now, BUDGET).unwrap(), 1, 0);
                    if steady_checks {
                        assert_eq!(pair.in_use()[1].1, 1, "B TX pool before send");
                    }
                    let start = Instant::now();
                    let sent = pair.b.send();
                    let elapsed = start.elapsed();
                    assert_eq!(
                        sent,
                        Ok(Sent {
                            tx_accepted: 1,
                            tx_pending: 0,
                        })
                    );
                    elapsed
                }
                Case::RecvDataAck => {
                    if steady_checks {
                        assert_eq!(pair.in_use()[1].1, 0, "B TX pool before turn");
                    }
                    let start = Instant::now();
                    let turn = pair.b.turn(now, BUDGET);
                    let elapsed = start.elapsed();
                    assert_turn(turn.unwrap(), 1, 1);
                    elapsed
                }
                _ => unreachable!(),
            };
            (elapsed, ack)
        }
        Case::Send64 | Case::Send1448 => {
            if steady_checks {
                assert_eq!(pair.in_use()[0].1, 1, "A TX pool before send");
            }
            let start = Instant::now();
            let sent = pair.a.send();
            let elapsed = start.elapsed();
            assert_eq!(
                sent,
                Ok(Sent {
                    tx_accepted: 1,
                    tx_pending: 0,
                })
            );
            let ack = forward_data(pair, payload);
            assert_turn(pair.b.turn(now, BUDGET).unwrap(), 1, 1);
            (elapsed, ack)
        }
    };
    forward_ack(pair, ack);
    assert_turn(pair.a.turn(now, BUDGET).unwrap(), 1, 0);
    if steady_checks {
        assert_eq!(pair.a.poll_at(), None, "A deadline after ACK");
    }
    assert_eq!(pair.a_to_b.forward(), 0, "extra A→B frame after ACK");
    let mut read = 0usize;
    while let Some(frame) = pair.b.tcp_mut(&server).recv().unwrap() {
        let end = read.checked_add(frame.payload().len()).expect("read bytes");
        sink[read..end].copy_from_slice(frame.payload());
        read = end;
    }
    assert_eq!(read, payload.len());
    assert_eq!(sink, payload);
    if steady_checks {
        assert_eq!(pair.b.poll_at(), None, "B deadline after application read");
    }
    for (stack, handle) in [(&mut pair.a, client), (&mut pair.b, server)] {
        let socket = stack.tcp(&handle);
        assert_eq!((socket.send_queue(), socket.recv_queue()), (0, 0));
    }
    elapsed
}

fn close(pair: Pair) {
    for link in [&pair.a_to_b, &pair.b_to_a] {
        assert_eq!((link.pool_empty, link.ring_full, link.dropped), (0, 0, 0));
    }
    assert_eq!(pair.close(), 0);
}

fn benches(c: &mut Criterion) {
    with_eal(|eal| {
        let mut group = c.benchmark_group("emit");
        group.throughput(Throughput::Elements(1));
        for n in COUNTS {
            for case in [
                Case::PureAck,
                Case::RecvDataAck,
                Case::Send64,
                Case::Send1448,
            ] {
                let (mut pair, handles, fillers) = setup(eal, case, n);
                let payload = pattern(case.payload_len(), 7);
                let mut sink = vec![0; payload.len()];
                // The first untimed receive establishes the spare TX packet.
                iteration(&mut pair, &handles, case, &payload, &mut sink, false);
                for _ in 1..WARMUP {
                    iteration(&mut pair, &handles, case, &payload, &mut sink, true);
                }
                assert_quiet(&mut pair, &fillers);
                group.bench_function(BenchmarkId::new(case.name(), n), |b| {
                    b.iter_custom(|iters| {
                        let mut elapsed = Duration::ZERO;
                        for _ in 0..iters {
                            elapsed = elapsed
                                .checked_add(iteration(
                                    &mut pair, &handles, case, &payload, &mut sink, false,
                                ))
                                .expect("total emit duration");
                        }
                        elapsed
                    });
                });
                assert_quiet(&mut pair, &fillers);
                close(pair);
            }
        }
        group.bench_function("clock", |b| {
            b.iter_custom(|iters| {
                let mut elapsed = Duration::ZERO;
                for _ in 0..iters {
                    let start = Instant::now();
                    let sample = start.elapsed();
                    elapsed = elapsed.checked_add(sample).expect("total clock duration");
                }
                elapsed
            });
        });
        group.finish();
    });
}

criterion_group!(emit, benches);
criterion_main!(emit);
