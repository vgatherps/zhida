//! `Stack::receive` and `Stack::send`, the two halves of a turn: an
//! application that reads and writes sockets between them replies in the
//! loop iteration that received the request.

use zhida_test_kit::pair::drain_bytes;
use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::time::{Duration, Instant};
use dpdk_smoltcp::{rx_pool_count, rx_reserve};
use dpdk_smoltcp::{Eal, Sent, Stack, StackConfig, Turn};

use zhida_test_kit::{pair, wire, with_eal};
use pair::{config, establish, segment, Pair, Side, T0};
use wire::{Link, Verdict};

const BUDGET: usize = 32;

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

const SENT_ONE: Sent = Sent {
    tx_accepted: 1,
    tx_pending: 0,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Turn,
    Split,
}

fn ms(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

/// `receive` then `send` counted as one turn.
fn combined(received: Turn, sent: Sent) -> Turn {
    Turn {
        tx_accepted: received.tx_accepted + sent.tx_accepted,
        tx_pending: sent.tx_pending,
        ..received
    }
}

/// `turn`, or `receive` then `send` with nothing between.
fn step(stack: &mut Stack, mode: Mode, now: Instant) -> Turn {
    match mode {
        Mode::Turn => stack.turn(now, BUDGET).unwrap(),
        Mode::Split => {
            let received = stack.receive(now, BUDGET).unwrap();
            combined(received, stack.send().unwrap())
        }
    }
}

fn new_pair(eal: &Eal, names: [&str; 2]) -> Pair {
    Pair::new(eal, names, [config(Side::A), config(Side::B)], T0)
}

/// Every frame on `link`'s sender ring, delivered to its receiver.
fn forward(link: &mut Link) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    link.forward_with(|frame| frames.push(frame.to_vec()));
    frames
}

/// Payloads of TCP segments `src` sent.
fn payloads(frames: &[Vec<u8>], src: Side) -> Vec<Vec<u8>> {
    frames.iter().map(|frame| segment(frame, src).payload.to_vec()).collect()
}

/// A writes `data` and turns at `now`: one segment on A's TX ring.
fn a_sends(pair: &mut Pair, a: &TcpHandle, now: Instant, data: &[u8]) {
    assert_eq!(pair.a.tcp_mut(&a).send_slice(data), Ok(data.len()));
    assert_eq!(pair.a.turn(now, BUDGET).unwrap().tx_accepted, 1);
}

/// Read exactly `request`, then write `reply`.
fn answer(stack: &mut Stack, handle: &TcpHandle, request: &[u8], reply: &[u8]) {
    let socket = stack.tcp_mut(&handle);
    let buffer = drain_bytes(socket).unwrap();
    let read = buffer.len();
    assert_eq!(&buffer[..read], request);
    assert_eq!(socket.send_slice(reply), Ok(reply.len()));
}

/// Write back everything received.
fn echo(stack: &mut Stack, handle: &TcpHandle) {
    let socket = stack.tcp_mut(&handle);
    let buffer = drain_bytes(socket).unwrap();
    let read = buffer.len();
    assert_eq!(socket.send_slice(&buffer[..read]), Ok(read));
}

/// The link holds the next frame it takes and delivers it right after the
/// one following: the receiver gets those two in reverse order.
fn swap_next_two(link: &mut Link) {
    let mut taken = 0;
    link.impair(move |_| {
        taken += 1;
        if taken == 1 {
            Verdict::Hold
        } else {
            Verdict::Deliver
        }
    });
}

#[zhida_test_support::pinned_test]
fn reply_written_between_receive_and_send_leaves_in_send() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["rpla", "rplb"]);
        let ([a, b], _) = establish(&mut pair, Side::A);
        let now = pair.now();

        a_sends(&mut pair, &a, now, b"req1");
        assert_eq!(pair.a_to_b.forward(), 1);
        // In-order data: the ACK is delayed, nothing leaves in receive.
        assert_eq!(
            pair.b.receive(now, BUDGET),
            Ok(Turn {
                rx_received: 1,
                rx_processed: 1,
                ..IDLE
            })
        );
        answer(&mut pair.b, &b, b"req1", b"rep1");
        assert_eq!(pair.b.send(), Ok(SENT_ONE));
        assert_eq!(payloads(&forward(&mut pair.b_to_a), Side::B), [b"rep1"]);
        assert_eq!(pair.a.turn(now, BUDGET).unwrap().rx_processed, 1);

        // With turn the reply written after it waits for the next turn.
        a_sends(&mut pair, &a, now, b"req2");
        assert_eq!(pair.a_to_b.forward(), 1);
        assert_eq!(
            pair.b.turn(now, BUDGET),
            Ok(Turn {
                rx_received: 1,
                rx_processed: 1,
                ..IDLE
            })
        );
        answer(&mut pair.b, &b, b"req2", b"rep2");
        assert!(forward(&mut pair.b_to_a).is_empty());
        assert_eq!(
            pair.b.turn(now, BUDGET),
            Ok(Turn {
                tx_accepted: 1,
                ..IDLE
            })
        );
        assert_eq!(payloads(&forward(&mut pair.b_to_a), Side::B), [b"rep2"]);
        assert_eq!(pair.a.turn(now, BUDGET).unwrap().rx_processed, 1);
        assert_eq!(pair.close(), 0);
    });
}

/// A on its own clock, B 300 ms ahead; phases interleave A receive, B
/// receive, A send, B send. Both Stacks send without timestamps.
#[zhida_test_support::pinned_test]
fn interleaved_stacks_send_without_timestamps() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["ilva", "ilvb"]);
        let ([a, b], _) = establish(&mut pair, Side::A);
        // Each side's previous segment is still unacknowledged.
        let start = pair.now();
        let clocks = |k: u64| [start + ms(1 + k), start + ms(300 + k)];
        for k in 0..3 {
            let [at_a, at_b] = clocks(k);
            let tag = [b'0' + k as u8];
            assert_eq!(pair.a.tcp_mut(&a).send_slice(&tag), Ok(1));
            assert_eq!(pair.b.tcp_mut(&b).send_slice(&tag), Ok(1));
            // The other side's segment from the previous round, if any.
            let rx = usize::from(k > 0);
            let received = Turn {
                rx_received: rx,
                rx_processed: rx,
                ..IDLE
            };
            assert_eq!(pair.a.receive(at_a, BUDGET), Ok(received));
            assert_eq!(pair.b.receive(at_b, BUDGET), Ok(received));
            assert_eq!(pair.a.send(), Ok(SENT_ONE));
            assert_eq!(pair.b.send(), Ok(SENT_ONE));
            let from_a = forward(&mut pair.a_to_b);
            let from_b = forward(&mut pair.b_to_a);
            assert_eq!(payloads(&from_a, Side::A), [tag]);
            assert_eq!(payloads(&from_b, Side::B), [tag]);
            assert_eq!(segment(&from_a[0], Side::A).timestamp, None);
            assert_eq!(segment(&from_b[0], Side::B).timestamp, None);
        }
        let [at_a, at_b] = clocks(2);
        let last = Turn {
            rx_received: 1,
            rx_processed: 1,
            ..IDLE
        };
        assert_eq!(pair.a.turn(at_a, BUDGET), Ok(last));
        assert_eq!(pair.b.turn(at_b, BUDGET), Ok(last));
        assert_eq!(pair.close(), 0);
    });
}

/// B's step and the frames it put on its ring, per step; A's frames.
type Trace = (Vec<(Turn, Vec<Vec<u8>>)>, Vec<Vec<u8>>);

/// Three rounds, 20 ms apart: A sends three 2-byte segments; B steps three
/// times with ingress budget 2, echoing what it read after each step. In-order
/// data makes smoltcp queue nothing during ingress.
fn echo_rounds(pair: &mut Pair, mode: Mode) -> Trace {
    let ([a, b], _) = establish(pair, Side::A);
    let start = pair.now();
    let (mut steps, mut from_a) = (Vec::new(), Vec::new());
    for round in 0..3u8 {
        let now = start + ms(20 * u64::from(round));
        for i in 0..3 {
            a_sends(pair, &a, now, &[round, i]);
        }
        from_a.extend(forward(&mut pair.a_to_b));
        for _ in 0..3 {
            let turn = match mode {
                Mode::Turn => pair.b.turn(now, 2).unwrap(),
                Mode::Split => {
                    let received = pair.b.receive(now, 2).unwrap();
                    assert_eq!((received.tx_accepted, received.tx_pending), (0, 0));
                    combined(received, pair.b.send().unwrap())
                }
            };
            steps.push((turn, forward(&mut pair.b_to_a)));
            echo(&mut pair.b, &b);
        }
        assert_eq!(pair.a.turn(now, BUDGET).unwrap().rx_processed, 2);
    }
    (steps, from_a)
}

#[zhida_test_support::pinned_test]
fn turn_matches_receive_then_send() {
    with_eal(|eal| {
        let [turned, split] = [(Mode::Turn, ["mtta", "mttb"]), (Mode::Split, ["mtsa", "mtsb"])]
            .map(|(mode, names)| {
                let mut pair = new_pair(eal, names);
                let trace = echo_rounds(&mut pair, mode);
                assert_eq!(pair.close(), 0);
                trace
            });
        assert_eq!(turned, split);

        let (steps, from_a) = turned;
        assert_eq!(from_a.len(), 9);
        let expected = [
            Turn {
                rx_received: 3,
                rx_processed: 2,
                rx_staged: 1,
                ..IDLE
            },
            Turn {
                rx_processed: 1,
                tx_accepted: 1,
                ..IDLE
            },
            Turn {
                tx_accepted: 1,
                ..IDLE
            },
        ];
        for (round, steps) in steps.chunks(3).enumerate() {
            let round = round as u8;
            let turns: Vec<Turn> = steps.iter().map(|(turn, _)| *turn).collect();
            assert_eq!(turns, expected, "round {round}");
            let echoed: Vec<Vec<Vec<u8>>> =
                steps.iter().map(|(_, frames)| payloads(frames, Side::B)).collect();
            assert_eq!(
                echoed,
                [vec![], vec![vec![round, 0, round, 1]], vec![vec![round, 2]]],
                "round {round}"
            );
        }
    });
}

#[zhida_test_support::pinned_test]
fn receive_flushes_frames_built_during_ingress() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["rfla", "rflb"]);
        let ([a, b], _) = establish(&mut pair, Side::A);
        let now = pair.now();

        // A's two segments arrive in reverse order: smoltcp ACKs each during
        // ingress. B's own data waits for send.
        assert_eq!(pair.b.tcp_mut(&b).send_slice(b"late"), Ok(4));
        a_sends(&mut pair, &a, now, b"1");
        a_sends(&mut pair, &a, now, b"2");
        swap_next_two(&mut pair.a_to_b);
        let reordered = forward(&mut pair.a_to_b);
        assert_eq!(payloads(&reordered, Side::A), [b"2", b"1"]);
        let first = segment(&reordered[1], Side::A).seq_number;
        assert_eq!(
            pair.b.receive(now, BUDGET),
            Ok(Turn {
                rx_received: 2,
                rx_processed: 2,
                tx_accepted: 2,
                ..IDLE
            })
        );
        let acks: Vec<_> = forward(&mut pair.b_to_a)
            .iter()
            .map(|frame| {
                let ack = segment(frame, Side::B);
                (ack.payload.len(), ack.ack_number)
            })
            .collect();
        assert_eq!(acks, [(0, Some(first)), (0, Some(first + 2))]);
        assert_eq!(pair.b.send(), Ok(SENT_ONE));
        assert_eq!(payloads(&forward(&mut pair.b_to_a), Side::B), [b"late"]);
        assert_eq!(
            pair.a.turn(now, BUDGET),
            Ok(Turn {
                rx_received: 3,
                rx_processed: 3,
                ..IDLE
            })
        );

        // In-order data: ingress builds nothing, and B's data stays unsent
        // until send.
        assert_eq!(pair.b.tcp_mut(&b).send_slice(b"later"), Ok(5));
        a_sends(&mut pair, &a, now, b"3");
        assert_eq!(pair.a_to_b.forward(), 1);
        assert_eq!(
            pair.b.receive(now, BUDGET),
            Ok(Turn {
                rx_received: 1,
                rx_processed: 1,
                ..IDLE
            })
        );
        assert!(forward(&mut pair.b_to_a).is_empty());
        assert_eq!(pair.b.send(), Ok(SENT_ONE));
        assert_eq!(payloads(&forward(&mut pair.b_to_a), Side::B), [b"later"]);

        assert_eq!(
            pair.a.turn(now, BUDGET),
            Ok(Turn {
                rx_received: 1,
                rx_processed: 1,
                ..IDLE
            })
        );
        assert_eq!(pair.close(), 0);
    });
}

/// B with 2 pending slots and TX rings holding 3, `queued` of B's slots taken
/// by its own earlier data that the paused link leaves there. B has `late` to
/// send when A's two segments arrive in reverse order, so ingress fills the
/// pending queue with two ACKs. Returns B's step and the payloads it left on
/// its ring; then drains both sides and closes.
fn backpressure(eal: &Eal, names: [&str; 2], queued: usize, mode: Mode) -> (Turn, Vec<Vec<u8>>) {
    let configs = [
        config(Side::A),
        StackConfig {
            max_udp_sockets: 0,
            tx_pending: 2,
            ..config(Side::B)
        },
    ];
    let mut pair = Pair::with_pools(
        eal,
        names,
        configs,
        T0,
        4,
        rx_pool_count(rx_reserve(16, configs[0].rx_staging, 8), 1500, [4096]),
        63,
    );
    let ([a, b], _) = establish(&mut pair, Side::A);
    let now = pair.now();
    pair.b_to_a.paused = true;
    for _ in 0..queued {
        assert_eq!(pair.b.tcp_mut(&b).send_slice(b"q"), Ok(1));
        assert_eq!(pair.b.turn(now, BUDGET).unwrap().tx_accepted, 1);
    }
    assert_eq!(pair.b.tcp_mut(&b).send_slice(b"late"), Ok(4));
    a_sends(&mut pair, &a, now, b"1");
    a_sends(&mut pair, &a, now, b"2");
    swap_next_two(&mut pair.a_to_b);
    assert_eq!(pair.a_to_b.forward(), 2);

    let turn = step(&mut pair.b, mode, now);
    pair.b_to_a.paused = false;
    let ring = payloads(&forward(&mut pair.b_to_a), Side::B);

    // A's RX ring is full: A takes it, B sends what is left, A takes that.
    pair.a.turn(now, BUDGET).unwrap();
    assert_eq!(pair.b.turn(now, BUDGET).unwrap().tx_pending, 0);
    pair.b_to_a.forward();
    pair.a.turn(now, BUDGET).unwrap();
    assert_eq!(pair.close(), 0);
    (turn, ring)
}

/// Ingress fills the pending queue. `turn` cannot queue `late` until its final
/// flush; `receive` flushes first, so `send` queues it in the same iteration.
/// With room on the TX ring it leaves (`tx_accepted` 3, not 2); with the ring
/// full it stays pending (`tx_pending` 1, not 0). Nothing else differs.
#[zhida_test_support::pinned_test]
fn receive_flush_differs_from_turn_only_under_backpressure() {
    with_eal(|eal| {
        let acks = Turn {
            rx_received: 2,
            rx_processed: 2,
            tx_accepted: 2,
            ..IDLE
        };

        // TX ring with room for 3.
        let (turned, ring) = backpressure(eal, ["bp0a", "bp0b"], 0, Mode::Turn);
        assert_eq!(turned, acks);
        assert_eq!(ring, [Vec::<u8>::new(), vec![]]);
        let (split, ring) = backpressure(eal, ["bp1a", "bp1b"], 0, Mode::Split);
        assert_eq!(
            split,
            Turn {
                tx_accepted: 3,
                ..acks
            }
        );
        assert_eq!(ring, [Vec::new(), vec![], b"late".to_vec()]);

        // TX ring with room for 2.
        let (turned, ring) = backpressure(eal, ["bp2a", "bp2b"], 1, Mode::Turn);
        assert_eq!(turned, acks);
        assert_eq!(ring, [b"q".to_vec(), vec![], vec![]]);
        let (split, ring) = backpressure(eal, ["bp3a", "bp3b"], 1, Mode::Split);
        assert_eq!(
            split,
            Turn {
                tx_pending: 1,
                ..acks
            }
        );
        assert_eq!(ring, [b"q".to_vec(), vec![], vec![]]);
    });
}

/// `send` after a `turn`, with no `receive`, sends what the application wrote
/// at that turn's time, though A ran later on this thread. A second `send`
/// with nothing new sends nothing.
#[zhida_test_support::pinned_test]
fn send_alone_and_repeated() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["sola", "solb"]);
        let ([_a, b], _) = establish(&mut pair, Side::A);
        let at = pair.now() + ms(7);
        let later = at + ms(50);
        assert_eq!(pair.b.turn(at, BUDGET), Ok(IDLE));
        assert_eq!(pair.a.turn(later, BUDGET), Ok(IDLE));

        assert_eq!(pair.b.tcp_mut(&b).send_slice(b"solo"), Ok(4));
        assert_eq!(pair.b.send(), Ok(SENT_ONE));
        let sent = forward(&mut pair.b_to_a);
        assert_eq!(payloads(&sent, Side::B), [b"solo"]);
        assert_eq!(segment(&sent[0], Side::B).timestamp, None);

        assert_eq!(
            pair.b.send(),
            Ok(Sent {
                tx_accepted: 0,
                tx_pending: 0,
            })
        );
        assert!(forward(&mut pair.b_to_a).is_empty());

        assert_eq!(
            pair.a.turn(later, BUDGET),
            Ok(Turn {
                rx_received: 1,
                rx_processed: 1,
                ..IDLE
            })
        );
        assert_eq!(pair.close(), 0);
    });
}
