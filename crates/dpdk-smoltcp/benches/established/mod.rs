//! The established_tcp_turn round over a Pair, shared by the stack and
//! scaling benches; benches/stack.rs describes the round, its warmup and its
//! checks.

use std::hint::black_box;

use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::socket::tcp::State;
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::smoltcp::wire::{EthernetFrame, EthernetProtocol, TcpControl, TCP_HEADER_LEN};
use dpdk_smoltcp::Turn;

use zhida_test_kit::pair::{establish_sized, pattern, segment, App, Dir, Pair, Side, BUDGET};

/// Frames per TCP round: the Pair ports' RX burst, so B takes them in one turn.
pub const SEGMENTS: usize = 8;
/// Payload bytes per batch unit, independent of the negotiated send MSS.
pub const MSS: usize = 1448;
const OFFERED_MSS: u16 = 1460;
pub const CHUNK: usize = SEGMENTS * MSS;
/// A holds the unacknowledged `CHUNK` plus the next write; the third `CHUNK`
/// keeps B's window update off: after B reads, its window goes from 2 to 3
/// `CHUNK`s, short of the doubling smoltcp's `window_to_update` needs (with
/// 2 `CHUNK`s it doubles, leaving a window update pending every round). A
/// whole number of batches: smoltcp cuts a segment at the end of the TX
/// ring buffer, so each batch must end before the ring wraps.
pub const TCP_BUFFER: usize = 3 * CHUNK;
pub const SETTLE_ROUNDS: usize = 2 * TCP_BUFFER / CHUNK;

pub fn expected_turn(
    rx_processed: usize,
    tx_accepted: usize,
) -> (usize, usize, usize, usize, usize) {
    (rx_processed, 0, rx_processed, 0, tx_accepted)
}

/// (received, rejected, processed, still staged, accepted), with nothing
/// left pending and ingress not blocked.
pub fn turn_counts(turn: &Turn) -> (usize, usize, usize, usize, usize) {
    assert_eq!((turn.rx_blocked, turn.tx_pending), (false, 0), "{turn:?}");
    (
        turn.rx_received,
        turn.rx_rejected,
        turn.rx_processed,
        turn.rx_staged,
        turn.tx_accepted,
    )
}

/// Both SYNs offer `OFFERED_MSS`; the final ACK determines the option size.
fn check_handshake(frames: &[(Dir, Vec<u8>)]) -> usize {
    let syns: Vec<_> = frames
        .iter()
        .filter(|(_, frame)| {
            EthernetFrame::new_checked(frame).unwrap().ethertype() == EthernetProtocol::Ipv4
        })
        .filter_map(|(dir, frame)| {
            let side = if *dir == Dir::AToB { Side::A } else { Side::B };
            let tcp = segment(frame, side);
            (tcp.control == TcpControl::Syn).then_some((side, tcp))
        })
        .collect();
    let offer = Some(OFFERED_MSS);
    assert_eq!(syns.len(), 2);
    assert_eq!((syns[0].0, syns[1].0), (Side::A, Side::B));
    assert_eq!((syns[0].1.max_seg_size, syns[1].1.max_seg_size), (offer, offer));
    assert_eq!(syns[0].1.ack_number, None);
    assert_eq!(syns[1].1.ack_number, Some(syns[0].1.seq_number + 1));
    let (dir, frame) = frames.last().expect("handshake ACK");
    assert_eq!(*dir, Dir::AToB);
    let ack = segment(frame, Side::A);
    assert_eq!(ack.control, TcpControl::None);
    assert!(ack.payload.is_empty());
    assert_eq!(ack.seq_number, syns[0].1.seq_number + 1);
    assert_eq!(ack.ack_number, Some(syns[1].1.seq_number + 1));
    let options = ack
        .header_len()
        .checked_sub(TCP_HEADER_LEN)
        .expect("TCP header");
    usize::from(syns[1].1.max_seg_size.unwrap())
        .checked_sub(options)
        .expect("MSS includes room for TCP options")
}

/// A's client and B's server, and the round's time once warmed up.
pub struct Established {
    /// Client then server.
    pub handles: [TcpHandle; 2],
    now: Instant,
    pub send_mss: usize,
    payload: Vec<u8>,
    sink: Vec<u8>,
}

impl Established {
    /// A's client connects to a listener on B, both with `TCP_BUFFER`-byte
    /// buffers, and the handshake is checked; both sockets are then idle.
    pub fn connect(pair: &mut Pair) -> Self {
        let (handles, frames) = establish_sized(pair, Side::A, TCP_BUFFER);
        let send_mss = check_handshake(&frames);
        assert!(MSS <= send_mss, "payload chunk exceeds send MSS");
        assert_eq!(pair.a.tcp(&handles[0]).state(), State::Established);
        assert_eq!(pair.b.tcp(&handles[1]).state(), State::Established);
        Self {
            handles,
            now: pair.now(),
            send_mss,
            payload: pattern(CHUNK, 7),
            sink: vec![0; CHUNK],
        }
    }

    /// Untimed: drive rounds until one carries a whole `CHUNK` as `SEGMENTS`
    /// segments and one ACK, leaving A with that `CHUNK` unacknowledged, and
    /// A writes the next `CHUNK`, as every steady round ends; the largest
    /// A->B payload must reach the negotiated send MSS, every B->A frame a
    /// pure ACK, and every byte B reads must continue the stream of
    /// `payload` copies. Then
    /// `SETTLE_ROUNDS` steady rounds at the final time, each read equal to
    /// `payload` and ending with B's `poll_at` None. `observe` sees every
    /// frame the first part delivers.
    pub fn warm_up(&mut self, pair: &mut Pair, mut observe: impl FnMut(Dir, &[u8])) {
        let [client, server] = &self.handles;
        let (payload, sink) = (&self.payload, &mut self.sink);
        let mut largest = 0;
        let mut received = 0;
        pair.drive_rounds(
            |dir, frame| {
                let len = segment(frame, if dir == Dir::AToB { Side::A } else { Side::B })
                    .payload
                    .len();
                match dir {
                    Dir::AToB => largest = largest.max(len),
                    Dir::BToA => assert_eq!(len, 0, "B sent payload"),
                }
                observe(dir, frame);
            },
            |round, a, b| {
                let mut read = 0usize;
                while let Some(frame) = b.tcp_mut(&server).recv().unwrap() {
                    let end = read.checked_add(frame.payload().len()).expect("read bytes");
                    sink[read..end].copy_from_slice(frame.payload());
                    read = end;
                }
                for (offset, &byte) in sink[..read].iter().enumerate() {
                    assert_eq!(byte, payload[(received + offset) % CHUNK]);
                }
                received += read;
                let queued = a.tcp_mut(&client).send_queue();
                let steady = round.a_to_b == SEGMENTS
                    && round.b_to_a == 1
                    && read == CHUNK
                    && queued == CHUNK;
                if steady || queued == 0 {
                    assert_eq!(a.tcp_mut(&client).send_slice(payload), Ok(CHUNK));
                }
                match (steady, queued) {
                    (true, _) => App::Done,
                    (false, 0) => App::Moved,
                    _ if read > 0 => App::Moved,
                    _ => App::Idle,
                }
            },
        );
        assert_eq!(largest, self.send_mss);
        assert_eq!(received % CHUNK, 0);
        self.now = pair.now();
        for _ in 0..SETTLE_ROUNDS {
            self.round(pair);
            assert_eq!(self.sink, self.payload);
            assert_eq!(pair.b.poll_at(), None);
        }
    }

    /// The timed round: A turn, Link A->B, B turn, Link B->A, all at the
    /// warmup's final time, each moving exactly the steady frames; then A
    /// writes and B reads one `CHUNK`.
    pub fn round(&mut self, pair: &mut Pair) {
        let [client, server] = &self.handles;
        let turn_a = pair.a.turn(self.now, BUDGET).unwrap();
        let a_to_b = pair.a_to_b.forward();
        let turn_b = pair.b.turn(self.now, BUDGET).unwrap();
        let b_to_a = pair.b_to_a.forward();
        assert_eq!(turn_counts(black_box(&turn_a)), expected_turn(1, SEGMENTS));
        assert_eq!(turn_counts(black_box(&turn_b)), expected_turn(SEGMENTS, 1));
        assert_eq!((a_to_b, b_to_a), (SEGMENTS, 1));
        assert_eq!(pair.a.tcp_mut(&client).send_slice(&self.payload), Ok(CHUNK));
        let mut read = 0usize;
        while let Some(frame) = pair.b.tcp_mut(&server).recv().unwrap() {
            let end = read.checked_add(frame.payload().len()).expect("read bytes");
            self.sink[read..end].copy_from_slice(frame.payload());
            read = end;
        }
        assert_eq!(read, CHUNK);
        black_box(&*self.sink);
    }
}
