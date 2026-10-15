use zhida_test_kit::pair::{BUDGET, CLIENT_PORT, SERVER_PORT, Side, pattern, segment};
use zhida_test_kit::with_eal;
use dpdk_smoltcp::Turn;
use dpdk_smoltcp::smoltcp::wire::TcpControl;

#[allow(dead_code)]
#[path = "../benches/rx/mod.rs"]
mod rx;

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

#[zhida_test_support::pinned_test]
fn rx_append_returns_incoming_frames_to_pool() {
    with_eal(|eal| {
        let k = 8usize;
        let buffer = 3usize
            .checked_mul(k)
            .expect("buffer segments")
            .checked_mul(1448)
            .expect("socket buffer");
        // Segments of at most 64 bytes are copied into the first frame's tailroom;
        // larger ones keep their own frame.
        for (seg, held) in [(64usize, 1u32), (65, 8), (200, 8), (512, 8), (1448, 8)] {
            let batch = k.checked_mul(seg).expect("batch bytes");
            let payload = pattern(batch, 7);
            let (mut pair, handles) = rx::setup(eal, k, buffer);
            let [client, server] = handles;
            let now = pair.now();
            if seg == rx::MSS {
                assert_eq!(pair.a.tcp_mut(&client).send_slice(&payload), Ok(batch));
                assert_turn(pair.a.turn(now, BUDGET).unwrap(), 0, k);
            } else {
                for bytes in payload.chunks_exact(seg) {
                    assert_eq!(pair.a.tcp_mut(&client).send_slice(bytes), Ok(seg));
                    assert_turn(pair.a.turn(now, BUDGET).unwrap(), 0, 1);
                }
            }
            assert_eq!(pair.in_use()[1].0, 0, "B RX pool before forwarding");
            let mut offset = 0usize;
            let mut ack = None;
            let count = pair.a_to_b.forward_with(|frame| {
                let len = if seg == rx::MSS { 1460.min(batch - offset) } else { seg };
                let end = offset.checked_add(len).expect("data frame offset");
                assert_eq!(frame.len(), 54usize.checked_add(len).expect("frame bytes"));
                let tcp = segment(frame, Side::A);
                assert_eq!((tcp.src_port, tcp.dst_port), (CLIENT_PORT, SERVER_PORT));
                assert_eq!(tcp.payload, &payload[offset..end]);
                assert_eq!(
                    tcp.control,
                    if seg < rx::MSS || end == batch {
                        TcpControl::Psh
                    } else {
                        TcpControl::None
                    }
                );
                assert!(tcp.ack_number.is_some(), "data frame has no ACK flag");
                assert_eq!(tcp.timestamp, None);
                if let Some(expected) = ack {
                    assert_eq!(tcp.seq_number, expected, "in-order data sequence");
                }
                ack = Some(tcp.seq_number + len);
                offset = end;
            });
            assert_eq!(count, k, "A→B frame count");
            assert_eq!(offset, batch);
            assert_eq!(pair.in_use()[1].0, 8, "B RX pool after forwarding");
            assert_turn(pair.b.turn(now, BUDGET).unwrap(), k, 1);
            assert_eq!(pair.in_use()[1].0, held, "B RX pool after turn, seg={seg}");
            assert_eq!(pair.b.tcp(&server).recv_queue(), batch);
            let mut sink = vec![0; batch];
            let mut read = 0usize;
            let mut views = 0u32;
            while let Some(frame) = pair.b.tcp_mut(&server).recv().unwrap() {
                let bytes = frame.payload();
                assert!(!bytes.is_empty(), "empty held frame");
                let end = read.checked_add(bytes.len()).expect("read bytes");
                assert_eq!(bytes, &payload[read..end]);
                sink[read..end].copy_from_slice(bytes);
                read = end;
                views = views.checked_add(1).expect("held frames");
            }
            assert_eq!(read, batch);
            assert_eq!(views, held);
            assert_eq!(sink, payload);
            assert_eq!(pair.in_use()[1].0, 0, "B RX pool after read");
            let expected = ack.expect("data frames");
            let count = pair.b_to_a.forward_with(|frame| {
                assert_eq!(frame.len(), 54);
                let tcp = segment(frame, Side::B);
                assert_eq!((tcp.src_port, tcp.dst_port), (SERVER_PORT, CLIENT_PORT));
                assert_eq!(tcp.control, TcpControl::None);
                assert!(tcp.payload.is_empty(), "ACK frame has payload");
                assert_eq!(tcp.timestamp, None);
                assert_eq!(tcp.ack_number, Some(expected));
            });
            assert_eq!(count, 1, "B→A frame count");
            assert_turn(pair.a.turn(now, BUDGET).unwrap(), 1, 0);
            assert_eq!(pair.a_to_b.forward(), 0, "extra A→B frame after ACK");
            for (stack, handle) in [(&pair.a, client), (&pair.b, server)] {
                let socket = stack.tcp(&handle);
                assert_eq!((socket.send_queue(), socket.recv_queue()), (0, 0));
            }
            rx::close(pair);
        }
    });
}
