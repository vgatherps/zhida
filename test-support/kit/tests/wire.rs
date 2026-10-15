//! The copying wire: exact bytes and order each way, impairment verdicts,
//! pause, and loss counted under RX ring and pool pressure, without leaks.

use std::collections::VecDeque;

use zhida_test_kit::ring_port::{frame, send, RingPort};
use zhida_test_kit::wire::{Link, Verdict};
use zhida_test_kit::with_eal;
use dpdk_smoltcp::Port;
use zhida_dpdk_sys::{dpdk_raw_pktmbuf_alloc, dpdk_raw_pktmbuf_free};

/// (pool_empty, ring_full, dropped, held).
fn counts(link: &Link) -> (u64, u64, u64, u64) {
    (link.pool_empty, link.ring_full, link.dropped, link.held)
}

/// Every frame on the port's RX ring, in order, released.
fn receive(port: &mut Port) -> Vec<Vec<u8>> {
    let mut staged = VecDeque::with_capacity(16);
    let mut frames = Vec::new();
    loop {
        let burst = port.rx_burst(&mut staged).unwrap();
        assert_eq!(burst.rejected, 0);
        if burst.accepted == 0 {
            return frames;
        }
        frames.extend(staged.drain(..).map(|packet| packet.data().to_vec()));
    }
}

/// `4 + value` bytes starting at `value * 16`.
fn sized(value: u8) -> Vec<u8> {
    (0..4 + value).map(|offset| value * 16 + offset).collect()
}

#[zhida_test_support::pinned_test]
fn link_duplicates_each_frame_in_order_without_leak() {
    with_eal(|eal| {
        let sender = RingPort::new("dups", 32, 32);
        let receiver = RingPort::new("dupr", 32, 32);
        let mut sender_port = sender.open(eal);
        let mut receiver_port = receiver.open(eal);
        let mut link = sender.link_to(&receiver);
        link.impair(|_| Verdict::Duplicate);

        let sent: Vec<_> = (0..12).map(sized).collect();
        let expected: Vec<_> = sent.iter().flat_map(|bytes| [bytes.clone(), bytes.clone()]).collect();
        send(&mut sender_port, &sent);
        let mut observed = Vec::new();
        assert_eq!(link.forward_with(|bytes| observed.push(bytes.to_vec())), sent.len());
        assert_eq!(observed, expected);
        assert_eq!(counts(&link), (0, 0, 0, 0));
        assert_eq!(sender.in_use(), (0, 0));
        assert_eq!(receiver.in_use(), (24, 0));
        assert_eq!(receive(&mut receiver_port), expected);
        assert_eq!(receiver.in_use(), (0, 0));

        link.impair(|bytes| if bytes[0] == 30 { Verdict::Hold } else { Verdict::Duplicate });
        send(&mut sender_port, &[frame(30), frame(31)]);
        assert_eq!(link.forward(), 2);
        assert_eq!(receive(&mut receiver_port), [frame(31), frame(30), frame(31)]);
        assert_eq!(counts(&link), (0, 0, 0, 1));
        assert!(!link.free_held());
        assert_eq!((sender.in_use(), receiver.in_use()), ((0, 0), (0, 0)));

        link.impair(|_| Verdict::Duplicate);
        let pool = receiver.rx_pool();
        let taken: Vec<_> = (0..62).map(|_| unsafe { dpdk_raw_pktmbuf_alloc(pool) }).collect();
        assert!(taken.iter().all(|packet| !packet.is_null()));
        send(&mut sender_port, &[frame(40)]);
        assert_eq!(link.forward(), 1);
        assert_eq!(counts(&link), (1, 0, 0, 1));
        assert_eq!(receive(&mut receiver_port), [frame(40)]);
        for packet in taken {
            unsafe { dpdk_raw_pktmbuf_free(packet) };
        }
        assert_eq!(receiver.in_use(), (0, 0));

        let queued: Vec<_> = (100..130).map(frame).collect();
        receiver.inject(&queued);
        send(&mut sender_port, &[frame(41)]);
        assert_eq!(link.forward(), 1);
        assert_eq!(counts(&link), (1, 1, 0, 1));
        assert_eq!(receive(&mut receiver_port), [&queued[..], &[frame(41)]].concat());
        assert_eq!((sender.in_use(), receiver.in_use()), ((0, 0), (0, 0)));

        drop(link);
        sender_port.try_close().unwrap();
        receiver_port.try_close().unwrap();
        sender.close();
        receiver.close();
    });
}

#[zhida_test_support::pinned_test]
fn link_copies_exact_bytes_each_way_into_the_receivers_pool() {
    with_eal(|eal| {
        let fixtures = [RingPort::new("wire_a", 16, 16), RingPort::new("wire_b", 16, 16)];
        let [a, b] = &fixtures;
        let mut ports = fixtures.each_ref().map(|fixture| fixture.open(eal));

        // A → B: in order, exact bytes, each pool holding only its own packets.
        let sent: Vec<_> = (0..5).map(sized).collect();
        send(&mut ports[0], &sent);
        assert_eq!(a.in_use(), (0, 5));
        let mut a_to_b = a.link_to(b);
        assert_eq!(a_to_b.forward(), 5);
        assert_eq!((a_to_b.pool_empty, a_to_b.ring_full), (0, 0));
        assert_eq!((a.in_use(), b.in_use()), ((0, 0), (5, 0)));
        assert_eq!(receive(&mut ports[1]), sent);
        assert_eq!(b.in_use(), (0, 0));

        // B → A.
        let sent = vec![sized(7), sized(8)];
        send(&mut ports[1], &sent);
        let mut b_to_a = b.link_to(a);
        assert_eq!(b_to_a.forward(), 2);
        assert_eq!((b_to_a.pool_empty, b_to_a.ring_full), (0, 0));
        assert_eq!((b.in_use(), a.in_use()), ((0, 0), (2, 0)));
        assert_eq!(receive(&mut ports[0]), sent);
        assert_eq!(a.in_use(), (0, 0));

        drop((a_to_b, b_to_a));
        for port in ports {
            port.try_close().unwrap();
        }
        for fixture in fixtures {
            fixture.close();
        }
    });
}

#[zhida_test_support::pinned_test]
fn link_drop_hold_pause_counted_without_leak() {
    with_eal(|eal| {
        let sender = RingPort::new("lis", 16, 16);
        let receiver = RingPort::new("lir", 16, 16);
        let mut sender_port = sender.open(eal);
        let mut receiver_port = receiver.open(eal);
        let mut link = sender.link_to(&receiver);
        // `frame(tag)` starts with `tag`.
        link.impair(|bytes| match bytes[0] {
            1 => Verdict::Drop,
            2 | 20 => Verdict::Hold,
            _ => Verdict::Deliver,
        });

        let sent: Vec<_> = (0..6).map(frame).collect();
        send(&mut sender_port, &sent);
        let mut delivered = Vec::new();
        assert_eq!(link.forward_with(|bytes| delivered.push(bytes[0])), 6);
        assert_eq!(delivered, [0, 3, 2, 4, 5]);
        assert_eq!(counts(&link), (0, 0, 1, 1));
        assert_eq!(sender.in_use(), (0, 0));
        let expected: Vec<_> = [0, 3, 2, 4, 5].map(frame).into();
        assert_eq!(receive(&mut receiver_port), expected);
        assert_eq!(receiver.in_use(), (0, 0));

        // Paused: the frames stay on the sender's TX ring.
        link.paused = true;
        let sent: Vec<_> = (10..13).map(frame).collect();
        send(&mut sender_port, &sent);
        assert_eq!(link.forward(), 0);
        assert_eq!(sender.in_use(), (0, 3));
        assert_eq!(receiver.in_use(), (0, 0));
        link.paused = false;
        assert_eq!(link.forward(), 3);
        assert_eq!(sender.in_use(), (0, 0));
        assert_eq!(receive(&mut receiver_port), sent);

        // A hold with no later frame stays in the receiver's pool until freed.
        send(&mut sender_port, &[frame(20)]);
        assert_eq!(link.forward(), 1);
        assert_eq!(counts(&link), (0, 0, 1, 2));
        assert_eq!(receiver.in_use(), (1, 0));
        assert!(receive(&mut receiver_port).is_empty());
        assert!(link.free_held());
        assert!(!link.free_held());
        assert_eq!(receiver.in_use(), (0, 0));

        sender_port.try_close().unwrap();
        receiver_port.try_close().unwrap();
        sender.close();
        receiver.close();
    });
}

#[zhida_test_support::pinned_test]
fn link_held_frame_under_ring_and_pool_pressure() {
    with_eal(|eal| {
        let sender = RingPort::new("lps", 16, 16);
        let receiver = RingPort::new("lpr", 16, 16);
        let mut sender_port = sender.open(eal);
        let mut receiver_port = receiver.open(eal);
        let mut link = sender.link_to(&receiver);
        link.impair(|bytes| if bytes[0] % 10 == 1 { Verdict::Hold } else { Verdict::Deliver });

        // One RX ring slot free: the next frame takes it, the held copy finds
        // the ring full and is freed and counted.
        let queued: Vec<_> = (100..114).map(frame).collect();
        receiver.inject(&queued);
        send(&mut sender_port, &[frame(1), frame(2)]);
        let mut delivered = Vec::new();
        assert_eq!(link.forward_with(|bytes| delivered.push(bytes[0])), 2);
        assert_eq!(delivered, [2]);
        assert_eq!(counts(&link), (0, 1, 0, 1));
        assert_eq!((sender.in_use(), receiver.in_use()), ((0, 0), (15, 0)));
        assert!(!link.free_held());
        assert_eq!(receive(&mut receiver_port), [&queued[..], &[frame(2)]].concat());
        assert_eq!(receiver.in_use(), (0, 0));

        // RX pool empty: the next frame is dropped and counted, the held copy
        // stays and follows the frame after once the pool has room.
        send(&mut sender_port, &[frame(11)]);
        assert_eq!(link.forward(), 1);
        assert_eq!(receiver.in_use(), (1, 0));
        let pool = receiver.rx_pool();
        let mut taken = Vec::new();
        loop {
            let packet = unsafe { dpdk_raw_pktmbuf_alloc(pool) };
            if packet.is_null() {
                break;
            }
            taken.push(packet);
        }
        assert_eq!((taken.len(), receiver.in_use()), (62, (63, 0)));
        send(&mut sender_port, &[frame(12)]);
        assert_eq!(link.forward_with(|bytes| delivered.push(bytes[0])), 1);
        assert_eq!(counts(&link), (1, 1, 0, 2));
        for packet in taken {
            unsafe { dpdk_raw_pktmbuf_free(packet) };
        }
        assert_eq!(receiver.in_use(), (1, 0));
        send(&mut sender_port, &[frame(13)]);
        assert_eq!(link.forward_with(|bytes| delivered.push(bytes[0])), 1);
        assert_eq!(delivered, [2, 13, 11]);
        assert_eq!(counts(&link), (1, 1, 0, 2));
        assert_eq!(receive(&mut receiver_port), [frame(13), frame(11)]);
        assert_eq!((sender.in_use(), receiver.in_use()), ((0, 0), (0, 0)));
        assert!(!link.free_held());

        // RX pool empty when a frame is to be held: counted, nothing held.
        let taken: Vec<_> = (0..63).map(|_| unsafe { dpdk_raw_pktmbuf_alloc(pool) }).collect();
        assert!(taken.iter().all(|packet| !packet.is_null()));
        assert_eq!(receiver.in_use(), (63, 0));
        send(&mut sender_port, &[frame(21)]);
        assert_eq!(link.forward(), 1);
        assert_eq!(counts(&link), (2, 1, 0, 2));
        assert!(!link.free_held());
        for packet in taken {
            unsafe { dpdk_raw_pktmbuf_free(packet) };
        }
        assert_eq!((sender.in_use(), receiver.in_use()), ((0, 0), (0, 0)));
        assert!(receive(&mut receiver_port).is_empty());

        sender_port.try_close().unwrap();
        receiver_port.try_close().unwrap();
        sender.close();
        receiver.close();
    });
}

#[zhida_test_support::pinned_test]
fn link_counts_drops_without_leak() {
    with_eal(|eal| {
        let sender = RingPort::new("lks", 16, 16);
        let receiver = RingPort::new("lkr", 16, 16);
        let mut sender_port = sender.open(eal);
        let mut receiver_port = receiver.open(eal);
        let mut link = sender.link_to(&receiver);

        // Receiver ring has room for 5 of 15 frames, more than one link burst.
        let queued: Vec<_> = (100..110).map(frame).collect();
        receiver.inject(&queued);
        let sent: Vec<_> = (0..15).map(frame).collect();
        send(&mut sender_port, &sent);
        assert_eq!(sender.in_use(), (0, 15));
        assert_eq!(link.forward(), 15);
        assert_eq!((link.pool_empty, link.ring_full), (0, 10));
        assert_eq!(sender.in_use(), (0, 0));
        assert_eq!(receiver.in_use(), (15, 0));
        assert_eq!(receive(&mut receiver_port), [&queued[..], &sent[..5]].concat());
        assert_eq!(receiver.in_use(), (0, 0));

        // Receiver pool has room for 2 of 5 frames.
        let pool = receiver.rx_pool();
        let mut held = Vec::new();
        loop {
            let packet = unsafe { dpdk_raw_pktmbuf_alloc(pool) };
            if packet.is_null() {
                break;
            }
            held.push(packet);
        }
        assert_eq!(receiver.in_use(), (63, 0));
        for packet in held.drain(..2) {
            unsafe { dpdk_raw_pktmbuf_free(packet) };
        }
        let sent: Vec<_> = (20..25).map(frame).collect();
        send(&mut sender_port, &sent);
        assert_eq!(link.forward(), 5);
        assert_eq!((link.pool_empty, link.ring_full), (3, 10));
        assert_eq!(sender.in_use(), (0, 0));
        assert_eq!(receiver.in_use(), (63, 0));
        assert_eq!(receive(&mut receiver_port), sent[..2]);
        for packet in held {
            unsafe { dpdk_raw_pktmbuf_free(packet) };
        }
        assert_eq!(receiver.in_use(), (0, 0));

        sender_port.try_close().unwrap();
        receiver_port.try_close().unwrap();
        sender.close();
        receiver.close();
    });
}

#[zhida_test_support::pinned_test]
fn link_inject_copies_into_destination_pool_without_leak() {
    with_eal(|eal| {
        let sender = RingPort::new("injs", 16, 16);
        let receiver = RingPort::new("injr", 16, 16);
        let sender_port = sender.open(eal);
        let mut receiver_port = receiver.open(eal);
        let mut link = sender.link_to(&receiver);
        let sent = frame(7);
        link.inject(&sent);
        assert_eq!((sender.in_use(), receiver.in_use()), ((0, 0), (1, 0)));
        assert_eq!(receive(&mut receiver_port), [sent]);
        assert_eq!(counts(&link), (0, 0, 0, 0));
        assert_eq!(receiver.in_use(), (0, 0));

        let queued: Vec<_> = (100..115).map(frame).collect();
        receiver.inject(&queued);
        link.inject(&frame(8));
        assert_eq!(counts(&link), (0, 1, 0, 0));
        assert_eq!(receiver.in_use(), (15, 0));
        assert_eq!(receive(&mut receiver_port), queued);

        let pool = receiver.rx_pool();
        let taken: Vec<_> = (0..63)
            .map(|_| unsafe { dpdk_raw_pktmbuf_alloc(pool) })
            .collect();
        assert!(taken.iter().all(|packet| !packet.is_null()));
        link.inject(&frame(9));
        assert_eq!(counts(&link), (1, 1, 0, 0));
        assert!(receive(&mut receiver_port).is_empty());
        for packet in taken {
            unsafe { dpdk_raw_pktmbuf_free(packet) };
        }
        assert_eq!((sender.in_use(), receiver.in_use()), ((0, 0), (0, 0)));
        drop(link);
        sender_port.try_close().unwrap();
        receiver_port.try_close().unwrap();
        sender.close();
        receiver.close();
    });
}
