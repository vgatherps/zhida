//! A test that panics while holding kit fixtures keeps its own panic message
//! and leaves every ring, vdev and pool name reusable; a fixture dropped
//! without its close fails the test after cleaning up.

use std::any::Any;
use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr::null_mut;

use zhida_test_kit::pair::{
    ceil_ms, config, establish, new_pair, tcp_socket_sized, Side, CLIENT_PORT, SERVER_PORT, T0,
};
use zhida_test_kit::ring_port::{frame, send, RingPort};
use zhida_test_kit::wire::{copy_into, in_use, pool_exists, Verdict};
use zhida_test_kit::with_eal;
use dpdk_smoltcp::smoltcp::time::Duration;
use dpdk_smoltcp::smoltcp::wire::IpEndpoint;
use dpdk_smoltcp::{Port, Stack};
use zhida_dpdk_sys::{
    dpdk_raw_pktmbuf_free, dpdk_raw_ring_dequeue_burst, rte_ring_create, zhida_errno,
    RTE_PKTMBUF_HEADROOM,
};

fn message(payload: Box<dyn Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => payload.downcast_ref::<&str>().unwrap().to_string(),
    }
}

fn close_ports(ports: [Port; 2], fixtures: [RingPort; 2]) {
    for port in ports {
        port.try_close().unwrap();
    }
    for fixture in fixtures {
        fixture.close();
    }
}

#[zhida_test_support::pinned_test]
fn pair_unwind_with_frames_on_rings_and_a_held_frame_releases_every_name() {
    let names = ["td_pair_a", "td_pair_b"];
    with_eal(|eal| {
        let payload = catch_unwind(AssertUnwindSafe(|| {
            let mut pair = new_pair(eal, names);
            let mut verdicts = [Verdict::Hold, Verdict::Deliver, Verdict::Hold].into_iter();
            pair.a_to_b.impair(move |_| verdicts.next().unwrap());
            let client = pair.a.add_tcp(tcp_socket_sized(4096)).unwrap();
            let server = IpEndpoint::new(Side::B.ip().into(), SERVER_PORT);
            pair.a.connect(&client, server, CLIENT_PORT).unwrap();
            // A's SYN is held; its first retransmission is delivered with the
            // held SYN behind it onto B's RX ring; the second is held.
            assert_eq!(pair.a.turn(T0, 32).unwrap().tx_accepted, 1);
            assert_eq!(pair.a_to_b.forward(), 1);
            for _ in 0..2 {
                let bound = ceil_ms(pair.now() + Duration::from_secs(1));
                assert_eq!(pair.turn_until_sent(Side::A, bound).tx_accepted, 1);
                assert_eq!(pair.a_to_b.forward(), 1);
            }
            // The third retransmission stays on A's TX ring.
            let bound = ceil_ms(pair.now() + Duration::from_secs(1));
            assert_eq!(pair.turn_until_sent(Side::A, bound).tx_accepted, 1);
            assert_eq!(pair.a_to_b.held, 2);
            assert_eq!(pair.in_use(), [(0, 1), (3, 0)]);
            panic!("original pair panic");
        }))
        .unwrap_err();
        assert_eq!(message(payload), "original pair panic");

        let mut pair = new_pair(eal, names);
        let (_handles, _) = establish(&mut pair, Side::A);
        assert_eq!(pair.close(), 0);
    });
}

#[zhida_test_support::pinned_test]
fn ring_port_unwind_frees_queued_frames_and_releases_rings_and_vdev() {
    with_eal(|eal| {
        let payload = catch_unwind(AssertUnwindSafe(|| {
            let fixture = RingPort::new("td_unwind", 16, 16);
            let _stack = match Stack::new(fixture.open(eal), config(Side::A), T0) {
                Ok(stack) => stack,
                Err((_, error)) => panic!("{error}"),
            };
            fixture.inject(&[frame(1), frame(2), frame(3)]);
            assert_eq!(fixture.in_use(), (3, 0));
            panic!("original ring port panic");
        }))
        .unwrap_err();
        assert_eq!(message(payload), "original ring port panic");

        // The Stack dropped first: Port::drop closed the device, found the
        // three frames still on the RX ring and kept both pools. The fixture
        // then freed those frames into the kept RX pool.
        for name in [c"td_unwind_rxp", c"td_unwind_txp"] {
            assert!(pool_exists(name));
        }
        assert_eq!(in_use(c"td_unwind_rxp"), 0);
        RingPort::new("td_unwind", 16, 16).close();
    });
}

#[zhida_test_support::pinned_test]
fn ring_port_dropped_without_close_fails_after_cleanup() {
    with_eal(|_| {
        let payload =
            catch_unwind(AssertUnwindSafe(|| drop(RingPort::new("td_drop", 16, 16)))).unwrap_err();
        assert_eq!(message(payload), "RingPort net_ring_td_drop dropped without close");
        RingPort::new("td_drop", 16, 16).close();
    });
}

#[zhida_test_support::pinned_test]
fn ring_port_dropped_under_a_live_port_leaves_the_device_to_it() {
    with_eal(|eal| {
        let fixture = RingPort::new("td_live", 16, 16);
        let mut port = fixture.open(eal);
        let tx_ring = fixture.tx_ring();
        let payload = catch_unwind(AssertUnwindSafe(|| drop(fixture))).unwrap_err();
        assert_eq!(message(payload), "RingPort net_ring_td_live dropped without close");
        // Both rings still exist: creating either name again fails.
        for name in [c"td_live_rxr", c"td_live_txr"] {
            let ring = unsafe { rte_ring_create(name.as_ptr(), 16, -1, 0) };
            assert!(ring.is_null());
            assert_eq!(unsafe { zhida_errno() }, libc::EEXIST);
        }
        // The Port still sends onto its TX ring, then closes and frees its
        // pools. The vdev and rings stay leaked: this name is never reused.
        send(&mut port, &[frame(1)]);
        let mut raw = [null_mut::<c_void>(); 2];
        let taken =
            unsafe { dpdk_raw_ring_dequeue_burst(tx_ring, raw.as_mut_ptr(), 2, null_mut()) };
        assert_eq!(taken, 1);
        unsafe { dpdk_raw_pktmbuf_free(raw[0].cast()) };
        port.try_close().unwrap();
    });
}

#[zhida_test_support::pinned_test]
fn link_dropped_holding_a_frame_fails_after_freeing_it() {
    with_eal(|eal| {
        let fixtures = [RingPort::new("td_link_a", 16, 16), RingPort::new("td_link_b", 16, 16)];
        let mut ports = fixtures.each_ref().map(|fixture| fixture.open(eal));
        let mut link = fixtures[0].link_to(&fixtures[1]);
        link.impair(|_| Verdict::Hold);
        send(&mut ports[0], &[frame(1)]);
        assert_eq!(link.forward(), 1);
        assert_eq!(fixtures[1].in_use(), (1, 0));

        let payload = catch_unwind(AssertUnwindSafe(|| drop(link))).unwrap_err();
        assert_eq!(message(payload), "Link dropped holding a frame; call free_held");
        assert_eq!(fixtures[1].in_use(), (0, 0));
        close_ports(ports, fixtures);
    });
}

#[zhida_test_support::pinned_test]
fn pair_close_counts_frames_left_on_rings() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["td_count_a", "td_count_b"]);
        let ([client, _server], _) = establish(&mut pair, Side::A);
        pair.a.tcp_mut(&client).send_slice(b"left on the ring").unwrap();
        let now = pair.now();
        assert_eq!(pair.a.turn(now, 32).unwrap().tx_accepted, 1);
        assert_eq!(pair.close(), 1);
    });
}

#[zhida_test_support::pinned_test]
fn impair_callback_panic_frees_every_dequeued_frame() {
    with_eal(|eal| {
        let fixtures =
            [RingPort::new("td_impair_a", 16, 16), RingPort::new("td_impair_b", 16, 16)];
        let mut ports = fixtures.each_ref().map(|fixture| fixture.open(eal));
        let mut link = fixtures[0].link_to(&fixtures[1]);
        let mut seen = 0;
        link.impair(move |_| {
            seen += 1;
            assert!(seen < 2, "impairment panic");
            Verdict::Deliver
        });
        send(&mut ports[0], &[frame(1), frame(2), frame(3), frame(4)]);
        assert_eq!(fixtures[0].in_use(), (0, 4));

        let payload = catch_unwind(AssertUnwindSafe(|| link.forward())).unwrap_err();
        assert_eq!(message(payload), "impairment panic");
        // The first frame was delivered; the one being judged and the two
        // behind it in the burst were freed.
        assert_eq!(fixtures[0].in_use(), (0, 0));
        assert_eq!(fixtures[1].in_use(), (1, 0));
        assert_eq!(fixtures[1].drain(), 1);
        drop(link);
        close_ports(ports, fixtures);
    });
}

#[zhida_test_support::pinned_test]
fn delivery_observer_panic_frees_every_dequeued_frame() {
    with_eal(|eal| {
        let fixtures =
            [RingPort::new("td_observe_a", 16, 16), RingPort::new("td_observe_b", 16, 16)];
        let mut ports = fixtures.each_ref().map(|fixture| fixture.open(eal));
        let mut link = fixtures[0].link_to(&fixtures[1]);
        send(&mut ports[0], &[frame(1), frame(2), frame(3)]);
        assert_eq!(fixtures[0].in_use(), (0, 3));

        let payload = catch_unwind(AssertUnwindSafe(|| {
            link.forward_with(|_| panic!("observer panic"))
        }))
        .unwrap_err();
        assert_eq!(message(payload), "observer panic");
        // The first copy is on the receiver's ring; the sender's frame it was
        // copied from and the two behind it in the burst were freed.
        assert_eq!(fixtures[0].in_use(), (0, 0));
        assert_eq!(fixtures[1].in_use(), (1, 0));
        assert_eq!(fixtures[1].drain(), 1);
        drop(link);
        close_ports(ports, fixtures);
    });
}

#[zhida_test_support::pinned_test]
fn inject_into_a_full_rx_ring_frees_the_frame_it_refused() {
    with_eal(|eal| {
        // The RX ring holds 3.
        let fixture = RingPort::new("td_full", 4, 16);
        let port = fixture.open(eal);
        let payload = catch_unwind(AssertUnwindSafe(|| {
            fixture.inject(&[frame(1), frame(2), frame(3), frame(4)])
        }))
        .unwrap_err();
        assert!(message(payload).contains("RX ring full"));
        assert_eq!(fixture.in_use(), (3, 0));
        assert_eq!(fixture.drain(), 3);
        port.try_close().unwrap();
        fixture.close();
    });
}

#[zhida_test_support::pinned_test]
fn copy_into_an_oversize_frame_frees_the_mbuf_it_allocated() {
    with_eal(|eal| {
        let fixture = RingPort::new("td_oversize", 16, 16);
        let port = fixture.open(eal);
        let room = fixture.config().rx_pool.data_room_size - RTE_PKTMBUF_HEADROOM as u16;
        let oversized = vec![0; usize::from(room) + 1];
        let payload = catch_unwind(AssertUnwindSafe(|| {
            copy_into(fixture.rx_pool(), &oversized)
        }))
        .unwrap_err();
        assert!(message(payload).contains("tailroom"));
        assert_eq!(fixture.in_use(), (0, 0));
        port.try_close().unwrap();
        fixture.close();
    });
}

#[zhida_test_support::pinned_test]
fn pair_close_detects_double_return() {
    with_eal(|eal| {
        let pair = new_pair(eal, ["td_double_a", "td_double_b"]);
        let pool = zhida_test_kit::wire::pool_by_name(c"td_double_a_rxp");
        let packet = copy_into(pool, b"a");
        unsafe {
            zhida_dpdk_sys::zhida_pktmbuf_free_minimal(packet);
            zhida_dpdk_sys::zhida_pktmbuf_free_minimal(packet);
        }
        let result = catch_unwind(AssertUnwindSafe(|| pair.close()));
        assert!(result.is_err(), "Pair::close accepted a double-returned mbuf");
        assert!(message(result.unwrap_err()).contains("pool handed out"));
    });
}
