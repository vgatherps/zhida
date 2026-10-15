//! A test that panics while holding a TapVdev keeps its own panic message and
//! leaves the vdev name and the netdev free; a TapVdev dropped without close
//! fails the test after removing them. Needs CAP_NET_ADMIN and /dev/net/tun.

use std::any::Any;
use std::ffi::CStr;
use std::panic::{catch_unwind, AssertUnwindSafe};

use zhida_test_kit::tap::{ifindex, TapVdev};
use zhida_test_kit::wire::pool_exists;
use zhida_test_kit::with_eal;
use dpdk_smoltcp::{Offloads, Port, PortConfig};
use zhida_buffer::PoolConfig;
use zhida_dpdk_sys::RTE_PKTMBUF_HEADROOM;

fn message(payload: Box<dyn Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => payload.downcast_ref::<&str>().unwrap().to_string(),
    }
}

fn config(port_id: u16, rx_pool: &'static CStr, tx_pool: &'static CStr) -> PortConfig<'static> {
    let pool = |name| PoolConfig {
        name,
        count: 63,
        cache_size: 8,
        data_room_size: RTE_PKTMBUF_HEADROOM as u16 + 2048,
        socket_id: -1,
    };
    PortConfig {
        port_id,
        mtu: 1500,
        rx_descriptors: 16,
        tx_descriptors: 16,
        rx_burst: 8,
        tx_burst: 8,
        queue_socket: -1,
        rx_pool: pool(rx_pool),
        tx_pool: pool(tx_pool),
        offloads: Offloads::default(),
    }
}

#[zhida_test_support::pinned_test]
fn tap_vdev_unwind_removes_netdev_and_vdev_name() {
    let (vdev, iface) = (c"net_tap_kit_unwind", c"cdtap_kunwind");
    let (rx_pool, tx_pool) = (c"tap_kit_unwind_rx", c"tap_kit_unwind_tx");
    with_eal(|eal| {
        let payload = catch_unwind(AssertUnwindSafe(|| {
            let tap = TapVdev::new(vdev, iface);
            let _port = unsafe { Port::open(eal, config(tap.port_id(), rx_pool, tx_pool)) }
                .unwrap();
            assert_ne!(ifindex(iface), 0);
            panic!("original tap panic");
        }))
        .unwrap_err();
        assert_eq!(message(payload), "original tap panic");
        // The Port dropped first and freed its pools; the vdev went after it.
        assert_eq!(ifindex(iface), 0);
        assert!(!pool_exists(rx_pool) && !pool_exists(tx_pool));

        let tap = TapVdev::new(vdev, iface);
        assert_ne!(ifindex(iface), 0);
        tap.close();
    });
}

#[zhida_test_support::pinned_test]
fn tap_vdev_dropped_without_close_fails_after_cleanup() {
    let (vdev, iface) = (c"net_tap_kit_drop", c"cdtap_kdrop");
    with_eal(|_| {
        let payload = catch_unwind(AssertUnwindSafe(|| drop(TapVdev::new(vdev, iface))))
            .unwrap_err();
        assert_eq!(message(payload), "TapVdev net_tap_kit_drop dropped without close");
        assert_eq!(ifindex(iface), 0);
        TapVdev::new(vdev, iface).close();
    });
}
