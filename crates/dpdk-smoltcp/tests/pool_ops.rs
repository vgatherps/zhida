use std::ffi::CStr;

use zhida_test_kit::{ring_port::RingPort, wire, with_eal};
use dpdk_smoltcp::Port;
use zhida_dpdk_sys::zhida_mempool_ops_name;

#[zhida_test_support::pinned_test]
fn port_pools_use_single_producer_single_consumer_rings() {
    with_eal(|eal| {
        let ring = RingPort::new("pool_ops", 16, 16);
        let config = ring.config();
        let port = unsafe { Port::open(eal, config) }.unwrap();
        for name in [config.rx_pool.name, config.tx_pool.name] {
            let pool = wire::pool_by_name(name);
            assert_eq!(unsafe { CStr::from_ptr(zhida_mempool_ops_name(pool)) }, c"ring_sp_sc");
        }
        port.try_close().unwrap();
        ring.close();
    });
}
