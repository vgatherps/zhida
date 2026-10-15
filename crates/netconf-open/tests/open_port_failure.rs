#[path = "open_tap/common.rs"]
mod common;

use std::ffi::{CStr, CString};

use zhida_open::{open, OpenError};
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::{DeviceInfo, PortError};
use zhida_dpdk_sys::{rte_eth_dev_get_port_by_name, rte_eth_dev_info, rte_eth_dev_info_get};

#[zhida_test_support::pinned_test]
fn port_open_failure_keeps_retained_port() {
    let config = common::config(
        "net_tap_o3_port_fail",
        "cdo3_pfail",
        common::EXPLICIT_NONE,
        true,
    );
    let error = match unsafe { open(&config, &common::sizing(), &mut || Instant::ZERO) } {
        Err(error) => error,
        Ok(_) => panic!("open unexpectedly accepted RX timestamps"),
    };

    let name = CString::new("net_tap_o3_port_fail").unwrap();
    let mut port_id = 0;
    assert_eq!(unsafe { rte_eth_dev_get_port_by_name(name.as_ptr(), &mut port_id) }, 0);
    // SAFETY: EAL remains process-global after the failed open and `raw` is writable.
    let mut raw: rte_eth_dev_info = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { rte_eth_dev_info_get(port_id, &mut raw) }, 0);
    let driver_name = unsafe { CStr::from_ptr(raw.driver_name) }
        .to_string_lossy()
        .into_owned();
    let info = DeviceInfo {
        driver_name,
        rx_capa: raw.rx_offload_capa,
        tx_capa: raw.tx_offload_capa,
        min_mtu: raw.min_mtu,
        max_mtu: raw.max_mtu,
        max_rx_pktlen: raw.max_rx_pktlen,
        mac: [0; 6],
    };
    assert!(!info.advertised().rx_timestamp);

    let OpenError::PortOpen(error) = error else {
        panic!("unexpected error: {error:?}");
    };
    assert_eq!(
        error.cause,
        PortError::InvalidSettings("PMD lacks the requested RX timestamp offload")
    );
    assert_eq!(error.rollback_error, None);
    assert!(error.retained.is_none());
}
