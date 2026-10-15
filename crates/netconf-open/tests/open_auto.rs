#[path = "open_tap/common.rs"]
mod common;

use zhida_open::open;
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::Offloads;

#[zhida_test_support::pinned_test]
fn open_auto_on_net_tap_requests_none_and_reports_why() {
    let config = common::config("net_tap_o3_auto", "cdo3_auto", r#""auto""#, false);
    let opened = unsafe { open(&config, &common::sizing(), &mut || Instant::ZERO) }.unwrap();
    assert_eq!(opened.report.offloads.offloads, Offloads::default());
    assert!(opened
        .report
        .to_string()
        .contains("unknown driver net_tap: none requested; set offloads explicitly"));
    opened.stack.into_port().try_close().unwrap();
}
