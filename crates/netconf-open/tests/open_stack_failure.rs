#[path = "open_tap/common.rs"]
mod common;

use zhida_open::{open, OpenError};
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::StackError;

#[zhida_test_support::pinned_test]
fn stack_new_failure_returns_port() {
    let config = common::config("net_tap_o3_stack_fail", "cdo3_sfail", common::EXPLICIT_NONE, false);
    let mut sizing = common::sizing();
    sizing.max_sockets = 0;
    let error = match unsafe { open(&config, &sizing, &mut || Instant::ZERO) } {
        Err(error) => error,
        Ok(_) => panic!("open unexpectedly accepted zero max_sockets"),
    };
    let OpenError::Stack { port, error } = error else {
        panic!("unexpected error: {error:?}");
    };
    assert_eq!(error, StackError::InvalidConfig("max_sockets must be positive"));
    port.try_close().unwrap();
}
