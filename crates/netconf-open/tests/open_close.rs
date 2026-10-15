#[path = "open_tap/common.rs"]
mod common;

use zhida_open::open;
use dpdk_smoltcp::smoltcp::time::Instant;

#[zhida_test_support::pinned_test]
fn open_close_returns_all_buffers() {
    let config = common::config("net_tap_o3_close", "cdo3_close", common::EXPLICIT_NONE, false);
    let mut now = 0i64;
    let mut opened = unsafe {
        open(&config, &common::sizing(), &mut || {
            now += 1;
            Instant::from_millis(now)
        })
    }
    .unwrap();
    for _ in 0..4 {
        now += 1;
        opened.stack.turn(Instant::from_millis(now), 32).unwrap();
    }
    opened.stack.into_port().try_close().unwrap();
}
