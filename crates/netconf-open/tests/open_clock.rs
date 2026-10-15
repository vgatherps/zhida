#[path = "open_tap/common.rs"]
mod common;

use std::cell::Cell;

use zhida_open::open;
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::StackError;

#[zhida_test_support::pinned_test]
fn turn_after_open_continues_caller_clock() {
    let config = common::config("net_tap_o3_clock", "cdo3_clock", common::EXPLICIT_NONE, false);
    let tick = Cell::new(1000i64);
    let mut clock = || {
        tick.set(tick.get() + 1);
        Instant::from_millis(tick.get())
    };
    let mut opened = unsafe { open(&config, &common::sizing(), &mut clock) }.unwrap();
    let opened_at = Instant::from_millis(tick.get());
    match opened.stack.turn(Instant::from_millis(500), 32) {
        Err(StackError::TimeWentBackwards { last, now }) => {
            assert_eq!(last, opened_at);
            assert_eq!(now, Instant::from_millis(500));
        }
        other => panic!("unexpected result: {other:?}"),
    }
    opened.stack.turn(clock(), 32).unwrap();
    opened.stack.into_port().try_close().unwrap();
}
