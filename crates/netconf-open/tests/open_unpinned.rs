#[path = "open_tap/common.rs"]
mod common;

use zhida_open::{open, OpenError};
use dpdk_smoltcp::smoltcp::time::Instant;
use zhida_dpdk_sys::AffinityError;

#[zhida_test_support::pinned_test]
fn open_rejects_unpinned_process() {
    // SAFETY: all-zero is valid initialization for cpu_set_t.
    let mut allowed: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // PID 1 retains the container's CPU set while the test process may inherit
    // a narrower taskset from the gate.
    // SAFETY: `allowed` is writable for its exact size.
    assert_eq!(
        unsafe { libc::sched_getaffinity(1, std::mem::size_of_val(&allowed), &mut allowed) },
        0
    );
    let cpus: Vec<_> = (0..libc::CPU_SETSIZE as usize)
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &allowed) })
        .collect();
    assert!(
        cpus.len() >= 2,
        "open_rejects_unpinned_process gate must give the container two CPUs"
    );
    // SAFETY: all-zero is valid initialization for cpu_set_t.
    let mut widened: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    for &cpu in &cpus[..2] {
        // SAFETY: each CPU came from this valid CPU set and is below CPU_SETSIZE.
        unsafe { libc::CPU_SET(cpu, &mut widened) };
    }
    // SAFETY: `widened` is readable for its exact size.
    assert_eq!(
        unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&widened), &widened) },
        0
    );

    let config = common::config("net_tap_o3_unpinned", "cdo3_unpin", common::EXPLICIT_NONE, false);
    let error = match unsafe { open(&config, &common::sizing(), &mut || Instant::ZERO) } {
        Err(error) => error,
        Ok(_) => panic!("open unexpectedly accepted two allowed CPUs"),
    };
    match error {
        OpenError::NotPinned(AffinityError::NotOne { allowed }) => assert_eq!(allowed, 2),
        other => panic!("unexpected error: {other:?}"),
    }
}
