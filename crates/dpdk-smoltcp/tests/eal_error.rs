use dpdk_smoltcp::{Eal, EalError};
use zhida_dpdk_sys::EINVAL;

#[test]
fn conflicting_recognized_options_return_dpdk_error() {
    // Both core-selection options parse; their conflict returns before EAL setup.
    assert!(matches!(
        Eal::init(&["zhida-eal-error", "-l", "0", "-c", "1"]),
        Err(EalError::Initialization { return_code: -1, errno }) if errno == EINVAL as i32
    ));
}
