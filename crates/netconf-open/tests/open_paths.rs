//! One `open` call lives in this test binary because EAL initializes once per process.

#[path = "open_tap/common.rs"]
mod common;

use zhida_netconf::PathRule;
use zhida_open::open;
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::smoltcp::wire::IpEndpoint;
use dpdk_smoltcp::{UdpConfig, UdpSendError};

#[zhida_test_support::pinned_test]
fn open_passes_config_paths_to_stack() {
    let mut config = common::config(
        "net_tap_open_paths", "cdopen_paths", common::EXPLICIT_NONE, false,
    );
    config.paths = vec![PathRule {
        prefix: "192.0.2.1/32".parse().unwrap(),
        mtu: 1400,
        why: "test path".to_owned(),
    }];
    let mut sizing = common::sizing();
    sizing.max_udp_sockets = 1;
    sizing.udp_rx_datagrams = 1;
    let mut now = 0i64;
    // SAFETY: EAL creates this private net_tap vdev; this worker owns it and its
    // packets, and the vdev lives for the process lifetime.
    let mut opened = unsafe {
        open(&config, &sizing, &mut || {
            now += 1;
            Instant::from_millis(now)
        })
    }.unwrap();
    let handle = opened.stack.add_udp(UdpConfig {
        port: 12345,
        rx_queue: 1,
        tx_checksum: true,
        broadcast: false,
    }).unwrap();
    let capped = IpEndpoint::new("192.0.2.1".parse().unwrap(), 12346);
    assert_eq!(
        opened.stack.udp_send(&handle, Some(capped), &[0; 1372]),
        Err(UdpSendError::NeighborPending),
    );
    assert_eq!(
        opened.stack.udp_send(&handle, Some(capped), &[0; 1373]),
        Err(UdpSendError::TooLarge),
    );
    let uncapped = IpEndpoint::new("192.0.2.3".parse().unwrap(), 12346);
    assert_eq!(
        opened.stack.udp_send(&handle, Some(uncapped), &[0; 1472]),
        Err(UdpSendError::NeighborPending),
    );
    opened.stack.remove_udp(handle);
    opened.stack.into_port().try_close().unwrap();
}
