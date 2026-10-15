#![allow(dead_code)]

use zhida_netconf::Config;
use zhida_open::Sizing;

pub fn config(vdev: &str, iface: &str, offloads: &str, rx_timestamps: bool) -> Config {
    config_with_gateway(vdev, iface, offloads, rx_timestamps, "null")
}

pub fn config_with_gateway(
    vdev: &str,
    iface: &str,
    offloads: &str,
    rx_timestamps: bool,
    gateway: &str,
) -> Config {
    Config::from_json(&format!(
        r#"{{
          "version": 1,
          "device": {{"vdev": "{vdev},iface={iface},mac=02:00:00:00:00:fe"}},
          "mac": null,
          "ipv4": "192.0.2.2/24",
          "gateway": {gateway},
          "mtu": 1500,
          "paths": [],
          "offloads": {offloads},
          "rx_timestamps": {rx_timestamps},
          "descriptors": 16,
          "eal": {{
            "file_prefix": "{vdev}",
            "extra": ["--no-huge", "-m", "128", "--no-shconf"]
          }}
        }}"#
    ))
    .unwrap()
}

pub fn sizing() -> Sizing {
    Sizing {
        tcp_rx_frames: 0,
        udp_rx_datagrams: 0,
        max_sockets: 1,
        max_udp_sockets: 0,
        rx_staging: 32,
        tx_pending: 32,
        segments_per_visit: 1,
        neighbor_capacity: 256,
    }
}

pub const EXPLICIT_NONE: &str =
    r#"{"rx_checksum":false,"tx_tcp_checksum":false,"tx_udp_checksum":false}"#;
