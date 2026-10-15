use std::fmt;

use zhida_netconf::Offloads as Setting;
use dpdk_smoltcp::{DeviceInfo, Offloads};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffloadChoice {
    pub name: &'static str,
    pub requested: bool,
    pub reason: String,
}

/// The exact offloads to request from `Port::open` and why each checksum bit is on or off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffloadPlan {
    pub offloads: Offloads,
    /// rx_checksum, tx_tcp_checksum, tx_udp_checksum, in that order.
    pub choices: [OffloadChoice; 3],
    pub notes: Vec<String>,
}

/// Resolve the config's offload setting against what the device advertises.
/// Explicit bits pass through unchanged; auto requests a per-driver subset of the advertised bits.
/// RX timestamps are never auto: `rx_timestamps` is requested as given.
pub(crate) fn resolve(setting: &Setting, rx_timestamps: bool, device: &DeviceInfo) -> OffloadPlan {
    let choices = match *setting {
        Setting::Explicit {
            rx_checksum,
            tx_tcp_checksum,
            tx_udp_checksum,
        } => choices(
            [rx_checksum, tx_tcp_checksum, tx_udp_checksum],
            ["explicit".into(), "explicit".into(), "explicit".into()],
        ),
        Setting::Auto => auto(&device.driver_name, device.advertised()),
    };
    let note = match device.driver_name.as_str() {
        "net_ice" if rx_timestamps => Some("ice: RX timestamp forces scalar RX"),
        "net_ena" if rx_timestamps => Some("ena: stamps are device ns on the Time Sync clock"),
        _ => None,
    };
    OffloadPlan {
        offloads: Offloads {
            rx_checksum: choices[0].requested,
            rx_timestamp: rx_timestamps,
            tx_tcp_checksum: choices[1].requested,
            tx_udp_checksum: choices[2].requested,
        },
        choices,
        notes: note.into_iter().map(String::from).collect(),
    }
}

fn auto(driver: &str, advertised: Offloads) -> [OffloadChoice; 3] {
    let rx = advertised.rx_checksum;
    let tcp = advertised.tx_tcp_checksum;
    let udp = advertised.tx_udp_checksum;
    match driver {
        "net_ena" => advertised_choices("ena", [rx, tcp, udp]),
        "net_ice" => advertised_choices("ice", [rx, tcp, udp]),
        "net_ixgbe" => {
            let tx = "ixgbe: vector TX needs zero TX offloads";
            choices(
                [false; 3],
                [
                    "ixgbe: off until verified on an Intel host".into(),
                    tx.into(),
                    tx.into(),
                ],
            )
        }
        "net_i40e" => {
            let tx = "i40e: vector TX allows no checksum offloads";
            choices(
                [rx, false, false],
                [advertised_reason("i40e", rx), tx.into(), tx.into()],
            )
        }
        _ => {
            let reason =
                format!("unknown driver {driver}: none requested; set offloads explicitly");
            choices([false; 3], [reason.clone(), reason.clone(), reason])
        }
    }
}

fn advertised_choices(label: &str, requested: [bool; 3]) -> [OffloadChoice; 3] {
    choices(
        requested,
        requested.map(|bit| advertised_reason(label, bit)),
    )
}

fn advertised_reason(label: &str, advertised: bool) -> String {
    if advertised {
        format!("{label}: requested because advertised")
    } else {
        format!("{label}: not advertised")
    }
}

fn choices(requested: [bool; 3], reasons: [String; 3]) -> [OffloadChoice; 3] {
    let [rx, tcp, udp] = reasons;
    [
        OffloadChoice {
            name: "rx_checksum",
            requested: requested[0],
            reason: rx,
        },
        OffloadChoice {
            name: "tx_tcp_checksum",
            requested: requested[1],
            reason: tcp,
        },
        OffloadChoice {
            name: "tx_udp_checksum",
            requested: requested[2],
            reason: udp,
        },
    ]
}

impl fmt::Display for OffloadPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, choice) in self.choices.iter().enumerate() {
            if index != 0 {
                f.write_str("\n")?;
            }
            let state = if choice.requested {
                "requested"
            } else {
                "not requested"
            };
            write!(f, "{}: {state} ({})", choice.name, choice.reason)?;
        }
        for note in &self.notes {
            write!(f, "\n{note}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RX_CKSUM: u64 = (1 << 1) | (1 << 2) | (1 << 3);
    const RX_TIMESTAMP: u64 = 1 << 14;
    const TX_TCP_CKSUM: u64 = 1 << 3;
    const TX_UDP_CKSUM: u64 = 1 << 2;

    fn device(driver_name: &str, rx_capa: u64, tx_capa: u64) -> DeviceInfo {
        DeviceInfo {
            driver_name: driver_name.into(),
            rx_capa,
            tx_capa,
            min_mtu: 0,
            max_mtu: 0,
            max_rx_pktlen: 0,
            mac: [0; 6],
        }
    }

    fn auto(device: &DeviceInfo) -> OffloadPlan {
        resolve(&Setting::Auto, false, device)
    }

    #[test]
    fn ena_requests_advertised_checksums() {
        let all = auto(&device("net_ena", RX_CKSUM, TX_TCP_CKSUM | TX_UDP_CKSUM));
        assert_eq!(
            all.offloads,
            Offloads {
                rx_checksum: true,
                rx_timestamp: false,
                tx_tcp_checksum: true,
                tx_udp_checksum: true,
            }
        );
        let tcp_only = auto(&device("net_ena", 0, TX_TCP_CKSUM));
        assert_eq!(
            tcp_only.offloads,
            Offloads {
                rx_checksum: false,
                rx_timestamp: false,
                tx_tcp_checksum: true,
                tx_udp_checksum: false,
            }
        );
        assert_eq!(tcp_only.choices[0].reason, "ena: not advertised");
        assert_eq!(
            tcp_only.choices[1].reason,
            "ena: requested because advertised"
        );
        assert_eq!(
            tcp_only.to_string(),
            "rx_checksum: not requested (ena: not advertised)\ntx_tcp_checksum: requested (ena: requested because advertised)\ntx_udp_checksum: not requested (ena: not advertised)"
        );
    }

    #[test]
    fn ixgbe_never_requests_tx_checksum() {
        let plan = auto(&device("net_ixgbe", RX_CKSUM, TX_TCP_CKSUM | TX_UDP_CKSUM));
        assert_eq!(plan.offloads, Offloads::default());
        assert_eq!(
            plan.choices
                .iter()
                .map(|choice| choice.reason.as_str())
                .collect::<Vec<_>>(),
            [
                "ixgbe: off until verified on an Intel host",
                "ixgbe: vector TX needs zero TX offloads",
                "ixgbe: vector TX needs zero TX offloads",
            ]
        );
    }

    #[test]
    fn unknown_driver_requests_none() {
        let plan = auto(&device("net_tap", RX_CKSUM, TX_TCP_CKSUM | TX_UDP_CKSUM));
        assert_eq!(plan.offloads, Offloads::default());
        assert!(plan.choices.iter().all(|choice| {
            choice.reason == "unknown driver net_tap: none requested; set offloads explicitly"
        }));
    }

    #[test]
    fn auto_never_requests_unadvertised() {
        for driver in ["net_ena", "net_ixgbe", "net_i40e", "net_ice", "net_tap"] {
            for (rx_capa, tx_capa) in [
                (
                    (RX_CKSUM | RX_TIMESTAMP) & !(1 << 1),
                    TX_TCP_CKSUM | TX_UDP_CKSUM,
                ),
                (
                    (RX_CKSUM | RX_TIMESTAMP) & !(1 << 2),
                    TX_TCP_CKSUM | TX_UDP_CKSUM,
                ),
                (
                    (RX_CKSUM | RX_TIMESTAMP) & !(1 << 3),
                    TX_TCP_CKSUM | TX_UDP_CKSUM,
                ),
                (
                    (RX_CKSUM | RX_TIMESTAMP) & !RX_TIMESTAMP,
                    TX_TCP_CKSUM | TX_UDP_CKSUM,
                ),
                (RX_CKSUM | RX_TIMESTAMP, TX_UDP_CKSUM),
                (RX_CKSUM | RX_TIMESTAMP, TX_TCP_CKSUM),
            ] {
                let device = device(driver, rx_capa, tx_capa);
                let requested = auto(&device).offloads;
                let advertised = device.advertised();
                assert!(!requested.rx_checksum || advertised.rx_checksum, "{driver}");
                assert!(
                    !requested.rx_timestamp || advertised.rx_timestamp,
                    "{driver}"
                );
                assert!(
                    !requested.tx_tcp_checksum || advertised.tx_tcp_checksum,
                    "{driver}"
                );
                assert!(
                    !requested.tx_udp_checksum || advertised.tx_udp_checksum,
                    "{driver}"
                );
            }
        }
    }

    #[test]
    fn explicit_missing_capability_fails() {
        let plan = resolve(
            &Setting::Explicit {
                rx_checksum: true,
                tx_tcp_checksum: true,
                tx_udp_checksum: true,
            },
            false,
            &device("net_tap", 0, 0),
        );
        assert_eq!(
            plan.offloads,
            Offloads {
                rx_checksum: true,
                rx_timestamp: false,
                tx_tcp_checksum: true,
                tx_udp_checksum: true,
            }
        );
        assert!(plan
            .choices
            .iter()
            .all(|choice| choice.reason == "explicit"));
    }

    #[test]
    fn rx_timestamps_are_explicit_with_driver_notes() {
        for (driver, note) in [
            ("net_ice", Some("ice: RX timestamp forces scalar RX")),
            (
                "net_ena",
                Some("ena: stamps are device ns on the Time Sync clock"),
            ),
            ("net_tap", None),
        ] {
            let device = device(driver, RX_TIMESTAMP, 0);
            let enabled = resolve(&Setting::Auto, true, &device);
            assert!(enabled.offloads.rx_timestamp);
            assert_eq!(
                enabled.notes,
                note.into_iter().map(String::from).collect::<Vec<_>>()
            );
            let disabled = resolve(&Setting::Auto, false, &device);
            assert!(!disabled.offloads.rx_timestamp);
            assert!(disabled.notes.is_empty());
        }
    }
}
