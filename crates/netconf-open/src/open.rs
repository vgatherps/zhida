use std::fmt;

use zhida_netconf::{Config, Device};
use dpdk_smoltcp::smoltcp::iface::PathMtu;
use dpdk_smoltcp::smoltcp::time::{Duration, Instant};
use dpdk_smoltcp::smoltcp::wire::{EthernetAddress, Ipv4Address};
use dpdk_smoltcp::{
    device_info, os_random_seed, port_by_name, DeviceInfo, Eal, EalError, Port, PortError,
    PortOpenError, Stack, StackConfig, StackError,
};
use zhida_dpdk_sys::{only_allowed_cpu, AffinityError};

use crate::offloads::{self, OffloadPlan};
use crate::{adjusted_descriptors, port_config, wait_link, Link, Sizing};

pub struct Opened {
    pub stack: Stack,
    pub eal: Eal,
    pub report: OpenReport,
}

pub enum OpenError {
    NotPinned(AffinityError),
    Eal(EalError),
    DeviceNotFound {
        name: String,
    },
    DeviceInfo(PortError),
    MacMismatch {
        config: EthernetAddress,
        device: EthernetAddress,
    },
    Descriptors(String),
    PortConfig(String),
    PortOpen(PortOpenError),
    Link {
        port_id: u16,
        port: Port,
        error: String,
    },
    LinkDown {
        port_id: u16,
        port: Port,
        link: Link,
    },
    Seed {
        port: Port,
        error: std::io::Error,
    },
    Stack {
        port: Port,
        error: StackError,
    },
    GatewayUnresolved {
        stack: Stack,
        gateway: Ipv4Address,
        waited: Duration,
    },
    Receive {
        stack: Stack,
        error: StackError,
    },
}

impl fmt::Debug for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPinned(error) => f.debug_tuple("NotPinned").field(error).finish(),
            Self::Eal(error) => f.debug_tuple("Eal").field(error).finish(),
            Self::DeviceNotFound { name } => {
                f.debug_struct("DeviceNotFound").field("name", name).finish()
            }
            Self::DeviceInfo(error) => f.debug_tuple("DeviceInfo").field(error).finish(),
            Self::MacMismatch { config, device } => f
                .debug_struct("MacMismatch")
                .field("config", config)
                .field("device", device)
                .finish(),
            Self::Descriptors(error) => f.debug_tuple("Descriptors").field(error).finish(),
            Self::PortConfig(error) => f.debug_tuple("PortConfig").field(error).finish(),
            Self::PortOpen(error) => f.debug_tuple("PortOpen").field(error).finish(),
            Self::Link {
                port_id,
                port,
                error,
            } => f
                .debug_struct("Link")
                .field("port_id", port_id)
                .field("port", port)
                .field("error", error)
                .finish(),
            Self::LinkDown {
                port_id,
                port,
                link,
            } => f
                .debug_struct("LinkDown")
                .field("port_id", port_id)
                .field("port", port)
                .field("link", link)
                .finish(),
            Self::Seed { port, error } => f
                .debug_struct("Seed")
                .field("port", port)
                .field("error", error)
                .finish(),
            Self::Stack { port, error } => f
                .debug_struct("Stack")
                .field("port", port)
                .field("error", error)
                .finish(),
            Self::GatewayUnresolved {
                gateway, waited, ..
            } => f
                .debug_struct("GatewayUnresolved")
                .field("gateway", gateway)
                .field("waited", waited)
                .finish_non_exhaustive(),
            Self::Receive { error, .. } => f
                .debug_struct("Receive")
                .field("error", error)
                .finish_non_exhaustive(),
        }
    }
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPinned(error) => write!(f, "CPU affinity: {error}"),
            Self::Eal(error) => write!(f, "EAL initialization: {error}"),
            Self::DeviceNotFound { name } => write!(f, "device lookup: {name:?} was not found"),
            Self::DeviceInfo(error) => write!(f, "device information: {error}"),
            Self::MacMismatch { config, device } => {
                write!(
                    f,
                    "device MAC: config {config} differs from device {device}"
                )
            }
            Self::Descriptors(error) => write!(f, "descriptor adjustment: {error}"),
            Self::PortConfig(error) => write!(f, "port configuration: {error}"),
            Self::PortOpen(error) => write!(f, "port open: {error}"),
            Self::Link { error, .. } => write!(f, "link query: {error}"),
            Self::LinkDown { .. } => write!(f, "link wait: link down after 10 seconds"),
            Self::Seed { error, .. } => write!(f, "stack random seed: {error}"),
            Self::Stack { error, .. } => write!(f, "Stack::new: {error}"),
            Self::GatewayUnresolved {
                gateway, waited, ..
            } => write!(f, "gateway {gateway} unresolved after {waited}"),
            Self::Receive { error, .. } => write!(f, "gateway receive: {error}"),
        }
    }
}

impl std::error::Error for OpenError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenReport {
    pub cpu: usize,
    pub port_id: u16,
    pub device: DeviceInfo,
    pub offloads: OffloadPlan,
    pub descriptors: (u16, u16),
    pub rx_pool_count: u32,
    pub tx_pool_count: u32,
    pub link: Link,
    pub gateway: Option<(Ipv4Address, EthernetAddress, Duration)>,
}

impl fmt::Display for OpenReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mac = self.device.mac;
        write!(f, "driver: {}", self.device.driver_name)?;
        write!(
            f,
            "\nmac: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )?;
        write!(f, "\ncpu: {}", self.cpu)?;
        write!(f, "\nport_id: {}", self.port_id)?;
        write!(f, "\nrx_offload_capa: {:#018x}", self.device.rx_capa)?;
        write!(f, "\ntx_offload_capa: {:#018x}", self.device.tx_capa)?;
        write!(f, "\nmax_rx_pktlen: {}", self.device.max_rx_pktlen)?;
        write!(f, "\nmin_mtu: {}", self.device.min_mtu)?;
        write!(f, "\nmax_mtu: {}", self.device.max_mtu)?;
        write!(
            f,
            "\ndescriptors: rx={} tx={}",
            self.descriptors.0, self.descriptors.1
        )?;
        write!(f, "\nrx_pool_count: {}", self.rx_pool_count)?;
        write!(f, "\ntx_pool_count: {}", self.tx_pool_count)?;
        write!(f, "\n{}", self.offloads)?;
        write!(f, "\nlink_speed_mbps: {}", self.link.speed_mbps)?;
        write!(
            f,
            "\nlink_duplex: {}",
            if self.link.full_duplex {
                "full"
            } else {
                "half"
            }
        )?;
        write!(
            f,
            "\nlink_status: {}",
            if self.link.up { "up" } else { "down" }
        )?;
        match self.gateway {
            Some((ip, mac, waited)) => {
                write!(f, "\ngateway: {ip} at {mac} after {} ms", waited.total_millis())
            }
            None => write!(f, "\ngateway: none"),
        }
    }
}

/// Initialize EAL and open the configured device as a running Stack.
///
/// # Safety
/// The ethdev must be newly created, never configured or started, and under
/// exclusive control. EAL, packet operations and cleanup stay on its owner
/// thread. Preserve the production pools' direct/unique/single-segment
/// contract. The PMD must honor the requested packet profile and discharge
/// its buffers/DMA on close. The PMD must supply only valid DPDK mbufs with
/// valid links/refcounts, each transferring one reference; for net_ring this
/// also applies to whoever writes the attached RX ring. TX acceptance must
/// report at most the offered count and take the front of the offered array.
/// EAL and retained backing survive until all obligations are discharged.
/// Caller-owned attached rings must outlive device close and return queued
/// packets before pool destruction. Vdevs are created by EAL from `config`
/// and live as long as EAL.
pub unsafe fn open(
    config: &Config,
    sizing: &Sizing,
    clock: &mut impl FnMut() -> Instant,
) -> Result<Opened, OpenError> {
    let cpu = only_allowed_cpu().map_err(OpenError::NotPinned)?;
    let mut argv = vec![
        "zhida-open".to_owned(),
        format!("--lcores=0@{cpu}"),
        "--file-prefix".to_owned(),
        config.eal.file_prefix.clone(),
        "--no-telemetry".to_owned(),
    ];
    let device_name = match &config.device {
        Device::Pci(pci) => {
            argv.push("-a".to_owned());
            argv.push(if pci.devargs.is_empty() {
                pci.pci.clone()
            } else {
                format!("{},{}", pci.pci, pci.devargs)
            });
            pci.pci.clone()
        }
        Device::Vdev { vdev: spec } => {
            argv.push("--no-pci".to_owned());
            argv.push("--vdev".to_owned());
            argv.push(spec.clone());
            spec.split_once(',')
                .map_or_else(|| spec.clone(), |(name, _)| name.to_owned())
        }
    };
    argv.extend(config.eal.extra.iter().cloned());
    let args: Vec<_> = argv.iter().map(String::as_str).collect();
    let eal = Eal::init(&args).map_err(OpenError::Eal)?;
    let port_id = port_by_name(&eal, &device_name)
        .ok_or_else(|| OpenError::DeviceNotFound { name: device_name })?;
    let device = device_info(&eal, port_id).map_err(OpenError::DeviceInfo)?;
    check_mac(config, device.mac)?;
    let offloads = offloads::resolve(&config.offloads, config.rx_timestamps, &device);
    let descriptors =
        adjusted_descriptors(port_id, config.descriptors).map_err(OpenError::Descriptors)?;
    let port_config = port_config(port_id, config.mtu, offloads.offloads, descriptors, sizing)
        .map_err(OpenError::PortConfig)?;
    let rx_pool_count = port_config.rx_pool.count;
    let tx_pool_count = port_config.tx_pool.count;
    // SAFETY: the caller accepts this function's safety contract; EAL just
    // created the configured ethdev and remains alive in `Opened`.
    let port = unsafe { Port::open(&eal, port_config) }.map_err(OpenError::PortOpen)?;
    let link = match wait_link(port_id) {
        Ok(link) => link,
        Err(error) => {
            return Err(OpenError::Link {
                port_id,
                port,
                error,
            })
        }
    };
    if !link.up {
        return Err(OpenError::LinkDown {
            port_id,
            port,
            link,
        });
    }
    let seed = match os_random_seed() {
        Ok(seed) => seed,
        Err(error) => return Err(OpenError::Seed { port, error }),
    };
    let paths: Vec<PathMtu> = config
        .paths
        .iter()
        .map(|rule| PathMtu {
            prefix: rule.prefix,
            mtu: rule.mtu,
        })
        .collect();
    let stack_config = StackConfig {
        ethernet: EthernetAddress(device.mac),
        ipv4: config.ipv4,
        gateway: config.gateway,
        paths: &paths,
        random_seed: seed,
        neighbor_capacity: sizing.neighbor_capacity,
        segments_per_visit: sizing.segments_per_visit,
        max_sockets: sizing.max_sockets,
        max_udp_sockets: sizing.max_udp_sockets,
        rx_staging: sizing.rx_staging,
        tx_pending: sizing.tx_pending,
    };
    let start = clock();
    let mut stack = Stack::new(port, stack_config, start)
        .map_err(|(port, error)| OpenError::Stack { port, error })?;
    let gateway = if let Some(gateway) = config.gateway {
        let mut now = start;
        loop {
            if let Some(mac) = stack
                .resolve_gateway()
                .expect("the Stack was built with this gateway")
            {
                break Some((gateway, mac, now - start));
            }
            now = clock();
            let waited = now - start;
            if waited >= Duration::from_secs(3) {
                return Err(OpenError::GatewayUnresolved {
                    stack,
                    gateway,
                    waited,
                });
            }
            if let Err(error) = stack.receive(now, 32) {
                return Err(OpenError::Receive { stack, error });
            }
        }
    } else {
        None
    };
    Ok(Opened {
        stack,
        eal,
        report: OpenReport {
            cpu,
            port_id,
            device,
            offloads,
            descriptors,
            rx_pool_count,
            tx_pool_count,
            link,
            gateway,
        },
    })
}

fn check_mac(config: &Config, device: [u8; 6]) -> Result<(), OpenError> {
    if matches!(&config.device, Device::Pci(_)) {
        if let Some(expected) = config.mac {
            let actual = EthernetAddress(device);
            if expected != actual {
                return Err(OpenError::MacMismatch {
                    config: expected,
                    device: actual,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(device: &str, mac: &str) -> Config {
        Config::from_json(&format!(
            r#"{{
              "version": 1,
              "device": {device},
              "mac": {mac},
              "ipv4": "192.0.2.2/24",
              "gateway": null,
              "mtu": 1500,
              "paths": [],
              "offloads": "auto",
              "rx_timestamps": false,
              "descriptors": 16,
              "eal": {{"file_prefix": "mac-test", "extra": []}}
            }}"#
        ))
        .unwrap()
    }

    #[test]
    fn open_pci_mac_mismatch_is_error() {
        let expected = EthernetAddress([0x02, 0, 0, 0, 0, 1]);
        let actual = EthernetAddress([0x02, 0, 0, 0, 0, 2]);
        let pci = config(
            r#"{"pci":"0000:00:06.0","pci_id":"1d0f:ec20","devargs":"","kernel_driver":"ena","kernel_interface":"eth1","numa_node":0}"#,
            r#""02:00:00:00:00:01""#,
        );
        match check_mac(&pci, actual.0) {
            Err(OpenError::MacMismatch { config, device }) => {
                assert_eq!(config, expected);
                assert_eq!(device, actual);
            }
            other => panic!("unexpected result: {other:?}"),
        }
        assert!(check_mac(&pci, expected.0).is_ok());

        let vdev = config(r#"{"vdev":"net_tap0,iface=cdmac0"}"#, "null");
        assert!(check_mac(&vdev, actual.0).is_ok());
    }
}
