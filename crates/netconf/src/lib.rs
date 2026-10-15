//! Reads and writes the zhida network config (`dut.json`), discovers it from a
//! Linux interface, and binds the NIC to vfio-pci. The `zhida-netconf` binary
//! wraps these steps; `crates/nic-runner/README.md` walks through them and
//! `docs/USAGE.md` shows how an application loads the config.

mod aws;
mod config;
pub mod discover;
pub mod imds;

pub use config::{Config, ConfigError, Device, EalConfig, Offloads, PathRule, PciDevice};
pub mod devbind;
pub mod rediscover;
