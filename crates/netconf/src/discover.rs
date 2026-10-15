use crate::{Config, Device, EalConfig, Offloads, PathRule, PciDevice};
use smoltcp::wire::{EthernetAddress, Ipv4Address, Ipv4Cidr};
use std::{
    ffi::CStr,
    fmt, fs,
    path::{Path, PathBuf},
};

pub struct Roots {
    pub sys: PathBuf,
    pub proc: PathBuf,
    pub dev: PathBuf,
}

impl Roots {
    pub fn host() -> Self {
        Self {
            sys: "/sys".into(),
            proc: "/proc".into(),
            dev: "/dev".into(),
        }
    }
}

#[derive(Debug)]
pub struct DiscoverError(pub(crate) String);

impl fmt::Display for DiscoverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.replace(['\n', '\r'], " "))
    }
}

pub struct Discovered {
    pub config: Config,
    pub operstate: String,
    pub warnings: Vec<String>,
}

struct Link {
    mac: EthernetAddress,
    mtu: u16,
    operstate: String,
}

fn fact_error(interface: &str, path: &Path, error: impl fmt::Display) -> DiscoverError {
    DiscoverError(format!("{interface}: {}: {error}", path.display()))
}

fn read(interface: &str, path: &Path) -> Result<String, DiscoverError> {
    fs::read_to_string(path)
        .map(|s| s.trim().to_owned())
        .map_err(|e| fact_error(interface, path, e))
}

fn link(roots: &Roots, interface: &str) -> Result<Link, DiscoverError> {
    let dir = roots.sys.join("class/net").join(interface);
    match fs::metadata(&dir) {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(DiscoverError(format!(
                "interface {interface} does not exist"
            )));
        }
        Err(e) => return Err(fact_error(interface, &dir, e)),
    }
    let address = dir.join("address");
    let mtu = dir.join("mtu");
    Ok(Link {
        mac: read(interface, &address)?
            .parse()
            .map_err(|()| fact_error(interface, &address, "invalid MAC address"))?,
        mtu: read(interface, &mtu)?
            .parse()
            .map_err(|e| fact_error(interface, &mtu, e))?,
        operstate: read(interface, &dir.join("operstate"))?,
    })
}

pub(crate) fn link_basename(path: &Path) -> std::io::Result<String> {
    let target = fs::read_link(path)?;
    target
        .file_name()
        .and_then(|s| s.to_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "link has no UTF-8 basename",
            )
        })
}

fn pci_device(roots: &Roots, interface: &str) -> Result<PciDevice, DiscoverError> {
    let device = roots.sys.join("class/net").join(interface).join("device");
    let not_pci = || DiscoverError(format!("{interface} is not a PCI device"));
    let pci = link_basename(&device).map_err(|_| not_pci())?;
    if link_basename(&device.join("subsystem")).map_err(|_| not_pci())? != "pci" {
        return Err(not_pci());
    }
    let driver = device.join("driver");
    let kernel_driver = match link_basename(&driver) {
        Ok(driver) => driver,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(DiscoverError(format!(
                "{interface} ({pci}) has no kernel driver bound"
            )));
        }
        Err(e) => return Err(fact_error(interface, &driver, e)),
    };
    let dir = roots.sys.join("bus/pci/devices").join(&pci);
    let numa = dir.join("numa_node");
    Ok(PciDevice {
        pci,
        pci_id: pci_id(interface, &dir)?,
        devargs: String::new(),
        kernel_driver,
        kernel_interface: interface.into(),
        numa_node: read(interface, &numa)?
            .parse()
            .map_err(|e| fact_error(interface, &numa, e))?,
    })
}

pub(crate) fn pci_id(interface: &str, dir: &Path) -> Result<String, DiscoverError> {
    let id = |name: &str| -> Result<String, DiscoverError> {
        let value = read(interface, &dir.join(name))?;
        Ok(value
            .strip_prefix("0x")
            .unwrap_or(&value)
            .to_ascii_lowercase())
    };
    Ok(format!("{}:{}", id("vendor")?, id("device")?))
}

pub(crate) fn route_hex(interface: &str, path: &Path, value: &str) -> Result<u32, DiscoverError> {
    u32::from_str_radix(value, 16).map_err(|e| fact_error(interface, path, e))
}

fn default_gateway(roots: &Roots, interface: &str) -> Result<Option<Ipv4Address>, DiscoverError> {
    let path = roots.proc.join("net/route");
    let routes = read(interface, &path)?;
    let mut gateway = None;
    for row in routes.lines().skip(1) {
        let fields: Vec<_> = row.split_whitespace().collect();
        if fields.first().copied() != Some(interface) {
            continue;
        }
        if fields.len() < 8 {
            return Err(fact_error(
                interface,
                &path,
                "route row has fewer than eight columns",
            ));
        }
        let hex = |index| route_hex(interface, &path, fields[index]);
        if hex(1)? != 0 || hex(7)? != 0 || hex(3)? & 3 != 3 {
            continue;
        }
        let address = Ipv4Address::from(hex(2)?.to_ne_bytes());
        if let Some(previous) = gateway {
            return Err(fact_error(
                interface,
                &path,
                format!("several default gateways ({previous}, {address})"),
            ));
        }
        gateway = Some(address);
    }
    Ok(gateway)
}

pub(crate) struct Kernel {
    pub(crate) device: PciDevice,
    pub(crate) mac: EthernetAddress,
    pub(crate) mtu: u16,
    pub(crate) operstate: String,
    pub(crate) addresses: Vec<Ipv4Cidr>,
    pub(crate) gateway: Option<Ipv4Address>,
}

pub(crate) fn gather(
    roots: &Roots,
    interface: &str,
    addresses: &[Ipv4Cidr],
) -> Result<Kernel, DiscoverError> {
    let link = link(roots, interface)?;
    Ok(Kernel {
        device: pci_device(roots, interface)?,
        mac: link.mac,
        mtu: link.mtu,
        operstate: link.operstate,
        addresses: addresses.to_vec(),
        gateway: default_gateway(roots, interface)?,
    })
}

pub(crate) fn choose_address(
    interface: &str,
    addresses: &[Ipv4Cidr],
    select: Option<Ipv4Address>,
) -> Result<Ipv4Cidr, DiscoverError> {
    let ipv4 = if addresses.is_empty() {
        return Err(DiscoverError(format!("{interface} has no IPv4 address")));
    } else if let Some(select) = select {
        addresses
            .iter()
            .find(|a| a.address() == select)
            .copied()
            .ok_or_else(|| {
                DiscoverError(format!("{select} is not an IPv4 address of {interface}"))
            })?
    } else if addresses.len() == 1 {
        addresses[0]
    } else {
        let addresses = addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(DiscoverError(format!(
            "{interface} has several IPv4 addresses ({addresses}); choose one with --ipv4"
        )));
    };
    Ok(ipv4)
}

pub fn discover(
    roots: &Roots,
    interface: &str,
    addresses: &[Ipv4Cidr],
    select: Option<Ipv4Address>,
) -> Result<Discovered, DiscoverError> {
    let kernel = gather(roots, interface, addresses)?;
    let ipv4 = choose_address(interface, &kernel.addresses, select)?;
    build(kernel, ipv4, None)
}

pub fn discover_aws(
    roots: &Roots,
    interface: &str,
    addresses: &[Ipv4Cidr],
    select: Option<Ipv4Address>,
    imds: &crate::imds::Imds,
) -> Result<Discovered, DiscoverError> {
    let kernel = gather(roots, interface, addresses)?;
    let aws = crate::aws::derive(imds, &kernel, select)?;
    build(kernel, aws.ipv4, Some(aws))
}

fn build(
    kernel: Kernel,
    ipv4: Ipv4Cidr,
    aws: Option<crate::aws::Aws>,
) -> Result<Discovered, DiscoverError> {
    let mut paths: Vec<PathRule> = aws
        .as_ref()
        .map(|a| {
            a.vpc_blocks
                .iter()
                .map(|prefix| PathRule {
                    prefix: *prefix,
                    mtu: 9001,
                    why: "vpc".into(),
                })
                .collect()
        })
        .unwrap_or_default();
    paths.push(PathRule {
        prefix: Ipv4Cidr::new(Ipv4Address::UNSPECIFIED, 0),
        mtu: 1500,
        why: "default".into(),
    });
    let config = Config {
        device: Device::Pci(kernel.device),
        mac: Some(kernel.mac),
        ipv4,
        gateway: aws.as_ref().map(|a| a.gateway).or(kernel.gateway),
        mtu: kernel.mtu,
        paths,
        offloads: Offloads::Auto,
        rx_timestamps: false,
        descriptors: 1024,
        eal: EalConfig {
            file_prefix: "zhida".into(),
            extra: Vec::new(),
        },
    };
    Ok(Discovered {
        config: Config::from_json(&config.to_json()).map_err(|e| DiscoverError(e.to_string()))?,
        operstate: kernel.operstate,
        warnings: aws.map(|a| a.warnings).unwrap_or_default(),
    })
}

pub fn ipv4_addresses(interface: &str) -> Result<Vec<Ipv4Cidr>, DiscoverError> {
    struct Ifaddrs(*mut libc::ifaddrs);
    impl Drop for Ifaddrs {
        fn drop(&mut self) {
            // The list belongs to getifaddrs and stays alive until this guard drops.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let mut head = std::ptr::null_mut();
    // getifaddrs initializes head on success.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(DiscoverError(format!(
            "{interface}: getifaddrs: {}",
            std::io::Error::last_os_error()
        )));
    }
    let list = Ifaddrs(head);
    let mut current = list.0;
    let mut addresses = Vec::new();
    while !current.is_null() {
        // All entries and names belong to the live list. AF_INET selects sockaddr_in.
        unsafe {
            let entry = &*current;
            if !entry.ifa_name.is_null()
                && CStr::from_ptr(entry.ifa_name).to_bytes() == interface.as_bytes()
                && !entry.ifa_addr.is_null()
                && i32::from((*entry.ifa_addr).sa_family) == libc::AF_INET
            {
                if entry.ifa_netmask.is_null() {
                    return Err(DiscoverError(format!(
                        "{interface}: IPv4 netmask is missing"
                    )));
                }
                let addr = &*entry.ifa_addr.cast::<libc::sockaddr_in>();
                let mask = &*entry.ifa_netmask.cast::<libc::sockaddr_in>();
                let mask = u32::from_be_bytes(mask.sin_addr.s_addr.to_ne_bytes());
                let prefix = mask.count_ones() as u8;
                if mask.leading_ones() != u32::from(prefix) {
                    return Err(DiscoverError(format!(
                        "{interface}: IPv4 netmask is non-contiguous"
                    )));
                }
                addresses.push(Ipv4Cidr::new(
                    Ipv4Address::from(addr.sin_addr.s_addr.to_ne_bytes()),
                    prefix,
                ));
            }
            current = entry.ifa_next;
        }
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    mod aws;
    use super::*;
    use std::{
        os::unix::fs::symlink,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct Tree {
        dir: PathBuf,
        roots: Roots,
    }

    impl Tree {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "netconf-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let roots = Roots {
                sys: dir.join("sys"),
                proc: dir.join("proc"),
                dev: dir.join("dev"),
            };
            for path in [
                "devices/pci0000:00/0000:00:06.0",
                "bus/pci/drivers/ena",
                "bus/pci/devices",
                "class/net/eth1",
            ] {
                fs::create_dir_all(roots.sys.join(path)).unwrap();
            }
            fs::create_dir_all(roots.proc.join("net")).unwrap();
            let tree = Self { dir, roots };
            for (path, value) in [
                ("class/net/eth1/address", "0a:12:34:56:78:9a\n"),
                ("class/net/eth1/mtu", "9001\n"),
                ("class/net/eth1/operstate", "up\n"),
                ("devices/pci0000:00/0000:00:06.0/vendor", "0x1D0F\n"),
                ("devices/pci0000:00/0000:00:06.0/device", "0xec20\n"),
                ("devices/pci0000:00/0000:00:06.0/numa_node", "0\n"),
            ] {
                tree.write(path, value);
            }
            for (path, target) in [
                (
                    "devices/pci0000:00/0000:00:06.0/driver",
                    "../../../bus/pci/drivers/ena",
                ),
                (
                    "devices/pci0000:00/0000:00:06.0/subsystem",
                    "../../../bus/pci",
                ),
                (
                    "bus/pci/devices/0000:00:06.0",
                    "../../../devices/pci0000:00/0000:00:06.0",
                ),
                (
                    "class/net/eth1/device",
                    "../../../devices/pci0000:00/0000:00:06.0",
                ),
            ] {
                symlink(target, tree.roots.sys.join(path)).unwrap();
            }
            tree.routes("eth1 00000000 0101000A 0003 0 0 0 00000000\n");
            tree
        }

        fn write(&self, path: &str, value: &str) {
            fs::write(self.roots.sys.join(path), value).unwrap();
        }

        fn routes(&self, rows: &str) {
            fs::write(self.roots.proc.join("net/route"), format!("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n{rows}")).unwrap();
        }

        fn discover(
            &self,
            addresses: &[Ipv4Cidr],
            select: Option<Ipv4Address>,
        ) -> Result<Discovered, DiscoverError> {
            discover(&self.roots, "eth1", addresses, select)
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.dir).unwrap();
        }
    }

    fn addresses() -> Vec<Ipv4Cidr> {
        vec!["10.0.1.23/24".parse().unwrap()]
    }

    #[test]
    fn discover_reads_mac_mtu_bdf_driver_pci_id_numa() {
        let tree = Tree::new();
        for numa_node in [0, -1] {
            tree.write(
                "devices/pci0000:00/0000:00:06.0/numa_node",
                &format!("{numa_node}\n"),
            );
            let discovered = tree.discover(&addresses(), None).unwrap();
            let expected = Config {
                device: Device::Pci(PciDevice {
                    pci: "0000:00:06.0".into(),
                    pci_id: "1d0f:ec20".into(),
                    devargs: String::new(),
                    kernel_driver: "ena".into(),
                    kernel_interface: "eth1".into(),
                    numa_node,
                }),
                mac: Some("0a:12:34:56:78:9a".parse().unwrap()),
                ipv4: addresses()[0],
                gateway: Some("10.0.1.1".parse().unwrap()),
                mtu: 9001,
                paths: vec![PathRule {
                    prefix: "0.0.0.0/0".parse().unwrap(),
                    mtu: 1500,
                    why: "default".into(),
                }],
                offloads: Offloads::Auto,
                rx_timestamps: false,
                descriptors: 1024,
                eal: EalConfig {
                    file_prefix: "zhida".into(),
                    extra: Vec::new(),
                },
            };
            assert_eq!(discovered.config, expected);
            assert_eq!(discovered.operstate, "up");
            assert_eq!(
                Config::from_json(&discovered.config.to_json()).unwrap(),
                expected
            );
            let facts = link(&tree.roots, "eth1").unwrap();
            assert_eq!(facts.mac, expected.mac.unwrap());
            assert_eq!(facts.mtu, expected.mtu);
            assert_eq!(facts.operstate, "up");
            assert_eq!(
                Device::Pci(pci_device(&tree.roots, "eth1").unwrap()),
                expected.device
            );
        }
        tree.write("class/net/eth1/operstate", "down\n");
        assert_eq!(tree.discover(&addresses(), None).unwrap().operstate, "down");
        tree.write("class/net/eth1/mtu", "87\n");
        assert_eq!(
            tree.discover(&addresses(), None).err().unwrap().to_string(),
            "mtu: must be at least 88 (48-byte minimum TCP MSS + 40 bytes of headers)"
        );
        tree.write("class/net/eth1/mtu", "65536\n");
        assert!(link(&tree.roots, "eth1")
            .err()
            .unwrap()
            .to_string()
            .contains("eth1: "));
        tree.write("class/net/eth1/mtu", "9001\n");
        tree.write("class/net/eth1/address", "bad\n");
        assert!(link(&tree.roots, "eth1")
            .err()
            .unwrap()
            .to_string()
            .contains("class/net/eth1/address"));
    }

    #[test]
    fn discover_non_pci_interface_is_named_error() {
        let tree = Tree::new();
        let device = tree.roots.sys.join("class/net/eth1/device");
        fs::remove_file(&device).unwrap();
        assert_eq!(
            tree.discover(&addresses(), None).err().unwrap().to_string(),
            "eth1 is not a PCI device"
        );
        symlink("../../../devices/pci0000:00/0000:00:06.0", &device).unwrap();
        let subsystem = device.join("subsystem");
        fs::remove_file(&subsystem).unwrap();
        fs::create_dir_all(tree.roots.sys.join("bus/virtio")).unwrap();
        symlink("../../../bus/virtio", &subsystem).unwrap();
        assert_eq!(
            tree.discover(&addresses(), None).err().unwrap().to_string(),
            "eth1 is not a PCI device"
        );
        assert_eq!(
            discover(&tree.roots, "absent", &addresses(), None)
                .err()
                .unwrap()
                .to_string(),
            "interface absent does not exist"
        );
        fs::remove_file(&subsystem).unwrap();
        symlink("../../../bus/pci", &subsystem).unwrap();
        fs::remove_file(device.join("driver")).unwrap();
        assert_eq!(
            pci_device(&tree.roots, "eth1").unwrap_err().to_string(),
            "eth1 (0000:00:06.0) has no kernel driver bound"
        );
    }

    #[test]
    fn discover_gateway_from_interface_row_only() {
        let tree = Tree::new();
        tree.routes("eth0 00000000 0102000A 0003 0 0 0 00000000\neth1 00000000 0101000A 0003 0 0 0 00000000\neth1 0001000A 00000000 0001 0 0 0 00FFFFFF\n");
        assert_eq!(
            default_gateway(&tree.roots, "eth1").unwrap(),
            Some("10.0.1.1".parse().unwrap())
        );
        assert_eq!(
            tree.discover(&addresses(), None).unwrap().config.gateway,
            Some("10.0.1.1".parse().unwrap())
        );
        tree.routes("eth0 00000000 0102000A 0003 0 0 0 00000000\neth1 00000000 0101000A 0001 0 0 0 00000000\neth1 00000000 0101000A 0002 0 0 0 00000000\neth1 0001000A 00000000 0001 0 0 0 00FFFFFF\n");
        assert_eq!(default_gateway(&tree.roots, "eth1").unwrap(), None);
        assert!(tree
            .discover(&addresses(), None)
            .unwrap()
            .config
            .gateway
            .is_none());
        tree.routes("eth1 00000000 0101000A 0003 0 0 0 00000000\neth1 00000000 0201000A 0003 0 0 0 00000000\n");
        let error = default_gateway(&tree.roots, "eth1")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("eth1")
                && error.contains("net/route")
                && error.contains("10.0.1.1, 10.0.1.2")
        );
        tree.routes("other malformed row\neth1 00000000 invalid 0003 0 0 0 00000000\n");
        assert!(default_gateway(&tree.roots, "eth1")
            .unwrap_err()
            .to_string()
            .contains("net/route"));
    }

    #[test]
    fn discover_multiple_ipv4_requires_selection() {
        let tree = Tree::new();
        let addresses = [
            "10.0.1.23/24".parse().unwrap(),
            "10.0.1.24/24".parse().unwrap(),
        ];
        assert_eq!(
            tree.discover(&addresses, None).err().unwrap().to_string(),
            "eth1 has several IPv4 addresses (10.0.1.23/24, 10.0.1.24/24); choose one with --ipv4"
        );
        assert_eq!(
            tree.discover(&addresses, Some(addresses[1].address()))
                .unwrap()
                .config
                .ipv4,
            addresses[1]
        );
        assert_eq!(
            tree.discover(&addresses, Some("10.0.1.25".parse().unwrap()))
                .err()
                .unwrap()
                .to_string(),
            "10.0.1.25 is not an IPv4 address of eth1"
        );
        assert_eq!(
            tree.discover(&[], None).err().unwrap().to_string(),
            "eth1 has no IPv4 address"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_facts_of_veth_match_ip_addr() {
        use std::process::Command;
        fn ip(args: &[&str]) -> Vec<u8> {
            let output = Command::new("ip")
                .args(args)
                .output()
                .expect("could not run ip");
            assert!(
                output.status.success(),
                "ip {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            );
            output.stdout
        }
        struct Veth(String);
        impl Drop for Veth {
            fn drop(&mut self) {
                let output = Command::new("ip")
                    .args(["link", "del", &self.0])
                    .output()
                    .expect("could not run ip cleanup");
                if !output.status.success() {
                    eprintln!(
                        "ip link del {}: {}",
                        self.0,
                        String::from_utf8_lossy(&output.stderr)
                    );
                    if !std::thread::panicking() {
                        panic!("veth cleanup failed");
                    }
                }
            }
        }
        let pid = std::process::id();
        let interface = format!("cnf{pid}a");
        let peer = format!("cnf{pid}b");
        let x = pid % 250 + 1;
        let address = format!("198.18.{x}.2/24");
        let gateway = format!("198.18.{x}.1");
        ip(&[
            "link", "add", &interface, "type", "veth", "peer", "name", &peer,
        ]);
        let _guard = Veth(interface.clone());
        ip(&["link", "set", "dev", &interface, "mtu", "1400"]);
        ip(&["addr", "add", &address, "dev", &interface]);
        ip(&["link", "set", "dev", &interface, "up"]);
        ip(&["link", "set", "dev", &peer, "up"]);
        ip(&[
            "route", "add", "default", "via", &gateway, "dev", &interface, "metric", "4242",
        ]);
        let report: serde_json::Value =
            serde_json::from_slice(&ip(&["-j", "addr", "show", "dev", &interface])).unwrap();
        let reported = &report[0];
        let reported_addresses: Vec<Ipv4Cidr> = reported["addr_info"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["family"] == "inet")
            .map(|entry| {
                format!(
                    "{}/{}",
                    entry["local"].as_str().unwrap(),
                    entry["prefixlen"].as_u64().unwrap()
                )
                .parse()
                .unwrap()
            })
            .collect();
        assert_eq!(ipv4_addresses(&interface).unwrap(), reported_addresses);
        assert_eq!(reported_addresses, vec![address.parse().unwrap()]);
        let facts = link(&Roots::host(), &interface).unwrap();
        assert_eq!(
            facts.mac,
            reported["address"].as_str().unwrap().parse().unwrap()
        );
        assert_eq!(u64::from(facts.mtu), reported["mtu"].as_u64().unwrap());
        assert_eq!(facts.mtu, 1400);
        assert_eq!(
            facts.operstate.to_ascii_uppercase(),
            reported["operstate"].as_str().unwrap()
        );
        let link_report: serde_json::Value =
            serde_json::from_slice(&ip(&["-j", "link", "show", "dev", &interface])).unwrap();
        assert_eq!(reported["mtu"], link_report[0]["mtu"]);
        assert_eq!(reported["address"], link_report[0]["address"]);
        assert_eq!(
            default_gateway(&Roots::host(), &interface).unwrap(),
            Some(gateway.parse().unwrap())
        );
    }
}
