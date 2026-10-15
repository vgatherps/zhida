use zhida_netconf::{devbind, discover::Roots, Config, Device};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const BDF: &str = "0000:00:06.0";
const DEVICE: &str = "devices/pci0000:00/0000:00:06.0";
const CONNECTED: &str = "eth1 0001000A 00000000 0001 0 0 0 00FFFFFF\n";

struct Tree {
    dir: PathBuf,
    roots: Roots,
    config: Config,
}

impl Tree {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "netconf-devbind-{}-{}",
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
            DEVICE,
            "bus/pci/devices",
            "bus/pci/drivers/ena",
            "bus/pci/drivers/vfio-pci",
            "class/net/eth1",
            "kernel/iommu_groups/7/devices",
            "module/vfio/parameters",
        ] {
            fs::create_dir_all(roots.sys.join(path)).unwrap();
        }
        fs::create_dir_all(roots.sys.join(DEVICE).join("net/eth1")).unwrap();
        fs::create_dir_all(roots.proc.join("net")).unwrap();
        fs::create_dir_all(roots.dev.join("vfio")).unwrap();
        fs::write(roots.dev.join("vfio/7"), "").unwrap();
        let config = Config::from_json(
            r#"{
            "version": 1, "device": {"pci": "0000:00:06.0", "pci_id": "1d0f:ec20",
                "devargs": "", "kernel_driver": "ena", "kernel_interface": "eth1", "numa_node": 0},
            "mac": "0a:12:34:56:78:9a", "ipv4": "10.0.1.23/24", "gateway": null,
            "mtu": 9001, "paths": [], "offloads": "auto", "rx_timestamps": false,
            "descriptors": 1024, "eal": {"file_prefix": "zhida", "extra": []}
        }"#,
        )
        .unwrap();
        let tree = Self { dir, roots, config };
        for (path, value) in [
            (format!("{DEVICE}/vendor"), "0x1D0F\n"),
            (format!("{DEVICE}/device"), "0xec20\n"),
            (format!("{DEVICE}/numa_node"), "0\n"),
            (format!("{DEVICE}/net/eth1/address"), "0a:12:34:56:78:9a\n"),
            (format!("{DEVICE}/driver_override"), ""),
            ("bus/pci/drivers/ena/bind".into(), ""),
            ("bus/pci/drivers/ena/unbind".into(), ""),
            ("bus/pci/drivers/vfio-pci/bind".into(), ""),
            ("bus/pci/drivers/vfio-pci/unbind".into(), ""),
            ("bus/pci/drivers_probe".into(), ""),
            (
                "module/vfio/parameters/enable_unsafe_noiommu_mode".into(),
                "N",
            ),
        ] {
            tree.write(&path, value);
        }
        for (path, target) in [
            (format!("{DEVICE}/subsystem"), "../../../bus/pci"),
            (
                format!("{DEVICE}/iommu_group"),
                "../../../kernel/iommu_groups/7",
            ),
            (
                format!("bus/pci/devices/{BDF}"),
                "../../../devices/pci0000:00/0000:00:06.0",
            ),
            (
                format!("kernel/iommu_groups/7/devices/{BDF}"),
                "../../../../devices/pci0000:00/0000:00:06.0",
            ),
            (
                "class/net/eth1/device".into(),
                "../../../devices/pci0000:00/0000:00:06.0",
            ),
        ] {
            symlink(target, tree.roots.sys.join(path)).unwrap();
        }
        tree.driver(Some("ena"));
        tree.routes(CONNECTED);
        tree
    }

    fn write(&self, path: &str, value: &str) {
        fs::write(self.roots.sys.join(path), value).unwrap();
    }
    fn routes(&self, rows: &str) {
        fs::write(
            self.roots.proc.join("net/route"),
            format!(
                "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n{rows}"
            ),
        )
        .unwrap();
    }
    fn driver(&self, name: Option<&str>) {
        let path = self.roots.sys.join(DEVICE).join("driver");
        if fs::symlink_metadata(&path).is_ok() {
            fs::remove_file(&path).unwrap();
        }
        if let Some(name) = name {
            symlink(format!("../../../bus/pci/drivers/{name}"), path).unwrap();
        }
    }
    fn peer(&self, name: Option<&str>) {
        let peer = self.roots.sys.join("devices/pci0000:00/0000:00:07.0");
        fs::create_dir_all(&peer).unwrap();
        symlink(
            &peer,
            self.roots
                .sys
                .join("kernel/iommu_groups/7/devices/0000:00:07.0"),
        )
        .unwrap();
        if let Some(name) = name {
            symlink(
                self.roots.sys.join(format!("bus/pci/drivers/{name}")),
                peer.join("driver"),
            )
            .unwrap();
        }
    }
    fn log(&self, writes: &[(&str, &str)], dry: bool) -> String {
        writes
            .iter()
            .map(|(p, v)| {
                format!(
                    "{}write '{v}' > {}\n",
                    if dry { "dry-run: " } else { "" },
                    self.roots.sys.join(p).display()
                )
            })
            .collect()
    }
    fn bind_writes(&self, bound: bool) -> Vec<(&'static str, &'static str)> {
        let mut writes = Vec::new();
        if bound {
            writes.push(("bus/pci/devices/0000:00:06.0/driver/unbind", BDF));
        }
        writes.extend([
            ("bus/pci/devices/0000:00:06.0/driver_override", "vfio-pci"),
            ("bus/pci/drivers/vfio-pci/bind", BDF),
            ("bus/pci/devices/0000:00:06.0/driver_override", "\n"),
        ]);
        writes
    }
    fn unbind_writes(&self, bound: bool) -> Vec<(&'static str, &'static str)> {
        let mut writes = Vec::new();
        if bound {
            writes.push(("bus/pci/drivers/vfio-pci/unbind", BDF));
        }
        writes.extend([
            ("bus/pci/devices/0000:00:06.0/driver_override", "\n"),
            ("bus/pci/drivers_probe", BDF),
        ]);
        writes
    }
    fn snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        fn walk(dir: &Path, entries: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let kind = fs::symlink_metadata(&path).unwrap().file_type();
                if kind.is_symlink() {
                    entries.insert(
                        path.clone(),
                        fs::read_link(path)
                            .unwrap()
                            .as_os_str()
                            .as_encoded_bytes()
                            .to_vec(),
                    );
                } else if kind.is_dir() {
                    entries.insert(path.clone(), Vec::new());
                    walk(&path, entries);
                } else {
                    entries.insert(path.clone(), fs::read(path).unwrap());
                }
            }
        }
        let mut entries = BTreeMap::new();
        walk(&self.dir, &mut entries);
        entries
    }
    fn refuse(&self, euid: u32, noiommu: bool) -> String {
        let before = self.snapshot();
        let mut output = Vec::new();
        let err = devbind::bind(&self.roots, &self.config, euid, noiommu, false, &mut output)
            .unwrap_err();
        assert_eq!(output, b"");
        assert_eq!(self.snapshot(), before);
        err.to_string()
    }
    fn success_bind(&self, bound: bool) {
        let mut output = KernelOutput::new(self, "vfio-pci");
        devbind::bind(&self.roots, &self.config, 0, false, false, &mut output).unwrap();
        let expected = self.log(&self.bind_writes(bound), false);
        assert_eq!(
            output.text,
            format!(
                "{expected}{BDF} bound to vfio-pci ({})\n",
                self.roots.dev.join("vfio/7").display()
            )
        );
        assert_eq!(
            fs::read(self.roots.sys.join("bus/pci/drivers/vfio-pci/bind")).unwrap(),
            BDF.as_bytes()
        );
        assert_eq!(
            fs::read(self.roots.sys.join(DEVICE).join("driver_override")).unwrap(),
            b"\nfio-pci"
        );
        assert_eq!(
            fs::read(self.roots.sys.join("bus/pci/drivers/ena/unbind")).unwrap(),
            if bound { BDF.as_bytes() } else { b"" }
        );
    }
}
impl Drop for Tree {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.dir).unwrap();
    }
}

// Regular files do not run driver callbacks. Change only the fake driver link,
// after the bind write (at the following clear log), or before drivers_probe.
struct KernelOutput<'a> {
    tree: &'a Tree,
    target: &'static str,
    text: String,
    changed: bool,
}
impl<'a> KernelOutput<'a> {
    fn new(tree: &'a Tree, target: &'static str) -> Self {
        Self {
            tree,
            target,
            text: String::new(),
            changed: false,
        }
    }
}
impl Write for KernelOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.text.push_str(std::str::from_utf8(bytes).unwrap());
        let trigger = if self.target == "vfio-pci" {
            self.tree.log(
                &[("bus/pci/devices/0000:00:06.0/driver_override", "\n")],
                false,
            )
        } else {
            self.tree.log(&[("bus/pci/drivers_probe", BDF)], false)
        };
        if !self.changed && self.text.ends_with(&trigger) {
            self.tree.driver(Some(self.target));
            self.changed = true;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn bind_plan_is_unbind_override_bind_clear() {
    Tree::new().success_bind(true);
}

#[test]
fn bind_singleton_iommu_group_passes() {
    let tree = Tree::new();
    tree.success_bind(true);
    for peer in [None, Some("vfio-pci")] {
        let tree = Tree::new();
        tree.peer(peer);
        tree.success_bind(true);
    }
}

#[test]
fn bind_refuses_iommu_group_with_kernel_bound_peer() {
    let tree = Tree::new();
    tree.peer(Some("ena"));
    let err = tree.refuse(0, false);
    assert!(err.contains("0000:00:07.0") && err.contains("ena"), "{err}");
}

#[test]
fn bind_refuses_noiommu_without_flag() {
    let tree = Tree::new();
    fs::remove_file(tree.roots.sys.join(DEVICE).join("iommu_group")).unwrap();
    let err = tree.refuse(0, false);
    assert!(err.contains("taints the kernel") && err.contains("--noiommu"));
    let before = tree.snapshot();
    let mut output = Vec::new();
    devbind::bind(&tree.roots, &tree.config, 0, true, true, &mut output).unwrap();
    let mut expected = vec![("module/vfio/parameters/enable_unsafe_noiommu_mode", "1")];
    expected.extend(tree.bind_writes(true));
    assert_eq!(
        String::from_utf8(output).unwrap(),
        tree.log(&expected, true)
    );
    assert_eq!(tree.snapshot(), before);
    // A regular-file bind does not create a no-IOMMU group, so verification fails.
    let mut output = Vec::new();
    let err = devbind::bind(&tree.roots, &tree.config, 0, true, false, &mut output).unwrap_err();
    expected.extend([
        ("bus/pci/devices/0000:00:06.0/driver_override", "\n"),
        ("bus/pci/drivers/ena/bind", BDF),
    ]);
    assert_eq!(
        String::from_utf8(output).unwrap(),
        tree.log(&expected, false)
    );
    assert_eq!(
        fs::read(
            tree.roots
                .sys
                .join("module/vfio/parameters/enable_unsafe_noiommu_mode")
        )
        .unwrap(),
        b"1"
    );
    assert!(err.to_string().contains("rebind ok"));
    for enabled in ["Y", "1"] {
        tree.write("module/vfio/parameters/enable_unsafe_noiommu_mode", enabled);
        let mut output = Vec::new();
        devbind::bind(&tree.roots, &tree.config, 0, true, true, &mut output).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            tree.log(&tree.bind_writes(true), true)
        );
    }
}

#[test]
fn bind_noiommu_loads_vfio_before_enable_write() {
    let tree = Tree::new();
    fs::remove_file(tree.roots.sys.join(DEVICE).join("iommu_group")).unwrap();
    fs::remove_dir_all(tree.roots.sys.join("bus/pci/drivers/vfio-pci")).unwrap();
    fs::remove_file(
        tree.roots
            .sys
            .join("module/vfio/parameters/enable_unsafe_noiommu_mode"),
    )
    .unwrap();
    assert!(tree.refuse(0, false).contains("--noiommu"));
    let before = tree.snapshot();
    let mut output = Vec::new();
    devbind::bind(&tree.roots, &tree.config, 0, true, true, &mut output).unwrap();
    let mut writes = vec![("module/vfio/parameters/enable_unsafe_noiommu_mode", "1")];
    writes.extend(tree.bind_writes(true));
    assert_eq!(
        String::from_utf8(output).unwrap(),
        format!("dry-run: modprobe vfio-pci\n{}", tree.log(&writes, true))
    );
    assert_eq!(tree.snapshot(), before);
}

#[test]
fn bind_noiommu_parameter_read_error_refuses() {
    let tree = Tree::new();
    fs::remove_file(tree.roots.sys.join(DEVICE).join("iommu_group")).unwrap();
    fs::remove_dir_all(tree.roots.sys.join("bus/pci/drivers/vfio-pci")).unwrap();
    let parameter = tree
        .roots
        .sys
        .join("module/vfio/parameters/enable_unsafe_noiommu_mode");
    fs::remove_file(&parameter).unwrap();
    fs::create_dir(&parameter).unwrap();
    assert!(tree.refuse(0, true).contains("enable_unsafe_noiommu_mode"));
}

#[test]
fn bind_refuses_route_other_than_connected_subnet() {
    for (row, route) in [
        (
            "eth1 00000000 0101000A 0003 0 0 0 00000000\n",
            "0.0.0.0/0 via 10.0.1.1",
        ),
        (
            "eth1 0002000A 00000000 0001 0 0 0 00FFFFFF\n",
            "10.0.2.0/24 via 0.0.0.0",
        ),
        (
            "eth1 0001000A 00000000 0003 0 0 0 00FFFFFF\n",
            "10.0.1.0/24 via 0.0.0.0",
        ),
        (
            "eth1 0001000A 0101000A 0001 0 0 0 00FFFFFF\n",
            "10.0.1.0/24 via 10.0.1.1",
        ),
    ] {
        let tree = Tree::new();
        tree.routes(row);
        assert!(tree.refuse(0, false).contains(route));
    }
}

#[test]
fn bind_allows_only_connected_subnet_route() {
    let tree = Tree::new();
    tree.routes(&format!(
        "{CONNECTED}eth0 00000000 0101000A 0003 0 0 0 00000000\n"
    ));
    tree.success_bind(true);
}

#[test]
fn bind_refuses_changed_mac_or_pci_id() {
    for (path, value, actual, configured) in [
        (
            "net/eth1/address",
            "0a:00:00:00:00:01",
            "0a:00:00:00:00:01",
            "0A-12-34-56-78-9A",
        ),
        ("device", "0xabcd", "1d0f:abcd", "1d0f:ec20"),
    ] {
        let tree = Tree::new();
        tree.write(&format!("{DEVICE}/{path}"), value);
        let err = tree.refuse(0, false);
        assert!(
            err.contains(actual) && err.to_uppercase().contains(&configured.to_uppercase()),
            "{err}"
        );
    }
    let tree = Tree::new();
    fs::remove_dir_all(tree.roots.sys.join(DEVICE).join("net/eth1")).unwrap();
    assert!(tree.refuse(0, false).contains("net/eth1/address"));
}

#[test]
fn bind_resumes_with_no_driver_bound() {
    let tree = Tree::new();
    tree.driver(None);
    fs::remove_dir_all(tree.roots.sys.join(DEVICE).join("net")).unwrap();
    tree.routes("eth1 00000000 0101000A 0003 0 0 0 00000000\n");
    tree.success_bind(false);
}

#[test]
fn bind_already_bound_exits_zero() {
    let tree = Tree::new();
    tree.driver(Some("vfio-pci"));
    tree.write(&format!("{DEVICE}/driver_override"), "(null)\n");
    let before = tree.snapshot();
    let mut output = Vec::new();
    devbind::bind(&tree.roots, &tree.config, 0, false, false, &mut output).unwrap();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        format!(
            "{BDF} already bound to vfio-pci ({})\n",
            tree.roots.dev.join("vfio/7").display()
        )
    );
    assert_eq!(tree.snapshot(), before);
}

#[test]
fn bind_rerun_clears_leftover_override() {
    for dry_run in [true, false] {
        let tree = Tree::new();
        tree.driver(Some("vfio-pci"));
        tree.write(&format!("{DEVICE}/driver_override"), "vfio-pci");
        let before = tree.snapshot();
        let mut output = Vec::new();
        devbind::bind(&tree.roots, &tree.config, 0, false, dry_run, &mut output).unwrap();
        let clear = tree.log(
            &[("bus/pci/devices/0000:00:06.0/driver_override", "\n")],
            dry_run,
        );
        assert_eq!(
            String::from_utf8(output).unwrap(),
            if dry_run {
                clear
            } else {
                format!(
                    "{clear}{BDF} already bound to vfio-pci ({})\n",
                    tree.roots.dev.join("vfio/7").display()
                )
            }
        );
        if dry_run {
            assert_eq!(tree.snapshot(), before);
        } else {
            let mut expected = before;
            expected.insert(
                tree.roots.sys.join(DEVICE).join("driver_override"),
                b"\nfio-pci".to_vec(),
            );
            assert_eq!(tree.snapshot(), expected);
        }
    }
}

#[test]
fn bind_already_bound_verification_failure_does_not_rebind() {
    for missing_group in [false, true] {
        let tree = Tree::new();
        tree.driver(Some("vfio-pci"));
        if missing_group {
            fs::remove_file(tree.roots.sys.join(DEVICE).join("iommu_group")).unwrap();
        } else {
            fs::remove_file(tree.roots.dev.join("vfio/7")).unwrap();
        }
        let before = tree.snapshot();
        let mut output = Vec::new();
        let err = devbind::bind(&tree.roots, &tree.config, 0, false, false, &mut output)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(if missing_group {
                "No such file"
            } else {
                "bind verification: neither"
            }),
            "{err}"
        );
        assert!(output.is_empty());
        assert_eq!(tree.snapshot(), before);
    }
}

#[test]
fn bind_failure_clears_override_before_kernel_rebind() {
    for fail_bind in [false, true] {
        for fail_rebind in [false, true] {
            let tree = Tree::new();
            if fail_bind {
                fs::remove_file(tree.roots.sys.join("bus/pci/drivers/vfio-pci/bind")).unwrap();
            }
            if fail_rebind {
                fs::remove_file(tree.roots.sys.join("bus/pci/drivers/ena/bind")).unwrap();
            }
            let mut output = Vec::new();
            let err = devbind::bind(&tree.roots, &tree.config, 0, false, false, &mut output)
                .unwrap_err()
                .to_string();
            let mut expected = tree.bind_writes(true);
            if fail_bind {
                expected.pop();
            }
            expected.extend([
                ("bus/pci/devices/0000:00:06.0/driver_override", "\n"),
                ("bus/pci/drivers/ena/bind", BDF),
            ]);
            assert_eq!(
                String::from_utf8(output).unwrap(),
                tree.log(&expected, false)
            );
            assert_eq!(
                fs::read(tree.roots.sys.join(DEVICE).join("driver_override")).unwrap(),
                b"\nfio-pci"
            );
            if !fail_rebind {
                assert_eq!(
                    fs::read(tree.roots.sys.join("bus/pci/drivers/ena/bind")).unwrap(),
                    BDF.as_bytes()
                );
            }
            assert!(
                err.contains(if fail_bind {
                    "vfio-pci/bind"
                } else {
                    "bind verification: driver is ena"
                }),
                "{err}"
            );
            assert!(
                err.contains(if fail_rebind { "rebind:" } else { "rebind ok" }),
                "{err}"
            );
            assert!(err.contains("current driver ena"), "{err}");
        }
    }
}

fn success_unbind(bound: bool, back: bool) {
    let tree = Tree::new();
    tree.driver(if bound { Some("vfio-pci") } else { None });
    tree.write(&format!("{DEVICE}/driver_override"), "vfio-pci");
    let mut output = KernelOutput::new(&tree, "ena");
    let addresses = if back {
        vec![tree.config.ipv4]
    } else {
        vec!["10.0.1.24/24".parse().unwrap()]
    };
    devbind::unbind(&tree.roots, &tree.config, 0, || Ok(addresses), &mut output).unwrap();
    assert_eq!(
        output.text,
        format!(
            "{}{BDF} on ena; IPv4 10.0.1.23 {} on eth1\n",
            tree.log(&tree.unbind_writes(bound), false),
            if back { "is back" } else { "is not back" }
        )
    );
    assert_eq!(
        fs::read(tree.roots.sys.join("bus/pci/drivers_probe")).unwrap(),
        BDF.as_bytes()
    );
    assert_eq!(
        fs::read(tree.roots.sys.join("bus/pci/drivers/vfio-pci/unbind")).unwrap(),
        if bound { BDF.as_bytes() } else { b"" }
    );
    assert_eq!(
        fs::read(tree.roots.sys.join(DEVICE).join("driver_override")).unwrap(),
        b"\nfio-pci"
    );
}

#[test]
fn unbind_plan_uses_drivers_probe() {
    success_unbind(true, true);
    success_unbind(true, false);
    let tree = Tree::new();
    let before = tree.snapshot();
    let mut output = Vec::new();
    devbind::unbind(&tree.roots, &tree.config, 0, || Ok(Vec::new()), &mut output).unwrap();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        format!("{BDF} already on ena\n")
    );
    assert_eq!(tree.snapshot(), before);
    for missing_interface in [false, true] {
        let tree = Tree::new();
        tree.driver(Some("vfio-pci"));
        if missing_interface {
            fs::remove_dir_all(tree.roots.sys.join("class/net/eth1")).unwrap();
        }
        let mut output =
            KernelOutput::new(&tree, if missing_interface { "ena" } else { "vfio-pci" });
        let err = devbind::unbind(&tree.roots, &tree.config, 0, || Ok(Vec::new()), &mut output)
            .unwrap_err();
        assert!(err.to_string().contains("unbind verification"));
        assert_eq!(output.text, tree.log(&tree.unbind_writes(true), false));
    }
}

#[test]
fn unbind_resumes_with_no_driver_bound() {
    success_unbind(false, true);
}

#[test]
fn dry_run_writes_nothing() {
    for missing_vfio in [false, true] {
        let tree = Tree::new();
        if missing_vfio {
            fs::remove_dir_all(tree.roots.sys.join("bus/pci/drivers/vfio-pci")).unwrap();
        }
        let before = tree.snapshot();
        let mut output = Vec::new();
        devbind::bind(&tree.roots, &tree.config, 0, false, true, &mut output).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!(
                "{}{}",
                if missing_vfio {
                    "dry-run: modprobe vfio-pci\n"
                } else {
                    ""
                },
                tree.log(&tree.bind_writes(true), true)
            )
        );
        assert_eq!(tree.snapshot(), before);
    }
}

#[test]
fn refusal_writes_nothing() {
    let tree = Tree::new();
    assert!(tree.refuse(1000, false).contains("euid 0"));
    let tree = Tree::new();
    tree.driver(Some("other"));
    assert!(tree.refuse(0, false).contains("other"));
    let tree = Tree::new();
    tree.peer(Some("ena"));
    tree.refuse(0, false);
    let tree = Tree::new();
    tree.routes("eth1 00000000 0101000A 0003 0 0 0 00000000\n");
    tree.refuse(0, false);
    let tree = Tree::new();
    fs::remove_file(tree.roots.sys.join(DEVICE).join("iommu_group")).unwrap();
    tree.refuse(0, false);
    let tree = Tree::new();
    tree.write(&format!("{DEVICE}/vendor"), "0xabcd");
    tree.refuse(0, false);
    let tree = Tree::new();
    tree.write(&format!("{DEVICE}/net/eth1/address"), "0a:00:00:00:00:01");
    tree.refuse(0, false);
    let tree = Tree::new();
    fs::remove_dir_all(tree.roots.sys.join(DEVICE)).unwrap();
    tree.refuse(0, false);
    let mut tree = Tree::new();
    tree.config.device = Device::Vdev {
        vdev: "net_tap0,iface=cdnic0".into(),
    };
    tree.config.mac = None;
    assert_eq!(tree.refuse(0, false), "bind needs a PCI device");
    for euid in [0, 1000] {
        let before = tree.snapshot();
        let mut output = Vec::new();
        let err = devbind::unbind(
            &tree.roots,
            &tree.config,
            euid,
            || Ok(Vec::new()),
            &mut output,
        )
        .unwrap_err();
        assert!(err.to_string().contains(if euid == 0 {
            "bind needs a PCI device"
        } else {
            "euid 0"
        }));
        assert!(output.is_empty());
        assert_eq!(tree.snapshot(), before);
    }
}

#[test]
fn bind_cli_usage_and_vdev_refusal() {
    let mut tree = Tree::new();
    tree.config.device = Device::Vdev {
        vdev: "net_tap0,iface=cdnic0".into(),
    };
    tree.config.mac = None;
    let path = tree.dir.join("vdev.json");
    fs::write(&path, tree.config.to_json()).unwrap();
    for command in ["bind", "unbind"] {
        for args in [
            vec![command.into()],
            vec![
                command.into(),
                path.as_os_str().to_owned(),
                "--unknown".into(),
            ],
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_zhida-netconf"))
                .args(args)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            assert_eq!(String::from_utf8(output.stderr).unwrap().lines().count(), 1);
        }
        let before = tree.snapshot();
        let output = Command::new(env!("CARGO_BIN_EXE_zhida-netconf"))
            .arg(command)
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        // geteuid has no pointer arguments or preconditions.
        let euid = unsafe { libc::geteuid() };
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!(
                "zhida-netconf: {}\n",
                if euid == 0 {
                    "bind needs a PCI device"
                } else {
                    "bind/unbind needs euid 0"
                }
            )
        );
        assert_eq!(tree.snapshot(), before);
    }
}
