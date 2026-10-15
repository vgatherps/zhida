use crate::{
    discover::{link_basename, pci_id, route_hex, DiscoverError, Roots},
    Config, Device, PciDevice,
};
use smoltcp::wire::{EthernetAddress, Ipv4Address, Ipv4Cidr};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
};

type Result<T> = std::result::Result<T, DiscoverError>;

fn error(message: impl ToString) -> DiscoverError {
    DiscoverError(message.to_string())
}

fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path)
        .map(|s| s.trim().to_owned())
        .map_err(|e| error(format!("{}: {e}", path.display())))
}

fn driver(device: &Path) -> Result<Option<String>> {
    match link_basename(&device.join("driver")) {
        Ok(name) => Ok(Some(name)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(error(format!("{}: {e}", device.display()))),
    }
}

fn require_root(euid: u32) -> Result<()> {
    if euid != 0 {
        return Err(error("bind/unbind needs euid 0"));
    }
    Ok(())
}

struct State<'a> {
    pci: &'a PciDevice,
    device: PathBuf,
    driver: Option<String>,
}

fn state<'a>(roots: &Roots, config: &'a Config, euid: u32) -> Result<State<'a>> {
    require_root(euid)?;
    let Device::Pci(pci) = &config.device else {
        return Err(error("bind needs a PCI device"));
    };
    let device = roots.sys.join("bus/pci/devices").join(&pci.pci);
    fs::metadata(&device).map_err(|e| error(format!("{}: {e}", device.display())))?;
    let actual = pci_id(&pci.kernel_interface, &device)?;
    if actual != pci.pci_id {
        return Err(error(format!(
            "{} PCI ID {actual}, config {}",
            pci.pci, pci.pci_id
        )));
    }
    let current = driver(&device)?;
    if current.as_deref() == Some(&pci.kernel_driver) {
        let path = device
            .join("net")
            .join(&pci.kernel_interface)
            .join("address");
        let actual = read(&path)?;
        let mac: EthernetAddress = actual
            .parse()
            .map_err(|()| error(format!("{}: invalid MAC {actual}", path.display())))?;
        if Some(mac) != config.mac {
            return Err(error(format!(
                "{} MAC {actual}, config {}",
                pci.pci,
                config.mac.map_or_else(|| "none".into(), |m| m.to_string())
            )));
        }
    }
    if let Some(name) = &current {
        if name != "vfio-pci" && name != &pci.kernel_driver {
            return Err(error(format!("{} is bound to {name}", pci.pci)));
        }
    }
    Ok(State {
        pci,
        device,
        driver: current,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct SysfsWrite {
    path: PathBuf,
    value: String,
}

fn step(path: PathBuf, value: &str) -> SysfsWrite {
    SysfsWrite {
        path,
        value: value.into(),
    }
}

fn routes(roots: &Roots, config: &Config, pci: &PciDevice) -> Result<()> {
    let path = roots.proc.join("net/route");
    for row in read(&path)?.lines().skip(1) {
        let f: Vec<_> = row.split_whitespace().collect();
        if f.first().copied() != Some(&pci.kernel_interface) {
            continue;
        }
        if f.len() < 8 {
            return Err(error(format!(
                "{}: route row has fewer than eight columns",
                path.display()
            )));
        }
        let hex = |i: usize| route_hex(&pci.kernel_interface, &path, f[i]);
        let dest = Ipv4Address::from(hex(1)?.to_ne_bytes());
        let gw = Ipv4Address::from(hex(2)?.to_ne_bytes());
        let mask = u32::from_be_bytes(hex(7)?.to_ne_bytes());
        let prefix = mask.leading_ones();
        if dest != config.ipv4.network().address()
            || mask != u32::from_be_bytes(config.ipv4.netmask().octets())
            || gw != Ipv4Address::UNSPECIFIED
            || hex(3)? & 2 != 0
        {
            return Err(error(format!(
                "{} has route {dest}/{prefix} via {gw}",
                pci.kernel_interface
            )));
        }
    }
    Ok(())
}

fn bind_plan(
    roots: &Roots,
    config: &Config,
    state: &State<'_>,
    noiommu: bool,
) -> Result<Vec<SysfsWrite>> {
    if state.driver.as_deref() == Some("vfio-pci") {
        let path = state.device.join("driver_override");
        return Ok(if matches!(read(&path)?.as_str(), "" | "(null)") {
            Vec::new()
        } else {
            vec![step(path, "\n")]
        });
    }
    if state.driver.is_some() {
        routes(roots, config, state.pci)?;
    }
    let mut plan = Vec::new();
    let group_link = state.device.join("iommu_group");
    match fs::read_link(&group_link) {
        Ok(_) => {
            let mut peers = fs::read_dir(group_link.join("devices"))
                .map_err(error)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(error)?;
            peers.sort_by_key(|p| p.file_name());
            for peer in peers {
                if peer.file_name() == state.pci.pci.as_str() {
                    continue;
                }
                if let Some(name) = driver(&peer.path())? {
                    if name != "vfio-pci" {
                        return Err(error(format!(
                            "IOMMU peer {} is bound to {name}",
                            peer.file_name().to_string_lossy()
                        )));
                    }
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if !noiommu {
                return Err(error("no-IOMMU mode taints the kernel and needs --noiommu"));
            }
            let path = roots
                .sys
                .join("module/vfio/parameters/enable_unsafe_noiommu_mode");
            let enabled = match fs::read_to_string(&path) {
                Ok(value) => matches!(value.trim(), "Y" | "1"),
                Err(e) if e.kind() == io::ErrorKind::NotFound => false,
                Err(e) => return Err(error(format!("{}: {e}", path.display()))),
            };
            if !enabled {
                plan.push(step(path, "1"));
            }
        }
        Err(e) => return Err(error(e)),
    }
    if state.driver.is_some() {
        plan.push(step(state.device.join("driver/unbind"), &state.pci.pci));
    }
    plan.push(step(state.device.join("driver_override"), "vfio-pci"));
    plan.push(step(
        roots.sys.join("bus/pci/drivers/vfio-pci/bind"),
        &state.pci.pci,
    ));
    plan.push(step(state.device.join("driver_override"), "\n"));
    Ok(plan)
}

fn unbind_plan(roots: &Roots, state: &State<'_>) -> Vec<SysfsWrite> {
    if state.driver.as_deref() == Some(&state.pci.kernel_driver) {
        return Vec::new();
    }
    let mut plan = Vec::new();
    if state.driver.is_some() {
        plan.push(step(
            roots.sys.join("bus/pci/drivers/vfio-pci/unbind"),
            &state.pci.pci,
        ));
    }
    plan.push(step(state.device.join("driver_override"), "\n"));
    plan.push(step(
        roots.sys.join("bus/pci/drivers_probe"),
        &state.pci.pci,
    ));
    plan
}

fn write_sysfs(write: &SysfsWrite, dry_run: bool, output: &mut impl Write) -> Result<()> {
    let prefix = if dry_run { "dry-run: " } else { "" };
    writeln!(
        output,
        "{prefix}write '{}' > {}",
        write.value,
        write.path.display()
    )
    .map_err(error)?;
    if !dry_run {
        OpenOptions::new()
            .write(true)
            .open(&write.path)
            .and_then(|mut file| file.write_all(write.value.as_bytes()))
            .map_err(|e| error(format!("{}: {e}", write.path.display())))?;
    }
    Ok(())
}

fn verify_bind(roots: &Roots, state: &State<'_>) -> Result<PathBuf> {
    let current = driver(&state.device)?;
    if current.as_deref() != Some("vfio-pci") {
        return Err(error(format!(
            "{} bind verification: driver is {}",
            state.pci.pci,
            current.as_deref().unwrap_or("none")
        )));
    }
    let group = link_basename(&state.device.join("iommu_group")).map_err(error)?;
    let normal = roots.dev.join("vfio").join(&group);
    let unsafe_group = roots.dev.join("vfio").join(format!("noiommu-{group}"));
    if normal.exists() {
        Ok(normal)
    } else if unsafe_group.exists() {
        Ok(unsafe_group)
    } else {
        Err(error(format!(
            "bind verification: neither {} nor {} exists",
            normal.display(),
            unsafe_group.display()
        )))
    }
}

fn recover(
    roots: &Roots,
    state: &State<'_>,
    failure: DiscoverError,
    output: &mut impl Write,
) -> DiscoverError {
    let clear = write_sysfs(
        &step(state.device.join("driver_override"), "\n"),
        false,
        output,
    );
    let rebound = write_sysfs(
        &step(
            roots
                .sys
                .join("bus/pci/drivers")
                .join(&state.pci.kernel_driver)
                .join("bind"),
            &state.pci.pci,
        ),
        false,
        output,
    );
    let recovery = match rebound {
        Ok(()) => "rebind ok".into(),
        Err(e) => format!("rebind: {e}"),
    };
    let clear = match clear {
        Ok(()) => String::new(),
        Err(e) => format!("; override clear: {e}"),
    };
    let current = match driver(&state.device) {
        Ok(d) => d.unwrap_or_else(|| "none".into()),
        Err(e) => format!("unreadable ({e})"),
    };
    error(format!(
        "{failure}{clear}; {recovery}; current driver {current}"
    ))
}

fn hugepages(roots: &Roots, pci: &PciDevice, output: &mut impl Write) -> Result<()> {
    if pci.numa_node < 0 {
        return Ok(());
    }
    let dir = roots.sys.join(format!(
        "devices/system/node/node{}/hugepages",
        pci.numa_node
    ));
    if let Ok(entries) = fs::read_dir(dir) {
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("hugepages-")
            {
                if let Ok(count) = read(&entry.path().join("free_hugepages")) {
                    writeln!(
                        output,
                        "node{} {} HugePages_Free: {count}",
                        pci.numa_node,
                        entry.file_name().to_string_lossy()
                    )
                    .map_err(error)?;
                }
            }
        }
    }
    Ok(())
}

pub fn bind(
    roots: &Roots,
    config: &Config,
    euid: u32,
    noiommu: bool,
    dry_run: bool,
    output: &mut impl Write,
) -> Result<()> {
    let state = state(roots, config, euid)?;
    let plan = bind_plan(roots, config, &state, noiommu)?;
    if state.driver.as_deref() == Some("vfio-pci") {
        for write in &plan {
            write_sysfs(write, dry_run, output)?;
        }
        if !dry_run {
            let node = verify_bind(roots, &state)?;
            writeln!(
                output,
                "{} already bound to vfio-pci ({})",
                state.pci.pci,
                node.display()
            )
            .map_err(error)?;
        }
        return Ok(());
    }
    let vfio = roots.sys.join("bus/pci/drivers/vfio-pci");
    if !vfio.exists() {
        if dry_run {
            writeln!(output, "dry-run: modprobe vfio-pci").map_err(error)?;
        } else {
            let result = Command::new("modprobe")
                .arg("vfio-pci")
                .output()
                .map_err(error)?;
            if !vfio.exists() {
                return Err(error(format!(
                    "vfio-pci driver missing after modprobe ({}): {}",
                    result.status,
                    String::from_utf8_lossy(&result.stderr).trim()
                )));
            }
        }
    }
    let bind_path = vfio.join("bind");
    for write in &plan {
        if let Err(e) = write_sysfs(write, dry_run, output) {
            return Err(if write.path == bind_path && !dry_run {
                recover(roots, &state, e, output)
            } else {
                e
            });
        }
    }
    if !dry_run {
        let group = verify_bind(roots, &state).map_err(|e| recover(roots, &state, e, output))?;
        writeln!(
            output,
            "{} bound to vfio-pci ({})",
            state.pci.pci,
            group.display()
        )
        .map_err(error)?;
    }
    hugepages(roots, state.pci, output)
}

pub fn unbind(
    roots: &Roots,
    config: &Config,
    euid: u32,
    addresses: impl FnOnce() -> Result<Vec<Ipv4Cidr>>,
    output: &mut impl Write,
) -> Result<()> {
    let state = state(roots, config, euid)?;
    if state.driver.as_deref() == Some(&state.pci.kernel_driver) {
        writeln!(
            output,
            "{} already on {}",
            state.pci.pci, state.pci.kernel_driver
        )
        .map_err(error)?;
        return Ok(());
    }
    for write in unbind_plan(roots, &state) {
        write_sysfs(&write, false, output)?;
    }
    if driver(&state.device)?.as_deref() != Some(&state.pci.kernel_driver)
        || !roots
            .sys
            .join("class/net")
            .join(&state.pci.kernel_interface)
            .exists()
    {
        return Err(error(format!(
            "{} unbind verification: expected {} and interface {}",
            state.pci.pci, state.pci.kernel_driver, state.pci.kernel_interface
        )));
    }
    let back = addresses()?
        .iter()
        .any(|a| a.address() == config.ipv4.address());
    writeln!(
        output,
        "{} on {}; IPv4 {} {} on {}",
        state.pci.pci,
        state.pci.kernel_driver,
        config.ipv4.address(),
        if back { "is back" } else { "is not back" },
        state.pci.kernel_interface
    )
    .map_err(error)?;
    Ok(())
}
