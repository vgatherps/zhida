use crate::{Config, ConfigError, Device};
use std::{fs, io::Write, path::Path};

pub(crate) fn merge(mut discovered: Config, previous: &Config) -> Result<Config, ConfigError> {
    if let (Device::Pci(new), Device::Pci(old)) = (&mut discovered.device, &previous.device) {
        new.devargs.clone_from(&old.devargs);
    }
    discovered.offloads.clone_from(&previous.offloads);
    discovered.rx_timestamps = previous.rx_timestamps;
    discovered.descriptors = previous.descriptors;
    discovered.eal.clone_from(&previous.eal);
    let mut paths: Vec<_> = previous
        .paths
        .iter()
        .filter(|p| p.why != "vpc" && p.why != "default")
        .cloned()
        .collect();
    paths.extend(discovered.paths.into_iter().filter(|p| {
        !previous
            .paths
            .iter()
            .any(|old| old.why != "vpc" && old.why != "default" && old.prefix == p.prefix)
    }));
    discovered.paths = paths;
    Config::from_json(&discovered.to_json())
}

pub fn load_existing(path: &Path) -> Result<Option<Config>, ConfigError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Config::load(path).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(ConfigError(format!("{}: {e}", path.display()))),
    }
}

pub fn write(
    path: &Path,
    discovered: Config,
    previous: Option<&Config>,
    changes: &mut impl Write,
) -> Result<(), ConfigError> {
    let config = match previous {
        Some(old) => merge(discovered, old)?,
        None => discovered,
    };
    let mut changed = Vec::new();
    if let Some(old) = previous {
        let old = serde_json::to_value(old).map_err(|e| ConfigError(e.to_string()))?;
        let new = serde_json::to_value(&config).map_err(|e| ConfigError(e.to_string()))?;
        for key in [
            "version",
            "device",
            "mac",
            "ipv4",
            "gateway",
            "mtu",
            "paths",
            "offloads",
            "rx_timestamps",
            "descriptors",
            "eal",
        ] {
            if old[key] != new[key] {
                changed.push(key);
            }
        }
    }
    let mut options = fs::OpenOptions::new();
    options.write(true);
    if previous.is_some() {
        options.truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options
        .open(path)
        .map_err(|e| ConfigError(format!("{}: {e}", path.display())))?;
    file.write_all(config.to_json().as_bytes())
        .map_err(|e| ConfigError(format!("{}: {e}", path.display())))?;
    for key in changed {
        writeln!(changes, "changed: {key}").map_err(|e| ConfigError(e.to_string()))?;
    }
    Ok(())
}
