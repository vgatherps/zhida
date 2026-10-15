use zhida_netconf::{
    devbind,
    discover::{discover, discover_aws, ipv4_addresses, Roots},
    imds::Imds,
    rediscover, Config,
};
use std::{env, ffi::OsString, path::Path, process::ExitCode};

const USAGE: &str = "usage: zhida-netconf check FILE | zhida-netconf discover --interface IF [--ipv4 ADDR] [--aws] [-o FILE] | zhida-netconf bind FILE [--noiommu] [--dry-run] | zhida-netconf unbind FILE";

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

fn failure(error: impl std::fmt::Display) -> ExitCode {
    eprintln!(
        "zhida-netconf: {}",
        error.to_string().replace(['\n', '\r'], " ")
    );
    ExitCode::from(1)
}

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    match args.next().as_deref().and_then(|s| s.to_str()) {
        Some("check") => {
            let Some(file) = args.next() else {
                return usage();
            };
            if args.next().is_some() {
                return usage();
            }
            let path = Path::new(&file);
            match Config::load(path) {
                Ok(config) => {
                    print!("{config}");
                    ExitCode::SUCCESS
                }
                Err(error) => failure(format!("{}: {error}", path.display())),
            }
        }
        Some(command @ ("bind" | "unbind")) => {
            let Some(file) = args
                .next()
                .filter(|f| !f.to_string_lossy().starts_with('-'))
            else {
                return usage();
            };
            let mut noiommu = false;
            let mut dry_run = false;
            for flag in args {
                match flag.to_str() {
                    Some("--noiommu") if command == "bind" && !noiommu => noiommu = true,
                    Some("--dry-run") if command == "bind" && !dry_run => dry_run = true,
                    _ => return usage(),
                }
            }
            // geteuid has no pointer arguments or preconditions.
            let euid = unsafe { libc::geteuid() };
            if euid != 0 {
                return failure("bind/unbind needs euid 0");
            }
            let config = match Config::load(Path::new(&file)) {
                Ok(c) => c,
                Err(e) => return failure(e),
            };
            let roots = Roots::host();
            let mut output = std::io::stdout().lock();
            let result = if command == "bind" {
                devbind::bind(&roots, &config, euid, noiommu, dry_run, &mut output)
            } else {
                devbind::unbind(
                    &roots,
                    &config,
                    euid,
                    || {
                        let zhida_netconf::Device::Pci(pci) = &config.device else {
                            unreachable!("state rejects vdev before address lookup")
                        };
                        ipv4_addresses(&pci.kernel_interface)
                    },
                    &mut output,
                )
            };
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => failure(e),
            }
        }
        Some("discover") => {
            let mut interface = None;
            let mut ipv4 = None;
            let mut output: Option<OsString> = None;
            let mut aws = false;
            while let Some(flag) = args.next() {
                if flag == "--aws" {
                    if aws {
                        return usage();
                    }
                    aws = true;
                    continue;
                }
                let Some(value) = args.next() else {
                    return usage();
                };
                if value.to_str().is_some_and(|s| s.starts_with('-')) {
                    return usage();
                }
                match flag.to_str() {
                    Some("--interface") if interface.is_none() => {
                        let Some(value) = value.to_str().filter(|s| !s.is_empty()) else {
                            return usage();
                        };
                        interface = Some(value.to_owned());
                    }
                    Some("--ipv4") if ipv4.is_none() => {
                        let Some(value) = value.to_str().and_then(|s| s.parse().ok()) else {
                            return usage();
                        };
                        ipv4 = Some(value);
                    }
                    Some("-o") if output.is_none() => output = Some(value),
                    _ => return usage(),
                }
            }
            let Some(interface) = interface else {
                return usage();
            };
            let previous = match output
                .as_ref()
                .map(|p| rediscover::load_existing(Path::new(p)))
                .transpose()
            {
                Ok(value) => value.flatten(),
                Err(e) => return failure(e),
            };
            let discovered = ipv4_addresses(&interface).and_then(|addresses| {
                if aws {
                    discover_aws(
                        &Roots::host(),
                        &interface,
                        &addresses,
                        ipv4,
                        &Imds::new(std::net::SocketAddr::from(([169, 254, 169, 254], 80))),
                    )
                } else {
                    discover(&Roots::host(), &interface, &addresses, ipv4)
                }
            });
            let discovered = match discovered {
                Ok(value) => value,
                Err(e) => return failure(e),
            };
            if let Some(path) = output {
                let path = Path::new(&path);
                if let Err(e) = rediscover::write(
                    path,
                    discovered.config,
                    previous.as_ref(),
                    &mut std::io::stderr().lock(),
                ) {
                    return failure(e);
                }
                eprintln!("wrote {}", path.display());
            } else {
                print!("{}", discovered.config.to_json());
            }
            for warning in discovered.warnings {
                eprintln!(
                    "zhida-netconf: warning: {}",
                    warning.replace(['\n', '\r'], " ")
                );
            }
            if discovered.operstate != "up" {
                eprintln!(
                    "zhida-netconf: warning: {} operstate is {}",
                    interface,
                    discovered.operstate.replace(['\n', '\r'], " ")
                );
            }
            ExitCode::SUCCESS
        }
        _ => usage(),
    }
}
