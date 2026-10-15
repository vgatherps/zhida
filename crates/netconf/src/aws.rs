use crate::{
    discover::{choose_address, DiscoverError, Kernel},
    imds::Imds,
};
use smoltcp::wire::{Ipv4Address, Ipv4Cidr};

pub(crate) struct Aws {
    pub(crate) ipv4: Ipv4Cidr,
    pub(crate) gateway: Ipv4Address,
    pub(crate) vpc_blocks: Vec<Ipv4Cidr>,
    pub(crate) warnings: Vec<String>,
}

pub(crate) fn derive(
    imds: &Imds,
    kernel: &Kernel,
    select: Option<Ipv4Address>,
) -> Result<Aws, DiscoverError> {
    let token = imds.token().map_err(|e| DiscoverError(e.to_string()))?;
    let mac = kernel
        .mac
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    let get = |item: &str| {
        imds.get(&token, &format!("network/interfaces/macs/{mac}/{item}"))
            .map_err(|e| DiscoverError(e.to_string()))
    };
    let required = |item: &str| {
        get(item)?.ok_or_else(|| DiscoverError(format!("IMDS item {item} is missing (404)")))
    };
    let interface = &kernel.device.kernel_interface;
    let device = required("device-number")?
        .trim()
        .parse::<u32>()
        .map_err(|_| DiscoverError("IMDS device-number is invalid".into()))?;
    if device == 0 {
        return Err(DiscoverError(format!(
            "{interface} is the primary ENI (device-number 0); it carries IMDS and SSH"
        )));
    }
    let local = required("local-ipv4s")?;
    let addresses: Vec<Ipv4Address> = items(&local)
        .map(|s| {
            s.parse().map_err(|_| {
                DiscoverError(format!("IMDS local-ipv4s has invalid IPv4 address {s}"))
            })
        })
        .collect::<Result<_, _>>()?;
    let subnet = required("subnet-ipv4-cidr-block")?;
    let subnet = parse_block(subnet.trim(), "subnet-ipv4-cidr-block")?;
    let ipv4 = if kernel.addresses.is_empty() {
        Ipv4Cidr::new(
            *addresses
                .first()
                .ok_or_else(|| DiscoverError("IMDS local-ipv4s is empty".into()))?,
            subnet.prefix_len(),
        )
    } else {
        let chosen = choose_address(interface, &kernel.addresses, select)?;
        if !addresses.contains(&chosen.address()) {
            return Err(DiscoverError(format!(
                "{} is not in IMDS local-ipv4s ({})",
                chosen.address(),
                addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        if chosen.prefix_len() != subnet.prefix_len() {
            return Err(DiscoverError(format!(
                "kernel IPv4 {chosen} prefix differs from IMDS subnet-ipv4-cidr-block {subnet}"
            )));
        }
        chosen
    };
    let base = u32::from_be_bytes(subnet.address().octets());
    let gateway = Ipv4Address::from(
        base.checked_add(1)
            .ok_or_else(|| DiscoverError(format!("IMDS subnet {subnet} gateway overflows IPv4")))?
            .to_be_bytes(),
    );
    if let Some(route) = kernel.gateway {
        if route != gateway {
            return Err(DiscoverError(format!("{interface} kernel default gateway {route} differs from IMDS subnet gateway {gateway}")));
        }
    }
    let blocks = required("vpc-ipv4-cidr-blocks")?;
    let vpc_blocks = items(&blocks)
        .map(|s| parse_block(s, "vpc-ipv4-cidr-blocks"))
        .collect::<Result<_, _>>()?;
    let public = get("public-ipv4s")?;
    let warnings = if public.as_deref().is_none_or(|s| items(s).next().is_none()) {
        vec![format!("{interface} has no public IPv4 (IMDS public-ipv4s); internet destinations need an Elastic IP on this ENI or a NAT gateway route")]
    } else {
        Vec::new()
    };
    Ok(Aws {
        ipv4,
        gateway,
        vpc_blocks,
        warnings,
    })
}
fn items(s: &str) -> impl Iterator<Item = &str> {
    s.lines().map(str::trim).filter(|s| !s.is_empty())
}
fn parse_block(s: &str, item: &str) -> Result<Ipv4Cidr, DiscoverError> {
    let cidr: Ipv4Cidr = s
        .parse()
        .map_err(|_| DiscoverError(format!("IMDS {item} has invalid CIDR {s}")))?;
    if cidr != cidr.network() {
        return Err(DiscoverError(format!("IMDS {item} {s} has host bits set")));
    }
    Ok(cidr)
}
