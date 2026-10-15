use alloc::vec::Vec;
use crate::wire::{Ipv4Address, Ipv4Cidr};

/// One destination prefix and the IP MTU of the path to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathMtu {
    pub prefix: Ipv4Cidr,
    pub mtu: u16,
}

/// Static per-destination IP MTU table. Longest prefix wins; the interface subnet is an implicit
/// rule at the Port IP MTU unless an explicit rule has the same prefix; every result is clamped to
/// the Port IP MTU, and a destination no rule matches gets the Port IP MTU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathMtus {
    entries: Vec<(Ipv4Cidr, u16)>,
    ip_mtu: u16,
}

/// Smallest port or path IP MTU `PathMtus` accepts: a 48-byte TCP MSS plus 40 bytes of IPv4 and
/// TCP headers. Peers raise a smaller advertised MSS to 48 (Linux's TCP_MIN_SND_MSS, and our own
/// floor), so a smaller MTU would make them send packets the path cannot carry. The table also caps
/// UDP, which could use 68-87, but a path that small is taken to be a config mistake.
pub const MIN_IP_MTU: u16 = 88;

impl PathMtus {
    /// Build the table for an interface at `subnet` with Port IP MTU `ip_mtu`. Rejects a port or
    /// rule MTU below `MIN_IP_MTU`, a prefix with host bits set and a repeated prefix.
    pub fn new(rules: &[PathMtu], subnet: Ipv4Cidr, ip_mtu: u16) -> Result<Self, &'static str> {
        if ip_mtu < MIN_IP_MTU {
            return Err("port IP MTU must be at least 88 (48-byte minimum TCP MSS + 40 bytes of headers)");
        }
        let mut entries = Vec::new();
        for rule in rules {
            if rule.mtu < MIN_IP_MTU {
                return Err("path MTU must be at least 88 (48-byte minimum TCP MSS + 40 bytes of headers)");
            }
            if rule.prefix != rule.prefix.network() {
                return Err("path prefix has host bits set");
            }
            if entries.iter().any(|(prefix, _)| *prefix == rule.prefix) {
                return Err("duplicate path prefix");
            }
            entries.push((rule.prefix, rule.mtu.min(ip_mtu)));
        }
        let subnet = subnet.network();
        if !rules.is_empty() && !entries.iter().any(|(prefix, _)| *prefix == subnet) {
            entries.push((subnet, ip_mtu));
        }
        entries.sort_by(|(a, _), (b, _)| b.prefix_len().cmp(&a.prefix_len()));
        Ok(Self { entries, ip_mtu })
    }

    /// The path IP MTU toward `dst`.
    pub fn ip_mtu(&self, dst: Ipv4Address) -> u16 {
        self.entries.iter()
            .find(|(prefix, _)| prefix.contains_addr(&dst))
            .map_or(self.ip_mtu, |(_, mtu)| *mtu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(prefix: &str, mtu: u16) -> PathMtu {
        PathMtu { prefix: prefix.parse().unwrap(), mtu }
    }

    #[test]
    fn path_mtus_reject_host_bits_and_duplicates() {
        let subnet = "10.0.1.5/24".parse().unwrap();
        for (rules, reason) in [
            (alloc::vec![rule("10.0.1.5/24", 1500)], "path prefix has host bits set"),
            (alloc::vec![rule("0.0.0.0/0", 1500), rule("0.0.0.0/0", 1500)],
                "duplicate path prefix"),
        ] {
            assert_eq!(PathMtus::new(&rules, subnet, 9000).unwrap_err(), reason);
        }
    }

    #[test]
    fn path_mtus_reject_rule_mtu_87_accept_88() {
        let subnet = "10.0.1.5/24".parse().unwrap();
        assert_eq!(
            PathMtus::new(&[rule("0.0.0.0/0", 87)], subnet, 9000).unwrap_err(),
            "path MTU must be at least 88 (48-byte minimum TCP MSS + 40 bytes of headers)",
        );
        let paths = PathMtus::new(&[rule("0.0.0.0/0", 88)], subnet, 9000).unwrap();
        assert_eq!(paths.ip_mtu("8.8.8.8".parse().unwrap()), 88);
    }

    #[test]
    fn path_mtus_reject_port_mtu_87_accept_88() {
        let subnet = "10.0.1.5/24".parse().unwrap();
        assert_eq!(
            PathMtus::new(&[], subnet, 87).unwrap_err(),
            "port IP MTU must be at least 88 (48-byte minimum TCP MSS + 40 bytes of headers)",
        );
        let paths = PathMtus::new(&[], subnet, 88).unwrap();
        assert_eq!(paths.ip_mtu("8.8.8.8".parse().unwrap()), 88);
    }

    #[test]
    fn longest_prefix_wins_and_subnet_is_implicit() {
        let subnet = "10.0.1.5/24".parse().unwrap();
        let rules = [rule("0.0.0.0/0", 1500), rule("10.0.0.0/16", 9001),
            rule("10.0.1.7/32", 4000)];
        let shuffled = [rules[2], rules[0], rules[1]];
        let cases = [("10.0.1.7", 4000), ("10.0.1.8", 9000),
            ("10.0.2.1", 9000), ("8.8.8.8", 1500)];
        for rules in [&rules, &shuffled] {
            let paths = PathMtus::new(rules, subnet, 9000).unwrap();
            for (addr, mtu) in cases {
                assert_eq!(paths.ip_mtu(addr.parse().unwrap()), mtu);
            }
        }
        let explicit = [rules[0], rules[1], rules[2], rule("10.0.1.0/24", 1500)];
        let paths = PathMtus::new(&explicit, subnet, 9000).unwrap();
        assert_eq!(paths.ip_mtu("10.0.1.8".parse().unwrap()), 1500);
        let empty = PathMtus::new(&[], subnet, 9000).unwrap();
        assert!(empty.entries.is_empty());
        for (addr, _) in cases {
            assert_eq!(empty.ip_mtu(addr.parse().unwrap()), 9000);
        }
        let unmatched = PathMtus::new(&[rules[2]], subnet, 9000).unwrap();
        assert_eq!(unmatched.ip_mtu("8.8.8.8".parse().unwrap()), 9000);
    }
}
