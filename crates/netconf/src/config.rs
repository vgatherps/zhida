use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use smoltcp::iface::{PathMtu, PathMtus, MIN_IP_MTU};
use smoltcp::wire::{EthernetAddress, IpAddress, Ipv4Address, Ipv4Cidr};
use std::{fmt, fs, path::Path, str::FromStr};

/// Error for a port or path MTU below `MIN_IP_MTU`.
const MTU_TOO_SMALL: &str = "must be at least 88 (48-byte minimum TCP MSS + 40 bytes of headers)";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "JsonConfig", into = "JsonConfig")]
pub struct Config {
    pub device: Device,
    pub mac: Option<EthernetAddress>,
    pub ipv4: Ipv4Cidr,
    pub gateway: Option<Ipv4Address>,
    pub mtu: u16,
    pub paths: Vec<PathRule>,
    pub offloads: Offloads,
    pub rx_timestamps: bool,
    pub descriptors: u16,
    pub eal: EalConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Device {
    Pci(PciDevice),
    Vdev { vdev: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PciDevice {
    pub pci: String,
    pub pci_id: String,
    pub devargs: String,
    pub kernel_driver: String,
    pub kernel_interface: String,
    pub numa_node: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRule {
    #[serde(
        serialize_with = "serialize_string",
        deserialize_with = "deserialize_prefix"
    )]
    pub prefix: Ipv4Cidr,
    pub mtu: u16,
    pub why: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "Value", into = "JsonOffloads")]
pub enum Offloads {
    Auto,
    Explicit {
        rx_checksum: bool,
        tx_tcp_checksum: bool,
        tx_udp_checksum: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EalConfig {
    pub file_prefix: String,
    pub extra: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub(crate) String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn error(field: &str, message: &str) -> ConfigError {
    ConfigError(format!("{field}: {message}"))
}

#[derive(Serialize)]
#[serde(untagged, deny_unknown_fields)]
enum JsonOffloads {
    Auto(String),
    Explicit(ExplicitOffloads),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplicitOffloads {
    rx_checksum: bool,
    tx_tcp_checksum: bool,
    tx_udp_checksum: bool,
}

impl TryFrom<Value> for Offloads {
    type Error = ConfigError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::String(value) = value {
            return if value == "auto" {
                Ok(Self::Auto)
            } else {
                Err(error("offloads", "offloads string must be auto"))
            };
        }
        let o: ExplicitOffloads =
            serde_json::from_value(value).map_err(|e| ConfigError(e.to_string()))?;
        Ok(Self::Explicit {
            rx_checksum: o.rx_checksum,
            tx_tcp_checksum: o.tx_tcp_checksum,
            tx_udp_checksum: o.tx_udp_checksum,
        })
    }
}

impl From<Offloads> for JsonOffloads {
    fn from(offloads: Offloads) -> Self {
        match offloads {
            Offloads::Auto => Self::Auto("auto".into()),
            Offloads::Explicit {
                rx_checksum,
                tx_tcp_checksum,
                tx_udp_checksum,
            } => Self::Explicit(ExplicitOffloads {
                rx_checksum,
                tx_tcp_checksum,
                tx_udp_checksum,
            }),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonConfig {
    version: u32,
    device: Device,
    #[serde(deserialize_with = "required_option")]
    mac: Option<String>,
    ipv4: String,
    #[serde(deserialize_with = "required_option")]
    gateway: Option<String>,
    mtu: u16,
    paths: Vec<PathRule>,
    offloads: Offloads,
    rx_timestamps: bool,
    descriptors: u16,
    eal: EalConfig,
}

fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

fn serialize_string<S: Serializer, T: fmt::Display>(value: &T, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(value)
}

fn deserialize_prefix<'de, D: Deserializer<'de>>(d: D) -> Result<Ipv4Cidr, D::Error> {
    String::deserialize(d)?
        .parse()
        .map_err(|_| D::Error::custom("prefix: invalid IPv4 CIDR"))
}

fn parse<T: FromStr>(value: &str, field: &str, name: &str) -> Result<T, ConfigError> {
    value
        .parse()
        .map_err(|_| error(field, &format!("invalid {name}")))
}

impl TryFrom<JsonConfig> for Config {
    type Error = ConfigError;

    fn try_from(json: JsonConfig) -> Result<Self, Self::Error> {
        if json.version != 1 {
            return Err(error("version", "must be 1"));
        }
        let config = Self {
            device: json.device,
            mac: json
                .mac
                .as_deref()
                .map(|v| parse(v, "mac", "MAC address"))
                .transpose()?,
            ipv4: parse(&json.ipv4, "ipv4", "IPv4 CIDR")?,
            gateway: json
                .gateway
                .as_deref()
                .map(|v| parse(v, "gateway", "IPv4 address"))
                .transpose()?,
            mtu: json.mtu,
            paths: json.paths,
            offloads: json.offloads,
            rx_timestamps: json.rx_timestamps,
            descriptors: json.descriptors,
            eal: json.eal,
        };
        validate(&config)?;
        Ok(config)
    }
}

impl From<Config> for JsonConfig {
    fn from(config: Config) -> Self {
        Self {
            version: 1,
            device: config.device,
            mac: config.mac.map(mac_string),
            ipv4: config.ipv4.to_string(),
            gateway: config.gateway.map(|g| g.to_string()),
            mtu: config.mtu,
            paths: config.paths,
            offloads: config.offloads,
            rx_timestamps: config.rx_timestamps,
            descriptors: config.descriptors,
            eal: config.eal,
        }
    }
}

fn matches_hex(value: &str, pattern: &str) -> bool {
    value.len() == pattern.len()
        && value
            .bytes()
            .zip(pattern.bytes())
            .all(|(byte, expected)| match expected {
                b'h' => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
                b'f' => (b'0'..=b'7').contains(&byte),
                _ => byte == expected,
            })
}

fn validate(config: &Config) -> Result<(), ConfigError> {
    match &config.device {
        Device::Pci(pci) => {
            if !matches_hex(&pci.pci, "hhhh:hh:hh.f") {
                return Err(error("device.pci", "invalid PCI BDF"));
            }
            if !matches_hex(&pci.pci_id, "hhhh:hhhh") {
                return Err(error("device.pci_id", "invalid PCI ID"));
            }
            for (field, value) in [
                ("device.kernel_driver", &pci.kernel_driver),
                ("device.kernel_interface", &pci.kernel_interface),
            ] {
                if value.is_empty() {
                    return Err(error(field, "must not be empty"));
                }
            }
            if config.mac.is_none() {
                return Err(error("mac", "PCI device requires a MAC address"));
            }
        }
        Device::Vdev { vdev } if vdev.is_empty() => {
            return Err(error("device.vdev", "must not be empty"))
        }
        Device::Vdev { .. } => {}
    }
    if config.mac.is_some_and(|mac| !mac.is_unicast()) {
        return Err(error("mac", "Ethernet address must be unicast"));
    }
    if !IpAddress::Ipv4(config.ipv4.address()).is_unicast() {
        return Err(error("ipv4", "IPv4 address must be unicast"));
    }
    if let Some(gateway) = config.gateway {
        if !IpAddress::Ipv4(gateway).is_unicast() {
            return Err(error("gateway", "gateway must be unicast"));
        }
        if !config.ipv4.contains_addr(&gateway) {
            return Err(error("gateway", "gateway must be inside the IPv4 subnet"));
        }
        if gateway == config.ipv4.address() {
            return Err(error("gateway", "gateway must not be our IPv4 address"));
        }
        if let Some(broadcast) = config.ipv4.broadcast() {
            if gateway == config.ipv4.network().address() {
                return Err(error(
                    "gateway",
                    "gateway must not be the subnet's network address",
                ));
            }
            if gateway == broadcast {
                return Err(error(
                    "gateway",
                    "gateway must not be the subnet's broadcast address",
                ));
            }
        }
    }
    if config.mtu < MIN_IP_MTU {
        return Err(error("mtu", MTU_TOO_SMALL));
    }
    for (index, rule) in config.paths.iter().enumerate() {
        let field = format!("paths[{index}]");
        if rule.prefix != rule.prefix.network() {
            return Err(error(
                &format!("{field}.prefix"),
                "prefix must not have host bits set",
            ));
        }
        if let Some(earlier) = config.paths[..index]
            .iter()
            .position(|p| p.prefix == rule.prefix)
        {
            return Err(error(
                &format!("{field}.prefix"),
                &format!("duplicate of paths[{earlier}]"),
            ));
        }
        if rule.mtu < MIN_IP_MTU {
            return Err(error(&format!("{field}.mtu"), MTU_TOO_SMALL));
        }
        if rule.why.is_empty() {
            return Err(error(&format!("{field}.why"), "must not be empty"));
        }
    }
    if config.descriptors == 0 {
        return Err(error("descriptors", "must be > 0"));
    }
    if config.eal.file_prefix.is_empty() {
        return Err(error("eal.file_prefix", "must not be empty"));
    }
    Ok(())
}

/// Colon-separated lowercase hex, as sysfs prints it (smoltcp's Display uses dashes).
fn mac_string(mac: EthernetAddress) -> String {
    let b = mac.0;
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    )
}

impl Config {
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(json).map_err(|e| ConfigError(e.to_string()))
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let json = fs::read_to_string(path)
            .map_err(|e| error(&path.display().to_string(), &e.to_string()))?;
        Self::from_json(&json)
    }

    pub fn to_json(&self) -> String {
        format!(
            "{}\n",
            serde_json::to_string_pretty(self).expect("config contains JSON-compatible values")
        )
    }

    /// Query before opening the Stack to size a capped socket with `path_mtu - 40`.
    /// This is the same destination lookup the Stack applies to TCP connects.
    pub fn path_mtu(&self, addr: Ipv4Address) -> u16 {
        let rules: Vec<PathMtu> = self.paths.iter()
            .map(|rule| PathMtu { prefix: rule.prefix, mtu: rule.mtu })
            .collect();
        PathMtus::new(&rules, self.ipv4, self.mtu)
            .expect("validated config has a valid path table")
            .ip_mtu(addr)
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.device {
            Device::Pci(p) => writeln!(
                f,
                "device: pci {} ({}, {} {}, numa {})",
                p.pci, p.pci_id, p.kernel_driver, p.kernel_interface, p.numa_node
            )?,
            Device::Vdev { vdev } => writeln!(f, "device: vdev {vdev}")?,
        }
        writeln!(
            f,
            "mac: {}",
            self.mac.map_or_else(|| "device".into(), mac_string)
        )?;
        writeln!(f, "ipv4: {}", self.ipv4)?;
        writeln!(
            f,
            "gateway: {}",
            self.gateway
                .map_or_else(|| "null".into(), |g| g.to_string())
        )?;
        writeln!(f, "mtu: {}", self.mtu)?;
        writeln!(f, "paths:")?;
        for p in &self.paths {
            writeln!(f, "  {} mtu {} ({})", p.prefix, p.mtu, p.why)?;
        }
        writeln!(
            f,
            "offloads: {}",
            serde_json::to_string(&self.offloads).expect("offloads contain JSON-compatible values")
        )?;
        writeln!(f, "rx_timestamps: {}", self.rx_timestamps)?;
        writeln!(f, "descriptors: {}", self.descriptors)?;
        writeln!(
            f,
            "eal: {}",
            serde_json::to_string(&self.eal).expect("EAL contains JSON-compatible values")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const EXPECTED: &str = "{\n  \"version\": 1,\n  \"device\": {\n    \"pci\": \"0000:00:06.0\",\n    \"pci_id\": \"1d0f:ec20\",\n    \"devargs\": \"\",\n    \"kernel_driver\": \"ena\",\n    \"kernel_interface\": \"eth1\",\n    \"numa_node\": 0\n  },\n  \"mac\": \"0a:12:34:56:78:9a\",\n  \"ipv4\": \"10.0.1.23/24\",\n  \"gateway\": \"10.0.1.1\",\n  \"mtu\": 9001,\n  \"paths\": [\n    {\n      \"prefix\": \"10.0.0.0/16\",\n      \"mtu\": 9001,\n      \"why\": \"vpc\"\n    },\n    {\n      \"prefix\": \"0.0.0.0/0\",\n      \"mtu\": 1500,\n      \"why\": \"default\"\n    }\n  ],\n  \"offloads\": \"auto\",\n  \"rx_timestamps\": false,\n  \"descriptors\": 1024,\n  \"eal\": {\n    \"file_prefix\": \"zhida\",\n    \"extra\": []\n  }\n}\n";

    fn example() -> Value {
        serde_json::from_str(EXPECTED).unwrap()
    }

    fn reject(value: &Value, message: &str) -> ConfigError {
        let error = Config::from_json(&value.to_string()).unwrap_err();
        assert!(error.0.contains(message), "{error}");
        if !message.contains(":") {
            assert!(
                error.0.contains("line ") && error.0.contains("column "),
                "{error}"
            );
        } else {
            assert!(error.0.starts_with(message), "{error}");
        }
        error
    }

    #[test]
    fn config_path_mtu_matches_stack_lookup() {
        let mut value = example();
        value["paths"] = json!([
            {"prefix": "10.0.0.0/16", "mtu": 9001, "why": "vpc"},
            {"prefix": "0.0.0.0/0", "mtu": 1500, "why": "internet"},
            {"prefix": "10.0.1.99/32", "mtu": 1500, "why": "jumbo-less host"},
        ]);
        let config = Config::from_json(&value.to_string()).unwrap();
        let rules: Vec<PathMtu> = config.paths.iter()
            .map(|rule| PathMtu { prefix: rule.prefix, mtu: rule.mtu })
            .collect();
        let paths = PathMtus::new(&rules, config.ipv4, config.mtu).unwrap();
        for (addr, expected) in [("10.0.1.5", 9001), ("10.0.1.99", 1500),
            ("10.0.7.7", 9001), ("1.1.1.1", 1500)]
        {
            let addr = addr.parse().unwrap();
            assert_eq!(config.path_mtu(addr), expected);
            assert_eq!(config.path_mtu(addr), paths.ip_mtu(addr));
        }
    }

    #[test]
    fn config_round_trips_pci_and_vdev() {
        let pci = Config::from_json(EXPECTED).unwrap();
        assert_eq!(pci.to_json(), EXPECTED);
        assert_eq!(Config::from_json(&pci.to_json()).unwrap(), pci);
        let mut value = example();
        value["device"] = json!({"vdev": "net_tap0,iface=cdnic0"});
        value["mac"] = Value::Null;
        value["gateway"] = Value::Null;
        value["eal"]["extra"] = json!(["--no-huge", "-m", "128", "--no-shconf"]);
        value["offloads"] =
            json!({"rx_checksum": true, "tx_tcp_checksum": false, "tx_udp_checksum": true});
        let vdev = Config::from_json(&value.to_string()).unwrap();
        assert_eq!(Config::from_json(&vdev.to_json()).unwrap(), vdev);
        assert!(vdev.to_string().contains("mac: device\n"));
        assert!(vdev.to_string().contains(
            "offloads: {\"rx_checksum\":true,\"tx_tcp_checksum\":false,\"tx_udp_checksum\":true}\n"
        ));
    }

    #[test]
    fn config_rejects_unknown_field_and_version() {
        for (pointer, path) in [
            ("", "unknown field `foo`"),
            ("/device", "did not match any variant"),
            ("/paths/0", "unknown field `foo`"),
            ("/offloads", "unknown field `foo`"),
            ("/eal", "unknown field `foo`"),
        ] {
            let mut value = example();
            value["offloads"] =
                json!({"rx_checksum": true, "tx_tcp_checksum": false, "tx_udp_checksum": true});
            value
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("foo".into(), json!(true));
            reject(&value, path);
        }
        let mut value = example();
        value["version"] = json!(2);
        reject(&value, "version:");
        let mut value = example();
        value.as_object_mut().unwrap().remove("rx_timestamps");
        reject(&value, "missing field `rx_timestamps`");
        for key in ["mac", "gateway"] {
            let mut value = example();
            value.as_object_mut().unwrap().remove(key);
            reject(&value, &format!("missing field `{key}`"));
        }
        let error = Config::from_json("{\n").unwrap_err();
        assert!(error.0.contains("line 2 column 0"));
        for (pointer, replacement, path) in [
            ("/rx_timestamps", json!(0), "expected a boolean"),
            ("/mtu", json!(65536), "expected u16"),
            (
                "/device/numa_node",
                json!(2147483648_i64),
                "did not match any variant",
            ),
            ("/eal/extra", json!([false]), "expected a string"),
            ("/eal/file_prefix", json!(""), "eal.file_prefix:"),
            ("/paths/0/why", json!(""), "paths[0].why:"),
        ] {
            let mut value = example();
            *value.pointer_mut(pointer).unwrap() = replacement;
            reject(&value, path);
        }
    }

    #[test]
    fn config_rejects_gateway_outside_subnet() {
        for (gateway, message) in [
            ("10.0.2.1", "gateway must be inside the IPv4 subnet"),
            ("10.0.1.23", "gateway must not be our IPv4 address"),
            (
                "10.0.1.0",
                "gateway must not be the subnet's network address",
            ),
            (
                "10.0.1.255",
                "gateway must not be the subnet's broadcast address",
            ),
            ("224.0.0.1", "gateway must be unicast"),
        ] {
            let mut value = example();
            value["gateway"] = json!(gateway);
            assert!(reject(&value, "gateway:").0.contains(message));
        }
        let mut value = example();
        value["ipv4"] = json!("10.0.0.0/31");
        value["gateway"] = json!("10.0.0.1");
        Config::from_json(&value.to_string()).unwrap();
        value["ipv4"] = json!("10.0.0.1/31");
        value["gateway"] = json!("10.0.0.0");
        Config::from_json(&value.to_string()).unwrap();
        value["ipv4"] = json!("10.0.0.0/32");
        value["gateway"] = json!("10.0.0.0");
        assert_eq!(
            reject(&value, "gateway:").0,
            "gateway: gateway must not be our IPv4 address"
        );
        value["gateway"] = json!("10.0.0.1");
        reject(&value, "gateway:");
        value["gateway"] = Value::Null;
        Config::from_json(&value.to_string()).unwrap();
    }

    #[test]
    fn config_rejects_bad_mac_pci_id_path_and_offloads() {
        let mut value = example();
        value["mtu"] = json!(87);
        assert!(serde_json::from_value::<Config>(value).is_err());
        for (pointer, replacement, path) in [
            ("/mac", json!("bad"), "mac:"),
            ("/mac", json!("01:12:34:56:78:9a"), "mac:"),
            ("/mac", Value::Null, "mac:"),
            ("/device/pci", json!("0000:00:06.8"), "device.pci:"),
            ("/device/pci_id", json!("1D0F:ec20"), "device.pci_id:"),
            ("/device/pci_id", json!("1d0:ec20"), "device.pci_id:"),
            ("/paths/0/prefix", json!("10.0.1.0/16"), "paths[0].prefix:"),
            ("/paths/0/mtu", json!(87), "paths[0].mtu:"),
            ("/offloads", json!("on"), "offloads:"),
            (
                "/offloads",
                json!({"rx_checksum": true, "tx_tcp_checksum": false}),
                "missing field `tx_udp_checksum`",
            ),
            (
                "/offloads",
                json!({"rx_checksum": 1, "tx_tcp_checksum": false, "tx_udp_checksum": false}),
                "expected a boolean",
            ),
            ("/mtu", json!(87), "mtu:"),
            ("/descriptors", json!(0), "descriptors:"),
            ("/ipv4", json!("224.0.0.1/24"), "ipv4:"),
            ("/device", json!({"vdev": ""}), "device.vdev:"),
            ("/device/kernel_driver", json!(""), "device.kernel_driver:"),
            (
                "/device/kernel_interface",
                json!(""),
                "device.kernel_interface:",
            ),
        ] {
            let mut value = example();
            *value.pointer_mut(pointer).unwrap() = replacement;
            reject(&value, path);
        }
        let mut value = example();
        value["paths"][1]["prefix"] = value["paths"][0]["prefix"].clone();
        assert!(reject(&value, "paths[1].prefix:").0.contains("paths[0]"));
    }

    #[test]
    fn config_rejects_port_and_path_mtu_87_accepts_88() {
        for pointer in ["/mtu", "/paths/0/mtu"] {
            let mut value = example();
            *value.pointer_mut(pointer).unwrap() = json!(87);
            let field = &pointer[1..].replace("/0/", "[0].");
            reject(&value, &format!("{field}: {MTU_TOO_SMALL}"));
            *value.pointer_mut(pointer).unwrap() = json!(88);
            Config::from_json(&value.to_string()).unwrap();
        }
    }
}
