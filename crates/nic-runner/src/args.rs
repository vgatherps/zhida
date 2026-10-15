use std::collections::HashSet;
use std::ffi::OsString;
use std::path::PathBuf;

pub const USAGE: &str = "usage: zhida-nic --config FILE <MODE> [MODE OPTIONS]
OPTIONS (each at most once, before MODE):
  --config FILE        required Zhida network and EAL config
MODES:
  info
  sockperf-server [--udp-ports P[,P..]] [--tcp-port P] [--tcp-connections N]
                  [--seconds S] [--report-seconds R]
    Defaults: UDP 11111, no TCP, 8 TCP connections, S=0 (until SIGINT/SIGTERM), R=5.
    Socket buffers support messages through 65507 bytes. UDP above MTU - 28
    (1472 at MTU 1500) requires IP fragment reassembly; Zhida does not do it.
  feed [--host H] [--port P] [--path P] [--print N] [--seconds S]
    Defaults: data-stream.binance.vision, 9443, /ws/btcusdt@bookTicker, N=10, S=30.
Exit codes: 0 success; 2 buffers in use at close; 3 args/setup/run error; 101 panic.";

pub struct Args {
    pub config: PathBuf,
    pub mode: Mode,
}

pub enum Mode {
    Info,
    Server(Server),
    Feed(Feed),
}

pub struct Server {
    pub udp_ports: Vec<u16>,
    pub tcp_port: Option<u16>,
    pub tcp_connections: usize,
    pub seconds: u64,
    pub report_seconds: u64,
}

pub struct Feed {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub print: usize,
    pub seconds: u64,
}

fn number<T: std::str::FromStr>(flag: &str, value: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("invalid {flag}: {value:?}"))
}

fn port(flag: &str, value: &str) -> Result<u16, String> {
    let value = number(flag, value)?;
    if value == 0 {
        return Err(format!("{flag} must be positive"));
    }
    Ok(value)
}

pub fn parse(args: impl Iterator<Item = OsString>) -> Result<Args, String> {
    let mut args = args.map(|a| {
        a.into_string()
            .map_err(|a| format!("non-UTF-8 argument: {a:?}"))
    });
    let mut seen = HashSet::new();
    let mut config = None;
    let mode_name;
    loop {
        let flag = args.next().ok_or("missing MODE")??;
        if matches!(flag.as_str(), "info" | "sockperf-server" | "feed") {
            mode_name = flag;
            break;
        }
        if flag != "--config" {
            return Err(format!("unexpected option: {flag}"));
        }
        if !seen.insert(flag.clone()) {
            return Err(format!("{flag} given twice"));
        }
        let value = args
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))??;
        config = Some(PathBuf::from(value));
    }
    let config = config.ok_or("--config is required")?;
    let mut server = Server {
        udp_ports: vec![11111],
        tcp_port: None,
        tcp_connections: 8,
        seconds: 0,
        report_seconds: 5,
    };
    let mut feed = Feed {
        host: "data-stream.binance.vision".into(),
        port: 9443,
        path: "/ws/btcusdt@bookTicker".into(),
        print: 10,
        seconds: 30,
    };
    while let Some(flag) = args.next() {
        let flag = flag?;
        let allowed = match mode_name.as_str() {
            "sockperf-server" => matches!(
                flag.as_str(),
                "--udp-ports"
                    | "--tcp-port"
                    | "--tcp-connections"
                    | "--seconds"
                    | "--report-seconds"
            ),
            "feed" => matches!(
                flag.as_str(),
                "--host" | "--port" | "--path" | "--print" | "--seconds"
            ),
            _ => false,
        };
        if !allowed {
            return Err(format!("unexpected {mode_name} option: {flag}"));
        }
        if !seen.insert(flag.clone()) {
            return Err(format!("{flag} given twice"));
        }
        let value = args
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))??;
        if mode_name == "sockperf-server" {
            match flag.as_str() {
                "--udp-ports" => {
                    server.udp_ports = value
                        .split(',')
                        .map(|p| port(&flag, p))
                        .collect::<Result<_, _>>()?;
                    let unique: HashSet<_> = server.udp_ports.iter().collect();
                    if unique.len() != server.udp_ports.len() {
                        return Err("duplicate UDP port".into());
                    }
                }
                "--tcp-port" => server.tcp_port = Some(port(&flag, &value)?),
                "--tcp-connections" => {
                    server.tcp_connections = number(&flag, &value)?;
                    if server.tcp_connections == 0 {
                        return Err("--tcp-connections must be positive".into());
                    }
                }
                "--seconds" => server.seconds = number(&flag, &value)?,
                "--report-seconds" => {
                    server.report_seconds = number(&flag, &value)?;
                    if server.report_seconds == 0 {
                        return Err("--report-seconds must be positive".into());
                    }
                }
                _ => unreachable!(),
            }
        } else {
            match flag.as_str() {
                "--host" => feed.host = value,
                "--port" => feed.port = port(&flag, &value)?,
                "--path" => feed.path = value,
                "--print" => feed.print = number(&flag, &value)?,
                "--seconds" => feed.seconds = number(&flag, &value)?,
                _ => unreachable!(),
            }
        }
    }
    let mode = match mode_name.as_str() {
        "info" => Mode::Info,
        "sockperf-server" => Mode::Server(server),
        "feed" => Mode::Feed(feed),
        _ => unreachable!(),
    };
    Ok(Args { config, mode })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_is_required() {
        let error = parse(["info"].into_iter().map(OsString::from))
            .err()
            .unwrap();
        assert_eq!(error, "--config is required");
    }

    #[test]
    fn info_takes_config() {
        let parsed = parse(
            ["--config", "nic.json", "info"]
                .into_iter()
                .map(OsString::from),
        )
        .unwrap();
        assert_eq!(parsed.config, PathBuf::from("nic.json"));
        assert!(matches!(parsed.mode, Mode::Info));
    }

    #[test]
    fn server_defaults_to_no_tcp_port() {
        let args = ["--config", "nic.json", "sockperf-server"];
        let parsed = parse(args.into_iter().map(OsString::from)).unwrap();
        let Mode::Server(server) = parsed.mode else {
            panic!("expected sockperf-server mode");
        };
        assert_eq!(server.tcp_port, None);
    }

    #[test]
    fn workload_options_keep_their_syntax() {
        let args = [
            "--config",
            "nic.json",
            "sockperf-server",
            "--udp-ports",
            "11111,11112",
            "--tcp-port",
            "11113",
            "--tcp-connections",
            "4",
            "--seconds",
            "2",
            "--report-seconds",
            "1",
        ];
        let parsed = parse(args.into_iter().map(OsString::from)).unwrap();
        let Mode::Server(server) = parsed.mode else {
            panic!("expected sockperf-server mode");
        };
        assert_eq!(server.udp_ports, [11111, 11112]);
        assert_eq!(server.tcp_port, Some(11113));
        assert_eq!(server.tcp_connections, 4);
        assert_eq!(server.seconds, 2);
        assert_eq!(server.report_seconds, 1);
    }
}
