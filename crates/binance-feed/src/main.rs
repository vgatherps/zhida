//! Binance bookTicker over TLS and WebSocket on Zhida's net_tap TCP socket.
//! See `usage`.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::process;
use std::sync::Arc;
use std::time::{Duration, Instant};

use binance_feed::{connect, Clock, Target, INGRESS_BUDGET, SOCKET_BUFFER};
use dpdk_smoltcp::Stack;
use rustls::ClientConfig;
use tap_echo::driver::{self, ZHIDA_IP, EXIT_ERROR, IFACE, PREFIX_LEN, TESTER_IP};

const NAME: &str = "binance-feed";
const READY: &str = "target/binance-feed/ready";
const READY_LIMIT: Duration = Duration::from_secs(60);
/// The local port is drawn from here to 65535 (IANA dynamic ports).
const FIRST_LOCAL_PORT: u16 = 49152;
const CONNECT_LIMIT: Duration = Duration::from_secs(20);
const CLOSE_LIMIT: Duration = Duration::from_secs(10);
const DEFAULT_HOST: &str = "data-stream.binance.vision";
const DEFAULT_PORT: u16 = 9443;
const DEFAULT_PATH: &str = "/ws/btcusdt@bookTicker";
const DEFAULT_PRINT: usize = 10;

fn usage() -> String {
    format!(
        "\
usage: binance-feed [--host HOST] [--port PORT] [--path PATH] [--print N] -- <tester> [args...]

Resolves HOST with the kernel resolver before DPDK starts and uses its first IPv4
address. Defaults: HOST {DEFAULT_HOST}, PORT {DEFAULT_PORT}, PATH {DEFAULT_PATH},
N {DEFAULT_PRINT}. N may be 0. Each option may appear once, in any order before --.
TCP runs on Zhida at {ZHIDA_IP}/{PREFIX_LEN}, with IPv4 gateway {TESTER_IP} on
netdev {IFACE}, connecting from a random local port in {FIRST_LOCAL_PORT}-65535. TLS uses
the Mozilla roots from webpki-roots. stream.binance.com answers HTTP 451 from restricted
locations, so the default host is data-stream.binance.vision.

The tester starts before DPDK. It must wait for {IFACE} to be up, give the kernel
side {TESTER_IP} on {IFACE}, NAT Zhida's traffic out of the container, then create
{READY}. The client prints the first N bookTicker messages and keeps reading until
the tester exits. It then prints the count and update id range, closes the
WebSocket, sends TLS close_notify and closes TCP with FIN.
Only the tester process itself is killed: run it directly or have it exec its
final command. It must exit on SIGTERM. Bound the run with timeout --kill-after=N
without --foreground so expiry signals the tester too.

Exit status: 0 tester exited 0; 1 tester failed; 2 packet buffers still in use at
port close; 3 bad arguments, setup, feed or teardown error; 101 panic. Statuses 2
and 3 take precedence over the tester's status. Diagnostics on stderr are best
effort and never change the exit status.
"
    )
}

struct Args {
    host: String,
    port: u16,
    path: String,
    print: usize,
    tester: Vec<OsString>,
}

fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Args, String> {
    let (mut host, mut port, mut path, mut print) = (None, None, None, None);
    loop {
        let arg = args.next().ok_or("missing -- <tester>")?;
        let flag = match arg.to_str() {
            Some("--") => break,
            Some(flag @ ("--host" | "--port" | "--path" | "--print")) => flag,
            _ => return Err(format!("unexpected argument {arg:?}")),
        };
        let duplicate = match flag {
            "--host" => host.is_some(),
            "--port" => port.is_some(),
            "--path" => path.is_some(),
            "--print" => print.is_some(),
            _ => unreachable!("only known options reach this match"),
        };
        if duplicate {
            return Err(format!("{flag} given twice"));
        }
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let text = value.to_str().ok_or_else(|| format!("{flag} needs UTF-8, got {value:?}"))?;
        if text == "--" {
            return Err(format!("{flag} needs a value"));
        }
        match flag {
            "--host" => host = Some(text.to_owned()),
            "--path" => path = Some(text.to_owned()),
            "--port" => {
                port = Some(text.parse::<u16>().map_err(|_| {
                    format!("{flag} needs an integer from 0 to {}, got {value:?}", u16::MAX)
                })?);
            }
            "--print" => {
                print = Some(text.parse::<usize>().map_err(|_| {
                    format!("{flag} needs an integer from 0 to {}, got {value:?}", usize::MAX)
                })?);
            }
            _ => unreachable!("only known options reach this match"),
        }
    }
    let tester: Vec<OsString> = args.collect();
    if tester.is_empty() || tester[0].is_empty() {
        return Err("missing tester command after --".to_owned());
    }
    Ok(Args {
        host: host.unwrap_or_else(|| DEFAULT_HOST.to_owned()),
        port: port.unwrap_or(DEFAULT_PORT),
        path: path.unwrap_or_else(|| DEFAULT_PATH.to_owned()),
        print: print.unwrap_or(DEFAULT_PRINT),
        tester,
    })
}

fn main() {
    let args = match parse(std::env::args_os().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            driver::report(NAME, format_args!("{message}\n\n{}", usage()));
            process::exit(EXIT_ERROR);
        }
    };
    let mut addresses = match (args.host.as_str(), args.port).to_socket_addrs() {
        Ok(addresses) => addresses,
        Err(error) => {
            driver::report(NAME, format_args!("DNS: resolving {}: {error}", args.host));
            process::exit(EXIT_ERROR);
        }
    };
    let addr = match addresses.find_map(|addr| match addr {
        SocketAddr::V4(addr) => Some(addr),
        SocketAddr::V6(_) => None,
    }) {
        Some(addr) => addr,
        None => {
            driver::report(NAME, format_args!("DNS: {} has no IPv4 address", args.host));
            process::exit(EXIT_ERROR);
        }
    };
    let _ = writeln!(
        io::stdout(),
        "{NAME}: {} resolved to {} by the kernel resolver",
        args.host,
        addr.ip(),
    );
    let tls = binance_feed::webpki_client_config();
    let local_port = match random_local_port() {
        Ok(port) => port,
        Err(error) => {
            driver::report(NAME, format_args!("reading /dev/urandom: {error}"));
            process::exit(EXIT_ERROR);
        }
    };
    match fs::remove_file(READY) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            driver::report(NAME, format_args!("removing stale {READY}: {error}"));
            process::exit(EXIT_ERROR);
        }
    }
    let parent = Path::new(READY).parent().expect("READY has a parent directory");
    if let Err(error) = fs::create_dir_all(parent) {
        driver::report(NAME, format_args!("creating {}: {error}", parent.display()));
        process::exit(EXIT_ERROR);
    }
    let target = Target {
        addr,
        host: args.host,
        path: args.path,
    };
    let code = driver::run(
        NAME,
        &args.tester,
        1,
        SOCKET_BUFFER,
        Some(TESTER_IP),
        |stack, start, stop| feed(stack, start, stop, &target, tls, local_port, args.print),
    );
    process::exit(code);
}

/// A port from FIRST_LOCAL_PORT to 65535, from OS entropy. The Stack's initial
/// sequence numbers repeat every run (fixed random seed), so a fixed port would
/// repeat the previous run's SYN exactly; Docker Desktop's network answered such
/// a repeat with segments of the earlier connection.
fn random_local_port() -> io::Result<u16> {
    let mut bytes = [0; 2];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let span = u16::MAX - FIRST_LOCAL_PORT + 1;
    Ok(FIRST_LOCAL_PORT + u16::from_ne_bytes(bytes) % span)
}

fn feed(
    stack: &mut Stack,
    start: Instant,
    stop: &mut dyn FnMut() -> bool,
    target: &Target,
    tls: Arc<ClientConfig>,
    local_port: u16,
    print: usize,
) -> Result<(), String> {
    let clock = Clock::new(start);
    loop {
        stack
            .turn(clock.now(), INGRESS_BUDGET)
            .map_err(|error| format!("turn: {error}"))?;
        if stop() {
            return Err(format!("tester exited before {READY} existed"));
        }
        if Path::new(READY).exists() {
            break;
        }
        if start.elapsed() >= READY_LIMIT {
            return Err(format!("no {READY} within {READY_LIMIT:?}"));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut feed = connect(
        stack, &clock, target, binance_feed::socket(None), tls, local_port, CONNECT_LIMIT,
    )
    .map_err(|error| error.to_string())?;
    let _ = writeln!(
        io::stdout(),
        "{NAME}: connected to {} ({}) from {ZHIDA_IP}:{local_port} over Zhida, \
         {}, WebSocket open",
        target.url(),
        target.addr,
        feed.tls_summary(),
    );
    let mut count = 0usize;
    let mut first = None;
    let mut last = None;
    while let Some(ticker) = feed.next(&clock, stop).map_err(|error| error.to_string())? {
        count = count.checked_add(1).expect("bookTicker count fits usize");
        if first.is_none() {
            first = Some(ticker.update_id);
        }
        last = Some(ticker.update_id);
        if count <= print {
            let _ = writeln!(io::stdout(), "#{count} {ticker}");
        }
    }
    let secs = start.elapsed().as_secs_f64();
    if let (Some(first), Some(last)) = (first, last) {
        let _ = writeln!(
            io::stdout(),
            "{NAME}: {count} bookTicker messages in {secs:.1} s since start, \
             update ids {first}..{last}",
        );
    } else {
        let _ = writeln!(io::stdout(), "{NAME}: 0 bookTicker messages in {secs:.1} s since start");
    }
    let state = feed.close(&clock, CLOSE_LIMIT).map_err(|error| error.to_string())?;
    let _ = writeln!(
        io::stdout(),
        "{NAME}: closed (WebSocket close handshake, TLS close_notify, TCP {state})",
    );
    if count == 0 {
        return Err("no bookTicker message received".to_owned());
    }
    Ok(())
}
