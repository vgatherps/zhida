//! tungstenite on Zhida for Autobahn, on the tap_echo driver: an echo
//! server for fuzzingclient, or a client of fuzzingserver. See `usage`.

use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::process;
use std::time::Duration;

use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::smoltcp::wire::IpEndpoint;
use dpdk_smoltcp::{Stack, Turn};
use tap_echo::driver::{self, ZHIDA_IP, ECHO_PORT, EXIT_ERROR, IFACE, TESTER_IP};
use ws_autobahn::{Client, Server};

const NAME: &str = "ws-autobahn";
const BUFFER: usize = 128 * 1024;
const MAX_IDLE_SLEEP: Duration = Duration::from_millis(1);
/// Autobahn fuzzingserver's port on the tester address.
const FUZZINGSERVER_PORT: u16 = 9001;
/// Written by the tester once fuzzingserver listens; relative to the
/// working directory.
const SERVER_READY: &str = "autobahn/run/client/server-ready";
/// Written once the client's sequence completed, for peer.sh to stop
/// fuzzingserver; relative to the working directory.
const CLIENT_DONE: &str = "autobahn/run/client/client-done";
/// Counted from the driver's `start`, taken after EAL init and Port::open
/// (tap_echo driver::serve): only Stack::new precedes the wait.
/// zhida-tester.sh's 60 s LISTEN wait starts once it saw the netdev up
/// and wrote `ready`, which can be after `start`; this limit can then expire
/// first by that gap, and expiry only fails the run.
const SERVER_READY_LIMIT: Duration = Duration::from_secs(60);
const INGRESS_BUDGET: usize = 32;

fn usage() -> String {
    format!(
        "\
usage: ws-autobahn server --expect-connections N -- <tester> [args...]
       ws-autobahn client --expect-cases N -- <tester> [args...]

server: runs a tungstenite WebSocket echo server on Zhida at ws://{ZHIDA_IP}:{ECHO_PORT}
until <tester> exits: one session at a time, Text and Binary echoed, max_sockets N + 1.
Prints the accepted connection count, session endings and summed turn counters on stdout.
Fails (exit {EXIT_ERROR}) if a server error occurs or the accepted count is not N.

client: waits (at most {SERVER_READY_LIMIT:?}, turning the Stack) for the file {SERVER_READY},
then runs a tungstenite client of Autobahn's fuzzingserver at ws://{TESTER_IP}:{FUZZINGSERVER_PORT}
from Zhida until <tester> exits: getCaseCount (must report N), runCase 1..=N echoing Text
and Binary, updateReports; one connection at a time, max_sockets N + 2. Writes the file
{CLIENT_DONE} once all completed, and keeps turning the Stack until <tester> exits.
Prints the connection count, session endings and summed turn counters on stdout.
Fails (exit {EXIT_ERROR}) if a client error occurs or the sequence did not complete.

Both on netdev {IFACE}, otherwise the tap-echo driver configuration in tap-echo's usage;
RX and TX buffers of {BUFFER} bytes per socket; exit statuses otherwise as tap-echo.
"
    )
}

#[derive(Debug, Clone, Copy)]
enum Mode {
    Server,
    Client,
}

fn parse(args: &[OsString]) -> Result<(Mode, usize, Vec<OsString>), String> {
    let [mode, flag, count, separator, tester @ ..] = args else {
        return Err("expected: server|client --expect-... N -- <tester> [args...]".to_owned());
    };
    let (mode, expected_flag) = match mode.to_str() {
        Some("server") => (Mode::Server, "--expect-connections"),
        Some("client") => (Mode::Client, "--expect-cases"),
        _ => return Err(format!("unknown mode {mode:?}")),
    };
    if flag != expected_flag {
        return Err(format!("expected {expected_flag}, got {flag:?}"));
    }
    let expected = count
        .to_str()
        .and_then(|text| text.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .ok_or_else(|| format!("{expected_flag} needs a positive integer, got {count:?}"))?;
    if separator != "--" {
        return Err(format!("expected --, got {separator:?}"));
    }
    if tester.is_empty() {
        return Err("missing tester command after --".to_owned());
    }
    Ok((mode, expected, tester.to_vec()))
}

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let (mode, expected, tester) = match parse(&args) {
        Ok(parsed) => parsed,
        Err(message) => {
            driver::report(NAME, format_args!("{message}\n\n{}", usage()));
            process::exit(EXIT_ERROR);
        }
    };
    let code = match mode {
        Mode::Server => driver::run(
            NAME,
            &tester,
            expected + 1,
            BUFFER,
            None,
            |stack, start, stop| serve(stack, start, stop, expected),
        ),
        Mode::Client => driver::run(
            NAME,
            &tester,
            expected + 2,
            BUFFER,
            None,
            |stack, start, stop| client(stack, start, stop, expected),
        ),
    };
    process::exit(code);
}

/// The wall clock since `start` and the summed turn counters of a loop.
struct Pace {
    start: std::time::Instant,
    rx_received: usize,
    tx_accepted: usize,
}

impl Pace {
    fn new(start: std::time::Instant) -> Self {
        Self {
            start,
            rx_received: 0,
            tx_accepted: 0,
        }
    }

    fn now(&self) -> Instant {
        let micros = i64::try_from(self.start.elapsed().as_micros())
            .expect("elapsed wall time fits i64 microseconds");
        Instant::from_micros(micros)
    }

    fn count(&mut self, turn: Turn) {
        self.rx_received += turn.rx_received;
        self.tx_accepted += turn.tx_accepted;
    }

    /// After a step at `now` that moved nothing, with nothing pending to
    /// send and nothing staged, sleeps min(poll_at - now, 1 ms).
    fn rest(&self, now: Instant, moved: bool, turn: Turn, stack: &mut Stack) {
        if moved || turn.tx_pending > 0 || turn.rx_staged > 0 {
            return;
        }
        let sleep = match stack.poll_at() {
            None => MAX_IDLE_SLEEP,
            Some(at) if at <= now => return,
            Some(at) => Duration::from_micros((at - now).total_micros()).min(MAX_IDLE_SLEEP),
        };
        std::thread::sleep(sleep);
    }

    fn turns(&self) -> String {
        format!(
            "turns rx_received {}, tx_accepted {}",
            self.rx_received, self.tx_accepted
        )
    }
}

/// Steps the Server on the wall clock until `stop`, then requires `expected`
/// accepted connections.
fn serve(
    stack: &mut Stack,
    start: std::time::Instant,
    stop: &mut dyn FnMut() -> bool,
    expected: usize,
) -> Result<(), String> {
    let mut server =
        Server::new(stack, ECHO_PORT, BUFFER).map_err(|error| format!("Server::new: {error}"))?;
    let mut pace = Pace::new(start);
    loop {
        let now = pace.now();
        let moved = server
            .step(now)
            .map_err(|error| format!("server: {error}"))?;
        let turn = server.turn().expect("a step ran");
        pace.count(turn);
        if stop() {
            break;
        }
        pace.rest(now, moved, turn, server.stack());
    }
    let _ = writeln!(
        std::io::stdout(),
        "{NAME}: accepted {} of {expected} connections; endings {:?}; {}",
        server.accepted(),
        server.endings(),
        pace.turns(),
    );
    if server.accepted() != expected {
        return Err(format!(
            "accepted {} connections, expected {expected}",
            server.accepted()
        ));
    }
    Ok(())
}

/// Turns the Stack until `SERVER_READY` exists, then steps the Client on
/// the wall clock until `stop`, writing `CLIENT_DONE` once the sequence
/// completed, and requires it complete.
fn client(
    stack: &mut Stack,
    start: std::time::Instant,
    stop: &mut dyn FnMut() -> bool,
    cases: usize,
) -> Result<(), String> {
    let mut pace = Pace::new(start);
    loop {
        let now = pace.now();
        let turn = stack
            .turn(now, INGRESS_BUDGET)
            .map_err(|error| format!("turn: {error}"))?;
        pace.count(turn);
        if stop() {
            return Err(format!("tester exited before {SERVER_READY} existed"));
        }
        if Path::new(SERVER_READY).exists() {
            break;
        }
        if start.elapsed() >= SERVER_READY_LIMIT {
            return Err(format!("no {SERVER_READY} within {SERVER_READY_LIMIT:?}"));
        }
        pace.rest(now, false, turn, stack);
    }
    let server = IpEndpoint::new(TESTER_IP.into(), FUZZINGSERVER_PORT);
    let mut client = Client::new(stack, server, cases, BUFFER)
        .map_err(|error| format!("Client::new: {error}"))?;
    let mut done_written = false;
    loop {
        let now = pace.now();
        let moved = client
            .step(now)
            .map_err(|error| format!("client: {error}"))?;
        let turn = client.turn().expect("a step ran");
        pace.count(turn);
        if !done_written && client.done() {
            write_marker(CLIENT_DONE)?;
            done_written = true;
        }
        if stop() {
            break;
        }
        pace.rest(now, moved, turn, client.stack());
    }
    let _ = writeln!(
        std::io::stdout(),
        "{NAME}: {} of {} connections; endings {:?}; {}",
        client.handles().len(),
        cases + 2,
        client.endings(),
        pace.turns(),
    );
    if !client.done() {
        return Err(format!(
            "sequence did not complete: {} of {} connections started",
            client.handles().len(),
            cases + 2
        ));
    }
    Ok(())
}

/// Creates the empty file `path` atomically (write, then rename).
fn write_marker(path: &str) -> Result<(), String> {
    let tmp = format!("{path}.tmp");
    fs::write(&tmp, "")
        .and_then(|()| fs::rename(&tmp, path))
        .map_err(|error| format!("writing {path}: {error}"))
}
