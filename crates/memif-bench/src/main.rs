//! The v1 memif benchmark as two processes, each with its own EAL on its own
//! CPU: `peer` (memif server; echo or sink) and the measuring `client` (memif
//! client); `run`, which launches both and orders their shutdown; and
//! `matrix`, which runs every v1 configuration through `run`.
//!
//! Protocol on stdout/stdin: the peer prints `ready` once its memif server
//! listens; each side prints `report <json>` once done and polls no more;
//! each then closes its Port only after reading the line `close`. `run` sends
//! `close` to the client, waits for its exit, and only then to the peer, which
//! closes behind the disconnect barrier (`MemifVdev::close_after_peer`).
//! For UDP, `run` sends `sent` to the peer after the client report. The peer
//! receives until both sender completion and 50 ms without a datagram.

use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::process::{self, Child, ChildStdin, Command, Stdio};
use std::str::FromStr;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dpdk_smoltcp::{os_random_seed, Eal, Port, StackError};
use memif_bench::matrix::{self, Outcome, CONFIGS};
use memif_bench::memif::{Memif, MemifVdev, Role};
use memif_bench::workload::{port_config, Client, Peer, PeerMode, Shape};

const USAGE: &str = "usage:
  memif-bench peer --mode echo|sink|udp-sink --conns K --cpu C --socket NAME [--run-timeout-s S]
    udp-sink also takes --size N --warmup N
  memif-bench client SHAPE --cpu C --socket NAME [--run-timeout-s S]
  memif-bench run SHAPE --peer-cpu P --client-cpu C --control-cpu X [--socket NAME] [--run-timeout-s S]
  memif-bench matrix [--reps R] [--dry-run] --peer-cpu P --client-cpu C --control-cpu X [--run-timeout-s S]
SHAPE: --shape pingpong --conns K --message M --rounds N --warmup W
     | --shape bulk --bytes B --warmup W
     | --shape udp --size N --count N --warmup N
UDP is CLI only. The sink waits for sender completion and 50 ms without a datagram.
UDP loss is measured sent minus delivered; lost datagrams are never retried.
S: 1..=3600 seconds, default 120. run, matrix: P, C and X must be in its allowed CPUs.
matrix: R (default 3) passes over the v1 configurations, forward then reverse
alternately, each through `run`; writes both reports of every run to a new
target/memif-bench/matrix-<unix seconds>-<pid>.jsonl, stops at the first run not
valid, else prints min/median/max per configuration. --dry-run prints the run order only.
Exit status 0 iff the report is valid and the Port closed (run: both children
exited 0; matrix: every run did).";

/// memif `rsize`: 1024 descriptors, the driver's default.
const RING: u8 = 10;
const RUN_TIMEOUT_S: u64 = 120;
const CONNECT: Duration = Duration::from_secs(5);
const LINK: Duration = Duration::from_secs(10);
const CLOSE: Duration = Duration::from_secs(5);
/// Launcher bounds: a child's start to `ready`; reports beyond the start, link
/// and run bounds; a child's exit after `close`.
const READY: Duration = Duration::from_secs(30);
const REPORT_MARGIN: Duration = Duration::from_secs(10);
const EXIT: Duration = Duration::from_secs(10);

#[derive(Debug, PartialEq)]
enum Cmd {
    Peer {
        mode: PeerMode,
        conns: usize,
        cpu: usize,
        socket: String,
        run_timeout_s: u64,
    },
    Client {
        shape: Shape,
        cpu: usize,
        socket: String,
        run_timeout_s: u64,
    },
    Run {
        shape: Shape,
        peer_cpu: usize,
        client_cpu: usize,
        control_cpu: usize,
        socket: String,
        run_timeout_s: u64,
    },
    Matrix {
        reps: usize,
        dry_run: bool,
        peer_cpu: usize,
        client_cpu: usize,
        control_cpu: usize,
        run_timeout_s: u64,
    },
}

/// Flags that take no value.
const SWITCHES: [&str; 1] = ["dry-run"];

/// `--name value` pairs, each name at most once (a switch's value is
/// "true"). Each subcommand takes the names it uses; any left over does not
/// apply to it.
struct Flags(Vec<(String, String)>);

impl Flags {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut pairs: Vec<(String, String)> = Vec::new();
        while let Some(arg) = args.next() {
            let name = arg
                .strip_prefix("--")
                .ok_or_else(|| format!("unexpected argument {arg:?}"))?;
            if pairs.iter().any(|(seen, _)| seen == name) {
                return Err(format!("--{name} given twice"));
            }
            let value = if SWITCHES.contains(&name) {
                "true".to_owned()
            } else {
                args.next()
                    .ok_or_else(|| format!("--{name} needs a value"))?
            };
            pairs.push((name.to_owned(), value));
        }
        Ok(Self(pairs))
    }

    fn get<T: FromStr>(&mut self, name: &str) -> Result<Option<T>, String> {
        let Some(at) = self.0.iter().position(|(seen, _)| seen == name) else {
            return Ok(None);
        };
        let (_, value) = self.0.remove(at);
        value
            .parse()
            .map(Some)
            .map_err(|_| format!("--{name}: cannot parse {value:?}"))
    }

    fn need<T: FromStr>(&mut self, name: &str) -> Result<T, String> {
        self.get(name)?.ok_or_else(|| format!("missing --{name}"))
    }

    fn done(self) -> Result<(), String> {
        match self.0.first() {
            Some((name, _)) => Err(format!("--{name} does not apply here")),
            None => Ok(()),
        }
    }
}

fn shape(flags: &mut Flags) -> Result<Shape, String> {
    let shape = match flags.need::<String>("shape")?.as_str() {
        "pingpong" => Shape::PingPong {
            conns: flags.need("conns")?,
            message: flags.need("message")?,
            rounds: flags.need("rounds")?,
            warmup: flags.need("warmup")?,
        },
        "bulk" => Shape::Bulk {
            bytes: flags.need("bytes")?,
            warmup: flags.need("warmup")?,
        },
        "udp" => Shape::UdpStream {
            size: flags.need("size")?,
            count: flags.need("count")?,
            warmup: flags.need("warmup")?,
        },
        other => return Err(format!("--shape must be pingpong or bulk, got {other:?}")),
    };
    shape.validate()?;
    Ok(shape)
}

fn parse(args: Vec<String>) -> Result<Cmd, String> {
    let mut args = args.into_iter();
    let sub = args.next().ok_or("missing subcommand")?;
    let mut flags = Flags::parse(args)?;
    let run_timeout_s = Some(flags.get("run-timeout-s")?.unwrap_or(RUN_TIMEOUT_S))
        .filter(|s| (1..=3600).contains(s))
        .ok_or("--run-timeout-s must be 1..=3600")?;
    let cmd = match sub.as_str() {
        "peer" => Cmd::Peer {
            mode: match flags.need::<String>("mode")?.as_str() {
                "echo" => PeerMode::Echo,
                "sink" => PeerMode::Sink,
                "udp-sink" => {
                    let size = flags.need("size")?;
                    let warmup = flags.need("warmup")?;
                    Shape::UdpStream {
                        size,
                        count: 0,
                        warmup,
                    }
                    .validate()?;
                    PeerMode::UdpSink { size, warmup }
                }
                other => return Err(format!("--mode must be echo or sink, got {other:?}")),
            },
            conns: Some(flags.need("conns")?)
                .filter(|&n| n >= 1)
                .ok_or("--conns must be at least 1")?,
            cpu: flags.need("cpu")?,
            socket: flags.need("socket")?,
            run_timeout_s,
        },
        "client" => Cmd::Client {
            shape: shape(&mut flags)?,
            cpu: flags.need("cpu")?,
            socket: flags.need("socket")?,
            run_timeout_s,
        },
        "run" => Cmd::Run {
            shape: shape(&mut flags)?,
            peer_cpu: flags.need("peer-cpu")?,
            client_cpu: flags.need("client-cpu")?,
            control_cpu: flags.need("control-cpu")?,
            socket: flags
                .get("socket")?
                .unwrap_or_else(|| format!("memif-bench-{}", process::id())),
            run_timeout_s,
        },
        "matrix" => Cmd::Matrix {
            reps: Some(flags.get("reps")?.unwrap_or(3))
                .filter(|&n| n >= 1)
                .ok_or("--reps must be at least 1")?,
            dry_run: flags.get("dry-run")?.unwrap_or(false),
            peer_cpu: flags.need("peer-cpu")?,
            client_cpu: flags.need("client-cpu")?,
            control_cpu: flags.need("control-cpu")?,
            run_timeout_s,
        },
        other => return Err(format!("unknown subcommand {other:?}")),
    };
    flags.done()?;
    if matches!(cmd, Cmd::Peer { mode: PeerMode::UdpSink { .. }, conns, .. } if conns != 1) {
        return Err("udp-sink needs --conns 1".to_owned());
    }
    Ok(cmd)
}

fn main() {
    let command = parse(std::env::args().skip(1).collect());
    let random_seed = match os_random_seed() {
        Ok(seed) => seed,
        Err(error) => {
            eprintln!("memif-bench: OS random seed: {error}");
            process::exit(1);
        }
    };
    if matches!(command, Ok(Cmd::Peer { .. } | Cmd::Client { .. })) {
        // An unwinding panic would drop the Port, closing it outside the
        // ordered close; abort instead. Also covers println! on a closed stdout.
        let report = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            report(info);
            process::abort();
        }));
    }
    let result = match command {
        Err(message) => Err(format!("{message}\n{USAGE}")),
        Ok(Cmd::Peer {
            mode,
            conns,
            cpu,
            socket,
            run_timeout_s,
        }) => peer(
            mode,
            conns,
            cpu,
            &socket,
            Duration::from_secs(run_timeout_s),
            random_seed,
        ),
        Ok(Cmd::Client {
            shape,
            cpu,
            socket,
            run_timeout_s,
        }) => client(
            shape,
            cpu,
            &socket,
            Duration::from_secs(run_timeout_s),
            random_seed,
        ),
        Ok(Cmd::Run {
            shape,
            peer_cpu,
            client_cpu,
            control_cpu,
            socket,
            run_timeout_s,
        }) => run(
            shape,
            peer_cpu,
            client_cpu,
            control_cpu,
            &socket,
            run_timeout_s,
        ),
        Ok(Cmd::Matrix {
            reps,
            dry_run,
            peer_cpu,
            client_cpu,
            control_cpu,
            run_timeout_s,
        }) => run_matrix(
            reps,
            dry_run,
            [
                ("peer-cpu", peer_cpu),
                ("client-cpu", client_cpu),
                ("control-cpu", control_cpu),
            ],
            run_timeout_s,
        ),
    };
    if let Err(message) = result {
        eprintln!("memif-bench: {message}");
        process::exit(1);
    }
}

fn eal(role: &str, cpu: usize, socket: &str) -> Result<Eal, String> {
    let name = format!("memif-bench-{role}");
    let lcores = format!("--lcores=7@{cpu}");
    let prefix = format!("--file-prefix=memif-{role}-{socket}");
    let args = [
        name.as_str(),
        "--no-pci",
        "--no-huge",
        "--no-shconf",
        "--no-telemetry",
        lcores.as_str(),
        "--main-lcore=7",
        prefix.as_str(),
    ];
    Eal::init(&args).map_err(|error| format!("{role} EAL init: {error}"))
}

fn open(eal: &Eal, role: Role, socket: &str, conns: usize) -> Result<(MemifVdev, Port), String> {
    let name = match role {
        Role::Server => "peer",
        Role::Client => "client",
    };
    let vdev = CString::new(format!("net_memif_{name}")).expect("no NUL");
    let memif = Memif {
        vdev: &vdev,
        role,
        id: 0,
        socket,
        log2_ring_size: RING,
    };
    // SAFETY: `eal` is the caller's first local, so it outlives the Port. The
    // Port goes back to the vdev's `close` (client, first, while the peer
    // waits for `close`) or `close_after_peer` (peer, after the client exited),
    // only after `wait_link_up` returned Ok, and neither side bursts after its
    // report; every other path leaks it.
    unsafe {
        MemifVdev::open(eal, &memif, |id| {
            port_config(id, conns, c"memif_rx", c"memif_tx")
        })
    }
    .map_err(|error| format!("{name} memif open: {error}"))
}

/// Poll until done; on Err the caller leaks the side (and its Port).
fn drive(mut poll: impl FnMut(Instant) -> Result<bool, StackError>) -> Result<(), StackError> {
    while !poll(Instant::now())? {}
    Ok(())
}

fn wait_for_close() -> Result<(), String> {
    for line in io::stdin().lock().lines() {
        if line.map_err(|error| format!("stdin: {error}"))? == "close" {
            return Ok(());
        }
    }
    Err("stdin ended before `close`".to_owned())
}

fn valid(failure: Option<String>) -> Result<(), String> {
    failure.map_or(Ok(()), |reason| Err(format!("report invalid: {reason}")))
}

fn peer(
    mode: PeerMode,
    conns: usize,
    cpu: usize,
    socket: &str,
    run_timeout: Duration,
    random_seed: u64,
) -> Result<(), String> {
    let eal = eal("peer", cpu, socket)?;
    let (vdev, port) = open(&eal, Role::Server, socket, conns)?;
    println!("ready");
    if let Err(error) = vdev.wait_link_up(LINK) {
        std::mem::forget(port);
        return Err(format!("peer link up: {error}"));
    }
    let mut peer = Peer::new(port, mode, conns, run_timeout, random_seed, Instant::now()).map_err(
        |(port, error)| {
            std::mem::forget(port);
            format!("Peer::new: {error}")
        },
    )?;
    let result = if matches!(mode, PeerMode::UdpSink { .. }) {
        drive_udp_sink(&mut peer)
    } else {
        drive(|now| peer.poll(now)).map_err(|error| format!("peer poll: {error}"))
    };
    if let Err(error) = result {
        std::mem::forget(peer);
        return Err(error);
    }
    let report = peer.report();
    println!("report {}", report.to_json());
    let port = peer.into_port();
    if let Err(error) = wait_for_close() {
        std::mem::forget(port);
        return Err(error);
    }
    match vdev.close_after_peer(port, CLOSE) {
        Ok(closed) => closed.map_err(|error| format!("peer close: {error}"))?,
        Err((_, port, error)) => {
            std::mem::forget(port);
            return Err(format!("peer close barrier: {error}"));
        }
    }
    valid(report.failure)
}

fn drive_udp_sink(peer: &mut Peer) -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = io::stdin()
            .read_line(&mut line)
            .map_err(|error| format!("stdin: {error}"))
            .and_then(|_| {
                if line.trim_end() == "sent" {
                    Ok(())
                } else {
                    Err("expected `sent` from the parent".to_owned())
                }
            });
        let _ = tx.send(result);
    });
    let mut sent_at = None;
    loop {
        let now = Instant::now();
        let idle = peer
            .poll(now)
            .map_err(|error| format!("peer poll: {error}"))?;
        if idle && peer.report().failure.is_some() {
            return Ok(());
        }
        if sent_at.is_none() {
            match rx.try_recv() {
                Ok(result) => {
                    result?;
                    sent_at = Some(now);
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err("stdin reader stopped".to_owned())
                }
            }
        }
        if idle && sent_at.is_some_and(|sent| now.duration_since(sent) >= Duration::from_millis(50))
        {
            return Ok(());
        }
    }
}

fn client(
    shape: Shape,
    cpu: usize,
    socket: &str,
    run_timeout: Duration,
    random_seed: u64,
) -> Result<(), String> {
    let eal = eal("client", cpu, socket)?;
    let (vdev, port) = open(&eal, Role::Client, socket, shape.conns())?;
    if let Err(error) = vdev.wait_link_up(LINK) {
        std::mem::forget(port);
        return Err(format!("client link up: {error}"));
    }
    let mut client = Client::new(
        port,
        shape,
        CONNECT,
        run_timeout,
        random_seed,
        Instant::now(),
    )
    .map_err(|(port, error)| {
        std::mem::forget(port);
        format!("Client::new: {error}")
    })?;
    if let Err(error) = drive(|now| client.poll(now)) {
        std::mem::forget(client);
        return Err(format!("client poll: {error}"));
    }
    let report = client.report();
    println!("report {}", report.to_json());
    let port = client.into_port();
    if let Err(error) = wait_for_close() {
        std::mem::forget(port);
        return Err(error);
    }
    vdev.close(port)
        .map_err(|error| format!("client close: {error}"))?;
    valid(report.failure)
}

fn flag_args(pairs: Vec<(&str, String)>) -> Vec<String> {
    pairs
        .into_iter()
        .flat_map(|(name, value)| [format!("--{name}"), value])
        .collect()
}

fn shape_flags(shape: Shape) -> Vec<(&'static str, String)> {
    match shape {
        Shape::PingPong {
            conns,
            message,
            rounds,
            warmup,
        } => vec![
            ("shape", "pingpong".to_owned()),
            ("conns", conns.to_string()),
            ("message", message.to_string()),
            ("rounds", rounds.to_string()),
            ("warmup", warmup.to_string()),
        ],
        Shape::Bulk { bytes, warmup } => {
            vec![
                ("shape", "bulk".to_owned()),
                ("bytes", bytes.to_string()),
                ("warmup", warmup.to_string()),
            ]
        }
        Shape::UdpStream {
            size,
            count,
            warmup,
        } => vec![
            ("shape", "udp".to_owned()),
            ("size", size.to_string()),
            ("count", count.to_string()),
            ("warmup", warmup.to_string()),
        ],
    }
}

/// A spawned child, killed and reaped on drop unless already reaped.
struct Guard {
    role: &'static str,
    child: Child,
    reaped: bool,
}

impl Guard {
    fn kill(&mut self) {
        if !self.reaped {
            if let Err(error) = self.child.kill() {
                eprintln!("memif-bench: killing {}: {error}", self.role);
            }
        }
    }

    fn reap(&mut self) {
        if !self.reaped {
            if let Err(error) = self.child.wait() {
                eprintln!("memif-bench: reaping {}: {error}", self.role);
            }
            self.reaped = true;
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.kill();
        self.reap();
    }
}

/// A child `memif-bench` under `taskset`, its stdout read line by line on a
/// thread so every wait is bounded.
struct Proc {
    guard: Guard,
    stdin: ChildStdin,
    lines: Receiver<String>,
}

impl Proc {
    fn spawn(role: &'static str, cpus: String, args: Vec<String>) -> Result<Self, String> {
        let exe = std::env::current_exe().map_err(|error| format!("current_exe: {error}"))?;
        let child = Command::new("taskset")
            .arg("-c")
            .arg(cpus)
            .arg(exe)
            .arg(role)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|error| format!("spawn {role}: {error}"))?;
        let mut guard = Guard {
            role,
            child,
            reaped: false,
        };
        eprintln!("memif-bench: spawned {role} pid {}", guard.child.id());
        let stdin = guard.child.stdin.take().expect("piped");
        let stdout = guard.child.stdout.take().expect("piped");
        let (send, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            guard,
            stdin,
            lines,
        })
    }

    /// The next stdout line must be `word`, optionally followed by a space and
    /// the returned rest.
    fn expect(&self, word: &str, deadline: Instant) -> Result<String, String> {
        let role = self.guard.role;
        let line = match self
            .lines
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            Ok(line) => line,
            Err(RecvTimeoutError::Timeout) => {
                return Err(format!("timed out waiting for {role} `{word}`"))
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(format!("{role} exited before `{word}`"))
            }
        };
        match line.split_once(' ').unwrap_or((line.as_str(), "")) {
            (head, rest) if head == word => Ok(rest.to_owned()),
            _ => Err(format!("{role}: expected `{word}`, got {line:?}")),
        }
    }

    /// Send `close` and wait for the exit; Err only on a failed write or the
    /// deadline. A nonzero exit is returned as Ok(false).
    fn close(&mut self, deadline: Instant) -> Result<bool, String> {
        let role = self.guard.role;
        writeln!(self.stdin, "close")
            .map_err(|error| format!("sending close to {role}: {error}"))?;
        loop {
            if let Some(status) = self
                .guard
                .child
                .try_wait()
                .map_err(|error| format!("waiting for {role}: {error}"))?
            {
                self.guard.reaped = true;
                if !status.success() {
                    eprintln!("memif-bench: {role} exited with {status}");
                }
                return Ok(status.success());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for {role} to exit after `close`"
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// The children of one run. Dropping it, on any failure or unwind, kills
/// every child not yet reaped (client first, then peer) and only then reaps
/// them, so neither outlives the launcher.
struct Children {
    peer: Proc,
    client: Option<Proc>,
}

impl Drop for Children {
    fn drop(&mut self) {
        if let Some(client) = &mut self.client {
            client.guard.kill();
        }
        self.peer.guard.kill();
        if let Some(client) = &mut self.client {
            client.guard.reap();
        }
        self.peer.guard.reap();
    }
}

/// Every `cpus` entry is in this process's affinity mask.
fn check_allowed(cpus: [(&str, usize); 3]) -> Result<(), String> {
    // SAFETY: cpu_set_t is plain data; all-zero bytes are the empty set.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is writable and its size is passed; pid 0 is this thread.
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&set), &mut set) } != 0 {
        return Err(format!("sched_getaffinity: {}", io::Error::last_os_error()));
    }
    for (flag, cpu) in cpus {
        // SAFETY: `cpu` is below CPU_SETSIZE, the set's bit count.
        if cpu >= libc::CPU_SETSIZE as usize || !unsafe { libc::CPU_ISSET(cpu, &set) } {
            return Err(format!("--{flag} {cpu} is not in this process's allowed CPUs"));
        }
    }
    Ok(())
}

fn run(
    shape: Shape,
    peer_cpu: usize,
    client_cpu: usize,
    control_cpu: usize,
    socket: &str,
    run_timeout_s: u64,
) -> Result<(), String> {
    check_allowed([
        ("peer-cpu", peer_cpu),
        ("client-cpu", client_cpu),
        ("control-cpu", control_cpu),
    ])?;
    let (mode, conns) = match shape {
        Shape::PingPong { conns, .. } => ("echo", conns),
        Shape::Bulk { .. } => ("sink", 1),
        Shape::UdpStream { .. } => ("udp-sink", 1),
    };
    let common = |cpu: usize| {
        [
            ("cpu", cpu.to_string()),
            ("socket", socket.to_owned()),
            ("run-timeout-s", run_timeout_s.to_string()),
        ]
    };
    let mut peer_flags = vec![("mode", mode.to_owned()), ("conns", conns.to_string())];
    if let Shape::UdpStream { size, warmup, .. } = shape {
        peer_flags.extend([("size", size.to_string()), ("warmup", warmup.to_string())]);
    }
    peer_flags.extend(common(peer_cpu));
    let mut client_flags = shape_flags(shape);
    client_flags.extend(common(client_cpu));
    let peer = Proc::spawn(
        "peer",
        format!("{control_cpu},{peer_cpu}"),
        flag_args(peer_flags),
    )?;
    let mut children = Children { peer, client: None };
    children.peer.expect("ready", Instant::now() + READY)?;
    let client = children.client.insert(Proc::spawn(
        "client",
        format!("{control_cpu},{client_cpu}"),
        flag_args(client_flags),
    )?);
    let reports_by =
        Instant::now() + READY + LINK + Duration::from_secs(run_timeout_s) + REPORT_MARGIN;
    let client_report = client.expect("report", reports_by)?;
    if matches!(shape, Shape::UdpStream { .. }) {
        writeln!(children.peer.stdin, "sent")
            .map_err(|error| format!("sending sent to peer: {error}"))?;
    }
    let mut peer_report = children.peer.expect("report", reports_by)?;
    if matches!(shape, Shape::UdpStream { .. }) {
        peer_report = udp_loss_report(&client_report, &peer_report)?;
    }
    let client_ok = client.close(Instant::now() + EXIT)?;
    let peer_ok = children.peer.close(Instant::now() + EXIT)?;
    println!("{{\"role\":\"client\",\"report\":{client_report}}}");
    println!("{{\"role\":\"peer\",\"report\":{peer_report}}}");
    if client_ok && peer_ok {
        Ok(())
    } else {
        Err("a child exited nonzero".to_owned())
    }
}

fn udp_loss_report(client: &str, peer: &str) -> Result<String, String> {
    let sent = report_count(client, "sent")?;
    let delivered = report_count(peer, "delivered")?;
    let lost = sent
        .checked_sub(delivered)
        .expect("UDP delivered count exceeds sent");
    let end = peer
        .strip_suffix('}')
        .ok_or("peer report is not a JSON object")?;
    Ok(format!("{end},\"lost\":{lost}}}"))
}

fn report_count(report: &str, key: &str) -> Result<u64, String> {
    let pattern = format!("\"{key}\":");
    let rest = report
        .split_once(&pattern)
        .ok_or_else(|| format!("report missing {key}"))?
        .1;
    rest[..rest.find([',', '}']).unwrap_or(rest.len())]
        .parse()
        .map_err(|error| format!("report {key}: {error}"))
}

/// Every configuration of `matrix::plan(reps)` through `memif-bench run`,
/// one at a time; see `USAGE`.
fn run_matrix(
    reps: usize,
    dry_run: bool,
    cpus: [(&str, usize); 3],
    run_timeout_s: u64,
) -> Result<(), String> {
    let plan = matrix::plan(reps);
    let run_args = |config: usize| {
        let mut flags = shape_flags(CONFIGS[config].1);
        flags.extend(cpus.map(|(name, cpu)| (name, cpu.to_string())));
        flags.push(("run-timeout-s", run_timeout_s.to_string()));
        flag_args(flags)
    };
    if dry_run {
        for (rep, config) in plan {
            println!("rep {rep} {} {}", CONFIGS[config].0, run_args(config).join(" "));
        }
        return Ok(());
    }
    check_allowed(cpus)?;
    let exe = std::env::current_exe().map_err(|error| format!("current_exe: {error}"))?;
    fs::create_dir_all("target/memif-bench")
        .map_err(|error| format!("creating target/memif-bench: {error}"))?;
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("clock: {error}"))?;
    let path = format!(
        "target/memif-bench/matrix-{}-{}.jsonl",
        started.as_secs(),
        process::id()
    );
    let mut results = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("creating {path}: {error}"))?;
    let runs = matrix::execute(
        &plan,
        |rep, config| {
            eprintln!("memif-bench: matrix rep {rep} {}", CONFIGS[config].0);
            let output = Command::new(&exe)
                .arg("run")
                .args(run_args(config))
                .stdin(Stdio::null())
                .stderr(Stdio::inherit())
                .output()
                .map_err(|error| format!("spawn run: {error}"))?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(Outcome::from_run(&stdout, output.status.success()))
        },
        |rep, config, outcome| {
            writeln!(results, "{}", outcome.json(CONFIGS[config].0, rep))
                .map_err(|error| format!("writing {path}: {error}"))
        },
    )
    .map_err(|error| format!("{error}; results so far: {path}"))?;
    println!("results: {path}");
    for (config, runs) in runs.iter().enumerate() {
        print!("{}", matrix::table(CONFIGS[config].0, runs));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    fn rejected(line: &str) -> String {
        parse(args(line)).expect_err(line)
    }

    #[test]
    fn udp_flags_round_trip_and_require_the_sink_mode() {
        let udp = Shape::UdpStream {
            size: 1472,
            count: 1000,
            warmup: 20,
        };
        let mut line = vec!["client".to_owned()];
        line.extend(flag_args(shape_flags(udp)));
        line.extend(args("--cpu 3 --socket s"));
        assert_eq!(
            parse(line),
            Ok(Cmd::Client {
                shape: udp,
                cpu: 3,
                socket: "s".to_owned(),
                run_timeout_s: RUN_TIMEOUT_S,
            })
        );
        assert_eq!(
            parse(args(
                "peer --mode udp-sink --size 1472 --warmup 20 --conns 1 --cpu 4 --socket s"
            )),
            Ok(Cmd::Peer {
                mode: PeerMode::UdpSink {
                    size: 1472,
                    warmup: 20
                },
                conns: 1,
                cpu: 4,
                socket: "s".to_owned(),
                run_timeout_s: RUN_TIMEOUT_S,
            })
        );
        assert_eq!(
            rejected("run --shape udp --size 64 --count 1000 --warmup 20 --mode echo --peer-cpu 1 --client-cpu 2 --control-cpu 0"),
            "--mode does not apply here"
        );
        assert_eq!(
            rejected("peer --mode udp-sink --size 64 --warmup 20 --conns 2 --cpu 4 --socket s"),
            "udp-sink needs --conns 1"
        );
    }

    #[test]
    fn udp_parent_reports_measured_loss_from_both_reports() {
        for (delivered, lost) in [(1000, 0), (997, 3), (0, 1000)] {
            let client = "{\"sent\":1000,\"warmup\":20}";
            let peer = format!("{{\"delivered\":{delivered},\"warmup_delivered\":20}}");
            let report = udp_loss_report(client, &peer).unwrap();
            assert_eq!(report_count(&report, "lost"), Ok(lost));
            assert_eq!(report_count(&report, "delivered"), Ok(delivered));
            assert_eq!(report_count(&report, "warmup_delivered"), Ok(20));
        }
        assert!(udp_loss_report("{}", "{\"delivered\":0}").is_err());
        assert!(udp_loss_report("{\"sent\":1000}", "{}").is_err());
    }

    #[test]
    fn shape_flags_round_trip_through_client_parse() {
        for shape in [
            Shape::PingPong {
                conns: 4,
                message: 64,
                rounds: 10,
                warmup: 1,
            },
            Shape::Bulk {
                bytes: 1 << 20,
                warmup: 4096,
            },
        ] {
            let mut line = vec!["client".to_owned()];
            line.extend(flag_args(shape_flags(shape)));
            line.extend(args("--cpu 3 --socket s"));
            let cmd = Cmd::Client {
                shape,
                cpu: 3,
                socket: "s".to_owned(),
                run_timeout_s: RUN_TIMEOUT_S,
            };
            assert_eq!(parse(line), Ok(cmd));
        }
    }

    #[test]
    fn flags_that_do_not_apply_are_rejected() {
        let pingpong = "--shape pingpong --conns 1 --message 64 --rounds 5 --warmup 1";
        assert_eq!(
            rejected("client --shape bulk --bytes 9 --warmup 0 --conns 2 --cpu 0 --socket s"),
            "--conns does not apply here"
        );
        assert_eq!(
            rejected(&format!("client {pingpong} --bytes 9 --cpu 0 --socket s")),
            "--bytes does not apply here"
        );
        assert_eq!(
            rejected(&format!(
                "client {pingpong} --peer-cpu 1 --cpu 0 --socket s"
            )),
            "--peer-cpu does not apply here"
        );
        assert_eq!(
            rejected(&format!(
                "run {pingpong} --cpu 0 --peer-cpu 0 --client-cpu 0 --control-cpu 0"
            )),
            "--cpu does not apply here"
        );
        assert_eq!(
            rejected("peer --mode echo --conns 1 --cpu 0 --socket s --rounds 3"),
            "--rounds does not apply here"
        );
    }

    #[test]
    fn missing_duplicate_and_malformed_flags_are_rejected() {
        assert_eq!(
            rejected(
                "client --shape pingpong --conns 1 --message 64 --warmup 1 --cpu 0 --socket s"
            ),
            "missing --rounds"
        );
        assert_eq!(
            rejected("peer --mode echo --mode sink"),
            "--mode given twice"
        );
        assert_eq!(
            rejected("peer --mode echo --conns"),
            "--conns needs a value"
        );
        assert_eq!(
            rejected("peer --mode echo --conns 0 --cpu 0 --socket s"),
            "--conns must be at least 1"
        );
        assert_eq!(
            rejected("peer --mode flood --conns 1 --cpu 0 --socket s"),
            "--mode must be echo or sink, got \"flood\""
        );
        assert_eq!(
            rejected("client --shape stream --cpu 0 --socket s"),
            "--shape must be pingpong or bulk, got \"stream\""
        );
        assert_eq!(
            rejected("client --shape bulk --bytes -1 --warmup 0"),
            "--bytes: cannot parse \"-1\""
        );
        assert_eq!(rejected("peer echo"), "unexpected argument \"echo\"");
        assert_eq!(rejected("serve"), "unknown subcommand \"serve\"");
    }

    #[test]
    fn invalid_shapes_and_run_timeouts_are_rejected_before_start() {
        let cpus = "--peer-cpu 0 --client-cpu 0 --control-cpu 0";
        let cases = [
            (
                "client --shape pingpong --conns 0 --message 64 --rounds 1 --warmup 0 --cpu 0 --socket s"
                    .to_owned(),
                "conns must be 1..=25536",
            ),
            (
                format!("run --shape pingpong --conns 1 --message 7 --rounds 1 --warmup 0 {cpus}"),
                "message must be 8..=512 KiB: a shorter one cannot hold a whole pattern word, the only part unique to its connection and round",
            ),
            (
                format!("run --shape pingpong --conns 1 --message 64 --rounds 0 --warmup 0 {cpus}"),
                "rounds must be positive and warmup + rounds below 2^32",
            ),
            (
                format!(
                    "run --shape pingpong --conns 1 --message 64 --rounds 1 --warmup 4294967295 {cpus}"
                ),
                "rounds must be positive and warmup + rounds below 2^32",
            ),
            (
                "client --shape bulk --bytes 0 --warmup 0 --cpu 0 --socket s".to_owned(),
                "bytes must be positive",
            ),
            (
                "peer --mode echo --conns 1 --cpu 0 --socket s --run-timeout-s 0".to_owned(),
                "--run-timeout-s must be 1..=3600",
            ),
            (
                format!("run --shape bulk --bytes 9 --warmup 0 {cpus} --run-timeout-s 3601"),
                "--run-timeout-s must be 1..=3600",
            ),
        ];
        for (line, expected) in cases {
            assert_eq!(rejected(&line), expected, "{line}");
        }
    }

    #[test]
    fn run_defaults_to_a_short_per_launcher_socket() {
        let line =
            "run --shape bulk --bytes 9 --warmup 0 --peer-cpu 1 --client-cpu 2 --control-cpu 0";
        let Ok(Cmd::Run { socket, .. }) = parse(args(line)) else {
            panic!("{line}")
        };
        assert_eq!(socket, format!("memif-bench-{}", process::id()));
        assert!(socket.len() <= 100);
    }

    #[test]
    fn matrix_takes_reps_and_a_dry_run_switch() {
        let cpus = "--peer-cpu 4 --client-cpu 5 --control-cpu 3";
        let matrix = |reps, dry_run| Cmd::Matrix {
            reps,
            dry_run,
            peer_cpu: 4,
            client_cpu: 5,
            control_cpu: 3,
            run_timeout_s: RUN_TIMEOUT_S,
        };
        assert_eq!(parse(args(&format!("matrix {cpus}"))), Ok(matrix(3, false)));
        assert_eq!(
            parse(args(&format!("matrix --dry-run --reps 2 {cpus}"))),
            Ok(matrix(2, true))
        );
        assert_eq!(
            rejected(&format!("matrix --reps 0 {cpus}")),
            "--reps must be at least 1"
        );
        assert_eq!(
            rejected(&format!("matrix --dry-run --dry-run {cpus}")),
            "--dry-run given twice"
        );
        assert_eq!(
            rejected(&format!("matrix --dry-run yes {cpus}")),
            "unexpected argument \"yes\""
        );
        assert_eq!(
            rejected(&format!("matrix --shape bulk {cpus}")),
            "--shape does not apply here"
        );
        assert_eq!(
            rejected("run --dry-run --shape bulk --bytes 9 --warmup 0 --peer-cpu 0 --client-cpu 0 --control-cpu 0"),
            "--dry-run does not apply here"
        );
    }
}
