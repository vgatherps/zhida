//! The `memif-bench` binary as processes, every CPU the one this test may use:
//! `run` launching peer and client, and the peer/client stdin/stdout protocol
//! driven by hand.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use memif_bench::matrix::{self, Outcome};

const BIN: &str = env!("CARGO_BIN_EXE_memif-bench");
/// Every child's run deadline, so the launcher's own bounds (ready 30 s +
/// link 10 s + run + 10 s for the reports, 10 s per exit) stay below `BOUND`.
const RUN_TIMEOUT: &str = "--run-timeout-s 10";
const BOUND: Duration = Duration::from_secs(120);

fn cpu() -> String {
    zhida_dpdk_sys::only_allowed_cpu()
        .unwrap_or_else(|error| panic!("{error}"))
        .to_string()
}

fn socket(tag: &str) -> String {
    format!("mbt-{tag}-{}", std::process::id())
}

/// Lines of `source`, read on a thread so every read is bounded.
fn read_lines(source: impl Read + Send + 'static) -> Receiver<String> {
    let (send, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(source).lines().map_while(Result::ok) {
            if send.send(line).is_err() {
                break;
            }
        }
    });
    lines
}

/// A child killed on drop, its stdout and stderr read on threads.
struct Proc {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    errors: Receiver<String>,
}

impl Proc {
    fn spawn(args: &[String]) -> Self {
        let mut child = Command::new(BIN)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let lines = read_lines(child.stdout.take().unwrap());
        let errors = read_lines(child.stderr.take().unwrap());
        Self {
            child,
            stdin,
            lines,
            errors,
        }
    }

    fn line(&self) -> String {
        self.lines
            .recv_timeout(BOUND)
            .expect("a line before the bound")
    }

    fn report(&self) -> String {
        let line = self.line();
        line.strip_prefix("report ")
            .unwrap_or_else(|| panic!("{line}"))
            .to_owned()
    }

    fn exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + BOUND;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "child still running at the bound"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn close(&mut self) -> ExitStatus {
        writeln!(self.stdin, "close").unwrap();
        self.exit()
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn args(line: &str) -> Vec<String> {
    line.split_whitespace().map(str::to_owned).collect()
}

/// Every line `source` still yields until it ends.
fn drain(source: &Receiver<String>) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(line) = source.recv_timeout(Duration::from_secs(1)) {
        out.push(line);
    }
    out
}

struct Ran {
    ok: bool,
    stdout: Vec<String>,
    stderr: String,
    elapsed: Duration,
}

fn run_args(shape: &str, socket: &str) -> Vec<String> {
    let cpu = cpu();
    let mut line = args(&format!(
        "run {shape} --peer-cpu {cpu} --client-cpu {cpu} --control-cpu {cpu} {RUN_TIMEOUT}"
    ));
    line.extend(["--socket".to_owned(), socket.to_owned()]);
    line
}

/// `run` with `shape` on this test's CPU, to its exit.
fn run(shape: &str, socket: &str) -> Ran {
    let line = run_args(shape, socket);
    let started = Instant::now();
    let mut run = Proc::spawn(&line);
    let ok = run.exit().success();
    let elapsed = started.elapsed();
    let stderr = drain(&run.errors).join("\n");
    eprintln!("{stderr}");
    Ran {
        ok,
        stdout: drain(&run.lines),
        stderr,
        elapsed,
    }
}

fn valid_pair(lines: &[String]) -> (&str, &str) {
    let [client, peer] = lines else {
        panic!("{lines:?}")
    };
    let client = client
        .strip_prefix("{\"role\":\"client\",\"report\":")
        .unwrap_or_else(|| panic!("{client}"));
    let peer = peer
        .strip_prefix("{\"role\":\"peer\",\"report\":")
        .unwrap_or_else(|| panic!("{peer}"));
    assert!(client.contains("\"valid\":true"), "{client}");
    assert!(peer.contains("\"valid\":true"), "{peer}");
    (client, peer)
}

#[test]
fn run_pingpong_exits_zero_with_two_valid_reports() {
    let shape = "--shape pingpong --conns 1 --message 64 --rounds 20 --warmup 2";
    let ran = run(shape, &socket("pp"));
    assert!(ran.ok, "{:?}", ran.stdout);
    let (client, peer) = valid_pair(&ran.stdout);
    assert!(client.contains("\"shape\":\"pingpong\""), "{client}");
    assert!(client.contains("\"round_trips\":20,"), "{client}");
    assert!(peer.contains("\"mode\":\"echo\""), "{peer}");
    assert!(peer.contains(&format!("\"bytes\":{},", 22 * 64)), "{peer}");
    // The matrix reads these exact lines: a renamed report key drops a row.
    let outcome = Outcome::from_run(&ran.stdout.join("\n"), ran.ok);
    assert_eq!(outcome.status(), "valid");
    let runs = matrix::execute(&[(0, 0)], |_, _| Ok(outcome.clone()), |_, _, _| Ok(())).unwrap();
    let table = matrix::table("pingpong", &runs[0]);
    for row in [
        "ns/round trip",
        "rtt p50 ns",
        "rtt p99 ns",
        "rtt max ns",
        "turns/round trip",
        "ns/frame",
        "frames/s",
        "client idle turns",
        "peer idle turns (whole run)",
    ] {
        assert!(table.contains(&format!("  {row} ")), "{row}: {table}");
    }
}

#[test]
fn run_parallel_and_bulk_exit_zero() {
    let shape = "--shape pingpong --conns 4 --message 64 --rounds 10 --warmup 1";
    let ran = run(shape, &socket("par"));
    assert!(ran.ok, "{:?}", ran.stdout);
    let (client, peer) = valid_pair(&ran.stdout);
    assert!(client.contains("\"shape\":\"parallel\""), "{client}");
    assert!(client.contains("\"round_trips\":40,"), "{client}");
    assert!(
        peer.contains(&format!("\"bytes\":{},", 4 * 11 * 64)),
        "{peer}"
    );

    let (bytes, warmup) = (256 << 10, 16 << 10);
    let ran = run(
        &format!("--shape bulk --bytes {bytes} --warmup {warmup}"),
        &socket("bulk"),
    );
    assert!(ran.ok, "{:?}", ran.stdout);
    let (client, peer) = valid_pair(&ran.stdout);
    assert!(
        client.contains(&format!("\"bytes_acked\":{bytes},")),
        "{client}"
    );
    assert!(peer.contains("\"mode\":\"sink\""), "{peer}");
    assert!(
        peer.contains(&format!("\"bytes\":{},", bytes + warmup)),
        "{peer}"
    );
}

/// A socket name with a comma would make memif ignore its devargs; the
/// peer's `MemifVdev::open` refuses it, so the peer exits before `ready` and
/// the client is never started.
#[test]
fn run_fails_boundedly_when_peer_fails() {
    let socket = socket("bad,name");
    let ran = run(
        "--shape pingpong --conns 1 --message 64 --rounds 1 --warmup 0",
        &socket,
    );
    assert!(!ran.ok);
    assert!(ran.stdout.is_empty(), "{:?}", ran.stdout);
    assert!(ran.elapsed < Duration::from_secs(30), "{:?}", ran.elapsed);
    let refused = "peer memif open: Settings(\"socket name contains ',' or '='\")";
    assert!(ran.stderr.contains(refused), "{}", ran.stderr);
    assert!(
        ran.stderr.contains("peer exited before `ready`"),
        "{}",
        ran.stderr
    );
    for entry in std::fs::read_dir("/proc").unwrap() {
        let mut cmdline = Vec::new();
        if let Ok(mut file) = std::fs::File::open(entry.unwrap().path().join("cmdline")) {
            let _ = file.read_to_end(&mut cmdline);
        }
        assert!(
            !String::from_utf8_lossy(&cmdline).contains(&socket),
            "a child still runs"
        );
    }
}

/// The pid the launcher reported for `role` on stderr, waiting for the line.
fn spawned(launcher: &Proc, role: &str) -> u32 {
    let prefix = format!("memif-bench: spawned {role} pid ");
    loop {
        let line = launcher
            .errors
            .recv_timeout(BOUND)
            .expect("a stderr line before the bound");
        eprintln!("{line}");
        if let Some(pid) = line.strip_prefix(&prefix) {
            return pid.parse().unwrap();
        }
    }
}

/// The client dies (SIGKILL) after the peer reported `ready` and the client
/// was spawned: the launcher fails within its bound, killing and reaping the
/// peer, so no process (not even a zombie) remains under the peer's pid.
#[test]
fn run_kills_and_reaps_peer_when_client_fails() {
    let shape = "--shape pingpong --conns 1 --message 64 --rounds 1000000 --warmup 0";
    let started = Instant::now();
    let mut launcher = Proc::spawn(&run_args(shape, &socket("kill")));
    let peer = spawned(&launcher, "peer");
    let client = spawned(&launcher, "client");
    let killed = Command::new("kill")
        .args(["-9", &client.to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    assert!(!launcher.exit().success());
    assert!(started.elapsed() < BOUND);
    let stderr = drain(&launcher.errors).join("\n");
    assert!(
        stderr.contains("client exited before `report`"),
        "{stderr}"
    );
    assert!(drain(&launcher.lines).is_empty());
    assert!(!Path::new(&format!("/proc/{peer}")).exists(), "peer {peer} remains");
}

/// Each of the three CPUs outside the allowed set is refused before any
/// child starts.
#[test]
fn run_rejects_cpus_outside_its_affinity() {
    let cpu = cpu();
    let other = cpu.parse::<usize>().unwrap() + 1;
    for flag in ["peer-cpu", "client-cpu", "control-cpu"] {
        let mut line = args("run --shape bulk --bytes 9 --warmup 0");
        for name in ["peer-cpu", "client-cpu", "control-cpu"] {
            let value = if name == flag { other.to_string() } else { cpu.clone() };
            line.extend([format!("--{name}"), value]);
        }
        let mut launcher = Proc::spawn(&line);
        assert!(!launcher.exit().success());
        let stderr = drain(&launcher.errors).join("\n");
        let refused = format!("--{flag} {other} is not in this process's allowed CPUs");
        assert!(stderr.contains(&refused), "{stderr}");
        assert!(!stderr.contains("spawned"), "{stderr}");
    }
}

/// Two reps: every configuration forward, then reverse; each line carries
/// the `run` flags of its configuration.
#[test]
fn matrix_dry_run_lists_balanced_order() {
    let configs = [
        "pingpong-m64",
        "pingpong-m1448",
        "parallel-k4",
        "parallel-k16",
        "parallel-k64",
        "bulk-1g",
    ];
    let cpu = cpu();
    let mut matrix = Proc::spawn(&args(&format!(
        "matrix --reps 2 --dry-run --peer-cpu {cpu} --client-cpu {cpu} --control-cpu {cpu}"
    )));
    assert!(matrix.exit().success());
    let lines = drain(&matrix.lines);
    let planned: Vec<(&str, &str)> = lines
        .iter()
        .map(|line| {
            let mut words = line.split_whitespace();
            assert_eq!(words.next(), Some("rep"), "{line}");
            (words.next().unwrap(), words.next().unwrap())
        })
        .collect();
    let expected: Vec<(&str, &str)> = configs
        .iter()
        .map(|&config| ("0", config))
        .chain(configs.iter().rev().map(|&config| ("1", config)))
        .collect();
    assert_eq!(planned, expected);
    assert!(lines[0].ends_with(&format!(
        "--shape pingpong --conns 1 --message 64 --rounds 100000 --warmup 10000 \
         --peer-cpu {cpu} --client-cpu {cpu} --control-cpu {cpu} --run-timeout-s 120"
    )));
    assert!(lines[5].contains("--shape bulk --bytes 1073741824 --warmup 67108864"));
}

/// Socket inodes `pid` holds open: its `socket:[N]` links in /proc/<pid>/fd,
/// memif's control connection among them.
fn sockets(pid: u32) -> BTreeSet<String> {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
        .map(|target| target.to_string_lossy().into_owned())
        .filter(|target| target.starts_with("socket:"))
        .collect()
}

/// After both reports, neither side closes its Port (so neither drops its
/// memif control connection) until it reads `close`. Once the client closes,
/// the peer's memif drops the connection, proving the observation sees it.
#[test]
fn client_waits_for_close_before_closing() {
    let (cpu, socket) = (cpu(), socket("order"));
    let mut peer = Proc::spawn(&args(&format!(
        "peer --mode echo --conns 1 --cpu {cpu} --socket {socket} {RUN_TIMEOUT}"
    )));
    assert_eq!(peer.line(), "ready");
    let shape = "--shape pingpong --conns 1 --message 64 --rounds 20 --warmup 2";
    let mut client = Proc::spawn(&args(&format!(
        "client {shape} --cpu {cpu} --socket {socket} {RUN_TIMEOUT}"
    )));
    let client_report = client.report();
    let peer_report = peer.report();
    assert!(client_report.contains("\"valid\":true"), "{client_report}");
    assert!(peer_report.contains("\"valid\":true"), "{peer_report}");

    let (client_pid, peer_pid) = (client.child.id(), peer.child.id());
    let (client_sockets, peer_sockets) = (sockets(client_pid), sockets(peer_pid));
    assert!(!client_sockets.is_empty() && !peer_sockets.is_empty());
    for _ in 0..25 {
        assert!(client.child.try_wait().unwrap().is_none(), "client exited");
        assert!(peer.child.try_wait().unwrap().is_none(), "peer exited");
        assert_eq!(sockets(client_pid), client_sockets, "client closed a socket");
        assert_eq!(sockets(peer_pid), peer_sockets, "peer closed a socket");
        std::thread::sleep(Duration::from_millis(20));
    }

    assert!(client.close().success());
    let deadline = Instant::now() + BOUND;
    while sockets(peer_pid) == peer_sockets {
        assert!(Instant::now() < deadline, "peer kept the memif connection");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(sockets(peer_pid).is_subset(&peer_sockets));
    assert!(
        peer.child.try_wait().unwrap().is_none(),
        "peer exited before its `close`"
    );
    assert!(peer.close().success());
}
