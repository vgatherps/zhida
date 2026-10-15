//! The `tap-echo` binary's exit statuses. Each test runs the binary, which
//! creates the `cdtap_echo` netdev: needs CAP_NET_ADMIN and /dev/net/tun.

use std::fs::{self, File};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

/// The binary owns one fixed netdev name, so runs never overlap.
static SERIAL: Mutex<()> = Mutex::new(());

const DEADLINE: Duration = Duration::from_secs(20);

/// Held for a whole test, including checks after the driver exited.
fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn driver(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tap-echo"));
    command.args(args);
    command
}

/// Run `command` in its own process group and wait for it to exit within
/// `deadline`. On expiry SIGKILL the whole group, so no tester survives, and
/// fail. Stdout and stderr go to the test's own unless set by the caller.
fn run(mut command: Command, deadline: Duration) -> Output {
    let mut child = command.process_group(0).spawn().expect("spawn tap-echo");
    let start = Instant::now();
    loop {
        if child.try_wait().expect("try_wait").is_some() {
            return child.wait_with_output().expect("collect output");
        }
        if start.elapsed() > deadline {
            let group = libc::pid_t::try_from(child.id()).unwrap();
            // SAFETY: kill(2) takes no pointers. The group is the driver's own:
            // the driver is unreaped, so its pid is not reused.
            let rc = unsafe { libc::kill(-group, libc::SIGKILL) };
            assert_eq!(rc, 0, "kill: {}", std::io::Error::last_os_error());
            child.wait().expect("reap tap-echo");
            panic!("tap-echo did not exit within {deadline:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Waits up to 10 s of wall time for the netdev to be up, then checks every
/// environment variable and that no /dev/net/tun descriptor was inherited.
/// `--foreground` keeps the wait in the driver's process group.
const CHECKING_TESTER: &str = r#"
if ! timeout --foreground 10 sh -c '
    until flags=$(cat "/sys/class/net/$ZHIDA_IFACE/flags" 2>/dev/null) &&
        [ $(( $flags & 1 )) -eq 1 ]; do
        sleep 0.01
    done'; then
    echo "tester: $ZHIDA_IFACE not up within 10 s" >&2
    exit 2
fi
check() {
    eval "value=\${$1-unset}"
    if [ "$value" != "$2" ]; then
        echo "tester: $1=$value, expected $2" >&2
        exit 3
    fi
}
check ZHIDA_IFACE cdtap_echo
check ZHIDA_MAC 02:00:00:00:00:01
check ZHIDA_IP 192.0.2.2
check TESTER_MAC 02:00:00:00:00:02
check TESTER_IP 192.0.2.1
check ECHO_PORT 8080
if ls -l /proc/self/fd | grep -q /dev/net/tun; then
    echo "tester: inherited /dev/net/tun descriptors:" >&2
    ls -l /proc/self/fd >&2
    exit 4
fi
"#;

const USAGE: &str =
    "usage: tap-echo [--listeners N] [--buffer BYTES] [--close-after BYTES] -- <tester> [args...]";

#[test]
fn tester_success_exits_zero() {
    let _serial = serial();
    let status = run(driver(&["--", "sh", "-c", CHECKING_TESTER]), DEADLINE).status;
    assert_eq!(status.code(), Some(0), "{status}");
    assert!(
        !Path::new("/sys/class/net/cdtap_echo").exists(),
        "cdtap_echo outlived the driver"
    );
}

#[test]
fn tester_failure_exits_one() {
    let _serial = serial();
    let status = run(driver(&["--", "false"]), DEADLINE).status;
    assert_eq!(status.code(), Some(1), "{status}");
}

#[test]
fn tester_killed_by_signal_exits_one() {
    let _serial = serial();
    let status = run(driver(&["--", "sh", "-c", "kill -9 $$"]), DEADLINE).status;
    assert_eq!(status.code(), Some(1), "{status}");
}

/// The flags parse in either order with 1-byte and 1 MiB buffers and zero
/// --close-after. The 1 GiB upper bound is not run because its pool memory
/// grows with the receive buffer.
#[test]
fn buffer_and_close_after_flags_parse() {
    let _serial = serial();
    for args in [
        &["--buffer", "1", "--close-after", "0", "--", "true"][..],
        &[
            "--close-after",
            "5",
            "--listeners",
            "1",
            "--buffer",
            "1048576",
            "--",
            "true",
        ],
    ] {
        let mut command = driver(args);
        command.stderr(Stdio::piped());
        let output = run(command, DEADLINE);
        let (status, stderr) = (output.status, String::from_utf8_lossy(&output.stderr));
        assert_eq!(status.code(), Some(0), "{args:?}: {status}\n{stderr}");
    }
}

#[test]
fn bad_arguments_exit_three() {
    let _serial = serial();
    for (args, reason) in [
        (&["true"][..], "unexpected argument \"true\""),
        (&["--listeners", "2"], "missing -- <tester>"),
        (&["--bogus", "--", "true"], "unexpected argument \"--bogus\""),
        (&["--listeners", "0", "--", "true"], "--listeners needs an integer"),
        (&["--buffer", "0", "--", "true"], "--buffer needs an integer from 1 to 1073741824"),
        (&["--buffer", "1073741825", "--", "true"], "--buffer needs an integer"),
        (&["--buffer", "4k", "--", "true"], "--buffer needs an integer"),
        (&["--buffer"], "--buffer needs a value"),
        (&["--close-after", "-1", "--", "true"], "--close-after needs an integer"),
        (&["--close-after", "ten", "--", "true"], "--close-after needs an integer"),
        (&["--close-after", "1", "--close-after", "2", "--", "true"], "--close-after given twice"),
    ] {
        let mut command = driver(args);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let output = run(command, DEADLINE);
        let (status, stderr) = (output.status, String::from_utf8_lossy(&output.stderr));
        assert_eq!(status.code(), Some(3), "{args:?}: {status}\n{stderr}");
        assert!(
            stderr.contains(reason) && stderr.contains(USAGE),
            "{args:?}: no {reason:?} and usage on stderr:\n{stderr}"
        );
    }
}

/// Every write to /dev/full fails with ENOSPC; the usage diagnostic is lost,
/// the exit status is not.
#[test]
fn bad_arguments_exit_three_when_stderr_fails() {
    let _serial = serial();
    let mut command = driver(&["--bogus", "--", "true"]);
    let full = File::options().write(true).open("/dev/full").unwrap();
    command.stderr(full);
    let status = run(command, DEADLINE).status;
    assert_eq!(status.code(), Some(3), "{status}");
}

/// A tester that outlives the deadline is SIGKILLed with the driver's whole
/// group. Once killed it is gone or, orphaned, a zombie awaiting PID 1.
#[test]
fn deadline_kills_tester() {
    let _serial = serial();
    let pid_file = std::env::temp_dir().join(format!("zhida-tester-{}", std::process::id()));
    let path = pid_file.to_str().unwrap();
    let command = driver(&["--", "sh", "-c", r#"echo $$ > "$1"; exec sleep 60"#, "sh", path]);
    // The command is consumed by the run; nothing it touched is observed after a panic.
    let run_once = std::panic::AssertUnwindSafe(|| run(command, Duration::from_secs(3)));
    let panic = std::panic::catch_unwind(run_once);
    assert!(panic.is_err(), "tap-echo exited before the deadline");
    let pid = fs::read_to_string(&pid_file).expect("tester wrote its pid");
    fs::remove_file(&pid_file).unwrap();
    let stat = format!("/proc/{}/stat", pid.trim());
    // SIGKILL takes effect asynchronously; allow it a moment.
    let start = Instant::now();
    loop {
        match fs::read_to_string(&stat) {
            Err(_) => return,
            Ok(line) if line.rsplit_once(')').unwrap().1.trim_start().starts_with('Z') => return,
            Ok(line) => assert!(
                start.elapsed() < Duration::from_secs(1),
                "tester outlived the deadline kill: {line}"
            ),
        }
        thread::sleep(Duration::from_millis(10));
    }
}
