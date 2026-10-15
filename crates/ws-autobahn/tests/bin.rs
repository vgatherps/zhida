//! The `ws-autobahn` binary's exit statuses through the shared tap_echo
//! driver. Each test runs the binary, which creates the `cdtap_echo` netdev:
//! needs CAP_NET_ADMIN and /dev/net/tun. tap-echo's driver tests cover the
//! remaining statuses.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard};

/// The binary owns one fixed netdev name, so runs never overlap.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Runs the binary under `timeout` (not --foreground: expiry kills the
/// whole group, tester included).
fn run(args: &[&str]) -> Output {
    run_in(Path::new("."), args)
}

/// `run` with working directory `dir`.
fn run_in(dir: &Path, args: &[&str]) -> Output {
    Command::new("timeout")
        .args(["--kill-after=5", "30", env!("CARGO_BIN_EXE_ws-autobahn")])
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run ws-autobahn under timeout")
}

/// Waits for the netdev, takes 192.0.2.1 on it, then runs `$1` in python3.
const KERNEL_TESTER: &str = r#"
if ! timeout --foreground 10 sh -c '
    until flags=$(cat "/sys/class/net/$ZHIDA_IFACE/flags" 2>/dev/null) &&
        [ $(( $flags & 1 )) -eq 1 ]; do
        sleep 0.01
    done'; then
    echo "tester: $ZHIDA_IFACE not up within 10 s" >&2
    exit 2
fi
ip addr add "$TESTER_IP/24" dev "$ZHIDA_IFACE" || exit 3
exec python3 -c "$1"
"#;

/// Kernel TCP client: upgrade, a masked Text "hi", a Close; expects the
/// echo, the close reply and then EOF.
const CLIENT: &str = r#"
import os, socket
s = socket.create_connection((os.environ["ZHIDA_IP"], int(os.environ["ECHO_PORT"])), timeout=10)
s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
          b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
response = b""
while not response.endswith(b"\r\n\r\n"):
    data = s.recv(1)
    assert data, response
    response += data
assert response.startswith(b"HTTP/1.1 101 "), response
s.sendall(bytes([0x81, 0x82, 0, 0, 0, 0]) + b"hi" + bytes([0x88, 0x80, 0, 0, 0, 0]))
rest = b""
while True:
    data = s.recv(4096)
    if not data:
        break
    rest += data
assert rest == bytes([0x81, 2]) + b"hi" + bytes([0x88, 0]), rest
"#;

#[test]
fn kernel_client_session_exits_zero() {
    let _serial = serial();
    let output = run(&[
        "server",
        "--expect-connections",
        "1",
        "--",
        "sh",
        "-c",
        KERNEL_TESTER,
        "sh",
        CLIENT,
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}\n{stdout}\n{stderr}",
        output.status
    );
    assert!(
        stdout.contains("accepted 1 of 1 connections; endings {\"ConnectionClosed\": 1}"),
        "{stdout}"
    );
}

/// The tester succeeds without connecting: the app's accepted-count check
/// fails, and its error (exit 3) takes precedence over the tester's 0.
#[test]
fn missing_connection_exits_three() {
    let _serial = serial();
    let output = run(&["server", "--expect-connections", "1", "--", "true"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{}\n{stderr}", output.status);
    assert!(
        stderr.contains("ws-autobahn: accepted 0 connections, expected 1"),
        "{stderr}"
    );
}

/// Client mode, the tester exits 0 before server-ready exists (a fresh
/// working directory, so none does): the client's error, exit 3.
#[test]
fn client_tester_exit_before_server_ready_exits_three() {
    let _serial = serial();
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("ws-autobahn-client-early-exit");
    if dir.exists() {
        fs::remove_dir_all(&dir).unwrap();
    }
    fs::create_dir_all(&dir).unwrap();
    let output = run_in(&dir, &["client", "--expect-cases", "1", "--", "true"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{}\n{stderr}", output.status);
    assert!(
        stderr
            .contains("ws-autobahn: tester exited before autobahn/run/client/server-ready existed"),
        "{stderr}"
    );
}

/// Kernel TCP WebSocket server on TESTER_IP:9001 playing fuzzingserver's
/// protocol for one case: listens, writes autobahn/run/client/server-ready,
/// then serves getCaseCount ("1", Close), runCase 1 (Text "hi", expects its
/// masked echo, Close) and updateReports (Close). Each connection expects the
/// client's Close, then sends its FIN first and waits for the client's.
/// Then waits (10 s) for the client's autobahn/run/client/client-done.
const FUZZINGSERVER: &str = r#"
import base64, hashlib, os, socket
listener = socket.create_server((os.environ['TESTER_IP'], 9001))
listener.settimeout(10)
os.makedirs('autobahn/run/client', exist_ok=True)
open('autobahn/run/client/server-ready', 'w').close()

def exact(s, n):
    data = b''
    while len(data) < n:
        chunk = s.recv(n - len(data))
        assert chunk, data
        data += chunk
    return data

def frame(s):
    b0, b1 = exact(s, 2)
    assert b1 & 0x80, 'client frames are masked'
    assert b1 & 0x7f < 126
    mask = exact(s, 4)
    payload = bytes(b ^ mask[i % 4] for i, b in enumerate(exact(s, b1 & 0x7f)))
    return b0, payload

def session(path, send):
    s, _ = listener.accept()
    s.settimeout(10)
    request = b''
    while not request.endswith(b'\r\n\r\n'):
        data = s.recv(1)
        assert data, request
        request += data
    lines = request.decode().split('\r\n')
    assert lines[0] == 'GET ' + path + ' HTTP/1.1', lines[0]
    key = next(l.split(':', 1)[1].strip() for l in lines if l.lower().startswith('sec-websocket-key:'))
    accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
    s.sendall(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
              b'Sec-WebSocket-Accept: ' + accept + b'\r\n\r\n')
    send(s)
    s.sendall(bytes([0x88, 0]))
    assert frame(s) == (0x88, b''), 'close reply'
    s.shutdown(socket.SHUT_WR)
    assert s.recv(1) == b'', 'client FIN'
    s.close()

session('/getCaseCount', lambda s: s.sendall(bytes([0x81, 1]) + b'1'))
def case(s):
    s.sendall(bytes([0x81, 2]) + b'hi')
    assert frame(s) == (0x81, b'hi'), 'echo'
session('/runCase?case=1&agent=Tungstenite', case)
session('/updateReports?agent=Tungstenite', lambda s: None)
import time
deadline = time.monotonic() + 10
while not os.path.exists('autobahn/run/client/client-done'):
    assert time.monotonic() < deadline, 'no client-done within 10 s'
    time.sleep(0.01)
"#;

#[test]
fn kernel_fuzzingserver_session_exits_zero() {
    let _serial = serial();
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("ws-autobahn-client-bin");
    if dir.exists() {
        fs::remove_dir_all(&dir).unwrap();
    }
    fs::create_dir_all(&dir).unwrap();
    let output = run_in(
        &dir,
        &[
            "client",
            "--expect-cases",
            "1",
            "--",
            "sh",
            "-c",
            KERNEL_TESTER,
            "sh",
            FUZZINGSERVER,
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}\n{stdout}\n{stderr}",
        output.status
    );
    assert!(
        stdout.contains("3 of 3 connections; endings {\"ConnectionClosed\": 3}"),
        "{stdout}"
    );
}
