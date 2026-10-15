//! Zhida echo server on a net_tap netdev, supervising one tester process.
//! See `usage` for the fixed configuration and exit statuses.

use std::ffi::OsString;
use std::process;

use tap_echo::driver::{
    self, mac, tester_env, BURST, ZHIDA_IP, ZHIDA_MAC, DESCRIPTORS, DEVARGS, ECHO_PORT,
    EXIT_ERROR, EXIT_OK, EXIT_OUTSTANDING_BUFFERS, EXIT_TESTER_FAILED, FRAME_ROOM, IFACE, MTU,
    POOL_CACHE, POOL_COUNT, PREFIX_LEN, RX_STAGING, TX_PENDING, VDEV,
};
use tap_echo::{serve, EchoServer};

const NAME: &str = "tap-echo";
const ECHO_BUFFER: usize = 128 * 1024;
/// Largest receive buffer smoltcp accepts (it panics above 2^30); its window scale is 14.
const MAX_BUFFER: usize = 1 << 30;

fn usage() -> String {
    let env: Vec<String> = tester_env()
        .iter()
        .map(|(name, value)| format!("  {name}={value}"))
        .collect();
    format!(
        "\
usage: tap-echo [--listeners N] [--buffer BYTES] [--close-after BYTES] -- <tester> [args...]

Runs Zhida's TCP echo server until <tester> exits. N listening sockets
(default 1, at least 1) on port {ECHO_PORT}, RX and TX buffers of BYTES bytes each (default
{ECHO_BUFFER}, 1 to {MAX_BUFFER}). With --close-after, each connection echoes at most BYTES
bytes, then Zhida closes (FIN after them) and reads and discards whatever the peer
sends; a peer FIN before that closes as without it.
Zhida: MAC {zhida_mac}, IPv4 {ZHIDA_IP}/{PREFIX_LEN}. DPDK vdev {vdev} with
devargs {devargs}: kernel netdev {IFACE}. Port: MTU {MTU}, {DESCRIPTORS}/{DESCRIPTORS}
descriptors, bursts {BURST}/{BURST}, a TX pool of {POOL_COUNT} mbufs and an RX pool sized by
dpdk_smoltcp::rx_pool_count for N sockets of BYTES receive bytes (cache {POOL_CACHE}, data room
headroom + {FRAME_ROOM}). Stack: random_seed from /dev/urandom each run, max_sockets N, rx_staging
{RX_STAGING}, tx_pending {TX_PENDING}.

The tester starts before DPDK does and must itself wait until {IFACE} is up.
Only the tester itself is killed: run it directly or have it exec its final
command (no sh -c wrapper without exec). It must exit on SIGTERM. Bound a run with
`timeout --kill-after=N`, without --foreground, so expiry signals the whole
process group, tester included.
Its environment adds:
{env}

Exit status: {EXIT_OK} tester exited 0; {EXIT_TESTER_FAILED} tester exited nonzero or was killed by a signal;
{EXIT_OUTSTANDING_BUFFERS} packet buffers still in use at port close; {EXIT_ERROR} bad arguments, or a setup,
serve or teardown error; 101 panic. {EXIT_OUTSTANDING_BUFFERS} and {EXIT_ERROR} take precedence over the tester's status.
Diagnostics on stderr are best effort and never change the exit status.
",
        zhida_mac = mac(ZHIDA_MAC),
        vdev = VDEV.to_str().unwrap(),
        devargs = DEVARGS.to_str().unwrap(),
        env = env.join("\n"),
    )
}

struct Args {
    listeners: usize,
    buffer: usize,
    close_after: Option<usize>,
    tester: Vec<OsString>,
}

fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Args, String> {
    let (mut listeners, mut buffer, mut close_after) = (None, None, None);
    loop {
        let arg = args.next().ok_or("missing -- <tester>")?;
        let (flag, slot, range) = match arg.to_str() {
            Some("--") => break,
            Some(flag @ "--listeners") => (flag, &mut listeners, 1..=usize::MAX),
            Some(flag @ "--buffer") => (flag, &mut buffer, 1..=MAX_BUFFER),
            Some(flag @ "--close-after") => (flag, &mut close_after, 0..=usize::MAX),
            _ => return Err(format!("unexpected argument {arg:?}")),
        };
        if slot.is_some() {
            return Err(format!("{flag} given twice"));
        }
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let number = value
            .to_str()
            .and_then(|text| text.parse::<usize>().ok())
            .filter(|n| range.contains(n))
            .ok_or_else(|| {
                format!(
                    "{flag} needs an integer from {} to {}, got {value:?}",
                    range.start(),
                    range.end()
                )
            })?;
        *slot = Some(number);
    }
    let tester: Vec<OsString> = args.collect();
    if tester.is_empty() {
        return Err("missing tester command after --".to_owned());
    }
    Ok(Args {
        listeners: listeners.unwrap_or(1),
        buffer: buffer.unwrap_or(ECHO_BUFFER),
        close_after,
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
    let Args {
        listeners,
        buffer,
        close_after,
        tester,
    } = args;
    let code = driver::run(
        NAME,
        &tester,
        listeners,
        buffer,
        None,
        |stack, start, stop| {
            let mut echo = EchoServer::new(stack, ECHO_PORT, listeners, buffer)
                .map_err(|error| format!("EchoServer::new: {error}"))?
                .with_close_after(close_after);
            serve(stack, &mut echo, start, |_, _| stop()).map_err(|error| format!("serve: {error}"))
        },
    );
    process::exit(code);
}
