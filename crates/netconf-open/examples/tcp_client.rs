//! Connects to a TCP server through zhida, sends one line, prints whatever the
//! server sends back, and closes once the server closes its side.
//!
//! ```text
//! cargo build -p zhida-open --example tcp_client
//! taskset -c 3 target/debug/examples/tcp_client dut.json 192.0.2.1:7000
//! ```
//!
//! `open` needs exactly one allowed CPU, hence `taskset`. The config is the one
//! `zhida-netconf discover` writes.
//!
//! To try it without a NIC, as root on Linux (or in the Docker image with
//! `--cap-add NET_ADMIN --device /dev/net/tun`), save the tap config from
//! crates/nic-runner/README.md section 3 as `tap.json`. Start a kernel-side
//! server that replies and then closes, start the client, and give the tap
//! device its kernel address once the client has created it:
//!
//! ```text
//! python3 -c 'import socket; s = socket.create_server(("0.0.0.0", 7000)); c, _ = s.accept(); c.recv(100); c.sendall(b"tick\n"); c.close()' &
//! taskset -c 3 target/debug/examples/tcp_client tap.json 192.0.2.1:7000 &
//! until ip link show cdnic0 >/dev/null 2>&1; do sleep 0.1; done
//! ip addr add 192.0.2.1/24 dev cdnic0 && ip link set cdnic0 up
//! wait
//! ```

use std::error::Error;
use std::io::{self, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, Instant as WallInstant};

use dpdk_smoltcp::smoltcp::socket::tcp::{self, State};
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::DEFAULT_NEIGHBOR_CAPACITY;
use zhida_netconf::Config;
use zhida_open::{open, Sizing};

const BUFFER: usize = 64 * 1024;
/// There is no ephemeral port allocator; the local port must be nonzero.
const LOCAL_PORT: u16 = 40000;
const INGRESS_BUDGET: usize = 32;
const LIMIT: Duration = Duration::from_secs(30);

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let (Some(config), Some(server)) = (args.next(), args.next()) else {
        return Err("usage: tcp_client CONFIG HOST:PORT".into());
    };
    let config = Config::load(Path::new(&config))?;
    // Name lookup goes through the kernel and blocks, so do it before open.
    let Some(SocketAddr::V4(server)) = server.to_socket_addrs()?.find(SocketAddr::is_ipv4) else {
        return Err("server has no IPv4 address".into());
    };

    // Include the path MSS cap when sizing the RX pool.
    let socket = tcp::Config {
        rx_capacity: BUFFER, tx_capacity: BUFFER,
        mss_cap: Some(config.path_mtu((*server.ip()).into()) - 40),
    };
    let sizing = Sizing {
        tcp_rx_frames: tcp::rx_mbuf_budget(&socket, usize::from(config.mtu)),
        udp_rx_datagrams: 0,
        max_sockets: 1,
        max_udp_sockets: 0,
        rx_staging: 32,
        tx_pending: 32,
        segments_per_visit: 1,
        neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
    };

    // Every drive call must get time from this one clock. It never goes backwards.
    let start = WallInstant::now();
    let mut clock = || Instant::from_micros(i64::try_from(start.elapsed().as_micros()).unwrap());
    // SAFETY: EAL creates the device named in the config, this thread owns it and
    // every packet, and EAL (`_eal` below) lives until the process exits.
    // An error drops the Port it carries; crates/nic-runner/src/main.rs shows how
    // to close it instead.
    let opened = unsafe { open(&config, &sizing, &mut clock) }?;
    println!("{}", opened.report);
    let _eal = opened.eal;
    let mut stack = opened.stack;

    let handle = stack.add_tcp(socket)?;
    stack.connect(&handle, server, LOCAL_PORT)?;
    let mut said_hello = false;
    let mut server_closed = false;
    let mut out = io::stdout().lock();
    // This loop spins on its core. That is the intended deployment: one core per Stack.
    loop {
        if start.elapsed() > LIMIT {
            return Err(format!("not finished after {LIMIT:?}").into());
        }
        stack.receive(clock(), INGRESS_BUDGET)?;
        let socket = stack.tcp_mut(&handle);
        // Each frame holds an RX mbuf until it is dropped, so write and drop it here.
        while socket.may_recv() {
            let Some(frame) = socket.recv()? else { break };
            out.write_all(frame.payload())?;
        }
        if !said_hello && socket.may_send() {
            socket.send_slice(b"hello\n")?;
            said_hello = true;
        }
        if socket.state() == State::CloseWait {
            server_closed = true;
            socket.close();
        }
        if socket.state() == State::Closed {
            break;
        }
        stack.send()?;
    }
    out.flush()?;
    if stack.tcp(&handle).reset_by_peer() {
        return Err("the server reset the connection".into());
    }
    if !server_closed {
        return Err("the connection closed before the server finished".into());
    }

    // Received frames are all dropped, so the Port can return every buffer.
    match stack.into_port().try_close() {
        Ok(()) => {
            println!("port closed");
            Ok(())
        }
        Err((_port, error)) => Err(format!("port close: {error}").into()),
    }
}
