//! The net_tap driver both binaries share: one tester process spawned before
//! EAL, a Zhida Stack on the `cdtap_echo` netdev, an application run until
//! the tester exits, teardown and exit-status composition.

use std::ffi::{CStr, OsString};
use std::fmt::{self, Write as _};
use std::io;
use std::net::Ipv4Addr;
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::Instant;

use dpdk_smoltcp::smoltcp::time::Instant as StackInstant;
use dpdk_smoltcp::smoltcp::wire::{EthernetAddress, Ipv4Cidr};
use dpdk_smoltcp::{
    os_random_seed, port_by_name, rx_pool_count, rx_reserve, Eal, Offloads, Port, PortConfig,
    PortError, Stack, StackConfig, DEFAULT_NEIGHBOR_CAPACITY,
};
use zhida_buffer::PoolConfig;
use zhida_dpdk_sys::{only_allowed_cpu, rte_vdev_init, rte_vdev_uninit, RTE_PKTMBUF_HEADROOM};

pub const VDEV: &CStr = c"net_tap_echo";
pub const IFACE: &str = "cdtap_echo";
pub const DEVARGS: &CStr = c"iface=cdtap_echo,mac=02:00:00:00:00:fe";
const RX_POOL: &CStr = c"echo_rx";
const TX_POOL: &CStr = c"echo_tx";

pub const ZHIDA_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
pub const ZHIDA_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
pub const PREFIX_LEN: u8 = 24;
const TESTER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];
/// The kernel side's address on the tap netdev, given to the tester.
pub const TESTER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// The port the application listens on, given to the tester as ECHO_PORT.
pub const ECHO_PORT: u16 = 8080;

pub const MTU: u16 = 1500;
pub const DESCRIPTORS: u16 = 16;
pub const BURST: u16 = 32;
pub const POOL_COUNT: u32 = 127;
pub const POOL_CACHE: u32 = 8;
pub const FRAME_ROOM: u16 = 2048;
pub const RX_STAGING: usize = 32;
pub const TX_PENDING: usize = 32;

// Each mbuf's budget covers its data room, headers and alignment.
const MBUF_MEMORY_BYTES: u64 = 4096;
// EAL needs memory beyond the RX and TX pools.
const EAL_BASE_MEMORY_MB: u64 = 64;
// DPDK's -m value is in units of 1 MiB.
const BYTES_PER_MIB: u64 = 1024 * 1024;

/// Exit statuses besides 101, the default for a panic.
pub const EXIT_OK: i32 = 0;
pub const EXIT_TESTER_FAILED: i32 = 1;
pub const EXIT_OUTSTANDING_BUFFERS: i32 = 2;
pub const EXIT_ERROR: i32 = 3;

/// Best-effort diagnostic on stderr, prefixed `name: `: a failed write must
/// not change the exit status (`eprintln!` panics on failure).
pub fn report(name: &str, message: fmt::Arguments<'_>) {
    use std::io::Write as _;
    let _ = writeln!(io::stderr(), "{name}: {message}");
}

pub fn mac(bytes: [u8; 6]) -> String {
    let mut text = String::new();
    for (index, byte) in bytes.iter().enumerate() {
        let separator = if index == 0 { "" } else { ":" };
        write!(text, "{separator}{byte:02x}").unwrap();
    }
    text
}

/// Environment added for the tester.
pub fn tester_env() -> [(&'static str, String); 6] {
    [
        ("ZHIDA_IFACE", IFACE.to_owned()),
        ("ZHIDA_MAC", mac(ZHIDA_MAC)),
        ("ZHIDA_IP", ZHIDA_IP.to_string()),
        ("TESTER_MAC", mac(TESTER_MAC)),
        ("TESTER_IP", TESTER_IP.to_string()),
        ("ECHO_PORT", ECHO_PORT.to_string()),
    ]
}

/// The tester process. Unwinding kills and reaps it, so no tester outlives a
/// panicking driver.
struct Tester {
    child: Child,
    name: &'static str,
}

impl Tester {
    /// SIGKILL (a no-op once reaped), then reap.
    fn kill(&mut self) {
        if let Err(error) = self.child.kill() {
            report(self.name, format_args!("killing the tester: {error}"));
        }
        if let Err(error) = self.child.wait() {
            report(self.name, format_args!("reaping the tester: {error}"));
        }
    }

    /// Print `message`, kill the tester and return `EXIT_ERROR`.
    fn fail(&mut self, message: impl fmt::Display) -> i32 {
        report(self.name, format_args!("{message}"));
        self.kill();
        EXIT_ERROR
    }
}

impl Drop for Tester {
    fn drop(&mut self) {
        if thread::panicking() {
            self.kill();
        }
    }
}

/// Spawns `tester` (non-empty) with `tester_env`, then runs `app` on a Stack
/// with `max_sockets` slots, `recv_capacity` receive bytes per socket and
/// optional IPv4 `gateway` until it returns,
/// and composes the exit status.
///
/// `app` gets the Stack, created at `Instant::ZERO` = the wall-clock `start`,
/// and `stop`, which polls whether the tester exited. It must return `Ok` only
/// after `stop` returned true. `Err` is printed, the tester killed, exit
/// `EXIT_ERROR`. Diagnostics are prefixed `name: `.
pub fn run(
    name: &'static str,
    tester: &[OsString],
    max_sockets: usize,
    recv_capacity: usize,
    gateway: Option<Ipv4Addr>,
    app: impl FnOnce(&mut Stack, Instant, &mut dyn FnMut() -> bool) -> Result<(), String>,
) -> i32 {
    let random_seed = match os_random_seed() {
        Ok(seed) => seed,
        Err(error) => {
            report(name, format_args!("OS random seed: {error}"));
            return EXIT_ERROR;
        }
    };
    // EAL's main lcore 7 runs on the one CPU this process may use; checked
    // before a tester exists.
    let cpu = match only_allowed_cpu() {
        Ok(cpu) => cpu,
        Err(error) => {
            report(name, format_args!("EAL CPU: {error}"));
            return EXIT_ERROR;
        }
    };
    // Before EAL: net_tap opens its /dev/net/tun queue fds without
    // O_CLOEXEC (rte_eth_tap.c tun_alloc), and a child forked later would
    // inherit them and keep the netdev alive.
    let child = Command::new(&tester[0])
        .args(&tester[1..])
        .envs(tester_env())
        .spawn();
    let mut tester_process = match child {
        Ok(child) => Tester { child, name },
        Err(error) => {
            report(name, format_args!("starting tester {:?}: {error}", tester[0]));
            return EXIT_ERROR;
        }
    };
    serve(
        &mut tester_process,
        cpu,
        max_sockets,
        recv_capacity,
        gateway,
        random_seed,
        app,
    )
}

fn port_config(port_id: u16, max_sockets: usize, recv_capacity: usize) -> PortConfig<'static> {
    let pool = |name, count| PoolConfig {
        name,
        count,
        cache_size: POOL_CACHE,
        data_room_size: RTE_PKTMBUF_HEADROOM as u16 + FRAME_ROOM,
        socket_id: -1,
    };
    PortConfig {
        port_id,
        mtu: MTU,
        rx_descriptors: DESCRIPTORS,
        tx_descriptors: DESCRIPTORS,
        rx_burst: BURST,
        tx_burst: BURST,
        queue_socket: -1,
        rx_pool: pool(
            RX_POOL,
            rx_pool_count(
                rx_reserve(DESCRIPTORS, RX_STAGING, POOL_CACHE),
                MTU,
                std::iter::repeat(recv_capacity).take(max_sockets),
            ),
        ),
        tx_pool: pool(TX_POOL, POOL_COUNT),
        offloads: Offloads::default(),
    }
}

fn stack_config(max_sockets: usize, gateway: Option<Ipv4Addr>, random_seed: u64) -> StackConfig<'static> {
    StackConfig {
        max_udp_sockets: 0,
        ethernet: EthernetAddress(ZHIDA_MAC),
        ipv4: Ipv4Cidr::new(ZHIDA_IP, PREFIX_LEN),
        gateway: gateway.map(Into::into),
        paths: &[],
        random_seed,
        neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
        segments_per_visit: 1,
        max_sockets,
        rx_staging: RX_STAGING,
        tx_pending: TX_PENDING,
    }
}

/// Run `app` until the tester exits, tear down, and compose the exit status.
/// EAL's main lcore 7 runs on `cpu`.
fn serve(
    tester: &mut Tester,
    cpu: usize,
    max_sockets: usize,
    recv_capacity: usize,
    gateway: Option<Ipv4Addr>,
    random_seed: u64,
    app: impl FnOnce(&mut Stack, Instant, &mut dyn FnMut() -> bool) -> Result<(), String>,
) -> i32 {
    let mut config = port_config(u16::MAX, max_sockets, recv_capacity);
    let pool_memory_bytes = u64::from(config.rx_pool.count)
        .checked_add(u64::from(config.tx_pool.count))
        .and_then(|count| count.checked_mul(MBUF_MEMORY_BYTES))
        .expect("pool memory size exceeds u64");
    let pool_memory_mb = (pool_memory_bytes / BYTES_PER_MIB)
        .checked_add(u64::from(pool_memory_bytes % BYTES_PER_MIB != 0))
        .expect("pool memory MB exceeds u64");
    let memory_mb = EAL_BASE_MEMORY_MB
        .checked_add(pool_memory_mb)
        .expect("EAL memory MB exceeds u64");
    let memory = memory_mb.to_string();
    let lcores = format!("--lcores=7@{cpu}");
    let eal_args = [
        "tap-echo",
        "--no-pci",
        "--no-huge",
        "-m",
        memory.as_str(),
        "--no-shconf",
        "--no-telemetry",
        lcores.as_str(),
        "--main-lcore=7",
    ];
    let eal = match Eal::init(&eal_args) {
        Ok(eal) => eal,
        Err(error) => {
            return tester.fail(format_args!("EAL init: {error}; requested {memory_mb} MB"))
        }
    };
    // SAFETY: both arguments are NUL-terminated strings valid for the call.
    let rc = unsafe { rte_vdev_init(VDEV.as_ptr(), DEVARGS.as_ptr()) };
    if rc != 0 {
        return tester.fail(format_args!("rte_vdev_init: {rc}"));
    }
    let name = VDEV.to_str().unwrap();
    config.port_id = match port_by_name(&eal, name) {
        Some(port_id) => port_id,
        None => return tester.fail(format_args!("port_by_name: {name} not found")),
    };
    // SAFETY: the net_tap ethdev was just created by rte_vdev_init and nothing
    // else configures or uses it; this thread is the EAL main lcore and the
    // only one touching EAL, the Port and its packets. net_tap honors the
    // offload-free profile and frees its buffers on close (DPDK 25.11
    // rte_eth_tap.c: single-segment RX 438-493, 1523-1562; TX 662-745, freed
    // synchronously 729-732; close frees held RX buffers 1048-1073). The
    // vdev is removed only after the Port closed, and EAL lives until exit.
    let port = match unsafe { Port::open(&eal, config) } {
        Ok(port) => port,
        Err(error)
            if matches!(
                error.cause,
                PortError::Pool {
                    direction: "RX",
                    ..
                }
            ) =>
        {
            return tester.fail(format_args!(
                "RX pool {RX_POOL:?}: requested {} mbufs: {error}",
                config.rx_pool.count
            ))
        }
        Err(error) => return tester.fail(error),
    };
    let start = Instant::now();
    let mut stack = match Stack::new(
        port,
        stack_config(max_sockets, gateway, random_seed),
        StackInstant::ZERO,
    ) {
        Ok(stack) => stack,
        Err((_, error)) => return tester.fail(format_args!("Stack::new: {error}")),
    };

    let mut waited: io::Result<Option<ExitStatus>> = Ok(None);
    let served = app(&mut stack, start, &mut || {
        waited = tester.child.try_wait();
        !matches!(waited, Ok(None))
    });
    if let Err(error) = served {
        return tester.fail(error);
    }
    let status = match waited {
        Ok(Some(status)) => status,
        Ok(None) => unreachable!("the app returned while the tester runs"),
        Err(error) => return tester.fail(format_args!("waiting for the tester: {error}")),
    };

    let name = tester.name;
    let teardown = match stack.into_port().try_close() {
        Ok(()) => {
            // SAFETY: `VDEV` is NUL-terminated; its Port is closed.
            let rc = unsafe { rte_vdev_uninit(VDEV.as_ptr()) };
            if rc != 0 {
                report(name, format_args!("rte_vdev_uninit: {rc}"));
                Some(EXIT_ERROR)
            } else {
                None
            }
        }
        Err((_, PortError::OutstandingBuffers { rx, tx })) => {
            report(
                name,
                format_args!("buffers still in use at port close: rx {rx}, tx {tx}"),
            );
            Some(EXIT_OUTSTANDING_BUFFERS)
        }
        Err((_, error)) => {
            report(name, format_args!("port close: {error}"));
            Some(EXIT_ERROR)
        }
    };
    if !status.success() {
        report(name, format_args!("tester {status}"));
    }
    teardown.unwrap_or(if status.success() {
        EXIT_OK
    } else {
        EXIT_TESTER_FAILED
    })
}
