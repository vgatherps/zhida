mod args;
mod feed;
mod nic;
mod server;

use std::fmt;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use binance_feed::Clock;
use zhida_netconf::Config;
use zhida_open::{open, OpenError, Opened};
use dpdk_smoltcp::Stack;

use args::{Args, Mode};

static STOP: AtomicBool = AtomicBool::new(false);

pub fn line(key: &str, value: impl fmt::Display) {
    let _ = writeln!(io::stdout(), "zhida-nic: {key}: {value}");
}

pub fn stopped() -> bool {
    STOP.load(Ordering::Relaxed)
}

extern "C" fn stop_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

fn signals() -> Result<(), String> {
    // SAFETY: sigaction is initialized with a C handler that only sets an atomic.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = stop_signal as *const () as usize;
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    for signal in [libc::SIGINT, libc::SIGTERM] {
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
            return Err(format!("sigaction: {}", io::Error::last_os_error()));
        }
    }
    Ok(())
}

#[derive(Default)]
pub struct Turns {
    received: u64,
    rejected: u64,
    ipv4_checksum_bad: u64,
    processed: u64,
    transmitted: u64,
    staged: usize,
    pending: usize,
    blocked_turns: u64,
}

impl Turns {
    pub fn turn(&mut self, stack: &mut Stack, clock: &Clock) -> Result<(), String> {
        let t = stack
            .turn(clock.now(), 32)
            .map_err(|e| format!("Stack::turn: {e}"))?;
        self.received += t.rx_received as u64;
        self.rejected += t.rx_rejected as u64;
        self.ipv4_checksum_bad += t.rx_ipv4_checksum_bad as u64;
        self.processed += t.rx_processed as u64;
        self.transmitted += t.tx_accepted as u64;
        self.staged = t.rx_staged;
        self.pending = t.tx_pending;
        self.blocked_turns += u64::from(t.rx_blocked);
        Ok(())
    }

    pub fn send(&mut self, stack: &mut Stack) -> Result<(), String> {
        let sent = stack.send().map_err(|e| format!("Stack::send: {e}"))?;
        self.transmitted += sent.tx_accepted as u64;
        self.pending = sent.tx_pending;
        Ok(())
    }

    pub fn flush(&mut self, stack: &mut Stack) -> Result<(), String> {
        let sent = stack.flush().map_err(|e| format!("Stack::flush: {e}"))?;
        self.transmitted += sent.tx_accepted as u64;
        self.pending = sent.tx_pending;
        Ok(())
    }

    fn print(&self) {
        line(
            "stack_totals",
            format_args!(
                "rx_received={} rx_rejected={} rx_ipv4_checksum_bad={} rx_processed={} tx_accepted={} rx_staged={} tx_pending={} rx_blocked_turns={}",
                self.received, self.rejected, self.ipv4_checksum_bad, self.processed, self.transmitted,
                self.staged, self.pending, self.blocked_turns
            ),
        );
    }
}

fn run(args: Args) -> i32 {
    let config = match Config::load(&args.config) {
        Ok(config) => config,
        Err(error) => {
            line("error", error);
            return 3;
        }
    };
    if matches!(args.mode, Mode::Feed(_)) && config.gateway.is_none() {
        line("error", "feed requires a gateway in the config");
        return 3;
    }
    let target = match &args.mode {
        Mode::Feed(f) => match feed::resolve(f) {
            Ok(t) => Some(t),
            Err(e) => {
                line("error", e);
                return 3;
            }
        },
        _ => None,
    };
    let feed_socket = target
        .as_ref()
        .map(|target| nic::feed_socket(&config, (*target.addr.ip()).into()));
    if let Err(e) = signals() {
        line("error", e);
        return 3;
    }
    let clock = Clock::new(Instant::now());
    let sizing = nic::sizing(&config, &args.mode, feed_socket.as_ref());
    if let Some(target) = &target {
        let cap = config.path_mtu((*target.addr.ip()).into())
            .checked_sub(40)
            .expect("path MTU exceeds TCP headers");
        line("feed_mss_cap", cap);
    }
    // SAFETY: EAL creates the configured PCI device or vdev from the config, so
    // the ethdev is new and no caller-attached ring exists. This sole thread
    // owns its queue pair and all packets. The selected PMD must honor Port's
    // mbuf contract and return its DMA/packet ownership at close. EAL never
    // deinitializes, so it outlives the Port.
    let opened = match unsafe { open(&config, &sizing, &mut || clock.now()) } {
        Ok(opened) => opened,
        Err(OpenError::PortOpen(error)) => {
            line("port_open_error", error.cause);
            if let Some(rollback) = error.rollback_error {
                line("port_rollback_error", rollback);
            }
            drop(error.retained);
            return 3;
        }
        Err(OpenError::Link {
            port_id,
            port,
            error,
        }) => {
            line("error", format_args!("link query: {error}"));
            if let Err(error) = nic::print_eth_stats(port_id) {
                line("error", error);
            }
            return nic::close(port, 3);
        }
        Err(OpenError::LinkDown {
            port_id,
            port,
            link: _,
        }) => {
            line("error", "link down after 10 seconds");
            if let Err(error) = nic::print_eth_stats(port_id) {
                line("error", error);
            }
            return nic::close(port, 3);
        }
        Err(OpenError::Stack { port, error }) => {
            line("error", format_args!("Stack::new: {error}"));
            return nic::close(port, 3);
        }
        Err(OpenError::Seed { port, error }) => {
            line("error", format_args!("OS random seed: {error}"));
            return nic::close(port, 3);
        }
        Err(OpenError::GatewayUnresolved {
            stack,
            gateway,
            waited,
        }) => {
            line(
                "error",
                format_args!("gateway {gateway} unresolved after {waited}"),
            );
            return nic::close(stack.into_port(), 3);
        }
        Err(OpenError::Receive { stack, error }) => {
            line("error", format_args!("gateway receive: {error}"));
            return nic::close(stack.into_port(), 3);
        }
        Err(error) => {
            line("error", error);
            return 3;
        }
    };
    let Opened {
        mut stack,
        eal: _eal,
        report,
    } = opened;
    for report_line in report.to_string().lines() {
        let _ = writeln!(io::stdout(), "zhida-nic: {report_line}");
    }
    let port_id = report.port_id;
    let rx_timestamps = report.offloads.offloads.rx_timestamp;
    let mut turns = Turns::default();
    let workload_start = Instant::now();
    let result = match &args.mode {
        Mode::Info => Ok(()),
        Mode::Server(s) => server::run(
            &mut stack,
            s,
            port_id,
            rx_timestamps,
            &mut turns,
            &clock,
            workload_start,
        ),
        Mode::Feed(f) => feed::run(
            &mut stack,
            f,
            target.as_ref().unwrap(),
            feed_socket.expect("feed mode has a socket"),
            &clock,
        ),
    };
    let mut code = 0;
    if let Err(e) = result {
        line("error", e);
        code = 3;
    }
    if !matches!(args.mode, Mode::Server(_)) {
        line("udp_counters", format_args!("{:?}", stack.udp_counters()));
    }
    if let Err(e) = nic::print_eth_stats(port_id) {
        line("error", e);
        code = 3;
    }
    nic::close(stack.into_port(), code)
}

fn main() {
    let args = match args::parse(std::env::args_os().skip(1)) {
        Ok(args) => args,
        Err(e) => {
            line("error", e);
            line("usage", args::USAGE);
            std::process::exit(3);
        }
    };
    std::process::exit(run(args));
}
