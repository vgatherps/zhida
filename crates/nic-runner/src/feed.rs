use std::io::Read;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use binance_feed::{connect, webpki_client_config, Clock, Target};
use dpdk_smoltcp::{smoltcp::socket::tcp, Stack};

use crate::args::Feed;
use crate::{line, stopped};

pub fn resolve(args: &Feed) -> Result<Target, String> {
    let mut addresses = (args.host.as_str(), args.port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS {}: {e}", args.host))?;
    let addr = addresses
        .find_map(|a| match a {
            SocketAddr::V4(a) => Some(a),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("DNS {} has no IPv4 address", args.host))?;
    line("resolved", format_args!("{} -> {addr}", args.host));
    Ok(Target {
        addr,
        host: args.host.clone(),
        path: args.path.clone(),
    })
}

pub fn run(
    stack: &mut Stack,
    args: &Feed,
    target: &Target,
    socket: tcp::Config,
    clock: &Clock,
) -> Result<(), String> {
    let mut bytes = [0; 2];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| format!("local port entropy: {e}"))?;
    let local_port = 49152 + u16::from_ne_bytes(bytes) % (u16::MAX - 49152 + 1);
    let mut feed = connect(
        stack,
        clock,
        target,
        socket,
        webpki_client_config(),
        local_port,
        Duration::from_secs(20),
    )
    .map_err(|e| e.to_string())?;
    line(
        "feed_connected",
        format_args!(
            "{} local_port={local_port} {}",
            target.url(),
            feed.tls_summary()
        ),
    );
    let run_start = Instant::now();
    let mut stop = || stopped() || run_start.elapsed() >= Duration::from_secs(args.seconds);
    let mut count = 0u64;
    let mut first = None;
    let mut last = None;
    let read: Result<(), String> = (|| {
        while let Some(ticker) = feed.next(clock, &mut stop).map_err(|e| e.to_string())? {
            count += 1;
            if first.is_none() {
                first = Some(ticker.update_id);
            }
            last = Some(ticker.update_id);
            if count <= args.print as u64 {
                line("feed_message", format_args!("#{count} {ticker}"));
            }
        }
        Ok(())
    })();
    line("feed_count", count);
    match (first, last) {
        (Some(first), Some(last)) => line("feed_update_ids", format_args!("{first}..{last}")),
        _ => line("feed_update_ids", "none"),
    }
    let closed = feed
        .close(clock, Duration::from_secs(10))
        .map_err(|e| e.to_string());
    if let Ok(state) = &closed {
        line("feed_close", state);
    }
    if read.is_err() {
        if let Err(e) = &closed {
            line("feed_close_error", e);
        }
    }
    read?;
    closed?;
    if count == 0 {
        return Err("no bookTicker message received".into());
    }
    Ok(())
}
