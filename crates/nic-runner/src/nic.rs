use dpdk_smoltcp::smoltcp::{socket::tcp, wire::Ipv4Address};
use dpdk_smoltcp::{Port, PortError, DEFAULT_NEIGHBOR_CAPACITY};
use zhida_dpdk_sys::{rte_eth_stats, rte_eth_stats_get};

use crate::args::Mode;
use crate::line;
use zhida_open::Sizing;
use sockperf_wire::sockperf::MAX_MESSAGE;

pub const STAGING: usize = 32;
pub const UDP_QUEUE: usize = 32;
pub fn feed_socket(config: &zhida_netconf::Config, ip: Ipv4Address) -> tcp::Config {
    let cap = config.path_mtu(ip)
        .checked_sub(40)
        .expect("path MTU exceeds TCP headers");
    binance_feed::socket(Some(cap))
}

pub fn sizing(
    config: &zhida_netconf::Config,
    mode: &Mode,
    feed: Option<&tcp::Config>,
) -> Sizing {
    let (tcp, udp, bytes) = match mode {
        Mode::Info => (0, 0, MAX_MESSAGE),
        Mode::Server(s) => (
            if s.tcp_port.is_some() {
                s.tcp_connections
            } else {
                0
            },
            s.udp_ports.len(),
            MAX_MESSAGE,
        ),
        Mode::Feed(_) => (1, 0, binance_feed::SOCKET_BUFFER),
    };
    Sizing {
        tcp_rx_frames: match mode {
            Mode::Feed(_) => tcp::rx_mbuf_budget(
                feed.expect("feed mode has a config"), usize::from(config.mtu)),
            _ => tcp
                .checked_mul(tcp::rx_mbuf_budget(&tcp::Config {
                    rx_capacity: bytes, tx_capacity: bytes, mss_cap: None,
                }, usize::from(config.mtu)))
                .expect("TCP RX frame budget overflow"),
        },
        udp_rx_datagrams: udp.checked_mul(UDP_QUEUE).expect("UDP RX budget overflow"),
        max_sockets: tcp.max(1),
        max_udp_sockets: udp,
        rx_staging: STAGING,
        tx_pending: STAGING.max(tcp),
        segments_per_visit: 1,
        neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
    }
}

pub fn eth_stats(port_id: u16) -> Result<rte_eth_stats, String> {
    // SAFETY: the ethdev remains open and stats is a writable output.
    let mut stats: rte_eth_stats = unsafe { std::mem::zeroed() };
    let rc = unsafe { rte_eth_stats_get(port_id, &mut stats) };
    if rc != 0 {
        return Err(format!("rte_eth_stats_get: {rc}"));
    }
    Ok(stats)
}

pub fn print_eth_stats(port_id: u16) -> Result<(), String> {
    let s = eth_stats(port_id)?;
    line(
        "eth_stats",
        format_args!(
            "ipackets={} opackets={} imissed={} ierrors={} oerrors={} rx_nombuf={}",
            s.ipackets, s.opackets, s.imissed, s.ierrors, s.oerrors, s.rx_nombuf
        ),
    );
    Ok(())
}

pub fn close(port: Port, mut code: i32) -> i32 {
    match port.try_close() {
        Ok(()) => line("port_close", "ok"),
        Err((port, PortError::OutstandingBuffers { rx, tx })) => {
            line(
                "port_close",
                format_args!("buffers still in use: rx={rx} tx={tx}"),
            );
            code = 2;
            drop(port);
        }
        Err((port, error)) => {
            line("port_close", error);
            code = 3;
            drop(port);
        }
    }
    code
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use dpdk_smoltcp::{rx_pool_count, rx_reserve};

    use super::{feed_socket, sizing, STAGING, UDP_QUEUE};
    use crate::args::Args;

    fn parsed(args: &[&str]) -> Args {
        crate::args::parse(args.iter().map(OsString::from)).unwrap()
    }

    #[test]
    fn sizing_matches_rx_pool_count() {
        for (args, tcp, udp, bytes) in [
            (
                &["--config", "nic.json", "info"][..],
                0,
                0,
                sockperf_wire::sockperf::MAX_MESSAGE,
            ),
            (
                &[
                    "--config",
                    "nic.json",
                    "sockperf-server",
                    "--tcp-port",
                    "1",
                    "--tcp-connections",
                    "64",
                    "--udp-ports",
                    "11111,11112",
                ][..],
                64,
                2,
                sockperf_wire::sockperf::MAX_MESSAGE,
            ),
            (
                &["--config", "nic.json", "feed"][..],
                1,
                0,
                binance_feed::SOCKET_BUFFER,
            ),
        ] {
            let args = parsed(args);
            for mtu in [1500, 9000] {
                let config = test_config(mtu, "[]");
                let socket = feed_socket(&config, "203.0.113.1".parse().unwrap());
                let sizing = sizing(&config, &args.mode, Some(&socket));
                let reserve = rx_reserve(config.descriptors, STAGING, 8) + udp * UDP_QUEUE;
                let old = rx_pool_count(reserve, mtu, std::iter::repeat(bytes).take(tcp));
                let new = rx_reserve(config.descriptors, sizing.rx_staging, 8)
                    + sizing.udp_rx_datagrams
                    + sizing.tcp_rx_frames;
                assert_eq!(u32::try_from(new).unwrap(), old);
            }
        }
    }

    #[test]
    fn feed_sizing_uses_path_capped_budget() {
        let config = test_config(
            9000,
            r#"[{"prefix":"203.0.113.0/24","mtu":1500,"why":"feed path"}]"#,
        );
        let args = parsed(&["--config", "nic.json", "feed"]);
        let ip = "203.0.113.1".parse().unwrap();
        assert_eq!(config.path_mtu(ip).checked_sub(40).unwrap(), 1460);
        let socket = feed_socket(&config, ip);
        let capped = dpdk_smoltcp::smoltcp::socket::tcp::rx_mbuf_budget(&socket, 9000);
        let uncapped = dpdk_smoltcp::smoltcp::socket::tcp::rx_mbuf_budget(
            &binance_feed::socket(None), 9000,
        );
        assert_eq!(capped, 180);
        assert_eq!(uncapped, 30);
        assert_eq!(sizing(&config, &args.mode, Some(&socket)).tcp_rx_frames, capped);
        assert!(capped > uncapped);

        let socket = feed_socket(&config, "203.0.114.1".parse().unwrap());
        assert_eq!(sizing(&config, &args.mode, Some(&socket)).tcp_rx_frames, uncapped);
    }

    fn test_config(mtu: u16, paths: &str) -> zhida_netconf::Config {
        zhida_netconf::Config::from_json(&format!(
            r#"{{"version":1,"device":{{"vdev":"net_tap0,iface=cdnic0"}},"mac":null,"ipv4":"192.0.2.2/24","gateway":null,"mtu":{mtu},"paths":{paths},"offloads":"auto","rx_timestamps":false,"descriptors":1024,"eal":{{"file_prefix":"test","extra":[]}}}}"#
        ))
        .unwrap()
    }
}
