use std::path::Path;

use dpdk_smoltcp::DEFAULT_NEIGHBOR_CAPACITY;
use dpdk_smoltcp::smoltcp::socket::tcp;
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::smoltcp::wire::Ipv4Address;

fn setup() -> Result<(), Box<dyn std::error::Error>> {
    let config = zhida_netconf::Config::load(Path::new("dut.json"))?;
    let server = Ipv4Address::new(192, 0, 2, 1);
    let tcp_config = tcp::Config {
        rx_capacity: 65536,
        tx_capacity: 65536,
        mss_cap: Some(config.path_mtu(server) - 40),
    };
    let sizing = zhida_open::Sizing {
        tcp_rx_frames: tcp::rx_mbuf_budget(&tcp_config, usize::from(config.mtu)),
        udp_rx_datagrams: 0,
        max_sockets: 1,
        max_udp_sockets: 0,
        rx_staging: 32,
        tx_pending: 32,
        segments_per_visit: 1,
        neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
    };
    let start = std::time::Instant::now();
    let mut clock = || Instant::from_micros(i64::try_from(start.elapsed().as_micros()).unwrap());
    let opened = unsafe { zhida_open::open(&config, &sizing, &mut clock) }?;
    println!("{}", opened.report);
    let (mut stack, _eal) = (opened.stack, opened.eal);
    let handle = stack.add_tcp(tcp_config)?;
    stack.connect(&handle, (server, 7000), 40000)?;
    // then the drive loop; keep `_eal` alive until the Port is closed
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    setup()
}
