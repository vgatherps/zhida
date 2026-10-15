//! `serve` over a net_ring Port.

use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::smoltcp::wire::{EthernetAddress, Ipv4Address, Ipv4Cidr};
use dpdk_smoltcp::{Stack, StackConfig, StackError, DEFAULT_NEIGHBOR_CAPACITY};
use tap_echo::{serve, EchoServer};

use zhida_test_kit::{ring_port, with_eal};
use ring_port::RingPort;

#[zhida_test_support::pinned_test]
fn serve_returns_time_went_backwards_when_the_stack_starts_ahead_of_the_clock() {
    with_eal(|eal| {
        let fixture = RingPort::new("srvback", 16, 16);
        let config = StackConfig {
            max_udp_sockets: 0,
            ethernet: EthernetAddress([0x02, 0, 0, 0, 0, 0x01]),
            ipv4: Ipv4Cidr::new(Ipv4Address::new(10, 0, 0, 1), 24),
            gateway: None,
            paths: &[],
            random_seed: 1,
            neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
            segments_per_visit: 1,
            max_sockets: 1,
            rx_staging: 8,
            tx_pending: 8,
        };
        // An hour ahead of a wall clock that starts now.
        let ahead = Instant::from_secs(3600);
        let start = std::time::Instant::now();
        let mut stack = match Stack::new(fixture.open(eal), config, ahead) {
            Ok(stack) => stack,
            Err((_, error)) => panic!("{error}"),
        };
        let mut echo = EchoServer::new(&mut stack, 7, 1, 4096).unwrap();

        let mut stops = 0;
        let result = serve(&mut stack, &mut echo, start, |_, _| {
            stops += 1;
            true
        });
        match result {
            Err(StackError::TimeWentBackwards { last, now }) => {
                assert_eq!(last, ahead);
                assert!(now < ahead, "{now} not before {ahead}");
            }
            other => panic!("expected TimeWentBackwards, got {other:?}"),
        }
        assert_eq!(stops, 0, "stop ran although the first turn failed");

        drop(echo);
        let port = stack.into_port();
        assert_eq!(fixture.in_use(), (0, 0));
        port.try_close().unwrap();
        fixture.close();
    });
}
