use dpdk_smoltcp::smoltcp::iface::PathMtu;
use dpdk_smoltcp::smoltcp::time::{Duration, Instant};
use dpdk_smoltcp::smoltcp::wire::{ArpOperation, EthernetAddress, Ipv4Address, Ipv4Cidr};
use dpdk_smoltcp::{
    tx_reserve, Port, Stack, StackConfig, StackError, Turn, DEFAULT_NEIGHBOR_CAPACITY,
};

use zhida_test_kit::{pair::tcp_socket_sized, ring_port, with_eal};
use ring_port::{arp, RingPort};

const OURS: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x01]);
const OUR_IP: Ipv4Address = Ipv4Address::new(10, 0, 0, 1);
const T: Instant = Instant::from_millis_const(10);

const IDLE: Turn = Turn {
    rx_received: 0,
    rx_rejected: 0,
    rx_ipv4_checksum_bad: 0,
    rx_processed: 0,
    rx_staged: 0,
    rx_blocked: false,
    tx_accepted: 0,
    tx_pending: 0,
};

fn peer(i: u8) -> (EthernetAddress, Ipv4Address) {
    (EthernetAddress([0x02, 0, 0, 0, 1, i]), Ipv4Address::new(10, 0, 0, 10 + i))
}

fn request(i: u8) -> Vec<u8> {
    arp(
        ArpOperation::Request,
        EthernetAddress::BROADCAST,
        peer(i),
        (EthernetAddress([0; 6]), OUR_IP),
    )
}

fn reply(i: u8) -> Vec<u8> {
    arp(ArpOperation::Reply, peer(i).0, (OURS, OUR_IP), peer(i))
}

fn requests(ids: std::ops::Range<u8>) -> Vec<Vec<u8>> {
    ids.map(request).collect()
}

fn replies(ids: std::ops::Range<u8>) -> Vec<Vec<u8>> {
    ids.map(reply).collect()
}

fn config(rx_staging: usize, tx_pending: usize) -> StackConfig<'static> {
    StackConfig {
        max_udp_sockets: 0,
        ethernet: OURS,
        ipv4: Ipv4Cidr::new(OUR_IP, 24),
        gateway: None,
        paths: &[],
        random_seed: 1,
        neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
        segments_per_visit: 1,
        max_sockets: 1,
        rx_staging,
        tx_pending,
    }
}

fn stack(port: Port, config: StackConfig<'_>) -> Stack {
    match Stack::new(port, config, T) {
        Ok(stack) => stack,
        Err((_, error)) => panic!("{error}"),
    }
}

/// Both rings already drained by the test; every buffer is back.
fn finish(fixture: RingPort, stack: Stack) {
    let port = stack.into_port();
    assert_eq!(fixture.in_use(), (0, 0));
    port.try_close().unwrap();
    fixture.close();
}

#[zhida_test_support::pinned_test]
fn backward_time_rejected_without_work() {
    with_eal(|eal| {
        // TX ring holds 3, so 2 of 5 replies stay pending.
        let fixture = RingPort::new("bk", 16, 4);
        let mut stack = stack(fixture.open(eal), config(8, 8));
        // `new`'s time is the first floor.
        let before_start = T - Duration::from_micros(1);
        assert_eq!(
            stack.turn(before_start, 8),
            Err(StackError::TimeWentBackwards { last: T, now: before_start })
        );

        let later = T + Duration::from_millis(10);
        fixture.inject(&requests(0..5));
        assert_eq!(
            stack.turn(later, 8),
            Ok(Turn {
                rx_received: 5,
                rx_processed: 5,
                tx_accepted: 3,
                tx_pending: 2,
                ..IDLE
            })
        );
        assert_eq!(fixture.take_tx(), replies(0..3));

        // The floor is now the latest turn's time, not `new`'s.
        fixture.inject(&[request(5)]);
        assert_eq!(fixture.in_use(), (1, 2));
        let between = T + Duration::from_millis(5);
        assert_eq!(
            stack.turn(between, 8),
            Err(StackError::TimeWentBackwards { last: later, now: between })
        );
        // No flush, no burst: TX ring empty, the frame still on the RX ring.
        assert!(fixture.take_tx().is_empty());
        assert_eq!(fixture.in_use(), (1, 2));

        assert_eq!(
            stack.turn(later, 8),
            Ok(Turn {
                rx_received: 1,
                rx_processed: 1,
                tx_accepted: 3,
                ..IDLE
            })
        );
        assert_eq!(fixture.take_tx(), replies(3..6));
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn same_time_turns_repeat_safely() {
    with_eal(|eal| {
        let fixture = RingPort::new("same", 16, 16);
        let mut stack = stack(fixture.open(eal), config(8, 8));
        for _ in 0..3 {
            assert_eq!(stack.turn(T, 8), Ok(IDLE));
        }
        fixture.inject(&[request(0)]);
        assert_eq!(
            stack.turn(T, 8),
            Ok(Turn {
                rx_received: 1,
                rx_processed: 1,
                tx_accepted: 1,
                ..IDLE
            })
        );
        assert_eq!(stack.turn(T, 8), Ok(IDLE));
        assert_eq!(fixture.take_tx(), [reply(0)]);
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn ingress_budget_bounds_processing_rest_staged() {
    with_eal(|eal| {
        let fixture = RingPort::new("budget", 16, 16);
        let mut stack = stack(fixture.open(eal), config(8, 8));
        fixture.inject(&requests(0..6));
        assert_eq!(
            stack.turn(T, 4),
            Ok(Turn {
                rx_received: 6,
                rx_processed: 4,
                rx_staged: 2,
                tx_accepted: 4,
                ..IDLE
            })
        );
        assert_eq!(fixture.take_tx(), replies(0..4));
        assert_eq!(fixture.in_use(), (2, 0));
        assert_eq!(
            stack.turn(T, 4),
            Ok(Turn {
                rx_processed: 2,
                tx_accepted: 2,
                ..IDLE
            })
        );
        assert_eq!(fixture.take_tx(), replies(4..6));
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn turn_flushes_pending_beyond_one_tx_burst() {
    with_eal(|eal| {
        // Six replies, bursts of two, a TX ring with room for all of them.
        let fixture = RingPort::new("multi", 16, 16);
        let port_config = dpdk_smoltcp::PortConfig {
            tx_burst: 2,
            ..fixture.config()
        };
        let mut stack = stack(fixture.open_with(eal, port_config), config(8, 8));
        fixture.inject(&requests(0..6));
        assert_eq!(
            stack.turn(T, 8),
            Ok(Turn {
                rx_received: 6,
                rx_processed: 6,
                tx_accepted: 6,
                ..IDLE
            })
        );
        assert_eq!(fixture.take_tx(), replies(0..6));
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn rx_flood_each_turn_finite() {
    with_eal(|eal| {
        // The RX ring holds 15; staging 4 and budget 2 bound every turn.
        let fixture = RingPort::new("flood", 16, 16);
        let mut stack = stack(fixture.open(eal), config(4, 4));
        fixture.inject(&vec![request(0); 15]);
        let mut expected = Turn {
            rx_received: 4,
            rx_processed: 2,
            rx_staged: 2,
            tx_accepted: 2,
            ..IDLE
        };
        for _ in 0..20 {
            let turn = stack.turn(T, 2).unwrap();
            assert_eq!(turn, expected);
            assert_eq!(fixture.take_tx().len(), 2);
            // Ring refilled to 15, plus 2 staged: nothing accumulates.
            fixture.inject(&vec![request(0); turn.rx_received]);
            assert_eq!(fixture.in_use(), (17, 0));
            expected.rx_received = 2;
        }
        // Stop the flood: the ring and staging drain at the same bounded pace.
        let mut left = 17u32;
        while left > 0 {
            let processed = left.min(2);
            let turn = stack.turn(T, 2).unwrap();
            assert!(turn.rx_received <= 2);
            assert_eq!(turn.rx_processed, processed as usize);
            assert_eq!(fixture.take_tx().len(), processed as usize);
            left -= processed;
            assert_eq!(fixture.in_use(), (left, 0));
        }
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn undrained_tx_ring_blocks_ingress_reports_rx_blocked_then_recovers() {
    with_eal(|eal| {
        // TX ring holds 3, pending holds 2: replies back up into staging.
        let fixture = RingPort::new("blocked", 16, 4);
        let mut stack = stack(fixture.open(eal), config(8, 2));
        fixture.inject(&requests(0..8));
        let blocked = Turn {
            rx_blocked: true,
            ..IDLE
        };
        assert_eq!(
            stack.turn(T, 8),
            Ok(Turn {
                rx_received: 8,
                rx_processed: 2,
                rx_staged: 6,
                tx_accepted: 2,
                ..blocked
            })
        );
        assert_eq!(
            stack.turn(T, 8),
            Ok(Turn {
                rx_processed: 2,
                rx_staged: 4,
                tx_accepted: 1,
                tx_pending: 1,
                ..blocked
            })
        );
        assert_eq!(
            stack.turn(T, 8),
            Ok(Turn {
                rx_processed: 1,
                rx_staged: 3,
                tx_pending: 2,
                ..blocked
            })
        );
        // The peer is not draining: every further turn is finite and idle.
        for _ in 0..3 {
            assert_eq!(
                stack.turn(T, 8),
                Ok(Turn {
                    rx_staged: 3,
                    tx_pending: 2,
                    ..blocked
                })
            );
        }
        assert_eq!(fixture.in_use(), (3, 5));

        assert_eq!(fixture.take_tx(), replies(0..3));
        assert_eq!(
            stack.turn(T, 8),
            Ok(Turn {
                rx_processed: 2,
                rx_staged: 1,
                tx_accepted: 3,
                tx_pending: 1,
                ..blocked
            })
        );
        assert_eq!(fixture.take_tx(), replies(3..6));
        assert_eq!(
            stack.turn(T, 8),
            Ok(Turn {
                rx_processed: 1,
                tx_accepted: 2,
                ..IDLE
            })
        );
        assert_eq!(fixture.take_tx(), replies(6..8));
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn invalid_config_returns_port() {
    with_eal(|eal| {
        let fixture = RingPort::new("invalid", 16, 16);
        let mut port = fixture.open(eal);
        let identity = format!("{port:?}");
        let valid = config(8, 8);
        let host_bits = [PathMtu { prefix: Ipv4Cidr::new(OUR_IP, 24), mtu: 1500 }];
        let duplicate = [PathMtu { prefix: Ipv4Cidr::new(OUR_IP, 32), mtu: 1500 }; 2];
        let too_small = [PathMtu { prefix: Ipv4Cidr::new(OUR_IP, 32), mtu: 87 }];
        let cases = [
            (StackConfig { paths: &host_bits, ..valid }, "path prefix has host bits set"),
            (StackConfig { paths: &duplicate, ..valid }, "duplicate path prefix"),
            (
                StackConfig { paths: &too_small, ..valid },
                "path MTU must be at least 88 (48-byte minimum TCP MSS + 40 bytes of headers)",
            ),
            (
                StackConfig {
                    max_udp_sockets: 0,
                    ethernet: EthernetAddress([0x01, 0, 0x5e, 0, 0, 1]),
                    ..valid
                },
                "Ethernet address must be unicast",
            ),
            (
                StackConfig {
                    max_udp_sockets: 0,
                    ethernet: EthernetAddress::BROADCAST,
                    ..valid
                },
                "Ethernet address must be unicast",
            ),
            (
                StackConfig {
                    max_udp_sockets: 0,
                    ipv4: Ipv4Cidr::new(Ipv4Address::BROADCAST, 24),
                    ..valid
                },
                "IPv4 address must be unicast",
            ),
            (
                StackConfig {
                    max_udp_sockets: 0,
                    ipv4: Ipv4Cidr::new(Ipv4Address::new(224, 0, 0, 1), 24),
                    ..valid
                },
                "IPv4 address must be unicast",
            ),
            (
                StackConfig {
                    max_udp_sockets: 0,
                    ipv4: Ipv4Cidr::new(Ipv4Address::UNSPECIFIED, 24),
                    ..valid
                },
                "IPv4 address must be unicast",
            ),
            (
                StackConfig {
                    max_udp_sockets: 0,
                    max_sockets: 0,
                    ..valid
                },
                "max_sockets must be positive",
            ),
            (
                StackConfig {
                    max_udp_sockets: 0,
                    rx_staging: 0,
                    ..valid
                },
                "rx_staging must be positive",
            ),
            (
                StackConfig {
                    max_udp_sockets: 0,
                    segments_per_visit: 0,
                    ..valid
                },
                "segments_per_visit must be positive",
            ),
            (
                StackConfig {
                    max_udp_sockets: 0,
                    tx_pending: 0,
                    ..valid
                },
                "tx_pending must be positive",
            ),
        ];
        for (config, reason) in cases {
            port = match Stack::new(port, config, T) {
                Err((port, error)) => {
                    assert_eq!(error, StackError::InvalidConfig(reason));
                    assert_eq!(format!("{port:?}"), identity);
                    port
                }
                Ok(_) => panic!("accepted invalid config: {reason}"),
            };
        }
        let before_zero = Instant::ZERO - Duration::from_micros(1);
        port = match Stack::new(port, valid, before_zero) {
            Err((port, error)) => {
                assert_eq!(error, StackError::InvalidConfig("start time must be >= 0"));
                assert_eq!(format!("{port:?}"), identity);
                port
            }
            Ok(_) => panic!("accepted negative start time"),
        };
        // Still a working Port: the valid config builds a Stack on it.
        let stack = stack(port, valid);
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn stack_new_refuses_tx_pool_below_reserve() {
    with_eal(|eal| {
        assert_eq!(tx_reserve(16, 8), 24);
        for count in [23, 24] {
            let fixture = RingPort::new("mintx", 16, 16);
            let mut port_config = fixture.config();
            port_config.tx_pool.count = count;
            let port = fixture.open_with(eal, port_config);
            assert_eq!(port.descriptor_counts().1, 16);
            let identity = format!("{port:?}");
            match Stack::new(port, config(8, 8), T) {
                Err((port, error)) => {
                    assert_eq!(count, 23);
                    assert_eq!(error, StackError::TxPoolTooSmall { count: 23, required: 24 });
                    assert_eq!(format!("{port:?}"), identity);
                    assert_eq!(fixture.in_use(), (0, 0));
                    port.try_close().unwrap();
                    fixture.close();
                }
                Ok(stack) => {
                    assert_eq!(count, 24);
                    finish(fixture, stack);
                }
            }
        }
    });
}

/// Below 68 Stack::new refuses the IPv4 minimum itself; 68-87 reaches the path table, which needs
/// room for a 48-byte TCP segment; 88 builds.
#[zhida_test_support::pinned_test]
fn stack_new_refuses_ip_mtu_below_88() {
    with_eal(|eal| {
        for mtu in [67, 87, 88] {
            let fixture = RingPort::new("minmtu", 16, 16);
            let mut port_config = fixture.config();
            port_config.mtu = mtu;
            let port = fixture.open_with(eal, port_config);
            let identity = format!("{port:?}");
            match Stack::new(port, config(8, 8), T) {
                Err((port, error)) => {
                    let expected = match mtu {
                        67 => StackError::IpMtuBelowIpv4Minimum { mtu: 67 },
                        87 => StackError::InvalidConfig(
                            "port IP MTU must be at least 88 (48-byte minimum TCP MSS + 40 bytes of headers)",
                        ),
                        _ => panic!("MTU {mtu} refused: {error:?}"),
                    };
                    assert_eq!(error, expected);
                    assert_eq!(format!("{port:?}"), identity);
                    assert_eq!(fixture.in_use(), (0, 0));
                    port.try_close().unwrap();
                    fixture.close();
                }
                Ok(stack) => {
                    assert_eq!(mtu, 88);
                    finish(fixture, stack);
                }
            }
        }
    });
}

/// A gateway that is not another unicast host address inside the subnet
/// returns the Port unchanged; a /31 has no network or broadcast address, so
/// both its addresses are hosts. A valid gateway builds, and the first connect
/// outside the subnet asks ARP for the gateway, not the destination.
#[zhida_test_support::pinned_test]
fn gateway_must_be_another_unicast_address_in_the_subnet() {
    with_eal(|eal| {
        let fixture = RingPort::new("gateway", 16, 16);
        let mut port = fixture.open(eal);
        let identity = format!("{port:?}");
        let ours = Ipv4Address::new(192, 0, 2, 2);
        let off_subnet = Ipv4Address::new(198, 51, 100, 1);
        let with_gateway = |gateway| StackConfig {
            max_udp_sockets: 0,
            ipv4: Ipv4Cidr::new(ours, 24),
            gateway: Some(gateway),
            ..config(8, 8)
        };
        let cases = [
            (ours, "gateway must not be our IPv4 address"),
            (off_subnet, "gateway must be inside the IPv4 subnet"),
            (Ipv4Address::BROADCAST, "gateway must be unicast"),
            (Ipv4Address::new(224, 0, 0, 1), "gateway must be unicast"),
            (Ipv4Address::UNSPECIFIED, "gateway must be unicast"),
            (
                Ipv4Address::new(192, 0, 2, 0),
                "gateway must not be the subnet's network address",
            ),
            (
                Ipv4Address::new(192, 0, 2, 255),
                "gateway must not be the subnet's broadcast address",
            ),
        ];
        for (gateway, reason) in cases {
            port = match Stack::new(port, with_gateway(gateway), T) {
                Err((port, error)) => {
                    assert_eq!(error, StackError::InvalidConfig(reason));
                    assert_eq!(format!("{port:?}"), identity);
                    port
                }
                Ok(_) => panic!("accepted gateway {gateway}: {reason}"),
            };
        }
        let point_to_point = StackConfig {
            max_udp_sockets: 0,
            ipv4: Ipv4Cidr::new(Ipv4Address::new(192, 0, 2, 1), 31),
            gateway: Some(Ipv4Address::new(192, 0, 2, 0)),
            ..config(8, 8)
        };
        let port = stack(port, point_to_point).into_port();
        let gateway = Ipv4Address::new(192, 0, 2, 1);
        let mut stack = stack(port, with_gateway(gateway));
        let socket = stack.add_tcp(tcp_socket_sized(4096)).unwrap();
        stack.connect(&socket, (off_subnet, 80), 49152).unwrap();
        assert_eq!(
            stack.turn(T, 8),
            Ok(Turn {
                tx_accepted: 1,
                ..IDLE
            })
        );
        assert_eq!(
            fixture.take_tx(),
            vec![arp(
                ArpOperation::Request,
                EthernetAddress::BROADCAST,
                (OURS, ours),
                (EthernetAddress::BROADCAST, gateway),
            )]
        );
        finish(fixture, stack);
    });
}

#[zhida_test_support::pinned_test]
fn stack_drop_releases_queues_before_port_close() {
    with_eal(|eal| {
        // TX ring holds 3; budget 4 leaves 2 staged and 1 pending.
        let fixture = RingPort::new("drop", 16, 4);
        let mut stack = stack(fixture.open(eal), config(8, 4));
        fixture.inject(&requests(0..3));
        fixture.inject_foreign(&request(3));
        fixture.inject(&requests(4..7));
        assert_eq!(
            stack.turn(T, 4),
            Ok(Turn {
                rx_received: 6,
                rx_rejected: 1,
                rx_processed: 4,
                rx_staged: 2,
                tx_accepted: 3,
                tx_pending: 1,
                ..IDLE
            })
        );
        assert_eq!(fixture.take_tx(), vec![reply(0), reply(1), reply(2)]);
        assert_eq!(fixture.in_use(), (2, 1));
        // Implicit drop: Port cleanup releases both pools only if every staged
        // and pending packet already returned.
        drop(stack);
        assert!(!fixture.pools_exist());
        fixture.close();
    });
}
