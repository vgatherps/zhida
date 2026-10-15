//! Many established TCP connections between a Pair's Stacks: connection `id`
//! is A's client on port `CLIENT_BASE + id` connected to its own B listener on
//! port `SERVER_BASE + id`, so no two listeners share a port and no tuple
//! repeats. Both ranges stay clear of `SERVER_PORT` and `CLIENT_PORT`.

use std::ops::Range;

use dpdk_smoltcp::smoltcp::socket::tcp::State;
use dpdk_smoltcp::smoltcp::wire::IpEndpoint;
use dpdk_smoltcp::{StackConfig, TcpHandle};

use crate::pair::{self, assert_lossless, tcp_socket_sized, App, Pair, Side};

/// Connections opened per wave, and the most frames a caller should have in
/// flight per direction per round: a Pair receiver takes one RX burst of 8
/// per turn, and its RX ring holds 15, so more would overflow it.
pub const WAVE: usize = 8;
pub const SERVER_BASE: u16 = 10_000;
pub const CLIENT_BASE: u16 = 30_000;
/// Connection ids stay below this, keeping both port ranges clear of
/// `SERVER_PORT` and `CLIENT_PORT`.
const MAX_ID: u16 = 19_000;

#[derive(Debug)]
pub struct Conn {
    pub id: u16,
    pub client: TcpHandle,
    pub server: TcpHandle,
}

/// `pair::config(side)` with `max_sockets` slots.
pub fn config(side: Side, max_sockets: usize) -> StackConfig<'static> {
    StackConfig {
        max_udp_sockets: 0,
        max_sockets,
        ..pair::config(side)
    }
}

/// Opens connections `ids` with `buffer`-byte socket buffers, `WAVE` at a
/// time: each wave's listeners and clients are added, then driven until all of
/// them are Established, with no frame dropped or held. Returns them in `ids`
/// order. The Stacks need a free slot per connection.
pub fn open(pair: &mut Pair, ids: Range<u16>, buffer: usize) -> Vec<Conn> {
    assert!(ids.end <= MAX_ID, "connection ids {ids:?} reach {MAX_ID}");
    let mut conns = Vec::with_capacity(ids.len());
    let ids: Vec<u16> = ids.collect();
    for wave in ids.chunks(WAVE) {
        let start = conns.len();
        for &id in wave {
            let server = pair.b.add_tcp(tcp_socket_sized(buffer)).unwrap();
            pair.b.listen(&server, SERVER_BASE + id).unwrap();
            let client = pair.a.add_tcp(tcp_socket_sized(buffer)).unwrap();
            let remote = IpEndpoint::new(Side::B.ip().into(), SERVER_BASE + id);
            pair.a.connect(&client, remote, CLIENT_BASE + id).unwrap();
            conns.push(Conn { id, client, server });
        }
        let wave = &conns[start..];
        pair.drive(
            |_, _| {},
            |a, b| {
                let established = wave.iter().all(|conn| {
                    a.tcp(&conn.client).state() == State::Established
                        && b.tcp(&conn.server).state() == State::Established
                });
                if established {
                    App::Done
                } else {
                    App::Idle
                }
            },
        );
        assert_lossless(&pair.a_to_b, "A→B");
        assert_lossless(&pair.b_to_a, "B→A");
    }
    conns
}

/// Every connection is Established with nothing queued either way, neither
/// Stack has a deadline, and a round at the current time moves no frame.
pub fn assert_quiet(pair: &mut Pair, conns: &[Conn]) {
    for conn in conns {
        for (stack, handle) in [(&mut pair.a, &conn.client), (&mut pair.b, &conn.server)] {
            let socket = stack.tcp(handle);
            assert_eq!(
                (socket.state(), socket.send_queue(), socket.recv_queue()),
                (State::Established, 0, 0),
                "connection {} at {handle:?}",
                conn.id
            );
        }
    }
    assert_eq!((pair.a.poll_at(), pair.b.poll_at()), (None, None));
    let round = pair.round(|dir, frame| panic!("quiet Pair sent {dir:?} {frame:02x?}"));
    assert_eq!((round.a_to_b, round.b_to_a), (0, 0));
}
