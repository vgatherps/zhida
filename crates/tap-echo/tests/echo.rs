//! EchoServer on Stack B, client sockets on Stack A, over net_ring Ports
//! joined by copying links.

use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::phy::ChecksumCapabilities;
use dpdk_smoltcp::smoltcp::socket::tcp::{
    self, ListenError, State,
};
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::smoltcp::wire::{
    ArpOperation, EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, IpAddress,
    IpEndpoint, IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
    TcpTimestampRepr,
};
use dpdk_smoltcp::{rx_pool_count, rx_reserve, Eal, Stack, StackConfig};
use tap_echo::{EchoError, EchoServer};

use zhida_test_kit::{pair, ring_port, with_eal};
use pair::{assert_lossless, pattern, segment, App, Dir, Pair, Side, CLIENT_PORT, T0};
use ring_port::{arp, RingPort};

const ECHO_PORT: u16 = 7;

/// Side `side`'s kit config with `max_sockets` sockets.
fn config(side: Side, max_sockets: usize) -> StackConfig<'static> {
    StackConfig {
        max_udp_sockets: 0,

        max_sockets,
        ..pair::config(side)
    }
}

fn server_endpoint() -> IpEndpoint {
    IpEndpoint::new(Side::B.ip().into(), ECHO_PORT)
}

/// A holds `clients` sockets, B `servers`.
fn new_pair(eal: &Eal, names: [&str; 2], clients: usize, servers: usize) -> Pair {
    Pair::new(eal, names, [config(Side::A, clients), config(Side::B, servers)], T0)
}

/// No link lost or held a frame and no frame is left on a ring, then the Pair
/// closes. Every Pair test here runs no round, or ends its last drive in or
/// after the round whose B turn took the clients' last segment: the ACK of B's
/// FIN, which takes B's socket from LastAck to Closed and which B does not
/// answer; B then listens. Clients in TimeWait send nothing more, even while
/// they read echo bytes still buffered (echo_drains_before_closing_after_peer_fin):
/// smoltcp sends window updates only up to FinWait2 (window_to_update,
/// socket/tcp.rs 2415-2429). A's output in a round is forwarded and taken by
/// B's turn in that same round, so nothing is in flight when the drive ends.
fn close(pair: Pair) {
    assert_lossless(&pair.a_to_b, "A→B");
    assert_lossless(&pair.b_to_a, "B→A");
    assert_eq!(pair.close(), 0, "frames left on the rings");
}

/// Call sizes 1..=1500 in a fixed pseudo-random sequence.
fn chunk(call: usize) -> usize {
    call.wrapping_mul(7919) % 1500 + 1
}

/// Connects a fresh client socket with `rx`/`tx` byte buffers from `local`.
fn connect(stack: &mut Stack, local: u16, rx: usize, tx: usize) -> TcpHandle {
    let socket = tcp::Config { rx_capacity: rx, tx_capacity: tx, mss_cap: None };
    let handle = stack.add_tcp(socket).unwrap();
    stack.connect(&handle, server_endpoint(), local).unwrap();
    handle
}

/// Sends `data` in varying call sizes and collects what comes back.
struct Client<'h> {
    handle: &'h TcpHandle,
    data: Vec<u8>,
    written: usize,
    echoed: Vec<u8>,
    calls: usize,
    pending: Option<(tcp::TcpFrame, usize)>,
}

impl<'h> Client<'h> {
    fn new(handle: &'h TcpHandle, data: Vec<u8>) -> Self {
        let echoed = Vec::with_capacity(data.len());
        Self {
            handle,
            data,
            written: 0,
            echoed,
            calls: 0,
            pending: None,
        }
    }

    /// Sends one chunk; true if it moved bytes.
    fn write(&mut self, stack: &mut Stack) -> bool {
        let socket = stack.tcp_mut(&self.handle);
        if !socket.may_send() || self.written == self.data.len() {
            return false;
        }
        self.calls += 1;
        let end = self.data.len().min(self.written + chunk(self.calls));
        let sent = socket.send_slice(&self.data[self.written..end]).unwrap();
        self.written += sent;
        sent > 0
    }

    /// Reads one chunk; true if it moved bytes.
    fn read(&mut self, stack: &mut Stack) -> bool {
        let socket = stack.tcp_mut(&self.handle);
        if self.pending.is_none() && !socket.may_recv() {
            return false;
        }
        self.calls += 1;
        let mut buffer = [0; 1500];
        let limit = chunk(self.calls);
        let mut read = 0usize;
        while read < limit {
            if self.pending.is_none() {
                if !socket.can_recv() { break; }
                let Some(frame) = socket.recv().unwrap() else { break; };
                self.pending = Some((frame, 0));
            }
            let (frame, offset) = self.pending.as_mut().unwrap();
            let n = (limit - read).min(frame.payload().len() - *offset);
            buffer[read..read + n].copy_from_slice(&frame.payload()[*offset..*offset + n]);
            *offset = offset.checked_add(n).expect("frame offset exceeds usize");
            read = read.checked_add(n).expect("read count exceeds usize");
            if *offset == frame.payload().len() {
                self.pending = None;
            }
        }
        self.echoed.extend_from_slice(&buffer[..read]);
        read > 0
    }

    fn echoed_all(&self) -> bool {
        self.echoed.len() >= self.data.len()
    }

    fn assert_echoed(&self) {
        assert_eq!(
            (self.written, self.echoed.len()),
            (self.data.len(), self.data.len())
        );
        assert!(self.echoed == self.data, "echoed bytes differ");
    }
}

fn progress(moved: bool) -> App {
    if moved {
        App::Moved
    } else {
        App::Idle
    }
}

/// Clients write and read while the server echoes, until every client has
/// its whole stream back.
fn echo_all(pair: &mut Pair, server: &mut EchoServer, clients: &mut [Client]) {
    pair.drive(
        |_, _| {},
        |a, b| {
            let mut moved = server.step(b);
            for client in clients.iter_mut() {
                moved |= client.write(a);
                moved |= client.read(a);
            }
            if clients.iter().all(Client::echoed_all) {
                App::Done
            } else {
                progress(moved)
            }
        },
    );
    for client in clients.iter() {
        client.assert_echoed();
    }
}

/// Every client closes and reads to the server's FIN, nothing more arriving;
/// done once clients are TimeWait and every server socket listens again.
/// Returns each server socket's states, deduplicated, as seen before `step`.
fn close_all(
    pair: &mut Pair,
    server: &mut EchoServer,
    clients: &[&TcpHandle],
) -> Vec<Vec<State>> {
    let mut seen: Vec<Vec<State>> = vec![Vec::new(); server.handles().len()];
    for handle in clients {
        pair.a.tcp_mut(&handle).close();
    }
    pair.drive(
        |_, _| {},
        |a, b| {
            for (states, handle) in seen.iter_mut().zip(server.handles()) {
                let state = b.tcp(&handle).state();
                if states.last() != Some(&state) {
                    states.push(state);
                }
            }
            let moved = server.step(b);
            for handle in clients {
                let socket = a.tcp_mut(&handle);
                if socket.may_recv() {
                    assert!(socket.recv().unwrap().is_none());
                }
            }
            let clients_done = clients
                .iter()
                .all(|handle| a.tcp(&handle).state() == State::TimeWait);
            let servers_listen = server
                .handles()
                .iter()
                .all(|handle| b.tcp(&handle).state() == State::Listen);
            if clients_done && servers_listen {
                App::Done
            } else {
                progress(moved)
            }
        },
    );
    seen
}

/// The server socket closed after the client's FIN (FIN out, last ACK in)
/// and listens again; samples after it relistened, if the drive went on, are
/// Listen. Sampling cannot skip a state: `step` closes in one round, B's FIN
/// goes out in a later round's B turn and its ACK reaches B a round after that.
fn assert_closed_then_listens(states: &[State]) {
    let closing = match states.iter().rposition(|&state| state != State::Listen) {
        Some(last) => &states[..=last],
        None => &[],
    };
    assert!(
        closing.ends_with(&[State::CloseWait, State::LastAck, State::Closed]),
        "{states:?}"
    );
}

#[zhida_test_support::pinned_test]
fn echo_returns_exact_stream_and_relistens() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["e1a", "e1b"], 2, 1);
        let mut server = EchoServer::new(&mut pair.b, ECHO_PORT, 1, 4096).unwrap();
        let listener = format!("{:?}", server.handles()[0]);
        assert_eq!(pair.b.tcp(&server.handles()[0]).state(), State::Listen);

        let first = connect(&mut pair.a, CLIENT_PORT, 4096, 4096);
        let mut clients = [Client::new(&first, pattern(64 * 1024, 1))];
        echo_all(&mut pair, &mut server, &mut clients);
        let seen = close_all(&mut pair, &mut server, &[&first]);
        assert_closed_then_listens(&seen[0]);

        let second = connect(&mut pair.a, CLIENT_PORT + 1, 4096, 4096);
        let mut clients = [Client::new(&second, pattern(8 * 1024, 2))];
        echo_all(&mut pair, &mut server, &mut clients);
        let seen = close_all(&mut pair, &mut server, &[&second]);
        assert_eq!(server.handles().len(), 1);
        assert_eq!(format!("{:?}", server.handles()[0]), listener);
        assert_closed_then_listens(&seen[0]);
        close(pair);
    });
}

#[zhida_test_support::pinned_test]
fn echo_never_drops_bytes_when_send_buffer_is_full() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["e2a", "e2b"], 1, 1);
        let mut server = EchoServer::new(&mut pair.b, ECHO_PORT, 1, 1024).unwrap();
        let handle = connect(&mut pair.a, CLIENT_PORT, 4096, 4096);
        let mut client = Client::new(&handle, pattern(16 * 1024, 3));
        // Write only, until the client can store no more echo bytes, its send
        // buffer is full and the server's send buffer is full: the server
        // holds echo bytes it cannot send. The client's room can reach 0
        // before 4096 unread bytes, since each unread echo segment holds an
        // RX mbuf and the socket may hold six. 32 rounds in a row that
        // neither write a byte nor change an echo socket fail.
        let mut quiet = 0;
        pair.drive(
            |_, _| {},
            |a, b| {
                let moved = server.step(b) | client.write(a);
                let client_socket = a.tcp(&handle);
                let client_state = (
                    client_socket.recv_room(),
                    client_socket.recv_queue(),
                    client_socket.send_queue(),
                );
                let client_full =
                    client_state.0 == 0 && client_state.2 == client_socket.send_capacity();
                let server_socket = b.tcp(&server.handles()[0]);
                let server_queue = server_socket.send_queue();
                if client_full && server_queue == server_socket.send_capacity() {
                    return App::Done;
                }
                quiet = if moved { 0 } else { quiet + 1 };
                assert!(
                    quiet < 32,
                    "buffers not full: client (recv room, recv, send) {client_state:?}, server \
                     send {server_queue}"
                );
                progress(moved)
            },
        );
        assert!(client.written < client.data.len(), "{}", client.written);

        let mut clients = [client];
        echo_all(&mut pair, &mut server, &mut clients);
        close_all(&mut pair, &mut server, &[&handle]);
        close(pair);
    });
}

#[zhida_test_support::pinned_test]
fn echo_drains_before_closing_after_peer_fin() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["e3a", "e3b"], 1, 1);
        let mut server = EchoServer::new(&mut pair.b, ECHO_PORT, 1, 1024).unwrap();
        let data = pattern(8 * 1024, 4);
        let handle = connect(&mut pair.a, CLIENT_PORT, 4096, 8192);

        // Established first: send_slice needs it.
        pair.drive(
            |_, _| {},
            |a, b| {
                let moved = server.step(b);
                if a.tcp(&handle).state() == State::Established {
                    App::Done
                } else {
                    progress(moved)
                }
            },
        );
        let socket = pair.a.tcp_mut(&handle);
        assert_eq!(socket.send_slice(&data).unwrap(), data.len());
        socket.close();

        // The client reads 64 bytes a round, so the server's send buffer stays
        // full and the FIN arrives with echo bytes still in its receive buffer.
        let mut echoed = Vec::new();
        let mut states = Vec::new();
        let mut fin_with_bytes_pending = false;
        let mut pending = None;
        pair.drive(
            |_, _| {},
            |a, b| {
                let socket = b.tcp(&server.handles()[0]);
                let state = socket.state();
                fin_with_bytes_pending |= state == State::CloseWait && socket.recv_queue() > 0;
                if states.last() != Some(&state) {
                    states.push(state);
                }
                let mut moved = server.step(b);
                let socket = a.tcp_mut(&handle);
                if pending.is_some() || socket.may_recv() {
                    let mut buffer = [0; 64];
                    let mut read = 0usize;
                    while read < buffer.len() {
                        if pending.is_none() {
                            if !socket.can_recv() { break; }
                            let Some(frame) = socket.recv().unwrap() else { break; };
                            pending = Some((frame, 0));
                        }
                        let (frame, offset) = pending.as_mut().unwrap();
                        let n = (buffer.len() - read).min(frame.payload().len() - *offset);
                        buffer[read..read + n].copy_from_slice(&frame.payload()[*offset..*offset + n]);
                        *offset = offset.checked_add(n).expect("frame offset exceeds usize");
                        read = read.checked_add(n).expect("read count exceeds usize");
                        if *offset == frame.payload().len() {
                            pending = None;
                        }
                    }
                    echoed.extend_from_slice(&buffer[..read]);
                    moved |= read > 0;
                }
                let server_listens = b.tcp(&server.handles()[0]).state() == State::Listen;
                if pending.is_none() && !a.tcp(&handle).may_recv() && server_listens {
                    App::Done
                } else {
                    progress(moved)
                }
            },
        );
        assert!(fin_with_bytes_pending);
        assert_eq!(echoed.len(), data.len());
        assert!(echoed == data, "echoed bytes differ");
        assert_eq!(pair.a.tcp(&handle).state(), State::TimeWait);
        assert_closed_then_listens(&states);
        close(pair);
    });
}

#[zhida_test_support::pinned_test]
fn echo_serves_concurrent_connections_up_to_listener_count() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["e4a", "e4b"], 4, 3);
        let mut server = EchoServer::new(&mut pair.b, ECHO_PORT, 3, 2048).unwrap();
        let handles: Vec<_> = (0..3u16)
            .map(|i| connect(&mut pair.a, CLIENT_PORT + i, 4096, 4096))
            .collect();
        let mut clients: Vec<Client> = handles.iter().enumerate()
            .map(|(i, handle)| Client::new(handle, pattern(16 * 1024, 10 + i as u32)))
            .collect();

        let established = |stack: &mut Stack, handles: &[&TcpHandle]| {
            handles
                .iter()
                .all(|handle| stack.tcp(&handle).state() == State::Established)
        };
        let client_handles: Vec<&TcpHandle> = clients.iter().map(|c| c.handle).collect();
        let established_servers = |stack: &mut Stack, server: &EchoServer| {
            server.handles().iter().all(|handle| stack.tcp(handle).state() == State::Established)
        };
        pair.drive(
            |_, _| {},
            |a, b| {
                let moved = server.step(b);
                if established(a, &client_handles) && established_servers(b, &server) {
                    App::Done
                } else {
                    progress(moved)
                }
            },
        );

        // Every listener is busy: the fourth SYN finds no listening socket.
        let fourth = connect(&mut pair.a, CLIENT_PORT + 3, 4096, 4096);
        pair.drive(
            |_, _| {},
            |a, b| {
                let moved = server.step(b);
                match a.tcp(&fourth).state() {
                    State::SynSent => progress(moved),
                    State::Closed => App::Done,
                    state => panic!("fourth client reached {state}"),
                }
            },
        );
        assert!(established_servers(&mut pair.b, &server));

        echo_all(&mut pair, &mut server, &mut clients);
        let seen = close_all(&mut pair, &mut server, &client_handles);
        for states in &seen {
            assert_closed_then_listens(states);
        }
        close(pair);
    });
}

#[zhida_test_support::pinned_test]
fn new_removes_added_sockets_on_error() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["e5a", "e5b"], 1, 2);
        assert!(matches!(
            EchoServer::new(&mut pair.b, ECHO_PORT, 3, 1024),
            Err(EchoError::SocketsFull)
        ));
        let fresh = || tcp::Config { rx_capacity: 64, tx_capacity: 64, mss_cap: None };
        let added = [0, 1].map(|_| pair.b.add_tcp(fresh()).unwrap());
        for handle in added {
            pair.b.remove_tcp(handle);
        }

        assert!(matches!(
            EchoServer::new(&mut pair.b, 0, 2, 1024),
            Err(EchoError::Listen(ListenError::Unaddressable))
        ));
        let echo = EchoServer::new(&mut pair.b, ECHO_PORT, 2, 1024).unwrap();
        for handle in echo.handles() {
            assert_eq!(pair.b.tcp(handle).state(), State::Listen);
            assert_eq!(pair.b.tcp(handle).listen_endpoint().port, ECHO_PORT);
        }
        drop(echo);
        close(pair);
    });
}

#[zhida_test_support::pinned_test]
fn echo_relistens_after_peer_reset_mid_stream() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["e6a", "e6b"], 2, 1);
        let mut server = EchoServer::new(&mut pair.b, ECHO_PORT, 1, 1024).unwrap();
        let first = connect(&mut pair.a, CLIENT_PORT, 4096, 4096);
        let mut client = Client::new(&first, pattern(16 * 1024, 5));

        // The client writes without reading until the server's send buffer
        // is full: echo bytes are pending when the client aborts.
        pair.drive(
            |_, _| {},
            |a, b| {
                let moved = server.step(b) | client.write(a);
                let socket = b.tcp(&server.handles()[0]);
                if socket.send_queue() == socket.send_capacity() {
                    App::Done
                } else {
                    progress(moved)
                }
            },
        );
        assert_eq!(pair.b.tcp(&server.handles()[0]).state(), State::Established);
        pair.a.tcp_mut(&first).abort();

        // One sample per round, before `step`; every segment each side sends.
        let mut states = Vec::new();
        let mut from_a = Vec::new();
        let mut from_b = Vec::new();
        pair.drive(
            |dir, frame| match dir {
                Dir::AToB => from_a.push(segment(frame, Side::A).control),
                Dir::BToA => from_b.push(segment(frame, Side::B).control),
            },
            |a, b| {
                let state = b.tcp(&server.handles()[0]).state();
                states.push(state);
                let moved = server.step(b);
                assert_eq!(a.tcp(&first).state(), State::Closed);
                if state == State::Listen {
                    App::Done
                } else {
                    progress(moved)
                }
            },
        );
        // A's one abort RST is exact and takes the socket straight to Closed (no
        // CloseWait or LastAck); B never answers it. A segment B sent just before the
        // abort may still be on the wire: A, now without a socket, answers it with a
        // second RST (same sequence, ACK set) that reaches B's listener and is
        // ignored. Whether `step` sees the socket Established in the RST's round
        // depends only on the turn order within a round.
        assert!(
            from_a == [TcpControl::Rst] || from_a == [TcpControl::Rst, TcpControl::Rst],
            "segments from A after the abort: {from_a:?}"
        );
        assert_eq!(from_b, [], "segments from B after the abort");
        let after_reset = states.strip_prefix(&[State::Established]).unwrap_or(&states);
        assert_eq!(after_reset, [State::Closed, State::Listen], "{states:?}");
        let socket = pair.b.tcp(&server.handles()[0]);
        assert_eq!((socket.recv_queue(), socket.send_queue()), (0, 0));

        let second = connect(&mut pair.a, CLIENT_PORT + 1, 4096, 4096);
        let mut clients = [Client::new(&second, pattern(8 * 1024, 6))];
        echo_all(&mut pair, &mut server, &mut clients);
        let seen = close_all(&mut pair, &mut server, &[&second]);
        assert_closed_then_listens(&seen[0]);
        close(pair);
    });
}

/// Drives until `client` is Established while the server steps. Returns
/// each SYN and SYN-ACK delivered, in order, with its timestamp option.
fn handshake(
    pair: &mut Pair,
    server: &mut EchoServer,
    client: &TcpHandle,
) -> Vec<(Dir, Option<TcpTimestampRepr>)> {
    let mut syns = Vec::new();
    pair.drive(
        |dir, frame| {
            if EthernetFrame::new_checked(frame).unwrap().ethertype() == EthernetProtocol::Arp {
                return;
            }
            let src = match dir {
                Dir::AToB => Side::A,
                Dir::BToA => Side::B,
            };
            let tcp = segment(frame, src);
            if tcp.control == TcpControl::Syn {
                syns.push((dir, tcp.timestamp));
            }
        },
        |a, b| {
            let moved = server.step(b);
            if a.tcp(&client).state() == State::Established {
                App::Done
            } else {
                progress(moved)
            }
        },
    );
    syns
}

/// After a connection closes and the server listens again, both handshakes omit timestamps.
#[zhida_test_support::pinned_test]
fn echo_relisten_keeps_timestamps_off() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["e7a", "e7b"], 2, 1);
        let mut server = EchoServer::new(&mut pair.b, ECHO_PORT, 1, 4096).unwrap();

        let plain = connect(&mut pair.a, CLIENT_PORT, 4096, 4096);
        let syns = handshake(&mut pair, &mut server, &plain);
        assert_eq!(syns, [(Dir::AToB, None), (Dir::BToA, None)]);
        let mut clients = [Client::new(&plain, pattern(8 * 1024, 7))];
        echo_all(&mut pair, &mut server, &mut clients);
        let seen = close_all(&mut pair, &mut server, &[&plain]);
        assert_closed_then_listens(&seen[0]);

        let second = connect(&mut pair.a, CLIENT_PORT + 1, 4096, 4096);
        let syns = handshake(&mut pair, &mut server, &second);
        assert_eq!(syns, [(Dir::AToB, None), (Dir::BToA, None)]);
        let mut clients = [Client::new(&second, pattern(8 * 1024, 8))];
        echo_all(&mut pair, &mut server, &mut clients);
        let seen = close_all(&mut pair, &mut server, &[&second]);
        assert_closed_then_listens(&seen[0]);
        close(pair);
    });
}

const CLOSE_AFTER: usize = 1000;

/// One connection from `local` to a server echoing at most CLOSE_AFTER bytes
/// (buffers of 1024). The client sends `data`, longer than the server's
/// buffer, while reading the echo. The server's FIN must sit right after
/// CLOSE_AFTER echoed bytes, and every client byte must be acknowledged: the
/// bytes after the limit only fit through a 1024-byte window if the server
/// reads and discards them, which the server's empty receive queue after
/// every step while it is closing shows directly. The client then closes; the
/// server passes TIME-WAIT (10 s, smoltcp tcp.rs 301, 396) and listens again.
fn echo_until_server_fin(pair: &mut Pair, server: &mut EchoServer, local: u16, data: Vec<u8>) {
    let handle = connect(&mut pair.a, local, 4096, 4096);
    let mut client = Client::new(&handle, data);
    let mut isn = None;
    let mut fins = Vec::new();
    pair.drive(
        |dir, frame| {
            if dir == Dir::AToB
                || EthernetFrame::new_checked(frame).unwrap().ethertype() == EthernetProtocol::Arp
            {
                return;
            }
            let tcp = segment(frame, Side::B);
            match tcp.control {
                TcpControl::Syn => isn = Some(tcp.seq_number),
                TcpControl::Fin => fins.push(tcp.seq_number + tcp.payload.len()),
                _ => {}
            }
        },
        |a, b| {
            let moved = server.step(b) | client.write(a) | client.read(a);
            let socket = b.tcp(&server.handles()[0]);
            if matches!(socket.state(), State::FinWait1 | State::FinWait2) {
                assert_eq!(socket.recv_queue(), 0);
            }
            let socket = a.tcp(&handle);
            let sent_all = client.written == client.data.len() && socket.send_queue() == 0;
            if sent_all && !socket.may_recv() {
                App::Done
            } else {
                progress(moved)
            }
        },
    );
    assert!(
        client.echoed == client.data[..CLOSE_AFTER],
        "echoed {} bytes, not the first {CLOSE_AFTER} sent",
        client.echoed.len()
    );
    let isn = isn.expect("SYN-ACK seen");
    assert!(!fins.is_empty());
    assert!(fins.iter().all(|&fin| fin == isn + 1 + CLOSE_AFTER), "{fins:?} vs {isn}");
    assert_eq!(pair.a.tcp(&handle).state(), State::CloseWait);
    assert_eq!(pair.b.tcp(&server.handles()[0]).state(), State::FinWait2);

    pair.a.tcp_mut(&handle).close();
    let mut states = Vec::new();
    pair.drive(
        |_, _| {},
        |a, b| {
            let state = b.tcp(&server.handles()[0]).state();
            if states.last() != Some(&state) {
                states.push(state);
            }
            let moved = server.step(b);
            if a.tcp(&handle).state() == State::Closed && state == State::Listen {
                App::Done
            } else {
                progress(moved)
            }
        },
    );
    // The client's FIN reaches the server in the first round, before `step`.
    assert_eq!(states, [State::TimeWait, State::Closed, State::Listen]);
    pair.a.remove_tcp(handle);
}

#[zhida_test_support::pinned_test]
fn close_after_sends_fin_after_exactly_n_bytes_and_discards_the_rest() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["c1a", "c1b"], 1, 1);
        let mut server = EchoServer::new(&mut pair.b, ECHO_PORT, 1, 1024)
            .unwrap()
            .with_close_after(Some(CLOSE_AFTER));
        echo_until_server_fin(&mut pair, &mut server, CLIENT_PORT, pattern(8 * 1024, 20));
        close(pair);
    });
}

/// The second connection on the same listener gets CLOSE_AFTER bytes again.
#[zhida_test_support::pinned_test]
fn close_after_count_restarts_on_the_next_connection() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["c2a", "c2b"], 1, 1);
        let mut server = EchoServer::new(&mut pair.b, ECHO_PORT, 1, 1024)
            .unwrap()
            .with_close_after(Some(CLOSE_AFTER));
        echo_until_server_fin(&mut pair, &mut server, CLIENT_PORT, pattern(4 * 1024, 21));
        echo_until_server_fin(&mut pair, &mut server, CLIENT_PORT + 1, pattern(4 * 1024, 22));
        close(pair);
    });
}

/// A peer FIN before CLOSE_AFTER bytes: echo all, close after it as without a
/// limit.
#[zhida_test_support::pinned_test]
fn close_after_closes_after_peer_fin_below_the_limit() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["c3a", "c3b"], 1, 1);
        let mut server = EchoServer::new(&mut pair.b, ECHO_PORT, 1, 1024)
            .unwrap()
            .with_close_after(Some(CLOSE_AFTER));
        let handle = connect(&mut pair.a, CLIENT_PORT, 4096, 4096);
        let mut clients = [Client::new(&handle, pattern(CLOSE_AFTER - 1, 23))];
        echo_all(&mut pair, &mut server, &mut clients);
        let seen = close_all(&mut pair, &mut server, &[&handle]);
        assert_closed_then_listens(&seen[0]);
        close(pair);
    });
}

/// One TCP segment the server sent to the peer.
#[derive(Debug, PartialEq, Eq)]
struct Seg {
    dst_port: u16,
    control: TcpControl,
    seq: TcpSeqNumber,
    ack: Option<TcpSeqNumber>,
    window: u16,
    options: Vec<u8>,
    payload: Vec<u8>,
}

fn parse(frame: &[u8]) -> Seg {
    let repr = segment(frame, Side::B);
    let eth = EthernetFrame::new_checked(frame).unwrap();
    let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert_eq!(repr.src_port, ECHO_PORT);
    Seg {
        dst_port: repr.dst_port,
        control: repr.control,
        seq: repr.seq_number,
        ack: repr.ack_number,
        window: repr.window_len,
        options: ip.payload()[20..tcp.header_len() as usize].to_vec(),
        payload: repr.payload.to_vec(),
    }
}

/// One frame from the peer's `port` to the echo port.
fn from_peer(
    port: u16,
    control: TcpControl,
    seq: TcpSeqNumber,
    ack: Option<TcpSeqNumber>,
    payload: &[u8],
) -> Vec<u8> {
    let tcp = TcpRepr {
        src_port: port,
        dst_port: ECHO_PORT,
        control,
        seq_number: seq,
        ack_number: ack,
        window_len: 65535,
        window_scale: None,
        max_seg_size: (control == TcpControl::Syn).then_some(1460),
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload,
    };
    let caps = ChecksumCapabilities::default();
    let eth = EthernetRepr {
        src_addr: Side::A.mac(),
        dst_addr: Side::B.mac(),
        ethertype: EthernetProtocol::Ipv4,
    };
    let ip = Ipv4Repr {
        src_addr: Side::A.ip(),
        dst_addr: Side::B.ip(),
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    let mut bytes = vec![0; eth.buffer_len() + ip.buffer_len() + tcp.buffer_len()];
    let mut frame = EthernetFrame::new_unchecked(&mut bytes);
    eth.emit(&mut frame);
    let mut packet = Ipv4Packet::new_unchecked(frame.payload_mut());
    ip.emit(&mut packet, &caps);
    tcp.emit(
        &mut TcpPacket::new_unchecked(packet.payload_mut()),
        &IpAddress::Ipv4(Side::A.ip()),
        &IpAddress::Ipv4(Side::B.ip()),
        &caps,
    );
    bytes
}

/// One hand-driven client connection: `seq` is the next sequence number it
/// sends, `ack` the next it expects from the server.
struct Peer {
    port: u16,
    isn: TcpSeqNumber,
    seq: TcpSeqNumber,
    ack: TcpSeqNumber,
}

impl Peer {
    fn new(port: u16, isn: i32) -> Self {
        let isn = TcpSeqNumber(isn);
        Self {
            port,
            isn,
            seq: isn + 1,
            ack: TcpSeqNumber(0),
        }
    }

    fn endpoint(&self) -> IpEndpoint {
        IpEndpoint::new(Side::A.ip().into(), self.port)
    }

    /// The initial SYN; sending it again is a duplicate.
    fn syn(&self) -> Vec<u8> {
        from_peer(self.port, TcpControl::Syn, self.isn, None, &[])
    }

    fn send(&mut self, control: TcpControl, payload: &[u8]) -> Vec<u8> {
        self.send_acking(control, self.ack, payload)
    }

    fn send_acking(&mut self, control: TcpControl, ack: TcpSeqNumber, payload: &[u8]) -> Vec<u8> {
        let frame = from_peer(self.port, control, self.seq, Some(ack), payload);
        self.seq += payload.len() + usize::from(control == TcpControl::Fin);
        frame
    }

    /// Acknowledge everything the server sent this peer in `segs`.
    fn absorb(&mut self, segs: &[Seg]) {
        for seg in segs.iter().filter(|seg| seg.dst_port == self.port) {
            let flag = matches!(seg.control, TcpControl::Syn | TcpControl::Fin);
            self.ack = seg.seq + seg.payload.len() + usize::from(flag);
        }
    }

    /// Payload the server sent this peer in `segs`, in order.
    fn payload(&self, segs: &[Seg]) -> Vec<u8> {
        segs.iter()
            .filter(|seg| seg.dst_port == self.port)
            .flat_map(|seg| seg.payload.iter().copied())
            .collect()
    }
}

/// An EchoServer on one Stack whose peer is the test; the clock starts at T0
/// and stays fixed during packet exchanges.
struct Server {
    stack: Stack,
    echo: EchoServer,
    now: Instant,
    /// Last: the Stack's Port must close before the fixture releases its
    /// device.
    fixture: RingPort,
}

impl Server {
    /// `listeners` sockets of 1024 bytes; the peer's MAC is learned from its
    /// ARP request.
    fn new(eal: &Eal, name: &str, listeners: usize) -> Self {
        let fixture = RingPort::new(name, 16, 16);
        let stack_config = config(Side::B, listeners);
        let mut port_config = fixture.config();
        port_config.rx_pool.count = rx_pool_count(
            rx_reserve(
                port_config.rx_descriptors,
                stack_config.rx_staging,
                port_config.rx_pool.cache_size,
            ),
            port_config.mtu,
            std::iter::repeat(1024).take(listeners),
        );
        let mut stack = match Stack::new(fixture.open_with(eal, port_config), stack_config, T0) {
            Ok(stack) => stack,
            Err((_, error)) => panic!("{error}"),
        };
        let echo = EchoServer::new(&mut stack, ECHO_PORT, listeners, 1024).unwrap();
        fixture.inject(&[arp(
            ArpOperation::Request,
            EthernetAddress::BROADCAST,
            (Side::A.mac(), Side::A.ip()),
            (EthernetAddress([0; 6]), Side::B.ip()),
        )]);
        stack.turn(T0, 32).unwrap();
        assert_eq!(
            fixture.take_tx(),
            [arp(
                ArpOperation::Reply,
                Side::A.mac(),
                (Side::B.mac(), Side::B.ip()),
                (Side::A.mac(), Side::A.ip())
            )]
        );
        Self {
            stack,
            echo,
            now: T0,
            fixture,
        }
    }

    fn inject_and_turn(&mut self, frames: &[Vec<u8>]) {
        self.fixture.inject(frames);
        self.stack.turn(self.now, 32).unwrap();
    }

    /// Inject, turn, echo step, turn; every segment sent meanwhile.
    fn exchange(&mut self, frames: &[Vec<u8>]) -> Vec<Seg> {
        self.inject_and_turn(frames);
        self.echo.step(&mut self.stack);
        self.stack.turn(self.now, 32).unwrap();
        self.sent()
    }

    fn sent(&self) -> Vec<Seg> {
        self.fixture
            .take_tx()
            .iter()
            .map(|frame| parse(frame))
            .collect()
    }

    fn state(&mut self, slot: usize) -> State {
        let handle = &self.echo.handles()[slot];
        self.stack.tcp(&handle).state()
    }

    /// SYN, SYN-ACK, ACK.
    fn handshake(&mut self, peer: &mut Peer) {
        let segs = self.exchange(&[peer.syn()]);
        assert_eq!(segs.len(), 1, "{segs:?}");
        assert_eq!(
            (segs[0].dst_port, segs[0].control, segs[0].ack),
            (peer.port, TcpControl::Syn, Some(peer.isn + 1))
        );
        peer.absorb(&segs);
        let segs = self.exchange(&[peer.send(TcpControl::None, &[])]);
        assert!(segs.is_empty(), "{segs:?}");
    }

    /// The peer's FIN, the server's FIN, the peer's last ACK: the server
    /// socket in `slot` listens again.
    fn close(&mut self, peer: &mut Peer, slot: usize) {
        let segs = self.exchange(&[peer.send(TcpControl::Fin, &[])]);
        assert_eq!(self.state(slot), State::LastAck);
        peer.absorb(&segs);
        let segs = self.exchange(&[peer.send(TcpControl::None, &[])]);
        assert!(segs.is_empty(), "{segs:?}");
        assert_eq!(self.state(slot), State::Listen);
    }

    fn finish(self) {
        let Self { fixture, stack, .. } = self;
        assert!(fixture.take_tx().is_empty());
        let port = stack.into_port();
        assert_eq!(fixture.in_use(), (0, 0));
        port.try_close().unwrap();
        fixture.close();
    }
}

/// The peer sends data and FIN; the server echoes, closes (LastAck) and the
/// peer then sends a segment with payload that acks only part of the echo.
/// smoltcp discards that payload in LastAck while advancing SND.UNA;
/// `step` has no receive data to process.
#[zhida_test_support::pinned_test]
fn step_has_no_payload_received_after_fin_in_last_ack() {
    with_eal(|eal| {
        let mut server = Server::new(eal, "la", 1);
        let mut peer = Peer::new(CLIENT_PORT, 1000);
        server.handshake(&mut peer);
        let echo_start = peer.ack;

        let data = pattern(100, 7);
        let segs = server.exchange(&[peer.send(TcpControl::Fin, &data)]);
        assert_eq!(peer.payload(&segs), data);
        assert_eq!(segs.last().unwrap().control, TcpControl::Fin);
        assert_eq!(server.state(0), State::LastAck);
        peer.absorb(&segs);

        let late = [0xab; 20];
        let frame = peer.send_acking(TcpControl::None, echo_start + 10, &late);
        server.inject_and_turn(&[frame]);
        let observe = |server: &Server| {
            let socket = server.stack.tcp(&server.echo.handles()[0]);
            (socket.state(), socket.recv_queue(), socket.send_queue())
        };
        assert_eq!(observe(&server), (State::LastAck, 0, 90));
        assert!(!server.echo.step(&mut server.stack));
        assert_eq!(observe(&server), (State::LastAck, 0, 90));
        server.sent();

        let segs = server.exchange(&[peer.send(TcpControl::None, &[])]);
        assert!(segs.is_empty(), "{segs:?}");
        assert_eq!(observe(&server), (State::Listen, 0, 0));
        server.finish();
    });
}

/// A duplicate of an established connection's SYN reaches a lower slot that
/// listens again. Per RFC 5961 4.2 (Linux does this) the established
/// connection answers with exactly one challenge ACK: no SYN, empty, seq =
/// the server's SND.NXT, ack = its RCV.NXT. No other socket changes state.
#[zhida_test_support::pinned_test]
fn duplicate_syn_does_not_reset_established_connection() {
    with_eal(|eal| {
        let mut server = Server::new(eal, "r9a", 2);
        let mut c1 = Peer::new(CLIENT_PORT, 1000);
        let mut c2 = Peer::new(CLIENT_PORT + 1, 5000);
        server.handshake(&mut c1);
        server.handshake(&mut c2);
        let handles = server.echo.handles();
        let remotes: Vec<_> = handles
            .iter()
            .map(|handle| server.stack.tcp(handle).remote_endpoint())
            .collect();
        assert_eq!(remotes, [Some(c1.endpoint()), Some(c2.endpoint())]);
        server.close(&mut c1, 0);

        let segs = server.exchange(&[c2.syn()]);
        assert_eq!(
            [server.state(0), server.state(1)],
            [State::Listen, State::Established],
            "replies: {segs:?}"
        );
        assert_eq!(segs.len(), 1, "replies: {segs:?}");
        assert_eq!(
            (
                segs[0].dst_port,
                segs[0].control,
                segs[0].seq,
                segs[0].ack,
                segs[0].payload.len()
            ),
            (c2.port, TcpControl::None, c2.ack, Some(c2.seq), 0),
            "replies: {segs:?}"
        );

        let data = pattern(64, 8);
        let segs = server.exchange(&[c2.send(TcpControl::None, &data)]);
        assert_eq!(c2.payload(&segs), data);
        assert_eq!(
            [server.state(0), server.state(1)],
            [State::Listen, State::Established]
        );
        server.finish();
    });
}

/// The server's SYN-ACK to a client on slot 1 is lost; slot 0 then listens
/// again and the client retransmits its SYN. The original half-open
/// connection must complete: the SYN-ACK the client acks carries the lost
/// SYN-ACK's server ISN, and one socket ends Established. Linux resends the
/// existing request's identical SYN-ACK at once (tcp_check_req).
#[zhida_test_support::pinned_test]
fn retransmitted_syn_after_lost_synack_completes_one_connection() {
    with_eal(|eal| {
        let mut server = Server::new(eal, "r9b", 2);
        let mut c1 = Peer::new(CLIENT_PORT, 1000);
        let mut c = Peer::new(CLIENT_PORT + 1, 5000);
        let isn = c.isn;
        let assert_syn_ack = |seg: &Seg| {
            assert_eq!(
                (seg.control, seg.ack, seg.payload.len()),
                (TcpControl::Syn, Some(isn + 1), 0),
                "{seg:?}"
            );
        };
        server.handshake(&mut c1);
        let lost = server.exchange(&[c.syn()]);
        assert_eq!(lost.len(), 1, "{lost:?}");
        assert_eq!(lost[0].dst_port, c.port);
        assert_syn_ack(&lost[0]);
        assert_eq!(server.state(1), State::SynReceived);
        server.close(&mut c1, 0);

        let segs = server.exchange(&[c.syn()]);
        assert_eq!(segs, lost, "immediate SYN-ACK differs from the lost one");
        assert_eq!(
            [server.state(0), server.state(1)],
            [State::Listen, State::SynReceived]
        );
        c.ack = segs[0].seq + 1;
        let segs = server.exchange(&[c.send(TcpControl::None, &[])]);
        assert!(segs.is_empty(), "{segs:?}");

        let handles = server.echo.handles();
        let holding: Vec<(usize, State)> = handles
            .iter()
            .enumerate()
            .filter_map(|(slot, handle)| {
                let socket = server.stack.tcp(&handle);
                (socket.remote_endpoint() == Some(c.endpoint())).then(|| (slot, socket.state()))
            })
            .collect();
        assert_eq!(
            holding.len(),
            1,
            "sockets holding c: {holding:?}; replies {segs:?}"
        );
        assert_eq!(holding[0].1, State::Established);
        assert_eq!(holding[0].0, 1);
        let data = b"original connection";
        let segs = server.exchange(&[c.send(TcpControl::None, data)]);
        assert_eq!(c.payload(&segs), data);
        assert_eq!(
            [server.state(0), server.state(1)],
            [State::Listen, State::Established]
        );
        server.finish();
    });
}

#[zhida_test_support::pinned_test]
fn echo_retains_frame_when_free_send_space_is_smaller_than_payload() {
    with_eal(|eal| {
        for limit in [None, Some(5)] {
            let names = if limit.is_some() { ["leftlimita", "leftlimitb"] } else { ["lefta", "leftb"] };
            let mut pair = new_pair(eal, names, 1, 1);
            let mut server = EchoServer::new(&mut pair.b, ECHO_PORT, 1, 64).unwrap()
                .with_close_after(limit);
            let client = connect(&mut pair.a, CLIENT_PORT, 4096, 4096);
            pair.drive(|_, _| {}, |a, b| {
                server.step(b);
                if a.tcp(&client).state() == State::Established { App::Done } else { App::Idle }
            });
            let payload = pattern(48, 31);
            assert_eq!(pair.a.tcp_mut(&client).send_slice(&payload), Ok(payload.len()));
            pair.drive(|_, _| {}, |_, b| {
                if b.tcp(&server.handles()[0]).recv_queue() == payload.len() { App::Done } else { App::Idle }
            });
            let prefix = [0xa5; 60];
            assert_eq!(pair.b.tcp_mut(&server.handles()[0]).send_slice(&prefix), Ok(prefix.len()));
            assert!(server.step(&mut pair.b));
            let socket = pair.b.tcp(&server.handles()[0]);
            assert_eq!(socket.send_queue(), 64);
            assert_eq!(socket.recv_queue(), 0);
            assert_eq!(socket.held_frames().count(), 1);
            let echoed = limit.unwrap_or(payload.len());
            let mut received = Vec::new();
            pair.drive(|_, _| {}, |a, b| {
                let bytes = pair::drain_bytes(a.tcp_mut(&client)).unwrap();
                received.extend_from_slice(&bytes);
                let moved = server.step(b) || !bytes.is_empty();
                if received.len() == prefix.len() + echoed { App::Done } else { progress(moved) }
            });
            assert_eq!(&received[..prefix.len()], &prefix);
            assert_eq!(&received[prefix.len()..], &payload[..echoed]);
            assert_eq!(pair.b.tcp(&server.handles()[0]).held_frames().count(), 0);
            if limit.is_some() {
                // The server closed first after the limit: it passes TIME-WAIT, the
                // client ends Closed from LAST-ACK.
                pair.a.tcp_mut(&client).close();
                pair.drive(|_, _| {}, |a, b| {
                    let moved = server.step(b);
                    let listening = b.tcp(&server.handles()[0]).state() == State::Listen;
                    if a.tcp(&client).state() == State::Closed && listening {
                        App::Done
                    } else {
                        progress(moved)
                    }
                });
            } else {
                close_all(&mut pair, &mut server, &[&client]);
            }
            close(pair);
        }
    });
}
