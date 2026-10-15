//! `Server` over two Stacks on lossless net_ring links. B runs the Server;
//! A is the client: raw TCP sockets, a hand-written upgrade request, then a
//! tungstenite `WebSocketContext` with a pending frame between Stack borrows.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::rc::Rc;

use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::socket::tcp::{self, State};
use dpdk_smoltcp::smoltcp::time::Duration;
use dpdk_smoltcp::smoltcp::wire::{EthernetFrame, EthernetProtocol, IpEndpoint, TcpControl};
use dpdk_smoltcp::{AddTcpError, Stack, StackConfig};
use tungstenite::error::ProtocolError;
use tungstenite::protocol::{Role, WebSocketContext};
use tungstenite::{Error, Message};
use ws_autobahn::{Server, ServerError};
#[path = "common/stream.rs"]
mod stream;
use stream::with_stream;

use zhida_test_kit::{pair, wire, with_eal};
use pair::{
    assert_lossless, config, pattern, segment, Pair, Rounds, Side, CLIENT_PORT, SERVER_PORT, T0,
};
use wire::{Link, Verdict};

/// Socket buffers each way, server and client. At most 6 full frames in
/// flight per direction, so neither side's pending queue fills and blocks
/// its ingress while the 15-frame rings hold every frame (lossless links;
/// 64 KiB windows both ways overflowed a ring).
const BUFFER: usize = 8 * 1024;
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
/// RFC 6455 section 1.3's accept value for `KEY`.
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

fn request(key: Option<&str>) -> Vec<u8> {
    let key = key.map_or(String::new(), |key| format!("Sec-WebSocket-Key: {key}\r\n"));
    format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n{key}\r\n",
        Side::B.ip()
    )
    .into_bytes()
}

/// A with `client_sockets` slots, B with `server_sockets`.
fn new_pair(eal: &dpdk_smoltcp::Eal, names: [&str; 2], sockets: [usize; 2]) -> Pair {
    let configs = [Side::A, Side::B].map(|side| StackConfig {
        max_udp_sockets: 0,
        max_sockets: sockets[side.index()],
        ..config(side)
    });
    Pair::new(eal, names, configs, T0)
}

fn close(pair: Pair) {
    assert_lossless(&pair.a_to_b, "A→B");
    assert_lossless(&pair.b_to_a, "B→A");
    pair.close();
}

fn socket(rx: usize, tx: usize) -> tcp::Config {
    let socket = tcp::Config { rx_capacity: rx, tx_capacity: tx, mss_cap: None };
    socket
}

fn would_block(error: &Error) -> bool {
    matches!(error, Error::Io(io) if io.kind() == ErrorKind::WouldBlock)
}

fn endings(pairs: &[(&'static str, usize)]) -> BTreeMap<&'static str, usize> {
    pairs.iter().copied().collect()
}

/// The TCP control of `frame`, sent by `src`; `None` for a non-IPv4 frame.
fn tcp_control(frame: &[u8], src: Side) -> Option<TcpControl> {
    let ipv4 = EthernetFrame::new_checked(frame)
        .is_ok_and(|eth| eth.ethertype() == EthernetProtocol::Ipv4);
    ipv4.then(|| segment(frame, src).control)
}

/// From now on every frame `src` sends over `link` is checked as it
/// crosses: a TCP RST fails the test.
fn forbid_rst(link: &mut Link, src: Side) {
    link.impair(move |frame| {
        assert_ne!(
            tcp_control(frame, src),
            Some(TcpControl::Rst),
            "RST from {src:?}"
        );
        Verdict::Deliver
    });
}

struct Client {
    handle: Option<TcpHandle>,
    pending: Option<(tcp::TcpFrame, usize)>,
    ws: WebSocketContext,
}

/// A's Stack and the links, the Server holding B's Stack.
struct Net<'p> {
    rounds: Rounds,
    a: &'p mut Stack,
    a_to_b: &'p mut Link,
    b_to_a: &'p mut Link,
    server: Server<'p>,
}

impl<'p> Net<'p> {
    fn new(pair: &'p mut Pair, buffer: usize) -> Self {
        let rounds = Rounds::new(pair.now());
        let Pair {
            a,
            b,
            a_to_b,
            b_to_a,
            ..
        } = pair;
        Self {
            rounds,
            a,
            a_to_b,
            b_to_a,
            server: Server::new(b, SERVER_PORT, buffer).unwrap(),
        }
    }

    /// A round with B turned by `Server::step`.
    fn try_round(&mut self) -> Result<bool, ServerError> {
        let mut stepped = Ok(false);
        let server = &mut self.server;
        let moved = self
            .rounds
            .round_with(self.a, self.a_to_b, self.b_to_a, |now| {
                stepped = server.step(now);
                matches!(stepped, Ok(true))
            });
        stepped.map(|_| moved)
    }

    fn settle(&mut self, moved: bool) {
        self.rounds.settle(moved, self.a, self.server.stack());
    }

    /// Rounds until `done`, called after each, returns a value.
    fn until<T>(&mut self, mut done: impl FnMut(&mut Self) -> Option<T>) -> T {
        loop {
            let moved = self.try_round().unwrap();
            if let Some(value) = done(self) {
                return value;
            }
            self.settle(moved);
        }
    }

    /// Rounds until the Server fails.
    fn until_error(&mut self) -> ServerError {
        loop {
            match self.try_round() {
                Ok(moved) => self.settle(moved),
                Err(error) => return error,
            }
        }
    }

    fn state(&mut self, handle: &TcpHandle) -> State {
        self.a.tcp(&handle).state()
    }

    fn wait_state(&mut self, handle: &TcpHandle, state: State) {
        self.until(|net| (net.state(&handle) == state).then_some(()));
    }

    /// Adds `socket` on A and connects it from `local_port`.
    fn connect(&mut self, socket: tcp::Config, local_port: u16) -> TcpHandle {
        let handle = self.a.add_tcp(socket).unwrap();
        let server = IpEndpoint::new(Side::B.ip().into(), SERVER_PORT);
        self.a.connect(&handle, server, local_port).unwrap();
        handle
    }

    /// Sends `request` and returns every byte received until the first
    /// blank line, which must end them.
    fn upgrade(&mut self, handle: &TcpHandle, request: &[u8]) -> String {
        let sent = self.a.tcp_mut(&handle).send_slice(request);
        assert_eq!(sent, Ok(request.len()));
        let mut response = Vec::new();
        self.until(|net| {
            let bytes = pair::drain_bytes(net.a.tcp_mut(&handle)).unwrap();
            response.extend_from_slice(&bytes);
            response.ends_with(b"\r\n\r\n").then_some(())
        });
        String::from_utf8(response).unwrap()
    }

    /// A WebSocket client on a new socket from `local_port`.
    fn open_with(&mut self, socket: tcp::Config, local_port: u16) -> Client {
        let handle = self.connect(socket, local_port);
        self.wait_state(&handle, State::Established);
        self.upgrade_ws(handle)
    }

    /// A WebSocket client on the Established socket `handle`, after a 101
    /// response with the right accept value.
    fn upgrade_ws(&mut self, handle: TcpHandle) -> Client {
        let response = self.upgrade(&handle, &request(Some(KEY)));
        assert!(
            response.starts_with("HTTP/1.1 101 ")
                && response.contains(&format!("\r\nsec-websocket-accept: {ACCEPT}\r\n")),
            "{response}"
        );
        Client {
            handle: Some(handle),
            pending: None,
            ws: WebSocketContext::new(Role::Client, None),
        }
    }

    fn open(&mut self, local_port: u16) -> Client {
        self.open_with(socket(BUFFER, BUFFER), local_port)
    }

    /// `ws.write`; a WouldBlock leaves the frame buffered in tungstenite.
    fn write(&mut self, client: &mut Client, message: Message) {
        with_stream(self.a, &mut client.handle, &mut client.pending, |stream| {
            match client.ws.write(stream, message) {
                Err(error) if !would_block(&error) => panic!("client write: {error}"),
                _ => {}
            }
        })
    }

    /// Whether the client's tungstenite output is all in its socket.
    fn try_flush(&mut self, client: &mut Client) -> bool {
        with_stream(self.a, &mut client.handle, &mut client.pending, |stream| {
            match client.ws.flush(stream) {
                Ok(()) => true,
                Err(error) if would_block(&error) => false,
                Err(error) => panic!("client flush: {error}"),
            }
        })
    }

    fn flush(&mut self, client: &mut Client) {
        if !self.try_flush(client) {
            self.until(|net| net.try_flush(client).then_some(()));
        }
    }

    fn send(&mut self, client: &mut Client, message: Message) {
        self.write(client, message);
        self.flush(client);
    }

    fn try_read(&mut self, client: &mut Client) -> Option<Result<Message, Error>> {
        with_stream(self.a, &mut client.handle, &mut client.pending, |stream| {
            match client.ws.read(stream) {
                Err(error) if would_block(&error) => None,
                other => Some(other),
            }
        })
    }

    /// The client's next read that does not block.
    fn read(&mut self, client: &mut Client) -> Result<Message, Error> {
        match self.try_read(client) {
            Some(result) => result,
            None => self.until(|net| net.try_read(client)),
        }
    }

    fn echo(&mut self, client: &mut Client, message: Message) {
        self.send(client, message.clone());
        assert_eq!(self.read(client).unwrap(), message);
    }

    /// Close handshake started by the client: the reply comes first, then the
    /// server's FIN (the client sits in CloseWait), then EOF; the client then
    /// closes TCP and its socket ends Closed. A RST would also end it Closed:
    /// this does not show that no RST crossed.
    fn close_ws(&mut self, client: &mut Client) {
        with_stream(self.a, &mut client.handle, &mut client.pending, |stream| {
            match client.ws.close(stream, None) {
                Err(error) if !would_block(&error) => panic!("client close: {error}"),
                _ => {}
            }
        });
        self.flush(client);
        assert_eq!(self.read(client).unwrap(), Message::Close(None));
        self.wait_state(client.handle.as_ref().unwrap(), State::CloseWait);
        assert!(matches!(self.read(client), Err(Error::ConnectionClosed)));
        self.a.tcp_mut(client.handle.as_ref().unwrap()).close();
        self.wait_state(client.handle.as_ref().unwrap(), State::Closed);
    }
}

#[zhida_test_support::pinned_test]
fn echoes_text_binary_and_answers_ping() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["etba", "etbb"], [1, 2]);
        let mut net = Net::new(&mut pair, BUFFER);
        let mut client = net.open(CLIENT_PORT);
        net.echo(&mut client, Message::text("hello over zhida"));
        net.echo(&mut client, Message::binary(pattern(3000, 1)));
        net.send(&mut client, Message::Ping(b"are you there".to_vec().into()));
        assert_eq!(
            net.read(&mut client).unwrap(),
            Message::Pong(b"are you there".to_vec().into())
        );
        net.close_ws(&mut client);
        assert_eq!(net.server.accepted(), 1);
        assert_eq!(net.server.endings(), &endings(&[("ConnectionClosed", 1)]));
        drop(net);
        close(pair);
    });
}

/// The client reads the close reply, and only then finds the server's FIN
/// while it has not closed TCP itself.
#[zhida_test_support::pinned_test]
fn server_closes_tcp_first_after_close_handshake() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["scfa", "scfb"], [1, 2]);
        let mut net = Net::new(&mut pair, BUFFER);
        let mut client = net.open(CLIENT_PORT);
        net.send(&mut client, Message::Close(None));
        let reply = net.read(&mut client);
        assert_eq!(reply.unwrap(), Message::Close(None));
        net.wait_state(client.handle.as_ref().unwrap(), State::CloseWait);
        assert!(matches!(
            net.read(&mut client),
            Err(Error::ConnectionClosed)
        ));
        assert_eq!(net.server.endings(), &endings(&[("ConnectionClosed", 1)]));
        net.a.tcp_mut(client.handle.as_ref().unwrap()).close();
        net.wait_state(client.handle.as_ref().unwrap(), State::Closed);
        drop(net);
        close(pair);
    });
}

/// The client sends a 64 KiB message, Close and FIN while reading nothing
/// through a 4 KiB receive window, so the server's echo blocks with Close and
/// FIN in its receive buffer. Reading on would hit EOF with the close reply
/// still unsent; the server instead flushes the echo first and replies.
#[zhida_test_support::pinned_test]
fn close_reply_sent_before_fin_under_backpressure() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["crba", "crbb"], [1, 2]);
        let mut net = Net::new(&mut pair, 4096);
        let mut client = net.open_with(socket(4096, 256 * 1024), CLIENT_PORT);
        let message = Message::binary(pattern(64 * 1024, 2));
        net.write(&mut client, message.clone());
        net.write(&mut client, Message::Close(None));
        assert!(
            net.try_flush(&mut client),
            "message and Close fit the send buffer"
        );
        net.a.tcp_mut(client.handle.as_ref().unwrap()).close();
        net.until(|net| {
            let socket = net.a.tcp(client.handle.as_ref().unwrap());
            (socket.state() == State::FinWait2 && socket.recv_room() == 0).then_some(())
        });
        assert!(net.server.endings().is_empty());
        assert_eq!(net.read(&mut client).unwrap(), message);
        assert_eq!(net.read(&mut client).unwrap(), Message::Close(None));
        assert!(matches!(
            net.read(&mut client),
            Err(Error::ConnectionClosed)
        ));
        assert_eq!(net.server.endings(), &endings(&[("ConnectionClosed", 1)]));
        net.wait_state(client.handle.as_ref().unwrap(), State::TimeWait);
        drop(net);
        close(pair);
    });
}

/// A frame with RSV1 set: the server fails the connection with FIN and no
/// close frame.
#[zhida_test_support::pinned_test]
fn protocol_error_ends_session_with_fin() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["pefa", "pefb"], [1, 2]);
        let mut net = Net::new(&mut pair, BUFFER);
        let client = net.open(CLIENT_PORT);
        // FIN + RSV1 + text, masked, 1 byte: 'x' under a zero mask.
        let frame = [0xc1, 0x81, 0, 0, 0, 0, b'x'];
        assert_eq!(
            net.a.tcp_mut(client.handle.as_ref().unwrap()).send_slice(&frame),
            Ok(frame.len())
        );
        net.wait_state(client.handle.as_ref().unwrap(), State::CloseWait);
        assert_eq!(net.a.tcp(client.handle.as_ref().unwrap()).recv_queue(), 0);
        assert_eq!(net.server.endings(), &endings(&[("Protocol", 1)]));
        net.a.tcp_mut(client.handle.as_ref().unwrap()).close();
        net.wait_state(client.handle.as_ref().unwrap(), State::Closed);
        drop(net);
        close(pair);
    });
}

/// Two segments queued at the server in one turn: a valid "ok" frame plus an
/// RSV1 frame, then 65 more bytes. The server reads both segments before it
/// fails the connection, so its close sends FIN, not the RST for unread data.
/// The server sends no Close frame, so the client sees EOF without a close
/// handshake.
#[zhida_test_support::pinned_test]
fn protocol_error_reads_every_queued_segment_before_fin() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["pesa", "pesb"], [1, 2]);
        let mut net = Net::new(&mut pair, BUFFER);
        let mut client = net.open_with(socket(BUFFER, BUFFER), CLIENT_PORT);
        let handle = client.handle.take().unwrap();
        forbid_rst(net.b_to_a, Side::B);
        // Masked under a zero mask: text "ok", then FIN + RSV1 + text 'x'.
        let first = [0x81, 0x82, 0, 0, 0, 0, b'o', b'k', 0xc1, 0x81, 0, 0, 0, 0, b'x'];
        let second = [b'y'; 65];
        net.a_to_b.paused = true;
        for bytes in [&first[..], &second[..]] {
            assert_eq!(net.a.tcp_mut(&handle).send_slice(bytes), Ok(bytes.len()));
            assert_eq!(net.a.send().unwrap().tx_accepted, 1);
        }
        net.a_to_b.paused = false;
        net.wait_state(&handle, State::CloseWait);
        assert_eq!(net.server.endings(), &endings(&[("Protocol", 1)]));
        client.handle = Some(handle);
        assert_eq!(net.read(&mut client).unwrap(), Message::text("ok"));
        assert!(matches!(
            net.read(&mut client),
            Err(Error::Protocol(ProtocolError::ResetWithoutClosingHandshake))
        ));
        let handle = client.handle.as_ref().unwrap();
        net.a.tcp_mut(handle).close();
        net.wait_state(handle, State::Closed);
        drop(net);
        close(pair);
    });
}

/// The client pipelines four 1 MiB messages and reads nothing. The rounds
/// go quiet with the client's socket full (send buffer full, no receive room)
/// and output still in its tungstenite buffer: the server stopped reading. A
/// server that kept reading would drain all 4 MiB into memory. Then every
/// echo arrives once, in order. Unread echo segments each hold an RX mbuf, so
/// a short segment among full ones leaves no room before 8 KiB are unread.
#[zhida_test_support::pinned_test]
fn server_stops_reading_while_echo_blocked() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["ssra", "ssrb"], [1, 2]);
        let mut net = Net::new(&mut pair, BUFFER);
        let mut client = net.open(CLIENT_PORT);
        let messages: Vec<Message> = (0..4)
            .map(|seed| Message::binary(pattern(1 << 20, seed)))
            .collect();
        for message in &messages {
            net.write(&mut client, message.clone());
        }
        loop {
            let flushed = net.try_flush(&mut client);
            assert!(
                !flushed,
                "all 4 MiB left the client: the server kept reading"
            );
            let moved = net.try_round().unwrap();
            let socket = net.a.tcp(client.handle.as_ref().unwrap());
            let full = socket.send_queue() == socket.send_capacity();
            if !moved && full && socket.recv_room() == 0 {
                break;
            }
            net.settle(moved);
        }
        assert!(net.server.endings().is_empty());
        for message in &messages {
            let got = net.until(|net| {
                net.try_flush(&mut client);
                net.try_read(&mut client)
            });
            assert!(got.unwrap() == *message, "echo out of order or changed");
        }
        assert_eq!(net.a.tcp(client.handle.as_ref().unwrap()).recv_queue(), 0);
        net.close_ws(&mut client);
        assert_eq!(net.server.endings(), &endings(&[("ConnectionClosed", 1)]));
        drop(net);
        close(pair);
    });
}

/// The client sends 125-byte Pings and reads nothing through a 4 KiB
/// receive window. Once a Pong cannot be sent, the server stops reading: the
/// rounds go quiet with the client's socket full both ways, its flush
/// blocked and Pings unread in the server's receive buffer. tungstenite's
/// `read` alone keeps reading while its Pong is unsent, so a server without
/// the flush after each control message would take every Ping. Then the
/// client reads one Pong per Ping, in order, and the server reads them all.
#[zhida_test_support::pinned_test]
fn ping_flood_with_zero_window_stops_reading() {
    /// Far more Ping bytes than every buffer between the two applications
    /// holds.
    const MAX_PINGS: u32 = 1000;
    let ping = |i: u32| {
        let mut payload = pattern(125, i);
        payload[..4].copy_from_slice(&i.to_be_bytes());
        payload
    };
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["pfza", "pfzb"], [1, 2]);
        let mut net = Net::new(&mut pair, 4096);
        let mut client = net.open_with(socket(4096, 4096), CLIENT_PORT);
        let mut sent = 0;
        loop {
            if net.try_flush(&mut client) {
                assert!(
                    sent < MAX_PINGS,
                    "{sent} Pings left the client: the server kept reading"
                );
                net.write(&mut client, Message::Ping(ping(sent).into()));
                sent += 1;
                continue;
            }
            let moved = net.try_round().unwrap();
            let socket = net.a.tcp(client.handle.as_ref().unwrap());
            let full = socket.send_queue() == socket.send_capacity()
                && socket.recv_room() == 0;
            if !moved && full {
                break;
            }
            net.settle(moved);
        }
        let server_socket = net.server.socket().unwrap();
        assert!(server_socket.recv_queue() > 0, "the server read every Ping");
        assert!(net.server.endings().is_empty());
        for i in 0..sent {
            let got = net.until(|net| {
                net.try_flush(&mut client);
                net.try_read(&mut client)
            });
            assert_eq!(got.unwrap(), Message::Pong(ping(i).into()));
        }
        assert_eq!(net.server.socket().unwrap().recv_queue(), 0);
        net.echo(&mut client, Message::text("after the flood"));
        net.close_ws(&mut client);
        assert_eq!(net.server.endings(), &endings(&[("ConnectionClosed", 1)]));
        drop(net);
        close(pair);
    });
}

/// The client closes TCP and connects again before A's next turn: its FIN
/// and the new SYN reach B in one burst. The SYN finds a listener (the
/// replacement added when the first connection was accepted), so no RST: the
/// second connection establishes and the first ends in the client's
/// TIME-WAIT.
#[zhida_test_support::pinned_test]
fn next_syn_in_same_burst_as_client_fin_is_accepted() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["nsba", "nsbb"], [2, 3]);
        let mut net = Net::new(&mut pair, BUFFER);
        let mut first = net.open(CLIENT_PORT);
        net.echo(&mut first, Message::text("one"));
        net.a.tcp_mut(first.handle.as_ref().unwrap()).close();
        let second = net.connect(socket(BUFFER, BUFFER), CLIENT_PORT + 1);
        assert_eq!(net.state(first.handle.as_ref().unwrap()), State::FinWait1);
        assert_eq!(net.state(&second), State::SynSent);
        net.wait_state(&second, State::Established);
        let response = net.upgrade(&second, &request(Some(KEY)));
        assert!(response.starts_with("HTTP/1.1 101 "), "{response}");
        let mut second = Client {
            handle: Some(second),
            pending: None,
            ws: WebSocketContext::new(Role::Client, None),
        };
        net.echo(&mut second, Message::text("two"));
        net.close_ws(&mut second);
        net.wait_state(first.handle.as_ref().unwrap(), State::TimeWait);
        assert_eq!(net.server.accepted(), 2);
        // The first session read EOF without a close handshake.
        assert_eq!(
            net.server.endings(),
            &endings(&[("ConnectionClosed", 1), ("Protocol", 1)])
        );
        drop(net);
        close(pair);
    });
}

/// The client's handshake ACK is held on A's ring while it aborts, so the
/// ACK and the RST reach B in one turn: the listener goes SynReceived ->
/// Established -> Closed without a step seeing it Established. It is
/// replaced anyway (not counted as accepted), so the next client connects.
#[zhida_test_support::pinned_test]
fn establish_and_reset_in_one_turn_still_relistens() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["erra", "errb"], [2, 3]);
        let mut net = Net::new(&mut pair, BUFFER);
        let doomed = net.connect(socket(BUFFER, BUFFER), CLIENT_PORT);
        let syn_sent = Rc::new(Cell::new(false));
        let seen = syn_sent.clone();
        net.a_to_b.impair(move |frame| {
            if tcp_control(frame, Side::A) == Some(TcpControl::Syn) {
                seen.set(true);
            }
            Verdict::Deliver
        });
        // The round that delivers the SYN also puts B's SYN-ACK on A's RX
        // ring.
        net.until(|_| syn_sent.get().then_some(()));
        assert_eq!(net.state(&doomed), State::SynSent);
        net.a_to_b.paused = true;
        net.try_round().unwrap();
        assert_eq!(net.state(&doomed), State::Established);
        net.a.tcp_mut(&doomed).abort();
        net.a_to_b.paused = false;
        net.try_round().unwrap();
        assert_eq!(net.state(&doomed), State::Closed);
        assert_eq!(net.server.accepted(), 0);
        assert!(net.server.socket().is_none());
        let slots = [0; 2].map(|_| net.server.stack().add_tcp(socket(BUFFER, BUFFER)).unwrap());
        for handle in slots {
            net.server.stack().remove_tcp(handle);
        }
        let mut client = net.open(CLIENT_PORT + 1);
        net.echo(&mut client, Message::text("after the reset"));
        net.close_ws(&mut client);
        assert_eq!(net.server.accepted(), 1);
        drop(net);
        close(pair);
    });
}

/// As above, with every slot of B's Stack in use when the listener ends
/// Closed: the Server listens again on the same socket instead of adding a
/// replacement, so the full Stack is no error.
#[zhida_test_support::pinned_test]
fn closed_listener_relistens_on_full_stack() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["crla", "crlb"], [2, 2]);
        let mut net = Net::new(&mut pair, BUFFER);
        let filler = net.server.stack().add_tcp(socket(BUFFER, BUFFER)).unwrap();
        let doomed = net.connect(socket(BUFFER, BUFFER), CLIENT_PORT);
        let syn_sent = Rc::new(Cell::new(false));
        let seen = syn_sent.clone();
        net.a_to_b.impair(move |frame| {
            if tcp_control(frame, Side::A) == Some(TcpControl::Syn) {
                seen.set(true);
            }
            Verdict::Deliver
        });
        net.until(|_| syn_sent.get().then_some(()));
        net.a_to_b.paused = true;
        net.try_round().unwrap();
        assert_eq!(net.state(&doomed), State::Established);
        net.a.tcp_mut(&doomed).abort();
        net.a_to_b.paused = false;
        net.try_round().unwrap();
        assert_eq!(net.server.accepted(), 0);
        assert!(matches!(
            net.server.stack().add_tcp(socket(BUFFER, BUFFER)),
            Err(AddTcpError::SocketsFull(config)) if config == socket(BUFFER, BUFFER)
        ));
        net.server.stack().remove_tcp(filler);
        let mut client = net.open(CLIENT_PORT + 1);
        net.echo(&mut client, Message::text("after the reset"));
        net.close_ws(&mut client);
        assert_eq!(net.server.accepted(), 1);
        drop(net);
        close(pair);
    });
}

/// Every frame either way is checked as it crosses: no RST in any of the
/// twenty handshakes, echoes or closes.
#[zhida_test_support::pinned_test]
fn twenty_sequential_connections_no_rst() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["tsca", "tscb"], [20, 21]);
        let mut net = Net::new(&mut pair, BUFFER);
        forbid_rst(net.a_to_b, Side::A);
        forbid_rst(net.b_to_a, Side::B);
        for i in 0..20 {
            let mut client = net.open(CLIENT_PORT + i);
            net.echo(&mut client, Message::text(format!("connection {i}")));
            net.close_ws(&mut client);
        }
        assert_eq!(net.server.accepted(), 20);
        assert_eq!(net.server.endings(), &endings(&[("ConnectionClosed", 20)]));
        drop(net);
        close(pair);
    });
}

/// A SYN on the open session's 4-tuple reaches B while B listens again on a
/// higher slot. Capture the original client's SYN while delivering it at
/// open time, then replay it into B through Link::inject. The live connection
/// answers with a challenge ACK (RFC 5961 §4.2), the listener accepts nothing,
/// and the session keeps echoing. A's original client receives the ACK.
#[zhida_test_support::pinned_test]
fn dup_syn_reaches_live_connection_not_listener() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["dsla", "dslb"], [2, 2]);
        let mut net = Net::new(&mut pair, BUFFER);
        let original_syn = Rc::new(RefCell::new(None));
        let captured = original_syn.clone();
        net.a_to_b.impair(move |frame| {
            if tcp_control(frame, Side::A) == Some(TcpControl::Syn) {
                assert!(captured.borrow().is_none());
                *captured.borrow_mut() = Some(frame.to_vec());
            }
            Verdict::Deliver
        });
        let mut client = net.open(CLIENT_PORT);
        net.echo(&mut client, Message::text("before"));
        net.until(|net| {
            let quiet = net.a.poll_at().is_none() && net.server.stack().poll_at().is_none();
            quiet.then_some(())
        });
        let segments = Rc::new(RefCell::new(Vec::new()));
        for (link, src) in [(&mut *net.a_to_b, Side::A), (&mut *net.b_to_a, Side::B)] {
            let segments = segments.clone();
            link.impair(move |frame| {
                if let Some(control) = tcp_control(frame, src) {
                    let tcp = segment(frame, src);
                    segments.borrow_mut().push((
                        src,
                        tcp.src_port,
                        control,
                        tcp.ack_number.is_some(),
                        tcp.payload.len(),
                    ));
                }
                Verdict::Deliver
            });
        }

        let syn = original_syn.borrow_mut().take().unwrap();
        let tcp = segment(&syn, Side::A);
        segments.borrow_mut().push((
            Side::A,
            tcp.src_port,
            tcp.control,
            tcp.ack_number.is_some(),
            tcp.payload.len(),
        ));
        net.a_to_b.inject(&syn);
        while net.try_round().unwrap() {}
        assert_eq!(
            *segments.borrow(),
            [(Side::A, CLIENT_PORT, TcpControl::Syn, false, 0),
             (Side::B, SERVER_PORT, TcpControl::None, true, 0)],
            "TCP segments after the duplicate SYN"
        );
        assert_eq!(
            net.server.socket().unwrap().state(),
            State::Established
        );
        assert_eq!(net.server.accepted(), 1);

        net.echo(&mut client, Message::text("after the duplicate SYN"));
        net.close_ws(&mut client);
        assert_eq!(net.server.accepted(), 1);
        assert_eq!(net.server.endings(), &endings(&[("ConnectionClosed", 1)]));
        drop(net);
        close(pair);
    });
}

/// Two connections reach Established before either upgrades: the first
/// becomes the session and the second waits. Once the first session's
/// close handshake ends it, the second upgrades and echoes.
#[zhida_test_support::pinned_test]
fn waiting_connection_is_served_after_current_session() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["wcsa", "wcsb"], [2, 3]);
        let mut net = Net::new(&mut pair, BUFFER);
        let handles = [0, 1].map(|i| {
            let handle = net.connect(socket(BUFFER, BUFFER), CLIENT_PORT + i);
            net.wait_state(&handle, State::Established);
            handle
        });
        assert_eq!(net.server.accepted(), 2);
        let [first_handle, second_handle] = handles;
        let mut first = net.upgrade_ws(first_handle);
        net.echo(&mut first, Message::text("first"));
        net.close_ws(&mut first);
        assert_eq!(net.server.endings(), &endings(&[("ConnectionClosed", 1)]));
        let mut second = net.upgrade_ws(second_handle);
        net.echo(&mut second, Message::text("second"));
        net.close_ws(&mut second);
        assert_eq!(net.server.accepted(), 2);
        assert_eq!(net.server.endings(), &endings(&[("ConnectionClosed", 2)]));
        drop(net);
        close(pair);
    });
}

#[zhida_test_support::pinned_test]
fn failed_listen_releases_admitted_socket() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["sbadporta", "sbadportb"], [1, 1]);
        assert!(matches!(
            Server::new(&mut pair.b, 0, BUFFER),
            Err(ServerError::Listen(tcp::ListenError::Unaddressable))
        ));
        let handle = pair.b.add_tcp(socket(BUFFER, BUFFER)).unwrap();
        pair.b.listen(&handle, SERVER_PORT).unwrap();
        assert_eq!(pair.b.tcp(&handle).state(), State::Listen);
        pair.b.remove_tcp(handle);
        close(pair);
    });
}

/// Three slots: the listener plus two accepted connections. Accepting the
/// third leaves no slot for its replacement listener.
#[zhida_test_support::pinned_test]
fn socket_limit_is_an_error() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["slea", "sleb"], [3, 3]);
        let mut net = Net::new(&mut pair, BUFFER);
        for i in 0..2 {
            let mut client = net.open(CLIENT_PORT + i);
            net.close_ws(&mut client);
        }
        let _third = net.connect(socket(BUFFER, BUFFER), CLIENT_PORT + 2);
        let error = net.until_error();
        assert!(matches!(error, ServerError::SocketsFull), "{error}");
        assert_eq!(net.server.accepted(), 2);
        drop(net);
        close(pair);
    });
}

/// One session runs (its handshake not yet sent) and one accepted
/// connection waits; a third accepted connection is an error.
#[zhida_test_support::pinned_test]
fn second_waiting_connection_is_an_error() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["swca", "swcb"], [3, 4]);
        let mut net = Net::new(&mut pair, BUFFER);
        let _waiting: Vec<_> = (0..2).map(|i| {
            let handle = net.connect(socket(BUFFER, BUFFER), CLIENT_PORT + i);
            net.wait_state(&handle, State::Established);
            handle
        }).collect();
        assert_eq!(net.server.accepted(), 2);
        let _third = net.connect(socket(BUFFER, BUFFER), CLIENT_PORT + 2);
        let error = net.until_error();
        assert!(matches!(error, ServerError::SecondWaiting), "{error}");
        drop(net);
        close(pair);
    });
}

#[zhida_test_support::pinned_test]
fn handshake_failure_is_an_error() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["hfea", "hfeb"], [1, 2]);
        let mut net = Net::new(&mut pair, BUFFER);
        let handle = net.connect(socket(BUFFER, BUFFER), CLIENT_PORT);
        net.wait_state(&handle, State::Established);
        let request = request(None);
        assert_eq!(
            net.a.tcp_mut(&handle).send_slice(&request),
            Ok(request.len())
        );
        let error = net.until_error();
        assert!(
            matches!(
                error,
                ServerError::Handshake(Error::Protocol(ProtocolError::MissingSecWebSocketKey))
            ),
            "{error}"
        );
        drop(net);
        close(pair);
    });
}

/// The deadline counts from the step that accepted the connection: a step
/// exactly 120 s later is fine, one microsecond more fails.
#[zhida_test_support::pinned_test]
fn deadline_expires_after_120_seconds() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["dlea", "dleb"], [1, 2]);
        let mut net = Net::new(&mut pair, BUFFER);
        let handle = net.connect(socket(BUFFER, BUFFER), CLIENT_PORT);
        let accepted_at = net.until(|net| (net.server.accepted() == 1).then(|| net.rounds.now()));
        let response = net.upgrade(&handle, &request(Some(KEY)));
        assert!(response.starts_with("HTTP/1.1 101 "), "{response}");
        let limit = accepted_at + Duration::from_secs(120);
        net.server.step(limit).unwrap();
        let error = net
            .server
            .step(limit + Duration::from_micros(1))
            .unwrap_err();
        assert!(
            matches!(error, ServerError::Deadline { accepted_at: at, .. } if at == accepted_at),
            "{error}"
        );
        drop(net);
        close(pair);
    });
}

/// A client sends half its upgrade request and stalls: the deadline also
/// ends a session still in its handshake, a step exactly 120 s after
/// acceptance fine, one microsecond more failing.
#[zhida_test_support::pinned_test]
fn handshake_deadline_expires_after_120_seconds() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["hdea", "hdeb"], [1, 2]);
        let mut net = Net::new(&mut pair, BUFFER);
        let handle = net.connect(socket(BUFFER, BUFFER), CLIENT_PORT);
        let accepted_at = net.until(|net| (net.server.accepted() == 1).then(|| net.rounds.now()));
        let request = request(Some(KEY));
        let half = &request[..request.len() / 2];
        assert_eq!(net.a.tcp_mut(&handle).send_slice(half), Ok(half.len()));
        net.until(|net| (net.a.tcp(&handle).send_queue() == 0).then_some(()));
        assert_eq!(
            net.server.socket().unwrap().recv_queue(),
            0,
            "the handshake read the partial request"
        );
        let limit = accepted_at + Duration::from_secs(120);
        net.server.step(limit).unwrap();
        let error = net
            .server
            .step(limit + Duration::from_micros(1))
            .unwrap_err();
        assert!(
            matches!(error, ServerError::Deadline { accepted_at: at, .. } if at == accepted_at),
            "{error}"
        );
        drop(net);
        close(pair);
    });
}
