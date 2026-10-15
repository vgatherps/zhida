//! `Client` over two Stacks on lossless net_ring links. B runs the Client;
//! A is a test peer playing fuzzingserver's protocol: one listener per
//! expected connection, tungstenite's `accept_hdr` on each once its whole
//! upgrade request is drained into a Cursor. Its `WebSocketContext` keeps a
//! pending frame between Stack borrows. Like fuzzingserver it sends its Close right after
//! its last message and closes TCP once the close handshake completed.

use std::collections::BTreeMap;
use std::io::{Cursor, ErrorKind};

use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::socket::tcp::{self, State};
use dpdk_smoltcp::smoltcp::time::{Duration, Instant};
use dpdk_smoltcp::smoltcp::wire::IpEndpoint;
use dpdk_smoltcp::{Stack, StackConfig};
use tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tungstenite::protocol::{Role, WebSocketContext};
use tungstenite::{Error, Message};
use ws_autobahn::{Client, ClientError};
#[path = "common/stream.rs"]
mod stream;
use stream::with_stream;

use zhida_test_kit::{pair, wire, with_eal};
use pair::{assert_lossless, config, pattern, Pair, Rounds, Side, SERVER_PORT, T0};
use wire::Link;

/// Socket buffers each way, both sides (see tests/server.rs).
const BUFFER: usize = 8 * 1024;
/// The Client's first local port.
const FIRST_PORT: u16 = 49152;
/// smoltcp's TIME-WAIT duration (tcp.rs CLOSE_DELAY).
const TIME_WAIT: Duration = Duration::from_secs(10);

/// A with `sockets[0]` slots, B with `sockets[1]`.
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

fn would_block(error: &Error) -> bool {
    matches!(error, Error::Io(io) if io.kind() == ErrorKind::WouldBlock)
}

fn endings(pairs: &[(&'static str, usize)]) -> BTreeMap<&'static str, usize> {
    pairs.iter().copied().collect()
}

/// One accepted connection of the peer.
struct Peer {
    /// The Client's connection index.
    connection: usize,
    handle: Option<TcpHandle>,
    pending: Option<(tcp::TcpFrame, usize)>,
    ws: WebSocketContext,
}

/// A's Stack (the peer) and the links, the Client holding B's Stack.
struct Net<'p> {
    rounds: Rounds,
    a: &'p mut Stack,
    a_to_b: &'p mut Link,
    b_to_a: &'p mut Link,
    client: Client<'p>,
    /// Listener i takes connection i: a SYN goes to the first listener in
    /// slot order, and earlier ones are taken.
    listeners: Vec<Option<TcpHandle>>,
}

impl<'p> Net<'p> {
    /// `listeners` listeners on A's SERVER_PORT; a Client on B expecting
    /// `cases` cases from it.
    fn new(pair: &'p mut Pair, cases: usize, listeners: usize) -> Self {
        let rounds = Rounds::new(pair.now());
        let Pair {
            a,
            b,
            a_to_b,
            b_to_a,
            ..
        } = pair;
        let listeners = (0..listeners)
            .map(|_| {
                let socket = tcp::Config { rx_capacity: BUFFER, tx_capacity: BUFFER, mss_cap: None };
                let handle = a.add_tcp(socket).unwrap();
                a.listen(&handle, SERVER_PORT).unwrap();
                Some(handle)
            })
            .collect();
        let server = IpEndpoint::new(Side::A.ip().into(), SERVER_PORT);
        Self {
            rounds,
            a,
            a_to_b,
            b_to_a,
            client: Client::new(b, server, cases, BUFFER).unwrap(),
            listeners,
        }
    }

    /// A round with B turned by `Client::step`.
    fn try_round(&mut self) -> Result<bool, ClientError> {
        let mut stepped = Ok(false);
        let client = &mut self.client;
        let moved = self
            .rounds
            .round_with(self.a, self.a_to_b, self.b_to_a, |now| {
                stepped = client.step(now);
                matches!(stepped, Ok(true))
            });
        stepped.map(|_| moved)
    }

    fn settle(&mut self, moved: bool) {
        self.rounds.settle(moved, self.a, self.client.stack());
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

    /// Rounds until the Client fails.
    fn until_error(&mut self) -> ClientError {
        loop {
            match self.try_round() {
                Ok(moved) => self.settle(moved),
                Err(error) => return error,
            }
        }
    }

    fn wait_state(&mut self, handle: &TcpHandle, state: State) {
        self.until(|net| (net.a.tcp(&handle).state() == state).then_some(()));
    }

    /// Drain the listener's request until its final blank line arrives.
    fn request_buffered(&mut self, handle: &TcpHandle, request: &mut Vec<u8>) -> bool {
        let socket = self.a.tcp_mut(handle);
        if socket.state() != State::Established {
            return false;
        }
        request.extend_from_slice(&pair::drain_bytes(socket).unwrap());
        request.ends_with(b"\r\n\r\n")
    }

    /// Connection `i`: on listener i, from the Client's port
    /// `FIRST_PORT + i`, upgraded by tungstenite's server handshake in one
    /// call. Returns the peer and the request's path and query.
    fn accept(&mut self, i: usize) -> (Peer, String) {
        let handle = self.listeners[i].take().unwrap();
        let mut request = Vec::new();
        self.until(|net| net.request_buffered(&handle, &mut request).then_some(()));
        let remote = self.a.tcp(&handle).remote_endpoint().unwrap();
        assert_eq!(remote.port, FIRST_PORT + i as u16);
        let mut path = None;
        let callback = |request: &Request, response: Response| {
            path = Some(request.uri().to_string());
            Ok::<_, ErrorResponse>(response)
        };
        let request_len = request.len();
        let accepted = tungstenite::accept_hdr(Cursor::new(request), callback);
        let Ok(ws) = accepted else {
            panic!("upgrade of connection {i} not done in one call");
        };
        let bytes = ws.into_inner().into_inner();
        let response = &bytes[request_len..];
        assert_eq!(self.a.tcp_mut(&handle).send_slice(response), Ok(response.len()));
        let peer = Peer {
            connection: i,
            handle: Some(handle),
            pending: None,
            ws: WebSocketContext::new(Role::Server, None),
        };
        (peer, path.unwrap())
    }

    /// `ws.write`; a WouldBlock leaves the frame buffered in tungstenite.
    fn write(&mut self, peer: &mut Peer, message: Message) {
        with_stream(self.a, &mut peer.handle, &mut peer.pending, |stream| {
            match peer.ws.write(stream, message) {
                Err(error) if !would_block(&error) => panic!("peer write: {error}"),
                _ => {}
            }
        })
    }

    fn try_flush(&mut self, peer: &mut Peer) -> bool {
        with_stream(self.a, &mut peer.handle, &mut peer.pending, |stream| {
            match peer.ws.flush(stream) {
                Ok(()) => true,
                Err(error) if would_block(&error) => false,
                Err(error) => panic!("peer flush: {error}"),
            }
        })
    }

    fn flush(&mut self, peer: &mut Peer) {
        if !self.try_flush(peer) {
            self.until(|net| net.try_flush(peer).then_some(()));
        }
    }

    fn try_read(&mut self, peer: &mut Peer) -> Option<Result<Message, Error>> {
        with_stream(self.a, &mut peer.handle, &mut peer.pending, |stream| {
            match peer.ws.read(stream) {
                Err(error) if would_block(&error) => None,
                other => Some(other),
            }
        })
    }

    fn read(&mut self, peer: &mut Peer) -> Result<Message, Error> {
        match self.try_read(peer) {
            Some(result) => result,
            None => self.until(|net| net.try_read(peer)),
        }
    }

    /// Sends `messages` then Close, reads the client's Close and the end of
    /// the handshake, then closes TCP first. The peer's socket must reach
    /// TIME-WAIT, so its FIN went first, while the client's is LastAck or
    /// Closed: it closed from CloseWait, not first (which would leave it in
    /// TIME-WAIT). Checked within 10 s of the peer's close, so no clock jump
    /// can have expired a client TIME-WAIT.
    fn send_and_close(&mut self, peer: &mut Peer, messages: &[Message]) {
        for message in messages {
            self.write(peer, message.clone());
        }
        self.write(peer, Message::Close(None));
        self.flush(peer);
        assert_eq!(self.read(peer).unwrap(), Message::Close(None));
        assert!(matches!(self.read(peer), Err(Error::ConnectionClosed)));
        self.a.tcp_mut(peer.handle.as_ref().unwrap()).close();
        let closed_at = self.rounds.now();
        self.wait_state(peer.handle.as_ref().unwrap(), State::TimeWait);
        assert!(self.rounds.now() - closed_at < TIME_WAIT);
        let client = self.client_state(peer.connection);
        assert!(
            matches!(client, State::LastAck | State::Closed),
            "connection {}: client socket {client}",
            peer.connection
        );
    }

    /// getCaseCount on connection 0, answered with `count`.
    fn case_count(&mut self, count: &str) {
        let (mut peer, path) = self.accept(0);
        assert_eq!(path, "/getCaseCount");
        self.send_and_close(&mut peer, &[Message::text(count)]);
    }

    /// runCase `case` on connection `case`: `message` must come back
    /// exactly.
    fn run_case(&mut self, case: usize, message: Message) {
        let (mut peer, path) = self.accept(case);
        assert_eq!(path, format!("/runCase?case={case}&agent=Tungstenite"));
        self.write(&mut peer, message.clone());
        self.flush(&mut peer);
        assert_eq!(self.read(&mut peer).unwrap(), message);
        self.send_and_close(&mut peer, &[]);
    }

    /// updateReports on connection `connection`.
    fn update_reports(&mut self, connection: usize) {
        let (mut peer, path) = self.accept(connection);
        assert_eq!(path, "/updateReports?agent=Tungstenite");
        self.send_and_close(&mut peer, &[]);
    }

    fn client_state(&mut self, connection: usize) -> State {
        self.client.socket(connection).state()
    }

    /// Connection 0 was connected at `connected_at`: a step exactly 120 s
    /// later is fine, one microsecond more fails with `Deadline`.
    fn expire_deadline(&mut self, connected_at: Instant) {
        let limit = connected_at + Duration::from_secs(120);
        self.client.step(limit).unwrap();
        let error = self
            .client
            .step(limit + Duration::from_micros(1))
            .unwrap_err();
        assert!(
            matches!(
                error,
                ClientError::Deadline { connection: 0, connected_at: at, .. } if at == connected_at
            ),
            "{error}"
        );
    }
}

/// Each connection arrives from the next local port (checked by `accept`),
/// every echo is exact, every session ends with the close handshake and the
/// peer closing TCP first (checked by `send_and_close` before any clock
/// jump past TIME-WAIT), and every client socket ends Closed.
#[zhida_test_support::pinned_test]
fn client_runs_cases_with_distinct_local_ports() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["crca", "crcb"], [4, 4]);
        let mut net = Net::new(&mut pair, 2, 4);
        net.case_count("2");
        net.run_case(1, Message::text("case one"));
        net.run_case(2, Message::binary(pattern(3000, 1)));
        net.update_reports(3);
        net.until(|net| net.client.done().then_some(()));
        assert_eq!(net.client.endings(), &endings(&[("ConnectionClosed", 4)]));
        assert_eq!(net.client.handles().len(), 4);
        for i in 0..4 {
            net.until(|net| (net.client_state(i) == State::Closed).then_some(()));
        }
        drop(net);
        close(pair);
    });
}

#[zhida_test_support::pinned_test]
fn case_count_mismatch_is_an_error() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["ccma", "ccmb"], [4, 4]);
        let mut net = Net::new(&mut pair, 2, 4);
        let (mut peer, _) = net.accept(0);
        net.write(&mut peer, Message::text("3"));
        net.flush(&mut peer);
        let error = net.until_error();
        assert!(
            matches!(
                &error,
                ClientError::CaseCount { expected: 2, got } if *got == Message::text("3")
            ),
            "{error}"
        );
        drop(net);
        close(pair);
    });
}

/// Case 1's peer sends a frame with RSV1 set: the client fails the
/// connection and closes TCP first, so its socket goes to TIME-WAIT and is
/// kept; case 2 still connects from the next port and runs.
#[zhida_test_support::pinned_test]
fn client_closes_first_keeps_time_wait_socket() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["ctwa", "ctwb"], [4, 4]);
        let mut net = Net::new(&mut pair, 2, 4);
        net.case_count("2");
        let (peer, _) = net.accept(1);
        // FIN + RSV1 + text, unmasked, 1 byte.
        let frame = [0xc1, 0x01, b'x'];
        assert_eq!(
            net.a.tcp_mut(peer.handle.as_ref().unwrap()).send_slice(&frame),
            Ok(frame.len())
        );
        net.wait_state(peer.handle.as_ref().unwrap(), State::CloseWait);
        assert_eq!(net.a.tcp(peer.handle.as_ref().unwrap()).recv_queue(), 0, "no close frame");
        assert_eq!(
            net.client.endings(),
            &endings(&[("ConnectionClosed", 1), ("Protocol", 1)])
        );
        net.a.tcp_mut(peer.handle.as_ref().unwrap()).close();
        net.wait_state(peer.handle.as_ref().unwrap(), State::Closed);
        assert_eq!(net.client_state(1), State::TimeWait);
        net.run_case(2, Message::text("after the failure"));
        net.update_reports(3);
        net.until(|net| net.client.done().then_some(()));
        assert_eq!(
            net.client.endings(),
            &endings(&[("ConnectionClosed", 3), ("Protocol", 1)])
        );
        assert_eq!(net.client.handles().len(), 4);
        drop(net);
        close(pair);
    });
}

/// No listener on A: the SYN gets a RST.
#[zhida_test_support::pinned_test]
fn refused_connect_is_an_error() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["rcea", "rceb"], [1, 4]);
        let mut net = Net::new(&mut pair, 2, 0);
        let error = net.until_error();
        assert!(
            matches!(error, ClientError::NotEstablished { connection: 0 }),
            "{error}"
        );
        drop(net);
        close(pair);
    });
}

/// The peer never answers the upgrade request: the deadline fires while
/// the client is handshaking.
#[zhida_test_support::pinned_test]
fn deadline_expires_while_handshaking() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["dexa", "dexb"], [1, 4]);
        let mut net = Net::new(&mut pair, 2, 1);
        let connected_at = net.rounds.now();
        let listener = net.listeners[0].take().unwrap();
        let mut request = Vec::new();
        net.until(|net| net.request_buffered(&listener, &mut request).then_some(()));
        net.expire_deadline(connected_at);
        drop(net);
        close(pair);
    });
}

/// B→A paused: the SYN never arrives, so the deadline fires while the
/// client's socket is SynSent (it can only stay SynSent: Closed would fail
/// the step at the limit with NotEstablished).
#[zhida_test_support::pinned_test]
fn deadline_expires_while_connecting() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["dcna", "dcnb"], [1, 4]);
        let mut net = Net::new(&mut pair, 2, 1);
        net.b_to_a.paused = true;
        let connected_at = net.rounds.now();
        assert!(net.try_round().unwrap());
        assert_eq!(net.client_state(0), State::SynSent);
        net.expire_deadline(connected_at);
        drop(net);
        close(pair);
    });
}

/// getCaseCount's peer pings after the upgrade and gets the Pong, which only
/// an open WebSocket sends, then stalls: the deadline fires while Open.
#[zhida_test_support::pinned_test]
fn deadline_expires_while_open() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["dopa", "dopb"], [1, 4]);
        let mut net = Net::new(&mut pair, 2, 1);
        let connected_at = net.rounds.now();
        let (mut peer, _) = net.accept(0);
        net.write(&mut peer, Message::Ping("open".into()));
        net.flush(&mut peer);
        assert_eq!(net.read(&mut peer).unwrap(), Message::Pong("open".into()));
        net.expire_deadline(connected_at);
        drop(net);
        close(pair);
    });
}

/// getCaseCount's peer sends the right count, then closes TCP without a
/// Close: the client's Close gets no reply and its read ends Protocol.
#[zhida_test_support::pinned_test]
fn case_count_then_tcp_close_is_an_error() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["cfca", "cfcb"], [4, 4]);
        let mut net = Net::new(&mut pair, 2, 4);
        let (mut peer, _) = net.accept(0);
        net.write(&mut peer, Message::text("2"));
        net.flush(&mut peer);
        net.a.tcp_mut(peer.handle.as_ref().unwrap()).close();
        let error = net.until_error();
        assert!(
            matches!(
                error,
                ClientError::ControlEnding {
                    connection: 0,
                    ending: "Protocol"
                }
            ),
            "{error}"
        );
        drop(net);
        close(pair);
    });
}

/// getCaseCount's peer completes a close handshake without sending the
/// count: ConnectionClosed before the client's own Close is a failure.
#[zhida_test_support::pinned_test]
fn case_count_missing_is_an_error() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["cmia", "cmib"], [4, 4]);
        let mut net = Net::new(&mut pair, 2, 4);
        let (mut peer, _) = net.accept(0);
        net.write(&mut peer, Message::Close(None));
        net.flush(&mut peer);
        assert_eq!(net.read(&mut peer).unwrap(), Message::Close(None));
        assert!(matches!(net.read(&mut peer), Err(Error::ConnectionClosed)));
        net.a.tcp_mut(peer.handle.as_ref().unwrap()).close();
        let error = net.until_error();
        assert!(
            matches!(
                error,
                ClientError::ControlEnding {
                    connection: 0,
                    ending: "ConnectionClosed"
                }
            ),
            "{error}"
        );
        drop(net);
        close(pair);
    });
}

/// getCaseCount's peer sends a second message after the count, which the
/// client already answered with its Close.
#[zhida_test_support::pinned_test]
fn case_count_extra_message_is_an_error() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["cxma", "cxmb"], [4, 4]);
        let mut net = Net::new(&mut pair, 2, 4);
        let (mut peer, _) = net.accept(0);
        net.write(&mut peer, Message::text("2"));
        net.write(&mut peer, Message::text("extra"));
        net.flush(&mut peer);
        let error = net.until_error();
        assert!(
            matches!(
                &error,
                ClientError::ControlMessage { connection: 0, message }
                    if *message == Message::text("extra")
            ),
            "{error}"
        );
        drop(net);
        close(pair);
    });
}

/// updateReports' peer reads the client's Close, then closes TCP without
/// replying: the client's read ends Protocol.
#[zhida_test_support::pinned_test]
fn update_reports_without_close_reply_is_an_error() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["urna", "urnb"], [3, 3]);
        let mut net = Net::new(&mut pair, 1, 3);
        net.case_count("1");
        net.run_case(1, Message::text("case one"));
        let (mut peer, path) = net.accept(2);
        assert_eq!(path, "/updateReports?agent=Tungstenite");
        assert_eq!(net.read(&mut peer).unwrap(), Message::Close(None));
        net.a.tcp_mut(peer.handle.as_ref().unwrap()).close();
        let error = net.until_error();
        assert!(
            matches!(
                error,
                ClientError::ControlEnding {
                    connection: 2,
                    ending: "Protocol"
                }
            ),
            "{error}"
        );
        drop(net);
        close(pair);
    });
}

/// The peer answers the upgrade request with 404: the handshake fails,
/// which is fatal.
#[zhida_test_support::pinned_test]
fn non_101_response_is_a_handshake_error() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["nhra", "nhrb"], [1, 4]);
        let mut net = Net::new(&mut pair, 2, 1);
        let listener = net.listeners[0].take().unwrap();
        let mut request = Vec::new();
        net.until(|net| net.request_buffered(&listener, &mut request).then_some(()));
        let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            net.a.tcp_mut(&listener).send_slice(response),
            Ok(response.len())
        );
        let error = net.until_error();
        assert!(
            matches!(
                &error,
                ClientError::Handshake(Error::Http(response)) if response.status() == 404
            ),
            "{error}"
        );
        drop(net);
        close(pair);
    });
}

/// Local port `FIRST_PORT + i` for every connection i in 0..=cases + 1 must
/// fit a u16: 16382 cases fit, 16383 do not, and usize::MAX is rejected
/// rather than overflowing the bound.
#[zhida_test_support::pinned_test]
fn too_many_cases_is_an_error() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["tmca", "tmcb"], [1, 1]);
        let server = IpEndpoint::new(Side::A.ip().into(), SERVER_PORT);
        assert!(Client::new(&mut pair.b, server, 16382, BUFFER).is_ok());
        for cases in [16383, usize::MAX] {
            let Err(error) = Client::new(&mut pair.b, server, cases, BUFFER) else {
                panic!("Client::new accepted {cases} cases");
            };
            assert!(
                matches!(error, ClientError::TooManyCases(n) if n == cases),
                "{error}"
            );
        }
        close(pair);
    });
}
