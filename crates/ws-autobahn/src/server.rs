//! WebSocket echo server over a `Stack`, one session at a time, for Autobahn's
//! fuzzingclient (port of tungstenite examples/autobahn-server.rs).

use std::collections::BTreeMap;
use std::fmt;

use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::socket::tcp::{self, State};
use dpdk_smoltcp::smoltcp::time::{Duration, Instant};
use dpdk_smoltcp::{AddTcpError, Stack, StackError, Turn};
use tungstenite::handshake::server::NoCallback;
use tungstenite::handshake::MidHandshake;
use tungstenite::{accept_with_config, Error, HandshakeError, ServerHandshake, WebSocket};

use crate::session::{echo, tcp_socket, Stop};
use stack_stream::StackStream;

const INGRESS_BUDGET: usize = 32;
/// Longest a connection may live, counted from its acceptance.
const SESSION_DEADLINE: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub enum ServerError {
    Stack(StackError),
    /// `add_tcp` refused the replacement listener: every slot is in use.
    SocketsFull,
    RxPoolTooSmall {
        required: usize,
        pool: usize,
    },
    Listen(tcp::ListenError),
    /// A connection was accepted while another accepted one still waits for
    /// the running session to end.
    SecondWaiting,
    /// The session of the connection accepted at `accepted_at` was still
    /// running at `now`, more than `SESSION_DEADLINE` later.
    Deadline {
        accepted_at: Instant,
        now: Instant,
    },
    /// The handshake failed; see `Server` for why this ends the run.
    Handshake(Error),
    /// tungstenite reported `WriteBufferFull` or `AlreadyClosed`: this loop
    /// broke its contract.
    Contract(Error),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RxPoolTooSmall { required, pool } => {
                write!(
                    f,
                    "RX pool has {pool} mbufs; adding this socket requires {required}"
                )
            }
            _ => write!(f, "{self:?}"),
        }
    }
}

impl std::error::Error for ServerError {}

/// One accepted connection.
#[derive(Debug, Clone, Copy)]
struct Accepted {
    at: Instant,
}

/// Whichever state holds the Server's only Stack borrow.
enum Session<'s> {
    Idle(&'s mut Stack),
    Handshaking(
        MidHandshake<ServerHandshake<StackStream<'s>, NoCallback>>,
        Accepted,
    ),
    Open {
        ws: WebSocket<StackStream<'s>>,
        accepted: Accepted,
        /// tungstenite may hold unflushed output: only `flush` until Ok.
        flush_pending: bool,
    },
}

/// Echo server on one port: exactly one listening socket at a time, accepted
/// connections served in order, one WebSocket session at a time.
///
/// A failed handshake is a `ServerError`, fatal to the run: tungstenite drops
/// the stream on failure (`HandshakeError::Failure` carries none), and the
/// stream holds the Server's only Stack borrow.
///
/// Dropped connections are closed and reaped by the Stack.
pub struct Server<'s> {
    /// `None` only while a step moves it between states.
    session: Option<Session<'s>>,
    port: u16,
    buffer: usize,
    listener: TcpHandle,
    /// Accepted while a session runs; starts when it ends.
    waiting: Option<(TcpHandle, Accepted)>,
    accepted: usize,
    endings: BTreeMap<&'static str, usize>,
    turn: Option<Turn>,
}

impl<'s> Server<'s> {
    /// Adds the listener on `port` (Cubic with the default 1 MiB initial
    /// window, RX and TX buffers of `buffer` bytes each), before the first turn.
    pub fn new(stack: &'s mut Stack, port: u16, buffer: usize) -> Result<Self, ServerError> {
        let listener = add_listener(stack, port, buffer)?;
        Ok(Self {
            session: Some(Session::Idle(stack)),
            port,
            buffer,
            listener,
            waiting: None,
            accepted: 0,
            endings: BTreeMap::new(),
            turn: None,
        })
    }

    /// One `turn(now, 32)`, then listener maintenance and session progress.
    /// Returns whether anything moved: the turn received, processed or sent a
    /// frame, or the server accepted a connection, replaced its listener, or
    /// advanced a session. A session blocked on WouldBlock alone did not move.
    pub fn step(&mut self, now: Instant) -> Result<bool, ServerError> {
        let turn = self
            .stack()
            .turn(now, INGRESS_BUDGET)
            .map_err(ServerError::Stack)?;
        self.turn = Some(turn);
        let mut moved = turn.rx_received
            + turn.rx_rejected
            + turn.rx_ipv4_checksum_bad
            + turn.rx_processed
            + turn.tx_accepted
            > 0;
        moved |= self.maintain_listener(now)?;
        moved |= self.advance(now)?;
        Ok(moved)
    }

    /// The Stack, through whichever state holds it.
    pub fn stack(&mut self) -> &mut Stack {
        match self.session.as_mut().expect("session state present") {
            Session::Idle(stack) => stack,
            Session::Handshaking(mid, _) => mid.get_mut().get_mut().stack(),
            Session::Open { ws, .. } => ws.get_mut().stack(),
        }
    }

    /// The current session's socket, else the waiting connection's socket.
    pub fn socket(&mut self) -> Option<&tcp::Socket<'static>> {
        let session = self.session.as_mut().expect("session state present");
        let (stack, current) = match session {
            Session::Idle(stack) => (&mut **stack, None),
            Session::Handshaking(mid, _) => {
                let (stack, handle) = mid.get_mut().get_mut().parts();
                (stack, Some(handle))
            }
            Session::Open { ws, .. } => {
                let (stack, handle) = ws.get_mut().parts();
                (stack, Some(handle))
            }
        };
        current
            .or_else(|| self.waiting.as_ref().map(|(handle, _)| handle))
            .map(|handle| stack.tcp(handle))
    }

    /// The latest step's turn; `None` before the first step.
    pub fn turn(&self) -> Option<Turn> {
        self.turn
    }

    /// Connections that reached Established or CloseWait on the listener.
    pub fn accepted(&self) -> usize {
        self.accepted
    }

    /// Ended sessions by the tungstenite error variant that ended them.
    pub fn endings(&self) -> &BTreeMap<&'static str, usize> {
        &self.endings
    }

    /// A listener no longer in Listen or SynReceived is replaced; it becomes
    /// the next session if Established or CloseWait, else is dropped.
    fn maintain_listener(&mut self, now: Instant) -> Result<bool, ServerError> {
        let (port, buffer) = (self.port, self.buffer);
        let session = self.session.as_mut().expect("session state present");
        let stack = match session {
            Session::Idle(stack) => &mut **stack,
            Session::Handshaking(mid, _) => mid.get_mut().get_mut().stack(),
            Session::Open { ws, .. } => ws.get_mut().stack(),
        };
        let state = stack.tcp(&self.listener).state();
        if matches!(state, State::Listen | State::SynReceived) {
            return Ok(false);
        }
        if state == State::Closed {
            stack
                .listen(&self.listener, port)
                .map_err(ServerError::Listen)?;
            return Ok(true);
        }
        let listener = add_listener(stack, port, buffer)?;
        let old = std::mem::replace(&mut self.listener, listener);
        if matches!(state, State::Established | State::CloseWait) {
            if self.waiting.is_some() {
                return Err(ServerError::SecondWaiting);
            }
            self.waiting = Some((old, Accepted { at: now }));
            self.accepted += 1;
        } else {
            drop(old);
        }
        Ok(true)
    }

    /// Runs sessions until one blocks or none is left.
    fn advance(&mut self, now: Instant) -> Result<bool, ServerError> {
        let mut moved = false;
        loop {
            let session = self.session.take().expect("session state present");
            let (next, progressed) = match session {
                Session::Idle(stack) => match self.waiting.take() {
                    None => (Session::Idle(stack), false),
                    Some((handle, accepted)) => {
                        let stream = StackStream::new(stack, handle);
                        (handshake(accept_with_config(stream, None), accepted)?, true)
                    }
                },
                Session::Handshaking(mid, accepted) => {
                    check_deadline(accepted, now)?;
                    match handshake(mid.handshake(), accepted)? {
                        next @ Session::Handshaking(..) => (next, false),
                        next => (next, true),
                    }
                }
                Session::Open {
                    mut ws,
                    accepted,
                    mut flush_pending,
                } => {
                    check_deadline(accepted, now)?;
                    let mut progressed = false;
                    let stop = echo(&mut ws, &mut flush_pending, &mut progressed)
                        .map_err(ServerError::Contract)?;
                    match stop {
                        Stop::Blocked => (
                            Session::Open {
                                ws,
                                accepted,
                                flush_pending,
                            },
                            progressed,
                        ),
                        Stop::Ended(ending) => {
                            *self.endings.entry(ending).or_default() += 1;
                            let (stack, handle) = ws.into_inner().into_parts();
                            stack.tcp_mut(&handle).close();
                            drop(handle);
                            (Session::Idle(stack), true)
                        }
                    }
                }
            };
            self.session = Some(next);
            if !progressed {
                return Ok(moved);
            }
            moved = true;
        }
    }
}

fn add_listener(stack: &mut Stack, port: u16, buffer: usize) -> Result<TcpHandle, ServerError> {
    let handle = stack.add_tcp(tcp_socket(buffer)).map_err(|error| match error {
        AddTcpError::SocketsFull(_) => ServerError::SocketsFull,
        AddTcpError::RxPoolTooSmall { required, pool, .. } => {
            ServerError::RxPoolTooSmall { required, pool }
        }
    })?;
    if let Err(error) = stack.listen(&handle, port) {
        stack.remove_tcp(handle);
        return Err(ServerError::Listen(error));
    }
    Ok(handle)
}

fn check_deadline(accepted: Accepted, now: Instant) -> Result<(), ServerError> {
    if now - accepted.at > SESSION_DEADLINE {
        return Err(ServerError::Deadline {
            accepted_at: accepted.at,
            now,
        });
    }
    Ok(())
}

type Handshake<'s> = ServerHandshake<StackStream<'s>, NoCallback>;

fn handshake<'s>(
    result: Result<WebSocket<StackStream<'s>>, HandshakeError<Handshake<'s>>>,
    accepted: Accepted,
) -> Result<Session<'s>, ServerError> {
    match result {
        Ok(ws) => Ok(Session::Open {
            ws,
            accepted,
            flush_pending: false,
        }),
        Err(HandshakeError::Interrupted(mid)) => Ok(Session::Handshaking(mid, accepted)),
        Err(HandshakeError::Failure(error)) => Err(ServerError::Handshake(error)),
    }
}
