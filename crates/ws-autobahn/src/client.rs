//! WebSocket client over a `Stack` for Autobahn's fuzzingserver (port of
//! tungstenite examples/autobahn-client.rs): one connection at a time.

use std::collections::BTreeMap;
use std::fmt;

use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::socket::tcp::{self, State};
use dpdk_smoltcp::smoltcp::time::{Duration, Instant};
use dpdk_smoltcp::smoltcp::wire::IpEndpoint;
use dpdk_smoltcp::{AddTcpError, Stack, StackError, Turn};
use tungstenite::client::client_with_config;
use tungstenite::handshake::client::Response;
use tungstenite::handshake::MidHandshake;
use tungstenite::{ClientHandshake, Error, HandshakeError, Message, WebSocket};

use crate::session::{echo, next_data, tcp_socket, wrote, Next, Stop};
use stack_stream::StackStream;

const INGRESS_BUDGET: usize = 32;
/// Longest a connection may live, counted from its connect.
const CONNECTION_DEADLINE: Duration = Duration::from_secs(120);
/// Local port of connection 0; connection i uses `FIRST_LOCAL_PORT + i`.
const FIRST_LOCAL_PORT: u16 = 49152;
const AGENT: &str = "Tungstenite";

#[derive(Debug)]
pub enum ClientError {
    Stack(StackError),
    /// The connections' local ports would pass 65535.
    TooManyCases(usize),
    /// `add_tcp` refused a connection's socket: every slot is in use.
    SocketsFull,
    RxPoolTooSmall {
        required: usize,
        pool: usize,
    },
    Connect(tcp::ConnectError),
    /// Connection `connection`'s socket was Closed while the client waited
    /// for Established: refused (RST) or timed out.
    NotEstablished {
        connection: usize,
    },
    /// Connection `connection`, connected at `connected_at`, was still
    /// running at `now`, more than `CONNECTION_DEADLINE` later.
    Deadline {
        connection: usize,
        connected_at: Instant,
        now: Instant,
    },
    /// The handshake failed; see `Client` for why this ends the run.
    Handshake(Error),
    /// tungstenite reported `WriteBufferFull` or `AlreadyClosed`: this loop
    /// broke its contract.
    Contract(Error),
    /// getCaseCount's message was not the expected case count.
    CaseCount {
        expected: usize,
        got: Message,
    },
    /// A control connection received a Text or Binary message it does not
    /// expect.
    ControlMessage {
        connection: usize,
        message: Message,
    },
    /// A control connection ended other than by a completed close handshake
    /// (`ConnectionClosed`).
    ControlEnding {
        connection: usize,
        ending: &'static str,
    },
}

impl fmt::Display for ClientError {
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

impl std::error::Error for ClientError {}

/// One connection of the sequence.
#[derive(Debug, Clone, Copy)]
struct Connection {
    /// 0 = getCaseCount, 1..=cases = runCase, cases + 1 = updateReports.
    index: usize,
    at: Instant,
}

/// Whichever state holds the Client's only Stack borrow.
enum Session<'s> {
    Idle(&'s mut Stack),
    Connecting(&'s mut Stack, TcpHandle, Connection),
    Handshaking(MidHandshake<ClientHandshake<StackStream<'s>>>, Connection),
    Open {
        ws: WebSocket<StackStream<'s>>,
        connection: Connection,
        /// tungstenite may hold unflushed output: only `flush` until Ok.
        flush_pending: bool,
        /// A control connection sent its Close.
        closing: bool,
    },
}

/// Client of Autobahn's fuzzingserver at `server`. Connections strictly in
/// order, each on a new socket from local port `FIRST_LOCAL_PORT + i`:
/// getCaseCount (one message, which must be the expected case count, then a
/// close handshake), runCase 1..=cases (echo every Text and Binary message),
/// updateReports (close handshake only). A control
/// connection must end with `ConnectionClosed`. After a session ends its
/// socket is closed; sockets are never removed, so a socket the client
/// closed first keeps its TIME-WAIT. After the sequence the client only
/// turns the Stack.
///
/// A failed handshake is a `ClientError`, fatal to the run: tungstenite
/// drops the stream on failure, and the stream holds the only Stack borrow.
pub struct Client<'s> {
    /// `None` only while a step moves it between states.
    session: Option<Session<'s>>,
    server: IpEndpoint,
    cases: usize,
    buffer: usize,
    /// The next connection's index; `cases + 2` once all have started.
    next: usize,
    /// Sockets of completed sessions, by connection index.
    handles: Vec<TcpHandle>,
    endings: BTreeMap<&'static str, usize>,
    turn: Option<Turn>,
}

impl<'s> Client<'s> {
    /// A client expecting `cases` cases (getCaseCount must report exactly
    /// that); sockets get RX and TX buffers of `buffer` bytes each.
    pub fn new(
        stack: &'s mut Stack,
        server: IpEndpoint,
        cases: usize,
        buffer: usize,
    ) -> Result<Self, ClientError> {
        let last_port = usize::from(FIRST_LOCAL_PORT)
            .checked_add(cases)
            .and_then(|port| port.checked_add(1));
        if !matches!(last_port, Some(port) if port <= usize::from(u16::MAX)) {
            return Err(ClientError::TooManyCases(cases));
        }
        Ok(Self {
            session: Some(Session::Idle(stack)),
            server,
            cases,
            buffer,
            next: 0,
            handles: Vec::with_capacity(cases + 2),
            endings: BTreeMap::new(),
            turn: None,
        })
    }

    /// One `turn(now, 32)`, then connection progress. Returns whether
    /// anything moved: the turn received, processed or sent a frame, or the
    /// client connected, opened or advanced a session. A session blocked on
    /// WouldBlock alone did not move.
    pub fn step(&mut self, now: Instant) -> Result<bool, ClientError> {
        let turn = self
            .stack()
            .turn(now, INGRESS_BUDGET)
            .map_err(ClientError::Stack)?;
        self.turn = Some(turn);
        let moved = turn.rx_received
            + turn.rx_rejected
            + turn.rx_ipv4_checksum_bad
            + turn.rx_processed
            + turn.tx_accepted
            > 0;
        Ok(self.advance(now)? || moved)
    }

    /// The Stack, through whichever state holds it.
    pub fn stack(&mut self) -> &mut Stack {
        match self.session.as_mut().expect("session state present") {
            Session::Idle(stack) | Session::Connecting(stack, _, _) => stack,
            Session::Handshaking(mid, _) => mid.get_mut().get_mut().stack(),
            Session::Open { ws, .. } => ws.get_mut().stack(),
        }
    }

    /// The latest step's turn; `None` before the first step.
    pub fn turn(&self) -> Option<Turn> {
        self.turn
    }

    /// Sockets of the connections started so far, in connection order.
    pub fn handles(&self) -> Vec<&TcpHandle> {
        let mut handles: Vec<_> = self.handles.iter().collect();
        match self.session.as_ref().expect("session state present") {
            Session::Idle(_) => {}
            Session::Connecting(_, handle, _) => handles.push(handle),
            Session::Handshaking(mid, _) => handles.push(mid.get_ref().get_ref().handle()),
            Session::Open { ws, .. } => handles.push(ws.get_ref().handle()),
        }
        handles
    }

    /// Reads the socket of a connection started at `index`.
    pub fn socket(&mut self, index: usize) -> &tcp::Socket<'static> {
        let session = self.session.as_mut().expect("session state present");
        let (stack, current) = match session {
            Session::Idle(stack) => (&mut **stack, None),
            Session::Connecting(stack, handle, _) => (&mut **stack, Some(&*handle)),
            Session::Handshaking(mid, _) => {
                let (stack, handle) = mid.get_mut().get_mut().parts();
                (stack, Some(handle))
            }
            Session::Open { ws, .. } => {
                let (stack, handle) = ws.get_mut().parts();
                (stack, Some(handle))
            }
        };
        let handle = if index < self.handles.len() {
            &self.handles[index]
        } else {
            assert_eq!(index, self.handles.len());
            current.expect("connection started")
        };
        stack.tcp(handle)
    }

    /// Whether every connection ended.
    pub fn done(&self) -> bool {
        self.next == self.cases + 2 && matches!(self.session, Some(Session::Idle(_)))
    }

    /// Ended sessions, control connections included, by the tungstenite
    /// error variant that ended them.
    pub fn endings(&self) -> &BTreeMap<&'static str, usize> {
        &self.endings
    }

    fn url(&self, index: usize) -> String {
        let server = self.server;
        if index == 0 {
            format!("ws://{server}/getCaseCount")
        } else if index <= self.cases {
            format!("ws://{server}/runCase?case={index}&agent={AGENT}")
        } else {
            // Not `shutdownOnComplete=true`: fuzzingserver's onOpen
            // (fuzzing.py ~296-301) then calls reactor.stop() before
            // Twisted flushes the 101, so the handshake would read EOF.
            format!("ws://{server}/updateReports?agent={AGENT}")
        }
    }

    fn is_case(&self, index: usize) -> bool {
        (1..=self.cases).contains(&index)
    }

    /// Runs connections until one blocks or none is left.
    fn advance(&mut self, now: Instant) -> Result<bool, ClientError> {
        let mut moved = false;
        loop {
            let session = self.session.take().expect("session state present");
            let (next, progressed) = self.advance_session(session, now)?;
            self.session = Some(next);
            if !progressed {
                return Ok(moved);
            }
            moved = true;
        }
    }

    fn advance_session(
        &mut self,
        session: Session<'s>,
        now: Instant,
    ) -> Result<(Session<'s>, bool), ClientError> {
        Ok(match session {
            Session::Idle(stack) if self.next < self.cases + 2 => {
                let (handle, connection) = self.connect(stack, now)?;
                (Session::Connecting(stack, handle, connection), true)
            }
            idle @ Session::Idle(_) => (idle, false),
            Session::Connecting(stack, handle, connection) => {
                check_deadline(connection, now)?;
                match stack.tcp(&handle).state() {
                    State::Established | State::CloseWait => {
                        let stream = StackStream::new(stack, handle);
                        let url = self.url(connection.index);
                        (
                            handshake(client_with_config(url, stream, None), connection)?,
                            true,
                        )
                    }
                    State::Closed => {
                        return Err(ClientError::NotEstablished {
                            connection: connection.index,
                        })
                    }
                    _ => (Session::Connecting(stack, handle, connection), false),
                }
            }
            Session::Handshaking(mid, connection) => {
                check_deadline(connection, now)?;
                match handshake(mid.handshake(), connection)? {
                    next @ Session::Handshaking(..) => (next, false),
                    next => (next, true),
                }
            }
            Session::Open {
                mut ws,
                connection,
                mut flush_pending,
                mut closing,
            } => {
                check_deadline(connection, now)?;
                let mut progressed = false;
                let stop = if self.is_case(connection.index) {
                    echo(&mut ws, &mut flush_pending, &mut progressed)
                        .map_err(ClientError::Contract)?
                } else {
                    self.control(
                        &mut ws,
                        connection,
                        &mut flush_pending,
                        &mut closing,
                        &mut progressed,
                    )?
                };
                match stop {
                    Stop::Blocked => (
                        Session::Open {
                            ws,
                            connection,
                            flush_pending,
                            closing,
                        },
                        progressed,
                    ),
                    Stop::Ended(ending) => {
                        *self.endings.entry(ending).or_default() += 1;
                        let (stack, handle) = ws.into_inner().into_parts();
                        stack.tcp_mut(&handle).close();
                        self.handles.push(handle);
                        (Session::Idle(stack), true)
                    }
                }
            }
        })
    }

    /// Adds the next connection's socket and connects it.
    fn connect(
        &mut self,
        stack: &mut Stack,
        now: Instant,
    ) -> Result<(TcpHandle, Connection), ClientError> {
        let index = self.next;
        let local_port = FIRST_LOCAL_PORT + u16::try_from(index).expect("checked in new");
        let handle = stack
            .add_tcp(tcp_socket(self.buffer))
            .map_err(|error| match error {
                AddTcpError::SocketsFull(_) => ClientError::SocketsFull,
                AddTcpError::RxPoolTooSmall { required, pool, .. } => {
                    ClientError::RxPoolTooSmall { required, pool }
                }
            })?;
        stack
            .connect(&handle, self.server, local_port)
            .map_err(ClientError::Connect)?;
        self.next += 1;
        Ok((handle, Connection { index, at: now }))
    }

    /// getCaseCount reads the case count, then closes; updateReports closes
    /// at once. Both then read until the session ends, which must be
    /// `ConnectionClosed` after their Close.
    fn control(
        &self,
        ws: &mut WebSocket<StackStream<'_>>,
        connection: Connection,
        flush_pending: &mut bool,
        closing: &mut bool,
        progressed: &mut bool,
    ) -> Result<Stop, ClientError> {
        loop {
            if !*closing && connection.index != 0 {
                *closing = true;
                *progressed = true;
                if let Some(stop) =
                    wrote(ws.close(None), flush_pending).map_err(ClientError::Contract)?
                {
                    return control_stop(stop, connection);
                }
            }
            match next_data(ws, flush_pending, progressed).map_err(ClientError::Contract)? {
                Next::Data(message) if !*closing => {
                    let count = message.to_text().ok().and_then(|text| text.parse().ok());
                    if count != Some(self.cases) {
                        return Err(ClientError::CaseCount {
                            expected: self.cases,
                            got: message,
                        });
                    }
                    *closing = true;
                    if let Some(stop) =
                        wrote(ws.close(None), flush_pending).map_err(ClientError::Contract)?
                    {
                        return control_stop(stop, connection);
                    }
                }
                Next::Data(message) => {
                    return Err(ClientError::ControlMessage {
                        connection: connection.index,
                        message,
                    })
                }
                Next::Stop(Stop::Ended(ending)) if !*closing => {
                    return Err(ClientError::ControlEnding {
                        connection: connection.index,
                        ending,
                    })
                }
                Next::Stop(stop) => return control_stop(stop, connection),
            }
        }
    }
}

/// A control connection may only end with `ConnectionClosed`.
fn control_stop(stop: Stop, connection: Connection) -> Result<Stop, ClientError> {
    match stop {
        Stop::Ended(ending) if ending != "ConnectionClosed" => Err(ClientError::ControlEnding {
            connection: connection.index,
            ending,
        }),
        stop => Ok(stop),
    }
}

fn check_deadline(connection: Connection, now: Instant) -> Result<(), ClientError> {
    if now - connection.at > CONNECTION_DEADLINE {
        return Err(ClientError::Deadline {
            connection: connection.index,
            connected_at: connection.at,
            now,
        });
    }
    Ok(())
}

type Handshake<'s> = ClientHandshake<StackStream<'s>>;

fn handshake<'s>(
    result: Result<(WebSocket<StackStream<'s>>, Response), HandshakeError<Handshake<'s>>>,
    connection: Connection,
) -> Result<Session<'s>, ClientError> {
    match result {
        Ok((ws, _response)) => Ok(Session::Open {
            ws,
            connection,
            flush_pending: false,
            closing: false,
        }),
        Err(HandshakeError::Interrupted(mid)) => Ok(Session::Handshaking(mid, connection)),
        Err(HandshakeError::Failure(error)) => Err(ClientError::Handshake(error)),
    }
}
