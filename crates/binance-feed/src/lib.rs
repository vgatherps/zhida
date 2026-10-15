//! TLS + WebSocket client of Binance's bookTicker stream over one Zhida TCP socket.

use std::fmt;
use std::io::{self, ErrorKind};
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::{Duration, Instant as WallInstant};

use dpdk_smoltcp::smoltcp::socket::tcp::{self, State};
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::smoltcp::wire::IpEndpoint;
use dpdk_smoltcp::{AddTcpError, Stack, StackError};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use tungstenite::client::IntoClientRequest;
use tungstenite::{HandshakeError, Message, WebSocket};
use stack_stream::StackStream;

pub const INGRESS_BUDGET: usize = 32;
/// RX and TX buffer bytes of the feed's socket.
pub const SOCKET_BUFFER: usize = 256 * 1024;
/// Longest idle sleep between turns.
const MAX_IDLE_SLEEP: Duration = Duration::from_millis(1);

/// Wall clock since `start` as Stack time in microseconds; panics past i64 microseconds.
pub struct Clock {
    start: WallInstant,
}

impl Clock {
    pub fn new(start: WallInstant) -> Self {
        Self { start }
    }

    pub fn now(&self) -> Instant {
        let micros = i64::try_from(self.start.elapsed().as_micros())
            .expect("elapsed wall time fits i64 microseconds");
        Instant::from_micros(micros)
    }
}

/// `addr` is the resolved IPv4 endpoint, `host` the TLS name and HTTP Host,
/// and `path` the request path.
pub struct Target {
    pub addr: SocketAddrV4,
    pub host: String,
    pub path: String,
}

impl Target {
    /// `wss://{host}:{port}{path}` with the port of `addr`.
    pub fn url(&self) -> String {
        format!("wss://{}:{}{}", self.host, self.addr.port(), self.path)
    }
}

/// One bookTicker update; prices and quantities keep Binance's decimal strings.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct BookTicker {
    #[serde(rename = "u")]
    pub update_id: u64,
    #[serde(rename = "s")]
    pub symbol: String,
    #[serde(rename = "b")]
    pub bid_price: String,
    #[serde(rename = "B")]
    pub bid_qty: String,
    #[serde(rename = "a")]
    pub ask_price: String,
    #[serde(rename = "A")]
    pub ask_qty: String,
}

impl fmt::Display for BookTicker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "u={} {} bid {} x {} ask {} x {}",
            self.update_id, self.symbol, self.bid_price, self.bid_qty, self.ask_price, self.ask_qty,
        )
    }
}

/// rustls with ring, safe default protocol versions, `roots` and no client auth.
pub fn client_config(roots: RootCertStore) -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports rustls's safe default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// `client_config` with the Mozilla roots from webpki-roots.
pub fn webpki_client_config() -> Arc<ClientConfig> {
    client_config(RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    })
}

pub type TlsStream<'s> = StreamOwned<ClientConnection, StackStream<'s>>;

#[derive(Debug)]
pub enum FeedError {
    Stack(StackError),
    SocketsFull,
    RxPoolTooSmall {
        required: usize,
        pool: usize,
    },
    Connect(tcp::ConnectError),
    Refused {
        addr: SocketAddrV4,
    },
    ConnectTimeout {
        addr: SocketAddrV4,
        state: State,
        limit: Duration,
    },
    ServerName(String),
    Tls(rustls::Error),
    Upgrade {
        status: u16,
        reason: String,
        body: String,
    },
    Handshake(tungstenite::Error),
    HandshakeTimeout {
        limit: Duration,
    },
    Parse {
        text: String,
        error: serde_json::Error,
    },
    UnexpectedMessage(&'static str),
    ServerClosed(Option<String>),
    Read(tungstenite::Error),
    CloseIo(io::Error),
    CloseTimeout {
        step: &'static str,
        state: State,
        limit: Duration,
    },
}

impl fmt::Display for FeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stack(error) => write!(f, "Zhida stack: {error:?}"),
            Self::SocketsFull => write!(f, "no free socket slot in the Stack"),
            Self::RxPoolTooSmall { required, pool } => {
                write!(
                    f,
                    "RX pool has {pool} mbufs; adding this socket requires {required}"
                )
            }
            Self::Connect(error) => write!(f, "TCP connect: {error:?}"),
            Self::Refused { addr } => write!(
                f,
                "TCP connect to {addr}: reset by the peer (RST answering the SYN)",
            ),
            Self::ConnectTimeout { addr, state, limit } => write!(
                f,
                "TCP connect to {addr}: not established within {limit:?} \
                 (socket state {state}; SynSent means no SYN-ACK arrived)",
            ),
            Self::ServerName(host) => write!(f, "invalid TLS server name {host:?}"),
            Self::Tls(error) => write!(f, "TLS: {error}"),
            Self::Upgrade { status, reason, body } => {
                write!(f, "WebSocket upgrade refused: HTTP {status} {reason}: {body}")
            }
            Self::Handshake(error) => write!(f, "WebSocket handshake: {error}"),
            Self::HandshakeTimeout { limit } => {
                write!(f, "TLS + WebSocket handshake not finished within {limit:?}")
            }
            Self::Parse { text, error } => write!(f, "not a bookTicker message ({error}): {text}"),
            Self::UnexpectedMessage(kind) => write!(f, "unexpected WebSocket {kind} message"),
            Self::ServerClosed(frame) => {
                write!(f, "server closed the WebSocket")?;
                if let Some(frame) = frame {
                    write!(f, ": {frame}")?;
                }
                Ok(())
            }
            Self::Read(error) => write!(f, "WebSocket read: {error}"),
            Self::CloseIo(error) => write!(f, "sending TLS close_notify: {error}"),
            Self::CloseTimeout { step, state, limit } => {
                write!(f, "{step} not finished within {limit:?} (socket state {state})")
            }
        }
    }
}

impl std::error::Error for FeedError {}

fn pump(stack: &mut Stack, clock: &Clock) -> Result<(), FeedError> {
    let now = clock.now();
    let turn = stack.turn(now, INGRESS_BUDGET).map_err(FeedError::Stack)?;
    let moved = turn.rx_received
        + turn.rx_rejected
        + turn.rx_ipv4_checksum_bad
        + turn.rx_processed
        + turn.tx_accepted;
    if moved == 0 && turn.tx_pending == 0 && turn.rx_staged == 0 {
        let sleep = match stack.poll_at() {
            None => MAX_IDLE_SLEEP,
            Some(at) if at <= now => return Ok(()),
            Some(at) => Duration::from_micros((at - now).total_micros()).min(MAX_IDLE_SLEEP),
        };
        std::thread::sleep(sleep);
    }
    Ok(())
}

fn classify(error: tungstenite::Error, fallback: fn(tungstenite::Error) -> FeedError) -> FeedError {
    match error {
        tungstenite::Error::Http(response) => FeedError::Upgrade {
            status: response.status().as_u16(),
            reason: response.status().canonical_reason().unwrap_or("").to_owned(),
            body: response
                .body()
                .as_ref()
                .map(|body| String::from_utf8_lossy(body).into_owned())
                .unwrap_or_default(),
        },
        tungstenite::Error::Io(io) => {
            if let Some(tls) = io.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()) {
                FeedError::Tls(tls.clone())
            } else {
                fallback(tungstenite::Error::Io(io))
            }
        }
        other => fallback(other),
    }
}

/// Configures feed RX and TX buffers and an optional MSS cap.
pub fn socket(mss_cap: Option<u16>) -> tcp::Config {
    tcp::Config { rx_capacity: SOCKET_BUFFER, tx_capacity: SOCKET_BUFFER, mss_cap }
}

/// Opens TCP, TLS and WebSocket within one `limit`, turning the Stack between retries.
pub fn connect<'s>(
    stack: &'s mut Stack,
    clock: &Clock,
    target: &Target,
    socket: tcp::Config,
    tls: Arc<ClientConfig>,
    local_port: u16,
    limit: Duration,
) -> Result<Feed<'s>, FeedError> {
    let deadline = WallInstant::now()
        .checked_add(limit)
        .expect("connect deadline fits wall time");
    let handle = stack.add_tcp(socket).map_err(|error| match error {
        AddTcpError::SocketsFull(_) => FeedError::SocketsFull,
        AddTcpError::RxPoolTooSmall { required, pool, .. } => {
            FeedError::RxPoolTooSmall { required, pool }
        }
    })?;
    let endpoint = IpEndpoint::new((*target.addr.ip()).into(), target.addr.port());
    stack.connect(&handle, endpoint, local_port).map_err(FeedError::Connect)?;
    loop {
        let state = stack.tcp(&handle).state();
        if WallInstant::now() >= deadline {
            return Err(FeedError::ConnectTimeout {
                addr: target.addr,
                state,
                limit,
            });
        }
        match state {
            State::Established => break,
            State::Closed => return Err(FeedError::Refused { addr: target.addr }),
            _ => pump(stack, clock)?,
        }
    }
    let name = ServerName::try_from(target.host.clone())
        .map_err(|_| FeedError::ServerName(target.host.clone()))?;
    let conn = ClientConnection::new(tls, name).map_err(FeedError::Tls)?;
    let stream = StreamOwned::new(conn, StackStream::new(stack, handle));
    let request = target.url().into_client_request().map_err(FeedError::Handshake)?;
    let mut result = tungstenite::client(request, stream);
    let ws = loop {
        if WallInstant::now() >= deadline {
            return Err(FeedError::HandshakeTimeout { limit });
        }
        match result {
            Ok((ws, _)) => break ws,
            Err(HandshakeError::Interrupted(mut mid)) => {
                pump(mid.get_mut().get_mut().get_mut().stack(), clock)?;
                if WallInstant::now() >= deadline {
                    return Err(FeedError::HandshakeTimeout { limit });
                }
                result = mid.handshake();
            }
            Err(HandshakeError::Failure(error)) => {
                return Err(classify(error, FeedError::Handshake));
            }
        }
    };
    Ok(Feed { ws })
}

pub struct Feed<'s> {
    ws: WebSocket<TlsStream<'s>>,
}

impl<'s> Feed<'s> {
    /// Debug names of the negotiated TLS version and cipher suite.
    pub fn tls_summary(&self) -> String {
        let conn = &self.ws.get_ref().conn;
        let version = conn.protocol_version().expect("WebSocket opened after TLS negotiated");
        let suite = conn
            .negotiated_cipher_suite()
            .expect("WebSocket opened after TLS negotiated")
            .suite();
        format!("{version:?} {suite:?}")
    }

    /// Reads one update; buffered messages are drained before `stop` is checked.
    pub fn next(
        &mut self,
        clock: &Clock,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<Option<BookTicker>, FeedError> {
        loop {
            match self.ws.read() {
                Ok(Message::Text(text)) => {
                    return serde_json::from_str(&text)
                        .map(Some)
                        .map_err(|error| FeedError::Parse {
                            text: text.to_string(),
                            error,
                        });
                }
                Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
                Ok(Message::Binary(_)) => return Err(FeedError::UnexpectedMessage("binary")),
                Ok(Message::Frame(_)) => return Err(FeedError::UnexpectedMessage("frame")),
                Ok(Message::Close(frame)) => {
                    return Err(FeedError::ServerClosed(
                        frame.map(|frame| format!("{} {}", frame.code, frame.reason)),
                    ));
                }
                Err(tungstenite::Error::Io(error)) if error.kind() == ErrorKind::WouldBlock => {
                    if stop() {
                        return Ok(None);
                    }
                    pump(self.ws.get_mut().get_mut().stack(), clock)?;
                }
                Err(error) => return Err(classify(error, FeedError::Read)),
            }
        }
    }

    /// Closes WebSocket, sends TLS close_notify and closes TCP within one `limit`.
    pub fn close(mut self, clock: &Clock, limit: Duration) -> Result<State, FeedError> {
        let deadline = WallInstant::now()
            .checked_add(limit)
            .expect("close deadline fits wall time");
        let mut close_written = match self.ws.close(None) {
            Ok(()) => true,
            Err(tungstenite::Error::Io(error)) if error.kind() == ErrorKind::WouldBlock => false,
            Err(error) => return Err(classify(error, FeedError::Read)),
        };
        loop {
            let (stack, handle) = self.ws.get_mut().get_mut().parts();
            let state = stack.tcp(handle).state();
            if WallInstant::now() >= deadline {
                return Err(FeedError::CloseTimeout {
                    step: "WebSocket close handshake",
                    state,
                    limit,
                });
            }
            // A Close that close() could not write stays in tungstenite's
            // output buffer, and read() does not retry it: flush until it is out.
            if !close_written {
                match self.ws.flush() {
                    Ok(()) => close_written = true,
                    Err(tungstenite::Error::Io(error)) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(error) => return Err(classify(error, FeedError::Read)),
                }
            }
            // Messages sent before the server saw our Close still arrive and
            // are dropped. Its Close reply completes the handshake: nothing
            // may follow it, so reading stops there (a frame after it would
            // be a tungstenite protocol error).
            match self.ws.read() {
                Ok(Message::Close(_)) | Err(tungstenite::Error::ConnectionClosed) => break,
                Ok(_) => {}
                Err(tungstenite::Error::Io(error)) if error.kind() == ErrorKind::WouldBlock => {
                    pump(self.ws.get_mut().get_mut().stack(), clock)?;
                }
                Err(error) => return Err(classify(error, FeedError::Read)),
            }
        }
        let mut tls = self.ws.into_inner();
        tls.conn.send_close_notify();
        while tls.conn.wants_write() {
            let (stack, handle) = tls.sock.parts();
            let state = stack.tcp(handle).state();
            if WallInstant::now() >= deadline {
                return Err(FeedError::CloseTimeout {
                    step: "TLS close_notify",
                    state,
                    limit,
                });
            }
            match tls.conn.write_tls(&mut tls.sock) {
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => pump(tls.sock.stack(), clock)?,
                Err(error) => return Err(FeedError::CloseIo(error)),
            }
        }
        let (stack, handle) = tls.sock.into_parts();
        stack.tcp_mut(&handle).close();
        loop {
            let state = stack.tcp(&handle).state();
            if matches!(state, State::Closed | State::TimeWait) {
                return Ok(state);
            }
            if WallInstant::now() >= deadline {
                return Err(FeedError::CloseTimeout {
                    step: "TCP close",
                    state,
                    limit,
                });
            }
            pump(stack, clock)?;
        }
    }
}
