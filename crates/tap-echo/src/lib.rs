//! Passive TCP echo application over a `Stack`: every byte a peer sends comes
//! back on the same connection, and the server closes once the peer has closed
//! and every byte is queued back, or (`with_close_after`) once it has queued
//! back a set number of bytes.

pub mod driver;

use std::fmt;
use std::time::Duration;

use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::socket::tcp::{self, State, TcpFrame};
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::{AddTcpError, Stack, StackError};

const INGRESS_BUDGET: usize = 32;
const MAX_IDLE_SLEEP: Duration = Duration::from_millis(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoError {
    SocketsFull,
    RxPoolTooSmall { required: usize, pool: usize },
    Listen(tcp::ListenError),
}

impl fmt::Display for EchoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EchoError::SocketsFull => write!(f, "stack has no free socket slot"),
            EchoError::RxPoolTooSmall { required, pool } => {
                write!(
                    f,
                    "RX pool has {pool} mbufs; adding this socket requires {required}"
                )
            }
            EchoError::Listen(error) => write!(f, "listen failed: {error}"),
        }
    }
}

impl std::error::Error for EchoError {}

pub struct EchoServer {
    port: u16,
    handles: Vec<TcpHandle>,
    pending: Vec<Option<(TcpFrame, usize)>>,
    close_after: Option<usize>,
    /// Per handle: bytes queued back on its current connection.
    echoed: Vec<usize>,
}

impl EchoServer {
    /// Adds `listeners` TCP sockets (RX and TX buffers of `buffer` bytes, Cubic)
    /// listening on `port`. On error the sockets it already added are removed
    /// again. `listeners` 0, `buffer` 0 or a `buffer` over smoltcp's 1 GiB
    /// receive limit are caller errors `new` does not check.
    pub fn new(
        stack: &mut Stack,
        port: u16,
        listeners: usize,
        buffer: usize,
    ) -> Result<Self, EchoError> {
        let mut handles = Vec::with_capacity(listeners);
        for _ in 0..listeners {
            let added = stack
                .add_tcp(listener(buffer))
                .map_err(|error| match error {
                    AddTcpError::SocketsFull(_) => EchoError::SocketsFull,
                    AddTcpError::RxPoolTooSmall { required, pool, .. } => {
                        EchoError::RxPoolTooSmall { required, pool }
                    }
                })
                .and_then(|handle| {
                    if let Err(error) = stack.listen(&handle, port) {
                        stack.remove_tcp(handle);
                        return Err(EchoError::Listen(error));
                    }
                    Ok(handle)
                });
            match added {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    for handle in handles {
                        stack.remove_tcp(handle);
                    }
                    return Err(error);
                }
            }
        }
        Ok(Self {
            port,
            echoed: vec![0; handles.len()],
            pending: (0..handles.len()).map(|_| None).collect(),
            handles,
            close_after: None,
        })
    }

    /// Per connection, echo at most `close_after` bytes: once exactly that
    /// many are queued back, close (the FIN follows them) and from then on read
    /// and discard what the peer sends, so its window stays open. A peer FIN
    /// before that closes as without the limit. The count restarts when the
    /// socket listens again. `None` (the default): no limit.
    pub fn with_close_after(mut self, close_after: Option<usize>) -> Self {
        self.close_after = close_after;
        self
    }

    /// One pass over every socket; true if any socket changed (bytes moved,
    /// listen, close).
    pub fn step(&mut self, stack: &mut Stack) -> bool {
        let mut changed = false;
        for ((handle, echoed), pending) in self.handles.iter().zip(&mut self.echoed).zip(&mut self.pending) {
            if stack.tcp(&handle).state() == State::Closed {
                stack
                    .listen(&handle, self.port)
                    .expect("listen on a closed socket with a nonzero port");
                *pending = None;
                *echoed = 0;
                changed = true;
            }
            let socket = stack.tcp_mut(&handle);
            // send_slice fails outside Established and CloseWait. In LastAck
            // smoltcp still enqueues payload from an in-window segment that
            // acks only part of our data (smoltcp tcp.rs 2040-2052,
            // 2232-2242); those bytes stay unread rather than echoed.
            while socket.may_send() {
                let room = socket.send_capacity().checked_sub(socket.send_queue())
                    .expect("send queue exceeds capacity")
                    .min(self.close_after.map_or(usize::MAX, |limit| {
                        limit.checked_sub(*echoed).expect("echo count exceeds close limit")
                    }));
                if room == 0 {
                    break;
                }
                if pending.is_none() {
                    if !socket.can_recv() {
                        break;
                    }
                    let Some(frame) = socket.recv().expect("receive while sending is open") else {
                        break;
                    };
                    *pending = Some((frame, 0));
                }
                let (frame, offset) = pending.as_mut().unwrap();
                let n = room.min(frame.payload().len() - *offset);
                let sent = socket.send_slice(&frame.payload()[*offset..*offset + n]).unwrap();
                assert_eq!(sent, n, "send_slice short of free send space");
                *offset = offset.checked_add(n).expect("echo frame offset exceeds usize");
                *echoed = echoed.checked_add(n).expect("echo count exceeds usize");
                if *offset == frame.payload().len() {
                    *pending = None;
                }
                changed = true;
            }
            if self.close_after == Some(*echoed) {
                if socket.may_send() {
                    socket.close();
                    changed = true;
                }
                changed |= pending.take().is_some();
                while socket.recv_queue() > 0 {
                    drop(socket.recv().unwrap().unwrap());
                    changed = true;
                }
            }
            if socket.state() == State::CloseWait && socket.recv_queue() == 0 && pending.is_none() {
                socket.close();
                changed = true;
            }
        }
        changed
    }

    pub fn handles(&self) -> &[TcpHandle] {
        &self.handles
    }
}

fn listener(buffer: usize) -> tcp::Config {
    tcp::Config { rx_capacity: buffer, tx_capacity: buffer, mss_cap: None }
}

/// Drives `stack` and `echo` on the wall clock until `stop` returns true. Time is
/// `smoltcp Instant::from_micros(start.elapsed())`; the Stack must have been created at a time
/// <= that (e.g. Instant::ZERO with `start` taken just before). Each iteration: now, `turn(now,
/// 32)`, `echo.step(stack)`, then `stop(stack)`; if the turn received, processed and sent nothing
/// and step changed nothing, sleep min(poll_at - now, 1 ms) (no sleep if poll_at <= now; 1 ms if
/// None). Returns turn's error, if any. `stop` runs after `step` and before the next turn, so
/// output that step queued in the last iteration is not flushed before serve returns.
pub fn serve(
    stack: &mut Stack,
    echo: &mut EchoServer,
    start: std::time::Instant,
    mut stop: impl FnMut(&mut Stack, &EchoServer) -> bool,
) -> Result<(), StackError> {
    loop {
        let micros = i64::try_from(start.elapsed().as_micros())
            .expect("elapsed wall time fits i64 microseconds");
        let now = Instant::from_micros(micros);
        let turn = stack.turn(now, INGRESS_BUDGET)?;
        let changed = echo.step(stack);
        if stop(stack, echo) {
            return Ok(());
        }
        let idle =
            turn.rx_received == 0 && turn.rx_processed == 0 && turn.tx_accepted == 0 && !changed;
        if !idle {
            continue;
        }
        let sleep = match stack.poll_at() {
            None => MAX_IDLE_SLEEP,
            Some(at) if at <= now => continue,
            Some(at) => Duration::from_micros((at - now).total_micros()).min(MAX_IDLE_SLEEP),
        };
        std::thread::sleep(sleep);
    }
}
