//! Nonblocking byte streams over Stack TCP sockets.

use std::io::{self, ErrorKind, Read, Write};

use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::socket::tcp::{RecvError, SendError, State, TcpFrame};
use dpdk_smoltcp::Stack;

/// Nonblocking `Read`/`Write` over one TCP socket of a borrowed `Stack`.
///
/// Valid only for a socket that is Established or CloseWait when created.
/// Nothing leaves or arrives until the caller turns the Stack (`stack()`):
/// - an empty buffer returns `Ok(0)` without touching the socket;
/// - read copies queued frames until the buffer is full, keeping a partly read
///   frame in the stream for the next read;
///   no queued frame -> `WouldBlock`; FIN received and all bytes read -> `Ok(0)`;
///   peer reset without FIN, once buffered bytes are read ->
///   `ConnectionReset`; otherwise `NotConnected`;
/// - write: send buffer full -> `WouldBlock`, never `Ok(0)`; after a peer reset ->
///   `ConnectionReset`; after our own close or abort, through Closed -> `BrokenPipe`;
///   otherwise `NotConnected`;
/// - flush returns `Ok(())`: written bytes are in the send buffer and leave on
///   later turns.
pub struct StackStream<'a> {
    stack: &'a mut Stack,
    handle: TcpHandle,
    pending: Option<(TcpFrame, usize)>,
}

impl<'a> StackStream<'a> {
    pub fn new(stack: &'a mut Stack, handle: TcpHandle) -> Self {
        Self { stack, handle, pending: None }
    }

    /// The borrowed Stack, to turn it while the stream is held.
    pub fn stack(&mut self) -> &mut Stack {
        self.stack
    }

    /// The handle owned by this stream.
    pub fn handle(&self) -> &TcpHandle {
        &self.handle
    }

    /// Borrows the Stack and handle together.
    pub fn parts(&mut self) -> (&mut Stack, &TcpHandle) {
        (self.stack, &self.handle)
    }

    /// Ends the stream and returns its Stack borrow and owned handle.
    /// Unread leftover bytes are discarded.
    pub fn into_parts(self) -> (&'a mut Stack, TcpHandle) {
        (self.stack, self.handle)
    }

    /// Ends the stream, dropping its handle and returning the Stack borrow.
    /// Unread leftover bytes are discarded.
    pub fn into_stack(self) -> &'a mut Stack {
        self.stack
    }
}

impl Read for StackStream<'_> {
    /// Copies queued frames until `buf` is full or the socket has no more
    /// in-order data; a partly copied frame stays pending for the next read.
    /// End of stream or an error after some bytes were copied returns those
    /// bytes; the next call reports it.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut filled = 0;
        while filled < buf.len() {
            if self.pending.is_none() {
                let socket = self.stack.tcp(&self.handle);
                if !socket.can_recv() && socket.may_recv() {
                    if filled > 0 {
                        break;
                    }
                    return Err(ErrorKind::WouldBlock.into());
                }
                let socket = self.stack.tcp_mut(&self.handle);
                match socket.recv() {
                    Ok(Some(frame)) => self.pending = Some((frame, 0)),
                    _ if filled > 0 => break,
                    Ok(None) => return Err(ErrorKind::WouldBlock.into()),
                    Err(RecvError::Finished) => return Ok(0),
                    Err(RecvError::InvalidState) => return Err(if socket.reset_by_peer() {
                        ErrorKind::ConnectionReset
                    } else {
                        ErrorKind::NotConnected
                    }
                    .into()),
                }
            }
            let (frame, offset) = self.pending.as_mut().unwrap();
            let read = (buf.len() - filled).min(frame.payload().len() - *offset);
            buf[filled..filled + read].copy_from_slice(&frame.payload()[*offset..*offset + read]);
            *offset += read;
            filled += read;
            if *offset == frame.payload().len() {
                self.pending = None;
            }
        }
        Ok(filled)
    }
}

impl Write for StackStream<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let socket = self.stack.tcp_mut(&self.handle);
        match socket.send_slice(buf) {
            Ok(0) => Err(ErrorKind::WouldBlock.into()),
            Ok(written) => Ok(written),
            Err(SendError::InvalidState) => Err(match socket.state() {
                State::Closed if socket.reset_by_peer() => ErrorKind::ConnectionReset,
                State::Closed
                | State::FinWait1
                | State::FinWait2
                | State::Closing
                | State::LastAck
                | State::TimeWait => ErrorKind::BrokenPipe,
                _ => ErrorKind::NotConnected,
            }
            .into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
