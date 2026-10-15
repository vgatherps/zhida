//! The parts of a WebSocket session both apps share: socket setup and the
//! read loop that never reads while tungstenite may hold unflushed output.

use std::io::ErrorKind;

use dpdk_smoltcp::smoltcp::socket::tcp;
use tungstenite::{Error, Message, WebSocket};

use stack_stream::StackStream;

/// Configures a Cubic TCP socket with `buffer` bytes in each direction.
pub(crate) fn tcp_socket(buffer: usize) -> tcp::Config {
    tcp::Config { rx_capacity: buffer, tx_capacity: buffer, mss_cap: None }
}

/// Where a session's loop stopped.
pub(crate) enum Stop {
    /// WouldBlock: nothing more until the Stack turns.
    Blocked,
    /// The session ended with the tungstenite error of this variant name.
    Ended(&'static str),
}

/// What `next_data` read.
pub(crate) enum Next {
    /// A Text or Binary message.
    Data(Message),
    Stop(Stop),
}

/// Reads until a Text or Binary message, WouldBlock or the session's end.
/// Never reads while tungstenite may hold unflushed output: every other
/// message is followed by a flush, and a blocked flush (`flush_pending`) is
/// retried before any further read. `Err` is a `WriteBufferFull` or
/// `AlreadyClosed`: the caller broke tungstenite's contract.
pub(crate) fn next_data(
    ws: &mut WebSocket<StackStream<'_>>,
    flush_pending: &mut bool,
    progressed: &mut bool,
) -> Result<Next, Error> {
    loop {
        if *flush_pending {
            if let Err(error) = ws.flush() {
                return ending(error).map(Next::Stop);
            }
            *flush_pending = false;
            *progressed = true;
        }
        let message = match ws.read() {
            Ok(message) => message,
            Err(error) => return ending(error).map(Next::Stop),
        };
        *progressed = true;
        match message {
            Message::Text(_) | Message::Binary(_) => return Ok(Next::Data(message)),
            Message::Ping(_) | Message::Pong(_) | Message::Close(_) | Message::Frame(_) => {
                if let Some(stop) = wrote(ws.flush(), flush_pending)? {
                    return Ok(Next::Stop(stop));
                }
            }
        }
    }
}

/// Echoes every Text and Binary message once until the loop stops. A
/// WouldBlock send is already buffered and never sent again. `Err` as
/// `next_data`.
pub(crate) fn echo(
    ws: &mut WebSocket<StackStream<'_>>,
    flush_pending: &mut bool,
    progressed: &mut bool,
) -> Result<Stop, Error> {
    loop {
        match next_data(ws, flush_pending, progressed)? {
            Next::Data(message) => {
                if let Some(stop) = wrote(ws.send(message), flush_pending)? {
                    return Ok(stop);
                }
            }
            Next::Stop(stop) => return Ok(stop),
        }
    }
}

/// The result of a write that may leave output in tungstenite: `None` when
/// written; otherwise the output stays pending (`flush_pending`) and the
/// loop stops. `Err` as `next_data`.
pub(crate) fn wrote(
    result: tungstenite::Result<()>,
    flush_pending: &mut bool,
) -> Result<Option<Stop>, Error> {
    match result {
        Ok(()) => Ok(None),
        Err(error) => {
            *flush_pending = true;
            ending(error).map(Some)
        }
    }
}

fn ending(error: Error) -> Result<Stop, Error> {
    let name = match &error {
        Error::Io(io) if io.kind() == ErrorKind::WouldBlock => return Ok(Stop::Blocked),
        Error::WriteBufferFull(_) | Error::AlreadyClosed => return Err(error),
        Error::ConnectionClosed => "ConnectionClosed",
        Error::Io(_) => "Io",
        Error::Tls(_) => "Tls",
        Error::Capacity(_) => "Capacity",
        Error::Protocol(_) => "Protocol",
        Error::Utf8(_) => "Utf8",
        Error::AttackAttempt => "AttackAttempt",
        Error::Url(_) => "Url",
        Error::Http(_) => "Http",
        Error::HttpFormat(_) => "HttpFormat",
    };
    Ok(Stop::Ended(name))
}
