//! `StackStream` Read/Write results over two Stacks on lossless net_ring links.
//! A is the peer; B's socket is read and written through `StackStream`.

use std::io::{self, ErrorKind, Read, Write};

use dpdk_smoltcp::TcpHandle;
use dpdk_smoltcp::smoltcp::socket::tcp::State;
use dpdk_smoltcp::Stack;
use tungstenite::client::client_with_config;
use tungstenite::handshake::client::Response;
use tungstenite::handshake::server::NoCallback;
use tungstenite::handshake::{HandshakeRole, MidHandshake};
use tungstenite::{
    accept_with_config, ClientHandshake, Error, HandshakeError, Message, ServerHandshake, WebSocket,
};
use stack_stream::StackStream;

use zhida_test_kit::{pair, wire, with_eal};
use pair::{
    assert_lossless, establish, establish_sized, new_pair, pattern, tcp_socket_sized, App, Pair,
    Rounds, Side, SERVER_PORT,
};
use wire::Link;

/// Both links lost nothing, then `Pair::close`.
fn close(pair: Pair) {
    assert_lossless(&pair.a_to_b, "A→B");
    assert_lossless(&pair.b_to_a, "B→A");
    pair.close();
}

fn read(stack: &mut Stack, handle: &mut Option<TcpHandle>, buf: &mut [u8]) -> io::Result<usize> {
    with_stream(stack, handle, |stream| stream.read(buf))
}

fn write(stack: &mut Stack, handle: &mut Option<TcpHandle>, buf: &[u8]) -> io::Result<usize> {
    with_stream(stack, handle, |stream| stream.write(buf))
}

fn with_stream<T>(
    stack: &mut Stack,
    handle: &mut Option<TcpHandle>,
    body: impl FnOnce(&mut StackStream<'_>) -> T,
) -> T {
    let mut stream = StackStream::new(stack, handle.take().unwrap());
    let result = body(&mut stream);
    let (_, owned) = stream.into_parts();
    *handle = Some(owned);
    result
}

fn kind(result: io::Result<usize>) -> ErrorKind {
    match result {
        Ok(n) => panic!("expected an error, got Ok({n})"),
        Err(error) => error.kind(),
    }
}

/// Drive rounds until `done` holds.
fn wait(pair: &mut Pair, mut done: impl FnMut(&mut Stack, &mut Stack) -> bool) {
    pair.drive(
        |_, _| {},
        |a, b| if done(a, b) { App::Done } else { App::Idle },
    );
}

/// A sends `data`; drives until B holds it all and A has it acknowledged.
fn send_to_b(pair: &mut Pair, handles: &[Option<TcpHandle>; 2], data: &[u8]) {
    assert_eq!(pair.a.tcp_mut(handles[0].as_ref().unwrap()).send_slice(data), Ok(data.len()));
    wait(pair, |a, b| {
        a.tcp(handles[0].as_ref().unwrap()).send_queue() == 0 && b.tcp(handles[1].as_ref().unwrap()).recv_queue() == data.len()
    });
}

/// Reads B in 7-byte pieces until `len` bytes, never getting `Ok(0)` or an
/// error before then; returns them.
fn drain_b(stack: &mut Stack, handle: &mut Option<TcpHandle>, len: usize) -> Vec<u8> {
    let mut got = Vec::new();
    with_stream(stack, handle, |stream| {
        while got.len() < len {
            let mut buf = [0; 7];
            let n = stream.read(&mut buf).unwrap();
            assert_ne!(n, 0, "Ok(0) after {} of {len} bytes", got.len());
            got.extend_from_slice(&buf[..n]);
        }
    });
    got
}

/// A aborts: it sends RST and B ends Closed.
fn a_aborts(pair: &mut Pair, handles: &[Option<TcpHandle>; 2]) {
    pair.a.tcp_mut(handles[0].as_ref().unwrap()).abort();
    wait(pair, |_, b| b.tcp(handles[1].as_ref().unwrap()).state() == State::Closed);
}

#[zhida_test_support::pinned_test]
fn read_would_block_when_established_and_empty() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["rwba", "rwbb"]);
        let (handles, _) = establish(&mut pair, Side::A);
        let mut handles = handles.map(Some);
        assert_eq!(
            kind(read(&mut pair.b, &mut handles[1], &mut [0; 16])),
            ErrorKind::WouldBlock
        );
        close(pair);
    });
}

/// Read two 48-byte deliveries in order through a 64-byte socket.
#[zhida_test_support::pinned_test]
fn read_returns_successive_deliveries_in_order() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["rwra", "rwrb"]);
        let (handles, _) = establish_sized(&mut pair, Side::A, 64);
        let mut handles = handles.map(Some);
        let first = pattern(48, 1);
        send_to_b(&mut pair, &handles, &first);
        let mut buf = [0; 64];
        assert_eq!(read(&mut pair.b, &mut handles[1], &mut buf).unwrap(), 48);
        assert_eq!(buf[..48], first[..]);

        let second = pattern(48, 2);
        let mut sent = 0;
        wait(&mut pair, |a, b| {
            sent += a.tcp_mut(handles[0].as_ref().unwrap()).send_slice(&second[sent..]).unwrap();
            b.tcp(handles[1].as_ref().unwrap()).recv_queue() == second.len()
        });
        let mut buf = [0; 64];
        assert_eq!(read(&mut pair.b, &mut handles[1], &mut buf).unwrap(), 48);
        assert_eq!(buf[..48], second[..]);
        close(pair);
    });
}

/// B reads only once A's FIN is in (CloseWait): every byte comes before `Ok(0)`.
#[zhida_test_support::pinned_test]
fn eof_only_after_fin_and_drain() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["eofa", "eofb"]);
        let (handles, _) = establish(&mut pair, Side::A);
        let mut handles = handles.map(Some);
        let data = pattern(1000, 3);
        send_to_b(&mut pair, &handles, &data);
        pair.a.tcp_mut(handles[0].as_ref().unwrap()).close();
        wait(&mut pair, |_, b| {
            b.tcp(handles[1].as_ref().unwrap()).state() == State::CloseWait
        });
        assert_eq!(drain_b(&mut pair.b, &mut handles[1], data.len()), data);
        assert_eq!(read(&mut pair.b, &mut handles[1], &mut [0; 16]).unwrap(), 0);
        assert_eq!(read(&mut pair.b, &mut handles[1], &mut [0; 16]).unwrap(), 0);
        close(pair);
    });
}

#[zhida_test_support::pinned_test]
fn buffered_bytes_then_connection_reset_after_rst() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["bcra", "bcrb"]);
        let (handles, _) = establish(&mut pair, Side::A);
        let mut handles = handles.map(Some);
        let data = pattern(1000, 4);
        send_to_b(&mut pair, &handles, &data);
        a_aborts(&mut pair, &handles);
        assert_eq!(drain_b(&mut pair.b, &mut handles[1], data.len()), data);
        assert_eq!(
            kind(read(&mut pair.b, &mut handles[1], &mut [0; 16])),
            ErrorKind::ConnectionReset
        );
        close(pair);
    });
}

/// The RST after A's FIN leaves B Closed with the FIN recorded, so the drained
/// stream ends in EOF, not ConnectionReset.
#[zhida_test_support::pinned_test]
fn fin_then_rst_reads_eof_after_drain() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["fraa", "frab"]);
        let (handles, _) = establish(&mut pair, Side::A);
        let mut handles = handles.map(Some);
        let data = pattern(1000, 5);
        send_to_b(&mut pair, &handles, &data);
        pair.a.tcp_mut(handles[0].as_ref().unwrap()).close();
        wait(&mut pair, |a, b| {
            a.tcp(handles[0].as_ref().unwrap()).state() == State::FinWait2
                && b.tcp(handles[1].as_ref().unwrap()).state() == State::CloseWait
        });
        a_aborts(&mut pair, &handles);
        assert_eq!(drain_b(&mut pair.b, &mut handles[1], data.len()), data);
        assert_eq!(read(&mut pair.b, &mut handles[1], &mut [0; 16]).unwrap(), 0);
        close(pair);
    });
}

#[zhida_test_support::pinned_test]
fn write_would_block_when_send_buffer_full() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["wwba", "wwbb"]);
        let (handles, _) = establish(&mut pair, Side::A);
        let mut handles = handles.map(Some);
        let data = pattern(8192, 6);
        assert_eq!(write(&mut pair.b, &mut handles[1], &data).unwrap(), 4096);
        assert_eq!(
            kind(write(&mut pair.b, &mut handles[1], &data[4096..])),
            ErrorKind::WouldBlock
        );
        close(pair);
    });
}

#[zhida_test_support::pinned_test]
fn write_after_peer_rst_is_connection_reset() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["wpra", "wprb"]);
        let (handles, _) = establish(&mut pair, Side::A);
        let mut handles = handles.map(Some);
        a_aborts(&mut pair, &handles);
        assert_eq!(
            kind(write(&mut pair.b, &mut handles[1], b"x")),
            ErrorKind::ConnectionReset
        );
        close(pair);
    });
}

/// B's own close, through FinWait1, FinWait2 and TimeWait.
#[zhida_test_support::pinned_test]
fn write_after_own_close_is_broken_pipe() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["woca", "wocb"]);
        let (handles, _) = establish(&mut pair, Side::A);
        let mut handles = handles.map(Some);
        pair.b.tcp_mut(handles[1].as_ref().unwrap()).close();
        for state in [State::FinWait1, State::FinWait2, State::TimeWait] {
            if state == State::TimeWait {
                pair.a.tcp_mut(handles[0].as_ref().unwrap()).close();
            }
            wait(&mut pair, |_, b| b.tcp(handles[1].as_ref().unwrap()).state() == state);
            assert_eq!(pair.b.tcp(handles[1].as_ref().unwrap()).state(), state);
            assert_eq!(
                kind(write(&mut pair.b, &mut handles[1], b"x")),
                ErrorKind::BrokenPipe
            );
        }
        close(pair);
    });
}

/// A closes first; B closes from CloseWait and sends its FIN, whose ACK B has
/// not yet processed.
#[zhida_test_support::pinned_test]
fn write_in_last_ack_is_broken_pipe() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["wlaa", "wlab"]);
        let (handles, _) = establish(&mut pair, Side::A);
        let mut handles = handles.map(Some);
        pair.a.tcp_mut(handles[0].as_ref().unwrap()).close();
        wait(&mut pair, |_, b| {
            b.tcp(handles[1].as_ref().unwrap()).state() == State::CloseWait
        });
        pair.b.tcp_mut(handles[1].as_ref().unwrap()).close();
        pair.round(|_, _| {});
        assert_eq!(pair.b.tcp(handles[1].as_ref().unwrap()).state(), State::LastAck);
        assert_eq!(
            kind(write(&mut pair.b, &mut handles[1], b"x")),
            ErrorKind::BrokenPipe
        );
        wait(&mut pair, |_, b| {
            b.tcp(handles[1].as_ref().unwrap()).state() == State::Closed
        });
        // Graceful close completed: Closed without a peer reset stays BrokenPipe.
        assert!(!pair.b.tcp(handles[1].as_ref().unwrap()).reset_by_peer());
        assert_eq!(
            kind(write(&mut pair.b, &mut handles[1], b"x")),
            ErrorKind::BrokenPipe
        );
        close(pair);
    });
}

/// Both close before a round: B, in FinWait1, gets A's FIN before the ACK of
/// its own.
#[zhida_test_support::pinned_test]
fn write_in_closing_is_broken_pipe() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["wcla", "wclb"]);
        let (handles, _) = establish(&mut pair, Side::A);
        let mut handles = handles.map(Some);
        pair.a.tcp_mut(handles[0].as_ref().unwrap()).close();
        pair.b.tcp_mut(handles[1].as_ref().unwrap()).close();
        pair.round(|_, _| {});
        assert_eq!(pair.b.tcp(handles[1].as_ref().unwrap()).state(), State::Closing);
        assert_eq!(
            kind(write(&mut pair.b, &mut handles[1], b"x")),
            ErrorKind::BrokenPipe
        );
        wait(&mut pair, |_, b| {
            b.tcp(handles[1].as_ref().unwrap()).state() == State::TimeWait
        });
        close(pair);
    });
}

/// Pins only the "other state" arms: `StackStream::new` takes any socket, here
/// one in Listen.
#[zhida_test_support::pinned_test]
fn read_and_write_in_listen_are_not_connected() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["ncla", "nclb"]);
        let mut handle = Some(pair.b.add_tcp(tcp_socket_sized(4096)).unwrap());
        pair.b.listen(handle.as_ref().unwrap(), SERVER_PORT).unwrap();
        assert_eq!(pair.b.tcp(handle.as_ref().unwrap()).state(), State::Listen);
        assert_eq!(
            kind(read(&mut pair.b, &mut handle, &mut [0; 16])),
            ErrorKind::NotConnected
        );
        assert_eq!(
            kind(write(&mut pair.b, &mut handle, b"x")),
            ErrorKind::NotConnected
        );
        close(pair);
    });
}

/// B's own abort leaves it Closed with no peer reset: write is BrokenPipe and
/// read NotConnected, not ConnectionReset.
#[zhida_test_support::pinned_test]
fn own_abort_is_broken_pipe_not_connection_reset() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["oaba", "oabb"]);
        let (handles, _) = establish(&mut pair, Side::A);
        let mut handles = handles.map(Some);
        pair.b.tcp_mut(handles[1].as_ref().unwrap()).abort();
        assert_eq!(pair.b.tcp(handles[1].as_ref().unwrap()).state(), State::Closed);
        assert_eq!(
            kind(write(&mut pair.b, &mut handles[1], b"x")),
            ErrorKind::BrokenPipe
        );
        assert_eq!(
            kind(read(&mut pair.b, &mut handles[1], &mut [0; 16])),
            ErrorKind::NotConnected
        );
        wait(&mut pair, |a, _| a.tcp(handles[0].as_ref().unwrap()).state() == State::Closed);
        close(pair);
    });
}

/// Without the early return, the Established read would be WouldBlock and
/// the Closed read and write ConnectionReset.
#[zhida_test_support::pinned_test]
fn empty_buffers_return_zero() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["emba", "embb"]);
        let (handles, _) = establish(&mut pair, Side::A);
        let mut handles = handles.map(Some);
        assert_eq!(read(&mut pair.b, &mut handles[1], &mut []).unwrap(), 0);
        assert_eq!(write(&mut pair.b, &mut handles[1], &[]).unwrap(), 0);
        a_aborts(&mut pair, &handles);
        assert_eq!(read(&mut pair.b, &mut handles[1], &mut []).unwrap(), 0);
        assert_eq!(write(&mut pair.b, &mut handles[1], &[]).unwrap(), 0);
        close(pair);
    });
}

type Client<'s> = ClientHandshake<StackStream<'s>>;
type Server<'s> = ServerHandshake<StackStream<'s>, NoCallback>;
type Ws<'s> = WebSocket<StackStream<'s>>;

/// The handshake result, or the handshake to resume after it was interrupted.
fn pending<R: HandshakeRole>(
    result: Result<R::FinalResult, HandshakeError<R>>,
) -> Result<R::FinalResult, MidHandshake<R>> {
    match result {
        Ok(done) => Ok(done),
        Err(HandshakeError::Interrupted(mid)) => Err(mid),
        Err(HandshakeError::Failure(error)) => panic!("{error}"),
    }
}

fn client_stack<'r>(
    client: &'r mut Result<(Ws<'_>, Response), MidHandshake<Client<'_>>>,
) -> &'r mut Stack {
    match client {
        Ok((ws, _)) => ws.get_mut().stack(),
        Err(mid) => mid.get_mut().get_mut().stack(),
    }
}

fn server_stack<'r>(server: &'r mut Result<Ws<'_>, MidHandshake<Server<'_>>>) -> &'r mut Stack {
    match server {
        Ok(ws) => ws.get_mut().stack(),
        Err(mid) => mid.get_mut().get_mut().stack(),
    }
}

/// Rounds until `step`, called after each, returns a value.
fn until<'s, T>(
    rounds: &mut Rounds,
    client: &mut Ws<'s>,
    server: &mut Ws<'s>,
    a_to_b: &mut Link,
    b_to_a: &mut Link,
    mut step: impl FnMut(&mut Ws<'s>, &mut Ws<'s>) -> Option<T>,
) -> T {
    loop {
        let moved = rounds.round(
            client.get_mut().stack(),
            a_to_b,
            server.get_mut().stack(),
            b_to_a,
        );
        if let Some(done) = step(client, server) {
            return done;
        }
        rounds.settle(moved, client.get_mut().stack(), server.get_mut().stack());
    }
}

/// `ws.read()`, with `None` for WouldBlock.
fn try_read(ws: &mut Ws<'_>) -> Option<Result<Message, Error>> {
    match ws.read() {
        Err(Error::Io(error)) if error.kind() == ErrorKind::WouldBlock => None,
        other => Some(other),
    }
}

#[zhida_test_support::pinned_test]
fn tungstenite_handshake_and_message_over_two_stacks() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["wsta", "wstb"]);
        let (handles, _) = establish(&mut pair, Side::A);
        let mut rounds = Rounds::new(pair.now());
        let url = format!("ws://{}:{SERVER_PORT}/", Side::B.ip());
        let Pair {
            a,
            b,
            a_to_b,
            b_to_a,
            ..
        } = &mut pair;

        let [client_handle, server_handle] = handles;
        let mut client = pending(client_with_config(
            url,
            StackStream::new(a, client_handle),
            None,
        ));
        let mut server = pending(accept_with_config(StackStream::new(b, server_handle), None));
        assert!(
            client.is_err() && server.is_err(),
            "handshake done before any round"
        );
        let (mut client, mut server) = loop {
            let moved = rounds.round(
                client_stack(&mut client),
                a_to_b,
                server_stack(&mut server),
                b_to_a,
            );
            let mut progress = moved;
            if let Err(mid) = client {
                client = pending(mid.handshake());
                progress |= client.is_ok();
            }
            if let Err(mid) = server {
                server = pending(mid.handshake());
                progress |= server.is_ok();
            }
            match (client, server) {
                (Ok((client, _)), Ok(server)) => break (client, server),
                (c, s) => (client, server) = (c, s),
            }
            rounds.settle(
                progress,
                client_stack(&mut client),
                server_stack(&mut server),
            );
        };

        let hello = Message::text("hello over zhida");
        client.send(hello.clone()).unwrap();
        let got = until(
            &mut rounds,
            &mut client,
            &mut server,
            a_to_b,
            b_to_a,
            |_, s| try_read(s),
        );
        assert_eq!(got.unwrap(), hello);
        server.send(hello.clone()).unwrap();
        let got = until(
            &mut rounds,
            &mut client,
            &mut server,
            a_to_b,
            b_to_a,
            |c, _| try_read(c),
        );
        assert_eq!(got.unwrap(), hello);

        client.close(None).unwrap();
        let got = until(
            &mut rounds,
            &mut client,
            &mut server,
            a_to_b,
            b_to_a,
            |_, s| try_read(s),
        );
        assert_eq!(got.unwrap(), Message::Close(None));
        // The server writes its close reply and is done; it closes TCP first.
        assert!(matches!(server.flush(), Err(Error::ConnectionClosed)));
        let (stack, handle) = server.get_mut().parts();
        stack.tcp_mut(handle).close();
        let got = until(
            &mut rounds,
            &mut client,
            &mut server,
            a_to_b,
            b_to_a,
            |c, _| try_read(c),
        );
        assert_eq!(got.unwrap(), Message::Close(None));
        // After the close reply tungstenite reports any end of the stream,
        // EOF or ConnectionReset, as ConnectionClosed, so this shows only that
        // the client sees the connection end; the EOF tests above pin the
        // StackStream results.
        let got = until(
            &mut rounds,
            &mut client,
            &mut server,
            a_to_b,
            b_to_a,
            |c, _| try_read(c),
        );
        assert!(matches!(got, Err(Error::ConnectionClosed)), "{got:?}");
        drop((client, server));
        close(pair);
    });
}

#[zhida_test_support::pinned_test]
fn read_fills_buffer_across_frames_keeping_partial_frame() {
    with_eal(|eal| {
        let configs = [pair::config(Side::A), pair::config(Side::B)];
        let mut pair = Pair::with_ports(eal, ["partiala", "partialb"], configs, pair::T0, 16, |side, port| {
            port.rx_pool.count = dpdk_smoltcp::rx_pool_count(
                dpdk_smoltcp::rx_reserve(port.rx_descriptors, configs[side.index()].rx_staging, port.rx_pool.cache_size),
                port.mtu,
                [65536],
            );
        });
        let (handles, _) = establish_sized(&mut pair, Side::A, 65536);
        let mut handles = handles.map(Some);
        let first = pattern(200, 21);
        send_to_b(&mut pair, &handles, &first);
        let second = pattern(200, 22);
        assert_eq!(pair.a.tcp_mut(handles[0].as_ref().unwrap()).send_slice(&second), Ok(second.len()));
        wait(&mut pair, |a, b| {
            a.tcp(handles[0].as_ref().unwrap()).send_queue() == 0
                && b.tcp(handles[1].as_ref().unwrap()).recv_queue() == first.len() + second.len()
        });
        with_stream(&mut pair.b, &mut handles[1], |stream| {
            let room = {
                let (stack, handle) = stream.parts();
                stack.tcp(handle).recv_room()
            };
            let mut buf = [0; 256];
            assert_eq!(stream.read(&mut buf[..50]).unwrap(), 50);
            assert_eq!(&buf[..50], &first[..50]);
            {
                let (stack, handle) = stream.parts();
                assert_eq!(stack.tcp(handle).held_frames().count(), 1);
                assert_eq!(stack.tcp(handle).recv_room(), room);
                assert_eq!(stack.tcp(handle).recv_queue(), second.len());
            }
            assert_eq!(stream.read(&mut []).unwrap(), 0);
            // One read fills the buffer across frames: the rest of the first frame, then
            // the start of the second, which stays pending.
            assert_eq!(stream.read(&mut buf).unwrap(), 256);
            assert_eq!(&buf[..150], &first[50..]);
            assert_eq!(&buf[150..], &second[..106]);
            {
                let (stack, handle) = stream.parts();
                assert_eq!(stack.tcp(handle).held_frames().count(), 1);
                assert_eq!(stack.tcp(handle).recv_queue(), 0);
                assert_eq!(stack.tcp(handle).recv_room(), room + 1460);
            }
            assert_eq!(stream.read(&mut buf).unwrap(), 94);
            assert_eq!(&buf[..94], &second[106..]);
            {
                let (stack, handle) = stream.parts();
                assert_eq!(stack.tcp(handle).held_frames().count(), 0);
            }
            assert_eq!(kind(stream.read(&mut buf)), ErrorKind::WouldBlock);
        });
        close(pair);
    });
}

#[zhida_test_support::pinned_test]
fn pending_bytes_precede_eof() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["pendeofa", "pendeofb"]);
        let (handles, _) = establish(&mut pair, Side::A);
        let mut handles = handles.map(Some);
        send_to_b(&mut pair, &handles, b"abcdef");
        let now = pair.now();
        let client = handles[0].take().unwrap();
        with_stream(&mut pair.b, &mut handles[1], |stream| {
            let mut buf = [0; 8];
            assert_eq!(stream.read(&mut buf[..2]).unwrap(), 2);
            assert_eq!(&buf[..2], b"ab");
            pair.a.tcp_mut(&client).close();
            let mut rounds = Rounds::new(now);
            loop {
                let moved = rounds.round(&mut pair.a, &mut pair.a_to_b, stream.stack(), &mut pair.b_to_a);
                let (stack, handle) = stream.parts();
                if stack.tcp(handle).state() == State::CloseWait {
                    break;
                }
                rounds.settle(moved, &mut pair.a, stream.stack());
            }
            assert_eq!(stream.read(&mut buf).unwrap(), 4);
            assert_eq!(&buf[..4], b"cdef");
            assert_eq!(stream.read(&mut buf).unwrap(), 0);
        });
        close(pair);
    });
}

#[zhida_test_support::pinned_test]
fn pending_bytes_precede_connection_reset() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["pendrsta", "pendrstb"]);
        let (handles, _) = establish(&mut pair, Side::A);
        let mut handles = handles.map(Some);
        send_to_b(&mut pair, &handles, b"abcdef");
        let now = pair.now();
        let client = handles[0].take().unwrap();
        with_stream(&mut pair.b, &mut handles[1], |stream| {
            let mut buf = [0; 8];
            assert_eq!(stream.read(&mut buf[..2]).unwrap(), 2);
            assert_eq!(&buf[..2], b"ab");
            pair.a.tcp_mut(&client).abort();
            let mut rounds = Rounds::new(now);
            loop {
                let moved = rounds.round(&mut pair.a, &mut pair.a_to_b, stream.stack(), &mut pair.b_to_a);
                let (stack, handle) = stream.parts();
                if stack.tcp(handle).state() == State::Closed {
                    break;
                }
                rounds.settle(moved, &mut pair.a, stream.stack());
            }
            assert_eq!(stream.read(&mut buf).unwrap(), 4);
            assert_eq!(&buf[..4], b"cdef");
            assert_eq!(kind(stream.read(&mut buf)), ErrorKind::ConnectionReset);
        });
        close(pair);
    });
}

#[zhida_test_support::pinned_test]
fn into_stack_discards_pending_bytes_and_releases_frame() {
    with_eal(|eal| {
        let mut pair = new_pair(eal, ["discarda", "discardb"]);
        let (handles, _) = establish(&mut pair, Side::A);
        let mut handles = handles.map(Some);
        send_to_b(&mut pair, &handles, b"abcdef");
        let held = pair.b.tcp(handles[1].as_ref().unwrap()).held_frames();
        let mut stream = StackStream::new(&mut pair.b, handles[1].take().unwrap());
        let mut buffer = [0; 2];
        assert_eq!(stream.read(&mut buffer).unwrap(), 2);
        assert_eq!(&buffer, b"ab");
        assert_eq!(held.count(), 1);
        let _stack = stream.into_stack();
        assert_eq!(held.count(), 0);
        close(pair);
    });
}
