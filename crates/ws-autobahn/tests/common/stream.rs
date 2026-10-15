use std::io::{self, Cursor, Read, Write};

use dpdk_smoltcp::{Stack, TcpFrame, TcpHandle};
use stack_stream::StackStream;

pub struct PeerStream<'a, 's> {
    stream: StackStream<'s>,
    pending: &'a mut Option<(TcpFrame, usize)>,
}

pub fn with_stream<T>(
    stack: &mut Stack,
    handle: &mut Option<TcpHandle>,
    pending: &mut Option<(TcpFrame, usize)>,
    body: impl FnOnce(&mut PeerStream<'_, '_>) -> T,
) -> T {
    let mut peer = PeerStream { stream: StackStream::new(stack, handle.take().unwrap()), pending };
    let result = body(&mut peer);
    let (_, owned) = peer.stream.into_parts();
    *handle = Some(owned);
    result
}

impl Read for PeerStream<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return self.stream.read(buf);
        }
        if self.pending.is_none() {
            let (stack, handle) = self.stream.parts();
            let socket = stack.tcp_mut(handle);
            if socket.can_recv() {
                *self.pending = Some((socket.recv().unwrap().unwrap(), 0));
            }
        }
        let Some((frame, offset)) = self.pending.as_mut() else {
            return self.stream.read(buf);
        };
        let mut cursor = Cursor::new(frame.payload());
        cursor.set_position(u64::try_from(*offset).expect("frame offset fits u64"));
        let read = cursor.read(buf)?;
        *offset = usize::try_from(cursor.position()).expect("frame offset fits usize");
        if *offset == frame.payload().len() {
            *self.pending = None;
        }
        Ok(read)
    }
}

impl Write for PeerStream<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
