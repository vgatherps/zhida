use std::fmt;
use std::mem::ManuallyDrop;
use std::ptr;

use smoltcp::iface::{DropQueue, SocketHandle};

/// Owned name of one TCP socket in one [`Stack`](crate::Stack).
/// Access it through `&handle` on the Stack that made it. `Stack::remove_tcp`
/// consumes it and removes the socket immediately. Dropping it queues cleanup
/// at the start of the Stack's next `turn`, `receive`, `send`,
/// `add_tcp` or `add_udp`. TCP closes like Linux `close()`:
/// unread in-order data causes RST; otherwise it sends FIN. The slot stays
/// occupied until the connection is fully closed. This handle holds an Rc
/// and is single-threaded, not Send.
///
/// ```compile_fail,E0382
/// use dpdk_smoltcp::{Stack, TcpHandle};
/// fn f(stack: &mut Stack, h: TcpHandle) {
///     stack.remove_tcp(h);
///     stack.tcp(&h);
/// }
/// ```
/// ```compile_fail,E0382
/// use dpdk_smoltcp::{Stack, TcpHandle};
/// fn f(stack: &mut Stack, h: TcpHandle) {
///     stack.remove_tcp(h);
///     stack.remove_tcp(h);
/// }
/// ```
/// ```compile_fail,E0599
/// use dpdk_smoltcp::TcpHandle;
/// fn f(h: TcpHandle) { h.clone(); }
/// ```
/// ```compile_fail,E0277
/// use dpdk_smoltcp::TcpHandle;
/// fn needs_send<T: Send>(_: T) {}
/// fn f(h: TcpHandle) { needs_send(h); }
/// ```
/// ```no_run
/// use dpdk_smoltcp::{Stack, TcpHandle};
/// fn f(stack: &mut Stack, h: TcpHandle) {
///     let state = stack.tcp(&h).state();
///     stack.remove_tcp(h);
/// }
/// ```
pub struct TcpHandle {
    pub(crate) raw: SocketHandle,
    pub(crate) queue: DropQueue,
}

impl TcpHandle {
    pub(crate) fn into_raw(self) -> SocketHandle {
        let handle = ManuallyDrop::new(self);
        let raw = handle.raw;
        // SAFETY: ManuallyDrop prevents the handle's Drop. Read and drop the
        // queue once to release its Rc; raw is Copy and has no destructor.
        unsafe { drop(ptr::read(&handle.queue)) };
        raw
    }
}

impl fmt::Debug for TcpHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.raw, f)
    }
}

/// Displays the socket slot index.
impl fmt::Display for TcpHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.raw, f)
    }
}

impl Drop for TcpHandle {
    fn drop(&mut self) {
        self.queue.push_tcp(self.raw);
    }
}

/// Owned name of one UDP socket (one bound local port) in one [`Stack`](crate::Stack).
/// Access it through `&handle` on the Stack that made it. `Stack::remove_udp`
/// consumes it and removes the socket immediately. Dropping it queues cleanup
/// at the start of the Stack's next `turn`, `receive`, `send`,
/// `add_tcp` or `add_udp`, freeing the port binding and RX budget.
/// Datagrams the application holds stay valid and count against RX admission
/// until dropped. This handle holds an Rc and is single-threaded, not Send.
///
/// ```compile_fail,E0382
/// use dpdk_smoltcp::{Stack, UdpHandle};
/// fn f(stack: &mut Stack, h: UdpHandle) {
///     stack.remove_udp(h);
///     stack.udp(&h);
/// }
/// ```
/// ```compile_fail,E0382
/// use dpdk_smoltcp::{Stack, UdpHandle};
/// fn f(stack: &mut Stack, h: UdpHandle) {
///     stack.remove_udp(h);
///     stack.remove_udp(h);
/// }
/// ```
pub struct UdpHandle {
    pub(crate) raw: smoltcp::iface::UdpHandle,
    pub(crate) queue: DropQueue,
}

impl UdpHandle {
    pub(crate) fn into_raw(self) -> smoltcp::iface::UdpHandle {
        let handle = ManuallyDrop::new(self);
        let raw = handle.raw;
        // SAFETY: ManuallyDrop prevents the handle's Drop. Read and drop the
        // queue once to release its Rc; raw is Copy and has no destructor.
        unsafe { drop(ptr::read(&handle.queue)) };
        raw
    }
}

impl fmt::Debug for UdpHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.raw, f)
    }
}

impl Drop for UdpHandle {
    fn drop(&mut self) {
        self.queue.push_udp(self.raw);
    }
}
