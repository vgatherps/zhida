use alloc::{rc::Rc, vec::Vec};
use core::cell::RefCell;

use super::SocketHandle;
#[cfg(feature = "udp-set")]
use super::UdpHandle;

#[derive(Clone, Debug)]
pub struct DropQueue(Rc<RefCell<Dropped>>);

#[derive(Debug, Default)]
struct Dropped {
    tcp: Vec<SocketHandle>,
    wake: Vec<SocketHandle>,
    #[cfg(feature = "udp-set")]
    udp: Vec<UdpHandle>,
}

impl DropQueue {
    /// Capacities are the maximum number of live TCP and UDP handles, so pushes never allocate.
    pub fn with_capacity(tcp: usize, #[cfg(feature = "udp-set")] udp: usize) -> Self {
        Self(Rc::new(RefCell::new(Dropped {
            tcp: Vec::with_capacity(tcp),
            wake: Vec::with_capacity(tcp),
            #[cfg(feature = "udp-set")]
            udp: Vec::with_capacity(udp),
        })))
    }

    pub fn push_tcp(&self, handle: SocketHandle) {
        let mut dropped = self.0.borrow_mut();
        debug_assert!(dropped.tcp.len() < dropped.tcp.capacity());
        dropped.tcp.push(handle);
    }

    pub(crate) fn push_wake(&self, handle: SocketHandle) {
        let mut dropped = self.0.borrow_mut();
        debug_assert!(dropped.wake.len() < dropped.wake.capacity());
        dropped.wake.push(handle);
    }

    #[cfg(feature = "udp-set")]
    pub fn push_udp(&self, handle: UdpHandle) {
        let mut dropped = self.0.borrow_mut();
        debug_assert!(dropped.udp.len() < dropped.udp.capacity());
        dropped.udp.push(handle);
    }

    /// True when no dropped handles or receive wakes are queued.
    pub fn is_empty(&self) -> bool {
        let dropped = self.0.borrow();
        let empty = dropped.tcp.is_empty() && dropped.wake.is_empty();
        #[cfg(feature = "udp-set")]
        let empty = empty && dropped.udp.is_empty();
        empty
    }

    /// Append queued handles and wakes to the supplied lists, retaining the queue's capacity.
    pub fn drain_into(
        &self,
        tcp: &mut Vec<SocketHandle>,
        #[cfg(feature = "udp-set")] udp: &mut Vec<UdpHandle>,
        wake: &mut Vec<SocketHandle>,
    ) {
        let mut dropped = self.0.borrow_mut();
        tcp.append(&mut dropped.tcp);
        #[cfg(feature = "udp-set")]
        udp.append(&mut dropped.udp);
        wake.append(&mut dropped.wake);
    }

    /// True when `self` and `other` are the same queue.
    pub fn same(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

#[cfg(all(test, feature = "udp-set"))]
mod tests {
    use super::*;
    use crate::iface::{TcpSet, UdpConfig, UdpSet};
    use crate::socket::tcp;

    fn handles() -> ([SocketHandle; 3], [UdpHandle; 3]) {
        let mut tcp = TcpSet::new(Vec::new());
        let tcp = core::array::from_fn(|_| {
            tcp.add(tcp::Socket::new(tcp::RxBuffer::new(0), tcp::SocketBuffer::new(Vec::new())))
        });
        let mut udp = UdpSet::new(3);
        let udp = core::array::from_fn(|index| {
            udp.add(UdpConfig {
                port: u16::try_from(1000 + index).unwrap(),
                rx_queue: 1,
                tx_checksum: true,
                broadcast: false,
            }).unwrap()
        });
        (tcp, udp)
    }

    #[test]
    fn push_and_drain_append_in_order() {
        let (tcp_handles, udp_handles) = handles();
        let queue = DropQueue::with_capacity(2, 2);
        assert!(queue.is_empty());
        queue.push_tcp(tcp_handles[1]);
        assert!(!queue.is_empty());
        queue.push_udp(udp_handles[1]);
        queue.push_tcp(tcp_handles[2]);
        queue.push_udp(udp_handles[2]);
        let mut tcp = Vec::from([tcp_handles[0]]);
        let mut udp = Vec::from([udp_handles[0]]);
        queue.drain_into(&mut tcp, &mut udp, &mut Vec::new());
        assert_eq!(tcp, tcp_handles);
        assert_eq!(udp, udp_handles);
        assert!(queue.is_empty());
        queue.drain_into(&mut tcp, &mut udp, &mut Vec::new());
        assert_eq!(tcp, tcp_handles);
        assert_eq!(udp, udp_handles);
        queue.push_udp(udp_handles[0]);
        assert!(!queue.is_empty());
    }

    #[test]
    fn push_and_drain_keep_capacity_and_allocation() {
        let (tcp_handles, udp_handles) = handles();
        let queue = DropQueue::with_capacity(3, 3);
        let allocation = {
            let dropped = queue.0.borrow();
            (dropped.tcp.capacity(), dropped.tcp.as_ptr(),
             dropped.udp.capacity(), dropped.udp.as_ptr())
        };
        let mut tcp = Vec::with_capacity(3);
        let mut udp = Vec::with_capacity(3);
        for _ in 0..2 {
            for handle in tcp_handles {
                queue.push_tcp(handle);
            }
            for handle in udp_handles {
                queue.push_udp(handle);
            }
            queue.drain_into(&mut tcp, &mut udp, &mut Vec::new());
            assert_eq!(tcp, tcp_handles);
            assert_eq!(udp, udp_handles);
            let dropped = queue.0.borrow();
            assert_eq!(allocation,
                       (dropped.tcp.capacity(), dropped.tcp.as_ptr(),
                        dropped.udp.capacity(), dropped.udp.as_ptr()));
            assert!(dropped.tcp.is_empty());
            assert!(dropped.udp.is_empty());
            tcp.clear();
            udp.clear();
        }
    }

    #[test]
    fn same_identifies_shared_queue() {
        let (tcp_handles, udp_handles) = handles();
        let queue = DropQueue::with_capacity(1, 1);
        let clone = queue.clone();
        let other = DropQueue::with_capacity(1, 1);
        assert!(queue.same(&queue));
        assert!(queue.same(&clone));
        assert!(clone.same(&queue));
        assert!(!queue.same(&other));
        clone.push_tcp(tcp_handles[0]);
        clone.push_udp(udp_handles[0]);
        assert!(!queue.is_empty());
        let mut tcp = Vec::new();
        let mut udp = Vec::new();
        queue.drain_into(&mut tcp, &mut udp, &mut Vec::new());
        assert_eq!(tcp, [tcp_handles[0]]);
        assert_eq!(udp, [udp_handles[0]]);
        assert!(clone.is_empty());
        assert!(other.is_empty());
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic]
    fn push_tcp_past_capacity_panics() {
        let (tcp, _) = handles();
        let queue = DropQueue::with_capacity(1, 0);
        queue.push_tcp(tcp[0]);
        queue.push_tcp(tcp[1]);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic]
    fn push_udp_past_capacity_panics() {
        let (_, udp) = handles();
        let queue = DropQueue::with_capacity(0, 1);
        queue.push_udp(udp[0]);
        queue.push_udp(udp[1]);
    }
}
