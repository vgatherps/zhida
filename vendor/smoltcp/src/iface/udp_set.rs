use alloc::{collections::VecDeque, rc::Rc, vec::Vec};
use core::ops::Range;

use super::flow_table::FlowTable;
use crate::phy::{HeldFrames, RxBuf, RxShared};
use crate::wire::{IpAddress, IpEndpoint, Ipv4Address};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UdpHandle {
    slot: usize,
    generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpConfig {
    pub port: u16,
    pub rx_queue: usize,
    /// Compute the UDP checksum in software when true, or write 0 when false.
    /// With a device whose `checksum.udp` capability has no TX, smoltcp always
    /// writes 0; whether the checksum is filled in later depends on the device.
    pub tx_checksum: bool,
    pub broadcast: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpAddError {
    Full,
    PortInUse,
    InvalidConfig(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpConnectError {
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSendError {
    NoDestination,
    PeerMismatch,
    Unaddressable,
    TooLarge,
    NoRoute,
    NeighborPending,
    WouldBlock,
}

/// A validated UDP send: socket, destination and payload length.
/// `Interface::udp_target` makes one; pass it to `udp_send` of the same `Interface`, with the
/// same `UdpSet`, before the socket or the interface's addresses change.
#[derive(Debug, PartialEq, Eq)]
pub struct UdpTarget {
    pub(crate) handle: UdpHandle,
    pub(crate) to: IpEndpoint,
    pub(crate) dst_addr: Ipv4Address,
    pub(crate) len: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UdpCounters {
    pub rx_no_port: u64,
    pub rx_checksum_bad: u64,
    pub rx_malformed: u64,
    pub rx_not_unicast: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UdpSocketStats {
    pub rx_delivered: u64,
    pub rx_dropped_full: u64,
    pub rx_dropped_peer: u64,
}

#[derive(Debug)]
pub struct UdpDatagram {
    frame: RxBuf,
    src: IpEndpoint,
    dst_addr: Ipv4Address,
    shared: Rc<RxShared>,
}

impl UdpDatagram {
    pub fn rx_timestamp(&self) -> u64 {
        self.frame.rx_timestamp()
    }

    pub fn payload(&self) -> &[u8] {
        self.frame.as_slice()
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        self.frame.as_mut_slice()
    }

    pub fn src(&self) -> IpEndpoint {
        self.src
    }

    pub fn dst_addr(&self) -> Ipv4Address {
        self.dst_addr
    }
}

impl Drop for UdpDatagram {
    fn drop(&mut self) {
        self.shared.release();
    }
}

#[derive(Debug)]
pub struct UdpSocket {
    config: UdpConfig,
    peer: Option<IpEndpoint>,
    queue: VecDeque<UdpDatagram>,
    shared: Rc<RxShared>,
    pub(crate) stats: UdpSocketStats,
    pub(crate) template: Option<super::header_template::UdpTemplate>,
}

impl UdpSocket {
    pub fn config(&self) -> &UdpConfig {
        &self.config
    }

    pub fn connect(&mut self, peer: IpEndpoint) -> Result<(), UdpConnectError> {
        if !matches!(peer.addr, IpAddress::Ipv4(_)) || !peer.addr.is_unicast() || peer.port == 0 {
            return Err(UdpConnectError::Invalid);
        }
        self.peer = Some(peer);
        Ok(())
    }

    pub fn peer(&self) -> Option<IpEndpoint> {
        self.peer
    }

    pub fn recv(&mut self) -> Option<UdpDatagram> {
        self.queue.pop_front()
    }

    pub fn rx_queued(&self) -> usize {
        self.queue.len()
    }

    pub fn stats(&self) -> UdpSocketStats {
        self.stats
    }

    pub(crate) fn at_limit(&self) -> bool {
        self.shared.held.get() == self.config.rx_queue
    }
}

#[derive(Debug)]
struct Slot {
    socket: Option<UdpSocket>,
    generation: u64,
}

#[derive(Debug)]
pub(crate) struct PendingUdp {
    pub(crate) src: IpEndpoint,
    pub(crate) dst_addr: Ipv4Address,
    pub(crate) payload: Range<usize>,
}

#[derive(Debug)]
pub struct UdpSet {
    slots: Vec<Slot>,
    ports: FlowTable<u16>,
    pub(crate) counters: UdpCounters,
    pub(crate) pending_rx_attach: Option<(usize, PendingUdp)>,
    #[cfg(test)]
    pub(crate) template_frames: usize,
}

impl UdpSet {
    pub fn new(max_sockets: usize) -> Self {
        Self {
            slots: (0..max_sockets)
                .map(|_| Slot {
                    socket: None,
                    generation: 0,
                })
                .collect(),
            ports: FlowTable::new(max_sockets),
            counters: UdpCounters::default(),
            pending_rx_attach: None,
            #[cfg(test)]
            template_frames: 0,
        }
    }

    pub fn add(&mut self, config: UdpConfig) -> Result<UdpHandle, UdpAddError> {
        if config.port == 0 {
            return Err(UdpAddError::InvalidConfig("UDP port is zero"));
        }
        if config.rx_queue == 0 {
            return Err(UdpAddError::InvalidConfig("UDP receive queue is zero"));
        }
        if self.ports.get(&config.port).is_some() {
            return Err(UdpAddError::PortInUse);
        }
        let slot = self
            .slots
            .iter()
            .position(|slot| slot.socket.is_none())
            .ok_or(UdpAddError::Full)?;
        self.slots[slot].socket = Some(UdpSocket {
            config,
            peer: None,
            queue: VecDeque::with_capacity(config.rx_queue),
            shared: RxShared::new(),
            stats: UdpSocketStats::default(),
            template: None,
        });
        self.ports.set(config.port, slot);
        Ok(UdpHandle {
            slot,
            generation: self.slots[slot].generation,
        })
    }

    pub fn get(&self, handle: UdpHandle) -> &UdpSocket {
        let slot = &self.slots[handle.slot];
        assert_eq!(slot.generation, handle.generation, "stale UDP handle");
        slot.socket.as_ref().expect("removed UDP handle")
    }

    pub fn get_mut(&mut self, handle: UdpHandle) -> &mut UdpSocket {
        let slot = &mut self.slots[handle.slot];
        assert_eq!(slot.generation, handle.generation, "stale UDP handle");
        slot.socket.as_mut().expect("removed UDP handle")
    }

    pub fn remove(&mut self, handle: UdpHandle) -> HeldFrames {
        let socket = self.get(handle);
        let port = socket.config.port;
        let held = HeldFrames::new(socket.shared.clone());
        let slot = &mut self.slots[handle.slot];
        slot.generation = slot
            .generation
            .checked_add(1)
            .expect("UDP generation overflow");
        slot.socket = None;
        self.ports.remove(&port);
        held
    }

    pub fn counters(&self) -> UdpCounters {
        self.counters
    }

    pub(crate) fn lookup(&self, port: u16) -> Option<usize> {
        self.ports.get(&port)
    }

    pub(crate) fn socket_at_mut(&mut self, slot: usize) -> &mut UdpSocket {
        self.slots[slot]
            .socket
            .as_mut()
            .expect("UDP socket is missing")
    }

    pub(crate) fn commit_rx(&mut self, slot: usize, mut frame: RxBuf, pending: PendingUdp) {
        let socket = self.socket_at_mut(slot);
        assert!(!socket.at_limit(), "UDP receive credit is exhausted");
        frame.narrow(pending.payload);
        socket.shared.hold();
        socket.queue.push_back(UdpDatagram {
            frame,
            src: pending.src,
            dst_addr: pending.dst_addr,
            shared: socket.shared.clone(),
        });
        socket.stats.rx_delivered = socket
            .stats
            .rx_delivered
            .checked_add(1)
            .expect("UDP delivered count overflow");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    use crate::wire::IpAddress;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn config(port: u16) -> UdpConfig {
        UdpConfig {
            port,
            rx_queue: 2,
            tx_checksum: true,
            broadcast: false,
        }
    }

    #[test]
    fn duplicate_port_refused_without_change() {
        let mut set = UdpSet::new(2);
        let handle = set.add(config(1234)).unwrap();
        let peer = IpEndpoint::new(IpAddress::v4(192, 168, 1, 2), 4321);
        set.get_mut(handle).connect(peer).unwrap();
        assert_eq!(set.add(config(1234)), Err(UdpAddError::PortInUse));
        assert_eq!(set.get(handle).config(), &config(1234));
        assert_eq!(set.get(handle).peer(), Some(peer));
        assert_eq!(set.lookup(1234), Some(handle.slot));
        assert!(set.add(config(1235)).is_ok());
    }

    #[test]
    fn stale_handle_panics() {
        let mut set = UdpSet::new(1);
        let old = set.add(config(1234)).unwrap();
        set.remove(old);
        assert!(catch_unwind(AssertUnwindSafe(|| set.get(old))).is_err());
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                set.get_mut(old);
            }))
            .is_err()
        );
        assert!(catch_unwind(AssertUnwindSafe(|| set.remove(old))).is_err());
        let new = set.add(config(1234)).unwrap();
        assert_ne!(old, new);
        assert!(catch_unwind(AssertUnwindSafe(|| set.get(old))).is_err());
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                set.get_mut(old);
            }))
            .is_err()
        );
        assert!(catch_unwind(AssertUnwindSafe(|| set.remove(old))).is_err());
        assert_eq!(set.get(new).config().port, 1234);
    }

    #[test]
    fn receive_queue_wraps_without_growing() {
        let mut set = UdpSet::new(1);
        let handle = set
            .add(UdpConfig {
                rx_queue: 3,
                ..config(1234)
            })
            .unwrap();
        let capacity = set.get(handle).queue.capacity();
        assert_eq!(capacity, 3);
        let releases = Rc::new(Cell::new(0));
        let enqueue = |set: &mut UdpSet, byte| {
            set.commit_rx(
                handle.slot,
                RxBuf::counted_frame(alloc::vec![0, byte, 0], 0, releases.clone()),
                PendingUdp {
                    src: IpEndpoint::new(IpAddress::v4(192, 168, 1, 2), 4321),
                    dst_addr: Ipv4Address::new(192, 168, 1, 1),
                    payload: 1..2,
                },
            );
            assert_eq!(set.get(handle).queue.capacity(), capacity);
        };
        for cycle in 0..4 {
            let first = cycle * 5;
            for offset in 0..3 {
                enqueue(&mut set, first + offset);
                assert_eq!(set.get(handle).rx_queued(), usize::from(offset) + 1);
            }
            assert!(set.get(handle).at_limit());
            for offset in 0..2 {
                let datagram = set.get_mut(handle).recv().unwrap();
                assert_eq!(datagram.payload(), &[first + offset]);
                drop(datagram);
                assert_eq!(set.get(handle).rx_queued(), 2 - usize::from(offset));
                assert_eq!(set.get(handle).queue.capacity(), capacity);
            }
            for offset in 3..5 {
                enqueue(&mut set, first + offset);
                assert_eq!(set.get(handle).rx_queued(), usize::from(offset) - 1);
            }
            assert!(set.get(handle).at_limit());
            for offset in 2..5 {
                let datagram = set.get_mut(handle).recv().unwrap();
                assert_eq!(datagram.payload(), &[first + offset]);
                drop(datagram);
                assert_eq!(set.get(handle).rx_queued(), 4 - usize::from(offset));
                assert_eq!(set.get(handle).queue.capacity(), capacity);
            }
            assert!(set.get_mut(handle).recv().is_none());
            assert_eq!(set.get(handle).shared.held.get(), 0);
        }
        assert_eq!(releases.get(), 20);
        assert_eq!(set.get(handle).stats().rx_delivered, 20);
        assert_eq!(set.get(handle).stats().rx_dropped_full, 0);
        assert_eq!(set.get(handle).stats().rx_dropped_peer, 0);
    }

    #[test]
    fn remove_frees_queued_held_stays_valid() {
        let mut set = UdpSet::new(1);
        let handle = set.add(config(1234)).unwrap();
        let releases = Rc::new(Cell::new(0));
        for byte in [1, 2] {
            set.commit_rx(
                handle.slot,
                RxBuf::counted_frame(alloc::vec![0, byte, 0], 0, releases.clone()),
                PendingUdp {
                    src: IpEndpoint::new(IpAddress::v4(192, 168, 1, 2), 4321),
                    dst_addr: Ipv4Address::new(192, 168, 1, 1),
                    payload: 1..2,
                },
            );
        }
        let mut held = set.get_mut(handle).recv().unwrap();
        set.remove(handle);
        assert_eq!(set.lookup(1234), None);
        assert_eq!(releases.get(), 1);
        assert_eq!(held.payload(), &[1]);
        held.payload_mut()[0] = 3;
        assert_eq!(held.payload(), &[3]);
        let replacement = set.add(config(1234)).unwrap();
        assert_eq!(set.get(replacement).shared.held.get(), 0);
        drop(held);
        assert_eq!(releases.get(), 2);
        assert_eq!(set.get(replacement).shared.held.get(), 0);
    }

    #[test]
    fn remove_returns_held_count() {
        let mut set = UdpSet::new(1);
        let handle = set
            .add(UdpConfig {
                rx_queue: 3,
                ..config(1234)
            })
            .unwrap();
        let releases = Rc::new(Cell::new(0));
        for byte in [1, 2, 3] {
            set.commit_rx(
                handle.slot,
                RxBuf::counted_frame(alloc::vec![byte], 0, releases.clone()),
                PendingUdp {
                    src: IpEndpoint::new(IpAddress::v4(192, 168, 1, 2), 4321),
                    dst_addr: Ipv4Address::new(192, 168, 1, 1),
                    payload: 0..1,
                },
            );
        }
        let first = set.get_mut(handle).recv().unwrap();
        let second = set.get_mut(handle).recv().unwrap();
        let held = set.remove(handle);
        assert_eq!(held.count(), 2);
        assert_eq!(releases.get(), 1);
        drop(first);
        assert_eq!(held.count(), 1);
        assert_eq!(releases.get(), 2);
        drop(second);
        assert_eq!(held.count(), 0);
        assert_eq!(releases.get(), 3);
    }

    #[test]
    fn removed_datagram_drop_clears_count_without_wake() {
        let mut set = UdpSet::new(1);
        let handle = set.add(config(1234)).unwrap();
        let shared = set.get(handle).shared.clone();
        let releases = Rc::new(Cell::new(0));
        for byte in [1, 2] {
            set.commit_rx(
                handle.slot,
                RxBuf::counted_frame(alloc::vec![byte], 0, releases.clone()),
                PendingUdp {
                    src: IpEndpoint::new(IpAddress::v4(192, 168, 1, 2), 4321),
                    dst_addr: Ipv4Address::new(192, 168, 1, 1),
                    payload: 0..1,
                },
            );
            assert!(shared.wake.borrow().is_none());
            assert_eq!(shared.wake_at_held.get(), usize::MAX);
            assert!(!shared.wake_queued.get());
        }
        let datagram = set.get_mut(handle).recv().unwrap();
        let held = set.remove(handle);
        assert_eq!(held.count(), 1);
        assert_eq!(releases.get(), 1);
        assert!(shared.wake.borrow().is_none());
        assert_eq!(shared.wake_at_held.get(), usize::MAX);
        assert!(!shared.wake_queued.get());
        drop(datagram);
        assert_eq!(held.count(), 0);
        assert_eq!(releases.get(), 2);
        assert!(shared.wake.borrow().is_none());
        assert_eq!(shared.wake_at_held.get(), usize::MAX);
        assert!(!shared.wake_queued.get());
    }

    #[test]
    fn at_limit_counts_drained_datagrams_until_drop() {
        let mut set = UdpSet::new(1);
        let handle = set.add(config(1234)).unwrap();
        let releases = Rc::new(Cell::new(0));
        assert!(!set.get(handle).at_limit());
        let mut datagrams = Vec::new();
        for byte in [1, 2] {
            set.commit_rx(
                handle.slot,
                RxBuf::counted_frame(alloc::vec![byte], 0, releases.clone()),
                PendingUdp {
                    src: IpEndpoint::new(IpAddress::v4(192, 168, 1, 2), 4321),
                    dst_addr: Ipv4Address::new(192, 168, 1, 1),
                    payload: 0..1,
                },
            );
            assert_eq!(set.get(handle).at_limit(), byte == 2);
            datagrams.push(set.get_mut(handle).recv().unwrap());
            assert_eq!(set.get(handle).rx_queued(), 0);
            assert_eq!(set.get(handle).at_limit(), byte == 2);
        }
        drop(datagrams.pop().unwrap());
        assert!(!set.get(handle).at_limit());
        assert_eq!(set.get(handle).shared.held.get(), 1);
        assert_eq!(releases.get(), 1);
        drop(datagrams);
        assert_eq!(set.get(handle).shared.held.get(), 0);
        assert_eq!(releases.get(), 2);
    }

    #[test]
    fn invalid_config_refused() {
        let mut set = UdpSet::new(1);
        assert!(matches!(
            set.add(config(0)),
            Err(UdpAddError::InvalidConfig(_))
        ));
        assert!(matches!(
            set.add(UdpConfig {
                rx_queue: 0,
                ..config(1234)
            }),
            Err(UdpAddError::InvalidConfig(_))
        ));
        let handle = set.add(config(1234)).unwrap();
        let peer = IpEndpoint::new(IpAddress::v4(192, 168, 1, 2), 4321);
        set.get_mut(handle).connect(peer).unwrap();
        for invalid in [
            IpEndpoint::new(IpAddress::v4(0, 0, 0, 0), 4321),
            IpEndpoint::new(IpAddress::v4(224, 0, 0, 1), 4321),
            IpEndpoint::new(IpAddress::v4(255, 255, 255, 255), 4321),
            IpEndpoint::new(peer.addr, 0),
        ] {
            assert_eq!(
                set.get_mut(handle).connect(invalid),
                Err(UdpConnectError::Invalid)
            );
            assert_eq!(set.get(handle).peer(), Some(peer));
        }
    }

    #[test]
    fn full_set() {
        assert_eq!(UdpSet::new(0).add(config(1234)), Err(UdpAddError::Full));
        let mut set = UdpSet::new(1);
        let handle = set.add(config(1234)).unwrap();
        assert_eq!(set.add(config(1235)), Err(UdpAddError::Full));
        assert_eq!(set.lookup(1235), None);
        assert_eq!(set.get(handle).config(), &config(1234));
        set.remove(handle);
        assert!(set.add(config(1235)).is_ok());
        assert_eq!(set.slots.len(), 1);
    }
}
