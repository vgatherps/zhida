//! Test-only net_ring Port fixture for Stack tests. The test is the ring peer:
//! it produces frames onto the RX ring from the port's own RX pool and takes
//! frames off the TX ring. Pools are found by the names in the PortConfig.

use std::cell::Cell;
use std::collections::VecDeque;
use std::ffi::{c_void, CStr, CString};
use std::io::Write;
use std::ptr::null_mut;

use dpdk_smoltcp::smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
    EthernetRepr, Ipv4Address,
};
use dpdk_smoltcp::{Eal, Offloads, Port, PortConfig};
use zhida_buffer::PoolConfig;
use zhida_dpdk_sys::*;

use crate::wire;

/// Dropped without `close`, it frees the frames on both rings and releases the
/// vdev and rings unless a Port it opened still uses the device; outside a
/// panic it then fails the test.
pub struct RingPort {
    port_id: u16,
    vdev: CString,
    pub(crate) rx_ring: *mut rte_ring,
    pub(crate) tx_ring: *mut rte_ring,
    rx_pool: CString,
    tx_pool: CString,
    opened: Cell<bool>,
    closed: bool,
}

impl RingPort {
    /// `name` is short and unique among live fixtures. Ring sizes are powers of
    /// two holding one entry less than their size.
    pub fn new(name: &str, rx_ring: u32, tx_ring: u32) -> Self {
        let ring = |suffix: &str, size| {
            let ring_name = CString::new(format!("{name}_{suffix}")).unwrap();
            let ring = unsafe {
                rte_ring_create(ring_name.as_ptr(), size, -1, RING_F_SP_ENQ | RING_F_SC_DEQ)
            };
            assert!(!ring.is_null());
            ring
        };
        let (rx_ring, tx_ring) = (ring("rxr", rx_ring), ring("txr", tx_ring));
        let port_name = CString::new(name).unwrap();
        let id = unsafe { rte_eth_from_rings(port_name.as_ptr(), &rx_ring, 1, &tx_ring, 1, 0) };
        assert!(id >= 0);
        Self {
            port_id: id as u16,
            vdev: CString::new(format!("net_ring_{name}")).unwrap(),
            rx_ring,
            tx_ring,
            rx_pool: CString::new(format!("{name}_rxp")).unwrap(),
            tx_pool: CString::new(format!("{name}_txp")).unwrap(),
            opened: Cell::new(false),
            closed: false,
        }
    }

    pub fn port_id(&self) -> u16 {
        self.port_id
    }

    pub fn rx_ring(&self) -> *mut rte_ring {
        self.rx_ring
    }

    pub fn tx_ring(&self) -> *mut rte_ring {
        self.tx_ring
    }

    pub fn open(&self, eal: &Eal) -> Port {
        self.open_with(eal, self.config())
    }

    /// IP MTU 1500, 16 descriptors and bursts of 8 each way, RX and TX pools
    /// of 63 packets with per-lcore cache 8, each with 2048 usable bytes,
    /// under this fixture's pool names.
    pub fn config(&self) -> PortConfig<'_> {
        fn pool(name: &CStr) -> PoolConfig<'_> {
            PoolConfig {
                name,
                count: 63,
                cache_size: 8,
                data_room_size: RTE_PKTMBUF_HEADROOM as u16 + 2048,
                socket_id: -1,
            }
        }
        PortConfig {
            port_id: self.port_id,
            mtu: 1500,
            rx_descriptors: 16,
            tx_descriptors: 16,
            rx_burst: 8,
            tx_burst: 8,
            queue_socket: -1,
            rx_pool: pool(&self.rx_pool),
            tx_pool: pool(&self.tx_pool),
            offloads: Offloads::default(),
        }
    }

    /// `config` names this fixture's port and pools; `config()` with changes.
    pub fn open_with(&self, eal: &Eal, config: PortConfig<'_>) -> Port {
        assert_eq!(config.port_id, self.port_id);
        assert_eq!(config.rx_pool.name, self.rx_pool.as_c_str());
        assert_eq!(config.tx_pool.name, self.tx_pool.as_c_str());
        let port = unsafe { Port::open(eal, config) }.unwrap();
        self.opened.set(true);
        port
    }

    /// Enqueue every frame on the RX ring, each a copy in the port's RX pool.
    pub fn inject(&self, frames: &[Vec<u8>]) {
        self.inject_from(wire::pool_by_name(&self.rx_pool), frames);
    }

    /// `inject` with the copies from `pool`, the open Port's RX pool.
    pub(crate) fn inject_from(&self, pool: *mut rte_mempool, frames: &[Vec<u8>]) {
        for bytes in frames {
            self.enqueue_rx(wire::copy_into(pool, bytes));
        }
    }

    /// Enqueue one frame copied into the port's TX pool, which the Port's RX
    /// burst must reject.
    pub fn inject_foreign(&self, bytes: &[u8]) {
        self.enqueue_rx(wire::copy_into(wire::pool_by_name(&self.tx_pool), bytes));
    }

    fn enqueue_rx(&self, packet: *mut rte_mbuf) {
        let raw = [packet.cast::<c_void>()];
        let queued =
            unsafe { dpdk_raw_ring_enqueue_burst(self.rx_ring, raw.as_ptr(), 1, null_mut()) };
        if queued != 1 {
            unsafe { dpdk_raw_pktmbuf_free(packet) };
        }
        assert_eq!(queued, 1, "RX ring full");
    }

    /// Take every frame off the TX ring, returning copies of their bytes.
    pub fn take_tx(&self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let mut burst = wire::Burst::<16>::new();
        loop {
            let packets = burst.refill(self.tx_ring);
            if packets.is_empty() {
                return frames;
            }
            for &packet in packets {
                unsafe {
                    let len = usize::from((*packet).data_len());
                    frames.push(std::slice::from_raw_parts((*packet).data_ptr(), len).to_vec());
                }
            }
        }
    }

    /// Free every frame left on both rings; returns how many.
    pub fn drain(&self) -> usize {
        wire::drain_ring(self.tx_ring) + wire::drain_ring(self.rx_ring)
    }

    /// The open Port's RX pool.
    pub fn rx_pool(&self) -> *mut rte_mempool {
        wire::pool_by_name(&self.rx_pool)
    }

    /// The link from this port's TX ring to `receiver`'s RX ring, while both
    /// Ports are open.
    pub fn link_to(&self, receiver: &RingPort) -> wire::Link {
        wire::Link::new(self.tx_ring, receiver.rx_ring, receiver.rx_pool())
    }

    /// (RX, TX) pool packets in use, by pool name.
    pub fn in_use(&self) -> (u32, u32) {
        (wire::in_use(&self.rx_pool), wire::in_use(&self.tx_pool))
    }

    /// Audit both pools after every frame has been freed.
    pub fn assert_returned_exactly_once(&self) {
        wire::assert_returned_exactly_once(&self.rx_pool);
        wire::assert_returned_exactly_once(&self.tx_pool);
    }

    /// Whether either pool still exists: Port cleanup frees both.
    pub fn pools_exist(&self) -> bool {
        wire::pool_exists(&self.rx_pool) || wire::pool_exists(&self.tx_pool)
    }

    /// After the Port closed: both rings empty, vdev removed, rings freed.
    /// Pools are checked only when this fixture opened a Port.
    pub fn close(mut self) {
        if self.opened.get() {
            assert!(!self.pools_exist());
        }
        assert!(self.take_tx().is_empty());
        assert_eq!(wire::drain_ring(self.rx_ring), 0, "RX ring not drained");
        assert_eq!(unsafe { rte_vdev_uninit(self.vdev.as_ptr()) }, 0);
        unsafe {
            rte_ring_free(self.rx_ring);
            rte_ring_free(self.tx_ring);
        }
        self.closed = true;
    }
}

impl Drop for RingPort {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        let name = self.vdev.to_string_lossy();
        self.drain();
        if self.opened.get() && unsafe { rte_eth_dev_is_valid_port(self.port_id) } != 0 {
            let _ = writeln!(
                std::io::stderr(),
                "RingPort {name}: a Port still uses the device; leaking the vdev and rings"
            );
        } else if unsafe { rte_vdev_uninit(self.vdev.as_ptr()) } != 0 {
            let _ = writeln!(
                std::io::stderr(),
                "RingPort {name}: rte_vdev_uninit failed; leaking the rings"
            );
        } else {
            unsafe {
                rte_ring_free(self.rx_ring);
                rte_ring_free(self.tx_ring);
            }
        }
        if !std::thread::panicking() {
            panic!("RingPort {name} dropped without close");
        }
    }
}

/// Set `config`'s IP MTU to `mtu` and both pools' data room to `room` bytes
/// after headroom.
pub fn resize(config: &mut PortConfig<'_>, mtu: u16, room: u16) {
    config.mtu = mtu;
    for pool in [&mut config.rx_pool, &mut config.tx_pool] {
        pool.data_room_size = RTE_PKTMBUF_HEADROOM as u16 + room;
    }
}

/// One Ethernet frame carrying an ARP packet.
pub fn arp(
    operation: ArpOperation,
    eth_dst: EthernetAddress,
    sender: (EthernetAddress, Ipv4Address),
    target: (EthernetAddress, Ipv4Address),
) -> Vec<u8> {
    let arp = ArpRepr::EthernetIpv4 {
        operation,
        source_hardware_addr: sender.0,
        source_protocol_addr: sender.1,
        target_hardware_addr: target.0,
        target_protocol_addr: target.1,
    };
    let eth = EthernetRepr {
        src_addr: sender.0,
        dst_addr: eth_dst,
        ethertype: EthernetProtocol::Arp,
    };
    let mut bytes = vec![0; eth.buffer_len() + arp.buffer_len()];
    let mut frame = EthernetFrame::new_unchecked(&mut bytes);
    eth.emit(&mut frame);
    arp.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()));
    bytes
}

/// A 60-byte frame starting with `tag`.
pub fn frame(tag: u8) -> Vec<u8> {
    (0..60).map(|offset| tag.wrapping_add(offset)).collect()
}

/// Queue every frame on the port's TX ring through `tx_burst`.
pub fn send(port: &mut Port, frames: &[Vec<u8>]) {
    let mut pending = VecDeque::with_capacity(frames.len());
    for bytes in frames {
        let mut packet = port.alloc_tx(bytes.len() as u16).unwrap();
        packet.data_mut().copy_from_slice(bytes);
        pending.push_back(packet);
    }
    while !pending.is_empty() {
        assert!(port.tx_burst(&mut pending).unwrap() > 0);
    }
}
