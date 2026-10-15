// Heads up! Before working on this file you should read the parts
// of RFC 1122 that discuss Ethernet, ARP and IP.

#[cfg(test)]
mod tests;

mod ethernet;

mod ipv4;

mod tcp;
#[cfg(feature = "udp-set")]
mod udp;

use super::packet::*;
use super::PathMtus;

use core::result::Result;
use heapless::Vec;

use super::neighbor::{Answer as NeighborAnswer, Cache as NeighborCache};
use super::tcp_set::TcpSet;
#[cfg(feature = "udp-set")]
use super::udp_set::UdpSet;
use crate::config::{
    IFACE_MAX_ADDR_COUNT,
};
use crate::phy::{PacketMeta, TxChecksum};
use crate::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use crate::rand::Rand;
use crate::socket::*;
use crate::time::{Duration, Instant};

use crate::wire::*;

macro_rules! check {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(_) => {
                net_trace!(concat!("iface: malformed ", stringify!($e)));
                return Default::default();
            }
        }
    };
}
use check;

/// No route exists for an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoRoute;

impl core::fmt::Display for NoRoute {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("no route")
    }
}

struct TrackedTxToken<'a, T> {
    inner: T,
    consumed: &'a mut bool,
}

impl<T: TxToken> TxToken for TrackedTxToken<'_, T> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        *self.consumed = true;
        self.inner.consume(len, f)
    }

    fn set_meta(&mut self, meta: PacketMeta) {
        self.inner.set_meta(meta);
    }
}

/// Result returned by [`Interface::poll`].
///
/// This contains information on whether socket states might have changed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PollResult {
    /// Socket state is guaranteed to not have changed.
    None,
    /// You should check the state of sockets again for received data or completion of operations.
    SocketStateChanged,
}

/// Result returned by [`Interface::poll_ingress_single`].
///
/// This contains information on whether a packet was processed or not,
/// and whether it might've affected socket states.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PollIngressSingleResult {
    /// No packet was processed. You don't need to call [`Interface::poll_ingress_single`]
    /// again, until more packets arrive.
    ///
    /// Socket state is guaranteed to not have changed.
    None,
    /// A packet was processed.
    ///
    /// There may be more packets in the device's RX queue, so you should call [`Interface::poll_ingress_single`] again.
    ///
    /// Socket state is guaranteed to not have changed.
    PacketProcessed,
    /// A packet was processed, which might have caused socket state to change.
    ///
    /// There may be more packets in the device's RX queue, so you should call [`Interface::poll_ingress_single`] again.
    ///
    /// You should check the state of sockets again for received data or completion of operations.
    SocketStateChanged,
}

/// A  network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
pub struct Interface {
    pub(crate) inner: InterfaceInner,
    segments_per_visit: usize,
}

/// The device independent part of an Ethernet network interface.
///
/// Separating the device from the data required for processing and dispatching makes
/// it possible to borrow them independently. For example, the tx and rx tokens borrow
/// the `device` mutably until they're used, which makes it impossible to call other
/// methods on the `Interface` in this time (since its `device` field is borrowed
/// exclusively). However, it is still possible to call methods on its `inner` field.
pub struct InterfaceInner {
    caps: DeviceCapabilities,
    ipv4_dropped: u64,
    now: Instant,
    pub(crate) tcp_isn_secret: [u64; 2],
    #[cfg(test)]
    pub(crate) template_frames: usize,

    neighbor_cache: NeighborCache,
    probe_owed: Option<Ipv4Address>,
    hardware_addr: HardwareAddress,
    ip_addrs: Vec<IpCidr, IFACE_MAX_ADDR_COUNT>,
    any_ip: bool,
    ipv4_gateway: Option<Ipv4Address>,
    path_mtus: Option<PathMtus>,
}

/// Configuration structure used for creating a network interface.
#[non_exhaustive]
pub struct Config {
    /// Random seed.
    ///
    /// It is strongly recommended that the random seed is different on each boot,
    /// to avoid problems with TCP port/sequence collisions.
    ///
    /// The TCP ISN secret is derived from this seed. Production callers should
    /// obtain an unpredictable seed from OS entropy.
    pub random_seed: u64,

    /// How many neighbors the cache holds. Defaults to 256.
    pub neighbor_capacity: usize,

    /// How many segments one egress visit may send to a socket while other sockets are waiting.
    /// A socket that is alone keeps sending while it is due. Defaults to 1.
    pub segments_per_visit: usize,

    /// Set the Hardware address the interface will use.
    ///
    /// # Panics
    /// Creating the interface panics if the address is not unicast.
    pub(crate) hardware_addr: HardwareAddress,
}

impl Config {
    pub fn new(hardware_addr: HardwareAddress) -> Self {
        Config {
            random_seed: 0,
            neighbor_capacity: 256,
            segments_per_visit: 1,
            hardware_addr,
        }
    }
}

impl Interface {
    /// Create a network interface using the previously provided configuration.
    ///
    /// # Panics
    /// This function panics if the configured `hardware_addr` does not match
    /// the medium of the device.
    /// It also panics if [`Config::neighbor_capacity`] or
    /// [`Config::segments_per_visit`] is zero.
    pub fn new(config: Config, device: &mut (impl Device + ?Sized), now: Instant) -> Self {
        assert!(
            config.neighbor_capacity != 0,
            "Neighbor capacity must be nonzero."
        );

        assert!(
            config.segments_per_visit != 0,
            "Segments per visit must be nonzero."
        );

        let caps = device.capabilities();
        assert_eq!(
            config.hardware_addr.medium(),
            caps.medium,
            "The hardware address does not match the medium of the interface."
        );

        let mut rand = Rand::new(config.random_seed);

        // Drawn and discarded so tcp_isn_secret stays the same for a given random_seed.
        let mut ipv4_id;

        loop {
            ipv4_id = rand.rand_u16();
            if ipv4_id != 0 {
                break;
            }
        }

        let tcp_isn_secret = [
            (u64::from(rand.rand_u32()) << 32) | u64::from(rand.rand_u32()),
            (u64::from(rand.rand_u32()) << 32) | u64::from(rand.rand_u32()),
        ];

        Interface {
            segments_per_visit: config.segments_per_visit,
            inner: InterfaceInner {
                now,
                caps,
                ipv4_dropped: 0,
                hardware_addr: config.hardware_addr,
                ip_addrs: Vec::new(),
                any_ip: false,
                ipv4_gateway: None,
                path_mtus: None,
                neighbor_cache: NeighborCache::new(config.neighbor_capacity),
                probe_owed: None,
                tcp_isn_secret,
                #[cfg(test)]
                template_frames: 0,
            },
        }
    }

    /// Get the socket context.
    ///
    /// The context is needed for some socket methods.
    pub fn context(&mut self) -> &mut InterfaceInner {
        &mut self.inner
    }

    /// IPv4 packets rejected before transport processing.
    pub fn ipv4_dropped(&self) -> u64 {
        self.inner.ipv4_dropped
    }

    /// Get the HardwareAddress address of the interface.
    ///
    /// # Panics
    /// This function panics if the medium is not Ethernet.
    #[cfg(test)]
    pub(crate) fn hardware_addr(&self) -> HardwareAddress {
        assert!(self.inner.caps.medium == Medium::Ethernet);

        self.inner.hardware_addr
    }

    /// Set the HardwareAddress address of the interface.
    ///
    /// # Panics
    /// This function panics if the address is not unicast, and if the medium is not Ethernet.
    #[cfg(test)]
    pub(crate) fn set_hardware_addr(&mut self, addr: HardwareAddress) {
        assert!(self.inner.caps.medium == Medium::Ethernet);

        InterfaceInner::check_hardware_addr(&addr);
        self.inner.hardware_addr = addr;
    }

    /// Get the IP addresses of the interface.
    pub fn ip_addrs(&self) -> &[IpCidr] {
        self.inner.ip_addrs.as_ref()
    }

    /// Get the first IPv4 address if present.
    #[cfg(test)]
    pub(crate) fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.inner.ipv4_addr()
    }

    /// Get an address from the interface that could be used as source address.
    /// For IPv4, this function tries to find a registered IPv4 address in the same
    /// subnet as the destination, falling back to the first IPv4 address if none is
    /// found.
    pub fn get_source_address(&self, dst_addr: &IpAddress) -> Option<IpAddress> {
        self.inner.get_source_address(dst_addr)
    }

    /// Update the IP addresses of the interface.
    ///
    /// # Panics
    /// This function panics if any of the addresses are not unicast.
    pub fn update_ip_addrs<F: FnOnce(&mut Vec<IpCidr, IFACE_MAX_ADDR_COUNT>)>(&mut self, f: F) {
        f(&mut self.inner.ip_addrs);
        InterfaceInner::flush_neighbor_cache(&mut self.inner);
        InterfaceInner::check_ip_addrs(&self.inner.ip_addrs);
    }

    pub fn set_ipv4_gateway(&mut self, gateway: Option<Ipv4Address>) {
        self.inner.neighbor_cache.bump();
        self.inner.ipv4_gateway = gateway;
    }

    /// The caller fixes this table for the Stack lifetime. It does not route traffic.
    /// Path MTUs do not change next hops, so the neighbor cache stays valid.
    pub fn set_path_mtus(&mut self, paths: PathMtus) {
        self.inner.path_mtus = Some(paths);
    }

    /// Enable or disable the AnyIP capability.
    ///
    /// When enabled, packets for any destination address are accepted locally,
    /// regardless of the interface's configured [`ip_addrs`](Self::ip_addrs).
    #[cfg(test)]
    pub(crate) fn set_any_ip(&mut self, any_ip: bool) {
        self.inner.any_ip = any_ip;
    }

    /// Transmit packets queued in the sockets, and receive packets queued
    /// in the device.
    ///
    /// This function returns a value indicating whether the state of any socket
    /// might have changed.
    ///
    /// ## DoS warning
    ///
    /// This function processes all packets in the device's queue. This can
    /// be an unbounded amount of work if packets arrive faster than they're
    /// processed.
    ///
    /// If this is a concern for your application (i.e. your environment doesn't
    /// have preemptive scheduling, or `poll()` is called from a main loop where
    /// other important things are processed), you may use the lower-level methods
    /// [`poll_egress()`](Self::poll_egress), [`poll_maintenance()`](Self::poll_maintenance)
    /// and [`poll_ingress_single()`](Self::poll_ingress_single).
    /// This allows you to insert yields or process other events between processing
    /// individual ingress packets.
    pub fn poll(
        &mut self,
        timestamp: Instant,
        device: &mut (impl Device + ?Sized),
        sockets: &mut TcpSet<'_>,
    ) -> PollResult {
        self.inner.now = timestamp;

        let mut res = PollResult::None;

        self.poll_maintenance(timestamp);

        sockets.sync_dirty_identities();

        // Process ingress while there's packets available.
        loop {
            match self.socket_ingress(
                device,
                sockets,
                #[cfg(feature = "udp-set")]
                None,
            ) {
                PollIngressSingleResult::None => break,
                PollIngressSingleResult::PacketProcessed => {}
                PollIngressSingleResult::SocketStateChanged => res = PollResult::SocketStateChanged,
            }
        }

        // Process egress.
        loop {
            match self.poll_egress(timestamp, device, sockets) {
                PollResult::None => break,
                PollResult::SocketStateChanged => res = PollResult::SocketStateChanged,
            }
        }

        res
    }

    /// Transmit packets queued in the sockets.
    ///
    /// This function returns a value indicating whether the state of any socket
    /// might have changed.
    ///
    /// This is guaranteed to always perform a bounded amount of work.
    pub fn poll_egress(
        &mut self,
        timestamp: Instant,
        device: &mut (impl Device + ?Sized),
        sockets: &mut TcpSet<'_>,
    ) -> PollResult {
        self.inner.now = timestamp;

        self.socket_egress(device, sockets)
    }

    /// The next `poll_egress` at the same timestamp would send nothing and change nothing.
    /// A caller may skip that pass when this returns true.
    pub fn egress_idle(&self, sockets: &TcpSet<'_>) -> bool {
        if self.inner.probe_owed.is_some() {
            return false;
        }
        sockets.egress_idle()
    }

    /// Process one incoming packet queued in the device.
    ///
    /// Returns a value indicating:
    /// - whether a packet was processed, in which case you have to call this method again in case there's more packets queued.
    /// - whether the state of any socket might have changed.
    ///
    /// Since it processes at most one packet, this is guaranteed to always perform a bounded amount of work.
    pub fn poll_ingress_single(
        &mut self,
        timestamp: Instant,
        device: &mut (impl Device + ?Sized),
        sockets: &mut TcpSet<'_>,
    ) -> PollIngressSingleResult {
        self.inner.now = timestamp;

        sockets.sync_dirty_identities();

        self.socket_ingress(
            device,
            sockets,
            #[cfg(feature = "udp-set")]
            None,
        )
    }

    /// Process one frame with TCP and UDP sockets.
    #[cfg(feature = "udp-set")]
    pub fn poll_ingress_single_udp(
        &mut self,
        timestamp: Instant,
        device: &mut (impl Device + ?Sized),
        tcp: &mut TcpSet<'_>,
        udp: &mut UdpSet,
    ) -> PollIngressSingleResult {
        self.inner.now = timestamp;

        tcp.sync_dirty_identities();

        self.socket_ingress(device, tcp, Some(udp))
    }

    /// Maintain stateful processing on the device.
    ///
    /// This is guaranteed to always perform a bounded amount of work.
    pub fn poll_maintenance(&mut self, timestamp: Instant) {
        self.inner.now = timestamp;
    }

    /// Return a _soft deadline_ for calling [poll] the next time.
    /// The [Instant] returned is the time at which you should call [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Instant], and
    /// potentially harmful (impacting quality of service) to call it after the
    /// [Instant]
    ///
    /// [poll]: #method.poll
    /// [Instant]: struct.Instant.html
    pub fn poll_at(&mut self, timestamp: Instant, sockets: &mut TcpSet<'_>) -> Option<Instant> {
        self.inner.now = timestamp;

        self.classify_dirty(sockets, timestamp);

        #[cfg(debug_assertions)]
        let full = sockets
            .items()
            .filter_map(|item| {
                let (socket_poll_at, _) = item.socket.poll_at_read(&self.inner);
                match item.meta.poll_at(
                    socket_poll_at,
                    |ip_addr| self.inner.has_neighbor(&ip_addr),
                    timestamp,
                ) {
                    PollAt::Ingress => None,
                    PollAt::Time(instant) => Some(instant),
                    PollAt::Now => Some(Instant::from_millis(0)),
                }
            })
            .min();

        let cached = sockets.poll_at();

        #[cfg(debug_assertions)]
        assert!(
            match (cached, full) {
                (None, None) => true,
                (Some(cached), Some(full)) => {
                    let micros = i128::from(full.total_micros());
                    let rounded = if micros < 0 {
                        micros
                    } else {
                        (micros + 999) / 1000 * 1000
                    };
                    i128::from(cached.total_micros()) <= rounded
                }
                _ => false,
            },
            "TCP cached poll_at {:?}, full scan poll_at {:?}",
            cached,
            full
        );

        #[allow(unused_mut)]
        let mut res = cached;

        res
    }

    /// Return an _advisory wait time_ for calling [poll] the next time.
    /// The [Duration] returned is the time left to wait before calling [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Duration] has passed,
    /// and potentially harmful (impacting quality of service) to call it after the
    /// [Duration] has passed.
    ///
    /// [poll]: #method.poll
    /// [Duration]: struct.Duration.html
    pub fn poll_delay(&mut self, timestamp: Instant, sockets: &mut TcpSet<'_>) -> Option<Duration> {
        match self.poll_at(timestamp, sockets) {
            Some(poll_at) if timestamp < poll_at => Some(poll_at - timestamp),
            Some(_) => Some(Duration::from_millis(0)),
            _ => None,
        }
    }

    pub(crate) fn classify_dirty(&mut self, sockets: &mut TcpSet, timestamp: Instant) {
        classify_dirty(&mut self.inner, sockets, timestamp, false);
    }

    fn socket_ingress(
        &mut self,
        device: &mut (impl Device + ?Sized),
        sockets: &mut TcpSet<'_>,
        #[cfg(feature = "udp-set")] mut udp: Option<&mut UdpSet>,
    ) -> PollIngressSingleResult {
        let Some((rx_token, tx_token)) = device.receive(self.inner.now) else {
            return PollIngressSingleResult::None;
        };

        let rx_meta = rx_token.meta();
        let frame = rx_token.into_buf();
        let bytes = frame.as_slice();
        if bytes.is_empty() {
            return PollIngressSingleResult::PacketProcessed;
        }

        match self.inner.caps.medium {
            Medium::Ethernet => {
                if let Some(packet) = self.inner.process_ethernet(
                    sockets,
                    rx_meta,
                    bytes,
                    #[cfg(feature = "udp-set")]
                    udp.as_deref_mut(),
                ) {
                    let result = if let Some(index) = sockets.pending_tcp_reply.take() {
                        // The socket's cached next hop is current only while the neighbor
                        // generation is; an entry that expired since the last egress pass
                        // must bump it, so the reply resolves (and ARPs) like egress does.
                        self.inner.neighbor_cache.expire(self.inner.now);
                        let EthernetPacket::Ip(packet) = packet else {
                            unreachable!("TCP socket reply is not an IP packet")
                        };
                        let IpPayload::Tcp(tcp) = packet.payload() else {
                            unreachable!("TCP socket reply is not a TCP segment")
                        };
                        let meta = &mut sockets.item_at_mut(index)
                            .expect("TCP reply socket is missing").meta;
                        self.inner.dispatch_tcp(
                            tx_token,
                            PacketMeta::default(),
                            packet.ip_repr(),
                            *tcp,
                            &mut meta.next_hop,
                            &mut meta.tcp_template,
                        )
                    } else {
                        self.inner.dispatch(tx_token, packet)
                    };
                    if let Err(err) = result {
                        net_debug!("Failed to send response: {:?}", err);
                    }
                }
            }
            #[cfg(feature = "medium-ip")]
            Medium::Ip => {
                if let Some(packet) = self.inner.process_ip(
                    sockets,
                    rx_meta,
                    bytes,
                    #[cfg(feature = "udp-set")]
                    udp.as_deref_mut(),
                ) && let Err(err) = self.inner.dispatch_ip(
                    tx_token,
                    PacketMeta::default(),
                    packet,
                    None,
                ) {
                    net_debug!("Failed to send response: {:?}", err);
                }
            }
        }

        if let Some((index, pending)) = sockets.pending_rx_attach.take() {
            sockets
                .item_at_mut(index)
                .expect("pending TCP receive socket is missing")
                .socket
                .commit_rx(frame, pending);
        } else {
            #[cfg(feature = "udp-set")]
            if let Some(udp) = udp
                && let Some((slot, pending)) = udp.pending_rx_attach.take()
            {
                udp.commit_rx(slot, frame, pending);
            }
        }

        // TODO: Propagate the PollIngressSingleResult from deeper.
        // There's many received packets that we process but can't cause sockets
        // to change state. For example IP fragments, multicast stuff, ICMP pings.
        // We should return `PacketProcessed` for these to save the user from
        // doing useless socket polls.
        PollIngressSingleResult::SocketStateChanged
    }

    fn socket_egress(
        &mut self,
        device: &mut (impl Device + ?Sized),
        sockets: &mut TcpSet<'_>,
    ) -> PollResult {
        self.inner.neighbor_cache.expire(self.inner.now);
        let timestamp = self.inner.now;
        let visits = classify_dirty(&mut self.inner, sockets, timestamp, true);
        let _caps = device.capabilities();

        enum EgressError {
            Exhausted,
            Dispatch,
        }

        let mut result = PollResult::None;
        for _ in 0..visits {
            let index = {
                let index = sockets.pop_ready();
                if !sockets.deadline_due(index, self.inner.now) {
                    sockets.include_deadline(index);
                    continue;
                }
                index
            };
            let handle = sockets.handle_at(index);
            let Some(item) = sockets.item_at_mut(index) else {
                continue;
            };
            if !item.meta.egress_permitted(handle, self.inner.now, |ip_addr| {
                self.inner.has_neighbor(&ip_addr)
            }) {
                sockets.mark_dirty(index);
                continue;
            }

            let mut sent = 0usize;
            let mut end_poll_at = None;
            let result = loop {
                #[cfg(test)]
                sockets.dispatches.push(index);
                let item = sockets.item_at_mut(index).expect("ready TCP slot is empty");
                let before = item.socket.state();
                let next_hop = &mut item.meta.next_hop;
                let template = &mut item.meta.tcp_template;
                let mut neighbor_addr = None;
                let mut emitted = false;
                let mut respond =
                    |inner: &mut InterfaceInner, meta: PacketMeta, ip: IpRepr, tcp: TcpRepr| {
                        neighbor_addr = Some(ip.dst_addr());
                        let t = device.transmit(inner.now).ok_or_else(|| {
                            net_debug!("failed to transmit IP: device exhausted");
                            EgressError::Exhausted
                        })?;

                        let t = TrackedTxToken {
                            inner: t,
                            consumed: &mut emitted,
                        };
                        let dispatch = inner.dispatch_tcp(
                            t,
                            meta,
                            ip,
                            tcp,
                            &mut *next_hop,
                            &mut *template,
                        );
                        dispatch.map_err(|_| EgressError::Dispatch)?;

                        result = PollResult::SocketStateChanged;

                        Ok(())
                    };

                let dispatch_result = item
                    .socket
                    .dispatch(&mut self.inner, |inner, meta, (ip, tcp)| {
                        respond(inner, meta, ip, tcp)
                    });


                match dispatch_result {
                    Err(EgressError::Exhausted) => {}
                    Err(EgressError::Dispatch) => {
                        // `NeighborCache` already takes care of rate limiting the neighbor discovery
                        // requests from the socket. However, without an additional rate limiting
                        // mechanism, we would spin on every socket that has yet to discover its
                        // neighbor.
                        item.meta.neighbor_missing(
                            handle,
                            self.inner.now,
                            neighbor_addr.expect("non-IP response packet"),
                        );
                    }
                    Ok(()) => {}
                }
                let state_changed = item.socket.state() != before;
                if item.socket.remote_endpoint().is_none() {
                    {
                        item.meta.next_hop = None;
                    }
                    sockets.check_reapable(index);
                }
                // Inside dispatch, a flow key change requires a state change.
                if state_changed {
                    sockets.sync_identity(index);
                    sockets.check_reapable(index);
                } else {
                    #[cfg(debug_assertions)]
                    sockets.debug_assert_synced(index);
                }
                if dispatch_result.is_err() || !emitted {
                    break dispatch_result;
                }
                sent = sent
                    .checked_add(1)
                    .expect("TCP visit segment count overflow");
                // A lone socket keeps sending; other ready or dirty sockets bound its burst.
                if !(sockets.ready_len() == 0 && sockets.dirty_list.is_empty())
                    && sent >= self.segments_per_visit
                {
                    break dispatch_result;
                }
                let item = sockets.item_at_mut(index).expect("ready TCP slot is empty");
                debug_assert!(
                    item.meta.poll_at(
                        PollAt::Now,
                        |ip| self.inner.has_neighbor(&ip),
                        self.inner.now,
                    ) == PollAt::Now
                );
                let socket_poll_at = item.socket.poll_at(&mut self.inner);
                if socket_poll_at != PollAt::Now {
                    end_poll_at = Some(socket_poll_at);
                    break dispatch_result;
                }
            };
            if matches!(result, Err(EgressError::Exhausted)) {
                let waiting = sockets
                    .item_at_mut(index)
                    .expect("ready TCP slot is empty")
                    .meta
                    .is_waiting();
                sockets.set_waiting(index, waiting);
                sockets.mark_dirty(index);
                sockets.push_ready(index, true);
            } else {
                if let Some(socket_poll_at) = end_poll_at {
                    classify_polled(&mut self.inner, sockets, index, timestamp, socket_poll_at);
                } else {
                    classify(&mut self.inner, sockets, index, timestamp);
                }
                if sockets.deadline_due(index, timestamp) {
                    sockets.mark_dirty(index);
                } else {
                    sockets.include_deadline(index);
                }
            }
            if matches!(result, Err(EgressError::Exhausted)) {
                break;
            }
        }

        self.inner.dispatch_neighbor_probe(device);

        #[cfg(debug_assertions)]
        sockets.debug_assert_ready(self.inner.now, |ip| self.inner.has_neighbor(&ip));

        result
    }
}

pub(crate) fn classify(
    inner: &mut InterfaceInner,
    sockets: &mut TcpSet,
    index: usize,
    timestamp: Instant,
) {
    if let Some(item) = sockets.item_at_mut(index) {
        let socket_poll_at = item.socket.poll_at(inner);
        classify_polled(inner, sockets, index, timestamp, socket_poll_at);
    } else {
        #[cfg(test)]
        {
            sockets.classify_calls += 1;
        }
        sockets.set_deadline(index, PollAt::Ingress, false);
    }
}

pub(crate) fn classify_polled(
    inner: &mut InterfaceInner,
    sockets: &mut TcpSet,
    index: usize,
    timestamp: Instant,
    socket_poll_at: PollAt,
) {
    #[cfg(test)]
    {
        sockets.classify_calls += 1;
    }
    let item = sockets.item_at_mut(index).expect("ready TCP slot is empty");
    let deadline = item.meta.poll_at(
        socket_poll_at,
        |ip_addr| inner.has_neighbor(&ip_addr),
        timestamp,
    );
    let waiting = item.meta.is_waiting();
    sockets.set_deadline(index, deadline, waiting);
}

fn classify_dirty(
    inner: &mut InterfaceInner,
    sockets: &mut TcpSet,
    timestamp: Instant,
    admit: bool,
) -> usize {
    sockets.advance_wheel(timestamp, admit);
    let rescan_waiting = {
        let changes = inner.neighbor_cache.changes();
        let changed = sockets.neighbor_changes != changes;
        sockets.neighbor_changes = changes;
        changed
    };
    if rescan_waiting {
        for position in 0..sockets.waiting.len() {
            #[cfg(test)]
            {
                sockets.slot_visits += 1;
            }
            sockets.mark_dirty(sockets.waiting[position]);
        }
    }
    sockets.dirty_list.sort_unstable();
    for position in 0..sockets.dirty_list.len() {
        #[cfg(test)]
        {
            sockets.slot_visits += 1;
        }
        let index = sockets.dirty_list[position];
        sockets.sync_identity(index);
        classify(inner, sockets, index, timestamp);
    }
    if admit {
        sockets.admit_ready(timestamp)
    } else {
        sockets.clear_dirty();
        sockets.ready_len()
    }
}

impl InterfaceInner {
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn now(&self) -> Instant {
        self.now
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn ip_mtu(&self) -> usize {
        self.caps.ip_mtu()
    }

    #[allow(unused)]
    pub(crate) fn path_ip_mtu(&self, dst: &IpAddress) -> usize {
        match (self.path_mtus.as_ref(), dst) {
            (Some(table), IpAddress::Ipv4(addr)) => return usize::from(table.ip_mtu(*addr)),
            _ => {}
        }
        self.ip_mtu()
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn get_source_address(&self, dst_addr: &IpAddress) -> Option<IpAddress> {
        match dst_addr {
            IpAddress::Ipv4(addr) => self.get_source_address_ipv4(addr).map(|a| a.into()),
        }
    }

    #[cfg(test)]
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn set_now(&mut self, now: Instant) {
        self.now = now
    }

    #[cfg(test)]
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn set_ip_addrs(&mut self, addrs: Vec<IpCidr, IFACE_MAX_ADDR_COUNT>) {
        self.ip_addrs = addrs;
        self.flush_neighbor_cache();
    }

    fn check_hardware_addr(addr: &HardwareAddress) {
        if !addr.is_unicast() {
            panic!("Hardware address {addr} is not unicast")
        }
    }

    fn check_ip_addrs(addrs: &[IpCidr]) {
        for cidr in addrs {
            if !cidr.address().is_unicast() && !cidr.address().is_unspecified() {
                panic!("IP address {} is not unicast", cidr.address())
            }
        }
    }

    /// Check whether the interface has the given IP address assigned.
    ///
    /// Always returns true if [`InterfaceInner::any_ip`].
    pub(crate) fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        // If any IP is set to true, we don't bother about checking the IP.
        if self.any_ip {
            return true;
        }

        let addr = addr.into();
        self.ip_addrs.iter().any(|probe| probe.address() == addr)
    }

    #[cfg(feature = "medium-ip")]
    fn process_ip<'frame>(
        &mut self,
        sockets: &mut TcpSet,
        meta: PacketMeta,
        ip_payload: &'frame [u8],
        #[cfg(feature = "udp-set")] udp: Option<&mut UdpSet>,
    ) -> Option<Packet<'frame>> {
        match IpVersion::of_packet(ip_payload) {
            Ok(IpVersion::Ipv4) => {
                let ipv4_packet = Ipv4Packet::new_unchecked(ip_payload);
                self.process_ipv4(
                    sockets,
                    meta,
                    HardwareAddress::Ip,
                    &ipv4_packet,
                    #[cfg(feature = "udp-set")]
                    udp,
                )
            }
            // Drop all other traffic.
            _ => None,
        }
    }

    /// Checks if an address is broadcast, taking into account ipv4 subnet-local
    /// broadcast addresses.
    pub(crate) fn is_broadcast(&self, address: &IpAddress) -> bool {
        match address {
            IpAddress::Ipv4(address) => self.is_broadcast_v4(*address),
        }
    }

    fn dispatch<Tx>(
        &mut self,
        tx_token: Tx,
        packet: EthernetPacket,
    ) -> Result<(), DispatchError>
    where
        Tx: TxToken,
    {
        match packet {
            EthernetPacket::Arp(arp_repr) => {
                let dst_hardware_addr = match arp_repr {
                    ArpRepr::EthernetIpv4 {
                        target_hardware_addr,
                        ..
                    } => target_hardware_addr,
                };

                self.dispatch_ethernet(tx_token, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(dst_hardware_addr);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
                    arp_repr.emit(&mut packet);
                });
                Ok(())
            }
            EthernetPacket::Ip(packet) => self.dispatch_ip(
                tx_token,
                PacketMeta::default(),
                packet,
                None,
            ),
        }
    }

    fn in_same_network(&self, addr: &IpAddress) -> bool {
        self.ip_addrs.iter().any(|cidr| cidr.contains_addr(addr))
    }

    fn route(&self, addr: &IpAddress) -> Option<IpAddress> {
        // Send directly.
        // note: no need to use `self.is_broadcast()` to check for subnet-local broadcast addrs
        //       here because `in_same_network` will already return true.
        if self.in_same_network(addr) || addr.is_broadcast() {
            return Some(*addr);
        }

        match addr {
            IpAddress::Ipv4(_) => self.ipv4_gateway.map(IpAddress::Ipv4),
        }
    }

    pub(crate) fn has_neighbor(&self, addr: &IpAddress) -> bool {
        match self.route(addr) {
            Some(_routed_addr) => match self.caps.medium {
                Medium::Ethernet => self.neighbor_cache.lookup(&_routed_addr, self.now).found(),
                #[cfg(feature = "medium-ip")]
                Medium::Ip => true,
            },
            None => false,
        }
    }
}

impl Interface {
    /// Resolve the configured IPv4 gateway's Ethernet address, dispatching an ARP
    /// request when resolution is not already pending. `Err(NoRoute)` when no
    /// gateway is configured. The caller keeps the gateway unicast.
    pub fn resolve_gateway(
        &mut self,
        device: &mut (impl Device + ?Sized),
    ) -> Result<Option<EthernetAddress>, NoRoute> {
        let next_hop = self.inner.ipv4_gateway.ok_or(NoRoute)?;
        match self
            .inner
            .neighbor_cache
            .lookup(&next_hop.into(), self.inner.now)
        {
            NeighborAnswer::Found(hardware_addr) => {
                return Ok(Some(hardware_addr.ethernet_or_panic()));
            }
            NeighborAnswer::Stale {
                hardware_addr,
                probe,
            } => {
                if probe && self.inner.probe_owed.is_none() {
                    self.inner.probe_owed = Some(next_hop);
                }
                return Ok(Some(hardware_addr.ethernet_or_panic()));
            }
            NeighborAnswer::RateLimited => return Ok(None),
            NeighborAnswer::NotFound => {}
        }
        let Some(tx_token) = device.transmit(self.inner.now) else {
            return Ok(None);
        };
        match self.inner.dispatch_arp_request(tx_token, next_hop) {
            Ok(()) => {}
            Err(DispatchError::NoRoute) => return Err(NoRoute),
            Err(DispatchError::NeighborPending) => {
                unreachable!("ARP request dispatch cannot await neighbor resolution")
            }
        }
        self.inner
            .neighbor_cache
            .limit_rate(next_hop.into(), self.inner.now);
        Ok(None)
    }
}

impl InterfaceInner {
    fn lookup_hardware_addr<Tx>(
        &mut self,
        tx_token: Tx,
        dst_addr: &IpAddress,
        mut next_hop: Option<
            &mut Option<(u64, EthernetAddress)>,
        >,
    ) -> Result<(HardwareAddress, Tx), DispatchError>
    where
        Tx: TxToken,
    {
        if let Some(kept) = next_hop.as_deref_mut() {
            if let Some((changes, mac)) = *kept
                && changes == self.neighbor_cache.changes()
            {
                return Ok((HardwareAddress::Ethernet(mac), tx_token));
            }
            *kept = None;
        }
        if self.is_broadcast(dst_addr) {
            let hardware_addr = match self.caps.medium {
                Medium::Ethernet => HardwareAddress::Ethernet(EthernetAddress::BROADCAST),
                #[cfg(feature = "medium-ip")]
                Medium::Ip => unreachable!(),
            };

            return Ok((hardware_addr, tx_token));
        }

        if dst_addr.is_multicast() {
            let hardware_addr = match *dst_addr {
                IpAddress::Ipv4(addr) => match self.caps.medium {
                    Medium::Ethernet => {
                        let b = addr.octets();
                        HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[
                            0x01,
                            0x00,
                            0x5e,
                            b[1] & 0x7F,
                            b[2],
                            b[3],
                        ]))
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => unreachable!(),
                },
            };

            return Ok((hardware_addr, tx_token));
        }

        let dst_addr = self.route(dst_addr).ok_or(DispatchError::NoRoute)?;

        match self.neighbor_cache.lookup(&dst_addr, self.now) {
            NeighborAnswer::Found(hardware_addr) => {
                if let Some(kept) = next_hop {
                    *kept = Some((
                        self.neighbor_cache.changes(),
                        hardware_addr.ethernet_or_panic(),
                    ));
                }
                return Ok((hardware_addr, tx_token));
            }
            NeighborAnswer::Stale {
                hardware_addr,
                probe,
            } if matches!(dst_addr, IpAddress::Ipv4(_))
                && matches!(self.caps.medium, Medium::Ethernet) =>
            {
                if probe && self.probe_owed.is_none() {
                    #[allow(irrefutable_let_patterns)]
                    if let IpAddress::Ipv4(addr) = dst_addr {
                        self.probe_owed = Some(addr);
                    }
                }
                return Ok((hardware_addr, tx_token));
            }
            NeighborAnswer::RateLimited => return Err(DispatchError::NeighborPending),
            _ => (), // XXX
        }

        match dst_addr {
            IpAddress::Ipv4(dst_addr) if matches!(self.caps.medium, Medium::Ethernet) => {
                net_debug!(
                    "address {} not in neighbor cache, sending ARP request",
                    dst_addr
                );
                self.dispatch_arp_request(tx_token, dst_addr)?;
            }

            #[allow(unreachable_patterns)]
            _ => (),
        }

        // The request got dispatched, limit the rate on the cache.
        self.neighbor_cache.limit_rate(dst_addr, self.now);
        Err(DispatchError::NeighborPending)
    }

    fn dispatch_arp_request<Tx: TxToken>(
        &mut self,
        tx_token: Tx,
        dst_addr: Ipv4Address,
    ) -> Result<(), DispatchError> {
        let arp_repr = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: self.hardware_addr.ethernet_or_panic(),
            source_protocol_addr: self
                .get_source_address_ipv4(&dst_addr)
                .ok_or(DispatchError::NoRoute)?,
            target_hardware_addr: EthernetAddress::BROADCAST,
            target_protocol_addr: dst_addr,
        };

        self.dispatch_ethernet(tx_token, arp_repr.buffer_len(), |mut frame| {
            frame.set_dst_addr(EthernetAddress::BROADCAST);
            frame.set_ethertype(EthernetProtocol::Arp);
            arp_repr.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()))
        });
        Ok(())
    }

    #[inline]
    pub(crate) fn dispatch_neighbor_probe(&mut self, device: &mut (impl Device + ?Sized)) {
        if let Some(addr) = self.probe_owed {
            self.dispatch_owed_probe(device, addr);
        }
    }

    #[cold]
    #[inline(never)]
    fn dispatch_owed_probe(&mut self, device: &mut (impl Device + ?Sized), addr: Ipv4Address) {
        if !matches!(
            self.neighbor_cache.lookup(&addr.into(), self.now),
            NeighborAnswer::Stale { probe: true, .. }
        ) {
            self.probe_owed = None;
            return;
        }
        let Some(tx_token) = device.transmit(self.now) else {
            return;
        };
        if let Err(e) = self.dispatch_arp_request(tx_token, addr) {
            net_debug!("Failed to dispatch ARP probe: {:?}", e);
        }
        self.neighbor_cache.limit_rate(addr.into(), self.now);
        self.probe_owed = None;
    }

    fn flush_neighbor_cache(&mut self) {
        self.neighbor_cache.flush()
    }

    fn tx_checksum(&self, ip: &IpRepr, tcp_header_len: usize) -> Option<TxChecksum> {
        match ip {
            IpRepr::Ipv4(ip) => {
                let ip_header_len = u8::try_from(ip.buffer_len()).expect("IPv4 header fits u8");
                match ip.next_header {
                    IpProtocol::Tcp if !self.caps.checksum.tcp.tx() => Some(TxChecksum::Tcp {
                        ip_header_len,
                        tcp_header_len: u8::try_from(tcp_header_len).expect("TCP header fits u8"),
                    }),
                    IpProtocol::Udp if !self.caps.checksum.udp.tx() => {
                        Some(TxChecksum::Udp { ip_header_len })
                    }
                    _ => None,
                }
            }
        }
    }

    fn dispatch_ip<Tx: TxToken>(
        &mut self,
        // NOTE(unused_mut): tx_token isn't always mutated, depending on
        // the feature set that is used.
        #[allow(unused_mut)] mut tx_token: Tx,
        mut meta: PacketMeta,
        packet: Packet,
        next_hop: Option<
            &mut Option<(u64, EthernetAddress)>,
        >,
    ) -> Result<(), DispatchError> {
        let mut ip_repr = packet.ip_repr();
        let tcp_header_len = match packet.payload() {
            IpPayload::Tcp(tcp) => tcp.header_len(),
            _ => 0,
        };
        meta.tx_checksum = self.tx_checksum(&ip_repr, tcp_header_len);
        assert!(!ip_repr.dst_addr().is_unspecified());

        // Dispatch IP/Ethernet:

        let caps = self.caps.clone();

        // First we calculate the total length that we will have to emit.
        let mut total_len = ip_repr.buffer_len();

        // Add the size of the Ethernet header if the medium is Ethernet.
        if matches!(self.caps.medium, Medium::Ethernet) {
            total_len = EthernetFrame::<&[u8]>::buffer_len(total_len);
        }

        // If the medium is Ethernet, then we need to retrieve the destination hardware address.
        let (dst_hardware_addr, mut tx_token) = match self.caps.medium {
            Medium::Ethernet => {
                match self.lookup_hardware_addr(
                    tx_token,
                    &ip_repr.dst_addr(),
                    next_hop,
                )? {
                    (HardwareAddress::Ethernet(addr), tx_token) => (addr, tx_token),
                    (_, _) => unreachable!(),
                }
            }
            _ => (EthernetAddress([0; 6]), tx_token),
        };

        // Emit function for the Ethernet header.
        let emit_ethernet = |repr: &IpRepr, tx_buffer: &mut [u8]| {
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = self.hardware_addr.ethernet_or_panic();
            frame.set_src_addr(src_addr);
            frame.set_dst_addr(dst_hardware_addr);

            match repr.version() {
                IpVersion::Ipv4 => frame.set_ethertype(EthernetProtocol::Ipv4),
            }
        };

        // Emit function for the IP header and payload.
        let emit_ip = |repr: &IpRepr, tx_buffer: &mut [u8]| {
            repr.emit(&mut *tx_buffer, &self.caps.checksum);

            let payload = &mut tx_buffer[repr.header_len()..];
            packet.emit_payload(repr, payload, &caps)
        };

        let total_ip_len = ip_repr.buffer_len();

        match &mut ip_repr {
            IpRepr::Ipv4(repr) => {
                // IPv4 packets larger than the IP MTU are dropped; there is no fragmentation.
                let should_fragment = total_ip_len > self.caps.ip_mtu();

                if should_fragment {
                    {
                        net_debug!(
                            "IPv4 packet larger than the IP MTU; dropping it."
                        );
                        Ok(())
                    }
                } else {
                    tx_token.set_meta(meta);

                    // No fragmentation is required.
                    tx_token.consume(total_len, |mut tx_buffer| {
                        if matches!(self.caps.medium, Medium::Ethernet) {
                            emit_ethernet(&ip_repr, tx_buffer);
                            tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
                        }

                        emit_ip(&ip_repr, tx_buffer);
                    });

                    Ok(())
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchError {
    /// No route to dispatch this packet. Retrying won't help unless
    /// configuration is changed.
    NoRoute,
    /// We do have a route to dispatch this packet, but we haven't discovered
    /// the neighbor for it yet. Discovery has been initiated, dispatch
    /// should be retried later.
    NeighborPending,
}
