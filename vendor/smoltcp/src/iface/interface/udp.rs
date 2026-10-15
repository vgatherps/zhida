use super::*;
use crate::iface::header_template::UdpTemplate;
use crate::iface::udp_set::PendingUdp;
use crate::iface::{UdpHandle, UdpSendError, UdpTarget};

impl Interface {
    /// Check one UDP send of `len` payload bytes before any device work.
    /// Errors come in this order: `NoDestination`, `PeerMismatch`, `Unaddressable`, `TooLarge`.
    ///
    /// Panics if the interface medium is not Ethernet or `handle` is stale.
    pub fn udp_target(
        &self,
        udp: &UdpSet,
        handle: UdpHandle,
        to: Option<IpEndpoint>,
        len: usize,
    ) -> Result<UdpTarget, UdpSendError> {
        assert!(
            matches!(self.inner.caps.medium, Medium::Ethernet),
            "UDP send needs an Ethernet interface"
        );
        let socket = udp.get(handle);
        let to = match (to, socket.peer()) {
            (None, None) => return Err(UdpSendError::NoDestination),
            (Some(to), Some(peer)) if to != peer => return Err(UdpSendError::PeerMismatch),
            (Some(to), _) | (None, Some(to)) => to,
        };
        let dst_addr = match to.addr {
            IpAddress::Ipv4(addr) => addr,
        };
        if dst_addr.is_unspecified()
            || dst_addr.is_multicast()
            || self.inner.has_ip_addr(dst_addr)
            || to.port == 0
            || (self.inner.is_broadcast(&to.addr) && !socket.config().broadcast)
        {
            return Err(UdpSendError::Unaddressable);
        }
        if len
            > self
                .inner
                .path_ip_mtu(&to.addr)
                .checked_sub(28)
                .expect("IP MTU is smaller than IPv4 and UDP headers")
        {
            return Err(UdpSendError::TooLarge);
        }
        Ok(UdpTarget {
            handle,
            to,
            dst_addr,
            len,
        })
    }

    /// Send one UDP datagram to `target`, written in place by `fill`, into one TX frame.
    /// Errors are `WouldBlock`, `NoRoute` and `NeighborPending`; `fill` runs only on success.
    ///
    /// Panics if the interface medium is not Ethernet or the target's handle is stale.
    pub fn udp_send(
        &mut self,
        device: &mut (impl Device + ?Sized),
        udp: &mut UdpSet,
        target: UdpTarget,
        fill: impl FnOnce(&mut [u8]),
    ) -> Result<(), UdpSendError> {
        let UdpTarget {
            handle,
            to,
            dst_addr,
            len,
        } = target;
        let socket = udp.get_mut(handle);
        let now = self.inner.now;
        self.inner.neighbor_cache.expire(now);
        let mut token = device.transmit(now).ok_or(UdpSendError::WouldBlock)?;
        let src_mac = self.inner.hardware_addr.ethernet_or_panic();
        let udp_repr = UdpRepr {
            src_port: socket.config().port,
            dst_port: to.port,
        };
        let ip_repr = self
            .inner
            .get_source_address_ipv4(&dst_addr)
            .map(|src_addr| Ipv4Repr {
                src_addr,
                dst_addr,
                next_header: IpProtocol::Udp,
                payload_len: UDP_HEADER_LEN
                    .checked_add(len)
                    .expect("UDP length overflow"),
                hop_limit: 64,
            });
        let mut checksum_caps = self.inner.caps.checksum.clone();
        checksum_caps.udp = if socket.config().tx_checksum && self.inner.caps.checksum.udp.tx() {
            crate::phy::Checksum::Both
        } else {
            crate::phy::Checksum::None
        };
        if let Some(ip_repr) = &ip_repr
            && let Some(template) = &socket.template
            && template.fits(
                self.inner.neighbor_cache.changes(),
                src_mac,
                ip_repr,
                &udp_repr,
            )
        {
            let mut meta = PacketMeta::default();
            meta.tx_checksum = self.inner.tx_checksum(&IpRepr::Ipv4(*ip_repr), 0);
            token.set_meta(meta);
            token.consume(
                34usize
                    .checked_add(ip_repr.payload_len)
                    .expect("UDP frame length overflow"),
                |frame| template.emit(frame, ip_repr, fill, &checksum_caps),
            );
            #[cfg(test)]
            {
                udp.template_frames = udp
                    .template_frames
                    .checked_add(1)
                    .expect("UDP template frame count overflow");
            }
            self.inner.dispatch_neighbor_probe(device);
            return Ok(());
        }
        let mut next_hop = None;
        let (hardware_addr, mut token) = self
            .inner
            .lookup_hardware_addr(token, &to.addr, Some(&mut next_hop))
            .map_err(|err| match err {
                DispatchError::NoRoute => UdpSendError::NoRoute,
                DispatchError::NeighborPending => UdpSendError::NeighborPending,
            })?;
        let ip_repr = ip_repr.ok_or(UdpSendError::NoRoute)?;
        let mut meta = PacketMeta::default();
        meta.tx_checksum = self.inner.tx_checksum(&IpRepr::Ipv4(ip_repr), 0);
        token.set_meta(meta);
        self.inner.dispatch_ethernet(
            token,
            ip_repr
                .buffer_len()
                .checked_add(ip_repr.payload_len)
                .expect("IPv4 length overflow"),
            |mut frame| {
                frame.set_dst_addr(hardware_addr.ethernet_or_panic());
                frame.set_ethertype(EthernetProtocol::Ipv4);
                ip_repr.emit(
                    &mut Ipv4Packet::new_unchecked(frame.payload_mut()),
                    &checksum_caps,
                );
                udp_repr.emit(
                    &mut UdpPacket::new_unchecked(
                        &mut frame.payload_mut()[ip_repr.buffer_len()..],
                    ),
                    &ip_repr.src_addr.into(),
                    &to.addr,
                    len,
                    fill,
                    &checksum_caps,
                );
            },
        );
        if let Some((changes, mac)) = next_hop {
            socket.template = Some(UdpTemplate::new(
                src_mac,
                mac,
                &ip_repr,
                udp_repr.src_port,
                udp_repr.dst_port,
                changes,
            ));
        }
        self.inner.dispatch_neighbor_probe(device);
        Ok(())
    }
}

impl InterfaceInner {
    pub(super) fn process_udp<'frame>(
        &mut self,
        udp: Option<&mut UdpSet>,
        meta: PacketMeta,
        ipv4_repr: Ipv4Repr,
        ip_payload: &'frame [u8],
        payload_offset: usize,
    ) -> Option<Packet<'frame>> {
        let udp = udp?;
        assert!(udp.pending_rx_attach.is_none());
        let packet = match UdpPacket::new_checked(ip_payload) {
            Ok(packet) => packet,
            Err(_) => {
                udp.counters.rx_malformed = udp
                    .counters
                    .rx_malformed
                    .checked_add(1)
                    .expect("UDP malformed count overflow");
                return None;
            }
        };
        if !meta.l4_checksum_verified
            && packet.checksum() != 0
            && !packet.verify_checksum(&ipv4_repr.src_addr.into(), &ipv4_repr.dst_addr.into())
        {
            udp.counters.rx_checksum_bad = udp
                .counters
                .rx_checksum_bad
                .checked_add(1)
                .expect("UDP checksum count overflow");
            return None;
        }
        if !self.is_broadcast_v4(ipv4_repr.dst_addr)
            && (!self.has_ip_addr(ipv4_repr.dst_addr) || !ipv4_repr.dst_addr.x_is_unicast())
        {
            udp.counters.rx_not_unicast = udp
                .counters
                .rx_not_unicast
                .checked_add(1)
                .expect("UDP destination count overflow");
            return None;
        }
        let slot = match udp.lookup(packet.dst_port()) {
            Some(slot) => slot,
            None => {
                udp.counters.rx_no_port = udp
                    .counters
                    .rx_no_port
                    .checked_add(1)
                    .expect("UDP closed port count overflow");
                return None;
            }
        };
        let src = IpEndpoint::new(ipv4_repr.src_addr.into(), packet.src_port());
        let socket = udp.socket_at_mut(slot);
        if socket.peer().is_some_and(|peer| src != peer) {
            socket.stats.rx_dropped_peer = socket
                .stats
                .rx_dropped_peer
                .checked_add(1)
                .expect("UDP peer drop count overflow");
            return None;
        }
        if socket.at_limit() {
            socket.stats.rx_dropped_full = socket
                .stats
                .rx_dropped_full
                .checked_add(1)
                .expect("UDP full drop count overflow");
            return None;
        }
        let start = payload_offset
            .checked_add(UDP_HEADER_LEN)
            .expect("UDP payload offset overflow");
        let end = payload_offset
            .checked_add(packet.len() as usize)
            .expect("UDP payload end overflow");
        udp.pending_rx_attach = Some((
            slot,
            PendingUdp {
                src,
                dst_addr: ipv4_repr.dst_addr,
                payload: start..end,
            },
        ));
        None
    }
}
