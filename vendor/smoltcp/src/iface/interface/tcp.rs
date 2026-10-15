use super::*;

use crate::socket::tcp::Socket;

impl InterfaceInner {
    pub(super) fn dispatch_tcp<Tx: TxToken>(
        &mut self,
        mut tx: Tx,
        mut meta: PacketMeta,
        ip: IpRepr,
        tcp: TcpRepr,
        next_hop: &mut Option<(u64, EthernetAddress)>,
        template: &mut Option<crate::iface::header_template::TcpTemplate>,
    ) -> Result<(), DispatchError> {
        use crate::iface::header_template::TcpTemplate;

        #[allow(irrefutable_let_patterns)]
        if let IpRepr::Ipv4(ip4) = ip
            && self.caps.medium == Medium::Ethernet
            && TcpTemplate::is_eligible(&tcp)
        {
            assert!(!ip4.dst_addr.is_unspecified());
            let changes = self.neighbor_cache.changes();
            let src_mac = self.hardware_addr.ethernet_or_panic();
            if !next_hop.is_some_and(|(generation, _)| generation == changes)
                || !template.as_ref().is_some_and(|template| {
                    template.fits(changes, src_mac, &ip4, &tcp)
                })
            {
                let (mac, resolved_tx) = self.lookup_hardware_addr(
                    tx,
                    &ip4.dst_addr.into(),
                    Some(next_hop),
                )?;
                tx = resolved_tx;
                *template = Some(TcpTemplate::new(
                    src_mac,
                    mac.ethernet_or_panic(),
                    &ip4,
                    tcp.src_port,
                    tcp.dst_port,
                    self.neighbor_cache.changes(),
                ));
            }
            if 20 + ip4.payload_len > self.caps.ip_mtu() {
                return Ok(());
            }
            let mut tcp = tcp;
            if let Some(max_burst_size) = self.caps.max_burst_size {
                let max_segment_size = self.caps.max_transmission_unit - 20 - tcp.header_len();
                let max_window_size = max_burst_size * max_segment_size;
                if tcp.window_len as usize > max_window_size {
                    tcp.window_len = max_window_size as u16;
                }
            }
            meta.tx_checksum = self.tx_checksum(&ip, tcp.header_len());
            tx.set_meta(meta);
            tx.consume(14 + 20 + ip4.payload_len, |frame| {
                template.as_ref().unwrap().emit(frame, &ip4, &tcp, &self.caps.checksum)
            });
            #[cfg(test)]
            {
                self.template_frames = self
                    .template_frames
                    .checked_add(1)
                    .expect("TCP template frame count overflow");
            }
            return Ok(());
        }

        self.dispatch_ip(
            tx,
            meta,
            Packet::new(ip.clone(), IpPayload::Tcp(tcp)),
            Some(next_hop),
        )?;
        #[allow(irrefutable_let_patterns)]
        if let IpRepr::Ipv4(ip4) = ip
            && self.caps.medium == Medium::Ethernet
            && let Some((changes, mac)) = *next_hop
            && changes == self.neighbor_cache.changes()
        {
            *template = Some(TcpTemplate::new(
                self.hardware_addr.ethernet_or_panic(),
                mac,
                &ip4,
                tcp.src_port,
                tcp.dst_port,
                changes,
            ));
        }
        Ok(())
    }

    pub(crate) fn process_tcp<'frame>(
        &mut self,
        sockets: &mut TcpSet,
        meta: PacketMeta,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        assert!(sockets.pending_rx_attach.is_none());
        assert!(sockets.pending_tcp_reply.is_none());

        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());

        // Per RFC 1122 §3.2.1.3, the unspecified address must never appear as a source
        // or destination in any IP datagram. Drop such TCP segments early to avoid
        // creating sockets with unspecified peers (which would later panic on egress).
        if src_addr.is_unspecified() || dst_addr.is_unspecified() {
            return None;
        }

        let tcp_packet = check!(TcpPacket::new_checked(ip_payload));
        if tcp_packet.src_port() == 0 || tcp_packet.dst_port() == 0 {
            return None;
        }
        if !meta.l4_checksum_verified && self.caps.checksum.tcp.rx()
            && !tcp_packet.verify_checksum(&src_addr, &dst_addr)
        {
            sockets.counters.rx_checksum_bad = sockets.counters.rx_checksum_bad
                .checked_add(1)
                .expect("TCP RX checksum failure count overflow");
            return None;
        }
        let mut checksum_caps = self.caps.checksum.clone();
        checksum_caps.tcp = crate::phy::Checksum::None;
        let tcp_repr = check!(TcpRepr::parse(
            &tcp_packet,
            &src_addr,
            &dst_addr,
            &checksum_caps
        ));

        let syn_like = tcp_repr.ack_number.is_none() && tcp_repr.control != TcpControl::Rst;
        let dst = IpEndpoint::new(dst_addr, tcp_repr.dst_port);
        let src = IpEndpoint::new(src_addr, tcp_repr.src_port);

        #[cfg(debug_assertions)]
        let linear = {
            let listener = (0..sockets.slot_count()).find(|&index| {
                sockets.item_at_mut(index).is_some_and(|item| {
                    item.socket.is_listening()
                        && item.socket.accepts(self, &ip_repr, &tcp_repr)
                })
            });
            (0..sockets.slot_count())
                .find(|&index| {
                    sockets.item_at_mut(index).is_some_and(|item| {
                        !item.socket.is_listening()
                            && item.socket.accepts(self, &ip_repr, &tcp_repr)
                            && !(listener.is_some()
                                && item.socket.time_wait_accepts_syn(&tcp_repr))
                    })
                })
                .or(listener)
        };

        let mut winner = sockets.tcp_lookup(dst, src, syn_like);
        if tcp_repr.control == TcpControl::Syn && tcp_repr.ack_number.is_none() {
            while let Some(index) = winner {
                let socket = &mut sockets
                    .item_at_mut(index)
                    .expect("TCP flow index contains an empty slot")
                    .socket;
                if !socket.time_wait_accepts_syn(&tcp_repr)
                    || sockets.tcp_listener_lookup(dst).is_none()
                {
                    break;
                }
                sockets
                    .item_at_mut(index)
                    .expect("TCP flow index contains an empty slot")
                    .socket
                    .finish_time_wait();
                sockets.sync_identity(index);
                sockets.check_reapable(index);
                sockets.mark_dirty_synced(index);
                winner = sockets.tcp_lookup(dst, src, syn_like);
            }
        }

        #[cfg(debug_assertions)]
        {
            assert_eq!(
                linear, winner,
                "TCP segment {src_addr}:{} -> {dst_addr}:{} {tcp_repr:?}: linear slot {linear:?}, flow index slot {winner:?}",
                tcp_repr.src_port, tcp_repr.dst_port,
            );
        }

        if let Some(index) = winner {
            let socket = &mut sockets
                .item_at_mut(index)
                .expect("TCP flow index contains an empty slot")
                .socket;
            debug_assert!(
                socket.accepts(self, &ip_repr, &tcp_repr),
                "flow index out of date for slot {index}"
            );
            let before = socket.state();
            let (reply, pending) = socket.process(self, &ip_repr, &tcp_repr);
            // Inside process, a flow key change requires a state change.
            if socket.state() != before {
                sockets.sync_identity(index);
                sockets.check_reapable(index);
            } else {
                #[cfg(debug_assertions)]
                sockets.debug_assert_synced(index);
            }
            sockets.mark_dirty_synced(index);
            if let Some(pending) = pending {
                sockets.pending_rx_attach = Some((index, pending));
            }
            #[cfg(test)]
            sockets.check_flow_index();
            return reply.map(|(ip, tcp)| {
                if self.caps.medium == Medium::Ethernet && ip.version() == IpVersion::Ipv4 {
                    sockets.pending_tcp_reply = Some(index);
                }
                Packet::new(ip, IpPayload::Tcp(tcp))
            });
        }

        if tcp_repr.control == TcpControl::Rst
            || ip_repr.dst_addr().is_unspecified()
            || ip_repr.src_addr().is_unspecified()
        {
            // Never reply to a TCP RST packet with another TCP RST packet.
            // Never send a TCP RST packet with unspecified addresses.
            None
        } else {
            // The packet wasn't handled by a socket, send a TCP RST packet.
            let (ip, tcp) = Socket::rst_reply(&ip_repr, &tcp_repr);
            Some(Packet::new(ip, IpPayload::Tcp(tcp)))
        }
    }
}
