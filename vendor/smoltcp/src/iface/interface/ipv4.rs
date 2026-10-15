use super::*;

impl InterfaceInner {
    fn count_ipv4_drop(&mut self) {
        self.ipv4_dropped = self
            .ipv4_dropped
            .checked_add(1)
            .expect("IPv4 drop count overflow");
    }

    /// Get an IPv4 source address based on a destination address.
    ///
    /// This function tries to find the first IPv4 address from the interface
    /// that is in the same subnet as the destination address. If no such
    /// address is found, the first IPv4 address from the interface is returned.
    #[allow(unused)]
    pub(crate) fn get_source_address_ipv4(&self, dst_addr: &Ipv4Address) -> Option<Ipv4Address> {
        let mut first_ipv4 = None;
        for cidr in self.ip_addrs.iter() {
            #[allow(irrefutable_let_patterns)] // if only ipv4 is enabled
            if let IpCidr::Ipv4(cidr) = cidr {
                // Return immediately if we find an address in the same subnet
                if cidr.contains_addr(dst_addr) {
                    return Some(cidr.address());
                }

                // Remember the first IPv4 address as fallback
                if first_ipv4.is_none() {
                    first_ipv4 = Some(cidr.address());
                }
            }
        }
        first_ipv4
    }

    /// Checks if an address is broadcast, taking into account ipv4 subnet-local
    /// broadcast addresses.
    pub(crate) fn is_broadcast_v4(&self, address: Ipv4Address) -> bool {
        if address.is_broadcast() {
            return true;
        }

        self.ip_addrs
            .iter()
            .filter_map(|own_cidr| match own_cidr {
                IpCidr::Ipv4(own_ip) => Some(own_ip.broadcast()?),
            })
            .any(|broadcast_address| address == broadcast_address)
    }

    /// Checks if an ipv4 address is unicast, taking into account subnet broadcast addresses
    fn is_unicast_v4(&self, address: Ipv4Address) -> bool {
        address.x_is_unicast() && !self.is_broadcast_v4(address)
    }

    /// Get the first IPv4 address of the interface.
    #[cfg(test)]
    pub(crate) fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.ip_addrs.iter().find_map(|addr| match *addr {
            IpCidr::Ipv4(cidr) => Some(cidr.address()),
            #[allow(unreachable_patterns)]
            _ => None,
        })
    }

    pub(super) fn process_ipv4<'a>(
        &mut self,
        sockets: &mut TcpSet,
        meta: PacketMeta,
        source_hardware_addr: HardwareAddress,
        ipv4_packet: &Ipv4Packet<&'a [u8]>,
        #[cfg(feature = "udp-set")] udp: Option<&mut UdpSet>,
    ) -> Option<Packet<'a>> {
        let mut checksum_caps = self.caps.checksum.clone();
        if meta.ipv4_checksum_verified {
            checksum_caps.ipv4 = crate::phy::Checksum::None;
        }
        let ipv4_repr = match Ipv4Repr::parse(ipv4_packet, &checksum_caps) {
            Ok(repr) => repr,
            Err(err) => {
                net_debug!("{:?}", err);
                self.count_ipv4_drop();
                return None;
            }
        };
        if !self.is_unicast_v4(ipv4_repr.src_addr) && !ipv4_repr.src_addr.is_unspecified() {
            // Discard packets with non-unicast source addresses but allow unspecified
            net_debug!("non-unicast or unspecified source address");
            self.count_ipv4_drop();
            return None;
        }

        let ip_payload = ipv4_packet.payload();

        let ip_repr = IpRepr::Ipv4(ipv4_repr);

        if !self.has_ip_addr(ipv4_repr.dst_addr) {
            // Only UDP may arrive on a broadcast or multicast destination. Like Linux, TCP and
            // ICMP sent there get no RST and no echo reply.
            #[cfg(feature = "udp-set")]
            let accept = ipv4_repr.next_header == IpProtocol::Udp
                && (ipv4_repr.dst_addr.is_multicast() || self.is_broadcast_v4(ipv4_repr.dst_addr));
            #[cfg(not(feature = "udp-set"))]
            let accept = false;
            if !accept {
                net_trace!("Rejecting IPv4 packet to {}", ipv4_repr.dst_addr);
                return None;
            }
        }

        if self.is_unicast_v4(ipv4_repr.dst_addr) {
            self.neighbor_cache.reset_expiry_if_existing(
                IpAddress::Ipv4(ipv4_repr.src_addr),
                source_hardware_addr,
                self.now,
            );
        }

        match ipv4_repr.next_header {
            IpProtocol::Icmp => self.process_icmpv4(ipv4_repr, ip_payload),

            #[cfg(feature = "udp-set")]
            IpProtocol::Udp => {
                let link_header_len = match self.caps.medium {
                    Medium::Ethernet => EthernetFrame::<&[u8]>::header_len(),
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => 0,
                };
                let payload_offset = link_header_len
                    .checked_add(ipv4_packet.header_len() as usize)
                    .expect("UDP payload offset overflow");
                self.process_udp(udp, meta, ipv4_repr, ip_payload, payload_offset)
            }

            IpProtocol::Tcp => {
                self.process_tcp(sockets, meta, ip_repr, ip_payload)
            }

            _ => None,
        }
    }

    pub(super) fn process_arp<'frame>(
        &mut self,
        timestamp: Instant,
        eth_frame: &EthernetFrame<&'frame [u8]>,
    ) -> Option<EthernetPacket<'frame>> {
        let arp_packet = check!(ArpPacket::new_checked(eth_frame.payload()));
        let arp_repr = check!(ArpRepr::parse(&arp_packet));

        match arp_repr {
            ArpRepr::EthernetIpv4 {
                operation,
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr,
                target_protocol_addr,
            } => {
                if !self.has_ip_addr(target_protocol_addr) {
                    // Follow Linux arp_is_garp; ignore non-gratuitous ARP for other hosts (no locktime).
                    if matches!(operation, ArpOperation::Request | ArpOperation::Reply)
                        && source_protocol_addr == target_protocol_addr
                        && (operation != ArpOperation::Reply
                            || target_hardware_addr == source_hardware_addr)
                        && source_protocol_addr.x_is_unicast()
                        && source_hardware_addr.is_unicast()
                        && self.in_same_network(&source_protocol_addr.into())
                    {
                        self.neighbor_cache.update_existing(
                            source_protocol_addr.into(),
                            source_hardware_addr.into(),
                            timestamp,
                        );
                    }
                    return None;
                }

                // Only process REQUEST and RESPONSE.
                if let ArpOperation::Unknown(_) = operation {
                    net_debug!("arp: unknown operation code");
                    return None;
                }

                if !source_hardware_addr.is_unicast() {
                    net_debug!("arp: non-unicast source hardware address");
                    return None;
                }

                if source_protocol_addr.is_unspecified() {
                    // RFC 5227 probe for our address: answer it, learn nothing (Linux arp_process).
                    if operation != ArpOperation::Request {
                        return None;
                    }
                } else if !source_protocol_addr.x_is_unicast() {
                    net_debug!("arp: non-unicast source address");
                    return None;
                } else if self.in_same_network(&IpAddress::Ipv4(source_protocol_addr)) {
                    // Fill the ARP cache from any ARP packet aimed at us (both request or response)
                    // whose sender is in our network. We fill from requests too because if someone
                    // is requesting our address they are probably going to talk to us, so we avoid
                    // having to request their address when we later reply to them. Requests from
                    // other networks are still answered (RFC 826), but not learned.
                    self.neighbor_cache.fill(
                        source_protocol_addr.into(),
                        source_hardware_addr.into(),
                        timestamp,
                    );
                } else {
                    net_debug!("arp: source IP address not in same network as us");
                }

                if operation == ArpOperation::Request {
                    let src_hardware_addr = self.hardware_addr.ethernet_or_panic();

                    Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
                        operation: ArpOperation::Reply,
                        source_hardware_addr: src_hardware_addr,
                        source_protocol_addr: target_protocol_addr,
                        target_hardware_addr: source_hardware_addr,
                        target_protocol_addr: source_protocol_addr,
                    }))
                } else {
                    None
                }
            }
        }
    }

    pub(super) fn process_icmpv4<'frame>(
        &mut self,
        ip_repr: Ipv4Repr,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        let icmp_packet = check!(Icmpv4Packet::new_checked(ip_payload));
        let icmp_repr = check!(Icmpv4Repr::parse(&icmp_packet, &self.caps.checksum));

        match icmp_repr {
            // Respond to echo requests.
            #[cfg(feature = "auto-icmp-echo-reply")]
            Icmpv4Repr::EchoRequest {
                ident,
                seq_no,
                data,
            } => {
                let icmp_reply_repr = Icmpv4Repr::EchoReply {
                    ident,
                    seq_no,
                    data,
                };
                self.icmpv4_reply(ip_repr, icmp_reply_repr)
            }

            // Ignore any echo replies.
            Icmpv4Repr::EchoReply { .. } => None,

            // FIXME: do something correct here?
            // By doing nothing, this arm handles the case when auto echo replies are disabled.
            _ => None,
        }
    }

    pub(super) fn icmpv4_reply<'frame, 'icmp: 'frame>(
        &self,
        ipv4_repr: Ipv4Repr,
        icmp_repr: Icmpv4Repr<'icmp>,
    ) -> Option<Packet<'frame>> {
        if !self.is_unicast_v4(ipv4_repr.src_addr) {
            // Do not send ICMP replies to non-unicast sources
            None
        } else if self.is_unicast_v4(ipv4_repr.dst_addr) {
            // Reply as normal when src_addr and dst_addr are both unicast
            let ipv4_reply_repr = Ipv4Repr {
                src_addr: ipv4_repr.dst_addr,
                dst_addr: ipv4_repr.src_addr,
                next_header: IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64,
            };
            Some(Packet::new_ipv4(
                ipv4_reply_repr,
                IpPayload::Icmpv4(icmp_repr),
            ))
        } else {
            None
        }
    }
}
