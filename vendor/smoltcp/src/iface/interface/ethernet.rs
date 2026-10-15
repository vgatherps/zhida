use super::*;

impl InterfaceInner {
    pub(super) fn process_ethernet<'frame>(
        &mut self,
        sockets: &mut TcpSet,
        meta: crate::phy::PacketMeta,
        frame: &'frame [u8],
        #[cfg(feature = "udp-set")] udp: Option<&mut UdpSet>,
    ) -> Option<EthernetPacket<'frame>> {
        let eth_frame = check!(EthernetFrame::new_checked(frame));

        // Ignore any packets not directed to our hardware address or any of the multicast groups.
        if !eth_frame.dst_addr().is_broadcast()
            && !eth_frame.dst_addr().is_multicast()
            && HardwareAddress::Ethernet(eth_frame.dst_addr()) != self.hardware_addr
        {
            return None;
        }

        match eth_frame.ethertype() {
            EthernetProtocol::Arp => self.process_arp(self.now, &eth_frame),
            EthernetProtocol::Ipv4 => {
                let ipv4_packet = Ipv4Packet::new_unchecked(eth_frame.payload());

                self.process_ipv4(
                    sockets,
                    meta,
                    eth_frame.src_addr().into(),
                    &ipv4_packet,
                    #[cfg(feature = "udp-set")]
                    udp,
                )
                .map(EthernetPacket::Ip)
            }
            // Drop all other traffic.
            _ => None,
        }
    }

    pub(super) fn dispatch_ethernet<Tx, F>(
        &mut self,
        tx_token: Tx,
        buffer_len: usize,
        f: F,
    ) where
        Tx: TxToken,
        F: FnOnce(EthernetFrame<&mut [u8]>),
    {
        let tx_len = EthernetFrame::<&[u8]>::buffer_len(buffer_len);
        tx_token.consume(tx_len, |tx_buffer| {
            debug_assert!(tx_buffer.as_ref().len() == tx_len);
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = self.hardware_addr.ethernet_or_panic();
            frame.set_src_addr(src_addr);

            f(frame);
        });
    }
}
