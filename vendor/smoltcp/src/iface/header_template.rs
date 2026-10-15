use crate::phy::ChecksumCapabilities;
use crate::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr,
    checksum,
};
use crate::wire::{TcpControl, TcpOption, TcpPacket, TcpRepr};
use byteorder::{ByteOrder, NetworkEndian};
#[cfg(feature = "udp-set")]
use crate::wire::{UdpPacket, UdpRepr};

/// Ethernet and IPv4 headers with zero total length and checksum, plus their partial sums.
#[derive(Debug)]
pub(crate) struct Ipv4Prefix {
    bytes: [u8; 34],
    changes: u64,
    src_mac: EthernetAddress,
    src: Ipv4Address,
    dst: Ipv4Address,
    hop_limit: u8,
    ip_sum: u16,
    pseudo_sum: u16,
}

impl Ipv4Prefix {
    fn new(
        src_mac: EthernetAddress,
        dst_mac: EthernetAddress,
        ip: &Ipv4Repr,
        changes: u64,
    ) -> Self {
        let mut bytes = [0; 34];
        let mut frame = EthernetFrame::new_unchecked(&mut bytes[..]);
        frame.set_src_addr(src_mac);
        frame.set_dst_addr(dst_mac);
        frame.set_ethertype(EthernetProtocol::Ipv4);
        let mut packet = Ipv4Packet::new_unchecked(frame.payload_mut());
        Ipv4Repr {
            payload_len: 0,
            ..*ip
        }
        .emit(&mut packet, &ChecksumCapabilities::ignored());
        packet.set_total_len(0);
        let ip_sum = checksum::data(&bytes[14..34]);
        Self {
            bytes,
            changes,
            src_mac,
            src: ip.src_addr,
            dst: ip.dst_addr,
            hop_limit: ip.hop_limit,
            ip_sum,
            pseudo_sum: checksum::pseudo_header_v4(&ip.src_addr, &ip.dst_addr, ip.next_header, 0),
        }
    }

    fn fits(&self, changes: u64, src_mac: EthernetAddress, ip: &Ipv4Repr) -> bool {
        self.changes == changes
            && self.src_mac == src_mac
            && self.src == ip.src_addr
            && self.dst == ip.dst_addr
            && self.hop_limit == ip.hop_limit
    }

    fn emit(&self, frame: &mut [u8], ip: &Ipv4Repr, caps: &ChecksumCapabilities) {
        frame[..34].copy_from_slice(&self.bytes);
        let total_len = 20 + ip.payload_len as u16;
        let mut packet = Ipv4Packet::new_unchecked(&mut frame[14..]);
        packet.set_total_len(total_len);
        packet.set_checksum(if caps.ipv4.tx() {
            !checksum::combine(&[self.ip_sum, total_len])
        } else {
            0
        });
    }
}

#[derive(Debug)]
pub(crate) struct TcpTemplate {
    prefix: Ipv4Prefix,
    src_port: core::num::NonZeroU16,
    dst_port: u16,
}

impl TcpTemplate {
    pub(crate) fn new(
        src_mac: EthernetAddress,
        dst_mac: EthernetAddress,
        ip: &Ipv4Repr,
        src_port: u16,
        dst_port: u16,
        changes: u64,
    ) -> Self {
        Self {
            prefix: Ipv4Prefix::new(src_mac, dst_mac, ip, changes),
            src_port: core::num::NonZeroU16::new(src_port)
                .expect("TCP template source port must be nonzero"),
            dst_port,
        }
    }

    pub(crate) fn is_eligible(tcp: &TcpRepr) -> bool {
        tcp.ack_number.is_some()
            && matches!(
                tcp.control,
                TcpControl::None | TcpControl::Psh | TcpControl::Fin | TcpControl::Rst
            )
    }

    pub(crate) fn fits(
        &self,
        changes: u64,
        src_mac: EthernetAddress,
        ip: &Ipv4Repr,
        tcp: &TcpRepr,
    ) -> bool {
        self.prefix.fits(changes, src_mac, ip)
            && self.src_port.get() == tcp.src_port
            && self.dst_port == tcp.dst_port
    }

    pub(crate) fn emit(
        &self,
        frame: &mut [u8],
        ip: &Ipv4Repr,
        tcp: &TcpRepr,
        checksum: &ChecksumCapabilities,
    ) {
        assert!(
            tcp.max_seg_size.is_none() && tcp.window_scale.is_none() && !tcp.sack_permitted,
            "ACK-bearing TCP template segment carries SYN-only options"
        );
        self.prefix.emit(frame, ip, checksum);
        let header_len = tcp.header_len();

        let mut packet = TcpPacket::new_unchecked(&mut frame[34..]);
        packet.set_src_port(tcp.src_port);
        packet.set_dst_port(tcp.dst_port);
        packet.set_seq_number(tcp.seq_number);
        packet.set_ack_number(tcp.ack_number.expect("TCP template requires ACK"));
        packet.set_header_len(header_len as u8);
        packet.clear_flags();
        packet.set_ack(true);
        match tcp.control {
            TcpControl::None => (),
            TcpControl::Psh => packet.set_psh(true),
            TcpControl::Fin => packet.set_fin(true),
            TcpControl::Rst => packet.set_rst(true),
            _ => unreachable!("TCP control does not fit template"),
        }
        packet.set_window_len(tcp.window_len);
        packet.set_checksum(0);
        packet.set_urgent_at(0);
        let mut options = packet.options_mut();
        if tcp.sack_ranges.iter().any(Option::is_some) {
            options = TcpOption::SackRange(tcp.sack_ranges).emit(options);
        }
        if let Some(timestamp) = tcp.timestamp {
            options = TcpOption::TimeStamp {
                tsval: timestamp.tsval,
                tsecr: timestamp.tsecr,
            }
            .emit(options);
        }
        if !options.is_empty() {
            TcpOption::EndOfList.emit(options);
        }
        packet.payload_mut().copy_from_slice(tcp.payload);
        if checksum.tcp.tx() {
            let tcp_len = ip.payload_len as u16;
            // The fixed header is summed from its field values and the payload from its source, so
            // no checksum load spans the narrow header stores or reads back the copied payload.
            let seq = tcp.seq_number.0 as u32;
            let ack = tcp.ack_number.expect("TCP template requires ACK").0 as u32;
            let sum = !checksum::combine(&[
                self.prefix.pseudo_sum,
                tcp_len,
                tcp.src_port,
                tcp.dst_port,
                (seq >> 16) as u16,
                seq as u16,
                (ack >> 16) as u16,
                ack as u16,
                NetworkEndian::read_u16(&packet.as_ref()[12..14]),
                tcp.window_len,
                checksum::data(&packet.as_ref()[20..header_len]),
                checksum::data(tcp.payload),
            ]);
            packet.set_checksum(sum);
        }
    }
}

#[derive(Debug)]
#[cfg(feature = "udp-set")]
pub(crate) struct UdpTemplate {
    prefix: Ipv4Prefix,
    src_port: u16,
    dst_port: u16,
}

#[cfg(feature = "udp-set")]
impl UdpTemplate {
    pub(crate) fn new(
        src_mac: EthernetAddress,
        dst_mac: EthernetAddress,
        ip: &Ipv4Repr,
        src_port: u16,
        dst_port: u16,
        changes: u64,
    ) -> Self {
        Self {
            prefix: Ipv4Prefix::new(src_mac, dst_mac, ip, changes),
            src_port,
            dst_port,
        }
    }

    pub(crate) fn fits(
        &self,
        changes: u64,
        src_mac: EthernetAddress,
        ip: &Ipv4Repr,
        udp: &UdpRepr,
    ) -> bool {
        self.prefix.fits(changes, src_mac, ip)
            && self.src_port == udp.src_port
            && self.dst_port == udp.dst_port
    }

    pub(crate) fn emit(
        &self,
        frame: &mut [u8],
        ip: &Ipv4Repr,
        fill: impl FnOnce(&mut [u8]),
        checksum: &ChecksumCapabilities,
    ) {
        self.prefix.emit(frame, ip, checksum);

        let mut packet = UdpPacket::new_unchecked(&mut frame[34..]);
        let udp_len = ip.payload_len as u16;
        packet.set_src_port(self.src_port);
        packet.set_dst_port(self.dst_port);
        packet.set_len(udp_len);
        packet.set_checksum(0);
        fill(packet.payload_mut());
        if checksum.udp.tx() {
            // The header words come from their values and the payload is summed from its own
            // start, so no load spans both the header stores and the app's payload stores.
            let sum = !checksum::combine(&[
                self.prefix.pseudo_sum,
                udp_len,
                self.src_port,
                self.dst_port,
                udp_len,
                checksum::data(packet.payload_mut()),
            ]);
            packet.set_checksum(if sum == 0 { 0xffff } else { sum });
        }
    }
}
