use std::collections::VecDeque;

use smoltcp::phy::{self, Checksum, DeviceCapabilities, Medium, TxChecksum};
use smoltcp::time::Instant;
use zhida_dpdk_sys::{
    zhida_errno, RTE_MBUF_F_RX_IP_CKSUM_GOOD, RTE_MBUF_F_RX_IP_CKSUM_MASK,
    RTE_MBUF_F_RX_L4_CKSUM_GOOD, RTE_MBUF_F_RX_L4_CKSUM_MASK, RTE_MBUF_F_TX_IPV4,
    RTE_MBUF_F_TX_TCP_CKSUM, RTE_MBUF_F_TX_UDP_CKSUM,
};

use crate::port::{eth_tx_prepare, Packet, Port, PortError, RxBurst};

/// smoltcp device over one Port with bounded RX staging and TX pending queues.
///
/// Tokens are issued only with a free pending slot and a full-frame TX packet
/// in hand, so `TxToken::consume` never fails or allocates. Otherwise
/// `receive` returns `None` and the RX packet stays staged.
pub(crate) struct Device {
    rx: VecDeque<Packet>,
    tx: VecDeque<Packet>,
    /// Full-frame TX packet of a token dropped without `consume`, never
    /// written; the next token takes it instead of allocating.
    spare: Option<Packet>,
    /// With a TX checksum profile on, the last `flush` returned with this
    /// many pending frames; frames at or after this index were queued since and
    /// are not prepared yet. Unused with both TX checksum profiles off.
    prepared: usize,
    /// Last: fields drop in order, so staged, pending and spare packets must
    /// return to their pools before Port cleanup checks that both pools are idle.
    port: Port,
}

impl Device {
    /// Queues hold at least `rx_staging` / `tx_pending` packets and never grow.
    pub(crate) fn new(port: Port, rx_staging: usize, tx_pending: usize) -> Self {
        Self {
            port,
            rx: VecDeque::with_capacity(rx_staging),
            tx: VecDeque::with_capacity(tx_pending),
            spare: None,
            prepared: 0,
        }
    }

    /// One PMD burst into the free staging space.
    pub(crate) fn rx_burst(&mut self) -> Result<RxBurst, PortError> {
        self.port.rx_burst(&mut self.rx)
    }

    /// Offer pending frames to the PMD, one burst after another while it
    /// accepts everything offered and frames remain; the unaccepted suffix
    /// stays in order. Returns the total accepted.
    /// With either TX checksum profile on, first prepares every frame queued since
    /// the last flush and panics if the PMD refuses a frame.
    pub(crate) fn flush(&mut self) -> Result<usize, PortError> {
        if self.port.tx_tcp_checksum() || self.port.tx_udp_checksum() {
            return self.prepare_and_offer();
        }
        self.offer()
    }

    /// Kept out of line: inlined into `flush`, it made each profile-off
    /// `Stack::turn` about 5 ns slower in the memif pingpong benchmarks.
    #[inline(never)]
    fn prepare_and_offer(&mut self) -> Result<usize, PortError> {
        let port_id = self.port.port_id();
        let (front, back) = self.tx.as_mut_slices();
        let skip_front = self.prepared.min(front.len());
        let skip_back = self.prepared.saturating_sub(front.len());
        let mut index = 0;
        for part in [&mut front[skip_front..], &mut back[skip_back..]] {
            for packets in part.chunks_mut(usize::from(u16::MAX)) {
                let count = u16::try_from(packets.len())
                    .expect("TX prepare chunk is bounded by u16::MAX");
                // SAFETY: Packet is transparent over one mbuf pointer. These
                // packets are owned, direct and unshared on the Port's thread.
                let ready = unsafe { eth_tx_prepare(port_id, 0, packets.as_mut_ptr().cast(), count) };
                if ready < count {
                    panic!(
                        "port {port_id}: TX checksum preparation refused at frame {}, rte_errno {}",
                        index + usize::from(ready),
                        unsafe { zhida_errno() }
                    );
                }
                index += packets.len();
            }
        }
        let accepted = self.offer();
        // offer removes only the accepted prefix; consume only appends. Every
        // remaining frame is prepared even on Err; next flush skips these frames.
        self.prepared = self.tx.len();
        accepted
    }

    fn offer(&mut self) -> Result<usize, PortError> {
        let burst = self.port.tx_burst_size();
        let mut accepted = 0;
        loop {
            let offered = self.tx.len().min(burst);
            let taken = self.port.tx_burst(&mut self.tx)?;
            accepted += taken;
            if taken < offered || self.tx.is_empty() {
                return Ok(accepted);
            }
        }
    }

    pub(crate) fn staged(&self) -> usize {
        self.rx.len()
    }

    pub(crate) fn pending(&self) -> usize {
        self.tx.len()
    }

    /// Release every staged, pending and spare packet, then return the Port.
    pub(crate) fn into_port(self) -> Port {
        let Self {
            port,
            rx,
            tx,
            spare,
            ..
        } = self;
        drop((rx, tx, spare));
        port
    }
}

/// Reserve a free pending slot and a full-frame TX packet: the spare if one
/// is held, else a new allocation.
fn reserve<'a>(
    port: &'a Port,
    pending: &'a mut VecDeque<Packet>,
    spare: &'a mut Option<Packet>,
) -> Option<Tx<'a>> {
    if pending.len() == pending.capacity() {
        return None;
    }
    let packet = match spare.take() {
        Some(packet) => packet,
        None => port.alloc_tx(port.frame_capacity())?,
    };
    Some(Tx {
        packet: Some(packet),
        pending,
        spare,
        port,
        tx_checksum: None,
    })
}

impl phy::Device for Device {
    type RxToken<'a> = Rx<'a>;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Rx<'_>, Tx<'_>)> {
        if self.rx.is_empty() {
            return None;
        }
        let tx = reserve(&self.port, &mut self.tx, &mut self.spare)?;
        let rx = self.rx.pop_front()?;
        Some((Rx(rx, &self.port), tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Tx<'_>> {
        reserve(&self.port, &mut self.tx, &mut self.spare)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = usize::from(self.port.frame_capacity());
        if self.port.tx_tcp_checksum() {
            caps.checksum.tcp = Checksum::Rx;
        }
        if self.port.tx_udp_checksum() {
            caps.checksum.udp = Checksum::Rx;
        }
        caps
    }
}

/// One staged RX packet; its storage returns to the pool when the owned frame drops.
pub(crate) struct Rx<'a>(Packet, &'a Port);

impl phy::RxToken for Rx<'_> {
    fn into_buf(self) -> phy::RxBuf {
        if let Some(field) = self.1.rx_timestamp_field() {
            let stamp = if self.0.ol_flags() & field.flag != 0 {
                // SAFETY: Port registered this u64 field, and the PMD's flag
                // says it initialized the field in this exclusively owned mbuf.
                unsafe { self.0.dynfield_u64(field.offset) }
            } else {
                0
            };
            let mut frame = self.0.into_rx_buf();
            frame.set_rx_timestamp(stamp);
            return frame;
        }
        self.0.into_rx_buf()
    }

    fn meta(&self) -> phy::PacketMeta {
        let mut meta = phy::PacketMeta::default();
        if self.1.rx_checksum_enabled() {
            let flags = self.0.ol_flags();
            meta.ipv4_checksum_verified =
                flags & RTE_MBUF_F_RX_IP_CKSUM_MASK == RTE_MBUF_F_RX_IP_CKSUM_GOOD;
            meta.l4_checksum_verified =
                flags & RTE_MBUF_F_RX_L4_CKSUM_MASK == RTE_MBUF_F_RX_L4_CKSUM_GOOD;
        }
        meta
    }
}

/// A full-frame TX packet plus the free pending slot held by the exclusive
/// borrow. Queued only when `consume`'s callback returns. Dropped without
/// `consume`, the untouched packet becomes the Device's spare; once `consume`
/// takes it, a panic returns it to the TX pool and nothing is queued.
pub(crate) struct Tx<'a> {
    /// `None` only after `consume` took it.
    packet: Option<Packet>,
    pending: &'a mut VecDeque<Packet>,
    spare: &'a mut Option<Packet>,
    port: &'a Port,
    tx_checksum: Option<TxChecksum>,
}

impl Drop for Tx<'_> {
    fn drop(&mut self) {
        if let Some(packet) = self.packet.take() {
            *self.spare = Some(packet);
        }
    }
}

impl phy::TxToken for Tx<'_> {
    fn set_meta(&mut self, meta: phy::PacketMeta) {
        self.tx_checksum = meta.tx_checksum;
    }

    /// Panics before calling `f` if `len` exceeds the frame capacity.
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, len: usize, f: F) -> R {
        let Some(mut packet) = self.packet.take() else {
            unreachable!("a TX token holds its packet until consume")
        };
        packet.truncate(len);
        let result = f(packet.data_mut());
        let port_id = self.port.port_id();
        let (flags, l3, l4) = match self.tx_checksum {
            Some(TxChecksum::Tcp {
                ip_header_len,
                tcp_header_len,
            }) => {
                assert!(
                    self.port.tx_tcp_checksum(),
                    "port {port_id}: TCP TX offload metadata without its profile"
                );
                (
                    RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_TCP_CKSUM,
                    u16::from(ip_header_len),
                    u16::from(tcp_header_len),
                )
            }
            Some(TxChecksum::Udp { ip_header_len }) => {
                assert!(
                    self.port.tx_udp_checksum(),
                    "port {port_id}: UDP TX offload metadata without its profile"
                );
                (RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_UDP_CKSUM, u16::from(ip_header_len), 8)
            }
            None => (0, 0, 0),
        };
        // SAFETY: the Packet owns its direct, unshared mbuf exclusively.
        unsafe {
            let raw = packet.as_ptr();
            (*raw).set_ol_flags(flags);
            (*raw).set_tx_offload_lengths(if flags == 0 { 0 } else { 14 }, l3, l4);
        }
        // The slot checked at reservation is still free: this borrow was exclusive.
        self.pending.push_back(packet);
        result
    }
}

#[cfg(test)]
#[path = "device_tests.rs"]
mod tests;
