//! On-link peers for neighbor-cache tests and benches. Peer `i` has its own
//! IPv4 and Ethernet addresses. A sends ARP requests and TCP SYNs; the
//! responder answers with ARP replies and RSTs. It drains A once per turn,
//! rejects unexpected frames and duplicate SYNs, and checks at most 32 replies
//! per pass. Each turn consumes all prior replies and leaves no staged or
//! pending frames. Completion checks every socket Closed and idle pools.

use dpdk_smoltcp::smoltcp::phy::ChecksumCapabilities;
use dpdk_smoltcp::smoltcp::socket::tcp::State;
use dpdk_smoltcp::smoltcp::time::{Duration, Instant};
use dpdk_smoltcp::smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol, IpAddress,
    IpEndpoint, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr,
    TcpSeqNumber,
};
use dpdk_smoltcp::TcpHandle;

use crate::pair::{tcp_frame_between, Pair, Side, BUDGET};
use crate::ring_port;

const LOCAL_PORT: u16 = 40_000;
const REMOTE_PORT: u16 = 80;
const MAX_TURNS: usize = 10_000;
const MAX_TIME: Duration = Duration::from_secs(3600);

/// IPv4 address of peer `i` on A's /16 subnet.
pub fn peer_ip(i: usize) -> Ipv4Address {
    Ipv4Address::new(10, 0, u8::try_from(1 + i / 256).unwrap(), (i % 256) as u8)
}

/// Ethernet address of peer `i`.
pub fn peer_mac(i: usize) -> EthernetAddress {
    EthernetAddress([2, 0, 0, 1, u8::try_from(i / 256).unwrap(), (i % 256) as u8])
}

fn local_port(i: usize) -> u16 {
    LOCAL_PORT
        .checked_add(u16::try_from(i).unwrap())
        .expect("local port overflow")
}

/// No packet is in use except A's Device spare: a TX packet it reserved for a
/// frame it then did not write, kept for its next frame.
pub fn assert_idle(pair: &Pair) {
    let [(a_rx, a_tx), b] = pair.in_use();
    assert_eq!((a_rx, b), (0, (0, 0)));
    assert!(a_tx <= 1, "A holds {a_tx} TX packets");
}

/// Drain A once and inject one reply for each ARP request or SYN.
pub fn respond(pair: &Pair, answered: &mut [bool]) -> (usize, usize) {
    let mut replies = Vec::with_capacity(BUDGET);
    let (mut arps, mut syns) = (0, 0);
    let drained = pair.drain_tx(Side::A, |bytes| {
        let eth = EthernetFrame::new_checked(bytes)
            .unwrap_or_else(|error| panic!("invalid Ethernet frame {bytes:02x?}: {error:?}"));
        assert_eq!(eth.src_addr(), Side::A.mac(), "unexpected frame: {eth}");
        match eth.ethertype() {
            EthernetProtocol::Arp => {
                let packet = ArpPacket::new_checked(eth.payload())
                    .unwrap_or_else(|error| panic!("unexpected frame: {eth}, {error:?}"));
                let ArpRepr::EthernetIpv4 {
                    operation,
                    source_hardware_addr,
                    source_protocol_addr,
                    target_protocol_addr,
                    ..
                } = ArpRepr::parse(&packet)
                    .unwrap_or_else(|error| panic!("unexpected frame: {eth}, {packet}, {error:?}"))
                else {
                    panic!("unexpected frame: {eth}, {packet}");
                };
                assert_eq!(operation, ArpOperation::Request, "unexpected frame: {eth}");
                assert_eq!(
                    eth.dst_addr(),
                    EthernetAddress::BROADCAST,
                    "unexpected frame: {eth}"
                );
                assert_eq!(
                    (source_hardware_addr, source_protocol_addr),
                    (Side::A.mac(), Side::A.ip()),
                    "unexpected frame: {eth}"
                );
                let octets = target_protocol_addr.octets();
                assert!(octets[2] >= 1, "unexpected ARP target: {eth}, {packet}");
                let subnet = octets[2] - 1;
                let i = usize::from(subnet) * 256 + usize::from(octets[3]);
                assert!(i < answered.len(), "unexpected ARP target: {eth}, {packet}");
                assert_eq!(target_protocol_addr, peer_ip(i), "unexpected frame: {eth}");
                replies.push(ring_port::arp(
                    ArpOperation::Reply,
                    Side::A.mac(),
                    (peer_mac(i), peer_ip(i)),
                    (Side::A.mac(), Side::A.ip()),
                ));
                arps += 1;
            }
            EthernetProtocol::Ipv4 => {
                let caps = ChecksumCapabilities::default();
                let ip = Ipv4Packet::new_checked(eth.payload())
                    .unwrap_or_else(|error| panic!("unexpected frame: {eth}, {error:?}"));
                let repr = Ipv4Repr::parse(&ip, &caps)
                    .unwrap_or_else(|error| panic!("unexpected frame: {eth}, {ip}, {error:?}"));
                assert_eq!(
                    (repr.src_addr, repr.next_header),
                    (Side::A.ip(), IpProtocol::Tcp),
                    "unexpected frame: {eth}, {ip}"
                );
                let packet = TcpPacket::new_checked(ip.payload())
                    .unwrap_or_else(|error| panic!("unexpected frame: {eth}, {ip}, {error:?}"));
                let syn = TcpRepr::parse(
                    &packet,
                    &IpAddress::Ipv4(repr.src_addr),
                    &IpAddress::Ipv4(repr.dst_addr),
                    &caps,
                )
                .unwrap_or_else(|error| {
                    panic!("unexpected frame: {eth}, {ip}, {packet}, {error:?}")
                });
                assert!(
                    syn.src_port >= LOCAL_PORT,
                    "unexpected frame: {eth}, {ip}, {packet}"
                );
                let i = usize::from(syn.src_port - LOCAL_PORT);
                assert!(
                    i < answered.len(),
                    "unexpected frame: {eth}, {ip}, {packet}"
                );
                assert_eq!(
                    (eth.dst_addr(), repr.dst_addr),
                    (peer_mac(i), peer_ip(i)),
                    "unexpected frame: {eth}, {ip}"
                );
                assert_eq!(
                    (syn.dst_port, syn.control, syn.ack_number, syn.payload.len()),
                    (REMOTE_PORT, TcpControl::Syn, None, 0),
                    "unexpected frame: {eth}, {ip}, {packet}"
                );
                assert!(
                    !answered[i],
                    "duplicate SYN for peer {i}: {eth}, {ip}, {packet}"
                );
                answered[i] = true;
                replies.push(tcp_frame_between(
                    (peer_mac(i), peer_ip(i)),
                    (Side::A.mac(), Side::A.ip()),
                    &TcpRepr {
                        src_port: syn.dst_port,
                        dst_port: syn.src_port,
                        control: TcpControl::Rst,
                        seq_number: TcpSeqNumber(0),
                        ack_number: Some(syn.seq_number + 1),
                        window_len: 0,
                        window_scale: None,
                        max_seg_size: None,
                        sack_permitted: false,
                        sack_ranges: [None; 3],
                        timestamp: None,
                        payload: &[],
                    },
                ));
                syns += 1;
            }
            _ => panic!("unexpected frame: {eth}"),
        }
    });
    assert_eq!(drained, arps + syns);
    assert_eq!(replies.len(), drained);
    assert!(
        replies.len() <= BUDGET,
        "P={}, replies {}, ARP requests {arps}, SYNs {syns}, drained {drained}",
        answered.len(),
        replies.len()
    );
    pair.inject(Side::A, &replies);
    (arps, syns)
}

/// Connect every socket from A to its peer and turn A until every RST closes
/// its socket. Return ARP requests, elapsed virtual time and turns. The drive
/// fails after 10,000 turns or 3600 seconds of virtual time. B and both links
/// stay unused; every frame and reply is checked.
pub fn connect_all(
    pair: &mut Pair,
    handles: &[TcpHandle],
    now: &mut Instant,
) -> (usize, Duration, usize) {
    let p = handles.len();
    assert_idle(pair);
    for (i, handle) in handles.iter().enumerate() {
        assert_eq!(pair.a.tcp(handle).state(), State::Closed);
        pair.a
            .connect(
                handle,
                IpEndpoint::new(peer_ip(i).into(), REMOTE_PORT),
                local_port(i),
            )
            .unwrap();
        assert_eq!(pair.a.tcp(handle).state(), State::SynSent);
    }
    let start = *now;
    let mut answered = vec![false; p];
    let (mut arps, mut syns, mut turns, mut pending_replies) = (0, 0, 0, 0);
    loop {
        assert!(
            turns < MAX_TURNS && *now - start <= MAX_TIME,
            "P={p}, ARP requests {arps}, RST replies {syns}, turns {turns}, elapsed {} ms",
            (*now - start).total_millis()
        );
        let turn = pair.a.turn(*now, BUDGET).unwrap();
        turns += 1;
        assert_eq!(
            (turn.rx_received, turn.rx_processed),
            (pending_replies, pending_replies)
        );
        assert_eq!(
            (
                turn.rx_rejected,
                turn.rx_staged,
                turn.rx_blocked,
                turn.tx_pending
            ),
            (0, 0, false, 0)
        );
        let (new_arps, new_syns) = respond(pair, &mut answered);
        pending_replies = new_arps + new_syns;
        assert_eq!(turn.tx_accepted, pending_replies);
        arps += new_arps;
        syns += new_syns;
        assert!(syns <= p);
        if syns == p && pending_replies == 0 {
            assert!(answered.iter().all(|&rst| rst));
            for handle in handles {
                assert_eq!(pair.a.tcp(handle).state(), State::Closed);
            }
            assert_idle(pair);
            return (arps, *now - start, turns);
        }
        if turn.tx_accepted == 0 {
            *now = (*now + Duration::from_millis(1)).max(pair.a.poll_at().unwrap_or(*now));
        }
    }
}
