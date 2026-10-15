use super::*;
use crate::iface::header_template::TcpTemplate;
use crate::phy::Checksum;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

#[test]
fn template_matches_generic_emitter() {
    let (mut iface, _, _) = setup(Medium::Ethernet);
    iface.inner.caps.max_transmission_unit = 1600;
    let src = Ipv4Address::new(192, 168, 1, 1);
    let dst = Ipv4Address::new(192, 168, 1, 2);
    let payload: Vec<u8> = (0..1451).map(|n| (n % 251) as u8).collect();
    for control in [
        TcpControl::None,
        TcpControl::Psh,
        TcpControl::Fin,
        TcpControl::Rst,
    ] {
        for (len, blocks, offset) in [0, 1, 2, 3, 63, 64, 1447, 1448]
            .into_iter()
            .flat_map(|len| (0..=3).flat_map(move |blocks| (0..4).map(move |offset| (len, blocks, offset))))
        {
            for hop_limit in [1, 64, 255] {
                for (ipv4_checksum, tcp_checksum) in [
                    (Checksum::Both, Checksum::Both),
                    (Checksum::Both, Checksum::Rx),
                    (Checksum::Rx, Checksum::Both),
                    (Checksum::Rx, Checksum::Rx),
                ] {
                    iface.inner.caps.checksum = ChecksumCapabilities {
                        ipv4: ipv4_checksum,
                        tcp: tcp_checksum,
                        ..ChecksumCapabilities::default()
                    };
                    let tcp = TcpRepr {
                        src_port: 40000,
                        dst_port: 80,
                        control,
                        seq_number: TcpSeqNumber(0x12345678),
                        ack_number: Some(TcpSeqNumber(-12345)),
                        window_len: 4096,
                        window_scale: None,
                        max_seg_size: None,
                        sack_permitted: false,
                        sack_ranges: core::array::from_fn(|index| {
                            (index < blocks).then_some((100 + index as u32 * 10, 105 + index as u32 * 10))
                        }),
                        timestamp: None,
                        payload: &payload[offset..offset + len],
                    };
                    let ip = Ipv4Repr {
                        src_addr: src,
                        dst_addr: dst,
                        next_header: IpProtocol::Tcp,
                        payload_len: tcp.buffer_len(),
                        hop_limit,
                    };
                    compare_template(&mut iface, ip, tcp);
                }
            }
        }
    }
}

fn compare_template(iface: &mut Interface, ip: Ipv4Repr, tcp: TcpRepr) -> Vec<u8> {
    let src_mac = iface.inner.hardware_addr.ethernet_or_panic();
    let dst_mac = EthernetAddress([2, 0, 0, 0, 0, 2]);
    iface
        .inner
        .neighbor_cache
        .fill(ip.dst_addr.into(), dst_mac.into(), Instant::ZERO);
    let changes = iface.inner.neighbor_cache.changes();
    let template = TcpTemplate::new(src_mac, dst_mac, &ip, tcp.src_port, tcp.dst_port, changes);
    assert!(template.fits(changes, src_mac, &ip, &tcp));
    let mut frame = Vec::new();
    CaptureTxToken(&mut frame).consume(14 + 20 + ip.payload_len, |frame| {
        template.emit(frame, &ip, &tcp, &iface.inner.caps.checksum)
    });
    let mut generic = Vec::new();
    iface
        .inner
        .dispatch_ip(
            CaptureTxToken(&mut generic),
            PacketMeta::default(),
            Packet::new_ipv4(ip, IpPayload::Tcp(tcp)),
            None,
        )
        .unwrap();
    assert_eq!(frame, generic);
    frame
}

#[test]
fn template_matches_generic_emitter_above_u16_payload_len() {
    let (mut iface, _, _) = setup(Medium::Ethernet);
    iface.inner.caps.max_transmission_unit = 65590;
    let payload = vec![0x5a; 65535];
    let tcp = TcpRepr {
        src_port: 40000,
        dst_port: 80,
        control: TcpControl::Psh,
        seq_number: TcpSeqNumber(123),
        ack_number: Some(TcpSeqNumber(456)),
        window_len: 65535,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &payload,
    };
    let ip = Ipv4Repr {
        src_addr: Ipv4Address::new(192, 168, 1, 1),
        dst_addr: Ipv4Address::new(192, 168, 1, 2),
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    assert_eq!(ip.payload_len, 65555);
    let frame = compare_template(&mut iface, ip, tcp);
    assert_eq!(frame.len(), 65589);
    assert_eq!(Ipv4Packet::new_unchecked(&frame[14..]).total_len(), 39);
    assert_eq!(&frame[54..], payload);
}

#[test]
fn template_checksum_matches_generic_for_payload_offsets() {
    let (mut iface, _, _) = setup(Medium::Ethernet);
    iface.inner.caps.checksum = ChecksumCapabilities::default();
    let mut rng = ChaCha8Rng::seed_from_u64(0x8742_abcd_1234_5678);
    let mut payload = [0; 134];
    rng.fill(&mut payload[..]);
    for len in 0..=130 {
        for offset in 0..4 {
            let tcp = TcpRepr {
                src_port: 40000,
                dst_port: 80,
                control: TcpControl::Psh,
                seq_number: TcpSeqNumber(123),
                ack_number: Some(TcpSeqNumber(456)),
                window_len: 4096,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None; 3],
                timestamp: None,
                payload: &payload[offset..offset + len],
            };
            let ip = Ipv4Repr {
                src_addr: Ipv4Address::new(192, 168, 1, 1),
                dst_addr: Ipv4Address::new(192, 168, 1, 2),
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            };
            compare_template(&mut iface, ip, tcp);
        }
    }
}

// The template sums its fixed header from field values; every header field, SACK block count and
// timestamp option must give the generic emitter's bytes and checksum.
#[test]
fn template_header_checksum_matches_generic_random_fields_and_options() {
    let (mut iface, _, _) = setup(Medium::Ethernet);
    iface.inner.caps.checksum = ChecksumCapabilities::default();
    let mut rng = ChaCha8Rng::seed_from_u64(0x5eed_0f_f1e1d5);
    let mut payload = [0; 1400];
    for _ in 0..10_000 {
        let len = rng.gen_range(0..=payload.len());
        rng.fill(&mut payload[..len]);
        let blocks = rng.gen_range(0..=3);
        let tcp = TcpRepr {
            src_port: rng.gen_range(1..=u16::MAX),
            dst_port: rng.gen_range(1..=u16::MAX),
            control: [
                TcpControl::None,
                TcpControl::Psh,
                TcpControl::Fin,
                TcpControl::Rst,
            ][rng.gen_range(0..4)],
            seq_number: TcpSeqNumber(rng.r#gen()),
            ack_number: Some(TcpSeqNumber(rng.r#gen())),
            window_len: rng.r#gen(),
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: core::array::from_fn(|index| {
                (index < blocks).then(|| (rng.r#gen(), rng.r#gen()))
            }),
            timestamp: rng.r#gen::<bool>().then(|| TcpTimestampRepr {
                tsval: rng.r#gen(),
                tsecr: rng.r#gen(),
            }),
            payload: &payload[..len],
        };
        let ip = Ipv4Repr {
            src_addr: Ipv4Address::new(192, 168, 1, 1),
            dst_addr: Ipv4Address::new(192, 168, 1, 2),
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };
        compare_template(&mut iface, ip, tcp);
    }
}

#[test]
fn template_checksums_match_generic_random() {
    let (mut iface, _, _) = setup(Medium::Ethernet);
    iface.update_ip_addrs(|addrs| {
        addrs.clear();
        addrs
            .push(IpCidr::new(Ipv4Address::new(192, 168, 1, 1).into(), 0))
            .unwrap();
    });
    let mut rng = ChaCha8Rng::seed_from_u64(0x8742_abcd_1234_5678);
    let mut payload = [0; 1448];
    for _ in 0..10_000 {
        let len = rng.gen_range(0..=payload.len());
        rng.fill(&mut payload[..len]);
        let tcp = TcpRepr {
            src_port: 40000,
            dst_port: 80,
            control: TcpControl::Psh,
            seq_number: TcpSeqNumber(rng.r#gen()),
            ack_number: Some(TcpSeqNumber(rng.r#gen())),
            window_len: rng.r#gen(),
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &payload[..len],
        };
        let ip = Ipv4Repr {
            src_addr: Ipv4Address::new(192, 168, 1, 1),
            dst_addr: Ipv4Address::new(192, 168, 1, 2),
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };
        compare_template(&mut iface, ip, tcp);
    }
    let zeros = [0; 2];
    let tcp = TcpRepr {
        src_port: 40000,
        dst_port: 80,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(123),
        ack_number: Some(TcpSeqNumber(456)),
        window_len: 4096,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &zeros,
    };
    let mut ip = Ipv4Repr {
        src_addr: Ipv4Address::new(192, 168, 1, 1),
        dst_addr: Ipv4Address::new(192, 168, 0, 0),
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    let mut header = [0xa5; 20];
    ip.emit(
        &mut Ipv4Packet::new_unchecked(&mut header[..]),
        &ChecksumCapabilities::default(),
    );
    let correction = Ipv4Packet::new_unchecked(&header[..])
        .checksum()
        .to_be_bytes();
    ip.dst_addr = Ipv4Address::new(192, 168, correction[0], correction[1]);
    let frame = compare_template(&mut iface, ip, tcp);
    let packet = Ipv4Packet::new_checked(&frame[14..]).unwrap();
    assert_eq!(packet.checksum(), 0);
    assert_eq!(crate::wire::checksum::data(&frame[14..34]), 0xffff);
    let payload = TcpPacket::new_checked(packet.payload())
        .unwrap()
        .checksum()
        .to_be_bytes();
    let frame = compare_template(
        &mut iface,
        ip,
        TcpRepr {
            payload: &payload,
            ..tcp
        },
    );
    let packet = Ipv4Packet::new_checked(&frame[14..]).unwrap();
    let tcp_packet = TcpPacket::new_checked(packet.payload()).unwrap();
    assert_eq!(tcp_packet.checksum(), 0);
    assert!(tcp_packet.verify_checksum(&ip.src_addr.into(), &ip.dst_addr.into()));
}

#[test]
fn template_neighbor_errors_and_mtu_drop_match_generic() {
    let payload = [0x5a; 64];
    let tcp = TcpRepr {
        src_port: 40000,
        dst_port: 80,
        control: TcpControl::Psh,
        seq_number: TcpSeqNumber(123),
        ack_number: Some(TcpSeqNumber(456)),
        window_len: 4096,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [Some((100, 110)), None, None],
        timestamp: None,
        payload: &payload,
    };
    for (dst, mtu, known, expected) in [
        (Ipv4Address::new(192, 168, 1, 2), 1514, false, Err(DispatchError::NeighborPending)),
        (Ipv4Address::new(192, 168, 1, 2), 54, false, Err(DispatchError::NeighborPending)),
        (Ipv4Address::new(192, 168, 1, 2), 54, true, Ok(())),
        (Ipv4Address::new(198, 51, 100, 2), 1514, false, Err(DispatchError::NoRoute)),
    ] {
        let (mut direct, _, _) = setup(Medium::Ethernet);
        let (mut generic, _, _) = setup(Medium::Ethernet);
        let ip = Ipv4Repr {
            src_addr: Ipv4Address::new(192, 168, 1, 1),
            dst_addr: dst,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };
        for iface in [&mut direct, &mut generic] {
            iface.inner.caps.max_transmission_unit = mtu;
            if known {
                iface.inner.neighbor_cache.fill(
                    dst.into(), EthernetAddress([2, 0, 0, 0, 0, 2]).into(), Instant::ZERO,
                );
            }
        }
        let mut next_hop = None;
        let mut template = None;
        for attempt in 0..2 {
            let mut direct_frame = Vec::new();
            let mut generic_frame = Vec::new();
            let result = direct.inner.dispatch_tcp(
                CaptureTxToken(&mut direct_frame),
                PacketMeta::default(),
                IpRepr::Ipv4(ip),
                tcp,
                &mut next_hop,
                &mut template,
            );
            let generic_result = generic.inner.dispatch_ip(
                CaptureTxToken(&mut generic_frame),
                PacketMeta::default(),
                Packet::new_ipv4(ip, IpPayload::Tcp(tcp)),
                None,
            );
            assert_eq!(result, expected);
            assert_eq!(result, generic_result);
            assert_eq!(direct_frame, generic_frame);
            assert_eq!(direct.inner.template_frames, 0);
            if expected == Err(DispatchError::NeighborPending) && attempt == 0 {
                let ethernet = EthernetFrame::new_checked(&direct_frame).unwrap();
                assert_eq!(ethernet.ethertype(), EthernetProtocol::Arp);
                let arp = ArpRepr::parse(&ArpPacket::new_checked(ethernet.payload()).unwrap()).unwrap();
                assert!(matches!(arp, ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Request, target_protocol_addr, ..
                } if target_protocol_addr == dst));
            } else {
                assert!(direct_frame.is_empty());
            }
        }
    }
}

#[test]
fn segments_without_ack_or_with_syn_stay_generic() {
    let (mut iface, _, _) = setup(Medium::Ethernet);
    let dst = Ipv4Address::new(192, 168, 1, 2);
    iface.inner.neighbor_cache.fill(
        dst.into(), EthernetAddress([2, 0, 0, 0, 0, 2]).into(), Instant::ZERO,
    );
    let mut next_hop = None;
    let mut template = None;
    for (control, ack_number) in [
        (TcpControl::Syn, None),
        (TcpControl::Syn, Some(TcpSeqNumber(456))),
        (TcpControl::Rst, None),
    ] {
        let tcp = TcpRepr {
            src_port: 40000,
            dst_port: 80,
            control,
            seq_number: TcpSeqNumber(123),
            ack_number,
            window_len: 4096,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let ip = Ipv4Repr {
            src_addr: Ipv4Address::new(192, 168, 1, 1),
            dst_addr: dst,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };
        let mut frame = Vec::new();
        iface.inner.dispatch_tcp(
            CaptureTxToken(&mut frame), PacketMeta::default(), IpRepr::Ipv4(ip), tcp,
            &mut next_hop, &mut template,
        ).unwrap();
        assert!(template.is_some());
        assert_eq!(iface.inner.template_frames, 0);
        assert_generic_frame(&mut iface, &frame);
    }
}
