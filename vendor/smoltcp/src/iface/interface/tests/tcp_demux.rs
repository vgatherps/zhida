use super::*;
use crate::iface::SocketHandle;
use crate::socket::tcp;
use crate::tests::TestingDevice;
use crate::time::Duration;

const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
const LOCAL_PORT: u16 = 1234;
const REMOTE_PORT: u16 = 65000;
const REMOTE_SEQ: TcpSeqNumber = TcpSeqNumber(100);

fn socket() -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(tcp::RxBuffer::new(64), tcp::SocketBuffer::new(vec![0; 64]));
    socket.set_ack_delay(None);
    socket
}

fn segment(control: TcpControl, seq: TcpSeqNumber, ack: Option<TcpSeqNumber>) -> TcpRepr<'static> {
    TcpRepr {
        src_port: REMOTE_PORT,
        dst_port: LOCAL_PORT,
        control,
        seq_number: seq,
        ack_number: ack,
        window_len: 64,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    }
}

fn receive(
    iface: &mut Interface,
    sockets: &mut TcpSet,
    device: &mut TestingDevice,
    now: Instant,
    tcp: TcpRepr,
) {
    device.rx_queue.push_back(packet_bytes(tcp));
    iface.poll(now, device, sockets);
}

fn packet_bytes(tcp: TcpRepr) -> Vec<u8> {
    packet_bytes_to(tcp, LOCAL_ADDR)
}

fn packet_bytes_to(tcp: TcpRepr, dst_addr: Ipv4Address) -> Vec<u8> {
    let ip = Ipv4Repr {
        src_addr: REMOTE_ADDR,
        dst_addr,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    let mut bytes = vec![0; ip.buffer_len() + tcp.buffer_len()];
    ip.emit(
        &mut Ipv4Packet::new_unchecked(&mut bytes),
        &ChecksumCapabilities::default(),
    );
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut bytes[ip.buffer_len()..]),
        &REMOTE_ADDR.into(),
        &dst_addr.into(),
        &ChecksumCapabilities::default(),
    );
    bytes
}

#[track_caller]
fn take_reply(device: &mut TestingDevice) -> Vec<u8> {
    assert_eq!(device.tx_queue.len(), 1);
    device.tx_queue.pop_front().unwrap()
}

fn reply(bytes: &[u8]) -> TcpRepr<'_> {
    let ip = Ipv4Packet::new_checked(bytes).unwrap();
    assert!(ip.verify_checksum());
    assert_eq!(ip.src_addr(), LOCAL_ADDR);
    assert_eq!(ip.dst_addr(), REMOTE_ADDR);
    assert_eq!(ip.next_header(), IpProtocol::Tcp);
    TcpRepr::parse(
        &TcpPacket::new_checked(ip.payload()).unwrap(),
        &LOCAL_ADDR.into(),
        &REMOTE_ADDR.into(),
        &ChecksumCapabilities::default(),
    )
    .unwrap()
}

#[track_caller]
fn assert_control(tcp: &TcpRepr, port: u16, control: TcpControl, ack: Option<TcpSeqNumber>) {
    assert_eq!(tcp.src_port, port);
    assert_eq!(tcp.dst_port, REMOTE_PORT);
    assert_eq!(tcp.control, control);
    assert_eq!(tcp.ack_number, ack);
    assert!(tcp.payload.is_empty());
}

fn establish(
    iface: &mut Interface,
    sockets: &mut TcpSet<'static>,
    device: &mut TestingDevice,
) -> (SocketHandle, TcpSeqNumber) {
    establish_with_options(iface, sockets, device, REMOTE_SEQ, None)
}

fn establish_with_options(
    iface: &mut Interface,
    sockets: &mut TcpSet<'static>,
    device: &mut TestingDevice,
    peer_seq: TcpSeqNumber,
    tsval: Option<u32>,
) -> (SocketHandle, TcpSeqNumber) {
    let mut listener = socket();
    listener.listen(LOCAL_PORT).unwrap();
    let handle = sockets.add(listener);
    receive(
        iface,
        sockets,
        device,
        Instant::ZERO,
        TcpRepr {
            timestamp: tsval.map(|ts| TcpTimestampRepr::new(ts, 0)),
            ..segment(TcpControl::Syn, peer_seq, None)
        },
    );
    assert_eq!(sockets.get(handle).state(), tcp::State::SynReceived);
    let bytes = take_reply(device);
    let synack = reply(&bytes);
    assert_control(&synack, LOCAL_PORT, TcpControl::Syn, Some(peer_seq + 1));
    let local_seq = synack.seq_number + 1;
    receive(
        iface,
        sockets,
        device,
        Instant::ZERO,
        TcpRepr {
            timestamp: tsval.map(|ts| TcpTimestampRepr::new(ts, 1)),
            ..segment(TcpControl::None, peer_seq + 1, Some(local_seq))
        },
    );
    assert_eq!(sockets.get(handle).state(), tcp::State::Established);
    assert!(device.tx_queue.is_empty());
    (handle, local_seq)
}

fn duplicate_connection(sockets: &mut TcpSet<'static>, local_seq: TcpSeqNumber) -> SocketHandle {
    let (mut iface, mut other_sockets, mut device) = setup(Medium::Ip);
    let (handle, other_seq) = establish(&mut iface, &mut other_sockets, &mut device);
    assert_eq!(other_seq, local_seq);
    let (socket, _) = other_sockets.take(handle);
    sockets.add(socket)
}

fn active_sequence() -> TcpSeqNumber {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let mut active = socket();
    active
        .connect(
            iface.context(),
            (REMOTE_ADDR, REMOTE_PORT),
            (LOCAL_ADDR, LOCAL_PORT),
        )
        .unwrap();
    sockets.add(active);
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    let bytes = take_reply(&mut device);
    let syn = reply(&bytes);
    assert_control(&syn, LOCAL_PORT, TcpControl::Syn, None);
    syn.seq_number
}

#[test]
fn ingress_syncs_app_listeners_and_rekeys_after_each_syn() {
    for entry in ["batch", "single", "udp_single"] {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        let handles: Vec<_> = (0..2).map(|_| sockets.add(socket())).collect();
        for &handle in &handles {
            sockets.get_mut(handle).listen(LOCAL_PORT).unwrap();
        }
        let syn = segment(TcpControl::Syn, REMOTE_SEQ, None);
        for port in [REMOTE_PORT, REMOTE_PORT + 1] {
            device.rx_queue.push_back(packet_bytes(TcpRepr {
                src_port: port,
                ..syn
            }));
        }
        if entry == "batch" {
            iface.poll(Instant::ZERO, &mut device, &mut sockets);
        } else {
            for _ in 0..2 {
                let result = if entry == "single" {
                    iface.poll_ingress_single(Instant::ZERO, &mut device, &mut sockets)
                } else {
                    #[cfg(feature = "udp-set")]
                    {
                        let mut udp = crate::iface::UdpSet::new(0);
                        iface.poll_ingress_single_udp(
                            Instant::ZERO, &mut device, &mut sockets, &mut udp,
                        )
                    }
                    #[cfg(not(feature = "udp-set"))]
                    continue;
                };
                assert_eq!(result, PollIngressSingleResult::SocketStateChanged);
                assert_eq!(sockets.classify_calls, 0);
            }
            #[cfg(not(feature = "udp-set"))]
            if entry == "udp_single" {
                continue;
            }
            assert_eq!(sockets.dirty_list, vec![0, 1]);
            iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
        }
        assert!(device.rx_queue.is_empty());
        assert_eq!(sockets.dispatches, vec![0, 1]);
        assert_eq!(device.tx_queue.len(), 2);
        for (index, port) in [REMOTE_PORT, REMOTE_PORT + 1].into_iter().enumerate() {
            let bytes = device.tx_queue.pop_front().unwrap();
            let tcp = reply(&bytes);
            assert_eq!((tcp.src_port, tcp.dst_port), (LOCAL_PORT, port));
            assert_eq!(tcp.control, TcpControl::Syn);
            assert_eq!(tcp.ack_number, Some(REMOTE_SEQ + 1));
            assert!(tcp.payload.is_empty());
            assert_eq!(sockets.get(handles[index]).state(), tcp::State::SynReceived);
            assert_eq!(sockets.get(handles[index]).remote_endpoint().unwrap().port, port);
        }
    }
}

#[test]
fn ingress_keeps_commit_in_set_and_poll_attaches_payload() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, local_seq) = establish(&mut iface, &mut sockets, &mut device);
    let frame = crate::phy::RxBuf::from_vec(packet_bytes(TcpRepr {
        payload: b"abc",
        ..segment(TcpControl::None, REMOTE_SEQ + 1, Some(local_seq))
    }));
    {
        let packet = Ipv4Packet::new_checked(frame.as_slice()).unwrap();
        let ip = Ipv4Repr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
        let response = iface.inner.process_tcp(
            &mut sockets,
            PacketMeta::default(),
            IpRepr::Ipv4(ip),
            packet.payload(),
        );
        assert!(response.is_none());
    }
    assert!(sockets.pending_rx_attach.is_some());
    assert_eq!(sockets.get(handle).recv_queue(), 3);
    let (index, pending) = sockets.pending_rx_attach.take().unwrap();
    sockets
        .item_at_mut(index)
        .unwrap()
        .socket
        .commit_rx(frame, pending);
    let mut bytes = Vec::new();
    while let Some(frame) = sockets.get_mut(handle).recv().unwrap() {
        bytes.extend_from_slice(frame.payload());
    }
    assert_eq!(bytes.len(), 3);
    assert_eq!(&bytes, b"abc");

    device.rx_queue.push_back(packet_bytes(TcpRepr {
        payload: b"def",
        ..segment(TcpControl::None, REMOTE_SEQ + 4, Some(local_seq))
    }));
    assert_eq!(
        iface.poll_ingress_single(Instant::ZERO, &mut device, &mut sockets),
        PollIngressSingleResult::SocketStateChanged,
    );
    assert!(sockets.pending_rx_attach.is_none());
    let frame = sockets.get_mut(handle).recv().unwrap().unwrap();
    let bytes = frame.payload();
    assert_eq!(bytes.len(), 3);
    assert_eq!(&bytes, b"def");
}

#[test]
fn ingress_commits_payload_after_reply_dispatch() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, local_seq) = establish(&mut iface, &mut sockets, &mut device);
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        TcpRepr {
            payload: b"def",
            ..segment(TcpControl::None, REMOTE_SEQ + 4, Some(local_seq))
        },
    );
    let bytes = take_reply(&mut device);
    assert!(sockets.pending_rx_attach.is_none());
    assert_control(
        &reply(&bytes),
        LOCAL_PORT,
        TcpControl::None,
        Some(REMOTE_SEQ + 1),
    );

    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        TcpRepr {
            payload: b"abc",
            ..segment(TcpControl::None, REMOTE_SEQ + 1, Some(local_seq))
        },
    );
    let bytes = take_reply(&mut device);
    assert!(sockets.pending_rx_attach.is_none());
    assert_control(
        &reply(&bytes),
        LOCAL_PORT,
        TcpControl::None,
        Some(REMOTE_SEQ + 7),
    );
    let socket = sockets.get_mut(handle);
    assert_eq!(
        socket.recv().map(|frame| frame.unwrap().payload().to_vec()),
        Ok(b"abc".to_vec())
    );
    assert_eq!(socket.recv_queue(), 3);
    assert_eq!(
        socket.recv().map(|frame| frame.unwrap().payload().to_vec()),
        Ok(b"def".to_vec())
    );
    assert_eq!(socket.recv_queue(), 0);
}

#[track_caller]
fn receive_data(
    iface: &mut Interface,
    sockets: &mut TcpSet,
    device: &mut TestingDevice,
    now: Instant,
    handle: SocketHandle,
    local_seq: TcpSeqNumber,
) {
    receive(
        iface,
        sockets,
        device,
        now,
        TcpRepr {
            payload: b"abc",
            ..segment(TcpControl::Psh, REMOTE_SEQ + 1, Some(local_seq))
        },
    );
    let mut data = Vec::new();
    while let Some(frame) = sockets.get_mut(handle).recv().unwrap() {
        data.extend_from_slice(frame.payload());
    }
    assert_eq!(data.len(), 3);
    assert_eq!(&data, b"abc");
}

#[track_caller]
fn assert_data_received(
    iface: &mut Interface,
    sockets: &mut TcpSet,
    device: &mut TestingDevice,
    now: Instant,
    handle: SocketHandle,
    local_seq: TcpSeqNumber,
) {
    receive_data(iface, sockets, device, now, handle, local_seq);
    assert_eq!(sockets.get(handle).state(), tcp::State::Established);
    let bytes = take_reply(device);
    assert_control(
        &reply(&bytes),
        LOCAL_PORT,
        TcpControl::None,
        Some(REMOTE_SEQ + 4),
    );
}

#[test]
fn two_listeners_lowest_slot_takes_syn() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let mut first = socket();
    first.listen(LOCAL_PORT).unwrap();
    let first = sockets.add(first);
    let mut second = socket();
    second.listen(LOCAL_PORT).unwrap();
    let second = sockets.add(second);

    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        segment(TcpControl::Syn, REMOTE_SEQ, None),
    );
    assert_eq!(sockets.get(first).state(), tcp::State::SynReceived);
    assert_eq!(sockets.get(second).state(), tcp::State::Listen);
    let bytes = take_reply(&mut device);
    assert_control(
        &reply(&bytes),
        LOCAL_PORT,
        TcpControl::Syn,
        Some(REMOTE_SEQ + 1),
    );

    let first_seq = reply(&bytes).seq_number + 1;
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        TcpRepr {
            src_port: REMOTE_PORT + 1,
            ..segment(TcpControl::Syn, REMOTE_SEQ, None)
        },
    );
    assert_eq!(sockets.get(first).state(), tcp::State::SynReceived);
    assert_eq!(sockets.get(second).state(), tcp::State::SynReceived);
    let bytes = take_reply(&mut device);
    let synack = reply(&bytes);
    assert_eq!(synack.dst_port, REMOTE_PORT + 1);
    assert_eq!(synack.control, TcpControl::Syn);
    assert_eq!(synack.ack_number, Some(REMOTE_SEQ + 1));

    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        segment(TcpControl::None, REMOTE_SEQ + 1, Some(first_seq)),
    );
    assert_eq!(sockets.get(first).state(), tcp::State::Established);
    assert_eq!(sockets.get(second).state(), tcp::State::SynReceived);
    assert!(device.tx_queue.is_empty());
    assert_data_received(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        first,
        first_seq,
    );
    assert_eq!(sockets.get(second).recv_queue(), 0);
}

#[test]
fn syn_to_port_zero_is_dropped_with_wildcard_listener() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let mut listener = socket();
    assert_eq!(listener.listen(0), Err(tcp::ListenError::Unaddressable));
    listener.listen(LOCAL_PORT).unwrap();
    let handle = sockets.add(listener);

    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        TcpRepr {
            dst_port: 0,
            ..segment(TcpControl::Syn, REMOTE_SEQ, None)
        },
    );
    assert!(device.rx_queue.is_empty());
    assert!(device.tx_queue.is_empty());
    assert_eq!(sockets.get(handle).state(), tcp::State::Listen);
    assert_eq!(sockets.get(handle).recv_queue(), 0);
}

#[test]
fn duplicate_exact_tuple_lowest_slot() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let mut first = socket();
    first
        .connect(
            iface.context(),
            (REMOTE_ADDR, REMOTE_PORT),
            (LOCAL_ADDR, LOCAL_PORT),
        )
        .unwrap();
    let first = sockets.add(first);
    let mut second = socket();
    second
        .connect(
            iface.context(),
            (REMOTE_ADDR, REMOTE_PORT),
            (LOCAL_ADDR, LOCAL_PORT),
        )
        .unwrap();
    let second = sockets.add(second);
    assert_eq!(sockets.get(first).state(), tcp::State::SynSent);
    assert_eq!(sockets.get(second).state(), tcp::State::SynSent);
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(device.tx_queue.len(), 2);
    let first_syn = device.tx_queue.pop_front().unwrap();
    let second_syn = device.tx_queue.pop_front().unwrap();
    assert_control(&reply(&first_syn), LOCAL_PORT, TcpControl::Syn, None);
    assert_control(&reply(&second_syn), LOCAL_PORT, TcpControl::Syn, None);
    assert_eq!(reply(&first_syn).seq_number, reply(&second_syn).seq_number);
    let local_seq = reply(&first_syn).seq_number + 1;

    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        segment(TcpControl::Syn, REMOTE_SEQ, Some(local_seq)),
    );
    assert_eq!(sockets.get(first).state(), tcp::State::Established);
    assert_eq!(sockets.get(second).state(), tcp::State::SynSent);
    let bytes = take_reply(&mut device);
    assert_control(
        &reply(&bytes),
        LOCAL_PORT,
        TcpControl::None,
        Some(REMOTE_SEQ + 1),
    );

    assert_data_received(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        first,
        local_seq,
    );
    assert_eq!(sockets.get(second).recv_queue(), 0);
    assert_eq!(sockets.get(second).state(), tcp::State::SynSent);
}

#[test]
fn fast_path_follows_group_head_changes() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let empty = sockets.add(socket());
    let (first, local_seq) = establish(&mut iface, &mut sockets, &mut device);
    let second = duplicate_connection(&mut sockets, local_seq);
    for _ in 0..2 {
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::ZERO,
            segment(TcpControl::None, REMOTE_SEQ + 1, Some(local_seq)),
        );
        assert!(device.tx_queue.is_empty());
    }

    sockets.remove(empty);
    let head = duplicate_connection(&mut sockets, local_seq);
    assert_data_received(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        head,
        local_seq,
    );
    assert_eq!(sockets.get(first).recv_queue(), 0);
    assert_eq!(sockets.get(second).recv_queue(), 0);

    sockets.remove(head);
    assert_data_received(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        first,
        local_seq,
    );
    assert_eq!(sockets.get(second).recv_queue(), 0);
}

#[test]
fn cached_exact_tuple_challenges_syn_before_lower_listener() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let empty = sockets.add(socket());
    let (exact, local_seq) = establish(&mut iface, &mut sockets, &mut device);
    sockets.remove(empty);
    let mut listener = socket();
    listener.listen(LOCAL_PORT).unwrap();
    let listener = sockets.add(listener);
    for _ in 0..2 {
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::ZERO,
            segment(TcpControl::None, REMOTE_SEQ + 1, Some(local_seq)),
        );
        assert!(device.tx_queue.is_empty());
    }

    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        segment(TcpControl::Syn, REMOTE_SEQ, None),
    );
    assert_eq!(sockets.get(listener).state(), tcp::State::Listen);
    assert_eq!(sockets.get(exact).state(), tcp::State::Established);
    let bytes = take_reply(&mut device);
    assert_control(
        &reply(&bytes),
        LOCAL_PORT,
        TcpControl::None,
        Some(REMOTE_SEQ + 1),
    );
}

#[test]
fn alternating_established_tuples_use_their_own_slots() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (first, first_seq) = establish(&mut iface, &mut sockets, &mut device);
    let mut listener = socket();
    listener.listen(LOCAL_PORT).unwrap();
    let second = sockets.add(listener);
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        TcpRepr {
            src_port: REMOTE_PORT + 1,
            ..segment(TcpControl::Syn, REMOTE_SEQ, None)
        },
    );
    assert_eq!(sockets.get(second).state(), tcp::State::SynReceived);
    let bytes = take_reply(&mut device);
    let synack = reply(&bytes);
    assert_eq!(synack.dst_port, REMOTE_PORT + 1);
    assert_eq!(synack.control, TcpControl::Syn);
    let second_seq = synack.seq_number + 1;
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        TcpRepr {
            src_port: REMOTE_PORT + 1,
            ..segment(TcpControl::None, REMOTE_SEQ + 1, Some(second_seq))
        },
    );
    assert_eq!(sockets.get(first).state(), tcp::State::Established);
    assert_eq!(sockets.get(second).state(), tcp::State::Established);
    assert!(device.tx_queue.is_empty());

    for offset in 0..2 {
        for (handle, other, port, local_seq, payload) in [
            (first, second, REMOTE_PORT, first_seq, &b"a"[..]),
            (second, first, REMOTE_PORT + 1, second_seq, &b"b"[..]),
        ] {
            let other_len = sockets.get(other).recv_queue();
            receive(
                &mut iface,
                &mut sockets,
                &mut device,
                Instant::ZERO,
                TcpRepr {
                    src_port: port,
                    payload,
                    ..segment(TcpControl::Psh, REMOTE_SEQ + 1 + offset, Some(local_seq))
                },
            );
            assert_eq!(sockets.get(handle).recv_queue(), offset + 1);
            assert_eq!(sockets.get(other).recv_queue(), other_len);
            let bytes = take_reply(&mut device);
            let ack = reply(&bytes);
            assert_eq!(ack.dst_port, port);
            assert_eq!(ack.control, TcpControl::None);
            assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 2 + offset));
        }
    }
    for (handle, expected) in [(first, b"aa"), (second, b"bb")] {
        let mut data = Vec::new();
        while let Some(frame) = sockets.get_mut(handle).recv().unwrap() {
            data.extend_from_slice(frame.payload());
        }
        assert_eq!(data.len(), 2);
        assert_eq!(&data, expected);
    }
}

#[test]
fn egress_after_get_mut_change_without_ingress() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let handle = sockets.add(socket());
    sockets
        .get_mut(handle)
        .connect(
            iface.context(),
            (REMOTE_ADDR, REMOTE_PORT),
            (LOCAL_ADDR, LOCAL_PORT),
        )
        .unwrap();
    assert!(device.rx_queue.is_empty());
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(sockets.get(handle).state(), tcp::State::SynSent);
    sockets.check_flow_index();
    let bytes = take_reply(&mut device);
    let syn = reply(&bytes);
    assert_control(&syn, LOCAL_PORT, TcpControl::Syn, None);
    let local_seq = syn.seq_number + 1;

    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::from_millis(1),
        segment(TcpControl::Syn, REMOTE_SEQ, Some(local_seq)),
    );
    assert_eq!(sockets.get(handle).state(), tcp::State::Established);
    let bytes = take_reply(&mut device);
    assert_control(
        &reply(&bytes),
        LOCAL_PORT,
        TcpControl::None,
        Some(REMOTE_SEQ + 1),
    );
    assert_data_received(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::from_millis(1),
        handle,
        local_seq,
    );
}

#[test]
fn get_mut_connect_receives_synack_next_poll() {
    let initial_seq = active_sequence();
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let handle = sockets.add(socket());
    assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert!(device.tx_queue.is_empty());

    sockets
        .get_mut(handle)
        .connect(
            iface.context(),
            (REMOTE_ADDR, REMOTE_PORT),
            (LOCAL_ADDR, LOCAL_PORT),
        )
        .unwrap();
    assert_eq!(sockets.get(handle).state(), tcp::State::SynSent);
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::from_millis(1),
        segment(TcpControl::Syn, REMOTE_SEQ, Some(initial_seq + 1)),
    );
    assert_eq!(sockets.get(handle).state(), tcp::State::Established);
    let bytes = take_reply(&mut device);
    let ack = reply(&bytes);
    assert_control(&ack, LOCAL_PORT, TcpControl::None, Some(REMOTE_SEQ + 1));
    assert_eq!(ack.seq_number, initial_seq + 1);
}

#[track_caller]
fn assert_old_tuple_rst(
    iface: &mut Interface,
    sockets: &mut TcpSet,
    device: &mut TestingDevice,
    now: Instant,
    peer_seq: TcpSeqNumber,
    local_seq: TcpSeqNumber,
) {
    receive(
        iface,
        sockets,
        device,
        now,
        segment(TcpControl::None, peer_seq, Some(local_seq)),
    );
    let bytes = take_reply(device);
    let rst = reply(&bytes);
    assert_control(&rst, LOCAL_PORT, TcpControl::Rst, None);
    assert_eq!(rst.seq_number, local_seq);
    assert_eq!(rst.window_len, 0);
}

#[track_caller]
fn assert_listener_receives_syn(
    iface: &mut Interface,
    sockets: &mut TcpSet,
    device: &mut TestingDevice,
    handle: SocketHandle,
    port: u16,
) {
    assert_eq!(sockets.get(handle).state(), tcp::State::Listen);
    receive(
        iface,
        sockets,
        device,
        Instant::ZERO,
        TcpRepr {
            dst_port: port,
            ..segment(TcpControl::Syn, REMOTE_SEQ, None)
        },
    );
    assert_eq!(sockets.get(handle).state(), tcp::State::SynReceived);
    let bytes = take_reply(device);
    assert_control(&reply(&bytes), port, TcpControl::Syn, Some(REMOTE_SEQ + 1));
}

#[test]
fn index_follows_socket_lifecycle() {
    // 1. A reset returns a passive SYN-RECEIVED socket to LISTEN.
    {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        let mut listener = socket();
        listener.listen(LOCAL_PORT).unwrap();
        let handle = sockets.add(listener);
        assert_listener_receives_syn(&mut iface, &mut sockets, &mut device, handle, LOCAL_PORT);
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::ZERO,
            segment(TcpControl::Rst, REMOTE_SEQ + 1, None),
        );
        assert_eq!(sockets.get(handle).state(), tcp::State::Listen);
        assert!(device.tx_queue.is_empty());
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::ZERO,
            TcpRepr {
                src_port: REMOTE_PORT + 1,
                ..segment(TcpControl::Syn, REMOTE_SEQ, None)
            },
        );
        assert_eq!(sockets.get(handle).state(), tcp::State::SynReceived);
        let bytes = take_reply(&mut device);
        let synack = reply(&bytes);
        assert_eq!(synack.src_port, LOCAL_PORT);
        assert_eq!(synack.dst_port, REMOTE_PORT + 1);
        assert_eq!(synack.control, TcpControl::Syn);
        assert_eq!(synack.ack_number, Some(REMOTE_SEQ + 1));
        assert!(synack.payload.is_empty());
        let local_seq = synack.seq_number + 1;
        assert_old_tuple_rst(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::ZERO,
            REMOTE_SEQ + 1,
            local_seq,
        );
        assert_eq!(sockets.get(handle).state(), tcp::State::SynReceived);
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::ZERO,
            TcpRepr {
                src_port: REMOTE_PORT + 1,
                payload: b"abc",
                ..segment(TcpControl::Psh, REMOTE_SEQ + 1, Some(local_seq))
            },
        );
        assert_eq!(sockets.get(handle).state(), tcp::State::Established);
        let mut data = Vec::new();
        while let Some(frame) = sockets.get_mut(handle).recv().unwrap() {
            data.extend_from_slice(frame.payload());
        }
        assert_eq!(data.len(), 3);
        assert_eq!(&data, b"abc");
        let bytes = take_reply(&mut device);
        let ack = reply(&bytes);
        assert_eq!(ack.dst_port, REMOTE_PORT + 1);
        assert_eq!(ack.control, TcpControl::None);
        assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 4));
    }

    // 2. An ACK of the LAST-ACK socket's FIN closes it.
    {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        let (handle, local_seq) = establish(&mut iface, &mut sockets, &mut device);
        let survivor = duplicate_connection(&mut sockets, local_seq);
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::ZERO,
            segment(TcpControl::Fin, REMOTE_SEQ + 1, Some(local_seq)),
        );
        assert_eq!(sockets.get(handle).state(), tcp::State::CloseWait);
        let bytes = take_reply(&mut device);
        assert_control(
            &reply(&bytes),
            LOCAL_PORT,
            TcpControl::None,
            Some(REMOTE_SEQ + 2),
        );
        sockets.get_mut(handle).close();
        assert_eq!(sockets.get(handle).state(), tcp::State::LastAck);
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::ZERO,
            segment(TcpControl::None, REMOTE_SEQ + 2, Some(local_seq)),
        );
        assert_eq!(sockets.get(handle).state(), tcp::State::LastAck);
        assert_eq!(sockets.get(survivor).recv_queue(), 0);
        assert_eq!(device.tx_queue.len(), 1);
        let bytes = take_reply(&mut device);
        let fin = reply(&bytes);
        assert_control(&fin, LOCAL_PORT, TcpControl::Fin, Some(REMOTE_SEQ + 2));
        assert_eq!(fin.seq_number, local_seq);
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::ZERO,
            segment(TcpControl::None, REMOTE_SEQ + 2, Some(fin.seq_number + 1)),
        );
        assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
        assert!(device.tx_queue.is_empty());
        assert_data_received(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::ZERO,
            survivor,
            local_seq,
        );
        assert_eq!(sockets.get(handle).recv_queue(), 0);
        sockets.remove(survivor);
        assert_old_tuple_rst(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::ZERO,
            REMOTE_SEQ + 2,
            local_seq + 1,
        );
        assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
    }

    // 3. Polling past the TIME-WAIT timer closes the socket.
    {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        let (handle, local_seq) = establish(&mut iface, &mut sockets, &mut device);
        let survivor = duplicate_connection(&mut sockets, local_seq);
        sockets.get_mut(handle).close();
        assert_eq!(sockets.get(handle).state(), tcp::State::FinWait1);
        receive_data(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::ZERO,
            handle,
            local_seq,
        );
        assert_eq!(sockets.get(handle).state(), tcp::State::FinWait1);
        assert_eq!(sockets.get(survivor).recv_queue(), 0);
        let bytes = take_reply(&mut device);
        let fin = reply(&bytes);
        assert_control(&fin, LOCAL_PORT, TcpControl::Fin, Some(REMOTE_SEQ + 4));
        assert_eq!(fin.seq_number, local_seq);
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::ZERO,
            segment(TcpControl::Fin, REMOTE_SEQ + 4, Some(fin.seq_number + 1)),
        );
        assert_eq!(sockets.get(handle).state(), tcp::State::TimeWait);
        let bytes = take_reply(&mut device);
        assert_control(
            &reply(&bytes),
            LOCAL_PORT,
            TcpControl::None,
            Some(REMOTE_SEQ + 5),
        );
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::from_millis(1),
            segment(TcpControl::Fin, REMOTE_SEQ + 4, Some(local_seq + 1)),
        );
        let bytes = take_reply(&mut device);
        assert_control(
            &reply(&bytes),
            LOCAL_PORT,
            TcpControl::None,
            Some(REMOTE_SEQ + 5),
        );
        assert_eq!(sockets.get(handle).state(), tcp::State::TimeWait);
        assert_eq!(sockets.get(survivor).state(), tcp::State::Established);
        iface.poll(Instant::from_millis(10_002), &mut device, &mut sockets);
        assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
        assert!(device.tx_queue.is_empty());
        assert_data_received(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::from_millis(10_003),
            survivor,
            local_seq,
        );
        assert_eq!(sockets.get(handle).recv_queue(), 0);
        sockets.remove(survivor);
        assert_old_tuple_rst(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::from_millis(10_004),
            REMOTE_SEQ + 5,
            local_seq + 1,
        );
        assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
    }

    // 4. Aborting an established socket sends a reset and closes it.
    {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        let (handle, local_seq) = establish(&mut iface, &mut sockets, &mut device);
        let survivor = duplicate_connection(&mut sockets, local_seq);
        sockets.get_mut(handle).abort();
        assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
        receive_data(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::ZERO,
            survivor,
            local_seq,
        );
        assert_eq!(sockets.get(survivor).state(), tcp::State::Established);
        assert_eq!(device.tx_queue.len(), 2);
        let bytes = device.tx_queue.pop_front().unwrap();
        let rst = reply(&bytes);
        assert_control(&rst, LOCAL_PORT, TcpControl::Rst, Some(REMOTE_SEQ + 1));
        assert_eq!(rst.seq_number, local_seq);
        let bytes = take_reply(&mut device);
        assert_control(
            &reply(&bytes),
            LOCAL_PORT,
            TcpControl::None,
            Some(REMOTE_SEQ + 4),
        );
        assert_eq!(sockets.get(handle).recv_queue(), 0);
        sockets.remove(survivor);
        assert_old_tuple_rst(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::ZERO,
            REMOTE_SEQ + 1,
            local_seq,
        );
        assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
    }

    // 5. Removing a socket lets the same tuple or another port reuse its slot.
    {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        let (handle, local_seq) = establish(&mut iface, &mut sockets, &mut device);
        sockets.remove(handle);
        let replacement = duplicate_connection(&mut sockets, local_seq);
        assert_data_received(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::ZERO,
            replacement,
            local_seq,
        );
        sockets.remove(replacement);
        let mut other = socket();
        other.listen(LOCAL_PORT + 1).unwrap();
        let replacement = sockets.add(other);
        assert_listener_receives_syn(
            &mut iface,
            &mut sockets,
            &mut device,
            replacement,
            LOCAL_PORT + 1,
        );
        assert_old_tuple_rst(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::ZERO,
            REMOTE_SEQ + 1,
            local_seq,
        );
    }

    // 6. Replacing the whole socket changes which port receives SYNs.
    {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        let (handle, local_seq) = establish(&mut iface, &mut sockets, &mut device);
        let mut other = socket();
        other.listen(LOCAL_PORT + 1).unwrap();
        *sockets.get_mut(handle) = other;
        assert_listener_receives_syn(
            &mut iface,
            &mut sockets,
            &mut device,
            handle,
            LOCAL_PORT + 1,
        );
        assert_old_tuple_rst(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::ZERO,
            REMOTE_SEQ + 1,
            local_seq,
        );
    }
}

#[test]
fn precedence_across_match_classes() {
    for bound_first in [false, true] {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        let mut wildcard = socket();
        wildcard.listen(LOCAL_PORT).unwrap();
        let mut bound = socket();
        bound.listen((LOCAL_ADDR, LOCAL_PORT)).unwrap();
        let (first, second) = if bound_first {
            (sockets.add(bound), sockets.add(wildcard))
        } else {
            (sockets.add(wildcard), sockets.add(bound))
        };
        assert_listener_receives_syn(&mut iface, &mut sockets, &mut device, first, LOCAL_PORT);
        assert_eq!(sockets.get(second).state(), tcp::State::Listen);
    }

    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let listener = sockets.add(socket());
    let (connected, local_seq) = establish(&mut iface, &mut sockets, &mut device);
    sockets.get_mut(listener).listen(LOCAL_PORT).unwrap();
    assert_data_received(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        connected,
        local_seq,
    );
    assert_eq!(sockets.get(listener).state(), tcp::State::Listen);
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        TcpRepr {
            src_port: REMOTE_PORT + 1,
            ..segment(TcpControl::Syn, REMOTE_SEQ, None)
        },
    );
    assert_eq!(sockets.get(listener).state(), tcp::State::SynReceived);
    assert_eq!(sockets.get(connected).state(), tcp::State::Established);
    assert_eq!(sockets.get(connected).recv_queue(), 0);
    let bytes = take_reply(&mut device);
    let synack = reply(&bytes);
    assert_eq!(synack.dst_port, REMOTE_PORT + 1);
    assert_eq!(synack.control, TcpControl::Syn);
    assert_eq!(synack.ack_number, Some(REMOTE_SEQ + 1));
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        TcpRepr {
            src_port: REMOTE_PORT + 2,
            ..segment(TcpControl::Rst, REMOTE_SEQ, None)
        },
    );
    assert!(device.tx_queue.is_empty());
    assert_eq!(sockets.get(listener).state(), tcp::State::SynReceived);
    assert_eq!(sockets.get(connected).state(), tcp::State::Established);
}

#[test]
fn exact_tuple_takes_syn_before_lower_listener() {
    for bound in [false, true] {
        for exact_first in [false, true] {
            let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
            let mut listener = socket();
            if bound {
                listener.listen((LOCAL_ADDR, LOCAL_PORT)).unwrap();
            } else {
                listener.listen(LOCAL_PORT).unwrap();
            }
            let mut exact = socket();
            exact
                .connect(
                    iface.context(),
                    (REMOTE_ADDR, REMOTE_PORT),
                    (LOCAL_ADDR, LOCAL_PORT),
                )
                .unwrap();
            let (first, second) = if exact_first {
                (sockets.add(exact), sockets.add(listener))
            } else {
                (sockets.add(listener), sockets.add(exact))
            };
            iface.poll(Instant::ZERO, &mut device, &mut sockets);
            let bytes = take_reply(&mut device);
            assert_control(&reply(&bytes), LOCAL_PORT, TcpControl::Syn, None);

            receive(
                &mut iface,
                &mut sockets,
                &mut device,
                Instant::ZERO,
                segment(TcpControl::Syn, REMOTE_SEQ, None),
            );
            let (exact, listener) = if exact_first {
                (first, second)
            } else {
                (second, first)
            };
            assert_eq!(sockets.get(exact).state(), tcp::State::SynReceived);
            assert_eq!(sockets.get(listener).state(), tcp::State::Listen);
            let bytes = take_reply(&mut device);
            let synack = reply(&bytes);
            assert_control(&synack, LOCAL_PORT, TcpControl::Syn, Some(REMOTE_SEQ + 1));
            assert_data_received(
                &mut iface,
                &mut sockets,
                &mut device,
                Instant::ZERO,
                exact,
                synack.seq_number + 1,
            );
            assert_eq!(sockets.get(listener).recv_queue(), 0);
        }
    }
}

#[test]
fn exact_syn_received_resends_identical_synack_before_lower_listener() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let lower = sockets.add(socket());
    let mut exact = socket();
    exact.listen(LOCAL_PORT).unwrap();
    let exact = sockets.add(exact);
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        segment(TcpControl::Syn, REMOTE_SEQ, None),
    );
    let original = take_reply(&mut device);
    sockets.get_mut(lower).listen(LOCAL_PORT).unwrap();
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::from_millis(1),
        segment(TcpControl::Syn, REMOTE_SEQ, None),
    );
    assert_eq!(sockets.get(lower).state(), tcp::State::Listen);
    assert_eq!(sockets.get(exact).state(), tcp::State::SynReceived);
    let resent = take_reply(&mut device);
    assert_eq!(reply(&resent), reply(&original));
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::from_millis(1),
        segment(TcpControl::None, REMOTE_SEQ + 1, Some(reply(&resent).seq_number + 1)),
    );
    assert_eq!(sockets.get(exact).state(), tcp::State::Established);
    assert_eq!(sockets.get(lower).state(), tcp::State::Listen);
    assert!(device.tx_queue.is_empty());
}

#[test]
fn exact_established_challenges_syn_before_lower_listener() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let lower = sockets.add(socket());
    let (exact, local_seq) = establish(&mut iface, &mut sockets, &mut device);
    sockets.get_mut(lower).listen(LOCAL_PORT).unwrap();
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::from_millis(1),
        segment(TcpControl::Syn, REMOTE_SEQ, None),
    );
    assert_eq!(sockets.get(lower).state(), tcp::State::Listen);
    assert_eq!(sockets.get(exact).state(), tcp::State::Established);
    let bytes = take_reply(&mut device);
    let ack = reply(&bytes);
    assert_control(&ack, LOCAL_PORT, TcpControl::None, Some(REMOTE_SEQ + 1));
    assert_eq!(ack.seq_number, local_seq);
    assert_data_received(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::from_millis(2),
        exact,
        local_seq,
    );
}

fn enter_time_wait(
    iface: &mut Interface,
    sockets: &mut TcpSet<'static>,
    device: &mut TestingDevice,
    peer_seq: TcpSeqNumber,
    tsval: Option<u32>,
) -> (SocketHandle, TcpSeqNumber) {
    let (exact, local_seq) = establish_with_options(iface, sockets, device, peer_seq, tsval);
    sockets.get_mut(exact).close();
    iface.poll(Instant::ZERO, device, sockets);
    let bytes = take_reply(device);
    assert_control(&reply(&bytes), LOCAL_PORT, TcpControl::Fin, Some(peer_seq + 1));
    receive(
        iface,
        sockets,
        device,
        Instant::ZERO,
        TcpRepr {
            timestamp: tsval.map(|ts| TcpTimestampRepr::new(ts, 1)),
            ..segment(TcpControl::Fin, peer_seq + 1, Some(local_seq + 1))
        },
    );
    assert_eq!(sockets.get(exact).state(), tcp::State::TimeWait);
    let bytes = take_reply(device);
    assert_control(&reply(&bytes), LOCAL_PORT, TcpControl::None, Some(peer_seq + 2));
    (exact, local_seq + 1)
}

#[test]
fn time_wait_reopens_on_higher_sequence_only() {
    for (seq, tsval, reopens) in [
        (REMOTE_SEQ + 1, 11, false),
        (REMOTE_SEQ + 2, 11, false),
        (REMOTE_SEQ + 3, 9, true),
    ] {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        let (exact, local_seq) =
            enter_time_wait(&mut iface, &mut sockets, &mut device, REMOTE_SEQ, Some(10));
        let mut listener = socket();
        listener.listen(LOCAL_PORT).unwrap();
        let listener = sockets.add(listener);
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::from_millis(1),
            TcpRepr {
                timestamp: Some(TcpTimestampRepr::new(tsval, 0)),
                ..segment(TcpControl::Syn, seq, None)
            },
        );
        let bytes = take_reply(&mut device);
        let response = reply(&bytes);
        if reopens {
            assert_eq!(sockets.get(exact).state(), tcp::State::Closed);
            assert_eq!(sockets.get(listener).state(), tcp::State::SynReceived);
            assert_control(&response, LOCAL_PORT, TcpControl::Syn, Some(seq + 1));
        } else {
            assert_eq!(sockets.get(exact).state(), tcp::State::TimeWait);
            assert_eq!(sockets.get(listener).state(), tcp::State::Listen);
            assert_control(&response, LOCAL_PORT, TcpControl::None, Some(REMOTE_SEQ + 2));
            assert_eq!(response.seq_number, local_seq);
        }
        assert_eq!(response.timestamp, None);
        sockets.check_flow_index();
    }
}

#[test]
fn time_wait_reopen_clears_cached_close_deadline() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (exact, _) = enter_time_wait(&mut iface, &mut sockets, &mut device, REMOTE_SEQ, None);
    assert_eq!(sockets.slot_count(), 1);
    let close_deadline = Instant::from_millis(10_000);
    let wake = iface.poll_at(Instant::ZERO, &mut sockets).unwrap();
    assert!(wake > Instant::ZERO && wake <= close_deadline);
    assert!(!sockets.deadline_due(0, close_deadline - Duration::from_millis(1)));
    assert!(sockets.deadline_due(0, close_deadline));

    let mut listener = socket();
    listener.listen(LOCAL_PORT).unwrap();
    let listener = sockets.add(listener);
    assert_eq!(sockets.slot_count(), 2);
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::from_millis(1),
        segment(TcpControl::Syn, REMOTE_SEQ + 3, None),
    );
    assert_eq!(sockets.get(exact).state(), tcp::State::Closed);
    assert_eq!(sockets.get(listener).state(), tcp::State::SynReceived);
    let bytes = take_reply(&mut device);
    assert_control(&reply(&bytes), LOCAL_PORT, TcpControl::Syn, Some(REMOTE_SEQ + 4));
    assert_eq!(sockets.get(exact).poll_at(iface.context()), PollAt::Ingress);
    assert!(
        !sockets.deadline_due(0, close_deadline),
        "reopened TIME-WAIT slot retains its cached close deadline"
    );
    sockets.check_flow_index();
}

#[test]
fn time_wait_acceptable_syn_reopens_lowest_listener() {
    assert_time_wait_syn_reopens(&[
        (REMOTE_SEQ, None, REMOTE_SEQ + 3, None),
        (TcpSeqNumber(-3), None, TcpSeqNumber(0), None),
    ]);
}

#[track_caller]
fn assert_time_wait_syn_reopens(cases: &[(TcpSeqNumber, Option<u32>, TcpSeqNumber, Option<u32>)]) {
    for &(peer_seq, recent, seq, tsval) in cases {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        let lower = sockets.add(socket());
        let (exact, _) = enter_time_wait(&mut iface, &mut sockets, &mut device, peer_seq, recent);
        sockets.get_mut(lower).listen(LOCAL_PORT).unwrap();
        let mut higher = socket();
        higher.listen(LOCAL_PORT).unwrap();
        let higher = sockets.add(higher);
        let syn = TcpRepr {
            timestamp: tsval.map(|ts| TcpTimestampRepr::new(ts, 0)),
            ..segment(TcpControl::Syn, seq, None)
        };
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::from_millis(1),
            syn,
        );
        assert_eq!(sockets.get(exact).state(), tcp::State::Closed);
        assert_eq!(sockets.get(exact).local_endpoint(), None);
        assert_eq!(sockets.get(exact).remote_endpoint(), None);
        assert_eq!(sockets.get(lower).state(), tcp::State::SynReceived);
        assert_eq!(sockets.get(higher).state(), tcp::State::Listen);
        let original = take_reply(&mut device);
        assert_control(&reply(&original), LOCAL_PORT, TcpControl::Syn, Some(seq + 1));
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::from_millis(2),
            syn,
        );
        let resent = take_reply(&mut device);
        assert_eq!(reply(&resent), reply(&original));
        assert_eq!(sockets.get(higher).state(), tcp::State::Listen);
        sockets.check_flow_index();
    }
}

#[test]
fn time_wait_unacceptable_syn_challenges_before_lower_listener() {
    for (recent, seq, tsval) in [
        (None, REMOTE_SEQ + 1, None),
        (None, REMOTE_SEQ + 2, None),
        (None, REMOTE_SEQ + 2, Some(11)),
        (Some(10), REMOTE_SEQ + 2, None),
        (Some(10), REMOTE_SEQ + 2, Some(10)),
        (Some(10), REMOTE_SEQ + 1, Some(9)),
        (Some(0), REMOTE_SEQ + 2, Some(u32::MAX)),
    ] {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        let lower = sockets.add(socket());
        let (exact, local_seq) =
            enter_time_wait(&mut iface, &mut sockets, &mut device, REMOTE_SEQ, recent);
        sockets.get_mut(lower).listen(LOCAL_PORT).unwrap();
        let syn = TcpRepr {
            timestamp: tsval.map(|ts| TcpTimestampRepr::new(ts, 0)),
            ..segment(TcpControl::Syn, seq, None)
        };
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::from_millis(1),
            syn,
        );
        assert_eq!(sockets.get(exact).state(), tcp::State::TimeWait);
        assert_eq!(sockets.get(lower).state(), tcp::State::Listen);
        let bytes = take_reply(&mut device);
        assert_control(&reply(&bytes), LOCAL_PORT, TcpControl::None, Some(REMOTE_SEQ + 2));
        assert_eq!(reply(&bytes).seq_number, local_seq);
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::from_millis(2),
            syn,
        );
        assert!(device.tx_queue.is_empty());
        iface.poll(Instant::from_millis(10_000), &mut device, &mut sockets);
        assert_eq!(sockets.get(exact).state(), tcp::State::Closed);
        assert!(device.tx_queue.is_empty());
    }
}

#[test]
fn time_wait_acceptable_syn_without_listener_acks_and_keeps_tuple() {
    for wrong_address_listener in [false, true] {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        let (exact, local_seq) =
            enter_time_wait(&mut iface, &mut sockets, &mut device, REMOTE_SEQ, None);
        if wrong_address_listener {
            let mut listener = socket();
            listener
                .listen((Ipv4Address::new(127, 0, 0, 1), LOCAL_PORT))
                .unwrap();
            sockets.add(listener);
        }
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::from_millis(1),
            segment(TcpControl::Syn, REMOTE_SEQ + 2, None),
        );
        let bytes = take_reply(&mut device);
        assert_control(&reply(&bytes), LOCAL_PORT, TcpControl::None, Some(REMOTE_SEQ + 2));
        for millis in [2, 3] {
            receive(
                &mut iface,
                &mut sockets,
                &mut device,
                Instant::from_millis(millis),
                segment(TcpControl::Syn, REMOTE_SEQ + 3, None),
            );
            assert_eq!(sockets.get(exact).state(), tcp::State::TimeWait);
            assert_eq!(
                sockets.get(exact).local_endpoint(),
                Some((LOCAL_ADDR, LOCAL_PORT).into()),
            );
            assert_eq!(
                sockets.get(exact).remote_endpoint(),
                Some((REMOTE_ADDR, REMOTE_PORT).into()),
            );
            let bytes = take_reply(&mut device);
            assert_control(&reply(&bytes), LOCAL_PORT, TcpControl::None, Some(REMOTE_SEQ + 2));
            assert_eq!(reply(&bytes).seq_number, local_seq);
        }
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::from_millis(4),
            segment(TcpControl::Rst, REMOTE_SEQ + 2, None),
        );
        assert_eq!(sockets.get(exact).state(), tcp::State::Closed);
        assert_eq!(sockets.get(exact).local_endpoint(), None);
        assert_eq!(sockets.get(exact).remote_endpoint(), None);
        assert!(device.tx_queue.is_empty());
        sockets.get_mut(exact).listen(LOCAL_PORT).unwrap();
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::from_millis(5),
            segment(TcpControl::Syn, REMOTE_SEQ + 3, None),
        );
        assert_eq!(sockets.get(exact).state(), tcp::State::SynReceived);
        let bytes = take_reply(&mut device);
        assert_control(&reply(&bytes), LOCAL_PORT, TcpControl::Syn, Some(REMOTE_SEQ + 4));
    }
}

#[test]
fn time_wait_duplicate_tuples_reopen_before_listener() {
    for listener_slot in 0..3 {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        let (first, _) = enter_time_wait(&mut iface, &mut sockets, &mut device, REMOTE_SEQ, None);
        let (first, _) = sockets.take(first);
        let (mut other_iface, mut other_sockets, mut other_device) = setup(Medium::Ip);
        let (second, _) = enter_time_wait(
            &mut other_iface,
            &mut other_sockets,
            &mut other_device,
            REMOTE_SEQ,
            None,
        );
        let (second, _) = other_sockets.take(second);
        let mut listener = socket();
        listener.listen(LOCAL_PORT).unwrap();
        let (first, second, listener) = match listener_slot {
            0 => {
                let listener = sockets.add(listener);
                (sockets.add(first), sockets.add(second), listener)
            }
            1 => {
                let first = sockets.add(first);
                let listener = sockets.add(listener);
                (first, sockets.add(second), listener)
            }
            _ => (sockets.add(first), sockets.add(second), sockets.add(listener)),
        };
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            Instant::from_millis(1),
            segment(TcpControl::Syn, REMOTE_SEQ + 3, None),
        );
        for exact in [first, second] {
            assert_eq!(sockets.get(exact).state(), tcp::State::Closed);
            assert_eq!(sockets.get(exact).local_endpoint(), None);
            assert_eq!(sockets.get(exact).remote_endpoint(), None);
        }
        assert_eq!(sockets.get(listener).state(), tcp::State::SynReceived);
        let bytes = take_reply(&mut device);
        assert_control(&reply(&bytes), LOCAL_PORT, TcpControl::Syn, Some(REMOTE_SEQ + 4));
        sockets.check_flow_index();
    }
}

#[test]
fn time_wait_syn_sequence_half_space_reopens() {
    assert_time_wait_syn_reopens(&[(
        REMOTE_SEQ,
        None,
        TcpSeqNumber((REMOTE_SEQ + 2).0.wrapping_add(i32::MIN)),
        None,
    )]);
}

#[test]
fn time_wait_syn_ack_does_not_reopen() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let lower = sockets.add(socket());
    let (exact, local_seq) =
        enter_time_wait(&mut iface, &mut sockets, &mut device, REMOTE_SEQ, Some(10));
    sockets.get_mut(lower).listen(LOCAL_PORT).unwrap();
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::from_millis(1),
        TcpRepr {
            timestamp: Some(TcpTimestampRepr::new(11, 0)),
            ..segment(TcpControl::Syn, REMOTE_SEQ + 3, Some(local_seq))
        },
    );
    assert_eq!(sockets.get(exact).state(), tcp::State::TimeWait);
    assert_eq!(sockets.get(lower).state(), tcp::State::Listen);
    let bytes = take_reply(&mut device);
    assert_control(&reply(&bytes), LOCAL_PORT, TcpControl::None, Some(REMOTE_SEQ + 2));
    assert_eq!(reply(&bytes).seq_number, local_seq);
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::from_millis(2),
        TcpRepr {
            timestamp: Some(TcpTimestampRepr::new(11, 0)),
            ..segment(TcpControl::Syn, REMOTE_SEQ + 3, Some(local_seq))
        },
    );
    assert!(device.tx_queue.is_empty());
    for millis in [10_000, 10_001] {
        iface.poll(Instant::from_millis(millis), &mut device, &mut sockets);
        assert_eq!(sockets.get(exact).state(), tcp::State::TimeWait);
        assert_eq!(sockets.get(lower).state(), tcp::State::Listen);
        assert!(device.tx_queue.is_empty());
    }
    iface.poll(Instant::from_millis(10_002), &mut device, &mut sockets);
    assert_eq!(sockets.get(exact).state(), tcp::State::Closed);
    assert_eq!(sockets.get(lower).state(), tcp::State::Listen);
    assert!(device.tx_queue.is_empty());
}

#[test]
fn close_listener_and_relisten_same_slot() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let mut listener = socket();
    listener.listen(LOCAL_PORT).unwrap();
    let handle = sockets.add(listener);
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert!(device.tx_queue.is_empty());

    sockets.get_mut(handle).close();
    assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        segment(TcpControl::Syn, REMOTE_SEQ, None),
    );
    let bytes = take_reply(&mut device);
    assert_control(
        &reply(&bytes),
        LOCAL_PORT,
        TcpControl::Rst,
        Some(REMOTE_SEQ + 1),
    );
    assert_eq!(sockets.get(handle).state(), tcp::State::Closed);

    sockets.get_mut(handle).listen(LOCAL_PORT + 1).unwrap();
    assert_listener_receives_syn(
        &mut iface,
        &mut sockets,
        &mut device,
        handle,
        LOCAL_PORT + 1,
    );
}

#[test]
fn close_synsent_and_reconnect_same_slot() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let handle = sockets.add(socket());
    sockets
        .get_mut(handle)
        .connect(
            iface.context(),
            (REMOTE_ADDR, REMOTE_PORT),
            (LOCAL_ADDR, LOCAL_PORT),
        )
        .unwrap();
    let mut other = socket();
    other
        .connect(
            iface.context(),
            (REMOTE_ADDR, REMOTE_PORT),
            (LOCAL_ADDR, LOCAL_PORT),
        )
        .unwrap();
    let survivor = sockets.add(other);
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(device.tx_queue.len(), 2);
    let bytes = device.tx_queue.pop_front().unwrap();
    let local_seq = reply(&bytes).seq_number + 1;
    assert_control(&reply(&bytes), LOCAL_PORT, TcpControl::Syn, None);
    let bytes = take_reply(&mut device);
    let syn = reply(&bytes);
    assert_control(&syn, LOCAL_PORT, TcpControl::Syn, None);
    assert_eq!(syn.seq_number + 1, local_seq);

    sockets.get_mut(handle).close();
    assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        segment(TcpControl::Syn, REMOTE_SEQ, Some(local_seq)),
    );
    assert_eq!(sockets.get(survivor).state(), tcp::State::Established);
    assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
    assert_eq!(device.tx_queue.len(), 2);
    let bytes = device.tx_queue.pop_front().unwrap();
    assert_control(
        &reply(&bytes),
        LOCAL_PORT,
        TcpControl::Rst,
        Some(TcpSeqNumber(0)),
    );
    let bytes = take_reply(&mut device);
    assert_control(
        &reply(&bytes),
        LOCAL_PORT,
        TcpControl::None,
        Some(REMOTE_SEQ + 1),
    );
    assert_data_received(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        survivor,
        local_seq,
    );
    assert_eq!(sockets.get(handle).recv_queue(), 0);
    sockets.remove(survivor);
    assert_old_tuple_rst(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        REMOTE_SEQ + 1,
        local_seq,
    );
    assert_eq!(sockets.get(handle).state(), tcp::State::Closed);

    sockets
        .get_mut(handle)
        .connect(
            iface.context(),
            (REMOTE_ADDR, REMOTE_PORT + 1),
            (LOCAL_ADDR, LOCAL_PORT + 1),
        )
        .unwrap();
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        TcpRepr {
            src_port: REMOTE_PORT + 1,
            dst_port: LOCAL_PORT + 1,
            ..segment(TcpControl::Syn, REMOTE_SEQ, Some(local_seq))
        },
    );
    assert_eq!(sockets.get(handle).state(), tcp::State::Established);
    let bytes = take_reply(&mut device);
    let ack = reply(&bytes);
    assert_eq!(ack.src_port, LOCAL_PORT + 1);
    assert_eq!(ack.dst_port, REMOTE_PORT + 1);
    assert_eq!(ack.control, TcpControl::None);
    assert_eq!(ack.ack_number, Some(REMOTE_SEQ + 1));
    assert_eq!(ack.seq_number, local_seq);
    assert_old_tuple_rst(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        REMOTE_SEQ + 1,
        local_seq,
    );
    assert_eq!(sockets.get(handle).state(), tcp::State::Established);
}

#[test]
fn incoming_rst_closes_established_socket() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, local_seq) = establish(&mut iface, &mut sockets, &mut device);
    let survivor = duplicate_connection(&mut sockets, local_seq);
    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        segment(TcpControl::Rst, REMOTE_SEQ + 1, None),
    );
    assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
    assert_eq!(sockets.get(survivor).state(), tcp::State::Established);
    assert!(device.tx_queue.is_empty());
    assert_data_received(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        survivor,
        local_seq,
    );
    assert_eq!(sockets.get(handle).recv_queue(), 0);
    sockets.remove(survivor);
    assert_old_tuple_rst(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        REMOTE_SEQ + 1,
        local_seq,
    );
    assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
}

#[test]
fn app_abort_closes_established_socket_after_idle() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, local_seq) = establish(&mut iface, &mut sockets, &mut device);
    let survivor = duplicate_connection(&mut sockets, local_seq);

    iface.poll(Instant::from_millis(5), &mut device, &mut sockets);
    assert_eq!(sockets.get(handle).state(), tcp::State::Established);
    assert!(device.tx_queue.is_empty());
    assert_eq!(iface.poll_at(Instant::from_millis(11), &mut sockets), None);
    iface.poll(Instant::from_millis(11), &mut device, &mut sockets);
    assert_eq!(sockets.get(handle).state(), tcp::State::Established);
    assert!(device.tx_queue.is_empty());
    sockets.get_mut(handle).abort();
    iface.poll(Instant::from_millis(11), &mut device, &mut sockets);
    assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
    let bytes = take_reply(&mut device);
    let rst = reply(&bytes);
    assert_control(&rst, LOCAL_PORT, TcpControl::Rst, Some(REMOTE_SEQ + 1));
    assert_eq!(rst.seq_number, local_seq);
    assert_data_received(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::from_millis(12),
        survivor,
        local_seq,
    );
    assert_eq!(sockets.get(handle).recv_queue(), 0);
    sockets.remove(survivor);
    assert_old_tuple_rst(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::from_millis(12),
        REMOTE_SEQ + 1,
        local_seq,
    );
    assert_eq!(sockets.get(handle).state(), tcp::State::Closed);
}

#[test]
fn flow_index_matches_linear_scan_under_churn() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let mut handles: [SocketHandle; 16] = core::array::from_fn(|_| sockets.add(socket()));
    let mut seed = 0x5eeda11u32;

    for round in 0..32 {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        let index = round as usize % 8;
        let first = handles[index];
        let second = handles[index + 8];
        let local_port = LOCAL_PORT + (seed % 4) as u16;
        let remote_port = REMOTE_PORT + ((seed >> 8) % 8) as u16;
        let now = Instant::from_millis(round * 20_000);
        let peer_segment = |control, seq, ack| TcpRepr {
            src_port: remote_port,
            dst_port: local_port,
            ..segment(control, seq, ack)
        };

        if seed & 1 == 0 {
            sockets.get_mut(first).listen(local_port).unwrap();
        } else {
            sockets
                .get_mut(first)
                .listen((LOCAL_ADDR, local_port))
                .unwrap();
        }
        sockets.get_mut(second).listen(local_port).unwrap();
        iface.poll(now, &mut device, &mut sockets);
        assert!(device.tx_queue.is_empty());
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            now,
            peer_segment(TcpControl::Syn, REMOTE_SEQ, None),
        );
        assert_eq!(sockets.get(first).state(), tcp::State::SynReceived);
        assert_eq!(sockets.get(second).state(), tcp::State::Listen);
        let bytes = take_reply(&mut device);
        let synack = reply(&bytes);
        assert_eq!(synack.control, TcpControl::Syn);
        assert_eq!(synack.dst_port, remote_port);
        let local_seq = synack.seq_number + 1;
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            now,
            peer_segment(TcpControl::None, REMOTE_SEQ + 1, Some(local_seq)),
        );
        assert_eq!(sockets.get(first).state(), tcp::State::Established);
        assert!(device.tx_queue.is_empty());

        sockets.get_mut(second).close();
        sockets.get_mut(first).close();
        iface.poll(now, &mut device, &mut sockets);
        let bytes = take_reply(&mut device);
        let fin = reply(&bytes);
        assert_eq!(fin.control, TcpControl::Fin);
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            now,
            peer_segment(TcpControl::Fin, REMOTE_SEQ + 1, Some(fin.seq_number + 1)),
        );
        assert_eq!(sockets.get(first).state(), tcp::State::TimeWait);
        assert_eq!(sockets.get(second).state(), tcp::State::Closed);
        let bytes = take_reply(&mut device);
        assert_eq!(reply(&bytes).ack_number, Some(REMOTE_SEQ + 2));
        let now = now + Duration::from_millis(10_001);
        iface.poll(now, &mut device, &mut sockets);
        assert_eq!(sockets.get(first).state(), tcp::State::Closed);
        assert!(device.tx_queue.is_empty());
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            now,
            peer_segment(TcpControl::None, REMOTE_SEQ + 2, Some(local_seq + 1)),
        );
        let bytes = take_reply(&mut device);
        assert_eq!(reply(&bytes).control, TcpControl::Rst);

        sockets.remove(first);
        iface.poll(now, &mut device, &mut sockets);
        handles[index] = sockets.add(socket());
        let first = handles[index];
        sockets
            .get_mut(first)
            .connect(
                iface.context(),
                (REMOTE_ADDR, remote_port),
                (LOCAL_ADDR, local_port),
            )
            .unwrap();
        iface.poll(now, &mut device, &mut sockets);
        let bytes = take_reply(&mut device);
        let syn = reply(&bytes);
        assert_eq!(syn.control, TcpControl::Syn);
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            now,
            peer_segment(TcpControl::Syn, REMOTE_SEQ, Some(syn.seq_number + 1)),
        );
        assert_eq!(sockets.get(first).state(), tcp::State::Established);
        let bytes = take_reply(&mut device);
        assert_eq!(reply(&bytes).ack_number, Some(REMOTE_SEQ + 1));
        sockets.get_mut(first).abort();
        iface.poll(now, &mut device, &mut sockets);
        let bytes = take_reply(&mut device);
        assert_eq!(reply(&bytes).control, TcpControl::Rst);
        assert_eq!(sockets.get(first).state(), tcp::State::Closed);
        sockets.remove(first);
        handles[index] = sockets.add(socket());
        sockets.remove(second);
        handles[index + 8] = sockets.add(socket());
        iface.poll(now, &mut device, &mut sockets);
        assert!(device.tx_queue.is_empty());
        assert_eq!(sockets.len(), 16);
        sockets.check_flow_index();
    }
    sockets.check_flow_index();
}

#[test]
fn tcp_bad_checksum_counted_without_delivery_or_ack_advance() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, local_seq) = establish(&mut iface, &mut sockets, &mut device);
    let mut bytes = packet_bytes(TcpRepr {
        payload: b"abc",
        ..segment(TcpControl::None, REMOTE_SEQ + 1, Some(local_seq))
    });
    bytes[20 + 16] ^= 1;
    device.rx_queue.push_back(bytes);
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(sockets.get(handle).recv_queue(), 0);
    assert!(device.tx_queue.is_empty());
    assert_eq!(sockets.counters().rx_checksum_bad, 1);

    receive(
        &mut iface,
        &mut sockets,
        &mut device,
        Instant::ZERO,
        TcpRepr {
            payload: b"abc",
            ..segment(TcpControl::None, REMOTE_SEQ + 1, Some(local_seq))
        },
    );
    assert_eq!(sockets.get(handle).recv_queue(), 3);
    let bytes = take_reply(&mut device);
    assert_eq!(reply(&bytes).ack_number, Some(REMOTE_SEQ + 4));
    assert_eq!(sockets.counters().rx_checksum_bad, 1);
}

#[test]
fn tcp_truncated_and_zero_ports_not_checksum_failures() {
    let (mut iface, mut sockets, _) = setup(Medium::Ip);
    let bytes = packet_bytes(segment(TcpControl::Syn, REMOTE_SEQ, None));
    let packet = Ipv4Packet::new_checked(&bytes[..]).unwrap();
    let ip = Ipv4Repr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
    for length in [0, 16, 19] {
        assert!(iface.inner.process_tcp(
            &mut sockets,
            PacketMeta::default(),
            IpRepr::Ipv4(ip),
            &packet.payload()[..length],
        ).is_none());
    }
    for port_offset in [0, 2] {
        let mut tcp = packet.payload().to_vec();
        tcp[port_offset..port_offset + 2].fill(0);
        assert!(iface.inner.process_tcp(
            &mut sockets,
            PacketMeta::default(),
            IpRepr::Ipv4(ip),
            &tcp,
        ).is_none());
    }
    assert_eq!(sockets.counters().rx_checksum_bad, 0);
}

const NON_UNICAST_DSTS: [Ipv4Address; 4] = [
    Ipv4Address::BROADCAST,
    Ipv4Address::new(192, 168, 1, 255),
    Ipv4Address::new(224, 0, 0, 1),
    Ipv4Address::new(239, 1, 1, 1),
];

// Linux tcp_v4_rcv drops TCP that is not addressed to this host (pkt_type != PACKET_HOST).
#[test]
fn syn_to_broadcast_leaves_wildcard_listener_listening() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let mut listener = socket();
    listener.listen(LOCAL_PORT).unwrap();
    let handle = sockets.add(listener);
    for (i, dst) in NON_UNICAST_DSTS.into_iter().enumerate() {
        let syn = segment(TcpControl::Syn, REMOTE_SEQ, None);
        device.rx_queue.push_back(packet_bytes_to(syn, dst));
        iface.poll(Instant::from_millis(2 * i as i64), &mut device, &mut sockets);
        iface.poll(Instant::from_millis(2 * i as i64 + 1), &mut device, &mut sockets);
        assert!(device.tx_queue.is_empty(), "replied to a SYN sent to {dst}");
        assert_eq!(sockets.get(handle).state(), tcp::State::Listen, "SYN to {dst}");
    }
    receive(&mut iface, &mut sockets, &mut device, Instant::from_millis(10),
        segment(TcpControl::Syn, REMOTE_SEQ, None));
    let bytes = take_reply(&mut device);
    assert_control(&reply(&bytes), LOCAL_PORT, TcpControl::Syn, Some(REMOTE_SEQ + 1));
}

#[test]
fn broadcast_syn_without_socket_gets_no_rst() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    for dst in NON_UNICAST_DSTS {
        device.rx_queue.push_back(packet_bytes_to(segment(TcpControl::Syn, REMOTE_SEQ, None), dst));
        iface.poll(Instant::ZERO, &mut device, &mut sockets);
        assert!(device.tx_queue.is_empty(), "answered a SYN sent to {dst}");
    }
    receive(&mut iface, &mut sockets, &mut device, Instant::ZERO,
        segment(TcpControl::Syn, REMOTE_SEQ, None));
    let bytes = take_reply(&mut device);
    assert_control(&reply(&bytes), LOCAL_PORT, TcpControl::Rst, Some(REMOTE_SEQ + 1));
}
