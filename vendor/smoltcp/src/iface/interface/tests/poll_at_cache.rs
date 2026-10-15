use super::*;
use crate::iface::SocketHandle;
use crate::socket::tcp;
use crate::tests::TestingDevice;
use crate::time::Duration;

const LOCAL: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
const REMOTE: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
const START: Instant = Instant::from_millis_const(100);

fn socket() -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(tcp::RxBuffer::new(64), tcp::SocketBuffer::new(vec![0; 64]));
    socket.set_ack_delay(None);
    socket
}

fn connect(iface: &mut Interface, sockets: &mut TcpSet<'static>, port: u16) -> SocketHandle {
    let mut socket = socket();
    socket
        .connect(iface.context(), (REMOTE, 65000), (LOCAL, port))
        .unwrap();
    sockets.add(socket)
}

fn segment(
    port: u16,
    control: TcpControl,
    seq: i32,
    ack: Option<TcpSeqNumber>,
) -> TcpRepr<'static> {
    TcpRepr {
        src_port: 65000,
        dst_port: port,
        control,
        seq_number: TcpSeqNumber(seq),
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
    let ip = Ipv4Repr {
        src_addr: REMOTE,
        dst_addr: LOCAL,
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
        &REMOTE.into(),
        &LOCAL.into(),
        &ChecksumCapabilities::default(),
    );
    device.rx_queue.push_back(bytes);
    assert_eq!(
        iface.poll_ingress_single(now, device, sockets),
        PollIngressSingleResult::SocketStateChanged
    );
    iface.poll_at(now, sockets);
}

fn take_tcp(device: &mut TestingDevice) -> (u16, TcpControl, TcpSeqNumber, Vec<u8>) {
    let bytes = device.tx_queue.pop_front().unwrap();
    let ip = Ipv4Packet::new_checked(&bytes).unwrap();
    assert!(ip.verify_checksum());
    assert_eq!((ip.src_addr(), ip.dst_addr()), (LOCAL, REMOTE));
    let tcp = TcpRepr::parse(
        &TcpPacket::new_checked(ip.payload()).unwrap(),
        &LOCAL.into(),
        &REMOTE.into(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();
    (
        tcp.src_port,
        tcp.control,
        tcp.seq_number,
        tcp.payload.to_vec(),
    )
}

fn establish(
    iface: &mut Interface,
    sockets: &mut TcpSet<'static>,
    device: &mut TestingDevice,
) -> (SocketHandle, TcpSeqNumber) {
    let handle = connect(iface, sockets, 1234);
    assert_eq!(iface.poll_at(START, sockets), Some(Instant::ZERO));
    iface.poll_egress(START, device, sockets);
    assert_eq!(
        iface.poll_at(START, sockets),
        Some(Instant::from_millis(384))
    );
    let (port, control, seq, payload) = take_tcp(device);
    assert_eq!((port, control), (1234, TcpControl::Syn));
    assert!(payload.is_empty());
    receive(
        iface,
        sockets,
        device,
        START,
        segment(1234, TcpControl::Syn, 100, Some(seq + 1)),
    );
    assert_eq!(sockets.get(handle).state(), tcp::State::Established);
    iface.poll_egress(START, device, sockets);
    assert_eq!(iface.poll_at(START, sockets), None);
    let (_, control, _, payload) = take_tcp(device);
    assert_eq!(control, TcpControl::None);
    assert!(payload.is_empty());
    assert!(device.tx_queue.is_empty());
    (handle, seq + 1)
}

#[test]
fn deadline_follows_app_change_without_ingress() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let (handle, seq) = establish(&mut iface, &mut sockets, &mut device);
    sockets.get_mut(handle).set_rto(Duration::from_millis(100));
    assert_eq!(iface.poll_at(START, &mut sockets), None);
    assert_eq!(sockets.get_mut(handle).send_slice(b"abc"), Ok(3));
    assert_eq!(iface.poll_at(START, &mut sockets), Some(Instant::ZERO));
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(iface.poll_at(START, &mut sockets), Some(Instant::from_millis(192)));
    assert_eq!(take_tcp(&mut device).3, b"abc");
    sockets.get_mut(handle).set_rto(Duration::from_millis(300));
    assert_eq!(iface.poll_at(START, &mut sockets), Some(Instant::from_millis(192)));
    receive(&mut iface, &mut sockets, &mut device, START,
        segment(1234, TcpControl::None, 101, Some(seq + 3)));
    assert_eq!(iface.poll_at(START, &mut sockets), None);
    assert_eq!(sockets.get_mut(handle).send_slice(b"def"), Ok(3));
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(take_tcp(&mut device).3, b"def");
    assert_eq!(iface.poll_at(START, &mut sockets), Some(Instant::from_millis(384)));
    assert!(device.rx_queue.is_empty());
}

#[test]
fn remove_and_reuse_resets_deadline() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
    let handle = connect(&mut iface, &mut sockets, 1234);
    assert_eq!(iface.poll_at(START, &mut sockets), Some(Instant::ZERO));
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(
        iface.poll_at(START, &mut sockets),
        Some(Instant::from_millis(1024))
    );
    assert_eq!(sockets.waiting, vec![0]);
    sockets.remove(handle);
    assert!(sockets.waiting.is_empty());
    assert_eq!(iface.poll_at(START, &mut sockets), None);
    let mut listener = socket();
    listener.listen(1234).unwrap();
    let reused = sockets.add(listener);
    assert_ne!(reused, handle);
    assert_eq!(sockets.slot_count(), 1);
    assert_eq!(iface.poll_at(START, &mut sockets), None);
    sockets.remove(reused);
    connect(&mut iface, &mut sockets, 1234);
    assert_eq!(iface.poll_at(START, &mut sockets), Some(Instant::ZERO));
    assert!(sockets.waiting.is_empty());
}

#[test]
fn waiting_socket_switches_when_silence_ends() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
    let handle = connect(&mut iface, &mut sockets, 1234);
    iface.poll_egress(START, &mut device, &mut sockets);
    let silent_until = START + Duration::from_secs(1);
    for (now, expected) in [
        (START, Instant::from_millis(1024)),
        (silent_until - Duration::from_millis(1), silent_until),
    ] {
        assert_eq!(
            iface.poll_at(now, &mut sockets),
            Some(expected)
        );
        assert_eq!(sockets.waiting, vec![0]);
    }
    assert_eq!(sockets.get(handle).poll_at(iface.context()), PollAt::Now);
    assert_eq!(
        iface.poll_at(silent_until, &mut sockets),
        Some(Instant::ZERO)
    );
    assert_eq!(
        iface.poll_at(silent_until + Duration::from_millis(1), &mut sockets),
        Some(Instant::ZERO)
    );
}

#[test]
fn neighbor_learned_releases_waiting_deadline() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
    let handle = connect(&mut iface, &mut sockets, 1234);
    iface.poll_egress(START, &mut device, &mut sockets);
    assert_eq!(
        iface.poll_at(START, &mut sockets),
        Some(Instant::from_millis(1024))
    );
    let learned = START + Duration::from_millis(1);
    iface.inner.neighbor_cache.fill(
        REMOTE.into(),
        HardwareAddress::Ethernet(EthernetAddress([2, 0, 0, 0, 0, 1])),
        learned,
    );
    assert_eq!(sockets.get(handle).poll_at(iface.context()), PollAt::Now);
    assert_eq!(iface.poll_at(learned, &mut sockets), Some(Instant::ZERO));
    iface.poll_egress(learned, &mut device, &mut sockets);
    assert!(sockets.waiting.is_empty());
    assert_eq!(
        iface.poll_at(learned, &mut sockets),
        Some(Instant::from_millis(384))
    );
}

#[test]
fn cached_poll_at_matches_full_scan_under_churn() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let mut handles = Vec::new();
    let mut local_seq = [TcpSeqNumber(0); 16];
    for index in 0..16 {
        let port = 1234 + index as u16;
        let handle = if index < 8 {
            let handle = sockets.add(socket());
            sockets.get_mut(handle).listen(port).unwrap();
            handle
        } else {
            connect(&mut iface, &mut sockets, port)
        };
        handles.push(handle);
        iface.poll_at(START, &mut sockets);
    }
    iface.poll_egress(START, &mut device, &mut sockets);
    iface.poll_at(START, &mut sockets);
    for seq in &mut local_seq[8..] {
        let (_, control, sent_seq, payload) = take_tcp(&mut device);
        assert_eq!(control, TcpControl::Syn);
        assert!(payload.is_empty());
        *seq = sent_seq + 1;
    }
    for index in 0..16 {
        let port = 1234 + index as u16;
        if index < 8 {
            receive(
                &mut iface,
                &mut sockets,
                &mut device,
                START,
                segment(port, TcpControl::Syn, 100, None),
            );
            iface.poll_egress(START, &mut device, &mut sockets);
            iface.poll_at(START, &mut sockets);
            let (sent_port, control, seq, payload) = take_tcp(&mut device);
            assert_eq!((sent_port, control), (port, TcpControl::Syn));
            assert!(payload.is_empty());
            local_seq[index] = seq + 1;
            receive(
                &mut iface,
                &mut sockets,
                &mut device,
                START,
                segment(port, TcpControl::None, 101, Some(local_seq[index])),
            );
        } else {
            receive(
                &mut iface,
                &mut sockets,
                &mut device,
                START,
                segment(port, TcpControl::Syn, 100, Some(local_seq[index])),
            );
        }
        iface.poll_egress(START, &mut device, &mut sockets);
        iface.poll_at(START, &mut sockets);
        if index >= 8 {
            let (sent_port, control, _, payload) = take_tcp(&mut device);
            assert_eq!((sent_port, control), (port, TcpControl::None));
            assert!(payload.is_empty());
        }
        assert_eq!(sockets.get(handles[index]).state(), tcp::State::Established);
        assert!(device.tx_queue.is_empty());
    }
    assert_eq!(iface.poll_at(START, &mut sockets), None);

    for index in 0..16 {
        let now = Instant::from_millis(150 + index as i64);
        let port = 1234 + index as u16;
        let handle = handles[index];
        sockets.get_mut(handle).set_rto(Duration::from_millis(100));
        assert_eq!(iface.poll_at(now, &mut sockets), None);
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            now,
            TcpRepr {
                payload: b"abc",
                ..segment(port, TcpControl::Psh, 101, Some(local_seq[index]))
            },
        );
        iface.poll_egress(now, &mut device, &mut sockets);
        assert_eq!(iface.poll_at(now, &mut sockets), None);
        let (_, control, _, payload) = take_tcp(&mut device);
        assert_eq!(control, TcpControl::None);
        assert!(payload.is_empty());
        let mut received = Vec::new();
        while let Some(frame) = sockets.get_mut(handle).recv().unwrap() {
            received.extend_from_slice(frame.payload());
        }
        assert_eq!(received.len(), 3);
        assert_eq!(&received, b"abc");
        iface.poll_at(now, &mut sockets);
        assert_eq!(sockets.get_mut(handle).send_slice(b"def"), Ok(3));
        assert_eq!(iface.poll_at(now, &mut sockets), Some(Instant::ZERO));
        iface.poll_egress(now, &mut device, &mut sockets);
        assert_eq!(
            iface.poll_at(now, &mut sockets),
            Some(Instant::from_millis(if index < 6 { 224 } else { 256 }))
        );
        let (_, _, seq, payload) = take_tcp(&mut device);
        assert_eq!(seq, local_seq[index]);
        assert_eq!(&payload, b"def");
        local_seq[index] += 3;
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            now,
            segment(port, TcpControl::None, 104, Some(local_seq[index])),
        );
        assert_eq!(iface.poll_at(now, &mut sockets), None);
        assert!(device.tx_queue.is_empty());
    }

    let now = Instant::from_millis(200);
    for (index, &handle) in handles.iter().enumerate() {
        if index < 8 {
            sockets.get_mut(handle).set_rto(Duration::from_millis(25));
            sockets.get_mut(handle).close();
        } else {
            sockets.get_mut(handle).abort();
        }
        assert_eq!(iface.poll_at(now, &mut sockets), Some(Instant::ZERO));
        iface.poll_egress(now, &mut device, &mut sockets);
        iface.poll_at(now, &mut sockets);
        let (_, control, _, payload) = take_tcp(&mut device);
        assert_eq!(
            control,
            if index < 8 {
                TcpControl::Fin
            } else {
                TcpControl::Rst
            }
        );
        assert!(payload.is_empty());
    }
    let expired = Instant::from_millis(500);
    iface.poll_at(expired, &mut sockets);
    iface.poll_egress(expired, &mut device, &mut sockets);
    for _ in 0..8 {
        let (_, control, _, payload) = take_tcp(&mut device);
        assert_eq!(control, TcpControl::Fin);
        assert!(payload.is_empty());
    }
    for &handle in &handles[..8] {
        assert_eq!(sockets.get(handle).state(), tcp::State::FinWait1);
        sockets.get_mut(handle).abort();
    }
    iface.poll_egress(expired, &mut device, &mut sockets);
    for _ in 0..8 {
        assert_eq!(take_tcp(&mut device).1, TcpControl::Rst);
    }
    assert_eq!(iface.poll_at(expired, &mut sockets), None);
    for &handle in &handles {
        sockets.get_mut(handle).listen(4321).unwrap();
        assert_eq!(iface.poll_at(expired, &mut sockets), None);
        sockets.get_mut(handle).close();
        assert_eq!(iface.poll_at(expired, &mut sockets), None);
    }
    for &handle in handles.iter().step_by(2) {
        sockets.remove(handle);
        assert_eq!(iface.poll_at(expired, &mut sockets), None);
    }
    for _ in 0..8 {
        sockets.add(socket());
        assert_eq!(iface.poll_at(expired, &mut sockets), None);
    }
    assert_eq!(sockets.len(), 16);
}

#[test]
fn poll_at_matches_full_scan_with_wheel() {
    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let start = Instant::from_millis(-100);
    assert_eq!(iface.poll_at(start, &mut sockets), None);
    let mut handles = Vec::new();
    for index in 0..64 {
        let port = 1234 + index;
        let handle = connect(&mut iface, &mut sockets, port);
        iface.poll_egress(start, &mut device, &mut sockets);
        let (sent_port, control, seq, payload) = take_tcp(&mut device);
        assert_eq!((sent_port, control), (port, TcpControl::Syn));
        assert!(payload.is_empty());
        receive(
            &mut iface,
            &mut sockets,
            &mut device,
            start,
            segment(port, TcpControl::Syn, 100, Some(seq + 1)),
        );
        iface.poll_egress(start, &mut device, &mut sockets);
        assert_eq!(take_tcp(&mut device).1, TcpControl::None);
        assert_eq!(sockets.get(handle).state(), tcp::State::Established);
        assert_eq!(iface.poll_at(start, &mut sockets), None);
        handles.push(handle);
    }
    let delays = [
        Duration::from_millis(1),
        Duration::from_micros(105_500),
        Duration::from_millis(140),
        Duration::from_secs(1),
        Duration::from_secs(32),
        Duration::from_secs(60),
    ];
    let mut sequences = Vec::new();
    for (index, &handle) in handles.iter().enumerate() {
        sockets.get_mut(handle).set_rto(delays.get(index).copied().unwrap_or(Duration::from_secs(60)));
        assert_eq!(sockets.get_mut(handle).send_slice(b"x"), Ok(1));
        iface.poll_egress(start, &mut device, &mut sockets);
        let (_, _, seq, payload) = take_tcp(&mut device);
        assert_eq!(payload, b"x");
        sequences.push(seq);
    }
    assert_eq!(iface.poll_at(start, &mut sockets), Some(Instant::from_millis(-99)));
    iface.poll_egress(Instant::from_micros(-99_001), &mut device, &mut sockets);
    assert!(device.tx_queue.is_empty());
    iface.poll_egress(Instant::from_millis(-99), &mut device, &mut sockets);
    assert_eq!(take_tcp(&mut device).0, 1234);
    assert_eq!(sockets.get(handles[0]).state(), tcp::State::Established);
    sockets.remove(handles[0]);
    let replacement = sockets.add(socket());
    sockets.get_mut(replacement).listen(1234).unwrap();
    assert_eq!(iface.poll_at(start, &mut sockets), Some(Instant::from_millis(6)));
    let churn_delays = [Duration::from_millis(1500), Duration::from_secs(33),
                        Duration::from_secs(45), Duration::from_secs(60)];
    let mut pending = vec![true; handles.len()];
    for turn in 0..16 {
        for (index, &handle) in handles.iter().enumerate().skip(6) {
            if pending[index] {
                receive(&mut iface, &mut sockets, &mut device, start,
                    segment(1234 + index as u16, TcpControl::None, 101, Some(sequences[index] + 1)));
                sequences[index] += 1;
            }
            sockets.get_mut(handle).set_rto(churn_delays[(index + turn) % 4]);
            assert_eq!(sockets.get_mut(handle).send_slice(b"x"), Ok(1));
            iface.poll_egress(start, &mut device, &mut sockets);
            assert_eq!(take_tcp(&mut device).3, b"x");
            pending[index] = true;
            assert_eq!(iface.poll_at(start, &mut sockets), Some(Instant::from_millis(6)));
            if (index + turn) % 3 == 0 {
                receive(&mut iface, &mut sockets, &mut device, start,
                    segment(1234 + index as u16, TcpControl::None, 101, Some(sequences[index] + 1)));
                sequences[index] += 1;
                pending[index] = false;
                assert_eq!(iface.poll_at(start, &mut sockets), Some(Instant::from_millis(6)));
            }
        }
    }
    iface.poll_egress(Instant::from_micros(5500), &mut device, &mut sockets);
    assert!(device.tx_queue.is_empty());
    assert_eq!(iface.poll_at(Instant::from_micros(5500), &mut sockets), Some(Instant::from_millis(6)));
    iface.poll_egress(Instant::from_millis(6), &mut device, &mut sockets);
    assert_eq!(take_tcp(&mut device).0, 1235);
    assert_eq!(sockets.get(handles[1]).state(), tcp::State::Established);
    receive(&mut iface, &mut sockets, &mut device, Instant::from_millis(6),
        segment(1235, TcpControl::None, 101, Some(sequences[1] + 1)));
    assert_eq!(iface.poll_at(Instant::from_millis(6), &mut sockets), Some(Instant::from_millis(32)));
    iface.poll_egress(Instant::from_millis(32), &mut device, &mut sockets);
    assert!(device.tx_queue.is_empty());
    assert_eq!(iface.poll_at(Instant::from_millis(32), &mut sockets), Some(Instant::from_millis(40)));
    iface.poll_egress(Instant::from_millis(40), &mut device, &mut sockets);
    assert_eq!(take_tcp(&mut device).0, 1236);
    assert_eq!(sockets.get(handles[2]).state(), tcp::State::Established);
    receive(&mut iface, &mut sockets, &mut device, Instant::from_millis(40),
        segment(1236, TcpControl::None, 101, Some(sequences[2] + 1)));
    assert_eq!(iface.poll_at(Instant::from_millis(40), &mut sockets), Some(Instant::from_millis(896)));
    iface.poll_egress(start, &mut device, &mut sockets);
    assert!(device.tx_queue.is_empty());
    for (index, &handle) in handles.iter().enumerate().skip(6) {
        if pending[index] {
            receive(&mut iface, &mut sockets, &mut device, start,
                segment(1234 + index as u16, TcpControl::None, 101, Some(sequences[index] + 1)));
        }
    }
    sockets.remove(handles[3]);
    assert_eq!(iface.poll_at(start, &mut sockets), Some(Instant::from_millis(31_744)));
    sockets.remove(handles[4]);
    assert_eq!(iface.poll_at(start, &mut sockets), Some(Instant::from_millis(32_768)));
    receive(&mut iface, &mut sockets, &mut device, start,
        segment(1239, TcpControl::None, 101, Some(sequences[5] + 1)));
    assert_eq!(iface.poll_at(start, &mut sockets), None);
    assert!(device.tx_queue.is_empty());
}
