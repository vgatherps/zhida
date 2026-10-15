#![cfg(feature = "medium-ip")]

use smoltcp::iface::{Config, DropQueue, Interface, SocketHandle, TcpSet};
use smoltcp::phy::{Device, Loopback, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpCidr, Ipv4Address, Ipv4Packet, TcpControl, TcpPacket};

const LOCAL: Ipv4Address = Ipv4Address::new(192, 0, 2, 1);
const REMOTE: Ipv4Address = Ipv4Address::new(192, 0, 2, 2);

fn interface(seed: u64) -> (Interface, Loopback) {
    let mut device = Loopback::new(Medium::Ip);
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = seed;
    let mut iface = Interface::new(config, &mut device, Instant::ZERO);
    iface.update_ip_addrs(|addrs| addrs.push(IpCidr::new(LOCAL.into(), 24)).unwrap());
    (iface, device)
}

fn add_socket(sockets: &mut TcpSet<'static>) -> SocketHandle {
    let config = tcp::Config { rx_capacity: 64, tx_capacity: 64, mss_cap: None };
    let wake = DropQueue::with_capacity(1, #[cfg(feature = "udp-set")] 0);
    sockets.add_admitted(&config, 1500, wake)
}

fn take_syn(device: &mut Loopback) -> u32 {
    let frame = device.receive(Instant::ZERO).unwrap().0.into_buf();
    let ip = Ipv4Packet::new_checked(frame.as_slice()).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(tcp.syn());
    tcp.seq_number().0 as u32
}

#[test]
fn different_interface_seeds_change_active_syn_isn() {
    let syn = |seed| {
        let (mut iface, mut device) = interface(seed);
        let mut sockets = TcpSet::new(vec![]);
        let handle = add_socket(&mut sockets);
        sockets
            .get_mut(handle)
            .connect(iface.context(), (REMOTE, 80), 49152)
            .unwrap();
        iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
        take_syn(&mut device)
    };
    assert_ne!(syn(1), syn(2));
}

#[test]
fn reconnect_same_tuple_advances_syn_isn_with_interface_time() {
    let (mut iface, mut device) = interface(1);
    let mut sockets = TcpSet::new(vec![]);
    let handle = add_socket(&mut sockets);
    sockets
        .get_mut(handle)
        .connect(iface.context(), (REMOTE, 80), 49152)
        .unwrap();
    iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    let first = take_syn(&mut device);
    sockets.get_mut(handle).abort();
    iface.poll_maintenance(Instant::from_millis(1));
    sockets
        .get_mut(handle)
        .connect(iface.context(), (REMOTE, 80), 49152)
        .unwrap();
    iface.poll_egress(Instant::from_millis(1), &mut device, &mut sockets);
    let second = take_syn(&mut device);
    assert_eq!(second.wrapping_sub(first), 250);
}

#[test]
fn passive_syn_isn_uses_interface_seed_and_time() {
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{IpProtocol, Ipv4Repr, TcpRepr, TcpSeqNumber};

    let syn = |seed, now| {
        let (mut iface, mut device) = interface(seed);
        let mut sockets = TcpSet::new(vec![]);
        let handle = add_socket(&mut sockets);
        sockets.get_mut(handle).listen(80).unwrap();
        let tcp = TcpRepr {
            src_port: 49152,
            dst_port: 80,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(123),
            ack_number: None,
            window_len: 64,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let ip = Ipv4Repr {
            src_addr: REMOTE,
            dst_addr: LOCAL,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };
        let checksums = ChecksumCapabilities::default();
        device
            .transmit(now)
            .unwrap()
            .consume(ip.buffer_len() + tcp.buffer_len(), |bytes| {
                ip.emit(&mut Ipv4Packet::new_unchecked(&mut *bytes), &checksums);
                tcp.emit(
                    &mut TcpPacket::new_unchecked(&mut bytes[ip.buffer_len()..]),
                    &REMOTE.into(),
                    &LOCAL.into(),
                    &checksums,
                );
            });
        iface.poll_ingress_single(now, &mut device, &mut sockets);
        iface.poll_egress(now, &mut device, &mut sockets);
        take_syn(&mut device)
    };
    assert_ne!(syn(1, Instant::ZERO), syn(2, Instant::ZERO));
    assert_eq!(
        syn(1, Instant::from_millis(1)).wrapping_sub(syn(1, Instant::ZERO)),
        250
    );
}
