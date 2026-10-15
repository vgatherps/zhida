//! One `open` call lives in this test binary because EAL initializes once per process.

#[path = "open_tap/common.rs"]
mod common;

use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration as WallDuration, Instant as WallInstant};

use zhida_open::{open, OpenError};
use dpdk_smoltcp::smoltcp::time::{Duration, Instant};
use dpdk_smoltcp::smoltcp::wire::Ipv4Address;

const ETH_P_ARP: u16 = 0x0806;

/// Counts ARP requests for `target` that Zhida writes into the tap, read on the kernel side with
/// a packet socket on every interface, opened before `open` so the first request is not missed
/// (the tap does not exist yet; frames are matched to it by interface index).
fn count_arp_requests(
    iface: &'static str,
    target: Ipv4Address,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<usize> {
    // SAFETY: plain socket(2) call; the result is checked.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, i32::from(ETH_P_ARP.to_be())) };
    assert!(fd >= 0, "packet socket: {}", std::io::Error::last_os_error());
    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 50_000,
    };
    // SAFETY: `timeout` is a live timeval and the length matches it.
    let set = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast(),
            u32::try_from(size_of::<libc::timeval>()).unwrap(),
        )
    };
    assert_eq!(set, 0, "SO_RCVTIMEO: {}", std::io::Error::last_os_error());
    thread::spawn(move || {
        let name = CString::new(iface).unwrap();
        let mut count = 0;
        let mut frame = [0u8; 2048];
        while !stop.load(Ordering::Acquire) {
            // SAFETY: an all-zero sockaddr_ll is valid output storage.
            let mut from: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut from_len = u32::try_from(size_of::<libc::sockaddr_ll>()).unwrap();
            // SAFETY: `frame` and `from` are live writable buffers of the given lengths.
            let len = unsafe {
                libc::recvfrom(
                    fd,
                    frame.as_mut_ptr().cast(),
                    frame.len(),
                    0,
                    (&raw mut from).cast(),
                    &mut from_len,
                )
            };
            if len < 0 {
                let error = std::io::Error::last_os_error();
                assert!(
                    matches!(error.raw_os_error(), Some(libc::EAGAIN | libc::EINTR)),
                    "recv: {error}"
                );
                continue;
            }
            // SAFETY: `name` is a live NUL-terminated interface name.
            let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
            let frame = &frame[..usize::try_from(len).unwrap()];
            // Ethernet header 14 bytes, then ARP: opcode at 6..8, target IPv4 at 24..28.
            if index != 0
                && from.sll_ifindex == i32::try_from(index).unwrap()
                && frame.len() >= 42
                && frame[12..14] == ETH_P_ARP.to_be_bytes()
                && frame[20..22] == [0, 1]
                && frame[38..42] == target.octets()
            {
                count += 1;
            }
        }
        // SAFETY: `fd` is owned by this thread and closed once.
        unsafe { libc::close(fd) };
        count
    })
}

#[zhida_test_support::pinned_test]
fn open_gateway_silent_fails_after_3s() {
    let iface = "cdo5_gw_no";
    let gateway = Ipv4Address::new(192, 0, 2, 254);
    let stop = Arc::new(AtomicBool::new(false));
    let counter = count_arp_requests(iface, gateway, Arc::clone(&stop));
    let config = common::config_with_gateway(
        "net_tap_o5_gw_no",
        iface,
        common::EXPLICIT_NONE,
        false,
        r#""192.0.2.254""#,
    );
    let started = WallInstant::now();
    let mut clock = || {
        Instant::from_micros(i64::try_from(started.elapsed().as_micros()).unwrap())
    };
    let result = unsafe { open(&config, &common::sizing(), &mut clock) };
    thread::sleep(WallDuration::from_millis(200));
    stop.store(true, Ordering::Release);
    let requests = counter.join().unwrap();
    match result {
        Err(OpenError::GatewayUnresolved {
            stack,
            gateway: actual,
            waited,
        }) => {
            assert_eq!(actual, gateway);
            assert!(waited >= Duration::from_secs(3));
            assert_eq!(requests, 3, "one ARP request per 1 s silence over 3 s");
            stack.into_port().try_close().unwrap();
        }
        Err(error) => panic!("unexpected error: {error}"),
        Ok(_) => panic!("silent gateway resolved"),
    }
}
