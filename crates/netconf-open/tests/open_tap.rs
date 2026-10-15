//! One `open` call lives in this test binary because EAL initializes once per process.

#[path = "open_tap/common.rs"]
mod common;

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant as WallInstant};

use zhida_open::open;
use dpdk_smoltcp::smoltcp::time::Instant;

const PEER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];

struct KernelSide(OwnedFd);

impl KernelSide {
    fn bind(iface: &str) -> Self {
        let iface = CString::new(iface).unwrap();
        // SAFETY: `iface` is a live NUL-terminated interface name.
        let index = unsafe { libc::if_nametoindex(iface.as_ptr()) };
        assert_ne!(index, 0, "tap interface {iface:?} does not exist");
        let protocol = (libc::ETH_P_ALL as u16).to_be();
        // SAFETY: plain socket call; the result is checked before ownership transfer.
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                i32::from(protocol),
            )
        };
        assert!(raw >= 0, "socket: {}", std::io::Error::last_os_error());
        // SAFETY: `raw` is a new descriptor owned by this value.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: all-zero is valid initialization for sockaddr_ll.
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_protocol = protocol;
        address.sll_ifindex = index as i32;
        // SAFETY: `address` and its exact size are valid for bind.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_ll).cast(),
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "bind: {}", std::io::Error::last_os_error());
        Self(fd)
    }

    fn send(&self, frame: &[u8]) {
        // SAFETY: `frame` is readable for its length.
        let sent = unsafe {
            libc::send(
                self.0.as_raw_fd(),
                frame.as_ptr().cast(),
                frame.len(),
                0,
            )
        };
        assert_eq!(sent, frame.len() as isize);
    }

    fn receive_arp_reply(&self, stack_mac: [u8; 6]) -> bool {
        let mut frame = [0u8; 2048];
        loop {
            // SAFETY: all-zero is valid initialization for sockaddr_ll.
            let mut from: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut from_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            // SAFETY: both output buffers are writable for the supplied lengths.
            let len = unsafe {
                libc::recvfrom(
                    self.0.as_raw_fd(),
                    frame.as_mut_ptr().cast(),
                    frame.len(),
                    libc::MSG_DONTWAIT,
                    (&mut from as *mut libc::sockaddr_ll).cast(),
                    &mut from_len,
                )
            };
            if len < 0 {
                let error = std::io::Error::last_os_error();
                return match error.kind() {
                    std::io::ErrorKind::WouldBlock => false,
                    std::io::ErrorKind::Interrupted => continue,
                    _ => panic!("recvfrom: {error}"),
                };
            }
            let bytes = &frame[..len as usize];
            if from.sll_pkttype != libc::PACKET_OUTGOING
                && bytes.len() >= 42
                && bytes[0..6] == PEER_MAC
                && bytes[6..12] == stack_mac
                && bytes[12..14] == [0x08, 0x06]
                && bytes[20..22] == [0, 2]
                && bytes[22..28] == stack_mac
                && bytes[28..32] == [192, 0, 2, 2]
                && bytes[32..38] == PEER_MAC
                && bytes[38..42] == [192, 0, 2, 1]
            {
                return true;
            }
        }
    }
}

fn arp_request() -> [u8; 42] {
    let mut frame = [0u8; 42];
    frame[0..6].fill(0xff);
    frame[6..12].copy_from_slice(&PEER_MAC);
    frame[12..14].copy_from_slice(&[0x08, 0x06]);
    frame[14..22].copy_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 1]);
    frame[22..28].copy_from_slice(&PEER_MAC);
    frame[28..32].copy_from_slice(&[192, 0, 2, 1]);
    frame[38..42].copy_from_slice(&[192, 0, 2, 2]);
    frame
}

#[zhida_test_support::pinned_test]
fn open_vdev_tap_config_reaches_running_stack() {
    let config = common::config("net_tap_o3_stack", "cdo3_stack", common::EXPLICIT_NONE, false);
    let mut now = 0i64;
    // SAFETY: EAL creates this private net_tap vdev; this worker owns it and its
    // packets, and the vdev lives for the process lifetime.
    let mut opened = unsafe {
        open(&config, &common::sizing(), &mut || {
            now += 1;
            Instant::from_millis(now)
        })
    }
    .unwrap();
    assert_eq!(opened.report.device.driver_name, "net_tap");
    assert!(opened.report.link.up);
    assert_eq!(opened.report.gateway, None);
    assert!(opened.report.to_string().ends_with("\ngateway: none"));

    let kernel = KernelSide::bind("cdo3_stack");
    kernel.send(&arp_request());
    let deadline = WallInstant::now() + Duration::from_secs(2);
    while WallInstant::now() < deadline {
        now += 1;
        opened.stack.turn(Instant::from_millis(now), 32).unwrap();
        if kernel.receive_arp_reply(opened.report.device.mac) {
            opened.stack.into_port().try_close().unwrap();
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("Stack did not answer the kernel-side ARP request");
}
