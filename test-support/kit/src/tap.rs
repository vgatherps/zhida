//! Test-only net_tap vdev: a kernel tap netdev the test talks to from the
//! kernel side. Needs CAP_NET_ADMIN and /dev/net/tun.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use zhida_dpdk_sys::{rte_eth_dev_get_port_by_name, rte_vdev_init, rte_vdev_uninit};

/// A net_tap vdev whose kernel netdev is `iface` (not persistent). Declare it
/// before the Port it backs so the Port drops first. Dropped without `close`,
/// it removes the vdev and netdev; outside a panic it then fails the test.
pub struct TapVdev {
    vdev: CString,
    iface: CString,
    port_id: u16,
    closed: bool,
}

impl TapVdev {
    pub fn new(vdev: &CStr, iface: &CStr) -> Self {
        let args = CString::new(format!(
            "iface={},mac=02:00:00:00:00:fe",
            iface.to_str().unwrap()
        ))
        .unwrap();
        assert_eq!(unsafe { rte_vdev_init(vdev.as_ptr(), args.as_ptr()) }, 0);
        let mut tap = Self {
            vdev: vdev.to_owned(),
            iface: iface.to_owned(),
            port_id: u16::MAX,
            closed: false,
        };
        assert_eq!(
            unsafe { rte_eth_dev_get_port_by_name(vdev.as_ptr(), &mut tap.port_id) },
            0
        );
        tap
    }

    pub fn port_id(&self) -> u16 {
        self.port_id
    }

    /// The kernel netdev's MTU. net_tap sets it to 1500 when it creates the
    /// netdev; the MTU a Port configures on the vdev does not reach it.
    pub fn kernel_mtu(&self) -> u32 {
        let mtu = mtu_ioctl(&self.iface, libc::SIOCGIFMTU, "SIOCGIFMTU", 0);
        u32::try_from(mtu).unwrap()
    }

    /// Set the kernel netdev's MTU, which bounds what the kernel sends and
    /// accepts on it.
    pub fn set_kernel_mtu(&self, mtu: u32) {
        let mtu = libc::c_int::try_from(mtu).unwrap();
        mtu_ioctl(&self.iface, libc::SIOCSIFMTU, "SIOCSIFMTU", mtu);
    }

    /// After the Port closed: the vdev is removed and the netdev is gone.
    pub fn close(mut self) {
        assert_eq!(unsafe { rte_vdev_uninit(self.vdev.as_ptr()) }, 0);
        assert_eq!(ifindex(&self.iface), 0, "{:?} left after uninit", self.iface);
        self.closed = true;
    }
}

impl Drop for TapVdev {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        // Best effort: a failure here leaves the name taken, which the next
        // TapVdev::new with it reports.
        unsafe { rte_vdev_uninit(self.vdev.as_ptr()) };
        if !std::thread::panicking() {
            panic!("TapVdev {} dropped without close", self.vdev.to_string_lossy());
        }
    }
}

/// The kernel interface index of `iface`; 0 when no such netdev exists.
pub fn ifindex(iface: &CStr) -> u32 {
    // SAFETY: `iface` is a NUL-terminated string valid for the call.
    unsafe { libc::if_nametoindex(iface.as_ptr()) }
}

/// The MTU-field `request` on `iface` with `mtu` in the request; returns the
/// field afterwards.
fn mtu_ioctl(iface: &CStr, request: libc::Ioctl, name: &str, mtu: libc::c_int) -> libc::c_int {
    // SAFETY: socket(2) takes no pointers; the result is checked before use.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0, "socket(AF_INET): {}", io::Error::last_os_error());
    // SAFETY: `fd` is a freshly opened descriptor nothing else owns.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: ifreq is plain data; all-zero bytes are a valid value.
    let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
    let bytes = iface.to_bytes();
    assert!(bytes.len() < ifreq.ifr_name.len());
    for (dst, &src) in ifreq.ifr_name.iter_mut().zip(bytes) {
        *dst = src as libc::c_char;
    }
    ifreq.ifr_ifru.ifru_mtu = mtu;
    // SAFETY: both MTU requests take a `struct ifreq *`; `ifreq` is valid and
    // writable for the call.
    let rc = unsafe { libc::ioctl(socket.as_raw_fd(), request, &mut ifreq) };
    assert_eq!(rc, 0, "{name} {iface:?}: {}", io::Error::last_os_error());
    // SAFETY: the MTU requests read and write `ifru_mtu`, a plain c_int.
    unsafe { ifreq.ifr_ifru.ifru_mtu }
}
