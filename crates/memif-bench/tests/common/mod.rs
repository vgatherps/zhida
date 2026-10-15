//! Both ends of one net_memif connection in one process: the server vdev
//! first, then the client on the same abstract socket, a new one per pair.

use std::ffi::{CStr, CString};
use std::mem::ManuallyDrop;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use dpdk_smoltcp::{Port, PortConfig};
use memif_bench::memif::{Memif, MemifVdev, Role};
use zhida_dpdk_sys::*;

use zhida_test_kit::with_eal;

pub const DEADLINE: Duration = Duration::from_secs(2);

/// Vdev and pool names; reusable once the pair using them is closed.
pub struct Names {
    pub server: CString,
    pub client: CString,
    pub server_rx: CString,
    pub server_tx: CString,
    pub client_rx: CString,
    pub client_tx: CString,
}

/// Vdev and pool names unique to `tag`.
pub fn names(tag: &str) -> Names {
    let name = |suffix: &str| CString::new(format!("{tag}_{suffix}")).unwrap();
    Names {
        server: CString::new(format!("net_memif_{tag}_s")).unwrap(),
        client: CString::new(format!("net_memif_{tag}_c")).unwrap(),
        server_rx: name("srx"),
        server_tx: name("stx"),
        client_rx: name("crx"),
        client_tx: name("ctx"),
    }
}

/// An abstract socket name never used before in this process (or by another
/// process at the same time). Works around a DPDK 25.11.3 memif bug: when
/// the last device on a listening socket closes, memif never closes the
/// listening fd nor unregisters its interrupt callback
/// (memif_socket_remove_device), so the name stays bound and a new server on
/// it in the same process fails.
pub fn fresh_socket() -> String {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    format!("zhida_memif_{}_{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))
}

/// One end: the vdev and the Port opened on it. The Port is never dropped:
/// dropping it while the link is up closes it without the ordered close, so a
/// test that panics before `close_pair` leaks it.
pub struct End {
    pub vdev: MemifVdev,
    pub port: ManuallyDrop<Port>,
}

/// Open the server, then the client, on a `fresh_socket` with
/// `config(port_id, rx_pool, tx_pool)`, and wait until both links are up. If
/// a wait fails its connect handling may still run, so both Ports are
/// leaked, never dropped.
pub fn open_pair(
    names: &Names,
    log2_ring_size: u8,
    config: impl for<'a> Fn(u16, &'a CStr, &'a CStr) -> PortConfig<'a>,
) -> (End, End) {
    let socket = fresh_socket();
    with_eal(|eal| {
        let open = |vdev: &CStr, role, rx: &CStr, tx: &CStr| {
            let memif = Memif { vdev, role, id: 0, socket: &socket, log2_ring_size };
            let (vdev, port) = unsafe { MemifVdev::open(eal, &memif, |id| config(id, rx, tx)) }.unwrap();
            End { vdev, port: ManuallyDrop::new(port) }
        };
        let server = open(&names.server, Role::Server, &names.server_rx, &names.server_tx);
        let client = open(&names.client, Role::Client, &names.client_rx, &names.client_tx);
        let up = server.vdev.wait_link_up(DEADLINE).and_then(|()| client.vdev.wait_link_up(DEADLINE));
        if let Err(error) = up {
            std::mem::forget((server, client));
            panic!("memif link up: {error}");
        }
        (server, client)
    })
}

/// Close `first`, then `second` behind the close barrier; all pools are gone.
/// On any failure the Ports not yet closed are leaked (`End`).
pub fn close_pair(first: End, second: End, names: &Names) {
    first.vdev.close(ManuallyDrop::into_inner(first.port)).unwrap();
    match second.vdev.close_after_peer(ManuallyDrop::into_inner(second.port), DEADLINE) {
        Ok(closed) => closed.unwrap(),
        Err((_, port, error)) => {
            std::mem::forget(port);
            panic!("close barrier: {error}");
        }
    }
    for name in [&names.server_rx, &names.server_tx, &names.client_rx, &names.client_tx] {
        assert!(unsafe { rte_mempool_lookup(name.as_ptr()) }.is_null());
    }
}
