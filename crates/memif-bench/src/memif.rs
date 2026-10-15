//! A Zhida Port on a net_memif vdev in copy mode, and the barrier that
//! keeps local bursts and closes from racing the EAL interrupt thread's
//! handling of the remote end's connect and disconnect.

use std::ffi::{c_void, CStr, CString};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use dpdk_smoltcp::{Eal, Port, PortConfig, PortError, PortOpenError};
use zhida_dpdk_sys::*;

/// memif `bsize`, the same on both ends. Copy RX stays on its single-segment
/// fast path only if the RX data room after headroom holds it; copy TX only if
/// it holds the TX data room after headroom.
pub const BUFFER_SIZE: u16 = 2048;

/// Longest abstract socket name memif keeps whole: it copies the name into
/// the address with `strlcpy(sun_path + 1, name, 107)` (memif_socket.c:920,
/// 1141) and checks the length only for filesystem sockets
/// (rte_eth_memif.c:2077), so a longer name is silently truncated.
pub const MAX_SOCKET_NAME: usize = 106;

const POLL: Duration = Duration::from_micros(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Server,
    Client,
}

/// One memif vdev. A server and a client with the same `socket` and `id`
/// connect; one process may hold both if the server is created first.
#[derive(Debug, Clone, Copy)]
pub struct Memif<'a> {
    /// Vdev name, `net_memif` followed by a unique suffix.
    pub vdev: &'a CStr,
    pub role: Role,
    pub id: u32,
    /// Abstract socket name, unique per run: at most `MAX_SOCKET_NAME` bytes,
    /// without ',' or '=' (devargs separators). Never reuse a name within one
    /// process: DPDK 25.11.3 memif leaks a closed listening socket (its fd
    /// stays bound), so a later server on the same name fails. The bench
    /// opens one vdev per process; tests take a new name per pair.
    pub socket: &'a str,
    /// memif `rsize`: the ring holds `1 << log2_ring_size` descriptors.
    pub log2_ring_size: u8,
}

#[derive(Debug)]
pub enum MemifError {
    Settings(&'static str),
    Dpdk { operation: &'static str, code: i32 },
    Open(PortOpenError),
    Close(PortError),
    Timeout(&'static str),
    /// Removing the vdev after `cause` failed with `uninit_code`; the vdev
    /// may remain.
    Rollback { cause: Box<MemifError>, uninit_code: i32 },
}

impl fmt::Display for MemifError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for MemifError {}

/// A memif vdev this value created and removes on close, and the id of the
/// Port opened on it. The Port itself is returned separately so a Stack can
/// own it; `close` and `close_after_peer` take it back (`Stack::into_port`).
#[derive(Debug)]
pub struct MemifVdev {
    port_id: u16,
    vdev: CString,
}

impl MemifVdev {
    /// Create the vdev and open a Port on it with `config(port_id)`. The RX
    /// data room after headroom must hold `BUFFER_SIZE` and the TX data room
    /// after headroom must not exceed it. memif copy RX allocates 32 mbufs per
    /// call with data waiting and returns nothing if it cannot, so the RX pool
    /// count must cover the caller's staging plus 32 plus cache slack.
    ///
    /// # Safety
    /// EAL survives until the port is closed; the remaining `Port::open`
    /// obligations hold for a fresh copy-mode memif vdev. The remote end's
    /// disconnect runs `memif_disconnect` on the EAL interrupt thread, which
    /// unmaps the shared regions that `rx_burst`/`tx_burst` read without a
    /// lock: no burst may run while the remote end can disconnect. The
    /// returned Port is closed only by handing it back to this value's `close`
    /// or `close_after_peer`, never by dropping it. Either close requires that
    /// `wait_link_up` returned `Ok`; once the remote end may have closed, only
    /// `close_after_peer`, and `wait_link_up` must have returned `Ok` before
    /// the remote end closed.
    pub unsafe fn open<'a>(
        eal: &Eal,
        memif: &Memif<'_>,
        config: impl FnOnce(u16) -> PortConfig<'a>,
    ) -> Result<(Self, Port), MemifError> {
        let role = match memif.role {
            Role::Server => "server",
            Role::Client => "client",
        };
        // An unparsable devargs string is ignored whole: memif then probes a
        // default client on /run/memif.sock (rte_eth_memif.c:2025-2028).
        if memif.socket.contains([',', '=']) {
            return Err(MemifError::Settings("socket name contains ',' or '='"));
        }
        if memif.socket.len() > MAX_SOCKET_NAME {
            return Err(MemifError::Settings("socket name longer than MAX_SOCKET_NAME"));
        }
        let args = CString::new(format!(
            "role={role},id={},socket={},socket-abstract=yes,bsize={BUFFER_SIZE},rsize={},zero-copy=no",
            memif.id, memif.socket, memif.log2_ring_size
        ))
        .map_err(|_| MemifError::Settings("socket name contains NUL"))?;
        let code = rte_vdev_init(memif.vdev.as_ptr(), args.as_ptr());
        if code != 0 {
            return Err(MemifError::Dpdk { operation: "rte_vdev_init", code });
        }
        let uninit = |cause| {
            let uninit_code = rte_vdev_uninit(memif.vdev.as_ptr());
            if uninit_code != 0 {
                return MemifError::Rollback { cause: Box::new(cause), uninit_code };
            }
            cause
        };
        let mut port_id = u16::MAX;
        let code = rte_eth_dev_get_port_by_name(memif.vdev.as_ptr(), &mut port_id);
        if code != 0 {
            return Err(uninit(MemifError::Dpdk {
                operation: "rte_eth_dev_get_port_by_name",
                code,
            }));
        }
        let config = config(port_id);
        let headroom = RTE_PKTMBUF_HEADROOM as u16;
        if config.rx_pool.data_room_size < headroom + BUFFER_SIZE {
            return Err(uninit(MemifError::Settings("RX data room is below headroom + bsize")));
        }
        if config.tx_pool.data_room_size > headroom + BUFFER_SIZE {
            return Err(uninit(MemifError::Settings("TX data room exceeds headroom + bsize")));
        }
        match Port::open(eal, config) {
            Ok(port) => Ok((
                Self {
                    port_id,
                    vdev: memif.vdev.to_owned(),
                },
                port,
            )),
            // A retained Port still owns the ethdev; the vdev must stay.
            Err(error) if error.retained.is_some() => Err(MemifError::Open(error)),
            Err(error) => Err(uninit(MemifError::Open(error))),
        }
    }

    fn link_up(&self) -> Result<bool, MemifError> {
        let mut link: rte_eth_link = unsafe { std::mem::zeroed() };
        let code = unsafe { rte_eth_link_get_nowait(self.port_id, &mut link) };
        if code != 0 {
            return Err(MemifError::Dpdk { operation: "rte_eth_link_get_nowait", code });
        }
        let status = unsafe { link.__bindgen_anon_1.__bindgen_anon_1.link_status() };
        Ok(status == RTE_ETH_LINK_UP as u16)
    }

    /// Poll until the memif connection is up, then wait until the interrupt
    /// thread's connect handling has returned: it marks the link up before it
    /// finishes. Bursts move nothing before this returns `Ok`.
    ///
    /// After `Err` the connect handling may still be running: the caller must
    /// neither close nor drop the Port (dropping closes it), but retries this
    /// or leaks the Port (`std::mem::forget`).
    pub fn wait_link_up(&self, timeout: Duration) -> Result<(), MemifError> {
        let deadline = Instant::now() + timeout;
        while !self.link_up()? {
            if Instant::now() >= deadline {
                return Err(MemifError::Timeout("memif link did not come up"));
            }
            std::thread::sleep(POLL);
        }
        interrupt_thread_barrier(deadline)
    }

    /// Close `port` (this vdev's) while the remote end is still open, then
    /// remove the vdev. Ports close one at a time; the remote end then uses
    /// `close_after_peer`. A refused close keeps the port's backing (Port's
    /// drop reports it).
    pub fn close(self, port: Port) -> Result<(), MemifError> {
        port.try_close().map_err(|(_, error)| MemifError::Close(error))?;
        let code = unsafe { rte_vdev_uninit(self.vdev.as_ptr()) };
        if code != 0 {
            return Err(MemifError::Dpdk { operation: "rte_vdev_uninit", code });
        }
        Ok(())
    }

    /// Close `port` (this vdev's) after the remote end closed. The EAL
    /// interrupt thread handles the remote's disconnect: it marks the link
    /// down first and frees this end's regions and queues afterwards. Wait for
    /// link down, then for the interrupt thread to return from that handling,
    /// and only then close.
    ///
    /// If that wait fails the outer `Err` returns the port unclosed. Dropping
    /// it closes the port and may race the disconnect handling still running;
    /// the caller retries or leaks it (`std::mem::forget`). Otherwise the
    /// inner result is that of `close`.
    pub fn close_after_peer(
        self,
        port: Port,
        timeout: Duration,
    ) -> Result<Result<(), MemifError>, (Self, Port, MemifError)> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.link_up() {
                Ok(false) => break,
                Ok(true) if Instant::now() < deadline => std::thread::sleep(POLL),
                Ok(true) => {
                    return Err((self, port, MemifError::Timeout("memif link did not go down")))
                }
                Err(error) => return Err((self, port, error)),
            }
        }
        match interrupt_thread_barrier(deadline) {
            Ok(()) => Ok(self.close(port)),
            Err(error) => Err((self, port, error)),
        }
    }
}

/// Wait for an EAL alarm. Alarms run as interrupt-thread callbacks, one
/// callback at a time, so its firing proves every memif callback running when
/// it was set has returned. On failure the flag is leaked: a failed
/// `rte_eal_alarm_set` may leave the alarm queued, and a timed-out one may
/// still fire.
fn interrupt_thread_barrier(deadline: Instant) -> Result<(), MemifError> {
    let fired = Box::into_raw(Box::new(AtomicBool::new(false)));
    let code = unsafe { rte_eal_alarm_set(1, Some(alarm_fired), fired.cast()) };
    if code != 0 {
        return Err(MemifError::Dpdk { operation: "rte_eal_alarm_set", code });
    }
    while !unsafe { &*fired }.load(Ordering::Acquire) {
        if Instant::now() >= deadline {
            return Err(MemifError::Timeout("EAL alarm did not fire"));
        }
        std::thread::sleep(POLL);
    }
    drop(unsafe { Box::from_raw(fired) });
    Ok(())
}

unsafe extern "C" fn alarm_fired(arg: *mut c_void) {
    (*arg.cast::<AtomicBool>()).store(true, Ordering::Release);
}
