//! A TCP/UDP stack (smoltcp) on one DPDK port, driven from one thread.
//!
//! Start with `docs/USAGE.md` in the repository. It covers EAL, `Port`, `Stack`,
//! pool sizing, the drive calls and shutdown. Most applications open the Stack
//! through `zhida-open` instead of calling `Eal::init` and `Port::open` here.
//!
//! `make test-stack` builds `zhida-buffer` with default features as a dependency
//! of this crate (`tap-echo` also depends on it that way), so these doctests check
//! that the test-only EAL and pool helpers are not exported. They assume a
//! per-package run (`cargo test -p dpdk-smoltcp`): testing several packages at
//! once, `zhida-buffer`'s included, unifies the `testing` feature that its self
//! dev-dependency enables, and these `compile_fail` tests then fail.
//!
//! ```compile_fail,E0432
//! use zhida_buffer::ensure_eal_init;
//! ```
//! ```compile_fail,E0432
//! use zhida_buffer::acquire_test_pool;
//! ```
//! ```compile_fail,E0432
//! use zhida_buffer::TestPoolGuard;
//! ```
//! ```compile_fail,E0599
//! let _ = zhida_buffer::PoolManager::new;
//! ```
//! ```compile_fail,E0599
//! let _ = zhida_buffer::PoolManager::new_unchecked;
//! ```
//! The production API resolves through the same paths:
//! ```
//! use zhida_buffer::{Mbuf, PoolConfig, PoolCreateError, PoolManager};
//! let _ = PoolManager::new_production;
//! ```
//! Applications cannot disable receive frame drop wakes:
//! ```compile_fail,E0624
//! fn disable_wake(stack: &mut dpdk_smoltcp::Stack, h: &dpdk_smoltcp::TcpHandle) {
//!     stack.tcp_mut(h).clear_rx_wake();
//! }
//! ```
//! Applications get TCP sockets from `Stack::add_tcp(tcp::Config)`, and no public API hands out
//! an owned socket, so the MSS cap comes from the config and an admitted socket cannot be
//! overwritten with a new one. Swapping it with a socket held by another `TcpSet` or Stack is
//! unsupported:
//! ```compile_fail,E0624
//! use dpdk_smoltcp::smoltcp::socket::tcp;
//! let _ = tcp::Socket::new;
//! ```
//! ```compile_fail,E0624
//! use dpdk_smoltcp::smoltcp::socket::tcp;
//! let _ = tcp::Socket::set_mss_cap;
//! ```
//! ```compile_fail,E0624
//! fn unadmitted(set: &mut dpdk_smoltcp::smoltcp::iface::TcpSet<'static>,
//!               socket: dpdk_smoltcp::smoltcp::socket::tcp::Socket<'static>) {
//!     set.add(socket);
//! }
//! ```
//! Removing a socket from any `TcpSet` drops it, so no admitted socket can be taken out and
//! written over another one through `Stack::tcp_mut`:
//! ```compile_fail,E0308
//! use dpdk_smoltcp::smoltcp::{iface::{SocketHandle, TcpSet}, socket::tcp};
//! fn removed(set: &mut TcpSet<'static>, h: SocketHandle) -> tcp::Socket<'static> {
//!     set.remove(h).0
//! }
//! ```
//! ```compile_fail,E0624
//! use dpdk_smoltcp::smoltcp::{iface::{SocketHandle, TcpSet}, socket::tcp};
//! fn taken(set: &mut TcpSet<'static>, h: SocketHandle) -> tcp::Socket<'static> {
//!     set.take(h).0
//! }
//! ```

mod device;
mod eal;
mod handle;
mod port;
mod rx_pool;
mod stack;

pub use eal::{Eal, EalError};
pub use handle::{TcpHandle, UdpHandle};
pub use port::{
    device_info, port_by_name, DeviceInfo, Offloads, Packet, Port, PortConfig, PortError,
    PortOpenError, RxBurst,
};
pub use rx_pool::{rx_pool_count, rx_reserve, tx_reserve};
pub use smoltcp;
pub use smoltcp::phy::HeldFrames;
pub use smoltcp::socket::tcp::TcpFrame;
pub use smoltcp::iface::{
    NoRoute, TcpCounters, UdpConfig, UdpConnectError, UdpCounters, UdpDatagram, UdpSendError,
    UdpSocket, UdpSocketStats,
};
pub use stack::{
    os_random_seed, AddTcpError, AddUdpError, Sent, Stack, StackConfig, StackError, Turn,
    DEFAULT_NEIGHBOR_CAPACITY,
};
