/*! Network interface logic.

The `iface` module deals with the *network interfaces*. It filters incoming frames,
provides lookup and caching of hardware addresses, and handles management packets.
*/

mod flow_table;
mod header_template;
mod interface;
mod path_mtu;
mod neighbor;
mod socket_meta;
mod tcp_set;
mod timer_wheel;

#[cfg(feature = "udp-set")]
mod udp_set;
mod drop_queue;

mod packet;

pub use self::interface::{
    Config, Interface, InterfaceInner as Context, NoRoute, PollIngressSingleResult, PollResult,
};

pub use self::tcp_set::{SocketHandle, TcpCounters, TcpSet, TcpStorage};
pub use self::drop_queue::DropQueue;
#[cfg(feature = "udp-set")]
pub use self::udp_set::{
    UdpAddError, UdpConfig, UdpConnectError, UdpCounters, UdpDatagram, UdpHandle,
    UdpSendError, UdpSet, UdpSocket, UdpSocketStats, UdpTarget,
};

pub use self::path_mtu::{PathMtu, PathMtus, MIN_IP_MTU};
