#![deny(unsafe_code)]
// Since we have many different flags that can come on and off, we expect some variables to
// be unused sometimes, and we allow that.
#![cfg_attr(not(ci_forbid_unused), allow(unused, irrefutable_let_patterns))]

//! The _smoltcp_ library is built in a layered structure, with the layers corresponding
//! to the levels of API abstraction. Only the highest layers would be used by a typical
//! application; however, the goal of _smoltcp_ is not just to provide a simple interface
//! for writing applications but also to be a toolbox of networking primitives, so
//! every layer is fully exposed and documented.
//!
//! When discussing networking stacks and layering, often the [OSI model][osi] is invoked.
//! _smoltcp_ makes no effort to conform to the OSI model as it is not applicable to TCP/IP.
//!
//! # The socket layer
//! The socket layer APIs are provided in the module [socket](socket/index.html); currently,
//! TCP sockets are provided. The socket API provides the usual primitives,
//! but necessarily differs in many from the [Berkeley socket API][berk], as the latter was
//! not designed to be used without heap allocation.
//!
//! The socket layer provides the buffering, packet construction and validation, and (for
//! stateful sockets) the state machines, but it is interface-agnostic. An application must
//! use sockets together with a network interface.
//!
//! # The interface layer
//! The interface layer APIs are provided in the module [iface](iface/index.html); currently,
//! Ethernet interface is provided.
//!
//! The interface layer handles the control messages, physical addressing and neighbor discovery.
//! It routes packets to and from sockets.
//!
//! # The physical layer
//! The physical layer APIs are provided in the module [phy](phy/index.html); currently,
//! only a loopback device is provided.
//!
//! The physical layer handles interaction with a platform-specific network device.
//!
//! # The wire layers
//! Unlike the higher layers, the wire layer APIs will not be used by a typical application.
//! They however are the bedrock of _smoltcp_, and everything else is built on top of them.
//!
//! The wire layer APIs are designed by the principle "make illegal states ir-representable".
//! If a wire layer object can be constructed, then it can also be parsed from or emitted to
//! a lower level.
//!
//! The wire layer APIs also provide _tcpdump_-like pretty printing.
//!
//! ## The representation layer
//! The representation layer APIs are provided in the module [wire].
//!
//! The representation layer exists to reduce the state space of raw packets. Raw packets
//! may be nonsensical in a multitude of ways: invalid checksums, impossible combinations of flags,
//! pointers to fields out of bounds, meaningless options... Representations shed all that,
//! as well as any features not supported by _smoltcp_.
//!
//! ## The packet layer
//! The packet layer APIs are also provided in the module [wire].
//!
//! The packet layer exists to provide a more structured way to work with packets than
//! treating them as sequences of octets. It makes no judgement as to content of the packets,
//! except where necessary to provide safe access to fields, and strives to implement every
//! feature ever defined, to ensure that, when the representation layer is unable to make sense
//! of a packet, it is still logged correctly and in full.
//!
//! # Minimum Supported Rust Version (MSRV)
//!
//! This crate is guaranteed to compile on stable Rust 1.91 and up with any valid set of features.
//! It *might* compile on older versions but that may change in any new patch release.
//!
//! [wire]: wire/index.html
//! [osi]: https://en.wikipedia.org/wiki/OSI_model
//! [berk]: https://en.wikipedia.org/wiki/Berkeley_sockets

#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::redundant_field_names)]
#![allow(clippy::identity_op)]
#![allow(clippy::option_map_unit_fn)]
#![allow(clippy::unit_arg)]
#![allow(clippy::new_without_default)]

extern crate alloc;

#[macro_use]
mod macros;
mod parsers;
mod rand;

pub mod config {
    /// Maximum number of IP addresses per interface.
    pub const IFACE_MAX_ADDR_COUNT: usize = 2;
}

mod table_hash;

pub mod iface;

pub mod phy;
pub mod socket;
pub mod storage;
pub mod time;
pub mod wire;

#[cfg(test)]
mod tests;
