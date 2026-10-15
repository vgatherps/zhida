//! Thin DPDK mbuf wrapper for zero-copy packet processing.
//!
//! Uses DPDK rte_mbuf directly - no custom view tracking.

mod dpdk;

#[cfg(feature = "testing")]
pub mod testing;

pub use dpdk::{Mbuf, PoolConfig, PoolCreateError, PoolManager, RTE_MBUF_F_INDIRECT, SegmentIter};
#[cfg(feature = "testing")]
pub use dpdk::{TestPoolGuard, acquire_test_pool, ensure_eal_init};
