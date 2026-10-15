//! Tests for shared buffer behavior.
//!
//! Mutation safety model:
//! - share() increments refcount, both views point to same mbuf
//! - data_mut(): requires refcnt==1 AND NOT indirect (panics otherwise)
//! - prepend(): writes in place only into headroom that is exclusively ours
//!   (refcnt==1, and an indirect head the only holder of its backing buffer);
//!   otherwise links a fresh header segment, leaving the old head unchanged
//! - adj/trim: require refcnt==1 (panics otherwise); on an indirect clone they
//!   change only the clone's own header

mod common;

use common::assert_returned_exactly_once;
use zhida_buffer::PoolManager;

// DPDK provides RTE_PKTMBUF_HEADROOM (128 bytes)
const DPDK_HEADROOM: u16 = 128;

#[zhida_test_support::pinned_test]
fn test_share_creates_alias() {
    let pool = PoolManager::new(256);
    let mut mbuf = pool.alloc_with_len(100).unwrap();
    mbuf.data_mut().fill(0xAA);

    let clone = mbuf.share();
    assert_eq!(mbuf.refcount(), 2);
    assert_eq!(clone.refcount(), 2);

    // Both see the same data
    assert!(mbuf.data().iter().all(|&b| b == 0xAA));
    assert!(clone.data().iter().all(|&b| b == 0xAA));
}

#[zhida_test_support::pinned_test]
fn test_shared_prepend_adds_header_segment() {
    let pool = PoolManager::new(256);
    let mut mbuf = pool.alloc_with_len(100).unwrap();
    mbuf.data_mut().fill(0xAA);
    let old_head = mbuf.as_ptr();

    let clone = mbuf.share();

    mbuf.prepend(20).expect("header segment").fill(0xBB);
    assert_eq!(mbuf.next(), Some(old_head));
    assert_eq!((mbuf.len(), mbuf.pkt_len(), mbuf.nb_segs()), (20, 120, 2));
    assert!(mbuf.data().iter().all(|&b| b == 0xBB));

    // The other holder still sees the unchanged single-segment packet.
    assert_eq!(clone.as_ptr(), old_head);
    assert_eq!((clone.headroom(), clone.len(), clone.pkt_len()), (DPDK_HEADROOM, 100, 100));
    assert_eq!((clone.nb_segs(), clone.refcount()), (1, 2));
    assert!(clone.data().iter().all(|&b| b == 0xAA));

    drop(mbuf);
    assert_eq!(clone.refcount(), 1);
    drop(clone);
    assert_returned_exactly_once(&pool, 256);
}

#[zhida_test_support::pinned_test]
fn test_clone_trait_increments_refcount() {
    let pool = PoolManager::new(256);
    let mbuf = pool.alloc_with_len(100).unwrap();
    let clone = mbuf.clone();
    assert_eq!(mbuf.refcount(), 2);
    assert_eq!(clone.refcount(), 2);
}

#[zhida_test_support::pinned_test]
fn test_multiple_shares() {
    let pool = PoolManager::new(256);
    let mut mbuf = pool.alloc_with_len(100).unwrap();
    mbuf.data_mut().fill(0xFF);

    let clone1 = mbuf.share();
    let clone2 = mbuf.share();
    let clone3 = mbuf.share();

    assert_eq!(mbuf.refcount(), 4);

    assert!(mbuf.data().iter().all(|&b| b == 0xFF));
    assert!(clone1.data().iter().all(|&b| b == 0xFF));
    assert!(clone2.data().iter().all(|&b| b == 0xFF));
    assert!(clone3.data().iter().all(|&b| b == 0xFF));
}

#[zhida_test_support::pinned_test]
fn test_prepend_then_share() {
    let pool = PoolManager::new(256);
    let mut mbuf = pool.alloc_with_len(100).unwrap();
    mbuf.data_mut().fill(0xDD);

    mbuf.prepend(20).unwrap().fill(0xAA);

    let data = mbuf.data();
    assert!(data[0..20].iter().all(|&b| b == 0xAA));
    assert!(data[20..120].iter().all(|&b| b == 0xDD));

    let clone = mbuf.share();
    assert_eq!(mbuf.len(), clone.len());
}

#[zhida_test_support::pinned_test]
fn test_drop_clones_safely() {
    let pool = PoolManager::new(256);
    let mut mbuf = pool.alloc_with_len(100).unwrap();
    mbuf.data_mut().fill(0xCC);

    {
        let _clone1 = mbuf.share();
        let _clone2 = mbuf.share();
    }

    assert_eq!(mbuf.refcount(), 1);
    assert!(mbuf.data().iter().all(|&b| b == 0xCC));
}

#[zhida_test_support::pinned_test]
fn test_insufficient_headroom() {
    let pool = PoolManager::new(256);
    let mut mbuf = pool.alloc_with_len(100).unwrap();
    mbuf.data_mut().fill(0xDD);
    let old_head = mbuf.as_ptr();

    // DPDK has 128 bytes headroom; 150 bytes go into a new header segment.
    mbuf.prepend(150).expect("header segment").fill(0xAA);
    assert_eq!(mbuf.next(), Some(old_head));
    assert_eq!((mbuf.len(), mbuf.pkt_len(), mbuf.nb_segs()), (150, 250, 2));

    // Old head unchanged
    let old = unsafe { &*old_head };
    assert_eq!((old.data_off(), old.data_len(), old.pkt_len()), (DPDK_HEADROOM, 100, 100));
    assert_eq!((old.nb_segs(), old.refcnt()), (1, 1));
    drop(mbuf);
    assert_returned_exactly_once(&pool, 256);
}

#[zhida_test_support::pinned_test]
fn test_headroom_available() {
    let pool = PoolManager::new(256);
    let mbuf = pool.alloc_with_len(100).unwrap();
    assert_eq!(mbuf.headroom(), DPDK_HEADROOM);
}

#[zhida_test_support::pinned_test]
fn test_adj_increases_headroom() {
    let pool = PoolManager::new(256);
    let mut mbuf = pool.alloc_with_len(100).unwrap();
    let initial_headroom = mbuf.headroom();

    // Consume 20 bytes from front
    assert!(mbuf.adj(20));
    assert_eq!(mbuf.len(), 80);
    assert_eq!(mbuf.headroom(), initial_headroom + 20);

    // Can now prepend into the consumed space
    let hdr = mbuf.prepend(20).expect("Should prepend into consumed space");
    hdr.fill(0xAA);
    assert_eq!(mbuf.len(), 100);
}
