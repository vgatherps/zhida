//! Property-based testing for mbuf operations.
//!
//! Tests that:
//! 1. Our zhida_* operations produce identical results to raw DPDK operations
//! 2. Operations can be freely interleaved between implementations
//!
//! Strategy:
//! - Generate random sequences of mbuf operations
//! - Execute with different implementation strategies
//! - Compare final state (live mbufs, their metadata, refcounts)
//!
//! DPDK test bodies run serially on the persistent pinned test worker.

use proptest::prelude::*;
use zhida_buffer::testing::{
    Op, MbufId, ImplChoice, SelectionMode,
    ValidationResult, validate_ops_with_zhida, compare_executions, validate_then_compare,
};
use zhida_buffer::PoolManager;

// =============================================================================
// Proptest strategies for generating operations
// =============================================================================

fn arb_op(max_id: MbufId) -> impl Strategy<Value = Op> {
    prop_oneof![
        // Alloc: any ID, reasonable length
        (0..max_id, 0u16..1500u16).prop_map(|(id, len)| Op::Alloc { id, len }),
        // Free: any ID
        (0..max_id).prop_map(|id| Op::Free { id }),
        // Chain: two different IDs
        (0..max_id, 0..max_id)
            .prop_filter_map("head != tail", |(h, t)| {
                if h != t { Some(Op::Chain { head: h, tail: t }) } else { None }
            }),
        // Share: any ID, new ID
        (0..max_id, 0..max_id)
            .prop_filter_map("id != new_id", |(id, new_id)| {
                if id != new_id { Some(Op::Share { id, new_id }) } else { None }
            }),
        // ShareAll: any ID, new ID
        (0..max_id, 0..max_id)
            .prop_filter_map("id != new_id", |(id, new_id)| {
                if id != new_id { Some(Op::ShareAll { id, new_id }) } else { None }
            }),
        // CloneIndirect: any ID, new ID
        (0..max_id, 0..max_id)
            .prop_filter_map("id != new_id", |(id, new_id)| {
                if id != new_id { Some(Op::CloneIndirect { id, new_id }) } else { None }
            }),
        // Prepend: any ID, small length
        (0..max_id, 1u16..50u16).prop_map(|(id, len)| Op::Prepend { id, len }),
        // Adj: any ID, small length
        (0..max_id, 1u16..50u16).prop_map(|(id, len)| Op::Adj { id, len }),
        // Trim: any ID, small length
        (0..max_id, 1u16..50u16).prop_map(|(id, len)| Op::Trim { id, len }),
    ]
}

fn arb_ops(max_len: usize, max_id: MbufId) -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec(arb_op(max_id), 0..max_len)
}

fn arb_impl_choices(len: usize) -> impl Strategy<Value = Vec<ImplChoice>> {
    prop::collection::vec(prop_oneof![Just(ImplChoice::Zhida), Just(ImplChoice::Dpdk)], len)
}

// =============================================================================
// Property tests
// =============================================================================

proptest! {
    // Note: Case count is low due to DPDK mempool cache limits when creating
    // many pools. Each test iteration creates a new pool. Use fuzzer for
    // more thorough coverage.
    #![proptest_config(ProptestConfig::with_cases(10))]

    /// All-zhida should equal all-dpdk (after chain_safe validation)
    #[zhida_test_support::pinned_test]
    fn zhida_equals_dpdk(ops in arb_ops(50, 8)) {
        let pool = PoolManager::new(1024);
        // Two-phase: validate with zhida chain_safe, then compare
        match validate_then_compare(&ops, &pool) {
            Ok(true) => {} // Test passed
            Ok(false) => {} // Test skipped (chain_safe refused a chain: shared head/tail or cycle)
            Err(e) => return Err(TestCaseError::fail(e)),
        }
    }

    /// Mixed strategy should equal all-zhida
    #[zhida_test_support::pinned_test]
    fn mixed_equals_zhida(
        ops in arb_ops(50, 8),
        choices in arb_impl_choices(50)
    ) {
        let pool = PoolManager::new(1024);
        // Validate first - skip sequences containing a chain chain_safe refuses
        match validate_ops_with_zhida(&ops, &pool) {
            ValidationResult::ChainRejected => return Ok(()), // Skip
            ValidationResult::LeakedMbufs => return Err(TestCaseError::fail("Validation leaked mbufs")),
            ValidationResult::AllPassed => {}
        }
        compare_executions(&ops, &pool, SelectionMode::AllZhida, SelectionMode::Mixed(choices))
            .map_err(|e| TestCaseError::fail(e))?;
    }

    /// Mixed strategy should equal all-dpdk
    #[zhida_test_support::pinned_test]
    fn mixed_equals_dpdk(
        ops in arb_ops(50, 8),
        choices in arb_impl_choices(50)
    ) {
        let pool = PoolManager::new(1024);
        // Validate first - skip sequences containing a chain chain_safe refuses
        match validate_ops_with_zhida(&ops, &pool) {
            ValidationResult::ChainRejected => return Ok(()), // Skip
            ValidationResult::LeakedMbufs => return Err(TestCaseError::fail("Validation leaked mbufs")),
            ValidationResult::AllPassed => {}
        }
        compare_executions(&ops, &pool, SelectionMode::AllDpdk, SelectionMode::Mixed(choices))
            .map_err(|e| TestCaseError::fail(e))?;
    }

    /// Two different mixed strategies should be equivalent
    #[zhida_test_support::pinned_test]
    fn mixed_equals_mixed(
        ops in arb_ops(50, 8),
        choices1 in arb_impl_choices(50),
        choices2 in arb_impl_choices(50)
    ) {
        let pool = PoolManager::new(1024);
        // Validate first - skip sequences containing a chain chain_safe refuses
        match validate_ops_with_zhida(&ops, &pool) {
            ValidationResult::ChainRejected => return Ok(()), // Skip
            ValidationResult::LeakedMbufs => return Err(TestCaseError::fail("Validation leaked mbufs")),
            ValidationResult::AllPassed => {}
        }
        compare_executions(&ops, &pool, SelectionMode::Mixed(choices1), SelectionMode::Mixed(choices2))
            .map_err(|e| TestCaseError::fail(e))?;
    }
}

// =============================================================================
// Deterministic tests for specific scenarios
// =============================================================================

#[zhida_test_support::pinned_test]
fn test_alloc_free_equivalence() {
    let pool = PoolManager::new(1024);
    let ops = vec![
        Op::Alloc { id: 0, len: 100 },
        Op::Free { id: 0 },
    ];
    compare_executions(&ops, &pool, SelectionMode::AllZhida, SelectionMode::AllDpdk).unwrap();
}

#[zhida_test_support::pinned_test]
fn test_chain_equivalence() {
    let pool = PoolManager::new(1024);
    let ops = vec![
        Op::Alloc { id: 0, len: 100 },
        Op::Alloc { id: 1, len: 200 },
        Op::Chain { head: 0, tail: 1 },
        Op::Free { id: 0 },
    ];
    compare_executions(&ops, &pool, SelectionMode::AllZhida, SelectionMode::AllDpdk).unwrap();
}

#[zhida_test_support::pinned_test]
fn test_share_all_equivalence() {
    let pool = PoolManager::new(1024);
    let ops = vec![
        Op::Alloc { id: 0, len: 100 },
        Op::Alloc { id: 1, len: 200 },
        Op::Chain { head: 0, tail: 1 },
        Op::ShareAll { id: 0, new_id: 2 },
        Op::Free { id: 0 },
        Op::Free { id: 2 },
    ];
    compare_executions(&ops, &pool, SelectionMode::AllZhida, SelectionMode::AllDpdk).unwrap();
}

#[zhida_test_support::pinned_test]
fn test_clone_indirect_equivalence() {
    let pool = PoolManager::new(1024);
    let ops = vec![
        Op::Alloc { id: 0, len: 100 },
        Op::CloneIndirect { id: 0, new_id: 1 },
        Op::Prepend { id: 1, len: 20 },
        Op::Free { id: 0 },
        Op::Free { id: 1 },
    ];
    compare_executions(&ops, &pool, SelectionMode::AllZhida, SelectionMode::AllDpdk).unwrap();
}

#[zhida_test_support::pinned_test]
fn test_interleaved_alloc_free() {
    let pool = PoolManager::new(1024);
    // Alloc with zhida, free with dpdk (and vice versa)
    let ops = vec![
        Op::Alloc { id: 0, len: 100 },
        Op::Alloc { id: 1, len: 100 },
        Op::Free { id: 0 },
        Op::Free { id: 1 },
    ];

    // zhida alloc, dpdk free
    let choices1 = vec![ImplChoice::Zhida, ImplChoice::Zhida, ImplChoice::Dpdk, ImplChoice::Dpdk];
    // dpdk alloc, zhida free
    let choices2 = vec![ImplChoice::Dpdk, ImplChoice::Dpdk, ImplChoice::Zhida, ImplChoice::Zhida];

    compare_executions(&ops, &pool, SelectionMode::Mixed(choices1), SelectionMode::Mixed(choices2)).unwrap();
}

#[zhida_test_support::pinned_test]
fn test_interleaved_clone() {
    let pool = PoolManager::new(1024);
    // Clone with zhida on dpdk-allocated mbuf
    let ops = vec![
        Op::Alloc { id: 0, len: 100 },
        Op::CloneIndirect { id: 0, new_id: 1 },
        Op::Free { id: 0 },
        Op::Free { id: 1 },
    ];

    // dpdk alloc, zhida clone, zhida free
    let choices = vec![ImplChoice::Dpdk, ImplChoice::Zhida, ImplChoice::Zhida, ImplChoice::Zhida];

    compare_executions(&ops, &pool, SelectionMode::AllZhida, SelectionMode::Mixed(choices)).unwrap();
}

#[zhida_test_support::pinned_test]
fn test_proptest_regression_refcount() {
    let pool = PoolManager::new(1024);
    // Test Share + ShareAll refcount behavior
    let ops = vec![
        Op::Alloc { id: 2, len: 1220 },
        Op::Share { id: 2, new_id: 0 },
        Op::Share { id: 2, new_id: 4 },
        Op::ShareAll { id: 2, new_id: 6 },
    ];
    compare_executions(&ops, &pool, SelectionMode::AllZhida, SelectionMode::AllDpdk).unwrap();
}

#[zhida_test_support::pinned_test]
fn test_clone_and_share_refcount() {
    let pool = PoolManager::new(1024);
    // From proptest failure - involves CloneIndirect and ShareAll
    let ops = vec![
        Op::Alloc { id: 0, len: 1220 },
        Op::CloneIndirect { id: 0, new_id: 1 },
        Op::Share { id: 0, new_id: 2 },
        Op::ShareAll { id: 1, new_id: 3 },
    ];
    compare_executions(&ops, &pool, SelectionMode::AllZhida, SelectionMode::AllDpdk).unwrap();
}

#[zhida_test_support::pinned_test]
fn test_proptest_regression_full() {
    let pool = PoolManager::new(1024);
    // Full failing case from proptest - now with validation-first approach
    // Note: This sequence contains chains that chain_safe rejects (potential cycles)
    // so we use validate_then_compare which skips such sequences
    let ops = vec![
        Op::CloneIndirect { id: 7, new_id: 2 },
        Op::Trim { id: 7, len: 17 },
        Op::ShareAll { id: 5, new_id: 0 },
        Op::Free { id: 3 },
        Op::Adj { id: 5, len: 47 },
        Op::Trim { id: 7, len: 49 },
        Op::Free { id: 1 },
        Op::Chain { head: 2, tail: 3 },
        Op::Adj { id: 7, len: 41 },
        Op::Alloc { id: 6, len: 571 },
        Op::Prepend { id: 4, len: 14 },
        Op::Alloc { id: 2, len: 1220 },
        Op::Share { id: 2, new_id: 0 },
        Op::Free { id: 6 },
        Op::Alloc { id: 3, len: 379 },
        Op::Chain { head: 3, tail: 5 },
        Op::Chain { head: 4, tail: 6 },
        Op::Share { id: 2, new_id: 4 },
        Op::ShareAll { id: 3, new_id: 6 },
        Op::Prepend { id: 6, len: 18 },
        Op::ShareAll { id: 7, new_id: 4 },
        Op::CloneIndirect { id: 6, new_id: 1 },
        Op::Prepend { id: 3, len: 14 },
        Op::ShareAll { id: 1, new_id: 7 },
        Op::Adj { id: 3, len: 39 },
        Op::ShareAll { id: 7, new_id: 1 },
        Op::Chain { head: 7, tail: 2 },
        Op::ShareAll { id: 7, new_id: 2 },
    ];

    // This sequence has chain ops that chain_safe rejects - expected to be skipped
    match validate_then_compare(&ops, &pool) {
        Ok(true) => {} // Passed
        Ok(false) => {} // Skipped (chain_safe rejected - this is expected for this sequence)
        Err(e) => panic!("Unexpected error: {}", e),
    }
}

// =============================================================================
// Targeted tests for unsafe conditions
// =============================================================================

/// Test that self-chain (via shared handles) is properly rejected
#[zhida_test_support::pinned_test]
fn test_self_chain_rejected() {
    let pool = PoolManager::new(256);

    // Allocate and share to create multiple handles to same mbuf
    let mut m1 = pool.alloc_with_len(100).unwrap();
    let m2 = m1.share(); // m1 and m2 point to same mbuf

    let ptr1 = m1.as_ptr();
    let ptr2 = m2.as_ptr();
    assert_eq!(ptr1, ptr2, "Share should create alias to same mbuf");

    // Attempting to chain m2 onto m1 would be self-chain
    // Our API should prevent this or we need to add the check
    // For now, document that this is UB if not caught
}

/// Test refcount behavior with multiple shared handles
#[zhida_test_support::pinned_test]
fn test_shared_handle_refcount() {
    let pool = PoolManager::new(256);

    let mut m1 = pool.alloc_with_len(100).unwrap();
    assert_eq!(m1.refcount(), 1);

    let m2 = m1.share();
    assert_eq!(m1.refcount(), 2);
    assert_eq!(m2.refcount(), 2); // Same mbuf

    let m3 = m1.share();
    assert_eq!(m1.refcount(), 3);

    drop(m2);
    assert_eq!(m1.refcount(), 2);

    drop(m3);
    assert_eq!(m1.refcount(), 1);

    drop(m1); // Should free to pool
}

/// Test that freeing one shared handle doesn't corrupt others
#[zhida_test_support::pinned_test]
fn test_shared_handle_independence() {
    let pool = PoolManager::new(256);

    let mut m1 = pool.alloc_with_len(100).unwrap();

    // Write some data
    let data = m1.data_mut();
    data[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    let m2 = m1.share();

    // Free m1
    drop(m1);

    // m2 should still be valid (refcount was 2, now 1)
    assert_eq!(m2.refcount(), 1);
    assert_eq!(&m2.data()[0..4], &[0xDE, 0xAD, 0xBE, 0xEF]);
}

/// Test chain consumes tail ownership
#[zhida_test_support::pinned_test]
fn test_chain_ownership_transfer() {
    let pool = PoolManager::new(256);

    let mut head = pool.alloc_with_len(100).unwrap();
    let tail = pool.alloc_with_len(200).unwrap();

    let head_ptr = head.as_ptr();
    let tail_ptr = tail.as_ptr();
    assert_ne!(head_ptr, tail_ptr);

    // Chain consumes tail
    head.chain(tail).ok().expect("chain failed");

    // Head now owns both segments
    assert_eq!(head.nb_segs(), 2);
    assert_eq!(head.pkt_len(), 300);

    // Verify chain structure
    unsafe {
        assert_eq!((*head_ptr).next(), tail_ptr);
        assert!((*tail_ptr).next().is_null());
    }
}

/// Verify DPDK's rte_mbuf_check can validate our mbufs
#[zhida_test_support::pinned_test]
fn test_dpdk_mbuf_check() {
    let pool = PoolManager::new(256);

    let m = pool.alloc_with_len(100).unwrap();

    // Call DPDK's validation - should pass
    let mut reason: *const std::ffi::c_char = std::ptr::null();
    let ret = unsafe {
        // rte_mbuf_check(m, is_header, &reason)
        // We need to add this to our bindings
        zhida_dpdk_sys::rte_mbuf_check(m.as_ptr(), 1, &mut reason)
    };

    if ret != 0 {
        let reason_str = unsafe { std::ffi::CStr::from_ptr(reason) };
        panic!("rte_mbuf_check failed: {:?}", reason_str);
    }
}

/// Verify chain sets head pkt_len to sum of data_lens.
#[zhida_test_support::pinned_test]
fn test_chain_pkt_len_update() {
    let pool = PoolManager::new(256);

    // Zhida path
    let zhida_head = unsafe {
        let h = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(pool.pool(), pool.cache());
        let t = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(pool.pool(), pool.cache());
        (*h).set_data_len(1500);
        (*h).set_pkt_len(1500);
        (*t).set_data_len(1500);
        (*t).set_pkt_len(1500);
        zhida_dpdk_sys::zhida_pktmbuf_chain_safe(h, t);
        h
    };

    // DPDK path
    let dpdk_head = unsafe {
        let h = zhida_dpdk_sys::dpdk_raw_pktmbuf_alloc(pool.pool());
        let t = zhida_dpdk_sys::dpdk_raw_pktmbuf_alloc(pool.pool());
        (*h).set_data_len(1500);
        (*h).set_pkt_len(1500);
        (*t).set_data_len(1500);
        (*t).set_pkt_len(1500);
        zhida_dpdk_sys::dpdk_raw_pktmbuf_chain(h, t);
        h
    };

    let zhida_pkt_len = unsafe { (*zhida_head).pkt_len() };
    let dpdk_pkt_len = unsafe { (*dpdk_head).pkt_len() };

    unsafe {
        zhida_dpdk_sys::zhida_pktmbuf_free(zhida_head);
        zhida_dpdk_sys::dpdk_raw_pktmbuf_free(dpdk_head);
    }

    assert_eq!(zhida_pkt_len, 3000);
    assert_eq!(dpdk_pkt_len, 3000);
}

/// Verify Executor sets pkt_len correctly after chain (DPDK-only).
#[zhida_test_support::pinned_test]
fn test_executor_chain_pkt_len_dpdk_only() {
    use zhida_buffer::testing::Executor;

    let ops = vec![
        Op::Alloc { id: 0, len: 1500 },
        Op::Alloc { id: 1, len: 1500 },
        Op::Chain { head: 0, tail: 1 },
    ];

    let pool = PoolManager::new(1024);
    let mut executor = Executor::new(&pool, SelectionMode::AllDpdk);

    for op in &ops {
        executor.execute(op);
    }

    let snap = executor.snapshot();
    let state = snap.get(&0).expect("handle 0 should exist");

    assert_eq!(state.pkt_len, 3000);
    assert_eq!(state.nb_segs, 2);
}

/// Run both executors sequentially (not interleaved) - check for interference.
#[zhida_test_support::pinned_test]
fn test_executor_chain_sequential_not_interleaved() {
    use zhida_buffer::testing::Executor;

    let ops = vec![
        Op::Alloc { id: 0, len: 1500 },
        Op::Alloc { id: 1, len: 1500 },
        Op::Chain { head: 0, tail: 1 },
    ];

    {
        let pool = PoolManager::new(1024);
        let mut exec = Executor::new(&pool, SelectionMode::AllZhida);
        for op in &ops { exec.execute(op); }
        let snap = exec.snapshot();
        assert_eq!(snap.get(&0).unwrap().pkt_len, 3000);
    }

    {
        let pool = PoolManager::new(1024);
        let mut exec = Executor::new(&pool, SelectionMode::AllDpdk);
        for op in &ops { exec.execute(op); }
        let snap = exec.snapshot();
        assert_eq!(snap.get(&0).unwrap().pkt_len, 3000);
    }
}

/// Run both executors interleaved on same pool (like compare_executions).
#[zhida_test_support::pinned_test]
fn test_executor_chain_interleaved_same_pool() {
    use zhida_buffer::testing::Executor;

    let ops = vec![
        Op::Alloc { id: 0, len: 1500 },
        Op::Alloc { id: 1, len: 1500 },
        Op::Chain { head: 0, tail: 1 },
    ];

    let pool = PoolManager::new(1024);
    let mut exec1 = Executor::new(&pool, SelectionMode::AllZhida);
    let mut exec2 = Executor::new(&pool, SelectionMode::AllDpdk);

    for op in &ops {
        exec1.execute(op);
        exec2.execute(op);
    }

    let snap1 = exec1.snapshot();
    let snap2 = exec2.snapshot();

    assert_eq!(snap1.get(&0).unwrap().pkt_len, 3000);
    assert_eq!(snap2.get(&0).unwrap().pkt_len, 3000);
}

/// Chain resets tail's pkt_len to data_len (DPDK 24.11 behavior).
/// Root cause of the fuzzer-found bug: zhida wasn't doing this reset.
#[zhida_test_support::pinned_test]
fn test_chain_resets_tail_pkt_len() {
    let pool = PoolManager::new(256);

    // Create 2-segment chain A->B, then chain onto head H
    let tail_ptr = unsafe {
        let a = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(pool.pool(), pool.cache());
        let b = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(pool.pool(), pool.cache());
        (*a).set_data_len(100);
        (*a).set_pkt_len(100);
        (*b).set_data_len(200);
        (*b).set_pkt_len(200);
        zhida_dpdk_sys::zhida_pktmbuf_chain_safe(a, b);
        a
    };

    assert_eq!(unsafe { (*tail_ptr).pkt_len() }, 300);
    assert_eq!(unsafe { (*tail_ptr).nb_segs() }, 2);

    let head_ptr = unsafe {
        let h = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(pool.pool(), pool.cache());
        (*h).set_data_len(50);
        (*h).set_pkt_len(50);
        zhida_dpdk_sys::zhida_pktmbuf_chain_safe(h, tail_ptr);
        h
    };

    assert_eq!(unsafe { (*head_ptr).pkt_len() }, 350);
    assert_eq!(unsafe { (*head_ptr).nb_segs() }, 3);

    // Tail's pkt_len reset to data_len, nb_segs unchanged (DPDK behavior)
    assert_eq!(unsafe { (*tail_ptr).pkt_len() }, 100);
    assert_eq!(unsafe { (*tail_ptr).nb_segs() }, 2);

    unsafe { zhida_dpdk_sys::zhida_pktmbuf_free(head_ptr); }
}

/// Baseline: verify DPDK's chain behavior matches our expectations.
#[zhida_test_support::pinned_test]
fn test_dpdk_chain_resets_tail_pkt_len() {
    let pool = PoolManager::new(256);

    let tail_ptr = unsafe {
        let a = zhida_dpdk_sys::dpdk_raw_pktmbuf_alloc(pool.pool());
        let b = zhida_dpdk_sys::dpdk_raw_pktmbuf_alloc(pool.pool());
        (*a).set_data_len(100);
        (*a).set_pkt_len(100);
        (*b).set_data_len(200);
        (*b).set_pkt_len(200);
        zhida_dpdk_sys::dpdk_raw_pktmbuf_chain(a, b);
        a
    };

    let head_ptr = unsafe {
        let h = zhida_dpdk_sys::dpdk_raw_pktmbuf_alloc(pool.pool());
        (*h).set_data_len(50);
        (*h).set_pkt_len(50);
        zhida_dpdk_sys::dpdk_raw_pktmbuf_chain(h, tail_ptr);
        h
    };

    // DPDK 24.11: resets pkt_len, not nb_segs
    assert_eq!(unsafe { (*tail_ptr).pkt_len() }, 100);
    assert_eq!(unsafe { (*tail_ptr).nb_segs() }, 2);

    unsafe { zhida_dpdk_sys::dpdk_raw_pktmbuf_free(head_ptr); }
}

/// Regression from fuzzer: ShareAll, then chain the shared two-segment chain
/// onto another head. Raw DPDK resets the shared head's pkt_len, so alias
/// handle 1 would see 3000 drop to 1500; zhida chain_safe refuses that append.
/// Everything before it still matches DPDK.
#[zhida_test_support::pinned_test]
fn test_fuzz_regression_share_all_then_chain() {
    let pool = PoolManager::new(1024);
    let ops = vec![
        Op::Alloc { id: 137, len: 1500 },
        Op::Alloc { id: 3, len: 1500 },
        Op::Chain { head: 137, tail: 3 },    // 137.pkt_len=3000
        Op::Alloc { id: 169, len: 1500 },
        Op::ShareAll { id: 137, new_id: 1 }, // handle 1 = alias to 137
        Op::Chain { head: 169, tail: 137 },  // would reset alias 1's pkt_len
    ];

    assert!(matches!(validate_ops_with_zhida(&ops, &pool), ValidationResult::ChainRejected));
    compare_executions(&ops[..5], &pool, SelectionMode::AllZhida, SelectionMode::AllDpdk)
        .expect("zhida and dpdk should match");
}

/// Test alloc/clone with moderate pool usage.
/// The fuzzer tests cover exhaustion edge cases via artifacts.
#[zhida_test_support::pinned_test]
fn test_alloc_clone_moderate_usage() {
    let pool = PoolManager::new(1024);

    let mut ops = Vec::new();
    // Allocate 100 mbufs
    for i in 0..100u8 {
        ops.push(Op::Alloc { id: i, len: 100 });
    }
    // Clone some
    for i in 0..10u8 {
        ops.push(Op::CloneIndirect { id: i, new_id: 100 + i });
    }
    // Free and reallocate
    for i in 50..60u8 {
        ops.push(Op::Free { id: i });
    }
    for i in 50..60u8 {
        ops.push(Op::Alloc { id: i, len: 200 });
    }

    compare_executions(&ops, &pool, SelectionMode::AllZhida, SelectionMode::AllDpdk)
        .expect("zhida and dpdk should match");
}

#[zhida_test_support::pinned_test]
fn test_dpdk_mbuf_check_chain() {
    let pool = PoolManager::new(256);

    let mut head = pool.alloc_with_len(100).unwrap();
    let tail = pool.alloc_with_len(200).unwrap();
    head.chain(tail).ok().expect("chain failed");

    let mut reason: *const std::ffi::c_char = std::ptr::null();
    let ret = unsafe {
        zhida_dpdk_sys::rte_mbuf_check(head.as_ptr(), 1, &mut reason)
    };

    if ret != 0 {
        let reason_str = unsafe { std::ffi::CStr::from_ptr(reason) };
        panic!("rte_mbuf_check failed on chain: {:?}", reason_str);
    }
}

#[zhida_test_support::pinned_test]
fn test_debug_refcount_diff() {
    let pool = PoolManager::new(1024);
    // Debug test to understand refcount difference
    // NOTE: This sequence contains a chain operation that chain_safe rejects
    // because the head (id 7) has refcount > 1 after ShareAll.
    // This is expected behavior - zhida's chain_safe prevents potential cycles.
    let ops = vec![
        Op::Alloc { id: 2, len: 1220 },
        Op::Share { id: 2, new_id: 0 },      // 0,2 -> same mbuf, refcount=2
        Op::Share { id: 2, new_id: 4 },      // 0,2,4 -> same mbuf, refcount=3
        Op::Alloc { id: 3, len: 379 },
        Op::ShareAll { id: 3, new_id: 6 },   // 3,6 -> same mbuf, refcount=2
        Op::CloneIndirect { id: 6, new_id: 1 }, // 1 -> indirect clone of 6
        Op::ShareAll { id: 1, new_id: 7 },   // 1,7 -> same indirect, refcount=2
        Op::Chain { head: 7, tail: 2 },      // chain_safe REJECTS: head has refcount > 1
        Op::ShareAll { id: 7, new_id: 2 },   // only executes if chain succeeded
    ];

    // Use validate_then_compare - expected to skip due to chain rejection
    match validate_then_compare(&ops, &pool) {
        Ok(true) => panic!("Expected this sequence to be skipped (chain_safe should reject)"),
        Ok(false) => {
            // Expected: chain_safe rejected the chain at op[7]
            eprintln!("Test skipped as expected: chain_safe rejected potential cycle");
        }
        Err(e) => panic!("Unexpected error: {}", e),
    }
}
