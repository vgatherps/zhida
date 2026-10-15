//! Shared testing infrastructure for proptests and fuzzing.
//!
//! This module provides types and execution logic that can be used by:
//! - Property-based tests (proptest)
//! - Fuzz targets (cargo-fuzz/libfuzzer)
//!
//! The core abstraction is `Op` - operations on mbufs that can be generated
//! from random bytes and executed against both zhida and raw DPDK.

use std::collections::HashMap;
use std::mem::ManuallyDrop;
use std::ptr::NonNull;
use crate::{Mbuf, PoolManager, TestPoolGuard, RTE_MBUF_F_INDIRECT};
#[cfg(feature = "arbitrary")]
use crate::acquire_test_pool;
use zhida_dpdk_sys::{
    rte_mbuf, rte_mempool, rte_mempool_cache,
    dpdk_raw_pktmbuf_prepend, dpdk_raw_pktmbuf_adj, dpdk_raw_pktmbuf_trim,
};

/// Temporarily wrap a raw mbuf pointer to use Mbuf methods.
/// Does NOT take ownership - original pointer remains valid.
#[inline]
unsafe fn with_mbuf_ref<F, R>(m: *mut rte_mbuf, f: F) -> R
where
    F: FnOnce(&mut Mbuf) -> R,
{
    let mut wrapper = ManuallyDrop::new(Mbuf::from_raw(NonNull::new_unchecked(m)));
    f(&mut wrapper)
}

/// Fill entire data region with deterministic pattern.
/// Pattern: (op_index ^ id ^ seg_index) as u8 repeated.
#[inline]
unsafe fn fill_payload_pattern(m: *mut rte_mbuf, op_index: usize, id: MbufId, seg_index: usize) {
    let data_len = (*m).data_len() as usize;
    if data_len == 0 {
        return;
    }
    let data_ptr = (*m).data_ptr();
    let pattern = ((op_index ^ id as usize ^ seg_index) & 0xFF) as u8;
    std::ptr::write_bytes(data_ptr, pattern, data_len);
}

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;

/// Identifier for an mbuf in test state.
pub type MbufId = u8;

/// Operations that can be performed on mbufs.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub enum Op {
    Alloc { id: MbufId, len: u16 },
    Free { id: MbufId },
    Chain { head: MbufId, tail: MbufId },
    Share { id: MbufId, new_id: MbufId },
    ShareAll { id: MbufId, new_id: MbufId },
    CloneIndirect { id: MbufId, new_id: MbufId },
    Prepend { id: MbufId, len: u16 },
    Adj { id: MbufId, len: u16 },
    Trim { id: MbufId, len: u16 },
}

/// Snapshot of a single segment in an mbuf chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentState {
    pub data_off: u16,
    pub data_len: u16,
    pub refcount: u16,
    pub is_indirect: bool,
    pub payload_hash: u64,
}

impl SegmentState {
    /// Create snapshot from raw mbuf pointer.
    ///
    /// # Safety
    /// Pointer must be valid.
    pub unsafe fn from_raw(m: *mut rte_mbuf) -> Self {
        Self {
            data_off: (*m).data_off(),
            data_len: (*m).data_len(),
            refcount: (*m).refcnt(),
            is_indirect: ((*m).ol_flags & RTE_MBUF_F_INDIRECT) != 0,
            payload_hash: compute_payload_hash(m),
        }
    }
}

/// Simple hash of first 32 bytes (or entire data region if smaller).
unsafe fn compute_payload_hash(m: *mut rte_mbuf) -> u64 {
    let data_ptr = (*m).data_ptr();
    let data_len = (*m).data_len() as usize;
    let check_len = data_len.min(32);

    if check_len == 0 {
        return 0;
    }

    let data = std::slice::from_raw_parts(data_ptr, check_len);
    // Simple FNV-1a hash
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Snapshot of an entire mbuf chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainState {
    pub pkt_len: u32,
    pub nb_segs: u16,
    pub segments: Vec<SegmentState>,
}

impl ChainState {
    /// Create snapshot from raw mbuf pointer (head of chain).
    ///
    /// # Safety
    /// Pointer must be valid head of chain.
    pub unsafe fn from_raw(m: *mut rte_mbuf) -> Self {
        let pkt_len = (*m).pkt_len();
        let nb_segs = (*m).nb_segs();

        let mut segments = Vec::with_capacity(nb_segs as usize);
        let mut cur = m;
        while !cur.is_null() {
            segments.push(SegmentState::from_raw(cur));
            cur = (*cur).next();
        }

        Self {
            pkt_len,
            nb_segs,
            segments,
        }
    }
}

/// Legacy MbufState for backward compatibility.
/// Use ChainState for full chain comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbufState {
    pub data_off: u16,
    pub data_len: u16,
    pub pkt_len: u32,
    pub nb_segs: u16,
    pub refcount: u16,
    pub is_indirect: bool,
}

impl MbufState {
    /// Create snapshot from raw mbuf pointer.
    ///
    /// # Safety
    /// Pointer must be valid.
    pub unsafe fn from_raw(m: *mut rte_mbuf) -> Self {
        Self {
            data_off: (*m).data_off(),
            data_len: (*m).data_len(),
            pkt_len: (*m).pkt_len(),
            nb_segs: (*m).nb_segs(),
            refcount: (*m).refcnt(),
            is_indirect: ((*m).ol_flags & RTE_MBUF_F_INDIRECT) != 0,
        }
    }
}

/// Which implementation to use for an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub enum ImplChoice {
    Zhida,
    Dpdk,
}

/// Selection mode for choosing implementation per operation.
#[derive(Debug, Clone)]
pub enum SelectionMode {
    AllZhida,
    AllDpdk,
    /// Use the given sequence of choices (cycling if needed)
    Mixed(Vec<ImplChoice>),
}

impl SelectionMode {
    pub fn get(&self, op_index: usize) -> ImplChoice {
        match self {
            SelectionMode::AllZhida => ImplChoice::Zhida,
            SelectionMode::AllDpdk => ImplChoice::Dpdk,
            SelectionMode::Mixed(choices) => {
                if choices.is_empty() {
                    ImplChoice::Zhida
                } else {
                    choices[op_index % choices.len()]
                }
            }
        }
    }
}

/// Trait for pool access - allows Executor to work with different pool types.
///
/// # Safety
/// `Executor` passes these pointers straight to the zhida and DPDK allocation,
/// clone and free shims, which take the cache without locking. An implementation
/// must guarantee, for every call and on whichever thread makes it:
///
/// - `pool()` is a live pktmbuf pool whose objects had their 8-byte private slot
///   set by `zhida_pool_init_cache_ptrs` to `cache()`.
/// - `cache()` is non-null and is that pool's cache for the calling thread's
///   lcore (as returned by `zhida_get_pool_cache` on that thread), so no other
///   thread uses it at the same time.
/// - Both stay valid while `self` is borrowed and every mbuf allocated through
///   them is alive.
///
/// A safe implementation is rejected:
/// ```compile_fail,E0200
/// struct Copied(*mut zhida_dpdk_sys::rte_mempool, *mut zhida_dpdk_sys::rte_mempool_cache);
/// impl zhida_buffer::testing::PoolAccess for Copied {
///     fn pool(&self) -> *mut zhida_dpdk_sys::rte_mempool { self.0 }
///     fn cache(&self) -> *mut zhida_dpdk_sys::rte_mempool_cache { self.1 }
///     fn in_use_count(&self) -> u32 { 0 }
/// }
/// ```
/// The same implementation compiles when declared `unsafe`:
/// ```
/// struct Copied(*mut zhida_dpdk_sys::rte_mempool, *mut zhida_dpdk_sys::rte_mempool_cache);
/// unsafe impl zhida_buffer::testing::PoolAccess for Copied {
///     fn pool(&self) -> *mut zhida_dpdk_sys::rte_mempool { self.0 }
///     fn cache(&self) -> *mut zhida_dpdk_sys::rte_mempool_cache { self.1 }
///     fn in_use_count(&self) -> u32 { 0 }
/// }
/// ```
pub unsafe trait PoolAccess {
    fn pool(&self) -> *mut rte_mempool;
    fn cache(&self) -> *mut rte_mempool_cache;
    fn in_use_count(&self) -> u32;
}

// SAFETY: `acquire_test_pool` set every object's slot with
// `zhida_pool_init_cache_ptrs(pool, cache)` and rejected a null cache. The pool
// and cache are the acquiring thread's and are never freed; the guard is neither
// `Send` nor `Sync`, so every call happens on that thread.
unsafe impl PoolAccess for TestPoolGuard {
    fn pool(&self) -> *mut rte_mempool {
        TestPoolGuard::pool(self)
    }
    fn cache(&self) -> *mut rte_mempool_cache {
        TestPoolGuard::cache(self)
    }
    fn in_use_count(&self) -> u32 {
        TestPoolGuard::in_use_count(self)
    }
}

// SAFETY: every `PoolManager` constructor rejects a null cache from
// `zhida_get_pool_cache` on the creating thread and then calls
// `zhida_pool_init_cache_ptrs(pool, cache)`. `PoolManager` is neither `Send` nor
// `Sync`, so calls stay on that thread, and its pool lives until it drops.
unsafe impl PoolAccess for PoolManager {
    fn pool(&self) -> *mut rte_mempool {
        PoolManager::pool(self)
    }
    fn cache(&self) -> *mut rte_mempool_cache {
        PoolManager::cache(self)
    }
    fn in_use_count(&self) -> u32 {
        PoolManager::in_use_count(self)
    }
}

/// Executor that tracks live mbufs and executes operations.
pub struct Executor<'a, P: PoolAccess> {
    pool: &'a P,
    mbufs: HashMap<MbufId, *mut rte_mbuf>,
    mode: SelectionMode,
    op_index: usize,
}

impl<'a, P: PoolAccess> Executor<'a, P> {
    pub fn new(pool: &'a P, mode: SelectionMode) -> Self {
        Self {
            pool,
            mbufs: HashMap::new(),
            mode,
            op_index: 0,
        }
    }

    pub fn current_impl(&self) -> ImplChoice {
        self.mode.get(self.op_index)
    }

    pub fn execute(&mut self, op: &Op) -> bool {
        let result = match op {
            Op::Alloc { id, len } => self.exec_alloc(*id, *len),
            Op::Free { id } => self.exec_free(*id),
            Op::Chain { head, tail } => self.exec_chain(*head, *tail),
            Op::Share { id, new_id } => self.exec_share(*id, *new_id),
            Op::ShareAll { id, new_id } => self.exec_share_all(*id, *new_id),
            Op::CloneIndirect { id, new_id } => self.exec_clone_indirect(*id, *new_id),
            Op::Prepend { id, len } => self.exec_prepend(*id, *len),
            Op::Adj { id, len } => self.exec_adj(*id, *len),
            Op::Trim { id, len } => self.exec_trim(*id, *len),
        };
        self.op_index += 1;
        result
    }

    fn exec_alloc(&mut self, id: MbufId, len: u16) -> bool {
        if self.mbufs.contains_key(&id) {
            return false;
        }

        // Clamp to standard Ethernet MTU - avoids exhausting buffer space with jumbo frames
        let len = len.min(1500);

        let choice = self.current_impl();
        let m = match choice {
            ImplChoice::Zhida => unsafe {
                zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(self.pool.pool(), self.pool.cache())
            },
            ImplChoice::Dpdk => unsafe { zhida_dpdk_sys::dpdk_raw_pktmbuf_alloc(self.pool.pool()) },
        };

        if m.is_null() {
            return false;
        }

        // A pool whose data room cannot hold `len` refuses the op like an exhausted one.
        unsafe {
            if len > (*m).buf_len() - (*m).data_off() {
                match choice {
                    ImplChoice::Zhida => zhida_dpdk_sys::zhida_pktmbuf_free(m),
                    ImplChoice::Dpdk => zhida_dpdk_sys::dpdk_raw_pktmbuf_free(m),
                }
                return false;
            }
            (*m).set_data_len(len);
            (*m).set_pkt_len(len as u32);
        }

        // Fill payload with deterministic pattern for validation
        unsafe { fill_payload_pattern(m, self.op_index, id, 0) };

        self.mbufs.insert(id, m);
        true
    }

    fn exec_free(&mut self, id: MbufId) -> bool {
        let Some(m) = self.mbufs.remove(&id) else {
            return false;
        };

        match self.current_impl() {
            ImplChoice::Zhida => unsafe {
                zhida_dpdk_sys::zhida_pktmbuf_free(m);
            },
            ImplChoice::Dpdk => unsafe {
                zhida_dpdk_sys::dpdk_raw_pktmbuf_free(m);
            },
        }
        true
    }

    fn exec_chain(&mut self, head_id: MbufId, tail_id: MbufId) -> bool {
        if head_id == tail_id {
            return false;
        }

        let Some(&head) = self.mbufs.get(&head_id) else {
            return false;
        };
        let Some(tail) = self.mbufs.remove(&tail_id) else {
            return false;
        };

        let ret = match self.current_impl() {
            // Use chain_safe for zhida - rejects shared-head, shared-tail and cycle-creating chains
            ImplChoice::Zhida => unsafe { zhida_dpdk_sys::zhida_pktmbuf_chain_safe(head, tail) },
            ImplChoice::Dpdk => unsafe { zhida_dpdk_sys::dpdk_raw_pktmbuf_chain(head, tail) },
        };

        if ret != 0 {
            // Chain failed, restore tail
            self.mbufs.insert(tail_id, tail);
            return false;
        }
        true
    }

    fn exec_share(&mut self, id: MbufId, new_id: MbufId) -> bool {
        if self.mbufs.contains_key(&new_id) {
            return false;
        }

        let Some(&m) = self.mbufs.get(&id) else {
            return false;
        };

        // share() only works on single-segment mbufs
        if unsafe { (*m).nb_segs() } != 1 {
            return false;
        }

        match self.current_impl() {
            ImplChoice::Zhida => {
                let shared = unsafe { with_mbuf_ref(m, |mbuf| mbuf.share().into_raw().as_ptr()) };
                self.mbufs.insert(new_id, shared);
            }
            ImplChoice::Dpdk => {
                unsafe { (*m).refcnt_inc() };
                self.mbufs.insert(new_id, m);
            }
        }
        true
    }

    fn exec_share_all(&mut self, id: MbufId, new_id: MbufId) -> bool {
        if self.mbufs.contains_key(&new_id) {
            return false;
        }

        let Some(&m) = self.mbufs.get(&id) else {
            return false;
        };

        match self.current_impl() {
            ImplChoice::Zhida => {
                let shared = unsafe { with_mbuf_ref(m, |mbuf| mbuf.share_all().into_raw().as_ptr()) };
                self.mbufs.insert(new_id, shared);
            }
            ImplChoice::Dpdk => {
                // Walk chain, increment all refcounts
                let mut cur = m;
                while !cur.is_null() {
                    unsafe {
                        (*cur).refcnt_inc();
                        cur = (*cur).next();
                    }
                }
                self.mbufs.insert(new_id, m);
            }
        }
        true
    }

    fn exec_clone_indirect(&mut self, id: MbufId, new_id: MbufId) -> bool {
        if self.mbufs.contains_key(&new_id) {
            return false;
        }

        let Some(&m) = self.mbufs.get(&id) else {
            return false;
        };

        let cloned = match self.current_impl() {
            ImplChoice::Zhida => unsafe {
                zhida_dpdk_sys::zhida_pktmbuf_clone(m, self.pool.pool(), self.pool.cache())
            },
            ImplChoice::Dpdk => unsafe {
                zhida_dpdk_sys::dpdk_raw_pktmbuf_clone(m, self.pool.pool())
            },
        };

        if cloned.is_null() {
            return false;
        }

        self.mbufs.insert(new_id, cloned);
        true
    }

    fn exec_prepend(&mut self, id: MbufId, len: u16) -> bool {
        let Some(&m) = self.mbufs.get(&id) else {
            return false;
        };
        let result = match self.current_impl() {
            // Use _force to match DPDK semantics (no refcount check)
            ImplChoice::Zhida => unsafe { with_mbuf_ref(m, |mbuf| mbuf.prepend_force(len).is_some()) },
            // Use actual DPDK function
            ImplChoice::Dpdk => unsafe { !dpdk_raw_pktmbuf_prepend(m, len).is_null() },
        };
        if result && len > 0 {
            // Fill ALL prepended bytes with deterministic pattern
            let pattern = ((self.op_index ^ id as usize) & 0xFF) as u8;
            unsafe {
                let data_ptr = (*m).data_ptr();
                std::ptr::write_bytes(data_ptr, pattern, len as usize);
            }
        }
        result
    }

    fn exec_adj(&mut self, id: MbufId, len: u16) -> bool {
        let Some(&m) = self.mbufs.get(&id) else {
            return false;
        };
        match self.current_impl() {
            // Use _force to match DPDK semantics (no refcount check)
            ImplChoice::Zhida => unsafe { with_mbuf_ref(m, |mbuf| mbuf.adj_force(len)) },
            // Use actual DPDK function
            ImplChoice::Dpdk => unsafe { !dpdk_raw_pktmbuf_adj(m, len).is_null() },
        }
    }

    fn exec_trim(&mut self, id: MbufId, len: u16) -> bool {
        let Some(&m) = self.mbufs.get(&id) else {
            return false;
        };
        match self.current_impl() {
            // Use _force to match DPDK semantics (no refcount check)
            ImplChoice::Zhida => unsafe { with_mbuf_ref(m, |mbuf| mbuf.trim_force(len)) },
            // Use actual DPDK function (returns 0 on success, -1 on failure)
            ImplChoice::Dpdk => unsafe { dpdk_raw_pktmbuf_trim(m, len) == 0 },
        }
    }

    /// Get snapshot of all live mbuf states (head only, for backward compatibility).
    pub fn snapshot(&self) -> HashMap<MbufId, MbufState> {
        self.mbufs
            .iter()
            .map(|(&id, &m)| (id, unsafe { MbufState::from_raw(m) }))
            .collect()
    }

    /// Get snapshot of all live mbuf chains (full chain state including all segments).
    pub fn snapshot_chains(&self) -> HashMap<MbufId, ChainState> {
        self.mbufs
            .iter()
            .map(|(&id, &m)| (id, unsafe { ChainState::from_raw(m) }))
            .collect()
    }

    /// Get reference to tracked mbufs (for debugging).
    pub fn mbufs(&self) -> &HashMap<MbufId, *mut rte_mbuf> {
        &self.mbufs
    }
}

impl<P: PoolAccess> Drop for Executor<'_, P> {
    fn drop(&mut self) {
        for (_, m) in self.mbufs.drain() {
            unsafe { zhida_dpdk_sys::zhida_pktmbuf_free(m) };
        }
    }
}

/// Validation result for zhida chain_safe pass.
#[derive(Debug)]
pub enum ValidationResult {
    /// All ops succeeded, safe to test against dpdk
    AllPassed,
    /// A chain op was rejected by chain_safe (shared head/tail or potential cycle)
    ChainRejected,
    /// Pool leaked mbufs - something went wrong
    LeakedMbufs,
}

/// Validate ops with zhida chain_safe, detecting sequences chain_safe refuses.
pub fn validate_ops_with_zhida<P: PoolAccess>(ops: &[Op], pool: &P) -> ValidationResult {
    let mut executor = Executor::new(pool, SelectionMode::AllZhida);
    let mut chain_rejected = false;

    for op in ops {
        let result = executor.execute(op);
        if let Op::Chain { .. } = op {
            if !result {
                chain_rejected = true;
            }
        }
    }

    drop(executor);

    let in_use = pool.in_use_count();

    if in_use != 0 {
        ValidationResult::LeakedMbufs
    } else if chain_rejected {
        ValidationResult::ChainRejected
    } else {
        ValidationResult::AllPassed
    }
}

/// Compare two executions in lockstep on the same pool.
/// Both executors run interleaved on the same pool to detect memory corruption.
/// Returns Ok(()) on success or pool exhaustion (not a real divergence).
pub fn compare_executions<P: PoolAccess>(
    ops: &[Op],
    pool: &P,
    mode1: SelectionMode,
    mode2: SelectionMode,
) -> Result<(), String> {
    let mut exec1 = Executor::new(pool, mode1.clone());
    let mut exec2 = Executor::new(pool, mode2.clone());

    for (i, op) in ops.iter().enumerate() {
        let result1 = exec1.execute(op);
        let result2 = exec2.execute(op);

        if result1 != result2 {
            return Err(format!(
                "Op {} {:?} result differs: {:?}={} vs {:?}={}",
                i, op, mode1, result1, mode2, result2
            ));
        }

        // Use full chain comparison for shape and payload validation
        let snap1 = exec1.snapshot_chains();
        let snap2 = exec2.snapshot_chains();

        if snap1 != snap2 {
            return Err(format!(
                "State diverged after op {} {:?}:\n  {:?}: {:?}\n  {:?}: {:?}",
                i, op, mode1, snap1, mode2, snap2
            ));
        }
    }

    drop(exec1);
    drop(exec2);

    let in_use = pool.in_use_count();
    if in_use != 0 {
        return Err(format!("Pool leaked {} mbufs", in_use));
    }

    Ok(())
}

/// Run validation then comparison in two phases.
/// Phase 1: Validate with zhida (uses chain_safe) - skip if a chain is refused
/// Phase 2: Compare zhida vs dpdk lockstep (only if phase 1 passes)
///
/// Returns Ok(true) if test passed
/// Returns Ok(false) if test was skipped (zhida refused a chain: shared head/tail or cycle)
/// Returns Err if implementations differ or something went wrong
pub fn validate_then_compare<P: PoolAccess>(ops: &[Op], pool: &P) -> Result<bool, String> {
    match validate_ops_with_zhida(ops, pool) {
        ValidationResult::ChainRejected => {
            return Ok(false);
        }
        ValidationResult::LeakedMbufs => {
            return Err("Validation phase leaked mbufs".to_string());
        }
        ValidationResult::AllPassed => {}
    }

    compare_executions(ops, pool, SelectionMode::AllZhida, SelectionMode::AllDpdk)?;
    Ok(true)
}

/// Fuzz target entry point - run ops and verify zhida == dpdk.
/// Returns true if test passed or was skipped (chain refused by chain_safe).
/// Panics on mismatch (which libfuzzer will catch as a crash).
#[cfg(feature = "arbitrary")]
pub fn fuzz_ops(ops: &[Op]) {
    // Reuses this thread's test pool across fuzz iterations.
    let pool = acquire_test_pool();
    match validate_then_compare(ops, &pool) {
        Ok(_) => {} // Passed or skipped
        Err(e) => panic!("Fuzz failure: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PoolConfig, ensure_eal_init};
    use zhida_dpdk_sys::RTE_PKTMBUF_HEADROOM;

    #[zhida_test_support::pinned_test]
    fn alloc_longer_than_data_room_is_refused_and_returns_the_mbuf() {
        ensure_eal_init();
        // SAFETY: every test here runs on the pinned worker, which initialized EAL
        // and is its main lcore; only direct single-segment alloc and free follow,
        // and the pool drops after the executors.
        let pool = unsafe {
            PoolManager::new_production(PoolConfig {
                name: c"executor_small_room",
                count: 8,
                cache_size: 4,
                data_room_size: RTE_PKTMBUF_HEADROOM as u16 + 100,
                socket_id: -1,
            })
        }
        .unwrap();
        for mode in [SelectionMode::AllZhida, SelectionMode::AllDpdk] {
            let mut executor = Executor::new(&pool, mode);
            assert!(!executor.execute(&Op::Alloc { id: 0, len: 101 }));
            assert_eq!(pool.in_use_count(), 0);
            assert!(!executor.execute(&Op::Free { id: 0 }));

            assert!(executor.execute(&Op::Alloc { id: 1, len: 100 }));
            assert_eq!(pool.in_use_count(), 1);
            assert!(executor.execute(&Op::Free { id: 1 }));
            assert_eq!(pool.in_use_count(), 0);
        }
    }
}
