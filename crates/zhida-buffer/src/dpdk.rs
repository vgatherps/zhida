//! Thin Mbuf wrapper following DPDK's model directly.
//!
//! Uses rte_mbuf's data_off and data_len directly - no custom view tracking.

use std::marker::PhantomData;
use std::ptr::NonNull;
use zhida_dpdk_sys::{rte_mbuf, rte_pktmbuf_free};

/// ol_flags bit indicating mbuf is indirect (attached to another mbuf's buffer).
pub const RTE_MBUF_F_INDIRECT: u64 = 1 << 62;

/// Thin wrapper around rte_mbuf.
///
/// Follows DPDK's model directly:
/// - data_off determines where data starts
/// - data_len determines data length
/// - prepend() decreases data_off
/// - adj() increases data_off (consumed bytes become headroom)
/// - trim() decreases data_len
/// - share() increments refcount
#[derive(Debug)]
#[repr(transparent)]
pub struct Mbuf {
    mbuf: NonNull<rte_mbuf>,
    _marker: PhantomData<*const ()>, // !Send + !Sync
}

impl Mbuf {
    /// Create an Mbuf from a raw mbuf pointer.
    ///
    /// # Safety
    /// `Drop` frees with `zhida_pktmbuf_free`, not DPDK's free. It walks `next`,
    /// decrements each segment's `refcnt` without atomics (the C shim undefines
    /// `RTE_MBUF_REFCNT_ATOMIC`), and puts a segment whose count reaches zero into the
    /// `rte_mempool_cache` read from the 8 bytes right after its `rte_mbuf` header,
    /// without locking. The shim's `ASSUME` checks compile to undefined behaviour
    /// (`build.rs` builds it with `opt_level(3)`). The caller must guarantee:
    ///
    /// - The caller transfers one reference on every segment reached from `mbuf`
    ///   through `next`. The links end in NULL without a cycle, and the segments
    ///   stay valid until this `Mbuf` and every alias made from it drop.
    /// - Every segment has `data_off + data_len <= buf_len` over a valid buffer
    ///   (`data()` and `data_mut()` slice `data_len` bytes at `buf_addr + data_off`),
    ///   and the head's `nb_segs` is the segment count: `share()` takes
    ///   `nb_segs == 1` to mean single-segment and adds a reference to the head only,
    ///   while each alias's `Drop` walks `next`.
    /// - Every segment comes from a pktmbuf pool with an 8-byte private area whose
    ///   objects had that slot set by `zhida_pool_init_cache_ptrs` to a cache of the
    ///   same pool (`PoolManager` constructors do this). A full cache is flushed to
    ///   the segment's `pool`.
    /// - No segment has an external buffer (`RTE_MBUF_F_EXTERNAL`); the free path
    ///   assumes none. An indirect segment (`RTE_MBUF_F_INDIRECT`) is supported
    ///   only when attached to the buffer of a direct mbuf from a pool meeting the
    ///   requirement above. The free path finds that mbuf with
    ///   `rte_mbuf_from_indirect` (using the indirect segment's `priv_size`), drops
    ///   one reference on it non-atomically, returns it through its own cache slot
    ///   at zero, and restores the indirect segment's own buffer assuming exactly 8
    ///   private bytes.
    /// - This is called on the thread whose lcore owns the caches in those slots
    ///   (the thread that took them from `zhida_get_pool_cache`). `Mbuf` is neither
    ///   `Send` nor `Sync`, so `Drop` runs here; no other thread may use these
    ///   mbufs, their reference counts or those caches while it lives.
    /// - Every header reachable from `mbuf` (each segment, and the direct mbuf
    ///   backing an indirect segment) stays writable while this `Mbuf` or an alias
    ///   made from it lives, and no Rust reference to such a header, or to the bytes
    ///   in its buffer, may be used across a call that writes it. The wrapper takes
    ///   `&mut rte_mbuf` to the head (`share`, `adj`, `trim`, in-place `prepend`),
    ///   writes `refcnt` on every segment through raw pointers (`share_all`,
    ///   `Clone`), writes the last segment's `data_len` (`trim`) and payload bytes
    ///   (`data_mut`, `prepend`), and the C shims for `chain`, `clone_indirect`,
    ///   `clone_indirect_head`, `into_indirect_head` and `Drop` write `next`,
    ///   `nb_segs`, `pkt_len`, `refcnt`, the buffer fields and the backing mbuf's
    ///   `refcnt`, `nb_segs` and `next`. Other `Mbuf`s that hold their own counted
    ///   reference (made by `share`, `share_all`, `Clone`, `clone_indirect` or
    ///   `clone_indirect_head`) are allowed.
    #[inline]
    pub unsafe fn from_raw(mbuf: NonNull<rte_mbuf>) -> Self {
        Self {
            mbuf,
            _marker: PhantomData,
        }
    }

    /// Create an Mbuf from a raw mbuf pointer, setting initial data length.
    ///
    /// # Safety
    /// Every requirement of [`Mbuf::from_raw`]. In addition, this writes `data_len`
    /// and `pkt_len` before taking ownership, so the caller owns the header
    /// exclusively (no other reference observes it), `mbuf` is a single segment
    /// (`next == NULL`, `nb_segs == 1`) since `pkt_len` becomes `len`, and
    /// `len <= buf_len - data_off`.
    #[inline]
    pub unsafe fn from_raw_with_len(mbuf: NonNull<rte_mbuf>, len: u16) -> Self {
        (*mbuf.as_ptr()).set_data_len(len);
        (*mbuf.as_ptr()).set_pkt_len(len as u32);
        Self {
            mbuf,
            _marker: PhantomData,
        }
    }

    /// Get raw mbuf pointer.
    #[inline(always)]
    pub fn as_ptr(&self) -> *mut rte_mbuf {
        self.mbuf.as_ptr()
    }

    /// Consume Mbuf and return raw mbuf pointer.
    /// Caller takes ownership - Mbuf will not free on drop.
    #[inline]
    pub fn into_raw(self) -> NonNull<rte_mbuf> {
        let ptr = self.mbuf;
        std::mem::forget(self);
        ptr
    }

    #[inline(always)]
    fn mbuf(&self) -> &rte_mbuf {
        unsafe { self.mbuf.as_ref() }
    }

    #[inline(always)]
    fn mbuf_mut(&mut self) -> &mut rte_mbuf {
        unsafe { self.mbuf.as_mut() }
    }

    /// Data slice (from data_off, length data_len).
    #[inline(always)]
    pub fn data(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self.mbuf().data_ptr(),
                self.mbuf().data_len() as usize,
            )
        }
    }

    /// Mutable data slice. Panics if shared (refcnt > 1) or indirect.
    ///
    /// Indirect mbufs share underlying buffer with original, so mutation
    /// would affect the original even with refcnt==1.
    #[inline(always)]
    pub fn data_mut(&mut self) -> &mut [u8] {
        assert!(
            self.mbuf().refcnt() == 1,
            "data_mut() called on shared mbuf (refcount = {})",
            self.mbuf().refcnt()
        );
        assert!(
            !self.is_head_indirect(),
            "data_mut() called on indirect mbuf (shares buffer with original)"
        );
        unsafe {
            std::slice::from_raw_parts_mut(
                self.mbuf().data_ptr(),
                self.mbuf().data_len() as usize,
            )
        }
    }

    /// Try to get mutable data slice. Returns None if shared (refcnt > 1) or indirect.
    #[inline(always)]
    pub fn try_data_mut(&mut self) -> Option<&mut [u8]> {
        if self.mbuf().refcnt() != 1 || self.is_head_indirect() {
            return None;
        }
        Some(unsafe {
            std::slice::from_raw_parts_mut(
                self.mbuf().data_ptr(),
                self.mbuf().data_len() as usize,
            )
        })
    }

    /// Mutable data slice without safety checks. Matches DPDK semantics.
    ///
    /// # Safety
    /// For the lifetime of the returned slice, no other reference to these bytes
    /// (from any handle's `data()`/`iter_segs` or an earlier mutable slice) may be
    /// live, even if not read until later, and no raw-pointer access to them may
    /// occur. This covers every handle sharing the head header (`share`/`Clone`) or
    /// its backing buffer (indirect clones and the direct mbuf they attach to), and
    /// no DPDK/NIC use of such a handle (e.g. one queued for TX). Debug builds
    /// additionally assert `refcnt == 1` and not indirect.
    #[inline(always)]
    pub unsafe fn data_mut_force(&mut self) -> &mut [u8] {
        debug_assert!(
            self.mbuf().refcnt() == 1,
            "data_mut_force() on shared mbuf (refcount = {})",
            self.mbuf().refcnt()
        );
        debug_assert!(
            !self.is_head_indirect(),
            "data_mut_force() on indirect mbuf"
        );
        std::slice::from_raw_parts_mut(
            self.mbuf().data_ptr(),
            self.mbuf().data_len() as usize,
        )
    }

    /// Data length.
    #[inline(always)]
    pub fn len(&self) -> u16 {
        self.mbuf().data_len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Available headroom (bytes before data_off).
    #[inline(always)]
    pub fn headroom(&self) -> u16 {
        self.mbuf().data_off()
    }

    /// Available tailroom.
    #[inline(always)]
    pub fn tailroom(&self) -> u16 {
        self.mbuf().tailroom()
    }

    /// Prepend `n` bytes and return them for the caller to write. Never panics.
    ///
    /// Writes in place (data_off -= n) when the headroom is exclusively ours:
    /// `n <= headroom()`, `refcount() == 1`, and for an indirect head also no other
    /// holder of its backing buffer (the original, other clones), whose payload the
    /// headroom may be (e.g. after `adj`).
    ///
    /// Otherwise allocates a fresh direct header segment from this head's own pool
    /// (for an indirect head, the pool passed to `clone_indirect` etc., not the
    /// backing buffer's) and links the old head behind it. This handle's references
    /// move into the chain; no field of the old chain is written, so every other
    /// holder sees unchanged bytes and metadata. The new head carries `n` bytes at
    /// the end of its buffer, `nb_segs`/`pkt_len` of the whole packet, and the old
    /// head's DPDK header-copy metadata (port, VLAN tags, tx_offload, hash,
    /// packet_type, dynfields; ol_flags without the indirect/external bits).
    /// After this path `data()`/`len()` cover only the header segment; use
    /// `pkt_len()`/`iter_segs()` for the whole packet. The result is a chain, so
    /// `share()` on it panics (use `share_all()`/`Clone`).
    ///
    /// `prepend(0)` on a non-exclusive head returns an empty slice and changes
    /// nothing.
    ///
    /// Returns `None`, packet unchanged, when the header path is needed and the
    /// pool is exhausted, `n` exceeds the pool's data room (headroom included), or
    /// the packet already has `u16::MAX` (RTE_MBUF_MAX_NB_SEGS) segments.
    #[inline(always)]
    pub fn prepend(&mut self, n: u16) -> Option<&mut [u8]> {
        if self.mbuf().refcnt() == 1
            && (!self.is_head_indirect() || self.indirect_backing_refcnt() == 1)
        {
            if let Some(ptr) = self.mbuf_mut().prepend(n) {
                return Some(unsafe { std::slice::from_raw_parts_mut(ptr, n as usize) });
            }
        }
        self.prepend_header_segment(n)
    }

    #[cold]
    #[inline(never)]
    fn prepend_header_segment(&mut self, n: u16) -> Option<&mut [u8]> {
        if n == 0 {
            return Some(&mut []);
        }
        let head = unsafe { zhida_dpdk_sys::zhida_pktmbuf_prepend_seg(self.as_ptr(), n) };
        self.mbuf = NonNull::new(head)?;
        Some(unsafe { std::slice::from_raw_parts_mut(self.mbuf().data_ptr(), n as usize) })
    }

    /// Refcount of the direct mbuf whose buffer this indirect head is attached to
    /// (DPDK `rte_mbuf_from_indirect`). Only meaningful when the head is indirect.
    #[inline(always)]
    fn indirect_backing_refcnt(&self) -> u16 {
        let m = self.mbuf();
        unsafe {
            let direct = (m.buf_addr as *const u8)
                .sub(std::mem::size_of::<rte_mbuf>() + m.priv_size as usize)
                .cast::<rte_mbuf>();
            (*direct).refcnt()
        }
    }

    /// Prepend without sharing checks. Matches DPDK semantics.
    ///
    /// # Safety
    /// For the lifetime of the returned slice, no other reference to the prepended
    /// bytes (from any handle's `data()`/`iter_segs` or an earlier mutable slice)
    /// may be live, even if not read until later, and no raw-pointer access to them
    /// may occur. This covers every handle sharing the head header (`share`/`Clone`)
    /// or its backing buffer (indirect clones and the direct mbuf they attach to),
    /// and no DPDK/NIC use of such a handle. The head header's
    /// data_off/data_len/pkt_len change for every handle sharing it; none of them
    /// may be in use by DPDK during the call.
    #[inline(always)]
    pub unsafe fn prepend_force(&mut self, n: u16) -> Option<&mut [u8]> {
        let ptr = self.mbuf_mut().prepend(n)?;
        Some(std::slice::from_raw_parts_mut(ptr, n as usize))
    }

    /// Adjust (consume front): increase data_off by n bytes.
    /// The consumed bytes become available as headroom for future prepend.
    /// Returns false if n > data_len.
    ///
    /// # Panics
    /// Panics if refcnt > 1 (shared mbuf). Use is_head_unique() to check first.
    #[inline(always)]
    pub fn adj(&mut self, n: u16) -> bool {
        assert!(
            self.mbuf().refcnt() == 1,
            "adj() called on shared mbuf (refcount = {})",
            self.mbuf().refcnt()
        );
        self.mbuf_mut().adjust(n)
    }

    /// Adjust without refcount check. Matches DPDK semantics.
    ///
    /// # Safety
    /// The head header's data_off/data_len/pkt_len change for every handle sharing
    /// it (`share`/`Clone`); none of them may be in use by DPDK (e.g. queued for TX)
    /// during the call, and every holder must expect the new metadata.
    #[inline(always)]
    pub unsafe fn adj_force(&mut self, n: u16) -> bool {
        self.mbuf_mut().adjust(n)
    }

    /// Trim back: decrease data_len of LAST segment by n bytes.
    /// Returns false if n > last segment's data_len (does NOT propagate across segments).
    /// Matches DPDK's rte_pktmbuf_trim semantics.
    ///
    /// # Panics
    /// Panics if refcnt > 1 (shared mbuf). Use is_head_unique() to check first.
    #[inline(always)]
    pub fn trim(&mut self, n: u16) -> bool {
        assert!(
            self.mbuf().refcnt() == 1,
            "trim() called on shared mbuf (refcount = {})",
            self.mbuf().refcnt()
        );
        // For chains, tail may be shared even if head isn't (clone_indirect_head pattern)
        if self.is_chained() {
            assert!(
                self.is_tail_unique(),
                "trim() called on chain with shared tail (tail refcount = {})",
                unsafe { (*self.lastseg()).refcnt() }
            );
        }
        // DPDK trims from last segment, not head
        let lastseg = self.lastseg();
        let pkt_len = self.mbuf().pkt_len();
        unsafe {
            if n > (*lastseg).data_len() || (n as u32) > pkt_len {
                return false;
            }
            (*lastseg).set_data_len((*lastseg).data_len() - n);
        }
        self.mbuf_mut().set_pkt_len(pkt_len - n as u32);
        true
    }

    /// Trim without refcount check. Matches DPDK semantics.
    /// Trims from LAST segment.
    ///
    /// # Safety
    /// The last segment's data_len and this head's pkt_len change. No handle sharing
    /// either header may be in use by DPDK during the call, and every holder must
    /// expect the new metadata. Every other chain head reaching a shared last
    /// segment keeps its old pkt_len, so its pkt_len no longer equals the sum of
    /// its segments' data_len; the caller must not let such a head reach DPDK.
    #[inline(always)]
    pub unsafe fn trim_force(&mut self, n: u16) -> bool {
        let lastseg = self.lastseg();
        let pkt_len = self.mbuf().pkt_len();
        if n > (*lastseg).data_len() || (n as u32) > pkt_len {
            return false;
        }
        (*lastseg).set_data_len((*lastseg).data_len() - n);
        self.mbuf_mut().set_pkt_len(pkt_len - n as u32);
        true
    }

    /// Reference count of head segment.
    #[inline(always)]
    pub fn refcount(&self) -> u16 {
        self.mbuf().refcnt()
    }

    /// Check if head segment has refcount==1.
    /// Sufficient for adj. `prepend` writes in place on a direct head only when
    /// this holds (an indirect head also needs its backing buffer unshared);
    /// otherwise it links a new header segment.
    #[inline(always)]
    pub fn is_head_unique(&self) -> bool {
        self.refcount() == 1
    }

    /// Check if last segment has refcount==1.
    /// Sufficient for trim operations on tail.
    #[inline(always)]
    pub fn is_tail_unique(&self) -> bool {
        unsafe { (*self.lastseg()).refcnt() == 1 }
    }

    /// Check if this is a multi-segment chain.
    #[inline(always)]
    pub fn is_chained(&self) -> bool {
        self.nb_segs() > 1
    }

    /// Check if head segment is indirect (points to another mbuf's buffer).
    /// Only checks head - tail segments may have different indirect status.
    #[inline(always)]
    pub fn is_head_indirect(&self) -> bool {
        (self.mbuf().ol_flags & RTE_MBUF_F_INDIRECT) != 0
    }

    /// Share single-segment mbuf: increment refcount, return new Mbuf pointing to same buffer.
    /// Both Mbufs see the same header. While both live, `prepend` on either links a
    /// new header segment and the other sees no change; `adj`/`trim`/`data_mut` panic;
    /// `prepend_force`/`adj_force`/`trim_force` change the header both see.
    ///
    /// PANICS if called on multi-segment chain. Use share_all() for chains.
    #[inline(always)]
    pub fn share(&mut self) -> Mbuf {
        assert_eq!(self.nb_segs(), 1, "use share_all() for chains");
        self.mbuf_mut().refcnt_inc();
        Mbuf {
            mbuf: self.mbuf,
            _marker: PhantomData,
        }
    }

    /// Share entire chain: increment refcount on ALL segments.
    /// Both Mbufs point to the same mbuf chain. While both live, `prepend` on either
    /// links a new header segment and the other sees no change; `adj`/`trim` panic;
    /// `prepend_force`/`adj_force`/`trim_force` change segments both see.
    /// Maps to: rte_pktmbuf_refcnt_update(m, 1)
    #[inline]
    pub fn share_all(&mut self) -> Mbuf {
        let mut m = self.as_ptr();
        while !m.is_null() {
            unsafe {
                (*m).refcnt_inc();
                m = (*m).next();
            }
        }
        Mbuf {
            mbuf: self.mbuf,
            _marker: PhantomData,
        }
    }

    /// Clone chain with new indirect mbufs. Allocates from pool.
    /// Returns independent chain pointing to same buffer DATA.
    /// Each indirect has independent data_off/data_len.
    /// Maps to: rte_pktmbuf_clone
    ///
    /// Known gap: unlike DPDK `rte_pktmbuf_attach`, zhida's attach does not copy
    /// dynfields, so each indirect keeps its pool object's stale dynfields, and a
    /// header segment `prepend` links on an indirect head copies those.
    #[inline]
    pub fn clone_indirect(&self, pool: &PoolManager) -> Option<Mbuf> {
        let ptr = unsafe {
            zhida_dpdk_sys::zhida_pktmbuf_clone(self.as_ptr(), pool.pool(), pool.cache())
        };
        // Cache pointers set by alloc_fast internally
        NonNull::new(ptr).map(|p| unsafe { Mbuf::from_raw(p) })
    }

    /// Clone only head as indirect, share tail segments directly. O(n).
    /// Returns new chain: [indirect-head] -> [shared-tails...]
    /// Both chains share the same tail mbufs (refcount incremented).
    ///
    /// Known gap: the indirect head's dynfields are not copied from the original
    /// (see `clone_indirect`); a header segment prepended on it copies the stale ones.
    #[inline]
    pub fn clone_indirect_head(&self, pool: &PoolManager) -> Option<Mbuf> {
        let ptr = unsafe {
            zhida_dpdk_sys::zhida_pktmbuf_clone_indirect_head(
                self.as_ptr(),
                pool.pool(),
                pool.cache(),
            )
        };
        NonNull::new(ptr).map(|p| unsafe { Mbuf::from_raw(p) })
    }

    /// Consume self, return new chain with indirect head. O(1).
    /// [indirect-head] -> [tails...] (tail ownership transfers, no refcount bump).
    ///
    /// The conversion cuts the old head off its chain (writes `next = NULL`,
    /// `nb_segs = 1`). Returns `Err(self)`, unchanged and without allocating, when
    /// that changes a head another owner reaches: `refcount != 1` and chained.
    /// A shared single-segment head converts (nothing changes). A chained
    /// direct head with attached indirect clones is refused conservatively.
    /// An indirect head is refused: it already references its backing buffer,
    /// and the C conversion assumes a direct input (an indirect one would leak).
    /// Also returns `Err(self)` if allocation fails.
    #[inline]
    pub fn into_indirect_head(self, pool: &PoolManager) -> Result<Mbuf, Mbuf> {
        if self.is_head_indirect() || (self.refcount() != 1 && !self.mbuf().next().is_null()) {
            return Err(self);
        }
        let ptr = self.into_raw();
        let indirect = unsafe {
            zhida_dpdk_sys::zhida_pktmbuf_into_indirect_head(ptr.as_ptr(), pool.pool(), pool.cache())
        };
        match NonNull::new(indirect) {
            Some(p) => Ok(unsafe { Mbuf::from_raw(p) }),
            None => Err(unsafe { Mbuf::from_raw(ptr) }),
        }
    }

    /// Get next mbuf in chain (for multi-segment packets).
    #[inline(always)]
    pub fn next(&self) -> Option<*mut rte_mbuf> {
        let next = self.mbuf().next();
        if next.is_null() { None } else { Some(next) }
    }

    /// Get the pool this mbuf belongs to.
    #[inline(always)]
    pub fn pool(&self) -> *mut zhida_dpdk_sys::rte_mempool {
        self.mbuf().pool
    }

    // ========================================================================
    // Chain operations
    //
    // Appending writes lastseg(head).next, head.nb_segs, head.pkt_len and
    // resets tail.pkt_len to tail.data_len. `chain` refuses, writing
    // nothing, unless no other owner reaches any of those fields:
    //
    // - lastseg(head).refcount == 1. Every owner holds one reference on each
    //   segment of its chain (Clone, share_all and clone_indirect_head
    //   increment every segment they walk), and every walk through head's
    //   chain ends at lastseg. So refcount 1 there means no other owner can
    //   free through our link into the new tail or observe head's metadata.
    //   It also excludes cycles: tail is a separate owner, so a tail that
    //   contained lastseg would hold a second reference on it.
    // - tail.refcount == 1, or tail.pkt_len == tail.data_len. A shared tail
    //   is fine only when the reset is a no-op (single-segment fan-in, or a
    //   multi-segment tail trimmed so only its head carries data); the store is
    //   skipped then. A shared tail whose pkt_len != data_len is refused because
    //   its other owner would see its pkt_len change.
    //
    // Conservative: an indirect clone attached to a direct segment raises that
    // segment's refcount, so a direct lastseg with attached indirects is refused
    // even though indirects never read its link or metadata.
    //
    // Both APIs reject more than RTE_MBUF_MAX_NB_SEGS (u16::MAX) segments.
    // ========================================================================

    /// Chain another mbuf onto this one. Consumes tail. **Fastest safe option.**
    ///
    /// Refuses when another owner reaches a field the append writes (see the
    /// rule above): a shared last segment of `self`, or a shared tail whose
    /// `pkt_len` differs from its `data_len`.
    ///
    /// # Performance
    /// O(n) where n = self's segment count: one walk to lastseg, then loads of
    /// lastseg.refcount and tail refcount/pkt_len/data_len.
    ///
    /// # Returns
    /// - `Ok(())`: tail chained; its references now belong to `self`
    /// - `Err(tail)`: refused (shared fields or segment limit); both packets unchanged
    #[inline]
    #[must_use = "chain() can fail; handle the returned Result"]
    pub fn chain(&mut self, tail: Mbuf) -> Result<(), Mbuf> {
        let tail_ptr = tail.into_raw();
        let ret = unsafe {
            zhida_dpdk_sys::zhida_pktmbuf_chain_safe(self.mbuf.as_ptr(), tail_ptr.as_ptr())
        };
        if ret == 0 {
            Ok(())
        } else {
            // ret == -1: shared fields; ret == -EOVERFLOW: too many segments
            Err(unsafe { Mbuf::from_raw(tail_ptr) })
        }
    }

    /// Number of segments in this chain.
    #[inline(always)]
    pub fn nb_segs(&self) -> u16 {
        self.mbuf().nb_segs()
    }

    /// Total packet length across all segments.
    #[inline(always)]
    pub fn pkt_len(&self) -> u32 {
        self.mbuf().pkt_len()
    }

    /// Get last segment in chain.
    #[inline]
    pub fn lastseg(&self) -> *mut rte_mbuf {
        unsafe { zhida_dpdk_sys::rte_pktmbuf_lastseg(self.mbuf.as_ptr()) }
    }

    /// Iterate over segments in this chain.
    ///
    /// The iterator borrows `self`, so the owner cannot be dropped while it is live:
    // Stable rustdoc ignores the E0505 code (verified: E0599 also passed); any compile error passes.
    /// ```compile_fail,E0505
    /// fn segments_outlive_owner(pool: &zhida_buffer::PoolManager) {
    ///     let mbuf = pool.alloc().unwrap();
    ///     let mut segments = mbuf.iter_segs();
    ///     drop(mbuf);
    ///     segments.next();
    /// }
    /// ```
    /// Dropping the owner after the iterator's last use compiles:
    /// ```no_run
    /// fn segments_within_owner(pool: &zhida_buffer::PoolManager) {
    ///     let mbuf = pool.alloc().unwrap();
    ///     let mut segments = mbuf.iter_segs();
    ///     segments.next();
    ///     drop(mbuf);
    /// }
    /// ```
    #[inline]
    pub fn iter_segs(&self) -> SegmentIter<'_> {
        SegmentIter {
            current: Some(self.mbuf.as_ptr()),
            _owner: PhantomData,
        }
    }
}

/// Iterator over segments in an mbuf chain.
///
/// Borrows the owning `Mbuf`: the owner cannot be dropped or mutated while it is live.
pub struct SegmentIter<'a> {
    current: Option<*mut rte_mbuf>,
    _owner: PhantomData<&'a Mbuf>,
}

impl Iterator for SegmentIter<'_> {
    type Item = *mut rte_mbuf;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.current?;
        self.current = unsafe {
            let next = (*cur).next();
            if next.is_null() { None } else { Some(next) }
        };
        Some(cur)
    }
}

impl Clone for Mbuf {
    /// Clone increments refcount on ALL segments.
    /// Same as share_all() but takes &self.
    #[inline(always)]
    fn clone(&self) -> Self {
        let mut m = self.mbuf.as_ptr();
        while !m.is_null() {
            unsafe {
                (*m).refcnt_inc();
                m = (*m).next();
            }
        }
        Mbuf {
            mbuf: self.mbuf,
            _marker: PhantomData,
        }
    }
}

impl Drop for Mbuf {
    #[inline]
    fn drop(&mut self) {
        unsafe { rte_pktmbuf_free(self.mbuf.as_ptr()) };
    }
}

// ============================================================================
// Pool management
// ============================================================================

use std::ffi::CStr;
use zhida_dpdk_sys::{
    rte_mempool, rte_mempool_free, rte_mempool_in_use_count, rte_pktmbuf_pool_create_by_ops,
};

#[cfg(feature = "testing")]
pub use test_pool::{TestPoolGuard, acquire_test_pool, ensure_eal_init};
#[cfg(feature = "testing")]
use test_pool::create_test_pool;

/// Test-only EAL and pool setup, compiled only with the `testing` feature.
/// `ensure_eal_init` initializes EAL with fixed test arguments; in an application
/// it would make `dpdk-smoltcp`'s `Eal::init` fail, so no port could open.
#[cfg(feature = "testing")]
mod test_pool {
    use super::*;
    use std::cell::{Cell, OnceCell};
    use std::ffi::CString;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU32, Ordering};
    use zhida_dpdk_sys::{
        rte_eal_init, rte_mempool_cache, rte_pktmbuf_pool_create, rte_socket_id,
        RTE_MBUF_DEFAULT_BUF_SIZE,
    };

    /// EAL's argv strings, built and passed to `rte_eal_init` on first use.
    /// EAL keeps pointers into them after it returns, so they live for the
    /// whole process. Holding them in a static keeps them reachable for
    /// LeakSanitizer, which reports a `Box::leak`ed copy as a leak at exit.
    static EAL_ARGS: LazyLock<Vec<CString>> = LazyLock::new(|| {
        let cpu = zhida_dpdk_sys::only_allowed_cpu().unwrap_or_else(|error| panic!("{error}"));
        let lcores = format!("--lcores=0@{cpu}");
        let args = ["test", "--no-pci", "--no-huge", lcores.as_str()]
            .into_iter()
            .map(|arg| CString::new(arg).unwrap())
            .collect::<Vec<_>>();
        // EAL's argument parsing may rewrite the argv array but does not
        // write through these string pointers.
        let mut argv: Vec<*mut std::ffi::c_char> =
            args.iter().map(|arg| arg.as_ptr().cast_mut()).collect();
        let ret = unsafe { rte_eal_init(argv.len() as i32, argv.as_mut_ptr()) };
        assert!(ret >= 0, "EAL init failed with code {}", ret);
        args
    });

    /// Ensure DPDK EAL is initialized. Safe to call multiple times.
    pub fn ensure_eal_init() {
        LazyLock::force(&EAL_ARGS);
    }

    thread_local! {
        /// The calling thread's test pool and its lcore cache. Created by the
        /// thread's first `acquire_test_pool`, reused by later ones, never freed.
        static TEST_POOL: OnceCell<(*mut rte_mempool, *mut rte_mempool_cache)> =
            const { OnceCell::new() };
        static TEST_POOL_HELD: Cell<bool> = const { Cell::new(false) };
    }

    /// Exclusive use of the calling thread's test pool.
    /// On drop, flushes the cache and panics if any mbuf is still in use.
    ///
    /// The pool's cache belongs to the acquiring thread's lcore, and mbufs return
    /// to it from whichever thread drops them. The guard is therefore neither
    /// `Send` nor `Sync` (as `Mbuf` is neither), so every allocation and free
    /// through this cache stays on the acquiring thread:
    ///
    /// ```compile_fail
    /// fn shared_across_threads<T: Sync>() {}
    /// shared_across_threads::<zhida_buffer::TestPoolGuard>();
    /// ```
    /// ```compile_fail
    /// fn moved_across_threads<T: Send>() {}
    /// moved_across_threads::<zhida_buffer::TestPoolGuard>();
    /// ```
    /// The same path names the type, so the failures above come from the bounds:
    /// ```
    /// let _: fn() -> zhida_buffer::TestPoolGuard = zhida_buffer::acquire_test_pool;
    /// ```
    pub struct TestPoolGuard {
        pool: *mut rte_mempool,
        cache: *mut rte_mempool_cache,
    }

    impl TestPoolGuard {
        /// Get the pool pointer.
        pub fn pool(&self) -> *mut rte_mempool {
            self.pool
        }

        /// Get the cache pointer.
        pub fn cache(&self) -> *mut rte_mempool_cache {
            self.cache
        }

        /// Allocate an mbuf from the pool.
        pub fn alloc(&self) -> Option<Mbuf> {
            let mbuf = unsafe { zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(self.pool, self.cache) };
            NonNull::new(mbuf).map(|p| unsafe { Mbuf::from_raw(p) })
        }

        /// Number of buffers currently in use.
        pub fn in_use_count(&self) -> u32 {
            unsafe { rte_mempool_in_use_count(self.pool) }
        }
    }

    impl Drop for TestPoolGuard {
        fn drop(&mut self) {
            // Flush cache back to pool
            unsafe { zhida_dpdk_sys::zhida_mempool_cache_flush(self.cache, self.pool) };
            TEST_POOL_HELD.set(false);

            // Verify pool is clean
            let in_use = unsafe { rte_mempool_in_use_count(self.pool) };
            if in_use != 0 {
                panic!("TestPoolGuard dropped with {} mbufs still in use! Test leaked mbufs.", in_use);
            }
        }
    }

    /// Acquire exclusive access to the calling thread's test pool.
    /// Creates the pool on the thread's first call (1024 mbufs - large enough for
    /// interleaved testing). On guard drop, verifies all mbufs were returned.
    ///
    /// Panics if this thread already holds the guard, or if the thread has no
    /// DPDK lcore (no per-lcore cache); the pool created for that thread is freed
    /// before the panic. Tests using this pool must run on the persistent pinned
    /// test worker.
    pub fn acquire_test_pool() -> TestPoolGuard {
        ensure_eal_init();

        let (pool, cache) = TEST_POOL.with(|slot| {
            *slot.get_or_init(|| {
                let pool = create_test_pool_impl(1024, RTE_MBUF_DEFAULT_BUF_SIZE as u16);
                let cache = unsafe { zhida_dpdk_sys::zhida_get_pool_cache(pool) };
                if cache.is_null() {
                    unsafe { rte_mempool_free(pool) };
                    panic!("Failed to get mempool cache for this thread's test pool");
                }
                unsafe { zhida_dpdk_sys::zhida_pool_init_cache_ptrs(pool, cache) };
                (pool, cache)
            })
        });
        assert!(!TEST_POOL_HELD.replace(true), "test pool already acquired on this thread");

        TestPoolGuard { pool, cache }
    }

    static POOL_COUNTER: AtomicU32 = AtomicU32::new(0);

    /// Create a DPDK mempool (internal, no EAL init check). `data_room` includes headroom.
    fn create_test_pool_impl(size: u32, data_room: u16) -> *mut rte_mempool {
        let id = POOL_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pool_name = CString::new(format!("test_pool_{}", id)).unwrap();
        let cache_size = 256u32.min(size / 2);
        let pool = unsafe {
            rte_pktmbuf_pool_create(
                pool_name.as_ptr(),
                size,
                cache_size,
                8, // priv_size: 8 bytes for cache pointer
                data_room,
                rte_socket_id() as i32,
            )
        };
        assert!(!pool.is_null(), "Pool creation failed for pool_{} with size {}", id, size);
        pool
    }

    /// Create a new DPDK mempool with a unique name.
    pub(super) fn create_test_pool(size: u32, data_room: u16) -> *mut rte_mempool {
        ensure_eal_init();
        create_test_pool_impl(size, data_room)
    }
}

/// Explicit production pool settings. Data room includes DPDK headroom.
#[derive(Debug, Clone, Copy)]
pub struct PoolConfig<'a> {
    pub name: &'a CStr,
    pub count: u32,
    pub cache_size: u32,
    pub data_room_size: u16,
    /// NUMA socket, or -1 for DPDK's SOCKET_ID_ANY.
    pub socket_id: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolCreateError {
    CacheDisabled,
    DataRoomTooSmall { provided: u16, minimum: u16 },
    Dpdk { errno: i32 },
    OwnerCacheUnavailable { lcore_id: u32 },
}

impl std::fmt::Display for PoolCreateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CacheDisabled => f.write_str("zhida allocation requires a nonzero pool cache"),
            Self::DataRoomTooSmall { provided, minimum } => write!(
                f,
                "pool data room {provided} is smaller than DPDK headroom {minimum}"
            ),
            Self::Dpdk { errno } => {
                write!(f, "rte_pktmbuf_pool_create_by_ops failed with rte_errno {errno}")
            }
            Self::OwnerCacheUnavailable { lcore_id } => {
                write!(f, "pool cache unavailable for owner lcore {lcore_id}")
            }
        }
    }
}

impl std::error::Error for PoolCreateError {}

/// RAII wrapper for a DPDK mempool.
pub struct PoolManager {
    pool: *mut rte_mempool,
    cache: *mut zhida_dpdk_sys::rte_mempool_cache,
    /// If true, drop unconditionally without checking for leaks (test mode).
    unsafe_drop: bool,
    /// Cache is lcore-local, so PoolManager must not cross threads.
    /// Raw pointers already make this !Send/!Sync, but be explicit.
    _marker: PhantomData<*const ()>,
}

impl PoolManager {
    /// Create a pool using already initialized EAL and the calling owner's cache.
    ///
    /// The eight-byte private cache slot is initialized on every object before
    /// returning. DPDK validates count, cache limits, name and NUMA allocation;
    /// its creation failures retain the actual `rte_errno`.
    ///
    /// # Safety
    /// EAL must already be initialized and the calling thread must have a valid,
    /// stable DPDK lcore identity established by the existing EAL owner. Keep EAL
    /// and that owner identity alive until this pool and every mbuf from it are
    /// finished. This constructor does not initialize EAL or register a thread.
    /// All allocations, frees and cache access must remain on that owner thread
    /// with that same lcore identity: the pool's backing ring is
    /// single-producer/single-consumer (`ring_sp_sc`), so a get or put from any
    /// other thread, including a PMD or EAL thread, corrupts it.
    /// This pool must outlive every mbuf allocated from it, including mbufs handed
    /// to DPDK. Do not clean up EAL or unregister the owner while resources remain.
    /// Use this pool only for direct, uniquely owned, single-segment packets
    /// (`refcnt == 1`, `nb_segs == 1`, `next == NULL`) without external backing.
    /// Do not use indirect attachments, clones, sharing or chains with this pool.
    /// `prepend` beyond the headroom creates a chain. The general PoolManager/Mbuf
    /// APIs do not enforce these restrictions; callers must preserve them through
    /// all Rust and DPDK operations.
    pub unsafe fn new_production(config: PoolConfig<'_>) -> Result<Self, PoolCreateError> {
        if config.cache_size == 0 {
            return Err(PoolCreateError::CacheDisabled);
        }
        let minimum = zhida_dpdk_sys::RTE_PKTMBUF_HEADROOM as u16;
        if config.data_room_size < minimum {
            return Err(PoolCreateError::DataRoomTooSmall {
                provided: config.data_room_size,
                minimum,
            });
        }

        // Single-producer/single-consumer backing ring: every get and put, cache
        // refill and flush included, runs on the owner thread (see # Safety).
        // DPDK always builds ring_sp_sc; an unknown name fails with EINVAL.
        let pool = rte_pktmbuf_pool_create_by_ops(
            config.name.as_ptr(),
            config.count,
            config.cache_size,
            8,
            config.data_room_size,
            config.socket_id,
            c"ring_sp_sc".as_ptr(),
        );
        if pool.is_null() {
            return Err(PoolCreateError::Dpdk {
                errno: zhida_dpdk_sys::zhida_errno(),
            });
        }

        let cache = zhida_dpdk_sys::zhida_get_pool_cache(pool);
        if cache.is_null() {
            let lcore_id = zhida_dpdk_sys::zhida_lcore_id();
            rte_mempool_free(pool);
            return Err(PoolCreateError::OwnerCacheUnavailable { lcore_id });
        }
        zhida_dpdk_sys::zhida_pool_init_cache_ptrs(pool, cache);
        Ok(Self {
            pool,
            cache,
            unsafe_drop: false,
            _marker: PhantomData,
        })
    }

    /// Create a test pool with the given size, initializing EAL with test
    /// arguments if needed. Only with the `testing` feature.
    #[cfg(feature = "testing")]
    pub fn new(size: u32) -> Self {
        Self::with_data_room(size, zhida_dpdk_sys::RTE_MBUF_DEFAULT_BUF_SIZE as u16)
    }

    /// Test pool whose mbufs have `data_room` bytes, headroom included.
    #[cfg(feature = "testing")]
    fn with_data_room(size: u32, data_room: u16) -> Self {
        let pool = create_test_pool(size, data_room);

        let cache = unsafe { zhida_dpdk_sys::zhida_get_pool_cache(pool) };

        // If cache retrieval failed, free the pool before panicking
        if cache.is_null() {
            unsafe { rte_mempool_free(pool) };
            panic!("Failed to get mempool cache");
        }

        // Pre-set cache pointer on all mbufs in pool.
        // This means alloc path doesn't need to touch priv_data.
        unsafe { zhida_dpdk_sys::zhida_pool_init_cache_ptrs(pool, cache) };

        Self { pool, cache, unsafe_drop: false, _marker: PhantomData }
    }

    /// Create a pool that will unconditionally free on drop (no leak check).
    /// Use this in tests where cleanup must succeed even if mbufs leaked.
    ///
    /// # Safety
    /// After drop, any mbufs from this pool become invalid. Caller must ensure
    /// no references to pool mbufs outlive the pool.
    #[cfg(feature = "testing")]
    pub unsafe fn new_unchecked(size: u32) -> Self {
        let mut pool = Self::new(size);
        pool.unsafe_drop = true;
        pool
    }

    /// Enable unconditional drop (no leak check on drop).
    /// Returns self for chaining.
    ///
    /// # Safety
    /// Same as `new_unchecked` - mbufs become invalid after drop.
    pub unsafe fn set_unchecked_drop(mut self) -> Self {
        self.unsafe_drop = true;
        self
    }

    /// Get the raw pool pointer.
    #[inline]
    pub fn pool(&self) -> *mut rte_mempool {
        self.pool
    }

    /// Get the precomputed cache pointer for fast alloc.
    #[inline]
    pub fn cache(&self) -> *mut zhida_dpdk_sys::rte_mempool_cache {
        self.cache
    }

    /// Allocate an mbuf from this pool.
    #[inline]
    pub fn alloc(&self) -> Option<Mbuf> {
        let mbuf = unsafe { zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(self.pool, self.cache) };
        NonNull::new(mbuf).map(|p| unsafe { Mbuf::from_raw(p) })
    }

    /// Allocate an mbuf with initial data length. Returns None if len exceeds available space.
    #[inline]
    pub fn alloc_with_len(&self, len: u16) -> Option<Mbuf> {
        let mbuf = unsafe { zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(self.pool, self.cache) };
        NonNull::new(mbuf).and_then(|p| {
            let m = unsafe { &*p.as_ptr() };
            if len > m.buf_len() - m.data_off() {
                unsafe { zhida_dpdk_sys::rte_pktmbuf_free(p.as_ptr()) };
                return None;
            }
            Some(unsafe { Mbuf::from_raw_with_len(p, len) })
        })
    }

    /// Number of buffers currently in use.
    #[inline]
    pub fn in_use_count(&self) -> u32 {
        unsafe { rte_mempool_in_use_count(self.pool) }
    }

    /// Forcibly close pool NO MATTER WHAT.
    /// Returns true if pool was clean (no outstanding mbufs).
    /// Returns false if pool had outstanding mbufs (indicates bug/cycle).
    ///
    /// Unlike normal Drop (which panics on outstanding mbufs), this
    /// ALWAYS deallocates the pool and just reports the status.
    ///
    /// # Safety
    /// After this call, no mbufs from this pool may be accessed.
    pub unsafe fn unsafe_close_pool(self) -> bool {
        // Check outstanding count FIRST
        let count = rte_mempool_in_use_count(self.pool);
        let was_clean = count == 0;

        // Bypass Drop - use ManuallyDrop so our Drop impl doesn't run
        let this = std::mem::ManuallyDrop::new(self);

        // Manually call DPDK to deallocate the pool - ALWAYS do this
        rte_mempool_free(this.pool);

        was_clean
    }
}

impl Drop for PoolManager {
    fn drop(&mut self) {
        let in_use = self.in_use_count();
        if in_use != 0 && !self.unsafe_drop {
            // Panic before freeing pool - leaks pool but avoids use-after-free
            panic!("PoolManager dropped with {} buffers still in use!", in_use);
        }
        unsafe { rte_mempool_free(self.pool) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zhida_dpdk_sys::RTE_PKTMBUF_HEADROOM;

    #[zhida_test_support::pinned_test]
    fn test_mbuf_size() {
        let size = std::mem::size_of::<Mbuf>();
        assert_eq!(size, 8, "Mbuf should be thin wrapper (8 bytes), got {}", size);
    }

    #[zhida_test_support::pinned_test]
    fn test_pool_is_reused_on_its_thread_and_returns_every_mbuf() {
        let first = acquire_test_pool();
        let pool = first.pool();
        let mbuf = first.alloc().unwrap();
        assert_eq!(first.in_use_count(), 1);
        drop(mbuf);
        drop(first);

        let second = acquire_test_pool();
        assert_eq!(second.pool(), pool);
        assert_eq!(second.in_use_count(), 0);
    }

    #[zhida_test_support::pinned_test]
    #[should_panic(expected = "test pool already acquired on this thread")]
    fn test_pool_second_acquire_while_held_panics() {
        let _held = acquire_test_pool();
        let _second = acquire_test_pool();
    }

    #[zhida_test_support::pinned_test]
    fn test_pool_guard_drop_with_live_mbuf_panics_and_releases_the_pool() {
        let guard = acquire_test_pool();
        let live = guard.alloc().unwrap().into_raw();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(guard)))
            .expect_err("dropping the guard with a live mbuf must panic");
        assert_eq!(
            panic.downcast_ref::<String>().map(String::as_str),
            Some("TestPoolGuard dropped with 1 mbufs still in use! Test leaked mbufs.")
        );
        drop(unsafe { Mbuf::from_raw(live) });

        let again = acquire_test_pool();
        assert_eq!(again.in_use_count(), 0);
    }

    #[zhida_test_support::pinned_test]
    fn test_pool_on_thread_without_lcore_panics_and_frees_its_pool() {
        // Test pool names share one counter, so the next pool created after this
        // probe is named `test_pool_{probe + 1}`.
        let probe = create_test_pool(1, RTE_PKTMBUF_HEADROOM as u16);
        let probe_name = unsafe { std::ffi::CStr::from_ptr((*probe).name.as_ptr()) };
        let probe_id: u32 = probe_name.to_str().unwrap()["test_pool_".len()..].parse().unwrap();
        unsafe { rte_mempool_free(probe) };

        let panic = std::thread::spawn(|| {
            assert_eq!(unsafe { zhida_dpdk_sys::zhida_lcore_id() }, u32::MAX);
            drop(acquire_test_pool());
        })
        .join()
        .expect_err("acquire on a thread without an lcore must panic");
        assert_eq!(
            panic.downcast_ref::<&str>().copied(),
            Some("Failed to get mempool cache for this thread's test pool")
        );

        let created = std::ffi::CString::new(format!("test_pool_{}", probe_id + 1)).unwrap();
        assert!(unsafe { zhida_dpdk_sys::rte_mempool_lookup(created.as_ptr()) }.is_null());
    }

    #[zhida_test_support::pinned_test]
    fn test_basic_alloc() {
        let pool = PoolManager::new(256);
        let mbuf = pool.alloc().unwrap();
        assert_eq!(mbuf.len(), 0);
        assert_eq!(mbuf.refcount(), 1);
        assert_eq!(mbuf.headroom(), RTE_PKTMBUF_HEADROOM as u16);
    }

    #[zhida_test_support::pinned_test]
    fn test_alloc_with_len() {
        let pool = PoolManager::new(256);
        let mbuf = pool.alloc_with_len(100).unwrap();
        assert_eq!(mbuf.len(), 100);
        assert_eq!(mbuf.refcount(), 1);
    }

    #[zhida_test_support::pinned_test]
    fn test_share() {
        let pool = PoolManager::new(256);
        let mut mbuf = pool.alloc_with_len(100).unwrap();
        assert_eq!(mbuf.refcount(), 1);

        let clone = mbuf.share();
        assert_eq!(mbuf.refcount(), 2);
        assert_eq!(clone.refcount(), 2);

        drop(clone);
        assert_eq!(mbuf.refcount(), 1);
    }

    #[zhida_test_support::pinned_test]
    fn test_prepend() {
        let pool = PoolManager::new(256);
        let mut mbuf = pool.alloc_with_len(100).unwrap();
        mbuf.data_mut().fill(0xDD);

        let hdr = mbuf.prepend(20).expect("Should prepend");
        hdr.fill(0xAA);

        assert_eq!(mbuf.len(), 120);
        let data = mbuf.data();
        assert!(data[0..20].iter().all(|&b| b == 0xAA));
        assert!(data[20..120].iter().all(|&b| b == 0xDD));
    }

    #[zhida_test_support::pinned_test]
    fn test_adj() {
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

    #[zhida_test_support::pinned_test]
    fn test_trim() {
        let pool = PoolManager::new(256);
        let mut mbuf = pool.alloc_with_len(100).unwrap();

        assert!(mbuf.trim(20));
        assert_eq!(mbuf.len(), 80);
    }

    #[zhida_test_support::pinned_test]
    fn test_trim_chained_trims_last_segment() {
        // This test verifies trim() on chained mbufs trims from the LAST segment,
        // matching DPDK's rte_pktmbuf_trim semantics.
        let pool = PoolManager::new(256);
        let mut head = pool.alloc_with_len(100).unwrap();
        let tail = pool.alloc_with_len(200).unwrap();
        head.chain(tail).expect("chain should succeed");

        assert_eq!(head.nb_segs(), 2);
        assert_eq!(head.pkt_len(), 300); // 100 + 200
        assert_eq!(head.len(), 100); // head segment data_len

        // Get tail segment's data_len before trim
        let tail_ptr = head.lastseg();
        let tail_len_before = unsafe { (*tail_ptr).data_len() };
        assert_eq!(tail_len_before, 200);

        // Trim 50 bytes - should come from TAIL segment, not head
        assert!(head.trim(50));

        // pkt_len should decrease
        assert_eq!(head.pkt_len(), 250);

        // Head segment should be UNCHANGED (this is what DPDK does)
        assert_eq!(head.len(), 100, "trim on chain should NOT affect head segment");

        // Tail segment should have decreased
        let tail_len_after = unsafe { (*tail_ptr).data_len() };
        assert_eq!(tail_len_after, 150, "trim on chain should reduce LAST segment's data_len");
    }

    #[zhida_test_support::pinned_test]
    fn test_trim_chained_fails_if_exceeds_last_segment() {
        // DPDK does NOT propagate trim across segments - it fails if trim > last segment's data_len
        let pool = PoolManager::new(256);
        let mut head = pool.alloc_with_len(100).unwrap();
        let tail = pool.alloc_with_len(50).unwrap();
        head.chain(tail).expect("chain should succeed");

        assert_eq!(head.pkt_len(), 150); // 100 + 50

        // Try to trim 60 bytes - more than tail's 50 bytes
        // Should FAIL, not propagate to head segment
        assert!(!head.trim(60), "trim should fail when exceeding last segment's data_len");

        // Nothing should have changed
        assert_eq!(head.pkt_len(), 150);
        assert_eq!(head.len(), 100);
        let tail_ptr = head.lastseg();
        assert_eq!(unsafe { (*tail_ptr).data_len() }, 50);
    }

    #[zhida_test_support::pinned_test]
    #[should_panic(expected = "trim() called on chain with shared tail")]
    fn test_trim_panics_on_shared_tail() {
        let pool = PoolManager::new(256);
        let mut head = pool.alloc_with_len(100).unwrap();
        let mut tail = pool.alloc_with_len(200).unwrap();

        // Share tail before chaining (tail is single-segment, share() allowed)
        let _tail_clone = tail.share();
        // Now tail.refcnt=2

        // chain accepts a shared tail whose pkt_len == data_len (single segment)
        head.chain(tail).ok().unwrap();
        // Now: head.refcnt=1, tail.refcnt=2

        // trim on head should panic - would corrupt _tail_clone's view
        head.trim(10);
    }

    #[zhida_test_support::pinned_test]
    fn test_buffers_freed_on_drop() {
        let pool = PoolManager::new(16);
        for i in 0..1000 {
            let mbuf = pool.alloc_with_len(100)
                .unwrap_or_else(|| panic!("pool exhausted at iteration {}", i));
            drop(mbuf);
        }
    }

    #[zhida_test_support::pinned_test]
    fn test_shared_buffers_freed_correctly() {
        let pool = PoolManager::new(16);
        for i in 0..1000 {
            let mut mbuf = pool.alloc_with_len(100)
                .unwrap_or_else(|| panic!("pool exhausted at iteration {} (alloc)", i));
            let clone = mbuf.share();
            drop(mbuf);
            drop(clone);
        }
    }

    #[zhida_test_support::pinned_test]
    fn test_chain() {
        let pool = PoolManager::new(256);
        let mut head = pool.alloc_with_len(100).unwrap();
        let tail = pool.alloc_with_len(200).unwrap();

        assert_eq!(head.nb_segs(), 1);
        assert_eq!(head.pkt_len(), 100);

        assert!(head.chain(tail).is_ok());

        assert_eq!(head.nb_segs(), 2);
        assert_eq!(head.pkt_len(), 300); // 100 + 200

        // Iterate over segments
        let segs: Vec<_> = head.iter_segs().collect();
        assert_eq!(segs.len(), 2);
    }

    #[zhida_test_support::pinned_test]
    fn test_chain_freed_on_drop() {
        let pool = PoolManager::new(256);
        {
            let mut head = pool.alloc_with_len(100).unwrap();
            let tail = pool.alloc_with_len(200).unwrap();
            assert!(head.chain(tail).is_ok());
            // Both freed when head drops
        }
        assert_eq!(pool.in_use_count(), 0);
    }

    #[zhida_test_support::pinned_test]
    #[should_panic(expected = "use share_all() for chains")]
    fn test_share_asserts_on_chain() {
        let pool = PoolManager::new(256);
        let mut head = pool.alloc_with_len(100).unwrap();
        let tail = pool.alloc_with_len(200).unwrap();
        assert!(head.chain(tail).is_ok());
        // This should panic because share() is only for single-segment
        let _ = head.share();
    }

    #[zhida_test_support::pinned_test]
    fn test_share_all_increments_all_refcounts() {
        let pool = PoolManager::new(256);
        let mut head = pool.alloc_with_len(100).unwrap();
        let tail = pool.alloc_with_len(200).unwrap();
        assert!(head.chain(tail).is_ok());

        // Both should have refcount 1
        assert_eq!(head.refcount(), 1);
        let tail_ptr = head.lastseg();
        assert_eq!(unsafe { (*tail_ptr).refcnt() }, 1);

        // share_all should increment both
        let shared = head.share_all();

        assert_eq!(head.refcount(), 2);
        assert_eq!(unsafe { (*tail_ptr).refcnt() }, 2);
        assert_eq!(shared.refcount(), 2);

        drop(shared);
        assert_eq!(head.refcount(), 1);
        assert_eq!(unsafe { (*tail_ptr).refcnt() }, 1);
    }

    #[zhida_test_support::pinned_test]
    fn test_clone_indirect_creates_indirects() {
        let pool = PoolManager::new(256);
        let original = pool.alloc_with_len(100).unwrap();

        assert!(!original.is_head_indirect());
        assert_eq!(original.refcount(), 1);

        let clone = original.clone_indirect(&pool).expect("clone_indirect should succeed");

        // Clone should be indirect
        assert!(clone.is_head_indirect());
        // Original should still be direct
        assert!(!original.is_head_indirect());
        // Original's refcount incremented (indirect points to it)
        assert_eq!(original.refcount(), 2);
        // Clone (indirect mbuf itself) has refcount 1
        assert_eq!(clone.refcount(), 1);
    }

    #[zhida_test_support::pinned_test]
    fn test_is_chained() {
        let pool = PoolManager::new(256);
        let mut head = pool.alloc_with_len(100).unwrap();
        assert!(!head.is_chained());

        let tail = pool.alloc_with_len(200).unwrap();
        assert!(head.chain(tail).is_ok());
        assert!(head.is_chained());
    }

    #[zhida_test_support::pinned_test]
    fn test_is_head_unique_and_is_tail_unique() {
        let pool = PoolManager::new(256);
        let mut head = pool.alloc_with_len(100).unwrap();
        let tail = pool.alloc_with_len(200).unwrap();
        assert!(head.chain(tail).is_ok());

        assert!(head.is_head_unique());
        assert!(head.is_tail_unique());

        // Share only head
        let head_ptr = head.as_ptr();
        unsafe { (*head_ptr).refcnt_inc() };
        assert!(!head.is_head_unique());
        assert!(head.is_tail_unique());
        unsafe { (*head_ptr).refcnt_dec() };

        // Share only tail
        let tail_ptr = head.lastseg();
        unsafe { (*tail_ptr).refcnt_inc() };
        assert!(head.is_head_unique());
        assert!(!head.is_tail_unique());
        unsafe { (*tail_ptr).refcnt_dec() };
    }

    #[zhida_test_support::pinned_test]
    fn test_clone_chain_indirect() {
        let pool = PoolManager::new(256);
        let mut original = pool.alloc_with_len(100).unwrap();
        let tail = pool.alloc_with_len(200).unwrap();
        assert!(original.chain(tail).is_ok());

        let clone = original.clone_indirect(&pool).expect("clone_indirect should succeed");

        // Clone should also be chained
        assert_eq!(clone.nb_segs(), 2);
        assert_eq!(clone.pkt_len(), 300);

        // Both segments of clone should be indirect
        assert!(clone.is_head_indirect());
        let clone_tail_ptr = clone.lastseg();
        const RTE_MBUF_F_INDIRECT: u64 = 1 << 62;
        assert!((unsafe { (*clone_tail_ptr).ol_flags } & RTE_MBUF_F_INDIRECT) != 0);

        // Original segments should have refcount 2 (one for original, one from indirect)
        assert_eq!(original.refcount(), 2);
        assert_eq!(unsafe { (*original.lastseg()).refcnt() }, 2);
    }

    #[zhida_test_support::pinned_test]
    fn test_into_indirect_head() {
        let pool = PoolManager::new(256);
        let mut original = pool.alloc_with_len(100).unwrap();
        let tail = pool.alloc_with_len(200).unwrap();
        let tail_ptr = tail.as_ptr();
        assert!(original.chain(tail).is_ok());

        let original_headroom = original.headroom();

        // Consume original, get indirect-headed chain
        let indirect = original.into_indirect_head(&pool).expect("into_indirect_head should succeed");

        // Indirect chain has same structure
        assert_eq!(indirect.nb_segs(), 2);
        assert_eq!(indirect.pkt_len(), 300);
        assert!(indirect.is_head_indirect());

        // Tail is same mbuf, refcount unchanged (ownership transferred)
        assert_eq!(indirect.lastseg(), tail_ptr);
        assert_eq!(unsafe { (*tail_ptr).refcnt() }, 1);

        // Indirect head keeps the original's data offset
        assert_eq!(indirect.headroom(), original_headroom);
    }

    #[zhida_test_support::pinned_test]
    fn test_clone_indirect_head() {
        let pool = PoolManager::new(256);
        let mut original = pool.alloc_with_len(100).unwrap();
        let tail = pool.alloc_with_len(200).unwrap();
        let tail_ptr = tail.as_ptr();
        assert!(original.chain(tail).is_ok());

        // Clone with indirect head, shared tails
        let clone = original.clone_indirect_head(&pool).expect("clone_indirect_head should succeed");

        // Both chains have same structure
        assert_eq!(original.nb_segs(), 2);
        assert_eq!(clone.nb_segs(), 2);

        // Clone head is indirect
        assert!(clone.is_head_indirect());
        assert!(!original.is_head_indirect());

        // Tail is shared (same pointer, refcount=2)
        assert_eq!(clone.lastseg(), tail_ptr);
        assert_eq!(original.lastseg(), tail_ptr);
        assert_eq!(unsafe { (*tail_ptr).refcnt() }, 2);

        // Original head refcount bumped (indirect points to it)
        assert_eq!(original.refcount(), 2);
    }

    #[zhida_test_support::pinned_test]
    fn test_into_indirect_head_single_segment() {
        let pool = PoolManager::new(256);
        let original = pool.alloc_with_len(100).unwrap();
        let original_headroom = original.headroom();

        let indirect = original.into_indirect_head(&pool).expect("should work for single segment");

        assert_eq!(indirect.nb_segs(), 1);
        assert_eq!(indirect.len(), 100);
        assert!(indirect.is_head_indirect());
        assert_eq!(indirect.headroom(), original_headroom);
    }

    // ========================================================================
    // Chain safety assumption tests
    // These validate the ASSUMPTIONS underlying the chain ownership checks
    // (shared-head/shared-tail refusal and cycle prevention), not just
    // that chaining works. If any of these fail, our safety checks are unsound.
    // ========================================================================

    #[zhida_test_support::pinned_test]
    fn test_assumption_share_all_increments_all_segments() {
        // ASSUMPTION: share_all() always increments lastseg's refcount.
        // The shared-head refusal relies on this - if share_all() missed any
        // segment, we couldn't detect shared chains.
        let pool = PoolManager::new(256);
        let mut head = pool.alloc_with_len(100).unwrap();

        // Build a 6-segment chain
        for _ in 0..5 {
            let seg = pool.alloc_with_len(50).unwrap();
            head.chain(seg).ok().expect("chain failed");
        }
        assert_eq!(head.nb_segs(), 6);

        let lastseg_ptr = head.lastseg();
        assert_eq!(unsafe { (*lastseg_ptr).refcnt() }, 1);

        let _shared = head.share_all();

        // CRITICAL: lastseg refcount MUST be incremented
        assert_eq!(
            unsafe { (*lastseg_ptr).refcnt() },
            2,
            "share_all() must increment ALL segments including lastseg"
        );
    }

    #[zhida_test_support::pinned_test]
    fn test_assumption_share_only_single_segment() {
        // ASSUMPTION: share() only works on single-segment mbufs.
        // This means share() handles can only create self-cycles (single mbuf),
        // which we detect via is_tail_unique().
        let pool = PoolManager::new(256);
        let mut a = pool.alloc_with_len(100).unwrap();
        let b = a.share();

        // For single-segment, head == tail, so is_tail_unique() catches it
        assert!(!a.is_tail_unique(), "share() should make tail non-unique");
        assert!(a.chain(b).is_err(), "chain should reject shared single mbuf");
    }

    #[zhida_test_support::pinned_test]
    fn test_assumption_tail_unique_means_never_shared() {
        // ASSUMPTION: lastseg.refcount == 1 implies no share_all() was ever called.
        // Because share_all() increments ALL segments, if ANY segment was shared,
        // lastseg was also shared.
        let pool = PoolManager::new(256);
        let mut head = pool.alloc_with_len(100).unwrap();
        let tail = pool.alloc_with_len(50).unwrap();
        head.chain(tail).ok().expect("chain failed");

        // Initially unique
        assert!(head.is_tail_unique(), "fresh chain should be tail-unique");

        // After share_all, no longer unique
        let _shared = head.share_all();
        assert!(
            !head.is_tail_unique(),
            "share_all() must make tail non-unique"
        );
    }

    #[zhida_test_support::pinned_test]
    fn test_self_chain_via_share_prevented() {
        // Verify: share() on single mbuf, then chain, creates cycle.
        // Our check must prevent this.
        let pool = PoolManager::new(256);
        let mut a = pool.alloc_with_len(100).unwrap();
        let b = a.share(); // refcount=2, both point to same mbuf

        // a.chain(b) would set a->next = a (CYCLE)
        assert!(!a.is_tail_unique());
        let result = a.chain(b);
        assert!(result.is_err(), "must reject self-chain via share");

        // Return the Err mbuf to prevent leak
        drop(result.err().unwrap());
    }

    #[zhida_test_support::pinned_test]
    fn test_self_chain_multiseg_via_share_all_prevented() {
        // Verify: share_all() on chain, then chain back, creates cycle.
        let pool = PoolManager::new(256);
        let mut chain1 = pool.alloc_with_len(100).unwrap();
        let seg = pool.alloc_with_len(50).unwrap();
        chain1.chain(seg).ok().expect("chain failed");

        let chain2 = chain1.share_all(); // All refcounts = 2

        // chain1.chain(chain2) would create cycle
        assert!(!chain1.is_tail_unique());
        let result = chain1.chain(chain2);
        assert!(result.is_err(), "must reject self-chain via share_all");

        drop(result.err().unwrap());
    }

    #[zhida_test_support::pinned_test]
    fn test_fan_in_shared_tail_allowed() {
        // Valid pattern: multiple chains share a tail segment.
        // This is NOT a cycle - free walks forward, refcounts prevent double-free.
        let pool = PoolManager::new(256);

        // Create shared tail
        let mut shared_tail = pool.alloc_with_len(100).unwrap();
        let shared_tail2 = shared_tail.share();

        // Two fresh heads
        let mut head1 = pool.alloc_with_len(50).unwrap();
        let mut head2 = pool.alloc_with_len(50).unwrap();

        // Both heads are tail-unique (fresh, never shared)
        assert!(head1.is_tail_unique());
        assert!(head2.is_tail_unique());

        // Both can chain to shared tails - no cycle!
        head1.chain(shared_tail).ok().expect("chain1 should succeed");
        head2.chain(shared_tail2).ok().expect("chain2 should succeed");

        // Verify shared structure:
        // head1: [h1] -> [shared_tail]
        // head2: [h2] -> [shared_tail]
        // shared_tail has refcount=2
        assert_eq!(head1.nb_segs(), 2);
        assert_eq!(head2.nb_segs(), 2);
        assert_eq!(head1.lastseg(), head2.lastseg()); // Same tail!
        assert_eq!(unsafe { (*head1.lastseg()).refcnt() }, 2);
    }

    /// Pool whose segments hold one payload byte, so `u16::MAX + 1` mbufs fit
    /// in the `--no-huge` EAL memory.
    fn one_byte_segment_pool(count: u32) -> PoolManager {
        PoolManager::with_data_room(count, RTE_PKTMBUF_HEADROOM as u16 + 1)
    }

    /// Exactly-once return proof. `in_use_count() == 0` cannot see a double return:
    /// DPDK caps the available count at the pool size. Allocating until empty
    /// yields more than `size` buffers, or a repeated address, after one.
    fn assert_pool_returned_exactly_once(pool: &PoolManager, size: u32) {
        let mut held = Vec::with_capacity(size as usize);
        while let Some(m) = pool.alloc() {
            held.push(m);
            if held.len() > size as usize {
                break;
            }
        }
        let mut addrs: Vec<usize> = held.iter().map(|m| m.as_ptr() as usize).collect();
        addrs.sort_unstable();
        addrs.dedup();
        if held.len() != size as usize || addrs.len() != held.len() {
            let (count, distinct) = (held.len(), addrs.len());
            std::mem::forget(held);
            panic!("pool handed out {count} buffers ({distinct} distinct), size {size}");
        }
    }

    /// Unique chain of `n` one-byte segments; halving keeps the walks O(n log n).
    fn one_byte_chain(pool: &PoolManager, n: u32) -> Mbuf {
        if n == 1 {
            return pool.alloc_with_len(1).unwrap();
        }
        let mut head = one_byte_chain(pool, n - n / 2);
        head.chain(one_byte_chain(pool, n / 2)).ok().expect("below the segment limit");
        head
    }

    #[zhida_test_support::pinned_test]
    fn test_chain_rejects_segment_count_overflow() {
        const LINUX_EOVERFLOW: i32 = 75;
        let limit = u32::from(u16::MAX);
        let pool = one_byte_segment_pool(limit + 1);

        let mut head = one_byte_chain(&pool, limit / 2 + 1);
        head.chain(one_byte_chain(&pool, limit / 2)).ok().expect("exactly the segment limit");
        assert_eq!((head.nb_segs(), head.pkt_len()), (u16::MAX, limit));
        let lastseg = head.lastseg();

        let extra = pool.alloc_with_len(1).unwrap();
        let extra = head.chain(extra).expect_err("chain past the segment limit");
        let ret = unsafe { zhida_dpdk_sys::rte_pktmbuf_chain(head.as_ptr(), extra.as_ptr()) };
        assert_eq!(ret, -LINUX_EOVERFLOW, "unchecked chain past the limit");

        assert_eq!((head.nb_segs(), head.pkt_len()), (u16::MAX, limit));
        assert_eq!(head.lastseg(), lastseg);
        assert!(unsafe { (*lastseg).next() }.is_null());
        assert_eq!((extra.nb_segs(), extra.pkt_len(), extra.next()), (1, 1, None));

        drop(extra);
        assert_eq!(pool.in_use_count(), limit);
        drop(head);
        assert_eq!(pool.in_use_count(), 0);
        assert_pool_returned_exactly_once(&pool, limit + 1);
    }

    #[zhida_test_support::pinned_test]
    fn test_pool_init_sets_cache_ptr_on_all_mbufs() {
        // Verify that cache pointers are pre-set at pool creation.
        // Even mbufs allocated via raw DPDK alloc (simulating RX path) have cache ptr set.
        let pool = PoolManager::new(256);

        // Use raw DPDK alloc (bypasses our alloc_fast, simulates NIC driver alloc)
        let raw_mbuf = unsafe { zhida_dpdk_sys::dpdk_raw_pktmbuf_alloc(pool.pool()) };
        assert!(!raw_mbuf.is_null(), "raw alloc should succeed");

        // Read the cache pointer from priv_data
        let cache_ptr: *mut zhida_dpdk_sys::rte_mempool_cache = unsafe {
            let cache_slot = (raw_mbuf as *mut u8)
                .add(std::mem::size_of::<rte_mbuf>())
                as *mut *mut zhida_dpdk_sys::rte_mempool_cache;
            *cache_slot
        };

        // Should match the pool's cache pointer
        assert_eq!(
            cache_ptr,
            pool.cache(),
            "raw DPDK alloc should have cache ptr pre-set from pool init"
        );

        // Clean up
        unsafe { zhida_dpdk_sys::dpdk_raw_pktmbuf_free(raw_mbuf) };
    }

    // ========================================================================
    // Mutation safety tests (Rc-style refcount enforcement)
    // ========================================================================

    #[zhida_test_support::pinned_test]
    #[should_panic(expected = "data_mut() called on shared mbuf")]
    fn test_data_mut_panics_on_shared() {
        let pool = PoolManager::new(256);
        let mut mbuf = pool.alloc_with_len(100).unwrap();
        let _shared = mbuf.share();
        let _ = mbuf.data_mut(); // refcnt = 2, should panic
    }

    #[zhida_test_support::pinned_test]
    fn test_try_data_mut_returns_none_on_shared() {
        let pool = PoolManager::new(256);
        let mut mbuf = pool.alloc_with_len(100).unwrap();
        let _shared = mbuf.share();
        assert!(mbuf.try_data_mut().is_none());
    }

    #[zhida_test_support::pinned_test]
    fn test_data_mut_works_after_unshare() {
        let pool = PoolManager::new(256);
        let mut mbuf = pool.alloc_with_len(100).unwrap();
        {
            let shared = mbuf.share();
            drop(shared);
        }
        // refcnt back to 1
        mbuf.data_mut().fill(0xAA);
    }

    #[zhida_test_support::pinned_test]
    fn test_prepend_on_shared_adds_header_segment() {
        let pool = PoolManager::new(256);
        let mut mbuf = pool.alloc_with_len(100).unwrap();
        mbuf.data_mut().fill(0xDD);
        let shared = mbuf.share();
        let shared_before = chain_state(shared.as_ptr());

        assert_prepends_header(&mut mbuf, 10, 0xAA);
        assert_eq!(chain_state(shared.as_ptr()), shared_before);
        assert_eq!(pool.in_use_count(), 2);

        drop(mbuf);
        assert_eq!(shared.refcount(), 1);
        let headroom = RTE_PKTMBUF_HEADROOM as u16;
        assert_eq!((shared.headroom(), shared.len(), shared.pkt_len()), (headroom, 100, 100));
        assert!(shared.data().iter().all(|&b| b == 0xDD));
        drop(shared);
        assert_pool_returned_exactly_once(&pool, 256);
    }

    #[zhida_test_support::pinned_test]
    fn test_prepend_on_indirect_clone_adds_header_segment() {
        let pool = PoolManager::new(256);
        let mut original = pool.alloc_with_len(100).unwrap();
        original.data_mut().fill(0xDD);
        let mut clone = original.clone_indirect(&pool).expect("clone should succeed");
        // refcnt 1, but its headroom is the original's buffer.
        assert!(clone.is_head_indirect());
        assert_eq!(clone.refcount(), 1);
        let original_before = chain_state(original.as_ptr());

        assert_prepends_header(&mut clone, 10, 0xAA);
        assert_eq!(chain_state(original.as_ptr()), original_before);
        assert_eq!(pool.in_use_count(), 3);

        drop(clone);
        assert_eq!(original.refcount(), 1);
        assert!(original.data().iter().all(|&b| b == 0xDD));
        drop(original);
        assert_pool_returned_exactly_once(&pool, 256);
    }

    #[zhida_test_support::pinned_test]
    #[should_panic(expected = "adj() called on shared mbuf")]
    fn test_adj_panics_on_shared() {
        let pool = PoolManager::new(256);
        let mut mbuf = pool.alloc_with_len(100).unwrap();
        let _shared = mbuf.share();
        let _ = mbuf.adj(10); // refcnt = 2, should panic
    }

    #[zhida_test_support::pinned_test]
    #[should_panic(expected = "trim() called on shared mbuf")]
    fn test_trim_panics_on_shared() {
        let pool = PoolManager::new(256);
        let mut mbuf = pool.alloc_with_len(100).unwrap();
        let _shared = mbuf.share();
        let _ = mbuf.trim(10); // refcnt = 2, should panic
    }

    #[zhida_test_support::pinned_test]
    #[should_panic(expected = "data_mut() called on indirect mbuf")]
    fn test_data_mut_panics_on_indirect() {
        let pool = PoolManager::new(256);
        let original = pool.alloc_with_len(100).unwrap();
        let mut clone = original.clone_indirect(&pool).expect("clone should succeed");

        // clone is indirect with refcnt=1, but data_mut should still panic
        assert!(clone.is_head_indirect());
        assert_eq!(clone.refcount(), 1);
        let _ = clone.data_mut(); // should panic
    }

    #[zhida_test_support::pinned_test]
    fn test_try_data_mut_returns_none_on_indirect() {
        let pool = PoolManager::new(256);
        let original = pool.alloc_with_len(100).unwrap();
        let mut clone = original.clone_indirect(&pool).expect("clone should succeed");

        // clone is indirect with refcnt=1
        assert!(clone.is_head_indirect());
        assert_eq!(clone.refcount(), 1);
        assert!(clone.try_data_mut().is_none());
    }

    #[zhida_test_support::pinned_test]
    fn test_alloc_with_len_rejects_oversize() {
        let pool = PoolManager::new(256);
        assert!(pool.alloc_with_len(u16::MAX).is_none());
    }

    // ========================================================================
    // Shared backing bytes: indirect clones share the original's buffer
    // ========================================================================

    fn panic_text(panic: Box<dyn std::any::Any + Send>) -> String {
        match panic.downcast::<String>() {
            Ok(text) => *text,
            Err(panic) => panic.downcast_ref::<&str>().unwrap().to_string(),
        }
    }

    const RTE_MBUF_F_EXTERNAL: u64 = 1 << 61;

    /// DPDK's header-copy set (`__rte_pktmbuf_copy_hdr`) plus ol_flags.
    #[derive(Debug, Clone, PartialEq)]
    struct PacketMeta {
        port: u16,
        vlan_tci: u16,
        vlan_tci_outer: u16,
        tx_offload: u64,
        hash: (u32, u32),
        packet_type: u32,
        dynfield1: Vec<u32>,
        ol_flags: u64,
    }

    fn packet_meta(p: *const rte_mbuf) -> PacketMeta {
        unsafe {
            let m = &*p;
            let f = &m.__bindgen_anon_2.__bindgen_anon_1;
            PacketMeta {
                port: m.__bindgen_anon_1.__bindgen_anon_1.port,
                vlan_tci: f.vlan_tci,
                vlan_tci_outer: f.vlan_tci_outer,
                tx_offload: m.__bindgen_anon_3.tx_offload,
                hash: (f.__bindgen_anon_2.hash.rss, f.__bindgen_anon_2.hash.fdir.hi),
                packet_type: f.__bindgen_anon_1.packet_type,
                dynfield1: m.dynfield1.to_vec(),
                ol_flags: m.ol_flags,
            }
        }
    }

    /// Non-default value in every `PacketMeta` field (ol_flags keeps the INDIRECT bit).
    fn set_packet_meta(m: &Mbuf) {
        unsafe {
            let m = &mut *m.as_ptr();
            m.__bindgen_anon_1.__bindgen_anon_1.port = 3;
            let f = &mut m.__bindgen_anon_2.__bindgen_anon_1;
            f.vlan_tci = 0x0123;
            f.vlan_tci_outer = 0x0456;
            f.__bindgen_anon_2.hash.rss = 0xA5A5_0001;
            f.__bindgen_anon_2.hash.fdir.hi = 0xA5A5_0002;
            f.__bindgen_anon_1.packet_type = 0x0211;
            m.__bindgen_anon_3.tx_offload = 0x0E0E_1414;
            for (i, d) in m.dynfield1.iter_mut().enumerate() {
                *d = 0xD0D0_0000 + i as u32;
            }
            // RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_RX_RSS_HASH
            m.ol_flags = (m.ol_flags & RTE_MBUF_F_INDIRECT) | (1 << 55) | (1 << 1);
        }
    }

    /// Every header field `prepend` can write or move, plus every buffer byte up to
    /// the data end (headroom included), per segment reachable from `p`.
    #[derive(Debug, PartialEq)]
    struct SegState {
        addr: usize,
        refcnt: u16,
        data_off: u16,
        data_len: u16,
        pkt_len: u32,
        nb_segs: u16,
        next: usize,
        meta: PacketMeta,
        bytes: Vec<u8>,
    }

    fn chain_state(mut p: *mut rte_mbuf) -> Vec<SegState> {
        let mut segs = Vec::new();
        while !p.is_null() {
            let m = unsafe { &*p };
            let end = m.data_off() as usize + m.data_len() as usize;
            segs.push(SegState {
                addr: p as usize,
                refcnt: m.refcnt(),
                data_off: m.data_off(),
                data_len: m.data_len(),
                pkt_len: m.pkt_len(),
                nb_segs: m.nb_segs(),
                next: m.next() as usize,
                meta: packet_meta(p),
                bytes: unsafe { std::slice::from_raw_parts(m.buf_addr as *const u8, end) }.to_vec(),
            });
            p = m.next();
        }
        segs
    }

    /// `m.prepend(n)` must take the header path: a fresh direct segment holding
    /// the `n` bytes at its buffer end, linked in front of the unchanged old chain,
    /// carrying the old head's header-copy metadata without INDIRECT/EXTERNAL.
    fn assert_prepends_header(m: &mut Mbuf, n: u16, fill: u8) {
        let old_head = m.as_ptr();
        let old = chain_state(old_head);
        let (pkt_len, nb_segs) = (m.pkt_len(), m.nb_segs());
        let mut meta = packet_meta(old_head);
        meta.ol_flags &= !(RTE_MBUF_F_INDIRECT | RTE_MBUF_F_EXTERNAL);

        m.prepend(n).expect("header segment").fill(fill);

        assert_ne!(m.as_ptr(), old_head);
        assert_eq!(m.next(), Some(old_head));
        assert!(!m.is_head_indirect());
        assert_eq!(m.refcount(), 1);
        assert_eq!((m.len(), m.tailroom()), (n, 0));
        assert_eq!((m.pkt_len(), m.nb_segs()), (pkt_len + n as u32, nb_segs + 1));
        assert_eq!(packet_meta(m.as_ptr()), meta);
        assert!(m.data().iter().all(|&b| b == fill));
        assert_eq!(chain_state(old_head), old, "old chain changed");
    }

    #[zhida_test_support::pinned_test]
    fn test_two_indirect_clones_prepend_disjoint_headers() {
        let pool = PoolManager::new(256);
        let mut original = pool.alloc_with_len(100).unwrap();
        original.data_mut().fill(0xAA);
        let buf = unsafe {
            let m = &*original.as_ptr();
            m.buf_addr as usize..m.buf_addr as usize + m.buf_len() as usize
        };

        let mut first = original.clone_indirect(&pool).unwrap();
        // A clone of a clone attaches to the same direct mbuf.
        let mut second = first.clone_indirect(&pool).unwrap();
        assert_eq!(original.refcount(), 3);
        let original_before = chain_state(original.as_ptr());

        for (clone, fill) in [(&mut first, 0xBB), (&mut second, 0xCC)] {
            assert_prepends_header(clone, 20, fill);
            let hdr = clone.data().as_ptr() as usize;
            assert!(hdr + 20 <= buf.start || hdr >= buf.end, "header inside the shared buffer");
        }
        assert_ne!(first.as_ptr(), second.as_ptr());
        assert!(first.data().iter().all(|&b| b == 0xBB));
        assert_eq!(chain_state(original.as_ptr()), original_before);

        drop(first);
        drop(second);
        assert_eq!(original.refcount(), 1);
        drop(original);
        assert_pool_returned_exactly_once(&pool, 256);
    }

    #[zhida_test_support::pinned_test]
    fn test_adj_prepend_on_indirect_clone_preserves_original() {
        let pool = PoolManager::new(256);
        let mut original = pool.alloc_with_len(100).unwrap();
        for (i, byte) in original.data_mut().iter_mut().enumerate() {
            *byte = i as u8;
        }
        let expected: Vec<u8> = (0..100).collect();
        let headroom = original.headroom();

        let mut clone = original.clone_indirect(&pool).unwrap();
        let original_before = chain_state(original.as_ptr());
        // adj only moves the clone's own data_off: no bytes written.
        assert!(clone.adj(20));
        assert_eq!(chain_state(original.as_ptr()), original_before);
        assert_eq!((clone.headroom(), clone.len(), clone.pkt_len()), (headroom + 20, 80, 80));

        // The clone's headroom is now the original's first 20 payload bytes.
        assert_prepends_header(&mut clone, 20, 0xBB);
        assert_eq!(original.data(), &expected[..], "original payload overwritten via clone");
        assert_eq!(chain_state(original.as_ptr()), original_before);
        assert_eq!((clone.len(), clone.pkt_len(), clone.nb_segs()), (20, 100, 2));

        drop(clone);
        assert_eq!(original.refcount(), 1);
        drop(original);
        assert_pool_returned_exactly_once(&pool, 256);
    }

    #[zhida_test_support::pinned_test]
    fn test_original_prepend_while_indirect_clone_lives_adds_header() {
        let pool = PoolManager::new(256);
        let mut original = pool.alloc_with_len(100).unwrap();
        original.data_mut().fill(0x11);

        let clone = original.clone_indirect(&pool).unwrap();
        // shim_clone.c attach increments the direct mbuf's refcnt per clone.
        assert_eq!(original.refcount(), 2);
        assert!(original.try_data_mut().is_none());
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            original.data_mut().fill(0x22);
        }));
        let text = panic_text(attempt.expect_err("data_mut on shared original must be rejected"));
        assert!(text.contains("data_mut() called on shared mbuf"), "{text}");

        assert_prepends_header(&mut original, 20, 0x33);
        assert!(clone.data().iter().all(|&b| b == 0x11));

        drop(clone);
        // The header segment is direct and unshared: the next prepend goes in place.
        let header = original.as_ptr();
        original.prepend(20).unwrap().fill(0x44);
        assert_eq!(original.as_ptr(), header);
        assert_eq!((original.len(), original.pkt_len(), original.nb_segs()), (40, 140, 2));
        assert!(original.data()[..20].iter().all(|&b| b == 0x44));
        assert!(original.data()[20..].iter().all(|&b| b == 0x33));
        drop(original);
        assert_pool_returned_exactly_once(&pool, 256);
    }

    #[zhida_test_support::pinned_test]
    fn test_force_variants_on_unique_direct_mbuf() {
        let pool = PoolManager::new(256);
        let mut mbuf = pool.alloc_with_len(100).unwrap();
        let headroom = mbuf.headroom();

        unsafe { mbuf.data_mut_force() }.fill(0xDD);
        assert!(unsafe { mbuf.adj_force(10) });
        assert_eq!((mbuf.headroom(), mbuf.len()), (headroom + 10, 90));
        unsafe { mbuf.prepend_force(30) }.unwrap().fill(0xAA);
        assert_eq!((mbuf.headroom(), mbuf.len()), (headroom - 20, 120));
        assert!(unsafe { mbuf.trim_force(5) });
        assert_eq!((mbuf.len(), mbuf.pkt_len()), (115, 115));
        assert!(unsafe { mbuf.prepend_force(headroom) }.is_none());
        assert!(!unsafe { mbuf.adj_force(116) });
        assert!(!unsafe { mbuf.trim_force(116) });

        let data = mbuf.data();
        assert_eq!(data.len(), 115);
        assert!(data[..30].iter().all(|&b| b == 0xAA));
        assert!(data[30..].iter().all(|&b| b == 0xDD));
        drop(mbuf);
        assert_pool_returned_exactly_once(&pool, 256);
    }

    #[zhida_test_support::pinned_test]
    fn test_prepend_after_into_indirect_head_writes_backing_buffer() {
        let pool = PoolManager::new(256);
        let mut original = pool.alloc_with_len(100).unwrap();
        for (i, byte) in original.data_mut().iter_mut().enumerate() {
            *byte = i as u8;
        }
        let payload_ptr = original.data().as_ptr();
        let headroom = original.headroom();
        original.chain(pool.alloc_with_len(50).unwrap()).unwrap();

        let mut indirect = original.into_indirect_head(&pool).unwrap();
        assert!(indirect.is_head_indirect());
        let hdr = indirect.prepend(20).expect("sole holder of the backing buffer may prepend");
        assert_eq!(hdr.as_ptr(), payload_ptr.wrapping_sub(20));
        hdr.fill(0xBB);

        assert_eq!(indirect.headroom(), headroom - 20);
        assert_eq!((indirect.len(), indirect.pkt_len(), indirect.nb_segs()), (120, 170, 2));
        assert!(indirect.data()[..20].iter().all(|&b| b == 0xBB));
        assert!(indirect.data()[20..].iter().copied().eq(0..100u8));
        drop(indirect);
        assert_pool_returned_exactly_once(&pool, 256);
    }

    #[zhida_test_support::pinned_test]
    fn test_prepend_on_indirect_clone_allowed_after_original_drops() {
        let pool = PoolManager::new(256);
        let mut original = pool.alloc_with_len(100).unwrap();
        for (i, byte) in original.data_mut().iter_mut().enumerate() {
            *byte = i as u8;
        }
        let mut clone = original.clone_indirect(&pool).unwrap();
        drop(original);

        clone.prepend(20).expect("sole holder of the backing buffer may prepend").fill(0xBB);
        assert_eq!((clone.len(), clone.pkt_len()), (120, 120));
        assert!(clone.data()[..20].iter().all(|&b| b == 0xBB));
        assert!(clone.data()[20..].iter().copied().eq(0..100u8));
        drop(clone);
        assert_pool_returned_exactly_once(&pool, 256);
    }

    #[zhida_test_support::pinned_test]
    fn test_prepend_on_indirect_clone_adds_header_while_sibling_clone_lives() {
        let pool = PoolManager::new(256);
        let mut original = pool.alloc_with_len(100).unwrap();
        original.data_mut().fill(0xAA);
        let mut first = original.clone_indirect(&pool).unwrap();
        let mut second = first.clone_indirect(&pool).unwrap();
        drop(original);
        let first_before = chain_state(first.as_ptr());

        assert_prepends_header(&mut second, 20, 0xBB);
        assert_eq!(chain_state(first.as_ptr()), first_before);

        drop(second);
        first.prepend(20).expect("sibling dropped; backing buffer now unique").fill(0xBB);
        assert_eq!(first.nb_segs(), 1);
        assert!(first.data()[..20].iter().all(|&b| b == 0xBB));
        assert!(first.data()[20..].iter().all(|&b| b == 0xAA));
        drop(first);
        assert_pool_returned_exactly_once(&pool, 256);
    }

    #[zhida_test_support::pinned_test]
    fn test_prepend_after_into_indirect_head_of_shared_head_adds_header() {
        let pool = PoolManager::new(256);
        let mut a = pool.alloc_with_len(100).unwrap();
        for (i, byte) in a.data_mut().iter_mut().enumerate() {
            *byte = i as u8;
        }
        let b = a.share();
        // Shared single-segment head: conversion cuts nothing another owner reaches.
        let mut i = a.into_indirect_head(&pool).expect("shared single-segment head converts");
        assert!(i.is_head_indirect());
        assert_eq!((i.refcount(), b.refcount()), (1, 2));

        // i's headroom is now b's first 20 payload bytes.
        assert!(i.adj(20));
        let b_before = chain_state(b.as_ptr());
        assert_prepends_header(&mut i, 20, 0xBB);
        assert_eq!(chain_state(b.as_ptr()), b_before);
        assert!(b.data().iter().copied().eq(0..100u8));

        drop(i);
        assert_eq!(b.refcount(), 1);
        drop(b);
        assert_pool_returned_exactly_once(&pool, 256);
    }

    #[zhida_test_support::pinned_test]
    fn test_prepend_on_clone_indirect_head_adds_header_while_original_lives() {
        let pool = PoolManager::new(256);
        let mut original = pool.alloc_with_len(100).unwrap();
        for (i, byte) in original.data_mut().iter_mut().enumerate() {
            *byte = i as u8;
        }
        let mut head = original.clone_indirect_head(&pool).unwrap();
        assert!(head.is_head_indirect());
        assert!(head.is_head_unique());

        assert!(head.adj(20));
        let original_before = chain_state(original.as_ptr());
        assert_prepends_header(&mut head, 20, 0xBB);
        assert_eq!(chain_state(original.as_ptr()), original_before);
        assert!(original.data().iter().copied().eq(0..100u8));
        drop(head);

        let mut retransmit = original.clone_indirect_head(&pool).unwrap();
        assert!(retransmit.adj(20));
        drop(original);
        retransmit.prepend(20).expect("sole holder of the backing buffer may prepend").fill(0xBB);
        assert_eq!((retransmit.len(), retransmit.pkt_len(), retransmit.nb_segs()), (100, 100, 1));
        assert!(retransmit.data()[..20].iter().all(|&b| b == 0xBB));
        assert!(retransmit.data()[20..].iter().copied().eq(20..100u8));
        drop(retransmit);
        assert_pool_returned_exactly_once(&pool, 256);
    }

    #[zhida_test_support::pinned_test]
    fn test_prepend_header_segment_len_bounded_by_data_room() {
        let pool = PoolManager::new(256);
        let mut mbuf = pool.alloc_with_len(100).unwrap();
        mbuf.data_mut().fill(0xDD);
        // Data room includes headroom: buf_len of a direct pktmbuf.
        let room = unsafe { (*mbuf.as_ptr()).buf_len() };
        let before = chain_state(mbuf.as_ptr());

        assert!(mbuf.prepend(room + 1).is_none());
        assert_eq!(pool.in_use_count(), 1, "refusal must not leave a segment allocated");
        assert_eq!(chain_state(mbuf.as_ptr()), before);

        assert_prepends_header(&mut mbuf, room, 0xAA);
        assert_eq!(mbuf.headroom(), 0);
        drop(mbuf);
        assert_pool_returned_exactly_once(&pool, 256);
    }

    /// The header-path length bound is the header pool's data room, not the
    /// backing buffer's: an indirect head from a 129-byte pool over a default
    /// buffer, with the original retained, refuses 130 without allocating and
    /// takes 129 with headroom 0. Would catch the bound read from the old head.
    #[zhida_test_support::pinned_test]
    fn test_prepend_header_segment_len_bounded_by_header_pool_data_room() {
        const HDR_POOL: u32 = 8;
        let backing = PoolManager::new(256);
        let headers = one_byte_segment_pool(HDR_POOL);
        let room = RTE_PKTMBUF_HEADROOM as u16 + 1;
        let mut original = backing.alloc_with_len(100).unwrap();
        original.data_mut().fill(0xDD);
        let mut indirect = original.clone_indirect(&headers).unwrap();
        assert!(unsafe { (*original.as_ptr()).buf_len() } > room + 1);
        let before = chain_state(indirect.as_ptr());
        let original_before = chain_state(original.as_ptr());

        assert!(indirect.prepend(room + 1).is_none());
        assert_eq!(chain_state(indirect.as_ptr()), before);
        assert_eq!((backing.in_use_count(), headers.in_use_count()), (1, 1), "refusal must not leave a segment allocated");

        assert_prepends_header(&mut indirect, room, 0xAA);
        assert_eq!(indirect.headroom(), 0);
        assert_eq!(indirect.pool(), headers.pool());
        assert_eq!((backing.in_use_count(), headers.in_use_count()), (1, 2));
        assert_eq!(chain_state(original.as_ptr()), original_before);

        drop(indirect);
        drop(original);
        assert_pool_returned_exactly_once(&backing, 256);
        assert_pool_returned_exactly_once(&headers, HDR_POOL);
    }

    #[zhida_test_support::pinned_test]
    fn test_prepend_header_segment_refused_at_segment_limit() {
        let limit = u32::from(u16::MAX);
        let pool = one_byte_segment_pool(limit + 1);
        let room = RTE_PKTMBUF_HEADROOM as u16 + 1;

        // Exclusive head with 128 bytes headroom: 129 bytes need a header segment.
        let mut m = one_byte_chain(&pool, limit - 1);
        m.prepend(room).expect("one below the segment limit").fill(0xAA);
        let pkt_len = limit - 1 + u32::from(room);
        assert_eq!((m.nb_segs(), m.pkt_len(), m.headroom()), (u16::MAX, pkt_len, 0));
        assert_eq!(pool.in_use_count(), limit);

        // One object is still free, so this refusal is the segment limit.
        let head = m.as_ptr();
        assert!(m.prepend(1).is_none());
        assert_eq!(m.as_ptr(), head);
        assert_eq!((m.nb_segs(), m.pkt_len(), m.len()), (u16::MAX, pkt_len, room));
        assert_eq!(pool.in_use_count(), limit);

        drop(m);
        assert_pool_returned_exactly_once(&pool, limit + 1);
    }

    #[zhida_test_support::pinned_test]
    fn test_prepend_header_segment_on_exhausted_pool_returns_none_unchanged() {
        let pool = PoolManager::new(8);
        let mut mbuf = pool.alloc_with_len(100).unwrap();
        mbuf.data_mut().fill(0xDD);
        let shared = mbuf.share();
        let mut held = Vec::new();
        while let Some(m) = pool.alloc() {
            held.push(m);
        }
        assert_eq!(held.len(), 7);

        let before = chain_state(mbuf.as_ptr());
        assert!(mbuf.prepend(10).is_none(), "shared head");
        assert_eq!(chain_state(mbuf.as_ptr()), before);
        drop(shared);
        let before = chain_state(mbuf.as_ptr());
        assert!(mbuf.prepend(200).is_none(), "beyond headroom");
        assert_eq!(chain_state(mbuf.as_ptr()), before);
        assert_eq!(pool.in_use_count(), 8);

        drop(held);
        drop(mbuf);
        assert_pool_returned_exactly_once(&pool, 8);
    }

    #[zhida_test_support::pinned_test]
    fn test_prepend_zero_on_non_exclusive_head_is_noop() {
        let pool = PoolManager::new(256);
        let mut mbuf = pool.alloc_with_len(100).unwrap();
        mbuf.data_mut().fill(0xDD);
        let shared = mbuf.share();
        let mut clone = mbuf.clone_indirect(&pool).unwrap();

        for m in [&mut mbuf, &mut clone] {
            let head = m.as_ptr();
            let before = chain_state(head);
            let in_use = pool.in_use_count();
            assert_eq!(m.prepend(0).expect("empty header").len(), 0);
            assert_eq!(m.as_ptr(), head);
            assert_eq!(chain_state(head), before);
            assert_eq!(pool.in_use_count(), in_use);
        }

        drop(clone);
        drop(shared);
        drop(mbuf);
        assert_pool_returned_exactly_once(&pool, 256);
    }

    #[zhida_test_support::pinned_test]
    fn test_prepend_header_and_in_place_give_same_packet_metadata() {
        let pool = PoolManager::new(256);
        let mut in_place = pool.alloc_with_len(100).unwrap();
        let mut header = pool.alloc_with_len(100).unwrap();
        set_packet_meta(&in_place);
        set_packet_meta(&header);
        let shared = header.share();

        in_place.prepend(20).unwrap().fill(0xAA);
        assert_eq!(in_place.nb_segs(), 1);
        assert_prepends_header(&mut header, 20, 0xAA);
        assert_eq!(packet_meta(header.as_ptr()), packet_meta(in_place.as_ptr()));

        // Indirect old head: the header segment is direct (INDIRECT bit cleared).
        let mut clone = in_place.clone_indirect(&pool).unwrap();
        set_packet_meta(&clone);
        assert!(clone.is_head_indirect());
        assert_prepends_header(&mut clone, 20, 0xBB);
        assert_eq!(packet_meta(clone.as_ptr()), packet_meta(in_place.as_ptr()));

        drop(clone);
        drop(header);
        drop(shared);
        drop(in_place);
        assert_pool_returned_exactly_once(&pool, 256);
    }

    /// Converting an indirect head whose header has a second owner must be refused:
    /// the C conversion would move a backing-buffer reference the second owner still
    /// needs, letting the result prepend over its bytes and free the buffer under it.
    fn assert_into_indirect_head_refused_with_second_owner(second_owner: fn(&mut Mbuf) -> Mbuf) {
        let pool = PoolManager::new(256);
        let mut orig = pool.alloc_with_len(100).unwrap();
        for (i, byte) in orig.data_mut().iter_mut().enumerate() {
            *byte = i as u8;
        }
        let mut c = orig.clone_indirect(&pool).unwrap();
        drop(orig);
        let c2 = second_owner(&mut c);
        assert_eq!(c2.refcount(), 2);
        let in_use = pool.in_use_count();

        let c = c.into_indirect_head(&pool).expect_err("indirect head must not convert");
        assert_eq!(pool.in_use_count(), in_use);
        assert!(c.is_head_indirect());
        drop(c);
        // Backing buffer stays allocated while c2 is attached to it.
        assert_eq!(c2.refcount(), 1);
        assert_eq!(pool.in_use_count(), 2);
        assert!(c2.data().iter().copied().eq(0..100u8));
        drop(c2);
        assert_pool_returned_exactly_once(&pool, 256);
    }

    #[zhida_test_support::pinned_test]
    fn test_into_indirect_head_refused_on_indirect_with_shared_header() {
        assert_into_indirect_head_refused_with_second_owner(Mbuf::share);
    }

    #[zhida_test_support::pinned_test]
    fn test_into_indirect_head_refused_on_indirect_with_cloned_header() {
        assert_into_indirect_head_refused_with_second_owner(|m| m.clone());
    }

    // ========================================================================
    // Segment iteration
    // ========================================================================

    #[zhida_test_support::pinned_test]
    fn test_iter_segs_single_segment() {
        let pool = PoolManager::new(256);
        let mbuf = pool.alloc_with_len(100).unwrap();
        let mut segments = mbuf.iter_segs();
        assert_eq!(segments.next(), Some(mbuf.as_ptr()));
        assert_eq!(segments.next(), None);
        assert_eq!(segments.next(), None);
        drop(segments);
        drop(mbuf);
        assert_pool_returned_exactly_once(&pool, 256);
    }

    #[zhida_test_support::pinned_test]
    fn test_iter_segs_chain_in_order_then_end() {
        let pool = PoolManager::new(256);
        let mut head = pool.alloc_with_len(100).unwrap();
        let middle = pool.alloc_with_len(50).unwrap();
        let tail = pool.alloc_with_len(30).unwrap();
        let expected = vec![head.as_ptr(), middle.as_ptr(), tail.as_ptr()];
        head.chain(middle).unwrap();
        head.chain(tail).unwrap();

        let mut segments = head.iter_segs();
        let visited: Vec<_> = segments.by_ref().take(3).collect();
        assert_eq!(visited, expected);
        let lens: Vec<u16> = visited.iter().map(|&seg| unsafe { (*seg).data_len() }).collect();
        assert_eq!(lens, [100, 50, 30]);
        assert_eq!(segments.next(), None);
        assert_eq!(segments.next(), None);
        drop(segments);
        drop(head);
        assert_pool_returned_exactly_once(&pool, 256);
    }

    #[zhida_test_support::pinned_test]
    fn test_iter_segs_early_drop_leaves_owner_usable() {
        let pool = PoolManager::new(256);
        let mut head = pool.alloc_with_len(100).unwrap();
        head.chain(pool.alloc_with_len(50).unwrap()).unwrap();

        let mut segments = head.iter_segs();
        assert_eq!(segments.next(), Some(head.as_ptr()));
        drop(segments);

        head.chain(pool.alloc_with_len(30).unwrap()).unwrap();
        assert_eq!(head.iter_segs().count(), 3);
        assert_eq!(head.pkt_len(), 180);
        drop(head);
        assert_pool_returned_exactly_once(&pool, 256);
    }
}
