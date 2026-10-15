#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

mod affinity;
pub use affinity::{only_allowed_cpu, AffinityError};

// Shim functions for DPDK inline functions
#[link(name = "zhida_dpdk_shim")]
unsafe extern "C" {
    /// Direct inline ethdev calls: valid started port/queue and writable pointer array.
    /// TX transfers only the returned prefix; RX transfers every returned pointer.
    pub fn dpdk_raw_eth_rx_burst(
        port: u16,
        queue: u16,
        packets: *mut *mut rte_mbuf,
        count: u16,
    ) -> u16;
    pub fn dpdk_raw_eth_tx_burst(
        port: u16,
        queue: u16,
        packets: *mut *mut rte_mbuf,
        count: u16,
    ) -> u16;
    /// Requires a valid started port/queue and exclusively writable mbufs.
    /// Returns the prepared prefix length.
    pub fn dpdk_raw_eth_tx_prepare(
        port: u16,
        queue: u16,
        packets: *mut *mut rte_mbuf,
        count: u16,
    ) -> u16;
    /// Requires an exclusively writable mbuf with TX offload flags and lengths set.
    pub fn dpdk_raw_net_intel_cksum_prepare(m: *mut rte_mbuf) -> std::ffi::c_int;

    /// Ring calls require valid ring/storage and its producer/consumer discipline.
    /// Enqueue transfers the returned prefix; dequeue transfers returned objects.
    pub fn dpdk_raw_ring_enqueue_burst(
        ring: *mut rte_ring,
        objects: *const *mut std::ffi::c_void,
        count: std::ffi::c_uint,
        free_space: *mut std::ffi::c_uint,
    ) -> std::ffi::c_uint;
    pub fn dpdk_raw_ring_dequeue_burst(
        ring: *mut rte_ring,
        objects: *mut *mut std::ffi::c_void,
        count: std::ffi::c_uint,
        available: *mut std::ffi::c_uint,
    ) -> std::ffi::c_uint;

    pub fn zhida_pktmbuf_alloc(mp: *mut rte_mempool) -> *mut rte_mbuf;

    /// Get the current thread's DPDK error number.
    pub fn zhida_errno() -> std::ffi::c_int;

    /// Get the current thread's DPDK lcore ID, or u32::MAX if unregistered.
    pub fn zhida_lcore_id() -> u32;

    /// Get cache pointer for pool+lcore. Call ONCE at pool init, store result.
    /// Returns null if the calling thread has no lcore ID or caches are disabled.
    pub fn zhida_get_pool_cache(mp: *mut rte_mempool) -> *mut rte_mempool_cache;

    /// Alloc with precomputed cache pointer stored in dynfield2.
    /// Cache pointer must come from zhida_get_pool_cache called on same lcore.
    pub fn zhida_pktmbuf_alloc_fast(
        mp: *mut rte_mempool,
        cache: *mut rte_mempool_cache,
    ) -> *mut rte_mbuf;

    /// Optimized single-segment free with musttail structure.
    /// Handles refcount, direct/indirect/external correctly.
    /// Uses tail calls to keep fast path tight.
    pub fn zhida_pktmbuf_free_seg(m: *mut rte_mbuf);

    /// Full DPDK free - handles refcount, chains, indirect, external
    /// Use this for chain free (walks entire chain).
    pub fn zhida_pktmbuf_free(m: *mut rte_mbuf);

    /// Minimal free - ONLY for refcnt==1, no chain, direct buffer
    /// No refcount check, no indirect/external handling.
    pub fn zhida_pktmbuf_free_minimal(m: *mut rte_mbuf);

    /// Append `tail` to `head` without ownership or cycle checks.
    /// Writes lastseg(head).next, head.nb_segs, head.pkt_len and sets tail.pkt_len = tail.data_len.
    /// Returns 0 on success, -EOVERFLOW (nothing written) if the combined segment
    /// count exceeds RTE_MBUF_MAX_NB_SEGS.
    ///
    /// # Safety
    /// - `head` and `tail` are valid chain heads with consistent metadata
    ///   (nb_segs = segment count, pkt_len = sum of data_len); this bounds the
    ///   pkt_len sum, which is not checked separately.
    /// - No other owner reaches any segment of `head`'s chain (lastseg(head).refcnt == 1
    ///   suffices): another owner's free would walk into `tail` without a reference.
    /// - `tail` is a reference the caller owns independently of `head`, and `tail`'s chain
    ///   shares no segment with `head`'s chain (no cycles). lastseg(head).refcnt == 1 does
    ///   not exclude this: `chain(p, p)` with one reference sets p.next = p, and free then
    ///   returns p twice.
    /// - No other owner relies on tail.pkt_len (tail.refcnt == 1, or tail.pkt_len == tail.data_len).
    /// - On 0, the caller's reference to every `tail` segment moves into `head`; do not free
    ///   `tail` separately. On -EOVERFLOW the caller still owns `tail`.
    pub fn zhida_pktmbuf_chain(head: *mut rte_mbuf, tail: *mut rte_mbuf) -> i32;

    /// Append `tail` to `head` only if no other owner reaches a written field:
    /// lastseg(head).refcnt == 1, and tail.refcnt == 1 or tail.pkt_len == tail.data_len
    /// (tail.pkt_len is stored only when it changes). Single walk to lastseg.
    /// Returns: 0 success, -1 refused, -EOVERFLOW too many segs; nothing written on refusal.
    /// The caller keeps ownership of `tail` on refusal; on 0 it moves into `head`.
    ///
    /// # Safety
    /// The refusal is sound only if:
    /// - `head` and `tail` are valid chain heads with consistent metadata.
    /// - Every other holder of a pointer to any segment of either chain owns a counted
    ///   reference on it (refcnt counts every walker and every attached indirect).
    /// - `tail` is a reference the caller owns independently of `head`, and `tail`'s chain
    ///   shares no segment with `head`'s chain. Not checked: `chain_safe(p, p)` with one
    ///   reference passes the refcnt checks and creates the cycle p.next = p.
    pub fn zhida_pktmbuf_chain_safe(head: *mut rte_mbuf, tail: *mut rte_mbuf) -> i32;

    /// Get last segment in chain.
    pub fn zhida_pktmbuf_lastseg(m: *mut rte_mbuf) -> *mut rte_mbuf;

    /// Update refcount by delta. Returns new refcount.
    pub fn zhida_mbuf_refcnt_update(m: *mut rte_mbuf, delta: i16) -> u16;

    /// Initialize all mbufs in pool with cache pointer.
    /// Call ONCE at pool creation to pre-set cache ptr in every mbuf's priv_data.
    /// After this, alloc path doesn't need to set cache ptr.
    pub fn zhida_pool_init_cache_ptrs(mp: *mut rte_mempool, cache: *mut rte_mempool_cache);

    /// Clone chain with indirect mbufs. Creates new mbuf wrappers pointing to same buffers.
    /// Each indirect has independent data_off/data_len but shares underlying buffer bytes.
    /// Underlying direct mbufs get refcount incremented.
    pub fn zhida_pktmbuf_clone(
        md: *mut rte_mbuf,
        mp: *mut rte_mempool,
        cache: *mut rte_mempool_cache,
    ) -> *mut rte_mbuf;

    /// Attach indirect mbuf to direct mbuf's buffer.
    /// mi becomes indirect, pointing to md's buffer. md's refcount incremented.
    pub fn zhida_pktmbuf_attach(mi: *mut rte_mbuf, md: *mut rte_mbuf);

    /// Consume `m`'s reference, return a new chain: a fresh indirect attached to
    /// `m`'s direct buffer, then `m`'s former tail segments. O(1). Returns NULL
    /// (nothing written) if allocation fails.
    ///
    /// Writes m.next = NULL and m.nb_segs = 1; the reference `m`'s owner held on
    /// every tail segment moves to the new head (no tail refcount changes); `m`'s
    /// owner reference becomes the new indirect's attachment.
    ///
    /// # Safety
    /// - `m` MUST be a direct chain head: not indirect, no external buffer. The
    ///   function never detaches or returns `m`, so an indirect `m`'s header leaks
    ///   and its attachment count passes to the new header: two headers attached to
    ///   the backing buffer, one count.
    /// - `m` has consistent metadata. The new header is allocated from `mp`, and
    ///   `cache` is `mp`'s cache for this lcore; `m` may come from any pool.
    /// - No other owner reaches `m` unless `m.next` is already NULL (`m.refcnt == 1`
    ///   suffices). Otherwise that owner's chain is cut to one segment and its
    ///   references on the former tail segments leak.
    /// - On non-NULL the caller no longer owns `m`; on NULL it still does.
    pub fn zhida_pktmbuf_into_indirect_head(
        m: *mut rte_mbuf,
        mp: *mut rte_mempool,
        cache: *mut rte_mempool_cache,
    ) -> *mut rte_mbuf;

    /// Clone head as indirect, share tail segments. O(n).
    /// Original chain unchanged. Returns new chain sharing same tail mbufs.
    pub fn zhida_pktmbuf_clone_indirect_head(
        m: *mut rte_mbuf,
        mp: *mut rte_mempool,
        cache: *mut rte_mempool_cache,
    ) -> *mut rte_mbuf;

    /// Allocate a fresh direct segment from `head`'s own pool and link it in front of
    /// `head`. Returns the new head, or NULL with nothing allocated or written when
    /// `head.nb_segs` is already RTE_MBUF_MAX_NB_SEGS, `len` exceeds the pool's data
    /// room (headroom included), or the pool is exhausted.
    ///
    /// The new head has `len` bytes at the end of its buffer (`data_off = buf_len - len`),
    /// `pkt_len = head.pkt_len + len`, `nb_segs = head.nb_segs + 1`, `next = head`, DPDK's
    /// header-copy metadata from `head` (`__rte_pktmbuf_copy_hdr`: port, VLAN tags,
    /// tx_offload, hash, packet_type, dynfields) and `head.ol_flags` without
    /// INDIRECT/EXTERNAL (as `rte_pktmbuf_copy`). No field of `head`'s chain is written.
    ///
    /// # Safety
    /// - `head` is a valid chain head with consistent metadata, owned by the caller.
    /// - `head.pool` is a pktmbuf pool whose objects carry the zhida cache pointer in
    ///   their private slot (`zhida_pool_init_cache_ptrs`) for the calling lcore. For an
    ///   indirect head this is the pool its header came from, not the backing buffer's.
    /// - On non-NULL the caller's references to `head`'s chain move into the new head;
    ///   own and free only the returned pointer. On NULL the caller still owns `head`.
    pub fn zhida_pktmbuf_prepend_seg(head: *mut rte_mbuf, len: u16) -> *mut rte_mbuf;

    // =========================================================================
    // Raw DPDK wrappers - for benchmark comparison
    // These call standard DPDK functions directly (no optimizations).
    // =========================================================================

    /// Raw DPDK alloc - computes cache from TLS each call.
    pub fn dpdk_raw_pktmbuf_alloc(mp: *mut rte_mempool) -> *mut rte_mbuf;

    /// Raw DPDK free - standard chain-walking free.
    pub fn dpdk_raw_pktmbuf_free(m: *mut rte_mbuf);

    /// Raw DPDK single-segment free.
    pub fn dpdk_raw_pktmbuf_free_seg(m: *mut rte_mbuf);

    /// Raw DPDK clone - computes cache from TLS each call.
    pub fn dpdk_raw_pktmbuf_clone(md: *mut rte_mbuf, mp: *mut rte_mempool) -> *mut rte_mbuf;

    /// Raw DPDK chain.
    pub fn dpdk_raw_pktmbuf_chain(head: *mut rte_mbuf, tail: *mut rte_mbuf) -> i32;

    /// Raw DPDK lastseg.
    pub fn dpdk_raw_pktmbuf_lastseg(m: *mut rte_mbuf) -> *mut rte_mbuf;

    /// Raw DPDK refcount update.
    pub fn dpdk_raw_mbuf_refcnt_update(m: *mut rte_mbuf, delta: i16) -> u16;

    /// Raw DPDK attach.
    pub fn dpdk_raw_pktmbuf_attach(mi: *mut rte_mbuf, md: *mut rte_mbuf);

    /// Raw DPDK trim (trims from last segment). Returns 0 on success, -1 on failure.
    pub fn dpdk_raw_pktmbuf_trim(m: *mut rte_mbuf, len: u16) -> i32;

    /// Raw DPDK adjust (consume from front). Returns pointer to new data start, or NULL.
    pub fn dpdk_raw_pktmbuf_adj(m: *mut rte_mbuf, len: u16) -> *mut u8;

    /// Raw DPDK prepend. Returns pointer to new data start, or NULL.
    pub fn dpdk_raw_pktmbuf_prepend(m: *mut rte_mbuf, len: u16) -> *mut u8;

    /// Raw DPDK external-buffer attach for a direct mbuf with refcnt 1.
    /// Shared info is carved from the end of `buf`; `free_cb(buf, opaque)` runs
    /// when the last reference is released. Returns 0, or -1 if `len` is too small.
    pub fn dpdk_raw_pktmbuf_attach_extbuf(
        m: *mut rte_mbuf,
        buf: *mut std::ffi::c_void,
        len: u16,
        free_cb: Option<unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void)>,
        opaque: *mut std::ffi::c_void,
    ) -> i32;

    /// Flush per-lcore cache back to pool.
    pub fn zhida_mempool_cache_flush(cache: *mut rte_mempool_cache, mp: *mut rte_mempool);

    /// Name of the mempool ops backing `mp` (for example `ring_sp_sc`).
    pub fn zhida_mempool_ops_name(mp: *const rte_mempool) -> *const std::ffi::c_char;
}

/// Allocate an mbuf from a mempool.
#[inline]
pub unsafe fn rte_pktmbuf_alloc(mp: *mut rte_mempool) -> *mut rte_mbuf {
    zhida_pktmbuf_alloc(mp)
}

/// Free an mbuf back to its pool.
#[inline]
pub unsafe fn rte_pktmbuf_free(m: *mut rte_mbuf) {
    zhida_pktmbuf_free(m)
}

/// Unchecked append; see `zhida_pktmbuf_chain` for the return codes and safety contract.
///
/// # Safety
/// Same as `zhida_pktmbuf_chain`.
#[inline]
pub unsafe fn rte_pktmbuf_chain(head: *mut rte_mbuf, tail: *mut rte_mbuf) -> i32 {
    zhida_pktmbuf_chain(head, tail)
}

/// Get last segment in chain.
#[inline]
pub unsafe fn rte_pktmbuf_lastseg(m: *mut rte_mbuf) -> *mut rte_mbuf {
    zhida_pktmbuf_lastseg(m)
}

/// Update refcount by delta. Returns new refcount.
#[inline]
pub unsafe fn rte_mbuf_refcnt_update(m: *mut rte_mbuf, delta: i16) -> u16 {
    zhida_mbuf_refcnt_update(m, delta)
}

/// Pure Rust inline methods for rte_mbuf.
/// These bypass C shims for hot-path performance.
impl rte_mbuf {
    /// Get ol_flags field.
    #[inline(always)]
    pub fn ol_flags(&self) -> u64 {
        self.ol_flags
    }

    /// Set ol_flags field.
    #[inline(always)]
    pub fn set_ol_flags(&mut self, val: u64) {
        self.ol_flags = val
    }

    /// Set l2_len, l3_len and l4_len bitfields.
    ///
    /// Panics if a length does not fit its DPDK field (7, 9 and 8 bits); a
    /// truncated length would make the PMD read headers at wrong offsets.
    #[inline(always)]
    pub fn set_tx_offload_lengths(&mut self, l2_len: u16, l3_len: u16, l4_len: u16) {
        assert!(
            l2_len < 1 << 7 && l3_len < 1 << 9 && l4_len < 1 << 8,
            "TX offload lengths {l2_len}/{l3_len}/{l4_len} exceed the mbuf fields"
        );
        unsafe {
            let offload = &mut self.__bindgen_anon_3.__bindgen_anon_1;
            offload.set_l2_len(u64::from(l2_len));
            offload.set_l3_len(u64::from(l3_len));
            offload.set_l4_len(u64::from(l4_len));
        }
    }

    /// Get data_off field.
    #[inline(always)]
    pub fn data_off(&self) -> u16 {
        unsafe { self.__bindgen_anon_1.__bindgen_anon_1.data_off }
    }

    /// Set data_off field.
    #[inline(always)]
    pub fn set_data_off(&mut self, val: u16) {
        self.__bindgen_anon_1.__bindgen_anon_1.data_off = val
    }

    /// Get refcnt field (non-atomic read).
    #[inline(always)]
    pub fn refcnt(&self) -> u16 {
        unsafe { self.__bindgen_anon_1.__bindgen_anon_1.refcnt }
    }

    /// Set refcnt field (non-atomic write).
    #[inline(always)]
    pub fn set_refcnt(&mut self, val: u16) {
        self.__bindgen_anon_1.__bindgen_anon_1.refcnt = val
    }

    /// Increment refcnt (non-atomic) with overflow check.
    /// Aborts if refcount would overflow.
    #[inline(always)]
    pub fn refcnt_inc(&mut self) {
        unsafe {
            let r = self.__bindgen_anon_1.__bindgen_anon_1.refcnt;
            if r == u16::MAX {
                // Cold path - will abort, compiler knows this won't return
                Self::refcnt_overflow();
            }
            self.__bindgen_anon_1.__bindgen_anon_1.refcnt = r + 1;
        }
    }

    #[cold]
    #[inline(never)]
    fn refcnt_overflow() -> ! {
        panic!("FATAL: mbuf refcnt overflow (would exceed u16::MAX)");
    }

    /// Decrement refcnt (non-atomic). Returns true if refcnt reached 0.
    #[inline(always)]
    pub fn refcnt_dec(&mut self) -> bool {
        unsafe {
            let r = &mut self.__bindgen_anon_1.__bindgen_anon_1.refcnt;
            debug_assert!(*r > 0, "refcnt_dec() called on mbuf with refcnt=0");
            *r -= 1;
            *r == 0
        }
    }

    /// Get data_len field.
    #[inline(always)]
    pub fn data_len(&self) -> u16 {
        unsafe { self.__bindgen_anon_2.__bindgen_anon_1.data_len }
    }

    /// Set data_len field.
    #[inline(always)]
    pub fn set_data_len(&mut self, val: u16) {
        self.__bindgen_anon_2.__bindgen_anon_1.data_len = val
    }

    /// Get pkt_len field.
    #[inline(always)]
    pub fn pkt_len(&self) -> u32 {
        unsafe { self.__bindgen_anon_2.__bindgen_anon_1.pkt_len }
    }

    /// Set pkt_len field.
    #[inline(always)]
    pub fn set_pkt_len(&mut self, val: u32) {
        self.__bindgen_anon_2.__bindgen_anon_1.pkt_len = val
    }

    /// Get buf_len field.
    #[inline(always)]
    pub fn buf_len(&self) -> u16 {
        unsafe { self.__bindgen_anon_2.__bindgen_anon_1.buf_len }
    }

    /// Get nb_segs field.
    #[inline(always)]
    pub fn nb_segs(&self) -> u16 {
        unsafe { self.__bindgen_anon_1.__bindgen_anon_1.nb_segs }
    }

    /// Set nb_segs field.
    #[inline(always)]
    pub fn set_nb_segs(&mut self, val: u16) {
        self.__bindgen_anon_1.__bindgen_anon_1.nb_segs = val
    }

    /// Get pointer to data start (buf_addr + data_off).
    #[inline(always)]
    pub fn data_ptr(&self) -> *mut u8 {
        unsafe { (self.buf_addr as *mut u8).add(self.data_off() as usize) }
    }

    /// Available headroom (data_off).
    #[inline(always)]
    pub fn headroom(&self) -> u16 {
        self.data_off()
    }

    /// Available tailroom.
    #[inline(always)]
    pub fn tailroom(&self) -> u16 {
        self.buf_len() - self.data_off() - self.data_len()
    }

    /// Prepend n bytes into headroom. Returns pointer to prepended region, or None if insufficient.
    #[inline(always)]
    pub fn prepend(&mut self, n: u16) -> Option<*mut u8> {
        let data_off = self.data_off();
        if n > data_off {
            return None;
        }
        let new_off = data_off - n;
        self.set_data_off(new_off);
        self.set_data_len(self.data_len() + n);
        self.set_pkt_len(self.pkt_len() + n as u32);
        Some(unsafe { (self.buf_addr as *mut u8).add(new_off as usize) })
    }

    /// Adjust (trim front) by n bytes. Returns false if insufficient data.
    #[inline(always)]
    pub fn adjust(&mut self, n: u16) -> bool {
        if n > self.data_len() {
            return false;
        }
        self.set_data_off(self.data_off() + n);
        self.set_data_len(self.data_len() - n);
        self.set_pkt_len(self.pkt_len() - n as u32);
        true
    }

    /// Trim back by n bytes. Returns false if insufficient data.
    #[inline(always)]
    pub fn trim(&mut self, n: u16) -> bool {
        if n > self.data_len() {
            return false;
        }
        self.set_data_len(self.data_len() - n);
        self.set_pkt_len(self.pkt_len() - n as u32);
        true
    }

    /// Get next mbuf in chain (NULL if tail).
    #[inline(always)]
    pub fn next(&self) -> *mut rte_mbuf {
        self.next
    }

    /// Set next mbuf in chain.
    #[inline(always)]
    pub fn set_next(&mut self, next: *mut rte_mbuf) {
        self.next = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mbuf_size() {
        assert_eq!(std::mem::size_of::<rte_mbuf>(), 128);
    }

    #[test]
    fn test_field_offsets() {
        // Verify critical field offsets match DPDK layout
        assert_eq!(std::mem::offset_of!(rte_mbuf, buf_addr), 0);
        assert_eq!(std::mem::offset_of!(rte_mbuf, buf_iova), 8);
        // __bindgen_anon_1 (data_off, refcnt, etc.) at offset 16
        assert_eq!(std::mem::offset_of!(rte_mbuf, __bindgen_anon_1), 16);
        assert_eq!(std::mem::offset_of!(rte_mbuf, ol_flags), 24);
        // __bindgen_anon_2 (pkt_len, data_len, etc.) at offset 32
        assert_eq!(std::mem::offset_of!(rte_mbuf, __bindgen_anon_2), 32);
        assert_eq!(std::mem::offset_of!(rte_mbuf, pool), 56);
        assert_eq!(std::mem::offset_of!(rte_mbuf, __bindgen_anon_3), 72);
        assert_eq!(std::mem::offset_of!(rte_mbuf__bindgen_ty_3, tx_offload), 0);
    }

    #[test]
    fn tx_offload_lengths_fill_dpdk_bit_layout() {
        let mut m: rte_mbuf = unsafe { std::mem::zeroed() };
        m.set_tx_offload_lengths(127, 511, 255);
        assert_eq!(unsafe { m.__bindgen_anon_3.tx_offload }, 0xff_ffff);
        m.set_tx_offload_lengths(14, 20, 32);
        assert_eq!(
            unsafe { m.__bindgen_anon_3.tx_offload },
            14 | 20 << 7 | 32 << 16
        );
    }

    #[test]
    #[should_panic(expected = "exceed the mbuf fields")]
    fn tx_offload_l2_len_overflow_panics() {
        let mut m: rte_mbuf = unsafe { std::mem::zeroed() };
        m.set_tx_offload_lengths(128, 20, 20);
    }
}

#[cfg(all(test, debug_assertions))]
#[test]
fn assume_checked_in_debug_build() {
    unsafe extern "C" {
        fn zhida_assume_checked() -> i32;
    }
    assert_eq!(unsafe { zhida_assume_checked() }, 1);
}
