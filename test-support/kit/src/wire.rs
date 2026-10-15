//! Test/bench-only copying wire between net_ring ports; not a Zhida path.
//! Also the pool lookups tests share: `in_use` and `pool_exists` by name.
//!
//! The receiver's RX pool is found by the name the test passed in its
//! PortConfig. Standard `rte_pktmbuf_alloc` takes from the pool's default cache
//! for this lcore, the same cache the zhida destructor reaches through the
//! private slot initialized on every object at pool creation.

use std::ffi::{c_void, CStr};
use std::mem::MaybeUninit;
use std::ptr::{null_mut, NonNull};

use zhida_buffer::Mbuf;
use zhida_dpdk_sys::*;

pub fn pool_by_name(name: &CStr) -> *mut rte_mempool {
    let pool = unsafe { rte_mempool_lookup(name.as_ptr()) };
    assert!(!pool.is_null());
    pool
}

/// Packets in use in the pool named `name`, which must exist.
pub fn in_use(name: &CStr) -> u32 {
    unsafe { rte_mempool_in_use_count(pool_by_name(name)) }
}

/// Audit a live pool after every frame has been freed.
pub fn assert_returned_exactly_once(name: &CStr) {
    let pool = pool_by_name(name);
    unsafe {
        let size = (*pool).size;
        let mut held = Vec::with_capacity(size as usize);
        let cache = zhida_dpdk_sys::zhida_get_pool_cache(pool);
        while let Some(m) = NonNull::new(zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(pool, cache))
            .map(|m| Mbuf::from_raw(m))
        {
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
}

/// Whether a pool named `name` exists.
pub fn pool_exists(name: &CStr) -> bool {
    !unsafe { rte_mempool_lookup(name.as_ptr()) }.is_null()
}

/// A fresh single-segment mbuf from `pool` holding a copy of `bytes`.
#[inline]
pub fn copy_into(pool: *mut rte_mempool, bytes: &[u8]) -> *mut rte_mbuf {
    let packet = try_copy_into(pool, bytes);
    assert!(!packet.is_null());
    packet
}

/// Null when `pool` is empty. Checks run before allocating or free the
/// packet, so a panic leaks nothing.
#[inline]
fn try_copy_into(pool: *mut rte_mempool, bytes: &[u8]) -> *mut rte_mbuf {
    let len = u16::try_from(bytes.len()).unwrap();
    let packet = unsafe { dpdk_raw_pktmbuf_alloc(pool) };
    if packet.is_null() {
        return packet;
    }
    unsafe {
        let mbuf = &mut *packet;
        if len > mbuf.tailroom() {
            oversize(packet);
        }
        mbuf.set_data_len(len);
        mbuf.set_pkt_len(u32::from(len));
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), mbuf.data_ptr(), bytes.len());
    }
    packet
}

/// Frees `packet`, which this side owns, then panics.
#[cold]
#[inline(never)]
fn oversize(packet: *mut rte_mbuf) -> ! {
    unsafe { dpdk_raw_pktmbuf_free(packet) };
    panic!("frame exceeds the mbuf tailroom");
}

/// The data bytes of a single-segment mbuf.
///
/// # Safety
/// `packet` is a valid mbuf that outlives the returned slice.
#[inline]
unsafe fn bytes<'p>(packet: *mut rte_mbuf) -> &'p [u8] {
    assert_eq!((*packet).nb_segs(), 1, "Link copies single-segment frames");
    std::slice::from_raw_parts((*packet).data_ptr(), usize::from((*packet).data_len()))
}

/// Up to `N` mbufs dequeued from one ring and owned until the next `refill` or
/// the drop frees them, so a panic while the caller reads them leaks nothing.
/// Reused across bursts: nothing is initialized or moved per burst.
pub(crate) struct Burst<const N: usize> {
    raw: [MaybeUninit<*mut rte_mbuf>; N],
    count: usize,
}

impl<const N: usize> Burst<N> {
    pub(crate) fn new() -> Self {
        Self {
            raw: [MaybeUninit::uninit(); N],
            count: 0,
        }
    }

    /// Free the current mbufs, then dequeue up to `N` from `ring`.
    pub(crate) fn refill(&mut self, ring: *mut rte_ring) -> &[*mut rte_mbuf] {
        self.free();
        let raw = self.raw.as_mut_ptr().cast();
        self.count =
            unsafe { dpdk_raw_ring_dequeue_burst(ring, raw, N as u32, null_mut()) } as usize;
        self.packets()
    }

    /// The current mbufs, in ring order.
    fn packets(&self) -> &[*mut rte_mbuf] {
        // The ring wrote the first `count` slots.
        unsafe { std::slice::from_raw_parts(self.raw.as_ptr().cast(), self.count) }
    }

    fn free(&mut self) {
        for &packet in self.packets() {
            unsafe { dpdk_raw_pktmbuf_free(packet) };
        }
        self.count = 0;
    }
}

impl<const N: usize> Drop for Burst<N> {
    fn drop(&mut self) {
        self.free();
    }
}

/// Free every frame on `ring`; returns how many. Allocates nothing and cannot
/// panic.
pub(crate) fn drain_ring(ring: *mut rte_ring) -> usize {
    let mut burst = Burst::<16>::new();
    let mut freed = 0;
    loop {
        let count = burst.refill(ring).len();
        if count == 0 {
            return freed;
        }
        freed += count;
    }
}

/// Take every frame off `ring`, in order, each seen by `inspect` and then
/// freed; returns how many. Allocates nothing.
pub(crate) fn drain_ring_with(ring: *mut rte_ring, mut inspect: impl FnMut(&[u8])) -> usize {
    let mut burst = Burst::<16>::new();
    let mut taken = 0;
    loop {
        let packets = burst.refill(ring);
        if packets.is_empty() {
            return taken;
        }
        for &packet in packets {
            inspect(unsafe { bytes(packet) });
        }
        taken += packets.len();
    }
}

const BURST: usize = 8;

/// What an impaired Link does with one frame taken off the sender's ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Deliver,
    /// Deliver it twice, each copy from the receiver's RX pool. A held frame
    /// follows the first delivered copy, as with Deliver.
    Duplicate,
    /// Free it and count it in `Link::dropped`.
    Drop,
    /// Keep a copy, counted in `Link::held`, and deliver it right after the
    /// next frame this Link delivers. One frame at a time; the copy is from
    /// the receiver's RX pool, which must hold one more packet for it.
    Hold,
}

/// One direction of a lossy link: a sender's TX ring to a receiver's RX ring,
/// each frame copied into the receiver's RX pool. The rings and pool must
/// outlive the Link.
pub struct Link {
    from: *mut rte_ring,
    to: *mut rte_ring,
    to_pool: *mut rte_mempool,
    /// Frames dropped because the receiver's RX pool was empty.
    pub pool_empty: u64,
    /// Frames dropped because the receiver's RX ring was full.
    pub ring_full: u64,
    /// Frames the impairment dropped.
    pub dropped: u64,
    /// Frames the impairment held.
    pub held: u64,
    /// A paused Link leaves every frame on the sender's TX ring.
    pub paused: bool,
    impairment: Option<Box<dyn FnMut(&[u8]) -> Verdict>>,
    /// The held copy, in the receiver's RX pool; this Link owns it.
    holding: Option<NonNull<rte_mbuf>>,
}

impl Link {
    pub(crate) fn new(from: *mut rte_ring, to: *mut rte_ring, to_pool: *mut rte_mempool) -> Self {
        Self {
            from,
            to,
            to_pool,
            pool_empty: 0,
            ring_full: 0,
            dropped: 0,
            held: 0,
            paused: false,
            impairment: None,
            holding: None,
        }
    }

    /// From now on `decide` sees the bytes of every frame taken off the
    /// sender's ring, in order, and chooses its fate.
    pub fn impair(&mut self, decide: impl FnMut(&[u8]) -> Verdict + 'static) {
        self.impairment = Some(Box::new(decide));
    }

    /// Copy `frame` into the receiver's RX pool and ring, counting drops.
    pub fn inject(&mut self, frame: &[u8]) {
        let copy = try_copy_into(self.to_pool, frame);
        if copy.is_null() {
            self.pool_empty += 1;
        } else {
            self.enqueue(copy, &mut |_| {});
        }
    }

    /// Free the held frame, if any; returns whether there was one.
    pub fn free_held(&mut self) -> bool {
        match self.holding.take() {
            Some(held) => {
                unsafe { dpdk_raw_pktmbuf_free(held.as_ptr()) };
                true
            }
            None => false,
        }
    }

    /// `forward_with` observing nothing.
    #[inline]
    pub fn forward(&mut self) -> usize {
        self.forward_with(|_| {})
    }

    /// Unless paused, drain the sender's TX ring, in order. Each frame gets
    /// the impairment's verdict (Deliver without one). A delivered frame is
    /// copied into the receiver's pool and enqueued on its RX ring, or dropped
    /// and counted; the sender's buffers are freed once either way, a burst at
    /// a time. `delivered` sees the bytes of each enqueued frame, held ones
    /// included. Returns the frames taken off the sender's ring.
    pub fn forward_with(&mut self, mut delivered: impl FnMut(&[u8])) -> usize {
        if self.paused {
            return 0;
        }
        // Owns each burst until the next refill frees it, also when a callback
        // panics.
        let mut burst = Burst::<BURST>::new();
        let mut taken = 0;
        loop {
            let sent_burst = burst.refill(self.from);
            if sent_burst.is_empty() {
                return taken;
            }
            taken += sent_burst.len();
            for &sent in sent_burst {
                let bytes = unsafe { bytes(sent) };
                let verdict = match &mut self.impairment {
                    Some(decide) => decide(bytes),
                    None => Verdict::Deliver,
                };
                match verdict {
                    Verdict::Deliver | Verdict::Duplicate => {
                        let copies = if verdict == Verdict::Duplicate { 2 } else { 1 };
                        for _ in 0..copies {
                            let copy = try_copy_into(self.to_pool, bytes);
                            if copy.is_null() {
                                self.pool_empty += 1;
                            } else if self.enqueue(copy, &mut delivered) {
                                if let Some(held) = self.holding.take() {
                                    self.enqueue(held.as_ptr(), &mut delivered);
                                }
                            }
                        }
                    }
                    Verdict::Drop => self.dropped += 1,
                    Verdict::Hold => {
                        assert!(self.holding.is_none(), "Link holds one frame at a time");
                        match NonNull::new(try_copy_into(self.to_pool, bytes)) {
                            None => self.pool_empty += 1,
                            Some(copy) => {
                                self.holding = Some(copy);
                                self.held += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Enqueue `copy`, which this Link owns, on the receiver's ring, or free
    /// it and count the drop.
    fn enqueue(&mut self, copy: *mut rte_mbuf, delivered: &mut impl FnMut(&[u8])) -> bool {
        let raw = [copy.cast::<c_void>()];
        if unsafe { dpdk_raw_ring_enqueue_burst(self.to, raw.as_ptr(), 1, null_mut()) } == 1 {
            // The receiver owns `copy` now but cannot run before this returns.
            delivered(unsafe { bytes(copy) });
            true
        } else {
            unsafe { dpdk_raw_pktmbuf_free(copy) };
            self.ring_full += 1;
            false
        }
    }
}

impl Drop for Link {
    /// Frees the held frame; outside a panic, holding one fails the test.
    fn drop(&mut self) {
        if self.free_held() && !std::thread::panicking() {
            panic!("Link dropped holding a frame; call free_held");
        }
    }
}
