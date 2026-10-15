//! Chain append ownership: `Mbuf::chain` may only write fields that no
//! other owner can reach. Rejection returns the tail and leaves both packets
//! unchanged; every segment returns to the pool exactly once. Also the chains
//! `prepend` builds when it links a header segment in front of a shared payload.

mod common;

use common::assert_returned_exactly_once;
use zhida_buffer::{Mbuf, PoolManager};
use zhida_dpdk_sys::rte_mbuf;

#[derive(Debug, PartialEq)]
struct Seg {
    addr: usize,
    refcnt: u16,
    data_len: u16,
    pkt_len: u32,
    nb_segs: u16,
    payload: Vec<u8>,
}

/// Every field the chain operation can write, plus payload bytes, per segment.
fn snapshot(m: &Mbuf) -> Vec<Seg> {
    let mut segs = Vec::new();
    let mut p = m.as_ptr();
    while !p.is_null() {
        assert!(segs.len() < 1024, "chain walk did not terminate");
        let seg = unsafe { &*p };
        segs.push(Seg {
            addr: p as usize,
            refcnt: seg.refcnt(),
            data_len: seg.data_len(),
            pkt_len: seg.pkt_len(),
            nb_segs: seg.nb_segs(),
            payload: unsafe {
                std::slice::from_raw_parts(seg.data_ptr(), seg.data_len() as usize).to_vec()
            },
        });
        p = seg.next();
    }
    segs
}

fn filled(pool: &PoolManager, len: u16, byte: u8) -> Mbuf {
    let mut m = pool.alloc_with_len(len).unwrap();
    m.data_mut().fill(byte);
    m
}

/// Unique chain of `lens.len()` segments, segment i filled with `byte + i`.
fn unique_chain(pool: &PoolManager, lens: &[u16], byte: u8) -> Mbuf {
    let mut head = filled(pool, lens[0], byte);
    for (i, &len) in lens.iter().enumerate().skip(1) {
        let seg = filled(pool, len, byte + i as u8);
        head.chain(seg).ok().expect("building a unique chain");
    }
    head
}

/// Assert `chain` rejects, returns the same tail, and changes neither packet.
fn assert_rejected(head: &mut Mbuf, tail: Mbuf) -> Mbuf {
    let head_before = snapshot(head);
    let tail_before = snapshot(&tail);
    let tail_ptr = tail.as_ptr();
    let tail = match head.chain(tail) {
        Ok(()) => panic!("accepted an append that writes a field another owner reaches"),
        Err(tail) => tail,
    };
    assert_eq!(tail.as_ptr(), tail_ptr, "rejection must return the same tail");
    assert_eq!(snapshot(head), head_before, "rejected head changed");
    assert_eq!(snapshot(&tail), tail_before, "rejected tail changed");
    tail
}

/// Allocate every free object and check none of them is `addr`, then release them.
fn assert_not_reallocated(pool: &PoolManager, addr: usize) {
    let mut taken = Vec::new();
    while let Some(m) = pool.alloc() {
        assert_ne!(m.as_ptr() as usize, addr, "segment still referenced was reallocated");
        taken.push(m);
    }
    assert!(!taken.is_empty());
}

const POOL: u32 = 64;

#[zhida_test_support::pinned_test]
fn unique_append_links_tail_and_frees_each_segment_once() {
    let pool = PoolManager::new(64);
    let mut head = filled(&pool, 100, 0xA1);
    let tail = unique_chain(&pool, &[50, 30], 0xB1);
    let tail_ptr = tail.as_ptr();

    head.chain(tail).ok().expect("unique append must succeed");

    let segs = snapshot(&head);
    assert_eq!(segs.len(), 3);
    assert_eq!((head.nb_segs(), head.pkt_len()), (3, 180));
    assert_eq!(segs[1].addr, tail_ptr as usize);
    assert!(segs.iter().all(|s| s.refcnt == 1));
    // Consumed multi-segment tail head no longer carries its old packet length.
    assert_eq!(segs[1].pkt_len, 50);
    assert_eq!(pool.in_use_count(), 3);
    drop(head);
    assert_eq!(pool.in_use_count(), 0);
    assert_returned_exactly_once(&pool, POOL);
}

#[zhida_test_support::pinned_test]
fn aliased_head_rejected_and_both_drop_orders_return_every_segment() {
    let pool = PoolManager::new(64);
    for head_lens in [&[100u16][..], &[100, 40]] {
        for alias_first in [true, false] {
            for use_share_all in [false, true] {
                let mut head = unique_chain(&pool, head_lens, 0x10);
                let alias = if use_share_all { head.share_all() } else { head.clone() };
                let alias_before = snapshot(&alias);

                let tail = filled(&pool, 50, 0xEE);
                let tail = assert_rejected(&mut head, tail);
                assert_eq!(snapshot(&alias), alias_before);

                let expected = head_lens.len() as u32 + 1;
                assert_eq!(pool.in_use_count(), expected);
                drop(tail);
                if alias_first {
                    drop(alias);
                    assert_eq!(snapshot(&head).iter().map(|s| s.refcnt).max(), Some(1));
                    drop(head);
                } else {
                    drop(head);
                    drop(alias);
                }
                assert_eq!(pool.in_use_count(), 0, "{head_lens:?} alias_first={alias_first}");
                assert_returned_exactly_once(&pool, POOL);
            }
        }
    }
}

#[zhida_test_support::pinned_test]
fn aliased_head_self_append_rejected_as_cycle() {
    let pool = PoolManager::new(64);
    for head_lens in [&[100u16][..], &[100, 40]] {
        let mut head = unique_chain(&pool, head_lens, 0x20);
        let alias = head.clone();
        let alias = assert_rejected(&mut head, alias);
        drop(alias);
        drop(head);
        assert_eq!(pool.in_use_count(), 0, "{head_lens:?}");
        assert_returned_exactly_once(&pool, POOL);
    }
}

#[zhida_test_support::pinned_test]
fn independently_headed_chains_sharing_last_segment_reject_append() {
    let pool = PoolManager::new(64);
    for original_first in [true, false] {
        // original: [D0] -> [S];  indirect: [I -> D0's buffer] -> [S]
        let mut original = unique_chain(&pool, &[100, 40], 0x30);
        let mut indirect = original.clone_indirect_head(&pool).unwrap();
        assert_eq!(original.lastseg(), indirect.lastseg());
        assert_eq!(unsafe { (*original.lastseg()).refcnt() }, 2);

        let tail = filled(&pool, 50, 0xEE);
        let tail = assert_rejected(&mut original, tail);
        let tail = assert_rejected(&mut indirect, tail);

        drop(tail);
        if original_first {
            drop(original);
            drop(indirect);
        } else {
            drop(indirect);
            drop(original);
        }
        assert_eq!(pool.in_use_count(), 0, "original_first={original_first}");
        assert_returned_exactly_once(&pool, POOL);
    }
}

#[zhida_test_support::pinned_test]
fn unique_indirect_head_appends_and_direct_with_attached_indirect_is_rejected() {
    let pool = PoolManager::new(64);
    for original_first in [true, false] {
        let mut original = filled(&pool, 100, 0x40);
        let mut indirect = original.clone_indirect(&pool).unwrap();
        assert!(indirect.is_head_indirect());
        assert_eq!(indirect.refcount(), 1);

        // The indirect's own link and metadata have one owner: append allowed.
        let tail = filled(&pool, 50, 0x41);
        indirect.chain(tail).ok().expect("unique indirect head appends");
        assert_eq!((indirect.nb_segs(), indirect.pkt_len()), (2, 150));

        // The attached indirect raises the direct segment's refcount, which
        // cannot be told apart from a second chain owner: conservatively rejected.
        assert_eq!(original.refcount(), 2);
        let other = filled(&pool, 20, 0x42);
        let other = assert_rejected(&mut original, other);
        drop(other);

        assert_eq!(pool.in_use_count(), 3);
        if original_first {
            drop(original);
            assert_eq!(indirect.data(), &[0x40; 100][..]);
            drop(indirect);
        } else {
            drop(indirect);
            drop(original);
        }
        assert_eq!(pool.in_use_count(), 0, "original_first={original_first}");
        assert_returned_exactly_once(&pool, POOL);
    }
}

#[zhida_test_support::pinned_test]
fn shared_single_segment_tail_fans_in_and_stays_referenced() {
    let pool = PoolManager::new(64);
    for first_head_first in [true, false] {
        let tail = filled(&pool, 100, 0x50);
        let tail2 = tail.clone();
        let tail_addr = tail.as_ptr() as usize;

        let mut head1 = filled(&pool, 20, 0x51);
        let mut head2 = filled(&pool, 30, 0x52);
        head1.chain(tail).ok().expect("fan-in onto shared single segment");
        head2.chain(tail2).ok().expect("fan-in onto shared single segment");

        assert_eq!((head1.nb_segs(), head1.pkt_len()), (2, 120));
        assert_eq!((head2.nb_segs(), head2.pkt_len()), (2, 130));
        assert_eq!(head1.lastseg(), head2.lastseg());
        let shared = &snapshot(&head1)[1];
        assert_eq!((shared.refcnt, shared.pkt_len, shared.data_len), (2, 100, 100));
        assert_eq!(pool.in_use_count(), 3);

        let (first, survivor) = if first_head_first { (head1, head2) } else { (head2, head1) };
        drop(first);
        assert_eq!(pool.in_use_count(), 2);
        assert_not_reallocated(&pool, tail_addr);
        let segs = snapshot(&survivor);
        assert_eq!(segs[1].addr, tail_addr);
        assert_eq!(segs[1].refcnt, 1);
        assert_eq!(segs[1].payload, vec![0x50; 100]);
        drop(survivor);
        assert_eq!(pool.in_use_count(), 0, "first_head_first={first_head_first}");
        assert_returned_exactly_once(&pool, POOL);
    }
}

#[zhida_test_support::pinned_test]
fn shared_multi_segment_tail_rejected_and_alias_length_kept() {
    let pool = PoolManager::new(64);
    for alias_first in [true, false] {
        let tail = unique_chain(&pool, &[60, 40], 0x60);
        let tail2 = tail.clone();
        let mut head = filled(&pool, 20, 0x61);

        let tail = assert_rejected(&mut head, tail);
        assert_eq!(tail2.pkt_len(), 100);
        assert_eq!(tail2.nb_segs(), 2);

        drop(head);
        if alias_first {
            drop(tail2);
            drop(tail);
        } else {
            drop(tail);
            drop(tail2);
        }
        assert_eq!(pool.in_use_count(), 0, "alias_first={alias_first}");
        assert_returned_exactly_once(&pool, POOL);
    }
}

// into_indirect_head writes the consumed head's next (NULL) and nb_segs (1);
// it reads, never writes, the tail segments, whose references move to the new head.

#[zhida_test_support::pinned_test]
fn aliased_chain_into_indirect_head_rejected_and_both_drop_orders_return_every_segment() {
    let pool = PoolManager::new(64);
    for use_share_all in [false, true] {
        for alias_first in [true, false] {
            let mut head = unique_chain(&pool, &[100, 40], 0x70);
            let alias = if use_share_all { head.share_all() } else { head.clone() };
            let head_ptr = head.as_ptr();
            let before = snapshot(&head);

            let head = match head.into_indirect_head(&pool) {
                Ok(_) => panic!("converted a head whose link another owner walks"),
                Err(head) => head,
            };
            assert_eq!(head.as_ptr(), head_ptr);
            assert_eq!(snapshot(&head), before);
            assert_eq!(snapshot(&alias), before);
            assert_eq!(pool.in_use_count(), 2, "refusal must not allocate");

            if alias_first {
                drop(alias);
                drop(head);
            } else {
                drop(head);
                drop(alias);
            }
            assert_eq!(pool.in_use_count(), 0, "share_all={use_share_all} alias_first={alias_first}");
            assert_returned_exactly_once(&pool, POOL);
        }
    }
}

#[zhida_test_support::pinned_test]
fn direct_chain_with_attached_indirect_into_indirect_head_rejected() {
    let pool = PoolManager::new(64);
    let head = unique_chain(&pool, &[100, 40], 0x71);
    let clone = head.clone_indirect(&pool).unwrap();
    assert_eq!(head.refcount(), 2);
    let before = snapshot(&head);
    let head = head.into_indirect_head(&pool).expect_err("conservatively refused");
    assert_eq!(snapshot(&head), before);
    drop(clone);
    drop(head);
    assert_eq!(pool.in_use_count(), 0);
    assert_returned_exactly_once(&pool, POOL);
}

#[zhida_test_support::pinned_test]
fn unique_chain_into_indirect_head_transfers_every_segment() {
    let pool = PoolManager::new(64);
    let head = unique_chain(&pool, &[100, 40], 0x72);
    let segs = snapshot(&head);

    let converted = head.into_indirect_head(&pool).ok().expect("unique chain converts");
    assert!(converted.is_head_indirect());
    let conv = snapshot(&converted);
    assert_eq!((converted.nb_segs(), converted.pkt_len()), (2, 140));
    assert_eq!(conv[0].payload, segs[0].payload);
    assert_eq!(conv[1].addr, segs[1].addr);
    assert_eq!(conv[1].refcnt, 1);
    let direct = unsafe { &*(segs[0].addr as *const zhida_dpdk_sys::rte_mbuf) };
    assert_eq!((direct.refcnt(), direct.nb_segs(), direct.next()), (1, 1, std::ptr::null_mut()));
    assert_eq!(pool.in_use_count(), 3);
    drop(converted);
    assert_eq!(pool.in_use_count(), 0);
    assert_returned_exactly_once(&pool, POOL);
}

#[zhida_test_support::pinned_test]
fn shared_single_segment_into_indirect_head_converts_without_changing_alias() {
    let pool = PoolManager::new(64);
    for alias_first in [true, false] {
        let mut m = filled(&pool, 100, 0x73);
        let alias = m.share();
        let before = snapshot(&alias);

        let converted = m.into_indirect_head(&pool).ok().expect("single segment has no link to cut");
        assert!(converted.is_head_indirect());
        assert_eq!(converted.data(), &[0x73; 100][..]);
        assert_eq!(snapshot(&alias), before, "alias handle + attached indirect keep refcount 2");
        assert_eq!(pool.in_use_count(), 2);

        if alias_first {
            drop(alias);
            assert_eq!(converted.data(), &[0x73; 100][..]);
            drop(converted);
        } else {
            drop(converted);
            assert_eq!(alias.refcount(), 1);
            drop(alias);
        }
        assert_eq!(pool.in_use_count(), 0, "alias_first={alias_first}");
        assert_returned_exactly_once(&pool, POOL);
    }
}

#[zhida_test_support::pinned_test]
fn indirect_head_into_indirect_head_rejected_and_every_segment_returned() {
    let pool = PoolManager::new(64);
    for shared in [false, true] {
        for lens in [&[100u16][..], &[100, 40]] {
            let direct = unique_chain(&pool, lens, 0x80);
            let mut indirect = direct.clone_indirect(&pool).unwrap();
            let alias = shared.then(|| indirect.share_all());
            let direct_before = snapshot(&direct);
            let indirect_before = snapshot(&indirect);
            let in_use = pool.in_use_count();

            let indirect = indirect.into_indirect_head(&pool).expect_err("indirect head refused");
            assert_eq!(snapshot(&indirect), indirect_before);
            assert_eq!(snapshot(&direct), direct_before);
            assert_eq!(pool.in_use_count(), in_use, "refusal must not allocate");

            drop(alias);
            drop(indirect);
            drop(direct);
            assert_eq!(pool.in_use_count(), 0, "shared={shared} {lens:?}");
            assert_returned_exactly_once(&pool, POOL);
        }
    }
}

/// A shared multi-segment tail whose pkt_len == data_len (trimmed so its last
/// segment is empty) appends: the tail.pkt_len reset is a no-op and skipped,
/// so the other owner's view is unchanged. Pins "a shared tail whose
/// pkt_len != data_len is refused", not "every shared multi-segment tail".
#[zhida_test_support::pinned_test]
fn shared_trimmed_multi_segment_tail_appends_and_alias_unchanged() {
    let pool = PoolManager::new(POOL);
    for alias_first in [true, false] {
        let mut tail = unique_chain(&pool, &[60, 40], 0x90);
        assert!(tail.trim(40));
        let lens: Vec<_> = snapshot(&tail).iter().map(|s| s.data_len).collect();
        assert_eq!((tail.pkt_len(), lens), (60, vec![60, 0]));
        let tail2 = tail.clone();
        let tail2_before = snapshot(&tail2);
        let mut head = filled(&pool, 20, 0x91);

        head.chain(tail).ok().expect("shared tail with pkt_len == data_len appends");
        assert_eq!((head.nb_segs(), head.pkt_len()), (3, 80));
        assert_eq!(snapshot(&tail2), tail2_before, "other owner's segments changed");

        if alias_first {
            drop(tail2);
            drop(head);
        } else {
            drop(head);
            assert_eq!(snapshot(&tail2).iter().map(|s| s.refcnt).max(), Some(1));
            assert_eq!(snapshot(&tail2)[0].payload, vec![0x90; 60]);
            drop(tail2);
        }
        assert_eq!(pool.in_use_count(), 0, "alias_first={alias_first}");
        assert_returned_exactly_once(&pool, POOL);
    }
}

/// Allocation failure in the destination pool returns the same unique chain
/// with links, metadata and refcounts untouched; retry after freeing one
/// destination mbuf converts. Every buffer of both pools returns exactly once.
#[zhida_test_support::pinned_test]
fn into_indirect_head_on_exhausted_destination_returns_chain_unchanged() {
    const DST: u32 = 8;
    let src = PoolManager::new(POOL);
    let dst = PoolManager::new(DST);
    let mut held: Vec<Mbuf> = std::iter::from_fn(|| dst.alloc()).collect();
    assert_eq!(held.len(), DST as usize);

    let head = unique_chain(&src, &[100, 40], 0xA0);
    let head_ptr = head.as_ptr();
    let before = snapshot(&head);
    let head = head.into_indirect_head(&dst).expect_err("destination pool exhausted");
    assert_eq!(head.as_ptr(), head_ptr);
    assert_eq!(snapshot(&head), before);
    assert_eq!((src.in_use_count(), dst.in_use_count()), (2, DST));

    drop(held.pop());
    let converted = head.into_indirect_head(&dst).ok().expect("one destination mbuf free");
    assert!(converted.is_head_indirect());
    assert_eq!((converted.nb_segs(), converted.pkt_len()), (2, 140));
    assert_eq!(converted.data(), &[0xA0; 100][..]);
    assert_eq!(snapshot(&converted)[1], before[1]);
    assert_eq!(dst.in_use_count(), DST);

    drop(converted);
    drop(held);
    assert_eq!((src.in_use_count(), dst.in_use_count()), (0, 0));
    assert_returned_exactly_once(&src, POOL);
    assert_returned_exactly_once(&dst, DST);
}

/// clone_indirect_head of an already-indirect head attaches to the backing
/// direct buffer and counts it there (refcnt 2), not on the input header.
/// The backing buffer stays allocated and keeps its bytes until both drop.
#[zhida_test_support::pinned_test]
fn clone_indirect_head_of_indirect_head_counts_backing_buffer() {
    let pool = PoolManager::new(POOL);
    for i_first in [true, false] {
        let d = filled(&pool, 100, 0xB0);
        let backing = d.as_ptr();
        let i = d.clone_indirect(&pool).unwrap();
        drop(d);
        assert_eq!(unsafe { (*backing).refcnt() }, 1);

        let j = i.clone_indirect_head(&pool).unwrap();
        assert!(j.is_head_indirect());
        assert_eq!(unsafe { (*backing).refcnt() }, 2);
        assert_eq!((i.refcount(), j.refcount()), (1, 1));
        assert_eq!(pool.in_use_count(), 3);

        let (first, survivor) = if i_first { (i, j) } else { (j, i) };
        drop(first);
        assert_eq!(unsafe { (*backing).refcnt() }, 1);
        assert_not_reallocated(&pool, backing as usize);
        assert_eq!(survivor.data(), &[0xB0; 100][..]);
        drop(survivor);
        assert_eq!(pool.in_use_count(), 0, "i_first={i_first}");
        assert_returned_exactly_once(&pool, POOL);
    }
}

/// into_indirect_head on a unique head whose tail segment is shared by fan-in
/// (tail refcnt 2) moves the head's tail reference without changing it; the
/// tail survives either owner's drop and returns once.
#[zhida_test_support::pinned_test]
fn into_indirect_head_with_fan_in_tail_keeps_tail_referenced() {
    let pool = PoolManager::new(POOL);
    for converted_first in [true, false] {
        let tail = filled(&pool, 40, 0xC0);
        let tail2 = tail.clone();
        let tail_addr = tail.as_ptr() as usize;
        let mut head1 = filled(&pool, 100, 0xC1);
        let mut head2 = filled(&pool, 30, 0xC2);
        head1.chain(tail).ok().expect("fan-in");
        head2.chain(tail2).ok().expect("fan-in");
        let head2_before = snapshot(&head2);

        let converted = head1.into_indirect_head(&pool).ok().expect("unique head converts");
        let conv = snapshot(&converted);
        assert_eq!((converted.nb_segs(), converted.pkt_len()), (2, 140));
        assert_eq!((conv[1].addr, conv[1].refcnt), (tail_addr, 2));
        assert_eq!(snapshot(&head2), head2_before);
        assert_eq!(pool.in_use_count(), 4);

        let (first, survivor) =
            if converted_first { (converted, head2) } else { (head2, converted) };
        drop(first);
        assert_not_reallocated(&pool, tail_addr);
        let segs = snapshot(&survivor);
        assert_eq!((segs[1].addr, segs[1].refcnt), (tail_addr, 1));
        assert_eq!(segs[1].payload, vec![0xC0; 40]);
        drop(survivor);
        assert_eq!(pool.in_use_count(), 0, "converted_first={converted_first}");
        assert_returned_exactly_once(&pool, POOL);
    }
}

/// A direct multi-segment tail shared only through an attachment (a live
/// clone_indirect) has refcnt 2 and pkt_len != data_len: refused, nothing written.
#[zhida_test_support::pinned_test]
fn tail_shared_only_by_attachment_is_refused() {
    let pool = PoolManager::new(POOL);
    for clone_first in [true, false] {
        let tail = unique_chain(&pool, &[60, 40], 0xD0);
        let clone = tail.clone_indirect(&pool).unwrap();
        assert_eq!(tail.refcount(), 2);
        let clone_before = snapshot(&clone);
        let mut head = filled(&pool, 20, 0xD1);

        let tail = assert_rejected(&mut head, tail);
        assert_eq!(snapshot(&clone), clone_before);

        drop(head);
        if clone_first {
            drop(clone);
            drop(tail);
        } else {
            drop(tail);
            drop(clone);
        }
        assert_eq!(pool.in_use_count(), 0, "clone_first={clone_first}");
        assert_returned_exactly_once(&pool, POOL);
    }
}

// ============================================================================
// Header-segment prepend
// ============================================================================

fn data_addr(seg: *mut rte_mbuf) -> usize {
    unsafe { (*seg).data_ptr() as usize }
}

/// A payload buffer's header fields and bytes (headroom included), read through
/// its direct mbuf. refcnt is excluded: holders come and go.
#[derive(Debug, PartialEq)]
struct PayloadView {
    data_off: u16,
    data_len: u16,
    pkt_len: u32,
    nb_segs: u16,
    next: usize,
    bytes: Vec<u8>,
}

fn payload_view(p: *mut rte_mbuf) -> PayloadView {
    let m = unsafe { &*p };
    let end = m.data_off() as usize + m.data_len() as usize;
    PayloadView {
        data_off: m.data_off(),
        data_len: m.data_len(),
        pkt_len: m.pkt_len(),
        nb_segs: m.nb_segs(),
        next: m.next() as usize,
        bytes: unsafe { std::slice::from_raw_parts(m.buf_addr as *const u8, end) }.to_vec(),
    }
}

#[derive(Clone, Copy, Debug)]
enum FanOut {
    Share,
    CloneIndirect,
}

#[derive(Clone, Copy, Debug)]
enum DropOrder {
    PayloadFirst,
    PacketsFirst,
    Interleaved,
}

impl DropOrder {
    /// Holder indices in drop order: 0 is the payload, 1..=n the packets.
    fn indices(self, n: usize) -> Vec<usize> {
        let packets = 1..=n;
        match self {
            Self::PayloadFirst => std::iter::once(0).chain(packets).collect(),
            Self::PacketsFirst => packets.chain(std::iter::once(0)).collect(),
            Self::Interleaved => packets
                .clone()
                .step_by(2)
                .chain(std::iter::once(0))
                .chain(packets.skip(1).step_by(2))
                .collect(),
        }
    }
}

/// Every live packet still carries its own header bytes over the one payload
/// buffer, whose header, headroom and bytes are unchanged; no live segment
/// (nor the payload buffer) has been handed out again.
fn assert_fan_out_intact(
    pool: &PoolManager,
    holders: &[Option<Mbuf>],
    payload: *mut rte_mbuf,
    view: &PayloadView,
    hdr: u16,
) {
    assert_eq!(&payload_view(payload), view, "payload buffer changed");
    let payload_bytes = &view.bytes[view.data_off as usize..];
    let payload_data = data_addr(payload);
    let mut live = vec![payload as usize];
    for (idx, m) in holders.iter().enumerate() {
        let Some(m) = m else { continue };
        let segs = snapshot(m);
        live.extend(segs.iter().map(|s| s.addr));
        if idx == 0 {
            assert_eq!(m.data(), payload_bytes);
            continue;
        }
        assert_eq!((m.nb_segs(), m.pkt_len()), (2, u32::from(hdr + view.data_len)));
        assert_eq!(segs[0].payload, vec![idx as u8; hdr as usize]);
        assert_eq!(data_addr(m.iter_segs().nth(1).unwrap()), payload_data);
        assert_eq!(segs[1].payload, payload_bytes);
    }
    live.sort_unstable();
    live.dedup();
    for addr in live {
        assert_not_reallocated(pool, addr);
    }
}

/// One payload fanned out to N packets (share or clone_indirect), each given its
/// own header by `prepend`: distinct header segments with per-packet bytes over
/// the same payload bytes, which no packet changes. Every drop order keeps live
/// segments allocated and returns every segment exactly once.
#[zhida_test_support::pinned_test]
fn fan_out_payload_to_n_header_segments_shares_payload_and_returns_every_segment_once() {
    const HDR: u16 = 40;
    let pool = PoolManager::new(POOL);
    for how in [FanOut::Share, FanOut::CloneIndirect] {
        for n in [1usize, 4, 16] {
            for order in [DropOrder::PayloadFirst, DropOrder::PacketsFirst, DropOrder::Interleaved] {
                let mut payload = filled(&pool, 100, 0xEE);
                let payload_ptr = payload.as_ptr();
                let view = payload_view(payload_ptr);

                let mut packets: Vec<Mbuf> = (0..n)
                    .map(|_| match how {
                        FanOut::Share => payload.share(),
                        FanOut::CloneIndirect => payload.clone_indirect(&pool).unwrap(),
                    })
                    .collect();
                for (i, p) in packets.iter_mut().enumerate() {
                    p.prepend(HDR).expect("header segment").fill(i as u8 + 1);
                }
                assert_eq!(usize::from(payload.refcount()), 1 + n);
                let per_packet = match how {
                    FanOut::Share => 1,
                    FanOut::CloneIndirect => 2,
                };
                assert_eq!(pool.in_use_count() as usize, 1 + per_packet * n);
                let mut headers: Vec<usize> = packets.iter().map(|p| p.as_ptr() as usize).collect();
                headers.sort_unstable();
                headers.dedup();
                assert_eq!(headers.len(), n, "header segments must be distinct");

                let mut holders: Vec<Option<Mbuf>> =
                    std::iter::once(payload).chain(packets).map(Some).collect();
                assert_fan_out_intact(&pool, &holders, payload_ptr, &view, HDR);
                for idx in order.indices(n) {
                    holders[idx] = None;
                    if holders.iter().any(Option::is_some) {
                        assert_fan_out_intact(&pool, &holders, payload_ptr, &view, HDR);
                    }
                }
                assert_eq!(pool.in_use_count(), 0, "{how:?} n={n} {order:?}");
                assert_returned_exactly_once(&pool, POOL);
            }
        }
    }
}

/// An indirect head's header segment comes from the indirect header's own pool
/// (the one passed to clone_indirect), not the backing buffer's: the header pool
/// runs out while the backing pool has room. Both pools return every buffer once.
#[zhida_test_support::pinned_test]
fn header_segment_comes_from_indirect_heads_own_pool() {
    const HDR_POOL: u32 = 4;
    let backing = PoolManager::new(POOL);
    let headers = PoolManager::new(HDR_POOL);
    let payload = filled(&backing, 100, 0xA5);
    let payload_data = payload.data().as_ptr() as usize;

    let mut first = payload.clone_indirect(&headers).unwrap();
    first.prepend(20).expect("header segment").fill(0x01);
    assert_eq!(first.pool(), headers.pool());
    assert_eq!((backing.in_use_count(), headers.in_use_count()), (1, 2));

    let mut second = payload.clone_indirect(&headers).unwrap();
    let held = headers.alloc().unwrap();
    assert!(headers.alloc().is_none());
    let before = snapshot(&second);
    assert!(second.prepend(20).is_none(), "header pool exhausted");
    assert_eq!(snapshot(&second), before);
    assert_eq!((backing.in_use_count(), headers.in_use_count()), (1, HDR_POOL));

    drop(held);
    second.prepend(20).expect("one header mbuf free").fill(0x02);
    assert_eq!(second.pool(), headers.pool());
    assert_eq!(backing.in_use_count(), 1);
    for packet in [&first, &second] {
        assert_eq!(data_addr(packet.iter_segs().nth(1).unwrap()), payload_data);
    }

    drop(payload);
    drop(first);
    drop(second);
    assert_eq!((backing.in_use_count(), headers.in_use_count()), (0, 0));
    assert_returned_exactly_once(&backing, POOL);
    assert_returned_exactly_once(&headers, HDR_POOL);
}

/// The chain a header-segment prepend returns works with the other safe
/// operations: chain refuses while the old head is shared and accepts on a packet
/// whose old head was never shared (the same-packet shared-then-exclusive case is
/// the next test), a second prepend goes in place on the header segment, and
/// clones and conversions of the result return every segment once.
#[zhida_test_support::pinned_test]
fn header_segment_packet_safe_ops() {
    let pool = PoolManager::new(POOL);

    let mut packet = filled(&pool, 100, 0xB0);
    let alias = packet.share();
    packet.prepend(20).expect("header segment").fill(0xB1);
    let alias_before = snapshot(&alias);
    // Last segment is the old head, shared with `alias`.
    let tail = assert_rejected(&mut packet, filled(&pool, 30, 0xB2));
    assert_eq!(snapshot(&alias), alias_before);
    drop(tail);

    let header = packet.as_ptr();
    let headroom = packet.headroom();
    packet.prepend(10).expect("in place on the header segment").fill(0xB3);
    assert_eq!((packet.as_ptr(), packet.headroom()), (header, headroom - 10));
    assert_eq!((packet.len(), packet.pkt_len(), packet.nb_segs()), (30, 130, 2));
    assert_eq!(snapshot(&alias), alias_before);

    let clone = packet.clone_indirect(&pool).unwrap();
    assert_eq!((clone.nb_segs(), clone.pkt_len()), (2, 130));
    assert_eq!(clone.data(), packet.data());
    drop(clone);
    assert_segments_not_reallocated(&pool, &packet);
    assert_segments_not_reallocated(&pool, &alias);
    let head_clone = packet.clone_indirect_head(&pool).unwrap();
    assert_eq!((head_clone.nb_segs(), head_clone.pkt_len()), (2, 130));
    drop(head_clone);
    assert_segments_not_reallocated(&pool, &packet);
    assert_segments_not_reallocated(&pool, &alias);
    let converted = packet.into_indirect_head(&pool).ok().expect("header segment is unique and direct");
    assert_eq!((converted.nb_segs(), converted.pkt_len()), (2, 130));
    assert_eq!(snapshot(&alias), alias_before);
    drop(converted);
    assert_eq!(alias.refcount(), 1);
    assert_segments_not_reallocated(&pool, &alias);
    assert!(alias.data().iter().all(|&b| b == 0xB0));
    drop(alias);
    assert_eq!(pool.in_use_count(), 0);
    assert_returned_exactly_once(&pool, POOL);

    // Exclusive old head without room for the header.
    let mut packet = filled(&pool, 100, 0xC0);
    packet.prepend(150).expect("header segment").fill(0xC1);
    packet.chain(filled(&pool, 30, 0xC2)).ok().expect("old head is exclusive");
    assert_eq!((packet.nb_segs(), packet.pkt_len()), (3, 280));
    drop(packet);
    assert_eq!(pool.in_use_count(), 0);
    assert_returned_exactly_once(&pool, POOL);
}

/// Every segment `m` reaches is still allocated: a drop of another owner did
/// not return it to the pool early.
fn assert_segments_not_reallocated(pool: &PoolManager, m: &Mbuf) {
    for seg in snapshot(m) {
        assert_not_reallocated(pool, seg.addr);
    }
}

/// Same packet across the alias's lifetime: after a header-segment prepend over
/// a shared old head, chain refuses (the old head, now the last segment, is
/// reachable by the alias) and accepts once the alias drops. Dropping the alias
/// must leave the old head allocated. Catches a chain check that looks at the
/// new header segment instead of lastseg, and a drop that frees the old head.
#[zhida_test_support::pinned_test]
fn header_segment_chain_refused_while_old_head_shared_then_accepted() {
    let pool = PoolManager::new(POOL);
    let mut packet = filled(&pool, 100, 0xD0);
    let alias = packet.share();
    packet.prepend(20).expect("header segment").fill(0xD1);
    let alias_before = snapshot(&alias);

    let tail = assert_rejected(&mut packet, filled(&pool, 30, 0xD2));
    assert_eq!(snapshot(&alias), alias_before);

    drop(alias);
    assert_segments_not_reallocated(&pool, &packet);
    packet.chain(tail).ok().expect("old head is exclusive after the alias drops");
    let segs = snapshot(&packet);
    assert_eq!((packet.nb_segs(), packet.pkt_len()), (3, 150));
    assert_eq!(segs.iter().map(|s| s.data_len).collect::<Vec<_>>(), [20, 100, 30]);
    assert!(segs.iter().all(|s| s.refcnt == 1));
    drop(packet);
    assert_returned_exactly_once(&pool, POOL);
}

#[derive(Clone, Copy, Debug)]
enum Alias {
    Clone,
    ShareAll,
}

/// A header-segment prepend on a shared 2-segment chain leaves the safe edits
/// on the result working only where they touch segments this packet owns alone:
/// adj edits the new header segment, trim (last segment shared) panics with
/// nothing written, and succeeds once the alias drops. The alias sees no change
/// at any step. Catches adj/trim reaching through to shared segments, a trim
/// that writes before its check, and an early free in either drop order.
#[zhida_test_support::pinned_test]
fn shared_chain_header_segment_adj_trim() {
    let pool = PoolManager::new(POOL);
    for how in [Alias::Clone, Alias::ShareAll] {
        for alias_first in [true, false] {
            let mut packet = unique_chain(&pool, &[60, 40], 0xE0);
            let alias = match how {
                Alias::Clone => packet.clone(),
                Alias::ShareAll => packet.share_all(),
            };
            let old_head = packet.as_ptr();
            let old_last = packet.lastseg();
            let alias_before = snapshot(&alias);

            packet.prepend(20).expect("header segment").fill(0xE9);
            assert_ne!(packet.as_ptr(), old_head);
            assert_eq!(packet.next(), Some(old_head));
            assert_eq!((packet.nb_segs(), packet.pkt_len()), (3, 120));
            assert_eq!(snapshot(&alias), alias_before);

            let before = snapshot(&packet);
            assert!(!packet.adj(21), "adj beyond the header segment");
            assert_eq!(snapshot(&packet), before);
            assert_eq!(snapshot(&alias), alias_before);

            assert!(packet.adj(20));
            assert_eq!((packet.len(), packet.pkt_len(), packet.nb_segs()), (0, 100, 3));
            assert_eq!(packet.next(), Some(old_head));
            assert_eq!(snapshot(&alias), alias_before);

            let before = snapshot(&packet);
            let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                packet.trim(10);
            }));
            assert!(attempt.is_err(), "trim with a shared last segment must panic");
            assert_eq!(snapshot(&packet), before);
            assert_eq!(snapshot(&alias), alias_before);

            if alias_first {
                drop(alias);
                assert_segments_not_reallocated(&pool, &packet);
                assert!(packet.trim(10));
                assert_eq!(unsafe { (*old_last).data_len() }, 30);
                assert_eq!((packet.pkt_len(), packet.nb_segs()), (90, 3));
                drop(packet);
            } else {
                drop(packet);
                let mut expected = alias_before;
                for seg in &mut expected {
                    seg.refcnt = 1;
                }
                assert_eq!(snapshot(&alias), expected);
                assert_segments_not_reallocated(&pool, &alias);
                drop(alias);
            }
            assert_eq!(pool.in_use_count(), 0, "{how:?} alias_first={alias_first}");
            assert_returned_exactly_once(&pool, POOL);
        }
    }
}
