use alloc::collections::VecDeque;
use core::ops::Range;

use crate::phy::RxBuf;

pub(super) const IN_ORDER_RESERVE: usize = 1;

/// The largest in-order segment copied into the last held frame's tailroom instead of held as its
/// own frame. Larger segments keep their own frame.
pub(super) const APPEND_MAX: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Decision {
    New(NewView),
    Append(Range<usize>),
    Duplicate(Range<usize>),
    Refused,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct NewView {
    kept: Range<usize>,
    len: usize,
    index: usize,
    left: Option<Range<usize>>,
    released: usize,
    released_span: Option<Range<usize>>,
    trimmed: Option<Range<usize>>,
    cap: usize,
}

impl Decision {
    pub(super) fn kept(&self) -> Option<Range<usize>> {
        match self {
            Self::New(view) => Some(view.kept.clone()),
            Self::Append(range) => Some(range.clone()),
            Self::Duplicate(_) | Self::Refused => None,
        }
    }
}

#[derive(Debug)]
struct View {
    start: usize,
    len: usize,
    frame: Option<RxBuf>,
}

impl View {
    fn range(&self) -> Range<usize> {
        self.start..self.end()
    }

    fn end(&self) -> usize {
        self.start
            .checked_add(self.len)
            .expect("view end exceeds usize")
    }
}

#[derive(Debug)]
pub(super) struct RxStore {
    views: VecDeque<View>,
    head: usize,
    in_order: u32,
    pending: bool,
}

impl RxStore {
    pub(super) fn new() -> Self {
        Self {
            views: VecDeque::new(),
            head: 0,
            in_order: 0,
            pending: false,
        }
    }

    fn absolute(&self, offset: usize) -> usize {
        self.head.checked_add(offset).expect("receive offset exceeds usize")
    }

    fn relative(&self, offset: usize) -> usize {
        offset.checked_sub(self.head).expect("view precedes read head")
    }

    fn absolute_range(&self, range: Range<usize>) -> Range<usize> {
        self.absolute(range.start)..self.absolute(range.end)
    }

    fn relative_range(&self, range: Range<usize>) -> Range<usize> {
        self.relative(range.start)..self.relative(range.end)
    }

    pub(super) fn decide(&self, offset: usize, len: usize, cap: usize) -> Decision {
        assert!(len > 0);
        let offset = self.absolute(offset);
        let end = offset.checked_add(len).expect("segment end exceeds usize");
        // A segment at or past the end of the last view (the next in-order segment in the
        // common case) overlaps nothing, so it needs no search.
        let after_last = self.views.back().is_none_or(|view| view.end() <= offset);
        if after_last
            && offset == self.absolute(self.in_order_len())
            && len <= APPEND_MAX
            && self
                .views
                .back()
                .is_some_and(|view| view.frame.as_ref().is_some_and(|frame| len <= frame.room()))
        {
            return Decision::Append(self.relative_range(offset..end));
        }
        if !after_last && self.is_held(offset..end) {
            return Decision::Duplicate(self.relative_range(offset..end));
        }

        let (start, index) = if after_last {
            (offset, self.held())
        } else {
            let before_offset = self.views.partition_point(|view| view.start < offset);
            let start = before_offset
                .checked_sub(1)
                .map(|index| &self.views[index])
                .map_or(offset, |view| offset.max(view.end()));
            (start, self.views.partition_point(|view| view.start < start))
        };
        let left = index
            .checked_sub(1)
            .and_then(|index| self.views.get(index))
            .map(View::range);
        let mut released = 0usize;
        let mut released_span: Option<Range<usize>> = None;
        let mut trimmed = None;
        for view in self.views.iter().skip(index) {
            if view.start >= end {
                break;
            }
            if view.start >= start {
                if view.end() <= end {
                    released = released.checked_add(1).expect("view count exceeds usize");
                    if let Some(span) = &mut released_span {
                        span.end = view.end();
                    } else {
                        released_span = Some(view.range());
                    }
                } else {
                    trimmed = Some(view.range());
                    break;
                }
            }
        }

        let after = self
            .held()
            .checked_sub(released)
            .expect("released views exceed held views")
            .checked_add(1)
            .expect("view count exceeds usize");
        let limit = if start <= self.absolute(self.in_order_len()) {
            Some(cap)
        } else {
            cap.checked_sub(IN_ORDER_RESERVE)
        };
        if limit.is_none_or(|limit| after > limit) {
            Decision::Refused
        } else {
            Decision::New(NewView {
                kept: self.relative_range(start..end),
                len,
                index,
                left: left.map(|range| self.relative_range(range)),
                released,
                released_span: released_span.map(|range| self.relative_range(range)),
                trimmed: trimmed.map(|range| self.relative_range(range)),
                cap,
            })
        }
    }

    fn is_held(&self, range: Range<usize>) -> bool {
        let mut covered = range.start;
        let index = self
            .views
            .partition_point(|view| view.start <= range.start)
            .checked_sub(1)
            .unwrap_or(0);
        for view in self.views.iter().skip(index) {
            if view.start > covered {
                break;
            }
            covered = covered.max(view.end());
            if covered >= range.end {
                return true;
            }
        }
        false
    }

    /// The store must be unchanged since decide returned.
    pub(super) fn append(&mut self, offset: usize, decision: Decision, payload: &[u8]) {
        self.assert_attached();
        let range = match decision {
            Decision::Append(range) => range,
            _ => panic!("stale append decision: variant"),
        };
        assert!(range.start == offset, "stale append decision: offset");
        assert!(
            range.len() == payload.len(),
            "stale append decision: payload length"
        );
        assert!(!payload.is_empty(), "stale append decision: empty payload");
        assert!(
            offset == self.in_order_len(),
            "stale append decision: in-order bytes"
        );
        assert!(
            self.views.back().is_some(),
            "stale append decision: last view"
        );
        let view = self.views.back_mut().unwrap();
        assert!(view.end() == self.head.checked_add(offset).expect("receive offset exceeds usize"), "stale append decision: last view end");
        let frame = view.frame.as_mut().unwrap();
        assert!(
            frame.room() >= payload.len(),
            "stale append decision: frame room"
        );
        let len = view
            .len
            .checked_add(payload.len())
            .expect("view length exceeds usize");
        let in_order = self
            .in_order
            .checked_add(u32::try_from(payload.len()).expect("payload length exceeds u32"))
            .expect("in-order byte count exceeds u32");
        frame.extend_from_slice(payload);
        view.len = len;
        self.in_order = in_order;
    }

    /// The store must be unchanged since decide returned.
    pub(super) fn place(&mut self, offset: usize, decision: Decision) {
        self.assert_attached();
        let offset = self.absolute(offset);
        let mut new = match decision {
            Decision::New(new) => new,
            Decision::Append(_) => panic!("append decision passed to place"),
            Decision::Duplicate(range) => {
                let range = self.absolute_range(range);
                assert!(
                    range.start == offset && range.start < range.end && self.is_held(range),
                    "stale duplicate decision"
                );
                return;
            }
            Decision::Refused => return,
        };
        new.kept = self.absolute_range(new.kept);
        new.left = new.left.map(|range| self.absolute_range(range));
        new.released_span = new.released_span.map(|range| self.absolute_range(range));
        new.trimmed = new.trimmed.map(|range| self.absolute_range(range));
        assert!(
            new.kept.end
                == offset
                    .checked_add(new.len)
                    .expect("segment end exceeds usize")
                && offset <= new.kept.start
                && new.kept.start < new.kept.end,
            "stale new decision"
        );
        let index = new.index;
        if index == self.held() && new.released == 0 && new.trimmed.is_none() {
            assert!(
                self.views.back().map(View::range) == new.left,
                "stale new decision: left neighbor"
            );
            let after = self
                .held()
                .checked_add(1)
                .expect("view count exceeds usize");
            let limit = if new.kept.start <= self.absolute(self.in_order_len()) {
                Some(new.cap)
            } else {
                new.cap.checked_sub(IN_ORDER_RESERVE)
            };
            assert!(
                limit.is_some_and(|limit| after <= limit),
                "stale new decision: view cap"
            );
            self.views.push_back(View {
                start: new.kept.start,
                len: new
                    .kept
                    .end
                    .checked_sub(new.kept.start)
                    .expect("empty kept range"),
                frame: None,
            });
            if new.kept.start == self.absolute(self.in_order_len()) {
                self.in_order =
                    u32::try_from(self.relative(new.kept.end)).expect("in-order byte count exceeds u32");
            }
            self.pending = true;
            return;
        }
        assert!(index <= self.held(), "stale new decision: insertion index");
        let left = index
            .checked_sub(1)
            .and_then(|index| self.views.get(index))
            .map(View::range);
        assert!(left == new.left, "stale new decision: left neighbor");
        assert!(
            self.views
                .get(index)
                .is_none_or(|view| view.start >= new.kept.start),
            "stale new decision: insertion index"
        );
        let released_end = index
            .checked_add(new.released)
            .expect("view index exceeds usize");
        assert!(
            released_end <= self.held(),
            "stale new decision: released views"
        );
        let released_span = if new.released == 0 {
            None
        } else {
            let last = released_end.checked_sub(1).expect("no released views");
            Some(self.views[index].start..self.views[last].end())
        };
        assert!(
            released_span == new.released_span,
            "stale new decision: released views"
        );
        if let Some(trimmed) = &new.trimmed {
            assert!(
                self.views.get(released_end).map(View::range) == Some(trimmed.clone()),
                "stale new decision: trimmed view"
            );
        } else {
            assert!(
                self.views
                    .get(released_end)
                    .is_none_or(|view| view.start >= new.kept.end),
                "stale new decision: right neighbor"
            );
        }
        let after = self
            .held()
            .checked_sub(new.released)
            .expect("released views exceed held views")
            .checked_add(1)
            .expect("view count exceeds usize");
        let limit = if new.kept.start <= self.absolute(self.in_order_len()) {
            Some(new.cap)
        } else {
            new.cap.checked_sub(IN_ORDER_RESERVE)
        };
        assert!(
            limit.is_some_and(|limit| after <= limit),
            "stale new decision: view cap"
        );
        if new.released != 0 {
            drop(self.views.drain(index..released_end));
        }
        if new.trimmed.is_some() {
            let view = &mut self.views[index];
            let head = new
                .kept
                .end
                .checked_sub(view.start)
                .expect("trim ends before view start");
            view.frame.as_mut().unwrap().narrow(head..view.len);
            view.len = view.len.checked_sub(head).expect("trim exceeds view");
            view.start = new.kept.end;
        }
        self.views.insert(
            index,
            View {
                start: new.kept.start,
                len: new
                    .kept
                    .end
                    .checked_sub(new.kept.start)
                    .expect("empty kept range"),
                frame: None,
            },
        );
        if new.kept.start <= self.absolute(self.in_order_len()) {
            let mut end = new.kept.end;
            let mut next = index.checked_add(1).expect("view index exceeds usize");
            while let Some(view) = self.views.get(next).filter(|view| view.start == end) {
                end = view.end();
                next = next.checked_add(1).expect("view index exceeds usize");
            }
            self.in_order = u32::try_from(self.relative(end)).expect("in-order byte count exceeds u32");
        }
        self.pending = true;
    }

    pub(super) fn attach(&mut self, frame: RxBuf) {
        let view = self
            .views
            .iter_mut()
            .rev()
            .find(|view| view.frame.is_none())
            .expect("no pending receive view");
        assert!(self.pending, "no pending receive view");
        assert_eq!(
            frame.len(),
            view.len,
            "frame length differs from pending view"
        );
        view.frame = Some(frame);
        self.pending = false;
    }

    fn assert_attached(&self) {
        assert!(!self.pending, "pending receive view");
    }

    #[cfg(test)]
    pub(super) fn has_pending(&self) -> bool {
        self.pending
    }

    pub(super) fn in_order_len(&self) -> usize {
        self.in_order as usize
    }

    #[cfg(test)]
    pub(super) fn out_of_order_len(&self) -> usize {
        let end = self.absolute(self.in_order_len());
        if self.views.back().is_none_or(|view| view.start < end) {
            return 0;
        }
        self.views
            .iter()
            .rev()
            .take_while(|view| view.start >= end)
            .try_fold(0usize, |total, view| total.checked_add(view.len))
            .expect("held byte count exceeds usize")
    }

    pub(super) fn out_of_order_span(&self) -> usize {
        self.views.back().map_or(0, |view| {
            view.end()
                .checked_sub(self.absolute(self.in_order_len()))
                .expect("last view ends before in-order data")
        })
    }

    pub(super) fn held(&self) -> usize {
        self.views.len()
    }

    /// Frames needed to fill the gaps before and between out-of-order views, each gap
    /// charged `ceil(gap bytes / seg_bytes)`. Zero without out-of-order data.
    pub(super) fn out_of_order_hole_frames(&self, seg_bytes: usize) -> usize {
        if self.out_of_order_span() == 0 {
            return 0;
        }
        let in_order_end = self.absolute(self.in_order_len());
        let first = self.views.partition_point(|view| view.start < in_order_end);
        let mut end = in_order_end;
        let mut frames = 0usize;
        for view in self.views.range(first..) {
            if view.start > end {
                frames = frames
                    .checked_add((view.start - end).div_ceil(seg_bytes))
                    .expect("hole frame count exceeds usize");
            }
            end = view.end();
        }
        frames
    }

    pub(super) fn ranges(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        self.views.iter().map(|view| (self.relative(view.start), self.relative(view.end())))
    }

    pub(super) fn out_of_order_ranges(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        let in_order_end = self.absolute(self.in_order_len());
        let first = if self.out_of_order_span() == 0 {
            self.views.len()
        } else {
            self.views.partition_point(|view| view.start < in_order_end)
        };
        let mut views = self.views.range(first..).peekable();
        core::iter::from_fn(move || {
            let view = views.next()?;
            let start = view.start;
            let mut end = view.end();
            while let Some(next) = views.peek()
                && next.start == end
            {
                end = views.next().unwrap().end();
            }
            Some((
                start.checked_sub(in_order_end).expect("range starts before in-order end"),
                end.checked_sub(in_order_end).expect("range ends before in-order end"),
            ))
        })
    }

    #[inline]
    pub(super) fn pop_front(&mut self) -> Option<RxBuf> {
        let view = self.views.front()?;
        if view.start != self.head || view.frame.is_none() {
            return None;
        }
        let view = self.views.pop_front().unwrap();
        self.head = self.head.checked_add(view.len).expect("receive head exceeds usize");
        self.in_order = self.in_order
            .checked_sub(u32::try_from(view.len).expect("frame length exceeds u32"))
            .expect("frame exceeds in-order bytes");
        if self.views.is_empty() {
            self.head = 0;
        }
        view.frame
    }

    pub(super) fn clear(&mut self) {
        self.views.clear();
        self.head = 0;
        self.in_order = 0;
        self.pending = false;
    }

    pub(super) fn truncate_from(&mut self, offset: usize) {
        let offset = self.absolute(offset);
        assert!(
            self.views
                .iter()
                .all(|view| view.frame.is_some() || view.end() <= offset),
            "truncate cuts pending receive view"
        );
        while self.views.back().is_some_and(|view| view.start >= offset) {
            self.views.pop_back();
        }
        if let Some(view) = self.views.back_mut() {
            if view.end() > offset {
                let len = offset
                    .checked_sub(view.start)
                    .expect("truncate precedes view");
                view.frame.as_mut().unwrap().narrow(0..len);
                view.len = len;
            }
        }
        self.in_order = u32::try_from(self.in_order_len().min(self.relative(offset)))
            .expect("in-order byte count exceeds u32");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{rc::Rc, vec, vec::Vec};
    use core::cell::Cell;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    fn drain_bytes(store: &mut RxStore) -> Vec<u8> {
        let mut bytes = Vec::new();
        while let Some(frame) = store.pop_front() {
            bytes.extend_from_slice(frame.as_slice());
        }
        bytes
    }

    fn counted_frame(bytes: &[u8]) -> (RxBuf, Rc<Cell<usize>>) {
        let releases = Rc::new(Cell::new(0));
        (
            RxBuf::counted_frame(bytes.to_vec(), 0, releases.clone()),
            releases,
        )
    }

    fn place_attach(store: &mut RxStore, offset: usize, mut frame: RxBuf, decision: Decision) {
        let kept = decision.kept();
        store.place(offset, decision);
        if let Some(kept) = kept {
            frame.narrow(
                kept.start.checked_sub(offset).unwrap()..kept.end.checked_sub(offset).unwrap(),
            );
            store.attach(frame);
        }
    }

    fn counted_frame_with_room(bytes: &[u8], room: usize) -> (RxBuf, Rc<Cell<usize>>) {
        let releases = Rc::new(Cell::new(0));
        (
            RxBuf::counted_frame(bytes.to_vec(), room, releases.clone()),
            releases,
        )
    }

    fn insert_with_room(
        store: &mut RxStore,
        offset: usize,
        bytes: &[u8],
        room: usize,
        cap: usize,
    ) -> Rc<Cell<usize>> {
        let (frame, releases) = counted_frame_with_room(bytes, room);
        let decision = store.decide(offset, bytes.len(), cap);
        assert!(matches!(decision, Decision::New(_)));
        place_attach(store, offset, frame, decision);
        assert_eq!(releases.get(), 0);
        releases
    }

    #[test]
    fn pop_front_requires_an_attached_in_order_frame() {
        let mut store = RxStore::new();
        assert!(store.pop_front().is_none());
        insert(&mut store, 4, b"ef", 6);
        assert!(store.pop_front().is_none());
        let decision = store.decide(0, 4, 6);
        store.place(0, decision);
        assert!(store.pop_front().is_none());
        store.attach(RxBuf::from_vec(b"abcd".to_vec()));
        assert_eq!(store.pop_front().unwrap().as_slice(), b"abcd");
        assert_eq!(store.pop_front().unwrap().as_slice(), b"ef");
        assert!(store.pop_front().is_none());
    }

    #[test]
    fn draining_frames_keeps_out_of_order_ranges() {
        let mut store = RxStore::new();
        for (offset, bytes) in [(0, &b"ab"[..]), (2, b"cde"), (9, b"jk"), (15, b"pq")] {
            insert(&mut store, offset, bytes, 6);
        }
        assert_eq!(store.pop_front().unwrap().as_slice(), b"ab");
        assert_eq!(store.head, 2);
        assert_eq!(ranges(&store), vec![(0, 3), (7, 9), (13, 15)]);
        assert_eq!(store.pop_front().unwrap().as_slice(), b"cde");
        assert_eq!(store.head, 5);
        assert_eq!(ranges(&store), vec![(4, 6), (10, 12)]);
        assert_eq!(store.out_of_order_span(), 12);
        assert_eq!(store.out_of_order_hole_frames(64), 2);
        assert!(store.pop_front().is_none());
        insert(&mut store, 0, b"fghi", 6);
        assert_eq!(store.in_order_len(), 6);
        assert_eq!(drain_bytes(&mut store), b"fghijk");
        assert_eq!(ranges(&store), vec![(4, 6)]);
    }

    #[test]
    fn pop_front_after_truncate_and_clear() {
        let mut store = RxStore::new();
        insert(&mut store, 0, b"ab", 6);
        insert(&mut store, 2, b"cdef", 6);
        insert(&mut store, 9, b"jk", 6);
        assert_eq!(store.pop_front().unwrap().as_slice(), b"ab");
        store.truncate_from(2);
        assert_eq!(ranges(&store), vec![(0, 2)]);
        assert_eq!(store.pop_front().unwrap().as_slice(), b"cd");
        assert_eq!(store.head, 0);
        assert!(store.pop_front().is_none());
        insert(&mut store, 0, b"ef", 6);
        insert(&mut store, 5, b"jk", 6);
        drop(store.pop_front().unwrap());
        assert_eq!(store.head, 2);
        store.clear();
        assert_eq!(store.head, 0);
        assert!(store.pop_front().is_none());
        insert(&mut store, 0, b"lm", 6);
        assert_eq!(store.pop_front().unwrap().as_slice(), b"lm");
    }

    #[test]
    fn append_reads_back_exact_bytes() {
        let mut store = RxStore::new();
        let first = insert_with_room(&mut store, 0, b"ab", APPEND_MAX, 4);
        for bytes in [&b"cd"[..], &b"efg"[..], &b"hij"[..]] {
            let offset = store.in_order_len();
            let (frame, releases) = counted_frame(bytes);
            let decision = store.decide(offset, bytes.len(), 4);
            assert_eq!(
                decision,
                Decision::Append(offset..offset.checked_add(bytes.len()).unwrap())
            );
            assert_eq!(
                decision.kept(),
                Some(offset..offset.checked_add(bytes.len()).unwrap())
            );
            store.append(offset, decision, frame.as_slice());
            drop(frame);
            assert_eq!(releases.get(), 1);
            assert!(!store.has_pending());
        }
        assert_eq!(store.held(), 1);
        assert_eq!(store.in_order_len(), 10);
        assert_eq!(first.get(), 0);
        assert_eq!(drain_bytes(&mut store), b"abcdefghij");
        assert_eq!(first.get(), 1);
        drop(store);
        assert_eq!(first.get(), 1);
    }

    #[test]
    fn append_limits() {
        let mut store = RxStore::new();
        assert!(matches!(store.decide(0, 1, 4), Decision::New(_)));
        insert_with_room(&mut store, 0, b"a", APPEND_MAX, 4);
        assert!(matches!(
            store.decide(1, APPEND_MAX.checked_add(1).unwrap(), 4),
            Decision::New(_)
        ));
        let decision = store.decide(1, APPEND_MAX, 4);
        assert!(matches!(decision, Decision::Append(_)));
        store.append(1, decision, &vec![b'b'; APPEND_MAX]);
        assert_eq!(
            store.views.back().unwrap().frame.as_ref().unwrap().room(),
            0
        );
        assert!(matches!(
            store.decide(store.in_order_len(), 1, 4),
            Decision::New(_)
        ));

        let mut store = RxStore::new();
        insert_with_room(&mut store, 0, b"a", 3, 4);
        assert!(matches!(store.decide(1, 4, 4), Decision::New(_)));
        let mut store = RxStore::new();
        let large = APPEND_MAX.checked_add(1).unwrap();
        insert_with_room(&mut store, 0, b"a", large.checked_mul(2).unwrap(), 4);
        assert!(matches!(store.decide(1, large, 4), Decision::New(_)));
    }

    #[test]
    fn append_never_crosses_a_hole() {
        let mut store = RxStore::new();
        insert_with_room(&mut store, 0, b"ab", APPEND_MAX, 4);
        insert_with_room(&mut store, 4, b"ef", APPEND_MAX, 4);
        assert!(matches!(store.decide(2, 2, 4), Decision::New(_)));
        assert!(matches!(store.decide(6, 1, 4), Decision::New(_)));
        let mut store = RxStore::new();
        let decision = store.decide(0, 2, 4);
        store.place(0, decision);
        assert!(store.has_pending());
        assert!(matches!(store.decide(2, 1, 4), Decision::New(_)));
    }

    #[test]
    fn append_ignores_the_view_cap() {
        let mut store = RxStore::new();
        let cap = 1;
        insert_with_room(&mut store, 0, b"a", APPEND_MAX, cap);
        assert_eq!(store.held(), cap);
        let decision = store.decide(1, 1, cap);
        assert_eq!(decision, Decision::Append(1..2));
        store.append(1, decision, b"b");
        assert_eq!(store.held(), cap);
        assert_eq!(store.in_order_len(), 2);
    }

    #[test]
    fn append_after_drain_and_truncate() {
        let mut store = RxStore::new();
        insert(&mut store, 0, b"z", 4);
        let releases = insert_with_room(&mut store, 1, b"ab", APPEND_MAX, 4);
        drop(store.pop_front().unwrap());
        let decision = store.decide(2, 2, 4);
        store.append(2, decision, b"cd");
        let decision = store.decide(4, 2, 4);
        store.append(4, decision, b"ef");
        let room = store.views.back().unwrap().frame.as_ref().unwrap().room();
        store.truncate_from(4);
        assert_eq!(store.views.back().unwrap().frame.as_ref().unwrap().room(),
            room.checked_add(2).unwrap());
        let decision = store.decide(4, 2, 4);
        store.append(4, decision, b"XY");
        assert_eq!(store.held(), 1);
        assert_eq!(drain_bytes(&mut store), b"abcdXY");
        assert_eq!(releases.get(), 1);
    }

    #[test]
    #[should_panic(expected = "pending receive view")]
    fn stale_append_with_pending_view_panics() {
        let mut store = RxStore::new();
        insert_with_room(&mut store, 0, b"a", APPEND_MAX, 4);
        let decision = store.decide(1, 1, 4);
        let later = store.decide(3, 1, 4);
        store.place(3, later);
        store.append(1, decision, b"b");
    }

    #[test]
    #[should_panic(expected = "stale append decision: variant")]
    fn append_with_new_decision_panics() {
        let mut store = RxStore::new();
        let decision = store.decide(0, 1, 4);
        store.append(0, decision, b"a");
    }

    #[test]
    #[should_panic(expected = "stale append decision: offset")]
    fn stale_append_with_different_offset_panics() {
        let mut store = RxStore::new();
        insert_with_room(&mut store, 0, b"a", APPEND_MAX, 4);
        let decision = store.decide(1, 1, 4);
        store.append(2, decision, b"b");
    }

    #[test]
    #[should_panic(expected = "stale append decision: payload length")]
    fn stale_append_with_different_payload_length_panics() {
        let mut store = RxStore::new();
        insert_with_room(&mut store, 0, b"a", APPEND_MAX, 4);
        let decision = store.decide(1, 1, 4);
        store.append(1, decision, b"bc");
    }

    #[test]
    #[should_panic(expected = "stale append decision: empty payload")]
    fn append_with_empty_payload_panics() {
        let mut store = RxStore::new();
        store.append(0, Decision::Append(0..0), b"");
    }

    #[test]
    #[should_panic(expected = "stale append decision: in-order bytes")]
    fn stale_append_after_drain_panics() {
        let mut store = RxStore::new();
        insert_with_room(&mut store, 0, b"ab", APPEND_MAX, 4);
        let decision = store.decide(2, 1, 4);
        drop(store.pop_front().unwrap());
        store.append(2, decision, b"c");
    }

    #[test]
    #[should_panic(expected = "stale append decision: in-order bytes")]
    fn stale_append_after_truncate_panics() {
        let mut store = RxStore::new();
        insert_with_room(&mut store, 0, b"ab", APPEND_MAX, 4);
        let decision = store.decide(2, 1, 4);
        store.truncate_from(1);
        store.append(2, decision, b"c");
    }

    #[test]
    #[should_panic(expected = "stale append decision: last view")]
    fn append_without_last_view_panics() {
        let mut store = RxStore::new();
        store.append(0, Decision::Append(0..1), b"a");
    }

    #[test]
    #[should_panic(expected = "stale append decision: last view end")]
    fn stale_append_after_out_of_order_insert_panics() {
        let mut store = RxStore::new();
        insert_with_room(&mut store, 0, b"a", APPEND_MAX, 4);
        let decision = store.decide(1, 1, 4);
        insert_with_room(&mut store, 3, b"d", APPEND_MAX, 4);
        store.append(1, decision, b"b");
    }

    #[test]
    #[should_panic(expected = "stale append decision: frame room")]
    fn stale_append_after_frame_replacement_panics() {
        let mut store = RxStore::new();
        insert_with_room(&mut store, 0, b"a", APPEND_MAX, 4);
        let decision = store.decide(1, 1, 4);
        store.clear();
        insert(&mut store, 0, b"a", 4);
        store.append(1, decision, b"b");
    }

    #[test]
    #[should_panic(expected = "append decision passed to place")]
    fn place_with_append_decision_panics() {
        let mut store = RxStore::new();
        insert_with_room(&mut store, 0, b"a", APPEND_MAX, 4);
        let decision = store.decide(1, 1, 4);
        store.place(1, decision);
    }

    fn insert(store: &mut RxStore, offset: usize, bytes: &[u8], cap: usize) -> Rc<Cell<usize>> {
        let (frame, releases) = counted_frame(bytes);
        let decision = store.decide(offset, bytes.len(), cap);
        assert!(matches!(decision, Decision::New(_)));
        place_attach(store, offset, frame, decision);
        assert_eq!(releases.get(), 0);
        releases
    }

    fn ranges(store: &RxStore) -> Vec<(usize, usize)> {
        store.ranges().collect()
    }

    fn insert_stamped(
        store: &mut RxStore,
        offset: usize,
        bytes: &[u8],
        stamp: u64,
    ) -> Rc<Cell<usize>> {
        let (mut frame, releases) = counted_frame(bytes);
        frame.set_rx_timestamp(stamp);
        let decision = store.decide(offset, bytes.len(), 4);
        assert!(matches!(decision, Decision::New(_)));
        place_attach(store, offset, frame, decision);
        releases
    }

    fn drain_stamped(store: &mut RxStore) -> Vec<(Vec<u8>, u64)> {
        let mut frames = Vec::new();
        while let Some(frame) = store.pop_front() {
            frames.push((frame.as_slice().to_vec(), frame.rx_timestamp()));
        }
        frames
    }

    #[test]
    fn popped_frame_reports_its_timestamp() {
        for stamp in [0, 0xfedc_ba98_7654_3210] {
            let mut store = RxStore::new();
            insert_stamped(&mut store, 0, b"abc", stamp);
            assert_eq!(drain_stamped(&mut store), vec![(b"abc".to_vec(), stamp)]);
        }
    }

    #[test]
    fn append_keeps_target_frame_timestamp() {
        let mut store = RxStore::new();
        let (mut first, first_releases) = counted_frame_with_room(b"abc", 3);
        first.set_rx_timestamp(1);
        let decision = store.decide(0, 3, 4);
        place_attach(&mut store, 0, first, decision);
        let (mut incoming, incoming_releases) = counted_frame(b"def");
        incoming.set_rx_timestamp(2);
        let decision = store.decide(3, 3, 4);
        assert_eq!(decision, Decision::Append(3..6));
        store.append(3, decision, incoming.as_slice());
        drop(incoming);
        assert_eq!(store.held(), 1);
        assert_eq!((first_releases.get(), incoming_releases.get()), (0, 1));
        assert_eq!(drain_stamped(&mut store), vec![(b"abcdef".to_vec(), 1)]);
        assert_eq!((first_releases.get(), incoming_releases.get()), (1, 1));
    }

    #[test]
    fn hole_fill_frames_keep_arrival_timestamps() {
        let mut store = RxStore::new();
        insert_stamped(&mut store, 3, b"def", 1);
        insert_stamped(&mut store, 6, b"ghi", 2);
        insert_stamped(&mut store, 0, b"abc", 3);
        assert_eq!(
            drain_stamped(&mut store),
            vec![(b"abc".to_vec(), 3), (b"def".to_vec(), 1), (b"ghi".to_vec(), 2)]
        );
    }

    #[test]
    fn covering_segment_replaces_released_timestamps() {
        let mut store = RxStore::new();
        let first = insert_stamped(&mut store, 3, b"def", 1);
        let second = insert_stamped(&mut store, 6, b"ghi", 2);
        let replacement = insert_stamped(&mut store, 0, b"abcdefghi", 3);
        assert_eq!(store.held(), 1);
        assert_eq!((first.get(), second.get(), replacement.get()), (1, 1, 0));
        assert_eq!(drain_stamped(&mut store), vec![(b"abcdefghi".to_vec(), 3)]);
        assert_eq!((first.get(), second.get(), replacement.get()), (1, 1, 1));
    }

    #[test]
    fn right_neighbor_trim_keeps_timestamp() {
        let mut store = RxStore::new();
        let right = insert_stamped(&mut store, 3, b"defghi", 1);
        insert_stamped(&mut store, 0, b"ABCDE", 2);
        assert_eq!(ranges(&store), vec![(0, 5), (5, 9)]);
        assert_eq!(right.get(), 0);
        assert_eq!(
            drain_stamped(&mut store),
            vec![(b"ABCDE".to_vec(), 2), (b"fghi".to_vec(), 1)]
        );
        assert_eq!(right.get(), 1);
    }

    #[test]
    fn fin_truncate_keeps_timestamp() {
        let mut store = RxStore::new();
        let releases = insert_stamped(&mut store, 0, b"abcdef", 1);
        store.truncate_from(2);
        assert_eq!(releases.get(), 0);
        assert_eq!(drain_stamped(&mut store), vec![(b"ab".to_vec(), 1)]);
        assert_eq!(releases.get(), 1);
    }

    #[test]
    fn timestamps_stop_at_in_order_end() {
        let mut store = RxStore::new();
        assert!(drain_stamped(&mut store).is_empty());
        insert_stamped(&mut store, 6, b"ghi", 2);
        assert!(drain_stamped(&mut store).is_empty());
        insert_stamped(&mut store, 0, b"abc", 1);
        assert_eq!(store.held(), 2);
        assert_eq!(drain_stamped(&mut store), vec![(b"abc".to_vec(), 1)]);
        assert_eq!(store.held(), 1);
    }

    #[test]
    fn in_order_appends_match_general_path() {
        let mut x = RxStore::new();
        let x_releases = [
            insert(&mut x, 0, b"abc", 4),
            insert(&mut x, 3, b"defg", 4),
            insert(&mut x, 7, b"hijkl", 4),
        ];
        let mut y = RxStore::new();
        let y_last = insert(&mut y, 7, b"hijkl", 4);
        let y_middle = insert(&mut y, 3, b"defg", 4);
        let y_first = insert(&mut y, 0, b"abc", 4);
        let y_releases = [y_first, y_middle, y_last];

        assert_eq!(ranges(&x), vec![(0, 3), (3, 7), (7, 12)]);
        assert_eq!(ranges(&x), ranges(&y));
        for (index, expected) in [b"abc".as_slice(), b"defg", b"hijkl"].into_iter().enumerate() {
            let x_frame = x.pop_front().unwrap();
            let y_frame = y.pop_front().unwrap();
            assert_eq!(x_frame.as_slice(), expected);
            assert_eq!(y_frame.as_slice(), expected);
            assert_eq!(ranges(&x), ranges(&y));
            assert_eq!(x.in_order_len(), y.in_order_len());
            assert_eq!(x.out_of_order_len(), 0);
            assert_eq!(y.out_of_order_len(), 0);
            assert_eq!(x.held(), 2 - index);
            assert_eq!(y.held(), 2 - index);
            assert_eq!(x_releases[index].get(), 0);
            assert_eq!(y_releases[index].get(), 0);
            drop((x_frame, y_frame));
            assert_eq!(x_releases[index].get(), 1);
            assert_eq!(y_releases[index].get(), 1);
        }
        assert!(x.pop_front().is_none());
        assert!(y.pop_front().is_none());
        assert_eq!(x.in_order_len(), 0);
        assert_eq!(y.in_order_len(), 0);
        drop((x, y));
        assert!(x_releases.iter().all(|count| count.get() == 1));
        assert!(y_releases.iter().all(|count| count.get() == 1));
    }

    #[test]
    fn drain_all_in_order_releases_each_frame_once() {
        let mut store = RxStore::new();
        let first = insert(&mut store, 0, b"abc", 4);
        let second = insert(&mut store, 3, b"defg", 4);
        let third = insert(&mut store, 7, b"hijkl", 4);
        drop(drain_bytes(&mut store));
        assert_eq!(store.held(), 0);
        assert_eq!(store.in_order_len(), 0);
        assert_eq!(store.out_of_order_len(), 0);
        assert_eq!((first.get(), second.get(), third.get()), (1, 1, 1));
        assert!(store.pop_front().is_none());
        drop(store);
        assert_eq!((first.get(), second.get(), third.get()), (1, 1, 1));

        let mut store = RxStore::new();
        let first = insert(&mut store, 0, b"abc", 4);
        let second = insert(&mut store, 3, b"defg", 4);
        let later = insert(&mut store, 10, b"kl", 4);
        drop(drain_bytes(&mut store));
        assert_eq!(store.held(), 1);
        assert_eq!(store.in_order_len(), 0);
        assert_eq!(store.out_of_order_len(), 2);
        assert_eq!(ranges(&store), vec![(3, 5)]);
        assert_eq!(store.views[0].frame.as_ref().unwrap().as_slice(), b"kl");
        assert!(store.pop_front().is_none());
        assert_eq!((first.get(), second.get(), later.get()), (1, 1, 0));
        drop(store);
        assert_eq!((first.get(), second.get(), later.get()), (1, 1, 1));
    }

    #[test]
    fn append_place_keeps_stale_checks() {
        for consume in [false, true] {
            let mut store = RxStore::new();
            let first = insert(&mut store, 0, b"abc", 4);
            let decision = store.decide(3, 4, 4);
            let second = insert(&mut store, 3, b"de", 4);
            if consume {
                drop(store.pop_front().unwrap());
            }
            let before = ranges(&store);
            let (frame, incoming) = counted_frame(b"DEFG");
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                place_attach(&mut store, 3, frame, decision);
            }))
            .unwrap_err();
            let message = if consume {
                "stale new decision: left neighbor"
            } else {
                "stale new decision: right neighbor"
            };
            assert_eq!(panic.downcast_ref::<&str>(), Some(&message));
            assert_eq!(ranges(&store), before);
            assert!(!store.has_pending());
            let expected_bytes = if consume { &b"de"[..] } else { &b"abcde"[..] };
            assert_eq!(
                drain_bytes(&mut store),
                expected_bytes
            );
            assert_eq!(
                (first.get(), second.get(), incoming.get()),
                (1, 1, 1)
            );
            drop(store);
            assert_eq!((first.get(), second.get(), incoming.get()), (1, 1, 1));
        }
    }

    #[test]
    fn append_place_rejects_stale_view_cap() {
        let mut store = RxStore::new();
        insert(&mut store, 0, b"ab", 3);
        insert(&mut store, 2, b"c", 3);
        let decision = store.decide(3, 1, 3);
        store.clear();
        let left = insert(&mut store, 1, b"b", 3);
        let right = insert(&mut store, 2, b"c", 3);
        assert_eq!(store.in_order_len(), 0);
        let before = ranges(&store);
        assert_eq!(before, vec![(1, 2), (2, 3)]);
        let (frame, incoming) = counted_frame(b"d");
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            place_attach(&mut store, 3, frame, decision);
        }))
        .unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"stale new decision: view cap")
        );
        assert_eq!(ranges(&store), before);
        assert!(!store.has_pending());
        assert_eq!((left.get(), right.get(), incoming.get()), (0, 0, 1));
        drop(store);
        assert_eq!((left.get(), right.get(), incoming.get()), (1, 1, 1));
    }

    #[test]
    fn out_of_order_ranges_empty() {
        let store = RxStore::new();
        assert_eq!(store.out_of_order_ranges().next(), None);
    }

    #[test]
    fn out_of_order_ranges_in_order_only() {
        let mut store = RxStore::new();
        insert(&mut store, 0, b"abcd", 16);
        insert(&mut store, 4, b"ef", 16);
        assert_eq!(store.out_of_order_ranges().next(), None);
    }

    #[test]
    fn out_of_order_ranges_merge_adjacent_views() {
        let mut store = RxStore::new();
        insert(&mut store, 0, b"ab", 16);
        insert(&mut store, 4, b"ef", 16);
        insert(&mut store, 6, b"gh", 16);
        insert(&mut store, 10, b"kl", 16);
        insert(&mut store, 12, b"mn", 16);
        assert_eq!(store.out_of_order_ranges().collect::<Vec<_>>(), vec![(2, 6), (8, 12)]);
    }

    #[test]
    fn out_of_order_ranges_after_partial_hole_fill() {
        let mut store = RxStore::new();
        insert(&mut store, 0, b"ab", 16);
        insert(&mut store, 6, b"gh", 16);
        insert(&mut store, 10, b"kl", 16);
        insert(&mut store, 2, b"cd", 16);
        assert_eq!(store.in_order_len(), 4);
        assert_eq!(store.out_of_order_ranges().collect::<Vec<_>>(), vec![(2, 4), (6, 8)]);
    }

    #[test]
    fn out_of_order_ranges_after_draining_in_order_frames() {
        let mut store = RxStore::new();
        insert(&mut store, 0, b"ab", 16);
        insert(&mut store, 2, b"cd", 16);
        insert(&mut store, 6, b"gh", 16);
        insert(&mut store, 10, b"kl", 16);
        let expected = vec![(2, 4), (6, 8)];
        assert_eq!(store.out_of_order_ranges().collect::<Vec<_>>(), expected);
        drop(store.pop_front().unwrap());
        assert_eq!(store.in_order_len(), 2);
        assert_eq!(store.out_of_order_ranges().collect::<Vec<_>>(), expected);
        drop(store.pop_front().unwrap());
        assert_eq!(store.in_order_len(), 0);
        assert_eq!(store.out_of_order_ranges().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn out_of_order_len_is_zero_without_out_of_order_views() {
        let mut store = RxStore::new();
        assert_eq!(store.out_of_order_len(), 0);

        insert(&mut store, 0, b"abc", 6);
        insert(&mut store, 3, b"de", 6);
        assert_eq!(store.out_of_order_len(), 0);

        insert(&mut store, 7, b"hij", 6);
        assert_eq!(store.out_of_order_len(), 3);

        insert(&mut store, 5, b"fg", 6);
        assert_eq!(store.out_of_order_len(), 0);
        assert_eq!(drain_bytes(&mut store), b"abcdefghij");
        assert_eq!(store.held(), 0);
        assert_eq!(store.out_of_order_len(), 0);
    }

    #[test]
    fn out_of_order_span_tracks_last_view_end_from_in_order_end() {
        let mut store = RxStore::new();
        assert_eq!(store.out_of_order_span(), 0);
        insert(&mut store, 0, b"ab", 8);
        insert(&mut store, 2, b"cde", 6);
        assert_eq!(store.out_of_order_span(), 0);
        insert(&mut store, 7, b"hij", 6);
        assert_eq!(store.out_of_order_span(), 5);
        insert(&mut store, 12, b"mn", 6);
        assert_eq!(store.out_of_order_len(), 5);
        assert_eq!(store.out_of_order_span(), 9);
        drop(store.pop_front().unwrap());
        assert_eq!(store.out_of_order_span(), 9);
        store.truncate_from(11);
        assert_eq!(store.out_of_order_span(), 8);
        insert(&mut store, 3, b"fg", 6);
        assert_eq!(store.out_of_order_span(), 3);
        insert(&mut store, 8, b"kl", 6);
        assert_eq!(store.out_of_order_span(), 0);
        assert_eq!(drain_bytes(&mut store), b"cdefghijklm");
        assert_eq!(store.out_of_order_span(), 0);
        insert(&mut store, 2, b"c", 6);
        assert_eq!(store.out_of_order_span(), 3);
        store.clear();
        assert_eq!(store.out_of_order_span(), 0);
    }

    // Every gap below is shorter than 64 bytes, so each costs one frame.
    #[test]
    fn out_of_order_hole_frames_tracks_gaps_between_contiguous_views() {
        let mut store = RxStore::new();
        assert_eq!(store.out_of_order_hole_frames(64), 0);
        insert(&mut store, 0, b"ab", 8);
        insert(&mut store, 2, b"cde", 8);
        assert_eq!(store.out_of_order_hole_frames(64), 0);
        insert(&mut store, 7, b"hij", 8);
        assert_eq!(store.out_of_order_hole_frames(64), 1);
        insert(&mut store, 10, b"kl", 8);
        assert_eq!(store.out_of_order_hole_frames(64), 1);
        insert(&mut store, 14, b"op", 8);
        assert_eq!(store.out_of_order_hole_frames(64), 2);
        insert(&mut store, 18, b"st", 8);
        assert_eq!(store.out_of_order_hole_frames(64), 3);
        drop(store.pop_front().unwrap());
        assert_eq!(store.out_of_order_hole_frames(64), 3);
        store.truncate_from(16);
        assert_eq!(store.out_of_order_hole_frames(64), 2);
        insert(&mut store, 3, b"fg", 8);
        assert_eq!(store.out_of_order_hole_frames(64), 1);
        insert(&mut store, 10, b"mn", 8);
        assert_eq!(store.out_of_order_hole_frames(64), 0);
        assert_eq!(drain_bytes(&mut store), b"cdefghijklmnop");
        assert_eq!(store.out_of_order_hole_frames(64), 0);
        insert(&mut store, 2, b"c", 8);
        assert_eq!(store.out_of_order_hole_frames(64), 1);
        store.clear();
        assert_eq!(store.out_of_order_hole_frames(64), 0);
    }

    #[test]
    fn out_of_order_hole_frames_with_many_in_order_views() {
        let mut store = RxStore::new();
        for offset in 0..700 {
            insert(&mut store, offset, b"a", 704);
        }
        assert_eq!(store.held(), 700);
        assert_eq!(store.in_order_len(), 700);
        assert_eq!(store.out_of_order_span(), 0);
        assert_eq!(store.out_of_order_hole_frames(64), 0);

        insert(&mut store, 702, b"bc", 704);
        insert(&mut store, 704, b"de", 704);
        insert(&mut store, 708, b"fg", 704);
        assert_eq!(store.held(), 703);
        assert_eq!(store.in_order_len(), 700);
        assert_eq!(store.out_of_order_hole_frames(64), 2);
    }

    #[test]
    fn out_of_order_hole_frames_charge_ceil_of_gap_per_segment() {
        for (k, seg) in [(1, 4), (3, 4), (2, 1460)] {
            for (gap, frames) in [(k * seg, k), (k * seg + 1, k + 1)] {
                let mut store = RxStore::new();
                insert(&mut store, 0, b"a", 8);
                insert(&mut store, 1 + gap, b"b", 8);
                assert_eq!(store.out_of_order_hole_frames(seg), frames, "gap {gap}, segment {seg}");
            }
        }
    }

    #[test]
    fn out_of_order_hole_frames_matches_brute_force_after_randomized_operations() {
        // Missing byte runs between in-order end and the last view, each charged by segment.
        fn brute_force(store: &RxStore, seg_bytes: usize) -> usize {
            let in_order_end = store.absolute(store.in_order_len());
            let end = store.views.back().map_or(in_order_end, View::end).max(in_order_end);
            let mut held = vec![false; end - in_order_end];
            for view in &store.views {
                for byte in view.range().filter(|&byte| byte >= in_order_end) {
                    held[byte - in_order_end] = true;
                }
            }
            held.split(|&held| held)
                .map(|run| run.len().div_ceil(seg_bytes))
                .sum()
        }

        let mut store = RxStore::new();
        let mut seed = 0x12345678u32;
        let mut next = || {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            (seed >> 16) as usize
        };
        for step in 0..3000 {
            match next() % 6 {
                operation @ 0..=3 => {
                    let offset = match operation {
                        0 | 1 => store.in_order_len(),
                        2 => store.in_order_len().checked_add(1 + next() % 32).unwrap(),
                        _ => next() % 64,
                    };
                    let len = 1 + next() % 16;
                    let payload = &[b'a'; 16][..len];
                    let (frame, _) = counted_frame(payload);
                    let decision = store.decide(offset, len, 1024);
                    if matches!(decision, Decision::Append(_)) {
                        store.append(offset, decision, payload);
                    } else {
                        place_attach(&mut store, offset, frame, decision);
                    }
                }
                4 => {
                    for _ in 0..next() % store.held().checked_add(1).unwrap() {
                        drop(store.pop_front());
                    }
                }
                _ => {
                    let end = store.ranges().last().map_or(0, |(_, end)| end);
                    store.truncate_from(next() % end.checked_add(1).unwrap());
                }
            }
            for seg_bytes in [1, 3, 64] {
                assert_eq!(
                    store.out_of_order_hole_frames(seg_bytes),
                    brute_force(&store, seg_bytes),
                    "step {step}, segment {seg_bytes}, in-order end {}, ranges {:?}",
                    store.in_order_len(),
                    ranges(&store)
                );
            }
        }
    }

    #[test]
    fn hole_fill_joins_following_views() {
        let mut store = RxStore::new();
        insert(&mut store, 3, b"de", 5);
        insert(&mut store, 5, b"fgh", 5);
        insert(&mut store, 10, b"kl", 5);
        assert_eq!((store.in_order_len(), store.out_of_order_len()), (0, 7));
        assert_eq!(ranges(&store), vec![(3, 5), (5, 8), (10, 12)]);

        insert(&mut store, 0, b"abc", 5);
        assert_eq!((store.in_order_len(), store.out_of_order_len()), (8, 2));
        assert_eq!(ranges(&store), vec![(0, 3), (3, 5), (5, 8), (10, 12)]);

        insert(&mut store, 8, b"ij", 5);
        assert_eq!((store.in_order_len(), store.out_of_order_len()), (12, 0));
        assert_eq!(
            ranges(&store),
            vec![(0, 3), (3, 5), (5, 8), (8, 10), (10, 12)]
        );
        assert_eq!(drain_bytes(&mut store), b"abcdefghijkl");
    }

    #[test]
    fn covering_segment_extends_in_order_over_released_views() {
        let mut store = RxStore::new();
        let first = insert(&mut store, 0, b"ab", 4);
        let middle = insert(&mut store, 4, b"ef", 4);
        let last = insert(&mut store, 7, b"hi", 4);
        assert_eq!((store.in_order_len(), store.out_of_order_len()), (2, 4));

        let decision = store.decide(2, 7, 4);
        assert!(matches!(&decision, Decision::New(new) if new.released == 2));
        store.place(2, decision);
        assert_eq!((store.in_order_len(), store.out_of_order_len()), (9, 0));
        assert_eq!(ranges(&store), vec![(0, 2), (2, 9)]);
        assert_eq!((first.get(), middle.get(), last.get()), (0, 1, 1));

        let (frame, new) = counted_frame(b"cdefghi");
        store.attach(frame);
        assert_eq!(drain_bytes(&mut store), b"abcdefghi");
        assert_eq!(
            (first.get(), middle.get(), last.get(), new.get()),
            (1, 1, 1, 1)
        );
        drop(store);
        assert_eq!(
            (first.get(), middle.get(), last.get(), new.get()),
            (1, 1, 1, 1)
        );
    }

    #[test]
    fn truncate_and_drain_update_counts() {
        let mut store = RxStore::new();
        insert(&mut store, 0, b"ab", 6);
        insert(&mut store, 2, b"cd", 6);
        insert(&mut store, 4, b"efgh", 6);
        insert(&mut store, 10, b"kl", 6);
        insert(&mut store, 14, b"op", 6);
        assert_eq!((store.in_order_len(), store.out_of_order_len()), (8, 4));
        assert_eq!(store.pop_front().unwrap().as_slice(), b"ab");
        assert_eq!((store.in_order_len(), store.out_of_order_len()), (6, 4));
        assert_eq!(ranges(&store), vec![(0, 2), (2, 6), (8, 10), (12, 14)]);
        store.truncate_from(4);
        assert_eq!((store.in_order_len(), store.out_of_order_len()), (4, 0));
        assert_eq!(ranges(&store), vec![(0, 2), (2, 4)]);
        insert(&mut store, 8, b"kl", 6);
        insert(&mut store, 12, b"op", 6);
        assert_eq!((store.in_order_len(), store.out_of_order_len()), (4, 4));
        store.truncate_from(9);
        assert_eq!(ranges(&store), vec![(0, 2), (2, 4), (8, 9)]);
        assert_eq!(store.views[2].frame.as_ref().unwrap().as_slice(), b"k");
        assert_eq!(drain_bytes(&mut store), b"cdef");
        assert!(store.pop_front().is_none());
        store.clear();
        assert!(store.pop_front().is_none());
        assert_eq!(store.head, 0);
        insert(&mut store, 0, b"new", 6);
        assert_eq!(store.pop_front().unwrap().as_slice(), b"new");
        assert_eq!(store.head, 0);
    }

    #[test]
    fn attach_finds_pending_view_before_later_views() {
        let mut store = RxStore::new();
        let later = insert(&mut store, 10, b"kl", 3);
        store.place(0, store.decide(0, 3, 3));
        assert!(store.has_pending());
        assert_eq!(ranges(&store), vec![(0, 3), (10, 12)]);

        let (frame, attached) = counted_frame(b"abc");
        store.attach(frame);
        assert!(!store.has_pending());
        assert_eq!((store.in_order_len(), store.out_of_order_len()), (3, 2));
        assert_eq!(drain_bytes(&mut store), b"abc");
        assert_eq!(ranges(&store), vec![(7, 9)]);
        assert_eq!((attached.get(), later.get()), (1, 0));
        store.clear();
        assert_eq!((attached.get(), later.get()), (1, 1));
    }

    #[test]
    fn append_after_last_view_decides_like_inner_offsets() {
        let mut store = RxStore::new();
        insert(&mut store, 0, b"abc", 4);
        insert(&mut store, 5, b"fgh", 4);
        let new = |kept: Range<usize>, len| {
            Decision::New(NewView {
                kept,
                len,
                index: 2,
                left: Some(5..8),
                released: 0,
                released_span: None,
                trimmed: None,
                cap: 4,
            })
        };
        assert_eq!(store.decide(8, 2, 4), new(8..10, 2));
        assert_eq!(store.decide(9, 2, 4), new(9..11, 2));
        assert_eq!(store.decide(7, 3, 4), new(8..10, 3));
        assert_eq!(store.decide(6, 2, 4), Decision::Duplicate(6..8));
        assert_eq!(store.decide(8, 2, 2), Decision::Refused);
        assert_eq!(ranges(&store), vec![(0, 3), (5, 8)]);
    }

    #[test]
    fn pending_layout_counts_bytes_and_blocks_reads() {
        let mut store = RxStore::new();
        let covered = insert(&mut store, 0, b"old", 4);
        let trimmed = insert(&mut store, 6, b"ghi", 4);
        let later = insert(&mut store, 10, b"klm", 4);
        let decision = store.decide(0, 7, 4);
        store.place(0, decision);
        assert!(store.has_pending());
        assert_eq!(ranges(&store), vec![(0, 7), (7, 9), (10, 13)]);
        assert_eq!(
            (store.in_order_len(), store.out_of_order_len(), store.held()),
            (9, 3, 3)
        );
        assert_eq!((covered.get(), trimmed.get(), later.get()), (1, 0, 0));
        assert!(store.pop_front().is_none());
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store.place(0, store.decide(0, 1, 4));
        })).unwrap_err();
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"pending receive view"));
        assert_eq!(ranges(&store), vec![(0, 7), (7, 9), (10, 13)]);
        assert_eq!((covered.get(), trimmed.get(), later.get()), (1, 0, 0));
        let (frame, attached) = counted_frame(b"abcdefg");
        store.attach(frame);
        assert!(!store.has_pending());
        assert_eq!(drain_bytes(&mut store), b"abcdefghi");
        assert_eq!((attached.get(), trimmed.get(), later.get()), (1, 1, 0));
    }

    #[test]
    fn truncate_preserves_pending_view_before_boundary() {
        let mut store = RxStore::new();
        let later = insert(&mut store, 5, b"fgh", 3);
        store.place(0, store.decide(0, 3, 3));
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store.truncate_from(2);
        }))
        .unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"truncate cuts pending receive view")
        );
        assert_eq!(ranges(&store), vec![(0, 3), (5, 8)]);
        assert_eq!(later.get(), 0);
        store.truncate_from(3);
        assert_eq!(ranges(&store), vec![(0, 3)]);
        assert_eq!(later.get(), 1);
        assert!(store.has_pending());
        store.attach(RxBuf::from_vec(b"abc".to_vec()));
        assert_eq!(store.views.front().unwrap().frame.as_ref().unwrap().as_slice(), b"abc");
    }

    #[test]
    fn clear_and_drop_release_frames_with_pending_view() {
        for clear in [false, true] {
            let mut store = RxStore::new();
            let held = insert(&mut store, 5, b"fgh", 3);
            store.place(0, store.decide(0, 3, 3));
            if clear {
                store.clear();
                assert!(!store.has_pending());
                assert_eq!(store.held(), 0);
                assert_eq!(held.get(), 1);
            }
            drop(store);
            assert_eq!(held.get(), 1);
        }
    }

    #[test]
    fn left_neighbor_wins_overlap() {
        let mut store = RxStore::new();
        let left = insert(&mut store, 5, b"abcdefghij", 8);
        let (frame, new) = counted_frame(b"ABCDEFGHIJ");
        let decision = store.decide(10, 10, 8);
        assert_eq!(decision.kept(), Some(15..20));
        assert_eq!(ranges(&store), vec![(5, 15)]);
        place_attach(&mut store, 10, frame, decision);
        assert_eq!(ranges(&store), vec![(5, 15), (15, 20)]);
        assert_eq!(
            store.views[0].frame.as_ref().unwrap().as_slice(),
            b"abcdefghij"
        );
        assert_eq!(store.views[1].frame.as_ref().unwrap().as_slice(), b"FGHIJ");
        assert_eq!(store.in_order_len(), 0);
        assert_eq!(store.out_of_order_len(), 15);
        assert!(store.pop_front().is_none());
        assert!(store.pop_front().is_none());
        assert!(store.pop_front().is_none());
        assert_eq!((left.get(), new.get()), (0, 0));
        store.clear();
        assert_eq!((left.get(), new.get()), (1, 1));
    }

    #[test]
    fn covering_segment_releases_neighbors() {
        let mut store = RxStore::new();
        let first = insert(&mut store, 5, b"first", 4);
        let second = insert(&mut store, 12, b"two", 4);
        let last = insert(&mut store, 20, b"last!", 4);
        let (frame, new) = counted_frame(b"ABCDEFGHIJKL");
        let decision = store.decide(4, 12, 4);
        assert_eq!(
            decision,
            Decision::New(NewView {
                kept: 4..16,
                len: 12,
                index: 0,
                left: None,
                released: 2,
                released_span: Some(5..15),
                trimmed: None,
                cap: 4,
            })
        );
        assert_eq!((first.get(), second.get()), (0, 0));
        place_attach(&mut store, 4, frame, decision);
        assert_eq!(ranges(&store), vec![(4, 16), (20, 25)]);
        assert_eq!(
            store.views[0].frame.as_ref().unwrap().as_slice(),
            b"ABCDEFGHIJKL"
        );
        assert_eq!(
            (first.get(), second.get(), last.get(), new.get()),
            (1, 1, 0, 0)
        );
        store.clear();
        assert_eq!(
            (first.get(), second.get(), last.get(), new.get()),
            (1, 1, 1, 1)
        );
    }

    #[test]
    fn right_neighbor_head_trimmed() {
        let mut store = RxStore::new();
        let left = insert(&mut store, 5, b"abcdefghij", 8);
        let covered = insert(&mut store, 20, b"abcde", 8);
        let right = insert(&mut store, 28, b"abcdefghijkl", 8);
        let new = insert(&mut store, 10, b"ABCDEFGHIJKLMNOPQRST", 8);
        assert_eq!(ranges(&store), vec![(5, 15), (15, 30), (30, 40)]);
        assert_eq!(
            store.views[1].frame.as_ref().unwrap().as_slice(),
            b"FGHIJKLMNOPQRST"
        );
        assert_eq!(
            store.views[2].frame.as_ref().unwrap().as_slice(),
            b"cdefghijkl"
        );
        assert_eq!(
            (left.get(), covered.get(), right.get(), new.get()),
            (0, 1, 0, 0)
        );
        drop(store);
        assert_eq!(
            (left.get(), covered.get(), right.get(), new.get()),
            (1, 1, 1, 1)
        );
    }

    #[test]
    fn duplicate_inside_view_released() {
        let mut store = RxStore::new();
        let held = insert(&mut store, 0, b"abcdefghij", 4);
        let (frame, duplicate) = counted_frame(b"XYZ");
        let decision = store.decide(3, 3, 0);
        assert_eq!(decision, Decision::Duplicate(3..6));
        place_attach(&mut store, 3, frame, decision);
        assert_eq!(duplicate.get(), 1);
        assert_eq!(held.get(), 0);
        assert_eq!(store.views.front().unwrap().frame.as_ref().unwrap().as_slice(), b"abcdefghij");
        store.clear();
        assert_eq!(held.get(), 1);

        let first = insert(&mut store, 0, b"abcde", 4);
        let second = insert(&mut store, 5, b"fghij", 4);
        let (frame, duplicate) = counted_frame(b"XXXXXXXX");
        let decision = store.decide(1, 8, 4);
        assert_eq!(decision, Decision::Duplicate(1..9));
        place_attach(&mut store, 1, frame, decision);
        assert_eq!(ranges(&store), vec![(0, 5), (5, 10)]);
        assert_eq!((first.get(), second.get(), duplicate.get()), (0, 0, 1));
        store.clear();
        assert_eq!((first.get(), second.get(), duplicate.get()), (1, 1, 1));
    }

    #[test]
    fn equal_start_longer_wins() {
        let mut store = RxStore::new();
        let short = insert(&mut store, 0, b"old", 1);
        let long = insert(&mut store, 0, b"longer", 1);
        assert_eq!(ranges(&store), vec![(0, 6)]);
        assert_eq!(store.views.front().unwrap().frame.as_ref().unwrap().as_slice(), b"longer");
        assert_eq!(short.get(), 1);
        for bytes in [&b"short"[..], &b"equal!"[..]] {
            let (frame, duplicate) = counted_frame(bytes);
            let decision = store.decide(0, bytes.len(), 1);
            assert_eq!(decision, Decision::Duplicate(0..bytes.len()));
            place_attach(&mut store, 0, frame, decision);
            assert_eq!(duplicate.get(), 1);
            assert_eq!(store.views.front().unwrap().frame.as_ref().unwrap().as_slice(), b"longer");
        }
        store.clear();
        assert_eq!(long.get(), 1);
    }

    #[test]
    fn ooo_never_takes_front_slot() {
        let mut store = RxStore::new();
        assert_eq!(store.decide(0, 1, 0), Decision::Refused);
        assert_eq!(store.decide(5, 1, 0), Decision::Refused);
        assert_eq!(store.decide(5, 1, 1), Decision::Refused);
        insert(&mut store, 5, b"fghij", 3);
        insert(&mut store, 20, b"uvwxy", 3);
        let (frame, refused) = counted_frame(b"z");
        assert_eq!(store.decide(30, 1, 3), Decision::Refused);
        drop(frame);
        assert_eq!(refused.get(), 1);
        assert_eq!(ranges(&store), vec![(5, 10), (20, 25)]);
        insert(&mut store, 0, b"abcde", 3);
        assert_eq!(store.held(), 3);
        assert_eq!(store.in_order_len(), 10);
        assert_eq!(store.out_of_order_len(), 5);
    }

    #[test]
    fn front_slot_admits_hole_fill() {
        let mut store = RxStore::new();
        insert(&mut store, 0, b"abcde", 3);
        insert(&mut store, 10, b"klmno", 3);
        insert(&mut store, 5, b"fghij", 3);
        assert_eq!(store.held(), 3);
        assert_eq!(store.in_order_len(), 15);
        assert_eq!(store.out_of_order_len(), 0);
        store.clear();

        insert(&mut store, 20, b"uvwxy", 3);
        insert(&mut store, 0, b"abcde", 3);
        let covered = insert(&mut store, 5, b"fghij", 3);
        let (frame, new) = counted_frame(b"ABCDEFGHIJ");
        let decision = store.decide(2, 10, 3);
        assert_eq!(decision.kept(), Some(5..12));
        place_attach(&mut store, 2, frame, decision);
        assert_eq!(store.held(), 3);
        assert_eq!(store.in_order_len(), 12);
        assert_eq!(ranges(&store), vec![(0, 5), (5, 12), (20, 25)]);
        assert_eq!(
            store.views[1].frame.as_ref().unwrap().as_slice(),
            b"DEFGHIJ"
        );
        assert_eq!((covered.get(), new.get()), (1, 0));
    }

    #[test]
    fn drain_releases_two_whole_views() {
        let mut store = RxStore::new();
        let first = insert(&mut store, 0, b"abcd", 2);
        let second = insert(&mut store, 4, b"efgh", 2);
        assert_eq!(drain_bytes(&mut store), b"abcdefgh");
        assert_eq!(store.held(), 0);
        assert_eq!(store.in_order_len(), 0);
        assert_eq!((first.get(), second.get()), (1, 1));
        drop(store);
        assert_eq!((first.get(), second.get()), (1, 1));
    }

    #[test]
    fn truncate_from_drops_views_past_offset() {
        let mut store = RxStore::new();
        let first = insert(&mut store, 0, b"abcde", 5);
        let middle = insert(&mut store, 10, b"klmno", 5);
        let last = insert(&mut store, 20, b"uvwxy", 5);
        store.truncate_from(30);
        assert_eq!(store.held(), 3);
        store.truncate_from(12);
        assert_eq!(ranges(&store), vec![(0, 5), (10, 12)]);
        assert_eq!(store.views[1].frame.as_ref().unwrap().as_slice(), b"kl");
        assert_eq!((first.get(), middle.get(), last.get()), (0, 0, 1));
        store.truncate_from(10);
        assert_eq!(ranges(&store), vec![(0, 5)]);
        assert_eq!(middle.get(), 1);
        store.truncate_from(3);
        assert_eq!(store.views.front().unwrap().frame.as_ref().unwrap().as_slice(), b"abc");
        assert_eq!(first.get(), 0);
        store.truncate_from(0);
        assert_eq!(store.held(), 0);
        assert_eq!(first.get(), 1);
    }

    #[test]
    fn truncate_drops_several_whole_views() {
        let mut store = RxStore::new();
        let first = insert(&mut store, 0, b"abcde", 4);
        let middle = insert(&mut store, 10, b"klmno", 4);
        let last = insert(&mut store, 20, b"uvwxy", 4);
        store.truncate_from(10);
        assert_eq!(ranges(&store), vec![(0, 5)]);
        assert_eq!(store.views.front().unwrap().frame.as_ref().unwrap().as_slice(), b"abcde");
        assert_eq!((first.get(), middle.get(), last.get()), (0, 1, 1));
        drop(store);
        assert_eq!((first.get(), middle.get(), last.get()), (1, 1, 1));
    }

    #[test]
    fn stale_decision_after_commit_panics() {
        let mut store = RxStore::new();
        let decision = store.decide(0, 2, 1);
        let held = insert(&mut store, 0, b"ab", 1);
        let (frame, incoming) = counted_frame(b"AB");
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            place_attach(&mut store, 0, frame, decision);
        }))
        .unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"stale new decision: right neighbor")
        );
        assert_eq!(ranges(&store), vec![(0, 2)]);
        assert_eq!(store.views.front().unwrap().frame.as_ref().unwrap().as_slice(), b"ab");
        assert_eq!((held.get(), incoming.get()), (0, 1));
        drop(store);
        assert_eq!((held.get(), incoming.get()), (1, 1));
    }

    #[test]
    fn stale_duplicate_after_clear_panics() {
        let mut store = RxStore::new();
        let held = insert(&mut store, 0, b"abcd", 1);
        let decision = store.decide(1, 2, 1);
        assert_eq!(decision, Decision::Duplicate(1..3));
        store.clear();
        assert_eq!(held.get(), 1);
        let (frame, incoming) = counted_frame(b"BC");
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            place_attach(&mut store, 1, frame, decision);
        }))
        .unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"stale duplicate decision")
        );
        assert_eq!(store.held(), 0);
        assert_eq!((held.get(), incoming.get()), (1, 1));
        drop(store);
        assert_eq!((held.get(), incoming.get()), (1, 1));
    }

    #[test]
    fn stale_trim_after_truncate_panics() {
        let mut store = RxStore::new();
        let covered = insert(&mut store, 5, b"fgh", 4);
        let trimmed = insert(&mut store, 10, b"klmno", 4);
        let decision = store.decide(4, 8, 4);
        store.truncate_from(14);
        let (frame, incoming) = counted_frame(b"EFGHIJKL");
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            place_attach(&mut store, 4, frame, decision);
        }))
        .unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"stale new decision: trimmed view")
        );
        assert_eq!(ranges(&store), vec![(5, 8), (10, 14)]);
        assert_eq!(store.views[0].frame.as_ref().unwrap().as_slice(), b"fgh");
        assert_eq!(store.views[1].frame.as_ref().unwrap().as_slice(), b"klmn");
        assert_eq!((covered.get(), trimmed.get(), incoming.get()), (0, 0, 1));
        drop(store);
        assert_eq!((covered.get(), trimmed.get(), incoming.get()), (1, 1, 1));
    }

    #[test]
    fn stale_released_view_after_commit_panics() {
        let mut store = RxStore::new();
        let original = insert(&mut store, 5, b"fgh", 3);
        let decision = store.decide(4, 8, 3);
        let replacement = insert(&mut store, 5, b"fghi", 3);
        assert_eq!(original.get(), 1);
        let (frame, incoming) = counted_frame(b"EFGHIJKL");
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            place_attach(&mut store, 4, frame, decision);
        }))
        .unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"stale new decision: released views")
        );
        assert_eq!(ranges(&store), vec![(5, 9)]);
        assert_eq!(store.views[0].frame.as_ref().unwrap().as_slice(), b"fghi");
        assert_eq!(
            (original.get(), replacement.get(), incoming.get()),
            (1, 0, 1)
        );
        drop(store);
        assert_eq!(
            (original.get(), replacement.get(), incoming.get()),
            (1, 1, 1)
        );
    }

    #[test]
    fn stale_decision_exceeds_cap_panics() {
        let mut store = RxStore::new();
        let decision = store.decide(0, 2, 2);
        let first = insert(&mut store, 10, b"kl", 3);
        let second = insert(&mut store, 20, b"uv", 3);
        let (frame, incoming) = counted_frame(b"ab");
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            place_attach(&mut store, 0, frame, decision);
        }))
        .unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"stale new decision: view cap")
        );
        assert_eq!(ranges(&store), vec![(10, 12), (20, 22)]);
        assert_eq!(store.views[0].frame.as_ref().unwrap().as_slice(), b"kl");
        assert_eq!(store.views[1].frame.as_ref().unwrap().as_slice(), b"uv");
        assert_eq!((first.get(), second.get(), incoming.get()), (0, 0, 1));
        drop(store);
        assert_eq!((first.get(), second.get(), incoming.get()), (1, 1, 1));
    }

    fn check_oracle(
        store: &RxStore,
        stream: &[u8],
        oracle: &[bool],
        head: usize,
        cap: usize,
        releases: &[Rc<Cell<usize>>],
    ) {
        let contiguous = oracle[head..].iter().take_while(|&&held| held).count();
        assert_eq!(store.in_order_len(), contiguous);
        let total = oracle[head..].iter().filter(|&&held| held).count();
        assert_eq!(store.out_of_order_len(), total.checked_sub(contiguous).unwrap());
        assert!(store.held() <= cap);

        let mut previous_end = 0;
        let mut union: Vec<(usize, usize)> = Vec::new();
        let mut actual = vec![false; stream.len()];
        let mut readable = Vec::new();
        for (view, (start, end)) in store.views.iter().zip(store.ranges()) {
            assert!(start >= previous_end);
            assert!(start < end);
            previous_end = end;
            let absolute_start = head.checked_add(start).unwrap();
            let absolute_end = head.checked_add(end).unwrap();
            let payload = view.frame.as_ref().unwrap().as_slice();
            assert_eq!(payload, &stream[absolute_start..absolute_end]);
            actual[absolute_start..absolute_end].fill(true);
            if start < contiguous {
                readable.extend_from_slice(payload);
            }
            if let Some(last) = union.last_mut() {
                if last.1 == start {
                    last.1 = end;
                    continue;
                }
            }
            union.push((start, end));
        }
        assert_eq!(readable, stream[head..head.checked_add(contiguous).unwrap()]);
        assert_eq!(actual, oracle);
        assert_eq!(store.ranges().count(), store.held());
        let out_of_order: Vec<(usize, usize)> = union
            .iter()
            .filter(|&&(start, _)| start > contiguous)
            .map(|&(start, end)| {
                (
                    start.checked_sub(contiguous).unwrap(),
                    end.checked_sub(contiguous).unwrap(),
                )
            })
            .collect();
        assert_eq!(store.out_of_order_ranges().collect::<Vec<_>>(), out_of_order);
        assert!(releases.iter().all(|count| count.get() <= 1));
        assert_eq!(releases.iter().filter(|count| count.get() == 0).count(), store.held());
    }

    #[test]
    fn randomized_against_byte_oracle() {
        let stream: Vec<u8> = (0..4096).map(|index| (index % 251) as u8).collect();
        let mut new_segments = 0usize;
        let mut appends = 0usize;
        let mut duplicates = 0usize;
        let mut refused_store = 0usize;
        let mut consumes = 0usize;
        for seed in [1, 7, 0x12345678, 0xabcdef01] {
            for cap in [1, 3, 6, 16] {
                let mut rng = StdRng::seed_from_u64(seed);
                let mut store = RxStore::new();
                let mut oracle = vec![false; stream.len()];
                let mut releases = Vec::new();
                let mut head = 0usize;
                for _ in 0..1500 {
                    if rng.gen_ratio(1, 4) {
                        for _ in 0..rng.gen_range(0..=store.held()) {
                            let Some(frame) = store.pop_front() else { break; };
                            let end = head.checked_add(frame.len()).unwrap();
                            assert_eq!(frame.as_slice(), &stream[head..end]);
                            oracle[head..end].fill(false);
                            head = end;
                        }
                        consumes = consumes.checked_add(1).unwrap();
                    } else if head < stream.len() {
                        let remaining = stream.len().checked_sub(head).unwrap();
                        let offset = match rng.gen_range(0..4) {
                            0 => 0,
                            1 => store.in_order_len().min(remaining.checked_sub(1).unwrap()),
                            _ => rng.gen_range(0..remaining.min(96)),
                        };
                        let len =
                            rng.gen_range(1..=remaining.checked_sub(offset).unwrap().min(24));
                        let end = offset.checked_add(len).unwrap();
                        let absolute_start = head.checked_add(offset).unwrap();
                        let absolute_end = head.checked_add(end).unwrap();
                        let room = rng.gen_range(0..=APPEND_MAX);
                        let (frame, count) =
                            counted_frame_with_room(&stream[absolute_start..absolute_end], room);
                        releases.push(count.clone());
                        let before = ranges(&store);
                        let decision = store.decide(offset, len, cap);
                        assert_eq!(ranges(&store), before);
                        assert_eq!(count.get(), 0);
                        if decision == Decision::Refused {
                            refused_store = refused_store.checked_add(1).unwrap();
                            drop(frame);
                            assert_eq!(count.get(), 1);
                        } else {
                            let contiguous = store.in_order_len();
                            if matches!(decision, Decision::Append(_)) {
                                appends = appends.checked_add(1).unwrap();
                                store.append(offset, decision, frame.as_slice());
                                drop(frame);
                                assert_eq!(count.get(), 1);
                            } else if matches!(decision, Decision::Duplicate(_)) {
                                duplicates = duplicates.checked_add(1).unwrap();
                                place_attach(&mut store, offset, frame, decision);
                            } else {
                                new_segments = new_segments.checked_add(1).unwrap();
                                place_attach(&mut store, offset, frame, decision);
                            }
                            oracle[absolute_start..absolute_end].fill(true);
                            assert!(store.in_order_len() >= contiguous);
                        }
                    }
                    check_oracle(&store, &stream, &oracle, head, cap, &releases);
                }
                store.clear();
                oracle.fill(false);
                check_oracle(&store, &stream, &oracle, head, cap, &releases);
                drop(store);
                assert!(releases.iter().all(|count| count.get() == 1));
            }
        }
        assert!(new_segments > 0);
        assert!(appends > 0);
        assert!(duplicates > 0);
        assert!(refused_store > 0);
        assert!(consumes > 0);
    }
}
