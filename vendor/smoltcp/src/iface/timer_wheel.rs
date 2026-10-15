// Derived from the switch project's src/timer_wheel.rs and src/intrusive/, adapted for smoltcp.
//! Intrusive timer wheel driven by caller-supplied absolute u64 ticks.
//! Each of four levels uses one five-bit timestamp digit; the top level wraps.

mod links {
    //! Intrusive link structures and traits.

    /// Sentinel value for "no link".
    pub(crate) const NIL: u32 = u32::MAX;

    /// Intrusive links for list structures.
    ///
    /// For doubly-linked list: uses a (prev), b (next)
    #[derive(Clone, Copy, Debug, Default)]
    #[repr(C)]
    pub(crate) struct IntrusiveLinks {
        pub(crate) a: u32,
        pub(crate) b: u32,
    }

    impl IntrusiveLinks {
        pub(crate) const fn new() -> Self {
            Self {
                a: NIL,
                b: NIL,
            }
        }
    }

    /// Entry that can be linked into intrusive structures.
    pub(crate) trait Linked {
        fn links(&self) -> &IntrusiveLinks;
        fn links_mut(&mut self) -> &mut IntrusiveLinks;
    }

    /// Entry with a deadline for timer structures.
    pub(crate) trait Timed: Linked {
        fn deadline(&self) -> u64;
    }

    /// List-specific accessors.
    pub(crate) trait ListLinked: Linked {
        #[inline]
        fn prev(&self) -> u32 {
            self.links().a
        }

        #[inline]
        fn next(&self) -> u32 {
            self.links().b
        }

        #[inline]
        fn set_prev(&mut self, v: u32) {
            self.links_mut().a = v;
        }

        #[inline]
        fn set_next(&mut self, v: u32) {
            self.links_mut().b = v;
        }
    }

    impl<T: Linked> ListLinked for T {}
}

mod list {
    //! Intrusive doubly-linked list.

    use super::links::{ListLinked, NIL};
    #[cfg(test)]
    use alloc::{vec, vec::Vec};

    /// Head of an intrusive doubly-linked list.
    #[derive(Clone, Copy, Debug, Default)]
    pub(crate) struct ListHead {
        pub(crate) first: u32,
        pub(crate) last: u32,
    }

    impl ListHead {
        pub(crate) const fn new() -> Self {
            Self {
                first: NIL,
                last: NIL,
            }
        }

        #[inline]
        pub(crate) fn is_empty(&self) -> bool {
            self.first == NIL
        }

        /// Push to back. O(1).
        pub(crate) fn push_back<T: ListLinked>(&mut self, entries: &mut [T], idx: u32) {
            debug_assert!(idx != NIL);
            let entry = &mut entries[idx as usize];
            entry.set_prev(self.last);
            entry.set_next(NIL);

            if self.last != NIL {
                entries[self.last as usize].set_next(idx);
            } else {
                self.first = idx;
            }
            self.last = idx;
        }

        /// Remove by index. O(1).
        pub(crate) fn remove<T: ListLinked>(&mut self, entries: &mut [T], idx: u32) {
            debug_assert!(idx != NIL);
            let prev = entries[idx as usize].prev();
            let next = entries[idx as usize].next();

            if prev != NIL {
                entries[prev as usize].set_next(next);
            } else {
                self.first = next;
            }

            if next != NIL {
                entries[next as usize].set_prev(prev);
            } else {
                self.last = prev;
            }

            // Clear links
            entries[idx as usize].set_prev(NIL);
            entries[idx as usize].set_next(NIL);
        }

        /// Pop from front. O(1).
        pub(crate) fn pop_front<T: ListLinked>(&mut self, entries: &mut [T]) -> Option<u32> {
            if self.first == NIL {
                return None;
            }

            let idx = self.first;
            let next = entries[idx as usize].next();

            self.first = next;
            if next != NIL {
                entries[next as usize].set_prev(NIL);
            } else {
                self.last = NIL;
            }

            entries[idx as usize].set_prev(NIL);
            entries[idx as usize].set_next(NIL);

            Some(idx)
        }

        /// Drain all entries, calling f for each.
        pub(crate) fn drain<T: ListLinked, F: FnMut(u32)>(&mut self, entries: &mut [T], mut f: F) {
            while let Some(idx) = self.pop_front(entries) {
                f(idx);
            }
        }

        /// Iterate over all indices (non-mutating).
        pub(crate) fn iter<'a, T: ListLinked>(&self, entries: &'a [T]) -> ListIter<'a, T> {
            ListIter {
                entries,
                current: self.first,
            }
        }
    }

    pub(crate) struct ListIter<'a, T> {
        entries: &'a [T],
        current: u32,
    }

    impl<T: ListLinked> Iterator for ListIter<'_, T> {
        type Item = u32;

        fn next(&mut self) -> Option<Self::Item> {
            if self.current == NIL {
                return None;
            }
            let idx = self.current;
            self.current = self.entries[idx as usize].next();
            Some(idx)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::super::links::{IntrusiveLinks, Linked};
        use super::*;

        #[derive(Default)]
        struct TestEntry {
            links: IntrusiveLinks,
        }

        impl Linked for TestEntry {
            fn links(&self) -> &IntrusiveLinks {
                &self.links
            }
            fn links_mut(&mut self) -> &mut IntrusiveLinks {
                &mut self.links
            }
        }

        fn make_entries(n: usize) -> Vec<TestEntry> {
            (0..n)
                .map(|_| TestEntry {
                    links: IntrusiveLinks::new(),
                })
                .collect()
        }

        #[test]
        fn test_empty_list() {
            let list = ListHead::new();
            assert!(list.is_empty());
        }

        #[test]
        fn test_push_back_single() {
            let mut entries = make_entries(5);
            let mut list = ListHead::new();

            list.push_back(&mut entries, 0);

            assert!(!list.is_empty());
            assert_eq!(list.first, 0);
            assert_eq!(list.last, 0);
        }

        #[test]
        fn test_push_back_multiple() {
            let mut entries = make_entries(5);
            let mut list = ListHead::new();

            list.push_back(&mut entries, 0);
            list.push_back(&mut entries, 1);
            list.push_back(&mut entries, 2);

            assert_eq!(list.first, 0);
            assert_eq!(list.last, 2);

            // Check forward links
            assert_eq!(entries[0].next(), 1);
            assert_eq!(entries[1].next(), 2);
            assert_eq!(entries[2].next(), NIL);

            // Check backward links
            assert_eq!(entries[0].prev(), NIL);
            assert_eq!(entries[1].prev(), 0);
            assert_eq!(entries[2].prev(), 1);
        }

        #[test]
        fn test_pop_front() {
            let mut entries = make_entries(5);
            let mut list = ListHead::new();

            list.push_back(&mut entries, 0);
            list.push_back(&mut entries, 1);
            list.push_back(&mut entries, 2);

            assert_eq!(list.pop_front(&mut entries), Some(0));
            assert_eq!(list.first, 1);
            assert_eq!(entries[1].prev(), NIL);

            assert_eq!(list.pop_front(&mut entries), Some(1));
            assert_eq!(list.pop_front(&mut entries), Some(2));
            assert_eq!(list.pop_front(&mut entries), None);
            assert!(list.is_empty());
        }

        #[test]
        fn test_remove_middle() {
            let mut entries = make_entries(5);
            let mut list = ListHead::new();

            list.push_back(&mut entries, 0);
            list.push_back(&mut entries, 1);
            list.push_back(&mut entries, 2);

            list.remove(&mut entries, 1);

            assert_eq!(list.first, 0);
            assert_eq!(list.last, 2);
            assert_eq!(entries[0].next(), 2);
            assert_eq!(entries[2].prev(), 0);
        }

        #[test]
        fn test_remove_first() {
            let mut entries = make_entries(5);
            let mut list = ListHead::new();

            list.push_back(&mut entries, 0);
            list.push_back(&mut entries, 1);
            list.push_back(&mut entries, 2);

            list.remove(&mut entries, 0);

            assert_eq!(list.first, 1);
            assert_eq!(entries[1].prev(), NIL);
        }

        #[test]
        fn test_remove_last() {
            let mut entries = make_entries(5);
            let mut list = ListHead::new();

            list.push_back(&mut entries, 0);
            list.push_back(&mut entries, 1);
            list.push_back(&mut entries, 2);

            list.remove(&mut entries, 2);

            assert_eq!(list.last, 1);
            assert_eq!(entries[1].next(), NIL);
        }

        #[test]
        fn test_iter() {
            let mut entries = make_entries(5);
            let mut list = ListHead::new();

            list.push_back(&mut entries, 0);
            list.push_back(&mut entries, 2);
            list.push_back(&mut entries, 4);

            let indices: Vec<_> = list.iter(&entries).collect();
            assert_eq!(indices, vec![0, 2, 4]);
        }

        #[test]
        fn test_drain() {
            let mut entries = make_entries(5);
            let mut list = ListHead::new();

            list.push_back(&mut entries, 0);
            list.push_back(&mut entries, 1);
            list.push_back(&mut entries, 2);

            let mut drained = Vec::new();
            list.drain(&mut entries, |idx| drained.push(idx));

            assert_eq!(drained, vec![0, 1, 2]);
            assert!(list.is_empty());
        }
    }
}

#[cfg(test)]
use alloc::vec;
use alloc::vec::Vec;

pub(crate) use links::{IntrusiveLinks, Linked, ListLinked, NIL, Timed};
pub(crate) use list::ListHead;

pub(crate) const DEFAULT_LEVELS: usize = 4;
pub(crate) const DEFAULT_SLOTS: usize = 32;
/// The furthest a deadline may be ahead of the wheel's current tick.
pub(crate) const MAX_DEADLINE_DISTANCE: u64 = (1 << 20) - (1 << 15);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum WheelPosition {
    #[default]
    Unlinked,
    Linked {
        level: u8,
        slot: u8,
    },
}

pub(crate) trait WheelEntry: Timed + ListLinked {
    fn wheel_position(&self) -> WheelPosition;
    fn set_wheel_position(&mut self, position: WheelPosition);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InsertOutcome {
    Due,
    Linked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TimeRegressed {
    pub(crate) current: u64,
    pub(crate) supplied: u64,
}

#[derive(Debug)]
pub(crate) struct TimerWheel {
    levels: [[ListHead; DEFAULT_SLOTS]; DEFAULT_LEVELS],
    pending: [u32; DEFAULT_LEVELS],
    current_tick: u64,
    linked_count: usize,
    #[cfg(test)]
    pub(crate) slot_visits: usize,
}

impl Default for TimerWheel {
    fn default() -> Self {
        Self::new(0)
    }
}

impl TimerWheel {
    pub(crate) const fn new(initial_tick: u64) -> Self {
        Self {
            levels: [[ListHead::new(); DEFAULT_SLOTS]; DEFAULT_LEVELS],
            pending: [0; DEFAULT_LEVELS],
            current_tick: initial_tick,
            linked_count: 0,
            #[cfg(test)]
            slot_visits: 0,
        }
    }

    pub(crate) const fn current_tick(&self) -> u64 {
        self.current_tick
    }

    pub(crate) fn has_pending(&self) -> bool {
        self.linked_count != 0
    }

    pub(crate) fn insert<T: WheelEntry>(&mut self, entries: &mut [T], idx: u32) -> InsertOutcome {
        assert!(idx != NIL, "invalid timer index");
        assert!(
            matches!(
                entries[idx as usize].wheel_position(),
                WheelPosition::Unlinked
            ),
            "timer is already linked"
        );
        let deadline = entries[idx as usize].deadline();
        if deadline <= self.current_tick {
            return InsertOutcome::Due;
        }
        let distance = deadline - self.current_tick;
        assert!(
            distance < MAX_DEADLINE_DISTANCE,
            "deadline tick {deadline}, current tick {}: distance {distance} ms must be below bound {MAX_DEADLINE_DISTANCE} ms",
            self.current_tick
        );
        let (level, slot) = Self::place(self.current_tick, deadline);
        self.link(entries, idx, level, slot);
        self.linked_count += 1;
        InsertOutcome::Linked
    }

    pub(crate) fn remove<T: WheelEntry>(&mut self, entries: &mut [T], idx: u32) -> bool {
        assert!(idx != NIL, "invalid timer index");
        let WheelPosition::Linked { level, slot } = entries[idx as usize].wheel_position() else {
            return false;
        };
        let (level, slot) = (level as usize, slot as usize);
        assert!(
            level < DEFAULT_LEVELS && slot < DEFAULT_SLOTS,
            "invalid wheel position"
        );
        self.levels[level][slot].remove(entries, idx);
        entries[idx as usize].set_wheel_position(WheelPosition::Unlinked);
        self.linked_count -= 1;
        if self.levels[level][slot].is_empty() {
            self.pending[level] &= !(1 << slot);
        }
        true
    }

    pub(crate) fn advance_to<T: WheelEntry>(
        &mut self,
        entries: &mut [T],
        now_tick: u64,
        expired: &mut Vec<u32>,
    ) -> Result<(), TimeRegressed> {
        if now_tick < self.current_tick {
            return Err(TimeRegressed {
                current: self.current_tick,
                supplied: now_tick,
            });
        }
        if now_tick == self.current_tick {
            return Ok(());
        }
        expired.reserve(self.linked_count);
        loop {
            let Some(boundary) = self.next_boundary() else {
                self.current_tick = now_tick;
                return Ok(());
            };
            if boundary > now_tick {
                self.current_tick = now_tick;
                return Ok(());
            }
            self.current_tick = boundary;
            for level in (0..DEFAULT_LEVELS).rev() {
                let shift = 5 * level;
                let width = 1u64 << shift;
                if boundary & (width - 1) != 0 {
                    continue;
                }
                let slot = ((boundary >> shift) & 31) as usize;
                if self.pending[level] & (1 << slot) == 0 {
                    continue;
                }
                let mut detached =
                    core::mem::replace(&mut self.levels[level][slot], ListHead::new());
                self.pending[level] &= !(1 << slot);
                while let Some(idx) = detached.pop_front(entries) {
                    #[cfg(test)]
                    {
                        self.slot_visits += 1;
                    }
                    entries[idx as usize].set_wheel_position(WheelPosition::Unlinked);
                    let deadline = entries[idx as usize].deadline();
                    if deadline <= boundary {
                        assert!(deadline == boundary, "timer passed its deadline");
                        self.linked_count -= 1;
                        expired.push(idx);
                    } else {
                        let (new_level, new_slot) = Self::place(boundary, deadline);
                        assert!(new_level < level, "cascade did not descend");
                        self.link(entries, idx, new_level, new_slot);
                    }
                }
            }
        }
    }

    fn link<T: WheelEntry>(&mut self, entries: &mut [T], idx: u32, level: usize, slot: usize) {
        entries[idx as usize].set_wheel_position(WheelPosition::Linked {
            level: level as u8,
            slot: slot as u8,
        });
        self.levels[level][slot].push_back(entries, idx);
        self.pending[level] |= 1 << slot;
    }

    fn place(current: u64, deadline: u64) -> (usize, usize) {
        let bit = 63 - (current ^ deadline).leading_zeros();
        let level = ((bit / 5) as usize).min(3);
        (level, ((deadline >> (5 * level)) & 31) as usize)
    }

    pub(crate) fn next_boundary(&self) -> Option<u64> {
        let mut next = None;
        for level in 0..DEFAULT_LEVELS {
            let pending = self.pending[level];
            if pending == 0 {
                continue;
            }
            let shift = 5 * level;
            let digit = ((self.current_tick >> shift) & 31) as u32;
            let above = if digit == 31 {
                0
            } else {
                u32::MAX << (digit + 1)
            };
            let boundary = if level == 3 {
                assert!(
                    pending & (1 << digit) == 0,
                    "occupied top-level bucket has current digit"
                );
                let ahead = pending & above;
                let slot = if ahead != 0 {
                    ahead.trailing_zeros()
                } else {
                    pending.trailing_zeros()
                };
                let boundary = ((self.current_tick >> 20) << 20)
                    | (u64::from(slot) << 15);
                if slot < digit {
                    boundary + (1 << 20)
                } else {
                    boundary
                }
            } else {
                assert!(
                    pending & !above == 0,
                    "occupied bucket is not ahead of current time"
                );
                let slot = pending.trailing_zeros();
                let prefix = (self.current_tick >> (shift + 5)) << (shift + 5);
                prefix | (u64::from(slot) << shift)
            };
            assert!(
                boundary > self.current_tick,
                "bucket boundary is not future"
            );
            next = Some(next.map_or(boundary, |previous: u64| previous.min(boundary)));
        }
        next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default, Clone)]
    struct TestTimer {
        links: IntrusiveLinks,
        deadline: u64,
        position: WheelPosition,
    }

    impl Linked for TestTimer {
        fn links(&self) -> &IntrusiveLinks {
            &self.links
        }
        fn links_mut(&mut self) -> &mut IntrusiveLinks {
            &mut self.links
        }
    }

    impl Timed for TestTimer {
        fn deadline(&self) -> u64 {
            self.deadline
        }
    }

    impl WheelEntry for TestTimer {
        fn wheel_position(&self) -> WheelPosition {
            self.position
        }
        fn set_wheel_position(&mut self, position: WheelPosition) {
            self.position = position;
        }
    }

    fn make_timers(deadlines: &[u64]) -> Vec<TestTimer> {
        deadlines
            .iter()
            .map(|&d| TestTimer {
                links: IntrusiveLinks::new(),
                deadline: d,
                position: WheelPosition::Unlinked,
            })
            .collect()
    }

    #[test]
    fn test_empty_wheel() {
        let wheel: TimerWheel = TimerWheel::new(0);
        assert!(!wheel.has_pending());
        assert_eq!(wheel.current_tick(), 0);
    }

    #[test]
    fn test_insert_single() {
        let mut timers = make_timers(&[5]);
        let mut wheel: TimerWheel = TimerWheel::new(0);

        assert_eq!(wheel.insert(&mut timers, 0), InsertOutcome::Linked);

        assert!(wheel.has_pending());
    }

    #[test]
    fn test_expire_single() {
        let mut timers = make_timers(&[3]);
        let mut wheel: TimerWheel = TimerWheel::new(0);

        assert_eq!(wheel.insert(&mut timers, 0), InsertOutcome::Linked);

        let mut expired = Vec::new();
        wheel.advance_to(&mut timers, 5, &mut expired).unwrap();

        assert_eq!(expired, vec![0]);
        assert!(!wheel.has_pending());
    }

    #[test]
    fn test_expire_order() {
        let mut timers = make_timers(&[10, 5, 15, 3, 20]);
        let mut wheel: TimerWheel = TimerWheel::new(0);

        for i in 0..5 {
            assert_eq!(wheel.insert(&mut timers, i), InsertOutcome::Linked);
        }

        let mut expired = Vec::new();
        wheel.advance_to(&mut timers, 25, &mut expired).unwrap();

        // Should expire in deadline order: 3, 5, 10, 15, 20
        let deadlines: Vec<_> = expired
            .iter()
            .map(|&i| timers[i as usize].deadline)
            .collect();
        assert_eq!(deadlines, vec![3, 5, 10, 15, 20]);
    }

    #[test]
    fn test_remove_before_expire() {
        let mut timers = make_timers(&[10, 20]);
        let mut wheel: TimerWheel = TimerWheel::new(0);

        assert_eq!(wheel.insert(&mut timers, 0), InsertOutcome::Linked);
        assert_eq!(wheel.insert(&mut timers, 1), InsertOutcome::Linked);

        // Remove the first one
        wheel.remove(&mut timers, 0);

        let mut expired = Vec::new();
        wheel.advance_to(&mut timers, 25, &mut expired).unwrap();

        assert_eq!(expired, vec![1]);
    }

    #[test]
    fn test_multiple_per_slot() {
        let mut timers = make_timers(&[5, 5, 5]);
        let mut wheel: TimerWheel = TimerWheel::new(0);

        for i in 0..3 {
            assert_eq!(wheel.insert(&mut timers, i), InsertOutcome::Linked);
        }

        let mut expired = Vec::new();
        wheel.advance_to(&mut timers, 10, &mut expired).unwrap();

        assert_eq!(expired.len(), 3);
    }

    #[test]
    fn test_cascade_from_l1() {
        let mut timers = make_timers(&[40]); // Will go to L1 (> 32 ticks away)
        let mut wheel: TimerWheel = TimerWheel::new(0);

        assert_eq!(wheel.insert(&mut timers, 0), InsertOutcome::Linked);

        // Should be in L1
        assert_eq!(
            timers[0].position,
            WheelPosition::Linked { level: 1, slot: 1 }
        );

        let mut expired = Vec::new();
        wheel.advance_to(&mut timers, 45, &mut expired).unwrap();

        assert_eq!(expired, vec![0]);
    }

    #[test]
    fn test_advance_partial() {
        let mut timers = make_timers(&[5, 15, 25]);
        let mut wheel: TimerWheel = TimerWheel::new(0);

        for i in 0..3 {
            assert_eq!(wheel.insert(&mut timers, i), InsertOutcome::Linked);
        }

        let mut expired1 = Vec::new();
        wheel.advance_to(&mut timers, 10, &mut expired1).unwrap();
        assert_eq!(expired1, vec![0]);

        let mut expired2 = Vec::new();
        wheel.advance_to(&mut timers, 20, &mut expired2).unwrap();
        assert_eq!(expired2, vec![1]);

        let mut expired3 = Vec::new();
        wheel.advance_to(&mut timers, 30, &mut expired3).unwrap();
        assert_eq!(expired3, vec![2]);
    }

    #[test]
    fn test_insert_past_deadline() {
        let mut timers = make_timers(&[5]);
        let mut wheel = TimerWheel::new(10);
        let mut expired = Vec::new();
        assert_eq!(wheel.insert(&mut timers, 0), InsertOutcome::Due);
        assert_eq!(timers[0].position, WheelPosition::Unlinked);
        assert!(!wheel.has_pending());
        wheel.advance_to(&mut timers, 11, &mut expired).unwrap();
        assert!(expired.is_empty());
    }

    #[test]
    fn test_large_deadline() {
        let mut timers = make_timers(&[MAX_DEADLINE_DISTANCE - 1]);
        let mut wheel: TimerWheel = TimerWheel::new(0);

        assert_eq!(wheel.insert(&mut timers, 0), InsertOutcome::Linked);

        assert_eq!(
            timers[0].position,
            WheelPosition::Linked { level: 3, slot: 30 }
        );
    }
}

#[cfg(test)]
mod test_entries {
    use super::*;
    pub(crate) struct Entry {
        links: IntrusiveLinks,
        deadline: u64,
        position: WheelPosition,
    }

    impl Linked for Entry {
        fn links(&self) -> &IntrusiveLinks {
            &self.links
        }
        fn links_mut(&mut self) -> &mut IntrusiveLinks {
            &mut self.links
        }
    }

    impl Timed for Entry {
        fn deadline(&self) -> u64 {
            self.deadline
        }
    }

    impl WheelEntry for Entry {
        fn wheel_position(&self) -> WheelPosition {
            self.position
        }
        fn set_wheel_position(&mut self, position: WheelPosition) {
            self.position = position;
        }
    }

    pub(crate) fn entries(deadlines: impl IntoIterator<Item = u64>) -> Vec<Entry> {
        deadlines
            .into_iter()
            .map(|deadline| Entry {
                links: IntrusiveLinks::new(),
                deadline,
                position: WheelPosition::Unlinked,
            })
            .collect()
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::test_entries::{Entry, entries};
    use super::*;

    fn check_future_positions(wheel: &TimerWheel, entries: &[Entry]) {
        let mut linked = 0;
        for entry in entries {
            let WheelPosition::Linked { level, slot } = entry.wheel_position() else {
                continue;
            };
            linked += 1;
            let shift = 5 * usize::from(level);
            assert!(entry.deadline() > wheel.current_tick());
            assert_eq!(u64::from(slot), (entry.deadline() >> shift) & 31);
            let current_digit = (wheel.current_tick() >> shift) & 31;
            if level == 3 {
                assert_ne!(u64::from(slot), current_digit);
                let epoch = wheel.current_tick() >> 20;
                assert_eq!(
                    entry.deadline() >> 20,
                    epoch + u64::from(u64::from(slot) < current_digit)
                );
            } else {
                assert!(u64::from(slot) > current_digit);
                assert_eq!(
                    entry.deadline() >> (shift + 5),
                    wheel.current_tick() >> (shift + 5)
                );
            }
        }
        assert_eq!(wheel.linked_count, linked);
        assert_eq!(wheel.has_pending(), linked != 0);
        assert_eq!(wheel.levels.len(), 4);
    }

    #[test]
    fn four_levels_cover_the_largest_allowed_distance() {
        let deadline = MAX_DEADLINE_DISTANCE - 1;
        let mut entries = entries([deadline]);
        let mut wheel = TimerWheel::new(0);
        assert_eq!(wheel.levels.len(), 4);
        assert_eq!(wheel.insert(&mut entries, 0), InsertOutcome::Linked);
        assert_eq!(entries[0].wheel_position(), WheelPosition::Linked { level: 3, slot: 30 });
        let mut expired = Vec::new();
        wheel.advance_to(&mut entries, deadline - 1, &mut expired).unwrap();
        assert!(expired.is_empty());
        wheel.advance_to(&mut entries, deadline, &mut expired).unwrap();
        assert_eq!(expired, [0]);
        wheel.advance_to(&mut entries, deadline + 1, &mut expired).unwrap();
        assert_eq!(expired, [0]);
        assert!(!wheel.has_pending());
    }

    #[test]
    #[should_panic(expected = "distance 1015808 ms must be below bound 1015808 ms")]
    fn deadline_at_distance_bound_panics() {
        let mut entries = entries([123 + MAX_DEADLINE_DISTANCE]);
        TimerWheel::new(123).insert(&mut entries, 0);
    }

    #[test]
    fn deadlines_crossing_epoch_expire_exactly_once_in_order() {
        let start = (1 << 20) - 3;
        let deadlines = [(1 << 20) + 5, (1 << 20) + (1 << 15), (1 << 21) - (1 << 15) - 4];
        let mut entries = entries(deadlines);
        let mut wheel = TimerWheel::new(start);
        for index in (0..3).rev() {
            assert_eq!(wheel.insert(&mut entries, index), InsertOutcome::Linked);
            assert!(matches!(entries[index as usize].wheel_position(), WheelPosition::Linked { level: 3, .. }));
        }
        let mut expired = Vec::new();
        for (index, deadline) in deadlines.into_iter().enumerate() {
            wheel.advance_to(&mut entries, deadline - 1, &mut expired).unwrap();
            assert_eq!(expired, (0..index as u32).collect::<Vec<_>>());
            wheel.advance_to(&mut entries, deadline, &mut expired).unwrap();
            assert_eq!(expired, (0..=index as u32).collect::<Vec<_>>());
        }
        wheel.advance_to(&mut entries, 1 << 21, &mut expired).unwrap();
        assert_eq!(expired, [0, 1, 2]);
        assert!(!wheel.has_pending());
    }

    #[test]
    fn wrapped_and_nonwrapped_top_buckets_choose_nearest_boundary() {
        let start = 20 << 15;
        let deadlines = [(1 << 20) + 7, (22 << 15) + 9, (21 << 15) + 8];
        let mut entries = entries(deadlines);
        let mut wheel = TimerWheel::new(start);
        for index in 0..3 {
            assert_eq!(wheel.insert(&mut entries, index), InsertOutcome::Linked);
        }
        assert_eq!(entries[0].wheel_position(), WheelPosition::Linked { level: 3, slot: 0 });
        assert_eq!(wheel.next_boundary(), Some(21 << 15));
        let mut expired = Vec::new();
        wheel.advance_to(&mut entries, deadlines[2], &mut expired).unwrap();
        assert_eq!(expired, [2]);
        assert_eq!(wheel.next_boundary(), Some(22 << 15));
        wheel.advance_to(&mut entries, deadlines[1], &mut expired).unwrap();
        assert_eq!(expired, [2, 1]);
        assert_eq!(wheel.next_boundary(), Some(1 << 20));
        wheel.advance_to(&mut entries, deadlines[0], &mut expired).unwrap();
        assert_eq!(expired, [2, 1, 0]);
        assert!(!wheel.has_pending());
    }

    #[test]
    fn former_late_boundaries_expire_exactly() {
        let mut entries = entries([64, 65, 1024, 1025]);
        let mut wheel = TimerWheel::new(0);
        for index in 0..4 {
            assert_eq!(wheel.insert(&mut entries, index), InsertOutcome::Linked);
        }
        let mut expired = Vec::new();
        for (tick, expected) in [(63, 0), (64, 1), (65, 2), (1023, 2), (1024, 3), (1025, 4)] {
            wheel.advance_to(&mut entries, tick, &mut expired).unwrap();
            assert_eq!(expired, (0..expected).collect::<Vec<u32>>());
            check_future_positions(&wheel, &entries);
        }
    }

    #[test]
    fn equal_and_backward_time_leave_everything_untouched() {
        let mut entries = entries([101]);
        let mut wheel = TimerWheel::new(100);
        assert_eq!(wheel.insert(&mut entries, 0), InsertOutcome::Linked);
        let mut expired = Vec::with_capacity(1);
        expired.push(77);
        let capacity = expired.capacity();
        let pending = wheel.pending;
        let heads = wheel
            .levels
            .map(|buckets| buckets.map(|head| (head.first, head.last)));
        let position = entries[0].wheel_position();
        assert_eq!(
            wheel.advance_to(&mut entries, 99, &mut expired),
            Err(TimeRegressed {
                current: 100,
                supplied: 99
            })
        );
        wheel.advance_to(&mut entries, 100, &mut expired).unwrap();
        assert_eq!(wheel.current_tick(), 100);
        assert_eq!(wheel.pending, pending);
        assert_eq!(
            wheel
                .levels
                .map(|buckets| buckets.map(|head| (head.first, head.last))),
            heads
        );
        assert_eq!(entries[0].wheel_position(), position);
        assert_eq!(entries[0].prev(), NIL);
        assert_eq!(entries[0].next(), NIL);
        assert_eq!(expired, [77]);
        assert_eq!(expired.capacity(), capacity);
        check_future_positions(&wheel, &entries);
        wheel.advance_to(&mut entries, 101, &mut expired).unwrap();
        assert_eq!(expired, [77, 0]);
    }

    #[test]
    fn due_insertions_complete_without_linking_at_nonzero_start_and_max() {
        for start in [MAX_DEADLINE_DISTANCE + 100, u64::MAX] {
            let deadlines = if start == u64::MAX {
                vec![start - 1, start]
            } else {
                vec![0, start, start + 1]
            };
            let mut entries = entries(deadlines);
            let mut wheel = TimerWheel::new(start);
            let mut completed = Vec::new();
            for index in 0..entries.len() {
                match wheel.insert(&mut entries, index as u32) {
                    InsertOutcome::Due => completed.push(index as u32),
                    InsertOutcome::Linked => {
                        assert_eq!(Some(entries[index].deadline()), start.checked_add(1))
                    }
                }
            }
            assert_eq!(completed, [0, 1]);
            for &index in &completed {
                assert_eq!(
                    entries[index as usize].wheel_position(),
                    WheelPosition::Unlinked
                );
                assert_eq!(entries[index as usize].prev(), NIL);
                assert_eq!(entries[index as usize].next(), NIL);
            }
            check_future_positions(&wheel, &entries);
            let mut expired = Vec::new();
            let now = if start == u64::MAX { start } else { start + 1 };
            wheel.advance_to(&mut entries, now, &mut expired).unwrap();
            assert_eq!(expired, if start == u64::MAX { vec![] } else { vec![2] });
        }
    }

    #[test]
    fn every_five_bit_transition_preserves_exact_expiry_and_future_positions() {
        for level in 0..13 {
            let boundary = 1u64 << (5 * level);
            for start in [boundary - 1, boundary, boundary + 1] {
                let deadlines = [start + 1, start + 2];
                let mut entries = entries(deadlines);
                let mut wheel = TimerWheel::new(start);
                for index in 0..2 {
                    assert_eq!(wheel.insert(&mut entries, index), InsertOutcome::Linked);
                }
                if start == boundary - 1 {
                    assert_eq!(
                        entries[0].wheel_position(),
                        WheelPosition::Linked {
                            level: level.min(3) as u8,
                            slot: if level < 4 { 1 } else { 0 },
                        }
                    );
                }
                check_future_positions(&wheel, &entries);
                let mut expired = Vec::new();
                wheel.advance_to(&mut entries, start, &mut expired).unwrap();
                assert!(expired.is_empty());
                wheel
                    .advance_to(&mut entries, deadlines[0], &mut expired)
                    .unwrap();
                assert_eq!(expired, [0]);
                check_future_positions(&wheel, &entries);
                wheel
                    .advance_to(&mut entries, deadlines[1], &mut expired)
                    .unwrap();
                assert_eq!(expired, [0, 1]);
                check_future_positions(&wheel, &entries);
            }
        }
    }

    #[test]
    fn all_thirty_two_top_digits_are_supported() {
        for digit in 0..32u64 {
            let boundary = (1 << 20) | (digit << 15);
            let start = boundary - 1;
            let deadline = boundary;
            let mut entries = entries([deadline]);
            let mut wheel = TimerWheel::new(start);
            assert_eq!(wheel.insert(&mut entries, 0), InsertOutcome::Linked);
            assert_eq!(
                entries[0].wheel_position(),
                WheelPosition::Linked {
                    level: 3,
                    slot: digit as u8
                }
            );
            check_future_positions(&wheel, &entries);
            let mut expired = Vec::new();
            wheel
                .advance_to(&mut entries, deadline - 1, &mut expired)
                .unwrap();
            assert!(expired.is_empty());
            wheel
                .advance_to(&mut entries, deadline, &mut expired)
                .unwrap();
            assert_eq!(expired, [0]);
            check_future_positions(&wheel, &entries);
        }
    }

    #[test]
    fn arbitrary_starts_and_max_neighbor_use_absolute_deadlines() {
        for (start, deadlines) in [
            (1, [33, 1025]),
            (31, [32, 64]),
            ((1 << 40) - 1, [1 << 40, (1 << 40) + MAX_DEADLINE_DISTANCE - 2]),
            (u64::MAX - MAX_DEADLINE_DISTANCE + 1, [u64::MAX - 1, u64::MAX]),
            (u64::MAX - 1, [u64::MAX, u64::MAX]),
        ] {
            let mut entries = entries(deadlines);
            let mut wheel = TimerWheel::new(start);
            for index in 0..2 {
                assert_eq!(wheel.insert(&mut entries, index), InsertOutcome::Linked);
            }
            check_future_positions(&wheel, &entries);
            let mut expired = Vec::new();
            wheel
                .advance_to(&mut entries, deadlines[0] - 1, &mut expired)
                .unwrap();
            assert!(expired.is_empty());
            wheel
                .advance_to(&mut entries, deadlines[0], &mut expired)
                .unwrap();
            assert_eq!(
                expired.len(),
                if deadlines[0] == deadlines[1] { 2 } else { 1 }
            );
            check_future_positions(&wheel, &entries);
            wheel
                .advance_to(&mut entries, deadlines[1], &mut expired)
                .unwrap();
            assert_eq!(expired, [0, 1]);
            check_future_positions(&wheel, &entries);
        }
    }

    struct CountedEntry {
        links: IntrusiveLinks,
        position: WheelPosition,
        dispositions: usize,
    }

    impl Linked for CountedEntry {
        fn links(&self) -> &IntrusiveLinks {
            &self.links
        }
        fn links_mut(&mut self) -> &mut IntrusiveLinks {
            &mut self.links
        }
    }
    impl Timed for CountedEntry {
        fn deadline(&self) -> u64 {
            MAX_DEADLINE_DISTANCE - 1
        }
    }
    impl WheelEntry for CountedEntry {
        fn wheel_position(&self) -> WheelPosition {
            self.position
        }
        fn set_wheel_position(&mut self, position: WheelPosition) {
            if position == WheelPosition::Unlinked {
                self.dispositions += 1;
            }
            self.position = position;
        }
    }

    #[test]
    fn single_bound_neighbor_needs_at_most_four_dispositions() {
        let mut entries = [CountedEntry {
            links: IntrusiveLinks::new(),
            position: WheelPosition::Unlinked,
            dispositions: 0,
        }];
        let mut wheel = TimerWheel::new(0);
        assert_eq!(wheel.insert(&mut entries, 0), InsertOutcome::Linked);
        let mut expired = Vec::new();
        wheel
            .advance_to(&mut entries, MAX_DEADLINE_DISTANCE - 1, &mut expired)
            .unwrap();
        assert_eq!(expired, [0]);
        assert!((1..=4).contains(&entries[0].dispositions));
        assert_eq!(entries[0].wheel_position(), WheelPosition::Unlinked);
        assert!(!wheel.has_pending());
    }

    #[test]
    fn empty_max_jump_has_no_bucket_to_process() {
        let mut wheel = TimerWheel::new(0);
        let mut entries: Vec<Entry> = Vec::new();
        let mut expired = Vec::new();
        assert_eq!(wheel.next_boundary(), None);
        wheel
            .advance_to(&mut entries, u64::MAX, &mut expired)
            .unwrap();
        assert_eq!(wheel.current_tick(), u64::MAX);
        assert_eq!(wheel.next_boundary(), None);
        assert!(wheel.levels.iter().flatten().all(ListHead::is_empty));
        assert_eq!(wheel.slot_visits, 0);
        assert!(expired.is_empty());
    }
}

#[cfg(test)]
mod membership_tests {
    use super::test_entries::{Entry, entries};
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn check_structure(wheel: &TimerWheel, entries: &[Entry]) {
        let mut seen = vec![false; entries.len()];
        for (level, buckets) in wheel.levels.iter().enumerate() {
            let mut pending = 0;
            for (slot, bucket) in buckets.iter().enumerate() {
                let mut previous = NIL;
                let mut index = bucket.first;
                while index != NIL {
                    let entry = &entries[index as usize];
                    assert!(!seen[index as usize], "duplicate list membership");
                    seen[index as usize] = true;
                    assert_eq!(entry.prev(), previous);
                    assert_eq!(
                        entry.wheel_position(),
                        WheelPosition::Linked {
                            level: level as u8,
                            slot: slot as u8,
                        }
                    );
                    previous = index;
                    index = entry.next();
                }
                assert_eq!(bucket.last, previous);
                if bucket.first != NIL {
                    pending |= 1 << slot;
                }
            }
            assert_eq!(wheel.pending[level], pending);
        }
        assert_eq!(
            seen.iter().filter(|&&linked| linked).count(),
            wheel.linked_count
        );
        for (index, entry) in entries.iter().enumerate() {
            assert_eq!(
                seen[index],
                entry.wheel_position() != WheelPosition::Unlinked
            );
            if !seen[index] {
                assert_eq!(entry.prev(), NIL);
                assert_eq!(entry.next(), NIL);
            }
        }
    }

    fn state(
        wheel: &TimerWheel,
        entries: &[Entry],
    ) -> (
        Vec<(u32, u32)>,
        Vec<(WheelPosition, u32, u32)>,
        Vec<u32>,
        u64,
        usize,
    ) {
        (
            wheel
                .levels
                .iter()
                .flatten()
                .map(|bucket| (bucket.first, bucket.last))
                .collect(),
            entries
                .iter()
                .map(|entry| (entry.wheel_position(), entry.prev(), entry.next()))
                .collect(),
            wheel.pending.to_vec(),
            wheel.current_tick(),
            wheel.linked_count,
        )
    }

    #[test]
    fn never_inserted_cancel_preserves_occupied_bucket() {
        let mut entries = entries([0, 32]);
        let mut wheel = TimerWheel::new(0);
        assert_eq!(wheel.insert(&mut entries, 1), InsertOutcome::Linked);
        let before = state(&wheel, &entries);
        assert!(!wheel.remove(&mut entries, 0));
        assert_eq!(state(&wheel, &entries), before);
        check_structure(&wheel, &entries);
        let mut expired = Vec::new();
        wheel.advance_to(&mut entries, 32, &mut expired).unwrap();
        assert_eq!(expired, [1]);
        check_structure(&wheel, &entries);
    }

    #[test]
    fn cancel_twice_preserves_shared_bucket_survivor() {
        let mut entries = entries([5, 5]);
        let mut wheel = TimerWheel::new(0);
        assert_eq!(wheel.insert(&mut entries, 0), InsertOutcome::Linked);
        assert_eq!(wheel.insert(&mut entries, 1), InsertOutcome::Linked);
        assert!(wheel.remove(&mut entries, 0));
        let before = state(&wheel, &entries);
        assert!(!wheel.remove(&mut entries, 0));
        assert_eq!(state(&wheel, &entries), before);
        check_structure(&wheel, &entries);
        let mut expired = Vec::new();
        wheel.advance_to(&mut entries, 5, &mut expired).unwrap();
        assert_eq!(expired, [1]);
        check_structure(&wheel, &entries);
    }

    #[test]
    fn expired_cancel_preserves_another_timer_in_reused_bucket() {
        let mut entries = entries([3, 35]);
        let mut wheel = TimerWheel::new(0);
        assert_eq!(wheel.insert(&mut entries, 0), InsertOutcome::Linked);
        let mut expired = Vec::new();
        wheel.advance_to(&mut entries, 3, &mut expired).unwrap();
        assert_eq!(expired, [0]);
        assert_eq!(entries[0].wheel_position(), WheelPosition::Unlinked);
        wheel.advance_to(&mut entries, 32, &mut expired).unwrap();
        assert_eq!(wheel.insert(&mut entries, 1), InsertOutcome::Linked);
        assert_eq!(
            entries[1].wheel_position(),
            WheelPosition::Linked { level: 0, slot: 3 }
        );
        let before = state(&wheel, &entries);
        assert!(!wheel.remove(&mut entries, 0));
        assert_eq!(state(&wheel, &entries), before);
        check_structure(&wheel, &entries);
        wheel.advance_to(&mut entries, 35, &mut expired).unwrap();
        assert_eq!(expired, [0, 1]);
        check_structure(&wheel, &entries);
    }

    #[test]
    fn linked_singleton_has_nil_links_and_remains_removable() {
        let mut entries = entries([5]);
        let mut wheel = TimerWheel::new(0);
        assert_eq!(wheel.insert(&mut entries, 0), InsertOutcome::Linked);
        assert_eq!(entries[0].prev(), NIL);
        assert_eq!(entries[0].next(), NIL);
        assert_eq!(
            entries[0].wheel_position(),
            WheelPosition::Linked { level: 0, slot: 5 }
        );
        check_structure(&wheel, &entries);
        assert!(wheel.remove(&mut entries, 0));
        assert_eq!(entries[0].wheel_position(), WheelPosition::Unlinked);
        assert!(!wheel.has_pending());
        check_structure(&wheel, &entries);
    }

    #[test]
    fn duplicate_insert_panics_before_any_mutation() {
        let mut entries = entries([5, 5]);
        let mut wheel = TimerWheel::new(0);
        assert_eq!(wheel.insert(&mut entries, 0), InsertOutcome::Linked);
        assert_eq!(wheel.insert(&mut entries, 1), InsertOutcome::Linked);
        let before = state(&wheel, &entries);
        assert!(catch_unwind(AssertUnwindSafe(|| wheel.insert(&mut entries, 0))).is_err());
        assert_eq!(state(&wheel, &entries), before);
        check_structure(&wheel, &entries);
        let mut expired = Vec::new();
        wheel.advance_to(&mut entries, 5, &mut expired).unwrap();
        assert_eq!(expired, [0, 1]);
        check_structure(&wheel, &entries);
    }

    #[test]
    fn formerly_overflowing_pair_expires_exactly_once() {
        let mut entries = entries([2097152, 2097152]);
        let mut wheel = TimerWheel::new(2097152 - MAX_DEADLINE_DISTANCE + 1);
        assert_eq!(wheel.insert(&mut entries, 0), InsertOutcome::Linked);
        assert_eq!(wheel.insert(&mut entries, 1), InsertOutcome::Linked);
        let mut expired = Vec::new();
        wheel
            .advance_to(&mut entries, 2097151, &mut expired)
            .unwrap();
        assert!(expired.is_empty());
        check_structure(&wheel, &entries);
        wheel
            .advance_to(&mut entries, 2097152, &mut expired)
            .unwrap();
        assert_eq!(expired, [0, 1]);
        assert!(!wheel.remove(&mut entries, 0));
        assert!(!wheel.remove(&mut entries, 1));
        wheel
            .advance_to(&mut entries, 2097153, &mut expired)
            .unwrap();
        assert_eq!(expired, [0, 1]);
        assert!(!wheel.has_pending());
        check_structure(&wheel, &entries);
    }
}

#[cfg(test)]
mod model_tests {
    use super::*;

    struct Entry {
        links: IntrusiveLinks,
        deadline: u64,
        position: WheelPosition,
    }

    impl Linked for Entry {
        fn links(&self) -> &IntrusiveLinks {
            &self.links
        }
        fn links_mut(&mut self) -> &mut IntrusiveLinks {
            &mut self.links
        }
    }

    impl Timed for Entry {
        fn deadline(&self) -> u64 {
            self.deadline
        }
    }

    impl WheelEntry for Entry {
        fn wheel_position(&self) -> WheelPosition {
            self.position
        }
        fn set_wheel_position(&mut self, position: WheelPosition) {
            self.position = position;
        }
    }

    fn entries(count: usize) -> Vec<Entry> {
        (0..count)
            .map(|_| Entry {
                links: IntrusiveLinks::new(),
                deadline: 0,
                position: WheelPosition::Unlinked,
            })
            .collect()
    }

    fn random(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn deadline(state: &mut u64, now: u64) -> u64 {
        match random(state) % 4 {
            0 => now,
            1 => now.saturating_add(1 + random(state) % 4096),
            2 => now.saturating_add(random(state) % MAX_DEADLINE_DISTANCE),
            _ => {
                let power = 1u64 << (random(state) % 20);
                let distance = if random(state) & 1 == 0 {
                    power - 1
                } else {
                    power + 1
                };
                now.saturating_add(distance)
            }
        }
    }

    fn check(wheel: &TimerWheel, entries: &[Entry], live: &[Option<u64>], now: u64) {
        assert_eq!(wheel.current_tick(), now);
        let count = live.iter().filter(|deadline| deadline.is_some()).count();
        assert_eq!(wheel.linked_count, count);
        assert_eq!(wheel.has_pending(), count != 0);

        let mut seen = vec![false; entries.len()];
        for (level, buckets) in wheel.levels.iter().enumerate() {
            let mut pending = 0;
            for (slot, bucket) in buckets.iter().enumerate() {
                let mut previous = NIL;
                let mut index = bucket.first;
                while index != NIL {
                    let i = index as usize;
                    assert!(i < entries.len());
                    assert!(!seen[i]);
                    seen[i] = true;
                    assert_eq!(entries[i].prev(), previous);
                    assert_eq!(
                        entries[i].wheel_position(),
                        WheelPosition::Linked {
                            level: level as u8,
                            slot: slot as u8,
                        }
                    );
                    previous = index;
                    index = entries[i].next();
                }
                assert_eq!(bucket.last, previous);
                if bucket.first != NIL {
                    pending |= 1 << slot;
                }
            }
            assert_eq!(wheel.pending[level], pending);
        }
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(seen[i], live[i].is_some());
            if !seen[i] {
                assert_eq!(entry.wheel_position(), WheelPosition::Unlinked);
                assert_eq!(entry.prev(), NIL);
                assert_eq!(entry.next(), NIL);
            }
        }
    }

    fn insert(
        wheel: &mut TimerWheel,
        entries: &mut [Entry],
        live: &mut [Option<u64>],
        now: u64,
        index: usize,
    ) {
        assert!(live[index].is_none());
        assert_eq!(entries[index].wheel_position(), WheelPosition::Unlinked);
        let deadline = entries[index].deadline;
        let result = wheel.insert(entries, index as u32);
        if deadline <= now {
            assert_eq!(result, InsertOutcome::Due);
        } else {
            assert_eq!(result, InsertOutcome::Linked);
            live[index] = Some(deadline);
        }
        check(wheel, entries, live, now);
    }

    fn advance(
        wheel: &mut TimerWheel,
        entries: &mut [Entry],
        live: &mut [Option<u64>],
        now: &mut u64,
        supplied: u64,
    ) -> Vec<u32> {
        if supplied < *now {
            let before = live.to_vec();
            let mut output = vec![u32::MAX - 1];
            let before_output = output.clone();
            assert_eq!(
                wheel.advance_to(entries, supplied, &mut output),
                Err(TimeRegressed {
                    current: *now,
                    supplied,
                })
            );
            assert_eq!(output, before_output);
            assert_eq!(live, before.as_slice());
            check(wheel, entries, live, *now);
            return Vec::new();
        }

        let mut expected: Vec<u32> = live
            .iter()
            .enumerate()
            .filter_map(|(i, deadline)| {
                deadline
                    .filter(|deadline| *deadline <= supplied)
                    .map(|_| i as u32)
            })
            .collect();
        let mut actual = Vec::new();
        assert_eq!(wheel.advance_to(entries, supplied, &mut actual), Ok(()));
        expected.sort_unstable();
        actual.sort_unstable();
        assert_eq!(actual, expected);
        for index in expected {
            live[index as usize] = None;
        }
        *now = supplied;
        check(wheel, entries, live, *now);
        actual
    }

    fn run(initial: u64, seed: u64) {
        const BOUNDARIES: [u64; 12] = [
            0,
            1,
            31,
            32,
            1023,
            1024,
            32767,
            32768,
            65535,
            65536,
            MAX_DEADLINE_DISTANCE - 2,
            MAX_DEADLINE_DISTANCE - 1,
        ];
        let mut deadlines: Vec<_> = BOUNDARIES
            .into_iter()
            .map(|distance| initial.saturating_add(distance))
            .collect();
        deadlines.extend([
            initial.saturating_sub(1),
            initial,
            initial.saturating_add(1),
        ]);
        deadlines.sort_unstable();
        deadlines.dedup();

        let mut wheel = TimerWheel::new(initial);
        let mut entries = entries(64);
        let mut live = vec![None; entries.len()];
        let mut now = initial;
        let mut rng = seed;
        for (i, value) in deadlines.iter().copied().enumerate() {
            entries[i].deadline = value;
            insert(&mut wheel, &mut entries, &mut live, now, i);
        }

        let reused = deadlines.len();
        entries[reused].deadline = now.checked_add(1).expect("start is below MAX");
        insert(&mut wheel, &mut entries, &mut live, now, reused);
        assert!(wheel.remove(&mut entries, reused as u32));
        live[reused] = None;
        check(&wheel, &entries, &live, now);
        assert!(!wheel.remove(&mut entries, reused as u32));
        check(&wheel, &entries, &live, now);
        entries[reused].deadline = now.checked_add(2).expect("start is below MAX");
        insert(&mut wheel, &mut entries, &mut live, now, reused);

        for _ in 0..768 {
            let choice = random(&mut rng) % 7;
            let i = random(&mut rng) as usize % entries.len();
            match choice {
                0 | 1 if live[i].is_none() => {
                    entries[i].deadline = deadline(&mut rng, now);
                    insert(&mut wheel, &mut entries, &mut live, now, i);
                }
                2 => {
                    assert_eq!(wheel.remove(&mut entries, i as u32), live[i].is_some());
                    live[i] = None;
                    check(&wheel, &entries, &live, now);
                }
                3 if live[i].is_none() => {
                    assert_eq!(entries[i].wheel_position(), WheelPosition::Unlinked);
                    entries[i].deadline = deadline(&mut rng, now);
                }
                4 => {
                    let supplied = now;
                    advance(&mut wheel, &mut entries, &mut live, &mut now, supplied);
                }
                5 if now > 0 => {
                    let supplied = now - 1;
                    advance(&mut wheel, &mut entries, &mut live, &mut now, supplied);
                }
                _ => {
                    let target = now
                        .saturating_add(1 + random(&mut rng) % 4096)
                        .min(u64::MAX - 1);
                    advance(&mut wheel, &mut entries, &mut live, &mut now, target);
                }
            }
            check(&wheel, &entries, &live, now);
        }

        let first_boundary = now;
        for target in deadlines
            .into_iter()
            .filter(|target| *target >= first_boundary)
        {
            let expired = advance(&mut wheel, &mut entries, &mut live, &mut now, target);
            for i in expired {
                let i = i as usize;
                if now < u64::MAX {
                    entries[i].deadline = now.checked_add(1).expect("now is below MAX");
                    insert(&mut wheel, &mut entries, &mut live, now, i);
                }
            }
            check(&wheel, &entries, &live, now);
        }
        advance(&mut wheel, &mut entries, &mut live, &mut now, u64::MAX);
    }

    #[test]
    fn seeded_timer_wheel_matches_independent_deadline_scan() {
        for initial in [0, 31, (1 << 20) - 3, (1 << 40) - 3, u64::MAX - (1 << 21)] {
            for seed in [0x5eed, 0xc0ffee, 0x7f4a_7c15_9e37_79b9] {
                run(initial, seed);
            }
        }
    }
}
