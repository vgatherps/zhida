#![allow(unsafe_code)]

use core::{fmt, ops::Range, ptr::NonNull, slice};

use alloc::{boxed::Box, vec::Vec};

/// An owned receive frame with a storage release callback.
pub struct RxBuf {
    data: NonNull<u8>,
    len: usize,
    room: usize,
    rx_timestamp: u64,
    owner: NonNull<()>,
    release: unsafe fn(NonNull<()>),
}

impl RxBuf {
    /// Take ownership of a frame and its storage.
    ///
    /// # Safety
    /// `data..data + len + room` must be valid for reads and writes and owned exclusively
    /// by this value until `release(owner)` runs. The range must fit within one
    /// allocation and `len + room` must not exceed `isize::MAX`.
    /// `owner` must be valid for `release`, which must release the storage.
    /// `release` is called exactly once, from `Drop`, on the thread that owns
    /// this value.
    pub unsafe fn from_raw_parts(
        owner: NonNull<()>,
        release: unsafe fn(NonNull<()>),
        data: NonNull<u8>,
        len: usize,
        room: usize,
    ) -> Self {
        Self {
            data,
            len,
            room,
            rx_timestamp: 0,
            owner,
            release,
        }
    }

    /// Take ownership of a vector without copying its bytes.
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        unsafe fn release_vec(owner: NonNull<()>) {
            // SAFETY: from_vec transfers a Box<Vec<u8>> to this callback.
            unsafe { drop(Box::from_raw(owner.cast::<Vec<u8>>().as_ptr())) };
        }

        let bytes = Box::leak(Box::new(bytes));
        let len = bytes.len();
        let data = NonNull::new(bytes.as_mut_ptr()).unwrap();
        let owner = NonNull::from(bytes).cast();
        // SAFETY: the vector owns these bytes exclusively, including when empty.
        // The callback drops its box and vector once on this value's owner thread.
        unsafe { Self::from_raw_parts(owner, release_vec, data, len, 0) }
    }

    /// Raw value from the NIC driver; 0 means no hardware stamp.
    pub fn rx_timestamp(&self) -> u64 {
        self.rx_timestamp
    }

    /// Set the raw value from the NIC driver; 0 means no hardware stamp.
    pub fn set_rx_timestamp(&mut self, stamp: u64) {
        self.rx_timestamp = stamp;
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: the constructor requires this range to remain valid until drop.
        unsafe { slice::from_raw_parts(self.data.as_ptr(), self.len) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: the constructor requires exclusive ownership of this range,
        // and the mutable borrow prevents other views while this slice is live.
        unsafe { slice::from_raw_parts_mut(self.data.as_ptr(), self.len) }
    }

    /// Keep only the given range of the current view.
    /// Panics without changing the view if the range is out of bounds.
    pub(crate) fn narrow(&mut self, range: Range<usize>) {
        let len = self.as_slice()[range.clone()].len();
        let room = self
            .room
            .checked_add(self.len.checked_sub(range.end).expect("range exceeds frame"))
            .expect("frame room exceeds usize");
        // SAFETY: the slice index above checked range.start <= self.len. The pointer
        // keeps the constructor's provenance, which covers the room after the view.
        self.data = unsafe { self.data.add(range.start) };
        self.len = len;
        self.room = room;
    }

    pub(crate) fn room(&self) -> usize {
        self.room
    }

    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) {
        assert!(bytes.len() <= self.room, "extend exceeds frame room");
        let len = self
            .len
            .checked_add(bytes.len())
            .expect("frame length exceeds usize");
        let room = self
            .room
            .checked_sub(bytes.len())
            .expect("extend exceeds frame room");
        // SAFETY: the constructor gives this value exclusive writable tailroom.
        // The assert keeps the copy within it, and the borrow keeps bytes separate.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.data.as_ptr().add(self.len),
                bytes.len(),
            );
        }
        self.len = len;
        self.room = room;
    }

    #[cfg(test)]
    pub(crate) fn counted_frame(
        mut bytes: Vec<u8>,
        room: usize,
        releases: alloc::rc::Rc<core::cell::Cell<usize>>,
    ) -> Self {
        struct Storage {
            bytes: Vec<u8>,
            releases: alloc::rc::Rc<core::cell::Cell<usize>>,
        }

        unsafe fn release_storage(owner: NonNull<()>) {
            // SAFETY: counted_frame transfers a Box<Storage> to this callback.
            let storage = unsafe { Box::from_raw(owner.cast::<Storage>().as_ptr()) };
            storage.releases.set(
                storage
                    .releases
                    .get()
                    .checked_add(1)
                    .expect("release count exceeds usize"),
            );
        }

        let len = bytes.len();
        bytes.resize(
            len.checked_add(room).expect("frame storage exceeds usize"),
            0,
        );
        let storage = Box::leak(Box::new(Storage { bytes, releases }));
        let data = NonNull::new(storage.bytes.as_mut_ptr()).unwrap();
        let owner = NonNull::from(storage).cast();
        // SAFETY: the box owns the bytes exclusively and the callback drops it once.
        unsafe { Self::from_raw_parts(owner, release_storage, data, len, room) }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for RxBuf {
    fn drop(&mut self) {
        // SAFETY: the constructor transfers ownership to this value and requires
        // owner to be valid for release. This is the only call to release.
        unsafe { (self.release)(self.owner) };
    }
}

impl fmt::Debug for RxBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RxBuf")
            .field("len", &self.len)
            .field("room", &self.room)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use core::cell::Cell;

    struct Storage {
        bytes: [u8; 6],
        releases: Rc<Cell<usize>>,
    }

    impl Drop for Storage {
        fn drop(&mut self) {
            self.releases
                .set(self.releases.get().checked_add(1).unwrap());
        }
    }

    unsafe fn release_storage(owner: NonNull<()>) {
        // SAFETY: owned_frame transfers a Box<Storage> to this callback.
        unsafe { drop(Box::from_raw(owner.cast::<Storage>().as_ptr())) };
    }

    #[test]
    fn rx_timestamp_absent_by_default() {
        assert_eq!(RxBuf::from_vec(alloc::vec![1, 2]).rx_timestamp(), 0);
        let frame = RxBuf::counted_frame(alloc::vec![1, 2], 2, Rc::new(Cell::new(0)));
        assert_eq!(frame.rx_timestamp(), 0);
        let (frame, _, _) = owned_frame(4);
        assert_eq!(frame.rx_timestamp(), 0);
    }

    #[test]
    fn rx_timestamp_kept_through_narrow_and_extend() {
        let mut frame = RxBuf::counted_frame(alloc::vec![1, 2, 3], 2, Rc::new(Cell::new(0)));
        frame.set_rx_timestamp(7);
        frame.narrow(1..2);
        assert_eq!(frame.rx_timestamp(), 7);
        frame.extend_from_slice(&[4, 5]);
        assert_eq!(frame.as_slice(), &[2, 4, 5]);
        assert_eq!(frame.rx_timestamp(), 7);
    }

    #[test]
    fn extend_reads_back_old_and_new_bytes() {
        let releases = Rc::new(Cell::new(0));
        let mut frame = RxBuf::counted_frame(alloc::vec![1, 2], 4, releases);
        frame.extend_from_slice(&[3, 4, 5]);
        assert_eq!(frame.as_slice(), &[1, 2, 3, 4, 5]);
        assert_eq!(frame.len(), 5);
        assert_eq!(frame.room(), 1);
    }

    #[test]
    fn extend_exact_room_then_panic_leaves_frame_unchanged() {
        let releases = Rc::new(Cell::new(0));
        let mut frame = RxBuf::counted_frame(alloc::vec![1, 2], 2, releases.clone());
        frame.extend_from_slice(&[3, 4]);
        let data = frame.as_slice().as_ptr();
        assert_eq!(frame.room(), 0);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                frame.extend_from_slice(&[5]);
            }))
            .is_err()
        );
        assert_eq!(frame.as_slice().as_ptr(), data);
        assert_eq!(frame.as_slice(), &[1, 2, 3, 4]);
        assert_eq!(frame.len(), 4);
        assert_eq!(frame.room(), 0);
        assert_eq!(releases.get(), 0);
    }

    #[test]
    fn narrow_tail_adds_room_for_extend() {
        let releases = Rc::new(Cell::new(0));
        let mut frame = RxBuf::counted_frame(alloc::vec![1, 2, 3, 4], 2, releases);
        frame.narrow(1..2);
        assert_eq!(frame.room(), 4);
        frame.extend_from_slice(&[5, 6, 7, 8]);
        assert_eq!(frame.as_slice(), &[2, 5, 6, 7, 8]);
        assert_eq!(frame.room(), 0);
    }

    #[test]
    fn narrow_head_keeps_room() {
        let releases = Rc::new(Cell::new(0));
        let mut frame = RxBuf::counted_frame(alloc::vec![1, 2, 3, 4], 2, releases);
        frame.narrow(2..4);
        assert_eq!(frame.as_slice(), &[3, 4]);
        assert_eq!(frame.room(), 2);
    }

    #[test]
    fn release_runs_once_after_extends() {
        let releases = Rc::new(Cell::new(0));
        let mut frame = RxBuf::counted_frame(alloc::vec![1], 3, releases.clone());
        frame.extend_from_slice(&[2]);
        frame.extend_from_slice(&[3, 4]);
        assert_eq!(releases.get(), 0);
        drop(frame);
        assert_eq!(releases.get(), 1);
    }

    #[test]
    fn from_vec_has_no_spare_room() {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(&[1, 2]);
        assert!(bytes.capacity() > bytes.len());
        let frame = RxBuf::from_vec(bytes);
        assert_eq!(frame.room(), 0);
    }

    fn owned_frame(len: usize) -> (RxBuf, Rc<Cell<usize>>, NonNull<Storage>) {
        assert!(len <= 4);
        let releases = Rc::new(Cell::new(0));
        let storage = Storage {
            bytes: [10, 20, 30, 40, 50, 60],
            releases: releases.clone(),
        };
        let raw = Box::into_raw(Box::new(storage));
        let owner = NonNull::new(raw).unwrap();
        let data = unsafe {
            NonNull::new(core::ptr::addr_of_mut!((*raw).bytes).cast::<u8>().add(1)).unwrap()
        };
        // SAFETY: the box owns the range exclusively, len stays within bytes,
        // and release_storage drops the box once.
        let frame = unsafe { RxBuf::from_raw_parts(owner.cast(), release_storage, data, len, 0) };
        (frame, releases, owner)
    }

    #[test]
    fn release_runs_exactly_once() {
        let (frame, releases, _) = owned_frame(4);
        assert_eq!(releases.get(), 0);
        let moved = core::hint::black_box(frame);
        assert_eq!(releases.get(), 0);
        drop(moved);
        assert_eq!(releases.get(), 1);
    }

    #[test]
    fn view_ops_stay_in_bounds() {
        let (mut frame, releases, storage) = owned_frame(3);
        assert_eq!(frame.len(), 3);
        assert!(!frame.is_empty());
        assert_eq!(frame.as_slice(), &[20, 30, 40]);
        assert_eq!(frame.as_mut_slice().len(), 3);
        frame.as_mut_slice().copy_from_slice(&[21, 31, 41]);
        assert_eq!(frame.as_slice(), &[21, 31, 41]);
        // SAFETY: frame still owns the box and no mutable slice is live.
        assert_eq!(unsafe { storage.as_ref().bytes }, [10, 21, 31, 41, 50, 60]);
        drop(frame);
        assert_eq!(releases.get(), 1);

        let (mut empty, releases, storage) = owned_frame(0);
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
        assert!(empty.as_slice().is_empty());
        assert!(empty.as_mut_slice().is_empty());
        empty.as_mut_slice().fill(99);
        // SAFETY: empty still owns the box and no mutable slice is live.
        assert_eq!(unsafe { storage.as_ref().bytes }, [10, 20, 30, 40, 50, 60]);
        drop(empty);
        assert_eq!(releases.get(), 1);
    }

    #[test]
    fn from_vec_round_trips() {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(&[1, 2, 3, 4]);
        assert!(bytes.capacity() > bytes.len());
        let data = bytes.as_ptr();
        let mut frame = RxBuf::from_vec(bytes);
        assert_eq!(frame.as_slice().as_ptr(), data);
        assert_eq!(frame.as_slice(), &[1, 2, 3, 4]);
        frame.as_mut_slice()[2] = 9;
        assert_eq!(frame.as_slice(), &[1, 2, 9, 4]);
        drop(frame);

        let empty = RxBuf::from_vec(Vec::new());
        assert!(empty.is_empty());
        assert!(empty.as_slice().is_empty());
        drop(empty);
    }

    #[test]
    fn narrow_stays_in_bounds() {
        let (mut frame, releases, storage) = owned_frame(4);
        let data = frame.as_slice().as_ptr();
        frame.narrow(0..4);
        assert_eq!(frame.as_slice().as_ptr(), data);
        assert_eq!(frame.as_slice(), &[20, 30, 40, 50]);
        frame.narrow(1..4);
        frame.narrow(1..2);
        assert_eq!(frame.as_slice().as_ptr(), data.wrapping_add(2));
        assert_eq!(frame.as_slice(), &[40]);
        frame.as_mut_slice()[0] = 41;
        // SAFETY: frame owns the box and no mutable slice is live.
        assert_eq!(unsafe { storage.as_ref().bytes }, [10, 20, 30, 41, 50, 60]);
        frame.narrow(1..1);
        assert_eq!(frame.as_slice().as_ptr(), data.wrapping_add(3));
        assert!(frame.is_empty());
        frame.narrow(0..0);
        assert!(frame.as_mut_slice().is_empty());
        assert_eq!(releases.get(), 0);
        drop(frame);
        assert_eq!(releases.get(), 1);

        let (mut frame, releases, _) = owned_frame(0);
        frame.narrow(0..0);
        assert!(frame.is_empty());
        drop(frame);
        assert_eq!(releases.get(), 1);
    }

    #[test]
    fn narrow_panic_leaves_view_unchanged() {
        let (mut frame, releases, _) = owned_frame(4);
        frame.narrow(1..3);
        let data = frame.as_slice().as_ptr();
        for range in [0..3, 3..3, 2..1, 0..usize::MAX] {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| frame.narrow(range)))
                    .is_err()
            );
            assert_eq!(frame.as_slice().as_ptr(), data);
            assert_eq!(frame.as_slice(), &[30, 40]);
            assert_eq!(releases.get(), 0);
        }
        drop(frame);
        assert_eq!(releases.get(), 1);
    }

    #[test]
    #[should_panic]
    fn narrow_out_of_bounds_panics() {
        let (mut frame, _, _) = owned_frame(4);
        frame.narrow(0..5);
    }
}
