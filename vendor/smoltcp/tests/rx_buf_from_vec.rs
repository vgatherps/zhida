use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use smoltcp::phy::RxBuf;

struct WatchFrees;

static WATCHED: AtomicUsize = AtomicUsize::new(0);
static WATCHED_FREES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for WatchFrees {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr as usize == WATCHED.load(Ordering::SeqCst) {
            WATCHED_FREES.fetch_add(1, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: WatchFrees = WatchFrees;

#[test]
fn from_vec_frees_vector_storage_once_on_drop() {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&[7; 40]);
    WATCHED.store(bytes.as_ptr() as usize, Ordering::SeqCst);

    let frame = RxBuf::from_vec(bytes);
    assert_eq!(frame.as_slice(), &[7; 40]);
    assert_eq!(WATCHED_FREES.load(Ordering::SeqCst), 0);

    drop(frame);
    assert_eq!(WATCHED_FREES.load(Ordering::SeqCst), 1);
    WATCHED.store(0, Ordering::SeqCst);
}
