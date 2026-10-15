use alloc::rc::Rc;
use core::cell::{Cell, RefCell};

use crate::iface::{DropQueue, SocketHandle};

#[derive(Debug)]
pub(crate) struct RxShared {
    pub(crate) held: Cell<usize>,
    pub(crate) wake: RefCell<Option<(DropQueue, SocketHandle)>>,
    pub(crate) wake_queued: Cell<bool>,
    /// The app-held count at which a window update becomes due, as of the socket's last
    /// quiet `poll_at`; `usize::MAX` when no drop can make one due.
    pub(crate) wake_at_held: Cell<usize>,
}

impl RxShared {
    /// Create an empty held-frame count with no readiness wake.
    pub(crate) fn new() -> Rc<RxShared> {
        Rc::new(RxShared {
            held: Cell::new(0),
            wake: RefCell::new(None),
            wake_queued: Cell::new(false),
            wake_at_held: Cell::new(usize::MAX),
        })
    }

    /// Count one more frame: drained TCP frames, and UDP datagrams from the moment they are queued.
    #[inline]
    pub(crate) fn hold(&self) {
        self.held.set(self.held.get().checked_add(1).expect("held frame count overflow"));
    }

    /// Release one held frame and queue a readiness wake when its threshold is reached.
    #[inline]
    pub(crate) fn release(&self) {
        let held = self.held.get().checked_sub(1).expect("held frame count underflow");
        self.held.set(held);
        if held != self.wake_at_held.get() {
            return;
        }
        if let Some((queue, handle)) = self.wake.borrow().as_ref() {
            if !self.wake_queued.replace(true) {
                queue.push_wake(*handle);
            }
        }
    }
}

/// Frames the app still holds; they keep their RX pool buffers until dropped.
#[derive(Debug)]
pub struct HeldFrames {
    shared: Rc<RxShared>,
}

impl HeldFrames {
    pub(crate) fn new(shared: Rc<RxShared>) -> Self {
        Self { shared }
    }

    pub fn count(&self) -> usize {
        self.shared.held.get()
    }
}
