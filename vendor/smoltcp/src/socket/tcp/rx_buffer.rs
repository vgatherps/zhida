use alloc::rc::Rc;

use crate::phy::{RxBuf, RxShared};
use super::rx_store::RxStore;

/// An owned in-order TCP frame, including any appended payload.
#[derive(Debug)]
pub struct TcpFrame {
    pub(super) frame: RxBuf,
    pub(super) shared: Rc<RxShared>,
}

impl TcpFrame {
    pub fn payload(&self) -> &[u8] {
        self.frame.as_slice()
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        self.frame.as_mut_slice()
    }

    /// Raw NIC stamp of the segment that created this frame; 0 means none.
    /// Bytes appended into the frame keep its earlier stamp.
    pub fn rx_timestamp(&self) -> u64 {
        self.frame.rx_timestamp()
    }
}

impl Drop for TcpFrame {
    #[inline]
    fn drop(&mut self) {
        self.shared.release();
    }
}

/// Receive storage for a TCP socket.
#[derive(Debug)]
pub struct RxBuffer {
    pub(super) store: RxStore,
    pub(super) capacity: usize,
    pub(super) shared: Rc<RxShared>,
}

impl RxBuffer {
    /// Set the receive window ceiling and its scale.
    pub fn new(capacity: usize) -> RxBuffer {
        RxBuffer {
            store: RxStore::new(),
            capacity,
            shared: RxShared::new(),
        }
    }
}
