use core::fmt;
use managed::ManagedSlice;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::socket_meta::Meta;
use crate::socket::tcp;

use super::flow_table::FlowTable;
use super::timer_wheel::{
    InsertOutcome, IntrusiveLinks, Linked, ListHead, Timed, TimerWheel, WheelEntry, WheelPosition,
};
use crate::socket::PollAt;
use crate::time::Instant;
use crate::wire::IpEndpoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowKey {
    None,
    Listener(u16),
    Exact {
        local: IpEndpoint,
        remote: IpEndpoint,
    },
}

pub(crate) fn flow_key(socket: &tcp::Socket) -> FlowKey {
    let message = match socket.state() {
        tcp::State::Closed => return FlowKey::None,
        tcp::State::Listen => {
            debug_assert!(socket.local_endpoint().is_none());
            debug_assert!(socket.remote_endpoint().is_none());
            return FlowKey::Listener(socket.listen_endpoint().port);
        }
        tcp::State::SynSent => "TCP SynSent requires local and remote endpoints",
        tcp::State::SynReceived => "TCP SynReceived requires local and remote endpoints",
        tcp::State::Established => "TCP Established requires local and remote endpoints",
        tcp::State::FinWait1 => "TCP FinWait1 requires local and remote endpoints",
        tcp::State::FinWait2 => "TCP FinWait2 requires local and remote endpoints",
        tcp::State::CloseWait => "TCP CloseWait requires local and remote endpoints",
        tcp::State::Closing => "TCP Closing requires local and remote endpoints",
        tcp::State::LastAck => "TCP LastAck requires local and remote endpoints",
        tcp::State::TimeWait => "TCP TimeWait requires local and remote endpoints",
    };
    FlowKey::Exact {
        local: socket.local_endpoint().expect(message),
        remote: socket.remote_endpoint().expect(message),
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(align(64))]
struct FlowSlot {
    registered: FlowKey,
    next: usize,
    dirty: bool,
    deadline: PollAt,
    waiting: bool,
    queued: bool,
    timer_links: IntrusiveLinks,
    timer_position: WheelPosition,
    due: bool,
    orphaned: bool,
    reap_queued: bool,
}

impl FlowSlot {
    const EMPTY: Self = Self {
        registered: FlowKey::None,
        next: usize::MAX,
        dirty: false,
        deadline: PollAt::Ingress,
        waiting: false,
        queued: false,
        timer_links: IntrusiveLinks::new(),
        timer_position: WheelPosition::Unlinked,
        due: false,
        orphaned: false,
        reap_queued: false,
    };
}

fn deadline_tick(instant: Instant) -> u64 {
    let micros = instant.total_micros();
    if micros < 0 {
        0
    } else {
        (micros as u64).div_ceil(1000)
    }
}

impl Linked for FlowSlot {
    fn links(&self) -> &IntrusiveLinks {
        &self.timer_links
    }

    fn links_mut(&mut self) -> &mut IntrusiveLinks {
        &mut self.timer_links
    }
}

impl Timed for FlowSlot {
    fn deadline(&self) -> u64 {
        match self.deadline {
            PollAt::Time(instant) => deadline_tick(instant),
            _ => unreachable!("TCP wheel entry has no timed deadline"),
        }
    }
}

impl WheelEntry for FlowSlot {
    fn wheel_position(&self) -> WheelPosition {
        self.timer_position
    }

    fn set_wheel_position(&mut self, position: WheelPosition) {
        self.timer_position = position;
    }
}

/// Opaque struct with space for storing one socket.
///
/// This is public so you can use it to allocate space for storing
/// sockets when creating an Interface.
#[derive(Debug, Default)]
#[repr(C, align(64))]
pub struct TcpStorage<'a> {
    /// Bumped on every remove, so handles to a removed socket stop matching.
    generation: u64,
    inner: Option<Item<'a>>,
    admitted_rx_budget: usize,
}

impl<'a> TcpStorage<'a> {
    pub const EMPTY: Self = Self {
        inner: None,
        generation: 0,
        admitted_rx_budget: 0,
    };
}

/// An item of a socket set.
#[derive(Debug)]
#[repr(C)]
pub(crate) struct Item<'a> {
    pub(crate) meta: Meta,
    pub(crate) socket: tcp::Socket<'a>,
}

/// A handle, identifying a socket in an Interface.
///
/// A handle names one socket: once that socket is removed, the handle
/// stops matching even if a new socket reuses the slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct SocketHandle {
    index: usize,
    generation: u64,
}

impl fmt::Display for SocketHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "#{}", self.index)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TcpCounters {
    pub rx_checksum_bad: u64,
}

/// An extensible set of TCP sockets.
///
/// The lifetime `'a` is used when storing a `tcp::Socket<'a>`.  If you're using
/// owned buffers for your sockets (passed in as `Vec`s) you can use
/// `TcpSet<'static>`.
///
/// A set is used with one Interface. Cached deadlines depend on its IP MTU.
///
/// Inside `tcp::Socket::process` and `dispatch`, a change of the flow key happens
/// only together with a change of `state()`. The key is None for Closed, the listen
/// port for Listen, and the 4-tuple otherwise. The flow index is resynced on state
/// changes. App changes go through `get_mut` or `iter_mut`, which mark slots dirty.
///
/// If a socket method unwinds out of `Interface::poll`, the set must not be polled again.
#[derive(Debug)]
pub struct TcpSet<'a> {
    sockets: ManagedSlice<'a, TcpStorage<'a>>,
    pub(crate) counters: TcpCounters,
    pub(crate) pending_rx_attach: Option<(usize, tcp::PendingRxCommit)>,
    pub(crate) pending_tcp_reply: Option<usize>,
    /// Number of occupied slots.
    len: usize,
    /// Bit `i` is set when slot `i` holds a socket.
    occupied: Vec<u64>,
    flow_slots: Vec<FlowSlot>,
    exact: FlowTable<(IpEndpoint, IpEndpoint)>,
    listeners: FlowTable<u16>,
    flow_epoch: u64,
    last_exact: Option<(usize, u64)>,
    pub(crate) dirty_list: Vec<usize>,
    pub(crate) identity_synced: usize,
    wheel: TimerWheel,
    due: ListHead,
    admission: Vec<u32>,
    pub(crate) waiting: Vec<usize>,
    pub(crate) neighbor_changes: u64,
    ready: VecDeque<usize>,
    reapable: Vec<SocketHandle>,
    #[cfg(test)]
    pub(crate) dispatches: Vec<usize>,
    #[cfg(test)]
    pub(crate) classify_calls: usize,
    #[cfg(test)]
    pub(crate) slot_visits: usize,
}

impl<'a> TcpSet<'a> {
    pub fn counters(&self) -> TcpCounters {
        self.counters
    }

    /// Create a socket set using the provided storage.
    pub fn new<SocketsT>(sockets: SocketsT) -> TcpSet<'a>
    where
        SocketsT: Into<ManagedSlice<'a, TcpStorage<'a>>>,
    {
        let sockets = sockets.into();
        let len = sockets.iter().filter(|x| x.inner.is_some()).count();
        let slot_count = sockets.len();
        let occupied = {
            let mut occupied = alloc::vec![0u64; sockets.len().div_ceil(64)];
            for (index, slot) in sockets.iter().enumerate() {
                if slot.inner.is_some() {
                    occupied[index / 64] |= 1 << (index % 64);
                }
            }
            occupied
        };
        let mut set = TcpSet {
            sockets,
            pending_rx_attach: None,
            counters: TcpCounters::default(),
            pending_tcp_reply: None,
            len,
            occupied,
            flow_slots: alloc::vec![FlowSlot::EMPTY; slot_count],
            exact: FlowTable::new(slot_count),
            listeners: FlowTable::new(slot_count),
            flow_epoch: 0,
            last_exact: None,
            dirty_list: Vec::with_capacity(slot_count),
            identity_synced: 0,
            wheel: TimerWheel::default(),
            due: ListHead::new(),
            admission: Vec::with_capacity(slot_count),
            waiting: Vec::with_capacity(slot_count),
            neighbor_changes: 0,
            ready: VecDeque::with_capacity(slot_count),
            reapable: Vec::with_capacity(slot_count),
            #[cfg(test)]
            dispatches: Vec::new(),
            #[cfg(test)]
            classify_calls: 0,
            #[cfg(test)]
            slot_visits: 0,
        };
        for index in 0..slot_count {
            set.sync_identity(index);
            if set.sockets[index].inner.is_some() {
                set.mark_dirty(index);
            }
        }
        set
    }

    /// Return the number of sockets in the set.
    pub fn len(&self) -> usize {
        self.len
    }

    fn lowest_free(&self) -> Option<usize> {
        let (word, bits) = self
            .occupied
            .iter()
            .enumerate()
            .find(|(_, bits)| **bits != u64::MAX)?;
        let index = word * 64 + bits.trailing_ones() as usize;
        (index < self.sockets.len()).then_some(index)
    }

    fn set_occupied(&mut self, index: usize, occupied: bool) {
        if occupied {
            self.len += 1;
        } else {
            self.len -= 1;
        }
        let bit = 1u64 << (index % 64);
        if occupied {
            self.occupied[index / 64] |= bit;
        } else {
            self.occupied[index / 64] &= !bit;
        }
    }

    /// Add a socket to the set without RX admission, and return its handle.
    ///
    /// # Panics
    /// This function panics if the storage is fixed-size (not a `Vec`) and is full.
    pub(crate) fn add(&mut self, socket: tcp::Socket<'a>) -> SocketHandle {
        fn put<'a>(
            index: usize,
            slot: &mut TcpStorage<'a>,
            socket: tcp::Socket<'a>,
        ) -> SocketHandle {
            net_trace!("[{}]: adding", index);
            let handle = SocketHandle {
                index,
                generation: slot.generation,
            };
            let meta = Meta::default();
            slot.admitted_rx_budget = 0;
            slot.inner = Some(Item { meta, socket });
            handle
        }

        let index = match self.lowest_free() {
            Some(index) => index,
            None => match &mut self.sockets {
                ManagedSlice::Borrowed(_) => panic!("adding a socket to a full TcpSet"),
                ManagedSlice::Owned(sockets) => {
                    sockets.push(TcpStorage::EMPTY);
                    let index = sockets.len() - 1;
                    if index / 64 == self.occupied.len() {
                        self.occupied.push(0);
                    }
                    self.flow_slots.push(FlowSlot::EMPTY);
                    if self.ready.capacity() < sockets.len() {
                        self.ready.reserve_exact(sockets.len() - self.ready.len());
                    }
                    if self.reapable.capacity() < sockets.len() {
                        self.reapable.reserve_exact(sockets.len() - self.reapable.len());
                    }
                    self.exact.grow(sockets.len());
                    self.listeners.grow(sockets.len());
                    self.flow_epoch = self.flow_epoch.wrapping_add(1);
                    if self.dirty_list.capacity() < sockets.len() {
                        self.dirty_list
                            .reserve_exact(sockets.len() - self.dirty_list.len());
                    }
                    index
                }
            },
        };
        self.set_occupied(index, true);
        let handle = put(index, &mut self.sockets[index], socket);
        self.sync_identity(index);
        self.mark_dirty(index);
        handle
    }

    /// Build a socket from `config`, fix its RX frame count to
    /// [`tcp::rx_mbuf_budget`]`(config, ip_mtu)` and add it. The caller has already
    /// admitted that many mbufs. Outside this crate, sockets are created only here and
    /// [`TcpSet::remove`] drops them, so no owned socket leaves the set.
    ///
    /// # Panics
    /// This function panics if `ip_mtu` is below 68, `config.rx_capacity` exceeds 1 GiB,
    /// `config.mss_cap` is `Some(0)`, the frame count exceeds u32, or the storage is
    /// fixed-size (not a `Vec`) and is full.
    pub fn add_admitted(
        &mut self,
        config: &tcp::Config,
        ip_mtu: usize,
        wake: super::DropQueue,
    ) -> SocketHandle {
        let mut socket = tcp::Socket::from_config(config);
        socket.set_rx_mbuf_budget(ip_mtu);
        let budget = socket.rx_frame_cap();
        let handle = self.add(socket);
        let slot = &mut self.sockets[handle.index];
        slot.admitted_rx_budget = budget;
        slot.inner.as_mut().unwrap().socket.set_rx_wake(wake, handle);
        handle
    }

    /// Get a socket from the set by its handle.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set,
    /// and panics if the socket it named was removed.
    pub fn get(&self, handle: SocketHandle) -> &tcp::Socket<'a> {
        &self.item(handle).socket
    }

    /// Get a mutable socket from the set by its handle.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set,
    /// and panics if the socket it named was removed.
    pub fn get_mut(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'a> {
        self.item(handle);
        self.identity_synced = 0;
        self.mark_dirty(handle.index);
        &mut self.item_mut(handle).socket
    }

    /// Complete a queued receive wake and schedule the socket's readiness check.
    pub fn rx_woken(&mut self, handle: SocketHandle) {
        let socket = &mut self.sockets.get_mut(handle.index)
            .filter(|slot| slot.generation == handle.generation)
            .and_then(|slot| slot.inner.as_mut())
            .expect("receive wake does not name a live TCP socket").socket;
        socket.clear_rx_wake_queued();
        self.mark_dirty(handle.index);
    }

    /// Close the socket after its application handle is dropped, keeping it in the set.
    pub fn orphan(&mut self, handle: SocketHandle, now: Instant) {
        self.get_mut(handle).orphan(now);
        self.flow_slots[handle.index].orphaned = true;
        self.check_reapable(handle.index);
    }

    pub(crate) fn check_reapable(&mut self, index: usize) {
        let flow = &mut self.flow_slots[index];
        if !flow.orphaned || flow.reap_queued {
            return;
        }
        let storage = &self.sockets[index];
        let socket = &storage.inner.as_ref().expect("orphan slot is empty").socket;
        if socket.state() == tcp::State::Closed && socket.remote_endpoint().is_none() {
            debug_assert!(self.reapable.len() < self.reapable.capacity());
            self.reapable.push(SocketHandle { index, generation: storage.generation });
            flow.reap_queued = true;
        }
    }

    /// Whether an orphan has become CLOSED with no remote endpoint.
    pub fn has_reapable(&self) -> bool {
        !self.reapable.is_empty()
    }

    /// Drain reapable orphan handles, retaining the list's allocation.
    pub fn take_reapable(&mut self, f: impl FnMut(SocketHandle)) {
        self.reapable.drain(..).for_each(f);
    }

    /// Removes a socket from the set without changing its state, discarding unread received
    /// bytes and clearing receive wakes. Returns the frames the application still holds and the
    /// socket's admitted RX budget. The socket itself is dropped: handing it out would let a
    /// caller write it over another admitted socket through `get_mut`.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set,
    /// and panics if the socket it named was already removed.
    pub fn remove(&mut self, handle: SocketHandle) -> (crate::phy::HeldFrames, usize) {
        let (socket, budget) = self.take(handle);
        (socket.held_frames(), budget)
    }

    /// `remove`, but returns the socket with an empty receive buffer.
    pub(crate) fn take(&mut self, handle: SocketHandle) -> (tcp::Socket<'a>, usize) {
        net_trace!("[{}]: removing", handle.index);
        self.item(handle);
        let slot = &mut self.sockets[handle.index];
        slot.generation = slot
            .generation
            .checked_add(1)
            .expect("socket slot generation overflow");
        if self.flow_slots[handle.index].reap_queued {
            self.reapable.retain(|&queued| queued != handle);
        }
        self.flow_slots[handle.index].orphaned = false;
        self.flow_slots[handle.index].reap_queued = false;
        self.unlink_identity(handle.index);
        self.set_deadline(handle.index, PollAt::Ingress, false);
        if self.flow_slots[handle.index].queued {
            let position = self
                .ready
                .iter()
                .position(|&index| index == handle.index)
                .expect("queued TCP slot is not in the ready queue");
            self.ready.remove(position);
            self.flow_slots[handle.index].queued = false;
        }
        // Before the take, so the socket is moved out once, straight to the caller.
        self.set_occupied(handle.index, false);
        match self.sockets[handle.index].inner.take() {
            Some(mut item) => {
                item.socket.clear_rx_wake();
                item.socket.discard_received();
                (item.socket, self.sockets[handle.index].admitted_rx_budget)
            }
            None => unreachable!(),
        }
    }

    /// The item `handle` names; panics unless it is the socket currently in its slot.
    fn item(&self, handle: SocketHandle) -> &Item<'a> {
        match &self.sockets[handle.index] {
            TcpStorage {
                inner: Some(item),
                generation,
                ..
            } if *generation == handle.generation => item,
            _ => panic!("handle does not refer to a valid socket"),
        }
    }

    /// The item `handle` names; panics unless it is the socket currently in its slot.
    fn item_mut(&mut self, handle: SocketHandle) -> &mut Item<'a> {
        match &mut self.sockets[handle.index] {
            TcpStorage {
                inner: Some(item),
                generation,
                ..
            } if *generation == handle.generation => item,
            _ => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Get an iterator to the inner sockets.
    pub fn iter(&self) -> impl Iterator<Item = (SocketHandle, &tcp::Socket<'a>)> {
        self.sockets.iter().enumerate().filter_map(|(index, storage)| {
            let item = storage.inner.as_ref()?;
            let handle = SocketHandle {
                index,
                generation: storage.generation,
            };
            Some((handle, &item.socket))
        })
    }

    /// Get a mutable iterator to the inner sockets.
    #[cfg(test)]
    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = (SocketHandle, &mut tcp::Socket<'a>)> {
        self.identity_synced = 0;
        let dirty_list = &mut self.dirty_list;
        let flow_slots = &mut self.flow_slots;
        let wheel = &mut self.wheel;
        let due = &mut self.due;
        self.sockets
            .iter_mut()
            .enumerate()
            .filter_map(move |(index, storage)| {
                let item = storage.inner.as_mut()?;
                if !flow_slots[index].dirty {
                    let timer_index = u32::try_from(index).expect("TCP timer index overflow");
                    wheel.remove(flow_slots, timer_index);
                    if flow_slots[index].due {
                        due.remove(flow_slots, timer_index);
                        flow_slots[index].due = false;
                    }
                    flow_slots[index].dirty = true;
                    dirty_list.push(index);
                }
                let handle = SocketHandle {
                    index,
                    generation: storage.generation,
                };
                Some((handle, &mut item.socket))
            })
    }

    /// Iterate every socket in this set.
    pub(crate) fn items(&self) -> impl Iterator<Item = &Item<'a>> + '_ {
        self.sockets.iter().filter_map(|x| x.inner.as_ref())
    }

    pub(crate) fn slot_count(&self) -> usize {
        self.sockets.len()
    }

    pub(crate) fn item_at_mut(&mut self, index: usize) -> Option<&mut Item<'a>> {
        self.sockets[index].inner.as_mut()
    }

    pub(crate) fn handle_at(&self, index: usize) -> SocketHandle {
        SocketHandle {
            index,
            generation: self.sockets[index].generation,
        }
    }
}

impl TcpSet<'_> {
    fn flow_head(&self, key: FlowKey) -> Option<usize> {
        match key {
            FlowKey::None => None,
            FlowKey::Listener(port) => self.listeners.get(&port),
            FlowKey::Exact { local, remote } => self.exact.get(&(local, remote)),
        }
    }

    fn set_flow_head(&mut self, key: FlowKey, head: usize) {
        self.flow_epoch = self.flow_epoch.wrapping_add(1);
        match key {
            FlowKey::None => unreachable!(),
            FlowKey::Listener(port) => {
                if head == usize::MAX {
                    self.listeners.remove(&port);
                } else {
                    self.listeners.set(port, head);
                }
            }
            FlowKey::Exact { local, remote } => {
                if head == usize::MAX {
                    self.exact.remove(&(local, remote));
                } else {
                    self.exact.set((local, remote), head);
                }
            }
        }
    }

    fn unlink_identity(&mut self, index: usize) {
        let slot = self.flow_slots[index];
        if slot.registered == FlowKey::None {
            return;
        }
        let head = self
            .flow_head(slot.registered)
            .expect("registered TCP flow has no chain head");
        if head == index {
            self.set_flow_head(slot.registered, slot.next);
        } else {
            let mut previous = head;
            while self.flow_slots[previous].next != index {
                #[cfg(test)]
                {
                    self.slot_visits += 1;
                }
                previous = self.flow_slots[previous].next;
                assert_ne!(
                    previous,
                    usize::MAX,
                    "registered TCP slot is not in its chain"
                );
            }
            self.flow_slots[previous].next = slot.next;
            self.flow_epoch = self.flow_epoch.wrapping_add(1);
        }
        self.flow_slots[index].registered = FlowKey::None;
        self.flow_slots[index].next = usize::MAX;
    }

    pub(crate) fn sync_identity(&mut self, index: usize) {
        let key = self.sockets[index]
            .inner
            .as_ref()
            .map_or(FlowKey::None, |item| flow_key(&item.socket));
        if key == self.flow_slots[index].registered {
            return;
        }
        self.set_deadline(index, PollAt::Ingress, false);
        if let Some(item) = &mut self.sockets[index].inner {
            item.meta = Meta::default();
        }
        self.unlink_identity(index);
        if key == FlowKey::None {
            return;
        }
        let head = self.flow_head(key).unwrap_or(usize::MAX);
        self.flow_slots[index].registered = key;
        if index < head {
            self.flow_slots[index].next = head;
            self.set_flow_head(key, index);
        } else {
            let mut previous = head;
            while self.flow_slots[previous].next < index {
                #[cfg(test)]
                {
                    self.slot_visits += 1;
                }
                previous = self.flow_slots[previous].next;
            }
            self.flow_slots[index].next = self.flow_slots[previous].next;
            self.flow_slots[previous].next = index;
            self.flow_epoch = self.flow_epoch.wrapping_add(1);
        }
    }

    #[cfg(debug_assertions)]
    pub(crate) fn debug_assert_synced(&self, index: usize) {
        let key = self.sockets[index]
            .inner
            .as_ref()
            .map_or(FlowKey::None, |item| flow_key(&item.socket));
        assert_eq!(
            self.flow_slots[index].registered, key,
            "TCP flow index out of date for slot {index}"
        );
    }

    fn remove_deadline(&mut self, index: usize) {
        if self.flow_slots[index].timer_position == WheelPosition::Unlinked
            && !self.flow_slots[index].due
        {
            return;
        }
        let timer_index = u32::try_from(index).expect("TCP timer index overflow");
        self.wheel.remove(&mut self.flow_slots, timer_index);
        if self.flow_slots[index].due {
            self.due.remove(&mut self.flow_slots, timer_index);
            self.flow_slots[index].due = false;
        }
    }

    pub(crate) fn mark_dirty(&mut self, index: usize) {
        if !self.flow_slots[index].dirty {
            self.remove_deadline(index);
            self.flow_slots[index].dirty = true;
            self.dirty_list.push(index);
        }
    }

    /// `mark_dirty` for a slot whose identity the caller has just synced: the sync cursor
    /// stays at the end of the dirty list when it was there.
    pub(crate) fn mark_dirty_synced(&mut self, index: usize) {
        let all_synced = self.identity_synced == self.dirty_list.len();
        self.mark_dirty(index);
        if all_synced {
            self.identity_synced = self.dirty_list.len();
        }
    }

    pub(crate) fn clear_dirty(&mut self) {
        for position in 0..self.dirty_list.len() {
            #[cfg(test)]
            {
                self.slot_visits += 1;
            }
            let index = self.dirty_list[position];
            self.flow_slots[index].dirty = false;
            if !self.flow_slots[index].queued {
                self.include_deadline(index);
            }
        }
        self.dirty_list.clear();
        self.identity_synced = 0;
    }

    pub(crate) fn sync_dirty_identities(&mut self) {
        for position in self.identity_synced..self.dirty_list.len() {
            #[cfg(test)]
            {
                self.slot_visits += 1;
            }
            self.sync_identity(self.dirty_list[position]);
        }
        self.identity_synced = self.dirty_list.len();
    }

    pub(crate) fn set_deadline(&mut self, index: usize, deadline: PollAt, waiting: bool) {
        if self.flow_slots[index].deadline != deadline {
            self.remove_deadline(index);
            self.flow_slots[index].deadline = deadline;
            if !self.flow_slots[index].dirty && !self.flow_slots[index].queued {
                self.include_deadline(index);
            }
        }
        self.set_waiting(index, waiting);
    }

    pub(crate) fn set_waiting(&mut self, index: usize, waiting: bool) {
        let slot = &mut self.flow_slots[index];
        if waiting != slot.waiting {
            if waiting {
                self.waiting.push(index);
            } else {
                let position = self
                    .waiting
                    .iter()
                    .position(|&i| {
                        #[cfg(test)]
                        {
                            self.slot_visits += 1;
                        }
                        i == index
                    })
                    .expect("waiting TCP slot is not in the waiting list");
                self.waiting.swap_remove(position);
            }
            slot.waiting = waiting;
        }
    }

    pub(crate) fn poll_at(&mut self) -> Option<Instant> {
        let mut earliest = self.wheel.next_boundary().map(|tick| {
            Instant::from_micros(
                i64::try_from(tick.checked_mul(1000).expect("TCP timer boundary overflow"))
                    .expect("TCP timer boundary exceeds Instant"),
            )
        });
        for index in self
            .ready
            .iter()
            .copied()
            .map(|i| i as u32)
            .chain(self.due.iter(&self.flow_slots))
        {
            #[cfg(test)]
            {
                self.slot_visits += 1;
            }
            let deadline = match self.flow_slots[index as usize].deadline {
                PollAt::Ingress => continue,
                PollAt::Now => Instant::ZERO,
                PollAt::Time(instant) => instant,
            };
            earliest = Some(earliest.map_or(deadline, |previous| previous.min(deadline)));
        }
        earliest
    }

    pub(crate) fn deadline_due(&self, index: usize, timestamp: Instant) -> bool {
        match self.flow_slots[index].deadline {
            PollAt::Ingress => false,
            PollAt::Now => true,
            PollAt::Time(instant) if instant.total_micros() < 0 => instant <= timestamp,
            PollAt::Time(instant) => {
                timestamp.total_micros() >= 0
                    && deadline_tick(instant) <= timestamp.total_micros() as u64 / 1000
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn stored_deadline(&self, index: usize) -> PollAt {
        self.flow_slots[index].deadline
    }

    pub(crate) fn advance_wheel(&mut self, timestamp: Instant, admit: bool) {
        debug_assert!(self.admission.is_empty());
        if timestamp.total_micros() >= 0 {
            let now_tick = timestamp.total_micros() as u64 / 1000;
            if now_tick >= self.wheel.current_tick() {
                #[cfg(test)]
                let before = self.wheel.slot_visits;
                self.wheel
                    .advance_to(&mut self.flow_slots, now_tick, &mut self.admission)
                    .expect("TCP wheel time regressed");
                #[cfg(test)]
                {
                    self.slot_visits += self.wheel.slot_visits - before;
                }
            }
        }
        let mut kept = 0usize;
        for position in 0..self.admission.len() {
            #[cfg(test)]
            {
                self.slot_visits += 1;
            }
            let index = self.admission[position];
            if self.flow_slots[index as usize].waiting {
                self.mark_dirty(index as usize);
                continue;
            }
            if admit {
                debug_assert!(!self.flow_slots[index as usize].dirty);
                self.admission[kept] = index;
                kept = kept.checked_add(1).expect("TCP admission length overflow");
            } else {
                self.flow_slots[index as usize].due = true;
                self.due.push_back(&mut self.flow_slots, index);
            }
        }
        self.admission.truncate(kept);
    }

    /// `admission` may already hold slots whose wheel deadline expired at the start of this egress pass.
    pub(crate) fn admit_ready(&mut self, timestamp: Instant) -> usize {
        for position in 0..self.dirty_list.len() {
            #[cfg(test)]
            {
                self.slot_visits += 1;
            }
            let index = self.dirty_list[position];
            self.flow_slots[index].dirty = false;
            if !self.flow_slots[index].queued {
                if self.sockets[index].inner.is_some() && self.deadline_due(index, timestamp) {
                    self.admission
                        .push(u32::try_from(index).expect("TCP timer index overflow"));
                } else {
                    self.include_deadline(index);
                }
            }
        }
        self.dirty_list.clear();
        self.identity_synced = 0;
        for index in self.due.iter(&self.flow_slots) {
            #[cfg(test)]
            {
                self.slot_visits += 1;
            }
            if self.deadline_due(index as usize, timestamp) {
                self.admission.push(index);
            }
        }
        self.admission.sort_unstable();
        self.admission.dedup();
        for position in 0..self.admission.len() {
            #[cfg(test)]
            {
                self.slot_visits += 1;
            }
            self.push_ready(self.admission[position] as usize, false);
        }
        self.admission.clear();
        self.ready.len()
    }

    pub(crate) fn ready_len(&self) -> usize {
        self.ready.len()
    }

    pub(crate) fn egress_idle(&self) -> bool {
        self.ready.is_empty()
            && self.dirty_list.is_empty()
            && self.waiting.is_empty()
            && self.due.is_empty()
    }

    pub(crate) fn pop_ready(&mut self) -> usize {
        let index = self.ready.pop_front().expect("TCP ready queue is empty");
        self.flow_slots[index].queued = false;
        index
    }

    pub(crate) fn include_deadline(&mut self, index: usize) {
        let slot = &self.flow_slots[index];
        debug_assert!(!slot.dirty && !slot.queued);
        if self.sockets[index].inner.is_none()
            || slot.due
            || slot.timer_position != WheelPosition::Unlinked
        {
            return;
        }
        let timer_index = u32::try_from(index).expect("TCP timer index overflow");
        let due = match slot.deadline {
            PollAt::Ingress => false,
            PollAt::Now => true,
            PollAt::Time(_) => {
                self.wheel.insert(&mut self.flow_slots, timer_index) == InsertOutcome::Due
            }
        };
        if due {
            self.due.push_back(&mut self.flow_slots, timer_index);
            self.flow_slots[index].due = true;
        }
    }

    pub(crate) fn push_ready(&mut self, index: usize, first: bool) {
        if !self.flow_slots[index].queued {
            self.remove_deadline(index);
            if first {
                self.ready.push_front(index);
            } else {
                self.ready.push_back(index);
            }
            self.flow_slots[index].queued = true;
        }
    }

    #[cfg(debug_assertions)]
    pub(crate) fn debug_assert_ready<F>(&self, timestamp: Instant, has_neighbor: F)
    where
        F: Fn(crate::wire::IpAddress) -> bool,
    {
        for (index, storage) in self.sockets.iter().enumerate() {
            let queued = self.flow_slots[index].queued;
            match &storage.inner {
                Some(item) => {
                    if !self.flow_slots[index].dirty
                        && self.deadline_due(index, timestamp)
                        && item
                            .meta
                            .poll_at(crate::socket::PollAt::Now, &has_neighbor, timestamp)
                            == crate::socket::PollAt::Now
                    {
                        assert!(queued, "TCP slot {index} needs egress but is not queued");
                    }
                }
                None => assert!(!queued, "empty TCP slot {index} is queued"),
            }
        }
        for &index in &self.ready {
            assert!(self.flow_slots[index].queued);
            assert!(self.sockets[index].inner.is_some());
        }
    }

    /// The cached slot was the exact group's head at this epoch, so it is the lowest
    /// accepting slot when no listener is eligible. SYN-like segments need the full lookup.
    pub(crate) fn tcp_lookup(
        &mut self,
        dst: IpEndpoint,
        src: IpEndpoint,
        syn_like: bool,
    ) -> Option<usize> {
        if !syn_like
            && let Some((index, epoch)) = self.last_exact
            && epoch == self.flow_epoch
            && self.flow_slots[index].registered
                == (FlowKey::Exact {
                    local: dst,
                    remote: src,
                })
        {
            return Some(index);
        }
        let e = self.exact.get(&(dst, src));
        if !syn_like && let Some(index) = e {
            self.last_exact = Some((index, self.flow_epoch));
        }
        if e.is_some() {
            return e;
        }
        if syn_like {
            self.tcp_listener_lookup(dst)
        } else {
            None
        }
    }

    pub(crate) fn tcp_listener_lookup(&self, dst: IpEndpoint) -> Option<usize> {
        let mut index = self.listeners.get(&dst.port).unwrap_or(usize::MAX);
        while index != usize::MAX {
            let socket = &self.sockets[index]
                .inner
                .as_ref()
                .expect("TCP listener chain contains an empty slot")
                .socket;
            if socket
                .listen_endpoint()
                .addr
                .is_none_or(|addr| addr == dst.addr)
            {
                return Some(index);
            }
            index = self.flow_slots[index].next;
        }
        None
    }

    #[cfg(any(test, debug_assertions))]
    pub(crate) fn check_flow_index(&self) {
        assert_eq!(self.flow_slots.len(), self.sockets.len());
        let mut seen = alloc::vec![false; self.sockets.len()];
        let entries = self
            .listeners
            .entries()
            .map(|(port, head)| (FlowKey::Listener(port), head))
            .chain(
                self.exact
                    .entries()
                    .map(|((local, remote), head)| (FlowKey::Exact { local, remote }, head)),
            );
        for (key, head) in entries {
            assert_eq!(self.flow_head(key), Some(head));
            assert_eq!(
                self.flow_slots
                    .iter()
                    .position(|slot| slot.registered == key),
                Some(head)
            );
            let mut index = head;
            while index != usize::MAX {
                assert!(!seen[index], "TCP slot occurs in more than one chain");
                seen[index] = true;
                assert!(self.sockets[index].inner.is_some());
                let slot = &self.flow_slots[index];
                assert_eq!(slot.registered, key);
                assert!(slot.next > index, "TCP flow chain is not ascending");
                index = slot.next;
            }
        }
        let mut dirty = alloc::vec![false; self.sockets.len()];
        for &index in &self.dirty_list {
            assert!(!dirty[index], "TCP dirty list contains a duplicate");
            dirty[index] = true;
        }
        for (index, (storage, slot)) in self.sockets.iter().zip(&self.flow_slots).enumerate() {
            assert_eq!(slot.dirty, dirty[index]);
            assert_eq!(seen[index], slot.registered != FlowKey::None);
            if let Some(item) = &storage.inner {
                if !slot.dirty {
                    assert_eq!(slot.registered, flow_key(&item.socket));
                }
            } else {
                assert_eq!(slot.registered, FlowKey::None);
            }
            if slot.registered == FlowKey::None {
                assert_eq!(slot.next, usize::MAX);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    fn socket() -> tcp::Socket<'static> {
        tcp::Socket::new(tcp::RxBuffer::new(0), tcp::SocketBuffer::new(vec![]))
    }

    fn at(index: usize, generation: u64) -> SocketHandle {
        SocketHandle { index, generation }
    }

    const INVALID: &str = "handle does not refer to a valid socket";

    fn assert_reapable(set: &mut TcpSet, expected: &[SocketHandle]) {
        let mut found = Vec::new();
        set.take_reapable(|handle| found.push(handle));
        assert_eq!(found, expected);
        assert!(!set.has_reapable());
        set.take_reapable(|_| panic!("orphan reported twice"));
    }

    #[cfg(feature = "medium-ip")]
    #[test]
    fn reapable_immediate_orphans_and_slot_reuse() {
        let (mut iface, _, _) = crate::tests::setup(crate::phy::Medium::Ip);
        let mut set = TcpSet::new(vec![TcpStorage::EMPTY]);
        let allocation = (set.reapable.capacity(), set.reapable.as_ptr());
        for _ in 0..2 {
            let handle = set.add(socket());
            set.get_mut(handle).listen(80).unwrap();
            set.orphan(handle, Instant::ZERO);
            set.orphan(handle, Instant::ZERO);
            assert!(set.has_reapable());
            assert_reapable(&mut set, &[handle]);
            set.orphan(handle, Instant::ZERO);
            assert_reapable(&mut set, &[]);
            set.remove(handle);
        }
        assert_eq!(allocation, (set.reapable.capacity(), set.reapable.as_ptr()));
        let owned = set.add(socket());
        let sent = set.add(socket());
        set.get_mut(sent).connect(iface.context(), (crate::wire::IpAddress::v4(192, 168, 1, 2), 80), 1234).unwrap();
        set.orphan(sent, Instant::ZERO);
        assert_reapable(&mut set, &[sent]);
        set.orphan(owned, Instant::ZERO);
        set.remove(owned);
        assert_reapable(&mut set, &[]);
        assert!(set.reapable.capacity() >= set.slot_count());
    }

    #[cfg(feature = "medium-ip")]
    #[test]
    fn reapable_abort_rst_dispatch() {
        let (mut iface, mut set, mut device) = crate::tests::setup(crate::phy::Medium::Ip);
        let handle = set.add(socket());
        set.get_mut(handle).connect(iface.context(), (crate::wire::IpAddress::v4(192, 168, 1, 2), 80), 1234).unwrap();
        set.get_mut(handle).abort();
        set.orphan(handle, Instant::ZERO);
        assert_eq!(set.get(handle).state(), tcp::State::Closed);
        assert!(set.get(handle).remote_endpoint().is_some());
        assert_reapable(&mut set, &[]);
        iface.poll_egress(Instant::ZERO, &mut device, &mut set);
        assert_eq!(set.get(handle).remote_endpoint(), None);
        assert_reapable(&mut set, &[handle]);
        iface.poll_egress(Instant::ZERO, &mut device, &mut set);
        assert_reapable(&mut set, &[]);
        let owned = set.add(socket());
        set.get_mut(owned).connect(iface.context(), (crate::wire::IpAddress::v4(192, 168, 1, 2), 81), 1235).unwrap();
        set.get_mut(owned).abort();
        iface.poll_egress(Instant::ZERO, &mut device, &mut set);
        assert_eq!(set.get(owned).remote_endpoint(), None);
        assert_reapable(&mut set, &[]);
    }

    #[cfg(feature = "medium-ip")]
    #[test]
    fn owned_time_wait_reopen_keeps_received_data_and_eof() {
        use crate::phy::Medium;
        use crate::wire::{IpAddress, IpCidr};

        let (mut a, mut a_set, mut a_device) = crate::tests::setup(Medium::Ip);
        let (mut b, mut b_set, mut b_device) = crate::tests::setup(Medium::Ip);
        let remote = IpAddress::v4(192, 168, 1, 2);
        b.update_ip_addrs(|addrs| {
            addrs.clear();
            addrs.push(IpCidr::new(remote, 24)).unwrap();
        });
        let buffered = || tcp::Socket::new(tcp::RxBuffer::new(64), tcp::SocketBuffer::new(vec![0; 64]));
        let ah = a_set.add(buffered());
        let bh = b_set.add(buffered());
        a_set.get_mut(ah).set_ack_delay(None);
        b_set.get_mut(bh).set_ack_delay(None);
        b_set.get_mut(bh).listen(80).unwrap();
        a_set.get_mut(ah).connect(a.context(), (remote, 80), 1234).unwrap();
        for _ in 0..8 {
            a.poll(Instant::ZERO, &mut a_device, &mut a_set);
            b_device.rx_queue.append(&mut a_device.tx_queue);
            b.poll(Instant::ZERO, &mut b_device, &mut b_set);
            a_device.rx_queue.append(&mut b_device.tx_queue);
        }
        assert_eq!(a_set.get(ah).state(), tcp::State::Established);
        a_set.get_mut(ah).close();
        a.poll(Instant::ZERO, &mut a_device, &mut a_set);
        b_device.rx_queue.append(&mut a_device.tx_queue);
        b.poll(Instant::ZERO, &mut b_device, &mut b_set);
        b_set.get_mut(bh).send_slice(b"abc").unwrap();
        b_set.get_mut(bh).close();
        for _ in 0..8 {
            b.poll(Instant::ZERO, &mut b_device, &mut b_set);
            a_device.rx_queue.append(&mut b_device.tx_queue);
            a.poll(Instant::ZERO, &mut a_device, &mut a_set);
            b_device.rx_queue.append(&mut a_device.tx_queue);
        }
        assert_eq!(b_set.get(bh).state(), tcp::State::Closed);
        assert_eq!(a_set.get(ah).state(), tcp::State::TimeWait);
        assert_eq!(a_set.get(ah).recv_queue(), 3);
        let listener = a_set.add(buffered());
        a_set.get_mut(listener).listen(1234).unwrap();
        b.poll_maintenance(Instant::from_millis(1));
        b_set.get_mut(bh).connect(b.context(), (IpAddress::v4(192, 168, 1, 1), 1234), 80).unwrap();
        b.poll_egress(Instant::from_millis(1), &mut b_device, &mut b_set);
        let bytes = b_device.tx_queue.front_mut().unwrap();
        let mut ip = crate::wire::Ipv4Packet::new_unchecked(bytes.as_mut_slice());
        let (src, dst) = (ip.src_addr().into(), ip.dst_addr().into());
        let mut syn = crate::wire::TcpPacket::new_unchecked(ip.payload_mut());
        syn.set_seq_number(syn.seq_number() + 6);
        syn.fill_checksum(&src, &dst);
        a_device.rx_queue.append(&mut b_device.tx_queue);
        a.poll(Instant::from_millis(1), &mut a_device, &mut a_set);
        assert_eq!(a_set.get(listener).state(), tcp::State::SynReceived);
        assert_eq!(a_set.get(ah).state(), tcp::State::Closed);
        assert_eq!(a_set.get(ah).remote_endpoint(), None);
        assert_reapable(&mut a_set, &[]);
        assert_eq!(a_set.get(ah).recv_queue(), 3);
        let frame = a_set.get_mut(ah).recv().unwrap().unwrap();
        assert_eq!(frame.payload(), b"abc");
        drop(frame);
        assert!(matches!(a_set.get_mut(ah).recv(), Err(tcp::RecvError::Finished)));
    }

    #[cfg(feature = "medium-ip")]
    #[test]
    fn reapable_ingress_and_time_wait_expiry() {
        use crate::phy::Medium;
        use crate::wire::{IpAddress, IpCidr};

        for (orphaned, reset_with_syn) in [(true, false), (false, false), (true, true)] {
            let (mut a, mut a_set, mut a_device) = crate::tests::setup(Medium::Ip);
            let (mut b, mut b_set, mut b_device) = crate::tests::setup(Medium::Ip);
            let remote = IpAddress::v4(192, 168, 1, 2);
            b.update_ip_addrs(|addrs| {
                addrs.clear();
                addrs.push(IpCidr::new(remote, 24)).unwrap();
            });
            let buffered = || tcp::Socket::new(tcp::RxBuffer::new(64), tcp::SocketBuffer::new(vec![0; 64]));
            let ah = a_set.add(buffered());
            let bh = b_set.add(buffered());
            b_set.get_mut(bh).listen(80).unwrap();
            a_set.get_mut(ah).connect(a.context(), (remote, 80), 1234).unwrap();
            for _ in 0..8 {
                a.poll(Instant::ZERO, &mut a_device, &mut a_set);
                b_device.rx_queue.append(&mut a_device.tx_queue);
                b.poll(Instant::ZERO, &mut b_device, &mut b_set);
                a_device.rx_queue.append(&mut b_device.tx_queue);
            }
            assert_eq!(a_set.get(ah).state(), tcp::State::Established);
            assert_eq!(b_set.get(bh).state(), tcp::State::Established);
            a_set.get_mut(ah).close();
            if orphaned { a_set.orphan(ah, Instant::ZERO); }
            a.poll(Instant::ZERO, &mut a_device, &mut a_set);
            b_device.rx_queue.append(&mut a_device.tx_queue);
            b.poll(Instant::ZERO, &mut b_device, &mut b_set);
            b_set.get_mut(bh).close();
            if orphaned { b_set.orphan(bh, Instant::ZERO); }
            for _ in 0..8 {
                b.poll(Instant::ZERO, &mut b_device, &mut b_set);
                a_device.rx_queue.append(&mut b_device.tx_queue);
                a.poll(Instant::ZERO, &mut a_device, &mut a_set);
                b_device.rx_queue.append(&mut a_device.tx_queue);
            }
            assert_eq!(b_set.get(bh).state(), tcp::State::Closed);
            let expected_b = [bh];
            assert_reapable(&mut b_set, if orphaned { &expected_b } else { &[] });
            assert_eq!(a_set.get(ah).state(), tcp::State::TimeWait);
            assert_reapable(&mut a_set, &[]);
            if reset_with_syn {
                let listener = a_set.add(buffered());
                a_set.get_mut(listener).listen(1234).unwrap();
                b.poll_maintenance(Instant::from_millis(1));
                b_set.get_mut(bh).connect(b.context(), (crate::wire::IpAddress::v4(192, 168, 1, 1), 1234), 80).unwrap();
                b.poll_egress(Instant::from_millis(1), &mut b_device, &mut b_set);
                let bytes = b_device.tx_queue.front_mut().unwrap();
                let mut ip = crate::wire::Ipv4Packet::new_unchecked(bytes.as_mut_slice());
                let (src, dst) = (ip.src_addr().into(), ip.dst_addr().into());
                let mut syn = crate::wire::TcpPacket::new_unchecked(ip.payload_mut());
                syn.set_seq_number(syn.seq_number() + 3);
                syn.fill_checksum(&src, &dst);
                a_device.rx_queue.append(&mut b_device.tx_queue);
                a.poll(Instant::from_millis(1), &mut a_device, &mut a_set);
                assert_eq!(a_set.get(listener).state(), tcp::State::SynReceived);
            } else {
                a.poll_egress(Instant::from_secs(10), &mut a_device, &mut a_set);
            }
            assert_eq!(a_set.get(ah).state(), tcp::State::Closed);
            assert_eq!(a_set.get(ah).remote_endpoint(), None);
            let expected_a = [ah];
            assert_reapable(&mut a_set, if orphaned { &expected_a } else { &[] });
            a.poll_egress(Instant::from_secs(11), &mut a_device, &mut a_set);
            assert_reapable(&mut a_set, &[]);
        }
    }

    #[cfg(feature = "medium-ip")]
    #[test]
    fn reapable_retry_limit_and_ingress_rst() {
        use crate::phy::Medium;
        use crate::wire::{IpAddress, IpCidr};

        for (orphaned, rst) in [(true, false), (false, false), (true, true), (false, true)] {
            let (mut a, mut a_set, mut a_device) = crate::tests::setup(Medium::Ip);
            let (mut b, mut b_set, mut b_device) = crate::tests::setup(Medium::Ip);
            let remote = IpAddress::v4(192, 168, 1, 2);
            b.update_ip_addrs(|addrs| {
                addrs.clear();
                addrs.push(IpCidr::new(remote, 24)).unwrap();
            });
            let buffered = || tcp::Socket::new(tcp::RxBuffer::new(64), tcp::SocketBuffer::new(vec![0; 64]));
            let ah = a_set.add(buffered());
            let bh = b_set.add(buffered());
            b_set.get_mut(bh).listen(80).unwrap();
            a_set.get_mut(ah).connect(a.context(), (remote, 80), 1234).unwrap();
            for _ in 0..8 {
                a.poll(Instant::ZERO, &mut a_device, &mut a_set);
                b_device.rx_queue.append(&mut a_device.tx_queue);
                b.poll(Instant::ZERO, &mut b_device, &mut b_set);
                a_device.rx_queue.append(&mut b_device.tx_queue);
            }
            assert_eq!(a_set.get(ah).state(), tcp::State::Established);
            a_set.get_mut(ah).close();
            if orphaned { a_set.orphan(ah, Instant::ZERO); }
            a.poll_egress(Instant::ZERO, &mut a_device, &mut a_set);
            if rst {
                b_set.get_mut(bh).abort();
                b.poll_egress(Instant::from_millis(1), &mut b_device, &mut b_set);
                a_device.rx_queue.append(&mut b_device.tx_queue);
                a.poll(Instant::from_millis(1), &mut a_device, &mut a_set);
            } else {
                let mut now = Instant::ZERO;
                for _ in 0..10_000 {
                    if a_set.get(ah).state() == tcp::State::Closed
                        || (!orphaned && a_device.tx_queue.len() == 10) {
                        break;
                    }
                    now = a.poll_at(now, &mut a_set).unwrap();
                    a.poll_egress(now, &mut a_device, &mut a_set);
                }
                assert_eq!(a_device.tx_queue.len(), if orphaned { 9 } else { 10 });
            }
            if orphaned || rst {
                assert_eq!(a_set.get(ah).state(), tcp::State::Closed);
                assert_eq!(a_set.get(ah).remote_endpoint(), None);
            } else {
                assert_eq!(a_set.get(ah).state(), tcp::State::FinWait1);
                assert!(a_set.get(ah).remote_endpoint().is_some());
            }
            let expected = [ah];
            assert_reapable(&mut a_set, if orphaned { &expected } else { &[] });
            assert_reapable(&mut b_set, &[]);
        }
    }

    #[test]
    fn orphan_stale_handle_panics() {
        let mut set = TcpSet::new(vec![]);
        let stale = set.add(socket());
        set.remove(stale);
        let current = set.add(socket());
        assert_panics(INVALID, || set.orphan(stale, Instant::ZERO));
        assert_eq!(set.get(current).state(), tcp::State::Closed);
    }

    #[cfg(feature = "medium-ip")]
    #[test]
    fn orphan_established_schedules_fin_and_close_deadline() {
        use crate::phy::Medium;
        use crate::wire::{IpAddress, IpCidr, Ipv4Packet, TcpPacket};

        let (mut a, mut a_set, mut a_device) = crate::tests::setup(Medium::Ip);
        let (mut b, mut b_set, mut b_device) = crate::tests::setup(Medium::Ip);
        let remote = IpAddress::v4(192, 168, 1, 2);
        b.update_ip_addrs(|addrs| {
            addrs.clear();
            addrs.push(IpCidr::new(remote, 24)).unwrap();
        });
        let buffered =
            || tcp::Socket::new(tcp::RxBuffer::new(64), tcp::SocketBuffer::new(vec![0; 64]));
        let a_handle = a_set.add(buffered());
        let b_handle = b_set.add(buffered());
        b_set.get_mut(b_handle).listen(80).unwrap();
        a_set.get_mut(a_handle).connect(a.context(), (remote, 80), 1234).unwrap();
        for _ in 0..8 {
            a.poll(Instant::ZERO, &mut a_device, &mut a_set);
            b_device.rx_queue.append(&mut a_device.tx_queue);
            b.poll(Instant::ZERO, &mut b_device, &mut b_set);
            a_device.rx_queue.append(&mut b_device.tx_queue);
        }
        assert_eq!(a_set.get(a_handle).state(), tcp::State::Established);
        assert_eq!(b_set.get(b_handle).state(), tcp::State::Established);
        assert_eq!(a.poll_at(Instant::ZERO, &mut a_set), None);
        assert!(a_device.tx_queue.is_empty());
        a_set.orphan(a_handle, Instant::from_millis(10));
        assert_eq!(a_set.get(a_handle).state(), tcp::State::FinWait1);
        a.poll_egress(Instant::from_millis(10), &mut a_device, &mut a_set);
        assert_eq!(a_device.tx_queue.len(), 1);
        let ip = Ipv4Packet::new_checked(a_device.tx_queue.front().unwrap().as_slice()).unwrap();
        let segment = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(segment.fin());
        assert!(!segment.rst());
        b_device.rx_queue.append(&mut a_device.tx_queue);
        b.poll(Instant::from_millis(20), &mut b_device, &mut b_set);
        assert_eq!(b_set.get(b_handle).state(), tcp::State::CloseWait);
        a_device.rx_queue.append(&mut b_device.tx_queue);
        a.poll(Instant::from_millis(20), &mut a_device, &mut a_set);
        assert_eq!(a_set.get(a_handle).state(), tcp::State::FinWait2);
        // The timer wheel reports a boundary no later than the 60 s deadline.
        let at = a.poll_at(Instant::from_millis(20), &mut a_set).unwrap();
        assert!(at > Instant::from_millis(20) && at <= Instant::from_millis(60_020));
        a.poll_egress(Instant::from_millis(60_019), &mut a_device, &mut a_set);
        assert_eq!(a_set.get(a_handle).state(), tcp::State::FinWait2);
        a.poll_egress(Instant::from_millis(60_020), &mut a_device, &mut a_set);
        assert_eq!(a_set.get(a_handle).state(), tcp::State::Closed);
        assert_eq!(a_set.get(a_handle).remote_endpoint(), None);
        assert!(a_device.tx_queue.is_empty());
        assert_reapable(&mut a_set, &[a_handle]);
        a.poll_egress(Instant::from_millis(60_021), &mut a_device, &mut a_set);
        assert_reapable(&mut a_set, &[]);
        assert_reapable(&mut b_set, &[]);
    }

    #[test]
    fn tcp_storage_line_map() {
        use core::mem::{align_of, offset_of, size_of};

        let storage = TcpStorage {
            generation: 0,
            admitted_rx_budget: 0,
            inner: Some(Item {
                meta: Meta::default(),
                socket: socket(),
            }),
        };
        let base = &storage as *const _ as usize;
        let item = storage.inner.as_ref().unwrap();
        let item_offset = item as *const _ as usize - base;
        let meta_offset = item_offset + offset_of!(Item<'static>, meta);
        let socket_offset = item_offset + offset_of!(Item<'static>, socket);
        let meta_offsets = super::super::socket_meta::meta_field_offsets();
        let socket_offsets = tcp::socket_field_offsets();

        std::println!(
            "TcpStorage: {}; align: {}; Item: {}; Option<Item>: {}; Meta: {}; Socket: {}",
            size_of::<TcpStorage<'static>>(),
            align_of::<TcpStorage<'static>>(),
            size_of::<Item<'static>>(),
            size_of::<Option<Item<'static>>>(),
            size_of::<Meta>(),
            size_of::<tcp::Socket<'static>>(),
        );
        std::println!(
            "slot: generation {}; inner {}; Item {}; Meta {}; Socket {}",
            offset_of!(TcpStorage<'static>, generation),
            offset_of!(TcpStorage<'static>, inner),
            item_offset,
            meta_offset,
            socket_offset,
        );
        for &(name, offset) in meta_offsets {
            std::println!("Meta.{name}: relative {offset}; slot {}", meta_offset + offset);
        }
        for &(name, offset) in socket_offsets {
            std::println!(
                "Socket.{name}: relative {offset}; slot {}; line {}",
                socket_offset + offset,
                (socket_offset + offset) / 64,
            );
        }

        assert_eq!(size_of::<TcpStorage<'static>>(), 576);
        assert_eq!(align_of::<TcpStorage<'static>>(), 64);
        assert_eq!(size_of::<Meta>(), 112);
        assert_eq!(size_of::<tcp::Socket<'static>>(), 408);
        assert_eq!(size_of::<Option<Item<'static>>>(), size_of::<Item<'static>>());
        assert_eq!(offset_of!(TcpStorage<'static>, generation), 0);
        assert_eq!(offset_of!(TcpStorage<'static>, inner), 8);
        assert_eq!(item_offset, 8);
        assert_eq!(offset_of!(Item<'static>, meta), 0);
        assert_eq!(offset_of!(Item<'static>, socket), 112);
        assert_eq!(meta_offset, 8);
        assert_eq!(socket_offset, 120);
        assert_eq!(
            meta_offsets,
            &[("tcp_template", 0), ("neighbor_state", 72), ("next_hop", 88)],
        );
        let expected_offsets = [
            ("hop_limit", 0),
            ("ack_delay_enabled", 2),
            ("rx_fin_received", 3),
            ("in_rto_loss_episode", 4),
            ("remote_has_sack", 5),
            ("timer", 8),
            ("ack_at", 24),
            ("local_seq_no", 32),
            ("remote_last_ack", 48),
            ("remote_win_len", 60),
            ("state", 64),
            ("recover_valid", 71),
            ("tuple", 72),
            ("max_snd_wnd", 92),
            ("rx_fin_seq", 100),
            ("rx_seg_bytes", 132),
            ("tx_buffer", 136),
            ("rtte", 176),
            ("congestion_controller", 200),
            ("rx_buffer", 272),
            ("ack_delay_us", 336),
            ("retransmits", 344),
            ("loss_events", 352),
            ("initial_window", 360),
            ("listen_endpoint", 368),
            ("bytes_acked", 376),
            ("rcv_mss", 384),
            ("challenge_ack_timer", 392),
            ("rx_refused_segments", 400),
            ("mss_cap", 404),
            ("reset_by_peer", 407),
        ];
        for (name, expected) in expected_offsets {
            let &(_, actual) = socket_offsets
                .iter()
                .find(|&&(field, _)| field == name)
                .unwrap();
            assert_eq!(actual, expected, "Socket.{name} offset");
        }
        let expected_lines = [
            ("hop_limit", 1),
            ("local_rx_dup_acks", 1),
            ("ack_delay_enabled", 1),
            ("rx_fin_received", 1),
            ("in_rto_loss_episode", 1),
            ("remote_has_sack", 1),
            ("timer", 2),
            ("ack_at", 2),
            ("local_seq_no", 2),
            ("remote_seq_no", 2),
            ("remote_last_seq", 2),
            ("remote_max_seq", 2),
            ("remote_last_ack", 2),
            ("remote_last_win_bytes", 2),
            ("remote_win_len", 2),
            ("state", 2),
            ("ack_kind", 2),
            ("remote_win_shift", 2),
            ("pending_fast_retransmit", 2),
            ("remote_last_ack_is_marker", 2),
            ("local_rx_last_seq_valid", 2),
            ("local_rx_last_ack_valid", 2),
            ("recover_valid", 2),
            ("tuple", 3),
            ("remote_win_scale", 3),
            ("remote_mss", 3),
            ("connection_mss_cap", 3),
            ("max_snd_wnd", 3),
            ("remote_win_seq", 3),
            ("rx_fin_seq", 3),
            ("local_rx_last_seq", 3),
            ("local_rx_last_ack", 3),
            ("recover", 3),
            ("rto_us", 3),
            ("rto_backoff", 3),
            ("rx_mbuf_cap", 3),
            ("rx_seg_bytes", 3),
            ("tx_buffer", 4),
            ("rtte", 4),
            ("congestion_controller", 5),
            ("rx_buffer", 6),
            ("ack_delay_us", 7),
            ("retransmits", 7),
            ("loss_events", 7),
            ("initial_window", 7),
            ("listen_endpoint", 7),
            ("bytes_acked", 7),
            ("rcv_mss", 7),
            ("challenge_ack_timer", 8),
            ("rx_refused_segments", 8),
            ("mss_cap", 8),
            ("reset_by_peer", 8),
        ];
        assert_eq!(socket_offsets.len(), expected_lines.len());
        for (&(name, offset), (expected_name, expected_line)) in
            socket_offsets.iter().zip(expected_lines)
        {
            assert_eq!(name, expected_name);
            assert_eq!((120 + offset) / 64, expected_line, "Socket.{name} line");
        }
    }

    #[test]
    fn tcp_set_slots_are_cache_line_aligned() {
        let set = TcpSet::new(vec![
            TcpStorage::EMPTY,
            TcpStorage::EMPTY,
            TcpStorage::EMPTY,
        ]);
        assert_eq!(set.sockets.len(), 3);
        for (index, slot) in set.sockets.iter().enumerate() {
            assert_eq!(slot as *const _ as usize % 64, 0, "slot {index}");
        }
    }

    fn assert_panics(message: &str, f: impl FnOnce()) {
        let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_err();
        let actual = payload.downcast_ref::<&str>().copied().or_else(|| {
            payload
                .downcast_ref::<std::string::String>()
                .map(|s| s.as_str())
        });
        assert_eq!(actual, Some(message));
    }

    #[test]
    fn template_rejects_zero_source_port() {
        use crate::iface::header_template::TcpTemplate;
        use crate::wire::{EthernetAddress, IpProtocol, Ipv4Address, Ipv4Repr};

        let ip = Ipv4Repr {
            src_addr: Ipv4Address::new(192, 168, 1, 1),
            dst_addr: Ipv4Address::new(192, 168, 1, 2),
            next_header: IpProtocol::Tcp,
            payload_len: 20,
            hop_limit: 64,
        };
        assert_panics("TCP template source port must be nonzero", || {
            TcpTemplate::new(
                EthernetAddress([2, 0, 0, 0, 0, 1]),
                EthernetAddress([2, 0, 0, 0, 0, 2]),
                &ip,
                0,
                80,
                0,
            );
        });
    }

    fn handles(set: &TcpSet) -> Vec<usize> {
        set.iter().map(|(h, _)| h.index).collect()
    }

    #[test]
    fn flow_slot_is_one_aligned_line() {
        assert_eq!(core::mem::size_of::<FlowSlot>(), 64);
        assert_eq!(core::mem::align_of::<FlowSlot>(), 64);

        let set = TcpSet::new(vec![TcpStorage::EMPTY, TcpStorage::EMPTY]);
        assert_eq!((&set.flow_slots[0] as *const FlowSlot as usize) % 64, 0);
        assert_eq!((&set.flow_slots[1] as *const FlowSlot as usize) % 64, 0);
    }

    #[cfg(feature = "medium-ip")]
    #[test]
    fn remove_discards_unread_received_bytes() {
        use crate::phy::Medium;
        use crate::wire::IpAddress;

        let (mut a, mut a_set, mut a_device) = crate::tests::setup(Medium::Ip);
        let (mut b, mut b_set, mut b_device) = crate::tests::setup(Medium::Ip);
        let remote = IpAddress::v4(192, 168, 1, 2);
        b.update_ip_addrs(|addrs| {
            addrs.clear();
            addrs.push(crate::wire::IpCidr::new(remote, 24)).unwrap();
        });
        let buffered =
            || tcp::Socket::new(tcp::RxBuffer::new(64), tcp::SocketBuffer::new(vec![0; 64]));
        let a_handle = a_set.add(buffered());
        let b_handle = b_set.add(buffered());
        b_set.get_mut(b_handle).listen(80).unwrap();
        a_set
            .get_mut(a_handle)
            .connect(a.context(), (remote, 80), 1234)
            .unwrap();
        let drive = |a: &mut crate::iface::Interface,
                     a_set: &mut TcpSet,
                     a_device: &mut crate::tests::TestingDevice,
                     b: &mut crate::iface::Interface,
                     b_set: &mut TcpSet,
                     b_device: &mut crate::tests::TestingDevice| {
            for _ in 0..8 {
                a.poll(Instant::ZERO, a_device, a_set);
                b_device.rx_queue.append(&mut a_device.tx_queue);
                b.poll(Instant::ZERO, b_device, b_set);
                a_device.rx_queue.append(&mut b_device.tx_queue);
            }
        };
        drive(
            &mut a,
            &mut a_set,
            &mut a_device,
            &mut b,
            &mut b_set,
            &mut b_device,
        );
        assert_eq!(a_set.get(a_handle).state(), tcp::State::Established);
        assert_eq!(b_set.get(b_handle).state(), tcp::State::Established);
        assert_eq!(a_set.get_mut(a_handle).send_slice(b"unread"), Ok(6));
        drive(
            &mut a,
            &mut a_set,
            &mut a_device,
            &mut b,
            &mut b_set,
            &mut b_device,
        );
        assert_eq!(b_set.get(b_handle).recv_queue(), 6);
        assert_eq!(b_set.get_mut(b_handle).send_slice(b"queued"), Ok(6));
        let (removed, _) = b_set.take(b_handle);
        assert_eq!(removed.recv_queue(), 0);
        assert_eq!(removed.recv_capacity(), 64);
        assert_eq!(removed.send_queue(), 6);
        assert_eq!(removed.state(), tcp::State::Established);
        let b_handle = b_set.add(removed);
        assert_eq!(a_set.get_mut(a_handle).send_slice(b"next"), Ok(4));
        drive(
            &mut a,
            &mut a_set,
            &mut a_device,
            &mut b,
            &mut b_set,
            &mut b_device,
        );
        let mut bytes = Vec::new();
        while let Some(frame) = b_set.get_mut(b_handle).recv().unwrap() {
            bytes.extend_from_slice(frame.payload());
        }
        assert_eq!(bytes.len(), 4);
        assert_eq!(&bytes, b"next");
    }

    #[cfg(feature = "medium-ip")]
    #[test]
    fn add_admitted_preserves_configured_rx_budget() {
        use crate::phy::Medium;
        use crate::wire::IpAddress;

        let mut set = TcpSet::new(vec![]);
        let config = tcp::Config { rx_capacity: 4096, tx_capacity: 64, mss_cap: Some(100) };
        let budget = tcp::rx_mbuf_budget(&config, 1500);
        let handle = set.add_admitted(
            &config,
            1500,
            super::super::DropQueue::with_capacity(1, #[cfg(feature = "udp-set")] 0),
        );
        // Raising the cap after admission must not change the admitted frame count.
        let (mut iface, _, _) = crate::tests::setup(Medium::Ip);
        let socket = set.get_mut(handle);
        socket.set_mss_cap(Some(1000));
        socket
            .connect(iface.context(), (IpAddress::v4(192, 168, 1, 2), 80), 1234)
            .unwrap();
        assert_eq!(socket.state(), tcp::State::SynSent);
        // 4096 bytes / 100-byte frames = 41; a 1000-byte cap would give the six-frame floor.
        assert_eq!(budget, 41);
        assert_eq!(socket.rx_frame_cap(), budget);
    }

    #[test]
    fn add_reuses_lowest_free_slot() {
        let mut set = TcpSet::new(vec![]);
        let h: Vec<_> = (0..130).map(|_| set.add(socket())).collect();
        set.remove(h[70]);
        set.remove(h[3]);
        set.remove(h[129]);
        assert_eq!(set.add(socket()), at(3, 1));
        assert_eq!(set.add(socket()), at(70, 1));
        assert_eq!(set.add(socket()), at(129, 1));
        assert_eq!(set.add(socket()), at(130, 0));
    }

    #[test]
    fn add_to_presized_storage_takes_lowest_empty_slot() {
        let mut storage = vec![];
        storage.resize_with(65, || TcpStorage::EMPTY);
        let mut set = TcpSet::new(storage);
        for i in 0..65 {
            assert_eq!(set.add(socket()), at(i, 0));
        }
        set.remove(at(64, 0));
        assert_eq!(set.add(socket()), at(64, 1));
        assert_eq!(set.sockets.len(), 65);
    }

    #[test]
    #[should_panic(expected = "adding a socket to a full TcpSet")]
    fn add_to_full_borrowed_storage_panics() {
        let mut storage: [TcpStorage; 65] = core::array::from_fn(|_| TcpStorage::EMPTY);
        let mut set = TcpSet::new(&mut storage[..]);
        for _ in 0..65 {
            set.add(socket());
        }
        set.add(socket());
    }

    #[test]
    fn capacity_count_tracks_interleaved_add_remove() {
        let mut set = TcpSet::new(vec![]);
        assert_eq!(set.len(), 0);
        let a = set.add(socket());
        let b = set.add(socket());
        let c = set.add(socket());
        assert_eq!(set.len(), 3);
        set.remove(b);
        assert_eq!(set.len(), 2);
        assert_eq!(handles(&set), vec![a.index, c.index]);
        let b2 = set.add(socket());
        set.remove(a);
        set.remove(c);
        assert_eq!(set.len(), 1);
        assert_eq!(handles(&set), vec![b.index]);
        set.remove(b2);
        assert_eq!(set.len(), 0);
        assert_eq!(set.len(), set.iter().count());
    }

    #[test]
    fn remove_of_empty_slot_panics_and_changes_nothing() {
        let mut set = TcpSet::new(vec![]);
        let a = set.add(socket());
        let b = set.add(socket());
        set.remove(a);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| set.remove(a)));
        assert!(result.is_err());
        assert_eq!(set.len(), 1);
        assert_eq!(handles(&set), vec![b.index]);
        assert_eq!(set.add(socket()), at(a.index, 1));
    }

    #[test]
    fn presized_storage_grows_past_its_last_word() {
        let mut storage = vec![];
        storage.resize_with(64, || TcpStorage::EMPTY);
        let mut set = TcpSet::new(storage);
        for i in 0..66 {
            assert_eq!(set.add(socket()), at(i, 0));
        }
        set.remove(at(65, 0));
        set.remove(at(64, 0));
        assert_eq!(set.add(socket()), at(64, 1));
        assert_eq!(set.len(), 65);
        assert_eq!(set.len(), set.iter().count());
    }

    #[test]
    fn stale_handle_after_reuse_panics() {
        let mut set = TcpSet::new(vec![]);
        let a = set.add(socket());
        set.remove(a);
        let b = set.add(socket());
        assert_eq!(b.to_string(), a.to_string());
        assert_ne!(b, a);
        assert_panics(INVALID, || {
            set.get_mut(a);
        });
        assert_panics(INVALID, || {
            set.remove(a);
        });
        assert_eq!(set.len(), 1);
        assert_eq!(set.iter().map(|(h, _)| h).collect::<Vec<_>>(), vec![b]);
        set.get_mut(b);
    }

    #[test]
    #[should_panic(expected = "handle does not refer to a valid socket")]
    fn stale_handle_after_remove_panics() {
        let mut set = TcpSet::new(vec![]);
        let a = set.add(socket());
        set.remove(a);
        set.get(a);
    }

    #[test]
    fn generation_survives_storage_growth() {
        let mut set = TcpSet::new(vec![]);
        let h: Vec<_> = (0..70).map(|_| set.add(socket())).collect();
        for (i, handle) in h.iter().enumerate() {
            assert_eq!(*handle, at(i, 0));
        }
        set.remove(h[66]);
        let reused = set.add(socket());
        assert_eq!(reused, at(66, 1));
        set.remove(reused);
        assert_eq!(set.add(socket()), at(66, 2));
        assert_eq!(set.add(socket()), at(70, 0));
    }

    #[test]
    #[should_panic(expected = "handle does not refer to a valid socket")]
    fn stale_handle_get_after_reuse_panics() {
        let mut set = TcpSet::new(vec![]);
        let a = set.add(socket());
        set.remove(a);
        set.add(socket());
        set.get(a);
    }

    #[test]
    fn generation_overflow_panics_and_changes_nothing() {
        let mut set = TcpSet::new(vec![]);
        set.add(socket());
        set.sockets[0].generation = u64::MAX;
        let a = set.iter().next().unwrap().0;
        assert_panics("socket slot generation overflow", || {
            set.remove(a);
        });
        assert_eq!(set.len(), 1);
        assert_eq!(set.iter().map(|(h, _)| h).collect::<Vec<_>>(), vec![a]);
        set.get_mut(a);
        assert_eq!(set.add(socket()), at(1, 0));
    }

    #[test]
    fn iter_handles_match_add_after_reuse() {
        let mut set = TcpSet::new(vec![]);
        let old = set.add(socket());
        set.remove(old);
        let reused = set.add(socket());
        assert_eq!(reused, at(old.index, old.generation + 1));
        assert_eq!(set.iter().map(|(h, _)| h).collect::<Vec<_>>(), vec![reused]);
        assert_eq!(
            set.iter_mut().map(|(h, _)| h).collect::<Vec<_>>(),
            vec![reused],
        );
        assert_panics(INVALID, || {
            set.get(old);
        });
    }

    #[test]
    fn tcp_set_iter_yields_tcp_sockets_with_handles() {
        let mut set = TcpSet::new(vec![]);
        let a = set.add(socket());
        let b = set.add(socket());
        let c = set.add(socket());
        set.remove(b);
        let b2 = set.add(socket());
        assert_eq!(b2, at(b.index, 1));
        assert_ne!(b2, b);

        assert_eq!(
            set.iter().map(|(h, _)| h).collect::<Vec<_>>(),
            vec![a, b2, c]
        );
        for (handle, socket) in set.iter() {
            assert!(core::ptr::eq(socket, set.get(handle)));
        }
    }

    #[cfg(feature = "medium-ip")]
    mod flow_index {
        use super::*;
        use crate::phy::Medium;
        use crate::wire::IpAddress;

        fn endpoints() -> (IpEndpoint, IpEndpoint) {
            (
                IpEndpoint::new(IpAddress::v4(192, 168, 1, 1), 1234),
                IpEndpoint::new(IpAddress::v4(192, 168, 1, 2), 65000),
            )
        }

        fn connected(local: IpEndpoint, remote: IpEndpoint) -> tcp::Socket<'static> {
            let (mut iface, _, _) = crate::tests::setup(Medium::Ip);
            let mut socket = socket();
            socket.connect(iface.context(), remote, local).unwrap();
            assert_eq!(socket.state(), tcp::State::SynSent);
            socket
        }

        fn listener(port: u16) -> tcp::Socket<'static> {
            let mut socket = socket();
            socket.listen(port).unwrap();
            socket
        }

        #[test]
        fn mutable_access_unlinks_tcp_timer() {
            let (mut iface, mut set, mut device) = crate::tests::setup(Medium::Ip);
            let (local, remote) = endpoints();
            let handle = set.add(connected(local, remote));
            iface.poll_egress(Instant::ZERO, &mut device, &mut set);
            iface.poll_at(Instant::ZERO, &mut set);
            assert!(set.wheel.has_pending());
            assert_ne!(
                set.flow_slots[handle.index].timer_position,
                WheelPosition::Unlinked
            );
            set.get_mut(handle);
            assert!(!set.wheel.has_pending());
            assert_eq!(
                set.flow_slots[handle.index].timer_position,
                WheelPosition::Unlinked
            );
            assert!(set.flow_slots[handle.index].dirty);
            iface.poll_at(Instant::ZERO, &mut set);
            assert!(set.wheel.has_pending());
            set.iter_mut().next().unwrap();
            assert!(!set.wheel.has_pending());
            iface.poll_at(Instant::ZERO, &mut set);
            assert!(set.wheel.has_pending());
            set.remove(handle);
            assert!(!set.wheel.has_pending());
            assert_eq!(iface.poll_at(Instant::ZERO, &mut set), None);
        }

        #[test]
        fn flow_index_tracks_add_remove_and_listen() {
            let (mut iface, _, _) = crate::tests::setup(Medium::Ip);
            let (local, remote) = endpoints();
            let mut set = TcpSet::new(vec![]);
            let first = set.add(socket());
            set.check_flow_index();
            assert_eq!(set.tcp_lookup(local, remote, true), None);
            set.get_mut(first).listen(local.port).unwrap();
            set.check_flow_index();
            iface.classify_dirty(&mut set, Instant::ZERO);
            set.check_flow_index();
            assert_eq!(set.tcp_lookup(local, remote, true), Some(first.index));
            assert_eq!(set.tcp_lookup(local, remote, false), None);
            let second = set.add(listener(local.port));
            set.check_flow_index();
            assert_eq!(set.tcp_lookup(local, remote, true), Some(first.index));
            assert_eq!(set.tcp_lookup(local, remote, false), None);
            set.remove(first);
            set.check_flow_index();
            assert_eq!(set.tcp_lookup(local, remote, true), Some(second.index));
            assert_eq!(set.tcp_lookup(local, remote, false), None);
            set.get_mut(second).close();
            iface.classify_dirty(&mut set, Instant::ZERO);
            set.check_flow_index();
            assert_eq!(set.tcp_lookup(local, remote, true), None);
            set.get_mut(second).listen(local.port).unwrap();
            iface.classify_dirty(&mut set, Instant::ZERO);
            set.remove(second);
            set.check_flow_index();
            assert_eq!(set.tcp_lookup(local, remote, true), None);
        }

        #[test]
        fn flow_index_exact_groups_are_ascending() {
            let (mut iface, _, _) = crate::tests::setup(Medium::Ip);
            let (local, remote) = endpoints();
            let mut set = TcpSet::new(vec![]);
            let handles: Vec<_> = (0..3).map(|_| set.add(socket())).collect();
            for index in [2, 0, 1] {
                *set.get_mut(handles[index]) = connected(local, remote);
                set.check_flow_index();
                iface.classify_dirty(&mut set, Instant::ZERO);
                set.check_flow_index();
            }
            assert_eq!(set.flow_slots[0].next, 1);
            assert_eq!(set.flow_slots[1].next, 2);
            assert_eq!(set.flow_slots[2].next, usize::MAX);
            assert_eq!(set.tcp_lookup(local, remote, true), Some(0));
            assert_eq!(set.tcp_lookup(local, remote, false), Some(0));
            set.remove(handles[0]);
            set.check_flow_index();
            assert_eq!(set.tcp_lookup(local, remote, false), Some(1));
            let reused = set.add(connected(local, remote));
            assert_eq!(reused.index, 0);
            set.remove(handles[1]);
            set.check_flow_index();
            assert_eq!(set.flow_slots[0].next, 2);
            set.remove(handles[2]);
            set.check_flow_index();
            assert_eq!(set.flow_slots[0].next, usize::MAX);
            set.remove(reused);
            set.check_flow_index();
            assert_eq!(set.tcp_lookup(local, remote, false), None);
        }

        #[test]
        fn flow_index_replaced_socket_is_resynced() {
            let (mut iface, _, _) = crate::tests::setup(Medium::Ip);
            let (local, remote) = endpoints();
            let other_local = IpEndpoint {
                port: 4321,
                ..local
            };
            let mut set = TcpSet::new(vec![]);
            let handle = set.add(connected(local, remote));
            *set.get_mut(handle) = connected(other_local, remote);
            set.check_flow_index();
            assert_eq!(set.tcp_lookup(local, remote, false), Some(handle.index));
            iface.classify_dirty(&mut set, Instant::ZERO);
            set.check_flow_index();
            assert_eq!(set.tcp_lookup(local, remote, false), None);
            assert_eq!(
                set.tcp_lookup(other_local, remote, false),
                Some(handle.index)
            );
        }

        #[test]
        fn flow_index_survives_storage_growth() {
            let (mut iface, _, _) = crate::tests::setup(Medium::Ip);
            let (local, remote) = endpoints();
            let mut set = TcpSet::new(vec![TcpStorage::EMPTY]);
            let first = set.add(connected(local, remote));
            for index in 1..70 {
                let port = local.port + index as u16;
                let handle = set.add(listener(port));
                assert_eq!(handle.index, index);
                set.check_flow_index();
                assert_eq!(set.tcp_lookup(local, remote, false), Some(first.index));
                for expected in 1..=index {
                    let dst = IpEndpoint {
                        port: local.port + expected as u16,
                        ..local
                    };
                    assert_eq!(set.tcp_lookup(dst, remote, true), Some(expected));
                }
            }
            assert_eq!(set.sockets.len(), 70);
            assert_eq!(set.flow_slots.len(), 70);
            assert!(set.dirty_list.capacity() >= 70);
            set.get_mut(first).abort();
            set.remove(first);
            set.check_flow_index();
            let replacement = set.add(connected(local, remote));
            set.check_flow_index();
            iface.classify_dirty(&mut set, Instant::ZERO);
            set.check_flow_index();
            assert_eq!(
                set.tcp_lookup(local, remote, false),
                Some(replacement.index)
            );
            std::println!(
                "flow index bytes: FlowSlot={}, dirty index={}, exact table slot={}, listener table slot={}",
                core::mem::size_of::<FlowSlot>(),
                core::mem::size_of::<usize>(),
                core::mem::size_of::<Option<((IpEndpoint, IpEndpoint), usize)>>(),
                core::mem::size_of::<Option<(u16, usize)>>(),
            );
        }

        #[test]
        fn flow_index_filters_bound_listeners_and_keeps_lowest_match() {
            let (local, remote) = endpoints();
            for exact_first in [false, true] {
                let mut set = TcpSet::new(vec![]);
                let mut bound = socket();
                bound.listen((remote.addr, local.port)).unwrap();
                let bound = set.add(bound);
                let (first, second) = if exact_first {
                    (
                        set.add(connected(local, remote)),
                        set.add(listener(local.port)),
                    )
                } else {
                    (
                        set.add(listener(local.port)),
                        set.add(connected(local, remote)),
                    )
                };
                set.check_flow_index();
                let exact = if exact_first { first } else { second };
                assert_eq!(set.tcp_lookup(local, remote, true), Some(exact.index));
                assert_eq!(set.tcp_lookup(local, remote, false), Some(exact.index));
                let dst = IpEndpoint {
                    addr: remote.addr,
                    ..local
                };
                assert_eq!(set.tcp_lookup(dst, remote, true), Some(bound.index));
                set.remove(bound);
                set.check_flow_index();
                assert_eq!(set.tcp_lookup(local, remote, true), Some(exact.index));
            }
        }

        #[test]
        fn flow_index_marks_only_mutably_yielded_slots() {
            let (mut iface, _, _) = crate::tests::setup(Medium::Ip);
            let (local, remote) = endpoints();
            let mut set = TcpSet::new(vec![]);
            let handles: Vec<_> = (0..3).map(|_| set.add(socket())).collect();
            iface.classify_dirty(&mut set, Instant::ZERO);
            set.get(handles[0]);
            assert_eq!(set.iter().count(), 3);
            assert!(set.dirty_list.is_empty());
            drop(set.iter_mut());
            assert!(set.dirty_list.is_empty());
            set.iter_mut().next().unwrap().1.listen(local.port).unwrap();
            set.get_mut(handles[0]);
            set.get_mut(handles[0]);
            assert_eq!(set.dirty_list, vec![0]);
            set.check_flow_index();
            iface.classify_dirty(&mut set, Instant::ZERO);
            set.check_flow_index();
            assert_eq!(set.tcp_lookup(local, remote, true), Some(0));
            for (_, socket) in set.iter_mut() {
                socket.abort();
            }
            assert_eq!(set.dirty_list, vec![0, 1, 2]);
            set.check_flow_index();
            iface.classify_dirty(&mut set, Instant::ZERO);
            iface.classify_dirty(&mut set, Instant::ZERO);
            set.check_flow_index();
            assert_eq!(set.tcp_lookup(local, remote, true), None);
        }

        #[test]
        fn flow_index_constructor_registers_occupied_storage() {
            let (local, remote) = endpoints();
            let mut set = TcpSet::new(vec![]);
            set.add(listener(local.port));
            set.add(connected(local, remote));
            let mut set = TcpSet::new(set.sockets);
            set.check_flow_index();
            assert_eq!(set.tcp_lookup(local, remote, true), Some(1));
            assert_eq!(set.tcp_lookup(local, remote, false), Some(1));
        }
    }
}
