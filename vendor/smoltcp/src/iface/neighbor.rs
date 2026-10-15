// Heads up! Before working on this file you should read, at least,
// the parts of RFC 1122 that discuss ARP.

use crate::table_hash::{C1, finish, mix};
use alloc::vec::Vec;
use core::cell::Cell;
#[cfg(test)]
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::time::{Duration, Instant};
use crate::wire::{HardwareAddress, IpAddress};

/// A cached neighbor.
///
/// A neighbor mapping translates from a protocol address to a hardware address,
/// and contains the timestamp past which the mapping should be discarded.
#[derive(Debug, Clone)]
pub struct Neighbor {
    hardware_addr: HardwareAddress,
    expires_at: Instant,
    silent_until: Instant,
    stale_until: Cell<Option<Instant>>,
}

/// An answer to a neighbor cache lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    /// The neighbor address is in the cache and not expired.
    Found(HardwareAddress),
    Stale {
        hardware_addr: HardwareAddress,
        probe: bool,
    },
    /// The neighbor address is not in the cache, or has expired.
    NotFound,
    /// The neighbor address is not in the cache, or has expired,
    /// and a lookup has been made recently.
    RateLimited,
}

impl Answer {
    /// Returns whether a valid address was found.
    pub(crate) fn found(&self) -> bool {
        match self {
            Answer::Found(_) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
enum Entry {
    Resolved(Neighbor),
    Pending { silent_until: Instant },
}

impl Entry {
    fn expires_at(&self) -> Instant {
        match self {
            Self::Resolved(neighbor) => neighbor.expires_at,
            Self::Pending { silent_until } => *silent_until,
        }
    }
}

/// A neighbor cache holds up to `capacity` neighbors. When full, a new neighbor
/// evicts the entry that expires first; among entries expiring at the same instant,
/// the lowest address goes.
#[derive(Debug)]
pub struct Cache {
    /// Linear-probing slots, a power of two at least twice `capacity` long.
    storage: Vec<Option<(IpAddress, Entry)>>,
    hash_shift: u32,
    len: usize,
    capacity: usize,
    changes: u64,
    next_expiry: Option<Instant>,
    #[cfg(test)]
    pub(crate) lookup_calls: AtomicUsize,
    /// Slot of the last address found. Checked against the slot's address before use,
    /// so moves and removals never make it wrong; it only skips the hash when a Stack
    /// keeps talking to the same neighbor.
    last_found: Cell<usize>,
}

impl Cache {
    /// Minimum delay between discovery requests, in milliseconds.
    pub(crate) const SILENT_TIME: Duration = Duration::from_millis(1_000);

    pub(crate) const STALE_TIME: Duration = Duration::from_micros(
        Self::SILENT_TIME
            .total_micros()
            .checked_mul(3)
            .expect("neighbor stale duration overflow"),
    );

    /// Neighbor entry lifetime, in milliseconds.
    pub(crate) const ENTRY_LIFETIME: Duration = Duration::from_millis(60_000);

    /// Create a cache holding up to `capacity` neighbors.
    ///
    /// # Panics
    /// Panics if `capacity` is 0 or too large to allocate twice over.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity != 0, "Neighbor capacity must be nonzero.");
        let slots = capacity
            .checked_mul(2)
            .and_then(usize::checked_next_power_of_two)
            .expect("Neighbor capacity is too large.");
        Self {
            storage: alloc::vec![None; slots],
            hash_shift: 64 - slots.trailing_zeros(),
            len: 0,
            capacity,
            last_found: Cell::new(0),
            changes: 0,
            next_expiry: None,
            #[cfg(test)]
            lookup_calls: AtomicUsize::new(0),
        }
    }

    fn home(&self, address: &IpAddress) -> usize {
        let hash = match address {
            IpAddress::Ipv4(address) => mix(C1, u32::from_be_bytes(address.octets()) as u64),
        };
        (finish(hash) >> self.hash_shift) as usize
    }

    fn find(&self, address: &IpAddress) -> Result<usize, usize> {
        let last = self.last_found.get();
        if let Some((stored_address, _)) = &self.storage[last]
            && stored_address == address
        {
            return Ok(last);
        }
        let mut index = self.home(address);
        while let Some((stored_address, _)) = &self.storage[index] {
            if stored_address == address {
                self.last_found.set(index);
                return Ok(index);
            }
            index = (index + 1) & (self.storage.len() - 1);
        }
        Err(index)
    }

    fn remove(&mut self, mut hole: usize) -> (IpAddress, Entry) {
        let removed = self.storage[hole].take().unwrap();
        let mask = self.storage.len() - 1;
        let mut index = (hole + 1) & mask;
        while let Some((address, _)) = &self.storage[index] {
            let home = self.home(address);
            if (hole.wrapping_sub(home) & mask) < (index.wrapping_sub(home) & mask) {
                self.storage[hole] = self.storage[index].take();
                hole = index;
            }
            index = (index + 1) & mask;
        }
        self.len -= 1;
        removed
    }

    fn earliest(&self) -> usize {
        self.storage
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                slot.as_ref()
                    .map(|(address, entry)| (index, entry.expires_at(), *address))
            })
            .min_by_key(|(_, expires_at, address)| (*expires_at, *address))
            .expect("empty neighbor cache storage")
            .0
    }

    fn pending_eviction_is_silent(&self, timestamp: Instant) -> bool {
        self.len == self.capacity
            && matches!(
                self.storage[self.earliest()].as_ref().unwrap().1,
                Entry::Pending { silent_until } if timestamp < silent_until
            )
    }

    fn evict_earliest(&mut self) -> (IpAddress, Entry) {
        let removed = self.remove(self.earliest());
        if matches!(removed.1, Entry::Resolved(_)) {
            self.bump();
        }
        removed
    }

    pub fn reset_expiry_if_existing(
        &mut self,
        protocol_addr: IpAddress,
        source_hardware_addr: HardwareAddress,
        timestamp: Instant,
    ) {
        if let Ok(index) = self.find(&protocol_addr)
            && let Entry::Resolved(neighbor) = &mut self.storage[index].as_mut().unwrap().1
        {
            if source_hardware_addr == neighbor.hardware_addr {
                let expired = timestamp >= neighbor.expires_at;
                neighbor.expires_at = timestamp + Self::ENTRY_LIFETIME;
                neighbor.stale_until.set(None);
                {
                    self.next_expiry = Some(
                        self.next_expiry
                            .map_or(neighbor.expires_at, |old| old.min(neighbor.expires_at)),
                    );
                    if expired {
                        self.bump();
                    }
                }
            }
        }
    }

    pub fn update_existing(
        &mut self,
        protocol_addr: IpAddress,
        hardware_addr: HardwareAddress,
        timestamp: Instant,
    ) {
        if let Ok(index) = self.find(&protocol_addr) {
            if matches!(
                &self.storage[index].as_ref().unwrap().1,
                Entry::Resolved(neighbor) if neighbor.hardware_addr == hardware_addr
            ) {
                return;
            }
            self.fill(protocol_addr, hardware_addr, timestamp);
        }
    }

    pub fn fill(
        &mut self,
        protocol_addr: IpAddress,
        hardware_addr: HardwareAddress,
        timestamp: Instant,
    ) {
        debug_assert!(protocol_addr.is_unicast());
        debug_assert!(hardware_addr.is_unicast());

        let expires_at = timestamp + Self::ENTRY_LIFETIME;
        self.fill_with_expiration(protocol_addr, hardware_addr, expires_at);
    }

    pub fn fill_with_expiration(
        &mut self,
        protocol_addr: IpAddress,
        hardware_addr: HardwareAddress,
        expires_at: Instant,
    ) {
        debug_assert!(protocol_addr.is_unicast());
        debug_assert!(hardware_addr.is_unicast());

        {
            self.bump();
            self.next_expiry = Some(
                self.next_expiry
                    .map_or(expires_at, |old| old.min(expires_at)),
            );
        }
        let neighbor = Entry::Resolved(Neighbor {
            silent_until: expires_at,
            stale_until: Cell::new(None),
            expires_at,
            hardware_addr,
        });
        let mut index = match self.find(&protocol_addr) {
            Ok(index) => {
                let old_neighbor = self.storage[index]
                    .replace((protocol_addr, neighbor))
                    .unwrap()
                    .1;
                if let Entry::Resolved(old_neighbor) = old_neighbor
                    && old_neighbor.hardware_addr != hardware_addr
                {
                    net_trace!(
                        "replaced {} => {} (was {})",
                        protocol_addr,
                        hardware_addr,
                        old_neighbor.hardware_addr
                    );
                }
                return;
            }
            Err(index) => index,
        };
        if self.len == self.capacity {
            let (old_protocol_addr, _old_neighbor) = self.evict_earliest();
            index = self.find(&protocol_addr).unwrap_err();
            net_trace!(
                "filled {} => {} (evicted {} => {:?})",
                protocol_addr,
                hardware_addr,
                old_protocol_addr,
                _old_neighbor
            );
        } else {
            net_trace!("filled {} => {} (was empty)", protocol_addr, hardware_addr);
        }
        self.storage[index] = Some((protocol_addr, neighbor));
        self.len += 1;
    }

    pub(crate) fn lookup(&self, protocol_addr: &IpAddress, timestamp: Instant) -> Answer {
        #[cfg(test)]
        self.lookup_calls.fetch_add(1, Ordering::Relaxed);
        assert!(protocol_addr.is_unicast());

        if let Ok(index) = self.find(protocol_addr) {
            match &self.storage[index].as_ref().unwrap().1 {
                Entry::Resolved(neighbor) => {
                    if timestamp < neighbor.expires_at {
                        return Answer::Found(neighbor.hardware_addr);
                    }
                    let stale_until = neighbor.stale_until.get().unwrap_or_else(|| {
                        let stale_until = Instant::from_micros(
                            timestamp
                                .total_micros()
                                .checked_add(Self::STALE_TIME.total_micros() as i64)
                                .expect("neighbor stale expiry overflow"),
                        );
                        neighbor.stale_until.set(Some(stale_until));
                        stale_until
                    });
                    if timestamp < stale_until {
                        return Answer::Stale {
                            hardware_addr: neighbor.hardware_addr,
                            probe: timestamp >= neighbor.silent_until,
                        };
                    }
                    if timestamp < neighbor.silent_until {
                        return Answer::RateLimited;
                    }
                }
                Entry::Pending { silent_until } if timestamp < *silent_until => {
                    return Answer::RateLimited;
                }
                _ => (),
            }
            return Answer::NotFound;
        }
        if self.pending_eviction_is_silent(timestamp) {
            return Answer::RateLimited;
        }
        Answer::NotFound
    }

    pub(crate) fn limit_rate(&mut self, protocol_addr: IpAddress, timestamp: Instant) {
        debug_assert!(protocol_addr.is_unicast());

        let silent_until = Instant::from_micros(
            timestamp
                .total_micros()
                .checked_add(Self::SILENT_TIME.total_micros() as i64)
                .expect("neighbor silence overflow"),
        );
        let index = match self.find(&protocol_addr) {
            Ok(index) => {
                if let Entry::Resolved(neighbor) = &mut self.storage[index].as_mut().unwrap().1 {
                    neighbor.silent_until = silent_until;
                    return;
                }
                index
            }
            Err(index) => {
                if self.pending_eviction_is_silent(timestamp) {
                    return;
                }
                let index = if self.len == self.capacity {
                    self.evict_earliest();
                    self.find(&protocol_addr).unwrap_err()
                } else {
                    index
                };
                self.len += 1;
                index
            }
        };
        self.storage[index] = Some((protocol_addr, Entry::Pending { silent_until }));
    }

    pub(crate) fn flush(&mut self) {
        self.storage.fill(None);
        self.len = 0;
        {
            self.bump();
            self.next_expiry = None;
        }
    }

    pub(crate) fn bump(&mut self) {
        self.changes = self
            .changes
            .checked_add(1)
            .expect("neighbor changes overflow");
    }

    pub(crate) fn changes(&self) -> u64 {
        self.changes
    }

    pub(crate) fn expire(&mut self, timestamp: Instant) {
        let Some(old) = self.next_expiry else {
            return;
        };
        if timestamp < old {
            return;
        }
        let mut expired = false;
        let mut next_expiry: Option<Instant> = None;
        for (_, entry) in self.storage.iter().flatten() {
            let Entry::Resolved(neighbor) = entry else {
                continue;
            };
            if neighbor.expires_at > timestamp {
                next_expiry = Some(
                    next_expiry.map_or(neighbor.expires_at, |old| old.min(neighbor.expires_at)),
                );
            } else if neighbor.expires_at >= old {
                expired = true;
            }
        }
        if expired {
            self.bump();
        }
        self.next_expiry = next_expiry;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::wire::ipv4::test::{MOCK_IP_ADDR_1, MOCK_IP_ADDR_2, MOCK_IP_ADDR_3, MOCK_IP_ADDR_4};

    use crate::wire::EthernetAddress;

    const HADDR_A: HardwareAddress = HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 1]));
    const HADDR_B: HardwareAddress = HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 2]));
    const HADDR_C: HardwareAddress = HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 3]));
    const HADDR_D: HardwareAddress = HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 4]));

    #[test]
    fn update_existing_absent() {
        let mut cache = Cache::new(3);

        cache.update_existing(MOCK_IP_ADDR_1.into(), HADDR_B, Instant::ZERO);
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::ZERO),
            Answer::NotFound
        );
        {
            assert_eq!(cache.len, 0);
            assert_eq!(cache.changes(), 0);
        }
    }

    #[test]
    fn update_existing_pending() {
        let mut cache = Cache::new(3);
        cache.limit_rate(MOCK_IP_ADDR_1.into(), Instant::ZERO);
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::ZERO),
            Answer::RateLimited
        );
        let changes = cache.changes();
        let now = Instant::from_millis(100);
        cache.update_existing(MOCK_IP_ADDR_1.into(), HADDR_B, now);
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), now),
            Answer::Found(HADDR_B)
        );
        assert_eq!(cache.changes(), changes + 1);
        let index = cache.find(&MOCK_IP_ADDR_1.into()).unwrap();
        let Entry::Resolved(neighbor) = &cache.storage[index].as_ref().unwrap().1 else {
            panic!("neighbor remains pending");
        };
        assert_eq!(neighbor.expires_at, now + Cache::ENTRY_LIFETIME);
        assert_eq!(neighbor.silent_until, neighbor.expires_at);
        assert_eq!(cache.len, 1);
    }

    #[test]
    fn update_existing_different_mac() {
        let mut cache = Cache::new(3);

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::ZERO);
        let changes = cache.changes();
        let now = Instant::from_millis(100);
        cache.update_existing(MOCK_IP_ADDR_1.into(), HADDR_B, now);
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), now),
            Answer::Found(HADDR_B)
        );
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::ZERO + Cache::ENTRY_LIFETIME),
            Answer::Found(HADDR_B)
        );
        assert_eq!(cache.changes(), changes + 1);
    }

    #[test]
    fn update_existing_same_mac() {
        let mut cache = Cache::new(3);

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::ZERO);
        let changes = cache.changes();
        let now = Instant::from_millis(10_000);
        cache.update_existing(MOCK_IP_ADDR_1.into(), HADDR_A, now);
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), now),
            Answer::Found(HADDR_A)
        );
        {
            assert_eq!(cache.changes(), changes);
            let index = cache.find(&MOCK_IP_ADDR_1.into()).unwrap();
            let Entry::Resolved(neighbor) = &cache.storage[index].as_ref().unwrap().1 else {
                panic!("resolved neighbor became pending");
            };
            assert_eq!(neighbor.expires_at, Instant::ZERO + Cache::ENTRY_LIFETIME);
            assert_eq!(neighbor.silent_until, neighbor.expires_at);
        }
    }

    #[test]
    fn test_fill() {
        let mut cache = Cache::new(3);

        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0))
                .found()
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0))
                .found()
        );

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0))
                .found()
        );
        assert!(
            !cache
                .lookup(
                    &MOCK_IP_ADDR_1.into(),
                    Instant::from_millis(0) + Cache::ENTRY_LIFETIME * 2
                )
                .found(),
        );

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0))
                .found()
        );
    }

    #[test]
    fn test_expire() {
        let mut cache = Cache::new(3);

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert!(
            !cache
                .lookup(
                    &MOCK_IP_ADDR_1.into(),
                    Instant::from_millis(0) + Cache::ENTRY_LIFETIME * 2
                )
                .found(),
        );
    }

    #[test]
    fn test_replace() {
        let mut cache = Cache::new(3);

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_B, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_B)
        );
    }

    #[test]
    fn test_evict() {
        let mut cache = Cache::new(3);

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(100));
        cache.fill(MOCK_IP_ADDR_2.into(), HADDR_B, Instant::from_millis(50));
        cache.fill(MOCK_IP_ADDR_3.into(), HADDR_C, Instant::from_millis(200));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(1000)),
            Answer::Found(HADDR_B)
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_4.into(), Instant::from_millis(1000))
                .found()
        );

        cache.fill(MOCK_IP_ADDR_4.into(), HADDR_D, Instant::from_millis(300));
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(1000))
                .found()
        );
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_4.into(), Instant::from_millis(1000)),
            Answer::Found(HADDR_D)
        );
    }

    #[test]
    fn test_hush() {
        let mut cache = Cache::new(3);

        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::NotFound
        );

        cache.limit_rate(MOCK_IP_ADDR_1.into(), Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(100)),
            Answer::RateLimited
        );
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(2000)),
            Answer::NotFound
        );
    }

    #[test]
    fn test_flush() {
        let mut cache = Cache::new(3);

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0))
                .found()
        );

        cache.flush();
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0))
                .found()
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0))
                .found()
        );
    }

    mod alloc_tests {
        use super::*;

        fn assert_spread(
            name: &str,
            capacity: usize,
            addresses: impl IntoIterator<Item = IpAddress>,
            max_probe: usize,
        ) {
            let mut cache = Cache::new(capacity);
            assert_eq!(cache.storage.len(), 2 * capacity);
            let mut count = 0;
            for address in addresses {
                cache.fill(address, HADDR_A, Instant::ZERO);
                count += 1;
            }
            let mask = cache.storage.len() - 1;
            let mut longest = 0;
            let mut total = 0;
            let mut at_home = 0;
            for (index, entry) in cache.storage.iter().enumerate() {
                if let Some((address, _)) = entry {
                    assert_eq!(cache.lookup(address, Instant::ZERO), Answer::Found(HADDR_A));
                    let distance = index.wrapping_sub(cache.home(address)) & mask;
                    longest = longest.max(distance);
                    total += distance;
                    at_home += usize::from(distance == 0);
                }
            }
            assert_eq!(count, capacity);
            assert_eq!(cache.len, count);
            std::println!(
                "{name}: max={longest}, mean={total}/{count} ({}), home={at_home}/{count}",
                total as f64 / count as f64,
            );
            assert!(longest <= 40, "{name}: max {longest} > 40");
            assert!(longest <= max_probe, "{name}: max {longest} > {max_probe}");
            assert!(total * 2 <= 3 * count, "{name}: mean {total}/{count} > 1.5");
        }

        #[test]
        fn sequential_addresses_spread() {
            let config = crate::iface::Config::new(HADDR_A);
            assert_eq!(config.neighbor_capacity, 256);
            assert_spread(
                "neighbor default",
                config.neighbor_capacity,
                (1..=256u32).map(|index| {
                    crate::wire::Ipv4Address::from((0x0a000000 + index).to_be_bytes()).into()
                }),
                13,
            );
        }

        #[test]
        fn sequential_subnet_22_addresses_spread() {
            assert_spread(
                "neighbor /22",
                1024,
                (0..1024u32).map(|index| {
                    crate::wire::Ipv4Address::from((0x0a000000 + index).to_be_bytes()).into()
                }),
                27,
            );
        }

        #[test]
        fn sequential_third_octets_spread() {
            assert_spread(
                "neighbor third octet",
                256,
                (0..=255).map(|third| IpAddress::v4(172, 16, third, 1)),
                10,
            );
        }

        #[test]
        fn reviewer_address_stride_65537_spread() {
            assert_spread(
                "neighbor stride 65537",
                128,
                (0..128u32).map(|index| {
                    crate::wire::Ipv4Address::from((0x0a010001 + 65537 * index).to_be_bytes())
                        .into()
                }),
                7,
            );
        }

        #[test]
        fn reviewer_address_stride_3600_spread() {
            assert_spread(
                "neighbor stride 3600",
                256,
                (0..256u32).map(|index| {
                    crate::wire::Ipv4Address::from((0x0a010001 + 3600 * index).to_be_bytes()).into()
                }),
                11,
            );
        }

        fn address(last: u8) -> IpAddress {
            return crate::wire::Ipv4Address::new(192, 0, 2, last).into();
        }

        #[test]
        fn idle_stale_window_starts_at_lookup() {
            let mut cache = Cache::new(1);
            cache.fill(address(1), HADDR_A, Instant::ZERO);
            cache.expire(Instant::from_secs(60));
            cache.expire(Instant::from_secs(70));
            for millis in [70_000, 72_999] {
                assert_eq!(
                    cache.lookup(&address(1), Instant::from_millis(millis)),
                    Answer::Stale {
                        hardware_addr: HADDR_A,
                        probe: true,
                    }
                );
            }
            assert_eq!(
                cache.lookup(&address(1), Instant::from_micros(73_000_001)),
                Answer::NotFound
            );
        }

        #[test]
        fn idle_stale_window_refresh() {
            for refill in [false, true] {
                let mut cache = Cache::new(1);
                cache.fill(address(1), HADDR_A, Instant::ZERO);
                let now = Instant::from_secs(70);
                assert_eq!(
                    cache.lookup(&address(1), now),
                    Answer::Stale {
                        hardware_addr: HADDR_A,
                        probe: true,
                    }
                );
                cache.limit_rate(address(1), now);
                let refresh = Instant::from_millis(70_500);
                if refill {
                    cache.fill(address(1), HADDR_A, refresh);
                } else {
                    cache.reset_expiry_if_existing(address(1), HADDR_A, refresh);
                }
                assert_eq!(cache.lookup(&address(1), refresh), Answer::Found(HADDR_A));
                assert_eq!(
                    cache.lookup(&address(1), Instant::from_millis(130_499)),
                    Answer::Found(HADDR_A)
                );
                assert_eq!(
                    cache.lookup(&address(1), Instant::from_secs(140)),
                    Answer::Stale {
                        hardware_addr: HADDR_A,
                        probe: true,
                    }
                );
                assert_eq!(
                    cache.lookup(&address(1), Instant::from_secs(143)),
                    Answer::NotFound
                );
            }
        }

        #[test]
        fn stale_window_answers() {
            let mut cache = Cache::new(1);
            cache.fill(address(1), HADDR_A, Instant::ZERO);
            let fresh = cache.lookup(&address(1), Instant::from_millis(59_999));
            assert_eq!(fresh, Answer::Found(HADDR_A));
            assert!(fresh.found());
            for millis in [60_000, 60_001, 62_999] {
                let stale = cache.lookup(&address(1), Instant::from_millis(millis));
                assert_eq!(
                    stale,
                    Answer::Stale {
                        hardware_addr: HADDR_A,
                        probe: true
                    }
                );
                assert!(!stale.found());
            }
            assert_eq!(Cache::STALE_TIME, Duration::from_millis(3_000));
        }

        #[test]
        fn stale_probe_once_per_silence() {
            let mut cache = Cache::new(2);
            cache.fill(address(1), HADDR_A, Instant::ZERO);
            cache.fill(address(2), HADDR_B, Instant::ZERO);
            cache.expire(Instant::from_millis(60_000));
            let changes = cache.changes();
            for millis in [60_000, 61_000, 62_000] {
                let now = Instant::from_millis(millis);
                assert_eq!(
                    cache.lookup(&address(1), now),
                    Answer::Stale {
                        hardware_addr: HADDR_A,
                        probe: true,
                    }
                );
                cache.limit_rate(address(1), now);
                for offset in [0, 500, 999] {
                    assert_eq!(
                        cache.lookup(&address(1), Instant::from_millis(millis + offset)),
                        Answer::Stale {
                            hardware_addr: HADDR_A,
                            probe: false
                        }
                    );
                }
                assert_eq!(
                    cache.lookup(&address(2), now),
                    Answer::Stale {
                        hardware_addr: HADDR_B,
                        probe: true,
                    }
                );
                assert_eq!(cache.changes(), changes);
                assert_eq!(cache.len, 2);
                assert_eq!(cache.next_expiry, None);
            }
        }

        #[test]
        fn fill_makes_stale_fresh() {
            let mut cache = Cache::new(1);
            cache.fill(address(1), HADDR_A, Instant::ZERO);
            cache.limit_rate(address(1), Instant::from_millis(60_000));
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(60_500)),
                Answer::Stale {
                    hardware_addr: HADDR_A,
                    probe: false
                }
            );
            cache.fill(address(1), HADDR_B, Instant::from_millis(60_500));
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(60_500)),
                Answer::Found(HADDR_B)
            );
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(120_499)),
                Answer::Found(HADDR_B)
            );
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(120_500)),
                Answer::Stale {
                    hardware_addr: HADDR_B,
                    probe: true
                }
            );
        }

        #[test]
        fn after_stale_time_missing() {
            let mut cache = Cache::new(1);
            cache.fill(address(1), HADDR_A, Instant::ZERO);
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(60_000)),
                Answer::Stale {
                    hardware_addr: HADDR_A,
                    probe: true,
                }
            );
            cache.limit_rate(address(1), Instant::from_millis(62_999));
            for millis in [63_000, 63_500, 64_000] {
                let answer = cache.lookup(&address(1), Instant::from_millis(millis));
                assert_eq!(
                    answer,
                    if millis < 63_999 {
                        Answer::RateLimited
                    } else {
                        Answer::NotFound
                    }
                );
                assert!(!answer.found());
            }
        }

        #[test]
        fn reset_expiry_refreshes_stale() {
            let mut cache = Cache::new(1);
            cache.fill(address(1), HADDR_A, Instant::ZERO);
            let now = Instant::from_millis(60_500);
            cache.limit_rate(address(1), now);
            cache.reset_expiry_if_existing(address(1), HADDR_B, now);
            assert_eq!(
                cache.lookup(&address(1), now),
                Answer::Stale {
                    hardware_addr: HADDR_A,
                    probe: false
                }
            );
            let changes = cache.changes();
            cache.reset_expiry_if_existing(address(1), HADDR_A, now);
            assert_eq!(cache.lookup(&address(1), now), Answer::Found(HADDR_A));
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(120_499)),
                Answer::Found(HADDR_A)
            );
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(120_500)),
                Answer::Stale {
                    hardware_addr: HADDR_A,
                    probe: true
                }
            );
            assert_eq!(cache.changes(), changes + 1);
        }

        #[test]
        fn silence_is_per_address() {
            let mut cache = Cache::new(3);
            cache.limit_rate(address(1), Instant::ZERO);
            let now = Instant::from_millis(100);
            assert_eq!(cache.lookup(&address(1), now), Answer::RateLimited);
            assert_eq!(cache.lookup(&address(2), now), Answer::NotFound);
            cache.limit_rate(address(2), now);
            assert_eq!(cache.lookup(&address(1), now), Answer::RateLimited);
            assert_eq!(cache.lookup(&address(2), now), Answer::RateLimited);
            assert_eq!(cache.lookup(&address(3), now), Answer::NotFound);
        }

        #[test]
        fn pending_entry_expires_after_silent_time() {
            let mut cache = Cache::new(1);
            cache.limit_rate(address(1), Instant::ZERO);
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(999)),
                Answer::RateLimited
            );
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(1_000)),
                Answer::NotFound
            );
            cache.limit_rate(address(1), Instant::from_millis(1_000));
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(1_999)),
                Answer::RateLimited
            );
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(2_000)),
                Answer::NotFound
            );
            assert_eq!(cache.len, 1);
        }

        #[test]
        fn fill_resolves_pending() {
            let mut cache = Cache::new(2);
            cache.limit_rate(address(1), Instant::ZERO);
            cache.limit_rate(address(2), Instant::ZERO);
            cache.reset_expiry_if_existing(address(1), HADDR_A, Instant::ZERO);
            assert_eq!(
                cache.lookup(&address(1), Instant::ZERO),
                Answer::RateLimited
            );
            assert_eq!(cache.next_expiry, None);
            cache.fill(address(1), HADDR_A, Instant::from_millis(100));
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(100)),
                Answer::Found(HADDR_A)
            );
            assert_eq!(cache.changes(), 1);
            assert_eq!(cache.next_expiry, Some(Instant::from_millis(60_100)));
            cache.fill_with_expiration(address(2), HADDR_B, Instant::from_millis(2_000));
            assert_eq!(
                cache.lookup(&address(2), Instant::from_millis(100)),
                Answer::Found(HADDR_B)
            );
            assert_eq!(cache.changes(), 2);
            assert_eq!(cache.next_expiry, Some(Instant::from_millis(2_000)));
            cache.limit_rate(address(1), Instant::from_millis(200));
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(200)),
                Answer::Found(HADDR_A)
            );
            cache.limit_rate(address(2), Instant::from_millis(2_000));
            assert_eq!(
                cache.lookup(&address(2), Instant::from_millis(2_000)),
                Answer::Stale {
                    hardware_addr: HADDR_B,
                    probe: false
                }
            );
            assert_eq!(
                cache.lookup(&address(2), Instant::from_millis(5_000)),
                Answer::NotFound
            );
            assert_eq!(cache.changes(), 2);
            assert_eq!(cache.len, 2);
        }

        #[test]
        fn pending_eviction_of_resolved_bumps_changes() {
            let mut cache = Cache::new(1);
            cache.fill(address(1), HADDR_A, Instant::ZERO);
            let changes = cache.changes();
            cache.limit_rate(address(2), Instant::from_millis(2));
            assert_eq!(cache.changes(), changes + 1);
            assert!(cache.find(&address(1)).is_err());
            assert_eq!(
                cache.lookup(&address(2), Instant::from_millis(2)),
                Answer::RateLimited
            );
            assert_eq!(cache.len, 1);
            cache.expire(Instant::from_millis(60_000));
            assert_eq!(cache.changes(), changes + 1);
            assert_eq!(cache.next_expiry, None);
        }

        #[test]
        fn silence_after_stale_window() {
            let mut cache = Cache::new(1);
            cache.fill(address(1), HADDR_A, Instant::ZERO);
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(60_000)),
                Answer::Stale {
                    hardware_addr: HADDR_A,
                    probe: true,
                }
            );
            cache.limit_rate(address(1), Instant::from_millis(62_999));
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(62_999)),
                Answer::Stale {
                    hardware_addr: HADDR_A,
                    probe: false
                }
            );
            for millis in [63_000, 63_500, 63_998] {
                assert_eq!(
                    cache.lookup(&address(1), Instant::from_millis(millis)),
                    Answer::RateLimited
                );
            }
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(63_999)),
                Answer::NotFound
            );
            cache.limit_rate(address(1), Instant::from_millis(63_999));
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(64_998)),
                Answer::RateLimited
            );
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(64_999)),
                Answer::NotFound
            );
        }

        #[test]
        fn full_cache_of_silent_pending_answers_rate_limited() {
            let mut cache = Cache::new(1);
            cache.limit_rate(address(1), Instant::ZERO);
            for millis in [0, 100, 999] {
                let now = Instant::from_millis(millis);
                assert_eq!(cache.lookup(&address(2), now), Answer::RateLimited);
                cache.limit_rate(address(2), now);
                assert_eq!(cache.lookup(&address(1), now), Answer::RateLimited);
                assert!(cache.find(&address(2)).is_err());
                assert_eq!(cache.len, 1);
                assert_eq!(cache.changes(), 0);
            }
            let now = Instant::from_millis(1_000);
            assert_eq!(cache.lookup(&address(2), now), Answer::NotFound);
            cache.limit_rate(address(2), now);
            assert!(cache.find(&address(1)).is_err());
            assert_eq!(cache.lookup(&address(2), now), Answer::RateLimited);
            assert_eq!(cache.len, 1);
            assert_eq!(cache.changes(), 0);
        }

        #[test]
        fn pending_never_evicts_resolved_that_expires_later() {
            let mut cache = Cache::new(2);
            cache.fill(address(1), HADDR_A, Instant::ZERO);
            cache.limit_rate(address(2), Instant::ZERO);
            cache.limit_rate(address(3), Instant::from_millis(100));
            let now = Instant::from_millis(100);
            assert_eq!(cache.lookup(&address(1), now), Answer::Found(HADDR_A));
            assert_eq!(cache.lookup(&address(2), now), Answer::RateLimited);
            assert_eq!(cache.lookup(&address(3), now), Answer::RateLimited);
            cache.fill(address(4), HADDR_D, now);
            assert_eq!(cache.lookup(&address(1), now), Answer::Found(HADDR_A));
            assert_eq!(cache.lookup(&address(3), now), Answer::NotFound);
            assert_eq!(cache.lookup(&address(4), now), Answer::Found(HADDR_D));
            assert_eq!(cache.len, 2);
        }

        #[test]
        fn pending_does_not_bump_changes() {
            let mut cache = Cache::new(2);
            cache.limit_rate(address(1), Instant::ZERO);
            cache.limit_rate(address(1), Instant::from_millis(100));
            assert_eq!(cache.changes(), 0);
            assert_eq!(cache.next_expiry, None);
            cache.expire(Instant::from_millis(100));
            assert_eq!(cache.changes(), 0);
            assert_eq!(cache.next_expiry, None);
            cache.fill_with_expiration(address(2), HADDR_B, Instant::from_millis(500));
            cache.limit_rate(address(3), Instant::from_millis(200));
            assert_eq!(cache.changes(), 2);
            assert_eq!(cache.next_expiry, Some(Instant::from_millis(500)));
            cache.expire(Instant::from_millis(500));
            assert_eq!(cache.changes(), 2);
            assert_eq!(cache.next_expiry, None);
            cache.fill_with_expiration(address(2), HADDR_B, Instant::from_millis(2_000));
            cache.expire(Instant::from_millis(1_200));
            assert_eq!(cache.changes(), 3);
            assert_eq!(cache.next_expiry, Some(Instant::from_millis(2_000)));
            cache.expire(Instant::from_millis(2_000));
            assert_eq!(cache.changes(), 4);
            assert_eq!(cache.next_expiry, None);
        }

        #[test]
        fn len_exact_with_pending() {
            let mut cache = Cache::new(3);
            let mask = cache.storage.len() - 1;
            let colliding: Vec<IpAddress> = (1..=254)
                .map(address)
                .filter(|address| cache.home(address) == mask)
                .take(4)
                .collect();
            assert_eq!(colliding.len(), 4);
            for (index, address) in colliding[..3].iter().enumerate() {
                cache.limit_rate(*address, Instant::from_millis(index as i64));
                assert_eq!(cache.len, index + 1);
                assert_eq!(cache.len, cache.storage.iter().flatten().count());
            }
            cache.limit_rate(colliding[1], Instant::from_millis(100));
            cache.fill(colliding[2], HADDR_C, Instant::ZERO);
            assert_eq!(cache.len, 3);
            cache.lookup(&colliding[2], Instant::ZERO);
            cache.limit_rate(colliding[3], Instant::from_millis(200));
            assert_eq!(cache.len, 3);
            assert_eq!(cache.len, cache.storage.iter().flatten().count());
            let now = Instant::from_millis(200);
            assert_eq!(cache.lookup(&colliding[0], now), Answer::RateLimited);
            assert_eq!(cache.lookup(&colliding[1], now), Answer::RateLimited);
            assert_eq!(cache.lookup(&colliding[2], now), Answer::Found(HADDR_C));
            assert_eq!(cache.lookup(&colliding[3], now), Answer::RateLimited);
            cache.expire(Instant::from_millis(1_200));
            assert_eq!(
                cache.lookup(&colliding[1], Instant::from_millis(1_200)),
                Answer::NotFound
            );
            assert_eq!(cache.len, 3);
            assert_eq!(cache.len, cache.storage.iter().flatten().count());
            cache.flush();
            assert_eq!(cache.len, 0);
            assert_eq!(cache.storage.iter().flatten().count(), 0);
            assert_eq!(cache.next_expiry, None);
            for address in &colliding {
                assert_eq!(cache.lookup(address, Instant::ZERO), Answer::NotFound);
            }
        }

        #[test]
        fn changes_track_fill_flush_and_expiry() {
            let mut cache = Cache::new(1);
            assert_eq!(cache.changes(), 0);
            cache.fill(address(1), HADDR_A, Instant::ZERO);
            assert_eq!(cache.changes(), 1);
            cache.fill(address(1), HADDR_B, Instant::ZERO);
            assert_eq!(cache.changes(), 2);
            cache.fill(address(2), HADDR_C, Instant::ZERO);
            assert_eq!(cache.changes(), 4);
            cache.expire(Instant::from_millis(59_999));
            assert_eq!(cache.changes(), 4);
            cache.expire(Instant::from_millis(60_000));
            assert_eq!(cache.changes(), 5);
            cache.expire(Instant::from_millis(60_000));
            cache.expire(Instant::from_millis(120_000));
            assert_eq!(cache.changes(), 5);
            cache.flush();
            assert_eq!(cache.changes(), 6);
            cache.expire(Instant::from_millis(180_000));
            assert_eq!(cache.changes(), 6);
        }

        #[test]
        fn expiry_counts_each_scan_once_and_skips_old_entries() {
            let mut cache = Cache::new(3);
            cache.fill(address(1), HADDR_A, Instant::ZERO);
            cache.fill(address(2), HADDR_B, Instant::ZERO);
            cache.fill(address(3), HADDR_C, Instant::from_millis(10_000));
            cache.expire(Instant::from_millis(60_000));
            assert_eq!(cache.changes(), 4);
            cache.expire(Instant::from_millis(69_999));
            assert_eq!(cache.changes(), 4);
            cache.expire(Instant::from_millis(70_000));
            assert_eq!(cache.changes(), 5);
            cache.expire(Instant::from_millis(140_000));
            assert_eq!(cache.changes(), 5);
        }

        #[test]
        fn refresh_reschedules_without_bumping() {
            let mut cache = Cache::new(1);
            cache.fill(address(1), HADDR_A, Instant::ZERO);
            cache.reset_expiry_if_existing(address(1), HADDR_B, Instant::from_millis(1_000));
            assert_eq!(cache.changes(), 1);
            cache.reset_expiry_if_existing(address(1), HADDR_A, Instant::from_millis(10_000));
            assert_eq!(cache.changes(), 1);
            cache.expire(Instant::from_millis(60_000));
            assert_eq!(cache.changes(), 1);
            assert_eq!(cache.next_expiry, Some(Instant::from_millis(70_000)));
            cache.expire(Instant::from_millis(70_000));
            assert_eq!(cache.changes(), 2);
        }

        #[test]
        fn refresh_revives_counted_entry_and_can_shorten_expiry() {
            let mut cache = Cache::new(1);
            cache.fill(address(1), HADDR_A, Instant::ZERO);
            cache.expire(Instant::from_millis(60_000));
            assert_eq!(cache.changes(), 2);
            cache.reset_expiry_if_existing(address(1), HADDR_A, Instant::from_millis(61_000));
            assert_eq!(cache.changes(), 3);
            assert_eq!(cache.next_expiry, Some(Instant::from_millis(121_000)));
            cache.expire(Instant::from_millis(121_000));
            assert_eq!(cache.changes(), 4);
            cache.fill_with_expiration(address(1), HADDR_A, Instant::from_millis(300_000));
            cache.expire(Instant::from_millis(122_000));
            cache.reset_expiry_if_existing(address(1), HADDR_A, Instant::from_millis(123_000));
            assert_eq!(cache.changes(), 5);
            assert_eq!(cache.next_expiry, Some(Instant::from_millis(183_000)));
            cache.expire(Instant::from_millis(183_000));
            assert_eq!(cache.changes(), 6);
            cache.expire(Instant::from_millis(400_000));
            assert_eq!(cache.changes(), 6);
        }

        #[test]
        fn maximum_instant_expiry_is_counted_once() {
            let mut cache = Cache::new(1);
            let maximum = Instant::from_micros(i64::MAX);
            cache.expire(maximum);
            assert_eq!(cache.changes(), 0);
            cache.fill_with_expiration(address(1), HADDR_A, maximum);
            assert_eq!(cache.changes(), 1);
            assert_eq!(cache.next_expiry, Some(maximum));
            cache.expire(maximum);
            assert_eq!(cache.changes(), 2);
            assert_eq!(cache.next_expiry, None);
            cache.expire(maximum);
            assert_eq!(cache.changes(), 2);
        }

        #[test]
        fn nine_neighbors_fit_in_default_capacity() {
            let config = crate::iface::Config::new(HADDR_A);
            assert_eq!(config.neighbor_capacity, 256);
            let mut cache = Cache::new(config.neighbor_capacity);
            assert_eq!(cache.storage.len(), 512);

            for last in 1..=9 {
                cache.fill(address(last), HADDR_A, Instant::ZERO);
            }
            for last in 1..=9 {
                assert_eq!(
                    cache.lookup(&address(last), Instant::ZERO),
                    Answer::Found(HADDR_A)
                );
            }
        }

        #[test]
        fn eviction_tie_goes_to_lowest_address() {
            let mut cache = Cache::new(3);
            for last in (1..=3).rev() {
                cache.fill(address(last), HADDR_A, Instant::ZERO);
            }
            cache.fill(address(4), HADDR_D, Instant::ZERO);

            assert_eq!(cache.lookup(&address(1), Instant::ZERO), Answer::NotFound);
            for last in 2..=3 {
                assert_eq!(
                    cache.lookup(&address(last), Instant::ZERO),
                    Answer::Found(HADDR_A)
                );
            }
            assert_eq!(
                cache.lookup(&address(4), Instant::ZERO),
                Answer::Found(HADDR_D)
            );
        }

        #[test]
        fn fill_existing_when_full_updates_in_place() {
            let mut cache = Cache::new(3);
            for last in 1..=3 {
                cache.fill(address(last), HADDR_A, Instant::ZERO);
            }
            let index = cache.find(&address(1)).unwrap();
            cache.fill(address(1), HADDR_D, Instant::from_millis(1_000));

            assert_eq!(cache.find(&address(1)), Ok(index));
            assert_eq!(cache.len, 3);
            assert_eq!(
                cache.lookup(&address(1), Instant::ZERO),
                Answer::Found(HADDR_D)
            );
            for last in 2..=3 {
                assert_eq!(
                    cache.lookup(&address(last), Instant::ZERO),
                    Answer::Found(HADDR_A)
                );
            }
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(60_000)),
                Answer::Found(HADDR_D)
            );
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(61_000)),
                Answer::Stale {
                    hardware_addr: HADDR_D,
                    probe: true
                }
            );
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(64_000)),
                Answer::NotFound
            );
        }

        #[test]
        fn refresh_extends_expiry() {
            let mut cache = Cache::new(3);
            cache.fill(address(1), HADDR_A, Instant::ZERO);
            cache.reset_expiry_if_existing(address(1), HADDR_B, Instant::from_millis(10_000));
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(60_000)),
                Answer::Stale {
                    hardware_addr: HADDR_A,
                    probe: true
                }
            );
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(63_000)),
                Answer::NotFound
            );
            assert_eq!(cache.len, 1);

            cache.reset_expiry_if_existing(address(1), HADDR_A, Instant::from_millis(60_000));
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(119_999)),
                Answer::Found(HADDR_A)
            );
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(120_000)),
                Answer::Stale {
                    hardware_addr: HADDR_A,
                    probe: true
                }
            );
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(123_000)),
                Answer::NotFound
            );

            cache.reset_expiry_if_existing(address(2), HADDR_A, Instant::from_millis(60_000));
            assert_eq!(
                cache.lookup(&address(2), Instant::from_millis(60_000)),
                Answer::NotFound
            );
            assert_eq!(cache.len, 1);
        }

        #[test]
        fn mac_change_replaces_hardware_address() {
            let mut cache = Cache::new(3);
            cache.fill_with_expiration(address(1), HADDR_A, Instant::from_millis(1_000));
            cache.fill_with_expiration(address(1), HADDR_B, Instant::from_millis(2_000));

            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(1_000)),
                Answer::Found(HADDR_B)
            );
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(2_000)),
                Answer::Stale {
                    hardware_addr: HADDR_B,
                    probe: true
                }
            );
            assert_eq!(
                cache.lookup(&address(1), Instant::from_millis(5_000)),
                Answer::NotFound
            );
            assert_eq!(cache.len, 1);
        }

        #[test]
        fn colliding_keys_probe_and_delete() {
            let mut cache = Cache::new(3);
            let mask = cache.storage.len() - 1;
            let colliding: Vec<IpAddress> = (1..=254)
                .map(address)
                .filter(|address| cache.home(address) == mask)
                .take(4)
                .collect();
            assert_eq!(colliding.len(), 4);

            for (index, address) in colliding[..3].iter().enumerate() {
                cache.fill(*address, HADDR_A, Instant::from_millis(index as i64));
            }
            assert_eq!(cache.find(&colliding[0]), Ok(mask));
            assert_eq!(cache.find(&colliding[1]), Ok(0));
            assert_eq!(cache.find(&colliding[2]), Ok(1));
            for address in &colliding[..3] {
                assert_eq!(
                    cache.lookup(address, Instant::from_millis(10)),
                    Answer::Found(HADDR_A)
                );
            }
            // The last lookup remembered colliding[2]'s slot.
            assert_eq!(cache.last_found.get(), 1);

            cache.fill(colliding[3], HADDR_D, Instant::from_millis(3));
            assert_eq!(
                cache.lookup(&colliding[0], Instant::from_millis(10)),
                Answer::NotFound
            );
            // Eviction moved colliding[2] out of the remembered slot and put colliding[3]
            // there; finds must not trust it.
            assert_eq!(cache.last_found.get(), 1);
            assert_eq!(cache.find(&colliding[1]), Ok(mask));
            assert_eq!(cache.find(&colliding[2]), Ok(0));
            for address in &colliding[1..3] {
                assert_eq!(
                    cache.lookup(address, Instant::from_millis(10)),
                    Answer::Found(HADDR_A)
                );
            }
            assert_eq!(
                cache.lookup(&colliding[3], Instant::from_millis(10)),
                Answer::Found(HADDR_D)
            );
        }
    }
}
