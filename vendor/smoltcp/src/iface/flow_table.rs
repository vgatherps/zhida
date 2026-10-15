use alloc::vec::Vec;

use crate::table_hash::{C1, finish, mix};
use crate::wire::{IpAddress, IpEndpoint};

pub(crate) trait FlowTableKey: Copy + Eq {
    fn hash(&self) -> u64;
}

impl FlowTableKey for u16 {
    fn hash(&self) -> u64 {
        finish(mix(C1, *self as u64))
    }
}

impl FlowTableKey for (IpEndpoint, IpEndpoint) {
    fn hash(&self) -> u64 {
        let ports = (self.0.port as u64) << 16 | self.1.port as u64;
        match (self.0.addr, self.1.addr) {
            (IpAddress::Ipv4(local), IpAddress::Ipv4(remote)) => {
                let addresses = (u32::from_be_bytes(local.octets()) as u64) << 32
                    | u32::from_be_bytes(remote.octets()) as u64;
                finish(mix(mix(C1, addresses), ports))
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct FlowTable<K> {
    storage: Vec<Option<(K, usize)>>,
    hash_shift: u32,
}

impl<K: FlowTableKey> FlowTable<K> {
    pub(crate) fn new(slots: usize) -> Self {
        let size = Self::table_size(slots);
        Self {
            storage: alloc::vec![None; size],
            hash_shift: 64 - size.trailing_zeros(),
        }
    }

    fn table_size(slots: usize) -> usize {
        slots
            .max(1)
            .checked_mul(2)
            .and_then(usize::checked_next_power_of_two)
            .expect("TCP flow table slot count is too large")
    }

    fn home(&self, key: &K) -> usize {
        (key.hash() >> self.hash_shift) as usize
    }

    fn find(&self, key: &K) -> Result<usize, usize> {
        let mut index = self.home(key);
        while let Some((stored_key, _)) = &self.storage[index] {
            if stored_key == key {
                return Ok(index);
            }
            index = (index + 1) & (self.storage.len() - 1);
        }
        Err(index)
    }

    #[inline]
    pub(crate) fn get(&self, key: &K) -> Option<usize> {
        self.find(key)
            .ok()
            .map(|index| self.storage[index].unwrap().1)
    }

    pub(crate) fn set(&mut self, key: K, head: usize) {
        let index = match self.find(&key) {
            Ok(index) | Err(index) => index,
        };
        self.storage[index] = Some((key, head));
    }

    pub(crate) fn remove(&mut self, key: &K) {
        let Ok(mut hole) = self.find(key) else {
            return;
        };
        self.storage[hole] = None;
        let mask = self.storage.len() - 1;
        let mut index = (hole + 1) & mask;
        while let Some((key, _)) = &self.storage[index] {
            let home = self.home(key);
            if (hole.wrapping_sub(home) & mask) < (index.wrapping_sub(home) & mask) {
                self.storage[hole] = self.storage[index].take();
                hole = index;
            }
            index = (index + 1) & mask;
        }
    }

    pub(crate) fn grow(&mut self, new_slot_count: usize) {
        let size = Self::table_size(new_slot_count);
        if size <= self.storage.len() {
            return;
        }
        let old = core::mem::replace(&mut self.storage, alloc::vec![None; size]);
        self.hash_shift = 64 - size.trailing_zeros();
        for (key, head) in old.into_iter().flatten() {
            self.set(key, head);
        }
    }

    #[cfg(any(test, debug_assertions))]
    pub(crate) fn entries(&self) -> impl Iterator<Item = (K, usize)> + '_ {
        self.storage.iter().filter_map(|entry| *entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_spread<K: FlowTableKey>(
        name: &str,
        slots: usize,
        keys: impl IntoIterator<Item = K>,
        max_probe: usize,
    ) {
        let mut table = FlowTable::new(slots);
        let mut count = 0;
        for (head, key) in keys.into_iter().enumerate() {
            table.set(key, head);
            count += 1;
        }
        assert!(count > 0 && count <= slots);
        assert_eq!(table.storage.len(), 2 * slots);
        let mask = table.storage.len() - 1;
        let mut longest = 0;
        let mut total = 0;
        let mut at_home = 0;
        for (index, entry) in table.storage.iter().enumerate() {
            if let Some((key, head)) = entry {
                assert_eq!(table.get(key), Some(*head));
                let distance = index.wrapping_sub(table.home(key)) & mask;
                longest = longest.max(distance);
                total += distance;
                at_home += usize::from(distance == 0);
            }
        }
        std::println!(
            "{name}: max={longest}, mean={total}/{count} ({}), home={at_home}/{count}",
            total as f64 / count as f64,
        );
        assert!(longest <= 40, "{name}: max {longest} > 40");
        assert!(longest <= max_probe, "{name}: max {longest} > {max_probe}");
        assert!(total * 2 <= 3 * count, "{name}: mean {total}/{count} > 1.5");
    }

    #[test]
    fn sequential_remote_ports_spread() {
        assert_spread(
            "remote ports",
            1024,
            (40000..41024).map(|port| {
                (
                    IpEndpoint::new(IpAddress::v4(192, 0, 2, 1), 1234),
                    IpEndpoint::new(IpAddress::v4(192, 0, 2, 2), port),
                )
            }),
            12,
        );
    }

    #[test]
    fn sequential_local_ports_spread() {
        assert_spread(
            "local ports",
            1024,
            (40000..41024).map(|port| {
                (
                    IpEndpoint::new(IpAddress::v4(192, 0, 2, 1), port),
                    IpEndpoint::new(IpAddress::v4(192, 0, 2, 2), 1234),
                )
            }),
            13,
        );
    }

    #[test]
    fn sequential_remote_addresses_spread() {
        assert_spread(
            "remote addresses",
            1024,
            (1..=1024u32).map(|index| {
                (
                    IpEndpoint::new(IpAddress::v4(192, 0, 2, 1), 1234),
                    IpEndpoint::new(
                        crate::wire::Ipv4Address::from((0x0a000000 + index).to_be_bytes()).into(),
                        4321,
                    ),
                )
            }),
            11,
        );
    }

    #[test]
    fn sequential_listener_ports_spread() {
        assert_spread("listener ports", 1024, 40000..41024u16, 15);
    }

    #[test]
    fn sequential_reviewer_remote_ports_spread() {
        assert_spread(
            "reviewer remote ports",
            1024,
            (40000..41024).map(|port| {
                (
                    IpEndpoint::new(IpAddress::v4(10, 0, 0, 1), 1234),
                    IpEndpoint::new(IpAddress::v4(10, 0, 0, 211), port),
                )
            }),
            17,
        );
    }

    #[test]
    fn sequential_reviewer_local_ports_spread() {
        assert_spread(
            "reviewer local ports",
            1024,
            (40000..41024).map(|port| {
                (
                    IpEndpoint::new(IpAddress::v4(10, 63, 106, 136), port),
                    IpEndpoint::new(IpAddress::v4(10, 0, 0, 1), 1234),
                )
            }),
            14,
        );
    }

    #[test]
    fn sequential_reviewer_remote_addresses_spread() {
        assert_spread(
            "reviewer remote addresses",
            256,
            (1..=254).map(|last| {
                (
                    IpEndpoint::new(IpAddress::v4(10, 0, 0, 1), 1234),
                    IpEndpoint::new(IpAddress::v4(10, 0, 0, last), 4983),
                )
            }),
            10,
        );
    }

    #[test]
    fn sequential_remote_first_octets_spread() {
        assert_spread(
            "remote first octet",
            256,
            (1..=254).map(|first| {
                (
                    IpEndpoint::new(IpAddress::v4(10, 0, 0, 1), 1234),
                    IpEndpoint::new(IpAddress::v4(first, 0, 0, 1), 4983),
                )
            }),
            17,
        );
    }

    #[test]
    fn sequential_reviewer_remote_ports_swapped_spread() {
        assert_spread(
            "reviewer remote ports swapped",
            1024,
            (40000..41024).map(|port| {
                (
                    IpEndpoint::new(IpAddress::v4(10, 0, 0, 211), port),
                    IpEndpoint::new(IpAddress::v4(10, 0, 0, 1), 1234),
                )
            }),
            10,
        );
    }

    #[test]
    fn sequential_remote_port_high_bits_spread() {
        assert_spread(
            "high bit remote ports",
            64,
            (1..=63u16).map(|index| {
                (
                    IpEndpoint::new(IpAddress::v4(10, 0, 0, 1), 1234),
                    IpEndpoint::new(IpAddress::v4(10, 0, 0, 211), 1024 * index),
                )
            }),
            7,
        );
    }

    #[test]
    fn reviewer_remote_address_stride_4_spread() {
        assert_spread(
            "remote address stride 4",
            1024,
            (0..1024u32).map(|index| {
                (
                    IpEndpoint::new(IpAddress::v4(192, 0, 2, 1), 1234),
                    IpEndpoint::new(
                        crate::wire::Ipv4Address::from((0xc0a80001 + 4 * index).to_be_bytes())
                            .into(),
                        443,
                    ),
                )
            }),
            11,
        );
    }

    #[test]
    fn flow_table_backward_shift() {
        let table = FlowTable::<u16>::new(4);
        let keys: Vec<_> = (0..u16::MAX)
            .filter(|key| table.home(key) == table.storage.len() - 1)
            .take(4)
            .collect();
        assert_eq!(keys.len(), 4);
        for removed in 0..keys.len() {
            let mut table = FlowTable::new(4);
            for (head, key) in keys.iter().enumerate() {
                table.set(*key, head);
            }
            table.set(keys[3], 10);
            table.remove(&keys[removed]);
            table.remove(&keys[removed]);
            for (head, key) in keys.iter().enumerate() {
                let expected = if head == removed {
                    None
                } else {
                    Some(if head == 3 { 10 } else { head })
                };
                assert_eq!(table.get(key), expected);
            }
            table.grow(9);
            assert_eq!(table.storage.len(), 32);
            for (head, key) in keys.iter().enumerate() {
                if head != removed {
                    assert_eq!(table.get(key), Some(if head == 3 { 10 } else { head }));
                }
            }
        }
    }
}
