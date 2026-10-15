use smoltcp::socket::tcp;

/// RX mbufs reserved for the driver, staging queue and one lcore's cache.
/// The count is max(rx_descriptors, 32) + rx_staging + floor(3 * rx_cache_size / 2).
/// A NIC keeps its RX descriptors filled; memif copy mode needs 32 mbufs
/// before it can receive. Staged packets still use mbufs. A DPDK cache can
/// hold up to its flush threshold of 1.5 times its configured size.
///
/// Panics if the reserve exceeds usize.
pub fn rx_reserve(rx_descriptors: u16, rx_staging: usize, rx_cache_size: u32) -> usize {
    let cache = usize::try_from(rx_cache_size)
        .expect("RX cache size exceeds usize")
        .checked_mul(3)
        .expect("RX cache flush threshold exceeds usize")
        / 2;
    usize::from(rx_descriptors)
        .max(32)
        .checked_add(rx_staging)
        .and_then(|count| count.checked_add(cache))
        .expect("RX reserve exceeds usize")
}

/// TX mbufs reserved for a NIC PMD and the Device.
/// The count is tx_descriptors + tx_pending.
/// Use the negotiated TX descriptor count from Port::descriptor_counts().1:
/// a NIC PMD may keep that many sent mbufs until it reclaims them. The Device
/// holds at most tx_pending more: built frames, the live reservation and the
/// spare share those slots. The pool cache needs no slack because this lcore
/// is the only allocator.
///
/// Panics if the reserve exceeds usize.
pub fn tx_reserve(tx_descriptors: u16, tx_pending: usize) -> usize {
    usize::from(tx_descriptors)
        .checked_add(tx_pending)
        .expect("TX reserve exceeds usize")
}

/// RX pool count is the reserve plus every uncapped TCP socket's RX mbuf budget.
/// The reserve keeps the driver supplied while sockets hold received data.
/// For capped sockets, add `tcp::rx_mbuf_budget(&config, usize::from(ip_mtu))`
/// to the reserve instead. Use the same config for sizing and admission.
///
/// Panics if `ip_mtu` is below 68 or the pool count exceeds u32.
pub fn rx_pool_count(
    reserve: usize,
    ip_mtu: u16,
    recv_capacities: impl IntoIterator<Item = usize>,
) -> u32 {
    assert!(ip_mtu >= 68, "IP MTU must be at least 68 bytes");
    let mut count = u32::try_from(reserve).expect("RX pool count exceeds u32");
    for rx_capacity in recv_capacities {
        let config = tcp::Config { rx_capacity, tx_capacity: 0, mss_cap: None };
        let budget = u32::try_from(tcp::rx_mbuf_budget(&config, usize::from(ip_mtu)))
            .expect("RX mbuf budget exceeds u32");
        count = count
            .checked_add(budget)
            .expect("RX pool count exceeds u32");
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_reserve_covers_descriptors_and_pending() {
        assert_eq!(tx_reserve(1024, 32), 1024 + 32);
        assert_eq!(tx_reserve(64, 32), 96);
        assert_eq!(tx_reserve(16, 8), 24);
        assert_eq!(tx_reserve(16, 1), 17);
        assert_eq!(tx_reserve(16, 0), 16);
        assert_eq!(tx_reserve(0, 0), 0);
    }

    #[test]
    #[should_panic(expected = "TX reserve exceeds usize")]
    fn tx_reserve_refuses_pending_overflow() {
        tx_reserve(1, usize::MAX);
    }

    #[test]
    fn tx_reserve_accepts_pending_at_usize_limit() {
        assert_eq!(tx_reserve(0, usize::MAX), usize::MAX);
        assert_eq!(tx_reserve(1, usize::MAX - 1), usize::MAX);
    }

    #[test]
    fn rx_pool_count_covers_reserve_and_budgets() {
        let nic = rx_reserve(1024, 32, 64);
        assert_eq!(nic, 1024 + 32 + 96);
        assert_eq!(
            rx_pool_count(nic, 1500, [4096, 65536, 262144]),
            1152 + 6 + 45 + 180
        );
        assert_eq!(
            rx_pool_count(nic, 9000, [4096, 65536, 262144]),
            1152 + 6 + 8 + 30
        );
        assert_eq!(rx_pool_count(nic, 1500, []), 1152);
        assert_eq!(rx_pool_count(nic, 9000, []), 1152);

        let memif = rx_reserve(64, 32, 8);
        assert_eq!(memif, 64 + 32 + 12);
        assert_eq!(rx_pool_count(memif, 1500, [8192, 65536]), 108 + 6 + 45);
        assert_eq!(rx_pool_count(memif, 9000, [8192, 65536]), 108 + 6 + 8);
        let small = rx_reserve(16, 32, 8);
        assert_eq!(small, 32 + 32 + 12);
        assert_eq!(rx_pool_count(small, 1500, []), 76);
        assert_eq!(rx_reserve(16, 0, 1), 33);
    }

    #[test]
    fn rx_pool_count_accepts_capacities_with_capped_budget_in_reserve() {
        let capped = tcp::Config {
            rx_capacity: 65536,
            tx_capacity: 4096,
            mss_cap: Some(536),
        };
        let reserve = 76 + tcp::rx_mbuf_budget(&capped, 1500);
        let capacities = std::iter::once(0).chain(std::iter::repeat(65536).take(2));
        assert_eq!(rx_pool_count(reserve, 1500, capacities), 76 + 123 + 6 + 45 + 45);
    }

    #[test]
    #[should_panic(expected = "RX pool count exceeds u32")]
    fn rx_pool_count_refuses_overflow() {
        rx_pool_count(u32::MAX as usize, 1500, [4096]);
    }
}
