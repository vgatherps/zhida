use super::*;
use crate::eal::with_test_eal;
use std::cell::{Cell, RefCell};
use std::ffi::{c_void, CString};
use std::ptr::NonNull;
use zhida_buffer::PoolManager;

#[derive(Clone, Copy, Default)]
pub(crate) struct Faults {
    tx_queue: u16,
    start_after_success: bool,
    stop_before_call: bool,
    close_after_success: bool,
    rxq_info_code: Option<i32>,
    rxq_info_scattered_rx: Option<u8>,
    /// Offer at most this many packets to the real PMD.
    pub(crate) tx_accept_limit: Option<u16>,
    pub(crate) tx_prepare_refuse: bool,
    pub(crate) tx_prepare_limit: Option<u16>,
    /// Model a PMD that frees accepted packets inside TX burst: dequeue them
    /// from this ring, free them and overwrite the caller's pointer array.
    tx_free_ring: Option<NonNull<rte_ring>>,
    /// Model a PMD breaking its contract: report this many more packets than
    /// the real PMD accepted.
    tx_report_extra: u16,
    /// Model a NIC reclaiming sent mbufs in TX done cleanup: dequeue every
    /// packet from this ring, free it and return the count, instead of the
    /// real call (net_ring returns -ENOTSUP).
    cleanup_reclaim_ring: Option<NonNull<rte_ring>>,
    /// Return this code from TX done cleanup instead of the real call.
    cleanup_code: Option<i32>,
}

thread_local! {
    static FAULTS: Cell<Faults> = Cell::new(Faults::default());
    static STOP_CALLS: Cell<u32> = const { Cell::new(0) };
    static CLOSE_CALLS: Cell<u32> = const { Cell::new(0) };
    static TX_CALLS: Cell<u32> = const { Cell::new(0) };
    static PREPARE_CALLS: Cell<u32> = const { Cell::new(0) };
    static PREPARE_ARGS: Cell<(u16, u16, u16)> = const { Cell::new((0, 0, 0)) };
    static PREPARE_PACKETS: RefCell<Vec<Vec<usize>>> = const { RefCell::new(Vec::new()) };
    static RX_CALLS: Cell<u32> = const { Cell::new(0) };
    static TX_FREED: Cell<u32> = const { Cell::new(0) };
    static CLEANUP_CALLS: Cell<u32> = const { Cell::new(0) };
    static CLEANUP_RESULT: Cell<i32> = const { Cell::new(0) };
}

#[test]
fn device_info_advertised_maps_bits() {
    let info = |rx_capa, tx_capa| DeviceInfo {
        driver_name: "test".into(),
        rx_capa,
        tx_capa,
        min_mtu: 0,
        max_mtu: 0,
        max_rx_pktlen: 0,
        mac: [0; 6],
    };

    assert!(!info(
        RX_OFFLOAD_IPV4_CKSUM | RX_OFFLOAD_UDP_CKSUM,
        0,
    )
    .advertised()
    .rx_checksum);
    let advertised = info(
        RX_OFFLOAD_IPV4_CKSUM | RX_OFFLOAD_UDP_CKSUM | RX_OFFLOAD_TCP_CKSUM,
        TX_OFFLOAD_TCP_CKSUM,
    )
    .advertised();
    assert!(advertised.rx_checksum);
    assert!(advertised.tx_tcp_checksum);
    assert!(!advertised.tx_udp_checksum);
    let advertised = info(RX_OFFLOAD_TIMESTAMP, TX_OFFLOAD_UDP_CKSUM).advertised();
    assert!(advertised.rx_timestamp);
    assert!(!advertised.tx_tcp_checksum);
    assert!(advertised.tx_udp_checksum);
}

pub(crate) struct FaultGuard(Faults);

impl FaultGuard {
    pub(crate) fn new(faults: Faults) -> Self {
        Self(FAULTS.replace(faults))
    }
}

impl Drop for FaultGuard {
    fn drop(&mut self) {
        FAULTS.set(self.0);
    }
}

pub(super) fn tx_queue() -> u16 {
    FAULTS.get().tx_queue
}

pub(super) unsafe fn rx_queue_info_get(port: u16, queue: u16, info: *mut rte_eth_rxq_info) -> i32 {
    let faults = FAULTS.get();
    if let Some(code) = faults.rxq_info_code {
        code
    } else if let Some(scattered_rx) = faults.rxq_info_scattered_rx {
        (*info).scattered_rx = scattered_rx;
        0
    } else {
        rte_eth_rx_queue_info_get(port, queue, info)
    }
}

pub(super) unsafe fn start(port: u16) -> i32 {
    let result = rte_eth_dev_start(port);
    if result == 0 && FAULTS.get().start_after_success {
        -5
    } else {
        result
    }
}

pub(super) unsafe fn stop(port: u16) -> i32 {
    STOP_CALLS.set(STOP_CALLS.get() + 1);
    if FAULTS.get().stop_before_call {
        -5
    } else {
        rte_eth_dev_stop(port)
    }
}

pub(super) unsafe fn close(port: u16) -> i32 {
    CLOSE_CALLS.set(CLOSE_CALLS.get() + 1);
    let result = rte_eth_dev_close(port);
    if result == 0 && FAULTS.get().close_after_success {
        -5
    } else {
        result
    }
}

pub(super) unsafe fn eth_tx_burst(
    port: u16,
    queue: u16,
    packets: *mut *mut rte_mbuf,
    count: u16,
) -> u16 {
    TX_CALLS.set(TX_CALLS.get() + 1);
    let faults = FAULTS.get();
    let offered = faults.tx_accept_limit.map_or(count, |limit| count.min(limit));
    let accepted = dpdk_raw_eth_tx_burst(port, queue, packets, offered);
    if let Some(ring) = faults.tx_free_ring {
        // No assertions here: a panic inside the PMD call is not the model.
        let mut taken = [null_mut::<c_void>(); 16];
        let freed = dpdk_raw_ring_dequeue_burst(
            ring.as_ptr(),
            taken.as_mut_ptr(),
            u32::from(accepted),
            null_mut(),
        );
        for &packet in &taken[..freed as usize] {
            dpdk_raw_pktmbuf_free(packet.cast());
        }
        TX_FREED.set(TX_FREED.get() + freed);
        for slot in 0..usize::from(count) {
            *packets.add(slot) = NonNull::dangling().as_ptr();
        }
    }
    accepted + faults.tx_report_extra
}

pub(crate) unsafe fn eth_tx_prepare(
    port: u16,
    queue: u16,
    packets: *mut *mut rte_mbuf,
    count: u16,
) -> u16 {
    PREPARE_CALLS.set(PREPARE_CALLS.get() + 1);
    PREPARE_ARGS.set((port, queue, count));
    PREPARE_PACKETS.with_borrow_mut(|calls| {
        calls.push(
            (0..usize::from(count))
                .map(|index| *packets.add(index) as usize)
                .collect(),
        );
    });
    if FAULTS.get().tx_prepare_refuse {
        0
    } else if let Some(limit) = FAULTS.get().tx_prepare_limit {
        count.min(limit)
    } else {
        dpdk_raw_eth_tx_prepare(port, queue, packets, count)
    }
}

pub(crate) fn prepare_calls() -> u32 {
    PREPARE_CALLS.get()
}

pub(crate) fn prepare_args() -> (u16, u16, u16) {
    PREPARE_ARGS.get()
}

pub(crate) fn prepare_packets() -> Vec<Vec<usize>> {
    PREPARE_PACKETS.with_borrow(Clone::clone)
}

pub(crate) fn enable_tx_tcp_checksum(port: &mut Port) {
    port.tx_tcp_checksum = true;
}

pub(crate) fn enable_tx_udp_checksum(port: &mut Port) {
    port.force_tx_udp_checksum();
}

pub(super) unsafe fn tx_done_cleanup(port: u16, queue: u16, free_cnt: u32) -> i32 {
    CLEANUP_CALLS.set(CLEANUP_CALLS.get() + 1);
    let faults = FAULTS.get();
    let result = if let Some(code) = faults.cleanup_code {
        code
    } else if let Some(ring) = faults.cleanup_reclaim_ring {
        let mut reclaimed = 0;
        loop {
            let mut taken = [null_mut::<c_void>(); 16];
            let count =
                dpdk_raw_ring_dequeue_burst(ring.as_ptr(), taken.as_mut_ptr(), 16, null_mut());
            for &packet in &taken[..count as usize] {
                dpdk_raw_pktmbuf_free(packet.cast());
            }
            if count == 0 {
                break reclaimed;
            }
            reclaimed += count as i32;
        }
    } else {
        rte_eth_tx_done_cleanup(port, queue, free_cnt)
    };
    CLEANUP_RESULT.set(result);
    result
}

pub(super) unsafe fn eth_rx_burst(
    port: u16,
    queue: u16,
    packets: *mut *mut rte_mbuf,
    count: u16,
) -> u16 {
    RX_CALLS.set(RX_CALLS.get() + 1);
    dpdk_raw_eth_rx_burst(port, queue, packets, count)
}

/// TX burst calls that reached the PMD seam so far on this thread.
pub(crate) fn tx_calls() -> u32 {
    TX_CALLS.get()
}

pub(crate) struct Fixture {
    port_id: u16,
    vdev: CString,
    rings: Vec<*mut rte_ring>,
    attached: bool,
    cleanup_attempted: bool,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let mut fixture = Self {
            port_id: u16::MAX,
            vdev: CString::new("net_ring_port_setup").unwrap(),
            rings: Vec::with_capacity(2),
            attached: false,
            cleanup_attempted: false,
        };
        for name in [c"port_setup_rx", c"port_setup_tx"] {
            let ring =
                unsafe { rte_ring_create(name.as_ptr(), 8, -1, RING_F_SP_ENQ | RING_F_SC_DEQ) };
            assert!(!ring.is_null());
            fixture.rings.push(ring);
        }
        let port = unsafe {
            rte_eth_from_rings(
                c"port_setup".as_ptr(),
                &fixture.rings[0],
                1,
                &fixture.rings[1],
                1,
                0,
            )
        };
        assert!(port >= 0);
        fixture.port_id = port as u16;
        fixture.attached = true;
        fixture
    }

    pub(crate) fn config(&self) -> PortConfig<'static> {
        Self::config_for_port(self.port_id)
    }

    pub(crate) fn config_for_port(port_id: u16) -> PortConfig<'static> {
        let pool = |name, room| PoolConfig {
            name,
            count: 63,
            cache_size: 8,
            data_room_size: RTE_PKTMBUF_HEADROOM as u16 + room,
            socket_id: -1,
        };
        PortConfig {
            port_id,
            mtu: 1500,
            rx_descriptors: 8,
            tx_descriptors: 16,
            rx_burst: 4,
            tx_burst: 4,
            queue_socket: -1,
            rx_pool: pool(c"port_pool_rx", 2048),
            tx_pool: pool(c"port_pool_tx", 1514),
            offloads: Offloads::default(),
        }
    }

    fn drain(&self) {
        for &ring in &self.rings {
            let mut raw = [null_mut::<c_void>(); 16];
            loop {
                let count =
                    unsafe { dpdk_raw_ring_dequeue_burst(ring, raw.as_mut_ptr(), 16, null_mut()) };
                for &packet in &raw[..count as usize] {
                    unsafe { dpdk_raw_pktmbuf_free(packet.cast()) };
                }
                if count == 0 {
                    break;
                }
            }
        }
    }

    fn cleanup(&mut self) -> Result<(), i32> {
        if unsafe { rte_eth_dev_is_valid_port(self.port_id) } != 0 {
            let result = unsafe { rte_eth_dev_stop(self.port_id) };
            if result != 0 {
                return Err(result);
            }
            let result = unsafe { rte_eth_dev_close(self.port_id) };
            if result != 0 {
                return Err(result);
            }
        }
        if self.attached {
            let result = unsafe { rte_vdev_uninit(self.vdev.as_ptr()) };
            if result != 0 {
                return Err(result);
            }
            self.attached = false;
        }
        self.drain();
        for ring in self.rings.drain(..) {
            unsafe { rte_ring_free(ring) };
        }
        Ok(())
    }

    pub(crate) fn close(mut self) -> Result<(), i32> {
        self.cleanup_attempted = true;
        self.cleanup()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if !self.cleanup_attempted {
            self.cleanup_attempted = true;
            if let Err(error) = self.cleanup() {
                use std::io::Write;
                let _ = writeln!(
                    std::io::stderr(),
                    "Port fixture retained rings after cleanup error {error}"
                );
            }
        }
    }
}

pub(crate) fn assert_no_pools() {
    for name in [c"port_pool_rx", c"port_pool_tx"] {
        assert!(unsafe { rte_mempool_lookup(name.as_ptr()) }.is_null());
    }
}

#[zhida_test_support::pinned_test]
fn real_open_start_close_reuses_all_names_and_reports_descriptors() {
    with_test_eal(|eal| {
        for _ in 0..3 {
            let fixture = Fixture::new();
            let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
            assert_eq!(port.descriptor_counts(), (8, 16));
            let mut conf: rte_eth_conf = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { rte_eth_dev_conf_get(fixture.port_id, &mut conf) },
                0
            );
            assert_eq!(conf.rxmode.mtu, 1500);
            assert_eq!((conf.rxmode.offloads, conf.txmode.offloads), (0, 0));
            for (pool, room) in [(&port.rx, 2048), (&port.tx, 1514)] {
                let packet = pool.pool().alloc().unwrap();
                assert_eq!(packet.tailroom(), room);
                assert_eq!(packet.headroom(), RTE_PKTMBUF_HEADROOM as u16);
            }
            // Prove a real started queue using one valid software producer packet.
            let mut packet = port.tx.pool().alloc_with_len(4).unwrap();
            packet.data_mut().copy_from_slice(b"real");
            let mut raw = [packet.into_raw().as_ptr()];
            assert_eq!(
                unsafe { dpdk_raw_eth_tx_burst(fixture.port_id, 0, raw.as_mut_ptr(), 1) },
                1
            );
            fixture.drain();
            port.try_close().unwrap();
            assert_eq!(unsafe { rte_eth_dev_is_valid_port(fixture.port_id) }, 0);
            assert_no_pools();
            fixture.close().unwrap();
        }
    });
}

#[zhida_test_support::pinned_test]
fn preflight_failures_leave_the_caller_device_and_pool_names_untouched() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let baseline = fixture.config();
        let mut configs = [baseline; 9];
        configs[0].port_id = u16::MAX;
        configs[1].rx_descriptors = 0;
        configs[2].tx_descriptors = 0;
        configs[3].mtu = 1;
        configs[4].rx_pool.data_room_size -= 1;
        configs[5].tx_pool.data_room_size -= 1;
        configs[6].mtu = u16::MAX;
        configs[7].tx_burst = 0;
        configs[8].rx_burst = 0;
        for config in configs {
            let error = unsafe { Port::open(eal, config) }.unwrap_err();
            assert!(error.retained.is_none());
            assert!(error.rollback_error.is_none());
            assert_eq!(unsafe { rte_eth_dev_is_valid_port(fixture.port_id) }, 1);
            assert_eq!(
                unsafe { rte_eth_dev_start(fixture.port_id) },
                -(EINVAL as i32)
            );
            assert_no_pools();
        }
        let port = unsafe { Port::open(eal, baseline) }.unwrap();
        port.try_close().unwrap();
    });
}

#[zhida_test_support::pinned_test]
fn open_rejects_exact_fit_room_below_rule() {
    with_test_eal(|eal| {
        for (mtu, required_room, short_rooms) in
            [(1500, 2048, &[1514, 2047][..]), (9000, 9216, &[9215][..])]
        {
            let fixture = Fixture::new();
            let mut config = fixture.config();
            config.mtu = mtu;
            config.tx_pool.data_room_size = RTE_PKTMBUF_HEADROOM as u16 + mtu + 14;
            let (stops, closes) = (STOP_CALLS.get(), CLOSE_CALLS.get());
            assert_no_pools();
            for &room in short_rooms {
                config.rx_pool.data_room_size = RTE_PKTMBUF_HEADROOM as u16 + room;
                let error = unsafe { Port::open(eal, config) }.unwrap_err();
                assert_eq!(
                    error.cause,
                    PortError::InvalidSettings(
                        "RX usable room must be at least ceil1024(MTU + 26) for single-segment RX"
                    )
                );
                assert!(error.retained.is_none());
                assert!(error.rollback_error.is_none());
                assert_eq!((STOP_CALLS.get(), CLOSE_CALLS.get()), (stops, closes));
                assert_eq!(unsafe { rte_eth_dev_is_valid_port(fixture.port_id) }, 1);
                assert_eq!(
                    unsafe { rte_eth_dev_start(fixture.port_id) },
                    -(EINVAL as i32)
                );
                assert_no_pools();
            }
            config.rx_pool.data_room_size = RTE_PKTMBUF_HEADROOM as u16 + required_room;
            let port = unsafe { Port::open(eal, config) }.unwrap();
            assert_eq!(in_use(&port), (0, 0));
            port.try_close().unwrap();
            assert_no_pools();
            fixture.close().unwrap();
        }
    });
}

#[zhida_test_support::pinned_test]
fn open_fails_when_pmd_reports_scattered_rx() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let guard = FaultGuard::new(Faults {
            rxq_info_scattered_rx: Some(1),
            ..Faults::default()
        });
        let (stops, closes) = (STOP_CALLS.get(), CLOSE_CALLS.get());
        let error = unsafe { Port::open(eal, fixture.config()) }.unwrap_err();
        assert_eq!(
            error.cause,
            PortError::InvalidSettings(
                "PMD enabled scattered RX; only single-segment RX is supported"
            )
        );
        assert!(error.retained.is_none());
        assert!(error.rollback_error.is_none());
        assert_eq!(
            (STOP_CALLS.get(), CLOSE_CALLS.get()),
            (stops + 1, closes + 1)
        );
        assert_eq!(unsafe { rte_eth_dev_is_valid_port(fixture.port_id) }, 0);
        assert_no_pools();
        drop(guard);
        fixture.close().unwrap();
    });
}

#[zhida_test_support::pinned_test]
fn open_fails_when_rxq_info_errors() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let guard = FaultGuard::new(Faults {
            rxq_info_code: Some(-5),
            ..Faults::default()
        });
        let (stops, closes) = (STOP_CALLS.get(), CLOSE_CALLS.get());
        let error = unsafe { Port::open(eal, fixture.config()) }.unwrap_err();
        assert_eq!(
            error.cause,
            PortError::Dpdk {
                operation: "rte_eth_rx_queue_info_get",
                code: -5
            }
        );
        assert!(error.retained.is_none());
        assert!(error.rollback_error.is_none());
        assert_eq!(
            (STOP_CALLS.get(), CLOSE_CALLS.get()),
            (stops + 1, closes + 1)
        );
        assert_eq!(unsafe { rte_eth_dev_is_valid_port(fixture.port_id) }, 0);
        assert_no_pools();
        drop(guard);
        fixture.close().unwrap();
    });
}

#[zhida_test_support::pinned_test]
fn open_succeeds_when_rxq_info_unsupported() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let guard = FaultGuard::new(Faults {
            rxq_info_code: Some(-(ENOTSUP as i32)),
            ..Faults::default()
        });
        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        assert!(port.ready);
        assert_eq!(in_use(&port), (0, 0));
        port.try_close().unwrap();
        assert_no_pools();
        drop(guard);
        fixture.close().unwrap();
    });
}

#[zhida_test_support::pinned_test]
fn open_succeeds_when_pmd_reports_single_segment_rx() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let guard = FaultGuard::new(Faults {
            rxq_info_scattered_rx: Some(0),
            ..Faults::default()
        });
        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        assert!(port.ready);
        port.try_close().unwrap();
        assert_no_pools();
        drop(guard);
        fixture.close().unwrap();
    });
}

#[zhida_test_support::pinned_test]
fn tx_pool_creation_failure_releases_rx_without_adopting_device() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let mut config = fixture.config();
        config.tx_pool.name = config.rx_pool.name;
        let error = unsafe { Port::open(eal, config) }.unwrap_err();
        assert!(matches!(
            error.cause,
            PortError::Pool {
                direction: "TX",
                ..
            }
        ));
        assert!(error.retained.is_none());
        assert_eq!(unsafe { rte_eth_dev_is_valid_port(fixture.port_id) }, 1);
        assert_eq!(
            unsafe { rte_eth_dev_start(fixture.port_id) },
            -(EINVAL as i32)
        );
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn actual_late_tx_queue_failure_rolls_back_and_start_error_stops_running_port() {
    with_test_eal(|eal| {
        for fault in [
            Faults {
                tx_queue: 1,
                ..Faults::default()
            },
            Faults {
                start_after_success: true,
                ..Faults::default()
            },
        ] {
            let fixture = Fixture::new();
            let guard = FaultGuard::new(fault);
            let stops = STOP_CALLS.get();
            let error = unsafe { Port::open(eal, fixture.config()) }.unwrap_err();
            let expected = if fault.start_after_success {
                "rte_eth_dev_start"
            } else {
                "rte_eth_tx_queue_setup"
            };
            assert!(
                matches!(error.cause, PortError::Dpdk { operation, .. } if operation == expected)
            );
            assert!(error.retained.is_none());
            assert_eq!(STOP_CALLS.get(), stops + 1);
            assert_eq!(unsafe { rte_eth_dev_is_valid_port(fixture.port_id) }, 0);
            assert_no_pools();
            drop(guard);
        }
    });
}

#[zhida_test_support::pinned_test]
fn rollback_stop_refusal_retains_both_empty_pools_and_original_error() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let guard = FaultGuard::new(Faults {
            tx_queue: 1,
            stop_before_call: true,
            ..Faults::default()
        });
        let mut error = unsafe { Port::open(eal, fixture.config()) }.unwrap_err();
        assert_eq!(
            error.cause,
            PortError::Dpdk {
                operation: "rte_eth_tx_queue_setup",
                code: -(EINVAL as i32)
            }
        );
        assert_eq!(
            error.rollback_error,
            Some(PortError::Dpdk {
                operation: "rte_eth_dev_stop",
                code: -5
            })
        );
        let port = error.retained.take().unwrap();
        assert_eq!(port.rx.pool().in_use_count(), 0);
        assert_eq!(port.tx.pool().in_use_count(), 0);
        assert_eq!(
            unsafe { rte_mempool_lookup(c"port_pool_rx".as_ptr()) },
            port.rx.pool().pool()
        );
        assert_eq!(
            unsafe { rte_mempool_lookup(c"port_pool_tx".as_ptr()) },
            port.tx.pool().pool()
        );
        assert_eq!(unsafe { rte_eth_dev_is_valid_port(fixture.port_id) }, 1);
        drop(guard);
        port.try_close().unwrap();
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn released_id_close_error_latches_and_never_retries_device_or_frees_empty_pools() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let (rx, tx) = (port.rx.pool().pool(), port.tx.pool().pool());
        let guard = FaultGuard::new(Faults {
            close_after_success: true,
            ..Faults::default()
        });
        let (port, error) = port.try_close().unwrap_err();
        assert_eq!(
            error,
            PortError::Dpdk {
                operation: "rte_eth_dev_close",
                code: -5
            }
        );
        assert!(port.closed);
        assert_eq!(unsafe { rte_eth_dev_is_valid_port(fixture.port_id) }, 0);
        drop(guard);
        let (stops, closes) = (STOP_CALLS.get(), CLOSE_CALLS.get());
        let (mut port, retry_error) = port.try_close().unwrap_err();
        assert_eq!(retry_error, error);
        assert_eq!((STOP_CALLS.get(), CLOSE_CALLS.get()), (stops, closes));
        assert_eq!(unsafe { rte_mempool_lookup(c"port_pool_rx".as_ptr()) }, rx);
        assert_eq!(unsafe { rte_mempool_lookup(c"port_pool_tx".as_ptr()) }, tx);
        // The seam actually closed net_ring successfully. Reclaim this test's
        // empty backing explicitly; production has no recovery for this error.
        assert_eq!(
            (port.rx.pool().in_use_count(), port.tx.pool().in_use_count()),
            (0, 0)
        );
        unsafe {
            ManuallyDrop::drop(&mut port.rx);
            ManuallyDrop::drop(&mut port.tx);
        }
        port.released = true;
        drop(port);
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn attached_ring_packet_survives_device_close_until_external_drain() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let mut packet = port.tx.pool().alloc_with_len(4).unwrap();
        packet.data_mut().copy_from_slice(b"live");
        let identity = packet.as_ptr();
        let raw = [packet.into_raw().as_ptr().cast::<c_void>()];
        assert_eq!(
            unsafe { dpdk_raw_ring_enqueue_burst(fixture.rings[1], raw.as_ptr(), 1, null_mut()) },
            1
        );
        let (port, error) = port.try_close().unwrap_err();
        assert_eq!(error, PortError::OutstandingBuffers { rx: 0, tx: 1 });
        assert!(port.closed);
        let mut returned = [null_mut::<c_void>(); 1];
        assert_eq!(
            unsafe {
                dpdk_raw_ring_dequeue_burst(fixture.rings[1], returned.as_mut_ptr(), 1, null_mut())
            },
            1
        );
        assert_eq!(returned[0].cast::<rte_mbuf>(), identity);
        assert_eq!(
            unsafe { std::slice::from_raw_parts((*identity).data_ptr(), 4) },
            b"live"
        );
        unsafe { dpdk_raw_pktmbuf_free(identity) };
        port.try_close().unwrap();
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn port_drop_preserves_original_panic_and_releases_names() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
            panic!("original port panic");
        }))
        .unwrap_err();
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"original port panic"));
        assert_eq!(unsafe { rte_eth_dev_is_valid_port(fixture.port_id) }, 0);
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn actual_config_readback_validation_rejects_changed_mtu() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let mut conf: rte_eth_conf = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { rte_eth_dev_conf_get(fixture.port_id, &mut conf) },
            0
        );
        assert_eq!(check_configuration(1500, Offloads::default(), &conf), Ok(()));
        // Mutate the real readback to test validation, not PMD behavior.
        conf.rxmode.mtu = 1499;
        assert_eq!(
            check_configuration(1500, Offloads::default(), &conf),
            Err(PortError::InvalidSettings("PMD changed the requested MTU"))
        );
        port.try_close().unwrap();
        assert_eq!(fixture.close(), Ok(()));
        assert_no_pools();
    });
}

const RX_CHECKSUM: Offloads = Offloads {
    rx_timestamp: false,
    rx_checksum: true,
    tx_tcp_checksum: false,
    tx_udp_checksum: false,
};
const TX_CHECKSUM: Offloads = Offloads {
    rx_timestamp: false,
    rx_checksum: false,
    tx_tcp_checksum: true,
    tx_udp_checksum: false,
};
const BOTH_CHECKSUMS: Offloads = Offloads {
    rx_timestamp: false,
    rx_checksum: true,
    tx_tcp_checksum: true,
    tx_udp_checksum: false,
};

const TX_UDP_CHECKSUM: Offloads = Offloads {
    rx_timestamp: false,
    rx_checksum: false,
    tx_tcp_checksum: false,
    tx_udp_checksum: true,
};

const TX_TCP_UDP_CHECKSUMS: Offloads = Offloads {
    rx_timestamp: false,
    rx_checksum: false,
    tx_tcp_checksum: true,
    tx_udp_checksum: true,
};

#[zhida_test_support::pinned_test]
fn missing_rx_timestamp_offload_is_error() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let config = PortConfig {
            offloads: Offloads {
                rx_timestamp: true,
                ..Offloads::default()
            },
            ..fixture.config()
        };
        // SAFETY: the fixture owns this newly created ethdev and its rings on
        // the EAL owner thread; Port::open preserves the production pool contract.
        let error = unsafe { Port::open(eal, config) }.unwrap_err();
        assert_eq!(
            error.cause,
            PortError::InvalidSettings("PMD lacks the requested RX timestamp offload")
        );
        assert!(error.retained.is_none());
        assert!(error.rollback_error.is_none());
        assert_no_pools();
        // SAFETY: the failed preflight left the fixture's ethdev unconfigured.
        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        assert!(port.rx_timestamp_field().is_none());
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn rx_timestamp_readback_must_match() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        // SAFETY: the fixture owns this newly created ethdev and its rings on
        // the EAL owner thread; Port::open preserves the production pool contract.
        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        // SAFETY: an all-zero rte_eth_conf is valid storage for the readback.
        let mut conf: rte_eth_conf = unsafe { std::mem::zeroed() };
        // SAFETY: the configured port is live and conf is writable call storage.
        assert_eq!(unsafe { rte_eth_dev_conf_get(fixture.port_id, &mut conf) }, 0);
        let offloads = Offloads {
            rx_timestamp: true,
            ..Offloads::default()
        };
        assert_eq!(conf.rxmode.offloads & RX_OFFLOAD_TIMESTAMP, 0);
        assert_eq!(
            check_configuration(1500, offloads, &conf),
            Err(PortError::InvalidSettings("PMD dropped requested offloads"))
        );
        conf.rxmode.offloads |= RX_OFFLOAD_TIMESTAMP;
        assert_eq!(
            check_configuration(1500, Offloads::default(), &conf),
            Err(PortError::InvalidSettings("PMD enabled unrequested offloads"))
        );
        assert_eq!(check_configuration(1500, offloads, &conf), Ok(()));
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

/// net_ring advertises no checksum offloads. Requesting one fails before
/// pool acquisition with an error naming it, leaving the device unconfigured
/// with the caller; a readback lacking a requested bit fails too.
#[zhida_test_support::pinned_test]
fn missing_requested_offload_is_error() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        for (offloads, message) in [
            (RX_CHECKSUM, "PMD lacks the requested RX IPv4/TCP/UDP checksum offload"),
            (TX_CHECKSUM, "PMD lacks the requested TX TCP checksum offload"),
            (TX_UDP_CHECKSUM, "PMD lacks the requested TX UDP checksum offload"),
            (TX_TCP_UDP_CHECKSUMS, "PMD lacks the requested TX TCP checksum offload"),
            (BOTH_CHECKSUMS, "PMD lacks the requested RX IPv4/TCP/UDP checksum offload"),
        ] {
            let config = PortConfig {
                offloads,
                ..fixture.config()
            };
            let error = unsafe { Port::open(eal, config) }.unwrap_err();
            assert_eq!(error.cause, PortError::InvalidSettings(message));
            assert!(error.retained.is_none());
            assert!(error.rollback_error.is_none());
            assert_eq!(unsafe { rte_eth_dev_is_valid_port(fixture.port_id) }, 1);
            assert_eq!(
                unsafe { rte_eth_dev_start(fixture.port_id) },
                -(EINVAL as i32)
            );
            assert_no_pools();
        }

        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let mut conf: rte_eth_conf = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { rte_eth_dev_conf_get(fixture.port_id, &mut conf) },
            0
        );
        // Mutate the real readback to test validation, not PMD behavior.
        let dropped = Err(PortError::InvalidSettings("PMD dropped requested offloads"));
        assert_eq!(check_configuration(1500, RX_CHECKSUM, &conf), dropped);
        assert_eq!(check_configuration(1500, TX_CHECKSUM, &conf), dropped);
        assert_eq!(check_configuration(1500, TX_UDP_CHECKSUM, &conf), dropped);
        conf.txmode.offloads = TX_OFFLOAD_TCP_CKSUM;
        assert_eq!(check_configuration(1500, TX_TCP_UDP_CHECKSUMS, &conf), dropped);
        conf.txmode.offloads = 0;
        conf.rxmode.offloads = RX_OFFLOAD_IPV4_CKSUM;
        assert_eq!(check_configuration(1500, RX_CHECKSUM, &conf), dropped);
        conf.rxmode.offloads = RX_OFFLOAD_IPV4_CKSUM | RX_OFFLOAD_TCP_CKSUM;
        assert_eq!(check_configuration(1500, RX_CHECKSUM, &conf), dropped);
        conf.rxmode.offloads = RX_OFFLOAD_IPV4_CKSUM | RX_OFFLOAD_UDP_CKSUM | RX_OFFLOAD_TCP_CKSUM;
        assert_eq!(check_configuration(1500, RX_CHECKSUM, &conf), Ok(()));
        assert_eq!(check_configuration(1500, BOTH_CHECKSUMS, &conf), dropped);
        port.try_close().unwrap();
        assert_eq!(fixture.close(), Ok(()));
        assert_no_pools();
    });
}

/// A readback holding any offload bit outside the requested set fails, with
/// or without a requested profile.
#[zhida_test_support::pinned_test]
fn unrequested_offload_is_error() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let mut conf: rte_eth_conf = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { rte_eth_dev_conf_get(fixture.port_id, &mut conf) },
            0
        );
        // Mutate the real readback to test validation, not PMD behavior.
        let unrequested = Err(PortError::InvalidSettings("PMD enabled unrequested offloads"));
        conf.rxmode.offloads = 1;
        assert_eq!(check_configuration(1500, Offloads::default(), &conf), unrequested);
        conf.rxmode.offloads = 0;
        conf.txmode.offloads = 1;
        assert_eq!(check_configuration(1500, Offloads::default(), &conf), unrequested);
        conf.txmode.offloads = TX_OFFLOAD_TCP_CKSUM;
        assert_eq!(check_configuration(1500, Offloads::default(), &conf), unrequested);
        assert_eq!(check_configuration(1500, TX_CHECKSUM, &conf), Ok(()));
        conf.txmode.offloads = TX_OFFLOAD_UDP_CKSUM;
        assert_eq!(check_configuration(1500, Offloads::default(), &conf), unrequested);
        assert_eq!(check_configuration(1500, TX_UDP_CHECKSUM, &conf), Ok(()));
        conf.txmode.offloads = TX_OFFLOAD_TCP_CKSUM | TX_OFFLOAD_UDP_CKSUM;
        assert_eq!(check_configuration(1500, TX_CHECKSUM, &conf), unrequested);
        conf.txmode.offloads = TX_OFFLOAD_TCP_CKSUM;
        conf.rxmode.offloads = RX_OFFLOAD_IPV4_CKSUM | RX_OFFLOAD_UDP_CKSUM | RX_OFFLOAD_TCP_CKSUM;
        assert_eq!(check_configuration(1500, RX_CHECKSUM, &conf), unrequested);
        assert_eq!(check_configuration(1500, BOTH_CHECKSUMS, &conf), Ok(()));
        conf.rxmode.offloads = 0;
        conf.txmode.offloads = TX_OFFLOAD_TCP_CKSUM | 1;
        assert_eq!(check_configuration(1500, TX_CHECKSUM, &conf), unrequested);
        conf.txmode.offloads = 0;
        conf.rxmode.offloads = RX_OFFLOAD_IPV4_CKSUM | RX_OFFLOAD_UDP_CKSUM | RX_OFFLOAD_TCP_CKSUM | 1;
        assert_eq!(check_configuration(1500, RX_CHECKSUM, &conf), unrequested);
        port.try_close().unwrap();
        assert_eq!(fixture.close(), Ok(()));
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn forced_multi_segs_accepted() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let mut conf: rte_eth_conf = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { rte_eth_dev_conf_get(fixture.port_id, &mut conf) },
            0
        );
        // Mutate the real readback the way the ENA PMD does at configure.
        conf.txmode.offloads = TX_OFFLOAD_MULTI_SEGS;
        assert_eq!(check_configuration(1500, Offloads::default(), &conf), Ok(()));
        conf.txmode.offloads = TX_OFFLOAD_MULTI_SEGS | TX_OFFLOAD_TCP_CKSUM | TX_OFFLOAD_UDP_CKSUM;
        assert_eq!(check_configuration(1500, TX_TCP_UDP_CHECKSUMS, &conf), Ok(()));
        // MULTI_SEGS does not stand in for a requested offload.
        conf.txmode.offloads = TX_OFFLOAD_MULTI_SEGS;
        assert_eq!(
            check_configuration(1500, TX_CHECKSUM, &conf),
            Err(PortError::InvalidSettings("PMD dropped requested offloads"))
        );
        port.try_close().unwrap();
        assert_eq!(fixture.close(), Ok(()));
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn unknown_forced_offload_still_refused() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let mut conf: rte_eth_conf = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { rte_eth_dev_conf_get(fixture.port_id, &mut conf) },
            0
        );
        let unrequested = Err(PortError::InvalidSettings("PMD enabled unrequested offloads"));
        // Bit 15 is tolerated only in txmode.
        conf.rxmode.offloads = 1 << 15;
        assert_eq!(check_configuration(1500, Offloads::default(), &conf), unrequested);
        conf.rxmode.offloads = 0;
        conf.txmode.offloads = TX_OFFLOAD_MULTI_SEGS | 1 << 16;
        assert_eq!(check_configuration(1500, Offloads::default(), &conf), unrequested);
        conf.txmode.offloads = TX_OFFLOAD_MULTI_SEGS | 1;
        assert_eq!(check_configuration(1500, Offloads::default(), &conf), unrequested);
        port.try_close().unwrap();
        assert_eq!(fixture.close(), Ok(()));
        assert_no_pools();
    });
}

/// ENA sets scattered RX without `rx_queue_info_get`; the room rule alone
/// must refuse a frame that would chain.
#[zhida_test_support::pinned_test]
fn room_rule_refuses_when_rxq_info_unsupported() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let guard = FaultGuard::new(Faults {
            rxq_info_code: Some(-(ENOTSUP as i32)),
            ..Faults::default()
        });
        let mut config = fixture.config();
        config.mtu = 1500;
        config.tx_pool.data_room_size = RTE_PKTMBUF_HEADROOM as u16 + 1514;
        config.rx_pool.data_room_size = RTE_PKTMBUF_HEADROOM as u16 + 1500 + 26 - 1;
        let error = unsafe { Port::open(eal, config) }.unwrap_err();
        assert_eq!(
            error.cause,
            PortError::InvalidSettings(
                "RX usable room must be at least ceil1024(MTU + 26) for single-segment RX"
            )
        );
        assert!(error.retained.is_none());
        assert_no_pools();
        config.rx_pool.data_room_size = RTE_PKTMBUF_HEADROOM as u16 + 2048;
        let port = unsafe { Port::open(eal, config) }.unwrap();
        port.try_close().unwrap();
        assert_no_pools();
        drop(guard);
        fixture.close().unwrap();
    });
}

#[zhida_test_support::pinned_test]
fn failed_drop_retains_empty_pools_preserves_panic_and_never_repeats_explicit_cleanup() {
    #[derive(Clone, Copy)]
    enum Case {
        OrdinaryDrop,
        Unwind,
        RefusedClose,
        RefusedSetup,
    }
    with_test_eal(|eal| {
        for case in [
            Case::OrdinaryDrop,
            Case::Unwind,
            Case::RefusedClose,
            Case::RefusedSetup,
        ] {
            let fixture = Fixture::new();
            let guard = FaultGuard::new(Faults {
                stop_before_call: true,
                tx_queue: if matches!(case, Case::RefusedSetup) {
                    1
                } else {
                    0
                },
                ..Faults::default()
            });
            let calls = (STOP_CALLS.get(), CLOSE_CALLS.get());
            let port = if matches!(case, Case::RefusedSetup) {
                let error = unsafe { Port::open(eal, fixture.config()) }.unwrap_err();
                assert!(error.rollback_error.is_some());
                error.retained.unwrap()
            } else {
                unsafe { Port::open(eal, fixture.config()) }.unwrap()
            };
            let pools = [port.rx.pool().pool(), port.tx.pool().pool()];
            assert_eq!(
                (port.rx.pool().in_use_count(), port.tx.pool().in_use_count()),
                (0, 0)
            );
            match case {
                Case::RefusedClose => {
                    let (port, error) = port.try_close().unwrap_err();
                    assert_eq!(
                        error,
                        PortError::Dpdk {
                            operation: "rte_eth_dev_stop",
                            code: -5
                        }
                    );
                    drop(port);
                }
                Case::Unwind => {
                    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                        let _port = port;
                        panic!("original refused-stop panic");
                    }))
                    .unwrap_err();
                    assert_eq!(
                        panic.downcast_ref::<&str>(),
                        Some(&"original refused-stop panic")
                    );
                }
                Case::OrdinaryDrop | Case::RefusedSetup => drop(port),
            }
            assert_eq!(
                (STOP_CALLS.get(), CLOSE_CALLS.get()),
                (calls.0 + 1, calls.1)
            );
            assert_eq!(unsafe { rte_eth_dev_is_valid_port(fixture.port_id) }, 1);
            for (name, pool) in [c"port_pool_rx", c"port_pool_tx"].into_iter().zip(pools) {
                assert_eq!(unsafe { rte_mempool_lookup(name.as_ptr()) }, pool);
                assert_eq!(unsafe { rte_mempool_in_use_count(pool) }, 0);
            }
            drop(guard);
            // The owner was dropped. Quiesce this real ring device before
            // reclaiming its known-empty retained backing in the test only.
            assert_eq!(unsafe { rte_eth_dev_stop(fixture.port_id) }, 0);
            assert_eq!(unsafe { rte_eth_dev_close(fixture.port_id) }, 0);
            for pool in pools {
                assert_eq!(unsafe { rte_mempool_in_use_count(pool) }, 0);
                unsafe { rte_mempool_free(pool) };
            }
            assert_eq!(fixture.close(), Ok(()));
            assert_no_pools();
        }
    });
}

#[zhida_test_support::pinned_test]
fn readiness_requires_successful_setup_and_is_revoked_on_refused_close() {
    with_test_eal(|eal| {
        for fault in [
            Faults {
                tx_queue: 1,
                stop_before_call: true,
                ..Faults::default()
            },
            Faults {
                start_after_success: true,
                stop_before_call: true,
                ..Faults::default()
            },
        ] {
            let fixture = Fixture::new();
            let guard = FaultGuard::new(fault);
            let error = unsafe { Port::open(eal, fixture.config()) }.unwrap_err();
            let port = error.retained.unwrap();
            assert!(!port.ready);
            assert!(!port.stopped);
            drop(guard);
            port.try_close().unwrap();
            fixture.close().unwrap();
            assert_no_pools();
        }

        let fixture = Fixture::new();
        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        assert!(port.ready);
        let guard = FaultGuard::new(Faults {
            stop_before_call: true,
            ..Faults::default()
        });
        let (port, error) = port.try_close().unwrap_err();
        assert_eq!(
            error,
            PortError::Dpdk {
                operation: "rte_eth_dev_stop",
                code: -5
            }
        );
        assert!(!port.ready);
        assert!(!port.stopped);
        drop(guard);
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();

        let fixture = Fixture::new();
        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        assert!(port.ready);
        let packet = port.tx.pool().alloc().unwrap();
        let (port, error) = port.try_close().unwrap_err();
        assert_eq!(error, PortError::OutstandingBuffers { rx: 0, tx: 1 });
        assert!(!port.ready);
        assert!(port.stopped);
        assert!(port.closed);
        drop(packet);
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

type Frames = Vec<(*mut rte_mbuf, Vec<u8>)>;

fn expected(identities: &[*mut rte_mbuf], base: u8) -> Frames {
    (base..)
        .zip(identities)
        .map(|(value, &identity)| (identity, vec![value, 0x55, 0xaa, value]))
        .collect()
}

fn pending_frames(pending: &VecDeque<Packet>) -> Frames {
    pending
        .iter()
        .map(|packet| (packet.0.as_ptr(), packet.data().to_vec()))
        .collect()
}

fn mbuf_frames(packets: &[Mbuf]) -> Frames {
    packets
        .iter()
        .map(|packet| (packet.as_ptr(), packet.data().to_vec()))
        .collect()
}

fn stage(port: &Port, pending: &mut VecDeque<Packet>, base: u8, count: u8) -> Vec<*mut rte_mbuf> {
    let mut identities = Vec::with_capacity(usize::from(count));
    for value in base..base + count {
        let mut packet = port.alloc_tx(4).unwrap();
        packet
            .data_mut()
            .copy_from_slice(&[value, 0x55, 0xaa, value]);
        identities.push(packet.0.as_ptr());
        pending.push_back(packet);
    }
    identities
}

/// The ring peer takes ownership of up to `max` packets from the port's TX ring.
pub(crate) fn peer_receive(fixture: &Fixture, max: u32) -> Vec<Mbuf> {
    ring_take(fixture.rings[1], max)
}

/// Take ownership of up to `max` packets queued in `ring`.
fn ring_take(ring: *mut rte_ring, max: u32) -> Vec<Mbuf> {
    let mut raw = [null_mut::<c_void>(); 16];
    let count = unsafe { dpdk_raw_ring_dequeue_burst(ring, raw.as_mut_ptr(), max, null_mut()) };
    raw[..count as usize]
        .iter()
        .map(|&packet| unsafe { Mbuf::from_raw(NonNull::new_unchecked(packet.cast())) })
        .collect()
}

#[zhida_test_support::pinned_test]
fn tx_burst_transfers_accepted_prefix_and_retries_ordered_suffix_after_saturation() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let mut port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let mut pending = VecDeque::with_capacity(16);
        assert_eq!(port.tx_burst(&mut pending), Ok(0));

        let ids = stage(&port, &mut pending, 10, 9);
        // Full acceptance of one four-packet burst.
        assert_eq!(port.tx_burst(&mut pending), Ok(4));
        assert_eq!(pending_frames(&pending), expected(&ids[4..], 14));
        // The eight-slot ring holds seven: partial acceptance.
        assert_eq!(port.tx_burst(&mut pending), Ok(3));
        assert_eq!(pending_frames(&pending), expected(&ids[7..], 17));
        // Saturated ring: zero acceptance leaves the suffix intact.
        assert_eq!(port.tx_burst(&mut pending), Ok(0));
        assert_eq!(pending_frames(&pending), expected(&ids[7..], 17));
        // Ring-accepted packets stay live until the peer releases them.
        assert_eq!(port.tx.pool().in_use_count(), 9);
        let received = peer_receive(&fixture, 4);
        assert_eq!(mbuf_frames(&received), expected(&ids[..4], 10));
        drop(received);
        assert_eq!(port.tx.pool().in_use_count(), 5);
        let received = peer_receive(&fixture, 16);
        assert_eq!(mbuf_frames(&received), expected(&ids[4..7], 14));
        drop(received);
        assert_eq!(port.tx_burst(&mut pending), Ok(2));
        assert!(pending.is_empty());
        let received = peer_receive(&fixture, 16);
        assert_eq!(mbuf_frames(&received), expected(&ids[7..], 17));
        drop(received);
        assert_eq!(port.tx.pool().in_use_count(), 0);

        // PMD-chosen partial and zero acceptance below the ring's capacity.
        let ids = stage(&port, &mut pending, 40, 3);
        let guard = FaultGuard::new(Faults {
            tx_accept_limit: Some(1),
            ..Faults::default()
        });
        assert_eq!(port.tx_burst(&mut pending), Ok(1));
        assert_eq!(pending_frames(&pending), expected(&ids[1..], 41));
        FAULTS.set(Faults {
            tx_accept_limit: Some(0),
            ..Faults::default()
        });
        assert_eq!(port.tx_burst(&mut pending), Ok(0));
        assert_eq!(pending_frames(&pending), expected(&ids[1..], 41));
        drop(guard);
        assert_eq!(port.tx_burst(&mut pending), Ok(2));
        let received = peer_receive(&fixture, 16);
        assert_eq!(mbuf_frames(&received), expected(&ids, 40));
        drop(received);
        assert_eq!(port.tx.pool().in_use_count(), 0);
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

/// Proves the owners of a prefix the PMD accepted and freed are disarmed: new
/// owners reuse those mbufs and nothing frees them a second time, while the
/// suffix stays owned and intact. Mempool memory stays mapped, so a stray read
/// of a freed mbuf would not be detected here.
#[zhida_test_support::pinned_test]
fn tx_burst_disarms_a_prefix_the_pmd_freed_synchronously() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let mut port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let mut pending = VecDeque::with_capacity(16);
        let ids = stage(&port, &mut pending, 20, 6);
        let freed = TX_FREED.get();
        let guard = FaultGuard::new(Faults {
            tx_accept_limit: Some(3),
            tx_free_ring: NonNull::new(fixture.rings[1]),
            ..Faults::default()
        });
        assert_eq!(port.tx_burst(&mut pending), Ok(3));
        drop(guard);
        assert_eq!(TX_FREED.get(), freed + 3);
        assert_eq!(pending_frames(&pending), expected(&ids[3..], 23));
        assert_eq!(port.tx.pool().in_use_count(), 3);
        // The freed objects are reusable by a new owner; a stale Rust owner
        // would free them a second time when `pending` or these drop.
        let reused: Vec<Packet> = (0..3).map(|_| port.alloc_tx(4).unwrap()).collect();
        let mut reused_ids: Vec<_> = reused.iter().map(|packet| packet.0.as_ptr()).collect();
        reused_ids.sort();
        let mut freed_ids = ids[..3].to_vec();
        freed_ids.sort();
        assert_eq!(reused_ids, freed_ids);
        assert_eq!(port.tx.pool().in_use_count(), 6);
        assert_eq!(port.tx_burst(&mut pending), Ok(3));
        let received = peer_receive(&fixture, 16);
        assert_eq!(mbuf_frames(&received), expected(&ids[3..], 23));
        drop(received);
        drop(reused);
        assert_eq!(port.tx.pool().in_use_count(), 0);
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn tx_burst_never_disarms_packets_a_pmd_over_reports_but_was_not_offered() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let mut port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let mut pending = VecDeque::with_capacity(16);
        let ids = stage(&port, &mut pending, 50, 6);
        // Four offered and accepted; the PMD reports six.
        let guard = FaultGuard::new(Faults {
            tx_report_extra: 2,
            ..Faults::default()
        });
        assert_eq!(port.tx_burst(&mut pending), Ok(4));
        drop(guard);
        assert_eq!(pending_frames(&pending), expected(&ids[4..], 54));
        assert_eq!(port.tx.pool().in_use_count(), 6);
        let received = peer_receive(&fixture, 16);
        assert_eq!(mbuf_frames(&received), expected(&ids[..4], 50));
        drop(received);
        assert_eq!(port.tx.pool().in_use_count(), 2);
        assert_eq!(port.tx_burst(&mut pending), Ok(2));
        assert!(pending.is_empty());
        let received = peer_receive(&fixture, 16);
        assert_eq!(mbuf_frames(&received), expected(&ids[4..], 54));
        drop(received);
        assert_eq!(port.tx.pool().in_use_count(), 0);
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn tx_burst_refuses_unready_ports_without_calling_the_pmd() {
    with_test_eal(|eal| {
        // Retained after failed setup, then after a refused close.
        let fixture = Fixture::new();
        let guard = FaultGuard::new(Faults {
            tx_queue: 1,
            stop_before_call: true,
            ..Faults::default()
        });
        let mut port = unsafe { Port::open(eal, fixture.config()) }
            .unwrap_err()
            .retained
            .unwrap();
        drop(guard);
        let mut pending = VecDeque::with_capacity(4);
        let ids = stage(&port, &mut pending, 60, 2);
        let calls = TX_CALLS.get();
        assert_eq!(port.tx_burst(&mut pending), Err(PortError::NotReady));
        assert_eq!(TX_CALLS.get(), calls);
        assert_eq!(pending_frames(&pending), expected(&ids, 60));
        drop(pending);
        port.try_close().unwrap();
        fixture.close().unwrap();

        let fixture = Fixture::new();
        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let mut pending = VecDeque::with_capacity(4);
        let ids = stage(&port, &mut pending, 70, 2);
        let guard = FaultGuard::new(Faults {
            stop_before_call: true,
            ..Faults::default()
        });
        let (mut port, _) = port.try_close().unwrap_err();
        drop(guard);
        let calls = TX_CALLS.get();
        assert_eq!(port.tx_burst(&mut pending), Err(PortError::NotReady));
        assert_eq!(TX_CALLS.get(), calls);
        assert_eq!(pending_frames(&pending), expected(&ids, 70));
        assert!(peer_receive(&fixture, 16).is_empty());
        drop(pending);
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

/// An idle flush offers nothing: `tx_burst` returns 0 without the PMD call
/// that memif's copy-mode TX mishandles for an empty burst.
#[zhida_test_support::pinned_test]
fn tx_burst_with_nothing_pending_never_calls_the_pmd() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let mut port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let mut pending = VecDeque::with_capacity(4);
        let calls = TX_CALLS.get();
        for _ in 0..3 {
            assert_eq!(port.tx_burst(&mut pending), Ok(0));
        }
        assert_eq!(TX_CALLS.get(), calls);
        stage(&port, &mut pending, 80, 1);
        assert_eq!(port.tx_burst(&mut pending), Ok(1));
        assert_eq!(TX_CALLS.get(), calls + 1);
        drop(peer_receive(&fixture, 16));
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

/// Every TX mbuf (the fixture pool holds 63), each with a live owner.
fn exhaust_tx_pool(port: &Port) -> Vec<Packet> {
    let held: Vec<Packet> = (0..63).map(|_| port.alloc_tx(4).unwrap()).collect();
    assert_eq!(port.tx.pool().in_use_count(), 63);
    held
}

/// With the TX pool exhausted, `alloc_tx` asks the PMD once to reclaim sent
/// mbufs; net_ring has no cleanup (-ENOTSUP), so the allocation fails.
#[zhida_test_support::pinned_test]
fn alloc_tx_on_exhausted_pool_tries_one_cleanup_then_fails_without_support() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let held = exhaust_tx_pool(&port);
        let calls = CLEANUP_CALLS.get();
        assert!(port.alloc_tx(4).is_none());
        assert_eq!(CLEANUP_CALLS.get(), calls + 1);
        assert_eq!(CLEANUP_RESULT.get(), -(ENOTSUP as i32));
        assert_eq!(port.tx.pool().in_use_count(), 63);
        drop(held);
        assert!(port.alloc_tx(4).is_some());
        assert_eq!(CLEANUP_CALLS.get(), calls + 1);
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

/// Sent mbufs the "NIC" (the fixture's TX ring) still holds exhaust the pool;
/// the cleanup releases them, as a NIC PMD reclaiming completed descriptors
/// does, and the one retry allocates.
#[zhida_test_support::pinned_test]
fn alloc_tx_retries_once_after_cleanup_reclaims_sent_mbufs() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let mut port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let mut pending: VecDeque<Packet> = exhaust_tx_pool(&port).into();
        // The eight-slot ring takes seven: 4 + 3.
        assert_eq!(port.tx_burst(&mut pending), Ok(4));
        assert_eq!(port.tx_burst(&mut pending), Ok(3));
        assert_eq!(pending.len(), 56);
        assert_eq!(port.tx.pool().in_use_count(), 63);
        let calls = CLEANUP_CALLS.get();
        let guard = FaultGuard::new(Faults {
            cleanup_reclaim_ring: NonNull::new(fixture.rings[1]),
            ..Faults::default()
        });
        let packet = port.alloc_tx(4).unwrap();
        drop(guard);
        assert_eq!(CLEANUP_CALLS.get(), calls + 1);
        assert_eq!(CLEANUP_RESULT.get(), 7);
        assert_eq!(port.tx.pool().in_use_count(), 57);
        drop((packet, pending));
        assert_eq!(port.tx.pool().in_use_count(), 0);
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

/// A length beyond the TX room is refused before the pool is touched, so it
/// never triggers a cleanup, even with the pool exhausted.
#[zhida_test_support::pinned_test]
fn alloc_tx_too_long_never_calls_cleanup() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let calls = CLEANUP_CALLS.get();
        // The fixture's TX room after headroom is 1514 bytes.
        assert_eq!(port.alloc_tx(1514).unwrap().data().len(), 1514);
        assert!(port.alloc_tx(1515).is_none());
        let held = exhaust_tx_pool(&port);
        assert!(port.alloc_tx(1515).is_none());
        assert_eq!(CLEANUP_CALLS.get(), calls);
        drop(held);
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

/// A cleanup error other than -ENOTSUP panics naming port, queue and code;
/// the Port and its packets stay intact.
#[zhida_test_support::pinned_test]
fn alloc_tx_panics_on_unexpected_cleanup_error() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let held = exhaust_tx_pool(&port);
        let guard = FaultGuard::new(Faults {
            cleanup_code: Some(-(EINVAL as i32)),
            ..Faults::default()
        });
        let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| port.alloc_tx(4)))
        else {
            panic!("alloc_tx returned after a failed cleanup");
        };
        drop(guard);
        let message = format!(
            "rte_eth_tx_done_cleanup(port {}, queue 0) failed: {}",
            fixture.port_id,
            -(EINVAL as i32)
        );
        assert_eq!(panic.downcast_ref::<String>(), Some(&message));
        assert_eq!(port.tx.pool().in_use_count(), 63);
        drop(held);
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

/// A Port that is not ready, retained after a failed open (TX queue 0 never
/// set up) or after a refused close, allocates from its pool but never calls
/// the cleanup on exhaustion: `None`, zero calls. The cleanup seam would
/// fail with -EINVAL, so a call would panic.
#[zhida_test_support::pinned_test]
fn alloc_tx_on_unready_port_never_calls_cleanup() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let guard = FaultGuard::new(Faults {
            tx_queue: 1,
            stop_before_call: true,
            ..Faults::default()
        });
        let failed_open = unsafe { Port::open(eal, fixture.config()) }
            .unwrap_err()
            .retained
            .unwrap();
        drop(guard);
        let calls = CLEANUP_CALLS.get();
        let guard = FaultGuard::new(Faults {
            cleanup_code: Some(-(EINVAL as i32)),
            ..Faults::default()
        });
        let held = exhaust_tx_pool(&failed_open);
        assert!(failed_open.alloc_tx(4).is_none());
        assert_eq!(CLEANUP_CALLS.get(), calls);
        drop(guard);
        drop(held);
        failed_open.try_close().unwrap();
        fixture.close().unwrap();

        let fixture = Fixture::new();
        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let guard = FaultGuard::new(Faults {
            stop_before_call: true,
            ..Faults::default()
        });
        let (refused_close, _) = port.try_close().unwrap_err();
        drop(guard);
        let guard = FaultGuard::new(Faults {
            cleanup_code: Some(-(EINVAL as i32)),
            ..Faults::default()
        });
        let held = exhaust_tx_pool(&refused_close);
        assert!(refused_close.alloc_tx(4).is_none());
        assert_eq!(CLEANUP_CALLS.get(), calls);
        drop(guard);
        drop(held);
        refused_close.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

/// Producer side of the port's RX ring: enqueue every packet.
pub(crate) fn produce(fixture: &Fixture, packets: &[*mut rte_mbuf]) {
    let raw: Vec<*mut c_void> = packets.iter().map(|&packet| packet.cast()).collect();
    let count = unsafe {
        dpdk_raw_ring_enqueue_burst(fixture.rings[0], raw.as_ptr(), raw.len() as u32, null_mut())
    };
    assert_eq!(count as usize, raw.len());
}

/// A supported frame from the port's own RX pool, as NIC RX provisioning supplies.
fn rx_frame(port: &Port, value: u8) -> *mut rte_mbuf {
    rx_frame_bytes(port, &[value, 0x55, 0xaa, value])
}

/// A supported frame holding exactly `bytes`, from the port's own RX pool.
pub(crate) fn rx_frame_bytes(port: &Port, bytes: &[u8]) -> *mut rte_mbuf {
    let mut packet = port.rx.pool().alloc_with_len(bytes.len() as u16).unwrap();
    packet.data_mut().copy_from_slice(bytes);
    packet.into_raw().as_ptr()
}

pub(crate) fn enable_rx_checksum(port: &mut Port) {
    port.rx_checksum = true;
}

pub(crate) fn enable_rx_timestamp(port: &mut Port) {
    port.rx_timestamp = Some(register_rx_timestamp().unwrap());
}

fn bad_checksum_dropped_and_counted(flags: u64) {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let mut port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        enable_rx_checksum(&mut port);
        let raw = rx_frame(&port, 7);
        // SAFETY: the producer exclusively owns this live RX-pool mbuf.
        unsafe { (*raw).ol_flags = flags };
        produce(&fixture, &[raw]);
        assert_eq!(in_use(&port), (1, 0));
        let mut staged = VecDeque::with_capacity(4);
        assert_eq!(
            port.rx_burst(&mut staged).unwrap(),
            RxBurst {
                accepted: 0,
                rejected: 0,
                rx_ipv4_checksum_bad: 1
            }
        );
        assert!(staged.is_empty());
        assert_eq!(in_use(&port), (0, 0));
        assert_eq!(port.rx_burst(&mut staged), rx(0, 0));
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn bad_and_unknown_l4_tcp_staged() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let mut port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        enable_rx_checksum(&mut port);
        let mut bytes = vec![0; 54];
        bytes[12..14].copy_from_slice(&[0x08, 0x00]);
        bytes[14] = 0x45;
        bytes[23] = 6;
        bytes[46] = 0x50;
        let mut staged = VecDeque::with_capacity(4);
        for flags in [RTE_MBUF_F_RX_L4_CKSUM_BAD, 0] {
            let raw = rx_frame_bytes(&port, &bytes);
            unsafe { (*raw).ol_flags = RTE_MBUF_F_RX_IP_CKSUM_GOOD | flags };
            produce(&fixture, &[raw]);
            assert_eq!(port.rx_burst(&mut staged), rx(1, 0));
            assert_eq!(staged.pop_front().unwrap().data(), bytes);
            assert_eq!(in_use(&port), (0, 0));
        }
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn bad_ipv4_dropped_and_counted() {
    bad_checksum_dropped_and_counted(RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_GOOD);
}

fn rx(accepted: usize, rejected: usize) -> Result<RxBurst, PortError> {
    Ok(RxBurst {
        accepted,
        rejected,
        rx_ipv4_checksum_bad: 0,
    })
}

#[zhida_test_support::pinned_test]
fn rx_into_buf_aliases_mbuf_and_frees_to_rx_pool() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let config = fixture.config();
        // SAFETY: the fixture owns the ring port and EAL pins this owner thread.
        let mut port = unsafe { Port::open(eal, config) }.unwrap();
        let bytes = b"owned receive frame";
        let raw = rx_frame_bytes(&port, bytes);
        // SAFETY: the producer owns this live RX-pool mbuf before enqueue.
        let data = unsafe { (*raw).data_ptr() };
        produce(&fixture, &[raw]);
        let mut staged = VecDeque::with_capacity(1);
        assert_eq!(port.rx_burst(&mut staged), rx(1, 0));
        let packet = staged.pop_front().unwrap();
        assert_eq!(packet.as_ptr(), raw);
        let frame = packet.into_rx_buf();
        assert_eq!(frame.as_slice().as_ptr(), data.cast_const());
        assert_eq!(frame.as_slice(), bytes);
        assert_eq!(in_use(&port), (1, 0));
        drop(frame);
        assert_eq!(in_use(&port), (0, 0));

        let all: Vec<Mbuf> = std::iter::from_fn(|| port.rx.pool().alloc()).collect();
        assert_eq!(all.len(), config.rx_pool.count as usize);
        assert_eq!(in_use(&port), (config.rx_pool.count, 0));
        let mut ids: Vec<_> = all.iter().map(Mbuf::as_ptr).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), all.len());
        drop(all);
        assert_eq!(in_use(&port), (0, 0));
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn rx_burst_imports_own_pool_packets_in_order_within_burst_and_spare_capacity() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let mut port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let mut staged = VecDeque::with_capacity(16);
        let capacity = staged.capacity();
        assert_eq!(port.rx_burst(&mut staged), rx(0, 0));

        let ids: Vec<_> = (10..16).map(|value| rx_frame(&port, value)).collect();
        produce(&fixture, &ids);
        assert_eq!(port.rx_burst(&mut staged), rx(4, 0));
        assert_eq!(pending_frames(&staged), expected(&ids[..4], 10));
        assert_eq!(port.rx_burst(&mut staged), rx(2, 0));
        assert_eq!(pending_frames(&staged), expected(&ids, 10));

        // One free slot: one import; the rest stay queued in the ring.
        while staged.len() < capacity - 1 {
            staged.push_back(unsafe { Packet::from_restricted(port.rx.pool().alloc().unwrap()) });
        }
        let ids: Vec<_> = (20..23).map(|value| rx_frame(&port, value)).collect();
        produce(&fixture, &ids);
        assert_eq!(port.rx_burst(&mut staged), rx(1, 0));
        let last = staged.back().unwrap();
        assert_eq!((last.0.as_ptr(), last.data()), (ids[0], &[20, 0x55, 0xaa, 20][..]));
        assert_eq!(port.rx_burst(&mut staged), rx(0, 0));
        assert_eq!(staged.capacity(), capacity);
        staged.clear();
        assert_eq!(port.rx.pool().in_use_count(), 2);
        assert_eq!(port.rx_burst(&mut staged), rx(2, 0));
        assert_eq!(pending_frames(&staged), expected(&ids[1..], 21));
        staged.clear();
        assert_eq!(port.rx.pool().in_use_count(), 0);
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn rx_burst_with_full_staging_never_calls_the_pmd() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let mut port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let mut staged = VecDeque::with_capacity(4);
        while staged.len() < staged.capacity() {
            staged.push_back(port.alloc_tx(4).unwrap());
        }
        let ids = [rx_frame(&port, 7)];
        produce(&fixture, &ids);
        let calls = RX_CALLS.get();
        assert_eq!(port.rx_burst(&mut staged), rx(0, 0));
        assert_eq!(RX_CALLS.get(), calls);
        assert_eq!(port.rx.pool().in_use_count(), 1);

        // One free slot: one PMD call imports the waiting frame.
        staged.pop_front();
        assert_eq!(port.rx_burst(&mut staged), rx(1, 0));
        assert_eq!(RX_CALLS.get(), calls + 1);
        assert_eq!(staged.back().unwrap().0.as_ptr(), ids[0]);
        drop(staged);
        assert_eq!(in_use(&port), (0, 0));
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

thread_local! {
    static EXT_FREES: Cell<u32> = const { Cell::new(0) };
}

unsafe extern "C" fn count_ext_free(_buf: *mut c_void, _opaque: *mut c_void) {
    EXT_FREES.set(EXT_FREES.get() + 1);
}

#[zhida_test_support::pinned_test]
fn rx_burst_frees_valid_unsupported_packets_once_with_standard_free() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let mut config = fixture.config();
        config.rx_burst = 8;
        let mut port = unsafe { Port::open(eal, config) }.unwrap();
        let rx_pool = port.rx.pool().pool();
        let foreign = unsafe {
            rte_pktmbuf_pool_create(
                c"port_foreign".as_ptr(),
                15,
                0,
                0,
                RTE_PKTMBUF_HEADROOM as u16 + 64,
                -1,
            )
        };
        assert!(!foreign.is_null());
        let peer = unsafe {
            PoolManager::new_production(PoolConfig {
                name: c"port_peer_tx",
                count: 15,
                cache_size: 4,
                data_room_size: RTE_PKTMBUF_HEADROOM as u16 + 1514,
                socket_id: -1,
            })
        }
        .unwrap();
        let mut staged = VecDeque::with_capacity(16);

        // Standard pool without the private cache slot.
        let foreign_packet = unsafe { dpdk_raw_pktmbuf_alloc(foreign) };
        assert!(!foreign_packet.is_null());
        let chained = rx_frame(&port, 0);
        assert_eq!(
            unsafe { dpdk_raw_pktmbuf_chain(chained, rx_frame(&port, 1)) },
            0
        );
        let shared = rx_frame(&port, 2);
        assert_eq!(unsafe { dpdk_raw_mbuf_refcnt_update(shared, 1) }, 2);
        let shared_held = unsafe { Mbuf::from_raw(NonNull::new_unchecked(shared)) };
        let direct = rx_frame(&port, 3);
        let direct_held = unsafe { Mbuf::from_raw(NonNull::new_unchecked(direct)) };
        let indirect = unsafe { dpdk_raw_pktmbuf_clone(direct, rx_pool) };
        assert!(!indirect.is_null());
        assert_eq!(direct_held.refcount(), 2);
        let ids = [rx_frame(&port, 10), rx_frame(&port, 11), rx_frame(&port, 12)];
        produce(
            &fixture,
            &[
                ids[0],
                foreign_packet,
                ids[1],
                chained,
                shared,
                indirect,
                ids[2],
            ],
        );
        assert_eq!(port.rx_burst(&mut staged), rx(3, 4));
        assert_eq!(pending_frames(&staged), expected(&ids, 10));
        assert_eq!(unsafe { rte_mempool_in_use_count(foreign) }, 0);
        assert_eq!(shared_held.refcount(), 1);
        assert_eq!(direct_held.refcount(), 1);
        // Staged three plus the two test-held references; chain and clone returned.
        assert_eq!(port.rx.pool().in_use_count(), 5);
        drop((shared_held, direct_held));
        staged.clear();
        assert_eq!(port.rx.pool().in_use_count(), 0);

        // A real chain whose packet length equals its head's data length: only
        // the segment count and link reject it.
        let chained = rx_frame(&port, 4);
        let tail = port.rx.pool().alloc_with_len(0).unwrap().into_raw().as_ptr();
        assert_eq!(unsafe { dpdk_raw_pktmbuf_chain(chained, tail) }, 0);
        let head = unsafe { &*chained };
        assert_eq!((head.nb_segs(), head.next()), (2, tail));
        assert_eq!(head.pkt_len(), u32::from(head.data_len()));
        assert_eq!(port.rx.pool().in_use_count(), 2);
        let ids = [rx_frame(&port, 30), rx_frame(&port, 31)];
        produce(&fixture, &[ids[0], chained, ids[1]]);
        assert_eq!(port.rx_burst(&mut staged), rx(2, 1));
        assert_eq!(pending_frames(&staged), expected(&ids, 30));
        assert_eq!(port.rx.pool().in_use_count(), 2);
        staged.clear();
        assert_eq!(port.rx.pool().in_use_count(), 0);

        let mut storage = [0u64; 64];
        let external = port.rx.pool().alloc().unwrap().into_raw().as_ptr();
        assert_eq!(
            unsafe {
                dpdk_raw_pktmbuf_attach_extbuf(
                    external,
                    storage.as_mut_ptr().cast(),
                    512,
                    Some(count_ext_free),
                    null_mut(),
                )
            },
            0
        );
        unsafe {
            (*external).set_data_len(4);
            (*external).set_pkt_len(4);
        }
        let too_long = rx_frame(&port, 4);
        unsafe {
            let length = (*too_long).buf_len() - (*too_long).data_off() + 1;
            (*too_long).set_data_len(length);
            (*too_long).set_pkt_len(u32::from(length));
        }
        let mismatched = rx_frame(&port, 5);
        unsafe { (*mismatched).set_pkt_len(5) };
        // Compatible production pool, but not this port's RX pool.
        let peer_packet = peer.alloc_with_len(4).unwrap().into_raw().as_ptr();
        let id = rx_frame(&port, 13);
        let ext_frees = EXT_FREES.get();
        produce(
            &fixture,
            &[external, too_long, mismatched, peer_packet, id],
        );
        assert_eq!(port.rx_burst(&mut staged), rx(1, 4));
        assert_eq!(pending_frames(&staged), expected(&[id], 13));
        assert_eq!(EXT_FREES.get(), ext_frees + 1);
        assert_eq!(peer.in_use_count(), 0);
        assert_eq!(port.rx.pool().in_use_count(), 1);
        staged.clear();
        assert_eq!(port.rx.pool().in_use_count(), 0);

        drop(peer);
        unsafe { rte_mempool_free(foreign) };
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn rx_burst_refuses_unready_ports_and_leaves_packets_queued() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let guard = FaultGuard::new(Faults {
            tx_queue: 1,
            stop_before_call: true,
            ..Faults::default()
        });
        let mut port = unsafe { Port::open(eal, fixture.config()) }
            .unwrap_err()
            .retained
            .unwrap();
        drop(guard);
        let ids = [rx_frame(&port, 30), rx_frame(&port, 31)];
        produce(&fixture, &ids);
        let mut staged = VecDeque::with_capacity(4);
        assert_eq!(port.rx_burst(&mut staged), Err(PortError::NotReady));
        assert!(staged.is_empty());
        assert_eq!(mbuf_frames(&ring_take(fixture.rings[0], 16)), expected(&ids, 30));
        port.try_close().unwrap();
        fixture.close().unwrap();

        let fixture = Fixture::new();
        let port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let ids = [rx_frame(&port, 40), rx_frame(&port, 41)];
        produce(&fixture, &ids);
        let guard = FaultGuard::new(Faults {
            stop_before_call: true,
            ..Faults::default()
        });
        let (mut port, _) = port.try_close().unwrap_err();
        drop(guard);
        assert_eq!(port.rx_burst(&mut staged), Err(PortError::NotReady));
        assert!(staged.is_empty());
        assert_eq!(mbuf_frames(&ring_take(fixture.rings[0], 16)), expected(&ids, 40));
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

pub(crate) fn in_use(port: &Port) -> (u32, u32) {
    (port.rx.pool().in_use_count(), port.tx.pool().in_use_count())
}

fn sorted(mut ids: Vec<*mut rte_mbuf>) -> Vec<*mut rte_mbuf> {
    ids.sort();
    ids
}

/// The 63 freed mbufs `ids` are back in their own pool: reallocating the whole
/// pool yields exactly these mbufs, each with refcnt 1 and no external buffer
/// (allocation resets every other header field, so only these two say
/// anything about the free).
fn assert_pool_defaults(pool: &PoolManager, ids: &[*mut rte_mbuf]) {
    let all: Vec<Mbuf> = std::iter::from_fn(|| pool.alloc()).collect();
    for mbuf in &all {
        let m = unsafe { &*mbuf.as_ptr() };
        assert_eq!(m.refcnt(), 1);
        assert_eq!(m.ol_flags & RTE_MBUF_F_EXTERNAL, 0);
    }
    assert_eq!(sorted(all.iter().map(Mbuf::as_ptr).collect()), sorted(ids.to_vec()));
    drop(all);
    assert_eq!(pool.in_use_count(), 0);
}

/// Ownership and accounting regression guard for Packet's drop: 63 packets
/// per pool far exceed the 8-entry mempool cache, so dropping them together
/// runs the cache-flush path as well as the cached put. The single-segment
/// free is meant to behave exactly like the general free here, which would
/// pass this test too; a double or missing free would not.
#[zhida_test_support::pinned_test]
fn dropped_packets_return_to_their_own_pools_beyond_the_cache() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let mut config = fixture.config();
        config.rx_burst = 7;
        let mut port = unsafe { Port::open(eal, config) }.unwrap();

        let tx: Vec<Packet> = std::iter::from_fn(|| port.alloc_tx(1514)).collect();
        assert_eq!(tx.len(), 63);
        let tx_ids: Vec<_> = tx.iter().map(|packet| packet.0.as_ptr()).collect();
        assert_eq!(in_use(&port), (0, 63));
        drop(tx);
        assert_eq!(in_use(&port), (0, 0));

        // RX packets through rx_burst, seven per ring fill.
        let mut staged = VecDeque::with_capacity(63);
        while staged.len() < 63 {
            let fill = (63 - staged.len()).min(7) as u8;
            let ids: Vec<_> = (0..fill).map(|value| rx_frame(&port, value)).collect();
            produce(&fixture, &ids);
            assert_eq!(port.rx_burst(&mut staged), rx(usize::from(fill), 0));
        }
        let rx_ids: Vec<_> = staged.iter().map(|packet| packet.0.as_ptr()).collect();
        assert_eq!(in_use(&port), (63, 0));
        drop(staged);
        assert_eq!(in_use(&port), (0, 0));

        assert_pool_defaults(port.tx.pool(), &tx_ids);
        assert_pool_defaults(port.rx.pool(), &rx_ids);
        port.try_close().unwrap();
        fixture.close().unwrap();
        assert_no_pools();
    });
}

#[zhida_test_support::pinned_test]
fn shutdown_refuses_until_staged_queued_and_ring_held_packets_each_return_once() {
    with_test_eal(|eal| {
        let fixture = Fixture::new();
        let mut port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
        let mut staged = VecDeque::with_capacity(16);
        let mut pending = VecDeque::with_capacity(16);
        let rx_ids: Vec<_> = (10..15).map(|value| rx_frame(&port, value)).collect();
        produce(&fixture, &rx_ids);
        assert_eq!(port.rx_burst(&mut staged), rx(4, 0));
        let tx_ids = stage(&port, &mut pending, 50, 9);
        assert_eq!(port.tx_burst(&mut pending), Ok(4));
        assert_eq!(port.tx_burst(&mut pending), Ok(3));
        // RX: four staged, one unreceived in the ring. TX: two queued, seven in the ring.
        assert_eq!(in_use(&port), (5, 9));

        // A refused stop leaves the device started but ends packet transfers.
        let guard = FaultGuard::new(Faults {
            stop_before_call: true,
            ..Faults::default()
        });
        let (mut port, error) = port.try_close().unwrap_err();
        drop(guard);
        assert_eq!(
            error,
            PortError::Dpdk {
                operation: "rte_eth_dev_stop",
                code: -5
            }
        );
        assert_eq!(port.tx_burst(&mut pending), Err(PortError::NotReady));
        assert_eq!(port.rx_burst(&mut staged), Err(PortError::NotReady));
        assert_eq!(pending_frames(&pending), expected(&tx_ids[7..], 57));
        assert_eq!(pending_frames(&staged), expected(&rx_ids[..4], 10));

        // Stopped and closed; every packet is still owned somewhere.
        let (port, error) = port.try_close().unwrap_err();
        assert_eq!(error, PortError::OutstandingBuffers { rx: 5, tx: 9 });
        assert_eq!(unsafe { rte_eth_dev_is_valid_port(fixture.port_id) }, 0);

        // Adapter-owned packets return first; the queued TX suffix is never sent.
        drop((staged, pending));
        let (port, error) = port.try_close().unwrap_err();
        assert_eq!(error, PortError::OutstandingBuffers { rx: 1, tx: 7 });

        // The ring owner drains transport-held packets.
        assert_eq!(
            mbuf_frames(&ring_take(fixture.rings[1], 16)),
            expected(&tx_ids[..7], 50)
        );
        assert_eq!(
            mbuf_frames(&ring_take(fixture.rings[0], 16)),
            expected(&rx_ids[4..], 14)
        );
        port.try_close().unwrap();
        assert_no_pools();
        fixture.close().unwrap();
    });
}

#[zhida_test_support::pinned_test]
fn caller_unwind_returns_adapter_packets_and_never_frees_ring_held_ones() {
    with_test_eal(|eal| {
        // Port declared before its queues: the queues drop first, then the
        // Port's Drop cleanup finds every packet returned and releases all.
        let fixture = Fixture::new();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
            let mut staged = VecDeque::with_capacity(16);
            let mut pending = VecDeque::with_capacity(16);
            produce(&fixture, &[rx_frame(&port, 1), rx_frame(&port, 2)]);
            assert_eq!(port.rx_burst(&mut staged), rx(2, 0));
            stage(&port, &mut pending, 3, 3);
            panic!("caller panic with adapter packets");
        }))
        .unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"caller panic with adapter packets")
        );
        assert_eq!(unsafe { rte_eth_dev_is_valid_port(fixture.port_id) }, 0);
        assert_no_pools();
        fixture.close().unwrap();

        // Queues declared before the Port, with accepted packets in the ring:
        // Drop cleanup refuses and retains the pools; packets returned later
        // land in still-valid pools.
        let fixture = Fixture::new();
        let mut tx_ids = Vec::new();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut staged = VecDeque::with_capacity(16);
            let mut pending = VecDeque::with_capacity(16);
            let mut port = unsafe { Port::open(eal, fixture.config()) }.unwrap();
            produce(&fixture, &[rx_frame(&port, 1), rx_frame(&port, 2)]);
            assert_eq!(port.rx_burst(&mut staged), rx(2, 0));
            tx_ids = stage(&port, &mut pending, 20, 5);
            assert_eq!(port.tx_burst(&mut pending), Ok(4));
            panic!("caller panic before queues drop");
        }))
        .unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"caller panic before queues drop")
        );
        assert_eq!(unsafe { rte_eth_dev_is_valid_port(fixture.port_id) }, 0);
        let pools = [c"port_pool_rx", c"port_pool_tx"]
            .map(|name| unsafe { rte_mempool_lookup(name.as_ptr()) });
        assert!(pools.iter().all(|pool| !pool.is_null()));
        let counts = pools.map(|pool| unsafe { rte_mempool_in_use_count(pool) });
        assert_eq!(counts, [0, 4]);
        assert_eq!(
            mbuf_frames(&ring_take(fixture.rings[1], 16)),
            expected(&tx_ids[..4], 20)
        );
        assert_eq!(unsafe { rte_mempool_in_use_count(pools[1]) }, 0);
        // The dropped Port retained this backing; reclaim the empty pools here only.
        for pool in pools {
            unsafe { rte_mempool_free(pool) };
        }
        fixture.close().unwrap();
        assert_no_pools();
    });
}
