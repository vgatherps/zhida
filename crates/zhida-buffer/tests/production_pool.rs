use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::ptr::NonNull;

use zhida_buffer::{Mbuf, PoolConfig, PoolCreateError, PoolManager};
use zhida_dpdk_sys::{
    dpdk_raw_pktmbuf_alloc, dpdk_raw_pktmbuf_free, rte_eal_init, rte_mbuf, zhida_errno,
    zhida_get_pool_cache, zhida_lcore_id, zhida_mempool_ops_name, EINVAL, RTE_PKTMBUF_HEADROOM,
};

/// EAL with main lcore 7 on this thread. A nonzero owner lcore is the property:
/// on lcore 0 a pool cache wrongly taken from slot 0 would pass.
fn init_eal_on_lcore_7() {
    let cpu = zhida_dpdk_sys::only_allowed_cpu().unwrap_or_else(|error| panic!("{error}"));
    let lcores = format!("--lcores=7@{cpu}");
    let storage = [
        "production-pool",
        "--no-pci",
        "--no-huge",
        "--no-shconf",
        "--no-telemetry",
        lcores.as_str(),
        "--main-lcore=7",
    ]
    .map(|arg| CString::new(arg).unwrap().into_bytes_with_nul());
    let storage = Box::leak(Box::new(storage));
    let mut argv = storage.each_mut().map(|arg| arg.as_mut_ptr().cast::<std::ffi::c_char>());
    assert!(unsafe { rte_eal_init(argv.len() as i32, argv.as_mut_ptr()) } >= 0);
    assert_eq!(unsafe { zhida_lcore_id() }, 7);
}

fn config(name: &CStr) -> PoolConfig<'_> {
    PoolConfig {
        name,
        count: 63,
        cache_size: 8,
        data_room_size: RTE_PKTMBUF_HEADROOM as u16 + 512,
        socket_id: -1,
    }
}

fn assert_object(pool: &PoolManager, m: *mut rte_mbuf, room: u16) {
    unsafe {
        assert_eq!((*m).pool, pool.pool());
        assert_eq!((*m).priv_size, 8);
        assert_eq!((*m).buf_len(), room);
        assert_eq!((*m).data_off(), RTE_PKTMBUF_HEADROOM as u16);
        assert_eq!((*m).refcnt(), 1);
        assert_eq!((*m).nb_segs(), 1);
        assert!((*m).next.is_null());
        let slot = m
            .cast::<u8>()
            .add(std::mem::size_of::<rte_mbuf>())
            .cast::<*mut zhida_dpdk_sys::rte_mempool_cache>();
        assert_eq!(*slot, pool.cache());
    }
}

fn assert_distinct(objects: impl Iterator<Item = *mut rte_mbuf>) {
    let mut seen = HashSet::new();
    for object in objects {
        assert!(seen.insert(object), "pool returned an already held object");
    }
}

fn exhaustion_and_circulation(pool: &PoolManager, cfg: PoolConfig<'_>) {
    let mut all = Vec::new();
    while let Some(m) = pool.alloc() {
        assert_object(pool, m.as_ptr(), cfg.data_room_size);
        all.push(m);
    }
    assert_eq!(all.len(), cfg.count as usize);
    assert_distinct(all.iter().map(Mbuf::as_ptr));
    assert_eq!(pool.in_use_count(), cfg.count);
    assert!(pool.alloc().is_none());
    assert!(pool.alloc_with_len(0).is_none());
    drop(all);
    assert_eq!(pool.in_use_count(), 0);

    // Hold every standard allocation, then alternate standard and custom frees.
    let mut raw = Vec::new();
    loop {
        let m = unsafe { dpdk_raw_pktmbuf_alloc(pool.pool()) };
        if m.is_null() {
            break;
        }
        assert_object(pool, m, cfg.data_room_size);
        raw.push(m);
    }
    assert_eq!(raw.len(), cfg.count as usize);
    assert_distinct(raw.iter().copied());
    for (i, m) in raw.into_iter().enumerate() {
        if i % 2 == 0 {
            unsafe { dpdk_raw_pktmbuf_free(m) };
        } else {
            drop(unsafe { Mbuf::from_raw(NonNull::new(m).unwrap()) });
        }
    }
    assert_eq!(pool.in_use_count(), 0);

    // Exhaust the custom path again and return every object through standard free.
    let mut all = Vec::new();
    while let Some(m) = pool.alloc() {
        assert_object(pool, m.as_ptr(), cfg.data_room_size);
        all.push(m);
    }
    assert_eq!(all.len(), cfg.count as usize);
    assert_distinct(all.iter().map(Mbuf::as_ptr));
    for m in all {
        unsafe { dpdk_raw_pktmbuf_free(m.into_raw().as_ptr()) };
    }
    assert_eq!(pool.in_use_count(), 0);
    drop(pool.alloc().expect("returned objects must be reusable"));
}

fn rejected_config(cfg: PoolConfig<'_>) -> PoolCreateError {
    match unsafe { PoolManager::new_production(cfg) } {
        Err(err) => err,
        Ok(_) => panic!("invalid production pool config was accepted"),
    }
}

fn invalid_configs(cfg: PoolConfig<'_>) {
    assert_eq!(
        rejected_config(PoolConfig {
            cache_size: 0,
            ..cfg
        }),
        PoolCreateError::CacheDisabled
    );
    assert_eq!(
        rejected_config(PoolConfig {
            data_room_size: RTE_PKTMBUF_HEADROOM as u16 - 1,
            ..cfg
        }),
        PoolCreateError::DataRoomTooSmall {
            provided: RTE_PKTMBUF_HEADROOM as u16 - 1,
            minimum: RTE_PKTMBUF_HEADROOM as u16,
        }
    );
    for invalid in [
        PoolConfig { count: 0, ..cfg },
        PoolConfig {
            count: 8,
            cache_size: 8,
            ..cfg
        },
        PoolConfig {
            cache_size: u32::MAX,
            ..cfg
        },
        PoolConfig {
            count: u32::MAX,
            ..cfg
        },
    ] {
        let PoolCreateError::Dpdk { errno } = rejected_config(invalid) else {
            panic!("DPDK must report its actual configuration rejection");
        };
        assert_eq!(errno, EINVAL as i32);
        assert_eq!(errno, unsafe { zhida_errno() });
    }
}

#[zhida_test_support::pinned_test]
fn production_pool_preserves_owner_cache_and_initializes_all_objects() {
    init_eal_on_lcore_7();
    let name = CString::new("production_pool").unwrap();
    let cfg = config(&name);
    invalid_configs(cfg);
    let pool = unsafe { PoolManager::new_production(cfg) }.unwrap();
    unsafe {
        assert_eq!(CStr::from_ptr((*pool.pool()).name.as_ptr()), cfg.name);
        assert_eq!((*pool.pool()).size, cfg.count);
        assert_eq!((*pool.pool()).cache_size, cfg.cache_size);
        assert_eq!((*pool.pool()).socket_id, cfg.socket_id);
        assert_eq!(CStr::from_ptr(zhida_mempool_ops_name(pool.pool())), c"ring_sp_sc");
        assert_eq!(pool.cache(), (*pool.pool()).local_cache.add(7));
    }
    assert!(matches!(rejected_config(cfg), PoolCreateError::Dpdk { errno } if errno > 0));
    let empty = pool.alloc_with_len(0).unwrap();
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.headroom(), RTE_PKTMBUF_HEADROOM as u16);
    assert_eq!(empty.tailroom(), 512);
    drop(empty);
    let full = pool.alloc_with_len(512).unwrap();
    assert_eq!(full.len(), 512);
    assert_eq!(full.tailroom(), 0);
    drop(full);
    assert!(pool.alloc_with_len(513).is_none());
    assert_eq!(pool.in_use_count(), 0);
    exhaustion_and_circulation(&pool, cfg);

    for i in 0..16 {
        let name = CString::new(format!("production_other_{i}")).unwrap();
        let other = unsafe { PoolManager::new_production(config(&name)) }.unwrap();
        assert_eq!(unsafe { zhida_lcore_id() }, 7);
        assert_eq!(unsafe { zhida_get_pool_cache(pool.pool()) }, pool.cache());
        assert_eq!(unsafe { zhida_get_pool_cache(other.pool()) }, other.cache());
        drop(other.alloc().unwrap());
    }
    drop(pool);
    // A clean close releases the name and allows fresh construction.
    drop(unsafe { PoolManager::new_production(cfg) }.unwrap());

    let cfg = PoolConfig {
        data_room_size: RTE_PKTMBUF_HEADROOM as u16,
        ..cfg
    };
    let pool = unsafe { PoolManager::new_production(cfg) }.unwrap();
    let empty = pool.alloc_with_len(0).unwrap();
    assert_eq!(empty.headroom(), RTE_PKTMBUF_HEADROOM as u16);
    assert_eq!(empty.tailroom(), 0);
    drop(empty);
    assert!(pool.alloc_with_len(1).is_none());
    assert_eq!(pool.in_use_count(), 0);
    drop(pool);

    let name = CString::new("production_minimal").unwrap();
    let cfg = PoolConfig {
        count: 1,
        cache_size: 1,
        ..config(&name)
    };
    let pool = unsafe { PoolManager::new_production(cfg) }.unwrap();
    exhaustion_and_circulation(&pool, cfg);
    let raw = unsafe { dpdk_raw_pktmbuf_alloc(pool.pool()) };
    let m = unsafe { Mbuf::from_raw(NonNull::new(raw).expect("minimal pool must recover")) };
    assert_object(&pool, m.as_ptr(), cfg.data_room_size);
    drop(m);
    assert_eq!(pool.in_use_count(), 0);
    assert_eq!(unsafe { zhida_lcore_id() }, 7);
}
