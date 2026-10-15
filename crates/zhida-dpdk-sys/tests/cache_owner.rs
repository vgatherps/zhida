use zhida_test_support::pinned_test;
use std::cell::OnceCell;
use std::ffi::CString;
use std::sync::OnceLock;
use std::thread::{self, ThreadId};
use zhida_dpdk_sys::*;

struct OwnerPools {
    pools: [(*mut rte_mempool, *mut rte_mempool_cache); 2],
    lcore: u32,
}

thread_local! {
    // The worker and its EAL/pools stay alive until process exit.
    static POOLS: OnceCell<OwnerPools> = const { OnceCell::new() };
}

fn with_owner_pools(f: impl FnOnce(&OwnerPools)) {
    static OWNER: OnceLock<(ThreadId, u32)> = OnceLock::new();
    POOLS.with(|cell| {
        let owner = cell.get_or_init(|| {
            let cpu = zhida_dpdk_sys::only_allowed_cpu().unwrap_or_else(|error| panic!("{error}"));
            let lcores = format!("--lcores=0@{cpu}");
            let storage = ["cache_owner", "--no-pci", "--no-huge", lcores.as_str()]
                .into_iter()
                .map(|arg| CString::new(arg).unwrap().into_bytes_with_nul())
                .collect::<Vec<_>>();
            let storage = Box::leak(storage.into_boxed_slice());
            let mut argv = storage
                .iter_mut()
                .map(|arg| arg.as_mut_ptr().cast())
                .collect::<Vec<*mut std::ffi::c_char>>();
            assert!(unsafe { rte_eal_init(argv.len() as i32, argv.as_mut_ptr()) } >= 0);
            let lcore = unsafe { zhida_lcore_id() };
            assert!(lcore < RTE_MAX_LCORE);
            let pools = std::array::from_fn(|index| {
                let name = CString::new(format!("owner_pool_{index}")).unwrap();
                let pool = unsafe {
                    rte_pktmbuf_pool_create(
                        name.as_ptr(),
                        128,
                        32,
                        8,
                        RTE_MBUF_DEFAULT_BUF_SIZE as u16,
                        rte_socket_id() as i32,
                    )
                };
                assert!(!pool.is_null(), "pool creation failed: {}", unsafe {
                    zhida_errno()
                });
                let cache = unsafe { zhida_get_pool_cache(pool) };
                assert!(!cache.is_null());
                unsafe { zhida_pool_init_cache_ptrs(pool, cache) };
                (pool, cache)
            });
            OwnerPools { pools, lcore }
        });
        let identity = (thread::current().id(), unsafe { zhida_lcore_id() });
        assert_eq!(*OWNER.get_or_init(|| identity), identity);
        assert_eq!(identity.1, owner.lcore);
        f(owner);
        assert_eq!(unsafe { zhida_lcore_id() }, owner.lcore);
    });
}

fn exercise_owner_pools() {
    with_owner_pools(|owner| {
        for &(pool, cache) in &owner.pools {
            for _ in 0..8 {
                assert_eq!(unsafe { zhida_get_pool_cache(pool) }, cache);
                assert_eq!(unsafe { zhida_lcore_id() }, owner.lcore);
                let standard = unsafe { dpdk_raw_pktmbuf_alloc(pool) };
                assert!(!standard.is_null());
                assert_eq!(unsafe { (*standard).pool }, pool);
                unsafe { zhida_pktmbuf_free(standard) };
                let custom = unsafe { zhida_pktmbuf_alloc_fast(pool, cache) };
                assert!(!custom.is_null());
                assert_eq!(unsafe { (*custom).pool }, pool);
                unsafe { dpdk_raw_pktmbuf_free(custom) };
            }
            unsafe { zhida_mempool_cache_flush(cache, pool) };
            assert_eq!(unsafe { rte_mempool_in_use_count(pool) }, 0);
        }
    });
}

#[pinned_test]
fn first_test_allocates_and_frees_on_owner() {
    exercise_owner_pools();
}

#[pinned_test]
fn second_test_reuses_owner_lcore_and_caches() {
    exercise_owner_pools();
}

#[pinned_test]
fn unregistered_lookup_returns_null_and_preserves_identity() {
    with_owner_pools(|owner| {
        let address = owner.pools[0].0 as usize;
        thread::spawn(move || {
            assert_eq!(unsafe { zhida_lcore_id() }, u32::MAX);
            assert!(unsafe { zhida_get_pool_cache(address as *mut rte_mempool) }.is_null());
            assert_eq!(unsafe { zhida_lcore_id() }, u32::MAX);
        })
        .join()
        .unwrap();
    });
}
