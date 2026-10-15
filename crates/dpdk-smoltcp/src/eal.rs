use std::ffi::{c_char, c_int, CString};
use std::fmt;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::rc::Rc;

use zhida_buffer::{PoolConfig, PoolCreateError, PoolManager};
use zhida_dpdk_sys::{rte_eal_init, zhida_errno, zhida_lcore_id};

/// The calling thread's process-lifetime EAL setup.
///
/// Dropping this owner does not clean up EAL or unregister its main lcore.
/// EAL cannot be initialized a second time after successful initialization.
///
/// ```compile_fail
/// use dpdk_smoltcp::Eal;
/// fn requires_send<T: Send>() {}
/// requires_send::<Eal>();
/// ```
///
/// ```compile_fail
/// use dpdk_smoltcp::Eal;
/// fn requires_sync<T: Sync>() {}
/// requires_sync::<Eal>();
/// ```
#[derive(Debug)]
pub struct Eal {
    owner_lcore_id: u32,
    consumed_args: usize,
    _thread_local: PhantomData<Rc<()>>,
}

impl Eal {
    /// Initialize DPDK with caller-supplied argv, including the program name.
    ///
    /// Strings and the pointer array are copied into writable C storage. Argument
    /// strings passed to DPDK remain allocated until process exit because DPDK
    /// retains pointers to parsed string options, even after a returned failure.
    /// No options are added, and the calling thread becomes EAL's main lcore.
    ///
    /// Empty argv, an unrepresentable count and interior NUL bytes are rejected
    /// before calling DPDK. Returned DPDK failures preserve its return code and
    /// `rte_errno`. DPDK's help and some argument-parser errors exit the process;
    /// this method preserves those startup semantics. Failure does not promise
    /// that initialization can be retried.
    pub fn init(args: &[&str]) -> Result<Self, EalError> {
        let argc = argc_for_count(args.len())?;
        let mut storage = args
            .iter()
            .enumerate()
            .map(|(argument, arg)| {
                CString::new(*arg)
                    .map(CString::into_bytes_with_nul)
                    .map_err(|err| EalError::InteriorNul {
                        argument,
                        position: err.nul_position(),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut argv: Vec<*mut c_char> = storage
            .iter_mut()
            .map(|arg| arg.as_mut_ptr().cast())
            .collect();
        argv.push(std::ptr::null_mut());

        // Each pointer refers to writable, NUL-terminated storage for this call.
        let return_code = unsafe { rte_eal_init(argc, argv.as_mut_ptr()) };
        let errno = if return_code < 0 {
            unsafe { zhida_errno() }
        } else {
            0
        };
        // EAL's global parsed options can retain pointers into these strings.
        std::mem::forget(storage);
        if return_code < 0 {
            return Err(EalError::Initialization { return_code, errno });
        }

        Ok(Self {
            owner_lcore_id: unsafe { zhida_lcore_id() },
            consumed_args: return_code as usize,
            _thread_local: PhantomData,
        })
    }

    pub fn owner_lcore_id(&self) -> u32 {
        self.owner_lcore_id
    }

    /// Number of arguments consumed, as returned by `rte_eal_init`.
    pub fn consumed_args(&self) -> usize {
        self.consumed_args
    }
}

/// Local pool backing; a live-buffer drop retains both the pool and its cache.
pub(crate) struct PoolResources {
    pool: ManuallyDrop<PoolManager>,
}

impl PoolResources {
    /// # Safety
    /// EAL must already be initialized on the stable owner lcore. Keep EAL and
    /// that identity alive until every allocated mbuf has returned, including
    /// after a live-buffer drop retains the backing. All pool/cache operations
    /// and mbuf frees must stay on that thread. Preserve `new_production`'s
    /// direct, unique, single-segment, no-external-backing contract through Rust
    /// and DPDK; no clones, sharing, indirect attachments or chains.
    pub(crate) unsafe fn new(config: PoolConfig<'_>) -> Result<Self, PoolCreateError> {
        PoolManager::new_production(config).map(|pool| Self {
            pool: ManuallyDrop::new(pool),
        })
    }

    pub(crate) fn pool(&self) -> &PoolManager {
        &self.pool
    }
}

impl Drop for PoolResources {
    fn drop(&mut self) {
        let in_use = self.pool.in_use_count();
        if in_use == 0 {
            // The single owner cannot allocate between this check and Drop.
            unsafe { ManuallyDrop::drop(&mut self.pool) };
        } else {
            use std::io::Write;
            let _ = writeln!(
                std::io::stderr(),
                "Zhida retained pool backing with {in_use} buffers still in use"
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EalError {
    EmptyArguments,
    ArgumentCountTooLarge { count: usize },
    InteriorNul { argument: usize, position: usize },
    Initialization { return_code: c_int, errno: c_int },
}

impl fmt::Display for EalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyArguments => f.write_str("EAL argv requires a program name"),
            Self::ArgumentCountTooLarge { count } => {
                write!(f, "EAL argument count {count} exceeds DPDK's C count limit")
            }
            Self::InteriorNul { argument, position } => {
                write!(
                    f,
                    "EAL argument {argument} contains a NUL at byte {position}"
                )
            }
            Self::Initialization { return_code, errno } => {
                write!(
                    f,
                    "rte_eal_init returned {return_code} with rte_errno {errno}"
                )
            }
        }
    }
}

impl std::error::Error for EalError {}

fn argc_for_count(count: usize) -> Result<c_int, EalError> {
    if count == 0 {
        return Err(EalError::EmptyArguments);
    }
    // DPDK's eal_save_args computes argc + 1 in signed C arithmetic.
    c_int::try_from(count)
        .ok()
        .filter(|&argc| argc < c_int::MAX)
        .ok_or(EalError::ArgumentCountTooLarge { count })
}

#[cfg(test)]
pub(crate) fn with_test_eal<R>(body: impl FnOnce(&Eal) -> R) -> R {
    thread_local! {
        static EAL: std::cell::OnceCell<Eal> = const { std::cell::OnceCell::new() };
    }
    EAL.with(|owner| {
        let eal = owner.get_or_init(|| {
            let args = zhida_test_kit::eal_args();
            Eal::init(&args.iter().map(String::as_str).collect::<Vec<_>>())
                .expect("resource test EAL initialization")
        });
        assert_eq!(eal.owner_lcore_id(), 7);
        assert_eq!(unsafe { zhida_lcore_id() }, 7);
        body(eal)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_count_rejects_empty_and_c_overflow() {
        assert_eq!(argc_for_count(0), Err(EalError::EmptyArguments));
        assert_eq!(argc_for_count(1), Ok(1));
        assert_eq!(argc_for_count(c_int::MAX as usize - 1), Ok(c_int::MAX - 1));
        for count in [c_int::MAX as usize, c_int::MAX as usize + 1] {
            assert_eq!(
                argc_for_count(count),
                Err(EalError::ArgumentCountTooLarge { count })
            );
        }
    }

    fn resource_config(name: &std::ffi::CStr) -> PoolConfig<'_> {
        with_test_eal(|_| {});
        PoolConfig {
            name,
            count: 63,
            cache_size: 8,
            data_room_size: zhida_dpdk_sys::RTE_PKTMBUF_HEADROOM as u16 + 512,
            socket_id: -1,
        }
    }

    #[zhida_test_support::pinned_test]
    fn clean_resource_drop_releases_pool_name() {
        let name = CString::new("resource_clean").unwrap();
        let cfg = resource_config(&name);
        for _ in 0..8 {
            let owner = unsafe { PoolResources::new(cfg) }.unwrap();
            drop(owner.pool().alloc().unwrap());
            assert_eq!(owner.pool().in_use_count(), 0);
            drop(owner);
            drop(unsafe { PoolResources::new(cfg) }.unwrap());
        }
    }

    // Called only after the Rust owner was dropped with one real survivor.
    fn return_survivor_and_free_retained_backing(
        survivor: zhida_buffer::Mbuf,
        backing: *mut zhida_dpdk_sys::rte_mempool,
        cache: *mut zhida_dpdk_sys::rte_mempool_cache,
    ) {
        use zhida_dpdk_sys::{
            dpdk_raw_pktmbuf_alloc, dpdk_raw_pktmbuf_free, rte_mempool_free,
            rte_mempool_in_use_count, zhida_mempool_cache_flush,
        };
        assert_eq!(survivor.len(), 4);
        assert_eq!(survivor.data(), b"live");
        assert_eq!(unsafe { rte_mempool_in_use_count(backing) }, 1);
        let returned = survivor.as_ptr();
        drop(survivor);
        assert_eq!(unsafe { rte_mempool_in_use_count(backing) }, 0);
        // Recover every object exactly once, including the returned survivor.
        let mut objects = Vec::new();
        for _ in 0..63 {
            let packet = unsafe { dpdk_raw_pktmbuf_alloc(backing) };
            assert!(!packet.is_null());
            assert!(
                !objects.contains(&packet),
                "duplicate free returned a held object"
            );
            objects.push(packet);
        }
        assert!(objects.contains(&returned));
        assert!(unsafe { dpdk_raw_pktmbuf_alloc(backing) }.is_null());
        assert_eq!(unsafe { rte_mempool_in_use_count(backing) }, 63);
        for packet in objects {
            unsafe { dpdk_raw_pktmbuf_free(packet) };
        }
        // Return cached free objects before releasing the test's retained pool.
        unsafe { zhida_mempool_cache_flush(cache, backing) };
        assert_eq!(unsafe { rte_mempool_in_use_count(backing) }, 0);
        unsafe { rte_mempool_free(backing) };
    }

    #[zhida_test_support::pinned_test]
    fn live_resource_drop_preserves_surviving_packet() {
        let name = CString::new("resource_live_drop").unwrap();
        let cfg = resource_config(&name);
        let owner = unsafe { PoolResources::new(cfg) }.unwrap();
        let backing = owner.pool().pool();
        let cache = owner.pool().cache();
        let mut survivor = owner.pool().alloc_with_len(4).unwrap();
        survivor.data_mut().copy_from_slice(b"live");
        drop(owner);
        return_survivor_and_free_retained_backing(survivor, backing, cache);
        drop(unsafe { PoolResources::new(cfg) }.unwrap());
    }

    #[zhida_test_support::pinned_test]
    fn live_resource_unwind_preserves_original_panic_and_packet() {
        let name = CString::new("resource_unwind").unwrap();
        let cfg = resource_config(&name);
        let mut survivor = None;
        let mut backing = std::ptr::null_mut();
        let mut cache = std::ptr::null_mut();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let owner = unsafe { PoolResources::new(cfg) }.unwrap();
            backing = owner.pool().pool();
            cache = owner.pool().cache();
            let mut packet = owner.pool().alloc_with_len(4).unwrap();
            packet.data_mut().copy_from_slice(b"live");
            survivor = Some(packet);
            panic!("original resource panic");
        }))
        .expect_err("original panic must survive owner Drop");
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"original resource panic")
        );
        return_survivor_and_free_retained_backing(survivor.unwrap(), backing, cache);
        drop(unsafe { PoolResources::new(cfg) }.unwrap());
    }
}
