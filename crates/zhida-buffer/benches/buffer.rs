use criterion::{criterion_group, criterion_main, Criterion, black_box};
use zhida_buffer::PoolManager;
use zhida_dpdk_sys::{
    dpdk_raw_pktmbuf_alloc, dpdk_raw_pktmbuf_free, dpdk_raw_pktmbuf_clone,
    dpdk_raw_pktmbuf_chain,
};

fn bench_mbuf_alloc(c: &mut Criterion) {
    let pool = PoolManager::new(4096);
    c.bench_function("mbuf_alloc", |b| {
        b.iter(|| {
            let mbuf = pool.alloc_with_len(1400).unwrap();
            black_box(&mbuf);
        })
    });
}

fn bench_prepend(c: &mut Criterion) {
    let pool = PoolManager::new(4096);
    c.bench_function("prepend_20", |b| {
        b.iter_batched(
            || pool.alloc_with_len(1400).unwrap(),
            |mut mbuf| {
                let hdr = mbuf.prepend(20).unwrap();
                hdr.fill(0);
                black_box(&mbuf);
            },
            criterion::BatchSize::PerIteration,
        )
    });
}

fn bench_prepend_header_segment(c: &mut Criterion) {
    let pool = PoolManager::new(4096);
    let payload = pool.alloc_with_len(1400).unwrap();
    c.bench_function("prepend_header_segment_20", |b| {
        b.iter_batched(
            || payload.clone_indirect(&pool).unwrap(),
            |mut packet| {
                let hdr = packet.prepend(20).unwrap();
                hdr.fill(0);
                black_box(&packet);
            },
            criterion::BatchSize::PerIteration,
        )
    });
    drop(payload);
}

fn bench_share(c: &mut Criterion) {
    let pool = PoolManager::new(4096);
    c.bench_function("share", |b| {
        let mut mbuf = pool.alloc_with_len(1400).unwrap();
        b.iter(|| {
            let shared = mbuf.share();
            black_box(&shared);
        });
        drop(mbuf);
    });
}

fn bench_adj(c: &mut Criterion) {
    let pool = PoolManager::new(4096);
    c.bench_function("adj", |b| {
        let mut mbuf = pool.alloc_with_len(1400).unwrap();
        let mbuf_ptr = mbuf.as_ptr();
        b.iter(|| {
            mbuf.adj(100);
            black_box(mbuf.len());
            // Reset via raw pointer - restore data_off and data_len
            unsafe {
                (*mbuf_ptr).set_data_off(128); // RTE_PKTMBUF_HEADROOM
                (*mbuf_ptr).set_data_len(1400);
                (*mbuf_ptr).set_pkt_len(1400);
            }
        });
        drop(mbuf);
    });
}

fn bench_trim(c: &mut Criterion) {
    let pool = PoolManager::new(4096);
    c.bench_function("trim", |b| {
        let mut mbuf = pool.alloc_with_len(1400).unwrap();
        let mbuf_ptr = mbuf.as_ptr();
        b.iter(|| {
            mbuf.trim(100);
            black_box(mbuf.len());
            // Reset data_len via raw pointer
            unsafe {
                (*mbuf_ptr).set_data_len(1400);
                (*mbuf_ptr).set_pkt_len(1400);
            }
        });
        drop(mbuf);
    });
}

fn bench_refcount(c: &mut Criterion) {
    let pool = PoolManager::new(4096);
    c.bench_function("refcount", |b| {
        let mbuf = pool.alloc_with_len(1400).unwrap();
        b.iter(|| black_box(mbuf.refcount()));
        drop(mbuf);
    });
}

fn bench_chain(c: &mut Criterion) {
    let pool = PoolManager::new(8192);
    c.bench_function("chain", |b| {
        b.iter_batched(
            || {
                let head = pool.alloc_with_len(100).unwrap();
                let tail = pool.alloc_with_len(100).unwrap();
                (head, tail)
            },
            |(mut head, tail)| {
                let _ = head.chain(tail);
                black_box(&head);
            },
            criterion::BatchSize::NumIterations(1000),
        )
    });
}

fn bench_share_all(c: &mut Criterion) {
    let pool = PoolManager::new(8192);
    c.bench_function("share_all_2seg", |b| {
        b.iter_batched(
            || {
                let mut head = pool.alloc_with_len(100).unwrap();
                let tail = pool.alloc_with_len(100).unwrap();
                let _ = head.chain(tail);
                head
            },
            |mut mbuf| {
                let shared = mbuf.share_all();
                black_box(&shared);
                black_box(&mbuf);
            },
            criterion::BatchSize::NumIterations(1000),
        )
    });
}

fn bench_clone_indirect(c: &mut Criterion) {
    let pool = PoolManager::new(8192);
    c.bench_function("clone_indirect_1seg", |b| {
        b.iter_batched(
            || pool.alloc_with_len(1400).unwrap(),
            |mbuf| {
                let cloned = mbuf.clone_indirect(&pool).unwrap();
                black_box(&cloned);
                black_box(&mbuf);
            },
            criterion::BatchSize::NumIterations(1000),
        )
    });
}

fn bench_clone_indirect_chain(c: &mut Criterion) {
    let pool = PoolManager::new(8192);
    c.bench_function("clone_indirect_2seg", |b| {
        b.iter_batched(
            || {
                let mut head = pool.alloc_with_len(100).unwrap();
                let tail = pool.alloc_with_len(100).unwrap();
                let _ = head.chain(tail);
                head
            },
            |mbuf| {
                let cloned = mbuf.clone_indirect(&pool).unwrap();
                black_box(&cloned);
                black_box(&mbuf);
            },
            criterion::BatchSize::NumIterations(1000),
        )
    });
}

fn bench_into_indirect_head(c: &mut Criterion) {
    let pool = PoolManager::new(8192);
    c.bench_function("into_indirect_head_2seg", |b| {
        b.iter_batched(
            || {
                let mut head = pool.alloc_with_len(100).unwrap();
                let tail = pool.alloc_with_len(100).unwrap();
                let _ = head.chain(tail);
                head
            },
            |mbuf| {
                let indirect = mbuf.into_indirect_head(&pool).unwrap();
                black_box(&indirect);
            },
            criterion::BatchSize::NumIterations(1000),
        )
    });
}

fn bench_clone_indirect_head(c: &mut Criterion) {
    let pool = PoolManager::new(8192);
    c.bench_function("clone_indirect_head_2seg", |b| {
        b.iter_batched(
            || {
                let mut head = pool.alloc_with_len(100).unwrap();
                let tail = pool.alloc_with_len(100).unwrap();
                let _ = head.chain(tail);
                head
            },
            |mbuf| {
                let cloned = mbuf.clone_indirect_head(&pool).unwrap();
                black_box(&cloned);
                black_box(&mbuf);
            },
            criterion::BatchSize::NumIterations(1000),
        )
    });
}

// =============================================================================
// Comparison benchmarks: zhida vs raw DPDK
// =============================================================================

fn bench_clone_comparison(c: &mut Criterion) {
    let pool = PoolManager::new(8192);
    let mp = pool.pool();
    let cache = pool.cache();

    let mut group = c.benchmark_group("clone_1seg");

    group.bench_function("zhida", |b| {
        b.iter_batched(
            || unsafe {
                let m = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(mp, cache);
                (*m).set_data_len(1400);
                (*m).set_pkt_len(1400);
                m
            },
            |m| unsafe {
                let cloned = zhida_dpdk_sys::zhida_pktmbuf_clone(m, mp, cache);
                black_box(cloned);
                black_box(m);
                dpdk_raw_pktmbuf_free(cloned);
                dpdk_raw_pktmbuf_free(m);
            },
            criterion::BatchSize::NumIterations(1000),
        )
    });

    group.bench_function("dpdk_raw", |b| {
        b.iter_batched(
            || unsafe {
                let m = dpdk_raw_pktmbuf_alloc(mp);
                (*m).set_data_len(1400);
                (*m).set_pkt_len(1400);
                m
            },
            |m| unsafe {
                let cloned = dpdk_raw_pktmbuf_clone(m, mp);
                black_box(cloned);
                black_box(m);
                dpdk_raw_pktmbuf_free(cloned);
                dpdk_raw_pktmbuf_free(m);
            },
            criterion::BatchSize::NumIterations(1000),
        )
    });

    group.finish();
}

fn bench_clone_chain_comparison(c: &mut Criterion) {
    let pool = PoolManager::new(8192);
    let mp = pool.pool();
    let cache = pool.cache();

    let mut group = c.benchmark_group("clone_2seg");

    group.bench_function("zhida", |b| {
        b.iter_batched(
            || unsafe {
                let head = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(mp, cache);
                let tail = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(mp, cache);
                (*head).set_data_len(100);
                (*head).set_pkt_len(100);
                (*tail).set_data_len(100);
                (*tail).set_pkt_len(100);
                zhida_dpdk_sys::zhida_pktmbuf_chain_safe(head, tail);
                head
            },
            |m| unsafe {
                let cloned = zhida_dpdk_sys::zhida_pktmbuf_clone(m, mp, cache);
                black_box(cloned);
                black_box(m);
                dpdk_raw_pktmbuf_free(cloned);
                dpdk_raw_pktmbuf_free(m);
            },
            criterion::BatchSize::NumIterations(1000),
        )
    });

    group.bench_function("dpdk_raw", |b| {
        b.iter_batched(
            || unsafe {
                let head = dpdk_raw_pktmbuf_alloc(mp);
                let tail = dpdk_raw_pktmbuf_alloc(mp);
                (*head).set_data_len(100);
                (*head).set_pkt_len(100);
                (*tail).set_data_len(100);
                (*tail).set_pkt_len(100);
                dpdk_raw_pktmbuf_chain(head, tail);
                head
            },
            |m| unsafe {
                let cloned = dpdk_raw_pktmbuf_clone(m, mp);
                black_box(cloned);
                black_box(m);
                dpdk_raw_pktmbuf_free(cloned);
                dpdk_raw_pktmbuf_free(m);
            },
            criterion::BatchSize::NumIterations(1000),
        )
    });

    // clone_indirect_head: 1 alloc for head, bump refcounts on tail (TCP retransmit pattern)
    group.bench_function("clone_indirect_head", |b| {
        b.iter_batched(
            || {
                let mut head = pool.alloc_with_len(100).unwrap();
                let tail = pool.alloc_with_len(100).unwrap();
                let _ = head.chain(tail);
                head
            },
            |mbuf| {
                let cloned = mbuf.clone_indirect_head(&pool).unwrap();
                black_box(&cloned);
                black_box(&mbuf);
            },
            criterion::BatchSize::NumIterations(1000),
        )
    });

    group.finish();
}

// 10-segment chain: shows clone_indirect_head advantage
fn bench_clone_10seg(c: &mut Criterion) {
    let pool = PoolManager::new(8192);
    let mp = pool.pool();
    let cache = pool.cache();

    let mut group = c.benchmark_group("clone_10seg");

    // Helper to build 10-segment chain
    unsafe fn make_10seg_chain(
        mp: *mut zhida_dpdk_sys::rte_mempool,
        cache: *mut zhida_dpdk_sys::rte_mempool_cache,
    ) -> *mut zhida_dpdk_sys::rte_mbuf {
        let head = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(mp, cache);
        (*head).set_data_len(100);
        let mut pkt_len = 100u32;
        let mut prev = head;
        for _ in 1..10 {
            let seg = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(mp, cache);
            (*seg).set_data_len(100);
            (*seg).set_pkt_len(100);
            (*seg).next = std::ptr::null_mut(); // terminate
            (*prev).next = seg;
            pkt_len += 100;
            prev = seg;
        }
        (*head).set_pkt_len(pkt_len);
        (*head).set_nb_segs(10);
        head
    }

    // Full clone: 10 allocs + 10 attaches
    group.bench_function("zhida_clone", |b| {
        b.iter_batched(
            || unsafe { make_10seg_chain(mp, cache) },
            |m| unsafe {
                let cloned = zhida_dpdk_sys::zhida_pktmbuf_clone(m, mp, cache);
                black_box(cloned);
                dpdk_raw_pktmbuf_free(cloned);
                dpdk_raw_pktmbuf_free(m);
            },
            criterion::BatchSize::NumIterations(100),
        )
    });

    group.bench_function("dpdk_raw_clone", |b| {
        b.iter_batched(
            || unsafe { make_10seg_chain(mp, cache) },
            |m| unsafe {
                let cloned = dpdk_raw_pktmbuf_clone(m, mp);
                black_box(cloned);
                dpdk_raw_pktmbuf_free(cloned);
                dpdk_raw_pktmbuf_free(m);
            },
            criterion::BatchSize::NumIterations(100),
        )
    });

    // clone_indirect_head: 1 alloc + 9 refcount bumps (TCP retransmit pattern)
    group.bench_function("clone_indirect_head", |b| {
        b.iter_batched(
            || unsafe { make_10seg_chain(mp, cache) },
            |m| unsafe {
                let cloned = zhida_dpdk_sys::zhida_pktmbuf_clone_indirect_head(m, mp, cache);
                black_box(cloned);
                dpdk_raw_pktmbuf_free(cloned);
                dpdk_raw_pktmbuf_free(m);
            },
            criterion::BatchSize::NumIterations(100),
        )
    });

    group.finish();
}

// Isolate clone operation from free (reuse mbufs)
fn bench_clone_isolated(c: &mut Criterion) {
    let pool = PoolManager::new(8192);
    let mp = pool.pool();
    let cache = pool.cache();

    let mut group = c.benchmark_group("clone_isolated");

    // Pre-allocate source chain, measure only clone + immediate free of clone
    // (source stays allocated, only clone is freed each iteration)
    let source = unsafe {
        let head = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(mp, cache);
        (*head).set_data_len(100);
        let mut prev = head;
        for _ in 1..10 {
            let seg = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(mp, cache);
            (*seg).set_data_len(100);
            (*seg).set_pkt_len(100);
            (*seg).next = std::ptr::null_mut();
            (*prev).next = seg;
            prev = seg;
        }
        (*head).set_pkt_len(1000);
        (*head).set_nb_segs(10);
        head
    };

    // Pre-compute all segment pointers (avoid dependent loads in reset)
    let mut seg_ptrs: [*mut zhida_dpdk_sys::rte_mbuf; 10] = [std::ptr::null_mut(); 10];
    unsafe {
        let mut seg = source;
        for i in 0..10 {
            seg_ptrs[i] = seg;
            seg = (*seg).next;
        }
    }

    // Just 9 refcount increments (what clone_indirect_head does to tail)
    group.bench_function("9_refcount_inc", |b| {
        b.iter(|| unsafe {
            let mut seg = (*source).next;
            while !seg.is_null() {
                (*seg).refcnt_inc();
                seg = (*seg).next;
            }
            // Undo the increments
            seg = (*source).next;
            while !seg.is_null() {
                (*seg).set_refcnt(1);
                seg = (*seg).next;
            }
        })
    });

    // Just chain walk (measure cost of 9 dependent loads, no refcount ops)
    group.bench_function("chain_walk_only", |b| {
        b.iter(|| unsafe {
            let mut seg = (*source).next;
            let mut count = 0u32;
            while !seg.is_null() {
                count += 1;
                seg = (*seg).next;
            }
            black_box(count);
        })
    });

    // Just 1 attach (no alloc, no free - measure attach cost alone)
    // Pre-allocate indirect, reset it between iterations
    let indirect_for_attach = unsafe { zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(mp, cache) };
    group.bench_function("attach_only", |b| {
        b.iter(|| unsafe {
            zhida_dpdk_sys::zhida_pktmbuf_attach(indirect_for_attach, source);
            black_box(indirect_for_attach);
            // Reset: decrement source refcount, make indirect direct again
            (*source).set_refcnt(1);
            // Quick detach (just reset ol_flags so it's direct)
            (*indirect_for_attach).ol_flags = 0;
        })
    });
    unsafe { dpdk_raw_pktmbuf_free(indirect_for_attach); }

    // Raw FFI call to clone_indirect_head, no cleanup measured
    // Just leak the clone, manually reset refcounts
    group.bench_function("clone_ffi_only", |b| {
        b.iter(|| unsafe {
            let cloned = zhida_dpdk_sys::zhida_pktmbuf_clone_indirect_head(source, mp, cache);
            black_box(cloned);
            // Just manually reset state for next iteration (not measured as "clone" cost)
            // by resetting refcounts in place
            for ptr in &seg_ptrs {
                if !ptr.is_null() {
                    (**ptr).set_refcnt(1);
                }
            }
            // Return indirect to pool the fast way
            (*cloned).next = std::ptr::null_mut();
            (*cloned).set_nb_segs(1);
            (*cloned).ol_flags = 0;
            let priv_size = 8usize;
            (*cloned).buf_addr = (cloned as *mut u8).add(128 + priv_size) as *mut _;
            zhida_dpdk_sys::zhida_pktmbuf_free_minimal(cloned);
        })
    });

    // Break it down further: just alloc_noreset + return to pool
    group.bench_function("alloc_noreset_free_minimal", |b| {
        b.iter(|| unsafe {
            let m = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(mp, cache);
            black_box(m);
            // Skip reset entirely, just return to pool
            zhida_dpdk_sys::zhida_pktmbuf_free_minimal(m);
        })
    });

    // Just alloc + minimal free (no indirect, no attach)
    group.bench_function("alloc_free_direct", |b| {
        b.iter(|| unsafe {
            let m = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(mp, cache);
            black_box(m);
            zhida_dpdk_sys::zhida_pktmbuf_free(m);
        })
    });

    // Alloc + attach to source head + return indirect to pool (minimal, isolated)
    // This measures: 1 alloc + attach + 1 indirect free (no tail refcount walk)
    group.bench_function("alloc_attach_free_indirect", |b| {
        b.iter(|| unsafe {
            let indirect = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(mp, cache);
            zhida_dpdk_sys::zhida_pktmbuf_attach(indirect, source);
            black_box(indirect);
            // Free indirect (will detach and return to pool)
            zhida_dpdk_sys::zhida_pktmbuf_free(indirect);
            // Reset source refcount (attach bumped it)
            (*source).set_refcnt(1);
        })
    });

    // PURE CLONE ONLY: clone + direct return to cache (no indirect free path)
    // By manually detaching and freeing as direct, we avoid the indirect free overhead
    group.bench_function("clone_indirect_head_pure", |b| {
        b.iter(|| unsafe {
            let cloned = zhida_dpdk_sys::zhida_pktmbuf_clone_indirect_head(source, mp, cache);
            black_box(cloned);
            // Manually detach: reset buf_addr to own buffer, clear indirect flag
            // This simulates what we'd do if we had a fast "return to pool" path
            (*cloned).next = std::ptr::null_mut();
            (*cloned).set_nb_segs(1);
            // Reset source refcounts using precomputed pointers
            for ptr in &seg_ptrs {
                if !ptr.is_null() {
                    (**ptr).set_refcnt(1);
                }
            }
            // Detach indirect: restore buf_addr to own buffer
            let priv_size = 8u64; // our ZHIDA_PRIV_SIZE
            (*cloned).buf_addr = (cloned as *mut u8).add(128 + priv_size as usize) as *mut _;
            (*cloned).ol_flags = 0;
            // Now it's direct, can use fast free
            zhida_dpdk_sys::zhida_pktmbuf_free_minimal(cloned);
        })
    });

    // Clone using iter_batched to avoid any cleanup in hot path
    group.bench_function("clone_indirect_head_batched", |b| {
        b.iter_batched(
            || {
                // Setup: build fresh 10-segment chain each iteration
                unsafe {
                    let head = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(mp, cache);
                    (*head).set_data_len(100);
                    let mut prev = head;
                    for _ in 1..10 {
                        let seg = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(mp, cache);
                        (*seg).set_data_len(100);
                        (*seg).set_pkt_len(100);
                        (*seg).next = std::ptr::null_mut();
                        (*prev).next = seg;
                        prev = seg;
                    }
                    (*head).set_pkt_len(1000);
                    (*head).set_nb_segs(10);
                    head
                }
            },
            |source_fresh| unsafe {
                // ONLY measure the clone operation
                let cloned = zhida_dpdk_sys::zhida_pktmbuf_clone_indirect_head(source_fresh, mp, cache);
                black_box(cloned);
                black_box(source_fresh);
                // Let criterion handle cleanup (both will be freed after batch)
                dpdk_raw_pktmbuf_free(cloned);
                dpdk_raw_pktmbuf_free(source_fresh);
            },
            criterion::BatchSize::NumIterations(100),
        )
    });

    // Full clone_indirect_head + free both with zhida_free (uses cached pool ptr)
    group.bench_function("clone_indirect_head_zhida_free", |b| {
        b.iter(|| unsafe {
            let cloned = zhida_dpdk_sys::zhida_pktmbuf_clone_indirect_head(source, mp, cache);
            black_box(cloned);
            zhida_dpdk_sys::zhida_pktmbuf_free(cloned);
            // Reset source refcounts for next iteration
            (*source).set_refcnt(1);
            let mut seg = (*source).next;
            while !seg.is_null() {
                (*seg).set_refcnt(1);
                seg = (*seg).next;
            }
        })
    });

    // Same but with dpdk_raw_free (TLS lookup per segment)
    group.bench_function("clone_indirect_head_dpdk_free", |b| {
        b.iter(|| unsafe {
            let cloned = zhida_dpdk_sys::zhida_pktmbuf_clone_indirect_head(source, mp, cache);
            black_box(cloned);
            dpdk_raw_pktmbuf_free(cloned);
            // Reset source refcounts for next iteration
            (*source).set_refcnt(1);
            let mut seg = (*source).next;
            while !seg.is_null() {
                (*seg).set_refcnt(1);
                seg = (*seg).next;
            }
        })
    });

    group.finish();

    // Clean up source
    unsafe { dpdk_raw_pktmbuf_free(source); }
}

// Isolate alloc vs free performance
fn bench_alloc_free_isolation(c: &mut Criterion) {
    let pool = PoolManager::new(4096);
    let mp = pool.pool();
    let cache = pool.cache();

    let mut group = c.benchmark_group("isolation");

    // zhida alloc + dpdk free
    group.bench_function("zhida_alloc_dpdk_free", |b| {
        b.iter(|| unsafe {
            let m = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(mp, cache);
            black_box(m);
            dpdk_raw_pktmbuf_free(m);
        })
    });

    // dpdk alloc + zhida free
    group.bench_function("dpdk_alloc_zhida_free", |b| {
        b.iter(|| unsafe {
            let m = dpdk_raw_pktmbuf_alloc(mp);
            black_box(m);
            zhida_dpdk_sys::zhida_pktmbuf_free(m);
        })
    });

    // both zhida
    group.bench_function("zhida_both", |b| {
        b.iter(|| unsafe {
            let m = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(mp, cache);
            black_box(m);
            zhida_dpdk_sys::zhida_pktmbuf_free(m);
        })
    });

    // both dpdk
    group.bench_function("dpdk_both", |b| {
        b.iter(|| unsafe {
            let m = dpdk_raw_pktmbuf_alloc(mp);
            black_box(m);
            dpdk_raw_pktmbuf_free(m);
        })
    });

    group.finish();
}

fn bench_chain_comparison(c: &mut Criterion) {
    let pool = PoolManager::new(8192);
    let mp = pool.pool();
    let cache = pool.cache();

    let mut group = c.benchmark_group("chain");

    // chain() - safe with refcount check (single walk)
    group.bench_function("safe", |b| {
        b.iter_batched(
            || {
                let head = pool.alloc_with_len(100).unwrap();
                let tail = pool.alloc_with_len(100).unwrap();
                (head, tail)
            },
            |(mut head, tail)| {
                let _ = head.chain(tail);
                black_box(&head);
            },
            criterion::BatchSize::NumIterations(1000),
        )
    });

    // raw DPDK for comparison
    group.bench_function("dpdk_raw", |b| {
        b.iter_batched(
            || unsafe {
                let head = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(mp, cache);
                let tail = zhida_dpdk_sys::zhida_pktmbuf_alloc_fast(mp, cache);
                (*head).set_data_len(100);
                (*head).set_pkt_len(100);
                (*tail).set_data_len(100);
                (*tail).set_pkt_len(100);
                (head, tail)
            },
            |(head, tail)| unsafe {
                dpdk_raw_pktmbuf_chain(head, tail);
                black_box(head);
                zhida_dpdk_sys::zhida_pktmbuf_free(head);
            },
            criterion::BatchSize::NumIterations(1000),
        )
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_mbuf_alloc,
    bench_prepend,
    bench_prepend_header_segment,
    bench_share,
    bench_adj,
    bench_trim,
    bench_refcount,
    bench_chain,
    bench_share_all,
    bench_clone_indirect,
    bench_clone_indirect_chain,
    bench_into_indirect_head,
    bench_clone_indirect_head,
);

criterion_group!(
    comparison,
    bench_alloc_free_isolation,
    bench_clone_comparison,
    bench_clone_chain_comparison,
    bench_clone_10seg,
    bench_clone_isolated,
    bench_chain_comparison,
);

criterion_main!(benches, comparison);
