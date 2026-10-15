use std::hint::black_box;
use std::time::Instant;
use zhida_buffer::{Mbuf, PoolManager};

fn main() {
    const ITERS: u64 = 10_000_000;
    const BATCH: usize = 4000;  // Fits in pool
    const ROUNDS: usize = 2500; // BATCH * ROUNDS = 10M ops

    // Large pool for batch operations
    let pool = PoolManager::new(8192);

    println!("Mbuf Operation Benchmarks ({} iterations)\n", ITERS);

    // === share() ===
    // One mbuf, share many times - each share() bumps refcount, drop decrements
    {
        let mut mbuf = pool.alloc_with_len(1400).expect("alloc failed");

        // Warmup
        for _ in 0..10_000 {
            let shared = mbuf.share();
            black_box(&shared);
        }

        let start = Instant::now();
        for _ in 0..ITERS {
            let shared = mbuf.share();
            black_box(&shared);
        }
        let elapsed = start.elapsed();
        println!(
            "share() + drop:        {:7.2} ns/op",
            elapsed.as_nanos() as f64 / ITERS as f64
        );
    }

    // === clone() - same as share semantically ===
    {
        let mbuf = pool.alloc_with_len(1400).expect("alloc failed");

        let start = Instant::now();
        for _ in 0..ITERS {
            let cloned = mbuf.clone();
            black_box(&cloned);
        }
        let elapsed = start.elapsed();
        println!(
            "clone() + drop:        {:7.2} ns/op",
            elapsed.as_nanos() as f64 / ITERS as f64
        );
    }

    // === prepend() ===
    // Pre-allocate batch, time prepend only
    {
        let mut total_ns = 0u128;

        for _ in 0..ROUNDS {
            let mut mbufs: Vec<Mbuf> = (0..BATCH)
                .map(|_| pool.alloc_with_len(1400).expect("alloc failed"))
                .collect();

            let start = Instant::now();
            for mbuf in &mut mbufs {
                let hdr = mbuf.prepend(20).expect("prepend failed");
                black_box(hdr);
            }
            total_ns += start.elapsed().as_nanos();
        }

        let total_ops = (BATCH * ROUNDS) as f64;
        println!(
            "prepend():             {:7.2} ns/op",
            total_ns as f64 / total_ops
        );
    }

    // === adj() (consume front) ===
    {
        let mut total_ns = 0u128;

        for _ in 0..ROUNDS {
            let mut mbufs: Vec<Mbuf> = (0..BATCH)
                .map(|_| pool.alloc_with_len(1400).expect("alloc failed"))
                .collect();

            let start = Instant::now();
            for mbuf in &mut mbufs {
                mbuf.adj(100);
                black_box(mbuf.len());
            }
            total_ns += start.elapsed().as_nanos();
        }

        let total_ops = (BATCH * ROUNDS) as f64;
        println!(
            "adj():                 {:7.2} ns/op",
            total_ns as f64 / total_ops
        );
    }

    // === trim() (remove from back) ===
    {
        let mut total_ns = 0u128;

        for _ in 0..ROUNDS {
            let mut mbufs: Vec<Mbuf> = (0..BATCH)
                .map(|_| pool.alloc_with_len(1400).expect("alloc failed"))
                .collect();

            let start = Instant::now();
            for mbuf in &mut mbufs {
                mbuf.trim(100);
                black_box(mbuf.len());
            }
            total_ns += start.elapsed().as_nanos();
        }

        let total_ops = (BATCH * ROUNDS) as f64;
        println!(
            "trim():                {:7.2} ns/op",
            total_ns as f64 / total_ops
        );
    }

    // === refcount() read ===
    {
        let mbuf = pool.alloc_with_len(1400).expect("alloc failed");
        let start = Instant::now();
        for _ in 0..ITERS {
            black_box(mbuf.refcount());
        }
        let elapsed = start.elapsed();
        println!(
            "refcount() read:       {:7.2} ns/op",
            elapsed.as_nanos() as f64 / ITERS as f64
        );
    }

    // === data() ===
    {
        let mbuf = pool.alloc_with_len(1400).expect("alloc failed");
        let start = Instant::now();
        for _ in 0..ITERS {
            black_box(mbuf.data().as_ptr());
        }
        let elapsed = start.elapsed();
        println!(
            "data().as_ptr():       {:7.2} ns/op",
            elapsed.as_nanos() as f64 / ITERS as f64
        );
    }

    // === len() ===
    {
        let mbuf = pool.alloc_with_len(1400).expect("alloc failed");
        let start = Instant::now();
        for _ in 0..ITERS {
            black_box(mbuf.len());
        }
        let elapsed = start.elapsed();
        println!(
            "len():                 {:7.2} ns/op",
            elapsed.as_nanos() as f64 / ITERS as f64
        );
    }

    println!();

    // === Alloc+free baseline for reference ===
    {
        let start = Instant::now();
        for _ in 0..ITERS {
            let mbuf = pool.alloc_with_len(1400).expect("alloc failed");
            black_box(&mbuf);
        }
        let elapsed = start.elapsed();
        println!(
            "(alloc+free baseline:  {:7.2} ns/op)",
            elapsed.as_nanos() as f64 / ITERS as f64
        );
    }
}
