//! Receive turn and application read timings, Criterion groups "rx" and "rx_seg".
//! copy/1, copy/8, drain/1 and drain/8 receive k in-order 1448-byte
//! segments and send one ACK, then read all k × 1448 bytes from B's socket.
//! rx_seg receives eight in-order segments of 64, 200, 512 or 1448 bytes.
//! A drain read returns each whole frame and drops it inside the timed region.
//! A frame may contain several small in-order segments copied into its tailroom.
//! The turn and read are timed together; one throughput element is a segment.
//! A's write and turn, forwarding, frame checks and ACK handling are untimed.
//! Both sockets use Cubic with the default 1 MiB initial window, no ACK delay,
//! and buffers of three batches each way.
//! rx_seg sizes every buffer for three batches of eight 1448-byte segments.
//! Setup verifies a full batch before six warmup iterations. Warmup
//! checks all bytes; measured drain reads check lengths and slice endpoints.
//! Copy reads always compare all bytes after timing. Every iteration uses a
//! new pattern seed and ends with empty send and receive queues on both sockets.
//! Warmup iterations after the first also check B's TX pool before the timed
//! call and both poll_at deadlines afterwards. Measured iterations skip those
//! checks, as emit.rs does, to avoid their effect on caches and socket polling.
//! The timer read is inside the timed region. Criterion averages these samples;
//! emit's clock bench reports the cost of the same two Instant reads.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use zhida_test_kit::pair::pattern;
use zhida_test_kit::with_eal;

#[path = "rx/mod.rs"]
mod rx;

const WARMUP: usize = 6;

fn benches(c: &mut Criterion) {
    with_eal(|eal| {
        let mut group = c.benchmark_group("rx");
        for style in [rx::Read::Copy, rx::Read::Drain] {
            for k in [1usize, 8] {
                let batch = k.checked_mul(rx::MSS).expect("batch bytes");
                let buffer = batch.checked_mul(3).expect("socket buffer");
                let (mut pair, handles) = rx::setup(eal, k, buffer);
                let mut sink = vec![0; batch];
                let mut seed = 7u32;
                for warmup in 0..WARMUP {
                    let payload = pattern(batch, seed);
                    seed = seed.checked_add(1).expect("payload seed");
                    rx::iteration(
                        &mut pair,
                        &handles,
                        style,
                        rx::MSS,
                        &payload,
                        &mut sink,
                        true,
                        warmup > 0,
                    );
                }
                group.throughput(Throughput::Elements(u64::try_from(k).expect("segments")));
                group.bench_function(BenchmarkId::new(style.name(), k), |b| {
                    b.iter_custom(|iters| {
                        let mut elapsed = Duration::ZERO;
                        for _ in 0..iters {
                            let payload = pattern(batch, seed);
                            seed = seed.checked_add(1).expect("payload seed");
                            let (sample, _) = rx::iteration(
                                &mut pair,
                                &handles,
                                style,
                                rx::MSS,
                                &payload,
                                &mut sink,
                                false,
                                false,
                            );
                            elapsed = elapsed.checked_add(sample).expect("total rx duration");
                        }
                        elapsed
                    });
                });
                rx::close(pair);
            }
        }
        group.finish();

        let mut group = c.benchmark_group("rx_seg");
        for style in [rx::Read::Copy, rx::Read::Drain] {
            for seg in [64usize, 200, 512, 1448] {
                let k = 8usize;
                let batch = k.checked_mul(seg).expect("batch bytes");
                let buffer = 3usize
                    .checked_mul(k)
                    .expect("buffer segments")
                    .checked_mul(1448)
                    .expect("socket buffer");
                let (mut pair, handles) = rx::setup(eal, k, buffer);
                let mut sink = vec![0; batch];
                let mut seed = 7u32;
                for warmup in 0..WARMUP {
                    let payload = pattern(batch, seed);
                    seed = seed.checked_add(1).expect("payload seed");
                    rx::iteration(
                        &mut pair,
                        &handles,
                        style,
                        seg,
                        &payload,
                        &mut sink,
                        true,
                        warmup > 0,
                    );
                }
                group.throughput(Throughput::Elements(u64::try_from(k).expect("segments")));
                group.bench_function(BenchmarkId::new(style.name(), seg), |b| {
                    b.iter_custom(|iters| {
                        let mut elapsed = Duration::ZERO;
                        for _ in 0..iters {
                            let payload = pattern(batch, seed);
                            seed = seed.checked_add(1).expect("payload seed");
                            let (sample, _) = rx::iteration(
                                &mut pair, &handles, style, seg, &payload, &mut sink, false, false,
                            );
                            elapsed = elapsed.checked_add(sample).expect("total rx duration");
                        }
                        elapsed
                    });
                });
                rx::close(pair);
            }
        }
        group.finish();
    });
}

criterion_group!(rx, benches);
criterion_main!(rx);
