# zhida-buffer

Thin wrapper over DPDK mbufs with ownership-checked chain operations (refuse shared heads, shared tails whose metadata would change, and cycles).

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Mbuf (8 bytes, repr(transparent))                               │
│  - Direct wrapper over NonNull<rte_mbuf>                         │
│  - Uses DPDK's data_off/data_len directly                        │
│  - !Send + !Sync (single-threaded, never migrates)               │
├──────────────────────────────────────────────────────────────────┤
│  PoolManager                                                     │
│  - Owns rte_mempool + precomputed cache pointer                  │
│  - Cache ptr stored in mbuf priv_data (8 bytes)                  │
│  - Eliminates TLS lookup + array index on alloc/free             │
└──────────────────────────────────────────────────────────────────┘
```

## Mbuf operations

```rust
// Allocation
let mut m = pool.alloc_with_len(100)?;

// Data access (via DPDK's data_off + data_len)
m.data();           // &[u8]
m.data_mut();       // &mut [u8]

// Headroom manipulation
m.prepend(20)?;     // In place if headroom is exclusively ours, else new header segment (see Prepend)
m.adj(20);          // Increase data_off (consume front)
m.trim(20);         // Decrease data_len (truncate back)

// Reference counting (per-segment)
m.share();          // Single-segment only: bump refcount, return alias
m.share_all();      // Chain: bump refcount on ALL segments
m.refcount();       // Head segment refcount
m.is_head_unique(); // refcount == 1
m.is_tail_unique(); // lastseg.refcount == 1
```

## Clone operations

| Operation | Allocates | Head | Tails | Use Case |
|-----------|-----------|------|-------|----------|
| `share()` | 0 | same mbuf, refcount++ | N/A (single only) | Alias, same data_off |
| `share_all()` | 0 | same chain, all refcount++ | same chain | Alias entire chain |
| `clone_indirect()` | n | new indirect mbufs | new indirect mbufs | Independent data_off per segment; dynfields not copied |
| `clone_indirect_head()` | 1 | new indirect mbuf | shared (refcount++) | Independent head data_off; `prepend` links a header segment while the original (or any other holder of the backing buffer) lives, writes in place once this head is the sole holder; dynfields not copied |
| `into_indirect_head()` | 1 | new indirect; original header becomes its backing buffer, which returns to the pool when its last counted reference drops (other holders, e.g. a `share()` alias, keep it alive) | transferred (no refcount change) | Replace head with indirect; `Err(self)` if head is indirect, or shared and chained |

Unlike DPDK `rte_pktmbuf_attach`, zhida's attach does not copy dynfields. An indirect head carries its pool object's stale dynfields, and a header segment prepended on it copies those.

## Prepend

`prepend(n) -> Option<&mut [u8]>` never panics and never changes bytes or metadata another holder sees.

- In place (`data_off -= n`) when `n <= headroom()`, `refcount() == 1`, and for an indirect head no other holder of its backing buffer (original, other clones).
- Otherwise a fresh direct segment from the head's own pool (an indirect head's own header pool, not the backing buffer's) is linked in front. The handle's references move into the chain; the old chain is not written. The new head holds the `n` bytes at the end of its buffer, the packet's `nb_segs`/`pkt_len`, and the old head's DPDK header-copy metadata (`__rte_pktmbuf_copy_hdr` set; `ol_flags` without INDIRECT/EXTERNAL). Afterwards `data()`/`len()` cover only the header segment (use `pkt_len()`/`iter_segs()`); `share()` panics on the chain.
- `prepend(0)` on a non-exclusive head returns an empty slice and changes nothing.
- `None`, packet unchanged: pool exhausted, `n` above the pool's data room (headroom included), or already `u16::MAX` segments.

## Chain operations

Appending writes `lastseg(head).next`, `head.nb_segs`, `head.pkt_len`, and resets `tail.pkt_len` to `tail.data_len`. If another owner reaches any of those fields, it observes changed metadata, or its free walks into a tail it holds no reference to (the tail goes back to the pool while linked). DPDK's `rte_pktmbuf_chain()` checks none of this.

`chain` refuses, writing nothing and returning `Err(tail)`, unless:

- `lastseg(head).refcount == 1`. Every owner holds one reference on each segment of its chain (`Clone`, `share_all()`, `clone_indirect_head()` increment every segment they walk) and every walk through head's chain ends at `lastseg`, so this means no other owner reaches any head segment. It also excludes cycles.
- `tail.refcount == 1` or `tail.pkt_len == tail.data_len`. A shared tail is allowed only when the reset is a no-op and is skipped (single-segment fan-in, or a multi-segment tail trimmed to `pkt_len == data_len`).

An indirect clone attached to a direct last segment raises its refcount, so appending to that segment is refused. Every chain path, the unchecked `zhida_pktmbuf_chain` included, refuses more than `u16::MAX` total segments.

```rust
// O(n): walk head to lastseg, then the checks above
head.chain(tail) -> Result<(), Mbuf>
```

## C shim (zhida-dpdk-sys)

C implementations of the hot paths. Free uses tail calls (`musttail`). Allocation receives the cached pointer; free reads it from mbuf private data. Refcount and cache ops are inlined into callers.

```c
// Single-segment free: refcnt check → direct check → pool put
void zhida_pktmbuf_free_seg(struct rte_mbuf *m);

// Chain-walking free: recursive tail calls, indirect handling
void zhida_pktmbuf_free(struct rte_mbuf *m);

// Fast alloc: pop from precomputed cache, no TLS lookup
struct rte_mbuf *zhida_pktmbuf_alloc_fast(rte_mempool *mp, rte_mempool_cache *cache);

// Chain with the ownership rule above
int zhida_pktmbuf_chain_safe(struct rte_mbuf *head, struct rte_mbuf *tail);
```

## priv_data layout

Pool created with `priv_size=8`. First 8 bytes store precomputed cache pointer:

```
┌─────────────────┬────────────┬─────────────────────┐
│   rte_mbuf      │ priv_data  │     buf_addr...     │
│   (128 bytes)   │ (8 bytes)  │                     │
└─────────────────┴────────────┴─────────────────────┘
                  │
                  └── *rte_mempool_cache (set at pool init)
```

`zhida_pool_init_cache_ptrs()` sets the cache pointer in every mbuf at pool creation, so alloc and free skip the TLS and array lookup.

## Testing

```bash
make test-buffer                        # Unit and integration tests, one test thread
make test-props                         # Proptests (single-threaded, zhida vs DPDK)
cargo bench -p zhida-buffer             # Benchmarks
```

The proptests compare zhida's chain shape, refcounts and payload against plain DPDK mbufs for the same operations. Every test claims EAL on the one CPU the process may run on, so run them under `taskset -c N` or in the Docker image.

`fuzz/fuzz_targets/fuzz_ops.rs` is a cargo-fuzz harness that runs the same comparison on random operation lists. No make target runs it, and the Docker image has neither nightly nor cargo-fuzz. The fuzz crate is its own workspace with its own `fuzz/Cargo.lock`. On a Linux host with DPDK set up as in [docker/README.md](../../docker/README.md#linux-vm) and cargo-fuzz installed (it needs a nightly toolchain), run it from this directory:

```bash
taskset -c 3 cargo +nightly fuzz run fuzz_ops -- -max_total_time=60
```

A clean run exits 0. LeakSanitizer is on, so a leak at exit fails the run.

`make fuzz` fuzzes the TCP stack through tap-echo and does not touch this crate.

The test helpers `ensure_eal_init`, `acquire_test_pool`/`TestPoolGuard`, `PoolManager::new`, `PoolManager::new_unchecked` and the `testing` module exist only with the `testing` feature, because `ensure_eal_init` claims EAL with test arguments and would make `dpdk-smoltcp`'s `Eal::init` fail. A self dev-dependency enables `testing` for this crate's tests, benches and doctests; `src/bin/profile.rs` requires it. Applications create pools with `PoolManager::new_production`. `acquire_test_pool` gives each thread its own pool and lcore cache, and `TestPoolGuard` is neither `Send` nor `Sync`.

Chain ownership tests (shared-head and shared-tail refusal, cycle prevention):
- `test_assumption_share_all_increments_all_segments`
- `test_assumption_tail_unique_means_never_shared`
- `test_self_chain_via_share_prevented`
- `test_self_chain_multiseg_via_share_all_prevented`
- `tests/chain_ownership.rs`: shared head/tail refusal with both packets intact, fan-in, drop orders, pool accounting
- `test_chain_rejects_segment_count_overflow`: `u16::MAX` segments accepted, one more refused
