use zhida_buffer::PoolManager;

/// Exactly-once return proof, run after the final drop. `in_use_count() == 0`
/// cannot see a double return: DPDK caps the available count at the pool size.
/// A double-returned buffer is handed out twice, so allocating until empty
/// yields more than `size` buffers or a repeated address. Releases them after.
pub fn assert_returned_exactly_once(pool: &PoolManager, size: u32) {
    let mut held = Vec::with_capacity(size as usize);
    while let Some(m) = pool.alloc() {
        held.push(m);
        if held.len() > size as usize {
            break;
        }
    }
    let mut addrs: Vec<usize> = held.iter().map(|m| m.as_ptr() as usize).collect();
    addrs.sort_unstable();
    addrs.dedup();
    if held.len() != size as usize || addrs.len() != held.len() {
        let (count, distinct) = (held.len(), addrs.len());
        std::mem::forget(held);
        panic!("pool handed out {count} buffers ({distinct} distinct), size {size}");
    }
}
