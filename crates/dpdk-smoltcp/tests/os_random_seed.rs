use dpdk_smoltcp::os_random_seed;

#[test]
fn os_random_seed_returns_eight_bytes_of_fresh_entropy() {
    let first = os_random_seed().expect("read /dev/urandom");
    let second = os_random_seed().expect("read /dev/urandom again");
    assert_eq!(std::mem::size_of_val(&first), 8);
    assert_ne!(first, second);
}
