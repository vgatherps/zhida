use zhida_test_support::pinned_test;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[pinned_test]
    #[test]
    fn generated_property_function_runs_on_worker(value in 0u16..1000) {
        let current = std::thread::current();
        prop_assert_eq!(current.name(), Some("zhida-test-worker"));
        prop_assert!(value < 1000);
    }
}
