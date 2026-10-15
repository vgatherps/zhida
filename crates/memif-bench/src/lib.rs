//! memif benchmark support: a Zhida Port on a net_memif vdev, the benchmark
//! workloads between two Zhida Stacks, and the configuration matrix the
//! `memif-bench` binary runs.

pub mod matrix;
pub mod memif;
pub mod workload;
