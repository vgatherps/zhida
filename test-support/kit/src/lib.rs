//! Test-only DPDK fixtures shared by the workspace's integration tests and
//! benches: one EAL argv, net_ring Ports, net_tap and net_pcap vdevs, a copying wire, a
//! two-Stack driver and many connections over it.

use std::cell::OnceCell;

use dpdk_smoltcp::Eal;
use zhida_dpdk_sys::zhida_lcore_id;

pub mod many;
pub mod pair;
pub mod pcap;
pub mod peers;
pub mod ring_port;
pub mod tap;
pub mod wire;

/// Test EAL argv: no PCI, hugepages, shared config or telemetry; lcore 7 as
/// the main lcore, on the one CPU the calling thread may run on; 1 GiB of
/// (lazily touched) memory, because RX pools back every socket's receive
/// budget and the 2 x 10 240-connection benches need ~320 MiB of RX mbufs.
/// Panics unless exactly one CPU is allowed.
pub fn eal_args() -> Vec<String> {
    let cpu = zhida_dpdk_sys::only_allowed_cpu().unwrap_or_else(|error| panic!("{error}"));
    [
        "zhida-test",
        "--no-pci",
        "--no-huge",
        "--no-shconf",
        "--no-telemetry",
        "-m",
        "1024",
        format!("--lcores=7@{cpu}").as_str(),
        "--main-lcore=7",
    ]
    .map(str::to_owned)
    .into()
}

thread_local! {
    static EAL: OnceCell<Eal> = const { OnceCell::new() };
}

/// `body` with this thread's EAL, initialized on first use; the thread that
/// initialized EAL owns it.
pub fn with_eal<R>(body: impl FnOnce(&Eal) -> R) -> R {
    EAL.with(|owner| {
        let eal = owner.get_or_init(|| {
            let args = eal_args();
            Eal::init(&args.iter().map(String::as_str).collect::<Vec<_>>()).unwrap()
        });
        assert_eq!(eal.owner_lcore_id(), 7);
        assert_eq!(unsafe { zhida_lcore_id() }, 7);
        body(eal)
    })
}
