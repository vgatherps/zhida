use std::env;
use std::path::PathBuf;

/// mbuf ol_flags constants as u64, the type of `rte_mbuf::ol_flags`; bindgen
/// otherwise gives the ones that fit 32 bits a u32 type.
#[derive(Debug)]
struct MbufFlagsU64;

impl bindgen::callbacks::ParseCallbacks for MbufFlagsU64 {
    fn int_macro(&self, name: &str, _value: i64) -> Option<bindgen::callbacks::IntKind> {
        name.starts_with("RTE_MBUF_F_")
            .then_some(bindgen::callbacks::IntKind::U64)
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-changed=shim_common.h");
    println!("cargo:rerun-if-changed=shim_free.c");
    println!("cargo:rerun-if-changed=shim_alloc.c");
    println!("cargo:rerun-if-changed=shim_chain.c");
    println!("cargo:rerun-if-changed=shim_clone.c");
    println!("cargo:rerun-if-changed=shim_raw.c");
    println!("cargo:rerun-if-changed=shim_ethdev.c");

    // Get include paths and link flags from pkg-config
    let lib = pkg_config::Config::new()
        .probe("libdpdk")
        .expect("Failed to find libdpdk via pkg-config");

    // libdpdk pkg-config excludes the PMD needed by the ring fixture.
    println!("cargo:rustc-link-lib=rte_net_ring");
    println!("cargo:rustc-link-lib=rte_bus_vdev");

    // Compile shim modules
    let mut cc_build = cc::Build::new();
    cc_build.compiler("clang");
    cc_build.file("shim_free.c");
    cc_build.file("shim_alloc.c");
    cc_build.file("shim_chain.c");
    cc_build.file("shim_clone.c");
    cc_build.file("shim_raw.c");
    cc_build.file("shim_ethdev.c");
    // PROFILE distinguishes dev/test from release while both keep the C shims at -O3.
    if env::var("PROFILE").as_deref() == Ok("debug") {
        cc_build.define("ZHIDA_ASSUME_CHECKED", None);
        let proof = PathBuf::from(env::var("OUT_DIR").unwrap()).join("assume_checked.c");
        std::fs::write(&proof, "#include \"shim_common.h\"\nint zhida_assume_checked(void) {\n#ifdef ZHIDA_ASSUME_CHECKED\nreturn 1;\n#else\nreturn 0;\n#endif\n}\n").unwrap();
        cc_build.include(env::var("CARGO_MANIFEST_DIR").unwrap());
        cc_build.file(proof);
    }
    cc_build.opt_level(3);
    // Same CPU baseline as DPDK's platform=generic build (docker/Dockerfile), so the
    // shims run on any CPU the DPDK libraries run on.
    match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => cc_build.flag("-march=corei7"),
        Ok("aarch64") => cc_build.flag("-march=armv8-a+crc"),
        arch => panic!("no DPDK generic CPU baseline for target arch {arch:?}"),
    };

    if env::var("PROFILE").as_deref() == Ok("release") {
        cc_build.flag("-flto=thin");
        cc_build.flag("-fvisibility=hidden");
    }

    for path in &lib.include_paths {
        cc_build.include(path);
    }
    cc_build.compile("zhida_dpdk_shim");

    // Generate bindings
    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .parse_callbacks(Box::new(MbufFlagsU64))
        .generate_comments(false)
        .allowlist_type("rte_mbuf")
        .allowlist_type("rte_mempool")
        .allowlist_type("rte_mempool_cache")
        .allowlist_type("rte_ring")
        .allowlist_function("rte_ring_create")
        .allowlist_function("rte_ring_free")
        .allowlist_function("rte_eth_from_rings")
        .allowlist_function("rte_eth_dev_configure")
        .allowlist_function("rte_eth_dev_info_get")
        .allowlist_function("rte_eth_macaddr_get")
        .allowlist_function("rte_eth_dev_conf_get")
        .allowlist_function("rte_eth_dev_is_valid_port")
        .allowlist_function("rte_eth_dev_adjust_nb_rx_tx_desc")
        .allowlist_function("rte_mempool_lookup")
        .allowlist_function("rte_eth_rx_queue_setup")
        .allowlist_function("rte_eth_rx_queue_info_get")
        .allowlist_type("rte_eth_rxq_info")
        .allowlist_function("rte_eth_tx_queue_setup")
        .allowlist_function("rte_eth_dev_start")
        .allowlist_function("rte_eth_dev_stop")
        .allowlist_function("rte_eth_dev_close")
        .allowlist_function("rte_eth_tx_done_cleanup")
        .allowlist_function("rte_vdev_init")
        .allowlist_function("rte_vdev_uninit")
        .allowlist_function("rte_eth_dev_get_port_by_name")
        .allowlist_function("rte_eth_link_get_nowait")
        .allowlist_type("rte_eth_link")
        .allowlist_function("rte_eth_stats_get")
        .allowlist_type("rte_eth_stats")
        .allowlist_var("RTE_ETH_LINK_UP")
        .allowlist_function("rte_eal_alarm_set")
        .allowlist_function("rte_eal_init")
        .allowlist_function("rte_eal_cleanup")
        .allowlist_function("rte_pktmbuf_pool_create")
        .allowlist_function("rte_pktmbuf_pool_create_by_ops")
        .allowlist_function("rte_mempool_free")
        .allowlist_function("rte_mempool_in_use_count")
        .allowlist_function("rte_socket_id")
        .allowlist_function("rte_lcore_id")
        .allowlist_function("rte_mempool_ops_enqueue_bulk")
        .allowlist_function("rte_mbuf_check")
        .allowlist_function("rte_mbuf_dyn_rx_timestamp_register")
        .allowlist_function("rte_mbuf_sanity_check")
        .allowlist_var("RTE_PKTMBUF_HEADROOM")
        .allowlist_var("RTE_MBUF_DEFAULT_BUF_SIZE")
        .allowlist_var("RTE_MAX_LCORE")
        .allowlist_var("RING_F_SP_ENQ")
        .allowlist_var("RING_F_SC_DEQ")
        .allowlist_var("EALREADY")
        .allowlist_var("EINVAL")
        .allowlist_var("ENOTSUP")
        .allowlist_var("RTE_MBUF_F_TX_(IPV4|TCP_CKSUM|UDP_CKSUM|TCP_SEG|IP_CKSUM)")
        .allowlist_var("RTE_MBUF_F_INDIRECT")
        .allowlist_var("RTE_MBUF_F_RX_IP_CKSUM_MASK")
        .allowlist_var("RTE_MBUF_F_RX_IP_CKSUM_GOOD")
        .allowlist_var("RTE_MBUF_F_RX_IP_CKSUM_BAD")
        .allowlist_var("RTE_MBUF_F_RX_L4_CKSUM_MASK")
        .allowlist_var("RTE_MBUF_F_RX_L4_CKSUM_GOOD")
        .allowlist_var("RTE_MBUF_F_RX_L4_CKSUM_BAD")
        .allowlist_var("RTE_MBUF_F_EXTERNAL");

    for path in &lib.include_paths {
        builder = builder.clang_arg(format!("-I{}", path.display()));
    }

    let bindings = builder.generate().expect("Failed to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Failed to write bindings");
}
