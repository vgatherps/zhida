use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn check_prints_summary_and_exit_codes() {
    let path = std::env::temp_dir().join(format!(
        "zhida-netconf-{}-{}.json",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let run = |args: &[&std::ffi::OsStr]| {
        Command::new(env!("CARGO_BIN_EXE_zhida-netconf"))
            .args(args)
            .output()
            .unwrap()
    };
    let check = std::ffi::OsStr::new("check");
    fs::write(
        &path,
        r#"{
        "version": 1, "device": {"vdev": "net_tap0,iface=cdnic0"}, "mac": null,
        "ipv4": "10.0.1.23/24", "gateway": null, "mtu": 9001,
        "paths": [{"prefix": "10.0.0.0/16", "mtu": 9001, "why": "vpc"},
                  {"prefix": "0.0.0.0/0", "mtu": 1500, "why": "default"}],
        "offloads": "auto", "rx_timestamps": false, "descriptors": 1024,
        "eal": {"file_prefix": "zhida", "extra": []}
    }"#,
    )
    .unwrap();
    let valid = run(&[check, path.as_os_str()]);
    let mut invalid_config: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    invalid_config["version"] = serde_json::json!(2);
    fs::write(&path, invalid_config.to_string()).unwrap();
    let invalid = run(&[check, path.as_os_str()]);
    fs::remove_file(&path).unwrap();
    let missing = run(&[check, path.as_os_str()]);
    assert_eq!(valid.status.code(), Some(0));
    assert!(valid.stderr.is_empty());
    let stdout = String::from_utf8(valid.stdout).unwrap();
    assert!(stdout.contains("ipv4: 10.0.1.23/24\n"));
    assert!(stdout.contains("  10.0.0.0/16 mtu 9001 (vpc)\n"));
    assert!(stdout.contains("  0.0.0.0/0 mtu 1500 (default)\n"));
    assert_eq!(invalid.status.code(), Some(1));
    let stderr = String::from_utf8(invalid.stderr).unwrap();
    assert_eq!(stderr.lines().count(), 1);
    assert!(stderr.contains("version"));
    assert!(stderr.starts_with(&format!("zhida-netconf: {}: ", path.display())));
    assert_eq!(missing.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(missing.stderr).unwrap().lines().count(),
        1
    );
    for args in [
        &[][..],
        &[std::ffi::OsStr::new("unknown")][..],
        &[check][..],
        &[check, path.as_os_str(), std::ffi::OsStr::new("extra")][..],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "usage: zhida-netconf check FILE | zhida-netconf discover --interface IF [--ipv4 ADDR] [--aws] [-o FILE] | zhida-netconf bind FILE [--noiommu] [--dry-run] | zhida-netconf unbind FILE\n"
        );
    }
}
