use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn discover_cli_usage_and_existing_output() {
    let path = std::env::temp_dir().join(format!(
        "netconf-cli-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    struct File(std::path::PathBuf);
    impl Drop for File {
        fn drop(&mut self) {
            fs::remove_file(&self.0).unwrap();
        }
    }
    fs::write(&path, "keep this file\n").unwrap();
    let _guard = File(path.clone());
    let run = |args: &[&std::ffi::OsStr]| {
        Command::new(env!("CARGO_BIN_EXE_zhida-netconf"))
            .args(args)
            .output()
            .unwrap()
    };
    let discover = std::ffi::OsStr::new("discover");
    let flag = std::ffi::OsStr::new("--interface");
    let interface = std::ffi::OsStr::new("zhida-interface-cannot-exist");
    for args in [
        vec![discover],
        vec![discover, flag],
        vec![discover, flag, interface, flag, interface],
        vec![
            discover,
            flag,
            interface,
            std::ffi::OsStr::new("--aws"),
            std::ffi::OsStr::new("--aws"),
        ],
        vec![
            discover,
            flag,
            interface,
            std::ffi::OsStr::new("--unknown"),
            interface,
        ],
        vec![discover, flag, interface, std::ffi::OsStr::new("--ipv4")],
        vec![
            discover,
            flag,
            interface,
            std::ffi::OsStr::new("--ipv4"),
            std::ffi::OsStr::new("bad"),
        ],
        vec![
            discover,
            flag,
            interface,
            std::ffi::OsStr::new("--ipv4"),
            std::ffi::OsStr::new("10.0.1.23"),
            std::ffi::OsStr::new("--ipv4"),
            std::ffi::OsStr::new("10.0.1.24"),
        ],
        vec![
            discover,
            flag,
            interface,
            std::ffi::OsStr::new("-o"),
            path.as_os_str(),
            std::ffi::OsStr::new("-o"),
            path.as_os_str(),
        ],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2));
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(stderr.lines().count(), 1);
        assert!(stderr.contains("check FILE") && stderr.contains("discover --interface"));
        assert!(output.stdout.is_empty());
    }
    for args in [
        vec![
            discover,
            flag,
            interface,
            std::ffi::OsStr::new("-o"),
            path.as_os_str(),
        ],
        vec![
            discover,
            std::ffi::OsStr::new("-o"),
            path.as_os_str(),
            flag,
            interface,
        ],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(stderr.lines().count(), 1);
        assert!(stderr.contains("expected value"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "keep this file\n");
        assert!(output.stdout.is_empty());
    }
    let output = run(&[discover, flag, interface, std::ffi::OsStr::new("--aws")]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "zhida-netconf: interface zhida-interface-cannot-exist does not exist\n"
    );
    assert!(output.stdout.is_empty());
}
