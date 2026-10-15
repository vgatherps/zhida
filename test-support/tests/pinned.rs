use zhida_test_support::{pinned_test, run, PINNED_TEST_BOUND};
use std::env;
use std::io::{self, Read};
use std::panic::{catch_unwind, resume_unwind};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, OnceLock};
use std::thread::{self, JoinHandle, ThreadId};
use std::time::{Duration, Instant};

fn assert_worker_identity() {
    static OWNER: OnceLock<ThreadId> = OnceLock::new();
    assert_eq!(
        *OWNER.get_or_init(|| thread::current().id()),
        thread::current().id()
    );
    assert_eq!(thread::current().name(), Some("zhida-test-worker"));
}

#[pinned_test]
fn first_test_uses_worker() {
    assert_worker_identity();
}

#[pinned_test]
fn second_test_uses_same_worker() {
    assert_worker_identity();
}

#[test]
fn parallel_submissions_serialize_and_return_values() {
    let barrier = Arc::new(Barrier::new(9));
    let active = Arc::new(AtomicUsize::new(0));
    let calls = (0..8)
        .map(|value| {
            let barrier = barrier.clone();
            let active = active.clone();
            thread::spawn(move || {
                barrier.wait();
                run("parallel submission", PINNED_TEST_BOUND, move || {
                    assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
                    let owner = thread::current().id();
                    thread::yield_now();
                    assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
                    (owner, value * 2)
                })
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let owner = run("parallel owner", PINNED_TEST_BOUND, || thread::current().id());
    for (value, call) in calls.into_iter().enumerate() {
        assert_eq!(call.join().unwrap(), (owner, value * 2));
    }
}

#[pinned_test(bound_ms = 200)]
#[ignore = "runs only as a child process of hung_pinned_tests_exit_naming_them"]
fn hung_body_child() {
    loop {
        thread::park();
    }
}

#[pinned_test(bound_ms = 200)]
#[ignore = "runs only as a child process of hung_pinned_tests_exit_naming_them"]
fn hung_holding_stderr_child() {
    let _stderr = io::stderr().lock();
    loop {
        thread::park();
    }
}

/// libc only: std's thread-locals may already be gone when atexit handlers run.
extern "C" fn block_forever() {
    loop {
        // SAFETY: pause has no preconditions.
        unsafe { libc::pause() };
    }
}

/// An atexit handler that never returns stands in for a C destructor blocked on
/// state the stuck body holds: the bound must end the process without running it.
/// Registered on the test thread before `run` starts the bound, so the bound cannot
/// expire before the handler exists.
#[test]
#[ignore = "runs only as a child process of hung_pinned_tests_exit_naming_them"]
fn hung_with_blocking_atexit_child() {
    // SAFETY: block_forever is an extern "C" fn that lives as long as the process.
    assert_eq!(unsafe { libc::atexit(block_forever) }, 0);
    run(
        concat!(module_path!(), "::hung_with_blocking_atexit_child"),
        Duration::from_millis(200),
        || loop {
            thread::park();
        },
    )
}

fn drain(mut pipe: impl Read + Send + 'static) -> JoinHandle<String> {
    thread::spawn(move || {
        let mut text = String::new();
        pipe.read_to_string(&mut text).unwrap();
        text
    })
}

/// Runs this test binary with `args`, with capture on and tests in name order; kills
/// it and fails if it runs past 30 s. Returns its exit status, stdout and stderr.
fn run_child(args: &[&str]) -> (ExitStatus, String, String) {
    let mut child = Command::new(env::current_exe().unwrap())
        .args(args)
        .env_remove("RUST_TEST_NOCAPTURE")
        .env_remove("RUST_TEST_SHUFFLE")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = drain(child.stdout.take().unwrap());
    let stderr = drain(child.stderr.take().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("child test process {args:?} still running after 30 s");
        }
        thread::sleep(Duration::from_millis(20));
    };
    (status, stdout.join().unwrap(), stderr.join().unwrap())
}

#[test]
fn hung_pinned_tests_exit_naming_them() {
    for name in [
        "hung_body_child",
        "hung_holding_stderr_child",
        "hung_with_blocking_atexit_child",
    ] {
        let (status, _, stderr) = run_child(&[name, "--exact", "--ignored"]);

        assert_eq!(status.code(), Some(1), "{name} stderr: {stderr}");
        assert!(
            stderr.contains(&format!(
                "pinned test `pinned::{name}` did not finish within 200ms"
            )),
            "{name} stderr: {stderr}"
        );
    }
}

#[pinned_test]
#[ignore = "runs only as a child process of failing_tests_report_message_and_location"]
fn failing_child_1_pinned() {
    panic!("first pinned failure on line {}", line!());
}

#[pinned_test]
#[ignore = "runs only as a child process of failing_tests_report_message_and_location"]
fn failing_child_2_pinned() {
    panic!("second pinned failure on line {}", line!());
}

#[test]
#[ignore = "runs only as a child process of failing_tests_report_message_and_location"]
fn failing_child_3_unpinned() {
    panic!("unpinned failure on line {}", line!());
}

fn panic_on_another_thread(message: &'static str) -> ! {
    let payload = thread::spawn(move || panic!("{message}"))
        .join()
        .unwrap_err();
    resume_unwind(payload)
}

#[pinned_test]
#[ignore = "runs only as a child process of failing_tests_report_message_and_location"]
fn failing_child_4_resumed_from_thread() {
    panic_on_another_thread("failure resumed from a spawned thread");
}

#[pinned_test]
#[ignore = "runs only as a child process of failing_tests_report_message_and_location"]
fn failing_child_5_caught_then_resumed() {
    let _ = catch_unwind(|| panic!("caught panic A"));
    panic_on_another_thread("real failure B");
}

fn failure_section<'a>(stdout: &'a str, test: &str) -> &'a str {
    stdout
        .split(&format!("---- {test} stdout ----\n"))
        .nth(1)
        .and_then(|rest| rest.split("\n---- ").next())
        .unwrap_or_else(|| panic!("no failure output for {test}:\n{stdout}"))
}

/// Asserts libtest printed `message` and the `file:line` of the panic under `test`.
fn assert_reported(stdout: &str, test: &str, message: &str) {
    let section = failure_section(stdout, test);
    let line: u32 = section
        .split_once(message)
        .and_then(|(_, rest)| rest.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|digits| digits.parse().ok())
        .unwrap_or_else(|| panic!("{test} output lacks `{message}`:\n{section}"));
    assert!(
        section.contains(&format!("panicked at {}:{line}:", file!())),
        "{test} output lacks its panic location:\n{section}"
    );
}

/// Asserts libtest printed `message`, marked as resumed from another thread, under `test`.
fn assert_resumed(stdout: &str, test: &str, message: &str) {
    let section = failure_section(stdout, test);
    assert!(
        section.contains(&format!(
            "pinned test resumed a panic raised on another thread (location not recorded):\n{message}\n"
        )),
        "{test} output lacks `{message}`:\n{section}"
    );
}

// Tests run in name order on one thread, so the first pinned test spawns the worker
// and the later tests run after the worker's panic hook is installed.
#[test]
fn failing_tests_report_message_and_location() {
    let (status, stdout, stderr) =
        run_child(&["failing_child_", "--ignored", "--test-threads=1"]);

    assert_eq!(status.code(), Some(101), "child stdout: {stdout}\nstderr: {stderr}");
    assert_reported(&stdout, "failing_child_1_pinned", "first pinned failure on line ");
    assert_reported(&stdout, "failing_child_2_pinned", "second pinned failure on line ");
    assert_reported(&stdout, "failing_child_3_unpinned", "unpinned failure on line ");
    assert_resumed(
        &stdout,
        "failing_child_4_resumed_from_thread",
        "failure resumed from a spawned thread",
    );
    assert_resumed(&stdout, "failing_child_5_caught_then_resumed", "real failure B");
    let caught = failure_section(&stdout, "failing_child_5_caught_then_resumed");
    assert!(!caught.contains("caught panic A"), "caught panic reported as the failure:\n{caught}");
}

#[pinned_test]
fn result_return_is_preserved() -> Result<(), &'static str> {
    assert_worker_identity();
    Ok(())
}

#[pinned_test]
#[should_panic(expected = "pinned panic")]
fn should_panic_is_preserved() {
    panic!("pinned panic");
}

#[pinned_test]
#[ignore = "must stay ignored: validates attribute forwarding"]
fn ignored_test_is_preserved() {
    panic!("ignored body must never run in the normal test suite");
}
