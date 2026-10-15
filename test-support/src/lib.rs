use std::any::Any;
use std::backtrace::Backtrace;
use std::cell::{Cell, RefCell};
use std::env;
use std::fs::File;
use std::io::Write;
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;
use std::panic::{self, catch_unwind, resume_unwind, AssertUnwindSafe};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

pub use zhida_test_support_macros::pinned_test;

type Job = Box<dyn FnOnce() + Send>;

/// The last panic the hook saw on the worker during the current job.
struct RecordedPanic {
    /// `None` for a payload that is not a string.
    message: Option<String>,
    report: String,
}

type WorkerPanic = (Box<dyn Any + Send>, Option<RecordedPanic>);

thread_local! {
    static ON_WORKER: Cell<bool> = const { Cell::new(false) };
    static LAST_WORKER_PANIC: RefCell<Option<RecordedPanic>> = const { RefCell::new(None) };
}

/// The worker inherits the output capture of the libtest thread that spawned it, so
/// the default hook would print a worker panic into that first test's output. Record
/// it instead; `run` prints it on the calling test thread. Other threads are unchanged.
fn record_worker_panics() {
    let previous = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        if !ON_WORKER.get() {
            return previous(info);
        }
        let message = info.payload_as_str();
        let text = message.unwrap_or("Box<dyn Any>");
        let mut report = match info.location() {
            Some(location) => {
                format!("thread 'zhida-test-worker' panicked at {location}:\n{text}\n")
            }
            None => format!("thread 'zhida-test-worker' panicked:\n{text}\n"),
        };
        // Same switch as the default hook: RUST_BACKTRACE unset or 0 prints none.
        match env::var("RUST_BACKTRACE").as_deref() {
            Err(_) | Ok("0") => {}
            Ok("full") => {
                report.push_str(&format!("stack backtrace:\n{:#}\n", Backtrace::force_capture()))
            }
            Ok(_) => {
                report.push_str(&format!("stack backtrace:\n{}\n", Backtrace::force_capture()))
            }
        }
        LAST_WORKER_PANIC.set(Some(RecordedPanic {
            message: message.map(str::to_owned),
            report,
        }));
    }));
}

fn payload_message(payload: &(dyn Any + Send)) -> Option<&str> {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
}

fn worker() -> &'static SyncSender<Job> {
    static WORKER: OnceLock<SyncSender<Job>> = OnceLock::new();

    WORKER.get_or_init(|| {
        record_worker_panics();
        let (tx, rx): (SyncSender<Job>, Receiver<Job>) = sync_channel(0);
        thread::Builder::new()
            .name("zhida-test-worker".to_string())
            .spawn(move || {
                ON_WORKER.set(true);
                for job in rx {
                    job();
                }
            })
            .expect("failed to spawn zhida test worker");
        tx
    })
}

/// Longest a `#[pinned_test]` body may run. It must exceed every deadline a test body
/// sets for itself plus that test's setup and teardown, and stay under the Makefile's
/// TEST_TIMEOUT (600 s). The longest in-body deadlines are 60 s (tap-echo kernel_interop
/// ACK_LOSS_DEADLINE; two 30 s serve_client runs in failed_run_cleans_up_for_the_next).
/// The slowest passing body took 3.5 s (2026-10-08, Docker, one CPU).
pub const PINNED_TEST_BOUND: Duration = Duration::from_secs(180);

/// Runs `f` on the pinned worker and returns its result. A panic in `f` prints into this
/// test's output and resumes with the original payload: the worker's report (message and
/// location) when it describes that payload, otherwise only the payload's message, as for
/// a panic raised on another thread and resumed by `f`.
/// If `f` runs longer than `bound`, prints `test_name` and ends the process with
/// `_exit(1)`: the worker is still running `f`, so no later pinned test could run.
/// `_exit` runs no atexit handlers or C destructors (DPDK's among them), which could
/// block on state the stuck worker holds. It also skips std's stdout flush, so
/// libtest's partial `test <name> ... ` line can be lost; the message names the test.
/// Known limit: the message write blocks if stderr is a pipe whose reader stopped and
/// whose buffer is full, so `_exit` is not reached; the Makefile's `timeout` around
/// each test step still ends the process.
pub fn run<R, F>(test_name: &str, bound: Duration, f: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let (done_tx, done_rx) = sync_channel::<Result<R, WorkerPanic>>(0);
    let job: Job = Box::new(move || {
        let result = catch_unwind(AssertUnwindSafe(f));
        let recorded = LAST_WORKER_PANIC.take();
        let _ = done_tx.send(result.map_err(|payload| (payload, recorded)));
    });

    worker()
        .send(job)
        .expect("zhida test worker has stopped");
    match done_rx.recv_timeout(bound) {
        Ok(Ok(value)) => value,
        Ok(Err((payload, recorded))) => {
            let message = payload_message(&*payload);
            match recorded {
                Some(recorded) if recorded.message.as_deref() == message => {
                    eprint!("{}", recorded.report)
                }
                _ => eprint!(
                    "pinned test resumed a panic raised on another thread (location not recorded):\n{}\n",
                    message.unwrap_or("Box<dyn Any>")
                ),
            }
            resume_unwind(payload)
        }
        Err(RecvTimeoutError::Timeout) => {
            let message = format!(
                "pinned test `{test_name}` did not finish within {bound:?}; exiting the test process\n"
            );
            // Raw fd 2: libtest captures eprintln!, and the stuck worker may hold std's
            // stderr lock. A failed write is ignored; a blocked one is the limit above.
            // SAFETY: fd 2 stays open for the process; ManuallyDrop never closes it.
            let mut stderr = ManuallyDrop::new(unsafe { File::from_raw_fd(2) });
            let _ = stderr.write_all(message.as_bytes());
            // SAFETY: _exit ends the process at once; nothing after it runs.
            unsafe { libc::_exit(1) }
        }
        Err(RecvTimeoutError::Disconnected) => {
            panic!("zhida test worker dropped a job without a result")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{run, PINNED_TEST_BOUND};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::thread;

    fn on_worker<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> R {
        run("unit test", PINNED_TEST_BOUND, f)
    }

    #[test]
    fn calls_share_one_worker_thread() {
        let first = on_worker(|| thread::current().id());
        let second = on_worker(|| thread::current().id());

        assert_eq!(first, second);
        assert_ne!(first, thread::current().id());
    }

    #[test]
    fn panic_reaches_the_caller() {
        let panic = catch_unwind(AssertUnwindSafe(|| on_worker(|| panic!("worker panic"))))
            .expect_err("worker panic must reach the caller");
        let message = panic
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic.downcast_ref::<String>().map(String::as_str));

        assert_eq!(message, Some("worker panic"));
    }

    #[test]
    fn worker_survives_a_panic() {
        let before = on_worker(|| thread::current().id());
        let _ = catch_unwind(AssertUnwindSafe(|| on_worker(|| panic!("worker panic"))));
        let after = on_worker(|| thread::current().id());

        assert_eq!(before, after);
    }
}
