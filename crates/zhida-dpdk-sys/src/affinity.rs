//! The CPU EAL pins its main lcore to: the one CPU the caller may run on, so
//! the caller's CPU set (taskset -c N, docker --cpuset-cpus=N) chooses it.

use std::fmt;
use std::io;

/// Why `only_allowed_cpu` found no single CPU.
#[derive(Debug)]
pub enum AffinityError {
    /// sched_getaffinity failed.
    Query(io::Error),
    /// The calling thread may run on this many CPUs, not exactly one.
    NotOne { allowed: usize },
}

impl fmt::Display for AffinityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Query(error) => write!(f, "sched_getaffinity: {error}"),
            Self::NotOne { allowed } => write!(
                f,
                "the calling thread may run on {allowed} CPUs, not exactly one; \
                 restrict it to the CPU for EAL (taskset -c N, docker --cpuset-cpus=N)"
            ),
        }
    }
}

impl std::error::Error for AffinityError {}

/// The one CPU the calling thread may run on, for EAL's `--lcores=<id>@<cpu>`.
pub fn only_allowed_cpu() -> Result<usize, AffinityError> {
    // SAFETY: cpu_set_t is plain data; all-zero bytes are the empty set.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is writable and its size is passed; pid 0 is this thread.
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&set), &mut set) } != 0 {
        return Err(AffinityError::Query(io::Error::last_os_error()));
    }
    single_cpu(&set)
}

fn single_cpu(set: &libc::cpu_set_t) -> Result<usize, AffinityError> {
    // SAFETY: CPU_COUNT and CPU_ISSET only read `set`; every index is below
    // CPU_SETSIZE.
    let allowed = unsafe { libc::CPU_COUNT(set) } as usize;
    if allowed != 1 {
        return Err(AffinityError::NotOne { allowed });
    }
    Ok((0..libc::CPU_SETSIZE as usize)
        .find(|&cpu| unsafe { libc::CPU_ISSET(cpu, set) })
        .expect("CPU_COUNT counted one CPU"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_of(cpus: &[usize]) -> libc::cpu_set_t {
        // SAFETY: all-zero bytes are the empty set; every CPU is below CPU_SETSIZE.
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        for &cpu in cpus {
            unsafe { libc::CPU_SET(cpu, &mut set) };
        }
        set
    }

    #[test]
    fn single_cpu_requires_exactly_one() {
        assert_eq!(single_cpu(&set_of(&[3])).unwrap(), 3);
        assert_eq!(single_cpu(&set_of(&[0])).unwrap(), 0);
        for (cpus, count) in [(&[][..], 0), (&[1, 5], 2)] {
            match single_cpu(&set_of(cpus)) {
                Err(AffinityError::NotOne { allowed }) => assert_eq!(allowed, count),
                other => panic!("{cpus:?}: {other:?}"),
            }
        }
    }

    /// Run under a one-CPU set (as `make test` in Docker is): the thread runs
    /// on the CPU the helper reports.
    #[test]
    fn only_allowed_cpu_is_where_this_thread_runs() {
        let cpu = only_allowed_cpu().unwrap();
        // SAFETY: plain syscall wrapper.
        assert_eq!(unsafe { libc::sched_getcpu() }, cpu as i32);
    }
}
