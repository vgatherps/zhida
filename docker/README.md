# Linux DPDK tests

From the Zhida root with Docker running:

```sh
make docker-image
make docker-doctor
make docker-build
make docker-test
make docker-fuzz
make docker-bench
make docker-memif-bench
make docker-bench-stack
make docker-binance   # live Binance example, needs internet (section below)
```

## Image

The image uses the native host architecture by default, Rust 1.93.0 and Ubuntu 24.04, with both
base image digests pinned. It builds checksum-pinned upstream DPDK 25.11.3 from source, because
Ubuntu's 23.11 package has a different mbuf field structure that these Rust accessors do not
compile against. Cargo.lock pins Rust dependencies; system build tools come from the Ubuntu
repositories unpinned.

`DOCKER_PLATFORM=linux/amd64` builds the same Dockerfile for x86-64 through `docker buildx build
--load`, with default tag `zhida-dpdk-test:linux-amd64` and target volume
`zhida-linux-target-linux-amd64`, leaving the native `:local` image and its cache alone. Every
target that uses `DOCKER_IMAGE` then runs the amd64 image (emulated on an arm64 host):

```sh
make docker-image DOCKER_PLATFORM=linux/amd64
make docker-build DOCKER_PLATFORM=linux/amd64
```

Emulation can violate wall-clock test bounds; use native x86-64 for the gate.
Packetdrill defaults to 25 ms, with stricter per-script overrides.

DPDK is configured with `platform=generic`, `enable_stdatomic=false`, `mbuf_refcnt_atomic=false`
and `enable_iova_as_pa=true`. It builds the ring, PCAP, TAP, memif and af_packet network PMDs
(af_packet for its kernel RX timestamps), plus net/ena and net/intel/{ixgbe,i40e,ice} for the
real-NIC runner `zhida-nic` (runbook: crates/nic-runner/README.md). No test uses those four. mlx5
is not built (it needs rdma-core). DPDK's own app/test targets are disabled. The image also
installs sockperf 3.10 (checksum-pinned source build, `/opt/sockperf/bin/sockperf`) as the kernel
client of `make test-nic-runner`.

The image patches pinned packetdrill 83f72d3 with `docker/packetdrill-relearn-isn.patch`: each new
passive handshake learns its server ISN only when its live SYN-ACK acknowledges the new SYN's live
sequence plus one. SYN-ACK retransmissions within the earlier handshake reuse its learned ISN,
including after a stray SYN.

Docker builds with context `docker/` (only docker/Dockerfile is used). `make docker-doctor`
prints versions.

## Containers and CPUs

Containers mount the project at /work. Registry downloads and Linux artifacts persist in the
zhida-cargo-registry and zhida-linux-target named volumes; the target volume hides macOS
artifacts. Concurrent runs from separate worktrees need distinct targets, e.g.
`make DOCKER_TARGET_VOLUME=zhida-target-rxtx docker-test`.

Tests use the real EAL/pool setup with no PCI or huge pages. Containers are not privileged and
publish no ports or host networking. Every container the Makefile runs adds only `--cap-add
NET_ADMIN --device /dev/net/tun`; CAP_NET_RAW comes from Docker's default capability set.

Except for the memif and stack benchmarks, containers run on the one CPU `DOCKER_CPUSET` names
(default 0, passed as `--cpuset-cpus`). The `make docker-test` and `make docker-known-bugs`
containers also get `PACKETDRILL_CPUSET` (default 2) and `PACKETDRILL_ZHIDA_CPUSET` (default 7)
and run make under `taskset -c DOCKER_CPUSET`, so everything except the packetdrill runs has one
CPU. Every EAL argv (tests, benches, the tap-echo driver) pins its main lcore to the one CPU the
process may run on, read with sched_getaffinity (`zhida_dpdk_sys::only_allowed_cpu`), and fails
with the count if more than one is allowed.

Example: `make DOCKER_CPUSET=1 AUTOBAHN_CPUSET=2 PACKETDRILL_CPUSET=3 PACKETDRILL_ZHIDA_CPUSET=8
docker-test` runs everything on CPU 1 except the Autobahn peer and the packetdrill runs.
`AUTOBAHN_CPUSET` must differ from `DOCKER_CPUSET`; `DOCKER_CPUSET`, `PACKETDRILL_CPUSET` and
`PACKETDRILL_ZHIDA_CPUSET` must all differ.

| CPU | Default use |
| --- | --- |
| 0 | gates (`DOCKER_CPUSET`) |
| 1 | Autobahn peer (`AUTOBAHN_CPUSET`) |
| 2 | packetdrill (`PACKETDRILL_CPUSET`) |
| 3-6 | benches |
| 7 | packetdrill's tap-echo (`PACKETDRILL_ZHIDA_CPUSET`) |
| 8 | `make docker-soak` (`SOAK_CPUSET`) |

With these defaults Docker's VM needs at least 8 CPUs (9 for `make docker-soak`). In Docker
Desktop that is Settings, Resources, CPU limit. The `memif-bench` binary takes explicit CPUs
(`--cpu`, `--peer-cpu`, `--client-cpu`, `--control-cpu`); its tests pass the test's one CPU for
all of them.

`DOCKER_RUN` containers run with `--init`: tini is PID 1 and forwards signals (`docker kill`, or
the `docker run` client's signal proxy) to the command. Without it make is PID 1, and the kernel
drops the TERM make re-raises on itself, so a SIGTERM mid-step can leave make alive. The whole
in-container `make test` runs under `timeout --kill-after=10 $(MAKE_TEST_TIMEOUT)` (default
3600 s), so a stuck make exits 124 (137 after the KILL grace) and `docker-test` reports it.

## Stack configuration in the drivers

The shared driver for tap-echo, ws-autobahn and binance-feed sizes DPDK memory from its RX and TX
pool counts: `-m` requests `64 + ceil((rx_count + tx_count) * 4096 / 1048576)` MB. The RX pool
grows with sockets × receive buffer through `rx_pool_count`. ws-autobahn keeps every case's
socket, so memory grows with the Autobahn case count: 91 RX mbufs per case at 128 KiB, about
250 MB for 517 cases (249 MB server, 250 MB client).

tap-echo, ws-autobahn, binance-feed and memif-bench read `StackConfig.random_seed` from
`/dev/urandom` on each run. Tests and library benches use fixed seeds. memif-bench has no seed
override, so its traffic choices vary between runs.

TCP ISNs follow [RFC 6528 section 3](https://www.rfc-editor.org/rfc/rfc6528#section-3):
SipHash-2-4 over the local address/port and remote address/port, plus the interface clock
(`cx.now().total_micros() / 4`), wrapping at 32 bits. Each interface draws its 128-bit hash key
once from its seeded PRNG. The tick is the RFC's 4 µs;
[Linux v6.12](https://github.com/torvalds/linux/blob/v6.12/net/core/secure_seq.c) uses 64 ns.
Scapy learns each server ISN from its SYN-ACK; `FUZZ_SEED` reproduces the client's plan, while
Zhida's ISNs vary.

## DPDK net_memif workarounds

DPDK is built unmodified. Zhida works around these DPDK 25.11.3 net_memif behaviors:

- `eth_memif_tx` (copy-mode TX) reads `bufs[0]->pool` even for an empty burst. `Port::tx_burst`
  returns 0 without calling the PMD when nothing is pending.
- An idle Port therefore never calls TX burst, so `Port::alloc_tx` on an exhausted TX pool calls
  `rte_eth_tx_done_cleanup` once and retries, letting a NIC PMD that reclaims sent buffers only
  inside TX burst return them. `-ENOTSUP` means no allocation. memif and net_ring hold nothing
  after send, but some NIC PMDs answer `-ENOTSUP` while holding sent buffers (25.11.3 ixgbe
  vector TX), so a TX pool such a NIC can hold entirely may stall. Pool size is not checked.
- `memif_socket_remove_device` never closes a listening socket's fd or unregisters its interrupt
  callback when the last device on it closes, so the name stays bound and a new server on it in
  the same process fails. The memif tests take a new abstract socket name (pid + counter) for
  every pair, and the bench opens one vdev per process.
- Copy-mode RX (`eth_memif_rx`) allocates 32 mbufs in bulk on every call that finds a frame
  waiting, copies what arrived and frees the rest, and returns nothing if 32 are not free. The
  bench's RX pools are sized for it, and its cost is part of every memif number.

Two DPDK gaps are unreachable with one client per server. A connection accepted but not assigned
to a device keeps its own callback after the last device leaves, so its INIT message reads the
freed socket (memif_socket.c:839-889, 206). A failed vdev probe, e.g. a duplicate id and role on
one socket, leaks the ethdev it allocated (rte_eth_memif.c:1699-1729).

## `make test`

`make test` runs the test-support, sys, buffer, property and EAL/integration suites in order,
then the suites below. Make serializes targets even with -j and propagates failures; run
separate Make invocations sequentially too. Each `cargo test` step runs under
`timeout --kill-after=10 $(TEST_TIMEOUT)` (default 600 s; `make docker-test` passes it into the
container), so a hung test fails the step with 124 (137 if it ignores TERM). Cargo commands use
--locked. The property invocation runs only the `props` test target, the one target its
`proptest` feature adds. Two documentation examples are marked ignored. `docker-test` runs
`test-stack-release` after `test-stack`, testing dpdk-smoltcp and stack-stream in release.

### Pinned tests

DPDK test bodies use `#[zhida_test_support::pinned_test]` to queue work onto one persistent OS
thread per test executable. EAL initializes on that worker, and packet owners stay there.
Results and panics return to libtest with the original payload. For a panic raised on the
worker, that test's output shows its message and location (and a backtrace under
RUST_BACKTRACE); for a panic raised on a thread the body spawned and re-raised with
`resume_unwind`, it shows the message only.

A pinned test body that runs longer than `PINNED_TEST_BOUND` (180 s) prints its full name
(`<crate>::<module path>::<fn name>`) and the bound to stderr (raw fd 2) and ends the test
process with `_exit(1)`, because the stuck worker owns EAL. `_exit` runs no atexit handlers or C
destructors (DPDK's included), which could block on what the worker holds. It also skips std's
stdout flush, so libtest's partial `test <name> ... ` line can be lost. The bound must exceed
every deadline a test body sets for itself plus its setup and teardown (the longest is 60 s in
tap-echo `kernel_interop`), and stay under `TEST_TIMEOUT`.

Explicit EAL startup and error cases each use a separate single-test process. Test support has
intentionally ignored bodies: a panic that verifies the macro preserves `#[ignore]`, and three
hung bodies (one with an atexit handler that never returns) and five failing bodies that
`hung_pinned_tests_exit_naming_them` and `failing_tests_report_message_and_location` run as
child processes.

### tap and af_packet tests

The dpdk-smoltcp `tap_port` test runs a net_tap Port exchanging frames with an AF_PACKET socket
on the kernel side of the tap netdev. It creates and deletes `cdtap_*` netdevs in the network
namespace of the process running it: the container's own namespace under `make docker-test`,
the caller's (the host's, unless the caller arranged otherwise) under native `make test` or
`make test-stack`. Native runs of those targets need root or CAP_NET_ADMIN+CAP_NET_RAW, and
/dev/net/tun.

The dpdk-smoltcp `af_packet_timestamps` test opens a net_af_packet Port with
`Offloads::rx_timestamp` on one end of a veth pair (`cdafp<pid>a`, peer `cdafp<pid>b` with
198.19.x.y/30, both deleted at the end), sends five complete UDP frames from an AF_PACKET socket
on the peer, and checks that every datagram reaches the Zhida UDP socket with a nonzero kernel
receive time in ns that lies between two CLOCK_REALTIME reads around the sends and never
decreases. Native runs need root or CAP_NET_ADMIN+CAP_NET_RAW.

### tap-echo (`make test-echo`)

`make test-echo` runs the echo server between two Stacks and the `kernel_interop` checks, where a
Linux kernel TCP client echoes 1 MiB through a net_tap Port and closes cleanly, or aborts with an
RST, while an AF_PACKET capture records how the connection closed. It passes `--show-output`, so
the TCP options Linux negotiated with Zhida appear in its output. These checks set 192.0.2.1/24
on their `cdtap_kern` test netdev: in the container's namespace under `make docker-test`, the
caller's under native runs. Native `make test` and `make test-echo` need root or
CAP_NET_ADMIN+CAP_NET_RAW, and /dev/net/tun. The pure-ACK and data-segment loss checks run `tc`
(iproute2, in the image) to add and remove drop filters on the qdiscs of their `cdtap_kern`
netdev. The gateway checks run `ip` to add 198.51.100.1/32 to that netdev, outside Zhida's /24,
so Zhida reaches it only through its gateway 192.0.2.1; the address goes away with the netdev.

The `tap-echo` binary (`tap-echo [--listeners N] -- <tester> [args...]`, N default 1) runs
Zhida's echo server on port 8080 at 192.0.2.2/24 (MAC 02:00:00:00:00:01) over the net_tap netdev
`cdtap_echo` until its one tester command exits. With bad arguments it prints the full fixed
configuration. The tester starts before DPDK and must wait for `cdtap_echo` to be up itself. Its
environment adds `ZHIDA_IFACE`, `ZHIDA_MAC`, `ZHIDA_IP`, `TESTER_MAC` (02:00:00:00:00:02),
`TESTER_IP` (192.0.2.1) and `ECHO_PORT`.

| Exit | Meaning |
| --- | --- |
| 0 | tester exited 0 |
| 1 | tester exited nonzero or was killed by a signal |
| 2 | packet buffers in use at port close |
| 3 | bad arguments, or a setup, serve or teardown error |
| 101 | panic (the tester is killed) |

2 and 3 take precedence over the tester's status. Diagnostics on stderr are best effort and
never change the exit status. The binary has no timeout; wrap it in `timeout --kill-after=N`.
It kills only its direct child, so a tester must run directly or `exec` its final command (no
`sh -c` wrapper without `exec`) and must exit on SIGTERM, and `timeout` must run without
`--foreground` so expiry signals its whole process group, tester included. GNU timeout stops
waiting once it reaps tap-echo, so its `--kill-after` SIGKILL bounds a tester that ignores
SIGTERM only while tap-echo is alive. Its tests (`tests/driver.rs`, part of `make test-echo`)
need root or CAP_NET_ADMIN, and /dev/net/tun; each runs tap-echo in its own process group and
SIGKILLs that group when its 20 s deadline expires.

### NIC runner (`make test-nic-runner`)

`make test-nic-runner` runs crates/nic-runner/tests/run.sh: the sockperf-wire and `zhida-nic`
unit tests and the `sockperf_merge.py` self-test, then, for net_tap (`cdnic0`) and for
net_af_packet on a veth pair (`vethc0`/`vethc1`, deleted at the end), `zhida-nic info` and
`zhida-nic sockperf-server` at 192.0.2.2/24 with two TCP slots against kernel sockperf 3.10
clients at 192.0.2.1: UDP and TCP ping-pong (`--data-integrity`), under-load (its `--full-log`
is read back by `sockperf_merge.py`), a 1472-byte UDP ping-pong, and two concurrent UDP plus two
concurrent TCP under-load clients. net_tap also runs a UDP-only server.

It passes when every client reports zero dropped, duplicated and out-of-order messages, the
server exits 0 after SIGTERM with zero malformed messages and 4 TCP connections accepted and
closed, and, over af_packet (`--rx-timestamps`), every UDP datagram and TCP segment carries a
kernel receive stamp with no decreases. The af_packet part turns TX checksum offload off on
`vethc1` (`ethtool`, in the image); with it on, kernel frames cross the veth with unfinished
UDP/TCP checksums and Zhida drops them as bad. The script needs root or
CAP_NET_ADMIN+CAP_NET_RAW and /dev/net/tun, and runs every process on `DOCKER_CPUSET`.

### packetdrill (`make test-packetdrill`)

`make test-packetdrill` builds `tap-echo`, compiles `fuzz/packetdrill/zhida_shim.c` into
`target/fuzz/zhida_shim.so` (`make packetdrill-build`) and runs `fuzz/packetdrill/run.sh` with
`ZHIDA_CPU=PACKETDRILL_ZHIDA_CPUSET` and `PACKETDRILL_CPU=PACKETDRILL_CPUSET`. Each script runs as
`taskset -c ZHIDA_CPU tap-echo ... -- taskset -c PACKETDRILL_CPU packetdrill ...`, both off CPU 0
where every gate's builds and tests run, so the scripts' timing checks see neither Zhida nor
packetdrill wait for a CPU. The shim fails the run unless packetdrill may run only on
`PACKETDRILL_CPU`.

While the scripts run, a SCHED_IDLE busy loop on each of the two CPUs keeps them awake. In the
Docker Desktop VM a process sleeping on an idle vCPU wakes up to 10 ms late, past the scripts'
4 ms tolerance. SCHED_IDLE yields only to processes of its own container, where a waking
tap-echo or packetdrill preempts the loop at once. Another container's loop on the same CPU
competes as an equal, so `make test-packetdrill` and `make known-bugs` run under the packetdrill
lock (`fuzz/packetdrill/locked.sh`): flock(2) on the file `PACKETDRILL_LOCK`. In Docker that is
`/packetdrill-lock/run.lock` on the named volume `PACKETDRILL_LOCK_VOLUME` (default
`zhida-packetdrill-lock`), which every `DOCKER_MAKE_TEST` container mounts, so one packetdrill
run at a time holds the packetdrill CPUs across all worktrees. Natively it is
`/tmp/zhida-packetdrill.lock`. Every process of the run (tap-echo, packetdrill, the busy loops)
inherits the locked descriptor, and the kernel releases the lock when the last of them exits: a
cancelled run holds it until its last process is gone, and a killed run leaves no stale lock. A
held lock is waited for (the suite takes about 65 s), up to `PACKETDRILL_LOCK_TIMEOUT` (default
600 s, forwarded into the container); then the run fails naming the lock and its holder
(container hostname = container ID, pid, start time). Direct `run.sh` calls take no lock.

`fuzz/packetdrill/lock-self-test.sh` (first in `make test-packetdrill`) checks that two
concurrent holders serialize, the timeout failure, status pass-through, and that a SIGKILLed
holder's surviving child keeps the lock until it exits. `fuzz/packetdrill/cpu-self-test.sh`
(last) checks the CPU checks' failure paths: run.sh refuses equal or non-numeric CPUs, and the
shim fails a packetdrill left on tap-echo's CPU. Timing results are valid only while no
benchmark or other heavy container saturates the host; otherwise the whole Docker VM stalls
(packetdrill 70-100 ms late on its own CPU) and scripts fail on a correct Zhida.

The image builds packetdrill from a checksum-pinned upstream commit
(`/opt/packetdrill/bin/packetdrill`, on PATH). Each script runs in a fresh `tap-echo` process
with packetdrill as its tester, in shared-object mode. Before the script starts, the shim ARPs
for Zhida's 192.0.2.2 until Zhida replies (10 s bound), which fills Zhida's neighbor cache so its
first SYN-ACK does not wait on ARP. It then writes each scripted packet as an Ethernet frame to
an AF_PACKET socket on `cdtap_echo`, answers any ARP request from Zhida for 192.0.2.1 (a
malformed ARP frame from Zhida fails the run), and hands Zhida's IPv4 frames back to packetdrill
stamped with the kernel's receive time, so every packet crosses net_tap, the Port and smoltcp,
and timing checks see when it arrived.

Scripts are packet-only: the runner refuses files containing a backquote, `%{`, `/*` or `=`, and
lines other than blanks, `//` comments and one TCP packet event each; the shim aborts on any
syscall. They passively open port 8080 on one socket by default. A script may carry one
`// tap-echo: <flags>` line with only `--listeners N` (positive integer, default 1),
`--buffer N` (each connection's RX and TX buffer, default 128 KiB) and `--close-after N` (Zhida
echoes N bytes per connection, then sends FIN and discards later data), passed to `tap-echo`
before `--`. Another flag or a second such line refuses the script unrun.

The TCP behavior the scripts check: TCP demux selects an accepting exact tuple before any
listener; among listeners the lowest accepting socket slot wins. SYNs on Established
connections get challenge ACKs; duplicate SYNs in SynReceived resend the original SYN-ACK
immediately. Zhida does not negotiate or emit TCP timestamps and performs no PAWS checks.
A TIME-WAIT SYN or SYN+FIN without ACK reopens when SEG.SEQ is after RCV.NXT and an
accepting listener exists. The old socket closes and the listener answers SYN-ACK.
Without a listener, that SYN keeps TIME-WAIT and gets an ACK without rate limiting.
Other TIME-WAIT SYNs get a rate-limited challenge ACK and restart the timer only when
ACK is set. An empty segment without SYN/RST/FIN at RCV.NXT silently restarts the timer,
regardless of ACK. Other non-RST, non-SYN segments restart it only when ACK is set and
receive ACKs: non-SYN data and FIN bypass the 500 ms limit; empty replies use it.
The three reopening scripts set `--listeners 2`, including `syn-in-time-wait-reopen.pkt`;
the single-socket
`syn-in-time-wait.pkt` checks ACK, peer RST, then successful retry. tap-echo relistens only
Closed sockets.

`scripts/*.pkt` must exit 0. Each `selftest/*.pkt` declares `// expect-refused: <text>` (refused
unrun, reason containing the text) or `// expect-error: <text>` (exit exactly 1, output
containing the text). Each run is bounded by `timeout --kill-after=5 $PACKETDRILL_TIMEOUT`
(default 60 s) without `--foreground`; expiry fails the script, since packetdrill's
shared-object mode waits forever for a packet that never comes. The runner prints one line per
script and packetdrill's output for wrong results, and exits nonzero if any result is wrong.

To run chosen scripts, pass them to the runner after `make packetdrill-build`, e.g. inside a
container started with the Makefile's `DOCKER_ACCESS` flags and `--cpuset-cpus=0,2,7` (as
`DOCKER_MAKE_TEST`):
`ZHIDA_CPU=7 PACKETDRILL_CPU=2 taskset -c 0 fuzz/packetdrill/run.sh fuzz/packetdrill/scripts/echo-and-close.pkt`.

Native `make test` pins packetdrill's tap-echo to `PACKETDRILL_ZHIDA_CPUSET` and packetdrill to
`PACKETDRILL_CPUSET` (defaults 7 and 2): run it as `taskset -c D make test DOCKER_CPUSET=D
PACKETDRILL_CPUSET=P PACKETDRILL_ZHIDA_CPUSET=C` with three CPUs you may use. Native
`make test-packetdrill` needs packetdrill on PATH, its header in /opt/packetdrill/include, root
or CAP_NET_ADMIN+CAP_NET_RAW, and /dev/net/tun.

### Known bugs (`make docker-known-bugs`)

`known-bugs/*.pkt` are repros of Zhida bugs that fail while the bug exists and are in no gate;
see `fuzz/packetdrill/README.md`. `make docker-known-bugs` (native: `make known-bugs`) runs
every repro listed in `fuzz/known-bugs.txt` (those scripts, the `#[ignore]`d Rust tests of known
bugs and the Scapy replay below), each alone by its exact selector, past failures. Each of those
scripts gets `KNOWN_BUGS_PKT_TIMEOUT` seconds (default 15), every other repro `TEST_TIMEOUT`.
The per-repro outer timeout starts after acquiring the packetdrill lock; a lock-wait expiry is
`INFRA`. Scripts that run until timeout add their count × 15 s to the runtime, excluding setup
and lock waits.

It prints one line per repro:

| Line | Meaning |
| --- | --- |
| `FAIL` | with the first failure location; the bug reproduces |
| `UNEXPECTED-PASS` | graduate it: un-ignore the test or move the script to `scripts/`, and delete its line |
| `INFRA` | no such test or script, build error, refused script; with the output tail |

It exits 1 when every repro fails, 2 on any unexpected pass or infrastructure failure. A
malformed manifest line, or a `known-bugs/*.pkt` the manifest does not list, runs nothing and
exits 2 (`fuzz/known-bugs.sh`; its self-test `make test-known-bugs` is part of `make test`).

### Scapy (`make test-scapy`, `make docker-fuzz`)

`make test-scapy` runs the Scapy fuzzer's unit tests (`python3 -m unittest discover -s
fuzz/scapy`). `make docker-fuzz` (`make fuzz` natively) runs only the Scapy fuzzer, on the one
`DOCKER_CPUSET` CPU. Native `make test-scapy` needs python3-scapy.

The two deterministic scenarios in `fuzz/scapy/r9.py`, R9a and R9b in its output, run as
`target/debug/tap-echo --listeners 2 -- python3 fuzz/scapy/r9.py` inside the Linux container
(bound it with `timeout --kill-after=10 30`). R9a requires the live connection's challenge ACK
and continued echo. R9b loses a SYN-ACK, frees the lower listener, and requires the original
identical SYN-ACK before its retransmission timer, then one connection echoing with no extra
half-open retransmission. `--only R9a` or `--only R9b` selects one scenario. Their assertion
tests are in `make test-scapy` discovery.

The Scapy fuzzer (`fuzz/scapy/fuzz_tcp.py`, Scapy 2.5.0 from the image's apt) is the tester of
one `tap-echo` run, bounded by `timeout --kill-after=10 $(FUZZ_TIMEOUT)` (default 600 s; 300
connections take 145-173 s; expiry fails). It opens one AF_PACKET socket on `cdtap_echo`,
answers ARP itself and plays a Linux-like TCP client: `FUZZ_CONNECTIONS` (default 300)
connections, one at a time, each after 100 ms without a fuzzer frame (one listener, no accept
backlog), plus a clean probe connection (Linux SYN, 1 KiB echo, FIN close, 5 s bound) after
every 25 and at the end.

Connection i does what `random.Random(f"{FUZZ_SEED}:{i}")` plans (default seed 1): SYN options
(MSS, window scale, SACK, timestamps, order), client ISN (also just below 2^32), payload up to
96 KiB, segment boundaries, pacing, ACK policy, close style and realistic impairments: loss of
its own segments (it retransmits), of Zhida's (Zhida must), reordering, duplication,
identical-byte overlaps, bad checksums, lost and duplicate ACKs, an application that stops
reading (zero window, then a window update).

A quarter of the connections are disruptive: one to three seeded mutations
(`fuzz/scapy/mutate.py`) replace the SYN, the handshake ACK, the FIN or a data segment with one
whose bytes were changed after Scapy serialized it (checksums then recomputed as Zhida reads the
header, except for bad-checksum mutations): IP header (TTL, TOS, ID, DF, fragments, short IHL,
real IP options behind a long IHL, total length, checksum), TCP flags, sequence/ACK numbers,
options (bad lengths, truncated, unknown kinds, MSS 0/1/65535, window scale 15/255, bogus SACK,
garbage TS, SYN options on data), window, data offset and truncation, overlaps with conflicting
bytes, and RST/FIN/SYN timing (RSTs in and out of the window, early and repeated FINs, data
after FIN, SYN mid-connection or with data). A mutation counts as applied once a changed or
extra frame of it was sent. One that changed nothing (no-op), whose changed frames were all
withheld (known bug) or whose target never came (target not reached) does not, and a connection
with nothing applied is judged as a stream-preserving one. A mutated SYN is followed by a clean
one 200 ms later. A connection with a mutation applied ends, after its close, a Zhida RST or
3 s, with a teardown: quiet, an ACK of Zhida's latest segment, then an RST at Zhida's latest ACK
number.

A run passes when:

- Every Zhida frame is ARP or well-formed IPv4/TCP to the tester (checksums, IHL 5, options that
  parse, no SYN+FIN/SYN+RST, ACK on all but RSTs).
- Every RST is exactly the one smoltcp's `rst_reply` (smoltcp 0.14.0 `src/socket/tcp.rs`
  1459-1473) answers some segment the fuzzer sent with: SEQ = that segment's ACK and no ACK
  flag, or, for an ACK-less SYN, RST|ACK with SEQ 0 and ACK = SYN SEQ + length (an ACK-less
  non-SYN: RST, SEQ 0).
- Zhida never acknowledges sequence space the fuzzer did not send and never sends a byte the
  fuzzer did not send at that position. "Sent" means a frame smoltcp's parser accepts (valid
  checksums, not a fragment, ports not 0, at most one of SYN/FIN/RST, options as smoltcp parses
  them).
- Each connection's handshake (after a mutated SYN, the clean SYN's) completes within 3 s, so
  the connection after a disruptive one shows that Zhida recovered, and each connection
  completes within its deadline (10 s, probes 5 s); a completion seen after the deadline fails.
- A probe's timestamped SYN must get a SYN-ACK without timestamps.
- On a stream-preserving connection the echo equals the payload exactly and the connection
  closes with FINs both ways and no RST; on a disruptive one without conflicting bytes the echo
  is a prefix of the payload.
- The kernel dropped no frames from the AF_PACKET socket.
- tap-echo exits 0 (101 on panic, 2 on buffers left in the pools).

The run prints the seed, one line per connection, counts of planned and applied impairments,
mutations applied (per class and kind) and not applied (no-op, withheld, target not reached),
oracle checks, Zhida retransmissions/RSTs/challenge ACKs, fuzzer retransmissions, how
disruptive connections ended, socket received/dropped counts, and the wall time.

Any Zhida RST ends a disruptive connection with the teardown, even when Zhida's connection
survives it. smoltcp in SYN-RECEIVED answers an unacceptable handshake ACK with an RST and stays
in SYN-RECEIVED (`src/socket/tcp.rs` 1665-1668), so what Zhida does after such an ACK is barely
exercised; the next connection's handshake checks that Zhida recovered.

A failure prints the reason, writes `target/fuzz/fail-s<seed>-c<i>.pcap` (frames of that and
the previous connection, both directions) and `.json` (both plans), prints a replay command and
exits 1 (tap-echo then exits 1). A replay repeats the plan, not the timing. Replay one
connection (then the end probe) inside a container started with the Makefile's `DOCKER_RUN`
flags, after `make fuzz` (or `cargo build --locked -p tap-echo`) built `tap-echo`:
`target/debug/tap-echo -- python3 -B fuzz/scapy/fuzz_tcp.py --seed 1 --only 17`, or a whole
seed: `make docker-fuzz FUZZ_SEED=7` (`FUZZ_ONLY=17` there runs only that connection).

### memif (`make test-memif`)

`make test-memif` runs the `memif-bench` crate's tests on the one test CPU: Zhida Ports on both
ends of one net_memif connection (copy mode, abstract socket) in one process, the server vdev
created first (`tests/port.rs`); the benchmark workloads between two Stacks over that connection
in one thread (`tests/workload.rs`); and the `memif-bench` binary as peer, client and launcher
processes, plus the matrix's dry run (`tests/process.rs`). It needs no privileges beyond the EAL
setup above. It then runs the self-test of `docker/cpuset-overlap.sh` (needs only sh and grep).

### Autobahn checker (`make test-autobahn-check`)

`make test-autobahn-check` runs the self-test of the Autobahn report checker
(`autobahn/check.py`, see autobahn/README.md; needs only python3) and
`autobahn/peer-self-test.sh`, which runs `peer.sh client` against fakes on PATH. A `wstest`
that exits 0 and only then sees `client-done` appear, and one that exits 0 without it, must both
give `done` 1; one that runs until SIGINT must give `done` 0. The first case is ordered, not
raced: a fake `sleep` holds peer.sh's first poll until wstest has exited and `client-done`
exists, so peer.sh's first check sees wstest alive and its next sees both. A fake `timeout` that
reaps its command and stays alive until signalled makes a supervisor between peer.sh and wstest
fail it too (needs Linux `/proc`, awk, python3).

### smoltcp (`make test-smoltcp`)

`make test-smoltcp` runs smoltcp's own lib unit tests from `vendor/smoltcp` with Zhida's smoltcp
features plus `medium-ip`, which gates smoltcp's TCP socket tests. The fork supports only
Zhida's configuration (IPv4 TCP and UDP over Ethernet, with std); its only features are
`udp-set`, `auto-icmp-echo-reply` and `medium-ip`. The crate is outside the workspace: it builds
into `target/smoltcp` against its own `vendor/smoltcp/Cargo.lock` (`--locked`). Its
dev-dependencies are downloaded from crates.io into the `zhida-cargo-registry` volume on the
first run, so that run needs network.

## `make docker-test`

`make docker-test` runs `make test` in the Zhida container, then `make docker-autobahn` (both
Autobahn roles, below) even if `make test` failed, and prints one line
`docker-test: PASS|FAIL: make test exit N, docker-autobahn exit M`. It exits 0 only if both
passed. An interrupt (INT/TERM/HUP), or `make test` exiting >= 128 (ended by a signal), stops it
without running `docker-autobahn`. The recipe contains `$(MAKE)`, so `make -n docker-test` runs
it, including `docker run`. Native `make test` cannot run Autobahn: the gate needs a second
container (the Autobahn image, sharing the Zhida container's netns).

`make docker-gate-self-test` (about 10 s, not part of `docker-test`) runs
`docker/gate-self-test.mk` in named containers. A step that never ends under
`$(DOCKER_MAKE_TEST)` with a 5 s bound must exit 124. A one-line shell step (`echo ...; timeout
... sleep`), sent `docker kill -s TERM` once it printed `term-step: started`, must exit 143 both
under `$(DOCKER_MAKE_TEST)` (30 s bound) and under plain `$(DOCKER_RUN) make` (the `docker-fuzz`
shape, which only `--init` protects). Each must name its step, not run the next one and leave no
container. Its watchdog kills the docker client and removes the container at the deadline, and
every docker call it makes is bounded.

## Benchmarks

`make docker-memif-bench` (`make memif-bench` natively) measures Zhida's TCP over memif: two
Zhida Stacks in two processes, the measuring client and an echo or sink peer, each with its own
EAL busy-polling one CPU with no sleep, yield or backoff (peer `MEMIF_PEER_CPU`, default 4;
client `MEMIF_CLIENT_CPU`, default 5; EAL control threads on `MEMIF_CONTROL_CPU`, default 3;
container cpuset `MEMIF_CPUSET`, default 3-5, which `DOCKER_CPUSET` does not change). It runs
ping-pong (64 and 1448 bytes), 4, 16 and 64 parallel ping-pong connections, and a 1 GiB bulk
send, 3 reps in alternating order, writes every report to a new
`target/memif-bench/matrix-<unix seconds>-<pid>.jsonl`, and prints min/median/max per
configuration.

A run that is not valid (a byte mismatch, a rejected frame, a reset or unclean close, a missed
deadline, a child exiting nonzero, a missing report) stops the matrix right after its JSONL row:
no later run starts, its reports and reason go to stderr, and make fails. Client counters cover
the measured window only: from the first measured writes through the last echo (or bulk ACK),
excluding what the poll that sends those first writes received (the last warmup echoes, or
warmup ACKs for bulk) and the FINs sent in the poll that receives the last echo or bulk ACK. The
peer's counters cover its whole run, so its idle-turn row is labeled "peer idle turns (whole
run)". Every frame includes memif's copy on each side.

It refuses to start if `docker ps` or `docker inspect` fails, or if a running container is
unpinned (no cpuset: it may run on any CPU) or its cpuset shares a CPU with `MEMIF_CPUSET`.
`docker/cpuset-overlap.sh` makes that check and names each such container. Containers pinned
elsewhere, e.g. gates on CPUs 0-2, may keep running.

`make docker-bench-stack` (`make bench-stack` natively, under one allowed CPU) runs the
dpdk-smoltcp Criterion benches (`ring`, `stack`, `scaling`, `neighbor`, `emit`, `rx`, `udp`;
built with the `bench-offload` feature, which `udp` requires) in a container on
`STACK_BENCH_CPU` alone (default 6; `DOCKER_CPUSET` does not change it), with the same refusal
as `make docker-memif-bench` for that CPU. `BENCH_FILTER` is passed to Criterion as its
benchmark name filter (a regex, e.g. `BENCH_FILTER=stack/established`). `BENCH_RUSTFLAGS` is
appended to the image's `RUSTFLAGS` for the bench build, e.g.
`BENCH_RUSTFLAGS='-C llvm-args=-align-all-functions=6'` for a code-layout variant (it rebuilds
everything; give each variant its own `DOCKER_TARGET_VOLUME`). Both reach cargo as given,
without make expansion (`BENCH_FILTER='round_low/1024$'` needs no `$$`); neither may contain a
single quote.

Benchmark timings inside Docker are VM measurements and must be labeled so.

## Autobahn testsuite image

`docker/autobahn.Dockerfile` builds Autobahn|Testsuite 25.10.1 (`wstest`) natively for arm64,
adapted from upstream's `docker/Dockerfile` (which installs a local wheel and publishes no arm64
image). `make docker-autobahn-image` builds it, or directly:

```sh
docker build --platform linux/arm64 -t zhida-autobahn:25.10.1 -f docker/autobahn.Dockerfile docker
```

The base `pypy:2-7-bullseye` is pinned by index digest (PyPy 7.3.20, Python 2.7.18, OpenSSL 1.1;
cryptography 3.3.2 does not build against OpenSSL 3). Every pip package is pinned `==` and
installed `--no-deps`, so nothing resolves transitively; cryptography, pyOpenSSL, Twisted and
autobahntestsuite build with `--no-build-isolation`. The base ships cffi 1.18.0.dev0, greenlet
0.4.13 and readline 6.2.4.1, plus pip 20.0.2, setuptools 44.0.0 and wheel 0.37.1, which the
image re-pins to 20.3.4 / 44.0.0 / 0.36.2. Pins are by version, not artifact hash
(`--require-hashes` is not used).

The last layer fails the build unless `wstest --help` runs, `pip freeze --all` exits 0 and its
output, minus exactly those three base lines (fixed-string whole-line match), equals the 32
pinned packages including pip/setuptools/wheel, and `pip check` reports exactly
`unittest2 1.1.0 requires argparse, which is not installed.` That one is harmless: unittest2's
metadata names the argparse backport, but argparse is in the 2.7 stdlib (the layer imports it).

## Autobahn gate (`make docker-autobahn`, part of `make docker-test`)

```sh
make DOCKER_TARGET_VOLUME=zhida-target-websocket docker-autobahn [AUTOBAHN_TIMEOUT=600] [AUTOBAHN_IMAGE_TIMEOUT=300]
```

Two roles, all 517 cases each, checked against the same pinned expected file. Server role:
`wstest -m fuzzingclient` (`autobahn/fuzzingclient.json`) against `ws-autobahn server`, a
tungstenite 0.30.0 echo server on Zhida at ws://192.0.2.2:8080. Client role: `ws-autobahn
client`, a tungstenite 0.30.0 client on Zhida (192.0.2.2, local ports 49152..49670), drives
`wstest -m fuzzingserver` (`autobahn/fuzzingserver.json`, kernel TCP at ws://192.0.2.1:9001,
`--webport 0`) through getCaseCount, runCase 1..517 and updateReports. Every byte crosses kernel
TCP -> net_tap -> Port -> Stack -> `StackStream` -> tungstenite. `make docker-test` runs it
after `make test`; `make docker-autobahn` runs the gate alone.

Each role needs two containers (Zhida on `DOCKER_CPUSET`, Autobahn on `AUTOBAHN_CPUSET`) and the
Autobahn image. make builds the image first (`docker-autobahn-image`, bounded by
`AUTOBAHN_IMAGE_TIMEOUT`, default 300 s; on expiry, or on INT/TERM/HUP, the build gets SIGTERM,
then SIGKILL if alive 10 s later, and make fails). A cold image build needs network once (base
image and PyPI); a cached one takes seconds. The release build uses the cargo registry volume
that `make docker-build`/`docker-test` filled; nothing else uses the network.

- Refuses to start when `AUTOBAHN_CPUSET` equals `DOCKER_CPUSET`.
- Takes the lock `autobahn/run.lock` (`mkdir`, atomic) or fails naming it; a second run in the
  same checkout is refused, and a lock left by a killed `make` must be removed by hand. Builds
  the release binary in `$(DOCKER_RUN)` under `timeout --kill-after=10 $(TEST_TIMEOUT)`, then
  runs the server role, then the client role (the client role runs even if the server role
  failed). Each role deletes and recreates its own `autobahn/run/<role>/` (gitignored) and
  starts two detached containers with unique names. Zhida container C (`$(DOCKER_IMAGE)`, CPU
  `DOCKER_CPUSET`, same mounts as `DOCKER_RUN`) runs the driver under `timeout --kill-after=10
  $(AUTOBAHN_TIMEOUT)` with tester `autobahn/zhida-tester.sh <role>`. Autobahn container A
  (`zhida-autobahn:25.10.1`, CPU `AUTOBAHN_CPUSET`, default 1, `--network container:C`,
  `autobahn/` mounted at `/work/autobahn`) runs `autobahn/peer.sh <role>`.
- The tester waits (60 s) for `cdtap_echo` to be up, adds 192.0.2.1/24, checks that this is the
  netns's only 192.0.2.0/24 address (so every connection to 192.0.2.2 crosses net_tap), and
  writes `ready`. In the client role it then waits (60 s) for a LISTEN socket on port 9001 at
  192.0.2.1 or 0.0.0.0 in `/proc/net/tcp` (wstest binds 0.0.0.0) and writes `server-ready`,
  which the driver waits for (60 s) before its first connect. Then the tester waits
  (`AUTOBAHN_TIMEOUT`) for `done` and execs `autobahn/check.py` on
  `autobahn/run/<role>/reports/index.json` if `done` holds 0.
- peer.sh waits (60 s) for `ready` and writes wstest's status to `done` from an EXIT trap.
  Server role: wstest runs under `timeout --kill-after=10 $(AUTOBAHN_TIMEOUT)`; `done` is its
  status. Client role: wstest runs directly in the background (so peer.sh holds wstest's own
  pid, with SIGINT restored by `env --default-signal=INT`) until the driver's client writes
  `client-done` (its sequence complete: updateReports has made fuzzingserver write the
  reports); peer.sh's poll bounds that wait by `AUTOBAHN_TIMEOUT` (expiry: SIGKILL, `done` 1).
  fuzzingserver without `shutdownOnComplete` never exits on its own, so wstest must be alive and
  not a zombie (`/proc/<pid>/stat` state != Z) when peer.sh observes `client-done`; otherwise
  `done` is 1. Then peer.sh sends SIGINT, and `done` is wstest's status if it exits within 10 s
  of the signal, else SIGKILL and `done` 1. The client uses `updateReports` without
  `shutdownOnComplete=true`, because with it fuzzing.py's onOpen (lines 296-301) calls
  `reactor.stop()` before Twisted flushes the 101 response, and the client's handshake reads EOF
  and fails.
- Per role, make polls C (`docker inspect`; the macOS host has no coreutils `timeout`) for up to
  `AUTOBAHN_TIMEOUT` + 60 s from its start, then kills both containers. It then polls A for up
  to 30 s and kills it. Either kill fails the role, as does any failed `docker inspect` (never
  read as "stopped"). make saves both logs to `autobahn/run/<role>/{zhida,autobahn}.log`,
  prints C's log (check.py counts and divergences, the driver's connection count, session
  endings and turn counters), removes both containers and prints one result line per role.
  Removal fails the role if `docker inspect` or `docker rm -f` fails, or if a container is
  running on a role that would otherwise pass. On exit (also on interrupt) any container not
  yet removed is removed the same way and the lock released; a failure there fails make.
- A role passes only if C exited 0 (tester = check.py passed; server: accepted connections ==
  517, no server error or 120 s session deadline; client: all 519 connections completed, no
  client error or 120 s connection deadline; zero packet buffers in use at port close), `done`
  holds 0, and make killed neither container and removed both. make exits 0 only if both roles
  pass. wstest fuzzingclient exits 0 even when its connects fail (it then skips the remaining
  cases), so its status alone proves nothing; check.py's 517-case set does.

Limits:

- A SIGKILLed Autobahn container never writes `done`, so the tester waits the full
  `AUTOBAHN_TIMEOUT` before failing.
- One `AUTOBAHN_TIMEOUT` sets three nested bounds (driver, tester's wait for `done`, wstest); a
  run near the limit reports "driver exit 124" rather than a wstest timeout.
- wstest exiting on its own between peer.sh's check at `client-done` and its SIGINT (one shell
  command apart) is indistinguishable from exiting on the SIGINT.
- On Linux hosts the containers write root-owned files under `autobahn/run/`, so the next run's
  `rm -rf` fails loudly. Docker Desktop for Mac is unaffected.
- The server's listener has no SYN-RECEIVED timeout: a client that sends a SYN and vanishes
  keeps the only listener in SynReceived, and SYNs from other tuples are reset. On the lossless
  tap with a cooperating kernel this does not happen; the run would fail on missing cases.
- The host watchdog polls `docker inspect`; a Docker request that itself blocks (any
  `docker run`, `inspect`, `logs` or `rm`) is not bounded.

## Live Binance example (`make docker-binance`)

`crates/binance-feed` subscribes to Binance's public `btcusdt@bookTicker` WebSocket stream over
TLS with TCP running on Zhida: a DPDK net_tap port and a `Stack` inside the Docker container,
not kernel sockets. rustls (ring provider, webpki-roots) runs over ws-autobahn's `StackStream`,
tungstenite over rustls. It needs internet:

```sh
make docker-binance BINANCE_SECONDS=30
```

| Variable | Default |
| --- | --- |
| `BINANCE_SECONDS` | 10 |
| `BINANCE_HOST` | `data-stream.binance.vision` (`stream.binance.com` answers HTTP 451 from restricted locations) |
| `BINANCE_PORT` | 9443 |
| `BINANCE_PATH` | `/ws/btcusdt@bookTicker` |
| `BINANCE_PRINT` | 10 (messages printed) |

The target builds `zhida-dpdk-test:binance` (the `:local` image plus nftables,
`docker/binance.Dockerfile`) and runs the container with `--sysctl net.ipv4.ip_forward=1`. It
does not build the `:local` image it starts from, so run `make docker-image` first. The binary
resolves the host with the container's kernel resolver before DPDK starts.
`crates/binance-feed/tester.sh` gives the kernel side of the tap netdev 192.0.2.1/24 (Zhida is
192.0.2.2 with gateway 192.0.2.1), NATs Zhida's traffic out of eth0 and recomputes the TCP
checksum of segments arriving on eth0: under Docker Desktop they arrive with an unfilled
checksum, which the kernel's own TCP accepts but Zhida rejects. After `BINANCE_SECONDS` the
client closes the WebSocket, sends TLS close_notify and closes TCP.

Example output:

```text
binance-feed: data-stream.binance.vision resolved to 52.199.68.85 by the kernel resolver
binance-tester: ready: Zhida 192.0.2.2, gateway 192.0.2.1 on cdtap_echo, NAT out of eth0; running 30 s
binance-feed: connected to wss://data-stream.binance.vision:9443/ws/btcusdt@bookTicker (52.199.68.85:9443) from 192.0.2.2:54479 over Zhida, TLSv1_2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, WebSocket open
#1 u=101215365458 BTCUSDT bid 80572.00000000 x 2.23662000 ask 80572.01000000 x 1.35982000
#2 u=101215365462 BTCUSDT bid 80572.00000000 x 1.89912000 ask 80572.01000000 x 1.35982000
#3 u=101215365470 BTCUSDT bid 80572.00000000 x 1.89905000 ask 80572.01000000 x 1.35982000
#4 u=101215365479 BTCUSDT bid 80572.00000000 x 1.89905000 ask 80572.01000000 x 1.02232000
#5 u=101215365480 BTCUSDT bid 80572.00000000 x 2.23655000 ask 80572.01000000 x 1.02232000
#6 u=101215365485 BTCUSDT bid 80572.00000000 x 2.23655000 ask 80572.01000000 x 1.02941000
#7 u=101215365486 BTCUSDT bid 80572.00000000 x 2.34304000 ask 80572.01000000 x 1.02941000
#8 u=101215365500 BTCUSDT bid 80572.00000000 x 2.34304000 ask 80572.01000000 x 1.02232000
#9 u=101215365502 BTCUSDT bid 80572.00000000 x 2.34304000 ask 80572.01000000 x 0.66772000
#10 u=101215365505 BTCUSDT bid 80572.00000000 x 2.34304000 ask 80572.01000000 x 0.65452000
binance-feed: 5961 bookTicker messages in 30.1 s since start, update ids 101215365458..101215391860
binance-feed: closed (WebSocket close handshake, TLS close_notify, TCP TIME-WAIT)
```

`make test-binance` (part of `make test`) runs the same client offline: a kernel TCP rustls +
tungstenite server with a self-signed certificate on 198.51.100.10, reached through Zhida's
gateway across a net_tap netdev. It checks 12 bookTicker messages, a Ping answered with Pong and
the close sequence, an HTTP 451 upgrade refusal reported with its status and body, and a
certificate outside the webpki-roots set rejected as UnknownIssuer.

## Linux VM

A Linux machine runs the same targets without Docker. It needs what docker/Dockerfile installs:

- Rust 1.93.0. `rust-toolchain.toml` at the repository root pins it for cargo commands in this
  tree (`cargo +nightly` overrides it). The Dockerfile's `rust:1.93.0-bookworm` base image must
  name the same version; bump both together.
- clang 18 and lld 18, `clang` and `ld.lld` on `PATH`, plus pkg-config, meson, ninja,
  python3-pyelftools, libnuma-dev, libpcap-dev, iproute2 and ethtool (Ubuntu 24.04 package
  names).
- DPDK 25.11.3 built from source into `/opt/dpdk` with the Dockerfile's meson options
  (`-Dplatform=generic -Denable_stdatomic=false -Dmbuf_refcnt_atomic=false`, its driver list and
  the rest). `make doctor` refuses any other DPDK version.
- packetdrill at the Dockerfile's commit with `docker/packetdrill-relearn-isn.patch` applied, the
  binary on `PATH` and `packetdrill.h` in `/opt/packetdrill/include`.
- python3-scapy.
- sockperf 3.10 installed under `/opt/sockperf` (`make test-nic-runner` runs
  `/opt/sockperf/bin/sockperf`).
- root or CAP_NET_ADMIN and CAP_NET_RAW, and `/dev/net/tun`, for the tap tests.

Then:

```sh
export PKG_CONFIG_PATH=/opt/dpdk/lib/pkgconfig
export LD_LIBRARY_PATH=/opt/dpdk/lib
export RUSTFLAGS='-C linker=clang -C link-arg=-fuse-ld=lld'
make doctor
make build
taskset -c 3 make test DOCKER_CPUSET=3 PACKETDRILL_CPUSET=4 PACKETDRILL_ZHIDA_CPUSET=5
taskset -c 3 make bench
```

`make test` needs three CPUs you may use: `DOCKER_CPUSET` for everything except packetdrill, and
the two packetdrill CPUs (defaults 0, 2 and 7). Run make itself under `taskset -c` on the
`DOCKER_CPUSET` CPU. `make help` lists targets. `DOCKER_IMAGE` overrides the local image tag for
the Docker targets.

`make soak` (or `make docker-soak` on CPU 8) runs the ignored two-stack soak test in
`crates/dpdk-smoltcp/tests/soak.rs` for at least `SOAK_SECONDS` (default 600) with seed
`SOAK_SEED` (default 1). It is not part of `make test`.
