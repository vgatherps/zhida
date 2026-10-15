# zhida

zhida is a userspace TCP/UDP stack for low-latency market feeds. It runs a modified smoltcp on one
DPDK port: packets go from the NIC to your process with no kernel in the path, and received data
stays in DPDK buffers instead of being copied into a socket buffer (a small in-order segment can be
appended to the buffer before it). Everything runs on one thread, one `Stack` per process on its own
CPU core. Your program drives the stack in a loop and passes it the current time. IPv4 over
Ethernet.

## Repository

| directory | package | contents |
|---|---|---|
| `crates/dpdk-smoltcp` | `dpdk-smoltcp` | The stack: `Eal`, `Port`, `Stack`, TCP and UDP sockets |
| `crates/netconf-open` | `zhida-open` | `open()`: config file to running `Stack` in one call |
| `crates/netconf` | `zhida-netconf` | Config file format, and the `zhida-netconf` tool that writes it and binds the NIC |
| `crates/zhida-buffer` | `zhida-buffer` | DPDK mbufs and pools with ownership-checked chaining |
| `crates/zhida-dpdk-sys` | `zhida-dpdk-sys` | Bindings to DPDK 25.11.3 |
| `crates/nic-runner` | `nic-runner` | `zhida-nic`: runs a Stack on a real NIC (link info, sockperf server, feed client) |
| `crates/tap-echo` | `tap-echo` | TCP echo server over a tap device, the target for packetdrill and the fuzzers |
| `crates/binance-feed` | `binance-feed` | Binance bookTicker client over TCP, TLS and WebSocket |
| `crates/stack-stream` | `stack-stream` | `Read`/`Write` adapter over a TCP socket |
| `crates/ws-autobahn` | `ws-autobahn` | tungstenite over `stack-stream`, checked with the Autobahn suite |
| `crates/memif-bench` | `memif-bench` | Benchmarks over DPDK memif |
| `crates/sockperf-wire` | `sockperf-wire` | sockperf's message format, used by `zhida-nic` |
| `vendor/smoltcp` | `smoltcp` | smoltcp 0.14.0, cut down to IPv4 TCP and UDP over Ethernet, with mbuf-native receive |
| `test-support` | `zhida-test-support`, `zhida-test-kit`, `zhida-test-support-macros` | Test helpers |

`fuzz/` has the packetdrill scripts and the Scapy fuzzers, `autobahn/` the WebSocket conformance
setup, `docker/` the test image.

## Tests

Docker Desktop with at least 8 CPUs for its VM. No NIC or hugepages needed.

```sh
make docker-image    # Ubuntu 24.04, Rust 1.93.0, DPDK 25.11.3 built from source
make docker-build    # whole workspace, all targets
make docker-test     # every test suite, then the Autobahn WebSocket suite
make docker-fuzz     # Scapy TCP fuzzer
```

`make docker-test` passes when make exits 0 and its last line is

```text
docker-test: PASS: make test exit 0, docker-autobahn exit 0
```

`make help` lists the per-suite targets (`test-stack`, `test-buffer`, `test-netconf`, ...), which
run natively on Linux or inside the image. [docker/README.md](docker/README.md) covers each suite,
the CPU layout, benchmarks and native Linux setup.

## Running on a NIC

[crates/nic-runner/README.md](crates/nic-runner/README.md): supported drivers, writing the config
with `zhida-netconf discover`, hugepages, binding the NIC to vfio-pci, and `zhida-nic`.

## Writing a program

[docs/USAGE.md](docs/USAGE.md) is the API guide: setup, pool sizing, the drive loop, time, TCP, UDP,
errors and shutdown. [crates/netconf-open/examples/tcp_client.rs](crates/netconf-open/examples/tcp_client.rs)
loads a config, opens the stack, connects to a TCP server, prints what it sends and closes the port.

```sh
cargo build -p zhida-open --example tcp_client
```

## License

Copyright (C) 2026 vgatherps. GPL-3.0-only, see [LICENSE](LICENSE).

Imported files keep their own licenses:

- `vendor/smoltcp`: 0BSD (`vendor/smoltcp/LICENSE-0BSD.txt`).
- packetdrill scripts from freebsd-net/tcp-testsuite: BSD-2-Clause, notice in each file.
- packetdrill scripts from google/packetdrill, and `docker/packetdrill-relearn-isn.patch`:
  GPL-2.0-or-later.
- `autobahn/expected-results.json`: from tungstenite, MIT OR Apache-2.0
  (`autobahn/LICENSE-MIT-tungstenite`).

Sources and commits: [fuzz/packetdrill/README.md](fuzz/packetdrill/README.md#upstream-suites),
[autobahn/README.md](autobahn/README.md).
