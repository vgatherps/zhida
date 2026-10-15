# Zhida application guide

## What Zhida is

Zhida runs a TCP/UDP stack on DPDK with IPv4 over Ethernet. One `Stack` owns one `Port`, which
controls one RX queue and one TX queue, both queue 0. The application drives packet processing on
one thread and supplies time. Packet processing never reads a clock or waits for a packet, writable
socket, or timer; the application decides when to drive it again. The adapter is `dpdk_smoltcp`,
which re-exports `smoltcp`, `TcpHandle`/`UdpHandle`, `TcpFrame`, `HeldFrames`, and the UDP and
counter types. The Stack answers ICMP echo requests (ping) to its address automatically.

## Process model

Zhida is single-threaded. Initialize EAL on the application thread and keep `Eal`, the `Port`,
the `Stack`, socket handles, held frames and datagrams, and their packet operations and cleanup on
that same thread. `Eal`, `TcpHandle`, and `UdpHandle` are not `Send`.

Run exactly one `Stack` per process. Several Stacks can exist (the test harness does this), but each
handle carries its Stack's identity: using a handle with a Stack that did not create it panics.
Do not move sockets, handles, or frames between Stacks. The DPDK lcore identity established by
`Eal::init` must remain valid until every buffer has returned, including buffers that survive
socket removal or a refused port close.

For multicore deployment, run one process per NIC, each with one Stack, its own EAL instance and
its own CPU. Share no Zhida ports, stacks, sockets, pools, or buffers between those processes.
`Eal::init` does not create that isolation.

EAL lasts for the process. Dropping `Eal` does not clean up DPDK or unregister its main lcore. After
successful initialization, it cannot be initialized again. The application owns connection
deadlines, scheduling, waiting, and protocols, as in `binance-feed`.

## Setup

### Open from a netconf config

Applications start from a config file written by `zhida-netconf discover` (see
[crates/nic-runner/README.md](../crates/nic-runner/README.md) §2) and open everything with one call
to `zhida_open::open`. [crates/netconf-open/examples/tcp_client.rs](../crates/netconf-open/examples/tcp_client.rs)
is a complete client built this way: it opens, connects, sends a line, prints what comes back and
closes the Port.

The crates are not published. Depend on them by path; the package names differ from the directory
names:

```toml
[dependencies]
dpdk-smoltcp = { path = "../zhida/crates/dpdk-smoltcp" }
zhida-netconf = { path = "../zhida/crates/netconf" }
zhida-open = { path = "../zhida/crates/netconf-open" }
```

Setup for one TCP socket looks like this. The same code is
[crates/netconf-open/examples/setup.rs](../crates/netconf-open/examples/setup.rs), which the build
compiles; a test fails if the two differ.

```rust
use std::path::Path;

use dpdk_smoltcp::DEFAULT_NEIGHBOR_CAPACITY;
use dpdk_smoltcp::smoltcp::socket::tcp;
use dpdk_smoltcp::smoltcp::time::Instant;
use dpdk_smoltcp::smoltcp::wire::Ipv4Address;

fn setup() -> Result<(), Box<dyn std::error::Error>> {
    let config = zhida_netconf::Config::load(Path::new("dut.json"))?;
    let server = Ipv4Address::new(192, 0, 2, 1);
    let tcp_config = tcp::Config {
        rx_capacity: 65536,
        tx_capacity: 65536,
        mss_cap: Some(config.path_mtu(server) - 40),
    };
    let sizing = zhida_open::Sizing {
        tcp_rx_frames: tcp::rx_mbuf_budget(&tcp_config, usize::from(config.mtu)),
        udp_rx_datagrams: 0,
        max_sockets: 1,
        max_udp_sockets: 0,
        rx_staging: 32,
        tx_pending: 32,
        segments_per_visit: 1,
        neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
    };
    let start = std::time::Instant::now();
    let mut clock = || Instant::from_micros(i64::try_from(start.elapsed().as_micros()).unwrap());
    let opened = unsafe { zhida_open::open(&config, &sizing, &mut clock) }?;
    println!("{}", opened.report);
    let (mut stack, _eal) = (opened.stack, opened.eal);
    let handle = stack.add_tcp(tcp_config)?;
    stack.connect(&handle, (server, 7000), 40000)?;
    // then the drive loop; keep `_eal` alive until the Port is closed
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    setup()
}
```

Build the TCP config before calling `open`: `open` sizes the RX pool, and the pool must hold every
socket's receive budget. Use the same config, including its MSS cap, for sizing and admission.
`Sizing` has no defaults; fill all eight fields:

| field | what to put there |
|---|---|
| `tcp_rx_frames` | sum of `tcp::rx_mbuf_budget(&config, mtu)` over every TCP config you will add (see "Pool sizing" below) |
| `udp_rx_datagrams` | sum of `UdpConfig::rx_queue` over every UDP socket you will add |
| `max_sockets`, `max_udp_sockets`, `rx_staging`, `tx_pending`, `segments_per_visit`, `neighbor_capacity` | passed to the `StackConfig` fields of the same name ("Configure the Stack" below) |

A socket that does not fit gets `AddTcpError::RxPoolTooSmall` from `add_tcp`.

`open` checks the process is pinned to one CPU, initializes EAL (`--lcores=0@cpu`, the config's file
prefix, the PCI address or vdev, then `eal.extra`), checks the PCI MAC against the config, resolves
offloads (`"auto"` picks per driver; the report says why), opens the Port, waits up to 10 s for
link, builds the Stack at `clock()`, then resolves the gateway's MAC. Each failure is one
`OpenError` variant. Every failure after `Port::open` hands back the `Port`, or the `Stack` for
`GatewayUnresolved` and `Receive`, so the caller can close it and return every buffer. The `?` above
drops it; `crates/nic-runner/src/main.rs` matches each variant and closes the Port. `open` is
`unsafe` for the same reasons as `Eal::init` and `Port::open`; see its doc comment.

Gateway warm-up: with a `gateway` in the config, `open` loops `Stack::resolve_gateway()` and
`receive` on your clock. One ARP request leaves per second of silence; a gateway that has not
answered after 3 s fails with `OpenError::GatewayUnresolved { stack, gateway, waited }`. On success
the report prints `gateway: <ip> at <mac> after <n> ms`, and the first send to an off-subnet peer
does not wait for ARP. A Stack built without `open` can do the same: `resolve_gateway()` returns
`Ok(Some(mac))` when resolved, `Ok(None)` after queueing a request (or while within the 1 s silence
or with no free TX buffer; call again after `receive`), and `Err(NoRoute)` when the Stack has no
gateway.

Drive `turn`/`receive` with the same clock. The Stack refuses time that goes backwards, so a second
clock with another origin fails the first drive call.

Per-destination path MTU: the config's `paths` list holds `(prefix, mtu)` rules. The longest
matching prefix wins, the Stack's own subnet is an implicit rule at the Port MTU, and everything is
clamped to the Port MTU. TCP caps a connection's MSS at path MTU - 40 toward the peer, on `connect`
and on an accepted SYN; a UDP send larger than path MTU - 28 returns `TooLarge`. Port and rule MTUs
must be at least 88, both in the config and in `Stack::new`. A peer raises an advertised MSS below
48 up to 48 (Linux and zhida both do), so a smaller path cannot carry its full-size segments. The
68-87 range is refused for UDP too.
`zhida-netconf discover --aws` writes these rules:

| destination | path MTU | TCP MSS | UDP payload max |
|---|---:|---:|---:|
| own subnet (implicit) | Port MTU (9001 on EC2) | 8961 | 8973 |
| each VPC CIDR | 9001 | 8961 | 8973 |
| `0.0.0.0/0` (internet gateway, NAT gateway) | 1500 | 1460 | 1472 |

Add your own rules for peered VPCs (intra-region 9001; inter-region, transit gateway 8500), VPN
(≤ 1446) or Direct Connect; without one they fall into the 1500 default. Before sizing sockets,
`config.path_mtu(addr)` returns the same answer the Stack will use.

DNS: Zhida does not resolve names. Resolve with the kernel (`ToSocketAddrs`) before `open` or
outside the packet loop, never inside it (it blocks). On EC2 the kernel resolver goes through the
primary ENI, which stays kernel-owned.

Clock: feed the Stack from `CLOCK_MONOTONIC` (`std::time::Instant`), which chrony slews but never
steps. For wall time, run chrony against the Amazon Time Sync service (169.254.169.123), or on
instances with the ENA PHC `refclock PHC /dev/ptp_ena`.

### Setting up by hand

The next four sections do by hand what `open` does: initialize EAL, find the ethdev, configure the
Port and build the Stack. `tap-echo` and the tests set up this way. An application that calls
`open` can skip to "Pool sizing".

### Initialize EAL

Restrict the process to one CPU before startup, with `taskset -c N` or a container CPU set with
one CPU. `zhida_dpdk_sys::only_allowed_cpu` queries the calling thread's affinity and errors unless
exactly one CPU is allowed.

Pass a complete argument vector to `Eal::init(&[&str])`, including the program name. Zhida adds no
options. EAL pins its main lcore according to the supplied arguments. The tap driver maps lcore 7
onto the one allowed CPU; the lcore number and CPU number need not be equal.

This is the argument shape in `crates/tap-echo/src/driver.rs`. `memory` is a decimal MiB count sized
by the driver for its pools and EAL overhead.

```rust
let cpu = zhida_dpdk_sys::only_allowed_cpu()?;
let lcores = format!("--lcores=7@{cpu}");
let eal_args = [
    "tap-echo", "--no-pci", "--no-huge", "-m", memory.as_str(),
    "--no-shconf", "--no-telemetry",
    lcores.as_str(), "--main-lcore=7",
];
let eal = Eal::init(&eal_args)?;
```

The tap's device/memory options are example-specific; `--no-pci` disables PCI probing. Use options
for your device and keep the one-CPU mapping. `owner_lcore_id()` reports the initialized lcore;
`consumed_args()` reports DPDK's consumed count.

EAL creates writable argument strings and a pointer array for initialization. Only the strings
remain allocated until process exit, because DPDK retains pointers to parsed options. A failed
initialization cannot be assumed retryable. DPDK help and some parser errors exit the process instead of returning an `EalError`.

### Create or find the ethdev

`Port::open` takes an existing ethdev ID; it does not create a vdev. The tap driver creates one with
`rte_vdev_init`, finds its ID with `rte_eth_dev_get_port_by_name`, then opens it. For a probed NIC,
use the ethdev ID of the newly probed device. In either case, the device must be fresh, never
configured or started, and exclusively controlled by this application. Remove a caller-created vdev
only after its Port has closed successfully.

### Configure the Port

`PortConfig<'a>` supplies device settings and separate `zhida_buffer::PoolConfig<'a>` pools. Open a
fresh device with `let port = unsafe { Port::open(&eal, config) }?;` after satisfying the safety
obligations below.

| Field | Type | Meaning |
| --- | --- | --- |
| `port_id` | `u16` | Existing ethdev ID. |
| `mtu` | `u16` | Requested IP MTU. |
| `rx_descriptors` | `u16` | Requested RX descriptor count. |
| `tx_descriptors` | `u16` | Requested TX descriptor count. |
| `rx_burst` | `u16` | Maximum packets requested in one RX burst. |
| `tx_burst` | `u16` | Maximum packets offered in one TX burst. |
| `queue_socket` | `i32` | NUMA socket passed to queue setup. |
| `rx_pool` | `PoolConfig<'a>` | RX pool configuration. |
| `tx_pool` | `PoolConfig<'a>` | TX pool configuration. |
| `offloads` | `Offloads` | Requested checksum and RX timestamp offloads. |

`PoolConfig` has `name: &CStr`, `count: u32`, `cache_size: u32`, `data_room_size: u16`, and
`socket_id: i32`. Use distinct pool names. `socket_id: -1` requests DPDK's `SOCKET_ID_ANY`. The
production allocator requires a nonzero cache size. DPDK validates pool count, cache limits, names,
and NUMA allocation.

`data_room_size` includes `RTE_PKTMBUF_HEADROOM`. For RX, usable room must be at least `ceil1024(mtu
+ 26)`, as well as at least the larger of `mtu + 14` and the PMD's `min_rx_bufsize`. TX usable room
must hold `mtu + 14` bytes. These checks preserve single-segment packets. At MTU 1500, the tap
driver uses headroom plus 2048 bytes for both pools. A larger MTU needs correspondingly larger rooms
and PMD support.

Descriptor and burst counts must be positive. The PMD may adjust descriptor counts;
`Port::descriptor_counts()` returns the negotiated RX/TX pair. Setup rejects invalid adjusted
counts. If the PMD can report RX queue information, setup also rejects scattered RX.

Size `rx_burst` and free RX staging capacity for the PMD's burst requirements. The Port requests
`min(free staging capacity, rx_burst)` packets. Some vector PMDs round requests down to a multiple
of their per-loop count and return nothing below it, so a request that is always too small stops
reception.

`Offloads::default()` requests none. `rx_checksum: true` requests IPv4, TCP, and UDP RX verification
together. GOOD verdicts let smoltcp skip the corresponding software check. An IPv4-header BAD verdict
drops the packet in the Port and increments `rx_ipv4_checksum_bad`. Any other verdict, including L4
BAD, leaves the packet to smoltcp's software verification; TCP and UDP software failures appear in
`Stack::tcp_counters()` and `Stack::udp_counters()`. `rx_timestamp: true` requests hardware RX
timestamps; see Hardware RX timestamps. `tx_tcp_checksum: true` and `tx_udp_checksum: true` request
the respective TX checksums. IPv4 header checksums run in software. The Stack prepares offload
metadata before flushing frames; direct `Port::tx_burst` does not. With UDP TX offload enabled,
`UdpConfig::tx_checksum` has no effect: the NIC computes the checksum even when it is false. An
unsupported requested offload fails setup before pool acquisition. Setup reads back the device
configuration and requires exactly the requested MTU and offload set; the one tolerated extra bit is
TX `MULTI_SEGS`, which the ENA PMD forces on. There is no fallback to a different profile.

The `net_tap` TX checksum profile needs extra TX pool slack. That PMD allocates a header copy from
the TX pool; without a free extra mbuf it accepts nothing, and a failed kernel write can leak the
copy and damage the pending frame.

Opening a Port is unsafe because Rust cannot establish the ethdev and PMD obligations. Before the
call, ensure exclusive control of a fresh device and retain the EAL owner. Keep setup, packet
access, buffer return, and cleanup on the EAL owner thread. Do not clone, share, chain, indirectly
attach, or externally back production pool packets. The PMD, and any producer of an attached RX
ring, must supply valid DPDK mbufs with valid links and reference counts, transferring one reference
per received packet. TX acceptance must consume the front of the offered array and report no more
than the offered count. The PMD must honor the packet profile and release buffers and DMA on close.
Caller-owned vdevs and rings must survive device close; queued buffers must return before pool
destruction. These requirements also apply to a Port retained after failed setup or cleanup.

Before both pools are acquired, a setup error leaves the ethdev with the caller. After acquisition,
setup owns the ethdev and rolls back on failure. `PortOpenError` records the original cause, any
rollback failure, and any retained Port owner. Preserve a retained owner and its dependencies for
cleanup; it is not ready for packet transfers.

### Configure the Stack

`StackConfig` selects one Ethernet address, one IPv4 address/subnet, and fixed socket limits. This
has the shape used by the tap driver, with UDP enabled for an application that needs it.

`StackConfig::ethernet` configures smoltcp's address; it does not program the NIC's MAC or receive
filters. Frames addressed to that MAC must reach this Port. The address below is an example.

```rust
fn create_stack(port: Port) -> Result<Stack, Box<dyn std::error::Error>> {
    let config = StackConfig {
        ethernet: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
        ipv4: Ipv4Cidr::new(Ipv4Address::new(192, 0, 2, 2), 24),
        gateway: None,
        paths: &[],
        random_seed: os_random_seed()?,
        neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
        segments_per_visit: 1,
        max_sockets: 8,
        max_udp_sockets: 2,
        rx_staging: 32,
        tx_pending: 32,
    };
    match Stack::new(port, config, Instant::ZERO) {
        Ok(stack) => Ok(stack),
        Err((_port, error)) => Err(error.into()),
    }
}
```

`ethernet` and the `ipv4` address must be unicast. A destination inside the configured subnet is
reached directly; any other destination goes to the gateway's MAC. There is no route table. With
`gateway: None` only on-link peers are reachable: UDP sends to other addresses fail with `NoRoute`
and a TCP connect to them sends nothing. A gateway must be unicast, inside the configured subnet, and
different from our own address and the subnet's network and broadcast addresses. A /31 has neither of
the latter.

`random_seed: u64` seeds the interface PRNG, including the TCP initial-sequence-number secret.
`os_random_seed() -> std::io::Result<u64>` reads eight bytes from `/dev/urandom`; use a fixed seed
only in tests and benchmarks. `neighbor_capacity: usize` controls the ARP cache. `DEFAULT_NEIGHBOR_CAPACITY` is 256. A
new neighbor in a full cache evicts the neighbor that expires first. `segments_per_visit: usize`
limits consecutive frames from one TCP socket while other sockets have frames ready. A socket alone
can continue sending; 1 gives one-segment interleaving.

`max_sockets: usize` is the TCP slot limit and must be positive, even for a UDP-only application.
`max_udp_sockets: usize` is a separate UDP slot limit; zero disables UDP sockets.
`neighbor_capacity`, `segments_per_visit`, `rx_staging`, and `tx_pending` must be positive.
`rx_staging: usize` and `tx_pending: usize` set fixed-capacity device queues (`VecDeque::with_capacity`,
so actual capacity can exceed the request). RX bursts fill available staging space. TCP-built
frames and UDP sends share the pending TX FIFO. A full pending queue blocks ingress, so size it for
both traffic directions. `Stack::new(port, config, now)` consumes the Port on success. On failure it
returns `(Port, StackError)`. Invalid configuration or negative start time gives `InvalidConfig`;
IP MTU below 68 gives `IpMtuBelowIpv4Minimum`, and 68-87 gives `InvalidConfig` from the path table,
which needs 88; a TX pool smaller than `tx_reserve(negotiated TX descriptors, tx_pending)` gives
`TxPoolTooSmall { count, required }`. Creation does not check the RX pool against sockets added
afterwards.

## Pool sizing

### RX reserve and socket budgets

Socket receive data occupies RX mbufs. Size the RX pool for held data as well as the driver's
working space. `rx_reserve(rx_descriptors, rx_staging, rx_cache_size) -> usize` computes:

```text
max(rx_descriptors, 32) + rx_staging + floor(3 * rx_cache_size / 2)
```

The descriptors keep the NIC supplied, staging holds unprocessed packets, and the cache term covers
one lcore's DPDK cache flush threshold. The 32 minimum also covers memif copy RX: with data waiting,
it allocates 32 mbufs per call and receives nothing if that allocation fails.
`crates/memif-bench/src/memif.rs` documents additional memif room and disconnect requirements.

`rx_pool_count(reserve, ip_mtu, recv_capacities) -> u32` adds uncapped TCP socket budgets:

```text
reserve + sum(max(ceil(recv_capacity / (ip_mtu - 40)), 6))
```

Each receive capacity is in bytes, not packets. Six is the minimum frame budget even for a small or
zero-capacity socket. For MTU 1500, a 65536-byte uncapped receive buffer charges 45 mbufs. For MTU
9000, it charges 8. These are admission budgets, not throughput estimates.

For a socket with an MSS cap, add `tcp::rx_mbuf_budget(&config, usize::from(ip_mtu))` to the
reserve instead, using the same config for sizing and admission. Admission computes the budget with
`min(ip_mtu - 40, configured MSS cap)` bytes per frame. Add every UDP socket's
`UdpConfig::rx_queue` to the same RX pool count; TCP and UDP share the pool. A drained `TcpFrame`
keeps its slot in the socket's frame budget, and a `UdpDatagram` taken from the queue keeps its
slot in `rx_queue`, until the application drops it. `Stack::add_tcp` charges the new socket's frame
budget beside the reserve and existing TCP and UDP budgets. `Stack::add_udp` charges its receive
queue capacity. A Closed TCP socket keeps its slot and budget until removed or, after its handle is
dropped, reaped. A removed TCP or UDP socket releases its budget, but frames and datagrams held by
the application count against future admission until dropped.

`AddTcpError::RxPoolTooSmall { config, required, pool }` means the pool's object count is smaller
than the full admission requirement, not that an allocation failed. Both admission errors return the
config unchanged. `AddUdpError::RxPoolTooSmall` reports the same failure without a socket value.
The Stack computes its reserve from the negotiated RX descriptor count, which the PMD may raise;
leave room for that.

### TX pool

TX socket buffers are ordinary byte rings; TX mbufs hold frames built from them.
`tx_reserve(tx_descriptors, tx_pending) -> usize` computes the minimum TX pool count:

```text
tx_descriptors + tx_pending
```

Use the negotiated count, `Port::descriptor_counts().1`: a NIC PMD can keep that many sent mbufs
after reporting acceptance. The Stack holds at most `tx_pending` more; built frames, the live
reservation, and one full-frame spare share those slots. No cache slack is needed because this
lcore is the only allocator. `Stack::new` refuses a smaller pool with `TxPoolTooSmall`. Test PMDs
such as `net_ring` ignore the descriptor count and queue sent mbufs into an attached ring, whose
capacity bounds retention. Ingress needs a TX packet before processing each RX frame, even one that
needs no reply, so an empty TX pool blocks receive too. Add room for PMD-specific allocations such
as the `net_tap` checksum header copy.

`Port::alloc_tx` retries an exhausted pool after one TX-done cleanup on queue 0. If the PMD does not
support cleanup, it returns `None`. A cleanup error other than `-ENOTSUP` panics.

## The drive loop

### A complete turn

`stack.turn(now, ingress_budget) -> Result<Turn, StackError>` checks time, flushes previous pending
frames, takes one RX burst, performs maintenance, processes at most `ingress_budget` staged frames,
runs TCP egress passes, then flushes. Egress stops when a pass makes no socket progress or queues no
frame. A full pending queue bounds how much it can build in that call.

Application work after `turn` sees received data. TCP bytes written then wait for `send` or the next
`turn`, as in the feed pump and echo server's `serve` loop. `ingress_budget` bounds frames handed to
smoltcp, not frames fetched in the RX burst, frames drained by the application, or egress work. A
zero budget stages RX and runs maintenance and egress without processing staged RX. Staged frames
are processed on subsequent calls even when the new burst receives nothing.

### Receive, application work, send

Use `receive` followed by socket drains/writes and `send` when a reply should leave in the iteration
that receives its request:

```rust
let received = stack.receive(now, BUDGET)?;
let socket = stack.tcp_mut(&handle);
if let Some(frame) = socket.recv()? {
    let written = socket.send_slice(frame.payload())?;
    // keep frame.payload()[written..] for a later write
}
let sent = stack.send()?;
```

If `written` is short, keep the unwritten suffix; the echo callers keep the drained frame and an
offset, and bound each write by free TX-buffer space.

`receive(now, budget)` flushes pending frames, takes one RX burst, runs maintenance and bounded
ingress, then flushes ingress-built frames if any are pending. RSTs, immediate and challenge ACKs,
and ARP replies can therefore reach the PMD before application work. It runs no TCP egress.

`send() -> Result<Sent, StackError>` runs TCP egress and flushes. SYN-ACKs, retransmissions, expired
delayed ACKs, and window updates built in egress wait for this call, so keep the application step
short. `send` needs no preceding receive and may repeat. It uses the last supplied Stack time.

Without TX backpressure, `receive` then `send` with no application changes emits the same frames as
`turn`, with the same combined counts. Under backpressure, the extra flush between ingress and
egress can let more frames through, so accepted/pending counts and the next call's `rx_blocked` can
differ.

### Push pending frames

`flush() -> Result<Sent, StackError>` pushes pending frames without building any or changing time.
The memif workload calls `receive`, runs its application step, then calls `send` for TCP or `flush`
for UDP. Ingress replies are offered before the step; application replies are offered afterwards.

`flush` offers burst after burst while the PMD accepts every offered frame. The first short
acceptance stops it, and the unaccepted suffix stays pending in order. PMD acceptance transfers
buffer ownership; it is not a peer acknowledgement or proof of wire delivery. Pending frames leave
through `flush`, or the flush inside `turn`, `receive`, or `send`; `poll_at` leaves them pending.
If the PMD accepts nothing, retry on the application's cadence rather than in a tight loop.

### Decide when to drive again

`poll_at(&mut self) -> Option<Instant>` evaluates cached TCP socket deadlines at the latest time
supplied to `new`, `turn`, or `receive`. A ready socket or past deadline is reported at that latest
time. Unprocessed dropped handles or frame-drop wakes, or a dropped TCP socket that reached Closed,
also report that time, so the next drive call cleans them up. `None` means no socket deadline. The
timer wheel can report a boundary before the actual socket deadline. `poll_at` does not cover
staged RX frames, pending TX frames, or packet arrivals, so never wait on it indefinitely. The feed
caps its idle wait at 1 ms; a busy-poll application calls again immediately.

If `rx_staged > 0` and `rx_blocked == false`, the ingress budget ran out: call ingress again
promptly. If `rx_blocked` is true, processing needs a pending slot and a TX packet; flush and retry
as the PMD accepts frames or returns TX buffers. Budget exhaustion alone does not set `rx_blocked`.
If a call reported `tx_pending > 0`, call `flush` until nothing is pending, then `send`,
independently of `poll_at`. `send` runs egress before its flush, so with the pending queue full it
only flushes. A TCP sender refused by the full queue stays due and is served first on retry; a
refused dropped socket's zero-window probe is rescheduled. An ARP probe due for a stale neighbor is
not covered by `poll_at`; after freeing capacity, `send` or `turn` retries it in egress. Advance
time with `turn` or `receive`; repeating `send` or `flush` does not advance timers or receive ARP
replies.

## Time rules

Supply `dpdk_smoltcp::smoltcp::time::Instant`, not `std::time::Instant`, to Stack calls. Choose a
nonnegative origin. The feed converts elapsed monotonic time into microseconds:

```rust
let micros = i64::try_from(start.elapsed().as_micros())
    .expect("elapsed wall time fits i64 microseconds");
let now = Instant::from_micros(micros);
```

`Stack::new` rejects a start before `Instant::ZERO`. Each `turn` and `receive`
must supply time at least as large as the previous supplied time. Earlier time returns
`StackError::TimeWentBackwards { last, now }` before any work. Equal times are allowed, including
multiple receive calls that drain a burst at one time. `send` and `flush` take no time argument and
use the stored time. If application work is long enough for timers to matter, supply fresh time
with an ingress drive call. Avoid values near `i64::MAX` microseconds: timer arithmetic overflows
there.

TCP timer scheduling has 1 ms granularity. Nonnegative deadlines are rounded up to the next
millisecond boundary; expiry checks do not fire before the requested deadline. A late drive call
makes the timer late.

The base retransmission timeout is fixed per socket at 300 ms by default. Backoff is capped at 60
seconds. `set_rto(smoltcp::time::Duration)` changes the base used the next time a retransmission or
probe timer is armed and survives reset/reconnect. It does not rewrite an already armed timer. Zero
or more than 60 seconds panics.

Delayed ACK defaults to 10 ms. `set_ack_delay(Some(duration))` changes the delay;
`set_ack_delay(None)` disables delayed ACK. Immediate ACK conditions apply either way. Disabling
delay affects newly scheduled ACKs; an armed delayed-ACK timer keeps its deadline. Egress must run
to transmit the ACK.

`ack_now()` sends a due ACK at the next egress instead of after the delay. If the socket has
received in-order data it has not acknowledged, the next `send` or `turn` sends one ACK for all of
it, alone or on data the application wrote; otherwise the call does nothing. Call it after draining
the socket, before the `send` that ends the iteration:

```rust
let received = stack.receive(now, BUDGET)?;
let socket = stack.tcp_mut(&handle);
while let Some(frame) = socket.recv()? {
    // consume frame.payload()
}
socket.ack_now();
let sent = stack.send()?;
```

TimeWait has a 10-second close timer. Its expiry is processed only by egress (`send` or `turn`)
after an ingress drive call has supplied the time. Established connections have no keepalive or
idle expiry; the application owns those deadlines.

TCP timestamp options are not negotiated or emitted. Peer timestamp offers are ignored.

## TCP

### Build and admit a socket

Pass receive and transmit byte capacities and an optional MSS cap to `add_tcp`:

```rust
use dpdk_smoltcp::smoltcp::socket::tcp;

let config = tcp::Config {
    rx_capacity: 65536,
    tx_capacity: 65536,
    mss_cap: Some(1460),
};
let handle: TcpHandle = stack.add_tcp(config)?;
stack.tcp_mut(&handle).set_ack_delay(None);
stack.listen(&handle, 7000)?;
```

`rx_capacity` sets a byte capacity without allocating a payload byte ring. Received payload stays in
owned RX mbufs until the application drains and drops it. The byte capacity sets the advertised
window and window scale; the admitted frame count also limits how much the socket can hold. After
admission the Stack allocates a TX byte ring of `tx_capacity` bytes for unacknowledged stream data.

Each received segment uses its own buffer unless it is a small in-order one appended to the last
frame, so a peer sending many tiny segments can fill a socket's buffers before its byte window;
refused segments are counted by `rx_refused_segments()`.

The config's `mss_cap` limits the advertised MSS and outgoing segment payloads. `None` applies no
application cap; local MTU and peer MSS apply regardless. The cap survives reset/reconnect and
cannot be changed after admission. `set_initial_window(bytes)` sets Cubic's initial congestion
window for the handshake and survives reset/reconnect. The default is 1048576 bytes. Set it before
connect/listen. The peer's advertised window limits transmission. `set_rto` takes
`smoltcp::time::Duration`; `set_ack_delay` takes `Option<smoltcp::time::Duration>` (see Time rules).

`add_tcp(config) -> Result<TcpHandle, AddTcpError>` returns the config unchanged if TCP slots are
full or RX admission fails. Configure the admitted socket through `stack.tcp_mut(&handle)`, then
call `stack.connect` or `stack.listen`. Admission alone leaves the socket closed.

### Handles

`TcpHandle` and `UdpHandle` own their socket's place in the Stack. They are not `Copy`, `Clone`,
`Default`, or `Send`. Every accessor borrows the handle: `tcp(&h)`, `tcp_mut(&h)`, `connect(&h, ..)`,
`listen(&h, ..)`, `udp(&h)`, `udp_mut(&h)`, `udp_send(&h, ..)`, `udp_send_with(&h, ..)`.
`remove_tcp(h)` and `remove_udp(h)` consume the handle, so use after removal does not compile. Using
a handle with a Stack that did not create it panics. Handles may outlive the Stack; dropping them
afterwards does nothing.

Dropping a handle queues cleanup. The Stack processes the queue at the start of its next `turn`,
`receive`, `send`, `add_tcp`, `add_udp`, or `remove_tcp`; `flush`
does not process it, and `poll_at` reports the current time while it is non-empty. A dropped UDP
handle frees its port binding, queued datagrams, and RX budget. A dropped TCP handle closes the
connection like Linux `close()`:

| State at drop | Result |
| --- | --- |
| Unread in-order data queued (SynReceived through LastAck) | Data discarded; Closed; one RST attempt. |
| Listen | Closed, nothing sent. |
| SynSent | Closed, nothing sent. |
| SynReceived, no data | Closed; one RST attempt. |
| Established / CloseWait, no data | FIN after queued TX bytes (FinWait1 / LastAck). |
| FinWait1, FinWait2, Closing, LastAck, no data | Close continues. |

An orphan's RST is attempted once during egress and not retried on failure (for example no TX
capacity). The orphan keeps its slot, so `add_tcp` can return `SocketsFull`, until it is Closed with
its remote endpoint cleared (for an abortive drop, after egress attempts the RST); the next cleanup
call then frees the slot and budget. In FinWait1 or FinWait2, acceptable new payload or an
out-of-order FIN makes an orphan reply RST and close. An orphan in FinWait2 closes after 60 s; an
orphan that receives the peer FIN waits the usual 10 s in TimeWait. An orphan closes silently at an
RTO or zero-window-probe expiry once its backoff count reaches 8 (Linux `tcp_orphan_retries`);
zero-window ACKs that neither advance nor reopen the window do not reset that count. A socket whose
handle is owned retries without limit.

### Connect and listen

The active-open shape in `binance-feed` is:

```rust
let endpoint = IpEndpoint::new((*target.addr.ip()).into(), target.addr.port());
stack.connect(&handle, endpoint, local_port)?;
```

`Stack::connect(&handle, remote, local)` supplies the interface context. `remote` converts to
`IpEndpoint`; `local` converts to `IpListenEndpoint`. The local port must be nonzero; there is no
ephemeral-port allocator. Omitting the local address lets the interface choose its IPv4 source
address. Success enters `State::SynSent`; drive the Stack until `state()` is `Established` or the
application gives up. A returned connect error leaves the socket unchanged.

For passive open, call `stack.listen(&handle, local_port)` or supply an `IpListenEndpoint`. An
unspecified listen address matches the interface address; an explicit address filters incoming SYNs.
TCP and ICMP sent to a broadcast or multicast address are dropped without a reply, as on Linux.
Success enters `State::Listen`. Listening again on the same endpoint while already in Listen
succeeds without resetting it; listening on an otherwise open socket errors.

Multiple TCP sockets can listen on the same local port; there is no TCP `PortInUse` error. For a
new SYN, an exact connection tuple wins before listener lookup. A SYN without ACK whose sequence
number is beyond a matching TimeWait socket's receive-next position resets that socket and goes to
an available matching listener. Listener lookup selects the lowest socket slot whose listen port
and optional address match.

An accepted SYN changes that listening socket itself to `SynReceived` and installs the local/remote
tuple. The final handshake ACK changes it to `Established`. There is no separate accepted socket,
accept queue, or `accept()` call, so one listener serves one connection at a time. Add more
listening sockets to accept concurrent connections. The echo caller re-arms a closed socket with
`Stack::listen`. `is_open()` is false for Closed and TimeWait; `is_active()` also excludes Listen.
Neither means Established; check `state()`.

### Drain received frames

TCP receive is drain-only. `recv() -> Result<Option<TcpFrame>, tcp::RecvError>` removes the next
whole in-order frame; `Ok(None)` means no in-order data is queued. Out-of-order bytes become drainable
after their gaps are filled. There is no byte-oriented read, peek, or partial consume.

```rust
loop {
    let socket = stack.tcp(&handle);
    if !socket.can_recv() && socket.may_recv() {
        break;
    }
    let Some(frame) = stack.tcp_mut(&handle).recv()? else {
        break;
    };
    parse(frame.payload());
    // frame drops here, returning its RX mbuf
}
```

`TcpFrame` owns its RX mbuf. `payload()` gives `&[u8]`, `payload_mut()` gives `&mut [u8]`, and
`rx_timestamp()` gives the raw hardware stamp (see Hardware RX timestamps). A frame stays valid after
socket removal, handle drop, or Stack teardown, but it occupies the socket's frame budget, and
therefore the receive window, until dropped. Copy bytes out if a parser needs them longer. Dropping
a frame that makes a window update due queues the socket for a readiness check, so `poll_at`
reports the current time and the next egress attempts to send the update, subject to TX capacity.

A frame can contain several wire segments: an in-order payload of at most 64 bytes, measured after
window and overlap trimming, can be copied into the last queued undrained frame if it ends at the
new payload's start and has enough tailroom. The incoming mbuf is then returned immediately.
Otherwise the payload keeps its own frame. Neither frame boundaries nor wire segments delimit
application messages. `recv_queue()` counts all queued
in-order bytes; `can_recv()` tests whether that count is positive. After peer FIN, queued frames
drain first; then `recv` returns `RecvError::Finished`. `RecvError::InvalidState` means the receive
half is unavailable without a clean EOF (for example reset, or before the connection is
established), and received data may be truncated. Queued frames remain drainable after a state
change.

`crates/stack-stream`'s `StackStream::new(&mut stack, handle)` wraps one Established or CloseWait
socket as nonblocking `std::io::Read`/`Write` for byte-stream protocols (rustls, tungstenite). Read
copies drained frames into the caller's buffer, keeping a partly copied frame for the next read; no
data gives `WouldBlock`, clean EOF gives `Ok(0)` (also when a peer RST follows the peer FIN), and a peer reset without a
prior FIN gives `ConnectionReset` once buffered bytes are drained. Write maps
a full send buffer to `WouldBlock`, a peer reset to `ConnectionReset`, and our own close or abort
(FinWait1 through TimeWait, and Closed without a peer reset) to `BrokenPipe`. Both use
`tcp::Socket::reset_by_peer()`, true when an acceptable peer RST closed the connection (not one
arriving in TimeWait, where our close came first) and cleared by `connect`/`listen`. The
stream owns the handle; `stack()` or `parts()` reach the Stack to drive it, and `into_parts()`
returns the handle, discarding any partly read frame.

### Send stream bytes

`send` exposes the largest contiguous free region of the TX byte ring. Its closure returns
`(enqueued_bytes, result)`. Returning more than the exposed slice length panics. Ring wrap can make
that slice smaller than total free space. Repeat if more bytes remain and space is available.

`send_slice(&data) -> Result<usize, tcp::SendError>` copies as many bytes as fit into the TX ring,
down to zero. Keep and retry the suffix. `can_send()` means the transmit half is open and its byte
ring has space, not that the peer or congestion window allows a frame now. `may_send()` is true in
Established and CloseWait. `send` and `send_slice` enqueue bytes without calling the PMD; run
`Stack::send` or `turn` to build and flush TCP frames. There is no Nagle delay: a short write is
eligible at the next egress, subject to the peer window, congestion window, and TX resources.
Delayed ACK is independent. `send_queue()` includes unacknowledged data; `send_capacity()` is
byte-ring capacity.

### Close, abort, remove, and access

`close()` closes the transmit half. In Established it enters FinWait1; in CloseWait it enters
LastAck. Queued stream bytes precede FIN. Receive can continue until the peer closes its half. In
SynReceived it aborts, sending one RST, because the peer is not synchronized for a FIN. In Listen it
stops listening; in SynSent it enters Closed. In closing states it does nothing. Keep driving to
send FIN and process replies, and run egress at the TimeWait close deadline (see Time rules).

`abort()` enters Closed immediately. If a connection tuple is present, the next egress attempts to
emit one RST, subject to TX capacity, and forgets the tuple after successful emission. A fresh closed
socket or unconnected listener has no remote endpoint to reset. To send the RST, drive egress before removing or reconnecting the
socket. `abort` itself does not transmit or discard queued receive frames.

`remove_tcp(handle)` removes the socket immediately, freeing the slot and budget, and returns
nothing. It discards queued receive data and sends neither FIN nor RST. Frames already drained stay
valid and count against admission until dropped. To close gracefully instead, `close()` and keep
driving, or drop the handle.

Neither `abort`, `remove_tcp`, nor a handle drop cancels TCP frames already in the shared pending
FIFO. They remain eligible for later flushes, subject to PMD acceptance.

`Stack::tcp(&handle)` reads state, queues, endpoints, and counters and marks nothing.
`tcp_mut(&handle)` schedules a readiness check before `poll_at` or egress; use it for drains and
changes. Do not swap the socket behind `tcp_mut` with one from another `TcpSet` or Stack.

## UDP

### Bind and optionally connect

`add_udp(UdpConfig) -> Result<UdpHandle, AddUdpError>` binds one local port exclusively. TCP and UDP
have separate socket sets; UDP exclusivity is between UDP sockets. There is no UDP local-address
field. Reception uses the Stack's IPv4 address and recognized broadcasts.

```rust
let handle = stack.add_udp(UdpConfig {
    port: 1234,
    rx_queue: 32,
    tx_checksum: true,
    broadcast: false,
})?;
let peer = IpEndpoint::new(Ipv4Address::new(192, 0, 2, 1).into(), 4321);
stack.udp_mut(&handle).connect(peer)?;
```

`port: u16` and `rx_queue: usize` must be nonzero. `rx_queue` limits the total datagrams retained by
that socket, including datagrams held by the application. `tx_checksum: bool` selects software UDP
checksum generation when TX UDP offload is absent. A false value writes zero. `broadcast: bool`
permits sending to broadcast destinations; it does not filter broadcast reception. There is no
multicast. `UdpSocket::connect(peer)` validates a unicast IPv4 address and nonzero port, then
stores the peer. The address check is not subnet-aware: with `192.0.2.2/24`, connecting to
`192.0.2.255:4321` succeeds, but sending requires `broadcast: true`. There is no handshake. The
peer is the default destination and filters received datagrams by source address and port.
Calling it again changes the peer; invalid input keeps the previous one. Queued datagrams are not
purged. `peer()` reads the optional peer, and `config()` reads the socket configuration.

### Send datagrams

`udp_send(&handle, to: Option<IpEndpoint>, payload: &[u8])` copies one payload into a frame.
`udp_send_with(&handle, to, len: usize, fill)` supplies the payload slice in the TX mbuf for in-place
filling. It runs at the interface's stored time, without reading a clock.

```rust
stack.udp_send_with(&handle, Some(peer), 5, |buffer| {
    buffer.copy_from_slice(b"hello");
})?;
let sent = stack.flush()?;
```

Use `to: None` with a connected socket, or supply a destination for an unconnected socket. An
explicit destination on a connected socket must equal its peer. UDP has no socket TX byte ring: a
successful call queues the whole datagram frame in the shared pending FIFO. Zero-length payloads are
allowed. Payload length must be at most path MTU minus 28 (1472 at MTU 1500); there is no
fragmentation. Every error is returned before `fill` runs. `NeighborPending` can queue an ARP
request but drops the datagram; flush, receive ARP replies, and retry. `WouldBlock` means no TX
packet or pending slot is available; flush and retry. Flush at least every `StackConfig::tx_pending`
sends. The pending FIFO is shared with TCP and ingress replies and keeps frame-building order:
TCP bytes written before a UDP call do not go first unless TCP egress runs. Keep calling `receive`
or `turn` in a send loop to accept ARP replies and advance time.

### Receive and remove

`stack.udp_mut(&handle).recv() -> Option<UdpDatagram>` removes the oldest queued datagram. `None`
means the queue is empty. The datagram owns its RX mbuf; its payload remains valid until it is
dropped, even after socket removal, handle drop, or Stack teardown.

Fragmented IPv4 datagrams are dropped without reassembly, before UDP receive counters are updated.

```rust
let datagram = stack.udp_mut(&handle).recv().unwrap();
let source = datagram.src();
let destination = datagram.dst_addr();
let stamp = datagram.rx_timestamp();
let payload = datagram.payload();
drop(datagram);
```

`src()` returns `IpEndpoint`, including source port; `dst_addr()` returns `Ipv4Address`;
`rx_timestamp()` returns the raw hardware stamp, 0 for none. `payload()` gives `&[u8]`, and
`payload_mut()` gives `&mut [u8]`. A held datagram consumes receive credit even when
`rx_queued() == 0`. Datagrams arriving at the credit limit are dropped and counted; UDP does not
backpressure the sender. `udp_counters()` reads Stack-wide receive counts; `udp(&handle).stats()`
reads socket counts. `remove_udp(handle)` consumes the handle, frees queued datagrams, unbinds the
port, and releases the budget immediately; dropping the handle does the same at the next cleanup
call (see Handles). Held datagrams remain charged until dropped. Do not replace a socket through
`udp_mut`.

Neither `remove_udp` nor a handle drop cancels datagram frames already in the shared pending FIFO.
They remain eligible for later flushes, subject to PMD acceptance.

## Hardware RX timestamps

Set `Offloads { rx_timestamp: true, .. }` to request DPDK's `RTE_ETH_RX_OFFLOAD_TIMESTAMP`. It is
off by default. `Port::open` refuses it with `InvalidSettings("PMD lacks the requested RX timestamp
offload")` if the PMD does not advertise the capability, then registers DPDK's RX timestamp dynamic
field; a registration failure returns `PortError::Dpdk`. There is no fallback to software time.

Each received packet the PMD flags as stamped carries the PMD's raw `u64` unchanged; an unflagged
packet, or any packet with the offload off, reports 0. Zhida converts nothing and never reads a
clock. Read it with `UdpDatagram::rx_timestamp()` or `TcpFrame::rx_timestamp()`. A TCP frame reports
the stamp of the segment that created it; small in-order segments appended into it keep that earlier
stamp, so a frame's stamp can predate some of its bytes.

The unit and clock are the PMD's: ENA reports ns on the device clock (Amazon Time Sync PHC),
`net_af_packet` reports ns of the kernel socket stamp, and `net_pcap` does not advertise the offload.
[crates/nic-runner/README.md](../crates/nic-runner/README.md) lists which real NICs offer it under
DPDK 25.11.3, and [section 4](../crates/nic-runner/README.md#4-timestamps) shows how the runner
reports stamps when `rx_timestamps` is enabled in the config.

## Counters and observability

### Drive results and Port rejection

`Turn` fields describe one `turn` or `receive` call:

| Field | Type | Meaning |
| --- | --- | --- |
| `rx_received` | `usize` | Packets accepted into staging by this call's RX burst. |
| `rx_rejected` | `usize` | Unsupported RX mbufs released by the Port. |
| `rx_ipv4_checksum_bad` | `usize` | RX packets dropped for a BAD IPv4-header checksum verdict. |
| `rx_processed` | `usize` | Staged packets handed to smoltcp in this call. |
| `rx_staged` | `usize` | Packets left staged after ingress. |
| `rx_blocked` | `bool` | Ingress lacked reply capacity while packets remained staged. |
| `tx_accepted` | `usize` | Frames accepted by the PMD across this call's flushes. |
| `tx_pending` | `usize` | Frames pending after this call. |

`rx_processed` can exceed `rx_received` when old staging is drained. It includes packets smoltcp
drops; it is not an application delivery count. `receive` includes its initial and post-ingress
flushes; `turn` includes its initial and final flushes.

`Sent` has `tx_accepted: usize` and `tx_pending: usize`. For `send`, acceptance is from its final
flush; for `flush`, it is from that flush. To account for a split iteration, add
`received.tx_accepted + sent.tx_accepted` and use `sent.tx_pending` as the final pending count.

`RxBurst` reports `accepted`, `rejected`, and `rx_ipv4_checksum_bad`. The Port imports only its own
RX pool's direct, unique, single-segment mbufs with valid lengths and no external buffer, and frees
and counts other mbufs separately from checksum drops. There is no cumulative Port rejection getter;
accumulate the per-call counts.

### TCP and UDP counters

Read TCP counters without scheduling work:

```rust
let socket = stack.tcp(&handle);
let retransmits = socket.retransmits();
let losses = socket.loss_events();
let window = socket.congestion_window();
```

`retransmits() -> u64` counts successful sequence-space emissions beginning below the highest
sequence number already sent. Data, SYN, FIN, and repeated probe bytes can count; pure ACKs and
failed emissions do not. `loss_events() -> u64` counts fast-retransmit entries and the first RTO
expiry since the oldest unacknowledged sequence advanced. Further RTO expiries in that episode do
not add events until an ACK advances it.

Both counters survive abort and other closes until socket reset runs, such as connect/listen,
TimeWait expiry, or a peer reset that re-arms Listen. `congestion_window() -> usize` reports Cubic's
current window in bytes. It is separate from the peer window and TX ring space. Also inspect
`state`, endpoints, `send_queue`, `recv_queue`, `recv_room`, capacities, and `rx_refused_segments`.
The latter is a `u32` count that saturates at its maximum. `Stack::tcp_counters() -> TcpCounters`
has one cumulative `u64` field, `rx_checksum_bad`: TCP segments rejected by software checksum
verification.

`Stack::ipv4_dropped()` counts malformed IPv4 packets, software IPv4 checksum failures, and rejected fragments before transport processing.

`UdpCounters` fields are cumulative `u64` receive counts for the UDP set:

| Field | Meaning |
| --- | --- |
| `rx_no_port` | Validated UDP packets for an unbound destination port. |
| `rx_checksum_bad` | Bad nonzero UDP checksums found in software. |
| `rx_malformed` | UDP packet/header length validation failures. |
| `rx_not_unicast` | Destinations rejected by UDP destination validation. |

These counters count packets reaching the UDP handler, not every frame rejected earlier by Ethernet,
IPv4, or the Port. RX-offload IPv4-header BAD drops appear in `Turn::rx_ipv4_checksum_bad`; an
offload L4 BAD verdict leaves the packet to software verification, which counts here if it fails.
UDP checksum zero is accepted. Recognized broadcast destinations are
accepted; multicast is rejected. An unbound port is dropped without an ICMP port-unreachable
response. `UdpSocketStats` has cumulative `u64` fields `rx_delivered`, `rx_dropped_full`, and
`rx_dropped_peer`. Delivery means queued successfully, not read by the application. The full count
includes credit exhaustion from held datagrams; the peer count records connected-socket source
mismatches. `rx_queued()` reports only datagrams in the queue. Removing and re-adding a UDP
socket starts new socket stats; Stack-wide counters remain.

## Errors and panics

### Startup and Port errors

`EalError::EmptyArguments` rejects missing argv, `ArgumentCountTooLarge { count }` rejects a count
that does not fit DPDK's C argument arithmetic, and `InteriorNul { argument, position }` identifies
an argument containing NUL. `Initialization { return_code, errno }` carries a returned DPDK
initialization failure. `os_random_seed` returns `std::io::Error` on entropy-file open or read
failure.

`PortOpenError` has `cause: PortError`, `rollback_error: Option<PortError>`, and `retained:
Option<Port>`. A retained owner must be cleaned up with its dependencies alive. `PortError` variants
are:

| Variant | When returned |
| --- | --- |
| `OwnerMismatch { expected, actual }` | Open/cleanup sees a different lcore identity. |
| `InvalidSettings(reason)` | Requested or read-back device settings are unacceptable. |
| `Pool { direction, error }` | RX or TX production pool creation failed. |
| `Dpdk { operation, code }` | A checked DPDK setup/cleanup call returned nonzero. |
| `OutstandingBuffers { rx, tx }` | Close cannot release pools with live buffers. |
| `NotReady` | Bursts attempted after incomplete setup or cleanup began. |

`InvalidSettings` includes zero descriptors/bursts, unavailable queues, MTU limits, insufficient
data rooms, unsupported or changed offloads, invalid adjusted descriptors, and scattered RX. A pool
error contains `PoolCreateError`: `CacheDisabled`, `DataRoomTooSmall { provided, minimum }`, `Dpdk {
errno }`, or `OwnerCacheUnavailable { lcore_id }`. A valid lcore-local production cache is required.

### Stack admission and drive errors

`StackError::InvalidConfig(reason)` covers configuration validation and negative start time.
`IpMtuBelowIpv4Minimum { mtu }` rejects MTU below 68 during creation (68-87 is `InvalidConfig`). `TxPoolTooSmall { count,
required }` rejects a TX pool below `tx_reserve` during creation. `TimeWentBackwards { last, now
}` rejects an earlier ingress-drive time before doing work. `Port(error)` propagates a Port
burst/flush error. `Stack::new` returns its Port with the error; drive methods return the error
directly. `AddTcpError::SocketsFull(config)` means all
TCP slots are occupied. `RxPoolTooSmall { config, required, pool }` means admission would exceed the
RX pool count. Both return the unchanged config.
`AddUdpError::Full` means all UDP slots are occupied, including when UDP is disabled. `PortInUse`
means that local UDP port is already bound. `InvalidConfig(reason)` rejects port zero or receive
queue zero. `RxPoolTooSmall { required, pool }` rejects the shared RX requirement. The pool check
runs before UDP config/slot/port checks, so a request with multiple problems can report pool
insufficiency first.

### Socket errors

`tcp::ConnectError::InvalidState` means the socket is already open. `Unaddressable` covers zero
local/remote port, unspecified remote or explicit local address, unavailable source address
selection, or mismatched address versions. `Stack::connect` returns `AddressInUse` when a
socket holds the same local and remote endpoints, including while closing or in TIME-WAIT.
Closed sockets and listeners do not reserve an exact tuple. Different remote endpoints may share a
local port. Success does not promise reachability.

`tcp::ListenError::Unaddressable` means port zero. `InvalidState` means an open socket that is not
already listening on that same endpoint. Duplicate local TCP listen ports do not produce an error.

`tcp::SendError::InvalidState` means the transmit half is not open. A full byte ring returns success
with zero enqueued bytes instead. `tcp::RecvError::Finished` means clean peer FIN with no queued
frames left; `InvalidState` means the receive half is unavailable otherwise. An open receive half
with no data returns `Ok(None)` instead of an error.

`UdpConnectError::Invalid` rejects a non-unicast/non-IPv4 peer or port zero. `UdpSendError` reports
whole-datagram send failures:

| Variant | When returned |
| --- | --- |
| `NoDestination` | No explicit destination and no connected peer. |
| `PeerMismatch` | Explicit destination differs from the connected peer. |
| `Unaddressable` | Invalid destination or broadcast without send permission. |
| `TooLarge` | Payload exceeds the path IP MTU toward the destination minus 28 (the Port IP MTU minus 28 without a smaller `StackConfig::paths` rule). |
| `NoRoute` | Destination outside the subnet and no gateway configured. |
| `NeighborPending` | Next-hop address resolution has not completed. |
| `WouldBlock` | Pending capacity or a TX packet is unavailable. |

UDP invalid destinations include unspecified or multicast addresses, our own interface address, port
zero, and broadcast without `broadcast: true`. `WouldBlock` is checked before neighbor lookup, so it
can hide an unresolved route or neighbor until capacity returns. UDP receive reports drops through
counters, not per-read errors.

### Panics and recovery

These panic:

- using a handle with a Stack that did not create it
- a TCP `send` callback reporting more enqueued bytes than exposed
- TCP admission with receive capacity above 1 GiB; admission or budget sizing with `mss_cap: Some(0)`
- `set_initial_window(0)`, `set_rto(Duration::ZERO)` or RTO above 60 seconds, `set_ack_delay` above
  60 seconds, `set_hop_limit(Some(0))`
- `rx_mbuf_budget` and `rx_pool_count` below MTU 68
- overflow in pool-count/reserve arithmetic, frame-budget conversions, or timer arithmetic near the
  integer limit; excessive `neighbor_capacity` at startup
- a TX-done cleanup failure other than `-ENOTSUP` when a drive operation allocates a TX packet
- with TX checksum offload, the PMD's checksum preparation refusing a frame during flush (Zhida does
  not validate frame headers there)
- a panicking UDP fill callback, including ordinary slice bounds

A panic unwinding out of `turn`, `receive`, `send`, or `flush` leaves the Stack unusable: after
catching it, only drop the Stack or call `into_port`.

## Shutdown

For graceful TCP shutdown, `close` (or drop the handle) and keep driving until the desired state and
TX drain. Stack drop/`into_port` sends no pending FIN, RST, TCP bytes, or UDP datagrams.
`Stack::into_port(self) -> Port` drops sockets and interface, releases staged, pending, and spare
packets, and returns the Port. Handles dropped afterwards do nothing. TCP frames and UDP datagrams
held by the application survive it. Drop those on the owner thread before closing the Port.

The tap driver calls `stack.into_port().try_close()` and checks its result. `try_close(self) ->
Result<(), (Port, PortError)>` returns the owner for cleanup/retry.

Cleanup marks the Port unready, stops/closes the ethdev, then checks pool in-use counts.
`OutstandingBuffers { rx, tx }` refuses pool destruction. Return all application-owned buffers and
drain caller-owned rings, then retry `try_close` on the returned owner. Other cleanup failures
return the owner too. If close released the device ID while returning an error, backing is
retained for good and subsequent closes return that recorded error. Dropping after refused cleanup
retains backing and prints a diagnostic. After successful close, remove caller-created vdevs/rings.
Keep EAL and its owner identity alive until every buffer has returned.

## Where to look next

- [crates/netconf-open/examples/tcp_client.rs](../crates/netconf-open/examples/tcp_client.rs): the
  `open` path end to end. Load a config, size and open, connect, receive and send, close, check
  `try_close`.
- `crates/nic-runner`: the real-NIC runbook and `zhida-nic`, which calls `open` and handles each
  `OpenError` variant (`src/main.rs`, sizing in `src/nic.rs`). Also lists RX timestamp support per NIC.
- `crates/binance-feed`: bookTicker over TCP, TLS and WebSocket, with application deadlines. It sets up
  by hand through tap-echo's driver, not through `open`.
- `crates/tap-echo`: EAL/vdev/Port setup by hand, bounded echo I/O, drive loop, and explicit teardown.
- `crates/stack-stream`: nonblocking `Read`/`Write` adapter over a drained TCP socket.
- `crates/ws-autobahn`: `StackStream` with tungstenite client/server integration.
- `crates/memif-bench`: pool sizing, queued drive calls, stream workloads, and in-place UDP sending.
- [docker/README.md](../docker/README.md): Linux DPDK test setup and commands.
