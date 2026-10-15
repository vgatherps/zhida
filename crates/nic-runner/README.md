# zhida-nic: real-NIC runbook

`zhida-nic` runs one Zhida Stack on one NIC port, one core, one process. It has three modes:
`info` prints what the NIC offers and exits; `sockperf-server` answers kernel `sockperf` 3.10 clients over
UDP and TCP the way `sockperf server` does; `feed` connects to the Binance TLS feed through the gateway.
Every result line on stdout starts with `zhida-nic:`. DPDK's EAL and driver messages go to stderr, so
capture both streams (`2>&1 | tee`).

The host needs the test NIC bound to vfio-pci and hugepages reserved. The bound port disappears from the
kernel, so the host needs a separate management interface.

The DUT runs Zhida on the test port. The peer is a second Linux machine on the same L2 segment (same
subnet, same VPC subnet on EC2) running kernel sockperf clients. Two ports of one machine also work if the
peer port is in its own network namespace (`ip netns add peer; ip link set <if> netns peer`); otherwise the
kernel routes the traffic locally.

Applications use the same host setup (sections 1, 2, 3 and 3a) and build on `zhida_open::open`; start
from [crates/netconf-open/examples/tcp_client.rs](../netconf-open/examples/tcp_client.rs) and
[docs/USAGE.md](../../docs/USAGE.md).

## 1. Which PMD, and what it offers
The image builds net/ena, net/intel/{ixgbe,i40e,ice} and net/af_packet. `lspci -nn -s <BDF>` tells which:
Intel 82599/X520/X540/X550 = ixgbe, X710/XL710/XXV710 = i40e, E810 = ice, Amazon ENA = ena.
Mellanox/NVIDIA ConnectX (mlx5) is not built: it needs rdma-core in the image, and the mlx5 kernel driver
stays bound (no vfio-pci).

RX hardware timestamps (`rx_timestamps` in the config, DPDK RX offload bit 14) in DPDK 25.11.3:
- ice (E810): offered. Values are ns on the NIC's PTP clock.
- ena: offered when the device reports timestamp support (newer instance types); `info` shows it.
  Values are ns on the device's clock, with an undocumented epoch (see [section 4](#4-timestamps)).
- ixgbe, i40e: not offered (their PMDs have IEEE 1588 PTP packet stamping only); Port open refuses
  `rx_timestamps: true`.
- af_packet: offered, ns of kernel CLOCK_REALTIME at socket receive (software time, not the NIC).

Per-PMD setup:
- ice needs its DDP package (`/lib/firmware/intel/ice/ddp/ice.pkg`, from the linux-firmware package or
  Intel). Without it the port fails to initialize and stderr says so. In docker, mount the host's
  `/lib/firmware` (section 3).
- ena on EC2: use a secondary ENI for DPDK; the primary ENI (device number 0) stays the management
  interface and carries SSH, IMDS and DNS. `zhida-netconf discover --aws` refuses the primary ENI and fills
  in the ENI's private IPv4, subnet, gateway (subnet base + 1, the VPC router) and MTU rules from IMDS.
  Security groups must allow UDP/TCP 11111-11130 between DUT and peer. Without an IOMMU (every non-metal
  instance), bind with `--noiommu`. ENA forces TX MULTI_SEGS on; Zhida accepts that bit and refuses any
  other offload the driver forces on.
- ENA LLQ needs write combining on the device BAR, which mainline vfio-pci does not provide (required on
  6th-generation Nitro and later). Install the patched module from
  https://github.com/amzn/amzn-drivers/tree/master/userspace/dpdk/README.md before binding. The tool cannot
  detect it; the ENA PMD's stderr lines about LLQ show it, and a warning that LLQ is disabled means the
  module lacks write combining.
- AWS does not auto-assign a public IPv4 when an instance has more than one network interface. Internet
  destinations (the Binance feed) need an Elastic IP on the DPDK ENI or a NAT gateway route;
  `discover --aws` warns when `public-ipv4s` is empty.
- Leave ENA Express off on the DPDK ENI. With it on, UDP needs a lower MTU for its SRD headers; add a path
  rule with that MTU for the affected prefix.
- In-VPC traffic is MTU 9001; the internet gateway forwards 1500 only. `discover --aws` writes MTU 9001
  plus a 9001 rule per VPC CIDR and `0.0.0.0/0 → 1500`; a TCP connect then advertises MSS 8961 inside the
  VPC and 1460 to the internet. The peer's interface must be at 9001 for jumbo frames. UDP `--msg-size`
  above path MTU - 28 needs fragmentation, which Zhida does not do.

## 2. Discover, bind (root), unbind
`zhida-netconf` (crate `zhida-netconf`) writes the config file that `zhida-nic` and `zhida_open::open`
read, and moves the NIC between its kernel driver and vfio-pci. It does not need DPDK. Build it on the
host with `cargo build --locked --release -p zhida-netconf`; the binary is `target/release/zhida-netconf`.
The commands below assume it is on your `PATH`. `bind` and `unbind` run as root.
```
zhida-netconf discover --interface <iface> --aws -o dut.json      # EC2; no root
zhida-netconf discover --interface <iface> -o dut.json            # elsewhere; gateway from /proc/net/route
zhida-netconf check dut.json                                      # prints the config and the path table
```
`discover` reads the interface's IPv4/prefix, MAC, MTU, PCI address, PCI id, kernel driver and NUMA node
from the kernel (and with `--aws` the ENI facts from IMDSv2), writes the file and prints
`wrote dut.json`; warnings start `zhida-netconf: warning:`. With several IPv4 addresses on the
interface it asks for `--ipv4 ADDR`. Running it over an existing file keeps hand-added path rules and
prints `changed: <key>` for each changed field. Off EC2, if the interface has no default route in the main
table, set `gateway` by hand (or null for on-link peers only). `--aws` inside docker needs
`--network host` (IMDS answers only one hop by default). Edit `offloads`, `rx_timestamps`, `descriptors`,
`eal` and ENA's `devargs` (e.g. `llq_policy=1`) as needed; `check` must exit 0.

Hugepages: 1 GiB of 2 MiB pages on the NIC's NUMA node.
```
echo 512 > /sys/devices/system/node/node<N>/hugepages/hugepages-2048kB/nr_hugepages
mkdir -p /dev/hugepages && { mountpoint -q /dev/hugepages || mount -t hugetlbfs nodev /dev/hugepages; }
```

Bind (root):
```
zhida-netconf bind dut.json --dry-run        # prints every write, changes nothing
zhida-netconf bind dut.json                  # IOMMU hosts
zhida-netconf bind dut.json --noiommu        # no IOMMU (EC2 non-metal): taints the kernel
```
Before any write it checks: root; the device at `pci` has the recorded `pci_id` and, while kernel-bound,
the config's MAC; the interface carries no route except its own connected subnet (so a default or
management route is never cut); every other device in the IOMMU group is unbound or on vfio-pci; without
an IOMMU, `--noiommu` is given. Each refusal is one line naming the reason and writes nothing. It then
prints each sysfs write (`write '<value>' > <path>`), runs `modprobe vfio-pci` if needed, the hugepages
free per NUMA node, and `<BDF> bound to vfio-pci (<group>)`. A device already on vfio-pci prints
`already bound` and exits 0. If the vfio bind fails, it puts the device back on its kernel driver and
reports both errors. Running `bind` (or `unbind`) again finishes an interrupted bind.

Unbind (root), after the run:
```
zhida-netconf unbind dut.json
```
It gives the device back to `kernel_driver` and prints `<BDF> on <driver>; IPv4 <addr> is back on
<iface>` (or `is not back`). It does not restore addresses or routes; the host's network manager owns
that.

Pick one core for Zhida on the NIC's NUMA node, ideally isolated (`isolcpus=`), and not core 0. Zhida
busy-polls that core at 100%.

## 3. Building and running
Docker: build the image on the DUT, from the repository root (native architecture; x86_64 and arm64 use
the same Dockerfile):
```
make docker-image DOCKER_IMAGE=zhida-dpdk-test:local
```
Run (the cargo volumes keep the build between runs; the first run compiles for a few minutes):
```
nic() {
  docker run --rm -it --privileged --network host --cpuset-cpus="${ZHIDA_CPU:-2}" \
    -v /dev/hugepages:/dev/hugepages -v /dev/vfio:/dev/vfio -v /lib/firmware:/lib/firmware:ro \
    -v "$PWD:/work" -w /work \
    -v zhida-cargo-registry:/usr/local/cargo/registry -v zhida-nic-target:/work/target \
    zhida-dpdk-test:local cargo run --locked --release -p nic-runner -- "$@"
}
```
Native: install DPDK 25.11.3 under /opt/dpdk with the meson options in docker/Dockerfile, Rust 1.93,
clang and lld, then use the Dockerfile's `PKG_CONFIG_PATH`, `LD_LIBRARY_PATH` and `RUSTFLAGS`, and
`cargo build --locked --release -p nic-runner`; run the binary as
`taskset -c <core> target/release/zhida-nic ...`.

Arguments: `zhida-nic --config FILE <MODE> [MODE OPTIONS]`. The config contains the network, device,
offload and EAL settings. `open` chooses EAL's main lcore from the one CPU allowed by `taskset` or Docker's
CPU set, and rejects a process that may run on more than one CPU. An argument error prints `error:` and the
usage text. Exit codes: 0 ok, 2 packet buffers held at close (a Zhida bug), 3 argument, setup or run error
(the `error:` line says which), 101 panic.

A vdev config for a local tap is:
```
{
  "version": 1,
  "device": {"vdev": "net_tap0,iface=cdnic0"},
  "mac": null,
  "ipv4": "192.0.2.2/24",
  "gateway": null,
  "mtu": 1500,
  "paths": [],
  "offloads": {"rx_checksum": false, "tx_tcp_checksum": false, "tx_udp_checksum": false},
  "rx_timestamps": false,
  "descriptors": 1024,
  "eal": {"file_prefix": "zhida-tap", "extra": ["--no-huge", "-m", "128", "--no-shconf"]}
}
```

For a real NIC use the `dut.json` that `discover` wrote (section 2). On EC2 it looks like this (ENA, MTU
9001, VPC 10.0.0.0/16); the configured MAC must equal the device's. Put PMD devargs in `devargs`; EAL
options not supplied by `open` belong in `eal.extra`.
```
{
  "version": 1,
  "device": {
    "pci": "0000:00:06.0",
    "pci_id": "1d0f:ec20",
    "devargs": "llq_policy=1",
    "kernel_driver": "ena",
    "kernel_interface": "eth1",
    "numa_node": 0
  },
  "mac": "0a:12:34:56:78:9a",
  "ipv4": "10.0.1.23/24",
  "gateway": "10.0.1.1",
  "mtu": 9001,
  "paths": [{"prefix": "10.0.0.0/16", "mtu": 9001, "why": "vpc"},
            {"prefix": "0.0.0.0/0", "mtu": 1500, "why": "default"}],
  "offloads": "auto",
  "rx_timestamps": false,
  "descriptors": 1024,
  "eal": {"file_prefix": "zhida", "extra": []}
}
```
With a `gateway`, `open` resolves its MAC before the mode starts (one ARP request per second; after 3 s
of silence it fails with `gateway <ip> unresolved after <time>`) and the report prints
`gateway: <ip> at <mac> after <n> ms`.

### 3a. info
Copy `dut.json` to `dut-offloads.json`, replace `"auto"` with explicit checksum booleans, and set
`rx_timestamps` as needed in the copy.
```
nic --config dut.json info 2>&1 | tee info.log
nic --config dut-offloads.json info 2>&1 | tee info-offloads.log
```
A good run exits 0 and prints `driver`, the RX/TX offload capability bits, `max_rx_pktlen`, MTU limits,
`mac`, pool counts, `descriptors`, link speed/duplex/status `up`, and `port_close: ok`. For each offload
it prints the requested bit and the reason. A refused offload fails Port open with
`port_open_error: InvalidSettings("PMD lacks the requested ... offload")` naming it; turn that setting off.

### 3b. feed
```
nic --config dut.json feed --seconds 30 --print 10 2>&1 | tee feed.log
```
Options: `--host H` (default data-stream.binance.vision), `--port P` (9443), `--path P`
(/ws/btcusdt@bookTicker), `--print N` (10), `--seconds S` (30). The kernel resolves the host name before
the NIC is taken. Output is the TLS summary, up to N bookTicker messages, a message count and the
update-id range. Success requires at least one message and successful read/close.

### 3c. sockperf-server
```
nic --config dut.json sockperf-server --udp-ports 11111 --tcp-port 11112 \
    --tcp-connections 16 --report-seconds 5 2>&1 | tee server.log
```
Defaults: UDP port 11111, no TCP, 8 TCP connections, `--seconds 0` (run until SIGINT/SIGTERM),
`--report-seconds 5`. The server prints `zhida-nic: server: ready` when it accepts traffic. On Ctrl-C
(SIGINT) or SIGTERM it attempts TCP FIN close with a five-second deadline, prints `report: final`
and the counters, and closes the port. Successful shutdown exits 0; a close timeout or pending UDP
reply fails with exit 3, and outstanding buffers at port close cause exit 2.

Peer clients are sockperf 3.10 (the image has it at /opt/sockperf/bin/sockperf; distro 3.7 is
wire-identical). To build it: `git clone -b 3.10 https://github.com/Mellanox/sockperf && cd sockperf &&
./autogen.sh && ./configure && make`.
```
sockperf ping-pong  -i 10.0.0.2 -p 11111 -t 10 --msg-size 64 --data-integrity
sockperf ping-pong  -i 10.0.0.2 -p 11112 --tcp -t 10 --msg-size 64 --data-integrity
sockperf under-load -i 10.0.0.2 -p 11111 -t 10 --msg-size 64 --mps 10000
```
A clean run ends with `# dropped messages = 0; # duplicated messages = 0; # out-of-order messages = 0`.
`--data-integrity` makes ping-pong compare every reply byte with what it sent; it does not work with
under-load, which compares against the latest sent message. UDP `--msg-size` above MTU - 28 (1472 at
1500) needs IP fragment reassembly, which Zhida does not do.

Zhida keeps reply order per socket, not across sockets, so give each sockperf client process its own UDP
port (`--udp-ports 11111,11112,...`) and at least as many TCP connections as clients. A client feed file
(`-f`, lines `U:IP:PORT` or `T:IP:PORT`) cannot be combined with `-i`, `-p` or `--tcp`.

The server report (every `--report-seconds` and at exit) has per protocol `received`, `replies`,
`malformed`; TCP `accepted`/`closed`; per UDP socket its counters and `pending` (1 while a reply waits for
the TX queue or for ARP); per TCP slot its state, `retransmits`, `loss_events`, `rx_refused_segments`;
`udp_counters`; `stack_totals` including `tx_pending`; `eth_stats` (`ipackets`, `opackets`, `imissed`,
`ierrors`, `oerrors`, `rx_nombuf`); and with `rx_timestamps` enabled, the timestamp lines (section 4).
TCP `accepted` and `closed` count slot state changes seen between visits, so a reset in SYN-RECEIVED
followed by a new SYN within one poll turn counts once.

`sockperf_merge.py` in this directory combines the `--full-log` files of several under-load clients run
with `--full-rtt`. It reads the per-reply sample rows (`packet, txTime(sec), rxTime(sec), rtt(usec)`), the
`--mps=` parameter line and the `[Valid Duration] ... SentMessages=` line, and prints the combined sample
count, p50/p99/p99.9/max in µs, offered msg/s (sum of `--mps`) and achieved msg/s (sum of SentMessages
over the valid run time). It rejects a log whose sample rows do not match its `ReceivedMessages`.
`python3 sockperf_merge.py --self-test` checks it. Only every `--reply-every`-th message (default 100) is
a sample, so a 20 s run at 10 000 msg/s gives about 2 000 samples; p99.9 needs at least 10 000 samples, so
use `--reply-every 10` or a longer `-t` at low rates.

## 4. Timestamps
With `rx_timestamps` enabled (only if bit 14 is set in `rx_offload_capa`), the report has
`udp_timestamps: datagrams= stamped= first= last= decreases=` and `tcp_timestamps: segments= ...`. TCP
counts receive-buffer segments, not wire packets. A small in-order arrival appended to the previous buffer
keeps that buffer's earlier stamp, so `stamped == segments` does not mean every packet was stamped.
`decreases` counts stamps lower than the previous one on the same socket and is not an error. TCP
decreases appear after wire reordering or loss recovery. UDP decreases appear with af_packet when two CPUs
deliver frames at once (the kernel stamps before the ring slot is claimed). `first` and `last` are raw
driver units (section 1). To find the epoch, take `date +%s%N` on the DUT right after a periodic report and
compare it with that report's `last`.
