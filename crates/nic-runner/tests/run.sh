#!/bin/sh
set -eu

fail() {
    echo "test-nic-runner: $*" >&2
    if [ -n "${server_log:-}" ] && [ -f "$server_log" ]; then cat "$server_log" >&2; fi
    exit 1
}

sockperf=/opt/sockperf/bin/sockperf
[ -x "$sockperf" ] || fail "missing sockperf executable: $sockperf"
command -v timeout >/dev/null || fail "missing timeout"
command -v taskset >/dev/null || fail "missing taskset"
command -v ip >/dev/null || fail "missing ip"

export TEST_TIMEOUT=${TEST_TIMEOUT:-600}
cpu=${DOCKER_CPUSET:-$(awk '/Cpus_allowed_list:/ {print $2}' /proc/self/status)}
case "$cpu" in *[!0-9]*|'') fail "runner requires one CPU; set DOCKER_CPUSET to one CPU number (got $cpu)" ;; esac

log_dir=$(mktemp -d /tmp/zhida-nic.XXXXXX)
server_pid=
client_pids=
server_log=
veth_created=no
stop_server() {
    kill -TERM "$server_pid" 2>/dev/null || :
    i=0
    while kill -0 "$server_pid" 2>/dev/null && [ "$i" -lt 80 ]; do
        i=$((i + 1))
        sleep 0.1
    done
    timed_out=no
    if kill -0 "$server_pid" 2>/dev/null; then
        timed_out=yes
        kill -KILL "$server_pid" 2>/dev/null || :
    fi
    rc=0
    wait "$server_pid" 2>/dev/null || rc=$?
    server_pid=
}

cleanup() {
    for pid in $client_pids; do kill "$pid" 2>/dev/null || :; done
    if [ -n "$server_pid" ]; then
        stop_server
    fi
    if [ "$veth_created" = yes ]; then ip link del vethc0 2>/dev/null || :; fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM

timeout --kill-after=10 "$TEST_TIMEOUT" cargo test --locked --manifest-path crates/sockperf-wire/Cargo.toml --lib sockperf
timeout --kill-after=10 "$TEST_TIMEOUT" cargo test --locked -p nic-runner --bin zhida-nic
timeout --kill-after=10 "$TEST_TIMEOUT" cargo build --locked -p nic-runner --bin zhida-nic
timeout --kill-after=10 "$TEST_TIMEOUT" python3 crates/nic-runner/sockperf_merge.py --self-test

run_info() {
    kind=$1
    config=$2
    info_log=$log_dir/$kind-info.log
    rc=0
    timeout --kill-after=10 "$TEST_TIMEOUT" taskset -c "$cpu" \
        target/debug/zhida-nic --config "$config" info >"$info_log" 2>&1 || rc=$?
    cat "$info_log"
    [ "$rc" -eq 0 ] || fail "$kind info exited $rc"
    for prefix in 'zhida-nic: driver: ' 'zhida-nic: link_status: up' 'zhida-nic: port_close: ok'; do
        grep -e "^$prefix" "$info_log" >/dev/null || fail "$kind info missing $prefix"
    done
}

write_config() {
    path=$1
    prefix=$2
    vdev=$3
    rx_timestamps=$4
    cat >"$path" <<EOF
{
  "version": 1,
  "device": {"vdev": "$vdev"},
  "mac": null,
  "ipv4": "192.0.2.2/24",
  "gateway": null,
  "mtu": 1500,
  "paths": [],
  "offloads": {
    "rx_checksum": false,
    "tx_tcp_checksum": false,
    "tx_udp_checksum": false
  },
  "rx_timestamps": $rx_timestamps,
  "descriptors": 1024,
  "eal": {
    "file_prefix": "$prefix",
    "extra": ["--no-huge", "-m", "128", "--no-shconf"]
  }
}
EOF
}

run_client() {
    label=$1
    shift
    log=$log_dir/$label.log
    if ! timeout --kill-after=10 "$TEST_TIMEOUT" "$sockperf" "$@" >"$log" 2>&1; then
        cat "$log" >&2
        fail "sockperf $label failed"
    fi
    if ! grep -F '# dropped messages = 0; # duplicated messages = 0; # out-of-order messages = 0' "$log" >/dev/null; then
        cat "$log" >&2
        fail "sockperf $label did not report zero dropped, duplicated and out-of-order messages"
    fi
    cat "$log"
}

wait_interface() {
    iface=$1
    i=0
    until ip link show "$iface" >/dev/null 2>&1; do
        if ! kill -0 "$server_pid" 2>/dev/null; then
            wait "$server_pid" || :
            server_pid=
            fail "server exited before $iface appeared; for af_packet, check that the net_af_packet PMD is installed"
        fi
        i=$((i + 1))
        [ "$i" -le 80 ] || fail "interface $iface did not appear within 8 seconds"
        sleep 0.1
    done
}

wait_ready() {
    i=0
    until grep -F 'zhida-nic: server: ready' "$server_log" >/dev/null; do
        if ! kill -0 "$server_pid" 2>/dev/null; then
            wait "$server_pid" || :
            server_pid=
            fail "server failed setup; for af_packet, check that the net_af_packet PMD is installed and offers RX TIMESTAMP"
        fi
        i=$((i + 1))
        [ "$i" -le 120 ] || fail "server did not become ready within 12 seconds"
        sleep 0.1
    done
}

check_final() {
    stamped=$1
    python3 - "$server_log" "$stamped" <<'PY'
import re
import sys

path, require_stamps = sys.argv[1:]
with open(path) as stream:
    text = stream.read()
marker = 'zhida-nic: report: final\n'
if marker not in text:
    sys.exit('test-nic-runner: server has no final report')
final = text.rsplit(marker, 1)[1]
for protocol in ('udp', 'tcp'):
    match = re.search(rf'^zhida-nic: {protocol}: received=(\d+) replies=(\d+) malformed=(\d+)', final, re.M)
    if not match or int(match[1]) == 0 or int(match[2]) == 0 or int(match[3]) != 0:
        sys.exit(f'test-nic-runner: {protocol} final report must have traffic, replies and zero malformed')
    if protocol == 'tcp':
        match = re.search(r'^zhida-nic: tcp: .* accepted=(\d+) closed=(\d+)', final, re.M)
        if not match or int(match[1]) != 4 or int(match[2]) != 4:
            sys.exit('test-nic-runner: tcp final report must have accepted=4 and closed=4')
    if require_stamps == 'yes':
        unit = 'datagrams' if protocol == 'udp' else 'segments'
        match = re.search(rf'^zhida-nic: {protocol}_timestamps: {unit}=(\d+) stamped=(\d+) first=(\d+) last=(\d+) decreases=(\d+)', final, re.M)
        if not match or int(match[1]) == 0 or match[1] != match[2] or int(match[3]) == 0 or int(match[4]) == 0:
            sys.exit(f'test-nic-runner: af_packet {protocol} must stamp every {unit}')
        # Decreases are reported but not checked. TCP stamps are one per
        # receive-buffer segment in stream order, so wire reordering or loss
        # recovery returns earlier-stamped data later. af_packet UDP stamps are
        # kernel receive times taken before the ring slot is claimed, so two CPUs
        # delivering veth frames at once (a migrating sender, concurrent clients)
        # can put a later stamp into the ring first.
PY
}

test_device() {
    kind=$1
    server_log=$log_dir/$kind-server.log
    if [ "$kind" = tap ]; then
        config=$log_dir/tap.json
        write_config "$config" nic-tap net_tap0,iface=cdnic0 false
        run_info "$kind" "$config"
        taskset -c "$cpu" target/debug/zhida-nic --config "$config" sockperf-server \
            --udp-ports 11111 --tcp-port 11112 --tcp-connections 2 --seconds 0 \
            >"$server_log" 2>&1 &
        server_pid=$!
        wait_interface cdnic0
        ip addr add 192.0.2.1/24 dev cdnic0
        ip link set cdnic0 up
    else
        ip link add vethc0 type veth peer name vethc1
        veth_created=yes
        ip addr add 192.0.2.1/24 dev vethc1
        # With TX checksum offload on (the veth default), kernel UDP and TCP
        # frames cross the veth with only the pseudo-header sum in the checksum
        # field. net_af_packet copies them unchanged, so Zhida counts them as
        # bad checksums and drops them; no UDP datagram or SYN gets through.
        # A real NIC's wire always carries complete checksums.
        ethtool -K vethc1 tx off >/dev/null
        ip link set vethc0 up
        ip link set vethc1 up
        # The server busy-polls the same single CPU as the kernel and four
        # concurrent clients, so it is descheduled for whole time slices; the
        # default 512-frame kernel ring then overflows (imissed) and sockperf
        # sees lost replies. 8192 frames hold a slice of the 10k msg/s load.
        afp=net_af_packet0,iface=vethc0,framecnt=8192
        config=$log_dir/af-packet.json
        write_config "$config" nic-af-packet "$afp" true
        run_info "$kind" "$config"
        taskset -c "$cpu" target/debug/zhida-nic --config "$config" sockperf-server \
            --udp-ports 11111 --tcp-port 11112 --tcp-connections 2 --seconds 0 \
            >"$server_log" 2>&1 &
        server_pid=$!
    fi
    wait_ready
    run_client "$kind-udp-ping" ping-pong --ip 192.0.2.2 --port 11111 -t 3 --msg-size 64 --data-integrity
    run_client "$kind-udp-load" under-load --ip 192.0.2.2 --port 11111 --mps 10000 -t 3 \
        --full-rtt --full-log "$log_dir/$kind-udp-load.full"
    merged=$(python3 crates/nic-runner/sockperf_merge.py "$log_dir/$kind-udp-load.full") ||
        fail "sockperf_merge.py could not read sockperf's --full-log"
    echo "$merged"
    echo "$merged" | grep -x 'unit: rtt usec' >/dev/null || fail "merged log is not full RTT"
    echo "$merged" | grep -x 'offered_mps: 10000' >/dev/null || fail "merged log lost --mps"
    echo "$merged" | grep '^samples: [1-9]' >/dev/null || fail "merged log has no samples"
    run_client "$kind-udp-mtu" ping-pong --ip 192.0.2.2 --port 11111 --msg-size 1472 -t 2 --data-integrity
    run_client "$kind-tcp-ping" ping-pong --ip 192.0.2.2 --port 11112 --tcp -t 3 --msg-size 64 --data-integrity
    run_client "$kind-tcp-load" under-load --ip 192.0.2.2 --port 11112 --tcp --mps 10000 -t 3
    client_pids=
    # Four clients at 2500 msg/s offer the same 10k msg/s as the single-client
    # runs. At 4 x 10k the debug-build server, sharing its one CPU with the
    # clients and the kernel, fell behind whenever the host was busy and up to
    # 15% of UDP requests never reached it (sockperf reported dropped replies).
    for n in 1 2; do
        (
            trap - EXIT INT TERM
            run_client "$kind-udp-concurrent-$n" under-load --ip 192.0.2.2 --port 11111 --mps 2500 -t 3
        ) &
        client_pids="$client_pids $!"
        (
            trap - EXIT INT TERM
            run_client "$kind-tcp-concurrent-$n" under-load --ip 192.0.2.2 --port 11112 --tcp --mps 2500 -t 3
        ) &
        client_pids="$client_pids $!"
    done
    failed=no
    for pid in $client_pids; do wait "$pid" || failed=yes; done
    client_pids=
    [ "$failed" = no ] || fail "concurrent sockperf clients failed"
    stop_server
    [ "$timed_out" = no ] || fail "server did not exit within 8 seconds after SIGTERM"
    [ "$rc" -eq 0 ] || fail "server exited $rc after SIGTERM"
    cat "$server_log"
    if [ "$kind" = tap ]; then check_final no; else check_final yes; fi
    if [ "$kind" = tap ]; then
        server_log=$log_dir/$kind-udp-only-server.log
        taskset -c "$cpu" target/debug/zhida-nic --config "$config" sockperf-server \
            --udp-ports 11111 --seconds 0 >"$server_log" 2>&1 &
        server_pid=$!
        wait_interface cdnic0
        ip addr add 192.0.2.1/24 dev cdnic0
        ip link set cdnic0 up
        wait_ready
        run_client "$kind-udp-only-ping" ping-pong --ip 192.0.2.2 --port 11111 -t 2 --msg-size 64 --data-integrity
        stop_server
        [ "$timed_out" = no ] || fail "server did not exit within 8 seconds after SIGTERM"
        [ "$rc" -eq 0 ] || fail "server exited $rc after SIGTERM"
        cat "$server_log"
        python3 - "$server_log" <<'PY'
import re
import sys

with open(sys.argv[1]) as stream:
    text = stream.read()
marker = 'zhida-nic: report: final\n'
if marker not in text:
    sys.exit('test-nic-runner: UDP-only server has no final report')
final = text.rsplit(marker, 1)[1]
match = re.search(r'^zhida-nic: udp: received=(\d+)', final, re.M)
if not match or int(match[1]) == 0:
    sys.exit('test-nic-runner: UDP-only final report must have received traffic')
PY

        # A reply that reaches NeighborPending stays on its UDP socket while ARP is unresolved.
        # Once ARP resolves, the same pending reply is sent exactly once.
        server_log=$log_dir/$kind-udp-arp-server.log
        taskset -c "$cpu" target/debug/zhida-nic --config "$config" sockperf-server \
            --udp-ports 11111 --seconds 0 --report-seconds 1 >"$server_log" 2>&1 &
        server_pid=$!
        wait_interface cdnic0
        i=0
        until mac=$(awk '/^zhida-nic: mac: / { print $3; exit }' "$server_log") && [ -n "$mac" ]; do
            kill -0 "$server_pid" 2>/dev/null || fail "ARP test server exited before printing its MAC"
            i=$((i + 1))
            [ "$i" -le 80 ] || fail "ARP test server did not print its MAC within 8 seconds"
            sleep 0.1
        done
        ip addr add 192.0.2.1/24 dev cdnic0
        ip link set cdnic0 arp off
        ip neigh replace 192.0.2.2 lladdr "$mac" dev cdnic0 nud permanent
        ip link set cdnic0 up
        wait_ready
        arp_ready=$log_dir/arp-ready
        arp_release=$log_dir/arp-release
        arp_client_log=$log_dir/arp-client.log
        python3 - "$arp_ready" "$arp_release" >"$arp_client_log" 2>&1 <<'PY' &
import os
import socket
import sys
import time

ready, release = sys.argv[1:]
request = bytearray(14)
request[8:10] = (3).to_bytes(2, "big")
request[10:14] = len(request).to_bytes(4, "big")
expected = request.copy()
expected[9] &= ~1
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("192.0.2.1", 0))
sock.settimeout(2.5)
sock.sendto(request, ("192.0.2.2", 11111))
try:
    sock.recvfrom(65535)
except TimeoutError:
    pass
else:
    sys.exit("ARP test received a reply while ARP was disabled")
open(ready, "w").close()
release_deadline = time.monotonic() + 10
while not os.path.exists(release):
    if time.monotonic() >= release_deadline:
        sys.exit("ARP test was not released")
    time.sleep(0.05)
replies = []
reply_deadline = time.monotonic() + 10
while True:
    remaining = reply_deadline - time.monotonic()
    if remaining <= 0:
        break
    sock.settimeout(remaining)
    try:
        replies.append(sock.recvfrom(65535)[0])
    except TimeoutError:
        break
if replies != [bytes(expected)]:
    sys.exit(f"ARP test expected one exact reply, got {len(replies)}")
PY
        arp_client_pid=$!
        client_pids=$arp_client_pid
        i=0
        until [ -f "$arp_ready" ]; do
            if ! kill -0 "$arp_client_pid" 2>/dev/null; then
                wait "$arp_client_pid" || :
                client_pids=
                cat "$arp_client_log" >&2
                fail "ARP test client exited before the pending report"
            fi
            i=$((i + 1))
            [ "$i" -le 80 ] || fail "ARP test client did not finish its no-reply check"
            sleep 0.1
        done
        grep -F 'zhida-nic: udp_socket: port=11111 pending=1 ' "$server_log" >/dev/null ||
            fail "ARP test has no periodic report with one pending reply"
        ip link set cdnic0 arp on
        : >"$arp_release"
        arp_client_rc=0
        wait "$arp_client_pid" || arp_client_rc=$?
        client_pids=
        if [ "$arp_client_rc" -ne 0 ]; then
            cat "$arp_client_log" >&2
            fail "ARP test client failed"
        fi
        stop_server
        [ "$timed_out" = no ] || fail "server did not exit within 8 seconds after SIGTERM"
        [ "$rc" -eq 0 ] || fail "server exited $rc after SIGTERM"
        cat "$server_log"
        python3 - "$server_log" <<'PY'
import re
import sys

with open(sys.argv[1]) as stream:
    text = stream.read()
marker = 'zhida-nic: report: final\n'
if marker not in text:
    sys.exit('test-nic-runner: ARP test server has no final report')
final = text.rsplit(marker, 1)[1]
if not re.search(r'^zhida-nic: udp: received=1 replies=1 malformed=0$', final, re.M):
    sys.exit('test-nic-runner: ARP test final UDP counts are not received=1 replies=1 malformed=0')
if not re.search(r'^zhida-nic: udp_socket: port=11111 pending=0 ', final, re.M):
    sys.exit('test-nic-runner: ARP test final report still has a pending reply')
PY
    fi
    if [ "$kind" = af_packet ]; then ip link del vethc0; veth_created=no; fi
    echo "test-nic-runner: $kind passed"
}

test_device tap
test_device af_packet
echo "test-nic-runner: logs in $log_dir"
