#!/usr/bin/env python3
"""Seeded Scapy TCP fuzzer against Zhida's echo server; runs as tap-echo's tester.

    tap-echo -- python3 -B fuzz/scapy/fuzz_tcp.py [--seed S] [--connections N] [--only I]

One AF_PACKET socket (Scapy's L2 socket) on ZHIDA_IFACE; the fuzzer answers ARP for
TESTER_IP itself and plays a Linux-like TCP client (conn.py), one connection at a time with a
100 ms quiet gap before every SYN (one listener, and smoltcp has no accept backlog).
Connection i follows plan.make_plan(seed, i); a clean probe connection runs after every 25
connections and at the end. Exit 0 only if every oracle passed; on failure the frames of the
failing and the previous connection go to target/fuzz/fail-s<seed>-c<i>.pcap, the plans to
.json, the replay command to stdout, and the exit status is 1.
"""

import argparse
import errno
import fcntl
import json
import logging
import os
import select
import socket
import struct
import sys
import time
from collections import Counter

import oracles
from conn import Conn
from plan import make_plan, probe_plan
from wire import Builder, Env

QUIET_GAP = 0.1
QUIET_GAP_LIMIT = 3.0  # a gap that does not come within this long fails the run
PROBE_EVERY = 25
IFACE_UP_TIMEOUT = 10.0
OUT_DIR = "target/fuzz"
RCVBUF = 8 << 20
SIOCGIFFLAGS = 0x8913
IFF_UP = 0x1
SO_RCVBUFFORCE = 33
SOL_PACKET = 263
PACKET_STATISTICS = 6


def wait_iface_up(name):
    """tap-echo starts its tester before DPDK creates the netdev (as zhida_shim.c)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    request = struct.pack("16sH14s", name.encode(), 0, b"")
    deadline = time.monotonic() + IFACE_UP_TIMEOUT
    try:
        while time.monotonic() < deadline:
            try:
                reply = fcntl.ioctl(probe, SIOCGIFFLAGS, request)
                if struct.unpack("16sH", reply[:18])[1] & IFF_UP:
                    return
            except OSError as e:
                if e.errno != errno.ENODEV:
                    raise
            time.sleep(0.01)
    finally:
        probe.close()
    sys.exit(f"fuzz: {name} not up after {IFACE_UP_TIMEOUT} s")


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in frames:
            sec = int(ts)
            f.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(frame), len(frame)))
            f.write(frame)


class Runner:
    def __init__(self, env, sock, args):
        self.env = env
        self.sock = sock
        self.args = args
        self.build = Builder(env)
        self.stats = Counter()
        self.current = None
        self.previous = None
        self.frames = []
        self.previous_frames = []
        self.errors = []  # failures not owned by a connection's model
        self.last_tx = 0.0

    def send(self, frame, now):
        self.sock.send(frame)
        self.frames.append((time.time(), frame))
        self.last_tx = now

    def poll(self, until):
        """Handle timers and frames until `until` or the current connection is done. Due
        timers run before any frame is handled, including timers that come due while waiting
        for a frame (an expired deadline fails before a late frame
        can complete the connection; Conn.finish rejects a completion past the deadline that
        happens inside a drain), and a drain ends once a timer is due, so a continuous frame
        stream cannot starve them."""
        while not self.errors:
            conn = self.current
            now = time.monotonic()
            if conn is not None:
                conn.on_timer(now)
                if conn.phase == "done":
                    return
            if now >= until:
                return
            ready, _, _ = select.select([self.sock], [], [], max(0.0, self.wake(until) - now))
            if time.monotonic() >= self.wake(until):
                continue  # a timer came due while waiting: it runs before any frame
            while ready and not self.errors:
                _, frame, ts = self.sock.recv_raw()
                if frame is not None:  # None: one of our own frames
                    self.handle(frame, ts)
                if (conn is not None and conn.phase == "done") or \
                        time.monotonic() >= self.wake(until):
                    break
                ready, _, _ = select.select([self.sock], [], [], 0)

    def wake(self, until):
        """The earliest of `until` and the current connection's next timer."""
        conn = self.current
        deadline = conn.next_deadline() if conn is not None else None
        return until if deadline is None else min(until, deadline)

    def handle(self, frame, ts):
        self.frames.append((ts, frame))
        self.stats["check_frame"] += 1
        kind, parsed, errors = oracles.check_frame(frame, self.env)
        if errors:
            self.errors += [f"malformed output: {e}" for e in errors]
            return
        now = time.monotonic()
        if kind == "arp":
            if parsed.tpa == self.env.tester_ip:
                self.stats["fuzzer_arp_replies"] += 1
                self.send(self.build.arp_reply(parsed), now)
            return
        for conn in (self.current, self.previous):
            if conn is not None and parsed.dport == conn.plan.sport:
                conn.on_segment(parsed, now)
                if conn is self.previous and conn.failures:
                    self.errors += [f"previous connection {conn.plan.index}: {f}"
                                    for f in conn.failures]
                return
        self.errors.append(f"Zhida segment for port {parsed.dport}, neither the current nor "
                           f"the previous connection ({parsed.describe()})")

    def run(self, plan):
        """One connection after the quiet gap; returns its failures."""
        self.previous, self.previous_frames = self.current, self.frames
        self.current, self.frames = None, []
        gap_from = time.monotonic()
        while time.monotonic() < self.last_tx + QUIET_GAP and not self.errors:
            if time.monotonic() >= gap_from + QUIET_GAP_LIMIT:
                self.errors.append(f"no {QUIET_GAP} s without a fuzzer frame within "
                                   f"{QUIET_GAP_LIMIT} s before connection {plan.index}")
                break
            self.poll(min(self.last_tx + QUIET_GAP, gap_from + QUIET_GAP_LIMIT))
        if self.errors:
            return self.errors
        conn = Conn(plan, self.build, self.send, self.stats, time.monotonic())
        self.current = conn
        self.stats[f"connections_{'probe' if plan.index.startswith('probe') else plan.kind}"] += 1
        for name in plan.impairments():
            self.stats[f"planned_{name}"] += 1
        self.stats["planned_mutations"] += len(plan.mutations)
        conn.start(time.monotonic())
        self.poll(float("inf"))
        failures = conn.failures + self.errors
        dropped = self.socket_drops()
        if dropped:
            failures.append(f"the kernel dropped {dropped} frame(s) from the AF_PACKET socket "
                            f"during this connection; no oracle saw them")
        return failures

    def socket_drops(self):
        """Frames the kernel dropped from the socket since the previous call (reading
        PACKET_STATISTICS resets the counters; its received count includes the drops)."""
        received, dropped = struct.unpack(
            "II", self.sock.ins.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8))
        self.stats["socket_received"] += received
        self.stats["socket_dropped"] += dropped
        return dropped

    def report(self, wall):
        st = self.stats
        def group(prefix):
            items = sorted((k[len(prefix):], v) for k, v in st.items() if k.startswith(prefix))
            return ", ".join(f"{k} {v}" for k, v in items) or "none"
        print(f"connections: {group('connections_')}")
        print(f"impairments planned: {group('planned_')}")
        print(f"impairments applied: {group('impair_')}")
        print(f"mutation classes applied: {group('mutclass_')}")
        print(f"mutations applied: {group('mut_')}")
        print(f"mutations not applied, no-op: {group('mutnoop_')}")
        print(f"mutations not applied, target not reached: {group('mutunreached_')}")
        print(f"disruptive endings: {group('disruptive_')}")
        print(f"oracle checks: {group('check_')}")
        print(f"zhida: {group('zhida_')}")
        print(f"fuzzer: {group('fuzzer_')}")
        print(f"socket: {st['socket_received']} frames received, {st['socket_dropped']} dropped "
              f"by the kernel")
        print(f"wall time {wall:.1f} s")

    def fail(self, plan, failures, wall):
        os.makedirs(OUT_DIR, exist_ok=True)
        base = f"{OUT_DIR}/fail-s{self.args.seed}-c{plan.index}"
        write_pcap(f"{base}.pcap", self.previous_frames + self.frames)
        previous = self.previous.plan if self.previous is not None else None
        # A probe has no --only of its own: the plan before it is what broke Zhida.
        target = plan if plan.index.isdigit() else previous
        replay = f"target/debug/tap-echo -- python3 -B fuzz/scapy/fuzz_tcp.py --seed {self.args.seed}"
        replay += f" --only {target.index}" if target is not None and target.index.isdigit() \
            else f" --connections {self.args.connections}"
        with open(f"{base}.json", "w") as f:
            json.dump({"seed": self.args.seed, "connection": plan.index, "failures": failures,
                       "plan": plan.to_json(),
                       "previous_plan": previous.to_json() if previous else None,
                       "replay": replay}, f, indent=1)
        print(f"FAIL connection {plan.index} ({plan.kind}):")
        for failure in failures:
            print(f"  {failure}")
        self.report(wall)
        print(f"wrote {base}.pcap (this and the previous connection, both directions) "
              f"and {base}.json")
        print(f"replay: {replay}")
        if target is plan and previous is not None and previous.index.isdigit():
            print(f"        or, if connection {previous.index} left Zhida broken: "
                  f"--only {previous.index}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--seed", default="1")
    parser.add_argument("--connections", type=int, default=300)
    parser.add_argument("--only", type=int, help="run only connection I (then the end probe)")
    args = parser.parse_args()
    sys.stdout.reconfigure(line_buffering=True)

    env = Env.from_environ(os.environ)
    logging.getLogger("scapy").setLevel(logging.ERROR)
    import scapy
    from scapy.arch.linux import L2Socket
    if not scapy.__version__.startswith("2.5.0"):
        sys.exit(f"fuzz: Scapy {scapy.__version__}, expected 2.5.0 (docker/Dockerfile)")
    wait_iface_up(env.iface)
    sock = L2Socket(iface=env.iface, promisc=False)
    sock.ins.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, RCVBUF)

    indices = [args.only] if args.only is not None else list(range(args.connections))
    print(f"fuzz: seed {args.seed}, {len(indices)} connection(s)"
          f"{f' (only {args.only})' if args.only is not None else ''}, probe every "
          f"{PROBE_EVERY} and at the end, Scapy {scapy.__version__}")
    runner = Runner(env, sock, args)
    start = time.monotonic()
    schedule = []
    probes = 0
    for n, i in enumerate(indices):
        schedule.append(make_plan(args.seed, i))
        if (n + 1) % PROBE_EVERY == 0 and n + 1 < len(indices):
            schedule.append(probe_plan(args.seed, probes))
            probes += 1
    schedule.append(probe_plan(args.seed, probes))
    for plan in schedule:
        began = time.monotonic()
        failures = runner.run(plan)
        line = (f"c{plan.index} {plan.kind} {len(plan.payload)} B "
                f"{','.join(plan.impairments() + plan.mutation_names()) or '-'} "
                f"{time.monotonic() - began:.3f} s")
        print(line)
        if failures:
            runner.fail(plan, failures, time.monotonic() - start)
            return 1
    print(f"PASS seed {args.seed}: {len(indices)} connection(s), all oracles passed")
    runner.report(time.monotonic() - start)
    return 0


if __name__ == "__main__":
    sys.exit(main())
