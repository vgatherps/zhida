"""Deterministic exact-tuple SYN regressions; run with two tap-echo listeners.

target/debug/tap-echo --listeners 2 -- python3 fuzz/scapy/r9.py
"""

import argparse
import os
import select
import sys
import time

import oracles
import seqmath
from fuzz_tcp import wait_iface_up
from wire import ACK, FIN, PSH, RST, SYN, Builder, Env

EXCHANGE_BOUND = 0.2  # shorter than the initial SYN-ACK retransmission timeout (1 s)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Peer:
    def __init__(self, port, isn):
        self.port, self.isn = port, isn
        self.seq, self.ack = seqmath.add(isn, 1), 0

    def syn(self, build):
        return build.tcp(self.port, self.isn, 0, SYN, 65535, options=(("MSS", 1460),))

    def send(self, build, flags=ACK, payload=b""):
        frame = build.tcp(self.port, self.seq, self.ack, flags, 65535, payload=payload)
        self.seq = seqmath.add(self.seq, len(payload) + bool(flags & FIN))
        return frame


class Scenarios:
    def __init__(self, build, exchange):
        self.build, self.exchange = build, exchange

    def synack(self, peer, segments):
        require(len(segments) == 1, f"expected one SYN-ACK, got {segments}")
        seg = segments[0]
        require((seg.dport, seg.flags, seg.ack, seg.payload) ==
                (peer.port, SYN | ACK, peer.seq, b""), f"bad SYN-ACK: {seg.describe()}")
        return seg

    def handshake(self, peer):
        seg = self.synack(peer, self.exchange([peer.syn(self.build)]))
        peer.ack = seqmath.add(seg.seq, 1)
        require(not self.exchange([peer.send(self.build)]), "handshake ACK got a reply")

    def close(self, peer):
        segments = self.exchange([peer.send(self.build, FIN | ACK)])
        require(segments and segments[-1].flags == FIN | ACK, f"missing FIN: {segments}")
        for seg in segments:
            require(seg.dport == peer.port and seg.ack == peer.seq and not seg.payload
                    and seg.flags in (ACK, FIN | ACK), f"bad close: {seg.describe()}")
        peer.ack = seqmath.add(segments[-1].seq, 1)
        require(not self.exchange([peer.send(self.build)]), "final ACK got a reply")

    def echo(self, peer):
        payload = b"original connection"
        segments = self.exchange([peer.send(self.build, payload=payload)])
        received = b""
        for seg in segments:
            require(seg.dport == peer.port and seg.flags in (ACK, ACK | PSH)
                    and seg.ack == peer.seq, f"bad echo: {seg.describe()}")
            if seg.payload:
                require(seg.seq == peer.ack, f"echo sequence changed: {seg.describe()}")
                received += seg.payload
                peer.ack = seqmath.add(peer.ack, len(seg.payload))
        require(received == payload, f"echo differs: {received!r}")
        require(not self.exchange([peer.send(self.build)]), "echo ACK got a reply")

    def cleanup(self, peer):
        require(not self.exchange([peer.send(self.build, RST | ACK)]), "RST got a reply")

    def established_duplicate_syn(self):
        first, live = Peer(40000, 1000), Peer(40001, 5000)
        self.handshake(first)
        self.handshake(live)
        self.close(first)
        segments = self.exchange([live.syn(self.build)])
        require(len(segments) == 1, f"expected one challenge ACK, got {segments}")
        seg = segments[0]
        require((seg.dport, seg.flags, seg.seq, seg.ack, seg.payload) ==
                (live.port, ACK, live.ack, live.seq, b""),
                f"expected live connection's challenge ACK: {seg.describe()}")
        self.echo(live)
        self.cleanup(live)

    def lost_synack(self):
        first, live = Peer(40002, 1000), Peer(40003, 5000)
        self.handshake(first)
        lost = self.synack(live, self.exchange([live.syn(self.build)]))
        self.close(first)
        resent = self.synack(live, self.exchange([live.syn(self.build)]))
        require((resent.seq, resent.ack, resent.flags, resent.window,
                 resent.options_raw, resent.payload) ==
                (lost.seq, lost.ack, lost.flags, lost.window, lost.options_raw, lost.payload),
                f"immediate SYN-ACK differs from lost one: {resent.describe()}")
        live.ack = seqmath.add(resent.seq, 1)
        require(not self.exchange([live.send(self.build)]), "handshake ACK got a reply")
        self.echo(live)
        require(not self.exchange([], wait=1.1), "another half-open connection retransmitted")
        self.cleanup(live)


class Wire:
    def __init__(self, env, sock):
        self.env, self.sock, self.build = env, sock, Builder(env)

    def exchange(self, frames, wait=0.05):
        for frame in frames:
            self.sock.send(frame)
        deadline = time.monotonic() + wait
        segments = []
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.sock], [], [], max(0, deadline - time.monotonic()))
            if not ready:
                break
            _, frame, _ = self.sock.recv_raw()
            if frame is None:
                continue
            kind, parsed, errors = oracles.check_frame(frame, self.env)
            require(not errors, f"malformed output: {errors}")
            if kind == "arp":
                if parsed.tpa == self.env.tester_ip:
                    self.sock.send(self.build.arp_reply(parsed))
            else:
                segments.append(parsed)
        require(not frames or time.monotonic() < deadline + EXCHANGE_BOUND,
                "packet exchange exceeded immediate-reply bound")
        return segments


def main():
    from scapy.arch.linux import L2Socket
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=("R9a", "R9b"))
    args = parser.parse_args()
    env = Env.from_environ(os.environ)
    wait_iface_up(env.iface)
    sock = L2Socket(iface=env.iface, promisc=False)
    try:
        wire = Wire(env, sock)
        scenarios = Scenarios(wire.build, wire.exchange)
        if args.only in (None, "R9a"):
            scenarios.established_duplicate_syn()
            print("PASS R9a: challenge ACK and continued echo", flush=True)
        if args.only in (None, "R9b"):
            scenarios.lost_synack()
            print("PASS R9b: immediate identical SYN-ACK, one connection echoes", flush=True)
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
