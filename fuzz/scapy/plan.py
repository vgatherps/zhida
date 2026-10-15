"""Connection plans: everything connection i does comes from random.Random(f"{seed}:{i}").

A plan fixes the client's SYN options, ISN, port, payload, segment boundaries, pacing, ACK
policy, close style and impairments; the engine (conn.py) applies it to whatever Zhida does,
so a replay repeats the schedule, not the timing. Impairments are keyed by stream offset ("the
first transmission of the segment carrying byte X"), not by packet index, so they do not depend
on how the window split the stream. Weights favor what a modern Linux peer in a data center
sends: a quarter of the plans are disruptive, adding one to three mutations (mutate.py) to
the same kind of connection.
"""

import hashlib
import random
from dataclasses import asdict, dataclass, field

import mutate
import seqmath

LINUX_MSS = 1460
PROBE_PAYLOAD = 1024
MAX_PAYLOAD = 98304
DISRUPTIVE_SHARE = 0.25
PACING_TOTAL_MS = 2000


def weighted(rng, pairs):
    values, weights = zip(*pairs)
    return rng.choices(values, weights)[0]


@dataclass
class Plan:
    seed: str
    index: str
    kind: str  # "preserving" (impairments only) or "disruptive" (>= 1 mutation)
    sport: int
    isn: int
    ts_base: int
    syn: dict  # mss, wscale (None = absent), sack, ts, order (option names)
    rcv_buffer: int
    sizes: list  # preferred segment sizes from the stream start; [] = full MSS
    pacing: dict  # mode burst | paced (gap_ms) | bursts (n, gap_ms)
    ack: dict  # every (segments per ACK), delay_ms (delayed-ACK timer)
    psh: str  # last | every
    close: str  # after_echo | after_send | with_data
    tx: list = field(default_factory=list)  # {"at": offset, "do": action, ...}
    rx_drop: list = field(default_factory=list)  # echo offsets whose first arrival is ignored
    drop_peer_fin: bool = False  # ignore Zhida's first FIN
    drop_own_fin: bool = False  # first transmission of the fuzzer's FIN is lost
    ack_drop: list = field(default_factory=list)  # indices of pure ACKs lost (0 = handshake)
    dup_acks: list = field(default_factory=list)  # {"at": echo offset, "count": n}
    stall: dict = None  # {"at": echo offset, "ms": d}: the app stops reading
    mutations: list = field(default_factory=list)  # mutate.draw specs (disruptive only)
    budget: float = 3.0  # disruptive: seconds before the teardown (quiesce, ACK, RST)
    deadline: float = 10.0
    payload: bytes = field(default=b"", repr=False)

    def to_json(self):
        d = asdict(self)
        del d["payload"]
        d["payload_len"] = len(self.payload)
        d["payload_sha256"] = hashlib.sha256(self.payload).hexdigest()
        return d

    def impairments(self):
        names = [t["do"] for t in self.tx]
        names += ["rx_drop"] * len(self.rx_drop) + ["ack_drop"] * len(self.ack_drop)
        names += ["dup_acks"] * len(self.dup_acks)
        names += ["drop_peer_fin"] * self.drop_peer_fin + ["drop_own_fin"] * self.drop_own_fin
        names += ["stall"] * (self.stall is not None)
        return names

    def mutation_names(self):
        return [f"{m['class']}.{m['kind']}@{m['target']}" for m in self.mutations]


def _syn_options(rng):
    ts = rng.random() < 0.9
    sack = rng.random() < 0.9
    wscale = weighted(rng, [(7, 60), (None, 10), ("any", 30)])
    if wscale == "any":
        wscale = rng.randint(0, 14)
    mss = weighted(rng, [(1460, 70), (1448, 5), (1400, 8), (1380, 5), (536, 5), (8960, 7)])
    present = ["mss"] + ["sack"] * sack + ["ts"] * ts + ["wscale"] * (wscale is not None)
    if rng.random() < 0.85:
        order = ["linux"]
    else:
        order = present[:]
        rng.shuffle(order)
    return {"mss": mss, "wscale": wscale, "sack": sack, "ts": ts, "order": order}


def _payload_len(rng):
    lo, hi = weighted(rng, [((0, 0), 5), ((1, 100), 20), ((101, 1448), 25),
                            ((1449, 16384), 30), ((16385, 65536), 15),
                            ((65537, MAX_PAYLOAD), 5)])
    return rng.randint(lo, hi)


def _sizes(rng, length):
    mode = weighted(rng, [("mss", 50), ("random", 25), ("small", 10), ("writes", 15)])
    if mode == "mss" or length == 0:
        return []
    top = {"random": 1448, "small": 64, "writes": 8192}[mode]
    sizes, total = [], 0
    while total < length:
        n = rng.randint(1, top)
        sizes.append(n)
        total += n
    return sizes


def _base(rng, seed, index, kind):
    length = _payload_len(rng)
    syn = _syn_options(rng)
    buffer = weighted(rng, [(131072, 40), (65535, 25), (262144, 15), (16384, 10), (4096, 10)])
    if syn["wscale"] is None:
        buffer = min(buffer, 65535)
    if rng.random() < 0.2:
        # ISN just below 2**32 so the sequence space wraps inside the connection.
        isn = seqmath.MOD - rng.randint(1, 2 * length + 2000)
    else:
        isn = rng.getrandbits(32)
    mode = weighted(rng, [("burst", 50), ("paced", 30), ("bursts", 20)])
    pacing = {"mode": mode}
    if mode == "paced":
        pacing["gap_ms"] = round(rng.uniform(0.2, 3.0), 2)  # between segments
    elif mode == "bursts":
        pacing.update(n=rng.randint(2, 10), gap_ms=round(rng.uniform(1.0, 20.0), 2))
    plan = Plan(
        seed=str(seed), index=str(index), kind=kind,
        sport=rng.randrange(32768, 61000), isn=isn, ts_base=rng.getrandbits(32), syn=syn,
        rcv_buffer=buffer, sizes=_sizes(rng, length), pacing=pacing,
        ack={"every": weighted(rng, [(1, 20), (2, 55), (4, 15), (8, 10)]),
             "delay_ms": weighted(rng, [(40, 90), (rng.randint(1, 200), 10)])},
        psh=weighted(rng, [("last", 70), ("every", 30)]),
        close=weighted(rng, [("after_echo", 50), ("after_send", 35), ("with_data", 15)]),
        payload=rng.randbytes(length))
    if mode != "burst":
        # Pacing gaps add up over many small segments (seed 2 connection 273: 1665 segments
        # of up to 64 B, a 19 ms gap every 2, ran past the 10 s deadline); keep their sum
        # within PACING_TOTAL_MS.
        segments = len(plan.sizes) or length // 1448 + 1
        gaps = segments if mode == "paced" else segments // pacing["n"] + 1
        pacing["gap_ms"] = min(pacing["gap_ms"], PACING_TOTAL_MS / gaps)
    return plan


def _impairments(rng, plan):
    length = len(plan.payload)
    if length:
        for _ in range(weighted(rng, [(0, 50), (1, 25), (2, 15), (rng.randint(3, 5), 10)])):
            do = weighted(rng, [("drop", 30), ("bad_tcp_csum", 10), ("bad_ip_csum", 5),
                                ("dup", 20), ("reorder", 20), ("overlap", 15)])
            t = {"at": rng.randrange(length), "do": do}
            if do == "reorder":
                t["hold"] = rng.randint(1, 3)
            if do == "overlap":
                t["back"] = rng.randint(1, 2000)
            plan.tx.append(t)
        if rng.random() < 0.2:
            plan.rx_drop = sorted(rng.randrange(length) for _ in range(rng.randint(1, 2)))
        if rng.random() < 0.1:
            plan.dup_acks = [{"at": rng.randrange(length), "count": rng.randint(1, 4)}]
        if rng.random() < 0.1:
            plan.stall = {"at": rng.randrange(length), "ms": rng.randint(20, 400)}
    plan.drop_peer_fin = rng.random() < 0.05
    plan.drop_own_fin = rng.random() < 0.05
    if rng.random() < 0.15:
        plan.ack_drop = sorted(set(rng.randrange(11) for _ in range(rng.randint(1, 3))))


def make_plan(seed, index):
    rng = random.Random(f"{seed}:{index}")
    disruptive = rng.random() < DISRUPTIVE_SHARE
    plan = _base(rng, seed, index, "disruptive" if disruptive else "preserving")
    _impairments(rng, plan)
    if disruptive:
        count = weighted(rng, [(1, 60), (2, 30), (3, 10)])
        plan.mutations = mutate.draw(rng, len(plan.payload), count)
    return plan


def probe_plan(seed, number):
    """Clean liveness probe: Linux SYN, 1 KiB echo, FIN close, no impairments, 5 s bound."""
    rng = random.Random(f"{seed}:probe:{number}")
    return Plan(
        seed=str(seed), index=f"probe{number}", kind="preserving",
        sport=rng.randrange(32768, 61000), isn=rng.getrandbits(32),
        ts_base=rng.getrandbits(32),
        syn={"mss": LINUX_MSS, "wscale": 7, "sack": True, "ts": True, "order": ["linux"]},
        rcv_buffer=131072, sizes=[], pacing={"mode": "burst"},
        ack={"every": 2, "delay_ms": 40}, psh="last", close="after_echo", deadline=5.0,
        payload=rng.randbytes(PROBE_PAYLOAD))
