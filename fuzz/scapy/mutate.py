"""Mutation engine: disruptive changes to the fuzzer's own segments.

Frames are serialized valid first (wire.Builder, Scapy), then their bytes are changed here,
so Scapy never repairs a malformed field. Byte constructors change exactly one field (or,
for options and lengths, the header fields that describe them); `apply` then recomputes the
checksums as the receiver reads the mutated header (wire.fix_checksums), unless the
mutation is a bad checksum, so a mutated segment reaches Zhida's TCP logic instead of
dying at the checksum.

A mutation spec, drawn by `draw` into the plan, is {"class", "kind", "target", "p"}:
target "syn" (the first SYN), "ack" (the handshake ACK), "fin" (the first FIN) or a stream
offset (the first transmission of the data segment carrying it); p is a seeded 32-bit
number every value derives from.
"""

import struct
from dataclasses import dataclass
from typing import Callable

import seqmath
from wire import (ACK, CWR, ECE, FIN, IP_AT, IP_CSUM, IP_FRAG, IP_ID, IP_TOS, IP_TOTAL, IP_TTL,
                  OPT_MSS, OPT_SACK, OPT_SACK_PERM, OPT_TS, OPT_WSCALE, PSH, RST, SYN, TCP_ACK,
                  TCP_AT, TCP_CSUM, TCP_DOFF, TCP_FLAGS, TCP_SEQ, TCP_URP, TCP_WIN, URG,
                  fix_checksums)

DF, MF = 0x4000, 0x2000


# ---------------------------------------------------------------- byte constructors

def put(frame, at, fmt, value):
    out = bytearray(frame)
    struct.pack_into(fmt, out, at, value)
    return bytes(out)


def ip_ttl(frame, ttl):
    return put(frame, IP_AT + IP_TTL, "!B", ttl)


def ip_tos(frame, tos):
    return put(frame, IP_AT + IP_TOS, "!B", tos)


def ip_id(frame, ident):
    return put(frame, IP_AT + IP_ID, "!H", ident)


def ip_flags_frag(frame, value):
    """The 16-bit flags (DF 0x4000, MF 0x2000) and fragment offset field."""
    return put(frame, IP_AT + IP_FRAG, "!H", value)


def ip_ihl(frame, ihl):
    return put(frame, IP_AT, "!B", (frame[IP_AT] & 0xF0) | ihl)


def ip_total(frame, total):
    return put(frame, IP_AT + IP_TOTAL, "!H", total)


def ip_options(frame, options):
    """Insert IPv4 options (a 4-byte multiple, at most 40) after the 20-byte IP header; IHL
    and total length follow, the TCP header and payload stay byte-identical."""
    assert len(options) % 4 == 0 and len(options) <= 40
    total = struct.unpack_from("!H", frame, IP_AT + IP_TOTAL)[0]
    out = ip_ihl(frame[:TCP_AT] + options + frame[TCP_AT:], 5 + len(options) // 4)
    return ip_total(out, total + len(options))


def tcp_seq(frame, seq):
    return put(frame, TCP_AT + TCP_SEQ, "!I", seq)


def tcp_ack(frame, ack):
    return put(frame, TCP_AT + TCP_ACK, "!I", ack)


def tcp_flags(frame, flags):
    return put(frame, TCP_AT + TCP_FLAGS, "!B", flags)


def tcp_urgent(frame, pointer):
    return put(frame, TCP_AT + TCP_URP, "!H", pointer)


def tcp_window(frame, window):
    return put(frame, TCP_AT + TCP_WIN, "!H", window)


def tcp_doff(frame, doff):
    return put(frame, TCP_AT + TCP_DOFF, "!B", (doff << 4) | (frame[TCP_AT + TCP_DOFF] & 0x0F))


def corrupt_checksum(frame, at):
    """Flip bits of the 16-bit checksum at `at`: wrong for any content."""
    return put(frame, at, "!H", struct.unpack_from("!H", frame, at)[0] ^ 0x5A5A)


def options_region(frame):
    doff = frame[TCP_AT + TCP_DOFF] >> 4
    return TCP_AT + 20, TCP_AT + doff * 4


def tcp_options(frame, options):
    """Replace the option bytes (a 4-byte multiple, at most 40); data offset and IP total
    length follow, payload and every other field stay."""
    assert len(options) % 4 == 0 and len(options) <= 40
    start, end = options_region(frame)
    out = frame[:start] + options + frame[end:]
    out = tcp_doff(out, 5 + len(options) // 4)
    return ip_total(out, struct.unpack_from("!H", frame, IP_AT + IP_TOTAL)[0]
                    + len(options) - (end - start))


def _walk(frame):
    """Yield (kind, start, length) for each option up to EOL (the fuzzer's own clean
    options; NOPs have length 1)."""
    start, end = options_region(frame)
    i = start
    while i < end and frame[i] != 0:
        if frame[i] == 1:
            yield 1, i, 1
            i += 1
            continue
        yield frame[i], i, frame[i + 1]
        i += frame[i + 1]


def find_option(frame, kind):
    """(offset of the option's value, value length) in the frame, or None."""
    for k, at, length in _walk(frame):
        if k == kind:
            return at + 2, length - 2
    return None


def used_options(frame):
    """The option bytes up to the end of the last option, without EOL padding."""
    start, _ = options_region(frame)
    end = start
    for _, at, length in _walk(frame):
        end = at + length
    return frame[start:end]


def with_option(frame, kind, value):
    """Overwrite option `kind`'s value in place if present with that length, else append
    the option (NOP padded) after the existing ones."""
    found = find_option(frame, kind)
    if found is not None and found[1] == len(value):
        out = bytearray(frame)
        out[found[0]:found[0] + len(value)] = value
        return bytes(out)
    return tcp_options(frame, pad(used_options(frame) + bytes([kind, 2 + len(value)]) + value))


def pad(options):
    return options + b"\x01" * (-len(options) % 4)


def append_payload(frame, data):
    out = frame + data
    return ip_total(out, struct.unpack_from("!H", frame, IP_AT + IP_TOTAL)[0] + len(data))


def truncate(frame, length):
    """Cut the frame to `length` bytes and set the IP total length to match."""
    return ip_total(frame[:length], length - IP_AT)


def payload_xor(frame, lo, hi):
    """Invert payload bytes [lo, hi): same length and position, every byte different."""
    _, end = options_region(frame)
    out = bytearray(frame)
    for i in range(end + lo, end + hi):
        out[i] ^= 0xFF
    return bytes(out)


# ---------------------------------------------------------------- kinds

@dataclass
class View:
    """What a mutation may know when it fires, all absolute sequence numbers."""
    peer_ack: int  # Zhida's latest ACK number: its RCV.NXT
    peer_right: int  # right edge of Zhida's advertised window
    peer_max_right: int  # peer_ack + the largest window Zhida's announced scale allows
    rcv_nxt: int  # the fuzzer's RCV.NXT (Zhida's sequence space)
    stream: bytes  # the planned payload, for SYN data
    build: Callable  # (seq, flags, payload=b"") -> clean frame from the fuzzer


def _seg(frame):
    seq, ack = struct.unpack_from("!II", frame, TCP_AT + TCP_SEQ)
    flags = frame[TCP_AT + TCP_FLAGS]
    _, end = options_region(frame)
    total = struct.unpack_from("!H", frame, IP_AT + IP_TOTAL)[0]
    return seq, ack, flags, frame[end:IP_AT + total]


def _ip(kind, frame, p, v):
    if kind == "ttl_0":
        return [ip_ttl(frame, 0)]
    if kind == "ttl_1":
        return [ip_ttl(frame, 1)]
    if kind == "ttl_255":
        return [ip_ttl(frame, 255)]
    if kind == "tos":
        return [ip_tos(frame, frame[IP_AT + IP_TOS] ^ (1 + p % 255))]
    if kind == "id":
        ident = struct.unpack_from("!H", frame, IP_AT + IP_ID)[0]
        return [ip_id(frame, ident ^ (1 + p % 0xFFFF))]
    frag = struct.unpack_from("!H", frame, IP_AT + IP_FRAG)[0]
    if kind == "df_clear":
        return [ip_flags_frag(frame, frag & ~DF)]
    if kind == "mf_set":
        return [ip_flags_frag(frame, frag | MF)]
    if kind == "frag_offset":
        return [ip_flags_frag(frame, (frag & 0xE000) | (1 + p % 0x1FFF))]
    if kind == "ihl_short":
        return [ip_ihl(frame, p % 5)]
    if kind == "ihl_long":
        # Real options (NOPs, then EOL) behind IHL 6..15: smoltcp skips IHL*4 bytes and must
        # read the same TCP segment as the clean frame's (src/wire/ipv4.rs 386-390).
        n = 4 * (1 + p % 10)
        return [ip_options(frame, b"\x01" * (n - 1) + b"\x00")]
    total = struct.unpack_from("!H", frame, IP_AT + IP_TOTAL)[0]
    if kind == "total_short":
        return [ip_total(frame, 20 + p % (total - 20))]
    if kind == "total_long":
        return [ip_total(frame, total + 1 + p % 1000)]
    if kind == "bad_checksum":
        return [corrupt_checksum(frame, IP_AT + IP_CSUM)]
    raise ValueError(kind)


FLAG_VALUES = {"syn_fin": SYN | FIN, "syn_rst": SYN | RST, "fin_rst": FIN | RST | ACK,
               "xmas": FIN | SYN | RST | PSH | ACK | URG}


def _flags(kind, frame, p, v):
    flags = frame[TCP_AT + TCP_FLAGS]
    if kind in FLAG_VALUES:
        return [tcp_flags(frame, FLAG_VALUES[kind] | (flags & ACK))]
    if kind == "urg":
        _, _, _, payload = _seg(frame)
        return [tcp_urgent(tcp_flags(frame, flags | URG), 1 + p % max(1, len(payload)))]
    if kind == "none":
        return [tcp_flags(frame, 0)]
    if kind == "no_ack":
        return [tcp_flags(frame, flags & ~ACK)]
    if kind == "ece_cwr":
        return [tcp_flags(frame, flags | ECE | CWR)]
    if kind == "random":
        return [tcp_flags(frame, flags ^ (1 + p % 255))]
    raise ValueError(kind)


def _seqack(kind, frame, p, v):
    seq, ack, _, _ = _seg(frame)
    values = {
        "seq_window_edge": ("seq", v.peer_right),
        "seq_window_last": ("seq", seqmath.add(v.peer_right, -1)),
        "seq_old": ("seq", seqmath.add(seq, -(1 + p % 65536))),
        "seq_future": ("seq", seqmath.add(seq, (1 << 30) + p % (1 << 20))),
        "seq_wrap": ("seq", seq ^ 0x80000000),
        "seq_nudge": ("seq", seqmath.add(seq, 1 + p % 64)),
        "ack_unsent": ("ack", seqmath.add(v.rcv_nxt, 1 + p % 1000)),
        "ack_old": ("ack", seqmath.add(v.rcv_nxt, -(1 + p % (1 << 20)))),
        "ack_zero": ("ack", 0),
        "ack_wrap": ("ack", ack ^ 0x80000000),
        "ack_future": ("ack", seqmath.add(ack, 1 << 30)),
    }
    field, value = values[kind]
    return [tcp_seq(frame, value) if field == "seq" else tcp_ack(frame, value)]


def _options(kind, frame, p, v):
    used = used_options(frame)
    if kind == "bad_length":
        # A TS option whose length byte is 0, 1 or runs past the option area.
        length = (0, 1, 39)[p % 3]
        return [tcp_options(frame, pad(used + bytes([OPT_TS, length]) + b"\0" * 8))]
    if kind == "truncated":
        # The option area ends with an MSS kind byte and no length byte.
        return [tcp_options(frame, used + b"\x01" * (-(len(used) + 1) % 4) + bytes([OPT_MSS]))]
    if kind == "unknown_kind":
        kind_byte = (6, 7, 9, 30, 34, 99, 253, 254)[p % 8]
        size = (p >> 8) % 7
        body = bytes([kind_byte, 2 + size]) + bytes([(p >> 16) & 0xFF]) * size
        return [tcp_options(frame, pad(used + body))]
    if kind in ("mss_0", "mss_1", "mss_65535"):
        return [with_option(frame, OPT_MSS, struct.pack("!H", int(kind[4:])))]
    if kind in ("wscale_15", "wscale_255"):
        return [with_option(frame, OPT_WSCALE, bytes([int(kind[7:])]))]
    if kind == "sack_bogus":
        blocks = 1 + p % 3
        edges = [seqmath.add(v.rcv_nxt, (p * (i + 7)) % 70000 - 35000) for i in range(2 * blocks)]
        return [with_option(frame, OPT_SACK, struct.pack(f"!{2 * blocks}I", *edges))]
    if kind == "ts_garbage":
        return [with_option(frame, OPT_TS, struct.pack("!II", p, (p * 2654435761) & 0xFFFFFFFF))]
    if kind == "syn_options_on_data":
        extra = bytes([OPT_MSS, 4]) + struct.pack("!H", 1460) + bytes([OPT_WSCALE, 3, 7]) \
            + bytes([OPT_SACK_PERM, 2])
        return [tcp_options(frame, pad(used + extra))]
    raise ValueError(kind)


def _window(kind, frame, p, v):
    return [tcp_window(frame, {"win_0": 0, "win_1": 1, "win_max": 0xFFFF}[kind])]


def _lengths(kind, frame, p, v):
    if kind == "doff_small":
        return [tcp_doff(frame, 5)]
    if kind == "doff_below_5":
        return [tcp_doff(frame, p % 5)]
    if kind == "doff_max":
        return [tcp_doff(frame, 15)]
    if kind == "truncated_header":
        return [truncate(frame, TCP_AT + p % 20)]
    if kind == "truncated_payload":
        _, end = options_region(frame)
        return [truncate(frame, end + p % max(1, len(frame) - end))]
    raise ValueError(kind)


def _overlap(kind, frame, p, v):
    seq, _, flags, payload = _seg(frame)
    if kind == "conflict_same":
        other = payload_xor(frame, 0, len(payload))
        return [other, frame] if p % 2 else [frame, other]
    if kind == "conflict_shifted":
        shift = 1 + p % max(1, len(payload))
        data = bytes(b ^ 0xFF for b in payload)
        return [frame, v.build(seqmath.add(seq, shift), flags & ~FIN, data)]
    raise ValueError(kind)


def _timing(kind, frame, p, v):
    seq, _, flags, payload = _seg(frame)
    window = max(1, seqmath.offset(v.peer_right, v.peer_ack))
    if kind == "rst_in_window":
        return [frame, v.build(seqmath.add(v.peer_ack, 1 + p % max(1, window - 1)), RST)]
    if kind == "rst_exact":
        return [frame, v.build(v.peer_ack, RST)]
    if kind == "rst_out_of_window":
        return [frame, v.build(seqmath.add(v.peer_max_right, p % 100000), RST)]
    if kind == "rst_ack":
        return [frame, v.build(seqmath.add(v.peer_ack, p % window), RST | ACK)]
    if kind == "early_fin":
        return [frame, v.build(seqmath.add(seq, len(payload)), FIN | ACK)]
    if kind == "fin_repeat":
        return [frame] * (2 + p % 3)
    if kind == "data_after_fin":
        junk = bytes((p + i) & 0xFF for i in range(1 + p % 100))
        return [frame, v.build(seqmath.add(seq, len(payload) + 1), PSH | ACK, junk)]
    if kind == "syn_mid":
        target = seqmath.add(v.peer_ack, p % window) if p % 2 else p
        return [frame, v.build(target, SYN)]
    if kind == "syn_data":
        return [append_payload(frame, v.stream[:1 + p % 100])]
    raise ValueError(kind)


# class -> {kind: allowed targets}. S syn, A handshake ACK, D data segment, F our FIN.
KINDS = {
    "ip": {k: "SADF" for k in ("ttl_0", "ttl_1", "ttl_255", "tos", "id", "df_clear", "mf_set",
                              "frag_offset", "ihl_short", "ihl_long", "total_long",
                              "bad_checksum")} | {"total_short": "D"},
    "flags": {"syn_fin": "SADF", "syn_rst": "SADF", "fin_rst": "SADF", "urg": "SADF",
              "none": "SADF", "no_ack": "ADF", "xmas": "SADF", "ece_cwr": "SADF",
              "random": "SADF"},
    "seqack": {"seq_window_edge": "D", "seq_window_last": "D", "seq_old": "ADF",
               "seq_future": "ADF", "seq_wrap": "ADF", "seq_nudge": "D", "ack_unsent": "ADF",
               "ack_old": "ADF", "ack_zero": "ADF", "ack_wrap": "ADF", "ack_future": "ADF"},
    "options": {"bad_length": "SADF", "truncated": "SADF", "unknown_kind": "SADF",
                "mss_0": "S", "mss_1": "S", "mss_65535": "S", "wscale_15": "S",
                "wscale_255": "S", "sack_bogus": "ADF", "ts_garbage": "SADF",
                "syn_options_on_data": "ADF"},
    "window": {"win_0": "SADF", "win_1": "SADF", "win_max": "SADF"},
    "lengths": {"doff_small": "S", "doff_below_5": "SADF", "doff_max": "SADF",
                "truncated_header": "SADF", "truncated_payload": "D"},
    "overlap": {"conflict_same": "D", "conflict_shifted": "D"},
    "timing": {"rst_in_window": "D", "rst_exact": "D", "rst_out_of_window": "D",
               "rst_ack": "D", "early_fin": "D", "fin_repeat": "F", "data_after_fin": "F",
               "syn_mid": "D", "syn_data": "S"},
}
APPLY = {"ip": _ip, "flags": _flags, "seqack": _seqack, "options": _options,
         "window": _window, "lengths": _lengths, "overlap": _overlap, "timing": _timing}


def apply(m, frame, view):
    """The frames to send instead of `frame` (a clean frame for m's target)."""
    frames = APPLY[m["class"]](m["kind"], frame, m["p"], view)
    if (m["class"], m["kind"]) in (("ip", "bad_checksum"),):
        return frames
    return [fix_checksums(f) for f in frames]


def draw(rng, payload_len, count):
    """Up to `count` mutation specs (fewer when the targets run out: without payload only
    the SYN, handshake ACK and FIN can be mutated, one mutation each), at least one."""
    specs = []
    for _ in range(50 * count):
        if len(specs) == count:
            break
        cls = rng.choice(sorted(KINDS))
        kind = rng.choice(sorted(KINDS[cls]))
        targets = [t for t in KINDS[cls][kind] if t != "D" or payload_len > 0]
        if not targets:
            continue
        target = rng.choice(targets)
        spec = {"class": cls, "kind": kind,
                "target": rng.randrange(payload_len) if target == "D" else
                {"S": "syn", "A": "ack", "F": "fin"}[target],
                "p": rng.getrandbits(32)}
        if isinstance(spec["target"], str) and \
                any(s["target"] == spec["target"] for s in specs):
            continue  # one mutation per control segment
        specs.append(spec)
    assert specs, "no mutation drawn"
    return specs
