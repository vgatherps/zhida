"""Fuzzer oracles, observed from outside Zhida (docker/README.md, docker-fuzz).

Pure functions and plain data structures: each takes what was seen on the wire and returns
error strings (empty / None when the check passes). The panic and pool oracles are tap-echo's
exit statuses 101 and 2, which the tester's own exit status joins, not checked here.
"""

from wire import (ACK, ETH_P_ARP, ETH_P_IP, FIN, RST, SYN, Malformed, ethertype, flag_names,
                  parse_arp, parse_tcp)
import seqmath


def check_arp(frame, env):
    """Zhida's ARP frames must be well-formed Ethernet/IPv4 requests from ZHIDA_MAC/IP,
    as Linux requires before answering (same rule as fuzz/packetdrill/zhida_shim.c)."""
    try:
        arp = parse_arp(frame)
    except Malformed as e:
        return [f"malformed ARP from Zhida: {e}"]
    errors = []
    if (arp.htype, arp.ptype, arp.hlen, arp.plen) != (1, ETH_P_IP, 6, 4):
        errors.append(f"ARP htype/ptype/hlen/plen {arp.htype}/{arp.ptype:#x}/{arp.hlen}/"
                      f"{arp.plen}, expected 1/0x800/6/4")
    if arp.op != 1:
        errors.append(f"ARP op {arp.op} from Zhida, expected a request (1)")
    if arp.sha != env.zhida_mac or arp.spa != env.zhida_ip:
        errors.append(f"ARP sender {arp.sha.hex(':')} {'.'.join(map(str, arp.spa))} "
                      f"is not Zhida's MAC/IP")
    return errors


def check_frame(frame, env):
    """Well-formed output for one frame Zhida sent. Returns (kind, parsed, errors) with kind
    "arp", "tcp" or None. TCP frames: ZHIDA_MAC/IP to TESTER_MAC/IP from ECHO_PORT, IHL 5,
    valid IP and TCP checksums, options that parse, no SYN+FIN or SYN+RST, ACK on every
    segment but RST (see check_rst for RSTs)."""
    if frame[6:12] != env.zhida_mac:
        return None, None, [f"frame from {frame[6:12].hex(':')}, not ZHIDA_MAC"]
    kind = ethertype(frame)
    if kind == ETH_P_ARP:
        return "arp", parse_arp(frame) if len(frame) >= 42 else None, check_arp(frame, env)
    if kind != ETH_P_IP:
        return None, None, [f"ethertype {kind} from Zhida is neither ARP nor IPv4"]
    try:
        seg = parse_tcp(frame)
    except Malformed as e:
        return None, None, [f"malformed IPv4/TCP from Zhida: {e}"]
    errors = []
    if seg.dst_mac != env.tester_mac:
        errors.append(f"destination MAC {seg.dst_mac.hex(':')} is not TESTER_MAC")
    if seg.src_ip != env.zhida_ip or seg.dst_ip != env.tester_ip:
        errors.append("IP addresses are not ZHIDA_IP -> TESTER_IP")
    if seg.ihl != 5:
        errors.append(f"IHL {seg.ihl}, Zhida emits no IP options")
    if not seg.ip_checksum_ok:
        errors.append("bad IP header checksum")
    if not seg.tcp_checksum_ok:
        errors.append("bad TCP checksum")
    if seg.sport != env.port:
        errors.append(f"source port {seg.sport}, expected ECHO_PORT {env.port}")
    if seg.options_error is not None:
        errors.append(f"TCP options do not parse: {seg.options_error}")
    if seg.flags & SYN and seg.flags & FIN:
        errors.append("SYN+FIN")
    if seg.flags & SYN and seg.flags & RST:
        errors.append("SYN+RST")
    if not seg.flags & (ACK | RST):
        errors.append(f"flags {flag_names(seg.flags)}: ACK missing on a non-RST segment")
    return "tcp", seg, [f"{e} ({seg.describe()})" for e in errors]


class SeqCoverage:
    """Union of sequence ranges, wrap-safe: ranges are kept as offsets from `base`."""

    def __init__(self, base):
        self.base = base
        self.ranges = []  # sorted, merged [start, end) offsets in [0, 2**32]

    def add(self, seq, length):
        if length <= 0:
            return
        start = seqmath.offset(seq, self.base)
        end = start + length
        if end > seqmath.MOD:
            self._add(start, seqmath.MOD)
            self._add(0, end - seqmath.MOD)
        else:
            self._add(start, end)

    def _add(self, start, end):
        merged = []
        for s, e in self.ranges:
            if e < start or s > end:
                merged.append((s, e))
            else:
                start, end = min(s, start), max(e, end)
        merged.append((start, end))
        merged.sort()
        self.ranges = merged

    def _covered(self, start, end):
        return any(s <= start and end <= e for s, e in self.ranges)

    def covers(self, lo, hi):
        """True if every sequence number in [lo, hi) was added (hi at most 2**31 after lo)."""
        length = seqmath.offset(hi, lo)
        if length == 0:
            return True
        if length >= seqmath.HALF:
            return False
        start = seqmath.offset(lo, self.base)
        end = start + length
        if end > seqmath.MOD:
            return self._covered(start, seqmath.MOD) and self._covered(0, end - seqmath.MOD)
        return self._covered(start, end)


def check_ack_bound(ack, coverage, syn_seqs):
    """Zhida never ACKs sequence space the fuzzer never sent: some SYN the fuzzer sent at S
    must start a covered run [S, ack) (S + 1 for the SYN alone)."""
    for syn in syn_seqs:
        if seqmath.gt(ack, syn) and coverage.covers(syn, ack):
            return None
    return (f"ACK {ack} covers sequence space the fuzzer never sent "
            f"(SYNs at {sorted(syn_seqs)}, sent ranges {coverage.ranges} from {coverage.base})")


def rst_reply_shape(seg):
    """(flags, SEQ, ACK field) of the RST smoltcp answers a non-RST segment it parsed with
    (rst_reply, src/socket/tcp.rs 1459-1473; also for segments no socket accepts,
    src/iface/interface/tcp.rs 43-56): a segment with ACK gets RST, SEQ = its ACK, no ACK
    (ACK field 0, src/wire/tcp.rs 1044); one without ACK gets SEQ 0, and if it is a SYN,
    RST|ACK with ACK = its SEQ + segment length, else RST alone."""
    if seg.flags & ACK:
        return RST, seg.ack, 0
    if seg.flags & SYN:
        return RST | ACK, 0, seqmath.add(seg.seq, seg.seg_len)
    return RST, 0, 0


def check_rst(seg, shapes):
    """RST shape per RFC 9293 3.10.7.1 as smoltcp builds it: exactly rst_reply_shape of some
    segment the fuzzer sent on this 4-tuple (`shapes`), with window 0, no options, no
    payload."""
    if not seg.flags & RST:
        return None
    if seg.window or seg.options_raw or seg.payload:
        return (f"RST with window {seg.window}, {len(seg.options_raw)} option bytes, "
                f"{len(seg.payload)} payload bytes; rst_reply sends none")
    if (seg.flags, seg.seq, seg.ack) in shapes:
        return None
    return (f"RST {flag_names(seg.flags)} SEQ {seg.seq} ACK {seg.ack} is not smoltcp's "
            f"rst_reply to any segment the fuzzer sent ({len(shapes)} possible RSTs)")


class SentRecord:
    """Which byte the fuzzer validly sent (checksums correct) at each of its sequence
    numbers: the planned stream at base.., plus any other byte a mutated segment put there."""

    def __init__(self, base, stream):
        self.base = base
        self.stream = stream
        self.stream_sent = SeqCoverage(base)
        self.extras = {}  # seq -> set of byte values other than the stream's

    def add(self, seq, payload, window=None):
        """window: (left, size), the only sequence numbers whose bytes Zhida can keep;
        bytes outside it are dropped by Zhida (smoltcp keeps only the in-window part of a
        segment, src/socket/tcp.rs 1772-1784) and not recorded."""
        if window is not None:
            left, size = window
            lead = seqmath.diff(left, seq)  # bytes before left
            first = max(0, lead)
            last = min(len(payload), lead + size)
            if first >= last:
                return
            seq, payload = seqmath.add(seq, first), payload[first:last]
        start = seqmath.offset(seq, self.base)
        if start + len(payload) <= len(self.stream) and \
                self.stream[start:start + len(payload)] == payload:
            self.stream_sent.add(seq, len(payload))
            return
        for i, b in enumerate(payload):
            s = seqmath.add(seq, i)
            pos = seqmath.offset(s, self.base)
            if pos < len(self.stream) and self.stream[pos] == b:
                self.stream_sent.add(s, 1)
            else:
                self.extras.setdefault(s, set()).add(b)

    @property
    def conflicting(self):
        return bool(self.extras)

    def sent(self, seq, value):
        pos = seqmath.offset(seq, self.base)
        if pos < len(self.stream) and self.stream[pos] == value and \
                self.stream_sent.covers(seq, seqmath.add(seq, 1)):
            return True
        return value in self.extras.get(seq, ())


def check_echo(record, peer_isn, local_base, seq, payload):
    """Echo-only: Zhida's payload byte at its stream offset k (seq - (peer_isn + 1)) must be
    a byte the fuzzer sent at its own sequence number local_base + k (local_base: the ACK of
    Zhida's SYN-ACK, i.e. the fuzzer's ISN + 1)."""
    if not payload:
        return None
    k = seqmath.offset(seq, seqmath.add(peer_isn, 1))
    local = seqmath.add(local_base, k)
    start = seqmath.offset(local, record.base)
    if start + len(payload) <= len(record.stream) and \
            record.stream[start:start + len(payload)] == payload and \
            record.stream_sent.covers(local, seqmath.add(local, len(payload))):
        return None
    for i, b in enumerate(payload):
        if not record.sent(seqmath.add(local, i), b):
            return (f"Zhida sent byte {b:#04x} at its stream offset {k + i}; the fuzzer never "
                    f"sent that byte at seq {seqmath.add(local, i)}")
    return None


def _first_difference(a, b):
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return min(len(a), len(b))


def check_stream_exact(sent, echoed):
    if echoed == sent:
        return None
    i = _first_difference(sent, echoed)
    return (f"stream integrity: echoed {len(echoed)} bytes, sent {len(sent)}; first difference "
            f"at offset {i}")


def check_stream_prefix(sent, echoed):
    if len(echoed) <= len(sent) and sent[:len(echoed)] == echoed:
        return None
    i = _first_difference(sent, echoed)
    return (f"stream prefix: echoed {len(echoed)} bytes are not a prefix of the {len(sent)} "
            f"sent; first difference at offset {i}")


def check_clean_close(fin_acked, peer_fin, zhida_rsts):
    """Stream-preserving close: the fuzzer's FIN acknowledged, Zhida's FIN received, no RST
    from Zhida."""
    errors = []
    if not fin_acked:
        errors.append("close: Zhida never acknowledged the fuzzer's FIN")
    if not peer_fin:
        errors.append("close: no FIN from Zhida")
    if zhida_rsts:
        errors.append(f"close: Zhida sent {zhida_rsts} RST(s)")
    return errors


def check_handshake(synack_after, bound):
    """Liveness: a SYN-ACK answering the connection's (clean) SYN within bound seconds."""
    if synack_after is None:
        return f"liveness: no SYN-ACK within {bound} s"
    if synack_after > bound:
        return f"liveness: SYN-ACK after {synack_after:.3f} s, bound {bound} s"
    return None
