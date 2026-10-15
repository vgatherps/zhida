"""One fuzzer connection: a Linux-like TCP client that applies a Plan to Zhida's echo server.

Sender: sequence numbers are kept as offsets u from the ISN (u 0 the SYN, 1..L the payload,
L + 1 the FIN); go-back-N retransmission on an RTO (Linux TCP_RTO_MIN 200 ms, doubling), fast
retransmit of the head on the third duplicate ACK, zero-window probes as Linux sends them
(an ACK at SND.UNA - 1). Receiver: cumulative ACKs, every Nth segment or a delayed-ACK timer,
immediate ACKs for out-of-order, duplicate and FIN segments; a receive buffer whose right edge
never moves back. Like Linux (tcp_sequence), a pure ACK with SEQ below RCV.NXT and a data
segment ending below it are discarded with a duplicate ACK (rate-limited to one per 500 ms for
pure ACKs, tcp_invalid_ratelimit); Zhida sends such pure ACKs after an RTO (smoltcp rewinds
its send pointer to SND.UNA), which is never an error. TS is used only if both SYNs carry it, and
any segment boundary Zhida picks is accepted (smoltcp segments by its own rules).

Disruptive plans: the plan's mutations (mutate.py) replace the clean SYN, handshake ACK,
first FIN or first transmission of a data segment at their target; a mutated SYN is
followed after 200 ms by a clean one, whose SYN-ACK the liveness bound applies to. A
mutation counts as applied once a changed or extra frame of it was sent (not when it was a
no-op or its target never came); until then the connection
is stream-preserving and judged so. A disrupted connection ends, after its close, a Zhida
RST or the plan's budget, with a teardown: quiet for longer than Zhida's delayed ACK, an
ACK of Zhida's latest segment (which completes a handshake Zhida may still hold in
SYN-RECEIVED), then an RST at Zhida's latest ACK number, repeated at most twice at the
number a challenge ACK names, so the socket closes and EchoServer listens again.
"""

import bisect

import mutate
import oracles
import seqmath
from wire import (ACK, FIN, PSH, RST, SYN, TCP_AT, TCP_CSUM, IP_AT, IP_CSUM, Malformed,
                  fix_checksums, parse_tcp, smoltcp_accepts)

SYN_RTO = 1.0  # Linux TCP_TIMEOUT_INIT
SYN_RETRY = 0.2  # clean SYN after a mutated one
RTO_MIN = 0.2  # Linux TCP_RTO_MIN
RTO_MAX = 1.6  # Linux allows 120 s; capped so a connection fits its deadline
HANDSHAKE_BOUND = 3.0
STALE_DUPACK_INTERVAL = 0.5  # Linux tcp_invalid_ratelimit
REORDER_HOLD_MAX = 0.005
QUIESCE = 0.05  # > Zhida's delayed ACK, 10 ms (smoltcp tcp.rs:300 ACK_DELAY_DEFAULT)
TEARDOWN_RST_RETRIES = 2
OWN_MTU_MSS = 1460
TS_OVERHEAD = 12
MAX_WINDOW = 65535  # largest TCP window field; scaled by the announced shift
MAX_FRAME = 14 + 1500  # Ethernet header + the netdev MTU; AF_PACKET refuses longer frames


class Conn:
    def __init__(self, plan, builder, emit, stats, now):
        self.plan = plan
        self.build = builder
        self.emit_frame = emit
        self.stats = stats
        self.t0 = now
        self.data = plan.payload
        self.L = len(self.data)
        self.isn = plan.isn
        self.phase = "syn"
        self.failures = []
        self.timers = {}
        self.disrupted = False  # a mutation's changed or extra frame was sent
        self.mutations = list(plan.mutations)
        self.latest = None  # Zhida's latest non-RST segment
        self.teardown_rst = None
        self.teardown_rsts = 0

        # Sender (offsets u from the ISN).
        self.snd_una = 0
        self.snd_nxt = 0
        self.snd_max = 0
        self.rto = RTO_MIN
        self.dupacks = 0
        self.last_ack_seen = None  # (u_ack, window) of the latest acceptable ACK
        self.peer_right = 0  # u of the right edge of Zhida's window
        self.boundaries = []
        total = 0
        for n in plan.sizes:
            total += n
            self.boundaries.append(total)
        self.tx_plan = sorted(plan.tx, key=lambda t: t["at"])
        self.held = []  # [frame, segments still to pass it]
        self.pace_count = 0
        self.fin_sent = False
        self.persist = RTO_MIN
        self.syn_sent_at = None
        self.synack_after = None

        # Receiver (Zhida's echo stream).
        self.cisn = None
        self.rcv_nxt = None
        self.received = bytearray()
        self.ooo = {}  # echo offset -> bytes
        self.peer_fin_at = None  # echo offset of Zhida's FIN
        self.peer_fin = False
        self.unread = 0
        self.stall_done = plan.stall is None
        self.adv_right = None
        self.unacked = 0
        self.pure_acks = 0
        self.dup_ack_plan = sorted(plan.dup_acks, key=lambda d: d["at"])
        self.extra_acks = 0
        self.rx_drop = sorted(plan.rx_drop)
        self.drop_peer_fin = plan.drop_peer_fin
        self.last_stale_dupack = None
        self.rx_high = 0  # highest echo offset end seen, for counting retransmissions
        self.peer_fin_seen = 0
        self.ts_recent = 0

        # Negotiated.
        self.ts_on = False
        self.our_ws = 0
        self.peer_ws = 0
        self.send_mss = 536

        # Oracle state.
        self.coverage = oracles.SeqCoverage(self.isn)
        self.record = oracles.SentRecord(seqmath.add(self.isn, 1), self.data)
        self.syn_seqs = set()
        self.rst_shapes = set()  # oracles.rst_reply_shape of each segment smoltcp accepts
        self.synack_ack = None
        self.zhida_rsts = 0
        self.challenge_armed = False
        self.last_tx = now

    # ---------------------------------------------------------------- helpers

    def fail(self, message):
        self.failures.append(message)
        self.phase = "done"

    def seq(self, u):
        return seqmath.add(self.isn, u)

    def tsval(self, now):
        return (self.plan.ts_base + int((now - self.t0) * 1000)) & seqmath.MASK

    def _acceptable(self):
        """(left, size): every sequence number Zhida may still accept bytes at. Its
        RCV.NXT only grows, so nothing below its latest ACK seen here; it is at most our
        SND.MAX, and its window at most 65535 << the scale it announced. Valid only after
        the SYN-ACK (snd_una > 0)."""
        return self.seq(self.snd_una), self.snd_max - self.snd_una + (MAX_WINDOW << self.peer_ws)

    def _max_right(self, frame):
        """u past every right edge Zhida's window can have while `frame` is in flight: its
        RCV.NXT is at most the end of what we sent, `frame` included."""
        seg = parse_tcp(frame)
        end = seqmath.offset(seqmath.add(seg.seq, seg.seg_len), self.isn)
        return max(self.snd_max, end) + (MAX_WINDOW << self.peer_ws)

    def next_deadline(self):
        return min(self.timers.values()) if self.timers else None

    def _emit(self, frame, now):
        """Send one frame; record what it put on the wire that smoltcp accepts, read as
        Zhida reads it (wire.smoltcp_accepts)."""
        try:
            seg = parse_tcp(frame)
        except Malformed:
            seg = None
        if seg is not None and smoltcp_accepts(seg):
            if seg.flags & SYN:
                self.syn_seqs.add(seg.seq)
            if not seg.flags & RST:
                self.rst_shapes.add(oracles.rst_reply_shape(seg))
            self.coverage.add(seg.seq, seg.seg_len)
            self.record.add(seqmath.add(seg.seq, 1) if seg.flags & SYN else seg.seq, seg.payload,
                            self._acceptable() if self.snd_una else None)
            if seg.flags & (SYN | RST) and self.phase == "est":
                self.challenge_armed = True
        self.last_tx = now
        self.emit_frame(frame, now)

    def _options(self, now):
        if not self.ts_on:
            return []
        return [("NOP", None), ("NOP", None), ("Timestamp", (self.tsval(now), self.ts_recent))]

    def _window_field(self):
        """Advertised window: free buffer, rounded up to the scale unit, never moving the
        right edge back (Linux tcp_select_window)."""
        free = max(0, self.plan.rcv_buffer - self.unread)
        unit = 1 << self.our_ws
        right = seqmath.add(self.rcv_nxt, free)
        if seqmath.lt(right, self.adv_right):
            right = self.adv_right
        field = min((seqmath.offset(right, self.rcv_nxt) + unit - 1) >> self.our_ws, 0xFFFF)
        edge = seqmath.add(self.rcv_nxt, field << self.our_ws)
        if seqmath.gt(edge, self.adv_right):
            self.adv_right = edge
        return field

    def _segment(self, now, u, flags, payload=b"", seq=None):
        ack = self.rcv_nxt if flags & ACK else 0
        window = self._window_field() if self.rcv_nxt is not None else 0
        return self.build.tcp(self.plan.sport, self.seq(u) if seq is None else seq, ack,
                              flags, window, self._options(now), payload)

    def _arm(self, name, at):
        self.timers[name] = at

    def _cancel(self, name):
        self.timers.pop(name, None)

    def _take(self, hits):
        """Remove and return the first pending mutation whose target `hits`."""
        for m in self.mutations:
            if hits(m["target"]):
                self.mutations.remove(m)
                return m
        return None

    def _send_mutated(self, m, frame, now, emit_first=None):
        """Send m's frames instead of the clean `frame` (the first through emit_first, default
        _emit). Counts exactly one outcome: no-op (mutnoop_: m left the frame as it was),
        applied (mut_/mutclass_: a changed or extra frame was sent; the connection is
        disrupted from now on). Returns whether it was applied."""
        name = f"{m['class']}.{m['kind']}"
        emit_first = emit_first or self._emit
        view = mutate.View(
            peer_ack=self.seq(self.snd_una), peer_right=self.seq(self.peer_right),
            peer_max_right=self.seq(self._max_right(frame)),
            rcv_nxt=self.rcv_nxt or 0, stream=self.data,
            build=lambda seq, flags, payload=b"": self._segment(now, 0, flags, payload, seq))
        frames = mutate.apply(m, frame, view)
        if frames == [frame]:
            self.stats[f"mutnoop_{name}"] += 1
            emit_first(frame, now)
            return False
        for i, f in enumerate(frames):
            if len(f) > MAX_FRAME:
                # Options grown on a full-sized segment: the netdev refuses frames over its
                # MTU (EMSGSIZE), so the end of the payload is cut off.
                self.stats["fuzzer_mutated_frames_cut_to_mtu"] += 1
                frames[i] = fix_checksums(mutate.truncate(f, MAX_FRAME))
        for i, f in enumerate(frames):
            (emit_first if i == 0 else self._emit)(f, now)
        self.disrupted = True
        self.stats[f"mut_{name}"] += 1
        self.stats[f"mutclass_{m['class']}"] += 1
        return True

    # ---------------------------------------------------------------- start / SYN

    def start(self, now):
        self._arm("deadline", self.t0 + self.plan.deadline)
        if self.plan.kind == "disruptive":
            self._arm("budget", self.t0 + self.plan.budget)
        self._arm("handshake", now + HANDSHAKE_BOUND)
        self.syn_sent_at = now
        self._send_syn(now)

    def syn_options(self, now):
        s = self.plan.syn
        opts = {"mss": ("MSS", s["mss"]), "sack": ("SAckOK", b""),
                "ts": ("Timestamp", (self.tsval(now), 0)), "wscale": ("WScale", s["wscale"])}
        if s["order"] != ["linux"]:
            return [opts[name] for name in s["order"]]
        # Linux tcp_options_write order: MSS, SACK-permitted folded into TS, wscale last.
        out = [opts["mss"]]
        if s["ts"]:
            out += [opts["sack"], opts["ts"]] if s["sack"] else [("NOP", None), ("NOP", None),
                                                                 opts["ts"]]
        elif s["sack"]:
            out += [("NOP", None), ("NOP", None), opts["sack"]]
        if s["wscale"] is not None:
            out += [("NOP", None), opts["wscale"]]
        return out

    def _send_syn(self, now):
        window = min(self.plan.rcv_buffer, 0xFFFF)
        frame = self.build.tcp(self.plan.sport, self.isn, 0, SYN, window, self.syn_options(now))
        m = self._take(lambda t: t == "syn")
        if m is None:
            self._emit(frame, now)
        elif self._send_mutated(m, frame, now):
            self._arm("syn_retry", now + SYN_RETRY)
        self.snd_nxt = self.snd_max = 1
        self._arm("syn_rto", now + SYN_RTO)

    def _on_synack(self, seg, now):
        if seqmath.offset(seg.ack, self.isn) != 1:
            return  # the ACK-bound oracle has judged it; Linux would RST, we ignore it
        if self.cisn is not None:
            if seg.seq == self.cisn:
                self.stats["zhida_retransmissions"] += 1
                self._send_ack(now)
            elif not self.disrupted:
                self.fail(f"second SYN-ACK with ISN {seg.seq}, first was {self.cisn}")
            return
        self.cisn = seg.seq
        self.rcv_nxt = seqmath.add(seg.seq, 1)
        self.adv_right = self.rcv_nxt
        self.synack_ack = seg.ack
        self.synack_after = now - self.syn_sent_at
        s = self.plan.syn
        if seg.timestamp is not None and self.plan.index.startswith("probe"):
            self.fail(f"Zhida's SYN-ACK carried TS despite the probe expecting none "
                      f"({seg.describe()})")
            return
        self.ts_on = s["ts"] and seg.timestamp is not None
        if self.ts_on:
            self.ts_recent = seg.timestamp[0]
        if s["wscale"] is not None and seg.wscale is not None:
            self.our_ws, self.peer_ws = s["wscale"], min(seg.wscale, 14)
        peer_mss = seg.mss if seg.mss else 536
        self.send_mss = min(peer_mss, OWN_MTU_MSS) - (TS_OVERHEAD if self.ts_on else 0)
        self.snd_una = 1
        self.peer_right = 1 + seg.window  # SYN windows are never scaled
        self.last_ack_seen = (1, seg.window)
        self._cancel("syn_rto")
        self._cancel("syn_retry")
        self._cancel("handshake")
        self.rto = RTO_MIN
        self.phase = "est"
        self._send_ack(now)
        self._pump(now)

    # ---------------------------------------------------------------- receive

    def on_segment(self, seg, now):
        """A TCP segment from Zhida for this connection (check_frame already passed)."""
        new_from = self._oracles(seg)
        if not seg.flags & RST:
            self.latest = seg
        if self.disrupted:
            if seg.flags & RST:
                self.zhida_rsts += 1
                if self.phase == "est" and not self.failures:
                    self._teardown(now, "after_zhida_rst")
                return
            if self.phase in ("teardown", "done") or self.failures:
                return
        # After the close completed, Zhida's socket is gone (passive close, no TIME-WAIT):
        # an ACK of ours, e.g. re-ACKing a FIN retransmission that crossed our final ACK,
        # draws an RST per RFC 9293 3.10.7.1, whose shape check_rst has checked.
        elif seg.flags & RST and self.phase != "done" and not self.failures:
            self.zhida_rsts += 1
            self.fail(f"Zhida sent RST on a stream-preserving connection ({seg.describe()})")
        elif seg.flags & RST and self.phase == "done":
            self.stats["zhida_rsts_after_close"] += 1
        if self.phase == "done" or self.failures:
            if not self.failures and self.peer_fin and seg.flags & FIN:
                self._send_ack(now)  # FIN retransmitted into our TIME-WAIT
            return
        if seg.flags & SYN:
            if seg.flags & ACK:
                self._on_synack(seg, now)
            return
        if self.cisn is None:
            return
        if self._impair_rx(seg, new_from):
            return
        self._receive(seg, now)
        self._check_done(now)

    def _oracles(self, seg):
        """Per-connection oracles on one Zhida segment. Returns the echo offset from which
        its payload is new (the highest offset seen before it)."""
        st = self.stats
        armed, self.challenge_armed = self.challenge_armed, False
        if seg.flags & RST:
            st["zhida_rsts"] += 1
            st["check_rst"] += 1
            error = oracles.check_rst(seg, self.rst_shapes)
        else:
            st["check_ack_bound"] += 1
            error = oracles.check_ack_bound(seg.ack, self.coverage, self.syn_seqs)
            if armed and not seg.payload and not seg.flags & (SYN | FIN):
                st["zhida_challenge_acks"] += 1
        if error:
            self.failures.append(f"{error} ({seg.describe()})")
        new_from = self.rx_high
        if seg.payload:
            if self.cisn is None and not seg.flags & SYN:
                self.fail(f"payload before any SYN-ACK ({seg.describe()})")
                return new_from
            peer_isn = seg.seq if seg.flags & SYN else self.cisn
            local_base = seg.ack if seg.flags & SYN else self.synack_ack
            data_seq = seqmath.add(seg.seq, 1) if seg.flags & SYN else seg.seq
            st["check_echo"] += 1
            error = oracles.check_echo(self.record, peer_isn, local_base, data_seq, seg.payload)
            if error:
                self.failures.append(f"{error} ({seg.describe()})")
            k = seqmath.offset(data_seq, seqmath.add(peer_isn, 1))
            if k < self.rx_high:
                st["zhida_retransmissions"] += 1
            self.rx_high = max(self.rx_high, k + len(seg.payload))
        if seg.flags & FIN and not seg.flags & RST:
            self.peer_fin_seen += 1
            if self.peer_fin_seen > 1:
                st["zhida_retransmissions"] += 1
        if self.failures:
            self.phase = "done"
        return new_from

    def _impair_rx(self, seg, new_from):
        """Planned loss of a Zhida segment: the first arrival of a planned echo offset, or
        Zhida's first FIN. Zhida must retransmit."""
        if seg.payload and self.rx_drop:
            k = seqmath.offset(seg.seq, seqmath.add(self.cisn, 1))
            hit = [x for x in self.rx_drop if max(k, new_from) <= x < k + len(seg.payload)]
            if hit:
                self.rx_drop = [x for x in self.rx_drop if x not in hit]
                self.stats["impair_rx_drop"] += 1
                return True
        if seg.flags & FIN and self.drop_peer_fin:
            self.drop_peer_fin = False
            self.stats["impair_drop_peer_fin"] += 1
            return True
        return False

    def _receive(self, seg, now):
        payload, fin = seg.payload, bool(seg.flags & FIN)
        off = seqmath.diff(seg.seq, self.rcv_nxt)
        pure = not payload and not fin
        if off + len(payload) + fin < 0:
            # Linux tcp_sequence: the segment ends below RCV.NXT (a pure ACK whose SEQ is).
            self.stats["stale_zhida_segments_discarded"] += 1
            if not pure or self.last_stale_dupack is None or \
                    now - self.last_stale_dupack >= STALE_DUPACK_INTERVAL:
                self.last_stale_dupack = now
                self._send_ack(now)
            return
        if off > seqmath.diff(self.adv_right, self.rcv_nxt):
            self.stats["zhida_beyond_window"] += 1
            self._send_ack(now)
            return
        self._on_ack(seg, now)
        if self.ts_on and seg.timestamp is not None:
            self.ts_recent = seg.timestamp[0]
        if payload or fin:
            self._accept(off, payload, fin, now)

    def _accept(self, off, payload, fin, now):
        """Queue Zhida's data/FIN at `off` from RCV.NXT and ACK per the plan's policy."""
        if self.peer_fin:
            self._send_ack(now)  # nothing follows Zhida's FIN: a retransmission
            return
        if off < 0:
            payload, off = payload[-off:], 0
        window = seqmath.diff(self.adv_right, self.rcv_nxt)
        immediate = False
        if off + len(payload) > window:
            payload = payload[:max(0, window - off)]
            fin = False
            immediate = True
            self.stats["zhida_beyond_window"] += 1
        base = len(self.received)
        if fin:
            self.peer_fin_at = base + off + len(payload)
        if not payload:
            immediate = True  # duplicate, beyond the window, or a FIN
        elif off == 0:
            immediate = bool(self.ooo)  # fills a hole
            self._deliver(payload, now)
            while True:
                pos = len(self.received)
                ahead = sorted(k for k in self.ooo if k <= pos)
                if not ahead:
                    break
                for k in ahead:
                    chunk = self.ooo.pop(k)
                    pos = len(self.received)
                    if k + len(chunk) > pos:
                        self._deliver(chunk[pos - k:], now)
            self.unacked += 1
        else:
            key = base + off
            if len(self.ooo.get(key, b"")) < len(payload):
                self.ooo[key] = payload
            immediate = True
        if self.peer_fin_at is not None and len(self.received) == self.peer_fin_at:
            self.peer_fin = True
            self.rcv_nxt = seqmath.add(self.rcv_nxt, 1)
            immediate = True
        if immediate or self.unacked >= self.plan.ack["every"]:
            self._send_ack(now)
        elif "delack" not in self.timers:
            self._arm("delack", now + self.plan.ack["delay_ms"] / 1000)
        if self.plan.close == "after_echo":
            self._pump(now)

    def _deliver(self, chunk, now):
        self.received += chunk
        self.rcv_nxt = seqmath.add(self.rcv_nxt, len(chunk))
        stall = self.plan.stall
        if "stall" in self.timers:
            self.unread += len(chunk)
        elif not self.stall_done and len(self.received) > stall["at"]:
            # The application stops reading at byte `at` for `ms`; the window closes as
            # unread bytes fill the buffer and reopens with a window update.
            self.stall_done = True
            self.unread += len(self.received) - stall["at"]
            self._arm("stall", now + stall["ms"] / 1000)
            self.stats["impair_stall"] += 1
        while self.dup_ack_plan and len(self.received) > self.dup_ack_plan[0]["at"]:
            self.extra_acks += self.dup_ack_plan.pop(0)["count"]

    # ---------------------------------------------------------------- ACKs we receive

    def _on_ack(self, seg, now):
        if not seg.flags & ACK:
            return
        u_ack = seqmath.offset(seg.ack, self.isn)
        if not 0 < u_ack <= self.snd_max:
            return
        window = seg.window << self.peer_ws
        if u_ack > self.snd_una:
            self.snd_una = u_ack
            self.snd_nxt = max(self.snd_nxt, u_ack)
            self.dupacks = 0
            self.rto = RTO_MIN
            self.persist = RTO_MIN
            self._cancel("persist")
            if self.snd_una < self.snd_max:
                self._arm("rto", now + self.rto)
            else:
                self._cancel("rto")
        elif u_ack == self.snd_una and not seg.payload and not seg.flags & (SYN | FIN) and \
                self.last_ack_seen == (u_ack, window) and self.snd_una < self.snd_max:
            self.dupacks += 1
            if self.dupacks == 3:
                self.stats["fuzzer_fast_retransmits"] += 1
                self._retransmit_head(now)
        if u_ack >= self.snd_una:
            self.peer_right = u_ack + window
            self.last_ack_seen = (u_ack, window)
        self._pump(now)

    # ---------------------------------------------------------------- send

    def _boundary_after(self, o):
        i = bisect.bisect_right(self.boundaries, o)
        return self.boundaries[i] if i < len(self.boundaries) else self.L

    def _want_fin(self):
        if self.fin_sent or self.plan.close in ("after_send", "with_data"):
            return True
        return len(self.received) >= self.L

    def _tx_action(self, o, n):
        hit = [t for t in self.tx_plan if o <= t["at"] < o + n]
        if not hit:
            return None
        self.tx_plan = [t for t in self.tx_plan if t not in hit]
        return hit[0]

    def _data_flags(self, u, n):
        end = u + n
        flags = ACK
        if self.plan.psh == "every" or end == self.L + 1:
            flags |= PSH
        if end == self.L + 1 and self.plan.close == "with_data":
            flags |= FIN
        return flags

    def _pump(self, now):
        while self.phase == "est" and not self.failures:
            if self.timers.get("pace", 0) > now:
                return
            u = self.snd_nxt
            if u <= self.L:
                avail = self.peer_right - u
                if avail <= 0:
                    if self.snd_una == self.snd_nxt and "persist" not in self.timers:
                        self._arm("persist", now + self.persist)
                    return
                first = u >= self.snd_max
                n = min(self.send_mss, avail, self.L + 1 - u)
                if first:
                    n = min(n, self._boundary_after(u - 1) - (u - 1))
                else:
                    n = min(n, self.snd_max - u)
                flags = self._data_flags(u, n)
                self._send_data(now, u, n, flags, first)
                self.snd_nxt = u + n + bool(flags & FIN)
                self.fin_sent |= bool(flags & FIN)
            elif u == self.L + 1 and self._want_fin():
                first = not self.fin_sent
                self.fin_sent = True
                self.snd_nxt = u + 1
                frame = self._segment(now, u, FIN | ACK)
                m = self._take(lambda t: t == "fin") if first else None
                if m is not None:
                    self._send_mutated(m, frame, now)
                elif first and self.plan.drop_own_fin:
                    self.stats["impair_drop_own_fin"] += 1
                else:
                    self._emit(frame, now)
            else:
                return
            self.snd_max = max(self.snd_max, self.snd_nxt)
            if "rto" not in self.timers:
                self._arm("rto", now + self.rto)
            self._pace(now)

    def _pace(self, now):
        p = self.plan.pacing
        if p["mode"] == "paced":
            self._arm("pace", now + p["gap_ms"] / 1000)
        elif p["mode"] == "bursts":
            self.pace_count += 1
            if self.pace_count % p["n"] == 0:
                self._arm("pace", now + p["gap_ms"] / 1000)

    def _send_data(self, now, u, n, flags, first):
        o = u - 1
        frame = self._segment(now, u, flags, self.data[o:o + n])
        if first:
            m = self._take(lambda t: isinstance(t, int) and o <= t < o + n)
            if m is None and flags & FIN:
                m = self._take(lambda t: t == "fin")
            if m is not None:
                self._tx_action(o, n)  # the mutation replaces any impairment planned here
                self._send_mutated(m, frame, now, emit_first=self._emit_data)
                return
        action = self._tx_action(o, n) if first else None
        if action is not None and action["do"] == "overlap" and o == 0:
            action = None  # nothing sent before the first byte to overlap with
        if action is None:
            self._emit_data(frame, now)
            return
        do = action["do"]
        self.stats[f"impair_{do}"] += 1
        if do == "drop":
            return
        if do == "bad_tcp_csum":
            frame = mutate.corrupt_checksum(frame, TCP_AT + TCP_CSUM)
        elif do == "bad_ip_csum":
            frame = mutate.corrupt_checksum(frame, IP_AT + IP_CSUM)
        if do == "reorder":
            self.held.append([frame, action["hold"]])
            self._arm("release", now + REORDER_HOLD_MAX)
            return
        self._emit_data(frame, now)
        if do == "dup":
            self._emit(frame, now)
        elif do == "overlap":
            # A second segment re-covering up to `back` earlier bytes and this segment's
            # start, same bytes, at most one MSS.
            back = min(action["back"], o)
            end = min(o + n, o - back + self.send_mss)
            self._emit(self._segment(now, u - back, flags & ~(FIN | PSH),
                                     self.data[o - back:end]), now)

    def _emit_data(self, frame, now):
        self._emit(frame, now)
        for h in self.held:
            h[1] -= 1
        self._release(now, lambda h: h[1] <= 0)

    def _release(self, now, ready):
        keep = []
        for h in self.held:
            if ready(h):
                self._emit(h[0], now)
            else:
                keep.append(h)
        self.held = keep
        if not self.held:
            self._cancel("release")

    def _retransmit_head(self, now):
        u = self.snd_una
        if u <= self.L:
            n = min(self.send_mss, self.L + 1 - u, max(1, self.snd_max - u))
            self._emit(self._segment(now, u, self._data_flags(u, n), self.data[u - 1:u - 1 + n]),
                       now)
        elif u == self.L + 1 and self.fin_sent:
            self._emit(self._segment(now, u, FIN | ACK), now)
        self._arm("rto", now + self.rto)

    def _send_ack(self, now):
        self._cancel("delack")
        self.unacked = 0
        index = self.pure_acks
        self.pure_acks += 1
        frame = self._segment(now, self.snd_nxt, ACK)
        m = self._take(lambda t: t == "ack") if index == 0 else None
        if m is not None:
            self._send_mutated(m, frame, now)
            return
        # Planned ACK loss and duplication never hit ACKs of Zhida's FIN: a lost one would
        # leave Zhida in LAST-ACK after we are done, and a copy reaching the closed socket
        # draws a (correct) RST, which stream-preserving connections must not see.
        if self.peer_fin:
            self.extra_acks = 0
        elif index in self.plan.ack_drop:
            self.stats["impair_ack_drop"] += 1
            return
        self._emit(frame, now)
        if self.extra_acks:
            self.stats["impair_dup_acks"] += 1
        while self.extra_acks:
            self.extra_acks -= 1
            self._emit(frame, now)

    # ---------------------------------------------------------------- timers

    def on_timer(self, now):
        for name, at in sorted(self.timers.items(), key=lambda kv: kv[1]):
            if at > now or self.phase == "done" or name not in self.timers:
                continue
            del self.timers[name]
            getattr(self, f"_t_{name}")(now)

    def _t_deadline(self, now):
        self.fail(f"connection not finished within {self.plan.deadline} s "
                  f"(phase {self.phase}, sent {self.snd_una - 1}/{self.L} acked, echoed "
                  f"{len(self.received)}, peer FIN {self.peer_fin})")

    def _t_handshake(self, now):
        self.stats["check_handshake"] += 1
        self.fail(oracles.check_handshake(None, HANDSHAKE_BOUND))

    def _t_syn_rto(self, now):
        self.stats["fuzzer_syn_retransmits"] += 1
        self._send_syn(now)

    def _t_syn_retry(self, now):
        """Liveness after a mutated SYN: a clean SYN must get a SYN-ACK within the bound."""
        self.syn_sent_at = now
        self._arm("handshake", now + HANDSHAKE_BOUND)
        self._send_syn(now)

    def _t_budget(self, now):
        if self.phase != "est":
            return
        if self.disrupted:
            self._teardown(now, "at_budget")
        else:
            # Nothing disruptive reached Zhida: no mutation fires after the budget, and the
            # connection continues as a stream-preserving one.
            self._drop_unreached()

    def _teardown(self, now, cause):
        self.stats[f"disruptive_teardown_{cause}"] += 1
        self.phase = "teardown"
        self.held = []
        self.timers = {"deadline": self.timers["deadline"], "td_ack": now + QUIESCE}

    def _t_td_ack(self, now):
        s = self.latest
        self._emit(self.build.tcp(self.plan.sport, s.ack, seqmath.add(s.seq, s.seg_len), ACK,
                                  self._window_field(), self._options(now)), now)
        self._arm("td_rst", now + QUIESCE)

    def _t_td_rst(self, now):
        self.teardown_rst = self.latest.ack
        self._send_teardown_rst(now)

    def _send_teardown_rst(self, now):
        self.teardown_rsts += 1
        self._emit(self.build.tcp(self.plan.sport, self.teardown_rst, 0, RST, 0), now)
        self._arm("td_end", now + QUIESCE)

    def _t_td_end(self, now):
        ack = self.latest.ack  # a challenge ACK names the sequence number Zhida expects
        if ack != self.teardown_rst and self.teardown_rsts <= TEARDOWN_RST_RETRIES:
            self.stats["fuzzer_teardown_rst_retries"] += 1
            self.teardown_rst = ack
            self._send_teardown_rst(now)
        else:
            self.finish(now)

    def _t_rto(self, now):
        if self.snd_una >= self.snd_max:
            return
        self.stats["fuzzer_rtos"] += 1
        self.snd_nxt = self.snd_una
        self.rto = min(self.rto * 2, RTO_MAX)
        self._cancel("pace")
        self._arm("rto", now + self.rto)
        self._pump(now)

    def _t_persist(self, now):
        if self.peer_right > self.snd_nxt or self.snd_nxt > self.L:
            return
        self.stats["fuzzer_window_probes"] += 1
        self._emit(self._segment(now, self.snd_una - 1, ACK), now)
        self.persist = min(self.persist * 2, RTO_MAX)
        self._arm("persist", now + self.persist)

    def _t_delack(self, now):
        self._send_ack(now)

    def _t_pace(self, now):
        self._pump(now)

    def _t_release(self, now):
        self._release(now, lambda h: True)

    def _t_stall(self, now):
        self.unread = 0
        self._send_ack(now)  # window update

    # ---------------------------------------------------------------- finish

    def _check_done(self, now):
        if self.phase == "est" and not self.failures and \
                self.snd_una == self.L + 2 and self.peer_fin:
            if self.disrupted:
                # The fuzzer's view of the close can be wrong after a mutation (e.g. an
                # injected FIN Zhida took but the sender model did not count leaves the
                # fuzzer's ACKs below Zhida's RCV.NXT and Zhida in LAST-ACK: seed 2
                # connection 155), so the teardown always runs.
                self._teardown(now, "after_close")
            else:
                self.finish(now)

    def _drop_unreached(self):
        for m in self.mutations:
            self.stats[f"mutunreached_{m['class']}.{m['kind']}"] += 1
        self.mutations = []

    def finish(self, now):
        st = self.stats
        errors = []
        self._drop_unreached()
        if now > self.t0 + self.plan.deadline:
            # A frame handled after the deadline passed, before the deadline timer ran
            # (fuzz_tcp.Runner.poll), may have completed the connection.
            errors.append(f"connection finished {now - self.t0:.3f} s after its start, past "
                          f"its {self.plan.deadline} s deadline")
        if self.disrupted:
            if self.record.conflicting:
                st["check_stream_prefix_skipped_conflicting"] += 1
            else:
                st["check_stream_prefix"] += 1
                error = oracles.check_stream_prefix(self.data, bytes(self.received))
                if error:
                    errors.append(error)
        else:
            if self.plan.kind == "disruptive":
                st["disruptive_nothing_applied"] += 1
            st["check_stream_exact"] += 1
            error = oracles.check_stream_exact(self.data, bytes(self.received))
            if error:
                errors.append(error)
            st["check_clean_close"] += 1
            errors += oracles.check_clean_close(self.snd_una == self.L + 2, self.peer_fin,
                                                self.zhida_rsts)
        st["check_handshake"] += 1
        error = oracles.check_handshake(self.synack_after, HANDSHAKE_BOUND)
        if error:
            errors.append(error)
        self.failures += errors
        self.phase = "done"
        self.timers.clear()
