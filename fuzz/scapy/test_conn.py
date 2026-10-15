import struct
import unittest
from collections import Counter
from dataclasses import replace

import mutate
import oracles
import seqmath
from conn import QUIESCE, STALE_DUPACK_INTERVAL, Conn
from plan import PACING_TOTAL_MS, make_plan, probe_plan
from testframes import ENV, tcp_frame
from wire import ACK, FIN, PSH, RST, SYN, Builder, fix_checksums, parse_tcp

CISN = 70000  # Synthetic server fixture; the live runner learns ISNs from SYN-ACKs.
TS = b"\x01\x01\x08\x0a" + struct.pack("!II", 1, 0)
MSS_WS = b"\x02\x04\x05\xb4" + b"\x01\x03\x03\x07"


class Harness:
    """One Conn driven by hand: `zhida` plays Zhida's segments (through the runner's
    well-formed-output check), `sent` collects the fuzzer's frames."""

    def __init__(self, plan):
        self.sent = []
        self.stats = Counter()
        self.c = Conn(plan, Builder(ENV), lambda f, now: self.sent.append(f), self.stats, 0.0)

    def segs(self, start=0):
        return [parse_tcp(f) for f in self.sent[start:]]

    def ack_of(self, n):
        """The ACK number covering the SYN and n payload bytes of the fuzzer."""
        return seqmath.add(self.c.isn, 1 + n)

    def zhida(self, flags, seq, ack, payload=b"", window=65535, ts=False, now=0.0):
        if flags & RST:
            options = b""
        elif flags & SYN:
            options = MSS_WS + TS if ts else MSS_WS
        else:
            options = TS if ts else b""
        frame = tcp_frame(flags, seq, ack, window=window, options=options, payload=payload,
                          dport=self.c.plan.sport)
        _, seg, errors = oracles.check_frame(frame, ENV)
        assert not errors, errors
        self.c.on_segment(seg, now)

    def establish(self, ts=False, now=0.01):
        self.c.start(0.0)
        self.zhida(SYN | ACK, CISN, self.ack_of(0), ts=ts, now=now)

    def echo(self, lo, hi, now):
        """Zhida echoes payload bytes [lo, hi) and ACKs all the fuzzer's payload."""
        self.zhida(PSH | ACK, CISN + 1 + lo, self.ack_of(self.c.L), self.c.data[lo:hi],
                     now=now)

    def close(self, now):
        """Zhida's FIN after the whole echo, ACKing the fuzzer's FIN."""
        self.zhida(FIN | ACK, CISN + 1 + self.c.L, self.ack_of(self.c.L + 1), now=now)


def disruptive_probe(*mutations):
    return replace(probe_plan(1, 0), index="0", kind="disruptive", mutations=list(mutations))


def spec(cls, kind, target, p=4):
    return {"class": cls, "kind": kind, "target": target, "p": p}


class DataAfterFinTest(unittest.TestCase):
    """Payload at or past a FIN exercises Zhida's receive-side discard."""

    def conn(self):
        h = Harness(disruptive_probe())
        h.establish()
        h.sent.clear()
        return h

    def fin_frame(self, h):
        return h.c._segment(0.0, 11, FIN | ACK)

    def test_data_after_fin_sent(self):
        h = self.conn()
        self.assertTrue(h.c._send_mutated(spec("timing", "data_after_fin", "fin"),
                                          self.fin_frame(h), 0.0))
        self.assertEqual(len(h.sent), 2)
        self.assertEqual(len(parse_tcp(h.sent[1]).payload), 5)
        self.assertEqual(h.stats["mut_timing.data_after_fin"], 1)
        self.assertTrue(h.c.disrupted)

    def test_stream_data_after_an_early_fin_is_sent(self):
        h = self.conn()
        h.c._emit(h.c._segment(0.0, 11, FIN | ACK), 0.0)  # an early FIN at stream offset 10
        h.c.snd_nxt = 5
        h.c.timers.pop("pace", None)
        before = len(h.sent)
        h.c._pump(0.1)
        self.assertGreater(len(h.sent), before)
        self.assertTrue(any(s.payload for s in h.segs(before)))
        self.assertEqual(h.c.phase, "est")

    def test_retransmit_after_an_early_fin_is_sent(self):
        h = self.conn()
        h.c._emit(h.c._segment(0.0, 11, FIN | ACK), 0.0)
        h.c.snd_una = 5
        before = len(h.sent)
        h.c._retransmit_head(0.1)
        self.assertEqual(len(h.sent), before + 1)
        self.assertTrue(h.segs(before)[0].payload)
        self.assertEqual(h.c.phase, "est")

    def test_oversized_mutation_is_cut_to_the_mtu(self):
        h = self.conn()
        full = h.c._segment(0.0, 1, PSH | ACK, bytes(1460))
        h.c._send_mutated(spec("options", "syn_options_on_data", 0, 1), full, 0.0)
        [out] = h.sent
        self.assertEqual(len(out), 14 + 1500)
        seg = parse_tcp(out)
        self.assertTrue(seg.ip_checksum_ok and seg.tcp_checksum_ok)
        self.assertEqual(h.stats["fuzzer_mutated_frames_cut_to_mtu"], 1)
        self.assertEqual(h.stats["mut_options.syn_options_on_data"], 1)


class MutationOutcomeTest(unittest.TestCase):
    """Applied counts follow the frames actually sent; a plan with nothing applied is judged
    as stream-preserving."""

    def test_applied_syn_mutation(self):
        h = Harness(disruptive_probe(spec("ip", "ttl_1", "syn")))
        h.c.start(0.0)
        [seg] = h.segs()
        self.assertEqual(h.sent[0][22], 1)  # TTL
        self.assertEqual(seg.flags, SYN)
        self.assertEqual((h.stats["mut_ip.ttl_1"], h.stats["mutclass_ip"]), (1, 1))
        self.assertTrue(h.c.disrupted)
        self.assertIn("syn_retry", h.c.timers)

    def test_no_op_mutation_sends_the_clean_frame_and_judges_preserving(self):
        # The SYN already advertises 65535 (rcv_buffer 131072): win_max changes nothing.
        h = Harness(disruptive_probe(spec("window", "win_max", "syn")))
        h.establish()
        self.assertEqual(h.segs()[0].window, 65535)
        self.assertEqual(h.stats["mutnoop_window.win_max"], 1)
        self.assertEqual((h.stats["mut_window.win_max"], h.stats["mutclass_window"]), (0, 0))
        self.assertFalse(h.c.disrupted)
        h.echo(0, h.c.L, now=0.02)
        h.close(now=0.03)
        self.assertEqual(h.c.failures, [])
        self.assertEqual(h.c.phase, "done")
        self.assertEqual((h.stats["check_stream_exact"], h.stats["check_clean_close"],
                          h.stats["disruptive_nothing_applied"]), (1, 1, 1))
        self.assertEqual(h.stats["disruptive_teardown_after_close"], 0)

    def test_nothing_applied_by_the_budget_continues_preserving(self):
        # The FIN mutation's target comes only after the echo, which arrives after the budget.
        h = Harness(disruptive_probe(spec("timing", "fin_repeat", "fin")))
        h.establish()
        h.c.on_timer(h.c.plan.budget)
        self.assertEqual(h.c.phase, "est")
        self.assertEqual(h.stats["mutunreached_timing.fin_repeat"], 1)
        before = len(h.sent)
        h.echo(0, h.c.L, now=3.1)
        fins = [s for s in h.segs(before) if s.flags & FIN]
        self.assertEqual(len(fins), 1)  # the clean FIN, not repeated
        h.close(now=3.2)
        self.assertEqual(h.c.failures, [])
        self.assertEqual(h.stats["check_stream_exact"], 1)

    def test_rejected_frames_are_not_recorded(self):
        """Frames smoltcp's parser drops (wire.smoltcp_accepts) put nothing on record."""
        h = Harness(disruptive_probe())
        h.establish()
        shapes, syns = set(h.c.rst_shapes), set(h.c.syn_seqs)
        fin = h.c._segment(0.0, 11, FIN | ACK)
        h.c._emit(fix_checksums(mutate.tcp_flags(fin, SYN | FIN | ACK)), 0.0)
        self.assertEqual((h.c.rst_shapes, h.c.syn_seqs), (shapes, syns))
        data = h.c._segment(0.0, 1, PSH | ACK, bytes(b ^ 0xFF for b in h.c.data[:4]))
        h.c._emit(fix_checksums(mutate.put(data, 34, "!H", 0)), 0.0)  # source port 0
        self.assertFalse(h.c.record.conflicting)
        h.c._emit(data, 0.0)
        self.assertTrue(h.c.record.conflicting)


class DeadlineTest(unittest.TestCase):
    def run_probe(self, close_at):
        h = Harness(probe_plan(1, 0))  # deadline 5 s
        h.establish()
        h.echo(0, h.c.L, now=0.02)
        h.close(now=close_at)
        return h

    def test_completion_in_time(self):
        h = self.run_probe(0.03)
        self.assertEqual(h.c.failures, [])
        self.assertEqual(h.c.phase, "done")

    def test_completion_after_the_deadline_fails(self):
        h = self.run_probe(6.0)
        self.assertEqual(h.c.phase, "done")
        self.assertEqual(len(h.c.failures), 1)
        self.assertIn("past its 5.0 s deadline", h.c.failures[0])


class ClientModelTest(unittest.TestCase):
    """Invariants of the Linux-like client the oracles rely on."""

    def test_teardown_acks_zhidas_latest_segment_then_resets_at_its_ack(self):
        h = Harness(disruptive_probe(spec("ip", "ttl_1", "syn")))
        h.establish()
        h.zhida(ACK, CISN + 1, h.ack_of(500), now=0.02)  # Zhida's latest: ACKs 500 bytes
        h.zhida(RST, CISN + 1, 0, window=0, now=0.03)  # SEQ = the fuzzer's ACK: rst_reply
        self.assertEqual(h.c.failures, [])
        self.assertEqual(h.c.phase, "teardown")
        before = len(h.sent)
        for t in (0.03 + QUIESCE, 0.03 + 2 * QUIESCE, 0.03 + 3 * QUIESCE):
            h.c.on_timer(t + 1e-6)
        ack, rst = h.segs(before)
        self.assertEqual((ack.flags, ack.seq, ack.ack), (ACK, h.ack_of(500), CISN + 1))
        self.assertEqual((rst.flags, rst.seq), (RST, h.ack_of(500)))
        self.assertEqual((h.c.phase, h.c.failures), ("done", []))
        self.assertEqual(h.stats["disruptive_teardown_after_zhida_rst"], 1)

    def test_stale_pure_ack_is_discarded_with_a_rate_limited_dup_ack(self):
        h = Harness(probe_plan(1, 0))
        h.establish()
        h.echo(0, 100, now=0.02)
        acks = []
        for t in (0.1, 0.2, 0.1 + STALE_DUPACK_INTERVAL + 0.01):
            before = len(h.sent)
            h.zhida(ACK, CISN + 1, h.ack_of(h.c.L), now=t)  # SEQ below RCV.NXT (rewound after an RTO)
            acks.append([(s.flags, s.ack) for s in h.segs(before)])
        self.assertEqual(acks, [[(ACK, CISN + 101)], [], [(ACK, CISN + 101)]])

        self.assertEqual(h.stats["stale_zhida_segments_discarded"], 3)
        self.assertEqual(h.c.failures, [])

    def test_out_of_order_reassembly(self):
        h = Harness(probe_plan(1, 0))
        h.establish()
        before = len(h.sent)
        h.echo(100, 200, now=0.02)
        self.assertEqual(bytes(h.c.received), b"")
        h.echo(0, 100, now=0.03)
        self.assertEqual(bytes(h.c.received), h.c.data[:200])
        self.assertEqual([s.ack for s in h.segs(before)], [CISN + 1, CISN + 201])

    def test_advertised_right_edge_never_moves_back(self):
        # Window scale 7 (128-byte units) while the application reads nothing: rounding the
        # free space up to units would move the edge back at 128 bytes received.
        plan = replace(probe_plan(1, 0), rcv_buffer=4096, stall={"at": 0, "ms": 1000},
                       ack={"every": 1, "delay_ms": 40})
        h = Harness(plan)
        h.establish()
        start = len(h.sent) - 2  # the handshake ACK and the data segment
        pos = 0
        for n in (10, 118, 7, 200, 13, 300, 128, 90):
            h.echo(pos, pos + n, now=0.02)
            pos += n
        windows = [s.window for s in h.segs(start)]
        edges = [seqmath.add(s.ack, s.window << 7) for s in h.segs(start)]
        self.assertLess(windows[-1], windows[0])  # the window closes
        for a, b in zip(edges, edges[1:]):
            self.assertFalse(seqmath.lt(b, a), edges)


class WindowBoundTest(unittest.TestCase):
    """Zhida's window is bounded by 65535 scaled by the shift its SYN-ACK announced
    (MSS_WS: 7), not by the unscaled SYN-ACK window."""

    def setUp(self):
        self.h = Harness(disruptive_probe())
        self.h.establish()
        self.assertEqual(self.h.c.peer_ws, 7)

    def test_bytes_past_the_unscaled_window_are_recorded(self):
        c = self.h.c
        c._emit(c._segment(0.0, 70001, PSH | ACK, b"\xEE"), 0.0)
        self.assertTrue(c.record.conflicting)

    def test_bytes_past_the_scaled_window_are_not_recorded(self):
        c = self.h.c
        c._emit(c._segment(0.0, c.snd_max + (65535 << 7), PSH | ACK, b"\xEE"), 0.0)
        self.assertFalse(c.record.conflicting)

    def test_max_right_counts_the_frame_in_flight_and_the_scale(self):
        c = self.h.c
        frame = c._segment(0.0, 5001, PSH | ACK, b"x" * 100)
        end = 5001 + len(parse_tcp(frame).payload)
        self.assertEqual(c._max_right(frame), max(c.snd_max, end) + (65535 << 7))


class ProbeTimestampTest(unittest.TestCase):
    def test_synack_learns_arbitrary_server_isn(self):
        for isn in (0, 70000, 0xA5A5A5A5, 0xFFFFFFFF):
            with self.subTest(isn=isn):
                h = Harness(probe_plan(1, 0))
                h.c.start(0.0)
                h.zhida(SYN | ACK, isn, h.ack_of(0), now=0.01)
                self.assertEqual(h.c.failures, [])
                self.assertEqual(h.c.cisn, isn)
                self.assertEqual(h.c.rcv_nxt, seqmath.add(isn, 1))
                self.assertEqual(h.segs()[-1].ack, seqmath.add(isn, 1))

    def test_probe_synack_with_timestamps_fails(self):
        h = Harness(probe_plan(1, 0))
        h.establish(ts=True)
        self.assertEqual(len(h.c.failures), 1)
        self.assertIn("SYN-ACK carried TS", h.c.failures[0])

    def test_probe_synack_without_timestamps_passes(self):
        h = Harness(probe_plan(1, 0))
        h.establish(ts=False)
        self.assertEqual(h.c.failures, [])
        self.assertFalse(h.c.ts_on)
        self.assertIsNotNone(h.segs()[0].timestamp)
        self.assertTrue(all(seg.timestamp is None for seg in h.segs()[1:]))

    def test_numbered_plan_without_timestamps_passes(self):
        h = Harness(replace(probe_plan(1, 0), index="7"))
        h.establish(ts=False)
        self.assertEqual(h.c.failures, [])
        self.assertFalse(h.c.ts_on)

    def test_numbered_plan_with_timestamps_keeps_generic_coverage(self):
        h = Harness(replace(probe_plan(1, 0), index="7"))
        h.establish(ts=True)
        self.assertEqual(h.c.failures, [])
        self.assertTrue(h.c.ts_on)
        self.assertTrue(all(seg.timestamp is not None for seg in h.segs()[1:]))


class PacingTest(unittest.TestCase):
    def test_pacing_gaps_sum_within_the_bound(self):
        """Without loss and with Zhida ACKing everything at once into a large window, the
        first transmission of the whole payload ends within PACING_TOTAL_MS of gaps."""
        checked = 0
        for i in range(300):
            plan = replace(make_plan(1, i), tx=[], drop_own_fin=False)
            if plan.kind != "preserving" or plan.pacing["mode"] == "burst" or not plan.payload:
                continue
            h = Harness(plan)
            h.establish(now=0.0)
            t = 0.0
            while not h.c.failures:
                h.zhida(ACK, CISN + 1, seqmath.add(h.c.isn, h.c.snd_max),
                          now=t)
                if h.c.snd_max > h.c.L:
                    break
                t = h.c.timers["pace"]
                h.c.on_timer(t)
            self.assertEqual(h.c.failures, [], i)
            self.assertLessEqual(t, PACING_TOTAL_MS / 1000 + 1e-6, (i, plan.pacing, plan.sizes))
            checked += 1
        self.assertGreater(checked, 50)


if __name__ == "__main__":
    unittest.main()
