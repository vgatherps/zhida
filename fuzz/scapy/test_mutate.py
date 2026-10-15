import random
import struct
import unittest

import mutate
from mutate import KINDS, View
from testframes import ENV, tcp_frame
from wire import (ACK, FIN, OPT_MSS, OPT_SACK, OPT_SACK_PERM, OPT_WSCALE, PSH, RST, SYN,
                  Malformed, fix_checksums, parse_options, parse_tcp, smoltcp_accepts)

TS = b"\x01\x01\x08\x0a" + struct.pack("!II", 1000, 2000)
SYN_OPTS = (b"\x02\x04\x05\xb4\x04\x02\x08\x0a" + struct.pack("!II", 1000, 0)
            + b"\x01\x03\x03\x07")
SEQ, ACKNO = 0x10000000, 0x20000000
PAYLOAD = bytes(range(200))
IP_CSUM, TCP_CSUM = {24, 25}, {50, 51}


def fuzzer_frame(flags=PSH | ACK, payload=PAYLOAD, options=TS, seq=SEQ):
    """A clean frame from the fuzzer (tester -> Zhida)."""
    return tcp_frame(flags, seq, ACKNO, window=502, options=options, payload=payload,
                     src_mac=ENV.tester_mac, dst_mac=ENV.zhida_mac, src_ip=ENV.tester_ip,
                     dst_ip=ENV.zhida_ip, sport=40000, dport=8080)


def view():
    return View(peer_ack=SEQ, peer_right=SEQ + 4000, peer_max_right=SEQ + 65535, rcv_nxt=ACKNO,
                stream=PAYLOAD,
                build=lambda seq, flags, payload=b"": fuzzer_frame(flags, payload, TS, seq))


def changed(a, b):
    assert len(a) == len(b)
    return {i for i in range(len(a)) if a[i] != b[i]}


class ConstructorTest(unittest.TestCase):
    """Each byte constructor changes exactly its field."""

    def setUp(self):
        self.frame = fuzzer_frame()

    def assert_field(self, out, positions):
        diff = changed(self.frame, out)
        self.assertTrue(diff, "constructor changed nothing")
        self.assertLessEqual(diff, positions)

    def test_ip_fields(self):
        self.assert_field(mutate.ip_ttl(self.frame, 1), {22})
        self.assert_field(mutate.ip_tos(self.frame, 0xB8), {15})
        self.assert_field(mutate.ip_id(self.frame, 0xBEEF), {18, 19})
        self.assert_field(mutate.ip_flags_frag(self.frame, 0x2001), {20, 21})
        self.assert_field(mutate.ip_total(self.frame, 99), {16, 17})
        out = mutate.ip_ihl(self.frame, 7)
        self.assert_field(out, {14})
        self.assertEqual(out[14], 0x47)  # version kept

    def test_tcp_fields(self):
        self.assert_field(mutate.tcp_seq(self.frame, 5), set(range(38, 42)))
        self.assert_field(mutate.tcp_ack(self.frame, 5), set(range(42, 46)))
        self.assert_field(mutate.tcp_flags(self.frame, SYN | FIN), {47})
        self.assert_field(mutate.tcp_window(self.frame, 0), {48, 49})
        self.assert_field(mutate.tcp_urgent(self.frame, 3), {52, 53})
        out = mutate.tcp_doff(self.frame, 6)
        self.assert_field(out, {46})
        self.assertEqual(out[46] >> 4, 6)

    def test_corrupt_checksum(self):
        out = mutate.corrupt_checksum(self.frame, 50)
        self.assert_field(out, TCP_CSUM)
        self.assertFalse(parse_tcp(out).tcp_checksum_ok)

    def test_tcp_options_relayout(self):
        out = mutate.tcp_options(self.frame, b"\x02\x04\x05\xb4" + TS)
        seg, before = parse_tcp(fix_checksums(out)), parse_tcp(self.frame)
        self.assertEqual((seg.doff, seg.ip_total), (before.doff + 1, before.ip_total + 4))
        self.assertEqual(seg.payload, PAYLOAD)
        self.assertEqual((seg.seq, seg.ack, seg.flags, seg.window), (SEQ, ACKNO, PSH | ACK, 502))
        self.assertEqual((seg.mss, seg.timestamp), (1460, (1000, 2000)))
        self.assertTrue(seg.tcp_checksum_ok and seg.ip_checksum_ok)

    def test_with_option_in_place_and_appended(self):
        syn = fuzzer_frame(SYN, b"", SYN_OPTS)
        out = mutate.with_option(syn, OPT_MSS, b"\x00\x00")
        self.assertEqual(changed(syn, out), {56, 57})
        self.assertEqual(mutate.used_options(syn), SYN_OPTS)  # TS ecr 0 is not padding
        no_ws = fuzzer_frame(SYN, b"", SYN_OPTS[:16] + b"\0" * 4)
        seg = parse_tcp(fix_checksums(mutate.with_option(no_ws, OPT_WSCALE, b"\x0f")))
        self.assertEqual((seg.wscale, seg.mss, seg.timestamp), (15, 1460, (1000, 0)))

    def test_truncate_and_append(self):
        out = mutate.truncate(self.frame, 60)
        self.assertEqual(len(out), 60)
        self.assertEqual(struct.unpack_from("!H", out, 16)[0], 46)
        self.assertLessEqual(changed(self.frame[:60], out), {16, 17})
        syn = fuzzer_frame(SYN, b"", SYN_OPTS)
        seg = parse_tcp(fix_checksums(mutate.append_payload(syn, b"abc")))
        self.assertEqual((seg.payload, seg.mss), (b"abc", 1460))

    def test_payload_xor(self):
        out = mutate.payload_xor(self.frame, 10, 20)
        start = len(self.frame) - len(PAYLOAD)
        self.assertEqual(changed(self.frame, out), set(range(start + 10, start + 20)))


def apply(cls, kind, frame=None, p=12345):
    return mutate.apply({"class": cls, "kind": kind, "target": 0, "p": p},
                        frame if frame is not None else fuzzer_frame(), view())


class ApplyTest(unittest.TestCase):
    """apply = constructor + checksums as the receiver reads them; the target field moves."""

    FIELDS = {"ip": {"ttl_0": {22}, "ttl_1": {22}, "ttl_255": {22}, "tos": {15},
                     "id": {18, 19}, "df_clear": {20, 21}, "mf_set": {20, 21},
                     "frag_offset": {20, 21}, "total_short": {16, 17},
                     "total_long": {16, 17}},
              "window": {"win_0": {48, 49}, "win_1": {48, 49}, "win_max": {48, 49}},
              "seqack": {k: set(range(38, 42)) if k.startswith("seq") else set(range(42, 46))
                         for k in KINDS["seqack"]},
              "flags": {k: {47, 52, 53} if k == "urg" else {47} for k in KINDS["flags"]}}

    def test_every_kind_applies_to_every_allowed_target(self):
        frames = {"S": fuzzer_frame(SYN, b"", SYN_OPTS), "A": fuzzer_frame(ACK, b""),
                  "D": fuzzer_frame(), "F": fuzzer_frame(FIN | ACK, b"")}
        for cls, kinds in KINDS.items():
            for kind, targets in kinds.items():
                for t in targets:
                    for p in (0, 1, 2, 0xFFFFFFFF, 987654321):
                        out = apply(cls, kind, frames[t], p)
                        self.assertTrue(out, (cls, kind, t))
                        self.assertNotEqual(out, [frames[t]], (cls, kind, t, p))

    def test_single_field_kinds(self):
        frame = fuzzer_frame()
        for cls, kinds in self.FIELDS.items():
            for kind, positions in kinds.items():
                for p in (0, 7, 0xFFFFFFFF):
                    [out] = apply(cls, kind, frame, p)
                    diff = changed(frame, out)
                    self.assertLessEqual(diff, positions | IP_CSUM | TCP_CSUM, (cls, kind))
                    self.assertTrue(diff & positions, (cls, kind, p))
                    if kind not in ("total_long", "total_short"):  # TCP header may be cut
                        seg = parse_tcp(out)
                        self.assertTrue(seg.ip_checksum_ok and seg.tcp_checksum_ok, (cls, kind))

    def test_ip_header_length_and_checksum(self):
        frame = fuzzer_frame()
        [out] = apply("ip", "bad_checksum", frame)
        self.assertEqual(changed(frame, out), IP_CSUM)
        self.assertFalse(parse_tcp(out).ip_checksum_ok)
        [out] = apply("ip", "ihl_short", frame, 3)
        self.assertEqual(changed(frame, out), {14})
        with self.assertRaises(Malformed):
            parse_tcp(out)
        clean = parse_tcp(frame)
        for p in (0, 9):
            [out] = apply("ip", "ihl_long", frame, p)
            seg = parse_tcp(out)
            self.assertEqual(seg.ihl, 6 + p)
            self.assertEqual(out[34:14 + seg.ihl * 4], b"\x01" * (4 * seg.ihl - 21) + b"\0")
            self.assertEqual(out[14 + seg.ihl * 4:], frame[34:])  # TCP bytes identical
            self.assertEqual(seg.ip_total, clean.ip_total + 4 * (seg.ihl - 5))
            self.assertEqual((seg.sport, seg.dport, seg.seq, seg.ack, seg.flags, seg.payload),
                             (clean.sport, clean.dport, clean.seq, clean.ack, clean.flags,
                              clean.payload))
            self.assertTrue(smoltcp_accepts(seg))

    def test_values(self):
        frame = fuzzer_frame()
        seg = lambda out: parse_tcp(out[0])
        self.assertEqual(seg(apply("seqack", "seq_window_edge")).seq, SEQ + 4000)
        self.assertEqual(seg(apply("seqack", "seq_window_last")).seq, SEQ + 3999)
        self.assertEqual(seg(apply("seqack", "seq_wrap")).seq, SEQ ^ 0x80000000)
        self.assertEqual(seg(apply("seqack", "ack_zero")).ack, 0)
        self.assertGreater(seg(apply("seqack", "ack_unsent")).ack, ACKNO)
        self.assertEqual(seg(apply("flags", "syn_fin")).flags, SYN | FIN | ACK)
        self.assertEqual(seg(apply("flags", "none")).flags, 0)
        self.assertEqual(seg(apply("flags", "no_ack")).flags, PSH)
        self.assertEqual(seg(apply("window", "win_0")).window, 0)
        # total = 20 + p % (252 - 20) = 102: 82 TCP bytes, 32 of header and 50 of payload.
        self.assertEqual(parse_tcp(apply("ip", "total_short", frame, 82)[0]).payload,
                         PAYLOAD[:50])

    def test_options_kinds(self):
        frame = fuzzer_frame()
        syn = fuzzer_frame(SYN, b"", SYN_OPTS)
        opts = lambda out: parse_options(parse_tcp(out[0]).options_raw)
        for p in range(3):
            self.assertIsNotNone(opts(apply("options", "bad_length", frame, p))[1])
        self.assertIn("no length byte", opts(apply("options", "truncated", frame))[1])
        self.assertIn("no length byte", opts(apply("options", "truncated", syn))[1])
        parsed, error = opts(apply("options", "unknown_kind", frame, 3))
        self.assertIsNone(error)
        self.assertIn(30, [k for k, _ in parsed])
        self.assertEqual(parse_tcp(apply("options", "mss_0", syn)[0]).mss, 0)
        self.assertEqual(parse_tcp(apply("options", "mss_65535", syn)[0]).mss, 65535)
        self.assertEqual(parse_tcp(apply("options", "wscale_255", syn)[0]).wscale, 255)
        seg = parse_tcp(apply("options", "sack_bogus", frame, 2)[0])
        self.assertEqual(len(seg.option(OPT_SACK)), 24)
        self.assertEqual(seg.timestamp, (1000, 2000))
        self.assertNotEqual(parse_tcp(apply("options", "ts_garbage", frame)[0]).timestamp,
                            (1000, 2000))
        seg = parse_tcp(apply("options", "syn_options_on_data", frame)[0])
        self.assertEqual((seg.mss, seg.wscale, seg.option(OPT_SACK_PERM)), (1460, 7, b""))
        for kind in KINDS["options"]:
            target = syn if "S" in KINDS["options"][kind] and "D" not in KINDS["options"][kind] \
                else frame
            out = parse_tcp(apply("options", kind, target)[0])
            self.assertEqual(out.payload, parse_tcp(target).payload, kind)
            self.assertTrue(out.tcp_checksum_ok, kind)

    def test_lengths_kinds(self):
        frame = fuzzer_frame()
        seg = parse_tcp(apply("lengths", "doff_small", fuzzer_frame(SYN, b"", SYN_OPTS))[0])
        self.assertEqual((seg.doff, seg.payload), (5, SYN_OPTS))
        with self.assertRaises(Malformed):
            parse_tcp(apply("lengths", "doff_below_5", frame, 3)[0])
        self.assertEqual(apply("lengths", "doff_max", frame)[0][46] >> 4, 15)
        with self.assertRaises(Malformed):
            parse_tcp(apply("lengths", "truncated_header", frame, 9)[0])
        seg = parse_tcp(apply("lengths", "truncated_payload", frame, 50)[0])
        self.assertEqual(seg.payload, PAYLOAD[:50])
        self.assertTrue(seg.tcp_checksum_ok)

    def test_overlap_kinds_conflict(self):
        frame = fuzzer_frame()
        a, b = (parse_tcp(f) for f in apply("overlap", "conflict_same", frame, 1))
        self.assertEqual(a.seq, b.seq)
        self.assertTrue(all(x != y for x, y in zip(a.payload, b.payload)))
        self.assertEqual(b.payload, PAYLOAD)  # odd p: the conflicting copy first
        orig, other = (parse_tcp(f) for f in apply("overlap", "conflict_shifted", frame, 9))
        self.assertEqual(other.seq, SEQ + 10)
        self.assertEqual(orig.payload, PAYLOAD)
        self.assertNotEqual(other.payload[0], PAYLOAD[10])

    def test_timing_kinds(self):
        frame = fuzzer_frame()
        fin = fuzzer_frame(FIN | ACK, b"", seq=SEQ + 300)
        segs = lambda out: [parse_tcp(f) for f in out]
        orig, rst = segs(apply("timing", "rst_exact", frame))
        self.assertEqual((orig.payload, rst.flags, rst.seq), (PAYLOAD, RST, SEQ))
        _, rst = segs(apply("timing", "rst_in_window", frame, 10))
        self.assertTrue(SEQ < rst.seq < SEQ + 4000)
        _, rst = segs(apply("timing", "rst_out_of_window", frame))
        self.assertGreaterEqual(rst.seq, SEQ + 65535)  # past any window, not just the advertised one
        _, rst = segs(apply("timing", "rst_ack", frame))
        self.assertEqual(rst.flags, RST | ACK)
        _, early = segs(apply("timing", "early_fin", frame))
        self.assertEqual((early.flags & FIN, early.seq), (FIN, SEQ + len(PAYLOAD)))
        self.assertEqual(len(apply("timing", "fin_repeat", fin, 2)), 4)
        _, after = segs(apply("timing", "data_after_fin", fin, 4))
        self.assertEqual((after.seq, len(after.payload)), (SEQ + 301, 5))
        _, syn = segs(apply("timing", "syn_mid", frame, 3))
        self.assertEqual(syn.flags, SYN)
        self.assertTrue(SEQ <= syn.seq < SEQ + 4000)
        [syn] = segs(apply("timing", "syn_data", fuzzer_frame(SYN, b"", SYN_OPTS), 9))
        self.assertEqual((syn.flags, syn.payload, syn.mss), (SYN, PAYLOAD[:10], 1460))


class DrawTest(unittest.TestCase):
    def test_deterministic(self):
        a = mutate.draw(random.Random("1:5"), 1000, 3)
        self.assertEqual(a, mutate.draw(random.Random("1:5"), 1000, 3))
        self.assertNotEqual(a, mutate.draw(random.Random("2:5"), 1000, 3))

    def test_draw_rule(self):
        for i in range(2000):
            rng = random.Random(i)
            specs = mutate.draw(rng, rng.choice([0, 100]), 1 + i % 3)
            control = [s["target"] for s in specs if isinstance(s["target"], str)]
            self.assertEqual(len(control), len(set(control)))
            for s in specs:
                if isinstance(s["target"], int):
                    self.assertIn("D", KINDS[s["class"]][s["kind"]])

    def test_resets_drawn_with_a_tsless_syn(self):
        """Kinds that may put an RST into SYN-RECEIVED are drawn together with a SYN mutation
        that turns the SYN's options (TS included) into payload: a listener reset in
        SYN-RECEIVED negotiates the next SYN afresh, so nothing is excluded."""
        resets = {("timing", "rst_in_window"), ("timing", "rst_exact"), ("timing", "rst_ack"),
                  ("flags", "random")}
        seen = set()
        for i in range(20000):
            specs = mutate.draw(random.Random(i), 100, 3)
            if any(s["target"] == "syn" and (s["class"], s["kind"]) == ("lengths", "doff_small")
                   for s in specs):
                seen |= {(s["class"], s["kind"]) for s in specs if s["target"] != "syn"}
        self.assertEqual(seen & resets, resets)

    def test_every_class_drawn(self):
        rng = random.Random(0)
        seen = {s["class"] for _ in range(300) for s in mutate.draw(rng, 500, 1)}
        self.assertEqual(seen, set(KINDS))


if __name__ == "__main__":
    unittest.main()
