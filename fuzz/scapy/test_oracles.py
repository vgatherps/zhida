import struct
import unittest

import oracles
import seqmath
from testframes import ENV, arp_frame, tcp_frame
from wire import ACK, FIN, PSH, RST, SYN, parse_tcp

TS = b"\x08\x0a" + struct.pack("!II", 100, 1000) + b"\x00\x00"
SYNACK_OPTS = (b"\x02\x04\x05\xb4" + b"\x03\x03\x02" + b"\x04\x02" + b"\x08\x0a"
               + struct.pack("!II", 100, 1000) + b"\x00")


def errors(frame):
    return oracles.check_frame(frame, ENV)[2]


class CheckFrameTest(unittest.TestCase):
    def assert_flags(self, frame, text):
        found = errors(frame)
        self.assertTrue(any(text in e for e in found), f"{text!r} not in {found}")

    def test_valid_segments_pass(self):
        self.assertEqual(errors(tcp_frame(SYN | ACK, 5, 6, options=SYNACK_OPTS)), [])
        self.assertEqual(errors(tcp_frame(PSH | ACK, 6, 7, options=TS, payload=b"abc")), [])
        self.assertEqual(errors(tcp_frame(RST, 6, 0)), [])
        kind, seg, _ = oracles.check_frame(tcp_frame(ACK, 6, 7, options=TS), ENV)
        self.assertEqual((kind, seg.timestamp), ("tcp", (100, 1000)))

    def test_bad_ip_checksum(self):
        frame = bytearray(tcp_frame(ACK, 1, 2))
        frame[24] ^= 0xFF
        self.assert_flags(bytes(frame), "bad IP header checksum")

    def test_bad_tcp_checksum(self):
        frame = bytearray(tcp_frame(ACK, 1, 2, payload=b"x"))
        frame[-1] ^= 0x01
        self.assert_flags(bytes(frame), "bad TCP checksum")

    def test_ip_options(self):
        self.assert_flags(tcp_frame(ACK, 1, 2, ip_options=b"\x01\x01\x01\x00"), "IHL 6")

    def test_addresses_and_port(self):
        self.assert_flags(tcp_frame(ACK, 1, 2, src_mac=b"\x02" * 6), "not ZHIDA_MAC")
        self.assert_flags(tcp_frame(ACK, 1, 2, dst_mac=b"\x02" * 6), "is not TESTER_MAC")
        self.assert_flags(tcp_frame(ACK, 1, 2, dst_ip=b"\x0a\0\0\x01"), "IP addresses")
        self.assert_flags(tcp_frame(ACK, 1, 2, src_ip=b"\x0a\0\0\x01"), "IP addresses")
        self.assert_flags(tcp_frame(ACK, 1, 2, sport=8081), "source port 8081")

    def test_options_must_parse(self):
        self.assert_flags(tcp_frame(ACK, 1, 2, options=b"\x02\x03\x05\x01"),
                          "kind 2 has length 3, expected 4")
        self.assert_flags(tcp_frame(ACK, 1, 2, options=b"\x02\x05\x05\xb4"),
                          "at byte 0 has length 5")
        self.assert_flags(tcp_frame(ACK, 1, 2, options=b"\x00\x01\x00\x00"),
                          "nonzero padding after EOL")
        self.assert_flags(tcp_frame(ACK, 1, 2, options=b"\x01\x01\x01\x08"), "no length byte")
        self.assert_flags(tcp_frame(ACK, 1, 2, options=b"\x05\x0c" + b"\0" * 10),
                          "SACK option length 12")

    def test_flag_combinations(self):
        self.assert_flags(tcp_frame(SYN | FIN | ACK, 1, 2), "SYN+FIN")
        self.assert_flags(tcp_frame(SYN | RST | ACK, 1, 2), "SYN+RST")
        self.assert_flags(tcp_frame(PSH, 1, 2, payload=b"x"), "ACK missing")
        self.assert_flags(tcp_frame(0, 1, 2), "ACK missing")

    def test_unreadable_frames(self):
        self.assert_flags(tcp_frame(ACK, 1, 2)[:30], "too short")
        frame = tcp_frame(ACK, 1, 2)
        self.assert_flags(frame[:12] + b"\x86\xdd" + frame[14:], "neither ARP nor IPv4")
        self.assert_flags(frame[:14] + b"\x46" + frame[15:], "shorter than its header")

    def test_arp(self):
        _, arp, errs = oracles.check_frame(arp_frame(), ENV)
        self.assertEqual(errs, [])
        self.assertEqual(arp.tpa, ENV.tester_ip)
        self.assertTrue(any("op 2" in e for e in errors(arp_frame(op=2))))
        self.assertTrue(any("sender" in e for e in errors(arp_frame(spa=b"\x0a\0\0\x09"))))
        self.assertTrue(any("sender" in e for e in errors(arp_frame(sha=b"\x02" * 6))))


class SeqCoverageTest(unittest.TestCase):
    def test_gaps_and_merges(self):
        c = oracles.SeqCoverage(1000)
        c.add(1000, 10)
        c.add(1020, 5)
        self.assertTrue(c.covers(1000, 1010))
        self.assertFalse(c.covers(1000, 1011))
        self.assertFalse(c.covers(1005, 1022))
        c.add(1010, 10)
        self.assertTrue(c.covers(1000, 1025))
        self.assertTrue(c.covers(1003, 1003))

    def test_wrap(self):
        c = oracles.SeqCoverage(0xFFFFFFF0)
        c.add(0xFFFFFFF0, 0x40)  # crosses 2**32
        self.assertTrue(c.covers(0xFFFFFFF8, 0x20))
        self.assertFalse(c.covers(0xFFFFFFF8, 0x31))
        straddle = oracles.SeqCoverage(10)
        straddle.add(5, 10)  # [5, 15) straddles the base: offsets wrap inside the range
        self.assertTrue(straddle.covers(7, 12))
        self.assertFalse(straddle.covers(7, 16))
        self.assertFalse(straddle.covers(3, 12))


class AckBoundTest(unittest.TestCase):
    def setUp(self):
        self.isn = 0xFFFFFFC0
        self.cov = oracles.SeqCoverage(self.isn)
        self.cov.add(self.isn, 1)  # SYN
        self.cov.add(self.isn + 1, 63)  # data up to 2**32
        self.cov.add(0, 100)  # data past the wrap

    def test_ack_within_sent_space(self):
        self.assertIsNone(oracles.check_ack_bound(self.isn + 1, self.cov, {self.isn}))
        self.assertIsNone(oracles.check_ack_bound(100, self.cov, {self.isn}))

    def test_ack_beyond_sent_space(self):
        self.assertIn("never sent", oracles.check_ack_bound(101, self.cov, {self.isn}))
        self.cov.add(200, 10)  # not contiguous with the stream
        self.assertIn("never sent", oracles.check_ack_bound(210, self.cov, {self.isn}))

    def test_ack_below_isn(self):
        self.assertIn("never sent", oracles.check_ack_bound(self.isn, self.cov, {self.isn}))
        self.assertIn("never sent", oracles.check_ack_bound(self.isn - 5, self.cov, {self.isn}))


class RstTest(unittest.TestCase):
    def rst(self, flags, seq, ack, window=0, payload=b""):
        return parse_tcp(tcp_frame(flags, seq, ack, window=window, payload=payload))

    def request(self, flags, seq, ack, payload=b""):
        """A fuzzer segment as Zhida reads it."""
        return parse_tcp(tcp_frame(flags, seq, ack, payload=payload, src_mac=ENV.tester_mac,
                                   dst_mac=ENV.zhida_mac, src_ip=ENV.tester_ip,
                                   dst_ip=ENV.zhida_ip, sport=40000, dport=8080))

    def test_rst_reply_shapes(self):
        # src/socket/tcp.rs 1459-1473: SEQ = the request's ACK (0 without ACK); RST|ACK
        # acknowledging SEQ + length only for an ACK-less SYN.
        shape = lambda *a: oracles.rst_reply_shape(self.request(*a))
        self.assertEqual(shape(PSH | ACK, 100, 4000, b"abc"), (RST, 4000, 0))
        self.assertEqual(shape(SYN | ACK, 100, 4000), (RST, 4000, 0))
        self.assertEqual(shape(SYN, 100, 0), (RST | ACK, 0, 101))
        self.assertEqual(shape(SYN, 0xFFFFFFFF, 0, b"ab"), (RST | ACK, 0, 2))
        self.assertEqual(shape(PSH, 100, 0, b"abc"), (RST, 0, 0))
        self.assertEqual(shape(FIN, 100, 0), (RST, 0, 0))

    def test_matching_rsts_pass(self):
        shapes = {(RST, 4000, 0), (RST | ACK, 0, 101), (RST, 0, 0)}
        for flags, seq, ack in shapes:
            self.assertIsNone(oracles.check_rst(self.rst(flags, seq, ack), shapes))
        self.assertIsNone(oracles.check_rst(self.rst(ACK, 5, 6), set()))  # not an RST

    def test_rst_ack_with_wrong_seq(self):
        # The only request was a SYN at 100: RST|ACK must have SEQ 0.
        shapes = {oracles.rst_reply_shape(self.request(SYN, 100, 0))}
        self.assertIn("not smoltcp's rst_reply",
                      oracles.check_rst(self.rst(RST | ACK, 98765, 101), shapes))

    def test_rst_seq_0_answering_an_ack(self):
        # The only request carried ACK 4000: the RST must have SEQ 4000, not 0.
        shapes = {oracles.rst_reply_shape(self.request(ACK, 100, 4000))}
        self.assertIn("not smoltcp's rst_reply", oracles.check_rst(self.rst(RST, 0, 0), shapes))
        self.assertIn("not smoltcp's rst_reply",
                      oracles.check_rst(self.rst(RST | ACK, 4000, 0), shapes))

    def test_rst_with_window_or_payload(self):
        shapes = {(RST, 4000, 0)}
        self.assertIn("window 7", oracles.check_rst(self.rst(RST, 4000, 0, window=7), shapes))
        self.assertIn("1 payload", oracles.check_rst(self.rst(RST, 4000, 0, payload=b"x"),
                                                     shapes))


class EchoTest(unittest.TestCase):
    def setUp(self):
        self.base = 0xFFFFFFFE  # the stream wraps after two bytes
        self.stream = bytes(range(256)) * 4
        self.record = oracles.SentRecord(self.base, self.stream)
        self.record.add(self.base, self.stream[:600])
        self.peer_isn = 5000

    def echo(self, k, data):
        return oracles.check_echo(self.record, self.peer_isn, self.base, self.peer_isn + 1 + k,
                                  data)

    def test_echo_of_sent_bytes(self):
        self.assertIsNone(self.echo(0, self.stream[:600]))
        self.assertIsNone(self.echo(100, self.stream[100:200]))

    def test_corrupted_echo(self):
        bad = bytearray(self.stream[100:200])
        bad[50] ^= 1
        self.assertIn("stream offset 150", self.echo(100, bytes(bad)))

    def test_echo_of_unsent_bytes(self):
        self.assertIn("stream offset 600", self.echo(590, self.stream[590:610]))

    def test_conflicting_bytes(self):
        self.assertFalse(self.record.conflicting)
        self.record.add(self.base + 10, b"\xEE")
        self.assertTrue(self.record.conflicting)
        self.assertIsNone(self.echo(10, b"\xEE"))
        self.assertIsNone(self.echo(10, self.stream[10:11]))
        self.assertIsNotNone(self.echo(10, b"\xEF"))

    def test_bytes_outside_the_window_are_not_recorded(self):
        left, size = seqmath.add(self.base, 1000), 4096  # Zhida's ACK at offset 1000
        old = seqmath.add(self.base, 1000 - 12346 - 100)  # ends 12346 below the ACK
        for seq in (old, seqmath.add(left, 1 << 30), seqmath.add(left, -(1 << 31))):
            self.record.add(seq, b"\xEE" * 100, (left, size))
        self.assertFalse(self.record.conflicting)

    def test_in_window_part_is_recorded(self):
        left = seqmath.add(self.base, 1000)
        self.record.add(seqmath.add(left, -2), b"\xEE" * 6, (left, 3))
        self.assertEqual(sorted(self.record.extras), [seqmath.add(left, i) for i in range(3)])


class StreamAndCloseTest(unittest.TestCase):
    def test_exact(self):
        self.assertIsNone(oracles.check_stream_exact(b"abc", b"abc"))
        self.assertIn("first difference at offset 1", oracles.check_stream_exact(b"abc", b"aXc"))
        self.assertIn("echoed 2 bytes", oracles.check_stream_exact(b"abc", b"ab"))
        self.assertIn("echoed 4 bytes", oracles.check_stream_exact(b"abc", b"abcd"))

    def test_prefix(self):
        self.assertIsNone(oracles.check_stream_prefix(b"abc", b"ab"))
        self.assertIsNone(oracles.check_stream_prefix(b"abc", b""))
        self.assertIsNotNone(oracles.check_stream_prefix(b"abc", b"b"))
        self.assertIsNotNone(oracles.check_stream_prefix(b"abc", b"abcd"))

    def test_clean_close(self):
        self.assertEqual(oracles.check_clean_close(True, True, 0), [])
        self.assertEqual(len(oracles.check_clean_close(False, True, 0)), 1)
        self.assertEqual(len(oracles.check_clean_close(True, False, 0)), 1)
        self.assertEqual(len(oracles.check_clean_close(True, True, 1)), 1)

    def test_handshake(self):
        self.assertIsNone(oracles.check_handshake(0.01, 3.0))
        self.assertIn("no SYN-ACK", oracles.check_handshake(None, 3.0))
        self.assertIn("bound", oracles.check_handshake(3.5, 3.0))


if __name__ == "__main__":
    unittest.main()
