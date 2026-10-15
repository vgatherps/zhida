import struct
import unittest
from collections import Counter

import wire
from conn import Conn
from plan import probe_plan
from testframes import ENV, tcp_frame
from wire import ACK, FIN, PSH, RST, SYN, Builder, Malformed, parse_tcp


class ChecksumTest(unittest.TestCase):
    def test_rfc1071_example(self):
        self.assertEqual(wire.checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220D)
        self.assertEqual(wire.checksum(bytes.fromhex("0001f203f4f5f6f7220d")), 0)

    def test_odd_length_pads_with_zero(self):
        self.assertEqual(wire.checksum(b"\x01"), wire.checksum(b"\x01\x00"))


class ParseTest(unittest.TestCase):
    def test_round_trip(self):
        ts = b"\x01\x01\x08\x0a" + struct.pack("!II", 7, 9)
        seg = parse_tcp(tcp_frame(PSH | ACK, 0xFFFFFFFF, 12, window=513, options=ts,
                                  payload=b"hello"))
        self.assertEqual((seg.seq, seg.ack, seg.window, seg.flags), (0xFFFFFFFF, 12, 513,
                                                                     PSH | ACK))
        self.assertEqual((seg.payload, seg.timestamp, seg.seg_len), (b"hello", (7, 9), 5))
        self.assertTrue(seg.ip_checksum_ok and seg.tcp_checksum_ok)
        self.assertEqual(parse_tcp(tcp_frame(SYN | FIN, 1, 0, payload=b"ab")).seg_len, 4)

    def test_receiver_view_of_lengths(self):
        frame = bytearray(tcp_frame(ACK, 1, 2, payload=b"abcdef"))
        frame += b"\0" * 4  # Ethernet padding past the IP total length is not payload
        self.assertEqual(parse_tcp(bytes(frame)).payload, b"abcdef")
        frame[16:18] = struct.pack("!H", 20 + 20 + 2)  # total length cuts the payload
        self.assertEqual(parse_tcp(bytes(frame)).payload, b"ab")

    def test_malformed(self):
        frame = tcp_frame(ACK, 1, 2)
        cases = {
            "too short": frame[:20],
            "IP version": frame[:14] + b"\x65" + frame[15:],
            "IHL 4": frame[:14] + b"\x44" + frame[15:],
            "total length 70": frame[:16] + struct.pack("!H", 70) + frame[18:],
            "protocol 17": frame[:23] + b"\x11" + frame[24:],
            "data offset 15": frame[:46] + b"\xf0" + frame[47:],
            "data offset 4": frame[:46] + b"\x40" + frame[47:],
        }
        for text, bad in cases.items():
            with self.assertRaises(Malformed, msg=text) as caught:
                parse_tcp(bad)
            self.assertIn(text.split()[-1], str(caught.exception), text)

    def test_fix_checksums_follows_the_mutated_header(self):
        frame = bytearray(tcp_frame(ACK, 1, 2, payload=b"abcdef"))
        frame[16:18] = struct.pack("!H", 20 + 20 + 3)
        fixed = parse_tcp(wire.fix_checksums(bytes(frame)))
        self.assertTrue(fixed.ip_checksum_ok and fixed.tcp_checksum_ok)
        self.assertEqual(fixed.payload, b"abc")
        frame = bytearray(tcp_frame(ACK, 1, 2))
        frame[22] = 1  # TTL
        self.assertFalse(parse_tcp(bytes(frame)).ip_checksum_ok)
        self.assertTrue(parse_tcp(wire.fix_checksums(bytes(frame))).ip_checksum_ok)


class SmoltcpAcceptsTest(unittest.TestCase):
    """wire.smoltcp_accepts mirrors smoltcp's IPv4 and TcpRepr::parse rejects."""

    def accepts(self, flags=ACK, options=b"", **kw):
        return wire.smoltcp_accepts(parse_tcp(tcp_frame(flags, 1, 2, options=options, **kw)))

    def test_clean_segments(self):
        self.assertTrue(self.accepts())
        self.assertTrue(self.accepts(SYN, b"\x02\x04\x05\xb4"))
        self.assertTrue(self.accepts(FIN | ACK))
        self.assertTrue(self.accepts(RST))

    def test_ports_and_flags(self):
        self.assertFalse(self.accepts(sport=0))
        self.assertFalse(self.accepts(dport=0))
        for flags in (SYN | FIN, SYN | RST, FIN | RST | ACK, SYN | FIN | RST):
            self.assertFalse(self.accepts(flags), flags)

    def test_checksums_and_fragments(self):
        frame = bytearray(tcp_frame(ACK, 1, 2, payload=b"x"))
        frame[-1] ^= 1
        self.assertFalse(wire.smoltcp_accepts(parse_tcp(bytes(frame))))
        for frag in (0x2000, 0x0001, 0x4001):  # MF, offset 8, DF + offset
            frame = bytearray(tcp_frame(ACK, 1, 2))
            frame[20:22] = struct.pack("!H", frag)
            self.assertFalse(wire.smoltcp_accepts(parse_tcp(wire.fix_checksums(bytes(frame)))))

    def test_options_as_smoltcp_parses_them(self):
        ok = {"TS length 2 is Unknown": b"\x08\x02\x01\x01",
              "TS length 6 is Unknown": b"\x08\x06\0\0\0\0\x01\x01",
              "garbage after EOL": b"\x00\x05\x01\xff",
              "unknown kind": b"\x1e\x04\xab\xcd",
              "SACK, one block": b"\x01\x01\x05\x0a" + b"\0" * 8}
        bad = {"MSS length 3": b"\x02\x03\x05\x01", "window scale length 4": b"\x03\x04\x07\x01",
               "SACK-permitted length 3": b"\x04\x03\x00\x01", "SACK length 2": b"\x05\x02\x01\x01",
               "SACK length 12": b"\x05\x0c" + b"\0" * 10, "length 0": b"\x1e\x00\x01\x01",
               "length 1": b"\x1e\x01\x01\x01", "past the end": b"\x1e\x05\x01\x01",
               "no length byte": b"\x01\x01\x01\x02"}
        for name, options in ok.items():
            self.assertTrue(self.accepts(options=options), name)
        for name, options in bad.items():
            self.assertFalse(self.accepts(options=options), name)


class BuilderTest(unittest.TestCase):
    def test_tester_segment(self):
        b = Builder(ENV)
        frame = b.tcp(40000, 0xFFFFFFFE, 77, PSH | ACK, 502,
                      [("NOP", None), ("NOP", None), ("Timestamp", (5, 6))], b"xyz")
        seg = parse_tcp(frame)
        self.assertEqual((seg.src_mac, seg.dst_mac), (ENV.tester_mac, ENV.zhida_mac))
        self.assertEqual((seg.src_ip, seg.dst_ip), (ENV.tester_ip, ENV.zhida_ip))
        self.assertEqual((seg.sport, seg.dport, seg.seq, seg.ack), (40000, 8080, 0xFFFFFFFE, 77))
        self.assertEqual((seg.window, seg.payload, seg.timestamp), (502, b"xyz", (5, 6)))
        self.assertTrue(seg.ip_checksum_ok and seg.tcp_checksum_ok)
        self.assertEqual(seg.ip_flags_frag, 0x4000)  # DF, as Linux

    def test_linux_syn_layout(self):
        frames = []
        plan = probe_plan(1, 0)
        conn = Conn(plan, Builder(ENV), lambda f, now: frames.append(f), Counter(), 0.0)
        conn.start(0.0)
        seg = parse_tcp(frames[0])
        self.assertEqual(seg.flags, SYN)
        self.assertEqual(seg.seq, plan.isn)
        # Linux: mss, sackOK, TS, nop, wscale (20 bytes, no padding).
        self.assertEqual(seg.options_raw[:4], b"\x02\x04\x05\xb4")
        self.assertEqual(seg.options_raw[4:8], b"\x04\x02\x08\x0a")
        self.assertEqual(seg.options_raw[16:], b"\x01\x03\x03\x07")
        self.assertEqual(seg.timestamp[1], 0)


if __name__ == "__main__":
    unittest.main()
