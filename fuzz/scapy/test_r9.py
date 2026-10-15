import unittest

from r9 import EXCHANGE_BOUND, Scenarios
from testframes import ENV, tcp_frame
from wire import ACK, FIN, PSH, RST, SYN, Builder, parse_tcp


class R9Test(unittest.TestCase):
    def scenarios(self, replies):
        self.sent = []
        self.waits = []
        self.replies = list(replies)

        def exchange(frames, wait=0.05):
            self.sent.extend(parse_tcp(frame) for frame in frames)
            self.waits.append(wait)
            return [parse_tcp(frame) for frame in self.replies.pop(0)]

        return Scenarios(Builder(ENV), exchange)

    def handshake(self, port, isn, server_isn):
        return [[tcp_frame(SYN | ACK, server_isn, isn + 1, dport=port)], []]

    def close_first(self, port):
        return [[tcp_frame(FIN | ACK, 101, 1002, dport=port)], []]

    def echo(self, port, server_seq):
        return [[tcp_frame(PSH | ACK, server_seq, 5020, dport=port,
                           payload=b"original connection")], []]

    def established_trace(self, duplicate):
        return (self.handshake(40000, 1000, 100) + self.handshake(40001, 5000, 200)
                + self.close_first(40000) + [duplicate] + self.echo(40001, 201) + [[]])

    def lost_trace(self, resent):
        lost = tcp_frame(SYN | ACK, 200, 5001, dport=40003)
        return (self.handshake(40002, 1000, 100) + [[lost]] + self.close_first(40002)
                + [resent, []] + self.echo(40003, 201) + [[], []])

    def test_established_challenge_ack_and_echo(self):
        scenarios = self.scenarios(self.established_trace([tcp_frame(ACK, 201, 5001, dport=40001)]))
        scenarios.established_duplicate_syn()
        self.assertFalse(self.replies)
        self.assertEqual([(s.dport, s.sport) for s in self.sent], [(8080, p) for p in
                         [40000, 40000, 40001, 40001, 40000, 40000, 40001, 40001, 40001, 40001]])
        self.assertEqual([s.flags for s in self.sent],
                         [SYN, ACK, SYN, ACK, FIN | ACK, ACK, SYN, ACK, ACK, RST | ACK])
        self.assertEqual((self.sent[2].seq, self.sent[6].seq), (5000, 5000))
        self.assertTrue(all(wait < EXCHANGE_BOUND for wait in self.waits))

    def test_established_rejects_lower_listener_synack(self):
        scenarios = self.scenarios(self.established_trace([tcp_frame(SYN | ACK, 300, 5001, dport=40001)]))
        with self.assertRaisesRegex(AssertionError, "challenge ACK"):
            scenarios.established_duplicate_syn()

    def test_lost_synack_identical_immediate_reply_and_echo(self):
        scenarios = self.scenarios(self.lost_trace([tcp_frame(SYN | ACK, 200, 5001, dport=40003)]))
        scenarios.lost_synack()
        self.assertFalse(self.replies)
        self.assertEqual([s.flags for s in self.sent],
                         [SYN, ACK, SYN, FIN | ACK, ACK, SYN, ACK, ACK, ACK, RST | ACK])
        self.assertEqual((self.sent[2].seq, self.sent[5].seq), (5000, 5000))
        self.assertEqual(self.sent[6].ack, 201)
        self.assertEqual(self.waits[-2], 1.1)
        self.assertLess(self.waits[5], EXCHANGE_BOUND)

    def test_lost_synack_rejects_different_isn_or_options(self):
        for kw in [{"seq": 300}, {"options": b"\x02\x04\x05\xb4"}, {"window": 2000}]:
            with self.subTest(kw=kw):
                fields = {"seq": 200, **kw}
                scenarios = self.scenarios(self.lost_trace([tcp_frame(SYN | ACK, ack=5001,
                                                                     dport=40003, **fields)]))
                with self.assertRaisesRegex(AssertionError, "differs from lost one"):
                    scenarios.lost_synack()

    def test_lost_synack_rejects_delayed_or_multiple_replies(self):
        synack = tcp_frame(SYN | ACK, 200, 5001, dport=40003)
        for replies in [[], [synack, synack]]:
            scenarios = self.scenarios(self.lost_trace(replies))
            with self.assertRaisesRegex(AssertionError, "expected one SYN-ACK"):
                scenarios.lost_synack()

    def test_lost_synack_rejects_second_half_open_retransmission(self):
        synack = tcp_frame(SYN | ACK, 200, 5001, dport=40003)
        trace = self.lost_trace([synack])
        trace[-2] = [synack]
        scenarios = self.scenarios(trace)
        with self.assertRaisesRegex(AssertionError, "another half-open"):
            scenarios.lost_synack()


if __name__ == "__main__":
    unittest.main()
