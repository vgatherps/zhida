import os
import struct
import time
import unittest
from argparse import Namespace
from dataclasses import replace

import seqmath
import fuzz_tcp
from fuzz_tcp import Runner
from plan import probe_plan
from testframes import ENV, tcp_frame
from wire import ACK


class FakeSocket:
    """Stands in for Scapy's L2 socket: readable forever if `flood` (each recv_raw returns
    `frame`), never readable otherwise; PACKET_STATISTICS reports `dropped` once."""

    def __init__(self, frame, flood, dropped=0):
        self.r, self.w = os.pipe()
        if flood:
            os.write(self.w, b"x")
        self.frame = frame
        self.dropped = dropped
        self.started = None
        self.ins = self

    def fileno(self):
        return self.r

    def recv_raw(self):
        self.started = self.started or time.monotonic()
        if time.monotonic() - self.started > 3.0:
            raise AssertionError("the receive drain never let the timers run")
        return None, self.frame, time.time()

    def send(self, frame):
        pass

    def getsockopt(self, level, name, size):
        dropped, self.dropped = self.dropped, 0
        return struct.pack("II", dropped, dropped)

    def close(self):
        os.close(self.r)
        os.close(self.w)


class RunnerTest(unittest.TestCase):
    def run_plan(self, flood, dropped=0):
        plan = replace(probe_plan(1, 0), deadline=0.3)
        # A pure ACK of the fuzzer's SYN: well-formed and acceptable at any time.
        frame = tcp_frame(ACK, 5000, seqmath.add(plan.isn, 1), dport=plan.sport)
        sock = FakeSocket(frame, flood, dropped)
        self.addCleanup(sock.close)
        runner = Runner(ENV, sock, Namespace())
        began = time.monotonic()
        failures = runner.run(plan)
        return failures, time.monotonic() - began, runner

    def test_continuous_input_cannot_starve_the_deadline(self):
        failures, took, runner = self.run_plan(flood=True)
        self.assertEqual(len(failures), 1, failures)
        self.assertIn("not finished within 0.3 s", failures[0])
        self.assertLess(took, 1.0)
        self.assertGreater(runner.stats["check_frame"], 0)

    def test_socket_drops_fail_the_connection(self):
        failures, _, runner = self.run_plan(flood=False, dropped=2)
        self.assertEqual(len(failures), 2, failures)
        self.assertIn("not finished within 0.3 s", failures[0])
        self.assertIn("dropped 2 frame(s)", failures[1])
        self.assertEqual(runner.stats["socket_dropped"], 2)

    def test_timer_due_during_select_runs_before_a_ready_frame(self):
        # select() returns late with a frame ready (the deadline came due while waiting):
        # the deadline must fail the connection before the frame is handled.
        real = fuzz_tcp.select.select

        def late_select(r, w, x, timeout):
            time.sleep(timeout + 0.05)
            return real(r, w, x, 0)

        fuzz_tcp.select.select = late_select
        self.addCleanup(setattr, fuzz_tcp.select, "select", real)
        failures, _, runner = self.run_plan(flood=True)
        self.assertEqual(len(failures), 1, failures)
        self.assertIn("not finished within 0.3 s", failures[0])
        self.assertEqual(runner.stats["check_frame"], 0)

    def test_quiet_gap_that_never_comes_fails_the_run(self):
        plan = replace(probe_plan(1, 0), deadline=0.3)
        sock = FakeSocket(b"", flood=False)
        self.addCleanup(sock.close)
        runner = Runner(ENV, sock, Namespace())
        runner.last_tx = time.monotonic() + 3600  # as if the fuzzer never stopped sending
        began = time.monotonic()
        failures = runner.run(plan)
        self.assertLess(time.monotonic() - began, fuzz_tcp.QUIET_GAP_LIMIT + 1.0)
        self.assertTrue(any("without a fuzzer frame" in f for f in failures), failures)


if __name__ == "__main__":
    unittest.main()
