import json
import unittest

from plan import make_plan, probe_plan


def frozen(plan):
    return json.dumps(plan.to_json(), sort_keys=True), plan.payload


class PlanTest(unittest.TestCase):
    def test_same_seed_same_plans(self):
        for i in range(50):
            self.assertEqual(frozen(make_plan(1, i)), frozen(make_plan(1, i)))
            self.assertEqual(frozen(make_plan("1", i)), frozen(make_plan(1, i)))
        self.assertEqual(frozen(probe_plan(1, 3)), frozen(probe_plan(1, 3)))

    def test_different_seeds_and_indices_differ(self):
        a = [frozen(make_plan(1, i)) for i in range(50)]
        b = [frozen(make_plan(2, i)) for i in range(50)]
        self.assertTrue(all(x != y for x, y in zip(a, b)))
        self.assertEqual(len(set(p[0] for p in a)), 50)
        self.assertNotEqual(frozen(probe_plan(1, 0)), frozen(probe_plan(2, 0)))

    def test_json_names_the_payload(self):
        plan = make_plan(1, 7)
        d = plan.to_json()
        self.assertEqual(d["payload_len"], len(plan.payload))
        self.assertNotIn("payload", d)
        json.dumps(d)

    def test_plans_are_well_formed(self):
        for i in range(500):
            p = make_plan(1, i)
            self.assertTrue(32768 <= p.sport < 61000)
            self.assertTrue(0 <= p.isn < 1 << 32)
            if p.syn["wscale"] is None:
                self.assertLessEqual(p.rcv_buffer, 65535)
            if p.sizes:
                self.assertGreaterEqual(sum(p.sizes), len(p.payload))
            for t in p.tx:
                self.assertTrue(0 <= t["at"] < len(p.payload))
            for x in p.rx_drop:
                self.assertTrue(0 <= x < len(p.payload))
            if p.syn["order"] != ["linux"]:
                present = {"mss", "sack" if p.syn["sack"] else None, "ts" if p.syn["ts"] else None,
                           "wscale" if p.syn["wscale"] is not None else None} - {None}
                self.assertEqual(sorted(p.syn["order"]), sorted(present))

    def test_probe_is_clean(self):
        p = probe_plan(1, 0)
        self.assertEqual(len(p.payload), 1024)
        self.assertEqual(p.impairments(), [])
        self.assertTrue(p.syn["ts"])

    def test_weights_favor_realistic_traffic(self):
        plans = [make_plan(1, i) for i in range(1000)]
        preserving = [p for p in plans if p.kind == "preserving"]
        self.assertTrue(650 < len(preserving) < 850)
        self.assertGreater(sum(1 for p in preserving if not p.impairments()), 150)
        self.assertGreater(sum(1 for p in plans if p.syn["ts"]), 800)

    def test_disruptive_plans_carry_mutations(self):
        for i in range(1000):
            p = make_plan(1, i)
            self.assertEqual(bool(p.mutations), p.kind == "disruptive")
            if p.kind == "disruptive":
                self.assertLessEqual(len(p.mutations), 3)
            json.dumps(p.to_json())

    def test_tsless_plans_may_drop_the_handshake_ack(self):
        """A plan whose SYN carries no TS may drop the handshake ACK too: a listener reset in
        SYN-RECEIVED negotiates the next SYN afresh."""
        self.assertTrue(any(p.kind == "disruptive" and not p.syn["ts"] and 0 in p.ack_drop
                            for p in (make_plan(1, i) for i in range(20000))))


if __name__ == "__main__":
    unittest.main()
