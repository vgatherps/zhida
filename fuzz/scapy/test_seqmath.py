import unittest

import seqmath


class SeqMathTest(unittest.TestCase):
    def test_add_wraps(self):
        self.assertEqual(seqmath.add(0xFFFFFFFF, 1), 0)
        self.assertEqual(seqmath.add(0xFFFFFFF0, 0x20), 0x10)

    def test_offset_is_forward_distance_across_wrap(self):
        self.assertEqual(seqmath.offset(5, 0xFFFFFFFB), 10)
        self.assertEqual(seqmath.offset(0xFFFFFFFB, 5), seqmath.MOD - 10)

    def test_diff_is_signed_across_wrap(self):
        self.assertEqual(seqmath.diff(5, 0xFFFFFFFB), 10)
        self.assertEqual(seqmath.diff(0xFFFFFFFB, 5), -10)
        self.assertEqual(seqmath.diff(7, 7), 0)

    def test_comparisons_across_wrap(self):
        before, after = 0xFFFFFF00, 0x00000100
        self.assertTrue(seqmath.lt(before, after))
        self.assertTrue(seqmath.gt(after, before))
        self.assertFalse(seqmath.lt(after, before))
        self.assertFalse(seqmath.lt(after, after) or seqmath.gt(after, after))

    def test_half_space_boundary(self):
        # Exactly 2**31 apart is ambiguous (RFC 1982); diff resolves it as "before".
        self.assertEqual(seqmath.diff(seqmath.HALF, 0), -seqmath.HALF)
        self.assertEqual(seqmath.diff(seqmath.HALF - 1, 0), seqmath.HALF - 1)


if __name__ == "__main__":
    unittest.main()
