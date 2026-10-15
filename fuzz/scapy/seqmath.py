"""TCP sequence-number arithmetic modulo 2**32 (RFC 9293 3.4, RFC 1982 comparisons)."""

MOD = 1 << 32
MASK = MOD - 1
HALF = 1 << 31


def add(seq, n):
    return (seq + n) & MASK


def offset(seq, base):
    """Unsigned distance from base forward to seq, in [0, 2**32)."""
    return (seq - base) & MASK


def diff(a, b):
    """Signed distance a - b in [-2**31, 2**31): positive when a is after b."""
    d = (a - b) & MASK
    return d - MOD if d >= HALF else d


def lt(a, b):
    return diff(a, b) < 0


def gt(a, b):
    return diff(a, b) > 0
