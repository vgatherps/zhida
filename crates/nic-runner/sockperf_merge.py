#!/usr/bin/env python3
"""Merge sockperf 3.10 --full-log files from N client processes into one latency summary.

Format read (sockperf 3.10 src/client.cpp):
  sample rows   "%zu, %.9lf, %.9lf, %.3lf"  packet, txTime(sec), rxTime(sec), latency|rtt(usec)   (:327-337)
  parameters    "test was performed using the following parameters: --mps=%d --burst=%d ..." (:760-764)
  valid window  "[Valid Duration] RunTime=%.3lf sec; SentMessages=%lu; ReceivedMessages=%lu" (:534)
The usec column is RTT/2 unless the client ran with --full-rtt (header says "rtt(usec)").
Only replied messages (every --reply-every-th) are sample rows.

usage: sockperf_merge.py FILE...      |      sockperf_merge.py --self-test
"""
import math
import re
import sys

ROW = re.compile(r"^\d+, \d+\.\d+, \d+\.\d+, (-?\d+\.\d+)$")
HEADER = re.compile(r"^packet, txTime\(sec\), rxTime\(sec\), (latency|rtt)\(usec\)$")
MPS = re.compile(r"--mps=(\d+)")
VALID = re.compile(r"\[Valid Duration\] RunTime=(\d+\.\d+) sec; SentMessages=(\d+); ReceivedMessages=(\d+)")
DELIMITER = "------------------------------"


def parse(text, name):
    lines = [line.strip() for line in text.splitlines()]
    samples, mps, valid = [], None, None
    headers = [(i, match) for i, line in enumerate(lines) if (match := HEADER.match(line))]
    if len(headers) != 1:
        raise ValueError(f"{name}: not a sockperf --full-log file (missing or repeated sample header)")
    header_index, header = headers[0]
    if header_index == 0 or lines[header_index - 1] != DELIMITER:
        raise ValueError(f"{name}: sample header has no opening delimiter")
    row_index = header_index + 1
    while row_index < len(lines) and (match := ROW.match(lines[row_index])):
        samples.append(float(match.group(1)))
        row_index += 1
    if row_index == len(lines) or lines[row_index] != DELIMITER:
        raise ValueError(f"{name}: sample rows have no closing delimiter")
    for line in lines:
        if "test was performed" in line and (m := MPS.search(line)):
            mps = int(m.group(1))
        elif m := VALID.search(line):
            valid = (float(m.group(1)), int(m.group(2)), int(m.group(3)))
    if valid is None:
        raise ValueError(f"{name}: missing [Valid Duration] line")
    if len(samples) != valid[2]:
        raise ValueError(
            f"{name}: sample row count {len(samples)} does not match ReceivedMessages {valid[2]}"
        )
    return samples, header.group(1), mps, valid


def percentile(sorted_values, p):
    # nearest rank
    rank = max(1, math.ceil(p / 100 * len(sorted_values)))
    return sorted_values[rank - 1]


def merge(files):
    all_samples, kinds, offered, achieved = [], set(), 0, 0.0
    for name, text in files:
        samples, kind, mps, (run, sent, _received) = parse(text, name)
        all_samples += samples
        kinds.add(kind)
        offered += mps or 0
        achieved += sent / run if run > 0 else 0.0
    if len(kinds) != 1:
        raise ValueError("files mix --full-rtt and half-RTT samples")
    all_samples.sort()
    return {
        "unit": f"{kinds.pop()} usec",
        "samples": len(all_samples),
        "p50": percentile(all_samples, 50),
        "p99": percentile(all_samples, 99),
        "p99.9": percentile(all_samples, 99.9),
        "max": all_samples[-1],
        "offered_mps": offered,
        "achieved_mps": round(achieved),
    }


SELF_TEST = [
    """sockperf: [Valid Duration] RunTime=2.000 sec; SentMessages=2000; ReceivedMessages=2
------------------------------
test was performed using the following parameters: --mps=1000 --burst=1 --reply-every=100 --msg-size=64 --time=3
------------------------------
------------------------------
packet, txTime(sec), rxTime(sec), rtt(usec)
0, 1.000000000, 1.000010000, 10.000
1, 1.100000000, 1.100030000, 30.000
------------------------------
""",
    """[Valid Duration] RunTime=1.000 sec; SentMessages=500; ReceivedMessages=1
test was performed using the following parameters: --mps=500 --burst=1 --reply-every=100 --msg-size=64 --time=3
------------------------------
packet, txTime(sec), rxTime(sec), rtt(usec)
0, 2.000000000, 2.000020000, 20.000
------------------------------
""",
]


def self_test():
    files = [("first.full", SELF_TEST[0]), ("second.full", SELF_TEST[1])]
    r = merge(files)
    assert r["samples"] == 3 and r["unit"] == "rtt usec", r
    assert (r["p50"], r["p99"], r["max"]) == (20.0, 30.0, 30.0), r
    assert r["offered_mps"] == 1500 and r["achieved_mps"] == 1500, r
    try:
        merge([files[0], ("second.full", SELF_TEST[1].replace("rtt(usec)", "latency(usec)"))])
        raise AssertionError("mixed units accepted")
    except ValueError:
        pass
    truncated = SELF_TEST[0].replace("1, 1.100000000, 1.100030000, 30.000\n", "")
    missing_close = SELF_TEST[1].rsplit(DELIMITER, 1)[0]
    for name, text in [("truncated.full", truncated), ("missing-close.full", missing_close)]:
        try:
            merge([(name, text)])
            raise AssertionError(f"{name} accepted")
        except ValueError as error:
            assert name in str(error), error
    print("self-test ok")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    elif len(sys.argv) > 1:
        try:
            files = [(path, open(path).read()) for path in sys.argv[1:]]
            for k, v in merge(files).items():
                print(f"{k}: {v}")
        except (OSError, ValueError) as error:
            sys.exit(f"sockperf_merge.py: {error}")
    else:
        sys.exit(__doc__)
