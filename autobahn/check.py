#!/usr/bin/env python3
"""Compare an Autobahn fuzzingclient index.json to tungstenite's expected results.

Exit 0: exact per-case match. Exit 1: mismatch. Exit 2: malformed input.
"""
import argparse
import collections
import copy
import json
import os
import subprocess
import sys
import tempfile

AGENT = "Tungstenite"
COMPARED = ("behavior", "behaviorClose", "remoteCloseCode")
DEFAULT_EXPECTED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "expected-results.json")


class Malformed(Exception):
    pass


class AgentMismatch(Exception):
    pass


def reject_duplicates(path):
    def hook(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise Malformed("%s: duplicate key %r" % (path, key))
            obj[key] = value
        return obj
    return hook


def load_cases(path):
    try:
        with open(path) as f:
            data = json.load(f, object_pairs_hook=reject_duplicates(path))
    except (OSError, ValueError) as e:
        raise Malformed("%s: unreadable JSON: %s" % (path, e))
    if not isinstance(data, dict):
        raise Malformed("%s: top level is %s, not an object" % (path, type(data).__name__))
    if list(data) != [AGENT]:
        raise AgentMismatch("%s: expected exactly one agent key %r, got %r" % (path, AGENT, list(data)))
    cases = data[AGENT]
    if not isinstance(cases, dict):
        raise Malformed("%s: agent %r value is not an object" % (path, AGENT))
    for case_id, case in cases.items():
        if not isinstance(case, dict):
            raise Malformed("%s: case %s is not an object" % (path, case_id))
        for field in COMPARED:
            if field not in case:
                raise Malformed("%s: case %s missing field %r" % (path, case_id, field))
        for field in ("behavior", "behaviorClose"):
            if not isinstance(case[field], str):
                raise Malformed("%s: case %s field %r is %r, not a string" % (path, case_id, field, case[field]))
        code = case["remoteCloseCode"]
        if code is not None and (type(code) is not int):
            raise Malformed("%s: case %s remoteCloseCode is %r, not an int or null" % (path, case_id, code))
        if "reportfile" in case and not isinstance(case["reportfile"], str):
            raise Malformed("%s: case %s reportfile is %r, not a string" % (path, case_id, case["reportfile"]))
    return cases


def case_sort_key(case_id):
    return [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in case_id.split(".")]


def triple(case):
    return tuple(case[f] for f in COMPARED)


def compare(report_path, expected_path):
    report = load_cases(report_path)
    expected = load_cases(expected_path)
    counts = collections.Counter((c["behavior"], c["behaviorClose"]) for c in report.values())
    print("report %s: %d cases" % (report_path, len(report)))
    for (behavior, behavior_close), n in sorted(counts.items()):
        print("  %-14s %-14s %d" % (behavior, behavior_close, n))

    report_dir = os.path.dirname(os.path.abspath(report_path))
    missing = sorted(set(expected) - set(report), key=case_sort_key)
    extra = sorted(set(report) - set(expected), key=case_sort_key)
    diverging = []
    for case_id in sorted(set(expected) & set(report), key=case_sort_key):
        if triple(expected[case_id]) != triple(report[case_id]):
            diverging.append(case_id)

    for case_id in diverging:
        reportfile = report[case_id].get("reportfile")
        location = os.path.join(report_dir, reportfile) if reportfile else "(no reportfile)"
        print("DIVERGES %s expected=%r actual=%r report=%s"
              % (case_id, triple(expected[case_id]), triple(report[case_id]), location))
    for case_id in missing:
        print("MISSING %s" % case_id)
    for case_id in extra:
        print("EXTRA %s" % case_id)

    if diverging or missing or extra:
        print("FAIL: %d diverging, %d missing, %d extra (fields %s)"
              % (len(diverging), len(missing), len(extra), ", ".join(COMPARED)))
        return 1
    print("PASS: %d cases match %s" % (len(report), expected_path))
    return 0


def self_test(expected_path):
    with open(expected_path) as f:
        base = json.load(f)
    cases = base[AGENT]
    with_code = next(k for k, v in cases.items() if isinstance(v["remoteCloseCode"], int))
    with_null = next(k for k, v in cases.items() if v["remoteCloseCode"] is None)
    any_case = next(iter(cases))

    def set_field(case_id, field, value):
        def mutate(d):
            d[AGENT][case_id][field] = value
        return mutate

    def other_behavior(field):
        value = cases[any_case][field]
        return "FAILED" if value != "FAILED" else "OK"

    def drop_case(d):
        del d[AGENT][any_case]

    def add_case(d):
        d[AGENT]["99.9.9"] = copy.deepcopy(cases[any_case])

    def rename_agent(d):
        d["NotTungstenite"] = d.pop(AGENT)

    def add_agent(d):
        d["Other"] = copy.deepcopy(d[AGENT])

    def add_extra_ids(d):
        d[AGENT]["99.9.9"] = copy.deepcopy(cases[any_case])
        d[AGENT]["extra"] = copy.deepcopy(cases[any_case])

    def ignored_metadata(d):
        d[AGENT][any_case]["duration"] = 123456
        d[AGENT][any_case]["reportfile"] = "elsewhere.json"

    def duplicate_case(text):
        key = json.dumps(any_case) + ": "
        i = text.index(key)
        return text[:i] + key + '{"behavior": "FAILED", "behaviorClose": "FAILED", "remoteCloseCode": null}, ' + text[i:]

    def diverges(case_id):
        return "DIVERGES %s " % case_id

    # (name, dict mutation, text mutation, want exit, required output substring)
    scenarios = [
        ("expected vs itself", None, None, 0, "PASS: "),
        ("ignored duration and reportfile", ignored_metadata, None, 0, "PASS: "),
        ("changed behavior", set_field(any_case, "behavior", other_behavior("behavior")), None, 1,
         diverges(any_case)),
        ("changed behaviorClose", set_field(any_case, "behaviorClose", other_behavior("behaviorClose")),
         None, 1, diverges(any_case)),
        ("remoteCloseCode number->other number",
         set_field(with_code, "remoteCloseCode", cases[with_code]["remoteCloseCode"] + 1), None, 1,
         diverges(with_code)),
        ("remoteCloseCode null->number", set_field(with_null, "remoteCloseCode", 1000), None, 1,
         diverges(with_null)),
        ("remoteCloseCode number->null", set_field(with_code, "remoteCloseCode", None), None, 1,
         diverges(with_code)),
        ("missing case", drop_case, None, 1, "MISSING %s\n" % any_case),
        ("extra case", add_case, None, 1, "EXTRA 99.9.9\n"),
        ("extra mixed case ids", add_extra_ids, None, 1, "EXTRA extra\n"),
        ("wrong agent key", rename_agent, None, 1, "expected exactly one agent key"),
        ("extra agent key", add_agent, None, 1, "expected exactly one agent key"),
        ("duplicate case key", None, duplicate_case, 2, "duplicate key %r" % any_case),
        ("behavior null", set_field(any_case, "behavior", None), None, 2, "not a string"),
        ("remoteCloseCode 1000.0", set_field(with_code, "remoteCloseCode", 1000.0), None, 2,
         "not an int or null"),
    ]

    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        for i, (name, mutate, mutate_text, want, reason) in enumerate(scenarios):
            data = copy.deepcopy(base)
            if mutate:
                mutate(data)
            text = json.dumps(data)
            if mutate_text:
                text = mutate_text(text)
            path = os.path.join(tmp, "index-%d.json" % i)
            with open(path, "w") as f:
                f.write(text)
            proc = subprocess.run(
                [sys.executable, os.path.abspath(__file__), path, "--expected", expected_path],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
            ok = proc.returncode == want and reason in proc.stdout and "Traceback" not in proc.stdout
            print("%s %-40s exit %d (want %d, reason %r)"
                  % ("ok  " if ok else "FAIL", name, proc.returncode, want, reason.strip()))
            if not ok:
                failures.append(name)
                print(proc.stdout)
    if failures:
        print("self-test FAILED: %s" % ", ".join(failures))
        return 1
    print("self-test passed: %d scenarios" % len(scenarios))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("index", nargs="?", help="Autobahn report index.json")
    parser.add_argument("--expected", default=DEFAULT_EXPECTED)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            return self_test(args.expected)
        if not args.index:
            parser.error("index.json path required")
        return compare(args.index, args.expected)
    except AgentMismatch as e:
        print("FAIL: %s" % e)
        return 1
    except Malformed as e:
        print("malformed input: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
