# Autobahn report checker

`expected-results.json` is a byte-identical copy of tungstenite's
`autobahn/expected-results.json` at tag v0.30.0 (commit 7f4aeaf094; same file on master),
sha256 `1ef1023a82e8602e10404c0d0cacfff9400b122131546972fe597d2298ab5c8f`. 517 cases, agent
`Tungstenite`: 296 OK/OK, 216 UNIMPLEMENTED/OK, 3 INFORMATIONAL/INFORMATIONAL, 2 NON-STRICT/OK.

```sh
python3 autobahn/check.py <outdir>/index.json [--expected <path>]
python3 autobahn/check.py --self-test    # make test-autobahn-check
```

Python 3 stdlib only. Both files must have exactly the one agent key `Tungstenite` and the
same case ids; each case must match on `behavior`, `behaviorClose` and `remoteCloseCode`
(null is a value; other fields such as `duration` are ignored). Input is malformed (exit 2)
on unreadable JSON, a duplicate object key at any level, a non-string `behavior` /
`behaviorClose` / `reportfile`, or a `remoteCloseCode` that is not an int or null (`1000.0`
is rejected). Prints per-(behavior, behaviorClose) counts of the report, then every diverging
case (expected vs actual, plus the case report file), missing and extra case ids (numeric id
parts sort before non-numeric ones). Exit 0 full match, 1 mismatch (including agent keys), 2
malformed input. `--self-test` runs 15 scenarios, each checking the exit code, a
scenario-specific output line (`DIVERGES <id>`, `MISSING`, `EXTRA`, the agent-key or
malformed reason) and the absence of a traceback: the expected file against itself and with
changed `duration`/`reportfile` (exit 0); changed behavior, behaviorClose, close code
number->number, null->number, number->null, missing case, extra case, extra mixed ids
(`99.9.9`, `extra`), wrong agent key, extra agent key (exit 1); duplicate case key, null
behavior, close code `1000.0` (exit 2).
