#!/bin/sh
# Self-test of fuzz/known-bugs.sh with stub cargo, locked.sh, run.sh and tap-echo:
# exact output, exit status and commands run for
# continuation past failures, unexpected passes, missing selectors and other
# infrastructure failures, timeouts, malformed manifests and known-bugs scripts missing
# from the manifest.
set -u

cd "$(dirname "$0")/.."
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/cargo" <<'EOF'
#!/bin/sh
echo "cargo $*" >>"$KB_CALLS"
list=
for a; do
    case $a in --list) list=1 ;; fails | passes | hangs | missing | nobuild | silent | deadline) test=$a ;; esac
done
if [ $test = nobuild ]; then echo 'error: could not compile `stub`'; exit 101; fi
if [ -n "$list" ]; then
    [ $test = missing ] || echo "$test: test"
    exit 0
fi
case $test in
passes)
    echo "test $test ... EAL: Detected CPU lcores: 14"
    echo "ok"
    echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.01s"
    exit 0
    ;;
fails)
    echo "test $test ... EAL: Detected CPU lcores: 14"
    echo "FAILED"
    echo "---- $test stdout ----"
    echo "thread 'zhida-test-worker' panicked at tests/stub.rs:12:5:"
    echo "assertion failed: bug"
    echo "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.01s"
    exit 101
    ;;
hangs) exec sleep 30 ;;
silent) exit 101 ;;
deadline)
    printf 'pinned test `%s` did not finish within 180s; exiting the test process\n' "c::f::$test"
    exit 1
    ;;
esac
EOF
cat >"$tmp/locked.sh" <<'EOF'
#!/bin/sh
echo "locked.sh $*" >>"$KB_CALLS"
case $* in
*/lock-timeout.pkt)
    echo "locked.sh: waiting up to 600 s for packetdrill lock /packetdrill-lock/run.lock, held by unknown" >&2
    echo "locked.sh: packetdrill lock /packetdrill-lock/run.lock still held after 600 s by unknown: another packetdrill run (any worktree) still has a process alive" >&2
    exit 1
    ;;
esac
exec "$@"
EOF
cat >"$tmp/run.sh" <<'EOF'
#!/bin/sh
echo "run.sh PACKETDRILL_TIMEOUT=$PACKETDRILL_TIMEOUT $*" >>"$KB_CALLS"
case $1 in
*/fails.pkt)
    echo "WRONG $1 exit 1, expected exit 0 (5 ms); output:"
    echo "    $1:7: error handling packet: live packet field tcp_ack"
    exit 1
    ;;
*/passes.pkt) echo "ok    $1 exit 0 (5 ms)"; exit 0 ;;
*/refused.pkt) echo "WRONG $1 refused: $1:3: not exactly one packet event: x"; exit 1 ;;
*/timeout.pkt) echo "WRONG $1 exit 124, expected exit 0 (7000 ms); output:"; exit 1 ;;
*/outer-timeout.pkt) exec sleep 30 ;;
*/startup-failure.pkt)
    echo "WRONG $1 exit 3, expected exit 0 (5 ms); output:"
    echo "    tap-echo: EAL init: rte_eal_init returned -1 with rte_errno 22"
    exit 1
    ;;
*/affinity-failure.pkt)
    echo "WRONG $1 exit 1, expected exit 0 (5 ms); output:"
    echo "    zhida_shim: packetdrill may run on 2 CPU(s), not only CPU 2"
    exit 1
    ;;
*/setup-failure.pkt)
    echo "WRONG $1 exit 3, expected exit 0 (5 ms); output:"
    echo "    tap-echo: rte_vdev_init: -1"
    exit 1
    ;;
esac
EOF
cat >"$tmp/tap-echo" <<'EOF'
#!/bin/sh
echo "tap-echo $*" >>"$KB_CALLS"
case $* in
*"--seed fails"*) echo "FAIL connection 5 (echo):"; echo "  Zhida sent byte 0x42 at its stream offset 0; the fuzzer never sent that byte at seq 1"; exit 1 ;;
*"--seed passes"*) echo "PASS seed passes: 1 connection(s), all oracles passed"; exit 0 ;;
*"--seed panic"*)
    echo "thread 'main' panicked at crates/tap-echo/src/lib.rs:118:17:"
    printf 'assertion `left == right` failed: recv_slice short of recv_queue\n  left: 0\n right: 1\n'
    exit 101
    ;;
*"--seed leak"*) echo "tap-echo: buffers still in use at port close: rx 1, tx 0"; exit 2 ;;
*)
    echo 'usage: fuzz_tcp.py [-h] [--seed SEED] [--connections CONNECTIONS]'
    echo '                   [--only ONLY] [--known-bugs]'
    echo 'fuzz_tcp.py: error: argument --only: invalid int value: '\''bad'\'''
    echo 'tap-echo: tester exit status: 2'
    exit 1
    ;;
esac
EOF
chmod +x "$tmp/cargo" "$tmp/locked.sh" "$tmp/run.sh" "$tmp/tap-echo"
for s in fails passes refused timeout outer-timeout startup-failure affinity-failure setup-failure lock-timeout; do : >"$tmp/$s.pkt"; done
mkdir "$tmp/no-pkt" "$tmp/kb"
: >"$tmp/kb/listed.pkt"
: >"$tmp/kb/extra.pkt"

wrong=0
# check CASE STATUS EXPECTED-OUTPUT: runs the manifest on stdin, with known-bugs scripts in
# $pkt_dir; output and status must match.
pkt_dir=$tmp/no-pkt
check() {
    cat >"$tmp/manifest"
    : >"$tmp/calls"
    status=0
    KB_CALLS=$tmp/calls CARGO=$tmp/cargo PACKETDRILL_RUN=$tmp/run.sh PACKETDRILL_LOCKED=$tmp/locked.sh TAP_ECHO=$tmp/tap-echo \
        KNOWN_BUGS_PKT_DIR=$pkt_dir KNOWN_BUGS_TIMEOUT=1 KNOWN_BUGS_PKT_TIMEOUT=7 \
        sh fuzz/known-bugs.sh "$tmp/manifest" >"$tmp/out" 2>&1 || status=$?
    printf '%s\n' "$3" >"$tmp/want"
    same=0
    diff -u "$tmp/want" "$tmp/out" >"$tmp/diff" || same=$?
    if [ $status = "$2" ] && [ $same = 0 ]; then
        echo "ok    $1"
    else
        echo "WRONG $1: exit $status (want $2); expected output vs actual:"
        sed 's/^/    /' "$tmp/diff"
        wrong=1
    fi
}

check "every repro fails, run past each failure" 1 "FAIL            A rust c f fails: tests/stub.rs:12:5: assertion failed: bug
FAIL            B pkt $tmp/fails.pkt: $tmp/fails.pkt:7: error handling packet: live packet field tcp_ack (run.sh: exit 1, expected exit 0 (5 ms))
FAIL            C scapy --seed fails --only 5: FAIL connection 5 (echo): Zhida sent byte 0x42 at its stream offset 0; the fuzzer never sent that byte at seq 1
FAIL            D rust c f hangs: no result within 1 s (exit 124)
known-bugs: 4 FAIL, 0 UNEXPECTED-PASS, 0 INFRA" <<EOF
# comment
A rust c f fails

  B pkt $tmp/fails.pkt
C scapy --seed fails --only 5
D rust c f hangs
EOF
printf '%s\n' "cargo test --locked -p c --test f -- --ignored --exact --list fails" \
    "cargo test --locked -p c --test f -- --ignored --exact fails --test-threads=1" \
    "locked.sh timeout --kill-after=10 1 $tmp/run.sh $tmp/fails.pkt" \
    "run.sh PACKETDRILL_TIMEOUT=7 $tmp/fails.pkt" \
    "tap-echo -- python3 -B fuzz/scapy/fuzz_tcp.py --seed fails --only 5" \
    "cargo test --locked -p c --test f -- --ignored --exact --list hangs" \
    "cargo test --locked -p c --test f -- --ignored --exact hangs --test-threads=1" >"$tmp/want"
if diff -u "$tmp/want" "$tmp/calls" >"$tmp/diff"; then
    echo "ok    each repro runs alone by its exact selector"
else
    echo "WRONG commands run, expected vs actual:"
    sed 's/^/    /' "$tmp/diff"
    wrong=1
fi

check "unexpected passes are loud and fail the run" 2 "UNEXPECTED-PASS A rust c f passes: unexpectedly passes, graduate it
FAIL            B rust c f fails: tests/stub.rs:12:5: assertion failed: bug
UNEXPECTED-PASS C pkt $tmp/passes.pkt: unexpectedly passes, graduate it
UNEXPECTED-PASS D scapy --seed passes: unexpectedly passes, graduate it
known-bugs: 1 FAIL, 3 UNEXPECTED-PASS, 0 INFRA" <<EOF
A rust c f passes
B rust c f fails
C pkt $tmp/passes.pkt
D scapy --seed passes
EOF

check "missing selectors are infrastructure failures" 2 "INFRA           A rust c f missing: no ignored test 'missing' in c --test f; output tail:
FAIL            B rust c f fails: tests/stub.rs:12:5: assertion failed: bug
INFRA           C pkt $tmp/missing.pkt: no script $tmp/missing.pkt; output tail:
INFRA           D scapy --only bad: the fuzzer exited 1 without a result; output tail:
    usage: fuzz_tcp.py [-h] [--seed SEED] [--connections CONNECTIONS]
                       [--only ONLY] [--known-bugs]
    fuzz_tcp.py: error: argument --only: invalid int value: 'bad'
    tap-echo: tester exit status: 2
known-bugs: 1 FAIL, 0 UNEXPECTED-PASS, 3 INFRA" <<EOF
A rust c f missing
B rust c f fails
C pkt $tmp/missing.pkt
D scapy --only bad
EOF

check "other infrastructure failures" 2 "INFRA           A rust c f nobuild: listing the ignored tests exited 101; output tail:
    error: could not compile \`stub\`
INFRA           B rust c f silent: cargo test exited 101 without a result for 'silent'; output tail:
INFRA           C pkt $tmp/refused.pkt: run.sh refused the script; output tail:
    WRONG $tmp/refused.pkt refused: $tmp/refused.pkt:3: not exactly one packet event: x
known-bugs: 0 FAIL, 0 UNEXPECTED-PASS, 3 INFRA" <<EOF
A rust c f nobuild
B rust c f silent
C pkt $tmp/refused.pkt
EOF

check "packetdrill-timeout" 1 "FAIL            A pkt $tmp/timeout.pkt: packetdrill timeout (run.sh: exit 124, expected exit 0 (7000 ms))
known-bugs: 1 FAIL, 0 UNEXPECTED-PASS, 0 INFRA" <<EOF
A pkt $tmp/timeout.pkt
EOF

check "packetdrill outer timeout has no script verdict" 2 "INFRA           A pkt $tmp/outer-timeout.pkt: run.sh did not finish within 1 s (exit 124); output tail:
known-bugs: 0 FAIL, 0 UNEXPECTED-PASS, 1 INFRA" <<EOF
A pkt $tmp/outer-timeout.pkt
EOF

check "packetdrill-startup-failure" 2 "INFRA           A pkt $tmp/startup-failure.pkt: run.sh reported no packetdrill mismatch or script timeout; output tail:
    WRONG $tmp/startup-failure.pkt exit 3, expected exit 0 (5 ms); output:
        tap-echo: EAL init: rte_eal_init returned -1 with rte_errno 22
INFRA           B pkt $tmp/affinity-failure.pkt: run.sh reported no packetdrill mismatch or script timeout; output tail:
    WRONG $tmp/affinity-failure.pkt exit 1, expected exit 0 (5 ms); output:
        zhida_shim: packetdrill may run on 2 CPU(s), not only CPU 2
INFRA           C pkt $tmp/setup-failure.pkt: run.sh reported no packetdrill mismatch or script timeout; output tail:
    WRONG $tmp/setup-failure.pkt exit 3, expected exit 0 (5 ms); output:
        tap-echo: rte_vdev_init: -1
known-bugs: 0 FAIL, 0 UNEXPECTED-PASS, 3 INFRA" <<EOF
A pkt $tmp/startup-failure.pkt
B pkt $tmp/affinity-failure.pkt
C pkt $tmp/setup-failure.pkt
EOF

check "lock-timeout" 2 "INFRA           A pkt $tmp/lock-timeout.pkt: packetdrill lock wait expired; output tail:
    locked.sh: waiting up to 600 s for packetdrill lock /packetdrill-lock/run.lock, held by unknown
    locked.sh: packetdrill lock /packetdrill-lock/run.lock still held after 600 s by unknown: another packetdrill run (any worktree) still has a process alive
known-bugs: 0 FAIL, 0 UNEXPECTED-PASS, 1 INFRA" <<EOF
A pkt $tmp/lock-timeout.pkt
EOF
printf '%s\n' "locked.sh timeout --kill-after=10 1 $tmp/run.sh $tmp/lock-timeout.pkt" >"$tmp/want"
if diff -u "$tmp/want" "$tmp/calls" >"$tmp/diff"; then
    echo "ok    lock expiry never invokes run.sh"
else
    echo "WRONG lock-timeout commands, expected vs actual:"
    sed 's/^/    /' "$tmp/diff"
    wrong=1
fi

check "pinned_test-deadline" 1 'FAIL            A rust c f deadline: pinned test deadline: pinned test `c::f::deadline` did not finish within 180s; exiting the test process
known-bugs: 1 FAIL, 0 UNEXPECTED-PASS, 0 INFRA' <<EOF
A rust c f deadline
EOF

check "scapy-panic" 1 "FAIL            A scapy --seed panic: tap-echo panic oracle (exit 101)
known-bugs: 1 FAIL, 0 UNEXPECTED-PASS, 0 INFRA" <<EOF
A scapy --seed panic
EOF

check "scapy-leak" 1 "FAIL            A scapy --seed leak: tap-echo leaked buffers oracle (exit 2)
known-bugs: 1 FAIL, 0 UNEXPECTED-PASS, 0 INFRA" <<EOF
A scapy --seed leak
EOF

check "a malformed manifest runs nothing" 2 "known-bugs: MALFORMED $tmp/manifest:2: unknown kind 'ruts' (rust, pkt, scapy)
known-bugs: MALFORMED $tmp/manifest:3: rust takes <crate> <test-file> <name>, got 2 field(s)
known-bugs: MALFORMED $tmp/manifest:4: pkt takes one <script>, got 4 field(s)
known-bugs: MALFORMED $tmp/manifest:5: scapy takes fuzz_tcp.py arguments, got none
known-bugs: MALFORMED $tmp/manifest:6: want <bug> <kind> <selector...>
known-bugs: bad manifest, nothing run" <<EOF
A rust c f fails
B ruts c f fails
C rust c fails
D pkt $tmp/fails.pkt # trailing comment
E scapy
F
EOF
if [ -s "$tmp/calls" ]; then
    echo "WRONG a malformed manifest ran:"
    sed 's/^/    /' "$tmp/calls"
    wrong=1
fi

pkt_dir=$tmp/kb
check "a known-bugs script missing from the manifest runs nothing" 2 "known-bugs: UNLISTED $tmp/kb/extra.pkt is not in $tmp/manifest
known-bugs: bad manifest, nothing run" <<EOF
A rust c f fails
B pkt $tmp/kb/listed.pkt
EOF
if [ -s "$tmp/calls" ]; then
    echo "WRONG a manifest missing a script ran:"
    sed 's/^/    /' "$tmp/calls"
    wrong=1
fi
pkt_dir=$tmp/no-pkt

check "an empty manifest passes" 0 "known-bugs: 0 FAIL, 0 UNEXPECTED-PASS, 0 INFRA" <<EOF
# all graduated
EOF

exit $wrong
