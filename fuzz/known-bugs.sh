#!/bin/sh
# Runs every known-bug repro listed in a manifest (default fuzz/known-bugs.txt), each alone
# by its exact selector, continuing past failures, and prints one line per repro:
#   FAIL             the bug still reproduces (expected while it exists), with the first
#                    failure location or an output excerpt
#   UNEXPECTED-PASS  the repro passes: graduate it (fix slice: un-ignore the test or move
#                    the script to scripts/, and delete its manifest line)
#   INFRA            the repro did not run to a verdict (no such test or script, build
#                    error, script refused, unrecognized output); the output tail follows
# then a summary. Exit 0: no repro listed. 1: every repro FAILs. 2: any UNEXPECTED-PASS or
# INFRA, or a manifest that is malformed or misses a fuzz/packetdrill/known-bugs/*.pkt
# (every bad line and unlisted script reported, nothing run).
#
# Manifest: blank lines and # comments; any other line is `<bug> <kind> <selector...>`:
#   <bug> rust <crate> <test-file> <name>  #[ignore]d test: cargo test --locked -p <crate>
#                                          --test <test-file> -- --ignored --exact <name>
#   <bug> pkt <script>                     packetdrill script, alone via fuzz/packetdrill/run.sh
#   <bug> scapy <fuzz_tcp.py args...>      Scapy replay: tap-echo -- python3 -B fuzz/scapy/fuzz_tcp.py
# A rust test must be listed by `--ignored --list` (an un-ignored test is INFRA, not a pass).
#
# Usage: fuzz/known-bugs.sh [manifest]
# Env (required): KNOWN_BUGS_TIMEOUT, seconds per repro (packetdrill lock wait excluded;
# expiry is INFRA for run.sh, FAIL for Rust/Scapy);
# KNOWN_BUGS_PKT_TIMEOUT, seconds per packetdrill script (run.sh's PACKETDRILL_TIMEOUT);
# ZHIDA_CPU and PACKETDRILL_CPU, passed to run.sh. For the self-test: KNOWN_BUGS_PKT_DIR
# replaces fuzz/packetdrill/known-bugs; CARGO, PACKETDRILL_RUN, PACKETDRILL_LOCKED and TAP_ECHO replace cargo,
# fuzz/packetdrill/run.sh and target/debug/tap-echo.
set -u
set -f

cd "$(dirname "$0")/.."
manifest=${1:-fuzz/known-bugs.txt}
limit=${KNOWN_BUGS_TIMEOUT:?KNOWN_BUGS_TIMEOUT: seconds per repro}
pkt_limit=${KNOWN_BUGS_PKT_TIMEOUT:?KNOWN_BUGS_PKT_TIMEOUT: seconds per packetdrill script}
pkt_dir=${KNOWN_BUGS_PKT_DIR:-fuzz/packetdrill/known-bugs}
cargo=${CARGO:-cargo}
packetdrill_run=${PACKETDRILL_RUN:-fuzz/packetdrill/run.sh}
packetdrill_lock=${PACKETDRILL_LOCKED:-fuzz/packetdrill/locked.sh}
tap_echo=${TAP_ECHO:-target/debug/tap-echo}

if ! [ -f "$manifest" ]; then
    echo "known-bugs: INFRA: no manifest $manifest" >&2
    exit 2
fi

# Prints why line $1 (fields $2...) is malformed, or nothing.
malformed() {
    [ $# -ge 3 ] || { echo "$1: want <bug> <kind> <selector...>"; return; }
    n=$1 kind=$3
    shift 3
    case $kind in
    rust) [ $# = 3 ] || echo "$n: rust takes <crate> <test-file> <name>, got $# field(s)" ;;
    pkt) [ $# = 1 ] || echo "$n: pkt takes one <script>, got $# field(s)" ;;
    scapy) [ $# -ge 1 ] || echo "$n: scapy takes fuzz_tcp.py arguments, got none" ;;
    *) echo "$n: unknown kind '$kind' (rust, pkt, scapy)" ;;
    esac
}

bad=0
number=0
listed=
while IFS= read -r line || [ -n "$line" ]; do
    number=$((number + 1))
    case ${line#"${line%%[![:space:]]*}"} in '' | '#'*) continue ;; esac
    # shellcheck disable=SC2086
    why=$(malformed "$manifest:$number" $line)
    if [ -n "$why" ]; then
        echo "known-bugs: MALFORMED $why"
        bad=1
        continue
    fi
    # shellcheck disable=SC2086
    set -- $line
    [ "$2" = pkt ] && listed="$listed
$3"
done <"$manifest"
set +f
for script in "$pkt_dir"/*.pkt; do
    [ -e "$script" ] || continue
    case "$listed
" in
    *"
$script
"*) ;;
    *)
        echo "known-bugs: UNLISTED $script is not in $manifest"
        bad=1
        ;;
    esac
done
set -f
if [ $bad = 1 ]; then
    echo "known-bugs: bad manifest, nothing run"
    exit 2
fi

out=$(mktemp) || exit 2
trap 'rm -f "$out"' EXIT
fails=0 passes=0 infras=0

# Runs $@ bounded by $limit with output in $out; sets status.
bounded() {
    status=0
    timeout --kill-after=10 "$limit" "$@" </dev/null >"$out" 2>&1 || status=$?
}

timed_out() {
    [ "$status" = 124 ] || [ "$status" = 137 ]
}

verdict() {
    case $1 in
    FAIL) fails=$((fails + 1)); echo "FAIL            $name: $2" ;;
    PASS) passes=$((passes + 1)); echo "UNEXPECTED-PASS $name: unexpectedly passes, graduate it" ;;
    INFRA)
        infras=$((infras + 1))
        echo "INFRA           $name: $2; output tail:"
        tail -n 20 "$out" | sed 's/^/    /'
        ;;
    esac
}

run_rust() {
    crate=$1 file=$2 test=$3
    bounded "$cargo" test --locked -p "$crate" --test "$file" -- --ignored --exact --list "$test"
    if [ $status != 0 ]; then
        verdict INFRA "listing the ignored tests exited $status"
        return
    fi
    if ! grep -qxF "$test: test" "$out"; then
        verdict INFRA "no ignored test '$test' in $crate --test $file"
        return
    fi
    bounded "$cargo" test --locked -p "$crate" --test "$file" -- --ignored --exact "$test" --test-threads=1
    if timed_out; then
        verdict FAIL "no result within $limit s (exit $status)"
    elif [ $status = 0 ] && grep -q '^test result: ok\. 1 passed; 0 failed;' "$out"; then
        verdict PASS
    elif [ $status != 0 ] && grep -q '^test result: FAILED\. 0 passed; 1 failed;' "$out"; then
        where=$(awk '/^thread .* panicked at .*:$/ { sub(/^.* panicked at /, ""); sub(/:$/, "");
            loc = $0; getline; print loc ": " $0; exit }' "$out")
        verdict FAIL "${where:-no panic location in the output}"
    elif [ $status != 0 ] && grep -q '^pinned test `.*` did not finish within .*; exiting the test process$' "$out"; then
        deadline=$(grep -m1 '^pinned test `.*` did not finish within .*; exiting the test process$' "$out")
        verdict FAIL "pinned test deadline: $deadline"
    else
        verdict INFRA "cargo test exited $status without a result for '$test'"
    fi
}

run_pkt() {
    script=$1
    if ! [ -f "$script" ]; then
        verdict INFRA "no script $script"
        return
    fi
    status=0
    PACKETDRILL_TIMEOUT="$pkt_limit" "$packetdrill_lock" \
        timeout --kill-after=10 "$limit" "$packetdrill_run" "$script" \
        </dev/null >"$out" 2>&1 || status=$?
    wrong=$(grep -m1 "^WRONG " "$out")
    if timed_out; then
        verdict INFRA "run.sh did not finish within $limit s (exit $status)"
    elif [ $status != 0 ] && grep -q '^locked.sh: packetdrill lock .* still held after ' "$out"; then
        verdict INFRA "packetdrill lock wait expired"
    elif [ $status = 0 ] && grep -q "^ok " "$out"; then
        verdict PASS
    elif [ $status = 1 ] && [ -n "$wrong" ]; then
        case $wrong in
        "WRONG $script refused:"*) verdict INFRA "run.sh refused the script" ;;
        *)
            where=$(grep -m1 -E '^[[:space:]]+[^[:space:]]+\.pkt:[0-9]+:' "$out" | sed 's/^[[:space:]]*//')
            summary=${wrong#"WRONG $script "}
            summary=${summary%"; output:"}
            case $wrong in
            "WRONG $script exit 124,"*) verdict FAIL "packetdrill timeout (run.sh: $summary)" ;;
            *)
                if [ -n "$where" ]; then
                    verdict FAIL "$where (run.sh: $summary)"
                else
                    verdict INFRA "run.sh reported no packetdrill mismatch or script timeout"
                fi
                ;;
            esac
            ;;
        esac
    else
        verdict INFRA "run.sh exited $status without a result for $script"
    fi
}

run_scapy() {
    bounded "$tap_echo" -- python3 -B fuzz/scapy/fuzz_tcp.py "$@"
    if timed_out; then
        verdict FAIL "no result within $limit s (exit $status)"
    elif [ $status = 0 ] && grep -q "^PASS seed " "$out"; then
        verdict PASS
    elif [ $status = 101 ]; then
        verdict FAIL "tap-echo panic oracle (exit 101)"
    elif [ $status = 2 ]; then
        verdict FAIL "tap-echo leaked buffers oracle (exit 2)"
    elif [ $status != 0 ] && grep -q "^FAIL connection " "$out"; then
        where=$(awk '/^FAIL connection / { head = $0; getline; sub(/^[[:space:]]+/, ""); print head " " $0; exit }' "$out")
        verdict FAIL "$where"
    else
        verdict INFRA "the fuzzer exited $status without a result"
    fi
}

while IFS= read -r line || [ -n "$line" ]; do
    case ${line#"${line%%[![:space:]]*}"} in '' | '#'*) continue ;; esac
    # shellcheck disable=SC2086
    set -- $line
    bug=$1 kind=$2
    shift 2
    name="$bug $kind $*"
    : >"$out"
    case $kind in
    rust) run_rust "$@" ;;
    pkt) run_pkt "$@" ;;
    scapy) run_scapy "$@" ;;
    esac
done <"$manifest"

echo "known-bugs: $fails FAIL, $passes UNEXPECTED-PASS, $infras INFRA"
if [ $passes != 0 ] || [ $infras != 0 ]; then
    exit 2
fi
[ $fails = 0 ] || exit 1
