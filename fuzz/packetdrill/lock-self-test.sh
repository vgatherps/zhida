#!/usr/bin/env bash
# Self-test of locked.sh on a private lock file: two concurrent holders serialize; a lock
# held past the timeout fails naming the lock and holder without running COMMAND; COMMAND's
# exit status passes through; a SIGKILLed holder's surviving child keeps the lock until it
# exits, and the lock is free once it has (no stale lock).
set -uo pipefail

cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$tmp"' EXIT
export PACKETDRILL_LOCK=$tmp/lock
locked=$PWD/fuzz/packetdrill/locked.sh
wrong=0
check() {
    if eval "$2"; then echo "ok    $1"; else echo "WRONG $1 ($2)"; wrong=1; fi
}
wait_for() {
    for _ in $(seq 200); do [[ -e $1 ]] && return; sleep 0.05; done
    echo "WRONG $1 did not appear within 10 s"
    exit 1
}

# Two concurrent holders serialize: the second waits for the first, names it, then runs.
PACKETDRILL_LOCK_TIMEOUT=30 $locked sh -c "touch $tmp/first-in; sleep 2; touch $tmp/first-out" &
first=$!
wait_for "$tmp/first-in"
start=$SECONDS
PACKETDRILL_LOCK_TIMEOUT=30 $locked sh -c "test -e $tmp/first-out && test ! -e $tmp/second-ran && touch $tmp/second-ran" \
    2>"$tmp/wait.err"
status=$?
waited=$((SECONDS - start))
wait "$first"
check "the second holder runs only after the first ended" "[[ $status == 0 && -e $tmp/second-ran ]]"
check "the second holder waited at least 1 s" "((waited >= 1))"
check "the waiter names the holder" "grep -q 'held by host .* pid $first ' $tmp/wait.err"

# A lock held past the timeout fails, names lock and holder, and COMMAND does not run.
echo "host manual-holder" >"$PACKETDRILL_LOCK.owner"
(exec 9>>"$PACKETDRILL_LOCK" && flock 9 && touch "$tmp/held" && exec sleep 30) &
holder=$!
wait_for "$tmp/held"
start=$SECONDS
PACKETDRILL_LOCK_TIMEOUT=1 $locked touch "$tmp/ran" 2>"$tmp/held.err"
status=$?
waited=$((SECONDS - start))
kill "$holder"
wait "$holder" 2>/dev/null
check "a lock held past the timeout fails with exit 1" "[[ $status == 1 ]]"
check "the failure came after the timeout, not at once" "((waited >= 1))"
check "the failure names the lock and its holder" "grep -q 'lock $PACKETDRILL_LOCK still held after 1 s by host manual-holder' $tmp/held.err"
check "COMMAND did not run without the lock" "[[ ! -e $tmp/ran ]]"

# COMMAND's exit status passes through.
PACKETDRILL_LOCK_TIMEOUT=1 $locked sh -c 'exit 3'
check "COMMAND's exit status 3 passes through" "[[ $? == 3 ]]"

# A SIGKILLed holder's child keeps the lock until it exits; then the lock is free.
PACKETDRILL_LOCK_TIMEOUT=1 $locked sh -c "sleep 30 & echo \$! >$tmp/child; wait" &
parent=$!
wait_for "$tmp/child"
kill -KILL "$parent"
wait "$parent" 2>/dev/null
child=$(cat "$tmp/child")
PACKETDRILL_LOCK_TIMEOUT=1 $locked true 2>/dev/null
check "a killed holder's surviving child still holds the lock" "[[ $? == 1 ]] && kill -0 $child"
kill "$child"
for _ in $(seq 100); do kill -0 "$child" 2>/dev/null || break; sleep 0.05; done
PACKETDRILL_LOCK_TIMEOUT=1 $locked true
check "the lock is free once the last process has exited" "[[ $? == 0 ]]"
exit "$wrong"
