#!/usr/bin/env bash
# Self-test of the packetdrill CPU checks, failure paths only (every run.sh script run
# exercises the passing path): run.sh refuses equal or non-numeric CPUs (and a
# PACKETDRILL_TIMEOUT that is not a positive number), and the shim fails
# a packetdrill that may run on another CPU than PACKETDRILL_CPU.
# Usage: ZHIDA_CPU=C PACKETDRILL_CPU=P fuzz/packetdrill/cpu-self-test.sh (as run.sh).
set -uo pipefail

: "${ZHIDA_CPU:?ZHIDA_CPU: the CPU tap-echo runs on}"
: "${PACKETDRILL_CPU:?PACKETDRILL_CPU: the CPU packetdrill runs on}"
cd "$(dirname "$0")/../.."
c=$ZHIDA_CPU
p=$PACKETDRILL_CPU
script=fuzz/packetdrill/scripts/handshake-no-options.pkt

wrong=0
# expect STATUS TEXT COMMAND...: COMMAND exits STATUS and its output contains TEXT.
expect() {
    local want=$1 text=$2 out status=0
    shift 2
    out=$("$@" 2>&1) || status=$?
    if [[ $status == "$want" && $out == *"$text"* ]]; then
        echo "ok    $* exit $status"
    else
        echo "WRONG $* exit $status, expected $want with \"$text\"; output:"
        sed 's/^/    /' <<<"$out"
        wrong=1
    fi
}

expect 2 "are both $c" env ZHIDA_CPU="$c" PACKETDRILL_CPU="$c" fuzz/packetdrill/run.sh "$script"
expect 2 "must each be one CPU number" \
    env ZHIDA_CPU="$c" PACKETDRILL_CPU="$p-$p" fuzz/packetdrill/run.sh "$script"
expect 2 "PACKETDRILL_TIMEOUT (0) must be a positive number" \
    env ZHIDA_CPU="$c" PACKETDRILL_CPU="$p" PACKETDRILL_TIMEOUT=0 fuzz/packetdrill/run.sh "$script"
# packetdrill left on tap-echo's CPU: the shim must refuse to run the script.
expect 1 "not only CPU $p" env PACKETDRILL_CPU="$p" timeout --kill-after=5 60 \
    taskset -c "$c" target/debug/tap-echo -- packetdrill \
    --so_filename=target/fuzz/zhida_shim.so --ip_version=ipv4 \
    --local_ip=192.0.2.2 --remote_ip=192.0.2.1 --bind_port=8080 "$script"
exit "$wrong"
