#!/usr/bin/env bash
# Runs packetdrill scripts against Zhida, each in a fresh tap-echo process, packetdrill
# being its tester (run directly, so tap-echo's kill reaches it) in shared-object mode
# through target/fuzz/zhida_shim.so. GNU timeout runs without --foreground, so expiry
# signals its whole process group, packetdrill included; expiry fails the script.
#
# Usage: fuzz/packetdrill/run.sh [script.pkt...]   (default: scripts/*.pkt selftest/*.pkt)
# scripts/*.pkt must pass the packet-only check and exit 0, and so must known-bugs/*.pkt,
# run only when named (make known-bugs); they fail while their bug exists. Each
# selftest/*.pkt carries
# one header line: `// expect-pass` (exit 0), `// expect-refused: <text>` (the check refuses it, unrun, with <text>
# in the reason) or `// expect-error: <text>` (it exits exactly 1 with <text> in the
# output). Any script may carry one `// tap-echo: <flags>` line, flags only `--buffer N`,
# `--close-after N` and `--listeners N` (each at most once), passed before `--`; any other
# line starting `// tap-echo:`, or a second one, refuses the script unrun.
# packetdrill gets `--tolerance_usecs=25000` by default. One `// tolerance_usecs: N`
# line, with positive integer N in usecs, overrides it per script; an invalid or repeated
# header refuses the script unrun.
#
# ZHIDA_CPU and PACKETDRILL_CPU (required, distinct CPU numbers): tap-echo runs pinned to the first,
# packetdrill to the second, so packetdrill's timing checks never wait for Zhida's CPU;
# the shim fails a run whose packetdrill may run anywhere else (exported for it).
# PACKETDRILL_TIMEOUT: seconds each script may run (default 60); expiry fails it (exit 124).
set -euo pipefail

: "${ZHIDA_CPU:?ZHIDA_CPU: the CPU tap-echo runs on}"
: "${PACKETDRILL_CPU:?PACKETDRILL_CPU: the CPU packetdrill runs on}"
if ! [[ $ZHIDA_CPU =~ ^(0|[1-9][0-9]*)$ && $PACKETDRILL_CPU =~ ^(0|[1-9][0-9]*)$ ]]; then
    echo "run.sh: ZHIDA_CPU ($ZHIDA_CPU) and PACKETDRILL_CPU ($PACKETDRILL_CPU) must each be one CPU number" >&2
    exit 2
fi
if [[ $ZHIDA_CPU == "$PACKETDRILL_CPU" ]]; then
    echo "run.sh: ZHIDA_CPU and PACKETDRILL_CPU are both $ZHIDA_CPU" >&2
    exit 2
fi
timeout_s=${PACKETDRILL_TIMEOUT:-60}
if ! [[ $timeout_s =~ ^[1-9][0-9]*$ ]]; then
    echo "run.sh: PACKETDRILL_TIMEOUT ($timeout_s) must be a positive number of seconds" >&2
    exit 2
fi
export PACKETDRILL_CPU

cd "$(dirname "$0")/../.."
dir=fuzz/packetdrill
tap_echo=target/debug/tap-echo
shim=target/fuzz/zhida_shim.so

# packetdrill's lexer treats newlines as whitespace and its grammar allows adjacent events,
# so the check pins each line to one whole event. A line that is not a // comment and
# contains a backquote (shell command), `%{` (code), `/*` (comment that can span lines) or
# `=` (every syscall has `= result`) refuses the file outright; a // comment line may hold
# them (upstream notices quote ``AS IS''), since the lexer's cpp_comment rule takes the
# whole line (lexer.l). Every other line is blank, a // comment, or one TCP
# packet: `TIME <|> FLAGS S:E(L) [ack N] [win N] [<options>]`; options may hold SACK
# blocks (`sack S:E`). TIME is a number in either form packetdrill's lexer reads (lexer.l:
# INTEGER `[0-9]+`, FLOAT `[0-9]*[.][0-9]+`, so `.1` and `+.1` too), optionally after `+`.
# FLAGS is flag letters, or `-` for a segment with no flags (parser.y `flags`).
packet_line='^[[:space:]]*\+?([0-9]+|[0-9]*\.[0-9]+)[[:space:]]+[<>][[:space:]]+([SFPRUEWA.]+|-)[[:space:]]+[0-9]+:[0-9]+\([0-9]+\)([[:space:]]+ack[[:space:]]+[0-9]+)?([[:space:]]+win[[:space:]]+[0-9]+)?([[:space:]]+<[A-Za-z0-9 ,.:]*>)?[[:space:]]*$'

# Prints why $1 is refused and returns 1, or returns 0.
packet_only() {
    local number=0 line hit
    # No grep -m1: an early exit could SIGPIPE the first grep, failing the pipeline.
    hit=$(grep -n -v '^[[:space:]]*//' "$1" | grep -e '`' -e '%{' -e '/\*' -e '=' || true)
    if [[ -n $hit ]]; then
        echo "$1:${hit%%:*}: contains \`, %{, /* or ="
        return 1
    fi
    while IFS= read -r line || [[ -n $line ]]; do
        number=$((number + 1))
        [[ $line =~ ^[[:space:]]*(//.*)?$ ]] && continue
        [[ $line =~ $packet_line ]] && continue
        echo "$1:$number: not exactly one packet event: $line"
        return 1
    done <"$1"
}

header_line='^// tap-echo:(( --(buffer|close-after|listeners) [0-9]+)+)$'

# Prints the flags of $1's `// tap-echo:` line (nothing without one), or prints why it is
# refused and returns 1.
tap_echo_flags() {
    local hits flags
    hits=$(grep -n -E '^[[:space:]]*//[[:space:]]*tap-echo:' "$1" || true)
    [[ -z $hits ]] && return 0
    if [[ $hits == *$'\n'* ]]; then
        echo "$1: more than one tap-echo header"
        return 1
    fi
    if ! [[ ${hits#*:} =~ $header_line ]]; then
        echo "$1:${hits%%:*}: tap-echo header takes only --buffer N, --close-after N and --listeners N"
        return 1
    fi
    flags=${BASH_REMATCH[1]}
    if [[ $flags == *--buffer*--buffer* || $flags == *--close-after*--close-after*
        || $flags == *--listeners*--listeners* ]]; then
        echo "$1:${hits%%:*}: tap-echo header repeats a flag"
        return 1
    fi
    if [[ $flags =~ --listeners[[:space:]]+0+([[:space:]]|$) ]]; then
        echo "$1:${hits%%:*}: tap-echo header --listeners needs a positive integer"
        return 1
    fi
    echo "${flags# }"
}

# Prints $1's `// tolerance_usecs:` value (25000 without one), or prints why it is
# refused and returns 1.
tolerance_usecs() {
    local hits value
    hits=$(grep -n -E '^[[:space:]]*//[[:space:]]*tolerance_usecs:' "$1" || true)
    [[ -z $hits ]] && { echo 25000; return 0; }
    if [[ $hits == *$'\n'* ]]; then
        echo "$1: more than one tolerance_usecs header"
        return 1
    fi
    if ! [[ ${hits#*:} =~ ^//\ tolerance_usecs:\ ([1-9][0-9]*)$ ]]; then
        echo "$1:${hits%%:*}: tolerance_usecs header needs a positive integer"
        return 1
    fi
    value=${BASH_REMATCH[1]}
    echo "$value"
}

# Prints `pass`, `refused <text>` or `error <text>` for $1.
expectation() {
    local header
    case $1 in
    $dir/scripts/*.pkt | $dir/known-bugs/*.pkt) echo pass ;;
    $dir/selftest/*.pkt)
        header=$(grep -E -m1 '^// expect-(pass$|(refused|error): .+)' "$1" || true)
        if [[ -z $header ]]; then
            echo "$1: no // expect-pass, // expect-refused: or // expect-error: header" >&2
            return 1
        fi
        header=${header#// expect-}
        if [[ $header == pass ]]; then echo pass; return; fi
        echo "${header%%:*} ${header#*: }"
        ;;
    *) echo "$1: not under $dir/scripts, $dir/known-bugs or $dir/selftest" >&2; return 1 ;;
    esac
}

if (($#)); then
    scripts=("$@")
else
    scripts=("$dir"/scripts/*.pkt "$dir"/selftest/*.pkt)
fi

wrong=0
output=$(mktemp)
# A process sleeping on an idle vCPU of the Docker Desktop VM wakes up to 10 ms late
# (measured: 50 ms sleeps overshoot by a median 10.07 ms on an idle CPU, 0.06 ms beside a
# busy loop), beyond the strict scripts' 4 ms tolerance. A SCHED_IDLE busy loop on each of
# the two CPUs keeps them awake; a waking tap-echo or packetdrill of this container preempts
# it at once, and it gets only a minimal share (weight 3 vs 1024) while they stay runnable.
# Another container's processes on these CPUs compete with it as equals (each container is
# its own CPU-share group), so callers hold locked.sh's lock: one run at a time.
awake=()
for cpu in "$ZHIDA_CPU" "$PACKETDRILL_CPU"; do
    taskset -c "$cpu" chrt -i 0 sh -c 'while :; do :; done' &
    awake+=($!)
done
trap 'kill "${awake[@]}" 2>/dev/null; rm -f "$output"' EXIT
for script in "${scripts[@]}"; do
    expected=$(expectation "$script")
    kind=${expected%% *}
    text=${expected#* }

    reason_bad=0
    if ! reason=$(packet_only "$script"); then
        reason_bad=1
    elif ! flags=$(tap_echo_flags "$script"); then
        reason=$flags
        reason_bad=1
    elif ! tolerance=$(tolerance_usecs "$script"); then
        reason=$tolerance
        reason_bad=1
    fi
    if ((reason_bad)); then
        if [[ $kind == refused && $reason == *"$text"* ]]; then
            echo "ok    $script refused before running ($reason)"
        else
            echo "WRONG $script refused: $reason"
            wrong=1
        fi
        continue
    fi
    if [[ $kind == refused ]]; then
        echo "WRONG $script passed the packet-only and header checks; expected refusal"
        wrong=1
        continue
    fi

    # --strict_segments: each outbound event matches exactly one live segment. Without it
    # packetdrill joins consecutive live segments until their payloads add up to the
    # script's length (config.c 110/585, run_packet.c 1823-1920, packet.c 275), so a
    # 1448-byte expectation would also pass for 1436 + 12 bytes.
    read -ra flag_args <<<"$flags"
    start=$(date +%s%N)
    status=0
    timeout --kill-after=5 "$timeout_s" taskset -c "$ZHIDA_CPU" "$tap_echo" "${flag_args[@]}" -- \
        taskset -c "$PACKETDRILL_CPU" packetdrill \
        --so_filename="$shim" --ip_version=ipv4 --strict_segments --tolerance_usecs="$tolerance" \
        --local_ip=192.0.2.2 --remote_ip=192.0.2.1 --bind_port=8080 \
        "$script" >"$output" 2>&1 || status=$?
    duration=$((($(date +%s%N) - start) / 1000000))

    result_ok=0
    if [[ $kind == pass ]]; then
        want="exit 0"
        if ((status == 0)); then result_ok=1; fi
    else
        want="exit 1 with \"$text\""
        if ((status == 1)) && grep -qF -- "$text" "$output"; then result_ok=1; fi
    fi
    if ((result_ok)); then
        echo "ok    $script exit $status (${duration} ms)"
    else
        echo "WRONG $script exit $status, expected $want (${duration} ms); output:"
        sed 's/^/    /' "$output"
        wrong=1
    fi
done
exit "$wrong"
