#!/bin/sh
# Tester of `ws-autobahn server|client` (make docker-autobahn), run by the driver
# in the Zhida container with its env (ZHIDA_IFACE, TESTER_IP=192.0.2.1, ...).
# Takes 192.0.2.1/24 on the tap netdev, signals `ready` to peer.sh; client role:
# then waits until wstest's fuzzingserver listens on port 9001 and signals
# `server-ready` to the driver. Waits for peer.sh's `done`, then exits with
# check.py's status. Run from the repo root.
set -u
case "${1-}" in
server | client) ;;
*) echo "usage: zhida-tester.sh server|client" >&2; exit 2 ;;
esac
run=autobahn/run/$1
say() { echo "zhida-tester: $*" >&2; }

# Bounded waits poll in a loop, so SIGTERM ends this script within one sleep.
wait_until() { # seconds, description, condition...
    limit=$1 what=$2
    shift 2
    deadline=$(($(date +%s) + limit))
    until "$@"; do
        if [ "$(date +%s)" -ge "$deadline" ]; then
            say "$what not within $limit s"
            exit 1
        fi
        sleep 0.1
    done
}

iface_up() {
    flags=$(cat "/sys/class/net/$ZHIDA_IFACE/flags" 2>/dev/null) && [ $((flags & 1)) -eq 1 ]
}
wait_until 60 "$ZHIDA_IFACE up" iface_up

ip addr add "$TESTER_IP/24" dev "$ZHIDA_IFACE" || exit 1
# Path proof: the kernel's only 192.0.2.0/24 address is ours on the tap netdev,
# so every connection to 192.0.2.2 (Zhida) crosses net_tap.
owned=$(ip -o -4 addr show | grep ' inet 192\.0\.2\.' | while read -r _ dev _ cidr _; do
    echo "$dev $cidr"
done)
if [ "$owned" != "$ZHIDA_IFACE $TESTER_IP/24" ]; then
    say "192.0.2.0/24 addresses in this netns: $owned"
    exit 1
fi

echo "$TESTER_IP $ZHIDA_IFACE" > "$run/ready.tmp" && mv "$run/ready.tmp" "$run/ready" || exit 1
say "ready"

# A LISTEN socket (state 0A) on port 9001 (2329) reachable at 192.0.2.1 (010200C0
# little-endian) or any address, in /proc/net/tcp of this netns, which the
# Autobahn container shares.
fuzzingserver_listens() {
    awk '$4 == "0A" && ($2 == "010200C0:2329" || $2 == "00000000:2329") { found = 1 }
        END { exit !found }' /proc/net/tcp
}
if [ "$1" = client ]; then
    wait_until 60 "fuzzingserver listening on 9001" fuzzingserver_listens
    : > "$run/server-ready.tmp" && mv "$run/server-ready.tmp" "$run/server-ready" || exit 1
    say "server-ready"
fi

wait_until "${AUTOBAHN_TIMEOUT:?}" "peer done" test -f "$run/done"
status=$(cat "$run/done")
if [ "$status" != 0 ]; then
    say "peer exited $status"
    exit 1
fi
exec python3 autobahn/check.py "$run/reports/index.json"
