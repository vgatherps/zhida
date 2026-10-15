#!/bin/sh
# Tester of binance-feed (make binance), run by the driver with its env
# (ZHIDA_IFACE, ZHIDA_IP, TESTER_IP, ...). Usage: tester.sh SECONDS.
# Run from the repo root. Needs CAP_NET_ADMIN, nft, tc and net.ipv4.ip_forward=1.
set -u
usage() { echo "usage: tester.sh SECONDS (positive integer)" >&2; exit 2; }
case "${1-}" in
'' | *[!0-9]*) usage ;;
esac
[ "$#" -eq 1 ] && [ "$1" -gt 0 ] || usage
secs=$1
say() { echo "binance-tester: $*" >&2; }

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
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != 1 ]; then
    say "net.ipv4.ip_forward is 0 (docker run --sysctl net.ipv4.ip_forward=1)"
    exit 1
fi
uplink=$(ip -4 route show default | awk '{ for (i = 1; i < NF; i++)
    if ($i == "dev") { print $(i + 1); exit } }')
if [ -z "$uplink" ]; then
    say "no device in the default IPv4 route"
    exit 1
fi
# Repeatable in one network namespace: the example's nft table is recreated,
# clsact is added only when missing and the checksum filter has its own pref.
if nft list table ip binance_feed >/dev/null 2>&1; then
    nft delete table ip binance_feed || exit 1
fi
nft add table ip binance_feed || exit 1
nft 'add chain ip binance_feed postrouting { type nat hook postrouting priority srcnat; }' || exit 1
nft "add rule ip binance_feed postrouting ip saddr $ZHIDA_IP oifname \"$uplink\" masquerade" || exit 1
# Under Docker Desktop, TCP segments from outside reach the container's eth0
# with a wrong checksum (the same value on every segment of a connection; the
# VM's network marks them as verified, so the kernel's own TCP accepts them).
# Forwarding keeps that checksum (NAT only adjusts it), and Zhida, which
# verifies every checksum, drops the segments: the server's SYN-ACK never
# counts. Recompute the TCP checksum of every IPv4 segment arriving on the
# uplink, before NAT. (Not on $ZHIDA_IFACE: net_tap owns its qdiscs.)
tc qdisc show dev "$uplink" | grep -q '^qdisc clsact ' || tc qdisc add dev "$uplink" clsact || exit 1
tc filter del dev "$uplink" ingress pref 49152 2>/dev/null
tc filter add dev "$uplink" ingress pref 49152 protocol ip matchall action csum tcp || exit 1

mkdir -p target/binance-feed && : > target/binance-feed/ready.tmp &&
    mv target/binance-feed/ready.tmp target/binance-feed/ready || exit 1
say "ready: Zhida $ZHIDA_IP, gateway $TESTER_IP on $ZHIDA_IFACE, NAT out of $uplink; running $secs s"
exec sleep "$secs"
