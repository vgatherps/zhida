#!/bin/sh
# Autobahn side of make docker-autobahn, in the Autobahn container sharing the
# Zhida container's netns. Waits for the tester's `ready`, runs wstest, and
# writes its exit status to `done` on any exit. Run from /work (repo root).
# server: wstest fuzzingclient against Zhida under timeout(1); done =
# wstest's status (124/137 if timeout ended it).
# client: wstest fuzzingserver on 192.0.2.1:9001, started directly in the
# background so $! is wstest itself (env restores SIGINT, which sh ignores in
# background jobs), until the driver writes `client-done` (its last
# connection, updateReports, already had fuzzingserver write the reports).
# peer.sh's poll bounds the wait by AUTOBAHN_TIMEOUT (expiry: SIGKILL, done 1).
# fuzzingserver without shutdownOnComplete never exits on its own, so when
# client-done is observed wstest must be alive and not a zombie
# (/proc/<pid>/stat state != Z); otherwise done = 1. Then SIGINT; done =
# wstest's status if it exits within 10 s of the signal, else SIGKILL and
# done = 1.
# Not updateReports?shutdownOnComplete=true: fuzzing.py onOpen (296-301)
# calls reactor.stop() before Twisted flushes the 101, so the client's
# handshake reads EOF.
set -u
case "${1-}" in
server | client) ;;
*) echo "usage: peer.sh server|client" >&2; exit 2 ;;
esac
run=autobahn/run/$1
status=1
trap 'echo "$status" > "$run/done.tmp" && mv "$run/done.tmp" "$run/done"' EXIT
trap 'exit' INT TERM

deadline=$(($(date +%s) + 60))
until [ -f "$run/ready" ]; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "peer: no ready within 60 s" >&2
        exit
    fi
    sleep 0.1
done

if [ "$1" = server ]; then
    timeout --kill-after=10 "${AUTOBAHN_TIMEOUT:?}" \
        wstest -m fuzzingclient -s autobahn/fuzzingclient.json
    status=$?
    echo "peer: wstest exited $status" >&2
    exit
fi

deadline=$(($(date +%s) + ${AUTOBAHN_TIMEOUT:?}))
env --default-signal=INT \
    wstest -m fuzzingserver -s autobahn/fuzzingserver.json --webport 0 &
pid=$!
# A reaped-or-zombie child is not running (kill -0 succeeds on a zombie).
running() {
    state=$(awk '{ print $3 }' "/proc/$pid/stat" 2>/dev/null) && [ "$state" != Z ]
}
until [ -f "$run/client-done" ]; do
    if ! running; then
        wait "$pid"
        echo "peer: wstest exited $? before client-done" >&2
        exit
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "peer: no client-done within $AUTOBAHN_TIMEOUT s; SIGKILL" >&2
        kill -KILL "$pid"
        wait "$pid"
        exit
    fi
    sleep 0.1
done
if ! running; then
    wait "$pid"
    echo "peer: wstest exited $? on its own by client-done" >&2
    exit
fi
kill -INT "$pid"
deadline=$(($(date +%s) + 10))
while running; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "peer: wstest still running 10 s after SIGINT; SIGKILL" >&2
        kill -KILL "$pid"
        wait "$pid"
        exit
    fi
    sleep 0.1
done
wait "$pid"
status=$?
echo "peer: wstest exited $status after SIGINT" >&2
