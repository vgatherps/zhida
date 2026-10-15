#!/bin/sh
# Self-test of peer.sh client mode (make test-autobahn-check) with fakes on
# PATH, each case in a fresh directory with `ready` present:
#   early-exit: wstest exits 0 and only then client-done appears -> done 1
#   no-done:    wstest exits 0, client-done never appears          -> done 1
#   sigint:     wstest runs until SIGINT, exits 0; client-done      -> done 0
# early-exit is ordered, not raced: a fake `sleep` (peer.sh's poll interval)
# on its first call writes `polled` and returns only once client-done exists;
# wstest exits once `polled` exists; a helper writes client-done once wstest
# is a zombie or gone. So peer.sh's first poll sees wstest alive and its next
# sees client-done with wstest exited. A fake `timeout` that reaps its command
# and then stays alive until SIGINT/SIGTERM (exiting with the command's
# status) makes a supervisor between peer.sh and wstest fail this case too. It
# installs handlers and blocks INT/TERM before it starts wstest, so a signal
# sent at any point after wstest exists is held until it is collected.
# Needs Linux /proc, awk and python3. Run from the repo root.
set -u
peer=$(pwd)/autobahn/peer.sh
real_sleep=$(command -v sleep) || exit 1
root=$(mktemp -d) || exit 1
trap 'rm -rf "$root"' EXIT
failed=0

# Writes the fakes for case $1 into $2/bin. Fake waits give up after 10 s.
fake() {
    mkdir -p "$2/bin"
    case $1 in
    early-exit)
        cat > "$2/bin/wstest" <<EOF
#!/bin/sh
i=0
until [ -e polled ] || [ \$i -ge 1000 ]; do $real_sleep 0.01; i=\$((i + 1)); done
me=\$\$
(
    i=0
    while state=\$(awk '{ print \$3 }' "/proc/\$me/stat" 2>/dev/null) && [ "\$state" != Z ] && [ \$i -lt 1000 ]; do
        $real_sleep 0.01; i=\$((i + 1))
    done
    : > autobahn/run/client/client-done
) &
exit 0
EOF
        cat > "$2/bin/sleep" <<EOF
#!/bin/sh
[ -e polled ] && exec $real_sleep "\$@"
: > polled
i=0
until [ -e autobahn/run/client/client-done ] || [ \$i -ge 1000 ]; do $real_sleep 0.01; i=\$((i + 1)); done
EOF
        cat > "$2/bin/timeout" <<'EOF'
#!/usr/bin/env python3
import signal, subprocess, sys
args = [a for a in sys.argv[1:] if not a.startswith("-")][1:]
stop = {signal.SIGINT, signal.SIGTERM}
for s in stop:
    signal.signal(s, lambda *_: None)  # not SIG_IGN: an ignored signal is discarded, not held
signal.pthread_sigmask(signal.SIG_BLOCK, stop)
signal.alarm(10)
status = subprocess.call(args)
signal.sigwait(stop)
sys.exit(status)
EOF
        chmod +x "$2/bin/sleep" "$2/bin/timeout"
        ;;
    no-done)
        printf '#!/bin/sh\nexit 0\n' > "$2/bin/wstest"
        ;;
    sigint)
        cat > "$2/bin/wstest" <<'EOF'
#!/bin/sh
trap 'exit 0' INT
: > autobahn/run/client/client-done
while :; do sleep 0.1; done
EOF
        ;;
    esac
    chmod +x "$2/bin/wstest"
}

for case in early-exit:1 no-done:1 sigint:0; do
    name=${case%%:*} want=${case#*:}
    dir=$root/$name
    mkdir -p "$dir/autobahn/run/client"
    : > "$dir/autobahn/run/client/ready"
    fake "$name" "$dir"
    (cd "$dir" && PATH="$dir/bin:$PATH" AUTOBAHN_TIMEOUT=20 sh "$peer" client) 2> "$dir/peer.log"
    got=$(cat "$dir/autobahn/run/client/done" 2>/dev/null || echo missing)
    if [ "$got" = "$want" ]; then
        echo "peer self-test $name: done $got as expected"
    else
        echo "peer self-test $name: done $got, expected $want; peer.sh said:" >&2
        cat "$dir/peer.log" >&2
        failed=1
    fi
done
exit $failed
