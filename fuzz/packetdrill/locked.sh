#!/usr/bin/env bash
# Runs COMMAND holding the packetdrill lock, so one packetdrill run at a time has the
# packetdrill CPUs: concurrent runs from other worktrees' containers would share them (the
# busy loops in run.sh only yield to processes of their own container) and make each other
# late. The lock is flock(2) on the file PACKETDRILL_LOCK; in Docker that file is on a named
# volume every gate container mounts. COMMAND and every process it starts (tap-echo,
# packetdrill, the busy loops) inherit the locked descriptor, and the kernel releases the
# lock only when the last of them has exited, so a cancelled run keeps it until its last
# process is gone and a killed run leaves no stale lock. A held lock is waited for, up to
# PACKETDRILL_LOCK_TIMEOUT seconds; then the run fails naming the lock and its holder as
# last recorded (best effort: the owner file is written just after taking the lock and
# names the run's first process).
#
# Usage: PACKETDRILL_LOCK=FILE PACKETDRILL_LOCK_TIMEOUT=SECONDS fuzz/packetdrill/locked.sh COMMAND...
set -uo pipefail

: "${PACKETDRILL_LOCK:?PACKETDRILL_LOCK: the lock file}"
: "${PACKETDRILL_LOCK_TIMEOUT:?PACKETDRILL_LOCK_TIMEOUT: seconds to wait for the lock}"
if ! [[ $PACKETDRILL_LOCK_TIMEOUT =~ ^(0|[1-9][0-9]*)$ ]] || (($# == 0)); then
    echo "usage: PACKETDRILL_LOCK=FILE PACKETDRILL_LOCK_TIMEOUT=SECONDS $0 COMMAND..." >&2
    exit 2
fi
lock=$PACKETDRILL_LOCK
owner=$lock.owner

holder() { cat "$owner" 2>/dev/null || echo "unknown"; }

exec 9>>"$lock" || exit 1
if ! flock -n 9; then
    echo "locked.sh: waiting up to $PACKETDRILL_LOCK_TIMEOUT s for packetdrill lock $lock, held by $(holder)" >&2
    start=$SECONDS
    if ! flock -w "$PACKETDRILL_LOCK_TIMEOUT" 9; then
        echo "locked.sh: packetdrill lock $lock still held after $PACKETDRILL_LOCK_TIMEOUT s by $(holder): another packetdrill run (any worktree) still has a process alive" >&2
        exit 1
    fi
    echo "locked.sh: took packetdrill lock $lock after $((SECONDS - start)) s" >&2
fi
echo "host $(hostname) pid $$ since $(date -u +%FT%TZ)" >"$owner.$$" && mv -f "$owner.$$" "$owner"
exec "$@"
