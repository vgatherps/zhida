#!/bin/sh
# Usage: cpuset-overlap.sh CPUSET < containers
#        cpuset-overlap.sh --self-test
# Reads lines "<name> <cpuset>" (docker inspect --format
# '{{.Name}} {{.HostConfig.CpusetCpus}}'); cpusets use Docker's syntax, e.g.
# 3-5 or 0,2-3. Prints every container that is unpinned (empty cpuset: it may
# run on any CPU) or shares a CPU with CPUSET, and exits 1 if there is one.
set -u

# One CPU per line; exits 2 unless the cpuset is a list of N and N-M items
# with N <= M, each number without leading zeros (CPUs compare as strings
# below).
expand() {
	n='(0|[1-9][0-9]*)'
	printf '%s\n' "$1" | grep -Eqx "$n(-$n)?(,$n(-$n)?)*" ||
		{ echo "cpuset-overlap: bad cpuset '$1'" >&2; exit 2; }
	printf '%s\n' "$1" | tr ',' '\n' | while IFS=- read -r lo hi; do
		[ -n "$hi" ] || hi=$lo
		[ "$lo" -le "$hi" ] || { echo "cpuset-overlap: descending range $lo-$hi in '$1'" >&2; exit 2; }
		while [ "$lo" -le "$hi" ]; do echo "$lo"; lo=$((lo + 1)); done
	done
}

check() {
	want=$(expand "$1") || exit 2
	busy=0
	# The second test reads a final line without a newline.
	while read -r name cpus || [ -n "$name" ]; do
		if [ -z "${cpus:-}" ]; then
			echo "$name: unpinned" >&2; busy=1; continue
		fi
		have=$(expand "$cpus") || exit 2
		for cpu in $have; do
			if printf '%s\n' "$want" | grep -qx "$cpu"; then
				echo "$name: cpuset $cpus shares CPU $cpu with $1" >&2; busy=1; break
			fi
		done
	done
	return $busy
}

self_test() {
	# want  containers  expected-status
	fail=0
	t() {
		printf '%b' "$2" | check "$1" 2>/dev/null; got=$?
		[ "$got" = "$3" ] || { echo "cpuset-overlap self-test: '$1' with '$2': got $got, want $3" >&2; fail=1; }
	}
	t 3-6 '' 0
	t 3-6 '/a 0\n/b 1-2\n/c 0,2\n' 0
	t 3-6 '/a\n' 1
	t 3-6 '/a 0\n/b \n' 1
	t 3-6 '/a 6\n' 1
	t 3-6 '/a 0-3\n' 1
	t 3-6 '/a 0,5\n' 1
	t 0,2 '/a 1\n' 0
	t 0,2 '/a 1-2\n' 1
	t 10-12 '/a 1\n' 0
	t 10-12 '/a 12\n' 1
	t 3-x '/a 0\n' 2
	t 3-6 '/a 0-\n' 2
	t 03 '/a 3\n' 2
	t 3-6 '/a 03\n' 2
	t 3-6 '/a 0-08\n' 2
	t 0 '/a 0\n' 1
	t 6-3 '/a 0\n' 2
	t 3-6 '/a 1,6-4\n' 2
	t 3-6 '/a 0\n/b 5' 1
	t 3-6 '/b 5' 1
	t 3-6 '/b' 1
	t 3-6 '/a 0\n/b 1' 0
	[ $fail = 0 ] && echo 'cpuset-overlap self-test: ok'
	return $fail
}

case "${1:-}" in
--self-test) self_test ;;
'') echo 'usage: cpuset-overlap.sh CPUSET < containers | --self-test' >&2; exit 2 ;;
*) check "$1" ;;
esac
