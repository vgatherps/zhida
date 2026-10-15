.DEFAULT_GOAL := help
.NOTPARALLEL:
.PHONY: help doctor build test-support test-sys test-buffer test-props test-stack test-stack-release test-echo test-nic-runner test-netconf test-stream test-ws test-binance test-memif test-autobahn-check test bench memif-bench fuzz binance known-bugs docker-image docker-doctor docker-build docker-test docker-gate-self-test docker-bench docker-memif-bench docker-fuzz docker-binance-image docker-binance docker-known-bugs docker-autobahn-image docker-autobahn test-smoltcp bench-stack docker-bench-stack test-packetdrill test-scapy test-known-bugs packetdrill-build soak docker-soak

DOCKER ?= docker
# Empty = native host architecture. DOCKER_PLATFORM=linux/amd64 builds through buildx (emulated on an
# arm64 host) and defaults the image tag and target volume per platform, so :local stays native.
DOCKER_PLATFORM ?=
DOCKER_PLATFORM_TAG = $(subst /,-,$(DOCKER_PLATFORM))
DOCKER_IMAGE ?= zhida-dpdk-test:$(if $(DOCKER_PLATFORM),$(DOCKER_PLATFORM_TAG),local)
DOCKER_TARGET_VOLUME ?= zhida-linux-target$(if $(DOCKER_PLATFORM),-$(DOCKER_PLATFORM_TAG))
# Image with nftables for Binance's live stream.
BINANCE_IMAGE ?= zhida-dpdk-test:binance
# Seconds the tester keeps the live feed open.
BINANCE_SECONDS ?= 10
# TLS server name and HTTP Host of the feed.
BINANCE_HOST ?= data-stream.binance.vision
# TLS WebSocket server port.
BINANCE_PORT ?= 9443
# WebSocket request path.
BINANCE_PATH ?= /ws/btcusdt@bookTicker
# Number of bookTicker messages printed.
BINANCE_PRINT ?= 10
# A hung test step fails (timeout exits 124, or 137 after the KILL grace).
# Measured 2026-10-07 in Docker: slowest step 22 s cold, 3 s warm.
TEST_TIMEOUT ?= 600
# The one CPU containers run on; EAL pins its main lcore to it.
DOCKER_CPUSET ?= 0
TIMEOUT = timeout --kill-after=10 $(TEST_TIMEOUT)
# Container flags other than the cpuset.
DOCKER_ACCESS = --cap-add NET_ADMIN --device /dev/net/tun \
	-v "$(CURDIR):/work" -w /work \
	-v zhida-cargo-registry:/usr/local/cargo/registry \
	-v $(DOCKER_TARGET_VOLUME):/work/target
DOCKER_DPDK = --cpuset-cpus=$(DOCKER_CPUSET) $(DOCKER_ACCESS)
# --init: tini is PID 1 and forwards signals. make as PID 1, sent SIGTERM mid-step,
# reaps the step, then the kernel drops the default-action TERM it re-raises on
# itself and make can stay alive (docker/README.md).
DOCKER_RUN = $(DOCKER) run --rm --init $(DOCKER_DPDK) $(DOCKER_IMAGE)
# Seconds for the whole in-container make test (each step also has TEST_TIMEOUT);
# expiry stops make with TERM (KILL 10 s later) and exits 124 (137).
MAKE_TEST_TIMEOUT ?= 3600
# make test's container: also gets the packetdrill CPUs (the later --cpuset-cpus
# wins); make is pinned to DOCKER_CPUSET (every EAL process needs exactly one
# allowed CPU); run.sh moves tap-echo and packetdrill to their own CPUs.
# The packetdrill lock (fuzz/packetdrill/locked.sh) is on PACKETDRILL_LOCK_VOLUME,
# which every such container mounts, so it is one lock for all worktrees.
PACKETDRILL_LOCK_VOLUME ?= zhida-packetdrill-lock
PACKETDRILL_CPUS = DOCKER_CPUSET=$(DOCKER_CPUSET) PACKETDRILL_CPUSET=$(PACKETDRILL_CPUSET) \
	PACKETDRILL_ZHIDA_CPUSET=$(PACKETDRILL_ZHIDA_CPUSET) PACKETDRILL_LOCK=/packetdrill-lock/run.lock \
	PACKETDRILL_LOCK_TIMEOUT=$(PACKETDRILL_LOCK_TIMEOUT)
DOCKER_MAKE_TEST = $(DOCKER) run --rm --init $(DOCKER_DPDK) -v $(PACKETDRILL_LOCK_VOLUME):/packetdrill-lock \
	--cpuset-cpus=$(DOCKER_CPUSET),$(PACKETDRILL_CPUSET),$(PACKETDRILL_ZHIDA_CPUSET) $(DOCKER_IMAGE) \
	taskset -c $(DOCKER_CPUSET) timeout --kill-after=10 $(MAKE_TEST_TIMEOUT) make $(PACKETDRILL_CPUS)
AUTOBAHN_IMAGE ?= zhida-autobahn:25.10.1
# Seconds for the driver and for wstest each; expiry fails the run.
AUTOBAHN_TIMEOUT ?= 600
# The CPU of the Autobahn peer container; it must differ from DOCKER_CPUSET.
AUTOBAHN_CPUSET ?= 1
# packetdrill runs (test-packetdrill, known-bugs): tap-echo alone on
# PACKETDRILL_ZHIDA_CPUSET, packetdrill alone on PACKETDRILL_CPUSET, both off
# DOCKER_CPUSET (which every gate shares), so the scripts' timing checks see
# neither side wait for a CPU. Single CPU numbers, distinct from DOCKER_CPUSET
# and from each other.
PACKETDRILL_CPUSET ?= 2
PACKETDRILL_ZHIDA_CPUSET ?= 7
# One packetdrill run at a time holds those CPUs (fuzz/packetdrill/locked.sh):
# the lock file (native default; Docker containers use the shared volume above),
# and the seconds a run waits for it before failing (the suite takes about 65 s).
PACKETDRILL_LOCK ?= /tmp/zhida-packetdrill.lock
PACKETDRILL_LOCK_TIMEOUT ?= 600
PACKETDRILL_ENV = ZHIDA_CPU=$(PACKETDRILL_ZHIDA_CPUSET) PACKETDRILL_CPU=$(PACKETDRILL_CPUSET) \
	PACKETDRILL_LOCK=$(PACKETDRILL_LOCK) PACKETDRILL_LOCK_TIMEOUT=$(PACKETDRILL_LOCK_TIMEOUT)
CHECK_CPUSETS = if [ "$(AUTOBAHN_CPUSET)" = "$(DOCKER_CPUSET)" ]; then \
	echo "$@: AUTOBAHN_CPUSET and DOCKER_CPUSET are both $(DOCKER_CPUSET); the peer and Zhida need separate CPUs" >&2; \
	exit 1; \
	fi
CHECK_PACKETDRILL_CPUSET = for cpu in "$(DOCKER_CPUSET)" "$(PACKETDRILL_CPUSET)" "$(PACKETDRILL_ZHIDA_CPUSET)"; do \
	case $$cpu in 0|[1-9]|[1-9]*[0-9]) case $$cpu in *[!0-9]*) cpu=;; esac;; *) cpu=;; esac; \
	[ -n "$$cpu" ] || { echo "$@: DOCKER_CPUSET, PACKETDRILL_CPUSET and PACKETDRILL_ZHIDA_CPUSET ($(DOCKER_CPUSET), $(PACKETDRILL_CPUSET), $(PACKETDRILL_ZHIDA_CPUSET)) must each be one CPU number" >&2; exit 1; }; \
	done; \
	if [ "$(DOCKER_CPUSET)" = "$(PACKETDRILL_CPUSET)" ] || [ "$(DOCKER_CPUSET)" = "$(PACKETDRILL_ZHIDA_CPUSET)" ] || \
		[ "$(PACKETDRILL_CPUSET)" = "$(PACKETDRILL_ZHIDA_CPUSET)" ]; then \
	echo "$@: DOCKER_CPUSET, PACKETDRILL_CPUSET and PACKETDRILL_ZHIDA_CPUSET ($(DOCKER_CPUSET), $(PACKETDRILL_CPUSET), $(PACKETDRILL_ZHIDA_CPUSET)) must differ" >&2; \
	exit 1; \
	fi
# Seconds for the Autobahn image build (host side; a cold build takes about
# 1 min and needs network, a cached one seconds); expiry kills it and fails.
AUTOBAHN_IMAGE_TIMEOUT ?= 300
# Autobahn 25.10.1 cases ("*"): fuzzingclient makes one connection each, the
# client role runs each against fuzzingserver.
AUTOBAHN_CASES = 517
# memif-bench CPUs: EAL control threads, peer process, client process; the
# Docker cpuset holds all three (off CPU 0, where other gates run).
MEMIF_CONTROL_CPU ?= 3
MEMIF_PEER_CPU ?= 4
MEMIF_CLIENT_CPU ?= 5
MEMIF_CPUSET ?= 3-5

# Stack benches (crates/dpdk-smoltcp/benches): the one CPU of docker-bench-stack's
# container. BENCH_FILTER is Criterion's benchmark name filter (a regex);
# BENCH_RUSTFLAGS is appended to RUSTFLAGS for the bench build, e.g. a code-layout
# perturbation. Both are used as given ($(value), no make expansion), so `$`
# needs no doubling; neither may contain a single quote.
STACK_BENCH_CPU ?= 6
BENCH_FILTER ?=
BENCH_RUSTFLAGS ?=
# Minimum wall seconds for the ignored two-stack soak.
SOAK_SECONDS ?= 600
# Seed for the soak's workload and link impairment.
SOAK_SEED ?= 1
# The one CPU of the soak container.
SOAK_CPUSET ?= 8
# Allow 1800 extra seconds for minima, drain and the release build.
TIMEOUT_SOAK = timeout --kill-after=10 $$(( $(SOAK_SECONDS) + 1800 ))
# Recipe line that fails if `docker ps` or `docker inspect` fails, or a running
# container is unpinned or shares a CPU with cpuset $(1), named by variable $(2)
# (docker/cpuset-overlap.sh); timed numbers need those CPUs to themselves.
cpuset_free = ids=$$($(DOCKER) ps -q) || { echo '$@: docker ps failed.' >&2; exit 1; }; \
	[ -z "$$ids" ] && exit 0; \
	running=$$($(DOCKER) inspect --format '{{.Name}} {{.HostConfig.CpusetCpus}}' $$ids) || \
		{ echo '$@: docker inspect failed.' >&2; exit 1; }; \
	printf '%s\n' "$$running" | sh docker/cpuset-overlap.sh '$(1)' || \
		{ echo '$@ needs $(2) ($(1)) free of other containers.' >&2; exit 1; }

# Scapy fuzzer (fuzz/scapy): seeded connection count; a run past FUZZ_TIMEOUT seconds fails.
FUZZ_SEED ?= 1
FUZZ_CONNECTIONS ?= 300
FUZZ_ONLY ?=
FUZZ_TIMEOUT ?= 600
FUZZ_VARS = FUZZ_SEED=$(FUZZ_SEED) FUZZ_CONNECTIONS=$(FUZZ_CONNECTIONS) FUZZ_ONLY=$(FUZZ_ONLY) \
	FUZZ_TIMEOUT=$(FUZZ_TIMEOUT)

help:
	@printf '%s\n' 'Native Linux: doctor build test-support test-sys test-buffer test-props test-stack test-stack-release test-echo test-nic-runner test-netconf test-stream test-ws test-binance test-memif test-autobahn-check test-packetdrill test-scapy test-known-bugs test bench memif-bench fuzz binance known-bugs test-smoltcp bench-stack soak' \
		'Docker: docker-image docker-doctor docker-build docker-test docker-gate-self-test docker-bench docker-memif-bench docker-fuzz docker-binance-image docker-binance docker-known-bugs docker-autobahn-image docker-autobahn docker-bench-stack docker-soak' \
		'Override image: make DOCKER_IMAGE=your-image docker-test' \
		'Docs: README.md, docker/README.md (tests), crates/nic-runner/README.md (NIC host), docs/USAGE.md (API)'

doctor:
	@test "$$(uname -s)" = Linux || { echo 'Native targets require Linux; use Docker on macOS.' >&2; exit 1; }
	@command -v cargo >/dev/null || { echo 'Missing cargo' >&2; exit 1; }
	@command -v clang >/dev/null || { echo 'Missing clang' >&2; exit 1; }
	@command -v pkg-config >/dev/null || { echo 'Missing pkg-config' >&2; exit 1; }
	@pkg-config --exists libdpdk || { echo 'Missing libdpdk development package' >&2; exit 1; }
	@test "$$(pkg-config --modversion libdpdk)" = 25.11.3 || { echo 'Expected DPDK 25.11.3; see docker/README.md.' >&2; exit 1; }
	uname -a
	cargo --version
	rustc --version
	clang --version
	pkg-config --version
	pkg-config --modversion libdpdk

build: doctor
	cargo build --locked --workspace --all-targets --features proptest,dpdk-smoltcp/bench-offload

test-support:
	$(TIMEOUT) cargo test --locked -p zhida-test-support -p zhida-test-support-macros

test-sys: doctor
	$(TIMEOUT) cargo test --locked -p zhida-dpdk-sys -- --test-threads=1

test-buffer: doctor
	$(TIMEOUT) cargo test --locked -p zhida-buffer -- --test-threads=1

test-props: doctor
	$(TIMEOUT) cargo test --locked -p zhida-buffer --features proptest --test props -- --test-threads=1

test-stack: doctor
	$(TIMEOUT) cargo test --locked -p dpdk-smoltcp -p zhida-test-kit -- --test-threads=1

test-stack-release: doctor
	$(TIMEOUT) cargo test --locked --release -p dpdk-smoltcp -p stack-stream -- --test-threads=1

test-echo: doctor
	$(TIMEOUT) cargo test --locked -p tap-echo -- --test-threads=1 --show-output

test-nic-runner: doctor
	TEST_TIMEOUT=$(TEST_TIMEOUT) DOCKER_CPUSET=$(DOCKER_CPUSET) $(TIMEOUT) sh crates/nic-runner/tests/run.sh

test-netconf: doctor
	$(TIMEOUT) cargo test --locked -p zhida-netconf -p zhida-open -- --test-threads=1

test-stream: doctor
	$(TIMEOUT) cargo test --locked -p stack-stream -- --test-threads=1

test-ws: doctor
	$(TIMEOUT) cargo test --locked -p ws-autobahn -- --test-threads=1

test-binance: doctor
	$(TIMEOUT) cargo test --locked -p binance-feed -- --test-threads=1

test-memif: doctor
	$(TIMEOUT) cargo test --locked -p memif-bench -- --test-threads=1
	$(TIMEOUT) sh docker/cpuset-overlap.sh --self-test

test-autobahn-check:
	$(TIMEOUT) python3 autobahn/check.py --self-test
	$(TIMEOUT) sh autobahn/peer-self-test.sh

# smoltcp's own lib unit test gate uses Zhida's smoltcp features (crates/dpdk-smoltcp/Cargo.toml)
# plus medium-ip, which gates smoltcp's TCP socket tests. vendor/smoltcp is outside the
# workspace, so it has its own lockfile and target dir. Include the TCP ISN integration
# test: it exercises production ISNs, while socket unit tests keep their fixed ISN.
SMOLTCP_TEST_FEATURES = udp-set,medium-ip,auto-icmp-echo-reply
test-smoltcp:
	$(TIMEOUT) cargo test --locked --manifest-path vendor/smoltcp/Cargo.toml --target-dir target/smoltcp \
		--lib --test tcp_isn --no-default-features --features $(SMOLTCP_TEST_FEATURES)

# The packetdrill lock's self-test, then under that lock the packetdrill suite,
# the runner's self-tests and the CPU checks' self-test (fuzz/packetdrill/README.md).
test-packetdrill: packetdrill-build
	fuzz/packetdrill/lock-self-test.sh
	$(PACKETDRILL_ENV) fuzz/packetdrill/locked.sh \
		sh -c 'fuzz/packetdrill/run.sh && fuzz/packetdrill/cpu-self-test.sh'

# The Scapy fuzzer's unit tests (no network).
test-scapy:
	$(TIMEOUT) python3 -B -m unittest discover -s fuzz/scapy

# fuzz/known-bugs.sh's self-test (stub commands; no DPDK).
test-known-bugs:
	$(TIMEOUT) sh fuzz/known-bugs-self-test.sh

test: test-support test-sys test-buffer test-props test-stack test-stack-release test-echo test-nic-runner test-netconf test-packetdrill test-stream test-ws test-binance test-memif test-autobahn-check test-scapy test-known-bugs test-smoltcp

bench: doctor
	cargo bench --locked -p zhida-buffer --bench buffer

# Every bench process needs exactly one allowed CPU (the EAL lcore's); run it
# natively under e.g. `taskset -c 6`.
bench-stack: doctor
	$(if $(value BENCH_RUSTFLAGS),RUSTFLAGS="$$RUSTFLAGS "'$(value BENCH_RUSTFLAGS)') \
		cargo bench --locked -p dpdk-smoltcp --features bench-offload --bench ring --bench stack --bench scaling --bench neighbor --bench emit --bench rx --bench udp \
		$(if $(value BENCH_FILTER),-- '$(value BENCH_FILTER)')

soak:
	SOAK_SECONDS=$(SOAK_SECONDS) SOAK_SEED=$(SOAK_SEED) $(TIMEOUT_SOAK) \
		cargo test --locked --release -p dpdk-smoltcp --test soak -- --ignored --nocapture --test-threads=1

memif-bench: doctor
	cargo build --locked --release -p memif-bench
	target/release/memif-bench matrix --peer-cpu $(MEMIF_PEER_CPU) \
		--client-cpu $(MEMIF_CLIENT_CPU) --control-cpu $(MEMIF_CONTROL_CPU)

# tap-echo and the packetdrill shim, the inputs of fuzz/packetdrill/run.sh.
packetdrill-build: doctor
	cargo build --locked -p tap-echo
	mkdir -p target/fuzz
	clang -shared -fPIC -Wall -Werror -I/opt/packetdrill/include \
		-o target/fuzz/zhida_shim.so fuzz/packetdrill/zhida_shim.c

# The Scapy mutation fuzzer only; its unit tests run in make test.
fuzz: doctor
	cargo build --locked -p tap-echo
	timeout --kill-after=10 $(FUZZ_TIMEOUT) target/debug/tap-echo -- python3 -B fuzz/scapy/fuzz_tcp.py \
		--seed $(FUZZ_SEED) --connections $(FUZZ_CONNECTIONS) $(if $(FUZZ_ONLY),--only $(FUZZ_ONLY))

# Native live feed; needs internet and the tester's network permissions.
binance: doctor
	cargo build --locked -p binance-feed
	timeout --kill-after=10 $$(( $(BINANCE_SECONDS) + 60 )) target/debug/binance-feed \
		--host '$(BINANCE_HOST)' --port $(BINANCE_PORT) --path '$(BINANCE_PATH)' \
		--print $(BINANCE_PRINT) -- crates/binance-feed/tester.sh $(BINANCE_SECONDS)

# Every repro in fuzz/known-bugs.txt, each alone (fuzz/known-bugs.sh): exits nonzero
# while any bug exists; not part of any gate. A known-bugs packetdrill script gets
# KNOWN_BUGS_PKT_TIMEOUT seconds (run.sh's default is 60), so the K5-style scripts that
# hang until expiry cost 15 s each; every other repro gets TEST_TIMEOUT.
KNOWN_BUGS_PKT_TIMEOUT ?= 15
known-bugs: packetdrill-build
	$(PACKETDRILL_ENV) KNOWN_BUGS_TIMEOUT=$(TEST_TIMEOUT) \
		KNOWN_BUGS_PKT_TIMEOUT=$(KNOWN_BUGS_PKT_TIMEOUT) fuzz/known-bugs.sh

docker-image:
	$(if $(DOCKER_PLATFORM),$(DOCKER) buildx build --load --platform $(DOCKER_PLATFORM),$(DOCKER) build) \
		-t $(DOCKER_IMAGE) -f docker/Dockerfile docker

docker-doctor:
	$(DOCKER_RUN) make doctor

docker-build:
	$(DOCKER_RUN) make build

# make test in the Zhida container (bounded by MAKE_TEST_TIMEOUT), then both
# Autobahn roles (docker-autobahn) even if make test failed; exit 0 only if both pass.
# An interrupt, or make test ending by a signal (exit >= 128), stops here.
docker-test:
	@set -u; trap 'exit 130' INT TERM HUP; \
	$(CHECK_CPUSETS); \
	$(CHECK_PACKETDRILL_CPUSET); \
	$(DOCKER_MAKE_TEST) test TEST_TIMEOUT=$(TEST_TIMEOUT); suite=$$?; \
	case $$suite in 124|137) echo "docker-test: make test did not finish within MAKE_TEST_TIMEOUT=$(MAKE_TEST_TIMEOUT) s" >&2;; esac; \
	if [ $$suite -ge 128 ]; then \
		echo "docker-test: FAIL: make test exit $$suite (signal); docker-autobahn not run" >&2; \
		exit $$suite; \
	fi; \
	[ $$suite = 0 ] || echo "docker-test: make test FAILED (exit $$suite); running docker-autobahn anyway" >&2; \
	$(MAKE) --no-print-directory docker-autobahn; autobahn=$$?; \
	[ $$suite = 0 ] && [ $$autobahn = 0 ] && result=PASS || result=FAIL; \
	echo "docker-test: $$result: make test exit $$suite, docker-autobahn exit $$autobahn" >&2; \
	[ $$result = PASS ]

# A stuck step must end the Zhida container with a failure. Runs goals of
# docker/gate-self-test.mk in a container named for the case, as `bounded`
# ($(DOCKER_MAKE_TEST), the docker-test shape) or `plain` ($(DOCKER_RUN) make,
# the docker-fuzz shape; it guards --init alone):
#   hang bounded, MAKE_TEST_TIMEOUT 5 s: must exit 124 (the bound).
#   term bounded and term plain, 30 s: once the log shows `term-step: started`,
#   `docker kill -s TERM` the container; must exit 143 (the TERM).
# Each must print its stuck step as Terminated, never run the next step, end
# within its bound + 10 s KILL grace + 15 s, and leave no container. At that
# deadline the docker client is killed (TERM, KILL 10 s later) and the container
# removed; that fails. Every docker kill/rm/ps is bounded (10 s) and fails if it
# fails or times out. About 10 s; not part of docker-test.
docker-gate-self-test: MAKE_TEST_TIMEOUT = $$bound
docker-gate-self-test: DOCKER_DPDK += --name $$name
docker-gate-self-test:
	@set -u; \
	bounded() { \
		secs=$$1; shift; "$$@" & bp=$$!; i=0; \
		while kill -0 $$bp 2>/dev/null && [ $$i -lt $$(( secs * 5 )) ]; do sleep 0.2; i=$$((i + 1)); done; \
		if kill -0 $$bp 2>/dev/null; then kill -KILL $$bp; wait $$bp; return 124; fi; \
		wait $$bp; \
	}; \
	check() { \
		goal=$$1 run=$$2 want=$$3 bound=$$4; name=zhida-gate-self-test-$$goal-$$run-$$$$; \
		log=$$(mktemp) || return 1; \
		start=$$(date +%s); deadline=$$(( start + bound + 25 )); \
		if [ $$run = bounded ]; then \
			$(DOCKER_MAKE_TEST) -f docker/gate-self-test.mk $$goal >$$log 2>&1 & pid=$$!; \
		else \
			$(DOCKER_RUN) make -f docker/gate-self-test.mk $$goal >$$log 2>&1 & pid=$$!; \
		fi; \
		failed=; sent=; \
		while kill -0 $$pid 2>/dev/null && [ "$$(date +%s)" -lt $$deadline ]; do \
			if [ $$goal = term ] && [ -z "$$sent" ] && grep -q '^term-step: started' $$log; then \
				sent=1; bounded 10 $(DOCKER) kill -s TERM $$name >/dev/null || failed="$$failed docker-kill"; \
			fi; \
			sleep 0.2; \
		done; \
		if kill -0 $$pid 2>/dev/null; then \
			failed="$$failed still-running"; \
			kill $$pid 2>/dev/null; i=0; \
			while kill -0 $$pid 2>/dev/null && [ $$i -lt 50 ]; do sleep 0.2; i=$$((i + 1)); done; \
			kill -KILL $$pid 2>/dev/null; \
			bounded 10 $(DOCKER) rm -f $$name >/dev/null 2>&1 || failed="$$failed docker-rm"; \
		fi; \
		wait $$pid; rc=$$?; \
		[ $$goal != term ] || [ -n "$$sent" ] || failed="$$failed term-not-sent"; \
		[ $$rc = $$want ] || failed="$$failed exit"; \
		grep -q "$$goal-step\] Terminated" $$log || failed="$$failed no-step-named"; \
		! grep -q 'after: ran' $$log || failed="$$failed next-step-ran"; \
		if left=$$(bounded 10 $(DOCKER) ps -aq --filter "name=^/$$name$$"); then \
			[ -z "$$left" ] || failed="$$failed container-left"; \
		else \
			failed="$$failed docker-ps"; \
		fi; \
		[ -z "$$failed" ] && result=PASS || result=FAIL; \
		echo "docker-gate-self-test: $$goal $$run $$result: exit $$rc (want $$want), $$(( $$(date +%s) - start )) s, failures:$${failed:- none}"; \
		[ $$result = PASS ] || sed 's/^/  | /' $$log; \
		rm -f $$log; \
		[ $$result = PASS ]; \
	}; \
	status=0; \
	check hang bounded 124 5 || status=1; \
	check term bounded 143 30 || status=1; \
	check term plain 143 30 || status=1; \
	exit $$status

docker-bench:
	$(DOCKER_RUN) make bench

# Timed numbers need MEMIF_CPUSET to itself (cpuset_free). The cpuset is
# MEMIF_CPUSET only, never DOCKER_CPUSET.
docker-memif-bench:
	@$(call cpuset_free,$(MEMIF_CPUSET),MEMIF_CPUSET)
	$(DOCKER) run --rm --cpuset-cpus=$(MEMIF_CPUSET) $(DOCKER_ACCESS) $(DOCKER_IMAGE) \
		make memif-bench MEMIF_PEER_CPU=$(MEMIF_PEER_CPU) \
		MEMIF_CLIENT_CPU=$(MEMIF_CLIENT_CPU) MEMIF_CONTROL_CPU=$(MEMIF_CONTROL_CPU)

# The stack benches on STACK_BENCH_CPU alone (cpuset_free), never DOCKER_CPUSET.
docker-bench-stack:
	@$(call cpuset_free,$(STACK_BENCH_CPU),STACK_BENCH_CPU)
	$(DOCKER) run --rm --init --cpuset-cpus=$(STACK_BENCH_CPU) $(DOCKER_ACCESS) $(DOCKER_IMAGE) \
		make bench-stack BENCH_FILTER='$(value BENCH_FILTER)' BENCH_RUSTFLAGS='$(value BENCH_RUSTFLAGS)'

docker-soak:
	@$(call cpuset_free,$(SOAK_CPUSET),SOAK_CPUSET)
	$(DOCKER) run --rm --init --cpuset-cpus=$(SOAK_CPUSET) $(DOCKER_ACCESS) $(DOCKER_IMAGE) \
		make soak SOAK_SECONDS=$(SOAK_SECONDS) SOAK_SEED=$(SOAK_SEED)

docker-fuzz:
	$(DOCKER_RUN) make fuzz $(FUZZ_VARS)

docker-binance-image:
	$(DOCKER) build -t $(BINANCE_IMAGE) --build-arg BASE=$(DOCKER_IMAGE) -f docker/binance.Dockerfile docker

# Live run against Binance's public stream; needs internet. The image adds
# nftables for the NAT. Example: make docker-binance BINANCE_SECONDS=30.
docker-binance: docker-binance-image
	$(DOCKER) run --rm --init --sysctl net.ipv4.ip_forward=1 $(DOCKER_DPDK) $(BINANCE_IMAGE) \
		make binance BINANCE_SECONDS='$(BINANCE_SECONDS)' BINANCE_HOST='$(BINANCE_HOST)' \
		BINANCE_PORT='$(BINANCE_PORT)' BINANCE_PATH='$(BINANCE_PATH)' BINANCE_PRINT='$(BINANCE_PRINT)'

docker-known-bugs:
	@$(CHECK_PACKETDRILL_CPUSET)
	$(DOCKER_MAKE_TEST) known-bugs TEST_TIMEOUT=$(TEST_TIMEOUT) KNOWN_BUGS_PKT_TIMEOUT=$(KNOWN_BUGS_PKT_TIMEOUT)

# Bounded on the host (no timeout(1) on macOS): the build runs in the
# background; after AUTOBAHN_IMAGE_TIMEOUT s, or on INT/TERM/HUP, stop sends it
# SIGTERM, then SIGKILL if it is still alive 10 s later. The shell reaps the
# finished build while it sleeps, so kill -0 then fails.
docker-autobahn-image:
	@set -u; pid=; \
	stop() { \
		kill $$pid 2>/dev/null; i=0; \
		while kill -0 $$pid 2>/dev/null && [ $$i -lt 10 ]; do sleep 1; i=$$((i + 1)); done; \
		kill -KILL $$pid 2>/dev/null; wait $$pid; \
	}; \
	trap '[ -z "$$pid" ] || stop; exit 130' INT TERM HUP; \
	$(DOCKER) build --platform linux/arm64 -t $(AUTOBAHN_IMAGE) - < docker/autobahn.Dockerfile & pid=$$!; \
	deadline=$$(( $$(date +%s) + $(AUTOBAHN_IMAGE_TIMEOUT) )); \
	while kill -0 $$pid 2>/dev/null; do \
		if [ "$$(date +%s)" -ge $$deadline ]; then \
			echo "docker-autobahn-image: build not done within $(AUTOBAHN_IMAGE_TIMEOUT) s; stopping it" >&2; \
			stop; exit 1; \
		fi; \
		sleep 1; \
	done; \
	wait $$pid

# Once per role, server (wstest fuzzingclient against `ws-autobahn server`) then
# client (`ws-autobahn client` against wstest fuzzingserver), each in a fresh
# autobahn/run/<role>/: Zhida container C (driver + tester) and Autobahn
# container A (wstest, in C's netns), both detached; see docker/README.md. A role
# passes only if C exited 0 within AUTOBAHN_TIMEOUT + 60 s, A ended within 30 s
# of C without being killed, wstest's status in autobahn/run/<role>/done is 0,
# every docker inspect succeeded and both containers were removed, neither still
# running. Exit 0 only if both roles pass.
docker-autobahn: docker-autobahn-image
	@set -u; \
	$(CHECK_CPUSETS); \
	lock=autobahn/run.lock; \
	if ! mkdir $$lock 2>/dev/null; then \
		echo "docker-autobahn: lock $(CURDIR)/$$lock exists: another run in this checkout, or a stale lock (remove it by hand)" >&2; \
		exit 1; \
	fi; \
	c=; a=; mode=; \
	say() { echo "docker-autobahn: $$*" >&2; }; \
	remove() { \
		removed=0; \
		for name in $$c $$a; do \
			if ! st=$$($(DOCKER) inspect -f '{{.State.Running}}' $$name 2>&1); then \
				say "$$mode: inspecting $$name for removal failed: $$st"; removed=1; \
			elif [ "$$st" = true ] && [ "$$1" = 0 ]; then \
				say "$$mode: container $$name still running at removal"; removed=1; \
			fi; \
			if ! $(DOCKER) rm -f $$name >/dev/null; then \
				say "$$mode: failed to remove container $$name"; removed=1; \
			fi; \
		done; \
		c=; a=; \
		return $$removed; \
	}; \
	cleanup() { \
		rc=$$?; \
		remove $$rc || rc=1; \
		rmdir $$lock || rc=1; \
		exit $$rc; \
	}; \
	trap cleanup EXIT; trap 'exit 130' INT TERM HUP; \
	watch() { \
		while :; do \
			if ! st=$$($(DOCKER) inspect -f '{{.State.Running}}' $$1 2>&1); then \
				say "$$mode: inspecting $$1 failed: $$st"; failed="$$failed inspect"; return; \
			fi; \
			[ "$$st" = true ] || return; \
			if [ "$$(date +%s)" -ge "$$2" ]; then \
				say "$$mode: $$4 container still running $$3; killing $$5"; \
				$(DOCKER) kill $$5 >/dev/null 2>&1; failed="$$failed killed-$$4"; return; \
			fi; \
			sleep 1; \
		done; \
	}; \
	role() { \
		mode=$$1; shift; \
		run=autobahn/run/$$mode; \
		rm -rf $$run && mkdir -p $$run || return 1; \
		start=$$(date +%s); failed=; \
		c=zhida-autobahn-c-$$mode-$$$$; \
		$(DOCKER) run -d --name $$c $(DOCKER_DPDK) -e AUTOBAHN_TIMEOUT=$(AUTOBAHN_TIMEOUT) \
			$(DOCKER_IMAGE) timeout --kill-after=10 $(AUTOBAHN_TIMEOUT) \
			target/release/ws-autobahn $$mode "$$@" \
			-- autobahn/zhida-tester.sh $$mode >/dev/null || { remove 1; return 1; }; \
		a=zhida-autobahn-a-$$mode-$$$$; \
		$(DOCKER) run -d --name $$a --network container:$$c --cpuset-cpus=$(AUTOBAHN_CPUSET) \
			-v "$(CURDIR)/autobahn:/work/autobahn" -w /work -e AUTOBAHN_TIMEOUT=$(AUTOBAHN_TIMEOUT) \
			$(AUTOBAHN_IMAGE) sh autobahn/peer.sh $$mode >/dev/null || { remove 1; return 1; }; \
		watch $$c $$(( start + $(AUTOBAHN_TIMEOUT) + 60 )) "$(AUTOBAHN_TIMEOUT) + 60 s after start" zhida "$$c $$a"; \
		driver=$$($(DOCKER) inspect -f '{{.State.ExitCode}}' $$c 2>/dev/null || echo unknown); \
		watch $$a $$(( $$(date +%s) + 30 )) "30 s after the driver" autobahn $$a; \
		$(DOCKER) logs $$c > $$run/zhida.log 2>&1 || failed="$$failed logs"; \
		$(DOCKER) logs $$a > $$run/autobahn.log 2>&1 || failed="$$failed logs"; \
		peer=$$(cat $$run/done 2>/dev/null || echo missing); \
		cat $$run/zhida.log; \
		[ "$$driver" = 0 ] && [ "$$peer" = 0 ] && [ -z "$$failed" ]; verdict=$$?; \
		remove $$verdict || { verdict=1; failed="$$failed remove"; }; \
		[ $$verdict = 0 ] && result=PASS || result=FAIL; \
		echo "docker-autobahn: $$mode $$result: $$(( $$(date +%s) - start )) s, driver exit $$driver, wstest $$peer, failures:$${failed:- none} (logs in $$run/)"; \
		return $$verdict; \
	}; \
	$(DOCKER_RUN) $(TIMEOUT) cargo build --release --locked -p ws-autobahn || exit 1; \
	role server --expect-connections $(AUTOBAHN_CASES); server=$$?; \
	role client --expect-cases $(AUTOBAHN_CASES); client=$$?; \
	[ $$server = 0 ] && [ $$client = 0 ]
