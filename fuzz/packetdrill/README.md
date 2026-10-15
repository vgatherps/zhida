# packetdrill suite

packetdrill plays a Linux TCP client against Zhida's echo server (`tap-echo`, smoltcp 0.14.0
over a DPDK net_tap Port). Each script states the Linux-interop behavior it proves and the
smoltcp code (`src/socket/tcp.rs` unless noted) that defines every Zhida packet.

tap-echo reads `random_seed` from `/dev/urandom` on each run. Zhida's ISN is
the low 32 bits of keyed SipHash-2-4 over the local/remote addresses and ports,
plus the interface's 4 µs clock, wrapping at 32 bits (RFC 6528 section 3).
The interface draws its 128-bit key once from its seeded PRNG; Linux v6.12
uses the same hash-plus-clock design with a 64 ns tick.

The image applies `docker/packetdrill-relearn-isn.patch` to pinned packetdrill
83f72d3. A new inbound passive SYN permits learning its SYN-ACK's ISN, mapped
to script 0, only when the live SYN-ACK acknowledges that SYN's live sequence
plus one. The script and live server ISNs change together after the SYN-ACK
is sniffed. Server sequences and client ACKs after it use offsets from that ISN.
A duplicate SYN or timed SYN-ACK retransmission in the same unfinished
handshake keeps the mapping and must reuse the ISN. Challenge ACKs and
TIME-WAIT ACKs keep the old mapping until that matching SYN-ACK appears.
After a stray SYN, a SYN-ACK acknowledging the original handshake's SYN
uses the learned ISN; retransmitting that original SYN cannot enable relearning.
Client SYN sequences stay absolute; other client sequences keep packetdrill's
original base (the first client ISN).

## Running

- `make docker-test` (native: `make test-packetdrill`, part of `make test`) builds `tap-echo`
  and the shim `target/fuzz/zhida_shim.so`, then `run.sh` runs `scripts/*.pkt` (must exit 0) and
  `selftest/*.pkt` (exit 0 with `// expect-pass`, or fail the way its
  `// expect-refused:` or `// expect-error:` header says). Container flags and
  details: docker/README.md.
- tap-echo runs on CPU `ZHIDA_CPU` and packetdrill alone on `PACKETDRILL_CPU` (both
  required; the Makefile passes `PACKETDRILL_ZHIDA_CPUSET`, default 7, and
  `PACKETDRILL_CPUSET`, default 2, both off CPU 0 where the gates' builds run), so the
  timing checks see neither side wait for a CPU. The shim fails the run unless
  packetdrill may run only on `PACKETDRILL_CPU`. run.sh keeps both CPUs awake with
  SCHED_IDLE busy loops (a sleep on an idle vCPU of the Docker VM ends up to 10 ms late).
  Those loops yield only within their own container, so two runs must not share the CPUs:
  the make targets run the suite under `locked.sh`, one host-wide flock (a file on a shared
  Docker volume) that a second run waits for and that is held until the run's last process
  exits; details: docker/README.md.
  Results are valid only while no bench or other heavy container saturates the host (the
  whole Docker VM then stalls).
- One script: inside a container with the Makefile's `DOCKER_ACCESS` flags and
  `--cpuset-cpus=0,2,7` (as `DOCKER_MAKE_TEST`), after one `make packetdrill-build`:
  `ZHIDA_CPU=7 PACKETDRILL_CPU=2 taskset -c 0 fuzz/packetdrill/run.sh fuzz/packetdrill/scripts/X.pkt`.
- Each script runs in a fresh `tap-echo` (default one socket listening on port 8080) with packetdrill as its
  tester, `--strict_segments` (one expected line is one Zhida segment), bounded by
  `timeout PACKETDRILL_TIMEOUT` (default 60 s; `make known-bugs` passes 15 s).
- Scripts are packet-only: run.sh refuses backquotes, `%{`, `/*` and `=` outside `//`
  comment lines and any line that is not blank, a `//` comment or one TCP packet event. A
  packet's time may be written as packetdrill's lexer reads numbers, `+.1` included; flags
  `-` mean a segment with none.

## `// tap-echo:` header

A script may carry one line `// tap-echo: <flags>` with `--listeners N` (positive integer,
default 1), `--buffer N` (each
connection's RX and TX buffer, 1 to 1073741824 bytes, default 131072) and `--close-after N`
(Zhida echoes N bytes per connection, then sends FIN after them and reads and discards
whatever the peer sends; a peer FIN first closes as without it). run.sh passes the flags to
`tap-echo` before `--`. Another flag, a repeated flag or a second such line refuses the
script unrun (`selftest/tap-echo-*.pkt`). The `--buffer` limit, 2^30, is the largest
receive buffer smoltcp accepts; it advertises window scale 14 for it.

## `// tolerance_usecs:` header

run.sh passes packetdrill `--tolerance_usecs=25000` by default, allowing for laptop VM
scheduling delays. A script may
carry one line `// tolerance_usecs: N`, where N is a positive integer in usecs, to override
the default. An invalid value or a second such line refuses the script unrun
(`selftest/tolerance-usecs-non-numeric.pkt`, `selftest/tolerance-usecs-zero.pkt` and
`selftest/tolerance-usecs-repeat.pkt`).

## Known bugs

A script that reproduces a Zhida bug goes in `known-bugs/`, outside the default run. Its
header states the bug, the expected packets, the assumed fix and any Linux differences, and
it passes once the bug is fixed that way. `make docker-known-bugs` (native: `make known-bugs`)
runs each such script alone, with the other repros listed in `fuzz/known-bugs.txt`, and exits
nonzero while any bug reproduces (docker/README.md). Each script gets 15 s by default
(`KNOWN_BUGS_PKT_TIMEOUT`); lock waiting is outside the per-repro outer timeout, and a
lock-wait expiry is `INFRA`.

## SYN and TIME-WAIT handling

- Parsed SYNs on synchronized connections receive a challenge ACK before ACK validation
  (RFC 5961 4.2), including SYN|ACK with an ACK below SND.UNA. Exact tuples take precedence
  over listeners; duplicate SYNs in SYN-RECEIVED resend the original SYN-ACK immediately.
  Among accepting listeners, the lowest socket slot wins.
- Challenge ACKs, pure ACK replies and duplicate-SYN SYN-ACK resends share a 500 ms
  per-socket limit; non-SYN data and FIN replies are exempt and consume no allowance.
- Zhida does not negotiate or emit TCP timestamps and performs no PAWS checks.
- In TIME-WAIT, an empty segment without SYN/RST/FIN at RCV.NXT silently restarts the
  timer, regardless of the ACK flag. Other non-RST, non-SYN segments restart it only
  when ACK is set and receive an ACK through the shared reply rule. Non-SYN data and
  FIN replies bypass the 500 ms limit; empty replies use it.
- A TIME-WAIT SYN or SYN+FIN without ACK reopens when SEG.SEQ is after RCV.NXT and an
  accepting listener exists. The old socket closes and clears its tuple; the listener
  answers SYN-ACK with its own ISN. Without a listener, that SYN keeps TIME-WAIT and
  gets an ACK without rate limiting. Other TIME-WAIT SYNs get a rate-limited challenge
  ACK and restart the timer only when ACK is set.
- `syn-in-time-wait-reopen.pkt` and the FreeBSD pure-SYN right-edge/outside-right scripts use
  `--listeners 2` and assert immediate reopening. EchoServer relistens only Closed sockets,
  so a second socket is needed while the first is in TIME-WAIT. `syn-in-time-wait.pkt`
  uses one socket and checks ACK, exact-sequence RST, then a successful retried SYN.

## smoltcp vs Linux differences (RFC-allowed; asserted as smoltcp behaves unless noted)

- When the delayed-ACK timer expires, the ACK segment carries whatever data fits the
  remaining congestion window, even less than one MSS, the same sizing a normal send uses.
  No script asserts this. `scripts/data-ack-clocking.pkt` uses MSS 1024 and a 2048-byte
  peer window to send whole segments as ACKs slide the window.
- Cubic is the default controller. Its initial cwnd is 1 MiB unless the socket sets
  another value with `set_initial_window`; Linux starts with 10 segments (RFC 6928).
  `scripts/google-fr-4pkt.pkt` sends all four 1460-byte echoes before the first ACK.
- No Nagle: Zhida always sends available data immediately (TCP_NODELAY), regardless of
  segment size or data in flight. Linux's default Nagle (Minshall's variant) holds a short
  segment only while an earlier short segment is unacknowledged.
  `scripts/handshake-no-options.pkt`, `handshake-small-mss.pkt`.
- The RTO is fixed per socket, 300 ms by default (`set_rto`), not derived from RTT
  samples; each expiry doubles it, up to 60 s, until SND.UNA advances. RFC 6298 2.4 says it
  SHOULD be at least 1 s; Linux's minimum is 200 ms (TCP_RTO_MIN). `scripts/rto-backoff.pkt`.
- If the peer closes its window while data is in flight, an RTO sends a one-byte
  probe, and further probes follow the same RTO and backoff. Linux v6.12's
  [tcp_retransmit_timer](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp_timer.c#L547-L585)
  instead retransmits the queued skb with `tcp_retransmit_skb(sk, skb, 1)`.
  `tcp.rs::test_zero_window_probe_after_retransmit_timeout` pins the one-byte behavior.
- Received SACK blocks are ignored: the socket only sets them on its own replies.
  Duplicate ACKs trigger fast retransmit, with Cubic controlling cwnd;
  Linux runs SACK-based recovery (RFC 6675). `scripts/fast-retransmit.pkt`.
- TIME-WAIT lasts 10 s (CLOSE_DELAY, 301, 394-397), Linux 60 s. `scripts/time-wait.pkt`.

## Scripts

- `handshake-linux-options.pkt`: SYN-ACK options for Linux's default SYN; the bare ACK
  completes the handshake; RST closes.
- `echo-and-close.pkt`: echo with piggybacked delayed ACK, close after the client's FIN,
  relisten, RST close.
- `fin-with-data.pkt`: data carrying FIN: echo, ACK of FIN and Zhida's FIN in one segment.
- `data-after-fin.pkt` (K7): payload past the peer's FIN is discarded silently
  (RFC 9293 3.10.7.4; Linux instead resets, TCPABORTONDATA) while its ACK retires the
  echo; the next ACK closes LAST-ACK, and a new SYN opens another connection.
- `peer-window-limit.pkt`: Zhida sends exactly the client's scaled window, the rest after
  the window slides.
- `peer-zero-window.pkt`: a pure ACK after 10 ms, the first zero-window probe one RTO
  (300 ms) after the data, then probes 600 ms and 1.2 s apart; data released by the window
  update. It pins 4000 usecs because the 10 ms ACK is finer than the 25 ms default can
  distinguish from an immediate ACK.
- `zhida-zero-window.pkt` (`--buffer 1024`): Zhida's window closes to 0, it answers the
  client's probe with window 0, and its reopened window rides on the drained echo. It pins
  4000 usecs because the 10 ms ACK is finer than the 25 ms default can distinguish from an
  immediate ACK.
- `zhida-fin-first.pkt` (`--close-after 10`): Zhida's FIN after 10 bytes; data received
  in FIN-WAIT-2 is ACKed and discarded with the window kept open; the client's FIN is ACKed
  and moves Zhida to TIME-WAIT (re-ACK of a retransmitted FIN). It pins 4000 usecs because
  the 10 ms ACK is finer than the 25 ms default can distinguish from an immediate ACK.
- `simultaneous-close.pkt` (`--close-after 10`): crossing FINs, Closing, then TIME-WAIT (no
  FIN retransmit, re-ACK of a retransmitted FIN).
- `time-wait.pkt` (`--close-after 10`): TIME-WAIT re-ACKs a retransmitted FIN 9.5 s
  after entry, a second one shows the timer restarted, and 10.5 s after that restart a new
  SYN gets a SYN-ACK.
- `rst-in-window.pkt`: RST at RCV.NXT closes; another in-window RST gets a challenge ACK,
  then more data echoes before an exact-sequence reset.
- `rst-out-of-window.pkt`: an RST exactly at the advertised window's right edge gets a
  challenge ACK; an RST below the last ACK sent is ignored; data keeps echoing.
- `rst-syn-received.pkt`: an RST answering the SYN-ACK returns the listener to Listen;
  the next SYN gets a SYN-ACK with a fresh ISN.
- `syn-no-ts-then-rst.pkt`: after a SYN without window scaling or SACK and an RST in
  SYN-RECEIVED, the next SYN negotiates window scaling and SACK. Both SYNs omit timestamps.
- `handshake-no-options.pkt`: a SYN without options gets a SYN-ACK with only MSS; Zhida
  then sends to the default MSS 536 with an unscaled window.
- `handshake-small-mss.pkt`: a client MSS of 536 limits Zhida's segments to 536 bytes;
  the SYN-ACK announces 1460.
- `synack-retransmit.pkt`: with the handshake ACK lost, the SYN-ACK is retransmitted after
  300 ms and 600 ms later; the late ACK completes the handshake and data echoes.
- `delayed-ack.pkt`: an ACK Zhida cannot piggyback waits 10 ms, a second segment does not
  restart the timer, and more than one MSS unacknowledged gets an immediate ACK. It pins
  4000 usecs because the 10 ms checks are finer than the 25 ms default can distinguish
  from immediate ACKs.
- `data-ack-clocking.pkt`: with the 2048-byte peer window full, further echoes wait for
  the client's ACK, which slides the window and releases them. Cubic's initial cwnd
  is 1 MiB. It pins 4000 usecs because its
  10 ms pure-ACK checks are finer than the 25 ms default can distinguish from immediate
  ACKs.
- `out-of-order.pkt`: an out-of-order segment gets an immediate duplicate ACK with a SACK
  block; the segment filling the hole gets an ACK of both, followed by the echo.
- `old-ack-keeps-payload.pkt`: a reordered gap-fill with an old ACK within the Linux
  ACK-age bound is ACKed and echoed; its zero-window advertisement leaves
  the following segment's window open.
- `fast-retransmit.pkt`: the third duplicate ACK, not the first or second, triggers a
  retransmission of the first unacknowledged segment. Cubic sets ssthresh to 70% of
  the 6144-byte flight, rounded down to 4300 bytes, and the full ACK deflates cwnd
  to that value. Four 1024-byte echoes and 204 bytes of the fifth fit before another
  ACK. It pins 4000 usecs because its duplicate-ACK timing checks
  are finer than the 25 ms default can distinguish.
- `rto-backoff.pkt`: unacknowledged data is retransmitted at 300 ms, then 600 ms and 1.2 s
  after that; the client's ACK stops it and the connection continues.
- `seq-wrap.pkt`: the client's sequence numbers wrap past 2^32; Zhida ACKs, echoes and
  closes across the wrap.
- `selftest/split-segment.pkt`: expects one 1072-byte segment where Zhida sends 536, 536
  and 376; run.sh's `--strict_segments` makes packetdrill report the first rather than join
  them.
- `selftest/relative-time-leading-dot.pkt`: `+.1` and `+.05` lines run as 0.1 s and 0.05 s
  after the previous event: packetdrill reports the echo early against about 0.15 s.
- `selftest/comment-special-chars.pkt`: `//` comment lines holding a backquote, `%{`, `/*`
  and `=` do not refuse a script; it runs and packetdrill reports its wrong SYN-ACK window.
- `selftest/relearn-isn.pkt`: two connections on one 4-tuple, each with a duplicate
  SYN and SYN-ACK. Both handshake ISNs map to 0; second-connection data and ACKs
  use the new mapping. Fails on the second SYN-ACK without the image's patch.
- `selftest/relearn-isn-same-client-seq.pkt`: an RST ends a half-open connection;
  a new SYN with the same client ISN learns a fresh server ISN, then a duplicate
  SYN must reuse it. Also fails without the patch.
- `selftest/synack-isn-mismatch.pkt`: expects ISN + 1 on a duplicate SYN's
  SYN-ACK; packetdrill must reject it, preserving the same-handshake ISN check.
- `selftest/synack-isn-mismatch-stray-syn.pkt`: injects SYN 5000 into an
  unfinished handshake, retransmits SYN 0, then wrongly expects ISN + 1.
  Must exit 1 on both patched and unpatched packetdrill.
- `selftest/relearn-isn-nonzero-client-seq.pkt`: starts at client ISN 1000,
  ignores a stray SYN, checks the original SYN-ACK retransmission, then reopens
  at client ISN 5000. SYN-ACK ACKs are absolute; data and ACKs after that keep
  the first client ISN as their base.

## Upstream suites

Standard packetdrill scripts adapted to this runner: `freebsd-*.pkt` and `google-*.pkt`, in
`scripts/` (part of the default run). Each header names the upstream file, commit and license
and lists every change. The five `freebsd-rcv-fin-time-wait-*` scripts replace FreeBSD's
silence with Linux v6.12's ACK of a FIN without ACK. RSTs at exactly RCV.NXT+RCV.WND in
ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSING and LAST-ACK expect a challenge ACK,
following Linux v6.12 tcp_sequence (net/ipv4/tcp_input.c); upstream FreeBSD expects
silence there. SYN-RECEIVED excludes the right edge: its named right-edge script sends
an RST one byte inside the window and expects a challenge ACK. In TIME-WAIT an RST
at the right edge draws no challenge ACK and TIME-WAIT keeps ACKing a
retransmitted FIN. A SYN+FIN segment around RCV.NXT in TIME-WAIT draws the same plain ACK a
lone SYN would. Each changed script records its difference.

- freebsd-net/tcp-testsuite 04b8c73fc5081fe3792f1bed9168c9b22aaedddb, BSD-2-Clause (each
  file keeps the notice): `state-event-engine`, IPv4, the RFC 5961 (`secure`) variants, in
  the states tap-echo reaches. 91 scripts.
- google/packetdrill 83f72d3f9085d0e26eb4d206fe4d7cfab5b6d872 (the image's packetdrill),
  GPL-2.0-or-later: `gtests/net/tcp` `validate`, `close` and `fast_retransmit`. 3 scripts.

`freebsd-rcv-syn-ack-time-wait-using-shutdown-outside-left-secure.pkt` and
`freebsd-rcv-syn-ack-time-wait-using-shutdown-outside-right-secure.pkt` check that SYN|ACKs
get a challenge ACK before ACK validation, including ACKs below SND.UNA, and that TIME-WAIT
then ACKs the retransmitted FIN. `test_syn_in_time_wait_challenge_ack` covers these
SYN-in-TIME-WAIT challenges; it does not exercise old-ACK processing.

Translation (each header says which apply):

- Zhida is a passive echo server. An upstream active open (connect) becomes the client's
  SYN carrying the options upstream's peer sent, so the same options are negotiated;
  socket/bind/listen/accept go; shutdown(SHUT_WR) becomes `--close-after 0` (Zhida's FIN
  right after the handshake); a close() Zhida would make first in ESTABLISHED becomes the
  client closing first; write() becomes the echo of data the client sends.
- Socket-state checks become packets: getsockopt(SO_ERROR) = ECONNRESET or no SYN_RCVD
  socket (sockstat) becomes "0.1 s later a SYN on the same 4-tuple gets a SYN-ACK" (a
  surviving connection would not answer it); sockstat showing TIME-WAIT becomes "1.1 s later
  the client's retransmitted FIN gets an ACK" (a listener would answer RST). FIN replies
  are exempt from the shared 500 ms limit on pure ACKs and SYN challenge ACKs
  (`out_of_window_reply`). The acceptable TIME-WAIT SYN scripts instead assert Linux
  reopening with a SYN-ACK from a second listener and drop upstream's old-connection FIN
  checks. ioctl(SIOCINQ) and read become whether data is echoed.
- Dropped: sysctl, sockstat and tcpdrop commands, fcntl, getsockopt(SO_RCVBUF),
  `--tolerance_usecs` (run.sh supplies it), FreeBSD `#ifdef FreeBSD` branches (the
  `#ifdef STANDARD` branch is kept). The first event moves to time 0 (packetdrill requires it).
- Configuration differences, set in the script: `--buffer 65535` makes Zhida's receive
  window 65535 unscaled, as FreeBSD's advertised window; FreeBSD's RCV.WND is 65700 (its
  65536-byte buffer rounded up to whole MSS), so edge sequence numbers are recomputed from
  65535. Zhida's SYN-ACK options are written in its own encoding (option order and
  padding) and window scale (2 for the default 128 KiB buffer; Linux 8). Upstream's
  application timing becomes tap-echo's (it closes and echoes at once). Setup only: in
  FIN-WAIT-1 Zhida answers the client's FIN with a pure ACK, FreeBSD with FIN|ACK; both
  reach CLOSING.

A failing script goes to `known-bugs/` when upstream's expectation is RFC 9293's or RFC
5961's or Linux's (Zhida follows Linux on protocol edge cases). It is not kept when
upstream asserts a behavior that neither the RFCs require nor current Linux shows while
Zhida does what they do:

| Upstream script | Upstream expects | Zhida, RFC 9293 and Linux |
|---|---|---|
| `rcv-rst-time-wait-using-shutdown-left-edge-secure`, `rcv-rst-ack-time-wait-using-shutdown-left-edge-secure` | RST at RCV.NXT leaves TIME-WAIT alive (RFC 1337) | TIME-WAIT closes (3.10.7.4; Linux tcp_rfc1337 = 0) |
| `rcv-syn-ack-with-data-listen`, `rcv-syn-ack-without-data-listen` | SYN\|ACK to a listener dropped | RST `<SEQ=SEG.ACK>` (3.10.7.2; Linux tcp_rcv_state_process) |
| `ts_recent/invalid_ack` | ACK of unsent data dropped silently | challenge ACK (3.10.7.4 fifth check, RFC 5961 5.2; Linux tcp_ack) |

Not adapted:

- FreeBSD: `*-ipv6` (Zhida is IPv4 only); `*-insecure-*` (RFC 793 RST/SYN rules selected by
  FreeBSD's `insecure_rst`/`insecure_syn`; no such switch here, the secure twin is adapted);
  `rcv-*-syn-sent`, `*-via-syn-sent-*`, `snd-syn`, `rcv-icmp` (Zhida's active open; tap-echo
  only listens); `rcv-*-closed` (a bound socket that does not listen; tap-echo always listens
  on the port packetdrill targets); `rcv-rst-close-wait`, `rcv-syn-close-wait` (tap-echo
  closes as soon as the peer's FIN arrives with nothing to echo, so Zhida never stays in
  CLOSE-WAIT); `rcv-syn-fin-listen-*-dropping-disabled` (FreeBSD's `drop_synfin = 0`; the
  dropping-enabled twin matches Linux, which discards SYN|FIN in LISTEN, and is adapted);
  `rcv-syn-fin-time-wait-*-nodrop` (same STANDARD branch as the adapted `-drop` twin);
  `rcv-data-segments` (the application only peeks, MSG_PEEK, while tap-echo reads and
  echoes, changing every ACK and window); `socket-api`, `fast-open`, `tcp-over-udp` (socket
  API, TCP Fast Open, UDP encapsulation); `rcv-rst-ack-syn-rcvd` (16 ACK-field variants of
  `rcv-rst-syn-rcvd`).
- google: `close-local-close-then-remote-fin`, `close-on-syn-sent`, `blocking-connect`
  (Zhida's active open; the close sequences are covered by the FreeBSD FIN-WAIT scripts);
  `ts_recent/fin_tsval` and `reset_tsval` (the application closes 1 s later, or with unread
  data to force an RST; tap-echo can do neither); `blocking-*` (the application's blocking
  calls); `epoll`, `zerocopy`, `sendfile`, `splice`, `ioctl`, `inq`, `tcp_info`,
  `syscall_bad_arg`, `notsent_lowat`, `eor`, `nagle`, `mss`, `shutdown`, `user_timeout`,
  `md5`, `fastopen`, `timestamping` (socket options and calls tap-echo does not make).
  Sender-side categories (`slow_start`, `fast_recovery`, `limited_transmit`, `sack`,
  `cwnd_moderation`, `cubic`, `ecn`, `gro`, `mtu_probe`) assume Linux's ten-segment initial
  window and TSO bursts and assert tcp_info; `fast_retransmit/fr-4pkt` is adapted as their
  representative.
