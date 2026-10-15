use std::time::{Duration, Instant};

use binance_feed::Clock;
use dpdk_smoltcp::smoltcp::socket::tcp::{self, State};
use dpdk_smoltcp::{Stack, TcpHandle, UdpConfig, UdpDatagram, UdpHandle, UdpSendError};
use sockperf_wire::sockperf::{reply, validate_udp, Framer, MAX_MESSAGE};

use crate::args::Server;
use crate::{line, nic, stopped, Turns};

#[derive(Default)]
struct Stamps {
    seen: u64,
    stamped: u64,
    first: u64,
    last: u64,
    decreases: u64,
}

impl Stamps {
    fn observe(&mut self, stamp: u64, previous: &mut u64, enabled: bool) -> Result<(), String> {
        self.seen += 1;
        if stamp == 0 {
            return Ok(());
        }
        if !enabled {
            return Err(format!(
                "nonzero RX timestamp {stamp} with rx_timestamps disabled"
            ));
        }
        self.stamped += 1;
        if self.first == 0 {
            self.first = stamp;
        }
        self.last = stamp;
        if *previous != 0 && stamp < *previous {
            self.decreases += 1;
        }
        *previous = stamp;
        Ok(())
    }
}

#[derive(Default)]
struct Counts {
    received: u64,
    replies: u64,
    malformed: u64,
    accepted: u64,
    closed: u64,
    stamps: Stamps,
}

struct UdpSlot {
    handle: UdpHandle,
    previous: u64,
    pending: Option<UdpDatagram>,
    pending_error: Option<UdpSendError>,
}

struct TcpSlot {
    handle: TcpHandle,
    framer: Framer,
    output: Vec<u8>,
    sent: usize,
    active: bool,
    previous: u64,
}

impl TcpSlot {
    fn flush(&mut self, stack: &mut Stack) -> Result<(), String> {
        if self.sent < self.output.len() && stack.tcp(&self.handle).can_send() {
            let n = stack
                .tcp_mut(&self.handle)
                .send_slice(&self.output[self.sent..])
                .map_err(|e| format!("TCP send: {e:?}"))?;
            self.sent += n;
        }
        if self.sent == self.output.len() {
            self.output.clear();
            self.sent = 0;
        }
        Ok(())
    }

    fn receive(
        &mut self,
        stack: &mut Stack,
        counts: &mut Counts,
        stamps: bool,
    ) -> Result<(), String> {
        let mut malformed = false;
        let mut error = None;
        while stack.tcp(&self.handle).can_recv() {
            let frame = stack
                .tcp_mut(&self.handle)
                .recv()
                .map_err(|e| format!("TCP receive: {e:?}"))?
                .expect("can_recv: data is queued");
            if let Err(e) = counts.stamps.observe(frame.rx_timestamp(), &mut self.previous, stamps) {
                error = Some(e);
            }
            if malformed {
                continue;
            }
            let result = self.framer.push(frame.payload(), |message| {
                counts.received += 1;
                if reply(message) {
                    self.output.extend_from_slice(message);
                    counts.replies += 1;
                }
            });
            malformed = result.is_err();
        }
        if let Some(error) = error {
            return Err(error);
        }
        if malformed {
            counts.malformed += 1;
            stack.tcp_mut(&self.handle).abort();
            self.output.clear();
            self.sent = 0;
        }
        Ok(())
    }

    fn visit(
        &mut self,
        stack: &mut Stack,
        counts: &mut Counts,
        port: u16,
        stamps: bool,
    ) -> Result<(), String> {
        let state = stack.tcp(&self.handle).state();
        if !self.active && !matches!(state, State::Closed | State::Listen) {
            self.active = true;
            self.framer.reset();
            counts.accepted += 1;
        }
        if self.active && matches!(state, State::Listen | State::Closed) {
            counts.closed += 1;
            self.active = false;
            self.framer.reset();
            self.output.clear();
            self.sent = 0;
        }
        if state == State::Closed {
            stack
                .listen(&self.handle, port)
                .map_err(|e| format!("TCP re-listen: {e:?}"))?;
            return Ok(());
        }
        self.flush(stack)?;
        if !self.output.is_empty() {
            return Ok(());
        }
        self.receive(stack, counts, stamps)?;
        self.flush(stack)?;
        if stack.tcp(&self.handle).state() == State::CloseWait
            && self.output.is_empty()
            && !stack.tcp(&self.handle).can_recv()
        {
            stack.tcp_mut(&self.handle).close();
        }
        Ok(())
    }
}

fn report(
    stack: &Stack,
    turns: &Turns,
    udp: &[UdpSlot],
    tcp: &[TcpSlot],
    u: &Counts,
    t: &Counts,
    port: u16,
    stamps: bool,
    final_report: bool,
) -> Result<(), String> {
    line("report", if final_report { "final" } else { "periodic" });
    line(
        "udp",
        format_args!(
            "received={} replies={} malformed={}",
            u.received, u.replies, u.malformed
        ),
    );
    line(
        "tcp",
        format_args!(
            "received={} replies={} malformed={} accepted={} closed={}",
            t.received, t.replies, t.malformed, t.accepted, t.closed
        ),
    );
    if stamps {
        line(
            "udp_timestamps",
            format_args!(
                "datagrams={} stamped={} first={} last={} decreases={}",
                u.stamps.seen, u.stamps.stamped, u.stamps.first, u.stamps.last, u.stamps.decreases
            ),
        );
        line(
            "tcp_timestamps",
            format_args!(
                "segments={} stamped={} first={} last={} decreases={}",
                t.stamps.seen, t.stamps.stamped, t.stamps.first, t.stamps.last, t.stamps.decreases
            ),
        );
    }
    for slot in udp {
        line(
            "udp_socket",
            format_args!(
                "port={} pending={} {:?}",
                stack.udp(&slot.handle).config().port,
                usize::from(slot.pending.is_some()),
                stack.udp(&slot.handle).stats()
            ),
        );
    }
    for (i, slot) in tcp.iter().enumerate() {
        let socket = stack.tcp(&slot.handle);
        line(
            "tcp_socket",
            format_args!(
                "slot={i} state={} retransmits={} loss_events={} rx_refused_segments={}",
                socket.state(), socket.retransmits(), socket.loss_events(), socket.rx_refused_segments()
            ),
        );
    }
    line("udp_counters", format_args!("{:?}", stack.udp_counters()));
    turns.print();
    nic::print_eth_stats(port)
}

fn udp_visit(
    stack: &mut Stack,
    slot: &mut UdpSlot,
    counts: &mut Counts,
    stamps: bool,
    turns: &mut Turns,
) -> Result<(), String> {
    if let Some(datagram) = &slot.pending {
        match stack.udp_send(&slot.handle, Some(datagram.src()), datagram.payload()) {
            Ok(()) => {
                counts.replies += 1;
                slot.pending = None;
                slot.pending_error = None;
                turns.flush(stack)?;
            }
            Err(e @ (UdpSendError::WouldBlock | UdpSendError::NeighborPending)) => {
                slot.pending_error = Some(e);
                return Ok(());
            }
            Err(e) => return Err(format!("UDP reply: {e:?}")),
        }
    }
    while let Some(mut datagram) = stack.udp_mut(&slot.handle).recv() {
        counts.received += 1;
        counts
            .stamps
            .observe(datagram.rx_timestamp(), &mut slot.previous, stamps)?;
        if validate_udp(datagram.payload()).is_err() {
            counts.malformed += 1;
            continue;
        }
        if !reply(datagram.payload_mut()) {
            continue;
        }
        match stack.udp_send(&slot.handle, Some(datagram.src()), datagram.payload()) {
            Ok(()) => {}
            Err(e @ (UdpSendError::WouldBlock | UdpSendError::NeighborPending)) => {
                slot.pending = Some(datagram);
                slot.pending_error = Some(e);
                return Ok(());
            }
            Err(e) => return Err(format!("UDP reply: {e:?}")),
        }
        counts.replies += 1;
        turns.flush(stack)?;
    }
    Ok(())
}

pub fn run(
    stack: &mut Stack,
    args: &Server,
    port: u16,
    stamps: bool,
    turns: &mut Turns,
    clock: &Clock,
    start: Instant,
) -> Result<(), String> {
    let mut udp = Vec::new();
    let mut tcp = Vec::new();
    let mut u = Counts::default();
    let mut t = Counts::default();
    let stop =
        || stopped() || (args.seconds != 0 && start.elapsed() >= Duration::from_secs(args.seconds));
    let served = (|| {
        for &port in &args.udp_ports {
            let handle = stack
                .add_udp(UdpConfig {
                    port,
                    rx_queue: nic::UDP_QUEUE,
                    tx_checksum: true,
                    broadcast: false,
                })
                .map_err(|e| format!("UDP bind {port}: {e:?}"))?;
            udp.push(UdpSlot {
                handle,
                previous: 0,
                pending: None,
                pending_error: None,
            });
            line("udp_listen", port);
        }
        if let Some(port) = args.tcp_port {
            for _ in 0..args.tcp_connections {
                let socket = tcp::Config {
                    rx_capacity: MAX_MESSAGE, tx_capacity: MAX_MESSAGE, mss_cap: None,
                };
                let handle = stack.add_tcp(socket).map_err(|e| format!("TCP add: {e}"))?;
                stack
                    .listen(&handle, port)
                    .map_err(|e| format!("TCP listen {port}: {e:?}"))?;
                tcp.push(TcpSlot {
                    handle,
                    framer: Framer::new(MAX_MESSAGE),
                    output: Vec::new(),
                    sent: 0,
                    active: false,
                    previous: 0,
                });
            }
            line(
                "tcp_listen",
                format_args!("port={port} slots={}", args.tcp_connections),
            );
        }
        line("server", "ready");
        let mut last_report = Instant::now();
        while !stop() {
            turns.turn(stack, clock)?;
            for slot in &mut udp {
                udp_visit(stack, slot, &mut u, stamps, turns)?;
            }
            for slot in &mut tcp {
                slot.visit(stack, &mut t, args.tcp_port.unwrap(), stamps)?;
            }
            turns.send(stack)?;
            if last_report.elapsed() >= Duration::from_secs(args.report_seconds) {
                report(stack, turns, &udp, &tcp, &u, &t, port, stamps, false)?;
                last_report = Instant::now();
            }
        }
        Ok(())
    })();
    let closing = (|| {
        let close_start = Instant::now();
        loop {
            let mut waiting = 0usize;
            for slot in &mut tcp {
                let state = stack.tcp(&slot.handle).state();
                if matches!(state, State::Closed | State::TimeWait) {
                    if slot.active {
                        t.closed += 1;
                        slot.active = false;
                    }
                    continue;
                }
                slot.flush(stack)?;
                if slot.output.is_empty() {
                    stack.tcp_mut(&slot.handle).close();
                }
                waiting = waiting.checked_add(1).expect("TCP slot count overflow");
            }
            if waiting == 0 && turns.pending == 0 {
                return Ok(());
            }
            if close_start.elapsed() >= Duration::from_secs(5) {
                return Err(format!(
                    "TCP FIN close did not finish within 5 seconds: TCP slots still open={waiting} tx_pending={}",
                    turns.pending
                ));
            }
            turns.turn(stack, clock)?;
        }
    })();
    if served.is_err() {
        if let Err(e) = &closing {
            line("tcp_close_error", e);
        }
    }
    let reported = report(stack, turns, &udp, &tcp, &u, &t, port, stamps, true);
    let pending = match udp.iter().find(|slot| slot.pending.is_some()) {
        Some(slot) => Err(format!(
            "UDP reply to {} still pending at stop ({:?})",
            slot.pending.as_ref().unwrap().src(),
            slot.pending_error.as_ref().expect("pending UDP reply has a send error")
        )),
        None => Ok(()),
    };
    served.and(closing).and(reported).and(pending)
}
