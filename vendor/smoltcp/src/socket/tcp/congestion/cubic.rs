use crate::{socket::tcp::SmoothedRtt, time::Instant};

// Constants for the Cubic congestion control algorithm.
// See RFC 9438.
const BETA_CUBIC: f64 = 0.7;
const C: f64 = 0.4;
// RFC 9438 §4.3: α_cubic = 3(1-β)/(1+β). ~0.5294 for β=0.7.
const ALPHA_CUBIC: f64 = 3.0 * (1.0 - BETA_CUBIC) / (1.0 + BETA_CUBIC);

const DEFAULT_MSS: usize = 1024;

#[derive(Debug)]
#[repr(C)]
pub struct Cubic {
    cwnd: usize,
    recovery_start: Instant,
    idle_start: Instant, // RFC 9438 §4.2: when in-flight last hit 0
    ssthresh: u32,
    rwnd: u32,
    mss: u16,
    recovery_started: bool,
    idle: bool,
    in_fast_recovery: bool,
    // Set on RTO, cleared when new data is ACKed. While set, further RTOs
    // are retransmissions of the same segment and must not reduce ssthresh
    // again (RFC 5681 section 3.1).
    in_rto_recovery: bool,
    // False until the first set_remote_window; until then `rwnd` is the
    // constructor default, not a window the peer advertised.
    peer_window_seen: bool,
    w_max: usize,      // window size prior to loss
    k: f64,            // cubic curve offset in seconds; depends only on w_max and mss
    w_est: f64,        // RFC 9438 §4.3 reno-friendly window, integrated per ACK
    cwnd_prior: usize, // cwnd at the most recent congestion event; gates α_cubic
}

impl Cubic {
    pub fn ssthresh(&self) -> usize {
        if self.ssthresh == u32::MAX {
            usize::MAX
        } else {
            self.ssthresh as usize
        }
    }

    fn set_ssthresh(&mut self, v: usize) {
        self.ssthresh = if v == usize::MAX {
            u32::MAX
        } else {
            let value = u32::try_from(v).expect("ssthresh must fit in u32");
            assert!(value < u32::MAX, "ssthresh must be less than u32::MAX");
            value
        };
    }

    fn recovery_start(&self) -> Option<Instant> {
        if self.recovery_started {
            Some(self.recovery_start)
        } else {
            None
        }
    }

    fn set_recovery_start(&mut self, value: Option<Instant>) {
        self.recovery_start = value.unwrap_or(Instant::ZERO);
        self.recovery_started = value.is_some();
    }

    fn idle_start(&self) -> Option<Instant> {
        if self.idle {
            Some(self.idle_start)
        } else {
            None
        }
    }

    fn set_idle_start(&mut self, value: Option<Instant>) {
        self.idle_start = value.unwrap_or(Instant::ZERO);
        self.idle = value.is_some();
    }

    #[cfg(test)]
    #[track_caller]
    pub(in crate::socket::tcp) fn assert_handshake_restart(&self, mss: usize) {
        assert_eq!(self.ssthresh(), usize::MAX);
        assert_eq!(self.cwnd, mss);
        assert_eq!(self.w_est, mss as f64);
        assert_eq!(self.recovery_start(), None);
        assert!(!self.in_fast_recovery);
        assert!(!self.in_rto_recovery);
    }

    #[cfg(test)]
    fn snapshot(&self) -> String {
        let instant = |value: Option<Instant>| {
            value.map_or_else(|| "-".into(), |t| t.total_micros().to_string())
        };
        let ssthresh = if self.ssthresh() == usize::MAX {
            u64::MAX
        } else {
            self.ssthresh() as u64
        };
        format!(
            "{} {} {} {} {} {:016x} {:016x} {} {} {} {} {}",
            self.w_max as u64,
            self.cwnd as u64,
            usize::from(self.mss) as u64,
            ssthresh,
            (self.rwnd as usize) as u64,
            self.k.to_bits(),
            self.w_est.to_bits(),
            self.cwnd_prior as u64,
            instant(self.recovery_start()),
            u8::from(self.in_fast_recovery),
            u8::from(self.in_rto_recovery),
            instant(self.idle_start()),
        )
    }

    pub fn new() -> Cubic {
        let mut cubic = Cubic {
            w_max: DEFAULT_MSS * 2,
            cwnd: DEFAULT_MSS * 2,
            mss: u16::try_from(DEFAULT_MSS).expect("DEFAULT_MSS must fit in u16"),
            rwnd: u32::try_from(64 * DEFAULT_MSS).expect("initial rwnd must fit in u32"),
            ssthresh: u32::MAX,
            k: 0.0,
            w_est: (DEFAULT_MSS * 2) as f64,
            cwnd_prior: DEFAULT_MSS * 2,

            recovery_start: Instant::ZERO,
            recovery_started: false,
            in_fast_recovery: false,
            in_rto_recovery: false,
            idle_start: Instant::ZERO,
            idle: false,
            peer_window_seen: false,
        };
        cubic.recompute_k();
        cubic
    }

    pub fn set_initial_window(&mut self, bytes: usize) {
        self.cwnd = bytes;
        self.w_est = bytes as f64;
    }

    pub fn on_handshake(&mut self, _now: Instant, initial_window: usize) {
        self.set_initial_window(initial_window);
        if self.in_rto_recovery {
            self.in_rto_recovery = false;
            self.set_ssthresh(usize::MAX);
            self.cwnd = usize::from(self.mss);
            self.w_est = self.cwnd as f64;
            self.set_recovery_start(None);
            self.in_fast_recovery = false;
        }
    }

    // K = cbrt(w_max * (1 - beta) / C) ^ 1/3
    fn recompute_k(&mut self) {
        let c_as_bytes = C * usize::from(self.mss) as f64;
        let k3 = (self.w_max as f64) * (1.0 - BETA_CUBIC) / c_as_bytes;
        self.k = cube_root(k3);
    }

    // RFC 9438 §4.2: subtract the most recent idle period from t by sliding
    // recovery_start forward by the idle duration.
    fn absorb_idle(&mut self, now: Instant) {
        if let (Some(idle), Some(start)) = (self.idle_start(), self.recovery_start())
            && now >= idle
        {
            self.set_recovery_start(Some(start + (now - idle)));
        }
        self.set_idle_start(None);
    }
}

impl Cubic {
    pub fn window(&self) -> usize {
        self.cwnd
    }

    pub fn on_ack(&mut self, now: Instant, len: usize, in_flight: usize, rtt: &SmoothedRtt) {
        self.absorb_idle(now);

        if in_flight == 0 {
            self.set_idle_start(Some(now));
        }

        // RFC 9438 only acts on ACKs of new data. The socket also notifies us
        // of accepted segments that acknowledge nothing (window updates, data
        // segments from the remote): those must not exit fast recovery nor
        // grow the window.
        if len == 0 {
            return;
        }

        // New data was ACKed: a timer-based loss episode, if any, is over.
        self.in_rto_recovery = false;

        // First new-data-ack exits fast recovery and deflates `cwnd`
        if self.in_fast_recovery {
            self.in_fast_recovery = false;
            self.cwnd = self.ssthresh();
            self.w_est = self.cwnd as f64;
            return;
        } else if self.cwnd < self.ssthresh() {
            // Slow start: add the acknowledged bytes to `cwnd`.
            if self.cwnd < self.rwnd as usize {
                self.cwnd = self
                    .cwnd
                    .checked_add(len)
                    .expect("slow start cwnd must fit in usize")
                    .min(self.ssthresh())
                    .min(self.rwnd as usize);
            }
            self.cwnd = self.cwnd.max(usize::from(self.mss));
            return;
        }

        // ca: RFC 9438 §4.2 and §4.3: Calculate W_cubic and W_est. Use whichever grows faster.
        let recovery_start = match self.recovery_start() {
            Some(t) => t,
            None => {
                // RFC 9438 §4.8: set W_max = cwnd and K = 0 at start of CA
                self.w_max = self.cwnd;
                self.k = 0.0;
                self.w_est = self.cwnd as f64;
                self.set_recovery_start(Some(now));
                now
            }
        };

        // Elapsed time since the start of the recovery phase, in microseconds so the
        // cubic curve still advances between ACKs on sub-millisecond-RTT links.
        let t = now.total_micros() - recovery_start.total_micros();
        if t < 0 {
            return;
        }

        // RFC 9438 §4.3: use cubic function to get suggested cwnd.
        // W_cubic(t) = C(t - K)^3 + w_max, evaluated at the current time t.
        let c_as_bytes = C * usize::from(self.mss) as f64;
        let w_cubic = c_as_bytes * (t as f64 / 1_000_000.0 - self.k).powi(3) + self.w_max as f64;

        // RFC 9438 §4.3: advance our reno-like suggested cwnd.
        // When cwnd exceeds prior cwnd, change α_cubic to match Reno's AIMD.
        let w_est = {
            let alpha = if self.w_est >= self.cwnd_prior as f64 {
                1.0
            } else {
                ALPHA_CUBIC
            };

            self.w_est += alpha * usize::from(self.mss) as f64 * len as f64 / self.cwnd as f64;
            self.w_est
        };

        // RFC 9438 §4.3: use the suggested window that grows fastest.
        if w_cubic < w_est {
            if self.cwnd < self.rwnd as usize {
                self.cwnd = (w_est as usize).clamp(self.cwnd, self.rwnd as usize);
            }
            self.cwnd = self.cwnd.max(usize::from(self.mss));
            return;
        }

        // RFC 9438 §4.2: the congestion window target is W_cubic one RTT into the future.
        let w_cubic_target = {
            // srtt is in millis so floor at 1ms to ensure sub-ms RTTs don't ruin the lookahead.
            let srtt = (rtt.smoothed_rtt() as u64 * 1000).max(1000);

            let t_ahead = (t as f64 + srtt as f64) / 1_000_000.0;
            let raw = c_as_bytes * (t_ahead - self.k).powi(3) + self.w_max as f64;
            raw.min(1.5 * self.cwnd as f64) // clamp to avoid increasing faster than slow-start would
        };

        // TODO: clamps to 0 on small w_cubic_target (i.e. close to plateau)
        // add additional counter (linux `cwnd_cnt`?) to track "lost" bytes
        if self.cwnd < self.rwnd as usize {
            let increment = (w_cubic_target as usize).saturating_sub(self.cwnd) * len / self.cwnd;
            self.cwnd = self
                .cwnd
                .checked_add(increment)
                .expect("cubic cwnd must fit in usize")
                .min(self.rwnd as usize);
        }
        self.cwnd = self.cwnd.max(usize::from(self.mss));
    }

    pub fn on_dup_ack(&mut self, _now: Instant, len: usize, _in_flight: usize) {
        if self.in_fast_recovery {
            if self.cwnd < self.rwnd as usize {
                self.cwnd = self
                    .cwnd
                    .checked_add(len)
                    .expect("fast recovery cwnd must fit in usize")
                    .min(self.rwnd as usize);
            }
            self.cwnd = self.cwnd.max(usize::from(self.mss));
        }
    }

    pub fn post_transmit(&mut self, now: Instant, _len: usize) {
        self.absorb_idle(now);
    }

    pub fn on_loss(&mut self, now: Instant, in_flight: usize) {
        self.set_idle_start(None);
        // Only cut window size on first entrance to fast recovery.
        if !self.in_fast_recovery {
            // The flight that saw the loss was limited by min(cwnd, peer window): an ACK
            // never shrinks cwnd, so cwnd can sit far above what the peer let us send.
            // `rwnd` is the largest peer window seen.
            let limit = self.cwnd.min(self.rwnd as usize);

            // RFC 9438 §4.3: remember the window at this congestion event so W_est can
            // detect when it has recovered and switch α_cubic to 1.
            self.cwnd_prior = limit;

            // TODO: Make this optional?
            // RFC recommends (SHOULD) disabling if only a single CUBIC flow is on a network.
            //
            // RFC 9483.4.7: Fast Convergence
            // If loss happened at a smaller window than before, it indicates a new flow.
            // Reduce the cubic plateau more than usual to create headroom.
            self.w_max = if limit < self.w_max {
                ((limit as f64) * (1.0 + BETA_CUBIC) / 2.0) as usize
            } else {
                limit
            };

            self.set_ssthresh(
                ((in_flight as f64 * BETA_CUBIC) as usize).max(2 * usize::from(self.mss)),
            );
            self.cwnd = self
                .ssthresh()
                .min(self.rwnd as usize)
                .saturating_add(3 * usize::from(self.mss));

            self.set_recovery_start(Some(now));
            self.in_fast_recovery = true;
            self.recompute_k();
        }
    }

    pub fn on_rto(&mut self, _now: Instant, in_flight: usize) {
        // RFC 5681: when the retransmission timer fires for a segment that has
        // already been retransmitted by the timer (no new data was ACKed since
        // the previous RTO), ssthresh is held constant.
        if !self.in_rto_recovery {
            self.set_ssthresh(
                ((in_flight as f64 * BETA_CUBIC) as usize).max(2 * usize::from(self.mss)),
            );
            self.in_rto_recovery = true;
        }

        self.cwnd = usize::from(self.mss);
        self.cwnd_prior = in_flight;

        // RFC 9438 §4.8: defer W_max and K reset to the start of the next CA stage.
        self.set_recovery_start(None);
        self.in_fast_recovery = false;
        self.set_idle_start(None);
    }

    pub fn set_mss(&mut self, mss: usize) {
        self.mss = u16::try_from(mss).expect("mss must fit in u16");
        self.recompute_k();
    }

    /// `rwnd` becomes the first peer window, then the largest one seen.
    pub fn set_remote_window(&mut self, remote_window: usize) {
        if !self.peer_window_seen || (self.rwnd as usize) < remote_window {
            self.rwnd = u32::try_from(remote_window).expect("rwnd must fit in u32");
            self.peer_window_seen = true;
        }
    }
}

/// Efficient cube root using f64 bit tricks and Newton-Raphson.
///
/// a = mantissa * 2^e
///
/// cbrt(a) = cbrt(mantissa * 2^e)
/// cbrt(a) = cbrt(mantissa) * cbrt(2^e)
/// -> cbrt(2^e) = 2^(e/3)
///     -> e = 3q + r
///   -> 2^(e/3) = 2^(3q + r)
///   -> 2^(e/3) = 2^q * 2^(r/3)
/// cbrt(a) = cbrt(mantissa) * 2^q * 2^(r/3)
///
/// Floats are constructed from a mantissa and expontnet component.
/// Cbrt of a float can be achieved by cbrt of these two components.
///
/// The mantissa is always between 1 and 2, putting the cbrt between 1
/// and 1.2599. The slope of the curve between those two points is
/// almost a straight line, so a linear interpolatoin between those
/// two points gives an error less than 2%.
///
///
/// The exponent `e` of `2^e` has two parts, tt's quotient and remainder: `e = 3q + r`.
/// Which means cbrt `2^e` is cbrt `2^3q * 2^r` which becomes `2^q * 2^(r/3)`.
///
/// The remainder operation means `r` can only be 0, 1, or 2, so we can calaculate
/// `2^(r/3)` ahead of time.
///
/// Multiplying everything gets us a pretty close answer to the true cbrt.
/// `cbrt(a) = cbrt(mantissa) * 2^q * 2^(r/3)`
///
/// One or two Newton-Raphson iterations reduce any error enough not to matter.
fn cube_root(a: f64) -> f64 {
    if !(a >= f64::MIN_POSITIVE && a.is_finite()) {
        return 0.0;
    }

    const POW2_REM_OVER_3: [f64; 3] = [1.0, 1.2599210498948732, 1.5874010519681994];

    // decompose a into IEEE-754 components
    let bits = a.to_bits();

    // extract mantissa, get rough cbrt using linear interpolation
    let m = f64::from_bits((bits & 0x000F_FFFF_FFFF_FFFF) | 0x3FF0_0000_0000_0000);
    let cbrt_m = m.mul_add(0.2599, 0.7401);

    // extract exponent, break into quotient and remainder
    // e = 3q + r where r ∈ {0, 1, 2}
    let e = (((bits >> 52) & 0x7FF) as i64) - 1023;
    let q = e.div_euclid(3);
    let r = e.rem_euclid(3) as usize;

    // calculate 2^q efficiently by constructing f64 from bits
    let pow2q = f64::from_bits(((q + 1023) as u64) << 52);

    // add cbrt mantissa and other component back in:
    // cbrt mantiassa * 2^q * 2^(r/3)
    let x = cbrt_m * pow2q * POW2_REM_OVER_3[r];

    // a single iteration should bring us close enough
    (2.0 * x + a / (x * x)) / 3.0
}

#[cfg(test)]
mod test {
    use crate::{socket::tcp::SmoothedRtt, time::Instant};

    use super::*;

    const MSS: usize = 1024;

    #[test]
    fn cubic_size() {
        let size = core::mem::size_of::<Cubic>();
        std::eprintln!("Cubic size: {size}");
        assert_eq!(size, 72);
    }

    #[test]
    fn ssthresh_sentinel_round_trips() {
        let mut cubic = Cubic::new();
        assert_eq!(cubic.ssthresh(), usize::MAX);
        cubic.on_loss(Instant::ZERO, 10_000);
        assert_eq!(cubic.ssthresh(), 7_000);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    #[should_panic(expected = "ssthresh must be less than u32::MAX")]
    fn ssthresh_rejects_real_sentinel_value() {
        Cubic::new().set_ssthresh(u32::MAX as usize);
    }

    fn ack(cubic: &mut Cubic, len: usize, now: Instant) {
        cubic.on_ack(now, len, cubic.window().saturating_sub(MSS), &rtte())
    }

    fn rtte() -> SmoothedRtt {
        SmoothedRtt::default()
    }

    enum Op {
        InitialWindow(usize),
        Handshake(i64, usize),
        Ack(i64, usize, usize, u32),
        DupAck(i64, usize, usize),
        Transmit(i64, usize),
        Loss(i64, usize),
        Rto(i64, usize),
        Mss(usize),
        RemoteWindow(usize),
        Window,
    }

    struct Trajectory<'a> {
        cubic: Cubic,
        lines: &'a mut Vec<String>,
    }

    impl<'a> Trajectory<'a> {
        fn new(lines: &'a mut Vec<String>, scenario: &str) -> Self {
            let cubic = Cubic::new();
            lines.push(format!("new {scenario} | {}", cubic.snapshot()));
            Self { cubic, lines }
        }

        fn apply(&mut self, op: Op) {
            let cubic = &mut self.cubic;
            let description = match op {
                Op::InitialWindow(bytes) => {
                    cubic.set_initial_window(bytes);
                    format!("set_initial_window {bytes}")
                }
                Op::Handshake(now, bytes) => {
                    cubic.on_handshake(Instant::from_micros(now), bytes);
                    format!("on_handshake {now} {bytes}")
                }
                Op::Ack(now, len, in_flight, srtt) => {
                    let mut rtt = rtte();
                    if srtt != 0 {
                        rtt.sample(srtt);
                    }
                    cubic.on_ack(Instant::from_micros(now), len, in_flight, &rtt);
                    format!("on_ack {now} {len} {in_flight} {srtt}")
                }
                Op::DupAck(now, len, in_flight) => {
                    cubic.on_dup_ack(Instant::from_micros(now), len, in_flight);
                    format!("on_dup_ack {now} {len} {in_flight}")
                }
                Op::Transmit(now, len) => {
                    cubic.post_transmit(Instant::from_micros(now), len);
                    format!("post_transmit {now} {len}")
                }
                Op::Loss(now, in_flight) => {
                    cubic.on_loss(Instant::from_micros(now), in_flight);
                    format!("on_loss {now} {in_flight}")
                }
                Op::Rto(now, in_flight) => {
                    cubic.on_rto(Instant::from_micros(now), in_flight);
                    format!("on_rto {now} {in_flight}")
                }
                Op::Mss(mss) => {
                    cubic.set_mss(mss);
                    format!("set_mss {mss}")
                }
                Op::RemoteWindow(rwnd) => {
                    cubic.set_remote_window(rwnd);
                    format!("set_remote_window {rwnd}")
                }
                Op::Window => format!("window {}", cubic.window()),
            };
            self.lines
                .push(format!("{description} | {}", cubic.snapshot()));
        }
    }

    fn compare_trajectory(name: &str, lines: Vec<String>, committed: &str) {
        let mut text = lines.join("\n");
        text.push('\n');
        if std::env::var("ZHIDA_CUBIC_BLESS").as_deref() == Ok("1") {
            let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/socket/tcp/congestion/testdata");
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join(name), &text).unwrap();
            return;
        }
        for (index, (got, want)) in text.lines().zip(committed.lines()).enumerate() {
            assert_eq!(got, want, "{name} line {}", index + 1);
        }
        assert_eq!(
            text.lines().count(),
            committed.lines().count(),
            "{name} line count"
        );
    }

    // On 32-bit targets an initial window of u32::MAX equals the usize::MAX ssthresh sentinel,
    // so the recorded trajectory is 64-bit only.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn trajectory_matches_committed() {
        const MAX_FLIGHT: usize = (1 << 31) - 1;
        const MAX_RWND: usize = 65535 << 14;
        let mut lines = Vec::new();
        for iw in [1, 14_480, 1 << 20, u32::MAX as usize] {
            for mss in [1, 48, 1448, 65535] {
                let mut t = Trajectory::new(&mut lines, "slow_start");
                t.apply(Op::InitialWindow(iw));
                t.apply(Op::Mss(mss));
                t.apply(Op::RemoteWindow(MAX_RWND));
                for now in 1..=64 {
                    let len = if now == 1 { MAX_FLIGHT } else { mss };
                    t.apply(Op::Ack(now, len, MAX_FLIGHT, 0));
                }
                t.apply(Op::Window);
            }
        }
        for step in [1, 1_000_000] {
            for srtt in [0, 30] {
                let mut t = Trajectory::new(&mut lines, "congestion_avoidance");
                t.apply(Op::Mss(1448));
                t.apply(Op::RemoteWindow(MAX_RWND));
                t.apply(Op::InitialWindow(14_480));
                t.apply(Op::Loss(0, 14_480));
                t.apply(Op::Ack(0, 1448, 14_480, srtt));
                t.apply(Op::Ack(1, 1448, MAX_FLIGHT, srtt));
                for i in 1..=2000 {
                    t.apply(Op::Ack(4_000_000 + i * step, 1448, MAX_FLIGHT, srtt));
                }
                t.apply(Op::Window);
            }
        }
        let mut t = Trajectory::new(&mut lines, "recovery_and_idle");
        t.apply(Op::Mss(1448));
        t.apply(Op::InitialWindow(14_480));
        for now in 1..=3 {
            t.apply(Op::DupAck(now, 1448, 14_480));
        }
        t.apply(Op::Loss(4, 14_480));
        t.apply(Op::DupAck(5, 1448, 14_480));
        t.apply(Op::Loss(6, MAX_FLIGHT));
        t.apply(Op::Ack(7, 0, 14_480, 30));
        t.apply(Op::Ack(8, 1448, 14_480, 30));
        t.apply(Op::Loss(9, 10_136));
        t.apply(Op::Ack(10, 1448, 10_136, 30));
        t.apply(Op::Ack(11, 1448, 0, 30));
        t.apply(Op::Ack(1_000_011, 1448, 1448, 30));
        t.apply(Op::Ack(1_000_012, 0, 0, 0));
        t.apply(Op::Ack(1_000_011, 1448, 1448, 0));
        t.apply(Op::Ack(1_000_013, 0, 0, 0));
        t.apply(Op::Transmit(2_000_013, MAX_FLIGHT));
        t.apply(Op::Ack(0, 1448, 1448, 0));
        t.apply(Op::Rto(2_000_014, MAX_FLIGHT));
        t.apply(Op::Rto(2_000_015, 1));
        t.apply(Op::Ack(2_000_016, 1, 1, 0));
        t.apply(Op::Rto(2_000_017, 1));
        t.apply(Op::Mss(48));
        t.apply(Op::Handshake(2_000_018, 1 << 20));
        t.apply(Op::Window);

        let mut t = Trajectory::new(&mut lines, "syn_rto");
        t.apply(Op::Rto(300_000, 1));
        t.apply(Op::Rto(900_000, 1));
        t.apply(Op::Mss(65535));
        t.apply(Op::Handshake(900_000, 14_480));
        t.apply(Op::Ack(900_001, 0, 0, 0));
        t.apply(Op::Ack(900_002, 65535, 65535, 30));
        t.apply(Op::Window);

        let mut t = Trajectory::new(&mut lines, "idle_at_time_zero");
        t.apply(Op::Mss(1448));
        t.apply(Op::InitialWindow(14_480));
        t.apply(Op::Loss(0, 14_480));
        t.apply(Op::Ack(0, 1448, 0, 0));
        t.apply(Op::Transmit(1_000, 1448));
        t.apply(Op::Ack(2_000, 1448, 1448, 0));
        t.apply(Op::Window);

        let mut random_lines = Vec::new();
        let mut t = Trajectory::new(&mut random_lines, "random_seed_6a09e667f3bcc909");
        let mut seed = 0x6a09e667f3bcc909_u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut now = 0;
        for _ in 0..10_000 {
            now += (next() % 1_000_001) as i64;
            let kind = next() % 11;
            let len = (next() % (MAX_FLIGHT as u64 + 1)) as usize;
            let in_flight = (next() % (MAX_FLIGHT as u64 + 1)) as usize;
            let op = match kind {
                0 => Op::InitialWindow((next() % (u32::MAX as u64 + 1)) as usize),
                1 => Op::Handshake(now, (next() % (u32::MAX as u64 + 1)) as usize),
                2 | 3 => {
                    Op::Ack(now, len, in_flight, if next() & 1 == 0 { 0 } else { 30 })
                }
                4 => Op::DupAck(now, len, in_flight),
                5 => Op::Transmit(now, len),
                6 => Op::Loss(now, in_flight),
                7 => Op::Rto(now, in_flight),
                8 => Op::Mss((next() % 65535 + 1) as usize),
                9 => Op::RemoteWindow((next() % (MAX_RWND as u64 + 1)) as usize),
                10 => Op::Window,
                _ => unreachable!(),
            };
            t.apply(op);
        }
        let full_size: usize = lines
            .iter()
            .chain(&random_lines)
            .map(|line| line.len() + 1)
            .sum();
        if full_size > 3_000_000 {
            lines.push(random_lines.remove(0));
            lines.extend(random_lines.into_iter().enumerate().filter_map(|(i, line)| {
                ((i + 1) % 10 == 0).then_some(line)
            }));
        } else {
            lines.extend(random_lines);
        }
        compare_trajectory(
            "cubic_trajectory.txt",
            lines,
            include_str!("testdata/cubic_trajectory.txt"),
        );
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn large_initial_window_trajectory_matches_committed() {
        let mut lines = Vec::new();
        for iw in [1_usize << 33, usize::MAX] {
            let mut t = Trajectory::new(&mut lines, "large_initial_window");
            t.apply(Op::InitialWindow(iw));
            t.apply(Op::Window);
            t.apply(Op::Ack(1, 1448, (1 << 31) - 1, 0));
            t.apply(Op::Loss(2, 65_536));
            t.apply(Op::Ack(3, 1448, 65_536, 30));
            for now in 4..=20 {
                t.apply(Op::Ack(now * 1_000_000, 1448, 65_536, 30));
            }
            t.apply(Op::Rto(21_000_000, 2048));
            t.apply(Op::Ack(21_000_001, 1024, 2048, 0));
            for now in 22..=40 {
                t.apply(Op::Ack(now * 1_000_000, 1448, 65_536, 0));
            }
            t.apply(Op::Window);
        }
        compare_trajectory(
            "cubic_trajectory_large_iw.txt",
            lines,
            include_str!("testdata/cubic_trajectory_large_iw.txt"),
        );
    }

    #[test]
    fn peer_window_does_not_reduce_initial_window_before_loss() {
        let mut cubic = Cubic::new();
        let w_max = cubic.w_max;
        let cwnd_prior = cubic.cwnd_prior;
        let k = cubic.k;
        cubic.set_initial_window(1_048_576);
        assert_eq!(cubic.window(), 1_048_576);
        assert_eq!(cubic.w_est, 1_048_576.0);
        ack(&mut cubic, MSS, Instant::from_millis(1));
        let cwnd_at_loss = cubic.window();
        assert_eq!(cwnd_at_loss, 1_048_576);

        cubic.set_remote_window(65536);
        cubic.on_loss(Instant::from_millis(2), 65536);
        // The 64 KiB peer window, not the unused 1 MiB cwnd, limited the lost flight.
        assert_eq!(cubic.w_max, 65536);
        assert_eq!(cubic.cwnd_prior, 65536);
        assert_eq!(cubic.window(), 45875 + 3 * MSS);
        assert!(cubic.window() < cwnd_at_loss);
        ack(&mut cubic, MSS, Instant::from_millis(3));
        assert_eq!(cubic.window(), 45875);
        cubic.set_initial_window(1_048_576);
        cubic.on_rto(Instant::from_millis(4), 65536);
        assert_eq!(cubic.window(), MSS);
        assert_eq!(cubic.ssthresh(), 45875);

        let mut cubic = Cubic::new();
        cubic.set_initial_window(1_048_576);
        assert_eq!(cubic.w_max, w_max);
        assert_eq!(cubic.cwnd_prior, cwnd_prior);
        assert_eq!(cubic.k, k);
    }

    #[test]
    fn loss_under_peer_window_below_default_records_peer_window() {
        let mut cubic = Cubic::new();
        cubic.set_initial_window(1_048_576);
        cubic.set_remote_window(16384);
        assert_eq!(cubic.rwnd, 16384);
        cubic.set_remote_window(8192);
        assert_eq!(cubic.rwnd, 16384);
        cubic.on_loss(Instant::from_millis(2), 16384);
        assert_eq!(cubic.w_max, 16384);
        assert_eq!(cubic.cwnd_prior, 16384);
        assert_eq!(cubic.window(), 11468 + 3 * MSS);
    }

    #[test]
    fn loss_under_large_peer_window_records_cwnd_as_w_max() {
        for peer_window in [1_048_576, 4 * 1_048_576] {
            let mut cubic = Cubic::new();
            cubic.set_initial_window(1_048_576);
            cubic.set_remote_window(peer_window);
            cubic.on_loss(Instant::from_millis(2), 1_048_576);
            assert_eq!(cubic.w_max, 1_048_576);
            assert_eq!(cubic.cwnd_prior, 1_048_576);
            let ssthresh = (1_048_576.0 * BETA_CUBIC) as usize;
            assert_eq!(cubic.ssthresh(), ssthresh);
            assert_eq!(cubic.window(), ssthresh + 3 * MSS);
        }
    }

    #[test]
    fn peer_window_allows_slow_start_growth_only_above_cwnd() {
        let mut cubic = Cubic::new();
        cubic.set_initial_window(1_048_576);
        for now in 0..3 {
            cubic.on_ack(Instant::from_millis(now), MSS, 65536, &rtte());
            assert_eq!(cubic.window(), 1_048_576);
        }
        cubic.set_remote_window(1_048_576 + 2 * MSS);
        cubic.on_ack(Instant::from_millis(3), MSS, 65536, &rtte());
        assert_eq!(cubic.window(), 1_048_576 + MSS);
        cubic.on_ack(Instant::from_millis(4), 2 * MSS, 65536, &rtte());
        assert_eq!(cubic.window(), 1_048_576 + 2 * MSS);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn cubic_fix_huge_initial_window_ack_does_not_overflow() {
        let mut cubic = Cubic::new();
        cubic.set_initial_window(usize::MAX - 1);
        cubic.on_ack(Instant::ZERO, MSS, 65536, &rtte());
        assert_eq!(cubic.window(), usize::MAX - 1);

        cubic.set_ssthresh(65536);
        cubic.w_max = cubic.cwnd;
        cubic.k = 0.0;
        cubic.set_recovery_start(Some(Instant::ZERO));
        cubic.on_ack(Instant::ZERO, MSS, 65536, &rtte());
        assert_eq!(cubic.window(), usize::MAX - 1);
        cubic.w_est = 0.0;
        cubic.on_ack(Instant::from_secs(100), MSS, 65536, &rtte());
        assert_eq!(cubic.window(), usize::MAX - 1);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn cubic_fix_huge_initial_window_duplicate_ack_does_not_overflow() {
        let mut cubic = Cubic::new();
        cubic.set_initial_window(usize::MAX - 1);
        cubic.in_fast_recovery = true;
        cubic.on_dup_ack(Instant::ZERO, MSS, 65536);
        assert_eq!(cubic.window(), usize::MAX - 1);
    }

    fn large_window_in_congestion_avoidance() -> Cubic {
        let mut cubic = Cubic::new();
        cubic.set_initial_window(1_048_576);
        cubic.w_max = cubic.cwnd;
        cubic.k = 0.0;
        cubic.cwnd_prior = cubic.cwnd;
        cubic.set_ssthresh(cubic.cwnd);
        cubic.set_recovery_start(Some(Instant::ZERO));
        cubic
    }

    #[test]
    fn peer_window_does_not_reduce_reno_window() {
        let mut cubic = large_window_in_congestion_avoidance();
        cubic.on_ack(Instant::ZERO, MSS, 65536, &rtte());
        assert_eq!(cubic.window(), 1_048_576);
        assert_eq!(cubic.w_est, 1_048_577.0);
        cubic.set_remote_window(1_048_576 + 2 * MSS);
        cubic.on_ack(Instant::ZERO, MSS, 65536, &rtte());
        assert_eq!(cubic.window(), 1_048_578);
    }

    #[test]
    fn peer_window_does_not_reduce_cubic_window() {
        let mut cubic = large_window_in_congestion_avoidance();
        let now = Instant::from_secs(100);
        cubic.on_ack(now, MSS, 65536, &rtte());
        assert_eq!(cubic.window(), 1_048_576);
        cubic.set_remote_window(1_048_576 + 2 * MSS);
        cubic.on_ack(now, MSS, 65536, &rtte());
        assert_eq!(cubic.window(), 1_048_576 + MSS / 2);
    }

    #[test]
    fn peer_window_does_not_reduce_duplicate_ack_inflation() {
        let mut cubic = Cubic::new();
        cubic.set_initial_window(1_048_576);
        cubic.in_fast_recovery = true;
        cubic.on_dup_ack(Instant::ZERO, MSS, 65536);
        assert_eq!(cubic.window(), 1_048_576);
        cubic.set_remote_window(1_048_576 + 2 * MSS);
        cubic.on_dup_ack(Instant::ZERO, MSS, 65536);
        assert_eq!(cubic.window(), 1_048_576 + MSS);
    }

    #[test]
    fn handshake_rto_restarts_from_one_mss_in_slow_start() {
        for mss in [536, 1024, 1460] {
            let now = Instant::from_millis(900);
            let mut cubic = Cubic::new();
            cubic.on_rto(Instant::from_millis(300), 1);
            cubic.on_rto(now, 1);
            cubic.set_mss(mss);
            cubic.on_handshake(now, 1_048_576);
            cubic.on_ack(now, 0, 0, &rtte());
            cubic.assert_handshake_restart(mss);
        }
    }

    #[test]
    fn handshake_rto_window_doubles_each_rtt_until_peer_window() {
        let mut cubic = Cubic::new();
        cubic.on_rto(Instant::from_millis(300), 1);
        cubic.on_handshake(Instant::from_millis(300), 1_048_576);
        assert_eq!(cubic.window(), MSS);
        for round in 0..8 {
            let before = cubic.window();
            let now = Instant::from_millis(330 + round * 30);
            for _ in 0..before / MSS {
                cubic.on_ack(now, MSS, before, &rtte());
            }
            assert_eq!(cubic.window(), (before * 2).min(cubic.rwnd as usize));
            assert_eq!(cubic.recovery_start(), None);
        }
        assert_eq!(cubic.window(), cubic.rwnd as usize);
    }

    #[test]
    fn idle_does_not_reset_cubic_cwnd() {
        let mut cubic = Cubic::new();
        for millis in 1..=10 {
            ack(&mut cubic, MSS, Instant::from_millis(millis));
        }
        cubic.on_loss(Instant::from_millis(11), cubic.window());
        cubic.on_ack(Instant::from_millis(12), MSS, 0, &rtte());
        let cwnd = cubic.window();
        assert!(cwnd > 2 * MSS);
        let w_max = cubic.w_max;
        let w_est = cubic.w_est;
        let k = cubic.k;
        let ssthresh = cubic.ssthresh();
        assert_eq!(cubic.idle_start(), Some(Instant::from_millis(12)));
        assert_eq!(cubic.recovery_start(), Some(Instant::from_millis(11)));

        cubic.post_transmit(Instant::from_millis(10_012), MSS);
        assert_eq!(cubic.window(), cwnd);
        assert_eq!(cubic.w_max, w_max);
        assert_eq!(cubic.w_est, w_est);
        assert_eq!(cubic.k, k);
        assert_eq!(cubic.ssthresh(), ssthresh);
        assert_eq!(cubic.idle_start(), None);
        assert_eq!(cubic.recovery_start(), Some(Instant::from_millis(10_011)));
        cubic.post_transmit(Instant::from_millis(10_013), MSS);
        assert_eq!(cubic.window(), cwnd);
        assert_eq!(cubic.recovery_start(), Some(Instant::from_millis(10_011)));
    }

    #[test]
    fn slow_start_after_rto_caps_ack_at_ssthresh() {
        let flight = 1_048_576;
        for len in [MSS / 2, flight] {
            let mut cubic = Cubic::new();
            cubic.set_initial_window(flight);
            cubic.set_remote_window(2 * flight);
            cubic.on_rto(Instant::ZERO, flight);
            assert_eq!(cubic.window(), MSS);
            assert_eq!(cubic.ssthresh(), 734_003);

            cubic.on_ack(Instant::from_millis(1), len, 0, &rtte());
            assert_eq!(cubic.window(), (MSS + len).min(cubic.ssthresh()));
        }
    }

    #[test]
    fn slow_start_credits_two_mss_ack() {
        let mut cubic = Cubic::new();
        let before = cubic.window();
        cubic.on_ack(Instant::ZERO, 2 * MSS, before, &rtte());
        assert_eq!(cubic.window(), before + 2 * MSS);
    }

    #[test]
    fn reno_region_credits_two_mss_ack() {
        let state = || {
            let mut cubic = Cubic::new();
            cubic.w_max = 32 * MSS;
            cubic.recompute_k();
            cubic.cwnd = 32 * MSS;
            cubic.w_est = cubic.cwnd as f64;
            cubic.cwnd_prior = cubic.cwnd;
            cubic.set_ssthresh(cubic.cwnd);
            cubic.set_recovery_start(Some(Instant::ZERO));
            cubic
        };
        let mut one = state();
        let mut two = state();
        let before = one.w_est;
        one.on_ack(Instant::ZERO, MSS, one.cwnd, &rtte());
        two.on_ack(Instant::ZERO, 2 * MSS, two.cwnd, &rtte());
        assert_eq!(one.w_est - before, 32.0);
        assert_eq!(two.w_est - before, 2.0 * (one.w_est - before));
        assert_eq!(one.cwnd, one.w_est as usize);
        assert_eq!(two.cwnd, two.w_est as usize);
    }

    #[test]
    fn cubic_region_credits_two_mss_ack() {
        let state = || {
            let mut cubic = Cubic::new();
            cubic.cwnd = 32 * MSS;
            cubic.w_max = cubic.cwnd;
            cubic.k = 0.0;
            cubic.w_est = cubic.cwnd as f64;
            cubic.cwnd_prior = cubic.cwnd;
            cubic.set_ssthresh(cubic.cwnd);
            cubic.set_recovery_start(Some(Instant::ZERO));
            cubic
        };
        let mut one = state();
        let mut two = state();
        let before = one.cwnd;
        let now = Instant::from_secs(100);
        one.on_ack(now, MSS, before, &rtte());
        two.on_ack(now, 2 * MSS, before, &rtte());
        assert_eq!(one.cwnd - before, MSS / 2);
        assert_eq!(two.cwnd - before, 2 * (one.cwnd - before));
    }

    #[test]
    fn congestion_avoidance_works() {
        let mut cubic = Cubic::new();
        cubic.set_mss(MSS);
        cubic.w_max = MSS * 32;
        cubic.recompute_k();

        // Post-fast-recovery state: cwnd = ssthresh ≈ w_max * beta.
        cubic.cwnd = (MSS * 32 * 7) / 10;
        cubic.set_ssthresh(cubic.cwnd);
        cubic.set_recovery_start(Some(Instant::from_millis(0)));

        // CA at small time intervals should grow by less than 1 MSS per ACK.
        for i in 1..10 {
            let initial_cwnd = cubic.window();
            ack(&mut cubic, MSS, Instant::from_millis(i));
            assert!(cubic.window() < initial_cwnd + MSS);
        }

        // CA approaches w_max as t approaches K, and exceeds it past K.
        let pre = cubic.window();
        for i in 0..60 {
            ack(&mut cubic, MSS, Instant::from_millis(i * 100));
        }
        assert!(cubic.window() >= cubic.w_max);
        assert!(cubic.window() > pre);

        // RFC 9438 §4.2: the target is clamped to 1.5 * cwnd
        let pre = cubic.window();
        ack(&mut cubic, MSS, Instant::from_millis(100_000));
        assert!(cubic.window() <= pre + MSS);

        // CA should still cap at the receive window once enough ACKs accrue.
        for i in 0..200 {
            ack(&mut cubic, MSS, Instant::from_millis(100_000 + i * 100));
        }
        assert_eq!(cubic.window(), cubic.rwnd as usize);
    }

    #[test]
    fn fast_recovery_works() {
        let mut cubic = Cubic::new();
        cubic.set_mss(MSS);
        cubic.cwnd = MSS * 32;

        // duplicate ACKs before fast recovery should do nothing
        let initial_cwnd = cubic.window();
        for _ in 0..3 {
            cubic.on_dup_ack(Instant::from_millis(0), MSS, initial_cwnd);
        }
        assert_eq!(cubic.window(), initial_cwnd);

        // we enter fast recovery upon minor loss (three duplicate ACKs).
        // ssthresh = flight_size * beta_cubic, cwnd = ssthresh + 3*MSS, recovery_start = now.
        // w_max = cwnd since the prior w_max (initial 2*MSS) is below cwnd.
        let in_flight = initial_cwnd / 2;
        let expected_ssthresh = (in_flight as f64 * BETA_CUBIC) as usize;
        cubic.on_loss(Instant::from_millis(0), in_flight);
        assert_eq!(cubic.ssthresh(), expected_ssthresh);
        assert_eq!(cubic.cwnd, expected_ssthresh + 3 * MSS);
        assert_eq!(cubic.w_max, initial_cwnd);
        assert!(cubic.in_fast_recovery);
        assert_eq!(cubic.recovery_start(), Some(Instant::from_millis(0)));

        // in fast recovery, each dup-ACK should increase the cwnd by 1 MSS
        let initial_cwnd = cubic.window();
        for i in 0..3 {
            for _ in 0..3 {
                let initial_cwnd = cubic.window();
                cubic.on_dup_ack(Instant::from_millis(i), MSS, initial_cwnd);
                assert_eq!(cubic.window(), initial_cwnd + MSS);
            }

            // multiple loss events (trip-dup-ack) should not trigger additional fast recovery reductions
            let initial_cwnd = cubic.window();
            let initial_ssthresh = cubic.ssthresh();
            let initial_w_max = cubic.w_max;
            cubic.on_loss(Instant::from_millis(i), initial_cwnd);
            assert_eq!(cubic.window(), initial_cwnd);
            assert_eq!(cubic.ssthresh(), initial_ssthresh);
            assert_eq!(cubic.w_max, initial_w_max);
        }
        assert_eq!(cubic.window(), initial_cwnd + MSS * 9);

        // a non-duplicate ACK exits fast recovery and deflates cwnd to ssthresh
        ack(&mut cubic, MSS, Instant::from_millis(10));
        assert_eq!(cubic.window(), cubic.ssthresh());
        assert!(!cubic.in_fast_recovery);
    }

    #[test]
    fn zero_length_ack_does_not_exit_fast_recovery() {
        let mut cubic = Cubic::new();
        cubic.set_mss(MSS);
        cubic.cwnd = MSS * 32;

        cubic.on_loss(Instant::from_millis(0), cubic.cwnd);
        assert!(cubic.in_fast_recovery);

        let cwnd = cubic.window();
        let ssthresh = cubic.ssthresh();

        // Accepted segments that acknowledge no new data (window updates,
        // data segments from the remote) must not end fast recovery or
        // change the window.
        ack(&mut cubic, 0, Instant::from_millis(1));
        assert!(cubic.in_fast_recovery);
        assert_eq!(cubic.window(), cwnd);
        assert_eq!(cubic.ssthresh(), ssthresh);

        // The first ACK of new data still exits and deflates.
        ack(&mut cubic, MSS, Instant::from_millis(2));
        assert!(!cubic.in_fast_recovery);
        assert_eq!(cubic.window(), ssthresh);
    }

    #[test]
    fn repeated_rto_holds_ssthresh() {
        let mut cubic = Cubic::new();
        cubic.set_mss(MSS);
        cubic.cwnd = MSS * 32;

        // First RTO reduces ssthresh based on the flight size.
        cubic.on_rto(Instant::from_millis(0), MSS * 32);
        let ssthresh = cubic.ssthresh();
        assert_eq!(ssthresh, (32.0 * MSS as f64 * BETA_CUBIC) as usize);

        // Until new data is ACKed, further RTOs are retransmissions of the
        // same segment and must hold ssthresh constant instead of collapsing
        // it towards the minimum.
        cubic.on_rto(Instant::from_millis(1), MSS);
        assert_eq!(cubic.ssthresh(), ssthresh);

        // Once new data is ACKed, the next RTO is a fresh loss detection
        // and reduces ssthresh again.
        ack(&mut cubic, MSS, Instant::from_millis(2));
        cubic.on_rto(Instant::from_millis(3), MSS * 4);
        assert_eq!(cubic.ssthresh(), (4.0 * MSS as f64 * BETA_CUBIC) as usize);
    }

    #[test]
    fn slow_start_works() {
        let mut cubic = Cubic::new();
        cubic.set_mss(MSS);
        cubic.cwnd = MSS * 64;
        cubic.set_ssthresh(MSS * 16);

        // we enter slow start upon major loss (an RTO)
        // window resets to MSS, ssthresh becomes a fraction of the inflight bytes,
        // recovery_start is cleared so any later CA uses a fresh epoch,
        // and w_max is preserved (RFC 9438 §4.8 defers it to the next CA stage).
        let w_max_before_rto = cubic.w_max;
        let inflight = cubic.window();
        cubic.on_rto(Instant::from_millis(0), inflight);
        assert_eq!(cubic.ssthresh(), (inflight as f64 * BETA_CUBIC) as usize);
        assert_eq!(cubic.window(), MSS);
        assert!(!cubic.in_fast_recovery);
        assert_eq!(cubic.recovery_start(), None);
        assert_eq!(cubic.w_max, w_max_before_rto);

        // Slow start adds all acknowledged bytes.
        let initial_cwnd = cubic.window();
        for i in 0..10 {
            let initial_cwnd = cubic.window();
            let now = Instant::from_millis(i);
            ack(&mut cubic, MSS * 2, now);
            assert_eq!(cubic.window(), initial_cwnd + MSS * 2);
        }
        assert_eq!(cubic.window(), initial_cwnd + MSS * 20);

        // slow start uses the number of ACKed bytes if they're less than the MSS
        let initial_cwnd = cubic.window();
        for i in 0..10 {
            let initial_cwnd = cubic.window();
            let now = Instant::from_millis(10 + i);
            ack(&mut cubic, MSS / 2, now);
            assert_eq!(cubic.window(), initial_cwnd + MSS / 2);
        }
        assert_eq!(cubic.window(), initial_cwnd + MSS / 2 * 10);

        // slow start transitions to congestion avoidance at ssthresh
        let initial_cwnd = cubic.window();
        cubic.set_ssthresh(initial_cwnd + MSS);
        ack(&mut cubic, MSS, Instant::from_millis(30));
        assert_eq!(cubic.window(), initial_cwnd + MSS);
        assert_eq!(cubic.ssthresh(), initial_cwnd + MSS);
    }

    #[test]
    fn progress_to_ca_via_rto() {
        let mut cubic = Cubic::new();
        cubic.set_mss(MSS);

        let mut time = 0;

        // slow start from default state
        let initial_cwnd = cubic.window();
        for _ in 0..30 {
            time += 1;
            ack(&mut cubic, MSS, Instant::from_millis(time));
        }
        assert_eq!(cubic.window(), initial_cwnd + MSS * 30);
        assert!(cubic.window() < cubic.ssthresh());

        // rto: cwnd resets to MSS and sstresh reduces
        let rto_cwnd = cubic.window();
        cubic.on_rto(Instant::from_millis(time), rto_cwnd);
        assert_eq!(cubic.window(), MSS);
        assert_eq!(cubic.ssthresh(), (rto_cwnd as f64 * BETA_CUBIC) as usize);

        // slow start again until cwnd reaches new ssthresh
        while cubic.window() < cubic.ssthresh() {
            time += 1;
            let initial_cwnd = cubic.window();
            ack(&mut cubic, MSS, Instant::from_millis(time));
            assert_eq!(cubic.window(), (initial_cwnd + MSS).min(cubic.ssthresh()));
        }
        assert!(cubic.window() >= cubic.ssthresh());
        assert!(cubic.window() < cubic.ssthresh() + MSS);

        // ca: first CA ACK starts a fresh epoch with W_max = cwnd and K = 0.
        time += 1;
        let cwnd_at_ca_entry = cubic.window();
        ack(&mut cubic, MSS, Instant::from_millis(time));
        assert_eq!(cubic.w_max, cwnd_at_ca_entry);
        assert_eq!(cubic.k, 0.0);
        assert!(cubic.window() >= cwnd_at_ca_entry);
    }

    #[test]
    fn progress_to_ca_via_loss() {
        let mut cubic = Cubic::new();
        cubic.set_mss(MSS);

        let mut time = 0;

        // slow start from default state
        let initial_cwnd = cubic.window();
        for _ in 0..30 {
            time += 1;
            ack(&mut cubic, MSS, Instant::from_millis(time));
        }
        assert_eq!(cubic.window(), initial_cwnd + MSS * 30);
        assert!(cubic.window() < cubic.ssthresh());

        // dup ACKs: ssthresh = cwnd * beta, cwnd = ssthresh + 3*MSS, recovery_start = now
        time += 1;
        let loss_cwnd = cubic.window();
        let expected_ssthresh = (loss_cwnd as f64 * BETA_CUBIC) as usize;
        cubic.on_loss(Instant::from_millis(time), loss_cwnd);
        assert_eq!(cubic.ssthresh(), expected_ssthresh);
        assert_eq!(cubic.window(), expected_ssthresh + 3 * MSS);
        assert!(cubic.in_fast_recovery);
        assert_eq!(cubic.recovery_start(), Some(Instant::from_millis(time)));

        // inflate cwnd on each duplicate ACK
        for _ in 0..9 {
            time += 1;
            let initial_cwnd = cubic.window();
            cubic.on_dup_ack(Instant::from_millis(time), MSS, cubic.cwnd);
            assert_eq!(cubic.window(), initial_cwnd + MSS);
        }

        // non-duplicate ACK deflates cwnd to ssthresh
        time += 1;
        ack(&mut cubic, MSS, Instant::from_millis(time));
        assert_eq!(cubic.window(), expected_ssthresh);
        assert!(!cubic.in_fast_recovery);

        // ca: subsequent ACKs follow the cubic curve
        time += 1;
        let initial_cwnd = cubic.window();
        ack(&mut cubic, MSS, Instant::from_millis(time));
        assert!(cubic.window() >= initial_cwnd);
    }

    #[test]
    fn fast_convergence_reduces_w_max() {
        let mut cubic = Cubic::new();
        cubic.set_mss(MSS);
        cubic.w_max = MSS * 50;
        cubic.cwnd = MSS * 30;

        // Loss while cwnd < w_max (a new competing flow) should pull w_max down.
        let w_max_prev = cubic.w_max;
        cubic.on_loss(Instant::from_millis(0), cubic.cwnd);
        assert!(cubic.w_max < w_max_prev);
    }

    #[test]
    fn test_cube_root() {
        let mut max_err = 0.0;
        let mut max_err_at = 0;
        let mut max_err_expected = 0.0;
        let mut max_err_found = 0.0;

        for i in (1..1_000_000).step_by(99) {
            let found = cube_root(i as f64);
            let expected = (i as f64).cbrt();
            let err = (found - expected).abs() / expected;

            if err > max_err {
                max_err = err;
                max_err_at = i;
                max_err_found = found;
                max_err_expected = expected;
            }
        }

        assert!(
            max_err < 0.0005,
            "cube_root({max_err_at}) = {max_err_found}, expected ~{max_err_expected}, rel err {max_err:.3e}"
        );
    }
}
