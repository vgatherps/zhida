//! The v1 configuration matrix: its run order, the stop at the first run not
//! valid, and the per-configuration table built from the report lines
//! `memif-bench run` prints.

use crate::workload::Shape;

pub const CONFIGS: [(&str, Shape); 6] = [
    ("pingpong-m64", pingpong(1, 64, 100_000, 10_000)),
    ("pingpong-m1448", pingpong(1, 1448, 100_000, 10_000)),
    ("parallel-k4", pingpong(4, 64, 20_000, 2_000)),
    ("parallel-k16", pingpong(16, 64, 20_000, 2_000)),
    ("parallel-k64", pingpong(64, 64, 20_000, 2_000)),
    (
        "bulk-1g",
        Shape::Bulk {
            bytes: 1 << 30,
            warmup: 64 << 20,
        },
    ),
];

const fn pingpong(conns: usize, message: usize, rounds: usize, warmup: usize) -> Shape {
    Shape::PingPong {
        conns,
        message,
        rounds,
        warmup,
    }
}

/// `reps` passes over `CONFIGS`, forward, reverse, forward, ...: pairs of
/// (rep, index into `CONFIGS`).
pub fn plan(reps: usize) -> Vec<(usize, usize)> {
    let mut order = Vec::with_capacity(reps * CONFIGS.len());
    for rep in 0..reps {
        let pass = 0..CONFIGS.len();
        if rep % 2 == 0 {
            order.extend(pass.map(|config| (rep, config)));
        } else {
            order.extend(pass.rev().map(|config| (rep, config)));
        }
    }
    order
}

/// The number at `key` in a flat JSON object this crate printed: None when
/// absent or null. Strings in those objects escape `"`, so `"key":` matches
/// only a key.
fn number(json: &str, key: &str) -> Option<f64> {
    let pattern = format!("\"{key}\":");
    let rest = &json[json.find(&pattern)? + pattern.len()..];
    rest[..rest.find([',', '}']).unwrap_or(rest.len())]
        .parse()
        .ok()
}

/// One `run` of the matrix: its two report objects, if it printed them, and
/// whether it exited 0 (both children exited 0: both reports valid, both
/// Ports closed).
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub client: Option<String>,
    pub peer: Option<String>,
    pub exit_ok: bool,
}

impl Outcome {
    pub fn from_run(stdout: &str, exit_ok: bool) -> Self {
        let report = |role: &str| {
            let prefix = format!("{{\"role\":\"{role}\",\"report\":");
            stdout
                .lines()
                .find_map(|line| Some(line.strip_prefix(&prefix)?.strip_suffix('}')?.to_owned()))
        };
        Self {
            client: report("client"),
            peer: report("peer"),
            exit_ok,
        }
    }

    /// Both reports valid and the run exited 0.
    fn reports(&self) -> Option<(&str, &str)> {
        fn valid(report: &Option<String>) -> Option<&str> {
            report
                .as_deref()
                .filter(|json| json.contains("\"valid\":true"))
        }
        Some((valid(&self.client)?, valid(&self.peer)?)).filter(|_| self.exit_ok)
    }

    pub fn status(&self) -> &'static str {
        match (self.reports(), &self.client, &self.peer) {
            (Some(_), _, _) => "valid",
            (None, Some(_), Some(_)) => "invalid",
            _ => "failed",
        }
    }

    /// One JSONL record: configuration, rep, status and both reports.
    pub fn json(&self, config: &str, rep: usize) -> String {
        let report = |json: &Option<String>| json.clone().unwrap_or_else(|| "null".to_owned());
        format!(
            "{{\"config\":\"{config}\",\"rep\":{rep},\"status\":\"{}\",\"exit_ok\":{},\"client\":{},\"peer\":{}}}",
            self.status(),
            self.exit_ok,
            report(&self.client),
            report(&self.peer)
        )
    }
}

/// Runs `plan` in order: `run` executes one (rep, config) and `record`
/// stores its outcome. Stops at the first run not valid, recorded first,
/// with its status and reports; nothing after it runs. Otherwise returns
/// each configuration's (client, peer) reports in plan order.
pub fn execute(
    plan: &[(usize, usize)],
    mut run: impl FnMut(usize, usize) -> Result<Outcome, String>,
    mut record: impl FnMut(usize, usize, &Outcome) -> Result<(), String>,
) -> Result<Vec<Vec<(String, String)>>, String> {
    let mut valid = vec![Vec::new(); CONFIGS.len()];
    for &(rep, config) in plan {
        let outcome = run(rep, config)?;
        record(rep, config, &outcome)?;
        let Some((client, peer)) = outcome.reports() else {
            let report = |json: &Option<String>| json.clone().unwrap_or_else(|| "missing".to_owned());
            return Err(format!(
                "rep {rep} {}: {} (exit_ok {}); client report {}; peer report {}",
                CONFIGS[config].0,
                outcome.status(),
                outcome.exit_ok,
                report(&outcome.client),
                report(&outcome.peer)
            ));
        };
        valid[config].push((client.to_owned(), peer.to_owned()));
    }
    Ok(valid)
}

fn ratio(numerator: Option<f64>, denominator: Option<f64>) -> Option<f64> {
    Some(numerator? / denominator.filter(|&d| d != 0.0)?)
}

/// The table rows of one valid run; ping-pong rows are None for bulk. The
/// client counts the measured window only, the peer its whole run.
fn metrics(client: &str, peer: &str) -> [(&'static str, Option<f64>); 9] {
    let c = |key| number(client, key);
    let p = |key| number(peer, key);
    [
        ("ns/round trip", c("ns_per_round_trip_amortized")),
        ("rtt p50 ns", c("rtt_p50_ns")),
        ("rtt p99 ns", c("rtt_p99_ns")),
        ("rtt max ns", c("rtt_max_ns")),
        ("turns/round trip", ratio(c("turns"), c("round_trips"))),
        ("ns/frame", c("ns_per_frame")),
        ("frames/s", c("frames_per_sec")),
        ("client idle turns", ratio(c("idle_turns"), c("turns"))),
        ("peer idle turns (whole run)", ratio(p("idle_turns"), p("turns"))),
    ]
}

/// `values` sorted ascending in place; their median.
fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        values[mid]
    } else {
        (values[mid - 1] + values[mid]) / 2.0
    }
}

fn cell(value: f64) -> String {
    if value.abs() < 100.0 {
        format!("{value:.3}")
    } else {
        format!("{value:.0}")
    }
}

/// Min, median and max of each metric over `runs`, the valid runs of
/// `label`; `runs` is not empty.
pub fn table(label: &str, runs: &[(String, String)]) -> String {
    let mut out = format!("{label}: {} runs\n", runs.len());
    out += &format!(
        "  {:<27} {:>12} {:>12} {:>12}\n",
        "metric", "min", "median", "max"
    );
    for row in 0..metrics("", "").len() {
        let mut values: Vec<f64> = runs
            .iter()
            .filter_map(|(c, p)| metrics(c, p)[row].1)
            .collect();
        if values.len() != runs.len() {
            continue;
        }
        let mid = median(&mut values);
        let (min, max) = (values[0], values[values.len() - 1]);
        let name = metrics("", "")[row].0;
        out += &format!(
            "  {name:<27} {:>12} {:>12} {:>12}\n",
            cell(min),
            cell(mid),
            cell(max)
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_alternates_forward_and_reverse() {
        let order: Vec<(usize, usize)> = plan(3);
        let n = CONFIGS.len();
        assert_eq!(order.len(), 3 * n);
        assert!(order[..n]
            .iter()
            .enumerate()
            .all(|(i, &pair)| pair == (0, i)));
        assert!(order[n..2 * n]
            .iter()
            .enumerate()
            .all(|(i, &pair)| pair == (1, n - 1 - i)));
        assert!(order[2 * n..]
            .iter()
            .enumerate()
            .all(|(i, &pair)| pair == (2, i)));
        for shape in CONFIGS.map(|(_, shape)| shape) {
            assert_eq!(shape.validate(), Ok(()));
        }
    }

    #[test]
    fn number_reads_only_keys() {
        let json =
            r#"{"turns":10,"idle_turns":4,"reason":"\"turns\":99","rtt_p50_ns":null,"frames":2}"#;
        assert_eq!(number(json, "turns"), Some(10.0));
        assert_eq!(number(json, "idle_turns"), Some(4.0));
        assert_eq!(number(json, "rtt_p50_ns"), None);
        assert_eq!(number(json, "frames"), Some(2.0));
        assert_eq!(number(json, "absent"), None);
    }

    fn line(role: &str, report: &str) -> String {
        format!("{{\"role\":\"{role}\",\"report\":{report}}}\n")
    }

    fn client(ns: u32) -> String {
        format!(
            r#"{{"side":"client","round_trips":10,"ns_per_round_trip_amortized":{ns},"rtt_p50_ns":5,"rtt_p99_ns":6,"rtt_max_ns":7,"turns":40,"idle_turns":10,"ns_per_frame":2.5,"frames_per_sec":400000000,"valid":true}}"#
        )
    }

    const PEER: &str = r#"{"side":"peer","turns":50,"idle_turns":25,"valid":true}"#;

    fn valid(ns: u32) -> Outcome {
        Outcome::from_run(&(line("client", &client(ns)) + &line("peer", PEER)), true)
    }

    fn pair(ns: u32) -> (String, String) {
        (client(ns), PEER.to_owned())
    }

    /// The ns/round trip row of `table`: min, median, max.
    fn round_trip_row(table: &str) -> Vec<String> {
        let row = table
            .lines()
            .find(|row| row.trim_start().starts_with("ns/round trip"))
            .unwrap_or_else(|| panic!("{table}"));
        row.split_whitespace().skip(2).map(str::to_owned).collect()
    }

    #[test]
    fn table_summarizes_runs() {
        assert_eq!(valid(300).status(), "valid");
        assert!(valid(300).json("pingpong-m64", 0).starts_with(r#"{"config":"pingpong-m64","rep":0,"status":"valid","exit_ok":true,"client":{"side":"client""#));
        assert_eq!(
            table("pingpong-m64", &[pair(300), pair(100), pair(200)]),
            "pingpong-m64: 3 runs\n\
             \x20 metric                               min       median          max\n\
             \x20 ns/round trip                        100          200          300\n\
             \x20 rtt p50 ns                         5.000        5.000        5.000\n\
             \x20 rtt p99 ns                         6.000        6.000        6.000\n\
             \x20 rtt max ns                         7.000        7.000        7.000\n\
             \x20 turns/round trip                   4.000        4.000        4.000\n\
             \x20 ns/frame                           2.500        2.500        2.500\n\
             \x20 frames/s                       400000000    400000000    400000000\n\
             \x20 client idle turns                  0.250        0.250        0.250\n\
             \x20 peer idle turns (whole run)        0.500        0.500        0.500\n"
        );
    }

    #[test]
    fn median_of_an_even_count_is_the_mean_of_the_middle_two() {
        let table = table("pingpong-m64", &[pair(100), pair(400)]);
        assert_eq!(round_trip_row(&table), ["100", "250", "400"]);
    }

    #[test]
    fn execute_groups_valid_reports_by_configuration_in_plan_order() {
        let plan = [(0, 0), (0, 1), (1, 1), (1, 0)];
        let mut recorded = Vec::new();
        let grouped = execute(
            &plan,
            |rep, config| Ok(valid(100 * rep as u32 + config as u32)),
            |rep, config, outcome| {
                recorded.push((rep, config, outcome.status()));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(recorded, [(0, 0, "valid"), (0, 1, "valid"), (1, 1, "valid"), (1, 0, "valid")]);
        assert_eq!(grouped[0], [pair(0), pair(100)]);
        assert_eq!(grouped[1], [pair(1), pair(101)]);
        assert!(grouped[2..].iter().all(Vec::is_empty));
    }

    /// `bad` second of three: recorded, then the matrix stops naming it;
    /// the third run never starts.
    fn assert_stops_at(bad: Outcome, status: &str) {
        assert_eq!(bad.status(), status);
        let mut outcomes = vec![valid(1), bad, valid(3)].into_iter();
        let (mut started, mut recorded) = (Vec::new(), Vec::new());
        let error = execute(
            &[(0, 0), (0, 1), (0, 2)],
            |rep, config| {
                started.push((rep, config));
                Ok(outcomes.next().unwrap())
            },
            |rep, config, outcome| {
                recorded.push((rep, config, outcome.status()));
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(started, [(0, 0), (0, 1)]);
        assert_eq!(recorded, [(0, 0, "valid"), (0, 1, status)]);
        assert!(error.starts_with(&format!("rep 0 pingpong-m1448: {status}")), "{error}");
    }

    #[test]
    fn valid_reports_with_a_failed_exit_stop_the_matrix() {
        let both = line("client", &client(900)) + &line("peer", PEER);
        assert_stops_at(Outcome::from_run(&both, false), "invalid");
    }

    #[test]
    fn a_report_not_valid_with_a_successful_exit_stops_the_matrix() {
        let peer = PEER.replace("\"valid\":true", "\"valid\":false");
        let both = line("client", &client(900)) + &line("peer", &peer);
        assert_stops_at(Outcome::from_run(&both, true), "invalid");
    }

    #[test]
    fn a_missing_report_with_a_successful_exit_stops_the_matrix() {
        let client_only = line("client", &client(900));
        assert_stops_at(Outcome::from_run(&client_only, true), "failed");
    }

    #[test]
    fn a_run_that_cannot_start_stops_the_matrix_unrecorded() {
        let mut recorded = 0;
        let error = execute(
            &[(0, 0), (0, 1)],
            |_, _| Err("spawn run: denied".to_owned()),
            |_, _, _| {
                recorded += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!((error.as_str(), recorded), ("spawn run: denied", 0));
    }

    #[test]
    fn bulk_rows_omit_round_trip_metrics() {
        let client = r#"{"side":"client","shape":"bulk","turns":8,"idle_turns":2,"ns_per_frame":3,"frames_per_sec":1000,"rtt_p50_ns":null,"valid":true}"#;
        let peer = r#"{"side":"peer","turns":4,"idle_turns":1,"valid":true}"#;
        let rows: Vec<String> = table("bulk-1g", &[(client.to_owned(), peer.to_owned())])
            .lines()
            .map(|row| row.split_whitespace().next().unwrap().to_owned())
            .collect();
        assert_eq!(
            rows,
            ["bulk-1g:", "metric", "ns/frame", "frames/s", "client", "peer"]
        );
    }
}
