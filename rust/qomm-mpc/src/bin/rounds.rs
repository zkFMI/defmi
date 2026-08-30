//! Where the rounds go, read from the engine and split by channel.
//!
//! The paper's claim about this protocol is a claim about *shape*: the round
//! count is set by the sequential depth of the comparison chain, so measures
//! that narrow a layer buy bandwidth and not latency. Until now the evidence for
//! it was a single total scraped out of a log line --- 70 rounds --- which is
//! consistent with the claim but does not show it. The engine has always kept
//! the breakdown; nothing printed it.
//!
//! Two things are measured here that the log could not give:
//!
//!   * **Which channel the rounds are on.** Rounds spent broadcasting a partial
//!     opening are the comparison chain; rounds spent sending shares are not.
//!   * **The same program under a second protocol.** If depth is what sets the
//!     count, then dropping the malicious-security machinery should move bytes a
//!     great deal and rounds hardly at all.
//!
//! The second one is a prediction, and it is written down before it is run.
//! Malicious Shamir at N=7, T=2 differs from semi-honest Shamir in two places.
//! Opening is the same exchange either way --- every party already sends to
//! every other --- and only the reconstruction differs, which is arithmetic and
//! not communication. Multiplication is also the same exchange, with a sacrifice
//! that roughly doubles the triples consumed and one verification at the end.
//! So:
//!
//!   * rounds should differ by a small constant, not a factor: the same
//!     comparison chain of the same depth, plus the final check. Under ten per
//!     cent.
//!   * bytes should differ by something near a factor of two, from the
//!     sacrificed triples.
//!
//! A result where rounds move with the security model would say the round count
//! is not a depth measurement, and the argument the paper builds on it would
//! have to be withdrawn rather than reworded.
//!
//! No network delay is inserted. Rounds and bytes are properties of the program
//! and the protocol; a delay changes when they happen, not how many there are,
//! and the wall-clock figures that do depend on it are measured elsewhere.

use qomm_measure::{hosts, Summary};
use qomm_mpc::Protocol;
use std::collections::BTreeMap;
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// What one party reported.
#[derive(Default, Clone)]
struct PartyRun {
    rounds: u64,
    raw_rounds: u64,
    sent: u64,
    payload: u64,
    seconds: f64,
    channels: BTreeMap<String, (u64, u64)>,
}

struct Options {
    root: PathBuf,
    program: String,
    parties: usize,
    threshold: usize,
    repeats: usize,
    protocols: Vec<Protocol>,
    out: PathBuf,
    party_bin: PathBuf,
}

fn main() {
    let opts = parse_args();
    if !qomm_mpc::available() {
        eprintln!("this build has no engine; set MP_SPDZ_ROOT and rebuild");
        std::process::exit(1);
    }

    let run_dir = opts.root.join("Player-Data").join("qomm-rounds");
    std::fs::create_dir_all(&run_dir).expect("a run directory");
    let base = free_port_block(opts.parties, 21_000);
    write_hosts(&run_dir, opts.parties, base);

    let mut sections = Vec::new();
    for protocol in &opts.protocols {
        println!("== {} ==", protocol.as_str());
        let mut runs: Vec<Vec<PartyRun>> = Vec::new();
        for repeat in 0..opts.repeats {
            match one_run(&opts, *protocol, &run_dir) {
                Ok(parties) => {
                    let p0 = &parties[0];
                    println!(
                        "  repeat {repeat}: rounds={} sent={} payload={} seconds={:.4}",
                        p0.rounds, p0.sent, p0.payload, p0.seconds
                    );
                    runs.push(parties);
                }
                Err(why) => {
                    eprintln!("  repeat {repeat} failed: {why}");
                    std::process::exit(1);
                }
            }
        }
        sections.push(report(*protocol, &runs));
    }

    let json = format!(
        "{{\n  \"host\": {},\n  \"program\": {},\n  \"parties\": {},\n  \
         \"threshold\": {},\n  \"repeats\": {},\n  \"delay_ms\": 0,\n  \
         \"protocols\": [\n{}\n  ]\n}}\n",
        quote(&hosts::this_host()),
        quote(&opts.program),
        opts.parties,
        opts.threshold,
        opts.repeats,
        sections.join(",\n")
    );
    if let Some(parent) = opts.out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&opts.out, &json).expect("could not write the artifact");
    println!("wrote {}", opts.out.display());
}

/// One run of the whole committee: `parties` processes, all of them ours.
fn one_run(opts: &Options, protocol: Protocol, run_dir: &Path) -> Result<Vec<PartyRun>, String> {
    let mut children = Vec::new();
    for party in 0..opts.parties {
        let child = Command::new(&opts.party_bin)
            .current_dir(&opts.root)
            .arg(protocol.as_str())
            .arg(party.to_string())
            .arg(&opts.program)
            .args(["-N", &opts.parties.to_string()])
            .args(["-T", &opts.threshold.to_string()])
            .arg("-ip")
            .arg(run_dir.join(format!("hosts-P{party}")))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("could not start party {party}: {e}"))?;
        children.push(child);
    }
    let mut parties = Vec::new();
    let mut failure = None;
    for (party, child) in children.into_iter().enumerate() {
        let done = child.wait_with_output().map_err(|e| e.to_string())?;
        if !done.status.success() {
            let why = String::from_utf8_lossy(&done.stderr);
            let why = why.trim();
            failure.get_or_insert(format!(
                "party {party} exited {}: {}",
                done.status.code().unwrap_or(-1),
                if why.is_empty() { "no message" } else { why }
            ));
            continue;
        }
        parties.push(read_party(&String::from_utf8_lossy(&done.stdout))?);
    }
    match failure {
        Some(why) => Err(why),
        None => Ok(parties),
    }
}

/// The party binary's flat output. One record per line, name last.
fn read_party(text: &str) -> Result<PartyRun, String> {
    let mut run = PartyRun::default();
    let mut seen = false;
    for line in text.lines() {
        let mut field = line.split_whitespace();
        if field.next() != Some("QOMM") {
            continue;
        }
        match field.next() {
            Some("total") => {
                run.rounds = number(field.next())?;
                run.raw_rounds = number(field.next())?;
                run.sent = number(field.next())?;
                run.payload = number(field.next())?;
                run.seconds = field
                    .next()
                    .and_then(|s| s.parse().ok())
                    .ok_or("a total line without a time")?;
                seen = true;
            }
            Some("channel") => {
                let (rounds, bytes) = (number(field.next())?, number(field.next())?);
                let name = field.collect::<Vec<_>>().join(" ");
                run.channels.insert(name, (rounds, bytes));
            }
            _ => {}
        }
    }
    if seen {
        Ok(run)
    } else {
        Err("a party said nothing about its run".into())
    }
}

fn number(field: Option<&str>) -> Result<u64, String> {
    field
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "a malformed count".into())
}

/// One protocol's section of the artifact.
///
/// Rounds and bytes are deterministic: the same program under the same protocol
/// sends the same messages every time. So the repeats are not there to average
/// them, they are there to notice if that stops being true --- which is why they
/// are reported as a value plus the number of runs that disagreed, and not as a
/// mean with a spread that would be zero and say nothing.
fn report(protocol: Protocol, runs: &[Vec<PartyRun>]) -> String {
    let first = &runs[0][0];
    let rounds_vary = runs.iter().any(|r| r[0].rounds != first.rounds);
    let bytes_vary = runs
        .iter()
        .any(|r| r[0].sent != first.sent || r[0].payload != first.payload);
    let seconds = Summary::of(&runs.iter().map(|r| r[0].seconds).collect::<Vec<_>>())
        .expect("a run has at least one repeat");

    // Every party's own byte count, from the same run: a shape the log never
    // showed, because only party 0 was ever read.
    let per_party: Vec<String> = runs[0]
        .iter()
        .enumerate()
        .map(|(i, p)| {
            format!(
                "        {{\"party\": {i}, \"rounds\": {}, \"sent\": {}, \
                               \"payload\": {}}}",
                p.rounds, p.sent, p.payload
            )
        })
        .collect();

    let mut channels: Vec<&String> = first.channels.keys().collect();
    channels.sort_by_key(|name| std::cmp::Reverse(first.channels[*name].0));
    let channel_rows: Vec<String> = channels
        .iter()
        .map(|name| {
            let (rounds, bytes) = first.channels[*name];
            format!(
                "        {{\"channel\": {}, \"rounds\": {rounds}, \"bytes\": {bytes}, \
                 \"share_of_rounds\": {:.4}}}",
                quote(name),
                rounds as f64 / first.rounds.max(1) as f64
            )
        })
        .collect();

    println!(
        "  total rounds={} sent={} payload={} (fan-out {:.2}x) over {} runs{}",
        first.rounds,
        first.sent,
        first.payload,
        first.sent as f64 / first.payload.max(1) as f64,
        runs.len(),
        if rounds_vary || bytes_vary {
            "  (NOT CONSTANT)"
        } else {
            ""
        }
    );
    for name in &channels {
        let (rounds, bytes) = first.channels[*name];
        println!(
            "    {name:24} rounds={rounds:5} ({:4.1}%)  bytes={bytes}",
            100.0 * rounds as f64 / first.rounds.max(1) as f64
        );
    }

    format!(
        "    {{\n      \"protocol\": {},\n      \"stock_binary\": {},\n      \
             \"rounds\": {},\n      \"raw_rounds\": {},\n      \"sent\": {},\n      \
             \"payload\": {},\n      \"constant_across_runs\": {},\n      \
             \"seconds\": {{\"n\": {}, \"mean\": {:.6}, \"sd\": {}, \"median\": {:.6}}},\n      \
             \"parties\": [\n{}\n      ],\n      \"channels\": [\n{}\n      ]\n    }}",
        quote(protocol.as_str()),
        quote(protocol.stock_binary()),
        first.rounds,
        first.raw_rounds,
        first.sent,
        first.payload,
        !(rounds_vary || bytes_vary),
        seconds.n,
        seconds.mean,
        seconds.sd.map_or("null".into(), |sd| format!("{sd:.6}")),
        seconds.median,
        per_party.join(",\n"),
        channel_rows.join(",\n")
    )
}

/// `parties` consecutive ports that nothing is listening on.
///
/// Bound and released rather than assumed free: this host also runs other
/// people's experiments, and a collision shows up as a party that hangs.
fn free_port_block(parties: usize, start: u16) -> u16 {
    let mut base = start;
    while base < 60_000 {
        let end = base + parties as u16;
        let mut collision = None;
        for port in base..end {
            if TcpListener::bind(("127.0.0.1", port)).is_err() {
                collision = Some(port);
                break;
            }
        }
        if let Some(port) = collision {
            base = port + 1;
        } else {
            return base;
        }
    }
    panic!("no free block of {parties} ports");
}

fn write_hosts(run_dir: &Path, parties: usize, base: u16) {
    let lines: String = (0..parties)
        .map(|target| format!("127.0.0.1:{}\n", base + target as u16))
        .collect();
    for party in 0..parties {
        let path = run_dir.join(format!("hosts-P{party}"));
        let mut file = std::fs::File::create(&path).expect("a hosts file");
        file.write_all(lines.as_bytes()).expect("a hosts file");
    }
}

fn parse_args() -> Options {
    let mut root = std::env::var_os("MP_SPDZ_ROOT").map(PathBuf::from);
    let mut program = String::new();
    let (mut parties, mut threshold, mut repeats) = (7usize, 2usize, 3usize);
    let mut protocols = vec![Protocol::MaliciousShamir, Protocol::SemiHonestShamir];
    let mut out = PathBuf::from("artifacts/rounds_by_channel.json");
    let mut party_bin = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("qomm-party")))
        .unwrap_or_else(|| PathBuf::from("qomm-party"));

    // Every option here takes a value, so the loop steps two at a time and a
    // flag left dangling at the end is a mistake worth stopping for rather than
    // a silent empty string.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let value = args
            .get(i + 1)
            .unwrap_or_else(|| panic!("{flag} needs a value"))
            .as_str();
        match flag {
            "--root" => root = Some(PathBuf::from(value)),
            "--program" => program = value.to_string(),
            "--parties" => parties = value.parse().expect("--parties"),
            "--threshold" => threshold = value.parse().expect("--threshold"),
            "--repeats" => repeats = value.parse().expect("--repeats"),
            "--out" => out = PathBuf::from(value),
            "--party-bin" => party_bin = PathBuf::from(value),
            "--protocols" => {
                protocols = value
                    .split(',')
                    .map(|n| Protocol::parse(n).unwrap_or_else(|| panic!("unknown protocol {n}")))
                    .collect()
            }
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    let root = root.expect("--root, or MP_SPDZ_ROOT in the environment");
    assert!(
        !program.is_empty(),
        "--program: the name compiled by ./compile.py"
    );
    assert!(
        parties > 2 * threshold,
        "Shamir needs more than 2T parties; got N={parties} T={threshold}"
    );
    Options {
        root,
        program,
        parties,
        threshold,
        repeats,
        protocols,
        out,
        party_bin,
    }
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}
