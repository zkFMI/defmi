//! Rust port of `scripts/run_deccp.py`.

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use qomm_defmi::ccp::{
    for_provider, net_positions, sign_obligation, ClearingProvider, ClearingRegistry, Obligation,
};
use qomm_defmi::credit::CreditCtx;
use qomm_defmi::netting::Mode as NetMode;
use qomm_harness::defmi_cycle::one_cycle;
use qomm_harness::{parse_value, timing_summary, write_pretty_json, HarnessResult};
use qomm_sim::pyrandom::PyRandom;
use qomm_zk::pedersen::{asset_tag, Pedersen};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Instant;

struct Options {
    trades: Vec<usize>,
    participants: usize,
    repeats: usize,
    out: PathBuf,
}

fn main() {
    if let Err(error) = run_main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run_main() -> HarnessResult<()> {
    let options = parse_args()?;
    let key = Pedersen::new(b"qomm:defmi:v1").with_value_generator(asset_tag(7));
    let mut rng = OsRng;
    let mut rows = Vec::new();
    for &trades in &options.trades {
        let mut plain = Vec::new();
        let mut attested = Vec::new();
        let mut clearing = Vec::new();
        for seed in 0..options.repeats {
            plain.push(one_cycle(
                NetMode::NetNet,
                trades,
                options.participants,
                false,
                seed as u64,
                &mut rng,
            )?);
        }
        for seed in 0..options.repeats {
            attested.push(one_cycle(
                NetMode::NetNet,
                trades,
                options.participants,
                true,
                seed as u64,
                &mut rng,
            )?);
        }
        for seed in 0..options.repeats {
            clearing.push(clearing_arm(
                &key,
                trades,
                options.participants,
                seed as u64,
                &mut rng,
            )?);
        }
        let plain_total = summary_field(&plain, "verify_total_ms");
        let attested_total = summary_field(&attested, "verify_total_ms");
        let added_values = clearing
            .iter()
            .map(|row| {
                row["novate_ms"].as_f64().unwrap_or(0.0)
                    + row["check_ms"].as_f64().unwrap_or(0.0)
                    + row["attest_ms"].as_f64().unwrap_or(0.0)
            })
            .collect::<Vec<_>>();
        let added = timing_summary(&added_values);
        let plain_median = plain_total["median"].as_f64().unwrap_or(0.0);
        let attested_median = attested_total["median"].as_f64().unwrap_or(0.0);
        let added_median = added["median"].as_f64().unwrap_or(0.0);
        let deccp_total = attested_median + added_median;
        let verify_per_order = qomm_sim::fsum::nsum(
            plain
                .iter()
                .filter_map(|row| row["verify_per_order_ms"].as_f64()),
        ) / plain.len().max(1) as f64;
        let row = json!({
            "trades": trades,
            "net_net": plain_total,
            "net_net_attested": attested_total,
            "deccp_added_to_attested": added,
            "deccp_total": deccp_total,
            "speedup_attested_vs_plain": py_round_places(plain_median / attested_median, 2),
            "speedup_deccp_vs_plain": py_round_places(plain_median / deccp_total, 2),
            "novate_us_per_trade": clearing[0]["novate_us_per_trade"],
            "check_us_per_trade": clearing[0]["check_us_per_trade"],
            "verify_per_order_ms_plain": py_round_places(verify_per_order, 2),
            "book_flat_without_a_proof": clearing.iter().all(|row| row["book_flat_without_a_proof"] == true),
            "edges": {
                "before": clearing[0]["edges_before"],
                "after": clearing[0]["edges_after"],
            },
        });
        println!(
            "trades={trades:5}  net-net {:8.1} ms  attested {:7.1} ms  DeCCP {:7.1} ms  ({}x vs net-net, novation {} us/trade)",
            plain_median,
            attested_median,
            deccp_total,
            row["speedup_deccp_vs_plain"],
            row["novate_us_per_trade"],
        );
        rows.push(row);
    }
    let payload = json!({
        "host": qomm_measure::hosts::this_host(),
        "group": "ed25519",
        "participants": options.participants,
        "rows": rows,
    });
    write_pretty_json(Some(&options.out), &payload)?;
    println!("wrote {}", options.out.display());
    Ok(())
}

fn clearing_arm(
    key: &Pedersen,
    trades: usize,
    participants: usize,
    seed: u64,
    rng: &mut OsRng,
) -> HarnessResult<Value> {
    if participants < 2 || trades == 0 {
        return Err("clearing measurement needs at least two participants and one trade".into());
    }
    let mut values = PyRandom::new(seed);
    let house = ClearingProvider::new("DeCCP-A", b"house-a", SigningKey::generate(&mut *rng));
    let members = (0..participants)
        .map(|index| format!("p{index}").into_bytes())
        .collect::<Vec<_>>();
    let signing = members
        .iter()
        .map(|member| (member.clone(), SigningKey::generate(&mut *rng)))
        .collect::<BTreeMap<_, _>>();
    let parties = signing
        .iter()
        .map(|(member, key)| (member.clone(), key.verifying_key()))
        .collect::<BTreeMap<_, _>>();
    let mut edges = Vec::new();
    for _ in 0..trades {
        let chosen = values.sample(participants, 2);
        let payer = members[chosen[0]].clone();
        let payee = members[chosen[1]].clone();
        let amount = values.randrange(1, 1_000) as u64;
        let obligation = Obligation {
            payer: payer.clone(),
            payee: payee.clone(),
            asset: "an instrument".into(),
            commitment: key.commit_u64(amount, &Scalar::random(&mut *rng)),
        };
        edges.push(sign_obligation(
            &obligation,
            &signing[&payer],
            &signing[&payee],
        ));
    }

    let started = Instant::now();
    let novation = house.novate(&edges)?;
    let novate_ms = started.elapsed().as_secs_f64() * 1e3;
    let started = Instant::now();
    let attestation = house.attest(&novation, b"cycle-1");
    let attest_ms = started.elapsed().as_secs_f64() * 1e3;

    let credit = CreditCtx::new(key.clone(), 64);
    let margin = credit.grant(
        &house.handle,
        "cash",
        5_000,
        &Scalar::random(&mut *rng),
        20_000,
        &Scalar::random(&mut *rng),
        1_000,
    )?;
    let waterfall = for_provider(
        "DeCCP-A",
        key.commit_u64(1_000, &Scalar::random(&mut *rng)),
        key.commit_u64(500, &Scalar::random(&mut *rng)),
        key.commit_u64(2_000, &Scalar::random(&mut *rng)),
        key.commit_u64(9_000, &Scalar::random(&mut *rng)),
    );
    let mut registry = ClearingRegistry::new();
    let admission = registry.admit(&credit, &house, margin, waterfall);
    let (admitted, admit_detail) = match admission {
        Ok(()) => (true, String::new()),
        Err(reason) => (false, reason),
    };
    let started = Instant::now();
    let checked = registry.check_cycle(&attestation, &novation, &parties);
    let check_ms = started.elapsed().as_secs_f64() * 1e3;
    let (verified, reason) = match checked {
        Ok(()) => (true, String::new()),
        Err(reason) => (false, reason),
    };
    let started = Instant::now();
    let nets = net_positions(&novation);
    let nets_ms = started.elapsed().as_secs_f64() * 1e3;
    Ok(json!({
        "trades": trades,
        "participants": participants,
        "provider_admitted": admitted,
        "admit_detail": admit_detail,
        "novate_ms": novate_ms,
        "attest_ms": attest_ms,
        "check_ms": check_ms,
        "net_positions_ms": nets_ms,
        "verified": verified,
        "reason": reason,
        "edges_before": novation.edges(),
        "edges_after": novation.after.len(),
        "book_flat_without_a_proof": verified,
        "novate_us_per_trade": py_round_places(novate_ms / trades as f64 * 1_000.0, 2),
        "check_us_per_trade": py_round_places(check_ms / trades as f64 * 1_000.0, 2),
        "participants_with_a_net": nets.len(),
    }))
}

fn summary_field(rows: &[Value], field: &str) -> Value {
    timing_summary(
        &rows
            .iter()
            .filter_map(|row| row[field].as_f64())
            .collect::<Vec<_>>(),
    )
}

fn py_round_places(value: f64, places: i32) -> f64 {
    let scale = 10f64.powi(places);
    qomm_sim::market::py_round(value * scale) as f64 / scale
}

fn parse_args() -> HarnessResult<Options> {
    let mut options = Options {
        trades: vec![16, 64, 256],
        participants: 8,
        repeats: 3,
        out: qomm_harness::repo_root().join("artifacts/deccp.json"),
    };
    let raw = std::env::args_os().skip(1).collect::<Vec<_>>();
    let mut index = 0;
    while index < raw.len() {
        match raw[index].to_string_lossy().as_ref() {
            "--participants" => {
                options.participants =
                    parse_value(value(&raw, &mut index, "--participants")?, "--participants")?
            }
            "--repeats" => {
                options.repeats = parse_value(value(&raw, &mut index, "--repeats")?, "--repeats")?
            }
            "--out" => options.out = PathBuf::from(value(&raw, &mut index, "--out")?),
            "--trades" => {
                options.trades.clear();
                index += 1;
                while index < raw.len() && !raw[index].to_string_lossy().starts_with("--") {
                    options
                        .trades
                        .push(parse_value(raw[index].clone(), "--trades")?);
                    index += 1;
                }
                continue;
            }
            unknown => return Err(format!("unknown argument {unknown}").into()),
        }
        index += 1;
    }
    if options.repeats == 0 || options.trades.is_empty() {
        return Err("--repeats and --trades must be non-zero".into());
    }
    Ok(options)
}

fn value(raw: &[OsString], index: &mut usize, name: &str) -> HarnessResult<OsString> {
    *index += 1;
    raw.get(*index)
        .cloned()
        .ok_or_else(|| format!("{name} expects a value").into())
}
