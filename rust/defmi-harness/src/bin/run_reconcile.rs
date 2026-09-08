use curve25519_dalek::scalar::Scalar;
use defmi::reconcile::{check, check_positions, locate_break, prove, Attestation, Reconciliation};
use defmi_harness::{parse_value, timing_summary, write_pretty_json, HarnessResult};
use merlin::Transcript;
use qomm_sim::deterministic_random::DeterministicRng;
use rand::rngs::OsRng;
use serde_json::json;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Instant;
use zkfmi_zk::pedersen::{asset_tag, Pedersen};
use zkpi_proofs::threshold_sigma::{deal, joint_prove_zero_opening};

struct Options {
    sizes: Vec<usize>,
    repeats: usize,
    parties: usize,
    threshold: usize,
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
    if options.repeats == 0 || options.sizes.is_empty() {
        return Err("--repeats and --sizes must be non-zero".into());
    }
    if options.parties <= options.threshold {
        return Err("--parties must be greater than --threshold".into());
    }
    let key = Pedersen::new(b"qomm:defmi:v1").with_value_generator(asset_tag(7));
    let mut rng = OsRng;
    let mut scaling = Vec::new();
    let mut quorums = Vec::new();
    let mut locating = Vec::new();
    for &positions in &options.sizes {
        if positions == 0 {
            return Err("--sizes must contain positive values".into());
        }
        let mut values_rng = DeterministicRng::new(positions as u64);
        let values = (0..positions)
            .map(|_| values_rng.randrange(1, 10_000) as u64)
            .collect::<Vec<_>>();
        let blindings = (0..positions)
            .map(|_| Scalar::random(&mut rng))
            .collect::<Vec<_>>();
        let commitments = values
            .iter()
            .zip(&blindings)
            .map(|(value, blinding)| key.commit_u64(*value, blinding))
            .collect::<Vec<_>>();
        let attestation = Attestation {
            register: "a book of record".into(),
            account: "omnibus".into(),
            asset: "an instrument".into(),
            total: values.iter().sum(),
            as_of: "2026-08-22T09:00Z".into(),
            signature: None,
        };
        let mut built = prove(&key, &commitments, &blindings, &attestation, &mut rng)?;
        let mut build_ms = Vec::new();
        for _ in 0..options.repeats {
            let started = Instant::now();
            built = prove(&key, &commitments, &blindings, &attestation, &mut rng)?;
            build_ms.push(started.elapsed().as_secs_f64() * 1e3);
        }
        let mut check_ms = Vec::new();
        for _ in 0..options.repeats {
            let started = Instant::now();
            let _ = check(&key, &commitments, &built, None);
            check_ms.push(started.elapsed().as_secs_f64() * 1e3);
        }
        let verified = check(&key, &commitments, &built, None).is_ok();
        scaling.push(json!({
            "positions": positions,
            "verified": verified,
            "prove": timing_summary(&build_ms),
            "check": timing_summary(&check_ms),
            "wire_bytes": 96,
        }));

        let parties = (1..=options.parties).collect::<Vec<_>>();
        let combined: Scalar = blindings.iter().sum();
        let shares = deal(
            &key,
            &Scalar::ZERO,
            &combined,
            &parties,
            options.threshold,
            &mut rng,
        )?;
        let quorum = (1..=options.threshold + 1).collect::<Vec<_>>();
        let mut joint =
            prove_by_quorum(&key, &commitments, &shares, &quorum, &attestation, &mut rng)?;
        let mut joint_ms = Vec::new();
        for _ in 0..options.repeats {
            let started = Instant::now();
            joint = prove_by_quorum(&key, &commitments, &shares, &quorum, &attestation, &mut rng)?;
            joint_ms.push(started.elapsed().as_secs_f64() * 1e3);
        }
        quorums.push(json!({
            "positions": positions,
            "quorum": quorum,
            "of": options.parties,
            "assemble": timing_summary(&joint_ms),
            "verified": check(&key, &commitments, &joint, None).is_ok(),
        }));

        let mut register = values.clone();
        register[positions / 3] += 5;
        let expected = register.iter().sum();
        let started = Instant::now();
        let search = locate_break(
            &key,
            &commitments,
            &blindings,
            |low, high| Some(register[low..high].iter().sum()),
            expected,
            &mut rng,
        )?;
        let search_ms = started.elapsed().as_secs_f64() * 1e3;
        let started = Instant::now();
        let per_position = check_positions(&key, &commitments, &blindings, &register, &mut rng);
        let per_position_ms = started.elapsed().as_secs_f64() * 1e3;
        let log = (usize::BITS - positions.leading_zeros() - 1) as usize;
        locating.push(json!({
            "positions": positions,
            "found": search.found,
            "planted": positions / 3,
            "sub_range_proofs": search.proofs,
            "two_log_n_plus_one": 2 * log + 1,
            "subtotals_made_public": search.ranges_made_public.len(),
            "narrowest_range": search.narrowest(),
            "ms": round_half_even_places(search_ms, 1),
            "per_position_register": {
                "found": per_position,
                "ms": round_half_even_places(per_position_ms, 1),
                "disclosed": 0,
            },
        }));
        println!(
            "n={positions:5}  prove {:.2} ms  check {:.2} ms  quorum {:.2} ms  locate {} proofs",
            scaling.last().unwrap()["prove"]["median"]
                .as_f64()
                .unwrap_or(0.0),
            scaling.last().unwrap()["check"]["median"]
                .as_f64()
                .unwrap_or(0.0),
            quorums.last().unwrap()["assemble"]["median"]
                .as_f64()
                .unwrap_or(0.0),
            search.proofs,
        );
    }
    let payload = json!({
        "host": zkfmi_measure::hosts::this_host(),
        "group": "ed25519",
        "note": "balances carry an asset tag, which is what a real one does",
        "scaling": scaling,
        "quorum": quorums,
        "locating": locating,
    });
    write_pretty_json(Some(&options.out), &payload)?;
    println!("wrote {}", options.out.display());
    Ok(())
}

fn prove_by_quorum(
    key: &Pedersen,
    commitments: &[curve25519_dalek::ristretto::RistrettoPoint],
    shares: &zkpi_proofs::threshold_sigma::ShareSet,
    quorum: &[usize],
    attestation: &Attestation,
    rng: &mut OsRng,
) -> HarnessResult<Reconciliation> {
    let mut transcript = Transcript::new(b"qomm:defmi:reconcile");
    transcript.append_message(b"attestation", &attestation.body());
    let (proof, _) = joint_prove_zero_opening(key, shares, quorum, &mut transcript, None, rng)?;
    Ok(Reconciliation {
        attestation: attestation.clone(),
        positions: commitments.len(),
        proof,
    })
}

fn round_half_even_places(value: f64, places: i32) -> f64 {
    let scale = 10f64.powi(places);
    qomm_sim::market::round_half_even(value * scale) as f64 / scale
}

fn parse_args() -> HarnessResult<Options> {
    let mut options = Options {
        sizes: vec![16, 64, 256, 1_024, 4_096],
        repeats: 9,
        parties: 7,
        threshold: 2,
        out: defmi_harness::repo_root().join("artifacts/reconcile.json"),
    };
    let raw = std::env::args_os().skip(1).collect::<Vec<_>>();
    let mut index = 0;
    while index < raw.len() {
        match raw[index].to_string_lossy().as_ref() {
            "--repeats" => {
                options.repeats = parse_value(value(&raw, &mut index, "--repeats")?, "--repeats")?
            }
            "--parties" => {
                options.parties = parse_value(value(&raw, &mut index, "--parties")?, "--parties")?
            }
            "--threshold" => {
                options.threshold =
                    parse_value(value(&raw, &mut index, "--threshold")?, "--threshold")?
            }
            "--out" => options.out = PathBuf::from(value(&raw, &mut index, "--out")?),
            "--sizes" => {
                options.sizes.clear();
                index += 1;
                while index < raw.len() && !raw[index].to_string_lossy().starts_with("--") {
                    options
                        .sizes
                        .push(parse_value(raw[index].clone(), "--sizes")?);
                    index += 1;
                }
                continue;
            }
            unknown => return Err(format!("unknown argument {unknown}").into()),
        }
        index += 1;
    }
    Ok(options)
}

fn value(raw: &[OsString], index: &mut usize, name: &str) -> HarnessResult<OsString> {
    *index += 1;
    raw.get(*index)
        .cloned()
        .ok_or_else(|| format!("{name} expects a value").into())
}
