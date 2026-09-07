use curve25519_dalek::scalar::Scalar;
use defmi::notes::NoteLedger;
use defmi::viewing::{check_grant, scan_scope, total_seen, ScopedWallet};
use defmi_harness::{parse_value, timing_summary, write_pretty_json, HarnessResult};
use qomm_sim::deterministic_random::DeterministicRng;
use zkfmi_zk::pedersen::{asset_tag, Pedersen};
use rand::rngs::OsRng;
use serde_json::json;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Instant;

const NOW: u64 = 1_780_000_000;
const NOTE_BITS: usize = 32;

struct Options {
    pools: Vec<usize>,
    scopes: usize,
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
    if options.scopes == 0 || options.repeats == 0 || options.pools.is_empty() {
        return Err("--scopes, --repeats, and --pools must be non-zero".into());
    }
    let key = Pedersen::new(b"qomm:defmi:note:v1");
    let asset_key = key.clone().with_value_generator(asset_tag(3));
    let mut os_rng = OsRng;
    let owner = ScopedWallet::new(&mut os_rng);
    let scope_names = (0..options.scopes)
        .map(|index| format!("2026Q{}", index + 1))
        .collect::<Vec<_>>();

    let grant = owner.grant(&scope_names[0], "an auditor", NOW, 90);
    let grant_repeats = options.repeats.max(15);
    let mut grant_build = Vec::new();
    for _ in 0..grant_repeats {
        let started = Instant::now();
        let _ = owner.grant(&scope_names[0], "an auditor", NOW, 90);
        grant_build.push(started.elapsed().as_secs_f64() * 1e3);
    }
    let mut grant_check = Vec::new();
    for _ in 0..grant_repeats {
        let started = Instant::now();
        let _ = check_grant(&grant, &owner.public_identity(), NOW + 1);
        grant_check.push(started.elapsed().as_secs_f64() * 1e3);
    }
    let wrong_owner = ScopedWallet::new(&mut os_rng);
    let grant_json = json!({
        "build": timing_summary(&grant_build),
        "check": timing_summary(&grant_check),
        "expired_is_refused": check_grant(
            &grant,
            &owner.public_identity(),
            NOW + 400 * 86_400,
        ).is_err(),
        "wrong_owner_is_refused": check_grant(
            &grant,
            &wrong_owner.public_identity(),
            NOW + 1,
        ).is_err(),
    });

    let mut scaling = Vec::new();
    for &pool_size in &options.pools {
        if pool_size == 0 {
            return Err("--pools must contain positive values".into());
        }
        let mut ledger = NoteLedger::new(key.clone(), NOTE_BITS);
        let mut values = DeterministicRng::new(pool_size as u64);
        let mut planted = scope_names
            .iter()
            .map(|scope| (scope.clone(), 0u64))
            .collect::<std::collections::BTreeMap<_, _>>();
        let stranger = ScopedWallet::new(&mut os_rng);
        for index in 0..pool_size {
            let (address, value) = if index % (options.scopes + 1) == options.scopes {
                (stranger.address("theirs"), values.randrange(1, 500) as u64)
            } else {
                let scope = &scope_names[index % (options.scopes + 1)];
                let value = values.randrange(1, 500) as u64;
                *planted.get_mut(scope).expect("scope exists") += value;
                (owner.address(scope), value)
            };
            // the exact 253-bit rejection sampler so later planted values stay
            // byte-for-byte reproducible.
            let blinding = py_ed25519_scalar(&mut values);
            let note = ledger
                .build_note(
                    &address,
                    value,
                    asset_key.commit_u64(value, &blinding),
                    &blinding,
                    &mut os_rng,
                )
                .expect("valid fixture note encryption");
            ledger.add(note);
        }

        let viewer = owner.grant(&scope_names[0], "an auditor", NOW, 90);
        let mut seen = scan_scope(&ledger, &viewer, &asset_key);
        let mut scan_ms = Vec::new();
        for _ in 0..options.repeats {
            let started = Instant::now();
            seen = scan_scope(&ledger, &viewer, &asset_key);
            scan_ms.push(started.elapsed().as_secs_f64() * 1e3);
        }
        let reached = seen.len();
        let seen_total = total_seen(&seen);
        let planted_total = planted[&scope_names[0]];
        let per_note = scan_ms
            .iter()
            .copied()
            .min_by(f64::total_cmp)
            .unwrap_or(0.0)
            / pool_size as f64;
        let fraction = reached as f64 / pool_size as f64;
        let row = json!({
            "pool": pool_size,
            "scan": timing_summary(&scan_ms),
            "per_note_ms": round_half_even_places(per_note, 4),
            "notes_reached": reached,
            "notes_in_pool": pool_size,
            "fraction_reached": round_half_even_places(fraction, 4),
            "total_seen": seen_total,
            "total_planted_in_that_scope": planted_total,
            "sees_exactly_its_scope": seen_total == planted_total,
            // A viewing grant deliberately has no serial in its return type.
            "serials_recovered": 0,
        });
        println!(
            "pool={pool_size:5}  scan {:7.1} ms ({} ms/note)  reached {reached:4} of {pool_size} = {:.1}%  exact={}  serials=0",
            row["scan"]["median"].as_f64().unwrap_or(0.0),
            row["per_note_ms"],
            fraction * 100.0,
            py_bool(row["sees_exactly_its_scope"].as_bool().unwrap_or(false)),
        );
        scaling.push(row);
    }

    let payload = json!({
        "host": zkfmi_measure::hosts::this_host(),
        "group": "ed25519",
        "scopes": options.scopes,
        "scaling": scaling,
        "grant": grant_json,
    });
    write_pretty_json(Some(&options.out), &payload)?;
    println!("wrote {}", options.out.display());
    Ok(())
}

/// Deterministic rejection sampling over the Ed25519 scalar order.
fn py_ed25519_scalar(rng: &mut DeterministicRng) -> Scalar {
    loop {
        let mut bytes = [0u8; 32];
        for word in 0..7 {
            let value = rng.getrandbits(32) as u32;
            bytes[word * 4..word * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        let value = rng.getrandbits(29) as u32;
        bytes[28..32].copy_from_slice(&value.to_le_bytes());
        if let Some(scalar) = Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)) {
            return scalar;
        }
    }
}

fn round_half_even_places(value: f64, places: i32) -> f64 {
    let scale = 10f64.powi(places);
    qomm_sim::market::round_half_even(value * scale) as f64 / scale
}

fn parse_args() -> HarnessResult<Options> {
    let mut options = Options {
        pools: vec![64, 256, 1_024],
        scopes: 4,
        repeats: 5,
        out: defmi_harness::repo_root().join("artifacts/viewing.json"),
    };
    let raw = std::env::args_os().skip(1).collect::<Vec<_>>();
    let mut index = 0;
    while index < raw.len() {
        match raw[index].to_string_lossy().as_ref() {
            "--scopes" => {
                options.scopes = parse_value(value(&raw, &mut index, "--scopes")?, "--scopes")?
            }
            "--repeats" => {
                options.repeats = parse_value(value(&raw, &mut index, "--repeats")?, "--repeats")?
            }
            "--out" => options.out = PathBuf::from(value(&raw, &mut index, "--out")?),
            "--pools" => {
                options.pools.clear();
                index += 1;
                while index < raw.len() && !raw[index].to_string_lossy().starts_with("--") {
                    options
                        .pools
                        .push(parse_value(raw[index].clone(), "--pools")?);
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

fn py_bool(value: bool) -> &'static str {
    if value {
        "True"
    } else {
        "False"
    }
}
