//! Agreeing with a book of record, and handing an auditor one slice.
//!
//! Both are linear in the positions and neither opens anything, so the numbers
//! that matter are the slope and the point at which a settlement operator would
//! stop wanting to run it in one go.
//!
//! 175 ms before it, because it was asking a multiscalar routine to multiply by
//! one. The prediction here is that Rust makes the aggregate a few hundred
//! microseconds and the sigma proof becomes the whole cost.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use qomm_defmi::notes::NoteLedger;
use qomm_defmi::reconcile::{check, check_positions, locate_break, prove, Attestation};
use qomm_defmi::viewing::{scan_scope, scope_commitments, total_seen, ScopedWallet};
use qomm_measure::{hosts, time_us};
use qomm_zk::pedersen::{asset_tag, Pedersen};
use rand::rngs::OsRng;
use rand::Rng;

fn shell(program: &str, args: &[&str]) -> String {
    std::process::Command::new(program)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn main() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1").with_value_generator(asset_tag(7));
    let mut rows = Vec::new();

    println!("Reconciling a committed ledger with a stated total\n");
    println!(
        "{:>8}  {:>12}  {:>12}  {:>10}  {:>10}  {:>12}",
        "positions", "prove us", "check us", "agree us", "name us", "locate"
    );
    for n in [16usize, 64, 256, 1024, 4096] {
        let values: Vec<u64> = (0..n).map(|_| rng.gen_range(1..10_000)).collect();
        let blindings: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let commitments: Vec<RistrettoPoint> = values
            .iter()
            .zip(&blindings)
            .map(|(v, r)| key.commit_u64(*v, r))
            .collect();
        let total: u64 = values.iter().sum();
        let attestation = Attestation {
            register: "a book of record".into(),
            account: "omnibus".into(),
            asset: "an instrument".into(),
            total,
            as_of: "2026-08-22T09:00Z".into(),
            signature: None,
        };

        let repeats = if n > 1024 { 9 } else { 25 };
        let build = time_us(repeats, || {
            prove(&key, &commitments, &blindings, &attestation, &mut OsRng).unwrap();
        });
        let reconciliation = prove(&key, &commitments, &blindings, &attestation, &mut rng).unwrap();
        let verify = time_us(repeats, || {
            check(&key, &commitments, &reconciliation, None).unwrap();
        });

        let mut register = values.clone();
        register[n / 3] += 5;
        let broken: u64 = register.iter().sum();
        let search = locate_break(
            &key,
            &commitments,
            &blindings,
            |a, b| Some(register[a..b].iter().sum()),
            broken,
            &mut rng,
        )
        .unwrap();
        // the common case: everything agrees, so one multiscalar settles it
        let agreeing = time_us(repeats, || {
            check_positions(&key, &commitments, &blindings, &values, &mut OsRng);
        });
        // and the day something is wrong, when the list has to be produced
        let naming = time_us(if n > 1024 { 3 } else { 9 }, || {
            check_positions(&key, &commitments, &blindings, &register, &mut OsRng);
        });

        println!(
            "{n:>8}  {:>12.1}  {:>12.1}  {:>10.1}  {:>10.1}  {:>7} proofs",
            build.median, verify.median, agreeing.median, naming.median, search.proofs
        );
        rows.push(format!(
            "    {{\"positions\": {n}, \"prove_us\": {}, \"check_us\": {}, \
\"per_position_agreeing_us\": {}, \"per_position_naming_us\": {}, \
\"locate_proofs\": {}, \
\"locate_two_log_n_plus_one\": {}, \"narrowest_range\": {}, \"found\": {:?}}}",
            build.json(),
            verify.json(),
            agreeing.json(),
            naming.json(),
            search.proofs,
            2 * (usize::BITS - n.leading_zeros() - 1) + 1,
            search.narrowest(),
            search.found
        ));
    }

    // --- one slice of a wallet ------------------------------------------
    println!("\nScanning one scope of a wallet out of a shared pool\n");
    println!(
        "{:>8}  {:>12}  {:>14}  {:>10}  {:>8}",
        "pool", "scan us", "us per note", "reached", "exact"
    );
    let note_key = Pedersen::new(b"qomm:defmi:note:v1");
    let asset = note_key.with_value_generator(asset_tag(3));
    let mut view_rows = Vec::new();
    for pool in [64usize, 256, 1024] {
        let mut ledger = NoteLedger::new(note_key.clone(), 40);
        let owner = ScopedWallet::new(&mut rng);
        let stranger = ScopedWallet::new(&mut rng);
        let scopes = ["2026Q1", "2026Q2", "2026Q3", "2026Q4"];
        let mut planted = 0u64;
        for i in 0..pool {
            let value = rng.gen_range(1..500) as u64;
            let blinding = Scalar::random(&mut rng);
            let address = if i % (scopes.len() + 1) == scopes.len() {
                stranger.address("theirs")
            } else {
                let scope = scopes[i % (scopes.len() + 1)];
                if scope == scopes[0] {
                    planted += value;
                }
                owner.address(scope)
            };
            let note = ledger.build_note(
                &address,
                value,
                asset.commit_u64(value, &blinding),
                &blinding,
                &mut rng,
            );
            ledger.add(note);
        }
        let grant = owner.grant(scopes[0], "an auditor", 1_780_000_000, 90);
        let scan = time_us(5, || {
            scan_scope(&ledger, &grant, &asset);
        });
        let seen = scan_scope(&ledger, &grant, &asset);
        let (commitments, blindings, total) = scope_commitments(&ledger, &grant, &asset);
        let exact = total == planted && total_seen(&seen) == planted;
        println!(
            "{pool:>8}  {:>12.1}  {:>14.3}  {:>4} of {:<4}  {:>8}",
            scan.median,
            scan.median / pool as f64,
            seen.len(),
            pool,
            exact
        );
        view_rows.push(format!(
            "    {{\"pool\": {pool}, \"scan_us\": {}, \"us_per_note\": {:.4}, \
\"notes_reached\": {}, \"sees_exactly_its_scope\": {}, \
\"commitments_for_reconciliation\": {}, \"blindings\": {}}}",
            scan.json(),
            scan.median / pool as f64,
            seen.len(),
            exact,
            commitments.len(),
            blindings.len()
        ));
    }

    if let Ok(path) = std::env::var("QOMM_BENCH_JSON") {
        let json = format!(
            "{{\n  \"host\": \"{}\",\n  \"rustc\": \"{}\",\n  \
\"reconcile\": [\n{}\n  ],\n  \"viewing\": [\n{}\n  ]\n}}\n",
            std::env::var("QOMM_HOST_LABEL").unwrap_or_else(|_| hosts::this_host()),
            shell("rustc", &["--version"]),
            rows.join(",\n"),
            view_rows.join(",\n")
        );
        std::fs::write(&path, json).expect("could not write the measurement");
        println!("\nwrote {path}");
    }
}
