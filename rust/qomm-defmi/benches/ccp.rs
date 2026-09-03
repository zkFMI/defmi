//! What novation costs once it cannot be lied about.
//!
//! a house could novate trades nobody made, and a member cleared at two houses
//! was not modelled. Closing the first one puts two Ed25519 verifications on
//! every edge, and the prediction written before this ran was that they would
//! dominate --- that the arithmetic would become invisible and the cost would
//! be the signatures.
//!
//! Both halves are timed separately so the prediction can be checked rather
//! than asserted.

use std::collections::BTreeMap;

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{SigningKey, VerifyingKey};
use qomm_defmi::ccp::*;
use qomm_defmi::credit::CreditCtx;
use qomm_measure::{hosts, time_us, Summary};
use qomm_zk::pedersen::Pedersen;
use rand::rngs::OsRng;
use rand::Rng;

const ASSET: &str = "an instrument";
const PARTICIPANTS: usize = 8;

fn shell(program: &str, args: &[&str]) -> String {
    std::process::Command::new(program)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn build(edges: usize, key: &Pedersen) -> (Vec<SignedObligation>, BTreeMap<Vec<u8>, VerifyingKey>) {
    let mut rng = OsRng;
    let mut signing = BTreeMap::new();
    let mut parties = BTreeMap::new();
    let mut members = Vec::new();
    for i in 0..PARTICIPANTS {
        let handle = format!("p{i}").into_bytes();
        let sk = SigningKey::generate(&mut rng);
        parties.insert(handle.clone(), sk.verifying_key());
        signing.insert(handle.clone(), sk);
        members.push(handle);
    }
    let mut graph = Vec::with_capacity(edges);
    for i in 0..edges {
        let payer = members[i % PARTICIPANTS].clone();
        let payee = members[(i + 1) % PARTICIPANTS].clone();
        let obligation = Obligation {
            payer: payer.clone(),
            payee: payee.clone(),
            asset: ASSET.to_string(),
            commitment: key.commit_u64(rng.gen_range(1..1000), &Scalar::random(&mut rng)),
        };
        graph.push(sign_obligation(
            &obligation,
            &signing[&payer],
            &signing[&payee],
        ));
    }
    (graph, parties)
}

fn main() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1").with_value_generator(qomm_zk::pedersen::asset_tag(7));
    let base = Pedersen::new(b"qomm:defmi:v1");
    let ctx = CreditCtx::new(base.clone(), 64);

    println!("DeCCP --- novation, agreement and attestation, {PARTICIPANTS} participants\n");
    println!(
        "{:>7}  {:>14}  {:>14}  {:>14}  {:>14}",
        "edges", "novate us/e", "agree us/e", "check us/e", "attest us"
    );
    let mut rows = Vec::new();

    for edges in [16usize, 64, 256, 1024] {
        let (graph, parties) = build(edges, &key);
        let house = ClearingProvider::new("DeCCP-A", b"house-a", SigningKey::generate(&mut rng));
        let margin = ctx
            .grant(
                b"house-a",
                "cash",
                8_000_000,
                &Scalar::random(&mut rng),
                10_000_000,
                &Scalar::random(&mut rng),
                500,
            )
            .unwrap();
        let mut layer = |v: u64| base.commit_u64(v, &Scalar::random(&mut rng));
        let waterfall = for_provider("DeCCP-A", layer(100), layer(200), layer(400), layer(5_000));
        let mut registry = ClearingRegistry::new();
        registry.admit(&ctx, &house, margin, waterfall).unwrap();

        let repeats = if edges > 256 { 5 } else { 25 };
        let novate = time_us(repeats, || {
            house.novate(&graph).unwrap();
        });
        let novation = house.novate(&graph).unwrap();
        let attest = time_us(repeats, || {
            house.attest(&novation, b"cycle-1");
        });
        let attestation = house.attest(&novation, b"cycle-1");

        let arithmetic = time_us(repeats, || {
            check_novation(&house.handle, &novation).unwrap();
        });
        // and the whole check, which is the arithmetic plus two signatures an edge
        let whole = time_us(repeats, || {
            registry
                .check_cycle(&attestation, &novation, &parties)
                .unwrap();
        });
        let agree_us = (whole.median - arithmetic.median) / edges as f64;

        println!(
            "{edges:>7}  {:>14.3}  {:>14.3}  {:>14.3}  {:>14.1}",
            novate.median / edges as f64,
            agree_us,
            arithmetic.median / edges as f64,
            attest.median
        );
        rows.push(format!(
            "    {{\"edges\": {edges}, \"novate\": {}, \"attest\": {}, \
\"check_arithmetic\": {}, \"check_whole\": {}, \
\"novate_us_per_edge\": {:.4}, \"agreement_us_per_edge\": {:.4}, \
\"arithmetic_us_per_edge\": {:.4}}}",
            novate.json(),
            attest.json(),
            arithmetic.json(),
            whole.json(),
            novate.median / edges as f64,
            agree_us,
            arithmetic.median / edges as f64
        ));
    }

    println!(
        "\nThe arithmetic is the small half. What an edge costs is the two \n\
              signatures that stop a house inventing it."
    );

    if let Ok(path) = std::env::var("QOMM_BENCH_JSON") {
        let json = format!(
            "{{\n  \"host\": \"{}\",\n  \"rustc\": \"{}\",\n  \
\"participants\": {PARTICIPANTS},\n  \
\"what\": \"novation, the two-party agreement check that stops a house \
inventing an edge, and the provider attestation\",\n  \
\"rows\": [\n{}\n  ]\n}}\n",
            std::env::var("QOMM_HOST_LABEL").unwrap_or_else(|_| hosts::this_host()),
            shell("rustc", &["--version"]),
            rows.join(",\n")
        );
        std::fs::write(&path, json).expect("could not write the measurement");
        println!("\nwrote {path}");
    }
    let _: Option<Summary> = None;
}
