//! What payment versus payment costs, and how long the second mover is exposed.
//!
//! The cost of the two legs is not the interesting number --- it is two
//! transfers, and `settle.rs` already prices a transfer. The interesting number
//! is the **reaction time**: after the first mover takes the money on ledger A,
//! how long does the second mover need before her claim is final on ledger B?
//!
//! That figure decides the two deadlines, and the gap between the two deadlines
//! *is* this arrangement's Herstatt risk. Set the gap below the reaction time
//! and the second mover can be robbed by a counterparty who simply waits;
//! set it far above and both parties' money is locked up for no reason.
//! Choosing it without measuring is where the loss actually happens.
//!
//! Measured here is the part that is arithmetic --- reading the published
//! signature, recovering the secret, adapting, and the ledger's verification.
//! What is *not* here is the part that belongs to the deployment: how long
//! ledger A takes to make the first claim visible, and how long ledger B takes
//! to accept the second. Those are block times and network round trips, and
//! they are the larger term. The number below is the floor.

use curve25519_dalek::scalar::Scalar;
use qomm_defmi::ledger::{Ledger, Transfer};
use qomm_defmi::pvp::{Leg, Swap};
use qomm_measure::{hosts, time_ms, time_us, Summary};
use qomm_zk::pedersen::Pedersen;
use rand::rngs::OsRng;
use std::time::Instant;

const BITS: usize = 32;
const AMOUNT: u64 = 1_000;
const BALANCE: u64 = 10_000;

fn shell(cmd: &str, args: &[&str]) -> String {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

struct Rail {
    ledger: Ledger,
    blinding: Scalar,
}

fn rail(label: &[u8], rng: &mut OsRng) -> Rail {
    let key = Pedersen::new(label);
    let mut ledger = Ledger::new(key.clone(), BITS);
    let blinding = Scalar::random(rng);
    ledger.open(b"payer", key.commit_u64(BALANCE, &blinding));
    ledger.open(b"payee", key.commit_u64(0, &Scalar::random(rng)));
    Rail { ledger, blinding }
}

fn transfer(rail: &Rail, rng: &mut OsRng) -> Transfer {
    rail.ledger
        .build_transfer(
            BALANCE,
            &rail.blinding,
            AMOUNT,
            b"pvp",
            None,
            &Scalar::ZERO,
            false,
            rng,
        )
        .unwrap()
        .0
}

/// One whole swap, timed in the four places it can be timed.
struct Timings {
    prepare_ms: Vec<f64>,
    claim_ms: Vec<f64>,
    react_ms: Vec<f64>,
    unwind_us: Vec<f64>,
}

fn run(repeats: usize) -> Timings {
    let mut rng = OsRng;
    let mut t = Timings {
        prepare_ms: vec![],
        claim_ms: vec![],
        react_ms: vec![],
        unwind_us: vec![],
    };

    for _ in 0..repeats {
        let (bob, _) = Swap::proposer(&mut rng);
        let mut alice = Swap::responder(bob.adaptor_point);
        let mut a = rail(b"qomm:defmi:jpy", &mut rng);
        let mut b = rail(b"qomm:defmi:usd", &mut rng);
        let (ta, tb) = (transfer(&a, &mut rng), transfer(&b, &mut rng));

        // Preparing: the transfer is already built, so this is the ledger's
        // check plus moving the amount out of the payer's account.
        let start = Instant::now();
        let leg_a: Leg = alice
            .prepare(
                &mut a.ledger,
                b"A",
                b"payer",
                b"payee",
                &Scalar::random(&mut rng),
                &ta,
                b"pvp",
                false,
                100,
                &mut rng,
            )
            .unwrap();
        t.prepare_ms.push(start.elapsed().as_secs_f64() * 1e3);

        let leg_b: Leg = bob
            .prepare(
                &mut b.ledger,
                b"B",
                b"payer",
                b"payee",
                &Scalar::random(&mut rng),
                &tb,
                b"pvp",
                false,
                160,
                &mut rng,
            )
            .unwrap();

        // The first mover claims. This is what appears on ledger A.
        let start = Instant::now();
        let published = bob.claim(&mut a.ledger, &leg_a, 90).unwrap();
        t.claim_ms.push(start.elapsed().as_secs_f64() * 1e3);

        // The reaction: everything the second mover does between seeing that
        // signature and being paid. This is the quantity the deadline gap has
        // to cover, less the network and the block times.
        let start = Instant::now();
        let secret = alice.learn(&leg_a, &published);
        alice
            .claim_with(&mut b.ledger, &leg_b, &secret, 120)
            .unwrap();
        t.react_ms.push(start.elapsed().as_secs_f64() * 1e3);

        assert!(a.ledger.conserved() && b.ledger.conserved());
    }

    // Unwinding is measured on its own: it needs an escrow that is left alone.
    for _ in 0..repeats {
        let (_, adaptor) = Swap::proposer(&mut rng);
        let swap = Swap::responder(adaptor.point);
        let mut a = rail(b"qomm:defmi:jpy", &mut rng);
        let ta = transfer(&a, &mut rng);
        let leg = swap
            .prepare(
                &mut a.ledger,
                b"A",
                b"payer",
                b"payee",
                &Scalar::random(&mut rng),
                &ta,
                b"pvp",
                false,
                100,
                &mut rng,
            )
            .unwrap();
        let start = Instant::now();
        swap.unwind(&mut a.ledger, &leg, 101).unwrap();
        t.unwind_us.push(start.elapsed().as_secs_f64() * 1e6);
    }
    t
}

fn json(name: &str, s: &Summary) -> String {
    format!(
        "    \"{name}\": {{\"n\": {}, \"mean\": {:.6}, \"sd\": {}, \
             \"median\": {:.6}, \"min\": {:.6}, \"max\": {:.6}}}",
        s.n,
        s.mean,
        s.sd.map_or("null".to_string(), |v| format!("{v:.6}")),
        s.median,
        s.min,
        s.max
    )
}

fn main() {
    let repeats: usize = std::env::var("QOMM_BENCH_REPEATS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25);

    // The calibration every artifact in this project carries, so a reading here
    // can be compared with one taken on another day or another machine.
    let mut rng = OsRng;
    let key = Pedersen::new(b"calibration");
    let point = key.g;
    let scalar = Scalar::random(&mut rng);
    let scalar_mult = time_us(200, || {
        std::hint::black_box(point * scalar);
    });

    let t = run(repeats);
    let prepare = Summary::of(&t.prepare_ms).unwrap();
    let claim = Summary::of(&t.claim_ms).unwrap();
    let react = Summary::of(&t.react_ms).unwrap();
    let unwind = Summary::of(&t.unwind_us).unwrap();

    println!("calibration: scalar mult {scalar_mult}");
    println!("payment versus payment, two ledgers, {BITS}-bit rails");
    println!("  prepare one leg        {prepare} ms");
    println!("  first mover's claim    {claim} ms");
    println!("  second mover's react   {react} ms   <- the deadline gap must exceed this");
    println!("  unwind an expired leg  {unwind} us");
    println!();
    println!("  The gap between the two deadlines is this arrangement's Herstatt");
    println!("  exposure. The figure above is its floor: it excludes the time for");
    println!("  ledger A to publish and ledger B to accept, which is the larger term.");

    let Ok(path) = std::env::var("QOMM_BENCH_JSON") else {
        return;
    };
    let json = format!(
        "{{\n  \"host\": \"{}\",\n  \"rustc\": \"{}\",\n  \"group\": \"ristretto255\",\n  \
         \"rail_bits\": {BITS},\n  \"amount\": {AMOUNT},\n  \"repeats\": {repeats},\n  \
         \"calibration\": {{{}}},\n  \"milliseconds\": {{\n{}\n  }},\n  \
         \"microseconds\": {{\n{}\n  }},\n  \
         \"note\": \"react is the floor on the deadline gap: it excludes the time for \
one ledger to publish and the other to accept\"\n}}\n",
        std::env::var("QOMM_HOST_LABEL").unwrap_or_else(|_| hosts::this_host()),
        shell("rustc", &["--version"]),
        json("scalar_mult_us", &scalar_mult).trim_start(),
        [
            json("prepare", &prepare),
            json("claim", &claim),
            json("react", &react)
        ]
        .join(",\n"),
        json("unwind", &unwind)
    );
    std::fs::write(&path, json).expect("could not write the benchmark JSON");
    println!("wrote {path}");
    let _ = time_ms(1, || {});
}
