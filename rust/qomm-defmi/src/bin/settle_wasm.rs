//! The settlement verifier, built for the machine and for WebAssembly.
//!
//! Deciding where this can run is a chain question before it is a cryptography
//! question. The EVM offers no curve25519 precompile --- only BN254 --- so a
//! ristretto verification there is interpreted field arithmetic, which measured
//! at eight to eleven verifications per second and 237--318K gas. A chain whose
//! contracts are WebAssembly runs the same compiled code we already have, so
//! what matters is the interpreter's overhead against native, and that is a
//! number rather than an argument.
//!
//! One binary, built twice, so the comparison is the target and not the code.
//! No shell, no files, nothing outside the sandbox: `std::process::Command` does
//! not exist under wasi, and reaching for it is what makes a benchmark
//! unbuildable for the target it is supposed to measure.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use qomm_defmi::assets::AssetRegistry;
use qomm_defmi::chain::ChainState;
use qomm_defmi::ledger::Ledger;
use qomm_defmi::settlement::*;
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::handles::Identity;
use qomm_zkpi::{deal_quorum, frost, Bounds, Issuer, Venue};
use rand_core::OsRng;
use std::collections::BTreeMap;
use std::time::Instant;

/// The two firms, named as the design says: one seed each, a handle for this
/// venue, and account names derived from that handle.
const VENUE: &[u8] = b"defmi:bench";
fn seller() -> RistrettoPoint {
    Identity::from_seed([11u8; 32]).handle(VENUE).point
}
fn buyer() -> RistrettoPoint {
    Identity::from_seed([22u8; 32]).handle(VENUE).point
}

fn median(mut xs: Vec<f64>) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    xs[xs.len() / 2]
}

fn run(bits: usize, repeats: usize) -> (f64, f64, f64, usize, usize) {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key.clone(), 16);
    let (secret, public) = deal_quorum(7, 3, &mut rng).unwrap();
    let shares: BTreeMap<_, _> = secret
        .into_iter()
        .map(|(id, s)| (id, frost::keys::KeyPackage::try_from(s).unwrap()))
        .collect();
    let bounds = Bounds {
        amount_bits: bits,
        price_bits: bits,
        ..Bounds::default()
    };
    let issuer = Issuer::new(key.clone(), bounds.clone());

    let ceiling = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let quantity = 100u64.min((ceiling / 2).max(1));
    let price = 99_990u64.min(((ceiling / 2) / quantity).max(1));

    let mut build_ms = Vec::new();
    let mut settle_ms = Vec::new();
    let mut state_ms = Vec::new();
    // the chain's half: what it holds between settlements and what each one
    // writes. Kept across repeats so the nullifier set grows the way it would
    let mut chain = ChainState::new();
    let accounts = [
        account_of(&seller(), SECURITIES_RAIL),
        account_of(&buyer(), SECURITIES_RAIL),
        account_of(&buyer(), CASH_RAIL),
        account_of(&seller(), CASH_RAIL),
    ];
    for account in &accounts {
        chain.open(account, RistrettoPoint::mul_base(&Scalar::from(1u64)));
    }
    let mut written = 0usize;
    for nonce in 0..repeats {
        let asset_key = key.with_value_generator(registry.tags[3]);
        let sec = (
            5_000u64.max(quantity).min(ceiling),
            Scalar::random(&mut rng),
        );
        let cash_holding = (
            50_000_000u64.max(quantity * price).min(ceiling),
            Scalar::random(&mut rng),
        );
        let mut securities = Ledger::new(key.clone(), bits);
        let mut cash = Ledger::new(key.clone(), bits);
        securities.open(
            &account_of(&seller(), SECURITIES_RAIL),
            asset_key.commit_u64(sec.0, &sec.1),
        );
        securities.open(
            &account_of(&buyer(), SECURITIES_RAIL),
            asset_key.commit_u64(0, &Scalar::random(&mut rng)),
        );
        cash.open(
            &account_of(&buyer(), CASH_RAIL),
            key.commit_u64(cash_holding.0, &cash_holding.1),
        );
        cash.open(
            &account_of(&seller(), CASH_RAIL),
            key.commit_u64(0, &Scalar::random(&mut rng)),
        );
        let venue = Venue::new(key.clone(), &bounds, public.clone());
        let mut defmi = Defmi::new(key.clone(), securities, cash, venue);

        let (digest, openings, partial) = issuer
            .build(
                quantity,
                price,
                3,
                buyer(),  // pays cash, receives securities
                seller(), // delivers securities, receives cash
                1_500,
                [nonce as u8; 32],
                1_599_845,
                &mut rng,
            )
            .unwrap();
        let chosen: Vec<_> = shares.keys().take(3).cloned().collect();
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for id in &chosen {
            let (n, c) = frost::round1::commit(shares[id].signing_share(), &mut rng);
            nonces.insert(*id, n);
            commitments.insert(*id, c);
        }
        let package_sig = frost::SigningPackage::new(commitments, &digest);
        let mut sig_shares = BTreeMap::new();
        for id in &chosen {
            sig_shares.insert(
                *id,
                frost::round2::sign(&package_sig, &nonces[id], &shares[id]).unwrap(),
            );
        }
        let signature = frost::aggregate(&package_sig, &sig_shares, &public).unwrap();
        let instruction = partial.sealed(signature);

        let (tag, gamma) = registry.blind(3, false, &mut rng).unwrap();
        let t = Instant::now();
        let (pkg, _) = build_package(
            &key,
            instruction,
            &defmi.securities,
            &defmi.cash,
            quantity,
            price,
            &Holdings {
                securities_balance: sec.0,
                securities_blinding: sec.1,
                cash_balance: cash_holding.0,
                cash_blinding: cash_holding.1,
            },
            &InstructionOpenings {
                amount: openings.amount,
                price: openings.price,
            },
            Some(&tag),
            &gamma,
            None,
            &Scalar::ZERO,
            &mut rng,
        )
        .unwrap();
        build_ms.push(t.elapsed().as_secs_f64() * 1e3);

        let t = Instant::now();
        let receipt = defmi.settle(&pkg, 1_000, &mut rng);
        settle_ms.push(t.elapsed().as_secs_f64() * 1e3);
        assert!(receipt.status.is_ok(), "{:?}", receipt.status);

        // and the part a contract does once verification has passed
        let mut nullifier = [0u8; 32];
        nullifier[..8].copy_from_slice(&(nonce as u64).to_be_bytes());
        let moves: Vec<(&[u8], RistrettoPoint)> = accounts
            .iter()
            .enumerate()
            .map(|(i, a)| {
                (
                    a.as_slice(),
                    RistrettoPoint::mul_base(&Scalar::from(nonce as u64 + 2 + i as u64)),
                )
            })
            .collect();
        let t = Instant::now();
        let delta = chain.settle(nullifier, 1_000_000, 1, &moves).unwrap();
        let _root = chain.root();
        state_ms.push(t.elapsed().as_secs_f64() * 1e3);
        written = delta.bytes_written;
    }
    (
        median(build_ms),
        median(settle_ms),
        median(state_ms),
        written,
        chain.stored_bytes(),
    )
}

fn main() {
    // the same yardstick every other artifact carries
    let mut rng = OsRng;
    let p = RistrettoPoint::mul_base(&Scalar::random(&mut rng));
    let s = Scalar::random(&mut rng);
    let t = Instant::now();
    let mut acc = p;
    for _ in 0..5_000 {
        acc = p * s;
    }
    std::hint::black_box(acc);
    let calib = t.elapsed().as_secs_f64() / 5_000.0 * 1e6;

    let target = if cfg!(target_arch = "wasm32") {
        "wasm32"
    } else {
        "native"
    };
    println!("target {target}, calibration scalar mult {calib:.2} us");
    let repeats: usize = if cfg!(target_arch = "wasm32") { 5 } else { 15 };
    let mut rows = Vec::new();
    for bits in [32usize, 64] {
        let (build, settle, state, written, held) = run(bits, repeats);
        println!(
            "  {bits:2} bits  build {build:8.3}  settle {settle:8.3}  state {state:7.4} ms  \
{written} B written  -> {:8.1} settlements/s",
            1000.0 / (settle + state)
        );
        rows.push(format!(
            "    {{\"bits\": {bits}, \"build_ms\": {build:.4}, \"settle_ms\": {settle:.4}, \
\"state_ms\": {state:.4}, \"bytes_written\": {written}, \"state_bytes_held\": {held}, \
\"per_second\": {:.2}}}",
            1000.0 / (settle + state)
        ));
    }
    // stdout carries the table for a person; this carries it for the document
    // generator, and writing it from inside the sandbox is the only way the
    // WebAssembly arm can produce one at all.
    if let Ok(path) = std::env::var("QOMM_WASM_JSON") {
        // The host label has to be passed in. Under wasi the sandbox has no
        // host name to read, and a pair of readings whose only difference is
        // supposed to be the target is worthless if it cannot say they were
        // taken on one machine.
        let host = std::env::var("QOMM_HOST_LABEL").unwrap_or_else(|_| "unlabelled".to_string());
        // Which interpreter, for the same reason. The two readings differ by a
        // factor that an earlier pair did not show, and the first thing anyone
        // will ask is whether the runtime moved under it.
        let runtime =
            std::env::var("QOMM_WASM_RUNTIME").unwrap_or_else(|_| "unrecorded".to_string());
        let json = format!(
            "{{\n  \"host\": \"{host}\",\n  \"target\": \"{target}\",\n  \
\"runtime\": \"{runtime}\",\n  \
\"repeats\": {repeats},\n  \
\"calibration\": {{\"scalar_mult_us\": {calib:.4}}},\n  \"scaling\": [\n{}\n  ]\n}}\n",
            rows.join(",\n")
        );
        std::fs::write(&path, json).expect("could not write the measurement");
        println!("wrote {path}");
    }
}
