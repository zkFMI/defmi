//! replaces. No criterion: the numbers here are medians of plain wall-clock

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_defmi::assets::AssetRegistry;
use qomm_defmi::ledger::Ledger;
use qomm_defmi::settlement::*;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::range::RangeCtx;
use qomm_zkpi::handles::Identity;
use qomm_zkpi::{deal_quorum, frost, Bounds, Issuer, Venue};
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::time::Instant;

const QTY: u64 = 100;
const PRICE: u64 = 99_990;

/// A trade that fits the width being measured. Range-proof cost depends on the
/// width, never on the value inside it, so shrinking the trade to fit a narrow
/// rail does not distort the comparison.
fn trade_for(bits: usize) -> (u64, u64) {
    let ceiling = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let quantity = QTY.min((ceiling / 2).max(1));
    let price = PRICE.min(((ceiling / 2) / quantity).max(1));
    (quantity, price)
}

/// One measured width. Kept as data rather than printed on the spot so the
/// same run can produce both the human table and the JSON the docs are built
/// from --- a number that exists only in stdout is a number that will be
/// retyped by hand into prose, and this project has already been bitten by
/// exactly that.
struct Row {
    bits: usize,
    issue_ms: f64,
    build_ms: f64,
    settle_ms: f64,
    package_bytes: usize,
}

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

fn run(bits: usize, repeats: usize) -> Row {
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

    let mut issue_ms = Vec::new();
    let mut build_ms = Vec::new();
    let mut settle_ms = Vec::new();
    let mut bytes = 0usize;

    let (qty, price) = trade_for(bits);
    for nonce in 0..repeats {
        let asset_key = key.with_value_generator(registry.tags[3]);
        let ceiling = if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        let sec = (5_000u64.max(qty).min(ceiling), Scalar::random(&mut rng));
        let cash_holding = (
            50_000_000u64.max(qty * price).min(ceiling),
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

        let t = Instant::now();
        let (digest, openings, partial) = issuer
            .build(
                qty,
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
        issue_ms.push(t.elapsed().as_secs_f64() * 1e3);

        let (tag, gamma) = registry.blind(3, false, &mut rng).unwrap();
        let t = Instant::now();
        let (pkg, _) = build_package(
            &key,
            instruction,
            &defmi.securities,
            &defmi.cash,
            qty,
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
        bytes = pkg.securities_leg.remainder_range.to_bytes().len()
            + pkg.cash_leg.remainder_range.to_bytes().len()
            + pkg.instruction.range_proof_bytes_len()
            + 32 * (3 + 2 + 3 + 2 + 2 + 2 + 3 + 3)
            + 64
            + 32;

        let t = Instant::now();
        let receipt = defmi.settle(&pkg, 1_000, &mut rng);
        settle_ms.push(t.elapsed().as_secs_f64() * 1e3);
        assert!(receipt.status.is_ok(), "{:?}", receipt.status);
    }
    let row = Row {
        bits,
        issue_ms: median(issue_ms),
        build_ms: median(build_ms),
        settle_ms: median(settle_ms),
        package_bytes: bytes,
    };
    println!("  {:2} bits  issue {:7.3}  build {:7.3}  settle {:7.3} ms  package {:6} B  -> {:8.1} settlements/s per core",
             row.bits, row.issue_ms, row.build_ms, row.settle_ms, row.package_bytes,
             1000.0 / row.settle_ms);
    row
}

/// The yardstick recorded beside every result.
///
/// machine and nothing in the artifact said so. The scalar multiplication is
/// through libsodium, so if the two agree the machine was in the same state and
/// the comparison means something. The range proof is not comparable --- the
/// only takes powers of two --- so it is recorded under its own name.
fn calibration(repeats: usize) -> (f64, f64) {
    let mut rng = OsRng;
    let p = RistrettoPoint::mul_base(&Scalar::random(&mut rng));
    let s = Scalar::random(&mut rng);
    let t = Instant::now();
    let mut acc = p;
    for _ in 0..20_000 {
        acc = p * s;
    }
    std::hint::black_box(acc);
    let scalar_mult_us = t.elapsed().as_secs_f64() / 20_000.0 * 1e6;

    let ctx = RangeCtx::new(64, 1);
    let mut ranges = Vec::new();
    for _ in 0..repeats {
        let blinding = Scalar::random(&mut rng);
        let mut transcript = Transcript::new(b"qomm:defmi:calib");
        let t = Instant::now();
        ctx.prove(&mut transcript, &[1234], &[blinding]).unwrap();
        ranges.push(t.elapsed().as_secs_f64() * 1e3);
    }
    (scalar_mult_us, median(ranges))
}

fn shell(cmd: &str, args: &[&str]) -> String {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn main() {
    let repeats: usize = std::env::var("QOMM_BENCH_REPEATS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25);

    let (scalar_mult_us, range_ms) = calibration(repeats);
    println!(
        "calibration: scalar mult {scalar_mult_us:.2} us, 64-bit range proof {range_ms:.2} ms"
    );
    println!("delivery versus payment, Rust");

    // rounds it up, which is the honest comparison for the deployed width.
    let rows: Vec<Row> = [8usize, 16, 32, 64]
        .iter()
        .map(|b| run(*b, repeats))
        .collect();

    let Ok(path) = std::env::var("QOMM_BENCH_JSON") else {
        return;
    };
    let scaling: Vec<String> = rows
        .iter()
        .map(|r| {
            format!(
        "    {{\"bits\": {}, \"issue_ms\": {:.4}, \"build_ms\": {:.4}, \"settle_ms\": {:.4}, \
\"package_bytes\": {}, \"per_second\": {:.2}}}",
        r.bits, r.issue_ms, r.build_ms, r.settle_ms, r.package_bytes, 1000.0 / r.settle_ms)
        })
        .collect();
    let json = format!(
        "{{\n  \"host\": \"{}\",\n  \"rustc\": \"{}\",\n  \"group\": \"ristretto255\",\n  \
\"quantity\": {},\n  \"price\": {},\n  \"repeats\": {},\n  \
\"calibration\": {{\"scalar_mult_us\": {:.4}, \"range_proof_64bit_ms\": {:.4}}},\n  \
\"scaling\": [\n{}\n  ]\n}}\n",
        std::env::var("QOMM_HOST_LABEL").unwrap_or_else(|_| shell("hostname", &[])),
        shell("rustc", &["--version"]),
        QTY,
        PRICE,
        repeats,
        scalar_mult_us,
        range_ms,
        scaling.join(",\n")
    );
    std::fs::write(&path, json).expect("could not write the benchmark JSON");
    println!("wrote {path}");
}
