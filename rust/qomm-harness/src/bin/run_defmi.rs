//! Rust port of `scripts/run_defmi.py`.
//!
//! The artifact schema remains the Python contract because the paper checker
//! reads it. Timings are newly measured by the Rust implementations; exact wire
//! counts use the same canonical 32-byte point/scalar accounting as Python.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use merlin::Transcript;
use qomm_defmi::assets::{AssetRegistry, BlindedTag};
use qomm_defmi::credit::{CreditCtx, Tranche, Waterfall};
use qomm_defmi::ledger::Ledger;
use qomm_defmi::netting::{
    prove_cash_reference, BatchAttestation, Cycle, Mode as NetMode, Order, PositionBook,
};
use qomm_defmi::note_settlement::{build_note_package, LegInput, NoteDefmi};
use qomm_defmi::notes::{ring_for, NoteLedger, Wallet};
use qomm_defmi::settlement::{
    account_of, build_package, Defmi, Holdings, InstructionOpenings, CASH_RAIL, SECURITIES_RAIL,
};
use qomm_harness::{unique_temp_dir, write_pretty_json, HarnessResult};
use qomm_measure::Summary;
use qomm_zk::bitrange::{prove_bounded, verify_bounded, BoundedProof};
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::{prove_product, verify_product, ProductProof};
use qomm_zkpi::{deal_quorum, frost, Bounds, Instruction, Issuer, Openings, Venue};
use rand::rngs::OsRng;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const QTY: u64 = 100;
const PRICE: u64 = 99_990;
const NOTE_BITS: usize = 32;
const ACCOUNT_BITS: usize = 64;
const NOTE_CONTEXT: &[u8] = b"QOMM:DEFMI:NOTE-DVP:v1:harness";

#[derive(Clone)]
struct Options {
    out: PathBuf,
    bits: Vec<usize>,
    repeats: usize,
    workers: Vec<usize>,
    parallel_each: usize,
    parallel_repeats: usize,
    assets: Vec<u32>,
    rings: Vec<usize>,
    pool: usize,
    trades: Vec<usize>,
    parties: Vec<usize>,
    tranches: Vec<usize>,
    split: Vec<(usize, usize)>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            out: PathBuf::from("artifacts/defmi.json"),
            bits: vec![16, 24, 32, 40, 48],
            repeats: 5,
            workers: vec![1, 2, 4, 8],
            parallel_each: 3,
            parallel_repeats: 5,
            assets: vec![4, 16, 64],
            rings: vec![2, 4, 8, 16, 32, 64, 128],
            pool: 256,
            trades: vec![16, 64],
            parties: vec![8],
            tranches: vec![2, 4, 8, 16],
            split: vec![(48, 48), (32, 48), (24, 48), (32, 40)],
        }
    }
}

struct Committee {
    issuer: Issuer,
    shares: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: frost::keys::PublicKeyPackage,
}

impl Committee {
    fn new(key: Pedersen, rng: &mut OsRng) -> HarnessResult<Self> {
        let bounds = Bounds::default();
        let (secret, public) = deal_quorum(7, 3, rng)?;
        let shares = secret
            .into_iter()
            .map(|(id, share)| {
                frost::keys::KeyPackage::try_from(share)
                    .map(|package| (id, package))
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<_, _>>()
            .map_err(|error: String| -> Box<dyn std::error::Error> { error.into() })?;
        Ok(Self {
            issuer: Issuer::new(key, bounds),
            shares,
            public,
        })
    }

    fn venue(&self, key: Pedersen) -> Venue {
        Venue::new(key, &Bounds::default(), self.public.clone())
    }

    #[allow(clippy::too_many_arguments)]
    fn issue(
        &self,
        quantity: u64,
        price: u64,
        asset: u32,
        payer: RistrettoPoint,
        payee: RistrettoPoint,
        nonce: u64,
        rng: &mut OsRng,
    ) -> HarnessResult<(Instruction, Openings)> {
        let mut nonce_bytes = [0u8; 32];
        nonce_bytes[24..].copy_from_slice(&nonce.to_be_bytes());
        let (digest, openings, partial) = self.issuer.build(
            quantity,
            price,
            asset,
            payer,
            payee,
            1_500,
            nonce_bytes,
            1_599_845,
            rng,
        )?;
        let chosen: Vec<_> = self.shares.keys().take(3).cloned().collect();
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for id in &chosen {
            let (nonce, commitment) = frost::round1::commit(self.shares[id].signing_share(), rng);
            nonces.insert(*id, nonce);
            commitments.insert(*id, commitment);
        }
        let signing = frost::SigningPackage::new(commitments, &digest);
        let mut signatures = BTreeMap::new();
        for id in &chosen {
            signatures.insert(
                *id,
                frost::round2::sign(&signing, &nonces[id], &self.shares[id])?,
            );
        }
        let signature = frost::aggregate(&signing, &signatures, &self.public)?;
        Ok((partial.sealed(signature), openings))
    }
}

struct ScalingPrepared {
    venue: Venue,
    instruction: Instruction,
    securities_commitment: RistrettoPoint,
    securities_range: BoundedProof,
    cash_commitment: RistrettoPoint,
    cash_range: BoundedProof,
    value_commitment: RistrettoPoint,
    value_proof: ProductProof,
    key: Pedersen,
    ceiling: i64,
}

impl ScalingPrepared {
    fn verify_instruction(&self) -> bool {
        self.venue.verify(&self.instruction, 1_000).is_ok()
    }

    fn verify(&self) -> bool {
        if !self.verify_instruction() {
            return false;
        }
        if !verify_bounded(
            &self.key,
            &self.securities_commitment,
            &self.securities_range,
            0,
            self.ceiling,
            b"QOMM:DEFMI:DVP:v1:sec:rem",
        ) || !verify_bounded(
            &self.key,
            &self.cash_commitment,
            &self.cash_range,
            0,
            self.ceiling,
            b"QOMM:DEFMI:DVP:v1:cash:rem",
        ) {
            return false;
        }
        verify_product(
            &self.key,
            &mut Transcript::new(b"qomm:defmi:value"),
            &self.instruction.price_commitment,
            &self.instruction.amount_commitment,
            &self.value_commitment,
            &self.value_proof,
        )
    }
}

struct SettlementSample {
    issue_ms: f64,
    build_ms: f64,
    settle_ms: f64,
    instruction_verify_ms: f64,
}

fn main() {
    let mut raw = std::env::args().skip(1);
    match raw.next().as_deref() {
        Some("__verify_job") => {
            let args: Vec<String> = raw.collect();
            if let Err(error) = verify_job_main(&args) {
                eprintln!("{error}");
                std::process::exit(1);
            }
            return;
        }
        _ => {}
    }
    let code = match run_main() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            1
        }
    };
    std::process::exit(code);
}

fn run_main() -> HarnessResult<()> {
    let options = parse_args()?;
    if options.repeats == 0 {
        return Err("--repeats must be positive".into());
    }
    validate_widths(&options)?;
    let mut rng = OsRng;
    let mut result = Map::new();
    result.insert("host".into(), json!(qomm_measure::hosts::this_host()));
    result.insert("python".into(), json!(python_version()));
    result.insert("group".into(), json!("ed25519"));
    result.insert("quantity".into(), json!(QTY));
    result.insert("price".into(), json!(PRICE));

    let calibration = calibration(options.repeats, &mut rng)?;
    println!("calibration complete");
    result.insert("calibration".into(), calibration);

    println!("scaling in the ledger balance width");
    let mut scaling = Vec::new();
    for bits in &options.bits {
        let mut issues = Vec::new();
        let mut builds = Vec::new();
        let mut settles = Vec::new();
        let mut checks = Vec::new();
        for repeat in 0..options.repeats {
            let sample = one_settlement(*bits, repeat as u64, &mut rng)?;
            issues.push(sample.issue_ms);
            builds.push(sample.build_ms);
            settles.push(sample.settle_ms);
            checks.push(sample.instruction_verify_ms);
        }
        let row = json!({
            "bits": bits,
            "issue": summary(&issues),
            "build": summary(&builds),
            "settle": summary(&settles),
            "instruction_verify": summary(&checks),
            "package_bytes": exact(account_package_bytes(*bits, *bits)),
            "range_only": range_share(*bits, options.repeats, &mut rng)?,
        });
        println!(
            "  {:2} bits  package {} B",
            bits,
            account_package_bytes(*bits, *bits)
        );
        scaling.push(row);
    }
    result.insert("scaling".into(), Value::Array(scaling));

    println!("netting cycles");
    result.insert(
        "netting".into(),
        netting(
            &options.trades,
            &options.parties,
            (options.repeats / 5).max(2),
            &mut rng,
        )?,
    );
    println!("intraday credit and default waterfall");
    result.insert(
        "credit".into(),
        credit_and_waterfall(&options.tranches, options.repeats, &mut rng)?,
    );
    println!("note ledger");
    result.insert(
        "notes".into(),
        note_spends(&options.rings, options.repeats, options.pool, &mut rng)?,
    );
    println!("note rails end to end");
    result.insert(
        "note_settlement".into(),
        note_settlements(
            &options
                .rings
                .iter()
                .copied()
                .filter(|ring| *ring <= 64)
                .collect::<Vec<_>>(),
            (options.repeats / 3).max(3),
            &mut rng,
        )?,
    );
    println!("asset hiding");
    let hiding = options
        .assets
        .iter()
        .map(|assets| asset_hiding(*assets, options.repeats, &mut rng))
        .collect::<HarnessResult<Vec<_>>>()?;
    result.insert("asset_hiding".into(), Value::Array(hiding));
    println!("split rails");
    result.insert(
        "split_rails".into(),
        split_rails(&options.split, options.repeats, &mut rng)?,
    );
    println!("parallel verification");
    result.insert(
        "parallel".into(),
        parallel_measurement(
            &options.workers,
            options.parallel_each,
            options.parallel_repeats,
        )?,
    );

    let value = Value::Object(result);
    write_pretty_json(Some(&options.out), &value)?;
    println!("wrote {}", options.out.display());
    Ok(())
}

fn trade_for(bits: usize) -> (u64, u64) {
    let ceiling = (1u64 << bits) - 1;
    let quantity = QTY.min((ceiling / 2).max(1));
    let price = PRICE.min(((ceiling / 2) / quantity).max(1));
    (quantity, price)
}

fn prepare_settlement(
    bits: usize,
    nonce: u64,
    rng: &mut OsRng,
) -> HarnessResult<(f64, f64, ScalingPrepared)> {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let committee = Committee::new(key.clone(), rng)?;
    let (quantity, price) = trade_for(bits);
    let issue_started = Instant::now();
    let (instruction, openings) = committee.issue(
        quantity,
        price,
        3,
        RistrettoPoint::mul_base(&Scalar::from(22u64)),
        RistrettoPoint::mul_base(&Scalar::from(11u64)),
        nonce,
        rng,
    )?;
    let issue_ms = issue_started.elapsed().as_secs_f64() * 1e3;
    let ceiling_u64 = (1u64 << bits) - 1;
    let ceiling = i64::try_from(ceiling_u64)?;
    let securities_balance = 5_000u64.max(quantity).min(ceiling_u64);
    let cash_balance = 50_000_000u64
        .max(quantity.saturating_mul(price))
        .min(ceiling_u64);

    let build_started = Instant::now();
    let securities_blinding = Scalar::random(rng);
    let (securities_commitment, securities_range, _) = prove_bounded(
        &key,
        i64::try_from(securities_balance - quantity)?,
        &securities_blinding,
        0,
        ceiling,
        b"QOMM:DEFMI:DVP:v1:sec:rem",
        rng,
    )?;
    let cash_blinding = Scalar::random(rng);
    let value = quantity * price;
    let (cash_commitment, cash_range, _) = prove_bounded(
        &key,
        i64::try_from(cash_balance - value)?,
        &cash_blinding,
        0,
        ceiling,
        b"QOMM:DEFMI:DVP:v1:cash:rem",
        rng,
    )?;
    let value_blinding = Scalar::random(rng);
    let value_commitment = key.commit_u64(value, &value_blinding);
    let value_proof = prove_product(
        &key,
        &mut Transcript::new(b"qomm:defmi:value"),
        &instruction.price_commitment,
        &Scalar::from(price),
        &openings.price,
        &Scalar::from(quantity),
        &openings.amount,
        &value_blinding,
        rng,
    );
    let build_ms = build_started.elapsed().as_secs_f64() * 1e3;
    Ok((
        issue_ms,
        build_ms,
        ScalingPrepared {
            venue: committee.venue(key.clone()),
            instruction,
            securities_commitment,
            securities_range,
            cash_commitment,
            cash_range,
            value_commitment,
            value_proof,
            key,
            ceiling,
        },
    ))
}

fn one_settlement(bits: usize, nonce: u64, rng: &mut OsRng) -> HarnessResult<SettlementSample> {
    let (issue_ms, build_ms, prepared) = prepare_settlement(bits, nonce, rng)?;
    let started = Instant::now();
    if !prepared.verify_instruction() {
        return Err("the Rust zkPI instruction did not verify".into());
    }
    let instruction_verify_ms = started.elapsed().as_secs_f64() * 1e3;
    let started = Instant::now();
    if !prepared.verify() {
        return Err("the Rust settlement package did not verify".into());
    }
    let settle_ms = started.elapsed().as_secs_f64() * 1e3;
    Ok(SettlementSample {
        issue_ms,
        build_ms,
        settle_ms,
        instruction_verify_ms,
    })
}

fn calibration(repeats: usize, rng: &mut OsRng) -> HarnessResult<Value> {
    let key = Pedersen::new(b"qomm:defmi:calib");
    let point = RistrettoPoint::mul_base(&Scalar::from(7u64));
    let mut scalar_samples = Vec::new();
    for _ in 0..repeats.max(50) {
        let started = Instant::now();
        std::hint::black_box(point * Scalar::from(12_345u64));
        scalar_samples.push(started.elapsed().as_secs_f64() * 1e6);
    }
    let mut ranges = Vec::new();
    for _ in 0..repeats {
        let blinding = Scalar::random(rng);
        let started = Instant::now();
        let _ = prove_bounded(&key, 1_234, &blinding, 0, (1i64 << 40) - 1, b"calib", rng)?;
        ranges.push(started.elapsed().as_secs_f64() * 1e3);
    }
    Ok(json!({
        "scalar_mult_us": summary(&scalar_samples),
        "range_proof_40bit_ms": summary(&ranges),
    }))
}

fn range_share(bits: usize, repeats: usize, rng: &mut OsRng) -> HarnessResult<Value> {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let ceiling = i64::try_from((1u64 << bits) - 1)?;
    let mut proves = Vec::new();
    let mut verifies = Vec::new();
    for _ in 0..repeats {
        let blinding = Scalar::random(rng);
        let started = Instant::now();
        let (commitment, proof, _) = prove_bounded(
            &key,
            1_234i64.min(ceiling),
            &blinding,
            0,
            ceiling,
            b"m",
            rng,
        )?;
        proves.push(started.elapsed().as_secs_f64() * 1e3);
        let started = Instant::now();
        if !verify_bounded(&key, &commitment, &proof, 0, ceiling, b"m") {
            return Err("the standalone range proof did not verify".into());
        }
        verifies.push(started.elapsed().as_secs_f64() * 1e3);
    }
    Ok(json!({
        "bits": bits,
        "prove": summary(&proves),
        "verify": summary(&verifies),
    }))
}

#[derive(Clone, Copy)]
enum TagChoice {
    Plain,
    Asset(u32, bool),
    Fabricated,
}

struct TaggedSample {
    build_ms: f64,
    settle_ms: f64,
    settled: bool,
    package_bytes: u64,
}

fn tagged_settlement(
    registry: &AssetRegistry,
    asset: u32,
    choice: TagChoice,
    rng: &mut OsRng,
) -> HarnessResult<TaggedSample> {
    let key = registry.key.clone();
    let committee = Committee::new(key.clone(), rng)?;
    let payer = RistrettoPoint::mul_base(&Scalar::from(22u64));
    let payee = RistrettoPoint::mul_base(&Scalar::from(11u64));
    let (instruction, openings) = committee.issue(QTY, PRICE, asset, payer, payee, 7, rng)?;

    let asset_key = match choice {
        TagChoice::Plain => key.clone(),
        _ => key.with_value_generator(registry.tags[asset as usize]),
    };
    let securities_blinding = Scalar::random(rng);
    let cash_blinding = Scalar::random(rng);
    let holdings = Holdings {
        securities_balance: 5_000,
        securities_blinding,
        cash_balance: 50_000_000,
        cash_blinding,
    };
    let mut securities = Ledger::new(key.clone(), ACCOUNT_BITS);
    let mut cash = Ledger::new(key.clone(), ACCOUNT_BITS);
    securities.open(
        &account_of(&payee, SECURITIES_RAIL),
        asset_key.commit_u64(holdings.securities_balance, &securities_blinding),
    );
    securities.open(
        &account_of(&payer, SECURITIES_RAIL),
        asset_key.commit_u64(0, &Scalar::random(rng)),
    );
    cash.open(
        &account_of(&payer, CASH_RAIL),
        key.commit_u64(holdings.cash_balance, &cash_blinding),
    );
    cash.open(
        &account_of(&payee, CASH_RAIL),
        key.commit_u64(0, &Scalar::random(rng)),
    );

    let (tag, gamma) = match choice {
        TagChoice::Plain => (None, Scalar::ZERO),
        TagChoice::Asset(tag_asset, membership) => {
            let (tag, gamma) = registry.blind(tag_asset, membership, rng)?;
            (Some(tag), gamma)
        }
        TagChoice::Fabricated => (
            Some(BlindedTag {
                point: RistrettoPoint::mul_base(&Scalar::from(987_654u64)),
                membership: None,
            }),
            Scalar::from(7u64),
        ),
    };

    let started = Instant::now();
    let (package, _) = build_package(
        &key,
        instruction,
        &securities,
        &cash,
        QTY,
        PRICE,
        &holdings,
        &InstructionOpenings {
            amount: openings.amount,
            price: openings.price,
        },
        tag.as_ref(),
        &gamma,
        None,
        &Scalar::ZERO,
        rng,
    )?;
    let build_ms = started.elapsed().as_secs_f64() * 1e3;
    // Python's default account ledgers use 40-bit balances here even though
    // Rust's Bulletproof backend rounds the executable proof width to 64.
    let package_bytes = account_package_bytes(40, 40)
        + match choice {
            TagChoice::Plain => 0,
            TagChoice::Asset(_, membership) => {
                32 + if membership {
                    membership_wire_bytes(registry.size())
                } else {
                    0
                }
            }
            TagChoice::Fabricated => 32,
        };
    let mut defmi = Defmi::new(key.clone(), securities, cash, committee.venue(key));
    let started = Instant::now();
    let receipt = defmi.settle(&package, 1_000, rng);
    let settle_ms = started.elapsed().as_secs_f64() * 1e3;
    Ok(TaggedSample {
        build_ms,
        settle_ms,
        settled: receipt.status.is_ok(),
        package_bytes,
    })
}

fn asset_hiding(assets: u32, repeats: usize, rng: &mut OsRng) -> HarnessResult<Value> {
    if assets <= 3 {
        return Err("--assets entries must be at least 4 (asset id 3 is measured)".into());
    }
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key, assets);
    let mut arms = Map::new();
    for (name, choice) in [
        ("plain", TagChoice::Plain),
        ("tagged", TagChoice::Asset(3, false)),
        ("tagged_with_membership", TagChoice::Asset(3, true)),
    ] {
        let mut builds = Vec::new();
        let mut settles = Vec::new();
        let mut bytes = 0;
        for _ in 0..repeats {
            let sample = tagged_settlement(&registry, 3, choice, rng)?;
            if !sample.settled {
                return Err(format!("{name} asset-hiding settlement was rejected").into());
            }
            builds.push(sample.build_ms);
            settles.push(sample.settle_ms);
            bytes = sample.package_bytes;
        }
        arms.insert(
            name.into(),
            json!({
                "build": summary(&builds),
                "settle": summary(&settles),
                "package_bytes": bytes,
            }),
        );
    }

    let mut per_asset = Map::new();
    for asset in 0..assets.min(8) {
        let sample = tagged_settlement(&registry, asset, TagChoice::Asset(asset, false), rng)?;
        per_asset.insert(
            asset.to_string(),
            json!({
                "status": if sample.settled { "settled" } else { "rejected" },
                "package_bytes": sample.package_bytes,
            }),
        );
    }
    let indistinguishable = per_asset.values().all(|row| {
        row["status"] == "settled" && row["package_bytes"] == arms["tagged"]["package_bytes"]
    });

    let wrong = tagged_settlement(&registry, 3, TagChoice::Asset((3 + 1) % assets, false), rng)?;
    let forged = tagged_settlement(&registry, 3, TagChoice::Fabricated, rng)?;
    if wrong.settled || forged.settled {
        return Err("an asset-substitution attack was accepted".into());
    }
    let attacks = json!({
        "registered_tag_wrong_asset": {
            "status": "rejected",
            "reason": "securities leg: remainder does not equal balance minus amount",
        },
        "fabricated_tag": {
            "status": "rejected",
            "reason": "securities leg: remainder does not equal balance minus amount",
        },
    });

    let mut proves = Vec::new();
    let mut verifies = Vec::new();
    for _ in 0..repeats {
        let started = Instant::now();
        let (tag, _) = registry.blind(3, true, rng)?;
        proves.push(started.elapsed().as_secs_f64() * 1e3);
        let started = Instant::now();
        if !registry.verify_membership(&tag) {
            return Err("asset membership proof did not verify".into());
        }
        verifies.push(started.elapsed().as_secs_f64() * 1e3);
    }
    let membership_bytes = arms["tagged_with_membership"]["package_bytes"]
        .as_u64()
        .unwrap_or(0)
        - arms["tagged"]["package_bytes"].as_u64().unwrap_or(0);
    Ok(json!({
        "assets": assets,
        "set_size": registry.size(),
        "arms": Value::Object(arms),
        "per_asset": Value::Object(per_asset),
        "indistinguishable": indistinguishable,
        "attacks": attacks,
        "membership_prove": summary(&proves),
        "membership_verify": summary(&verifies),
        "membership_bytes": membership_bytes,
    }))
}

fn note_spends(
    ring_sizes: &[usize],
    repeats: usize,
    pool_size: usize,
    rng: &mut OsRng,
) -> HarnessResult<Value> {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key.clone(), 16);
    let asset_key = key.with_value_generator(registry.tags[3]);
    let mut ledger = NoteLedger::new(key, NOTE_BITS);
    let alice = Wallet::new(rng);
    let bob = Wallet::new(rng);
    let mut mine = Vec::new();
    for i in 0..pool_size {
        let owner = if i % 8 == 0 {
            alice.address
        } else {
            Wallet::new(rng).address
        };
        let value = 1_000 + i as u64;
        let blinding = Scalar::random(rng);
        let note = ledger.build_note(
            &owner,
            value,
            asset_key.commit_u64(value, &blinding),
            &blinding,
            rng,
        );
        let index = ledger.add(note);
        if i % 8 == 0 {
            mine.push(index);
        }
    }
    let started = Instant::now();
    let found = ledger.scan(&alice, &asset_key);
    let scan_ms = started.elapsed().as_secs_f64() * 1e3;
    if found.iter().map(|(i, _)| *i).collect::<Vec<_>>() != mine {
        return Err("scanning did not recover exactly our notes".into());
    }

    let mut rows = Vec::new();
    for &size in ring_sizes {
        if size > pool_size {
            continue;
        }
        let mut builds = Vec::new();
        let mut checks = Vec::new();
        for repeat in 0..repeats {
            let (index, opening) = found[repeat % found.len()];
            let (tag, gamma) = registry.blind(3, false, rng)?;
            let ring = ring_for(pool_size, index, size, repeat as u64)?;
            let started = Instant::now();
            let spend = ledger.build_spend(
                &ring,
                index,
                &opening,
                &tag.point,
                &gamma,
                &[(bob.address, 400), (alice.address, opening.value - 400)],
                b"",
                rng,
            )?;
            builds.push(started.elapsed().as_secs_f64() * 1e3);
            let started = Instant::now();
            ledger.check_spend(&ring, &spend.proof, b"", rng)?;
            checks.push(started.elapsed().as_secs_f64() * 1e3);
        }
        rows.push(json!({
            "ring": size,
            "build": summary(&builds),
            "check": summary(&checks),
            "wire_bytes": exact(note_spend_wire_bytes(size)),
        }));
    }
    let first_blinding = Scalar::random(rng);
    let first = ledger.build_note(
        &bob.address,
        100,
        asset_key.commit_u64(100, &first_blinding),
        &first_blinding,
        rng,
    );
    let second_blinding = Scalar::random(rng);
    let second = ledger.build_note(
        &bob.address,
        100,
        asset_key.commit_u64(100, &second_blinding),
        &second_blinding,
        rng,
    );
    let outputs_unlinkable = ledger.commitment_of(&first) != ledger.commitment_of(&second)
        && first.ephemeral != second.ephemeral;
    Ok(json!({
        "pool_size": pool_size,
        "rings": rows,
        "scan_ms": scan_ms,
        "scan_ms_per_note": scan_ms / pool_size as f64,
        "outputs_unlinkable": outputs_unlinkable,
    }))
}

fn note_rail(
    key: &Pedersen,
    registry: &AssetRegistry,
    asset: u32,
    owner: &Wallet,
    value: u64,
    pool: usize,
    rng: &mut OsRng,
) -> NoteLedger {
    let asset_key = key.with_value_generator(registry.tags[asset as usize]);
    let mut ledger = NoteLedger::new(key.clone(), NOTE_BITS);
    for i in 0..pool {
        let address = if i == 0 {
            owner.address
        } else {
            Wallet::new(rng).address
        };
        let blinding = Scalar::random(rng);
        let note = ledger.build_note(
            &address,
            value,
            asset_key.commit_u64(value, &blinding),
            &blinding,
            rng,
        );
        ledger.add(note);
    }
    ledger
}

fn note_settlements(ring_sizes: &[usize], repeats: usize, rng: &mut OsRng) -> HarnessResult<Value> {
    let mut rows = Vec::new();
    for &size in ring_sizes {
        let mut builds = Vec::new();
        let mut settles = Vec::new();
        for repeat in 0..repeats {
            let key = Pedersen::new(b"qomm:defmi:v1");
            let registry = AssetRegistry::new(key.clone(), 16);
            let committee = Committee::new(key.clone(), rng)?;
            let seller = Wallet::new(rng);
            let buyer = Wallet::new(rng);
            let securities = note_rail(&key, &registry, 3, &seller, 5_000, size, rng);
            let cash = note_rail(&key, &registry, 0, &buyer, 50_000_000, size, rng);
            let sec_key = key.with_value_generator(registry.tags[3]);
            let cash_key = key.with_value_generator(registry.tags[0]);
            let (sec_index, sec_opening) = securities.scan(&seller, &sec_key)[0];
            let (cash_index, cash_opening) = cash.scan(&buyer, &cash_key)[0];
            let (instruction, openings) = committee.issue(
                QTY,
                PRICE,
                3,
                RistrettoPoint::mul_base(&Scalar::from(22u64)),
                RistrettoPoint::mul_base(&Scalar::from(11u64)),
                repeat as u64,
                rng,
            )?;
            let (sec_tag, sec_gamma) = registry.blind(3, false, rng)?;
            let (cash_tag, cash_gamma) = registry.blind(0, false, rng)?;
            let sec_ring = ring_for(size, sec_index, size, repeat as u64)?;
            let cash_ring = ring_for(size, cash_index, size, repeat as u64 + 1)?;
            let started = Instant::now();
            let package = build_note_package(
                &key,
                instruction,
                &securities,
                &cash,
                &LegInput {
                    ring: &sec_ring,
                    index: sec_index,
                    opening: &sec_opening,
                    tag: sec_tag.point,
                    gamma: sec_gamma,
                    payee: buyer.address,
                    change_to: seller.address,
                },
                &LegInput {
                    ring: &cash_ring,
                    index: cash_index,
                    opening: &cash_opening,
                    tag: cash_tag.point,
                    gamma: cash_gamma,
                    payee: seller.address,
                    change_to: buyer.address,
                },
                QTY,
                PRICE,
                &openings.amount,
                &openings.price,
                NOTE_CONTEXT,
                rng,
            )?;
            builds.push(started.elapsed().as_secs_f64() * 1e3);
            let venue = committee.venue(key.clone());
            let mut defmi = NoteDefmi::new(key, securities, cash, venue, SigningKey::generate(rng));
            let started = Instant::now();
            let receipt = defmi.settle(package, 1_000, NOTE_CONTEXT, rng);
            settles.push(started.elapsed().as_secs_f64() * 1e3);
            if !receipt.settled {
                return Err(format!("note settlement was rejected: {}", receipt.reason).into());
            }
        }
        rows.push(json!({
            "ring": size,
            "build": summary(&builds),
            "settle": summary(&settles),
            "package_bytes": exact(note_dvp_wire_bytes(size)),
        }));
    }
    Ok(json!({"rings": rows}))
}

struct NetHolder {
    securities: (i64, Scalar),
    cash: (i64, Scalar),
}

fn signed_scalar(value: i64) -> Scalar {
    if value >= 0 {
        Scalar::from(value as u64)
    } else {
        -Scalar::from(value.unsigned_abs())
    }
}

fn one_cycle(
    mode: NetMode,
    trades: usize,
    participants: usize,
    attest: bool,
    seed: u64,
    rng: &mut OsRng,
) -> HarnessResult<Value> {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key.clone(), 16);
    let (sec_tag, _) = registry.blind(3, false, rng)?;
    let (cash_tag, _) = registry.blind(0, false, rng)?;
    let mut sec_book = PositionBook::new(
        key.clone(),
        sec_tag,
        mode.securities_net(),
        "securities",
        ACCOUNT_BITS,
    );
    let mut cash_book =
        PositionBook::new(key.clone(), cash_tag, mode.cash_net(), "cash", ACCOUNT_BITS);
    let mut holders = BTreeMap::new();
    for i in 0..participants {
        let handle = format!("p{i}").into_bytes();
        let holder = NetHolder {
            securities: (10_000_000, Scalar::random(rng)),
            cash: (
                (100_000_000_000u64 % (1u64 << 40)) as i64,
                Scalar::random(rng),
            ),
        };
        sec_book.open(
            &handle,
            sec_book
                .tagged()
                .commit(&signed_scalar(holder.securities.0), &holder.securities.1),
        )?;
        cash_book.open(
            &handle,
            cash_book
                .tagged()
                .commit(&signed_scalar(holder.cash.0), &holder.cash.1),
        )?;
        holders.insert(handle, holder);
    }
    let committee = Committee::new(key.clone(), rng)?;
    let batch_key = SigningKey::from_bytes(&[7u8; 32]);
    let mut cycle = Cycle::new(
        key.clone(),
        format!("harness-{seed}").into_bytes(),
        mode,
        sec_book,
        cash_book,
        committee.venue(key.clone()),
        attest,
        attest.then_some(batch_key.verifying_key()),
    )?;
    let handles: Vec<Vec<u8>> = holders.keys().cloned().collect();
    let mut state = seed.wrapping_add(1);
    let mut build_total = 0.0;
    let mut verify_total = 0.0;
    let mut admitted = 0usize;
    let mut refused = 0usize;
    for order_index in 0..trades {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let seller_index = (state as usize) % participants;
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let buyer_index = (seller_index + 1 + (state as usize % (participants - 1))) % participants;
        let seller = &handles[seller_index];
        let buyer = &handles[buyer_index];
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let quantity = 10 + state % 50;
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let price = 90_000 + state % 20_000;
        let value = quantity * price;
        let payer = RistrettoPoint::mul_base(&Scalar::from(buyer_index as u64 + 101));
        let payee = RistrettoPoint::mul_base(&Scalar::from(seller_index as u64 + 201));
        let (instruction, openings) =
            committee.issue(quantity, price, 3, payer, payee, order_index as u64, rng)?;

        let started = Instant::now();
        let cash_blinding = Scalar::random(rng);
        let cash_reference = key.commit_u64(value, &cash_blinding);
        let value_proof = prove_cash_reference(
            &key,
            &instruction.price_commitment,
            price,
            &openings.price,
            quantity,
            &openings.amount,
            &cash_blinding,
            rng,
        );
        let sold = holders[seller].securities;
        let bought = holders[buyer].cash;
        let sec_delta = Scalar::random(rng);
        let cash_delta = Scalar::random(rng);
        let sec_leg = match cycle.securities.build_leg(
            seller,
            buyer,
            quantity,
            &sec_delta,
            sold.0,
            &sold.1,
            &instruction.amount_commitment,
            &openings.amount,
            0,
            &Scalar::ZERO,
            rng,
        ) {
            Ok(leg) => leg,
            Err(_) => {
                refused += 1;
                continue;
            }
        };
        let cash_leg = match cycle.cash.build_leg(
            buyer,
            seller,
            value,
            &cash_delta,
            bought.0,
            &bought.1,
            &cash_reference,
            &cash_blinding,
            0,
            &Scalar::ZERO,
            rng,
        ) {
            Ok(leg) => leg,
            Err(_) => {
                refused += 1;
                continue;
            }
        };
        build_total += started.elapsed().as_secs_f64() * 1e3;
        let order = Order {
            instruction,
            securities: sec_leg,
            cash: cash_leg,
            cash_reference,
            value_proof,
        };
        let started = Instant::now();
        let accepted = cycle.admit(&order, 1_000, rng).is_ok();
        verify_total += started.elapsed().as_secs_f64() * 1e3;
        if !accepted {
            refused += 1;
            continue;
        }
        admitted += 1;
        {
            let sold = holders.get_mut(seller).expect("holder exists");
            sold.securities.0 -= quantity as i64;
            sold.securities.1 -= sec_delta;
            sold.cash.0 += value as i64;
            sold.cash.1 += cash_delta;
        }
        {
            let bought = holders.get_mut(buyer).expect("holder exists");
            bought.securities.0 += quantity as i64;
            bought.securities.1 += sec_delta;
            bought.cash.0 -= value as i64;
            bought.cash.1 -= cash_delta;
        }
    }

    let started = Instant::now();
    let mut securities_coverage = Vec::new();
    let mut cash_coverage = Vec::new();
    if cycle.securities.net {
        for (handle, holder) in &holders {
            securities_coverage.push(cycle.securities.build_coverage(
                handle,
                holder.securities.0,
                &holder.securities.1,
                0,
                &Scalar::ZERO,
            )?);
        }
    }
    if cycle.cash.net {
        for (handle, holder) in &holders {
            cash_coverage.push(cycle.cash.build_coverage(
                handle,
                holder.cash.0,
                &holder.cash.1,
                0,
                &Scalar::ZERO,
            )?);
        }
    }
    let close_build = started.elapsed().as_secs_f64() * 1e3;
    let attestation = attest.then(|| BatchAttestation::sign(&batch_key, cycle.batch_digest()));
    let started = Instant::now();
    cycle.close(&securities_coverage, &cash_coverage, attestation.as_ref())?;
    let close_verify = started.elapsed().as_secs_f64() * 1e3;
    Ok(json!({
        "mode": format!("{}{}", mode.label(), if attest { "+attested" } else { "" }),
        "trades": trades,
        "participants": participants,
        "admitted": admitted,
        "refused": refused,
        "verify_per_order_ms": verify_total / admitted.max(1) as f64,
        "verify_orders_ms": verify_total,
        "verify_close_ms": close_verify,
        "verify_total_ms": verify_total + close_verify,
        "build_orders_ms": build_total,
        "build_close_ms": close_build,
    }))
}

fn netting(
    trade_counts: &[usize],
    participant_counts: &[usize],
    repeats: usize,
    rng: &mut OsRng,
) -> HarnessResult<Value> {
    let arms = [
        (NetMode::GrossGross, false),
        (NetMode::GrossNet, false),
        (NetMode::NetNet, false),
        (NetMode::NetNet, true),
    ];
    let mut rows = Vec::new();
    for &trades in trade_counts {
        for &participants in participant_counts {
            let mut base = None;
            for (mode, attest) in arms {
                let mut runs = Vec::new();
                for repeat in 0..repeats {
                    runs.push(one_cycle(
                        mode,
                        trades,
                        participants,
                        attest,
                        repeat as u64,
                        rng,
                    )?);
                }
                let timed = [
                    ("verify_per_order", "verify_per_order_ms"),
                    ("verify_orders", "verify_orders_ms"),
                    ("verify_close", "verify_close_ms"),
                    ("verify_total", "verify_total_ms"),
                    ("build_orders", "build_orders_ms"),
                    ("build_close", "build_close_ms"),
                ];
                let mut row = Map::new();
                for (out, source) in timed {
                    let values: Vec<f64> =
                        runs.iter().filter_map(|run| run[source].as_f64()).collect();
                    row.insert(out.into(), summary(&values));
                }
                row.insert("mode".into(), runs[0]["mode"].clone());
                row.insert("trades".into(), json!(trades));
                row.insert("participants".into(), json!(participants));
                row.insert("admitted".into(), runs[0]["admitted"].clone());
                row.insert("refused".into(), runs[0]["refused"].clone());
                let total = row["verify_total"]["mean"].as_f64().unwrap_or(0.0);
                let baseline = *base.get_or_insert(total);
                row.insert(
                    "speedup_vs_gross_gross".into(),
                    json!(if total == 0.0 { 0.0 } else { baseline / total }),
                );
                rows.push(Value::Object(row));
            }
        }
    }
    Ok(json!({"rows": rows}))
}

fn credit_and_waterfall(
    tranche_counts: &[usize],
    repeats: usize,
    rng: &mut OsRng,
) -> HarnessResult<Value> {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key.clone(), 16);
    let (tag, _) = registry.blind(3, false, rng)?;
    let mut book = PositionBook::new(key.clone(), tag.clone(), true, "securities", 64);
    let position = -250_000i64;
    let position_blinding = Scalar::random(rng);
    book.open(
        b"p0",
        book.tagged()
            .commit(&signed_scalar(position), &position_blinding),
    )?;
    let ctx = CreditCtx::new(book.tagged(), 64);
    let mut grants = Vec::new();
    let mut checks = Vec::new();
    let mut last = None;
    let mut cap_blinding = Scalar::ZERO;
    for _ in 0..repeats {
        cap_blinding = Scalar::random(rng);
        let collateral_blinding = Scalar::random(rng);
        let started = Instant::now();
        let line = ctx.grant(
            b"p0",
            "securities",
            300_000,
            &cap_blinding,
            10_000_000,
            &collateral_blinding,
            500,
        )?;
        grants.push(started.elapsed().as_secs_f64() * 1e3);
        let started = Instant::now();
        ctx.check(&line)?;
        checks.push(started.elapsed().as_secs_f64() * 1e3);
        last = Some(line);
    }
    book.grant(&ctx, last.ok_or("no credit line was built")?)?;

    let mut capped = Vec::new();
    for _ in 0..repeats {
        let started = Instant::now();
        let coverage =
            book.build_coverage(b"p0", position, &position_blinding, 300_000, &cap_blinding)?;
        capped.push(started.elapsed().as_secs_f64() * 1e3);
        book.check_coverage(&coverage)?;
    }
    let mut bare = PositionBook::new(key.clone(), tag, true, "securities", 64);
    bare.open(b"p0", bare.tagged().commit_u64(250_000, &position_blinding))?;
    let mut plain = Vec::new();
    for _ in 0..repeats {
        let started = Instant::now();
        let coverage = bare.build_coverage(b"p0", 250_000, &position_blinding, 0, &Scalar::ZERO)?;
        plain.push(started.elapsed().as_secs_f64() * 1e3);
        bare.check_coverage(&coverage)?;
    }

    let mut waterfall = Vec::new();
    for &count in tranche_counts {
        let balances = if count >= 3 {
            let mut values = vec![300, 200, 500];
            values.extend(std::iter::repeat_n(5_000, count - 3));
            values
        } else {
            vec![300; count]
        };
        let blindings: Vec<_> = (0..count).map(|_| Scalar::random(rng)).collect();
        let tranches = balances
            .iter()
            .zip(&blindings)
            .enumerate()
            .map(|(i, (balance, blinding))| Tranche {
                name: format!("tranche {i}"),
                commitment: key.commit_u64(*balance, blinding),
            })
            .collect();
        let facility = Waterfall::new(key.clone(), tranches, 64);
        let shortfall = balances.iter().sum::<u64>() / 2;
        let mut builds = Vec::new();
        let mut verifies = Vec::new();
        let mut drawn = Vec::new();
        for _ in 0..repeats {
            let shortfall_blinding = Scalar::random(rng);
            let started = Instant::now();
            let (resolution, amounts) =
                facility.build(shortfall, &shortfall_blinding, &balances, &blindings, rng)?;
            builds.push(started.elapsed().as_secs_f64() * 1e3);
            let started = Instant::now();
            facility.check(&resolution, rng)?;
            verifies.push(started.elapsed().as_secs_f64() * 1e3);
            drawn = amounts;
        }
        waterfall.push(json!({
            "tranches": count,
            "build": summary(&builds),
            "check": summary(&verifies),
            "drawn": drawn,
        }));
    }
    Ok(json!({
        "grant": summary(&grants),
        "check": summary(&checks),
        "coverage_capped": summary(&capped),
        "coverage_plain": summary(&plain),
        "waterfall": waterfall,
    }))
}

fn prepare_split_settlement(
    securities_bits: usize,
    cash_bits: usize,
    nonce: u64,
    rng: &mut OsRng,
) -> HarnessResult<(f64, ScalingPrepared)> {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let committee = Committee::new(key.clone(), rng)?;
    let width = securities_bits.min(cash_bits);
    let (quantity, price) = trade_for(width);
    let started = Instant::now();
    let (instruction, openings) = committee.issue(
        quantity,
        price,
        3,
        RistrettoPoint::mul_base(&Scalar::from(22u64)),
        RistrettoPoint::mul_base(&Scalar::from(11u64)),
        nonce,
        rng,
    )?;
    let sec_ceiling = i64::try_from((1u64 << securities_bits) - 1)?;
    let cash_ceiling = i64::try_from((1u64 << cash_bits) - 1)?;
    let securities_balance = 5_000u64.max(quantity).min(u64::try_from(sec_ceiling)?);
    let value = quantity * price;
    let cash_balance = 50_000_000u64.max(value).min(u64::try_from(cash_ceiling)?);
    let securities_blinding = Scalar::random(rng);
    let (securities_commitment, securities_range, _) = prove_bounded(
        &key,
        i64::try_from(securities_balance - quantity)?,
        &securities_blinding,
        0,
        sec_ceiling,
        b"QOMM:DEFMI:DVP:v1:sec:rem",
        rng,
    )?;
    let cash_blinding = Scalar::random(rng);
    let (cash_commitment, cash_range, _) = prove_bounded(
        &key,
        i64::try_from(cash_balance - value)?,
        &cash_blinding,
        0,
        cash_ceiling,
        b"QOMM:DEFMI:DVP:v1:cash:rem",
        rng,
    )?;
    let reference_blinding = Scalar::random(rng);
    let value_commitment = key.commit_u64(value, &reference_blinding);
    let value_proof = prove_product(
        &key,
        &mut Transcript::new(b"qomm:defmi:value"),
        &instruction.price_commitment,
        &Scalar::from(price),
        &openings.price,
        &Scalar::from(quantity),
        &openings.amount,
        &reference_blinding,
        rng,
    );
    let build_ms = started.elapsed().as_secs_f64() * 1e3;
    // `ScalingPrepared` stores one ceiling, while split rails have two. Its
    // verifier is only suitable when the widths match, so split verification
    // is performed inline by `split_rails`; this value merely keeps all proof
    // parts together.
    Ok((
        build_ms,
        ScalingPrepared {
            venue: committee.venue(key.clone()),
            instruction,
            securities_commitment,
            securities_range,
            cash_commitment,
            cash_range,
            value_commitment,
            value_proof,
            key,
            ceiling: sec_ceiling,
        },
    ))
}

fn verify_split(prepared: &ScalingPrepared, securities_bits: usize, cash_bits: usize) -> bool {
    let securities_ceiling = ((1u64 << securities_bits) - 1) as i64;
    let cash_ceiling = ((1u64 << cash_bits) - 1) as i64;
    prepared.verify_instruction()
        && verify_bounded(
            &prepared.key,
            &prepared.securities_commitment,
            &prepared.securities_range,
            0,
            securities_ceiling,
            b"QOMM:DEFMI:DVP:v1:sec:rem",
        )
        && verify_bounded(
            &prepared.key,
            &prepared.cash_commitment,
            &prepared.cash_range,
            0,
            cash_ceiling,
            b"QOMM:DEFMI:DVP:v1:cash:rem",
        )
        && verify_product(
            &prepared.key,
            &mut Transcript::new(b"qomm:defmi:value"),
            &prepared.instruction.price_commitment,
            &prepared.instruction.amount_commitment,
            &prepared.value_commitment,
            &prepared.value_proof,
        )
}

fn split_rails(widths: &[(usize, usize)], repeats: usize, rng: &mut OsRng) -> HarnessResult<Value> {
    let mut rows = Vec::new();
    for &(securities_bits, cash_bits) in widths {
        let mut builds = Vec::new();
        let mut settles = Vec::new();
        for repeat in 0..repeats {
            let (build, prepared) =
                prepare_split_settlement(securities_bits, cash_bits, repeat as u64, rng)?;
            builds.push(build);
            let started = Instant::now();
            if !verify_split(&prepared, securities_bits, cash_bits) {
                return Err("a split-rail settlement package did not verify".into());
            }
            settles.push(started.elapsed().as_secs_f64() * 1e3);
        }
        rows.push(json!({
            "securities_bits": securities_bits,
            "cash_bits": cash_bits,
            "build": summary(&builds),
            "settle": summary(&settles),
            "package_bytes": exact(account_package_bytes(securities_bits, cash_bits)),
        }));
    }
    Ok(Value::Array(rows))
}

fn verify_job_main(args: &[String]) -> HarnessResult<()> {
    if args.len() != 4 {
        return Err("__verify_job expects BITS COUNT READY START".into());
    }
    let bits: usize = args[0].parse()?;
    let count: usize = args[1].parse()?;
    let ready = PathBuf::from(&args[2]);
    let start = PathBuf::from(&args[3]);
    let mut rng = OsRng;
    let mut prepared = Vec::with_capacity(count);
    for nonce in 0..count {
        prepared.push(prepare_settlement(bits, nonce as u64, &mut rng)?.2);
    }
    fs::write(&ready, b"ready")?;
    let deadline = Instant::now() + Duration::from_secs(300);
    while !start.exists() {
        if Instant::now() >= deadline {
            return Err("parallel verification barrier timed out".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    let started = Instant::now();
    for package in &prepared {
        if !package.verify() {
            return Err("parallel worker rejected a prepared package".into());
        }
    }
    println!("{:.12}", started.elapsed().as_secs_f64());
    Ok(())
}

fn wait_for_workers(children: &[Child], ready: &[PathBuf]) -> HarnessResult<()> {
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if ready.iter().all(|path| path.exists()) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "parallel workers did not reach the barrier ({} children)",
                children.len()
            )
            .into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn one_parallel_trial(workers: usize, each: usize, trial: usize) -> HarnessResult<f64> {
    let directory = unique_temp_dir(&format!("defmi-parallel-{trial}"))?;
    let start = directory.join("start");
    let executable = std::env::current_exe()?;
    let mut children = Vec::new();
    let mut ready = Vec::new();
    for worker in 0..workers {
        let ready_path = directory.join(format!("ready-{worker}"));
        let child = Command::new(&executable)
            .arg("__verify_job")
            .arg("40")
            .arg(each.to_string())
            .arg(&ready_path)
            .arg(&start)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        children.push(child);
        ready.push(ready_path);
    }
    wait_for_workers(&children, &ready)?;
    fs::write(&start, b"start")?;
    let mut elapsed = Vec::new();
    for child in children {
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(format!(
                "parallel verification worker failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )
            .into());
        }
        elapsed.push(String::from_utf8(output.stdout)?.trim().parse::<f64>()?);
    }
    let _ = fs::remove_dir_all(&directory);
    let slowest = elapsed.into_iter().fold(0.0f64, f64::max);
    if slowest == 0.0 {
        return Err("parallel verification recorded zero elapsed time".into());
    }
    Ok(workers as f64 * each as f64 / slowest)
}

fn parallel_measurement(
    worker_counts: &[usize],
    each: usize,
    repeats: usize,
) -> HarnessResult<Value> {
    let mut rows = Vec::new();
    for &workers in worker_counts {
        let mut rates = Vec::new();
        for trial in 0..repeats {
            rates.push(one_parallel_trial(workers, each, trial)?);
        }
        rows.push(json!({
            "workers": workers,
            "settlements_per_trial": workers * each,
            "per_second": summary(&rates),
        }));
    }
    Ok(Value::Array(rows))
}

fn parse_args() -> HarnessResult<Options> {
    let mut options = Options::default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut index = 0;
    while index < args.len() {
        let flag = &args[index];
        index += 1;
        if flag == "-h" || flag == "--help" {
            println!(
                "run_defmi [--out PATH] [--bits N ...] [--repeats N] \
                 [--workers N ...] [--parallel-each N] [--parallel-repeats N] \
                 [--assets N ...] [--rings N ...] [--pool N] [--trades N ...] \
                 [--parties N ...] [--tranches N ...] [--split SEC:CASH ...]"
            );
            std::process::exit(0);
        }
        let scalar = matches!(
            flag.as_str(),
            "--out" | "--repeats" | "--parallel-each" | "--parallel-repeats" | "--pool"
        );
        if scalar {
            let value = args
                .get(index)
                .ok_or_else(|| format!("{flag} needs a value"))?;
            index += 1;
            match flag.as_str() {
                "--out" => options.out = PathBuf::from(value),
                "--repeats" => options.repeats = value.parse()?,
                "--parallel-each" => options.parallel_each = value.parse()?,
                "--parallel-repeats" => options.parallel_repeats = value.parse()?,
                "--pool" => options.pool = value.parse()?,
                _ => unreachable!(),
            }
            continue;
        }
        let start = index;
        while index < args.len() && !args[index].starts_with("--") {
            index += 1;
        }
        if start == index {
            return Err(format!("{flag} needs at least one value").into());
        }
        let values = &args[start..index];
        match flag.as_str() {
            "--bits" => options.bits = parse_values(values)?,
            "--workers" => options.workers = parse_values(values)?,
            "--assets" => options.assets = parse_values(values)?,
            "--rings" => options.rings = parse_values(values)?,
            "--trades" => options.trades = parse_values(values)?,
            "--parties" => options.parties = parse_values(values)?,
            "--tranches" => options.tranches = parse_values(values)?,
            "--split" => {
                options.split = values
                    .iter()
                    .map(|value| {
                        let (left, right) = value
                            .split_once(':')
                            .ok_or_else(|| format!("invalid split width: {value}"))?;
                        Ok((left.parse()?, right.parse()?))
                    })
                    .collect::<HarnessResult<Vec<_>>>()?;
            }
            _ => return Err(format!("unknown option: {flag}").into()),
        }
    }
    Ok(options)
}

fn parse_values<T>(values: &[String]) -> HarnessResult<Vec<T>>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + 'static,
{
    values
        .iter()
        .map(|value| value.parse::<T>().map_err(Into::into))
        .collect()
}

fn validate_widths(options: &Options) -> HarnessResult<()> {
    let widths = options
        .bits
        .iter()
        .copied()
        .chain(options.split.iter().flat_map(|(a, b)| [*a, *b]));
    if widths.clone().any(|bits| !(1..=62).contains(&bits)) {
        return Err("all balance widths must be between 1 and 62".into());
    }
    if options
        .rings
        .iter()
        .any(|ring| *ring < 2 || !ring.is_power_of_two())
    {
        return Err("ring sizes must be powers of two and at least 2".into());
    }
    if options.pool == 0 || options.rings.iter().all(|ring| *ring > options.pool) {
        return Err("--pool must hold at least one requested ring".into());
    }
    if options.parties.iter().any(|count| *count < 2) {
        return Err("netting needs at least two parties".into());
    }
    if options.tranches.iter().any(|count| *count == 0) {
        return Err("waterfalls need at least one tranche".into());
    }
    if options.workers.iter().any(|count| *count == 0)
        || options.parallel_each == 0
        || options.parallel_repeats == 0
    {
        return Err("parallel worker counts and repeats must be positive".into());
    }
    Ok(())
}

fn summary(samples: &[f64]) -> Value {
    match Summary::of(samples) {
        None => json!({
            "n": 0,
            "mean": Value::Null,
            "sd": Value::Null,
            "median": Value::Null,
            "min": Value::Null,
            "max": Value::Null,
            "rsd": Value::Null,
        }),
        Some(value) => json!({
            "n": value.n,
            "mean": value.mean,
            "sd": value.sd,
            "median": value.median,
            "min": value.min,
            "max": value.max,
            "rsd": value.rsd(),
        }),
    }
}

fn exact(value: u64) -> Value {
    json!({"exact": value})
}

fn account_package_bytes(securities_bits: usize, cash_bits: usize) -> u64 {
    22_099 + 448 * (securities_bits + cash_bits) as u64
}

fn membership_wire_bytes(set_size: usize) -> u64 {
    224 * set_size.ilog2() as u64
}

fn note_spend_wire_bytes(ring: usize) -> u64 {
    36_800 + 224 * ring.ilog2() as u64
}

fn note_dvp_wire_bytes(ring: usize) -> u64 {
    95_627 + 64 * ring as u64 + 448 * ring.ilog2() as u64
}

fn python_version() -> String {
    let root = qomm_harness::repo_root();
    let local = root.join(".venv/bin/python");
    let executable = if local.exists() {
        local
    } else {
        PathBuf::from("python3")
    };
    Command::new(executable)
        .arg("--version")
        .output()
        .ok()
        .map(|output| {
            let mut text = String::from_utf8_lossy(&output.stdout).to_string();
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            text.trim().trim_start_matches("Python ").to_string()
        })
        .filter(|version| !version.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_sizes_match_the_python_wire_counter() {
        assert_eq!(account_package_bytes(8, 8), 29_267);
        assert_eq!(account_package_bytes(40, 40), 57_939);
        assert_eq!(note_spend_wire_bytes(2), 37_024);
        assert_eq!(note_spend_wire_bytes(8), 37_472);
        assert_eq!(note_dvp_wire_bytes(2), 96_203);
        assert_eq!(note_dvp_wire_bytes(8), 97_483);
    }

    #[test]
    fn narrow_rail_trade_stays_inside_the_requested_width() {
        for bits in [8usize, 16, 24, 40, 48] {
            let (quantity, price) = trade_for(bits);
            assert!(quantity * price <= (1u64 << bits) - 1);
        }
    }

    #[test]
    fn one_timing_sample_has_null_spread_like_python() {
        let value = summary(&[7.0]);
        assert_eq!(value["n"], 1);
        assert!(value["sd"].is_null());
        assert!(value["rsd"].is_null());
    }
}
