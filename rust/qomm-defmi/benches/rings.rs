//! What a reader of a note ledger can still name.
//!
//! The account rails name a payer in every call, and section 6.1 of `DEFMI.md`
//! showed that deriving that name per venue is what makes an adaptor worth its
//! cost. The note ledger is supposed to be the stronger answer: it names no
//! account at all, only a ring the spent note is somewhere inside, so the claim
//! has been that it removes the handle rather than hiding it well.
//!
//! That claim has been argued and not measured, and the argument has a hole in
//! it worth stating before the numbers: **a ring is only an anonymity set if
//! the decoys are indistinguishable from the real note.** `ring_for` draws its
//! decoys uniformly over the whole pool. A real spend is of a note the spender
//! received recently, because that is what a settlement does --- you are paid,
//! and then you pay. Recent notes have high indices; uniform decoys mostly
//! do not.
//!
//! So the prediction, written before running this:
//!
//!   1. An observer guessing uniformly inside the ring scores 1/R. This is the
//!      number the design has been quoting.
//!   2. An observer guessing **the newest member of the ring** scores far above
//!      that --- above 0.8 at R = 8 once the pool is a few times the ring ---
//!      because the real note is usually the newest thing in it.
//!   3. Drawing decoys from the same recency window that real spends come from
//!      brings the second observer back to about 1/R.
//!
//! The first run said 1.000 for every ring size, and 1.000 for the recency
//! window too, which killed the third part of the prediction and was right to.
//! A note spent one settlement after it was received is the newest note there
//! is, and no decoy can be newer than the newest --- the window cannot help,
//! because there is nothing above the real note to draw from. What decides the
//! question is **how many other people's notes arrive in between**, so that is
//! the parameter, and the honest reading is:
//!
//!   an anonymity set on a note rail is other people's traffic, and the decoy
//!   rule only decides whether the ring can make use of it.
//!
//! Which is the same shape as the finding in section 6.1: the construction
//! protects you with other people's activity or it does not protect you.
//!
//! The observer is scored at the **better of its two strategies**, because a
//! real one would take it. Guessing the newest is free and uses only what the
//! chain publishes.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use qomm_defmi::assets::AssetRegistry;
use qomm_defmi::note_settlement::*;
use qomm_defmi::notes::{ring_for, ring_recent, NoteLedger, Wallet};
use qomm_measure::{hosts, Summary};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::{deal_quorum, frost, Bounds, Instruction, Issuer, Venue};
use rand::rngs::OsRng;
use sha2::Digest;
use std::collections::BTreeMap;
use std::time::Instant;

const BITS: usize = 32;
const QTY: u64 = 100;
const PRICE: u64 = 999;
const NOTE_VALUE: u64 = 5_000_000;
const CONTEXT: &[u8] = b"rings";

/// How the decoys are chosen. The whole measurement is about this one choice.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Decoys {
    /// `ring_for`: uniform over every note the ledger has ever held.
    Uniform,
    /// `ring_recent`: uniform over the newest window, which is where real
    /// spends come from.
    Recent,
}

struct World {
    key: Pedersen,
    registry: AssetRegistry,
    defmi: NoteDefmi,
    issuer: Issuer,
    shares: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: frost::keys::PublicKeyPackage,
    seller: Wallet,
    buyer: Wallet,
    sec_asset: u32,
    cash_asset: u32,
}

/// A rail that already holds notes: the owner's last, the rest other people's.
/// The pool has to be bigger than the ring before a ring means anything, and
/// the owner's note has to be recent because that is what a spender holds.
fn rail(
    key: &Pedersen,
    registry: &AssetRegistry,
    asset: u32,
    owner: &Wallet,
    depth: usize,
    rng: &mut OsRng,
) -> NoteLedger {
    let asset_key = key.with_value_generator(registry.tags[asset as usize]);
    let mut ledger = NoteLedger::new(key.clone(), BITS);
    for i in 0..depth {
        let mine = i + 1 == depth;
        let address = if mine {
            owner.address
        } else {
            Wallet::new(rng).address
        };
        let held = if mine {
            NOTE_VALUE
        } else {
            NOTE_VALUE + i as u64 + 1
        };
        let blinding = Scalar::random(rng);
        let note = ledger.build_note(
            &address,
            held,
            asset_key.commit_u64(held, &blinding),
            &blinding,
            rng,
        );
        ledger.add(note);
    }
    ledger
}

fn world(depth: usize, rng: &mut OsRng) -> World {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key.clone(), 16);
    let (secret, public) = deal_quorum(7, 3, rng).unwrap();
    let shares = secret
        .into_iter()
        .map(|(id, s)| (id, frost::keys::KeyPackage::try_from(s).unwrap()))
        .collect();
    let (seller, buyer) = (Wallet::new(rng), Wallet::new(rng));
    let (sec_asset, cash_asset) = (3u32, 0u32);
    let securities = rail(&key, &registry, sec_asset, &seller, depth, rng);
    let cash = rail(&key, &registry, cash_asset, &buyer, depth, rng);
    let venue = Venue::new(key.clone(), &Bounds::default(), public.clone());
    World {
        issuer: Issuer::new(key.clone(), Bounds::default()),
        defmi: NoteDefmi::new(
            key.clone(),
            securities,
            cash,
            venue,
            SigningKey::generate(rng),
        ),
        key,
        registry,
        shares,
        public,
        seller,
        buyer,
        sec_asset,
        cash_asset,
    }
}

fn sign(w: &World, message: &[u8], rng: &mut OsRng) -> frost::Signature {
    let chosen: Vec<_> = w.shares.keys().take(3).cloned().collect();
    let (mut nonces, mut commitments) = (BTreeMap::new(), BTreeMap::new());
    for id in &chosen {
        let (n, c) = frost::round1::commit(w.shares[id].signing_share(), rng);
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }
    let package = frost::SigningPackage::new(commitments, message);
    let mut shares = BTreeMap::new();
    for id in &chosen {
        shares.insert(
            *id,
            frost::round2::sign(&package, &nonces[id], &w.shares[id]).unwrap(),
        );
    }
    frost::aggregate(&package, &shares, &w.public).unwrap()
}

fn instruction(w: &World, rng: &mut OsRng, nonce: u8) -> (Instruction, Scalar, Scalar) {
    let (digest, openings, partial) = w
        .issuer
        .build(
            QTY,
            PRICE,
            w.sec_asset,
            RistrettoPoint::mul_base(&Scalar::from(11u64)),
            RistrettoPoint::mul_base(&Scalar::from(22u64)),
            1_500,
            [nonce; 32],
            1_599_845,
            rng,
        )
        .unwrap();
    (
        partial.sealed(sign(w, &digest, rng)),
        openings.amount,
        openings.price,
    )
}

/// One settlement, and the two rings it published.
struct Published {
    sec_ring: Vec<usize>,
    sec_true: usize,
    cash_ring: Vec<usize>,
    cash_true: usize,
    verify_ms: f64,
    pool: usize,
}

fn settle_once(
    w: &mut World,
    nonce: u8,
    ring: usize,
    decoys: Decoys,
    window: usize,
    rng: &mut OsRng,
) -> Option<Published> {
    let (instruction, amount_blinding, price_blinding) = instruction(w, rng, nonce);
    let sec_key = w
        .key
        .with_value_generator(w.registry.tags[w.sec_asset as usize]);
    let cash_key = w
        .key
        .with_value_generator(w.registry.tags[w.cash_asset as usize]);
    // What a spender actually reaches for: the newest note it holds. Nothing in
    // the ledger makes that choice; it is what being paid and then paying looks
    // like, and it is the whole reason the decoys matter.
    let sec_found = w.defmi.securities.scan(&w.seller, &sec_key);
    let cash_found = w.defmi.cash.scan(&w.buyer, &cash_key);
    let (sec_index, sec_opening) = *sec_found.last()?;
    let (cash_index, cash_opening) = *cash_found.last()?;

    let (sec_tag, sec_gamma) = w.registry.blind(w.sec_asset, false, rng).ok()?;
    let (cash_tag, cash_gamma) = w.registry.blind(w.cash_asset, false, rng).ok()?;
    let sec_pool = w.defmi.securities.notes.len();
    let cash_pool = w.defmi.cash.notes.len();
    let pick = |pool, index, seed| match decoys {
        Decoys::Uniform => ring_for(pool, index, ring, seed),
        Decoys::Recent => ring_recent(pool, index, ring, window, seed),
    };
    let sec_ring = pick(sec_pool, sec_index, nonce as u64 * 2 + 1).ok()?;
    let cash_ring = pick(cash_pool, cash_index, nonce as u64 * 2 + 2).ok()?;

    let package = build_note_package(
        &w.key,
        instruction,
        &w.defmi.securities,
        &w.defmi.cash,
        &LegInput {
            ring: &sec_ring,
            index: sec_index,
            opening: &sec_opening,
            tag: sec_tag.point,
            gamma: sec_gamma,
            payee: w.buyer.address,
            change_to: w.seller.address,
        },
        &LegInput {
            ring: &cash_ring,
            index: cash_index,
            opening: &cash_opening,
            tag: cash_tag.point,
            gamma: cash_gamma,
            payee: w.seller.address,
            change_to: w.buyer.address,
        },
        QTY,
        PRICE,
        &amount_blinding,
        &price_blinding,
        CONTEXT,
        rng,
    )
    .ok()?;

    let start = Instant::now();
    let receipt = w.defmi.settle(package, 1_000, CONTEXT, rng);
    let verify_ms = start.elapsed().as_secs_f64() * 1e3;
    if !receipt.settled {
        return None;
    }
    Some(Published {
        sec_ring,
        sec_true: sec_index,
        cash_ring,
        cash_true: cash_index,
        verify_ms,
        pool: w.defmi.securities.notes.len(),
    })
}

/// Guess uniformly inside the ring. This is the number the design quotes.
fn uniform(published: &[Published]) -> f64 {
    let mut total = 0.0;
    for p in published {
        total += 1.0 / p.sec_ring.len() as f64;
        total += 1.0 / p.cash_ring.len() as f64;
    }
    total / (2 * published.len()) as f64
}

/// Guess the newest member of the ring. Costs the observer nothing: the ring is
/// published and note indices are creation order.
fn newest(published: &[Published]) -> f64 {
    let mut total = 0.0;
    for p in published {
        for (ring, truth) in [(&p.sec_ring, p.sec_true), (&p.cash_ring, p.cash_true)] {
            let top = ring.iter().copied().max().unwrap();
            total += if top == truth { 1.0 } else { 0.0 };
        }
    }
    total / (2 * published.len()) as f64
}

/// Other people's outputs, arriving between one firm's receipt and its spend.
///
/// A settlement makes four notes --- payee and change, on two rails --- so this
/// is other settlements happening, modelled by what they leave behind. Nothing
/// about them is visible to the tracked pair and nothing about the tracked pair
/// is visible to them, which is exactly why they are the anonymity set.
fn churn(w: &mut World, settlements: usize, rng: &mut OsRng) {
    let sec_key = w
        .key
        .with_value_generator(w.registry.tags[w.sec_asset as usize]);
    let cash_key = w
        .key
        .with_value_generator(w.registry.tags[w.cash_asset as usize]);
    for _ in 0..settlements {
        for (ledger, asset_key) in [
            (&mut w.defmi.securities, &sec_key),
            (&mut w.defmi.cash, &cash_key),
        ] {
            for _ in 0..2 {
                let address = Wallet::new(rng).address;
                let blinding = Scalar::random(rng);
                let held = NOTE_VALUE;
                let note = ledger.build_note(
                    &address,
                    held,
                    asset_key.commit_u64(held, &blinding),
                    &blinding,
                    rng,
                );
                ledger.add(note);
            }
        }
    }
}

fn shell(cmd: &str, args: &[&str]) -> String {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn main() {
    let mut rng = OsRng;
    let settlements: usize = std::env::var("QOMM_BENCH_SETTLEMENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(12);
    let depth = 64;

    println!(
        "what a reader of a note ledger can name, {BITS}-bit rails, \
pool starts at {depth}\n"
    );
    println!(
        "{:<8} {:>5} {:>7} {:>8} {:>9} {:>9} {:>9} {:>24} {:>7}",
        "decoys", "ring", "window", "traffic", "uniform", "newest", "best", "verify ms", "pool"
    );
    let mut rows = Vec::new();

    for (decoys, name, window) in [
        (Decoys::Uniform, "uniform", 0usize),
        (Decoys::Recent, "recent", 32),
    ] {
        for ring in [4usize, 8, 16] {
            for traffic in [0usize, 4, 16] {
                let mut w = world(depth, &mut rng);
                let mut published = Vec::new();
                for nonce in 0..settlements {
                    if let Some(p) =
                        settle_once(&mut w, nonce as u8, ring, decoys, window, &mut rng)
                    {
                        published.push(p);
                    }
                    churn(&mut w, traffic, &mut rng);
                }
                let shown = if window == 0 {
                    "-".to_string()
                } else {
                    window.to_string()
                };
                if published.is_empty() {
                    println!(
                        "{name:<8} {ring:>5} {shown:>7} {traffic:>8} {:>9} {:>9} \
{:>9} {:>24} {:>7}",
                        "-", "-", "-", "nothing settled", "-"
                    );
                    continue;
                }
                let times: Vec<f64> = published.iter().map(|p| p.verify_ms).collect();
                let t = Summary::of(&times).unwrap();
                let (u, n) = (uniform(&published), newest(&published));
                let best = if n > u { n } else { u };
                let pool = published.last().unwrap().pool;
                println!(
                    "{name:<8} {ring:>5} {shown:>7} {traffic:>8} {u:>9.3} {n:>9.3} \
{best:>9.3} {:>24} {pool:>7}",
                    format!("{t}")
                );
                rows.push(format!(
                    "    {{\"decoys\": \"{name}\", \"ring\": {ring}, \"window\": {window}, \
\"traffic\": {traffic}, \
\"settlements\": {}, \"uniform_guess\": {u:.4}, \"newest_guess\": {n:.4}, \
\"observer_success\": {best:.4}, \"pool\": {pool}, \
\"verify_ms\": {{\"n\": {}, \"mean\": {:.4}, \"sd\": {}, \"median\": {:.4}}}}}",
                    published.len(),
                    t.n,
                    t.mean,
                    t.sd.map(|s| format!("{s:.4}"))
                        .unwrap_or_else(|| "null".into()),
                    t.median
                ));
            }
        }
    }

    println!(
        "\n`traffic` is how many other settlements land between one firm being\n\
paid and paying. `uniform` guesses inside the ring, `newest` guesses its\n\
highest note index, and `best` is what an observer that takes the better of\n\
the two gets --- which is the number that matters."
    );

    // The timing column above climbs with the pool, and nothing in
    // `check_spend` is proportional to it --- the ring proof, the range proofs
    // and the balance check are all O(ring). What is proportional to the pool
    // is the state root: `snapshot` compresses every note the ledger has ever
    // held, and a settlement takes four of them, two rails before and after.
    // So this is measured on its own, because a settlement cost that grows
    // with total history is a deployability question and not a privacy one.
    println!("\nthe state root, which is not a ring question\n");
    println!(
        "{:>8} {:>24} {:>24} {:>10}",
        "pool", "walked, us", "kept, us", "ratio"
    );
    let mut roots = Vec::new();
    for pool in [64usize, 256, 1024, 4096] {
        let w = world(pool, &mut rng);
        let mut kept = Vec::new();
        let mut walked = Vec::new();
        for _ in 0..9 {
            let start = Instant::now();
            std::hint::black_box(w.defmi.securities.snapshot());
            kept.push(start.elapsed().as_secs_f64() * 1e6);

            // exactly the work the old root did: compress every note the
            // ledger has ever held. Priced here rather than kept in the
            // library, because nothing needs it any more.
            let ledger = &w.defmi.securities;
            let start = Instant::now();
            let mut hasher = sha2::Sha256::new();
            for note in &ledger.notes {
                hasher.update(ledger.commitment_of(note).compress().as_bytes());
            }
            std::hint::black_box(hasher.finalize());
            walked.push(start.elapsed().as_secs_f64() * 1e6);
        }
        let (k, wk) = (Summary::of(&kept).unwrap(), Summary::of(&walked).unwrap());
        println!(
            "{pool:>8} {:>24} {:>24} {:>10.0}x",
            format!("{wk}"),
            format!("{k}"),
            wk.mean / k.mean
        );
        roots.push(format!(
            "    {{\"pool\": {pool}, \
\"kept_us\": {{\"n\": {}, \"mean\": {:.4}, \"sd\": {}, \"median\": {:.4}}}, \
\"walked_us\": {{\"n\": {}, \"mean\": {:.4}, \"sd\": {}, \"median\": {:.4}}}, \
\"per_settlement_kept_us\": {:.4}, \"per_settlement_walked_us\": {:.4}}}",
            k.n,
            k.mean,
            k.sd.map(|s| format!("{s:.4}"))
                .unwrap_or_else(|| "null".into()),
            k.median,
            wk.n,
            wk.mean,
            wk.sd
                .map(|s| format!("{s:.4}"))
                .unwrap_or_else(|| "null".into()),
            wk.median,
            k.mean * 4.0,
            wk.mean * 4.0
        ));
    }

    if let Ok(path) = std::env::var("QOMM_BENCH_JSON") {
        let json = format!(
            "{{\n  \"host\": \"{}\",\n  \"rustc\": \"{}\",\n  \"rail_bits\": {BITS},\n  \
\"pool_depth\": {depth},\n  \
\"observer\": \"names the note a leg spent, from the published ring alone\",\n  \
\"rows\": [\n{}\n  ],\n  \
\"state_root\": [\n{}\n  ]\n}}\n",
            std::env::var("QOMM_HOST_LABEL").unwrap_or_else(|_| hosts::this_host()),
            shell("rustc", &["--version"]),
            rows.join(",\n"),
            roots.join(",\n")
        );
        std::fs::write(&path, json).expect("could not write the measurement");
        println!("\nwrote {path}");
    }
}
