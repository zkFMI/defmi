//! Delivery versus payment with no accounts on either side, in Rust.
//!
//! `DEFMI.md` section 9 said the Rust side had no note-rail DvP and that the
//! `note_settlement.rs` was ported; this is the second half, so the sentence
//! can go rather than be softened.
//!
//! The shape to expect is the account rail's: the ring costs the prover and
//! barely costs the verifier, because a one-out-of-many proof is logarithmic on
//! the wire and the work of checking it is dominated by everything else in the
//! package.

use std::collections::BTreeMap;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use qomm_defmi::assets::AssetRegistry;
use qomm_defmi::note_settlement::*;
use qomm_defmi::notes::{ring_for, NoteLedger, Wallet};
use qomm_measure::{hosts, time_ms};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::{deal_quorum, frost, Bounds, Instruction, Issuer, Venue};
use rand::rngs::OsRng;

const BITS: usize = 32;
const QTY: u64 = 100;
const PRICE: u64 = 999;
const SEC_NOTE: u64 = 5_000;
const CASH_NOTE: u64 = 5_000_000;

fn shell(program: &str, args: &[&str]) -> String {
    std::process::Command::new(program)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
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
    ring: usize,
}

fn rail(
    key: &Pedersen,
    registry: &AssetRegistry,
    asset: u32,
    owner: &Wallet,
    value: u64,
    pool: usize,
    rng: &mut OsRng,
) -> NoteLedger {
    let asset_key = key.with_value_generator(registry.tags[asset as usize]);
    let mut ledger = NoteLedger::new(key.clone(), BITS);
    for i in 0..pool {
        let address = if i == 0 {
            owner.address
        } else {
            Wallet::new(rng).address
        };
        let held = if i == 0 { value } else { value + i as u64 };
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

fn world(ring: usize, rng: &mut OsRng) -> World {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key.clone(), 16);
    let (secret, public) = deal_quorum(7, 3, rng).unwrap();
    let shares = secret
        .into_iter()
        .map(|(id, s)| (id, frost::keys::KeyPackage::try_from(s).unwrap()))
        .collect();
    let (seller, buyer) = (Wallet::new(rng), Wallet::new(rng));
    let (sec_asset, cash_asset) = (3u32, 0u32);
    let securities = rail(&key, &registry, sec_asset, &seller, SEC_NOTE, ring, rng);
    let cash = rail(&key, &registry, cash_asset, &buyer, CASH_NOTE, ring, rng);
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
        ring,
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
    let signature = sign(w, &digest, rng);
    (partial.sealed(signature), openings.amount, openings.price)
}

fn package(w: &World, rng: &mut OsRng, nonce: u8) -> NoteDvpPackage {
    let (instruction, amount_blinding, price_blinding) = instruction(w, rng, nonce);
    let sec_key = w
        .key
        .with_value_generator(w.registry.tags[w.sec_asset as usize]);
    let cash_key = w
        .key
        .with_value_generator(w.registry.tags[w.cash_asset as usize]);
    let (sec_index, sec_opening) = w.defmi.securities.scan(&w.seller, &sec_key)[0];
    let (cash_index, cash_opening) = w.defmi.cash.scan(&w.buyer, &cash_key)[0];
    let (sec_tag, sec_gamma) = w.registry.blind(w.sec_asset, false, rng).unwrap();
    let (cash_tag, cash_gamma) = w.registry.blind(w.cash_asset, false, rng).unwrap();
    let sec_ring = ring_for(w.defmi.securities.notes.len(), sec_index, w.ring, 1).unwrap();
    let cash_ring = ring_for(w.defmi.cash.notes.len(), cash_index, w.ring, 2).unwrap();
    build_note_package(
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
        b"ctx",
        rng,
    )
    .unwrap()
}

/// What the package weighs, counted from the parts rather than serialised ---
/// there is no wire format for a settlement package yet, and inventing one for
/// a bench would be measuring the invention.
fn weight(p: &NoteDvpPackage) -> usize {
    let gk = |g: &qomm_zk::oneofmany::GkProof| {
        32 * (g.cl.len() + g.ca.len() + g.cb.len() + g.gk.len())
            + 32 * (g.f.len() + g.za.len() + g.zb.len() + 1)
    };
    let leg = |l: &NoteLeg| {
        // the ring is indices rather than points on the wire, so four bytes each
        4 * l.ring.len()
            + gk(&l.spend.ring)
            + l.spend.output_range.to_bytes().len()
            + 32 * (4 + 5 * l.notes.len())
    };
    qomm_zkpi::wire::encode(&p.instruction).len() + leg(&p.securities) + leg(&p.cash) + 32 * 6
}

fn main() {
    let rng = &mut OsRng;
    println!("Delivery versus payment on two note rails\n");
    println!(
        "{:>6}  {:>14}  {:>14}  {:>12}",
        "ring", "build ms", "settle ms", "package B"
    );
    let mut rows = Vec::new();
    for ring in [2usize, 4, 8, 16, 32, 64] {
        let mut w = world(ring, rng);
        let build = time_ms(5, || {
            package(&w, rng, 1);
        });
        let sample = package(&w, rng, 1);
        let bytes = weight(&sample);
        // settle consumes the package and the ledger, so each timed run gets
        // its own of both --- otherwise the second one is a replay refusal
        let mut nonce = 2u8;
        let settle = time_ms(5, || {
            let mut fresh = world(ring, rng);
            let p = package(&fresh, rng, nonce);
            nonce = nonce.wrapping_add(1);
            let receipt = fresh.defmi.settle(p, 1_000, b"ctx", rng);
            assert!(receipt.settled, "an honest package must settle");
        });
        let _ = &mut w;
        println!(
            "{ring:>6}  {:>14.1}  {:>14.1}  {:>12}",
            build.median, settle.median, bytes
        );
        rows.push(format!(
            "    {{\"ring\": {ring}, \"build\": {}, \"settle_including_build\": {}, \
\"package_bytes\": {bytes}}}",
            build.json(),
            settle.json()
        ));
    }
    println!(
        "\nThe settle column builds a fresh world and a fresh package each \n\
              time, because settling consumes both --- so it is an upper bound \n\
              that carries the build with it."
    );

    if let Ok(path) = std::env::var("QOMM_BENCH_JSON") {
        let json = format!(
            "{{\n  \"host\": \"{}\",\n  \"rustc\": \"{}\",\n  \"bits\": {BITS},\n  \
\"note\": \"settle includes a fresh build, since settling consumes the \
package and the ledger\",\n  \"rows\": [\n{}\n  ]\n}}\n",
            std::env::var("QOMM_HOST_LABEL").unwrap_or_else(|_| hosts::this_host()),
            shell("rustc", &["--version"]),
            rows.join(",\n")
        );
        std::fs::write(&path, json).expect("could not write the measurement");
        println!("\nwrote {path}");
    }
}
