//! Delivery versus payment with no accounts on either side.
//!
//! The properties under test are the ones the account version has, plus the one
//! it does not: two payments to one address share no bytes, and a spend does not
//! say which note it consumed.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use qomm_defmi::assets::AssetRegistry;
use qomm_defmi::note_settlement::*;
use qomm_defmi::notes::{ring_for, NoteLedger, Wallet};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::{deal_quorum, frost, Bounds, Instruction, Issuer, Venue};
use rand::rngs::OsRng;
use std::collections::BTreeMap;

const BITS: usize = 32;
const RING: usize = 8;
const QTY: u64 = 100;
const PRICE: u64 = 999;
const SEC_NOTE: u64 = 5_000;
const CASH_NOTE: u64 = 5_000_000;

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

fn stock_rail(
    key: &Pedersen,
    registry: &AssetRegistry,
    asset: u32,
    owner: &Wallet,
    value: u64,
    rng: &mut OsRng,
) -> NoteLedger {
    let asset_key = key.with_value_generator(registry.tags[asset as usize]);
    let mut ledger = NoteLedger::new(key.clone(), BITS);
    for i in 0..RING {
        // The owner's note is first; the rest are decoys the ring will hide it in.
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

fn world(rng: &mut OsRng) -> World {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key.clone(), 16);
    let (secret, public) = deal_quorum(7, 3, rng).unwrap();
    let shares = secret
        .into_iter()
        .map(|(id, s)| (id, frost::keys::KeyPackage::try_from(s).unwrap()))
        .collect();
    let (seller, buyer) = (Wallet::new(rng), Wallet::new(rng));
    let (sec_asset, cash_asset) = (3u32, 0u32);
    let securities = stock_rail(&key, &registry, sec_asset, &seller, SEC_NOTE, rng);
    let cash = stock_rail(&key, &registry, cash_asset, &buyer, CASH_NOTE, rng);

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

fn instruction(
    w: &World,
    rng: &mut OsRng,
    nonce: u8,
    qty: u64,
    price: u64,
) -> (Instruction, Scalar, Scalar) {
    let (digest, openings, partial) = w
        .issuer
        .build(
            qty,
            price,
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

fn package(
    w: &World,
    rng: &mut OsRng,
    nonce: u8,
    qty: u64,
    price: u64,
) -> Result<NoteDvpPackage, &'static str> {
    let (instruction, amount_blinding, price_blinding) = instruction(w, rng, nonce, qty, price);
    let sec_key = w
        .key
        .with_value_generator(w.registry.tags[w.sec_asset as usize]);
    let cash_key = w
        .key
        .with_value_generator(w.registry.tags[w.cash_asset as usize]);
    let sec_found = w.defmi.securities.scan(&w.seller, &sec_key);
    let cash_found = w.defmi.cash.scan(&w.buyer, &cash_key);
    let (sec_index, sec_opening) = sec_found[0];
    let (cash_index, cash_opening) = cash_found[0];

    let (sec_tag, sec_gamma) = w.registry.blind(w.sec_asset, false, rng)?;
    let (cash_tag, cash_gamma) = w.registry.blind(w.cash_asset, false, rng)?;
    let sec_ring = ring_for(w.defmi.securities.notes.len(), sec_index, RING, 1)?;
    let cash_ring = ring_for(w.defmi.cash.notes.len(), cash_index, RING, 2)?;

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
        qty,
        price,
        &amount_blinding,
        &price_blinding,
        b"ctx",
        rng,
    )
}

#[test]
fn an_honest_settlement_moves_both_rails_and_signs_a_receipt() {
    let rng = &mut OsRng;
    let mut w = world(rng);
    let p = package(&w, rng, 1, QTY, PRICE).unwrap();
    let before = (w.defmi.securities.snapshot(), w.defmi.cash.snapshot());
    let receipt = w.defmi.settle(p, 1_000, b"ctx", rng);
    assert!(receipt.settled, "{}", receipt.reason);
    assert!(receipt.verify(&w.defmi.public_key()));
    assert_ne!(receipt.securities_after, before.0);
    assert_ne!(receipt.cash_after, before.1);
}

#[test]
fn the_same_instruction_cannot_settle_twice() {
    let rng = &mut OsRng;
    let mut w = world(rng);
    let first = package(&w, rng, 2, QTY, PRICE).unwrap();
    assert!(w.defmi.settle(first, 1_000, b"ctx", rng).settled);
    // A second package reusing the nonce carries the same nullifier.
    let again = package(&w, rng, 2, QTY, PRICE);
    if let Ok(p) = again {
        let receipt = w.defmi.settle(p, 1_000, b"ctx", rng);
        assert!(!receipt.settled);
    }
}

#[test]
fn a_receipt_is_signed_over_what_it_says() {
    let rng = &mut OsRng;
    let mut w = world(rng);
    let p = package(&w, rng, 3, QTY, PRICE).unwrap();
    let mut receipt = w.defmi.settle(p, 1_000, b"ctx", rng);
    assert!(receipt.verify(&w.defmi.public_key()));
    receipt.settled_at += 1;
    assert!(
        !receipt.verify(&w.defmi.public_key()),
        "a receipt whose contents changed must stop verifying"
    );
}

#[test]
fn a_cash_leg_for_the_wrong_value_is_refused() {
    let rng = &mut OsRng;
    let mut w = world(rng);
    // Build the package honestly, then restate the cash value commitment as
    // something the product relation does not produce.
    let mut p = package(&w, rng, 4, QTY, PRICE).unwrap();
    p.cash_value_commitment = w.key.commit_u64(QTY * PRICE + 1, &Scalar::random(rng));
    let receipt = w.defmi.settle(p, 1_000, b"ctx", rng);
    assert!(!receipt.settled);
}

#[test]
fn nothing_is_applied_when_a_leg_fails() {
    let rng = &mut OsRng;
    let mut w = world(rng);
    let mut p = package(&w, rng, 5, QTY, PRICE).unwrap();
    p.securities.spend.outputs[0] += w.key.g; // no longer the proved value
    let before = (w.defmi.securities.snapshot(), w.defmi.cash.snapshot());
    let receipt = w.defmi.settle(p, 1_000, b"ctx", rng);
    assert!(!receipt.settled);
    assert_eq!(
        receipt.securities_after, before.0,
        "a failed leg still moved the rail"
    );
    assert_eq!(receipt.cash_after, before.1);
}

#[test]
fn two_payments_to_one_address_share_no_bytes() {
    let rng = &mut OsRng;
    let mut w = world(rng);
    let first = package(&w, rng, 6, QTY, PRICE).unwrap();
    let sec_notes: Vec<[u8; 32]> = first
        .securities
        .notes
        .iter()
        .map(|n| n.ephemeral.compress().to_bytes())
        .collect();
    assert!(w.defmi.settle(first, 1_000, b"ctx", rng).settled);

    let second = package(&w, rng, 7, QTY, PRICE);
    if let Ok(p) = second {
        for note in &p.securities.notes {
            assert!(
                !sec_notes.contains(&note.ephemeral.compress().to_bytes()),
                "a second payment to the same address reused a byte string"
            );
        }
    }
}
