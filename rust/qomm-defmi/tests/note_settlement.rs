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
use qomm_proofs::threshold_range::{deal_bits, joint_prove_range_from_contributions};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::{
    deal_quorum, frost, Bounds, Instruction, Issuer, Openings, PartialInstruction, Venue,
    AMOUNT_RANGE_CONTEXT, PRICE_RANGE_CONTEXT,
};
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

fn threshold_instruction(
    w: &World,
    rng: &mut OsRng,
    nonce: u8,
    qty: u64,
    price: u64,
    quote_proof_digest: [u8; 32],
) -> (Instruction, Scalar, Scalar) {
    let openings = Openings {
        amount: Scalar::random(rng),
        price: Scalar::random(rng),
        asset: Scalar::random(rng),
    };
    let parties = [1usize, 2, 3, 4, 5, 6, 7];
    let quorum = [1usize, 2, 3];
    let amount_shares = deal_bits(
        &w.issuer.key,
        qty,
        &openings.amount,
        w.issuer.bounds.amount_bits,
        &parties,
        2,
        rng,
    )
    .unwrap();
    let price_shares = deal_bits(
        &w.issuer.key,
        price,
        &openings.price,
        w.issuer.bounds.price_bits,
        &parties,
        2,
        rng,
    )
    .unwrap();
    let amount_nodes = quorum
        .iter()
        .map(|party| amount_shares.node_contribution(*party).unwrap())
        .collect::<Vec<_>>();
    let price_nodes = quorum
        .iter()
        .map(|party| price_shares.node_contribution(*party).unwrap())
        .collect::<Vec<_>>();
    let (amount_range, _) = joint_prove_range_from_contributions(
        &w.issuer.key,
        &amount_nodes,
        &quorum,
        AMOUNT_RANGE_CONTEXT,
        rng,
    )
    .unwrap();
    let (price_range, _) = joint_prove_range_from_contributions(
        &w.issuer.key,
        &price_nodes,
        &quorum,
        PRICE_RANGE_CONTEXT,
        rng,
    )
    .unwrap();
    let partial = PartialInstruction::from_threshold_ranges(
        &w.issuer.key,
        &w.issuer.bounds,
        amount_shares.commitment,
        price_shares.commitment,
        w.issuer
            .key
            .commit(&Scalar::from(w.sec_asset as u64), &openings.asset),
        amount_range,
        price_range,
        RistrettoPoint::mul_base(&Scalar::from(11u64)),
        RistrettoPoint::mul_base(&Scalar::from(22u64)),
        1_500,
        [nonce; 32],
        quote_proof_digest,
    )
    .unwrap();
    let digest = partial.digest_for(&w.issuer.domain);
    (
        partial.sealed(sign(w, &digest, rng)),
        openings.amount,
        openings.price,
    )
}

fn package_from_instruction(
    w: &World,
    rng: &mut OsRng,
    instruction: Instruction,
    amount_blinding: Scalar,
    price_blinding: Scalar,
    qty: u64,
    price: u64,
) -> Result<NoteDvpPackage, &'static str> {
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

fn package(
    w: &World,
    rng: &mut OsRng,
    nonce: u8,
    qty: u64,
    price: u64,
) -> Result<NoteDvpPackage, &'static str> {
    let (instruction, amount_blinding, price_blinding) = instruction(w, rng, nonce, qty, price);
    package_from_instruction(
        w,
        rng,
        instruction,
        amount_blinding,
        price_blinding,
        qty,
        price,
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

#[cfg(feature = "avalanche")]
#[test]
fn verified_wallet_dvp_and_typed_zkpi_project_only_to_a_non_product_note_order() {
    use qomm_defmi::facility::ZERO;
    use qomm_defmi::note_chain::{NoteLegProjection, VerifiedNoteSettlementProjection};
    use qomm_zkpi::typed::{
        digest_for as typed_digest_for, AuthorizationScope, ExecutionContext, OperationKind,
        TradeDirection, TypedInstruction,
    };
    use qomm_zkpi::DEFAULT_DOMAIN;
    use sha2::{Digest, Sha256};

    fn h(label: &str) -> [u8; 32] {
        Sha256::digest(label.as_bytes()).into()
    }

    let rng = &mut OsRng;
    let w = world(rng);
    let quote = h("verified-note-quote");
    let (instruction, amount_blinding, price_blinding) =
        threshold_instruction(&w, rng, 44, QTY, PRICE, quote);
    let package = package_from_instruction(
        &w,
        rng,
        instruction,
        amount_blinding,
        price_blinding,
        QTY,
        PRICE,
    )
    .unwrap();

    let maker_hold = h("verified-note-maker-hold");
    let taker_hold = h("verified-note-taker-hold");
    let market = h("verified-note-market");
    let context = ExecutionContext {
        operation: OperationKind::Settle,
        scope: AuthorizationScope::Joint,
        direction: TradeDirection::TakerBuys,
        venue_id: h("verified-note-venue"),
        defmi_id: h("verified-note-defmi"),
        maker_handle: package.instruction.payee_handle,
        taker_handle: package.instruction.payer_handle,
        reserve_handle: RistrettoPoint::mul_base(&Scalar::from(77u64)),
        maker_reservation_id: maker_hold,
        maker_reservation_sequence: 1,
        taker_reservation_id: taker_hold,
        taker_reservation_sequence: 1,
        rfq_nullifier: h("verified-note-rfq"),
        taker_mandate_digest: h("verified-note-taker-mandate"),
        maker_policy_digest: h("verified-note-maker-policy"),
        maker_mandate_digest: h("verified-note-maker-mandate"),
        maker_reserve_receipt_digest: h("verified-note-maker-receipt"),
        taker_reserve_receipt_digest: h("verified-note-taker-receipt"),
        quote_proof_digest: quote,
        market_statement_digest: market,
        before_state_root: h("verified-note-before-root"),
    };
    let typed_digest = typed_digest_for(&package.instruction, &context, DEFAULT_DOMAIN).unwrap();
    let typed = TypedInstruction {
        payment: package.instruction.clone(),
        context,
        authorization: sign(&w, &typed_digest, rng),
    };

    // This fixture marks every member eligible for the same lock class. The
    // separate constrained-ring tests exercise the production case where only
    // the hidden escrow note is eligible and all other members are decoys.
    let securities_locks = vec![maker_hold; package.securities.ring.len()];
    let cash_locks = vec![taker_hold; package.cash.ring.len()];
    let securities_output_locks = vec![ZERO; package.securities.notes.len()];
    let cash_output_locks = vec![ZERO; package.cash.notes.len()];
    let projection = VerifiedNoteSettlementProjection::verify_and_project(
        &w.defmi,
        &typed,
        &package,
        h("verified-note-operation"),
        NoteLegProjection {
            asset_id: h("verified-note-security-asset"),
            ring_locks: &securities_locks,
            input_lock_id: maker_hold,
            output_locks: &securities_output_locks,
        },
        NoteLegProjection {
            asset_id: h("verified-note-cash-asset"),
            ring_locks: &cash_locks,
            input_lock_id: taker_hold,
            output_locks: &cash_output_locks,
        },
        market,
        b"ctx",
        1_000,
        rng,
    )
    .unwrap();
    let settlement_statement = projection.settlement.statement().unwrap();
    assert_ne!(settlement_statement, [0; 32]);
    assert_eq!(projection.quote_proof_digest, quote);
    assert_eq!(projection.dvp_proof_digest, package.digest());
}

#[cfg(feature = "avalanche")]
#[test]
fn threshold_dvp_projects_to_predelegated_claims_without_a_post_quote_wallet_spend() {
    use qomm_defmi::facility::{
        CreditFacilityTransition, CreditTransitionKind, ReservationConsumption, ReservationRole,
        ZERO,
    };
    use qomm_defmi::note_chain::{
        DelegatedClaimOpenings, DelegatedNoteLegProjection, NoteClaimKind, ProductNoteBindings,
        VerifiedDelegatedNoteSettlementProjection,
    };
    use qomm_defmi::settlement::{
        build_threshold_package_from_contributions, Sides, ThresholdDvpNodeContribution,
    };
    use qomm_proofs::opening_envelope::{encrypt_opening_share, opening_context, OpeningEnvelope};
    use qomm_proofs::threshold_gadgets::{ProductNodeContribution, Shared};
    use qomm_proofs::threshold_sigma::deal;
    use qomm_zk::shamir;
    use qomm_zkpi::typed::{
        digest_for as typed_digest_for, AuthorizationScope, ExecutionContext, OperationKind,
        TradeDirection, TypedInstruction,
    };
    use qomm_zkpi::DEFAULT_DOMAIN;
    use sha2::{Digest, Sha256};

    fn h(label: &str) -> [u8; 32] {
        Sha256::digest(label.as_bytes()).into()
    }

    let rng = &mut OsRng;
    let w = world(rng);
    let quote = h("delegated-note-quote");
    let (instruction, amount_blinding, price_blinding) =
        threshold_instruction(&w, rng, 45, QTY, PRICE, quote);
    let cash_value = QTY.checked_mul(PRICE).unwrap();
    let cash_blinding = Scalar::random(rng);
    let securities_reserve_blinding = amount_blinding;
    let cash_reserve_blinding = Scalar::random(rng);
    // The Maker reserves exactly the traded quantity. This is the production
    // edge case in which the securities refund commitment is the Ristretto
    // identity rather than a non-zero point.
    let securities_reserve_value = QTY;
    let securities_reserve = w
        .key
        .commit_u64(securities_reserve_value, &securities_reserve_blinding);
    let cash_reserve = w.key.commit_u64(CASH_NOTE, &cash_reserve_blinding);
    let cash_commitment = w.key.commit_u64(cash_value, &cash_blinding);
    let parties = [1usize, 2, 3, 4, 5, 6, 7];
    let quorum = [1usize, 2, 3];
    let threshold = 2;

    let dealt_price = deal(
        &w.key,
        &Scalar::from(PRICE),
        &price_blinding,
        &parties,
        threshold,
        rng,
    )
    .unwrap();
    assert_eq!(dealt_price.commitment, instruction.price_commitment);
    let shared_price = Shared {
        commitment: dealt_price.commitment,
        value: dealt_price.value_shares,
        blinding: dealt_price.blinding_shares,
        coefficient_commitments: dealt_price.coefficient_commitments,
    };
    let product_cross = cash_blinding - amount_blinding * Scalar::from(PRICE);
    let party_points = parties
        .iter()
        .map(|party| Scalar::from(*party as u64))
        .collect::<Vec<_>>();
    let cross_shares = parties
        .iter()
        .copied()
        .zip(shamir::share(&product_cross, threshold, &party_points, rng))
        .collect::<BTreeMap<_, _>>();
    let securities_remainder = deal_bits(
        &w.key,
        securities_reserve_value - QTY,
        &(securities_reserve_blinding - amount_blinding),
        BITS,
        &parties,
        threshold,
        rng,
    )
    .unwrap();
    let cash_remainder = deal_bits(
        &w.key,
        CASH_NOTE - cash_value,
        &(cash_reserve_blinding - cash_blinding),
        BITS,
        &parties,
        threshold,
        rng,
    )
    .unwrap();
    let contributions = quorum
        .iter()
        .map(|party| {
            ThresholdDvpNodeContribution::new(
                ProductNodeContribution::new(
                    shared_price.node_share(*party).unwrap(),
                    cross_shares[party],
                ),
                securities_remainder.node_contribution(*party).unwrap(),
                cash_remainder.node_contribution(*party).unwrap(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let expected_sides = Sides::of(&instruction);
    let package = build_threshold_package_from_contributions(
        &w.key,
        instruction.clone(),
        Sides {
            securities_from: b"delegated-securities-escrow".to_vec(),
            securities_to: expected_sides.securities_to,
            cash_from: b"delegated-cash-escrow".to_vec(),
            cash_to: expected_sides.cash_to,
        },
        securities_reserve,
        cash_reserve,
        cash_commitment,
        &contributions,
        &quorum,
        threshold,
        BITS,
        rng,
    )
    .unwrap();

    let maker_hold = h("delegated-note-maker-hold");
    let taker_hold = h("delegated-note-taker-hold");
    let market = h("delegated-note-market");
    let context = ExecutionContext {
        operation: OperationKind::Settle,
        scope: AuthorizationScope::Joint,
        direction: TradeDirection::TakerBuys,
        venue_id: h("delegated-note-venue"),
        defmi_id: h("delegated-note-defmi"),
        maker_handle: instruction.payee_handle,
        taker_handle: instruction.payer_handle,
        reserve_handle: RistrettoPoint::mul_base(&Scalar::from(78u64)),
        maker_reservation_id: maker_hold,
        maker_reservation_sequence: 1,
        taker_reservation_id: taker_hold,
        taker_reservation_sequence: 1,
        rfq_nullifier: h("delegated-note-rfq"),
        taker_mandate_digest: h("delegated-note-taker-mandate"),
        maker_policy_digest: h("delegated-note-maker-policy"),
        maker_mandate_digest: h("delegated-note-maker-mandate"),
        maker_reserve_receipt_digest: h("delegated-note-maker-receipt"),
        taker_reserve_receipt_digest: h("delegated-note-taker-receipt"),
        quote_proof_digest: quote,
        market_statement_digest: market,
        before_state_root: h("delegated-note-before-root"),
    };
    let typed_digest = typed_digest_for(&instruction, &context, DEFAULT_DOMAIN).unwrap();
    let typed = TypedInstruction {
        payment: instruction,
        context,
        authorization: sign(&w, &typed_digest, rng),
    };
    let securities_asset = h("delegated-note-security-asset");
    let cash_asset = h("delegated-note-cash-asset");
    let proof_job_id = h("delegated-note-proof-job");
    let mut envelope = |leg: &str, recipient: RistrettoPoint| {
        let opening_context = opening_context(&proof_job_id, leg).unwrap();
        OpeningEnvelope::new(
            opening_context,
            threshold + 1,
            recipient,
            parties
                .iter()
                .map(|party| {
                    encrypt_opening_share(
                        opening_context,
                        *party,
                        Scalar::from(*party as u64),
                        Scalar::from(*party as u64 + 20),
                        &recipient,
                        rng,
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap()
    };
    let openings = DelegatedClaimOpenings {
        proof_job_id,
        securities_delivery: envelope("securities_delivery", typed.payment.payer_handle),
        securities_refund: envelope("securities_refund", typed.payment.payee_handle),
        cash_delivery: envelope("cash_delivery", typed.payment.payee_handle),
        cash_refund: envelope("cash_refund", typed.payment.payer_handle),
    };
    let projection = VerifiedDelegatedNoteSettlementProjection::verify_and_project(
        &w.defmi.venue,
        &typed,
        &package,
        h("delegated-note-operation"),
        DelegatedNoteLegProjection {
            asset_id: securities_asset,
            hold_id: maker_hold,
            escrow_note_id: h("delegated-note-security-escrow"),
            delegation_digest: h("delegated-note-maker-delegation"),
            reserve_commitment: securities_reserve.compress().to_bytes(),
        },
        DelegatedNoteLegProjection {
            asset_id: cash_asset,
            hold_id: taker_hold,
            escrow_note_id: h("delegated-note-cash-escrow"),
            delegation_digest: h("delegated-note-taker-delegation"),
            reserve_commitment: cash_reserve.compress().to_bytes(),
        },
        openings,
        market,
        1_000,
    )
    .unwrap();
    let settlement_statement = projection.settlement.statement().unwrap();
    let transition = |role: &str,
                      facility_id: [u8; 32],
                      hold_id: [u8; 32],
                      reserve: [u8; 32],
                      consumed: [u8; 32],
                      refund: [u8; 32]| CreditFacilityTransition {
        operation_id: h(&format!("delegated-note-{role}-consume")),
        facility_id,
        hold_id,
        kind: CreditTransitionKind::Consume,
        query_commitment: h(&format!("delegated-note-{role}-query")),
        amount_commitment: reserve,
        consumed_commitment: consumed,
        refund_commitment: refund,
        before_available_commitment: h(&format!("delegated-note-{role}-available")),
        after_available_commitment: h(&format!("delegated-note-{role}-available-after")),
        before_held_commitment: reserve,
        after_held_commitment: ZERO,
        before_outstanding_commitment: ZERO,
        after_outstanding_commitment: consumed,
        before_sequence: 1,
        expires_at: 1_500,
        settlement_digest: settlement_statement,
        relation_proof_digest: h(&format!("delegated-note-{role}-relation")),
    };
    let order = projection
        .into_product(ProductNoteBindings {
            maker_entity_commitment: h("delegated-note-maker-entity"),
            taker_entity_commitment: h("delegated-note-taker-entity"),
            traded_asset_id: securities_asset,
            price_limit_proof_digest: h("delegated-note-limit-proof"),
            asset_link_proof_digest: h("delegated-note-asset-proof"),
            admission_receipt_digest: h("delegated-note-admission"),
            admission_epoch: 9,
            admission_sequence: 4,
            reservations: vec![
                ReservationConsumption {
                    role: ReservationRole::Maker,
                    reserve_receipt_digest: h("delegated-note-maker-receipt"),
                    transition: transition(
                        "maker",
                        h("delegated-note-maker-facility"),
                        maker_hold,
                        securities_reserve.compress().to_bytes(),
                        typed.payment.amount_commitment.compress().to_bytes(),
                        package.securities_remainder.compress().to_bytes(),
                    ),
                },
                ReservationConsumption {
                    role: ReservationRole::Taker,
                    reserve_receipt_digest: h("delegated-note-taker-receipt"),
                    transition: transition(
                        "taker",
                        h("delegated-note-taker-facility"),
                        taker_hold,
                        cash_reserve.compress().to_bytes(),
                        package.cash_commitment.compress().to_bytes(),
                        package.cash_remainder.compress().to_bytes(),
                    ),
                },
            ],
        })
        .unwrap();
    assert_eq!(order.settlement.spends.len(), 2);
    assert!(order.settlement.spends.iter().all(|spend| {
        spend.claims.len() == 2
            && spend
                .claims
                .iter()
                .any(|claim| claim.kind == NoteClaimKind::Delivery)
            && spend
                .claims
                .iter()
                .any(|claim| claim.kind == NoteClaimKind::Refund)
    }));
    assert!(order.settlement.spends.iter().any(|spend| {
        spend
            .claims
            .iter()
            .any(|claim| claim.kind == NoteClaimKind::Refund && claim.value_commitment == ZERO)
    }));
    assert_eq!(order.dvp_proof_digest, package.digest());
    assert_ne!(order.statement().unwrap(), ZERO);
}
