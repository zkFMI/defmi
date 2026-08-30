//! The product zkPI binds a private payment to the pre-authorised QOMM
//! execution that produced it.  These tests intentionally exercise a fresh
//! quorum instead of treating the second signature as an opaque fixture.

use std::collections::BTreeMap;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::typed::{
    digest_for, AuthorizationScope, ExecutionContext, OperationKind, TradeDirection,
    TypedInstruction,
};
use qomm_zkpi::{
    deal_quorum, frost, typed_wire, Bounds, Issuer, QuoteBinding, Venue, DEFAULT_DOMAIN,
};
use rand::rngs::OsRng;

const THRESHOLD: usize = 3;

struct Quorum {
    shares: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: frost::keys::PublicKeyPackage,
}

fn quorum(rng: &mut OsRng) -> Quorum {
    let (secret, public) = deal_quorum(7, THRESHOLD as u16, rng).expect("deal test quorum");
    let shares = secret
        .into_iter()
        .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
        .collect();
    Quorum { shares, public }
}

fn sign(q: &Quorum, message: &[u8], rng: &mut OsRng) -> frost::Signature {
    let chosen: Vec<_> = q.shares.keys().take(THRESHOLD).copied().collect();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &chosen {
        let (nonce, commitment) = frost::round1::commit(q.shares[id].signing_share(), rng);
        nonces.insert(*id, nonce);
        commitments.insert(*id, commitment);
    }
    let package = frost::SigningPackage::new(commitments, message);
    let shares = chosen
        .iter()
        .map(|id| {
            (
                *id,
                frost::round2::sign(&package, &nonces[id], &q.shares[id]).unwrap(),
            )
        })
        .collect();
    frost::aggregate(&package, &shares, &q.public).expect("aggregate")
}

fn execution_context(
    operation: OperationKind,
    maker: RistrettoPoint,
    taker: RistrettoPoint,
) -> ExecutionContext {
    let execution_only = matches!(operation, OperationKind::Consume | OperationKind::Settle);
    ExecutionContext {
        operation,
        scope: if execution_only {
            AuthorizationScope::Joint
        } else {
            AuthorizationScope::Maker
        },
        direction: TradeDirection::TakerBuys,
        venue_id: [12; 32],
        defmi_id: [13; 32],
        maker_handle: maker,
        taker_handle: taker,
        reserve_handle: RistrettoPoint::mul_base(&Scalar::from(33u64)),
        maker_reservation_id: [1; 32],
        maker_reservation_sequence: 9,
        taker_reservation_id: if execution_only { [9; 32] } else { [0; 32] },
        taker_reservation_sequence: if execution_only { 12 } else { 0 },
        rfq_nullifier: if execution_only { [2; 32] } else { [0; 32] },
        taker_mandate_digest: if execution_only { [3; 32] } else { [0; 32] },
        maker_policy_digest: [4; 32],
        maker_mandate_digest: if execution_only || operation == OperationKind::Reserve {
            [11; 32]
        } else {
            [0; 32]
        },
        maker_reserve_receipt_digest: if operation == OperationKind::Reserve {
            [0; 32]
        } else {
            [5; 32]
        },
        taker_reserve_receipt_digest: if execution_only { [10; 32] } else { [0; 32] },
        quote_proof_digest: if execution_only { [6; 32] } else { [0; 32] },
        market_statement_digest: if execution_only { [7; 32] } else { [0; 32] },
        before_state_root: [8; 32],
    }
}

fn typed(operation: OperationKind) -> (TypedInstruction, Quorum) {
    let mut rng = OsRng;
    let q = quorum(&mut rng);
    let taker = RistrettoPoint::mul_base(&Scalar::from(11u64));
    let maker = RistrettoPoint::mul_base(&Scalar::from(22u64));
    let reserve = RistrettoPoint::mul_base(&Scalar::from(33u64));
    let (payer, payee) = if operation == OperationKind::Reserve {
        (maker, reserve)
    } else {
        (taker, maker)
    };
    let issuer = Issuer::new(Pedersen::new(b"qomm:defmi:v1"), Bounds::default());
    let (payment_digest, _, partial) = issuer
        .build(
            100, 99_990, 3, payer, payee, 1_500, [7; 32], 1_599_845, &mut rng,
        )
        .expect("build payment");
    let payment = partial.sealed(sign(&q, &payment_digest, &mut rng));
    let context = execution_context(operation, maker, taker);
    let typed_digest = digest_for(&payment, &context, DEFAULT_DOMAIN).expect("valid context");
    let authorization = sign(&q, &typed_digest, &mut rng);
    (
        TypedInstruction {
            payment,
            context,
            authorization,
        },
        q,
    )
}

fn venue(q: &Quorum) -> Venue {
    Venue::new(
        Pedersen::new(b"qomm:defmi:v1"),
        &Bounds::default(),
        q.public.clone(),
    )
}

#[test]
fn a_typed_instruction_round_trips_and_settles_only_once() {
    let (instruction, q) = typed(OperationKind::Settle);
    let bytes = typed_wire::encode(&instruction);
    let decoded = typed_wire::decode(&bytes).expect("decode typed zkPI");
    assert_eq!(typed_wire::encode(&decoded), bytes);
    assert_eq!(
        decoded.digest_for(DEFAULT_DOMAIN),
        instruction.digest_for(DEFAULT_DOMAIN)
    );

    let mut venue = venue(&q);
    assert_eq!(venue.settle_typed(&decoded, 1_000), Ok(()));
    assert_eq!(venue.settle_typed(&decoded, 1_000), Err("already settled"));
}

#[test]
fn changing_the_reservation_or_quote_breaks_the_product_signature() {
    let (instruction, q) = typed(OperationKind::Consume);
    let mut changed_sequence = instruction.clone();
    changed_sequence.context.maker_reservation_sequence += 1;
    assert_eq!(
        venue(&q).verify_typed(&changed_sequence, 1_000),
        Err("the typed zkPI authorization does not verify")
    );

    let mut changed_quote = instruction;
    changed_quote.context.quote_proof_digest[0] ^= 1;
    assert_eq!(
        venue(&q).verify_typed(&changed_quote, 1_000),
        Err("the typed zkPI authorization does not verify")
    );
}

#[test]
fn v2_payment_and_execution_context_must_name_the_same_quote_proof() {
    let (mut instruction, _) = typed(OperationKind::Settle);
    instruction.payment.quote_binding =
        QuoteBinding::ProofDigest(instruction.context.quote_proof_digest);
    assert_eq!(
        instruction.context.validate_against(&instruction.payment),
        Ok(())
    );
    instruction.context.quote_proof_digest[0] ^= 1;
    assert_eq!(
        instruction.context.validate_against(&instruction.payment),
        Err("the payment zkPI and execution context name different quote proofs")
    );
}

#[test]
fn payer_and_payee_must_match_the_trade_direction() {
    let (mut instruction, q) = typed(OperationKind::Settle);
    instruction.context.direction = TradeDirection::TakerSells;
    assert_eq!(
        venue(&q).verify_typed(&instruction, 1_000),
        Err("Maker/Taker roles do not match the payer/payee legs")
    );
}

#[test]
fn reserve_cannot_claim_a_future_rfq_and_settlement_cannot_omit_it() {
    let (mut reserve, _) = typed(OperationKind::Reserve);
    reserve.context.rfq_nullifier = [9; 32];
    assert_eq!(
        reserve.context.validate_against(&reserve.payment),
        Err("a Maker reserve cannot claim a later RFQ")
    );

    let (mut settlement, _) = typed(OperationKind::Settle);
    settlement.context.rfq_nullifier = [0; 32];
    assert_eq!(
        settlement.context.validate_against(&settlement.payment),
        Err("settlement lacks the one-use RFQ")
    );
}

#[test]
fn typed_wire_refuses_trailing_and_invalid_context_bytes() {
    let (instruction, _) = typed(OperationKind::Settle);
    let mut trailing = typed_wire::encode(&instruction);
    trailing.push(0);
    assert_eq!(
        typed_wire::decode(&trailing).err(),
        Some(typed_wire::Error::Trailing(1))
    );

    let mut invalid = typed_wire::encode(&instruction);
    // magic(8), version(2), base length(4), base, operation, scope, direction,
    // venue(32), DeFMI(32), maker(32), taker(32), reserve(32), then Maker reservation id.
    let base_len = u32::from_be_bytes(invalid[10..14].try_into().unwrap()) as usize;
    let reservation = 14 + base_len + 3 + 32 + 32 + 32 + 32 + 32;
    invalid[reservation..reservation + 32].fill(0);
    assert_eq!(
        typed_wire::decode(&invalid).err(),
        Some(typed_wire::Error::InvalidContext)
    );
}

#[test]
fn context_only_wire_round_trips_and_rejects_trailing_bytes() {
    let (instruction, _) = typed(OperationKind::Settle);
    let bytes = typed_wire::encode_context(&instruction.context);
    let decoded = typed_wire::decode_context(&bytes, &instruction.payment)
        .expect("decode context-only typed zkPI wire");
    assert_eq!(typed_wire::encode_context(&decoded), bytes);

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        typed_wire::decode_context(&trailing, &instruction.payment).err(),
        Some(typed_wire::Error::Trailing(1))
    );
}
