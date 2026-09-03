use std::collections::BTreeMap;

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use qomm_proofs::threshold_range::{
    deal_bits, joint_prove_range_from_contributions, ThresholdRangeProof,
};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::receivable::{
    digest_for, eligibility_relation_digest, ProviderReference, ReceivableExecutionContext,
    ReceivableInstruction, ReceivableOperation, ELIGIBILITY_REMAINING_CONTEXT,
};
use qomm_zkpi::{
    deal_quorum, frost, receivable_wire, Bounds, PartialInstruction, Venue, AMOUNT_RANGE_CONTEXT,
    DEFAULT_DOMAIN, PRICE_RANGE_CONTEXT,
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

fn reference(artifact: u8, provider: u8, backing: u8) -> ProviderReference {
    ProviderReference {
        artifact_id: [artifact; 32],
        provider_id: [provider; 32],
        backing_id: [backing; 32],
    }
}

fn threshold_range(
    key: &Pedersen,
    value: u64,
    blinding: Scalar,
    bits: usize,
    context: &[u8],
    rng: &mut OsRng,
) -> ThresholdRangeProof {
    let parties = [1_usize, 2, 3, 4, 5, 6, 7];
    let dealt = deal_bits(key, value, &blinding, bits, &parties, 2, rng).unwrap();
    let selected = [1_usize, 4, 7];
    let contributions = selected
        .iter()
        .map(|party| dealt.node_contribution(*party).unwrap())
        .collect::<Vec<_>>();
    joint_prove_range_from_contributions(key, &contributions, &selected, context, rng)
        .unwrap()
        .0
}

fn make_instruction() -> (ReceivableInstruction, Quorum) {
    let mut rng = OsRng;
    let q = quorum(&mut rng);
    let payer = RistrettoPoint::mul_base(&Scalar::from(11u64));
    let payee = RistrettoPoint::mul_base(&Scalar::from(22u64));
    let key = Pedersen::new(b"qomm:defmi:v1");
    let bounds = Bounds {
        amount_bits: 8,
        price_bits: 8,
        max_horizon: 86_400,
    };
    let amount_blinding = Scalar::from(55u64);
    let price_blinding = Scalar::from(56u64);
    let amount_commitment = key.commit(&Scalar::from(100u64), &amount_blinding);
    let price_commitment = key.commit(&Scalar::from(95u64), &price_blinding);
    let amount_range = threshold_range(
        &key,
        100,
        amount_blinding,
        bounds.amount_bits,
        AMOUNT_RANGE_CONTEXT,
        &mut rng,
    );
    let price_range = threshold_range(
        &key,
        95,
        price_blinding,
        bounds.price_bits,
        PRICE_RANGE_CONTEXT,
        &mut rng,
    );
    let eligible_blinding = Scalar::from(77u64);
    let eligible = key.commit(&Scalar::from(150u64), &eligible_blinding);
    let before_pledged = RistrettoPoint::identity();
    let after_pledged = amount_commitment;
    let eligibility_remaining = threshold_range(
        &key,
        50,
        eligible_blinding - amount_blinding,
        bounds.amount_bits,
        ELIGIBILITY_REMAINING_CONTEXT,
        &mut rng,
    );
    let relation_proof_digest = eligibility_relation_digest(&eligibility_remaining);
    let partial = PartialInstruction::from_threshold_ranges(
        &key,
        &bounds,
        amount_commitment,
        price_commitment,
        key.commit(&Scalar::from(3u64), &Scalar::from(57u64)),
        amount_range,
        price_range,
        payer,
        payee,
        1_500,
        [7; 32],
        relation_proof_digest,
    )
    .expect("build threshold payment");
    let payment_digest = partial.digest_for(DEFAULT_DOMAIN);
    let payment = partial.sealed(sign(&q, &payment_digest, &mut rng));
    let context = ReceivableExecutionContext {
        operation: ReceivableOperation::Issue,
        venue_id: [10; 32],
        defmi_id: [11; 32],
        verifier_epoch: 4,
        aethel_domain_id: [12; 32],
        request_id: [13; 32],
        action_id: [14; 32],
        series_id: [15; 32],
        stream_id: [16; 32],
        stream_state_version: 8,
        before_stream_state_root: [17; 32],
        after_stream_state_root: [18; 32],
        eligible_commitment: eligible.compress().to_bytes(),
        before_pledged_commitment: before_pledged.compress().to_bytes(),
        after_pledged_commitment: after_pledged.compress().to_bytes(),
        receivable_note_id: [19; 32],
        settlement_asset_id: [20; 32],
        credit: reference(21, 22, 23),
        guarantee: reference(24, 25, 26),
        funding: reference(27, 28, 29),
        policy_digest: [30; 32],
        relation_proof_digest,
        operation_nullifier: [31; 32],
        before_aethel_root: [32; 32],
    };
    let authorization_digest = digest_for(&payment, &context, DEFAULT_DOMAIN).unwrap();
    let authorization = sign(&q, &authorization_digest, &mut rng);
    (
        ReceivableInstruction {
            instruction: payment,
            context,
            eligibility_remaining: Some(eligibility_remaining),
            authorization,
        },
        q,
    )
}

fn venue(q: &Quorum) -> Venue {
    Venue::new(
        Pedersen::new(b"qomm:defmi:v1"),
        &Bounds {
            amount_bits: 8,
            price_bits: 8,
            max_horizon: 86_400,
        },
        q.public.clone(),
    )
}

#[test]
fn streaming_receivable_wire_round_trips_and_verifies() {
    let (instruction, q) = make_instruction();
    let bytes = receivable_wire::encode(&instruction);
    let decoded = receivable_wire::decode(&bytes).expect("decode streaming receivable zkPI");
    assert_eq!(receivable_wire::encode(&decoded), bytes);
    assert_eq!(venue(&q).verify_receivable(&decoded, 1_000), Ok(()));
}

#[test]
fn changing_a_guarantee_or_stream_root_breaks_authorization() {
    let (instruction, q) = make_instruction();
    let mut changed_guarantee = instruction.clone();
    changed_guarantee.context.guarantee.backing_id[0] ^= 1;
    assert_eq!(
        venue(&q).verify_receivable(&changed_guarantee, 1_000),
        Err("streaming-receivable zkPI authorization does not verify")
    );

    let mut changed_stream = instruction.clone();
    changed_stream.context.after_stream_state_root[0] ^= 1;
    assert_eq!(
        venue(&q).verify_receivable(&changed_stream, 1_000),
        Err("streaming-receivable zkPI authorization does not verify")
    );

    let mut exhausted_capacity = instruction.clone();
    exhausted_capacity.context.eligible_commitment =
        exhausted_capacity.context.after_pledged_commitment;
    assert_eq!(
        venue(&q).verify_receivable(&exhausted_capacity, 1_000),
        Err("issued face value exceeds the eligible stream balance")
    );

    let mut non_additive_pledge = instruction;
    non_additive_pledge.context.after_pledged_commitment =
        RistrettoPoint::mul_base(&Scalar::from(99u64))
            .compress()
            .to_bytes();
    assert_eq!(
        venue(&q).verify_receivable(&non_additive_pledge, 1_000),
        Err("post-issuance pledged commitment does not add the face value")
    );
}

#[test]
fn partial_provider_reference_and_wrong_relation_proof_are_rejected() {
    let (instruction, _) = make_instruction();
    let mut partial_reference = instruction.clone();
    partial_reference.context.funding.backing_id = [0; 32];
    assert_eq!(
        partial_reference
            .context
            .validate_against(&partial_reference.instruction),
        Err("provider artifact reference is only partially bound")
    );

    let mut wrong_relation = instruction;
    wrong_relation.context.relation_proof_digest[0] ^= 1;
    assert_eq!(
        wrong_relation
            .context
            .validate_against(&wrong_relation.instruction),
        Err("base zkPI and receivable context name different relation proofs")
    );
}

#[test]
fn replacing_the_eligibility_proof_breaks_its_signed_binding() {
    let (mut instruction, q) = make_instruction();
    instruction
        .eligibility_remaining
        .as_mut()
        .unwrap()
        .linkage
        .z_value += Scalar::ONE;
    assert_eq!(
        venue(&q).verify_receivable(&instruction, 1_000),
        Err("receivable eligibility proof digest does not match its binding")
    );
}
