//! Production zkPI shape: the MPC quorum proves ranges from Shamir shares,
//! then a separate FROST quorum signature authorises the public instruction.

use std::collections::BTreeMap;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use qomm_proofs::threshold_range::{deal_bits, joint_prove_range_from_contributions};
use qomm_proofs::threshold_sigma::PartyId;
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::wire::{decode, encode, VERSION};
use qomm_zkpi::{
    deal_quorum, frost, Bounds, Issuer, PartialInstruction, Venue, AMOUNT_RANGE_CONTEXT,
    PRICE_RANGE_CONTEXT,
};
use rand::rngs::OsRng;

const PARTIES: [PartyId; 7] = [1, 2, 3, 4, 5, 6, 7];
const QUORUM: [PartyId; 3] = [1, 2, 3];

fn sign(
    message: &[u8],
    shares: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: &frost::keys::PublicKeyPackage,
) -> frost::Signature {
    let chosen = shares.keys().take(3).copied().collect::<Vec<_>>();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &chosen {
        let (nonce, commitment) = frost::round1::commit(shares[id].signing_share(), &mut OsRng);
        nonces.insert(*id, nonce);
        commitments.insert(*id, commitment);
    }
    let package = frost::SigningPackage::new(commitments, message);
    let signature_shares = chosen
        .iter()
        .map(|id| {
            (
                *id,
                frost::round2::sign(&package, &nonces[id], &shares[id]).unwrap(),
            )
        })
        .collect();
    frost::aggregate(&package, &signature_shares, public).unwrap()
}

fn threshold_instruction() -> (qomm_zkpi::Instruction, frost::keys::PublicKeyPackage) {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let bounds = Bounds {
        amount_bits: 16,
        price_bits: 32,
        ..Bounds::default()
    };
    let amount = deal_bits(
        &key,
        1_000,
        &Scalar::random(&mut OsRng),
        bounds.amount_bits,
        &PARTIES,
        2,
        &mut OsRng,
    )
    .unwrap();
    let price = deal_bits(
        &key,
        99_990,
        &Scalar::random(&mut OsRng),
        bounds.price_bits,
        &PARTIES,
        2,
        &mut OsRng,
    )
    .unwrap();
    let amount_nodes = QUORUM
        .iter()
        .map(|party| amount.node_contribution(*party).unwrap())
        .collect::<Vec<_>>();
    let price_nodes = QUORUM
        .iter()
        .map(|party| price.node_contribution(*party).unwrap())
        .collect::<Vec<_>>();
    let (amount_range, _) = joint_prove_range_from_contributions(
        &key,
        &amount_nodes,
        &QUORUM,
        AMOUNT_RANGE_CONTEXT,
        &mut OsRng,
    )
    .unwrap();
    let (price_range, _) = joint_prove_range_from_contributions(
        &key,
        &price_nodes,
        &QUORUM,
        PRICE_RANGE_CONTEXT,
        &mut OsRng,
    )
    .unwrap();
    let partial = PartialInstruction::from_threshold_ranges(
        &key,
        &bounds,
        amount.commitment,
        price.commitment,
        key.commit(&Scalar::from(3u64), &Scalar::random(&mut OsRng)),
        amount_range,
        price_range,
        RistrettoPoint::mul_base(&Scalar::from(11u64)),
        RistrettoPoint::mul_base(&Scalar::from(22u64)),
        1_500,
        [7u8; 32],
        [42u8; 32],
    )
    .unwrap();
    let digest = partial.digest().to_vec();

    let (dealt, public) = deal_quorum(7, 3, &mut OsRng).unwrap();
    let shares = dealt
        .into_iter()
        .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
        .collect::<BTreeMap<_, _>>();
    let signature = sign(&digest, &shares, &public);
    (partial.sealed(signature), public)
}

#[test]
fn threshold_ranges_round_trip_and_verify_without_openings() {
    let (instruction, public) = threshold_instruction();
    let bytes = encode(&instruction);
    assert_eq!(
        u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
        VERSION
    );
    let decoded = decode(&bytes).unwrap();
    assert!(decoded.ranges.is_threshold());
    assert_eq!(encode(&decoded), bytes);

    let venue = Venue::new(
        Pedersen::new(b"qomm:defmi:v1"),
        &Bounds {
            amount_bits: 16,
            price_bits: 32,
            ..Bounds::default()
        },
        public,
    )
    .require_threshold_ranges();
    assert_eq!(venue.verify(&decoded, 1_000), Ok(()));
}

#[test]
fn a_production_venue_rejects_the_legacy_cleartext_issuer() {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let bounds = Bounds::default();
    let issuer = Issuer::new(key.clone(), bounds.clone());
    let (dealt, public) = deal_quorum(7, 3, &mut OsRng).unwrap();
    let shares = dealt
        .into_iter()
        .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
        .collect::<BTreeMap<_, _>>();
    let (digest, _, partial) = issuer
        .build(
            10,
            20,
            3,
            RistrettoPoint::mul_base(&Scalar::from(11u64)),
            RistrettoPoint::mul_base(&Scalar::from(22u64)),
            1_500,
            [8u8; 32],
            9,
            &mut OsRng,
        )
        .unwrap();
    let instruction = partial.sealed(sign(&digest, &shares, &public));
    let venue = Venue::new(key, &bounds, public).require_threshold_ranges();
    assert_eq!(
        venue.verify(&instruction, 1_000),
        Err("this venue requires range proofs produced by the MPC quorum")
    );
}
