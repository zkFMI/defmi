//! Seven-node issuance path from party-local MPC shares to a production zkPI.
//!
//! This test deliberately keeps the coordinator API on public group elements,
//! seals, challenges, and masked responses. No coordinator call accepts an
//! amount, price, Pedersen blinding, or raw Shamir share.

use std::collections::BTreeMap;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use qomm_proofs::threshold_range::{deal_bits, LocalRangeShares, ValueShares};
use qomm_proofs::threshold_sigma::PartyId;
use qomm_transport::zkpi_issuer::{
    assemble_ranges, build_partial_instruction, make_challenge,
    relation_statements_from_evaluations, statements_from_evaluations, MpcZkpiNode,
};
use qomm_transport::zkpi_wire::{decode, encode, Envelope, Message};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::{deal_quorum, frost, Bounds, Venue};
use rand::rngs::OsRng;

const PARTIES: [PartyId; 7] = [1, 2, 3, 4, 5, 6, 7];
const QUORUM: [PartyId; 3] = [1, 4, 7];
const THRESHOLD: usize = 2;
const JOB: [u8; 32] = [91u8; 32];

fn network(message: Message) -> Message {
    let bytes = encode(&Envelope {
        job_id: JOB,
        message,
    })
    .unwrap();
    let decoded = decode(&bytes).unwrap();
    assert_eq!(decoded.job_id, JOB);
    assert_eq!(encode(&decoded).unwrap(), bytes);
    decoded.message
}

fn local(value: &ValueShares, party: PartyId) -> LocalRangeShares {
    let view = value.node_view(party).unwrap();
    LocalRangeShares::new(
        party,
        view.value_share,
        view.blinding_share,
        view.bits
            .into_iter()
            .map(|bit| (bit.bit_share, bit.blinding_share, bit.cross_share))
            .collect(),
        THRESHOLD,
    )
    .unwrap()
}

fn frost_sign(
    message: &[u8],
    shares: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: &frost::keys::PublicKeyPackage,
) -> frost::Signature {
    let selected = shares.keys().take(3).copied().collect::<Vec<_>>();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &selected {
        let (nonce, commitment) = frost::round1::commit(shares[id].signing_share(), &mut OsRng);
        nonces.insert(*id, nonce);
        commitments.insert(*id, commitment);
    }
    let package = frost::SigningPackage::new(commitments, message);
    let signature_shares = selected
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

#[test]
fn seven_nodes_issue_a_production_instruction_without_reconstructing_price() {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let bounds = Bounds {
        amount_bits: 16,
        price_bits: 32,
        max_horizon: 3_600,
    };
    let amount = deal_bits(
        &key,
        1_250,
        &Scalar::random(&mut OsRng),
        bounds.amount_bits,
        &PARTIES,
        THRESHOLD,
        &mut OsRng,
    )
    .unwrap();
    let price = deal_bits(
        &key,
        101_375,
        &Scalar::random(&mut OsRng),
        bounds.price_bits,
        &PARTIES,
        THRESHOLD,
        &mut OsRng,
    )
    .unwrap();

    let nodes = PARTIES
        .iter()
        .map(|party| {
            MpcZkpiNode::from_local_ranges(local(&amount, *party), local(&price, *party)).unwrap()
        })
        .collect::<Vec<_>>();
    let evaluations = nodes
        .iter()
        .map(
            |node| match network(Message::Evaluations(node.evaluations(&key))) {
                Message::Evaluations(value) => value,
                _ => unreachable!(),
            },
        )
        .collect::<Vec<_>>();
    let statements = statements_from_evaluations(&evaluations, THRESHOLD).unwrap();
    assert_eq!(
        statements.amount.commitment.compress(),
        amount.commitment.compress()
    );
    assert_eq!(
        statements.price.commitment.compress(),
        price.commitment.compress()
    );

    let bound = nodes
        .into_iter()
        .map(|node| node.bind(&key, &statements).unwrap())
        .collect::<Vec<_>>();
    let relation_evaluations = bound
        .iter()
        .map(|node| {
            match network(Message::RelationEvaluations(
                node.relation_evaluations(&key),
            )) {
                Message::RelationEvaluations(value) => value,
                _ => unreachable!(),
            }
        })
        .collect::<Vec<_>>();
    let relations =
        relation_statements_from_evaluations(&statements, &relation_evaluations).unwrap();

    let mut seals = Vec::new();
    let mut secrets = Vec::new();
    let mut round1 = Vec::new();
    for node in bound.iter().filter(|node| QUORUM.contains(&node.party())) {
        let (seal, secret, message) = node.prepare_round1(&key, &mut OsRng);
        seals.push(match network(Message::Round1Seal(seal)) {
            Message::Round1Seal(value) => value,
            _ => unreachable!(),
        });
        secrets.push(secret);
        round1.push(match network(Message::Round1(message)) {
            Message::Round1(value) => value,
            _ => unreachable!(),
        });
    }
    let challenge = make_challenge(&statements, &round1, &seals, &QUORUM).unwrap();
    let challenge = match network(Message::Challenge(challenge)) {
        Message::Challenge(value) => value,
        _ => unreachable!(),
    };
    let responses = bound
        .iter()
        .filter(|node| QUORUM.contains(&node.party()))
        .zip(secrets)
        .map(|(node, secret)| {
            let response = node.answer(secret, &challenge).unwrap();
            match network(Message::Round2(response)) {
                Message::Round2(value) => value,
                _ => unreachable!(),
            }
        })
        .collect::<Vec<_>>();
    let proofs = assemble_ranges(
        &key,
        &statements,
        &relations,
        &round1,
        &seals,
        &responses,
        &QUORUM,
    )
    .unwrap();

    let partial = build_partial_instruction(
        &key,
        &bounds,
        &statements,
        proofs,
        key.commit(&Scalar::from(9u64), &Scalar::random(&mut OsRng)),
        RistrettoPoint::mul_base(&Scalar::from(11u64)),
        RistrettoPoint::mul_base(&Scalar::from(22u64)),
        2_000,
        [31u8; 32],
        [47u8; 32],
    )
    .unwrap();
    let message = partial.digest().to_vec();
    let (dealt, public) = deal_quorum(7, 3, &mut OsRng).unwrap();
    let signing_shares = dealt
        .into_iter()
        .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
        .collect::<BTreeMap<_, _>>();
    let instruction = partial.sealed(frost_sign(&message, &signing_shares, &public));

    let venue = Venue::new(key, &bounds, public).require_threshold_ranges();
    assert_eq!(venue.verify(&instruction, 1_000), Ok(()));
}

#[test]
fn the_public_wire_rejects_cross_node_amount_and_price_messages() {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let amount = deal_bits(
        &key,
        7,
        &Scalar::random(&mut OsRng),
        8,
        &PARTIES,
        THRESHOLD,
        &mut OsRng,
    )
    .unwrap();
    let price = deal_bits(
        &key,
        9,
        &Scalar::random(&mut OsRng),
        8,
        &PARTIES,
        THRESHOLD,
        &mut OsRng,
    )
    .unwrap();
    let first = MpcZkpiNode::from_local_ranges(local(&amount, 1), local(&price, 1)).unwrap();
    let second = MpcZkpiNode::from_local_ranges(local(&amount, 2), local(&price, 2)).unwrap();
    let mut crossed = first.evaluations(&key);
    crossed.price = second.evaluations(&key).price;
    assert_eq!(
        encode(&Envelope {
            job_id: JOB,
            message: Message::Evaluations(crossed),
        })
        .unwrap_err(),
        qomm_transport::zkpi_wire::Error::PartyMismatch
    );
}
