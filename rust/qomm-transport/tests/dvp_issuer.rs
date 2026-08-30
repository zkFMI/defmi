//! Seven-node DvP proof path with every public round crossing the canonical
//! wire.  First-round secrets and scalar MPC shares remain in their owner.

use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_proofs::threshold_gadgets::LocalProductShares;
use qomm_proofs::threshold_range::{
    deal_bits, verify_threshold_range, LocalRangeShares, NodeValueView,
};
use qomm_proofs::threshold_sigma::deal;
use qomm_transport::dvp_issuer::{
    assemble_proofs, make_challenge, relation_statements_from_evaluations,
    statements_from_evaluations, MpcDvpNode, DVP_CASH_REMAINDER_CONTEXT, DVP_PRODUCT_CONTEXT,
    DVP_SECURITIES_REMAINDER_CONTEXT,
};
use qomm_transport::dvp_wire::{decode, encode, Envelope, Error, Message};
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::verify_product;
use rand_core::OsRng;
use std::collections::BTreeMap;

fn local_range(view: NodeValueView, threshold: usize) -> LocalRangeShares {
    LocalRangeShares::new(
        view.party,
        view.value_share,
        view.blinding_share,
        view.bits
            .into_iter()
            .map(|bit| (bit.bit_share, bit.blinding_share, bit.cross_share))
            .collect(),
        threshold,
    )
    .unwrap()
}

fn cross<T>(job_id: [u8; 32], message: Message, take: impl FnOnce(Message) -> T) -> T {
    let raw = encode(&Envelope { job_id, message }).unwrap();
    let decoded = decode(&raw).unwrap();
    assert_eq!(decoded.job_id, job_id);
    take(decoded.message)
}

#[test]
fn seven_nodes_assemble_dvp_proofs_over_public_bounded_messages() {
    let key = Pedersen::new(b"qomm:test:dvp-wire:key");
    let parties = [1usize, 2, 3, 4, 5, 6, 7];
    let quorum = [1usize, 4, 7];
    let threshold = 2;
    let bits = 16;
    let quantity = Scalar::from(10u64);
    let price = Scalar::from(4u64);
    let quantity_blinding = Scalar::random(&mut OsRng);
    let price_blinding = Scalar::random(&mut OsRng);
    let cash_blinding = Scalar::random(&mut OsRng);
    let quantity_commitment = key.commit(&quantity, &quantity_blinding);
    let price_shares = deal(
        &key,
        &price,
        &price_blinding,
        &parties,
        threshold,
        &mut OsRng,
    )
    .unwrap();
    let cash_commitment = key.commit(&(quantity * price), &cash_blinding);
    let cross_shares = deal(
        &key,
        &(cash_blinding - quantity_blinding * price),
        &Scalar::ZERO,
        &parties,
        threshold,
        &mut OsRng,
    )
    .unwrap();
    let securities_blinding = Scalar::random(&mut OsRng);
    let cash_remainder_blinding = Scalar::random(&mut OsRng);
    let securities = deal_bits(
        &key,
        3,
        &securities_blinding,
        bits,
        &parties,
        threshold,
        &mut OsRng,
    )
    .unwrap();
    let cash = deal_bits(
        &key,
        9,
        &cash_remainder_blinding,
        bits,
        &parties,
        threshold,
        &mut OsRng,
    )
    .unwrap();
    let nodes = parties
        .iter()
        .map(|party| {
            MpcDvpNode::new(
                LocalProductShares::new(
                    *party,
                    price_shares.value_shares[party],
                    price_shares.blinding_shares[party],
                    cross_shares.value_shares[party],
                    threshold,
                )
                .unwrap(),
                local_range(securities.node_view(*party).unwrap(), threshold),
                local_range(cash.node_view(*party).unwrap(), threshold),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let job_id = [91u8; 32];
    let evaluations = nodes
        .iter()
        .map(|node| {
            cross(
                job_id,
                Message::Evaluations(node.evaluations(&key, &quantity_commitment)),
                |message| match message {
                    Message::Evaluations(value) => value,
                    _ => panic!("wire changed message type"),
                },
            )
        })
        .collect::<Vec<_>>();
    let statements = statements_from_evaluations(
        &quantity_commitment,
        &price_shares.commitment,
        &cash_commitment,
        &securities.commitment,
        &cash.commitment,
        &evaluations,
        threshold,
    )
    .unwrap();
    let bound = nodes
        .into_iter()
        .map(|node| (node.party(), node.bind(&key, &statements).unwrap()))
        .collect::<BTreeMap<_, _>>();
    let relations = bound
        .values()
        .map(|node| {
            cross(
                job_id,
                Message::RelationEvaluations(node.relation_evaluations(&key)),
                |message| match message {
                    Message::RelationEvaluations(value) => value,
                    _ => panic!("wire changed message type"),
                },
            )
        })
        .collect::<Vec<_>>();
    let relation_statements =
        relation_statements_from_evaluations(&statements, &relations).unwrap();

    let mut seals = Vec::new();
    let mut secrets = Vec::new();
    let mut first = Vec::new();
    for party in quorum {
        let (seal, secret, round) =
            bound[&party].prepare_round1(&key, &quantity_commitment, &mut OsRng);
        seals.push(cross(
            job_id,
            Message::Round1Seal(seal),
            |message| match message {
                Message::Round1Seal(value) => value,
                _ => panic!("wire changed message type"),
            },
        ));
        first.push(cross(
            job_id,
            Message::Round1(round),
            |message| match message {
                Message::Round1(value) => value,
                _ => panic!("wire changed message type"),
            },
        ));
        secrets.push((party, secret));
    }
    let challenge = make_challenge(&statements, &first, &seals, &quorum).unwrap();
    let challenge = cross(
        job_id,
        Message::Challenge(challenge),
        |message| match message {
            Message::Challenge(value) => value,
            _ => panic!("wire changed message type"),
        },
    );
    let responses = secrets
        .into_iter()
        .map(|(party, secret)| {
            let response = bound[&party].answer(secret, &challenge).unwrap();
            cross(job_id, Message::Round2(response), |message| match message {
                Message::Round2(value) => value,
                _ => panic!("wire changed message type"),
            })
        })
        .collect::<Vec<_>>();
    let proofs = assemble_proofs(
        &key,
        &statements,
        &relation_statements,
        &first,
        &seals,
        &responses,
        &quorum,
    )
    .unwrap();
    assert!(verify_product(
        &key,
        &mut Transcript::new(DVP_PRODUCT_CONTEXT),
        &quantity_commitment,
        &price_shares.commitment,
        &cash_commitment,
        &proofs.product,
    ));
    assert!(verify_threshold_range(
        &key,
        &securities.commitment,
        &proofs.securities_remainder,
        DVP_SECURITIES_REMAINDER_CONTEXT,
    ));
    assert!(verify_threshold_range(
        &key,
        &cash.commitment,
        &proofs.cash_remainder,
        DVP_CASH_REMAINDER_CONTEXT,
    ));

    let mut encoded = encode(&Envelope {
        job_id,
        message: Message::Round2(responses[0].clone()),
    })
    .unwrap();
    encoded.push(0);
    assert!(matches!(decode(&encoded), Err(Error::Trailing(1))));
}
