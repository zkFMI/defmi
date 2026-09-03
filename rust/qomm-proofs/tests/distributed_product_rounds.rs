use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_proofs::threshold_gadgets::{
    answer_product_challenge, assemble_product_from_rounds, make_product_challenge,
    prepare_product_round1, product_statement_from_evaluations, LocalProductShares,
};
use qomm_proofs::threshold_sigma::deal;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::verify_product;
use rand_core::OsRng;

const CONTEXT: &[u8] = b"qomm:test:distributed-product:v1";

#[test]
fn product_proof_uses_only_public_rounds_and_node_local_shares() {
    let key = Pedersen::new(b"qomm:test:distributed-product:key");
    let parties = [1usize, 2, 3, 4, 5, 6, 7];
    let quorum = [1usize, 4, 7];
    let threshold = 2;
    let amount = Scalar::from(11u64);
    let price = Scalar::from(7u64);
    let amount_blinding = Scalar::random(&mut OsRng);
    let price_blinding = Scalar::random(&mut OsRng);
    let cash_blinding = Scalar::random(&mut OsRng);
    let amount_commitment = key.commit(&amount, &amount_blinding);
    let price_shares = deal(
        &key,
        &price,
        &price_blinding,
        &parties,
        threshold,
        &mut OsRng,
    )
    .unwrap();
    let cash_commitment = key.commit(&(amount * price), &cash_blinding);
    let cross_shares = deal(
        &key,
        &(cash_blinding - amount_blinding * price),
        &Scalar::ZERO,
        &parties,
        threshold,
        &mut OsRng,
    )
    .unwrap();

    let locals = parties
        .iter()
        .map(|party| {
            LocalProductShares::new(
                *party,
                price_shares.value_shares[party],
                price_shares.blinding_shares[party],
                cross_shares.value_shares[party],
                threshold,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let evaluations = locals
        .iter()
        .map(|local| local.evaluations(&key, &amount_commitment))
        .collect::<Vec<_>>();
    let statement = product_statement_from_evaluations(
        &amount_commitment,
        &price_shares.commitment,
        &cash_commitment,
        &evaluations,
        threshold,
    )
    .unwrap();
    let contributions = locals
        .into_iter()
        .map(|local| (local.party(), local.bind(&key, &statement).unwrap()))
        .collect::<std::collections::BTreeMap<_, _>>();

    let mut seals = Vec::new();
    let mut secrets = Vec::new();
    let mut first = Vec::new();
    for party in quorum {
        let (seal, secret, message) = prepare_product_round1(
            &key,
            &contributions[&party],
            &amount_commitment,
            CONTEXT,
            &mut OsRng,
        );
        seals.push(seal);
        secrets.push((party, secret));
        first.push(message);
    }
    let challenge = make_product_challenge(&statement, &first, &seals, &quorum, CONTEXT).unwrap();
    let responses = secrets
        .into_iter()
        .map(|(party, secret)| {
            answer_product_challenge(&contributions[&party], secret, &challenge).unwrap()
        })
        .collect::<Vec<_>>();
    let proof = assemble_product_from_rounds(
        &key, &statement, &first, &seals, &responses, &quorum, CONTEXT,
    )
    .unwrap();
    assert!(verify_product(
        &key,
        &mut Transcript::new(CONTEXT),
        &amount_commitment,
        &price_shares.commitment,
        &cash_commitment,
        &proof,
    ));

    let mut tampered = responses;
    tampered[0].relation_answer += Scalar::ONE;
    assert!(assemble_product_from_rounds(
        &key, &statement, &first, &seals, &tampered, &quorum, CONTEXT,
    )
    .unwrap_err()
    .contains("bad product relation"));
}
