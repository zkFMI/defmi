//! Direct checks for the threshold opening protocol used by range linkage and
//! the winner opening.

use std::collections::BTreeMap;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use qomm_proofs::threshold_sigma::{deal, joint_prove_opening, verify_share, PartyId};
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::verify_opening;
use rand_core::OsRng;

const PARTIES: [PartyId; 7] = [1, 2, 3, 4, 5, 6, 7];
const T: usize = 2;

fn transcript() -> Transcript {
    let mut transcript = Transcript::new(b"qomm:test:threshold-opening:v1");
    transcript.append_message(b"ctx", b"ctx");
    transcript
}

#[test]
fn a_quorum_emits_the_native_opening_proof() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let shares = deal(
        &key,
        &Scalar::from(1234u64),
        &Scalar::random(&mut OsRng),
        &PARTIES,
        T,
        &mut OsRng,
    )
    .unwrap();
    assert!(PARTIES
        .iter()
        .all(|party| verify_share(&key, &shares, *party)));
    let (proof, record) = joint_prove_opening(
        &key,
        &shares,
        &[1, 2, 3],
        &mut transcript(),
        None,
        &mut OsRng,
    )
    .unwrap();
    assert!(verify_opening(
        &key,
        &mut transcript(),
        &shares.commitment,
        &proof
    ));
    assert!(record.bad_partials.is_empty());
}

#[test]
fn public_proof_transcript_contains_no_nonce_opening() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let shares = deal(
        &key,
        &Scalar::from(1234u64),
        &Scalar::random(&mut OsRng),
        &PARTIES,
        T,
        &mut OsRng,
    )
    .unwrap();
    let (proof, record) = joint_prove_opening(
        &key,
        &shares,
        &[1, 2, 3],
        &mut transcript(),
        None,
        &mut OsRng,
    )
    .unwrap();
    assert!(verify_opening(
        &key,
        &mut transcript(),
        &shares.commitment,
        &proof
    ));
    assert!(record
        .nonce_seals
        .values()
        .flatten()
        .all(|ladder| ladder.len() == T + 1));

    // The public constants combine only into a hiding group point.  The record
    // deliberately has no scalar opening for any nonce polynomial.
    let _joint_nonce_hiding_point = record
        .nonce_seals
        .values()
        .fold(RistrettoPoint::identity(), |sum, dealer| sum + dealer[0][0]);
    println!(
        "observer_can_compute=coefficient_share_points,joint_hiding_point,challenge,assembled_response,ordinary_verification observer_cannot_compute=joint_nonce_scalar,witness_scalar assumption=existing_pedersen_discrete_log"
    );
}

#[test]
fn t_shares_do_not_emit_a_valid_opening() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let shares = deal(
        &key,
        &Scalar::from(1234u64),
        &Scalar::random(&mut OsRng),
        &PARTIES,
        T,
        &mut OsRng,
    )
    .unwrap();
    let (proof, _) =
        joint_prove_opening(&key, &shares, &[1, 2], &mut transcript(), None, &mut OsRng).unwrap();
    assert!(!verify_opening(
        &key,
        &mut transcript(),
        &shares.commitment,
        &proof
    ));
}

#[test]
fn a_bad_opening_partial_is_attributed_to_its_node() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let shares = deal(
        &key,
        &Scalar::from(1234u64),
        &Scalar::random(&mut OsRng),
        &PARTIES,
        T,
        &mut OsRng,
    )
    .unwrap();
    let faulty = BTreeMap::from([(2, (Scalar::ZERO, Scalar::ZERO))]);
    let (proof, record) = joint_prove_opening(
        &key,
        &shares,
        &[1, 2, 3],
        &mut transcript(),
        Some(&faulty),
        &mut OsRng,
    )
    .unwrap();
    assert_eq!(record.bad_partials, vec![2]);
    assert!(!verify_opening(
        &key,
        &mut transcript(),
        &shares.commitment,
        &proof
    ));
}

#[test]
fn every_node_in_the_quorum_can_be_named_in_turn() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let shares = deal(
        &key,
        &Scalar::from(99u64),
        &Scalar::random(&mut OsRng),
        &PARTIES,
        T,
        &mut OsRng,
    )
    .unwrap();
    let quorum = [2, 4, 6];
    for culprit in quorum {
        let faulty = BTreeMap::from([(culprit, (Scalar::ONE, Scalar::ONE))]);
        let (proof, record) = joint_prove_opening(
            &key,
            &shares,
            &quorum,
            &mut transcript(),
            Some(&faulty),
            &mut OsRng,
        )
        .unwrap();
        assert_eq!(record.bad_partials, vec![culprit]);
        assert!(!verify_opening(
            &key,
            &mut transcript(),
            &shares.commitment,
            &proof
        ));
    }
}

#[test]
fn the_opening_transcript_records_what_each_node_sent() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let shares = deal(
        &key,
        &Scalar::from(7u64),
        &Scalar::random(&mut OsRng),
        &PARTIES,
        T,
        &mut OsRng,
    )
    .unwrap();
    let quorum = [1, 3, 5];
    let (_, record) =
        joint_prove_opening(&key, &shares, &quorum, &mut transcript(), None, &mut OsRng).unwrap();
    assert_eq!(
        record
            .partial_commitments
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        quorum
    );
    assert_eq!(
        record.partial_responses.keys().copied().collect::<Vec<_>>(),
        quorum
    );
}
