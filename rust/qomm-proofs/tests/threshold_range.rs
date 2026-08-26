//! Rust mirror of `tests/test_threshold_range.py`.

use std::collections::BTreeMap;

use curve25519_dalek::scalar::Scalar;
use qomm_proofs::threshold_range::{
    deal_bits, joint_prove_range_from_contributions, verify_threshold_range, BitShares,
    RangeAssemblyTranscript, ThresholdRangeProof, ValueShares,
};
use qomm_proofs::threshold_sigma::PartyId;
use qomm_zk::bitrange::{prove_range, verify_range};
use qomm_zk::pedersen::Pedersen;
use qomm_zk::shamir;
use rand_core::{CryptoRng, OsRng, RngCore};

const PARTIES: [PartyId; 7] = [1, 2, 3, 4, 5, 6, 7];
const T: usize = 2;
const WIDTH: usize = 16;

fn prove_range_from_nodes<R: RngCore + CryptoRng>(
    key: &Pedersen,
    shares: &ValueShares,
    quorum: &[PartyId],
    context: &[u8],
    rng: &mut R,
) -> Result<(ThresholdRangeProof, RangeAssemblyTranscript), String> {
    let contributions = quorum
        .iter()
        .map(|party| {
            shares
                .node_contribution(*party)
                .ok_or_else(|| format!("missing range contribution from party {party}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    joint_prove_range_from_contributions(key, &contributions, quorum, context, rng)
}

fn reconstruct(shares: &BTreeMap<PartyId, Scalar>, parties: &[PartyId]) -> Scalar {
    let points: Vec<_> = parties
        .iter()
        .map(|party| Scalar::from(*party as u64))
        .collect();
    let values: Vec<_> = parties.iter().map(|party| shares[party]).collect();
    shamir::reconstruct(&points, &values)
}

fn constant_shares(value: Scalar) -> BTreeMap<PartyId, Scalar> {
    PARTIES.into_iter().map(|party| (party, value)).collect()
}

#[test]
fn a_committed_two_is_not_accepted_as_a_bit() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let r = Scalar::random(&mut OsRng);
    let two = Scalar::from(2u64);
    let dishonest = BitShares {
        commitment: key.commit(&two, &r),
        bit: constant_shares(two),
        blinding: constant_shares(r),
        cross: constant_shares(-r),
        coefficient_commitments: vec![key.commit(&two, &r)],
    };
    let shares = ValueShares {
        commitment: key.commit(&two, &r),
        value: constant_shares(two),
        blinding: constant_shares(r),
        bits: vec![dishonest],
        threshold: 0,
    };
    let error = prove_range_from_nodes(&key, &shares, &[1, 2, 3], b"ctx", &mut OsRng)
        .expect_err("a committed two must be rejected before proof assembly");
    assert_eq!(
        error,
        "product relation VSS constant does not match the product"
    );
}

#[test]
fn a_value_that_does_not_fit_the_width_is_refused() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let error = deal_bits(
        &key,
        1u64 << WIDTH,
        &Scalar::random(&mut OsRng),
        WIDTH,
        &PARTIES,
        T,
        &mut OsRng,
    )
    .expect_err("the value is one past the declared range");
    assert_eq!(error, "value 65536 outside [0, 2^16)");
}

#[test]
fn a_proof_does_not_verify_against_another_commitment() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let a = deal_bits(
        &key,
        1234,
        &Scalar::random(&mut OsRng),
        WIDTH,
        &PARTIES,
        T,
        &mut OsRng,
    )
    .unwrap();
    let b = deal_bits(
        &key,
        1234,
        &Scalar::random(&mut OsRng),
        WIDTH,
        &PARTIES,
        T,
        &mut OsRng,
    )
    .unwrap();
    let (proof, _) = prove_range_from_nodes(&key, &a, &[1, 2, 3], b"ctx", &mut OsRng).unwrap();
    assert!(verify_threshold_range(&key, &a.commitment, &proof, b"ctx"));
    assert!(
        !verify_threshold_range(&key, &b.commitment, &proof, b"ctx"),
        "the same value under a different blinding accepted the other's proof"
    );
}

#[test]
fn the_context_is_bound() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let shares = deal_bits(
        &key,
        999,
        &Scalar::random(&mut OsRng),
        WIDTH,
        &PARTIES,
        T,
        &mut OsRng,
    )
    .unwrap();
    let (proof, _) =
        prove_range_from_nodes(&key, &shares, &[1, 2, 3], b"slot-7", &mut OsRng).unwrap();
    assert!(!verify_threshold_range(
        &key,
        &shares.commitment,
        &proof,
        b"slot-8"
    ));
}

#[test]
fn a_node_that_answers_on_the_wrong_share_breaks_the_proof() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let mut shares = deal_bits(
        &key,
        4321,
        &Scalar::random(&mut OsRng),
        WIDTH,
        &PARTIES,
        T,
        &mut OsRng,
    )
    .unwrap();
    *shares.bits[0].bit.get_mut(&2).unwrap() += Scalar::ONE;
    let error = prove_range_from_nodes(&key, &shares, &[1, 2, 3], b"ctx", &mut OsRng)
        .expect_err("the share no longer opens against the published ladder");
    assert_eq!(
        error,
        "factor share from party 2 does not match the published VSS coefficient ladder"
    );
}

#[test]
fn a_quorum_assembles_a_proof_an_ordinary_verifier_accepts() {
    let key = Pedersen::new(b"qomm:quote:v1");
    for value in [0, 1, 2, 255, 1023, (1u64 << WIDTH) - 1] {
        let shares = deal_bits(
            &key,
            value,
            &Scalar::random(&mut OsRng),
            WIDTH,
            &PARTIES,
            T,
            &mut OsRng,
        )
        .unwrap();
        let (proof, transcript) =
            prove_range_from_nodes(&key, &shares, &[1, 2, 3], b"ctx", &mut OsRng).unwrap();
        assert!(
            verify_threshold_range(&key, &shares.commitment, &proof, b"ctx"),
            "value {value}"
        );
        assert_eq!(transcript.width, WIDTH);
    }
}

#[test]
fn any_quorum_of_t_plus_one_works_and_fewer_does_not() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let shares = deal_bits(
        &key,
        777,
        &Scalar::random(&mut OsRng),
        WIDTH,
        &PARTIES,
        T,
        &mut OsRng,
    )
    .unwrap();
    for quorum in [
        vec![1, 2, 3],
        vec![5, 6, 7],
        vec![2, 4, 6],
        PARTIES.to_vec(),
    ] {
        let (proof, _) =
            prove_range_from_nodes(&key, &shares, &quorum, b"ctx", &mut OsRng).unwrap();
        assert!(
            verify_threshold_range(&key, &shares.commitment, &proof, b"ctx"),
            "quorum {quorum:?}"
        );
    }
    let error = prove_range_from_nodes(&key, &shares, &[1, 2], b"ctx", &mut OsRng)
        .expect_err("t contributions must not assemble a degree-t proof");
    assert_eq!(error, "2 public evaluations cannot define degree 2");
}

#[test]
fn no_node_holds_the_value_or_any_bit() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let value = 0b1011010110110101u64 & ((1u64 << WIDTH) - 1);
    let shares = deal_bits(
        &key,
        value,
        &Scalar::random(&mut OsRng),
        WIDTH,
        &PARTIES,
        T,
        &mut OsRng,
    )
    .unwrap();
    for party in PARTIES {
        let view = shares.node_view(party).expect("every party has a view");
        assert_ne!(
            view.value_share,
            Scalar::from(value),
            "party {party} holds the value"
        );
        for (index, bit) in view.bits.iter().enumerate() {
            let clear = Scalar::from((value >> index) & 1);
            assert!(
                bit.bit_share != clear || bit.bit_share == Scalar::ZERO,
                "party {party} holds bit {index} in the clear"
            );
        }
    }
    assert_ne!(reconstruct(&shares.value, &[1, 2]), Scalar::from(value));
    assert_eq!(reconstruct(&shares.value, &[1, 2, 3]), Scalar::from(value));
    for (index, bit) in shares.bits.iter().enumerate() {
        assert_eq!(
            reconstruct(&bit.bit, &[4, 5, 6]),
            Scalar::from((value >> index) & 1)
        );
    }
}

#[test]
fn the_square_proof_is_the_same_statement_as_the_ordinary_one() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let value = 40_000u64 % (1u64 << WIDTH);
    let blinding = Scalar::random(&mut OsRng);
    let shares = deal_bits(&key, value, &blinding, WIDTH, &PARTIES, T, &mut OsRng).unwrap();
    let (joint, _) = prove_range_from_nodes(&key, &shares, &[1, 2, 3], b"ctx", &mut OsRng).unwrap();
    let local = prove_range(
        &key,
        &shares.commitment,
        value,
        &blinding,
        WIDTH,
        b"ctx",
        &mut OsRng,
    )
    .unwrap();
    assert!(verify_threshold_range(
        &key,
        &shares.commitment,
        &joint,
        b"ctx"
    ));
    assert!(verify_range(&key, &shares.commitment, &local, b"ctx"));
    assert_eq!(joint.bits, local.bits);
    assert_eq!(joint.bit_commitments.len(), local.bit_commitments.len());
}
