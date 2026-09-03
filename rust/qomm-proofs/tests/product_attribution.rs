//! Product-attribution proof contract tests.

use std::collections::BTreeMap;

use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_proofs::threshold_gadgets::{
    audit_recorded_product_partials, joint_prove_product_from_contributions,
    ProductNodeContribution, Shared,
};
use qomm_proofs::threshold_range::deal_bits;
use qomm_proofs::threshold_sigma::{share_commitment, PartyId};
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::verify_product;
use rand_core::OsRng;

const PARTIES: [PartyId; 7] = [1, 2, 3, 4, 5, 6, 7];
const QUORUM: [PartyId; 3] = [1, 2, 3];
const T: usize = 2;

fn transcript() -> Transcript {
    let mut transcript = Transcript::new(b"qomm:test:product-attribution:v1");
    transcript.append_message(b"ctx", b"ctx");
    transcript
}

fn shared_bit(key: &Pedersen, bit: u64) -> (Shared, BTreeMap<PartyId, Scalar>) {
    let dealt = deal_bits(
        key,
        bit,
        &Scalar::random(&mut OsRng),
        1,
        &PARTIES,
        T,
        &mut OsRng,
    )
    .unwrap();
    let bit = dealt.bits.into_iter().next().unwrap();
    (
        Shared {
            commitment: bit.commitment,
            value: bit.bit,
            blinding: bit.blinding,
            coefficient_commitments: bit.coefficient_commitments,
        },
        bit.cross,
    )
}

fn node_contributions(
    shared: &Shared,
    cross: &BTreeMap<PartyId, Scalar>,
) -> Vec<ProductNodeContribution> {
    QUORUM
        .iter()
        .map(|party| {
            ProductNodeContribution::new(
                shared.node_share(*party).unwrap(),
                *cross.get(party).unwrap(),
            )
        })
        .collect()
}

#[test]
fn an_honest_quorum_names_nobody() {
    let key = Pedersen::new(b"qomm:quote:v1");
    for bit in [0, 1] {
        let (shared, cross) = shared_bit(&key, bit);
        let contributions = node_contributions(&shared, &cross);
        let (proof, record) = joint_prove_product_from_contributions(
            &key,
            &shared.commitment,
            &shared.commitment,
            &contributions,
            &QUORUM,
            T,
            &mut transcript(),
            &mut OsRng,
        )
        .unwrap();
        assert!(verify_product(
            &key,
            &mut transcript(),
            &shared.commitment,
            &shared.commitment,
            &shared.commitment,
            &proof
        ));
        assert_eq!(
            audit_recorded_product_partials(&key, &record),
            Vec::<PartyId>::new(),
            "bit {bit}"
        );
    }
}

#[test]
fn the_node_that_answered_on_a_different_share_is_named() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let (shared, cross) = shared_bit(&key, 1);
    let contributions = node_contributions(&shared, &cross);
    let (_, mut record) = joint_prove_product_from_contributions(
        &key,
        &shared.commitment,
        &shared.commitment,
        &contributions,
        &QUORUM,
        T,
        &mut transcript(),
        &mut OsRng,
    )
    .unwrap();
    record.answers.get_mut(&2).unwrap().0 += Scalar::ONE;
    assert_eq!(audit_recorded_product_partials(&key, &record), vec![2]);
}

#[test]
fn a_bad_partial_breaks_the_proof_as_well_as_being_named() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let (shared, cross) = shared_bit(&key, 1);
    let contributions = node_contributions(&shared, &cross);
    let (_, mut record) = joint_prove_product_from_contributions(
        &key,
        &shared.commitment,
        &shared.commitment,
        &contributions,
        &QUORUM,
        T,
        &mut transcript(),
        &mut OsRng,
    )
    .unwrap();
    record.answers.get_mut(&3).unwrap().0 += Scalar::from(5u64);
    let assembled = record.assemble().unwrap();
    assert!(
        !verify_product(
            &key,
            &mut transcript(),
            &shared.commitment,
            &shared.commitment,
            &shared.commitment,
            &assembled,
        ),
        "a proof built on a bad partial verified"
    );
    let culprits = audit_recorded_product_partials(&key, &record);
    println!("tampered_contribution_attributed_to={culprits:?}");
    assert_eq!(culprits, vec![3]);
    assert_eq!(audit_recorded_product_partials(&key, &record), vec![3]);
}

#[test]
fn regenerating_per_node_audit_points_cannot_hide_a_bad_partial() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let (shared, cross) = shared_bit(&key, 1);
    let contributions = node_contributions(&shared, &cross);
    let (_, mut record) = joint_prove_product_from_contributions(
        &key,
        &shared.commitment,
        &shared.commitment,
        &contributions,
        &QUORUM,
        T,
        &mut transcript(),
        &mut OsRng,
    )
    .unwrap();
    record.answers.get_mut(&2).unwrap().0 += Scalar::from(9u64);

    // The old record could solve both audit equations for replacement points
    // after seeing the bad answer.  These forged points satisfy those equations
    // exactly, but the fixed audit never consults them.
    let (z_b, z_rb, z_s) = record.answers[&2];
    let inverse = record.challenge.invert();
    let forged_share = (key.commit(&z_b, &z_rb) - record.factor_parts[&2]) * inverse;
    let product_left = record.c_a * z_b + key.h * z_s;
    let forged_cross = (product_left - record.product_parts[&2]) * inverse;
    assert_eq!(
        key.commit(&z_b, &z_rb).compress(),
        (record.factor_parts[&2] + forged_share * record.challenge).compress()
    );
    assert_eq!(
        product_left.compress(),
        (record.product_parts[&2] + forged_cross * record.challenge).compress()
    );

    let published = share_commitment(&record.share_coefficient_commitments, 2).unwrap();
    assert_ne!(published.compress(), forged_share.compress());
    assert_eq!(audit_recorded_product_partials(&key, &record), vec![2]);
    println!("regenerated_audit_record_passes=false culprit=2");
}
