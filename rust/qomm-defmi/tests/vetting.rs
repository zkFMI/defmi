//! Vetting: the roll says how big the crowd is, and nothing about who is in it.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::scalar::Scalar;
use qomm_defmi::vetting::{
    check_membership, cohort_of, handle_of, prove_membership, Operator, Roll,
};
use qomm_zk::pedersen::Pedersen;
use rand::rngs::OsRng;

const JP_BROKER: &[u8] = b"JP/broker/tier3";
const UK_BANK: &[u8] = b"UK/bank/tier2";

fn world(crowd: usize) -> (Pedersen, Operator, Roll) {
    let key = Pedersen::new(b"qomm:defmi:vetting");
    (key.clone(), Operator::new(key), Roll::new(crowd).unwrap())
}

#[test]
fn a_vetted_handle_proves_it_without_saying_which_entry_it_is() {
    let (key, operator, mut roll) = world(16);
    let secret = Scalar::random(&mut OsRng);
    let seal = operator.vouch(&mut roll, JP_BROKER, &secret, &mut OsRng);

    let membership = prove_membership(&key, &roll, &seal, &secret, b"round-1", &mut OsRng).unwrap();
    check_membership(&key, &roll, &handle_of(&secret), &membership, b"round-1").unwrap();

    // What the verifier learns is the group, which is the crowd being claimed.
    // The index inside it is in the seal and never leaves the holder.
    assert_eq!(membership.group, 0);
    assert_eq!(cohort_of(&roll, &membership).unwrap(), JP_BROKER);
}

#[test]
fn a_handle_nobody_vetted_cannot_prove_anything() {
    let (key, operator, mut roll) = world(16);
    let vetted = Scalar::random(&mut OsRng);
    let seal = operator.vouch(&mut roll, JP_BROKER, &vetted, &mut OsRng);
    let membership = prove_membership(&key, &roll, &seal, &vetted, b"c", &mut OsRng).unwrap();

    // The same proof, offered for somebody else's handle.
    let stranger = handle_of(&Scalar::random(&mut OsRng));
    assert!(check_membership(&key, &roll, &stranger, &membership, b"c").is_err());
}

#[test]
fn one_vetting_yields_one_handle_and_not_a_family_of_them() {
    // The soundness property the control proof exists for. Without it the ring
    // proof alone says only that `C_l - A` is a multiple of h, so `A + delta*h`
    // would pass for any delta the holder picks --- one vetting, unboundedly
    // many usable handles, and every per-firm cap void.
    let (key, operator, mut roll) = world(16);
    let secret = Scalar::random(&mut OsRng);
    let seal = operator.vouch(&mut roll, JP_BROKER, &secret, &mut OsRng);
    let membership = prove_membership(&key, &roll, &seal, &secret, b"c", &mut OsRng).unwrap();

    let shifted = handle_of(&secret) + key.h * Scalar::from(7u64);
    let why = check_membership(&key, &roll, &shifted, &membership, b"c").unwrap_err();
    assert!(why.contains("bare power"), "{why}");
}

#[test]
fn a_decoy_seat_cannot_be_used_by_anyone() {
    // Decoys are hashed, not drawn, so no opening exists for them --- which is
    // what makes `vetted()` an honest count rather than a claim.
    let (key, operator, mut roll) = world(8);
    let secret = Scalar::random(&mut OsRng);
    let mut seal = operator.vouch(&mut roll, JP_BROKER, &secret, &mut OsRng);
    assert_eq!(roll.vetted(), 1);

    // Point the seal at a seat that is still a decoy and try to prove from it.
    let taken = seal.index;
    seal.index = (taken + 1) % 8;
    let membership = prove_membership(&key, &roll, &seal, &secret, b"c", &mut OsRng);
    match membership {
        Err(_) => {}
        Ok(proof) => assert!(
            check_membership(&key, &roll, &handle_of(&secret), &proof, b"c").is_err(),
            "a decoy seat proved membership"
        ),
    }
}

#[test]
fn the_roll_says_how_big_the_crowd_is() {
    let (_key, operator, mut roll) = world(16);
    assert_eq!(roll.vetted(), 0);
    for _ in 0..20 {
        operator.vouch(
            &mut roll,
            JP_BROKER,
            &Scalar::random(&mut OsRng),
            &mut OsRng,
        );
    }
    // Twenty firms, sixteen to a group, so a second group opened.
    assert_eq!(roll.vetted(), 20);
    assert_eq!(roll.groups().len(), 2);
    assert_eq!(roll.crowd(), 16);
    assert_eq!(roll.groups()[0].filled, 16);
    assert_eq!(roll.groups()[1].filled, 4);
    // The second group is still mostly decoys, and says so rather than
    // pretending its four firms hide among sixteen.
    assert_eq!(roll.groups()[1].envelopes.len(), 16);
}

#[test]
fn cohorts_do_not_share_a_group() {
    let (key, operator, mut roll) = world(8);
    let broker = Scalar::random(&mut OsRng);
    let bank = Scalar::random(&mut OsRng);
    let broker_seal = operator.vouch(&mut roll, JP_BROKER, &broker, &mut OsRng);
    let bank_seal = operator.vouch(&mut roll, UK_BANK, &bank, &mut OsRng);
    assert_ne!(broker_seal.group, bank_seal.group);

    // An attribute gate reads the cohort off the group, so it does not have to
    // take the presenter's word for the attribute.
    let membership = prove_membership(&key, &roll, &bank_seal, &bank, b"c", &mut OsRng).unwrap();
    check_membership(&key, &roll, &handle_of(&bank), &membership, b"c").unwrap();
    assert_eq!(cohort_of(&roll, &membership).unwrap(), UK_BANK);
}

#[test]
fn a_seal_cut_before_the_group_moved_is_refused_rather_than_checked() {
    let (key, operator, mut roll) = world(8);
    let first = Scalar::random(&mut OsRng);
    let seal = operator.vouch(&mut roll, JP_BROKER, &first, &mut OsRng);
    // Somebody else joins the same group, so a decoy became an envelope.
    operator.vouch(
        &mut roll,
        JP_BROKER,
        &Scalar::random(&mut OsRng),
        &mut OsRng,
    );

    let why = prove_membership(&key, &roll, &seal, &first, b"c", &mut OsRng).unwrap_err();
    assert!(why.contains("moved under this seal"), "{why}");
}

#[test]
fn a_proof_does_not_travel_between_rounds() {
    let (key, operator, mut roll) = world(8);
    let secret = Scalar::random(&mut OsRng);
    let seal = operator.vouch(&mut roll, JP_BROKER, &secret, &mut OsRng);
    let membership = prove_membership(&key, &roll, &seal, &secret, b"round-1", &mut OsRng).unwrap();
    assert!(check_membership(&key, &roll, &handle_of(&secret), &membership, b"round-2").is_err());
}

#[test]
fn every_firm_in_a_full_group_proves_against_the_same_sixteen() {
    // The reason the group is fixed rather than drawn per proof: an observer
    // gets the same candidates every time, and intersecting a set with itself
    // narrows nothing.
    let (key, operator, mut roll) = world(16);
    let secrets: Vec<Scalar> = (0..16).map(|_| Scalar::random(&mut OsRng)).collect();
    let seals: Vec<_> = secrets
        .iter()
        .map(|s| operator.vouch(&mut roll, JP_BROKER, s, &mut OsRng))
        .collect();
    assert!(seals.iter().all(|s| s.group == 0));

    // Only the last seal is current, because each vouch bumps the epoch. Every
    // holder re-cuts against the group it is in, which is the operational cost
    // of a group that is still filling.
    let current: Vec<_> = seals
        .iter()
        .map(|s| qomm_defmi::vetting::Seal {
            epoch: roll.groups()[0].epoch,
            ..s.clone()
        })
        .collect();
    for (secret, seal) in secrets.iter().zip(&current) {
        let membership = prove_membership(&key, &roll, seal, secret, b"c", &mut OsRng).unwrap();
        check_membership(&key, &roll, &handle_of(secret), &membership, b"c").unwrap();
        assert_eq!(membership.group, 0);
    }
}

#[test]
fn the_group_size_is_a_power_of_two_because_the_proof_needs_one() {
    assert!(Roll::new(12).is_err());
    assert!(Roll::new(1).is_err());
    assert!(Roll::new(8).is_ok());
    assert!(Roll::new(16).is_ok());
}

#[test]
fn a_membership_proof_at_a_group_of_sixteen_is_one_thousand_and_four_bytes() {
    // Predicted before running: 928 for the ring (4 bits x (4 points + 3
    // scalars) + one scalar), 64 for the control proof, 12 for the group and
    // construction reports at N=16, which is how the two are known to be the
    // same object.
    let (key, operator, mut roll) = world(16);
    let secret = Scalar::random(&mut OsRng);
    let seal = operator.vouch(&mut roll, JP_BROKER, &secret, &mut OsRng);
    let membership = prove_membership(&key, &roll, &seal, &secret, b"c", &mut OsRng).unwrap();
    assert_eq!(membership.ring.size_bytes(), 928);
    assert_eq!(membership.size_bytes(), 1004);
}

#[test]
fn a_handle_that_is_g_to_the_secret_is_what_the_envelope_commits_to() {
    // The relation the whole construction rests on, checked directly rather
    // than only through the proof: an envelope is the handle plus a blinding,
    // so subtracting the handle leaves a commitment to zero.
    let key = Pedersen::new(b"qomm:defmi:vetting");
    let secret = Scalar::random(&mut OsRng);
    let blinding = Scalar::random(&mut OsRng);
    let envelope = key.commit(&secret, &blinding);
    assert_eq!(
        envelope - handle_of(&secret),
        key.commit(&Scalar::ZERO, &blinding)
    );
    assert_eq!(handle_of(&secret), G * secret);
}

#[test]
fn the_default_crowd_is_the_one_the_measurement_supports() {
    // 128, not 16. The cap was 16 while verification was believed linear in the
    // crowd; measured, doubling costs about 1.4x, so eight times the crowd fits
    // the same budget. This test is here so the constant cannot drift back
    // without somebody deciding to move it.
    use qomm_defmi::vetting::CROWD;
    assert_eq!(CROWD, 128);
    assert!(CROWD.is_power_of_two());
    assert!(Roll::new(CROWD).is_ok());
}

#[test]
fn a_crowd_of_a_hundred_and_twenty_eight_costs_what_the_document_says() {
    let key = Pedersen::new(b"qomm:defmi:vetting");
    let operator = Operator::new(key.clone());
    let mut roll = Roll::new(qomm_defmi::vetting::CROWD).unwrap();
    let secret = Scalar::random(&mut OsRng);
    let seal = operator.vouch(&mut roll, JP_BROKER, &secret, &mut OsRng);
    let membership = prove_membership(&key, &roll, &seal, &secret, b"c", &mut OsRng).unwrap();
    check_membership(&key, &roll, &handle_of(&secret), &membership, b"c").unwrap();
    // 7 bits: 4 vectors of points and 3 of scalars, plus zd, plus the control
    // proof and the group and epoch.
    assert_eq!(membership.ring.size_bytes(), 1600);
    assert_eq!(membership.size_bytes(), 1676);
}

#[test]
fn the_roll_a_verifier_checks_against_is_one_it_can_identify() {
    // `check_membership` proves a handle is in the roll it is given, so a proof
    // arriving with its own roll proves nothing. The digest is what a verifier
    // compares against whatever the chain published.
    let (_key, operator, mut roll) = world(16);
    let before = roll.digest();
    assert_eq!(
        before,
        roll.clone().digest(),
        "the digest is not a function of the roll"
    );

    operator.vouch(
        &mut roll,
        JP_BROKER,
        &Scalar::random(&mut OsRng),
        &mut OsRng,
    );
    assert_ne!(roll.digest(), before, "vouching did not move the digest");

    // and two rolls built the same way from different envelopes differ
    let (_k2, op2, mut other) = world(16);
    op2.vouch(
        &mut other,
        JP_BROKER,
        &Scalar::random(&mut OsRng),
        &mut OsRng,
    );
    assert_ne!(other.digest(), roll.digest());
}
