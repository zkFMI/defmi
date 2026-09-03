//! Agreeing with the book of record without opening anything to it.

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signer, SigningKey};
use qomm_defmi::reconcile::*;
use qomm_zk::pedersen::{asset_tag, Pedersen};
use rand::rngs::OsRng;
use rand::Rng;

fn key() -> Pedersen {
    Pedersen::new(b"qomm:defmi:v1").with_value_generator(asset_tag(7))
}

fn ledger(
    n: usize,
) -> (
    Pedersen,
    Vec<u64>,
    Vec<Scalar>,
    Vec<curve25519_dalek::ristretto::RistrettoPoint>,
) {
    let mut rng = OsRng;
    let k = key();
    let values: Vec<u64> = (0..n).map(|_| rng.gen_range(1..10_000)).collect();
    let blindings: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
    let commitments = values
        .iter()
        .zip(&blindings)
        .map(|(v, r)| k.commit_u64(*v, r))
        .collect();
    (k, values, blindings, commitments)
}

fn attest(total: u64) -> Attestation {
    Attestation {
        register: "a register".into(),
        account: "omnibus-001".into(),
        asset: "an instrument".into(),
        total,
        as_of: "2026-08-22T09:00Z".into(),
        signature: None,
    }
}

#[test]
fn the_committed_balances_reconcile_without_any_of_them_opening() {
    let mut rng = OsRng;
    let (k, values, blindings, commitments) = ledger(24);
    let total: u64 = values.iter().sum();
    let r = prove(&k, &commitments, &blindings, &attest(total), &mut rng).unwrap();
    assert_eq!(check(&k, &commitments, &r, None), Ok(()));
}

#[test]
fn only_the_right_total_verifies() {
    let mut rng = OsRng;
    let (k, values, blindings, commitments) = ledger(16);
    let total: u64 = values.iter().sum();
    for wrong in [total + 1, total - 1, 0] {
        let r = prove(&k, &commitments, &blindings, &attest(wrong), &mut rng).unwrap();
        assert!(check(&k, &commitments, &r, None)
            .unwrap_err()
            .contains("do not sum to"));
    }
}

#[test]
fn the_proof_is_about_this_account_at_this_moment() {
    let mut rng = OsRng;
    let (k, values, blindings, commitments) = ledger(12);
    let total: u64 = values.iter().sum();
    let r = prove(&k, &commitments, &blindings, &attest(total), &mut rng).unwrap();
    let mut moved = attest(total);
    moved.account = "omnibus-002".into();
    let elsewhere = Reconciliation {
        attestation: moved,
        positions: r.positions,
        proof: r.proof.clone(),
    };
    assert!(check(&k, &commitments, &elsewhere, None).is_err());
}

#[test]
fn a_different_set_of_positions_is_refused_rather_than_reinterpreted() {
    let mut rng = OsRng;
    let (k, values, blindings, commitments) = ledger(12);
    let total: u64 = values.iter().sum();
    let r = prove(&k, &commitments, &blindings, &attest(total), &mut rng).unwrap();
    assert!(check(&k, &commitments[..11], &r, None)
        .unwrap_err()
        .contains("positions"));
}

#[test]
fn the_wrong_asset_generator_does_not_verify() {
    // had this wrong: it took the total off with the base generator whatever the
    // key carried, which is the same point only when the key carries no tag.
    let mut rng = OsRng;
    let (k, values, blindings, commitments) = ledger(8);
    let total: u64 = values.iter().sum();
    let r = prove(&k, &commitments, &blindings, &attest(total), &mut rng).unwrap();
    let untagged = Pedersen::new(b"qomm:defmi:v1");
    assert!(check(&untagged, &commitments, &r, None).is_err());
}

#[test]
fn an_unsigned_attestation_is_only_as_good_as_the_number_it_carries() {
    let mut rng = OsRng;
    let (k, values, blindings, commitments) = ledger(10);
    let total: u64 = values.iter().sum();
    let registrar = SigningKey::generate(&mut rng);
    let mut signed = attest(total);
    signed.signature = Some(registrar.sign(&signed.body()));
    let r = prove(&k, &commitments, &blindings, &signed, &mut rng).unwrap();
    assert_eq!(
        check(&k, &commitments, &r, Some(&registrar.verifying_key())),
        Ok(())
    );
    // the same proof with a signature nobody checked
    assert!(check(&k, &commitments, &r, None).is_err());
    // and one from the wrong registrar
    let other = SigningKey::generate(&mut rng);
    assert!(check(&k, &commitments, &r, Some(&other.verifying_key())).is_err());
}

#[test]
fn a_break_is_pass_or_fail_and_says_nothing_about_where() {
    let mut rng = OsRng;
    let (k, values, blindings, commitments) = ledger(24);
    let mut register = values.clone();
    register[9] += 5;
    let total: u64 = register.iter().sum();
    let r = prove(&k, &commitments, &blindings, &attest(total), &mut rng).unwrap();
    let why = check(&k, &commitments, &r, None).unwrap_err();
    assert!(why.contains("says nothing about where"));
}

#[test]
fn finding_a_break_costs_about_two_log_n_and_reports_it() {
    let mut rng = OsRng;
    for n in [16usize, 64, 256] {
        let (k, values, blindings, commitments) = ledger(n);
        let mut register = values.clone();
        register[n / 3] += 5;
        let total: u64 = register.iter().sum();
        let search = locate_break(
            &k,
            &commitments,
            &blindings,
            |a, b| Some(register[a..b].iter().sum()),
            total,
            &mut rng,
        )
        .unwrap();
        assert_eq!(search.found, vec![n / 3]);
        assert_eq!(
            search.proofs,
            2 * (usize::BITS - n.leading_zeros() - 1) as usize + 1
        );
        // the narrowest range made public covers one position, which is a balance
        assert_eq!(search.narrowest(), 1);
    }
}

#[test]
fn a_register_that_holds_only_a_total_cannot_localise() {
    // There is nothing here that finds a break without somebody claiming
    // subtotals, and saying so is the point of returning an error.
    let mut rng = OsRng;
    let (k, values, blindings, commitments) = ledger(8);
    let total: u64 = values.iter().sum::<u64>() + 1;
    let why = locate_break(
        &k,
        &commitments,
        &blindings,
        |a, b| if (a, b) == (0, 8) { Some(total) } else { None },
        total,
        &mut rng,
    )
    .unwrap_err();
    assert!(why.contains("stays pass-or-fail"), "{why}");
}

#[test]
fn a_register_with_a_figure_per_position_localises_and_discloses_nothing() {
    let (k, values, blindings, commitments) = ledger(32);
    let mut register = values.clone();
    register[7] += 1;
    register[20] -= 3;
    assert_eq!(
        check_positions(&k, &commitments, &blindings, &register, &mut OsRng),
        vec![7, 20]
    );
    assert!(check_positions(&k, &commitments, &blindings, &values, &mut OsRng).is_empty());
}
