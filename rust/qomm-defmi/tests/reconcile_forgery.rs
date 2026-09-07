//! Regression for the 2026-09-07 finding: a prover who knows the openings must
//! not be able to make the reconciliation accept a total the balances do not
//! sum to. The residual is checked as a zero-relation opening, so a general
//! opening proof of it, which such a prover can always produce, is refused.

use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_defmi::reconcile::*;
use qomm_zk::pedersen::{asset_tag, Pedersen};
use qomm_zk::sigma::prove_opening;
use rand::rngs::OsRng;

#[test]
fn a_dishonest_total_is_refused() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1").with_value_generator(asset_tag(7));
    let values = [1_000u64, 2_000, 3_000];
    let blindings: Vec<Scalar> = (0..3).map(|_| Scalar::random(&mut rng)).collect();
    let commitments: Vec<_> = values
        .iter()
        .zip(&blindings)
        .map(|(v, r)| key.commit_u64(*v, r))
        .collect();
    let true_total: u64 = values.iter().sum();
    let claimed = true_total + 500; // the register says 6,500; the ledger holds 6,000
    let attestation = Attestation {
        register: "reg".into(),
        account: "acct".into(),
        asset: "7".into(),
        as_of: "2026-09-07".into(),
        total: claimed,
        signature: None,
    };
    // honest path refuses
    let honest = prove(&key, &commitments, &blindings, &attestation, &mut rng).unwrap();
    assert!(
        check(&key, &commitments, &honest, None).is_err(),
        "honest prover with wrong total must fail"
    );
    // dishonest path: open the residual with value (true - claimed) instead of zero
    let residual = aggregate(&commitments) - key.g * Scalar::from(claimed);
    let delta = Scalar::from(true_total) - Scalar::from(claimed);
    let combined: Scalar = blindings.iter().sum();
    let mut t = Transcript::new(b"qomm:defmi:reconcile");
    t.append_message(b"attestation", &attestation.body());
    let forged = prove_opening(&key, &mut t, &residual, &delta, &combined, &mut rng);
    let rec = Reconciliation {
        attestation: attestation.clone(),
        positions: commitments.len(),
        proof: forged,
    };
    assert!(
        check(&key, &commitments, &rec, None).is_err(),
        "FORGERY ACCEPTED: total {} accepted for balances summing to {}",
        claimed,
        true_total
    );
}
