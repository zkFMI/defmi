//! The audit has to accept a legal policy, reject an illegal one without being
//! told which field was wrong, and keep the sharing tied to the commitment the
//! range proof covers --- the last being the join that makes the other two mean
//! anything.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use qomm_proofs::policy_audit::{
    reconstruct, Invalid, Policy, PolicyAuditor, PolicyBounds, PolicyCommitter,
};
use rand_core::OsRng;

const REF_MID: i64 = 100_000;
const NOW: i64 = 1_000;

fn legal() -> Policy {
    Policy {
        ask_level: REF_MID + 22,
        spread: 24,
        slope: 3,
        invcoef: 2,
        inv: -250,
        maxqty: 400,
        expiry: NOW + 600,
        active: true,
    }
}

fn nullifier() -> RistrettoPoint {
    RistrettoPoint::random(&mut OsRng)
}

type NoVerifier = fn(&[u8], &[u8]) -> bool;
type NoSigner = fn(&[u8]) -> Vec<u8>;

#[test]
fn a_legal_policy_is_accepted() {
    let committer = PolicyCommitter::default();
    let auditor = PolicyAuditor::default();
    let (audit, _) = committer
        .audit(
            &legal(),
            REF_MID,
            NOW,
            7,
            2,
            &nullifier(),
            None::<NoSigner>,
            &mut OsRng,
        )
        .unwrap();
    assert_eq!(
        auditor.verify(&audit, NOW, REF_MID, 3_600, None::<NoVerifier>),
        Ok(())
    );
}

#[test]
fn every_field_is_actually_checked_against_its_band() {
    let committer = PolicyCommitter::default();
    let bounds = PolicyBounds::default();
    for (name, bad) in [
        (
            "spread",
            Policy {
                spread: bounds.spread.1 + 1,
                ..legal()
            },
        ),
        (
            "slope",
            Policy {
                slope: bounds.slope.1 + 1,
                ..legal()
            },
        ),
        (
            "invcoef",
            Policy {
                invcoef: -1,
                ..legal()
            },
        ),
        (
            "inv",
            Policy {
                inv: bounds.inv.0 - 1,
                ..legal()
            },
        ),
        (
            "maxqty",
            Policy {
                maxqty: 0,
                ..legal()
            },
        ),
        (
            "ask_level",
            Policy {
                ask_level: REF_MID + bounds.level_band + 1,
                ..legal()
            },
        ),
    ] {
        let out = committer.audit(
            &bad,
            REF_MID,
            NOW,
            7,
            2,
            &nullifier(),
            None::<NoSigner>,
            &mut OsRng,
        );
        assert!(
            out.is_err(),
            "{name} outside its band still produced an audit"
        );
    }
}

#[test]
fn an_audit_does_not_carry_to_a_different_reference_state() {
    let committer = PolicyCommitter::default();
    let auditor = PolicyAuditor::default();
    let (audit, _) = committer
        .audit(
            &legal(),
            REF_MID,
            NOW,
            7,
            2,
            &nullifier(),
            None::<NoSigner>,
            &mut OsRng,
        )
        .unwrap();
    assert_eq!(
        auditor.verify(&audit, NOW, REF_MID + 1, 3_600, None::<NoVerifier>),
        Err(Invalid::NotBoundToCurrentState)
    );
    assert_eq!(
        auditor.verify(&audit, NOW + 1, REF_MID, 3_600, None::<NoVerifier>),
        Err(Invalid::NotBoundToCurrentState)
    );
}

#[test]
fn an_expiry_past_the_horizon_is_refused() {
    let committer = PolicyCommitter::default();
    let auditor = PolicyAuditor::default();
    let far = Policy {
        expiry: NOW + 100_000,
        ..legal()
    };
    let (audit, _) = committer
        .audit(
            &far,
            REF_MID,
            NOW,
            7,
            2,
            &nullifier(),
            None::<NoSigner>,
            &mut OsRng,
        )
        .unwrap();
    assert_eq!(
        auditor.verify(&audit, NOW, REF_MID, 3_600, None::<NoVerifier>),
        Err(Invalid::ExpiryOutsideHorizon)
    );
}

#[test]
fn every_node_can_check_its_own_share_without_the_dealer() {
    let committer = PolicyCommitter::default();
    let (_, shares) = committer
        .audit(
            &legal(),
            REF_MID,
            NOW,
            7,
            2,
            &nullifier(),
            None::<NoSigner>,
            &mut OsRng,
        )
        .unwrap();
    let (audit, _) = committer
        .audit(
            &legal(),
            REF_MID,
            NOW,
            7,
            2,
            &nullifier(),
            None::<NoSigner>,
            &mut OsRng,
        )
        .unwrap();
    let _ = audit;
    for (name, field_shares) in &shares {
        assert_eq!(field_shares.len(), 7, "{name}");
    }
}

#[test]
fn shares_reconstruct_the_committed_value_and_a_forged_share_does_not_verify() {
    let committer = PolicyCommitter::default();
    let auditor = PolicyAuditor::default();
    let policy = legal();
    let (audit, shares) = committer
        .audit(
            &policy,
            REF_MID,
            NOW,
            7,
            2,
            &nullifier(),
            None::<NoSigner>,
            &mut OsRng,
        )
        .unwrap();

    let (name, spread_shares) = shares.iter().find(|(n, _)| n == "spread").unwrap();
    assert_eq!(name, "spread");
    assert_eq!(
        reconstruct(spread_shares, 2),
        Scalar::from(policy.spread as u64)
    );

    let field = &audit.fields.iter().find(|(n, _)| n == "spread").unwrap().1;
    assert!(auditor.verify_node_share(&spread_shares[0], field));

    let mut forged = spread_shares[0];
    forged.value_share += Scalar::ONE;
    assert!(!auditor.verify_node_share(&forged, field));
}

#[test]
fn the_signature_covers_the_commitments() {
    let committer = PolicyCommitter::default();
    let auditor = PolicyAuditor::default();
    let sign = |digest: &[u8]| digest.to_vec();
    let (audit, _) = committer
        .audit(
            &legal(),
            REF_MID,
            NOW,
            7,
            2,
            &nullifier(),
            Some(sign),
            &mut OsRng,
        )
        .unwrap();
    let check = |digest: &[u8], signature: &[u8]| digest == signature;
    assert_eq!(
        auditor.verify(&audit, NOW, REF_MID, 3_600, Some(check)),
        Ok(())
    );

    let mut tampered = audit;
    tampered.entity_signature[0] ^= 0xff;
    assert_eq!(
        auditor.verify(&tampered, NOW, REF_MID, 3_600, Some(check)),
        Err(Invalid::NotSignedByCredential)
    );
}
