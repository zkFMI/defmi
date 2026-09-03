//! Contract tests for policy and KYB proof composition.
//!
//! The control assertion before each negative case is intentional: a forged
//! object must first be shown to work in its honest form, then reach the check
//! named by the expected error.  This prevents a malformed proof from passing
//! a rejection test at an unrelated earlier check.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signer, SigningKey, Verifier};
use merlin::Transcript;
use qomm_proofs::kyb::{
    cohort_id, present, verify_presentation, verify_registry, BusinessAttributes, EntityLimits,
    EntityRateLimiter, Invalid as KybInvalid, KybCredential, KybIssuer, Refused,
    SignedCohortRegistry,
};
use qomm_proofs::policy_audit::{
    reconstruct, Invalid as PolicyInvalid, Policy, PolicyAudit, PolicyAuditor, PolicyBounds,
    PolicyCommitter, PolicyShare,
};
use qomm_zk::bitrange::{
    prove_bounded, prove_range, shift_commitment, suffixed_context, verify_bounded, BoundedProof,
};
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::prove_bit;
use rand_core::OsRng;
use sha2::{Digest, Sha256};

const REF_MID: i64 = 100_000;
const NOW: i64 = 1_000;
const HORIZON: i64 = 3_600;
const SCOPE: &[u8] = b"qomm:quote:epoch7";
const CONTEXT: &[u8] = br#"{"asset":1,"venue":"qomm"}"#;

type NoVerifier = fn(&[u8], &[u8]) -> bool;
type NoSigner = fn(&[u8]) -> Vec<u8>;
type Shares = Vec<(String, Vec<PolicyShare>)>;

fn good_policy() -> Policy {
    Policy {
        ask_level: 100_000,
        spread: 14,
        slope: 2,
        invcoef: 1,
        inv: -320,
        maxqty: 400,
        expiry: 1_600,
        active: true,
    }
}

fn entity_nullifier() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT * Scalar::from(0x454e_5449_5459u64)
}

fn audit(policy: &Policy) -> (PolicyCommitter, PolicyAudit, Shares) {
    let committer = PolicyCommitter::default();
    let (audit, shares) = committer
        .audit(
            policy,
            REF_MID,
            NOW,
            7,
            2,
            &entity_nullifier(),
            None::<NoSigner>,
            &mut OsRng,
        )
        .unwrap();
    (committer, audit, shares)
}

fn scalar(value: i64) -> Scalar {
    if value < 0 {
        -Scalar::from(value.unsigned_abs())
    } else {
        Scalar::from(value as u64)
    }
}

fn policy_context(expiry: i64, nullifier: &RistrettoPoint) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"qomm:policy-ctx:");
    for part in [REF_MID, NOW, expiry] {
        hash.update(part.to_be_bytes());
    }
    hash.update(nullifier.compress().as_bytes());
    hash.finalize().to_vec()
}

fn policy_transcript(context: &[u8], part: &[u8]) -> Transcript {
    let mut transcript = Transcript::new(b"qomm:policy:v1");
    transcript.append_message(b"ctx", context);
    transcript.append_message(b"part", part);
    transcript
}

fn venue() -> (KybIssuer, Vec<KybCredential>, SignedCohortRegistry) {
    let mut issuer = KybIssuer::new(5, &mut OsRng);
    let entities = [("GROUP-A", 4), ("GROUP-B", 2), ("GROUP-C", 5)]
        .into_iter()
        .map(|(name, tier)| {
            issuer
                .enroll(
                    name,
                    BusinessAttributes {
                        jurisdiction: "JP".into(),
                        entity_type: "bank".into(),
                        collateral_tier: tier,
                    },
                    &mut OsRng,
                )
                .unwrap()
        })
        .collect();
    let registry = issuer
        .publish(&cohort_id("JP", "bank", 2), 1, 9_999)
        .unwrap();
    (issuer, entities, registry)
}

#[test]
fn well_formed_policy_is_accepted() {
    let (_, audit, _) = audit(&good_policy());
    assert_eq!(
        PolicyAuditor::default().verify(&audit, NOW, REF_MID, HORIZON, None::<NoVerifier>),
        Ok(())
    );
}

#[test]
fn every_node_can_check_its_own_share() {
    let (committer, audit, shares) = audit(&good_policy());
    for (name, field_shares) in &shares {
        assert_eq!(field_shares.len(), 7, "{name}");
        let field = &audit
            .fields
            .iter()
            .find(|(field, _)| field == name)
            .unwrap()
            .1;
        for share in field_shares {
            assert!(
                committer.verify_share(share, field),
                "{name}/party{}",
                share.party
            );
        }
    }
}

#[test]
fn a_tampered_share_is_caught_by_its_node() {
    let (committer, audit, shares) = audit(&good_policy());
    let field = &audit
        .fields
        .iter()
        .find(|(name, _)| name == "maxqty")
        .unwrap()
        .1;
    let victim = shares.iter().find(|(name, _)| name == "maxqty").unwrap().1[3];
    assert!(committer.verify_share(&victim, field));
    let forged = PolicyShare {
        value_share: victim.value_share + Scalar::ONE,
        ..victim
    };
    assert!(!committer.verify_share(&forged, field));
}

#[test]
fn shares_reconstruct_the_committed_value() {
    let (_, _, shares) = audit(&good_policy());
    let field = |name: &str| &shares.iter().find(|(field, _)| field == name).unwrap().1;
    assert_eq!(reconstruct(field("maxqty"), 2), scalar(400));
    assert_eq!(reconstruct(field("inv"), 2), scalar(-320));
    let spread = field("spread");
    let subset = [spread[1], spread[4], spread[6]];
    assert_eq!(reconstruct(&subset, 2), scalar(14));
}

#[test]
fn out_of_band_fields_cannot_be_proved() {
    assert!(PolicyCommitter::default()
        .audit(
            &good_policy(),
            REF_MID,
            NOW,
            7,
            2,
            &entity_nullifier(),
            None::<NoSigner>,
            &mut OsRng,
        )
        .is_ok());
    for (name, bad) in [
        ("spread", 900),
        ("slope", 100),
        ("invcoef", 50),
        ("maxqty", 5_000),
        ("inv", 50_000),
        ("ask_level", 400_000),
    ] {
        let mut policy = good_policy();
        match name {
            "spread" => policy.spread = bad,
            "slope" => policy.slope = bad,
            "invcoef" => policy.invcoef = bad,
            "maxqty" => policy.maxqty = bad,
            "inv" => policy.inv = bad,
            "ask_level" => policy.ask_level = bad,
            _ => unreachable!(),
        }
        let result = PolicyCommitter::default().audit(
            &policy,
            REF_MID,
            NOW,
            7,
            2,
            &entity_nullifier(),
            None::<NoSigner>,
            &mut OsRng,
        );
        match result {
            Err(error) => assert_eq!(
                error, "a policy field is outside its published band",
                "{name}"
            ),
            Ok(_) => panic!("{name} outside its band still produced an audit"),
        }
    }
}

#[test]
fn swapping_in_another_commitment_is_rejected() {
    let (committer, mut audit, _) = audit(&good_policy());
    let auditor = PolicyAuditor::default();
    assert_eq!(
        auditor.verify(&audit, NOW, REF_MID, HORIZON, None::<NoVerifier>),
        Ok(())
    );
    let forged = committer
        .key
        .commit(&Scalar::from(900u64), &Scalar::random(&mut OsRng));
    let spread = &mut audit
        .fields
        .iter_mut()
        .find(|(name, _)| name == "spread")
        .unwrap()
        .1;
    spread.commitment = forged;
    spread.coefficients[0] = forged;
    assert_eq!(
        auditor.verify(&audit, NOW, REF_MID, HORIZON, None::<NoVerifier>),
        Err(PolicyInvalid::OutOfBand)
    );
}

#[test]
fn commitment_must_match_the_sharing() {
    let (committer, mut audit, _) = audit(&good_policy());
    let auditor = PolicyAuditor::default();
    assert_eq!(
        auditor.verify(&audit, NOW, REF_MID, HORIZON, None::<NoVerifier>),
        Ok(())
    );
    let other = committer
        .key
        .commit(&Scalar::from(7u64), &Scalar::random(&mut OsRng));
    audit
        .fields
        .iter_mut()
        .find(|(name, _)| name == "slope")
        .unwrap()
        .1
        .coefficients[0] = other;
    assert_eq!(
        auditor.verify(&audit, NOW, REF_MID, HORIZON, None::<NoVerifier>),
        Err(PolicyInvalid::ShareDoesNotMatchCommitment("slope".into()))
    );
}

#[test]
fn audit_is_bound_to_the_reference_state() {
    let (_, audit, _) = audit(&good_policy());
    let auditor = PolicyAuditor::default();
    assert_eq!(
        auditor.verify(&audit, NOW, REF_MID, HORIZON, None::<NoVerifier>),
        Ok(())
    );
    assert_eq!(
        auditor.verify(&audit, NOW + 1, REF_MID, HORIZON, None::<NoVerifier>),
        Err(PolicyInvalid::NotBoundToCurrentState)
    );
    assert_eq!(
        auditor.verify(&audit, NOW, REF_MID + 1, HORIZON, None::<NoVerifier>),
        Err(PolicyInvalid::NotBoundToCurrentState)
    );
}

#[test]
fn expiry_must_sit_inside_the_horizon() {
    let (_, mut audit, _) = audit(&good_policy());
    let auditor = PolicyAuditor::default();
    assert_eq!(
        auditor.verify(&audit, NOW, REF_MID, HORIZON, None::<NoVerifier>),
        Ok(())
    );
    assert_eq!(
        auditor.verify(&audit, NOW, REF_MID, 10, None::<NoVerifier>),
        Err(PolicyInvalid::ExpiryOutsideHorizon)
    );
    audit.expiry = NOW - 1;
    assert_eq!(
        auditor.verify(&audit, NOW, REF_MID, HORIZON, None::<NoVerifier>),
        Err(PolicyInvalid::ExpiryOutsideHorizon)
    );
}

#[test]
fn active_flag_must_be_a_bit() {
    let (committer, mut audit, _) = audit(&good_policy());
    let auditor = PolicyAuditor::default();
    assert_eq!(
        auditor.verify(&audit, NOW, REF_MID, HORIZON, None::<NoVerifier>),
        Ok(())
    );
    let blinding = Scalar::random(&mut OsRng);
    let two = committer.key.commit(&Scalar::from(2u64), &blinding);
    let context = policy_context(audit.expiry, &audit.entity_nullifier);
    let forged = prove_bit(
        &committer.key,
        &mut policy_transcript(&context, b"active"),
        &two,
        true,
        &blinding,
        &mut OsRng,
    );
    audit.active_commitment = two;
    audit.active_proof = forged;
    assert_eq!(
        auditor.verify(&audit, NOW, REF_MID, HORIZON, None::<NoVerifier>),
        Err(PolicyInvalid::ActiveNotABit)
    );
}

#[test]
fn policy_can_be_attributed_to_its_entity() {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();
    let committer = PolicyCommitter::default();
    let (mut audit, _) = committer
        .audit(
            &good_policy(),
            REF_MID,
            NOW,
            7,
            2,
            &entity_nullifier(),
            Some(|digest: &[u8]| signing.sign(digest).to_bytes().to_vec()),
            &mut OsRng,
        )
        .unwrap();
    let check = |digest: &[u8], signature: &[u8]| {
        let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
            return false;
        };
        verifying.verify(digest, &signature).is_ok()
    };
    let auditor = PolicyAuditor::default();
    assert_eq!(
        auditor.verify(&audit, NOW, REF_MID, HORIZON, Some(check)),
        Ok(())
    );
    audit.entity_signature = vec![0; 64];
    assert_eq!(
        auditor.verify(&audit, NOW, REF_MID, HORIZON, Some(check)),
        Err(PolicyInvalid::NotSignedByCredential)
    );
}

#[test]
fn qualified_entity_presents_anonymously() {
    let (issuer, entities, registry) = venue();
    let presentation = present(&entities[0], &registry, SCOPE, CONTEXT, &mut OsRng).unwrap();
    assert_eq!(
        verify_presentation(
            &presentation,
            &registry,
            &issuer.public_key(),
            SCOPE,
            CONTEXT,
            100,
            &registry.cohort,
        ),
        Ok(())
    );
}

#[test]
fn lower_tier_entity_cannot_enter_a_higher_cohort() {
    let (issuer, entities, _) = venue();
    let high = issuer
        .publish(&cohort_id("JP", "bank", 4), 1, 9_999)
        .unwrap();
    assert!(present(&entities[0], &high, SCOPE, CONTEXT, &mut OsRng).is_ok());
    let error = present(&entities[1], &high, SCOPE, CONTEXT, &mut OsRng).unwrap_err();
    assert_eq!(error, "credential does not qualify for this cohort");
}

#[test]
fn presentation_does_not_transfer() {
    let (issuer, entities, registry) = venue();
    let presentation = present(&entities[0], &registry, SCOPE, CONTEXT, &mut OsRng).unwrap();
    let key = issuer.public_key();
    assert_eq!(
        verify_presentation(
            &presentation,
            &registry,
            &key,
            SCOPE,
            CONTEXT,
            100,
            &registry.cohort,
        ),
        Ok(())
    );
    assert_eq!(
        verify_presentation(
            &presentation,
            &registry,
            &key,
            b"qomm:quote:epoch8",
            CONTEXT,
            100,
            &registry.cohort,
        ),
        Err(KybInvalid::WrongScopeOrContext)
    );
    assert_eq!(
        verify_presentation(
            &presentation,
            &registry,
            &key,
            SCOPE,
            br#"{"venue":"other"}"#,
            100,
            &registry.cohort,
        ),
        Err(KybInvalid::WrongScopeOrContext)
    );
}

#[test]
fn expired_or_foreign_registry_is_rejected() {
    let (issuer, entities, registry) = venue();
    let presentation = present(&entities[0], &registry, SCOPE, CONTEXT, &mut OsRng).unwrap();
    assert_eq!(
        verify_presentation(
            &presentation,
            &registry,
            &issuer.public_key(),
            SCOPE,
            CONTEXT,
            100,
            &registry.cohort,
        ),
        Ok(())
    );
    assert_eq!(
        verify_presentation(
            &presentation,
            &registry,
            &issuer.public_key(),
            SCOPE,
            CONTEXT,
            10_000,
            &registry.cohort,
        ),
        Err(KybInvalid::Expired)
    );
    let stranger = KybIssuer::new(5, &mut OsRng);
    assert_eq!(
        verify_presentation(
            &presentation,
            &registry,
            &stranger.public_key(),
            SCOPE,
            CONTEXT,
            100,
            &registry.cohort,
        ),
        Err(KybInvalid::NotFromTrustedIssuer)
    );
}

#[test]
fn registry_tampering_is_detected() {
    let (issuer, _, mut registry) = venue();
    assert_eq!(
        verify_registry(&registry, &issuer.public_key(), 100),
        Ok(())
    );
    registry
        .points
        .push(RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut OsRng));
    assert_eq!(
        verify_registry(&registry, &issuer.public_key(), 100),
        Err(KybInvalid::RegistryIdMismatch)
    );
}

#[test]
fn cohort_gate_is_enforced_at_the_venue() {
    let (issuer, entities, registry) = venue();
    let presentation = present(&entities[0], &registry, SCOPE, CONTEXT, &mut OsRng).unwrap();
    assert_eq!(
        verify_presentation(
            &presentation,
            &registry,
            &issuer.public_key(),
            SCOPE,
            CONTEXT,
            100,
            &registry.cohort,
        ),
        Ok(())
    );
    assert_eq!(
        verify_presentation(
            &presentation,
            &registry,
            &issuer.public_key(),
            SCOPE,
            CONTEXT,
            100,
            &cohort_id("JP", "bank", 4),
        ),
        Err(KybInvalid::WrongCohort)
    );
}

#[test]
fn limits_bind_the_entity_not_the_wallet() {
    let (_, entities, _) = venue();
    let mut limiter = EntityRateLimiter::new(EntityLimits {
        max_requests: 3,
        max_probe_lots: 10_000,
        max_epsilon: 1.0,
    });
    let nullifiers = (0..4)
        .map(|_| entities[0].scope_nullifier(SCOPE))
        .collect::<Vec<_>>();
    assert!(nullifiers.windows(2).all(|pair| pair[0] == pair[1]));
    for nullifier in nullifiers.iter().take(3) {
        assert_eq!(limiter.allow_request(nullifier, 7, 0), Ok(()));
    }
    for nullifier in [&nullifiers[3], &nullifiers[0]] {
        assert_eq!(
            limiter.allow_request(nullifier, 7, 0),
            Err(Refused::RequestCap)
        );
    }
    assert_eq!(
        limiter.allow_request(&entities[2].scope_nullifier(SCOPE), 7, 0),
        Ok(())
    );
}

#[test]
fn probing_volume_and_privacy_budget_are_capped_per_entity() {
    let (_, entities, _) = venue();
    let mut limiter = EntityRateLimiter::new(EntityLimits {
        max_requests: 100,
        max_probe_lots: 100,
        max_epsilon: 0.5,
    });
    let nullifier = entities[0].scope_nullifier(SCOPE);
    assert_eq!(limiter.allow_request(&nullifier, 7, 60), Ok(()));
    assert_eq!(
        limiter.allow_request(&nullifier, 7, 60),
        Err(Refused::ProbeVolumeCap)
    );
    assert_eq!(limiter.spend_epsilon(&nullifier, 7, 0.4), Ok(()));
    assert_eq!(
        limiter.spend_epsilon(&nullifier, 7, 0.4),
        Err(Refused::PrivacyBudget)
    );
    assert_eq!(limiter.spend_epsilon(&nullifier, 8, 0.4), Ok(()));
}

#[test]
fn nullifier_separates_scopes_and_entities() {
    let (_, entities, _) = venue();
    let a7 = entities[0].scope_nullifier(SCOPE);
    let a8 = entities[0].scope_nullifier(b"qomm:quote:epoch8");
    let c7 = entities[2].scope_nullifier(SCOPE);
    assert_ne!(a7, a8);
    assert_ne!(a7, c7);
}

#[test]
fn a_prover_that_skips_its_own_range_check_is_still_rejected() {
    let key = Pedersen::new(b"qomm:policy:v1");
    let (low, high) = PolicyBounds::default().spread;
    let span = (high - low) as u64;
    let bits = (u64::BITS - span.leading_zeros()).max(1) as usize;
    let out_of_band = 900i64;
    let blinding = Scalar::random(&mut OsRng);
    let commitment = key.commit(&scalar(out_of_band), &blinding);

    let honest = prove_bounded(&key, 200, &blinding, low, high, b"ctx", &mut OsRng).unwrap();
    assert!(verify_bounded(
        &key, &honest.0, &honest.1, low, high, b"ctx"
    ));

    let window = 1u64 << bits;
    let above_claim = (out_of_band - low) as u64 % window;
    let above = prove_range(
        &key,
        &shift_commitment(&key, &commitment, low),
        above_claim,
        &blinding,
        bits,
        &suffixed_context(b"ctx", b"|above"),
        &mut OsRng,
    )
    .unwrap();
    let ceiling = key.commit(&scalar(high), &Scalar::ZERO);
    let below_claim = (high - out_of_band).rem_euclid(window as i64) as u64;
    let below = prove_range(
        &key,
        &(ceiling - commitment),
        below_claim,
        &(-blinding),
        bits,
        &suffixed_context(b"ctx", b"|below"),
        &mut OsRng,
    )
    .unwrap();
    let forged = BoundedProof { above, below, bits };
    assert!(!verify_bounded(
        &key,
        &commitment,
        &forged,
        low,
        high,
        b"ctx"
    ));
}

#[test]
fn range_proof_rejects_a_relabelled_width() {
    let key = Pedersen::new(b"qomm:policy:v1");
    let blinding = Scalar::random(&mut OsRng);
    let (commitment, proof, _) =
        prove_bounded(&key, 300, &blinding, 0, 1_023, b"ctx", &mut OsRng).unwrap();
    assert!(verify_bounded(&key, &commitment, &proof, 0, 1_023, b"ctx"));
    let mut relabelled = proof.clone();
    relabelled.bits = 8;
    assert!(!verify_bounded(
        &key,
        &commitment,
        &relabelled,
        0,
        1_023,
        b"ctx"
    ));
    assert!(!verify_bounded(&key, &commitment, &proof, 0, 255, b"ctx"));
}

#[test]
fn a_published_band_is_the_band_that_is_enforced() {
    let key = Pedersen::new(b"qomm:policy:v1");
    let (low, high) = PolicyBounds::default().spread;
    let span = (high - low) as u64;
    let bits = (u64::BITS - span.leading_zeros()).max(1) as usize;
    assert!((1u64 << bits) > span + 1);

    for value in [low, (low + high) / 2, high] {
        let (commitment, proof, _) = prove_bounded(
            &key,
            value,
            &Scalar::random(&mut OsRng),
            low,
            high,
            b"band",
            &mut OsRng,
        )
        .unwrap();
        assert!(verify_bounded(
            &key,
            &commitment,
            &proof,
            low,
            high,
            b"band"
        ));
    }
    for value in [high + 1, low + (1i64 << bits) - 1] {
        assert_eq!(
            prove_bounded(
                &key,
                value,
                &Scalar::random(&mut OsRng),
                low,
                high,
                b"band",
                &mut OsRng,
            )
            .unwrap_err(),
            "value outside the bounded interval"
        );
    }
}

#[test]
fn a_bounded_proof_cannot_mix_widths_across_its_two_halves() {
    let key = Pedersen::new(b"qomm:policy:v1");
    let (low, high, value) = (-4_000i64, 4_000i64, 320i64);
    let span_bits = 13usize;
    let blinding = Scalar::random(&mut OsRng);
    let commitment = key.commit(&scalar(value), &blinding);
    let above = prove_range(
        &key,
        &shift_commitment(&key, &commitment, low),
        (value - low) as u64,
        &blinding,
        span_bits,
        &suffixed_context(b"", b"|above"),
        &mut OsRng,
    )
    .unwrap();
    let ceiling = key.commit(&scalar(high), &Scalar::ZERO);
    let below = prove_range(
        &key,
        &(ceiling - commitment),
        (high - value) as u64,
        &(-blinding),
        span_bits + 1,
        &suffixed_context(b"", b"|below"),
        &mut OsRng,
    )
    .unwrap();
    let forged = BoundedProof {
        above,
        below,
        bits: span_bits,
    };
    assert!(!verify_bounded(&key, &commitment, &forged, low, high, b""));

    let (honest_commitment, honest, _) =
        prove_bounded(&key, value, &blinding, low, high, b"", &mut OsRng).unwrap();
    assert!(verify_bounded(
        &key,
        &honest_commitment,
        &honest,
        low,
        high,
        b""
    ));
}
