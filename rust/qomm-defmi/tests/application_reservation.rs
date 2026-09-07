#![cfg(feature = "avalanche")]

use curve25519_dalek::scalar::Scalar;
use dekyx_core::{
    AnonymousPresentation, CredentialIssuer, CredentialRequest, CredentialWitness, DeKyxVerifier,
    EligibilityRequirement, IssuerDefinition, IssuerRegistry, IssuerStatus, PresentationContext,
    Qualification, SubjectKind,
};
use ed25519_dalek::SigningKey;
use qomm_defmi::application_reservation::{
    ApplicationIdentityEvidence, ApplicationReserveMandate, ApplicationReserveScope,
    VerifiedApplicationNoteReservation,
};
use qomm_defmi::facility::{
    CreditFacilityRelationProof, CreditFacilityTransition, CreditTransitionKind, ZERO,
};
use qomm_defmi::notes::{NoteLedger, Wallet};
use qomm_zk::pedersen::Pedersen;
use rand_core::OsRng;
use std::collections::BTreeSet;

/// Real DeKYX issuance + holder proof + anonymous-note ownership + credit
/// proof. This is a private approval-boundary test, not live L1 evidence.
#[test]
fn dekyx_mandate_and_note_proofs_bind_without_a_circular_dependency() {
    let signing = SigningKey::from_bytes(&[1; 32]);
    let definition = IssuerDefinition {
        issuer_id: [2; 32],
        key_epoch: 1,
        public_key: signing.verifying_key().to_bytes(),
        pq_public_key: zkfmi_crypto::traits::Signer::public_key(
            &zkfmi_crypto::test_support::public_fixture_pq_key(
                &(signing.verifying_key().to_bytes()),
            ),
        ),
        signature_suite: zkfmi_crypto::suite::Suite::new(
            zkfmi_crypto::suite::SuiteId::Ed25519MlDsa65,
        ),
        supported_subjects: BTreeSet::from([SubjectKind::LegalEntity]),
        namespace_digest: [3; 32],
        valid_from: 1,
        valid_until: 1_000,
        status: IssuerStatus::Active,
    };
    let issuer = CredentialIssuer::new(
        definition.clone(),
        (signing).clone(),
        zkfmi_crypto::test_support::public_fixture_pq_key(&(signing).verifying_key().to_bytes()),
    )
    .unwrap();
    let qualification = Qualification {
        namespace: "defmi.application.participant".into(),
        predicate_digest: [4; 32],
    };
    let witness = CredentialWitness::random(vec![qualification.clone()], &mut OsRng).unwrap();
    let request = CredentialRequest {
        credential_id: [5; 32],
        issuer_id: definition.issuer_id,
        issuer_key_epoch: 1,
        subject_kind: SubjectKind::LegalEntity,
        subject_commitment: witness.subject_commitment(),
        holder_public_key: witness.holder_public_key(),
        holder_suite: witness.holder_suite(),
        scope_digest: [6; 32],
        policy_digest: [7; 32],
        qualifications: vec![qualification.clone()],
        status_epoch: 1,
        valid_from: 1,
        valid_until: 1_000,
    };
    let issuance = witness.prove_issuance(&request, &mut OsRng).unwrap();
    let credential = issuer.issue(request, issuance).unwrap();
    let status = issuer.issue_status_list(1, 1, 1_000, vec![]).unwrap();
    let mut registry = IssuerRegistry::default();
    registry.register(definition.clone()).unwrap();
    let verifier = DeKyxVerifier {
        issuers: &registry,
        status_list: &status,
    };
    let requirement = EligibilityRequirement {
        issuer_id: definition.issuer_id,
        issuer_key_epoch: 1,
        issuer_namespace_digest: definition.namespace_digest,
        subject_kind: SubjectKind::LegalEntity,
        scope_digest: [6; 32],
        policy_digest: [7; 32],
        required_qualifications: vec![qualification.clone()],
    };
    // A holder's existing enrollment presentation determines its facility
    // beneficiary. It is not reused as the reservation's action proof.
    let enrollment = AnonymousPresentation::create(
        credential.clone(),
        &witness,
        PresentationContext {
            scope_digest: [6; 32],
            audience_digest: [8; 32],
            action_digest: [9; 32],
            request_digest: [10; 32],
            challenge_nonce: [11; 32],
            valid_until: 900,
        },
        std::slice::from_ref(&qualification),
        &mut OsRng,
    )
    .unwrap();

    let key = Pedersen::new(b"qomm:defmi:v1");
    let commit = |amount, blinding| key.commit_u64(amount, &blinding).compress().to_bytes();
    let scope = ApplicationReserveScope {
        application_binding: [12; 32],
        venue_id: [13; 32],
        defmi_id: [14; 32],
        committee_key_digest: [15; 32],
        pq_committee_digest: [231; 32],
        committee_epoch: 1,
        amount_bits: 32,
    };
    let participant = zkfmi_crypto::hybrid::signature::HybridSigner::generate().unwrap();
    let reserve_blinding = Scalar::from(40_u64);
    let mandate = ApplicationReserveMandate {
        version: 2,
        scope: scope.clone(),
        request_commitment: [17; 32],
        facility_id: [18; 32],
        hold_id: [19; 32],
        asset_id: [20; 32],
        amount_commitment: commit(40, reserve_blinding),
        participant_handle: (key.g * Scalar::from(21_u64)).compress().to_bytes(),
        entity_commitment: enrollment.subject_line_id().unwrap(),
        credential_digest: credential.digest().unwrap(),
        settlement_terms_commitment: commit(1, Scalar::from(22_u64)),
        valid_from: 100,
        valid_until: 900,
        participant_public: zkfmi_crypto::traits::Signer::public_key(&participant),
        signature: vec![],
    }
    .sign(&participant)
    .unwrap();
    // The mandate is signed BEFORE its randomized DeKYX proof exists.
    mandate.verify(&scope, 100).unwrap();
    let mut classical_only = mandate.clone();
    classical_only.signature.truncate(64);
    assert!(classical_only.verify(&scope, 100).is_err());
    let mut missing_key = mandate.clone();
    missing_key.participant_public.truncate(32);
    assert!(missing_key.verify(&scope, 100).is_err());
    let mut bad_pq = mandate.clone();
    bad_pq.signature[64] ^= 1;
    assert!(bad_pq.verify(&scope, 100).is_err());
    let mut old_version = mandate.clone();
    old_version.version = 1;
    assert!(old_version.verify(&scope, 100).is_err());
    let mut wrong_purpose = mandate.clone();
    wrong_purpose.signature = zkfmi_crypto::traits::Signer::sign(
        &participant,
        zkfmi_crypto::key::KeyPurpose::Attestation,
        &mandate.unsigned().unwrap(),
    )
    .unwrap();
    assert!(wrong_purpose.verify(&scope, 100).is_err());
    let present = |mandate: &ApplicationReserveMandate| {
        AnonymousPresentation::create(
            credential.clone(),
            &witness,
            mandate.identity_context(requirement.scope_digest).unwrap(),
            std::slice::from_ref(&qualification),
            &mut OsRng,
        )
        .unwrap()
    };
    let presentation = present(&mandate);
    assert_ne!(
        presentation.digest().unwrap(),
        present(&mandate).digest().unwrap()
    );
    let cap_blinding = Scalar::from(100_u64);
    let mut transition = CreditFacilityTransition {
        operation_id: [23; 32],
        facility_id: mandate.facility_id,
        hold_id: mandate.hold_id,
        kind: CreditTransitionKind::Hold,
        query_commitment: mandate.request_commitment,
        amount_commitment: mandate.amount_commitment,
        consumed_commitment: ZERO,
        refund_commitment: ZERO,
        before_available_commitment: commit(100, cap_blinding),
        after_available_commitment: commit(60, cap_blinding - reserve_blinding),
        before_held_commitment: ZERO,
        after_held_commitment: mandate.amount_commitment,
        before_outstanding_commitment: ZERO,
        after_outstanding_commitment: ZERO,
        before_sequence: 0,
        expires_at: mandate.valid_until,
        settlement_digest: ZERO,
        relation_proof_digest: ZERO,
    };
    let relation = CreditFacilityRelationProof::prove(
        &mut transition,
        [60, 40, 0, 40],
        [
            cap_blinding - reserve_blinding,
            reserve_blinding,
            Scalar::ZERO,
            reserve_blinding,
        ],
        [0; 2],
        [Scalar::ZERO; 2],
        &mut OsRng,
    )
    .unwrap();
    let wallet = Wallet::new(&mut OsRng);
    let decoy = Wallet::new(&mut OsRng);
    let covenant = Wallet::new(&mut OsRng);
    let mut ledger = NoteLedger::new(key.clone(), 32);
    let input_blinding = Scalar::from(30_u64);
    let note = ledger
        .build_note(
            &wallet.address,
            100,
            key.commit_u64(100, &input_blinding),
            &input_blinding,
            &mut OsRng,
        )
        .expect("valid fixture note encryption");
    ledger.add(note);
    let note = ledger
        .build_note(
            &decoy.address,
            20,
            key.commit_u64(20, &input_blinding),
            &input_blinding,
            &mut OsRng,
        )
        .expect("valid fixture note encryption");
    ledger.add(note);
    let opening = ledger
        .scan(&wallet, &key)
        .into_iter()
        .find_map(|(index, opening)| (index == 0).then_some(opening))
        .unwrap();
    let spend = ledger
        .build_spend_constrained_with_blindings(
            &[0, 1],
            0,
            &opening,
            &key.g,
            &Scalar::ZERO,
            &[(covenant.address, 40), (wallet.address, 60)],
            &[reserve_blinding, Scalar::from(31_u64)],
            &[true; 2],
            &mandate.spend_context().unwrap(),
            &mut OsRng,
        )
        .unwrap();
    let verify = |candidate: &ApplicationReserveMandate,
                  evidence: &AnonymousPresentation,
                  verifier: &DeKyxVerifier<'_>,
                  ledger: &NoteLedger,
                  now| {
        VerifiedApplicationNoteReservation::verify(
            candidate.clone(),
            transition.clone(),
            &relation,
            &scope,
            &ApplicationIdentityEvidence {
                verifier,
                requirement: &requirement,
                presentation: evidence,
            },
            ledger,
            &[0, 1],
            &spend.proof,
            &spend.notes,
            &[ZERO; 2],
            &[mandate.hold_id, ZERO],
            now,
            &mut OsRng,
        )
    };
    let verified = verify(&mandate, &presentation, &verifier, &ledger, 100).unwrap();
    verified
        .reservation()
        .verify_public_proofs(&ledger, &[0, 1], &[ZERO; 2], &mut OsRng)
        .unwrap();
    assert!(verify(&mandate, &enrollment, &verifier, &ledger, 100).is_err());
    assert!(verify(&mandate, &presentation, &verifier, &ledger, 901).is_err());
    let mut forged = presentation.clone();
    forged.response_subject[0] ^= 1;
    assert!(verify(&mandate, &forged, &verifier, &ledger, 100).is_err());
    for mutation in 0..3 {
        let mut other = mandate.clone();
        match mutation {
            0 => other.credential_digest = [80; 32],
            1 => other.entity_commitment = [81; 32],
            2 => other.participant_handle = (key.g * Scalar::from(82_u64)).compress().to_bytes(),
            _ => unreachable!(),
        }
        other = other.sign(&participant).unwrap();
        // The changed mandate and new DeKYX presentation are both valid.
        // Identity binding or the unchanged ownership proof must still fail.
        assert!(verify(&other, &present(&other), &verifier, &ledger, 100).is_err());
    }
    let revoked = issuer
        .issue_status_list(2, 1, 1_000, vec![credential.digest().unwrap()])
        .unwrap();
    let revoked_verifier = DeKyxVerifier {
        issuers: &registry,
        status_list: &revoked,
    };
    assert!(verify(&mandate, &presentation, &revoked_verifier, &ledger, 100).is_err());
    let mut invalid_ledger = NoteLedger::new(Pedersen::detached(b"wrong-generator"), 32);
    invalid_ledger.notes = ledger.notes.clone();
    assert!(verify(&mandate, &presentation, &verifier, &invalid_ledger, 100).is_err());
    invalid_ledger = NoteLedger::new(key, 16);
    invalid_ledger.notes = ledger.notes.clone();
    assert!(verify(&mandate, &presentation, &verifier, &invalid_ledger, 100).is_err());
}
