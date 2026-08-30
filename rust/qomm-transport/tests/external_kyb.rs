use ed25519_dalek::{Signature, SigningKey};
use qomm_proofs::kyb::BusinessAttributes;
use qomm_transport::external_kyb::{
    read_external_kyb_bundle, read_external_kyb_trust_anchor, write_external_kyb_inputs,
    ExternalKybAssertion, ExternalKybBundle, ExternalKybTrustAnchor,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;

fn id(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn assertion(signing: &SigningKey) -> ExternalKybAssertion {
    ExternalKybAssertion {
        provider: "regulated-provider".into(),
        key_id: "key-2026".into(),
        audience: "qomm-venue".into(),
        subject_digest: id("legal-entity"),
        control_group_digest: id("economic-control-group"),
        source_credential_digest: id("source-credential"),
        attributes: BusinessAttributes {
            jurisdiction: "JP".into(),
            entity_type: "bank".into(),
            collateral_tier: 3,
        },
        assurance_level: 3,
        status_epoch: 7,
        issued_at: 100,
        expires_at: 200,
        nonce: id("nonce"),
        signature: Signature::from_bytes(&[0_u8; 64]),
    }
    .sign(signing)
    .unwrap()
}

fn anchor(signing: &SigningKey) -> ExternalKybTrustAnchor {
    ExternalKybTrustAnchor {
        provider: "regulated-provider".into(),
        key_id: "key-2026".into(),
        audience: "qomm-venue".into(),
        public_key: signing.verifying_key(),
        valid_from: 1,
        valid_until: 1_000,
        minimum_assurance_level: 3,
        maximum_assertion_lifetime: 300,
        clock_skew_seconds: 5,
        minimum_status_epoch: 7,
        revoked_credentials: BTreeSet::new(),
    }
}

#[test]
fn external_provider_assertion_maps_wallets_to_one_private_control_group() {
    let signing = SigningKey::from_bytes(&id("external-provider-key"));
    let anchor = anchor(&signing);
    let first = assertion(&signing);
    let mut second = first.clone();
    second.nonce = id("second-wallet-nonce");
    second.source_credential_digest = id("second-provider-presentation");
    second = second.sign(&signing).unwrap();
    let first_verified = anchor.verify(&first, 150).unwrap();
    let second_verified = anchor.verify(&second, 150).unwrap();
    assert_eq!(
        first_verified.control_group_id,
        second_verified.control_group_id
    );
    assert_ne!(
        first_verified.evidence_digest,
        second_verified.evidence_digest
    );
    assert_eq!(first_verified.attributes.collateral_tier, 3);
}

#[test]
fn provider_can_aggregate_distinct_legal_entities_into_one_control_group() {
    let signing = SigningKey::from_bytes(&id("external-provider-key"));
    let anchor = anchor(&signing);
    let parent = assertion(&signing);
    let mut subsidiary = parent.clone();
    subsidiary.subject_digest = id("subsidiary-legal-entity");
    subsidiary.source_credential_digest = id("subsidiary-source-credential");
    subsidiary.nonce = id("subsidiary-nonce");
    subsidiary = subsidiary.sign(&signing).unwrap();

    let parent = anchor.verify(&parent, 150).unwrap();
    let subsidiary = anchor.verify(&subsidiary, 150).unwrap();
    assert_ne!(
        parent.legal_entity_reference_digest,
        subsidiary.legal_entity_reference_digest
    );
    assert_eq!(parent.control_group_id, subsidiary.control_group_id);
}

#[test]
fn external_provider_checks_signature_audience_expiry_status_and_revocation() {
    let signing = SigningKey::from_bytes(&id("external-provider-key"));
    let anchor = anchor(&signing);
    let valid = assertion(&signing);

    let mut tampered = valid.clone();
    tampered.attributes.collateral_tier = 5;
    assert!(anchor
        .verify(&tampered, 150)
        .unwrap_err()
        .contains("signature"));

    let mut wrong_audience = valid.clone();
    wrong_audience.audience = "another-venue".into();
    wrong_audience = wrong_audience.sign(&signing).unwrap();
    assert!(anchor
        .verify(&wrong_audience, 150)
        .unwrap_err()
        .contains("audience"));
    assert!(anchor.verify(&valid, 206).unwrap_err().contains("valid"));

    let mut stale = valid.clone();
    stale.status_epoch = 6;
    stale = stale.sign(&signing).unwrap();
    assert!(anchor.verify(&stale, 150).unwrap_err().contains("stale"));

    let mut revoked_anchor = anchor;
    revoked_anchor
        .revoked_credentials
        .insert(valid.source_credential_digest);
    assert!(revoked_anchor
        .verify(&valid, 150)
        .unwrap_err()
        .contains("revoked"));
}

#[test]
fn external_provider_files_round_trip_without_a_private_key() {
    let signing = SigningKey::from_bytes(&id("external-provider-key"));
    let anchor = anchor(&signing);
    let bundle = ExternalKybBundle {
        provider: anchor.provider.clone(),
        audience: anchor.audience.clone(),
        assertions: BTreeMap::from([("maker-0".into(), assertion(&signing))]),
    };
    let directory = tempfile::tempdir().unwrap();
    let anchor_path = directory.path().join("trust-anchor.json");
    let bundle_path = directory.path().join("bundle.json");
    write_external_kyb_inputs(&anchor_path, &bundle_path, &anchor, &bundle).unwrap();
    let recovered_anchor = read_external_kyb_trust_anchor(&anchor_path).unwrap();
    let recovered_bundle = read_external_kyb_bundle(&bundle_path).unwrap();
    assert_eq!(recovered_anchor, anchor);
    assert_eq!(
        recovered_bundle.evidence_digest().unwrap(),
        bundle.evidence_digest().unwrap()
    );
    assert_eq!(
        anchor_path.metadata().unwrap().permissions().mode() & 0o077,
        0
    );
    let contents = std::fs::read_to_string(bundle_path).unwrap();
    assert!(!contents.contains("external-provider-key"));
    assert!(!contents.contains("legal-entity"));

    std::fs::set_permissions(&anchor_path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(read_external_kyb_trust_anchor(&anchor_path)
        .unwrap_err()
        .contains("writable"));
}
