//! Standalone external-KYB provider process used by the full acceptance run.
//!
//! It deliberately writes only a public trust anchor and signed, digest-only
//! assertions. The provider signing key never enters the QOMM process. A live
//! deployment replaces this executable with its regulated KYC/KYB connector
//! while retaining the same fail-closed ingestion boundary.

use ed25519_dalek::{Signature, SigningKey};
use qomm_proofs::kyb::BusinessAttributes;
use qomm_transport::external_kyb::{
    write_external_kyb_inputs, ExternalKybAssertion, ExternalKybBundle, ExternalKybTrustAnchor,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn required_path(arguments: &[String], name: &str) -> Result<PathBuf, String> {
    arguments
        .iter()
        .position(|argument| argument == name)
        .and_then(|position| arguments.get(position + 1))
        .map(PathBuf::from)
        .ok_or_else(|| format!("{name} is required"))
}

fn assertion(
    provider: &str,
    key_id: &str,
    audience: &str,
    subject: &str,
    now: u64,
    signing: &SigningKey,
) -> Result<ExternalKybAssertion, String> {
    let mut nonce = [0_u8; 32];
    OsRng.fill_bytes(&mut nonce);
    ExternalKybAssertion {
        provider: provider.into(),
        key_id: key_id.into(),
        audience: audience.into(),
        // The raw provider subject and legal-entity name are intentionally not
        // exported from this process.
        subject_digest: Sha256::digest(
            [
                b"QOMM:ACCEPTANCE:PROVIDER-SUBJECT:v1".as_slice(),
                subject.as_bytes(),
            ]
            .concat(),
        )
        .into(),
        // A real provider assigns this from its beneficial-ownership/control
        // graph. The acceptance population uses one entity per group, while
        // the transport tests also cover parent/subsidiary aggregation.
        control_group_digest: Sha256::digest(
            [
                b"QOMM:ACCEPTANCE:CONTROL-GROUP:v1".as_slice(),
                subject.as_bytes(),
            ]
            .concat(),
        )
        .into(),
        source_credential_digest: Sha256::digest(
            [
                b"QOMM:ACCEPTANCE:SOURCE-CREDENTIAL:v1".as_slice(),
                subject.as_bytes(),
            ]
            .concat(),
        )
        .into(),
        attributes: BusinessAttributes {
            jurisdiction: "JP".into(),
            entity_type: "bank".into(),
            collateral_tier: 3,
        },
        assurance_level: 3,
        status_epoch: 1,
        issued_at: now.saturating_sub(1).max(1),
        expires_at: now.saturating_add(3_600),
        nonce,
        signature: Signature::from_bytes(&[0_u8; 64]),
    }
    .sign(signing)
}

fn run(arguments: &[String]) -> Result<(), String> {
    let trust_anchor_path = required_path(arguments, "--trust-anchor-out")?;
    let bundle_path = required_path(arguments, "--bundle-out")?;
    let provider = "jp-regulated-kyb-provider";
    let key_id = "acceptance-2026-08";
    let audience = "qomm-seven-node";
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    let signing = SigningKey::generate(&mut OsRng);
    let anchor = ExternalKybTrustAnchor {
        provider: provider.into(),
        key_id: key_id.into(),
        audience: audience.into(),
        public_key: signing.verifying_key(),
        valid_from: now.saturating_sub(60).max(1),
        valid_until: now.saturating_add(86_400),
        minimum_assurance_level: 3,
        maximum_assertion_lifetime: 7_200,
        clock_skew_seconds: 30,
        minimum_status_epoch: 1,
        revoked_credentials: BTreeSet::new(),
    };
    let mut assertions = BTreeMap::new();
    for (label, subject) in [
        ("taker-sell", "provider-subject-taker-sell"),
        ("taker-shared-buy", "provider-subject-shared-buy"),
        ("taker-cover", "provider-subject-cover"),
        ("maker-0", "provider-subject-maker-0"),
        ("maker-1", "provider-subject-maker-1"),
        ("maker-2", "provider-subject-maker-2"),
        ("maker-3", "provider-subject-maker-3"),
    ] {
        assertions.insert(
            label.into(),
            assertion(provider, key_id, audience, subject, now, &signing)?,
        );
    }
    let bundle = ExternalKybBundle {
        provider: provider.into(),
        audience: audience.into(),
        assertions,
    };
    write_external_kyb_inputs(&trust_anchor_path, &bundle_path, &anchor, &bundle)?;
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "provider": provider,
            "key_id": key_id,
            "audience": audience,
            "assertions": bundle.assertions.len(),
            "evidence_digest": hex::encode(bundle.evidence_digest()?),
            "provider_private_key_exported": false,
        }))
        .map_err(|error| error.to_string())?
    );
    Ok(())
}

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if let Err(error) = run(&arguments) {
        eprintln!("external KYB provider failed: {error}");
        std::process::exit(1);
    }
}
