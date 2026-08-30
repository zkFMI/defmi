//! Verification boundary between an external KYC/KYB provider and QOMM's
//! anonymous legal-entity credential.
//!
//! The provider never learns an RFQ and the market never receives a company
//! name, LEI, wallet or provider subject.  A provider signs stable digests and
//! business attributes.  After verification, QOMM derives one venue-neutral
//! control-group identifier and issues the existing scope-nullified anonymous
//! credential.  Different wallets backed by the same provider subject thus
//! share one economic limit without disclosing that subject to MPC nodes.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use qomm_proofs::kyb::BusinessAttributes;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const ASSERTION_DOMAIN: &[u8] = b"QOMM:EXTERNAL-KYB:ASSERTION:v2";
const CONTROL_GROUP_DOMAIN: &[u8] = b"QOMM:EXTERNAL-KYB:CONTROL-GROUP:v2";
const EVIDENCE_DOMAIN: &[u8] = b"QOMM:EXTERNAL-KYB:EVIDENCE:v2";
const BUNDLE_VERSION: u8 = 2;
const MAX_FILE: u64 = 1 << 20;
const MAX_ASSERTIONS: usize = 4096;

fn digest(domain: &[u8], value: &Value) -> Result<[u8; 32], String> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(serde_json::to_vec(value).map_err(|error| error.to_string())?);
    Ok(hash.finalize().into())
}

fn valid_label(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/+-".contains(&byte))
}

fn nonzero(value: &[u8; 32], name: &str) -> Result<(), String> {
    if *value == [0; 32] {
        Err(format!("external KYB {name} cannot be zero"))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalKybTrustAnchor {
    pub provider: String,
    pub key_id: String,
    pub audience: String,
    pub public_key: VerifyingKey,
    pub valid_from: u64,
    pub valid_until: u64,
    pub minimum_assurance_level: u8,
    pub maximum_assertion_lifetime: u64,
    pub clock_skew_seconds: u64,
    pub minimum_status_epoch: u64,
    pub revoked_credentials: BTreeSet<[u8; 32]>,
}

impl ExternalKybTrustAnchor {
    pub fn validate(&self) -> Result<(), String> {
        if !valid_label(&self.provider, 128)
            || !valid_label(&self.key_id, 128)
            || !valid_label(&self.audience, 128)
            || self.valid_from == 0
            || self.valid_until <= self.valid_from
            || self.minimum_assurance_level == 0
            || self.maximum_assertion_lifetime == 0
            || self.maximum_assertion_lifetime > 31_536_000
            || self.clock_skew_seconds > 300
            || self.minimum_status_epoch == 0
            || self
                .revoked_credentials
                .iter()
                .any(|value| *value == [0; 32])
        {
            return Err("external KYB trust anchor is incomplete or unsafe".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalKybAssertion {
    pub provider: String,
    pub key_id: String,
    pub audience: String,
    /// A provider-stable reference to this legal entity. It is never sent to
    /// MPC parties in the clear.
    pub subject_digest: [u8; 32],
    /// The provider-assigned economic-control group. Parent and subsidiary
    /// entities may have different subject digests while sharing this value,
    /// which makes their probing and credit limits aggregate safely.
    pub control_group_digest: [u8; 32],
    pub source_credential_digest: [u8; 32],
    pub attributes: BusinessAttributes,
    pub assurance_level: u8,
    pub status_epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: [u8; 32],
    pub signature: Signature,
}

impl ExternalKybAssertion {
    fn body(&self) -> Result<Value, String> {
        if !valid_label(&self.provider, 128)
            || !valid_label(&self.key_id, 128)
            || !valid_label(&self.audience, 128)
            || !valid_label(&self.attributes.jurisdiction, 32)
            || !valid_label(&self.attributes.entity_type, 64)
            || self.attributes.collateral_tier == 0
            || self.assurance_level == 0
            || self.status_epoch == 0
            || self.issued_at == 0
            || self.expires_at <= self.issued_at
        {
            return Err("external KYB assertion has invalid fields".into());
        }
        nonzero(&self.subject_digest, "subject digest")?;
        nonzero(&self.control_group_digest, "control-group digest")?;
        nonzero(&self.source_credential_digest, "source credential digest")?;
        nonzero(&self.nonce, "nonce")?;
        Ok(json!({
            "provider": self.provider,
            "key_id": self.key_id,
            "audience": self.audience,
            "subject_digest": hex::encode(self.subject_digest),
            "control_group_digest": hex::encode(self.control_group_digest),
            "source_credential_digest": hex::encode(self.source_credential_digest),
            "attributes": {
                "jurisdiction": self.attributes.jurisdiction,
                "entity_type": self.attributes.entity_type,
                "collateral_tier": self.attributes.collateral_tier,
            },
            "assurance_level": self.assurance_level,
            "status_epoch": self.status_epoch,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": hex::encode(self.nonce),
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(ASSERTION_DOMAIN, &self.body()?)
    }

    pub fn sign(mut self, key: &SigningKey) -> Result<Self, String> {
        self.signature = key.sign(&self.statement()?);
        Ok(self)
    }

    pub fn evidence_digest(&self) -> Result<[u8; 32], String> {
        let mut hash = Sha256::new();
        hash.update(EVIDENCE_DOMAIN);
        hash.update(self.statement()?);
        hash.update(self.signature.to_bytes());
        Ok(hash.finalize().into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedExternalKyb {
    pub control_group_id: String,
    pub legal_entity_reference_digest: [u8; 32],
    pub attributes: BusinessAttributes,
    pub provider: String,
    pub source_credential_digest: [u8; 32],
    pub status_epoch: u64,
    pub evidence_digest: [u8; 32],
}

impl ExternalKybTrustAnchor {
    pub fn verify(
        &self,
        assertion: &ExternalKybAssertion,
        now: u64,
    ) -> Result<VerifiedExternalKyb, String> {
        self.validate()?;
        let statement = assertion.statement()?;
        if assertion.provider != self.provider
            || assertion.key_id != self.key_id
            || assertion.audience != self.audience
        {
            return Err("external KYB assertion has another provider, key or audience".into());
        }
        if assertion.issued_at < self.valid_from
            || assertion.expires_at > self.valid_until
            || assertion.expires_at.saturating_sub(assertion.issued_at)
                > self.maximum_assertion_lifetime
            || assertion.issued_at > now.saturating_add(self.clock_skew_seconds)
            || now > assertion.expires_at.saturating_add(self.clock_skew_seconds)
        {
            return Err("external KYB assertion is not currently valid".into());
        }
        if assertion.assurance_level < self.minimum_assurance_level
            || assertion.status_epoch < self.minimum_status_epoch
        {
            return Err("external KYB assertion has insufficient assurance or stale status".into());
        }
        if self
            .revoked_credentials
            .contains(&assertion.source_credential_digest)
        {
            return Err("external KYB credential is revoked".into());
        }
        self.public_key
            .verify(&statement, &assertion.signature)
            .map_err(|_| "external KYB provider signature is invalid".to_string())?;
        let mut group = Sha256::new();
        group.update(CONTROL_GROUP_DOMAIN);
        group.update((assertion.provider.len() as u32).to_be_bytes());
        group.update(assertion.provider.as_bytes());
        group.update(assertion.control_group_digest);
        let group_digest: [u8; 32] = group.finalize().into();
        Ok(VerifiedExternalKyb {
            control_group_id: hex::encode(group_digest),
            legal_entity_reference_digest: assertion.subject_digest,
            attributes: assertion.attributes.clone(),
            provider: assertion.provider.clone(),
            source_credential_digest: assertion.source_credential_digest,
            status_epoch: assertion.status_epoch,
            evidence_digest: assertion.evidence_digest()?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ExternalKybBundle {
    pub provider: String,
    pub audience: String,
    pub assertions: BTreeMap<String, ExternalKybAssertion>,
}

impl ExternalKybBundle {
    pub fn evidence_digest(&self) -> Result<[u8; 32], String> {
        if !valid_label(&self.provider, 128)
            || !valid_label(&self.audience, 128)
            || self.assertions.is_empty()
            || self.assertions.len() > MAX_ASSERTIONS
        {
            return Err("external KYB bundle is incomplete or too large".into());
        }
        let mut hash = Sha256::new();
        hash.update(b"QOMM:EXTERNAL-KYB:BUNDLE:v2");
        hash.update((self.provider.len() as u32).to_be_bytes());
        hash.update(self.provider.as_bytes());
        hash.update((self.audience.len() as u32).to_be_bytes());
        hash.update(self.audience.as_bytes());
        hash.update((self.assertions.len() as u32).to_be_bytes());
        for (label, assertion) in &self.assertions {
            if !valid_label(label, 128)
                || assertion.provider != self.provider
                || assertion.audience != self.audience
            {
                return Err("external KYB bundle has an invalid member".into());
            }
            hash.update((label.len() as u32).to_be_bytes());
            hash.update(label.as_bytes());
            hash.update(assertion.evidence_digest()?);
        }
        Ok(hash.finalize().into())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustAnchorWire {
    version: u8,
    provider: String,
    key_id: String,
    audience: String,
    public_key: String,
    valid_from: u64,
    valid_until: u64,
    minimum_assurance_level: u8,
    maximum_assertion_lifetime: u64,
    clock_skew_seconds: u64,
    minimum_status_epoch: u64,
    revoked_credentials: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AssertionWire {
    provider: String,
    key_id: String,
    audience: String,
    subject_digest: String,
    control_group_digest: String,
    source_credential_digest: String,
    attributes: BusinessAttributes,
    assurance_level: u8,
    status_epoch: u64,
    issued_at: u64,
    expires_at: u64,
    nonce: String,
    signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BundleWire {
    version: u8,
    provider: String,
    audience: String,
    assertions: BTreeMap<String, AssertionWire>,
}

fn parse32(value: &str, name: &str) -> Result<[u8; 32], String> {
    hex::decode(value)
        .map_err(|_| format!("external KYB {name} is not hexadecimal"))?
        .try_into()
        .map_err(|_| format!("external KYB {name} is not 32 bytes"))
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("external KYB input could not be opened safely: {error}"))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_FILE
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(
            "external KYB input must be a bounded regular file not writable by group or others"
                .into(),
        );
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > MAX_FILE {
        return Err("external KYB input changed while it was being read".into());
    }
    Ok(bytes)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let temp = PathBuf::from(format!("{}.{}.tmp", path.display(), rand::random::<u64>()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|error| error.to_string())?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| error.to_string())?;
        fs::rename(&temp, path).map_err(|error| error.to_string())?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

impl From<&ExternalKybTrustAnchor> for TrustAnchorWire {
    fn from(value: &ExternalKybTrustAnchor) -> Self {
        Self {
            version: BUNDLE_VERSION,
            provider: value.provider.clone(),
            key_id: value.key_id.clone(),
            audience: value.audience.clone(),
            public_key: hex::encode(value.public_key.to_bytes()),
            valid_from: value.valid_from,
            valid_until: value.valid_until,
            minimum_assurance_level: value.minimum_assurance_level,
            maximum_assertion_lifetime: value.maximum_assertion_lifetime,
            clock_skew_seconds: value.clock_skew_seconds,
            minimum_status_epoch: value.minimum_status_epoch,
            revoked_credentials: value.revoked_credentials.iter().map(hex::encode).collect(),
        }
    }
}

impl TryFrom<TrustAnchorWire> for ExternalKybTrustAnchor {
    type Error = String;

    fn try_from(value: TrustAnchorWire) -> Result<Self, Self::Error> {
        if value.version != BUNDLE_VERSION {
            return Err("unsupported external KYB trust-anchor version".into());
        }
        let public_key = VerifyingKey::from_bytes(&parse32(&value.public_key, "public key")?)
            .map_err(|_| "external KYB public key is malformed".to_string())?;
        let revoked_credentials = value
            .revoked_credentials
            .iter()
            .map(|item| parse32(item, "revoked credential"))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let anchor = Self {
            provider: value.provider,
            key_id: value.key_id,
            audience: value.audience,
            public_key,
            valid_from: value.valid_from,
            valid_until: value.valid_until,
            minimum_assurance_level: value.minimum_assurance_level,
            maximum_assertion_lifetime: value.maximum_assertion_lifetime,
            clock_skew_seconds: value.clock_skew_seconds,
            minimum_status_epoch: value.minimum_status_epoch,
            revoked_credentials,
        };
        anchor.validate()?;
        Ok(anchor)
    }
}

impl From<&ExternalKybAssertion> for AssertionWire {
    fn from(value: &ExternalKybAssertion) -> Self {
        Self {
            provider: value.provider.clone(),
            key_id: value.key_id.clone(),
            audience: value.audience.clone(),
            subject_digest: hex::encode(value.subject_digest),
            control_group_digest: hex::encode(value.control_group_digest),
            source_credential_digest: hex::encode(value.source_credential_digest),
            attributes: value.attributes.clone(),
            assurance_level: value.assurance_level,
            status_epoch: value.status_epoch,
            issued_at: value.issued_at,
            expires_at: value.expires_at,
            nonce: hex::encode(value.nonce),
            signature: hex::encode(value.signature.to_bytes()),
        }
    }
}

impl TryFrom<AssertionWire> for ExternalKybAssertion {
    type Error = String;

    fn try_from(value: AssertionWire) -> Result<Self, Self::Error> {
        let signature: [u8; 64] = hex::decode(value.signature)
            .map_err(|_| "external KYB signature is not hexadecimal".to_string())?
            .try_into()
            .map_err(|_| "external KYB signature is not 64 bytes".to_string())?;
        let assertion = Self {
            provider: value.provider,
            key_id: value.key_id,
            audience: value.audience,
            subject_digest: parse32(&value.subject_digest, "subject digest")?,
            control_group_digest: parse32(&value.control_group_digest, "control-group digest")?,
            source_credential_digest: parse32(
                &value.source_credential_digest,
                "source credential digest",
            )?,
            attributes: value.attributes,
            assurance_level: value.assurance_level,
            status_epoch: value.status_epoch,
            issued_at: value.issued_at,
            expires_at: value.expires_at,
            nonce: parse32(&value.nonce, "nonce")?,
            signature: Signature::from_bytes(&signature),
        };
        assertion.body()?;
        Ok(assertion)
    }
}

pub fn write_external_kyb_inputs(
    trust_anchor_path: &Path,
    bundle_path: &Path,
    trust_anchor: &ExternalKybTrustAnchor,
    bundle: &ExternalKybBundle,
) -> Result<(), String> {
    trust_anchor.validate()?;
    bundle.evidence_digest()?;
    let anchor = serde_json::to_vec_pretty(&TrustAnchorWire::from(trust_anchor))
        .map_err(|error| error.to_string())?;
    let wire = BundleWire {
        version: BUNDLE_VERSION,
        provider: bundle.provider.clone(),
        audience: bundle.audience.clone(),
        assertions: bundle
            .assertions
            .iter()
            .map(|(label, assertion)| (label.clone(), AssertionWire::from(assertion)))
            .collect(),
    };
    let encoded = serde_json::to_vec_pretty(&wire).map_err(|error| error.to_string())?;
    write_private(trust_anchor_path, &anchor)?;
    write_private(bundle_path, &encoded)
}

pub fn read_external_kyb_trust_anchor(path: &Path) -> Result<ExternalKybTrustAnchor, String> {
    let wire: TrustAnchorWire =
        serde_json::from_slice(&read_bounded(path)?).map_err(|error| error.to_string())?;
    wire.try_into()
}

pub fn read_external_kyb_bundle(path: &Path) -> Result<ExternalKybBundle, String> {
    let wire: BundleWire =
        serde_json::from_slice(&read_bounded(path)?).map_err(|error| error.to_string())?;
    if wire.version != BUNDLE_VERSION
        || wire.assertions.is_empty()
        || wire.assertions.len() > MAX_ASSERTIONS
    {
        return Err("unsupported or empty external KYB bundle".into());
    }
    let bundle = ExternalKybBundle {
        provider: wire.provider,
        audience: wire.audience,
        assertions: wire
            .assertions
            .into_iter()
            .map(|(label, assertion)| Ok((label, assertion.try_into()?)))
            .collect::<Result<BTreeMap<_, _>, String>>()?,
    };
    bundle.evidence_digest()?;
    Ok(bundle)
}
