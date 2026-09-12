//! Opt-in canonical binding for the code-based confidential-settlement trial.
//!
//! This module is intentionally excluded from the default VM build.  It owns
//! no balances and cannot issue assets.  Governance may register an immutable
//! four-handle research book whose initial commitment came from the native
//! private-book owners, upload one bounded proof through ordinary consensus
//! transactions, and advance only that book after the trial verifier accepts
//! the exact authoritative statement.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use defmi::facility::{QuorumApproval, QuorumAuthorizer};
use serde::{
    de::DeserializeOwned, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256, Sha512};
use zkfmi_cosnark_trial::integration::{
    verify_serialized, verify_serialized_query_agreement, SettlementStatement,
};
use zkfmi_crypto::mode::{DeploymentCryptoPolicy, PqcMode};

use crate::{
    block::MAX_TRANSACTION_BYTES,
    execution::{authorize, require_keys},
    state::State,
    transaction::TransactionEnvelope,
};

pub const DEPLOYMENT_MODE: &str = "pq-only-research";
pub const PROOF_PROTOCOL: &str = "cocode-defmi-private-dvp-research-v1";
pub const QUERY_AGREEMENT_PROOF_PROTOCOL: &str =
    "cocode-defmi-private-dvp-research-v2-hybrid-query-agreement";
pub const ACCOUNT_ORDER: [&str; 4] = ["asset-seller", "asset-buyer", "cash-buyer", "cash-seller"];
pub const PROOF_CHUNK_BYTES: usize = 512 * 1024;
pub const MAX_PROOF_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_PROOF_CHUNKS: usize = MAX_PROOF_BYTES / PROOF_CHUNK_BYTES;
const MAX_POLICIES: usize = 8;
const MAX_BOOKS: usize = 64;
const MAX_ACTIVE_UPLOADS: usize = 4;
const MAX_RECEIPTS: usize = 4096;

const POLICY_DOMAIN: &[u8] = b"QOMM:DEFMI:RESEARCH-COCODE:POLICY:v1";
const BOOK_DOMAIN: &[u8] = b"QOMM:DEFMI:RESEARCH-COCODE:BOOK:v1";
const BEGIN_DOMAIN: &[u8] = b"QOMM:DEFMI:RESEARCH-COCODE:BEGIN:v1";
const CHUNK_DOMAIN: &[u8] = b"QOMM:DEFMI:RESEARCH-COCODE:CHUNK:v1";
const COMMIT_DOMAIN: &[u8] = b"QOMM:DEFMI:RESEARCH-COCODE:COMMIT:v1";
const BOOK_KEY_DOMAIN: &[u8] = b"QOMM:DEFMI:RESEARCH-COCODE:BOOK-KEY:v1";
const STATE_DOMAIN: &[u8] = b"QOMM:DEFMI:RESEARCH-COCODE:STATE:v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentPolicy {
    pub deployment_id: String,
    pub deployment_mode: String,
    pub proof_protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_query_roster_sha512: Option<String>,
    pub parties: u16,
    pub max_corrupt: u16,
    pub max_proof_bytes: u64,
    pub proof_chunk_bytes: u32,
}

impl DeploymentPolicy {
    pub fn native_v1(deployment_id: impl Into<String>) -> Self {
        Self {
            deployment_id: deployment_id.into(),
            deployment_mode: DEPLOYMENT_MODE.into(),
            proof_protocol: PROOF_PROTOCOL.into(),
            trusted_query_roster_sha512: None,
            parties: 7,
            max_corrupt: 2,
            max_proof_bytes: MAX_PROOF_BYTES as u64,
            proof_chunk_bytes: PROOF_CHUNK_BYTES as u32,
        }
    }

    pub fn native_query_agreement(
        deployment_id: impl Into<String>,
        trusted_query_roster_sha512: impl Into<String>,
    ) -> Result<Self, String> {
        let mut policy = Self::native_v1(deployment_id);
        policy.proof_protocol = QUERY_AGREEMENT_PROOF_PROTOCOL.into();
        policy.trusted_query_roster_sha512 = Some(trusted_query_roster_sha512.into());
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_id(&self.deployment_id, "deployment ID")?;
        if self.deployment_mode != DEPLOYMENT_MODE
            || self.parties != 7
            || self.max_corrupt != 2
            || self.max_proof_bytes != MAX_PROOF_BYTES as u64
            || self.proof_chunk_bytes != PROOF_CHUNK_BYTES as u32
        {
            return Err("unsupported research CoCode deployment policy".into());
        }
        match (
            self.proof_protocol.as_str(),
            self.trusted_query_roster_sha512.as_deref(),
        ) {
            (PROOF_PROTOCOL, None) => {}
            (QUERY_AGREEMENT_PROOF_PROTOCOL, Some(pin)) => {
                validate_hex_128(pin, "trusted query roster digest")?;
            }
            _ => return Err("research proof protocol and trusted roster policy disagree".into()),
        }
        Ok(())
    }

    fn verify_proof(&self, proof: &[u8], expected: &SettlementStatement) -> Result<(), String> {
        self.validate()?;
        match self.trusted_query_roster_sha512.as_deref() {
            None => verify_serialized(proof, expected),
            Some(pin) => verify_serialized_query_agreement(proof, expected, pin),
        }
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        action_digest(POLICY_DOMAIN, self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountAssetHandle {
    pub account_handle: String,
    pub asset_handle: String,
}

impl AccountAssetHandle {
    pub fn new(account_handle: impl Into<String>, asset_handle: impl Into<String>) -> Self {
        Self {
            account_handle: account_handle.into(),
            asset_handle: asset_handle.into(),
        }
    }

    fn validate(&self) -> Result<(), String> {
        validate_id(&self.account_handle, "account handle")?;
        validate_id(&self.asset_handle, "asset handle")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResearchBookGenesis {
    pub deployment_id: String,
    pub book_id: String,
    /// Ordered as `ACCOUNT_ORDER`; these are opaque handles, not balance issuance.
    pub handles: [AccountAssetHandle; 4],
    pub initial_commitment: String,
}

impl ResearchBookGenesis {
    pub fn new(
        deployment_id: impl Into<String>,
        book_id: impl Into<String>,
        handles: [AccountAssetHandle; 4],
        initial_commitment: impl Into<String>,
    ) -> Self {
        Self {
            deployment_id: deployment_id.into(),
            book_id: book_id.into(),
            handles,
            initial_commitment: initial_commitment.into(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_id(&self.deployment_id, "deployment ID")?;
        validate_id(&self.book_id, "book ID")?;
        validate_hex_128(&self.initial_commitment, "initial book commitment")?;
        let mut accounts = BTreeSet::new();
        for handle in &self.handles {
            handle.validate()?;
            if !accounts.insert(&handle.account_handle) {
                return Err("research book repeats an account handle".into());
            }
        }
        let traded_asset = &self.handles[0].asset_handle;
        let cash_asset = &self.handles[2].asset_handle;
        if traded_asset != &self.handles[1].asset_handle
            || cash_asset != &self.handles[3].asset_handle
            || traded_asset == cash_asset
        {
            return Err(
                "research book must pair one traded asset and one distinct cash asset in ACCOUNT_ORDER"
                    .into(),
            );
        }
        Ok(())
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        action_digest(BOOK_DOMAIN, self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProofManifest {
    pub deployment_mode: String,
    pub statement: SettlementStatement,
    pub proof_len: u64,
    pub proof_sha512: String,
    pub chunk_bytes: u32,
    pub chunk_count: u32,
}

impl ProofManifest {
    pub fn from_proof(statement: SettlementStatement, proof: &[u8]) -> Result<Self, String> {
        let proof_len = u64::try_from(proof.len())
            .map_err(|_| "research proof length exceeds u64".to_string())?;
        let chunk_count = proof.len().div_ceil(PROOF_CHUNK_BYTES);
        let value = Self {
            deployment_mode: DEPLOYMENT_MODE.into(),
            statement,
            proof_len,
            proof_sha512: sha512_hex(proof),
            chunk_bytes: PROOF_CHUNK_BYTES as u32,
            chunk_count: u32::try_from(chunk_count)
                .map_err(|_| "research proof has too many chunks".to_string())?,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.statement.validate()?;
        if self.deployment_mode != DEPLOYMENT_MODE {
            return Err("research proof deployment mode does not match policy".into());
        }
        validate_hex_128(&self.proof_sha512, "proof digest")?;
        let proof_len = usize::try_from(self.proof_len)
            .map_err(|_| "research proof length exceeds this platform".to_string())?;
        if proof_len == 0 || proof_len > MAX_PROOF_BYTES {
            return Err("research proof size is outside 1..=256 MiB".into());
        }
        if self.chunk_bytes != PROOF_CHUNK_BYTES as u32
            || usize::try_from(self.chunk_count).ok() != Some(proof_len.div_ceil(PROOF_CHUNK_BYTES))
            || self.chunk_count == 0
            || self.chunk_count as usize > MAX_PROOF_CHUNKS
        {
            return Err("research proof chunk plan is not canonical".into());
        }
        Ok(())
    }

    pub fn statement_digest(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        action_digest(BEGIN_DOMAIN, self)
    }

    fn expected_chunk_len(&self, index: u32) -> Result<usize, String> {
        self.validate()?;
        if index >= self.chunk_count {
            return Err("research proof chunk index exceeds the manifest".into());
        }
        let offset = usize::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(PROOF_CHUNK_BYTES))
            .ok_or_else(|| "research proof chunk offset overflow".to_string())?;
        Ok(
            (usize::try_from(self.proof_len).expect("validated proof length") - offset)
                .min(PROOF_CHUNK_BYTES),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProofChunkUpload {
    pub deployment_id: String,
    pub book_id: String,
    pub operation_id: String,
    pub proof_sha512: String,
    pub index: u32,
    pub chunk_sha512: String,
    pub data: String,
}

impl ProofChunkUpload {
    pub fn from_proof(manifest: &ProofManifest, proof: &[u8], index: u32) -> Result<Self, String> {
        manifest.validate()?;
        if proof.len() as u64 != manifest.proof_len || sha512_hex(proof) != manifest.proof_sha512 {
            return Err("proof bytes do not match the canonical manifest".into());
        }
        let expected_len = manifest.expected_chunk_len(index)?;
        let offset = index as usize * PROOF_CHUNK_BYTES;
        let chunk = &proof[offset..offset + expected_len];
        Ok(Self {
            deployment_id: manifest.statement.deployment_id.clone(),
            book_id: manifest.statement.book_id.clone(),
            operation_id: manifest.statement.operation_id.clone(),
            proof_sha512: manifest.proof_sha512.clone(),
            index,
            chunk_sha512: sha512_hex(chunk),
            data: BASE64.encode(chunk),
        })
    }

    pub fn decoded(&self) -> Result<Vec<u8>, String> {
        validate_id(&self.deployment_id, "deployment ID")?;
        validate_id(&self.book_id, "book ID")?;
        validate_id(&self.operation_id, "operation ID")?;
        validate_hex_128(&self.proof_sha512, "proof digest")?;
        validate_hex_128(&self.chunk_sha512, "proof chunk digest")?;
        let bytes = BASE64
            .decode(&self.data)
            .map_err(|_| "research proof chunk is not base64".to_string())?;
        if bytes.is_empty()
            || bytes.len() > PROOF_CHUNK_BYTES
            || BASE64.encode(&bytes) != self.data
            || sha512_hex(&bytes) != self.chunk_sha512
        {
            return Err("research proof chunk encoding or digest is invalid".into());
        }
        Ok(bytes)
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        let bytes = self.decoded()?;
        let body = ProofChunkBody {
            deployment_id: &self.deployment_id,
            book_id: &self.book_id,
            operation_id: &self.operation_id,
            proof_sha512: &self.proof_sha512,
            index: self.index,
            chunk_sha512: &self.chunk_sha512,
            chunk_len: bytes.len() as u32,
        };
        action_digest(CHUNK_DOMAIN, &body)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofChunkBody<'a> {
    deployment_id: &'a str,
    book_id: &'a str,
    operation_id: &'a str,
    proof_sha512: &'a str,
    index: u32,
    chunk_sha512: &'a str,
    chunk_len: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitRequest {
    pub statement: SettlementStatement,
    pub proof_sha512: String,
}

impl CommitRequest {
    pub fn from_manifest(manifest: &ProofManifest) -> Self {
        Self {
            statement: manifest.statement.clone(),
            proof_sha512: manifest.proof_sha512.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        self.statement.validate()?;
        validate_hex_128(&self.proof_sha512, "proof digest")
    }

    pub fn statement_digest(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        action_digest(COMMIT_DOMAIN, self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResearchBookRecord {
    pub genesis: ResearchBookGenesis,
    pub commitment: String,
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_proof_sha512: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementReceipt {
    pub deployment_id: String,
    pub book_id: String,
    pub operation_id: String,
    pub sequence: u64,
    pub before_commitment: String,
    pub after_commitment: String,
    pub no_fill: bool,
    pub proof_sha512: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredProofChunk {
    bytes: Arc<[u8]>,
    sha512: String,
}

/// Typed view used only by the persistence transport. A reference is never a
/// usable live-state placeholder: `StoredProofChunk` itself continues to
/// require the exact bytes and digest during every State validation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PersistedProofChunk<'a> {
    pub(crate) operation_id: &'a str,
    pub(crate) index: usize,
    pub(crate) sha512: &'a str,
    pub(crate) bytes: &'a [u8],
}

impl StoredProofChunk {
    fn new(bytes: Vec<u8>, expected: &str) -> Result<Self, String> {
        validate_hex_128(expected, "proof chunk digest")?;
        if bytes.is_empty() || bytes.len() > PROOF_CHUNK_BYTES || sha512_hex(&bytes) != expected {
            return Err("stored research proof chunk is invalid".into());
        }
        Ok(Self {
            bytes: Arc::from(bytes),
            sha512: expected.into(),
        })
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl Serialize for StoredProofChunk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("StoredProofChunk", 2)?;
        value.serialize_field("sha512", &self.sha512)?;
        value.serialize_field("data", &BASE64.encode(&self.bytes))?;
        value.end()
    }
}

impl<'de> Deserialize<'de> for StoredProofChunk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            sha512: String,
            data: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        let bytes = BASE64
            .decode(&wire.data)
            .map_err(serde::de::Error::custom)?;
        if BASE64.encode(&bytes) != wire.data {
            return Err(serde::de::Error::custom(
                "stored proof chunk base64 is not canonical",
            ));
        }
        StoredProofChunk::new(bytes, &wire.sha512).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofUploadRecord {
    manifest: ProofManifest,
    chunks: Vec<StoredProofChunk>,
}

impl ProofUploadRecord {
    fn validate(&self) -> Result<(), String> {
        self.manifest.validate()?;
        if self.chunks.len() > self.manifest.chunk_count as usize {
            return Err("research proof upload has too many chunks".into());
        }
        let mut total = 0usize;
        for (index, chunk) in self.chunks.iter().enumerate() {
            if chunk.len() != self.manifest.expected_chunk_len(index as u32)? {
                return Err("research proof upload has a noncanonical chunk length".into());
            }
            total = total
                .checked_add(chunk.len())
                .ok_or_else(|| "research proof upload length overflow".to_string())?;
        }
        if total > self.manifest.proof_len as usize
            || (self.chunks.len() == self.manifest.chunk_count as usize
                && total != self.manifest.proof_len as usize)
        {
            return Err("research proof upload length disagrees with its manifest".into());
        }
        Ok(())
    }

    fn assemble(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        if self.chunks.len() != self.manifest.chunk_count as usize {
            return Err("research proof upload is incomplete".into());
        }
        let mut proof = Vec::with_capacity(self.manifest.proof_len as usize);
        for chunk in &self.chunks {
            proof.extend_from_slice(&chunk.bytes);
        }
        if proof.len() as u64 != self.manifest.proof_len
            || sha512_hex(&proof) != self.manifest.proof_sha512
        {
            return Err("assembled research proof differs from its manifest".into());
        }
        Ok(proof)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResearchCoCodeState {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    policies: BTreeMap<String, DeploymentPolicy>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    books: BTreeMap<String, ResearchBookRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    uploads: BTreeMap<String, ProofUploadRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    receipts: BTreeMap<String, SettlementReceipt>,
}

impl ResearchCoCodeState {
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
            && self.books.is_empty()
            && self.uploads.is_empty()
            && self.receipts.is_empty()
    }

    pub fn policy(&self, deployment_id: &str) -> Option<&DeploymentPolicy> {
        self.policies.get(deployment_id)
    }

    pub fn book(&self, deployment_id: &str, book_id: &str) -> Option<&ResearchBookRecord> {
        self.books.get(&book_key(deployment_id, book_id))
    }

    pub fn receipt(&self, operation_id: &str) -> Option<&SettlementReceipt> {
        self.receipts.get(operation_id)
    }

    pub fn uploaded_chunks(&self, operation_id: &str) -> Option<usize> {
        self.uploads
            .get(operation_id)
            .map(|upload| upload.chunks.len())
    }

    pub(crate) fn persisted_proof_chunks(&self) -> Vec<PersistedProofChunk<'_>> {
        self.uploads
            .iter()
            .flat_map(|(operation_id, upload)| {
                upload
                    .chunks
                    .iter()
                    .enumerate()
                    .map(move |(index, chunk)| PersistedProofChunk {
                        operation_id,
                        index,
                        sha512: &chunk.sha512,
                        bytes: &chunk.bytes,
                    })
            })
            .collect()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.policies.len() > MAX_POLICIES
            || self.books.len() > MAX_BOOKS
            || self.uploads.len() > MAX_ACTIVE_UPLOADS
            || self.receipts.len() > MAX_RECEIPTS
        {
            return Err("research CoCode state exceeds its configured bounds".into());
        }
        for (key, policy) in &self.policies {
            policy.validate()?;
            if key != &policy.deployment_id {
                return Err("research policy is stored under the wrong deployment".into());
            }
        }
        for (key, book) in &self.books {
            book.genesis.validate()?;
            validate_hex_128(&book.commitment, "authoritative book commitment")?;
            if key != &book_key(&book.genesis.deployment_id, &book.genesis.book_id)
                || !self.policies.contains_key(&book.genesis.deployment_id)
                || (book.sequence == 0 && book.commitment != book.genesis.initial_commitment)
                || (book.sequence == 0
                    && (book.last_operation_id.is_some() || book.last_proof_sha512.is_some()))
                || (book.sequence > 0
                    && (book.last_operation_id.is_none() || book.last_proof_sha512.is_none()))
            {
                return Err("research book record is malformed or orphaned".into());
            }
            if let Some(operation_id) = &book.last_operation_id {
                validate_id(operation_id, "last operation ID")?;
            }
            if let Some(digest) = &book.last_proof_sha512 {
                validate_hex_128(digest, "last proof digest")?;
            }
        }
        let mut uploading_books = BTreeSet::new();
        let mut reserved_proof_bytes = 0usize;
        for (operation_id, upload) in &self.uploads {
            upload.validate()?;
            reserved_proof_bytes = reserved_proof_bytes
                .checked_add(
                    usize::try_from(upload.manifest.proof_len)
                        .map_err(|_| "research proof reservation exceeds this platform")?,
                )
                .ok_or_else(|| "research proof reservation total overflow".to_string())?;
            if reserved_proof_bytes > MAX_PROOF_BYTES {
                return Err(
                    "active research proof reservations exceed the global 256 MiB budget".into(),
                );
            }
            let statement = &upload.manifest.statement;
            if operation_id != &statement.operation_id
                || self.receipts.contains_key(operation_id)
                || !uploading_books.insert(book_key(&statement.deployment_id, &statement.book_id))
            {
                return Err(
                    "research proof upload is duplicated or stored under the wrong key".into(),
                );
            }
            let expected = self.authoritative_statement(&upload.manifest)?;
            if statement != &expected {
                return Err("research proof upload is stale relative to its book".into());
            }
        }
        for (operation_id, receipt) in &self.receipts {
            validate_receipt(receipt)?;
            if operation_id != &receipt.operation_id
                || self
                    .book(&receipt.deployment_id, &receipt.book_id)
                    .is_none_or(|book| book.sequence < receipt.sequence)
            {
                return Err("research settlement receipt is malformed or orphaned".into());
            }
        }
        Ok(())
    }

    pub(crate) fn validate_for_deployment_crypto(
        &self,
        deployment_crypto_policy: &DeploymentCryptoPolicy,
    ) -> Result<(), String> {
        deployment_crypto_policy
            .validate()
            .map_err(|error| error.to_string())?;
        if self
            .policies
            .values()
            .any(|policy| policy.deployment_id != deployment_crypto_policy.deployment_id)
            || self
                .books
                .values()
                .any(|book| book.genesis.deployment_id != deployment_crypto_policy.deployment_id)
            || self.uploads.values().any(|upload| {
                upload.manifest.statement.deployment_id != deployment_crypto_policy.deployment_id
            })
            || self
                .receipts
                .values()
                .any(|receipt| receipt.deployment_id != deployment_crypto_policy.deployment_id)
        {
            return Err(
                "research CoCode deployment differs from the fresh genesis crypto policy".into(),
            );
        }
        if deployment_crypto_policy.mode == PqcMode::On {
            for policy in self.policies.values() {
                let pin = policy
                    .trusted_query_roster_sha512
                    .as_deref()
                    .ok_or_else(|| {
                        "PQC-on research CoCode requires a pinned query-agreement-v2 roster"
                            .to_string()
                    })?;
                let expected = DeploymentPolicy::native_query_agreement(
                    deployment_crypto_policy.deployment_id.clone(),
                    pin,
                )?;
                if policy != &expected {
                    return Err(
                        "PQC-on research CoCode rejects legacy proof policy entry points".into(),
                    );
                }
            }
        }
        Ok(())
    }

    pub(crate) fn root_digest(&self) -> [u8; 32] {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct UploadView<'a> {
            manifest: &'a ProofManifest,
            chunks: Vec<(&'a str, usize)>,
        }
        let uploads = self
            .uploads
            .iter()
            .map(|(id, upload)| {
                (
                    id,
                    UploadView {
                        manifest: &upload.manifest,
                        chunks: upload
                            .chunks
                            .iter()
                            .map(|chunk| (chunk.sha512.as_str(), chunk.len()))
                            .collect(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let value = json!({
            "policies": self.policies,
            "books": self.books,
            "uploads": uploads,
            "receipts": self.receipts,
        });
        action_digest(STATE_DOMAIN, &value).expect("validated research state serializes")
    }

    fn authoritative_statement(
        &self,
        manifest: &ProofManifest,
    ) -> Result<SettlementStatement, String> {
        let supplied = &manifest.statement;
        let policy = self
            .policy(&supplied.deployment_id)
            .ok_or_else(|| "research proof names an unregistered deployment".to_string())?;
        if policy.deployment_mode != manifest.deployment_mode {
            return Err("research proof mixes deployment modes".into());
        }
        let book = self
            .book(&supplied.deployment_id, &supplied.book_id)
            .ok_or_else(|| "research proof names an unregistered book".to_string())?;
        let sequence = book
            .sequence
            .checked_add(1)
            .ok_or_else(|| "research book sequence overflow".to_string())?;
        Ok(SettlementStatement {
            deployment_id: policy.deployment_id.clone(),
            book_id: book.genesis.book_id.clone(),
            operation_id: supplied.operation_id.clone(),
            sequence,
            before_commitment: book.commitment.clone(),
            after_commitment: supplied.after_commitment.clone(),
            no_fill: supplied.no_fill,
        })
    }

    fn insert_policy(&mut self, policy: DeploymentPolicy) -> Result<(), String> {
        policy.validate()?;
        if self.policies.len() >= MAX_POLICIES || self.policies.contains_key(&policy.deployment_id)
        {
            return Err(
                "research deployment policy is already registered or capacity is full".into(),
            );
        }
        self.policies.insert(policy.deployment_id.clone(), policy);
        Ok(())
    }

    fn insert_book(&mut self, genesis: ResearchBookGenesis) -> Result<(), String> {
        genesis.validate()?;
        if !self.policies.contains_key(&genesis.deployment_id) {
            return Err("research book deployment policy is not registered".into());
        }
        let key = book_key(&genesis.deployment_id, &genesis.book_id);
        if self.books.len() >= MAX_BOOKS || self.books.contains_key(&key) {
            return Err("research book is already registered or capacity is full".into());
        }
        self.books.insert(
            key,
            ResearchBookRecord {
                commitment: genesis.initial_commitment.clone(),
                sequence: 0,
                last_operation_id: None,
                last_proof_sha512: None,
                genesis,
            },
        );
        Ok(())
    }

    fn begin(&mut self, manifest: ProofManifest) -> Result<(), String> {
        manifest.validate()?;
        let reserved_proof_bytes = self.uploads.values().try_fold(
            usize::try_from(manifest.proof_len)
                .map_err(|_| "research proof reservation exceeds this platform")?,
            |reserved, upload| {
                reserved
                    .checked_add(
                        usize::try_from(upload.manifest.proof_len)
                            .map_err(|_| "research proof reservation exceeds this platform")?,
                    )
                    .ok_or_else(|| "research proof reservation total overflow".to_string())
            },
        )?;
        if reserved_proof_bytes > MAX_PROOF_BYTES {
            return Err(
                "active research proof reservations exceed the global 256 MiB budget".into(),
            );
        }
        let operation_id = manifest.statement.operation_id.clone();
        let key = book_key(
            &manifest.statement.deployment_id,
            &manifest.statement.book_id,
        );
        if self.uploads.len() >= MAX_ACTIVE_UPLOADS
            || self.uploads.contains_key(&operation_id)
            || self.receipts.contains_key(&operation_id)
            || self.uploads.values().any(|upload| {
                book_key(
                    &upload.manifest.statement.deployment_id,
                    &upload.manifest.statement.book_id,
                ) == key
            })
        {
            return Err(
                "research proof operation is replayed or its book is already uploading".into(),
            );
        }
        if manifest.statement != self.authoritative_statement(&manifest)? {
            return Err("research proof statement is stale or not authoritative".into());
        }
        self.uploads.insert(
            operation_id,
            ProofUploadRecord {
                manifest,
                chunks: Vec::new(),
            },
        );
        Ok(())
    }

    fn append(&mut self, chunk: ProofChunkUpload) -> Result<(), String> {
        let bytes = chunk.decoded()?;
        let upload = self
            .uploads
            .get_mut(&chunk.operation_id)
            .ok_or_else(|| "research proof upload is not active".to_string())?;
        let statement = &upload.manifest.statement;
        if chunk.deployment_id != statement.deployment_id
            || chunk.book_id != statement.book_id
            || chunk.proof_sha512 != upload.manifest.proof_sha512
            || chunk.index as usize != upload.chunks.len()
            || bytes.len() != upload.manifest.expected_chunk_len(chunk.index)?
        {
            return Err(
                "research proof chunk is out of order or belongs to another manifest".into(),
            );
        }
        upload
            .chunks
            .push(StoredProofChunk::new(bytes, &chunk.chunk_sha512)?);
        Ok(())
    }

    fn verify_and_commit(&mut self, request: &CommitRequest) -> Result<SettlementReceipt, String> {
        request.validate()?;
        if self.receipts.contains_key(&request.statement.operation_id) {
            return Err("research settlement operation was already committed".into());
        }
        let upload = self
            .uploads
            .get(&request.statement.operation_id)
            .ok_or_else(|| "research proof upload is not active".to_string())?;
        let expected = self.authoritative_statement(&upload.manifest)?;
        if request.statement != expected
            || upload.manifest.statement != expected
            || request.proof_sha512 != upload.manifest.proof_sha512
        {
            return Err("research commit differs from its authoritative proof manifest".into());
        }
        let proof = upload.assemble()?;
        // This is the actual trial verifier.  The expected statement is rebuilt
        // from the canonical policy/book and the governance-approved transition;
        // no statement is extracted from or trusted to the proof.
        self.policies
            .get(&expected.deployment_id)
            .ok_or_else(|| "research deployment policy disappeared".to_string())?
            .verify_proof(&proof, &expected)
            .map_err(|error| format!("research CoCode proof verification failed: {error}"))?;
        if self.receipts.len() >= MAX_RECEIPTS {
            return Err("research settlement receipt capacity is full".into());
        }
        let receipt = SettlementReceipt {
            deployment_id: expected.deployment_id.clone(),
            book_id: expected.book_id.clone(),
            operation_id: expected.operation_id.clone(),
            sequence: expected.sequence,
            before_commitment: expected.before_commitment.clone(),
            after_commitment: expected.after_commitment.clone(),
            no_fill: expected.no_fill,
            proof_sha512: request.proof_sha512.clone(),
        };
        let book = self
            .books
            .get_mut(&book_key(&expected.deployment_id, &expected.book_id))
            .expect("authoritative statement required the book");
        book.commitment = expected.after_commitment;
        book.sequence = expected.sequence;
        book.last_operation_id = Some(expected.operation_id.clone());
        book.last_proof_sha512 = Some(request.proof_sha512.clone());
        self.uploads.remove(&expected.operation_id);
        self.receipts.insert(expected.operation_id, receipt.clone());
        Ok(receipt)
    }
}

#[cfg(test)]
impl ResearchCoCodeState {
    pub(crate) fn persistence_fixture(proof: &[u8]) -> Self {
        const DEPLOYMENT: &str = "persistence-fixture-deployment";
        const BOOK: &str = "persistence-fixture-book";
        const OPERATION: &str = "persistence-fixture-operation";
        let initial_commitment = "11".repeat(64);
        let mut state = Self::default();
        state
            .insert_policy(DeploymentPolicy::native_v1(DEPLOYMENT))
            .expect("fixture policy");
        state
            .insert_book(ResearchBookGenesis::new(
                DEPLOYMENT,
                BOOK,
                [
                    AccountAssetHandle::new("asset-seller-account", "traded-asset"),
                    AccountAssetHandle::new("asset-buyer-account", "traded-asset"),
                    AccountAssetHandle::new("cash-buyer-account", "cash-asset"),
                    AccountAssetHandle::new("cash-seller-account", "cash-asset"),
                ],
                initial_commitment.clone(),
            ))
            .expect("fixture book");
        let manifest = ProofManifest::from_proof(
            SettlementStatement {
                deployment_id: DEPLOYMENT.into(),
                book_id: BOOK.into(),
                operation_id: OPERATION.into(),
                sequence: 1,
                before_commitment: initial_commitment,
                after_commitment: "22".repeat(64),
                no_fill: false,
            },
            proof,
        )
        .expect("fixture manifest");
        state.begin(manifest.clone()).expect("fixture begin");
        for index in 0..manifest.chunk_count {
            state
                .append(
                    ProofChunkUpload::from_proof(&manifest, proof, index)
                        .expect("fixture proof chunk"),
                )
                .expect("fixture append");
        }
        state.validate().expect("fixture state");
        state
    }
}

pub(crate) fn register_policy(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
) -> Result<[u8; 32], String> {
    require_keys(params, &["policy", "approval", "expectedBeforeRoot"])?;
    let policy: DeploymentPolicy = field(params, "policy")?;
    ensure_policy_matches_fresh_deployment(state, &policy)?;
    let statement = policy.statement()?;
    authorize(state, params, statement, authorizer)?;
    state.research_cocode.insert_policy(policy)?;
    Ok(statement)
}

fn ensure_policy_matches_fresh_deployment(
    state: &State,
    policy: &DeploymentPolicy,
) -> Result<(), String> {
    let Some(deployment_crypto_policy) = &state.deployment_crypto_policy else {
        return Ok(());
    };
    if policy.deployment_id != deployment_crypto_policy.deployment_id {
        return Err("research policy deployment differs from fresh genesis".into());
    }
    if deployment_crypto_policy.mode == PqcMode::On {
        let pin = policy
            .trusted_query_roster_sha512
            .as_deref()
            .ok_or_else(|| {
                "PQC-on research policy requires a pinned query-agreement-v2 roster".to_string()
            })?;
        if policy
            != &DeploymentPolicy::native_query_agreement(
                deployment_crypto_policy.deployment_id.clone(),
                pin,
            )?
        {
            return Err("PQC-on research policy rejects the legacy proof protocol".into());
        }
    }
    Ok(())
}

pub(crate) fn register_book(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
) -> Result<[u8; 32], String> {
    require_keys(params, &["book", "approval", "expectedBeforeRoot"])?;
    let book: ResearchBookGenesis = field(params, "book")?;
    let statement = book.statement()?;
    authorize(state, params, statement, authorizer)?;
    state.research_cocode.insert_book(book)?;
    Ok(statement)
}

pub(crate) fn begin_proof(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
) -> Result<[u8; 32], String> {
    require_keys(params, &["manifest", "approval", "expectedBeforeRoot"])?;
    let manifest: ProofManifest = field(params, "manifest")?;
    let statement = manifest.statement_digest()?;
    authorize(state, params, statement, authorizer)?;
    state.research_cocode.begin(manifest)?;
    Ok(statement)
}

pub(crate) fn append_proof_chunk(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
) -> Result<[u8; 32], String> {
    require_keys(params, &["chunk", "approval", "expectedBeforeRoot"])?;
    let chunk: ProofChunkUpload = field(params, "chunk")?;
    let statement = chunk.statement()?;
    authorize(state, params, statement, authorizer)?;
    state.research_cocode.append(chunk)?;
    Ok(statement)
}

pub(crate) fn commit_settlement(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
) -> Result<[u8; 32], String> {
    require_keys(params, &["commit", "approval", "expectedBeforeRoot"])?;
    let request: CommitRequest = field(params, "commit")?;
    let statement = request.statement_digest()?;
    authorize(state, params, statement, authorizer)?;
    state.research_cocode.verify_and_commit(&request)?;
    Ok(statement)
}

pub fn encode_policy_transaction(
    policy: &DeploymentPolicy,
    approval: &QuorumApproval,
    before_root: [u8; 32],
) -> Result<Vec<u8>, String> {
    policy.validate()?;
    authorized_transaction(
        "defmivm.issueResearchCoCodePolicy",
        "policy",
        policy,
        approval,
        before_root,
    )
}

pub fn encode_book_transaction(
    book: &ResearchBookGenesis,
    approval: &QuorumApproval,
    before_root: [u8; 32],
) -> Result<Vec<u8>, String> {
    book.validate()?;
    authorized_transaction(
        "defmivm.issueResearchCoCodeBook",
        "book",
        book,
        approval,
        before_root,
    )
}

pub fn encode_begin_transaction(
    manifest: &ProofManifest,
    approval: &QuorumApproval,
    before_root: [u8; 32],
) -> Result<Vec<u8>, String> {
    manifest.validate()?;
    authorized_transaction(
        "defmivm.issueResearchCoCodeProofBegin",
        "manifest",
        manifest,
        approval,
        before_root,
    )
}

pub fn encode_chunk_transaction(
    chunk: &ProofChunkUpload,
    approval: &QuorumApproval,
    before_root: [u8; 32],
) -> Result<Vec<u8>, String> {
    chunk.statement()?;
    authorized_transaction(
        "defmivm.issueResearchCoCodeProofChunk",
        "chunk",
        chunk,
        approval,
        before_root,
    )
}

pub fn encode_commit_transaction(
    commit: &CommitRequest,
    approval: &QuorumApproval,
    before_root: [u8; 32],
) -> Result<Vec<u8>, String> {
    commit.validate()?;
    authorized_transaction(
        "defmivm.issueResearchCoCodeCommit",
        "commit",
        commit,
        approval,
        before_root,
    )
}

fn authorized_transaction<T: Serialize>(
    method: &str,
    field_name: &str,
    body: &T,
    approval: &QuorumApproval,
    before_root: [u8; 32],
) -> Result<Vec<u8>, String> {
    let mut params = Map::new();
    params.insert(
        field_name.into(),
        serde_json::to_value(body).map_err(|error| error.to_string())?,
    );
    params.insert("approval".into(), approval_json(approval));
    params.insert(
        "expectedBeforeRoot".into(),
        Value::String(hex::encode(before_root)),
    );
    let transaction = TransactionEnvelope::new(method, Value::Object(params))?.encode()?;
    if transaction.len() > MAX_TRANSACTION_BYTES {
        return Err(format!(
            "research transaction has {} bytes; maximum is {MAX_TRANSACTION_BYTES}",
            transaction.len()
        ));
    }
    Ok(transaction)
}

/// Existing DeFMI governance wire shape, exposed for adversarial acceptance
/// transactions that deliberately bypass the safe typed constructors.
pub fn approval_json(approval: &QuorumApproval) -> Value {
    json!({
        "statement": hex::encode(approval.statement),
        "signerEpoch": approval.signer_epoch,
        "suite": approval.suite,
        "committeeDigest": hex::encode(approval.committee_digest),
        "domain": approval.domain,
        "beforeRoot": hex::encode(approval.before_root),
        "approvals": approval.approvals.iter().map(|signed| json!({
            "nodeID": signed.node_id,
            "signature": hex::encode(&signed.signature),
        })).collect::<Vec<_>>(),
    })
}

fn validate_receipt(receipt: &SettlementReceipt) -> Result<(), String> {
    SettlementStatement {
        deployment_id: receipt.deployment_id.clone(),
        book_id: receipt.book_id.clone(),
        operation_id: receipt.operation_id.clone(),
        sequence: receipt.sequence,
        before_commitment: receipt.before_commitment.clone(),
        after_commitment: receipt.after_commitment.clone(),
        no_fill: receipt.no_fill,
    }
    .validate()?;
    validate_hex_128(&receipt.proof_sha512, "receipt proof digest")
}

fn field<T: DeserializeOwned>(params: &Map<String, Value>, name: &str) -> Result<T, String> {
    serde_json::from_value(
        params
            .get(name)
            .cloned()
            .ok_or_else(|| format!("missing transaction field {name}"))?,
    )
    .map_err(|error| format!("invalid transaction field {name}: {error}"))
}

fn validate_id(value: &str, name: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return Err(format!(
            "{name} must be nonempty ASCII with at most 128 bytes"
        ));
    }
    Ok(())
}

fn validate_hex_128(value: &str, name: &str) -> Result<(), String> {
    if value.len() != 128
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must be canonical lowercase 64-byte hex"));
    }
    Ok(())
}

fn sha512_hex(bytes: &[u8]) -> String {
    hex::encode(Sha512::digest(bytes))
}

fn book_key(deployment_id: &str, book_id: &str) -> String {
    let mut hash = Sha512::new();
    hash.update(BOOK_KEY_DOMAIN);
    hash.update((deployment_id.len() as u64).to_be_bytes());
    hash.update(deployment_id.as_bytes());
    hash.update((book_id.len() as u64).to_be_bytes());
    hash.update(book_id.as_bytes());
    hex::encode(hash.finalize())
}

fn action_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32], String> {
    let encoded = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    Ok(Sha256::new()
        .chain_update(domain)
        .chain_update((encoded.len() as u64).to_be_bytes())
        .chain_update(encoded)
        .finalize()
        .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPLOYMENT: &str = "reservation-budget-test";
    const INITIAL_COMMITMENT_BYTE: &str = "11";

    #[test]
    fn query_roster_is_explicit_immutable_policy_input_not_a_legacy_field() {
        let legacy = DeploymentPolicy::native_v1(DEPLOYMENT);
        let legacy_json = serde_json::to_value(&legacy).unwrap();
        assert!(legacy_json.get("trustedQueryRosterSha512").is_none());
        assert_eq!(
            serde_json::from_value::<DeploymentPolicy>(legacy_json).unwrap(),
            legacy
        );

        let pin = "ab".repeat(64);
        let policy = DeploymentPolicy::native_query_agreement(DEPLOYMENT, &pin).unwrap();
        assert_eq!(
            policy.trusted_query_roster_sha512.as_deref(),
            Some(pin.as_str())
        );
        assert_ne!(legacy.statement().unwrap(), policy.statement().unwrap());
        let other = DeploymentPolicy::native_query_agreement(DEPLOYMENT, "cd".repeat(64)).unwrap();
        assert_ne!(policy.statement().unwrap(), other.statement().unwrap());

        let mut mismatched = policy.clone();
        mismatched.proof_protocol = PROOF_PROTOCOL.into();
        assert!(mismatched.validate().is_err());
        let mut missing = policy;
        missing.trusted_query_roster_sha512 = None;
        assert!(missing.validate().is_err());
        assert!(DeploymentPolicy::native_query_agreement(DEPLOYMENT, "short").is_err());
        assert!(DeploymentPolicy::native_query_agreement(DEPLOYMENT, "AB".repeat(64)).is_err());
    }

    #[test]
    fn fresh_pqc_on_accepts_only_its_pinned_query_agreement_policy() {
        use zkfmi_crypto::suite::Version;

        let mut state = State {
            deployment_crypto_policy: Some(DeploymentCryptoPolicy {
                version: Version::V1,
                deployment_id: DEPLOYMENT.into(),
                mode: PqcMode::On,
            }),
            ..State::default()
        };
        let legacy = DeploymentPolicy::native_v1(DEPLOYMENT);
        assert!(ensure_policy_matches_fresh_deployment(&state, &legacy)
            .unwrap_err()
            .contains("requires a pinned query-agreement-v2 roster"));

        let pin = "ab".repeat(64);
        let query = DeploymentPolicy::native_query_agreement(DEPLOYMENT, &pin).unwrap();
        ensure_policy_matches_fresh_deployment(&state, &query)
            .expect("matching query-agreement-v2 policy");

        let wrong_deployment =
            DeploymentPolicy::native_query_agreement("another-deployment", &pin).unwrap();
        assert_eq!(
            ensure_policy_matches_fresh_deployment(&state, &wrong_deployment).unwrap_err(),
            "research policy deployment differs from fresh genesis"
        );

        state.deployment_crypto_policy.as_mut().unwrap().mode = PqcMode::Off;
        ensure_policy_matches_fresh_deployment(&state, &legacy)
            .expect("PQC-off preserves the established research policy surface");
    }

    fn genesis(book_id: &str) -> ResearchBookGenesis {
        ResearchBookGenesis::new(
            DEPLOYMENT,
            book_id,
            [
                AccountAssetHandle::new("asset-seller-account", "traded-asset"),
                AccountAssetHandle::new("asset-buyer-account", "traded-asset"),
                AccountAssetHandle::new("cash-buyer-account", "cash-asset"),
                AccountAssetHandle::new("cash-seller-account", "cash-asset"),
            ],
            INITIAL_COMMITMENT_BYTE.repeat(64),
        )
    }

    fn manifest(book_id: &str, operation_id: &str, proof_len: usize) -> ProofManifest {
        ProofManifest {
            deployment_mode: DEPLOYMENT_MODE.into(),
            statement: SettlementStatement {
                deployment_id: DEPLOYMENT.into(),
                book_id: book_id.into(),
                operation_id: operation_id.into(),
                sequence: 1,
                before_commitment: INITIAL_COMMITMENT_BYTE.repeat(64),
                after_commitment: "22".repeat(64),
                no_fill: false,
            },
            proof_len: proof_len as u64,
            proof_sha512: "33".repeat(64),
            chunk_bytes: PROOF_CHUNK_BYTES as u32,
            chunk_count: proof_len.div_ceil(PROOF_CHUNK_BYTES) as u32,
        }
    }

    fn state_with_two_books() -> ResearchCoCodeState {
        let mut state = ResearchCoCodeState::default();
        state
            .insert_policy(DeploymentPolicy::native_v1(DEPLOYMENT))
            .expect("policy");
        state.insert_book(genesis("book-a")).expect("book A");
        state.insert_book(genesis("book-b")).expect("book B");
        state
    }

    #[test]
    fn active_uploads_share_one_metadata_reserved_proof_budget() {
        let first_len = MAX_PROOF_BYTES / 2 + 1;
        let second_len = MAX_PROOF_BYTES - first_len + 1;
        let first = manifest("book-a", "operation-a", first_len);
        let second = manifest("book-b", "operation-b", second_len);
        let mut state = state_with_two_books();

        state.begin(first).expect("first reservation");
        state.validate().expect("within reservation budget");
        let before_rejected_begin = state.clone();
        assert!(state
            .begin(second.clone())
            .expect_err("combined reservations exceed the budget")
            .contains("global 256 MiB budget"));
        assert_eq!(state, before_rejected_begin);

        state.uploads.insert(
            second.statement.operation_id.clone(),
            ProofUploadRecord {
                manifest: second,
                chunks: Vec::new(),
            },
        );
        assert!(state
            .validate()
            .expect_err("deserialized over-budget metadata must be rejected")
            .contains("global 256 MiB budget"));
    }

    #[test]
    fn book_requires_paired_and_distinct_dvp_asset_rails() {
        let mut mismatched_traded = genesis("mismatched-traded");
        mismatched_traded.handles[1].asset_handle = "other-traded-asset".into();
        assert!(mismatched_traded.validate().is_err());

        let mut mismatched_cash = genesis("mismatched-cash");
        mismatched_cash.handles[3].asset_handle = "other-cash-asset".into();
        assert!(mismatched_cash.validate().is_err());

        let mut shared_rail = genesis("shared-rail");
        for handle in &mut shared_rail.handles {
            handle.asset_handle = "same-asset".into();
        }
        assert!(shared_rail.validate().is_err());
    }
}
