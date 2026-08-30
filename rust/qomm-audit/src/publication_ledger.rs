//! Crash-atomic privacy-budget and publication-certificate ledger.
//!
//! The MPC nodes produce and attest one final [`PublicationStatement`]. This
//! store commits its 3-of-7 certificate, the legal-entity budget debit and the
//! replay marker under one file lock and one atomic rename. It deliberately
//! accepts signatures, never signing keys: a coordinator cannot manufacture a
//! publication merely because it can open this database.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::distributed_dp::DpMechanism;
use crate::publication::{NodeSignature, PublicationCertificate, PublicationStatement, ZERO};

const STATE_VERSION: u8 = 1;
const BUDGET_DOMAIN: &[u8] = b"QOMM:DP:BUDGET-ALLOCATION:v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BudgetAllocation {
    pub budget_scope: [u8; 32],
    pub venue: String,
    pub output_name: String,
    pub total_micros: u64,
    pub policy_version: u64,
}

impl BudgetAllocation {
    pub fn body(&self) -> Result<Vec<u8>, String> {
        if self.budget_scope == ZERO
            || self.venue.trim().is_empty()
            || self.output_name.trim().is_empty()
            || self.total_micros == 0
            || self.policy_version == 0
        {
            return Err("privacy-budget allocation is incomplete".into());
        }
        let mut body = BUDGET_DOMAIN.to_vec();
        body.extend(
            serde_json::to_vec(self).map_err(|error| format!("budget encoding failed: {error}"))?,
        );
        Ok(body)
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        Ok(Sha256::digest(self.body()?).into())
    }
}

#[derive(Clone, Debug)]
pub struct PublicationRequest {
    pub operation_id: [u8; 32],
    pub budget_scope: [u8; 32],
    pub venue: String,
    pub epoch: u64,
    pub slot_start: u64,
    pub slot_end: u64,
    pub source_digest: [u8; 32],
    pub rule_digest: [u8; 32],
    pub private_input_commitment: [u8; 32],
    pub transcript_digest: [u8; 32],
    pub output_name: String,
    pub output_value: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredSignature {
    node_id: String,
    signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredCertificate {
    statement: PublicationStatement,
    signatures: Vec<StoredSignature>,
}

impl StoredCertificate {
    fn from_certificate(certificate: &PublicationCertificate) -> Self {
        Self {
            statement: certificate.statement.clone(),
            signatures: certificate
                .signatures
                .iter()
                .map(|signed| StoredSignature {
                    node_id: signed.node_id.clone(),
                    signature: hex::encode(signed.signature.to_bytes()),
                })
                .collect(),
        }
    }

    fn certificate(&self) -> Result<PublicationCertificate, String> {
        Ok(PublicationCertificate {
            statement: self.statement.clone(),
            signatures: self
                .signatures
                .iter()
                .map(|signed| {
                    let raw: [u8; 64] = hex::decode(&signed.signature)
                        .map_err(|_| "stored publication signature is malformed".to_string())?
                        .try_into()
                        .map_err(|_| "stored publication signature is malformed".to_string())?;
                    Ok(NodeSignature {
                        node_id: signed.node_id.clone(),
                        signature: Signature::from_bytes(&raw),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct BudgetRecord {
    allocation: BudgetAllocation,
    allocation_signatures: Vec<StoredSignature>,
    spent_micros: u64,
    last_epoch: u64,
    latest: Option<StoredCertificate>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LedgerState {
    version: u8,
    generation: u64,
    budgets: BTreeMap<String, BudgetRecord>,
    operations: BTreeMap<String, String>,
}

struct LedgerLock(File);

impl LedgerLock {
    fn acquire(path: &Path) -> Result<Self, String> {
        let lock_path = PathBuf::from(format!("{}.lock", path.display()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|error| error.to_string())?;
        fs::set_permissions(lock_path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
        // SAFETY: the descriptor stays live for the lifetime of this guard.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(Self(file))
    }
}

impl Drop for LedgerLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor is still owned by this guard here.
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

pub struct PublicationLedger {
    path: PathBuf,
    publication_registry: BTreeMap<String, VerifyingKey>,
    publication_threshold: usize,
    governance_registry: BTreeMap<String, VerifyingKey>,
    governance_threshold: usize,
}

impl PublicationLedger {
    pub fn open(
        path: impl Into<PathBuf>,
        registry: BTreeMap<String, VerifyingKey>,
        threshold: usize,
    ) -> Result<Self, String> {
        Self::open_with_registries(path, registry.clone(), threshold, registry, threshold)
    }

    /// Open with distinct operational MPC signers and governance signers.
    /// Compromise of a publication node therefore cannot allocate itself a
    /// fresh privacy budget, while governance cannot fabricate an MPC output.
    pub fn open_with_registries(
        path: impl Into<PathBuf>,
        publication_registry: BTreeMap<String, VerifyingKey>,
        publication_threshold: usize,
        governance_registry: BTreeMap<String, VerifyingKey>,
        governance_threshold: usize,
    ) -> Result<Self, String> {
        if publication_registry.len() != 7
            || publication_threshold != 3
            || governance_registry.len() != 7
            || governance_threshold != 3
        {
            return Err(
                "production publication ledger requires separate explicit 3-of-7 registries".into(),
            );
        }
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
        }
        let ledger = Self {
            path,
            publication_registry,
            publication_threshold,
            governance_registry,
            governance_threshold,
        };
        let _lock = LedgerLock::acquire(&ledger.path)?;
        if !ledger.path.exists() {
            ledger.write_unlocked(&LedgerState {
                version: STATE_VERSION,
                generation: 0,
                budgets: BTreeMap::new(),
                operations: BTreeMap::new(),
            })?;
        } else {
            ledger.read_unlocked()?;
        }
        Ok(ledger)
    }

    fn key(scope: &[u8; 32], venue: &str, output_name: &str) -> String {
        hex::encode(
            Sha256::new()
                .chain_update(b"QOMM:DP:BUDGET-KEY:v1")
                .chain_update(scope)
                .chain_update((venue.len() as u64).to_be_bytes())
                .chain_update(venue.as_bytes())
                .chain_update((output_name.len() as u64).to_be_bytes())
                .chain_update(output_name.as_bytes())
                .finalize(),
        )
    }

    fn verify_signatures(
        registry: &BTreeMap<String, VerifyingKey>,
        threshold: usize,
        body: &[u8],
        signatures: &[NodeSignature],
    ) -> bool {
        let mut seen = BTreeSet::new();
        signatures
            .iter()
            .filter(|signed| {
                seen.insert(signed.node_id.clone())
                    && registry
                        .get(&signed.node_id)
                        .is_some_and(|key| key.verify(body, &signed.signature).is_ok())
            })
            .count()
            >= threshold
    }

    fn stored_signatures(signatures: &[NodeSignature]) -> Vec<StoredSignature> {
        signatures
            .iter()
            .map(|signed| StoredSignature {
                node_id: signed.node_id.clone(),
                signature: hex::encode(signed.signature.to_bytes()),
            })
            .collect()
    }

    /// Install one governance-approved budget. Reconfiguration never resets a
    /// consumed budget: this MVP intentionally requires a new scope after use.
    pub fn configure_budget(
        &self,
        allocation: BudgetAllocation,
        signatures: &[NodeSignature],
    ) -> Result<(), String> {
        let body = allocation.body()?;
        if !Self::verify_signatures(
            &self.governance_registry,
            self.governance_threshold,
            &body,
            signatures,
        ) {
            return Err("privacy-budget allocation lacks 3-of-7 approval".into());
        }
        let _lock = LedgerLock::acquire(&self.path)?;
        let mut state = self.read_unlocked()?;
        let key = Self::key(
            &allocation.budget_scope,
            &allocation.venue,
            &allocation.output_name,
        );
        if state.budgets.contains_key(&key) {
            return Err("privacy-budget allocation already exists; budgets cannot be reset".into());
        }
        state.budgets.insert(
            key,
            BudgetRecord {
                allocation,
                allocation_signatures: Self::stored_signatures(signatures),
                spent_micros: 0,
                last_epoch: 0,
                latest: None,
            },
        );
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| "publication-ledger generation overflow".to_string())?;
        self.write_unlocked(&state)
    }

    /// Atomically debit the legal-entity budget and append the 3-of-7 MPC
    /// publication certificate. The callback runs while the cross-process CAS
    /// lock is held, so two coordinators cannot both sign the same `before`.
    pub fn publish_with<F>(
        &self,
        request: PublicationRequest,
        mechanism: &DpMechanism,
        sign: F,
    ) -> Result<PublicationCertificate, String>
    where
        F: FnOnce(&PublicationStatement) -> Result<Vec<NodeSignature>, String>,
    {
        if request.operation_id == ZERO {
            return Err("publication operation identifier is required".into());
        }
        let _lock = LedgerLock::acquire(&self.path)?;
        let mut state = self.read_unlocked()?;
        let operation = hex::encode(request.operation_id);
        if state.operations.contains_key(&operation) {
            return Err("publication operation was already committed".into());
        }
        let key = Self::key(&request.budget_scope, &request.venue, &request.output_name);
        let budget = state
            .budgets
            .get_mut(&key)
            .ok_or_else(|| "no approved privacy budget for this legal-entity scope".to_string())?;
        if request.venue != budget.allocation.venue
            || request.output_name != budget.allocation.output_name
            || request.epoch <= budget.last_epoch
        {
            return Err("publication scope or epoch does not follow its budget state".into());
        }
        let after = budget
            .spent_micros
            .checked_add(mechanism.epsilon_micros)
            .ok_or_else(|| "privacy budget exhausted".to_string())?;
        if after > budget.allocation.total_micros {
            return Err("privacy budget exhausted".into());
        }
        let previous = budget
            .latest
            .as_ref()
            .map(StoredCertificate::certificate)
            .transpose()?;
        let (delta_numerator, delta_denominator) = mechanism.certificate_delta()?;
        let statement = PublicationStatement {
            operation_id: request.operation_id,
            budget_scope: request.budget_scope,
            venue: request.venue,
            epoch: request.epoch,
            slot_start: request.slot_start,
            slot_end: request.slot_end,
            source_digest: request.source_digest,
            rule_digest: request.rule_digest,
            mechanism_digest: mechanism.digest(),
            private_input_commitment: request.private_input_commitment,
            transcript_digest: request.transcript_digest,
            output_name: request.output_name,
            output_value: request.output_value,
            epsilon_micros: mechanism.epsilon_micros,
            delta_numerator,
            delta_denominator,
            budget_total_micros: budget.allocation.total_micros,
            budget_before_micros: budget.spent_micros,
            budget_after_micros: after,
            previous_certificate: previous
                .as_ref()
                .map(PublicationCertificate::digest)
                .transpose()?
                .unwrap_or(ZERO),
        };
        statement.validate_against(mechanism)?;
        let signatures = sign(&statement)?;
        let certificate = PublicationCertificate {
            statement,
            signatures,
        };
        if !certificate.verify(
            &self.publication_registry,
            self.publication_threshold,
            previous.as_ref(),
        ) {
            return Err("publication lacks a valid 3-of-7 certificate or budget chain".into());
        }
        let certificate_digest = certificate.digest()?;
        budget.spent_micros = after;
        budget.last_epoch = certificate.statement.epoch;
        budget.latest = Some(StoredCertificate::from_certificate(&certificate));
        state
            .operations
            .insert(operation, hex::encode(certificate_digest));
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| "publication-ledger generation overflow".to_string())?;
        self.write_unlocked(&state)?;
        Ok(certificate)
    }

    pub fn budget_state(
        &self,
        scope: &[u8; 32],
        venue: &str,
        output_name: &str,
    ) -> Result<Option<(u64, u64, u64)>, String> {
        let _lock = LedgerLock::acquire(&self.path)?;
        let state = self.read_unlocked()?;
        Ok(state
            .budgets
            .get(&Self::key(scope, venue, output_name))
            .map(|budget| {
                (
                    budget.allocation.total_micros,
                    budget.spent_micros,
                    budget.last_epoch,
                )
            }))
    }

    fn read_unlocked(&self) -> Result<LedgerState, String> {
        let metadata = self.path.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("publication ledger must be a private regular file".into());
        }
        let mut bytes = Vec::new();
        File::open(&self.path)
            .and_then(|mut file| file.read_to_end(&mut bytes))
            .map_err(|error| error.to_string())?;
        let state: LedgerState = serde_json::from_slice(&bytes)
            .map_err(|_| "publication ledger is malformed".to_string())?;
        if state.version != STATE_VERSION {
            return Err("unsupported publication-ledger version".into());
        }
        Ok(state)
    }

    fn write_unlocked(&self, state: &LedgerState) -> Result<(), String> {
        let bytes = serde_json::to_vec(state).map_err(|error| error.to_string())?;
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let temp = parent.join(format!(".qomm-publication-{}.tmp", rand::random::<u64>()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)
                .map_err(|error| error.to_string())?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|error| error.to_string())?;
            fs::rename(&temp, &self.path).map_err(|error| error.to_string())?;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))
                .map_err(|error| error.to_string())?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| error.to_string())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}
