//! Crash-safe corporate request outbox used while the MPC committee is unavailable.
//!
//! The outbox is deliberately not a local execution engine. It preserves the exact
//! signed request bytes and releases them, in their original order, only to the MPC
//! path. A request remains durable until a canonical DeFMI settlement or release
//! receipt has been recorded.

use crate::key_management::{
    decrypt_authenticated, derive_secret_key, encrypt_authenticated, FileLock,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"QOMMOUT1";
const AAD: &[u8] = b"QOMM:CORPORATE-OUTBOX:v1";
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_RECEIPT_ID_BYTES: usize = 256;
const MAX_REASON_BYTES: usize = 512;
const MAX_AUTOMATIC_DISPATCH_ATTEMPTS: u32 = 10;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxState {
    Queued,
    Dispatching {
        attempt: u32,
        started_at: u64,
    },
    MpcAdmitted {
        attempt: u32,
        admitted_at: u64,
        receipt: MpcAdmissionReceipt,
    },
    Settled {
        receipt: CanonicalReceipt,
    },
    Expired {
        expired_at: u64,
    },
    ReleasePending {
        requested_at: u64,
    },
    Released {
        receipt: CanonicalReceipt,
    },
    /// Terminal local state used only when the participant module has read
    /// canonical DeFMI and proved that the signed reserve never existed. No
    /// synthetic ledger receipt is created because no ledger value moved.
    AbortedBeforeReserve {
        finalized_at: u64,
    },
    ManualReview {
        marked_at: u64,
        reason: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MpcAdmissionReceipt {
    pub committee_id: String,
    pub job_id: String,
    pub admitted_request_digest: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanonicalReceipt {
    pub defmi_network_id: String,
    pub transaction_id: String,
    pub ledger_height: u64,
    pub request_digest: [u8; 32],
    pub finalized_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct OutboxEntry {
    request_id: String,
    sequence: u64,
    accepted_at: u64,
    expires_at: u64,
    request_digest: [u8; 32],
    signed_request: Vec<u8>,
    state: OutboxState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct OutboxData {
    version: u8,
    generation: u64,
    next_sequence: u64,
    next_cover_slot: u64,
    next_cover_due_at: Option<u64>,
    entries: BTreeMap<String, OutboxEntry>,
}

impl Default for OutboxData {
    fn default() -> Self {
        Self {
            version: 1,
            generation: 0,
            next_sequence: 0,
            next_cover_slot: 0,
            next_cover_due_at: None,
            entries: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnqueueOutcome {
    Enqueued { sequence: u64 },
    AlreadyPresent { sequence: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedRequest {
    pub request_id: String,
    pub sequence: u64,
    pub accepted_at: u64,
    pub expires_at: u64,
    pub request_digest: [u8; 32],
    /// The exact bytes originally signed by the corporate participant.
    pub signed_request: Vec<u8>,
    pub attempt: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueueAction {
    Dispatch(ClaimedRequest),
    /// The reserve must be released or escalated; it must never be executed.
    Expire {
        request_id: String,
        request_digest: [u8; 32],
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoverAction {
    Real(ClaimedRequest),
    Dummy,
    Expire {
        request_id: String,
        request_digest: [u8; 32],
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverSlot {
    pub slot: u64,
    pub due_at: u64,
    /// This distinction is local only. The caller must encrypt and pad real and
    /// dummy packets to the same wire size before sending them.
    pub action: CoverAction,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OutboxEntrySummary {
    pub request_id: String,
    pub sequence: u64,
    pub accepted_at: u64,
    pub expires_at: u64,
    pub request_digest: [u8; 32],
    pub state: OutboxState,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutboxMetrics {
    pub queued: usize,
    pub dispatching: usize,
    pub mpc_admitted: usize,
    pub settled: usize,
    pub expired: usize,
    pub release_pending: usize,
    pub released: usize,
    pub aborted_before_reserve: usize,
    pub manual_review: usize,
    pub oldest_unfinalized_age_seconds: Option<u64>,
}

/// Encrypted, owner-only and crash-atomic corporate outbox.
pub struct CorporateOutbox {
    path: PathBuf,
    passphrase: Vec<u8>,
    max_entries: usize,
    max_request_bytes: usize,
}

impl fmt::Debug for CorporateOutbox {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CorporateOutbox")
            .field("path", &self.path)
            .field("passphrase", &"[redacted]")
            .field("max_entries", &self.max_entries)
            .field("max_request_bytes", &self.max_request_bytes)
            .finish()
    }
}

impl CorporateOutbox {
    pub fn new(
        path: impl Into<PathBuf>,
        passphrase: &[u8],
        max_entries: usize,
        max_request_bytes: usize,
    ) -> Result<Self, String> {
        if passphrase.len() < 12 {
            return Err("corporate outbox passphrase must contain at least 12 bytes".into());
        }
        if max_entries == 0 || max_request_bytes == 0 {
            return Err("corporate outbox limits must be greater than zero".into());
        }
        Ok(Self {
            path: path.into(),
            passphrase: passphrase.to_vec(),
            max_entries,
            max_request_bytes,
        })
    }

    pub fn initialize(&self) -> Result<(), String> {
        ensure_private_parent(&self.path)?;
        let _lock = FileLock::acquire(&self.path)?;
        if self.path.exists() {
            return Err(format!("{} already exists", self.path.display()));
        }
        self.write_unlocked(&OutboxData::default())
    }

    pub fn initialize_if_missing(&self) -> Result<(), String> {
        ensure_private_parent(&self.path)?;
        let _lock = FileLock::acquire(&self.path)?;
        if self.path.exists() {
            self.read_unlocked().map(|_| ())
        } else {
            self.write_unlocked(&OutboxData::default())
        }
    }

    pub fn enqueue(
        &self,
        request_id: &str,
        signed_request: &[u8],
        accepted_at: u64,
        expires_at: u64,
    ) -> Result<EnqueueOutcome, String> {
        validate_identifier("request id", request_id, MAX_REQUEST_ID_BYTES)?;
        if signed_request.is_empty() || signed_request.len() > self.max_request_bytes {
            return Err("signed request length is outside the configured outbox limit".into());
        }
        if expires_at <= accepted_at {
            return Err("request expiry must be later than its acceptance time".into());
        }
        let digest: [u8; 32] = Sha256::digest(signed_request).into();
        self.update(|data| {
            if let Some(existing) = data.entries.get(request_id) {
                if existing.request_digest == digest
                    && existing.signed_request == signed_request
                    && existing.accepted_at == accepted_at
                    && existing.expires_at == expires_at
                {
                    return Ok(EnqueueOutcome::AlreadyPresent {
                        sequence: existing.sequence,
                    });
                }
                return Err("request id was reused with different signed bytes".into());
            }
            if data.entries.len() >= self.max_entries {
                return Err("corporate outbox capacity is exhausted".into());
            }
            let sequence = data.next_sequence;
            data.next_sequence = data
                .next_sequence
                .checked_add(1)
                .ok_or_else(|| "corporate outbox sequence exhausted".to_string())?;
            data.entries.insert(
                request_id.to_string(),
                OutboxEntry {
                    request_id: request_id.to_string(),
                    sequence,
                    accepted_at,
                    expires_at,
                    request_digest: digest,
                    signed_request: signed_request.to_vec(),
                    state: OutboxState::Queued,
                },
            );
            Ok(EnqueueOutcome::Enqueued { sequence })
        })
    }

    /// Service-boundary variant of [`Self::enqueue`].  The corporate module,
    /// rather than an external caller, chooses `first_seen_at`.  Repeating the
    /// same signed bytes therefore returns the original sequence and acceptance
    /// time instead of turning a harmless network retry into an ID conflict.
    pub fn enqueue_first_seen(
        &self,
        request_id: &str,
        signed_request: &[u8],
        first_seen_at: u64,
        expires_at: u64,
    ) -> Result<EnqueueOutcome, String> {
        validate_identifier("request id", request_id, MAX_REQUEST_ID_BYTES)?;
        if signed_request.is_empty() || signed_request.len() > self.max_request_bytes {
            return Err("signed request length is outside the configured outbox limit".into());
        }
        if expires_at <= first_seen_at {
            return Err("request expiry must be later than its acceptance time".into());
        }
        let digest: [u8; 32] = Sha256::digest(signed_request).into();
        self.update(|data| {
            if let Some(existing) = data.entries.get(request_id) {
                if existing.request_digest == digest
                    && existing.signed_request == signed_request
                    && existing.expires_at == expires_at
                {
                    return Ok(EnqueueOutcome::AlreadyPresent {
                        sequence: existing.sequence,
                    });
                }
                return Err("request id was reused with different signed bytes".into());
            }
            if data.entries.len() >= self.max_entries {
                return Err("corporate outbox capacity is exhausted".into());
            }
            let sequence = data.next_sequence;
            data.next_sequence = data
                .next_sequence
                .checked_add(1)
                .ok_or_else(|| "corporate outbox sequence exhausted".to_string())?;
            data.entries.insert(
                request_id.to_string(),
                OutboxEntry {
                    request_id: request_id.to_string(),
                    sequence,
                    accepted_at: first_seen_at,
                    expires_at,
                    request_digest: digest,
                    signed_request: signed_request.to_vec(),
                    state: OutboxState::Queued,
                },
            );
            Ok(EnqueueOutcome::Enqueued { sequence })
        })
    }

    /// Claims the oldest request. A request whose send outcome is uncertain is
    /// retried with identical bytes using bounded exponential backoff whose
    /// initial delay is `retry_after_seconds`.
    pub fn claim_next(
        &self,
        now: u64,
        quorum_healthy: bool,
        retry_after_seconds: u64,
    ) -> Result<Option<QueueAction>, String> {
        self.update(|data| claim_oldest(data, now, retry_after_seconds, quorum_healthy))
    }

    /// Advances a fixed-rate cover schedule. An empty queue still returns a
    /// dummy slot, so a network observer need not learn whether a request exists.
    pub fn claim_cover_slot(
        &self,
        now: u64,
        quorum_healthy: bool,
        retry_after_seconds: u64,
        interval_seconds: u64,
    ) -> Result<Option<CoverSlot>, String> {
        if interval_seconds == 0 {
            return Err("cover interval must be greater than zero".into());
        }
        self.update(|data| {
            let due_at = data.next_cover_due_at.unwrap_or(now);
            if now < due_at {
                return Ok(None);
            }
            let slot = data.next_cover_slot;
            data.next_cover_slot = data
                .next_cover_slot
                .checked_add(1)
                .ok_or_else(|| "cover slot sequence exhausted".to_string())?;
            data.next_cover_due_at = Some(
                due_at
                    .checked_add(interval_seconds)
                    .ok_or_else(|| "cover schedule exhausted".to_string())?,
            );
            let action = if quorum_healthy {
                match claim_oldest(data, now, retry_after_seconds, true)? {
                    Some(QueueAction::Dispatch(request)) => CoverAction::Real(request),
                    Some(QueueAction::Expire {
                        request_id,
                        request_digest,
                    }) => CoverAction::Expire {
                        request_id,
                        request_digest,
                    },
                    None => CoverAction::Dummy,
                }
            } else {
                match claim_oldest(data, now, retry_after_seconds, false)? {
                    Some(QueueAction::Expire {
                        request_id,
                        request_digest,
                    }) => CoverAction::Expire {
                        request_id,
                        request_digest,
                    },
                    Some(QueueAction::Dispatch(_)) => {
                        return Err("an unhealthy MPC quorum cannot receive a request".into())
                    }
                    None => CoverAction::Dummy,
                }
            };
            Ok(Some(CoverSlot {
                slot,
                due_at,
                action,
            }))
        })
    }

    pub fn record_mpc_admission(
        &self,
        request_id: &str,
        request_digest: [u8; 32],
        admitted_at: u64,
        receipt: MpcAdmissionReceipt,
    ) -> Result<(), String> {
        validate_identifier("committee id", &receipt.committee_id, MAX_RECEIPT_ID_BYTES)?;
        validate_identifier("MPC job id", &receipt.job_id, MAX_RECEIPT_ID_BYTES)?;
        if receipt.admitted_request_digest != request_digest {
            return Err("MPC admission receipt is bound to a different request".into());
        }
        self.update(|data| {
            let entry = matching_entry(data, request_id, request_digest)?;
            match &entry.state {
                OutboxState::Dispatching { attempt, .. } => {
                    entry.state = OutboxState::MpcAdmitted {
                        attempt: *attempt,
                        admitted_at,
                        receipt,
                    };
                    Ok(())
                }
                OutboxState::MpcAdmitted {
                    receipt: existing, ..
                } if existing == &receipt => Ok(()),
                OutboxState::Settled { .. } => Ok(()),
                _ => Err("request is not awaiting an MPC admission receipt".into()),
            }
        })
    }

    /// Records a receipt observed from the canonical DeFMI ledger. This may
    /// close a dispatch with an uncertain network response.
    pub fn record_settlement(
        &self,
        request_id: &str,
        request_digest: [u8; 32],
        receipt: CanonicalReceipt,
    ) -> Result<(), String> {
        validate_canonical_receipt(&receipt, request_digest)?;
        self.update(|data| {
            let entry = matching_entry(data, request_id, request_digest)?;
            match &entry.state {
                OutboxState::Settled { receipt: existing }
                    if same_canonical_transition(existing, &receipt) =>
                {
                    Ok(())
                }
                OutboxState::Dispatching { .. } | OutboxState::MpcAdmitted { .. } => {
                    entry.state = OutboxState::Settled { receipt };
                    Ok(())
                }
                _ => Err("canonical settlement is incompatible with the request state".into()),
            }
        })
    }

    pub fn mark_release_pending(
        &self,
        request_id: &str,
        request_digest: [u8; 32],
        requested_at: u64,
    ) -> Result<(), String> {
        self.update(|data| {
            let entry = matching_entry(data, request_id, request_digest)?;
            match entry.state {
                OutboxState::Expired { .. } | OutboxState::ManualReview { .. } => {
                    entry.state = OutboxState::ReleasePending { requested_at };
                    Ok(())
                }
                OutboxState::ReleasePending { .. } | OutboxState::Released { .. } => Ok(()),
                _ => Err("only an expired or reviewed request may release its reserve".into()),
            }
        })
    }

    pub fn record_release(
        &self,
        request_id: &str,
        request_digest: [u8; 32],
        receipt: CanonicalReceipt,
    ) -> Result<(), String> {
        validate_canonical_receipt(&receipt, request_digest)?;
        self.update(|data| {
            let entry = matching_entry(data, request_id, request_digest)?;
            match &entry.state {
                OutboxState::Released { receipt: existing }
                    if same_canonical_transition(existing, &receipt) =>
                {
                    Ok(())
                }
                OutboxState::Queued
                | OutboxState::Dispatching { .. }
                | OutboxState::MpcAdmitted { .. }
                | OutboxState::Expired { .. }
                | OutboxState::ReleasePending { .. }
                | OutboxState::ManualReview { .. } => {
                    entry.state = OutboxState::Released { receipt };
                    Ok(())
                }
                _ => Err("request is not awaiting a canonical reserve-release receipt".into()),
            }
        })
    }

    /// Finalize a request that failed before any canonical reservation was
    /// created. The participant service, not the coordinator, is responsible
    /// for checking DeFMI non-existence before invoking this transition.
    pub fn record_pre_reserve_abort(
        &self,
        request_id: &str,
        request_digest: [u8; 32],
        finalized_at: u64,
    ) -> Result<(), String> {
        self.update(|data| {
            let entry = matching_entry(data, request_id, request_digest)?;
            match entry.state {
                OutboxState::Queued
                | OutboxState::Dispatching { .. }
                | OutboxState::Expired { .. }
                | OutboxState::ReleasePending { .. }
                | OutboxState::ManualReview { .. } => {
                    entry.state = OutboxState::AbortedBeforeReserve { finalized_at };
                    Ok(())
                }
                OutboxState::AbortedBeforeReserve {
                    finalized_at: existing,
                } if existing == finalized_at => Ok(()),
                OutboxState::AbortedBeforeReserve { .. } => Ok(()),
                _ => Err(
                    "only a request that has not reached MPC admission may abort before reserve"
                        .into(),
                ),
            }
        })
    }

    /// Read the exact durable request only for an authenticated in-process
    /// reconciliation worker.  Public snapshots intentionally expose only the
    /// digest; callers must never put these bytes in logs or metrics.
    pub fn signed_request(
        &self,
        request_id: &str,
        request_digest: [u8; 32],
    ) -> Result<Vec<u8>, String> {
        self.read(|data| {
            let entry = data
                .entries
                .get(request_id)
                .ok_or_else(|| "corporate outbox request was not found".to_string())?;
            if entry.request_digest != request_digest {
                return Err("corporate outbox request digest does not match".into());
            }
            Ok(entry.signed_request.clone())
        })
    }

    pub fn mark_manual_review(
        &self,
        request_id: &str,
        request_digest: [u8; 32],
        marked_at: u64,
        reason: &str,
    ) -> Result<(), String> {
        if reason.is_empty() || reason.len() > MAX_REASON_BYTES {
            return Err("manual-review reason length is invalid".into());
        }
        self.update(|data| {
            let entry = matching_entry(data, request_id, request_digest)?;
            if matches!(
                entry.state,
                OutboxState::Settled { .. }
                    | OutboxState::Released { .. }
                    | OutboxState::AbortedBeforeReserve { .. }
            ) {
                return Err("a finalized request cannot be moved to manual review".into());
            }
            entry.state = OutboxState::ManualReview {
                marked_at,
                reason: reason.to_string(),
            };
            Ok(())
        })
    }

    /// Deletes only entries already backed by a canonical ledger receipt.
    pub fn prune_finalized(&self, finalized_before: u64) -> Result<usize, String> {
        self.update(|data| {
            let before = data.entries.len();
            data.entries.retain(|_, entry| {
                let finalized_at = match &entry.state {
                    OutboxState::Settled { receipt } | OutboxState::Released { receipt } => {
                        Some(receipt.finalized_at)
                    }
                    OutboxState::AbortedBeforeReserve { finalized_at } => Some(*finalized_at),
                    _ => None,
                };
                !finalized_at.is_some_and(|at| at < finalized_before)
            });
            Ok(before - data.entries.len())
        })
    }

    pub fn summaries(&self) -> Result<Vec<OutboxEntrySummary>, String> {
        self.read(|data| {
            let mut summaries = data
                .entries
                .values()
                .map(|entry| OutboxEntrySummary {
                    request_id: entry.request_id.clone(),
                    sequence: entry.sequence,
                    accepted_at: entry.accepted_at,
                    expires_at: entry.expires_at,
                    request_digest: entry.request_digest,
                    state: entry.state.clone(),
                })
                .collect::<Vec<_>>();
            summaries.sort_by_key(|entry| entry.sequence);
            Ok(summaries)
        })
    }

    pub fn metrics(&self, now: u64) -> Result<OutboxMetrics, String> {
        self.read(|data| {
            let mut metrics = OutboxMetrics::default();
            let mut oldest = None::<u64>;
            for entry in data.entries.values() {
                match entry.state {
                    OutboxState::Queued => metrics.queued += 1,
                    OutboxState::Dispatching { .. } => metrics.dispatching += 1,
                    OutboxState::MpcAdmitted { .. } => metrics.mpc_admitted += 1,
                    OutboxState::Settled { .. } => metrics.settled += 1,
                    OutboxState::Expired { .. } => metrics.expired += 1,
                    OutboxState::ReleasePending { .. } => metrics.release_pending += 1,
                    OutboxState::Released { .. } => metrics.released += 1,
                    OutboxState::AbortedBeforeReserve { .. } => metrics.aborted_before_reserve += 1,
                    OutboxState::ManualReview { .. } => metrics.manual_review += 1,
                }
                if !matches!(
                    entry.state,
                    OutboxState::Settled { .. }
                        | OutboxState::Released { .. }
                        | OutboxState::AbortedBeforeReserve { .. }
                ) {
                    oldest = Some(
                        oldest.map_or(entry.accepted_at, |value| value.min(entry.accepted_at)),
                    );
                }
            }
            metrics.oldest_unfinalized_age_seconds = oldest.map(|at| now.saturating_sub(at));
            Ok(metrics)
        })
    }

    fn read<T>(
        &self,
        operation: impl FnOnce(&OutboxData) -> Result<T, String>,
    ) -> Result<T, String> {
        let _lock = FileLock::acquire(&self.path)?;
        let data = self.read_unlocked()?;
        operation(&data)
    }

    fn update<T>(
        &self,
        operation: impl FnOnce(&mut OutboxData) -> Result<T, String>,
    ) -> Result<T, String> {
        let _lock = FileLock::acquire(&self.path)?;
        let mut data = self.read_unlocked()?;
        let result = operation(&mut data)?;
        data.generation = data
            .generation
            .checked_add(1)
            .ok_or_else(|| "corporate outbox generation exhausted".to_string())?;
        self.validate_data(&data)?;
        self.write_unlocked(&data)?;
        Ok(result)
    }

    fn read_unlocked(&self) -> Result<OutboxData, String> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)
            .map_err(|error| error.to_string())?;
        validate_private_file(&file, &self.path)?;
        let length = file.metadata().map_err(|error| error.to_string())?.len();
        if length > MAX_FILE_BYTES {
            return Err("corporate outbox file exceeds the safety limit".into());
        }
        let mut raw = Vec::with_capacity(length as usize);
        file.read_to_end(&mut raw)
            .map_err(|error| error.to_string())?;
        if raw.len() < MAGIC.len() + SALT_BYTES + NONCE_BYTES + 16 || &raw[..MAGIC.len()] != MAGIC {
            return Err("corporate outbox header is invalid".into());
        }
        let salt_start = MAGIC.len();
        let nonce_start = salt_start + SALT_BYTES;
        let ciphertext_start = nonce_start + NONCE_BYTES;
        let key = derive_secret_key(&self.passphrase, &raw[salt_start..nonce_start])?;
        let nonce: [u8; NONCE_BYTES] = raw[nonce_start..ciphertext_start]
            .try_into()
            .map_err(|_| "corporate outbox nonce is invalid".to_string())?;
        let clear = decrypt_authenticated(&key, &nonce, AAD, &raw[ciphertext_start..])
            .map_err(|_| "corporate outbox authentication failed".to_string())?;
        let data: OutboxData = serde_json::from_slice(&clear)
            .map_err(|_| "corporate outbox payload is invalid".to_string())?;
        self.validate_data(&data)?;
        Ok(data)
    }

    fn write_unlocked(&self, data: &OutboxData) -> Result<(), String> {
        self.validate_data(data)?;
        let clear = serde_json::to_vec(data).map_err(|error| error.to_string())?;
        let mut salt = [0_u8; SALT_BYTES];
        let mut nonce = [0_u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let key = derive_secret_key(&self.passphrase, &salt)?;
        let ciphertext = encrypt_authenticated(&key, &nonce, AAD, &clear)?;
        let mut raw = Vec::with_capacity(MAGIC.len() + salt.len() + nonce.len() + ciphertext.len());
        raw.extend_from_slice(MAGIC);
        raw.extend_from_slice(&salt);
        raw.extend_from_slice(&nonce);
        raw.extend_from_slice(&ciphertext);
        if raw.len() as u64 > MAX_FILE_BYTES {
            return Err("corporate outbox file exceeds the safety limit".into());
        }
        atomic_private_write(&self.path, &raw)
    }

    fn validate_data(&self, data: &OutboxData) -> Result<(), String> {
        if data.version != 1 {
            return Err("unsupported corporate outbox version".into());
        }
        if data.entries.len() > self.max_entries {
            return Err("corporate outbox contains too many entries".into());
        }
        let mut sequences = data
            .entries
            .values()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>();
        sequences.sort_unstable();
        sequences.dedup();
        if sequences.len() != data.entries.len() {
            return Err("corporate outbox contains duplicate sequence numbers".into());
        }
        for (key, entry) in &data.entries {
            validate_identifier("request id", key, MAX_REQUEST_ID_BYTES)?;
            if key != &entry.request_id {
                return Err("corporate outbox request index is inconsistent".into());
            }
            if entry.signed_request.is_empty()
                || entry.signed_request.len() > self.max_request_bytes
            {
                return Err("corporate outbox request exceeds its configured limit".into());
            }
            if entry.expires_at <= entry.accepted_at {
                return Err("corporate outbox contains an invalid expiry".into());
            }
            let digest: [u8; 32] = Sha256::digest(&entry.signed_request).into();
            if digest != entry.request_digest {
                return Err("corporate outbox request digest mismatch".into());
            }
        }
        Ok(())
    }
}

fn claim_oldest(
    data: &mut OutboxData,
    now: u64,
    retry_after_seconds: u64,
    quorum_healthy: bool,
) -> Result<Option<QueueAction>, String> {
    // Expiry is a two-system transition: the owner-side queue first prevents
    // any further MPC dispatch, then DeFMI releases (or proves the absence of)
    // the canonical reserve.  A crash or rejected release between those two
    // writes must not make the local `Expired` marker terminal.  Keep emitting
    // the exact durable request until reconciliation records Released or
    // AbortedBeforeReserve.  `ReleasePending` is treated the same way because
    // a lost DeFMI response is resolved idempotently from canonical state.
    let pending_release = data
        .entries
        .values()
        .filter(|entry| {
            matches!(
                entry.state,
                OutboxState::Expired { .. } | OutboxState::ReleasePending { .. }
            )
        })
        .min_by_key(|entry| entry.sequence);
    if let Some(entry) = pending_release {
        return Ok(Some(QueueAction::Expire {
            request_id: entry.request_id.clone(),
            request_digest: entry.request_digest,
        }));
    }

    // Expiry is processed even for an item isolated for manual review. This
    // keeps a failed request from being redispatched forever while still
    // guaranteeing that its canonical DeFMI reserve is eventually released.
    let expired = data
        .entries
        .values()
        .filter(|entry| {
            now >= entry.expires_at
                && matches!(
                    entry.state,
                    OutboxState::Queued
                        | OutboxState::Dispatching { .. }
                        | OutboxState::ManualReview { .. }
                )
        })
        .min_by_key(|entry| entry.sequence)
        .map(|entry| entry.request_id.clone());
    if let Some(request_id) = expired {
        let entry = data
            .entries
            .get_mut(&request_id)
            .ok_or_else(|| "corporate outbox index changed unexpectedly".to_string())?;
        entry.state = OutboxState::Expired { expired_at: now };
        return Ok(Some(QueueAction::Expire {
            request_id: entry.request_id.clone(),
            request_digest: entry.request_digest,
        }));
    }
    if !quorum_healthy {
        return Ok(None);
    }
    loop {
        let oldest = data
            .entries
            .values()
            .filter(|entry| {
                matches!(
                    entry.state,
                    OutboxState::Queued | OutboxState::Dispatching { .. }
                )
            })
            .min_by_key(|entry| entry.sequence)
            .map(|entry| entry.request_id.clone());
        let Some(request_id) = oldest else {
            return Ok(None);
        };
        let entry = data
            .entries
            .get_mut(&request_id)
            .ok_or_else(|| "corporate outbox index changed unexpectedly".to_string())?;
        let next_attempt = match entry.state {
            OutboxState::Queued => 1,
            OutboxState::Dispatching {
                attempt,
                started_at,
            } => {
                if attempt >= MAX_AUTOMATIC_DISPATCH_ATTEMPTS {
                    entry.state = OutboxState::ManualReview {
                        marked_at: now,
                        reason: "automatic MPC dispatch retry limit reached".into(),
                    };
                    continue;
                }
                let exponent = attempt.saturating_sub(1).min(7);
                let retry_delay = retry_after_seconds
                    .saturating_mul(1_u64 << exponent)
                    .min(300);
                if now < started_at.saturating_add(retry_delay) {
                    return Ok(None);
                }
                attempt
                    .checked_add(1)
                    .ok_or_else(|| "corporate outbox retry counter exhausted".to_string())?
            }
            _ => return Err("corporate outbox selected a non-dispatchable request".into()),
        };
        entry.state = OutboxState::Dispatching {
            attempt: next_attempt,
            started_at: now,
        };
        return Ok(Some(QueueAction::Dispatch(ClaimedRequest {
            request_id: entry.request_id.clone(),
            sequence: entry.sequence,
            accepted_at: entry.accepted_at,
            expires_at: entry.expires_at,
            request_digest: entry.request_digest,
            signed_request: entry.signed_request.clone(),
            attempt: next_attempt,
        })));
    }
}

fn matching_entry<'a>(
    data: &'a mut OutboxData,
    request_id: &str,
    request_digest: [u8; 32],
) -> Result<&'a mut OutboxEntry, String> {
    let entry = data
        .entries
        .get_mut(request_id)
        .ok_or_else(|| "corporate outbox request was not found".to_string())?;
    if entry.request_digest != request_digest {
        return Err("corporate outbox request digest does not match".into());
    }
    Ok(entry)
}

fn validate_canonical_receipt(
    receipt: &CanonicalReceipt,
    request_digest: [u8; 32],
) -> Result<(), String> {
    validate_identifier(
        "DeFMI network id",
        &receipt.defmi_network_id,
        MAX_RECEIPT_ID_BYTES,
    )?;
    validate_identifier(
        "transaction id",
        &receipt.transaction_id,
        MAX_RECEIPT_ID_BYTES,
    )?;
    if receipt.request_digest != request_digest {
        return Err("canonical receipt is bound to a different request".into());
    }
    Ok(())
}

/// Network retries may observe the same final Avalanche transition at a later
/// wall-clock time. `finalized_at` records the first local observation and is
/// therefore deliberately excluded from the canonical identity comparison.
fn same_canonical_transition(left: &CanonicalReceipt, right: &CanonicalReceipt) -> bool {
    left.defmi_network_id == right.defmi_network_id
        && left.transaction_id == right.transaction_id
        && left.ledger_height == right.ledger_height
        && left.request_digest == right.request_digest
}

fn validate_identifier(label: &str, value: &str, maximum: usize) -> Result<(), String> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

fn ensure_private_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "corporate outbox path must have a parent directory".to_string())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let metadata = parent.metadata().map_err(|error| error.to_string())?;
    // SAFETY: geteuid has no preconditions and reveals no secret.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != effective_uid {
        return Err("corporate outbox directory must be owned by the service user".into());
    }
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn validate_private_file(file: &File, path: &Path) -> Result<(), String> {
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    // SAFETY: geteuid has no preconditions and reveals no secret.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_file() || metadata.uid() != effective_uid {
        return Err(format!(
            "{} must be a regular file owned by the service user",
            path.display()
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(format!("{} permissions must be owner-only", path.display()));
    }
    Ok(())
}

fn atomic_private_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "corporate outbox path must have a parent directory".to_string())?;
    let mut suffix = [0_u8; 8];
    OsRng.fill_bytes(&mut suffix);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "corporate outbox file name is invalid".to_string())?;
    let temp = parent.join(format!(
        ".{file_name}.{:016x}.tmp",
        u64::from_le_bytes(suffix)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)
            .map_err(|error| error.to_string())?;
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        fs::rename(&temp, path).map_err(|error| error.to_string())?;
        let directory = File::open(parent).map_err(|error| error.to_string())?;
        // SAFETY: fsync receives a live directory descriptor.
        if unsafe { libc::fsync(directory.as_raw_fd()) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_path(label: &str) -> PathBuf {
        let mut random = [0_u8; 8];
        OsRng.fill_bytes(&mut random);
        std::env::temp_dir().join(format!(
            "qomm-corporate-outbox-{label}-{}-{:016x}/outbox.enc",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            u64::from_le_bytes(random)
        ))
    }

    fn outbox(path: &Path) -> CorporateOutbox {
        CorporateOutbox::new(path, b"correct horse battery staple", 16, 4096).unwrap()
    }

    fn digest(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn canonical(request: &[u8], transaction_id: &str, finalized_at: u64) -> CanonicalReceipt {
        CanonicalReceipt {
            defmi_network_id: "defmi-jp-1".into(),
            transaction_id: transaction_id.into(),
            ledger_height: 42,
            request_digest: digest(request),
            finalized_at,
        }
    }

    #[test]
    fn restart_preserves_exact_bytes_order_and_uncertain_retry() {
        let path = temporary_path("restart");
        let store = outbox(&path);
        store.initialize().unwrap();
        assert_eq!(
            store.enqueue("request-1", b"signed-one", 10, 100).unwrap(),
            EnqueueOutcome::Enqueued { sequence: 0 }
        );
        store.enqueue("request-2", b"signed-two", 11, 100).unwrap();
        assert_eq!(store.claim_next(20, false, 5).unwrap(), None);
        let first = match store.claim_next(20, true, 5).unwrap().unwrap() {
            QueueAction::Dispatch(request) => request,
            QueueAction::Expire { .. } => panic!("request unexpectedly expired"),
        };
        assert_eq!(first.signed_request, b"signed-one");
        assert_eq!(first.attempt, 1);
        assert_eq!(store.claim_next(24, true, 5).unwrap(), None);

        let reopened = outbox(&path);
        let retry = match reopened.claim_next(25, true, 5).unwrap().unwrap() {
            QueueAction::Dispatch(request) => request,
            QueueAction::Expire { .. } => panic!("request unexpectedly expired"),
        };
        assert_eq!(retry.signed_request, first.signed_request);
        assert_eq!(retry.request_digest, first.request_digest);
        assert_eq!(retry.attempt, 2);

        reopened
            .record_mpc_admission(
                "request-1",
                digest(b"signed-one"),
                26,
                MpcAdmissionReceipt {
                    committee_id: "committee-7".into(),
                    job_id: "job-1".into(),
                    admitted_request_digest: digest(b"signed-one"),
                },
            )
            .unwrap();
        let second = match reopened.claim_next(27, true, 5).unwrap().unwrap() {
            QueueAction::Dispatch(request) => request,
            QueueAction::Expire { .. } => panic!("request unexpectedly expired"),
        };
        assert_eq!(second.request_id, "request-2");
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn uncertain_delivery_uses_bounded_exponential_backoff() {
        let path = temporary_path("retry-backoff");
        let store = outbox(&path);
        store.initialize().unwrap();
        store
            .enqueue("request-1", b"signed-one", 10, 10_000)
            .unwrap();

        let first = store.claim_next(20, true, 5).unwrap().unwrap();
        assert!(matches!(first, QueueAction::Dispatch(_)));
        let second = store.claim_next(25, true, 5).unwrap().unwrap();
        assert!(matches!(second, QueueAction::Dispatch(_)));
        assert_eq!(store.claim_next(34, true, 5).unwrap(), None);
        let third = store.claim_next(35, true, 5).unwrap().unwrap();
        assert!(matches!(third, QueueAction::Dispatch(_)));

        // After enough failures the delay is capped at five minutes.
        let mut now = 35;
        for expected_attempt in 4..=9 {
            let delay = 5_u64
                .saturating_mul(1_u64 << (expected_attempt - 2).min(7))
                .min(300);
            assert_eq!(store.claim_next(now + delay - 1, true, 5).unwrap(), None);
            now += delay;
            let action = store.claim_next(now, true, 5).unwrap().unwrap();
            match action {
                QueueAction::Dispatch(request) => assert_eq!(request.attempt, expected_attempt),
                QueueAction::Expire { .. } => panic!("request unexpectedly expired"),
            }
        }
        assert_eq!(store.claim_next(now + 299, true, 5).unwrap(), None);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn retry_exhaustion_isolates_one_request_but_still_processes_its_expiry() {
        let path = temporary_path("retry-manual-review");
        let store = outbox(&path);
        store.initialize().unwrap();
        store
            .enqueue("request-1", b"signed-one", 10, 10_000)
            .unwrap();
        let mut now = 20;
        for expected_attempt in 1..=MAX_AUTOMATIC_DISPATCH_ATTEMPTS {
            let action = store.claim_next(now, true, 0).unwrap().unwrap();
            match action {
                QueueAction::Dispatch(request) => assert_eq!(request.attempt, expected_attempt),
                QueueAction::Expire { .. } => panic!("request unexpectedly expired"),
            }
            now += 1;
        }
        assert_eq!(store.claim_next(now, true, 0).unwrap(), None);
        assert_eq!(store.metrics(now).unwrap().manual_review, 1);
        assert!(matches!(
            store.claim_next(10_000, false, 0).unwrap(),
            Some(QueueAction::Expire { .. })
        ));
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn idempotency_conflict_tamper_and_wrong_key_fail_closed() {
        let path = temporary_path("tamper");
        let store = outbox(&path);
        store.initialize().unwrap();
        store.enqueue("request-1", b"signed-one", 10, 100).unwrap();
        assert_eq!(
            store.enqueue("request-1", b"signed-one", 10, 100).unwrap(),
            EnqueueOutcome::AlreadyPresent { sequence: 0 }
        );
        assert!(store.enqueue("request-1", b"changed", 10, 100).is_err());
        let wrong = CorporateOutbox::new(&path, b"different valid secret", 16, 4096).unwrap();
        assert!(wrong.summaries().is_err());

        let mut raw = fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        fs::write(&path, raw).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(store.summaries().is_err());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn service_timestamped_retry_keeps_the_original_acceptance_time() {
        let path = temporary_path("first-seen");
        let store = outbox(&path);
        store.initialize().unwrap();
        assert_eq!(
            store
                .enqueue_first_seen("request-1", b"signed-one", 100, 200)
                .unwrap(),
            EnqueueOutcome::Enqueued { sequence: 0 }
        );
        assert_eq!(
            store
                .enqueue_first_seen("request-1", b"signed-one", 150, 200)
                .unwrap(),
            EnqueueOutcome::AlreadyPresent { sequence: 0 }
        );
        let summary = store.summaries().unwrap().remove(0);
        assert_eq!(summary.accepted_at, 100);
        assert!(store
            .enqueue_first_seen("request-1", b"signed-one", 150, 201)
            .is_err());
    }

    #[test]
    fn expiry_requires_canonical_release_before_pruning() {
        let path = temporary_path("expiry");
        let store = outbox(&path);
        store.initialize().unwrap();
        store.enqueue("request-1", b"signed-one", 10, 20).unwrap();
        assert!(matches!(
            store.claim_next(20, true, 5).unwrap(),
            Some(QueueAction::Expire { .. })
        ));
        assert_eq!(store.prune_finalized(100).unwrap(), 0);
        store
            .mark_release_pending("request-1", digest(b"signed-one"), 21)
            .unwrap();
        store
            .record_release(
                "request-1",
                digest(b"signed-one"),
                canonical(b"signed-one", "release-tx-1", 22),
            )
            .unwrap();
        assert_eq!(store.prune_finalized(23).unwrap(), 1);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn pre_reserve_abort_is_terminal_without_a_synthetic_ledger_receipt() {
        let path = temporary_path("pre-reserve-abort");
        let store = outbox(&path);
        store.initialize().unwrap();
        store.enqueue("request-1", b"signed-one", 10, 100).unwrap();
        assert!(matches!(
            store.claim_next(11, true, 5).unwrap(),
            Some(QueueAction::Dispatch(_))
        ));
        store
            .record_pre_reserve_abort("request-1", digest(b"signed-one"), 12)
            .unwrap();
        assert_eq!(store.metrics(13).unwrap().aborted_before_reserve, 1);
        assert_eq!(
            store.metrics(13).unwrap().oldest_unfinalized_age_seconds,
            None
        );
        assert_eq!(store.claim_next(20, true, 5).unwrap(), None);
        assert_eq!(store.prune_finalized(13).unwrap(), 1);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn reviewed_request_can_abort_after_the_participant_proves_no_reserve_exists() {
        let path = temporary_path("reviewed-pre-reserve-abort");
        let store = outbox(&path);
        store.initialize().unwrap();
        store.enqueue("request-1", b"signed-one", 10, 100).unwrap();
        store
            .mark_manual_review(
                "request-1",
                digest(b"signed-one"),
                11,
                "automatic MPC dispatch retry limit reached",
            )
            .unwrap();

        store
            .record_pre_reserve_abort("request-1", digest(b"signed-one"), 12)
            .unwrap();

        let metrics = store.metrics(13).unwrap();
        assert_eq!(metrics.manual_review, 0);
        assert_eq!(metrics.aborted_before_reserve, 1);
        assert_eq!(metrics.oldest_unfinalized_age_seconds, None);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn expired_unreserved_request_can_be_finalized_without_a_ledger_receipt() {
        let path = temporary_path("expired-pre-reserve-abort");
        let store = outbox(&path);
        store.initialize().unwrap();
        store.enqueue("request-1", b"signed-one", 10, 20).unwrap();
        assert!(matches!(
            store.claim_next(20, false, 5).unwrap(),
            Some(QueueAction::Expire { .. })
        ));
        store
            .record_pre_reserve_abort("request-1", digest(b"signed-one"), 21)
            .unwrap();
        let metrics = store.metrics(22).unwrap();
        assert_eq!(metrics.expired, 0);
        assert_eq!(metrics.aborted_before_reserve, 1);
        assert_eq!(metrics.oldest_unfinalized_age_seconds, None);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn pending_release_can_finish_when_canonical_reconciliation_proves_no_reserve() {
        let path = temporary_path("pending-release-pre-reserve-abort");
        let store = outbox(&path);
        store.initialize().unwrap();
        store.enqueue("request-1", b"signed-one", 10, 20).unwrap();
        assert!(matches!(
            store.claim_next(20, false, 5).unwrap(),
            Some(QueueAction::Expire { .. })
        ));
        store
            .mark_release_pending("request-1", digest(b"signed-one"), 20)
            .unwrap();
        // Pending means the result was unknown, not that a reserve existed.
        // Only the authenticated corporate reconciler calls this after reads.
        store
            .record_pre_reserve_abort("request-1", digest(b"signed-one"), 21)
            .unwrap();
        store
            .record_pre_reserve_abort("request-1", digest(b"signed-one"), 22)
            .unwrap();
        let metrics = store.metrics(23).unwrap();
        assert_eq!(metrics.release_pending, 0);
        assert_eq!(metrics.aborted_before_reserve, 1);
        assert_eq!(store.claim_next(24, true, 5).unwrap(), None);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn expiry_is_processed_even_while_the_mpc_quorum_is_down() {
        let path = temporary_path("expiry-no-quorum");
        let store = outbox(&path);
        store.initialize().unwrap();
        store.enqueue("request-1", b"signed-one", 10, 20).unwrap();
        assert!(matches!(
            store.claim_next(20, false, 5).unwrap(),
            Some(QueueAction::Expire { .. })
        ));
        assert_eq!(store.metrics(21).unwrap().expired, 1);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn expired_release_is_retried_until_a_canonical_terminal_state_is_recorded() {
        let path = temporary_path("expiry-release-retry");
        let store = outbox(&path);
        store.initialize().unwrap();
        store.enqueue("request-1", b"signed-one", 10, 20).unwrap();

        assert!(matches!(
            store.claim_next(20, false, 5).unwrap(),
            Some(QueueAction::Expire { .. })
        ));
        assert!(matches!(
            store.claim_next(21, false, 5).unwrap(),
            Some(QueueAction::Expire { .. })
        ));
        store
            .mark_release_pending("request-1", digest(b"signed-one"), 22)
            .unwrap();
        assert!(matches!(
            store.claim_next(23, false, 5).unwrap(),
            Some(QueueAction::Expire { .. })
        ));

        store
            .record_release(
                "request-1",
                digest(b"signed-one"),
                canonical(b"signed-one", "release-tx-1", 24),
            )
            .unwrap();
        assert_eq!(store.claim_next(25, false, 5).unwrap(), None);
        assert_eq!(store.metrics(25).unwrap().released, 1);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn fixed_cover_schedule_emits_dummy_and_real_slots() {
        let path = temporary_path("cover");
        let store = outbox(&path);
        store.initialize().unwrap();
        let first = store.claim_cover_slot(100, true, 5, 10).unwrap().unwrap();
        assert_eq!(first.slot, 0);
        assert_eq!(first.action, CoverAction::Dummy);
        assert!(store.claim_cover_slot(109, true, 5, 10).unwrap().is_none());
        store.enqueue("request-1", b"signed-one", 101, 200).unwrap();
        let second = store.claim_cover_slot(110, true, 5, 10).unwrap().unwrap();
        assert_eq!(second.slot, 1);
        assert!(matches!(second.action, CoverAction::Real(_)));
        let third = store.claim_cover_slot(120, false, 5, 10).unwrap().unwrap();
        assert_eq!(third.action, CoverAction::Dummy);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn canonical_settlement_is_the_only_execution_finalizer() {
        let path = temporary_path("settlement");
        let store = outbox(&path);
        store.initialize().unwrap();
        store.enqueue("request-1", b"signed-one", 10, 100).unwrap();
        store.claim_next(11, true, 5).unwrap();
        assert_eq!(store.prune_finalized(1_000).unwrap(), 0);
        let receipt = canonical(b"signed-one", "settlement-tx-1", 12);
        store
            .record_settlement("request-1", digest(b"signed-one"), receipt.clone())
            .unwrap();
        let mut retry_receipt = receipt.clone();
        retry_receipt.finalized_at = 99;
        store
            .record_settlement("request-1", digest(b"signed-one"), retry_receipt)
            .unwrap();
        assert_eq!(store.prune_finalized(13).unwrap(), 1);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
