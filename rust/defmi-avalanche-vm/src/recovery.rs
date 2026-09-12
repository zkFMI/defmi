//! Offline PQ-authorized archival checkpoints and fresh-quorum recovery.
//!
//! A checkpoint attests to retained bytes at its issue time. It never upgrades
//! the historical authenticity of classical signatures inside those bytes.
//! Trust anchors and the expected checkpoint digest must come from outside the
//! untrusted backup. Live validator activation remains the host's responsibility.
use crate::{
    application::ApplicationRuntime,
    id::Id,
    state_sync::{decode_snapshot, DecodedSnapshot, StateSummary},
};
use defmi::facility::{NodeApproval, QuorumApproval, QuorumAuthorizer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zkfmi_crypto::suite::Suite;

pub const CHECKPOINT_PROTOCOL: &str = "defmi-hybrid-governance-v2";
pub const MAX_CHECKPOINT_BYTES: usize = 1 << 20;
pub const MAX_ARCHIVE_BYTES: usize = 64 << 20;
const CHECKPOINT_DOMAIN: &[u8] = b"QOMM:DEFMI:ARCHIVE-CHECKPOINT:v1";
const RESTORE_DOMAIN: &[u8] = b"QOMM:DEFMI:RESTORE-AUTHORIZATION:v1";

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(domain)
        .chain_update((bytes.len() as u64).to_be_bytes())
        .chain_update(bytes)
        .finalize()
        .into()
}
fn json_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32], String> {
    Ok(digest(
        domain,
        &serde_json::to_vec(value).map_err(|error| error.to_string())?,
    ))
}
fn hex32(raw: &str) -> Result<[u8; 32], String> {
    if raw.len() != 64
        || raw
            .bytes()
            .any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase())
    {
        return Err("expected a canonical lowercase 32-byte hexadecimal field".into());
    }
    hex::decode(raw)
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "expected a 32-byte field".into())
}

/// Same JSON shape used by the existing governance RPC boundary.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalWire {
    pub statement: String,
    pub signer_epoch: u64,
    pub suite: Suite,
    pub committee_digest: String,
    pub domain: String,
    pub before_root: String,
    pub approvals: Vec<NodeApprovalWire>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeApprovalWire {
    #[serde(rename = "nodeID")]
    pub node_id: String,
    pub signature: String,
}
impl From<&QuorumApproval> for ApprovalWire {
    fn from(approval: &QuorumApproval) -> Self {
        Self {
            statement: hex::encode(approval.statement),
            signer_epoch: approval.signer_epoch,
            suite: approval.suite,
            committee_digest: hex::encode(approval.committee_digest),
            domain: approval.domain.clone(),
            before_root: hex::encode(approval.before_root),
            approvals: approval
                .approvals
                .iter()
                .map(|item| NodeApprovalWire {
                    node_id: item.node_id.clone(),
                    signature: hex::encode(&item.signature),
                })
                .collect(),
        }
    }
}
impl ApprovalWire {
    pub fn approval(&self) -> Result<QuorumApproval, String> {
        if self.approvals.len() > 64 || self.domain.len() > 128 {
            return Err("checkpoint approval exceeds bounds".into());
        }
        Ok(QuorumApproval {
            statement: hex32(&self.statement)?,
            signer_epoch: self.signer_epoch,
            suite: self.suite,
            committee_digest: hex32(&self.committee_digest)?,
            domain: self.domain.clone(),
            before_root: hex32(&self.before_root)?,
            approvals: self
                .approvals
                .iter()
                .map(|item| {
                    if item.node_id.len() > 128 || item.signature.len() != 2 * (64 + 3309) {
                        return Err("checkpoint requires complete hybrid node signatures".into());
                    }
                    let signature =
                        hex::decode(&item.signature).map_err(|error| error.to_string())?;
                    if hex::encode(&signature) != item.signature {
                        return Err("noncanonical checkpoint signature".into());
                    }
                    Ok(NodeApproval {
                        node_id: item.node_id.clone(),
                        signature,
                    })
                })
                .collect::<Result<_, String>>()?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointStatement {
    pub version: u16,
    pub authority_protocol: String,
    /// Canonical state-sync summary bytes, encoded as lowercase hexadecimal.
    pub summary: String,
    pub archived_records_digest: [u8; 32],
    pub issued_at: u64,
}
impl CheckpointStatement {
    pub fn prepare(
        summary: &StateSummary,
        snapshot: &[u8],
        archive: &[u8],
        issued_at: u64,
        application: &dyn ApplicationRuntime,
    ) -> Result<Self, String> {
        let decoded = decode_snapshot(summary, snapshot)?;
        crate::application::validate_host_state(application, &decoded.state)?;
        if archive.is_empty() || archive.len() > MAX_ARCHIVE_BYTES {
            return Err("archived records must contain 1..=64 MiB".into());
        }
        let value = Self {
            version: 1,
            authority_protocol: CHECKPOINT_PROTOCOL.into(),
            summary: hex::encode(summary.encode()?),
            archived_records_digest: digest(b"QOMM:DEFMI:ARCHIVED-RECORDS:v1", archive),
            issued_at,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<StateSummary, String> {
        if self.version != 1
            || self.authority_protocol != CHECKPOINT_PROTOCOL
            || self.summary.len() > 2048
            || self.issued_at == 0
            || self.issued_at > i64::MAX as u64
            || self.archived_records_digest == [0; 32]
        {
            return Err("unsupported or invalid checkpoint statement".into());
        }
        let raw = hex::decode(&self.summary).map_err(|error| error.to_string())?;
        if hex::encode(&raw) != self.summary {
            return Err("noncanonical checkpoint summary".into());
        }
        let summary = StateSummary::decode(&raw)?;
        if summary.timestamp as u64 > self.issued_at {
            return Err("checkpoint predates its state snapshot".into());
        }
        Ok(summary)
    }
    pub fn digest(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        json_digest(CHECKPOINT_DOMAIN, self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub statement: CheckpointStatement,
    pub approval: ApprovalWire,
}
impl Checkpoint {
    pub fn seal(
        statement: CheckpointStatement,
        approval: QuorumApproval,
        authority: &QuorumAuthorizer,
        now: u64,
    ) -> Result<Self, String> {
        // Creation requires a current authorization; archive verification later
        // uses independently pinned historical keys at the recorded issue time.
        let summary = statement.validate()?;
        if statement.issued_at > now
            || now.saturating_sub(statement.issued_at) > 300
            || authority.domain() != summary.chain_id.to_string()
            || !authority.at(statement.issued_at).verify(
                &statement.digest()?,
                &summary.state_root,
                &approval,
            )
            || !authority
                .at(now)
                .verify(&statement.digest()?, &summary.state_root, &approval)
        {
            return Err("checkpoint requires a current PQ governance quorum".into());
        }
        Ok(Self {
            statement,
            approval: ApprovalWire::from(&approval),
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.statement.validate()?;
        self.approval.approval()?;
        let raw = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if raw.len() > MAX_CHECKPOINT_BYTES {
            return Err("checkpoint exceeds one MiB".into());
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self, String> {
        if raw.is_empty() || raw.len() > MAX_CHECKPOINT_BYTES {
            return Err("invalid checkpoint size".into());
        }
        let value: Self = serde_json::from_slice(raw).map_err(|error| error.to_string())?;
        if value.encode()? != raw {
            return Err("checkpoint encoding is not canonical".into());
        }
        Ok(value)
    }
}

/// Obtain this policy through an authenticated operator channel, not the backup.
/// The exact pinned checkpoint plus minimum height rejects rollback. Fresh
/// authorization binds the recovery target, nonce and expiry; it cannot be
/// reused as a financial transaction or as a checkpoint publication approval.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicy {
    pub version: u16,
    pub network_id: u32,
    pub chain_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub expected_checkpoint: [u8; 32],
    pub minimum_height: u64,
    pub target_id: [u8; 32],
    pub nonce: [u8; 32],
    pub not_before: u64,
    pub expires_at: u64,
}
impl RecoveryPolicy {
    pub fn digest(&self) -> Result<[u8; 32], String> {
        if self.version != 1
            || self.chain_id == [0; 32]
            || self.genesis_hash == [0; 32]
            || self.expected_checkpoint == [0; 32]
            || self.target_id == [0; 32]
            || self.nonce == [0; 32]
            || self.not_before == 0
            || self.expires_at < self.not_before
            || self.expires_at > i64::MAX as u64
            || self.expires_at - self.not_before > 3600
        {
            return Err("invalid bounded recovery authorization policy".into());
        }
        json_digest(RESTORE_DOMAIN, self)
    }
}

/// All checks run before any output is returned or any persistent state changes.
/// Both authorities are caller-supplied trust anchors. Archived keys may have
/// expired since signing; a fresh, currently valid committee must approve the
/// recovery separately.
pub struct RecoveryTrust<'a> {
    pub policy: &'a RecoveryPolicy,
    pub historical_authority: &'a QuorumAuthorizer,
    pub current_authority: &'a QuorumAuthorizer,
    pub recovery_approval: &'a QuorumApproval,
    pub now: u64,
}

pub fn restore(
    checkpoint: &Checkpoint,
    snapshot: &[u8],
    archive: &[u8],
    trust: &RecoveryTrust<'_>,
    application: &dyn ApplicationRuntime,
) -> Result<DecodedSnapshot, String> {
    let RecoveryTrust {
        policy,
        historical_authority,
        current_authority,
        recovery_approval,
        now,
    } = trust;
    let now = *now;
    let restore_digest = policy.digest()?;
    let summary = checkpoint.statement.validate()?;
    if now < policy.not_before
        || now > policy.expires_at
        || checkpoint.statement.issued_at > now
        || checkpoint.statement.digest()? != policy.expected_checkpoint
        || !summary.matches_chain(
            policy.network_id,
            Id(policy.chain_id),
            Id(policy.genesis_hash),
        )
        || summary.height < policy.minimum_height
        || archive.is_empty()
        || archive.len() > MAX_ARCHIVE_BYTES
        || digest(b"QOMM:DEFMI:ARCHIVED-RECORDS:v1", archive)
            != checkpoint.statement.archived_records_digest
    {
        return Err("recovery backup does not match the trusted policy or archive".into());
    }
    let domain = Id(policy.chain_id).to_string();
    if historical_authority.domain() != domain || current_authority.domain() != domain {
        return Err("recovery governance domain differs from the pinned chain".into());
    }
    if !historical_authority
        .at(checkpoint.statement.issued_at)
        .verify(
            &policy.expected_checkpoint,
            &summary.state_root,
            &checkpoint.approval.approval()?,
        )
        || !current_authority.at(now).verify(
            &restore_digest,
            &summary.state_root,
            recovery_approval,
        )
    {
        return Err("recovery requires historical and fresh PQ quorum authorization".into());
    }
    let decoded = decode_snapshot(&summary, snapshot)?;
    crate::application::validate_host_state(application, &decoded.state)?;
    Ok(decoded)
}
