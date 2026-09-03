//! Cross-domain settlement primitives for independent DeFMI ledgers.
//!
//! A cross-domain settlement has a different public leg identifier on every
//! ledger.  The relationship between the identifiers is carried only in a
//! destination-bound finality receipt.  This avoids publishing one global
//! settlement identifier while still preventing replay and re-ordering.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const LEG_ID_DOMAIN: &[u8] = b"qomm:defmi:cross-domain-leg:v1";
const RECORD_DOMAIN: &[u8] = b"qomm:defmi:cross-domain-record:v1";
const RECEIPT_DOMAIN: &[u8] = b"qomm:defmi:cross-domain-receipt:v1";
const HANDLE_DOMAIN: &[u8] = b"qomm:defmi:cross-domain-handle:v1";
const ASSET_DOMAIN: &[u8] = b"qomm:defmi:cross-domain-asset:v1";

pub type DomainId = [u8; 32];
pub type LegId = [u8; 32];
pub type Commitment = [u8; 32];

/// Identifies one independently-finalising DeFMI deployment.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Domain {
    pub network_id: u32,
    pub chain_id: DomainId,
    pub defmi_id: DomainId,
}

impl Domain {
    pub fn id(&self) -> DomainId {
        canonical_hash(b"qomm:defmi:domain:v1", self)
    }
}

/// Derives an unlinkable public identifier for one ledger leg.
///
/// `settlement_secret` MUST be sampled uniformly and kept outside both public
/// ledgers. `side` separates the two legs even if both domains are identical.
pub fn derive_leg_id(settlement_secret: &[u8; 32], domain: &Domain, side: u8) -> LegId {
    let mut hasher = Sha256::new();
    hasher.update(LEG_ID_DOMAIN);
    hasher.update(settlement_secret);
    hasher.update(domain.id());
    hasher.update([side]);
    hasher.finalize().into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegStatus {
    Prepared,
    Armed,
    Claimed,
    Refunded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptEvent {
    Prepared,
    Claimed,
}

/// Public data committed when value is reserved on one DeFMI ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepareLeg {
    pub local_domain: Domain,
    pub remote_domain: Domain,
    pub local_leg_id: LegId,
    /// Destination-local opaque values derived by the private paired zkPI.
    /// They reveal neither the source leg identifier nor a common trade ID.
    pub expected_remote_prepare_binding: Commitment,
    pub expected_remote_claim_binding: Commitment,
    /// Commitments to the pseudonymous source, escrow and destination handles.
    pub owner_commitment: Commitment,
    pub escrow_commitment: Commitment,
    pub destination_commitment: Commitment,
    pub asset_commitment: Commitment,
    pub amount_commitment: Commitment,
    /// Destination-specific projection of the private paired zkPI instruction.
    /// The two ledgers intentionally store different values.
    pub local_instruction_digest: Commitment,
    /// Destination-specific digest of the zero-knowledge DvP relation proof.
    pub local_relation_proof_digest: Commitment,
    /// Exact local state transitions used to reserve, deliver and refund.
    pub reserve_transfer_digest: Commitment,
    pub claim_transfer_digest: Commitment,
    pub refund_transfer_digest: Commitment,
    /// The remote leg must be proven prepared no later than this timestamp.
    pub arm_deadline: u64,
    /// Operational target for releasing both claims. Once a leg is armed this
    /// is deliberately not a refund deadline: safety requires the leg to stay
    /// claimable until its peer catches up.
    pub claim_deadline: u64,
    /// Refund is allowed at or after this timestamp.
    pub refund_after: u64,
    /// Digest of the private release condition (for example an adaptor point).
    pub release_condition: Commitment,
}

impl PrepareLeg {
    pub fn validate(&self) -> Result<(), CrossDomainError> {
        if self.local_domain == self.remote_domain {
            return Err(CrossDomainError::SameDomain);
        }
        if !(self.arm_deadline < self.claim_deadline && self.claim_deadline < self.refund_after) {
            return Err(CrossDomainError::InvalidDeadlines);
        }
        for value in [
            self.owner_commitment,
            self.escrow_commitment,
            self.destination_commitment,
            self.asset_commitment,
            self.amount_commitment,
            self.local_instruction_digest,
            self.local_relation_proof_digest,
            self.reserve_transfer_digest,
            self.claim_transfer_digest,
            self.refund_transfer_digest,
            self.release_condition,
            self.expected_remote_prepare_binding,
            self.expected_remote_claim_binding,
        ] {
            if value == [0u8; 32] {
                return Err(CrossDomainError::MissingCommitment);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Commitment {
        canonical_hash(RECORD_DOMAIN, self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegRecord {
    pub prepare: PrepareLeg,
    pub status: LegStatus,
    pub prepared_at: u64,
    pub armed_at: Option<u64>,
    pub claimed_at: Option<u64>,
    pub refunded_at: Option<u64>,
    pub remote_prepare_receipt: Option<Commitment>,
    pub remote_claim_receipt: Option<Commitment>,
}

impl LegRecord {
    pub fn digest(&self) -> Commitment {
        canonical_hash(RECORD_DOMAIN, self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeMember {
    pub member_id: [u8; 32],
    pub public_key: [u8; 32],
    pub weight: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Committee {
    pub domain: Domain,
    pub epoch: u64,
    pub quorum_weight: u64,
    /// Strictly sorted by `member_id` for one canonical representation.
    pub members: Vec<CommitteeMember>,
}

impl Committee {
    pub fn validate(&self) -> Result<(), CrossDomainError> {
        if self.quorum_weight == 0 {
            return Err(CrossDomainError::InvalidCommittee);
        }
        let mut total = 0u64;
        let mut previous = None;
        for member in &self.members {
            if previous.is_some_and(|id| id >= member.member_id) || member.weight == 0 {
                return Err(CrossDomainError::InvalidCommittee);
            }
            previous = Some(member.member_id);
            VerifyingKey::from_bytes(&member.public_key)
                .map_err(|_| CrossDomainError::InvalidCommittee)?;
            total = total
                .checked_add(member.weight)
                .ok_or(CrossDomainError::ArithmeticOverflow)?;
        }
        if total < self.quorum_weight {
            return Err(CrossDomainError::InvalidCommittee);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptSignature {
    pub member_id: [u8; 32],
    pub signature: Vec<u8>,
}

/// Destination-bound proof of an event finalised by the source DeFMI.
///
/// The receipt contains no source-leg identifier or source-record digest. The
/// MPC quorum supplies a destination-specific opaque event binding derived
/// from the private paired zkPI. A public receipt therefore cannot be joined
/// to a source-ledger record by equality.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityReceipt {
    pub source_domain: Domain,
    pub destination_domain: Domain,
    pub destination_leg_id: LegId,
    pub event_binding: Commitment,
    pub event: ReceiptEvent,
    pub source_state_root: Commitment,
    /// Exact accepted Avalanche block whose canonical state is being signed.
    pub source_block_id: Commitment,
    pub source_height: u64,
    pub finalised_at: u64,
    pub validator_epoch: u64,
    pub signatures: Vec<ReceiptSignature>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalityContext {
    pub destination_domain: Domain,
    pub destination_leg_id: LegId,
    pub event_binding: Commitment,
    pub source_state_root: Commitment,
    pub source_block_id: Commitment,
    pub source_height: u64,
    pub finalised_at: u64,
    pub validator_epoch: u64,
}

impl FinalityReceipt {
    pub fn signing_digest(&self) -> Commitment {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            source_domain: &'a Domain,
            destination_domain: &'a Domain,
            destination_leg_id: &'a LegId,
            event_binding: &'a Commitment,
            event: ReceiptEvent,
            source_state_root: &'a Commitment,
            source_block_id: &'a Commitment,
            source_height: u64,
            finalised_at: u64,
            validator_epoch: u64,
        }
        canonical_hash(
            RECEIPT_DOMAIN,
            &Unsigned {
                source_domain: &self.source_domain,
                destination_domain: &self.destination_domain,
                destination_leg_id: &self.destination_leg_id,
                event_binding: &self.event_binding,
                event: self.event,
                source_state_root: &self.source_state_root,
                source_block_id: &self.source_block_id,
                source_height: self.source_height,
                finalised_at: self.finalised_at,
                validator_epoch: self.validator_epoch,
            },
        )
    }

    pub fn digest(&self) -> Commitment {
        canonical_hash(RECEIPT_DOMAIN, self)
    }

    pub fn verify(&self, committee: &Committee) -> Result<(), CrossDomainError> {
        committee.validate()?;
        if committee.domain != self.source_domain || committee.epoch != self.validator_epoch {
            return Err(CrossDomainError::WrongCommittee);
        }
        let message = self.signing_digest();
        let mut seen = BTreeSet::new();
        let mut weight = 0u64;
        for approval in &self.signatures {
            if !seen.insert(approval.member_id) {
                return Err(CrossDomainError::DuplicateSigner);
            }
            let member = committee
                .members
                .iter()
                .find(|member| member.member_id == approval.member_id)
                .ok_or(CrossDomainError::UnknownSigner)?;
            let key = VerifyingKey::from_bytes(&member.public_key)
                .map_err(|_| CrossDomainError::InvalidSignature)?;
            let signature = Signature::from_slice(&approval.signature)
                .map_err(|_| CrossDomainError::InvalidSignature)?;
            key.verify(&message, &signature)
                .map_err(|_| CrossDomainError::InvalidSignature)?;
            weight = weight
                .checked_add(member.weight)
                .ok_or(CrossDomainError::ArithmeticOverflow)?;
        }
        if weight < committee.quorum_weight {
            return Err(CrossDomainError::InsufficientQuorum);
        }
        Ok(())
    }
}

/// Deterministic state machine embedded by each DeFMI deployment.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainBook {
    #[serde(with = "leg_map_wire")]
    pub legs: BTreeMap<LegId, LegRecord>,
    pub consumed_receipts: BTreeSet<Commitment>,
}

impl CrossDomainBook {
    pub fn is_empty(&self) -> bool {
        self.legs.is_empty() && self.consumed_receipts.is_empty()
    }

    pub fn validate(&self) -> Result<(), CrossDomainError> {
        for (id, record) in &self.legs {
            record.prepare.validate()?;
            if id != &record.prepare.local_leg_id
                || record.prepared_at > record.prepare.arm_deadline
            {
                return Err(CrossDomainError::InvalidStoredState);
            }
            let valid = match record.status {
                LegStatus::Prepared => {
                    record.armed_at.is_none()
                        && record.claimed_at.is_none()
                        && record.refunded_at.is_none()
                        && record.remote_prepare_receipt.is_none()
                        && record.remote_claim_receipt.is_none()
                }
                LegStatus::Armed => {
                    record.armed_at.is_some()
                        && record.claimed_at.is_none()
                        && record.refunded_at.is_none()
                        && record.remote_prepare_receipt.is_some()
                        && record.remote_claim_receipt.is_none()
                }
                LegStatus::Claimed => {
                    record.armed_at.is_some()
                        && record.claimed_at.is_some()
                        && record.refunded_at.is_none()
                        && record.remote_prepare_receipt.is_some()
                }
                LegStatus::Refunded => {
                    record.armed_at.is_none()
                        && record.claimed_at.is_none()
                        && record.refunded_at.is_some()
                        && record.remote_prepare_receipt.is_none()
                        && record.remote_claim_receipt.is_none()
                }
            };
            if !valid {
                return Err(CrossDomainError::InvalidStoredState);
            }
            for digest in [record.remote_prepare_receipt, record.remote_claim_receipt]
                .into_iter()
                .flatten()
            {
                if !self.consumed_receipts.contains(&digest) {
                    return Err(CrossDomainError::InvalidStoredState);
                }
            }
        }
        Ok(())
    }

    pub fn prepare(
        &mut self,
        prepare: PrepareLeg,
        now: u64,
    ) -> Result<Commitment, CrossDomainError> {
        prepare.validate()?;
        if now > prepare.arm_deadline {
            return Err(CrossDomainError::ArmDeadlinePassed);
        }
        if self.legs.contains_key(&prepare.local_leg_id) {
            return Err(CrossDomainError::DuplicateLeg);
        }
        let id = prepare.local_leg_id;
        let record = LegRecord {
            prepare,
            status: LegStatus::Prepared,
            prepared_at: now,
            armed_at: None,
            claimed_at: None,
            refunded_at: None,
            remote_prepare_receipt: None,
            remote_claim_receipt: None,
        };
        let digest = record.digest();
        self.legs.insert(id, record);
        Ok(digest)
    }

    /// Arms a local leg after the counterparty DeFMI proves its leg finalised.
    pub fn arm(
        &mut self,
        local_leg_id: LegId,
        remote_receipt: &FinalityReceipt,
        remote_committee: &Committee,
        now: u64,
    ) -> Result<Commitment, CrossDomainError> {
        let receipt_digest = remote_receipt.digest();
        if self.consumed_receipts.contains(&receipt_digest) {
            return Err(CrossDomainError::ReceiptAlreadyConsumed);
        }
        let record = self
            .legs
            .get_mut(&local_leg_id)
            .ok_or(CrossDomainError::UnknownLeg)?;
        if record.status != LegStatus::Prepared {
            return Err(CrossDomainError::InvalidTransition);
        }
        if now > record.prepare.arm_deadline {
            return Err(CrossDomainError::ArmDeadlinePassed);
        }
        validate_receipt_binding(record, remote_receipt, ReceiptEvent::Prepared)?;
        if remote_receipt.finalised_at > record.prepare.arm_deadline
            || remote_receipt.finalised_at > now
        {
            return Err(CrossDomainError::ReceiptOutsideWindow);
        }
        remote_receipt.verify(remote_committee)?;
        record.status = LegStatus::Armed;
        record.armed_at = Some(now);
        record.remote_prepare_receipt = Some(receipt_digest);
        self.consumed_receipts.insert(receipt_digest);
        Ok(record.digest())
    }

    /// Claims an armed leg. `release_witness` is checked against the committed
    /// private release condition without storing the witness itself.
    pub fn claim(
        &mut self,
        local_leg_id: LegId,
        release_witness: &[u8],
        now: u64,
    ) -> Result<Commitment, CrossDomainError> {
        let record = self
            .legs
            .get_mut(&local_leg_id)
            .ok_or(CrossDomainError::UnknownLeg)?;
        if record.status != LegStatus::Armed {
            return Err(CrossDomainError::InvalidTransition);
        }
        if hash_release_witness(release_witness) != record.prepare.release_condition {
            return Err(CrossDomainError::InvalidReleaseWitness);
        }
        record.status = LegStatus::Claimed;
        record.claimed_at = Some(now);
        Ok(record.digest())
    }

    /// Records proof that the remote leg claimed. This is optional for value
    /// transfer, but supplies a final, replay-protected audit receipt.
    pub fn observe_remote_claim(
        &mut self,
        local_leg_id: LegId,
        remote_receipt: &FinalityReceipt,
        remote_committee: &Committee,
        now: u64,
    ) -> Result<Commitment, CrossDomainError> {
        let receipt_digest = remote_receipt.digest();
        if self.consumed_receipts.contains(&receipt_digest) {
            return Err(CrossDomainError::ReceiptAlreadyConsumed);
        }
        let record = self
            .legs
            .get_mut(&local_leg_id)
            .ok_or(CrossDomainError::UnknownLeg)?;
        if record.status != LegStatus::Claimed {
            return Err(CrossDomainError::InvalidTransition);
        }
        validate_receipt_binding(record, remote_receipt, ReceiptEvent::Claimed)?;
        if remote_receipt.finalised_at > now {
            return Err(CrossDomainError::ReceiptOutsideWindow);
        }
        remote_receipt.verify(remote_committee)?;
        record.remote_claim_receipt = Some(receipt_digest);
        self.consumed_receipts.insert(receipt_digest);
        Ok(record.digest())
    }

    /// Returns the reserved value if the cross-domain operation did not claim.
    pub fn refund(
        &mut self,
        local_leg_id: LegId,
        now: u64,
    ) -> Result<Commitment, CrossDomainError> {
        let record = self
            .legs
            .get_mut(&local_leg_id)
            .ok_or(CrossDomainError::UnknownLeg)?;
        // Once both sides are armed, permitting a local timeout refund can
        // leave one ledger claimed while the other refunds during a partition.
        // DeFMI chooses atomic safety over non-blocking progress: an armed leg
        // remains claimable and cannot be unilaterally refunded.
        if record.status != LegStatus::Prepared {
            return Err(CrossDomainError::InvalidTransition);
        }
        if now < record.prepare.refund_after {
            return Err(CrossDomainError::RefundTooEarly);
        }
        record.status = LegStatus::Refunded;
        record.refunded_at = Some(now);
        Ok(record.digest())
    }

    pub fn receipt_for(
        &self,
        local_leg_id: LegId,
        event: ReceiptEvent,
        context: FinalityContext,
    ) -> Result<FinalityReceipt, CrossDomainError> {
        let record = self
            .legs
            .get(&local_leg_id)
            .ok_or(CrossDomainError::UnknownLeg)?;
        let status_matches = matches!(
            (event, record.status),
            (
                ReceiptEvent::Prepared,
                LegStatus::Prepared | LegStatus::Armed | LegStatus::Claimed
            ) | (ReceiptEvent::Claimed, LegStatus::Claimed)
        );
        if !status_matches || context.destination_domain != record.prepare.remote_domain {
            return Err(CrossDomainError::InvalidReceipt);
        }
        if context.event_binding == [0u8; 32]
            || context.destination_leg_id == [0u8; 32]
            || context.source_state_root == [0u8; 32]
            || context.source_block_id == [0u8; 32]
            || context.source_height == 0
            || context.finalised_at == 0
            || context.validator_epoch == 0
        {
            return Err(CrossDomainError::InvalidReceipt);
        }
        Ok(FinalityReceipt {
            source_domain: record.prepare.local_domain.clone(),
            destination_domain: context.destination_domain,
            destination_leg_id: context.destination_leg_id,
            event_binding: context.event_binding,
            event,
            source_state_root: context.source_state_root,
            source_block_id: context.source_block_id,
            source_height: context.source_height,
            finalised_at: context.finalised_at,
            validator_epoch: context.validator_epoch,
            signatures: Vec::new(),
        })
    }
}

pub fn hash_release_witness(witness: &[u8]) -> Commitment {
    let mut hasher = Sha256::new();
    hasher.update(b"qomm:defmi:cross-domain-release:v1");
    hasher.update((witness.len() as u64).to_be_bytes());
    hasher.update(witness);
    hasher.finalize().into()
}

pub fn handle_commitment(handle: &[u8; 32]) -> Commitment {
    canonical_hash(HANDLE_DOMAIN, handle)
}

pub fn asset_id_commitment(asset_id: &[u8; 32]) -> Commitment {
    canonical_hash(ASSET_DOMAIN, asset_id)
}

fn validate_receipt_binding(
    record: &LegRecord,
    receipt: &FinalityReceipt,
    expected_event: ReceiptEvent,
) -> Result<(), CrossDomainError> {
    if receipt.source_domain != record.prepare.remote_domain
        || receipt.destination_domain != record.prepare.local_domain
        || receipt.destination_leg_id != record.prepare.local_leg_id
        || receipt.event != expected_event
    {
        return Err(CrossDomainError::WrongReceiptBinding);
    }
    let expected_binding = match expected_event {
        ReceiptEvent::Prepared => record.prepare.expected_remote_prepare_binding,
        ReceiptEvent::Claimed => record.prepare.expected_remote_claim_binding,
    };
    if receipt.event_binding != expected_binding
        || receipt.source_state_root == [0u8; 32]
        || receipt.source_block_id == [0u8; 32]
        || receipt.source_height == 0
        || receipt.finalised_at == 0
        || receipt.validator_epoch == 0
    {
        return Err(CrossDomainError::InvalidReceipt);
    }
    Ok(())
}

fn canonical_hash<T: Serialize>(domain: &[u8], value: &T) -> Commitment {
    let encoded = serde_json::to_vec(value).expect("serialising protocol value cannot fail");
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(encoded);
    hasher.finalize().into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrossDomainError {
    SameDomain,
    InvalidDeadlines,
    MissingCommitment,
    InvalidCommittee,
    ArithmeticOverflow,
    DuplicateLeg,
    UnknownLeg,
    InvalidTransition,
    ArmDeadlinePassed,
    RefundTooEarly,
    ReceiptOutsideWindow,
    WrongReceiptBinding,
    InvalidReceipt,
    ReceiptAlreadyConsumed,
    WrongCommittee,
    UnknownSigner,
    DuplicateSigner,
    InvalidSignature,
    InsufficientQuorum,
    InvalidReleaseWitness,
    InvalidStoredState,
}

impl fmt::Display for CrossDomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::SameDomain => "source and destination domains must differ",
                Self::InvalidDeadlines => "deadlines must satisfy arm < claim < refund",
                Self::MissingCommitment => "cross-domain prepare contains a zero commitment",
                Self::InvalidCommittee => "invalid finality committee",
                Self::ArithmeticOverflow => "arithmetic overflow",
                Self::DuplicateLeg => "leg already exists",
                Self::UnknownLeg => "unknown leg",
                Self::InvalidTransition => "invalid cross-domain state transition",
                Self::ArmDeadlinePassed => "arm deadline has passed",
                Self::RefundTooEarly => "refund is not yet available",
                Self::ReceiptOutsideWindow => "receipt is outside the accepted time window",
                Self::WrongReceiptBinding =>
                    "receipt is not bound to this source, destination and leg pair",
                Self::InvalidReceipt => "invalid finality receipt",
                Self::ReceiptAlreadyConsumed => "finality receipt was already consumed",
                Self::WrongCommittee => "receipt committee domain or epoch does not match",
                Self::UnknownSigner => "receipt contains an unknown signer",
                Self::DuplicateSigner => "receipt contains a duplicate signer",
                Self::InvalidSignature => "receipt signature is invalid",
                Self::InsufficientQuorum => "receipt does not have finality quorum",
                Self::InvalidReleaseWitness =>
                    "release witness does not satisfy the committed condition",
                Self::InvalidStoredState => "stored cross-domain state violates its invariants",
            }
        )
    }
}

impl std::error::Error for CrossDomainError {}

mod leg_map_wire {
    use super::{LegId, LegRecord};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    pub fn serialize<S>(
        value: &BTreeMap<LegId, LegRecord>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.iter().collect::<Vec<_>>().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<LegId, LegRecord>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let rows = Vec::<(LegId, LegRecord)>::deserialize(deserializer)?;
        let mut value = BTreeMap::new();
        for (id, record) in rows {
            if value.insert(id, record).is_some() {
                return Err(serde::de::Error::custom(
                    "cross-domain state repeats a leg identifier",
                ));
            }
        }
        Ok(value)
    }
}
