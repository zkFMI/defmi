//! Chain-neutral, durable DeFMI settlement facility.
//!
//! The existing crate contains the proof-aware settlement primitives.  This
//! replay/nullifier protection, k-of-n authorization, and signed receipts.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use merlin::Transcript;
use qomm_zk::pedersen::Pedersen;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::MAX_UNIX_TIME;

const DOMAIN: &[u8] = b"QOMM:DEFMI:FACILITY:v2";
const ASSET_DOMAIN: &[u8] = b"QOMM:DEFMI:ASSET:v1";
const ACCOUNT_DOMAIN: &[u8] = b"QOMM:DEFMI:ACCOUNT:v1";
const GUARANTOR_DOMAIN: &[u8] = b"QOMM:DEFMI:GUARANTOR:v1";
const CREDIT_GRANT_DOMAIN: &[u8] = b"QOMM:DEFMI:CREDIT:GRANT:v1";
const CREDIT_TRANSITION_DOMAIN: &[u8] = b"QOMM:DEFMI:CREDIT:TRANSITION:v1";
const CREDIT_CONTROL_DOMAIN: &[u8] = b"QOMM:DEFMI:CREDIT:CONTROL:v1";
const CREDIT_AMENDMENT_DOMAIN: &[u8] = b"QOMM:DEFMI:CREDIT:AMENDMENT:v1";
const CREDIT_AMENDMENT_CONTEXT_DOMAIN: &[u8] = b"QOMM:DEFMI:CREDIT:AMENDMENT:CONTEXT:v1";
const CREDIT_AMENDMENT_PROOF_DOMAIN: &[u8] = b"QOMM:DEFMI:CREDIT:AMENDMENT:PROOF:v1";
const CREDIT_RELATION_CONTEXT_DOMAIN: &[u8] = b"QOMM:DEFMI:CREDIT:RELATION:CONTEXT:v1";
const CREDIT_RELATION_PROOF_DOMAIN: &[u8] = b"QOMM:DEFMI:CREDIT:RELATION:PROOF:v1";
const CREDIT_THRESHOLD_DVP_RELATION_DOMAIN: &[u8] = b"QOMM:DEFMI:CREDIT:THRESHOLD-DVP-RELATION:v1";
const GUARANTOR_SIGNATURE_DOMAIN: &[u8] = b"QOMM:DEFMI:GUARANTOR:SIGNATURE:v1";
const RESERVATION_DOMAIN: &[u8] = b"QOMM:DEFMI:BOUND-RESERVATION:v1";
const RESERVATION_ESCROW_DOMAIN: &[u8] = b"QOMM:DEFMI:RESERVATION-ESCROW:v1";
const ADMISSION_BATCH_DOMAIN: &[u8] = b"QOMM:DEFMI:ADMISSION-BATCH:v1";
const ADMISSION_COMMITTEE_DOMAIN: &[u8] = b"QOMM:DEFMI:ADMISSION-COMMITTEE:v1";
const ADMISSION_ADVANCE_DOMAIN: &[u8] = b"QOMM:DEFMI:ADMISSION-ADVANCE:v1";
const PRODUCT_RELEASE_DOMAIN: &[u8] = b"QOMM:DEFMI:PRODUCT-RELEASE:v1";
const SETTLEMENT_DOMAIN: &[u8] = b"QOMM:DEFMI:SETTLEMENT:v1";
const PRODUCT_SETTLEMENT_DOMAIN: &[u8] = b"QOMM:DEFMI:PRODUCT-SETTLEMENT:v1";
const PRODUCT_SETTLEMENT_BATCH_DOMAIN: &[u8] = b"QOMM:DEFMI:PRODUCT-SETTLEMENT-BATCH:v1";
const RECEIPT_DOMAIN: &[u8] = b"QOMM:DEFMI:RECEIPT:v1";
// v2 commits the global operation replay set. In v1, two nodes could expose
// the same root while disagreeing about whether an operation ID was spent.
// v3 additionally commits the governance-pinned quote/zkPI verifier epochs.
const STATE_DOMAIN: &[u8] = b"QOMM:DEFMI:STATE:v3";
pub const ZERO: [u8; 32] = [0; 32];
pub type AccountState = ([u8; 32], [u8; 32], u64);

/// Governance-pinned resident-node receipt keys for one venue epoch. The
/// handoff may carry a copy of these bytes, but only this k-of-n-approved
/// DeFMI state is a trust root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionCommitteePlan {
    pub operation_id: [u8; 32],
    pub venue_id: [u8; 32],
    pub epoch: u64,
    /// Node order is fixed: index 0 verifies node 0, through index 6.
    pub node_keys: Vec<[u8; 32]>,
    pub valid_from: u64,
    pub valid_until: u64,
}

impl AdmissionCommitteePlan {
    pub fn body(&self) -> Result<Value, String> {
        if self.epoch == 0
            || self.valid_from == 0
            || self.valid_until < self.valid_from
            || self.valid_until > MAX_UNIX_TIME
            || self.node_keys.len() != qomm_transport::order::COMMITTEE_NODES
            || [self.operation_id, self.venue_id].contains(&ZERO)
            || self.node_keys.contains(&ZERO)
            || self.node_keys.iter().collect::<BTreeSet<_>>().len() != self.node_keys.len()
            || self
                .node_keys
                .iter()
                .any(|key| VerifyingKey::from_bytes(key).is_err())
        {
            return Err("admission committee is incomplete, duplicated, or invalid".into());
        }
        Ok(json!({
            "operation_id": hex::encode(self.operation_id),
            "venue_id": hex::encode(self.venue_id),
            "epoch": self.epoch,
            "node_keys": self.node_keys.iter().map(hex::encode).collect::<Vec<_>>(),
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(ADMISSION_COMMITTEE_DOMAIN, &self.body()?)
    }

    fn verifying_keys(&self) -> Result<Vec<VerifyingKey>, String> {
        self.node_keys
            .iter()
            .map(|key| {
                VerifyingKey::from_bytes(key)
                    .map_err(|_| "admission committee key is not canonical".to_string())
            })
            .collect()
    }
}

/// Fixed-population admission plan committed by the seven-node ordering
/// committee before any RFQ in the slot can reserve capacity.  Every entry is
/// an opaque digest: real RFQs and cover lanes have the same ledger shape.
/// The durable cursor is what prevents a coordinator from presenting sequence
/// 3 before sequence 2 merely because sequence 3 is more profitable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionBatchPlan {
    pub operation_id: [u8; 32],
    pub batch_id: [u8; 32],
    pub venue_id: [u8; 32],
    pub epoch: u64,
    pub slot: u64,
    pub batch_digest: [u8; 32],
    pub order_digest: [u8; 32],
    /// Global sequence assigned to position 0.  Older batches omit this from
    /// their signed body and therefore retain the legacy value `1`.
    pub first_sequence: u64,
    /// Position 0 is `first_sequence`, position 1 is
    /// `first_sequence + 1`, and so on.
    pub admission_digests: Vec<[u8; 32]>,
    pub expires_at: u64,
}

impl AdmissionBatchPlan {
    pub fn body(&self) -> Result<Value, String> {
        let unique_admissions = self
            .admission_digests
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if self.epoch == 0
            || self.first_sequence == 0
            || self.admission_digests.is_empty()
            || self
                .first_sequence
                .checked_add(self.admission_digests.len() as u64 - 1)
                .is_none()
            || self.expires_at == 0
            || self.expires_at > MAX_UNIX_TIME
            || self.admission_digests.len() > 4096
            || self.admission_digests.contains(&ZERO)
            || unique_admissions.len() != self.admission_digests.len()
            || [
                self.operation_id,
                self.batch_id,
                self.venue_id,
                self.batch_digest,
                self.order_digest,
            ]
            .contains(&ZERO)
        {
            return Err(
                "admission batch is incomplete, duplicated, or outside its fixed-population bound"
                    .into(),
            );
        }
        let mut body = json!({
            "operation_id": hex::encode(self.operation_id),
            "batch_id": hex::encode(self.batch_id),
            "venue_id": hex::encode(self.venue_id),
            "epoch": self.epoch,
            "slot": self.slot,
            "batch_digest": hex::encode(self.batch_digest),
            "order_digest": hex::encode(self.order_digest),
            "admission_digests": self.admission_digests.iter().map(hex::encode).collect::<Vec<_>>(),
            "expires_at": self.expires_at,
        });
        // Preserve the exact statement bytes of already-accepted legacy
        // sequence-1 batches while allowing later one-lane batches to carry a
        // venue-global sequence.
        if self.first_sequence != 1 {
            body.as_object_mut()
                .expect("admission batch body is an object")
                .insert("first_sequence".into(), json!(self.first_sequence));
        }
        Ok(body)
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(ADMISSION_BATCH_DOMAIN, &self.body()?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionBatchSnapshot {
    pub batch_id: [u8; 32],
    pub venue_id: [u8; 32],
    pub epoch: u64,
    pub slot: u64,
    pub batch_digest: [u8; 32],
    pub first_sequence: u64,
    pub population: u64,
    pub consumed: u64,
    pub expires_at: u64,
}

/// Consume one opaque cover lane.  The public statement deliberately has no
/// `is_cover` bit. Honest quorum nodes sign this only for a lane whose sealed
/// frame was cover traffic; a real lane is consumed atomically by
/// `reserve_for_authorization` instead.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionSlotAdvance {
    pub operation_id: [u8; 32],
    pub batch_id: [u8; 32],
    pub sequence: u64,
    pub admission_digest: [u8; 32],
}

impl AdmissionSlotAdvance {
    pub fn body(&self) -> Result<Value, String> {
        if self.sequence == 0
            || [self.operation_id, self.batch_id, self.admission_digest].contains(&ZERO)
        {
            return Err("admission advance is incomplete".into());
        }
        Ok(json!({
            "operation_id": hex::encode(self.operation_id),
            "batch_id": hex::encode(self.batch_id),
            "sequence": self.sequence,
            "admission_digest": hex::encode(self.admission_digest),
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(ADMISSION_ADVANCE_DOMAIN, &self.body()?)
    }
}

enum ProductDvpEvidence<'a> {
    Legacy(&'a crate::settlement::DvpPackage),
    Threshold(&'a crate::settlement::ThresholdDvpPackage),
}

impl ProductDvpEvidence<'_> {
    fn instruction(&self) -> &qomm_zkpi::Instruction {
        match self {
            Self::Legacy(package) => &package.instruction,
            Self::Threshold(package) => &package.instruction,
        }
    }

    fn digest(&self) -> [u8; 32] {
        match self {
            Self::Legacy(package) => package.digest(),
            Self::Threshold(package) => package.digest(),
        }
    }

    fn securities_from(&self) -> &[u8] {
        match self {
            Self::Legacy(package) => &package.securities_from,
            Self::Threshold(package) => &package.securities_from,
        }
    }

    fn securities_to(&self) -> &[u8] {
        match self {
            Self::Legacy(package) => &package.securities_to,
            Self::Threshold(package) => &package.securities_to,
        }
    }

    fn cash_from(&self) -> &[u8] {
        match self {
            Self::Legacy(package) => &package.cash_from,
            Self::Threshold(package) => &package.cash_from,
        }
    }

    fn cash_to(&self) -> &[u8] {
        match self {
            Self::Legacy(package) => &package.cash_to,
            Self::Threshold(package) => &package.cash_to,
        }
    }

    fn securities_amount(&self) -> RistrettoPoint {
        match self {
            Self::Legacy(package) => package.securities_leg.amount_commitment,
            Self::Threshold(package) => package.instruction.amount_commitment,
        }
    }

    fn cash_amount(&self) -> RistrettoPoint {
        match self {
            Self::Legacy(package) => package.cash_leg.amount_commitment,
            Self::Threshold(package) => package.cash_commitment,
        }
    }

    fn securities_remainder(&self) -> RistrettoPoint {
        match self {
            Self::Legacy(package) => package.securities_leg.remainder_commitment,
            Self::Threshold(package) => package.securities_remainder,
        }
    }

    fn cash_remainder(&self) -> RistrettoPoint {
        match self {
            Self::Legacy(package) => package.cash_leg.remainder_commitment,
            Self::Threshold(package) => package.cash_remainder,
        }
    }

    fn has_hidden_asset_tag(&self) -> bool {
        match self {
            Self::Legacy(package) => {
                package.securities_leg.tag.is_some() || package.cash_leg.tag.is_some()
            }
            Self::Threshold(_) => false,
        }
    }
}

/// Canonical escrow handle for all hidden reservations on one facility.  It is
/// a group point (so it can be signed inside zkPI) but reveals neither the
/// beneficiary account nor any amount.
pub fn reserve_handle_for(facility_id: &[u8; 32]) -> RistrettoPoint {
    let mut input = b"QOMM:DEFMI:FACILITY-RESERVE-HANDLE:v1".to_vec();
    input.extend_from_slice(facility_id);
    RistrettoPoint::hash_from_bytes::<Sha512>(&input)
}

fn canonical(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|error| error.to_string())
}

fn digest(domain: &[u8], value: &Value) -> Result<[u8; 32], String> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(canonical(value)?);
    Ok(hash.finalize().into())
}

fn nonzero(value: &[u8; 32], name: &str) -> Result<String, String> {
    if value == &ZERO {
        return Err(format!("{name} cannot be the all-zero identifier"));
    }
    Ok(hex::encode(value))
}

fn parse_hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    let raw = hex::decode(value).map_err(|_| format!("{name} must be 32 bytes"))?;
    raw.try_into()
        .map_err(|_| format!("{name} must be 32 bytes"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetKind {
    Cash,
    Security,
    Fund,
    Commodity,
    Carbon,
    Other,
}

impl AssetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cash => "cash",
            Self::Security => "security",
            Self::Fund => "fund",
            Self::Commodity => "commodity",
            Self::Carbon => "carbon",
            Self::Other => "other",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "cash" => Ok(Self::Cash),
            "security" => Ok(Self::Security),
            "fund" => Ok(Self::Fund),
            "commodity" => Ok(Self::Commodity),
            "carbon" => Ok(Self::Carbon),
            "other" => Ok(Self::Other),
            _ => Err("stored asset kind is invalid".into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetDefinition {
    pub asset_id: [u8; 32],
    pub code: String,
    pub kind: AssetKind,
    pub decimals: u8,
    pub terms_digest: [u8; 32],
}

impl AssetDefinition {
    pub fn body(&self) -> Result<Value, String> {
        if self.code.is_empty() || self.decimals > 30 {
            return Err("asset code or decimal precision is invalid".into());
        }
        Ok(json!({
            "asset_id": nonzero(&self.asset_id, "asset_id")?,
            "code": self.code,
            "kind": self.kind.as_str(),
            "decimals": self.decimals,
            "terms_digest": nonzero(&self.terms_digest, "terms_digest")?,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(ASSET_DOMAIN, &self.body()?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountOpening {
    pub handle: [u8; 32],
    pub asset_id: [u8; 32],
    pub commitment: [u8; 32],
    pub issuance_nonce: [u8; 32],
}

impl AccountOpening {
    pub fn body(&self) -> Result<Value, String> {
        Ok(json!({
            "handle": nonzero(&self.handle, "handle")?,
            "asset_id": nonzero(&self.asset_id, "asset_id")?,
            "commitment": nonzero(&self.commitment, "commitment")?,
            "issuance_nonce": nonzero(&self.issuance_nonce, "issuance_nonce")?,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(ACCOUNT_DOMAIN, &self.body()?)
    }
}

/// Legal/economic capacity in which the facility signer stands behind a line.
/// All five kinds use the same confidential cap state machine; the kind is
/// nevertheless consensus data because default handling and loss waterfalls
/// differ materially between a central bank, CCP, bilateral bank, specialist
/// credit/insurance provider, and self-collateral.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuarantorKind {
    CentralBank,
    CentralCounterparty,
    Bank,
    CreditProvider,
    SelfGuaranteed,
}

impl GuarantorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CentralBank => "central_bank",
            Self::CentralCounterparty => "ccp",
            Self::Bank => "bank",
            Self::CreditProvider => "credit_provider",
            Self::SelfGuaranteed => "self",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "central_bank" => Ok(Self::CentralBank),
            "ccp" => Ok(Self::CentralCounterparty),
            "bank" => Ok(Self::Bank),
            "credit_provider" => Ok(Self::CreditProvider),
            "self" => Ok(Self::SelfGuaranteed),
            _ => Err("stored guarantor kind is invalid".into()),
        }
    }
}

/// A central bank, CCP, bank, specialist credit provider, or self-guaranteeing
/// participant whose signatures may create and control committed credit
/// facilities. The policy is public by digest; bilateral limits and utilisation
/// are not.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuarantorDefinition {
    pub guarantor_id: [u8; 32],
    pub kind: GuarantorKind,
    pub name: String,
    pub public_key: [u8; 32],
    pub risk_policy_digest: [u8; 32],
}

impl GuarantorDefinition {
    pub fn body(&self) -> Result<Value, String> {
        if self.name.is_empty() || self.name.len() > 128 || self.public_key == ZERO {
            return Err("guarantor name or public key is invalid".into());
        }
        VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| "guarantor public key is malformed".to_string())?;
        Ok(json!({
            "guarantor_id": nonzero(&self.guarantor_id, "guarantor_id")?,
            "kind": self.kind.as_str(),
            "name": self.name,
            "public_key": hex::encode(self.public_key),
            "risk_policy_digest": nonzero(&self.risk_policy_digest, "risk_policy_digest")?,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(GUARANTOR_DOMAIN, &self.body()?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreditFacilityStatus {
    Active,
    Frozen,
    Closed,
    Defaulted,
}

impl CreditFacilityStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::Closed => "closed",
            Self::Defaulted => "defaulted",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "active" => Ok(Self::Active),
            "frozen" => Ok(Self::Frozen),
            "closed" => Ok(Self::Closed),
            "defaulted" => Ok(Self::Defaulted),
            _ => Err("stored credit facility status is invalid".into()),
        }
    }
}

/// Initial authoritative state of one guarantee facility.  Zero utilisation is
/// intentionally represented by the Ristretto identity (`ZERO` encoding): it
/// reveals only the unsurprising fact that a new line has no old exposure.
#[derive(Clone, Debug)]
pub struct CreditFacilityGrant {
    pub operation_id: [u8; 32],
    pub facility_id: [u8; 32],
    pub guarantor_id: [u8; 32],
    pub beneficiary_commitment: [u8; 32],
    pub rail_asset_id: [u8; 32],
    pub cap_commitment: [u8; 32],
    pub available_commitment: [u8; 32],
    pub held_commitment: [u8; 32],
    pub outstanding_commitment: [u8; 32],
    pub collateral_commitment: [u8; 32],
    pub risk_policy_digest: [u8; 32],
    pub relation_proof_digest: [u8; 32],
    pub valid_from: u64,
    pub valid_until: u64,
    pub nonce: [u8; 32],
    pub guarantor_signature: Signature,
}

impl CreditFacilityGrant {
    pub fn unsigned_body(&self) -> Result<Value, String> {
        if self.valid_from == 0
            || self.valid_until < self.valid_from
            || self.valid_until > MAX_UNIX_TIME
        {
            return Err("credit facility validity interval is invalid".into());
        }
        if self.available_commitment != self.cap_commitment
            || self.held_commitment != ZERO
            || self.outstanding_commitment != ZERO
        {
            return Err("new credit facility must start fully available and unused".into());
        }
        Ok(json!({
            "operation_id": nonzero(&self.operation_id, "operation_id")?,
            "facility_id": nonzero(&self.facility_id, "facility_id")?,
            "guarantor_id": nonzero(&self.guarantor_id, "guarantor_id")?,
            "beneficiary_commitment": nonzero(&self.beneficiary_commitment, "beneficiary_commitment")?,
            "rail_asset_id": nonzero(&self.rail_asset_id, "rail_asset_id")?,
            "cap_commitment": nonzero(&self.cap_commitment, "cap_commitment")?,
            "available_commitment": nonzero(&self.available_commitment, "available_commitment")?,
            "held_commitment": hex::encode(self.held_commitment),
            "outstanding_commitment": hex::encode(self.outstanding_commitment),
            "collateral_commitment": nonzero(&self.collateral_commitment, "collateral_commitment")?,
            "risk_policy_digest": nonzero(&self.risk_policy_digest, "risk_policy_digest")?,
            "relation_proof_digest": nonzero(&self.relation_proof_digest, "relation_proof_digest")?,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "nonce": nonzero(&self.nonce, "nonce")?,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(CREDIT_GRANT_DOMAIN, &self.unsigned_body()?)
    }

    pub fn guarantor_message(&self) -> Result<Vec<u8>, String> {
        let mut message = GUARANTOR_SIGNATURE_DOMAIN.to_vec();
        message.extend(self.statement()?);
        Ok(message)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreditTransitionKind {
    Hold,
    Release,
    Consume,
}

impl CreditTransitionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::Release => "release",
            Self::Consume => "consume",
        }
    }
}

/// A hidden-amount reservation transition.  The threshold signers verify the
/// proof named by `relation_proof_digest` before signing.  DeFMI additionally
/// enforces lifecycle, exact prior commitments, and compare-and-swap sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreditFacilityTransition {
    pub operation_id: [u8; 32],
    pub facility_id: [u8; 32],
    pub hold_id: [u8; 32],
    pub kind: CreditTransitionKind,
    pub query_commitment: [u8; 32],
    pub amount_commitment: [u8; 32],
    pub consumed_commitment: [u8; 32],
    pub refund_commitment: [u8; 32],
    pub before_available_commitment: [u8; 32],
    pub after_available_commitment: [u8; 32],
    pub before_held_commitment: [u8; 32],
    pub after_held_commitment: [u8; 32],
    pub before_outstanding_commitment: [u8; 32],
    pub after_outstanding_commitment: [u8; 32],
    pub before_sequence: u64,
    pub expires_at: u64,
    pub settlement_digest: [u8; 32],
    pub relation_proof_digest: [u8; 32],
}

impl CreditFacilityTransition {
    pub fn body(&self) -> Result<Value, String> {
        if self.expires_at == 0
            || self.expires_at > MAX_UNIX_TIME
            || self.before_sequence == u64::MAX
        {
            return Err("credit reservation expiry or sequence is invalid".into());
        }
        if self.kind == CreditTransitionKind::Hold && self.settlement_digest != ZERO {
            return Err("a new hold cannot name a settlement".into());
        }
        if self.kind == CreditTransitionKind::Release && self.settlement_digest != ZERO {
            return Err("a released hold cannot name a settlement".into());
        }
        if self.kind == CreditTransitionKind::Consume && self.settlement_digest == ZERO {
            return Err("a consumed hold must bind the resulting zkPI settlement".into());
        }
        if matches!(
            self.kind,
            CreditTransitionKind::Hold | CreditTransitionKind::Release
        ) && (self.consumed_commitment != ZERO || self.refund_commitment != ZERO)
        {
            return Err("only hold consumption can contain used and refunded amounts".into());
        }
        Ok(json!({
            "operation_id": nonzero(&self.operation_id, "operation_id")?,
            "facility_id": nonzero(&self.facility_id, "facility_id")?,
            "hold_id": nonzero(&self.hold_id, "hold_id")?,
            "kind": self.kind.as_str(),
            "query_commitment": nonzero(&self.query_commitment, "query_commitment")?,
            "amount_commitment": nonzero(&self.amount_commitment, "amount_commitment")?,
            "consumed_commitment": hex::encode(self.consumed_commitment),
            "refund_commitment": hex::encode(self.refund_commitment),
            "before_available_commitment": hex::encode(self.before_available_commitment),
            "after_available_commitment": hex::encode(self.after_available_commitment),
            "before_held_commitment": hex::encode(self.before_held_commitment),
            "after_held_commitment": hex::encode(self.after_held_commitment),
            "before_outstanding_commitment": hex::encode(self.before_outstanding_commitment),
            "after_outstanding_commitment": hex::encode(self.after_outstanding_commitment),
            "before_sequence": self.before_sequence,
            "expires_at": self.expires_at,
            "settlement_digest": hex::encode(self.settlement_digest),
            "relation_proof_digest": nonzero(&self.relation_proof_digest, "relation_proof_digest")?,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(CREDIT_TRANSITION_DOMAIN, &self.body()?)
    }

    fn relation_context(&self) -> Result<[u8; 32], String> {
        digest(
            CREDIT_RELATION_CONTEXT_DOMAIN,
            &json!({
                "operation_id": nonzero(&self.operation_id, "operation_id")?,
                "facility_id": nonzero(&self.facility_id, "facility_id")?,
                "hold_id": nonzero(&self.hold_id, "hold_id")?,
                "kind": self.kind.as_str(),
                "query_commitment": nonzero(&self.query_commitment, "query_commitment")?,
                "amount_commitment": nonzero(&self.amount_commitment, "amount_commitment")?,
                "consumed_commitment": hex::encode(self.consumed_commitment),
                "refund_commitment": hex::encode(self.refund_commitment),
                "before_available_commitment": hex::encode(self.before_available_commitment),
                "after_available_commitment": hex::encode(self.after_available_commitment),
                "before_held_commitment": hex::encode(self.before_held_commitment),
                "after_held_commitment": hex::encode(self.after_held_commitment),
                "before_outstanding_commitment": hex::encode(self.before_outstanding_commitment),
                "after_outstanding_commitment": hex::encode(self.after_outstanding_commitment),
                "before_sequence": self.before_sequence,
                "expires_at": self.expires_at,
                "settlement_digest": hex::encode(self.settlement_digest),
            }),
        )
    }
}

/// Range proofs for the hidden facility transition.  The first proof covers
/// post-transition available, held, outstanding and the original hold amount.
/// The second covers the consumed and refunded split.  Exact commitment
/// equations below bind those six non-negative values to the stored state.
#[derive(Debug)]
pub struct CreditFacilityRelationProof {
    pub state_range: RangeProof,
    pub split_range: RangeProof,
}

fn verify_credit_relation_equations(transition: &CreditFacilityTransition) -> Result<(), String> {
    let point = |encoded: &[u8; 32], name: &str| {
        CompressedRistretto(*encoded)
            .decompress()
            .ok_or_else(|| format!("{name} is not a canonical Ristretto commitment"))
    };
    let before_available = point(
        &transition.before_available_commitment,
        "before available commitment",
    )?;
    let after_available = point(
        &transition.after_available_commitment,
        "after available commitment",
    )?;
    let before_held = point(&transition.before_held_commitment, "before held commitment")?;
    let after_held = point(&transition.after_held_commitment, "after held commitment")?;
    let before_outstanding = point(
        &transition.before_outstanding_commitment,
        "before outstanding commitment",
    )?;
    let after_outstanding = point(
        &transition.after_outstanding_commitment,
        "after outstanding commitment",
    )?;
    let amount = point(&transition.amount_commitment, "hold amount commitment")?;
    let consumed = point(&transition.consumed_commitment, "consumed commitment")?;
    let refund = point(&transition.refund_commitment, "refund commitment")?;
    let relation_holds = match transition.kind {
        CreditTransitionKind::Hold => {
            before_available == after_available + amount
                && after_held == before_held + amount
                && before_outstanding == after_outstanding
                && consumed == RistrettoPoint::default()
                && refund == RistrettoPoint::default()
        }
        CreditTransitionKind::Release => {
            after_available == before_available + amount
                && before_held == after_held + amount
                && before_outstanding == after_outstanding
                && consumed == RistrettoPoint::default()
                && refund == RistrettoPoint::default()
        }
        CreditTransitionKind::Consume => {
            before_held == after_held + amount
                && after_outstanding == before_outstanding + consumed
                && after_available == before_available + refund
                && amount == consumed + refund
        }
    };
    if relation_holds {
        Ok(())
    } else {
        Err("credit commitments do not conserve the facility balance".into())
    }
}

impl CreditFacilityRelationProof {
    const WIRE_MAGIC: &'static [u8; 8] = b"QCRPROO1";
    const MAX_WIRE_PROOF_BYTES: usize = 1 << 20;

    /// Bounded, versioned wire form used between an entity-owned participant
    /// module and the DeFMI coordinator.  Only Bulletproof bytes cross the
    /// boundary; the private facility openings stay with the participant.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let state = self.state_range.to_bytes();
        let split = self.split_range.to_bytes();
        if state.is_empty()
            || split.is_empty()
            || state.len() > Self::MAX_WIRE_PROOF_BYTES
            || split.len() > Self::MAX_WIRE_PROOF_BYTES
        {
            return Err("credit relation proof exceeds its wire bound".into());
        }
        let state_len = u32::try_from(state.len())
            .map_err(|_| "credit state proof length exceeds u32".to_string())?;
        let split_len = u32::try_from(split.len())
            .map_err(|_| "credit split proof length exceeds u32".to_string())?;
        let mut wire = Vec::with_capacity(16 + state.len() + split.len());
        wire.extend_from_slice(Self::WIRE_MAGIC);
        wire.extend_from_slice(&state_len.to_be_bytes());
        wire.extend_from_slice(&state);
        wire.extend_from_slice(&split_len.to_be_bytes());
        wire.extend_from_slice(&split);
        Ok(wire)
    }

    pub fn from_bytes(wire: &[u8]) -> Result<Self, String> {
        if wire.len() < 16 || &wire[..8] != Self::WIRE_MAGIC {
            return Err("credit relation proof wire header is invalid".into());
        }
        let state_len = u32::from_be_bytes(
            wire[8..12]
                .try_into()
                .map_err(|_| "credit state proof length is truncated".to_string())?,
        ) as usize;
        if state_len == 0 || state_len > Self::MAX_WIRE_PROOF_BYTES {
            return Err("credit state proof length is outside its wire bound".into());
        }
        let split_len_offset = 12_usize
            .checked_add(state_len)
            .ok_or_else(|| "credit relation proof length overflowed".to_string())?;
        if split_len_offset
            .checked_add(4)
            .is_none_or(|end| end > wire.len())
        {
            return Err("credit relation proof wire is truncated".into());
        }
        let split_len = u32::from_be_bytes(
            wire[split_len_offset..split_len_offset + 4]
                .try_into()
                .map_err(|_| "credit split proof length is truncated".to_string())?,
        ) as usize;
        if split_len == 0 || split_len > Self::MAX_WIRE_PROOF_BYTES {
            return Err("credit split proof length is outside its wire bound".into());
        }
        let split_offset = split_len_offset + 4;
        if split_offset
            .checked_add(split_len)
            .is_none_or(|end| end != wire.len())
        {
            return Err("credit relation proof wire has trailing or missing bytes".into());
        }
        let state_range = RangeProof::from_bytes(&wire[12..split_len_offset])
            .map_err(|_| "credit state range proof is invalid".to_string())?;
        let split_range = RangeProof::from_bytes(&wire[split_offset..])
            .map_err(|_| "credit split range proof is invalid".to_string())?;
        Ok(Self {
            state_range,
            split_range,
        })
    }

    fn digest(&self) -> [u8; 32] {
        let state = self.state_range.to_bytes();
        let split = self.split_range.to_bytes();
        let mut hash = Sha256::new();
        hash.update(CREDIT_RELATION_PROOF_DOMAIN);
        hash.update((state.len() as u64).to_be_bytes());
        hash.update(state);
        hash.update((split.len() as u64).to_be_bytes());
        hash.update(split);
        hash.finalize().into()
    }

    fn transcript(label: &'static [u8], context: &[u8; 32]) -> Transcript {
        let mut transcript = Transcript::new(label);
        transcript.append_message(b"context", context);
        transcript
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove<R: RngCore + CryptoRng>(
        transition: &mut CreditFacilityTransition,
        post_state_values: [u64; 4],
        post_state_blindings: [Scalar; 4],
        split_values: [u64; 2],
        split_blindings: [Scalar; 2],
        rng: &mut R,
    ) -> Result<Self, String> {
        let _ = rng;
        let context = transition.relation_context()?;
        let key = Pedersen::new(b"qomm:defmi:credit-facility:v1");
        let pc = PedersenGens {
            B: key.g,
            B_blinding: key.h,
        };
        let mut state_transcript = Self::transcript(b"qomm:credit:state-range", &context);
        let (state_range, state_commitments) = RangeProof::prove_multiple(
            &BulletproofGens::new(64, 4),
            &pc,
            &mut state_transcript,
            &post_state_values,
            &post_state_blindings,
            64,
        )
        .map_err(|_| "credit facility state range proof failed".to_string())?;
        let expected_state = [
            transition.after_available_commitment,
            transition.after_held_commitment,
            transition.after_outstanding_commitment,
            transition.amount_commitment,
        ];
        if state_commitments
            .iter()
            .zip(expected_state)
            .any(|(commitment, expected)| commitment.to_bytes() != expected)
        {
            return Err("credit state openings do not match the transition commitments".into());
        }
        let mut split_transcript = Self::transcript(b"qomm:credit:split-range", &context);
        let (split_range, split_commitments) = RangeProof::prove_multiple(
            &BulletproofGens::new(64, 2),
            &pc,
            &mut split_transcript,
            &split_values,
            &split_blindings,
            64,
        )
        .map_err(|_| "credit facility split range proof failed".to_string())?;
        let expected_split = [transition.consumed_commitment, transition.refund_commitment];
        if split_commitments
            .iter()
            .zip(expected_split)
            .any(|(commitment, expected)| commitment.to_bytes() != expected)
        {
            return Err("credit split openings do not match the transition commitments".into());
        }
        let proof = Self {
            state_range,
            split_range,
        };
        transition.relation_proof_digest = proof.digest();
        proof.verify(transition)?;
        Ok(proof)
    }

    pub fn verify(&self, transition: &CreditFacilityTransition) -> Result<(), String> {
        if self.digest() != transition.relation_proof_digest {
            return Err("credit relation proof digest does not match the transition".into());
        }
        verify_credit_relation_equations(transition)?;
        let context = transition.relation_context()?;
        let state_commitments = [
            CompressedRistretto(transition.after_available_commitment),
            CompressedRistretto(transition.after_held_commitment),
            CompressedRistretto(transition.after_outstanding_commitment),
            CompressedRistretto(transition.amount_commitment),
        ];
        let split_commitments = [
            CompressedRistretto(transition.consumed_commitment),
            CompressedRistretto(transition.refund_commitment),
        ];
        let key = Pedersen::new(b"qomm:defmi:credit-facility:v1");
        let pc = PedersenGens {
            B: key.g,
            B_blinding: key.h,
        };
        self.state_range
            .verify_multiple(
                &BulletproofGens::new(64, 4),
                &pc,
                &mut Self::transcript(b"qomm:credit:state-range", &context),
                &state_commitments,
                64,
            )
            .map_err(|_| "credit facility post-state is outside the allowed range".to_string())?;
        self.split_range
            .verify_multiple(
                &BulletproofGens::new(64, 2),
                &pc,
                &mut Self::transcript(b"qomm:credit:split-range", &context),
                &split_commitments,
                64,
            )
            .map_err(|_| "credit consumed/refunded split is outside the allowed range".to_string())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreditControlAction {
    Activate,
    Freeze,
    Close,
    Default,
}

impl CreditControlAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Activate => "activate",
            Self::Freeze => "freeze",
            Self::Close => "close",
            Self::Default => "default",
        }
    }

    pub const fn status(self) -> CreditFacilityStatus {
        match self {
            Self::Activate => CreditFacilityStatus::Active,
            Self::Freeze => CreditFacilityStatus::Frozen,
            Self::Close => CreditFacilityStatus::Closed,
            Self::Default => CreditFacilityStatus::Defaulted,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CreditFacilityControl {
    pub operation_id: [u8; 32],
    pub facility_id: [u8; 32],
    pub action: CreditControlAction,
    pub before_sequence: u64,
    pub effective_at: u64,
    pub reason_digest: [u8; 32],
    pub guarantor_signature: Signature,
}

/// Whether an amended contractual cap still covers the already committed
/// holds and settled debt.  `OverLimit` never cancels those obligations: it
/// records the hidden excess and forces the facility into `Frozen` state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreditAmendmentMode {
    WithinLimit,
    OverLimit,
}

impl CreditAmendmentMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WithinLimit => "within_limit",
            Self::OverLimit => "over_limit",
        }
    }
}

/// Guarantor-authorized replacement of a facility's cap, collateral, policy,
/// or expiry.  Exposure commitments are immutable in this operation; only the
/// ordinary Hold/Release/Consume state machine may change them.
#[derive(Clone, Debug)]
pub struct CreditFacilityAmendment {
    pub operation_id: [u8; 32],
    pub facility_id: [u8; 32],
    pub mode: CreditAmendmentMode,
    pub before_cap_commitment: [u8; 32],
    pub after_cap_commitment: [u8; 32],
    pub before_available_commitment: [u8; 32],
    pub after_available_commitment: [u8; 32],
    pub before_held_commitment: [u8; 32],
    pub before_outstanding_commitment: [u8; 32],
    pub before_overlimit_commitment: [u8; 32],
    pub after_overlimit_commitment: [u8; 32],
    pub before_collateral_commitment: [u8; 32],
    pub after_collateral_commitment: [u8; 32],
    pub before_risk_policy_digest: [u8; 32],
    pub after_risk_policy_digest: [u8; 32],
    pub before_valid_until: u64,
    pub after_valid_until: u64,
    pub before_sequence: u64,
    pub effective_at: u64,
    pub reason_digest: [u8; 32],
    pub relation_proof_digest: [u8; 32],
    pub guarantor_signature: Signature,
}

impl CreditFacilityAmendment {
    fn relation_context(&self) -> Result<[u8; 32], String> {
        digest(
            CREDIT_AMENDMENT_CONTEXT_DOMAIN,
            &json!({
                "operation_id": nonzero(&self.operation_id, "operation_id")?,
                "facility_id": nonzero(&self.facility_id, "facility_id")?,
                "mode": self.mode.as_str(),
                "before_cap_commitment": nonzero(&self.before_cap_commitment, "before_cap_commitment")?,
                "after_cap_commitment": nonzero(&self.after_cap_commitment, "after_cap_commitment")?,
                "before_available_commitment": hex::encode(self.before_available_commitment),
                "after_available_commitment": hex::encode(self.after_available_commitment),
                "before_held_commitment": hex::encode(self.before_held_commitment),
                "before_outstanding_commitment": hex::encode(self.before_outstanding_commitment),
                "before_overlimit_commitment": hex::encode(self.before_overlimit_commitment),
                "after_overlimit_commitment": hex::encode(self.after_overlimit_commitment),
                "before_collateral_commitment": nonzero(&self.before_collateral_commitment, "before_collateral_commitment")?,
                "after_collateral_commitment": nonzero(&self.after_collateral_commitment, "after_collateral_commitment")?,
                "before_risk_policy_digest": nonzero(&self.before_risk_policy_digest, "before_risk_policy_digest")?,
                "after_risk_policy_digest": nonzero(&self.after_risk_policy_digest, "after_risk_policy_digest")?,
                "before_valid_until": self.before_valid_until,
                "after_valid_until": self.after_valid_until,
                "before_sequence": self.before_sequence,
                "effective_at": self.effective_at,
                "reason_digest": nonzero(&self.reason_digest, "reason_digest")?,
            }),
        )
    }

    pub fn unsigned_body(&self) -> Result<Value, String> {
        if self.before_sequence == u64::MAX
            || self.effective_at == 0
            || self.effective_at > MAX_UNIX_TIME
            || self.before_valid_until > MAX_UNIX_TIME
            || self.after_valid_until < self.effective_at
            || self.after_valid_until > MAX_UNIX_TIME
        {
            return Err("credit amendment time or sequence is invalid".into());
        }
        match self.mode {
            CreditAmendmentMode::WithinLimit if self.after_overlimit_commitment != ZERO => {
                return Err("within-limit amendment must clear the over-limit balance".into());
            }
            CreditAmendmentMode::OverLimit
                if self.after_available_commitment != ZERO
                    || self.after_overlimit_commitment == ZERO =>
            {
                return Err(
                    "over-limit amendment must expose no usable availability and record the excess"
                        .into(),
                );
            }
            _ => {}
        }
        let mut body = serde_json::Map::new();
        body.insert(
            "context".into(),
            Value::String(hex::encode(self.relation_context()?)),
        );
        body.insert(
            "relation_proof_digest".into(),
            Value::String(nonzero(
                &self.relation_proof_digest,
                "relation_proof_digest",
            )?),
        );
        Ok(Value::Object(body))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(CREDIT_AMENDMENT_DOMAIN, &self.unsigned_body()?)
    }

    pub fn guarantor_message(&self) -> Result<Vec<u8>, String> {
        let mut message = GUARANTOR_SIGNATURE_DOMAIN.to_vec();
        message.extend(self.statement()?);
        Ok(message)
    }
}

/// Zero-knowledge proof that an amended facility remains arithmetically
/// conserved.  It proves non-negative hidden cap/availability/exposure and
/// collateral/excess values, then checks either
/// `cap = available + held + outstanding` or
/// `cap + excess = held + outstanding` with `available = 0`.
#[derive(Debug)]
pub struct CreditFacilityAmendmentProof {
    pub balance_range: RangeProof,
    pub support_range: RangeProof,
}

impl CreditFacilityAmendmentProof {
    fn transcript(label: &'static [u8], context: &[u8; 32]) -> Transcript {
        let mut transcript = Transcript::new(label);
        transcript.append_message(b"context", context);
        transcript
    }

    fn digest(&self) -> [u8; 32] {
        let balance = self.balance_range.to_bytes();
        let support = self.support_range.to_bytes();
        let mut hash = Sha256::new();
        hash.update(CREDIT_AMENDMENT_PROOF_DOMAIN);
        hash.update((balance.len() as u64).to_be_bytes());
        hash.update(balance);
        hash.update((support.len() as u64).to_be_bytes());
        hash.update(support);
        hash.finalize().into()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove<R: RngCore + CryptoRng>(
        amendment: &mut CreditFacilityAmendment,
        balance_values: [u64; 4],
        balance_blindings: [Scalar; 4],
        support_values: [u64; 2],
        support_blindings: [Scalar; 2],
        rng: &mut R,
    ) -> Result<Self, String> {
        let _ = rng;
        let context = amendment.relation_context()?;
        let key = Pedersen::new(b"qomm:defmi:credit-facility:v1");
        let pc = PedersenGens {
            B: key.g,
            B_blinding: key.h,
        };
        let (balance_range, balance_commitments) = RangeProof::prove_multiple(
            &BulletproofGens::new(64, 4),
            &pc,
            &mut Self::transcript(b"qomm:credit:amendment:balance", &context),
            &balance_values,
            &balance_blindings,
            64,
        )
        .map_err(|_| "credit amendment balance range proof failed".to_string())?;
        let expected_balance = [
            amendment.after_cap_commitment,
            amendment.after_available_commitment,
            amendment.before_held_commitment,
            amendment.before_outstanding_commitment,
        ];
        if balance_commitments
            .iter()
            .zip(expected_balance)
            .any(|(commitment, expected)| commitment.to_bytes() != expected)
        {
            return Err("credit amendment balance openings do not match commitments".into());
        }
        let (support_range, support_commitments) = RangeProof::prove_multiple(
            &BulletproofGens::new(64, 2),
            &pc,
            &mut Self::transcript(b"qomm:credit:amendment:support", &context),
            &support_values,
            &support_blindings,
            64,
        )
        .map_err(|_| "credit amendment support range proof failed".to_string())?;
        let expected_support = [
            amendment.after_collateral_commitment,
            amendment.after_overlimit_commitment,
        ];
        if support_commitments
            .iter()
            .zip(expected_support)
            .any(|(commitment, expected)| commitment.to_bytes() != expected)
        {
            return Err("credit amendment support openings do not match commitments".into());
        }
        let proof = Self {
            balance_range,
            support_range,
        };
        amendment.relation_proof_digest = proof.digest();
        proof.verify(amendment)?;
        Ok(proof)
    }

    pub fn verify(&self, amendment: &CreditFacilityAmendment) -> Result<(), String> {
        if self.digest() != amendment.relation_proof_digest {
            return Err("credit amendment proof digest does not match the statement".into());
        }
        amendment.unsigned_body()?;
        let point = |encoded: &[u8; 32], name: &str| {
            CompressedRistretto(*encoded)
                .decompress()
                .ok_or_else(|| format!("{name} is not a canonical Ristretto commitment"))
        };
        let cap = point(&amendment.after_cap_commitment, "amended cap commitment")?;
        let available = point(
            &amendment.after_available_commitment,
            "amended available commitment",
        )?;
        let held = point(&amendment.before_held_commitment, "held commitment")?;
        let outstanding = point(
            &amendment.before_outstanding_commitment,
            "outstanding commitment",
        )?;
        let excess = point(
            &amendment.after_overlimit_commitment,
            "over-limit commitment",
        )?;
        let identity = curve25519_dalek::RistrettoPoint::default();
        let relation_holds = match amendment.mode {
            CreditAmendmentMode::WithinLimit => {
                excess == identity && cap == available + held + outstanding
            }
            CreditAmendmentMode::OverLimit => {
                available == identity && cap + excess == held + outstanding
            }
        };
        if !relation_holds {
            return Err("amended cap does not conserve the existing facility exposure".into());
        }
        let context = amendment.relation_context()?;
        let key = Pedersen::new(b"qomm:defmi:credit-facility:v1");
        let pc = PedersenGens {
            B: key.g,
            B_blinding: key.h,
        };
        self.balance_range
            .verify_multiple(
                &BulletproofGens::new(64, 4),
                &pc,
                &mut Self::transcript(b"qomm:credit:amendment:balance", &context),
                &[
                    CompressedRistretto(amendment.after_cap_commitment),
                    CompressedRistretto(amendment.after_available_commitment),
                    CompressedRistretto(amendment.before_held_commitment),
                    CompressedRistretto(amendment.before_outstanding_commitment),
                ],
                64,
            )
            .map_err(|_| "amended facility balance is outside the allowed range".to_string())?;
        self.support_range
            .verify_multiple(
                &BulletproofGens::new(64, 2),
                &pc,
                &mut Self::transcript(b"qomm:credit:amendment:support", &context),
                &[
                    CompressedRistretto(amendment.after_collateral_commitment),
                    CompressedRistretto(amendment.after_overlimit_commitment),
                ],
                64,
            )
            .map_err(|_| "amended collateral or excess is outside the allowed range".to_string())
    }
}

impl CreditFacilityControl {
    pub fn unsigned_body(&self) -> Result<Value, String> {
        if self.before_sequence == u64::MAX
            || self.effective_at == 0
            || self.effective_at > MAX_UNIX_TIME
        {
            return Err("credit control time or sequence is invalid".into());
        }
        Ok(json!({
            "operation_id": nonzero(&self.operation_id, "operation_id")?,
            "facility_id": nonzero(&self.facility_id, "facility_id")?,
            "action": self.action.as_str(),
            "before_sequence": self.before_sequence,
            "effective_at": self.effective_at,
            "reason_digest": nonzero(&self.reason_digest, "reason_digest")?,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(CREDIT_CONTROL_DOMAIN, &self.unsigned_body()?)
    }

    pub fn guarantor_message(&self) -> Result<Vec<u8>, String> {
        let mut message = GUARANTOR_SIGNATURE_DOMAIN.to_vec();
        message.extend(self.statement()?);
        Ok(message)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreditFacilitySnapshot {
    pub facility_id: [u8; 32],
    pub guarantor_id: [u8; 32],
    pub beneficiary_commitment: [u8; 32],
    pub rail_asset_id: [u8; 32],
    pub cap_commitment: [u8; 32],
    pub available_commitment: [u8; 32],
    pub held_commitment: [u8; 32],
    pub outstanding_commitment: [u8; 32],
    /// Hidden amount by which exposure exceeded a guarantor-approved cap at
    /// the last amendment.  Non-zero always implies `Frozen`.
    pub overlimit_commitment: [u8; 32],
    pub collateral_commitment: [u8; 32],
    pub risk_policy_digest: [u8; 32],
    pub valid_from: u64,
    pub valid_until: u64,
    pub status: CreditFacilityStatus,
    pub sequence: u64,
}

/// Public, canonical portion of one active facility hold.  This is sufficient
/// to consume a reservation after a coordinator restart: the original hidden
/// amount and blinding are neither retained nor reconstructed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreditHoldSnapshot {
    pub hold_id: [u8; 32],
    pub facility_id: [u8; 32],
    pub query_commitment: [u8; 32],
    pub amount_commitment: [u8; 32],
    pub expires_at: u64,
}

impl From<&CreditFacilityTransition> for CreditHoldSnapshot {
    fn from(value: &CreditFacilityTransition) -> Self {
        Self {
            hold_id: value.hold_id,
            facility_id: value.facility_id,
            query_commitment: value.query_commitment,
            amount_commitment: value.amount_commitment,
            expires_at: value.expires_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateLeg {
    pub handle: [u8; 32],
    pub asset_id: [u8; 32],
    pub before_commitment: [u8; 32],
    pub after_commitment: [u8; 32],
    pub before_sequence: u64,
}

impl StateLeg {
    fn body(&self) -> Result<Value, String> {
        Ok(json!({
            "handle": nonzero(&self.handle, "handle")?,
            "asset_id": nonzero(&self.asset_id, "asset_id")?,
            "before_commitment": nonzero(&self.before_commitment, "before_commitment")?,
            "after_commitment": nonzero(&self.after_commitment, "after_commitment")?,
            "before_sequence": self.before_sequence,
        }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementOrder {
    pub operation_id: [u8; 32],
    pub nullifier: [u8; 32],
    pub deadline: u64,
    pub payment_instruction_digest: [u8; 32],
    pub proof_digest: [u8; 32],
    pub market_statement_digest: [u8; 32],
    pub legs: Vec<StateLeg>,
}

impl SettlementOrder {
    pub fn body(&self) -> Result<Value, String> {
        if self.deadline == 0 || self.deadline > MAX_UNIX_TIME || self.legs.is_empty() {
            return Err("settlement needs a positive deadline and at least one leg".into());
        }
        let mut handles = BTreeSet::new();
        if self.legs.iter().any(|leg| !handles.insert(leg.handle)) {
            return Err("a settlement cannot update one handle twice".into());
        }
        Ok(json!({
            "operation_id": nonzero(&self.operation_id, "operation_id")?,
            "nullifier": nonzero(&self.nullifier, "nullifier")?,
            "deadline": self.deadline,
            "payment_instruction_digest": nonzero(&self.payment_instruction_digest, "payment_instruction_digest")?,
            "proof_digest": nonzero(&self.proof_digest, "proof_digest")?,
            "market_statement_digest": nonzero(&self.market_statement_digest, "market_statement_digest")?,
            "legs": self.legs.iter().map(StateLeg::body).collect::<Result<Vec<_>, _>>()?,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(SETTLEMENT_DOMAIN, &self.body()?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationRole {
    Maker,
    Taker,
}

/// Public state transition that removes the pre-authorised maximum from the
/// owner's spendable account and places it under one reservation identifier.
/// The confidential transfer proof itself is verified by the Rust admission
/// service; Avalanche stores this canonical projection and its proof digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationEscrow {
    pub source_handle: [u8; 32],
    pub escrow_handle: [u8; 32],
    pub asset_id: [u8; 32],
    pub amount_commitment: [u8; 32],
    pub source_before_commitment: [u8; 32],
    pub source_after_commitment: [u8; 32],
    pub source_before_sequence: u64,
    pub proof_digest: [u8; 32],
}

impl ReservationEscrow {
    pub fn body(&self) -> Result<Value, String> {
        if self.source_before_sequence == u64::MAX {
            return Err("reservation escrow source sequence overflows".into());
        }
        Ok(json!({
            "source_handle": nonzero(&self.source_handle, "source_handle")?,
            "escrow_handle": nonzero(&self.escrow_handle, "escrow_handle")?,
            "asset_id": nonzero(&self.asset_id, "asset_id")?,
            "amount_commitment": nonzero(&self.amount_commitment, "amount_commitment")?,
            "source_before_commitment": hex::encode(self.source_before_commitment),
            "source_after_commitment": hex::encode(self.source_after_commitment),
            "source_before_sequence": self.source_before_sequence,
            "proof_digest": nonzero(&self.proof_digest, "proof_digest")?,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(RESERVATION_ESCROW_DOMAIN, &self.body()?)
    }
}

impl ReservationRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Maker => "maker",
            Self::Taker => "taker",
        }
    }
}

fn threshold_dvp_relation_digest(
    transition: &CreditFacilityTransition,
    role: ReservationRole,
    dvp_proof_digest: [u8; 32],
) -> Result<[u8; 32], String> {
    if transition.kind != CreditTransitionKind::Consume
        || transition.settlement_digest == ZERO
        || dvp_proof_digest == ZERO
    {
        return Err("threshold DvP relation must bind a consumption and its settlement".into());
    }
    digest(
        CREDIT_THRESHOLD_DVP_RELATION_DOMAIN,
        &json!({
            "credit_relation_context": hex::encode(transition.relation_context()?),
            "reservation_role": role.as_str(),
            "dvp_proof_digest": hex::encode(dvp_proof_digest),
        }),
    )
}

/// Bind a product-consumption transition directly to the verifier-complete
/// threshold DvP package. The package already proves non-negative consumed and
/// refund amounts; re-proving the same values with an opening-based
/// Bulletproof would force an MPC coordinator to reconstruct their blindings.
pub fn bind_threshold_dvp_relation(
    transition: &mut CreditFacilityTransition,
    role: ReservationRole,
    dvp_proof_digest: [u8; 32],
) -> Result<(), String> {
    verify_credit_relation_equations(transition)?;
    transition.relation_proof_digest =
        threshold_dvp_relation_digest(transition, role, dvp_proof_digest)?;
    Ok(())
}

/// Construct the compare-and-swap facility consumption directly from public
/// commitments proved by a threshold DvP package. No amount or Pedersen
/// blinding is accepted by this API.
#[allow(clippy::too_many_arguments)]
pub fn build_threshold_dvp_consumption(
    operation_id: [u8; 32],
    hold: &CreditFacilityTransition,
    before: &CreditFacilitySnapshot,
    role: ReservationRole,
    consumed: RistrettoPoint,
    refund: RistrettoPoint,
    settlement_digest: [u8; 32],
    dvp_proof_digest: [u8; 32],
) -> Result<CreditFacilityTransition, String> {
    if hold.kind != CreditTransitionKind::Hold {
        return Err("threshold DvP consumption lacks a live hold or settlement".into());
    }
    build_threshold_dvp_consumption_from_snapshot(
        operation_id,
        &CreditHoldSnapshot::from(hold),
        before,
        role,
        consumed,
        refund,
        settlement_digest,
        dvp_proof_digest,
    )
}

/// Restart-safe form of [`build_threshold_dvp_consumption`].  The caller reads
/// both snapshots from the same canonical DeFMI root and verifies that the
/// hold is active before calling this function.
#[allow(clippy::too_many_arguments)]
pub fn build_threshold_dvp_consumption_from_snapshot(
    operation_id: [u8; 32],
    hold: &CreditHoldSnapshot,
    before: &CreditFacilitySnapshot,
    role: ReservationRole,
    consumed: RistrettoPoint,
    refund: RistrettoPoint,
    settlement_digest: [u8; 32],
    dvp_proof_digest: [u8; 32],
) -> Result<CreditFacilityTransition, String> {
    if operation_id == ZERO
        || settlement_digest == ZERO
        || hold.facility_id != before.facility_id
        || hold.hold_id == ZERO
        || hold.query_commitment == ZERO
        || hold.amount_commitment == ZERO
        || hold.expires_at == 0
    {
        return Err("threshold DvP consumption lacks a live hold or settlement".into());
    }
    let point = |encoded: [u8; 32], name: &str| {
        CompressedRistretto(encoded)
            .decompress()
            .ok_or_else(|| format!("{name} is not a canonical Ristretto commitment"))
    };
    let amount = point(hold.amount_commitment, "hold amount")?;
    if amount != consumed + refund {
        return Err("threshold DvP consumed and refund commitments do not fill the hold".into());
    }
    let before_available = point(before.available_commitment, "available facility balance")?;
    let before_held = point(before.held_commitment, "held facility balance")?;
    let before_outstanding = point(
        before.outstanding_commitment,
        "outstanding facility balance",
    )?;
    let mut transition = CreditFacilityTransition {
        operation_id,
        facility_id: hold.facility_id,
        hold_id: hold.hold_id,
        kind: CreditTransitionKind::Consume,
        query_commitment: hold.query_commitment,
        amount_commitment: hold.amount_commitment,
        consumed_commitment: consumed.compress().to_bytes(),
        refund_commitment: refund.compress().to_bytes(),
        before_available_commitment: before.available_commitment,
        after_available_commitment: (before_available + refund).compress().to_bytes(),
        before_held_commitment: before.held_commitment,
        after_held_commitment: (before_held - amount).compress().to_bytes(),
        before_outstanding_commitment: before.outstanding_commitment,
        after_outstanding_commitment: (before_outstanding + consumed).compress().to_bytes(),
        before_sequence: before.sequence,
        expires_at: hold.expires_at,
        settlement_digest,
        relation_proof_digest: ZERO,
    };
    bind_threshold_dvp_relation(&mut transition, role, dvp_proof_digest)?;
    Ok(transition)
}

fn verify_threshold_dvp_relation(
    transition: &CreditFacilityTransition,
    role: ReservationRole,
    dvp_proof_digest: [u8; 32],
) -> Result<(), String> {
    verify_credit_relation_equations(transition)?;
    if transition.relation_proof_digest
        != threshold_dvp_relation_digest(transition, role, dvp_proof_digest)?
    {
        return Err("credit transition is not bound to this threshold DvP proof".into());
    }
    Ok(())
}

/// Product meaning attached to one hidden-amount facility hold.  A Maker hold
/// is created before its policy is made eligible; a Taker hold is created
/// before that RFQ is evaluated.  The statement is the deterministic reserve
/// receipt named by their later signed mandate, avoiding any post-quote
/// signature or circular hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationAuthorization {
    pub role: ReservationRole,
    pub entity_commitment: [u8; 32],
    pub asset_id: [u8; 32],
    pub direction: u8,
    pub authorization_digest: [u8; 32],
    pub mandate_digest: [u8; 32],
    pub typed_reserve_digest: [u8; 32],
    pub reserve_nullifier: [u8; 32],
    pub asset_link_proof_digest: [u8; 32],
    /// Hidden Taker limit committed in the pre-RFQ mandate. A Maker record
    /// carries zero because the quote policy, not a Taker limit, governs it.
    pub limit_price_commitment: [u8; 32],
    pub escrow_digest: [u8; 32],
    pub rfq_nullifier: [u8; 32],
    pub policy_version: u64,
    pub admission_ticket_id: [u8; 32],
    pub admission_slot: u64,
    pub admission_receipt_digest: [u8; 32],
    pub admission_epoch: u64,
    pub admission_sequence: u64,
    pub admission_batch_id: [u8; 32],
}

impl ReservationAuthorization {
    pub fn body(&self, transition: &CreditFacilityTransition) -> Result<Value, String> {
        if transition.kind != CreditTransitionKind::Hold {
            return Err("a bound reservation must create a hold".into());
        }
        if self.direction != 1 && self.direction != 2 {
            return Err("reservation direction must be Taker-buy or Taker-sell".into());
        }
        if transition.query_commitment != self.authorization_digest {
            return Err("facility hold is bound to another policy or RFQ authorization".into());
        }
        match self.role {
            ReservationRole::Maker => {
                if self.policy_version == 0
                    || self.rfq_nullifier != ZERO
                    || self.admission_ticket_id != ZERO
                    || self.admission_slot != 0
                    || self.admission_receipt_digest != ZERO
                    || self.admission_epoch != 0
                    || self.admission_sequence != 0
                    || self.admission_batch_id != ZERO
                    || self.limit_price_commitment != ZERO
                {
                    return Err("Maker reservation must name a policy version, not an RFQ".into());
                }
            }
            ReservationRole::Taker => {
                if self.policy_version != 0
                    || self.rfq_nullifier == ZERO
                    || self.admission_ticket_id == ZERO
                    || self.admission_receipt_digest == ZERO
                    || self.admission_epoch == 0
                    || self.admission_sequence == 0
                    || self.admission_batch_id == ZERO
                    || self.limit_price_commitment == ZERO
                    || CompressedRistretto(self.limit_price_commitment)
                        .decompress()
                        .is_none()
                {
                    return Err("Taker reservation must name an admitted one-use RFQ".into());
                }
            }
        }
        Ok(json!({
            "role": self.role.as_str(),
            "entity_commitment": nonzero(&self.entity_commitment, "entity_commitment")?,
            "asset_id": nonzero(&self.asset_id, "asset_id")?,
            "direction": self.direction,
            "authorization_digest": nonzero(&self.authorization_digest, "authorization_digest")?,
            "mandate_digest": nonzero(&self.mandate_digest, "mandate_digest")?,
            "typed_reserve_digest": nonzero(&self.typed_reserve_digest, "typed_reserve_digest")?,
            "reserve_nullifier": nonzero(&self.reserve_nullifier, "reserve_nullifier")?,
            "asset_link_proof_digest": nonzero(&self.asset_link_proof_digest, "asset_link_proof_digest")?,
            "limit_price_commitment": hex::encode(self.limit_price_commitment),
            "escrow_digest": nonzero(&self.escrow_digest, "escrow_digest")?,
            "rfq_nullifier": hex::encode(self.rfq_nullifier),
            "policy_version": self.policy_version,
            "admission_ticket_id": hex::encode(self.admission_ticket_id),
            "admission_slot": self.admission_slot,
            "admission_receipt_digest": hex::encode(self.admission_receipt_digest),
            "admission_epoch": self.admission_epoch,
            "admission_sequence": self.admission_sequence,
            "admission_batch_id": hex::encode(self.admission_batch_id),
            "hold_statement": hex::encode(transition.statement()?),
        }))
    }

    pub fn statement(&self, transition: &CreditFacilityTransition) -> Result<[u8; 32], String> {
        digest(RESERVATION_DOMAIN, &self.body(transition)?)
    }
}

pub(crate) struct ReservationExecution<'a> {
    pub transition: &'a CreditFacilityTransition,
    pub relation_proof: &'a CreditFacilityRelationProof,
    pub authorization: &'a ReservationAuthorization,
    pub escrow: &'a ReservationEscrow,
    pub typed_instruction: &'a qomm_zkpi::typed::TypedInstruction,
    pub typed_venue: &'a qomm_zkpi::Venue,
    pub asset_link: &'a crate::asset_link::AssetLinkProof,
    pub ordered_admission: Option<&'a qomm_transport::order::OrderedAdmission>,
    pub approval: &'a QuorumApproval,
    pub now: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationConsumption {
    pub role: ReservationRole,
    pub reserve_receipt_digest: [u8; 32],
    pub transition: CreditFacilityTransition,
}

/// Atomic expiry release of one product reservation.  The credit hold and the
/// actual asset removed from the owner's spendable account must move together;
/// applying only the credit transition would strand the asset escrow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductReleaseOrder {
    pub transition: CreditFacilityTransition,
    pub role: ReservationRole,
    pub reserve_receipt_digest: [u8; 32],
    pub typed_instruction_digest: [u8; 32],
    pub release_nullifier: [u8; 32],
    pub release_deadline: u64,
    pub asset_id: [u8; 32],
    pub asset_link_proof_digest: [u8; 32],
    pub refund_leg: StateLeg,
}

impl ProductReleaseOrder {
    pub fn body(&self) -> Result<Value, String> {
        if self.transition.kind != CreditTransitionKind::Release
            || self.transition.operation_id == ZERO
            || self.release_deadline <= self.transition.expires_at
            || self.release_deadline > MAX_UNIX_TIME
            || self.refund_leg.asset_id != self.asset_id
        {
            return Err("product release has an invalid transition, deadline, or asset leg".into());
        }
        Ok(json!({
            "transition": self.transition.body()?,
            "role": self.role.as_str(),
            "reserve_receipt_digest": nonzero(&self.reserve_receipt_digest, "reserve_receipt_digest")?,
            "typed_instruction_digest": nonzero(&self.typed_instruction_digest, "typed_instruction_digest")?,
            "release_nullifier": nonzero(&self.release_nullifier, "release_nullifier")?,
            "release_deadline": self.release_deadline,
            "asset_id": nonzero(&self.asset_id, "asset_id")?,
            "asset_link_proof_digest": nonzero(&self.asset_link_proof_digest, "asset_link_proof_digest")?,
            "refund_leg": self.refund_leg.body()?,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(PRODUCT_RELEASE_DOMAIN, &self.body()?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductSettlementOrder {
    pub settlement: SettlementOrder,
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub maker_entity_commitment: [u8; 32],
    pub taker_entity_commitment: [u8; 32],
    pub rfq_nullifier: [u8; 32],
    pub taker_authorization_digest: [u8; 32],
    pub maker_policy_digest: [u8; 32],
    pub maker_mandate_digest: [u8; 32],
    pub taker_mandate_digest: [u8; 32],
    pub typed_instruction_digest: [u8; 32],
    pub quote_proof_digest: [u8; 32],
    pub price_limit_proof_digest: [u8; 32],
    pub dvp_proof_digest: [u8; 32],
    pub quantity_commitment: [u8; 32],
    pub cash_commitment: [u8; 32],
    pub traded_asset_id: [u8; 32],
    pub asset_link_proof_digest: [u8; 32],
    pub admission_receipt_digest: [u8; 32],
    pub admission_epoch: u64,
    pub admission_sequence: u64,
    pub reservations: Vec<ReservationConsumption>,
}

/// One governance-approved, admission-ordered group of product settlements.
///
/// Every member is separately proved and signed by the MPC proof committee,
/// but all members name the same DeFMI pre-state.  The batch statement is what
/// permits DeFMI to apply those disjoint state changes in one crash-atomic SQL
/// transaction instead of making the second member stale after the first one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductSettlementBatch {
    pub batch_id: [u8; 32],
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub admission_epoch: u64,
    pub members: Vec<ProductSettlementBatchMember>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductSettlementBatchMember {
    pub admission_sequence: u64,
    pub settlement_statement: [u8; 32],
}

impl ProductSettlementBatch {
    pub fn from_orders(
        batch_id: [u8; 32],
        orders: &[ProductSettlementOrder],
    ) -> Result<Self, String> {
        let first = orders
            .first()
            .ok_or_else(|| "product settlement batch cannot be empty".to_string())?;
        let batch = Self {
            batch_id,
            venue_id: first.venue_id,
            defmi_id: first.defmi_id,
            admission_epoch: first.admission_epoch,
            members: orders
                .iter()
                .map(|order| {
                    Ok(ProductSettlementBatchMember {
                        admission_sequence: order.admission_sequence,
                        settlement_statement: order.statement()?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?,
        };
        batch.validate_orders(orders)?;
        Ok(batch)
    }

    pub fn validate_orders(&self, orders: &[ProductSettlementOrder]) -> Result<(), String> {
        if self.batch_id == ZERO
            || self.venue_id == ZERO
            || self.defmi_id == ZERO
            || self.admission_epoch == 0
            || self.members.is_empty()
            || self.members.len() > 4096
            || self.members.len() != orders.len()
        {
            return Err("product settlement batch is incomplete or outside its bound".into());
        }
        let mut previous = 0u64;
        let mut statements = BTreeSet::new();
        let mut operations = BTreeSet::from([self.batch_id]);
        let mut nullifiers = BTreeSet::new();
        let mut rfq_nullifiers = BTreeSet::new();
        let mut facilities = BTreeSet::new();
        let mut holds = BTreeSet::new();
        let mut handles = BTreeSet::new();
        for (member, order) in self.members.iter().zip(orders) {
            if order.venue_id != self.venue_id
                || order.defmi_id != self.defmi_id
                || order.admission_epoch != self.admission_epoch
                || order.admission_sequence != member.admission_sequence
                || member.admission_sequence <= previous
                || member.settlement_statement != order.statement()?
                || !statements.insert(member.settlement_statement)
            {
                return Err(
                    "product settlement batch is not a unique certified admission sequence".into(),
                );
            }
            if !operations.insert(order.settlement.operation_id) {
                return Err("product settlement batch reuses an operation".into());
            }
            if !nullifiers.insert(order.settlement.nullifier) {
                return Err("product settlement batch reuses a payment nullifier".into());
            }
            if !rfq_nullifiers.insert(order.rfq_nullifier) {
                return Err("product settlement batch reuses an RFQ nullifier".into());
            }
            for reservation in &order.reservations {
                if !operations.insert(reservation.transition.operation_id) {
                    return Err("product settlement batch reuses a reservation operation".into());
                }
                if !facilities.insert(reservation.transition.facility_id) {
                    return Err("product settlement batch reuses a credit facility".into());
                }
                if !holds.insert(reservation.transition.hold_id) {
                    return Err("product settlement batch reuses a reservation hold".into());
                }
            }
            for leg in &order.settlement.legs {
                if !handles.insert(leg.handle) {
                    return Err("product settlement batch reuses an account".into());
                }
            }
            previous = member.admission_sequence;
        }
        Ok(())
    }

    pub fn body(&self) -> Result<Value, String> {
        if self.batch_id == ZERO
            || self.venue_id == ZERO
            || self.defmi_id == ZERO
            || self.admission_epoch == 0
            || self.members.is_empty()
            || self.members.len() > 4096
        {
            return Err("product settlement batch is incomplete or outside its bound".into());
        }
        let mut previous = 0u64;
        let mut statements = BTreeSet::new();
        for member in &self.members {
            if member.admission_sequence <= previous
                || member.settlement_statement == ZERO
                || !statements.insert(member.settlement_statement)
            {
                return Err(
                    "product settlement batch members must be unique and admission ordered".into(),
                );
            }
            previous = member.admission_sequence;
        }
        Ok(json!({
            "batch_id": hex::encode(self.batch_id),
            "venue_id": hex::encode(self.venue_id),
            "defmi_id": hex::encode(self.defmi_id),
            "admission_epoch": self.admission_epoch,
            "members": self.members.iter().map(|member| json!({
                "admission_sequence": member.admission_sequence,
                "settlement_statement": hex::encode(member.settlement_statement),
            })).collect::<Vec<_>>(),
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(PRODUCT_SETTLEMENT_BATCH_DOMAIN, &self.body()?)
    }
}

impl ProductSettlementOrder {
    pub fn body(&self) -> Result<Value, String> {
        self.settlement.body()?;
        if self.reservations.len() != 2 || self.admission_epoch == 0 || self.admission_sequence == 0
        {
            return Err("product settlement needs one ordered Maker and Taker reservation".into());
        }
        if !nonzero(&self.venue_id, "venue_id").is_ok()
            || !nonzero(&self.defmi_id, "defmi_id").is_ok()
            || !nonzero(&self.maker_entity_commitment, "maker_entity_commitment").is_ok()
            || !nonzero(&self.taker_entity_commitment, "taker_entity_commitment").is_ok()
            || !nonzero(&self.rfq_nullifier, "rfq_nullifier").is_ok()
            || !nonzero(
                &self.taker_authorization_digest,
                "taker_authorization_digest",
            )
            .is_ok()
            || !nonzero(&self.maker_policy_digest, "maker_policy_digest").is_ok()
            || !nonzero(&self.maker_mandate_digest, "maker_mandate_digest").is_ok()
            || !nonzero(&self.taker_mandate_digest, "taker_mandate_digest").is_ok()
            || !nonzero(&self.typed_instruction_digest, "typed_instruction_digest").is_ok()
            || !nonzero(&self.quote_proof_digest, "quote_proof_digest").is_ok()
            || !nonzero(&self.price_limit_proof_digest, "price_limit_proof_digest").is_ok()
            || !nonzero(&self.dvp_proof_digest, "dvp_proof_digest").is_ok()
            || !nonzero(&self.quantity_commitment, "quantity_commitment").is_ok()
            || !nonzero(&self.cash_commitment, "cash_commitment").is_ok()
            || !nonzero(&self.traded_asset_id, "traded_asset_id").is_ok()
            || !nonzero(&self.asset_link_proof_digest, "asset_link_proof_digest").is_ok()
            || !nonzero(&self.admission_receipt_digest, "admission_receipt_digest").is_ok()
        {
            return Err("product settlement has an all-zero binding".into());
        }
        if self.settlement.payment_instruction_digest != self.typed_instruction_digest
            || self.settlement.proof_digest != self.quote_proof_digest
        {
            return Err("settlement summary is not for the typed zkPI and quote proof".into());
        }
        let mut assets = BTreeMap::<[u8; 32], usize>::new();
        for leg in &self.settlement.legs {
            *assets.entry(leg.asset_id).or_default() += 1;
        }
        if self.settlement.legs.len() != 4
            || assets.len() != 2
            || assets.get(&self.traded_asset_id) != Some(&2)
            || assets.values().any(|count| *count != 2)
        {
            return Err("product DvP must have two traded-asset and two payment-asset legs".into());
        }
        let base_statement = self.settlement.statement()?;
        let mut roles = BTreeSet::new();
        let mut holds = BTreeSet::new();
        let mut facilities = BTreeSet::new();
        for reservation in &self.reservations {
            if !roles.insert(reservation.role.as_str())
                || !holds.insert(reservation.transition.hold_id)
                || !facilities.insert(reservation.transition.facility_id)
            {
                return Err("product settlement repeats a role, hold, or facility".into());
            }
            if reservation.transition.kind != CreditTransitionKind::Consume
                || reservation.transition.settlement_digest != base_statement
            {
                return Err("product settlement reservation is not consumed by this DvP".into());
            }
        }
        if !roles.contains(ReservationRole::Maker.as_str())
            || !roles.contains(ReservationRole::Taker.as_str())
        {
            return Err("product settlement lacks Maker or Taker reservation".into());
        }
        let reservations = self
            .reservations
            .iter()
            .map(|item| {
                Ok(json!({
                    "role": item.role.as_str(),
                    "reserve_receipt_digest": hex::encode(item.reserve_receipt_digest),
                    "transition": item.transition.body()?,
                }))
            })
            .collect::<Result<Vec<Value>, String>>()?;
        Ok(json!({
            "settlement": self.settlement.body()?,
            "venue_id": hex::encode(self.venue_id),
            "defmi_id": hex::encode(self.defmi_id),
            "maker_entity_commitment": hex::encode(self.maker_entity_commitment),
            "taker_entity_commitment": hex::encode(self.taker_entity_commitment),
            "rfq_nullifier": hex::encode(self.rfq_nullifier),
            "taker_authorization_digest": hex::encode(self.taker_authorization_digest),
            "maker_policy_digest": hex::encode(self.maker_policy_digest),
            "maker_mandate_digest": hex::encode(self.maker_mandate_digest),
            "taker_mandate_digest": hex::encode(self.taker_mandate_digest),
            "typed_instruction_digest": hex::encode(self.typed_instruction_digest),
            "quote_proof_digest": hex::encode(self.quote_proof_digest),
            "price_limit_proof_digest": hex::encode(self.price_limit_proof_digest),
            "dvp_proof_digest": hex::encode(self.dvp_proof_digest),
            "quantity_commitment": hex::encode(self.quantity_commitment),
            "cash_commitment": hex::encode(self.cash_commitment),
            "traded_asset_id": hex::encode(self.traded_asset_id),
            "asset_link_proof_digest": hex::encode(self.asset_link_proof_digest),
            "admission_receipt_digest": hex::encode(self.admission_receipt_digest),
            "admission_epoch": self.admission_epoch,
            "admission_sequence": self.admission_sequence,
            "reservations": reservations,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(PRODUCT_SETTLEMENT_DOMAIN, &self.body()?)
    }
}

#[derive(Clone, Debug)]
pub struct NodeApproval {
    pub node_id: String,
    pub signature: Signature,
}

#[derive(Clone, Debug)]
pub struct QuorumApproval {
    pub statement: [u8; 32],
    pub signer_epoch: u64,
    pub domain: String,
    pub before_root: [u8; 32],
    pub approvals: Vec<NodeApproval>,
}

#[derive(Clone, Debug)]
pub struct QuorumAuthorizer {
    nodes: BTreeMap<String, VerifyingKey>,
    threshold: usize,
    epoch: u64,
    domain: String,
}

impl QuorumAuthorizer {
    pub fn new(
        nodes: BTreeMap<String, VerifyingKey>,
        threshold: usize,
        epoch: u64,
        domain: impl Into<String>,
    ) -> Result<Self, String> {
        let domain = domain.into();
        if nodes.is_empty()
            || nodes.len() > 64
            || !(1..=nodes.len()).contains(&threshold)
            || epoch == 0
        {
            return Err("invalid k-of-n signer configuration".into());
        }
        let allowed =
            |character: char| character.is_ascii_alphanumeric() || "._:/+-".contains(character);
        if nodes
            .keys()
            .any(|node| node.is_empty() || node.len() > 128 || !node.chars().all(allowed))
        {
            return Err("quorum node identifiers contain invalid characters".into());
        }
        if !domain.is_ascii() || domain.is_empty() || domain.len() > 128 {
            return Err("approval domain must be ASCII and between 1 and 128 bytes".into());
        }
        let mut encoded = BTreeSet::new();
        for key in nodes.values() {
            let bytes = key.to_bytes();
            if bytes == ZERO {
                return Err("quorum public keys cannot use the all-zero encoding".into());
            }
            if !encoded.insert(bytes) {
                return Err("one quorum public key cannot occupy two node identities".into());
            }
        }
        Ok(Self {
            nodes,
            threshold,
            epoch,
            domain,
        })
    }

    fn signing_body(&self, statement: &[u8; 32], before_root: &[u8; 32]) -> Vec<u8> {
        let domain = self.domain.as_bytes();
        let mut body = DOMAIN.to_vec();
        body.extend(self.epoch.to_be_bytes());
        body.extend((domain.len() as u16).to_be_bytes());
        body.extend(domain);
        body.extend(before_root);
        body.extend(statement);
        body
    }

    pub fn verify(
        &self,
        expected: &[u8; 32],
        before_root: &[u8; 32],
        approval: &QuorumApproval,
    ) -> bool {
        if approval.statement != *expected
            || approval.before_root != *before_root
            || approval.domain != self.domain
            || approval.signer_epoch != self.epoch
            || approval.approvals.len() > 64
        {
            return false;
        }
        let body = self.signing_body(expected, before_root);
        let mut seen = BTreeSet::new();
        approval
            .approvals
            .iter()
            .filter(|signed| {
                seen.insert(signed.node_id.clone())
                    && self
                        .nodes
                        .get(&signed.node_id)
                        .is_some_and(|key| key.verify(&body, &signed.signature).is_ok())
            })
            .count()
            >= self.threshold
    }

    pub fn approve(
        &self,
        statement: [u8; 32],
        before_root: [u8; 32],
        signers: &BTreeMap<String, SigningKey>,
    ) -> Result<QuorumApproval, String> {
        if signers.is_empty() || signers.keys().any(|node| !self.nodes.contains_key(node)) {
            return Err("approval signers must be configured quorum nodes".into());
        }
        for (node, key) in signers {
            if self.nodes[node] != key.verifying_key() {
                return Err("approval signer key does not match the quorum configuration".into());
            }
        }
        let body = self.signing_body(&statement, &before_root);
        Ok(QuorumApproval {
            statement,
            signer_epoch: self.epoch,
            domain: self.domain.clone(),
            before_root,
            approvals: signers
                .iter()
                .map(|(node_id, key)| NodeApproval {
                    node_id: node_id.clone(),
                    signature: key.sign(&body),
                })
                .collect(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct SettlementReceipt {
    pub operation_id: [u8; 32],
    pub nullifier: [u8; 32],
    pub statement: [u8; 32],
    pub before_root: [u8; 32],
    pub after_root: [u8; 32],
    pub previous_receipt: [u8; 32],
    pub committed_at_ns: u64,
    pub elapsed_ns: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub database_bytes_before: u64,
    pub database_bytes_after: u64,
    pub signature: Signature,
}

impl SettlementReceipt {
    pub fn unsigned(&self) -> Result<Vec<u8>, String> {
        let mut body = RECEIPT_DOMAIN.to_vec();
        body.extend(canonical(&json!({
            "operation_id": hex::encode(self.operation_id),
            "nullifier": hex::encode(self.nullifier),
            "statement": hex::encode(self.statement),
            "before_root": hex::encode(self.before_root),
            "after_root": hex::encode(self.after_root),
            "previous_receipt": hex::encode(self.previous_receipt),
            "committed_at_ns": self.committed_at_ns,
            "elapsed_ns": self.elapsed_ns,
            "request_bytes": self.request_bytes,
            "response_bytes": self.response_bytes,
            "database_bytes_before": self.database_bytes_before,
            "database_bytes_after": self.database_bytes_after,
        }))?);
        Ok(body)
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        let mut hash = Sha256::new();
        hash.update(self.unsigned()?);
        hash.update(self.signature.to_bytes());
        Ok(hash.finalize().into())
    }

    pub fn verify(&self, key: &VerifyingKey) -> bool {
        self.unsigned()
            .is_ok_and(|body| key.verify(&body, &self.signature).is_ok())
    }
}

#[repr(C)]
struct Sqlite3 {
    _private: [u8; 0],
}

#[link(name = "sqlite3")]
unsafe extern "C" {
    fn sqlite3_open_v2(
        filename: *const c_char,
        database: *mut *mut Sqlite3,
        flags: c_int,
        vfs: *const c_char,
    ) -> c_int;
    fn sqlite3_close(database: *mut Sqlite3) -> c_int;
    fn sqlite3_exec(
        database: *mut Sqlite3,
        sql: *const c_char,
        callback: Option<
            unsafe extern "C" fn(
                data: *mut c_void,
                columns: c_int,
                values: *mut *mut c_char,
                names: *mut *mut c_char,
            ) -> c_int,
        >,
        data: *mut c_void,
        error: *mut *mut c_char,
    ) -> c_int;
    fn sqlite3_errmsg(database: *mut Sqlite3) -> *const c_char;
    fn sqlite3_free(pointer: *mut c_void);
}

struct Database(*mut Sqlite3);

unsafe impl Send for Database {}

impl Drop for Database {
    fn drop(&mut self) {
        unsafe {
            sqlite3_close(self.0);
        }
    }
}

unsafe extern "C" fn collect_rows(
    data: *mut c_void,
    columns: c_int,
    values: *mut *mut c_char,
    _names: *mut *mut c_char,
) -> c_int {
    let rows = &mut *(data as *mut Vec<Vec<Option<String>>>);
    let values = std::slice::from_raw_parts(values, columns as usize);
    rows.push(
        values
            .iter()
            .map(|value| {
                if value.is_null() {
                    None
                } else {
                    Some(CStr::from_ptr(*value).to_string_lossy().into_owned())
                }
            })
            .collect(),
    );
    0
}

impl Database {
    fn open(path: &Path) -> Result<Self, String> {
        let filename = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "database path contains a NUL byte".to_string())?;
        let mut database = ptr::null_mut();
        let result = unsafe {
            sqlite3_open_v2(
                filename.as_ptr(),
                &mut database,
                0x0000_0002 | 0x0000_0004 | 0x0001_0000,
                ptr::null(),
            )
        };
        if result != 0 || database.is_null() {
            return Err("could not open DeFMI database".into());
        }
        Ok(Self(database))
    }

    fn error(&self) -> String {
        unsafe { CStr::from_ptr(sqlite3_errmsg(self.0)) }
            .to_string_lossy()
            .into_owned()
    }

    fn execute(&self, sql: &str) -> Result<(), String> {
        let sql = CString::new(sql).map_err(|_| "SQL contains a NUL byte".to_string())?;
        let mut error = ptr::null_mut();
        let code = unsafe { sqlite3_exec(self.0, sql.as_ptr(), None, ptr::null_mut(), &mut error) };
        if code == 0 {
            return Ok(());
        }
        let message = if error.is_null() {
            self.error()
        } else {
            let message = unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned();
            unsafe { sqlite3_free(error.cast()) };
            message
        };
        Err(message)
    }

    fn query(&self, sql: &str) -> Result<Vec<Vec<Option<String>>>, String> {
        let sql = CString::new(sql).map_err(|_| "SQL contains a NUL byte".to_string())?;
        let mut rows = Vec::new();
        let mut error = ptr::null_mut();
        let code = unsafe {
            sqlite3_exec(
                self.0,
                sql.as_ptr(),
                Some(collect_rows),
                (&mut rows as *mut Vec<Vec<Option<String>>>).cast(),
                &mut error,
            )
        };
        if code == 0 {
            return Ok(rows);
        }
        let message = if error.is_null() {
            self.error()
        } else {
            let message = unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned();
            unsafe { sqlite3_free(error.cast()) };
            message
        };
        Err(message)
    }
}

fn blob(value: &[u8]) -> String {
    format!("X'{}'", hex::encode(value))
}

fn quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[derive(Serialize, Deserialize)]
struct ReceiptWire {
    operation_id: String,
    nullifier: String,
    statement: String,
    before_root: String,
    after_root: String,
    previous_receipt: String,
    committed_at_ns: u64,
    elapsed_ns: u64,
    request_bytes: u64,
    response_bytes: u64,
    database_bytes_before: u64,
    database_bytes_after: u64,
    signature: String,
}

impl ReceiptWire {
    fn from_receipt(receipt: &SettlementReceipt) -> Self {
        Self {
            operation_id: hex::encode(receipt.operation_id),
            nullifier: hex::encode(receipt.nullifier),
            statement: hex::encode(receipt.statement),
            before_root: hex::encode(receipt.before_root),
            after_root: hex::encode(receipt.after_root),
            previous_receipt: hex::encode(receipt.previous_receipt),
            committed_at_ns: receipt.committed_at_ns,
            elapsed_ns: receipt.elapsed_ns,
            request_bytes: receipt.request_bytes,
            response_bytes: receipt.response_bytes,
            database_bytes_before: receipt.database_bytes_before,
            database_bytes_after: receipt.database_bytes_after,
            signature: hex::encode(receipt.signature.to_bytes()),
        }
    }

    fn into_receipt(self) -> Result<SettlementReceipt, String> {
        let signature: [u8; 64] = hex::decode(self.signature)
            .map_err(|_| "receipt signature is malformed".to_string())?
            .try_into()
            .map_err(|_| "receipt signature is malformed".to_string())?;
        Ok(SettlementReceipt {
            operation_id: parse_hex32(&self.operation_id, "operation_id")?,
            nullifier: parse_hex32(&self.nullifier, "nullifier")?,
            statement: parse_hex32(&self.statement, "statement")?,
            before_root: parse_hex32(&self.before_root, "before_root")?,
            after_root: parse_hex32(&self.after_root, "after_root")?,
            previous_receipt: parse_hex32(&self.previous_receipt, "previous_receipt")?,
            committed_at_ns: self.committed_at_ns,
            elapsed_ns: self.elapsed_ns,
            request_bytes: self.request_bytes,
            response_bytes: self.response_bytes,
            database_bytes_before: self.database_bytes_before,
            database_bytes_after: self.database_bytes_after,
            signature: Signature::from_bytes(&signature),
        })
    }
}

pub struct DefmiFacility {
    path: PathBuf,
    database: Mutex<Database>,
    pub authorizer: QuorumAuthorizer,
    receipt_key: SigningKey,
    pub receipt_public_key: VerifyingKey,
}

impl DefmiFacility {
    pub fn open(
        path: impl AsRef<Path>,
        authorizer: QuorumAuthorizer,
        receipt_key: SigningKey,
    ) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let database = Database::open(&path)?;
        database.execute(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; \
             PRAGMA busy_timeout=5000;",
        )?;
        let version = database
            .query("PRAGMA user_version")?
            .first()
            .and_then(|row| row.first())
            .and_then(Option::as_deref)
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|error| error.to_string())?;
        if version > 15 {
            return Err(format!("unsupported DeFMI schema version {version}"));
        }
        database.execute(
            "CREATE TABLE IF NOT EXISTS assets(\
                asset_id BLOB PRIMARY KEY CHECK(length(asset_id)=32),\
                code TEXT NOT NULL,kind TEXT NOT NULL,decimals INTEGER NOT NULL,\
                terms_digest BLOB NOT NULL CHECK(length(terms_digest)=32),\
                active INTEGER NOT NULL DEFAULT 1,statement BLOB NOT NULL UNIQUE);\
             CREATE TABLE IF NOT EXISTS accounts(\
                handle BLOB PRIMARY KEY CHECK(length(handle)=32),\
                asset_id BLOB NOT NULL REFERENCES assets(asset_id),\
                commitment BLOB NOT NULL CHECK(length(commitment)=32),\
                sequence INTEGER NOT NULL,opening_statement BLOB NOT NULL UNIQUE);\
             CREATE TABLE IF NOT EXISTS nullifiers(\
                nullifier BLOB PRIMARY KEY CHECK(length(nullifier)=32),\
                deadline INTEGER NOT NULL,statement BLOB NOT NULL UNIQUE);\
             CREATE TABLE IF NOT EXISTS operations(\
                operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=32),\
                statement BLOB NOT NULL UNIQUE CHECK(length(statement)=32));\
             CREATE TABLE IF NOT EXISTS receipts(\
                operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=32),\
                nullifier BLOB NOT NULL UNIQUE,statement BLOB NOT NULL UNIQUE,\
                receipt_json BLOB NOT NULL,receipt_digest BLOB NOT NULL UNIQUE);\
             CREATE TABLE IF NOT EXISTS product_settlement_batches(\
                batch_id BLOB PRIMARY KEY CHECK(length(batch_id)=32),\
                statement BLOB NOT NULL UNIQUE CHECK(length(statement)=32),\
                before_root BLOB NOT NULL CHECK(length(before_root)=32),\
                after_root BLOB NOT NULL CHECK(length(after_root)=32),\
                item_count INTEGER NOT NULL,first_sequence INTEGER NOT NULL,\
                last_sequence INTEGER NOT NULL,first_receipt_digest BLOB NOT NULL CHECK(length(first_receipt_digest)=32),\
                last_receipt_digest BLOB NOT NULL CHECK(length(last_receipt_digest)=32));\
             CREATE TABLE IF NOT EXISTS guarantors(\
                guarantor_id BLOB PRIMARY KEY CHECK(length(guarantor_id)=32),\
                kind TEXT NOT NULL CHECK(kind IN ('central_bank','ccp','bank','credit_provider','self')),\
                name TEXT NOT NULL,public_key BLOB NOT NULL UNIQUE CHECK(length(public_key)=32),\
                risk_policy_digest BLOB NOT NULL CHECK(length(risk_policy_digest)=32),\
                active INTEGER NOT NULL DEFAULT 1,statement BLOB NOT NULL UNIQUE);\
             CREATE TABLE IF NOT EXISTS credit_facilities(\
                facility_id BLOB PRIMARY KEY CHECK(length(facility_id)=32),\
                guarantor_id BLOB NOT NULL REFERENCES guarantors(guarantor_id),\
                beneficiary_commitment BLOB NOT NULL CHECK(length(beneficiary_commitment)=32),\
                rail_asset_id BLOB NOT NULL REFERENCES assets(asset_id),\
                cap_commitment BLOB NOT NULL CHECK(length(cap_commitment)=32),\
                available_commitment BLOB NOT NULL CHECK(length(available_commitment)=32),\
                held_commitment BLOB NOT NULL CHECK(length(held_commitment)=32),\
                outstanding_commitment BLOB NOT NULL CHECK(length(outstanding_commitment)=32),\
                overlimit_commitment BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000' CHECK(length(overlimit_commitment)=32),\
                collateral_commitment BLOB NOT NULL CHECK(length(collateral_commitment)=32),\
                risk_policy_digest BLOB NOT NULL CHECK(length(risk_policy_digest)=32),\
                valid_from INTEGER NOT NULL,valid_until INTEGER NOT NULL,\
                status TEXT NOT NULL,sequence INTEGER NOT NULL,\
                grant_statement BLOB NOT NULL UNIQUE CHECK(length(grant_statement)=32));\
             CREATE TABLE IF NOT EXISTS credit_facility_scopes(\
                guarantor_id BLOB NOT NULL CHECK(length(guarantor_id)=32),\
                beneficiary_commitment BLOB NOT NULL CHECK(length(beneficiary_commitment)=32),\
                rail_asset_id BLOB NOT NULL CHECK(length(rail_asset_id)=32),\
                facility_id BLOB NOT NULL UNIQUE REFERENCES credit_facilities(facility_id),\
                PRIMARY KEY(guarantor_id,beneficiary_commitment,rail_asset_id));\
             CREATE TABLE IF NOT EXISTS credit_holds(\
                hold_id BLOB PRIMARY KEY CHECK(length(hold_id)=32),\
                facility_id BLOB NOT NULL REFERENCES credit_facilities(facility_id),\
                query_commitment BLOB NOT NULL CHECK(length(query_commitment)=32),\
                amount_commitment BLOB NOT NULL CHECK(length(amount_commitment)=32),\
                expires_at INTEGER NOT NULL,status TEXT NOT NULL,\
                settlement_digest BLOB NOT NULL CHECK(length(settlement_digest)=32),\
                created_sequence INTEGER NOT NULL,updated_sequence INTEGER NOT NULL);\
             CREATE INDEX IF NOT EXISTS credit_holds_facility_status \
                ON credit_holds(facility_id,status);\
             CREATE TABLE IF NOT EXISTS credit_operations(\
                operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=32),\
                facility_id BLOB NOT NULL CHECK(length(facility_id)=32),\
                kind TEXT NOT NULL,statement BLOB NOT NULL UNIQUE CHECK(length(statement)=32));\
             CREATE TABLE IF NOT EXISTS reservation_bindings(\
                hold_id BLOB PRIMARY KEY REFERENCES credit_holds(hold_id),\
                role TEXT NOT NULL,entity_commitment BLOB NOT NULL CHECK(length(entity_commitment)=32),\
                asset_id BLOB NOT NULL REFERENCES assets(asset_id),direction INTEGER NOT NULL,\
                authorization_digest BLOB NOT NULL CHECK(length(authorization_digest)=32),\
                mandate_digest BLOB NOT NULL CHECK(length(mandate_digest)=32),\
                typed_reserve_digest BLOB NOT NULL UNIQUE CHECK(length(typed_reserve_digest)=32),\
                reserve_nullifier BLOB NOT NULL CHECK(length(reserve_nullifier)=32),\
                asset_link_proof_digest BLOB NOT NULL CHECK(length(asset_link_proof_digest)=32),\
                limit_price_commitment BLOB NOT NULL CHECK(length(limit_price_commitment)=32),\
                rfq_nullifier BLOB NOT NULL CHECK(length(rfq_nullifier)=32),\
                policy_version INTEGER NOT NULL,\
                admission_ticket_id BLOB NOT NULL CHECK(length(admission_ticket_id)=32),\
                admission_slot INTEGER NOT NULL,\
                admission_receipt_digest BLOB NOT NULL CHECK(length(admission_receipt_digest)=32),\
                admission_epoch INTEGER NOT NULL,admission_sequence INTEGER NOT NULL,\
                admission_batch_id BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000' CHECK(length(admission_batch_id)=32),\
                receipt_digest BLOB NOT NULL UNIQUE CHECK(length(receipt_digest)=32));\
             CREATE TABLE IF NOT EXISTS reservation_escrows(\
                hold_id BLOB PRIMARY KEY REFERENCES reservation_bindings(hold_id),\
                source_handle BLOB NOT NULL CHECK(length(source_handle)=32),\
                escrow_handle BLOB NOT NULL CHECK(length(escrow_handle)=32),\
                asset_id BLOB NOT NULL REFERENCES assets(asset_id),\
                amount_commitment BLOB NOT NULL CHECK(length(amount_commitment)=32),\
                source_before_commitment BLOB NOT NULL CHECK(length(source_before_commitment)=32),\
                source_after_commitment BLOB NOT NULL CHECK(length(source_after_commitment)=32),\
                source_before_sequence INTEGER NOT NULL,\
                proof_digest BLOB NOT NULL UNIQUE CHECK(length(proof_digest)=32),\
                status TEXT NOT NULL,\
                settlement_digest BLOB NOT NULL CHECK(length(settlement_digest)=32));\
             CREATE TABLE IF NOT EXISTS rfq_nullifiers(\
                rfq_nullifier BLOB PRIMARY KEY CHECK(length(rfq_nullifier)=32),\
                settlement_statement BLOB NOT NULL UNIQUE CHECK(length(settlement_statement)=32));\
             CREATE TABLE IF NOT EXISTS admission_committees(\
                venue_id BLOB NOT NULL CHECK(length(venue_id)=32),\
                epoch INTEGER NOT NULL,operation_id BLOB NOT NULL UNIQUE CHECK(length(operation_id)=32),\
                node_keys BLOB NOT NULL CHECK(length(node_keys)=224),\
                valid_from INTEGER NOT NULL,valid_until INTEGER NOT NULL,\
                statement BLOB NOT NULL UNIQUE CHECK(length(statement)=32),\
                PRIMARY KEY(venue_id,epoch));\
             CREATE TABLE IF NOT EXISTS admission_batches(\
                batch_id BLOB PRIMARY KEY CHECK(length(batch_id)=32),\
                operation_id BLOB NOT NULL UNIQUE CHECK(length(operation_id)=32),\
                venue_id BLOB NOT NULL CHECK(length(venue_id)=32),\
                epoch INTEGER NOT NULL,slot INTEGER NOT NULL,\
                batch_digest BLOB NOT NULL CHECK(length(batch_digest)=32),\
                order_digest BLOB NOT NULL CHECK(length(order_digest)=32),\
                population INTEGER NOT NULL,consumed INTEGER NOT NULL,expires_at INTEGER NOT NULL,\
                statement BLOB NOT NULL UNIQUE CHECK(length(statement)=32),\
                UNIQUE(venue_id,epoch,slot,batch_digest));\
             CREATE TABLE IF NOT EXISTS admission_batch_entries(\
                batch_id BLOB NOT NULL REFERENCES admission_batches(batch_id),\
                sequence INTEGER NOT NULL,\
                admission_digest BLOB NOT NULL CHECK(length(admission_digest)=32),\
                consumed_by BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000' CHECK(length(consumed_by)=32),\
                PRIMARY KEY(batch_id,sequence),UNIQUE(batch_id,admission_digest));\
             CREATE TABLE IF NOT EXISTS admission_operations(\
                operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=32),\
                batch_id BLOB NOT NULL REFERENCES admission_batches(batch_id),\
                sequence INTEGER NOT NULL,statement BLOB NOT NULL UNIQUE CHECK(length(statement)=32));\
             CREATE TABLE IF NOT EXISTS settlement_verifiers(\
                verifier_id BLOB PRIMARY KEY CHECK(length(verifier_id)=32),\
                venue_id BLOB NOT NULL CHECK(length(venue_id)=32),\
                defmi_id BLOB NOT NULL CHECK(length(defmi_id)=32),\
                epoch INTEGER NOT NULL,\
                quote_registry_digest BLOB NOT NULL CHECK(length(quote_registry_digest)=32),\
                quote_eligibility_bits INTEGER NOT NULL,quote_span_bits INTEGER NOT NULL,\
                amount_bits INTEGER NOT NULL,price_bits INTEGER NOT NULL,\
                max_horizon INTEGER NOT NULL,frost_public_package BLOB NOT NULL,\
                valid_from INTEGER NOT NULL,valid_until INTEGER NOT NULL,\
                statement BLOB NOT NULL UNIQUE CHECK(length(statement)=32),\
                UNIQUE(venue_id,epoch));\
             CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value BLOB NOT NULL);",
        )?;
        // Schema v4 adds a separate committed over-limit balance.  Existing
        // v3 databases already have `credit_facilities`, while fresh databases
        // create the column above.  Inspecting the actual table makes this
        // migration safe for both paths and for pre-v3 databases upgraded in
        // one open.
        let has_overlimit = database
            .query("PRAGMA table_info(credit_facilities)")?
            .iter()
            .any(|row| row.get(1).and_then(Option::as_deref) == Some("overlimit_commitment"));
        if !has_overlimit {
            database.execute(
                "ALTER TABLE credit_facilities ADD COLUMN overlimit_commitment BLOB NOT NULL \
                 DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000' \
                 CHECK(length(overlimit_commitment)=32);",
            )?;
        }
        let guarantor_columns = database
            .query("PRAGMA table_info(guarantors)")?
            .into_iter()
            .filter_map(|row| row.get(1).and_then(Clone::clone))
            .collect::<BTreeSet<_>>();
        if !guarantor_columns.contains("kind") {
            // Schema v11 makes the economic guarantor role explicit. Legacy
            // deployments represented every external signer as a bank; that
            // is the only non-destructive migration value. Operators must
            // register new CCP/self lines explicitly rather than silently
            // reclassifying an existing legal agreement.
            database.execute(
                "ALTER TABLE guarantors ADD COLUMN kind TEXT NOT NULL DEFAULT 'bank' \
                 CHECK(kind IN ('central_bank','ccp','bank','credit_provider','self'))",
            )?;
        }
        let guarantor_schema = database
            .query("SELECT sql FROM sqlite_master WHERE type='table' AND name='guarantors'")?
            .first()
            .and_then(|row| row.first())
            .and_then(Option::as_deref)
            .ok_or_else(|| "guarantor table schema is missing".to_string())?
            .to_string();
        if !guarantor_schema.contains("credit_provider")
            || !guarantor_schema.contains("central_bank")
        {
            // Schema v15 aligns the durable constraint with every supported
            // guarantor kind, including central banks and specialist credit
            // providers, without changing any existing classification. SQLite
            // cannot widen a CHECK constraint in place, so rebuild only this
            // parent table while preserving its identifiers and the child
            // references from `credit_facilities`.
            database.execute("PRAGMA foreign_keys=OFF; BEGIN IMMEDIATE;")?;
            for (step, sql) in [
                ("drop stale temporary table", "DROP TABLE IF EXISTS guarantors_v15"),
                (
                    "create replacement table",
                    "CREATE TABLE guarantors_v15(\
                        guarantor_id BLOB PRIMARY KEY CHECK(length(guarantor_id)=32),\
                        kind TEXT NOT NULL CHECK(kind IN ('central_bank','ccp','bank','credit_provider','self')),\
                        name TEXT NOT NULL,public_key BLOB NOT NULL UNIQUE CHECK(length(public_key)=32),\
                        risk_policy_digest BLOB NOT NULL CHECK(length(risk_policy_digest)=32),\
                        active INTEGER NOT NULL DEFAULT 1,statement BLOB NOT NULL UNIQUE)",
                ),
                (
                    "copy guarantor records",
                    "INSERT INTO guarantors_v15(\
                        guarantor_id,kind,name,public_key,risk_policy_digest,active,statement) \
                     SELECT guarantor_id,kind,name,public_key,risk_policy_digest,active,statement \
                     FROM guarantors",
                ),
                ("drop constrained table", "DROP TABLE guarantors"),
                (
                    "install replacement table",
                    "ALTER TABLE guarantors_v15 RENAME TO guarantors",
                ),
            ] {
                if let Err(error) = database.execute(sql) {
                    let _ = database.execute("ROLLBACK; PRAGMA foreign_keys=ON;");
                    return Err(format!(
                        "failed to migrate guarantor kinds while attempting to {step}: {error}"
                    ));
                }
            }
            let foreign_key_violations = match database.query("PRAGMA foreign_key_check") {
                Ok(rows) => rows,
                Err(error) => {
                    let _ = database.execute("ROLLBACK; PRAGMA foreign_keys=ON;");
                    return Err(format!(
                        "failed to validate guarantor kind migration: {error}"
                    ));
                }
            };
            if !foreign_key_violations.is_empty() {
                let _ = database.execute("ROLLBACK; PRAGMA foreign_keys=ON;");
                return Err("guarantor kind migration violates a foreign key".into());
            }
            if let Err(error) = database.execute("COMMIT") {
                let _ = database.execute("ROLLBACK; PRAGMA foreign_keys=ON;");
                return Err(format!(
                    "failed to commit guarantor kind migration: {error}"
                ));
            }
            database.execute("PRAGMA foreign_keys=ON;")?;
        }
        for row in database.query("SELECT kind FROM guarantors")? {
            GuarantorKind::parse(row[0].as_deref().unwrap_or_default())?;
        }
        let mut reservation_columns = database
            .query("PRAGMA table_info(reservation_bindings)")?
            .into_iter()
            .filter_map(|row| row.get(1).and_then(Clone::clone))
            .collect::<BTreeSet<_>>();
        if reservation_columns.contains("admission_ticket_digest")
            && !reservation_columns.contains("admission_ticket_id")
        {
            database.execute(
                "ALTER TABLE reservation_bindings RENAME COLUMN admission_ticket_digest TO admission_ticket_id",
            )?;
            reservation_columns.remove("admission_ticket_digest");
            reservation_columns.insert("admission_ticket_id".into());
        }
        for (name, default) in [
            (
                "mandate_digest",
                "X'0000000000000000000000000000000000000000000000000000000000000000'",
            ),
            (
                "reserve_nullifier",
                "X'0000000000000000000000000000000000000000000000000000000000000000'",
            ),
            (
                "asset_link_proof_digest",
                "X'0000000000000000000000000000000000000000000000000000000000000000'",
            ),
            (
                "limit_price_commitment",
                "X'0000000000000000000000000000000000000000000000000000000000000000'",
            ),
            (
                "admission_ticket_id",
                "X'0000000000000000000000000000000000000000000000000000000000000000'",
            ),
            (
                "admission_receipt_digest",
                "X'0000000000000000000000000000000000000000000000000000000000000000'",
            ),
        ] {
            if !reservation_columns.contains(name) {
                database.execute(&format!(
                    "ALTER TABLE reservation_bindings ADD COLUMN {name} BLOB NOT NULL \
                     DEFAULT {default} CHECK(length({name})=32)"
                ))?;
            }
        }
        if !reservation_columns.contains("admission_slot") {
            database.execute(
                "ALTER TABLE reservation_bindings ADD COLUMN admission_slot INTEGER NOT NULL DEFAULT 0",
            )?;
        }
        if !reservation_columns.contains("admission_batch_id") {
            database.execute(
                "ALTER TABLE reservation_bindings ADD COLUMN admission_batch_id BLOB NOT NULL \
                 DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000' \
                 CHECK(length(admission_batch_id)=32)",
            )?;
        }
        database.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS reservation_bindings_reserve_nullifier \
             ON reservation_bindings(reserve_nullifier) WHERE reserve_nullifier != \
             X'0000000000000000000000000000000000000000000000000000000000000000';",
        )?;
        database.execute(
            "DROP INDEX IF EXISTS reservation_bindings_admission_sequence;\
             CREATE UNIQUE INDEX IF NOT EXISTS reservation_bindings_admission_ticket \
             ON reservation_bindings(admission_ticket_id) WHERE role='taker' AND \
             admission_ticket_id != X'0000000000000000000000000000000000000000000000000000000000000000';\
             CREATE UNIQUE INDEX IF NOT EXISTS reservation_bindings_admission_receipt \
             ON reservation_bindings(admission_receipt_digest) WHERE role='taker' AND \
             admission_receipt_digest != X'0000000000000000000000000000000000000000000000000000000000000000';\
             CREATE UNIQUE INDEX IF NOT EXISTS reservation_bindings_admission_sequence \
             ON reservation_bindings(admission_batch_id,admission_sequence) WHERE role='taker' AND \
             admission_batch_id != X'0000000000000000000000000000000000000000000000000000000000000000' \
             AND admission_sequence != 0;",
        )?;
        // One guarantor line per legal entity and rail is a consensus rule, not
        // an API convention.  Without this index the same entity could obtain
        // two facility IDs and reserve both in parallel, defeating the entity-
        // level cap even though each individual facility remained sound.
        database.execute(
            "INSERT OR IGNORE INTO credit_facility_scopes(\
                guarantor_id,beneficiary_commitment,rail_asset_id,facility_id) \
             SELECT guarantor_id,beneficiary_commitment,rail_asset_id,facility_id \
             FROM credit_facilities;",
        )?;
        let duplicate_scopes = database
            .query(
                "SELECT guarantor_id FROM credit_facilities GROUP BY \
                 guarantor_id,beneficiary_commitment,rail_asset_id HAVING count(*) > 1 LIMIT 1",
            )?
            .len();
        if duplicate_scopes != 0 {
            return Err(
                "existing DeFMI state contains duplicate legal-entity guarantee facilities".into(),
            );
        }
        // Every consensus operation shares one replay namespace.  Populate it
        // before installing triggers so an old database with cross-category
        // operation reuse fails migration instead of silently choosing a row.
        if version < 13 {
            database.execute(
                "INSERT OR IGNORE INTO operations(operation_id,statement) \
                 SELECT operation_id,statement FROM credit_operations;\
             INSERT OR IGNORE INTO operations(operation_id,statement) \
                 SELECT operation_id,statement FROM admission_operations;\
             INSERT OR IGNORE INTO operations(operation_id,statement) \
                 SELECT operation_id,statement FROM admission_committees;\
             INSERT OR IGNORE INTO operations(operation_id,statement) \
                 SELECT operation_id,statement FROM admission_batches;\
             INSERT OR IGNORE INTO operations(operation_id,statement) \
                 SELECT operation_id,statement FROM receipts;\
             INSERT OR IGNORE INTO operations(operation_id,statement) \
                 SELECT batch_id,statement FROM product_settlement_batches;",
            )?;
            let inconsistent_operations = database
                .query(
                    "SELECT operation_id FROM (\
                       SELECT operation_id,statement FROM credit_operations UNION ALL \
                       SELECT operation_id,statement FROM admission_operations UNION ALL \
                       SELECT operation_id,statement FROM admission_committees UNION ALL \
                       SELECT operation_id,statement FROM admission_batches UNION ALL \
                       SELECT operation_id,statement FROM receipts UNION ALL \
                       SELECT batch_id AS operation_id,statement FROM product_settlement_batches\
                     ) AS source LEFT JOIN operations USING(operation_id) \
                     WHERE operations.operation_id IS NULL \
                        OR operations.statement != source.statement LIMIT 1",
                )?
                .len();
            if inconsistent_operations != 0 {
                return Err(
                    "existing DeFMI state reuses an operation identifier or statement".into(),
                );
            }
        }
        database.execute(
            "CREATE TRIGGER IF NOT EXISTS credit_operation_registry \
                 AFTER INSERT ON credit_operations BEGIN \
                   INSERT OR IGNORE INTO operations(operation_id,statement) \
                     VALUES(NEW.operation_id,NEW.statement);\
                   SELECT CASE WHEN (SELECT statement FROM operations \
                     WHERE operation_id=NEW.operation_id) != NEW.statement \
                     THEN RAISE(ABORT,'operation identifier was reused') END;\
                 END;\
             CREATE TRIGGER IF NOT EXISTS admission_operation_registry \
                 AFTER INSERT ON admission_operations BEGIN \
                   INSERT OR IGNORE INTO operations(operation_id,statement) \
                     VALUES(NEW.operation_id,NEW.statement);\
                   SELECT CASE WHEN (SELECT statement FROM operations \
                     WHERE operation_id=NEW.operation_id) != NEW.statement \
                     THEN RAISE(ABORT,'operation identifier was reused') END;\
                 END;\
             CREATE TRIGGER IF NOT EXISTS admission_committee_operation_registry \
                 AFTER INSERT ON admission_committees BEGIN \
                   INSERT OR IGNORE INTO operations(operation_id,statement) \
                     VALUES(NEW.operation_id,NEW.statement);\
                   SELECT CASE WHEN (SELECT statement FROM operations \
                     WHERE operation_id=NEW.operation_id) != NEW.statement \
                     THEN RAISE(ABORT,'operation identifier was reused') END;\
                 END;\
             CREATE TRIGGER IF NOT EXISTS admission_batch_operation_registry \
                 AFTER INSERT ON admission_batches BEGIN \
                   INSERT OR IGNORE INTO operations(operation_id,statement) \
                     VALUES(NEW.operation_id,NEW.statement);\
                   SELECT CASE WHEN (SELECT statement FROM operations \
                     WHERE operation_id=NEW.operation_id) != NEW.statement \
                     THEN RAISE(ABORT,'operation identifier was reused') END;\
                 END;\
             CREATE TRIGGER IF NOT EXISTS receipt_operation_registry \
                 AFTER INSERT ON receipts BEGIN \
                   INSERT OR IGNORE INTO operations(operation_id,statement) \
                     VALUES(NEW.operation_id,NEW.statement);\
                   SELECT CASE WHEN (SELECT statement FROM operations \
                     WHERE operation_id=NEW.operation_id) != NEW.statement \
                     THEN RAISE(ABORT,'operation identifier was reused') END;\
                 END;\
             CREATE TRIGGER IF NOT EXISTS product_batch_operation_registry \
                 AFTER INSERT ON product_settlement_batches BEGIN \
                   INSERT OR IGNORE INTO operations(operation_id,statement) \
                     VALUES(NEW.batch_id,NEW.statement);\
                   SELECT CASE WHEN (SELECT statement FROM operations \
                     WHERE operation_id=NEW.batch_id) != NEW.statement \
                     THEN RAISE(ABORT,'operation identifier was reused') END;\
                 END;",
        )?;
        database.execute("PRAGMA user_version=15;")?;
        database.execute(&format!(
            "INSERT OR IGNORE INTO metadata(key,value) VALUES('state_root',{});\
             INSERT OR IGNORE INTO metadata(key,value) VALUES('last_receipt',{});",
            blob(&ZERO),
            blob(&ZERO)
        ))?;
        let receipt_public_key = receipt_key.verifying_key();
        Ok(Self {
            path,
            database: Mutex::new(database),
            authorizer,
            receipt_key,
            receipt_public_key,
        })
    }

    fn database_size(database: &Database) -> Result<u64, String> {
        let rows = database
            .query("SELECT page_count*page_size FROM pragma_page_count(), pragma_page_size()")?;
        rows.first()
            .and_then(|row| row.first())
            .and_then(Option::as_deref)
            .ok_or_else(|| "SQLite did not report its size".to_string())?
            .parse::<u64>()
            .map_err(|error| error.to_string())
    }

    fn calculate_root(database: &Database) -> Result<[u8; 32], String> {
        let mut hash = Sha256::new();
        hash.update(STATE_DOMAIN);
        for row in database.query(
            "SELECT hex(asset_id),code,kind,decimals,hex(terms_digest),active FROM assets ORDER BY asset_id",
        )? {
            let encoded = json!([
                row[0].as_deref().unwrap_or_default().to_ascii_lowercase(),
                row[1].as_deref().unwrap_or_default(),
                row[2].as_deref().unwrap_or_default(),
                row[3].as_deref().unwrap_or("0").parse::<u64>().map_err(|error| error.to_string())?,
                row[4].as_deref().unwrap_or_default().to_ascii_lowercase(),
                row[5].as_deref().unwrap_or("0").parse::<u64>().map_err(|error| error.to_string())?,
            ]);
            hash.update(canonical(&encoded)?);
        }
        for row in database.query(
            "SELECT hex(handle),hex(asset_id),hex(commitment),sequence FROM accounts ORDER BY handle",
        )? {
            hash.update(hex::decode(row[0].as_deref().unwrap_or_default()).map_err(|error| error.to_string())?);
            hash.update(hex::decode(row[1].as_deref().unwrap_or_default()).map_err(|error| error.to_string())?);
            hash.update(hex::decode(row[2].as_deref().unwrap_or_default()).map_err(|error| error.to_string())?);
            hash.update(row[3].as_deref().unwrap_or("0").parse::<u64>().map_err(|error| error.to_string())?.to_be_bytes());
        }
        for row in database.query(
            "SELECT hex(guarantor_id),kind,name,hex(public_key),hex(risk_policy_digest),active \
             FROM guarantors ORDER BY guarantor_id",
        )? {
            let encoded = json!([
                row[0].as_deref().unwrap_or_default().to_ascii_lowercase(),
                row[1].as_deref().unwrap_or_default(),
                row[2].as_deref().unwrap_or_default(),
                row[3].as_deref().unwrap_or_default().to_ascii_lowercase(),
                row[4].as_deref().unwrap_or_default().to_ascii_lowercase(),
                row[5]
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?,
            ]);
            hash.update(canonical(&encoded)?);
        }
        for row in database.query(
            "SELECT hex(facility_id),hex(guarantor_id),hex(beneficiary_commitment),\
                    hex(rail_asset_id),hex(cap_commitment),hex(available_commitment),\
                    hex(held_commitment),hex(outstanding_commitment),hex(overlimit_commitment),\
                    hex(collateral_commitment),\
                    hex(risk_policy_digest),valid_from,valid_until,status,sequence \
             FROM credit_facilities ORDER BY facility_id",
        )? {
            let columns = row
                .get(..11)
                .ok_or_else(|| "credit facility row is truncated".to_string())?;
            for column in columns {
                hash.update(
                    hex::decode(column.as_deref().unwrap_or_default())
                        .map_err(|error| error.to_string())?,
                );
            }
            hash.update(
                row[11]
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?
                    .to_be_bytes(),
            );
            hash.update(
                row[12]
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?
                    .to_be_bytes(),
            );
            let status = row[13].as_deref().unwrap_or_default().as_bytes();
            hash.update((status.len() as u16).to_be_bytes());
            hash.update(status);
            hash.update(
                row[14]
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?
                    .to_be_bytes(),
            );
        }
        for row in database.query(
            "SELECT hex(hold_id),hex(facility_id),hex(query_commitment),\
                    hex(amount_commitment),expires_at,status,hex(settlement_digest),\
                    created_sequence,updated_sequence \
             FROM credit_holds ORDER BY hold_id",
        )? {
            let columns = row
                .get(..4)
                .ok_or_else(|| "credit hold row is truncated".to_string())?;
            for column in columns {
                hash.update(
                    hex::decode(column.as_deref().unwrap_or_default())
                        .map_err(|error| error.to_string())?,
                );
            }
            hash.update(
                row[4]
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?
                    .to_be_bytes(),
            );
            let status = row[5].as_deref().unwrap_or_default().as_bytes();
            hash.update((status.len() as u16).to_be_bytes());
            hash.update(status);
            hash.update(
                hex::decode(row[6].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
            let columns = row
                .get(7..9)
                .ok_or_else(|| "credit hold sequence row is truncated".to_string())?;
            for column in columns {
                hash.update(
                    column
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?
                        .to_be_bytes(),
                );
            }
        }
        for row in database.query(
            "SELECT hex(hold_id),role,hex(entity_commitment),hex(asset_id),direction,\
                    hex(authorization_digest),hex(mandate_digest),hex(typed_reserve_digest),\
                    hex(reserve_nullifier),hex(asset_link_proof_digest),\
                    hex(limit_price_commitment),hex(rfq_nullifier),\
                    policy_version,hex(admission_ticket_id),admission_slot,\
                    hex(admission_receipt_digest),admission_epoch,admission_sequence,\
                    hex(admission_batch_id),hex(receipt_digest) \
             FROM reservation_bindings ORDER BY hold_id",
        )? {
            hash.update(
                hex::decode(row[0].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
            let role = row[1].as_deref().unwrap_or_default().as_bytes();
            hash.update((role.len() as u16).to_be_bytes());
            hash.update(role);
            for column in [2usize, 3] {
                hash.update(
                    hex::decode(row[column].as_deref().unwrap_or_default())
                        .map_err(|error| error.to_string())?,
                );
            }
            hash.update(
                row[4]
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?
                    .to_be_bytes(),
            );
            let columns = row
                .get(5..=11)
                .ok_or_else(|| "reservation binding row is truncated".to_string())?;
            for column in columns {
                hash.update(
                    hex::decode(column.as_deref().unwrap_or_default())
                        .map_err(|error| error.to_string())?,
                );
            }
            hash.update(
                row[12]
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?
                    .to_be_bytes(),
            );
            hash.update(
                hex::decode(row[13].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
            hash.update(
                row[14]
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?
                    .to_be_bytes(),
            );
            hash.update(
                hex::decode(row[15].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
            let columns = row
                .get(16..=17)
                .ok_or_else(|| "reservation admission row is truncated".to_string())?;
            for column in columns {
                hash.update(
                    column
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?
                        .to_be_bytes(),
                );
            }
            hash.update(
                hex::decode(row[18].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
            hash.update(
                hex::decode(row[19].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
        }
        for row in database.query(
            "SELECT hex(hold_id),hex(source_handle),hex(escrow_handle),hex(asset_id),\
                    hex(amount_commitment),hex(source_before_commitment),\
                    hex(source_after_commitment),source_before_sequence,hex(proof_digest),\
                    status,hex(settlement_digest) \
             FROM reservation_escrows ORDER BY hold_id",
        )? {
            let columns = row
                .get(..7)
                .ok_or_else(|| "reservation escrow row is truncated".to_string())?;
            for column in columns {
                hash.update(
                    hex::decode(column.as_deref().unwrap_or_default())
                        .map_err(|error| error.to_string())?,
                );
            }
            hash.update(
                row[7]
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?
                    .to_be_bytes(),
            );
            hash.update(
                hex::decode(row[8].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
            let status = row[9].as_deref().unwrap_or_default().as_bytes();
            hash.update((status.len() as u16).to_be_bytes());
            hash.update(status);
            hash.update(
                hex::decode(row[10].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
        }
        for row in database.query(
            "SELECT hex(nullifier),deadline,hex(statement) FROM nullifiers ORDER BY nullifier",
        )? {
            hash.update(
                hex::decode(row[0].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
            hash.update(
                row[1]
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?
                    .to_be_bytes(),
            );
            hash.update(
                hex::decode(row[2].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
        }
        for row in database.query(
            "SELECT hex(rfq_nullifier),hex(settlement_statement) \
             FROM rfq_nullifiers ORDER BY rfq_nullifier",
        )? {
            hash.update(
                hex::decode(row[0].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
            hash.update(
                hex::decode(row[1].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
        }
        for row in database.query(
            "SELECT hex(venue_id),epoch,hex(node_keys),valid_from,valid_until,hex(statement) \
             FROM admission_committees ORDER BY venue_id,epoch",
        )? {
            hash.update(
                hex::decode(row[0].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
            hash.update(
                row[1]
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?
                    .to_be_bytes(),
            );
            hash.update(
                hex::decode(row[2].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
            for column in [3usize, 4] {
                hash.update(
                    row[column]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?
                        .to_be_bytes(),
                );
            }
            hash.update(
                hex::decode(row[5].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
        }
        for row in database.query(
            "SELECT hex(batch_id),hex(venue_id),epoch,slot,hex(batch_digest),\
                    hex(order_digest),population,consumed,expires_at,hex(statement) \
             FROM admission_batches ORDER BY batch_id",
        )? {
            for column in [0usize, 1, 4, 5] {
                hash.update(
                    hex::decode(row[column].as_deref().unwrap_or_default())
                        .map_err(|error| error.to_string())?,
                );
            }
            for column in [2usize, 3, 6, 7, 8] {
                hash.update(
                    row[column]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?
                        .to_be_bytes(),
                );
            }
            hash.update(
                hex::decode(row[9].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
        }
        for row in database.query(
            "SELECT hex(batch_id),sequence,hex(admission_digest),hex(consumed_by) \
             FROM admission_batch_entries ORDER BY batch_id,sequence",
        )? {
            hash.update(
                hex::decode(row[0].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
            hash.update(
                row[1]
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?
                    .to_be_bytes(),
            );
            for column in [2usize, 3] {
                hash.update(
                    hex::decode(row[column].as_deref().unwrap_or_default())
                        .map_err(|error| error.to_string())?,
                );
            }
        }
        for row in database.query(
            "SELECT hex(venue_id),hex(defmi_id),epoch,hex(quote_registry_digest),\
                    quote_eligibility_bits,quote_span_bits,amount_bits,price_bits,max_horizon,\
                    hex(frost_public_package),valid_from,valid_until,hex(statement) \
             FROM settlement_verifiers ORDER BY verifier_id",
        )? {
            for column in [0usize, 1] {
                hash.update(
                    hex::decode(row[column].as_deref().unwrap_or_default())
                        .map_err(|error| error.to_string())?,
                );
            }
            hash.update(
                row[2]
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?
                    .to_be_bytes(),
            );
            hash.update(
                hex::decode(row[3].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
            for (column, field) in row.iter().enumerate().take(9).skip(4) {
                let value = field
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?;
                if column <= 7 {
                    let value = u16::try_from(value)
                        .map_err(|_| "stored settlement verifier width is invalid".to_string())?;
                    hash.update(value.to_be_bytes());
                } else {
                    hash.update(value.to_be_bytes());
                }
            }
            let frost_package = hex::decode(row[9].as_deref().unwrap_or_default())
                .map_err(|error| error.to_string())?;
            hash.update((frost_package.len() as u64).to_be_bytes());
            hash.update(frost_package);
            for column in [10usize, 11] {
                hash.update(
                    row[column]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?
                        .to_be_bytes(),
                );
            }
            hash.update(
                hex::decode(row[12].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
        }
        for row in database.query(
            "SELECT hex(operation_id),hex(statement) FROM operations ORDER BY operation_id",
        )? {
            for column in row
                .get(..2)
                .ok_or_else(|| "operation replay-protection row is truncated".to_string())?
            {
                hash.update(
                    hex::decode(column.as_deref().unwrap_or_default())
                        .map_err(|error| error.to_string())?,
                );
            }
        }
        Ok(hash.finalize().into())
    }

    fn register_operation(
        database: &Database,
        operation_id: &[u8; 32],
        statement: &[u8; 32],
    ) -> Result<(), String> {
        let existing = database.query(&format!(
            "SELECT hex(statement) FROM operations WHERE operation_id={}",
            blob(operation_id)
        ))?;
        if let Some(row) = existing.first() {
            return if parse_hex32(
                row.first().and_then(Option::as_deref).unwrap_or_default(),
                "operation statement",
            )? == *statement
            {
                Ok(())
            } else {
                Err("operation identifier was reused".into())
            };
        }
        database.execute(&format!(
            "INSERT INTO operations(operation_id,statement) VALUES({},{})",
            blob(operation_id),
            blob(statement),
        ))
    }

    fn require_quorum(
        &self,
        statement: &[u8; 32],
        before_root: &[u8; 32],
        approval: &QuorumApproval,
    ) -> Result<(), String> {
        if self.authorizer.verify(statement, before_root, approval) {
            Ok(())
        } else {
            Err("the transition lacks the configured k-of-n approval".into())
        }
    }

    fn load_admission_batch(
        database: &Database,
        batch_id: &[u8; 32],
    ) -> Result<Option<AdmissionBatchSnapshot>, String> {
        let rows = database.query(&format!(
            "SELECT hex(batch_id),hex(venue_id),epoch,slot,hex(batch_digest),\
                    (SELECT MIN(sequence) FROM admission_batch_entries \
                     WHERE admission_batch_entries.batch_id=admission_batches.batch_id),\
                    population,consumed,expires_at FROM admission_batches WHERE batch_id={}",
            blob(batch_id)
        ))?;
        rows.first()
            .map(|row| {
                Ok(AdmissionBatchSnapshot {
                    batch_id: parse_hex32(
                        row[0].as_deref().unwrap_or_default(),
                        "admission batch id",
                    )?,
                    venue_id: parse_hex32(
                        row[1].as_deref().unwrap_or_default(),
                        "admission venue id",
                    )?,
                    epoch: row[2]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                    slot: row[3]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                    batch_digest: parse_hex32(
                        row[4].as_deref().unwrap_or_default(),
                        "admission batch digest",
                    )?,
                    first_sequence: row[5]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                    population: row[6]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                    consumed: row[7]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                    expires_at: row[8]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                })
            })
            .transpose()
    }

    fn load_admission_committee(
        database: &Database,
        venue_id: &[u8; 32],
        epoch: u64,
    ) -> Result<Option<AdmissionCommitteePlan>, String> {
        let rows = database.query(&format!(
            "SELECT hex(operation_id),hex(node_keys),valid_from,valid_until \
             FROM admission_committees WHERE venue_id={} AND epoch={epoch}",
            blob(venue_id),
        ))?;
        rows.first()
            .map(|row| {
                let raw = hex::decode(row[1].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?;
                if raw.len() != 32 * qomm_transport::order::COMMITTEE_NODES {
                    return Err("stored admission committee key set has the wrong size".into());
                }
                Ok(AdmissionCommitteePlan {
                    operation_id: parse_hex32(
                        row[0].as_deref().unwrap_or_default(),
                        "admission committee operation",
                    )?,
                    venue_id: *venue_id,
                    epoch,
                    node_keys: raw
                        .chunks_exact(32)
                        .map(|key| key.try_into().expect("exact 32-byte committee key"))
                        .collect(),
                    valid_from: row[2]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                    valid_until: row[3]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                })
            })
            .transpose()
    }

    fn load_settlement_verifier(
        database: &Database,
        venue_id: &[u8; 32],
        epoch: u64,
    ) -> Result<Option<crate::settlement_verifier::SettlementVerifierConfig>, String> {
        let rows = database.query(&format!(
            "SELECT hex(defmi_id),hex(quote_registry_digest),quote_eligibility_bits,\
                    quote_span_bits,amount_bits,price_bits,max_horizon,\
                    hex(frost_public_package),valid_from,valid_until \
             FROM settlement_verifiers WHERE venue_id={} AND epoch={epoch}",
            blob(venue_id),
        ))?;
        rows.first()
            .map(|row| {
                let parse_u16 = |index: usize, name: &str| -> Result<u16, String> {
                    row[index]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u16>()
                        .map_err(|_| format!("stored settlement verifier {name} is invalid"))
                };
                let parse_u64 = |index: usize, name: &str| -> Result<u64, String> {
                    row[index]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|_| format!("stored settlement verifier {name} is invalid"))
                };
                let config = crate::settlement_verifier::SettlementVerifierConfig {
                    venue_id: *venue_id,
                    defmi_id: parse_hex32(
                        row[0].as_deref().unwrap_or_default(),
                        "settlement verifier DeFMI id",
                    )?,
                    epoch,
                    quote_registry_digest: parse_hex32(
                        row[1].as_deref().unwrap_or_default(),
                        "settlement verifier registry digest",
                    )?,
                    quote_eligibility_bits: parse_u16(2, "eligibility width")?,
                    quote_span_bits: parse_u16(3, "span width")?,
                    amount_bits: parse_u16(4, "amount width")?,
                    price_bits: parse_u16(5, "price width")?,
                    max_horizon: parse_u64(6, "horizon")?,
                    frost_public_package: hex::decode(row[7].as_deref().unwrap_or_default())
                        .map_err(|error| error.to_string())?,
                    valid_from: parse_u64(8, "valid-from time")?,
                    valid_until: parse_u64(9, "valid-until time")?,
                };
                config.validate()?;
                Ok(config)
            })
            .transpose()
    }

    /// Pin the eligible-Maker registry, circuit widths and FROST public key
    /// before an RFQ epoch opens. Settlement-supplied verifier material is
    /// never trusted; both the native facility and the Avalanche VM commit the
    /// same record into the cross-runtime state root.
    pub fn register_settlement_verifier(
        &self,
        config: &crate::settlement_verifier::SettlementVerifierConfig,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(), String> {
        config.validate()?;
        if now < config.valid_from || now > config.valid_until {
            return Err("settlement verifier is not currently valid".into());
        }
        let statement = config.statement()?;
        let database = self.database.lock().expect("DeFMI database lock");
        database.execute("BEGIN IMMEDIATE")?;
        let result = (|| {
            if let Some(existing) =
                Self::load_settlement_verifier(&database, &config.venue_id, config.epoch)?
            {
                return if existing == *config {
                    Ok(())
                } else {
                    Err("settlement verifier venue and epoch were reused".into())
                };
            }
            let before_root = Self::calculate_root(&database)?;
            self.require_quorum(&statement, &before_root, approval)?;
            database.execute(&format!(
                "INSERT INTO settlement_verifiers(\
                    verifier_id,venue_id,defmi_id,epoch,quote_registry_digest,\
                    quote_eligibility_bits,quote_span_bits,amount_bits,price_bits,max_horizon,\
                    frost_public_package,valid_from,valid_until,statement) \
                 VALUES({},{},{},{},{},{},{},{},{},{},{},{},{},{})",
                blob(&config.key()),
                blob(&config.venue_id),
                blob(&config.defmi_id),
                config.epoch,
                blob(&config.quote_registry_digest),
                config.quote_eligibility_bits,
                config.quote_span_bits,
                config.amount_bits,
                config.price_bits,
                config.max_horizon,
                blob(&config.frost_public_package),
                config.valid_from,
                config.valid_until,
                blob(&statement),
            ))
        })();
        match result {
            Ok(()) => {
                database.execute("COMMIT")?;
                Ok(())
            }
            Err(error) => {
                let _ = database.execute("ROLLBACK");
                Err(error)
            }
        }
    }

    pub fn settlement_verifier(
        &self,
        venue_id: &[u8; 32],
        epoch: u64,
    ) -> Result<Option<crate::settlement_verifier::SettlementVerifierConfig>, String> {
        Self::load_settlement_verifier(
            &self.database.lock().expect("DeFMI database lock"),
            venue_id,
            epoch,
        )
    }

    /// Pin the seven resident-node admission receipt keys through the normal
    /// DeFMI k-of-n governance path. Handoff-carried key bytes are never
    /// accepted unless they match this durable venue/epoch record.
    pub fn register_admission_committee(
        &self,
        plan: &AdmissionCommitteePlan,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(), String> {
        plan.body()?;
        if now < plan.valid_from || now > plan.valid_until {
            return Err("admission committee is not currently valid".into());
        }
        let statement = plan.statement()?;
        let database = self.database.lock().expect("DeFMI database lock");
        database.execute("BEGIN IMMEDIATE")?;
        let result = (|| {
            if let Some(existing) =
                Self::load_admission_committee(&database, &plan.venue_id, plan.epoch)?
            {
                return if existing == *plan {
                    Ok(())
                } else {
                    Err("admission committee venue and epoch were reused".into())
                };
            }
            let before_root = Self::calculate_root(&database)?;
            self.require_quorum(&statement, &before_root, approval)?;
            let node_keys = plan.node_keys.concat();
            database.execute(&format!(
                "INSERT INTO admission_committees(\
                    venue_id,epoch,operation_id,node_keys,valid_from,valid_until,statement) \
                 VALUES({},{},{},{},{},{},{})",
                blob(&plan.venue_id),
                plan.epoch,
                blob(&plan.operation_id),
                blob(&node_keys),
                plan.valid_from,
                plan.valid_until,
                blob(&statement),
            ))
        })();
        match result {
            Ok(()) => {
                database.execute("COMMIT")?;
                Ok(())
            }
            Err(error) => {
                let _ = database.execute("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Register the complete fixed-population order before any lane can touch
    /// a legal-entity cap or Maker reservation. The opaque digest vector has a
    /// constant population, so covers and real RFQs occupy identical slots.
    pub fn register_admission_batch(
        &self,
        plan: &AdmissionBatchPlan,
        admission_lanes: &[Vec<qomm_transport::order::NodeAdmissionAttestation>],
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<AdmissionBatchSnapshot, String> {
        plan.body()?;
        if now > plan.expires_at {
            return Err("admission batch has expired".into());
        }
        let statement = plan.statement()?;
        let database = self.database.lock().expect("DeFMI database lock");
        database.execute("BEGIN IMMEDIATE")?;
        let result = (|| {
            let committee = Self::load_admission_committee(&database, &plan.venue_id, plan.epoch)?
                .ok_or_else(|| {
                    "admission batch has no governance-pinned resident committee".to_string()
                })?;
            if now < committee.valid_from || now > committee.valid_until {
                return Err("admission committee is not currently valid".into());
            }
            let keys = committee.verifying_keys()?;
            let mut certified = admission_lanes
                .iter()
                .map(|lane| qomm_transport::order::verify_admission_lane(lane, &keys))
                .collect::<Result<Vec<_>, _>>()?;
            certified.sort_by_key(|lane| lane.sequence);
            if certified.len() != plan.admission_digests.len()
                || certified.iter().enumerate().any(|(index, lane)| {
                    lane.sequence != plan.first_sequence + index as u64
                        || lane.slot != plan.slot
                        || lane.cluster_digest != plan.batch_digest
                        || lane.order_digest != plan.order_digest
                        || lane.digest(plan.venue_id, plan.epoch).ok()
                            != plan.admission_digests.get(index).copied()
                })
            {
                return Err(
                    "admission batch differs from its seven-node certified population".into(),
                );
            }
            if let Some(existing) = Self::load_admission_batch(&database, &plan.batch_id)? {
                let stored = database.query(&format!(
                    "SELECT hex(operation_id),hex(statement) FROM admission_batches WHERE batch_id={}",
                    blob(&plan.batch_id)
                ))?;
                let row = stored.first().ok_or_else(|| {
                    "idempotent admission batch disappeared during lookup".to_string()
                })?;
                if parse_hex32(
                    row[0].as_deref().unwrap_or_default(),
                    "admission operation id",
                )? != plan.operation_id
                    || parse_hex32(row[1].as_deref().unwrap_or_default(), "admission statement")?
                        != statement
                {
                    return Err("admission batch id was reused with different contents".into());
                }
                return Ok(existing);
            }
            let prior = database.query(&format!(
                "SELECT COALESCE(MAX(e.sequence),0) FROM admission_batch_entries e \
                 JOIN admission_batches b ON b.batch_id=e.batch_id \
                 WHERE b.venue_id={} AND b.epoch={}",
                blob(&plan.venue_id),
                plan.epoch,
            ))?;
            let next_sequence = prior
                .first()
                .and_then(|row| row[0].as_deref())
                .unwrap_or("0")
                .parse::<u64>()
                .map_err(|error| error.to_string())?
                .checked_add(1)
                .ok_or_else(|| "admission sequence overflowed".to_string())?;
            if plan.first_sequence != next_sequence {
                return Err("admission batch is not the next venue sequence".into());
            }
            let before_root = Self::calculate_root(&database)?;
            self.require_quorum(&statement, &before_root, approval)?;
            database.execute(&format!(
                "INSERT INTO admission_batches(\
                    batch_id,operation_id,venue_id,epoch,slot,batch_digest,order_digest,\
                    population,consumed,expires_at,statement) \
                 VALUES({},{},{},{},{},{},{},{},0,{},{})",
                blob(&plan.batch_id),
                blob(&plan.operation_id),
                blob(&plan.venue_id),
                plan.epoch,
                plan.slot,
                blob(&plan.batch_digest),
                blob(&plan.order_digest),
                plan.admission_digests.len(),
                plan.expires_at,
                blob(&statement),
            ))?;
            for (index, admission) in plan.admission_digests.iter().enumerate() {
                let sequence = plan.first_sequence + index as u64;
                database.execute(&format!(
                    "INSERT INTO admission_batch_entries(\
                        batch_id,sequence,admission_digest,consumed_by) VALUES({},{},{},{})",
                    blob(&plan.batch_id),
                    sequence,
                    blob(admission),
                    blob(&ZERO),
                ))?;
            }
            Self::load_admission_batch(&database, &plan.batch_id)?
                .ok_or_else(|| "registered admission batch was not persisted".to_string())
        })();
        match result {
            Ok(snapshot) => {
                database.execute("COMMIT")?;
                Ok(snapshot)
            }
            Err(error) => {
                let _ = database.execute("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Advance one opaque lane that has no product reservation. The same
    /// strict cursor is used by real reservations, so skipping or reordering a
    /// lane requires the configured quorum to sign the exact skip statement.
    pub fn advance_admission_slot(
        &self,
        advance: &AdmissionSlotAdvance,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<AdmissionBatchSnapshot, String> {
        advance.body()?;
        let statement = advance.statement()?;
        let database = self.database.lock().expect("DeFMI database lock");
        database.execute("BEGIN IMMEDIATE")?;
        let result = (|| {
            let prior = database.query(&format!(
                "SELECT hex(statement) FROM admission_operations WHERE operation_id={}",
                blob(&advance.operation_id)
            ))?;
            if let Some(row) = prior.first() {
                if parse_hex32(
                    row[0].as_deref().unwrap_or_default(),
                    "admission advance statement",
                )? != statement
                {
                    return Err("admission advance operation id was reused".into());
                }
                return Self::load_admission_batch(&database, &advance.batch_id)?
                    .ok_or_else(|| "idempotent admission advance lost its batch".to_string());
            }
            let batch = Self::load_admission_batch(&database, &advance.batch_id)?
                .ok_or_else(|| "admission advance names an unknown batch".to_string())?;
            if now > batch.expires_at {
                return Err("admission batch has expired".into());
            }
            let expected_sequence = batch
                .first_sequence
                .checked_add(batch.consumed)
                .ok_or_else(|| "admission sequence overflowed".to_string())?;
            let last_sequence = batch
                .first_sequence
                .checked_add(batch.population - 1)
                .ok_or_else(|| "admission sequence overflowed".to_string())?;
            if advance.sequence != expected_sequence || advance.sequence > last_sequence {
                return Err("admission lane is not the next fixed-population sequence".into());
            }
            let expected = database.query(&format!(
                "SELECT hex(admission_digest),hex(consumed_by) FROM admission_batch_entries \
                 WHERE batch_id={} AND sequence={}",
                blob(&advance.batch_id),
                advance.sequence,
            ))?;
            let row = expected
                .first()
                .ok_or_else(|| "admission plan omits its next sequence".to_string())?;
            if parse_hex32(
                row[0].as_deref().unwrap_or_default(),
                "planned admission digest",
            )? != advance.admission_digest
                || parse_hex32(row[1].as_deref().unwrap_or_default(), "admission consumer")? != ZERO
            {
                return Err("admission advance does not match the unconsumed planned lane".into());
            }
            let before_root = Self::calculate_root(&database)?;
            self.require_quorum(&statement, &before_root, approval)?;
            database.execute(&format!(
                "UPDATE admission_batch_entries SET consumed_by={} \
                 WHERE batch_id={} AND sequence={} AND consumed_by={};\
                 UPDATE admission_batches SET consumed={} WHERE batch_id={};\
                 INSERT INTO admission_operations(operation_id,batch_id,sequence,statement) \
                 VALUES({},{},{},{})",
                blob(&advance.operation_id),
                blob(&advance.batch_id),
                advance.sequence,
                blob(&ZERO),
                batch.consumed + 1,
                blob(&advance.batch_id),
                blob(&advance.operation_id),
                blob(&advance.batch_id),
                advance.sequence,
                blob(&statement),
            ))?;
            Self::load_admission_batch(&database, &advance.batch_id)?
                .ok_or_else(|| "advanced admission batch disappeared".to_string())
        })();
        match result {
            Ok(snapshot) => {
                database.execute("COMMIT")?;
                Ok(snapshot)
            }
            Err(error) => {
                let _ = database.execute("ROLLBACK");
                Err(error)
            }
        }
    }

    fn consume_ordered_admission(
        database: &Database,
        admission: &qomm_transport::order::OrderedAdmission,
        operation_id: &[u8; 32],
        now: u64,
    ) -> Result<[u8; 32], String> {
        let rows = database.query(&format!(
            "SELECT hex(batch_id),\
                    (SELECT MIN(sequence) FROM admission_batch_entries \
                     WHERE admission_batch_entries.batch_id=admission_batches.batch_id),\
                    population,consumed,expires_at,hex(order_digest) FROM admission_batches \
             WHERE venue_id={} AND epoch={} AND slot={} AND batch_digest={}",
            blob(&admission.venue_id),
            admission.epoch,
            admission.slot,
            blob(&admission.batch_digest),
        ))?;
        let row = rows.first().ok_or_else(|| {
            "Taker reserve has no registered fixed-population admission batch".to_string()
        })?;
        let batch_id = parse_hex32(row[0].as_deref().unwrap_or_default(), "admission batch id")?;
        let first_sequence = row[1]
            .as_deref()
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|error| error.to_string())?;
        let population = row[2]
            .as_deref()
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|error| error.to_string())?;
        let consumed = row[3]
            .as_deref()
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|error| error.to_string())?;
        let expires_at = row[4]
            .as_deref()
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|error| error.to_string())?;
        let order_digest = parse_hex32(
            row[5].as_deref().unwrap_or_default(),
            "admission order digest",
        )?;
        let expected_sequence = first_sequence
            .checked_add(consumed)
            .ok_or_else(|| "admission sequence overflowed".to_string())?;
        let last_sequence = first_sequence
            .checked_add(population - 1)
            .ok_or_else(|| "admission sequence overflowed".to_string())?;
        if now > expires_at
            || admission.sequence != expected_sequence
            || admission.sequence > last_sequence
            || admission.order_digest != order_digest
        {
            return Err("Taker RFQ is expired or not next in the fixed-population order".into());
        }
        let admission_digest = admission.certified_digest()?;
        let expected = database.query(&format!(
            "SELECT hex(admission_digest),hex(consumed_by) FROM admission_batch_entries \
             WHERE batch_id={} AND sequence={}",
            blob(&batch_id),
            admission.sequence,
        ))?;
        let entry = expected
            .first()
            .ok_or_else(|| "registered admission batch omits the Taker sequence".to_string())?;
        if parse_hex32(
            entry[0].as_deref().unwrap_or_default(),
            "planned Taker admission digest",
        )? != admission_digest
            || parse_hex32(
                entry[1].as_deref().unwrap_or_default(),
                "planned Taker admission consumer",
            )? != ZERO
        {
            return Err("Taker RFQ does not match the next unconsumed admission lane".into());
        }
        database.execute(&format!(
            "UPDATE admission_batch_entries SET consumed_by={} \
             WHERE batch_id={} AND sequence={} AND consumed_by={};\
             UPDATE admission_batches SET consumed={} WHERE batch_id={}",
            blob(operation_id),
            blob(&batch_id),
            admission.sequence,
            blob(&ZERO),
            consumed + 1,
            blob(&batch_id),
        ))?;
        Ok(batch_id)
    }

    pub fn register_asset(
        &self,
        asset: &AssetDefinition,
        approval: &QuorumApproval,
    ) -> Result<(), String> {
        asset.body()?;
        let statement = asset.statement()?;
        let database = self.database.lock().expect("DeFMI database lock");
        let existing = database.query(&format!(
            "SELECT hex(statement) FROM assets WHERE asset_id={}",
            blob(&asset.asset_id)
        ))?;
        if let Some(row) = existing.first() {
            let same = hex::decode(row[0].as_deref().unwrap_or_default())
                .map_err(|error| error.to_string())?
                == statement;
            return if same {
                Ok(())
            } else {
                Err("asset identifier was reused for another definition".into())
            };
        }
        let root = Self::calculate_root(&database)?;
        self.require_quorum(&statement, &root, approval)?;
        database
            .execute(&format!(
                "INSERT INTO assets(asset_id,code,kind,decimals,terms_digest,statement) VALUES({},{},{},{},{},{})",
                blob(&asset.asset_id), quoted(&asset.code), quoted(asset.kind.as_str()), asset.decimals,
                blob(&asset.terms_digest), blob(&statement)
            ))
            .map_err(|_| "asset or authorization is already registered".to_string())
    }

    pub fn open_account(
        &self,
        opening: &AccountOpening,
        approval: &QuorumApproval,
    ) -> Result<(), String> {
        opening.body()?;
        let statement = opening.statement()?;
        let database = self.database.lock().expect("DeFMI database lock");
        let existing = database.query(&format!(
            "SELECT hex(opening_statement) FROM accounts WHERE handle={}",
            blob(&opening.handle)
        ))?;
        if let Some(row) = existing.first() {
            let same = hex::decode(row[0].as_deref().unwrap_or_default())
                .map_err(|error| error.to_string())?
                == statement;
            return if same {
                Ok(())
            } else {
                Err("account handle was reused for another opening".into())
            };
        }
        let root = Self::calculate_root(&database)?;
        self.require_quorum(&statement, &root, approval)?;
        let asset = database.query(&format!(
            "SELECT active FROM assets WHERE asset_id={}",
            blob(&opening.asset_id)
        ))?;
        if asset
            .first()
            .and_then(|row| row.first())
            .and_then(Option::as_deref)
            != Some("1")
        {
            return Err("account asset is unknown or inactive".into());
        }
        database
            .execute(&format!(
                "INSERT INTO accounts(handle,asset_id,commitment,sequence,opening_statement) VALUES({},{},{},0,{})",
                blob(&opening.handle), blob(&opening.asset_id), blob(&opening.commitment), blob(&statement)
            ))
            .map_err(|_| "account or issuance authorization already exists".to_string())
    }

    pub fn register_guarantor(
        &self,
        guarantor: &GuarantorDefinition,
        approval: &QuorumApproval,
    ) -> Result<(), String> {
        guarantor.body()?;
        let statement = guarantor.statement()?;
        let database = self.database.lock().expect("DeFMI database lock");
        let existing = database.query(&format!(
            "SELECT hex(statement) FROM guarantors WHERE guarantor_id={}",
            blob(&guarantor.guarantor_id)
        ))?;
        if let Some(row) = existing.first() {
            let same = parse_hex32(row[0].as_deref().unwrap_or_default(), "guarantor statement")?
                == statement;
            return if same {
                Ok(())
            } else {
                Err("guarantor identifier was reused for another definition".into())
            };
        }
        let root = Self::calculate_root(&database)?;
        self.require_quorum(&statement, &root, approval)?;
        database
            .execute(&format!(
                "INSERT INTO guarantors(guarantor_id,kind,name,public_key,risk_policy_digest,statement) \
                 VALUES({},{},{},{},{},{})",
                blob(&guarantor.guarantor_id),
                quoted(guarantor.kind.as_str()),
                quoted(&guarantor.name),
                blob(&guarantor.public_key),
                blob(&guarantor.risk_policy_digest),
                blob(&statement),
            ))
            .map_err(|_| "guarantor or public key is already registered".to_string())
    }

    fn credit_operation(
        database: &Database,
        operation_id: &[u8; 32],
        statement: &[u8; 32],
    ) -> Result<bool, String> {
        let rows = database.query(&format!(
            "SELECT hex(statement) FROM credit_operations WHERE operation_id={}",
            blob(operation_id)
        ))?;
        let Some(row) = rows.first() else {
            return Ok(false);
        };
        if parse_hex32(
            row[0].as_deref().unwrap_or_default(),
            "credit operation statement",
        )? != *statement
        {
            return Err("credit operation identifier was reused for another transition".into());
        }
        Ok(true)
    }

    fn load_credit_facility(
        database: &Database,
        facility_id: &[u8; 32],
    ) -> Result<Option<CreditFacilitySnapshot>, String> {
        let rows = database.query(&format!(
            "SELECT hex(facility_id),hex(guarantor_id),hex(beneficiary_commitment),\
                    hex(rail_asset_id),hex(cap_commitment),hex(available_commitment),\
                    hex(held_commitment),hex(outstanding_commitment),hex(overlimit_commitment),\
                    hex(collateral_commitment),\
                    hex(risk_policy_digest),valid_from,valid_until,status,sequence \
             FROM credit_facilities WHERE facility_id={}",
            blob(facility_id)
        ))?;
        rows.first()
            .map(|row| {
                Ok(CreditFacilitySnapshot {
                    facility_id: parse_hex32(row[0].as_deref().unwrap_or_default(), "facility_id")?,
                    guarantor_id: parse_hex32(
                        row[1].as_deref().unwrap_or_default(),
                        "guarantor_id",
                    )?,
                    beneficiary_commitment: parse_hex32(
                        row[2].as_deref().unwrap_or_default(),
                        "beneficiary_commitment",
                    )?,
                    rail_asset_id: parse_hex32(
                        row[3].as_deref().unwrap_or_default(),
                        "rail_asset_id",
                    )?,
                    cap_commitment: parse_hex32(
                        row[4].as_deref().unwrap_or_default(),
                        "cap_commitment",
                    )?,
                    available_commitment: parse_hex32(
                        row[5].as_deref().unwrap_or_default(),
                        "available_commitment",
                    )?,
                    held_commitment: parse_hex32(
                        row[6].as_deref().unwrap_or_default(),
                        "held_commitment",
                    )?,
                    outstanding_commitment: parse_hex32(
                        row[7].as_deref().unwrap_or_default(),
                        "outstanding_commitment",
                    )?,
                    overlimit_commitment: parse_hex32(
                        row[8].as_deref().unwrap_or_default(),
                        "overlimit_commitment",
                    )?,
                    collateral_commitment: parse_hex32(
                        row[9].as_deref().unwrap_or_default(),
                        "collateral_commitment",
                    )?,
                    risk_policy_digest: parse_hex32(
                        row[10].as_deref().unwrap_or_default(),
                        "risk_policy_digest",
                    )?,
                    valid_from: row[11]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                    valid_until: row[12]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                    status: CreditFacilityStatus::parse(row[13].as_deref().unwrap_or_default())?,
                    sequence: row[14]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                })
            })
            .transpose()
    }

    pub fn grant_credit_facility(
        &self,
        grant: &CreditFacilityGrant,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<CreditFacilitySnapshot, String> {
        grant.unsigned_body()?;
        let statement = grant.statement()?;
        let database = self.database.lock().expect("DeFMI database lock");
        database.execute("BEGIN IMMEDIATE")?;
        let result = (|| {
            if Self::credit_operation(&database, &grant.operation_id, &statement)? {
                return Self::load_credit_facility(&database, &grant.facility_id)?
                    .ok_or_else(|| "idempotent credit grant has no facility state".to_string());
            }
            if now > grant.valid_until || now > i64::MAX as u64 {
                return Err("credit facility grant has expired or cannot be stored".into());
            }
            let before_root = Self::calculate_root(&database)?;
            self.require_quorum(&statement, &before_root, approval)?;
            let guarantor_rows = database.query(&format!(
                "SELECT hex(public_key),hex(risk_policy_digest),active FROM guarantors \
                 WHERE guarantor_id={}",
                blob(&grant.guarantor_id)
            ))?;
            let guarantor = guarantor_rows
                .first()
                .ok_or_else(|| "credit facility names an unknown guarantor".to_string())?;
            if guarantor[2].as_deref() != Some("1") {
                return Err("credit facility guarantor is inactive".into());
            }
            if parse_hex32(
                guarantor[1].as_deref().unwrap_or_default(),
                "risk_policy_digest",
            )? != grant.risk_policy_digest
            {
                return Err("credit facility uses an unregistered risk policy".into());
            }
            let public_key = VerifyingKey::from_bytes(&parse_hex32(
                guarantor[0].as_deref().unwrap_or_default(),
                "guarantor public key",
            )?)
            .map_err(|_| "stored guarantor public key is malformed".to_string())?;
            public_key
                .verify(&grant.guarantor_message()?, &grant.guarantor_signature)
                .map_err(|_| "credit facility lacks the guarantor signature".to_string())?;
            if database
                .query(&format!(
                    "SELECT active FROM assets WHERE asset_id={}",
                    blob(&grant.rail_asset_id)
                ))?
                .first()
                .and_then(|row| row.first())
                .and_then(Option::as_deref)
                != Some("1")
            {
                return Err("credit facility asset rail is unknown or inactive".into());
            }
            if Self::load_credit_facility(&database, &grant.facility_id)?.is_some() {
                return Err("credit facility identifier is already registered".into());
            }
            if !database
                .query(&format!(
                    "SELECT hex(facility_id) FROM credit_facility_scopes WHERE \
                     guarantor_id={} AND beneficiary_commitment={} AND rail_asset_id={}",
                    blob(&grant.guarantor_id),
                    blob(&grant.beneficiary_commitment),
                    blob(&grant.rail_asset_id),
                ))?
                .is_empty()
            {
                return Err(
                    "this guarantor already has a facility for the legal entity and asset rail"
                        .into(),
                );
            }
            database.execute(&format!(
                "INSERT INTO credit_facilities(\
                    facility_id,guarantor_id,beneficiary_commitment,rail_asset_id,\
                    cap_commitment,available_commitment,held_commitment,\
                    outstanding_commitment,overlimit_commitment,collateral_commitment,risk_policy_digest,\
                    valid_from,valid_until,status,sequence,grant_statement) \
                 VALUES({},{},{},{},{},{},{},{},{},{},{},{},{},'active',0,{})",
                blob(&grant.facility_id),
                blob(&grant.guarantor_id),
                blob(&grant.beneficiary_commitment),
                blob(&grant.rail_asset_id),
                blob(&grant.cap_commitment),
                blob(&grant.available_commitment),
                blob(&grant.held_commitment),
                blob(&grant.outstanding_commitment),
                blob(&ZERO),
                blob(&grant.collateral_commitment),
                blob(&grant.risk_policy_digest),
                grant.valid_from,
                grant.valid_until,
                blob(&statement),
            ))?;
            database.execute(&format!(
                "INSERT INTO credit_facility_scopes(\
                    guarantor_id,beneficiary_commitment,rail_asset_id,facility_id) \
                 VALUES({},{},{},{})",
                blob(&grant.guarantor_id),
                blob(&grant.beneficiary_commitment),
                blob(&grant.rail_asset_id),
                blob(&grant.facility_id),
            ))?;
            database.execute(&format!(
                "INSERT INTO credit_operations(operation_id,facility_id,kind,statement) \
                 VALUES({},{},'grant',{})",
                blob(&grant.operation_id),
                blob(&grant.facility_id),
                blob(&statement),
            ))?;
            Self::load_credit_facility(&database, &grant.facility_id)?
                .ok_or_else(|| "credit facility was not stored".to_string())
        })();
        match result {
            Ok(snapshot) => {
                database.execute("COMMIT")?;
                Ok(snapshot)
            }
            Err(error) => {
                let _ = database.execute("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Apply a proved facility transition inside the caller's SQL transaction.
    /// Authorization and idempotency are intentionally outside: standalone,
    /// bound-reserve, and product-settlement statements authorize different
    /// envelopes while sharing exactly one state-transition implementation.
    fn apply_credit_transition(
        database: &Database,
        transition: &CreditFacilityTransition,
        operation_statement: &[u8; 32],
        operation_kind: &str,
        now: u64,
    ) -> Result<CreditFacilitySnapshot, String> {
        if now > i64::MAX as u64 || transition.expires_at > i64::MAX as u64 {
            return Err("credit reservation time cannot be stored".into());
        }
        let facility = Self::load_credit_facility(database, &transition.facility_id)?
            .ok_or_else(|| "credit transition names an unknown facility".to_string())?;
        if facility.sequence != transition.before_sequence
            || facility.available_commitment != transition.before_available_commitment
            || facility.held_commitment != transition.before_held_commitment
            || facility.outstanding_commitment != transition.before_outstanding_commitment
        {
            return Err("credit transition was proved against stale facility state".into());
        }
        match transition.kind {
            CreditTransitionKind::Hold => {
                if facility.status != CreditFacilityStatus::Active
                    || now < facility.valid_from
                    || now > facility.valid_until
                {
                    return Err("credit facility is not active for a new RFQ".into());
                }
                if transition.expires_at < now || transition.expires_at > facility.valid_until {
                    return Err("credit hold expiry is outside the facility validity".into());
                }
                if transition.before_outstanding_commitment
                    != transition.after_outstanding_commitment
                {
                    return Err("creating a hold cannot change settled debt".into());
                }
                if !database
                    .query(&format!(
                        "SELECT 1 FROM credit_holds WHERE hold_id={}",
                        blob(&transition.hold_id)
                    ))?
                    .is_empty()
                {
                    return Err("RFQ hold identifier is already registered".into());
                }
                database.execute(&format!(
                    "INSERT INTO credit_holds(\
                        hold_id,facility_id,query_commitment,amount_commitment,\
                        expires_at,status,settlement_digest,created_sequence,updated_sequence) \
                     VALUES({},{},{},{},{},'active',{}, {}, {})",
                    blob(&transition.hold_id),
                    blob(&transition.facility_id),
                    blob(&transition.query_commitment),
                    blob(&transition.amount_commitment),
                    transition.expires_at,
                    blob(&ZERO),
                    transition.before_sequence + 1,
                    transition.before_sequence + 1,
                ))?;
            }
            CreditTransitionKind::Release | CreditTransitionKind::Consume => {
                let rows = database.query(&format!(
                    "SELECT hex(facility_id),hex(query_commitment),hex(amount_commitment),\
                            expires_at,status FROM credit_holds WHERE hold_id={}",
                    blob(&transition.hold_id)
                ))?;
                let hold = rows
                    .first()
                    .ok_or_else(|| "credit transition names an unknown RFQ hold".to_string())?;
                if parse_hex32(hold[0].as_deref().unwrap_or_default(), "hold facility_id")?
                    != transition.facility_id
                    || parse_hex32(
                        hold[1].as_deref().unwrap_or_default(),
                        "hold query_commitment",
                    )? != transition.query_commitment
                    || parse_hex32(
                        hold[2].as_deref().unwrap_or_default(),
                        "hold amount_commitment",
                    )? != transition.amount_commitment
                    || hold[3]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?
                        != transition.expires_at
                    || hold[4].as_deref() != Some("active")
                {
                    return Err("credit hold context is stale or does not match the RFQ".into());
                }
                if transition.kind == CreditTransitionKind::Release {
                    if now <= transition.expires_at {
                        return Err(
                            "an RFQ hold cannot be released before its signed expiry".into()
                        );
                    }
                    if transition.before_outstanding_commitment
                        != transition.after_outstanding_commitment
                    {
                        return Err("releasing a hold cannot change settled debt".into());
                    }
                } else if now > transition.expires_at {
                    return Err("an expired RFQ hold cannot be consumed".into());
                }
                let status = if transition.kind == CreditTransitionKind::Release {
                    "released"
                } else {
                    "consumed"
                };
                database.execute(&format!(
                    "UPDATE credit_holds SET status={},settlement_digest={},updated_sequence={} \
                     WHERE hold_id={}",
                    quoted(status),
                    blob(&transition.settlement_digest),
                    transition.before_sequence + 1,
                    blob(&transition.hold_id),
                ))?;
            }
        }
        database.execute(&format!(
            "UPDATE credit_facilities SET available_commitment={},held_commitment={},\
                    outstanding_commitment={},sequence=sequence+1 \
             WHERE facility_id={} AND sequence={}",
            blob(&transition.after_available_commitment),
            blob(&transition.after_held_commitment),
            blob(&transition.after_outstanding_commitment),
            blob(&transition.facility_id),
            transition.before_sequence,
        ))?;
        let changed = database
            .query("SELECT changes()")?
            .first()
            .and_then(|row| row.first())
            .and_then(Option::as_deref)
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|error| error.to_string())?;
        if changed != 1 {
            return Err("credit facility compare-and-swap lost a concurrent update".into());
        }
        database.execute(&format!(
            "INSERT INTO credit_operations(operation_id,facility_id,kind,statement) \
             VALUES({},{},{},{})",
            blob(&transition.operation_id),
            blob(&transition.facility_id),
            quoted(operation_kind),
            blob(operation_statement),
        ))?;
        Self::load_credit_facility(database, &transition.facility_id)?
            .ok_or_else(|| "credit facility disappeared during transition".to_string())
    }

    pub fn transition_credit_facility(
        &self,
        transition: &CreditFacilityTransition,
        relation_proof: &CreditFacilityRelationProof,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<CreditFacilitySnapshot, String> {
        transition.body()?;
        relation_proof.verify(transition)?;
        let statement = transition.statement()?;
        let database = self.database.lock().expect("DeFMI database lock");
        database.execute("BEGIN IMMEDIATE")?;
        let result = (|| {
            if Self::credit_operation(&database, &transition.operation_id, &statement)? {
                return Self::load_credit_facility(&database, &transition.facility_id)?.ok_or_else(
                    || "idempotent credit transition has no facility state".to_string(),
                );
            }
            let before_root = Self::calculate_root(&database)?;
            self.require_quorum(&statement, &before_root, approval)?;
            Self::apply_credit_transition(
                &database,
                transition,
                &statement,
                transition.kind.as_str(),
                now,
            )
        })();
        match result {
            Ok(snapshot) => {
                database.execute("COMMIT")?;
                Ok(snapshot)
            }
            Err(error) => {
                let _ = database.execute("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Create the reserve that makes a signed Maker policy or Taker RFQ
    /// executable without asking that party again after seeing the quote.
    pub(crate) fn reserve_for_authorization(
        &self,
        request: ReservationExecution<'_>,
    ) -> Result<CreditFacilitySnapshot, String> {
        let ReservationExecution {
            transition,
            relation_proof,
            authorization,
            escrow,
            typed_instruction,
            typed_venue,
            asset_link,
            ordered_admission,
            approval,
            now,
        } = request;
        transition.body()?;
        relation_proof.verify(transition)?;
        if escrow.asset_id != authorization.asset_id
            || escrow.amount_commitment != transition.amount_commitment
            || escrow.statement()? != authorization.escrow_digest
            || escrow.source_handle == escrow.escrow_handle
        {
            return Err("reservation escrow differs from its signed authorization".into());
        }
        typed_venue
            .verify_typed(typed_instruction, now)
            .map_err(|error| format!("reserve zkPI failed: {error}"))?;
        let context = &typed_instruction.context;
        let expected_scope = match authorization.role {
            ReservationRole::Maker => qomm_zkpi::typed::AuthorizationScope::Maker,
            ReservationRole::Taker => qomm_zkpi::typed::AuthorizationScope::Taker,
        };
        match (authorization.role, ordered_admission) {
            (ReservationRole::Maker, None) => {}
            (ReservationRole::Taker, Some(admission))
                if admission.certified_digest()? == authorization.admission_receipt_digest
                    && admission.venue_id == context.venue_id
                    && admission.ticket_id == authorization.admission_ticket_id
                    && admission.slot == authorization.admission_slot
                    && admission.epoch == authorization.admission_epoch
                    && admission.sequence == authorization.admission_sequence
                    && admission.rfq_nullifier == authorization.rfq_nullifier
                    && admission.taker_entity_commitment == authorization.entity_commitment
                    && admission.taker_mandate_digest == authorization.mandate_digest
                    && admission.expires_at == transition.expires_at => {}
            (ReservationRole::Maker, Some(_)) => {
                return Err("Maker policy reserve must not carry an RFQ admission receipt".into())
            }
            (ReservationRole::Taker, _) => {
                return Err("Taker reserve lacks its exact ordered admission receipt".into())
            }
        }
        let (reservation_id, reservation_sequence) = match authorization.role {
            ReservationRole::Maker => (
                context.maker_reservation_id,
                context.maker_reservation_sequence,
            ),
            ReservationRole::Taker => (
                context.taker_reservation_id,
                context.taker_reservation_sequence,
            ),
        };
        if context.operation != qomm_zkpi::typed::OperationKind::Reserve
            || context.scope != expected_scope
            || context.direction as u8 != authorization.direction
            || context.reserve_handle != reserve_handle_for(&transition.facility_id)
            || reservation_id != transition.hold_id
            || reservation_sequence != transition.before_sequence
            || typed_instruction
                .payment
                .amount_commitment
                .compress()
                .to_bytes()
                != transition.amount_commitment
            || typed_instruction.payment.deadline != transition.expires_at
        {
            return Err("reserve zkPI does not describe this facility hold".into());
        }
        match authorization.role {
            ReservationRole::Maker
                if context.maker_policy_digest != authorization.authorization_digest
                    || context.maker_mandate_digest != authorization.mandate_digest =>
            {
                return Err("Maker reserve zkPI is bound to another policy mandate".into());
            }
            ReservationRole::Taker
                if authorization.authorization_digest != authorization.mandate_digest
                    || context.taker_mandate_digest != authorization.mandate_digest =>
            {
                return Err("Taker reserve zkPI is bound to another execution mandate".into());
            }
            _ => {}
        }
        let typed_bytes = qomm_zkpi::typed_wire::encode(typed_instruction);
        let typed_digest: [u8; 32] = Sha256::digest(&typed_bytes).into();
        if typed_digest != authorization.typed_reserve_digest
            || typed_instruction.payment.nullifier() != authorization.reserve_nullifier
            || !crate::asset_link::verify(
                &typed_venue.key,
                &authorization.asset_id,
                &typed_instruction.payment.asset_commitment,
                asset_link,
            )
            || asset_link.digest(
                &authorization.asset_id,
                &typed_instruction.payment.asset_commitment,
            ) != authorization.asset_link_proof_digest
        {
            return Err("reserve zkPI digest, nullifier, or hidden asset link is invalid".into());
        }
        let statement = authorization.statement(transition)?;
        let database = self.database.lock().expect("DeFMI database lock");
        database.execute("BEGIN IMMEDIATE")?;
        let result = (|| {
            if Self::credit_operation(&database, &transition.operation_id, &statement)? {
                let binding = database.query(&format!(
                    "SELECT hex(receipt_digest) FROM reservation_bindings WHERE hold_id={}",
                    blob(&transition.hold_id)
                ))?;
                if binding
                    .first()
                    .and_then(|row| row.first())
                    .and_then(Option::as_deref)
                    .is_none_or(|stored| {
                        parse_hex32(stored, "reserve receipt").ok() != Some(statement)
                    })
                {
                    return Err("idempotent bound reserve has another receipt".into());
                }
                if database
                    .query(&format!(
                        "SELECT 1 FROM reservation_escrows WHERE hold_id={} AND status='active'",
                        blob(&transition.hold_id)
                    ))?
                    .is_empty()
                {
                    return Err("idempotent bound reserve has no active asset escrow".into());
                }
                return Self::load_credit_facility(&database, &transition.facility_id)?
                    .ok_or_else(|| "idempotent bound reserve has no facility state".to_string());
            }
            let before_root = Self::calculate_root(&database)?;
            if context.before_state_root != before_root {
                return Err("reserve zkPI was authorized against a stale DeFMI state root".into());
            }
            self.require_quorum(&statement, &before_root, approval)?;
            let facility = Self::load_credit_facility(&database, &transition.facility_id)?
                .ok_or_else(|| "bound reserve names an unknown facility".to_string())?;
            if facility.beneficiary_commitment != authorization.entity_commitment
                || facility.rail_asset_id != authorization.asset_id
            {
                return Err("reserve entity or asset does not match its facility".into());
            }
            if authorization.role == ReservationRole::Taker
                && !database
                    .query(&format!(
                        "SELECT 1 FROM reservation_bindings WHERE role='taker' AND rfq_nullifier={}",
                        blob(&authorization.rfq_nullifier)
                    ))?
                    .is_empty()
            {
                return Err("one-use RFQ already has a Taker reservation".into());
            }
            if authorization.role == ReservationRole::Taker {
                for (column, value, message) in [
                    (
                        "admission_ticket_id",
                        blob(&authorization.admission_ticket_id),
                        "admission ticket was already used by another RFQ",
                    ),
                    (
                        "admission_receipt_digest",
                        blob(&authorization.admission_receipt_digest),
                        "admission receipt was already used by another RFQ",
                    ),
                ] {
                    if !database
                        .query(&format!(
                            "SELECT 1 FROM reservation_bindings WHERE role='taker' AND {column}={value}"
                        ))?
                        .is_empty()
                    {
                        return Err(message.into());
                    }
                }
            }
            let source = database.query(&format!(
                "SELECT hex(asset_id),hex(commitment),sequence FROM accounts WHERE handle={}",
                blob(&escrow.source_handle)
            ))?;
            let source = source
                .first()
                .ok_or_else(|| "reservation escrow names an unknown source account".to_string())?;
            if parse_hex32(
                source[0].as_deref().unwrap_or_default(),
                "escrow source asset",
            )? != escrow.asset_id
                || parse_hex32(
                    source[1].as_deref().unwrap_or_default(),
                    "escrow source commitment",
                )? != escrow.source_before_commitment
                || source[2]
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?
                    != escrow.source_before_sequence
            {
                return Err(
                    "reservation escrow was proved against stale source-account state".into(),
                );
            }
            let admission_batch_id = match ordered_admission {
                Some(admission) => Self::consume_ordered_admission(
                    &database,
                    admission,
                    &transition.operation_id,
                    now,
                )?,
                None => ZERO,
            };
            if admission_batch_id != authorization.admission_batch_id {
                return Err("Taker reservation names another admission batch".into());
            }
            let snapshot = Self::apply_credit_transition(
                &database,
                transition,
                &statement,
                "bound_hold",
                now,
            )?;
            database.execute(&format!(
                "INSERT INTO reservation_bindings(\
                    hold_id,role,entity_commitment,asset_id,direction,authorization_digest,\
                    mandate_digest,typed_reserve_digest,reserve_nullifier,asset_link_proof_digest,\
                    limit_price_commitment,rfq_nullifier,policy_version,admission_ticket_id,admission_slot,\
                    admission_receipt_digest,admission_epoch,admission_sequence,\
                    admission_batch_id,receipt_digest) \
                 VALUES({},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{})",
                blob(&transition.hold_id),
                quoted(authorization.role.as_str()),
                blob(&authorization.entity_commitment),
                blob(&authorization.asset_id),
                authorization.direction,
                blob(&authorization.authorization_digest),
                blob(&authorization.mandate_digest),
                blob(&authorization.typed_reserve_digest),
                blob(&authorization.reserve_nullifier),
                blob(&authorization.asset_link_proof_digest),
                blob(&authorization.limit_price_commitment),
                blob(&authorization.rfq_nullifier),
                authorization.policy_version,
                blob(&authorization.admission_ticket_id),
                authorization.admission_slot,
                blob(&authorization.admission_receipt_digest),
                authorization.admission_epoch,
                authorization.admission_sequence,
                blob(&admission_batch_id),
                blob(&statement),
            ))?;
            database.execute(&format!(
                "UPDATE accounts SET commitment={},sequence=sequence+1 WHERE handle={};\
                 INSERT INTO reservation_escrows(\
                    hold_id,source_handle,escrow_handle,asset_id,amount_commitment,\
                    source_before_commitment,source_after_commitment,source_before_sequence,\
                    proof_digest,status,settlement_digest) \
                 VALUES({},{},{},{},{},{},{},{},{},'active',{})",
                blob(&escrow.source_after_commitment),
                blob(&escrow.source_handle),
                blob(&transition.hold_id),
                blob(&escrow.source_handle),
                blob(&escrow.escrow_handle),
                blob(&escrow.asset_id),
                blob(&escrow.amount_commitment),
                blob(&escrow.source_before_commitment),
                blob(&escrow.source_after_commitment),
                escrow.source_before_sequence,
                blob(&escrow.proof_digest),
                blob(&ZERO),
            ))?;
            Ok(snapshot)
        })();
        match result {
            Ok(snapshot) => {
                database.execute("COMMIT")?;
                Ok(snapshot)
            }
            Err(error) => {
                let _ = database.execute("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Release an expired product reservation and restore the exact committed
    /// maximum to its original source account.  A plain credit `Release`
    /// transition is insufficient because the asset was removed from the
    /// account when the product hold was admitted.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn release_product_reservation(
        &self,
        order: &ProductReleaseOrder,
        relation_proof: &CreditFacilityRelationProof,
        typed_instruction: &qomm_zkpi::typed::TypedInstruction,
        typed_venue: &qomm_zkpi::Venue,
        asset_link: &crate::asset_link::AssetLinkProof,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<SettlementReceipt, String> {
        self.release_product_reservation_inner(
            order,
            relation_proof,
            typed_instruction,
            typed_venue,
            asset_link,
            approval,
            now,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn preflight_product_release(
        &self,
        order: &ProductReleaseOrder,
        relation_proof: &CreditFacilityRelationProof,
        typed_instruction: &qomm_zkpi::typed::TypedInstruction,
        typed_venue: &qomm_zkpi::Venue,
        asset_link: &crate::asset_link::AssetLinkProof,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(), String> {
        self.release_product_reservation_inner(
            order,
            relation_proof,
            typed_instruction,
            typed_venue,
            asset_link,
            approval,
            now,
            false,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn release_product_reservation_inner(
        &self,
        order: &ProductReleaseOrder,
        relation_proof: &CreditFacilityRelationProof,
        typed_instruction: &qomm_zkpi::typed::TypedInstruction,
        typed_venue: &qomm_zkpi::Venue,
        asset_link: &crate::asset_link::AssetLinkProof,
        approval: &QuorumApproval,
        now: u64,
        commit: bool,
    ) -> Result<SettlementReceipt, String> {
        let request = order.body()?;
        relation_proof.verify(&order.transition)?;
        typed_venue
            .verify_typed(typed_instruction, now)
            .map_err(|error| format!("release zkPI failed: {error}"))?;
        let context = &typed_instruction.context;
        let expected_scope = match order.role {
            ReservationRole::Maker => qomm_zkpi::typed::AuthorizationScope::Maker,
            ReservationRole::Taker => qomm_zkpi::typed::AuthorizationScope::Taker,
        };
        let (reservation_id, reservation_sequence, reserve_receipt) = match order.role {
            ReservationRole::Maker => (
                context.maker_reservation_id,
                context.maker_reservation_sequence,
                context.maker_reserve_receipt_digest,
            ),
            ReservationRole::Taker => (
                context.taker_reservation_id,
                context.taker_reservation_sequence,
                context.taker_reserve_receipt_digest,
            ),
        };
        if context.operation != qomm_zkpi::typed::OperationKind::Release
            || context.scope != expected_scope
            || context.reserve_handle != reserve_handle_for(&order.transition.facility_id)
            || reservation_id != order.transition.hold_id
            || reservation_sequence != order.transition.before_sequence
            || reserve_receipt != order.reserve_receipt_digest
            || typed_instruction
                .payment
                .amount_commitment
                .compress()
                .to_bytes()
                != order.transition.amount_commitment
            || typed_instruction.payment.nullifier() != order.release_nullifier
            || typed_instruction.payment.deadline != order.release_deadline
        {
            return Err("release zkPI does not describe this reservation state".into());
        }
        let typed_digest: [u8; 32] =
            Sha256::digest(qomm_zkpi::typed_wire::encode(typed_instruction)).into();
        if typed_digest != order.typed_instruction_digest
            || !crate::asset_link::verify(
                &typed_venue.key,
                &order.asset_id,
                &typed_instruction.payment.asset_commitment,
                asset_link,
            )
            || asset_link.digest(&order.asset_id, &typed_instruction.payment.asset_commitment)
                != order.asset_link_proof_digest
        {
            return Err("release zkPI digest or hidden asset link is invalid".into());
        }
        let rail = match self.asset_kind(&order.asset_id)? {
            AssetKind::Cash => crate::settlement::CASH_RAIL,
            AssetKind::Security
            | AssetKind::Fund
            | AssetKind::Commodity
            | AssetKind::Carbon
            | AssetKind::Other => crate::settlement::SECURITIES_RAIL,
        };
        let expected_refund: [u8; 32] =
            crate::settlement::account_of(&typed_instruction.payment.payee_handle, rail)
                .try_into()
                .map_err(|_| "derived release account handle is not 32 bytes".to_string())?;
        if order.refund_leg.handle != expected_refund {
            return Err("release refunds an account other than the reservation owner".into());
        }
        let before_point = CompressedRistretto(order.refund_leg.before_commitment)
            .decompress()
            .ok_or_else(|| "release before commitment is not canonical".to_string())?;
        let amount_point = CompressedRistretto(order.transition.amount_commitment)
            .decompress()
            .ok_or_else(|| "release amount commitment is not canonical".to_string())?;
        if (before_point + amount_point).compress().to_bytes() != order.refund_leg.after_commitment
        {
            return Err("release account does not receive the complete asset escrow".into());
        }

        let request_bytes = canonical(&request)?.len() as u64;
        let statement = order.statement()?;
        let started = Instant::now();
        let database = self.database.lock().expect("DeFMI database lock");
        database.execute("BEGIN IMMEDIATE")?;
        let result = (|| {
            let existing = database.query(&format!(
                "SELECT hex(statement),hex(receipt_json) FROM receipts WHERE operation_id={}",
                blob(&order.transition.operation_id)
            ))?;
            if let Some(row) = existing.first() {
                let stored = parse_hex32(row[0].as_deref().unwrap_or_default(), "statement")?;
                if stored != statement {
                    return Err("operation identifier was reused for another release".into());
                }
                let raw = hex::decode(row[1].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?;
                return Ok((Self::receipt_from_json(&raw)?, true));
            }
            let before_root = Self::calculate_root(&database)?;
            if context.before_state_root != before_root {
                return Err("release zkPI was authorized against a stale DeFMI state root".into());
            }
            self.require_quorum(&statement, &before_root, approval)?;
            if now <= order.transition.expires_at || now > order.release_deadline {
                return Err(
                    "reservation is not expired or its release authorization expired".into(),
                );
            }
            if !database
                .query(&format!(
                    "SELECT 1 FROM nullifiers WHERE nullifier={}",
                    blob(&order.release_nullifier)
                ))?
                .is_empty()
            {
                return Err("release nullifier was already used".into());
            }
            let binding_rows = database.query(&format!(
                "SELECT role,hex(asset_id),hex(authorization_digest),hex(mandate_digest),\
                        hex(rfq_nullifier),hex(receipt_digest) \
                 FROM reservation_bindings WHERE hold_id={}",
                blob(&order.transition.hold_id)
            ))?;
            let binding = binding_rows
                .first()
                .ok_or_else(|| "release reservation was not product-bound".to_string())?;
            let authorization_digest = parse_hex32(
                binding[2].as_deref().unwrap_or_default(),
                "reservation authorization",
            )?;
            let mandate_digest = parse_hex32(
                binding[3].as_deref().unwrap_or_default(),
                "reservation mandate",
            )?;
            let rfq_nullifier = parse_hex32(
                binding[4].as_deref().unwrap_or_default(),
                "reservation RFQ nullifier",
            )?;
            if binding[0].as_deref() != Some(order.role.as_str())
                || parse_hex32(
                    binding[1].as_deref().unwrap_or_default(),
                    "reservation asset",
                )? != order.asset_id
                || parse_hex32(
                    binding[5].as_deref().unwrap_or_default(),
                    "reservation receipt",
                )? != order.reserve_receipt_digest
            {
                return Err("release differs from the stored reservation binding".into());
            }
            match order.role {
                ReservationRole::Maker
                    if context.maker_policy_digest != authorization_digest
                        || context.maker_mandate_digest != mandate_digest
                        || context.taker_mandate_digest != ZERO
                        || context.rfq_nullifier != ZERO =>
                {
                    return Err("Maker release names another policy or RFQ".into());
                }
                ReservationRole::Taker
                    if context.taker_mandate_digest != mandate_digest
                        || context.maker_policy_digest != ZERO
                        || context.maker_mandate_digest != ZERO
                        || context.rfq_nullifier != rfq_nullifier =>
                {
                    return Err("Taker release names another RFQ mandate".into());
                }
                _ => {}
            }
            let escrow_rows = database.query(&format!(
                "SELECT hex(source_handle),hex(asset_id),hex(amount_commitment),status \
                 FROM reservation_escrows WHERE hold_id={}",
                blob(&order.transition.hold_id)
            ))?;
            let escrow = escrow_rows
                .first()
                .ok_or_else(|| "release reservation has no asset escrow".to_string())?;
            if escrow[3].as_deref() != Some("active")
                || parse_hex32(escrow[0].as_deref().unwrap_or_default(), "escrow source")?
                    != order.refund_leg.handle
                || parse_hex32(escrow[1].as_deref().unwrap_or_default(), "escrow asset")?
                    != order.asset_id
                || parse_hex32(escrow[2].as_deref().unwrap_or_default(), "escrow amount")?
                    != order.transition.amount_commitment
            {
                return Err("release has no matching active asset escrow".into());
            }
            let account_rows = database.query(&format!(
                "SELECT hex(asset_id),hex(commitment),sequence FROM accounts WHERE handle={}",
                blob(&order.refund_leg.handle)
            ))?;
            let account = account_rows
                .first()
                .ok_or_else(|| "release refund account is unknown".to_string())?;
            if parse_hex32(account[0].as_deref().unwrap_or_default(), "refund asset")?
                != order.asset_id
                || parse_hex32(account[1].as_deref().unwrap_or_default(), "refund before")?
                    != order.refund_leg.before_commitment
                || account[2]
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?
                    != order.refund_leg.before_sequence
            {
                return Err("release was built against a stale refund account".into());
            }
            let database_before = Self::database_size(&database)?;
            Self::apply_credit_transition(
                &database,
                &order.transition,
                &statement,
                "product_release",
                now,
            )?;
            database.execute(&format!(
                "UPDATE reservation_escrows SET status='released',settlement_digest={} \
                     WHERE hold_id={} AND status='active';\
                 INSERT INTO nullifiers(nullifier,deadline,statement) VALUES({},{},{});\
                 UPDATE accounts SET commitment={},sequence=sequence+1 WHERE handle={} AND sequence={}",
                blob(&statement),
                blob(&order.transition.hold_id),
                blob(&order.release_nullifier),
                order.release_deadline,
                blob(&statement),
                blob(&order.refund_leg.after_commitment),
                blob(&order.refund_leg.handle),
                order.refund_leg.before_sequence,
            ))?;
            let changed = database
                .query("SELECT changes()")?
                .first()
                .and_then(|row| row.first())
                .and_then(Option::as_deref)
                .unwrap_or("0")
                .parse::<u64>()
                .map_err(|error| error.to_string())?;
            if changed != 1 {
                return Err("release account compare-and-swap lost a concurrent update".into());
            }
            let after_root = Self::calculate_root(&database)?;
            let database_after = Self::database_size(&database)?;
            let previous = database
                .query("SELECT hex(value) FROM metadata WHERE key='last_receipt'")?
                .first()
                .and_then(|row| row.first())
                .and_then(Option::as_deref)
                .ok_or_else(|| "last receipt metadata is missing".to_string())?
                .to_string();
            let previous_receipt = parse_hex32(&previous, "previous_receipt")?;
            let mut receipt = SettlementReceipt {
                operation_id: order.transition.operation_id,
                nullifier: order.release_nullifier,
                statement,
                before_root,
                after_root,
                previous_receipt,
                committed_at_ns: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
                    .min(u128::from(u64::MAX)) as u64,
                elapsed_ns: started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
                request_bytes,
                response_bytes: 0,
                database_bytes_before: database_before,
                database_bytes_after: database_after,
                signature: Signature::from_bytes(&[0; 64]),
            };
            receipt.response_bytes = Self::receipt_json(&receipt)?.len() as u64;
            receipt.signature = self.receipt_key.sign(&receipt.unsigned()?);
            let raw = Self::receipt_json(&receipt)?;
            let receipt_digest = receipt.digest()?;
            database.execute(&format!(
                "INSERT INTO receipts(operation_id,nullifier,statement,receipt_json,receipt_digest) \
                     VALUES({},{},{},{},{});\
                 UPDATE metadata SET value={} WHERE key='state_root';\
                 UPDATE metadata SET value={} WHERE key='last_receipt'",
                blob(&order.transition.operation_id),
                blob(&order.release_nullifier),
                blob(&statement),
                blob(&raw),
                blob(&receipt_digest),
                blob(&after_root),
                blob(&receipt_digest),
            ))?;
            Ok((receipt, false))
        })();
        match result {
            Ok((receipt, replay)) => {
                database.execute(if replay || !commit {
                    "ROLLBACK"
                } else {
                    "COMMIT"
                })?;
                Ok(receipt)
            }
            Err(error) => {
                let _ = database.execute("ROLLBACK");
                Err(error)
            }
        }
    }

    pub fn amend_credit_facility(
        &self,
        amendment: &CreditFacilityAmendment,
        relation_proof: &CreditFacilityAmendmentProof,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<CreditFacilitySnapshot, String> {
        relation_proof.verify(amendment)?;
        let statement = amendment.statement()?;
        let database = self.database.lock().expect("DeFMI database lock");
        database.execute("BEGIN IMMEDIATE")?;
        let result = (|| {
            if Self::credit_operation(&database, &amendment.operation_id, &statement)? {
                return Self::load_credit_facility(&database, &amendment.facility_id)?.ok_or_else(
                    || "idempotent credit amendment has no facility state".to_string(),
                );
            }
            if amendment.effective_at > now
                || amendment.after_valid_until < now
                || now > i64::MAX as u64
                || amendment.after_valid_until > i64::MAX as u64
            {
                return Err(
                    "credit amendment is not effective, has expired, or cannot be stored".into(),
                );
            }
            let before_root = Self::calculate_root(&database)?;
            self.require_quorum(&statement, &before_root, approval)?;
            let facility = Self::load_credit_facility(&database, &amendment.facility_id)?
                .ok_or_else(|| "credit amendment names an unknown facility".to_string())?;
            if facility.status == CreditFacilityStatus::Closed
                || facility.status == CreditFacilityStatus::Defaulted
            {
                return Err("closed or defaulted facility cannot be amended".into());
            }
            if facility.sequence != amendment.before_sequence
                || facility.cap_commitment != amendment.before_cap_commitment
                || facility.available_commitment != amendment.before_available_commitment
                || facility.held_commitment != amendment.before_held_commitment
                || facility.outstanding_commitment != amendment.before_outstanding_commitment
                || facility.overlimit_commitment != amendment.before_overlimit_commitment
                || facility.collateral_commitment != amendment.before_collateral_commitment
                || facility.risk_policy_digest != amendment.before_risk_policy_digest
                || facility.valid_until != amendment.before_valid_until
            {
                return Err("credit amendment was proved against stale facility state".into());
            }
            if amendment.after_valid_until < facility.valid_from {
                return Err("credit amendment ends before the facility starts".into());
            }
            let guarantor_rows = database.query(&format!(
                "SELECT hex(public_key),hex(risk_policy_digest),active FROM guarantors \
                 WHERE guarantor_id={}",
                blob(&facility.guarantor_id)
            ))?;
            let guarantor = guarantor_rows
                .first()
                .ok_or_else(|| "credit facility guarantor is missing".to_string())?;
            if guarantor[2].as_deref() != Some("1") {
                return Err("inactive guarantor cannot amend a facility".into());
            }
            if parse_hex32(
                guarantor[1].as_deref().unwrap_or_default(),
                "guarantor risk policy",
            )? != amendment.after_risk_policy_digest
            {
                return Err("credit amendment uses an unregistered guarantor risk policy".into());
            }
            let public_key = VerifyingKey::from_bytes(&parse_hex32(
                guarantor[0].as_deref().unwrap_or_default(),
                "guarantor public key",
            )?)
            .map_err(|_| "stored guarantor public key is malformed".to_string())?;
            public_key
                .verify(
                    &amendment.guarantor_message()?,
                    &amendment.guarantor_signature,
                )
                .map_err(|_| "credit amendment lacks the guarantor signature".to_string())?;
            let next_status = if amendment.mode == CreditAmendmentMode::OverLimit {
                CreditFacilityStatus::Frozen
            } else {
                facility.status
            };
            database.execute(&format!(
                "UPDATE credit_facilities SET cap_commitment={},available_commitment={},\
                        overlimit_commitment={},collateral_commitment={},risk_policy_digest={},\
                        valid_until={},status={},sequence=sequence+1 \
                 WHERE facility_id={} AND sequence={}",
                blob(&amendment.after_cap_commitment),
                blob(&amendment.after_available_commitment),
                blob(&amendment.after_overlimit_commitment),
                blob(&amendment.after_collateral_commitment),
                blob(&amendment.after_risk_policy_digest),
                amendment.after_valid_until,
                quoted(next_status.as_str()),
                blob(&amendment.facility_id),
                amendment.before_sequence,
            ))?;
            if database
                .query("SELECT changes()")?
                .first()
                .and_then(|row| row.first())
                .and_then(Option::as_deref)
                != Some("1")
            {
                return Err("credit facility compare-and-swap lost a concurrent amendment".into());
            }
            database.execute(&format!(
                "INSERT INTO credit_operations(operation_id,facility_id,kind,statement) \
                 VALUES({},{},'amend',{})",
                blob(&amendment.operation_id),
                blob(&amendment.facility_id),
                blob(&statement),
            ))?;
            Self::load_credit_facility(&database, &amendment.facility_id)?
                .ok_or_else(|| "credit facility disappeared during amendment".to_string())
        })();
        match result {
            Ok(snapshot) => {
                database.execute("COMMIT")?;
                Ok(snapshot)
            }
            Err(error) => {
                let _ = database.execute("ROLLBACK");
                Err(error)
            }
        }
    }

    pub fn control_credit_facility(
        &self,
        control: &CreditFacilityControl,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<CreditFacilitySnapshot, String> {
        control.unsigned_body()?;
        let statement = control.statement()?;
        let database = self.database.lock().expect("DeFMI database lock");
        database.execute("BEGIN IMMEDIATE")?;
        let result = (|| {
            if Self::credit_operation(&database, &control.operation_id, &statement)? {
                return Self::load_credit_facility(&database, &control.facility_id)?
                    .ok_or_else(|| "idempotent credit control has no facility state".to_string());
            }
            if control.effective_at > now || now > i64::MAX as u64 {
                return Err("credit control is not yet effective or cannot be stored".into());
            }
            let before_root = Self::calculate_root(&database)?;
            self.require_quorum(&statement, &before_root, approval)?;
            let facility = Self::load_credit_facility(&database, &control.facility_id)?
                .ok_or_else(|| "credit control names an unknown facility".to_string())?;
            if facility.sequence != control.before_sequence {
                return Err("credit control was signed against stale facility state".into());
            }
            let guarantor_rows = database.query(&format!(
                "SELECT hex(public_key),active FROM guarantors WHERE guarantor_id={}",
                blob(&facility.guarantor_id)
            ))?;
            let guarantor = guarantor_rows
                .first()
                .ok_or_else(|| "credit facility guarantor is missing".to_string())?;
            if guarantor[1].as_deref() != Some("1") {
                return Err("inactive guarantor cannot control a facility".into());
            }
            let public_key = VerifyingKey::from_bytes(&parse_hex32(
                guarantor[0].as_deref().unwrap_or_default(),
                "guarantor public key",
            )?)
            .map_err(|_| "stored guarantor public key is malformed".to_string())?;
            public_key
                .verify(&control.guarantor_message()?, &control.guarantor_signature)
                .map_err(|_| "credit control lacks the guarantor signature".to_string())?;
            match control.action {
                CreditControlAction::Activate
                    if facility.status != CreditFacilityStatus::Frozen =>
                {
                    return Err("only a frozen facility can be reactivated".into());
                }
                CreditControlAction::Activate if facility.overlimit_commitment != ZERO => {
                    return Err(
                        "over-limit facility must be rehabilitated before activation".into(),
                    );
                }
                CreditControlAction::Freeze if facility.status != CreditFacilityStatus::Active => {
                    return Err("only an active facility can be frozen".into());
                }
                CreditControlAction::Close
                    if facility.held_commitment != ZERO
                        || facility.outstanding_commitment != ZERO
                        || facility.overlimit_commitment != ZERO =>
                {
                    return Err(
                        "facility with holds, debt, or an over-limit balance cannot be closed"
                            .into(),
                    );
                }
                CreditControlAction::Default if facility.status == CreditFacilityStatus::Closed => {
                    return Err("closed facility cannot enter default".into());
                }
                _ => {}
            }
            database.execute(&format!(
                "UPDATE credit_facilities SET status={},sequence=sequence+1 \
                 WHERE facility_id={} AND sequence={}",
                quoted(control.action.status().as_str()),
                blob(&control.facility_id),
                control.before_sequence,
            ))?;
            if database
                .query("SELECT changes()")?
                .first()
                .and_then(|row| row.first())
                .and_then(Option::as_deref)
                != Some("1")
            {
                return Err("credit facility compare-and-swap lost a concurrent control".into());
            }
            database.execute(&format!(
                "INSERT INTO credit_operations(operation_id,facility_id,kind,statement) \
                 VALUES({},{},{},{})",
                blob(&control.operation_id),
                blob(&control.facility_id),
                quoted(control.action.as_str()),
                blob(&statement),
            ))?;
            Self::load_credit_facility(&database, &control.facility_id)?
                .ok_or_else(|| "credit facility disappeared during control".to_string())
        })();
        match result {
            Ok(snapshot) => {
                database.execute("COMMIT")?;
                Ok(snapshot)
            }
            Err(error) => {
                let _ = database.execute("ROLLBACK");
                Err(error)
            }
        }
    }

    pub fn credit_facility(
        &self,
        facility_id: &[u8; 32],
    ) -> Result<Option<CreditFacilitySnapshot>, String> {
        Self::load_credit_facility(
            &self.database.lock().expect("DeFMI database lock"),
            facility_id,
        )
    }

    fn receipt_json(receipt: &SettlementReceipt) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&ReceiptWire::from_receipt(receipt)).map_err(|error| error.to_string())
    }

    fn receipt_from_json(raw: &[u8]) -> Result<SettlementReceipt, String> {
        serde_json::from_slice::<ReceiptWire>(raw)
            .map_err(|error| error.to_string())?
            .into_receipt()
    }

    /// Irrevocably consume both pre-trade reservations and apply the four DvP
    /// account legs in one SQLite transaction.  No Maker or Taker signature is
    /// accepted here: their authority is already in the two mandate digests
    /// covered by the typed zkPI quorum signature.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn preflight_product<R: RngCore + CryptoRng>(
        &self,
        order: &ProductSettlementOrder,
        relation_proofs: &[CreditFacilityRelationProof],
        typed_instruction: &qomm_zkpi::typed::TypedInstruction,
        typed_venue: &qomm_zkpi::Venue,
        asset_link: &crate::asset_link::AssetLinkProof,
        dvp_package: &crate::settlement::DvpPackage,
        approval: &QuorumApproval,
        now: u64,
        rng: &mut R,
    ) -> Result<(), String> {
        self.settle_product_inner(
            order,
            relation_proofs,
            typed_instruction,
            typed_venue,
            asset_link,
            ProductDvpEvidence::Legacy(dvp_package),
            Some(approval),
            None,
            now,
            rng,
            false,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn settle_product<R: RngCore + CryptoRng>(
        &self,
        order: &ProductSettlementOrder,
        relation_proofs: &[CreditFacilityRelationProof],
        typed_instruction: &qomm_zkpi::typed::TypedInstruction,
        typed_venue: &qomm_zkpi::Venue,
        asset_link: &crate::asset_link::AssetLinkProof,
        dvp_package: &crate::settlement::DvpPackage,
        approval: &QuorumApproval,
        now: u64,
        rng: &mut R,
    ) -> Result<SettlementReceipt, String> {
        self.settle_product_inner(
            order,
            relation_proofs,
            typed_instruction,
            typed_venue,
            asset_link,
            ProductDvpEvidence::Legacy(dvp_package),
            Some(approval),
            None,
            now,
            rng,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn preflight_product_threshold<R: RngCore + CryptoRng>(
        &self,
        order: &ProductSettlementOrder,
        relation_proofs: &[CreditFacilityRelationProof],
        typed_instruction: &qomm_zkpi::typed::TypedInstruction,
        typed_venue: &qomm_zkpi::Venue,
        asset_link: &crate::asset_link::AssetLinkProof,
        dvp_package: &crate::settlement::ThresholdDvpPackage,
        approval: &QuorumApproval,
        now: u64,
        rng: &mut R,
    ) -> Result<(), String> {
        self.settle_product_inner(
            order,
            relation_proofs,
            typed_instruction,
            typed_venue,
            asset_link,
            ProductDvpEvidence::Threshold(dvp_package),
            Some(approval),
            None,
            now,
            rng,
            false,
        )?;
        Ok(())
    }

    /// Verify one threshold-DvP member against the common pre-state of an
    /// already quorum-approved batch. This always rolls its SQL work back; the
    /// only committing path is [`Self::settle_product_threshold_batch`].
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn preflight_product_threshold_for_batch<R: RngCore + CryptoRng>(
        &self,
        order: &ProductSettlementOrder,
        relation_proofs: &[CreditFacilityRelationProof],
        typed_instruction: &qomm_zkpi::typed::TypedInstruction,
        typed_venue: &qomm_zkpi::Venue,
        asset_link: &crate::asset_link::AssetLinkProof,
        dvp_package: &crate::settlement::ThresholdDvpPackage,
        batch_root: [u8; 32],
        now: u64,
        rng: &mut R,
    ) -> Result<(), String> {
        self.settle_product_inner(
            order,
            relation_proofs,
            typed_instruction,
            typed_venue,
            asset_link,
            ProductDvpEvidence::Threshold(dvp_package),
            None,
            Some(batch_root),
            now,
            rng,
            false,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn settle_product_threshold<R: RngCore + CryptoRng>(
        &self,
        order: &ProductSettlementOrder,
        relation_proofs: &[CreditFacilityRelationProof],
        typed_instruction: &qomm_zkpi::typed::TypedInstruction,
        typed_venue: &qomm_zkpi::Venue,
        asset_link: &crate::asset_link::AssetLinkProof,
        dvp_package: &crate::settlement::ThresholdDvpPackage,
        approval: &QuorumApproval,
        now: u64,
        rng: &mut R,
    ) -> Result<SettlementReceipt, String> {
        self.settle_product_inner(
            order,
            relation_proofs,
            typed_instruction,
            typed_venue,
            asset_link,
            ProductDvpEvidence::Threshold(dvp_package),
            Some(approval),
            None,
            now,
            rng,
            true,
        )
    }

    /// Commit an admission-ordered set of already preflighted threshold-DvP
    /// settlements in one SQLite transaction. Every mutable reservation,
    /// facility, account and nullifier must be disjoint across members. This
    /// fail-closed rule prevents one Maker maximum or one legal-entity line
    /// from being spent twice while preserving a single common proof pre-state.
    pub(crate) fn settle_product_threshold_batch(
        &self,
        batch: &ProductSettlementBatch,
        orders: &[ProductSettlementOrder],
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<Vec<SettlementReceipt>, String> {
        batch.validate_orders(orders)?;
        let batch_statement = batch.statement()?;
        let mut operation_ids = BTreeSet::from([batch.batch_id]);
        let mut payment_nullifiers = BTreeSet::new();
        let mut rfq_nullifiers = BTreeSet::new();
        let mut holds = BTreeSet::new();
        let mut facilities = BTreeSet::new();
        let mut account_handles = BTreeSet::new();
        for order in orders {
            order.body()?;
            if !operation_ids.insert(order.settlement.operation_id)
                || !payment_nullifiers.insert(order.settlement.nullifier)
                || !rfq_nullifiers.insert(order.rfq_nullifier)
                || order.reservations.iter().any(|reservation| {
                    !operation_ids.insert(reservation.transition.operation_id)
                        || !holds.insert(reservation.transition.hold_id)
                        || !facilities.insert(reservation.transition.facility_id)
                })
                || order
                    .settlement
                    .legs
                    .iter()
                    .any(|leg| !account_handles.insert(leg.handle))
            {
                return Err(
                    "atomic product batch reuses an operation, nullifier, facility, hold, or account"
                        .into(),
                );
            }
        }

        let database = self.database.lock().expect("DeFMI database lock");
        database.execute("BEGIN IMMEDIATE")?;
        let result = (|| {
            let stored_batch = database.query(&format!(
                "SELECT hex(statement) FROM product_settlement_batches WHERE batch_id={}",
                blob(&batch.batch_id)
            ))?;
            if let Some(row) = stored_batch.first() {
                if parse_hex32(
                    row[0].as_deref().unwrap_or_default(),
                    "stored product batch statement",
                )? != batch_statement
                {
                    return Err("product batch identifier was reused for different members".into());
                }
                let mut receipts = Vec::with_capacity(orders.len());
                for order in orders {
                    let rows = database.query(&format!(
                        "SELECT hex(statement),hex(receipt_json) FROM receipts WHERE operation_id={}",
                        blob(&order.settlement.operation_id)
                    ))?;
                    let row = rows.first().ok_or_else(|| {
                        "committed product batch is missing an item receipt".to_string()
                    })?;
                    if parse_hex32(
                        row[0].as_deref().unwrap_or_default(),
                        "stored settlement statement",
                    )? != order.statement()?
                    {
                        return Err("stored batch receipt belongs to another settlement".into());
                    }
                    let raw = hex::decode(row[1].as_deref().unwrap_or_default())
                        .map_err(|error| error.to_string())?;
                    receipts.push(Self::receipt_from_json(&raw)?);
                }
                return Ok((receipts, true));
            }

            for order in orders {
                if !database
                    .query(&format!(
                        "SELECT 1 FROM receipts WHERE operation_id={} OR nullifier={}",
                        blob(&order.settlement.operation_id),
                        blob(&order.settlement.nullifier)
                    ))?
                    .is_empty()
                {
                    return Err(
                        "atomic product batch contains an independently committed member".into(),
                    );
                }
            }

            let batch_before_root = Self::calculate_root(&database)?;
            self.require_quorum(&batch_statement, &batch_before_root, approval)?;
            let mut receipts = Vec::with_capacity(orders.len());
            let mut receipt_digests = Vec::with_capacity(orders.len());

            for order in orders {
                if now > order.settlement.deadline {
                    return Err("payment instruction has expired".into());
                }
                let statement = order.statement()?;
                if !database
                    .query(&format!(
                        "SELECT 1 FROM nullifiers WHERE nullifier={}",
                        blob(&order.settlement.nullifier)
                    ))?
                    .is_empty()
                    || !database
                        .query(&format!(
                            "SELECT 1 FROM rfq_nullifiers WHERE rfq_nullifier={}",
                            blob(&order.rfq_nullifier)
                        ))?
                        .is_empty()
                {
                    return Err("atomic product batch contains an already settled RFQ".into());
                }

                for reservation in &order.reservations {
                    let rows = database.query(&format!(
                        "SELECT status FROM reservation_escrows WHERE hold_id={}",
                        blob(&reservation.transition.hold_id)
                    ))?;
                    if rows
                        .first()
                        .and_then(|row| row.first())
                        .and_then(Option::as_deref)
                        != Some("active")
                    {
                        return Err("atomic product batch names an inactive asset escrow".into());
                    }
                }
                for leg in &order.settlement.legs {
                    let rows = database.query(&format!(
                        "SELECT hex(asset_id),hex(commitment),sequence FROM accounts WHERE handle={}",
                        blob(&leg.handle)
                    ))?;
                    let row = rows
                        .first()
                        .ok_or_else(|| "settlement names an unknown account".to_string())?;
                    if parse_hex32(row[0].as_deref().unwrap_or_default(), "account asset")?
                        != leg.asset_id
                        || parse_hex32(row[1].as_deref().unwrap_or_default(), "account commitment")?
                            != leg.before_commitment
                        || row[2]
                            .as_deref()
                            .unwrap_or("0")
                            .parse::<u64>()
                            .map_err(|error| error.to_string())?
                            != leg.before_sequence
                    {
                        return Err(
                            "atomic product batch member was proved against stale account state"
                                .into(),
                        );
                    }
                }

                let item_before_root = Self::calculate_root(&database)?;
                let database_before = Self::database_size(&database)?;
                let started = Instant::now();
                for reservation in &order.reservations {
                    Self::apply_credit_transition(
                        &database,
                        &reservation.transition,
                        &reservation.transition.statement()?,
                        "product_consume",
                        now,
                    )?;
                    database.execute(&format!(
                        "UPDATE reservation_escrows SET status='consumed',settlement_digest={} \
                         WHERE hold_id={} AND status='active'",
                        blob(&statement),
                        blob(&reservation.transition.hold_id),
                    ))?;
                }
                database.execute(&format!(
                    "INSERT INTO nullifiers(nullifier,deadline,statement) VALUES({},{},{})",
                    blob(&order.settlement.nullifier),
                    order.settlement.deadline,
                    blob(&statement)
                ))?;
                database.execute(&format!(
                    "INSERT INTO rfq_nullifiers(rfq_nullifier,settlement_statement) VALUES({},{})",
                    blob(&order.rfq_nullifier),
                    blob(&statement)
                ))?;
                for leg in &order.settlement.legs {
                    database.execute(&format!(
                        "UPDATE accounts SET commitment={},sequence=sequence+1 WHERE handle={} \
                         AND commitment={} AND sequence={}",
                        blob(&leg.after_commitment),
                        blob(&leg.handle),
                        blob(&leg.before_commitment),
                        leg.before_sequence,
                    ))?;
                    let rows = database.query(&format!(
                        "SELECT hex(commitment),sequence FROM accounts WHERE handle={}",
                        blob(&leg.handle)
                    ))?;
                    let row = rows
                        .first()
                        .ok_or_else(|| "updated settlement account disappeared".to_string())?;
                    if parse_hex32(
                        row[0].as_deref().unwrap_or_default(),
                        "updated account commitment",
                    )? != leg.after_commitment
                        || row[1]
                            .as_deref()
                            .unwrap_or("0")
                            .parse::<u64>()
                            .map_err(|error| error.to_string())?
                            != leg.before_sequence + 1
                    {
                        return Err("atomic settlement account compare-and-swap failed".into());
                    }
                }

                Self::register_operation(&database, &order.settlement.operation_id, &statement)?;
                let item_after_root = Self::calculate_root(&database)?;
                let database_after = Self::database_size(&database)?;
                let previous_rows =
                    database.query("SELECT hex(value) FROM metadata WHERE key='last_receipt'")?;
                let previous_receipt = parse_hex32(
                    previous_rows
                        .first()
                        .and_then(|row| row.first())
                        .and_then(Option::as_deref)
                        .ok_or_else(|| "last receipt metadata is missing".to_string())?,
                    "previous_receipt",
                )?;
                let request_bytes = canonical(&order.body()?)?.len() as u64;
                let mut receipt = SettlementReceipt {
                    operation_id: order.settlement.operation_id,
                    nullifier: order.settlement.nullifier,
                    statement,
                    before_root: item_before_root,
                    after_root: item_after_root,
                    previous_receipt,
                    committed_at_ns: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos()
                        .min(u128::from(u64::MAX)) as u64,
                    elapsed_ns: started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
                    request_bytes,
                    response_bytes: 0,
                    database_bytes_before: database_before,
                    database_bytes_after: database_after,
                    signature: Signature::from_bytes(&[0; 64]),
                };
                receipt.response_bytes = Self::receipt_json(&receipt)?.len() as u64;
                receipt.signature = self.receipt_key.sign(&receipt.unsigned()?);
                let raw = Self::receipt_json(&receipt)?;
                let receipt_digest = receipt.digest()?;
                database.execute(&format!(
                    "INSERT INTO receipts(operation_id,nullifier,statement,receipt_json,receipt_digest) \
                     VALUES({},{},{},{},{})",
                    blob(&order.settlement.operation_id),
                    blob(&order.settlement.nullifier),
                    blob(&statement),
                    blob(&raw),
                    blob(&receipt_digest)
                ))?;
                database.execute(&format!(
                    "UPDATE metadata SET value={} WHERE key='state_root';\
                     UPDATE metadata SET value={} WHERE key='last_receipt'",
                    blob(&item_after_root),
                    blob(&receipt_digest)
                ))?;
                receipt_digests.push(receipt_digest);
                receipts.push(receipt);
            }

            Self::register_operation(&database, &batch.batch_id, &batch_statement)?;
            let batch_after_root = Self::calculate_root(&database)?;
            database.execute(&format!(
                "INSERT INTO product_settlement_batches(\
                    batch_id,statement,before_root,after_root,item_count,first_sequence,last_sequence,\
                    first_receipt_digest,last_receipt_digest) VALUES({},{},{},{},{},{},{},{},{})",
                blob(&batch.batch_id),
                blob(&batch_statement),
                blob(&batch_before_root),
                blob(&batch_after_root),
                orders.len(),
                batch.members.first().expect("non-empty batch").admission_sequence,
                batch.members.last().expect("non-empty batch").admission_sequence,
                blob(receipt_digests.first().expect("non-empty batch")),
                blob(receipt_digests.last().expect("non-empty batch")),
            ))?;
            Ok((receipts, false))
        })();
        match result {
            Ok((receipts, replay)) => {
                database.execute(if replay { "ROLLBACK" } else { "COMMIT" })?;
                Ok(receipts)
            }
            Err(error) => {
                let _ = database.execute("ROLLBACK");
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn settle_product_inner<R: RngCore + CryptoRng>(
        &self,
        order: &ProductSettlementOrder,
        relation_proofs: &[CreditFacilityRelationProof],
        typed_instruction: &qomm_zkpi::typed::TypedInstruction,
        typed_venue: &qomm_zkpi::Venue,
        asset_link: &crate::asset_link::AssetLinkProof,
        dvp_package: ProductDvpEvidence<'_>,
        approval: Option<&QuorumApproval>,
        batch_preflight_root: Option<[u8; 32]>,
        now: u64,
        rng: &mut R,
        commit: bool,
    ) -> Result<SettlementReceipt, String> {
        let request = order.body()?;
        if relation_proofs.is_empty() && matches!(&dvp_package, ProductDvpEvidence::Threshold(_)) {
            for reservation in &order.reservations {
                verify_threshold_dvp_relation(
                    &reservation.transition,
                    reservation.role,
                    order.dvp_proof_digest,
                )?;
            }
        } else {
            if relation_proofs.len() != order.reservations.len() {
                return Err("each reservation consumption needs one relation proof".into());
            }
            for (reservation, proof) in order.reservations.iter().zip(relation_proofs) {
                proof.verify(&reservation.transition)?;
            }
        }
        typed_venue
            .verify_typed(typed_instruction, now)
            .map_err(|error| format!("typed zkPI failed: {error}"))?;
        if !crate::asset_link::verify(
            &typed_venue.key,
            &order.traded_asset_id,
            &typed_instruction.payment.asset_commitment,
            asset_link,
        ) || asset_link.digest(
            &order.traded_asset_id,
            &typed_instruction.payment.asset_commitment,
        ) != order.asset_link_proof_digest
        {
            return Err("zkPI asset is not the traded DeFMI asset".into());
        }
        let typed_bytes = qomm_zkpi::typed_wire::encode(typed_instruction);
        let typed_digest: [u8; 32] = Sha256::digest(&typed_bytes).into();
        if typed_digest != order.typed_instruction_digest
            || typed_instruction.payment.nullifier() != order.settlement.nullifier
            || typed_instruction.payment.deadline != order.settlement.deadline
        {
            return Err("typed zkPI bytes, nullifier, or deadline do not match settlement".into());
        }
        if qomm_zkpi::wire::encode(dvp_package.instruction())
            != qomm_zkpi::wire::encode(&typed_instruction.payment)
        {
            return Err("DvP package is not for the typed zkPI instruction".into());
        }
        if dvp_package.digest() != order.dvp_proof_digest {
            return Err("DvP proof bytes differ from the committee-approved digest".into());
        }
        if order.quantity_commitment != dvp_package.securities_amount().compress().to_bytes()
            || order.cash_commitment != dvp_package.cash_amount().compress().to_bytes()
        {
            return Err("product amount commitments differ from the proved DvP package".into());
        }
        // The durable facility exposes the asset identifier on each rail.  A
        // separately blinded asset tag would need another tag-to-registry
        // proof; accepting one without that proof would detach the DvP from
        // the asset IDs in the canonical ledger.
        if dvp_package.has_hidden_asset_tag() {
            return Err(
                "durable DeFMI requires untagged DvP legs for its explicit asset rails".into(),
            );
        }
        let context = &typed_instruction.context;
        if !matches!(
            context.operation,
            qomm_zkpi::typed::OperationKind::Consume | qomm_zkpi::typed::OperationKind::Settle
        ) || context.scope != qomm_zkpi::typed::AuthorizationScope::Joint
            || context.venue_id != order.venue_id
            || context.defmi_id != order.defmi_id
            || context.rfq_nullifier != order.rfq_nullifier
            || context.maker_policy_digest != order.maker_policy_digest
            || context.maker_mandate_digest != order.maker_mandate_digest
            || context.taker_mandate_digest != order.taker_mandate_digest
            || context.quote_proof_digest != order.quote_proof_digest
            || context.market_statement_digest != order.settlement.market_statement_digest
        {
            return Err("typed zkPI execution context differs from the product settlement".into());
        }
        let maker = order
            .reservations
            .iter()
            .find(|reservation| reservation.role == ReservationRole::Maker)
            .ok_or_else(|| "Maker reservation is missing".to_string())?;
        let taker = order
            .reservations
            .iter()
            .find(|reservation| reservation.role == ReservationRole::Taker)
            .ok_or_else(|| "Taker reservation is missing".to_string())?;
        if context.maker_reservation_id != maker.transition.hold_id
            || context.maker_reservation_sequence != maker.transition.before_sequence
            || context.maker_reserve_receipt_digest != maker.reserve_receipt_digest
            || context.taker_reservation_id != taker.transition.hold_id
            || context.taker_reservation_sequence != taker.transition.before_sequence
            || context.taker_reserve_receipt_digest != taker.reserve_receipt_digest
        {
            return Err("typed zkPI names another Maker or Taker reservation state".into());
        }

        let package_handle = |raw: &[u8], name: &str| -> Result<[u8; 32], String> {
            raw.try_into()
                .map_err(|_| format!("{name} must be a 32-byte anonymous account handle"))
        };
        let securities_from_handle =
            package_handle(dvp_package.securities_from(), "securities escrow")?;
        let securities_to_handle = package_handle(dvp_package.securities_to(), "securities payee")?;
        let cash_from_handle = package_handle(dvp_package.cash_from(), "cash escrow")?;
        let cash_to_handle = package_handle(dvp_package.cash_to(), "cash payee")?;
        let party_sides = crate::settlement::Sides::of(dvp_package.instruction());
        if dvp_package.securities_to() != party_sides.securities_to
            || dvp_package.cash_to() != party_sides.cash_to
            || securities_from_handle == securities_to_handle
            || cash_from_handle == cash_to_handle
        {
            return Err(
                "DvP destinations or escrow source handles differ from the signed zkPI".into(),
            );
        }
        let payment_asset_id = order
            .settlement
            .legs
            .iter()
            .find(|leg| leg.asset_id != order.traded_asset_id)
            .map(|leg| leg.asset_id)
            .ok_or_else(|| "product settlement has no payment rail".to_string())?;

        let (maker_consumed, taker_consumed) = match context.direction {
            qomm_zkpi::typed::TradeDirection::TakerBuys => {
                (dvp_package.securities_amount(), dvp_package.cash_amount())
            }
            qomm_zkpi::typed::TradeDirection::TakerSells => {
                (dvp_package.cash_amount(), dvp_package.securities_amount())
            }
        };
        if maker.transition.consumed_commitment != maker_consumed.compress().to_bytes()
            || taker.transition.consumed_commitment != taker_consumed.compress().to_bytes()
        {
            return Err("guarantee reservations are not consumed by the proved DvP amounts".into());
        }

        let request_bytes = canonical(&request)?.len() as u64;
        let statement = order.statement()?;
        let started = Instant::now();
        let database = self.database.lock().expect("DeFMI database lock");
        database.execute("BEGIN IMMEDIATE")?;
        let result = (|| {
            let existing = database.query(&format!(
                "SELECT hex(statement),hex(receipt_json) FROM receipts WHERE operation_id={}",
                blob(&order.settlement.operation_id)
            ))?;
            if let Some(row) = existing.first() {
                let stored = parse_hex32(row[0].as_deref().unwrap_or_default(), "statement")?;
                if stored != statement {
                    return Err("operation identifier was reused for another settlement".into());
                }
                let raw = hex::decode(row[1].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?;
                return Ok((Self::receipt_from_json(&raw)?, true));
            }
            let before_root = Self::calculate_root(&database)?;
            if let Some(batch_root) = batch_preflight_root {
                if context.before_state_root != batch_root || before_root != batch_root {
                    return Err(
                        "typed zkPI batch was authorized against a stale DeFMI state root".into(),
                    );
                }
            } else {
                if context.before_state_root != before_root {
                    return Err("typed zkPI was authorized against a stale DeFMI state root".into());
                }
                self.require_quorum(
                    &statement,
                    &before_root,
                    approval.ok_or_else(|| {
                        "individual product settlement lacks quorum approval".to_string()
                    })?,
                )?;
            }
            if now > order.settlement.deadline {
                return Err("payment instruction has expired".into());
            }
            if !database
                .query(&format!(
                    "SELECT 1 FROM nullifiers WHERE nullifier={}",
                    blob(&order.settlement.nullifier)
                ))?
                .is_empty()
            {
                return Err("payment nullifier was already settled".into());
            }
            if !database
                .query(&format!(
                    "SELECT 1 FROM rfq_nullifiers WHERE rfq_nullifier={}",
                    blob(&order.rfq_nullifier)
                ))?
                .is_empty()
            {
                return Err("RFQ nullifier was already settled".into());
            }

            let direction = context.direction as u8;
            let mut reserved_escrows = Vec::<(ReservationRole, ReservationEscrow)>::new();
            for reservation in &order.reservations {
                let rows = database.query(&format!(
                    "SELECT role,hex(entity_commitment),hex(asset_id),direction,\
                            hex(authorization_digest),hex(mandate_digest),\
                            hex(typed_reserve_digest),hex(reserve_nullifier),\
                            hex(asset_link_proof_digest),hex(limit_price_commitment),\
                            hex(rfq_nullifier),policy_version,\
                            hex(admission_ticket_id),admission_slot,\
                            hex(admission_receipt_digest),admission_epoch,admission_sequence,\
                            hex(receipt_digest) \
                     FROM reservation_bindings WHERE hold_id={}",
                    blob(&reservation.transition.hold_id)
                ))?;
                let binding = rows
                    .first()
                    .ok_or_else(|| "settlement reservation was not product-bound".to_string())?;
                let expected_entity = if reservation.role == ReservationRole::Maker {
                    order.maker_entity_commitment
                } else {
                    order.taker_entity_commitment
                };
                let expected_authorization = if reservation.role == ReservationRole::Maker {
                    order.maker_policy_digest
                } else {
                    order.taker_authorization_digest
                };
                let expected_mandate = if reservation.role == ReservationRole::Maker {
                    order.maker_mandate_digest
                } else {
                    order.taker_mandate_digest
                };
                let asset_id = parse_hex32(
                    binding[2].as_deref().unwrap_or_default(),
                    "reservation asset_id",
                )?;
                if binding[0].as_deref() != Some(reservation.role.as_str())
                    || parse_hex32(
                        binding[1].as_deref().unwrap_or_default(),
                        "reservation entity",
                    )? != expected_entity
                    || binding[3]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u8>()
                        .map_err(|error| error.to_string())?
                        != direction
                    || parse_hex32(
                        binding[4].as_deref().unwrap_or_default(),
                        "reservation authorization",
                    )? != expected_authorization
                    || parse_hex32(
                        binding[5].as_deref().unwrap_or_default(),
                        "reservation mandate",
                    )? != expected_mandate
                    || parse_hex32(
                        binding[17].as_deref().unwrap_or_default(),
                        "reservation receipt",
                    )? != reservation.reserve_receipt_digest
                {
                    return Err(
                        "reservation binding differs from the signed product context".into(),
                    );
                }
                if reservation.role == ReservationRole::Maker {
                    if binding[11]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?
                        == 0
                        || (direction == 1 && asset_id != order.traded_asset_id)
                        || (direction == 2 && asset_id != payment_asset_id)
                    {
                        return Err("Maker reserve does not back the selected policy asset".into());
                    }
                } else {
                    if parse_hex32(
                        binding[9].as_deref().unwrap_or_default(),
                        "reservation limit price",
                    )? == ZERO
                        || parse_hex32(
                            binding[10].as_deref().unwrap_or_default(),
                            "reservation RFQ nullifier",
                        )? != order.rfq_nullifier
                    {
                        return Err("Taker reserve names another RFQ nullifier".into());
                    }
                    if parse_hex32(
                        binding[14].as_deref().unwrap_or_default(),
                        "ordered admission receipt",
                    )? != order.admission_receipt_digest
                    {
                        return Err("Taker reserve names another admission receipt".into());
                    }
                    if binding[15]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?
                        != order.admission_epoch
                        || binding[16]
                            .as_deref()
                            .unwrap_or("0")
                            .parse::<u64>()
                            .map_err(|error| error.to_string())?
                            != order.admission_sequence
                    {
                        return Err(
                            "Taker reserve names another certified admission position".into()
                        );
                    }
                    if (direction == 2 && asset_id != order.traded_asset_id)
                        || (direction == 1 && asset_id != payment_asset_id)
                    {
                        return Err("Taker reserve is on the wrong RFQ asset rail".into());
                    }
                }
                let escrow_rows = database.query(&format!(
                    "SELECT hex(source_handle),hex(escrow_handle),hex(asset_id),\
                            hex(amount_commitment),hex(source_before_commitment),\
                            hex(source_after_commitment),source_before_sequence,\
                            hex(proof_digest),status \
                     FROM reservation_escrows WHERE hold_id={}",
                    blob(&reservation.transition.hold_id)
                ))?;
                let escrow_row = escrow_rows
                    .first()
                    .ok_or_else(|| "settlement reservation has no asset escrow".to_string())?;
                if escrow_row[8].as_deref() != Some("active") {
                    return Err("settlement reservation asset escrow is not active".into());
                }
                let escrow = ReservationEscrow {
                    source_handle: parse_hex32(
                        escrow_row[0].as_deref().unwrap_or_default(),
                        "escrow source handle",
                    )?,
                    escrow_handle: parse_hex32(
                        escrow_row[1].as_deref().unwrap_or_default(),
                        "escrow handle",
                    )?,
                    asset_id: parse_hex32(
                        escrow_row[2].as_deref().unwrap_or_default(),
                        "escrow asset",
                    )?,
                    amount_commitment: parse_hex32(
                        escrow_row[3].as_deref().unwrap_or_default(),
                        "escrow amount",
                    )?,
                    source_before_commitment: parse_hex32(
                        escrow_row[4].as_deref().unwrap_or_default(),
                        "escrow source before",
                    )?,
                    source_after_commitment: parse_hex32(
                        escrow_row[5].as_deref().unwrap_or_default(),
                        "escrow source after",
                    )?,
                    source_before_sequence: escrow_row[6]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                    proof_digest: parse_hex32(
                        escrow_row[7].as_deref().unwrap_or_default(),
                        "escrow proof digest",
                    )?,
                };
                if escrow.asset_id != asset_id
                    || escrow.amount_commitment != reservation.transition.amount_commitment
                {
                    return Err("asset escrow differs from the consumed guarantee hold".into());
                }
                reserved_escrows.push((reservation.role, escrow));
            }

            if database
                .query(&format!(
                    "SELECT kind FROM assets WHERE asset_id={}",
                    blob(&payment_asset_id)
                ))?
                .first()
                .and_then(|row| row.first())
                .and_then(Option::as_deref)
                != Some(AssetKind::Cash.as_str())
            {
                return Err("the payment side of product DvP is not a registered cash rail".into());
            }

            let database_before = Self::database_size(&database)?;
            for leg in &order.settlement.legs {
                let rows = database.query(&format!(
                    "SELECT hex(asset_id),hex(commitment),sequence FROM accounts WHERE handle={}",
                    blob(&leg.handle)
                ))?;
                let Some(row) = rows.first() else {
                    return Err("settlement names an unknown account".into());
                };
                if parse_hex32(row[0].as_deref().unwrap_or_default(), "asset_id")? != leg.asset_id {
                    return Err("settlement leg is on the wrong asset rail".into());
                }
                if parse_hex32(row[1].as_deref().unwrap_or_default(), "commitment")?
                    != leg.before_commitment
                    || row[2]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?
                        != leg.before_sequence
                {
                    return Err("settlement was proved against stale account state".into());
                }
                if database
                    .query(&format!(
                        "SELECT active FROM assets WHERE asset_id={}",
                        blob(&leg.asset_id)
                    ))?
                    .first()
                    .and_then(|row| row.first())
                    .and_then(Option::as_deref)
                    != Some("1")
                {
                    return Err("settlement uses an inactive asset".into());
                }
            }

            let point = |raw: &[u8; 32], name: &str| -> Result<RistrettoPoint, String> {
                CompressedRistretto(*raw)
                    .decompress()
                    .ok_or_else(|| format!("{name} is not a canonical Ristretto commitment"))
            };
            let leg_for = |handle: &[u8; 32]| -> Result<&StateLeg, String> {
                order
                    .settlement
                    .legs
                    .iter()
                    .find(|leg| &leg.handle == handle)
                    .ok_or_else(|| {
                        "reservation source or DvP destination is absent from settlement"
                            .to_string()
                    })
            };
            let securities_escrow = reserved_escrows
                .iter()
                .find(|(_, escrow)| escrow.asset_id == order.traded_asset_id)
                .ok_or_else(|| "product has no traded-asset reservation escrow".to_string())?;
            let cash_escrow = reserved_escrows
                .iter()
                .find(|(_, escrow)| escrow.asset_id == payment_asset_id)
                .ok_or_else(|| "product has no payment-asset reservation escrow".to_string())?;
            if securities_escrow.1.escrow_handle != securities_from_handle
                || cash_escrow.1.escrow_handle != cash_from_handle
            {
                return Err("DvP spends an account other than the pre-trade asset escrow".into());
            }
            let securities_source = leg_for(&securities_escrow.1.source_handle)?;
            let securities_to = leg_for(&securities_to_handle)?;
            let cash_source = leg_for(&cash_escrow.1.source_handle)?;
            let cash_to = leg_for(&cash_to_handle)?;
            if securities_source.asset_id != order.traded_asset_id
                || securities_to.asset_id != order.traded_asset_id
                || cash_source.asset_id != payment_asset_id
                || cash_to.asset_id != payment_asset_id
            {
                return Err("settlement refund or destination is on the wrong asset rail".into());
            }
            let securities_source_before = point(
                &securities_source.before_commitment,
                "securities reserve owner before commitment",
            )?;
            let securities_to_before = point(
                &securities_to.before_commitment,
                "securities payee before commitment",
            )?;
            let cash_source_before = point(
                &cash_source.before_commitment,
                "cash reserve owner before commitment",
            )?;
            let cash_to_before = point(&cash_to.before_commitment, "cash payee before commitment")?;
            let securities_transfer = dvp_package.securities_amount();
            let cash_transfer = dvp_package.cash_amount();
            let securities_remainder = dvp_package.securities_remainder();
            let cash_remainder = dvp_package.cash_remainder();
            if securities_source.after_commitment
                != (securities_source_before + securities_remainder)
                    .compress()
                    .to_bytes()
                || securities_to.after_commitment
                    != (securities_to_before + securities_transfer)
                        .compress()
                        .to_bytes()
                || cash_source.after_commitment
                    != (cash_source_before + cash_remainder).compress().to_bytes()
                || cash_to.after_commitment
                    != (cash_to_before + cash_transfer).compress().to_bytes()
            {
                return Err(
                    "settlement does not pay from escrow and return its unused maximum".into(),
                );
            }
            let securities_amount = point(
                &securities_escrow.1.amount_commitment,
                "securities escrow amount",
            )?;
            let cash_amount = point(&cash_escrow.1.amount_commitment, "cash escrow amount")?;
            match &dvp_package {
                ProductDvpEvidence::Legacy(package) => {
                    let mut securities_ledger = crate::ledger::Ledger::new(
                        typed_venue.key.clone(),
                        typed_venue.amount_ranges.bits,
                    );
                    securities_ledger.open(package.securities_from.as_slice(), securities_amount);
                    securities_ledger.open(package.securities_to.as_slice(), securities_to_before);
                    let mut cash_ledger = crate::ledger::Ledger::new(
                        typed_venue.key.clone(),
                        typed_venue.amount_ranges.bits,
                    );
                    cash_ledger.open(package.cash_from.as_slice(), cash_amount);
                    cash_ledger.open(package.cash_to.as_slice(), cash_to_before);
                    let reserved_sides = crate::settlement::Sides {
                        securities_from: package.securities_from.clone(),
                        securities_to: party_sides.securities_to.clone(),
                        cash_from: package.cash_from.clone(),
                        cash_to: party_sides.cash_to.clone(),
                    };
                    crate::settlement::verify_package_legs_for_sides(
                        &typed_venue.key,
                        &securities_ledger,
                        &cash_ledger,
                        package,
                        &reserved_sides,
                        rng,
                    )
                    .map_err(|error| format!("reserved DvP proof failed: {error}"))?;
                }
                ProductDvpEvidence::Threshold(package) => {
                    if package.securities_remainder_range.bits != package.cash_remainder_range.bits
                    {
                        return Err(
                            "threshold DvP remainder proofs use different range widths".into()
                        );
                    }
                    crate::settlement::verify_threshold_package(
                        &typed_venue.key,
                        package,
                        &securities_amount,
                        &cash_amount,
                        package.securities_remainder_range.bits,
                    )
                    .map_err(|error| format!("reserved threshold DvP proof failed: {error}"))?;
                }
            }
            let reservation_for =
                |role: ReservationRole| -> Result<&ReservationConsumption, String> {
                    order
                        .reservations
                        .iter()
                        .find(|reservation| reservation.role == role)
                        .ok_or_else(|| "reservation role is missing".to_string())
                };
            if reservation_for(securities_escrow.0)?
                .transition
                .refund_commitment
                != securities_remainder.compress().to_bytes()
                || reservation_for(cash_escrow.0)?.transition.refund_commitment
                    != cash_remainder.compress().to_bytes()
            {
                return Err("guarantee refund differs from unused asset escrow".into());
            }

            for reservation in &order.reservations {
                Self::apply_credit_transition(
                    &database,
                    &reservation.transition,
                    &reservation.transition.statement()?,
                    "product_consume",
                    now,
                )?;
                database.execute(&format!(
                    "UPDATE reservation_escrows SET status='consumed',settlement_digest={} \
                     WHERE hold_id={} AND status='active'",
                    blob(&statement),
                    blob(&reservation.transition.hold_id),
                ))?;
            }
            database.execute(&format!(
                "INSERT INTO nullifiers(nullifier,deadline,statement) VALUES({},{},{})",
                blob(&order.settlement.nullifier),
                order.settlement.deadline,
                blob(&statement)
            ))?;
            database.execute(&format!(
                "INSERT INTO rfq_nullifiers(rfq_nullifier,settlement_statement) VALUES({},{})",
                blob(&order.rfq_nullifier),
                blob(&statement)
            ))?;
            for leg in &order.settlement.legs {
                database.execute(&format!(
                    "UPDATE accounts SET commitment={},sequence=sequence+1 WHERE handle={}",
                    blob(&leg.after_commitment),
                    blob(&leg.handle)
                ))?;
            }
            Self::register_operation(&database, &order.settlement.operation_id, &statement)?;
            let after_root = Self::calculate_root(&database)?;
            let database_after = Self::database_size(&database)?;
            let previous_rows =
                database.query("SELECT hex(value) FROM metadata WHERE key='last_receipt'")?;
            let previous = previous_rows
                .first()
                .and_then(|row| row.first())
                .and_then(Option::as_deref)
                .ok_or_else(|| "last receipt metadata is missing".to_string())?;
            let previous_receipt = parse_hex32(previous, "previous_receipt")?;
            let mut receipt = SettlementReceipt {
                operation_id: order.settlement.operation_id,
                nullifier: order.settlement.nullifier,
                statement,
                before_root,
                after_root,
                previous_receipt,
                committed_at_ns: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
                    .min(u128::from(u64::MAX)) as u64,
                elapsed_ns: started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
                request_bytes,
                response_bytes: 0,
                database_bytes_before: database_before,
                database_bytes_after: database_after,
                signature: Signature::from_bytes(&[0; 64]),
            };
            receipt.response_bytes = Self::receipt_json(&receipt)?.len() as u64;
            receipt.signature = self.receipt_key.sign(&receipt.unsigned()?);
            let raw = Self::receipt_json(&receipt)?;
            let receipt_digest = receipt.digest()?;
            database.execute(&format!(
                "INSERT INTO receipts(operation_id,nullifier,statement,receipt_json,receipt_digest) VALUES({},{},{},{},{})",
                blob(&order.settlement.operation_id),
                blob(&order.settlement.nullifier),
                blob(&statement),
                blob(&raw),
                blob(&receipt_digest)
            ))?;
            database.execute(&format!(
                "UPDATE metadata SET value={} WHERE key='state_root';\
                 UPDATE metadata SET value={} WHERE key='last_receipt'",
                blob(&after_root),
                blob(&receipt_digest)
            ))?;
            Ok((receipt, false))
        })();
        match result {
            Ok((receipt, replay)) => {
                database.execute(if replay || !commit {
                    "ROLLBACK"
                } else {
                    "COMMIT"
                })?;
                Ok(receipt)
            }
            Err(error) => {
                let _ = database.execute("ROLLBACK");
                Err(error)
            }
        }
    }

    pub fn settle(
        &self,
        order: &SettlementOrder,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<SettlementReceipt, String> {
        let request = order.body()?;
        let request_bytes = canonical(&request)?.len() as u64;
        let statement = order.statement()?;
        let started = Instant::now();
        let database = self.database.lock().expect("DeFMI database lock");
        database.execute("BEGIN IMMEDIATE")?;
        let result = (|| {
            let existing = database.query(&format!(
                "SELECT hex(statement),hex(receipt_json) FROM receipts WHERE operation_id={}",
                blob(&order.operation_id)
            ))?;
            if let Some(row) = existing.first() {
                let stored = parse_hex32(row[0].as_deref().unwrap_or_default(), "statement")?;
                if stored != statement {
                    return Err("operation identifier was reused for another settlement".into());
                }
                let raw = hex::decode(row[1].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?;
                return Ok((Self::receipt_from_json(&raw)?, true));
            }
            let before_root = Self::calculate_root(&database)?;
            self.require_quorum(&statement, &before_root, approval)?;
            if now > order.deadline {
                return Err("payment instruction has expired".into());
            }
            if !database
                .query(&format!(
                    "SELECT 1 FROM nullifiers WHERE nullifier={}",
                    blob(&order.nullifier)
                ))?
                .is_empty()
            {
                return Err("payment nullifier was already settled".into());
            }
            let database_before = Self::database_size(&database)?;
            for leg in &order.legs {
                let rows = database.query(&format!(
                    "SELECT hex(asset_id),hex(commitment),sequence FROM accounts WHERE handle={}",
                    blob(&leg.handle)
                ))?;
                let Some(row) = rows.first() else {
                    return Err("settlement names an unknown account".into());
                };
                if parse_hex32(row[0].as_deref().unwrap_or_default(), "asset_id")? != leg.asset_id {
                    return Err("settlement leg is on the wrong asset rail".into());
                }
                if parse_hex32(row[1].as_deref().unwrap_or_default(), "commitment")?
                    != leg.before_commitment
                    || row[2]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?
                        != leg.before_sequence
                {
                    return Err("settlement was proved against stale account state".into());
                }
                if database
                    .query(&format!(
                        "SELECT active FROM assets WHERE asset_id={}",
                        blob(&leg.asset_id)
                    ))?
                    .first()
                    .and_then(|row| row.first())
                    .and_then(Option::as_deref)
                    != Some("1")
                {
                    return Err("settlement uses an inactive asset".into());
                }
            }
            database.execute(&format!(
                "INSERT INTO nullifiers(nullifier,deadline,statement) VALUES({},{},{})",
                blob(&order.nullifier),
                order.deadline,
                blob(&statement)
            ))?;
            for leg in &order.legs {
                database.execute(&format!(
                    "UPDATE accounts SET commitment={},sequence=sequence+1 WHERE handle={}",
                    blob(&leg.after_commitment),
                    blob(&leg.handle)
                ))?;
            }
            Self::register_operation(&database, &order.operation_id, &statement)?;
            let after_root = Self::calculate_root(&database)?;
            let database_after = Self::database_size(&database)?;
            let previous_rows =
                database.query("SELECT hex(value) FROM metadata WHERE key='last_receipt'")?;
            let previous = previous_rows
                .first()
                .and_then(|row| row.first())
                .and_then(Option::as_deref)
                .ok_or_else(|| "last receipt metadata is missing".to_string())?;
            let previous_receipt = parse_hex32(previous, "previous_receipt")?;
            let mut receipt = SettlementReceipt {
                operation_id: order.operation_id,
                nullifier: order.nullifier,
                statement,
                before_root,
                after_root,
                previous_receipt,
                committed_at_ns: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
                    .min(u128::from(u64::MAX)) as u64,
                elapsed_ns: started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
                request_bytes,
                response_bytes: 0,
                database_bytes_before: database_before,
                database_bytes_after: database_after,
                signature: Signature::from_bytes(&[0; 64]),
            };
            receipt.response_bytes = Self::receipt_json(&receipt)?.len() as u64;
            receipt.signature = self.receipt_key.sign(&receipt.unsigned()?);
            let raw = Self::receipt_json(&receipt)?;
            let receipt_digest = receipt.digest()?;
            database.execute(&format!(
                "INSERT INTO receipts(operation_id,nullifier,statement,receipt_json,receipt_digest) VALUES({},{},{},{},{})",
                blob(&order.operation_id), blob(&order.nullifier), blob(&statement), blob(&raw), blob(&receipt_digest)
            ))?;
            database.execute(&format!(
                "UPDATE metadata SET value={} WHERE key='state_root';\
                 UPDATE metadata SET value={} WHERE key='last_receipt'",
                blob(&after_root),
                blob(&receipt_digest)
            ))?;
            Ok((receipt, false))
        })();
        match result {
            Ok((receipt, replay)) => {
                database.execute(if replay { "ROLLBACK" } else { "COMMIT" })?;
                Ok(receipt)
            }
            Err(error) => {
                let _ = database.execute("ROLLBACK");
                Err(error)
            }
        }
    }

    pub fn account(&self, handle: &[u8; 32]) -> Result<Option<AccountState>, String> {
        let database = self.database.lock().expect("DeFMI database lock");
        let rows = database.query(&format!(
            "SELECT hex(asset_id),hex(commitment),sequence FROM accounts WHERE handle={}",
            blob(handle)
        ))?;
        rows.first()
            .map(|row| {
                Ok((
                    parse_hex32(row[0].as_deref().unwrap_or_default(), "asset_id")?,
                    parse_hex32(row[1].as_deref().unwrap_or_default(), "commitment")?,
                    row[2]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                ))
            })
            .transpose()
    }

    pub fn asset_count(&self) -> Result<u64, String> {
        let rows = self
            .database
            .lock()
            .expect("DeFMI database lock")
            .query("SELECT count(*) FROM assets")?;
        rows.first()
            .and_then(|row| row.first())
            .and_then(Option::as_deref)
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|error| error.to_string())
    }

    pub(crate) fn asset_kind(&self, asset_id: &[u8; 32]) -> Result<AssetKind, String> {
        let rows = self
            .database
            .lock()
            .expect("DeFMI database lock")
            .query(&format!(
                "SELECT kind,active FROM assets WHERE asset_id={}",
                blob(asset_id)
            ))?;
        let row = rows
            .first()
            .ok_or_else(|| "reservation uses an unknown asset".to_string())?;
        if row.get(1).and_then(Option::as_deref) != Some("1") {
            return Err("reservation uses an inactive asset".into());
        }
        match row.first().and_then(Option::as_deref) {
            Some("cash") => Ok(AssetKind::Cash),
            Some("security") => Ok(AssetKind::Security),
            Some("fund") => Ok(AssetKind::Fund),
            Some("commodity") => Ok(AssetKind::Commodity),
            Some("carbon") => Ok(AssetKind::Carbon),
            Some("other") => Ok(AssetKind::Other),
            _ => Err("stored asset kind is invalid".into()),
        }
    }

    pub fn state_root(&self) -> Result<[u8; 32], String> {
        Self::calculate_root(&self.database.lock().expect("DeFMI database lock"))
    }

    pub fn verify_receipt_chain(&self) -> Result<bool, String> {
        let database = self.database.lock().expect("DeFMI database lock");
        let mut previous = ZERO;
        for row in database
            .query("SELECT hex(receipt_json),hex(receipt_digest) FROM receipts ORDER BY rowid")?
        {
            let raw = hex::decode(row[0].as_deref().unwrap_or_default())
                .map_err(|error| error.to_string())?;
            let receipt = Self::receipt_from_json(&raw)?;
            let recorded = parse_hex32(row[1].as_deref().unwrap_or_default(), "receipt_digest")?;
            if receipt.previous_receipt != previous
                || !receipt.verify(&self.receipt_public_key)
                || receipt.digest()? != recorded
            {
                return Ok(false);
            }
            previous = recorded;
        }
        let stored_rows =
            database.query("SELECT hex(value) FROM metadata WHERE key='last_receipt'")?;
        let stored = stored_rows
            .first()
            .and_then(|row| row.first())
            .and_then(Option::as_deref)
            .ok_or_else(|| "last receipt metadata is missing".to_string())?;
        Ok(previous == parse_hex32(stored, "last_receipt")?)
    }

    pub fn backup(&self, target: impl AsRef<Path>) -> Result<PathBuf, String> {
        let target = target.as_ref();
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let database = self.database.lock().expect("DeFMI database lock");
        database.execute("PRAGMA wal_checkpoint(FULL)")?;
        database.execute(&format!(
            "VACUUM main INTO {}",
            quoted(&target.to_string_lossy())
        ))?;
        Ok(target.to_path_buf())
    }

    pub fn checkpoint(&self) -> Result<(), String> {
        self.database
            .lock()
            .expect("DeFMI database lock")
            .execute("PRAGMA wal_checkpoint(TRUNCATE)")
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod schema_tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn v14_guarantor_table_migrates_to_all_supported_kinds() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy-v14.sqlite3");
        let legacy_signer = SigningKey::generate(&mut OsRng);
        let legacy = Database::open(&path).unwrap();
        legacy
            .execute(
                "CREATE TABLE guarantors(\
                    guarantor_id BLOB PRIMARY KEY CHECK(length(guarantor_id)=32),\
                    kind TEXT NOT NULL CHECK(kind IN ('ccp','bank','self')),\
                    name TEXT NOT NULL,public_key BLOB NOT NULL UNIQUE CHECK(length(public_key)=32),\
                    risk_policy_digest BLOB NOT NULL CHECK(length(risk_policy_digest)=32),\
                    active INTEGER NOT NULL DEFAULT 1,statement BLOB NOT NULL UNIQUE);\
                 PRAGMA user_version=14;",
            )
            .unwrap();
        legacy
            .execute(&format!(
                "INSERT INTO guarantors(\
                    guarantor_id,kind,name,public_key,risk_policy_digest,active,statement)\
                 VALUES({},'bank','Legacy bank',{},{},1,{})",
                blob(&[1; 32]),
                blob(&legacy_signer.verifying_key().to_bytes()),
                blob(&[2; 32]),
                blob(&[3; 32]),
            ))
            .unwrap();
        drop(legacy);

        let node = SigningKey::generate(&mut OsRng);
        let authorizer = QuorumAuthorizer::new(
            BTreeMap::from([("node-1".into(), node.verifying_key())]),
            1,
            1,
            "defmi:test:migration",
        )
        .unwrap();
        let facility =
            DefmiFacility::open(&path, authorizer, SigningKey::generate(&mut OsRng)).unwrap();
        let database = facility.database.lock().expect("DeFMI database lock");

        assert_eq!(
            database.query("PRAGMA user_version").unwrap()[0][0].as_deref(),
            Some("15")
        );
        assert_eq!(
            database
                .query("SELECT kind,name FROM guarantors WHERE guarantor_id=X'0101010101010101010101010101010101010101010101010101010101010101'")
                .unwrap()[0],
            vec![Some("bank".into()), Some("Legacy bank".into())]
        );
        let credit_provider = SigningKey::generate(&mut OsRng);
        database
            .execute(&format!(
                "INSERT INTO guarantors(\
                    guarantor_id,kind,name,public_key,risk_policy_digest,active,statement)\
                 VALUES({},'credit_provider','Specialist credit provider',{},{},1,{})",
                blob(&[4; 32]),
                blob(&credit_provider.verifying_key().to_bytes()),
                blob(&[5; 32]),
                blob(&[6; 32]),
            ))
            .unwrap();
        let central_bank = SigningKey::generate(&mut OsRng);
        database
            .execute(&format!(
                "INSERT INTO guarantors(\
                    guarantor_id,kind,name,public_key,risk_policy_digest,active,statement)\
                 VALUES({},'central_bank','Central bank',{},{},1,{})",
                blob(&[7; 32]),
                blob(&central_bank.verifying_key().to_bytes()),
                blob(&[8; 32]),
                blob(&[9; 32]),
            ))
            .unwrap();
        assert_eq!(
            database.query("SELECT count(*) FROM guarantors").unwrap()[0][0].as_deref(),
            Some("3")
        );
        assert!(database
            .query("SELECT sql FROM sqlite_master WHERE type='table' AND name='guarantors'")
            .unwrap()[0][0]
            .as_deref()
            .is_some_and(|schema| schema.contains("credit_provider")));
        assert_eq!(
            database.query("PRAGMA foreign_keys").unwrap()[0][0].as_deref(),
            Some("1")
        );
    }
}
