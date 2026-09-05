//! Canonical QOMM/DeFMI consensus state.
//!
//! The structures here deliberately contain no database handles. A candidate
//! block is evaluated against a clone and is persisted only by `BlockAccept`,
//! so rejected forks cannot leak writes into the authoritative ledger.

use std::collections::{BTreeMap, BTreeSet};

use aethel_core::AethelBook;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use deccp_core::{ClearingBook, ClearingSnapshot, DeCcpError};
use ed25519_dalek::VerifyingKey;
use qomm_defmi::application_reservation::{ApplicationReservationBinding, ApplicationReserveScope};
use qomm_defmi::central_bank_liquidity::BojLiquidityBook;
use qomm_defmi::cross_domain::{
    Committee as CrossDomainCommittee, CrossDomainBook, Domain as CrossDomain,
};
use qomm_defmi::facility::{QuorumAuthorizer, ZERO};
use qomm_defmi::note_chain::{
    standing_note_pool_delegation_digest, standing_note_pool_id, CsdIssuerDefinition, NoteClaim,
    NoteClaimKind, NoteOutput,
};
use qomm_defmi::participant::ParticipantRegistry;
use qomm_proofs::opening_envelope::{EncryptedOpeningShare, OpeningEnvelope};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{execution, id::Id, transaction::TransactionEnvelope};

const STATE_DOMAIN: &[u8] = b"QOMM:DEFMI:STATE:v3";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AssetRecord {
    pub code: String,
    pub kind: String,
    pub decimals: u8,
    pub terms_digest: [u8; 32],
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CsdIssuerRecord {
    pub code: String,
    pub jurisdiction: String,
    pub operator_entity_commitment: [u8; 32],
    pub public_key: [u8; 32],
    pub permitted_asset_ids: Vec<[u8; 32]>,
    pub policy_digest: [u8; 32],
    pub valid_from: u64,
    pub valid_until: u64,
    pub status: String,
    pub sequence: u64,
}

impl CsdIssuerRecord {
    pub(crate) fn definition(&self, issuer_id: [u8; 32]) -> CsdIssuerDefinition {
        CsdIssuerDefinition {
            issuer_id,
            code: self.code.clone(),
            jurisdiction: self.jurisdiction.clone(),
            operator_entity_commitment: self.operator_entity_commitment,
            public_key: self.public_key,
            permitted_asset_ids: self.permitted_asset_ids.clone(),
            policy_digest: self.policy_digest,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AccountRecord {
    pub asset_id: [u8; 32],
    pub commitment: [u8; 32],
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NoteRecord {
    pub asset_id: [u8; 32],
    pub one_time: [u8; 32],
    pub value_commitment: [u8; 32],
    pub ephemeral: [u8; 32],
    pub masked_value: [u8; 32],
    pub masked_blinding: [u8; 32],
    pub lock_id: [u8; 32],
}

impl NoteRecord {
    pub(crate) fn output(&self, note_id: [u8; 32]) -> NoteOutput {
        NoteOutput {
            note_id,
            asset_id: self.asset_id,
            one_time: self.one_time,
            value_commitment: self.value_commitment,
            ephemeral: self.ephemeral,
            masked_value: self.masked_value,
            masked_blinding: self.masked_blinding,
            lock_id: self.lock_id,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NoteReservationRecord {
    pub escrow_note_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub amount_commitment: [u8; 32],
    pub proof_digest: [u8; 32],
    pub delegation_digest: [u8; 32],
    pub status: String,
    pub settlement_digest: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ApplicationReservationRecord {
    pub binding: ApplicationReservationBinding,
    pub escrow_note_id: [u8; 32],
    pub proof_digest: [u8; 32],
    pub receipt_digest: [u8; 32],
    pub status: String,
    pub settlement_digest: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_commitment: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_receipt: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_opening: Option<qomm_defmi::application_settlement::ApplicationOpening>,
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

impl ApplicationReservationRecord {
    pub(crate) fn remaining(&self) -> [u8; 32] {
        self.remaining_commitment
            .unwrap_or(self.binding.amount_commitment)
    }
    pub(crate) fn head_receipt(&self) -> [u8; 32] {
        self.last_receipt.unwrap_or(self.receipt_digest)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StandingNotePoolRecord {
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub entity_commitment: [u8; 32],
    pub policy_digest: [u8; 32],
    pub mandate_digest: [u8; 32],
    pub asset_id: [u8; 32],
    pub direction: u8,
    pub maximum_amount_commitment: [u8; 32],
    pub current_pool_note_id: [u8; 32],
    pub delegation_digest: [u8; 32],
    pub committee_epoch: u64,
    pub valid_until: u64,
    pub sequence: u64,
    pub status: String,
    pub statement: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EncryptedOpeningShareRecord {
    pub party: u16,
    pub ephemeral: [u8; 32],
    pub masked_value: [u8; 32],
    pub masked_blinding: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OpeningEnvelopeRecord {
    pub context: [u8; 32],
    pub threshold: u16,
    pub recipient_view: [u8; 32],
    pub shares: Vec<EncryptedOpeningShareRecord>,
}

impl OpeningEnvelopeRecord {
    pub(crate) fn from_domain(envelope: &OpeningEnvelope) -> Result<Self, String> {
        Ok(Self {
            context: envelope.context,
            threshold: envelope
                .threshold
                .try_into()
                .map_err(|_| "opening threshold exceeds u16".to_string())?,
            recipient_view: envelope.recipient_view.compress().to_bytes(),
            shares: envelope
                .shares
                .iter()
                .map(|share| {
                    Ok(EncryptedOpeningShareRecord {
                        party: share
                            .party
                            .try_into()
                            .map_err(|_| "opening party exceeds u16".to_string())?,
                        ephemeral: share.ephemeral.compress().to_bytes(),
                        masked_value: share.masked_value.to_bytes(),
                        masked_blinding: share.masked_blinding.to_bytes(),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?,
        })
    }

    pub(crate) fn domain(&self) -> Result<OpeningEnvelope, String> {
        let point = |encoded: [u8; 32], name: &str| {
            CompressedRistretto(encoded)
                .decompress()
                .ok_or_else(|| format!("{name} is not a canonical Ristretto point"))
        };
        let scalar = |encoded: [u8; 32], name: &str| {
            Option::<Scalar>::from(Scalar::from_canonical_bytes(encoded))
                .ok_or_else(|| format!("{name} is not a canonical scalar"))
        };
        OpeningEnvelope::new(
            self.context,
            self.threshold.into(),
            point(self.recipient_view, "opening recipient view")?,
            self.shares
                .iter()
                .map(|share| {
                    Ok(EncryptedOpeningShare {
                        party: share.party.into(),
                        ephemeral: point(share.ephemeral, "opening ephemeral key")?,
                        masked_value: scalar(share.masked_value, "opening masked value")?,
                        masked_blinding: scalar(share.masked_blinding, "opening masked blinding")?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NoteClaimRecord {
    pub asset_id: [u8; 32],
    pub value_commitment: [u8; 32],
    pub recipient_commitment: [u8; 32],
    pub source_hold_id: [u8; 32],
    pub kind: String,
    pub opening_envelope: OpeningEnvelopeRecord,
    pub status: String,
    pub settlement_digest: [u8; 32],
    pub materialization: [u8; 32],
}

impl NoteClaimRecord {
    pub(crate) fn claim(&self, claim_id: [u8; 32]) -> Result<NoteClaim, String> {
        Ok(NoteClaim {
            claim_id,
            asset_id: self.asset_id,
            value_commitment: self.value_commitment,
            recipient_commitment: self.recipient_commitment,
            source_hold_id: self.source_hold_id,
            kind: match self.kind.as_str() {
                "delivery" => NoteClaimKind::Delivery,
                "refund" => NoteClaimKind::Refund,
                _ => return Err("note claim kind is invalid".into()),
            },
            opening_envelope: self.opening_envelope.domain()?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NoteSerialRecord {
    pub deadline: u64,
    pub asset_id: [u8; 32],
    pub ring_root: [u8; 32],
    pub statement: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuarantorRecord {
    pub kind: String,
    pub name: String,
    pub public_key: [u8; 32],
    pub risk_policy_digest: [u8; 32],
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreditFacilityRecord {
    pub guarantor_id: [u8; 32],
    pub beneficiary_commitment: [u8; 32],
    pub rail_asset_id: [u8; 32],
    pub cap_commitment: [u8; 32],
    pub available_commitment: [u8; 32],
    pub held_commitment: [u8; 32],
    pub outstanding_commitment: [u8; 32],
    pub overlimit_commitment: [u8; 32],
    pub collateral_commitment: [u8; 32],
    pub risk_policy_digest: [u8; 32],
    pub valid_from: u64,
    pub valid_until: u64,
    pub status: String,
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreditHoldRecord {
    pub facility_id: [u8; 32],
    pub query_commitment: [u8; 32],
    pub amount_commitment: [u8; 32],
    pub expires_at: u64,
    pub status: String,
    pub settlement_digest: [u8; 32],
    pub created_sequence: u64,
    pub updated_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReservationBindingRecord {
    pub role: String,
    pub entity_commitment: [u8; 32],
    pub asset_id: [u8; 32],
    pub direction: u8,
    pub authorization_digest: [u8; 32],
    pub mandate_digest: [u8; 32],
    pub typed_reserve_digest: [u8; 32],
    pub reserve_nullifier: [u8; 32],
    pub asset_link_proof_digest: [u8; 32],
    pub limit_price_commitment: [u8; 32],
    pub rfq_nullifier: [u8; 32],
    pub policy_version: u64,
    pub admission_ticket_id: [u8; 32],
    pub admission_slot: u64,
    pub admission_receipt_digest: [u8; 32],
    pub admission_epoch: u64,
    pub admission_sequence: u64,
    pub admission_batch_id: [u8; 32],
    pub receipt_digest: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReservationEscrowRecord {
    pub source_handle: [u8; 32],
    pub escrow_handle: [u8; 32],
    pub asset_id: [u8; 32],
    pub amount_commitment: [u8; 32],
    pub source_before_commitment: [u8; 32],
    pub source_after_commitment: [u8; 32],
    pub source_before_sequence: u64,
    pub proof_digest: [u8; 32],
    pub status: String,
    pub settlement_digest: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NullifierRecord {
    pub deadline: u64,
    pub statement: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionCommitteeRecord {
    pub venue_id: [u8; 32],
    pub epoch: u64,
    pub node_keys: Vec<[u8; 32]>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub statement: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionBatchRecord {
    pub venue_id: [u8; 32],
    pub epoch: u64,
    pub slot: u64,
    pub batch_digest: [u8; 32],
    pub order_digest: [u8; 32],
    pub population: u64,
    pub consumed: u64,
    pub expires_at: u64,
    pub statement: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionEntryRecord {
    pub batch_id: [u8; 32],
    pub sequence: u64,
    pub admission_digest: [u8; 32],
    pub consumed_by: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SettlementVerifierRecord {
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub epoch: u64,
    pub quote_registry_digest: [u8; 32],
    pub quote_eligibility_bits: u16,
    pub quote_span_bits: u16,
    pub amount_bits: u16,
    pub price_bits: u16,
    pub max_horizon: u64,
    pub frost_public_package: Vec<u8>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub statement: [u8; 32],
}

/// The DeCCP clearing book this VM hosts for Aethel guarantees.
///
/// `ClearingBook` deliberately has no `Deserialize`: DeCCP refuses to rebuild
/// a book from storage it cannot trust. Here the store is the VM's own
/// consensus state, whose root commits to these bytes and whose decoder
/// re-checks the canonical encoding, so the book is rebuilt through
/// `ClearingBook::restore_authenticated`, which still re-runs every DeCCP
/// structural invariant on load.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "ClearingSnapshot", into = "ClearingSnapshot")]
pub(crate) struct ClearingState {
    pub book: ClearingBook,
}

impl TryFrom<ClearingSnapshot> for ClearingState {
    type Error = DeCcpError;

    fn try_from(snapshot: ClearingSnapshot) -> Result<Self, DeCcpError> {
        ClearingBook::restore_authenticated(snapshot).map(|book| Self { book })
    }
}

impl From<ClearingState> for ClearingSnapshot {
    fn from(clearing: ClearingState) -> Self {
        clearing.book.snapshot()
    }
}

/// No default during deserialization: legacy snapshots must not silently gain
/// the new nullifier rules and make previously spent inputs spendable again.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum NoteProofVersion {
    #[default]
    #[serde(rename = "triptych_v2")]
    TriptychV2,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct State {
    pub(crate) note_proof_version: NoteProofVersion,
    pub transition_count: u64,
    pub applied_transactions: BTreeSet<[u8; 32]>,
    #[serde(default, skip_serializing_if = "AethelBook::is_empty")]
    pub(crate) aethel: AethelBook,
    /// The DeCCP clearing book that holds guarantee capacity for Aethel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) deccp: Option<ClearingState>,
    #[serde(default)]
    pub(crate) assets: BTreeMap<String, AssetRecord>,
    #[serde(default)]
    pub(crate) csd_issuers: BTreeMap<String, CsdIssuerRecord>,
    #[serde(default)]
    pub(crate) accounts: BTreeMap<String, AccountRecord>,
    #[serde(default)]
    pub(crate) notes: BTreeMap<String, NoteRecord>,
    #[serde(default)]
    pub(crate) note_reservations: BTreeMap<String, NoteReservationRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) application_reserve_scopes: BTreeMap<String, ApplicationReserveScope>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) application_reservations: BTreeMap<String, ApplicationReservationRecord>,
    #[serde(default)]
    pub(crate) standing_note_pools: BTreeMap<String, StandingNotePoolRecord>,
    #[serde(default)]
    pub(crate) note_claims: BTreeMap<String, NoteClaimRecord>,
    #[serde(default)]
    pub(crate) guarantors: BTreeMap<String, GuarantorRecord>,
    #[serde(default)]
    pub(crate) credit_facilities: BTreeMap<String, CreditFacilityRecord>,
    #[serde(default)]
    pub(crate) credit_holds: BTreeMap<String, CreditHoldRecord>,
    #[serde(default)]
    pub(crate) reservation_bindings: BTreeMap<String, ReservationBindingRecord>,
    #[serde(default)]
    pub(crate) reservation_escrows: BTreeMap<String, ReservationEscrowRecord>,
    #[serde(default)]
    pub(crate) nullifiers: BTreeMap<String, NullifierRecord>,
    #[serde(default)]
    pub(crate) note_serials: BTreeMap<String, NoteSerialRecord>,
    #[serde(default)]
    pub(crate) note_issuances: BTreeMap<String, [u8; 32]>,
    #[serde(default)]
    pub(crate) rfq_nullifiers: BTreeMap<String, [u8; 32]>,
    #[serde(default)]
    pub(crate) admission_committees: BTreeMap<String, AdmissionCommitteeRecord>,
    #[serde(default)]
    pub(crate) admission_batches: BTreeMap<String, AdmissionBatchRecord>,
    #[serde(default)]
    pub(crate) admission_entries: BTreeMap<String, AdmissionEntryRecord>,
    #[serde(default)]
    pub(crate) settlement_verifiers: BTreeMap<String, SettlementVerifierRecord>,
    #[serde(default)]
    pub(crate) operations: BTreeMap<String, [u8; 32]>,
    #[serde(default, skip_serializing_if = "CrossDomainBook::is_empty")]
    pub(crate) cross_domain: CrossDomainBook,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cross_domain_local_domain: Option<CrossDomain>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) cross_domain_committees: BTreeMap<String, CrossDomainCommittee>,
    #[serde(default, skip_serializing_if = "BojLiquidityBook::is_empty")]
    pub(crate) boj_liquidity: BojLiquidityBook,
    #[serde(default, skip_serializing_if = "ParticipantRegistry::is_empty")]
    pub(crate) participant_registry: ParticipantRegistry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionReceipt {
    pub transaction_id: Id,
    pub statement: [u8; 32],
    pub before_root: [u8; 32],
    pub after_root: [u8; 32],
}

impl State {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let state = Self::deserialize(&mut deserializer).map_err(|error| error.to_string())?;
        deserializer.end().map_err(|error| error.to_string())?;
        state.validate()?;
        if state.encode()? != bytes {
            return Err("consensus state is not in canonical encoding".into());
        }
        Ok(state)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.aethel.validate().map_err(|error| error.to_string())?;
        if let Some(clearing) = &self.deccp {
            clearing
                .book
                .validate()
                .map_err(|error| format!("invalid DeCCP clearing state: {error}"))?;
        }
        if self.transition_count != self.applied_transactions.len() as u64 {
            return Err("state transition count does not match the transaction index".into());
        }
        self.cross_domain
            .validate()
            .map_err(|error| format!("invalid cross-domain state: {error}"))?;
        self.boj_liquidity
            .validate()
            .map_err(|error| format!("invalid BOJ liquidity state: {error}"))?;
        self.participant_registry
            .validate()
            .map_err(|error| format!("invalid participant registry state: {error}"))?;
        if !self.cross_domain.is_empty() && self.cross_domain_local_domain.is_none() {
            return Err("cross-domain state has no configured local domain".into());
        }
        if let Some(local_domain) = &self.cross_domain_local_domain {
            if self
                .cross_domain
                .legs
                .values()
                .any(|record| &record.prepare.local_domain != local_domain)
            {
                return Err(
                    "cross-domain leg does not belong to the configured local domain".into(),
                );
            }
        }
        for (key, committee) in &self.cross_domain_committees {
            committee
                .validate()
                .map_err(|error| format!("invalid cross-domain committee: {error}"))?;
            if key != &cross_domain_committee_key(&committee.domain.id(), committee.epoch) {
                return Err("cross-domain committee is stored under the wrong key".into());
            }
        }
        for (name, map) in [
            ("asset", self.assets.keys().collect::<Vec<_>>()),
            ("CSD issuer", self.csd_issuers.keys().collect::<Vec<_>>()),
            ("account", self.accounts.keys().collect::<Vec<_>>()),
            ("note", self.notes.keys().collect::<Vec<_>>()),
            (
                "application reserve scope",
                self.application_reserve_scopes.keys().collect::<Vec<_>>(),
            ),
            (
                "application reservation",
                self.application_reservations.keys().collect::<Vec<_>>(),
            ),
            (
                "note reservation",
                self.note_reservations.keys().collect::<Vec<_>>(),
            ),
            (
                "standing note pool",
                self.standing_note_pools.keys().collect::<Vec<_>>(),
            ),
            ("note claim", self.note_claims.keys().collect::<Vec<_>>()),
            ("guarantor", self.guarantors.keys().collect::<Vec<_>>()),
            (
                "credit facility",
                self.credit_facilities.keys().collect::<Vec<_>>(),
            ),
            ("credit hold", self.credit_holds.keys().collect::<Vec<_>>()),
            (
                "reservation binding",
                self.reservation_bindings.keys().collect::<Vec<_>>(),
            ),
            (
                "reservation escrow",
                self.reservation_escrows.keys().collect::<Vec<_>>(),
            ),
            ("nullifier", self.nullifiers.keys().collect::<Vec<_>>()),
            ("note serial", self.note_serials.keys().collect::<Vec<_>>()),
            (
                "note issuance",
                self.note_issuances.keys().collect::<Vec<_>>(),
            ),
            (
                "RFQ nullifier",
                self.rfq_nullifiers.keys().collect::<Vec<_>>(),
            ),
            ("operation", self.operations.keys().collect::<Vec<_>>()),
        ] {
            if map.iter().any(|key| !is_hex_id(key)) {
                return Err(format!("state contains a malformed {name} identifier"));
            }
        }
        for (issuer_id, record) in &self.csd_issuers {
            let issuer_id: [u8; 32] = hex::decode(issuer_id)
                .expect("validated CSD issuer identifier")
                .try_into()
                .expect("32-byte CSD issuer identifier");
            record.definition(issuer_id).body()?;
            if !matches!(record.status.as_str(), "active" | "suspended" | "revoked")
                || record
                    .permitted_asset_ids
                    .iter()
                    .any(|asset_id| !self.assets.contains_key(&id_key(asset_id)))
            {
                return Err("state contains a malformed CSD issuer".into());
            }
        }
        for (note_id, record) in &self.notes {
            let note_id: [u8; 32] = hex::decode(note_id)
                .expect("validated note identifier")
                .try_into()
                .expect("32-byte note identifier");
            record.output(note_id).validate()?;
            if !self
                .assets
                .get(&id_key(&record.asset_id))
                .is_some_and(|asset| asset.active)
            {
                return Err("state note belongs to an inactive or unknown asset".into());
            }
        }
        for (key, scope) in &self.application_reserve_scopes {
            if key != &id_key(&scope.key()?) {
                return Err("application scope is stored under another key".into());
            }
        }
        let mut application_requests = BTreeSet::new();
        for (key, record) in &self.application_reservations {
            record.binding.validate()?;
            let binding = &record.binding;
            let hold = self
                .credit_holds
                .get(key)
                .ok_or_else(|| "application reserve has no credit hold".to_string())?;
            let note = self
                .notes
                .get(&id_key(&record.escrow_note_id))
                .ok_or_else(|| "application reserve has no covenant note".to_string())?;
            let facility = self
                .credit_facilities
                .get(&id_key(&binding.facility_id))
                .ok_or_else(|| "application reserve has no facility".to_string())?;
            if key != &id_key(&binding.hold_id)
                || self
                    .application_reserve_scopes
                    .get(&id_key(&binding.scope.key()?))
                    != Some(&binding.scope)
                || self.reservation_bindings.contains_key(key)
                || self.note_reservations.contains_key(key)
                || hold.facility_id != binding.facility_id
                || hold.query_commitment != binding.request_commitment
                || hold.amount_commitment != record.remaining()
                || hold.expires_at != binding.valid_until
                || hold.status != record.status
                || hold.settlement_digest != record.settlement_digest
                || note.asset_id != binding.asset_id
                || note.value_commitment != binding.amount_commitment
                || note.lock_id != binding.hold_id
                || facility.beneficiary_commitment != binding.entity_commitment
                || facility.rail_asset_id != binding.asset_id
                || record.proof_digest == ZERO
                || record.receipt_digest == ZERO
                || !matches!(record.status.as_str(), "active" | "consumed" | "released")
                || (record.status == "active" && record.settlement_digest != ZERO)
                || (record.status == "released" && record.settlement_digest != ZERO)
                || (record.status == "consumed"
                    && record.settlement_digest != record.head_receipt())
                || !application_requests.insert((binding.scope.key()?, binding.request_commitment))
            {
                return Err("state contains a malformed application reservation".into());
            }
            qomm_defmi::application_settlement::point(record.remaining())?;
            let custody =
                self.note_serials
                    .get(&id_key(&qomm_defmi::note_chain::escrow_claim_serial(
                        record.escrow_note_id,
                        binding.hold_id,
                    )));
            if record.sequence == 0 {
                if record.remaining_commitment.is_some()
                    || record.last_receipt.is_some()
                    || record.remaining_opening.is_some()
                    || record.status != "active"
                    || custody.is_some()
                {
                    return Err("initial application reserve contains a later head".into());
                }
            } else {
                if record.remaining_commitment.is_none()
                    || record.last_receipt.is_none_or(|value| value == ZERO)
                    || custody.is_none_or(|serial| {
                        serial.asset_id != binding.asset_id
                            || serial.ring_root != record.escrow_note_id
                    })
                    || !self
                        .operations
                        .values()
                        .any(|statement| *statement == record.head_receipt())
                    || (record.status == "active") != record.remaining_opening.is_some()
                {
                    return Err("advanced application reserve lost its custody or head".into());
                }
                if let Some(opening) = &record.remaining_opening {
                    opening.domain()?;
                }
            }
        }
        for (hold_id, record) in &self.note_reservations {
            let expected_lock_id: [u8; 32] = hex::decode(hold_id)
                .expect("validated hold identifier")
                .try_into()
                .expect("32-byte hold identifier");
            let note = self
                .notes
                .get(&id_key(&record.escrow_note_id))
                .ok_or_else(|| "note reservation has no escrow note".to_string())?;
            if !self.credit_holds.contains_key(hold_id)
                || !self.reservation_bindings.contains_key(hold_id)
                || note.asset_id != record.asset_id
                || note.value_commitment != record.amount_commitment
                || note.lock_id != expected_lock_id
                || record.proof_digest == ZERO
                || record.delegation_digest == ZERO
                || !matches!(record.status.as_str(), "active" | "consumed" | "released")
            {
                return Err("state contains a malformed note reservation".into());
            }
        }
        for (pool_id, record) in &self.standing_note_pools {
            let pool_id: [u8; 32] = hex::decode(pool_id)
                .expect("validated standing note pool identifier")
                .try_into()
                .expect("32-byte standing note pool identifier");
            let note = self
                .notes
                .get(&id_key(&record.current_pool_note_id))
                .ok_or_else(|| "standing note pool has no current covenant note".to_string())?;
            if pool_id
                != standing_note_pool_id(
                    record.entity_commitment,
                    record.policy_digest,
                    record.mandate_digest,
                    record.asset_id,
                    record.direction,
                )?
                || record.delegation_digest
                    != standing_note_pool_delegation_digest(
                        pool_id,
                        record.venue_id,
                        record.defmi_id,
                        record.committee_epoch,
                        record.valid_until,
                    )?
                || [
                    record.venue_id,
                    record.defmi_id,
                    record.maximum_amount_commitment,
                    record.statement,
                ]
                .contains(&ZERO)
                || !matches!(record.direction, 1 | 2)
                || record.committee_epoch == 0
                || record.valid_until == 0
                || record.status != "active"
                || note.asset_id != record.asset_id
                || note.lock_id != pool_id
            {
                return Err("state contains a malformed standing note pool".into());
            }
        }
        for (claim_id, record) in &self.note_claims {
            let claim_id: [u8; 32] = hex::decode(claim_id)
                .expect("validated note claim identifier")
                .try_into()
                .expect("32-byte note claim identifier");
            record.claim(claim_id)?.validate()?;
            if !self
                .credit_holds
                .contains_key(&id_key(&record.source_hold_id))
                || record.settlement_digest == ZERO
                || !matches!(record.status.as_str(), "active" | "materialized")
                || (record.status == "active" && record.materialization != ZERO)
                || (record.status == "materialized" && record.materialization == ZERO)
            {
                return Err("state contains a malformed note claim".into());
            }
        }
        if self.note_serials.values().any(|record| {
            record.deadline == 0
                || record.asset_id == ZERO
                || record.ring_root == ZERO
                || record.statement == ZERO
        }) || self
            .note_issuances
            .values()
            .any(|statement| *statement == ZERO)
        {
            return Err("state contains a malformed note serial or issuance".into());
        }
        let mut reserve_nullifiers = BTreeSet::new();
        let mut taker_rfq_nullifiers = BTreeSet::new();
        let mut admission_tickets = BTreeSet::new();
        let mut admission_receipts = BTreeSet::new();
        let mut admission_sequences = BTreeSet::new();
        for (hold_id, binding) in &self.reservation_bindings {
            let hold = self
                .credit_holds
                .get(hold_id)
                .ok_or_else(|| "reservation binding has no credit hold".to_string())?;
            if binding.entity_commitment == ZERO
                || binding.asset_id == ZERO
                || !matches!(binding.direction, 1 | 2)
                || binding.authorization_digest == ZERO
                || binding.mandate_digest == ZERO
                || binding.typed_reserve_digest == ZERO
                || binding.reserve_nullifier == ZERO
                || binding.asset_link_proof_digest == ZERO
                || binding.receipt_digest == ZERO
                || hold.query_commitment != binding.authorization_digest
                || !reserve_nullifiers.insert(binding.reserve_nullifier)
            {
                return Err("state contains a malformed or repeated reservation binding".into());
            }
            match binding.role.as_str() {
                "maker"
                    if binding.policy_version != 0
                        && binding.limit_price_commitment == ZERO
                        && binding.rfq_nullifier == ZERO
                        && binding.admission_ticket_id == ZERO
                        && binding.admission_slot == 0
                        && binding.admission_receipt_digest == ZERO
                        && binding.admission_epoch == 0
                        && binding.admission_sequence == 0
                        && binding.admission_batch_id == ZERO => {}
                "taker"
                    if binding.policy_version == 0
                        && binding.limit_price_commitment != ZERO
                        && CompressedRistretto(binding.limit_price_commitment)
                            .decompress()
                            .is_some()
                        && binding.rfq_nullifier != ZERO
                        && binding.admission_ticket_id != ZERO
                        && binding.admission_receipt_digest != ZERO
                        && binding.admission_epoch != 0
                        && binding.admission_sequence != 0
                        && binding.admission_batch_id != ZERO
                        && taker_rfq_nullifiers.insert(binding.rfq_nullifier)
                        && admission_tickets.insert(binding.admission_ticket_id)
                        && admission_receipts.insert(binding.admission_receipt_digest)
                        && admission_sequences
                            .insert((binding.admission_batch_id, binding.admission_sequence)) => {}
                _ => return Err("reservation role and scope disagree".into()),
            }
        }
        for (hold_id, escrow) in &self.reservation_escrows {
            if !self.reservation_bindings.contains_key(hold_id)
                || escrow.source_handle == ZERO
                || escrow.escrow_handle == ZERO
                || escrow.source_handle == escrow.escrow_handle
                || escrow.asset_id == ZERO
                || escrow.amount_commitment == ZERO
                || escrow.proof_digest == ZERO
                || !matches!(escrow.status.as_str(), "active" | "consumed" | "released")
            {
                return Err("state contains a malformed reservation escrow".into());
            }
        }
        for (key, committee) in &self.admission_committees {
            if *key != admission_committee_key(&committee.venue_id, committee.epoch)
                || committee.venue_id == ZERO
                || committee.epoch == 0
                || committee.valid_from == 0
                || committee.valid_until < committee.valid_from
                || committee.statement == ZERO
                || committee.node_keys.len() != qomm_transport::order::COMMITTEE_NODES
                || committee.node_keys.contains(&ZERO)
                || committee.node_keys.iter().collect::<BTreeSet<_>>().len()
                    != committee.node_keys.len()
                || committee
                    .node_keys
                    .iter()
                    .any(|node| VerifyingKey::from_bytes(node).is_err())
            {
                return Err("state contains a malformed admission committee".into());
            }
        }
        let mut scopes = BTreeSet::new();
        for (batch_id, batch) in &self.admission_batches {
            if !is_hex_id(batch_id)
                || batch.venue_id == ZERO
                || batch.epoch == 0
                || batch.batch_digest == ZERO
                || batch.order_digest == ZERO
                || batch.population == 0
                || batch.population > 4096
                || batch.consumed > batch.population
                || batch.expires_at == 0
                || batch.statement == ZERO
                || !scopes.insert((batch.venue_id, batch.epoch, batch.slot, batch.batch_digest))
            {
                return Err("state contains a malformed or duplicate admission batch".into());
            }
            let batch_id_bytes: [u8; 32] = hex::decode(batch_id)
                .expect("validated batch identifier")
                .try_into()
                .expect("32-byte batch identifier");
            let mut entries = self
                .admission_entries
                .values()
                .filter(|entry| entry.batch_id == batch_id_bytes)
                .collect::<Vec<_>>();
            entries.sort_by_key(|entry| entry.sequence);
            if entries.len() != batch.population as usize {
                return Err("admission batch omits a planned lane".into());
            }
            let first_sequence = entries
                .first()
                .map(|entry| entry.sequence)
                .ok_or_else(|| "admission batch has no planned lanes".to_string())?;
            for (index, entry) in entries.into_iter().enumerate() {
                let sequence = first_sequence + index as u64;
                if entry.batch_id != batch_id_bytes
                    || entry.sequence != sequence
                    || entry.admission_digest == ZERO
                    || (index < batch.consumed as usize && entry.consumed_by == ZERO)
                    || (index >= batch.consumed as usize && entry.consumed_by != ZERO)
                {
                    return Err("admission batch cursor and entries disagree".into());
                }
            }
        }
        if self.admission_entries.iter().any(|(key, entry)| {
            *key != admission_entry_key(&entry.batch_id, entry.sequence)
                || self
                    .admission_batches
                    .get(&id_key(&entry.batch_id))
                    .is_none_or(|_| entry.sequence == 0)
        }) {
            return Err("state contains an orphaned admission entry".into());
        }
        for (key, record) in &self.settlement_verifiers {
            let config = qomm_defmi::settlement_verifier::SettlementVerifierConfig {
                venue_id: record.venue_id,
                defmi_id: record.defmi_id,
                epoch: record.epoch,
                quote_registry_digest: record.quote_registry_digest,
                quote_eligibility_bits: record.quote_eligibility_bits,
                quote_span_bits: record.quote_span_bits,
                amount_bits: record.amount_bits,
                price_bits: record.price_bits,
                max_horizon: record.max_horizon,
                frost_public_package: record.frost_public_package.clone(),
                valid_from: record.valid_from,
                valid_until: record.valid_until,
            };
            if *key != id_key(&config.key()) || config.statement()? != record.statement {
                return Err("state contains a malformed settlement verifier".into());
            }
        }
        Ok(())
    }

    pub fn apply(
        &mut self,
        bytes: &[u8],
        authorizer: &QuorumAuthorizer,
        timestamp: u64,
    ) -> Result<TransitionReceipt, String> {
        let transaction = TransactionEnvelope::decode(bytes)?;
        let transaction_id = transaction.id()?;
        if self.applied_transactions.contains(&transaction_id.0) {
            return Err(format!("transaction {transaction_id} was already applied"));
        }
        let before_root = self.root();
        let mut next = self.clone();
        let statement = execution::execute(&mut next, &transaction, authorizer, timestamp)?;
        next.applied_transactions.insert(transaction_id.0);
        next.transition_count = next
            .transition_count
            .checked_add(1)
            .ok_or_else(|| "state transition counter overflow".to_string())?;
        next.validate()?;
        let after_root = next.root();
        *self = next;
        Ok(TransitionReceipt {
            transaction_id,
            statement,
            before_root,
            after_root,
        })
    }

    pub fn root(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(STATE_DOMAIN);
        // Keep the established empty-genesis root. Nonempty note state commits
        // the new scheme; missing/legacy scheme markers fail deserialization.
        if !self.notes.is_empty() || !self.note_serials.is_empty() {
            hash.update(b"native-note-protocol:triptych-v2");
        }
        if !self.application_reserve_scopes.is_empty() {
            hash.update(b"application-reserve-scopes:v1");
            let encoded = serde_json::to_vec(&self.application_reserve_scopes)
                .expect("validated scopes serialize");
            hash.update((encoded.len() as u64).to_be_bytes());
            hash.update(encoded);
        }
        if !self.application_reservations.is_empty() {
            hash.update(b"application-reservations:v1");
            let encoded = serde_json::to_vec(&self.application_reservations)
                .expect("validated reservations serialize");
            hash.update((encoded.len() as u64).to_be_bytes());
            hash.update(encoded);
        }
        if !self.aethel.is_empty() {
            hash.update(b"aethel-book:v1");
            let encoded =
                serde_json::to_vec(&self.aethel).expect("validated Aethel state is serializable");
            hash.update((encoded.len() as u64).to_be_bytes());
            hash.update(encoded);
        }
        if let Some(clearing) = &self.deccp {
            hash.update(b"deccp-book:v1");
            let encoded = serde_json::to_vec(clearing)
                .expect("validated DeCCP clearing state is serializable");
            hash.update((encoded.len() as u64).to_be_bytes());
            hash.update(encoded);
        }
        for (asset_id, record) in &self.assets {
            hash.update(
                serde_json::to_vec(&json!([
                    asset_id,
                    record.code,
                    record.kind,
                    record.decimals,
                    hex::encode(record.terms_digest),
                    u8::from(record.active),
                ]))
                .expect("state asset row is serializable"),
            );
        }
        for (issuer_id, record) in &self.csd_issuers {
            hash.update(
                serde_json::to_vec(&json!([
                    issuer_id,
                    record.code,
                    record.jurisdiction,
                    hex::encode(record.operator_entity_commitment),
                    hex::encode(record.public_key),
                    record
                        .permitted_asset_ids
                        .iter()
                        .map(hex::encode)
                        .collect::<Vec<_>>(),
                    hex::encode(record.policy_digest),
                    record.valid_from,
                    record.valid_until,
                    record.status,
                    record.sequence,
                ]))
                .expect("state CSD issuer row is serializable"),
            );
        }
        for (handle, record) in &self.accounts {
            hash.update(hex::decode(handle).expect("validated account identifier"));
            hash.update(record.asset_id);
            hash.update(record.commitment);
            hash.update(record.sequence.to_be_bytes());
        }
        for (note_id, record) in &self.notes {
            hash.update(hex::decode(note_id).expect("validated note identifier"));
            for field in [
                record.asset_id,
                record.one_time,
                record.value_commitment,
                record.ephemeral,
                record.masked_value,
                record.masked_blinding,
                record.lock_id,
            ] {
                hash.update(field);
            }
        }
        for (hold_id, record) in &self.note_reservations {
            hash.update(hex::decode(hold_id).expect("validated note reservation identifier"));
            for field in [
                record.escrow_note_id,
                record.asset_id,
                record.amount_commitment,
                record.proof_digest,
                record.delegation_digest,
                record.settlement_digest,
            ] {
                hash.update(field);
            }
            hash.update((record.status.len() as u16).to_be_bytes());
            hash.update(record.status.as_bytes());
        }
        for (pool_id, record) in &self.standing_note_pools {
            hash.update(hex::decode(pool_id).expect("validated standing note pool identifier"));
            for field in [
                record.venue_id,
                record.defmi_id,
                record.entity_commitment,
                record.policy_digest,
                record.mandate_digest,
                record.asset_id,
                record.maximum_amount_commitment,
                record.current_pool_note_id,
                record.delegation_digest,
                record.statement,
            ] {
                hash.update(field);
            }
            hash.update([record.direction]);
            hash.update(record.committee_epoch.to_be_bytes());
            hash.update(record.valid_until.to_be_bytes());
            hash.update(record.sequence.to_be_bytes());
            hash.update((record.status.len() as u16).to_be_bytes());
            hash.update(record.status.as_bytes());
        }
        for (claim_id, record) in &self.note_claims {
            hash.update(hex::decode(claim_id).expect("validated note claim identifier"));
            for field in [
                record.asset_id,
                record.value_commitment,
                record.recipient_commitment,
                record.source_hold_id,
                record.settlement_digest,
                record.materialization,
            ] {
                hash.update(field);
            }
            hash.update(record.kind.as_bytes());
            hash.update(record.status.as_bytes());
        }
        for (guarantor_id, record) in &self.guarantors {
            hash.update(
                serde_json::to_vec(&json!([
                    guarantor_id,
                    record.kind,
                    record.name,
                    hex::encode(record.public_key),
                    hex::encode(record.risk_policy_digest),
                    u8::from(record.active),
                ]))
                .expect("state guarantor row is serializable"),
            );
        }
        for (facility_id, record) in &self.credit_facilities {
            hash.update(hex::decode(facility_id).expect("validated facility identifier"));
            for field in [
                record.guarantor_id,
                record.beneficiary_commitment,
                record.rail_asset_id,
                record.cap_commitment,
                record.available_commitment,
                record.held_commitment,
                record.outstanding_commitment,
                record.overlimit_commitment,
                record.collateral_commitment,
                record.risk_policy_digest,
            ] {
                hash.update(field);
            }
            hash.update(record.valid_from.to_be_bytes());
            hash.update(record.valid_until.to_be_bytes());
            hash.update((record.status.len() as u16).to_be_bytes());
            hash.update(record.status.as_bytes());
            hash.update(record.sequence.to_be_bytes());
        }
        for (hold_id, record) in &self.credit_holds {
            hash.update(hex::decode(hold_id).expect("validated hold identifier"));
            hash.update(record.facility_id);
            hash.update(record.query_commitment);
            hash.update(record.amount_commitment);
            hash.update(record.expires_at.to_be_bytes());
            hash.update((record.status.len() as u16).to_be_bytes());
            hash.update(record.status.as_bytes());
            hash.update(record.settlement_digest);
            hash.update(record.created_sequence.to_be_bytes());
            hash.update(record.updated_sequence.to_be_bytes());
        }
        for (hold_id, record) in &self.reservation_bindings {
            hash.update(hex::decode(hold_id).expect("validated reservation identifier"));
            hash.update((record.role.len() as u16).to_be_bytes());
            hash.update(record.role.as_bytes());
            hash.update(record.entity_commitment);
            hash.update(record.asset_id);
            hash.update(u64::from(record.direction).to_be_bytes());
            for field in [
                record.authorization_digest,
                record.mandate_digest,
                record.typed_reserve_digest,
                record.reserve_nullifier,
                record.asset_link_proof_digest,
                record.limit_price_commitment,
                record.rfq_nullifier,
            ] {
                hash.update(field);
            }
            hash.update(record.policy_version.to_be_bytes());
            hash.update(record.admission_ticket_id);
            hash.update(record.admission_slot.to_be_bytes());
            hash.update(record.admission_receipt_digest);
            hash.update(record.admission_epoch.to_be_bytes());
            hash.update(record.admission_sequence.to_be_bytes());
            hash.update(record.admission_batch_id);
            hash.update(record.receipt_digest);
        }
        for (hold_id, record) in &self.reservation_escrows {
            hash.update(hex::decode(hold_id).expect("validated reservation escrow identifier"));
            for field in [
                record.source_handle,
                record.escrow_handle,
                record.asset_id,
                record.amount_commitment,
                record.source_before_commitment,
                record.source_after_commitment,
            ] {
                hash.update(field);
            }
            hash.update(record.source_before_sequence.to_be_bytes());
            hash.update(record.proof_digest);
            hash.update((record.status.len() as u16).to_be_bytes());
            hash.update(record.status.as_bytes());
            hash.update(record.settlement_digest);
        }
        for (nullifier, record) in &self.nullifiers {
            hash.update(hex::decode(nullifier).expect("validated nullifier identifier"));
            hash.update(record.deadline.to_be_bytes());
            hash.update(record.statement);
        }
        for (serial, record) in &self.note_serials {
            hash.update(hex::decode(serial).expect("validated note serial"));
            hash.update(record.deadline.to_be_bytes());
            hash.update(record.asset_id);
            hash.update(record.ring_root);
            hash.update(record.statement);
        }
        for (nonce, statement) in &self.note_issuances {
            hash.update(hex::decode(nonce).expect("validated note issuance nonce"));
            hash.update(statement);
        }
        for (rfq_nullifier, statement) in &self.rfq_nullifiers {
            hash.update(hex::decode(rfq_nullifier).expect("validated RFQ nullifier"));
            hash.update(statement);
        }
        for record in self.admission_committees.values() {
            hash.update(record.venue_id);
            hash.update(record.epoch.to_be_bytes());
            for node_key in &record.node_keys {
                hash.update(node_key);
            }
            hash.update(record.valid_from.to_be_bytes());
            hash.update(record.valid_until.to_be_bytes());
            hash.update(record.statement);
        }
        for (batch_id, record) in &self.admission_batches {
            hash.update(hex::decode(batch_id).expect("validated admission batch identifier"));
            hash.update(record.venue_id);
            hash.update(record.batch_digest);
            hash.update(record.order_digest);
            hash.update(record.epoch.to_be_bytes());
            hash.update(record.slot.to_be_bytes());
            hash.update(record.population.to_be_bytes());
            hash.update(record.consumed.to_be_bytes());
            hash.update(record.expires_at.to_be_bytes());
            hash.update(record.statement);
        }
        for record in self.admission_entries.values() {
            hash.update(record.batch_id);
            hash.update(record.sequence.to_be_bytes());
            hash.update(record.admission_digest);
            hash.update(record.consumed_by);
        }
        for record in self.settlement_verifiers.values() {
            hash.update(record.venue_id);
            hash.update(record.defmi_id);
            hash.update(record.epoch.to_be_bytes());
            hash.update(record.quote_registry_digest);
            hash.update(record.quote_eligibility_bits.to_be_bytes());
            hash.update(record.quote_span_bits.to_be_bytes());
            hash.update(record.amount_bits.to_be_bytes());
            hash.update(record.price_bits.to_be_bytes());
            hash.update(record.max_horizon.to_be_bytes());
            hash.update((record.frost_public_package.len() as u64).to_be_bytes());
            hash.update(&record.frost_public_package);
            hash.update(record.valid_from.to_be_bytes());
            hash.update(record.valid_until.to_be_bytes());
            hash.update(record.statement);
        }
        for (operation, statement) in &self.operations {
            hash.update(hex::decode(operation).expect("validated operation identifier"));
            hash.update(statement);
        }
        if !self.cross_domain.is_empty() {
            hash.update(b"cross-domain-book:v1");
            let encoded = serde_json::to_vec(&self.cross_domain)
                .expect("validated cross-domain state is serializable");
            hash.update((encoded.len() as u64).to_be_bytes());
            hash.update(encoded);
        }
        if let Some(domain) = &self.cross_domain_local_domain {
            hash.update(b"cross-domain-local:v1");
            let encoded = serde_json::to_vec(domain)
                .expect("validated cross-domain local domain is serializable");
            hash.update((encoded.len() as u64).to_be_bytes());
            hash.update(encoded);
        }
        for (key, committee) in &self.cross_domain_committees {
            hash.update(b"cross-domain-committee:v1");
            hash.update((key.len() as u64).to_be_bytes());
            hash.update(key.as_bytes());
            let encoded = serde_json::to_vec(committee)
                .expect("validated cross-domain committee is serializable");
            hash.update((encoded.len() as u64).to_be_bytes());
            hash.update(encoded);
        }
        if !self.boj_liquidity.is_empty() {
            hash.update(b"boj-liquidity-book:v1");
            let encoded = serde_json::to_vec(&self.boj_liquidity)
                .expect("validated BOJ liquidity state is serializable");
            hash.update((encoded.len() as u64).to_be_bytes());
            hash.update(encoded);
        }
        if !self.participant_registry.is_empty() {
            hash.update(b"participant-registry:v1");
            let encoded = serde_json::to_vec(&self.participant_registry)
                .expect("validated participant registry state is serializable");
            hash.update((encoded.len() as u64).to_be_bytes());
            hash.update(encoded);
        }
        hash.finalize().into()
    }
}

pub(crate) fn id_key(id: &[u8; 32]) -> String {
    hex::encode(id)
}

pub(crate) fn admission_committee_key(venue_id: &[u8; 32], epoch: u64) -> String {
    format!("{}:{epoch:020}", hex::encode(venue_id))
}

pub(crate) fn cross_domain_committee_key(domain_id: &[u8; 32], epoch: u64) -> String {
    format!("{}:{epoch:020}", hex::encode(domain_id))
}

pub(crate) fn admission_entry_key(batch_id: &[u8; 32], sequence: u64) -> String {
    format!("{}:{sequence:020}", hex::encode(batch_id))
}

fn is_hex_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_matches_the_cross_runtime_contract() {
        assert_eq!(
            hex::encode(State::default().root()),
            "521319db58f6bfced1198c186828bda021dcf35141f804d19a0b792ed4028f60"
        );
    }

    #[test]
    fn state_encoding_is_canonical_and_rejects_bad_keys() {
        let mut state = State::default();
        state.accounts.insert(
            "00".repeat(32),
            AccountRecord {
                asset_id: [1; 32],
                commitment: [2; 32],
                sequence: 3,
            },
        );
        let encoded = state.encode().expect("encode");
        assert_eq!(State::decode(&encoded).expect("decode"), state);
        state.accounts.insert(
            "NOT-AN-ID".into(),
            AccountRecord {
                asset_id: [1; 32],
                commitment: [2; 32],
                sequence: 3,
            },
        );
        assert!(state.encode().is_err());
    }

    #[test]
    fn legacy_note_state_cannot_silently_restart_under_new_nullifier_rules() {
        let state = State::default();
        let encoded = state.encode().unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(value["noteProofVersion"], "triptych_v2");
        value.as_object_mut().unwrap().remove("noteProofVersion");
        assert!(State::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        value["noteProofVersion"] = serde_json::json!("legacy_v1");
        assert!(State::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        assert_eq!(State::decode(&encoded).unwrap(), state);
    }

    #[test]
    fn state_root_commits_boj_and_participant_registry_books() {
        use qomm_defmi::central_bank_liquidity::{
            BojParticipant, ParticipantStatus, RegisterParticipant,
        };
        use qomm_defmi::participant::RegistryConfiguration;

        let empty = State::default().root();

        let mut boj = State::default();
        boj.boj_liquidity
            .register_participant(
                RegisterParticipant {
                    operation_id: [1; 32],
                    participant: BojParticipant {
                        legal_entity_id: [2; 32],
                        funds_account_id: [3; 32],
                        jgb_account_id: [4; 32],
                        current_account_balance_yen: 100,
                        other_secured_exposure_yen: 0,
                        intraday_overdraft_yen: 0,
                        business_day: 1,
                        repayment_deadline: 100,
                        business_day_closed: false,
                        sequence: 0,
                        status: ParticipantStatus::Active,
                    },
                },
                10,
            )
            .expect("BOJ participant");
        assert_ne!(boj.root(), empty);

        let mut participant = State::default();
        participant
            .participant_registry
            .configure(RegistryConfiguration {
                operation_id: [5; 32],
                domain_id: [6; 32],
                template_digest: [7; 32],
                schema_digest: [8; 32],
                template_version: 1,
            })
            .expect("participant registry");
        assert_ne!(participant.root(), empty);
        assert_ne!(participant.root(), boj.root());
        assert_eq!(
            State::decode(&participant.encode().expect("encode"))
                .expect("decode")
                .root(),
            participant.root()
        );
    }
}
