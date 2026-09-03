//! Fail-closed Avalanche custom-VM JSON-RPC client and projection bridge.

use crate::facility::{
    AccountOpening, AdmissionBatchPlan, AdmissionBatchSnapshot, AdmissionCommitteePlan,
    AdmissionSlotAdvance, AssetDefinition, AssetKind, CreditFacilityAmendment,
    CreditFacilityAmendmentProof, CreditFacilityControl, CreditFacilityGrant,
    CreditFacilityRelationProof, CreditFacilitySnapshot, CreditFacilityStatus,
    CreditFacilityTransition, DefmiFacility, GuarantorDefinition, GuarantorKind,
    ProductReleaseOrder, ProductSettlementBatch, ProductSettlementOrder, QuorumApproval,
    QuorumAuthorizer, ReservationAuthorization, ReservationEscrow, SettlementOrder,
    SettlementReceipt,
};
use crate::note_chain::{
    standing_pool_product_settlement_statement, CsdIssuerControl, CsdIssuerDefinition,
    DelegatedNoteSettlementOrder, EscrowClaimSpend, NoteClaim, NoteClaimKind,
    NoteClaimMaterialization, NoteIssuance, NoteOutput, NoteReservationEscrow, NoteSettlementOrder,
    NoteSpend, ProductNoteNoFillReleaseOrder, ProductNoteReleaseOrder, ProductNoteSettlementBatch,
    ProductNoteSettlementOrder, StandingNotePoolAllocation, StandingNotePoolRegistration,
};
use crate::notes::NoteLedger;
use crate::participant::{
    AccountBinding, EntityApproval, MandateControl, MandateReservation,
    MandateReservationTransition, MpcService, ParticipantControl, ParticipantServiceBinding,
    RegisterParticipant, RegistryConfiguration, RotateParticipantKey, StandingMandate,
};
use crate::product_evidence::{MpcNoFillEvidence, ProductSettlementEvidence};
use crate::settlement_verifier::SettlementVerifierConfig;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use qomm_proofs::opening_envelope::{EncryptedOpeningShare, OpeningEnvelope};
use qomm_proofs::price_limit::PriceLimitProof;
use qomm_transport::mandate::{MakerPolicyMandate, TakerExecutionMandate};
use qomm_transport::order::NodeAdmissionAttestation;
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::typed::TypedInstruction;
use qomm_zkpi::Venue;
use rand_core::{CryptoRng, RngCore};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const MAX_RESPONSE: usize = 1_048_576;
// Local Avalanche networks can legitimately take longer than one proposer
// interval to move a submitted transaction from pending to a terminal state.
// A caller must never mistake an observation timeout for consensus rejection:
// keep polling long enough to obtain an accepted or rejected receipt.
const CONSENSUS_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(180);
const CONSENSUS_POLL_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedTransition {
    pub tx_id: String,
    pub block_id: String,
    pub height: u64,
    pub statement: [u8; 32],
    pub before_root: [u8; 32],
    pub after_root: [u8; 32],
}

/// Complete input to one atomic standing-pool split and product settlement.
/// Grouping these references prevents callers from accidentally reordering or
/// omitting one of the two linked authorizations when crossing an RPC boundary.
#[derive(Clone, Copy)]
pub struct StandingPoolProductSettlementRequest<'a> {
    pub allocation_transition: &'a CreditFacilityTransition,
    pub allocation_authorization: &'a ReservationAuthorization,
    pub allocation: &'a StandingNotePoolAllocation,
    pub allocation_approval: &'a QuorumApproval,
    pub order: &'a ProductNoteSettlementOrder,
    pub evidence: &'a ProductSettlementEvidence,
}

fn result_object(value: &Value) -> Result<&serde_json::Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| "L1 returned a malformed canonical-state snapshot".to_string())
}

fn result_hex32(object: &serde_json::Map<String, Value>, name: &str) -> Result<[u8; 32], String> {
    let raw = object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("L1 snapshot is missing {name}"))?;
    hex::decode(raw)
        .map_err(|_| format!("L1 snapshot {name} is not hexadecimal"))?
        .try_into()
        .map_err(|_| format!("L1 snapshot {name} is not 32 bytes"))
}

fn result_u64(object: &serde_json::Map<String, Value>, name: &str) -> Result<u64, String> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("L1 snapshot is missing numeric {name}"))
}

fn result_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a str, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("L1 snapshot is missing {name}"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalCreditFacility {
    pub state_root: [u8; 32],
    pub facility: CreditFacilitySnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalAsset {
    pub state_root: [u8; 32],
    pub definition: AssetDefinition,
    pub active: bool,
}

impl CanonicalAsset {
    fn parse(value: &Value) -> Result<Self, String> {
        let object = result_object(value)?;
        let decimals = result_u64(object, "decimals")?;
        let definition = AssetDefinition {
            asset_id: result_hex32(object, "assetID")?,
            code: result_string(object, "code")?.to_string(),
            kind: AssetKind::parse(result_string(object, "kind")?)?,
            decimals: decimals
                .try_into()
                .map_err(|_| "L1 asset decimals exceed u8".to_string())?,
            terms_digest: result_hex32(object, "termsDigest")?,
        };
        definition.body()?;
        Ok(Self {
            state_root: result_hex32(object, "stateRoot")?,
            definition,
            active: object
                .get("active")
                .and_then(Value::as_bool)
                .ok_or_else(|| "L1 asset is missing active status".to_string())?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalGuarantor {
    pub state_root: [u8; 32],
    pub definition: GuarantorDefinition,
    pub active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalSettlementVerifier {
    pub state_root: [u8; 32],
    pub config: SettlementVerifierConfig,
    pub statement: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalAdmissionCursor {
    pub state_root: [u8; 32],
    pub venue_id: [u8; 32],
    pub epoch: u64,
    pub last_sequence: u64,
    pub next_sequence: u64,
}

impl CanonicalAdmissionCursor {
    fn parse(value: &Value) -> Result<Self, String> {
        let object = result_object(value)?;
        let last_sequence = result_u64(object, "lastSequence")?;
        let next_sequence = result_u64(object, "nextSequence")?;
        if result_u64(object, "epoch")? == 0
            || next_sequence
                != last_sequence
                    .checked_add(1)
                    .ok_or_else(|| "L1 admission sequence is exhausted".to_string())?
        {
            return Err("L1 admission cursor is not canonical".into());
        }
        Ok(Self {
            state_root: result_hex32(object, "stateRoot")?,
            venue_id: result_hex32(object, "venueID")?,
            epoch: result_u64(object, "epoch")?,
            last_sequence,
            next_sequence,
        })
    }
}

impl CanonicalSettlementVerifier {
    fn parse(value: &Value) -> Result<Self, String> {
        let object = result_object(value)?;
        let config = SettlementVerifierConfig {
            venue_id: result_hex32(object, "venueID")?,
            defmi_id: result_hex32(object, "defmiID")?,
            epoch: result_u64(object, "epoch")?,
            quote_registry_digest: result_hex32(object, "quoteRegistryDigest")?,
            quote_eligibility_bits: result_u64(object, "quoteEligibilityBits")?
                .try_into()
                .map_err(|_| "L1 quote eligibility width exceeds u16".to_string())?,
            quote_span_bits: result_u64(object, "quoteSpanBits")?
                .try_into()
                .map_err(|_| "L1 quote span width exceeds u16".to_string())?,
            amount_bits: result_u64(object, "amountBits")?
                .try_into()
                .map_err(|_| "L1 amount width exceeds u16".to_string())?,
            price_bits: result_u64(object, "priceBits")?
                .try_into()
                .map_err(|_| "L1 price width exceeds u16".to_string())?,
            max_horizon: result_u64(object, "maxHorizon")?,
            frost_public_package: BASE64
                .decode(result_string(object, "frostPublicPackage")?)
                .map_err(|_| "L1 FROST public package is not base64".to_string())?,
            valid_from: result_u64(object, "validFrom")?,
            valid_until: result_u64(object, "validUntil")?,
        };
        config.validate()?;
        let statement = result_hex32(object, "statement")?;
        if config.statement()? != statement {
            return Err("L1 settlement verifier statement differs from its fields".into());
        }
        Ok(Self {
            state_root: result_hex32(object, "stateRoot")?,
            config,
            statement,
        })
    }
}

impl CanonicalGuarantor {
    fn parse(value: &Value) -> Result<Self, String> {
        let object = result_object(value)?;
        let definition = GuarantorDefinition {
            guarantor_id: result_hex32(object, "guarantorID")?,
            kind: GuarantorKind::parse(result_string(object, "kind")?)?,
            name: result_string(object, "name")?.to_string(),
            public_key: result_hex32(object, "publicKey")?,
            risk_policy_digest: result_hex32(object, "riskPolicyDigest")?,
        };
        definition.body()?;
        Ok(Self {
            state_root: result_hex32(object, "stateRoot")?,
            definition,
            active: object
                .get("active")
                .and_then(Value::as_bool)
                .ok_or_else(|| "L1 guarantor is missing active status".to_string())?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalCsdIssuer {
    pub state_root: [u8; 32],
    pub definition: CsdIssuerDefinition,
    pub status: String,
    pub sequence: u64,
}

impl CanonicalCsdIssuer {
    fn parse(value: &Value) -> Result<Self, String> {
        let object = result_object(value)?;
        let public_key = result_hex32(object, "publicKey")?;
        let assets = object
            .get("permittedAssetIDs")
            .and_then(Value::as_array)
            .ok_or_else(|| "L1 CSD issuer is missing permittedAssetIDs".to_string())?
            .iter()
            .map(|value| {
                let encoded = value
                    .as_str()
                    .ok_or_else(|| "L1 CSD asset identifier is not text".to_string())?;
                hex::decode(encoded)
                    .map_err(|_| "L1 CSD asset identifier is not hexadecimal".to_string())?
                    .try_into()
                    .map_err(|_| "L1 CSD asset identifier is not 32 bytes".to_string())
            })
            .collect::<Result<Vec<[u8; 32]>, String>>()?;
        let definition = CsdIssuerDefinition {
            issuer_id: result_hex32(object, "issuerID")?,
            code: result_string(object, "code")?.to_string(),
            jurisdiction: result_string(object, "jurisdiction")?.to_string(),
            operator_entity_commitment: result_hex32(object, "operatorEntityCommitment")?,
            public_key,
            permitted_asset_ids: assets,
            policy_digest: result_hex32(object, "policyDigest")?,
            valid_from: result_u64(object, "validFrom")?,
            valid_until: result_u64(object, "validUntil")?,
        };
        definition.body()?;
        let status = result_string(object, "status")?.to_string();
        if !matches!(status.as_str(), "active" | "suspended" | "revoked") {
            return Err("L1 CSD issuer has an unknown status".into());
        }
        Ok(Self {
            state_root: result_hex32(object, "stateRoot")?,
            definition,
            status,
            sequence: result_u64(object, "sequence")?,
        })
    }
}

impl CanonicalCreditFacility {
    fn parse(value: &Value) -> Result<Self, String> {
        let object = result_object(value)?;
        Ok(Self {
            state_root: result_hex32(object, "stateRoot")?,
            facility: CreditFacilitySnapshot {
                facility_id: result_hex32(object, "facilityID")?,
                guarantor_id: result_hex32(object, "guarantorID")?,
                beneficiary_commitment: result_hex32(object, "beneficiaryCommitment")?,
                rail_asset_id: result_hex32(object, "railAssetID")?,
                cap_commitment: result_hex32(object, "capCommitment")?,
                available_commitment: result_hex32(object, "availableCommitment")?,
                held_commitment: result_hex32(object, "heldCommitment")?,
                outstanding_commitment: result_hex32(object, "outstandingCommitment")?,
                overlimit_commitment: result_hex32(object, "overlimitCommitment")?,
                collateral_commitment: result_hex32(object, "collateralCommitment")?,
                risk_policy_digest: result_hex32(object, "riskPolicyDigest")?,
                valid_from: result_u64(object, "validFrom")?,
                valid_until: result_u64(object, "validUntil")?,
                status: CreditFacilityStatus::parse(result_string(object, "status")?)?,
                sequence: result_u64(object, "sequence")?,
            },
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalCreditHold {
    pub state_root: [u8; 32],
    pub hold_id: [u8; 32],
    pub facility_id: [u8; 32],
    pub query_commitment: [u8; 32],
    pub amount_commitment: [u8; 32],
    pub expires_at: u64,
    pub status: String,
    pub settlement_digest: [u8; 32],
    pub created_sequence: u64,
    pub updated_sequence: u64,
}

impl CanonicalCreditHold {
    fn parse(value: &Value) -> Result<Self, String> {
        let object = result_object(value)?;
        let status = result_string(object, "status")?.to_string();
        if !matches!(status.as_str(), "active" | "released" | "consumed") {
            return Err("L1 snapshot contains an invalid credit-hold status".into());
        }
        Ok(Self {
            state_root: result_hex32(object, "stateRoot")?,
            hold_id: result_hex32(object, "holdID")?,
            facility_id: result_hex32(object, "facilityID")?,
            query_commitment: result_hex32(object, "queryCommitment")?,
            amount_commitment: result_hex32(object, "amountCommitment")?,
            expires_at: result_u64(object, "expiresAt")?,
            status,
            settlement_digest: result_hex32(object, "settlementDigest")?,
            created_sequence: result_u64(object, "createdSequence")?,
            updated_sequence: result_u64(object, "updatedSequence")?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalNote {
    pub state_root: [u8; 32],
    pub output: NoteOutput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalNoteSerial {
    pub state_root: [u8; 32],
    pub serial_point: [u8; 32],
    pub spent: bool,
}

impl CanonicalNoteSerial {
    fn parse(value: &Value) -> Result<Self, String> {
        let object = result_object(value)?;
        Ok(Self {
            state_root: result_hex32(object, "stateRoot")?,
            serial_point: result_hex32(object, "serialPoint")?,
            spent: object
                .get("spent")
                .and_then(Value::as_bool)
                .ok_or_else(|| "L1 note-serial snapshot has no spent flag".to_string())?,
        })
    }
}

impl CanonicalNote {
    fn parse(value: &Value) -> Result<Self, String> {
        let object = result_object(value)?;
        let output = NoteOutput {
            note_id: result_hex32(object, "noteID")?,
            asset_id: result_hex32(object, "assetID")?,
            one_time: result_hex32(object, "oneTime")?,
            value_commitment: result_hex32(object, "valueCommitment")?,
            ephemeral: result_hex32(object, "ephemeral")?,
            masked_value: result_hex32(object, "maskedValue")?,
            masked_blinding: result_hex32(object, "maskedBlinding")?,
            lock_id: result_hex32(object, "lockID")?,
        };
        output.validate()?;
        Ok(Self {
            state_root: result_hex32(object, "stateRoot")?,
            output,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalNotePage {
    pub state_root: [u8; 32],
    pub notes: Vec<NoteOutput>,
    pub next: Option<[u8; 32]>,
}

impl CanonicalNotePage {
    fn parse(value: &Value) -> Result<Self, String> {
        let object = result_object(value)?;
        let root = result_hex32(object, "stateRoot")?;
        let values = object
            .get("notes")
            .and_then(Value::as_array)
            .ok_or_else(|| "L1 note page has no note array".to_string())?;
        let mut notes = Vec::with_capacity(values.len());
        for value in values {
            let note = CanonicalNote::parse(value)?;
            if note.state_root != root {
                return Err("L1 note page mixes different state roots".into());
            }
            notes.push(note.output);
        }
        let next = match object.get("next").and_then(Value::as_str) {
            None | Some("") => None,
            Some(value) => Some(
                hex::decode(value)
                    .map_err(|_| "L1 note cursor is not hexadecimal".to_string())?
                    .try_into()
                    .map_err(|_| "L1 note cursor is not 32 bytes".to_string())?,
            ),
        };
        Ok(Self {
            state_root: root,
            notes,
            next,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalNoteReservation {
    pub state_root: [u8; 32],
    pub accepted_height: u64,
    pub hold_id: [u8; 32],
    pub escrow_note_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub amount_commitment: [u8; 32],
    pub proof_digest: [u8; 32],
    pub delegation_digest: [u8; 32],
    /// Canonical statement that created the reservation.  This remains stable
    /// while `settlement_digest` is zero for an active hold, so clients can
    /// safely recover the original reserve receipt after a retry or restart.
    pub reserve_receipt_digest: [u8; 32],
    pub status: String,
    pub settlement_digest: [u8; 32],
}

impl CanonicalNoteReservation {
    fn parse(value: &Value) -> Result<Self, String> {
        let object = result_object(value)?;
        let status = result_string(object, "status")?.to_string();
        if !matches!(status.as_str(), "active" | "released" | "consumed") {
            return Err("L1 snapshot contains an invalid note-reservation status".into());
        }
        Ok(Self {
            state_root: result_hex32(object, "stateRoot")?,
            accepted_height: result_u64(object, "acceptedHeight")?,
            hold_id: result_hex32(object, "holdID")?,
            escrow_note_id: result_hex32(object, "escrowNoteID")?,
            asset_id: result_hex32(object, "assetID")?,
            amount_commitment: result_hex32(object, "amountCommitment")?,
            proof_digest: result_hex32(object, "proofDigest")?,
            delegation_digest: result_hex32(object, "delegationDigest")?,
            reserve_receipt_digest: result_hex32(object, "reserveReceiptDigest")?,
            status,
            settlement_digest: result_hex32(object, "settlementDigest")?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalStandingNotePool {
    pub state_root: [u8; 32],
    pub pool_id: [u8; 32],
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

impl CanonicalStandingNotePool {
    fn parse(value: &Value) -> Result<Self, String> {
        let object = result_object(value)?;
        let status = result_string(object, "status")?.to_string();
        if status != "active" {
            return Err("L1 snapshot contains an invalid standing-note-pool status".into());
        }
        let direction = result_u64(object, "direction")?;
        Ok(Self {
            state_root: result_hex32(object, "stateRoot")?,
            pool_id: result_hex32(object, "poolID")?,
            venue_id: result_hex32(object, "venueID")?,
            defmi_id: result_hex32(object, "defmiID")?,
            entity_commitment: result_hex32(object, "entityCommitment")?,
            policy_digest: result_hex32(object, "policyDigest")?,
            mandate_digest: result_hex32(object, "mandateDigest")?,
            asset_id: result_hex32(object, "assetID")?,
            direction: direction
                .try_into()
                .map_err(|_| "standing-note-pool direction exceeds u8".to_string())?,
            maximum_amount_commitment: result_hex32(object, "maximumAmountCommitment")?,
            current_pool_note_id: result_hex32(object, "currentPoolNoteID")?,
            delegation_digest: result_hex32(object, "delegationDigest")?,
            committee_epoch: result_u64(object, "committeeEpoch")?,
            valid_until: result_u64(object, "validUntil")?,
            sequence: result_u64(object, "sequence")?,
            status,
            statement: result_hex32(object, "statement")?,
        })
    }
}

/// Read-only result of replaying one standing-pool allocation against the
/// current canonical root. The VM has not committed any of these fields; the
/// result exists solely to bind the final typed zkPI to the exact intermediate
/// root that the atomic settlement transaction will reproduce.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandingNotePoolAllocationPreview {
    pub before_state_root: [u8; 32],
    pub after_state_root: [u8; 32],
    pub statement: [u8; 32],
    pub pool_id: [u8; 32],
    pub current_pool_note_id: [u8; 32],
    pub pool_sequence: u64,
    pub reservation_hold_id: [u8; 32],
    pub escrow_note_id: [u8; 32],
    pub reservation_asset_id: [u8; 32],
    pub reservation_amount_commitment: [u8; 32],
    pub reservation_proof_digest: [u8; 32],
    pub reservation_delegation_digest: [u8; 32],
    pub reserve_receipt_digest: [u8; 32],
    pub reservation_status: String,
    pub hold_facility_id: [u8; 32],
    pub hold_query_commitment: [u8; 32],
    pub hold_amount_commitment: [u8; 32],
    pub hold_expires_at: u64,
    pub hold_status: String,
    pub facility: CreditFacilitySnapshot,
}

impl StandingNotePoolAllocationPreview {
    fn parse(value: &Value) -> Result<Self, String> {
        let object = result_object(value)?;
        let pool = object
            .get("pool")
            .ok_or_else(|| "L1 allocation preview is missing pool".to_string())
            .and_then(result_object)?;
        let reservation = object
            .get("reservation")
            .ok_or_else(|| "L1 allocation preview is missing reservation".to_string())
            .and_then(result_object)?;
        let hold = object
            .get("hold")
            .ok_or_else(|| "L1 allocation preview is missing hold".to_string())
            .and_then(result_object)?;
        let facility = object
            .get("facility")
            .ok_or_else(|| "L1 allocation preview is missing facility".to_string())
            .and_then(result_object)?;
        let reservation_status = result_string(reservation, "status")?.to_string();
        let hold_status = result_string(hold, "status")?.to_string();
        if reservation_status != "active" || hold_status != "active" {
            return Err("L1 allocation preview did not produce active Maker covenants".into());
        }
        let snapshot = CreditFacilitySnapshot {
            facility_id: result_hex32(facility, "facilityID")?,
            guarantor_id: result_hex32(facility, "guarantorID")?,
            beneficiary_commitment: result_hex32(facility, "beneficiaryCommitment")?,
            rail_asset_id: result_hex32(facility, "railAssetID")?,
            cap_commitment: result_hex32(facility, "capCommitment")?,
            available_commitment: result_hex32(facility, "availableCommitment")?,
            held_commitment: result_hex32(facility, "heldCommitment")?,
            outstanding_commitment: result_hex32(facility, "outstandingCommitment")?,
            overlimit_commitment: result_hex32(facility, "overlimitCommitment")?,
            collateral_commitment: result_hex32(facility, "collateralCommitment")?,
            risk_policy_digest: result_hex32(facility, "riskPolicyDigest")?,
            valid_from: result_u64(facility, "validFrom")?,
            valid_until: result_u64(facility, "validUntil")?,
            status: CreditFacilityStatus::parse(result_string(facility, "status")?)?,
            sequence: result_u64(facility, "sequence")?,
        };
        Ok(Self {
            before_state_root: result_hex32(object, "beforeStateRoot")?,
            after_state_root: result_hex32(object, "afterStateRoot")?,
            statement: result_hex32(object, "statement")?,
            pool_id: result_hex32(pool, "poolID")?,
            current_pool_note_id: result_hex32(pool, "currentPoolNoteID")?,
            pool_sequence: result_u64(pool, "sequence")?,
            reservation_hold_id: result_hex32(reservation, "holdID")?,
            escrow_note_id: result_hex32(reservation, "escrowNoteID")?,
            reservation_asset_id: result_hex32(reservation, "assetID")?,
            reservation_amount_commitment: result_hex32(reservation, "amountCommitment")?,
            reservation_proof_digest: result_hex32(reservation, "proofDigest")?,
            reservation_delegation_digest: result_hex32(reservation, "delegationDigest")?,
            reserve_receipt_digest: result_hex32(reservation, "reserveReceiptDigest")?,
            reservation_status,
            hold_facility_id: result_hex32(hold, "facilityID")?,
            hold_query_commitment: result_hex32(hold, "queryCommitment")?,
            hold_amount_commitment: result_hex32(hold, "amountCommitment")?,
            hold_expires_at: result_u64(hold, "expiresAt")?,
            hold_status,
            facility: snapshot,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalNoteClaim {
    pub state_root: [u8; 32],
    pub claim_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub value_commitment: [u8; 32],
    pub recipient_commitment: [u8; 32],
    pub source_hold_id: [u8; 32],
    pub kind: NoteClaimKind,
    pub status: String,
    pub settlement_digest: [u8; 32],
    pub materialization: [u8; 32],
    pub opening_envelope: OpeningEnvelope,
}

impl CanonicalNoteClaim {
    fn parse(value: &Value) -> Result<Self, String> {
        let object = result_object(value)?;
        let kind = match result_string(object, "kind")? {
            "delivery" => NoteClaimKind::Delivery,
            "refund" => NoteClaimKind::Refund,
            _ => return Err("L1 snapshot contains an invalid note-claim kind".into()),
        };
        let status = result_string(object, "status")?.to_string();
        if !matches!(status.as_str(), "active" | "materialized") {
            return Err("L1 snapshot contains an invalid note-claim status".into());
        }
        let opening = object
            .get("openingEnvelope")
            .and_then(Value::as_object)
            .ok_or_else(|| "L1 snapshot is missing openingEnvelope".to_string())?;
        let recipient_view = CompressedRistretto(result_hex32(opening, "recipientView")?)
            .decompress()
            .ok_or_else(|| "L1 opening recipient is not canonical".to_string())?;
        let shares = opening
            .get("shares")
            .and_then(Value::as_array)
            .ok_or_else(|| "L1 snapshot is missing opening shares".to_string())?
            .iter()
            .map(|value| {
                let share = result_object(value)?;
                let scalar = |name: &str| {
                    Option::<Scalar>::from(Scalar::from_canonical_bytes(result_hex32(share, name)?))
                        .ok_or_else(|| format!("L1 opening {name} is not canonical"))
                };
                Ok(EncryptedOpeningShare {
                    party: usize::try_from(result_u64(share, "party")?)
                        .map_err(|_| "L1 opening party is too large".to_string())?,
                    ephemeral: CompressedRistretto(result_hex32(share, "ephemeral")?)
                        .decompress()
                        .ok_or_else(|| "L1 opening ephemeral is not canonical".to_string())?,
                    masked_value: scalar("maskedValue")?,
                    masked_blinding: scalar("maskedBlinding")?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let opening_envelope = OpeningEnvelope::new(
            result_hex32(opening, "context")?,
            usize::try_from(result_u64(opening, "threshold")?)
                .map_err(|_| "L1 opening threshold is too large".to_string())?,
            recipient_view,
            shares,
        )?;
        Ok(Self {
            state_root: result_hex32(object, "stateRoot")?,
            claim_id: result_hex32(object, "claimID")?,
            asset_id: result_hex32(object, "assetID")?,
            value_commitment: result_hex32(object, "valueCommitment")?,
            recipient_commitment: result_hex32(object, "recipientCommitment")?,
            source_hold_id: result_hex32(object, "sourceHoldID")?,
            kind,
            status,
            settlement_digest: result_hex32(object, "settlementDigest")?,
            materialization: result_hex32(object, "materialization")?,
            opening_envelope,
        })
    }

    /// Reconstruct the public claim statement stored by DeFMI.  The canonical
    /// snapshot carries lifecycle metadata in addition to these immutable
    /// fields; callers use this projection when verifying recipient-side
    /// materialization without trusting a coordinator-supplied claim.
    pub fn claim(&self) -> Result<NoteClaim, String> {
        let claim = NoteClaim {
            claim_id: self.claim_id,
            asset_id: self.asset_id,
            value_commitment: self.value_commitment,
            recipient_commitment: self.recipient_commitment,
            source_hold_id: self.source_hold_id,
            kind: self.kind,
            opening_envelope: self.opening_envelope.clone(),
        };
        claim.validate()?;
        Ok(claim)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalNoteClaimPage {
    pub state_root: [u8; 32],
    pub claims: Vec<CanonicalNoteClaim>,
    pub next: Option<[u8; 32]>,
}

impl CanonicalNoteClaimPage {
    fn parse(value: &Value) -> Result<Self, String> {
        let object = result_object(value)?;
        let state_root = result_hex32(object, "stateRoot")?;
        let values = object
            .get("claims")
            .and_then(Value::as_array)
            .ok_or_else(|| "L1 note-claim page has no claim array".to_string())?;
        let mut claims = Vec::with_capacity(values.len());
        for value in values {
            let claim = CanonicalNoteClaim::parse(value)?;
            if claim.state_root != state_root {
                return Err("L1 note-claim page mixes different state roots".into());
            }
            claims.push(claim);
        }
        let next = match object.get("next").and_then(Value::as_str) {
            None | Some("") => None,
            Some(value) => Some(
                hex::decode(value)
                    .map_err(|_| "L1 note-claim cursor is not hexadecimal".to_string())?
                    .try_into()
                    .map_err(|_| "L1 note-claim cursor is not 32 bytes".to_string())?,
            ),
        };
        Ok(Self {
            state_root,
            claims,
            next,
        })
    }
}

impl AcceptedTransition {
    pub fn parse(value: &Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "L1 returned a malformed acceptance receipt".to_string())?;
        let parse = |name: &str| -> Result<[u8; 32], String> {
            hex::decode(
                object
                    .get(name)
                    .and_then(Value::as_str)
                    .ok_or_else(|| "L1 returned a malformed acceptance receipt".to_string())?,
            )
            .map_err(|_| "L1 acceptance receipt has invalid field widths".to_string())?
            .try_into()
            .map_err(|_| "L1 acceptance receipt has invalid field widths".to_string())
        };
        Ok(Self {
            tx_id: object
                .get("txID")
                .and_then(Value::as_str)
                .ok_or_else(|| "L1 returned a malformed acceptance receipt".to_string())?
                .to_string(),
            block_id: object
                .get("blockID")
                .and_then(Value::as_str)
                .ok_or_else(|| "L1 returned a malformed acceptance receipt".to_string())?
                .to_string(),
            height: object
                .get("height")
                .and_then(Value::as_u64)
                .ok_or_else(|| "L1 returned a malformed acceptance receipt".to_string())?,
            statement: parse("statement")?,
            before_root: parse("beforeRoot")?,
            after_root: parse("afterRoot")?,
        })
    }
}

fn approval_json(approval: &QuorumApproval) -> Value {
    json!({
        "statement": hex::encode(approval.statement),
        "signerEpoch": approval.signer_epoch,
        "domain": approval.domain,
        "beforeRoot": hex::encode(approval.before_root),
        "approvals": approval.approvals.iter().map(|signed| json!({
            "nodeID": signed.node_id,
            "signature": hex::encode(signed.signature.to_bytes()),
        })).collect::<Vec<_>>(),
    })
}

fn entity_approval_json(approval: &EntityApproval) -> Value {
    json!({
        "participantID": hex::encode(approval.participant_id),
        "keyPurpose": approval.key_purpose,
        "keyEpoch": approval.key_epoch,
        "statement": hex::encode(approval.statement),
        "signature": hex::encode(&approval.signature),
    })
}

fn registry_configuration_json(configuration: &RegistryConfiguration) -> Value {
    json!({
        "operationID": hex::encode(configuration.operation_id),
        "domainID": hex::encode(configuration.domain_id),
        "templateDigest": hex::encode(configuration.template_digest),
        "schemaDigest": hex::encode(configuration.schema_digest),
        "templateVersion": configuration.template_version,
    })
}

fn register_participant_json(registration: &RegisterParticipant) -> Value {
    let purpose_key = |key: &crate::participant::PurposeKey| {
        json!({
            "publicKey": hex::encode(key.public_key),
            "epoch": key.epoch,
        })
    };
    let participant = &registration.participant;
    json!({
        "operationID": hex::encode(registration.operation_id),
        "participant": {
            "participantID": hex::encode(participant.participant_id),
            "legalEntityCredentialCommitment": hex::encode(participant.legal_entity_credential_commitment),
            "credentialIssuerID": hex::encode(participant.credential_issuer_id),
            "credentialSchemeDigest": hex::encode(participant.credential_scheme_digest),
            "jurisdiction": participant.jurisdiction,
            "roles": participant.roles,
            "keys": {
                "admin": purpose_key(&participant.keys.admin),
                "settlement": purpose_key(&participant.keys.settlement),
                "quote": purpose_key(&participant.keys.quote),
                "mpcInput": purpose_key(&participant.keys.mpc_input),
                "emergency": purpose_key(&participant.keys.emergency),
            },
            "policyDigest": hex::encode(participant.policy_digest),
            "validFrom": participant.valid_from,
            "validUntil": participant.valid_until,
        },
    })
}

fn participant_control_json(control: &ParticipantControl) -> Value {
    json!({
        "operationID": hex::encode(control.operation_id),
        "participantID": hex::encode(control.participant_id),
        "expectedSequence": control.expected_sequence,
        "kind": control.kind,
        "reasonDigest": hex::encode(control.reason_digest),
    })
}

fn participant_key_rotation_json(rotation: &RotateParticipantKey) -> Value {
    json!({
        "operationID": hex::encode(rotation.operation_id),
        "participantID": hex::encode(rotation.participant_id),
        "expectedSequence": rotation.expected_sequence,
        "purpose": rotation.purpose,
        "newKey": {
            "publicKey": hex::encode(rotation.new_key.public_key),
            "epoch": rotation.new_key.epoch,
        },
    })
}

fn mpc_service_json(service: &MpcService) -> Value {
    json!({
        "operationID": hex::encode(service.operation_id),
        "serviceID": hex::encode(service.service_id),
        "kind": service.kind,
        "programDigest": hex::encode(service.program_digest),
        "schemaDigest": hex::encode(service.schema_digest),
        "committeeEpoch": service.committee_epoch,
        "threshold": service.threshold,
        "members": service.members.iter().map(|member| json!({
            "nodeID": hex::encode(member.node_id),
            "operatorParticipantID": hex::encode(member.operator_participant_id),
            "publicKey": hex::encode(member.public_key),
        })).collect::<Vec<_>>(),
        "validFrom": service.valid_from,
        "validUntil": service.valid_until,
    })
}

fn account_binding_json(binding: &AccountBinding) -> Value {
    json!({
        "operationID": hex::encode(binding.operation_id),
        "bindingID": hex::encode(binding.binding_id),
        "participantID": hex::encode(binding.participant_id),
        "accountCommitment": hex::encode(binding.account_commitment),
        "assetID": hex::encode(binding.asset_id),
        "kind": binding.kind,
        "controlProofDigest": hex::encode(binding.control_proof_digest),
        "validFrom": binding.valid_from,
        "validUntil": binding.valid_until,
        "expectedParticipantSequence": binding.expected_participant_sequence,
    })
}

fn participant_service_binding_json(binding: &ParticipantServiceBinding) -> Value {
    json!({
        "operationID": hex::encode(binding.operation_id),
        "bindingID": hex::encode(binding.binding_id),
        "participantID": hex::encode(binding.participant_id),
        "serviceID": hex::encode(binding.service_id),
        "serviceEpoch": binding.service_epoch,
        "inputPublicKey": hex::encode(binding.input_public_key),
        "capabilityDigest": hex::encode(binding.capability_digest),
        "validFrom": binding.valid_from,
        "validUntil": binding.valid_until,
        "expectedParticipantSequence": binding.expected_participant_sequence,
    })
}

fn standing_mandate_json(mandate: &StandingMandate) -> Value {
    json!({
        "operationID": hex::encode(mandate.operation_id),
        "mandateID": hex::encode(mandate.mandate_id),
        "participantID": hex::encode(mandate.participant_id),
        "serviceID": hex::encode(mandate.service_id),
        "serviceBindingID": hex::encode(mandate.service_binding_id),
        "role": mandate.role,
        "accountBindingIDs": mandate.account_binding_ids.iter().map(hex::encode).collect::<Vec<_>>(),
        "permittedAssetIDs": mandate.permitted_asset_ids.iter().map(hex::encode).collect::<Vec<_>>(),
        "permittedDestinationDomains": mandate.permitted_destination_domains.iter().map(hex::encode).collect::<Vec<_>>(),
        "limitCommitment": hex::encode(mandate.limit_commitment),
        "limitPolicyDigest": hex::encode(mandate.limit_policy_digest),
        "settlementPolicyDigest": hex::encode(mandate.settlement_policy_digest),
        "maxActiveReservations": mandate.max_active_reservations,
        "validFrom": mandate.valid_from,
        "validUntil": mandate.valid_until,
        "expectedParticipantSequence": mandate.expected_participant_sequence,
        "automaticSettlement": mandate.automatic_settlement,
    })
}

fn mandate_control_json(control: &MandateControl) -> Value {
    json!({
        "operationID": hex::encode(control.operation_id),
        "mandateID": hex::encode(control.mandate_id),
        "expectedMandateSequence": control.expected_mandate_sequence,
        "kind": control.kind,
        "reasonDigest": hex::encode(control.reason_digest),
    })
}

fn mandate_reservation_json(reservation: &MandateReservation) -> Value {
    json!({
        "operationID": hex::encode(reservation.operation_id),
        "reservationID": hex::encode(reservation.reservation_id),
        "mandateID": hex::encode(reservation.mandate_id),
        "serviceID": hex::encode(reservation.service_id),
        "serviceEpoch": reservation.service_epoch,
        "accountBindingID": hex::encode(reservation.account_binding_id),
        "assetID": hex::encode(reservation.asset_id),
        "amountCommitment": hex::encode(reservation.amount_commitment),
        "underlyingReservationDigest": hex::encode(reservation.underlying_reservation_digest),
        "admissionReceiptDigest": hex::encode(reservation.admission_receipt_digest),
        "limitProofDigest": hex::encode(reservation.limit_proof_digest),
        "zkpiDigest": hex::encode(reservation.zkpi_digest),
        "expiresAt": reservation.expires_at,
        "expectedMandateSequence": reservation.expected_mandate_sequence,
    })
}

fn mandate_reservation_transition_json(transition: &MandateReservationTransition) -> Value {
    json!({
        "operationID": hex::encode(transition.operation_id),
        "reservationID": hex::encode(transition.reservation_id),
        "expectedMandateSequence": transition.expected_mandate_sequence,
        "kind": transition.kind,
        "settlementDigest": hex::encode(transition.settlement_digest),
        "transitionProofDigest": hex::encode(transition.transition_proof_digest),
    })
}

fn asset_json(asset: &AssetDefinition) -> Value {
    json!({
        "assetID": hex::encode(asset.asset_id),
        "code": asset.code,
        "kind": asset.kind.as_str(),
        "decimals": asset.decimals,
        "termsDigest": hex::encode(asset.terms_digest),
    })
}

fn csd_issuer_json(issuer: &CsdIssuerDefinition) -> Value {
    json!({
        "issuerID": hex::encode(issuer.issuer_id),
        "code": issuer.code,
        "jurisdiction": issuer.jurisdiction,
        "operatorEntityCommitment": hex::encode(issuer.operator_entity_commitment),
        "publicKey": hex::encode(issuer.public_key),
        "permittedAssetIDs": issuer.permitted_asset_ids.iter().map(hex::encode).collect::<Vec<_>>(),
        "policyDigest": hex::encode(issuer.policy_digest),
        "validFrom": issuer.valid_from,
        "validUntil": issuer.valid_until,
    })
}

fn csd_issuer_control_json(control: &CsdIssuerControl) -> Value {
    json!({
        "operationID": hex::encode(control.operation_id),
        "issuerID": hex::encode(control.issuer_id),
        "kind": control.kind.as_str(),
        "beforeSequence": control.before_sequence,
        "reasonDigest": hex::encode(control.reason_digest),
    })
}

fn opening_json(opening: &AccountOpening) -> Value {
    json!({
        "handle": hex::encode(opening.handle),
        "assetID": hex::encode(opening.asset_id),
        "commitment": hex::encode(opening.commitment),
        "issuanceNonce": hex::encode(opening.issuance_nonce),
    })
}

fn guarantor_json(guarantor: &GuarantorDefinition) -> Value {
    json!({
        "guarantorID": hex::encode(guarantor.guarantor_id),
        "kind": guarantor.kind.as_str(),
        "name": guarantor.name,
        "publicKey": hex::encode(guarantor.public_key),
        "riskPolicyDigest": hex::encode(guarantor.risk_policy_digest),
    })
}

fn credit_grant_json(grant: &CreditFacilityGrant) -> Value {
    json!({
        "operationID": hex::encode(grant.operation_id),
        "facilityID": hex::encode(grant.facility_id),
        "guarantorID": hex::encode(grant.guarantor_id),
        "beneficiaryCommitment": hex::encode(grant.beneficiary_commitment),
        "railAssetID": hex::encode(grant.rail_asset_id),
        "capCommitment": hex::encode(grant.cap_commitment),
        "availableCommitment": hex::encode(grant.available_commitment),
        "heldCommitment": hex::encode(grant.held_commitment),
        "outstandingCommitment": hex::encode(grant.outstanding_commitment),
        "collateralCommitment": hex::encode(grant.collateral_commitment),
        "riskPolicyDigest": hex::encode(grant.risk_policy_digest),
        "relationProofDigest": hex::encode(grant.relation_proof_digest),
        "validFrom": grant.valid_from,
        "validUntil": grant.valid_until,
        "nonce": hex::encode(grant.nonce),
        "guarantorSignature": hex::encode(grant.guarantor_signature.to_bytes()),
    })
}

fn credit_transition_json(transition: &CreditFacilityTransition) -> Value {
    json!({
        "operationID": hex::encode(transition.operation_id),
        "facilityID": hex::encode(transition.facility_id),
        "holdID": hex::encode(transition.hold_id),
        "kind": transition.kind.as_str(),
        "queryCommitment": hex::encode(transition.query_commitment),
        "amountCommitment": hex::encode(transition.amount_commitment),
        "consumedCommitment": hex::encode(transition.consumed_commitment),
        "refundCommitment": hex::encode(transition.refund_commitment),
        "beforeAvailableCommitment": hex::encode(transition.before_available_commitment),
        "afterAvailableCommitment": hex::encode(transition.after_available_commitment),
        "beforeHeldCommitment": hex::encode(transition.before_held_commitment),
        "afterHeldCommitment": hex::encode(transition.after_held_commitment),
        "beforeOutstandingCommitment": hex::encode(transition.before_outstanding_commitment),
        "afterOutstandingCommitment": hex::encode(transition.after_outstanding_commitment),
        "beforeSequence": transition.before_sequence,
        "expiresAt": transition.expires_at,
        "settlementDigest": hex::encode(transition.settlement_digest),
        "relationProofDigest": hex::encode(transition.relation_proof_digest),
    })
}

fn credit_control_json(control: &CreditFacilityControl) -> Value {
    json!({
        "operationID": hex::encode(control.operation_id),
        "facilityID": hex::encode(control.facility_id),
        "action": control.action.as_str(),
        "beforeSequence": control.before_sequence,
        "effectiveAt": control.effective_at,
        "reasonDigest": hex::encode(control.reason_digest),
        "guarantorSignature": hex::encode(control.guarantor_signature.to_bytes()),
    })
}

fn credit_amendment_json(amendment: &CreditFacilityAmendment) -> Value {
    json!({
        "operationID": hex::encode(amendment.operation_id),
        "facilityID": hex::encode(amendment.facility_id),
        "mode": amendment.mode.as_str(),
        "beforeCapCommitment": hex::encode(amendment.before_cap_commitment),
        "afterCapCommitment": hex::encode(amendment.after_cap_commitment),
        "beforeAvailableCommitment": hex::encode(amendment.before_available_commitment),
        "afterAvailableCommitment": hex::encode(amendment.after_available_commitment),
        "beforeHeldCommitment": hex::encode(amendment.before_held_commitment),
        "beforeOutstandingCommitment": hex::encode(amendment.before_outstanding_commitment),
        "beforeOverlimitCommitment": hex::encode(amendment.before_overlimit_commitment),
        "afterOverlimitCommitment": hex::encode(amendment.after_overlimit_commitment),
        "beforeCollateralCommitment": hex::encode(amendment.before_collateral_commitment),
        "afterCollateralCommitment": hex::encode(amendment.after_collateral_commitment),
        "beforeRiskPolicyDigest": hex::encode(amendment.before_risk_policy_digest),
        "afterRiskPolicyDigest": hex::encode(amendment.after_risk_policy_digest),
        "beforeValidUntil": amendment.before_valid_until,
        "afterValidUntil": amendment.after_valid_until,
        "beforeSequence": amendment.before_sequence,
        "effectiveAt": amendment.effective_at,
        "reasonDigest": hex::encode(amendment.reason_digest),
        "relationProofDigest": hex::encode(amendment.relation_proof_digest),
        "guarantorSignature": hex::encode(amendment.guarantor_signature.to_bytes()),
    })
}

fn order_json(order: &SettlementOrder) -> Value {
    json!({
        "operationID": hex::encode(order.operation_id),
        "nullifier": hex::encode(order.nullifier),
        "deadline": order.deadline,
        "paymentInstructionDigest": hex::encode(order.payment_instruction_digest),
        "proofDigest": hex::encode(order.proof_digest),
        "marketStatementDigest": hex::encode(order.market_statement_digest),
        "legs": order.legs.iter().map(|leg| json!({
            "handle": hex::encode(leg.handle),
            "assetID": hex::encode(leg.asset_id),
            "beforeCommitment": hex::encode(leg.before_commitment),
            "afterCommitment": hex::encode(leg.after_commitment),
            "beforeSequence": leg.before_sequence,
        })).collect::<Vec<_>>(),
    })
}

fn reservation_authorization_json(authorization: &ReservationAuthorization) -> Value {
    json!({
        "role": authorization.role.as_str(),
        "entityCommitment": hex::encode(authorization.entity_commitment),
        "assetID": hex::encode(authorization.asset_id),
        "direction": authorization.direction,
        "authorizationDigest": hex::encode(authorization.authorization_digest),
        "mandateDigest": hex::encode(authorization.mandate_digest),
        "typedReserveDigest": hex::encode(authorization.typed_reserve_digest),
        "reserveNullifier": hex::encode(authorization.reserve_nullifier),
        "assetLinkProofDigest": hex::encode(authorization.asset_link_proof_digest),
        "limitPriceCommitment": hex::encode(authorization.limit_price_commitment),
        "escrowDigest": hex::encode(authorization.escrow_digest),
        "rfqNullifier": hex::encode(authorization.rfq_nullifier),
        "policyVersion": authorization.policy_version,
        "admissionTicketID": hex::encode(authorization.admission_ticket_id),
        "admissionSlot": authorization.admission_slot,
        "admissionReceiptDigest": hex::encode(authorization.admission_receipt_digest),
        "admissionEpoch": authorization.admission_epoch,
        "admissionSequence": authorization.admission_sequence,
        "admissionBatchID": hex::encode(authorization.admission_batch_id),
    })
}

fn admission_batch_json(plan: &AdmissionBatchPlan) -> Value {
    let mut value = json!({
        "operationID": hex::encode(plan.operation_id),
        "batchID": hex::encode(plan.batch_id),
        "venueID": hex::encode(plan.venue_id),
        "epoch": plan.epoch,
        "slot": plan.slot,
        "batchDigest": hex::encode(plan.batch_digest),
        "orderDigest": hex::encode(plan.order_digest),
        "admissionDigests": plan.admission_digests.iter().map(hex::encode).collect::<Vec<_>>(),
        "expiresAt": plan.expires_at,
    });
    if plan.first_sequence != 1 {
        value
            .as_object_mut()
            .expect("admission batch wire value is an object")
            .insert("firstSequence".into(), json!(plan.first_sequence));
    }
    value
}

fn admission_committee_json(plan: &AdmissionCommitteePlan) -> Value {
    json!({
        "operationID": hex::encode(plan.operation_id),
        "venueID": hex::encode(plan.venue_id),
        "epoch": plan.epoch,
        "nodeKeys": plan.node_keys.iter().map(hex::encode).collect::<Vec<_>>(),
        "validFrom": plan.valid_from,
        "validUntil": plan.valid_until,
    })
}

fn settlement_verifier_json(config: &SettlementVerifierConfig) -> Value {
    json!({
        "venueID": hex::encode(config.venue_id),
        "defmiID": hex::encode(config.defmi_id),
        "epoch": config.epoch,
        "quoteRegistryDigest": hex::encode(config.quote_registry_digest),
        "quoteEligibilityBits": config.quote_eligibility_bits,
        "quoteSpanBits": config.quote_span_bits,
        "amountBits": config.amount_bits,
        "priceBits": config.price_bits,
        "maxHorizon": config.max_horizon,
        "frostPublicPackage": BASE64.encode(&config.frost_public_package),
        "validFrom": config.valid_from,
        "validUntil": config.valid_until,
    })
}

fn admission_attestation_json(value: &NodeAdmissionAttestation) -> Value {
    json!({
        "node": value.node,
        "slot": value.slot,
        "sequence": value.sequence,
        "principalDigest": hex::encode(value.principal_digest),
        "ticketID": hex::encode(value.ticket_id),
        "claimDigest": hex::encode(value.claim_digest),
        "batchDigest": hex::encode(value.batch_digest),
        "orderDigest": hex::encode(value.order_digest),
        "signature": hex::encode(value.signature.to_bytes()),
    })
}

fn admission_lanes_json(values: &[Vec<NodeAdmissionAttestation>]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|lane| Value::Array(lane.iter().map(admission_attestation_json).collect()))
            .collect(),
    )
}

fn admission_advance_json(advance: &AdmissionSlotAdvance) -> Value {
    json!({
        "operationID": hex::encode(advance.operation_id),
        "batchID": hex::encode(advance.batch_id),
        "sequence": advance.sequence,
        "admissionDigest": hex::encode(advance.admission_digest),
    })
}

fn reservation_escrow_json(escrow: &ReservationEscrow) -> Value {
    json!({
        "sourceHandle": hex::encode(escrow.source_handle),
        "escrowHandle": hex::encode(escrow.escrow_handle),
        "assetID": hex::encode(escrow.asset_id),
        "amountCommitment": hex::encode(escrow.amount_commitment),
        "sourceBeforeCommitment": hex::encode(escrow.source_before_commitment),
        "sourceAfterCommitment": hex::encode(escrow.source_after_commitment),
        "sourceBeforeSequence": escrow.source_before_sequence,
        "proofDigest": hex::encode(escrow.proof_digest),
    })
}

fn product_release_json(order: &ProductReleaseOrder) -> Value {
    json!({
        "transition": credit_transition_json(&order.transition),
        "role": order.role.as_str(),
        "reserveReceiptDigest": hex::encode(order.reserve_receipt_digest),
        "typedInstructionDigest": hex::encode(order.typed_instruction_digest),
        "releaseNullifier": hex::encode(order.release_nullifier),
        "releaseDeadline": order.release_deadline,
        "assetID": hex::encode(order.asset_id),
        "assetLinkProofDigest": hex::encode(order.asset_link_proof_digest),
        "refundLeg": {
            "handle": hex::encode(order.refund_leg.handle),
            "assetID": hex::encode(order.refund_leg.asset_id),
            "beforeCommitment": hex::encode(order.refund_leg.before_commitment),
            "afterCommitment": hex::encode(order.refund_leg.after_commitment),
            "beforeSequence": order.refund_leg.before_sequence,
        },
    })
}

fn product_order_json(order: &ProductSettlementOrder) -> Value {
    json!({
        "settlement": order_json(&order.settlement),
        "venueID": hex::encode(order.venue_id),
        "defmiID": hex::encode(order.defmi_id),
        "makerEntityCommitment": hex::encode(order.maker_entity_commitment),
        "takerEntityCommitment": hex::encode(order.taker_entity_commitment),
        "rfqNullifier": hex::encode(order.rfq_nullifier),
        "takerAuthorizationDigest": hex::encode(order.taker_authorization_digest),
        "makerPolicyDigest": hex::encode(order.maker_policy_digest),
        "makerMandateDigest": hex::encode(order.maker_mandate_digest),
        "takerMandateDigest": hex::encode(order.taker_mandate_digest),
        "typedInstructionDigest": hex::encode(order.typed_instruction_digest),
        "quoteProofDigest": hex::encode(order.quote_proof_digest),
        "priceLimitProofDigest": hex::encode(order.price_limit_proof_digest),
        "dvpProofDigest": hex::encode(order.dvp_proof_digest),
        "quantityCommitment": hex::encode(order.quantity_commitment),
        "cashCommitment": hex::encode(order.cash_commitment),
        "tradedAssetID": hex::encode(order.traded_asset_id),
        "assetLinkProofDigest": hex::encode(order.asset_link_proof_digest),
        "admissionReceiptDigest": hex::encode(order.admission_receipt_digest),
        "admissionEpoch": order.admission_epoch,
        "admissionSequence": order.admission_sequence,
        "reservations": order.reservations.iter().map(|reservation| json!({
            "role": reservation.role.as_str(),
            "reserveReceiptDigest": hex::encode(reservation.reserve_receipt_digest),
            "transition": credit_transition_json(&reservation.transition),
        })).collect::<Vec<_>>(),
    })
}

fn product_batch_json(batch: &ProductSettlementBatch) -> Value {
    json!({
        "batchID": hex::encode(batch.batch_id),
        "venueID": hex::encode(batch.venue_id),
        "defmiID": hex::encode(batch.defmi_id),
        "admissionEpoch": batch.admission_epoch,
        "members": batch.members.iter().map(|member| json!({
            "admissionSequence": member.admission_sequence,
            "settlementStatement": hex::encode(member.settlement_statement),
        })).collect::<Vec<_>>(),
    })
}

fn note_output_json(output: &NoteOutput) -> Value {
    json!({
        "noteID": hex::encode(output.note_id),
        "assetID": hex::encode(output.asset_id),
        "oneTime": hex::encode(output.one_time),
        "valueCommitment": hex::encode(output.value_commitment),
        "ephemeral": hex::encode(output.ephemeral),
        "maskedValue": hex::encode(output.masked_value),
        "maskedBlinding": hex::encode(output.masked_blinding),
        "lockID": hex::encode(output.lock_id),
    })
}

fn note_spend_json(spend: &NoteSpend) -> Value {
    json!({
        "assetID": hex::encode(spend.asset_id),
        "ring": spend.ring.iter().map(hex::encode).collect::<Vec<_>>(),
        "ringRoot": hex::encode(spend.ring_root),
        "serialPoint": hex::encode(spend.serial_point),
        "inputLockID": hex::encode(spend.input_lock_id),
        "proofDigest": hex::encode(spend.proof_digest),
        "outputs": spend.outputs.iter().map(note_output_json).collect::<Vec<_>>(),
    })
}

fn note_issuance_json(issuance: &NoteIssuance) -> Value {
    json!({
        "operationID": hex::encode(issuance.operation_id),
        "issuanceNonce": hex::encode(issuance.issuance_nonce),
        "issuerID": hex::encode(issuance.issuer_id),
        "issuedAt": issuance.issued_at,
        "output": note_output_json(&issuance.output),
        "proofDigest": hex::encode(issuance.proof_digest),
        "issuerSignature": hex::encode(issuance.issuer_signature.to_bytes()),
    })
}

fn note_order_json(order: &NoteSettlementOrder) -> Value {
    let mut value = json!({
        "operationID": hex::encode(order.operation_id),
        "nullifier": hex::encode(order.nullifier),
        "deadline": order.deadline,
        "paymentInstructionDigest": hex::encode(order.payment_instruction_digest),
        "marketStatementDigest": hex::encode(order.market_statement_digest),
        "dvpProofDigest": hex::encode(order.dvp_proof_digest),
        "spends": order.spends.iter().map(note_spend_json).collect::<Vec<_>>(),
    });
    if let Some(output) = &order.consolidated_output {
        value
            .as_object_mut()
            .expect("note settlement wire value is an object")
            .insert("consolidatedOutput".into(), note_output_json(output));
    }
    value
}

fn note_claim_json(claim: &NoteClaim) -> Value {
    json!({
        "claimID": hex::encode(claim.claim_id),
        "assetID": hex::encode(claim.asset_id),
        "valueCommitment": hex::encode(claim.value_commitment),
        "recipientCommitment": hex::encode(claim.recipient_commitment),
        "sourceHoldID": hex::encode(claim.source_hold_id),
        "kind": claim.kind.as_str(),
        "openingEnvelope": {
            "context": hex::encode(claim.opening_envelope.context),
            "threshold": claim.opening_envelope.threshold,
            "recipientView": hex::encode(claim.opening_envelope.recipient_view.compress().to_bytes()),
            "shares": claim.opening_envelope.shares.iter().map(|share| json!({
                "party": share.party,
                "ephemeral": hex::encode(share.ephemeral.compress().to_bytes()),
                "maskedValue": hex::encode(share.masked_value.to_bytes()),
                "maskedBlinding": hex::encode(share.masked_blinding.to_bytes()),
            })).collect::<Vec<_>>(),
        },
    })
}

fn escrow_claim_spend_json(spend: &EscrowClaimSpend) -> Value {
    json!({
        "assetID": hex::encode(spend.asset_id),
        "holdID": hex::encode(spend.hold_id),
        "escrowNoteID": hex::encode(spend.escrow_note_id),
        "delegationDigest": hex::encode(spend.delegation_digest),
        "proofDigest": hex::encode(spend.proof_digest),
        "claims": spend.claims.iter().map(note_claim_json).collect::<Vec<_>>(),
    })
}

fn delegated_note_order_json(order: &DelegatedNoteSettlementOrder) -> Value {
    json!({
        "operationID": hex::encode(order.operation_id),
        "nullifier": hex::encode(order.nullifier),
        "deadline": order.deadline,
        "paymentInstructionDigest": hex::encode(order.payment_instruction_digest),
        "marketStatementDigest": hex::encode(order.market_statement_digest),
        "dvpProofDigest": hex::encode(order.dvp_proof_digest),
        "spends": order.spends.iter().map(escrow_claim_spend_json).collect::<Vec<_>>(),
    })
}

fn note_claim_materialization_json(value: &NoteClaimMaterialization) -> Value {
    json!({
        "operationID": hex::encode(value.operation_id),
        "claimID": hex::encode(value.claim_id),
        "output": note_output_json(&value.output),
        "ownershipProofDigest": hex::encode(value.ownership_proof_digest),
    })
}

fn note_reservation_escrow_json(escrow: &NoteReservationEscrow) -> Value {
    json!({
        "spend": note_spend_json(&escrow.spend),
        "escrowNoteID": hex::encode(escrow.escrow_note_id),
        "delegationDigest": hex::encode(escrow.delegation_digest),
    })
}

fn standing_note_pool_registration_json(registration: &StandingNotePoolRegistration) -> Value {
    json!({
        "operationID": hex::encode(registration.operation_id),
        "poolID": hex::encode(registration.pool_id),
        "venueID": hex::encode(registration.venue_id),
        "defmiID": hex::encode(registration.defmi_id),
        "entityCommitment": hex::encode(registration.entity_commitment),
        "policyDigest": hex::encode(registration.policy_digest),
        "mandateDigest": hex::encode(registration.mandate_digest),
        "assetID": hex::encode(registration.asset_id),
        "direction": registration.direction,
        "maximumAmountCommitment": hex::encode(registration.maximum_amount_commitment),
        "poolNoteID": hex::encode(registration.pool_note_id),
        "delegationDigest": hex::encode(registration.delegation_digest),
        "committeeEpoch": registration.committee_epoch,
        "validUntil": registration.valid_until,
        "spend": note_spend_json(&registration.spend),
    })
}

fn standing_note_pool_allocation_json(allocation: &StandingNotePoolAllocation) -> Value {
    json!({
        "poolID": hex::encode(allocation.pool_id),
        "delegationDigest": hex::encode(allocation.delegation_digest),
        "committeeEpoch": allocation.committee_epoch,
        "expectedPoolSequence": allocation.expected_pool_sequence,
        "previousPoolNoteID": hex::encode(allocation.previous_pool_note_id),
        "previousAmountCommitment": hex::encode(allocation.previous_amount_commitment),
        "escrowNote": note_output_json(&allocation.escrow_note),
        "remainderNote": note_output_json(&allocation.remainder_note),
        "proofJobID": hex::encode(allocation.proof_job_id),
        "quoteProofDigest": hex::encode(allocation.quote_proof_digest),
        "dvpProofDigest": hex::encode(allocation.dvp_proof_digest),
        "remainderRangeProofDigest": hex::encode(allocation.remainder_range_proof_digest),
        "committeeSignature": hex::encode(&allocation.committee_signature),
    })
}

fn note_product_release_json(order: &ProductNoteReleaseOrder) -> Value {
    json!({
        "transition": credit_transition_json(&order.transition),
        "role": order.role.as_str(),
        "reserveReceiptDigest": hex::encode(order.reserve_receipt_digest),
        "typedInstructionDigest": hex::encode(order.typed_instruction_digest),
        "releaseNullifier": hex::encode(order.release_nullifier),
        "releaseDeadline": order.release_deadline,
        "assetID": hex::encode(order.asset_id),
        "assetLinkProofDigest": hex::encode(order.asset_link_proof_digest),
        "escrowNoteID": hex::encode(order.escrow_note_id),
        "spend": note_spend_json(&order.spend),
    })
}

fn note_product_no_fill_release_json(order: &ProductNoteNoFillReleaseOrder) -> Value {
    json!({
        "release": note_product_release_json(&order.release),
        "venueID": hex::encode(order.venue_id),
        "defmiID": hex::encode(order.defmi_id),
        "admissionEpoch": order.admission_epoch,
        "admissionSequence": order.admission_sequence,
        "noFillEvidenceDigest": hex::encode(order.no_fill_evidence_digest),
    })
}

fn no_fill_evidence_json(evidence: &MpcNoFillEvidence) -> Value {
    json!({
        "signedTakerMandate": BASE64.encode(&evidence.signed_taker_mandate),
        "publicResultAttestations": BASE64.encode(&evidence.public_result_attestations),
        "fillMask": evidence.fill_mask,
    })
}

fn note_product_order_json(order: &ProductNoteSettlementOrder) -> Value {
    json!({
        "settlement": delegated_note_order_json(&order.settlement),
        "venueID": hex::encode(order.venue_id),
        "defmiID": hex::encode(order.defmi_id),
        "makerEntityCommitment": hex::encode(order.maker_entity_commitment),
        "takerEntityCommitment": hex::encode(order.taker_entity_commitment),
        "rfqNullifier": hex::encode(order.rfq_nullifier),
        "takerAuthorizationDigest": hex::encode(order.taker_authorization_digest),
        "makerPolicyDigest": hex::encode(order.maker_policy_digest),
        "makerMandateDigest": hex::encode(order.maker_mandate_digest),
        "takerMandateDigest": hex::encode(order.taker_mandate_digest),
        "typedInstructionDigest": hex::encode(order.typed_instruction_digest),
        "quoteProofDigest": hex::encode(order.quote_proof_digest),
        "priceLimitProofDigest": hex::encode(order.price_limit_proof_digest),
        "dvpProofDigest": hex::encode(order.dvp_proof_digest),
        "quantityCommitment": hex::encode(order.quantity_commitment),
        "cashCommitment": hex::encode(order.cash_commitment),
        "tradedAssetID": hex::encode(order.traded_asset_id),
        "assetLinkProofDigest": hex::encode(order.asset_link_proof_digest),
        "admissionReceiptDigest": hex::encode(order.admission_receipt_digest),
        "admissionEpoch": order.admission_epoch,
        "admissionSequence": order.admission_sequence,
        "reservations": order.reservations.iter().map(|reservation| json!({
            "role": reservation.role.as_str(),
            "reserveReceiptDigest": hex::encode(reservation.reserve_receipt_digest),
            "transition": credit_transition_json(&reservation.transition),
        })).collect::<Vec<_>>(),
    })
}

fn note_product_batch_json(batch: &ProductNoteSettlementBatch) -> Value {
    json!({
        "batchID": hex::encode(batch.batch_id),
        "venueID": hex::encode(batch.venue_id),
        "defmiID": hex::encode(batch.defmi_id),
        "admissionEpoch": batch.admission_epoch,
        "members": batch.members.iter().map(|member| json!({
            "admissionSequence": member.admission_sequence,
            "settlementStatement": hex::encode(member.settlement_statement),
        })).collect::<Vec<_>>(),
    })
}

fn product_settlement_evidence_json(evidence: &ProductSettlementEvidence) -> Result<Value, String> {
    evidence.validate_encoding()?;
    Ok(json!({
        "typedInstruction": BASE64.encode(&evidence.typed_instruction),
        "quoteVerification": BASE64.encode(&evidence.quote_verification),
        "priceLimitProof": BASE64.encode(&evidence.price_limit_proof),
        "dvpProofs": BASE64.encode(&evidence.dvp_proofs),
        "mpcExecutionAttestations": BASE64.encode(&evidence.mpc_execution_attestations),
        "assetLink": {
            "announcement": hex::encode(evidence.asset_link.announcement.compress().to_bytes()),
            "response": hex::encode(evidence.asset_link.response.to_bytes()),
        },
    }))
}

#[derive(Clone, Debug)]
struct Endpoint {
    tls: bool,
    host: String,
    port: u16,
    path: String,
    authority: String,
}

fn parse_endpoint(endpoint: &str, allow_insecure_localhost: bool) -> Result<Endpoint, String> {
    let (tls, rest) = if let Some(rest) = endpoint.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = endpoint.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err("Avalanche endpoint must be an absolute HTTP(S) URL".into());
    };
    let (authority, path) = rest
        .split_once('/')
        .map_or((rest, "/".to_string()), |(authority, path)| {
            (authority, format!("/{path}"))
        });
    if authority.is_empty() || authority.contains('@') {
        return Err("Avalanche endpoint must be an absolute HTTP(S) URL".into());
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, suffix) = bracketed
            .split_once(']')
            .ok_or_else(|| "Avalanche endpoint has an invalid IPv6 host".to_string())?;
        let port = suffix
            .strip_prefix(':')
            .map(|port| port.parse::<u16>())
            .transpose()
            .map_err(|_| "Avalanche endpoint has an invalid port".to_string())?
            .unwrap_or(if tls { 443 } else { 80 });
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (
                host.to_string(),
                port.parse::<u16>()
                    .map_err(|_| "Avalanche endpoint has an invalid port".to_string())?,
            ),
            _ => (authority.to_string(), if tls { 443 } else { 80 }),
        }
    };
    if host.is_empty() {
        return Err("Avalanche endpoint must be an absolute HTTP(S) URL".into());
    }
    let loopback = matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1");
    if !tls && !(allow_insecure_localhost && loopback) {
        return Err(
            "plaintext Avalanche RPC is allowed only for an explicit localhost test".into(),
        );
    }
    Ok(Endpoint {
        tls,
        host,
        port,
        path,
        authority: authority.to_string(),
    })
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn decode_chunked(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| "Avalanche RPC returned malformed chunked HTTP".to_string())?;
        let length = std::str::from_utf8(&body[..line_end])
            .ok()
            .and_then(|line| line.split(';').next())
            .and_then(|length| usize::from_str_radix(length.trim(), 16).ok())
            .ok_or_else(|| "Avalanche RPC returned malformed chunked HTTP".to_string())?;
        body = &body[line_end + 2..];
        if length == 0 {
            return Ok(decoded);
        }
        if body.len() < length + 2 || &body[length..length + 2] != b"\r\n" {
            return Err("Avalanche RPC returned malformed chunked HTTP".into());
        }
        decoded.extend_from_slice(&body[..length]);
        if decoded.len() > MAX_RESPONSE {
            return Err("Avalanche RPC response exceeded one MiB".into());
        }
        body = &body[length + 2..];
    }
}

fn http_post(endpoint: &Endpoint, body: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let tcp = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .map_err(|error| format!("Avalanche RPC transport failed: {error}"))?;
    tcp.set_read_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    tcp.set_write_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    let mut stream: Box<dyn ReadWrite> = if endpoint.tls {
        let mut builder =
            SslConnector::builder(SslMethod::tls_client()).map_err(|error| error.to_string())?;
        builder.set_verify(SslVerifyMode::PEER);
        builder
            .set_default_verify_paths()
            .map_err(|error| error.to_string())?;
        Box::new(
            builder
                .build()
                .connect(&endpoint.host, tcp)
                .map_err(|error| format!("Avalanche RPC TLS authentication failed: {error}"))?,
        )
    } else {
        Box::new(tcp)
    };
    write!(
        stream,
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        endpoint.path,
        endpoint.authority,
        body.len()
    )
    .map_err(|error| format!("Avalanche RPC transport failed: {error}"))?;
    stream
        .write_all(body)
        .map_err(|error| format!("Avalanche RPC transport failed: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("Avalanche RPC transport failed: {error}"))?;
    let mut raw = Vec::new();
    stream
        .take((MAX_RESPONSE + 65_536 + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|error| format!("Avalanche RPC transport failed: {error}"))?;
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "Avalanche RPC returned malformed HTTP".to_string())?;
    let headers = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| "Avalanche RPC returned malformed HTTP headers".to_string())?;
    let mut lines = headers.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| "Avalanche RPC returned malformed HTTP status".to_string())?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "Avalanche RPC HTTP endpoint returned status {status}"
        ));
    }
    let chunked = lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        })
    });
    let body = &raw[header_end + 4..];
    let body = if chunked {
        decode_chunked(body)?
    } else {
        body.to_vec()
    };
    if body.len() > MAX_RESPONSE {
        return Err("Avalanche RPC response exceeded one MiB".into());
    }
    Ok(body)
}

type Transport = dyn Fn(&[u8], Duration) -> Result<Vec<u8>, String> + Send + Sync;

pub struct AvalancheRpcClient {
    timeout: Duration,
    next_id: AtomicU64,
    transport: Arc<Transport>,
}

/// Opt-in audit journal of every state-changing transition this process
/// issues to the L1.  When `QOMM_DEFMI_JOURNAL_DIR` names a directory, each
/// `defmivm.issue*` request is written there verbatim (method and params) as
/// `<unix-ms>-<counter>-<method>.json` before it is sent.  Everything in it
/// is what the chain receives, so nothing here is secret; the record lets an
/// operator or an acceptance run re-present a transition to the L1 and show
/// it refuses a second application (the compare-and-swap on the pool note,
/// the hold, and the admission cursor are only observable that way from
/// outside the process that issued them).
fn journal_issued_transition(method: &str, params: &Value) {
    if !method.starts_with("defmivm.issue") {
        return;
    }
    let Ok(directory) = std::env::var("QOMM_DEFMI_JOURNAL_DIR") else {
        return;
    };
    if directory.is_empty() {
        return;
    }
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0);
    let path =
        std::path::Path::new(&directory).join(format!("{millis:013}-{counter:06}-{method}.json"));
    let record = json!({"method": method, "params": params});
    if std::fs::create_dir_all(&directory).is_err()
        || std::fs::write(
            &path,
            serde_json::to_vec_pretty(&record).unwrap_or_default(),
        )
        .is_err()
    {
        eprintln!("qomm-defmi: could not journal {method} under {directory}");
    }
}

impl AvalancheRpcClient {
    pub fn new(
        endpoint: &str,
        timeout: Duration,
        allow_insecure_localhost: bool,
    ) -> Result<Self, String> {
        if timeout.is_zero() {
            return Err("RPC timeout must be positive".into());
        }
        let endpoint = parse_endpoint(endpoint, allow_insecure_localhost)?;
        Ok(Self {
            timeout,
            next_id: AtomicU64::new(1),
            transport: Arc::new(move |body, timeout| http_post(&endpoint, body, timeout)),
        })
    }

    pub fn with_transport<F>(
        endpoint: &str,
        timeout: Duration,
        allow_insecure_localhost: bool,
        transport: F,
    ) -> Result<Self, String>
    where
        F: Fn(&[u8], Duration) -> Result<Vec<u8>, String> + Send + Sync + 'static,
    {
        parse_endpoint(endpoint, allow_insecure_localhost)?;
        if timeout.is_zero() {
            return Err("RPC timeout must be positive".into());
        }
        Ok(Self {
            timeout,
            next_id: AtomicU64::new(1),
            transport: Arc::new(transport),
        })
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let request_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }))
        .map_err(|error| error.to_string())?;
        journal_issued_transition(method, &params);
        let raw = (self.transport)(&body, self.timeout)?;
        if raw.len() > MAX_RESPONSE {
            return Err("Avalanche RPC response exceeded one MiB".into());
        }
        let envelope: Value = serde_json::from_slice(&raw)
            .map_err(|_| "Avalanche RPC returned invalid JSON".to_string())?;
        if envelope.get("id").and_then(Value::as_u64) != Some(request_id) {
            return Err("Avalanche RPC response identifier does not match".into());
        }
        if let Some(error) = envelope.get("error").filter(|value| !value.is_null()) {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Err(format!("Avalanche RPC rejected the request: {message}"));
        }
        envelope
            .get("result")
            .cloned()
            .ok_or_else(|| "Avalanche RPC response has no result".to_string())
    }

    fn transaction_id(result: &Value) -> Result<String, String> {
        result
            .get("txID")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "L1 did not return a transaction identifier".to_string())
    }

    pub fn participant_registry_snapshot(&self) -> Result<Value, String> {
        self.call("defmivm.participantRegistry", json!({}))
    }

    pub fn participant_snapshot(&self, participant_id: [u8; 32]) -> Result<Value, String> {
        self.call(
            "defmivm.participant",
            json!({"participantID": hex::encode(participant_id)}),
        )
    }

    pub fn mpc_service_snapshot(&self, service_id: [u8; 32]) -> Result<Value, String> {
        self.call(
            "defmivm.mpcService",
            json!({"serviceID": hex::encode(service_id)}),
        )
    }

    pub fn participant_account_binding_snapshot(
        &self,
        binding_id: [u8; 32],
    ) -> Result<Value, String> {
        self.call(
            "defmivm.participantAccountBinding",
            json!({"bindingID": hex::encode(binding_id)}),
        )
    }

    pub fn participant_service_binding_snapshot(
        &self,
        binding_id: [u8; 32],
    ) -> Result<Value, String> {
        self.call(
            "defmivm.participantServiceBinding",
            json!({"bindingID": hex::encode(binding_id)}),
        )
    }

    pub fn standing_mandate_snapshot(&self, mandate_id: [u8; 32]) -> Result<Value, String> {
        self.call(
            "defmivm.standingMandate",
            json!({"mandateID": hex::encode(mandate_id)}),
        )
    }

    pub fn mandate_reservation_snapshot(&self, reservation_id: [u8; 32]) -> Result<Value, String> {
        self.call(
            "defmivm.mandateReservation",
            json!({"reservationID": hex::encode(reservation_id)}),
        )
    }

    pub fn issue_participant_registry(
        &self,
        configuration: &RegistryConfiguration,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueParticipantRegistry",
            json!({
                "configuration": registry_configuration_json(configuration),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    pub fn issue_participant(
        &self,
        registration: &RegisterParticipant,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueParticipant",
            json!({
                "registration": register_participant_json(registration),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    pub fn issue_participant_control(
        &self,
        control: &ParticipantControl,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueParticipantControl",
            json!({
                "control": participant_control_json(control),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    pub fn issue_participant_key_rotation(
        &self,
        rotation: &RotateParticipantKey,
        entity_approval: &EntityApproval,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueParticipantKeyRotation",
            json!({
                "rotation": participant_key_rotation_json(rotation),
                "entityApproval": entity_approval_json(entity_approval),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    pub fn issue_mpc_service(
        &self,
        service: &MpcService,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueMpcService",
            json!({
                "service": mpc_service_json(service),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    pub fn issue_participant_account_binding(
        &self,
        binding: &AccountBinding,
        entity_approval: &EntityApproval,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueParticipantAccountBinding",
            json!({
                "binding": account_binding_json(binding),
                "entityApproval": entity_approval_json(entity_approval),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    pub fn issue_participant_service_binding(
        &self,
        binding: &ParticipantServiceBinding,
        entity_approval: &EntityApproval,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueParticipantServiceBinding",
            json!({
                "binding": participant_service_binding_json(binding),
                "entityApproval": entity_approval_json(entity_approval),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    pub fn issue_standing_mandate(
        &self,
        mandate: &StandingMandate,
        entity_approval: &EntityApproval,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueStandingMandate",
            json!({
                "mandate": standing_mandate_json(mandate),
                "entityApproval": entity_approval_json(entity_approval),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    pub fn issue_standing_mandate_control(
        &self,
        control: &MandateControl,
        entity_approval: &EntityApproval,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueStandingMandateControl",
            json!({
                "control": mandate_control_json(control),
                "entityApproval": entity_approval_json(entity_approval),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    pub fn issue_mandate_reservation(
        &self,
        reservation: &MandateReservation,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueMandateReservation",
            json!({
                "reservation": mandate_reservation_json(reservation),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    pub fn issue_mandate_reservation_transition(
        &self,
        transition: &MandateReservationTransition,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueMandateReservationTransition",
            json!({
                "transition": mandate_reservation_transition_json(transition),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_participant_product_reservation(
        &self,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
        escrow: &ReservationEscrow,
        mandate_reservation: &MandateReservation,
        underlying_approval: &QuorumApproval,
        mandate_approval: &QuorumApproval,
        expected_before_root: [u8; 32],
        expected_after_underlying_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueParticipantProductReservation",
            json!({
                "underlying": {
                    "transition": credit_transition_json(transition),
                    "authorization": reservation_authorization_json(authorization),
                    "escrow": reservation_escrow_json(escrow),
                },
                "mandateReservation": mandate_reservation_json(mandate_reservation),
                "underlyingApproval": approval_json(underlying_approval),
                "mandateApproval": approval_json(mandate_approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
                "expectedAfterUnderlyingRoot": hex::encode(expected_after_underlying_root),
            }),
        )?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_participant_note_product_reservation(
        &self,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
        escrow: &NoteReservationEscrow,
        mandate_reservation: &MandateReservation,
        underlying_approval: &QuorumApproval,
        mandate_approval: &QuorumApproval,
        expected_before_root: [u8; 32],
        expected_after_underlying_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueParticipantNoteProductReservation",
            json!({
                "underlying": {
                    "transition": credit_transition_json(transition),
                    "authorization": reservation_authorization_json(authorization),
                    "escrow": note_reservation_escrow_json(escrow),
                },
                "mandateReservation": mandate_reservation_json(mandate_reservation),
                "underlyingApproval": approval_json(underlying_approval),
                "mandateApproval": approval_json(mandate_approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
                "expectedAfterUnderlyingRoot": hex::encode(expected_after_underlying_root),
            }),
        )?)
    }
}

pub trait AvalancheClient: Send + Sync {
    fn state_root(&self) -> Result<[u8; 32], String>;
    fn asset_snapshot(&self, _asset_id: [u8; 32]) -> Result<CanonicalAsset, String> {
        Err("Avalanche client does not support canonical asset reads".into())
    }
    fn guarantor_snapshot(&self, _guarantor_id: [u8; 32]) -> Result<CanonicalGuarantor, String> {
        Err("Avalanche client does not support canonical guarantor reads".into())
    }
    fn credit_facility_snapshot(
        &self,
        _facility_id: [u8; 32],
    ) -> Result<CanonicalCreditFacility, String> {
        Err("Avalanche client does not support canonical facility reads".into())
    }
    fn csd_issuer_snapshot(&self, _issuer_id: [u8; 32]) -> Result<CanonicalCsdIssuer, String> {
        Err("Avalanche client does not support canonical CSD issuer reads".into())
    }
    fn credit_hold_snapshot(&self, _hold_id: [u8; 32]) -> Result<CanonicalCreditHold, String> {
        Err("Avalanche client does not support canonical hold reads".into())
    }
    fn note_snapshot(&self, _note_id: [u8; 32]) -> Result<CanonicalNote, String> {
        Err("Avalanche client does not support canonical note reads".into())
    }
    fn note_serial_snapshot(&self, _serial_point: [u8; 32]) -> Result<CanonicalNoteSerial, String> {
        Err("Avalanche client does not support canonical note serial reads".into())
    }
    fn note_page(
        &self,
        _asset_id: [u8; 32],
        _after: Option<[u8; 32]>,
        _limit: u32,
    ) -> Result<CanonicalNotePage, String> {
        Err("Avalanche client does not support canonical note pages".into())
    }
    fn note_reservation_snapshot(
        &self,
        _hold_id: [u8; 32],
    ) -> Result<CanonicalNoteReservation, String> {
        Err("Avalanche client does not support canonical note reservations".into())
    }
    fn standing_note_pool_snapshot(
        &self,
        _pool_id: [u8; 32],
    ) -> Result<CanonicalStandingNotePool, String> {
        Err("Avalanche client does not support canonical standing note pools".into())
    }
    fn settlement_verifier_snapshot(
        &self,
        _venue_id: [u8; 32],
        _epoch: u64,
    ) -> Result<CanonicalSettlementVerifier, String> {
        Err("Avalanche client does not support canonical settlement verifier reads".into())
    }
    fn admission_cursor(
        &self,
        _venue_id: [u8; 32],
        _epoch: u64,
    ) -> Result<CanonicalAdmissionCursor, String> {
        Err("Avalanche client does not support canonical admission cursor reads".into())
    }
    fn note_claim_snapshot(&self, _claim_id: [u8; 32]) -> Result<CanonicalNoteClaim, String> {
        Err("Avalanche client does not support canonical note claims".into())
    }
    fn note_claim_page(
        &self,
        _source_hold_id: [u8; 32],
        _after: Option<[u8; 32]>,
        _limit: u32,
    ) -> Result<CanonicalNoteClaimPage, String> {
        Err("Avalanche client does not support canonical note-claim pages".into())
    }
    fn note_claim_recipient_page(
        &self,
        _recipient_view: [u8; 32],
        _after: Option<[u8; 32]>,
        _limit: u32,
    ) -> Result<CanonicalNoteClaimPage, String> {
        Err("Avalanche client does not support recipient note-claim pages".into())
    }
    fn issue_asset(
        &self,
        asset: &AssetDefinition,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String>;
    fn issue_csd_issuer(
        &self,
        _issuer: &CsdIssuerDefinition,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support CSD issuer registration".into())
    }
    fn issue_csd_issuer_control(
        &self,
        _control: &CsdIssuerControl,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support CSD issuer controls".into())
    }
    fn issue_account(
        &self,
        opening: &AccountOpening,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String>;
    fn issue_note(
        &self,
        _issuance: &NoteIssuance,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support confidential note issuance".into())
    }
    fn issue_note_claim_materialization(
        &self,
        _materialization: &NoteClaimMaterialization,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support note-claim materialization".into())
    }
    fn issue_guarantor(
        &self,
        _guarantor: &GuarantorDefinition,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support guarantor registration".into())
    }
    fn issue_credit_grant(
        &self,
        _grant: &CreditFacilityGrant,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support credit facility grants".into())
    }
    fn issue_credit_transition(
        &self,
        _transition: &CreditFacilityTransition,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support credit facility transitions".into())
    }
    fn issue_admission_committee(
        &self,
        _plan: &AdmissionCommitteePlan,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support admission committees".into())
    }
    fn issue_settlement_verifier(
        &self,
        _config: &SettlementVerifierConfig,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support settlement verifier registration".into())
    }
    fn issue_admission_batch(
        &self,
        _plan: &AdmissionBatchPlan,
        _admission_lanes: &[Vec<NodeAdmissionAttestation>],
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support admission batches".into())
    }
    fn issue_admission_advance(
        &self,
        _advance: &AdmissionSlotAdvance,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support admission advances".into())
    }
    fn issue_product_reservation(
        &self,
        _transition: &CreditFacilityTransition,
        _authorization: &ReservationAuthorization,
        _escrow: &ReservationEscrow,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support product reservations".into())
    }

    fn issue_standing_note_pool(
        &self,
        _registration: &StandingNotePoolRegistration,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support standing note pools".into())
    }
    fn issue_standing_note_pool_allocation(
        &self,
        _transition: &CreditFacilityTransition,
        _authorization: &ReservationAuthorization,
        _allocation: &StandingNotePoolAllocation,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support standing note pool allocations".into())
    }
    fn preview_standing_note_pool_allocation(
        &self,
        _transition: &CreditFacilityTransition,
        _authorization: &ReservationAuthorization,
        _allocation: &StandingNotePoolAllocation,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<StandingNotePoolAllocationPreview, String> {
        Err("Avalanche client does not support standing note pool previews".into())
    }

    fn issue_note_product_reservation(
        &self,
        _transition: &CreditFacilityTransition,
        _authorization: &ReservationAuthorization,
        _escrow: &NoteReservationEscrow,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support anonymous product reservations".into())
    }
    fn issue_product_release(
        &self,
        _order: &ProductReleaseOrder,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support product reservation releases".into())
    }

    fn issue_note_product_release(
        &self,
        _order: &ProductNoteReleaseOrder,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support anonymous reservation releases".into())
    }
    fn issue_note_product_no_fill_release(
        &self,
        _order: &ProductNoteNoFillReleaseOrder,
        _evidence: &MpcNoFillEvidence,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support MPC no-fill reservation releases".into())
    }
    fn issue_credit_control(
        &self,
        _control: &CreditFacilityControl,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support credit facility controls".into())
    }
    fn issue_credit_amendment(
        &self,
        _amendment: &CreditFacilityAmendment,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support credit facility amendments".into())
    }
    fn issue_settlement(
        &self,
        order: &SettlementOrder,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String>;
    fn issue_note_settlement(
        &self,
        _order: &NoteSettlementOrder,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support confidential note settlement".into())
    }
    fn issue_product_settlement(
        &self,
        _order: &ProductSettlementOrder,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support product settlements".into())
    }
    fn issue_product_settlement_batch(
        &self,
        _batch: &ProductSettlementBatch,
        _orders: &[ProductSettlementOrder],
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support atomic product settlement batches".into())
    }
    fn issue_note_product_settlement(
        &self,
        _order: &ProductNoteSettlementOrder,
        _evidence: &ProductSettlementEvidence,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support anonymous product settlements".into())
    }
    fn issue_standing_pool_product_settlement(
        &self,
        _request: StandingPoolProductSettlementRequest<'_>,
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support atomic standing-pool settlements".into())
    }
    fn issue_note_product_settlement_batch(
        &self,
        _batch: &ProductNoteSettlementBatch,
        _orders: &[ProductNoteSettlementOrder],
        _evidence: &[ProductSettlementEvidence],
        _approval: &QuorumApproval,
        _expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Err("Avalanche client does not support atomic anonymous product batches".into())
    }
    fn wait_accepted(
        &self,
        tx_id: &str,
        timeout: Duration,
        poll: Duration,
    ) -> Result<AcceptedTransition, String>;
}

impl AvalancheClient for AvalancheRpcClient {
    fn state_root(&self) -> Result<[u8; 32], String> {
        let result = self.call("defmivm.stateRoot", json!({}))?;
        let raw = result
            .get("stateRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| "L1 returned an invalid state root".to_string())?;
        hex::decode(raw)
            .map_err(|_| "L1 returned an invalid state root".to_string())?
            .try_into()
            .map_err(|_| "L1 state root must be 32 bytes".to_string())
    }

    fn asset_snapshot(&self, asset_id: [u8; 32]) -> Result<CanonicalAsset, String> {
        CanonicalAsset::parse(
            &self.call("defmivm.asset", json!({"assetID": hex::encode(asset_id)}))?,
        )
    }

    fn guarantor_snapshot(&self, guarantor_id: [u8; 32]) -> Result<CanonicalGuarantor, String> {
        CanonicalGuarantor::parse(&self.call(
            "defmivm.guarantor",
            json!({"guarantorID": hex::encode(guarantor_id)}),
        )?)
    }

    fn credit_facility_snapshot(
        &self,
        facility_id: [u8; 32],
    ) -> Result<CanonicalCreditFacility, String> {
        CanonicalCreditFacility::parse(&self.call(
            "defmivm.creditFacility",
            json!({"facilityID": hex::encode(facility_id)}),
        )?)
    }

    fn csd_issuer_snapshot(&self, issuer_id: [u8; 32]) -> Result<CanonicalCsdIssuer, String> {
        CanonicalCsdIssuer::parse(&self.call(
            "defmivm.cSDIssuer",
            json!({"issuerID": hex::encode(issuer_id)}),
        )?)
    }

    fn credit_hold_snapshot(&self, hold_id: [u8; 32]) -> Result<CanonicalCreditHold, String> {
        CanonicalCreditHold::parse(&self.call(
            "defmivm.creditHold",
            json!({"holdID": hex::encode(hold_id)}),
        )?)
    }

    fn note_snapshot(&self, note_id: [u8; 32]) -> Result<CanonicalNote, String> {
        CanonicalNote::parse(&self.call("defmivm.note", json!({"noteID": hex::encode(note_id)}))?)
    }

    fn note_serial_snapshot(&self, serial_point: [u8; 32]) -> Result<CanonicalNoteSerial, String> {
        CanonicalNoteSerial::parse(&self.call(
            "defmivm.noteSerial",
            json!({"serialPoint": hex::encode(serial_point)}),
        )?)
    }

    fn note_page(
        &self,
        asset_id: [u8; 32],
        after: Option<[u8; 32]>,
        limit: u32,
    ) -> Result<CanonicalNotePage, String> {
        if limit == 0 || limit > 256 {
            return Err("canonical note page limit must be between 1 and 256".into());
        }
        CanonicalNotePage::parse(&self.call(
            "defmivm.listNotes",
            json!({
                "assetID": hex::encode(asset_id),
                "after": after.map(hex::encode).unwrap_or_default(),
                "limit": limit,
            }),
        )?)
    }

    fn note_reservation_snapshot(
        &self,
        hold_id: [u8; 32],
    ) -> Result<CanonicalNoteReservation, String> {
        CanonicalNoteReservation::parse(&self.call(
            "defmivm.noteReservation",
            json!({"holdID": hex::encode(hold_id)}),
        )?)
    }

    fn standing_note_pool_snapshot(
        &self,
        pool_id: [u8; 32],
    ) -> Result<CanonicalStandingNotePool, String> {
        CanonicalStandingNotePool::parse(&self.call(
            "defmivm.standingNotePool",
            json!({"poolID": hex::encode(pool_id)}),
        )?)
    }

    fn settlement_verifier_snapshot(
        &self,
        venue_id: [u8; 32],
        epoch: u64,
    ) -> Result<CanonicalSettlementVerifier, String> {
        CanonicalSettlementVerifier::parse(&self.call(
            "defmivm.settlementVerifier",
            json!({"venueID": hex::encode(venue_id), "epoch": epoch}),
        )?)
    }

    fn admission_cursor(
        &self,
        venue_id: [u8; 32],
        epoch: u64,
    ) -> Result<CanonicalAdmissionCursor, String> {
        let cursor = CanonicalAdmissionCursor::parse(&self.call(
            "defmivm.admissionCursor",
            json!({"venueID": hex::encode(venue_id), "epoch": epoch}),
        )?)?;
        if cursor.venue_id != venue_id || cursor.epoch != epoch {
            return Err("L1 admission cursor belongs to another venue or epoch".into());
        }
        Ok(cursor)
    }

    fn note_claim_snapshot(&self, claim_id: [u8; 32]) -> Result<CanonicalNoteClaim, String> {
        CanonicalNoteClaim::parse(&self.call(
            "defmivm.noteClaim",
            json!({"claimID": hex::encode(claim_id)}),
        )?)
    }

    fn note_claim_page(
        &self,
        source_hold_id: [u8; 32],
        after: Option<[u8; 32]>,
        limit: u32,
    ) -> Result<CanonicalNoteClaimPage, String> {
        if source_hold_id == [0; 32] || limit == 0 || limit > 256 {
            return Err("canonical note-claim page parameters are outside product bounds".into());
        }
        CanonicalNoteClaimPage::parse(&self.call(
            "defmivm.listNoteClaims",
            json!({
                "sourceHoldID": hex::encode(source_hold_id),
                "after": after.map(hex::encode).unwrap_or_default(),
                "limit": limit,
            }),
        )?)
    }

    fn note_claim_recipient_page(
        &self,
        recipient_view: [u8; 32],
        after: Option<[u8; 32]>,
        limit: u32,
    ) -> Result<CanonicalNoteClaimPage, String> {
        if recipient_view == [0; 32] || limit == 0 || limit > 256 {
            return Err("recipient note-claim page parameters are outside product bounds".into());
        }
        CanonicalNoteClaimPage::parse(&self.call(
            "defmivm.listNoteClaims",
            json!({
                "recipientView": hex::encode(recipient_view),
                "after": after.map(hex::encode).unwrap_or_default(),
                "limit": limit,
            }),
        )?)
    }

    fn issue_asset(
        &self,
        asset: &AssetDefinition,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueAsset",
            json!({
                "asset": asset_json(asset),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_csd_issuer(
        &self,
        issuer: &CsdIssuerDefinition,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueCSDIssuer",
            json!({
                "issuer": csd_issuer_json(issuer),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_csd_issuer_control(
        &self,
        control: &CsdIssuerControl,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueCSDIssuerControl",
            json!({
                "control": csd_issuer_control_json(control),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_admission_committee(
        &self,
        plan: &AdmissionCommitteePlan,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueAdmissionCommittee",
            json!({
                "plan": admission_committee_json(plan),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_settlement_verifier(
        &self,
        config: &SettlementVerifierConfig,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueSettlementVerifier",
            json!({
                "config": settlement_verifier_json(config),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_admission_batch(
        &self,
        plan: &AdmissionBatchPlan,
        admission_lanes: &[Vec<NodeAdmissionAttestation>],
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueAdmissionBatch",
            json!({
                "plan": admission_batch_json(plan),
                "admissionLanes": admission_lanes_json(admission_lanes),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_admission_advance(
        &self,
        advance: &AdmissionSlotAdvance,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueAdmissionAdvance",
            json!({
                "advance": admission_advance_json(advance),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_product_reservation(
        &self,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
        escrow: &ReservationEscrow,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueProductReservation",
            json!({
                "transition": credit_transition_json(transition),
                "authorization": reservation_authorization_json(authorization),
                "escrow": reservation_escrow_json(escrow),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_standing_note_pool(
        &self,
        registration: &StandingNotePoolRegistration,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueStandingNotePool",
            json!({
                "registration": standing_note_pool_registration_json(registration),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_standing_note_pool_allocation(
        &self,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
        allocation: &StandingNotePoolAllocation,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueStandingNotePoolAllocation",
            json!({
                "transition": credit_transition_json(transition),
                "authorization": reservation_authorization_json(authorization),
                "allocation": standing_note_pool_allocation_json(allocation),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn preview_standing_note_pool_allocation(
        &self,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
        allocation: &StandingNotePoolAllocation,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<StandingNotePoolAllocationPreview, String> {
        StandingNotePoolAllocationPreview::parse(&self.call(
            "defmivm.previewStandingNotePoolAllocation",
            json!({
                "transition": credit_transition_json(transition),
                "authorization": reservation_authorization_json(authorization),
                "allocation": standing_note_pool_allocation_json(allocation),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_note_product_reservation(
        &self,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
        escrow: &NoteReservationEscrow,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueNoteProductReservation",
            json!({
                "transition": credit_transition_json(transition),
                "authorization": reservation_authorization_json(authorization),
                "escrow": note_reservation_escrow_json(escrow),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_product_release(
        &self,
        order: &ProductReleaseOrder,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueProductRelease",
            json!({
                "order": product_release_json(order),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_note_product_release(
        &self,
        order: &ProductNoteReleaseOrder,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueNoteProductRelease",
            json!({
                "order": note_product_release_json(order),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_note_product_no_fill_release(
        &self,
        order: &ProductNoteNoFillReleaseOrder,
        evidence: &MpcNoFillEvidence,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueNoteProductNoFillRelease",
            json!({
                "order": note_product_no_fill_release_json(order),
                "evidence": no_fill_evidence_json(evidence),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_account(
        &self,
        opening: &AccountOpening,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueAccount",
            json!({
                "opening": opening_json(opening),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_note(
        &self,
        issuance: &NoteIssuance,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueNote",
            json!({
                "issuance": note_issuance_json(issuance),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_note_claim_materialization(
        &self,
        materialization: &NoteClaimMaterialization,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueNoteClaimMaterialization",
            json!({
                "materialization": note_claim_materialization_json(materialization),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_guarantor(
        &self,
        guarantor: &GuarantorDefinition,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueGuarantor",
            json!({
                "guarantor": guarantor_json(guarantor),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_credit_grant(
        &self,
        grant: &CreditFacilityGrant,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueCreditGrant",
            json!({
                "grant": credit_grant_json(grant),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_credit_transition(
        &self,
        transition: &CreditFacilityTransition,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueCreditTransition",
            json!({
                "transition": credit_transition_json(transition),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_credit_control(
        &self,
        control: &CreditFacilityControl,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueCreditControl",
            json!({
                "control": credit_control_json(control),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_credit_amendment(
        &self,
        amendment: &CreditFacilityAmendment,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueCreditAmendment",
            json!({
                "amendment": credit_amendment_json(amendment),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_settlement(
        &self,
        order: &SettlementOrder,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueSettlement",
            json!({
                "order": order_json(order),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_note_settlement(
        &self,
        order: &NoteSettlementOrder,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueNoteSettlement",
            json!({
                "order": note_order_json(order),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_product_settlement(
        &self,
        order: &ProductSettlementOrder,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueProductSettlement",
            json!({
                "order": product_order_json(order),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_product_settlement_batch(
        &self,
        batch: &ProductSettlementBatch,
        orders: &[ProductSettlementOrder],
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueProductSettlementBatch",
            json!({
                "batch": product_batch_json(batch),
                "orders": orders.iter().map(product_order_json).collect::<Vec<_>>(),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_note_product_settlement(
        &self,
        order: &ProductNoteSettlementOrder,
        evidence: &ProductSettlementEvidence,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueNoteProductSettlement",
            json!({
                "order": note_product_order_json(order),
                "evidence": product_settlement_evidence_json(evidence)?,
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_standing_pool_product_settlement(
        &self,
        request: StandingPoolProductSettlementRequest<'_>,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueStandingPoolProductSettlement",
            json!({
                "allocationTransition": credit_transition_json(request.allocation_transition),
                "allocationAuthorization": reservation_authorization_json(request.allocation_authorization),
                "allocation": standing_note_pool_allocation_json(request.allocation),
                "allocationApproval": approval_json(request.allocation_approval),
                "order": note_product_order_json(request.order),
                "evidence": product_settlement_evidence_json(request.evidence)?,
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_note_product_settlement_batch(
        &self,
        batch: &ProductNoteSettlementBatch,
        orders: &[ProductNoteSettlementOrder],
        evidence: &[ProductSettlementEvidence],
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueNoteProductSettlementBatch",
            json!({
                "batch": note_product_batch_json(batch),
                "orders": orders.iter().map(note_product_order_json).collect::<Vec<_>>(),
                "evidence": evidence.iter().map(product_settlement_evidence_json).collect::<Result<Vec<_>, _>>()?,
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn wait_accepted(
        &self,
        tx_id: &str,
        timeout: Duration,
        poll: Duration,
    ) -> Result<AcceptedTransition, String> {
        if timeout.is_zero() || poll.is_zero() {
            return Err("acceptance timeout and polling interval must be positive".into());
        }
        let started = Instant::now();
        loop {
            let result = self.call("defmivm.txStatus", json!({"txID": tx_id}))?;
            let status = result.get("status").and_then(Value::as_str);
            match status {
                Some("accepted") => return AcceptedTransition::parse(&result),
                Some("rejected") => {
                    return Err(format!(
                        "Avalanche consensus rejected transaction {tx_id}: {}",
                        result
                            .get("reason")
                            .and_then(Value::as_str)
                            .unwrap_or("unspecified")
                    ));
                }
                Some("pending" | "processing" | "unknown") => {}
                other => return Err(format!("L1 returned unknown transaction status {other:?}")),
            }
            if started.elapsed() >= timeout {
                return Err(format!(
                    "Avalanche transaction {tx_id} was not accepted in time"
                ));
            }
            thread::sleep(poll);
        }
    }
}

/// Avalanche-authoritative bridge for the account-free note rail.
///
/// Unlike the legacy account projection, the canonical note set lives on the
/// L1 itself.  Every call fetches the current consensus root, verifies the
/// k-of-n signatures locally, submits exactly that statement, and checks the
/// accepted transition receipt.  This avoids inventing a second source of
/// truth for hidden ownership.
pub struct AvalancheNoteBridge<'a, C: AvalancheClient> {
    pub authorizer: &'a QuorumAuthorizer,
    pub client: &'a C,
}

impl<'a, C: AvalancheClient> AvalancheNoteBridge<'a, C> {
    pub const fn new(authorizer: &'a QuorumAuthorizer, client: &'a C) -> Self {
        Self { authorizer, client }
    }

    pub fn credit_facility(
        &self,
        facility_id: [u8; 32],
    ) -> Result<CanonicalCreditFacility, String> {
        let snapshot = self.client.credit_facility_snapshot(facility_id)?;
        if snapshot.facility.facility_id != facility_id {
            return Err("Avalanche returned a different credit facility".into());
        }
        Ok(snapshot)
    }

    pub fn csd_issuer(&self, issuer_id: [u8; 32]) -> Result<CanonicalCsdIssuer, String> {
        let snapshot = self.client.csd_issuer_snapshot(issuer_id)?;
        if snapshot.definition.issuer_id != issuer_id {
            return Err("Avalanche returned a different CSD issuer".into());
        }
        Ok(snapshot)
    }

    pub fn credit_hold(&self, hold_id: [u8; 32]) -> Result<CanonicalCreditHold, String> {
        let snapshot = self.client.credit_hold_snapshot(hold_id)?;
        if snapshot.hold_id != hold_id {
            return Err("Avalanche returned a different credit hold".into());
        }
        Ok(snapshot)
    }

    pub fn note(&self, note_id: [u8; 32]) -> Result<CanonicalNote, String> {
        let snapshot = self.client.note_snapshot(note_id)?;
        if snapshot.output.note_id != note_id {
            return Err("Avalanche returned a different confidential note".into());
        }
        Ok(snapshot)
    }

    pub fn note_serial(&self, serial_point: [u8; 32]) -> Result<CanonicalNoteSerial, String> {
        let snapshot = self.client.note_serial_snapshot(serial_point)?;
        if snapshot.serial_point != serial_point {
            return Err("Avalanche returned a different confidential-note serial".into());
        }
        Ok(snapshot)
    }

    pub fn note_reservation(&self, hold_id: [u8; 32]) -> Result<CanonicalNoteReservation, String> {
        let snapshot = self.client.note_reservation_snapshot(hold_id)?;
        if snapshot.hold_id != hold_id {
            return Err("Avalanche returned a different anonymous reservation".into());
        }
        Ok(snapshot)
    }

    pub fn standing_note_pool(
        &self,
        pool_id: [u8; 32],
    ) -> Result<CanonicalStandingNotePool, String> {
        let snapshot = self.client.standing_note_pool_snapshot(pool_id)?;
        if snapshot.pool_id != pool_id || self.client.state_root()? != snapshot.state_root {
            return Err("canonical standing note pool is stale or names another pool".into());
        }
        Ok(snapshot)
    }

    pub fn note_claim(&self, claim_id: [u8; 32]) -> Result<CanonicalNoteClaim, String> {
        let snapshot = self.client.note_claim_snapshot(claim_id)?;
        if snapshot.claim_id != claim_id {
            return Err("Avalanche returned a different confidential note claim".into());
        }
        Ok(snapshot)
    }

    /// Read a complete, bounded anonymity pool from one immutable L1 root.
    /// If any RFQ or settlement is accepted between pages, the operation fails
    /// closed and the wallet restarts from the new root; it never constructs a
    /// proof over a mixture of two canonical states.
    pub fn note_pool(
        &self,
        asset_id: [u8; 32],
        maximum: usize,
    ) -> Result<([u8; 32], Vec<NoteOutput>), String> {
        if asset_id == [0; 32] || maximum == 0 || maximum > 16_384 {
            return Err("canonical note pool request is outside product bounds".into());
        }
        let mut root = None;
        let mut after = None;
        let mut notes = Vec::new();
        loop {
            let remaining = maximum.saturating_sub(notes.len());
            if remaining == 0 {
                return Err("canonical note pool exceeded the configured bound".into());
            }
            let page = self
                .client
                .note_page(asset_id, after, remaining.min(256) as u32)?;
            match root {
                None => root = Some(page.state_root),
                Some(expected) if expected != page.state_root => {
                    return Err("canonical note pool changed while it was being read".into())
                }
                Some(_) => {}
            }
            if page.notes.iter().any(|note| note.asset_id != asset_id) {
                return Err("canonical note page crossed asset rails".into());
            }
            notes.extend(page.notes);
            let Some(next) = page.next else {
                break;
            };
            if after == Some(next) {
                return Err("canonical note pagination cursor did not advance".into());
            }
            after = Some(next);
        }
        let root =
            root.ok_or_else(|| "canonical note endpoint returned no state root".to_string())?;
        if self.client.state_root()? != root {
            return Err("canonical note pool became stale before proof construction".into());
        }
        Ok((root, notes))
    }

    pub fn note_ledger(
        &self,
        asset_id: [u8; 32],
        key: Pedersen,
        bits: usize,
        maximum: usize,
    ) -> Result<([u8; 32], NoteLedger, Vec<NoteOutput>), String> {
        let (root, outputs) = self.note_pool(asset_id, maximum)?;
        let mut ledger = NoteLedger::new(key, bits);
        for output in &outputs {
            ledger.add(output.to_note()?);
        }
        Ok((root, ledger, outputs))
    }

    fn submit<F>(
        &self,
        statement: [u8; 32],
        approval: &QuorumApproval,
        issue: F,
    ) -> Result<AcceptedTransition, String>
    where
        F: FnOnce(&C, &QuorumApproval, [u8; 32]) -> Result<String, String>,
    {
        let before = approval.before_root;
        if !self.authorizer.verify(&statement, &before, approval) {
            return Err(
                "the note transition approval is invalid or names another statement".into(),
            );
        }
        // Always submit the exact approved pre-state. The VM first checks
        // whether this exact transaction was already accepted and returns its
        // existing ID before comparing the current root. Consequently a crash
        // after consensus but before the client persisted the receipt can be
        // retried byte-for-byte, while a different transaction signed over a
        // stale root still fails closed.
        let transaction = issue(self.client, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        if accepted.statement != statement || accepted.before_root != before {
            return Err("Avalanche accepted a different note transition or pre-state".into());
        }
        Ok(accepted)
    }

    pub fn register_asset(
        &self,
        asset: &AssetDefinition,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let statement = asset.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_asset(asset, approval, before)
        })
    }

    pub fn register_csd_issuer(
        &self,
        issuer: &CsdIssuerDefinition,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let statement = issuer.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_csd_issuer(issuer, approval, before)
        })
    }

    pub fn control_csd_issuer(
        &self,
        control: &CsdIssuerControl,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let statement = control.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_csd_issuer_control(control, approval, before)
        })
    }

    pub fn register_guarantor(
        &self,
        guarantor: &GuarantorDefinition,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let statement = guarantor.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_guarantor(guarantor, approval, before)
        })
    }

    pub fn grant_credit_facility(
        &self,
        grant: &CreditFacilityGrant,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let statement = grant.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_credit_grant(grant, approval, before)
        })
    }

    pub fn register_admission_committee(
        &self,
        plan: &AdmissionCommitteePlan,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let statement = plan.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_admission_committee(plan, approval, before)
        })
    }

    pub fn register_settlement_verifier(
        &self,
        config: &SettlementVerifierConfig,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let statement = config.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_settlement_verifier(config, approval, before)
        })
    }

    pub fn register_admission_batch(
        &self,
        plan: &AdmissionBatchPlan,
        lanes: &[Vec<NodeAdmissionAttestation>],
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let statement = plan.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_admission_batch(plan, lanes, approval, before)
        })
    }

    pub fn advance_admission(
        &self,
        advance: &AdmissionSlotAdvance,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let statement = advance.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_admission_advance(advance, approval, before)
        })
    }

    pub fn control_credit_facility(
        &self,
        control: &CreditFacilityControl,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let statement = control.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_credit_control(control, approval, before)
        })
    }

    pub fn amend_credit_facility(
        &self,
        amendment: &CreditFacilityAmendment,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let statement = amendment.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_credit_amendment(amendment, approval, before)
        })
    }

    pub fn issue_note(
        &self,
        issuance: &NoteIssuance,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let statement = issuance.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_note(issuance, approval, before)
        })
    }

    pub fn materialize_note_claim(
        &self,
        materialization: &NoteClaimMaterialization,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let statement = materialization.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_note_claim_materialization(materialization, approval, before)
        })
    }

    pub fn register_standing_note_pool(
        &self,
        registration: &StandingNotePoolRegistration,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let statement = registration.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_standing_note_pool(registration, approval, before)
        })
    }

    pub fn allocate_standing_note_pool(
        &self,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
        allocation: &StandingNotePoolAllocation,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        if allocation.statement(transition, authorization)? != authorization.escrow_digest {
            return Err("standing allocation differs from the reservation authorization".into());
        }
        let statement = authorization.statement(transition)?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_standing_note_pool_allocation(
                transition,
                authorization,
                allocation,
                approval,
                before,
            )
        })
    }

    pub fn preview_standing_note_pool_allocation(
        &self,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
        allocation: &StandingNotePoolAllocation,
        approval: &QuorumApproval,
    ) -> Result<StandingNotePoolAllocationPreview, String> {
        if allocation.statement(transition, authorization)? != authorization.escrow_digest {
            return Err("standing allocation differs from the reservation authorization".into());
        }
        let statement = authorization.statement(transition)?;
        if !self
            .authorizer
            .verify(&statement, &approval.before_root, approval)
        {
            return Err("standing allocation preview has an invalid approval".into());
        }
        let preview = self.client.preview_standing_note_pool_allocation(
            transition,
            authorization,
            allocation,
            approval,
            approval.before_root,
        )?;
        if preview.before_state_root != approval.before_root
            || preview.statement != statement
            || preview.pool_id != allocation.pool_id
            || preview.current_pool_note_id != allocation.remainder_note.note_id
            || preview.pool_sequence != allocation.expected_pool_sequence.saturating_add(1)
            || preview.reservation_hold_id != transition.hold_id
            || preview.escrow_note_id != allocation.escrow_note.note_id
            || preview.reservation_amount_commitment != transition.amount_commitment
            || preview.reserve_receipt_digest != statement
            || preview.hold_facility_id != transition.facility_id
            || preview.facility.facility_id != transition.facility_id
        {
            return Err("L1 preview produced another standing-pool successor".into());
        }
        Ok(preview)
    }

    pub fn reserve_product(
        &self,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
        escrow: &NoteReservationEscrow,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let escrow_statement = escrow.statement(transition, authorization)?;
        if escrow_statement != authorization.escrow_digest {
            return Err("anonymous escrow differs from the signed reservation".into());
        }
        let statement = authorization.statement(transition)?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_note_product_reservation(
                transition,
                authorization,
                escrow,
                approval,
                before,
            )
        })
    }

    pub fn release_product(
        &self,
        order: &ProductNoteReleaseOrder,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let statement = order.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_note_product_release(order, approval, before)
        })
    }

    pub fn release_product_no_fill(
        &self,
        order: &ProductNoteNoFillReleaseOrder,
        evidence: &MpcNoFillEvidence,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        evidence.validate_encoding()?;
        if evidence.digest()? != order.no_fill_evidence_digest {
            return Err("no-fill release order carries another evidence digest".into());
        }
        let statement = order.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_note_product_no_fill_release(order, evidence, approval, before)
        })
    }

    pub fn settle(
        &self,
        order: &NoteSettlementOrder,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let statement = order.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_note_settlement(order, approval, before)
        })
    }

    pub fn settle_product(
        &self,
        order: &ProductNoteSettlementOrder,
        evidence: &ProductSettlementEvidence,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let statement = order.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_note_product_settlement(order, evidence, approval, before)
        })
    }

    pub fn settle_standing_pool_product(
        &self,
        request: StandingPoolProductSettlementRequest<'_>,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        request.evidence.validate_encoding()?;
        if request.allocation.statement(
            request.allocation_transition,
            request.allocation_authorization,
        )? != request.allocation_authorization.escrow_digest
        {
            return Err("atomic settlement allocation differs from its authorization".into());
        }
        let allocation_statement = request
            .allocation_authorization
            .statement(request.allocation_transition)?;
        if request.allocation_approval.before_root != approval.before_root
            || !self.authorizer.verify(
                &allocation_statement,
                &request.allocation_approval.before_root,
                request.allocation_approval,
            )
        {
            return Err("atomic settlement has an invalid allocation approval".into());
        }
        let statement = standing_pool_product_settlement_statement(
            request.allocation_transition,
            request.allocation_authorization,
            request.allocation,
            request.order,
            request.evidence.digest()?,
        )?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_standing_pool_product_settlement(request, approval, before)
        })
    }

    pub fn settle_product_batch(
        &self,
        batch: &ProductNoteSettlementBatch,
        orders: &[ProductNoteSettlementOrder],
        evidence: &[ProductSettlementEvidence],
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        batch.validate_orders(orders)?;
        if evidence.len() != orders.len() {
            return Err("one verifier-complete proof bundle is required per settlement".into());
        }
        let statement = batch.statement()?;
        self.submit(statement, approval, |client, approval, before| {
            client.issue_note_product_settlement_batch(batch, orders, evidence, approval, before)
        })
    }
}

pub struct FacilityAvalancheBridge<'a, C: AvalancheClient> {
    pub facility: &'a DefmiFacility,
    pub client: &'a C,
}

impl<'a, C: AvalancheClient> FacilityAvalancheBridge<'a, C> {
    pub const fn new(facility: &'a DefmiFacility, client: &'a C) -> Self {
        Self { facility, client }
    }

    fn require_approval(
        &self,
        statement: &[u8; 32],
        before: &[u8; 32],
        approval: &QuorumApproval,
    ) -> Result<(), String> {
        if self.facility.authorizer.verify(statement, before, approval) {
            Ok(())
        } else {
            Err("the transition approval is not bound to this L1 and state root".into())
        }
    }

    fn check(
        accepted: &AcceptedTransition,
        statement: &[u8; 32],
        before: &[u8; 32],
    ) -> Result<(), String> {
        if accepted.statement != *statement {
            return Err("Avalanche accepted a different authorized statement".into());
        }
        if accepted.before_root != *before {
            return Err("Avalanche applied the transition to an unexpected state root".into());
        }
        Ok(())
    }

    pub fn register_asset(
        &self,
        asset: &AssetDefinition,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let before = self.facility.state_root()?;
        let statement = asset.statement()?;
        self.require_approval(&statement, &before, approval)?;
        let transaction = self.client.issue_asset(asset, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        Self::check(&accepted, &statement, &before)?;
        self.facility.register_asset(asset, approval)?;
        if self.facility.state_root()? != accepted.after_root {
            return Err("asset projection root differs from Avalanche".into());
        }
        Ok(accepted)
    }

    pub fn open_account(
        &self,
        opening: &AccountOpening,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let before = self.facility.state_root()?;
        let statement = opening.statement()?;
        self.require_approval(&statement, &before, approval)?;
        let transaction = self.client.issue_account(opening, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        Self::check(&accepted, &statement, &before)?;
        self.facility.open_account(opening, approval)?;
        if self.facility.state_root()? != accepted.after_root {
            return Err("account projection root differs from Avalanche".into());
        }
        Ok(accepted)
    }

    pub fn register_guarantor(
        &self,
        guarantor: &GuarantorDefinition,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let before = self.facility.state_root()?;
        let statement = guarantor.statement()?;
        self.require_approval(&statement, &before, approval)?;
        let transaction = self.client.issue_guarantor(guarantor, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        Self::check(&accepted, &statement, &before)?;
        self.facility.register_guarantor(guarantor, approval)?;
        if self.facility.state_root()? != accepted.after_root {
            return Err("guarantor projection root differs from Avalanche".into());
        }
        Ok(accepted)
    }

    pub fn grant_credit_facility(
        &self,
        grant: &CreditFacilityGrant,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(CreditFacilitySnapshot, AcceptedTransition), String> {
        let before = self.facility.state_root()?;
        let statement = grant.statement()?;
        self.require_approval(&statement, &before, approval)?;
        let transaction = self.client.issue_credit_grant(grant, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        Self::check(&accepted, &statement, &before)?;
        let snapshot = self.facility.grant_credit_facility(grant, approval, now)?;
        if self.facility.state_root()? != accepted.after_root {
            return Err("credit facility projection root differs from Avalanche".into());
        }
        Ok((snapshot, accepted))
    }

    /// Pin the resident-node receipt keys on Avalanche before any batch for
    /// the venue epoch can be accepted.
    pub fn register_admission_committee(
        &self,
        plan: &AdmissionCommitteePlan,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<AcceptedTransition, String> {
        plan.body()?;
        let before = self.facility.state_root()?;
        let statement = plan.statement()?;
        self.require_approval(&statement, &before, approval)?;
        let transaction = self
            .client
            .issue_admission_committee(plan, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        Self::check(&accepted, &statement, &before)?;
        self.facility
            .register_admission_committee(plan, approval, now)?;
        if self.facility.state_root()? != accepted.after_root {
            return Err("admission committee projection root differs from Avalanche".into());
        }
        Ok(accepted)
    }

    /// Pin the proof circuit, Maker registry and FROST group on Avalanche and
    /// project the identical trust anchor into the native DeFMI database.
    pub fn register_settlement_verifier(
        &self,
        config: &SettlementVerifierConfig,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<AcceptedTransition, String> {
        config.validate()?;
        let before = self.facility.state_root()?;
        let statement = config.statement()?;
        self.require_approval(&statement, &before, approval)?;
        let transaction = self
            .client
            .issue_settlement_verifier(config, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        Self::check(&accepted, &statement, &before)?;
        self.facility
            .register_settlement_verifier(config, approval, now)?;
        if self.facility.state_root()? != accepted.after_root {
            return Err("settlement verifier projection root differs from Avalanche".into());
        }
        Ok(accepted)
    }

    /// Register the complete fixed-size RFQ admission order on the Avalanche
    /// L1 first, then apply the byte-identical projection locally. No RFQ can
    /// consume a legal-entity facility before this transition is accepted.
    pub fn register_admission_batch(
        &self,
        plan: &AdmissionBatchPlan,
        admission_lanes: &[Vec<qomm_transport::order::NodeAdmissionAttestation>],
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(AdmissionBatchSnapshot, AcceptedTransition), String> {
        plan.body()?;
        let before = self.facility.state_root()?;
        let statement = plan.statement()?;
        self.require_approval(&statement, &before, approval)?;
        let transaction =
            self.client
                .issue_admission_batch(plan, admission_lanes, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        Self::check(&accepted, &statement, &before)?;
        let snapshot =
            self.facility
                .register_admission_batch(plan, admission_lanes, approval, now)?;
        if self.facility.state_root()? != accepted.after_root {
            return Err("admission batch projection root differs from Avalanche".into());
        }
        Ok((snapshot, accepted))
    }

    /// Consume one non-reservation lane in the same durable total order used
    /// by real Taker reservations. The opaque lane digest does not disclose
    /// whether the sealed input was cover traffic.
    pub fn advance_admission_slot(
        &self,
        advance: &AdmissionSlotAdvance,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(AdmissionBatchSnapshot, AcceptedTransition), String> {
        advance.body()?;
        let before = self.facility.state_root()?;
        let statement = advance.statement()?;
        self.require_approval(&statement, &before, approval)?;
        let transaction = self
            .client
            .issue_admission_advance(advance, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        Self::check(&accepted, &statement, &before)?;
        let snapshot = self
            .facility
            .advance_admission_slot(advance, approval, now)?;
        if self.facility.state_root()? != accepted.after_root {
            return Err("admission advance projection root differs from Avalanche".into());
        }
        Ok((snapshot, accepted))
    }

    pub fn transition_credit_facility(
        &self,
        transition: &CreditFacilityTransition,
        relation_proof: &CreditFacilityRelationProof,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(CreditFacilitySnapshot, AcceptedTransition), String> {
        relation_proof.verify(transition)?;
        let before = self.facility.state_root()?;
        let statement = transition.statement()?;
        self.require_approval(&statement, &before, approval)?;
        let transaction = self
            .client
            .issue_credit_transition(transition, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        Self::check(&accepted, &statement, &before)?;
        let snapshot =
            self.facility
                .transition_credit_facility(transition, relation_proof, approval, now)?;
        if self.facility.state_root()? != accepted.after_root {
            return Err("credit transition projection root differs from Avalanche".into());
        }
        Ok((snapshot, accepted))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn reserve_maker(
        &self,
        transition: &CreditFacilityTransition,
        relation_proof: &CreditFacilityRelationProof,
        authorization: &ReservationAuthorization,
        escrow: &ReservationEscrow,
        escrow_proof: &crate::product::ReservationEscrowProof,
        typed_instruction: &TypedInstruction,
        typed_venue: &Venue,
        asset_link: &crate::asset_link::AssetLinkProof,
        mandate: &MakerPolicyMandate,
        identity: &crate::product::IdentityEvidence<'_>,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(CreditFacilitySnapshot, AcceptedTransition), String> {
        crate::product::verify_maker_reservation(
            transition,
            authorization,
            typed_instruction,
            mandate,
            identity,
            now,
        )?;
        crate::product::verify_reservation_escrow(
            self.facility,
            transition,
            authorization,
            escrow,
            escrow_proof,
            typed_instruction,
            typed_venue,
        )?;
        relation_proof.verify(transition)?;
        let before = self.facility.state_root()?;
        let statement = authorization.statement(transition)?;
        self.require_approval(&statement, &before, approval)?;
        let transaction = self.client.issue_product_reservation(
            transition,
            authorization,
            escrow,
            approval,
            before,
        )?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        Self::check(&accepted, &statement, &before)?;
        let snapshot = crate::product::reserve_maker(
            self.facility,
            transition,
            relation_proof,
            authorization,
            escrow,
            escrow_proof,
            typed_instruction,
            typed_venue,
            asset_link,
            mandate,
            identity,
            approval,
            now,
        )?;
        if self.facility.state_root()? != accepted.after_root {
            return Err("Maker reservation projection root differs from Avalanche".into());
        }
        Ok((snapshot, accepted))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn reserve_taker(
        &self,
        transition: &CreditFacilityTransition,
        relation_proof: &CreditFacilityRelationProof,
        authorization: &ReservationAuthorization,
        escrow: &ReservationEscrow,
        escrow_proof: &crate::product::ReservationEscrowProof,
        typed_instruction: &TypedInstruction,
        typed_venue: &Venue,
        asset_link: &crate::asset_link::AssetLinkProof,
        ordered_admission: &qomm_transport::order::OrderedAdmission,
        mandate: &TakerExecutionMandate,
        identity: &crate::product::IdentityEvidence<'_>,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(CreditFacilitySnapshot, AcceptedTransition), String> {
        crate::product::verify_taker_reservation(
            transition,
            authorization,
            typed_instruction,
            mandate,
            ordered_admission,
            identity,
            now,
        )?;
        crate::product::verify_reservation_escrow(
            self.facility,
            transition,
            authorization,
            escrow,
            escrow_proof,
            typed_instruction,
            typed_venue,
        )?;
        relation_proof.verify(transition)?;
        let before = self.facility.state_root()?;
        let statement = authorization.statement(transition)?;
        self.require_approval(&statement, &before, approval)?;
        let transaction = self.client.issue_product_reservation(
            transition,
            authorization,
            escrow,
            approval,
            before,
        )?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        Self::check(&accepted, &statement, &before)?;
        let snapshot = crate::product::reserve_taker(
            self.facility,
            transition,
            relation_proof,
            authorization,
            escrow,
            escrow_proof,
            typed_instruction,
            typed_venue,
            asset_link,
            ordered_admission,
            mandate,
            identity,
            approval,
            now,
        )?;
        if self.facility.state_root()? != accepted.after_root {
            return Err("Taker reservation projection root differs from Avalanche".into());
        }
        Ok((snapshot, accepted))
    }

    pub fn amend_credit_facility(
        &self,
        amendment: &CreditFacilityAmendment,
        relation_proof: &CreditFacilityAmendmentProof,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(CreditFacilitySnapshot, AcceptedTransition), String> {
        relation_proof.verify(amendment)?;
        let before = self.facility.state_root()?;
        let statement = amendment.statement()?;
        self.require_approval(&statement, &before, approval)?;
        let transaction = self
            .client
            .issue_credit_amendment(amendment, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        Self::check(&accepted, &statement, &before)?;
        let snapshot =
            self.facility
                .amend_credit_facility(amendment, relation_proof, approval, now)?;
        if self.facility.state_root()? != accepted.after_root {
            return Err("credit amendment projection root differs from Avalanche".into());
        }
        Ok((snapshot, accepted))
    }

    pub fn control_credit_facility(
        &self,
        control: &CreditFacilityControl,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(CreditFacilitySnapshot, AcceptedTransition), String> {
        let before = self.facility.state_root()?;
        let statement = control.statement()?;
        self.require_approval(&statement, &before, approval)?;
        let transaction = self
            .client
            .issue_credit_control(control, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        Self::check(&accepted, &statement, &before)?;
        let snapshot = self
            .facility
            .control_credit_facility(control, approval, now)?;
        if self.facility.state_root()? != accepted.after_root {
            return Err("credit control projection root differs from Avalanche".into());
        }
        Ok((snapshot, accepted))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn release_product_reservation(
        &self,
        order: &ProductReleaseOrder,
        relation_proof: &CreditFacilityRelationProof,
        typed_instruction: &TypedInstruction,
        typed_venue: &Venue,
        asset_link: &crate::asset_link::AssetLinkProof,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(SettlementReceipt, AcceptedTransition), String> {
        relation_proof.verify(&order.transition)?;
        let before = self.facility.state_root()?;
        let statement = order.statement()?;
        self.require_approval(&statement, &before, approval)?;
        self.facility.preflight_product_release(
            order,
            relation_proof,
            typed_instruction,
            typed_venue,
            asset_link,
            approval,
            now,
        )?;
        let transaction = self.client.issue_product_release(order, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        Self::check(&accepted, &statement, &before)?;
        let receipt = crate::product::release_reservation(
            self.facility,
            order,
            relation_proof,
            typed_instruction,
            typed_venue,
            asset_link,
            approval,
            now,
        )?;
        if receipt.before_root != accepted.before_root || receipt.after_root != accepted.after_root
        {
            return Err("product release projection root differs from Avalanche".into());
        }
        Ok((receipt, accepted))
    }

    pub fn settle(
        &self,
        order: &SettlementOrder,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(SettlementReceipt, AcceptedTransition), String> {
        let before = self.facility.state_root()?;
        let statement = order.statement()?;
        self.require_approval(&statement, &before, approval)?;
        let transaction = self.client.issue_settlement(order, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        Self::check(&accepted, &statement, &before)?;
        let receipt = self.facility.settle(order, approval, now)?;
        if receipt.before_root != accepted.before_root || receipt.after_root != accepted.after_root
        {
            return Err("settlement projection root differs from Avalanche".into());
        }
        Ok((receipt, accepted))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn settle_product<R: RngCore + CryptoRng>(
        &self,
        order: &ProductSettlementOrder,
        relation_proofs: &[CreditFacilityRelationProof],
        typed_instruction: &TypedInstruction,
        typed_venue: &Venue,
        asset_link: &crate::asset_link::AssetLinkProof,
        dvp_package: &crate::settlement::DvpPackage,
        price_limit_proof: &PriceLimitProof,
        maker_mandate: &MakerPolicyMandate,
        maker_identity: &crate::product::IdentityEvidence<'_>,
        taker_mandate: &TakerExecutionMandate,
        taker_identity: &crate::product::IdentityEvidence<'_>,
        approval: &QuorumApproval,
        now: u64,
        rng: &mut R,
    ) -> Result<(SettlementReceipt, AcceptedTransition), String> {
        crate::product::verify_settlement_authority(
            order,
            typed_instruction,
            typed_venue,
            price_limit_proof,
            maker_mandate,
            maker_identity,
            taker_mandate,
            taker_identity,
            now,
        )?;
        if relation_proofs.len() != order.reservations.len() {
            return Err("each product reservation needs one credit relation proof".into());
        }
        for (reservation, proof) in order.reservations.iter().zip(relation_proofs) {
            proof.verify(&reservation.transition)?;
        }
        let before = self.facility.state_root()?;
        let statement = order.statement()?;
        self.require_approval(&statement, &before, approval)?;
        // Avalanche is the authoritative ordering layer, but it must never be
        // the first component to learn that locally supplied proof bytes were
        // malformed.  Execute the exact DeFMI verification and state transition
        // inside a rolled-back SQLite transaction before broadcasting.  The
        // accepted transaction is then projected for real below.
        self.facility.preflight_product(
            order,
            relation_proofs,
            typed_instruction,
            typed_venue,
            asset_link,
            dvp_package,
            approval,
            now,
            rng,
        )?;
        let transaction = self
            .client
            .issue_product_settlement(order, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        Self::check(&accepted, &statement, &before)?;
        let receipt = crate::product::settle_product(
            self.facility,
            order,
            relation_proofs,
            typed_instruction,
            typed_venue,
            asset_link,
            dvp_package,
            price_limit_proof,
            maker_mandate,
            maker_identity,
            taker_mandate,
            taker_identity,
            approval,
            now,
            rng,
        )?;
        if receipt.before_root != accepted.before_root || receipt.after_root != accepted.after_root
        {
            return Err("product settlement projection root differs from Avalanche".into());
        }
        Ok((receipt, accepted))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn settle_product_threshold<R: RngCore + CryptoRng>(
        &self,
        order: &ProductSettlementOrder,
        relation_proofs: &[CreditFacilityRelationProof],
        typed_instruction: &TypedInstruction,
        typed_venue: &Venue,
        asset_link: &crate::asset_link::AssetLinkProof,
        dvp_package: &crate::settlement::ThresholdDvpPackage,
        price_limit_proof: &PriceLimitProof,
        maker_mandate: &MakerPolicyMandate,
        maker_identity: &crate::product::IdentityEvidence<'_>,
        taker_mandate: &TakerExecutionMandate,
        taker_identity: &crate::product::IdentityEvidence<'_>,
        approval: &QuorumApproval,
        now: u64,
        rng: &mut R,
    ) -> Result<(SettlementReceipt, AcceptedTransition), String> {
        crate::product::verify_settlement_authority(
            order,
            typed_instruction,
            typed_venue,
            price_limit_proof,
            maker_mandate,
            maker_identity,
            taker_mandate,
            taker_identity,
            now,
        )?;
        if !relation_proofs.is_empty() {
            if relation_proofs.len() != order.reservations.len() {
                return Err("each product reservation needs one credit relation proof".into());
            }
            for (reservation, proof) in order.reservations.iter().zip(relation_proofs) {
                proof.verify(&reservation.transition)?;
            }
        }
        let before = self.facility.state_root()?;
        let statement = order.statement()?;
        self.require_approval(&statement, &before, approval)?;
        self.facility.preflight_product_threshold(
            order,
            relation_proofs,
            typed_instruction,
            typed_venue,
            asset_link,
            dvp_package,
            approval,
            now,
            rng,
        )?;
        let transaction = self
            .client
            .issue_product_settlement(order, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        Self::check(&accepted, &statement, &before)?;
        let receipt = crate::product::settle_product_threshold(
            self.facility,
            order,
            relation_proofs,
            typed_instruction,
            typed_venue,
            asset_link,
            dvp_package,
            price_limit_proof,
            maker_mandate,
            maker_identity,
            taker_mandate,
            taker_identity,
            approval,
            now,
            rng,
        )?;
        if receipt.before_root != accepted.before_root || receipt.after_root != accepted.after_root
        {
            return Err(
                "threshold product settlement projection root differs from Avalanche".into(),
            );
        }
        Ok((receipt, accepted))
    }

    /// Verify all private evidence and submit an atomic product batch without
    /// advancing the local projection. Keeping this boundary explicit lets a
    /// caller recover the exact failure window between L1 acceptance and the
    /// local SQLite commit by retrying `settle_product_threshold_batch`.
    pub fn submit_product_threshold_batch<R: RngCore + CryptoRng>(
        &self,
        batch: &ProductSettlementBatch,
        items: &[crate::product::ThresholdProductSettlement<'_>],
        typed_venue: &Venue,
        approval: &QuorumApproval,
        now: u64,
        rng: &mut R,
    ) -> Result<AcceptedTransition, String> {
        if items.is_empty() {
            return Err("product settlement batch cannot be empty".into());
        }
        let orders = items
            .iter()
            .map(|item| item.order.clone())
            .collect::<Vec<_>>();
        batch.validate_orders(&orders)?;
        let before = self.facility.state_root()?;
        let statement = batch.statement()?;
        self.require_approval(&statement, &before, approval)?;
        for item in items {
            crate::product::verify_settlement_authority(
                item.order,
                item.typed_instruction,
                typed_venue,
                item.price_limit_proof,
                item.maker_mandate,
                item.maker_identity,
                item.taker_mandate,
                item.taker_identity,
                now,
            )?;
            self.facility.preflight_product_threshold_for_batch(
                item.order,
                item.relation_proofs,
                item.typed_instruction,
                typed_venue,
                item.asset_link,
                item.dvp_package,
                before,
                now,
                rng,
            )?;
        }
        let transaction = self
            .client
            .issue_product_settlement_batch(batch, &orders, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            CONSENSUS_ACCEPTANCE_TIMEOUT,
            CONSENSUS_POLL_INTERVAL,
        )?;
        Self::check(&accepted, &statement, &before)?;
        Ok(accepted)
    }

    /// Submit all simultaneous, disjoint RFQs as one Avalanche consensus
    /// transaction, then project the accepted state into the local DeFMI
    /// database. Every proof and mandate is preflighted before broadcasting;
    /// neither layer can expose a partially settled batch.
    pub fn settle_product_threshold_batch<R: RngCore + CryptoRng>(
        &self,
        batch: &ProductSettlementBatch,
        items: &[crate::product::ThresholdProductSettlement<'_>],
        typed_venue: &Venue,
        approval: &QuorumApproval,
        now: u64,
        rng: &mut R,
    ) -> Result<(Vec<SettlementReceipt>, AcceptedTransition), String> {
        let accepted =
            self.submit_product_threshold_batch(batch, items, typed_venue, approval, now, rng)?;
        let receipts = crate::product::settle_product_threshold_batch(
            self.facility,
            batch,
            items,
            typed_venue,
            approval,
            now,
            rng,
        )?;
        if receipts.first().map(|receipt| receipt.before_root) != Some(accepted.before_root)
            || receipts.last().map(|receipt| receipt.after_root) != Some(accepted.after_root)
            || self.facility.state_root()? != accepted.after_root
        {
            return Err("atomic product batch projection root differs from Avalanche".into());
        }
        Ok((receipts, accepted))
    }
}
