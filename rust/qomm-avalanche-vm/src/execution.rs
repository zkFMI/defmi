//! Domain transition decoding and validation.
//!
//! JSON is only a transport envelope. Every accepted action is reconstructed
//! as the corresponding `qomm-defmi` domain type, so statement hashing and
//! k-of-n approval verification are shared with the native Rust facility.

use std::collections::BTreeSet;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use qomm_defmi::asset_link::{self, AssetLinkProof};
use qomm_defmi::facility::{
    AccountOpening, AdmissionBatchPlan, AdmissionCommitteePlan, AdmissionSlotAdvance,
    AssetDefinition, AssetKind, CreditAmendmentMode, CreditControlAction, CreditFacilityAmendment,
    CreditFacilityControl, CreditFacilityGrant, CreditFacilityTransition, CreditTransitionKind,
    GuarantorDefinition, GuarantorKind, NodeApproval, ProductReleaseOrder, ProductSettlementBatch,
    ProductSettlementBatchMember, ProductSettlementOrder, QuorumApproval, QuorumAuthorizer,
    ReservationAuthorization, ReservationConsumption, ReservationEscrow, ReservationRole,
    SettlementOrder, StateLeg, ZERO,
};
use qomm_defmi::note_chain::{
    escrow_claim_serial, CsdIssuerControl, CsdIssuerControlKind, CsdIssuerDefinition,
    DelegatedNoteSettlementOrder, EscrowClaimSpend, NoteClaim, NoteClaimKind,
    NoteClaimMaterialization, NoteIssuance, NoteOutput, NoteReservationEscrow, NoteSettlementOrder,
    NoteSpend, ProductNoteReleaseOrder, ProductNoteSettlementBatch, ProductNoteSettlementOrder,
};
use qomm_defmi::product_evidence::ProductSettlementEvidence;
use qomm_defmi::settlement::{build_threshold_package_from_proofs, Sides};
use qomm_defmi::settlement_verifier::{settlement_verifier_key, SettlementVerifierConfig};
use qomm_proofs::opening_envelope::{EncryptedOpeningShare, OpeningEnvelope};
use qomm_proofs::price_limit::{from_threshold as threshold_price_limit, PriceLimitDirection};
use qomm_proofs::quote_proof::registered_policy_digest;
use qomm_transport::order::{
    complete_quote_context, decode_execution_attestations, live_proof_job_id,
    verify_admission_lane, verify_execution_lane, CertifiedAdmissionLane, NodeAdmissionAttestation,
};
use qomm_transport::proof_codec::{
    decode_dvp_proofs, decode_quote_verification, decode_threshold_range, QuoteVerificationBundle,
};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::{frost, typed, typed_wire, Bounds, Venue, DEFAULT_DOMAIN};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    state::{
        admission_committee_key, admission_entry_key, id_key, AccountRecord, AdmissionBatchRecord,
        AdmissionCommitteeRecord, AdmissionEntryRecord, AssetRecord, CreditFacilityRecord,
        CreditHoldRecord, CsdIssuerRecord, GuarantorRecord, NoteClaimRecord, NoteRecord,
        NoteReservationRecord, NoteSerialRecord, NullifierRecord, OpeningEnvelopeRecord,
        ReservationBindingRecord, ReservationEscrowRecord, SettlementVerifierRecord, State,
    },
    transaction::TransactionEnvelope,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovalDto {
    statement: String,
    signer_epoch: u64,
    domain: String,
    before_root: String,
    approvals: Vec<NodeApprovalDto>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NodeApprovalDto {
    #[serde(rename = "nodeID")]
    node_id: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AssetDto {
    #[serde(rename = "assetID")]
    asset_id: String,
    code: String,
    kind: String,
    decimals: u8,
    terms_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccountOpeningDto {
    handle: String,
    #[serde(rename = "assetID")]
    asset_id: String,
    commitment: String,
    issuance_nonce: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GuarantorDto {
    #[serde(rename = "guarantorID")]
    guarantor_id: String,
    kind: String,
    name: String,
    public_key: String,
    risk_policy_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SettlementDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    nullifier: String,
    deadline: u64,
    payment_instruction_digest: String,
    proof_digest: String,
    market_statement_digest: String,
    legs: Vec<StateLegDto>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StateLegDto {
    handle: String,
    #[serde(rename = "assetID")]
    asset_id: String,
    before_commitment: String,
    after_commitment: String,
    before_sequence: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CsdIssuerDto {
    #[serde(rename = "issuerID")]
    issuer_id: String,
    code: String,
    jurisdiction: String,
    operator_entity_commitment: String,
    public_key: String,
    #[serde(rename = "permittedAssetIDs")]
    permitted_asset_ids: Vec<String>,
    policy_digest: String,
    valid_from: u64,
    valid_until: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CsdIssuerControlDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "issuerID")]
    issuer_id: String,
    kind: String,
    before_sequence: u64,
    reason_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NoteOutputDto {
    #[serde(rename = "noteID")]
    note_id: String,
    #[serde(rename = "assetID")]
    asset_id: String,
    one_time: String,
    value_commitment: String,
    ephemeral: String,
    masked_value: String,
    masked_blinding: String,
    #[serde(rename = "lockID")]
    lock_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NoteIssuanceDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    issuance_nonce: String,
    #[serde(rename = "issuerID")]
    issuer_id: String,
    issued_at: u64,
    output: NoteOutputDto,
    proof_digest: String,
    issuer_signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NoteSpendDto {
    #[serde(rename = "assetID")]
    asset_id: String,
    ring: Vec<String>,
    ring_root: String,
    serial_point: String,
    #[serde(rename = "inputLockID")]
    input_lock_id: String,
    proof_digest: String,
    outputs: Vec<NoteOutputDto>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NoteSettlementDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    nullifier: String,
    deadline: u64,
    payment_instruction_digest: String,
    market_statement_digest: String,
    dvp_proof_digest: String,
    spends: Vec<NoteSpendDto>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NoteClaimMaterializationDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "claimID")]
    claim_id: String,
    output: NoteOutputDto,
    ownership_proof_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NoteReservationEscrowDto {
    spend: NoteSpendDto,
    #[serde(rename = "escrowNoteID")]
    escrow_note_id: String,
    delegation_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductNoteReleaseDto {
    transition: CreditTransitionDto,
    role: String,
    reserve_receipt_digest: String,
    typed_instruction_digest: String,
    release_nullifier: String,
    release_deadline: u64,
    #[serde(rename = "assetID")]
    asset_id: String,
    asset_link_proof_digest: String,
    #[serde(rename = "escrowNoteID")]
    escrow_note_id: String,
    spend: NoteSpendDto,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpeningShareDto {
    party: usize,
    ephemeral: String,
    masked_value: String,
    masked_blinding: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpeningEnvelopeDto {
    context: String,
    threshold: usize,
    recipient_view: String,
    shares: Vec<OpeningShareDto>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NoteClaimDto {
    #[serde(rename = "claimID")]
    claim_id: String,
    #[serde(rename = "assetID")]
    asset_id: String,
    value_commitment: String,
    recipient_commitment: String,
    #[serde(rename = "sourceHoldID")]
    source_hold_id: String,
    kind: String,
    opening_envelope: OpeningEnvelopeDto,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EscrowClaimSpendDto {
    #[serde(rename = "assetID")]
    asset_id: String,
    #[serde(rename = "holdID")]
    hold_id: String,
    #[serde(rename = "escrowNoteID")]
    escrow_note_id: String,
    delegation_digest: String,
    proof_digest: String,
    claims: Vec<NoteClaimDto>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DelegatedNoteSettlementDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    nullifier: String,
    deadline: u64,
    payment_instruction_digest: String,
    market_statement_digest: String,
    dvp_proof_digest: String,
    spends: Vec<EscrowClaimSpendDto>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductNoteSettlementDto {
    settlement: DelegatedNoteSettlementDto,
    #[serde(rename = "venueID")]
    venue_id: String,
    #[serde(rename = "defmiID")]
    defmi_id: String,
    maker_entity_commitment: String,
    taker_entity_commitment: String,
    rfq_nullifier: String,
    taker_authorization_digest: String,
    maker_policy_digest: String,
    maker_mandate_digest: String,
    taker_mandate_digest: String,
    typed_instruction_digest: String,
    quote_proof_digest: String,
    price_limit_proof_digest: String,
    dvp_proof_digest: String,
    quantity_commitment: String,
    cash_commitment: String,
    #[serde(rename = "tradedAssetID")]
    traded_asset_id: String,
    asset_link_proof_digest: String,
    admission_receipt_digest: String,
    admission_epoch: u64,
    admission_sequence: u64,
    reservations: Vec<ReservationConsumptionDto>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductSettlementEvidenceDto {
    typed_instruction: String,
    quote_verification: String,
    price_limit_proof: String,
    dvp_proofs: String,
    mpc_execution_attestations: String,
    asset_link: AssetLinkProofDto,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AssetLinkProofDto {
    announcement: String,
    response: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreditGrantDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "facilityID")]
    facility_id: String,
    #[serde(rename = "guarantorID")]
    guarantor_id: String,
    beneficiary_commitment: String,
    #[serde(rename = "railAssetID")]
    rail_asset_id: String,
    cap_commitment: String,
    available_commitment: String,
    held_commitment: String,
    outstanding_commitment: String,
    collateral_commitment: String,
    risk_policy_digest: String,
    relation_proof_digest: String,
    valid_from: u64,
    valid_until: u64,
    nonce: String,
    guarantor_signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreditTransitionDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "facilityID")]
    facility_id: String,
    #[serde(rename = "holdID")]
    hold_id: String,
    kind: String,
    query_commitment: String,
    amount_commitment: String,
    consumed_commitment: String,
    refund_commitment: String,
    before_available_commitment: String,
    after_available_commitment: String,
    before_held_commitment: String,
    after_held_commitment: String,
    before_outstanding_commitment: String,
    after_outstanding_commitment: String,
    before_sequence: u64,
    expires_at: u64,
    settlement_digest: String,
    relation_proof_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreditControlDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "facilityID")]
    facility_id: String,
    action: String,
    before_sequence: u64,
    effective_at: u64,
    reason_digest: String,
    guarantor_signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreditAmendmentDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "facilityID")]
    facility_id: String,
    mode: String,
    before_cap_commitment: String,
    after_cap_commitment: String,
    before_available_commitment: String,
    after_available_commitment: String,
    before_held_commitment: String,
    before_outstanding_commitment: String,
    before_overlimit_commitment: String,
    after_overlimit_commitment: String,
    before_collateral_commitment: String,
    after_collateral_commitment: String,
    before_risk_policy_digest: String,
    after_risk_policy_digest: String,
    before_valid_until: u64,
    after_valid_until: u64,
    before_sequence: u64,
    effective_at: u64,
    reason_digest: String,
    relation_proof_digest: String,
    guarantor_signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionCommitteeDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "venueID")]
    venue_id: String,
    epoch: u64,
    node_keys: Vec<String>,
    valid_from: u64,
    valid_until: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SettlementVerifierDto {
    #[serde(rename = "venueID")]
    venue_id: String,
    #[serde(rename = "defmiID")]
    defmi_id: String,
    epoch: u64,
    quote_registry_digest: String,
    quote_eligibility_bits: u16,
    quote_span_bits: u16,
    amount_bits: u16,
    price_bits: u16,
    max_horizon: u64,
    frost_public_package: String,
    valid_from: u64,
    valid_until: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionBatchDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "batchID")]
    batch_id: String,
    #[serde(rename = "venueID")]
    venue_id: String,
    epoch: u64,
    slot: u64,
    batch_digest: String,
    order_digest: String,
    admission_digests: Vec<String>,
    expires_at: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionAttestationDto {
    node: u16,
    slot: u64,
    sequence: u64,
    principal_digest: String,
    #[serde(rename = "ticketID")]
    ticket_id: String,
    claim_digest: String,
    batch_digest: String,
    order_digest: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionAdvanceDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "batchID")]
    batch_id: String,
    sequence: u64,
    admission_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReservationAuthorizationDto {
    role: String,
    entity_commitment: String,
    #[serde(rename = "assetID")]
    asset_id: String,
    direction: u8,
    authorization_digest: String,
    mandate_digest: String,
    typed_reserve_digest: String,
    reserve_nullifier: String,
    asset_link_proof_digest: String,
    limit_price_commitment: String,
    escrow_digest: String,
    rfq_nullifier: String,
    policy_version: u64,
    #[serde(rename = "admissionTicketID")]
    admission_ticket_id: String,
    admission_slot: u64,
    admission_receipt_digest: String,
    admission_epoch: u64,
    admission_sequence: u64,
    #[serde(rename = "admissionBatchID")]
    admission_batch_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReservationEscrowDto {
    source_handle: String,
    escrow_handle: String,
    #[serde(rename = "assetID")]
    asset_id: String,
    amount_commitment: String,
    source_before_commitment: String,
    source_after_commitment: String,
    source_before_sequence: u64,
    proof_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReservationConsumptionDto {
    role: String,
    reserve_receipt_digest: String,
    transition: CreditTransitionDto,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductSettlementDto {
    settlement: SettlementDto,
    #[serde(rename = "venueID")]
    venue_id: String,
    #[serde(rename = "defmiID")]
    defmi_id: String,
    maker_entity_commitment: String,
    taker_entity_commitment: String,
    rfq_nullifier: String,
    taker_authorization_digest: String,
    maker_policy_digest: String,
    maker_mandate_digest: String,
    taker_mandate_digest: String,
    typed_instruction_digest: String,
    quote_proof_digest: String,
    price_limit_proof_digest: String,
    dvp_proof_digest: String,
    quantity_commitment: String,
    cash_commitment: String,
    #[serde(rename = "tradedAssetID")]
    traded_asset_id: String,
    asset_link_proof_digest: String,
    admission_receipt_digest: String,
    admission_epoch: u64,
    admission_sequence: u64,
    reservations: Vec<ReservationConsumptionDto>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductSettlementBatchDto {
    #[serde(rename = "batchID")]
    batch_id: String,
    #[serde(rename = "venueID")]
    venue_id: String,
    #[serde(rename = "defmiID")]
    defmi_id: String,
    admission_epoch: u64,
    members: Vec<ProductSettlementBatchMemberDto>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductSettlementBatchMemberDto {
    admission_sequence: u64,
    settlement_statement: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductReleaseDto {
    transition: CreditTransitionDto,
    role: String,
    reserve_receipt_digest: String,
    typed_instruction_digest: String,
    release_nullifier: String,
    release_deadline: u64,
    #[serde(rename = "assetID")]
    asset_id: String,
    asset_link_proof_digest: String,
    refund_leg: StateLegDto,
}

pub(crate) fn execute(
    state: &mut State,
    transaction: &TransactionEnvelope,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    let params = transaction
        .params
        .as_object()
        .ok_or_else(|| "transaction parameters must be an object".to_string())?;
    match transaction.method.as_str() {
        "defmivm.issueAsset" => register_asset(state, params, authorizer),
        "defmivm.issueCSDIssuer" => register_csd_issuer(state, params, authorizer, timestamp),
        "defmivm.issueCSDIssuerControl" => control_csd_issuer(state, params, authorizer),
        "defmivm.issueNote" => issue_note(state, params, authorizer, timestamp),
        "defmivm.issueNoteClaimMaterialization" => {
            materialize_note_claim(state, params, authorizer)
        }
        "defmivm.issueNoteSettlement" => settle_notes(state, params, authorizer, timestamp),
        "defmivm.issueAdmissionCommittee" => {
            register_admission_committee(state, params, authorizer, timestamp)
        }
        "defmivm.issueSettlementVerifier" => {
            register_settlement_verifier(state, params, authorizer, timestamp)
        }
        "defmivm.issueAdmissionBatch" => {
            register_admission_batch(state, params, authorizer, timestamp)
        }
        "defmivm.issueAdmissionAdvance" => advance_admission(state, params, authorizer, timestamp),
        "defmivm.issueProductReservation" => reserve_product(state, params, authorizer, timestamp),
        "defmivm.issueNoteProductReservation" => {
            reserve_note_product(state, params, authorizer, timestamp)
        }
        "defmivm.issueProductRelease" => release_product(state, params, authorizer, timestamp),
        "defmivm.issueNoteProductRelease" => {
            release_note_product(state, params, authorizer, timestamp)
        }
        "defmivm.issueProductSettlement" => settle_product(state, params, authorizer, timestamp),
        "defmivm.issueProductSettlementBatch" => {
            settle_product_batch(state, params, authorizer, timestamp)
        }
        "defmivm.issueNoteProductSettlement" => {
            settle_note_product(state, params, authorizer, timestamp)
        }
        "defmivm.issueNoteProductSettlementBatch" => {
            settle_note_product_batch(state, params, authorizer, timestamp)
        }
        "defmivm.issueAccount" => open_account(state, params, authorizer),
        "defmivm.issueGuarantor" => register_guarantor(state, params, authorizer),
        "defmivm.issueCreditGrant" => grant_credit(state, params, authorizer, timestamp),
        "defmivm.issueCreditTransition" => transition_credit(state, params, authorizer, timestamp),
        "defmivm.issueCreditControl" => control_credit(state, params, authorizer, timestamp),
        "defmivm.issueCreditAmendment" => amend_credit(state, params, authorizer, timestamp),
        "defmivm.issueSettlement" => settle(state, params, authorizer, timestamp),
        method => Err(format!(
            "{method} has no Rust consensus executor in this build"
        )),
    }
}

fn csd_issuer_from_dto(dto: CsdIssuerDto) -> Result<CsdIssuerDefinition, String> {
    Ok(CsdIssuerDefinition {
        issuer_id: hex_array(&dto.issuer_id, "issuer.issuerID")?,
        code: dto.code,
        jurisdiction: dto.jurisdiction,
        operator_entity_commitment: hex_array(
            &dto.operator_entity_commitment,
            "issuer.operatorEntityCommitment",
        )?,
        public_key: hex_array(&dto.public_key, "issuer.publicKey")?,
        permitted_asset_ids: dto
            .permitted_asset_ids
            .iter()
            .map(|asset_id| hex_array(asset_id, "issuer.permittedAssetIDs"))
            .collect::<Result<Vec<_>, _>>()?,
        policy_digest: hex_array(&dto.policy_digest, "issuer.policyDigest")?,
        valid_from: dto.valid_from,
        valid_until: dto.valid_until,
    })
}

fn csd_control_from_dto(dto: CsdIssuerControlDto) -> Result<CsdIssuerControl, String> {
    Ok(CsdIssuerControl {
        operation_id: hex_array(&dto.operation_id, "control.operationID")?,
        issuer_id: hex_array(&dto.issuer_id, "control.issuerID")?,
        kind: match dto.kind.as_str() {
            "activate" => CsdIssuerControlKind::Activate,
            "suspend" => CsdIssuerControlKind::Suspend,
            "revoke" => CsdIssuerControlKind::Revoke,
            _ => return Err("control.kind is not supported".into()),
        },
        before_sequence: dto.before_sequence,
        reason_digest: hex_array(&dto.reason_digest, "control.reasonDigest")?,
    })
}

fn note_output_from_dto(dto: NoteOutputDto, field_name: &str) -> Result<NoteOutput, String> {
    let output = NoteOutput {
        note_id: hex_array(&dto.note_id, &format!("{field_name}.noteID"))?,
        asset_id: hex_array(&dto.asset_id, &format!("{field_name}.assetID"))?,
        one_time: hex_array(&dto.one_time, &format!("{field_name}.oneTime"))?,
        value_commitment: hex_array(
            &dto.value_commitment,
            &format!("{field_name}.valueCommitment"),
        )?,
        ephemeral: hex_array(&dto.ephemeral, &format!("{field_name}.ephemeral"))?,
        masked_value: hex_array(&dto.masked_value, &format!("{field_name}.maskedValue"))?,
        masked_blinding: hex_array(
            &dto.masked_blinding,
            &format!("{field_name}.maskedBlinding"),
        )?,
        lock_id: hex_array(&dto.lock_id, &format!("{field_name}.lockID"))?,
    };
    output.validate()?;
    Ok(output)
}

fn note_spend_from_dto(dto: NoteSpendDto, field_name: &str) -> Result<NoteSpend, String> {
    let spend = NoteSpend {
        asset_id: hex_array(&dto.asset_id, &format!("{field_name}.assetID"))?,
        ring: dto
            .ring
            .iter()
            .map(|note_id| hex_array(note_id, &format!("{field_name}.ring")))
            .collect::<Result<Vec<_>, _>>()?,
        ring_root: hex_array(&dto.ring_root, &format!("{field_name}.ringRoot"))?,
        serial_point: hex_array(&dto.serial_point, &format!("{field_name}.serialPoint"))?,
        input_lock_id: hex_array(&dto.input_lock_id, &format!("{field_name}.inputLockID"))?,
        proof_digest: hex_array(&dto.proof_digest, &format!("{field_name}.proofDigest"))?,
        outputs: dto
            .outputs
            .into_iter()
            .enumerate()
            .map(|(index, output)| {
                note_output_from_dto(output, &format!("{field_name}.outputs[{index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    spend.validate()?;
    Ok(spend)
}

fn note_order_from_dto(dto: NoteSettlementDto) -> Result<NoteSettlementOrder, String> {
    let order = NoteSettlementOrder {
        operation_id: hex_array(&dto.operation_id, "order.operationID")?,
        nullifier: hex_array(&dto.nullifier, "order.nullifier")?,
        deadline: dto.deadline,
        payment_instruction_digest: hex_array(
            &dto.payment_instruction_digest,
            "order.paymentInstructionDigest",
        )?,
        market_statement_digest: hex_array(
            &dto.market_statement_digest,
            "order.marketStatementDigest",
        )?,
        dvp_proof_digest: hex_array(&dto.dvp_proof_digest, "order.dvpProofDigest")?,
        spends: dto
            .spends
            .into_iter()
            .enumerate()
            .map(|(index, spend)| note_spend_from_dto(spend, &format!("order.spends[{index}]")))
            .collect::<Result<Vec<_>, _>>()?,
    };
    order.body()?;
    Ok(order)
}

fn opening_envelope_from_dto(
    dto: OpeningEnvelopeDto,
    field_name: &str,
) -> Result<OpeningEnvelope, String> {
    let point = |encoded: &str, name: &str| {
        CompressedRistretto(hex_array(encoded, name)?)
            .decompress()
            .ok_or_else(|| format!("{name} is not a canonical Ristretto point"))
    };
    let scalar = |encoded: &str, name: &str| {
        Option::<Scalar>::from(Scalar::from_canonical_bytes(hex_array(encoded, name)?))
            .ok_or_else(|| format!("{name} is not a canonical scalar"))
    };
    OpeningEnvelope::new(
        hex_array(&dto.context, &format!("{field_name}.context"))?,
        dto.threshold,
        point(&dto.recipient_view, &format!("{field_name}.recipientView"))?,
        dto.shares
            .into_iter()
            .enumerate()
            .map(|(index, share)| {
                let share_name = format!("{field_name}.shares[{index}]");
                Ok(EncryptedOpeningShare {
                    party: share.party,
                    ephemeral: point(&share.ephemeral, &format!("{share_name}.ephemeral"))?,
                    masked_value: scalar(
                        &share.masked_value,
                        &format!("{share_name}.maskedValue"),
                    )?,
                    masked_blinding: scalar(
                        &share.masked_blinding,
                        &format!("{share_name}.maskedBlinding"),
                    )?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    )
}

fn note_claim_from_dto(dto: NoteClaimDto, field_name: &str) -> Result<NoteClaim, String> {
    let claim = NoteClaim {
        claim_id: hex_array(&dto.claim_id, &format!("{field_name}.claimID"))?,
        asset_id: hex_array(&dto.asset_id, &format!("{field_name}.assetID"))?,
        value_commitment: hex_array(
            &dto.value_commitment,
            &format!("{field_name}.valueCommitment"),
        )?,
        recipient_commitment: hex_array(
            &dto.recipient_commitment,
            &format!("{field_name}.recipientCommitment"),
        )?,
        source_hold_id: hex_array(&dto.source_hold_id, &format!("{field_name}.sourceHoldID"))?,
        kind: match dto.kind.as_str() {
            "delivery" => NoteClaimKind::Delivery,
            "refund" => NoteClaimKind::Refund,
            _ => return Err(format!("{field_name}.kind is not supported")),
        },
        opening_envelope: opening_envelope_from_dto(
            dto.opening_envelope,
            &format!("{field_name}.openingEnvelope"),
        )?,
    };
    claim.validate()?;
    Ok(claim)
}

fn delegated_note_settlement_from_dto(
    dto: DelegatedNoteSettlementDto,
    field_name: &str,
) -> Result<DelegatedNoteSettlementOrder, String> {
    let order = DelegatedNoteSettlementOrder {
        operation_id: hex_array(&dto.operation_id, &format!("{field_name}.operationID"))?,
        nullifier: hex_array(&dto.nullifier, &format!("{field_name}.nullifier"))?,
        deadline: dto.deadline,
        payment_instruction_digest: hex_array(
            &dto.payment_instruction_digest,
            &format!("{field_name}.paymentInstructionDigest"),
        )?,
        market_statement_digest: hex_array(
            &dto.market_statement_digest,
            &format!("{field_name}.marketStatementDigest"),
        )?,
        dvp_proof_digest: hex_array(
            &dto.dvp_proof_digest,
            &format!("{field_name}.dvpProofDigest"),
        )?,
        spends: dto
            .spends
            .into_iter()
            .enumerate()
            .map(|(spend_index, spend)| {
                let spend_name = format!("{field_name}.spends[{spend_index}]");
                Ok(EscrowClaimSpend {
                    asset_id: hex_array(&spend.asset_id, &format!("{spend_name}.assetID"))?,
                    hold_id: hex_array(&spend.hold_id, &format!("{spend_name}.holdID"))?,
                    escrow_note_id: hex_array(
                        &spend.escrow_note_id,
                        &format!("{spend_name}.escrowNoteID"),
                    )?,
                    delegation_digest: hex_array(
                        &spend.delegation_digest,
                        &format!("{spend_name}.delegationDigest"),
                    )?,
                    proof_digest: hex_array(
                        &spend.proof_digest,
                        &format!("{spend_name}.proofDigest"),
                    )?,
                    claims: spend
                        .claims
                        .into_iter()
                        .enumerate()
                        .map(|(claim_index, claim)| {
                            note_claim_from_dto(
                                claim,
                                &format!("{spend_name}.claims[{claim_index}]"),
                            )
                        })
                        .collect::<Result<Vec<_>, String>>()?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    };
    order.body()?;
    Ok(order)
}

fn register_csd_issuer(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["issuer", "approval", "expectedBeforeRoot"])?;
    let issuer = csd_issuer_from_dto(field(params, "issuer")?)?;
    issuer.body()?;
    let statement = issuer.statement()?;
    authorize(state, params, statement, authorizer)?;
    if timestamp == 0 || issuer.valid_until < timestamp {
        return Err("CSD issuer validity already ended".into());
    }
    if issuer.permitted_asset_ids.iter().any(|asset_id| {
        !state
            .assets
            .get(&id_key(asset_id))
            .is_some_and(|asset| asset.active)
    }) {
        return Err("CSD issuer permits an inactive or unknown asset".into());
    }
    let key = id_key(&issuer.issuer_id);
    if state.csd_issuers.contains_key(&key) {
        return Err("CSD issuer identifier was already registered".into());
    }
    state.csd_issuers.insert(
        key,
        CsdIssuerRecord {
            code: issuer.code,
            jurisdiction: issuer.jurisdiction,
            operator_entity_commitment: issuer.operator_entity_commitment,
            public_key: issuer.public_key,
            permitted_asset_ids: issuer.permitted_asset_ids,
            policy_digest: issuer.policy_digest,
            valid_from: issuer.valid_from,
            valid_until: issuer.valid_until,
            status: "active".into(),
            sequence: 0,
        },
    );
    Ok(statement)
}

fn control_csd_issuer(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
) -> Result<[u8; 32], String> {
    require_keys(params, &["control", "approval", "expectedBeforeRoot"])?;
    let control = csd_control_from_dto(field(params, "control")?)?;
    control.body()?;
    let statement = control.statement()?;
    authorize(state, params, statement, authorizer)?;
    if state
        .operations
        .contains_key(&id_key(&control.operation_id))
    {
        return Err("operation identifier was already used".into());
    }
    let key = id_key(&control.issuer_id);
    let record = state
        .csd_issuers
        .get_mut(&key)
        .ok_or_else(|| "CSD issuer is unknown".to_string())?;
    if record.sequence != control.before_sequence || record.status == "revoked" {
        return Err("CSD issuer control used stale or terminal state".into());
    }
    match control.kind {
        CsdIssuerControlKind::Activate if record.status == "suspended" => {
            record.status = "active".into();
        }
        CsdIssuerControlKind::Suspend if record.status == "active" => {
            record.status = "suspended".into();
        }
        CsdIssuerControlKind::Revoke => record.status = "revoked".into(),
        CsdIssuerControlKind::Activate => {
            return Err("only a suspended CSD issuer can be activated".into());
        }
        CsdIssuerControlKind::Suspend => {
            return Err("only an active CSD issuer can be suspended".into());
        }
    }
    record.sequence = record
        .sequence
        .checked_add(1)
        .ok_or_else(|| "CSD issuer sequence overflow".to_string())?;
    state
        .operations
        .insert(id_key(&control.operation_id), statement);
    Ok(statement)
}

fn insert_note(state: &mut State, output: &NoteOutput) -> Result<(), String> {
    output.validate()?;
    if !state
        .assets
        .get(&id_key(&output.asset_id))
        .is_some_and(|asset| asset.active)
    {
        return Err("note output belongs to an inactive or unknown asset".into());
    }
    let key = id_key(&output.note_id);
    if state.notes.contains_key(&key) {
        return Err("note output identifier was already used".into());
    }
    state.notes.insert(
        key,
        NoteRecord {
            asset_id: output.asset_id,
            one_time: output.one_time,
            value_commitment: output.value_commitment,
            ephemeral: output.ephemeral,
            masked_value: output.masked_value,
            masked_blinding: output.masked_blinding,
            lock_id: output.lock_id,
        },
    );
    Ok(())
}

fn issue_note(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["issuance", "approval", "expectedBeforeRoot"])?;
    let dto: NoteIssuanceDto = field(params, "issuance")?;
    let issuance = NoteIssuance {
        operation_id: hex_array(&dto.operation_id, "issuance.operationID")?,
        issuance_nonce: hex_array(&dto.issuance_nonce, "issuance.issuanceNonce")?,
        issuer_id: hex_array(&dto.issuer_id, "issuance.issuerID")?,
        issued_at: dto.issued_at,
        output: note_output_from_dto(dto.output, "issuance.output")?,
        proof_digest: hex_array(&dto.proof_digest, "issuance.proofDigest")?,
        issuer_signature: Signature::from_bytes(&hex_array::<64>(
            &dto.issuer_signature,
            "issuance.issuerSignature",
        )?),
    };
    issuance.body()?;
    let statement = issuance.statement()?;
    authorize(state, params, statement, authorizer)?;
    if timestamp == 0 {
        return Err("note issuance has no consensus timestamp".into());
    }
    if state
        .operations
        .contains_key(&id_key(&issuance.operation_id))
        || state
            .note_issuances
            .contains_key(&id_key(&issuance.issuance_nonce))
        || state.notes.contains_key(&id_key(&issuance.output.note_id))
    {
        return Err("note issuance reuses an operation, nonce, or note".into());
    }
    let issuer = state
        .csd_issuers
        .get(&id_key(&issuance.issuer_id))
        .ok_or_else(|| "note issuance names an unknown CSD issuer".to_string())?;
    if issuer.status != "active" {
        return Err("CSD issuer is not active".into());
    }
    issuance.verify_issuer(&issuer.definition(issuance.issuer_id), timestamp)?;
    insert_note(state, &issuance.output)?;
    state
        .note_issuances
        .insert(id_key(&issuance.issuance_nonce), statement);
    state
        .operations
        .insert(id_key(&issuance.operation_id), statement);
    Ok(statement)
}

fn materialize_note_claim(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &["materialization", "approval", "expectedBeforeRoot"],
    )?;
    let dto: NoteClaimMaterializationDto = field(params, "materialization")?;
    let materialization = NoteClaimMaterialization {
        operation_id: hex_array(&dto.operation_id, "materialization.operationID")?,
        claim_id: hex_array(&dto.claim_id, "materialization.claimID")?,
        output: note_output_from_dto(dto.output, "materialization.output")?,
        ownership_proof_digest: hex_array(
            &dto.ownership_proof_digest,
            "materialization.ownershipProofDigest",
        )?,
    };
    materialization.body()?;
    let statement = materialization.statement()?;
    authorize(state, params, statement, authorizer)?;
    if state
        .operations
        .contains_key(&id_key(&materialization.operation_id))
    {
        return Err("operation identifier was already used".into());
    }
    let claim_key = id_key(&materialization.claim_id);
    let mut claim = state
        .note_claims
        .get(&claim_key)
        .cloned()
        .ok_or_else(|| "note claim is unknown".to_string())?;
    if claim.status != "active"
        || claim.materialization != ZERO
        || claim.asset_id != materialization.output.asset_id
        || claim.value_commitment != materialization.output.value_commitment
    {
        return Err("claim materialization changes a final entitlement".into());
    }
    insert_note(state, &materialization.output)?;
    claim.status = "materialized".into();
    claim.materialization = statement;
    state.note_claims.insert(claim_key, claim);
    state
        .operations
        .insert(id_key(&materialization.operation_id), statement);
    Ok(statement)
}

fn check_note_spend(
    state: &State,
    spend: &NoteSpend,
    required_note: Option<[u8; 32]>,
    require_unlocked_ring: bool,
) -> Result<(), String> {
    spend.validate()?;
    if !state
        .assets
        .get(&id_key(&spend.asset_id))
        .is_some_and(|asset| asset.active)
    {
        return Err("note spend uses an inactive or unknown asset".into());
    }
    if state
        .note_serials
        .contains_key(&id_key(&spend.serial_point))
    {
        return Err("note serial was already settled".into());
    }
    let mut required_found = required_note.is_none();
    for note_id in &spend.ring {
        let note = state
            .notes
            .get(&id_key(note_id))
            .ok_or_else(|| "note anonymity set names an unknown note".to_string())?;
        if note.asset_id != spend.asset_id {
            return Err("note anonymity set crosses asset rails".into());
        }
        if require_unlocked_ring && note.lock_id != ZERO {
            return Err("ordinary note spend includes a reservation-locked note".into());
        }
        if required_note == Some(*note_id) && note.lock_id == spend.input_lock_id {
            required_found = true;
        }
    }
    if !required_found {
        return Err("anonymity set omits the required escrow note".into());
    }
    if spend
        .outputs
        .iter()
        .any(|output| state.notes.contains_key(&id_key(&output.note_id)))
    {
        return Err("note spend reuses an existing output".into());
    }
    Ok(())
}

fn apply_note_spend(
    state: &mut State,
    spend: &NoteSpend,
    deadline: u64,
    statement: [u8; 32],
) -> Result<(), String> {
    let serial_key = id_key(&spend.serial_point);
    if state.note_serials.contains_key(&serial_key) {
        return Err("note serial was already settled".into());
    }
    state.note_serials.insert(
        serial_key,
        NoteSerialRecord {
            deadline,
            asset_id: spend.asset_id,
            ring_root: spend.ring_root,
            statement,
        },
    );
    for output in &spend.outputs {
        insert_note(state, output)?;
    }
    Ok(())
}

fn settle_notes(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["order", "approval", "expectedBeforeRoot"])?;
    let order = note_order_from_dto(field(params, "order")?)?;
    let statement = order.statement()?;
    authorize(state, params, statement, authorizer)?;
    if timestamp > order.deadline {
        return Err("note settlement has expired".into());
    }
    if state.operations.contains_key(&id_key(&order.operation_id)) {
        return Err("operation identifier was already used".into());
    }
    if state.nullifiers.contains_key(&id_key(&order.nullifier)) {
        return Err("payment nullifier was already settled".into());
    }
    for spend in &order.spends {
        if spend.input_lock_id != ZERO {
            return Err("ordinary note settlement cannot consume a reservation lock".into());
        }
        check_note_spend(state, spend, None, true)?;
        if spend.outputs.iter().any(|output| output.lock_id != ZERO) {
            return Err("ordinary note settlement cannot create a reservation lock".into());
        }
    }
    state.nullifiers.insert(
        id_key(&order.nullifier),
        NullifierRecord {
            deadline: order.deadline,
            statement,
        },
    );
    state
        .operations
        .insert(id_key(&order.operation_id), statement);
    for spend in &order.spends {
        apply_note_spend(state, spend, order.deadline, statement)?;
    }
    Ok(statement)
}

fn register_admission_committee(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["plan", "approval", "expectedBeforeRoot"])?;
    let dto: AdmissionCommitteeDto = field(params, "plan")?;
    if dto.node_keys.len() > qomm_transport::order::COMMITTEE_NODES {
        return Err("admission committee contains too many node keys".into());
    }
    let plan = AdmissionCommitteePlan {
        operation_id: hex_array(&dto.operation_id, "plan.operationID")?,
        venue_id: hex_array(&dto.venue_id, "plan.venueID")?,
        epoch: dto.epoch,
        node_keys: dto
            .node_keys
            .iter()
            .map(|key| hex_array(key, "plan.nodeKeys"))
            .collect::<Result<Vec<_>, _>>()?,
        valid_from: dto.valid_from,
        valid_until: dto.valid_until,
    };
    plan.body()?;
    let statement = plan.statement()?;
    authorize(state, params, statement, authorizer)?;
    if timestamp < plan.valid_from || timestamp > plan.valid_until {
        return Err("admission committee is not currently valid".into());
    }
    if state.operations.contains_key(&id_key(&plan.operation_id)) {
        return Err("operation identifier was already used".into());
    }
    let key = admission_committee_key(&plan.venue_id, plan.epoch);
    if state.admission_committees.contains_key(&key) {
        return Err("admission committee venue and epoch were reused".into());
    }
    state.admission_committees.insert(
        key,
        AdmissionCommitteeRecord {
            venue_id: plan.venue_id,
            epoch: plan.epoch,
            node_keys: plan.node_keys,
            valid_from: plan.valid_from,
            valid_until: plan.valid_until,
            statement,
        },
    );
    state
        .operations
        .insert(id_key(&plan.operation_id), statement);
    Ok(statement)
}

fn register_settlement_verifier(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["config", "approval", "expectedBeforeRoot"])?;
    let dto: SettlementVerifierDto = field(params, "config")?;
    let config = SettlementVerifierConfig {
        venue_id: hex_array(&dto.venue_id, "config.venueID")?,
        defmi_id: hex_array(&dto.defmi_id, "config.defmiID")?,
        epoch: dto.epoch,
        quote_registry_digest: hex_array(&dto.quote_registry_digest, "config.quoteRegistryDigest")?,
        quote_eligibility_bits: dto.quote_eligibility_bits,
        quote_span_bits: dto.quote_span_bits,
        amount_bits: dto.amount_bits,
        price_bits: dto.price_bits,
        max_horizon: dto.max_horizon,
        frost_public_package: BASE64
            .decode(dto.frost_public_package)
            .map_err(|_| "config.frostPublicPackage is not valid base64".to_string())?,
        valid_from: dto.valid_from,
        valid_until: dto.valid_until,
    };
    let statement = config.statement()?;
    authorize(state, params, statement, authorizer)?;
    if timestamp < config.valid_from || timestamp > config.valid_until {
        return Err("settlement verifier is not currently valid".into());
    }
    let key = id_key(&config.key());
    if state.settlement_verifiers.contains_key(&key) {
        return Err("settlement verifier venue and epoch were reused".into());
    }
    state.settlement_verifiers.insert(
        key,
        SettlementVerifierRecord {
            venue_id: config.venue_id,
            defmi_id: config.defmi_id,
            epoch: config.epoch,
            quote_registry_digest: config.quote_registry_digest,
            quote_eligibility_bits: config.quote_eligibility_bits,
            quote_span_bits: config.quote_span_bits,
            amount_bits: config.amount_bits,
            price_bits: config.price_bits,
            max_horizon: config.max_horizon,
            frost_public_package: config.frost_public_package,
            valid_from: config.valid_from,
            valid_until: config.valid_until,
            statement,
        },
    );
    Ok(statement)
}

fn register_admission_batch(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &["plan", "admissionLanes", "approval", "expectedBeforeRoot"],
    )?;
    let dto: AdmissionBatchDto = field(params, "plan")?;
    if dto.admission_digests.len() > 4096 {
        return Err("admission batch contains too many lanes".into());
    }
    let plan = AdmissionBatchPlan {
        operation_id: hex_array(&dto.operation_id, "plan.operationID")?,
        batch_id: hex_array(&dto.batch_id, "plan.batchID")?,
        venue_id: hex_array(&dto.venue_id, "plan.venueID")?,
        epoch: dto.epoch,
        slot: dto.slot,
        batch_digest: hex_array(&dto.batch_digest, "plan.batchDigest")?,
        order_digest: hex_array(&dto.order_digest, "plan.orderDigest")?,
        admission_digests: dto
            .admission_digests
            .iter()
            .map(|digest| hex_array(digest, "plan.admissionDigests"))
            .collect::<Result<Vec<_>, _>>()?,
        expires_at: dto.expires_at,
    };
    plan.body()?;
    let statement = plan.statement()?;
    authorize(state, params, statement, authorizer)?;
    if timestamp > plan.expires_at {
        return Err("admission batch has expired".into());
    }
    if state.operations.contains_key(&id_key(&plan.operation_id)) {
        return Err("operation identifier was already used".into());
    }
    if state
        .admission_batches
        .contains_key(&id_key(&plan.batch_id))
        || state.admission_batches.values().any(|batch| {
            batch.venue_id == plan.venue_id
                && batch.epoch == plan.epoch
                && batch.slot == plan.slot
                && batch.batch_digest == plan.batch_digest
        })
    {
        return Err("admission batch identifier or scope was reused".into());
    }
    let committee = state
        .admission_committees
        .get(&admission_committee_key(&plan.venue_id, plan.epoch))
        .ok_or_else(|| "admission batch has no governance-pinned resident committee".to_string())?;
    if timestamp < committee.valid_from || timestamp > committee.valid_until {
        return Err("admission committee is not currently valid".into());
    }
    let trusted_keys = committee
        .node_keys
        .iter()
        .map(|key| {
            VerifyingKey::from_bytes(key)
                .map_err(|_| "stored admission committee key is invalid".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let lane_dtos: Vec<Vec<AdmissionAttestationDto>> = field(params, "admissionLanes")?;
    if lane_dtos.len() != plan.admission_digests.len() {
        return Err("admission batch differs from its certified population".into());
    }
    let mut certified = lane_dtos
        .into_iter()
        .map(|lane| {
            if lane.len() != qomm_transport::order::COMMITTEE_NODES {
                return Err("admission lane needs exactly seven attestations".to_string());
            }
            let attestations = lane
                .into_iter()
                .map(|dto| {
                    Ok(NodeAdmissionAttestation {
                        node: dto.node,
                        slot: dto.slot,
                        sequence: dto.sequence,
                        principal_digest: hex_array(
                            &dto.principal_digest,
                            "admissionLanes.principalDigest",
                        )?,
                        ticket_id: hex_array(&dto.ticket_id, "admissionLanes.ticketID")?,
                        claim_digest: hex_array(&dto.claim_digest, "admissionLanes.claimDigest")?,
                        batch_digest: hex_array(&dto.batch_digest, "admissionLanes.batchDigest")?,
                        order_digest: hex_array(&dto.order_digest, "admissionLanes.orderDigest")?,
                        signature: Signature::from_bytes(&hex_array(
                            &dto.signature,
                            "admissionLanes.signature",
                        )?),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            verify_admission_lane(&attestations, &trusted_keys)
        })
        .collect::<Result<Vec<_>, _>>()?;
    certified.sort_by_key(|lane| lane.sequence);
    if certified.iter().enumerate().any(|(index, lane)| {
        lane.sequence != index as u64 + 1
            || lane.slot != plan.slot
            || lane.cluster_digest != plan.batch_digest
            || lane.order_digest != plan.order_digest
            || lane.digest(plan.venue_id, plan.epoch).ok()
                != plan.admission_digests.get(index).copied()
    }) {
        return Err("admission batch differs from its seven-node certified population".into());
    }
    state.admission_batches.insert(
        id_key(&plan.batch_id),
        AdmissionBatchRecord {
            venue_id: plan.venue_id,
            epoch: plan.epoch,
            slot: plan.slot,
            batch_digest: plan.batch_digest,
            order_digest: plan.order_digest,
            population: plan.admission_digests.len() as u64,
            consumed: 0,
            expires_at: plan.expires_at,
            statement,
        },
    );
    for (index, admission_digest) in plan.admission_digests.into_iter().enumerate() {
        let sequence = index as u64 + 1;
        state.admission_entries.insert(
            admission_entry_key(&plan.batch_id, sequence),
            AdmissionEntryRecord {
                batch_id: plan.batch_id,
                sequence,
                admission_digest,
                consumed_by: ZERO,
            },
        );
    }
    state
        .operations
        .insert(id_key(&plan.operation_id), statement);
    Ok(statement)
}

fn advance_admission(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["advance", "approval", "expectedBeforeRoot"])?;
    let dto: AdmissionAdvanceDto = field(params, "advance")?;
    let advance = AdmissionSlotAdvance {
        operation_id: hex_array(&dto.operation_id, "advance.operationID")?,
        batch_id: hex_array(&dto.batch_id, "advance.batchID")?,
        sequence: dto.sequence,
        admission_digest: hex_array(&dto.admission_digest, "advance.admissionDigest")?,
    };
    advance.body()?;
    let statement = advance.statement()?;
    authorize(state, params, statement, authorizer)?;
    if state
        .operations
        .contains_key(&id_key(&advance.operation_id))
    {
        return Err("operation identifier was already used".into());
    }
    let batch_key = id_key(&advance.batch_id);
    let mut batch = state
        .admission_batches
        .get(&batch_key)
        .cloned()
        .ok_or_else(|| "admission advance names an unknown batch".to_string())?;
    if timestamp > batch.expires_at {
        return Err("admission batch has expired".into());
    }
    if advance.sequence != batch.consumed + 1 || advance.sequence > batch.population {
        return Err("admission lane is not the next fixed-population sequence".into());
    }
    let entry = state
        .admission_entries
        .get_mut(&admission_entry_key(&advance.batch_id, advance.sequence))
        .ok_or_else(|| "admission plan omits its next sequence".to_string())?;
    if entry.admission_digest != advance.admission_digest || entry.consumed_by != ZERO {
        return Err("admission lane differs from the plan or was already consumed".into());
    }
    entry.consumed_by = advance.operation_id;
    batch.consumed = advance.sequence;
    state.admission_batches.insert(batch_key, batch);
    state
        .operations
        .insert(id_key(&advance.operation_id), statement);
    Ok(statement)
}

fn credit_transition_from_dto(
    dto: CreditTransitionDto,
    field_name: &str,
) -> Result<CreditFacilityTransition, String> {
    Ok(CreditFacilityTransition {
        operation_id: hex_array(&dto.operation_id, &format!("{field_name}.operationID"))?,
        facility_id: hex_array(&dto.facility_id, &format!("{field_name}.facilityID"))?,
        hold_id: hex_array(&dto.hold_id, &format!("{field_name}.holdID"))?,
        kind: match dto.kind.as_str() {
            "hold" => CreditTransitionKind::Hold,
            "release" => CreditTransitionKind::Release,
            "consume" => CreditTransitionKind::Consume,
            _ => return Err(format!("{field_name}.kind is not supported")),
        },
        query_commitment: hex_array(
            &dto.query_commitment,
            &format!("{field_name}.queryCommitment"),
        )?,
        amount_commitment: hex_array(
            &dto.amount_commitment,
            &format!("{field_name}.amountCommitment"),
        )?,
        consumed_commitment: hex_array(
            &dto.consumed_commitment,
            &format!("{field_name}.consumedCommitment"),
        )?,
        refund_commitment: hex_array(
            &dto.refund_commitment,
            &format!("{field_name}.refundCommitment"),
        )?,
        before_available_commitment: hex_array(
            &dto.before_available_commitment,
            &format!("{field_name}.beforeAvailableCommitment"),
        )?,
        after_available_commitment: hex_array(
            &dto.after_available_commitment,
            &format!("{field_name}.afterAvailableCommitment"),
        )?,
        before_held_commitment: hex_array(
            &dto.before_held_commitment,
            &format!("{field_name}.beforeHeldCommitment"),
        )?,
        after_held_commitment: hex_array(
            &dto.after_held_commitment,
            &format!("{field_name}.afterHeldCommitment"),
        )?,
        before_outstanding_commitment: hex_array(
            &dto.before_outstanding_commitment,
            &format!("{field_name}.beforeOutstandingCommitment"),
        )?,
        after_outstanding_commitment: hex_array(
            &dto.after_outstanding_commitment,
            &format!("{field_name}.afterOutstandingCommitment"),
        )?,
        before_sequence: dto.before_sequence,
        expires_at: dto.expires_at,
        settlement_digest: hex_array(
            &dto.settlement_digest,
            &format!("{field_name}.settlementDigest"),
        )?,
        relation_proof_digest: hex_array(
            &dto.relation_proof_digest,
            &format!("{field_name}.relationProofDigest"),
        )?,
    })
}

fn settlement_from_dto(dto: SettlementDto, field_name: &str) -> Result<SettlementOrder, String> {
    Ok(SettlementOrder {
        operation_id: hex_array(&dto.operation_id, &format!("{field_name}.operationID"))?,
        nullifier: hex_array(&dto.nullifier, &format!("{field_name}.nullifier"))?,
        deadline: dto.deadline,
        payment_instruction_digest: hex_array(
            &dto.payment_instruction_digest,
            &format!("{field_name}.paymentInstructionDigest"),
        )?,
        proof_digest: hex_array(&dto.proof_digest, &format!("{field_name}.proofDigest"))?,
        market_statement_digest: hex_array(
            &dto.market_statement_digest,
            &format!("{field_name}.marketStatementDigest"),
        )?,
        legs: dto
            .legs
            .into_iter()
            .map(|leg| {
                Ok(StateLeg {
                    handle: hex_array(&leg.handle, &format!("{field_name}.legs.handle"))?,
                    asset_id: hex_array(&leg.asset_id, &format!("{field_name}.legs.assetID"))?,
                    before_commitment: hex_array(
                        &leg.before_commitment,
                        &format!("{field_name}.legs.beforeCommitment"),
                    )?,
                    after_commitment: hex_array(
                        &leg.after_commitment,
                        &format!("{field_name}.legs.afterCommitment"),
                    )?,
                    before_sequence: leg.before_sequence,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    })
}

fn reservation_authorization_from_dto(
    dto: ReservationAuthorizationDto,
    field_name: &str,
) -> Result<ReservationAuthorization, String> {
    Ok(ReservationAuthorization {
        role: match dto.role.as_str() {
            "maker" => ReservationRole::Maker,
            "taker" => ReservationRole::Taker,
            _ => return Err(format!("{field_name}.role is not supported")),
        },
        entity_commitment: hex_array(
            &dto.entity_commitment,
            &format!("{field_name}.entityCommitment"),
        )?,
        asset_id: hex_array(&dto.asset_id, &format!("{field_name}.assetID"))?,
        direction: dto.direction,
        authorization_digest: hex_array(
            &dto.authorization_digest,
            &format!("{field_name}.authorizationDigest"),
        )?,
        mandate_digest: hex_array(&dto.mandate_digest, &format!("{field_name}.mandateDigest"))?,
        typed_reserve_digest: hex_array(
            &dto.typed_reserve_digest,
            &format!("{field_name}.typedReserveDigest"),
        )?,
        reserve_nullifier: hex_array(
            &dto.reserve_nullifier,
            &format!("{field_name}.reserveNullifier"),
        )?,
        asset_link_proof_digest: hex_array(
            &dto.asset_link_proof_digest,
            &format!("{field_name}.assetLinkProofDigest"),
        )?,
        limit_price_commitment: hex_array(
            &dto.limit_price_commitment,
            &format!("{field_name}.limitPriceCommitment"),
        )?,
        escrow_digest: hex_array(&dto.escrow_digest, &format!("{field_name}.escrowDigest"))?,
        rfq_nullifier: hex_array(&dto.rfq_nullifier, &format!("{field_name}.rfqNullifier"))?,
        policy_version: dto.policy_version,
        admission_ticket_id: hex_array(
            &dto.admission_ticket_id,
            &format!("{field_name}.admissionTicketID"),
        )?,
        admission_slot: dto.admission_slot,
        admission_receipt_digest: hex_array(
            &dto.admission_receipt_digest,
            &format!("{field_name}.admissionReceiptDigest"),
        )?,
        admission_epoch: dto.admission_epoch,
        admission_sequence: dto.admission_sequence,
        admission_batch_id: hex_array(
            &dto.admission_batch_id,
            &format!("{field_name}.admissionBatchID"),
        )?,
    })
}

fn reserve_product(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &[
            "transition",
            "authorization",
            "escrow",
            "approval",
            "expectedBeforeRoot",
        ],
    )?;
    let transition = credit_transition_from_dto(field(params, "transition")?, "transition")?;
    transition.body()?;
    let authorization =
        reservation_authorization_from_dto(field(params, "authorization")?, "authorization")?;
    authorization.body(&transition)?;
    if authorization.role == ReservationRole::Taker
        && authorization.authorization_digest != authorization.mandate_digest
    {
        return Err("Taker reservation is not bound to its signed execution mandate".into());
    }
    let dto: ReservationEscrowDto = field(params, "escrow")?;
    let escrow = ReservationEscrow {
        source_handle: hex_array(&dto.source_handle, "escrow.sourceHandle")?,
        escrow_handle: hex_array(&dto.escrow_handle, "escrow.escrowHandle")?,
        asset_id: hex_array(&dto.asset_id, "escrow.assetID")?,
        amount_commitment: hex_array(&dto.amount_commitment, "escrow.amountCommitment")?,
        source_before_commitment: hex_array(
            &dto.source_before_commitment,
            "escrow.sourceBeforeCommitment",
        )?,
        source_after_commitment: hex_array(
            &dto.source_after_commitment,
            "escrow.sourceAfterCommitment",
        )?,
        source_before_sequence: dto.source_before_sequence,
        proof_digest: hex_array(&dto.proof_digest, "escrow.proofDigest")?,
    };
    escrow.body()?;
    if escrow.source_handle == escrow.escrow_handle
        || escrow.asset_id != authorization.asset_id
        || escrow.amount_commitment != transition.amount_commitment
        || escrow.statement()? != authorization.escrow_digest
    {
        return Err("reservation escrow differs from its signed authorization".into());
    }
    let statement = authorization.statement(&transition)?;
    authorize(state, params, statement, authorizer)?;
    if state
        .operations
        .contains_key(&id_key(&transition.operation_id))
        || state
            .reservation_bindings
            .contains_key(&id_key(&transition.hold_id))
        || state
            .reservation_escrows
            .contains_key(&id_key(&transition.hold_id))
    {
        return Err("reservation operation or hold identifier was already used".into());
    }
    if state
        .reservation_bindings
        .values()
        .any(|binding| binding.reserve_nullifier == authorization.reserve_nullifier)
    {
        return Err("reserve nullifier was already used".into());
    }
    if authorization.role == ReservationRole::Taker
        && state.reservation_bindings.values().any(|binding| {
            binding.role == "taker"
                && (binding.rfq_nullifier == authorization.rfq_nullifier
                    || binding.admission_ticket_id == authorization.admission_ticket_id
                    || binding.admission_receipt_digest == authorization.admission_receipt_digest
                    || (binding.admission_batch_id == authorization.admission_batch_id
                        && binding.admission_sequence == authorization.admission_sequence))
        })
    {
        return Err("Taker RFQ or admission lane was already reserved".into());
    }
    let facility_key = id_key(&transition.facility_id);
    let mut facility = state
        .credit_facilities
        .get(&facility_key)
        .cloned()
        .ok_or_else(|| "bound reserve names an unknown facility".to_string())?;
    if facility.beneficiary_commitment != authorization.entity_commitment
        || facility.rail_asset_id != authorization.asset_id
    {
        return Err("reserve entity or asset does not match its facility".into());
    }
    if facility.sequence != transition.before_sequence
        || facility.available_commitment != transition.before_available_commitment
        || facility.held_commitment != transition.before_held_commitment
        || facility.outstanding_commitment != transition.before_outstanding_commitment
    {
        return Err("reservation was proved against stale facility state".into());
    }
    if transition.kind != CreditTransitionKind::Hold
        || facility.status != "active"
        || timestamp < facility.valid_from
        || timestamp > facility.valid_until
        || transition.expires_at < timestamp
        || transition.expires_at > facility.valid_until
        || transition.before_outstanding_commitment != transition.after_outstanding_commitment
    {
        return Err("reservation cannot create a valid active facility hold".into());
    }
    let hold_key = id_key(&transition.hold_id);
    if state.credit_holds.contains_key(&hold_key) {
        return Err("credit hold identifier is already registered".into());
    }
    let source = state
        .accounts
        .get(&id_key(&escrow.source_handle))
        .cloned()
        .ok_or_else(|| "reservation escrow names an unknown source account".to_string())?;
    if source.asset_id != escrow.asset_id
        || source.commitment != escrow.source_before_commitment
        || source.sequence != escrow.source_before_sequence
    {
        return Err("reservation escrow was proved against stale source-account state".into());
    }

    let mut admission_update = None;
    if authorization.role == ReservationRole::Taker {
        let batch_key = id_key(&authorization.admission_batch_id);
        let batch = state
            .admission_batches
            .get(&batch_key)
            .cloned()
            .ok_or_else(|| "Taker reserve has no registered admission batch".to_string())?;
        if timestamp > batch.expires_at
            || authorization.admission_epoch != batch.epoch
            || authorization.admission_slot != batch.slot
        {
            return Err("Taker admission is expired or differs from its batch".into());
        }
        let expected = CertifiedAdmissionLane {
            slot: authorization.admission_slot,
            sequence: authorization.admission_sequence,
            principal_digest: ZERO,
            ticket_id: authorization.admission_ticket_id,
            claim_digest: authorization.mandate_digest,
            cluster_digest: batch.batch_digest,
            order_digest: batch.order_digest,
        }
        .digest(batch.venue_id, batch.epoch)?;
        if expected != authorization.admission_receipt_digest
            || authorization.admission_sequence != batch.consumed + 1
            || authorization.admission_sequence > batch.population
        {
            return Err("Taker mandate is not the next certified admission claim".into());
        }
        let entry_key = admission_entry_key(
            &authorization.admission_batch_id,
            authorization.admission_sequence,
        );
        let entry = state
            .admission_entries
            .get(&entry_key)
            .ok_or_else(|| "admission plan omits the Taker lane".to_string())?;
        if entry.admission_digest != authorization.admission_receipt_digest
            || entry.consumed_by != ZERO
        {
            return Err("Taker admission lane differs or was already consumed".into());
        }
        admission_update = Some((batch_key, batch, entry_key));
    }

    facility.available_commitment = transition.after_available_commitment;
    facility.held_commitment = transition.after_held_commitment;
    facility.outstanding_commitment = transition.after_outstanding_commitment;
    facility.sequence = facility
        .sequence
        .checked_add(1)
        .ok_or_else(|| "credit facility sequence overflow".to_string())?;
    state.credit_facilities.insert(facility_key, facility);
    state.credit_holds.insert(
        hold_key.clone(),
        CreditHoldRecord {
            facility_id: transition.facility_id,
            query_commitment: transition.query_commitment,
            amount_commitment: transition.amount_commitment,
            expires_at: transition.expires_at,
            status: "active".into(),
            settlement_digest: ZERO,
            created_sequence: transition.before_sequence + 1,
            updated_sequence: transition.before_sequence + 1,
        },
    );
    state.reservation_bindings.insert(
        hold_key.clone(),
        ReservationBindingRecord {
            role: authorization.role.as_str().into(),
            entity_commitment: authorization.entity_commitment,
            asset_id: authorization.asset_id,
            direction: authorization.direction,
            authorization_digest: authorization.authorization_digest,
            mandate_digest: authorization.mandate_digest,
            typed_reserve_digest: authorization.typed_reserve_digest,
            reserve_nullifier: authorization.reserve_nullifier,
            asset_link_proof_digest: authorization.asset_link_proof_digest,
            limit_price_commitment: authorization.limit_price_commitment,
            rfq_nullifier: authorization.rfq_nullifier,
            policy_version: authorization.policy_version,
            admission_ticket_id: authorization.admission_ticket_id,
            admission_slot: authorization.admission_slot,
            admission_receipt_digest: authorization.admission_receipt_digest,
            admission_epoch: authorization.admission_epoch,
            admission_sequence: authorization.admission_sequence,
            admission_batch_id: authorization.admission_batch_id,
            receipt_digest: statement,
        },
    );
    let source = state
        .accounts
        .get_mut(&id_key(&escrow.source_handle))
        .expect("source account was validated");
    source.commitment = escrow.source_after_commitment;
    source.sequence = source
        .sequence
        .checked_add(1)
        .ok_or_else(|| "source account sequence overflow".to_string())?;
    state.reservation_escrows.insert(
        hold_key,
        ReservationEscrowRecord {
            source_handle: escrow.source_handle,
            escrow_handle: escrow.escrow_handle,
            asset_id: escrow.asset_id,
            amount_commitment: escrow.amount_commitment,
            source_before_commitment: escrow.source_before_commitment,
            source_after_commitment: escrow.source_after_commitment,
            source_before_sequence: escrow.source_before_sequence,
            proof_digest: escrow.proof_digest,
            status: "active".into(),
            settlement_digest: ZERO,
        },
    );
    if let Some((batch_key, mut batch, entry_key)) = admission_update {
        state
            .admission_entries
            .get_mut(&entry_key)
            .expect("admission entry was validated")
            .consumed_by = transition.operation_id;
        batch.consumed = authorization.admission_sequence;
        state.admission_batches.insert(batch_key, batch);
    }
    state
        .operations
        .insert(id_key(&transition.operation_id), transition.statement()?);
    Ok(statement)
}

fn reserve_note_product(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &[
            "transition",
            "authorization",
            "escrow",
            "approval",
            "expectedBeforeRoot",
        ],
    )?;
    let transition = credit_transition_from_dto(field(params, "transition")?, "transition")?;
    transition.body()?;
    let authorization =
        reservation_authorization_from_dto(field(params, "authorization")?, "authorization")?;
    authorization.body(&transition)?;
    if authorization.role == ReservationRole::Taker
        && authorization.authorization_digest != authorization.mandate_digest
    {
        return Err("Taker reservation is not bound to its signed execution mandate".into());
    }
    let dto: NoteReservationEscrowDto = field(params, "escrow")?;
    let escrow = NoteReservationEscrow {
        spend: note_spend_from_dto(dto.spend, "escrow.spend")?,
        escrow_note_id: hex_array(&dto.escrow_note_id, "escrow.escrowNoteID")?,
        delegation_digest: hex_array(&dto.delegation_digest, "escrow.delegationDigest")?,
    };
    escrow.body(&transition, &authorization)?;
    if escrow.statement(&transition, &authorization)? != authorization.escrow_digest {
        return Err("anonymous escrow differs from the signed reservation".into());
    }
    let statement = authorization.statement(&transition)?;
    authorize(state, params, statement, authorizer)?;
    let hold_key = id_key(&transition.hold_id);
    if state
        .operations
        .contains_key(&id_key(&transition.operation_id))
        || state.reservation_bindings.contains_key(&hold_key)
        || state.note_reservations.contains_key(&hold_key)
        || state.credit_holds.contains_key(&hold_key)
    {
        return Err("anonymous reservation operation or hold was already used".into());
    }
    if state
        .reservation_bindings
        .values()
        .any(|binding| binding.reserve_nullifier == authorization.reserve_nullifier)
    {
        return Err("reserve nullifier was already used".into());
    }
    if authorization.role == ReservationRole::Taker
        && state.reservation_bindings.values().any(|binding| {
            binding.role == "taker"
                && (binding.rfq_nullifier == authorization.rfq_nullifier
                    || binding.admission_ticket_id == authorization.admission_ticket_id
                    || binding.admission_receipt_digest == authorization.admission_receipt_digest
                    || (binding.admission_batch_id == authorization.admission_batch_id
                        && binding.admission_sequence == authorization.admission_sequence))
        })
    {
        return Err("Taker RFQ or admission lane was already reserved".into());
    }
    let facility_key = id_key(&transition.facility_id);
    let mut facility = state
        .credit_facilities
        .get(&facility_key)
        .cloned()
        .ok_or_else(|| "anonymous reserve names an unknown facility".to_string())?;
    if facility.beneficiary_commitment != authorization.entity_commitment
        || facility.rail_asset_id != authorization.asset_id
    {
        return Err("anonymous reserve entity or asset does not match its facility".into());
    }
    if facility.sequence != transition.before_sequence
        || facility.available_commitment != transition.before_available_commitment
        || facility.held_commitment != transition.before_held_commitment
        || facility.outstanding_commitment != transition.before_outstanding_commitment
    {
        return Err("anonymous reservation was proved against stale facility state".into());
    }
    if transition.kind != CreditTransitionKind::Hold
        || facility.status != "active"
        || timestamp < facility.valid_from
        || timestamp > facility.valid_until
        || transition.expires_at < timestamp
        || transition.expires_at > facility.valid_until
        || transition.before_outstanding_commitment != transition.after_outstanding_commitment
    {
        return Err("anonymous reservation cannot create a valid active facility hold".into());
    }
    check_note_spend(state, &escrow.spend, None, true)?;

    let mut admission_update = None;
    if authorization.role == ReservationRole::Taker {
        let batch_key = id_key(&authorization.admission_batch_id);
        let batch = state
            .admission_batches
            .get(&batch_key)
            .cloned()
            .ok_or_else(|| "Taker reserve has no registered admission batch".to_string())?;
        if timestamp > batch.expires_at
            || authorization.admission_epoch != batch.epoch
            || authorization.admission_slot != batch.slot
        {
            return Err("Taker admission is expired or differs from its batch".into());
        }
        let expected = CertifiedAdmissionLane {
            slot: authorization.admission_slot,
            sequence: authorization.admission_sequence,
            principal_digest: ZERO,
            ticket_id: authorization.admission_ticket_id,
            claim_digest: authorization.mandate_digest,
            cluster_digest: batch.batch_digest,
            order_digest: batch.order_digest,
        }
        .digest(batch.venue_id, batch.epoch)?;
        if expected != authorization.admission_receipt_digest
            || authorization.admission_sequence != batch.consumed + 1
            || authorization.admission_sequence > batch.population
        {
            return Err("Taker mandate is not the next certified admission claim".into());
        }
        let entry_key = admission_entry_key(
            &authorization.admission_batch_id,
            authorization.admission_sequence,
        );
        let entry = state
            .admission_entries
            .get(&entry_key)
            .ok_or_else(|| "admission plan omits the Taker lane".to_string())?;
        if entry.admission_digest != authorization.admission_receipt_digest
            || entry.consumed_by != ZERO
        {
            return Err("Taker admission lane differs or was already consumed".into());
        }
        admission_update = Some((batch_key, batch, entry_key));
    }

    facility.available_commitment = transition.after_available_commitment;
    facility.held_commitment = transition.after_held_commitment;
    facility.outstanding_commitment = transition.after_outstanding_commitment;
    facility.sequence = facility
        .sequence
        .checked_add(1)
        .ok_or_else(|| "credit facility sequence overflow".to_string())?;
    state.credit_facilities.insert(facility_key, facility);
    state.credit_holds.insert(
        hold_key.clone(),
        CreditHoldRecord {
            facility_id: transition.facility_id,
            query_commitment: transition.query_commitment,
            amount_commitment: transition.amount_commitment,
            expires_at: transition.expires_at,
            status: "active".into(),
            settlement_digest: ZERO,
            created_sequence: transition.before_sequence + 1,
            updated_sequence: transition.before_sequence + 1,
        },
    );
    state.reservation_bindings.insert(
        hold_key.clone(),
        ReservationBindingRecord {
            role: authorization.role.as_str().into(),
            entity_commitment: authorization.entity_commitment,
            asset_id: authorization.asset_id,
            direction: authorization.direction,
            authorization_digest: authorization.authorization_digest,
            mandate_digest: authorization.mandate_digest,
            typed_reserve_digest: authorization.typed_reserve_digest,
            reserve_nullifier: authorization.reserve_nullifier,
            asset_link_proof_digest: authorization.asset_link_proof_digest,
            limit_price_commitment: authorization.limit_price_commitment,
            rfq_nullifier: authorization.rfq_nullifier,
            policy_version: authorization.policy_version,
            admission_ticket_id: authorization.admission_ticket_id,
            admission_slot: authorization.admission_slot,
            admission_receipt_digest: authorization.admission_receipt_digest,
            admission_epoch: authorization.admission_epoch,
            admission_sequence: authorization.admission_sequence,
            admission_batch_id: authorization.admission_batch_id,
            receipt_digest: statement,
        },
    );
    apply_note_spend(state, &escrow.spend, transition.expires_at, statement)?;
    state.note_reservations.insert(
        hold_key,
        NoteReservationRecord {
            escrow_note_id: escrow.escrow_note_id,
            asset_id: escrow.spend.asset_id,
            amount_commitment: transition.amount_commitment,
            proof_digest: escrow.spend.proof_digest,
            delegation_digest: escrow.delegation_digest,
            status: "active".into(),
            settlement_digest: ZERO,
        },
    );
    if let Some((batch_key, mut batch, entry_key)) = admission_update {
        state
            .admission_entries
            .get_mut(&entry_key)
            .expect("admission entry was validated")
            .consumed_by = transition.operation_id;
        batch.consumed = authorization.admission_sequence;
        state.admission_batches.insert(batch_key, batch);
    }
    state
        .operations
        .insert(id_key(&transition.operation_id), transition.statement()?);
    Ok(statement)
}

fn release_product(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["order", "approval", "expectedBeforeRoot"])?;
    let dto: ProductReleaseDto = field(params, "order")?;
    let refund_leg = StateLeg {
        handle: hex_array(&dto.refund_leg.handle, "order.refundLeg.handle")?,
        asset_id: hex_array(&dto.refund_leg.asset_id, "order.refundLeg.assetID")?,
        before_commitment: hex_array(
            &dto.refund_leg.before_commitment,
            "order.refundLeg.beforeCommitment",
        )?,
        after_commitment: hex_array(
            &dto.refund_leg.after_commitment,
            "order.refundLeg.afterCommitment",
        )?,
        before_sequence: dto.refund_leg.before_sequence,
    };
    let order = ProductReleaseOrder {
        transition: credit_transition_from_dto(dto.transition, "order.transition")?,
        role: match dto.role.as_str() {
            "maker" => ReservationRole::Maker,
            "taker" => ReservationRole::Taker,
            _ => return Err("order.role is not supported".into()),
        },
        reserve_receipt_digest: hex_array(
            &dto.reserve_receipt_digest,
            "order.reserveReceiptDigest",
        )?,
        typed_instruction_digest: hex_array(
            &dto.typed_instruction_digest,
            "order.typedInstructionDigest",
        )?,
        release_nullifier: hex_array(&dto.release_nullifier, "order.releaseNullifier")?,
        release_deadline: dto.release_deadline,
        asset_id: hex_array(&dto.asset_id, "order.assetID")?,
        asset_link_proof_digest: hex_array(
            &dto.asset_link_proof_digest,
            "order.assetLinkProofDigest",
        )?,
        refund_leg,
    };
    order.body()?;
    let statement = order.statement()?;
    authorize(state, params, statement, authorizer)?;
    if timestamp <= order.transition.expires_at || timestamp > order.release_deadline {
        return Err("product reservation is not yet releasable or release has expired".into());
    }
    if state
        .nullifiers
        .contains_key(&id_key(&order.release_nullifier))
    {
        return Err("release nullifier was already used".into());
    }
    if state
        .operations
        .contains_key(&id_key(&order.transition.operation_id))
    {
        return Err("release operation identifier was already used".into());
    }
    let hold_key = id_key(&order.transition.hold_id);
    let binding = state
        .reservation_bindings
        .get(&hold_key)
        .ok_or_else(|| "product release names an unknown reservation".to_string())?;
    if binding.role != order.role.as_str()
        || binding.asset_id != order.asset_id
        || binding.receipt_digest != order.reserve_receipt_digest
        || binding.authorization_digest != order.transition.query_commitment
    {
        return Err("release differs from the stored reservation".into());
    }
    match order.role {
        ReservationRole::Maker if binding.policy_version == 0 || binding.rfq_nullifier != ZERO => {
            return Err("Maker release is not policy-scoped".into());
        }
        ReservationRole::Taker
            if binding.policy_version != 0
                || binding.rfq_nullifier == ZERO
                || binding.mandate_digest != order.transition.query_commitment =>
        {
            return Err("Taker release is not RFQ-scoped".into());
        }
        _ => {}
    }
    let transition = &order.transition;
    if transition.kind != CreditTransitionKind::Release
        || transition.settlement_digest != ZERO
        || transition.before_outstanding_commitment != transition.after_outstanding_commitment
    {
        return Err("product release is not a pure expired-hold refund".into());
    }
    let facility_key = id_key(&transition.facility_id);
    let mut facility = state
        .credit_facilities
        .get(&facility_key)
        .cloned()
        .ok_or_else(|| "product release names an unknown facility".to_string())?;
    if facility.sequence != transition.before_sequence
        || facility.available_commitment != transition.before_available_commitment
        || facility.held_commitment != transition.before_held_commitment
        || facility.outstanding_commitment != transition.before_outstanding_commitment
        || facility.beneficiary_commitment != binding.entity_commitment
        || facility.rail_asset_id != order.asset_id
    {
        return Err("product release was proved against stale facility state".into());
    }
    let mut hold = state
        .credit_holds
        .get(&hold_key)
        .cloned()
        .ok_or_else(|| "product release names an unknown hold".to_string())?;
    if hold.facility_id != transition.facility_id
        || hold.query_commitment != transition.query_commitment
        || hold.amount_commitment != transition.amount_commitment
        || hold.expires_at != transition.expires_at
        || hold.status != "active"
    {
        return Err("product release was proved against stale hold state".into());
    }
    let mut escrow = state
        .reservation_escrows
        .get(&hold_key)
        .cloned()
        .ok_or_else(|| "product release names an unknown asset escrow".to_string())?;
    if escrow.status != "active"
        || escrow.source_handle != order.refund_leg.handle
        || escrow.asset_id != order.asset_id
        || escrow.amount_commitment != transition.amount_commitment
    {
        return Err("product release has no matching active asset escrow".into());
    }
    let account = state
        .accounts
        .get(&id_key(&order.refund_leg.handle))
        .ok_or_else(|| "product release refund account is unknown".to_string())?;
    if account.asset_id != order.asset_id
        || account.commitment != order.refund_leg.before_commitment
        || account.sequence != order.refund_leg.before_sequence
    {
        return Err("product release was proved against stale refund-account state".into());
    }

    facility.available_commitment = transition.after_available_commitment;
    facility.held_commitment = transition.after_held_commitment;
    facility.outstanding_commitment = transition.after_outstanding_commitment;
    facility.sequence = facility
        .sequence
        .checked_add(1)
        .ok_or_else(|| "credit facility sequence overflow".to_string())?;
    state.credit_facilities.insert(facility_key, facility);
    hold.status = "released".into();
    hold.settlement_digest = ZERO;
    hold.updated_sequence = transition.before_sequence + 1;
    state.credit_holds.insert(hold_key.clone(), hold);
    escrow.status = "released".into();
    escrow.settlement_digest = statement;
    state.reservation_escrows.insert(hold_key, escrow);
    state.nullifiers.insert(
        id_key(&order.release_nullifier),
        NullifierRecord {
            deadline: order.release_deadline,
            statement,
        },
    );
    let account = state
        .accounts
        .get_mut(&id_key(&order.refund_leg.handle))
        .expect("refund account was validated");
    account.commitment = order.refund_leg.after_commitment;
    account.sequence = account
        .sequence
        .checked_add(1)
        .ok_or_else(|| "refund account sequence overflow".to_string())?;
    state
        .operations
        .insert(id_key(&transition.operation_id), statement);
    Ok(statement)
}

fn release_note_product(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["order", "approval", "expectedBeforeRoot"])?;
    let dto: ProductNoteReleaseDto = field(params, "order")?;
    let order = ProductNoteReleaseOrder {
        transition: credit_transition_from_dto(dto.transition, "order.transition")?,
        role: match dto.role.as_str() {
            "maker" => ReservationRole::Maker,
            "taker" => ReservationRole::Taker,
            _ => return Err("order.role is not supported".into()),
        },
        reserve_receipt_digest: hex_array(
            &dto.reserve_receipt_digest,
            "order.reserveReceiptDigest",
        )?,
        typed_instruction_digest: hex_array(
            &dto.typed_instruction_digest,
            "order.typedInstructionDigest",
        )?,
        release_nullifier: hex_array(&dto.release_nullifier, "order.releaseNullifier")?,
        release_deadline: dto.release_deadline,
        asset_id: hex_array(&dto.asset_id, "order.assetID")?,
        asset_link_proof_digest: hex_array(
            &dto.asset_link_proof_digest,
            "order.assetLinkProofDigest",
        )?,
        escrow_note_id: hex_array(&dto.escrow_note_id, "order.escrowNoteID")?,
        spend: note_spend_from_dto(dto.spend, "order.spend")?,
    };
    order.body()?;
    let statement = order.statement()?;
    authorize(state, params, statement, authorizer)?;
    if timestamp <= order.transition.expires_at || timestamp > order.release_deadline {
        return Err("anonymous reservation is not yet releasable or release has expired".into());
    }
    if state
        .nullifiers
        .contains_key(&id_key(&order.release_nullifier))
    {
        return Err("release nullifier was already used".into());
    }
    if state
        .operations
        .contains_key(&id_key(&order.transition.operation_id))
    {
        return Err("release operation identifier was already used".into());
    }
    let hold_key = id_key(&order.transition.hold_id);
    let binding = state
        .reservation_bindings
        .get(&hold_key)
        .ok_or_else(|| "anonymous release names an unknown reservation".to_string())?;
    if binding.role != order.role.as_str()
        || binding.asset_id != order.asset_id
        || binding.receipt_digest != order.reserve_receipt_digest
        || binding.authorization_digest != order.transition.query_commitment
    {
        return Err("anonymous release differs from the stored reservation".into());
    }
    match order.role {
        ReservationRole::Maker if binding.policy_version == 0 || binding.rfq_nullifier != ZERO => {
            return Err("Maker release is not policy-scoped".into());
        }
        ReservationRole::Taker
            if binding.policy_version != 0
                || binding.rfq_nullifier == ZERO
                || binding.mandate_digest != order.transition.query_commitment =>
        {
            return Err("Taker release is not RFQ-scoped".into());
        }
        _ => {}
    }
    let transition = &order.transition;
    if transition.kind != CreditTransitionKind::Release
        || transition.settlement_digest != ZERO
        || transition.before_outstanding_commitment != transition.after_outstanding_commitment
    {
        return Err("anonymous release is not a pure expired-hold refund".into());
    }
    let facility_key = id_key(&transition.facility_id);
    let mut facility = state
        .credit_facilities
        .get(&facility_key)
        .cloned()
        .ok_or_else(|| "anonymous release names an unknown facility".to_string())?;
    if facility.sequence != transition.before_sequence
        || facility.available_commitment != transition.before_available_commitment
        || facility.held_commitment != transition.before_held_commitment
        || facility.outstanding_commitment != transition.before_outstanding_commitment
        || facility.beneficiary_commitment != binding.entity_commitment
        || facility.rail_asset_id != order.asset_id
    {
        return Err("anonymous release was proved against stale facility state".into());
    }
    let mut hold = state
        .credit_holds
        .get(&hold_key)
        .cloned()
        .ok_or_else(|| "anonymous release names an unknown hold".to_string())?;
    if hold.facility_id != transition.facility_id
        || hold.query_commitment != transition.query_commitment
        || hold.amount_commitment != transition.amount_commitment
        || hold.expires_at != transition.expires_at
        || hold.status != "active"
    {
        return Err("anonymous release was proved against stale hold state".into());
    }
    let mut escrow = state
        .note_reservations
        .get(&hold_key)
        .cloned()
        .ok_or_else(|| "anonymous release has no escrow note".to_string())?;
    if escrow.status != "active"
        || escrow.escrow_note_id != order.escrow_note_id
        || escrow.asset_id != order.asset_id
        || escrow.amount_commitment != transition.amount_commitment
    {
        return Err("anonymous release has no matching active escrow note".into());
    }
    check_note_spend(state, &order.spend, Some(order.escrow_note_id), false)?;

    facility.available_commitment = transition.after_available_commitment;
    facility.held_commitment = transition.after_held_commitment;
    facility.outstanding_commitment = transition.after_outstanding_commitment;
    facility.sequence = facility
        .sequence
        .checked_add(1)
        .ok_or_else(|| "credit facility sequence overflow".to_string())?;
    state.credit_facilities.insert(facility_key, facility);
    hold.status = "released".into();
    hold.settlement_digest = ZERO;
    hold.updated_sequence = transition.before_sequence + 1;
    state.credit_holds.insert(hold_key.clone(), hold);
    escrow.status = "released".into();
    escrow.settlement_digest = statement;
    state.note_reservations.insert(hold_key, escrow);
    state.nullifiers.insert(
        id_key(&order.release_nullifier),
        NullifierRecord {
            deadline: order.release_deadline,
            statement,
        },
    );
    apply_note_spend(state, &order.spend, order.release_deadline, statement)?;
    state
        .operations
        .insert(id_key(&transition.operation_id), statement);
    Ok(statement)
}

struct PreparedProductReservation {
    transition: CreditFacilityTransition,
    transition_statement: [u8; 32],
    facility_key: String,
    facility: CreditFacilityRecord,
    hold_key: String,
    hold: CreditHoldRecord,
    escrow: ReservationEscrowRecord,
}

fn settle_product(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["order", "approval", "expectedBeforeRoot"])?;
    let dto: ProductSettlementDto = field(params, "order")?;
    let order = product_order_from_dto(dto, "order")?;
    let statement = order.statement()?;
    authorize(state, params, statement, authorizer)?;
    apply_product_settlement(state, order, timestamp)
}

fn product_order_from_dto(
    dto: ProductSettlementDto,
    field_name: &str,
) -> Result<ProductSettlementOrder, String> {
    if dto.reservations.len() > 2 {
        return Err(format!("{field_name} contains too many reservations"));
    }
    let settlement = settlement_from_dto(dto.settlement, &format!("{field_name}.settlement"))?;
    let reservations = dto
        .reservations
        .into_iter()
        .map(|reservation| {
            Ok(ReservationConsumption {
                role: match reservation.role.as_str() {
                    "maker" => ReservationRole::Maker,
                    "taker" => ReservationRole::Taker,
                    _ => return Err(format!("{field_name}.reservations.role is not supported")),
                },
                reserve_receipt_digest: hex_array(
                    &reservation.reserve_receipt_digest,
                    &format!("{field_name}.reservations.reserveReceiptDigest"),
                )?,
                transition: credit_transition_from_dto(
                    reservation.transition,
                    &format!("{field_name}.reservations.transition"),
                )?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let order = ProductSettlementOrder {
        settlement,
        venue_id: hex_array(&dto.venue_id, &format!("{field_name}.venueID"))?,
        defmi_id: hex_array(&dto.defmi_id, &format!("{field_name}.defmiID"))?,
        maker_entity_commitment: hex_array(
            &dto.maker_entity_commitment,
            &format!("{field_name}.makerEntityCommitment"),
        )?,
        taker_entity_commitment: hex_array(
            &dto.taker_entity_commitment,
            &format!("{field_name}.takerEntityCommitment"),
        )?,
        rfq_nullifier: hex_array(&dto.rfq_nullifier, &format!("{field_name}.rfqNullifier"))?,
        taker_authorization_digest: hex_array(
            &dto.taker_authorization_digest,
            &format!("{field_name}.takerAuthorizationDigest"),
        )?,
        maker_policy_digest: hex_array(
            &dto.maker_policy_digest,
            &format!("{field_name}.makerPolicyDigest"),
        )?,
        maker_mandate_digest: hex_array(
            &dto.maker_mandate_digest,
            &format!("{field_name}.makerMandateDigest"),
        )?,
        taker_mandate_digest: hex_array(
            &dto.taker_mandate_digest,
            &format!("{field_name}.takerMandateDigest"),
        )?,
        typed_instruction_digest: hex_array(
            &dto.typed_instruction_digest,
            &format!("{field_name}.typedInstructionDigest"),
        )?,
        quote_proof_digest: hex_array(
            &dto.quote_proof_digest,
            &format!("{field_name}.quoteProofDigest"),
        )?,
        price_limit_proof_digest: hex_array(
            &dto.price_limit_proof_digest,
            &format!("{field_name}.priceLimitProofDigest"),
        )?,
        dvp_proof_digest: hex_array(
            &dto.dvp_proof_digest,
            &format!("{field_name}.dvpProofDigest"),
        )?,
        quantity_commitment: hex_array(
            &dto.quantity_commitment,
            &format!("{field_name}.quantityCommitment"),
        )?,
        cash_commitment: hex_array(
            &dto.cash_commitment,
            &format!("{field_name}.cashCommitment"),
        )?,
        traded_asset_id: hex_array(&dto.traded_asset_id, &format!("{field_name}.tradedAssetID"))?,
        asset_link_proof_digest: hex_array(
            &dto.asset_link_proof_digest,
            &format!("{field_name}.assetLinkProofDigest"),
        )?,
        admission_receipt_digest: hex_array(
            &dto.admission_receipt_digest,
            &format!("{field_name}.admissionReceiptDigest"),
        )?,
        admission_epoch: dto.admission_epoch,
        admission_sequence: dto.admission_sequence,
        reservations,
    };
    order.body()?;
    Ok(order)
}

fn apply_product_settlement(
    state: &mut State,
    order: ProductSettlementOrder,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    let statement = order.statement()?;
    if timestamp > order.settlement.deadline {
        return Err("product settlement has expired".into());
    }
    if state
        .operations
        .contains_key(&id_key(&order.settlement.operation_id))
    {
        return Err("settlement operation identifier was already used".into());
    }
    if state
        .nullifiers
        .contains_key(&id_key(&order.settlement.nullifier))
    {
        return Err("payment nullifier was already settled".into());
    }
    if state
        .rfq_nullifiers
        .contains_key(&id_key(&order.rfq_nullifier))
    {
        return Err("RFQ nullifier was already settled".into());
    }
    let payment_asset_id = order
        .settlement
        .legs
        .iter()
        .find(|leg| leg.asset_id != order.traded_asset_id)
        .map(|leg| leg.asset_id)
        .ok_or_else(|| "product settlement has no payment rail".to_string())?;
    let payment_asset = state
        .assets
        .get(&id_key(&payment_asset_id))
        .ok_or_else(|| "product settlement payment asset is unknown".to_string())?;
    if !payment_asset.active || payment_asset.kind != "cash" {
        return Err("product settlement payment side is not an active cash rail".into());
    }
    let base_statement = order.settlement.statement()?;
    let mut direction = 0u8;
    let mut transition_operations = BTreeSet::new();
    let mut prepared = Vec::with_capacity(order.reservations.len());
    for consumption in &order.reservations {
        if consumption.reserve_receipt_digest == ZERO
            || !transition_operations.insert(consumption.transition.operation_id)
            || consumption.transition.operation_id == order.settlement.operation_id
            || state
                .operations
                .contains_key(&id_key(&consumption.transition.operation_id))
        {
            return Err("product settlement repeats a used reservation operation".into());
        }
        let hold_key = id_key(&consumption.transition.hold_id);
        let binding = state
            .reservation_bindings
            .get(&hold_key)
            .ok_or_else(|| "product settlement names an unknown reservation".to_string())?;
        if direction == 0 {
            direction = binding.direction;
        } else if direction != binding.direction {
            return Err("Maker and Taker reservations use different directions".into());
        }
        let mut expected_entity = order.taker_entity_commitment;
        let mut expected_authorization = order.taker_authorization_digest;
        let mut expected_mandate = order.taker_mandate_digest;
        let mut expected_asset = if direction == 1 {
            payment_asset_id
        } else {
            order.traded_asset_id
        };
        if consumption.role == ReservationRole::Maker {
            expected_entity = order.maker_entity_commitment;
            expected_authorization = order.maker_policy_digest;
            expected_mandate = order.maker_mandate_digest;
            expected_asset = if direction == 1 {
                order.traded_asset_id
            } else {
                payment_asset_id
            };
        }
        if binding.role != consumption.role.as_str()
            || binding.entity_commitment != expected_entity
            || binding.asset_id != expected_asset
            || binding.authorization_digest != expected_authorization
            || binding.mandate_digest != expected_mandate
            || binding.receipt_digest != consumption.reserve_receipt_digest
        {
            return Err("reservation binding differs from product settlement".into());
        }
        match consumption.role {
            ReservationRole::Maker
                if binding.policy_version == 0 || binding.rfq_nullifier != ZERO =>
            {
                return Err("Maker reservation is not policy-scoped".into());
            }
            ReservationRole::Taker
                if binding.rfq_nullifier != order.rfq_nullifier
                    || binding.admission_receipt_digest != order.admission_receipt_digest
                    || binding.admission_epoch != order.admission_epoch
                    || binding.admission_sequence != order.admission_sequence =>
            {
                return Err("Taker reservation is not for the admitted RFQ".into());
            }
            _ => {}
        }
        let expected_consumed = if (direction == 1 && consumption.role == ReservationRole::Maker)
            || (direction == 2 && consumption.role == ReservationRole::Taker)
        {
            order.quantity_commitment
        } else {
            order.cash_commitment
        };
        if consumption.transition.consumed_commitment != expected_consumed {
            return Err("guarantee consumption differs from proved DvP amount".into());
        }
        let transition = &consumption.transition;
        if transition.kind != CreditTransitionKind::Consume
            || transition.settlement_digest != base_statement
            || timestamp > transition.expires_at
        {
            return Err("reservation is not consumable by this DvP".into());
        }
        let facility_key = id_key(&transition.facility_id);
        let facility = state
            .credit_facilities
            .get(&facility_key)
            .cloned()
            .ok_or_else(|| "reservation facility is unknown".to_string())?;
        if facility.sequence != transition.before_sequence
            || facility.available_commitment != transition.before_available_commitment
            || facility.held_commitment != transition.before_held_commitment
            || facility.outstanding_commitment != transition.before_outstanding_commitment
            || facility.beneficiary_commitment != expected_entity
            || facility.rail_asset_id != expected_asset
        {
            return Err("reservation consumption was proved against stale facility state".into());
        }
        let hold = state
            .credit_holds
            .get(&hold_key)
            .cloned()
            .ok_or_else(|| "reservation credit hold is unknown".to_string())?;
        if hold.facility_id != transition.facility_id
            || hold.query_commitment != transition.query_commitment
            || hold.amount_commitment != transition.amount_commitment
            || hold.expires_at != transition.expires_at
            || hold.status != "active"
        {
            return Err("reservation consumption was proved against stale hold state".into());
        }
        let escrow = state
            .reservation_escrows
            .get(&hold_key)
            .cloned()
            .ok_or_else(|| "reservation asset escrow is unknown".to_string())?;
        if escrow.status != "active"
            || escrow.asset_id != expected_asset
            || escrow.amount_commitment != transition.amount_commitment
            || !order
                .settlement
                .legs
                .iter()
                .any(|leg| leg.handle == escrow.source_handle && leg.asset_id == escrow.asset_id)
        {
            return Err("consumed reservation has no matching refund account".into());
        }
        prepared.push(PreparedProductReservation {
            transition: transition.clone(),
            transition_statement: transition.statement()?,
            facility_key,
            facility,
            hold_key,
            hold,
            escrow,
        });
    }
    if !matches!(direction, 1 | 2) {
        return Err("product settlement has an unsupported direction".into());
    }
    for leg in &order.settlement.legs {
        let account = state
            .accounts
            .get(&id_key(&leg.handle))
            .ok_or_else(|| "product settlement names an unknown account".to_string())?;
        if account.asset_id != leg.asset_id {
            return Err("product settlement leg is on the wrong asset rail".into());
        }
        if account.commitment != leg.before_commitment || account.sequence != leg.before_sequence {
            return Err("product settlement was proved against stale account state".into());
        }
        if !state
            .assets
            .get(&id_key(&leg.asset_id))
            .is_some_and(|asset| asset.active)
        {
            return Err("product settlement uses an inactive or unknown asset".into());
        }
    }

    for item in prepared {
        let mut facility = item.facility;
        facility.available_commitment = item.transition.after_available_commitment;
        facility.held_commitment = item.transition.after_held_commitment;
        facility.outstanding_commitment = item.transition.after_outstanding_commitment;
        facility.sequence = facility
            .sequence
            .checked_add(1)
            .ok_or_else(|| "credit facility sequence overflow".to_string())?;
        state.credit_facilities.insert(item.facility_key, facility);
        let mut hold = item.hold;
        hold.status = "consumed".into();
        hold.settlement_digest = item.transition.settlement_digest;
        hold.updated_sequence = item.transition.before_sequence + 1;
        state.credit_holds.insert(item.hold_key.clone(), hold);
        let mut escrow = item.escrow;
        escrow.status = "consumed".into();
        escrow.settlement_digest = statement;
        state.reservation_escrows.insert(item.hold_key, escrow);
        state.operations.insert(
            id_key(&item.transition.operation_id),
            item.transition_statement,
        );
    }
    state.nullifiers.insert(
        id_key(&order.settlement.nullifier),
        NullifierRecord {
            deadline: order.settlement.deadline,
            statement,
        },
    );
    state
        .rfq_nullifiers
        .insert(id_key(&order.rfq_nullifier), statement);
    for leg in &order.settlement.legs {
        let account = state
            .accounts
            .get_mut(&id_key(&leg.handle))
            .expect("settlement account was validated");
        account.commitment = leg.after_commitment;
        account.sequence = account
            .sequence
            .checked_add(1)
            .ok_or_else(|| "account sequence overflow".to_string())?;
    }
    state
        .operations
        .insert(id_key(&order.settlement.operation_id), statement);
    Ok(statement)
}

fn product_batch_from_dto(
    dto: ProductSettlementBatchDto,
) -> Result<ProductSettlementBatch, String> {
    if dto.members.len() > 4096 {
        return Err("batch contains too many settlement members".into());
    }
    Ok(ProductSettlementBatch {
        batch_id: hex_array(&dto.batch_id, "batch.batchID")?,
        venue_id: hex_array(&dto.venue_id, "batch.venueID")?,
        defmi_id: hex_array(&dto.defmi_id, "batch.defmiID")?,
        admission_epoch: dto.admission_epoch,
        members: dto
            .members
            .into_iter()
            .map(|member| {
                Ok(ProductSettlementBatchMember {
                    admission_sequence: member.admission_sequence,
                    settlement_statement: hex_array(
                        &member.settlement_statement,
                        "batch.members.settlementStatement",
                    )?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    })
}

fn settle_product_batch(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &["batch", "orders", "approval", "expectedBeforeRoot"],
    )?;
    let batch = product_batch_from_dto(field(params, "batch")?)?;
    let order_dtos: Vec<ProductSettlementDto> = field(params, "orders")?;
    if order_dtos.len() > 4096 {
        return Err("batch contains too many settlement orders".into());
    }
    let orders = order_dtos
        .into_iter()
        .enumerate()
        .map(|(index, dto)| product_order_from_dto(dto, &format!("orders[{index}]")))
        .collect::<Result<Vec<_>, String>>()?;
    batch.validate_orders(&orders)?;
    let statement = batch.statement()?;
    authorize(state, params, statement, authorizer)?;
    if state.operations.contains_key(&id_key(&batch.batch_id)) {
        return Err("product settlement batch identifier was already used".into());
    }

    // validate_orders proves that each order touches disjoint operations,
    // nullifiers, facilities, holds and accounts. Consequently sequential
    // application below is equivalent to applying every member against the
    // common pre-state, while State::apply still makes the whole batch
    // crash-atomic if any later member fails.
    for order in orders {
        apply_product_settlement(state, order, timestamp)?;
    }
    state.operations.insert(id_key(&batch.batch_id), statement);
    Ok(statement)
}

fn product_note_order_from_dto(
    dto: ProductNoteSettlementDto,
    field_name: &str,
) -> Result<ProductNoteSettlementOrder, String> {
    if dto.reservations.len() > 2 {
        return Err(format!("{field_name} contains too many reservations"));
    }
    let reservations = dto
        .reservations
        .into_iter()
        .map(|reservation| {
            Ok(ReservationConsumption {
                role: match reservation.role.as_str() {
                    "maker" => ReservationRole::Maker,
                    "taker" => ReservationRole::Taker,
                    _ => return Err(format!("{field_name}.reservations.role is not supported")),
                },
                reserve_receipt_digest: hex_array(
                    &reservation.reserve_receipt_digest,
                    &format!("{field_name}.reservations.reserveReceiptDigest"),
                )?,
                transition: credit_transition_from_dto(
                    reservation.transition,
                    &format!("{field_name}.reservations.transition"),
                )?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let order = ProductNoteSettlementOrder {
        settlement: delegated_note_settlement_from_dto(
            dto.settlement,
            &format!("{field_name}.settlement"),
        )?,
        venue_id: hex_array(&dto.venue_id, &format!("{field_name}.venueID"))?,
        defmi_id: hex_array(&dto.defmi_id, &format!("{field_name}.defmiID"))?,
        maker_entity_commitment: hex_array(
            &dto.maker_entity_commitment,
            &format!("{field_name}.makerEntityCommitment"),
        )?,
        taker_entity_commitment: hex_array(
            &dto.taker_entity_commitment,
            &format!("{field_name}.takerEntityCommitment"),
        )?,
        rfq_nullifier: hex_array(&dto.rfq_nullifier, &format!("{field_name}.rfqNullifier"))?,
        taker_authorization_digest: hex_array(
            &dto.taker_authorization_digest,
            &format!("{field_name}.takerAuthorizationDigest"),
        )?,
        maker_policy_digest: hex_array(
            &dto.maker_policy_digest,
            &format!("{field_name}.makerPolicyDigest"),
        )?,
        maker_mandate_digest: hex_array(
            &dto.maker_mandate_digest,
            &format!("{field_name}.makerMandateDigest"),
        )?,
        taker_mandate_digest: hex_array(
            &dto.taker_mandate_digest,
            &format!("{field_name}.takerMandateDigest"),
        )?,
        typed_instruction_digest: hex_array(
            &dto.typed_instruction_digest,
            &format!("{field_name}.typedInstructionDigest"),
        )?,
        quote_proof_digest: hex_array(
            &dto.quote_proof_digest,
            &format!("{field_name}.quoteProofDigest"),
        )?,
        price_limit_proof_digest: hex_array(
            &dto.price_limit_proof_digest,
            &format!("{field_name}.priceLimitProofDigest"),
        )?,
        dvp_proof_digest: hex_array(
            &dto.dvp_proof_digest,
            &format!("{field_name}.dvpProofDigest"),
        )?,
        quantity_commitment: hex_array(
            &dto.quantity_commitment,
            &format!("{field_name}.quantityCommitment"),
        )?,
        cash_commitment: hex_array(
            &dto.cash_commitment,
            &format!("{field_name}.cashCommitment"),
        )?,
        traded_asset_id: hex_array(&dto.traded_asset_id, &format!("{field_name}.tradedAssetID"))?,
        asset_link_proof_digest: hex_array(
            &dto.asset_link_proof_digest,
            &format!("{field_name}.assetLinkProofDigest"),
        )?,
        admission_receipt_digest: hex_array(
            &dto.admission_receipt_digest,
            &format!("{field_name}.admissionReceiptDigest"),
        )?,
        admission_epoch: dto.admission_epoch,
        admission_sequence: dto.admission_sequence,
        reservations,
    };
    order.body()?;
    Ok(order)
}

fn product_settlement_evidence_from_dto(
    dto: ProductSettlementEvidenceDto,
    field_name: &str,
) -> Result<ProductSettlementEvidence, String> {
    let decode = |encoded: &str, name: &str| {
        BASE64
            .decode(encoded)
            .map_err(|_| format!("{field_name}.{name} is not valid base64"))
    };
    let point = CompressedRistretto(hex_array(
        &dto.asset_link.announcement,
        &format!("{field_name}.assetLink.announcement"),
    )?)
    .decompress()
    .ok_or_else(|| format!("{field_name}.assetLink.announcement is not canonical"))?;
    let response = Option::<Scalar>::from(Scalar::from_canonical_bytes(hex_array(
        &dto.asset_link.response,
        &format!("{field_name}.assetLink.response"),
    )?))
    .ok_or_else(|| format!("{field_name}.assetLink.response is not canonical"))?;
    let evidence = ProductSettlementEvidence {
        typed_instruction: decode(&dto.typed_instruction, "typedInstruction")?,
        quote_verification: decode(&dto.quote_verification, "quoteVerification")?,
        price_limit_proof: decode(&dto.price_limit_proof, "priceLimitProof")?,
        dvp_proofs: decode(&dto.dvp_proofs, "dvpProofs")?,
        mpc_execution_attestations: decode(
            &dto.mpc_execution_attestations,
            "mpcExecutionAttestations",
        )?,
        asset_link: AssetLinkProof {
            announcement: point,
            response,
        },
    };
    evidence.validate_encoding()?;
    Ok(evidence)
}

struct PreparedNoteProductReservation {
    transition: CreditFacilityTransition,
    transition_statement: [u8; 32],
    facility_key: String,
    facility: CreditFacilityRecord,
    hold_key: String,
    hold: CreditHoldRecord,
    escrow: NoteReservationRecord,
}

fn apply_note_product_settlement(
    state: &mut State,
    order: ProductNoteSettlementOrder,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    order.body()?;
    let statement = order.statement()?;
    if timestamp > order.settlement.deadline {
        return Err("anonymous product settlement has expired".into());
    }
    if state
        .operations
        .contains_key(&id_key(&order.settlement.operation_id))
    {
        return Err("settlement operation identifier was already used".into());
    }
    if state
        .nullifiers
        .contains_key(&id_key(&order.settlement.nullifier))
    {
        return Err("payment nullifier was already settled".into());
    }
    if state
        .rfq_nullifiers
        .contains_key(&id_key(&order.rfq_nullifier))
    {
        return Err("RFQ nullifier was already settled".into());
    }
    let payment_asset_id = order
        .settlement
        .spends
        .iter()
        .find(|spend| spend.asset_id != order.traded_asset_id)
        .map(|spend| spend.asset_id)
        .ok_or_else(|| "anonymous product settlement has no payment rail".to_string())?;
    let payment_asset = state
        .assets
        .get(&id_key(&payment_asset_id))
        .ok_or_else(|| "anonymous product payment asset is unknown".to_string())?;
    if !payment_asset.active || payment_asset.kind != "cash" {
        return Err("anonymous payment side is not an active cash rail".into());
    }
    if !state
        .assets
        .get(&id_key(&order.traded_asset_id))
        .is_some_and(|asset| asset.active)
    {
        return Err("anonymous traded asset is inactive or unknown".into());
    }

    let base_statement = order.settlement.statement()?;
    let mut direction = 0u8;
    let mut transition_operations = BTreeSet::new();
    let mut prepared = Vec::with_capacity(order.reservations.len());
    for consumption in &order.reservations {
        let transition = &consumption.transition;
        if consumption.reserve_receipt_digest == ZERO
            || !transition_operations.insert(transition.operation_id)
            || transition.operation_id == order.settlement.operation_id
            || state
                .operations
                .contains_key(&id_key(&transition.operation_id))
        {
            return Err("anonymous settlement repeats a used reservation operation".into());
        }
        let hold_key = id_key(&transition.hold_id);
        let binding = state
            .reservation_bindings
            .get(&hold_key)
            .ok_or_else(|| "anonymous settlement names an unknown reservation".to_string())?;
        if direction == 0 {
            direction = binding.direction;
        } else if direction != binding.direction {
            return Err("Maker and Taker reservations use different directions".into());
        }
        let mut expected_entity = order.taker_entity_commitment;
        let mut expected_authorization = order.taker_authorization_digest;
        let mut expected_mandate = order.taker_mandate_digest;
        let mut expected_asset = if direction == 1 {
            payment_asset_id
        } else {
            order.traded_asset_id
        };
        if consumption.role == ReservationRole::Maker {
            expected_entity = order.maker_entity_commitment;
            expected_authorization = order.maker_policy_digest;
            expected_mandate = order.maker_mandate_digest;
            expected_asset = if direction == 1 {
                order.traded_asset_id
            } else {
                payment_asset_id
            };
        }
        if binding.role != consumption.role.as_str()
            || binding.entity_commitment != expected_entity
            || binding.asset_id != expected_asset
            || binding.authorization_digest != expected_authorization
            || binding.mandate_digest != expected_mandate
            || binding.receipt_digest != consumption.reserve_receipt_digest
        {
            return Err("anonymous reservation differs from product settlement".into());
        }
        match consumption.role {
            ReservationRole::Maker
                if binding.policy_version == 0 || binding.rfq_nullifier != ZERO =>
            {
                return Err("Maker reservation is not policy-scoped".into());
            }
            ReservationRole::Taker
                if binding.rfq_nullifier != order.rfq_nullifier
                    || binding.admission_receipt_digest != order.admission_receipt_digest
                    || binding.admission_epoch != order.admission_epoch
                    || binding.admission_sequence != order.admission_sequence =>
            {
                return Err("Taker reservation is not for the admitted RFQ".into());
            }
            _ => {}
        }
        let expected_consumed = if (direction == 1 && consumption.role == ReservationRole::Maker)
            || (direction == 2 && consumption.role == ReservationRole::Taker)
        {
            order.quantity_commitment
        } else {
            order.cash_commitment
        };
        if transition.consumed_commitment != expected_consumed {
            return Err("guarantee consumption differs from proved anonymous DvP amount".into());
        }
        if transition.kind != CreditTransitionKind::Consume
            || transition.settlement_digest != base_statement
            || timestamp > transition.expires_at
        {
            return Err("anonymous reservation is not consumable by this DvP".into());
        }
        let facility_key = id_key(&transition.facility_id);
        let facility = state
            .credit_facilities
            .get(&facility_key)
            .cloned()
            .ok_or_else(|| "anonymous reservation facility is unknown".to_string())?;
        if facility.sequence != transition.before_sequence
            || facility.available_commitment != transition.before_available_commitment
            || facility.held_commitment != transition.before_held_commitment
            || facility.outstanding_commitment != transition.before_outstanding_commitment
            || facility.beneficiary_commitment != expected_entity
            || facility.rail_asset_id != expected_asset
        {
            return Err("anonymous consumption was proved against stale facility state".into());
        }
        let hold = state
            .credit_holds
            .get(&hold_key)
            .cloned()
            .ok_or_else(|| "anonymous reservation credit hold is unknown".to_string())?;
        if hold.facility_id != transition.facility_id
            || hold.query_commitment != transition.query_commitment
            || hold.amount_commitment != transition.amount_commitment
            || hold.expires_at != transition.expires_at
            || hold.status != "active"
        {
            return Err("anonymous consumption was proved against stale hold state".into());
        }
        let escrow = state
            .note_reservations
            .get(&hold_key)
            .cloned()
            .ok_or_else(|| "anonymous reservation escrow note is unknown".to_string())?;
        if escrow.status != "active"
            || escrow.asset_id != expected_asset
            || escrow.amount_commitment != transition.amount_commitment
        {
            return Err("reservation has no matching active escrow note".into());
        }
        let matching = order
            .settlement
            .spends
            .iter()
            .find(|spend| spend.hold_id == transition.hold_id)
            .ok_or_else(|| "reservation escrow note is omitted from DvP".to_string())?;
        if matching.asset_id != expected_asset
            || matching.escrow_note_id != escrow.escrow_note_id
            || matching.delegation_digest != escrow.delegation_digest
            || matching.proof_digest != order.dvp_proof_digest
        {
            return Err("reservation escrow note differs from the DvP".into());
        }
        let escrow_note = state
            .notes
            .get(&id_key(&escrow.escrow_note_id))
            .ok_or_else(|| "live reservation covenant note is missing".to_string())?;
        if escrow_note.asset_id != expected_asset
            || escrow_note.lock_id != transition.hold_id
            || escrow_note.value_commitment != transition.amount_commitment
        {
            return Err("live covenant note differs from its reservation".into());
        }
        let delivery = matching
            .claims
            .iter()
            .find(|claim| claim.kind == NoteClaimKind::Delivery)
            .map(|claim| claim.value_commitment);
        let refund = matching
            .claims
            .iter()
            .find(|claim| claim.kind == NoteClaimKind::Refund)
            .map(|claim| claim.value_commitment);
        if delivery != Some(transition.consumed_commitment)
            || refund != Some(transition.refund_commitment)
        {
            return Err("claim commitments differ from proved consumption and refund".into());
        }
        let serial = escrow_claim_serial(matching.escrow_note_id, matching.hold_id);
        if state.note_serials.contains_key(&id_key(&serial)) {
            return Err("reservation escrow note was already settled".into());
        }
        if matching
            .claims
            .iter()
            .any(|claim| state.note_claims.contains_key(&id_key(&claim.claim_id)))
        {
            return Err("anonymous settlement reuses a note claim".into());
        }
        prepared.push(PreparedNoteProductReservation {
            transition: transition.clone(),
            transition_statement: transition.statement()?,
            facility_key,
            facility,
            hold_key,
            hold,
            escrow,
        });
    }
    if !matches!(direction, 1 | 2) {
        return Err("anonymous product settlement has an unsupported direction".into());
    }

    for item in prepared {
        let mut facility = item.facility;
        facility.available_commitment = item.transition.after_available_commitment;
        facility.held_commitment = item.transition.after_held_commitment;
        facility.outstanding_commitment = item.transition.after_outstanding_commitment;
        facility.sequence = facility
            .sequence
            .checked_add(1)
            .ok_or_else(|| "credit facility sequence overflow".to_string())?;
        state.credit_facilities.insert(item.facility_key, facility);
        let mut hold = item.hold;
        hold.status = "consumed".into();
        hold.settlement_digest = item.transition.settlement_digest;
        hold.updated_sequence = item.transition.before_sequence + 1;
        state.credit_holds.insert(item.hold_key.clone(), hold);
        let mut escrow = item.escrow;
        escrow.status = "consumed".into();
        escrow.settlement_digest = statement;
        state.note_reservations.insert(item.hold_key, escrow);
        state.operations.insert(
            id_key(&item.transition.operation_id),
            item.transition_statement,
        );
    }
    state.nullifiers.insert(
        id_key(&order.settlement.nullifier),
        NullifierRecord {
            deadline: order.settlement.deadline,
            statement,
        },
    );
    state
        .rfq_nullifiers
        .insert(id_key(&order.rfq_nullifier), statement);
    state
        .operations
        .insert(id_key(&order.settlement.operation_id), statement);
    for spend in &order.settlement.spends {
        let serial = escrow_claim_serial(spend.escrow_note_id, spend.hold_id);
        state.note_serials.insert(
            id_key(&serial),
            NoteSerialRecord {
                deadline: order.settlement.deadline,
                asset_id: spend.asset_id,
                ring_root: spend.escrow_note_id,
                statement,
            },
        );
        for claim in &spend.claims {
            state.note_claims.insert(
                id_key(&claim.claim_id),
                NoteClaimRecord {
                    asset_id: claim.asset_id,
                    value_commitment: claim.value_commitment,
                    recipient_commitment: claim.recipient_commitment,
                    source_hold_id: claim.source_hold_id,
                    kind: claim.kind.as_str().into(),
                    opening_envelope: OpeningEnvelopeRecord::from_domain(&claim.opening_envelope)?,
                    status: "active".into(),
                    settlement_digest: statement,
                    materialization: ZERO,
                },
            );
        }
    }
    Ok(statement)
}

fn settle_note_product(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &["order", "evidence", "approval", "expectedBeforeRoot"],
    )?;
    let order = product_note_order_from_dto(field(params, "order")?, "order")?;
    let evidence = product_settlement_evidence_from_dto(field(params, "evidence")?, "evidence")?;
    let statement = order.statement()?;
    authorize(state, params, statement, authorizer)?;
    verify_product_settlement_evidence(state, &evidence, &order, timestamp)?;
    apply_note_product_settlement(state, order, timestamp)
}

fn settlement_verifier_for<'a>(
    state: &'a State,
    order: &ProductNoteSettlementOrder,
    timestamp: u64,
) -> Result<&'a SettlementVerifierRecord, String> {
    let verifier = state
        .settlement_verifiers
        .get(&id_key(&settlement_verifier_key(
            order.venue_id,
            order.admission_epoch,
        )))
        .ok_or_else(|| "settlement has no governance-pinned verifier epoch".to_string())?;
    if verifier.defmi_id != order.defmi_id
        || timestamp < verifier.valid_from
        || timestamp > verifier.valid_until
    {
        return Err("settlement verifier is not valid for this DeFMI and time".into());
    }
    Ok(verifier)
}

fn verify_typed_evidence(
    state: &State,
    raw: &[u8],
    order: &ProductNoteSettlementOrder,
    timestamp: u64,
) -> Result<typed::TypedInstruction, String> {
    let verifier = settlement_verifier_for(state, order, timestamp)?;
    let instruction = typed_wire::decode(raw)
        .map_err(|error| format!("typed zkPI evidence is invalid: {error:?}"))?;
    let wire_digest: [u8; 32] = Sha256::digest(raw).into();
    if wire_digest != order.typed_instruction_digest
        || wire_digest != order.settlement.payment_instruction_digest
    {
        return Err("typed zkPI bytes do not match the settlement digest".into());
    }
    let public = frost::keys::PublicKeyPackage::deserialize(&verifier.frost_public_package)
        .map_err(|_| "governance-pinned FROST package is invalid".to_string())?;
    let bounds = Bounds {
        amount_bits: usize::from(verifier.amount_bits),
        price_bits: usize::from(verifier.price_bits),
        max_horizon: verifier.max_horizon,
    };
    Venue::new(Pedersen::new(b"qomm:defmi:v1"), &bounds, public.clone())
        .require_threshold_ranges()
        .verify(&instruction.payment, timestamp)
        .map_err(|error| format!("MPC zkPI payment verification failed: {error}"))?;
    let typed_digest =
        typed::digest_for(&instruction.payment, &instruction.context, DEFAULT_DOMAIN)
            .map_err(str::to_string)?;
    public
        .verifying_key()
        .verify(&typed_digest, &instruction.authorization)
        .map_err(|_| "MPC typed zkPI authorization is invalid".to_string())?;
    let context = &instruction.context;
    let maker = order
        .reservations
        .iter()
        .find(|reservation| reservation.role == ReservationRole::Maker)
        .ok_or_else(|| "settlement has no Maker reservation".to_string())?;
    let taker = order
        .reservations
        .iter()
        .find(|reservation| reservation.role == ReservationRole::Taker)
        .ok_or_else(|| "settlement has no Taker reservation".to_string())?;
    if context.venue_id != order.venue_id
        || context.defmi_id != order.defmi_id
        || context.rfq_nullifier != order.rfq_nullifier
        || context.taker_mandate_digest != order.taker_mandate_digest
        || context.taker_mandate_digest != order.taker_authorization_digest
        || context.maker_policy_digest != order.maker_policy_digest
        || context.maker_mandate_digest != order.maker_mandate_digest
        || context.quote_proof_digest != order.quote_proof_digest
        || context.market_statement_digest != order.settlement.market_statement_digest
        || context.before_state_root != state.root()
        || context.maker_reservation_id != maker.transition.hold_id
        || context.taker_reservation_id != taker.transition.hold_id
        || context.maker_reservation_sequence != maker.transition.before_sequence
        || context.taker_reservation_sequence != taker.transition.before_sequence
        || context.maker_reserve_receipt_digest != maker.reserve_receipt_digest
        || context.taker_reserve_receipt_digest != taker.reserve_receipt_digest
        || instruction.payment.amount_commitment.compress().to_bytes() != order.quantity_commitment
        || instruction.payment.nullifier() != order.settlement.nullifier
        || instruction.payment.deadline != order.settlement.deadline
        || !instruction.payment.ranges.is_threshold()
        || instruction.payment.quote_proof_digest() != Some(order.quote_proof_digest)
    {
        return Err("typed zkPI context differs from the canonical settlement".into());
    }
    Ok(instruction)
}

fn verify_quote_evidence(
    state: &State,
    raw: &[u8],
    order: &ProductNoteSettlementOrder,
    timestamp: u64,
) -> Result<QuoteVerificationBundle, String> {
    let verifier = settlement_verifier_for(state, order, timestamp)?;
    let evidence = decode_quote_verification(raw)?;
    let digest = evidence.verify()?;
    if evidence.eligibility_bits != usize::from(verifier.quote_eligibility_bits)
        || evidence.span_bits != usize::from(verifier.quote_span_bits)
        || evidence.public.registry_digest != verifier.quote_registry_digest
    {
        return Err("complete quote proof differs from the governance-pinned circuit".into());
    }
    if digest != order.quote_proof_digest {
        return Err("complete quote proof does not match the settlement digest".into());
    }
    let winning_policy = evidence
        .public
        .registry
        .get(evidence.proof.winner_index)
        .ok_or_else(|| "complete quote proof has no winning policy".to_string())?;
    if registered_policy_digest(evidence.proof.winner_index, winning_policy)
        != order.maker_policy_digest
    {
        return Err("complete quote proof winner differs from the signed Maker policy".into());
    }
    if evidence.public.market_digest != order.settlement.market_statement_digest {
        return Err("complete quote proof names another market statement".into());
    }
    if evidence.public.slot != order.admission_sequence {
        return Err("complete quote proof names another admission sequence".into());
    }
    let quote_time = u64::try_from(evidence.public.now)
        .map_err(|_| "complete quote proof has a negative market time".to_string())?;
    if quote_time > timestamp || timestamp - quote_time > verifier.max_horizon {
        return Err("complete quote proof is future-dated or stale".into());
    }
    Ok(evidence)
}

fn settlement_point(encoded: [u8; 32], name: &str) -> Result<RistrettoPoint, String> {
    CompressedRistretto(encoded)
        .decompress()
        .ok_or_else(|| format!("{name} is not a canonical Ristretto commitment"))
}

/// Re-run every public cryptographic check on each validator.  The k-of-n MPC
/// committee is trusted only for secret witness handling and liveness; its
/// approval cannot substitute for price-limit, DvP, asset, quote, or typed-zkPI
/// verification by the replicated DeFMI state machine.
fn verify_product_settlement_evidence(
    state: &State,
    evidence: &ProductSettlementEvidence,
    order: &ProductNoteSettlementOrder,
    timestamp: u64,
) -> Result<(), String> {
    evidence.validate_encoding()?;
    let instruction = verify_typed_evidence(state, &evidence.typed_instruction, order, timestamp)?;
    let quote = verify_quote_evidence(state, &evidence.quote_verification, order, timestamp)?;
    let verifier = settlement_verifier_for(state, order, timestamp)?;
    let maker = order
        .reservations
        .iter()
        .find(|reservation| reservation.role == ReservationRole::Maker)
        .ok_or_else(|| "settlement has no Maker reservation".to_string())?;
    let taker = order
        .reservations
        .iter()
        .find(|reservation| reservation.role == ReservationRole::Taker)
        .ok_or_else(|| "settlement has no Taker reservation".to_string())?;
    let maker_binding = state
        .reservation_bindings
        .get(&id_key(&maker.transition.hold_id))
        .ok_or_else(|| "Maker reservation has no canonical product binding".to_string())?;
    let taker_binding = state
        .reservation_bindings
        .get(&id_key(&taker.transition.hold_id))
        .ok_or_else(|| "Taker reservation has no canonical product binding".to_string())?;
    if maker_binding.role != ReservationRole::Maker.as_str()
        || taker_binding.role != ReservationRole::Taker.as_str()
        || maker_binding.direction != taker_binding.direction
    {
        return Err("Maker and Taker reservation directions are inconsistent".into());
    }
    let direction = maker_binding.direction;
    let context_direction = match instruction.context.direction {
        typed::TradeDirection::TakerBuys => 1,
        typed::TradeDirection::TakerSells => 2,
    };
    let quote_direction = match instruction.context.direction {
        typed::TradeDirection::TakerBuys => 0,
        typed::TradeDirection::TakerSells => 1,
    };
    if direction != context_direction
        || quote.public.direction != quote_direction
        || quote.public.qty_commitment != instruction.payment.amount_commitment
    {
        return Err("reserved request, Quote proof and typed zkPI are inconsistent".into());
    }

    let admission_batch = state
        .admission_batches
        .get(&id_key(&taker_binding.admission_batch_id))
        .ok_or_else(|| "settlement execution has no registered admission batch".to_string())?;
    let committee = state
        .admission_committees
        .get(&admission_committee_key(
            &admission_batch.venue_id,
            admission_batch.epoch,
        ))
        .ok_or_else(|| {
            "settlement execution has no governance-pinned resident committee".to_string()
        })?;
    let trusted_keys = committee
        .node_keys
        .iter()
        .map(|value| {
            VerifyingKey::from_bytes(value)
                .map_err(|_| "stored resident execution key is invalid".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let execution_attestations =
        decode_execution_attestations(&evidence.mpc_execution_attestations)?;
    let execution = verify_execution_lane(
        &execution_attestations,
        &trusted_keys,
        admission_batch.order_digest,
    )?;
    let lane = order
        .admission_sequence
        .checked_sub(1)
        .ok_or_else(|| "settlement admission sequence cannot identify an MPC lane".to_string())?;
    if execution.slot != admission_batch.slot
        || execution.lane != lane
        || execution.cluster_digest != admission_batch.batch_digest
        || admission_batch.venue_id != order.venue_id
        || admission_batch.epoch != order.admission_epoch
    {
        return Err("signed MPC execution receipts differ from the admitted lane".into());
    }
    let job_id = live_proof_job_id(
        u32::try_from(execution.slot)
            .map_err(|_| "settlement MPC slot is outside u32".to_string())?,
        usize::try_from(execution.lane)
            .map_err(|_| "settlement MPC lane is outside usize".to_string())?,
        execution.digest,
    )?;
    if quote.context != complete_quote_context(job_id, order.taker_mandate_digest) {
        return Err(
            "complete quote proof is not bound to the signed MPC execution receipts".into(),
        );
    }

    let key = Pedersen::new(b"qomm:defmi:v1");
    let limit_commitment = settlement_point(
        taker_binding.limit_price_commitment,
        "reserved Taker price limit",
    )?;
    let price_direction = match direction {
        1 => PriceLimitDirection::MaximumBuyPrice,
        2 => PriceLimitDirection::MinimumSellPrice,
        _ => return Err("settlement reservation direction is unsupported".into()),
    };
    let price_limit = threshold_price_limit(
        &key,
        &instruction.payment.price_commitment,
        &limit_commitment,
        price_direction,
        usize::from(verifier.price_bits),
        &order.taker_mandate_digest,
        decode_threshold_range(&evidence.price_limit_proof)?,
    )?;
    if price_limit.digest(
        &instruction.payment.price_commitment,
        &limit_commitment,
        &order.taker_mandate_digest,
    ) != order.price_limit_proof_digest
    {
        return Err("price-limit proof differs from the settled digest".into());
    }

    let (securities, cash) = match direction {
        1 => (maker, taker),
        2 => (taker, maker),
        _ => unreachable!("direction was validated"),
    };
    let securities_reserve = settlement_point(
        securities.transition.amount_commitment,
        "securities reservation",
    )?;
    let cash_reserve = settlement_point(cash.transition.amount_commitment, "cash reservation")?;
    let cash_commitment = settlement_point(order.cash_commitment, "settlement cash amount")?;
    let package = build_threshold_package_from_proofs(
        &key,
        instruction.payment.clone(),
        Sides::of(&instruction.payment),
        securities_reserve,
        cash_reserve,
        cash_commitment,
        decode_dvp_proofs(&evidence.dvp_proofs)?,
        usize::from(verifier.amount_bits),
    )?;
    if package.digest() != order.dvp_proof_digest
        || package.instruction.amount_commitment.compress().to_bytes() != order.quantity_commitment
        || package.cash_commitment.compress().to_bytes() != order.cash_commitment
        || package.securities_remainder.compress().to_bytes()
            != securities.transition.refund_commitment
        || package.cash_remainder.compress().to_bytes() != cash.transition.refund_commitment
    {
        return Err("DvP proof differs from the canonical reservation consumption".into());
    }

    if !asset_link::verify(
        &key,
        &order.traded_asset_id,
        &instruction.payment.asset_commitment,
        &evidence.asset_link,
    ) || evidence.asset_link.digest(
        &order.traded_asset_id,
        &instruction.payment.asset_commitment,
    ) != order.asset_link_proof_digest
    {
        return Err("zkPI asset is not the traded DeFMI asset".into());
    }
    Ok(())
}

fn note_product_batch_from_dto(
    dto: ProductSettlementBatchDto,
) -> Result<ProductNoteSettlementBatch, String> {
    if dto.members.len() > 4096 {
        return Err("anonymous batch contains too many settlement members".into());
    }
    Ok(ProductNoteSettlementBatch {
        batch_id: hex_array(&dto.batch_id, "batch.batchID")?,
        venue_id: hex_array(&dto.venue_id, "batch.venueID")?,
        defmi_id: hex_array(&dto.defmi_id, "batch.defmiID")?,
        admission_epoch: dto.admission_epoch,
        members: dto
            .members
            .into_iter()
            .map(|member| {
                Ok(ProductSettlementBatchMember {
                    admission_sequence: member.admission_sequence,
                    settlement_statement: hex_array(
                        &member.settlement_statement,
                        "batch.members.settlementStatement",
                    )?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    })
}

fn settle_note_product_batch(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &[
            "batch",
            "orders",
            "evidence",
            "approval",
            "expectedBeforeRoot",
        ],
    )?;
    let batch = note_product_batch_from_dto(field(params, "batch")?)?;
    let order_dtos: Vec<ProductNoteSettlementDto> = field(params, "orders")?;
    if order_dtos.len() > 4096 {
        return Err("anonymous batch contains too many settlement orders".into());
    }
    let orders = order_dtos
        .into_iter()
        .enumerate()
        .map(|(index, dto)| product_note_order_from_dto(dto, &format!("orders[{index}]")))
        .collect::<Result<Vec<_>, String>>()?;
    let evidence_dtos: Vec<ProductSettlementEvidenceDto> = field(params, "evidence")?;
    if evidence_dtos.len() != orders.len() {
        return Err("anonymous batch must carry one complete proof bundle per order".into());
    }
    let evidence = evidence_dtos
        .into_iter()
        .enumerate()
        .map(|(index, dto)| {
            product_settlement_evidence_from_dto(dto, &format!("evidence[{index}]"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    batch.validate_orders(&orders)?;
    let statement = batch.statement()?;
    authorize(state, params, statement, authorizer)?;
    for (proofs, order) in evidence.iter().zip(&orders) {
        verify_product_settlement_evidence(state, proofs, order, timestamp)?;
    }
    if state.operations.contains_key(&id_key(&batch.batch_id)) {
        return Err("anonymous settlement batch identifier was already used".into());
    }
    for order in orders {
        apply_note_product_settlement(state, order, timestamp)?;
    }
    state.operations.insert(id_key(&batch.batch_id), statement);
    Ok(statement)
}

fn register_asset(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
) -> Result<[u8; 32], String> {
    require_keys(params, &["asset", "approval", "expectedBeforeRoot"])?;
    let dto: AssetDto = field(params, "asset")?;
    let definition = AssetDefinition {
        asset_id: hex_array(&dto.asset_id, "asset.assetID")?,
        code: dto.code,
        kind: match dto.kind.as_str() {
            "cash" => AssetKind::Cash,
            "security" => AssetKind::Security,
            "fund" => AssetKind::Fund,
            "commodity" => AssetKind::Commodity,
            "carbon" => AssetKind::Carbon,
            "other" => AssetKind::Other,
            _ => return Err("asset.kind is not supported".into()),
        },
        decimals: dto.decimals,
        terms_digest: hex_array(&dto.terms_digest, "asset.termsDigest")?,
    };
    definition.body()?;
    let statement = definition.statement()?;
    authorize(state, params, statement, authorizer)?;
    let key = id_key(&definition.asset_id);
    if state.assets.contains_key(&key) {
        return Err("asset identifier is already registered".into());
    }
    state.assets.insert(
        key,
        AssetRecord {
            code: definition.code,
            kind: definition.kind.as_str().into(),
            decimals: definition.decimals,
            terms_digest: definition.terms_digest,
            active: true,
        },
    );
    Ok(statement)
}

fn open_account(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
) -> Result<[u8; 32], String> {
    require_keys(params, &["opening", "approval", "expectedBeforeRoot"])?;
    let dto: AccountOpeningDto = field(params, "opening")?;
    let opening = AccountOpening {
        handle: hex_array(&dto.handle, "opening.handle")?,
        asset_id: hex_array(&dto.asset_id, "opening.assetID")?,
        commitment: hex_array(&dto.commitment, "opening.commitment")?,
        issuance_nonce: hex_array(&dto.issuance_nonce, "opening.issuanceNonce")?,
    };
    opening.body()?;
    let statement = opening.statement()?;
    authorize(state, params, statement, authorizer)?;
    let asset = state
        .assets
        .get(&id_key(&opening.asset_id))
        .ok_or_else(|| "account asset is unknown".to_string())?;
    if !asset.active {
        return Err("account asset is inactive".into());
    }
    let key = id_key(&opening.handle);
    if state.accounts.contains_key(&key) {
        return Err("account handle is already registered".into());
    }
    state.accounts.insert(
        key,
        AccountRecord {
            asset_id: opening.asset_id,
            commitment: opening.commitment,
            sequence: 0,
        },
    );
    Ok(statement)
}

fn register_guarantor(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
) -> Result<[u8; 32], String> {
    require_keys(params, &["guarantor", "approval", "expectedBeforeRoot"])?;
    let dto: GuarantorDto = field(params, "guarantor")?;
    let definition = GuarantorDefinition {
        guarantor_id: hex_array(&dto.guarantor_id, "guarantor.guarantorID")?,
        kind: match dto.kind.as_str() {
            "ccp" => GuarantorKind::CentralCounterparty,
            "bank" => GuarantorKind::Bank,
            "self" => GuarantorKind::SelfGuaranteed,
            _ => return Err("guarantor.kind is not supported".into()),
        },
        name: dto.name,
        public_key: hex_array(&dto.public_key, "guarantor.publicKey")?,
        risk_policy_digest: hex_array(&dto.risk_policy_digest, "guarantor.riskPolicyDigest")?,
    };
    definition.body()?;
    let statement = definition.statement()?;
    authorize(state, params, statement, authorizer)?;
    let key = id_key(&definition.guarantor_id);
    if state.guarantors.contains_key(&key) {
        return Err("guarantor identifier is already registered".into());
    }
    state.guarantors.insert(
        key,
        GuarantorRecord {
            kind: definition.kind.as_str().into(),
            name: definition.name,
            public_key: definition.public_key,
            risk_policy_digest: definition.risk_policy_digest,
            active: true,
        },
    );
    Ok(statement)
}

fn grant_credit(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["grant", "approval", "expectedBeforeRoot"])?;
    let dto: CreditGrantDto = field(params, "grant")?;
    let grant = CreditFacilityGrant {
        operation_id: hex_array(&dto.operation_id, "grant.operationID")?,
        facility_id: hex_array(&dto.facility_id, "grant.facilityID")?,
        guarantor_id: hex_array(&dto.guarantor_id, "grant.guarantorID")?,
        beneficiary_commitment: hex_array(
            &dto.beneficiary_commitment,
            "grant.beneficiaryCommitment",
        )?,
        rail_asset_id: hex_array(&dto.rail_asset_id, "grant.railAssetID")?,
        cap_commitment: hex_array(&dto.cap_commitment, "grant.capCommitment")?,
        available_commitment: hex_array(&dto.available_commitment, "grant.availableCommitment")?,
        held_commitment: hex_array(&dto.held_commitment, "grant.heldCommitment")?,
        outstanding_commitment: hex_array(
            &dto.outstanding_commitment,
            "grant.outstandingCommitment",
        )?,
        collateral_commitment: hex_array(&dto.collateral_commitment, "grant.collateralCommitment")?,
        risk_policy_digest: hex_array(&dto.risk_policy_digest, "grant.riskPolicyDigest")?,
        relation_proof_digest: hex_array(&dto.relation_proof_digest, "grant.relationProofDigest")?,
        valid_from: dto.valid_from,
        valid_until: dto.valid_until,
        nonce: hex_array(&dto.nonce, "grant.nonce")?,
        guarantor_signature: Signature::from_bytes(&hex_array(
            &dto.guarantor_signature,
            "grant.guarantorSignature",
        )?),
    };
    grant.unsigned_body()?;
    let statement = grant.statement()?;
    authorize(state, params, statement, authorizer)?;
    if timestamp > grant.valid_until {
        return Err("credit facility is already expired".into());
    }
    if state.operations.contains_key(&id_key(&grant.operation_id)) {
        return Err("operation identifier was already used".into());
    }
    let guarantor = state
        .guarantors
        .get(&id_key(&grant.guarantor_id))
        .ok_or_else(|| "credit facility names an unknown guarantor".to_string())?;
    if !guarantor.active || guarantor.risk_policy_digest != grant.risk_policy_digest {
        return Err("credit facility uses an inactive guarantor or unregistered policy".into());
    }
    VerifyingKey::from_bytes(&guarantor.public_key)
        .map_err(|_| "stored guarantor public key is invalid".to_string())?
        .verify(&grant.guarantor_message()?, &grant.guarantor_signature)
        .map_err(|_| "credit facility has an invalid guarantor signature".to_string())?;
    if !state
        .assets
        .get(&id_key(&grant.rail_asset_id))
        .is_some_and(|asset| asset.active)
    {
        return Err("credit facility uses an inactive or unknown asset".into());
    }
    let key = id_key(&grant.facility_id);
    if state.credit_facilities.contains_key(&key)
        || state.credit_facilities.values().any(|existing| {
            existing.guarantor_id == grant.guarantor_id
                && existing.beneficiary_commitment == grant.beneficiary_commitment
                && existing.rail_asset_id == grant.rail_asset_id
        })
    {
        return Err("credit facility identifier or guarantor scope is already registered".into());
    }
    state.credit_facilities.insert(
        key,
        CreditFacilityRecord {
            guarantor_id: grant.guarantor_id,
            beneficiary_commitment: grant.beneficiary_commitment,
            rail_asset_id: grant.rail_asset_id,
            cap_commitment: grant.cap_commitment,
            available_commitment: grant.available_commitment,
            held_commitment: grant.held_commitment,
            outstanding_commitment: grant.outstanding_commitment,
            overlimit_commitment: ZERO,
            collateral_commitment: grant.collateral_commitment,
            risk_policy_digest: grant.risk_policy_digest,
            valid_from: grant.valid_from,
            valid_until: grant.valid_until,
            status: "active".into(),
            sequence: 0,
        },
    );
    state
        .operations
        .insert(id_key(&grant.operation_id), statement);
    Ok(statement)
}

fn transition_credit(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["transition", "approval", "expectedBeforeRoot"])?;
    let dto: CreditTransitionDto = field(params, "transition")?;
    let transition = CreditFacilityTransition {
        operation_id: hex_array(&dto.operation_id, "transition.operationID")?,
        facility_id: hex_array(&dto.facility_id, "transition.facilityID")?,
        hold_id: hex_array(&dto.hold_id, "transition.holdID")?,
        kind: match dto.kind.as_str() {
            "hold" => CreditTransitionKind::Hold,
            "release" => CreditTransitionKind::Release,
            "consume" => CreditTransitionKind::Consume,
            _ => return Err("transition.kind is not supported".into()),
        },
        query_commitment: hex_array(&dto.query_commitment, "transition.queryCommitment")?,
        amount_commitment: hex_array(&dto.amount_commitment, "transition.amountCommitment")?,
        consumed_commitment: hex_array(&dto.consumed_commitment, "transition.consumedCommitment")?,
        refund_commitment: hex_array(&dto.refund_commitment, "transition.refundCommitment")?,
        before_available_commitment: hex_array(
            &dto.before_available_commitment,
            "transition.beforeAvailableCommitment",
        )?,
        after_available_commitment: hex_array(
            &dto.after_available_commitment,
            "transition.afterAvailableCommitment",
        )?,
        before_held_commitment: hex_array(
            &dto.before_held_commitment,
            "transition.beforeHeldCommitment",
        )?,
        after_held_commitment: hex_array(
            &dto.after_held_commitment,
            "transition.afterHeldCommitment",
        )?,
        before_outstanding_commitment: hex_array(
            &dto.before_outstanding_commitment,
            "transition.beforeOutstandingCommitment",
        )?,
        after_outstanding_commitment: hex_array(
            &dto.after_outstanding_commitment,
            "transition.afterOutstandingCommitment",
        )?,
        before_sequence: dto.before_sequence,
        expires_at: dto.expires_at,
        settlement_digest: hex_array(&dto.settlement_digest, "transition.settlementDigest")?,
        relation_proof_digest: hex_array(
            &dto.relation_proof_digest,
            "transition.relationProofDigest",
        )?,
    };
    transition.body()?;
    let statement = transition.statement()?;
    authorize(state, params, statement, authorizer)?;
    if state
        .operations
        .contains_key(&id_key(&transition.operation_id))
    {
        return Err("operation identifier was already used".into());
    }
    let facility_key = id_key(&transition.facility_id);
    let mut facility = state
        .credit_facilities
        .get(&facility_key)
        .cloned()
        .ok_or_else(|| "credit transition names an unknown facility".to_string())?;
    if facility.sequence != transition.before_sequence
        || facility.available_commitment != transition.before_available_commitment
        || facility.held_commitment != transition.before_held_commitment
        || facility.outstanding_commitment != transition.before_outstanding_commitment
    {
        return Err("credit transition was proved against stale facility state".into());
    }
    let hold_key = id_key(&transition.hold_id);
    let hold = match transition.kind {
        CreditTransitionKind::Hold => {
            if facility.status != "active"
                || timestamp < facility.valid_from
                || timestamp > facility.valid_until
            {
                return Err("credit facility is not active".into());
            }
            if transition.expires_at < timestamp || transition.expires_at > facility.valid_until {
                return Err("credit hold expiry is outside the facility interval".into());
            }
            if transition.before_outstanding_commitment != transition.after_outstanding_commitment {
                return Err("a new hold cannot change settled debt".into());
            }
            if state.credit_holds.contains_key(&hold_key) {
                return Err("credit hold identifier is already registered".into());
            }
            CreditHoldRecord {
                facility_id: transition.facility_id,
                query_commitment: transition.query_commitment,
                amount_commitment: transition.amount_commitment,
                expires_at: transition.expires_at,
                status: "active".into(),
                settlement_digest: ZERO,
                created_sequence: transition.before_sequence + 1,
                updated_sequence: transition.before_sequence + 1,
            }
        }
        CreditTransitionKind::Release | CreditTransitionKind::Consume => {
            let mut hold = state
                .credit_holds
                .get(&hold_key)
                .cloned()
                .ok_or_else(|| "credit transition names an unknown hold".to_string())?;
            if hold.facility_id != transition.facility_id
                || hold.query_commitment != transition.query_commitment
                || hold.amount_commitment != transition.amount_commitment
                || hold.expires_at != transition.expires_at
                || hold.status != "active"
            {
                return Err("credit transition was proved against stale hold state".into());
            }
            if transition.kind == CreditTransitionKind::Release {
                if timestamp <= transition.expires_at {
                    return Err("credit hold cannot be released before signed expiry".into());
                }
                if transition.before_outstanding_commitment
                    != transition.after_outstanding_commitment
                {
                    return Err("hold release cannot change settled debt".into());
                }
                hold.status = "released".into();
            } else {
                if timestamp > transition.expires_at {
                    return Err("expired credit hold cannot be consumed".into());
                }
                hold.status = "consumed".into();
            }
            hold.settlement_digest = transition.settlement_digest;
            hold.updated_sequence = transition.before_sequence + 1;
            hold
        }
    };
    facility.available_commitment = transition.after_available_commitment;
    facility.held_commitment = transition.after_held_commitment;
    facility.outstanding_commitment = transition.after_outstanding_commitment;
    facility.sequence = facility
        .sequence
        .checked_add(1)
        .ok_or_else(|| "credit facility sequence overflow".to_string())?;
    state.credit_facilities.insert(facility_key, facility);
    state.credit_holds.insert(hold_key, hold);
    state
        .operations
        .insert(id_key(&transition.operation_id), statement);
    Ok(statement)
}

fn control_credit(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["control", "approval", "expectedBeforeRoot"])?;
    let dto: CreditControlDto = field(params, "control")?;
    let control = CreditFacilityControl {
        operation_id: hex_array(&dto.operation_id, "control.operationID")?,
        facility_id: hex_array(&dto.facility_id, "control.facilityID")?,
        action: match dto.action.as_str() {
            "activate" => CreditControlAction::Activate,
            "freeze" => CreditControlAction::Freeze,
            "close" => CreditControlAction::Close,
            "default" => CreditControlAction::Default,
            _ => return Err("control.action is not supported".into()),
        },
        before_sequence: dto.before_sequence,
        effective_at: dto.effective_at,
        reason_digest: hex_array(&dto.reason_digest, "control.reasonDigest")?,
        guarantor_signature: Signature::from_bytes(&hex_array(
            &dto.guarantor_signature,
            "control.guarantorSignature",
        )?),
    };
    control.unsigned_body()?;
    let statement = control.statement()?;
    authorize(state, params, statement, authorizer)?;
    if control.effective_at > timestamp {
        return Err("credit control is not yet effective".into());
    }
    if state
        .operations
        .contains_key(&id_key(&control.operation_id))
    {
        return Err("operation identifier was already used".into());
    }
    let facility_key = id_key(&control.facility_id);
    let mut facility = state
        .credit_facilities
        .get(&facility_key)
        .cloned()
        .ok_or_else(|| "credit control names an unknown facility".to_string())?;
    if facility.sequence != control.before_sequence {
        return Err("credit control was signed against stale facility state".into());
    }
    let guarantor = state
        .guarantors
        .get(&id_key(&facility.guarantor_id))
        .ok_or_else(|| "credit facility guarantor is missing".to_string())?;
    if !guarantor.active {
        return Err("inactive guarantor cannot control a facility".into());
    }
    VerifyingKey::from_bytes(&guarantor.public_key)
        .map_err(|_| "stored guarantor public key is invalid".to_string())?
        .verify(&control.guarantor_message()?, &control.guarantor_signature)
        .map_err(|_| "credit control lacks the guarantor signature".to_string())?;
    match control.action {
        CreditControlAction::Activate if facility.status != "frozen" => {
            return Err("only a frozen facility can be reactivated".into());
        }
        CreditControlAction::Activate if facility.overlimit_commitment != ZERO => {
            return Err("over-limit facility must be rehabilitated before activation".into());
        }
        CreditControlAction::Freeze if facility.status != "active" => {
            return Err("only an active facility can be frozen".into());
        }
        CreditControlAction::Close
            if facility.held_commitment != ZERO
                || facility.outstanding_commitment != ZERO
                || facility.overlimit_commitment != ZERO =>
        {
            return Err(
                "facility with holds, debt, or an over-limit balance cannot be closed".into(),
            );
        }
        CreditControlAction::Default if facility.status == "closed" => {
            return Err("closed facility cannot enter default".into());
        }
        _ => {}
    }
    facility.status = control.action.status().as_str().into();
    facility.sequence = facility
        .sequence
        .checked_add(1)
        .ok_or_else(|| "credit facility sequence overflow".to_string())?;
    state.credit_facilities.insert(facility_key, facility);
    state
        .operations
        .insert(id_key(&control.operation_id), statement);
    Ok(statement)
}

fn amend_credit(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["amendment", "approval", "expectedBeforeRoot"])?;
    let dto: CreditAmendmentDto = field(params, "amendment")?;
    let amendment = CreditFacilityAmendment {
        operation_id: hex_array(&dto.operation_id, "amendment.operationID")?,
        facility_id: hex_array(&dto.facility_id, "amendment.facilityID")?,
        mode: match dto.mode.as_str() {
            "within_limit" => CreditAmendmentMode::WithinLimit,
            "over_limit" => CreditAmendmentMode::OverLimit,
            _ => return Err("amendment.mode is not supported".into()),
        },
        before_cap_commitment: hex_array(
            &dto.before_cap_commitment,
            "amendment.beforeCapCommitment",
        )?,
        after_cap_commitment: hex_array(&dto.after_cap_commitment, "amendment.afterCapCommitment")?,
        before_available_commitment: hex_array(
            &dto.before_available_commitment,
            "amendment.beforeAvailableCommitment",
        )?,
        after_available_commitment: hex_array(
            &dto.after_available_commitment,
            "amendment.afterAvailableCommitment",
        )?,
        before_held_commitment: hex_array(
            &dto.before_held_commitment,
            "amendment.beforeHeldCommitment",
        )?,
        before_outstanding_commitment: hex_array(
            &dto.before_outstanding_commitment,
            "amendment.beforeOutstandingCommitment",
        )?,
        before_overlimit_commitment: hex_array(
            &dto.before_overlimit_commitment,
            "amendment.beforeOverlimitCommitment",
        )?,
        after_overlimit_commitment: hex_array(
            &dto.after_overlimit_commitment,
            "amendment.afterOverlimitCommitment",
        )?,
        before_collateral_commitment: hex_array(
            &dto.before_collateral_commitment,
            "amendment.beforeCollateralCommitment",
        )?,
        after_collateral_commitment: hex_array(
            &dto.after_collateral_commitment,
            "amendment.afterCollateralCommitment",
        )?,
        before_risk_policy_digest: hex_array(
            &dto.before_risk_policy_digest,
            "amendment.beforeRiskPolicyDigest",
        )?,
        after_risk_policy_digest: hex_array(
            &dto.after_risk_policy_digest,
            "amendment.afterRiskPolicyDigest",
        )?,
        before_valid_until: dto.before_valid_until,
        after_valid_until: dto.after_valid_until,
        before_sequence: dto.before_sequence,
        effective_at: dto.effective_at,
        reason_digest: hex_array(&dto.reason_digest, "amendment.reasonDigest")?,
        relation_proof_digest: hex_array(
            &dto.relation_proof_digest,
            "amendment.relationProofDigest",
        )?,
        guarantor_signature: Signature::from_bytes(&hex_array(
            &dto.guarantor_signature,
            "amendment.guarantorSignature",
        )?),
    };
    amendment.unsigned_body()?;
    let statement = amendment.statement()?;
    authorize(state, params, statement, authorizer)?;
    if amendment.effective_at > timestamp || amendment.after_valid_until < timestamp {
        return Err("credit amendment is not effective or has expired".into());
    }
    if state
        .operations
        .contains_key(&id_key(&amendment.operation_id))
    {
        return Err("operation identifier was already used".into());
    }
    let facility_key = id_key(&amendment.facility_id);
    let mut facility = state
        .credit_facilities
        .get(&facility_key)
        .cloned()
        .ok_or_else(|| "credit amendment names an unknown facility".to_string())?;
    if facility.status == "closed" || facility.status == "defaulted" {
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
    let guarantor = state
        .guarantors
        .get(&id_key(&facility.guarantor_id))
        .ok_or_else(|| "credit facility guarantor is missing".to_string())?;
    if !guarantor.active {
        return Err("inactive guarantor cannot amend a facility".into());
    }
    if guarantor.risk_policy_digest != amendment.after_risk_policy_digest {
        return Err("credit amendment uses an unregistered guarantor risk policy".into());
    }
    VerifyingKey::from_bytes(&guarantor.public_key)
        .map_err(|_| "stored guarantor public key is invalid".to_string())?
        .verify(
            &amendment.guarantor_message()?,
            &amendment.guarantor_signature,
        )
        .map_err(|_| "credit amendment lacks the guarantor signature".to_string())?;
    facility.cap_commitment = amendment.after_cap_commitment;
    facility.available_commitment = amendment.after_available_commitment;
    facility.overlimit_commitment = amendment.after_overlimit_commitment;
    facility.collateral_commitment = amendment.after_collateral_commitment;
    facility.risk_policy_digest = amendment.after_risk_policy_digest;
    facility.valid_until = amendment.after_valid_until;
    if amendment.mode == CreditAmendmentMode::OverLimit {
        facility.status = "frozen".into();
    }
    facility.sequence = facility
        .sequence
        .checked_add(1)
        .ok_or_else(|| "credit facility sequence overflow".to_string())?;
    state.credit_facilities.insert(facility_key, facility);
    state
        .operations
        .insert(id_key(&amendment.operation_id), statement);
    Ok(statement)
}

fn settle(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["order", "approval", "expectedBeforeRoot"])?;
    let dto: SettlementDto = field(params, "order")?;
    let order = SettlementOrder {
        operation_id: hex_array(&dto.operation_id, "order.operationID")?,
        nullifier: hex_array(&dto.nullifier, "order.nullifier")?,
        deadline: dto.deadline,
        payment_instruction_digest: hex_array(
            &dto.payment_instruction_digest,
            "order.paymentInstructionDigest",
        )?,
        proof_digest: hex_array(&dto.proof_digest, "order.proofDigest")?,
        market_statement_digest: hex_array(
            &dto.market_statement_digest,
            "order.marketStatementDigest",
        )?,
        legs: dto
            .legs
            .into_iter()
            .map(|leg| {
                Ok(StateLeg {
                    handle: hex_array(&leg.handle, "order.legs.handle")?,
                    asset_id: hex_array(&leg.asset_id, "order.legs.assetID")?,
                    before_commitment: hex_array(
                        &leg.before_commitment,
                        "order.legs.beforeCommitment",
                    )?,
                    after_commitment: hex_array(
                        &leg.after_commitment,
                        "order.legs.afterCommitment",
                    )?,
                    before_sequence: leg.before_sequence,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    };
    order.body()?;
    let statement = order.statement()?;
    authorize(state, params, statement, authorizer)?;
    if timestamp > order.deadline {
        return Err("payment instruction has expired".into());
    }
    if state.operations.contains_key(&id_key(&order.operation_id)) {
        return Err("operation identifier was already used".into());
    }
    if state.nullifiers.contains_key(&id_key(&order.nullifier)) {
        return Err("payment nullifier was already settled".into());
    }
    for leg in &order.legs {
        let account = state
            .accounts
            .get(&id_key(&leg.handle))
            .ok_or_else(|| "settlement names an unknown account".to_string())?;
        if account.asset_id != leg.asset_id {
            return Err("settlement leg is on the wrong asset rail".into());
        }
        if account.commitment != leg.before_commitment || account.sequence != leg.before_sequence {
            return Err("settlement was proved against stale account state".into());
        }
        if !state
            .assets
            .get(&id_key(&leg.asset_id))
            .is_some_and(|asset| asset.active)
        {
            return Err("settlement uses an inactive or unknown asset".into());
        }
    }
    state.nullifiers.insert(
        id_key(&order.nullifier),
        NullifierRecord {
            deadline: order.deadline,
            statement,
        },
    );
    for leg in &order.legs {
        let account = state
            .accounts
            .get_mut(&id_key(&leg.handle))
            .expect("account was validated");
        account.commitment = leg.after_commitment;
        account.sequence = account
            .sequence
            .checked_add(1)
            .ok_or_else(|| "account sequence overflow".to_string())?;
    }
    state
        .operations
        .insert(id_key(&order.operation_id), statement);
    Ok(statement)
}

fn authorize(
    state: &State,
    params: &Map<String, Value>,
    statement: [u8; 32],
    authorizer: &QuorumAuthorizer,
) -> Result<(), String> {
    let before_root = state.root();
    let expected = params
        .get("expectedBeforeRoot")
        .and_then(Value::as_str)
        .ok_or_else(|| "expectedBeforeRoot must be a 32-byte hex string".to_string())?;
    if hex_array::<32>(expected, "expectedBeforeRoot")? != before_root {
        return Err("transaction was built against a stale state root".into());
    }
    let dto: ApprovalDto = field(params, "approval")?;
    if dto.approvals.len() > 64 {
        return Err("approval contains too many signers".into());
    }
    let mut node_ids = BTreeSet::new();
    let approvals = dto
        .approvals
        .into_iter()
        .map(|signed| {
            if !node_ids.insert(signed.node_id.clone()) {
                return Err("approval repeats a node identity".to_string());
            }
            Ok(NodeApproval {
                node_id: signed.node_id,
                signature: Signature::from_bytes(&hex_array::<64>(
                    &signed.signature,
                    "approval.signature",
                )?),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let approval = QuorumApproval {
        statement: hex_array(&dto.statement, "approval.statement")?,
        signer_epoch: dto.signer_epoch,
        domain: dto.domain,
        before_root: hex_array(&dto.before_root, "approval.beforeRoot")?,
        approvals,
    };
    if !authorizer.verify(&statement, &before_root, &approval) {
        return Err("k-of-n DeFMI approval is invalid".into());
    }
    Ok(())
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

fn require_keys(params: &Map<String, Value>, expected: &[&str]) -> Result<(), String> {
    if params.len() != expected.len() || expected.iter().any(|key| !params.contains_key(*key)) {
        return Err(format!(
            "transaction parameters must contain exactly {}",
            expected.join(", ")
        ));
    }
    Ok(())
}

fn hex_array<const N: usize>(value: &str, name: &str) -> Result<[u8; N], String> {
    hex::decode(value)
        .map_err(|_| format!("{name} is not hexadecimal"))?
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{name} has {} bytes; expected {N}", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, scalar::Scalar};
    use ed25519_dalek::{Signer, SigningKey};
    use merlin::Transcript;
    use qomm_defmi::facility::DefmiFacility;
    use qomm_defmi::note_chain::{note_ring_root, NoteClaim, NoteClaimKind};
    use qomm_proofs::opening_envelope::{EncryptedOpeningShare, OpeningEnvelope};
    use qomm_proofs::price_limit::{
        from_threshold as threshold_price_limit, threshold_context as price_limit_context,
    };
    use qomm_proofs::quote_proof::{MakerWitness, QuoteCircuit, Registered};
    use qomm_proofs::threshold_quote::{deal_quote_shares_with_qty_blinding, joint_prove_quote};
    use qomm_proofs::threshold_range::{deal_bits, joint_prove_range_from_contributions};
    use qomm_transport::dvp_issuer::{
        DvpProofs, DVP_CASH_REMAINDER_CONTEXT, DVP_PRODUCT_CONTEXT,
        DVP_SECURITIES_REMAINDER_CONTEXT,
    };
    use qomm_transport::order::{
        decode_execution_attestations, encode_execution_attestations, NodeExecutionAttestation,
    };
    use qomm_transport::proof_codec::{
        encode_dvp_proofs, encode_quote_verification, encode_threshold_range,
        QuoteVerificationBundle,
    };
    use qomm_zk::sigma::prove_product;
    use qomm_zkpi::typed::{
        AuthorizationScope, ExecutionContext, OperationKind, TradeDirection, TypedInstruction,
    };
    use qomm_zkpi::{
        asset_scalar, frost, PartialInstruction, AMOUNT_RANGE_CONTEXT, PRICE_RANGE_CONTEXT,
    };
    use rand_core::OsRng;
    use serde_json::json;

    fn committee() -> (QuorumAuthorizer, BTreeMap<String, SigningKey>) {
        let signers = (0u8..3)
            .map(|index| {
                (
                    format!("node-{index}"),
                    SigningKey::from_bytes(&[index.saturating_add(1); 32]),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let nodes = signers
            .iter()
            .map(|(node, key)| (node.clone(), key.verifying_key()))
            .collect();
        (
            QuorumAuthorizer::new(nodes, 2, 1, "test-chain").expect("committee"),
            signers,
        )
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

    #[allow(clippy::too_many_arguments)]
    fn apply(
        state: &mut State,
        authorizer: &QuorumAuthorizer,
        signers: &BTreeMap<String, SigningKey>,
        method: &str,
        field_name: &str,
        field_value: Value,
        statement: [u8; 32],
        timestamp: u64,
    ) -> Result<(), String> {
        let transaction = authorized_transaction(
            state,
            authorizer,
            signers,
            method,
            field_name,
            field_value,
            statement,
        )?;
        state.apply(&transaction, authorizer, timestamp)?;
        Ok(())
    }

    fn authorized_transaction(
        state: &State,
        authorizer: &QuorumAuthorizer,
        signers: &BTreeMap<String, SigningKey>,
        method: &str,
        field_name: &str,
        field_value: Value,
        statement: [u8; 32],
    ) -> Result<Vec<u8>, String> {
        let root = state.root();
        let approval = authorizer.approve(statement, root, signers)?;
        let transaction = TransactionEnvelope::new(
            method,
            json!({
                (field_name): field_value,
                "approval": approval_json(&approval),
                "expectedBeforeRoot": hex::encode(root),
            }),
        )?;
        transaction.encode()
    }

    fn product_evidence_json(evidence: &ProductSettlementEvidence) -> Value {
        json!({
            "typedInstruction": BASE64.encode(&evidence.typed_instruction),
            "quoteVerification": BASE64.encode(&evidence.quote_verification),
            "priceLimitProof": BASE64.encode(&evidence.price_limit_proof),
            "dvpProofs": BASE64.encode(&evidence.dvp_proofs),
            "mpcExecutionAttestations": BASE64.encode(&evidence.mpc_execution_attestations),
            "assetLink": {
                "announcement": hex::encode(evidence.asset_link.announcement.compress().to_bytes()),
                "response": hex::encode(evidence.asset_link.response.to_bytes()),
            },
        })
    }

    fn authorized_note_product_transaction(
        state: &State,
        authorizer: &QuorumAuthorizer,
        signers: &BTreeMap<String, SigningKey>,
        order: &ProductNoteSettlementOrder,
        evidence: &ProductSettlementEvidence,
    ) -> Result<Vec<u8>, String> {
        let root = state.root();
        let approval = authorizer.approve(order.statement()?, root, signers)?;
        TransactionEnvelope::new(
            "defmivm.issueNoteProductSettlement",
            json!({
                "order": product_note_order_json(order),
                "evidence": product_evidence_json(evidence),
                "approval": approval_json(&approval),
                "expectedBeforeRoot": hex::encode(root),
            }),
        )?
        .encode()
    }

    fn frost_key_packages(
        shares: BTreeMap<frost::Identifier, frost::keys::SecretShare>,
    ) -> BTreeMap<frost::Identifier, frost::keys::KeyPackage> {
        shares
            .into_iter()
            .map(|(id, share)| {
                (
                    id,
                    frost::keys::KeyPackage::try_from(share).expect("test FROST key package"),
                )
            })
            .collect()
    }

    fn frost_sign(
        keys: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
        public: &frost::keys::PublicKeyPackage,
        message: &[u8],
    ) -> frost::Signature {
        let selected = keys.keys().take(3).copied().collect::<Vec<_>>();
        let mut nonces = BTreeMap::new();
        let commitments = selected
            .iter()
            .map(|id| {
                let (nonce, commitment) =
                    frost::round1::commit(keys[id].signing_share(), &mut OsRng);
                nonces.insert(*id, nonce);
                (*id, commitment)
            })
            .collect();
        let package = frost::SigningPackage::new(commitments, message);
        let shares = selected
            .iter()
            .map(|id| {
                (
                    *id,
                    frost::round2::sign(&package, &nonces[id], &keys[id]).unwrap(),
                )
            })
            .collect();
        frost::aggregate(&package, &shares, public).unwrap()
    }

    fn threshold_range(
        key: &Pedersen,
        value: u64,
        blinding: Scalar,
        bits: usize,
        context: &[u8],
    ) -> qomm_proofs::threshold_range::ThresholdRangeProof {
        let parties = [1_usize, 2, 3, 4, 5, 6, 7];
        let dealt = deal_bits(key, value, &blinding, bits, &parties, 2, &mut OsRng).unwrap();
        let quorum = [1_usize, 4, 7];
        let contributions = quorum
            .iter()
            .map(|party| dealt.node_contribution(*party).unwrap())
            .collect::<Vec<_>>();
        joint_prove_range_from_contributions(key, &contributions, &quorum, context, &mut OsRng)
            .unwrap()
            .0
    }

    fn threshold_quote_evidence(
        market_digest: [u8; 32],
        slot: u64,
        context: [u8; 32],
    ) -> (Vec<u8>, [u8; 32], [u8; 32], [u8; 32], u64) {
        let circuit = QuoteCircuit::new(16, 24);
        let makers = vec![MakerWitness {
            ask_level: 2,
            spread: 1,
            slope: 0,
            invcoef: 0,
            inv: 3,
            maxqty: 500,
            expiry: 2_000,
            active: true,
            blindings: Registered::fresh(&mut OsRng),
        }];
        let parties = [1_usize, 2, 3, 4, 5, 6, 7];
        let (shares, public) = deal_quote_shares_with_qty_blinding(
            &circuit,
            &makers,
            6,
            Scalar::ZERO,
            0,
            100,
            1 << 20,
            8,
            &parties,
            2,
            market_digest,
            slot,
            &mut OsRng,
        )
        .expect("deal threshold quote shares");
        let (proof, _) =
            joint_prove_quote(&circuit, &shares, &public, &[1, 4, 7], &context, &mut OsRng)
                .expect("assemble threshold quote");
        let policy_digest = registered_policy_digest(proof.winner_index, &public.registry[0]);
        let bundle = QuoteVerificationBundle {
            context,
            eligibility_bits: 16,
            span_bits: 24,
            public,
            proof,
        };
        let digest = bundle.verify().expect("verify threshold quote");
        let registry_digest = bundle.public.registry_digest;
        let winner_value = bundle.proof.winner_value;
        (
            encode_quote_verification(&bundle).expect("encode threshold quote"),
            digest,
            policy_digest,
            registry_digest,
            winner_value,
        )
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

    fn authorized_reservation_transaction(
        state: &State,
        authorizer: &QuorumAuthorizer,
        signers: &BTreeMap<String, SigningKey>,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
        escrow: &ReservationEscrow,
    ) -> Result<Vec<u8>, String> {
        let root = state.root();
        let statement = authorization.statement(transition)?;
        let approval = authorizer.approve(statement, root, signers)?;
        TransactionEnvelope::new(
            "defmivm.issueProductReservation",
            json!({
                "transition": transition_json(transition),
                "authorization": reservation_authorization_json(authorization),
                "escrow": reservation_escrow_json(escrow),
                "approval": approval_json(&approval),
                "expectedBeforeRoot": hex::encode(root),
            }),
        )?
        .encode()
    }

    fn transition_json(transition: &CreditFacilityTransition) -> Value {
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

    fn control_json(control: &CreditFacilityControl) -> Value {
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

    fn amendment_json(amendment: &CreditFacilityAmendment) -> Value {
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

    fn admission_batch_json(plan: &AdmissionBatchPlan) -> Value {
        json!({
            "operationID": hex::encode(plan.operation_id),
            "batchID": hex::encode(plan.batch_id),
            "venueID": hex::encode(plan.venue_id),
            "epoch": plan.epoch,
            "slot": plan.slot,
            "batchDigest": hex::encode(plan.batch_digest),
            "orderDigest": hex::encode(plan.order_digest),
            "admissionDigests": plan.admission_digests.iter().map(hex::encode).collect::<Vec<_>>(),
            "expiresAt": plan.expires_at,
        })
    }

    fn admission_lanes_json(lanes: &[Vec<NodeAdmissionAttestation>]) -> Value {
        Value::Array(
            lanes
                .iter()
                .map(|lane| {
                    Value::Array(
                        lane.iter()
                            .map(|value| {
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
                            })
                            .collect(),
                    )
                })
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

    fn settlement_json(order: &SettlementOrder) -> Value {
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

    fn product_order_json(order: &ProductSettlementOrder) -> Value {
        json!({
            "settlement": settlement_json(&order.settlement),
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
                "transition": transition_json(&reservation.transition),
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

    fn product_release_json(order: &ProductReleaseOrder) -> Value {
        json!({
            "transition": transition_json(&order.transition),
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

    fn csd_control_json(control: &CsdIssuerControl) -> Value {
        json!({
            "operationID": hex::encode(control.operation_id),
            "issuerID": hex::encode(control.issuer_id),
            "kind": control.kind.as_str(),
            "beforeSequence": control.before_sequence,
            "reasonDigest": hex::encode(control.reason_digest),
        })
    }

    fn synthetic_note(
        asset_id: [u8; 32],
        seed: u64,
        value_commitment: [u8; 32],
        lock_id: [u8; 32],
    ) -> NoteOutput {
        let mut output = NoteOutput {
            note_id: ZERO,
            asset_id,
            one_time: (G * Scalar::from(seed * 3 + 1)).compress().to_bytes(),
            value_commitment,
            ephemeral: (G * Scalar::from(seed * 3 + 2)).compress().to_bytes(),
            masked_value: Scalar::from(seed * 3 + 3).to_bytes(),
            masked_blinding: Scalar::from(seed * 3 + 4).to_bytes(),
            lock_id,
        };
        output.note_id = output.derived_id().expect("synthetic note identifier");
        output.validate().expect("valid synthetic note");
        output
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

    fn note_order_json(order: &NoteSettlementOrder) -> Value {
        json!({
            "operationID": hex::encode(order.operation_id),
            "nullifier": hex::encode(order.nullifier),
            "deadline": order.deadline,
            "paymentInstructionDigest": hex::encode(order.payment_instruction_digest),
            "marketStatementDigest": hex::encode(order.market_statement_digest),
            "dvpProofDigest": hex::encode(order.dvp_proof_digest),
            "spends": order.spends.iter().map(note_spend_json).collect::<Vec<_>>(),
        })
    }

    fn note_materialization_json(value: &NoteClaimMaterialization) -> Value {
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

    fn authorized_note_reservation_transaction(
        state: &State,
        authorizer: &QuorumAuthorizer,
        signers: &BTreeMap<String, SigningKey>,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
        escrow: &NoteReservationEscrow,
    ) -> Result<Vec<u8>, String> {
        let root = state.root();
        let statement = authorization.statement(transition)?;
        let approval = authorizer.approve(statement, root, signers)?;
        TransactionEnvelope::new(
            "defmivm.issueNoteProductReservation",
            json!({
                "transition": transition_json(transition),
                "authorization": reservation_authorization_json(authorization),
                "escrow": note_reservation_escrow_json(escrow),
                "approval": approval_json(&approval),
                "expectedBeforeRoot": hex::encode(root),
            }),
        )?
        .encode()
    }

    fn opening_envelope_json(envelope: &OpeningEnvelope) -> Value {
        json!({
            "context": hex::encode(envelope.context),
            "threshold": envelope.threshold,
            "recipientView": hex::encode(envelope.recipient_view.compress().to_bytes()),
            "shares": envelope.shares.iter().map(|share| json!({
                "party": share.party,
                "ephemeral": hex::encode(share.ephemeral.compress().to_bytes()),
                "maskedValue": hex::encode(share.masked_value.to_bytes()),
                "maskedBlinding": hex::encode(share.masked_blinding.to_bytes()),
            })).collect::<Vec<_>>(),
        })
    }

    fn note_claim_json(claim: &NoteClaim) -> Value {
        json!({
            "claimID": hex::encode(claim.claim_id),
            "assetID": hex::encode(claim.asset_id),
            "valueCommitment": hex::encode(claim.value_commitment),
            "recipientCommitment": hex::encode(claim.recipient_commitment),
            "sourceHoldID": hex::encode(claim.source_hold_id),
            "kind": claim.kind.as_str(),
            "openingEnvelope": opening_envelope_json(&claim.opening_envelope),
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

    fn product_note_order_json(order: &ProductNoteSettlementOrder) -> Value {
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
                "transition": transition_json(&reservation.transition),
            })).collect::<Vec<_>>(),
        })
    }

    fn product_note_batch_json(batch: &ProductNoteSettlementBatch) -> Value {
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

    fn product_note_release_json(order: &ProductNoteReleaseOrder) -> Value {
        json!({
            "transition": transition_json(&order.transition),
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

    fn synthetic_claim(
        asset_id: [u8; 32],
        hold_id: [u8; 32],
        kind: NoteClaimKind,
        value_commitment: [u8; 32],
        seed: u64,
    ) -> NoteClaim {
        let envelope = OpeningEnvelope::new(
            [seed as u8; 32],
            1,
            G * Scalar::from(seed * 4 + 1),
            vec![EncryptedOpeningShare {
                party: 1,
                ephemeral: G * Scalar::from(seed * 4 + 2),
                masked_value: Scalar::from(seed * 4 + 3),
                masked_blinding: Scalar::from(seed * 4 + 4),
            }],
        )
        .expect("synthetic opening envelope");
        let mut claim = NoteClaim {
            claim_id: ZERO,
            asset_id,
            value_commitment,
            recipient_commitment: [seed as u8 + 1; 32],
            source_hold_id: hold_id,
            kind,
            opening_envelope: envelope,
        };
        claim.claim_id = claim.derived_id().expect("synthetic claim identifier");
        claim.validate().expect("synthetic claim");
        claim
    }

    fn object_has_signature_key(value: &Value) -> bool {
        match value {
            Value::Object(object) => object.iter().any(|(key, value)| {
                key.to_ascii_lowercase().contains("signature") || object_has_signature_key(value)
            }),
            Value::Array(values) => values.iter().any(object_has_signature_key),
            _ => false,
        }
    }

    #[test]
    fn anonymous_reservations_settle_without_post_quote_signatures_and_batch_safely() {
        let (authorizer, signers) = committee();
        let security_asset = [101; 32];
        let cash_asset = [102; 32];
        let maker_facility = [103; 32];
        let taker_facility = [104; 32];
        let maker_entity = [105; 32];
        let taker_entity = [106; 32];
        let maker_available = [107; 32];
        let taker_available = [108; 32];
        let maker_hold_id = [109; 32];
        let taker_hold_id = [110; 32];
        let venue_id = [111; 32];
        let defmi_id = [112; 32];
        let market_statement_digest = [149; 32];
        let admission_batch_id = [129; 32];
        let admission_ticket_id = [130; 32];
        let taker_mandate = [131; 32];
        let admission_order_digest = [133; 32];
        let admission_keys = (0u8..7)
            .map(|node| SigningKey::from_bytes(&[151 + node; 32]))
            .collect::<Vec<_>>();
        let execution_attestations = admission_keys
            .iter()
            .enumerate()
            .map(|(node, key)| {
                let mut value = NodeExecutionAttestation {
                    node: node as u16,
                    slot: 7,
                    lane: 0,
                    batch_digest: [170 + node as u8; 32],
                    source_digest: [180; 32],
                    state_generation: 1,
                    frame_count: 1,
                    input_count: 32,
                    stdout_digest: [190 + node as u8; 32],
                    stderr_digest: [200 + node as u8; 32],
                    persistence_digest: [210 + node as u8; 32],
                    receipt_digest: ZERO,
                    signature: Signature::from_bytes(&[0; 64]),
                };
                value.receipt_digest = value.recompute_receipt_digest().unwrap();
                value.sign(key).unwrap()
            })
            .collect::<Vec<_>>();
        let trusted_execution_keys = admission_keys
            .iter()
            .map(SigningKey::verifying_key)
            .collect::<Vec<_>>();
        let execution = verify_execution_lane(
            &execution_attestations,
            &trusted_execution_keys,
            admission_order_digest,
        )
        .expect("certified MPC execution lane");
        let admission_batch_digest = execution.cluster_digest;
        let quote_job = live_proof_job_id(7, 0, execution.digest).expect("quote proof job");
        let quote_context = complete_quote_context(quote_job, taker_mandate);
        let (
            quote_verification,
            quote_proof_digest,
            maker_policy_digest,
            quote_registry_digest,
            winning_price,
        ) = threshold_quote_evidence(market_statement_digest, 1, quote_context);
        let quantity_value = 6_u64;
        let limit_price_value = winning_price
            .checked_add(10)
            .expect("test price limit overflow");
        let cash_value = quantity_value
            .checked_mul(winning_price)
            .expect("test cash multiplication");
        let cash_reserve_value = cash_value
            .checked_add(10)
            .expect("test cash reserve overflow");
        let (frost_shares, frost_public) = qomm_zkpi::deal_quorum(7, 3, &mut OsRng).unwrap();
        let frost_keys = frost_key_packages(frost_shares);
        let verifier = SettlementVerifierConfig {
            venue_id,
            defmi_id,
            epoch: 1,
            quote_registry_digest,
            quote_eligibility_bits: 16,
            quote_span_bits: 24,
            amount_bits: 16,
            price_bits: 32,
            max_horizon: 3_600,
            frost_public_package: frost_public.serialize().unwrap(),
            valid_from: 1,
            valid_until: 1_000,
        };
        let mut state = State::default();
        apply(
            &mut state,
            &authorizer,
            &signers,
            "defmivm.issueSettlementVerifier",
            "config",
            settlement_verifier_json(&verifier),
            verifier.statement().unwrap(),
            100,
        )
        .expect("register settlement verifier");
        state.admission_committees.insert(
            admission_committee_key(&venue_id, 1),
            AdmissionCommitteeRecord {
                venue_id,
                epoch: 1,
                node_keys: admission_keys
                    .iter()
                    .map(|key| key.verifying_key().to_bytes())
                    .collect(),
                valid_from: 1,
                valid_until: 1_000,
                statement: [150; 32],
            },
        );
        for (asset_id, code, kind, terms) in [
            (security_asset, "SEC", "security", [113; 32]),
            (cash_asset, "JPY", "cash", [114; 32]),
        ] {
            state.assets.insert(
                id_key(&asset_id),
                AssetRecord {
                    code: code.into(),
                    kind: kind.into(),
                    decimals: 0,
                    terms_digest: terms,
                    active: true,
                },
            );
        }
        for (facility_id, beneficiary, rail_asset, available) in [
            (
                maker_facility,
                maker_entity,
                security_asset,
                maker_available,
            ),
            (taker_facility, taker_entity, cash_asset, taker_available),
        ] {
            state.credit_facilities.insert(
                id_key(&facility_id),
                CreditFacilityRecord {
                    guarantor_id: [115; 32],
                    beneficiary_commitment: beneficiary,
                    rail_asset_id: rail_asset,
                    cap_commitment: available,
                    available_commitment: available,
                    held_commitment: ZERO,
                    outstanding_commitment: ZERO,
                    overlimit_commitment: ZERO,
                    collateral_commitment: [116; 32],
                    risk_policy_digest: [117; 32],
                    valid_from: 1,
                    valid_until: 1_000,
                    status: "active".into(),
                    sequence: 0,
                },
            );
        }
        let maker_ring = [
            synthetic_note(
                security_asset,
                10,
                (G * Scalar::from(10_u64)).compress().to_bytes(),
                ZERO,
            ),
            synthetic_note(
                security_asset,
                11,
                (G * Scalar::from(11_u64)).compress().to_bytes(),
                ZERO,
            ),
        ];
        let taker_ring = [
            synthetic_note(
                cash_asset,
                12,
                (G * Scalar::from(12_u64)).compress().to_bytes(),
                ZERO,
            ),
            synthetic_note(
                cash_asset,
                13,
                (G * Scalar::from(13_u64)).compress().to_bytes(),
                ZERO,
            ),
        ];
        for output in maker_ring.iter().chain(taker_ring.iter()) {
            insert_note(&mut state, output).expect("seed spendable note");
        }

        let maker_amount = (G * Scalar::from(20_u64)).compress().to_bytes();
        let maker_after_available = [118; 32];
        let maker_transition = CreditFacilityTransition {
            operation_id: [119; 32],
            facility_id: maker_facility,
            hold_id: maker_hold_id,
            kind: CreditTransitionKind::Hold,
            query_commitment: maker_policy_digest,
            amount_commitment: maker_amount,
            consumed_commitment: ZERO,
            refund_commitment: ZERO,
            before_available_commitment: maker_available,
            after_available_commitment: maker_after_available,
            before_held_commitment: ZERO,
            after_held_commitment: maker_amount,
            before_outstanding_commitment: ZERO,
            after_outstanding_commitment: ZERO,
            before_sequence: 0,
            expires_at: 500,
            settlement_digest: ZERO,
            relation_proof_digest: [121; 32],
        };
        let maker_locked = synthetic_note(security_asset, 14, maker_amount, maker_hold_id);
        let maker_spend = NoteSpend {
            asset_id: security_asset,
            ring: maker_ring.iter().map(|note| note.note_id).collect(),
            ring_root: note_ring_root(
                security_asset,
                &maker_ring
                    .iter()
                    .map(|note| note.note_id)
                    .collect::<Vec<_>>(),
            )
            .expect("maker ring root"),
            serial_point: (G * Scalar::from(122_u64)).compress().to_bytes(),
            input_lock_id: ZERO,
            proof_digest: [123; 32],
            outputs: vec![maker_locked.clone()],
        };
        let maker_escrow = NoteReservationEscrow {
            spend: maker_spend,
            escrow_note_id: maker_locked.note_id,
            delegation_digest: [124; 32],
        };
        let mut maker_authorization = ReservationAuthorization {
            role: ReservationRole::Maker,
            entity_commitment: maker_entity,
            asset_id: security_asset,
            direction: 1,
            authorization_digest: maker_transition.query_commitment,
            mandate_digest: [125; 32],
            typed_reserve_digest: [126; 32],
            reserve_nullifier: [127; 32],
            asset_link_proof_digest: [128; 32],
            limit_price_commitment: ZERO,
            escrow_digest: ZERO,
            rfq_nullifier: ZERO,
            policy_version: 1,
            admission_ticket_id: ZERO,
            admission_slot: 0,
            admission_receipt_digest: ZERO,
            admission_epoch: 0,
            admission_sequence: 0,
            admission_batch_id: ZERO,
        };
        maker_authorization.escrow_digest = maker_escrow
            .statement(&maker_transition, &maker_authorization)
            .expect("maker escrow statement");
        let maker_reservation = authorized_note_reservation_transaction(
            &state,
            &authorizer,
            &signers,
            &maker_transition,
            &maker_authorization,
            &maker_escrow,
        )
        .expect("maker anonymous reservation transaction");
        state
            .apply(&maker_reservation, &authorizer, 100)
            .expect("maker anonymous reservation");
        let maker_reserved_state = state.clone();

        let admission_receipt = CertifiedAdmissionLane {
            slot: 7,
            sequence: 1,
            principal_digest: ZERO,
            ticket_id: admission_ticket_id,
            claim_digest: taker_mandate,
            cluster_digest: admission_batch_digest,
            order_digest: admission_order_digest,
        }
        .digest(venue_id, 1)
        .expect("admission receipt");
        state.admission_batches.insert(
            id_key(&admission_batch_id),
            AdmissionBatchRecord {
                venue_id,
                epoch: 1,
                slot: 7,
                batch_digest: admission_batch_digest,
                order_digest: admission_order_digest,
                population: 1,
                consumed: 0,
                expires_at: 500,
                statement: [134; 32],
            },
        );
        state.admission_entries.insert(
            admission_entry_key(&admission_batch_id, 1),
            AdmissionEntryRecord {
                batch_id: admission_batch_id,
                sequence: 1,
                admission_digest: admission_receipt,
                consumed_by: ZERO,
            },
        );

        let taker_amount = (G * Scalar::from(cash_reserve_value)).compress().to_bytes();
        let taker_after_available = [135; 32];
        let taker_transition = CreditFacilityTransition {
            operation_id: [136; 32],
            facility_id: taker_facility,
            hold_id: taker_hold_id,
            kind: CreditTransitionKind::Hold,
            query_commitment: taker_mandate,
            amount_commitment: taker_amount,
            consumed_commitment: ZERO,
            refund_commitment: ZERO,
            before_available_commitment: taker_available,
            after_available_commitment: taker_after_available,
            before_held_commitment: ZERO,
            after_held_commitment: taker_amount,
            before_outstanding_commitment: ZERO,
            after_outstanding_commitment: ZERO,
            before_sequence: 0,
            expires_at: 500,
            settlement_digest: ZERO,
            relation_proof_digest: [137; 32],
        };
        let taker_locked = synthetic_note(cash_asset, 15, taker_amount, taker_hold_id);
        let taker_ring_ids = taker_ring
            .iter()
            .map(|note| note.note_id)
            .collect::<Vec<_>>();
        let taker_escrow = NoteReservationEscrow {
            spend: NoteSpend {
                asset_id: cash_asset,
                ring_root: note_ring_root(cash_asset, &taker_ring_ids).expect("taker ring root"),
                ring: taker_ring_ids,
                serial_point: (G * Scalar::from(138_u64)).compress().to_bytes(),
                input_lock_id: ZERO,
                proof_digest: [139; 32],
                outputs: vec![taker_locked.clone()],
            },
            escrow_note_id: taker_locked.note_id,
            delegation_digest: [140; 32],
        };
        let rfq_nullifier = [141; 32];
        let mut taker_authorization = ReservationAuthorization {
            role: ReservationRole::Taker,
            entity_commitment: taker_entity,
            asset_id: cash_asset,
            direction: 1,
            authorization_digest: taker_mandate,
            mandate_digest: taker_mandate,
            typed_reserve_digest: [142; 32],
            reserve_nullifier: [143; 32],
            asset_link_proof_digest: [144; 32],
            limit_price_commitment: (G * Scalar::from(limit_price_value)).compress().to_bytes(),
            escrow_digest: ZERO,
            rfq_nullifier,
            policy_version: 0,
            admission_ticket_id,
            admission_slot: 7,
            admission_receipt_digest: admission_receipt,
            admission_epoch: 1,
            admission_sequence: 1,
            admission_batch_id,
        };
        taker_authorization.escrow_digest = taker_escrow
            .statement(&taker_transition, &taker_authorization)
            .expect("taker escrow statement");
        let taker_reservation = authorized_note_reservation_transaction(
            &state,
            &authorizer,
            &signers,
            &taker_transition,
            &taker_authorization,
            &taker_escrow,
        )
        .expect("taker anonymous reservation transaction");
        let decoded_reservation =
            TransactionEnvelope::decode(&taker_reservation).expect("decode anonymous reservation");
        assert!(!object_has_signature_key(
            &decoded_reservation.params["authorization"]
        ));
        assert!(!object_has_signature_key(
            &decoded_reservation.params["escrow"]
        ));
        state
            .apply(&taker_reservation, &authorizer, 100)
            .expect("taker anonymous reservation");
        assert_eq!(state.accounts.len(), 0);
        assert_eq!(
            state.admission_batches[&id_key(&admission_batch_id)].consumed,
            1
        );
        assert_eq!(
            state.note_reservations[&id_key(&maker_hold_id)].status,
            "active"
        );
        assert_eq!(
            state.note_reservations[&id_key(&taker_hold_id)].status,
            "active"
        );

        let proof_key = Pedersen::new(b"qomm:defmi:v1");
        let amount_blinding = Scalar::ZERO;
        let price_blinding = Scalar::ZERO;
        let amount_commitment = proof_key.commit_u64(quantity_value, &amount_blinding);
        let price_commitment = proof_key.commit_u64(winning_price, &price_blinding);
        let asset_commitment = proof_key.commit(&asset_scalar(&security_asset), &Scalar::ZERO);
        let maker_handle = G * Scalar::from(201_u64);
        let taker_handle = G * Scalar::from(202_u64);
        let reserve_handle = G * Scalar::from(203_u64);
        let partial = PartialInstruction::from_threshold_ranges(
            &proof_key,
            &Bounds {
                amount_bits: 16,
                price_bits: 32,
                max_horizon: 3_600,
            },
            amount_commitment,
            price_commitment,
            asset_commitment,
            threshold_range(
                &proof_key,
                quantity_value,
                amount_blinding,
                16,
                AMOUNT_RANGE_CONTEXT,
            ),
            threshold_range(
                &proof_key,
                winning_price,
                price_blinding,
                32,
                PRICE_RANGE_CONTEXT,
            ),
            taker_handle,
            maker_handle,
            400,
            [147; 32],
            quote_proof_digest,
        )
        .expect("construct threshold zkPI");
        let payment_digest = partial.digest_for(DEFAULT_DOMAIN);
        let payment = partial.sealed(frost_sign(&frost_keys, &frost_public, &payment_digest));
        let maker_reserve_receipt = maker_authorization
            .statement(&maker_transition)
            .expect("maker reserve receipt");
        let taker_reserve_receipt = taker_authorization
            .statement(&taker_transition)
            .expect("taker reserve receipt");
        let execution_context = ExecutionContext {
            operation: OperationKind::Settle,
            scope: AuthorizationScope::Joint,
            direction: TradeDirection::TakerBuys,
            venue_id,
            defmi_id,
            maker_handle,
            taker_handle,
            reserve_handle,
            maker_reservation_id: maker_hold_id,
            maker_reservation_sequence: 1,
            taker_reservation_id: taker_hold_id,
            taker_reservation_sequence: 1,
            rfq_nullifier,
            taker_mandate_digest: taker_mandate,
            maker_policy_digest,
            maker_mandate_digest: maker_authorization.mandate_digest,
            maker_reserve_receipt_digest: maker_reserve_receipt,
            taker_reserve_receipt_digest: taker_reserve_receipt,
            quote_proof_digest,
            market_statement_digest,
            before_state_root: state.root(),
        };
        let authorization_digest =
            typed::digest_for(&payment, &execution_context, DEFAULT_DOMAIN).unwrap();
        let typed_instruction = TypedInstruction {
            payment,
            context: execution_context,
            authorization: frost_sign(&frost_keys, &frost_public, &authorization_digest),
        };
        let typed_instruction_wire = typed_wire::encode(&typed_instruction);
        let typed_instruction_digest: [u8; 32] = Sha256::digest(&typed_instruction_wire).into();
        let quantity = typed_instruction
            .payment
            .amount_commitment
            .compress()
            .to_bytes();
        let securities_remainder_value = 20_u64
            .checked_sub(quantity_value)
            .expect("test securities reservation covers the trade");
        let cash_remainder_value = cash_reserve_value
            .checked_sub(cash_value)
            .expect("test cash reservation covers the trade");
        let securities_refund = proof_key
            .commit_u64(securities_remainder_value, &Scalar::ZERO)
            .compress()
            .to_bytes();
        let cash_commitment = proof_key.commit_u64(cash_value, &Scalar::ZERO);
        let cash = cash_commitment.compress().to_bytes();
        let cash_refund = proof_key
            .commit_u64(cash_remainder_value, &Scalar::ZERO)
            .compress()
            .to_bytes();
        let dvp_proofs = DvpProofs {
            product: prove_product(
                &proof_key,
                &mut Transcript::new(DVP_PRODUCT_CONTEXT),
                &typed_instruction.payment.amount_commitment,
                &Scalar::from(quantity_value),
                &amount_blinding,
                &Scalar::from(winning_price),
                &price_blinding,
                &Scalar::ZERO,
                &mut OsRng,
            ),
            securities_remainder: threshold_range(
                &proof_key,
                securities_remainder_value,
                Scalar::ZERO,
                16,
                DVP_SECURITIES_REMAINDER_CONTEXT,
            ),
            cash_remainder: threshold_range(
                &proof_key,
                cash_remainder_value,
                Scalar::ZERO,
                16,
                DVP_CASH_REMAINDER_CONTEXT,
            ),
        };
        let dvp_package = build_threshold_package_from_proofs(
            &proof_key,
            typed_instruction.payment.clone(),
            Sides::of(&typed_instruction.payment),
            settlement_point(maker_amount, "test Maker reserve").unwrap(),
            settlement_point(taker_amount, "test Taker reserve").unwrap(),
            cash_commitment,
            dvp_proofs.clone(),
            16,
        )
        .expect("verify test threshold DvP");
        let dvp_proof_digest = dvp_package.digest();
        let limit_commitment = settlement_point(
            taker_authorization.limit_price_commitment,
            "test Taker price limit",
        )
        .unwrap();
        let limit_context = price_limit_context(
            PriceLimitDirection::MaximumBuyPrice,
            32,
            &typed_instruction.payment.price_commitment,
            &limit_commitment,
            &taker_mandate,
        );
        let price_limit_threshold = threshold_range(
            &proof_key,
            limit_price_value - winning_price,
            Scalar::ZERO,
            32,
            &limit_context,
        );
        let price_limit = threshold_price_limit(
            &proof_key,
            &typed_instruction.payment.price_commitment,
            &limit_commitment,
            PriceLimitDirection::MaximumBuyPrice,
            32,
            &taker_mandate,
            price_limit_threshold.clone(),
        )
        .expect("verify test hidden price limit");
        let asset_link = asset_link::prove(
            &proof_key,
            security_asset,
            &typed_instruction.payment.asset_commitment,
            &Scalar::ZERO,
            &mut OsRng,
        )
        .expect("prove test asset link");
        let evidence = ProductSettlementEvidence {
            typed_instruction: typed_instruction_wire.clone(),
            quote_verification: quote_verification.clone(),
            price_limit_proof: encode_threshold_range(&price_limit_threshold)
                .expect("encode test price-limit proof"),
            dvp_proofs: encode_dvp_proofs(&dvp_proofs).expect("encode test DvP proofs"),
            mpc_execution_attestations: encode_execution_attestations(&execution_attestations)
                .expect("encode test MPC execution attestations"),
            asset_link: asset_link.clone(),
        };
        evidence
            .validate_encoding()
            .expect("complete test settlement evidence");
        let settlement = DelegatedNoteSettlementOrder {
            operation_id: [146; 32],
            nullifier: typed_instruction.payment.nullifier(),
            deadline: 400,
            payment_instruction_digest: typed_instruction_digest,
            market_statement_digest,
            dvp_proof_digest,
            spends: vec![
                EscrowClaimSpend {
                    asset_id: security_asset,
                    hold_id: maker_hold_id,
                    escrow_note_id: maker_locked.note_id,
                    delegation_digest: maker_escrow.delegation_digest,
                    proof_digest: dvp_proof_digest,
                    claims: vec![
                        synthetic_claim(
                            security_asset,
                            maker_hold_id,
                            NoteClaimKind::Delivery,
                            quantity,
                            30,
                        ),
                        synthetic_claim(
                            security_asset,
                            maker_hold_id,
                            NoteClaimKind::Refund,
                            securities_refund,
                            31,
                        ),
                    ],
                },
                EscrowClaimSpend {
                    asset_id: cash_asset,
                    hold_id: taker_hold_id,
                    escrow_note_id: taker_locked.note_id,
                    delegation_digest: taker_escrow.delegation_digest,
                    proof_digest: dvp_proof_digest,
                    claims: vec![
                        synthetic_claim(
                            cash_asset,
                            taker_hold_id,
                            NoteClaimKind::Delivery,
                            cash,
                            32,
                        ),
                        synthetic_claim(
                            cash_asset,
                            taker_hold_id,
                            NoteClaimKind::Refund,
                            cash_refund,
                            33,
                        ),
                    ],
                },
            ],
        };
        let base_statement = settlement
            .statement()
            .expect("delegated settlement statement");
        let maker_consume = CreditFacilityTransition {
            operation_id: [150; 32],
            facility_id: maker_facility,
            hold_id: maker_hold_id,
            kind: CreditTransitionKind::Consume,
            query_commitment: maker_transition.query_commitment,
            amount_commitment: maker_amount,
            consumed_commitment: quantity,
            refund_commitment: securities_refund,
            before_available_commitment: maker_after_available,
            after_available_commitment: [151; 32],
            before_held_commitment: maker_amount,
            after_held_commitment: ZERO,
            before_outstanding_commitment: ZERO,
            after_outstanding_commitment: quantity,
            before_sequence: 1,
            expires_at: 500,
            settlement_digest: base_statement,
            relation_proof_digest: [152; 32],
        };
        let taker_consume = CreditFacilityTransition {
            operation_id: [153; 32],
            facility_id: taker_facility,
            hold_id: taker_hold_id,
            kind: CreditTransitionKind::Consume,
            query_commitment: taker_transition.query_commitment,
            amount_commitment: taker_amount,
            consumed_commitment: cash,
            refund_commitment: cash_refund,
            before_available_commitment: taker_after_available,
            after_available_commitment: [154; 32],
            before_held_commitment: taker_amount,
            after_held_commitment: ZERO,
            before_outstanding_commitment: ZERO,
            after_outstanding_commitment: cash,
            before_sequence: 1,
            expires_at: 500,
            settlement_digest: base_statement,
            relation_proof_digest: [155; 32],
        };
        let order = ProductNoteSettlementOrder {
            settlement,
            venue_id,
            defmi_id,
            maker_entity_commitment: maker_entity,
            taker_entity_commitment: taker_entity,
            rfq_nullifier,
            taker_authorization_digest: taker_mandate,
            maker_policy_digest: maker_transition.query_commitment,
            maker_mandate_digest: maker_authorization.mandate_digest,
            taker_mandate_digest: taker_mandate,
            typed_instruction_digest,
            quote_proof_digest,
            price_limit_proof_digest: price_limit.digest(
                &typed_instruction.payment.price_commitment,
                &limit_commitment,
                &taker_mandate,
            ),
            dvp_proof_digest,
            quantity_commitment: quantity,
            cash_commitment: cash,
            traded_asset_id: security_asset,
            asset_link_proof_digest: asset_link
                .digest(&security_asset, &typed_instruction.payment.asset_commitment),
            admission_receipt_digest: admission_receipt,
            admission_epoch: 1,
            admission_sequence: 1,
            reservations: vec![
                ReservationConsumption {
                    role: ReservationRole::Maker,
                    reserve_receipt_digest: maker_authorization
                        .statement(&maker_transition)
                        .expect("maker reserve receipt"),
                    transition: maker_consume,
                },
                ReservationConsumption {
                    role: ReservationRole::Taker,
                    reserve_receipt_digest: taker_authorization
                        .statement(&taker_transition)
                        .expect("taker reserve receipt"),
                    transition: taker_consume,
                },
            ],
        };
        order.body().expect("anonymous product settlement order");
        assert!(!object_has_signature_key(&product_note_order_json(&order)));

        let mut bad_limit = evidence.clone();
        let mut bad_limit_proof = decode_threshold_range(&bad_limit.price_limit_proof).unwrap();
        bad_limit_proof.linkage.z_value += Scalar::ONE;
        bad_limit.price_limit_proof = encode_threshold_range(&bad_limit_proof).unwrap();
        verify_product_settlement_evidence(&state, &bad_limit, &order, 120)
            .expect_err("tampered price-limit proof must be rejected");

        let mut bad_dvp = evidence.clone();
        let mut bad_dvp_proofs = decode_dvp_proofs(&bad_dvp.dvp_proofs).unwrap();
        bad_dvp_proofs.product.z_b += Scalar::ONE;
        bad_dvp.dvp_proofs = encode_dvp_proofs(&bad_dvp_proofs).unwrap();
        verify_product_settlement_evidence(&state, &bad_dvp, &order, 120)
            .expect_err("tampered DvP product proof must be rejected");

        let mut bad_asset = evidence.clone();
        bad_asset.asset_link.response += Scalar::ONE;
        verify_product_settlement_evidence(&state, &bad_asset, &order, 120)
            .expect_err("tampered asset-link proof must be rejected");

        let mut bad_execution = evidence.clone();
        let mut bad_execution_attestations =
            decode_execution_attestations(&bad_execution.mpc_execution_attestations)
                .expect("decode test MPC execution attestations");
        bad_execution_attestations[0].persistence_digest[0] ^= 1;
        bad_execution_attestations[0].receipt_digest = bad_execution_attestations[0]
            .recompute_receipt_digest()
            .expect("recompute tampered execution receipt digest");
        bad_execution.mpc_execution_attestations =
            encode_execution_attestations(&bad_execution_attestations)
                .expect("encode tampered MPC execution attestations");
        verify_product_settlement_evidence(&state, &bad_execution, &order, 120)
            .expect_err("tampered MPC persistence digest must be rejected");

        let before_settlement = state.clone();
        let settlement_transaction =
            authorized_note_product_transaction(&state, &authorizer, &signers, &order, &evidence)
                .expect("anonymous settlement transaction");
        state
            .apply(&settlement_transaction, &authorizer, 120)
            .expect("settle anonymous product without another signature");
        assert_eq!(state.accounts.len(), 0);
        assert_eq!(state.note_claims.len(), 4);
        assert_eq!(
            state.note_reservations[&id_key(&maker_hold_id)].status,
            "consumed"
        );
        assert_eq!(
            state.note_reservations[&id_key(&taker_hold_id)].status,
            "consumed"
        );
        assert!(state.rfq_nullifiers.contains_key(&id_key(&rfq_nullifier)));
        for spend in &order.settlement.spends {
            assert!(state
                .note_serials
                .contains_key(&id_key(&escrow_claim_serial(
                    spend.escrow_note_id,
                    spend.hold_id
                ))));
        }

        let mut batch_state = before_settlement.clone();
        let batch =
            ProductNoteSettlementBatch::from_orders([159; 32], std::slice::from_ref(&order))
                .expect("single-member anonymous batch");
        let batch_root = batch_state.root();
        let batch_statement = batch.statement().expect("batch statement");
        let batch_approval = authorizer
            .approve(batch_statement, batch_root, &signers)
            .expect("batch approval");
        let batch_transaction = TransactionEnvelope::new(
            "defmivm.issueNoteProductSettlementBatch",
            json!({
                "batch": product_note_batch_json(&batch),
                "orders": [product_note_order_json(&order)],
                "evidence": [product_evidence_json(&evidence)],
                "approval": approval_json(&batch_approval),
                "expectedBeforeRoot": hex::encode(batch_root),
            }),
        )
        .expect("anonymous batch transaction")
        .encode()
        .expect("encode anonymous batch");
        batch_state
            .apply(&batch_transaction, &authorizer, 120)
            .expect("apply anonymous settlement batch");
        assert_eq!(batch_state.note_claims, state.note_claims);
        assert!(batch_state
            .operations
            .contains_key(&id_key(&batch.batch_id)));

        let mut rfq_replay = order.clone();
        rfq_replay.settlement.operation_id = [160; 32];
        let mut replay_payment = typed_instruction.payment.clone();
        replay_payment.nonce = [161; 32];
        let replay_payment_digest = replay_payment.digest_for(DEFAULT_DOMAIN);
        replay_payment.signature = frost_sign(&frost_keys, &frost_public, &replay_payment_digest);
        let mut replay_context = typed_instruction.context.clone();
        replay_context.before_state_root = state.root();
        let replay_authorization_digest =
            typed::digest_for(&replay_payment, &replay_context, DEFAULT_DOMAIN)
                .expect("RFQ replay typed digest");
        let replay_typed_instruction = TypedInstruction {
            payment: replay_payment,
            context: replay_context,
            authorization: frost_sign(&frost_keys, &frost_public, &replay_authorization_digest),
        };
        let replay_typed_wire = typed_wire::encode(&replay_typed_instruction);
        let replay_typed_digest: [u8; 32] = Sha256::digest(&replay_typed_wire).into();
        rfq_replay.settlement.nullifier = replay_typed_instruction.payment.nullifier();
        rfq_replay.settlement.payment_instruction_digest = replay_typed_digest;
        rfq_replay.typed_instruction_digest = replay_typed_digest;
        let replay_dvp = build_threshold_package_from_proofs(
            &proof_key,
            replay_typed_instruction.payment.clone(),
            Sides::of(&replay_typed_instruction.payment),
            settlement_point(maker_amount, "replay Maker reserve").unwrap(),
            settlement_point(taker_amount, "replay Taker reserve").unwrap(),
            cash_commitment,
            dvp_proofs.clone(),
            16,
        )
        .expect("verify replay threshold DvP");
        let replay_dvp_digest = replay_dvp.digest();
        rfq_replay.settlement.dvp_proof_digest = replay_dvp_digest;
        rfq_replay.dvp_proof_digest = replay_dvp_digest;
        for spend in &mut rfq_replay.settlement.spends {
            spend.proof_digest = replay_dvp_digest;
        }
        let replay_base = rfq_replay
            .settlement
            .statement()
            .expect("RFQ replay base statement");
        for (index, reservation) in rfq_replay.reservations.iter_mut().enumerate() {
            reservation.transition.operation_id = [162 + index as u8; 32];
            reservation.transition.settlement_digest = replay_base;
        }
        rfq_replay.body().expect("RFQ replay order shape");
        let mut replay_evidence = evidence.clone();
        replay_evidence.typed_instruction = replay_typed_wire;
        let replay_transaction = authorized_note_product_transaction(
            &state,
            &authorizer,
            &signers,
            &rfq_replay,
            &replay_evidence,
        )
        .expect("RFQ replay transaction");
        let after_settlement = state.clone();
        assert!(state
            .apply(&replay_transaction, &authorizer, 121)
            .unwrap_err()
            .contains("RFQ nullifier was already settled"));
        assert_eq!(state, after_settlement);

        assert!(ProductNoteSettlementBatch::from_orders(
            order.settlement.operation_id,
            std::slice::from_ref(&order)
        )
        .is_err());
        let mut colliding = order.clone();
        colliding.admission_sequence = 2;
        colliding.settlement.operation_id = [164; 32];
        colliding.settlement.nullifier = [165; 32];
        colliding.rfq_nullifier = [166; 32];
        let colliding_base = colliding
            .settlement
            .statement()
            .expect("colliding base statement");
        for (index, reservation) in colliding.reservations.iter_mut().enumerate() {
            reservation.transition.operation_id = [167 + index as u8; 32];
            reservation.transition.settlement_digest = colliding_base;
        }
        colliding.body().expect("colliding order shape");
        let conflicting_batch = ProductNoteSettlementBatch {
            batch_id: [169; 32],
            venue_id,
            defmi_id,
            admission_epoch: 1,
            members: vec![
                ProductSettlementBatchMember {
                    admission_sequence: 1,
                    settlement_statement: order.statement().expect("first member"),
                },
                ProductSettlementBatchMember {
                    admission_sequence: 2,
                    settlement_statement: colliding.statement().expect("second member"),
                },
            ],
        };
        assert!(conflicting_batch
            .validate_orders(&[order, colliding])
            .unwrap_err()
            .contains("operation, facility or hold"));

        let release_transition = CreditFacilityTransition {
            operation_id: [170; 32],
            facility_id: maker_facility,
            hold_id: maker_hold_id,
            kind: CreditTransitionKind::Release,
            query_commitment: maker_transition.query_commitment,
            amount_commitment: maker_amount,
            consumed_commitment: ZERO,
            refund_commitment: ZERO,
            before_available_commitment: maker_after_available,
            after_available_commitment: maker_available,
            before_held_commitment: maker_amount,
            after_held_commitment: ZERO,
            before_outstanding_commitment: ZERO,
            after_outstanding_commitment: ZERO,
            before_sequence: 1,
            expires_at: 500,
            settlement_digest: ZERO,
            relation_proof_digest: [171; 32],
        };
        let release_ring = vec![maker_locked.note_id, maker_ring[0].note_id];
        let refund_output = synthetic_note(security_asset, 34, maker_amount, ZERO);
        let release_order = ProductNoteReleaseOrder {
            transition: release_transition,
            role: ReservationRole::Maker,
            reserve_receipt_digest: maker_authorization
                .statement(&maker_transition)
                .expect("maker release receipt"),
            typed_instruction_digest: [172; 32],
            release_nullifier: [173; 32],
            release_deadline: 600,
            asset_id: security_asset,
            asset_link_proof_digest: [174; 32],
            escrow_note_id: maker_locked.note_id,
            spend: NoteSpend {
                asset_id: security_asset,
                ring_root: note_ring_root(security_asset, &release_ring)
                    .expect("release ring root"),
                ring: release_ring,
                serial_point: (G * Scalar::from(175_u64)).compress().to_bytes(),
                input_lock_id: maker_hold_id,
                proof_digest: [176; 32],
                outputs: vec![refund_output.clone()],
            },
        };
        release_order.body().expect("anonymous release order");
        assert!(!object_has_signature_key(&product_note_release_json(
            &release_order
        )));
        let release_transaction = authorized_transaction(
            &maker_reserved_state,
            &authorizer,
            &signers,
            "defmivm.issueNoteProductRelease",
            "order",
            product_note_release_json(&release_order),
            release_order.statement().expect("release statement"),
        )
        .expect("anonymous release transaction");
        let mut release_state = maker_reserved_state;
        let before_early_release = release_state.clone();
        assert!(release_state
            .apply(&release_transaction, &authorizer, 500)
            .unwrap_err()
            .contains("not yet releasable"));
        assert_eq!(release_state, before_early_release);
        release_state
            .apply(&release_transaction, &authorizer, 501)
            .expect("release expired anonymous reservation");
        assert_eq!(
            release_state.note_reservations[&id_key(&maker_hold_id)].status,
            "released"
        );
        assert_eq!(
            release_state.credit_holds[&id_key(&maker_hold_id)].status,
            "released"
        );
        assert!(release_state
            .notes
            .contains_key(&id_key(&refund_output.note_id)));
        assert_eq!(release_state.accounts.len(), 0);
    }

    #[test]
    fn csd_note_lifecycle_is_signed_account_free_and_replay_safe() {
        let (authorizer, signers) = committee();
        let issuer_key = SigningKey::from_bytes(&[41; 32]);
        let asset_id = [42; 32];
        let issuer_id = [43; 32];
        let mut state = State::default();
        state.assets.insert(
            id_key(&asset_id),
            AssetRecord {
                code: "JPY".into(),
                kind: "cash".into(),
                decimals: 0,
                terms_digest: [44; 32],
                active: true,
            },
        );

        let issuer = CsdIssuerDefinition {
            issuer_id,
            code: "QOMM-CSD".into(),
            jurisdiction: "JP".into(),
            operator_entity_commitment: [45; 32],
            public_key: issuer_key.verifying_key().to_bytes(),
            permitted_asset_ids: vec![asset_id],
            policy_digest: [46; 32],
            valid_from: 1,
            valid_until: 1_000,
        };
        apply(
            &mut state,
            &authorizer,
            &signers,
            "defmivm.issueCSDIssuer",
            "issuer",
            csd_issuer_json(&issuer),
            issuer.statement().expect("issuer statement"),
            100,
        )
        .expect("register CSD issuer");
        assert_eq!(state.csd_issuers[&id_key(&issuer_id)].status, "active");

        let first_output = synthetic_note(
            asset_id,
            1,
            (G * Scalar::from(50_u64)).compress().to_bytes(),
            ZERO,
        );
        let unsigned = NoteIssuance {
            operation_id: [47; 32],
            issuance_nonce: [48; 32],
            issuer_id,
            issued_at: 100,
            output: first_output.clone(),
            proof_digest: [49; 32],
            issuer_signature: Signature::from_bytes(&[0; 64]),
        };
        let invalid_transaction = authorized_transaction(
            &state,
            &authorizer,
            &signers,
            "defmivm.issueNote",
            "issuance",
            note_issuance_json(&unsigned),
            unsigned.statement().expect("unsigned issuance statement"),
        )
        .expect("invalid-signature transaction");
        let before_invalid_signature = state.clone();
        assert!(state
            .apply(&invalid_transaction, &authorizer, 100)
            .unwrap_err()
            .contains("signature is invalid"));
        assert_eq!(state, before_invalid_signature);

        let first = unsigned.sign_issuer(&issuer_key).expect("sign first note");
        apply(
            &mut state,
            &authorizer,
            &signers,
            "defmivm.issueNote",
            "issuance",
            note_issuance_json(&first),
            first.statement().expect("first issuance statement"),
            100,
        )
        .expect("issue first note");

        let second_output = synthetic_note(
            asset_id,
            2,
            (G * Scalar::from(51_u64)).compress().to_bytes(),
            ZERO,
        );
        let second = NoteIssuance {
            operation_id: [52; 32],
            issuance_nonce: [53; 32],
            issuer_id,
            issued_at: 101,
            output: second_output.clone(),
            proof_digest: [54; 32],
            issuer_signature: Signature::from_bytes(&[0; 64]),
        }
        .sign_issuer(&issuer_key)
        .expect("sign second note");
        apply(
            &mut state,
            &authorizer,
            &signers,
            "defmivm.issueNote",
            "issuance",
            note_issuance_json(&second),
            second.statement().expect("second issuance statement"),
            101,
        )
        .expect("issue second note");
        assert_eq!(
            state.accounts.len(),
            0,
            "note rail must not create accounts"
        );
        assert_eq!(state.notes.len(), 2);

        let suspend = CsdIssuerControl {
            operation_id: [55; 32],
            issuer_id,
            kind: CsdIssuerControlKind::Suspend,
            before_sequence: 0,
            reason_digest: [56; 32],
        };
        apply(
            &mut state,
            &authorizer,
            &signers,
            "defmivm.issueCSDIssuerControl",
            "control",
            csd_control_json(&suspend),
            suspend.statement().expect("suspend statement"),
            102,
        )
        .expect("suspend issuer");

        let blocked = NoteIssuance {
            operation_id: [57; 32],
            issuance_nonce: [58; 32],
            issuer_id,
            issued_at: 102,
            output: synthetic_note(
                asset_id,
                3,
                (G * Scalar::from(59_u64)).compress().to_bytes(),
                ZERO,
            ),
            proof_digest: [60; 32],
            issuer_signature: Signature::from_bytes(&[0; 64]),
        }
        .sign_issuer(&issuer_key)
        .expect("sign blocked note");
        let blocked_transaction = authorized_transaction(
            &state,
            &authorizer,
            &signers,
            "defmivm.issueNote",
            "issuance",
            note_issuance_json(&blocked),
            blocked.statement().expect("blocked issuance statement"),
        )
        .expect("blocked issuance transaction");
        let suspended_state = state.clone();
        assert!(state
            .apply(&blocked_transaction, &authorizer, 102)
            .unwrap_err()
            .contains("not active"));
        assert_eq!(state, suspended_state);

        for control in [
            CsdIssuerControl {
                operation_id: [61; 32],
                issuer_id,
                kind: CsdIssuerControlKind::Activate,
                before_sequence: 1,
                reason_digest: [62; 32],
            },
            CsdIssuerControl {
                operation_id: [63; 32],
                issuer_id,
                kind: CsdIssuerControlKind::Revoke,
                before_sequence: 2,
                reason_digest: [64; 32],
            },
        ] {
            apply(
                &mut state,
                &authorizer,
                &signers,
                "defmivm.issueCSDIssuerControl",
                "control",
                csd_control_json(&control),
                control.statement().expect("control statement"),
                103,
            )
            .expect("apply CSD control");
        }
        assert_eq!(state.csd_issuers[&id_key(&issuer_id)].status, "revoked");

        let ring = vec![first_output.note_id, second_output.note_id];
        let settlement_output = synthetic_note(
            asset_id,
            4,
            (G * Scalar::from(65_u64)).compress().to_bytes(),
            ZERO,
        );
        let spend = NoteSpend {
            asset_id,
            ring_root: note_ring_root(asset_id, &ring).expect("ring root"),
            ring,
            serial_point: (G * Scalar::from(66_u64)).compress().to_bytes(),
            input_lock_id: ZERO,
            proof_digest: [67; 32],
            outputs: vec![settlement_output.clone()],
        };
        let order = NoteSettlementOrder {
            operation_id: [68; 32],
            nullifier: [69; 32],
            deadline: 300,
            payment_instruction_digest: [70; 32],
            market_statement_digest: [71; 32],
            dvp_proof_digest: [72; 32],
            spends: vec![spend.clone()],
        };
        apply(
            &mut state,
            &authorizer,
            &signers,
            "defmivm.issueNoteSettlement",
            "order",
            note_order_json(&order),
            order.statement().expect("note settlement statement"),
            120,
        )
        .expect("settle notes after issuer revocation");
        assert!(state
            .notes
            .contains_key(&id_key(&settlement_output.note_id)));
        assert!(state
            .note_serials
            .contains_key(&id_key(&spend.serial_point)));

        let replay_output = synthetic_note(
            asset_id,
            5,
            (G * Scalar::from(73_u64)).compress().to_bytes(),
            ZERO,
        );
        let replay_order = NoteSettlementOrder {
            operation_id: [74; 32],
            nullifier: [75; 32],
            spends: vec![NoteSpend {
                outputs: vec![replay_output],
                ..spend
            }],
            ..order
        };
        let replay_transaction = authorized_transaction(
            &state,
            &authorizer,
            &signers,
            "defmivm.issueNoteSettlement",
            "order",
            note_order_json(&replay_order),
            replay_order.statement().expect("serial replay statement"),
        )
        .expect("serial replay transaction");
        let before_replay = state.clone();
        assert!(state
            .apply(&replay_transaction, &authorizer, 121)
            .unwrap_err()
            .contains("serial was already settled"));
        assert_eq!(state, before_replay);

        let hold_id = [76; 32];
        state.credit_holds.insert(
            id_key(&hold_id),
            CreditHoldRecord {
                facility_id: [77; 32],
                query_commitment: [78; 32],
                amount_commitment: [79; 32],
                expires_at: 400,
                status: "consumed".into(),
                settlement_digest: [80; 32],
                created_sequence: 1,
                updated_sequence: 2,
            },
        );
        let envelope = OpeningEnvelope::new(
            [81; 32],
            1,
            G * Scalar::from(82_u64),
            vec![EncryptedOpeningShare {
                party: 1,
                ephemeral: G * Scalar::from(83_u64),
                masked_value: Scalar::from(84_u64),
                masked_blinding: Scalar::from(85_u64),
            }],
        )
        .expect("opening envelope");
        let claim_value = (G * Scalar::from(86_u64)).compress().to_bytes();
        let mut claim = NoteClaim {
            claim_id: ZERO,
            asset_id,
            value_commitment: claim_value,
            recipient_commitment: [87; 32],
            source_hold_id: hold_id,
            kind: NoteClaimKind::Delivery,
            opening_envelope: envelope.clone(),
        };
        claim.claim_id = claim.derived_id().expect("claim identifier");
        claim.validate().expect("valid claim");
        state.note_claims.insert(
            id_key(&claim.claim_id),
            crate::state::NoteClaimRecord {
                asset_id,
                value_commitment: claim_value,
                recipient_commitment: claim.recipient_commitment,
                source_hold_id: hold_id,
                kind: "delivery".into(),
                opening_envelope: crate::state::OpeningEnvelopeRecord::from_domain(&envelope)
                    .expect("opening record"),
                status: "active".into(),
                settlement_digest: [88; 32],
                materialization: ZERO,
            },
        );
        let materialized_output = synthetic_note(asset_id, 6, claim_value, ZERO);
        let materialization = NoteClaimMaterialization {
            operation_id: [89; 32],
            claim_id: claim.claim_id,
            output: materialized_output.clone(),
            ownership_proof_digest: [90; 32],
        };
        apply(
            &mut state,
            &authorizer,
            &signers,
            "defmivm.issueNoteClaimMaterialization",
            "materialization",
            note_materialization_json(&materialization),
            materialization
                .statement()
                .expect("materialization statement"),
            130,
        )
        .expect("materialize final entitlement");
        assert_eq!(
            state.note_claims[&id_key(&claim.claim_id)].status,
            "materialized"
        );
        assert!(state
            .notes
            .contains_key(&id_key(&materialized_output.note_id)));
        assert_eq!(
            state.accounts.len(),
            0,
            "materialization stays account-free"
        );
    }

    #[test]
    fn fixed_width_hex_parser_rejects_wrong_width() {
        assert_eq!(hex_array::<2>("0102", "x").expect("decode"), [1, 2]);
        assert!(hex_array::<2>("01", "x").is_err());
        assert!(hex_array::<2>("zzzz", "x").is_err());
    }

    #[test]
    fn top_level_action_shape_is_closed() {
        let mut params = Map::new();
        params.insert("asset".into(), Value::Null);
        params.insert("approval".into(), Value::Null);
        params.insert("expectedBeforeRoot".into(), Value::Null);
        assert!(require_keys(&params, &["asset", "approval", "expectedBeforeRoot"]).is_ok());
        params.insert("ignored".into(), Value::Null);
        assert!(require_keys(&params, &["asset", "approval", "expectedBeforeRoot"]).is_err());
    }

    #[test]
    fn rust_vm_state_matches_the_native_facility_through_settlement() {
        let (authorizer, signers) = committee();
        let directory = tempfile::tempdir().expect("temporary directory");
        let facility = DefmiFacility::open(
            directory.path().join("facility.sqlite"),
            authorizer.clone(),
            SigningKey::from_bytes(&[9; 32]),
        )
        .expect("facility");
        let mut state = State::default();
        assert_eq!(state.root(), facility.state_root().expect("facility root"));

        let asset = AssetDefinition {
            asset_id: [11; 32],
            code: "JPY".into(),
            kind: AssetKind::Cash,
            decimals: 0,
            terms_digest: [12; 32],
        };
        let asset_statement = asset.statement().expect("asset statement");
        let approval = authorizer
            .approve(
                asset_statement,
                facility.state_root().expect("root"),
                &signers,
            )
            .expect("approval");
        facility
            .register_asset(&asset, &approval)
            .expect("facility asset");
        apply(
            &mut state,
            &authorizer,
            &signers,
            "defmivm.issueAsset",
            "asset",
            json!({
                "assetID": hex::encode(asset.asset_id),
                "code": asset.code,
                "kind": asset.kind.as_str(),
                "decimals": asset.decimals,
                "termsDigest": hex::encode(asset.terms_digest),
            }),
            asset_statement,
            100,
        )
        .expect("VM asset");
        assert_eq!(state.root(), facility.state_root().expect("facility root"));

        let guarantor_key = SigningKey::from_bytes(&[71; 32]);
        let guarantor = GuarantorDefinition {
            guarantor_id: [72; 32],
            kind: GuarantorKind::CentralCounterparty,
            name: "test CCP".into(),
            public_key: guarantor_key.verifying_key().to_bytes(),
            risk_policy_digest: [73; 32],
        };
        let guarantor_statement = guarantor.statement().expect("guarantor statement");
        let approval = authorizer
            .approve(
                guarantor_statement,
                facility.state_root().expect("root"),
                &signers,
            )
            .expect("approval");
        facility
            .register_guarantor(&guarantor, &approval)
            .expect("facility guarantor");
        apply(
            &mut state,
            &authorizer,
            &signers,
            "defmivm.issueGuarantor",
            "guarantor",
            json!({
                "guarantorID": hex::encode(guarantor.guarantor_id),
                "kind": guarantor.kind.as_str(),
                "name": guarantor.name,
                "publicKey": hex::encode(guarantor.public_key),
                "riskPolicyDigest": hex::encode(guarantor.risk_policy_digest),
            }),
            guarantor_statement,
            100,
        )
        .expect("VM guarantor");
        assert_eq!(state.root(), facility.state_root().expect("facility root"));

        let mut grant = CreditFacilityGrant {
            operation_id: [74; 32],
            facility_id: [75; 32],
            guarantor_id: guarantor.guarantor_id,
            beneficiary_commitment: [76; 32],
            rail_asset_id: asset.asset_id,
            cap_commitment: [77; 32],
            available_commitment: [77; 32],
            held_commitment: ZERO,
            outstanding_commitment: ZERO,
            collateral_commitment: [78; 32],
            risk_policy_digest: guarantor.risk_policy_digest,
            relation_proof_digest: [79; 32],
            valid_from: 1,
            valid_until: 1_000,
            nonce: [80; 32],
            guarantor_signature: Signature::from_bytes(&[0; 64]),
        };
        grant.guarantor_signature =
            guarantor_key.sign(&grant.guarantor_message().expect("guarantor grant message"));
        let grant_statement = grant.statement().expect("grant statement");
        let approval = authorizer
            .approve(
                grant_statement,
                facility.state_root().expect("root"),
                &signers,
            )
            .expect("approval");
        facility
            .grant_credit_facility(&grant, &approval, 100)
            .expect("facility grant");
        apply(
            &mut state,
            &authorizer,
            &signers,
            "defmivm.issueCreditGrant",
            "grant",
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
            }),
            grant_statement,
            100,
        )
        .expect("VM grant");
        assert_eq!(state.root(), facility.state_root().expect("facility root"));

        let openings = [
            AccountOpening {
                handle: [21; 32],
                asset_id: asset.asset_id,
                commitment: [22; 32],
                issuance_nonce: [23; 32],
            },
            AccountOpening {
                handle: [31; 32],
                asset_id: asset.asset_id,
                commitment: [32; 32],
                issuance_nonce: [33; 32],
            },
        ];
        for opening in &openings {
            let statement = opening.statement().expect("opening statement");
            let approval = authorizer
                .approve(statement, facility.state_root().expect("root"), &signers)
                .expect("approval");
            facility
                .open_account(opening, &approval)
                .expect("facility account");
            apply(
                &mut state,
                &authorizer,
                &signers,
                "defmivm.issueAccount",
                "opening",
                json!({
                    "handle": hex::encode(opening.handle),
                    "assetID": hex::encode(opening.asset_id),
                    "commitment": hex::encode(opening.commitment),
                    "issuanceNonce": hex::encode(opening.issuance_nonce),
                }),
                statement,
                100,
            )
            .expect("VM account");
            assert_eq!(state.root(), facility.state_root().expect("facility root"));
        }

        let order = SettlementOrder {
            operation_id: [41; 32],
            nullifier: [42; 32],
            deadline: 1_000,
            payment_instruction_digest: [43; 32],
            proof_digest: [44; 32],
            market_statement_digest: [45; 32],
            legs: vec![
                StateLeg {
                    handle: openings[0].handle,
                    asset_id: asset.asset_id,
                    before_commitment: openings[0].commitment,
                    after_commitment: [24; 32],
                    before_sequence: 0,
                },
                StateLeg {
                    handle: openings[1].handle,
                    asset_id: asset.asset_id,
                    before_commitment: openings[1].commitment,
                    after_commitment: [34; 32],
                    before_sequence: 0,
                },
            ],
        };
        let statement = order.statement().expect("settlement statement");
        let approval = authorizer
            .approve(statement, facility.state_root().expect("root"), &signers)
            .expect("approval");
        facility
            .settle(&order, &approval, 100)
            .expect("facility settlement");
        apply(
            &mut state,
            &authorizer,
            &signers,
            "defmivm.issueSettlement",
            "order",
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
            }),
            statement,
            100,
        )
        .expect("VM settlement");
        assert_eq!(state.root(), facility.state_root().expect("facility root"));
    }

    #[test]
    fn concurrent_holds_cannot_both_consume_one_facility_sequence() {
        let (authorizer, signers) = committee();
        let facility_id = [90; 32];
        let mut state = State::default();
        state.credit_facilities.insert(
            id_key(&facility_id),
            CreditFacilityRecord {
                guarantor_id: [91; 32],
                beneficiary_commitment: [92; 32],
                rail_asset_id: [93; 32],
                cap_commitment: [94; 32],
                available_commitment: [94; 32],
                held_commitment: ZERO,
                outstanding_commitment: ZERO,
                overlimit_commitment: ZERO,
                collateral_commitment: [95; 32],
                risk_policy_digest: [96; 32],
                valid_from: 1,
                valid_until: 1_000,
                status: "active".into(),
                sequence: 0,
            },
        );
        let first = CreditFacilityTransition {
            operation_id: [101; 32],
            facility_id,
            hold_id: [102; 32],
            kind: CreditTransitionKind::Hold,
            query_commitment: [103; 32],
            amount_commitment: [104; 32],
            consumed_commitment: ZERO,
            refund_commitment: ZERO,
            before_available_commitment: [94; 32],
            after_available_commitment: [105; 32],
            before_held_commitment: ZERO,
            after_held_commitment: [104; 32],
            before_outstanding_commitment: ZERO,
            after_outstanding_commitment: ZERO,
            before_sequence: 0,
            expires_at: 500,
            settlement_digest: ZERO,
            relation_proof_digest: [106; 32],
        };
        let second = CreditFacilityTransition {
            operation_id: [111; 32],
            hold_id: [112; 32],
            query_commitment: [113; 32],
            amount_commitment: [114; 32],
            after_available_commitment: [115; 32],
            after_held_commitment: [114; 32],
            relation_proof_digest: [116; 32],
            ..first.clone()
        };
        let first_bytes = authorized_transaction(
            &state,
            &authorizer,
            &signers,
            "defmivm.issueCreditTransition",
            "transition",
            transition_json(&first),
            first.statement().expect("statement"),
        )
        .expect("first transaction");
        let simultaneous_second = authorized_transaction(
            &state,
            &authorizer,
            &signers,
            "defmivm.issueCreditTransition",
            "transition",
            transition_json(&second),
            second.statement().expect("statement"),
        )
        .expect("second transaction");
        state
            .apply(&first_bytes, &authorizer, 100)
            .expect("first hold");
        let after_first = state.clone();
        assert!(state
            .apply(&simultaneous_second, &authorizer, 100)
            .unwrap_err()
            .contains("stale state root"));
        assert_eq!(state, after_first);

        // Even if an attacker obtains a new quorum signature over the current
        // root, the stale compare-and-swap sequence remains consensus-invalid.
        let resigned_second = authorized_transaction(
            &state,
            &authorizer,
            &signers,
            "defmivm.issueCreditTransition",
            "transition",
            transition_json(&second),
            second.statement().expect("statement"),
        )
        .expect("re-signed transaction");
        assert!(state
            .apply(&resigned_second, &authorizer, 100)
            .unwrap_err()
            .contains("stale facility state"));
        assert_eq!(state, after_first);
        assert_eq!(state.credit_holds.len(), 1);
        assert_eq!(state.credit_facilities[&id_key(&facility_id)].sequence, 1);
    }

    #[test]
    fn credit_amendment_and_control_require_current_state_and_guarantor_authority() {
        let (authorizer, signers) = committee();
        let guarantor_key = SigningKey::from_bytes(&[121; 32]);
        let guarantor_id = [122; 32];
        let facility_id = [123; 32];
        let policy = [124; 32];
        let mut state = State::default();
        state.guarantors.insert(
            id_key(&guarantor_id),
            GuarantorRecord {
                kind: "ccp".into(),
                name: "test guarantor".into(),
                public_key: guarantor_key.verifying_key().to_bytes(),
                risk_policy_digest: policy,
                active: true,
            },
        );
        state.credit_facilities.insert(
            id_key(&facility_id),
            CreditFacilityRecord {
                guarantor_id,
                beneficiary_commitment: [125; 32],
                rail_asset_id: [126; 32],
                cap_commitment: [127; 32],
                available_commitment: [127; 32],
                held_commitment: [128; 32],
                outstanding_commitment: [129; 32],
                overlimit_commitment: ZERO,
                collateral_commitment: [130; 32],
                risk_policy_digest: policy,
                valid_from: 1,
                valid_until: 1_000,
                status: "active".into(),
                sequence: 0,
            },
        );

        let mut over_limit = CreditFacilityAmendment {
            operation_id: [131; 32],
            facility_id,
            mode: CreditAmendmentMode::OverLimit,
            before_cap_commitment: [127; 32],
            after_cap_commitment: [132; 32],
            before_available_commitment: [127; 32],
            after_available_commitment: ZERO,
            before_held_commitment: [128; 32],
            before_outstanding_commitment: [129; 32],
            before_overlimit_commitment: ZERO,
            after_overlimit_commitment: [133; 32],
            before_collateral_commitment: [130; 32],
            after_collateral_commitment: [134; 32],
            before_risk_policy_digest: policy,
            after_risk_policy_digest: policy,
            before_valid_until: 1_000,
            after_valid_until: 2_000,
            before_sequence: 0,
            effective_at: 100,
            reason_digest: [135; 32],
            relation_proof_digest: [136; 32],
            guarantor_signature: Signature::from_bytes(&[0; 64]),
        };
        over_limit.guarantor_signature = guarantor_key.sign(
            &over_limit
                .guarantor_message()
                .expect("over-limit guarantor message"),
        );
        let stale_over_limit = authorized_transaction(
            &state,
            &authorizer,
            &signers,
            "defmivm.issueCreditAmendment",
            "amendment",
            amendment_json(&over_limit),
            over_limit.statement().expect("over-limit statement"),
        )
        .expect("over-limit transaction");
        state
            .apply(&stale_over_limit, &authorizer, 100)
            .expect("over-limit amendment");
        let after_over_limit = state.clone();
        let record = &state.credit_facilities[&id_key(&facility_id)];
        assert_eq!(record.status, "frozen");
        assert_eq!(record.sequence, 1);
        assert_eq!(record.overlimit_commitment, [133; 32]);

        // A proposal signed for the same old state cannot be admitted twice.
        assert!(state
            .apply(&stale_over_limit, &authorizer, 100)
            .unwrap_err()
            .contains("already applied"));
        assert_eq!(state, after_over_limit);

        let mut activate_while_over_limit = CreditFacilityControl {
            operation_id: [137; 32],
            facility_id,
            action: CreditControlAction::Activate,
            before_sequence: 1,
            effective_at: 100,
            reason_digest: [138; 32],
            guarantor_signature: Signature::from_bytes(&[0; 64]),
        };
        activate_while_over_limit.guarantor_signature = guarantor_key.sign(
            &activate_while_over_limit
                .guarantor_message()
                .expect("activation message"),
        );
        let activation = authorized_transaction(
            &state,
            &authorizer,
            &signers,
            "defmivm.issueCreditControl",
            "control",
            control_json(&activate_while_over_limit),
            activate_while_over_limit
                .statement()
                .expect("activation statement"),
        )
        .expect("activation transaction");
        assert!(state
            .apply(&activation, &authorizer, 100)
            .unwrap_err()
            .contains("must be rehabilitated"));
        assert_eq!(state, after_over_limit);

        let mut rehabilitate = CreditFacilityAmendment {
            operation_id: [139; 32],
            mode: CreditAmendmentMode::WithinLimit,
            before_cap_commitment: [132; 32],
            after_cap_commitment: [140; 32],
            before_available_commitment: ZERO,
            after_available_commitment: [141; 32],
            before_overlimit_commitment: [133; 32],
            after_overlimit_commitment: ZERO,
            before_collateral_commitment: [134; 32],
            after_collateral_commitment: [142; 32],
            before_valid_until: 2_000,
            after_valid_until: 2_500,
            before_sequence: 1,
            reason_digest: [143; 32],
            relation_proof_digest: [144; 32],
            guarantor_signature: Signature::from_bytes(&[0; 64]),
            ..over_limit.clone()
        };
        rehabilitate.guarantor_signature = guarantor_key.sign(
            &rehabilitate
                .guarantor_message()
                .expect("rehabilitation message"),
        );
        apply(
            &mut state,
            &authorizer,
            &signers,
            "defmivm.issueCreditAmendment",
            "amendment",
            amendment_json(&rehabilitate),
            rehabilitate.statement().expect("rehabilitation statement"),
            100,
        )
        .expect("rehabilitation amendment");
        assert_eq!(
            state.credit_facilities[&id_key(&facility_id)].status,
            "frozen"
        );
        assert_eq!(state.credit_facilities[&id_key(&facility_id)].sequence, 2);

        let mut activate = CreditFacilityControl {
            operation_id: [145; 32],
            before_sequence: 2,
            reason_digest: [146; 32],
            ..activate_while_over_limit
        };
        activate.guarantor_signature = guarantor_key.sign(
            &activate
                .guarantor_message()
                .expect("rehabilitated activation message"),
        );
        apply(
            &mut state,
            &authorizer,
            &signers,
            "defmivm.issueCreditControl",
            "control",
            control_json(&activate),
            activate.statement().expect("activation statement"),
            100,
        )
        .expect("reactivate facility");
        let record = &state.credit_facilities[&id_key(&facility_id)];
        assert_eq!(record.status, "active");
        assert_eq!(record.sequence, 3);
        assert_eq!(record.overlimit_commitment, ZERO);
    }

    #[test]
    fn maker_and_taker_reservations_are_atomic_and_need_no_post_quote_signature() {
        let (authorizer, signers) = committee();
        let asset_id = [200; 32];
        let traded_asset_id = [195; 32];
        let maker_facility_id = [201; 32];
        let taker_facility_id = [219; 32];
        let batch_id = [224; 32];
        let venue_id = [225; 32];
        let mut state = State::default();
        state.assets.insert(
            id_key(&asset_id),
            AssetRecord {
                code: "JPY".into(),
                kind: "cash".into(),
                decimals: 0,
                terms_digest: [199; 32],
                active: true,
            },
        );
        state.assets.insert(
            id_key(&traded_asset_id),
            AssetRecord {
                code: "SEC".into(),
                kind: "security".into(),
                decimals: 0,
                terms_digest: [194; 32],
                active: true,
            },
        );
        state.accounts.insert(
            id_key(&[203; 32]),
            AccountRecord {
                asset_id: traded_asset_id,
                commitment: [204; 32],
                sequence: 0,
            },
        );
        state.accounts.insert(
            id_key(&[221; 32]),
            AccountRecord {
                asset_id,
                commitment: [222; 32],
                sequence: 0,
            },
        );
        state.accounts.insert(
            id_key(&[193; 32]),
            AccountRecord {
                asset_id: traded_asset_id,
                commitment: [192; 32],
                sequence: 0,
            },
        );
        state.accounts.insert(
            id_key(&[191; 32]),
            AccountRecord {
                asset_id,
                commitment: [190; 32],
                sequence: 0,
            },
        );
        for (facility_id, beneficiary, rail_asset_id, available) in [
            (maker_facility_id, [202; 32], traded_asset_id, [205; 32]),
            (taker_facility_id, [220; 32], asset_id, [223; 32]),
        ] {
            state.credit_facilities.insert(
                id_key(&facility_id),
                CreditFacilityRecord {
                    guarantor_id: [198; 32],
                    beneficiary_commitment: beneficiary,
                    rail_asset_id,
                    cap_commitment: available,
                    available_commitment: available,
                    held_commitment: ZERO,
                    outstanding_commitment: ZERO,
                    overlimit_commitment: ZERO,
                    collateral_commitment: [197; 32],
                    risk_policy_digest: [196; 32],
                    valid_from: 1,
                    valid_until: 1_000,
                    status: "active".into(),
                    sequence: 0,
                },
            );
        }
        let ticket_id = [228; 32];
        let taker_mandate = [229; 32];
        let batch_digest = [226; 32];
        let order_digest = [227; 32];
        let admission_receipt = CertifiedAdmissionLane {
            slot: 42,
            sequence: 1,
            principal_digest: ZERO,
            ticket_id,
            claim_digest: taker_mandate,
            cluster_digest: batch_digest,
            order_digest,
        }
        .digest(venue_id, 1)
        .expect("admission receipt");
        state.admission_batches.insert(
            id_key(&batch_id),
            AdmissionBatchRecord {
                venue_id,
                epoch: 1,
                slot: 42,
                batch_digest,
                order_digest,
                population: 1,
                consumed: 0,
                expires_at: 500,
                statement: [230; 32],
            },
        );
        state.admission_entries.insert(
            admission_entry_key(&batch_id, 1),
            AdmissionEntryRecord {
                batch_id,
                sequence: 1,
                admission_digest: admission_receipt,
                consumed_by: ZERO,
            },
        );

        let maker_transition = CreditFacilityTransition {
            operation_id: [206; 32],
            facility_id: maker_facility_id,
            hold_id: [207; 32],
            kind: CreditTransitionKind::Hold,
            query_commitment: [208; 32],
            amount_commitment: [209; 32],
            consumed_commitment: ZERO,
            refund_commitment: ZERO,
            before_available_commitment: [205; 32],
            after_available_commitment: [210; 32],
            before_held_commitment: ZERO,
            after_held_commitment: [209; 32],
            before_outstanding_commitment: ZERO,
            after_outstanding_commitment: ZERO,
            before_sequence: 0,
            expires_at: 500,
            settlement_digest: ZERO,
            relation_proof_digest: [211; 32],
        };
        let maker_escrow = ReservationEscrow {
            source_handle: [203; 32],
            escrow_handle: [212; 32],
            asset_id: traded_asset_id,
            amount_commitment: maker_transition.amount_commitment,
            source_before_commitment: [204; 32],
            source_after_commitment: [213; 32],
            source_before_sequence: 0,
            proof_digest: [214; 32],
        };
        let maker_authorization = ReservationAuthorization {
            role: ReservationRole::Maker,
            entity_commitment: [202; 32],
            asset_id: traded_asset_id,
            direction: 1,
            authorization_digest: maker_transition.query_commitment,
            mandate_digest: [215; 32],
            typed_reserve_digest: [216; 32],
            reserve_nullifier: [217; 32],
            asset_link_proof_digest: [218; 32],
            limit_price_commitment: ZERO,
            escrow_digest: maker_escrow.statement().expect("maker escrow digest"),
            rfq_nullifier: ZERO,
            policy_version: 1,
            admission_ticket_id: ZERO,
            admission_slot: 0,
            admission_receipt_digest: ZERO,
            admission_epoch: 0,
            admission_sequence: 0,
            admission_batch_id: ZERO,
        };
        let maker_bytes = authorized_reservation_transaction(
            &state,
            &authorizer,
            &signers,
            &maker_transition,
            &maker_authorization,
            &maker_escrow,
        )
        .expect("maker reserve transaction");
        state
            .apply(&maker_bytes, &authorizer, 100)
            .expect("maker reserve");
        assert_eq!(
            state.credit_facilities[&id_key(&maker_facility_id)].sequence,
            1
        );
        assert_eq!(
            state.accounts[&id_key(&maker_escrow.source_handle)].sequence,
            1
        );
        assert_eq!(
            state.reservation_bindings[&id_key(&maker_transition.hold_id)].role,
            "maker"
        );

        let taker_transition = CreditFacilityTransition {
            operation_id: [231; 32],
            facility_id: taker_facility_id,
            hold_id: [232; 32],
            kind: CreditTransitionKind::Hold,
            query_commitment: taker_mandate,
            amount_commitment: [233; 32],
            consumed_commitment: ZERO,
            refund_commitment: ZERO,
            before_available_commitment: [223; 32],
            after_available_commitment: [234; 32],
            before_held_commitment: ZERO,
            after_held_commitment: [233; 32],
            before_outstanding_commitment: ZERO,
            after_outstanding_commitment: ZERO,
            before_sequence: 0,
            expires_at: 500,
            settlement_digest: ZERO,
            relation_proof_digest: [235; 32],
        };
        let taker_escrow = ReservationEscrow {
            source_handle: [221; 32],
            escrow_handle: [236; 32],
            asset_id,
            amount_commitment: taker_transition.amount_commitment,
            source_before_commitment: [222; 32],
            source_after_commitment: [237; 32],
            source_before_sequence: 0,
            proof_digest: [238; 32],
        };
        let taker_authorization = ReservationAuthorization {
            role: ReservationRole::Taker,
            entity_commitment: [220; 32],
            asset_id,
            direction: 1,
            authorization_digest: taker_mandate,
            mandate_digest: taker_mandate,
            typed_reserve_digest: [239; 32],
            reserve_nullifier: [240; 32],
            asset_link_proof_digest: [241; 32],
            limit_price_commitment: (G * Scalar::from(250_u64)).compress().to_bytes(),
            escrow_digest: taker_escrow.statement().expect("taker escrow digest"),
            rfq_nullifier: [242; 32],
            policy_version: 0,
            admission_ticket_id: ticket_id,
            admission_slot: 42,
            admission_receipt_digest: admission_receipt,
            admission_epoch: 1,
            admission_sequence: 1,
            admission_batch_id: batch_id,
        };
        let taker_bytes = authorized_reservation_transaction(
            &state,
            &authorizer,
            &signers,
            &taker_transition,
            &taker_authorization,
            &taker_escrow,
        )
        .expect("taker reserve transaction");
        let decoded = TransactionEnvelope::decode(&taker_bytes).expect("decode reserve");
        let reserve_params = decoded.params.as_object().expect("reserve params");
        assert!(reserve_params["authorization"]
            .as_object()
            .expect("authorization")
            .keys()
            .all(|key| !key.to_ascii_lowercase().contains("signature")));
        assert!(reserve_params["escrow"]
            .as_object()
            .expect("escrow")
            .keys()
            .all(|key| !key.to_ascii_lowercase().contains("signature")));
        state
            .apply(&taker_bytes, &authorizer, 100)
            .expect("taker reserve");
        assert_eq!(state.admission_batches[&id_key(&batch_id)].consumed, 1);
        assert_eq!(
            state.admission_entries[&admission_entry_key(&batch_id, 1)].consumed_by,
            taker_transition.operation_id
        );
        assert_eq!(
            state.credit_facilities[&id_key(&taker_facility_id)].sequence,
            1
        );
        assert_eq!(
            state.accounts[&id_key(&taker_escrow.source_handle)].sequence,
            1
        );

        let duplicate_transition = CreditFacilityTransition {
            operation_id: [243; 32],
            hold_id: [244; 32],
            amount_commitment: [245; 32],
            before_available_commitment: [234; 32],
            after_available_commitment: [246; 32],
            before_held_commitment: [233; 32],
            after_held_commitment: [247; 32],
            before_sequence: 1,
            relation_proof_digest: [251; 32],
            ..taker_transition.clone()
        };
        let duplicate_escrow = ReservationEscrow {
            escrow_handle: [249; 32],
            amount_commitment: duplicate_transition.amount_commitment,
            source_before_commitment: [237; 32],
            source_after_commitment: [248; 32],
            source_before_sequence: 1,
            proof_digest: [250; 32],
            ..taker_escrow.clone()
        };
        let duplicate_authorization = ReservationAuthorization {
            reserve_nullifier: [252; 32],
            typed_reserve_digest: [253; 32],
            asset_link_proof_digest: [254; 32],
            escrow_digest: duplicate_escrow
                .statement()
                .expect("duplicate escrow digest"),
            ..taker_authorization.clone()
        };
        let duplicate = authorized_reservation_transaction(
            &state,
            &authorizer,
            &signers,
            &duplicate_transition,
            &duplicate_authorization,
            &duplicate_escrow,
        )
        .expect("duplicate reserve transaction");
        let accepted = state.clone();
        assert!(state
            .apply(&duplicate, &authorizer, 100)
            .unwrap_err()
            .contains("RFQ or admission lane was already reserved"));
        assert_eq!(state, accepted);

        let settlement = SettlementOrder {
            operation_id: [10; 32],
            nullifier: [11; 32],
            deadline: 400,
            payment_instruction_digest: [12; 32],
            proof_digest: [13; 32],
            market_statement_digest: [14; 32],
            legs: vec![
                StateLeg {
                    handle: maker_escrow.source_handle,
                    asset_id: traded_asset_id,
                    before_commitment: maker_escrow.source_after_commitment,
                    after_commitment: [15; 32],
                    before_sequence: 1,
                },
                StateLeg {
                    handle: [193; 32],
                    asset_id: traded_asset_id,
                    before_commitment: [192; 32],
                    after_commitment: [16; 32],
                    before_sequence: 0,
                },
                StateLeg {
                    handle: taker_escrow.source_handle,
                    asset_id,
                    before_commitment: taker_escrow.source_after_commitment,
                    after_commitment: [17; 32],
                    before_sequence: 1,
                },
                StateLeg {
                    handle: [191; 32],
                    asset_id,
                    before_commitment: [190; 32],
                    after_commitment: [18; 32],
                    before_sequence: 0,
                },
            ],
        };
        let base_statement = settlement.statement().expect("base settlement statement");
        let quantity_commitment = [22; 32];
        let cash_commitment = [27; 32];
        let maker_consumption = CreditFacilityTransition {
            operation_id: [21; 32],
            facility_id: maker_facility_id,
            hold_id: maker_transition.hold_id,
            kind: CreditTransitionKind::Consume,
            query_commitment: maker_transition.query_commitment,
            amount_commitment: maker_transition.amount_commitment,
            consumed_commitment: quantity_commitment,
            refund_commitment: [23; 32],
            before_available_commitment: maker_transition.after_available_commitment,
            after_available_commitment: [24; 32],
            before_held_commitment: maker_transition.after_held_commitment,
            after_held_commitment: ZERO,
            before_outstanding_commitment: ZERO,
            after_outstanding_commitment: quantity_commitment,
            before_sequence: 1,
            expires_at: maker_transition.expires_at,
            settlement_digest: base_statement,
            relation_proof_digest: [25; 32],
        };
        let taker_consumption = CreditFacilityTransition {
            operation_id: [26; 32],
            facility_id: taker_facility_id,
            hold_id: taker_transition.hold_id,
            kind: CreditTransitionKind::Consume,
            query_commitment: taker_transition.query_commitment,
            amount_commitment: taker_transition.amount_commitment,
            consumed_commitment: cash_commitment,
            refund_commitment: [28; 32],
            before_available_commitment: taker_transition.after_available_commitment,
            after_available_commitment: [29; 32],
            before_held_commitment: taker_transition.after_held_commitment,
            after_held_commitment: ZERO,
            before_outstanding_commitment: ZERO,
            after_outstanding_commitment: cash_commitment,
            before_sequence: 1,
            expires_at: taker_transition.expires_at,
            settlement_digest: base_statement,
            relation_proof_digest: [30; 32],
        };
        let product_order = ProductSettlementOrder {
            settlement,
            venue_id: [31; 32],
            defmi_id: [32; 32],
            maker_entity_commitment: maker_authorization.entity_commitment,
            taker_entity_commitment: taker_authorization.entity_commitment,
            rfq_nullifier: taker_authorization.rfq_nullifier,
            taker_authorization_digest: taker_authorization.authorization_digest,
            maker_policy_digest: maker_authorization.authorization_digest,
            maker_mandate_digest: maker_authorization.mandate_digest,
            taker_mandate_digest: taker_authorization.mandate_digest,
            typed_instruction_digest: [12; 32],
            quote_proof_digest: [13; 32],
            price_limit_proof_digest: [33; 32],
            dvp_proof_digest: [34; 32],
            quantity_commitment,
            cash_commitment,
            traded_asset_id,
            asset_link_proof_digest: [35; 32],
            admission_receipt_digest: taker_authorization.admission_receipt_digest,
            admission_epoch: taker_authorization.admission_epoch,
            admission_sequence: taker_authorization.admission_sequence,
            reservations: vec![
                ReservationConsumption {
                    role: ReservationRole::Maker,
                    reserve_receipt_digest: state.reservation_bindings
                        [&id_key(&maker_transition.hold_id)]
                        .receipt_digest,
                    transition: maker_consumption,
                },
                ReservationConsumption {
                    role: ReservationRole::Taker,
                    reserve_receipt_digest: state.reservation_bindings
                        [&id_key(&taker_transition.hold_id)]
                        .receipt_digest,
                    transition: taker_consumption,
                },
            ],
        };
        let mut batch_state = state.clone();
        let product_json = product_order_json(&product_order);
        assert!(!product_json
            .to_string()
            .to_ascii_lowercase()
            .contains("signature"));
        let product_statement = product_order.statement().expect("product statement");
        let root = state.root();
        let approval = authorizer
            .approve(product_statement, root, &signers)
            .expect("product approval");
        let product_transaction = TransactionEnvelope::new(
            "defmivm.issueProductSettlement",
            json!({
                "order": product_json,
                "approval": approval_json(&approval),
                "expectedBeforeRoot": hex::encode(root),
            }),
        )
        .expect("product transaction")
        .encode()
        .expect("product bytes");
        state
            .apply(&product_transaction, &authorizer, 100)
            .expect("signature-free product settlement");
        assert_eq!(
            state.credit_facilities[&id_key(&maker_facility_id)].sequence,
            2
        );
        assert_eq!(
            state.credit_facilities[&id_key(&taker_facility_id)].sequence,
            2
        );
        assert_eq!(
            state.credit_holds[&id_key(&maker_transition.hold_id)].status,
            "consumed"
        );
        assert_eq!(
            state.credit_holds[&id_key(&taker_transition.hold_id)].status,
            "consumed"
        );
        assert_eq!(
            state.reservation_escrows[&id_key(&maker_transition.hold_id)].status,
            "consumed"
        );
        assert_eq!(
            state.reservation_escrows[&id_key(&taker_transition.hold_id)].status,
            "consumed"
        );
        assert_eq!(
            state.nullifiers[&id_key(&product_order.settlement.nullifier)].statement,
            product_statement
        );
        assert_eq!(
            state.rfq_nullifiers[&id_key(&product_order.rfq_nullifier)],
            product_statement
        );
        for leg in &product_order.settlement.legs {
            let account = &state.accounts[&id_key(&leg.handle)];
            assert_eq!(account.commitment, leg.after_commitment);
            assert_eq!(account.sequence, leg.before_sequence + 1);
        }

        let batch =
            ProductSettlementBatch::from_orders([36; 32], std::slice::from_ref(&product_order))
                .expect("single-member atomic batch");
        let batch_statement = batch.statement().expect("batch statement");
        let batch_root = batch_state.root();
        let batch_approval = authorizer
            .approve(batch_statement, batch_root, &signers)
            .expect("batch approval");
        let batch_transaction = TransactionEnvelope::new(
            "defmivm.issueProductSettlementBatch",
            json!({
                "batch": product_batch_json(&batch),
                "orders": [product_order_json(&product_order)],
                "approval": approval_json(&batch_approval),
                "expectedBeforeRoot": hex::encode(batch_root),
            }),
        )
        .expect("batch transaction")
        .encode()
        .expect("batch bytes");
        batch_state
            .apply(&batch_transaction, &authorizer, 100)
            .expect("one quorum approval atomically settles the product batch");
        assert_eq!(
            batch_state.operations[&id_key(&batch.batch_id)],
            batch_statement
        );
        assert_eq!(
            batch_state.nullifiers[&id_key(&product_order.settlement.nullifier)].statement,
            product_statement
        );
        assert_eq!(
            batch_state.rfq_nullifiers[&id_key(&product_order.rfq_nullifier)],
            product_statement
        );
        for reservation in &product_order.reservations {
            assert_eq!(
                batch_state.credit_holds[&id_key(&reservation.transition.hold_id)].status,
                "consumed"
            );
        }
        for leg in &product_order.settlement.legs {
            let account = &batch_state.accounts[&id_key(&leg.handle)];
            assert_eq!(account.commitment, leg.after_commitment);
            assert_eq!(account.sequence, leg.before_sequence + 1);
        }
    }

    #[test]
    fn expired_reservation_releases_without_maker_or_taker_signature() {
        let (authorizer, signers) = committee();
        let asset_id = [1; 32];
        let account_handle = [2; 32];
        let facility_id = [4; 32];
        let hold_id = [8; 32];
        let mut state = State::default();
        state.assets.insert(
            id_key(&asset_id),
            AssetRecord {
                code: "JPY".into(),
                kind: "cash".into(),
                decimals: 0,
                terms_digest: [26; 32],
                active: true,
            },
        );
        state.accounts.insert(
            id_key(&account_handle),
            AccountRecord {
                asset_id,
                commitment: [3; 32],
                sequence: 1,
            },
        );
        state.credit_facilities.insert(
            id_key(&facility_id),
            CreditFacilityRecord {
                guarantor_id: [27; 32],
                beneficiary_commitment: [5; 32],
                rail_asset_id: asset_id,
                cap_commitment: [28; 32],
                available_commitment: [6; 32],
                held_commitment: [7; 32],
                outstanding_commitment: ZERO,
                overlimit_commitment: ZERO,
                collateral_commitment: [29; 32],
                risk_policy_digest: [30; 32],
                valid_from: 1,
                valid_until: 1_000,
                status: "active".into(),
                sequence: 1,
            },
        );
        state.credit_holds.insert(
            id_key(&hold_id),
            CreditHoldRecord {
                facility_id,
                query_commitment: [9; 32],
                amount_commitment: [10; 32],
                expires_at: 100,
                status: "active".into(),
                settlement_digest: ZERO,
                created_sequence: 1,
                updated_sequence: 1,
            },
        );
        state.reservation_bindings.insert(
            id_key(&hold_id),
            ReservationBindingRecord {
                role: "maker".into(),
                entity_commitment: [5; 32],
                asset_id,
                direction: 1,
                authorization_digest: [9; 32],
                mandate_digest: [11; 32],
                typed_reserve_digest: [12; 32],
                reserve_nullifier: [13; 32],
                asset_link_proof_digest: [14; 32],
                limit_price_commitment: ZERO,
                rfq_nullifier: ZERO,
                policy_version: 1,
                admission_ticket_id: ZERO,
                admission_slot: 0,
                admission_receipt_digest: ZERO,
                admission_epoch: 0,
                admission_sequence: 0,
                admission_batch_id: ZERO,
                receipt_digest: [15; 32],
            },
        );
        state.reservation_escrows.insert(
            id_key(&hold_id),
            ReservationEscrowRecord {
                source_handle: account_handle,
                escrow_handle: [16; 32],
                asset_id,
                amount_commitment: [10; 32],
                source_before_commitment: [17; 32],
                source_after_commitment: [3; 32],
                source_before_sequence: 0,
                proof_digest: [18; 32],
                status: "active".into(),
                settlement_digest: ZERO,
            },
        );
        let order = ProductReleaseOrder {
            transition: CreditFacilityTransition {
                operation_id: [19; 32],
                facility_id,
                hold_id,
                kind: CreditTransitionKind::Release,
                query_commitment: [9; 32],
                amount_commitment: [10; 32],
                consumed_commitment: ZERO,
                refund_commitment: ZERO,
                before_available_commitment: [6; 32],
                after_available_commitment: [20; 32],
                before_held_commitment: [7; 32],
                after_held_commitment: ZERO,
                before_outstanding_commitment: ZERO,
                after_outstanding_commitment: ZERO,
                before_sequence: 1,
                expires_at: 100,
                settlement_digest: ZERO,
                relation_proof_digest: [21; 32],
            },
            role: ReservationRole::Maker,
            reserve_receipt_digest: [15; 32],
            typed_instruction_digest: [22; 32],
            release_nullifier: [23; 32],
            release_deadline: 200,
            asset_id,
            asset_link_proof_digest: [24; 32],
            refund_leg: StateLeg {
                handle: account_handle,
                asset_id,
                before_commitment: [3; 32],
                after_commitment: [25; 32],
                before_sequence: 1,
            },
        };
        let order_json = product_release_json(&order);
        assert!(!order_json
            .to_string()
            .to_ascii_lowercase()
            .contains("signature"));
        let statement = order.statement().expect("release statement");
        let root = state.root();
        let approval = authorizer
            .approve(statement, root, &signers)
            .expect("release approval");
        let bytes = TransactionEnvelope::new(
            "defmivm.issueProductRelease",
            json!({
                "order": order_json,
                "approval": approval_json(&approval),
                "expectedBeforeRoot": hex::encode(root),
            }),
        )
        .expect("release transaction")
        .encode()
        .expect("release bytes");
        state
            .apply(&bytes, &authorizer, 101)
            .expect("automatic release");
        assert_eq!(state.credit_holds[&id_key(&hold_id)].status, "released");
        assert_eq!(
            state.reservation_escrows[&id_key(&hold_id)].status,
            "released"
        );
        assert_eq!(
            state.accounts[&id_key(&account_handle)].commitment,
            [25; 32]
        );
        assert_eq!(state.accounts[&id_key(&account_handle)].sequence, 2);
        assert_eq!(state.credit_facilities[&id_key(&facility_id)].sequence, 2);
        assert_eq!(
            state.nullifiers[&id_key(&order.release_nullifier)].statement,
            statement
        );
    }

    #[test]
    fn settlement_verifier_trust_anchor_has_the_same_native_and_vm_root() {
        let (authorizer, signers) = committee();
        let directory = tempfile::tempdir().expect("temporary directory");
        let facility = DefmiFacility::open(
            directory.path().join("settlement-verifier.sqlite"),
            authorizer.clone(),
            SigningKey::from_bytes(&[9; 32]),
        )
        .expect("facility");
        let mut state = State::default();
        let (_, frost_public) = qomm_zkpi::deal_quorum(7, 3, &mut OsRng).unwrap();
        let config = SettlementVerifierConfig {
            venue_id: [41; 32],
            defmi_id: [42; 32],
            epoch: 9,
            quote_registry_digest: [43; 32],
            quote_eligibility_bits: 16,
            quote_span_bits: 24,
            amount_bits: 16,
            price_bits: 32,
            max_horizon: 3_600,
            frost_public_package: frost_public.serialize().unwrap(),
            valid_from: 1,
            valid_until: 1_000,
        };
        let statement = config.statement().expect("verifier statement");
        let approval = authorizer
            .approve(
                statement,
                facility.state_root().expect("native root"),
                &signers,
            )
            .expect("verifier approval");
        facility
            .register_settlement_verifier(&config, &approval, 100)
            .expect("native settlement verifier");
        apply(
            &mut state,
            &authorizer,
            &signers,
            "defmivm.issueSettlementVerifier",
            "config",
            settlement_verifier_json(&config),
            statement,
            100,
        )
        .expect("VM settlement verifier");
        assert_eq!(
            state.root(),
            facility.state_root().expect("native verifier root")
        );
        assert_eq!(
            facility
                .settlement_verifier(&config.venue_id, config.epoch)
                .expect("native verifier lookup"),
            Some(config)
        );
    }

    #[test]
    fn seven_node_admission_order_matches_native_defmi_and_cannot_skip_a_lane() {
        let (authorizer, signers) = committee();
        let directory = tempfile::tempdir().expect("temporary directory");
        let facility = DefmiFacility::open(
            directory.path().join("admission.sqlite"),
            authorizer.clone(),
            SigningKey::from_bytes(&[9; 32]),
        )
        .expect("facility");
        let mut state = State::default();
        let admission_keys = (0u8..7)
            .map(|node| SigningKey::from_bytes(&[151 + node; 32]))
            .collect::<Vec<_>>();
        let committee_plan = AdmissionCommitteePlan {
            operation_id: [159; 32],
            venue_id: [160; 32],
            epoch: 7,
            node_keys: admission_keys
                .iter()
                .map(|key| key.verifying_key().to_bytes())
                .collect(),
            valid_from: 1,
            valid_until: 1_000,
        };
        let statement = committee_plan.statement().expect("committee statement");
        let approval = authorizer
            .approve(statement, facility.state_root().expect("root"), &signers)
            .expect("committee approval");
        facility
            .register_admission_committee(&committee_plan, &approval, 100)
            .expect("native committee");
        apply(
            &mut state,
            &authorizer,
            &signers,
            "defmivm.issueAdmissionCommittee",
            "plan",
            admission_committee_json(&committee_plan),
            statement,
            100,
        )
        .expect("VM committee");
        assert_eq!(state.root(), facility.state_root().expect("committee root"));

        let order_digest = [161; 32];
        let node_batch_digests = (0u8..7).map(|node| [170 + node; 32]).collect::<Vec<_>>();
        let lanes = (1u64..=2)
            .map(|sequence| {
                admission_keys
                    .iter()
                    .enumerate()
                    .map(|(node, key)| {
                        NodeAdmissionAttestation {
                            node: node as u16,
                            slot: 42,
                            sequence,
                            principal_digest: [180 + sequence as u8; 32],
                            ticket_id: [183 + sequence as u8; 32],
                            claim_digest: [186 + sequence as u8; 32],
                            batch_digest: node_batch_digests[node],
                            order_digest,
                            signature: Signature::from_bytes(&[0; 64]),
                        }
                        .sign(key)
                        .expect("admission signature")
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let trusted_keys = admission_keys
            .iter()
            .map(|key| key.verifying_key())
            .collect::<Vec<_>>();
        let certified = lanes
            .iter()
            .map(|lane| verify_admission_lane(lane, &trusted_keys).expect("certified lane"))
            .collect::<Vec<_>>();
        assert_eq!(certified[0].cluster_digest, certified[1].cluster_digest);
        let batch_plan = AdmissionBatchPlan {
            operation_id: [190; 32],
            batch_id: [191; 32],
            venue_id: committee_plan.venue_id,
            epoch: committee_plan.epoch,
            slot: 42,
            batch_digest: certified[0].cluster_digest,
            order_digest,
            admission_digests: certified
                .iter()
                .map(|lane| {
                    lane.digest(committee_plan.venue_id, committee_plan.epoch)
                        .expect("lane digest")
                })
                .collect(),
            expires_at: 500,
        };
        let statement = batch_plan.statement().expect("batch statement");
        let approval = authorizer
            .approve(statement, facility.state_root().expect("root"), &signers)
            .expect("batch approval");
        facility
            .register_admission_batch(&batch_plan, &lanes, &approval, 100)
            .expect("native batch");
        let root = state.root();
        let approval = authorizer
            .approve(statement, root, &signers)
            .expect("VM batch approval");
        let batch_transaction = TransactionEnvelope::new(
            "defmivm.issueAdmissionBatch",
            json!({
                "plan": admission_batch_json(&batch_plan),
                "admissionLanes": admission_lanes_json(&lanes),
                "approval": approval_json(&approval),
                "expectedBeforeRoot": hex::encode(root),
            }),
        )
        .expect("batch transaction")
        .encode()
        .expect("batch bytes");
        state
            .apply(&batch_transaction, &authorizer, 100)
            .expect("VM batch");
        assert_eq!(state.root(), facility.state_root().expect("batch root"));

        let skip = AdmissionSlotAdvance {
            operation_id: [192; 32],
            batch_id: batch_plan.batch_id,
            sequence: 2,
            admission_digest: batch_plan.admission_digests[1],
        };
        let skipped = authorized_transaction(
            &state,
            &authorizer,
            &signers,
            "defmivm.issueAdmissionAdvance",
            "advance",
            admission_advance_json(&skip),
            skip.statement().expect("skip statement"),
        )
        .expect("skip transaction");
        let before_skip = state.clone();
        assert!(state
            .apply(&skipped, &authorizer, 100)
            .unwrap_err()
            .contains("not the next"));
        assert_eq!(state, before_skip);

        for (index, digest) in batch_plan.admission_digests.iter().enumerate() {
            let advance = AdmissionSlotAdvance {
                operation_id: [193 + index as u8; 32],
                batch_id: batch_plan.batch_id,
                sequence: index as u64 + 1,
                admission_digest: *digest,
            };
            let statement = advance.statement().expect("advance statement");
            let approval = authorizer
                .approve(statement, facility.state_root().expect("root"), &signers)
                .expect("advance approval");
            facility
                .advance_admission_slot(&advance, &approval, 100)
                .expect("native advance");
            apply(
                &mut state,
                &authorizer,
                &signers,
                "defmivm.issueAdmissionAdvance",
                "advance",
                admission_advance_json(&advance),
                statement,
                100,
            )
            .expect("VM advance");
            assert_eq!(state.root(), facility.state_root().expect("advance root"));
        }
        assert_eq!(
            state.admission_batches[&id_key(&batch_plan.batch_id)].consumed,
            2
        );
    }
}
