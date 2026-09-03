//! Avalanche consensus adapter for Aethel's streaming-receivable state.
//!
//! Aethel owns the semantic state machine. DeFMI remains authoritative for
//! participant identity, notes, guarantee facilities, holds, cash reserves,
//! and settlement. This adapter is the only place where both books are joined.

use aethel_core::{
    dekyx_core::AnonymousPresentation, CreditDecision, DefaultAttestation, FundingQuote,
    GuaranteeClaim, GuaranteeCommitment, GuaranteeRelease, LossLayer, ProviderCapability,
    PublishCredentialStatus, ReceivableIssuance, RegisterCredentialIssuer, RegisterProvider,
    RegisterSeries, RegisterStream, RotateProviderKey, SetProviderStatus, StreamTransition,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use deccp_aethel::{
    AethelDeCcpAdapter, AethelGuaranteeBinding, AethelGuaranteeClaim, AethelGuaranteeOffer,
    AethelGuaranteeRelease, AethelLossLayer,
};
use deccp_core::{ClearingBook, DefmiSettlementReceipt};
use qomm_defmi::{
    facility::{QuorumAuthorizer, ZERO},
    participant::{ParticipantRole, ParticipantStatus},
    settlement_verifier::settlement_verifier_key,
};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::{
    frost,
    receivable::{ProviderReference, ReceivableInstruction, ReceivableOperation},
    receivable_wire, Bounds, Venue,
};
use serde::de::DeserializeOwned;
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use crate::state::{id_key, ClearingState, State};

use super::deccp::{clearing_book, next_facility_state, FacilityTransition, VmDefmiPort};
use super::{authorize, require_keys};

pub(super) fn register_provider(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["request", "approval", "expectedBeforeRoot"])?;
    let request: RegisterProvider = domain_field(params, "request")?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    ensure_global_operation_unused(state, request.operation_id)?;
    validate_provider_identity(state, &request)?;
    state
        .aethel
        .register_provider(request.clone(), timestamp)
        .map_err(|error| error.to_string())?;
    record_global_operation(state, request.operation_id, statement);
    Ok(statement)
}

pub(super) fn register_stream(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["request", "approval", "expectedBeforeRoot"])?;
    let request: RegisterStream = domain_field(params, "request")?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    ensure_global_operation_unused(state, request.operation_id)?;
    require_active_asset(
        state,
        request.state.settlement_asset_id,
        "stream settlement asset",
    )?;
    if state
        .assets
        .get(&id_key(&request.state.settlement_asset_id))
        .is_none_or(|asset| asset.kind != "cash")
    {
        return Err("Aethel stream settlement asset must use a DeFMI cash rail".into());
    }
    validate_provider_runtime(
        state,
        request.attestor_provider_id,
        ProviderCapability::StreamAttestor,
        timestamp,
    )?;
    state
        .aethel
        .register_stream(request.clone(), timestamp)
        .map_err(|error| error.to_string())?;
    record_global_operation(state, request.operation_id, statement);
    Ok(statement)
}

pub(super) fn transition_stream(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["request", "approval", "expectedBeforeRoot"])?;
    let request: StreamTransition = domain_field(params, "request")?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    ensure_global_operation_unused(state, request.operation_id)?;
    validate_provider_runtime(
        state,
        request.attestor_provider_id,
        ProviderCapability::StreamAttestor,
        timestamp,
    )?;
    state
        .aethel
        .transition_stream(request.clone(), timestamp)
        .map_err(|error| error.to_string())?;
    record_global_operation(state, request.operation_id, statement);
    Ok(statement)
}

pub(super) fn register_series(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["request", "approval", "expectedBeforeRoot"])?;
    let request: RegisterSeries = domain_field(params, "request")?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    ensure_global_operation_unused(state, request.operation_id)?;
    require_active_asset(
        state,
        request.series.receivable_asset_id,
        "receivable note asset",
    )?;
    require_active_participant(state, request.series.issuer_participant_id)?;
    state
        .aethel
        .register_series(request.clone(), timestamp)
        .map_err(|error| error.to_string())?;
    record_global_operation(state, request.operation_id, statement);
    Ok(statement)
}

pub(super) fn record_credit_decision(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_aethel_artifact_keys(params)?;
    let request: CreditDecision = domain_field(params, "request")?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    ensure_global_operation_unused(state, request.operation_id)?;
    validate_provider_runtime(
        state,
        request.provider_id,
        ProviderCapability::CreditAssessor,
        timestamp,
    )?;
    if let Some(presentation) = confidential_subject_proof(params)? {
        state
            .aethel
            .record_confidential_credit_decision(&presentation, request.clone(), timestamp)
            .map_err(|error| error.to_string())?;
    } else {
        state
            .aethel
            .record_credit_decision(request.clone(), timestamp)
            .map_err(|error| error.to_string())?;
    }
    record_global_operation(state, request.operation_id, statement);
    Ok(statement)
}

pub(super) fn record_guarantee(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_aethel_artifact_keys(params)?;
    let request: GuaranteeCommitment = domain_field(params, "request")?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    ensure_global_operation_unused(state, request.operation_id)?;
    validate_provider_runtime(
        state,
        request.provider_id,
        ProviderCapability::Guarantor,
        timestamp,
    )?;
    validate_guarantee_backing(state, &request, timestamp)?;
    // DeCCP reserves the hidden capacity first, on a copy of the book, so a
    // guarantee Aethel would accept but DeCCP would not never touches state.
    let mut book = clearing_book(state)?.clone();
    let offer = deccp_offer(state, &book, &request)?;
    AethelDeCcpAdapter::reserve(&mut book, offer, &VmDefmiPort { state }, timestamp)
        .map_err(|error| format!("DeCCP refused the guarantee reservation: {error}"))?;
    if let Some(presentation) = confidential_subject_proof(params)? {
        state
            .aethel
            .record_confidential_guarantee(&presentation, request.clone(), timestamp)
            .map_err(|error| error.to_string())?;
    } else {
        state
            .aethel
            .record_guarantee(request.clone(), timestamp)
            .map_err(|error| error.to_string())?;
    }
    state.deccp = Some(ClearingState { book });
    record_global_operation(state, request.operation_id, statement);
    Ok(statement)
}

/// The guarantor withdraws an unbound guarantee. DeFMI must already have
/// released the backing hold; DeCCP returns the hidden capacity through that
/// receipt; Aethel then marks the commitment released.
pub(super) fn release_guarantee(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["request", "approval", "expectedBeforeRoot"])?;
    let request: GuaranteeRelease = domain_field(params, "request")?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    ensure_global_operation_unused(state, request.operation_id)?;
    validate_provider_runtime(
        state,
        request.provider_id,
        ProviderCapability::Guarantor,
        timestamp,
    )?;
    let guarantee = state
        .aethel
        .guarantees
        .get(&id_key(&request.guarantee_id))
        .ok_or_else(|| "Aethel release names an unknown guarantee".to_string())?
        .clone();
    let hold = state
        .credit_holds
        .get(&id_key(&guarantee.defmi_hold_id))
        .ok_or_else(|| "Aethel release guarantee hold is absent".to_string())?;
    if hold.status != "released" || hold.settlement_digest != request.defmi_settlement_digest {
        return Err("Aethel release is not bound to the released DeFMI guarantee hold".into());
    }
    let mut book = clearing_book(state)?.clone();
    let binding = deccp_binding(&book, &guarantee)?;
    let facility = book
        .confidential_guarantee_facility(&binding.deccp_facility_id)
        .ok_or_else(|| "DeCCP facility for the guarantee is absent".to_string())?;
    let mut release = AethelGuaranteeRelease {
        operation_id: request.operation_id,
        deccp_expected_sequence: facility.sequence,
        deccp_expected_state_digest: facility.latest_facility_state_digest,
        deccp_after_state_digest: next_facility_state(
            facility.latest_facility_state_digest,
            FacilityTransition::Release,
            guarantee.defmi_hold_id,
            guarantee.coverage_commitment,
            hold.updated_sequence,
        ),
        transition_proof_digest: request.relation_proof_digest,
        receipt: DefmiSettlementReceipt {
            receipt_digest: request.defmi_settlement_digest,
            context_digest: ZERO,
            finalized_at: timestamp,
        },
    };
    release.receipt.context_digest = AethelDeCcpAdapter::release_context(&binding, &release);
    AethelDeCcpAdapter::release(
        &mut book,
        &binding,
        release,
        &VmDefmiPort { state },
        timestamp,
    )
    .map_err(|error| format!("DeCCP refused the guarantee release: {error}"))?;
    state
        .aethel
        .release_guarantee(request.clone(), timestamp)
        .map_err(|error| error.to_string())?;
    state.deccp = Some(ClearingState { book });
    record_global_operation(state, request.operation_id, statement);
    Ok(statement)
}

/// Moves an Aethel provider to its next artifact key. The next key must be
/// the key the DeFMI participant registry already holds for the provider's
/// participant, so the rotation is authorized by that registry's admin key
/// (and the VM committee), not by the key being retired. A provider that
/// guarantees keeps its DeFMI guarantor record, which was bound to the
/// registration key and does not rotate.
pub(super) fn rotate_provider_key(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["request", "approval", "expectedBeforeRoot"])?;
    let request: RotateProviderKey = domain_field(params, "request")?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    ensure_global_operation_unused(state, request.operation_id)?;
    let provider = state
        .aethel
        .provider(&request.provider_id)
        .map_err(|error| error.to_string())?;
    let participant = require_active_participant(state, provider.participant_id)?;
    if timestamp < participant.valid_from
        || timestamp > participant.valid_until
        || participant.keys.quote.public_key != request.next_public_key
    {
        return Err(
            "Aethel provider key rotation must install the participant's current quote key".into(),
        );
    }
    state
        .aethel
        .rotate_provider_key(request.clone(), timestamp)
        .map_err(|error| error.to_string())?;
    record_global_operation(state, request.operation_id, statement);
    Ok(statement)
}

/// Suspends, reinstates, or revokes an Aethel provider by quorum decision.
pub(super) fn set_provider_status(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["request", "approval", "expectedBeforeRoot"])?;
    let request: SetProviderStatus = domain_field(params, "request")?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    ensure_global_operation_unused(state, request.operation_id)?;
    state
        .aethel
        .set_provider_status(request.clone(), timestamp)
        .map_err(|error| error.to_string())?;
    record_global_operation(state, request.operation_id, statement);
    Ok(statement)
}

/// A credential-issuer provider vouches for a DeKYX issuer key epoch, or
/// rotates it. The DeKYX key is independent of the provider's quote key; the
/// provider signs the registration, DeKYX validates the definition.
pub(super) fn register_credential_issuer(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["request", "approval", "expectedBeforeRoot"])?;
    let request: RegisterCredentialIssuer = domain_field(params, "request")?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    ensure_global_operation_unused(state, request.operation_id)?;
    validate_provider_runtime(
        state,
        request.provider_id,
        ProviderCapability::CredentialIssuer,
        timestamp,
    )?;
    state
        .aethel
        .register_credential_issuer(request.clone(), timestamp)
        .map_err(|error| error.to_string())?;
    record_global_operation(state, request.operation_id, statement);
    Ok(statement)
}

/// Publishes an issuer-signed DeKYX revocation status list. Authenticity is
/// the DeKYX issuer key's; the VM adds quorum ordering and replay protection.
pub(super) fn publish_credential_status(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["request", "approval", "expectedBeforeRoot"])?;
    let request: PublishCredentialStatus = domain_field(params, "request")?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    ensure_global_operation_unused(state, request.operation_id)?;
    state
        .aethel
        .publish_credential_status(request.clone(), timestamp)
        .map_err(|error| error.to_string())?;
    record_global_operation(state, request.operation_id, statement);
    Ok(statement)
}

pub(super) fn record_funding_quote(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["request", "approval", "expectedBeforeRoot"])?;
    let request: FundingQuote = domain_field(params, "request")?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    ensure_global_operation_unused(state, request.operation_id)?;
    validate_provider_runtime(
        state,
        request.provider_id,
        ProviderCapability::LiquidityProvider,
        timestamp,
    )?;
    validate_funding_backing(state, &request, timestamp)?;
    state
        .aethel
        .record_funding_quote(request.clone(), timestamp)
        .map_err(|error| error.to_string())?;
    record_global_operation(state, request.operation_id, statement);
    Ok(statement)
}

pub(super) fn issue_receivable(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &["request", "zkpi", "approval", "expectedBeforeRoot"],
    )?;
    let request: ReceivableIssuance = domain_field(params, "request")?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    ensure_global_operation_unused(state, request.operation_id)?;
    validate_issuance_provider_status(state, &request, timestamp)?;
    let raw = base64_field(params, "zkpi")?;
    let instruction = verify_receivable_zkpi(state, &raw, timestamp)?;
    validate_issuance_binding(state, &request, &instruction)?;
    let clearing = match request.guarantee_id {
        Some(guarantee_id) => {
            let guarantee = state
                .aethel
                .guarantees
                .get(&id_key(&guarantee_id))
                .ok_or_else(|| "Aethel issuance names an unknown guarantee".to_string())?;
            let mut book = clearing_book(state)?.clone();
            let binding = deccp_binding(&book, guarantee)?;
            AethelDeCcpAdapter::bind_issuance(
                &mut book,
                request.operation_id,
                &binding,
                request.issuance_id,
                timestamp,
            )
            .map_err(|error| format!("DeCCP refused to bind the guarantee: {error}"))?;
            Some(ClearingState { book })
        }
        None => None,
    };
    state
        .aethel
        .issue_receivable(request.clone(), timestamp)
        .map_err(|error| error.to_string())?;
    if clearing.is_some() {
        state.deccp = clearing;
    }
    record_global_operation(state, request.operation_id, statement);
    Ok(statement)
}

pub(super) fn record_default(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["request", "approval", "expectedBeforeRoot"])?;
    let request: DefaultAttestation = domain_field(params, "request")?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    ensure_global_operation_unused(state, request.operation_id)?;
    validate_provider_runtime(
        state,
        request.provider_id,
        ProviderCapability::Servicer,
        timestamp,
    )?;
    state
        .aethel
        .record_default(request.clone(), timestamp)
        .map_err(|error| error.to_string())?;
    record_global_operation(state, request.operation_id, statement);
    Ok(statement)
}

pub(super) fn claim_guarantee(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &["request", "zkpi", "approval", "expectedBeforeRoot"],
    )?;
    let request: GuaranteeClaim = domain_field(params, "request")?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    ensure_global_operation_unused(state, request.operation_id)?;
    validate_claim_backing(state, &request)?;
    let raw = base64_field(params, "zkpi")?;
    let instruction = verify_receivable_zkpi(state, &raw, timestamp)?;
    validate_claim_binding(state, &request, &instruction)?;
    let book = consume_deccp_guarantee(state, &request, timestamp)?;
    state
        .aethel
        .claim_guarantee(request.clone(), timestamp)
        .map_err(|error| error.to_string())?;
    state.deccp = Some(ClearingState { book });
    record_global_operation(state, request.operation_id, statement);
    Ok(statement)
}

/// DeCCP consumes the hold for exactly this issuance and default event, with
/// the DeFMI settlement that consumed the guarantee hold as its receipt.
fn consume_deccp_guarantee(
    state: &State,
    request: &GuaranteeClaim,
    timestamp: u64,
) -> Result<ClearingBook, String> {
    let guarantee = state
        .aethel
        .guarantees
        .get(&id_key(&request.guarantee_id))
        .ok_or_else(|| "Aethel claim names an unknown guarantee".to_string())?;
    let default = state
        .aethel
        .default_attestations
        .get(&id_key(&request.default_attestation_id))
        .ok_or_else(|| "Aethel claim names an unknown default attestation".to_string())?;
    let hold = state
        .credit_holds
        .get(&id_key(&guarantee.defmi_hold_id))
        .ok_or_else(|| "Aethel claim guarantee hold is absent".to_string())?;
    let mut book = clearing_book(state)?.clone();
    let binding = deccp_binding(&book, guarantee)?;
    let facility = book
        .confidential_guarantee_facility(&binding.deccp_facility_id)
        .ok_or_else(|| "DeCCP facility for the guarantee is absent".to_string())?;
    let mut claim = AethelGuaranteeClaim {
        operation_id: request.operation_id,
        issuance_id: request.issuance_id,
        default_event_digest: default.event_digest,
        deccp_expected_sequence: facility.sequence,
        deccp_expected_state_digest: facility.latest_facility_state_digest,
        deccp_after_state_digest: next_facility_state(
            facility.latest_facility_state_digest,
            FacilityTransition::Claim,
            guarantee.defmi_hold_id,
            guarantee.coverage_commitment,
            hold.updated_sequence,
        ),
        transition_proof_digest: request.relation_proof_digest,
        receipt: DefmiSettlementReceipt {
            receipt_digest: request.defmi_settlement_digest,
            context_digest: ZERO,
            finalized_at: timestamp,
        },
    };
    claim.receipt.context_digest = AethelDeCcpAdapter::claim_context(&binding, &claim);
    AethelDeCcpAdapter::claim(
        &mut book,
        &binding,
        claim,
        &VmDefmiPort { state },
        timestamp,
    )
    .map_err(|error| format!("DeCCP refused the guarantee claim: {error}"))?;
    Ok(book)
}

/// The DeCCP reservation an Aethel guarantee asks for. The DeCCP facility is
/// the DeFMI facility (same id), the DeCCP hold is the Aethel guarantee, the
/// beneficiary line is the DeFMI facility's committed beneficiary, and the
/// CAS fields come from the book itself: the VM executes sequentially against
/// `expectedBeforeRoot`, so the DeCCP sequence check is a second lock, not
/// the client's view.
fn deccp_offer(
    state: &State,
    book: &ClearingBook,
    guarantee: &GuaranteeCommitment,
) -> Result<AethelGuaranteeOffer, String> {
    let facility = book
        .confidential_guarantee_facility(&guarantee.defmi_facility_id)
        .ok_or_else(|| "Aethel guarantee names a facility DeCCP does not clear".to_string())?;
    let hold = state
        .credit_holds
        .get(&id_key(&guarantee.defmi_hold_id))
        .ok_or_else(|| "Aethel guarantee names an unknown DeFMI hold".to_string())?;
    Ok(AethelGuaranteeOffer {
        operation_id: guarantee.operation_id,
        guarantee_id: guarantee.guarantee_id,
        request_id: guarantee.request_id,
        provider_id: guarantee.provider_id,
        series_id: guarantee.series_id,
        stream_state_version: guarantee.stream_state_version,
        stream_state_root: guarantee.stream_state_root,
        credit_decision_id: guarantee.credit_decision_id,
        deccp_facility_id: facility.facility_id,
        deccp_expected_sequence: facility.sequence,
        deccp_expected_state_digest: facility.latest_facility_state_digest,
        deccp_after_state_digest: next_facility_state(
            facility.latest_facility_state_digest,
            FacilityTransition::Reserve,
            guarantee.defmi_hold_id,
            guarantee.coverage_commitment,
            hold.created_sequence,
        ),
        deccp_hold_id: guarantee.guarantee_id,
        defmi_facility_id: guarantee.defmi_facility_id,
        defmi_hold_id: guarantee.defmi_hold_id,
        coverage_commitment: guarantee.coverage_commitment,
        beneficiary_subject_line_id: facility.beneficiary_subject_line_id,
        loss_layer: deccp_loss_layer(guarantee.loss_layer),
        guarantee_terms_digest: guarantee.guarantee_terms_digest,
        claim_policy_digest: guarantee.claim_policy_digest,
        relation_proof_digest: guarantee.relation_proof_digest,
        valid_until: guarantee.valid_until,
        nonce: guarantee.nonce,
    })
}

/// The DeCCP binding for a recorded guarantee, rebuilt from the guarantee
/// itself and the hold DeCCP keeps under the guarantee id.
fn deccp_binding(
    book: &ClearingBook,
    guarantee: &GuaranteeCommitment,
) -> Result<AethelGuaranteeBinding, String> {
    let hold = book
        .confidential_guarantee_hold(&guarantee.guarantee_id)
        .ok_or_else(|| "DeCCP holds no reservation for the Aethel guarantee".to_string())?;
    if hold.defmi_hold_id != guarantee.defmi_hold_id
        || hold.coverage_commitment != guarantee.coverage_commitment
        || hold.facility_id != guarantee.defmi_facility_id
    {
        return Err("DeCCP reservation and Aethel guarantee describe different holds".into());
    }
    Ok(AethelGuaranteeBinding {
        guarantee_id: guarantee.guarantee_id,
        request_id: guarantee.request_id,
        provider_id: guarantee.provider_id,
        series_id: guarantee.series_id,
        stream_state_version: guarantee.stream_state_version,
        stream_state_root: guarantee.stream_state_root,
        credit_decision_id: guarantee.credit_decision_id,
        deccp_facility_id: hold.facility_id,
        deccp_hold_id: hold.hold_id,
        defmi_facility_id: guarantee.defmi_facility_id,
        defmi_hold_id: guarantee.defmi_hold_id,
        coverage_commitment: guarantee.coverage_commitment,
        loss_layer: deccp_loss_layer(guarantee.loss_layer),
        guarantee_terms_digest: guarantee.guarantee_terms_digest,
        claim_policy_digest: guarantee.claim_policy_digest,
        relation_proof_digest: guarantee.relation_proof_digest,
        valid_until: guarantee.valid_until,
        nonce: guarantee.nonce,
    })
}

fn deccp_loss_layer(layer: LossLayer) -> AethelLossLayer {
    match layer {
        LossLayer::FirstLoss => AethelLossLayer::FirstLoss,
        LossLayer::PariPassu => AethelLossLayer::PariPassu,
        LossLayer::Excess => AethelLossLayer::Excess,
    }
}

fn validate_provider_identity(state: &State, request: &RegisterProvider) -> Result<(), String> {
    let provider = &request.provider;
    let participant = require_active_participant(state, provider.participant_id)?;
    if provider.valid_from < participant.valid_from
        || provider.valid_until > participant.valid_until
        || participant.keys.quote.public_key != provider.public_key
    {
        return Err(
            "Aethel provider is outside its participant identity or quote-key epoch".into(),
        );
    }
    for capability in &provider.capabilities {
        let role = match capability {
            ProviderCapability::StreamAttestor => ParticipantRole::StreamAttestor,
            ProviderCapability::CredentialIssuer => ParticipantRole::CredentialIssuer,
            ProviderCapability::CreditAssessor => ParticipantRole::CreditAssessor,
            ProviderCapability::Guarantor => ParticipantRole::Guarantor,
            ProviderCapability::LiquidityProvider => ParticipantRole::LiquidityProvider,
            ProviderCapability::Servicer => ParticipantRole::Servicer,
        };
        if !participant.roles.contains(&role) {
            return Err(
                "Aethel provider capability is absent from its verified participant role".into(),
            );
        }
    }
    if let Some(guarantor_id) = provider.defmi_guarantor_id {
        let guarantor = state
            .guarantors
            .get(&id_key(&guarantor_id))
            .ok_or_else(|| "Aethel guarantee provider has no DeFMI guarantor".to_string())?;
        if !guarantor.active || guarantor.public_key != provider.public_key {
            return Err("Aethel guarantee provider and DeFMI guarantor identity differ".into());
        }
    }
    Ok(())
}

fn validate_provider_runtime(
    state: &State,
    provider_id: [u8; 32],
    capability: ProviderCapability,
    timestamp: u64,
) -> Result<(), String> {
    let provider = state
        .aethel
        .provider(&provider_id)
        .map_err(|error| error.to_string())?;
    if !provider.has(capability, timestamp) {
        return Err("Aethel provider capability is inactive at execution time".into());
    }
    let participant = require_active_participant(state, provider.participant_id)?;
    if timestamp < participant.valid_from
        || timestamp > participant.valid_until
        || participant.keys.quote.public_key != provider.public_key
    {
        return Err("Aethel provider no longer matches its active participant key epoch".into());
    }
    if capability == ProviderCapability::Guarantor {
        let guarantor_id = provider
            .defmi_guarantor_id
            .ok_or_else(|| "guarantee provider has no DeFMI guarantor identity".to_string())?;
        let guarantor = state
            .guarantors
            .get(&id_key(&guarantor_id))
            .ok_or_else(|| "Aethel guarantee provider has no DeFMI guarantor".to_string())?;
        // The DeFMI guarantor record is bound to the key the provider was
        // registered with; Aethel key rotation does not re-bind it.
        if !guarantor.active || guarantor.public_key != provider.registration_key() {
            return Err("Aethel guarantee provider's DeFMI authority is inactive".into());
        }
    }
    Ok(())
}

fn validate_issuance_provider_status(
    state: &State,
    request: &ReceivableIssuance,
    timestamp: u64,
) -> Result<(), String> {
    let series = state
        .aethel
        .series
        .get(&id_key(&request.series_id))
        .ok_or_else(|| "Aethel issuance names an unknown series".to_string())?;
    let stream = state
        .aethel
        .stream(&series.stream_id)
        .map_err(|error| error.to_string())?;
    validate_provider_runtime(
        state,
        stream.attestor_provider_id,
        ProviderCapability::StreamAttestor,
        timestamp,
    )?;
    if let Some(decision_id) = request.credit_decision_id {
        let decision = state
            .aethel
            .credit_decisions
            .get(&id_key(&decision_id))
            .ok_or_else(|| "Aethel issuance names an unknown credit decision".to_string())?;
        validate_provider_runtime(
            state,
            decision.provider_id,
            ProviderCapability::CreditAssessor,
            timestamp,
        )?;
    }
    if let Some(guarantee_id) = request.guarantee_id {
        let guarantee = state
            .aethel
            .guarantees
            .get(&id_key(&guarantee_id))
            .ok_or_else(|| "Aethel issuance names an unknown guarantee".to_string())?;
        validate_provider_runtime(
            state,
            guarantee.provider_id,
            ProviderCapability::Guarantor,
            timestamp,
        )?;
        validate_guarantee_backing(state, guarantee, timestamp)?;
    }
    if let Some(quote_id) = request.funding_quote_id {
        let quote = state
            .aethel
            .funding_quotes
            .get(&id_key(&quote_id))
            .ok_or_else(|| "Aethel issuance names an unknown funding quote".to_string())?;
        validate_provider_runtime(
            state,
            quote.provider_id,
            ProviderCapability::LiquidityProvider,
            timestamp,
        )?;
        validate_funding_backing(state, quote, timestamp)?;
    }
    Ok(())
}

fn validate_guarantee_backing(
    state: &State,
    request: &GuaranteeCommitment,
    timestamp: u64,
) -> Result<(), String> {
    let provider = state
        .aethel
        .provider(&request.provider_id)
        .map_err(|e| e.to_string())?;
    let guarantor_id = provider
        .defmi_guarantor_id
        .ok_or_else(|| "guarantee provider has no DeFMI guarantor identity".to_string())?;
    let facility = state
        .credit_facilities
        .get(&id_key(&request.defmi_facility_id))
        .ok_or_else(|| "Aethel guarantee names an unknown DeFMI facility".to_string())?;
    let hold = state
        .credit_holds
        .get(&id_key(&request.defmi_hold_id))
        .ok_or_else(|| "Aethel guarantee names an unknown DeFMI hold".to_string())?;
    let series = state
        .aethel
        .series
        .get(&id_key(&request.series_id))
        .ok_or_else(|| "Aethel guarantee names an unknown series".to_string())?;
    let stream = state
        .aethel
        .stream(&series.stream_id)
        .map_err(|e| e.to_string())?;
    if facility.guarantor_id != guarantor_id
        || facility.rail_asset_id != stream.state.settlement_asset_id
        || facility.status != "active"
        || timestamp < facility.valid_from
        || request.valid_until > facility.valid_until
        || hold.facility_id != request.defmi_facility_id
        || hold.amount_commitment != request.coverage_commitment
        || hold.status != "active"
        || hold.settlement_digest != ZERO
        || request.valid_until > hold.expires_at
    {
        return Err("Aethel guarantee is not backed by the named live DeFMI hold".into());
    }
    Ok(())
}

fn validate_funding_backing(
    state: &State,
    request: &FundingQuote,
    timestamp: u64,
) -> Result<(), String> {
    let reserve = state
        .note_reservations
        .get(&id_key(&request.cash_reservation_id))
        .ok_or_else(|| "Aethel funding quote names an unknown DeFMI cash reserve".to_string())?;
    if reserve.asset_id != request.cash_asset_id
        || reserve.amount_commitment != request.advance_commitment
        || reserve.status != "active"
        || reserve.settlement_digest != ZERO
        || timestamp > request.valid_until
    {
        return Err("Aethel funding quote is not backed by the named live cash reserve".into());
    }
    Ok(())
}

fn validate_issuance_binding(
    state: &State,
    request: &ReceivableIssuance,
    instruction: &ReceivableInstruction,
) -> Result<(), String> {
    let wire_digest = instruction_wire_digest(instruction);
    if wire_digest != request.zkpi_digest {
        return Err("Aethel issuance zkPI digest differs from its canonical wire".into());
    }
    let series = state
        .aethel
        .series
        .get(&id_key(&request.series_id))
        .ok_or_else(|| "Aethel issuance names an unknown series".to_string())?;
    let stream = state
        .aethel
        .stream(&series.stream_id)
        .map_err(|e| e.to_string())?;
    let after = stream
        .state
        .valid_issuance_successor(request.after_pledged_commitment)
        .map_err(|error| error.to_string())?;
    let note = state
        .notes
        .get(&id_key(&request.note_id))
        .ok_or_else(|| "Aethel issuance names an unknown DeFMI note".to_string())?;
    let expected_note_lock = if series.policy.allow_secondary_transfer {
        ZERO
    } else {
        request.series_id
    };
    if note.asset_id != series.receivable_asset_id
        || note.value_commitment != request.face_value_commitment
        || note.lock_id != expected_note_lock
    {
        return Err("DeFMI note transfer policy, Aethel series, and face commitment differ".into());
    }
    let context = &instruction.context;
    if context.operation != ReceivableOperation::Issue
        || context.aethel_domain_id != series.aethel_domain_id
        || context.request_id != request.request_id
        || context.action_id != request.issuance_id
        || context.series_id != request.series_id
        || context.stream_id != series.stream_id
        || context.stream_state_version != request.before_stream_state_version
        || context.before_stream_state_root != request.before_stream_state_root
        || context.after_stream_state_root != after.root().map_err(|e| e.to_string())?
        || context.eligible_commitment != stream.state.eligible_commitment
        || context.before_pledged_commitment != stream.state.pledged_commitment
        || context.after_pledged_commitment != request.after_pledged_commitment
        || context.receivable_note_id != request.note_id
        || context.settlement_asset_id != stream.state.settlement_asset_id
        || context.credit != credit_reference(state, request.credit_decision_id)?
        || context.guarantee != guarantee_reference(state, request.guarantee_id)?
        || context.funding != funding_reference(state, request.funding_quote_id)?
        || context.policy_digest != series.policy.eligibility_policy_digest
        || context.relation_proof_digest != request.relation_proof_digest
        || context.operation_nullifier != request.allocation_nullifier
        || context.before_aethel_root != state.aethel.root().map_err(|e| e.to_string())?
        || instruction
            .instruction
            .amount_commitment
            .compress()
            .to_bytes()
            != request.face_value_commitment
        || instruction.instruction.payee_handle.compress().to_bytes() != request.owner_commitment
    {
        return Err("Aethel issuance and streaming-receivable zkPI bindings differ".into());
    }
    if series.policy.requires_confidential_subject {
        let binding = state
            .aethel
            .confidential_subject(&request.request_id)
            .ok_or_else(|| "confidential Aethel issuance has no subject binding".to_string())?;
        if binding.policy_digest != series.policy.eligibility_policy_digest {
            return Err("confidential Aethel subject uses another eligibility policy".into());
        }
        if let Some(decision_id) = request.credit_decision_id {
            let decision = state
                .aethel
                .credit_decisions
                .get(&id_key(&decision_id))
                .ok_or_else(|| "confidential Aethel issuance has no credit decision".to_string())?;
            if decision.decision_terms_commitment != context.eligible_commitment {
                return Err(
                    "confidential credit-line commitment differs from zkPI eligible capacity"
                        .into(),
                );
            }
        }
    }
    let expected_consideration = if let Some(quote_id) = request.funding_quote_id {
        state
            .aethel
            .funding_quotes
            .get(&id_key(&quote_id))
            .expect("reference helper checked quote")
            .advance_commitment
    } else if let Some(guarantee_id) = request.guarantee_id {
        state
            .aethel
            .guarantees
            .get(&id_key(&guarantee_id))
            .expect("reference helper checked guarantee")
            .coverage_commitment
    } else {
        request.face_value_commitment
    };
    if instruction
        .instruction
        .price_commitment
        .compress()
        .to_bytes()
        != expected_consideration
    {
        return Err(
            "Aethel issuance zkPI consideration commitment is not funding or coverage".into(),
        );
    }
    Ok(())
}

fn validate_claim_backing(state: &State, request: &GuaranteeClaim) -> Result<(), String> {
    let guarantee = state
        .aethel
        .guarantees
        .get(&id_key(&request.guarantee_id))
        .ok_or_else(|| "Aethel claim names an unknown guarantee".to_string())?;
    let hold = state
        .credit_holds
        .get(&id_key(&guarantee.defmi_hold_id))
        .ok_or_else(|| "Aethel claim guarantee hold is absent".to_string())?;
    let facility = state
        .credit_facilities
        .get(&id_key(&guarantee.defmi_facility_id))
        .ok_or_else(|| "Aethel claim guarantee facility is absent".to_string())?;
    let issuance = state
        .aethel
        .issuances
        .get(&id_key(&request.issuance_id))
        .ok_or_else(|| "Aethel claim names an unknown issuance".to_string())?;
    let series = state
        .aethel
        .series
        .get(&id_key(&issuance.series_id))
        .ok_or_else(|| "Aethel claim issuance has no series".to_string())?;
    if hold.status != "consumed"
        || hold.settlement_digest != request.defmi_settlement_digest
        || hold.amount_commitment != guarantee.coverage_commitment
        || request.claim_amount_commitment != guarantee.coverage_commitment
    {
        return Err(
            "Aethel full-cover claim is not bound to the consumed DeFMI guarantee hold".into(),
        );
    }
    let has_delivery_entitlement = state.note_claims.values().any(|claim| {
        claim.source_hold_id == guarantee.defmi_hold_id
            && claim.asset_id == facility.rail_asset_id
            && claim.value_commitment == request.claim_amount_commitment
            && claim.recipient_commitment == request.recovery_recipient_commitment
            && claim.kind == "delivery"
            && matches!(claim.status.as_str(), "active" | "materialized")
            && claim.settlement_digest == request.defmi_settlement_digest
    });
    if !has_delivery_entitlement {
        return Err(
            "Aethel claim has no matching DeFMI delivery entitlement for its recipient".into(),
        );
    }
    if !state.note_serials.values().any(|serial| {
        serial.asset_id == series.receivable_asset_id
            && serial.statement == request.defmi_settlement_digest
    }) {
        return Err(
            "Aethel claim settlement did not consume a note from the receivable series".into(),
        );
    }
    Ok(())
}

fn validate_claim_binding(
    state: &State,
    request: &GuaranteeClaim,
    instruction: &ReceivableInstruction,
) -> Result<(), String> {
    if instruction_wire_digest(instruction) != request.zkpi_digest {
        return Err("Aethel claim zkPI digest differs from its canonical wire".into());
    }
    let issuance = state
        .aethel
        .issuances
        .get(&id_key(&request.issuance_id))
        .ok_or_else(|| "Aethel claim names an unknown issuance".to_string())?;
    let series = state
        .aethel
        .series
        .get(&id_key(&issuance.series_id))
        .ok_or_else(|| "Aethel claim issuance has no series".to_string())?;
    let stream = state
        .aethel
        .stream(&series.stream_id)
        .map_err(|e| e.to_string())?;
    let context = &instruction.context;
    if context.operation != ReceivableOperation::ClaimGuarantee
        || context.aethel_domain_id != series.aethel_domain_id
        || context.request_id != issuance.request_id
        || context.action_id != request.claim_id
        || context.series_id != issuance.series_id
        || context.stream_id != series.stream_id
        || context.stream_state_version != stream.state.version
        || context.before_stream_state_root != stream.state.root().map_err(|e| e.to_string())?
        || context.after_stream_state_root != context.before_stream_state_root
        || context.eligible_commitment != stream.state.eligible_commitment
        || context.before_pledged_commitment != stream.state.pledged_commitment
        || context.after_pledged_commitment != stream.state.pledged_commitment
        || context.receivable_note_id != issuance.note_id
        || context.settlement_asset_id != stream.state.settlement_asset_id
        || context.credit != credit_reference(state, issuance.credit_decision_id)?
        || context.guarantee != guarantee_reference(state, Some(request.guarantee_id))?
        || !context.funding.is_absent()
        || context.policy_digest != series.policy.claim_policy_digest
        || context.relation_proof_digest != request.relation_proof_digest
        || context.operation_nullifier != request.claim_id
        || context.before_aethel_root != state.aethel.root().map_err(|e| e.to_string())?
        || instruction
            .instruction
            .amount_commitment
            .compress()
            .to_bytes()
            != request.claim_amount_commitment
        || instruction
            .instruction
            .price_commitment
            .compress()
            .to_bytes()
            != request.claim_amount_commitment
        || instruction.instruction.payee_handle.compress().to_bytes()
            != request.recovery_recipient_commitment
    {
        return Err("Aethel guarantee claim and zkPI bindings differ".into());
    }
    Ok(())
}

fn verify_receivable_zkpi(
    state: &State,
    raw: &[u8],
    timestamp: u64,
) -> Result<ReceivableInstruction, String> {
    let instruction = receivable_wire::decode(raw)
        .map_err(|error| format!("streaming-receivable zkPI wire is invalid: {error:?}"))?;
    let context = &instruction.context;
    let verifier = state
        .settlement_verifiers
        .get(&id_key(&settlement_verifier_key(
            context.venue_id,
            context.verifier_epoch,
        )))
        .ok_or_else(|| "streaming-receivable zkPI has no governance-pinned verifier".to_string())?;
    if verifier.defmi_id != context.defmi_id
        || timestamp < verifier.valid_from
        || timestamp > verifier.valid_until
    {
        return Err("streaming-receivable verifier is outside its DeFMI epoch".into());
    }
    let public = frost::keys::PublicKeyPackage::deserialize(&verifier.frost_public_package)
        .map_err(|_| "streaming-receivable FROST package is invalid".to_string())?;
    let bounds = Bounds {
        amount_bits: usize::from(verifier.amount_bits),
        price_bits: usize::from(verifier.price_bits),
        max_horizon: verifier.max_horizon,
    };
    Venue::new(Pedersen::new(b"qomm:defmi:v1"), &bounds, public)
        .require_threshold_ranges()
        .verify_receivable(&instruction, timestamp)
        .map_err(|error| format!("streaming-receivable zkPI verification failed: {error}"))?;
    Ok(instruction)
}

fn credit_reference(
    state: &State,
    decision_id: Option<[u8; 32]>,
) -> Result<ProviderReference, String> {
    let Some(decision_id) = decision_id else {
        return Ok(ProviderReference::absent());
    };
    let decision = state
        .aethel
        .credit_decisions
        .get(&id_key(&decision_id))
        .ok_or_else(|| "zkPI names an unknown Aethel credit decision".to_string())?;
    Ok(ProviderReference {
        artifact_id: decision_id,
        provider_id: decision.provider_id,
        backing_id: credit_backing_id(decision),
    })
}

fn guarantee_reference(
    state: &State,
    guarantee_id: Option<[u8; 32]>,
) -> Result<ProviderReference, String> {
    let Some(guarantee_id) = guarantee_id else {
        return Ok(ProviderReference::absent());
    };
    let guarantee = state
        .aethel
        .guarantees
        .get(&id_key(&guarantee_id))
        .ok_or_else(|| "zkPI names an unknown Aethel guarantee".to_string())?;
    Ok(ProviderReference {
        artifact_id: guarantee_id,
        provider_id: guarantee.provider_id,
        backing_id: guarantee.defmi_hold_id,
    })
}

fn funding_reference(
    state: &State,
    quote_id: Option<[u8; 32]>,
) -> Result<ProviderReference, String> {
    let Some(quote_id) = quote_id else {
        return Ok(ProviderReference::absent());
    };
    let quote = state
        .aethel
        .funding_quotes
        .get(&id_key(&quote_id))
        .ok_or_else(|| "zkPI names an unknown Aethel funding quote".to_string())?;
    Ok(ProviderReference {
        artifact_id: quote_id,
        provider_id: quote.provider_id,
        backing_id: quote.cash_reservation_id,
    })
}

fn instruction_wire_digest(instruction: &ReceivableInstruction) -> [u8; 32] {
    Sha256::digest(receivable_wire::encode(instruction)).into()
}

fn credit_backing_id(decision: &CreditDecision) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"AETHEL:CREDIT-BACKING:v1");
    hash.update(decision.model_digest);
    hash.update(decision.policy_digest);
    hash.update(decision.relation_proof_digest);
    hash.finalize().into()
}

fn require_active_asset(state: &State, asset_id: [u8; 32], name: &str) -> Result<(), String> {
    if !state
        .assets
        .get(&id_key(&asset_id))
        .is_some_and(|asset| asset.active)
    {
        return Err(format!("{name} is inactive or unknown"));
    }
    Ok(())
}

fn require_active_participant(
    state: &State,
    participant_id: [u8; 32],
) -> Result<&qomm_defmi::participant::ParticipantRecord, String> {
    let participant = state
        .participant_registry
        .participants
        .get(&id_key(&participant_id))
        .ok_or_else(|| "Aethel references an unknown DeFMI participant".to_string())?;
    if participant.status != ParticipantStatus::Active {
        return Err("Aethel references an inactive DeFMI participant".into());
    }
    Ok(participant)
}

pub(super) fn ensure_global_operation_unused(
    state: &State,
    operation_id: [u8; 32],
) -> Result<(), String> {
    if operation_id == ZERO || state.operations.contains_key(&id_key(&operation_id)) {
        return Err("Aethel operation identifier was already used".into());
    }
    Ok(())
}

pub(super) fn record_global_operation(
    state: &mut State,
    operation_id: [u8; 32],
    statement: [u8; 32],
) {
    state.operations.insert(id_key(&operation_id), statement);
}

fn base64_field(params: &Map<String, Value>, name: &str) -> Result<Vec<u8>, String> {
    let encoded = params
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{name} must be base64"))?;
    BASE64
        .decode(encoded)
        .map_err(|_| format!("{name} is not valid base64"))
}

fn require_aethel_artifact_keys(params: &Map<String, Value>) -> Result<(), String> {
    if params.contains_key("subjectProof") {
        require_keys(
            params,
            &["request", "subjectProof", "approval", "expectedBeforeRoot"],
        )
    } else {
        require_keys(params, &["request", "approval", "expectedBeforeRoot"])
    }
}

/// The holder's DeKYX presentation for exactly this artifact. Verification
/// happens inside `aethel-core` against the DeKYX issuer directory it stores.
fn confidential_subject_proof(
    params: &Map<String, Value>,
) -> Result<Option<AnonymousPresentation>, String> {
    params
        .contains_key("subjectProof")
        .then(|| domain_field(params, "subjectProof"))
        .transpose()
}

pub(super) fn domain_field<T: DeserializeOwned>(
    params: &Map<String, Value>,
    name: &str,
) -> Result<T, String> {
    let mut value = params
        .get(name)
        .cloned()
        .ok_or_else(|| format!("missing {name}"))?;
    normalize_hex(&mut value, None)?;
    serde_json::from_value(value).map_err(|error| format!("invalid {name}: {error}"))
}

/// The public RPC uses hex for binary fields while Aethel's consensus structs
/// use fixed arrays. Only exact 32-byte values and explicitly named signatures
/// are transformed; ordinary enum and policy strings are left untouched.
fn normalize_hex(value: &mut Value, field_name: Option<&str>) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (name, child) in map.iter_mut() {
                normalize_hex(child, Some(name))?;
            }
        }
        Value::Array(values) => {
            for child in values {
                normalize_hex(child, field_name)?;
            }
        }
        Value::String(encoded)
            if (encoded.len() == 64
                || field_name
                    .is_some_and(|name| name.to_ascii_lowercase().contains("signature"))) =>
        {
            let bytes = hex::decode(&*encoded)
                .map_err(|_| format!("{} is not hexadecimal", field_name.unwrap_or("field")))?;
            if encoded.len() == 64 && bytes.len() != 32 {
                return Err(format!(
                    "{} must be 32 bytes",
                    field_name.unwrap_or("field")
                ));
            }
            *value = Value::Array(
                bytes
                    .into_iter()
                    .map(|byte| Value::Number(Number::from(byte)))
                    .collect(),
            );
        }
        _ => {}
    }
    Ok(())
}
