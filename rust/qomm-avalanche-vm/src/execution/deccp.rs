//! Avalanche adapter for the DeCCP clearing book that holds Aethel guarantee
//! capacity.
//!
//! DeCCP owns clearing membership, hidden guarantee capacity, reservation,
//! binding, release, and claim consumption. DeFMI (this VM's facility, hold,
//! and note records) stays authoritative for what is actually locked or
//! settled, and DeKYX supplies the only identity evidence DeCCP ever sees: a
//! subject line, never a legal entity. This module is the port layer between
//! the three; the semantic rules live in `deccp-core` and `deccp-aethel`.

use aethel_core::{
    dekyx_core::{
        AnonymousPresentation, EligibilityProvider, EligibilityRequirement, PresentationContext,
        SubjectKind,
    },
    ProviderCapability,
};
use deccp_core::{
    confidential_guarantee_facility_approval_digest, AuthoritySet, CcpCapitalization, ClearingBook,
    CollateralLot, ConfidentialGuaranteeClaimRequest, ConfidentialGuaranteeFacility,
    ConfidentialGuaranteeHold, ConfidentialGuaranteeReleaseRequest,
    ConfidentialGuaranteeReservation, DeFmiPort, DefmiSettlementReceipt, EligibilityAttestation,
    EligibilityPort, GuaranteeFacility, GuaranteeReservation, ParticipantAdmission,
    QuorumApproval as DeccpQuorumApproval, VerifiedAdmission, ZERO,
};
use qomm_defmi::facility::QuorumAuthorizer;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::state::{id_key, ClearingState, CreditFacilityRecord, State};

use super::aethel::{domain_field, ensure_global_operation_unused, record_global_operation};
use super::{authorize, require_keys};

const CLEARING_BOOK_DOMAIN: &[u8] = b"AETHEL-DECCP:CLEARING-BOOK:v1";
const MEMBERSHIP_SCOPE_DOMAIN: &[u8] = b"AETHEL-DECCP:CLEARING-MEMBERSHIP-SCOPE:v1";
const MEMBERSHIP_AUDIENCE_DOMAIN: &[u8] = b"AETHEL-DECCP:CLEARING-MEMBERSHIP-AUDIENCE:v1";
const ADMISSION_ACTION_DOMAIN: &[u8] = b"AETHEL-DECCP:ACTION:ADMISSION:v1";
const ADMISSION_REQUEST_DOMAIN: &[u8] = b"AETHEL-DECCP:ADMISSION-REQUEST:v1";
const CAPITAL_LOCK_DOMAIN: &[u8] = b"AETHEL-DECCP:CCP-CAPITAL-LOCK:v1";
const DEFAULT_FUND_LOCK_DOMAIN: &[u8] = b"AETHEL-DECCP:DEFAULT-FUND-LOCK:v1";
const FACILITY_STATE_DOMAIN: &[u8] = b"AETHEL-DECCP:FACILITY-STATE:v1";
const FACILITY_TRANSITION_DOMAIN: &[u8] = b"AETHEL-DECCP:FACILITY-TRANSITION:v1";

/// Kinds of hidden-capacity transition the VM can attest from DeFMI records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FacilityTransition {
    Reserve,
    Release,
    Claim,
}

impl FacilityTransition {
    fn tag(self) -> u8 {
        match self {
            Self::Reserve => 1,
            Self::Release => 2,
            Self::Claim => 3,
        }
    }
}

/// Opens the clearing book: the DeCCP authority set and the CCP's own capital.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ClearingBookRegistration {
    pub operation_id: [u8; 32],
    pub authorities: AuthoritySet,
    pub capitalization: CcpCapitalization,
}

impl ClearingBookRegistration {
    pub fn statement(&self) -> Result<[u8; 32], String> {
        if self.operation_id == ZERO {
            return Err("DeCCP clearing book registration has no operation id".into());
        }
        self.authorities
            .validate()
            .map_err(|error| error.to_string())?;
        let encoded = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        let mut hash = Sha256::new();
        hash.update(CLEARING_BOOK_DOMAIN);
        hash.update((encoded.len() as u64).to_be_bytes());
        hash.update(encoded);
        Ok(hash.finalize().into())
    }
}

/// Registers a confidential guarantee facility with DeCCP over a DeFMI credit
/// facility this VM holds. The DeCCP authorities approve it separately from
/// the VM committee.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuaranteeFacilityRegistration {
    pub operation_id: [u8; 32],
    pub facility: ConfidentialGuaranteeFacility,
}

pub(super) fn open_clearing_book(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["request", "approval", "expectedBeforeRoot"])?;
    let request: ClearingBookRegistration = domain_field(params, "request")?;
    let statement = request.statement()?;
    authorize(state, params, statement, authorizer)?;
    ensure_global_operation_unused(state, request.operation_id)?;
    if state.deccp.is_some() {
        return Err("this VM already hosts a DeCCP clearing book".into());
    }
    let book = ClearingBook::new(
        request.authorities,
        request.capitalization,
        &VmDefmiPort { state },
        timestamp,
    )
    .map_err(|error| format!("DeCCP refused the clearing book: {error}"))?;
    state.deccp = Some(ClearingState { book });
    record_global_operation(state, request.operation_id, statement);
    Ok(statement)
}

/// Admits an Aethel guarantor provider as a DeCCP clearing member. DeCCP
/// records the DeKYX subject line the holder proved for exactly this
/// admission, the DeFMI default-fund lock, and nothing about who the member
/// is in law.
pub(super) fn admit_member(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &[
            "request",
            "subjectProof",
            "deccpApproval",
            "approval",
            "expectedBeforeRoot",
        ],
    )?;
    let request: ParticipantAdmission = domain_field(params, "request")?;
    let statement = request
        .statement_digest()
        .map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    ensure_global_operation_unused(state, request.operation_id)?;
    let presentation: AnonymousPresentation = domain_field(params, "subjectProof")?;
    let deccp_approval: DeccpQuorumApproval = domain_field(params, "deccpApproval")?;
    let provider = state
        .aethel
        .provider(&request.participant_id)
        .map_err(|error| error.to_string())?;
    if !provider.has(ProviderCapability::Guarantor, timestamp)
        || provider.participant_id != request.settlement_participant_id
    {
        return Err(
            "DeCCP member must be an active Aethel guarantor provider of the named DeFMI participant"
                .into(),
        );
    }
    let mut book = clearing_book(state)?.clone();
    let eligibility = DeKyxAdmissionPort {
        state,
        context: membership_context(&book, &request),
        presentation: &presentation,
        admission: &request,
    };
    book.admit_participant(
        request.clone(),
        &eligibility,
        &deccp_approval,
        &VmDefmiPort { state },
        timestamp,
    )
    .map_err(|error| format!("DeCCP refused the admission: {error}"))?;
    state.deccp = Some(ClearingState { book });
    record_global_operation(state, request.operation_id, statement);
    Ok(statement)
}

pub(super) fn register_guarantee_facility(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &["request", "deccpApproval", "approval", "expectedBeforeRoot"],
    )?;
    let request: GuaranteeFacilityRegistration = domain_field(params, "request")?;
    let statement =
        confidential_guarantee_facility_approval_digest(&request.operation_id, &request.facility);
    authorize(state, params, statement, authorizer)?;
    ensure_global_operation_unused(state, request.operation_id)?;
    let deccp_approval: DeccpQuorumApproval = domain_field(params, "deccpApproval")?;
    if request.facility.facility_id != request.facility.defmi_facility_id {
        return Err("DeCCP facility id must be the DeFMI facility id it is backed by".into());
    }
    let mut book = clearing_book(state)?.clone();
    book.register_confidential_guarantee_facility(
        request.operation_id,
        request.facility,
        &deccp_approval,
        &VmDefmiPort { state },
        timestamp,
    )
    .map_err(|error| format!("DeCCP refused the guarantee facility: {error}"))?;
    state.deccp = Some(ClearingState { book });
    record_global_operation(state, request.operation_id, statement);
    Ok(statement)
}

pub(super) fn clearing_book(state: &State) -> Result<&ClearingBook, String> {
    state
        .deccp
        .as_ref()
        .map(|clearing| &clearing.book)
        .ok_or_else(|| "this VM hosts no DeCCP clearing book".to_string())
}

/// The DeKYX scope every clearing-membership credential is issued for.
pub(crate) fn membership_scope_digest() -> [u8; 32] {
    Sha256::digest(MEMBERSHIP_SCOPE_DOMAIN).into()
}

/// Exact DeKYX context a would-be member presents against: this clearing
/// book (named by its capital lock), the admission action, and the admission
/// itself (who is admitted, under which policy, with which default fund),
/// with the operation id as the challenge. The evidence digest and subject
/// line are what the presentation produces, so they are not in the request
/// digest; DeCCP compares them against the attestation instead.
pub(crate) fn membership_context(
    book: &ClearingBook,
    admission: &ParticipantAdmission,
) -> PresentationContext {
    let (capital_lock, _, _) = book.ccp_capital_lock();
    let mut audience = Sha256::new();
    audience.update(MEMBERSHIP_AUDIENCE_DOMAIN);
    audience.update(capital_lock);
    let mut request = Sha256::new();
    request.update(ADMISSION_REQUEST_DOMAIN);
    request.update(admission.participant_id);
    request.update(admission.settlement_participant_id);
    request.update(admission.eligibility.provider_id);
    request.update(admission.eligibility.policy_digest);
    request.update(admission.eligibility.valid_until.to_be_bytes());
    request.update(admission.default_fund_contribution.to_be_bytes());
    request.update(admission.default_fund_defmi_lock_id);
    request.update(admission.default_fund_proof_digest);
    request.update(admission.admitted_at.to_be_bytes());
    PresentationContext {
        scope_digest: membership_scope_digest(),
        audience_digest: audience.finalize().into(),
        action_digest: Sha256::digest(ADMISSION_ACTION_DOMAIN).into(),
        request_digest: request.finalize().into(),
        challenge_nonce: admission.operation_id,
        valid_until: admission.eligibility.valid_until,
    }
}

/// Lock tag a cash note must carry to count as the CCP's own capital.
pub(crate) fn capital_lock_tag() -> [u8; 32] {
    Sha256::digest(CAPITAL_LOCK_DOMAIN).into()
}

/// Lock tag a cash note must carry to count as one member's default fund.
pub(crate) fn default_fund_lock_tag(participant_id: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DEFAULT_FUND_LOCK_DOMAIN);
    hash.update(participant_id);
    hash.finalize().into()
}

/// The hidden-capacity state DeCCP starts a facility at: the DeFMI facility's
/// committed cap and collateral, before any Aethel reservation.
pub(crate) fn initial_facility_state(
    defmi_facility_id: [u8; 32],
    record: &CreditFacilityRecord,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(FACILITY_STATE_DOMAIN);
    hash.update(defmi_facility_id);
    hash.update(record.cap_commitment);
    hash.update(record.collateral_commitment);
    hash.finalize().into()
}

/// The next hidden-capacity state after one DeFMI-attested transition. The
/// chain carries only commitments and DeFMI sequence numbers, never an
/// amount, so DeCCP's compare-and-swap works on it without opening anything.
pub(crate) fn next_facility_state(
    previous: [u8; 32],
    transition: FacilityTransition,
    defmi_hold_id: [u8; 32],
    amount_commitment: [u8; 32],
    defmi_sequence: u64,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(FACILITY_TRANSITION_DOMAIN);
    hash.update(previous);
    hash.update([transition.tag()]);
    hash.update(defmi_hold_id);
    hash.update(amount_commitment);
    hash.update(defmi_sequence.to_be_bytes());
    hash.finalize().into()
}

/// DeKYX verification for one admission. DeCCP hands over the attestation it
/// was given; this port checks that the holder's presentation, verified
/// against the issuer directory Aethel persists, proves exactly that subject
/// line for exactly this admission, and returns nothing else.
struct DeKyxAdmissionPort<'a> {
    state: &'a State,
    /// The exact context for this admission on this clearing book.
    context: PresentationContext,
    presentation: &'a AnonymousPresentation,
    admission: &'a ParticipantAdmission,
}

impl EligibilityPort for DeKyxAdmissionPort<'_> {
    fn verify(
        &self,
        evidence: &EligibilityAttestation,
        now: u64,
    ) -> Result<VerifiedAdmission, String> {
        let credential = &self.presentation.credential;
        if evidence != &self.admission.eligibility {
            return Err("DeCCP asked about another attestation than the admission carries".into());
        }
        if credential.issuer_id != evidence.provider_id {
            return Err("presentation names another DeKYX issuer than the attestation".into());
        }
        if !self
            .state
            .aethel
            .provider(&evidence.provider_id)
            .map_err(|error| error.to_string())?
            .has(ProviderCapability::CredentialIssuer, now)
        {
            return Err(
                "DeKYX issuer is not vouched for by an active credential-issuer provider".into(),
            );
        }
        let directory = &self.state.aethel.credential_issuers;
        let issuer = directory
            .issuer(&credential.issuer_id, credential.issuer_key_epoch)
            .map_err(|error| error.to_string())?;
        let context = self.context.clone();
        let requirement = EligibilityRequirement {
            issuer_id: credential.issuer_id,
            issuer_key_epoch: credential.issuer_key_epoch,
            issuer_namespace_digest: issuer.namespace_digest,
            subject_kind: SubjectKind::LegalEntity,
            scope_digest: context.scope_digest,
            policy_digest: evidence.policy_digest,
            required_qualifications: Vec::new(),
        };
        let verified = directory
            .verifier(&credential.issuer_id, credential.issuer_key_epoch)
            .map_err(|error| error.to_string())?
            .verify_eligibility(&requirement, &context, self.presentation, now)
            .map_err(|error| format!("DeKYX rejected the membership evidence: {error}"))?;
        let evidence_digest = self
            .presentation
            .digest()
            .map_err(|error| error.to_string())?;
        if verified.subject_line_id != evidence.subject_line_id
            || verified.policy_digest != evidence.policy_digest
            || verified.valid_until < evidence.valid_until
            || evidence_digest != evidence.evidence_digest
        {
            return Err("DeKYX evidence does not prove the attested subject line".into());
        }
        Ok(VerifiedAdmission {
            provider_id: evidence.provider_id,
            subject_line_id: verified.subject_line_id,
            policy_digest: verified.policy_digest,
            evidence_digest,
            valid_until: evidence.valid_until,
        })
    }
}

/// DeFMI evidence for DeCCP, read from this VM's authoritative records. Every
/// method verifies a record that DeFMI itself created; none trusts an
/// identifier on its own, and none opens a commitment.
pub(super) struct VmDefmiPort<'a> {
    pub state: &'a State,
}

impl VmDefmiPort<'_> {
    fn cash_note_lock(
        &self,
        note_id: [u8; 32],
        expected_lock: [u8; 32],
        proof_digest: [u8; 32],
        what: &str,
    ) -> Result<(), String> {
        let note = self
            .state
            .notes
            .get(&id_key(&note_id))
            .ok_or_else(|| format!("{what} names no DeFMI note"))?;
        let asset = self
            .state
            .assets
            .get(&id_key(&note.asset_id))
            .ok_or_else(|| format!("{what} note has no asset"))?;
        if !asset.active || asset.kind != "cash" {
            return Err(format!(
                "{what} must be a note on an active DeFMI cash rail"
            ));
        }
        if note.lock_id != expected_lock {
            return Err(format!("{what} note is not locked for that purpose"));
        }
        if proof_digest != note.value_commitment {
            return Err(format!(
                "{what} proof digest is not the locked note's value commitment"
            ));
        }
        Ok(())
    }

    fn facility_record(
        &self,
        facility: &ConfidentialGuaranteeFacility,
    ) -> Result<&CreditFacilityRecord, String> {
        let record = self
            .state
            .credit_facilities
            .get(&id_key(&facility.defmi_facility_id))
            .ok_or_else(|| "DeCCP facility names an unknown DeFMI credit facility".to_string())?;
        let provider = self
            .state
            .aethel
            .provider(&facility.guarantor_id)
            .map_err(|error| error.to_string())?;
        if provider.defmi_guarantor_id != Some(record.guarantor_id)
            || facility.facility_id != facility.defmi_facility_id
            || record.rail_asset_id != facility.settlement_asset_id
            || record.cap_commitment != facility.capacity_commitment
            || record.beneficiary_commitment != facility.beneficiary_subject_line_id
        {
            return Err("DeCCP facility does not describe its DeFMI credit facility".into());
        }
        Ok(record)
    }

    fn hold_transition(
        &self,
        facility: &ConfidentialGuaranteeFacility,
        transition: HoldTransition<'_>,
    ) -> Result<(), String> {
        self.facility_record(facility)?;
        let hold = self
            .state
            .credit_holds
            .get(&id_key(&transition.defmi_hold_id))
            .ok_or_else(|| "DeCCP hold names an unknown DeFMI hold".to_string())?;
        if hold.facility_id != facility.defmi_facility_id
            || hold.amount_commitment != transition.coverage_commitment
            || hold.status != transition.expected_status
            || hold.settlement_digest != transition.expected_settlement
        {
            return Err(format!(
                "DeFMI hold is not {} on this facility for this coverage",
                transition.expected_status
            ));
        }
        let sequence = match transition.kind {
            FacilityTransition::Reserve => hold.created_sequence,
            FacilityTransition::Release | FacilityTransition::Claim => hold.updated_sequence,
        };
        if transition.after_state
            != next_facility_state(
                transition.expected_state,
                transition.kind,
                transition.defmi_hold_id,
                transition.coverage_commitment,
                sequence,
            )
        {
            return Err("DeCCP after-state does not follow from the DeFMI hold transition".into());
        }
        Ok(())
    }
}

/// One DeFMI hold transition DeCCP asks the VM to attest.
struct HoldTransition<'a> {
    kind: FacilityTransition,
    defmi_hold_id: [u8; 32],
    coverage_commitment: [u8; 32],
    expected_status: &'a str,
    expected_settlement: [u8; 32],
    expected_state: [u8; 32],
    after_state: [u8; 32],
}

impl DeFmiPort for VmDefmiPort<'_> {
    fn verify_ccp_capital(
        &self,
        capitalization: &CcpCapitalization,
        now: u64,
    ) -> Result<(), String> {
        if capitalization.valid_until < now {
            return Err("CCP capital lock has expired".into());
        }
        self.cash_note_lock(
            capitalization.defmi_lock_id,
            capital_lock_tag(),
            capitalization.proof_digest,
            "CCP capital",
        )
    }

    fn verify_default_fund(
        &self,
        admission: &ParticipantAdmission,
        _now: u64,
    ) -> Result<(), String> {
        self.cash_note_lock(
            admission.default_fund_defmi_lock_id,
            default_fund_lock_tag(admission.participant_id),
            admission.default_fund_proof_digest,
            "default fund",
        )
    }

    fn verify_collateral_lock(&self, _lot: &CollateralLot, _now: u64) -> Result<(), String> {
        Err("this VM offers no public-value collateral lots".into())
    }

    fn verify_guarantee_facility(
        &self,
        _facility: &GuaranteeFacility,
        _now: u64,
    ) -> Result<(), String> {
        Err("this VM offers only confidential guarantee facilities".into())
    }

    fn verify_guarantee_hold(
        &self,
        _reservation: &GuaranteeReservation,
        _now: u64,
    ) -> Result<(), String> {
        Err("this VM offers only confidential guarantee holds".into())
    }

    fn verify_confidential_guarantee_facility(
        &self,
        facility: &ConfidentialGuaranteeFacility,
        now: u64,
    ) -> Result<(), String> {
        let record = self.facility_record(facility)?;
        if record.status != "active"
            || now < record.valid_from
            || facility.valid_until > record.valid_until
        {
            return Err("DeFMI credit facility is not live for the DeCCP facility window".into());
        }
        if facility.latest_facility_state_digest
            != initial_facility_state(facility.defmi_facility_id, record)
        {
            return Err("DeCCP facility does not start from the DeFMI facility state".into());
        }
        Ok(())
    }

    fn verify_confidential_guarantee_hold(
        &self,
        facility: &ConfidentialGuaranteeFacility,
        reservation: &ConfidentialGuaranteeReservation,
        _now: u64,
    ) -> Result<(), String> {
        let record = self.facility_record(facility)?;
        let hold = self
            .state
            .credit_holds
            .get(&id_key(&reservation.defmi_hold_id))
            .ok_or_else(|| "DeCCP reservation names an unknown DeFMI hold".to_string())?;
        if record.status != "active"
            || record.valid_until < reservation.valid_until
            || hold.expires_at < reservation.valid_until
        {
            return Err("DeFMI facility or hold ends before the DeCCP reservation".into());
        }
        self.hold_transition(
            facility,
            HoldTransition {
                kind: FacilityTransition::Reserve,
                defmi_hold_id: reservation.defmi_hold_id,
                coverage_commitment: reservation.coverage_commitment,
                expected_status: "active",
                expected_settlement: ZERO,
                expected_state: reservation.expected_facility_state_digest,
                after_state: reservation.after_facility_state_digest,
            },
        )
    }

    fn verify_confidential_guarantee_release(
        &self,
        facility: &ConfidentialGuaranteeFacility,
        hold: &ConfidentialGuaranteeHold,
        request: &ConfidentialGuaranteeReleaseRequest,
        now: u64,
    ) -> Result<(), String> {
        if request.receipt.receipt_digest == ZERO || request.receipt.finalized_at > now {
            return Err("DeFMI release receipt is empty or from the future".into());
        }
        self.hold_transition(
            facility,
            HoldTransition {
                kind: FacilityTransition::Release,
                defmi_hold_id: hold.defmi_hold_id,
                coverage_commitment: hold.coverage_commitment,
                expected_status: "released",
                expected_settlement: request.receipt.receipt_digest,
                expected_state: request.expected_facility_state_digest,
                after_state: request.after_facility_state_digest,
            },
        )
    }

    fn verify_confidential_guarantee_claim(
        &self,
        facility: &ConfidentialGuaranteeFacility,
        hold: &ConfidentialGuaranteeHold,
        request: &ConfidentialGuaranteeClaimRequest,
        now: u64,
    ) -> Result<(), String> {
        if request.receipt.receipt_digest == ZERO || request.receipt.finalized_at > now {
            return Err("DeFMI claim receipt is empty or from the future".into());
        }
        self.hold_transition(
            facility,
            HoldTransition {
                kind: FacilityTransition::Claim,
                defmi_hold_id: hold.defmi_hold_id,
                coverage_commitment: hold.coverage_commitment,
                expected_status: "consumed",
                expected_settlement: request.receipt.receipt_digest,
                expected_state: request.expected_facility_state_digest,
                after_state: request.after_facility_state_digest,
            },
        )
    }

    fn verify_guarantee_release(
        &self,
        _expected_context: &[u8; 32],
        _receipt: &DefmiSettlementReceipt,
        _now: u64,
    ) -> Result<(), String> {
        Err("this VM offers only confidential guarantee releases".into())
    }

    fn verify_settlement(
        &self,
        _expected_context: &[u8; 32],
        _receipt: &DefmiSettlementReceipt,
        _now: u64,
    ) -> Result<(), String> {
        Err("this VM settles no DeCCP netting cycle or default waterfall".into())
    }
}
