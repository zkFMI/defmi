use std::collections::BTreeSet;

use defmi::{
    facility::{QuorumAuthorizer, ReservationRole},
    participant::{
        AccountBinding, AccountBindingKind, EntityApproval, KeyPurpose, MandateControl,
        MandateControlKind, MandateReservation, MandateReservationTransition, MandateRole,
        MandateStatus, MpcService, MpcServiceKind, MpcServiceMember, ParticipantControl,
        ParticipantControlKind, ParticipantKeys, ParticipantRecord, ParticipantRole,
        ParticipantServiceBinding, ParticipantStatus, PurposeKey, RegisterParticipant,
        RegistryConfiguration, ReservationStatus, ReservationTransitionKind, RotateParticipantKey,
        ServiceStatus, StandingMandate,
    },
};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::state::State;

use super::{authorize, field, hex_array, require_keys};

const COMPOSITE_RESERVATION_DOMAIN: &[u8] = b"QOMM:DEFMI:PARTICIPANT-PRODUCT-RESERVATION:v1";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PurposeKeyDto {
    public_key: String,
    pq_public_key: String,
    epoch: u64,
}

impl PurposeKeyDto {
    fn domain(self, name: &str) -> Result<PurposeKey, String> {
        Ok(PurposeKey {
            public_key: hex_array(&self.public_key, &format!("{name}.publicKey"))?,
            pq_public_key: hex::decode(self.pq_public_key)
                .map_err(|_| format!("{name}.pqPublicKey is invalid hex"))?,
            epoch: self.epoch,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ParticipantKeysDto {
    admin: PurposeKeyDto,
    settlement: PurposeKeyDto,
    quote: PurposeKeyDto,
    mpc_input: PurposeKeyDto,
    emergency: PurposeKeyDto,
}

impl ParticipantKeysDto {
    fn domain(self, name: &str) -> Result<ParticipantKeys, String> {
        Ok(ParticipantKeys {
            admin: self.admin.domain(&format!("{name}.admin"))?,
            settlement: self.settlement.domain(&format!("{name}.settlement"))?,
            quote: self.quote.domain(&format!("{name}.quote"))?,
            mpc_input: self.mpc_input.domain(&format!("{name}.mpcInput"))?,
            emergency: self.emergency.domain(&format!("{name}.emergency"))?,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryConfigurationDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "domainID")]
    domain_id: String,
    template_digest: String,
    schema_digest: String,
    template_version: u32,
}

impl RegistryConfigurationDto {
    fn domain(self) -> Result<RegistryConfiguration, String> {
        Ok(RegistryConfiguration {
            operation_id: hex_array(&self.operation_id, "configuration.operationID")?,
            domain_id: hex_array(&self.domain_id, "configuration.domainID")?,
            template_digest: hex_array(&self.template_digest, "configuration.templateDigest")?,
            schema_digest: hex_array(&self.schema_digest, "configuration.schemaDigest")?,
            template_version: self.template_version,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ParticipantRecordDto {
    #[serde(rename = "participantID")]
    participant_id: String,
    legal_entity_credential_commitment: String,
    #[serde(rename = "credentialIssuerID")]
    credential_issuer_id: String,
    credential_scheme_digest: String,
    jurisdiction: String,
    roles: Vec<ParticipantRole>,
    keys: ParticipantKeysDto,
    policy_digest: String,
    valid_from: u64,
    valid_until: u64,
}

impl ParticipantRecordDto {
    fn domain(self) -> Result<ParticipantRecord, String> {
        let role_count = self.roles.len();
        let roles = self.roles.into_iter().collect::<BTreeSet<_>>();
        if roles.len() != role_count {
            return Err("participant.roles contains duplicates".into());
        }
        Ok(ParticipantRecord {
            participant_id: hex_array(&self.participant_id, "participant.participantID")?,
            legal_entity_credential_commitment: hex_array(
                &self.legal_entity_credential_commitment,
                "participant.legalEntityCredentialCommitment",
            )?,
            credential_issuer_id: hex_array(
                &self.credential_issuer_id,
                "participant.credentialIssuerID",
            )?,
            credential_scheme_digest: hex_array(
                &self.credential_scheme_digest,
                "participant.credentialSchemeDigest",
            )?,
            jurisdiction: self.jurisdiction,
            roles,
            keys: self.keys.domain("participant.keys")?,
            policy_digest: hex_array(&self.policy_digest, "participant.policyDigest")?,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            sequence: 0,
            status: ParticipantStatus::Active,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegisterParticipantDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    participant: ParticipantRecordDto,
}

impl RegisterParticipantDto {
    fn domain(self) -> Result<RegisterParticipant, String> {
        Ok(RegisterParticipant {
            operation_id: hex_array(&self.operation_id, "registration.operationID")?,
            participant: self.participant.domain()?,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ParticipantControlDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "participantID")]
    participant_id: String,
    expected_sequence: u64,
    kind: ParticipantControlKind,
    reason_digest: String,
}

impl ParticipantControlDto {
    fn domain(self) -> Result<ParticipantControl, String> {
        Ok(ParticipantControl {
            operation_id: hex_array(&self.operation_id, "control.operationID")?,
            participant_id: hex_array(&self.participant_id, "control.participantID")?,
            expected_sequence: self.expected_sequence,
            kind: self.kind,
            reason_digest: hex_array(&self.reason_digest, "control.reasonDigest")?,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeyRotationDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "participantID")]
    participant_id: String,
    expected_sequence: u64,
    purpose: KeyPurpose,
    new_key: PurposeKeyDto,
}

impl KeyRotationDto {
    fn domain(self) -> Result<RotateParticipantKey, String> {
        Ok(RotateParticipantKey {
            operation_id: hex_array(&self.operation_id, "rotation.operationID")?,
            participant_id: hex_array(&self.participant_id, "rotation.participantID")?,
            expected_sequence: self.expected_sequence,
            purpose: self.purpose,
            new_key: self.new_key.domain("rotation.newKey")?,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EntityApprovalDto {
    #[serde(rename = "participantID")]
    participant_id: String,
    key_purpose: KeyPurpose,
    key_epoch: u64,
    statement: String,
    signature: String,
}

impl EntityApprovalDto {
    fn domain(self) -> Result<EntityApproval, String> {
        Ok(EntityApproval {
            participant_id: hex_array(&self.participant_id, "entityApproval.participantID")?,
            key_purpose: self.key_purpose,
            key_epoch: self.key_epoch,
            statement: hex_array(&self.statement, "entityApproval.statement")?,
            signature: hex::decode(&self.signature)
                .map_err(|_| "entityApproval.signature is not hex".to_string())?,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MpcServiceMemberDto {
    #[serde(rename = "nodeID")]
    node_id: String,
    #[serde(rename = "operatorParticipantID")]
    operator_participant_id: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MpcServiceDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "serviceID")]
    service_id: String,
    kind: MpcServiceKind,
    program_digest: String,
    schema_digest: String,
    committee_epoch: u64,
    threshold: u16,
    members: Vec<MpcServiceMemberDto>,
    valid_from: u64,
    valid_until: u64,
}

impl MpcServiceDto {
    fn domain(self) -> Result<MpcService, String> {
        let mut members = self
            .members
            .into_iter()
            .map(|member| {
                Ok(MpcServiceMember {
                    node_id: hex_array(&member.node_id, "service.members.nodeID")?,
                    operator_participant_id: hex_array(
                        &member.operator_participant_id,
                        "service.members.operatorParticipantID",
                    )?,
                    public_key: hex_array(&member.public_key, "service.members.publicKey")?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        members.sort_by_key(|member| member.node_id);
        Ok(MpcService {
            operation_id: hex_array(&self.operation_id, "service.operationID")?,
            service_id: hex_array(&self.service_id, "service.serviceID")?,
            kind: self.kind,
            program_digest: hex_array(&self.program_digest, "service.programDigest")?,
            schema_digest: hex_array(&self.schema_digest, "service.schemaDigest")?,
            committee_epoch: self.committee_epoch,
            threshold: self.threshold,
            members,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            sequence: 0,
            status: ServiceStatus::Active,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccountBindingDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "bindingID")]
    binding_id: String,
    #[serde(rename = "participantID")]
    participant_id: String,
    account_commitment: String,
    #[serde(rename = "assetID")]
    asset_id: String,
    kind: AccountBindingKind,
    control_proof_digest: String,
    valid_from: u64,
    valid_until: u64,
    expected_participant_sequence: u64,
}

impl AccountBindingDto {
    fn domain(self) -> Result<AccountBinding, String> {
        Ok(AccountBinding {
            operation_id: hex_array(&self.operation_id, "binding.operationID")?,
            binding_id: hex_array(&self.binding_id, "binding.bindingID")?,
            participant_id: hex_array(&self.participant_id, "binding.participantID")?,
            account_commitment: hex_array(&self.account_commitment, "binding.accountCommitment")?,
            asset_id: hex_array(&self.asset_id, "binding.assetID")?,
            kind: self.kind,
            control_proof_digest: hex_array(
                &self.control_proof_digest,
                "binding.controlProofDigest",
            )?,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            expected_participant_sequence: self.expected_participant_sequence,
            sequence: 0,
            active: true,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceBindingDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "bindingID")]
    binding_id: String,
    #[serde(rename = "participantID")]
    participant_id: String,
    #[serde(rename = "serviceID")]
    service_id: String,
    service_epoch: u64,
    input_public_key: String,
    capability_digest: String,
    valid_from: u64,
    valid_until: u64,
    expected_participant_sequence: u64,
}

impl ServiceBindingDto {
    fn domain(self) -> Result<ParticipantServiceBinding, String> {
        Ok(ParticipantServiceBinding {
            operation_id: hex_array(&self.operation_id, "binding.operationID")?,
            binding_id: hex_array(&self.binding_id, "binding.bindingID")?,
            participant_id: hex_array(&self.participant_id, "binding.participantID")?,
            service_id: hex_array(&self.service_id, "binding.serviceID")?,
            service_epoch: self.service_epoch,
            input_public_key: hex_array(&self.input_public_key, "binding.inputPublicKey")?,
            capability_digest: hex_array(&self.capability_digest, "binding.capabilityDigest")?,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            expected_participant_sequence: self.expected_participant_sequence,
            sequence: 0,
            active: true,
        })
    }
}

fn canonical_ids(values: Vec<String>, name: &str) -> Result<Vec<[u8; 32]>, String> {
    let original_len = values.len();
    let mut ids = values
        .into_iter()
        .enumerate()
        .map(|(index, value)| hex_array(&value, &format!("{name}[{index}]")))
        .collect::<Result<Vec<_>, _>>()?;
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != original_len {
        return Err(format!("{name} contains duplicates"));
    }
    Ok(ids)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StandingMandateDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "mandateID")]
    mandate_id: String,
    #[serde(rename = "participantID")]
    participant_id: String,
    #[serde(rename = "serviceID")]
    service_id: String,
    #[serde(rename = "serviceBindingID")]
    service_binding_id: String,
    role: MandateRole,
    #[serde(rename = "accountBindingIDs")]
    account_binding_ids: Vec<String>,
    #[serde(rename = "permittedAssetIDs")]
    permitted_asset_ids: Vec<String>,
    #[serde(rename = "permittedDestinationDomains")]
    permitted_destination_domains: Vec<String>,
    limit_commitment: String,
    limit_policy_digest: String,
    settlement_policy_digest: String,
    max_active_reservations: u32,
    valid_from: u64,
    valid_until: u64,
    expected_participant_sequence: u64,
    automatic_settlement: bool,
}

impl StandingMandateDto {
    fn domain(self) -> Result<StandingMandate, String> {
        Ok(StandingMandate {
            operation_id: hex_array(&self.operation_id, "mandate.operationID")?,
            mandate_id: hex_array(&self.mandate_id, "mandate.mandateID")?,
            participant_id: hex_array(&self.participant_id, "mandate.participantID")?,
            service_id: hex_array(&self.service_id, "mandate.serviceID")?,
            service_binding_id: hex_array(&self.service_binding_id, "mandate.serviceBindingID")?,
            role: self.role,
            account_binding_ids: canonical_ids(
                self.account_binding_ids,
                "mandate.accountBindingIDs",
            )?,
            permitted_asset_ids: canonical_ids(
                self.permitted_asset_ids,
                "mandate.permittedAssetIDs",
            )?,
            permitted_destination_domains: canonical_ids(
                self.permitted_destination_domains,
                "mandate.permittedDestinationDomains",
            )?,
            limit_commitment: hex_array(&self.limit_commitment, "mandate.limitCommitment")?,
            limit_policy_digest: hex_array(&self.limit_policy_digest, "mandate.limitPolicyDigest")?,
            settlement_policy_digest: hex_array(
                &self.settlement_policy_digest,
                "mandate.settlementPolicyDigest",
            )?,
            max_active_reservations: self.max_active_reservations,
            active_reservations: 0,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            expected_participant_sequence: self.expected_participant_sequence,
            sequence: 0,
            automatic_settlement: self.automatic_settlement,
            status: MandateStatus::Active,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MandateControlDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "mandateID")]
    mandate_id: String,
    expected_mandate_sequence: u64,
    kind: MandateControlKind,
    reason_digest: String,
}

impl MandateControlDto {
    fn domain(self) -> Result<MandateControl, String> {
        Ok(MandateControl {
            operation_id: hex_array(&self.operation_id, "control.operationID")?,
            mandate_id: hex_array(&self.mandate_id, "control.mandateID")?,
            expected_mandate_sequence: self.expected_mandate_sequence,
            kind: self.kind,
            reason_digest: hex_array(&self.reason_digest, "control.reasonDigest")?,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MandateReservationDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "reservationID")]
    reservation_id: String,
    #[serde(rename = "mandateID")]
    mandate_id: String,
    #[serde(rename = "serviceID")]
    service_id: String,
    service_epoch: u64,
    #[serde(rename = "accountBindingID")]
    account_binding_id: String,
    #[serde(rename = "assetID")]
    asset_id: String,
    amount_commitment: String,
    underlying_reservation_digest: String,
    admission_receipt_digest: String,
    limit_proof_digest: String,
    zkpi_digest: String,
    expires_at: u64,
    expected_mandate_sequence: u64,
}

impl MandateReservationDto {
    fn domain(self) -> Result<MandateReservation, String> {
        Ok(MandateReservation {
            operation_id: hex_array(&self.operation_id, "reservation.operationID")?,
            reservation_id: hex_array(&self.reservation_id, "reservation.reservationID")?,
            mandate_id: hex_array(&self.mandate_id, "reservation.mandateID")?,
            service_id: hex_array(&self.service_id, "reservation.serviceID")?,
            service_epoch: self.service_epoch,
            account_binding_id: hex_array(
                &self.account_binding_id,
                "reservation.accountBindingID",
            )?,
            asset_id: hex_array(&self.asset_id, "reservation.assetID")?,
            amount_commitment: hex_array(&self.amount_commitment, "reservation.amountCommitment")?,
            underlying_reservation_digest: hex_array(
                &self.underlying_reservation_digest,
                "reservation.underlyingReservationDigest",
            )?,
            admission_receipt_digest: hex_array(
                &self.admission_receipt_digest,
                "reservation.admissionReceiptDigest",
            )?,
            limit_proof_digest: hex_array(
                &self.limit_proof_digest,
                "reservation.limitProofDigest",
            )?,
            zkpi_digest: hex_array(&self.zkpi_digest, "reservation.zkpiDigest")?,
            expires_at: self.expires_at,
            expected_mandate_sequence: self.expected_mandate_sequence,
            status: ReservationStatus::Active,
            settlement_digest: [0; 32],
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReservationTransitionDto {
    #[serde(rename = "operationID")]
    operation_id: String,
    #[serde(rename = "reservationID")]
    reservation_id: String,
    expected_mandate_sequence: u64,
    kind: ReservationTransitionKind,
    settlement_digest: String,
    transition_proof_digest: String,
}

impl ReservationTransitionDto {
    fn domain(self) -> Result<MandateReservationTransition, String> {
        Ok(MandateReservationTransition {
            operation_id: hex_array(&self.operation_id, "transition.operationID")?,
            reservation_id: hex_array(&self.reservation_id, "transition.reservationID")?,
            expected_mandate_sequence: self.expected_mandate_sequence,
            kind: self.kind,
            settlement_digest: hex_array(&self.settlement_digest, "transition.settlementDigest")?,
            transition_proof_digest: hex_array(
                &self.transition_proof_digest,
                "transition.transitionProofDigest",
            )?,
        })
    }
}

pub(super) fn configure_registry(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
) -> Result<[u8; 32], String> {
    require_keys(params, &["configuration", "approval", "expectedBeforeRoot"])?;
    let request: RegistryConfigurationDto = field(params, "configuration")?;
    let request = request.domain()?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    state
        .participant_registry
        .configure(request)
        .map_err(|error| error.to_string())
}

pub(super) fn register_participant(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["registration", "approval", "expectedBeforeRoot"])?;
    let request: RegisterParticipantDto = field(params, "registration")?;
    let request = request.domain()?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    state
        .participant_registry
        .register_participant(request, timestamp)
        .map_err(|error| error.to_string())
}

pub(super) fn control_participant(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
) -> Result<[u8; 32], String> {
    require_keys(params, &["control", "approval", "expectedBeforeRoot"])?;
    let request: ParticipantControlDto = field(params, "control")?;
    let request = request.domain()?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    state
        .participant_registry
        .control_participant(request)
        .map_err(|error| error.to_string())
}

pub(super) fn rotate_participant_key(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &[
            "rotation",
            "entityApproval",
            "approval",
            "expectedBeforeRoot",
        ],
    )?;
    let request: KeyRotationDto = field(params, "rotation")?;
    let request = request.domain()?;
    let entity_approval: EntityApprovalDto = field(params, "entityApproval")?;
    let entity_approval = entity_approval.domain()?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    state
        .participant_registry
        .rotate_key(request, &entity_approval)
        .map_err(|error| error.to_string())
}

pub(super) fn register_mpc_service(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["service", "approval", "expectedBeforeRoot"])?;
    let request: MpcServiceDto = field(params, "service")?;
    let request = request.domain()?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    state
        .participant_registry
        .register_service(request, timestamp)
        .map_err(|error| error.to_string())
}

pub(super) fn bind_account(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &[
            "binding",
            "entityApproval",
            "approval",
            "expectedBeforeRoot",
        ],
    )?;
    let request: AccountBindingDto = field(params, "binding")?;
    let request = request.domain()?;
    let entity_approval: EntityApprovalDto = field(params, "entityApproval")?;
    let entity_approval = entity_approval.domain()?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    state
        .participant_registry
        .bind_account(request, &entity_approval, timestamp)
        .map_err(|error| error.to_string())
}

pub(super) fn bind_service(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &[
            "binding",
            "entityApproval",
            "approval",
            "expectedBeforeRoot",
        ],
    )?;
    let request: ServiceBindingDto = field(params, "binding")?;
    let request = request.domain()?;
    let entity_approval: EntityApprovalDto = field(params, "entityApproval")?;
    let entity_approval = entity_approval.domain()?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    state
        .participant_registry
        .bind_service(request, &entity_approval, timestamp)
        .map_err(|error| error.to_string())
}

pub(super) fn create_standing_mandate(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &[
            "mandate",
            "entityApproval",
            "approval",
            "expectedBeforeRoot",
        ],
    )?;
    let request: StandingMandateDto = field(params, "mandate")?;
    let request = request.domain()?;
    let entity_approval: EntityApprovalDto = field(params, "entityApproval")?;
    let entity_approval = entity_approval.domain()?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    state
        .participant_registry
        .create_mandate(request, &entity_approval, timestamp)
        .map_err(|error| error.to_string())
}

pub(super) fn control_standing_mandate(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &[
            "control",
            "entityApproval",
            "approval",
            "expectedBeforeRoot",
        ],
    )?;
    let request: MandateControlDto = field(params, "control")?;
    let request = request.domain()?;
    let entity_approval: EntityApprovalDto = field(params, "entityApproval")?;
    let entity_approval = entity_approval.domain()?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    state
        .participant_registry
        .control_mandate(request, &entity_approval)
        .map_err(|error| error.to_string())
}

pub(super) fn reserve_under_mandate(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["reservation", "approval", "expectedBeforeRoot"])?;
    let request: MandateReservationDto = field(params, "reservation")?;
    let request = request.domain()?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    state
        .participant_registry
        .reserve_under_mandate(request, timestamp)
        .map_err(|error| error.to_string())
}

pub(super) fn transition_mandate_reservation(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["transition", "approval", "expectedBeforeRoot"])?;
    let request: ReservationTransitionDto = field(params, "transition")?;
    let request = request.domain()?;
    let statement = request.statement().map_err(|error| error.to_string())?;
    authorize(state, params, statement, authorizer)?;
    state
        .participant_registry
        .transition_reservation(request, timestamp)
        .map_err(|error| error.to_string())
}

fn composite_statement(
    kind: &[u8],
    underlying_statement: [u8; 32],
    participant_statement: [u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(COMPOSITE_RESERVATION_DOMAIN);
    hash.update((kind.len() as u64).to_be_bytes());
    hash.update(kind);
    hash.update(underlying_statement);
    hash.update(participant_statement);
    hash.finalize().into()
}

fn validate_underlying_mandate_link(
    state: &State,
    reservation: &MandateReservation,
    transition: &defmi::facility::CreditFacilityTransition,
    authorization: &defmi::facility::ReservationAuthorization,
    underlying_statement: [u8; 32],
) -> Result<(), String> {
    let mandate = state
        .participant_registry
        .mandates
        .get(&hex::encode(reservation.mandate_id))
        .ok_or_else(|| "participant reservation names an unknown standing mandate".to_string())?;
    let account = state
        .participant_registry
        .account_bindings
        .get(&hex::encode(reservation.account_binding_id))
        .ok_or_else(|| "participant reservation names an unknown account binding".to_string())?;
    let expected_role = match authorization.role {
        ReservationRole::Maker => MandateRole::Maker,
        ReservationRole::Taker => MandateRole::Taker,
    };
    let expected_admission = match authorization.role {
        ReservationRole::Maker => [0; 32],
        ReservationRole::Taker => authorization.admission_receipt_digest,
    };
    if reservation.underlying_reservation_digest != underlying_statement
        || reservation.amount_commitment != transition.amount_commitment
        || reservation.asset_id != authorization.asset_id
        || reservation.admission_receipt_digest != expected_admission
        || reservation.zkpi_digest != authorization.typed_reserve_digest
        || reservation.limit_proof_digest != transition.relation_proof_digest
        || mandate.role != expected_role
        || mandate.participant_id != account.participant_id
        || mandate.limit_policy_digest != authorization.authorization_digest
        || mandate.settlement_policy_digest != authorization.mandate_digest
        || account.account_commitment != authorization.entity_commitment
        || account.asset_id != authorization.asset_id
    {
        return Err(
            "participant mandate does not bind the exact underlying reserve, account, policy and zkPI"
                .into(),
        );
    }
    Ok(())
}

/// Creates the canonical asset/funding reserve and its participant-mandate
/// lane as one VM transaction.  The two quorum approvals are both included in
/// the transaction: the first signs the original reserve against the initial
/// root, and the second signs the mandate lane against the deterministic
/// intermediate root.  Any failure rolls the outer `State::apply` clone back.
pub(super) fn reserve_product_with_mandate(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
    anonymous_notes: bool,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &[
            "underlying",
            "mandateReservation",
            "underlyingApproval",
            "mandateApproval",
            "expectedBeforeRoot",
            "expectedAfterUnderlyingRoot",
        ],
    )?;
    let underlying = params
        .get("underlying")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| "underlying reservation must be an object".to_string())?;
    require_keys(&underlying, &["transition", "authorization", "escrow"])?;
    let transition = super::credit_transition_from_dto(
        field(&underlying, "transition")?,
        "underlying.transition",
    )?;
    transition.body()?;
    let authorization = super::reservation_authorization_from_dto(
        field(&underlying, "authorization")?,
        "underlying.authorization",
    )?;
    authorization.body(&transition)?;
    let reservation: MandateReservationDto = field(params, "mandateReservation")?;
    let reservation = reservation.domain()?;
    let participant_statement = reservation.statement().map_err(|error| error.to_string())?;

    let mut underlying_params = underlying;
    underlying_params.insert(
        "approval".into(),
        params
            .get("underlyingApproval")
            .cloned()
            .ok_or_else(|| "underlyingApproval is missing".to_string())?,
    );
    underlying_params.insert(
        "expectedBeforeRoot".into(),
        params
            .get("expectedBeforeRoot")
            .cloned()
            .ok_or_else(|| "expectedBeforeRoot is missing".to_string())?,
    );
    let underlying_statement = if anonymous_notes {
        super::reserve_note_product(state, &underlying_params, authorizer, timestamp)?
    } else {
        super::reserve_product(state, &underlying_params, authorizer, timestamp)?
    };
    validate_underlying_mandate_link(
        state,
        &reservation,
        &transition,
        &authorization,
        underlying_statement,
    )?;

    let intermediate_root = params
        .get("expectedAfterUnderlyingRoot")
        .and_then(Value::as_str)
        .ok_or_else(|| "expectedAfterUnderlyingRoot must be a hex state root".to_string())?;
    if hex_array::<32>(intermediate_root, "expectedAfterUnderlyingRoot")? != state.root() {
        return Err("underlying reservation produced an unexpected intermediate root".into());
    }
    let mut mandate_params = Map::new();
    mandate_params.insert(
        "reservation".into(),
        params
            .get("mandateReservation")
            .cloned()
            .ok_or_else(|| "mandateReservation is missing".to_string())?,
    );
    mandate_params.insert(
        "approval".into(),
        params
            .get("mandateApproval")
            .cloned()
            .ok_or_else(|| "mandateApproval is missing".to_string())?,
    );
    mandate_params.insert(
        "expectedBeforeRoot".into(),
        Value::String(intermediate_root.to_owned()),
    );
    authorize(state, &mandate_params, participant_statement, authorizer)?;
    let actual_participant_statement = state
        .participant_registry
        .reserve_under_mandate(reservation, timestamp)
        .map_err(|error| error.to_string())?;
    debug_assert_eq!(participant_statement, actual_participant_statement);
    Ok(composite_statement(
        if anonymous_notes { b"note" } else { b"account" },
        underlying_statement,
        participant_statement,
    ))
}
