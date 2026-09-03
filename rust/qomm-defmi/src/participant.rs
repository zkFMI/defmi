//! Standard legal-entity participation modules for a shared DeFMI domain.
//!
//! A participant module is deliberately not a private copy of the canonical
//! ledger.  It binds one verified legal entity to purpose-specific keys,
//! opaque account references, service subscriptions and bounded standing
//! settlement mandates.  Balances, title, collateral and credit utilisation
//! remain on the shared authoritative DeFMI books.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::MAX_UNIX_TIME;

pub type Identifier = [u8; 32];
pub type Commitment = [u8; 32];

const ZERO: [u8; 32] = [0; 32];
const CONFIG_DOMAIN: &[u8] = b"QOMM:DEFMI:PARTICIPANT-CONFIG:v1";
const PARTICIPANT_DOMAIN: &[u8] = b"QOMM:DEFMI:PARTICIPANT:v1";
const CONTROL_DOMAIN: &[u8] = b"QOMM:DEFMI:PARTICIPANT-CONTROL:v1";
const KEY_ROTATION_DOMAIN: &[u8] = b"QOMM:DEFMI:PARTICIPANT-KEY-ROTATION:v1";
const ACCOUNT_BINDING_DOMAIN: &[u8] = b"QOMM:DEFMI:PARTICIPANT-ACCOUNT:v1";
const SERVICE_DOMAIN: &[u8] = b"QOMM:DEFMI:MPC-SERVICE:v1";
const SERVICE_BINDING_DOMAIN: &[u8] = b"QOMM:DEFMI:PARTICIPANT-SERVICE:v1";
const MANDATE_DOMAIN: &[u8] = b"QOMM:DEFMI:STANDING-MANDATE:v1";
const MANDATE_CONTROL_DOMAIN: &[u8] = b"QOMM:DEFMI:STANDING-MANDATE-CONTROL:v1";
const RESERVATION_DOMAIN: &[u8] = b"QOMM:DEFMI:MANDATE-RESERVATION:v1";
const RESERVATION_TRANSITION_DOMAIN: &[u8] = b"QOMM:DEFMI:MANDATE-RESERVATION-TRANSITION:v1";
const AUTOMATIC_TRANSITION_DOMAIN: &[u8] = b"QOMM:DEFMI:AUTOMATIC-MANDATE-TRANSITION:v1";
const ENTITY_SIGNATURE_DOMAIN: &[u8] = b"QOMM:DEFMI:ENTITY-SIGNATURE:v1";

fn id_key(id: &Identifier) -> String {
    hex::encode(id)
}

fn digest<T: Serialize>(domain: &[u8], value: &T) -> Result<Commitment, ParticipantError> {
    let encoded = serde_json::to_vec(value).map_err(|_| ParticipantError::Encoding)?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((encoded.len() as u64).to_be_bytes());
    hash.update(encoded);
    Ok(hash.finalize().into())
}

fn valid_ascii(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._:/+-".contains(c))
}

fn valid_window(valid_from: u64, valid_until: u64) -> bool {
    valid_from > 0 && valid_from <= valid_until && valid_until <= MAX_UNIX_TIME
}

fn verifying_key(bytes: &[u8; 32]) -> Result<VerifyingKey, ParticipantError> {
    if *bytes == ZERO {
        return Err(ParticipantError::InvalidKey);
    }
    VerifyingKey::from_bytes(bytes).map_err(|_| ParticipantError::InvalidKey)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantRole {
    CentralBank,
    Csd,
    Ccp,
    SettlementBank,
    Custodian,
    BrokerDealer,
    Maker,
    Taker,
    StreamAttestor,
    CreditAssessor,
    Guarantor,
    LiquidityProvider,
    Servicer,
    Regulator,
    MpcOperator,
    CredentialIssuer,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    Admin,
    Settlement,
    Quote,
    MpcInput,
    Emergency,
}

impl KeyPurpose {
    fn tag(self) -> u8 {
        match self {
            Self::Admin => 1,
            Self::Settlement => 2,
            Self::Quote => 3,
            Self::MpcInput => 4,
            Self::Emergency => 5,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PurposeKey {
    pub public_key: [u8; 32],
    pub epoch: u64,
}

impl PurposeKey {
    fn validate(&self) -> Result<(), ParticipantError> {
        if self.epoch == 0 {
            return Err(ParticipantError::InvalidKey);
        }
        verifying_key(&self.public_key).map(|_| ())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParticipantKeys {
    pub admin: PurposeKey,
    pub settlement: PurposeKey,
    pub quote: PurposeKey,
    pub mpc_input: PurposeKey,
    pub emergency: PurposeKey,
}

impl ParticipantKeys {
    pub fn key(&self, purpose: KeyPurpose) -> &PurposeKey {
        match purpose {
            KeyPurpose::Admin => &self.admin,
            KeyPurpose::Settlement => &self.settlement,
            KeyPurpose::Quote => &self.quote,
            KeyPurpose::MpcInput => &self.mpc_input,
            KeyPurpose::Emergency => &self.emergency,
        }
    }

    fn key_mut(&mut self, purpose: KeyPurpose) -> &mut PurposeKey {
        match purpose {
            KeyPurpose::Admin => &mut self.admin,
            KeyPurpose::Settlement => &mut self.settlement,
            KeyPurpose::Quote => &mut self.quote,
            KeyPurpose::MpcInput => &mut self.mpc_input,
            KeyPurpose::Emergency => &mut self.emergency,
        }
    }

    fn validate(&self) -> Result<(), ParticipantError> {
        let keys = [
            &self.admin,
            &self.settlement,
            &self.quote,
            &self.mpc_input,
            &self.emergency,
        ];
        for key in keys {
            key.validate()?;
        }
        if keys
            .iter()
            .map(|key| key.public_key)
            .collect::<BTreeSet<_>>()
            .len()
            != keys.len()
        {
            return Err(ParticipantError::InvalidKey);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantStatus {
    Active,
    Suspended,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParticipantRecord {
    pub participant_id: Identifier,
    pub legal_entity_credential_commitment: Commitment,
    pub credential_issuer_id: Identifier,
    pub credential_scheme_digest: Commitment,
    pub jurisdiction: String,
    pub roles: BTreeSet<ParticipantRole>,
    pub keys: ParticipantKeys,
    pub policy_digest: Commitment,
    pub valid_from: u64,
    pub valid_until: u64,
    pub sequence: u64,
    pub status: ParticipantStatus,
}

impl ParticipantRecord {
    pub fn validate(&self) -> Result<(), ParticipantError> {
        if [
            self.participant_id,
            self.legal_entity_credential_commitment,
            self.credential_issuer_id,
            self.credential_scheme_digest,
            self.policy_digest,
        ]
        .contains(&ZERO)
            || !valid_ascii(&self.jurisdiction, 32)
            || self.roles.is_empty()
            || !valid_window(self.valid_from, self.valid_until)
            || self.sequence != 0
            || self.status != ParticipantStatus::Active
        {
            return Err(ParticipantError::InvalidParticipant);
        }
        self.keys.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryConfiguration {
    pub operation_id: Identifier,
    pub domain_id: Identifier,
    pub template_digest: Commitment,
    pub schema_digest: Commitment,
    pub template_version: u32,
}

impl RegistryConfiguration {
    pub fn statement(&self) -> Result<Commitment, ParticipantError> {
        if [
            self.operation_id,
            self.domain_id,
            self.template_digest,
            self.schema_digest,
        ]
        .contains(&ZERO)
            || self.template_version == 0
        {
            return Err(ParticipantError::InvalidConfiguration);
        }
        digest(CONFIG_DOMAIN, self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterParticipant {
    pub operation_id: Identifier,
    pub participant: ParticipantRecord,
}

impl RegisterParticipant {
    pub fn statement(&self) -> Result<Commitment, ParticipantError> {
        if self.operation_id == ZERO {
            return Err(ParticipantError::InvalidParticipant);
        }
        self.participant.validate()?;
        digest(PARTICIPANT_DOMAIN, self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantControlKind {
    Activate,
    Suspend,
    Revoke,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParticipantControl {
    pub operation_id: Identifier,
    pub participant_id: Identifier,
    pub expected_sequence: u64,
    pub kind: ParticipantControlKind,
    pub reason_digest: Commitment,
}

impl ParticipantControl {
    pub fn statement(&self) -> Result<Commitment, ParticipantError> {
        if [self.operation_id, self.participant_id, self.reason_digest].contains(&ZERO) {
            return Err(ParticipantError::InvalidControl);
        }
        digest(CONTROL_DOMAIN, self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RotateParticipantKey {
    pub operation_id: Identifier,
    pub participant_id: Identifier,
    pub expected_sequence: u64,
    pub purpose: KeyPurpose,
    pub new_key: PurposeKey,
}

impl RotateParticipantKey {
    pub fn statement(&self) -> Result<Commitment, ParticipantError> {
        if [self.operation_id, self.participant_id].contains(&ZERO) {
            return Err(ParticipantError::InvalidControl);
        }
        self.new_key.validate()?;
        digest(KEY_ROTATION_DOMAIN, self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntityApproval {
    pub participant_id: Identifier,
    pub key_purpose: KeyPurpose,
    pub key_epoch: u64,
    pub statement: Commitment,
    pub signature: Vec<u8>,
}

impl EntityApproval {
    pub fn signing_body(
        domain_id: &Identifier,
        purpose: KeyPurpose,
        epoch: u64,
        statement: &Commitment,
    ) -> Vec<u8> {
        let mut body = Vec::with_capacity(32 + 32 + 8 + 1 + ENTITY_SIGNATURE_DOMAIN.len());
        body.extend(ENTITY_SIGNATURE_DOMAIN);
        body.extend(domain_id);
        body.push(purpose.tag());
        body.extend(epoch.to_be_bytes());
        body.extend(statement);
        body
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountBindingKind {
    Cash,
    Securities,
    Collateral,
    Fee,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountBinding {
    pub operation_id: Identifier,
    pub binding_id: Identifier,
    pub participant_id: Identifier,
    pub account_commitment: Commitment,
    pub asset_id: Identifier,
    pub kind: AccountBindingKind,
    pub control_proof_digest: Commitment,
    pub valid_from: u64,
    pub valid_until: u64,
    pub expected_participant_sequence: u64,
    pub sequence: u64,
    pub active: bool,
}

impl AccountBinding {
    pub fn statement(&self) -> Result<Commitment, ParticipantError> {
        if [
            self.operation_id,
            self.binding_id,
            self.participant_id,
            self.account_commitment,
            self.asset_id,
            self.control_proof_digest,
        ]
        .contains(&ZERO)
            || !valid_window(self.valid_from, self.valid_until)
            || self.sequence != 0
            || !self.active
        {
            return Err(ParticipantError::InvalidBinding);
        }
        digest(ACCOUNT_BINDING_DOMAIN, self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MpcServiceKind {
    QommMatching,
    PrivateAnalytics,
    CrossDomainDvp,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStatus {
    Active,
    Suspended,
    Retired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MpcServiceMember {
    pub node_id: Identifier,
    pub operator_participant_id: Identifier,
    pub public_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MpcService {
    pub operation_id: Identifier,
    pub service_id: Identifier,
    pub kind: MpcServiceKind,
    pub program_digest: Commitment,
    pub schema_digest: Commitment,
    pub committee_epoch: u64,
    pub threshold: u16,
    pub members: Vec<MpcServiceMember>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub sequence: u64,
    pub status: ServiceStatus,
}

impl MpcService {
    pub fn statement(&self) -> Result<Commitment, ParticipantError> {
        if [
            self.operation_id,
            self.service_id,
            self.program_digest,
            self.schema_digest,
        ]
        .contains(&ZERO)
            || self.committee_epoch == 0
            || self.sequence != 0
            || self.status != ServiceStatus::Active
            || !valid_window(self.valid_from, self.valid_until)
            || self.members.is_empty()
            || self.members.len() > 64
            || !(1..=self.members.len()).contains(&usize::from(self.threshold))
        {
            return Err(ParticipantError::InvalidService);
        }
        let mut previous = None;
        let mut operators = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for member in &self.members {
            if [member.node_id, member.operator_participant_id].contains(&ZERO)
                || previous.is_some_and(|node_id| node_id >= member.node_id)
                || !operators.insert(member.operator_participant_id)
                || !keys.insert(member.public_key)
            {
                return Err(ParticipantError::InvalidService);
            }
            verifying_key(&member.public_key)?;
            previous = Some(member.node_id);
        }
        digest(SERVICE_DOMAIN, self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParticipantServiceBinding {
    pub operation_id: Identifier,
    pub binding_id: Identifier,
    pub participant_id: Identifier,
    pub service_id: Identifier,
    pub service_epoch: u64,
    pub input_public_key: [u8; 32],
    pub capability_digest: Commitment,
    pub valid_from: u64,
    pub valid_until: u64,
    pub expected_participant_sequence: u64,
    pub sequence: u64,
    pub active: bool,
}

impl ParticipantServiceBinding {
    pub fn statement(&self) -> Result<Commitment, ParticipantError> {
        if [
            self.operation_id,
            self.binding_id,
            self.participant_id,
            self.service_id,
            self.input_public_key,
            self.capability_digest,
        ]
        .contains(&ZERO)
            || self.service_epoch == 0
            || !valid_window(self.valid_from, self.valid_until)
            || self.sequence != 0
            || !self.active
        {
            return Err(ParticipantError::InvalidBinding);
        }
        verifying_key(&self.input_public_key)?;
        digest(SERVICE_BINDING_DOMAIN, self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateRole {
    Maker,
    Taker,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateStatus {
    Active,
    Suspended,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StandingMandate {
    pub operation_id: Identifier,
    pub mandate_id: Identifier,
    pub participant_id: Identifier,
    pub service_id: Identifier,
    pub service_binding_id: Identifier,
    pub role: MandateRole,
    pub account_binding_ids: Vec<Identifier>,
    pub permitted_asset_ids: Vec<Identifier>,
    pub permitted_destination_domains: Vec<Identifier>,
    pub limit_commitment: Commitment,
    pub limit_policy_digest: Commitment,
    pub settlement_policy_digest: Commitment,
    pub max_active_reservations: u32,
    pub active_reservations: u32,
    pub valid_from: u64,
    pub valid_until: u64,
    pub expected_participant_sequence: u64,
    pub sequence: u64,
    pub automatic_settlement: bool,
    pub status: MandateStatus,
}

impl StandingMandate {
    pub fn statement(&self) -> Result<Commitment, ParticipantError> {
        if [
            self.operation_id,
            self.mandate_id,
            self.participant_id,
            self.service_id,
            self.service_binding_id,
            self.limit_commitment,
            self.limit_policy_digest,
            self.settlement_policy_digest,
        ]
        .contains(&ZERO)
            || self.account_binding_ids.is_empty()
            || self.permitted_asset_ids.is_empty()
            || self.account_binding_ids.len() > 64
            || self.permitted_asset_ids.len() > 64
            || self.permitted_destination_domains.len() > 64
            || !strict_identifiers(&self.account_binding_ids)
            || !strict_identifiers(&self.permitted_asset_ids)
            || !strict_identifiers(&self.permitted_destination_domains)
            || self.max_active_reservations == 0
            || self.active_reservations != 0
            || !valid_window(self.valid_from, self.valid_until)
            || self.sequence != 0
            || !self.automatic_settlement
            || self.status != MandateStatus::Active
        {
            return Err(ParticipantError::InvalidMandate);
        }
        digest(MANDATE_DOMAIN, self)
    }
}

fn strict_identifiers(values: &[Identifier]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1]) && !values.contains(&ZERO)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateControlKind {
    Activate,
    Suspend,
    Revoke,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MandateControl {
    pub operation_id: Identifier,
    pub mandate_id: Identifier,
    pub expected_mandate_sequence: u64,
    pub kind: MandateControlKind,
    pub reason_digest: Commitment,
}

impl MandateControl {
    pub fn statement(&self) -> Result<Commitment, ParticipantError> {
        if [self.operation_id, self.mandate_id, self.reason_digest].contains(&ZERO) {
            return Err(ParticipantError::InvalidControl);
        }
        digest(MANDATE_CONTROL_DOMAIN, self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Active,
    Consumed,
    Released,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MandateReservation {
    pub operation_id: Identifier,
    pub reservation_id: Identifier,
    pub mandate_id: Identifier,
    pub service_id: Identifier,
    pub service_epoch: u64,
    pub account_binding_id: Identifier,
    pub asset_id: Identifier,
    pub amount_commitment: Commitment,
    pub underlying_reservation_digest: Commitment,
    pub admission_receipt_digest: Commitment,
    pub limit_proof_digest: Commitment,
    pub zkpi_digest: Commitment,
    pub expires_at: u64,
    pub expected_mandate_sequence: u64,
    pub status: ReservationStatus,
    pub settlement_digest: Commitment,
}

impl MandateReservation {
    pub fn statement(&self) -> Result<Commitment, ParticipantError> {
        if [
            self.operation_id,
            self.reservation_id,
            self.mandate_id,
            self.service_id,
            self.account_binding_id,
            self.asset_id,
            self.amount_commitment,
            self.underlying_reservation_digest,
            self.limit_proof_digest,
            self.zkpi_digest,
        ]
        .contains(&ZERO)
            || self.service_epoch == 0
            || self.expires_at == 0
            || self.expires_at > MAX_UNIX_TIME
            || self.status != ReservationStatus::Active
            || self.settlement_digest != ZERO
        {
            return Err(ParticipantError::InvalidReservation);
        }
        digest(RESERVATION_DOMAIN, self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationTransitionKind {
    Consume,
    Release,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MandateReservationTransition {
    pub operation_id: Identifier,
    pub reservation_id: Identifier,
    pub expected_mandate_sequence: u64,
    pub kind: ReservationTransitionKind,
    pub settlement_digest: Commitment,
    pub transition_proof_digest: Commitment,
}

/// Evidence already verified by the enclosing QOMM/zkPI settlement executor.
/// It lets the standing mandate follow the canonical reserve into settlement
/// without a second Maker or Taker signature.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomaticReservationEvidence {
    pub underlying_reservation_digest: Commitment,
    pub amount_commitment: Commitment,
    pub asset_id: Identifier,
    pub role: MandateRole,
    pub settlement_digest: Commitment,
    pub transition_proof_digest: Commitment,
}

impl MandateReservationTransition {
    pub fn statement(&self) -> Result<Commitment, ParticipantError> {
        if [
            self.operation_id,
            self.reservation_id,
            self.transition_proof_digest,
        ]
        .contains(&ZERO)
            || (self.kind == ReservationTransitionKind::Consume && self.settlement_digest == ZERO)
            || (self.kind == ReservationTransitionKind::Release && self.settlement_digest != ZERO)
        {
            return Err(ParticipantError::InvalidReservation);
        }
        digest(RESERVATION_TRANSITION_DOMAIN, self)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParticipantRegistry {
    pub configuration: Option<RegistryConfiguration>,
    pub participants: BTreeMap<String, ParticipantRecord>,
    pub account_bindings: BTreeMap<String, AccountBinding>,
    pub services: BTreeMap<String, MpcService>,
    pub service_bindings: BTreeMap<String, ParticipantServiceBinding>,
    pub mandates: BTreeMap<String, StandingMandate>,
    pub reservations: BTreeMap<String, MandateReservation>,
    pub consumed_operations: BTreeSet<String>,
}

impl ParticipantRegistry {
    pub fn is_empty(&self) -> bool {
        self.configuration.is_none()
            && self.participants.is_empty()
            && self.account_bindings.is_empty()
            && self.services.is_empty()
            && self.service_bindings.is_empty()
            && self.mandates.is_empty()
            && self.reservations.is_empty()
            && self.consumed_operations.is_empty()
    }

    pub fn validate(&self) -> Result<(), ParticipantError> {
        if self.is_empty() {
            return Ok(());
        }
        let configuration = self
            .configuration
            .as_ref()
            .ok_or(ParticipantError::RegistryNotConfigured)?;
        configuration.statement()?;
        if !self
            .consumed_operations
            .contains(&id_key(&configuration.operation_id))
        {
            return Err(ParticipantError::InvalidState);
        }
        for (key, participant) in &self.participants {
            let mut initial = participant.clone();
            initial.sequence = 0;
            initial.status = ParticipantStatus::Active;
            initial.validate()?;
            if key != &id_key(&participant.participant_id) {
                return Err(ParticipantError::InvalidState);
            }
        }
        for (key, service) in &self.services {
            service.statement()?;
            if key != &id_key(&service.service_id) {
                return Err(ParticipantError::InvalidState);
            }
            for member in &service.members {
                let operator = self.participant(&member.operator_participant_id)?;
                if !operator.roles.contains(&ParticipantRole::MpcOperator) {
                    return Err(ParticipantError::InvalidState);
                }
            }
        }
        for (key, binding) in &self.account_bindings {
            binding.statement()?;
            if key != &id_key(&binding.binding_id)
                || !self
                    .participants
                    .contains_key(&id_key(&binding.participant_id))
            {
                return Err(ParticipantError::InvalidState);
            }
        }
        for (key, binding) in &self.service_bindings {
            binding.statement()?;
            if key != &id_key(&binding.binding_id)
                || !self
                    .participants
                    .contains_key(&id_key(&binding.participant_id))
                || !self.services.contains_key(&id_key(&binding.service_id))
            {
                return Err(ParticipantError::InvalidState);
            }
        }
        let mut active_by_mandate: BTreeMap<String, u32> = BTreeMap::new();
        for (key, reservation) in &self.reservations {
            let mut initial = reservation.clone();
            initial.status = ReservationStatus::Active;
            initial.settlement_digest = ZERO;
            initial.statement()?;
            if key != &id_key(&reservation.reservation_id)
                || !self.mandates.contains_key(&id_key(&reservation.mandate_id))
            {
                return Err(ParticipantError::InvalidState);
            }
            if reservation.status == ReservationStatus::Active {
                let count = active_by_mandate
                    .entry(id_key(&reservation.mandate_id))
                    .or_default();
                *count = count
                    .checked_add(1)
                    .ok_or(ParticipantError::ArithmeticOverflow)?;
            }
        }
        for (key, mandate) in &self.mandates {
            let mut initial = mandate.clone();
            initial.active_reservations = 0;
            initial.sequence = 0;
            initial.status = MandateStatus::Active;
            initial.statement()?;
            if key != &id_key(&mandate.mandate_id)
                || !self
                    .participants
                    .contains_key(&id_key(&mandate.participant_id))
                || !self.services.contains_key(&id_key(&mandate.service_id))
                || mandate.active_reservations
                    != active_by_mandate.get(key).copied().unwrap_or_default()
            {
                return Err(ParticipantError::InvalidState);
            }
        }
        if self
            .consumed_operations
            .iter()
            .any(|key| key.len() != 64 || hex::decode(key).map_or(true, |bytes| bytes.len() != 32))
        {
            return Err(ParticipantError::InvalidState);
        }
        Ok(())
    }

    pub fn configure(
        &mut self,
        configuration: RegistryConfiguration,
    ) -> Result<Commitment, ParticipantError> {
        if self.configuration.is_some() {
            return Err(ParticipantError::RegistryAlreadyConfigured);
        }
        let statement = configuration.statement()?;
        self.consume_operation(&configuration.operation_id)?;
        self.configuration = Some(configuration);
        Ok(statement)
    }

    pub fn register_participant(
        &mut self,
        request: RegisterParticipant,
        now: u64,
    ) -> Result<Commitment, ParticipantError> {
        self.configuration()?;
        let statement = request.statement()?;
        if now < request.participant.valid_from || now > request.participant.valid_until {
            return Err(ParticipantError::OutsideValidityWindow);
        }
        let key = id_key(&request.participant.participant_id);
        if self.participants.contains_key(&key) {
            return Err(ParticipantError::DuplicateParticipant);
        }
        self.consume_operation(&request.operation_id)?;
        self.participants.insert(key, request.participant);
        Ok(statement)
    }

    pub fn control_participant(
        &mut self,
        request: ParticipantControl,
    ) -> Result<Commitment, ParticipantError> {
        self.configuration()?;
        let statement = request.statement()?;
        self.ensure_operation_unused(&request.operation_id)?;
        let participant = self.participant_mut(&request.participant_id)?;
        if participant.sequence != request.expected_sequence
            || participant.status == ParticipantStatus::Revoked
            || (request.kind == ParticipantControlKind::Activate
                && participant.status == ParticipantStatus::Active)
            || (request.kind == ParticipantControlKind::Suspend
                && participant.status != ParticipantStatus::Active)
        {
            return Err(ParticipantError::InvalidControl);
        }
        participant.status = match request.kind {
            ParticipantControlKind::Activate => ParticipantStatus::Active,
            ParticipantControlKind::Suspend => ParticipantStatus::Suspended,
            ParticipantControlKind::Revoke => ParticipantStatus::Revoked,
        };
        participant.sequence = participant
            .sequence
            .checked_add(1)
            .ok_or(ParticipantError::ArithmeticOverflow)?;
        self.consume_operation(&request.operation_id)?;
        Ok(statement)
    }

    pub fn rotate_key(
        &mut self,
        request: RotateParticipantKey,
        approval: &EntityApproval,
    ) -> Result<Commitment, ParticipantError> {
        let statement = request.statement()?;
        self.verify_approval(
            &request.participant_id,
            KeyPurpose::Admin,
            &statement,
            approval,
        )?;
        self.ensure_operation_unused(&request.operation_id)?;
        let participant = self.active_participant_mut(&request.participant_id)?;
        if participant.sequence != request.expected_sequence {
            return Err(ParticipantError::StaleSequence);
        }
        let current = participant.keys.key(request.purpose);
        if request.new_key.epoch != current.epoch + 1
            || request.new_key.public_key == current.public_key
        {
            return Err(ParticipantError::InvalidKey);
        }
        *participant.keys.key_mut(request.purpose) = request.new_key;
        participant.sequence = participant
            .sequence
            .checked_add(1)
            .ok_or(ParticipantError::ArithmeticOverflow)?;
        participant.keys.validate()?;
        self.consume_operation(&request.operation_id)?;
        Ok(statement)
    }

    pub fn register_service(
        &mut self,
        service: MpcService,
        now: u64,
    ) -> Result<Commitment, ParticipantError> {
        self.configuration()?;
        let statement = service.statement()?;
        if now < service.valid_from || now > service.valid_until {
            return Err(ParticipantError::OutsideValidityWindow);
        }
        for member in &service.members {
            let operator = self.active_participant(&member.operator_participant_id, now)?;
            if !operator.roles.contains(&ParticipantRole::MpcOperator) {
                return Err(ParticipantError::MissingRole);
            }
        }
        let key = id_key(&service.service_id);
        if self.services.contains_key(&key) {
            return Err(ParticipantError::DuplicateService);
        }
        self.consume_operation(&service.operation_id)?;
        self.services.insert(key, service);
        Ok(statement)
    }

    pub fn bind_account(
        &mut self,
        binding: AccountBinding,
        approval: &EntityApproval,
        now: u64,
    ) -> Result<Commitment, ParticipantError> {
        let statement = binding.statement()?;
        self.verify_approval(
            &binding.participant_id,
            KeyPurpose::Settlement,
            &statement,
            approval,
        )?;
        self.ensure_operation_unused(&binding.operation_id)?;
        let participant = self.active_participant(&binding.participant_id, now)?;
        if participant.sequence != binding.expected_participant_sequence
            || binding.valid_from < participant.valid_from
            || binding.valid_until > participant.valid_until
        {
            return Err(ParticipantError::StaleSequence);
        }
        if self
            .account_bindings
            .contains_key(&id_key(&binding.binding_id))
        {
            return Err(ParticipantError::DuplicateBinding);
        }
        self.bump_participant_sequence(&binding.participant_id)?;
        self.consume_operation(&binding.operation_id)?;
        self.account_bindings
            .insert(id_key(&binding.binding_id), binding);
        Ok(statement)
    }

    pub fn bind_service(
        &mut self,
        binding: ParticipantServiceBinding,
        approval: &EntityApproval,
        now: u64,
    ) -> Result<Commitment, ParticipantError> {
        let statement = binding.statement()?;
        self.verify_approval(
            &binding.participant_id,
            KeyPurpose::MpcInput,
            &statement,
            approval,
        )?;
        self.ensure_operation_unused(&binding.operation_id)?;
        let participant = self.active_participant(&binding.participant_id, now)?;
        if participant.sequence != binding.expected_participant_sequence
            || binding.valid_from < participant.valid_from
            || binding.valid_until > participant.valid_until
        {
            return Err(ParticipantError::StaleSequence);
        }
        let service = self.active_service(&binding.service_id, now)?;
        if service.committee_epoch != binding.service_epoch
            || binding.valid_from < service.valid_from
            || binding.valid_until > service.valid_until
        {
            return Err(ParticipantError::InvalidBinding);
        }
        if self
            .service_bindings
            .contains_key(&id_key(&binding.binding_id))
        {
            return Err(ParticipantError::DuplicateBinding);
        }
        self.bump_participant_sequence(&binding.participant_id)?;
        self.consume_operation(&binding.operation_id)?;
        self.service_bindings
            .insert(id_key(&binding.binding_id), binding);
        Ok(statement)
    }

    pub fn create_mandate(
        &mut self,
        mandate: StandingMandate,
        approval: &EntityApproval,
        now: u64,
    ) -> Result<Commitment, ParticipantError> {
        let statement = mandate.statement()?;
        self.verify_approval(
            &mandate.participant_id,
            KeyPurpose::Settlement,
            &statement,
            approval,
        )?;
        self.ensure_operation_unused(&mandate.operation_id)?;
        let participant = self.active_participant(&mandate.participant_id, now)?;
        if participant.sequence != mandate.expected_participant_sequence
            || mandate.valid_from < participant.valid_from
            || mandate.valid_until > participant.valid_until
        {
            return Err(ParticipantError::StaleSequence);
        }
        let required_role = match mandate.role {
            MandateRole::Maker => ParticipantRole::Maker,
            MandateRole::Taker => ParticipantRole::Taker,
        };
        if !participant.roles.contains(&required_role) {
            return Err(ParticipantError::MissingRole);
        }
        let service = self.active_service(&mandate.service_id, now)?;
        if mandate.valid_from < service.valid_from || mandate.valid_until > service.valid_until {
            return Err(ParticipantError::InvalidMandate);
        }
        let service_binding = self
            .service_bindings
            .get(&id_key(&mandate.service_binding_id))
            .ok_or(ParticipantError::UnknownBinding)?;
        if !service_binding.active
            || service_binding.participant_id != mandate.participant_id
            || service_binding.service_id != mandate.service_id
            || service_binding.service_epoch != service.committee_epoch
            || mandate.valid_from < service_binding.valid_from
            || mandate.valid_until > service_binding.valid_until
        {
            return Err(ParticipantError::InvalidMandate);
        }
        for binding_id in &mandate.account_binding_ids {
            let binding = self
                .account_bindings
                .get(&id_key(binding_id))
                .ok_or(ParticipantError::UnknownBinding)?;
            if !binding.active
                || binding.participant_id != mandate.participant_id
                || !mandate.permitted_asset_ids.contains(&binding.asset_id)
                || mandate.valid_from < binding.valid_from
                || mandate.valid_until > binding.valid_until
            {
                return Err(ParticipantError::InvalidMandate);
            }
        }
        if self.mandates.contains_key(&id_key(&mandate.mandate_id)) {
            return Err(ParticipantError::DuplicateMandate);
        }
        self.bump_participant_sequence(&mandate.participant_id)?;
        self.consume_operation(&mandate.operation_id)?;
        self.mandates.insert(id_key(&mandate.mandate_id), mandate);
        Ok(statement)
    }

    pub fn control_mandate(
        &mut self,
        request: MandateControl,
        approval: &EntityApproval,
    ) -> Result<Commitment, ParticipantError> {
        let statement = request.statement()?;
        let participant_id = self
            .mandates
            .get(&id_key(&request.mandate_id))
            .ok_or(ParticipantError::UnknownMandate)?
            .participant_id;
        self.verify_approval(
            &participant_id,
            KeyPurpose::Settlement,
            &statement,
            approval,
        )?;
        self.ensure_operation_unused(&request.operation_id)?;
        let mandate = self
            .mandates
            .get_mut(&id_key(&request.mandate_id))
            .ok_or(ParticipantError::UnknownMandate)?;
        if mandate.sequence != request.expected_mandate_sequence
            || mandate.status == MandateStatus::Revoked
            || (mandate.active_reservations != 0 && request.kind == MandateControlKind::Revoke)
        {
            return Err(ParticipantError::InvalidControl);
        }
        mandate.status = match request.kind {
            MandateControlKind::Activate => MandateStatus::Active,
            MandateControlKind::Suspend => MandateStatus::Suspended,
            MandateControlKind::Revoke => MandateStatus::Revoked,
        };
        mandate.sequence = mandate
            .sequence
            .checked_add(1)
            .ok_or(ParticipantError::ArithmeticOverflow)?;
        self.consume_operation(&request.operation_id)?;
        Ok(statement)
    }

    /// Reserves one lane under an already signed standing mandate.
    ///
    /// This transition intentionally takes no fresh entity signature.  The
    /// standing mandate, pinned service epoch, zkPI digest, limit proof and
    /// underlying canonical-ledger reservation are the authorisation.
    pub fn reserve_under_mandate(
        &mut self,
        reservation: MandateReservation,
        now: u64,
    ) -> Result<Commitment, ParticipantError> {
        let statement = reservation.statement()?;
        self.ensure_operation_unused(&reservation.operation_id)?;
        let mandate = self
            .mandates
            .get(&id_key(&reservation.mandate_id))
            .cloned()
            .ok_or(ParticipantError::UnknownMandate)?;
        self.active_participant(&mandate.participant_id, now)?;
        let service = self.active_service(&mandate.service_id, now)?;
        if mandate.status != MandateStatus::Active
            || !mandate.automatic_settlement
            || now < mandate.valid_from
            || now > mandate.valid_until
            || reservation.expires_at > mandate.valid_until
            || reservation.expected_mandate_sequence != mandate.sequence
            || reservation.service_id != mandate.service_id
            || reservation.service_epoch != service.committee_epoch
            || !mandate
                .account_binding_ids
                .contains(&reservation.account_binding_id)
            || !mandate.permitted_asset_ids.contains(&reservation.asset_id)
            || mandate.active_reservations >= mandate.max_active_reservations
            || (mandate.role == MandateRole::Taker && reservation.admission_receipt_digest == ZERO)
            || (mandate.role == MandateRole::Maker && reservation.admission_receipt_digest != ZERO)
        {
            return Err(ParticipantError::InvalidReservation);
        }
        if self
            .reservations
            .contains_key(&id_key(&reservation.reservation_id))
            || self.reservations.values().any(|existing| {
                existing.underlying_reservation_digest == reservation.underlying_reservation_digest
            })
        {
            return Err(ParticipantError::DuplicateReservation);
        }
        let mandate = self
            .mandates
            .get_mut(&id_key(&reservation.mandate_id))
            .expect("mandate was validated");
        mandate.active_reservations = mandate
            .active_reservations
            .checked_add(1)
            .ok_or(ParticipantError::ArithmeticOverflow)?;
        mandate.sequence = mandate
            .sequence
            .checked_add(1)
            .ok_or(ParticipantError::ArithmeticOverflow)?;
        self.consume_operation(&reservation.operation_id)?;
        self.reservations
            .insert(id_key(&reservation.reservation_id), reservation);
        Ok(statement)
    }

    /// Consumes or expires a reservation without asking the participant to
    /// sign again.  The caller must apply the underlying balance/title
    /// transition atomically in the enclosing DeFMI state transition.
    pub fn transition_reservation(
        &mut self,
        request: MandateReservationTransition,
        now: u64,
    ) -> Result<Commitment, ParticipantError> {
        let statement = request.statement()?;
        self.ensure_operation_unused(&request.operation_id)?;
        let key = id_key(&request.reservation_id);
        let reservation = self
            .reservations
            .get(&key)
            .cloned()
            .ok_or(ParticipantError::UnknownReservation)?;
        if reservation.status != ReservationStatus::Active {
            return Err(ParticipantError::InvalidReservation);
        }
        let mandate = self
            .mandates
            .get(&id_key(&reservation.mandate_id))
            .ok_or(ParticipantError::UnknownMandate)?;
        if mandate.sequence != request.expected_mandate_sequence
            || (request.kind == ReservationTransitionKind::Consume
                && (now > reservation.expires_at || !mandate.automatic_settlement))
            || (request.kind == ReservationTransitionKind::Release && now < reservation.expires_at)
        {
            return Err(ParticipantError::InvalidReservation);
        }
        let mandate = self
            .mandates
            .get_mut(&id_key(&reservation.mandate_id))
            .expect("mandate was validated");
        mandate.active_reservations = mandate
            .active_reservations
            .checked_sub(1)
            .ok_or(ParticipantError::ArithmeticOverflow)?;
        mandate.sequence = mandate
            .sequence
            .checked_add(1)
            .ok_or(ParticipantError::ArithmeticOverflow)?;
        let reservation = self
            .reservations
            .get_mut(&key)
            .expect("reservation was validated");
        reservation.status = match request.kind {
            ReservationTransitionKind::Consume => ReservationStatus::Consumed,
            ReservationTransitionKind::Release => ReservationStatus::Released,
        };
        reservation.settlement_digest = request.settlement_digest;
        self.consume_operation(&request.operation_id)?;
        Ok(statement)
    }

    /// Atomically follows a proof-verified QOMM reserve into consumption.
    /// Returns `Ok(None)` for an older reserve that was not created through a
    /// participant module, preserving the existing settlement path.
    pub fn consume_linked_reservation(
        &mut self,
        evidence: AutomaticReservationEvidence,
        now: u64,
    ) -> Result<Option<Commitment>, ParticipantError> {
        self.automatic_transition(evidence, ReservationTransitionKind::Consume, now)
    }

    /// Atomically follows an expired underlying reserve into release.
    pub fn release_linked_reservation(
        &mut self,
        evidence: AutomaticReservationEvidence,
        now: u64,
    ) -> Result<Option<Commitment>, ParticipantError> {
        self.automatic_transition(evidence, ReservationTransitionKind::Release, now)
    }

    fn automatic_transition(
        &mut self,
        evidence: AutomaticReservationEvidence,
        kind: ReservationTransitionKind,
        now: u64,
    ) -> Result<Option<Commitment>, ParticipantError> {
        if [
            evidence.underlying_reservation_digest,
            evidence.amount_commitment,
            evidence.asset_id,
            evidence.transition_proof_digest,
        ]
        .contains(&ZERO)
            || (kind == ReservationTransitionKind::Consume && evidence.settlement_digest == ZERO)
            || (kind == ReservationTransitionKind::Release && evidence.settlement_digest != ZERO)
        {
            return Err(ParticipantError::InvalidReservation);
        }
        let matches = self
            .reservations
            .values()
            .filter(|reservation| {
                reservation.underlying_reservation_digest == evidence.underlying_reservation_digest
            })
            .map(|reservation| reservation.reservation_id)
            .collect::<Vec<_>>();
        let Some(reservation_id) = matches.first().copied() else {
            return Ok(None);
        };
        if matches.len() != 1 {
            return Err(ParticipantError::InvalidState);
        }
        let reservation = self
            .reservations
            .get(&id_key(&reservation_id))
            .ok_or(ParticipantError::UnknownReservation)?;
        let mandate = self
            .mandates
            .get(&id_key(&reservation.mandate_id))
            .ok_or(ParticipantError::UnknownMandate)?;
        if reservation.amount_commitment != evidence.amount_commitment
            || reservation.asset_id != evidence.asset_id
            || mandate.role != evidence.role
        {
            return Err(ParticipantError::InvalidReservation);
        }
        let expected_mandate_sequence = mandate.sequence;
        let operation_id = digest(
            AUTOMATIC_TRANSITION_DOMAIN,
            &(
                reservation_id,
                kind,
                evidence.settlement_digest,
                evidence.transition_proof_digest,
            ),
        )?;
        self.transition_reservation(
            MandateReservationTransition {
                operation_id,
                reservation_id,
                expected_mandate_sequence,
                kind,
                settlement_digest: evidence.settlement_digest,
                transition_proof_digest: evidence.transition_proof_digest,
            },
            now,
        )
        .map(Some)
    }

    pub fn participant(
        &self,
        participant_id: &Identifier,
    ) -> Result<&ParticipantRecord, ParticipantError> {
        self.participants
            .get(&id_key(participant_id))
            .ok_or(ParticipantError::UnknownParticipant)
    }

    fn participant_mut(
        &mut self,
        participant_id: &Identifier,
    ) -> Result<&mut ParticipantRecord, ParticipantError> {
        self.participants
            .get_mut(&id_key(participant_id))
            .ok_or(ParticipantError::UnknownParticipant)
    }

    fn active_participant(
        &self,
        participant_id: &Identifier,
        now: u64,
    ) -> Result<&ParticipantRecord, ParticipantError> {
        let participant = self.participant(participant_id)?;
        if participant.status != ParticipantStatus::Active
            || now < participant.valid_from
            || now > participant.valid_until
        {
            return Err(ParticipantError::ParticipantUnavailable);
        }
        Ok(participant)
    }

    fn active_participant_mut(
        &mut self,
        participant_id: &Identifier,
    ) -> Result<&mut ParticipantRecord, ParticipantError> {
        let participant = self.participant_mut(participant_id)?;
        if participant.status != ParticipantStatus::Active {
            return Err(ParticipantError::ParticipantUnavailable);
        }
        Ok(participant)
    }

    fn active_service(
        &self,
        service_id: &Identifier,
        now: u64,
    ) -> Result<&MpcService, ParticipantError> {
        let service = self
            .services
            .get(&id_key(service_id))
            .ok_or(ParticipantError::UnknownService)?;
        if service.status != ServiceStatus::Active
            || now < service.valid_from
            || now > service.valid_until
        {
            return Err(ParticipantError::ServiceUnavailable);
        }
        Ok(service)
    }

    fn configuration(&self) -> Result<&RegistryConfiguration, ParticipantError> {
        self.configuration
            .as_ref()
            .ok_or(ParticipantError::RegistryNotConfigured)
    }

    fn verify_approval(
        &self,
        participant_id: &Identifier,
        purpose: KeyPurpose,
        statement: &Commitment,
        approval: &EntityApproval,
    ) -> Result<(), ParticipantError> {
        let configuration = self.configuration()?;
        let participant = self.participant(participant_id)?;
        let key = participant.keys.key(purpose);
        if approval.participant_id != *participant_id
            || approval.key_purpose != purpose
            || approval.key_epoch != key.epoch
            || approval.statement != *statement
            || approval.signature.len() != 64
        {
            return Err(ParticipantError::InvalidEntityApproval);
        }
        let signature_bytes: [u8; 64] = approval
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| ParticipantError::InvalidEntityApproval)?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key(&key.public_key)?
            .verify(
                &EntityApproval::signing_body(
                    &configuration.domain_id,
                    purpose,
                    key.epoch,
                    statement,
                ),
                &signature,
            )
            .map_err(|_| ParticipantError::InvalidEntityApproval)
    }

    fn bump_participant_sequence(
        &mut self,
        participant_id: &Identifier,
    ) -> Result<(), ParticipantError> {
        let participant = self.participant_mut(participant_id)?;
        participant.sequence = participant
            .sequence
            .checked_add(1)
            .ok_or(ParticipantError::ArithmeticOverflow)?;
        Ok(())
    }

    fn ensure_operation_unused(&self, operation_id: &Identifier) -> Result<(), ParticipantError> {
        if *operation_id == ZERO || self.consumed_operations.contains(&id_key(operation_id)) {
            return Err(ParticipantError::OperationAlreadyUsed);
        }
        Ok(())
    }

    fn consume_operation(&mut self, operation_id: &Identifier) -> Result<(), ParticipantError> {
        self.ensure_operation_unused(operation_id)?;
        self.consumed_operations.insert(id_key(operation_id));
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ParticipantError {
    #[error("participant registry is not configured")]
    RegistryNotConfigured,
    #[error("participant registry is already configured")]
    RegistryAlreadyConfigured,
    #[error("participant registry configuration is invalid")]
    InvalidConfiguration,
    #[error("participant definition is invalid")]
    InvalidParticipant,
    #[error("participant key is invalid")]
    InvalidKey,
    #[error("participant control is invalid")]
    InvalidControl,
    #[error("participant is already registered")]
    DuplicateParticipant,
    #[error("participant is unknown")]
    UnknownParticipant,
    #[error("participant is unavailable")]
    ParticipantUnavailable,
    #[error("required participant role is missing")]
    MissingRole,
    #[error("entity approval is invalid")]
    InvalidEntityApproval,
    #[error("service definition is invalid")]
    InvalidService,
    #[error("service is already registered")]
    DuplicateService,
    #[error("service is unknown")]
    UnknownService,
    #[error("service is unavailable")]
    ServiceUnavailable,
    #[error("participant binding is invalid")]
    InvalidBinding,
    #[error("participant binding is already registered")]
    DuplicateBinding,
    #[error("participant binding is unknown")]
    UnknownBinding,
    #[error("standing mandate is invalid")]
    InvalidMandate,
    #[error("standing mandate is already registered")]
    DuplicateMandate,
    #[error("standing mandate is unknown")]
    UnknownMandate,
    #[error("mandate reservation is invalid")]
    InvalidReservation,
    #[error("mandate reservation is already registered")]
    DuplicateReservation,
    #[error("mandate reservation is unknown")]
    UnknownReservation,
    #[error("operation identifier was already used")]
    OperationAlreadyUsed,
    #[error("request was built against a stale sequence")]
    StaleSequence,
    #[error("request is outside its validity window")]
    OutsideValidityWindow,
    #[error("participant registry arithmetic overflow")]
    ArithmeticOverflow,
    #[error("participant registry encoding failed")]
    Encoding,
    #[error("participant registry state is internally inconsistent")]
    InvalidState,
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn id(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn signing_key(value: u8) -> SigningKey {
        SigningKey::from_bytes(&id(value))
    }

    fn key(value: u8) -> PurposeKey {
        PurposeKey {
            public_key: signing_key(value).verifying_key().to_bytes(),
            epoch: 1,
        }
    }

    fn participant(
        participant_id: u8,
        key_base: u8,
        roles: &[ParticipantRole],
    ) -> ParticipantRecord {
        ParticipantRecord {
            participant_id: id(participant_id),
            legal_entity_credential_commitment: id(participant_id + 1),
            credential_issuer_id: id(240),
            credential_scheme_digest: id(241),
            jurisdiction: "JP".into(),
            roles: roles.iter().copied().collect(),
            keys: ParticipantKeys {
                admin: key(key_base),
                settlement: key(key_base + 1),
                quote: key(key_base + 2),
                mpc_input: key(key_base + 3),
                emergency: key(key_base + 4),
            },
            policy_digest: id(participant_id + 2),
            valid_from: 10,
            valid_until: 1_000,
            sequence: 0,
            status: ParticipantStatus::Active,
        }
    }

    fn approval(
        registry: &ParticipantRegistry,
        participant_id: u8,
        purpose: KeyPurpose,
        statement: [u8; 32],
        signer: &SigningKey,
    ) -> EntityApproval {
        let participant = registry.participant(&id(participant_id)).unwrap();
        let epoch = participant.keys.key(purpose).epoch;
        let domain = registry.configuration.as_ref().unwrap().domain_id;
        EntityApproval {
            participant_id: id(participant_id),
            key_purpose: purpose,
            key_epoch: epoch,
            statement,
            signature: signer
                .sign(&EntityApproval::signing_body(
                    &domain, purpose, epoch, &statement,
                ))
                .to_bytes()
                .to_vec(),
        }
    }

    fn configured() -> ParticipantRegistry {
        let mut registry = ParticipantRegistry::default();
        registry
            .configure(RegistryConfiguration {
                operation_id: id(1),
                domain_id: id(2),
                template_digest: id(3),
                schema_digest: id(4),
                template_version: 1,
            })
            .unwrap();
        registry
    }

    fn register(
        registry: &mut ParticipantRegistry,
        operation: u8,
        participant_id: u8,
        key_base: u8,
        roles: &[ParticipantRole],
    ) {
        registry
            .register_participant(
                RegisterParticipant {
                    operation_id: id(operation),
                    participant: participant(participant_id, key_base, roles),
                },
                20,
            )
            .unwrap();
    }

    #[test]
    fn seven_independent_operators_can_serve_a_bound_automatic_mandate() {
        let mut registry = configured();
        register(
            &mut registry,
            10,
            20,
            30,
            &[ParticipantRole::Maker, ParticipantRole::BrokerDealer],
        );
        for offset in 0..7u8 {
            register(
                &mut registry,
                50 + offset,
                80 + offset,
                100 + offset * 5,
                &[ParticipantRole::MpcOperator],
            );
        }
        let service = MpcService {
            operation_id: id(60),
            service_id: id(61),
            kind: MpcServiceKind::QommMatching,
            program_digest: id(62),
            schema_digest: id(63),
            committee_epoch: 1,
            threshold: 4,
            members: (0..7u8)
                .map(|offset| MpcServiceMember {
                    node_id: id(10 + offset),
                    operator_participant_id: id(80 + offset),
                    public_key: signing_key(170 + offset).verifying_key().to_bytes(),
                })
                .collect(),
            valid_from: 10,
            valid_until: 900,
            sequence: 0,
            status: ServiceStatus::Active,
        };
        registry.register_service(service, 20).unwrap();

        let service_binding = ParticipantServiceBinding {
            operation_id: id(64),
            binding_id: id(65),
            participant_id: id(20),
            service_id: id(61),
            service_epoch: 1,
            input_public_key: signing_key(33).verifying_key().to_bytes(),
            capability_digest: id(66),
            valid_from: 20,
            valid_until: 800,
            expected_participant_sequence: 0,
            sequence: 0,
            active: true,
        };
        let statement = service_binding.statement().unwrap();
        let signed = approval(
            &registry,
            20,
            KeyPurpose::MpcInput,
            statement,
            &signing_key(33),
        );
        registry.bind_service(service_binding, &signed, 20).unwrap();

        let account_binding = AccountBinding {
            operation_id: id(67),
            binding_id: id(68),
            participant_id: id(20),
            account_commitment: id(69),
            asset_id: id(70),
            kind: AccountBindingKind::Securities,
            control_proof_digest: id(71),
            valid_from: 20,
            valid_until: 800,
            expected_participant_sequence: 1,
            sequence: 0,
            active: true,
        };
        let statement = account_binding.statement().unwrap();
        let signed = approval(
            &registry,
            20,
            KeyPurpose::Settlement,
            statement,
            &signing_key(31),
        );
        registry.bind_account(account_binding, &signed, 20).unwrap();

        let mandate = StandingMandate {
            operation_id: id(72),
            mandate_id: id(73),
            participant_id: id(20),
            service_id: id(61),
            service_binding_id: id(65),
            role: MandateRole::Maker,
            account_binding_ids: vec![id(68)],
            permitted_asset_ids: vec![id(70)],
            permitted_destination_domains: vec![id(74)],
            limit_commitment: id(75),
            limit_policy_digest: id(76),
            settlement_policy_digest: id(77),
            max_active_reservations: 2,
            active_reservations: 0,
            valid_from: 20,
            valid_until: 700,
            expected_participant_sequence: 2,
            sequence: 0,
            automatic_settlement: true,
            status: MandateStatus::Active,
        };
        let statement = mandate.statement().unwrap();
        let signed = approval(
            &registry,
            20,
            KeyPurpose::Settlement,
            statement,
            &signing_key(31),
        );
        registry.create_mandate(mandate, &signed, 20).unwrap();

        let reservation = |operation, reservation, expected| MandateReservation {
            operation_id: id(operation),
            reservation_id: id(reservation),
            mandate_id: id(73),
            service_id: id(61),
            service_epoch: 1,
            account_binding_id: id(68),
            asset_id: id(70),
            amount_commitment: id(operation + 1),
            underlying_reservation_digest: id(operation + 2),
            admission_receipt_digest: ZERO,
            limit_proof_digest: id(operation + 4),
            zkpi_digest: id(operation + 5),
            expires_at: 100,
            expected_mandate_sequence: expected,
            status: ReservationStatus::Active,
            settlement_digest: ZERO,
        };
        registry
            .reserve_under_mandate(reservation(120, 121, 0), 30)
            .unwrap();
        registry
            .reserve_under_mandate(reservation(130, 131, 1), 30)
            .unwrap();
        assert_eq!(
            registry
                .reserve_under_mandate(reservation(140, 141, 2), 30)
                .unwrap_err(),
            ParticipantError::InvalidReservation
        );

        // No participant signature is requested here: the previously signed
        // mandate and the proof-carrying reservation are sufficient.
        assert!(registry
            .consume_linked_reservation(
                AutomaticReservationEvidence {
                    underlying_reservation_digest: id(122),
                    amount_commitment: id(121),
                    asset_id: id(70),
                    role: MandateRole::Maker,
                    settlement_digest: id(151),
                    transition_proof_digest: id(152),
                },
                40,
            )
            .unwrap()
            .is_some());
        registry
            .reserve_under_mandate(reservation(160, 161, 3), 40)
            .unwrap();
        assert_eq!(registry.mandates[&id_key(&id(73))].active_reservations, 2);

        // An entity must not be able to escape an already accepted trade by
        // suspending its mandate or by being revoked after the reserve was
        // admitted.  Those controls prevent new work, while the existing
        // reservations still follow the canonical settlement/release path.
        let suspend = MandateControl {
            operation_id: id(170),
            mandate_id: id(73),
            expected_mandate_sequence: 4,
            kind: MandateControlKind::Suspend,
            reason_digest: id(171),
        };
        let statement = suspend.statement().unwrap();
        let signed = approval(
            &registry,
            20,
            KeyPurpose::Settlement,
            statement,
            &signing_key(31),
        );
        registry.control_mandate(suspend, &signed).unwrap();
        registry
            .control_participant(ParticipantControl {
                operation_id: id(172),
                participant_id: id(20),
                expected_sequence: 3,
                kind: ParticipantControlKind::Revoke,
                reason_digest: id(173),
            })
            .unwrap();

        assert!(registry
            .consume_linked_reservation(
                AutomaticReservationEvidence {
                    underlying_reservation_digest: id(132),
                    amount_commitment: id(131),
                    asset_id: id(70),
                    role: MandateRole::Maker,
                    settlement_digest: id(174),
                    transition_proof_digest: id(175),
                },
                50,
            )
            .unwrap()
            .is_some());
        assert!(registry
            .release_linked_reservation(
                AutomaticReservationEvidence {
                    underlying_reservation_digest: id(162),
                    amount_commitment: id(161),
                    asset_id: id(70),
                    role: MandateRole::Maker,
                    settlement_digest: ZERO,
                    transition_proof_digest: id(176),
                },
                100,
            )
            .unwrap()
            .is_some());
        assert_eq!(registry.mandates[&id_key(&id(73))].active_reservations, 0);
        assert_eq!(
            registry.participants[&id_key(&id(20))].status,
            ParticipantStatus::Revoked
        );
        registry.validate().unwrap();
    }

    #[test]
    fn one_legal_entity_cannot_count_as_two_mpc_trust_domains() {
        let mut registry = configured();
        register(&mut registry, 10, 20, 30, &[ParticipantRole::MpcOperator]);
        let service = MpcService {
            operation_id: id(40),
            service_id: id(41),
            kind: MpcServiceKind::PrivateAnalytics,
            program_digest: id(42),
            schema_digest: id(43),
            committee_epoch: 1,
            threshold: 2,
            members: vec![
                MpcServiceMember {
                    node_id: id(50),
                    operator_participant_id: id(20),
                    public_key: signing_key(60).verifying_key().to_bytes(),
                },
                MpcServiceMember {
                    node_id: id(51),
                    operator_participant_id: id(20),
                    public_key: signing_key(61).verifying_key().to_bytes(),
                },
            ],
            valid_from: 10,
            valid_until: 900,
            sequence: 0,
            status: ServiceStatus::Active,
        };
        assert_eq!(
            registry.register_service(service, 20).unwrap_err(),
            ParticipantError::InvalidService
        );
    }

    #[test]
    fn wrong_entity_signature_and_stale_key_epoch_are_rejected() {
        let mut registry = configured();
        register(&mut registry, 10, 20, 30, &[ParticipantRole::Maker]);
        let request = RotateParticipantKey {
            operation_id: id(40),
            participant_id: id(20),
            expected_sequence: 0,
            purpose: KeyPurpose::Quote,
            new_key: PurposeKey {
                public_key: signing_key(90).verifying_key().to_bytes(),
                epoch: 2,
            },
        };
        let statement = request.statement().unwrap();
        let wrong = approval(
            &registry,
            20,
            KeyPurpose::Admin,
            statement,
            &signing_key(31),
        );
        assert_eq!(
            registry.rotate_key(request.clone(), &wrong).unwrap_err(),
            ParticipantError::InvalidEntityApproval
        );
        let valid = approval(
            &registry,
            20,
            KeyPurpose::Admin,
            statement,
            &signing_key(30),
        );
        registry.rotate_key(request, &valid).unwrap();
        assert_eq!(registry.participant(&id(20)).unwrap().keys.quote.epoch, 2);
        assert_eq!(
            registry
                .rotate_key(
                    RotateParticipantKey {
                        operation_id: id(41),
                        participant_id: id(20),
                        expected_sequence: 0,
                        purpose: KeyPurpose::Quote,
                        new_key: PurposeKey {
                            public_key: signing_key(91).verifying_key().to_bytes(),
                            epoch: 3,
                        },
                    },
                    &valid,
                )
                .unwrap_err(),
            ParticipantError::InvalidEntityApproval
        );
    }
}
