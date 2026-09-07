use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use defmi::{
    facility::{QuorumApproval, QuorumAuthorizer},
    participant::{
        AccountBinding, AccountBindingKind, EntityApproval, KeyPurpose, MandateReservation,
        MandateReservationTransition, MandateRole, MandateStatus, MpcService, MpcServiceKind,
        MpcServiceMember, ParticipantKeys, ParticipantRecord, ParticipantRole,
        ParticipantServiceBinding, ParticipantStatus, PurposeKey, RegisterParticipant,
        RegistryConfiguration, ReservationStatus, ReservationTransitionKind, ServiceStatus,
        StandingMandate,
    },
};
use serde_json::{json, Map, Value};

use crate::{state::State, transaction::TransactionEnvelope};

fn id(value: u8) -> [u8; 32] {
    [value; 32]
}

fn signing_key(value: u8) -> SigningKey {
    SigningKey::from_bytes(&id(value))
}

fn purpose_key(key: &SigningKey) -> PurposeKey {
    PurposeKey {
        public_key: key.verifying_key().to_bytes(),
        pq_public_key: zkfmi_crypto::traits::Signer::public_key(
            &zkfmi_crypto::test_support::entity_pq_signer(&key.to_bytes()),
        ),
        epoch: 1,
    }
}

struct EntityKeys {
    admin: SigningKey,
    settlement: SigningKey,
    quote: SigningKey,
    mpc_input: SigningKey,
    emergency: SigningKey,
}

impl EntityKeys {
    fn new(base: u8) -> Self {
        Self {
            admin: signing_key(base),
            settlement: signing_key(base + 1),
            quote: signing_key(base + 2),
            mpc_input: signing_key(base + 3),
            emergency: signing_key(base + 4),
        }
    }

    fn domain(&self) -> ParticipantKeys {
        ParticipantKeys {
            admin: purpose_key(&self.admin),
            settlement: purpose_key(&self.settlement),
            quote: purpose_key(&self.quote),
            mpc_input: purpose_key(&self.mpc_input),
            emergency: purpose_key(&self.emergency),
        }
    }

    fn json(&self) -> Value {
        let key = |signer: &SigningKey| {
            json!({
                "publicKey": hex::encode(signer.verifying_key().to_bytes()),
                "pqPublicKey": hex::encode(purpose_key(signer).pq_public_key),
                "epoch": 1,
            })
        };
        json!({
            "admin": key(&self.admin),
            "settlement": key(&self.settlement),
            "quote": key(&self.quote),
            "mpcInput": key(&self.mpc_input),
            "emergency": key(&self.emergency),
        })
    }
}

fn committee() -> (
    QuorumAuthorizer,
    BTreeMap<String, defmi::governance::GovernanceSigner>,
) {
    let signers = (0u8..3)
        .map(|index| {
            (
                format!("node-{index}"),
                defmi::governance::GovernanceSigner::generate(
                    &format!("node-{index}"),
                    0,
                    i64::MAX as u64,
                )
                .unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let nodes = signers
        .iter()
        .map(|(node, key)| (node.clone(), key.verifying_key()))
        .collect();
    (
        QuorumAuthorizer::new(nodes, 2, 1, "participant-test").expect("committee"),
        signers,
    )
}

fn approval_json(approval: &QuorumApproval) -> Value {
    json!({
        "statement": hex::encode(approval.statement),
        "signerEpoch": approval.signer_epoch,
        "suite": approval.suite,
        "committeeDigest": hex::encode(approval.committee_digest),
        "domain": approval.domain,
        "beforeRoot": hex::encode(approval.before_root),
        "approvals": approval.approvals.iter().map(|signed| json!({
            "nodeID": signed.node_id,
            "signature": hex::encode(&signed.signature),
        })).collect::<Vec<_>>(),
    })
}

fn apply(
    state: &mut State,
    authorizer: &QuorumAuthorizer,
    signers: &BTreeMap<String, defmi::governance::GovernanceSigner>,
    method: &str,
    mut params: Map<String, Value>,
    statement: [u8; 32],
    timestamp: u64,
) -> Result<(), String> {
    let before_root = state.root();
    let approval = authorizer.approve(statement, before_root, signers)?;
    params.insert("approval".into(), approval_json(&approval));
    params.insert(
        "expectedBeforeRoot".into(),
        Value::String(hex::encode(before_root)),
    );
    let transaction = TransactionEnvelope::new(method, Value::Object(params))?.encode()?;
    state.apply(&transaction, authorizer, timestamp)?;
    Ok(())
}

fn entity_approval_json(
    domain_id: [u8; 32],
    participant_id: [u8; 32],
    purpose: KeyPurpose,
    statement: [u8; 32],
    signer: &SigningKey,
) -> Value {
    let signature = EntityApproval::sign(
        participant_id,
        &domain_id,
        purpose,
        1,
        statement,
        signer,
        &zkfmi_crypto::test_support::entity_pq_signer(&signer.to_bytes()),
    )
    .unwrap()
    .signature;
    json!({
        "participantID": hex::encode(participant_id),
        "keyPurpose": purpose,
        "keyEpoch": 1,
        "statement": hex::encode(statement),
        "signature": hex::encode(signature),
    })
}

fn participant(
    participant_id: u8,
    credential: u8,
    roles: &[ParticipantRole],
    keys: &EntityKeys,
) -> ParticipantRecord {
    ParticipantRecord {
        participant_id: id(participant_id),
        legal_entity_credential_commitment: id(credential),
        credential_issuer_id: id(240),
        credential_scheme_digest: id(241),
        jurisdiction: "JP".into(),
        roles: roles.iter().copied().collect::<BTreeSet<_>>(),
        keys: keys.domain(),
        policy_digest: id(credential + 1),
        valid_from: 10,
        valid_until: 1_000,
        sequence: 0,
        status: ParticipantStatus::Active,
    }
}

fn participant_json(record: &ParticipantRecord, keys: &EntityKeys) -> Value {
    json!({
        "participantID": hex::encode(record.participant_id),
        "legalEntityCredentialCommitment": hex::encode(record.legal_entity_credential_commitment),
        "credentialIssuerID": hex::encode(record.credential_issuer_id),
        "credentialSchemeDigest": hex::encode(record.credential_scheme_digest),
        "jurisdiction": record.jurisdiction,
        "roles": record.roles,
        "keys": keys.json(),
        "policyDigest": hex::encode(record.policy_digest),
        "validFrom": record.valid_from,
        "validUntil": record.valid_until,
    })
}

#[test]
fn vm_registers_entity_module_and_auto_consumes_without_a_second_entity_signature() {
    let (authorizer, signers) = committee();
    let mut state = State::default();
    let domain_id = id(10);

    let configuration = RegistryConfiguration {
        operation_id: id(11),
        domain_id,
        template_digest: id(12),
        schema_digest: id(13),
        template_version: 1,
    };
    let mut params = Map::new();
    params.insert(
        "configuration".into(),
        json!({
            "operationID": hex::encode(configuration.operation_id),
            "domainID": hex::encode(configuration.domain_id),
            "templateDigest": hex::encode(configuration.template_digest),
            "schemaDigest": hex::encode(configuration.schema_digest),
            "templateVersion": configuration.template_version,
        }),
    );
    apply(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueParticipantRegistry",
        params,
        configuration.statement().unwrap(),
        10,
    )
    .unwrap();

    let maker_keys = EntityKeys::new(20);
    let maker = participant(
        30,
        31,
        &[ParticipantRole::BrokerDealer, ParticipantRole::Maker],
        &maker_keys,
    );
    let maker_registration = RegisterParticipant {
        operation_id: id(32),
        participant: maker.clone(),
    };
    let mut params = Map::new();
    params.insert(
        "registration".into(),
        json!({
            "operationID": hex::encode(maker_registration.operation_id),
            "participant": participant_json(&maker, &maker_keys),
        }),
    );
    apply(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueParticipant",
        params,
        maker_registration.statement().unwrap(),
        20,
    )
    .unwrap();

    let operator_keys = EntityKeys::new(40);
    let operator = participant(50, 51, &[ParticipantRole::MpcOperator], &operator_keys);
    let operator_registration = RegisterParticipant {
        operation_id: id(52),
        participant: operator.clone(),
    };
    let mut params = Map::new();
    params.insert(
        "registration".into(),
        json!({
            "operationID": hex::encode(operator_registration.operation_id),
            "participant": participant_json(&operator, &operator_keys),
        }),
    );
    apply(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueParticipant",
        params,
        operator_registration.statement().unwrap(),
        20,
    )
    .unwrap();

    let node_signer = signing_key(60);
    let service = MpcService {
        operation_id: id(61),
        service_id: id(62),
        kind: MpcServiceKind::QommMatching,
        program_digest: id(63),
        schema_digest: id(64),
        committee_epoch: 1,
        threshold: 1,
        members: vec![MpcServiceMember {
            node_id: id(65),
            operator_participant_id: operator.participant_id,
            public_key: node_signer.verifying_key().to_bytes(),
        }],
        valid_from: 10,
        valid_until: 900,
        sequence: 0,
        status: ServiceStatus::Active,
    };
    let mut params = Map::new();
    params.insert(
        "service".into(),
        json!({
            "operationID": hex::encode(service.operation_id),
            "serviceID": hex::encode(service.service_id),
            "kind": service.kind,
            "programDigest": hex::encode(service.program_digest),
            "schemaDigest": hex::encode(service.schema_digest),
            "committeeEpoch": service.committee_epoch,
            "threshold": service.threshold,
            "members": [{
                "nodeID": hex::encode(service.members[0].node_id),
                "operatorParticipantID": hex::encode(service.members[0].operator_participant_id),
                "publicKey": hex::encode(service.members[0].public_key),
            }],
            "validFrom": service.valid_from,
            "validUntil": service.valid_until,
        }),
    );
    apply(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueMpcService",
        params,
        service.statement().unwrap(),
        20,
    )
    .unwrap();

    let service_binding = ParticipantServiceBinding {
        operation_id: id(66),
        binding_id: id(67),
        participant_id: maker.participant_id,
        service_id: service.service_id,
        service_epoch: 1,
        input_public_key: maker_keys.mpc_input.verifying_key().to_bytes(),
        capability_digest: id(68),
        valid_from: 20,
        valid_until: 800,
        expected_participant_sequence: 0,
        sequence: 0,
        active: true,
    };
    let statement = service_binding.statement().unwrap();
    let mut params = Map::new();
    params.insert(
        "binding".into(),
        json!({
            "operationID": hex::encode(service_binding.operation_id),
            "bindingID": hex::encode(service_binding.binding_id),
            "participantID": hex::encode(service_binding.participant_id),
            "serviceID": hex::encode(service_binding.service_id),
            "serviceEpoch": service_binding.service_epoch,
            "inputPublicKey": hex::encode(service_binding.input_public_key),
            "capabilityDigest": hex::encode(service_binding.capability_digest),
            "validFrom": service_binding.valid_from,
            "validUntil": service_binding.valid_until,
            "expectedParticipantSequence": service_binding.expected_participant_sequence,
        }),
    );
    params.insert(
        "entityApproval".into(),
        entity_approval_json(
            domain_id,
            maker.participant_id,
            KeyPurpose::MpcInput,
            statement,
            &maker_keys.mpc_input,
        ),
    );
    apply(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueParticipantServiceBinding",
        params,
        statement,
        20,
    )
    .unwrap();

    let account_binding = AccountBinding {
        operation_id: id(69),
        binding_id: id(70),
        participant_id: maker.participant_id,
        account_commitment: id(71),
        asset_id: id(72),
        kind: AccountBindingKind::Securities,
        control_proof_digest: id(73),
        valid_from: 20,
        valid_until: 800,
        expected_participant_sequence: 1,
        sequence: 0,
        active: true,
    };
    let statement = account_binding.statement().unwrap();
    let mut params = Map::new();
    params.insert(
        "binding".into(),
        json!({
            "operationID": hex::encode(account_binding.operation_id),
            "bindingID": hex::encode(account_binding.binding_id),
            "participantID": hex::encode(account_binding.participant_id),
            "accountCommitment": hex::encode(account_binding.account_commitment),
            "assetID": hex::encode(account_binding.asset_id),
            "kind": account_binding.kind,
            "controlProofDigest": hex::encode(account_binding.control_proof_digest),
            "validFrom": account_binding.valid_from,
            "validUntil": account_binding.valid_until,
            "expectedParticipantSequence": account_binding.expected_participant_sequence,
        }),
    );
    params.insert(
        "entityApproval".into(),
        entity_approval_json(
            domain_id,
            maker.participant_id,
            KeyPurpose::Settlement,
            statement,
            &maker_keys.settlement,
        ),
    );
    apply(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueParticipantAccountBinding",
        params,
        statement,
        20,
    )
    .unwrap();

    let mandate = StandingMandate {
        operation_id: id(74),
        mandate_id: id(75),
        participant_id: maker.participant_id,
        service_id: service.service_id,
        service_binding_id: service_binding.binding_id,
        role: MandateRole::Maker,
        account_binding_ids: vec![account_binding.binding_id],
        permitted_asset_ids: vec![account_binding.asset_id],
        permitted_destination_domains: vec![id(76)],
        limit_commitment: id(77),
        limit_policy_digest: id(78),
        settlement_policy_digest: id(79),
        max_active_reservations: 1,
        active_reservations: 0,
        valid_from: 20,
        valid_until: 700,
        expected_participant_sequence: 2,
        sequence: 0,
        automatic_settlement: true,
        status: MandateStatus::Active,
    };
    let statement = mandate.statement().unwrap();
    let mut params = Map::new();
    params.insert(
        "mandate".into(),
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
            "automaticSettlement": true,
        }),
    );
    params.insert(
        "entityApproval".into(),
        entity_approval_json(
            domain_id,
            maker.participant_id,
            KeyPurpose::Settlement,
            statement,
            &maker_keys.settlement,
        ),
    );
    apply(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueStandingMandate",
        params,
        statement,
        20,
    )
    .unwrap();

    let reservation = MandateReservation {
        operation_id: id(80),
        reservation_id: id(81),
        mandate_id: mandate.mandate_id,
        service_id: service.service_id,
        service_epoch: 1,
        account_binding_id: account_binding.binding_id,
        asset_id: account_binding.asset_id,
        amount_commitment: id(82),
        underlying_reservation_digest: id(83),
        admission_receipt_digest: [0; 32],
        limit_proof_digest: id(85),
        zkpi_digest: id(86),
        expires_at: 100,
        expected_mandate_sequence: 0,
        status: ReservationStatus::Active,
        settlement_digest: [0; 32],
    };
    let statement = reservation.statement().unwrap();
    let reservation_json = |reservation: &MandateReservation| {
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
    };
    let mut params = Map::new();
    params.insert("reservation".into(), reservation_json(&reservation));
    apply(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueMandateReservation",
        params,
        statement,
        30,
    )
    .unwrap();

    let blocked = MandateReservation {
        operation_id: id(87),
        reservation_id: id(88),
        expected_mandate_sequence: 1,
        amount_commitment: id(89),
        underlying_reservation_digest: id(90),
        admission_receipt_digest: [0; 32],
        limit_proof_digest: id(92),
        zkpi_digest: id(93),
        ..reservation.clone()
    };
    let mut params = Map::new();
    params.insert("reservation".into(), reservation_json(&blocked));
    assert!(apply(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueMandateReservation",
        params,
        blocked.statement().unwrap(),
        30,
    )
    .unwrap_err()
    .contains("mandate reservation is invalid"));

    // This accepted transition has no entityApproval field.  It proves that
    // settlement does not wait for the Maker to sign after seeing the match.
    let transition = MandateReservationTransition {
        operation_id: id(94),
        reservation_id: reservation.reservation_id,
        expected_mandate_sequence: 1,
        kind: ReservationTransitionKind::Consume,
        settlement_digest: id(95),
        transition_proof_digest: id(96),
    };
    let mut params = Map::new();
    params.insert(
        "transition".into(),
        json!({
            "operationID": hex::encode(transition.operation_id),
            "reservationID": hex::encode(transition.reservation_id),
            "expectedMandateSequence": transition.expected_mandate_sequence,
            "kind": transition.kind,
            "settlementDigest": hex::encode(transition.settlement_digest),
            "transitionProofDigest": hex::encode(transition.transition_proof_digest),
        }),
    );
    apply(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueMandateReservationTransition",
        params,
        transition.statement().unwrap(),
        40,
    )
    .unwrap();

    assert_eq!(
        state.participant_registry.reservations[&hex::encode(reservation.reservation_id)].status,
        ReservationStatus::Consumed
    );
    assert_eq!(
        state.participant_registry.mandates[&hex::encode(mandate.mandate_id)].active_reservations,
        0
    );
    state.validate().unwrap();
}
