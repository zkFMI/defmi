use std::collections::{BTreeMap, BTreeSet};

use aethel_core::dekyx_core::{
    AnonymousPresentation, Credential, CredentialIssuer, CredentialRequest, CredentialWitness,
    IssuerDefinition, IssuerStatus, Qualification, SubjectKind,
};
use aethel_core::{
    ConfidentialArtifact, CreditDecision, DefaultAttestation, GuaranteeClaim, GuaranteeCommitment,
    GuaranteeRelease, GuaranteeStatus, LossLayer, ProviderCapability, ProviderDefinition,
    ProviderStatus, PublishCredentialStatus, ReceivableIssuance, ReceivableSeries,
    ReceivableStatus, RegisterCredentialIssuer, RegisterProvider, RegisterSeries, RegisterStream,
    SeriesPolicy, StreamState, StreamStatus, StreamTransition,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use deccp_core::{
    confidential_guarantee_facility_approval_digest, AuthorityMember, AuthoritySet,
    CcpCapitalization, ConfidentialGuaranteeFacility, EligibilityAttestation,
    GuaranteeFacilityStatus, GuaranteeHoldStatus, ParticipantAdmission,
    QuorumApproval as DeccpQuorumApproval,
};
use ed25519_dalek::{Signer, SigningKey};
use qomm_defmi::{
    facility::{NodeApproval, QuorumApproval, QuorumAuthorizer},
    note_chain::{NoteClaim, NoteClaimKind, NoteOutput},
    participant::{
        ParticipantKeys, ParticipantRecord, ParticipantRole, ParticipantStatus, PurposeKey,
        RegisterParticipant, RegistryConfiguration,
    },
    settlement_verifier::SettlementVerifierConfig,
};
use qomm_proofs::opening_envelope::{EncryptedOpeningShare, OpeningEnvelope};
use qomm_proofs::threshold_range::{
    deal_bits, joint_prove_range_from_contributions, ThresholdRangeProof,
};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::{
    deal_quorum, frost,
    receivable::{
        digest_for as receivable_digest, eligibility_relation_digest, ProviderReference,
        ReceivableExecutionContext, ReceivableInstruction, ReceivableOperation,
        ELIGIBILITY_REMAINING_CONTEXT,
    },
    receivable_wire, Bounds, PartialInstruction, AMOUNT_RANGE_CONTEXT, DEFAULT_DOMAIN,
    PRICE_RANGE_CONTEXT,
};
use rand_core::OsRng;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    execution::deccp::{
        capital_lock_tag, default_fund_lock_tag, initial_facility_state, membership_context,
        membership_scope_digest, ClearingBookRegistration, GuaranteeFacilityRegistration,
    },
    state::{
        id_key, AssetRecord, CreditFacilityRecord, CreditHoldRecord, GuarantorRecord,
        NoteClaimRecord, NoteRecord, NoteSerialRecord, OpeningEnvelopeRecord,
        SettlementVerifierRecord, State,
    },
    transaction::TransactionEnvelope,
};

pub(super) fn id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

pub(super) fn committee() -> (QuorumAuthorizer, BTreeMap<String, SigningKey>) {
    let signers = (0u8..3)
        .map(|index| {
            (
                format!("node-{index}"),
                SigningKey::from_bytes(&[index + 1; 32]),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let nodes = signers
        .iter()
        .map(|(node, key)| (node.clone(), key.verifying_key()))
        .collect();
    (
        QuorumAuthorizer::new(nodes, 2, 1, "aethel-test-chain").unwrap(),
        signers,
    )
}

pub(super) fn approval_json(approval: &QuorumApproval) -> Value {
    json!({
        "statement": hex::encode(approval.statement),
        "signerEpoch": approval.signer_epoch,
        "domain": approval.domain,
        "beforeRoot": hex::encode(approval.before_root),
        "approvals": approval.approvals.iter().map(|signed: &NodeApproval| json!({
            "nodeID": signed.node_id,
            "signature": hex::encode(signed.signature.to_bytes()),
        })).collect::<Vec<_>>(),
    })
}

pub(super) fn rpc_value<T: Serialize>(request: &T) -> Value {
    fn convert(value: &mut Value) {
        match value {
            Value::Array(values)
                if (values.len() == 32 || values.len() == 64)
                    && values.iter().all(Value::is_u64) =>
            {
                let bytes = values
                    .iter()
                    .map(|value| value.as_u64().unwrap() as u8)
                    .collect::<Vec<_>>();
                *value = Value::String(hex::encode(bytes));
            }
            Value::Array(values) => values.iter_mut().for_each(convert),
            Value::Object(map) => map.values_mut().for_each(convert),
            _ => {}
        }
    }
    let mut value = serde_json::to_value(request).unwrap();
    convert(&mut value);
    value
}

pub(super) fn apply_request<T: Serialize>(
    state: &mut State,
    authorizer: &QuorumAuthorizer,
    signers: &BTreeMap<String, SigningKey>,
    method: &str,
    request: &T,
    statement: [u8; 32],
    timestamp: u64,
) -> Result<(), String> {
    apply_fields(
        state,
        authorizer,
        signers,
        method,
        vec![("request", rpc_value(request))],
        statement,
        timestamp,
    )
}

/// Applies one transaction whose parameters are `fields` plus the committee
/// approval and the expected state root.
pub(super) fn apply_fields(
    state: &mut State,
    authorizer: &QuorumAuthorizer,
    signers: &BTreeMap<String, SigningKey>,
    method: &str,
    fields: Vec<(&str, Value)>,
    statement: [u8; 32],
    timestamp: u64,
) -> Result<(), String> {
    let before = state.root();
    let approval = authorizer.approve(statement, before, signers)?;
    let mut params = serde_json::Map::new();
    for (name, value) in fields {
        params.insert(name.to_owned(), value);
    }
    params.insert("approval".to_owned(), approval_json(&approval));
    params.insert(
        "expectedBeforeRoot".to_owned(),
        Value::String(hex::encode(before)),
    );
    let transaction = TransactionEnvelope::new(method, Value::Object(params))?.encode()?;
    state.apply(&transaction, authorizer, timestamp)?;
    Ok(())
}

/// A DeFMI cash note locked for one DeCCP purpose; returns its id and value
/// commitment, which DeCCP records as the lock and its proof digest.
pub(super) fn locked_cash_note(
    state: &mut State,
    seed: u64,
    lock_id: [u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let mut note = NoteOutput {
        note_id: [0; 32],
        asset_id: id(20),
        one_time: RistrettoPoint::mul_base(&Scalar::from(seed))
            .compress()
            .to_bytes(),
        value_commitment: RistrettoPoint::mul_base(&Scalar::from(seed + 1))
            .compress()
            .to_bytes(),
        ephemeral: RistrettoPoint::mul_base(&Scalar::from(seed + 2))
            .compress()
            .to_bytes(),
        masked_value: Scalar::from(seed + 3).to_bytes(),
        masked_blinding: Scalar::from(seed + 4).to_bytes(),
        lock_id,
    };
    note.note_id = note.derived_id().unwrap();
    note.validate().unwrap();
    state.notes.insert(
        id_key(&note.note_id),
        NoteRecord {
            asset_id: note.asset_id,
            one_time: note.one_time,
            value_commitment: note.value_commitment,
            ephemeral: note.ephemeral,
            masked_value: note.masked_value,
            masked_blinding: note.masked_blinding,
            lock_id: note.lock_id,
        },
    );
    (note.note_id, note.value_commitment)
}

#[allow(clippy::too_many_arguments)]
fn apply_confidential_request<T: Serialize, P: Serialize>(
    state: &mut State,
    authorizer: &QuorumAuthorizer,
    signers: &BTreeMap<String, SigningKey>,
    method: &str,
    request: &T,
    subject_proof: &P,
    statement: [u8; 32],
    timestamp: u64,
) -> Result<(), String> {
    let before = state.root();
    let approval = authorizer.approve(statement, before, signers)?;
    let transaction = TransactionEnvelope::new(
        method,
        json!({
            "request": rpc_value(request),
            "subjectProof": rpc_value(subject_proof),
            "approval": approval_json(&approval),
            "expectedBeforeRoot": hex::encode(before),
        }),
    )?
    .encode()?;
    state.apply(&transaction, authorizer, timestamp)?;
    Ok(())
}

fn dekyx_presentation(
    state: &State,
    credential: &Credential,
    witness: &CredentialWitness,
    qualification: &Qualification,
    artifact: ConfidentialArtifact<'_>,
) -> AnonymousPresentation {
    AnonymousPresentation::create(
        credential.clone(),
        witness,
        state.aethel.presentation_context(artifact).unwrap(),
        std::slice::from_ref(qualification),
        &mut OsRng,
    )
    .unwrap()
}

fn credit_backing(decision: &CreditDecision) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"AETHEL:CREDIT-BACKING:v1");
    hash.update(decision.model_digest);
    hash.update(decision.policy_digest);
    hash.update(decision.relation_proof_digest);
    hash.finalize().into()
}

fn apply_receivable_request(
    state: &mut State,
    authorizer: &QuorumAuthorizer,
    signers: &BTreeMap<String, SigningKey>,
    request: &ReceivableIssuance,
    zkpi: &[u8],
    timestamp: u64,
) -> Result<(), String> {
    let before = state.root();
    let statement = request.statement().map_err(|error| error.to_string())?;
    let approval = authorizer.approve(statement, before, signers)?;
    let transaction = TransactionEnvelope::new(
        "defmivm.issueAethelReceivable",
        json!({
            "request": rpc_value(request),
            "zkpi": BASE64.encode(zkpi),
            "approval": approval_json(&approval),
            "expectedBeforeRoot": hex::encode(before),
        }),
    )?
    .encode()?;
    state.apply(&transaction, authorizer, timestamp)?;
    Ok(())
}

fn apply_claim_request(
    state: &mut State,
    authorizer: &QuorumAuthorizer,
    signers: &BTreeMap<String, SigningKey>,
    request: &GuaranteeClaim,
    zkpi: &[u8],
    timestamp: u64,
) -> Result<(), String> {
    let before = state.root();
    let statement = request.statement().map_err(|error| error.to_string())?;
    let approval = authorizer.approve(statement, before, signers)?;
    let transaction = TransactionEnvelope::new(
        "defmivm.issueAethelGuaranteeClaim",
        json!({
            "request": rpc_value(request),
            "zkpi": BASE64.encode(zkpi),
            "approval": approval_json(&approval),
            "expectedBeforeRoot": hex::encode(before),
        }),
    )?
    .encode()?;
    state.apply(&transaction, authorizer, timestamp)?;
    Ok(())
}

fn frost_key_packages(
    shares: BTreeMap<frost::Identifier, frost::keys::SecretShare>,
) -> BTreeMap<frost::Identifier, frost::keys::KeyPackage> {
    shares
        .into_iter()
        .map(|(identifier, share)| {
            (
                identifier,
                frost::keys::KeyPackage::try_from(share).unwrap(),
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
        .map(|identifier| {
            let (nonce, commitment) =
                frost::round1::commit(keys[identifier].signing_share(), &mut OsRng);
            nonces.insert(*identifier, nonce);
            (*identifier, commitment)
        })
        .collect();
    let package = frost::SigningPackage::new(commitments, message);
    let shares = selected
        .iter()
        .map(|identifier| {
            (
                *identifier,
                frost::round2::sign(&package, &nonces[identifier], &keys[identifier]).unwrap(),
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
) -> ThresholdRangeProof {
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

pub(super) fn purpose_key(seed: u8) -> (PurposeKey, SigningKey) {
    let key = SigningKey::from_bytes(&id(seed));
    (
        PurposeKey {
            public_key: key.verifying_key().to_bytes(),
            epoch: 1,
        },
        key,
    )
}

pub(super) fn base_state() -> (State, SigningKey) {
    let mut state = State::default();
    state
        .participant_registry
        .configure(RegistryConfiguration {
            operation_id: id(1),
            domain_id: id(2),
            template_digest: id(3),
            schema_digest: id(4),
            template_version: 1,
        })
        .unwrap();
    let (admin, _) = purpose_key(10);
    let (settlement, _) = purpose_key(11);
    let (quote, quote_signer) = purpose_key(12);
    let (mpc_input, _) = purpose_key(13);
    let (emergency, _) = purpose_key(14);
    state
        .participant_registry
        .register_participant(
            RegisterParticipant {
                operation_id: id(5),
                participant: ParticipantRecord {
                    participant_id: id(6),
                    legal_entity_credential_commitment: id(7),
                    credential_issuer_id: id(8),
                    credential_scheme_digest: id(9),
                    jurisdiction: "SG".into(),
                    roles: [
                        ParticipantRole::StreamAttestor,
                        ParticipantRole::CreditAssessor,
                        ParticipantRole::Guarantor,
                        ParticipantRole::LiquidityProvider,
                        ParticipantRole::Servicer,
                    ]
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
                    keys: ParticipantKeys {
                        admin,
                        settlement,
                        quote,
                        mpc_input,
                        emergency,
                    },
                    policy_digest: id(15),
                    valid_from: 1,
                    valid_until: 1_000,
                    sequence: 0,
                    status: ParticipantStatus::Active,
                },
            },
            10,
        )
        .unwrap();
    state.assets.insert(
        id_key(&id(20)),
        AssetRecord {
            code: "USDC".into(),
            kind: "cash".into(),
            decimals: 6,
            terms_digest: id(21),
            active: true,
        },
    );
    state.assets.insert(
        id_key(&id(22)),
        AssetRecord {
            code: "AETH-STREAM".into(),
            kind: "security".into(),
            decimals: 6,
            terms_digest: id(23),
            active: true,
        },
    );
    state.validate().unwrap();
    (state, quote_signer)
}

#[test]
fn avalanche_state_executes_guaranteed_receivable_issue_default_and_claim() {
    let (authorizer, signers) = committee();
    let (mut state, quote_signer) = base_state();
    let (credential_admin, _) = purpose_key(205);
    let (credential_settlement, _) = purpose_key(206);
    let (credential_quote, credential_issuer_signer) = purpose_key(207);
    let (credential_mpc_input, _) = purpose_key(208);
    let (credential_emergency, _) = purpose_key(209);
    state
        .participant_registry
        .register_participant(
            RegisterParticipant {
                operation_id: id(200),
                participant: ParticipantRecord {
                    participant_id: id(201),
                    legal_entity_credential_commitment: id(202),
                    credential_issuer_id: id(203),
                    credential_scheme_digest: id(204),
                    jurisdiction: "SG".into(),
                    roles: [ParticipantRole::CredentialIssuer]
                        .into_iter()
                        .collect::<BTreeSet<_>>(),
                    keys: ParticipantKeys {
                        admin: credential_admin,
                        settlement: credential_settlement,
                        quote: credential_quote,
                        mpc_input: credential_mpc_input,
                        emergency: credential_emergency,
                    },
                    policy_digest: id(210),
                    valid_from: 1,
                    valid_until: 1_000,
                    sequence: 0,
                    status: ParticipantStatus::Active,
                },
            },
            10,
        )
        .unwrap();
    let commitment_key = Pedersen::new(b"qomm:defmi:v1");
    let eligible_value = 200u64;
    let eligible_blinding = Scalar::from(71u64);
    let eligible_commitment =
        commitment_key.commit(&Scalar::from(eligible_value), &eligible_blinding);
    let before_pledged = RistrettoPoint::identity();

    let provider = RegisterProvider {
        operation_id: id(30),
        provider: ProviderDefinition {
            provider_id: id(31),
            participant_id: id(6),
            capabilities: [ProviderCapability::StreamAttestor].into_iter().collect(),
            public_key: quote_signer.verifying_key().to_bytes(),
            policy_registry_digest: id(32),
            defmi_guarantor_id: None,
            valid_from: 1,
            valid_until: 900,
            sequence: 0,
            status: ProviderStatus::Active,
            retired_keys: Vec::new(),
        },
    };
    apply_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelProvider",
        &provider,
        provider.statement().unwrap(),
        20,
    )
    .unwrap();

    let mut stream = RegisterStream {
        operation_id: id(33),
        attestor_provider_id: id(31),
        state: StreamState {
            stream_id: id(34),
            payer_commitment: id(35),
            payee_commitment: id(36),
            settlement_asset_id: id(20),
            source_domain_digest: id(37),
            terms_digest: id(38),
            event_root: id(39),
            accrued_commitment: id(40),
            paid_commitment: [0; 32],
            eligible_commitment: eligible_commitment.compress().to_bytes(),
            pledged_commitment: before_pledged.compress().to_bytes(),
            as_of: 21,
            version: 1,
            status: StreamStatus::Active,
        },
        source_evidence_digest: id(42),
        relation_proof_digest: id(43),
        signature: Vec::new(),
    };
    stream.signature = quote_signer
        .sign(&stream.statement().unwrap())
        .to_bytes()
        .to_vec();
    apply_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelStream",
        &stream,
        stream.statement().unwrap(),
        21,
    )
    .unwrap();

    let series = RegisterSeries {
        operation_id: id(44),
        series: ReceivableSeries {
            series_id: id(45),
            aethel_domain_id: id(46),
            stream_id: id(34),
            receivable_asset_id: id(22),
            issuer_participant_id: id(6),
            policy: SeriesPolicy {
                requires_credit_decision: true,
                requires_guarantee: true,
                requires_funding_reservation: false,
                requires_confidential_subject: true,
                subject_kind: SubjectKind::LegalEntity,
                required_qualifications: vec![Qualification {
                    namespace: "jp.kyb".into(),
                    predicate_digest: id(218),
                }],
                accepted_issuer_namespace_digest: Some(id(215)),
                allow_secondary_transfer: true,
                eligibility_policy_digest: id(47),
                claim_policy_digest: id(48),
            },
            valid_from: 1,
            maturity: 800,
            sequence: 0,
            status: ReceivableStatus::Active,
        },
    };
    apply_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelSeries",
        &series,
        series.statement().unwrap(),
        22,
    )
    .unwrap();

    state.guarantors.insert(
        id_key(&id(80)),
        GuarantorRecord {
            kind: "credit_provider".into(),
            name: "Aethel test guarantor".into(),
            public_key: quote_signer.verifying_key().to_bytes(),
            risk_policy_digest: id(81),
            active: true,
        },
    );
    let aethel_operator_provider = RegisterProvider {
        operation_id: id(82),
        provider: ProviderDefinition {
            provider_id: id(83),
            participant_id: id(6),
            capabilities: [
                ProviderCapability::CreditAssessor,
                ProviderCapability::Guarantor,
                ProviderCapability::LiquidityProvider,
            ]
            .into_iter()
            .collect(),
            public_key: quote_signer.verifying_key().to_bytes(),
            policy_registry_digest: id(81),
            defmi_guarantor_id: Some(id(80)),
            valid_from: 1,
            valid_until: 900,
            sequence: 0,
            status: ProviderStatus::Active,
            retired_keys: Vec::new(),
        },
    };
    apply_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelProvider",
        &aethel_operator_provider,
        aethel_operator_provider.statement().unwrap(),
        23,
    )
    .unwrap();
    let registered_operator = state.aethel.provider(&id(83)).unwrap();
    assert!(registered_operator.has(ProviderCapability::CreditAssessor, 23));
    assert!(registered_operator.has(ProviderCapability::Guarantor, 23));
    assert!(registered_operator.has(ProviderCapability::LiquidityProvider, 23));
    assert!(!registered_operator.has(ProviderCapability::CredentialIssuer, 23));

    let credential_issuer_provider = RegisterProvider {
        operation_id: id(211),
        provider: ProviderDefinition {
            provider_id: id(212),
            participant_id: id(201),
            capabilities: [ProviderCapability::CredentialIssuer].into_iter().collect(),
            public_key: credential_issuer_signer.verifying_key().to_bytes(),
            policy_registry_digest: id(213),
            defmi_guarantor_id: None,
            valid_from: 1,
            valid_until: 900,
            sequence: 0,
            status: ProviderStatus::Active,
            retired_keys: Vec::new(),
        },
    };
    apply_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelProvider",
        &credential_issuer_provider,
        credential_issuer_provider.statement().unwrap(),
        23,
    )
    .unwrap();
    let registered_credential_issuer = state.aethel.provider(&id(212)).unwrap();
    assert!(registered_credential_issuer.has(ProviderCapability::CredentialIssuer, 23));
    assert!(!registered_credential_issuer.has(ProviderCapability::CreditAssessor, 23));

    // The credential-issuer provider vouches for a DeKYX issuer key that is
    // separate from its own quote key, then publishes an empty status list.
    let dekyx_key = SigningKey::from_bytes(&id(214));
    let dekyx_definition = IssuerDefinition {
        issuer_id: id(212),
        key_epoch: 1,
        public_key: dekyx_key.verifying_key().to_bytes(),
        supported_subjects: [SubjectKind::LegalEntity].into_iter().collect(),
        namespace_digest: id(215),
        valid_from: 1,
        valid_until: 900,
        status: IssuerStatus::Active,
    };
    let mut issuer_registration = RegisterCredentialIssuer {
        operation_id: id(216),
        provider_id: id(212),
        issuer: dekyx_definition.clone(),
        previous_epochs_valid_until: None,
        signature: Vec::new(),
    };
    issuer_registration.signature = credential_issuer_signer
        .sign(&issuer_registration.statement().unwrap())
        .to_bytes()
        .to_vec();
    apply_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelCredentialIssuer",
        &issuer_registration,
        issuer_registration.statement().unwrap(),
        23,
    )
    .unwrap();
    let dekyx_issuer = CredentialIssuer::new(dekyx_definition.clone(), dekyx_key).unwrap();
    let status_publication = PublishCredentialStatus {
        operation_id: id(217),
        status_list: dekyx_issuer.issue_status_list(1, 1, 900, vec![]).unwrap(),
    };
    apply_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelCredentialStatus",
        &status_publication,
        status_publication.statement().unwrap(),
        23,
    )
    .unwrap();
    assert!(state
        .aethel
        .credential_issuers
        .status_list(&id(212), 1)
        .is_some());

    let kyb = Qualification {
        namespace: "jp.kyb".into(),
        predicate_digest: id(218),
    };
    let subject = CredentialWitness::random(vec![kyb.clone()], &mut OsRng).unwrap();
    let credential_request = CredentialRequest {
        credential_id: id(219),
        issuer_id: id(212),
        issuer_key_epoch: 1,
        subject_kind: SubjectKind::LegalEntity,
        subject_commitment: subject.subject_commitment(),
        scope_digest: id(53),
        policy_digest: id(47),
        qualifications: vec![kyb.clone()],
        status_epoch: 1,
        valid_from: 1,
        valid_until: 800,
    };
    let subject_credential = dekyx_issuer
        .issue(
            credential_request.clone(),
            subject
                .prove_issuance(&credential_request, &mut OsRng)
                .unwrap(),
        )
        .unwrap();
    // The assessor can sign a DeKYX credential too, but it vouches for no
    // issuer key and the VM must refuse it.
    let assessor_dekyx_key = SigningKey::from_bytes(&id(220));
    let assessor_definition = IssuerDefinition {
        issuer_id: id(83),
        public_key: assessor_dekyx_key.verifying_key().to_bytes(),
        ..dekyx_definition.clone()
    };
    let assessor_issuer = CredentialIssuer::new(assessor_definition, assessor_dekyx_key).unwrap();
    let assessor_request = CredentialRequest {
        credential_id: id(221),
        issuer_id: id(83),
        ..credential_request.clone()
    };
    let assessor_credential = assessor_issuer
        .issue(
            assessor_request.clone(),
            subject
                .prove_issuance(&assessor_request, &mut OsRng)
                .unwrap(),
        )
        .unwrap();

    let (frost_shares, frost_public) = deal_quorum(7, 3, &mut OsRng).unwrap();
    let frost_keys = frost_key_packages(frost_shares);
    let verifier = SettlementVerifierConfig {
        venue_id: id(49),
        defmi_id: id(50),
        epoch: 1,
        quote_registry_digest: id(51),
        quote_eligibility_bits: 16,
        quote_span_bits: 16,
        amount_bits: 8,
        price_bits: 8,
        max_horizon: 1_000,
        frost_public_package: frost_public.serialize().unwrap(),
        valid_from: 1,
        valid_until: 900,
    };
    let verifier_statement = verifier.statement().unwrap();
    state.settlement_verifiers.insert(
        id_key(&verifier.key()),
        SettlementVerifierRecord {
            venue_id: verifier.venue_id,
            defmi_id: verifier.defmi_id,
            epoch: verifier.epoch,
            quote_registry_digest: verifier.quote_registry_digest,
            quote_eligibility_bits: verifier.quote_eligibility_bits,
            quote_span_bits: verifier.quote_span_bits,
            amount_bits: verifier.amount_bits,
            price_bits: verifier.price_bits,
            max_horizon: verifier.max_horizon,
            frost_public_package: verifier.frost_public_package.clone(),
            valid_from: verifier.valid_from,
            valid_until: verifier.valid_until,
            statement: verifier_statement,
        },
    );

    let face_value = 100u64;
    let face_blinding = Scalar::from(72u64);
    let face_commitment = commitment_key.commit(&Scalar::from(face_value), &face_blinding);
    let amount_range = threshold_range(
        &commitment_key,
        face_value,
        face_blinding,
        8,
        AMOUNT_RANGE_CONTEXT,
    );
    let price_range = threshold_range(
        &commitment_key,
        face_value,
        face_blinding,
        8,
        PRICE_RANGE_CONTEXT,
    );
    let eligibility_remaining = threshold_range(
        &commitment_key,
        eligible_value - face_value,
        eligible_blinding - face_blinding,
        8,
        ELIGIBILITY_REMAINING_CONTEXT,
    );
    let relation_proof_digest = eligibility_relation_digest(&eligibility_remaining);
    let payer_handle = RistrettoPoint::mul_base(&Scalar::from(73u64));
    let owner_handle = RistrettoPoint::mul_base(&Scalar::from(74u64));
    let partial = PartialInstruction::from_threshold_ranges(
        &commitment_key,
        &Bounds {
            amount_bits: 8,
            price_bits: 8,
            max_horizon: 1_000,
        },
        face_commitment,
        face_commitment,
        commitment_key.commit(&Scalar::from(3u64), &Scalar::from(75u64)),
        amount_range,
        price_range,
        payer_handle,
        owner_handle,
        500,
        id(52),
        relation_proof_digest,
    )
    .unwrap();
    let base_signature = frost_sign(
        &frost_keys,
        &frost_public,
        &partial.digest_for(DEFAULT_DOMAIN),
    );
    let base_instruction = partial.sealed(base_signature);

    let mut note = NoteOutput {
        note_id: [0; 32],
        asset_id: id(22),
        one_time: RistrettoPoint::mul_base(&Scalar::from(76u64))
            .compress()
            .to_bytes(),
        value_commitment: face_commitment.compress().to_bytes(),
        ephemeral: RistrettoPoint::mul_base(&Scalar::from(77u64))
            .compress()
            .to_bytes(),
        masked_value: Scalar::from(78u64).to_bytes(),
        masked_blinding: Scalar::from(79u64).to_bytes(),
        lock_id: [0; 32],
    };
    note.note_id = note.derived_id().unwrap();
    note.validate().unwrap();
    state.notes.insert(
        id_key(&note.note_id),
        NoteRecord {
            asset_id: note.asset_id,
            one_time: note.one_time,
            value_commitment: note.value_commitment,
            ephemeral: note.ephemeral,
            masked_value: note.masked_value,
            masked_blinding: note.masked_blinding,
            lock_id: note.lock_id,
        },
    );

    state.credit_facilities.insert(
        id_key(&id(84)),
        CreditFacilityRecord {
            guarantor_id: id(80),
            beneficiary_commitment: id(92),
            rail_asset_id: id(20),
            cap_commitment: face_commitment.compress().to_bytes(),
            available_commitment: [0; 32],
            held_commitment: face_commitment.compress().to_bytes(),
            outstanding_commitment: [0; 32],
            overlimit_commitment: [0; 32],
            collateral_commitment: id(93),
            risk_policy_digest: id(81),
            valid_from: 1,
            valid_until: 900,
            status: "active".into(),
            sequence: 1,
        },
    );
    state.credit_holds.insert(
        id_key(&id(85)),
        CreditHoldRecord {
            facility_id: id(84),
            query_commitment: id(94),
            amount_commitment: face_commitment.compress().to_bytes(),
            expires_at: 800,
            status: "active".into(),
            settlement_digest: [0; 32],
            created_sequence: 1,
            updated_sequence: 1,
        },
    );

    // DeCCP: the clearing book that holds the guarantor's hidden capacity.
    // The DeCCP authorities are a threshold set of their own, separate from
    // the VM committee; the CCP's capital is a cash note locked for it.
    let deccp_keys: Vec<([u8; 32], SigningKey)> = (1..=2u8)
        .map(|index| (id(230 + index), SigningKey::from_bytes(&id(240 + index))))
        .collect();
    let deccp_approve = |digest: [u8; 32]| {
        DeccpQuorumApproval::sign(
            1,
            digest,
            &[
                (deccp_keys[0].0, &deccp_keys[0].1),
                (deccp_keys[1].0, &deccp_keys[1].1),
            ],
        )
    };
    let (capital_note, capital_commitment) = locked_cash_note(&mut state, 300, capital_lock_tag());
    let clearing_book = ClearingBookRegistration {
        operation_id: id(232),
        authorities: AuthoritySet {
            epoch: 1,
            threshold: 2,
            members: deccp_keys
                .iter()
                .map(|(member_id, key)| AuthorityMember {
                    member_id: *member_id,
                    public_key: key.verifying_key().to_bytes(),
                })
                .collect(),
        },
        capitalization: CcpCapitalization {
            amount: 1_000,
            defmi_lock_id: capital_note,
            proof_digest: capital_commitment,
            valid_until: 900,
        },
    };
    apply_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueDeccpClearingBook",
        &clearing_book,
        clearing_book.statement().unwrap(),
        23,
    )
    .unwrap();

    // The guarantor joins DeCCP with a DeKYX credential for the clearing
    // membership scope. DeCCP learns a subject line, a default-fund lock, and
    // the Aethel provider id; the legal entity behind participant 6 stays in
    // the DeFMI registry.
    let member_witness = CredentialWitness::random(vec![kyb.clone()], &mut OsRng).unwrap();
    let membership_request = CredentialRequest {
        credential_id: id(233),
        issuer_id: id(212),
        issuer_key_epoch: 1,
        subject_kind: SubjectKind::LegalEntity,
        subject_commitment: member_witness.subject_commitment(),
        scope_digest: membership_scope_digest(),
        policy_digest: id(234),
        qualifications: vec![kyb.clone()],
        status_epoch: 1,
        valid_from: 1,
        valid_until: 800,
    };
    let membership_credential = dekyx_issuer
        .issue(
            membership_request.clone(),
            member_witness
                .prove_issuance(&membership_request, &mut OsRng)
                .unwrap(),
        )
        .unwrap();
    let (fund_note, fund_commitment) =
        locked_cash_note(&mut state, 310, default_fund_lock_tag(id(83)));
    let mut admission = ParticipantAdmission {
        operation_id: id(235),
        participant_id: id(83),
        settlement_participant_id: id(6),
        eligibility: EligibilityAttestation {
            provider_id: id(212),
            subject_line_id: [0; 32],
            policy_digest: id(234),
            evidence_digest: [0; 32],
            valid_until: 800,
        },
        default_fund_contribution: 100,
        default_fund_defmi_lock_id: fund_note,
        default_fund_proof_digest: fund_commitment,
        admitted_at: 23,
    };
    let membership_presentation = AnonymousPresentation::create(
        membership_credential.clone(),
        &member_witness,
        membership_context(&state.deccp.as_ref().unwrap().book, &admission),
        &[],
        &mut OsRng,
    )
    .unwrap();
    admission.eligibility.subject_line_id = membership_presentation.subject_line_id().unwrap();
    admission.eligibility.evidence_digest = membership_presentation.digest().unwrap();
    let admission_statement = admission.statement_digest().unwrap();
    // A membership credential the assessor signed for itself names an issuer
    // that vouches for no DeKYX key; the VM refuses it before DeCCP sees it.
    let self_issued_request = CredentialRequest {
        credential_id: id(237),
        issuer_id: id(83),
        ..membership_request.clone()
    };
    let self_issued = assessor_issuer
        .issue(
            self_issued_request.clone(),
            member_witness
                .prove_issuance(&self_issued_request, &mut OsRng)
                .unwrap(),
        )
        .unwrap();
    let mut self_vouched = admission.clone();
    self_vouched.eligibility.provider_id = id(83);
    let self_presentation = AnonymousPresentation::create(
        self_issued,
        &member_witness,
        membership_context(&state.deccp.as_ref().unwrap().book, &self_vouched),
        &[],
        &mut OsRng,
    )
    .unwrap();
    self_vouched.eligibility.subject_line_id = self_presentation.subject_line_id().unwrap();
    self_vouched.eligibility.evidence_digest = self_presentation.digest().unwrap();
    let before_self_vouched = state.root();
    assert!(apply_fields(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueDeccpMember",
        vec![
            ("request", rpc_value(&self_vouched)),
            ("subjectProof", rpc_value(&self_presentation)),
            (
                "deccpApproval",
                rpc_value(&deccp_approve(self_vouched.statement_digest().unwrap())),
            ),
        ],
        self_vouched.statement_digest().unwrap(),
        23,
    )
    .is_err());
    assert_eq!(state.root(), before_self_vouched);
    apply_fields(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueDeccpMember",
        vec![
            ("request", rpc_value(&admission)),
            ("subjectProof", rpc_value(&membership_presentation)),
            (
                "deccpApproval",
                rpc_value(&deccp_approve(admission_statement)),
            ),
        ],
        admission_statement,
        23,
    )
    .unwrap();

    // DeCCP clears the DeFMI credit facility as a confidential facility:
    // same id, the cap and beneficiary as commitments, no amount anywhere.
    let facility = ConfidentialGuaranteeFacility {
        facility_id: id(84),
        guarantor_id: id(83),
        beneficiary_subject_line_id: id(92),
        settlement_asset_id: id(20),
        capacity_commitment: face_commitment.compress().to_bytes(),
        latest_facility_state_digest: initial_facility_state(
            id(84),
            state.credit_facilities.get(&id_key(&id(84))).unwrap(),
        ),
        defmi_facility_id: id(84),
        policy_digest: id(48),
        valid_until: 800,
        sequence: 0,
        status: GuaranteeFacilityStatus::Active,
    };
    let facility_statement = confidential_guarantee_facility_approval_digest(&id(236), &facility);
    apply_fields(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueDeccpGuaranteeFacility",
        vec![
            (
                "request",
                rpc_value(&GuaranteeFacilityRegistration {
                    operation_id: id(236),
                    facility,
                }),
            ),
            (
                "deccpApproval",
                rpc_value(&deccp_approve(facility_statement)),
            ),
        ],
        facility_statement,
        23,
    )
    .unwrap();

    let current_stream = state.aethel.stream(&id(34)).unwrap().state.clone();
    let mut credit_decision = CreditDecision {
        operation_id: id(180),
        decision_id: id(181),
        request_id: id(53),
        provider_id: id(83),
        series_id: id(45),
        stream_state_version: current_stream.version,
        stream_state_root: current_stream.root().unwrap(),
        model_digest: id(182),
        policy_digest: id(47),
        decision_terms_commitment: current_stream.eligible_commitment,
        relation_proof_digest: id(183),
        valid_until: 800,
        nonce: id(184),
        signature: Vec::new(),
    };
    credit_decision.signature = quote_signer
        .sign(&credit_decision.statement().unwrap())
        .to_bytes()
        .to_vec();
    let assessor_subject_proof = dekyx_presentation(
        &state,
        &assessor_credential,
        &subject,
        &kyb,
        ConfidentialArtifact::CreditDecision(&credit_decision),
    );
    let subject_proof = dekyx_presentation(
        &state,
        &subject_credential,
        &subject,
        &kyb,
        ConfidentialArtifact::CreditDecision(&credit_decision),
    );
    let before_unauthorized_issuer = state.root();
    assert!(apply_confidential_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelCreditDecision",
        &credit_decision,
        &assessor_subject_proof,
        credit_decision.statement().unwrap(),
        24,
    )
    .is_err());
    assert_eq!(state.root(), before_unauthorized_issuer);
    apply_confidential_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelCreditDecision",
        &credit_decision,
        &subject_proof,
        credit_decision.statement().unwrap(),
        24,
    )
    .unwrap();
    let private_binding = state.aethel.confidential_subject(&id(53)).unwrap();
    assert_eq!(private_binding.issuer_provider_id, id(212));
    assert_eq!(
        private_binding.subject_commitment,
        subject.subject_commitment()
    );
    assert_eq!(private_binding.subject_nullifier, subject_proof.nullifier);

    let mut guarantee = GuaranteeCommitment {
        operation_id: id(86),
        guarantee_id: id(87),
        request_id: id(53),
        provider_id: id(83),
        series_id: id(45),
        stream_state_version: current_stream.version,
        stream_state_root: current_stream.root().unwrap(),
        credit_decision_id: Some(id(181)),
        defmi_facility_id: id(84),
        defmi_hold_id: id(85),
        coverage_commitment: face_commitment.compress().to_bytes(),
        loss_layer: LossLayer::FirstLoss,
        guarantee_terms_digest: id(88),
        claim_policy_digest: id(48),
        relation_proof_digest: id(89),
        valid_until: 800,
        nonce: id(90),
        signature: Vec::new(),
        status: GuaranteeStatus::Available,
        bound_issuance_id: None,
    };
    guarantee.signature = quote_signer
        .sign(&guarantee.statement().unwrap())
        .to_bytes()
        .to_vec();
    let guarantee_subject_proof = dekyx_presentation(
        &state,
        &subject_credential,
        &subject,
        &kyb,
        ConfidentialArtifact::Guarantee(&guarantee),
    );
    assert_eq!(guarantee_subject_proof.nullifier, subject_proof.nullifier);
    assert_ne!(
        guarantee_subject_proof.digest().unwrap(),
        subject_proof.digest().unwrap()
    );
    // The decision's transcript is bound to the decision and cannot be moved
    // onto the guarantee.
    let before_moved_proof = state.root();
    assert!(apply_confidential_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelGuarantee",
        &guarantee,
        &subject_proof,
        guarantee.statement().unwrap(),
        25,
    )
    .is_err());
    assert_eq!(state.root(), before_moved_proof);
    let mut tampered_subject_proof = guarantee_subject_proof.clone();
    tampered_subject_proof.nullifier[0] ^= 1;
    let before_tamper = state.root();
    assert!(apply_confidential_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelGuarantee",
        &guarantee,
        &tampered_subject_proof,
        guarantee.statement().unwrap(),
        25,
    )
    .is_err());
    assert_eq!(state.root(), before_tamper);
    apply_confidential_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelGuarantee",
        &guarantee,
        &guarantee_subject_proof,
        guarantee.statement().unwrap(),
        25,
    )
    .unwrap();

    // DeCCP now holds the reservation for the guarantee: hidden capacity moved
    // by one DeFMI-attested transition, keyed by the guarantee id.
    {
        let book = &state.deccp.as_ref().unwrap().book;
        let hold = book.confidential_guarantee_hold(&id(87)).unwrap();
        assert_eq!(hold.status, GuaranteeHoldStatus::Reserved);
        assert_eq!(hold.defmi_hold_id, id(85));
        assert_eq!(
            hold.coverage_commitment,
            face_commitment.compress().to_bytes()
        );
        assert_eq!(
            book.confidential_guarantee_facility(&id(84))
                .unwrap()
                .sequence,
            1
        );
    }
    // A guarantee on a hold DeCCP does not clear is refused before Aethel
    // records anything.
    state.credit_holds.insert(
        id_key(&id(131)),
        CreditHoldRecord {
            facility_id: id(84),
            query_commitment: id(94),
            amount_commitment: face_commitment.compress().to_bytes(),
            expires_at: 800,
            status: "active".into(),
            settlement_digest: [0; 32],
            created_sequence: 2,
            updated_sequence: 2,
        },
    );
    let mut second_guarantee = GuaranteeCommitment {
        operation_id: id(133),
        guarantee_id: id(130),
        defmi_hold_id: id(131),
        nonce: id(132),
        signature: Vec::new(),
        ..guarantee.clone()
    };
    second_guarantee.signature = quote_signer
        .sign(&second_guarantee.statement().unwrap())
        .to_bytes()
        .to_vec();
    let second_guarantee_proof = dekyx_presentation(
        &state,
        &subject_credential,
        &subject,
        &kyb,
        ConfidentialArtifact::Guarantee(&second_guarantee),
    );
    apply_confidential_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelGuarantee",
        &second_guarantee,
        &second_guarantee_proof,
        second_guarantee.statement().unwrap(),
        25,
    )
    .unwrap();
    // The guarantor withdraws the second guarantee once DeFMI released its
    // hold; DeCCP returns the capacity through that receipt and Aethel marks
    // the commitment released. A release without the DeFMI release is refused.
    let mut release = GuaranteeRelease {
        operation_id: id(135),
        guarantee_id: id(130),
        provider_id: id(83),
        defmi_settlement_digest: id(134),
        relation_proof_digest: id(136),
        released_at: 25,
        signature: Vec::new(),
    };
    release.signature = quote_signer
        .sign(&release.statement().unwrap())
        .to_bytes()
        .to_vec();
    let before_premature_release = state.root();
    assert!(apply_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelGuaranteeRelease",
        &release,
        release.statement().unwrap(),
        25,
    )
    .is_err());
    assert_eq!(state.root(), before_premature_release);
    let released_hold = state.credit_holds.get_mut(&id_key(&id(131))).unwrap();
    released_hold.status = "released".into();
    released_hold.settlement_digest = id(134);
    released_hold.updated_sequence = 3;
    apply_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelGuaranteeRelease",
        &release,
        release.statement().unwrap(),
        25,
    )
    .unwrap();
    {
        let book = &state.deccp.as_ref().unwrap().book;
        let hold = book.confidential_guarantee_hold(&id(130)).unwrap();
        assert_eq!(hold.status, GuaranteeHoldStatus::Released);
        assert_eq!(hold.defmi_settlement_receipt, Some(id(134)));
        assert_eq!(
            book.confidential_guarantee_facility(&id(84))
                .unwrap()
                .sequence,
            3
        );
        assert_eq!(
            state
                .aethel
                .guarantees
                .get(&hex::encode(id(130)))
                .unwrap()
                .status,
            GuaranteeStatus::Released
        );
    }

    let before_stream = state.aethel.stream(&id(34)).unwrap().state.clone();
    let after_stream = before_stream
        .valid_issuance_successor(face_commitment.compress().to_bytes())
        .unwrap();
    let context = ReceivableExecutionContext {
        operation: ReceivableOperation::Issue,
        venue_id: verifier.venue_id,
        defmi_id: verifier.defmi_id,
        verifier_epoch: verifier.epoch,
        aethel_domain_id: id(46),
        request_id: id(53),
        action_id: id(54),
        series_id: id(45),
        stream_id: id(34),
        stream_state_version: before_stream.version,
        before_stream_state_root: before_stream.root().unwrap(),
        after_stream_state_root: after_stream.root().unwrap(),
        eligible_commitment: before_stream.eligible_commitment,
        before_pledged_commitment: before_stream.pledged_commitment,
        after_pledged_commitment: after_stream.pledged_commitment,
        receivable_note_id: note.note_id,
        settlement_asset_id: id(20),
        credit: ProviderReference {
            artifact_id: id(181),
            provider_id: id(83),
            backing_id: credit_backing(&credit_decision),
        },
        guarantee: ProviderReference {
            artifact_id: id(87),
            provider_id: id(83),
            backing_id: id(85),
        },
        funding: ProviderReference::absent(),
        policy_digest: id(47),
        relation_proof_digest,
        operation_nullifier: id(55),
        before_aethel_root: state.aethel.root().unwrap(),
    };
    let authorization = frost_sign(
        &frost_keys,
        &frost_public,
        &receivable_digest(&base_instruction, &context, DEFAULT_DOMAIN).unwrap(),
    );
    let zkpi = receivable_wire::encode(&ReceivableInstruction {
        instruction: base_instruction,
        context,
        eligibility_remaining: Some(eligibility_remaining),
        authorization,
    });
    let issuance = ReceivableIssuance {
        operation_id: id(56),
        issuance_id: id(54),
        request_id: id(53),
        series_id: id(45),
        note_id: note.note_id,
        owner_commitment: owner_handle.compress().to_bytes(),
        face_value_commitment: face_commitment.compress().to_bytes(),
        before_stream_state_version: before_stream.version,
        before_stream_state_root: before_stream.root().unwrap(),
        after_pledged_commitment: after_stream.pledged_commitment,
        allocation_nullifier: id(55),
        credit_decision_id: Some(id(181)),
        guarantee_id: Some(id(87)),
        funding_quote_id: None,
        relation_proof_digest,
        zkpi_digest: Sha256::digest(&zkpi).into(),
        issued_at: 25,
    };
    apply_receivable_request(&mut state, &authorizer, &signers, &issuance, &zkpi, 25).unwrap();

    let servicer_provider = RegisterProvider {
        operation_id: id(95),
        provider: ProviderDefinition {
            provider_id: id(96),
            participant_id: id(6),
            capabilities: [ProviderCapability::Servicer].into_iter().collect(),
            public_key: quote_signer.verifying_key().to_bytes(),
            policy_registry_digest: id(97),
            defmi_guarantor_id: None,
            valid_from: 1,
            valid_until: 900,
            sequence: 0,
            status: ProviderStatus::Active,
            retired_keys: Vec::new(),
        },
    };
    apply_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelProvider",
        &servicer_provider,
        servicer_provider.statement().unwrap(),
        26,
    )
    .unwrap();

    let current_stream = state.aethel.stream(&id(34)).unwrap().state.clone();
    let mut defaulted_stream = current_stream.clone();
    defaulted_stream.event_root = id(101);
    defaulted_stream.as_of = 26;
    defaulted_stream.version += 1;
    defaulted_stream.status = StreamStatus::Defaulted;
    let mut stream_transition = StreamTransition {
        operation_id: id(98),
        attestor_provider_id: id(31),
        before_state_root: current_stream.root().unwrap(),
        after_state: defaulted_stream,
        source_evidence_digest: id(99),
        relation_proof_digest: id(100),
        signature: Vec::new(),
    };
    stream_transition.signature = quote_signer
        .sign(&stream_transition.statement().unwrap())
        .to_bytes()
        .to_vec();
    apply_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelStreamTransition",
        &stream_transition,
        stream_transition.statement().unwrap(),
        26,
    )
    .unwrap();

    let defaulted_stream = state.aethel.stream(&id(34)).unwrap().state.clone();
    let mut default = DefaultAttestation {
        operation_id: id(102),
        attestation_id: id(103),
        provider_id: id(96),
        stream_id: id(34),
        stream_state_version: defaulted_stream.version,
        stream_state_root: defaulted_stream.root().unwrap(),
        event_digest: id(104),
        reason_digest: id(105),
        observed_at: 27,
        signature: Vec::new(),
    };
    default.signature = quote_signer
        .sign(&default.statement().unwrap())
        .to_bytes()
        .to_vec();
    apply_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelDefault",
        &default,
        default.statement().unwrap(),
        27,
    )
    .unwrap();

    let settlement_digest = id(106);
    let guarantee_hold = state.credit_holds.get_mut(&id_key(&id(85))).unwrap();
    guarantee_hold.status = "consumed".into();
    guarantee_hold.settlement_digest = settlement_digest;
    guarantee_hold.updated_sequence = 2;
    let opening_envelope = OpeningEnvelope::new(
        id(107),
        1,
        RistrettoPoint::mul_base(&Scalar::from(108u64)),
        vec![EncryptedOpeningShare {
            party: 1,
            ephemeral: RistrettoPoint::mul_base(&Scalar::from(109u64)),
            masked_value: Scalar::from(110u64),
            masked_blinding: Scalar::from(111u64),
        }],
    )
    .unwrap();
    let mut delivery = NoteClaim {
        claim_id: [0; 32],
        asset_id: id(20),
        value_commitment: face_commitment.compress().to_bytes(),
        recipient_commitment: owner_handle.compress().to_bytes(),
        source_hold_id: id(85),
        kind: NoteClaimKind::Delivery,
        opening_envelope: opening_envelope.clone(),
    };
    delivery.claim_id = delivery.derived_id().unwrap();
    delivery.validate().unwrap();
    state.note_claims.insert(
        id_key(&delivery.claim_id),
        NoteClaimRecord {
            asset_id: delivery.asset_id,
            value_commitment: delivery.value_commitment,
            recipient_commitment: delivery.recipient_commitment,
            source_hold_id: delivery.source_hold_id,
            kind: delivery.kind.as_str().into(),
            opening_envelope: OpeningEnvelopeRecord::from_domain(&opening_envelope).unwrap(),
            status: "active".into(),
            settlement_digest,
            materialization: [0; 32],
        },
    );
    state.note_serials.insert(
        id_key(&id(112)),
        NoteSerialRecord {
            deadline: 800,
            asset_id: id(22),
            ring_root: id(113),
            statement: settlement_digest,
        },
    );

    let claim_relation_proof_digest = id(114);
    let claim_partial = PartialInstruction::from_threshold_ranges(
        &commitment_key,
        &Bounds {
            amount_bits: 8,
            price_bits: 8,
            max_horizon: 1_000,
        },
        face_commitment,
        face_commitment,
        commitment_key.commit(&Scalar::from(3u64), &Scalar::from(115u64)),
        threshold_range(
            &commitment_key,
            face_value,
            face_blinding,
            8,
            AMOUNT_RANGE_CONTEXT,
        ),
        threshold_range(
            &commitment_key,
            face_value,
            face_blinding,
            8,
            PRICE_RANGE_CONTEXT,
        ),
        RistrettoPoint::mul_base(&Scalar::from(115u64)),
        owner_handle,
        500,
        id(116),
        claim_relation_proof_digest,
    )
    .unwrap();
    let claim_base_signature = frost_sign(
        &frost_keys,
        &frost_public,
        &claim_partial.digest_for(DEFAULT_DOMAIN),
    );
    let claim_base = claim_partial.sealed(claim_base_signature);
    let claim_context = ReceivableExecutionContext {
        operation: ReceivableOperation::ClaimGuarantee,
        venue_id: verifier.venue_id,
        defmi_id: verifier.defmi_id,
        verifier_epoch: verifier.epoch,
        aethel_domain_id: id(46),
        request_id: id(53),
        action_id: id(117),
        series_id: id(45),
        stream_id: id(34),
        stream_state_version: defaulted_stream.version,
        before_stream_state_root: defaulted_stream.root().unwrap(),
        after_stream_state_root: defaulted_stream.root().unwrap(),
        eligible_commitment: defaulted_stream.eligible_commitment,
        before_pledged_commitment: defaulted_stream.pledged_commitment,
        after_pledged_commitment: defaulted_stream.pledged_commitment,
        receivable_note_id: note.note_id,
        settlement_asset_id: id(20),
        credit: ProviderReference {
            artifact_id: id(181),
            provider_id: id(83),
            backing_id: credit_backing(&credit_decision),
        },
        guarantee: ProviderReference {
            artifact_id: id(87),
            provider_id: id(83),
            backing_id: id(85),
        },
        funding: ProviderReference::absent(),
        policy_digest: id(48),
        relation_proof_digest: claim_relation_proof_digest,
        operation_nullifier: id(117),
        before_aethel_root: state.aethel.root().unwrap(),
    };
    let claim_authorization = frost_sign(
        &frost_keys,
        &frost_public,
        &receivable_digest(&claim_base, &claim_context, DEFAULT_DOMAIN).unwrap(),
    );
    let claim_zkpi = receivable_wire::encode(&ReceivableInstruction {
        instruction: claim_base,
        context: claim_context,
        eligibility_remaining: None,
        authorization: claim_authorization,
    });
    let claim = GuaranteeClaim {
        operation_id: id(118),
        claim_id: id(117),
        guarantee_id: id(87),
        issuance_id: id(54),
        default_attestation_id: id(103),
        claim_amount_commitment: face_commitment.compress().to_bytes(),
        recovery_recipient_commitment: owner_handle.compress().to_bytes(),
        defmi_settlement_digest: settlement_digest,
        relation_proof_digest: claim_relation_proof_digest,
        zkpi_digest: Sha256::digest(&claim_zkpi).into(),
        claimed_at: 28,
    };
    apply_claim_request(&mut state, &authorizer, &signers, &claim, &claim_zkpi, 28).unwrap();

    assert!(state.aethel.providers.contains_key(&hex::encode(id(31))));
    assert!(state.aethel.streams.contains_key(&hex::encode(id(34))));
    assert!(state.aethel.series.contains_key(&hex::encode(id(45))));
    assert!(state.aethel.issuances.contains_key(&hex::encode(id(54))));
    assert_eq!(
        state
            .aethel
            .guarantees
            .get(&hex::encode(id(87)))
            .unwrap()
            .status,
        GuaranteeStatus::Claimed
    );
    assert!(state
        .aethel
        .guarantee_claims
        .contains_key(&hex::encode(id(117))));
    assert_eq!(
        state
            .aethel
            .stream(&id(34))
            .unwrap()
            .state
            .pledged_commitment,
        face_commitment.compress().to_bytes()
    );
    assert_eq!(state.aethel.stream(&id(34)).unwrap().state.version, 3);
    // Ten Aethel transactions, the DeKYX issuer registration and status
    // publication, the three DeCCP transactions, and the second guarantee
    // with its release.
    assert_eq!(state.transition_count, 19);
    state.validate().unwrap();

    // DeCCP consumed the bound hold through the claim's DeFMI settlement, and
    // what it persisted carries commitments, digests, a subject line, and
    // sequence numbers: no guarantee amount and no legal entity.
    let clearing = state.deccp.as_ref().unwrap();
    let consumed = clearing.book.confidential_guarantee_hold(&id(87)).unwrap();
    assert_eq!(consumed.status, GuaranteeHoldStatus::Consumed);
    assert_eq!(consumed.bound_exposure_id, Some(id(54)));
    assert_eq!(consumed.defmi_settlement_receipt, Some(settlement_digest));
    let facility = clearing
        .book
        .confidential_guarantee_facility(&id(84))
        .unwrap();
    assert_eq!(facility.sequence, 4);
    let member = clearing.book.participant(&id(83)).unwrap();
    assert_eq!(
        member.eligibility.subject_line_id,
        membership_presentation.subject_line_id().unwrap()
    );
    let snapshot = serde_json::to_value(clearing).unwrap();
    for record in [
        &snapshot["confidentialGuaranteeFacilities"][&hex::encode(id(84))],
        &snapshot["confidentialGuaranteeHolds"][&hex::encode(id(87))],
        &snapshot["participants"][&hex::encode(id(83))],
    ] {
        let object = record.as_object().unwrap();
        assert!(object.keys().all(|key| {
            let key = key.to_ascii_lowercase();
            !key.contains("amount")
                && (!key.contains("capacity") || key.ends_with("commitment"))
                && !key.contains("legal")
                && !key.contains("name")
        }));
    }
    let persisted = serde_json::to_string(&snapshot).unwrap();
    assert!(!persisted.contains(&hex::encode(id(7))));
    assert!(!persisted.contains(&hex::encode(id(202))));
    // The clearing book survives the consensus encoding round trip and is
    // rebuilt only through DeCCP's own invariants.
    let encoded = state.encode().unwrap();
    assert_eq!(State::decode(&encoded).unwrap(), state);
}
