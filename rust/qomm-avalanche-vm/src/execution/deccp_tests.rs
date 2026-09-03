//! Aethel provider key rotation and status control on the Avalanche VM.
//!
//! The DeCCP guarantee path itself is exercised end to end in
//! `aethel_tests`; this file covers the provider-control transactions that
//! sit beside it.

use std::collections::BTreeMap;

use aethel_core::{
    ProviderCapability, ProviderDefinition, ProviderStatus, RegisterProvider, RegisterStream,
    RotateProviderKey, SetProviderStatus, StreamState, StreamStatus, StreamTransition,
};
use ed25519_dalek::{Signer, SigningKey};
use qomm_defmi::{
    facility::QuorumAuthorizer,
    participant::{EntityApproval, KeyPurpose, PurposeKey, RotateParticipantKey},
};

use super::aethel_tests::{apply_request, base_state, committee, id, purpose_key};
use crate::state::State;

fn initial_stream() -> StreamState {
    StreamState {
        stream_id: id(34),
        payer_commitment: id(35),
        payee_commitment: id(36),
        settlement_asset_id: id(20),
        source_domain_digest: id(37),
        terms_digest: id(38),
        event_root: id(39),
        accrued_commitment: id(40),
        paid_commitment: [0; 32],
        eligible_commitment: id(41),
        pledged_commitment: [0; 32],
        as_of: 21,
        version: 1,
        status: StreamStatus::Active,
    }
}

fn signed_transition(
    state: &State,
    signer: &SigningKey,
    operation: u8,
    as_of: u64,
) -> StreamTransition {
    let current = state.aethel.stream(&id(34)).unwrap().state.clone();
    let mut next = current.clone();
    next.event_root = id(operation);
    next.as_of = as_of;
    next.version += 1;
    let mut transition = StreamTransition {
        operation_id: id(operation),
        attestor_provider_id: id(31),
        before_state_root: current.root().unwrap(),
        after_state: next,
        source_evidence_digest: id(42),
        relation_proof_digest: id(43),
        signature: Vec::new(),
    };
    transition.signature = signer
        .sign(&transition.statement().unwrap())
        .to_bytes()
        .to_vec();
    transition
}

fn apply_transition(
    state: &mut State,
    authorizer: &QuorumAuthorizer,
    signers: &BTreeMap<String, SigningKey>,
    transition: &StreamTransition,
    timestamp: u64,
) -> Result<(), String> {
    apply_request(
        state,
        authorizer,
        signers,
        "defmivm.issueAethelStreamTransition",
        transition,
        transition.statement().unwrap(),
        timestamp,
    )
}

fn signed_rotation(
    next: &SigningKey,
    operation: u8,
    expected_sequence: u64,
    at: u64,
) -> RotateProviderKey {
    let mut rotation = RotateProviderKey {
        operation_id: id(operation),
        provider_id: id(31),
        next_public_key: next.verifying_key().to_bytes(),
        expected_sequence,
        rotated_at: at,
        signature: Vec::new(),
    };
    rotation.signature = next
        .sign(&rotation.statement().unwrap())
        .to_bytes()
        .to_vec();
    rotation
}

#[test]
fn provider_key_rotation_follows_the_participant_registry_and_keeps_recorded_artifacts() {
    let (authorizer, signers) = committee();
    let (mut state, quote_signer) = base_state();
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
        state: initial_stream(),
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

    // Aethel cannot move the provider to a key the DeFMI participant registry
    // does not hold: the registry's admin key is the rotation authority.
    let next = SigningKey::from_bytes(&id(120));
    let rotation = signed_rotation(&next, 121, 0, 22);
    let before_unregistered = state.root();
    assert!(apply_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelProviderKeyRotation",
        &rotation,
        rotation.statement().unwrap(),
        22,
    )
    .is_err());
    assert_eq!(state.root(), before_unregistered);

    let (_, admin) = purpose_key(10);
    let registry_rotation = RotateParticipantKey {
        operation_id: id(122),
        participant_id: id(6),
        expected_sequence: 0,
        purpose: KeyPurpose::Quote,
        new_key: PurposeKey {
            public_key: next.verifying_key().to_bytes(),
            epoch: 2,
        },
    };
    let registry_statement = registry_rotation.statement().unwrap();
    let entity_approval = EntityApproval {
        participant_id: id(6),
        key_purpose: KeyPurpose::Admin,
        key_epoch: 1,
        statement: registry_statement,
        signature: admin
            .sign(&EntityApproval::signing_body(
                &id(2),
                KeyPurpose::Admin,
                1,
                &registry_statement,
            ))
            .to_bytes()
            .to_vec(),
    };
    state
        .participant_registry
        .rotate_key(registry_rotation, &entity_approval)
        .unwrap();
    // Between the registry rotation and the Aethel rotation the provider's
    // recorded key no longer matches its participant, so it can attest
    // nothing; nothing it recorded earlier is disturbed.
    let stale = signed_transition(&state, &quote_signer, 123, 22);
    assert!(apply_transition(&mut state, &authorizer, &signers, &stale, 22).is_err());
    state.validate().unwrap();

    apply_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelProviderKeyRotation",
        &rotation,
        rotation.statement().unwrap(),
        22,
    )
    .unwrap();
    let rotated = state.aethel.provider(&id(31)).unwrap().clone();
    assert_eq!(rotated.public_key, next.verifying_key().to_bytes());
    assert_eq!(rotated.retired_keys.len(), 1);
    assert_eq!(rotated.sequence, 1);
    assert_eq!(
        rotated.registration_key(),
        quote_signer.verifying_key().to_bytes()
    );
    // The retired key attests nothing new; the next key does; the stream the
    // retired key registered is still part of a valid, re-decodable state.
    let old_key = signed_transition(&state, &quote_signer, 124, 23);
    assert!(apply_transition(&mut state, &authorizer, &signers, &old_key, 23).is_err());
    let new_key = signed_transition(&state, &next, 124, 23);
    apply_transition(&mut state, &authorizer, &signers, &new_key, 23).unwrap();
    assert_eq!(state.aethel.stream(&id(34)).unwrap().state.version, 2);
    let encoded = state.encode().unwrap();
    assert_eq!(State::decode(&encoded).unwrap(), state);

    // Suspension by quorum stops the provider; reinstatement resumes it.
    let suspend = SetProviderStatus {
        operation_id: id(125),
        provider_id: id(31),
        status: ProviderStatus::Suspended,
        expected_sequence: 1,
        effective_at: 24,
    };
    apply_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelProviderStatus",
        &suspend,
        suspend.statement().unwrap(),
        24,
    )
    .unwrap();
    let while_suspended = signed_transition(&state, &next, 126, 24);
    assert!(apply_transition(&mut state, &authorizer, &signers, &while_suspended, 24).is_err());
    let reinstate = SetProviderStatus {
        operation_id: id(127),
        provider_id: id(31),
        status: ProviderStatus::Active,
        expected_sequence: 2,
        effective_at: 25,
    };
    apply_request(
        &mut state,
        &authorizer,
        &signers,
        "defmivm.issueAethelProviderStatus",
        &reinstate,
        reinstate.statement().unwrap(),
        25,
    )
    .unwrap();
    let resumed = signed_transition(&state, &next, 128, 25);
    apply_transition(&mut state, &authorizer, &signers, &resumed, 25).unwrap();
    assert_eq!(state.aethel.stream(&id(34)).unwrap().state.version, 3);
    assert_eq!(state.transition_count, 7);
    state.validate().unwrap();
}
