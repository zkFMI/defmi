//! Generic runtime contract tests. Financial application tests live with their owner.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use qomm_avalanche_vm::{
    application::{ApplicationRuntime, NoApplications},
    state::State,
    transaction::TransactionEnvelope,
};
use qomm_defmi::facility::QuorumAuthorizer;
use serde_json::{json, Map, Value};

fn authorizer() -> QuorumAuthorizer {
    let key = SigningKey::from_bytes(&[1; 32]);
    QuorumAuthorizer::new(
        BTreeMap::from([("node-0".into(), key.verifying_key())]),
        1,
        1,
        "application-boundary-test",
    )
    .unwrap()
}

struct ExampleRuntime;

impl ApplicationRuntime for ExampleRuntime {
    fn validate_state(&self, state: &State) -> Result<(), String> {
        if state
            .application_states
            .iter()
            .any(|(name, value)| name != "example.v1" || value != &[1])
        {
            return Err("invalid example state".into());
        }
        Ok(())
    }

    fn execute(
        &self,
        state: &mut State,
        params: &Map<String, Value>,
        _authorizer: &QuorumAuthorizer,
        _timestamp: u64,
    ) -> Result<[u8; 32], String> {
        let invalid = params.get("invalid") == Some(&Value::Bool(true));
        state
            .application_states
            .insert("example.v1".into(), vec![if invalid { 2 } else { 1 }]);
        if params.get("fail") == Some(&Value::Bool(true)) {
            return Err("application rejected the candidate".into());
        }
        Ok([7; 32])
    }
}

fn transaction(params: Value) -> Vec<u8> {
    TransactionEnvelope::new("defmivm.issueApplication", params)
        .unwrap()
        .encode()
        .unwrap()
}

#[test]
fn default_host_rejects_application_requests_and_stored_application_state() {
    let mut state = State::default();
    let before = state.clone();
    assert!(state
        .apply(&transaction(json!({})), &authorizer(), 1)
        .unwrap_err()
        .contains("no application runtime"));
    assert_eq!(state, before);
    state
        .application_states
        .insert("example.v1".into(), vec![1]);
    assert!(NoApplications.validate_state(&state).is_err());
}

#[test]
fn application_error_or_failed_post_validation_rolls_back_every_change() {
    for params in [json!({"fail": true}), json!({"invalid": true})] {
        let mut state = State::default();
        let before = state.encode().unwrap();
        assert!(state
            .apply_with_application(&transaction(params), &authorizer(), 1, &ExampleRuntime)
            .is_err());
        assert_eq!(state.encode().unwrap(), before);
    }
}

#[test]
fn application_state_is_committed_roundtrips_and_cannot_replay() {
    let mut state = State::default();
    let original_root = state.root();
    let bytes = transaction(json!({}));
    let receipt = state
        .apply_with_application(&bytes, &authorizer(), 1, &ExampleRuntime)
        .unwrap();
    assert_eq!(receipt.before_root, original_root);
    assert_eq!(receipt.after_root, state.root());
    assert_ne!(original_root, state.root());
    let encoded = state.encode().unwrap();
    let restored = State::decode(&encoded).unwrap();
    ExampleRuntime.validate_state(&restored).unwrap();
    assert_eq!(state, restored);
    assert!(state
        .apply_with_application(&bytes, &authorizer(), 2, &ExampleRuntime)
        .unwrap_err()
        .contains("already applied"));
    assert_eq!(state.encode().unwrap(), encoded);
    state
        .application_states
        .insert("example.v1".into(), vec![2]);
    assert_ne!(receipt.after_root, state.root());
}

#[test]
fn retired_embedded_application_state_and_rpc_names_are_rejected() {
    for key in ["aethel", "deccp"] {
        let mut saved = serde_json::to_value(State::default()).unwrap();
        saved
            .as_object_mut()
            .unwrap()
            .insert(key.into(), json!({"legacy": true}));
        assert!(State::decode(&serde_json::to_vec(&saved).unwrap())
            .unwrap_err()
            .contains("unknown field"));
    }
    for method in [
        "defmivm.issueAethelProvider",
        "defmivm.issueAethelGuarantee",
        "defmivm.issueDeccpMember",
    ] {
        assert!(TransactionEnvelope::new(method, json!({})).is_err());
    }
}
