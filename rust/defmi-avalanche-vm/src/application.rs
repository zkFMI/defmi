//! Application-owned execution plugged into a dedicated host binary.
//!
//! The default DeFMI VM has no application runtime. An application implements
//! this interface in its own repository; the VM never imports that application.
//! Implementations are trusted consensus code and must be deterministic. Their
//! methods must authorize the complete application statement and parent root.

use defmi::facility::QuorumAuthorizer;
use serde_json::{Map, Value};

use crate::state::State;

pub use crate::execution::{authorize, require_keys};

pub fn validate_host_state(application: &dyn ApplicationRuntime, state: &State) -> Result<(), String> {
    use zkpi_committee::optimistic::{ChallengeVerifier, QuoteChallengeVerifier};
    for policy in state.optimistic.policies() {
        if policy.verifier != QuoteChallengeVerifier.verifier_id()
            && application.optimistic_verifier(policy.verifier)?.verifier_id() != policy.verifier
        { return Err("stored optimistic policy has no installed verifier".into()); }
    }
    application.validate_state(state)
}

pub trait ApplicationRuntime: Send + Sync {
    /// Optional application-specific verifier. Implementations must resolve it
    /// from canonical host configuration, never from proof-supplied keys.
    fn optimistic_verifier(
        &self, _id: [u8; 32],
    ) -> Result<Box<dyn zkpi_committee::optimistic::ChallengeVerifier + '_>, String> {
        Err("this application has no installed optimistic challenge verifier".into())
    }

    /// Bind the application's public output to both its finalized claim and
    /// the MPC result consumed by a monetary fill. A host without the exact
    /// application verifier cannot settle that optimistic result.
    fn verify_optimistic_settlement(
        &self, _reference: &defmi::application_settlement::OptimisticSettlementReference,
        _mpc_result: [u8;32],
    ) -> Result<(), String> {
        Err("this application has no optimistic settlement output verifier".into())
    }

    fn verify_optimistic_transition(
        &self, _reference: &defmi::application_settlement::OptimisticSettlementReference,
    ) -> Result<(), String> {
        Err("this application has no optimistic account transition verifier".into())
    }

    /// Validate all application state on load and before and after execution.
    /// Reject namespaces the host does not implement.
    fn validate_state(&self, state: &State) -> Result<(), String>;

    /// Update a candidate ledger. The VM commits it only after all validation
    /// succeeds; an error discards both ledger and application changes.
    fn execute(
        &self,
        state: &mut State,
        params: &Map<String, Value>,
        authorizer: &QuorumAuthorizer,
        timestamp: u64,
    ) -> Result<[u8; 32], String>;
}

#[derive(Default)]
pub struct NoApplications;

impl ApplicationRuntime for NoApplications {
    fn validate_state(&self, state: &State) -> Result<(), String> {
        if state.application_states.is_empty() {
            Ok(())
        } else {
            Err("this VM has no runtime for the stored application state".into())
        }
    }

    fn execute(
        &self,
        _state: &mut State,
        _params: &Map<String, Value>,
        _authorizer: &QuorumAuthorizer,
        _timestamp: u64,
    ) -> Result<[u8; 32], String> {
        Err("this VM has no application runtime".into())
    }
}
