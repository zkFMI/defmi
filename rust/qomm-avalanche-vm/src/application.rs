//! Application-owned execution plugged into a dedicated host binary.
//!
//! The default DeFMI VM has no application runtime. An application implements
//! this interface in its own repository; the VM never imports that application.
//! Implementations are trusted consensus code and must be deterministic. Their
//! methods must authorize the complete application statement and parent root.

use qomm_defmi::facility::QuorumAuthorizer;
use serde_json::{Map, Value};

use crate::state::State;

pub use crate::execution::{authorize, require_keys};

pub trait ApplicationRuntime: Send + Sync {
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
