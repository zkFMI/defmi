//! Application SDK for zkPI-authorized workflows that settle on DeFMI.
//!
//! The SDK deliberately sits above the cryptographic and ledger crates. It
//! gives applications a stable identity, binds one exact distributed
//! execution to that identity, and accepts settlement only after canonical
//! DeFMI state has been read back. QOMM is the first adapter; OCLOB is a
//! distinct application using the same boundaries.

#![forbid(unsafe_code)]

pub mod application;
pub mod execution;
pub mod finality;

/// Durable legal-entity request queue. Applications use this facade instead
/// of depending on QOMM's transport layout directly.
pub mod corporate {
    pub use qomm_transport::corporate_outbox::{
        CanonicalReceipt, ClaimedRequest, CorporateOutbox, CoverAction, CoverSlot, EnqueueOutcome,
        MpcAdmissionReceipt, OutboxEntrySummary, OutboxMetrics, OutboxState, QueueAction,
    };
}

/// Current verifier-complete QOMM proof adapter. Future application adapters
/// can coexist without changing the application/execution/finality contracts.
pub mod product {
    pub use qomm_transport::product_proof_coordinator::{
        authorize_standing_pool_allocation, complete_product_proof, complete_quote_request,
        finalize_product_settlement, prove_complete_quote, prove_product_settlement,
        CompleteQuotePublicInput, CompleteQuoteRequest, ProductSettlementProof,
        ProductSettlementRequest, RegisteredPolicyOpening,
    };
}

/// Typed payment-instruction primitives used by application adapters.
pub mod zkpi {
    pub use qomm_zkpi::*;
}

/// DeFMI primitives and the Avalanche-backed canonical ledger adapter.
pub mod defmi {
    pub use qomm_defmi::*;
}

pub mod prelude {
    pub use crate::application::{
        oclob_manifest_v1, qomm_manifest_v1, ApplicationId, ApplicationManifest, CommitteeProfile,
        InputVisibility, MarketView, SettlementVisibility, WorkflowKind,
    };
    pub use crate::execution::{ApplicationExecutionPlan, ExecutionNodeDigest, ExecutionShape};
    pub use crate::finality::{
        accept_canonical_transition, accept_signed_facility_receipt, ApplicationSettlementReceipt,
        CanonicalReadback, CanonicalTransition, ReadbackKind,
    };
    pub use crate::{SdkError, SdkResult};
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("invalid application manifest: {0}")]
    InvalidManifest(String),
    #[error("invalid distributed execution: {0}")]
    InvalidExecution(String),
    #[error("invalid DeFMI finality evidence: {0}")]
    InvalidFinality(String),
}

pub type SdkResult<T> = Result<T, SdkError>;
