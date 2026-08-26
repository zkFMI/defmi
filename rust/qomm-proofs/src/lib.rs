//! The proofs a venue needs about the parties it deals with, as distinct from
//! the proofs a settlement layer needs about the transfers it applies.
//!
//! Everything here is stated over Pedersen commitments and verified without an
//! opening, so a venue can hold a maker to its policy and its book without
//! being shown either.
pub mod kyb;
pub mod liquidity;
pub mod policy_audit;
pub mod quote_proof;
pub mod rule_audit;
pub mod state_audit;
pub mod threshold_gadgets;
pub mod threshold_quote;
pub mod threshold_range;
pub mod threshold_sigma;
