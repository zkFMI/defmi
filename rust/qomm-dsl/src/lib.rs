//! A small total language for market-maker price rules.
//!
//! The design asks for the price rule to be restricted to a small description
//! format with a limited instruction set, and for a checker to establish that it
//! references only permitted inputs, does not use the requester's identity, and
//! has a finite output range. Those are static properties of a program, so they
//! belong in a checker rather than in a proof.
//!
//! What the checker produces is the interesting part. From one source it derives
//! the MPC circuit, the list of zero-knowledge obligations, and the bit width
//! the circuit needs. The audit stops being written by hand and becomes a
//! compiler output, which is the reason to have a language here at all.
pub mod emit;
pub mod interval;
pub mod parse;
pub mod registry;
pub mod rule;

pub use emit::{obligation_plan, ObligationPlan};
pub use interval::{Interval, RuleError};
pub use rule::{compile_rule, Declaration, Obligation, Role, Rule};
