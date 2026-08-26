//! Zero-knowledge primitives for QOMM.
//!
//! Where an audited implementation exists it is used rather than rewritten:
//! group arithmetic and range proofs come from `curve25519-dalek` and
//! `bulletproofs`, both covered by the Quarkslab assessment commissioned by
//! Tari Labs, with the dalek floor at 4.1.3 for RUSTSEC-2024-0344. What is
//! written here is what has no audited equivalent: the sigma protocols this
//! design needs, and the one-out-of-many proof.
pub mod adaptor;
pub mod bitrange;
pub mod oneofmany;
pub mod or_dleq;
pub mod pedersen;
pub mod range;
pub mod shamir;
pub mod sigma;

pub use pedersen::{asset_tag, encode, Pedersen};
