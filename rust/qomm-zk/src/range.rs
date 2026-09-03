//! Range proofs, delegated to the audited `bulletproofs` crate.
//!
//! This replaces a bit-decomposition proof built from our own bit proofs. The
//! swap is worth stating precisely: proving is about the same speed, but
//! verification is a single multiscalar multiplication instead of one sigma
//! check per bit, and the proof is logarithmic instead of linear. Aggregation
//! then makes a settlement's several ranges share one proof.
//!
//! One constraint comes with it: bit widths must be powers of two. A rail tuned
//! to 24 or 40 bits has to round up to 32 or 64, which changes how the
//! split-rail sizing plays out.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

pub struct RangeCtx {
    pub pc_gens: PedersenGens,
    pub bp_gens: BulletproofGens,
    pub bits: usize,
}

impl RangeCtx {
    pub fn new(bits: usize, max_aggregate: usize) -> Self {
        assert!(
            matches!(bits, 8 | 16 | 32 | 64),
            "bulletproofs takes 8, 16, 32 or 64 bits"
        );
        RangeCtx {
            pc_gens: PedersenGens::default(),
            bp_gens: BulletproofGens::new(bits, max_aggregate.next_power_of_two()),
            bits,
        }
    }

    /// One proof covering several values at once.
    ///
    /// The range is checked here because the crate does not check it. Passing a
    /// value wider than `bits` produces a proof of the truncated value against
    /// a commitment to the true one, which simply fails to verify later --- safe
    /// but silent, and the caller finds out from a rejection rather than from
    /// the call that was wrong.
    pub fn prove(
        &self,
        transcript: &mut Transcript,
        values: &[u64],
        blindings: &[Scalar],
    ) -> Result<(RangeProof, Vec<CompressedRistretto>), &'static str> {
        if self.bits < 64 && values.iter().any(|v| *v >= (1u64 << self.bits)) {
            return Err("a value does not fit the range being proved");
        }
        let padded = values.len().next_power_of_two();
        let mut v = values.to_vec();
        let mut b = blindings.to_vec();
        // aggregation sizes must be a power of two; padding with zero-valued
        // commitments is cheaper than refusing the shape
        while v.len() < padded {
            v.push(0);
            b.push(Scalar::ZERO);
        }
        RangeProof::prove_multiple(&self.bp_gens, &self.pc_gens, transcript, &v, &b, self.bits)
            .map_err(|_| "range proof failed")
    }

    pub fn verify(
        &self,
        transcript: &mut Transcript,
        proof: &RangeProof,
        commitments: &[CompressedRistretto],
    ) -> bool {
        proof
            .verify_multiple(
                &self.bp_gens,
                &self.pc_gens,
                transcript,
                commitments,
                self.bits,
            )
            .is_ok()
    }
}
