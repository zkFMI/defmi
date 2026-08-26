//! Bit-decomposition range proofs for widths the `bulletproofs` crate does not
//! accept.
//!
//! This is the Rust composition of `zk/commit.py`'s range and bounded proofs:
//! one bit proof per little-endian bit, followed by an opening proof linking
//! their weighted sum to the original commitment.  The component contexts are
//! kept byte-for-byte with Python (`:bit:` plus a two-byte big-endian index,
//! `:link`, `|above`, and `|below`).
//!
//! The leaf proofs intentionally remain the native `qomm-zk` primitives.  They
//! use Ristretto255 and Merlin, while Python uses Ed25519 and a SHA-512
//! transcript, so the two proof objects are not wire-compatible even though
//! this composition and its public inputs have the same semantics.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

use crate::pedersen::Pedersen;
use crate::sigma::{prove_bit, prove_opening, verify_bit, verify_opening, BitProof, OpeningProof};

const TRANSCRIPT_DOMAIN: &[u8] = b"qomm:bitrange:v1";

/// A commitment lies in `[0, 2^bits)`.
#[derive(Clone, Debug)]
pub struct RangeProof {
    pub bit_commitments: Vec<RistrettoPoint>,
    pub bit_proofs: Vec<BitProof>,
    pub linkage: OpeningProof,
    pub bits: usize,
}

/// Two range proofs that together pin an inclusive interval exactly.
#[derive(Clone, Debug)]
pub struct BoundedProof {
    pub above: RangeProof,
    pub below: RangeProof,
    pub bits: usize,
}

/// Build the transcript used by one leaf of the bit-decomposition proof.
///
/// Threshold range proofs reuse the same composition with square product
/// proofs in place of branch-selecting bit proofs.
pub fn component_transcript(context: &[u8]) -> Transcript {
    let mut transcript = Transcript::new(TRANSCRIPT_DOMAIN);
    transcript.append_message(b"context", context);
    transcript
}

/// Derive the context of the little-endian bit at `index`.
pub fn bit_context(context: &[u8], index: usize) -> Result<Vec<u8>, &'static str> {
    let index = u16::try_from(index).map_err(|_| "bit width exceeds the transcript index")?;
    let mut derived = Vec::with_capacity(context.len() + 7);
    derived.extend_from_slice(context);
    derived.extend_from_slice(b":bit:");
    derived.extend_from_slice(&index.to_be_bytes());
    Ok(derived)
}

/// Append a framed suffix used by the range-proof composition.
pub fn suffixed_context(context: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut derived = Vec::with_capacity(context.len() + suffix.len());
    derived.extend_from_slice(context);
    derived.extend_from_slice(suffix);
    derived
}

fn value_fits(value: u64, bits: usize) -> bool {
    bits >= u64::BITS as usize || value < (1u64 << bits)
}

/// Prove that `commitment` opens to `value` in `[0, 2^bits)`.
///
/// Unlike `range::RangeCtx`, `bits` need not be 8, 16, 32, or 64.  Widths
/// through 65,536 use the exact two-byte component index used by Python.
pub fn prove_range<R: RngCore + CryptoRng>(
    key: &Pedersen,
    commitment: &RistrettoPoint,
    value: u64,
    blinding: &Scalar,
    bits: usize,
    context: &[u8],
    rng: &mut R,
) -> Result<RangeProof, &'static str> {
    if !value_fits(value, bits) {
        return Err("value outside the range being proved");
    }
    if bits > usize::from(u16::MAX) + 1 {
        return Err("bit width exceeds the transcript index");
    }

    let bit_blindings: Vec<Scalar> = (0..bits).map(|_| Scalar::random(&mut *rng)).collect();
    let bit_values: Vec<bool> = (0..bits)
        .map(|index| index < u64::BITS as usize && ((value >> index) & 1) == 1)
        .collect();
    let bit_commitments: Vec<RistrettoPoint> = bit_values
        .iter()
        .zip(&bit_blindings)
        .map(|(bit, bit_blinding)| key.commit(&Scalar::from(u64::from(*bit)), bit_blinding))
        .collect();

    let mut bit_proofs = Vec::with_capacity(bits);
    for (index, ((bit, bit_blinding), bit_commitment)) in bit_values
        .iter()
        .zip(&bit_blindings)
        .zip(&bit_commitments)
        .enumerate()
    {
        let context = bit_context(context, index)?;
        let mut transcript = component_transcript(&context);
        bit_proofs.push(prove_bit(
            key,
            &mut transcript,
            bit_commitment,
            *bit,
            bit_blinding,
            rng,
        ));
    }

    // C - sum(2^j C_j) = h^(r - sum(2^j r_j)).
    let mut aggregate = RistrettoPoint::identity();
    let mut combined_blinding = Scalar::ZERO;
    let mut weight = Scalar::ONE;
    for (bit_commitment, bit_blinding) in bit_commitments.iter().zip(&bit_blindings) {
        aggregate += bit_commitment * weight;
        combined_blinding += bit_blinding * weight;
        weight += weight;
    }
    let residual = commitment - aggregate;
    let residual_blinding = blinding - combined_blinding;
    let link_context = suffixed_context(context, b":link");
    let mut transcript = component_transcript(&link_context);
    let linkage = prove_opening(
        key,
        &mut transcript,
        &residual,
        &Scalar::ZERO,
        &residual_blinding,
        rng,
    );

    Ok(RangeProof {
        bit_commitments,
        bit_proofs,
        linkage,
        bits,
    })
}

/// Verify a bit-decomposition proof against its original commitment.
pub fn verify_range(
    key: &Pedersen,
    commitment: &RistrettoPoint,
    proof: &RangeProof,
    context: &[u8],
) -> bool {
    if proof.bit_commitments.len() != proof.bits || proof.bit_proofs.len() != proof.bits {
        return false;
    }

    for (index, (bit_commitment, bit_proof)) in proof
        .bit_commitments
        .iter()
        .zip(&proof.bit_proofs)
        .enumerate()
    {
        let Ok(context) = bit_context(context, index) else {
            return false;
        };
        let mut transcript = component_transcript(&context);
        if !verify_bit(key, &mut transcript, bit_commitment, bit_proof) {
            return false;
        }
    }

    let mut aggregate = RistrettoPoint::identity();
    let mut weight = Scalar::ONE;
    for bit_commitment in &proof.bit_commitments {
        aggregate += bit_commitment * weight;
        weight += weight;
    }
    let residual = commitment - aggregate;
    let link_context = suffixed_context(context, b":link");
    let mut transcript = component_transcript(&link_context);
    verify_opening(key, &mut transcript, &residual, &proof.linkage)
}

fn scalar_from_i64(value: i64) -> Scalar {
    if value >= 0 {
        Scalar::from(value as u64)
    } else {
        -Scalar::from(value.unsigned_abs())
    }
}

fn interval(value: i64, low: i64, high: i64) -> Result<(u64, u64, usize), &'static str> {
    let span = i128::from(high) - i128::from(low);
    if span < 0 {
        return Err("empty interval");
    }
    if value < low || value > high {
        return Err("value outside the bounded interval");
    }
    let span = u64::try_from(span).map_err(|_| "bounded interval is too wide")?;
    let above = u64::try_from(i128::from(value) - i128::from(low))
        .map_err(|_| "value outside the bounded interval")?;
    let bits = usize::try_from((u64::BITS - span.leading_zeros()).max(1))
        .expect("a u32 bit width always fits usize");
    Ok((span, above, bits))
}

/// A commitment to `value - low`, carrying the original blinding unchanged.
pub fn shift_commitment(key: &Pedersen, commitment: &RistrettoPoint, low: i64) -> RistrettoPoint {
    commitment - key.g * scalar_from_i64(low)
}

/// Prove both `value - low >= 0` and `high - value >= 0`.
pub fn prove_bounded<R: RngCore + CryptoRng>(
    key: &Pedersen,
    value: i64,
    blinding: &Scalar,
    low: i64,
    high: i64,
    context: &[u8],
    rng: &mut R,
) -> Result<(RistrettoPoint, BoundedProof, usize), &'static str> {
    let (span, above_value, bits) = interval(value, low, high)?;
    let commitment = key.commit(&scalar_from_i64(value), blinding);

    let above_context = suffixed_context(context, b"|above");
    let above = prove_range(
        key,
        &shift_commitment(key, &commitment, low),
        above_value,
        blinding,
        bits,
        &above_context,
        rng,
    )?;

    let ceiling = key.commit(&scalar_from_i64(high), &Scalar::ZERO);
    let below_commitment = ceiling - commitment;
    let below_context = suffixed_context(context, b"|below");
    let below = prove_range(
        key,
        &below_commitment,
        span - above_value,
        &-*blinding,
        bits,
        &below_context,
        rng,
    )?;

    Ok((commitment, BoundedProof { above, below, bits }, bits))
}

/// Verify the same inclusive two-sided bound as Python's `verify_bounded`.
pub fn verify_bounded(
    key: &Pedersen,
    commitment: &RistrettoPoint,
    proof: &BoundedProof,
    low: i64,
    high: i64,
    context: &[u8],
) -> bool {
    let span = i128::from(high) - i128::from(low);
    if span < 0 {
        return false;
    }
    let Ok(span) = u64::try_from(span) else {
        return false;
    };
    let bits = usize::try_from((u64::BITS - span.leading_zeros()).max(1))
        .expect("a u32 bit width always fits usize");
    if proof.bits != bits {
        return false;
    }
    // The outer `bits` is the field a forger sets; what decides the statement is
    // each inner proof's own width, which `verify_range` reads from the proof.
    // Unchecked, the pair pins nothing: for [-4000, 4000] and value 4001,
    // `value - low` is 8001 and honest at 13 bits while `high - value` is -1,
    // which is ell-1 and honest at 253, and the outer field can still say 13.
    // Both sides verify and the value is outside the interval. That is the same
    // defect the second range proof was added to fix, surviving in the width
    // rather than in the bound.
    if proof.above.bits != bits || proof.below.bits != bits {
        return false;
    }

    let above_context = suffixed_context(context, b"|above");
    if !verify_range(
        key,
        &shift_commitment(key, commitment, low),
        &proof.above,
        &above_context,
    ) {
        return false;
    }

    let ceiling = key.commit(&scalar_from_i64(high), &Scalar::ZERO);
    let below_commitment = ceiling - commitment;
    let below_context = suffixed_context(context, b"|below");
    verify_range(key, &below_commitment, &proof.below, &below_context)
}
