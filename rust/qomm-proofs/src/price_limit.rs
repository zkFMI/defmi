//! Hidden limit-price enforcement for an automatically settled RFQ.
//!
//! A Taker signs a commitment to a maximum buy price or minimum sell price.
//! Once MPC selects a quote, this proof shows that the committed difference is
//! non-negative without opening either price.  It is the cryptographic reason
//! no post-quote Taker signature is needed.

use crate::threshold_range::{verify_threshold_range, ThresholdRangeProof};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_zk::pedersen::Pedersen;
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"QOMM:TAKER:PRICE-LIMIT:v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PriceLimitDirection {
    /// The Taker buys and will not pay above the committed limit.
    MaximumBuyPrice = 1,
    /// The Taker sells and will not receive below the committed limit.
    MinimumSellPrice = 2,
}

enum PriceLimitEvidence {
    Bulletproof(RangeProof),
    Threshold(ThresholdRangeProof),
}

pub struct PriceLimitProof {
    direction: PriceLimitDirection,
    bits: usize,
    evidence: PriceLimitEvidence,
}

fn valid_bits(bits: usize) -> bool {
    matches!(bits, 8 | 16 | 32 | 64)
}

fn transcript(
    direction: PriceLimitDirection,
    bits: usize,
    quote: &RistrettoPoint,
    limit: &RistrettoPoint,
    context: &[u8],
) -> Transcript {
    let mut transcript = Transcript::new(DOMAIN);
    transcript.append_u64(b"direction", direction as u64);
    transcript.append_u64(b"bits", bits as u64);
    transcript.append_message(b"quote", quote.compress().as_bytes());
    transcript.append_message(b"limit", limit.compress().as_bytes());
    transcript.append_message(b"context", context);
    transcript
}

fn difference_commitment(
    direction: PriceLimitDirection,
    quote: &RistrettoPoint,
    limit: &RistrettoPoint,
) -> RistrettoPoint {
    match direction {
        PriceLimitDirection::MaximumBuyPrice => limit - quote,
        PriceLimitDirection::MinimumSellPrice => quote - limit,
    }
}

/// Domain-separated transcript for a jointly generated price-limit range
/// proof.  Unlike the ordinary Bulletproof transcript, the threshold proof
/// protocol takes a byte context, so bind every public part of the same
/// statement into that context explicitly.
pub fn threshold_context(
    direction: PriceLimitDirection,
    bits: usize,
    quote: &RistrettoPoint,
    limit: &RistrettoPoint,
    context: &[u8],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"QOMM:TAKER:THRESHOLD-PRICE-LIMIT:v1")
        .chain_update([direction as u8])
        .chain_update((bits as u64).to_be_bytes())
        .chain_update(quote.compress().as_bytes())
        .chain_update(limit.compress().as_bytes())
        .chain_update((context.len() as u64).to_be_bytes())
        .chain_update(context)
        .finalize()
        .into()
}

#[allow(clippy::too_many_arguments)]
pub fn prove(
    key: &Pedersen,
    quote_value: u64,
    quote_blinding: &Scalar,
    limit_value: u64,
    limit_blinding: &Scalar,
    direction: PriceLimitDirection,
    bits: usize,
    context: &[u8],
) -> Result<PriceLimitProof, String> {
    if !valid_bits(bits) {
        return Err("price limit width must be 8, 16, 32, or 64 bits".into());
    }
    let difference = match direction {
        PriceLimitDirection::MaximumBuyPrice => limit_value
            .checked_sub(quote_value)
            .ok_or_else(|| "quote exceeds the signed maximum buy price".to_string())?,
        PriceLimitDirection::MinimumSellPrice => quote_value
            .checked_sub(limit_value)
            .ok_or_else(|| "quote is below the signed minimum sell price".to_string())?,
    };
    if bits < 64 && difference >= (1u64 << bits) {
        return Err("price difference does not fit the configured proof width".into());
    }
    let difference_blinding = match direction {
        PriceLimitDirection::MaximumBuyPrice => limit_blinding - quote_blinding,
        PriceLimitDirection::MinimumSellPrice => quote_blinding - limit_blinding,
    };
    let quote = key.commit_u64(quote_value, quote_blinding);
    let limit = key.commit_u64(limit_value, limit_blinding);
    let pc_gens = PedersenGens {
        B: key.g,
        B_blinding: key.h,
    };
    let bp_gens = BulletproofGens::new(bits, 1);
    let (range_proof, commitments) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut transcript(direction, bits, &quote, &limit, context),
        &[difference],
        &[difference_blinding],
        bits,
    )
    .map_err(|_| "price limit range proof generation failed".to_string())?;
    if commitments.len() != 1
        || commitments[0] != difference_commitment(direction, &quote, &limit).compress()
    {
        return Err("price limit proof commitment differs from the signed prices".into());
    }
    Ok(PriceLimitProof {
        direction,
        bits,
        evidence: PriceLimitEvidence::Bulletproof(range_proof),
    })
}

/// Accept a verifier-complete proof assembled from MPC-node shares.  No quote,
/// limit, or blinding opening is present at this boundary.
pub fn from_threshold(
    key: &Pedersen,
    quote: &RistrettoPoint,
    limit: &RistrettoPoint,
    direction: PriceLimitDirection,
    bits: usize,
    context: &[u8],
    proof: ThresholdRangeProof,
) -> Result<PriceLimitProof, String> {
    if !valid_bits(bits) || proof.bits != bits {
        return Err("threshold price limit proof uses an unsupported width".into());
    }
    let bound = threshold_context(direction, bits, quote, limit, context);
    if !verify_threshold_range(
        key,
        &difference_commitment(direction, quote, limit),
        &proof,
        &bound,
    ) {
        return Err("joint proof does not establish the signed hidden price limit".into());
    }
    Ok(PriceLimitProof {
        direction,
        bits,
        evidence: PriceLimitEvidence::Threshold(proof),
    })
}

pub fn verify(
    key: &Pedersen,
    quote: &RistrettoPoint,
    limit: &RistrettoPoint,
    expected_direction: PriceLimitDirection,
    expected_bits: usize,
    context: &[u8],
    proof: &PriceLimitProof,
) -> Result<(), String> {
    if proof.direction != expected_direction
        || proof.bits != expected_bits
        || !valid_bits(proof.bits)
    {
        return Err("price limit proof uses another direction or width".into());
    }
    let pc_gens = PedersenGens {
        B: key.g,
        B_blinding: key.h,
    };
    match &proof.evidence {
        PriceLimitEvidence::Bulletproof(range_proof) => range_proof
            .verify_multiple(
                &BulletproofGens::new(proof.bits, 1),
                &pc_gens,
                &mut transcript(proof.direction, proof.bits, quote, limit, context),
                &[difference_commitment(proof.direction, quote, limit).compress()],
                proof.bits,
            )
            .map_err(|_| "quote violates the signed hidden price limit".to_string()),
        PriceLimitEvidence::Threshold(range_proof) => {
            let bound = threshold_context(proof.direction, proof.bits, quote, limit, context);
            verify_threshold_range(
                key,
                &difference_commitment(proof.direction, quote, limit),
                range_proof,
                &bound,
            )
            .then_some(())
            .ok_or_else(|| "joint proof violates the signed hidden price limit".to_string())
        }
    }
}

fn hash_threshold_range(hash: &mut Sha256, proof: &ThresholdRangeProof) {
    hash.update((proof.bits as u64).to_be_bytes());
    hash.update((proof.bit_commitments.len() as u64).to_be_bytes());
    for commitment in &proof.bit_commitments {
        hash.update(commitment.compress().as_bytes());
    }
    hash.update((proof.bit_proofs.len() as u64).to_be_bytes());
    for bit in &proof.bit_proofs {
        hash.update(bit.t_factor.compress().as_bytes());
        hash.update(bit.t_product.compress().as_bytes());
        hash.update(bit.z_b.to_bytes());
        hash.update(bit.z_rb.to_bytes());
        hash.update(bit.z_s.to_bytes());
    }
    hash.update(proof.linkage.t.compress().as_bytes());
    hash.update(proof.linkage.z_value.to_bytes());
    hash.update(proof.linkage.z_blinding.to_bytes());
}

impl PriceLimitProof {
    pub fn digest(
        &self,
        quote: &RistrettoPoint,
        limit: &RistrettoPoint,
        context: &[u8],
    ) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update([self.direction as u8]);
        hash.update((self.bits as u64).to_be_bytes());
        hash.update(quote.compress().as_bytes());
        hash.update(limit.compress().as_bytes());
        hash.update((context.len() as u64).to_be_bytes());
        hash.update(context);
        match &self.evidence {
            PriceLimitEvidence::Bulletproof(proof) => {
                hash.update([1]);
                hash.update(proof.to_bytes());
            }
            PriceLimitEvidence::Threshold(proof) => {
                hash.update([2]);
                hash_threshold_range(&mut hash, proof);
            }
        }
        hash.finalize().into()
    }
}
