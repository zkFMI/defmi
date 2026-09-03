//! Joint proof that at least `minimum` registered makers are eligible.
//!
//! This is only the composition layer. Bit validity, Shamir/VSS handling,
//! product proofs, and the unsigned excess range proof are the existing native
//! threshold primitives used elsewhere in this crate.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::ProductProof;
use rand_core::{CryptoRng, RngCore};

use crate::threshold_gadgets::{
    add, joint_prove_product_from_contributions, shift, verify_square_bit, ProductNodeContribution,
    Shared,
};
use crate::threshold_range::{
    bits_for, joint_prove_range_from_contributions, verify_threshold_range, ThresholdRangeProof,
    ValueShares,
};
use crate::threshold_sigma::{deal, share_scalar, PartyId, ScalarShares};

const DOMAIN: &[u8] = b"QOMM:LIQUIDITY:v1";

#[derive(Clone, Debug)]
pub struct LiquidityShares {
    pub eligibility: Vec<Shared>,
    bit_crosses: Vec<ScalarShares>,
    excess: ValueShares,
    threshold: usize,
}

#[derive(Debug)]
pub struct LiquidityProof {
    pub n_slots: usize,
    pub minimum: usize,
    pub quote_statement_digest: [u8; 32],
    pub eligibility_commitments: Vec<RistrettoPoint>,
    pub bit_proofs: Vec<ProductProof>,
    pub count_commitment: RistrettoPoint,
    pub excess_range: ThresholdRangeProof,
    pub range_bits: usize,
}

fn width(value: usize) -> usize {
    if value == 0 {
        1
    } else {
        (usize::BITS - value.leading_zeros()) as usize
    }
}

fn context(
    quote_statement_digest: &[u8; 32],
    n_slots: usize,
    minimum: usize,
) -> Result<Vec<u8>, String> {
    let n_slots = u32::try_from(n_slots).map_err(|_| "maker count does not fit the transcript")?;
    let minimum = u32::try_from(minimum).map_err(|_| "minimum does not fit the transcript")?;
    let mut context = Vec::with_capacity(DOMAIN.len() + 40);
    context.extend_from_slice(DOMAIN);
    context.extend_from_slice(quote_statement_digest);
    context.extend_from_slice(&n_slots.to_be_bytes());
    context.extend_from_slice(&minimum.to_be_bytes());
    Ok(context)
}

fn suffixed(context: &[u8], label: &[u8], index: Option<usize>) -> Vec<u8> {
    let mut output = context.to_vec();
    output.extend_from_slice(label);
    if let Some(index) = index {
        output.extend_from_slice(&(index as u64).to_be_bytes());
    }
    output
}

fn bit_transcript(context: &[u8], index: usize) -> Transcript {
    let mut transcript = Transcript::new(b"qomm:liquidity:bit:v1");
    transcript.append_message(b"statement", &suffixed(context, b":bit:", Some(index)));
    transcript
}

pub fn deal_liquidity_shares<R: RngCore + CryptoRng>(
    key: &Pedersen,
    eligible: &[u8],
    minimum: usize,
    parties: &[PartyId],
    threshold: usize,
    rng: &mut R,
) -> Result<LiquidityShares, String> {
    if eligible.is_empty() || eligible.iter().any(|bit| *bit > 1) {
        return Err("eligibility must be a non-empty bit vector".into());
    }
    if minimum > eligible.len() {
        return Err("liquidity threshold is outside the maker population".into());
    }
    let count = eligible.iter().map(|bit| usize::from(*bit)).sum::<usize>();
    if count < minimum {
        return Err("fewer makers are eligible than the claimed threshold".into());
    }

    let mut eligibility = Vec::with_capacity(eligible.len());
    let mut bit_crosses = Vec::with_capacity(eligible.len());
    for bit in eligible {
        let value = Scalar::from(u64::from(*bit));
        let blinding = Scalar::random(&mut *rng);
        let shares = deal(key, &value, &blinding, parties, threshold, &mut *rng)?;
        eligibility.push(Shared {
            commitment: shares.commitment,
            value: shares.value_shares,
            blinding: shares.blinding_shares,
            coefficient_commitments: shares.coefficient_commitments,
        });
        bit_crosses.push(share_scalar(
            &(blinding * (Scalar::ONE - value)),
            parties,
            threshold,
            &mut *rng,
        )?);
    }

    let mut count_shared = eligibility[0].clone();
    for wire in &eligibility[1..] {
        count_shared = add(&count_shared, wire)?;
    }
    let minimum_scalar =
        Scalar::from(u64::try_from(minimum).map_err(|_| "minimum does not fit the proof field")?);
    let excess_shared = shift(key, &count_shared, &-minimum_scalar);
    let range_bits = width(eligible.len() - minimum);
    let excess = bits_for(
        key,
        &excess_shared,
        u64::try_from(count - minimum).map_err(|_| "excess does not fit u64")?,
        range_bits,
        parties,
        threshold,
        &mut *rng,
    )?;
    Ok(LiquidityShares {
        eligibility,
        bit_crosses,
        excess,
        threshold,
    })
}

pub fn joint_prove_liquidity<R: RngCore + CryptoRng>(
    key: &Pedersen,
    shares: &LiquidityShares,
    quorum: &[PartyId],
    minimum: usize,
    quote_statement_digest: [u8; 32],
    rng: &mut R,
) -> Result<LiquidityProof, String> {
    let n_slots = shares.eligibility.len();
    if minimum > n_slots {
        return Err("liquidity threshold is outside the maker population".into());
    }
    let context = context(&quote_statement_digest, n_slots, minimum)?;
    let mut bit_proofs = Vec::with_capacity(n_slots);
    for (index, (wire, crosses)) in shares
        .eligibility
        .iter()
        .zip(&shares.bit_crosses)
        .enumerate()
    {
        let contributions = quorum
            .iter()
            .map(|party| {
                Ok(ProductNodeContribution::new(
                    wire.node_share(*party)
                        .ok_or_else(|| format!("missing eligibility share for party {party}"))?,
                    *crosses
                        .get(party)
                        .ok_or_else(|| format!("missing bit cross share for party {party}"))?,
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let (proof, _) = joint_prove_product_from_contributions(
            key,
            &wire.commitment,
            &wire.commitment,
            &contributions,
            quorum,
            shares.threshold,
            &mut bit_transcript(&context, index),
            &mut *rng,
        )?;
        bit_proofs.push(proof);
    }

    let range_contributions = quorum
        .iter()
        .map(|party| {
            shares
                .excess
                .node_contribution(*party)
                .ok_or_else(|| format!("missing excess share for party {party}"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let excess_context = suffixed(&context, b":excess", None);
    let (excess_range, _) = joint_prove_range_from_contributions(
        key,
        &range_contributions,
        quorum,
        &excess_context,
        &mut *rng,
    )?;
    let count_commitment = shares
        .eligibility
        .iter()
        .fold(RistrettoPoint::identity(), |sum, wire| {
            sum + wire.commitment
        });
    Ok(LiquidityProof {
        n_slots,
        minimum,
        quote_statement_digest,
        eligibility_commitments: shares
            .eligibility
            .iter()
            .map(|wire| wire.commitment)
            .collect(),
        bit_proofs,
        count_commitment,
        excess_range,
        range_bits: shares.excess.width(),
    })
}

pub fn verify_liquidity(
    key: &Pedersen,
    proof: &LiquidityProof,
    expected_eligibility_commitments: &[RistrettoPoint],
    quote_statement_digest: &[u8; 32],
) -> bool {
    let Ok(context) = context(quote_statement_digest, proof.n_slots, proof.minimum) else {
        return false;
    };
    if &proof.quote_statement_digest != quote_statement_digest || proof.minimum > proof.n_slots {
        return false;
    }
    if expected_eligibility_commitments.len() != proof.n_slots
        || expected_eligibility_commitments
            .iter()
            .map(|point| point.compress())
            .ne(proof
                .eligibility_commitments
                .iter()
                .map(|point| point.compress()))
        || proof.bit_proofs.len() != proof.n_slots
    {
        return false;
    }
    for (index, (commitment, bit_proof)) in proof
        .eligibility_commitments
        .iter()
        .zip(&proof.bit_proofs)
        .enumerate()
    {
        if !verify_square_bit(
            key,
            commitment,
            bit_proof,
            &mut bit_transcript(&context, index),
        ) {
            return false;
        }
    }
    let aggregate = proof
        .eligibility_commitments
        .iter()
        .fold(RistrettoPoint::identity(), |sum, commitment| {
            sum + commitment
        });
    if aggregate.compress() != proof.count_commitment.compress() {
        return false;
    }
    let expected_bits = width(proof.n_slots - proof.minimum);
    if proof.range_bits != expected_bits || proof.excess_range.bits != expected_bits {
        return false;
    }
    let Ok(minimum) = u64::try_from(proof.minimum) else {
        return false;
    };
    let excess_commitment = proof.count_commitment - key.g * Scalar::from(minimum);
    verify_threshold_range(
        key,
        &excess_commitment,
        &proof.excess_range,
        &suffixed(&context, b":excess", None),
    )
}
