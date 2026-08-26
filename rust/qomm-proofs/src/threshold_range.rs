//! Bit-decomposition range proofs assembled from Shamir shares.
//!
//! This is the threshold form of `qomm_zk::bitrange`: it keeps the per-bit
//! commitments and the final linkage opening, but replaces the branch-selecting
//! OR proof with the field equation `b * b = b`. The resulting proof is not
//! wire-compatible with the single-prover proof, yet both are ordinary public
//! proofs of membership in `[0, 2^bits)`.

use std::collections::BTreeMap;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use qomm_zk::bitrange::{bit_context, component_transcript, suffixed_context};
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::{verify_opening, OpeningProof, ProductProof};
use rand_core::{CryptoRng, RngCore};

use crate::threshold_gadgets::{
    joint_prove_product_from_contributions, verify_square_bit, NodeShared,
    ProductAssemblyTranscript, ProductNodeContribution, Shared,
};
use crate::threshold_sigma::{
    deal, joint_opening_from_contributions, share_scalar, OpeningAssemblyTranscript,
    OpeningNodeContribution, PartyId, ScalarShares,
};

#[derive(Clone, Debug)]
pub struct BitShares {
    pub commitment: RistrettoPoint,
    pub bit: ScalarShares,
    pub blinding: ScalarShares,
    pub cross: ScalarShares,
    pub coefficient_commitments: Vec<RistrettoPoint>,
}

#[derive(Clone, Debug)]
pub struct ValueShares {
    pub commitment: RistrettoPoint,
    pub value: ScalarShares,
    pub blinding: ScalarShares,
    pub bits: Vec<BitShares>,
    pub threshold: usize,
}

impl ValueShares {
    pub fn width(&self) -> usize {
        self.bits.len()
    }

    /// The exact state one computing node receives; no aggregate or clear value
    /// is present in this view.
    pub fn node_view(&self, party: PartyId) -> Option<NodeValueView> {
        Some(NodeValueView {
            party,
            value_share: *self.value.get(&party)?,
            blinding_share: *self.blinding.get(&party)?,
            bits: self
                .bits
                .iter()
                .map(|bit| {
                    Some(NodeBitView {
                        bit_share: *bit.bit.get(&party)?,
                        blinding_share: *bit.blinding.get(&party)?,
                        cross_share: *bit.cross.get(&party)?,
                    })
                })
                .collect::<Option<Vec<_>>>()?,
        })
    }

    /// Materialize only one recipient's shares plus the public statement.
    pub fn node_contribution(&self, party: PartyId) -> Option<NodeValueShares> {
        Some(NodeValueShares {
            party,
            commitment: self.commitment,
            value_share: *self.value.get(&party)?,
            blinding_share: *self.blinding.get(&party)?,
            bits: self
                .bits
                .iter()
                .map(|bit| {
                    Some(NodeBitShares {
                        shared: NodeShared::new(
                            party,
                            bit.commitment,
                            *bit.bit.get(&party)?,
                            *bit.blinding.get(&party)?,
                            bit.coefficient_commitments.clone(),
                        ),
                        cross_share: *bit.cross.get(&party)?,
                    })
                })
                .collect::<Option<Vec<_>>>()?,
            threshold: self.threshold,
        })
    }
}

#[derive(Clone, Debug)]
pub struct NodeBitView {
    pub bit_share: Scalar,
    pub blinding_share: Scalar,
    pub cross_share: Scalar,
}

#[derive(Clone, Debug)]
pub struct NodeValueView {
    pub party: PartyId,
    pub value_share: Scalar,
    pub blinding_share: Scalar,
    pub bits: Vec<NodeBitView>,
}

/// One node's complete material for a single range statement.
#[derive(Clone, Debug)]
pub struct NodeBitShares {
    shared: NodeShared,
    cross_share: Scalar,
}

#[derive(Clone, Debug)]
pub struct NodeValueShares {
    party: PartyId,
    commitment: RistrettoPoint,
    value_share: Scalar,
    blinding_share: Scalar,
    bits: Vec<NodeBitShares>,
    threshold: usize,
}

impl NodeValueShares {
    pub fn party(&self) -> PartyId {
        self.party
    }

    pub fn width(&self) -> usize {
        self.bits.len()
    }

    pub fn commitment(&self) -> RistrettoPoint {
        self.commitment
    }

    pub fn own_evaluation(&self) -> (Scalar, Scalar) {
        (self.value_share, self.blinding_share)
    }

    pub fn bit_evaluations(&self) -> Vec<(Scalar, Scalar, Scalar)> {
        self.bits
            .iter()
            .map(|bit| {
                let (value, blinding) = bit.shared.own_evaluation();
                (value, blinding, bit.cross_share)
            })
            .collect()
    }
}

/// The same composition as `qomm_zk::bitrange::RangeProof`, with product
/// proofs where its disjunctive bit proofs sit.
#[derive(Clone, Debug)]
pub struct ThresholdRangeProof {
    pub bit_commitments: Vec<RistrettoPoint>,
    pub bit_proofs: Vec<ProductProof>,
    pub linkage: OpeningProof,
    pub bits: usize,
}

#[derive(Clone, Debug)]
pub struct RangeAssemblyTranscript {
    pub quorum: Vec<PartyId>,
    pub width: usize,
    pub bit_partials: Vec<ProductAssemblyTranscript>,
    pub linkage_partials: OpeningAssemblyTranscript,
}

fn value_fits(value: u64, width: usize) -> bool {
    width >= u64::BITS as usize || value < (1u64 << width)
}

fn validate_width(value: u64, width: usize) -> Result<(), String> {
    if width == 0 || width > u64::BITS as usize {
        return Err("bit width must be between 1 and 64".into());
    }
    if !value_fits(value, width) {
        return Err(format!("value {value} outside [0, 2^{width})"));
    }
    Ok(())
}

/// Model the bit decomposition and multiplication outputs an MPC hands to the
/// proof assembler.
pub fn deal_bits<R: RngCore + CryptoRng>(
    key: &Pedersen,
    value: u64,
    blinding: &Scalar,
    width: usize,
    parties: &[PartyId],
    threshold: usize,
    rng: &mut R,
) -> Result<ValueShares, String> {
    validate_width(value, width)?;
    let value_scalar = Scalar::from(value);
    let mut bits = Vec::with_capacity(width);
    for index in 0..width {
        let bit_value = Scalar::from((value >> index) & 1);
        let bit_blinding = Scalar::random(&mut *rng);
        let shared = deal(
            key,
            &bit_value,
            &bit_blinding,
            parties,
            threshold,
            &mut *rng,
        )?;
        bits.push(BitShares {
            commitment: shared.commitment,
            bit: shared.value_shares,
            blinding: shared.blinding_shares,
            cross: share_scalar(
                &(bit_blinding * (Scalar::ONE - bit_value)),
                parties,
                threshold,
                &mut *rng,
            )?,
            coefficient_commitments: shared.coefficient_commitments,
        });
    }
    Ok(ValueShares {
        commitment: key.commit(&value_scalar, blinding),
        value: share_scalar(&value_scalar, parties, threshold, &mut *rng)?,
        blinding: share_scalar(blinding, parties, threshold, &mut *rng)?,
        bits,
        threshold,
    })
}

/// Add a bit decomposition to a wire whose value and blinding are already
/// shared. The linkage uses those existing shares rather than a second sharing.
pub fn bits_for<R: RngCore + CryptoRng>(
    key: &Pedersen,
    shared: &Shared,
    value: u64,
    width: usize,
    parties: &[PartyId],
    threshold: usize,
    rng: &mut R,
) -> Result<ValueShares, String> {
    validate_width(value, width)?;
    let mut bits = Vec::with_capacity(width);
    for index in 0..width {
        let bit_value = Scalar::from((value >> index) & 1);
        let bit_blinding = Scalar::random(&mut *rng);
        let bit_shared = deal(
            key,
            &bit_value,
            &bit_blinding,
            parties,
            threshold,
            &mut *rng,
        )?;
        bits.push(BitShares {
            commitment: bit_shared.commitment,
            bit: bit_shared.value_shares,
            blinding: bit_shared.blinding_shares,
            cross: share_scalar(
                &(bit_blinding * (Scalar::ONE - bit_value)),
                parties,
                threshold,
                &mut *rng,
            )?,
            coefficient_commitments: bit_shared.coefficient_commitments,
        });
    }
    Ok(ValueShares {
        commitment: shared.commitment,
        value: shared.value.clone(),
        blinding: shared.blinding.clone(),
        bits,
        threshold,
    })
}

/// Distributed range assembly over one recipient-scoped contribution per node.
pub fn joint_prove_range_from_contributions<R: RngCore + CryptoRng>(
    key: &Pedersen,
    contributions: &[NodeValueShares],
    quorum: &[PartyId],
    context: &[u8],
    rng: &mut R,
) -> Result<(ThresholdRangeProof, RangeAssemblyTranscript), String> {
    if contributions.len() != quorum.len() {
        return Err(format!(
            "received {} range contributions for a quorum of {}",
            contributions.len(),
            quorum.len()
        ));
    }
    let by_party = contributions
        .iter()
        .map(|contribution| (contribution.party, contribution))
        .collect::<BTreeMap<_, _>>();
    if by_party.len() != contributions.len()
        || quorum.iter().any(|party| !by_party.contains_key(party))
    {
        return Err("range contributions do not exactly match the quorum".into());
    }
    let first = contributions
        .first()
        .ok_or("a range proof needs at least one node contribution")?;
    let width = first.width();
    let threshold = first.threshold;
    if contributions.iter().any(|node| {
        node.width() != width
            || node.threshold != threshold
            || node.commitment.compress() != first.commitment.compress()
    }) {
        return Err("nodes supplied different public range statements".into());
    }

    let mut bit_proofs = Vec::with_capacity(width);
    let mut bit_partials = Vec::with_capacity(width);
    for index in 0..width {
        let bit_contributions = contributions
            .iter()
            .map(|node| {
                ProductNodeContribution::new(
                    node.bits[index].shared.clone(),
                    node.bits[index].cross_share,
                )
            })
            .collect::<Vec<_>>();
        let bit_commitment = first.bits[index].shared.commitment();
        let component = bit_context(context, index).map_err(str::to_string)?;
        let mut transcript = component_transcript(&component);
        let (proof, partials) = joint_prove_product_from_contributions(
            key,
            &bit_commitment,
            &bit_commitment,
            &bit_contributions,
            quorum,
            threshold,
            &mut transcript,
            &mut *rng,
        )?;
        bit_proofs.push(proof);
        bit_partials.push(partials);
    }

    let mut aggregate = RistrettoPoint::identity();
    let mut weight = Scalar::ONE;
    for bit in &first.bits {
        aggregate += bit.shared.commitment() * weight;
        weight += weight;
    }
    let residual = first.commitment - aggregate;
    let opening_contributions = contributions
        .iter()
        .map(|node| {
            let mut value = node.value_share;
            let mut blinding = node.blinding_share;
            let mut weight = Scalar::ONE;
            for bit in &node.bits {
                let (bit_value, bit_blinding) = bit.shared.own_evaluation();
                value -= weight * bit_value;
                blinding -= weight * bit_blinding;
                weight += weight;
            }
            OpeningNodeContribution::new(node.party, value, blinding)
        })
        .collect::<Vec<_>>();
    let link_context = suffixed_context(context, b":link");
    let mut transcript = component_transcript(&link_context);
    let (linkage, linkage_partials) = joint_opening_from_contributions(
        key,
        &residual,
        &opening_contributions,
        threshold,
        quorum,
        &mut transcript,
        &mut *rng,
    )?;
    Ok((
        ThresholdRangeProof {
            bit_commitments: first
                .bits
                .iter()
                .map(|bit| bit.shared.commitment())
                .collect(),
            bit_proofs,
            linkage,
            bits: width,
        },
        RangeAssemblyTranscript {
            quorum: quorum.to_vec(),
            width,
            bit_partials,
            linkage_partials,
        },
    ))
}

/// Ordinary public verification: no shares, quorum, or setup are inputs.
pub fn verify_threshold_range(
    key: &Pedersen,
    commitment: &RistrettoPoint,
    proof: &ThresholdRangeProof,
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
        if !verify_square_bit(key, bit_commitment, bit_proof, &mut transcript) {
            return false;
        }
    }
    let mut aggregate = RistrettoPoint::identity();
    let mut weight = Scalar::ONE;
    for commitment in &proof.bit_commitments {
        aggregate += commitment * weight;
        weight += weight;
    }
    let residual = commitment - aggregate;
    let link_context = suffixed_context(context, b":link");
    let mut transcript = component_transcript(&link_context);
    verify_opening(key, &mut transcript, &residual, &proof.linkage)
}
