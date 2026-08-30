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
use qomm_zk::sigma::{
    opening_challenge, product_challenge, verify_opening, OpeningProof, ProductProof,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::threshold_gadgets::{
    coefficient_commitments_from_evaluations, joint_prove_product_from_contributions,
    verify_square_bit, NodeShared, ProductAssemblyTranscript, ProductNodeContribution, Shared,
};
use crate::threshold_sigma::{
    combine_commitments, deal, joint_opening_from_contributions, lagrange_at_zero,
    share_commitment, share_scalar, OpeningAssemblyTranscript, OpeningNodeContribution, PartyId,
    ScalarShares,
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
    pub value_coefficient_commitments: Vec<RistrettoPoint>,
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
            value_coefficient_commitments: self.value_coefficient_commitments.clone(),
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
    value_coefficient_commitments: Vec<RistrettoPoint>,
    bits: Vec<NodeBitShares>,
    threshold: usize,
}

/// Party-local range material read from that party's MPC persistence file.
/// It never contains another node's share.
#[derive(Clone, Debug)]
pub struct LocalRangeShares {
    party: PartyId,
    value_share: Scalar,
    blinding_share: Scalar,
    bits: Vec<(Scalar, Scalar, Scalar)>,
    threshold: usize,
}

/// Public Pedersen evaluations a node publishes before proof challenges exist.
/// These are commitments to shares, not shares themselves.
#[derive(Clone, Debug)]
pub struct RangeEvaluations {
    pub party: PartyId,
    pub value: RistrettoPoint,
    pub bits: Vec<RistrettoPoint>,
}

/// Public VSS statement reconstructed in the exponent from node evaluations.
#[derive(Clone, Debug)]
pub struct RangeStatement {
    pub commitment: RistrettoPoint,
    pub value_coefficients: Vec<RistrettoPoint>,
    pub bit_commitments: Vec<RistrettoPoint>,
    pub bit_coefficients: Vec<Vec<RistrettoPoint>>,
    pub threshold: usize,
}

impl LocalRangeShares {
    pub fn new(
        party: PartyId,
        value_share: Scalar,
        blinding_share: Scalar,
        bits: Vec<(Scalar, Scalar, Scalar)>,
        threshold: usize,
    ) -> Result<Self, String> {
        if party == 0 {
            return Err("party identifiers are one-based".into());
        }
        if bits.is_empty() {
            return Err("a range handoff must contain at least one bit".into());
        }
        Ok(Self {
            party,
            value_share,
            blinding_share,
            bits,
            threshold,
        })
    }

    pub fn party(&self) -> PartyId {
        self.party
    }

    pub fn width(&self) -> usize {
        self.bits.len()
    }

    pub fn evaluations(&self, key: &Pedersen) -> RangeEvaluations {
        RangeEvaluations {
            party: self.party,
            value: key.commit(&self.value_share, &self.blinding_share),
            bits: self
                .bits
                .iter()
                .map(|(value, blinding, _)| key.commit(value, blinding))
                .collect(),
        }
    }

    /// Attach only the public coefficient ladders. The party's private shares
    /// stay in this process and are checked against its own public evaluation.
    pub fn bind(
        self,
        key: &Pedersen,
        statement: &RangeStatement,
    ) -> Result<NodeValueShares, String> {
        if self.threshold != statement.threshold
            || self.bits.len() != statement.bit_commitments.len()
            || statement.bit_coefficients.len() != statement.bit_commitments.len()
        {
            return Err(
                "the local range handoff and public statement have different shapes".into(),
            );
        }
        let expected = share_commitment(&statement.value_coefficients, self.party)?;
        if key
            .commit(&self.value_share, &self.blinding_share)
            .compress()
            != expected.compress()
        {
            return Err("the local value share does not match the public VSS statement".into());
        }
        let bits = self
            .bits
            .into_iter()
            .enumerate()
            .map(|(index, (value, blinding, cross))| {
                let expected = share_commitment(&statement.bit_coefficients[index], self.party)?;
                if key.commit(&value, &blinding).compress() != expected.compress() {
                    return Err(format!(
                        "local bit {index} does not match the public VSS statement"
                    ));
                }
                Ok(NodeBitShares {
                    shared: NodeShared::new(
                        self.party,
                        statement.bit_commitments[index],
                        value,
                        blinding,
                        statement.bit_coefficients[index].clone(),
                    ),
                    cross_share: cross,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(NodeValueShares {
            party: self.party,
            commitment: statement.commitment,
            value_share: self.value_share,
            blinding_share: self.blinding_share,
            value_coefficient_commitments: statement.value_coefficients.clone(),
            bits,
            threshold: self.threshold,
        })
    }
}

/// Reconstruct the VSS coefficient ladders only in the group. No scalar share
/// or range value is accepted by this function.
pub fn range_statement_from_evaluations(
    evaluations: &[RangeEvaluations],
    threshold: usize,
) -> Result<RangeStatement, String> {
    let first = evaluations
        .first()
        .ok_or("a range statement needs at least one node evaluation")?;
    if evaluations.len() < threshold + 1 {
        return Err(format!(
            "{} evaluations cannot support threshold {threshold}",
            evaluations.len()
        ));
    }
    if first.bits.is_empty()
        || evaluations
            .iter()
            .any(|node| node.bits.len() != first.bits.len())
    {
        return Err("node range evaluations have different bit widths".into());
    }
    let values = evaluations
        .iter()
        .map(|node| (node.party, node.value))
        .collect::<BTreeMap<_, _>>();
    if values.len() != evaluations.len() {
        return Err("a party supplied more than one range evaluation".into());
    }
    let value_coefficients = coefficient_commitments_from_evaluations(&values, threshold)?;
    let mut bit_coefficients = Vec::with_capacity(first.bits.len());
    for index in 0..first.bits.len() {
        let points = evaluations
            .iter()
            .map(|node| (node.party, node.bits[index]))
            .collect::<BTreeMap<_, _>>();
        bit_coefficients.push(coefficient_commitments_from_evaluations(
            &points, threshold,
        )?);
    }
    Ok(RangeStatement {
        commitment: value_coefficients[0],
        value_coefficients,
        bit_commitments: bit_coefficients
            .iter()
            .map(|coefficients| coefficients[0])
            .collect(),
        bit_coefficients,
        threshold,
    })
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

    pub(crate) fn as_node_shared(&self) -> NodeShared {
        NodeShared::new(
            self.party,
            self.commitment,
            self.value_share,
            self.blinding_share,
            self.value_coefficient_commitments.clone(),
        )
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

    /// Public evaluations of `C_bit * bit_share + h * cross_share`.
    /// The cross-term scalar remains local to this node.
    pub fn relation_evaluations(&self, key: &Pedersen) -> RangeRelationEvaluations {
        RangeRelationEvaluations {
            party: self.party,
            bits: self
                .bits
                .iter()
                .map(|bit| {
                    let (value, _) = bit.shared.own_evaluation();
                    bit.shared.commitment() * value + key.h * bit.cross_share
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RangeRelationEvaluations {
    pub party: PartyId,
    pub bits: Vec<RistrettoPoint>,
}

#[derive(Clone, Debug)]
pub struct RangeRelationStatement {
    pub coefficients: Vec<Vec<RistrettoPoint>>,
    pub threshold: usize,
}

pub fn range_relations_from_evaluations(
    statement: &RangeStatement,
    evaluations: &[RangeRelationEvaluations],
) -> Result<RangeRelationStatement, String> {
    if evaluations.len() < statement.threshold + 1
        || evaluations
            .iter()
            .any(|node| node.bits.len() != statement.bit_commitments.len())
    {
        return Err("range relation evaluations have the wrong shape".into());
    }
    let unique = evaluations
        .iter()
        .map(|node| node.party)
        .collect::<std::collections::BTreeSet<_>>();
    if unique.len() != evaluations.len() {
        return Err("a party supplied more than one range relation evaluation".into());
    }
    let mut coefficients = Vec::with_capacity(statement.bit_commitments.len());
    for index in 0..statement.bit_commitments.len() {
        let points = evaluations
            .iter()
            .map(|node| (node.party, node.bits[index]))
            .collect::<BTreeMap<_, _>>();
        let ladder = coefficient_commitments_from_evaluations(&points, statement.threshold)?;
        if ladder[0].compress() != statement.bit_commitments[index].compress() {
            return Err(format!(
                "bit {index} relation constant does not equal its bit commitment"
            ));
        }
        coefficients.push(ladder);
    }
    Ok(RangeRelationStatement {
        coefficients,
        threshold: statement.threshold,
    })
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

/// First public proof move from one node. Every node seals these points before
/// any reveal, preventing an adaptive node from cancelling an honest nonce.
#[derive(Clone, Debug)]
pub struct RangeRound1 {
    pub party: PartyId,
    pub context_digest: [u8; 32],
    pub bit_factor: Vec<RistrettoPoint>,
    pub bit_product: Vec<RistrettoPoint>,
    pub linkage: RistrettoPoint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeRound1Seal {
    pub party: PartyId,
    pub digest: [u8; 32],
}

/// Kept by exactly one node and consumed when answering the challenge.
pub struct RangeRound1Secret {
    party: PartyId,
    bit_nonces: Vec<(Scalar, Scalar, Scalar)>,
    linkage_nonce: (Scalar, Scalar),
    message_digest: [u8; 32],
    context_digest: [u8; 32],
}

fn range_round1_digest(message: &RangeRound1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"QOMM:THRESHOLD-RANGE:ROUND1:v1");
    hasher.update((message.party as u64).to_be_bytes());
    hasher.update(message.context_digest);
    hasher.update((message.bit_factor.len() as u64).to_be_bytes());
    for (factor, product) in message.bit_factor.iter().zip(&message.bit_product) {
        hasher.update(factor.compress().as_bytes());
        hasher.update(product.compress().as_bytes());
    }
    hasher.update(message.linkage.compress().as_bytes());
    hasher.finalize().into()
}

pub fn prepare_range_round1<R: RngCore + CryptoRng>(
    key: &Pedersen,
    shares: &NodeValueShares,
    context: &[u8],
    rng: &mut R,
) -> (RangeRound1Seal, RangeRound1Secret, RangeRound1) {
    let bit_nonces = (0..shares.width())
        .map(|_| {
            (
                Scalar::random(&mut *rng),
                Scalar::random(&mut *rng),
                Scalar::random(&mut *rng),
            )
        })
        .collect::<Vec<_>>();
    let bit_factor = bit_nonces
        .iter()
        .map(|(value, blinding, _)| key.commit(value, blinding))
        .collect();
    let bit_product = bit_nonces
        .iter()
        .zip(&shares.bits)
        .map(|((value, _, relation), bit)| bit.shared.commitment() * value + key.h * relation)
        .collect();
    let linkage_nonce = (Scalar::random(&mut *rng), Scalar::random(&mut *rng));
    let context_digest: [u8; 32] = Sha256::digest(context).into();
    let message = RangeRound1 {
        party: shares.party,
        context_digest,
        bit_factor,
        bit_product,
        linkage: key.commit(&linkage_nonce.0, &linkage_nonce.1),
    };
    let digest = range_round1_digest(&message);
    (
        RangeRound1Seal {
            party: shares.party,
            digest,
        },
        RangeRound1Secret {
            party: shares.party,
            bit_nonces,
            linkage_nonce,
            message_digest: digest,
            context_digest,
        },
        message,
    )
}

#[derive(Clone, Debug)]
pub struct RangeChallenge {
    pub quorum: Vec<PartyId>,
    pub context_digest: [u8; 32],
    pub bit_factor: Vec<RistrettoPoint>,
    pub bit_product: Vec<RistrettoPoint>,
    pub bit_challenges: Vec<Scalar>,
    pub linkage: RistrettoPoint,
    pub linkage_challenge: Scalar,
}

fn checked_round1<'a>(
    messages: &'a [RangeRound1],
    seals: &[RangeRound1Seal],
    quorum: &[PartyId],
    context: &[u8],
    width: usize,
) -> Result<BTreeMap<PartyId, &'a RangeRound1>, String> {
    let expected_context: [u8; 32] = Sha256::digest(context).into();
    let by_party = messages
        .iter()
        .map(|message| (message.party, message))
        .collect::<BTreeMap<_, _>>();
    let seal_by_party = seals
        .iter()
        .map(|seal| (seal.party, seal))
        .collect::<BTreeMap<_, _>>();
    if by_party.len() != quorum.len()
        || seal_by_party.len() != quorum.len()
        || quorum
            .iter()
            .any(|party| !by_party.contains_key(party) || !seal_by_party.contains_key(party))
    {
        return Err("round-one messages and seals do not exactly match the quorum".into());
    }
    for party in quorum {
        let message = by_party[party];
        if message.context_digest != expected_context
            || message.bit_factor.len() != width
            || message.bit_product.len() != width
            || range_round1_digest(message) != seal_by_party[party].digest
        {
            return Err(format!(
                "party {party} supplied an invalid range round-one reveal"
            ));
        }
    }
    Ok(by_party)
}

pub fn make_range_challenge(
    statement: &RangeStatement,
    messages: &[RangeRound1],
    seals: &[RangeRound1Seal],
    quorum: &[PartyId],
    context: &[u8],
) -> Result<RangeChallenge, String> {
    let by_party = checked_round1(
        messages,
        seals,
        quorum,
        context,
        statement.bit_commitments.len(),
    )?;
    let combine_at = |factor: bool, index: usize| {
        combine_commitments(
            &quorum
                .iter()
                .map(|party| {
                    let message = by_party[party];
                    (
                        *party,
                        if factor {
                            message.bit_factor[index]
                        } else {
                            message.bit_product[index]
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>(),
        )
    };
    let mut bit_factor = Vec::with_capacity(statement.bit_commitments.len());
    let mut bit_product = Vec::with_capacity(statement.bit_commitments.len());
    let mut bit_challenges = Vec::with_capacity(statement.bit_commitments.len());
    for index in 0..statement.bit_commitments.len() {
        let factor = combine_at(true, index)?;
        let product = combine_at(false, index)?;
        let component = bit_context(context, index).map_err(str::to_string)?;
        let mut transcript = component_transcript(&component);
        let challenge = product_challenge(
            &mut transcript,
            &statement.bit_commitments[index],
            &statement.bit_commitments[index],
            &statement.bit_commitments[index],
            &factor,
            &product,
        );
        bit_factor.push(factor);
        bit_product.push(product);
        bit_challenges.push(challenge);
    }
    let linkage = combine_commitments(
        &quorum
            .iter()
            .map(|party| (*party, by_party[party].linkage))
            .collect::<BTreeMap<_, _>>(),
    )?;
    let mut aggregate = RistrettoPoint::identity();
    let mut weight = Scalar::ONE;
    for commitment in &statement.bit_commitments {
        aggregate += commitment * weight;
        weight += weight;
    }
    let residual = statement.commitment - aggregate;
    let link_context = suffixed_context(context, b":link");
    let mut transcript = component_transcript(&link_context);
    let linkage_challenge = opening_challenge(&mut transcript, &residual, &linkage);
    Ok(RangeChallenge {
        quorum: quorum.to_vec(),
        context_digest: Sha256::digest(context).into(),
        bit_factor,
        bit_product,
        bit_challenges,
        linkage,
        linkage_challenge,
    })
}

#[derive(Clone, Debug)]
pub struct RangeRound2 {
    pub party: PartyId,
    pub bit_answers: Vec<(Scalar, Scalar, Scalar)>,
    pub linkage_answer: (Scalar, Scalar),
}

pub fn answer_range_challenge(
    shares: &NodeValueShares,
    secret: RangeRound1Secret,
    challenge: &RangeChallenge,
) -> Result<RangeRound2, String> {
    if shares.party != secret.party
        || !challenge.quorum.contains(&shares.party)
        || secret.bit_nonces.len() != shares.bits.len()
        || secret.message_digest == [0u8; 32]
        || secret.context_digest != challenge.context_digest
    {
        return Err("range challenge does not match this node's sealed first round".into());
    }
    let bit_answers = shares
        .bits
        .iter()
        .zip(secret.bit_nonces)
        .zip(&challenge.bit_challenges)
        .map(|((bit, (k_value, k_blinding, k_relation)), challenge)| {
            let (value, blinding) = bit.shared.own_evaluation();
            (
                k_value + challenge * value,
                k_blinding + challenge * blinding,
                k_relation + challenge * bit.cross_share,
            )
        })
        .collect();
    let mut residual_value = shares.value_share;
    let mut residual_blinding = shares.blinding_share;
    let mut weight = Scalar::ONE;
    for bit in &shares.bits {
        let (value, blinding) = bit.shared.own_evaluation();
        residual_value -= weight * value;
        residual_blinding -= weight * blinding;
        weight += weight;
    }
    Ok(RangeRound2 {
        party: shares.party,
        bit_answers,
        linkage_answer: (
            secret.linkage_nonce.0 + challenge.linkage_challenge * residual_value,
            secret.linkage_nonce.1 + challenge.linkage_challenge * residual_blinding,
        ),
    })
}

fn residual_coefficients(statement: &RangeStatement) -> Vec<RistrettoPoint> {
    let mut out = statement.value_coefficients.clone();
    let mut weight = Scalar::ONE;
    for ladder in &statement.bit_coefficients {
        for (target, coefficient) in out.iter_mut().zip(ladder) {
            *target -= coefficient * weight;
        }
        weight += weight;
    }
    out
}

#[allow(clippy::too_many_arguments)]
pub fn assemble_range_from_rounds(
    key: &Pedersen,
    statement: &RangeStatement,
    relations: &RangeRelationStatement,
    messages: &[RangeRound1],
    seals: &[RangeRound1Seal],
    responses: &[RangeRound2],
    quorum: &[PartyId],
    context: &[u8],
) -> Result<ThresholdRangeProof, String> {
    if relations.threshold != statement.threshold
        || relations.coefficients.len() != statement.bit_commitments.len()
    {
        return Err("range relation and value statements have different shapes".into());
    }
    let challenge = make_range_challenge(statement, messages, seals, quorum, context)?;
    let first = messages
        .iter()
        .map(|message| (message.party, message))
        .collect::<BTreeMap<_, _>>();
    let answers = responses
        .iter()
        .map(|answer| (answer.party, answer))
        .collect::<BTreeMap<_, _>>();
    if answers.len() != quorum.len() || quorum.iter().any(|party| !answers.contains_key(party)) {
        return Err("range responses do not exactly match the quorum".into());
    }
    let residual_ladder = residual_coefficients(statement);
    for party in quorum {
        let answer = answers[party];
        if answer.bit_answers.len() != statement.bit_commitments.len() {
            return Err(format!(
                "party {party} returned the wrong number of bit answers"
            ));
        }
        for index in 0..statement.bit_commitments.len() {
            let (z_value, z_blinding, z_relation) = answer.bit_answers[index];
            let factor_evaluation = share_commitment(&statement.bit_coefficients[index], *party)?;
            if key.commit(&z_value, &z_blinding).compress()
                != (first[party].bit_factor[index]
                    + factor_evaluation * challenge.bit_challenges[index])
                    .compress()
            {
                return Err(format!(
                    "party {party} supplied a bad bit-{index} factor answer"
                ));
            }
            let relation_evaluation = share_commitment(&relations.coefficients[index], *party)?;
            if (statement.bit_commitments[index] * z_value + key.h * z_relation).compress()
                != (first[party].bit_product[index]
                    + relation_evaluation * challenge.bit_challenges[index])
                    .compress()
            {
                return Err(format!(
                    "party {party} supplied a bad bit-{index} relation answer"
                ));
            }
        }
        let residual_evaluation = share_commitment(&residual_ladder, *party)?;
        if key
            .commit(&answer.linkage_answer.0, &answer.linkage_answer.1)
            .compress()
            != (first[party].linkage + residual_evaluation * challenge.linkage_challenge).compress()
        {
            return Err(format!("party {party} supplied a bad range-link answer"));
        }
    }
    let coefficients = lagrange_at_zero(quorum)?;
    let mut bit_proofs = Vec::with_capacity(statement.bit_commitments.len());
    for index in 0..statement.bit_commitments.len() {
        let (mut z_b, mut z_rb, mut z_s) = (Scalar::ZERO, Scalar::ZERO, Scalar::ZERO);
        for party in quorum {
            let coefficient = coefficients[party];
            let answer = answers[party].bit_answers[index];
            z_b += coefficient * answer.0;
            z_rb += coefficient * answer.1;
            z_s += coefficient * answer.2;
        }
        bit_proofs.push(ProductProof {
            t_factor: challenge.bit_factor[index],
            t_product: challenge.bit_product[index],
            z_b,
            z_rb,
            z_s,
        });
    }
    let mut linkage_answer = (Scalar::ZERO, Scalar::ZERO);
    for party in quorum {
        linkage_answer.0 += coefficients[party] * answers[party].linkage_answer.0;
        linkage_answer.1 += coefficients[party] * answers[party].linkage_answer.1;
    }
    let proof = ThresholdRangeProof {
        bit_commitments: statement.bit_commitments.clone(),
        bit_proofs,
        linkage: OpeningProof {
            t: challenge.linkage,
            z_value: linkage_answer.0,
            z_blinding: linkage_answer.1,
        },
        bits: statement.bit_commitments.len(),
    };
    if !verify_threshold_range(key, &statement.commitment, &proof, context) {
        return Err("assembled threshold range proof does not verify".into());
    }
    Ok(proof)
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
    let value_shared = deal(key, &value_scalar, blinding, parties, threshold, &mut *rng)?;
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
        commitment: value_shared.commitment,
        value: value_shared.value_shares,
        blinding: value_shared.blinding_shares,
        value_coefficient_commitments: value_shared.coefficient_commitments,
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
        value_coefficient_commitments: shared.coefficient_commitments.clone(),
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
