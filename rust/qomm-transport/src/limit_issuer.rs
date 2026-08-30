//! Node-local proof that the MPC-selected quote is inside the Taker's
//! pre-signed hidden limit.
//!
//! The MPC circuit has already applied direction and persisted a sharing of
//! `limit - quote` for a buy or `quote - limit` for a sell.  This module turns
//! exactly one node's persistence prefix into a joint range proof without any
//! process reconstructing the quote, limit, difference, or blindings.

use curve25519_dalek::scalar::Scalar;
use qomm_mpc::persistence::{FieldElement, LocalRangeHandoff, LocalZkpiHandoff};
use qomm_proofs::threshold_quote::RISTRETTO_SCALAR_ORDER_LE;
use qomm_proofs::threshold_range::{
    answer_range_challenge, assemble_range_from_rounds, make_range_challenge, prepare_range_round1,
    range_relations_from_evaluations, range_statement_from_evaluations, LocalRangeShares,
    NodeValueShares, RangeChallenge, RangeEvaluations, RangeRelationEvaluations,
    RangeRelationStatement, RangeRound1, RangeRound1Seal, RangeRound1Secret, RangeRound2,
    RangeStatement, ThresholdRangeProof,
};
use qomm_proofs::threshold_sigma::PartyId;
use qomm_zk::pedersen::Pedersen;
use rand_core::{CryptoRng, RngCore};
use std::collections::BTreeSet;

fn field_scalar(value: &FieldElement) -> Result<Scalar, String> {
    let bytes: [u8; 32] = value
        .to_bytes_le(32)
        .map_err(|error| error.to_string())?
        .try_into()
        .expect("a requested 32-byte encoding");
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .ok_or_else(|| "an MPC limit share is outside the Ristretto scalar field".into())
}

fn local_range(
    party: PartyId,
    handoff: LocalRangeHandoff,
    threshold: usize,
) -> Result<LocalRangeShares, String> {
    LocalRangeShares::new(
        party,
        field_scalar(&handoff.value_share)?,
        field_scalar(&handoff.blinding_share)?,
        handoff
            .bits
            .iter()
            .map(|(bit, blinding, cross)| {
                Ok((
                    field_scalar(bit)?,
                    field_scalar(blinding)?,
                    field_scalar(cross)?,
                ))
            })
            .collect::<Result<Vec<_>, String>>()?,
        threshold,
    )
}

fn unique_parties(parties: impl IntoIterator<Item = PartyId>, what: &str) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for party in parties {
        if party == 0 || !seen.insert(party) {
            return Err(format!(
                "{what} has an invalid or duplicate node identifier"
            ));
        }
    }
    Ok(())
}

pub struct MpcLimitNode {
    party: PartyId,
    difference: LocalRangeShares,
}

impl MpcLimitNode {
    pub fn from_handoff(handoff: LocalZkpiHandoff, threshold: usize) -> Result<Self, String> {
        let prime: [u8; 32] = handoff
            .prime
            .to_bytes_le(32)
            .map_err(|error| error.to_string())?
            .try_into()
            .expect("a requested 32-byte encoding");
        if prime != RISTRETTO_SCALAR_ORDER_LE {
            return Err("MPC and hidden-limit commitments use different scalar fields".into());
        }
        let party = handoff
            .party
            .checked_add(1)
            .ok_or("MPC party identifier overflow")?;
        Ok(Self {
            party,
            difference: local_range(party, handoff.price_limit_difference, threshold)?,
        })
    }

    pub fn party(&self) -> PartyId {
        self.party
    }

    pub fn evaluations(&self, key: &Pedersen) -> RangeEvaluations {
        self.difference.evaluations(key)
    }

    pub fn bind(
        self,
        key: &Pedersen,
        statement: &RangeStatement,
    ) -> Result<BoundMpcLimitNode, String> {
        Ok(BoundMpcLimitNode {
            party: self.party,
            difference: self.difference.bind(key, statement)?,
        })
    }
}

pub struct BoundMpcLimitNode {
    party: PartyId,
    difference: NodeValueShares,
}

impl BoundMpcLimitNode {
    pub fn party(&self) -> PartyId {
        self.party
    }

    pub fn relation_evaluations(&self, key: &Pedersen) -> RangeRelationEvaluations {
        self.difference.relation_evaluations(key)
    }

    pub fn prepare_round1<R: RngCore + CryptoRng>(
        &self,
        key: &Pedersen,
        context: &[u8],
        rng: &mut R,
    ) -> (RangeRound1Seal, RangeRound1Secret, RangeRound1) {
        prepare_range_round1(key, &self.difference, context, rng)
    }

    pub fn answer(
        &self,
        secret: RangeRound1Secret,
        challenge: &RangeChallenge,
    ) -> Result<RangeRound2, String> {
        answer_range_challenge(&self.difference, secret, challenge)
    }
}

pub fn statement_from_evaluations(
    evaluations: &[RangeEvaluations],
    threshold: usize,
) -> Result<RangeStatement, String> {
    unique_parties(
        evaluations.iter().map(|value| value.party),
        "limit evaluation",
    )?;
    range_statement_from_evaluations(evaluations, threshold)
}

pub fn relation_from_evaluations(
    statement: &RangeStatement,
    evaluations: &[RangeRelationEvaluations],
) -> Result<RangeRelationStatement, String> {
    unique_parties(
        evaluations.iter().map(|value| value.party),
        "limit relation evaluation",
    )?;
    range_relations_from_evaluations(statement, evaluations)
}

pub fn challenge(
    statement: &RangeStatement,
    rounds: &[RangeRound1],
    seals: &[RangeRound1Seal],
    quorum: &[PartyId],
    context: &[u8],
) -> Result<RangeChallenge, String> {
    unique_parties(rounds.iter().map(|value| value.party), "limit round one")?;
    unique_parties(
        seals.iter().map(|value| value.party),
        "limit round-one seal",
    )?;
    make_range_challenge(statement, rounds, seals, quorum, context)
}

#[allow(clippy::too_many_arguments)]
pub fn assemble(
    key: &Pedersen,
    statement: &RangeStatement,
    relation: &RangeRelationStatement,
    rounds: &[RangeRound1],
    seals: &[RangeRound1Seal],
    responses: &[RangeRound2],
    quorum: &[PartyId],
    context: &[u8],
) -> Result<ThresholdRangeProof, String> {
    unique_parties(responses.iter().map(|value| value.party), "limit round two")?;
    assemble_range_from_rounds(
        key, statement, relation, rounds, seals, responses, quorum, context,
    )
}
