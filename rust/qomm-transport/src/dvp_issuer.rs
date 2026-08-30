//! Node-local threshold proof protocol for delivery versus payment.
//!
//! Each node owns one MPC output share for the price/cash product and one
//! share for each reservation remainder.  The coordinator sees only group
//! evaluations, sealed first moves, challenges and affine responses.  No API
//! in this module accepts a map containing another node's scalar shares.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use qomm_mpc::persistence::{FieldElement, LocalDvpHandoff, LocalRangeHandoff};
use qomm_proofs::threshold_gadgets::{
    answer_product_challenge, assemble_product_from_rounds, make_product_challenge,
    prepare_product_round1, product_statement_from_evaluations, LocalProductShares,
    ProductChallenge, ProductEvaluations, ProductNodeContribution, ProductRound1,
    ProductRound1Seal, ProductRound1Secret, ProductRound2, ProductStatement,
};
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
use qomm_zk::sigma::ProductProof;
use rand_core::{CryptoRng, RngCore};
use std::collections::BTreeSet;

pub const DVP_PRODUCT_CONTEXT: &[u8] = b"qomm:defmi:threshold-dvp:value:v1";
pub const DVP_SECURITIES_REMAINDER_CONTEXT: &[u8] =
    b"qomm:defmi:threshold-dvp:securities-remainder:v1";
pub const DVP_CASH_REMAINDER_CONTEXT: &[u8] = b"qomm:defmi:threshold-dvp:cash-remainder:v1";

fn field_scalar(value: &FieldElement) -> Result<Scalar, String> {
    let bytes: [u8; 32] = value
        .to_bytes_le(32)
        .map_err(|error| error.to_string())?
        .try_into()
        .expect("a requested 32-byte encoding");
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .ok_or_else(|| "an MPC DvP share is outside the Ristretto scalar field".into())
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

fn check_parties(
    parties: impl IntoIterator<Item = (PartyId, PartyId, PartyId, PartyId)>,
    what: &str,
) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for (outer, product, securities, cash) in parties {
        if outer == 0 || outer != product || outer != securities || outer != cash {
            return Err(format!("{what} has inconsistent DvP node identifiers"));
        }
        if !seen.insert(outer) {
            return Err(format!("a node supplied more than one {what}"));
        }
    }
    Ok(())
}

pub struct MpcDvpNode {
    party: PartyId,
    product: LocalProductShares,
    /// Exact cash-leg opening held only as this node's Shamir evaluation.
    /// It is not part of the coordinator-facing proof transcript.
    cash_opening: Option<(Scalar, Scalar)>,
    securities_remainder: LocalRangeShares,
    cash_remainder: LocalRangeShares,
}

impl MpcDvpNode {
    /// Convert exactly one party's MP-SPDZ persistence output.  Persistence
    /// files are zero-indexed; proof parties use Shamir evaluation points
    /// starting at one.
    pub fn from_handoff(handoff: LocalDvpHandoff, threshold: usize) -> Result<Self, String> {
        let prime: [u8; 32] = handoff
            .prime
            .to_bytes_le(32)
            .map_err(|error| error.to_string())?
            .try_into()
            .expect("a requested 32-byte encoding");
        if prime != RISTRETTO_SCALAR_ORDER_LE {
            return Err("MPC and DvP commitments use different scalar fields".into());
        }
        let party = handoff
            .party
            .checked_add(1)
            .ok_or("MPC party identifier overflow")?;
        let cash_opening = (
            field_scalar(&handoff.cash_value_share)?,
            field_scalar(&handoff.cash_blinding_share)?,
        );
        let mut node = Self::new(
            LocalProductShares::new(
                party,
                field_scalar(&handoff.price_share)?,
                field_scalar(&handoff.price_blinding_share)?,
                field_scalar(&handoff.product_cross_share)?,
                threshold,
            )?,
            local_range(party, handoff.securities_remainder, threshold)?,
            local_range(party, handoff.cash_remainder, threshold)?,
        )?;
        node.cash_opening = Some(cash_opening);
        Ok(node)
    }

    pub fn new(
        product: LocalProductShares,
        securities_remainder: LocalRangeShares,
        cash_remainder: LocalRangeShares,
    ) -> Result<Self, String> {
        let party = product.party();
        if securities_remainder.party() != party || cash_remainder.party() != party {
            return Err("one DvP node mixes private shares from different parties".into());
        }
        if securities_remainder.width() == 0 || cash_remainder.width() == 0 {
            return Err("a DvP remainder range cannot be empty".into());
        }
        Ok(Self {
            party,
            product,
            cash_opening: None,
            securities_remainder,
            cash_remainder,
        })
    }

    pub fn party(&self) -> PartyId {
        self.party
    }

    pub fn evaluations(
        &self,
        key: &Pedersen,
        quantity_commitment: &RistrettoPoint,
    ) -> DvpEvaluations {
        DvpEvaluations {
            party: self.party,
            product: self.product.evaluations(key, quantity_commitment),
            securities_remainder: self.securities_remainder.evaluations(key),
            cash_remainder: self.cash_remainder.evaluations(key),
        }
    }

    pub fn bind(
        self,
        key: &Pedersen,
        statements: &DvpStatements,
    ) -> Result<BoundMpcDvpNode, String> {
        Ok(BoundMpcDvpNode {
            party: self.party,
            product: self.product.bind(key, &statements.product)?,
            cash_opening: self.cash_opening,
            securities_remainder: self
                .securities_remainder
                .bind(key, &statements.securities_remainder)?,
            cash_remainder: self.cash_remainder.bind(key, &statements.cash_remainder)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct DvpEvaluations {
    pub party: PartyId,
    pub product: ProductEvaluations,
    pub securities_remainder: RangeEvaluations,
    pub cash_remainder: RangeEvaluations,
}

#[derive(Clone, Debug)]
pub struct DvpStatements {
    pub product: ProductStatement,
    pub securities_remainder: RangeStatement,
    pub cash_remainder: RangeStatement,
}

pub fn statements_from_evaluations(
    quantity_commitment: &RistrettoPoint,
    price_commitment: &RistrettoPoint,
    cash_commitment: &RistrettoPoint,
    securities_remainder: &RistrettoPoint,
    cash_remainder: &RistrettoPoint,
    evaluations: &[DvpEvaluations],
    threshold: usize,
) -> Result<DvpStatements, String> {
    check_parties(
        evaluations.iter().map(|node| {
            (
                node.party,
                node.product.party,
                node.securities_remainder.party,
                node.cash_remainder.party,
            )
        }),
        "DvP evaluation",
    )?;
    let product = product_statement_from_evaluations(
        quantity_commitment,
        price_commitment,
        cash_commitment,
        &evaluations
            .iter()
            .map(|node| node.product.clone())
            .collect::<Vec<_>>(),
        threshold,
    )?;
    let securities_statement = range_statement_from_evaluations(
        &evaluations
            .iter()
            .map(|node| node.securities_remainder.clone())
            .collect::<Vec<_>>(),
        threshold,
    )?;
    let cash_statement = range_statement_from_evaluations(
        &evaluations
            .iter()
            .map(|node| node.cash_remainder.clone())
            .collect::<Vec<_>>(),
        threshold,
    )?;
    if securities_statement.commitment.compress() != securities_remainder.compress()
        || cash_statement.commitment.compress() != cash_remainder.compress()
    {
        return Err("DvP remainder statements do not match the reservation differences".into());
    }
    Ok(DvpStatements {
        product,
        securities_remainder: securities_statement,
        cash_remainder: cash_statement,
    })
}

pub struct BoundMpcDvpNode {
    party: PartyId,
    product: ProductNodeContribution,
    cash_opening: Option<(Scalar, Scalar)>,
    securities_remainder: NodeValueShares,
    cash_remainder: NodeValueShares,
}

impl BoundMpcDvpNode {
    pub fn party(&self) -> PartyId {
        self.party
    }

    pub fn cash_opening_share(&self) -> Result<(Scalar, Scalar), String> {
        self.cash_opening
            .ok_or_else(|| "this DvP node was not created from an MPC cash handoff".into())
    }

    pub fn securities_remainder_opening_share(&self) -> (Scalar, Scalar) {
        self.securities_remainder.own_evaluation()
    }

    pub fn cash_remainder_opening_share(&self) -> (Scalar, Scalar) {
        self.cash_remainder.own_evaluation()
    }

    pub fn relation_evaluations(&self, key: &Pedersen) -> DvpRelationEvaluations {
        DvpRelationEvaluations {
            party: self.party,
            securities_remainder: self.securities_remainder.relation_evaluations(key),
            cash_remainder: self.cash_remainder.relation_evaluations(key),
        }
    }

    pub fn prepare_round1<R: RngCore + CryptoRng>(
        &self,
        key: &Pedersen,
        quantity_commitment: &RistrettoPoint,
        rng: &mut R,
    ) -> (DvpRound1Seals, DvpRound1Secrets, DvpRound1) {
        let (product_seal, product_secret, product) = prepare_product_round1(
            key,
            &self.product,
            quantity_commitment,
            DVP_PRODUCT_CONTEXT,
            rng,
        );
        let (securities_seal, securities_secret, securities_remainder) = prepare_range_round1(
            key,
            &self.securities_remainder,
            DVP_SECURITIES_REMAINDER_CONTEXT,
            rng,
        );
        let (cash_seal, cash_secret, cash_remainder) =
            prepare_range_round1(key, &self.cash_remainder, DVP_CASH_REMAINDER_CONTEXT, rng);
        (
            DvpRound1Seals {
                party: self.party,
                product: product_seal,
                securities_remainder: securities_seal,
                cash_remainder: cash_seal,
            },
            DvpRound1Secrets {
                party: self.party,
                product: product_secret,
                securities_remainder: securities_secret,
                cash_remainder: cash_secret,
            },
            DvpRound1 {
                party: self.party,
                product,
                securities_remainder,
                cash_remainder,
            },
        )
    }

    pub fn answer(
        &self,
        secrets: DvpRound1Secrets,
        challenge: &DvpChallenge,
    ) -> Result<DvpRound2, String> {
        if secrets.party != self.party {
            return Err("DvP proof-round secrets belong to another node".into());
        }
        Ok(DvpRound2 {
            party: self.party,
            product: answer_product_challenge(&self.product, secrets.product, &challenge.product)?,
            securities_remainder: answer_range_challenge(
                &self.securities_remainder,
                secrets.securities_remainder,
                &challenge.securities_remainder,
            )?,
            cash_remainder: answer_range_challenge(
                &self.cash_remainder,
                secrets.cash_remainder,
                &challenge.cash_remainder,
            )?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct DvpRelationEvaluations {
    pub party: PartyId,
    pub securities_remainder: RangeRelationEvaluations,
    pub cash_remainder: RangeRelationEvaluations,
}

#[derive(Clone, Debug)]
pub struct DvpRelationStatements {
    pub securities_remainder: RangeRelationStatement,
    pub cash_remainder: RangeRelationStatement,
}

pub fn relation_statements_from_evaluations(
    statements: &DvpStatements,
    evaluations: &[DvpRelationEvaluations],
) -> Result<DvpRelationStatements, String> {
    let mut seen = BTreeSet::new();
    for node in evaluations {
        if node.party == 0
            || node.party != node.securities_remainder.party
            || node.party != node.cash_remainder.party
            || !seen.insert(node.party)
        {
            return Err("a DvP relation evaluation has an inconsistent party".into());
        }
    }
    Ok(DvpRelationStatements {
        securities_remainder: range_relations_from_evaluations(
            &statements.securities_remainder,
            &evaluations
                .iter()
                .map(|node| node.securities_remainder.clone())
                .collect::<Vec<_>>(),
        )?,
        cash_remainder: range_relations_from_evaluations(
            &statements.cash_remainder,
            &evaluations
                .iter()
                .map(|node| node.cash_remainder.clone())
                .collect::<Vec<_>>(),
        )?,
    })
}

#[derive(Clone, Debug)]
pub struct DvpRound1Seals {
    pub party: PartyId,
    pub product: ProductRound1Seal,
    pub securities_remainder: RangeRound1Seal,
    pub cash_remainder: RangeRound1Seal,
}

pub struct DvpRound1Secrets {
    party: PartyId,
    product: ProductRound1Secret,
    securities_remainder: RangeRound1Secret,
    cash_remainder: RangeRound1Secret,
}

#[derive(Clone, Debug)]
pub struct DvpRound1 {
    pub party: PartyId,
    pub product: ProductRound1,
    pub securities_remainder: RangeRound1,
    pub cash_remainder: RangeRound1,
}

#[derive(Clone, Debug)]
pub struct DvpChallenge {
    pub product: ProductChallenge,
    pub securities_remainder: RangeChallenge,
    pub cash_remainder: RangeChallenge,
}

pub fn make_challenge(
    statements: &DvpStatements,
    rounds: &[DvpRound1],
    seals: &[DvpRound1Seals],
    quorum: &[PartyId],
) -> Result<DvpChallenge, String> {
    check_parties(
        rounds.iter().map(|node| {
            (
                node.party,
                node.product.party,
                node.securities_remainder.party,
                node.cash_remainder.party,
            )
        }),
        "DvP round-one message",
    )?;
    check_parties(
        seals.iter().map(|node| {
            (
                node.party,
                node.product.party,
                node.securities_remainder.party,
                node.cash_remainder.party,
            )
        }),
        "DvP round-one seal",
    )?;
    Ok(DvpChallenge {
        product: make_product_challenge(
            &statements.product,
            &rounds
                .iter()
                .map(|node| node.product.clone())
                .collect::<Vec<_>>(),
            &seals
                .iter()
                .map(|node| node.product.clone())
                .collect::<Vec<_>>(),
            quorum,
            DVP_PRODUCT_CONTEXT,
        )?,
        securities_remainder: make_range_challenge(
            &statements.securities_remainder,
            &rounds
                .iter()
                .map(|node| node.securities_remainder.clone())
                .collect::<Vec<_>>(),
            &seals
                .iter()
                .map(|node| node.securities_remainder.clone())
                .collect::<Vec<_>>(),
            quorum,
            DVP_SECURITIES_REMAINDER_CONTEXT,
        )?,
        cash_remainder: make_range_challenge(
            &statements.cash_remainder,
            &rounds
                .iter()
                .map(|node| node.cash_remainder.clone())
                .collect::<Vec<_>>(),
            &seals
                .iter()
                .map(|node| node.cash_remainder.clone())
                .collect::<Vec<_>>(),
            quorum,
            DVP_CASH_REMAINDER_CONTEXT,
        )?,
    })
}

#[derive(Clone, Debug)]
pub struct DvpRound2 {
    pub party: PartyId,
    pub product: ProductRound2,
    pub securities_remainder: RangeRound2,
    pub cash_remainder: RangeRound2,
}

#[derive(Clone, Debug)]
pub struct DvpProofs {
    pub product: ProductProof,
    pub securities_remainder: ThresholdRangeProof,
    pub cash_remainder: ThresholdRangeProof,
}

#[allow(clippy::too_many_arguments)]
pub fn assemble_proofs(
    key: &Pedersen,
    statements: &DvpStatements,
    relations: &DvpRelationStatements,
    rounds: &[DvpRound1],
    seals: &[DvpRound1Seals],
    responses: &[DvpRound2],
    quorum: &[PartyId],
) -> Result<DvpProofs, String> {
    check_parties(
        responses.iter().map(|node| {
            (
                node.party,
                node.product.party,
                node.securities_remainder.party,
                node.cash_remainder.party,
            )
        }),
        "DvP round-two response",
    )?;
    Ok(DvpProofs {
        product: assemble_product_from_rounds(
            key,
            &statements.product,
            &rounds
                .iter()
                .map(|node| node.product.clone())
                .collect::<Vec<_>>(),
            &seals
                .iter()
                .map(|node| node.product.clone())
                .collect::<Vec<_>>(),
            &responses
                .iter()
                .map(|node| node.product.clone())
                .collect::<Vec<_>>(),
            quorum,
            DVP_PRODUCT_CONTEXT,
        )?,
        securities_remainder: assemble_range_from_rounds(
            key,
            &statements.securities_remainder,
            &relations.securities_remainder,
            &rounds
                .iter()
                .map(|node| node.securities_remainder.clone())
                .collect::<Vec<_>>(),
            &seals
                .iter()
                .map(|node| node.securities_remainder.clone())
                .collect::<Vec<_>>(),
            &responses
                .iter()
                .map(|node| node.securities_remainder.clone())
                .collect::<Vec<_>>(),
            quorum,
            DVP_SECURITIES_REMAINDER_CONTEXT,
        )?,
        cash_remainder: assemble_range_from_rounds(
            key,
            &statements.cash_remainder,
            &relations.cash_remainder,
            &rounds
                .iter()
                .map(|node| node.cash_remainder.clone())
                .collect::<Vec<_>>(),
            &seals
                .iter()
                .map(|node| node.cash_remainder.clone())
                .collect::<Vec<_>>(),
            &responses
                .iter()
                .map(|node| node.cash_remainder.clone())
                .collect::<Vec<_>>(),
            quorum,
            DVP_CASH_REMAINDER_CONTEXT,
        )?,
    })
}
