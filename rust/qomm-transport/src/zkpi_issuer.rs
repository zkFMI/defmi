//! Node-local MPC output to a threshold-issued zkPI.
//!
//! The coordinator-facing types in this module contain group points, seals,
//! challenges, and masked responses. `MpcZkpiNode` alone owns scalar shares,
//! and its fields are private. This is the boundary that prevents a convenient
//! proof assembler from silently becoming a cleartext reconstruction service.

use curve25519_dalek::ristretto::RistrettoPoint;
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
use qomm_zkpi::{Bounds, PartialInstruction, AMOUNT_RANGE_CONTEXT, PRICE_RANGE_CONTEXT};
use rand_core::{CryptoRng, RngCore};
use std::collections::BTreeSet;

fn check_parties(
    parties: impl IntoIterator<Item = (PartyId, PartyId, PartyId)>,
    what: &str,
) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for (outer, amount, price) in parties {
        if outer == 0 || outer != amount || outer != price {
            return Err(format!(
                "{what} has inconsistent amount/price node identifiers"
            ));
        }
        if !seen.insert(outer) {
            return Err(format!("a node supplied more than one {what}"));
        }
    }
    Ok(())
}

pub(crate) fn field_scalar(value: &FieldElement) -> Result<Scalar, String> {
    let bytes: [u8; 32] = value
        .to_bytes_le(32)
        .map_err(|error| error.to_string())?
        .try_into()
        .expect("a requested 32-byte encoding");
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .ok_or_else(|| "an MPC persistence share is outside the Ristretto scalar field".into())
}

pub(crate) fn local_range(
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

pub struct MpcZkpiNode {
    party: PartyId,
    amount: LocalRangeShares,
    price: LocalRangeShares,
}

impl MpcZkpiNode {
    /// Convert one party's own Persistence file output. MP-SPDZ files are
    /// zero-indexed while Shamir evaluation points are one-indexed.
    pub fn from_handoff(handoff: LocalZkpiHandoff, threshold: usize) -> Result<Self, String> {
        let prime: [u8; 32] = handoff
            .prime
            .to_bytes_le(32)
            .map_err(|error| error.to_string())?
            .try_into()
            .expect("a requested 32-byte encoding");
        if prime != RISTRETTO_SCALAR_ORDER_LE {
            return Err("MPC and zkPI commitments use different scalar fields".into());
        }
        let party = handoff
            .party
            .checked_add(1)
            .ok_or("MPC party identifier overflow")?;
        Ok(Self {
            party,
            amount: local_range(party, handoff.amount, threshold)?,
            price: local_range(party, handoff.price, threshold)?,
        })
    }

    pub fn from_local_ranges(
        amount: LocalRangeShares,
        price: LocalRangeShares,
    ) -> Result<Self, String> {
        if amount.party() != price.party() || amount.width() == 0 || price.width() == 0 {
            return Err("amount and price handoffs belong to different nodes or are empty".into());
        }
        Ok(Self {
            party: amount.party(),
            amount,
            price,
        })
    }

    pub fn party(&self) -> PartyId {
        self.party
    }

    pub fn evaluations(&self, key: &Pedersen) -> ZkpiEvaluations {
        ZkpiEvaluations {
            party: self.party,
            amount: self.amount.evaluations(key),
            price: self.price.evaluations(key),
        }
    }

    pub fn bind(
        self,
        key: &Pedersen,
        statements: &ZkpiStatements,
    ) -> Result<BoundMpcZkpiNode, String> {
        Ok(BoundMpcZkpiNode {
            party: self.party,
            amount: self.amount.bind(key, &statements.amount)?,
            price: self.price.bind(key, &statements.price)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ZkpiEvaluations {
    pub party: PartyId,
    pub amount: RangeEvaluations,
    pub price: RangeEvaluations,
}

#[derive(Clone, Debug)]
pub struct ZkpiStatements {
    pub amount: RangeStatement,
    pub price: RangeStatement,
}

pub fn statements_from_evaluations(
    evaluations: &[ZkpiEvaluations],
    threshold: usize,
) -> Result<ZkpiStatements, String> {
    check_parties(
        evaluations
            .iter()
            .map(|node| (node.party, node.amount.party, node.price.party)),
        "zkPI evaluation",
    )?;
    let amount = evaluations
        .iter()
        .map(|node| node.amount.clone())
        .collect::<Vec<_>>();
    let price = evaluations
        .iter()
        .map(|node| node.price.clone())
        .collect::<Vec<_>>();
    Ok(ZkpiStatements {
        amount: range_statement_from_evaluations(&amount, threshold)?,
        price: range_statement_from_evaluations(&price, threshold)?,
    })
}

pub struct BoundMpcZkpiNode {
    party: PartyId,
    amount: NodeValueShares,
    price: NodeValueShares,
}

impl BoundMpcZkpiNode {
    pub fn party(&self) -> PartyId {
        self.party
    }

    /// This node's Shamir evaluation of the securities-delivery opening.
    /// Callers may encrypt it for a recipient but must never return it in
    /// cleartext to the coordinator.
    pub fn amount_opening_share(&self) -> (Scalar, Scalar) {
        self.amount.own_evaluation()
    }

    pub fn relation_evaluations(&self, key: &Pedersen) -> ZkpiRelationEvaluations {
        ZkpiRelationEvaluations {
            party: self.party,
            amount: self.amount.relation_evaluations(key),
            price: self.price.relation_evaluations(key),
        }
    }

    pub fn prepare_round1<R: RngCore + CryptoRng>(
        &self,
        key: &Pedersen,
        rng: &mut R,
    ) -> (ZkpiRound1Seals, ZkpiRound1Secrets, ZkpiRound1) {
        let (amount_seal, amount_secret, amount) =
            prepare_range_round1(key, &self.amount, AMOUNT_RANGE_CONTEXT, rng);
        let (price_seal, price_secret, price) =
            prepare_range_round1(key, &self.price, PRICE_RANGE_CONTEXT, rng);
        (
            ZkpiRound1Seals {
                party: self.party,
                amount: amount_seal,
                price: price_seal,
            },
            ZkpiRound1Secrets {
                party: self.party,
                amount: amount_secret,
                price: price_secret,
            },
            ZkpiRound1 {
                party: self.party,
                amount,
                price,
            },
        )
    }

    pub fn answer(
        &self,
        secrets: ZkpiRound1Secrets,
        challenge: &ZkpiChallenge,
    ) -> Result<ZkpiRound2, String> {
        if secrets.party != self.party {
            return Err("zkPI proof-round secrets belong to another node".into());
        }
        if challenge.amount.quorum != challenge.price.quorum {
            return Err("amount and price challenges name different quorums".into());
        }
        Ok(ZkpiRound2 {
            party: self.party,
            amount: answer_range_challenge(&self.amount, secrets.amount, &challenge.amount)?,
            price: answer_range_challenge(&self.price, secrets.price, &challenge.price)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ZkpiRelationEvaluations {
    pub party: PartyId,
    pub amount: RangeRelationEvaluations,
    pub price: RangeRelationEvaluations,
}

#[derive(Clone, Debug)]
pub struct ZkpiRelationStatements {
    pub amount: RangeRelationStatement,
    pub price: RangeRelationStatement,
}

pub fn relation_statements_from_evaluations(
    statements: &ZkpiStatements,
    evaluations: &[ZkpiRelationEvaluations],
) -> Result<ZkpiRelationStatements, String> {
    check_parties(
        evaluations
            .iter()
            .map(|node| (node.party, node.amount.party, node.price.party)),
        "zkPI relation evaluation",
    )?;
    Ok(ZkpiRelationStatements {
        amount: range_relations_from_evaluations(
            &statements.amount,
            &evaluations
                .iter()
                .map(|node| node.amount.clone())
                .collect::<Vec<_>>(),
        )?,
        price: range_relations_from_evaluations(
            &statements.price,
            &evaluations
                .iter()
                .map(|node| node.price.clone())
                .collect::<Vec<_>>(),
        )?,
    })
}

#[derive(Clone, Debug)]
pub struct ZkpiRound1Seals {
    pub party: PartyId,
    pub amount: RangeRound1Seal,
    pub price: RangeRound1Seal,
}

pub struct ZkpiRound1Secrets {
    party: PartyId,
    amount: RangeRound1Secret,
    price: RangeRound1Secret,
}

#[derive(Clone, Debug)]
pub struct ZkpiRound1 {
    pub party: PartyId,
    pub amount: RangeRound1,
    pub price: RangeRound1,
}

#[derive(Clone, Debug)]
pub struct ZkpiChallenge {
    pub amount: RangeChallenge,
    pub price: RangeChallenge,
}

pub fn make_challenge(
    statements: &ZkpiStatements,
    rounds: &[ZkpiRound1],
    seals: &[ZkpiRound1Seals],
    quorum: &[PartyId],
) -> Result<ZkpiChallenge, String> {
    check_parties(
        rounds
            .iter()
            .map(|node| (node.party, node.amount.party, node.price.party)),
        "zkPI round-one message",
    )?;
    check_parties(
        seals
            .iter()
            .map(|node| (node.party, node.amount.party, node.price.party)),
        "zkPI round-one seal",
    )?;
    Ok(ZkpiChallenge {
        amount: make_range_challenge(
            &statements.amount,
            &rounds
                .iter()
                .map(|node| node.amount.clone())
                .collect::<Vec<_>>(),
            &seals
                .iter()
                .map(|node| node.amount.clone())
                .collect::<Vec<_>>(),
            quorum,
            AMOUNT_RANGE_CONTEXT,
        )?,
        price: make_range_challenge(
            &statements.price,
            &rounds
                .iter()
                .map(|node| node.price.clone())
                .collect::<Vec<_>>(),
            &seals
                .iter()
                .map(|node| node.price.clone())
                .collect::<Vec<_>>(),
            quorum,
            PRICE_RANGE_CONTEXT,
        )?,
    })
}

#[derive(Clone, Debug)]
pub struct ZkpiRound2 {
    pub party: PartyId,
    pub amount: RangeRound2,
    pub price: RangeRound2,
}

pub struct ZkpiRangeProofs {
    pub amount: ThresholdRangeProof,
    pub price: ThresholdRangeProof,
}

pub fn assemble_ranges(
    key: &Pedersen,
    statements: &ZkpiStatements,
    relations: &ZkpiRelationStatements,
    rounds: &[ZkpiRound1],
    seals: &[ZkpiRound1Seals],
    responses: &[ZkpiRound2],
    quorum: &[PartyId],
) -> Result<ZkpiRangeProofs, String> {
    check_parties(
        rounds
            .iter()
            .map(|node| (node.party, node.amount.party, node.price.party)),
        "zkPI round-one message",
    )?;
    check_parties(
        seals
            .iter()
            .map(|node| (node.party, node.amount.party, node.price.party)),
        "zkPI round-one seal",
    )?;
    check_parties(
        responses
            .iter()
            .map(|node| (node.party, node.amount.party, node.price.party)),
        "zkPI round-two response",
    )?;
    Ok(ZkpiRangeProofs {
        amount: assemble_range_from_rounds(
            key,
            &statements.amount,
            &relations.amount,
            &rounds
                .iter()
                .map(|node| node.amount.clone())
                .collect::<Vec<_>>(),
            &seals
                .iter()
                .map(|node| node.amount.clone())
                .collect::<Vec<_>>(),
            &responses
                .iter()
                .map(|node| node.amount.clone())
                .collect::<Vec<_>>(),
            quorum,
            AMOUNT_RANGE_CONTEXT,
        )?,
        price: assemble_range_from_rounds(
            key,
            &statements.price,
            &relations.price,
            &rounds
                .iter()
                .map(|node| node.price.clone())
                .collect::<Vec<_>>(),
            &seals
                .iter()
                .map(|node| node.price.clone())
                .collect::<Vec<_>>(),
            &responses
                .iter()
                .map(|node| node.price.clone())
                .collect::<Vec<_>>(),
            quorum,
            PRICE_RANGE_CONTEXT,
        )?,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_partial_instruction(
    key: &Pedersen,
    bounds: &Bounds,
    statements: &ZkpiStatements,
    proofs: ZkpiRangeProofs,
    asset_commitment: RistrettoPoint,
    payer_handle: RistrettoPoint,
    payee_handle: RistrettoPoint,
    deadline: u64,
    nonce: [u8; 32],
    quote_proof_digest: [u8; 32],
) -> Result<PartialInstruction, String> {
    PartialInstruction::from_threshold_ranges(
        key,
        bounds,
        statements.amount.commitment,
        statements.price.commitment,
        asset_commitment,
        proofs.amount,
        proofs.price,
        payer_handle,
        payee_handle,
        deadline,
        nonce,
        quote_proof_digest,
    )
    .map_err(str::to_string)
}
