//! Bounded wire envelope for the one-range hidden-limit protocol.
//!
//! It deliberately reuses the reviewed threshold-zkPI range codec.  The range
//! is duplicated into that codec's amount and price positions and decoding
//! rejects any byte-level semantic disagreement between the copies.  This
//! keeps one canonical point/scalar parser instead of introducing a second
//! network parser for the same proof messages.

use qomm_proofs::threshold_range::{
    RangeChallenge, RangeEvaluations, RangeRelationEvaluations, RangeRound1, RangeRound1Seal,
    RangeRound2,
};

use crate::zkpi_issuer::{
    ZkpiChallenge, ZkpiEvaluations, ZkpiRelationEvaluations, ZkpiRound1, ZkpiRound1Seals,
    ZkpiRound2,
};
use crate::zkpi_wire::{self, Envelope as InnerEnvelope, Message as InnerMessage};

#[derive(Clone, Debug)]
pub enum Message {
    Evaluations(RangeEvaluations),
    RelationEvaluations(RangeRelationEvaluations),
    Round1Seal(RangeRound1Seal),
    Round1(RangeRound1),
    Challenge(RangeChallenge),
    Round2(RangeRound2),
}

#[derive(Clone, Debug)]
pub struct Envelope {
    pub job_id: [u8; 32],
    pub message: Message,
}

fn point_eq(
    left: &curve25519_dalek::ristretto::RistrettoPoint,
    right: &curve25519_dalek::ristretto::RistrettoPoint,
) -> bool {
    left.compress() == right.compress()
}

fn evaluations_eq(left: &RangeEvaluations, right: &RangeEvaluations) -> bool {
    left.party == right.party
        && point_eq(&left.value, &right.value)
        && left.bits.len() == right.bits.len()
        && left
            .bits
            .iter()
            .zip(&right.bits)
            .all(|(a, b)| point_eq(a, b))
}

fn relations_eq(left: &RangeRelationEvaluations, right: &RangeRelationEvaluations) -> bool {
    left.party == right.party
        && left.bits.len() == right.bits.len()
        && left
            .bits
            .iter()
            .zip(&right.bits)
            .all(|(a, b)| point_eq(a, b))
}

fn round1_eq(left: &RangeRound1, right: &RangeRound1) -> bool {
    left.party == right.party
        && left.context_digest == right.context_digest
        && left.bit_factor.len() == right.bit_factor.len()
        && left.bit_product.len() == right.bit_product.len()
        && left
            .bit_factor
            .iter()
            .zip(&right.bit_factor)
            .all(|(a, b)| point_eq(a, b))
        && left
            .bit_product
            .iter()
            .zip(&right.bit_product)
            .all(|(a, b)| point_eq(a, b))
        && point_eq(&left.linkage, &right.linkage)
}

fn challenge_eq(left: &RangeChallenge, right: &RangeChallenge) -> bool {
    left.quorum == right.quorum
        && left.context_digest == right.context_digest
        && left.bit_factor.len() == right.bit_factor.len()
        && left.bit_product.len() == right.bit_product.len()
        && left.bit_challenges == right.bit_challenges
        && left
            .bit_factor
            .iter()
            .zip(&right.bit_factor)
            .all(|(a, b)| point_eq(a, b))
        && left
            .bit_product
            .iter()
            .zip(&right.bit_product)
            .all(|(a, b)| point_eq(a, b))
        && point_eq(&left.linkage, &right.linkage)
        && left.linkage_challenge == right.linkage_challenge
}

fn round2_eq(left: &RangeRound2, right: &RangeRound2) -> bool {
    left.party == right.party
        && left.bit_answers == right.bit_answers
        && left.linkage_answer == right.linkage_answer
}

pub fn encode(envelope: &Envelope) -> Result<Vec<u8>, String> {
    let message = match &envelope.message {
        Message::Evaluations(value) => InnerMessage::Evaluations(ZkpiEvaluations {
            party: value.party,
            amount: value.clone(),
            price: value.clone(),
        }),
        Message::RelationEvaluations(value) => {
            InnerMessage::RelationEvaluations(ZkpiRelationEvaluations {
                party: value.party,
                amount: value.clone(),
                price: value.clone(),
            })
        }
        Message::Round1Seal(value) => InnerMessage::Round1Seal(ZkpiRound1Seals {
            party: value.party,
            amount: value.clone(),
            price: value.clone(),
        }),
        Message::Round1(value) => InnerMessage::Round1(ZkpiRound1 {
            party: value.party,
            amount: value.clone(),
            price: value.clone(),
        }),
        Message::Challenge(value) => InnerMessage::Challenge(ZkpiChallenge {
            amount: value.clone(),
            price: value.clone(),
        }),
        Message::Round2(value) => InnerMessage::Round2(ZkpiRound2 {
            party: value.party,
            amount: value.clone(),
            price: value.clone(),
        }),
    };
    zkpi_wire::encode(&InnerEnvelope {
        job_id: envelope.job_id,
        message,
    })
    .map_err(|error| error.to_string())
}

pub fn decode(raw: &[u8]) -> Result<Envelope, String> {
    let inner = zkpi_wire::decode(raw).map_err(|error| error.to_string())?;
    let message = match inner.message {
        InnerMessage::Evaluations(value) if evaluations_eq(&value.amount, &value.price) => {
            Message::Evaluations(value.amount)
        }
        InnerMessage::RelationEvaluations(value) if relations_eq(&value.amount, &value.price) => {
            Message::RelationEvaluations(value.amount)
        }
        InnerMessage::Round1Seal(value) if value.amount == value.price => {
            Message::Round1Seal(value.amount)
        }
        InnerMessage::Round1(value) if round1_eq(&value.amount, &value.price) => {
            Message::Round1(value.amount)
        }
        InnerMessage::Challenge(value) if challenge_eq(&value.amount, &value.price) => {
            Message::Challenge(value.amount)
        }
        InnerMessage::Round2(value) if round2_eq(&value.amount, &value.price) => {
            Message::Round2(value.amount)
        }
        _ => return Err("hidden-limit wire copies disagree".into()),
    };
    Ok(Envelope {
        job_id: inner.job_id,
        message,
    })
}
