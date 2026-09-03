//! Bounded JSON wire encoding for the public rounds of the complete quote
//! proof.  Only canonical Ristretto points/scalars, hashes, party identifiers,
//! and public proof messages have encodings; private MPC shares and nonce
//! secrets intentionally have none.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use qomm_proofs::threshold_gadgets::{
    ProductChallenge, ProductEvaluations, ProductRound1, ProductRound1Seal, ProductRound2,
};
use qomm_proofs::threshold_quote::{
    QuoteChallenges, QuoteNodeEvaluations, QuoteRelationEvaluations, QuoteRound1, QuoteRound1Seals,
    QuoteRound2,
};
use qomm_proofs::threshold_range::{
    RangeChallenge, RangeEvaluations, RangeRelationEvaluations, RangeRound1, RangeRound1Seal,
    RangeRound2,
};
use qomm_proofs::threshold_sigma::{
    OpeningChallenge, OpeningRound1, OpeningRound1Seal, OpeningRound2, PartyId,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const VERSION: u64 = 1;
const MAX_PARTIES: usize = 64;
const MAX_MAKERS: usize = 4096;
const MAX_PRODUCTS: usize = MAX_MAKERS * 11;
const MAX_RANGES: usize = MAX_MAKERS * 3;
const MAX_BITS: usize = 64;

#[derive(Clone, Debug)]
pub enum Message {
    Evaluations(QuoteNodeEvaluations),
    RelationEvaluations(QuoteRelationEvaluations),
    Round1Seal(QuoteRound1Seals),
    Round1(QuoteRound1),
    Challenge(QuoteChallenges),
    Round2(QuoteRound2),
}

#[derive(Clone, Debug)]
pub struct Envelope {
    pub job_id: [u8; 32],
    pub message: Message,
}

fn point(value: &RistrettoPoint) -> String {
    hex::encode(value.compress().to_bytes())
}

fn scalar(value: &Scalar) -> String {
    hex::encode(value.to_bytes())
}

fn digest(value: &[u8; 32]) -> String {
    hex::encode(value)
}

fn party(value: PartyId) -> Result<u64, String> {
    if value == 0 || value > u16::MAX as usize {
        return Err("quote wire party is outside its canonical range".into());
    }
    Ok(value as u64)
}

fn range_evaluation(value: &RangeEvaluations) -> Result<Value, String> {
    bounded(&value.bits, 1, MAX_BITS, "range bits")?;
    Ok(json!({
        "v": point(&value.value),
        "b": value.bits.iter().map(point).collect::<Vec<_>>(),
    }))
}

fn relation_evaluation(value: &RangeRelationEvaluations) -> Result<Value, String> {
    bounded(&value.bits, 1, MAX_BITS, "range relations")?;
    Ok(json!(value.bits.iter().map(point).collect::<Vec<_>>()))
}

fn range_round1(value: &RangeRound1) -> Result<Value, String> {
    if value.bit_factor.len() != value.bit_product.len() {
        return Err("range round one has different factor/product lengths".into());
    }
    bounded(&value.bit_factor, 1, MAX_BITS, "range round-one bits")?;
    Ok(json!({
        "c": digest(&value.context_digest),
        "f": value.bit_factor.iter().map(point).collect::<Vec<_>>(),
        "p": value.bit_product.iter().map(point).collect::<Vec<_>>(),
        "l": point(&value.linkage),
    }))
}

fn range_challenge(value: &RangeChallenge) -> Result<Value, String> {
    if value.bit_factor.len() != value.bit_product.len()
        || value.bit_factor.len() != value.bit_challenges.len()
    {
        return Err("range challenge has different component lengths".into());
    }
    bounded(&value.bit_factor, 1, MAX_BITS, "range challenge bits")?;
    Ok(json!({
        "c": digest(&value.context_digest),
        "f": value.bit_factor.iter().map(point).collect::<Vec<_>>(),
        "p": value.bit_product.iter().map(point).collect::<Vec<_>>(),
        "x": value.bit_challenges.iter().map(scalar).collect::<Vec<_>>(),
        "l": point(&value.linkage),
        "lx": scalar(&value.linkage_challenge),
    }))
}

fn range_round2(value: &RangeRound2) -> Result<Value, String> {
    bounded(&value.bit_answers, 1, MAX_BITS, "range responses")?;
    Ok(json!({
        "b": value.bit_answers.iter().map(|(a,b,c)| json!([scalar(a), scalar(b), scalar(c)])).collect::<Vec<_>>(),
        "l": [scalar(&value.linkage_answer.0), scalar(&value.linkage_answer.1)],
    }))
}

fn quorum(value: &[PartyId]) -> Result<Vec<u64>, String> {
    bounded(value, 1, MAX_PARTIES, "quote quorum")?;
    if value.iter().copied().collect::<BTreeSet<_>>().len() != value.len() {
        return Err("quote quorum contains a duplicate party".into());
    }
    value.iter().map(|value| party(*value)).collect()
}

fn bounded<T>(values: &[T], minimum: usize, maximum: usize, name: &str) -> Result<(), String> {
    if values.len() < minimum || values.len() > maximum {
        return Err(format!("{name} length is outside [{minimum}, {maximum}]"));
    }
    Ok(())
}

pub fn encode(envelope: &Envelope) -> Result<Vec<u8>, String> {
    let (kind, body) = match &envelope.message {
        Message::Evaluations(value) => {
            bounded(&value.wires, 1, 1 + MAX_MAKERS * 22, "quote wires")?;
            bounded(&value.ranges, 1, MAX_RANGES, "quote ranges")?;
            (
                "evaluations",
                json!({
                    "party": party(value.party)?,
                    "wires": value.wires.iter().map(|wire| point(&wire.point)).collect::<Vec<_>>(),
                    "ranges": value.ranges.iter().map(range_evaluation).collect::<Result<Vec<_>,_>>()?,
                }),
            )
        }
        Message::RelationEvaluations(value) => {
            bounded(&value.products, 1, MAX_PRODUCTS, "quote products")?;
            bounded(&value.ranges, 1, MAX_RANGES, "quote ranges")?;
            (
                "relations",
                json!({
                    "party": party(value.party)?,
                    "products": value.products.iter().map(|entry| json!({"f": point(&entry.factor), "r": point(&entry.relation)})).collect::<Vec<_>>(),
                    "ranges": value.ranges.iter().map(relation_evaluation).collect::<Result<Vec<_>,_>>()?,
                }),
            )
        }
        Message::Round1Seal(value) => {
            bounded(&value.products, 1, MAX_PRODUCTS, "quote product seals")?;
            bounded(&value.ranges, 1, MAX_RANGES, "quote range seals")?;
            (
                "round1-seal",
                json!({
                    "party": party(value.party)?,
                    "products": value.products.iter().map(|entry| digest(&entry.digest)).collect::<Vec<_>>(),
                    "ranges": value.ranges.iter().map(|entry| digest(&entry.digest)).collect::<Vec<_>>(),
                    "winner": digest(&value.winner.digest),
                }),
            )
        }
        Message::Round1(value) => {
            bounded(&value.products, 1, MAX_PRODUCTS, "quote product rounds")?;
            bounded(&value.ranges, 1, MAX_RANGES, "quote range rounds")?;
            (
                "round1",
                json!({
                    "party": party(value.party)?,
                    "products": value.products.iter().map(|entry| json!({"c": digest(&entry.context_digest), "f": point(&entry.factor), "p": point(&entry.product)})).collect::<Vec<_>>(),
                    "ranges": value.ranges.iter().map(range_round1).collect::<Result<Vec<_>,_>>()?,
                    "winner": {"c": digest(&value.winner.context_digest), "n": point(&value.winner.nonce_commitment)},
                }),
            )
        }
        Message::Challenge(value) => {
            bounded(&value.products, 1, MAX_PRODUCTS, "quote product challenges")?;
            bounded(&value.ranges, 1, MAX_RANGES, "quote range challenges")?;
            let selected = quorum(&value.winner.quorum)?;
            if value
                .products
                .iter()
                .any(|entry| entry.quorum != value.winner.quorum)
                || value
                    .ranges
                    .iter()
                    .any(|entry| entry.quorum != value.winner.quorum)
            {
                return Err("quote challenges name different quorums".into());
            }
            (
                "challenge",
                json!({
                    "quorum": selected,
                    "products": value.products.iter().map(|entry| json!({"c": digest(&entry.context_digest), "f": point(&entry.factor), "p": point(&entry.product), "x": scalar(&entry.challenge)})).collect::<Vec<_>>(),
                    "ranges": value.ranges.iter().map(range_challenge).collect::<Result<Vec<_>,_>>()?,
                    "winner": {"c": digest(&value.winner.context_digest), "n": point(&value.winner.nonce_commitment), "x": scalar(&value.winner.challenge)},
                }),
            )
        }
        Message::Round2(value) => {
            bounded(&value.products, 1, MAX_PRODUCTS, "quote product responses")?;
            bounded(&value.ranges, 1, MAX_RANGES, "quote range responses")?;
            (
                "round2",
                json!({
                    "party": party(value.party)?,
                    "products": value.products.iter().map(|entry| json!([scalar(&entry.factor_answer), scalar(&entry.factor_blinding_answer), scalar(&entry.relation_answer)])).collect::<Vec<_>>(),
                    "ranges": value.ranges.iter().map(range_round2).collect::<Result<Vec<_>,_>>()?,
                    "winner": [scalar(&value.winner.value_answer), scalar(&value.winner.blinding_answer)],
                }),
            )
        }
    };
    serde_json::to_vec(&json!({
        "version": VERSION,
        "job": hex::encode(envelope.job_id),
        "kind": kind,
        "body": body,
    }))
    .map_err(|error| error.to_string())
}

fn object<'a>(value: &'a Value, name: &str) -> Result<&'a serde_json::Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{name} must be an object"))
}

fn array<'a>(value: Option<&'a Value>, name: &str, maximum: usize) -> Result<&'a [Value], String> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{name} must be an array"))?;
    bounded(values, 1, maximum, name)?;
    Ok(values)
}

fn parse_hex<const N: usize>(value: Option<&Value>, name: &str) -> Result<[u8; N], String> {
    hex::decode(
        value
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{name} must be hexadecimal"))?,
    )
    .map_err(|_| format!("{name} must be hexadecimal"))?
    .try_into()
    .map_err(|_| format!("{name} must contain {N} bytes"))
}

fn parse_point(value: Option<&Value>, name: &str) -> Result<RistrettoPoint, String> {
    CompressedRistretto(parse_hex(value, name)?)
        .decompress()
        .ok_or_else(|| format!("{name} is not a canonical Ristretto point"))
}

fn parse_scalar(value: Option<&Value>, name: &str) -> Result<Scalar, String> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(parse_hex(value, name)?))
        .ok_or_else(|| format!("{name} is not a canonical Ristretto scalar"))
}

fn parse_party(value: Option<&Value>) -> Result<PartyId, String> {
    value
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0 && *value <= u16::MAX as usize)
        .ok_or_else(|| "quote wire party is invalid".into())
}

fn parse_quorum(value: Option<&Value>) -> Result<Vec<PartyId>, String> {
    let values = array(value, "quote quorum", MAX_PARTIES)?;
    let parties = values
        .iter()
        .map(|entry| parse_party(Some(entry)))
        .collect::<Result<Vec<_>, _>>()?;
    if parties.iter().copied().collect::<BTreeSet<_>>().len() != parties.len() {
        return Err("quote quorum contains a duplicate party".into());
    }
    Ok(parties)
}

fn parse_points(
    value: Option<&Value>,
    name: &str,
    maximum: usize,
) -> Result<Vec<RistrettoPoint>, String> {
    array(value, name, maximum)?
        .iter()
        .map(|entry| parse_point(Some(entry), name))
        .collect()
}

fn parse_scalars(value: Option<&Value>, name: &str, maximum: usize) -> Result<Vec<Scalar>, String> {
    array(value, name, maximum)?
        .iter()
        .map(|entry| parse_scalar(Some(entry), name))
        .collect()
}

fn parse_range_evaluation(value: &Value, party: PartyId) -> Result<RangeEvaluations, String> {
    let body = object(value, "range evaluation")?;
    Ok(RangeEvaluations {
        party,
        value: parse_point(body.get("v"), "range value")?,
        bits: parse_points(body.get("b"), "range bits", MAX_BITS)?,
    })
}

fn parse_range_round1(value: &Value, party: PartyId) -> Result<RangeRound1, String> {
    let body = object(value, "range round one")?;
    let factors = parse_points(body.get("f"), "range factors", MAX_BITS)?;
    let products = parse_points(body.get("p"), "range products", MAX_BITS)?;
    if factors.len() != products.len() {
        return Err("range round-one lengths differ".into());
    }
    Ok(RangeRound1 {
        party,
        context_digest: parse_hex(body.get("c"), "range context")?,
        bit_factor: factors,
        bit_product: products,
        linkage: parse_point(body.get("l"), "range linkage")?,
    })
}

fn parse_range_challenge(value: &Value, quorum: &[PartyId]) -> Result<RangeChallenge, String> {
    let body = object(value, "range challenge")?;
    let factors = parse_points(body.get("f"), "range challenge factors", MAX_BITS)?;
    let products = parse_points(body.get("p"), "range challenge products", MAX_BITS)?;
    let challenges = parse_scalars(body.get("x"), "range bit challenges", MAX_BITS)?;
    if factors.len() != products.len() || factors.len() != challenges.len() {
        return Err("range challenge lengths differ".into());
    }
    Ok(RangeChallenge {
        quorum: quorum.to_vec(),
        context_digest: parse_hex(body.get("c"), "range context")?,
        bit_factor: factors,
        bit_product: products,
        bit_challenges: challenges,
        linkage: parse_point(body.get("l"), "range linkage")?,
        linkage_challenge: parse_scalar(body.get("lx"), "range linkage challenge")?,
    })
}

fn parse_range_round2(value: &Value, party: PartyId) -> Result<RangeRound2, String> {
    let body = object(value, "range response")?;
    let bits = array(body.get("b"), "range bit responses", MAX_BITS)?
        .iter()
        .map(|entry| {
            let values = array(Some(entry), "range bit response", 3)?;
            if values.len() != 3 {
                return Err("range bit response must contain three scalars".into());
            }
            Ok((
                parse_scalar(values.first(), "range value answer")?,
                parse_scalar(values.get(1), "range blinding answer")?,
                parse_scalar(values.get(2), "range relation answer")?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let linkage = array(body.get("l"), "range linkage response", 2)?;
    if linkage.len() != 2 {
        return Err("range linkage response must contain two scalars".into());
    }
    Ok(RangeRound2 {
        party,
        bit_answers: bits,
        linkage_answer: (
            parse_scalar(linkage.first(), "linkage value answer")?,
            parse_scalar(linkage.get(1), "linkage blinding answer")?,
        ),
    })
}

pub fn decode(raw: &[u8]) -> Result<Envelope, String> {
    let value: Value = serde_json::from_slice(raw).map_err(|_| "quote wire is not JSON")?;
    let envelope = object(&value, "quote envelope")?;
    if envelope.get("version").and_then(Value::as_u64) != Some(VERSION) {
        return Err("unsupported quote wire version".into());
    }
    let job_id = parse_hex(envelope.get("job"), "quote job")?;
    let kind = envelope
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| "quote wire kind is absent".to_string())?;
    let body = object(
        envelope
            .get("body")
            .ok_or_else(|| "quote wire body is absent".to_string())?,
        "quote body",
    )?;
    let message = match kind {
        "evaluations" => {
            let party = parse_party(body.get("party"))?;
            Message::Evaluations(QuoteNodeEvaluations {
                party,
                wires: parse_points(body.get("wires"), "quote wires", 1 + MAX_MAKERS * 22)?
                    .into_iter()
                    .map(|point| qomm_proofs::threshold_gadgets::WireEvaluation { party, point })
                    .collect(),
                ranges: array(body.get("ranges"), "quote ranges", MAX_RANGES)?
                    .iter()
                    .map(|entry| parse_range_evaluation(entry, party))
                    .collect::<Result<Vec<_>, _>>()?,
            })
        }
        "relations" => {
            let party = parse_party(body.get("party"))?;
            Message::RelationEvaluations(QuoteRelationEvaluations {
                party,
                products: array(body.get("products"), "quote products", MAX_PRODUCTS)?
                    .iter()
                    .map(|entry| {
                        let entry = object(entry, "quote product evaluation")?;
                        Ok(ProductEvaluations {
                            party,
                            factor: parse_point(entry.get("f"), "product factor")?,
                            relation: parse_point(entry.get("r"), "product relation")?,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?,
                ranges: array(body.get("ranges"), "quote ranges", MAX_RANGES)?
                    .iter()
                    .map(|entry| {
                        Ok(RangeRelationEvaluations {
                            party,
                            bits: parse_points(Some(entry), "range relations", MAX_BITS)?,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?,
            })
        }
        "round1-seal" => {
            let party = parse_party(body.get("party"))?;
            Message::Round1Seal(QuoteRound1Seals {
                party,
                products: array(body.get("products"), "product seals", MAX_PRODUCTS)?
                    .iter()
                    .map(|entry| {
                        Ok(ProductRound1Seal {
                            party,
                            digest: parse_hex(Some(entry), "product seal")?,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?,
                ranges: array(body.get("ranges"), "range seals", MAX_RANGES)?
                    .iter()
                    .map(|entry| {
                        Ok(RangeRound1Seal {
                            party,
                            digest: parse_hex(Some(entry), "range seal")?,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?,
                winner: OpeningRound1Seal {
                    party,
                    digest: parse_hex(body.get("winner"), "winner seal")?,
                },
            })
        }
        "round1" => {
            let party = parse_party(body.get("party"))?;
            Message::Round1(QuoteRound1 {
                party,
                products: array(body.get("products"), "product rounds", MAX_PRODUCTS)?
                    .iter()
                    .map(|entry| {
                        let entry = object(entry, "product round")?;
                        Ok(ProductRound1 {
                            party,
                            context_digest: parse_hex(entry.get("c"), "product context")?,
                            factor: parse_point(entry.get("f"), "product nonce")?,
                            product: parse_point(entry.get("p"), "product relation nonce")?,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?,
                ranges: array(body.get("ranges"), "range rounds", MAX_RANGES)?
                    .iter()
                    .map(|entry| parse_range_round1(entry, party))
                    .collect::<Result<Vec<_>, _>>()?,
                winner: {
                    let winner = object(
                        body.get("winner").ok_or("winner round is absent")?,
                        "winner round",
                    )?;
                    OpeningRound1 {
                        party,
                        context_digest: parse_hex(winner.get("c"), "winner context")?,
                        nonce_commitment: parse_point(winner.get("n"), "winner nonce")?,
                    }
                },
            })
        }
        "challenge" => {
            let selected = parse_quorum(body.get("quorum"))?;
            Message::Challenge(QuoteChallenges {
                products: array(body.get("products"), "product challenges", MAX_PRODUCTS)?
                    .iter()
                    .map(|entry| {
                        let entry = object(entry, "product challenge")?;
                        Ok(ProductChallenge {
                            quorum: selected.clone(),
                            context_digest: parse_hex(entry.get("c"), "product context")?,
                            factor: parse_point(entry.get("f"), "product nonce")?,
                            product: parse_point(entry.get("p"), "product relation nonce")?,
                            challenge: parse_scalar(entry.get("x"), "product challenge")?,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?,
                ranges: array(body.get("ranges"), "range challenges", MAX_RANGES)?
                    .iter()
                    .map(|entry| parse_range_challenge(entry, &selected))
                    .collect::<Result<Vec<_>, _>>()?,
                winner: {
                    let winner = object(
                        body.get("winner").ok_or("winner challenge is absent")?,
                        "winner challenge",
                    )?;
                    OpeningChallenge {
                        quorum: selected,
                        context_digest: parse_hex(winner.get("c"), "winner context")?,
                        nonce_commitment: parse_point(winner.get("n"), "winner nonce")?,
                        challenge: parse_scalar(winner.get("x"), "winner challenge")?,
                    }
                },
            })
        }
        "round2" => {
            let party = parse_party(body.get("party"))?;
            Message::Round2(QuoteRound2 {
                party,
                products: array(body.get("products"), "product responses", MAX_PRODUCTS)?
                    .iter()
                    .map(|entry| {
                        let values = array(Some(entry), "product response", 3)?;
                        if values.len() != 3 {
                            return Err("product response must contain three scalars".into());
                        }
                        Ok(ProductRound2 {
                            party,
                            factor_answer: parse_scalar(values.first(), "factor answer")?,
                            factor_blinding_answer: parse_scalar(
                                values.get(1),
                                "factor blinding answer",
                            )?,
                            relation_answer: parse_scalar(values.get(2), "relation answer")?,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?,
                ranges: array(body.get("ranges"), "range responses", MAX_RANGES)?
                    .iter()
                    .map(|entry| parse_range_round2(entry, party))
                    .collect::<Result<Vec<_>, _>>()?,
                winner: {
                    let values = array(body.get("winner"), "winner response", 2)?;
                    if values.len() != 2 {
                        return Err("winner response must contain two scalars".into());
                    }
                    OpeningRound2 {
                        party,
                        value_answer: parse_scalar(values.first(), "winner value answer")?,
                        blinding_answer: parse_scalar(values.get(1), "winner blinding answer")?,
                    }
                },
            })
        }
        _ => return Err("unknown quote wire message type".into()),
    };
    Ok(Envelope { job_id, message })
}

#[cfg(test)]
mod tests {
    use super::*;
    use qomm_proofs::threshold_gadgets::WireEvaluation;

    fn p(value: u64) -> RistrettoPoint {
        RistrettoPoint::mul_base(&Scalar::from(value))
    }

    fn round_trip(message: Message) {
        let envelope = Envelope {
            job_id: [9; 32],
            message,
        };
        let first = encode(&envelope).unwrap();
        let decoded = decode(&first).unwrap();
        let second = encode(&decoded).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn every_public_quote_round_has_a_canonical_round_trip() {
        round_trip(Message::Evaluations(QuoteNodeEvaluations {
            party: 1,
            wires: vec![WireEvaluation {
                party: 1,
                point: p(1),
            }],
            ranges: vec![RangeEvaluations {
                party: 1,
                value: p(2),
                bits: vec![p(3)],
            }],
        }));
        round_trip(Message::RelationEvaluations(QuoteRelationEvaluations {
            party: 1,
            products: vec![ProductEvaluations {
                party: 1,
                factor: p(4),
                relation: p(5),
            }],
            ranges: vec![RangeRelationEvaluations {
                party: 1,
                bits: vec![p(6)],
            }],
        }));
        round_trip(Message::Round1Seal(QuoteRound1Seals {
            party: 1,
            products: vec![ProductRound1Seal {
                party: 1,
                digest: [1; 32],
            }],
            ranges: vec![RangeRound1Seal {
                party: 1,
                digest: [2; 32],
            }],
            winner: OpeningRound1Seal {
                party: 1,
                digest: [3; 32],
            },
        }));
        round_trip(Message::Round1(QuoteRound1 {
            party: 1,
            products: vec![ProductRound1 {
                party: 1,
                context_digest: [4; 32],
                factor: p(7),
                product: p(8),
            }],
            ranges: vec![RangeRound1 {
                party: 1,
                context_digest: [5; 32],
                bit_factor: vec![p(9)],
                bit_product: vec![p(10)],
                linkage: p(11),
            }],
            winner: OpeningRound1 {
                party: 1,
                context_digest: [6; 32],
                nonce_commitment: p(12),
            },
        }));
        let quorum = vec![1, 2, 3];
        round_trip(Message::Challenge(QuoteChallenges {
            products: vec![ProductChallenge {
                quorum: quorum.clone(),
                context_digest: [7; 32],
                factor: p(13),
                product: p(14),
                challenge: Scalar::from(15_u64),
            }],
            ranges: vec![RangeChallenge {
                quorum: quorum.clone(),
                context_digest: [8; 32],
                bit_factor: vec![p(16)],
                bit_product: vec![p(17)],
                bit_challenges: vec![Scalar::from(18_u64)],
                linkage: p(19),
                linkage_challenge: Scalar::from(20_u64),
            }],
            winner: OpeningChallenge {
                quorum,
                context_digest: [9; 32],
                nonce_commitment: p(21),
                challenge: Scalar::from(22_u64),
            },
        }));
        round_trip(Message::Round2(QuoteRound2 {
            party: 1,
            products: vec![ProductRound2 {
                party: 1,
                factor_answer: Scalar::from(23_u64),
                factor_blinding_answer: Scalar::from(24_u64),
                relation_answer: Scalar::from(25_u64),
            }],
            ranges: vec![RangeRound2 {
                party: 1,
                bit_answers: vec![(
                    Scalar::from(26_u64),
                    Scalar::from(27_u64),
                    Scalar::from(28_u64),
                )],
                linkage_answer: (Scalar::from(29_u64), Scalar::from(30_u64)),
            }],
            winner: OpeningRound2 {
                party: 1,
                value_answer: Scalar::from(31_u64),
                blinding_answer: Scalar::from(32_u64),
            },
        }));
    }
}
