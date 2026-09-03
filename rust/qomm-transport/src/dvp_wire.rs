//! Canonical bounded wire format for the public rounds of threshold DvP.
//!
//! The two range-proof messages are nested using the already audited zkPI
//! range codec.  Product-proof fields are appended explicitly.  Node-local
//! shares and first-round nonces have no representation in this format.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use qomm_proofs::threshold_gadgets::{
    ProductChallenge, ProductEvaluations, ProductRound1, ProductRound1Seal, ProductRound2,
};
use qomm_proofs::threshold_sigma::PartyId;
use thiserror::Error;

use crate::dvp_issuer::{
    DvpChallenge, DvpEvaluations, DvpRelationEvaluations, DvpRound1, DvpRound1Seals, DvpRound2,
};
use crate::zkpi_issuer::{
    ZkpiChallenge, ZkpiEvaluations, ZkpiRelationEvaluations, ZkpiRound1, ZkpiRound1Seals,
    ZkpiRound2,
};
use crate::zkpi_wire;

pub const MAGIC: &[u8; 8] = b"QOMMDVPR";
pub const VERSION: u16 = 1;
const MAX_INNER_BYTES: usize = 1 << 20;
const MAX_PARTIES: usize = 64;

#[derive(Clone, Debug)]
pub enum Message {
    Evaluations(DvpEvaluations),
    RelationEvaluations(DvpRelationEvaluations),
    Round1Seal(DvpRound1Seals),
    Round1(DvpRound1),
    Challenge(DvpChallenge),
    Round2(DvpRound2),
}

#[derive(Clone, Debug)]
pub struct Envelope {
    pub job_id: [u8; 32],
    pub message: Message,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("wrong threshold-DvP wire magic")]
    WrongMagic,
    #[error("unsupported threshold-DvP wire version {0}")]
    Version(u16),
    #[error("threshold-DvP message is truncated at {0}")]
    Truncated(&'static str),
    #[error("unknown threshold-DvP message type {0}")]
    MessageType(u8),
    #[error("threshold-DvP party identifier is invalid")]
    Party,
    #[error("threshold-DvP nested range message is invalid: {0}")]
    Inner(String),
    #[error("threshold-DvP nested range message has the wrong type")]
    InnerType,
    #[error("threshold-DvP product and range messages name different parties or jobs")]
    PartyMismatch,
    #[error("threshold-DvP quorum is empty, too large, or contains duplicates")]
    Quorum,
    #[error("invalid canonical Ristretto point")]
    Point,
    #[error("invalid canonical Ristretto scalar")]
    Scalar,
    #[error("threshold-DvP nested message is too large")]
    Length,
    #[error("threshold-DvP message has {0} trailing bytes")]
    Trailing(usize),
}

fn put_party(out: &mut Vec<u8>, party: PartyId) -> Result<(), Error> {
    let party = u16::try_from(party).map_err(|_| Error::Party)?;
    if party == 0 {
        return Err(Error::Party);
    }
    out.extend_from_slice(&party.to_be_bytes());
    Ok(())
}

fn put_point(out: &mut Vec<u8>, point: &RistrettoPoint) {
    out.extend_from_slice(point.compress().as_bytes());
}

fn put_scalar(out: &mut Vec<u8>, scalar: &Scalar) {
    out.extend_from_slice(&scalar.to_bytes());
}

fn put_inner(
    out: &mut Vec<u8>,
    job_id: [u8; 32],
    message: zkpi_wire::Message,
) -> Result<(), Error> {
    let raw = zkpi_wire::encode(&zkpi_wire::Envelope { job_id, message })
        .map_err(|error| Error::Inner(error.to_string()))?;
    if raw.len() > MAX_INNER_BYTES {
        return Err(Error::Length);
    }
    out.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    out.extend_from_slice(&raw);
    Ok(())
}

fn same_party(parties: &[PartyId]) -> Result<PartyId, Error> {
    let first = *parties.first().ok_or(Error::Party)?;
    if first == 0 || parties.iter().any(|party| *party != first) {
        return Err(Error::PartyMismatch);
    }
    Ok(first)
}

pub fn encode(envelope: &Envelope) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&envelope.job_id);
    match &envelope.message {
        Message::Evaluations(value) => {
            same_party(&[
                value.party,
                value.product.party,
                value.securities_remainder.party,
                value.cash_remainder.party,
            ])?;
            out.push(1);
            put_inner(
                &mut out,
                envelope.job_id,
                zkpi_wire::Message::Evaluations(ZkpiEvaluations {
                    party: value.party,
                    amount: value.securities_remainder.clone(),
                    price: value.cash_remainder.clone(),
                }),
            )?;
            put_party(&mut out, value.product.party)?;
            put_point(&mut out, &value.product.factor);
            put_point(&mut out, &value.product.relation);
        }
        Message::RelationEvaluations(value) => {
            same_party(&[
                value.party,
                value.securities_remainder.party,
                value.cash_remainder.party,
            ])?;
            out.push(2);
            put_inner(
                &mut out,
                envelope.job_id,
                zkpi_wire::Message::RelationEvaluations(ZkpiRelationEvaluations {
                    party: value.party,
                    amount: value.securities_remainder.clone(),
                    price: value.cash_remainder.clone(),
                }),
            )?;
        }
        Message::Round1Seal(value) => {
            same_party(&[
                value.party,
                value.product.party,
                value.securities_remainder.party,
                value.cash_remainder.party,
            ])?;
            out.push(3);
            put_inner(
                &mut out,
                envelope.job_id,
                zkpi_wire::Message::Round1Seal(ZkpiRound1Seals {
                    party: value.party,
                    amount: value.securities_remainder.clone(),
                    price: value.cash_remainder.clone(),
                }),
            )?;
            put_party(&mut out, value.product.party)?;
            out.extend_from_slice(&value.product.digest);
        }
        Message::Round1(value) => {
            same_party(&[
                value.party,
                value.product.party,
                value.securities_remainder.party,
                value.cash_remainder.party,
            ])?;
            out.push(4);
            put_inner(
                &mut out,
                envelope.job_id,
                zkpi_wire::Message::Round1(ZkpiRound1 {
                    party: value.party,
                    amount: value.securities_remainder.clone(),
                    price: value.cash_remainder.clone(),
                }),
            )?;
            put_party(&mut out, value.product.party)?;
            out.extend_from_slice(&value.product.context_digest);
            put_point(&mut out, &value.product.factor);
            put_point(&mut out, &value.product.product);
        }
        Message::Challenge(value) => {
            if value.securities_remainder.quorum != value.cash_remainder.quorum
                || value.product.quorum != value.securities_remainder.quorum
            {
                return Err(Error::PartyMismatch);
            }
            out.push(5);
            put_inner(
                &mut out,
                envelope.job_id,
                zkpi_wire::Message::Challenge(ZkpiChallenge {
                    amount: value.securities_remainder.clone(),
                    price: value.cash_remainder.clone(),
                }),
            )?;
            if value.product.quorum.is_empty() || value.product.quorum.len() > MAX_PARTIES {
                return Err(Error::Quorum);
            }
            let mut seen = std::collections::BTreeSet::new();
            out.extend_from_slice(&(value.product.quorum.len() as u16).to_be_bytes());
            for party in &value.product.quorum {
                if !seen.insert(*party) {
                    return Err(Error::Quorum);
                }
                put_party(&mut out, *party)?;
            }
            out.extend_from_slice(&value.product.context_digest);
            put_point(&mut out, &value.product.factor);
            put_point(&mut out, &value.product.product);
            put_scalar(&mut out, &value.product.challenge);
        }
        Message::Round2(value) => {
            same_party(&[
                value.party,
                value.product.party,
                value.securities_remainder.party,
                value.cash_remainder.party,
            ])?;
            out.push(6);
            put_inner(
                &mut out,
                envelope.job_id,
                zkpi_wire::Message::Round2(ZkpiRound2 {
                    party: value.party,
                    amount: value.securities_remainder.clone(),
                    price: value.cash_remainder.clone(),
                }),
            )?;
            put_party(&mut out, value.product.party)?;
            put_scalar(&mut out, &value.product.factor_answer);
            put_scalar(&mut out, &value.product.factor_blinding_answer);
            put_scalar(&mut out, &value.product.relation_answer);
        }
    }
    Ok(out)
}

struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize, name: &'static str) -> Result<&'a [u8], Error> {
        if self.at > self.raw.len() || self.raw.len() - self.at < count {
            return Err(Error::Truncated(name));
        }
        let value = &self.raw[self.at..self.at + count];
        self.at += count;
        Ok(value)
    }

    fn u8(&mut self, name: &'static str) -> Result<u8, Error> {
        Ok(self.take(1, name)?[0])
    }

    fn u16(&mut self, name: &'static str) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(
            self.take(2, name)?.try_into().expect("two bytes"),
        ))
    }

    fn u32(&mut self, name: &'static str) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4, name)?.try_into().expect("four bytes"),
        ))
    }

    fn id(&mut self, name: &'static str) -> Result<[u8; 32], Error> {
        Ok(self.take(32, name)?.try_into().expect("32 bytes"))
    }

    fn party(&mut self) -> Result<PartyId, Error> {
        let party = self.u16("party")?;
        if party == 0 {
            return Err(Error::Party);
        }
        Ok(party as usize)
    }

    fn point(&mut self) -> Result<RistrettoPoint, Error> {
        CompressedRistretto(self.id("point")?)
            .decompress()
            .ok_or(Error::Point)
    }

    fn scalar(&mut self) -> Result<Scalar, Error> {
        Option::<Scalar>::from(Scalar::from_canonical_bytes(self.id("scalar")?))
            .ok_or(Error::Scalar)
    }

    fn inner(&mut self, job_id: [u8; 32]) -> Result<zkpi_wire::Message, Error> {
        let length = self.u32("nested range length")? as usize;
        if length == 0 || length > MAX_INNER_BYTES {
            return Err(Error::Length);
        }
        let raw = self.take(length, "nested range message")?;
        let inner = zkpi_wire::decode(raw).map_err(|error| Error::Inner(error.to_string()))?;
        if inner.job_id != job_id {
            return Err(Error::PartyMismatch);
        }
        Ok(inner.message)
    }

    fn product_evaluations(&mut self) -> Result<ProductEvaluations, Error> {
        Ok(ProductEvaluations {
            party: self.party()?,
            factor: self.point()?,
            relation: self.point()?,
        })
    }

    fn product_seal(&mut self) -> Result<ProductRound1Seal, Error> {
        Ok(ProductRound1Seal {
            party: self.party()?,
            digest: self.id("product seal")?,
        })
    }

    fn product_round1(&mut self) -> Result<ProductRound1, Error> {
        Ok(ProductRound1 {
            party: self.party()?,
            context_digest: self.id("product context")?,
            factor: self.point()?,
            product: self.point()?,
        })
    }

    fn product_challenge(&mut self) -> Result<ProductChallenge, Error> {
        let count = self.u16("product quorum length")? as usize;
        if count == 0 || count > MAX_PARTIES {
            return Err(Error::Quorum);
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut quorum = Vec::with_capacity(count);
        for _ in 0..count {
            let party = self.party()?;
            if !seen.insert(party) {
                return Err(Error::Quorum);
            }
            quorum.push(party);
        }
        Ok(ProductChallenge {
            quorum,
            context_digest: self.id("product context")?,
            factor: self.point()?,
            product: self.point()?,
            challenge: self.scalar()?,
        })
    }

    fn product_round2(&mut self) -> Result<ProductRound2, Error> {
        Ok(ProductRound2 {
            party: self.party()?,
            factor_answer: self.scalar()?,
            factor_blinding_answer: self.scalar()?,
            relation_answer: self.scalar()?,
        })
    }
}

pub fn decode(raw: &[u8]) -> Result<Envelope, Error> {
    let mut reader = Reader { raw, at: 0 };
    if reader.take(8, "magic")? != MAGIC {
        return Err(Error::WrongMagic);
    }
    let version = reader.u16("version")?;
    if version != VERSION {
        return Err(Error::Version(version));
    }
    let job_id = reader.id("job id")?;
    let kind = reader.u8("message type")?;
    let inner = reader.inner(job_id)?;
    let message = match (kind, inner) {
        (1, zkpi_wire::Message::Evaluations(value)) => {
            let product = reader.product_evaluations()?;
            same_party(&[
                value.party,
                value.amount.party,
                value.price.party,
                product.party,
            ])?;
            Message::Evaluations(DvpEvaluations {
                party: value.party,
                product,
                securities_remainder: value.amount,
                cash_remainder: value.price,
            })
        }
        (2, zkpi_wire::Message::RelationEvaluations(value)) => {
            same_party(&[value.party, value.amount.party, value.price.party])?;
            Message::RelationEvaluations(DvpRelationEvaluations {
                party: value.party,
                securities_remainder: value.amount,
                cash_remainder: value.price,
            })
        }
        (3, zkpi_wire::Message::Round1Seal(value)) => {
            let product = reader.product_seal()?;
            same_party(&[
                value.party,
                value.amount.party,
                value.price.party,
                product.party,
            ])?;
            Message::Round1Seal(DvpRound1Seals {
                party: value.party,
                product,
                securities_remainder: value.amount,
                cash_remainder: value.price,
            })
        }
        (4, zkpi_wire::Message::Round1(value)) => {
            let product = reader.product_round1()?;
            same_party(&[
                value.party,
                value.amount.party,
                value.price.party,
                product.party,
            ])?;
            Message::Round1(DvpRound1 {
                party: value.party,
                product,
                securities_remainder: value.amount,
                cash_remainder: value.price,
            })
        }
        (5, zkpi_wire::Message::Challenge(value)) => {
            let product = reader.product_challenge()?;
            if value.amount.quorum != value.price.quorum || product.quorum != value.amount.quorum {
                return Err(Error::PartyMismatch);
            }
            Message::Challenge(DvpChallenge {
                product,
                securities_remainder: value.amount,
                cash_remainder: value.price,
            })
        }
        (6, zkpi_wire::Message::Round2(value)) => {
            let product = reader.product_round2()?;
            same_party(&[
                value.party,
                value.amount.party,
                value.price.party,
                product.party,
            ])?;
            Message::Round2(DvpRound2 {
                party: value.party,
                product,
                securities_remainder: value.amount,
                cash_remainder: value.price,
            })
        }
        (1..=6, _) => return Err(Error::InnerType),
        (other, _) => return Err(Error::MessageType(other)),
    };
    if reader.at != raw.len() {
        return Err(Error::Trailing(raw.len() - reader.at));
    }
    Ok(Envelope { job_id, message })
}
