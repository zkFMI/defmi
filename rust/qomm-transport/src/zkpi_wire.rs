//! Canonical, bounded wire format for the public rounds of threshold zkPI issuance.
//!
//! The node-local `RangeRound1Secret` and raw Shamir shares have no variant in
//! this codec.  A process using this format therefore cannot accidentally put
//! either on the network. Every envelope is also bound to one 32-byte MPC job
//! identifier so delayed messages cannot be reused in another quote.

use std::collections::BTreeSet;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use qomm_proofs::threshold_range::{
    RangeChallenge, RangeEvaluations, RangeRelationEvaluations, RangeRound1, RangeRound1Seal,
    RangeRound2,
};
use qomm_proofs::threshold_sigma::PartyId;
use thiserror::Error;

use crate::zkpi_issuer::{
    ZkpiChallenge, ZkpiEvaluations, ZkpiRelationEvaluations, ZkpiRound1, ZkpiRound1Seals,
    ZkpiRound2,
};

pub const MAGIC: &[u8; 8] = b"QOMMZKPR";
pub const VERSION: u16 = 1;
pub const MAX_RANGE_BITS: usize = 64;
pub const MAX_PARTIES: usize = 64;

#[derive(Clone, Debug)]
pub enum Message {
    Evaluations(ZkpiEvaluations),
    RelationEvaluations(ZkpiRelationEvaluations),
    Round1Seal(ZkpiRound1Seals),
    Round1(ZkpiRound1),
    Challenge(ZkpiChallenge),
    Round2(ZkpiRound2),
}

#[derive(Clone, Debug)]
pub struct Envelope {
    pub job_id: [u8; 32],
    pub message: Message,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("wrong threshold-zkPI wire magic")]
    WrongMagic,
    #[error("unsupported threshold-zkPI wire version {0}")]
    Version(u16),
    #[error("threshold-zkPI message is truncated at {0}")]
    Truncated(&'static str),
    #[error("unknown threshold-zkPI message type {0}")]
    MessageType(u8),
    #[error("party identifier is outside the wire range")]
    Party,
    #[error("amount and price messages name different parties")]
    PartyMismatch,
    #[error("threshold-zkPI vector is empty or exceeds its bound")]
    Length,
    #[error("threshold-zkPI quorum contains a duplicate party")]
    DuplicateParty,
    #[error("invalid canonical Ristretto point")]
    Point,
    #[error("invalid canonical Ristretto scalar")]
    Scalar,
    #[error("threshold-zkPI message has {0} trailing bytes")]
    Trailing(usize),
}

fn party_u16(party: PartyId) -> Result<u16, Error> {
    let value = u16::try_from(party).map_err(|_| Error::Party)?;
    if value == 0 {
        return Err(Error::Party);
    }
    Ok(value)
}

fn checked_len(length: usize) -> Result<u16, Error> {
    if length == 0 || length > MAX_RANGE_BITS {
        return Err(Error::Length);
    }
    u16::try_from(length).map_err(|_| Error::Length)
}

fn put_party(out: &mut Vec<u8>, party: PartyId) -> Result<(), Error> {
    out.extend_from_slice(&party_u16(party)?.to_be_bytes());
    Ok(())
}

fn put_point(out: &mut Vec<u8>, point: &RistrettoPoint) {
    out.extend_from_slice(point.compress().as_bytes());
}

fn put_scalar(out: &mut Vec<u8>, scalar: &Scalar) {
    out.extend_from_slice(&scalar.to_bytes());
}

fn put_evaluations(out: &mut Vec<u8>, value: &RangeEvaluations) -> Result<(), Error> {
    put_party(out, value.party)?;
    put_point(out, &value.value);
    out.extend_from_slice(&checked_len(value.bits.len())?.to_be_bytes());
    for point in &value.bits {
        put_point(out, point);
    }
    Ok(())
}

fn put_relations(out: &mut Vec<u8>, value: &RangeRelationEvaluations) -> Result<(), Error> {
    put_party(out, value.party)?;
    out.extend_from_slice(&checked_len(value.bits.len())?.to_be_bytes());
    for point in &value.bits {
        put_point(out, point);
    }
    Ok(())
}

fn put_seal(out: &mut Vec<u8>, value: &RangeRound1Seal) -> Result<(), Error> {
    put_party(out, value.party)?;
    out.extend_from_slice(&value.digest);
    Ok(())
}

fn put_round1(out: &mut Vec<u8>, value: &RangeRound1) -> Result<(), Error> {
    if value.bit_factor.len() != value.bit_product.len() {
        return Err(Error::Length);
    }
    put_party(out, value.party)?;
    out.extend_from_slice(&value.context_digest);
    out.extend_from_slice(&checked_len(value.bit_factor.len())?.to_be_bytes());
    for (factor, product) in value.bit_factor.iter().zip(&value.bit_product) {
        put_point(out, factor);
        put_point(out, product);
    }
    put_point(out, &value.linkage);
    Ok(())
}

fn put_quorum(out: &mut Vec<u8>, quorum: &[PartyId]) -> Result<(), Error> {
    if quorum.is_empty() || quorum.len() > MAX_PARTIES {
        return Err(Error::Length);
    }
    let mut unique = BTreeSet::new();
    out.extend_from_slice(&(quorum.len() as u16).to_be_bytes());
    for party in quorum {
        if !unique.insert(*party) {
            return Err(Error::DuplicateParty);
        }
        put_party(out, *party)?;
    }
    Ok(())
}

fn put_challenge(out: &mut Vec<u8>, value: &RangeChallenge) -> Result<(), Error> {
    if value.bit_factor.len() != value.bit_product.len()
        || value.bit_factor.len() != value.bit_challenges.len()
    {
        return Err(Error::Length);
    }
    put_quorum(out, &value.quorum)?;
    out.extend_from_slice(&value.context_digest);
    out.extend_from_slice(&checked_len(value.bit_factor.len())?.to_be_bytes());
    for ((factor, product), challenge) in value
        .bit_factor
        .iter()
        .zip(&value.bit_product)
        .zip(&value.bit_challenges)
    {
        put_point(out, factor);
        put_point(out, product);
        put_scalar(out, challenge);
    }
    put_point(out, &value.linkage);
    put_scalar(out, &value.linkage_challenge);
    Ok(())
}

fn put_round2(out: &mut Vec<u8>, value: &RangeRound2) -> Result<(), Error> {
    put_party(out, value.party)?;
    out.extend_from_slice(&checked_len(value.bit_answers.len())?.to_be_bytes());
    for (value, blinding, relation) in &value.bit_answers {
        put_scalar(out, value);
        put_scalar(out, blinding);
        put_scalar(out, relation);
    }
    put_scalar(out, &value.linkage_answer.0);
    put_scalar(out, &value.linkage_answer.1);
    Ok(())
}

fn same_party(outer: PartyId, amount: PartyId, price: PartyId) -> Result<(), Error> {
    if outer == amount && outer == price && outer != 0 {
        Ok(())
    } else {
        Err(Error::PartyMismatch)
    }
}

pub fn encode(envelope: &Envelope) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&envelope.job_id);
    match &envelope.message {
        Message::Evaluations(value) => {
            same_party(value.party, value.amount.party, value.price.party)?;
            out.push(1);
            put_party(&mut out, value.party)?;
            put_evaluations(&mut out, &value.amount)?;
            put_evaluations(&mut out, &value.price)?;
        }
        Message::RelationEvaluations(value) => {
            same_party(value.party, value.amount.party, value.price.party)?;
            out.push(2);
            put_party(&mut out, value.party)?;
            put_relations(&mut out, &value.amount)?;
            put_relations(&mut out, &value.price)?;
        }
        Message::Round1Seal(value) => {
            same_party(value.party, value.amount.party, value.price.party)?;
            out.push(3);
            put_party(&mut out, value.party)?;
            put_seal(&mut out, &value.amount)?;
            put_seal(&mut out, &value.price)?;
        }
        Message::Round1(value) => {
            same_party(value.party, value.amount.party, value.price.party)?;
            out.push(4);
            put_party(&mut out, value.party)?;
            put_round1(&mut out, &value.amount)?;
            put_round1(&mut out, &value.price)?;
        }
        Message::Challenge(value) => {
            if value.amount.quorum != value.price.quorum {
                return Err(Error::PartyMismatch);
            }
            out.push(5);
            put_challenge(&mut out, &value.amount)?;
            put_challenge(&mut out, &value.price)?;
        }
        Message::Round2(value) => {
            same_party(value.party, value.amount.party, value.price.party)?;
            out.push(6);
            put_party(&mut out, value.party)?;
            put_round2(&mut out, &value.amount)?;
            put_round2(&mut out, &value.price)?;
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

    fn party(&mut self) -> Result<PartyId, Error> {
        let value = self.u16("party")?;
        if value == 0 {
            return Err(Error::Party);
        }
        Ok(value as usize)
    }

    fn id(&mut self, name: &'static str) -> Result<[u8; 32], Error> {
        Ok(self.take(32, name)?.try_into().expect("32 bytes"))
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

    fn len(&mut self, max: usize) -> Result<usize, Error> {
        let value = self.u16("length")? as usize;
        if value == 0 || value > max {
            return Err(Error::Length);
        }
        Ok(value)
    }

    fn evaluations(&mut self) -> Result<RangeEvaluations, Error> {
        let party = self.party()?;
        let value = self.point()?;
        let count = self.len(MAX_RANGE_BITS)?;
        let bits = (0..count)
            .map(|_| self.point())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RangeEvaluations { party, value, bits })
    }

    fn relations(&mut self) -> Result<RangeRelationEvaluations, Error> {
        let party = self.party()?;
        let count = self.len(MAX_RANGE_BITS)?;
        let bits = (0..count)
            .map(|_| self.point())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RangeRelationEvaluations { party, bits })
    }

    fn seal(&mut self) -> Result<RangeRound1Seal, Error> {
        Ok(RangeRound1Seal {
            party: self.party()?,
            digest: self.id("seal")?,
        })
    }

    fn round1(&mut self) -> Result<RangeRound1, Error> {
        let party = self.party()?;
        let context_digest = self.id("context digest")?;
        let count = self.len(MAX_RANGE_BITS)?;
        let mut bit_factor = Vec::with_capacity(count);
        let mut bit_product = Vec::with_capacity(count);
        for _ in 0..count {
            bit_factor.push(self.point()?);
            bit_product.push(self.point()?);
        }
        Ok(RangeRound1 {
            party,
            context_digest,
            bit_factor,
            bit_product,
            linkage: self.point()?,
        })
    }

    fn quorum(&mut self) -> Result<Vec<PartyId>, Error> {
        let count = self.len(MAX_PARTIES)?;
        let mut unique = BTreeSet::new();
        let mut quorum = Vec::with_capacity(count);
        for _ in 0..count {
            let party = self.party()?;
            if !unique.insert(party) {
                return Err(Error::DuplicateParty);
            }
            quorum.push(party);
        }
        Ok(quorum)
    }

    fn challenge(&mut self) -> Result<RangeChallenge, Error> {
        let quorum = self.quorum()?;
        let context_digest = self.id("context digest")?;
        let count = self.len(MAX_RANGE_BITS)?;
        let mut bit_factor = Vec::with_capacity(count);
        let mut bit_product = Vec::with_capacity(count);
        let mut bit_challenges = Vec::with_capacity(count);
        for _ in 0..count {
            bit_factor.push(self.point()?);
            bit_product.push(self.point()?);
            bit_challenges.push(self.scalar()?);
        }
        Ok(RangeChallenge {
            quorum,
            context_digest,
            bit_factor,
            bit_product,
            bit_challenges,
            linkage: self.point()?,
            linkage_challenge: self.scalar()?,
        })
    }

    fn round2(&mut self) -> Result<RangeRound2, Error> {
        let party = self.party()?;
        let count = self.len(MAX_RANGE_BITS)?;
        let bit_answers = (0..count)
            .map(|_| Ok((self.scalar()?, self.scalar()?, self.scalar()?)))
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(RangeRound2 {
            party,
            bit_answers,
            linkage_answer: (self.scalar()?, self.scalar()?),
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
    let message = match kind {
        1 => {
            let party = reader.party()?;
            let amount = reader.evaluations()?;
            let price = reader.evaluations()?;
            same_party(party, amount.party, price.party)?;
            Message::Evaluations(ZkpiEvaluations {
                party,
                amount,
                price,
            })
        }
        2 => {
            let party = reader.party()?;
            let amount = reader.relations()?;
            let price = reader.relations()?;
            same_party(party, amount.party, price.party)?;
            Message::RelationEvaluations(ZkpiRelationEvaluations {
                party,
                amount,
                price,
            })
        }
        3 => {
            let party = reader.party()?;
            let amount = reader.seal()?;
            let price = reader.seal()?;
            same_party(party, amount.party, price.party)?;
            Message::Round1Seal(ZkpiRound1Seals {
                party,
                amount,
                price,
            })
        }
        4 => {
            let party = reader.party()?;
            let amount = reader.round1()?;
            let price = reader.round1()?;
            same_party(party, amount.party, price.party)?;
            Message::Round1(ZkpiRound1 {
                party,
                amount,
                price,
            })
        }
        5 => {
            let amount = reader.challenge()?;
            let price = reader.challenge()?;
            if amount.quorum != price.quorum {
                return Err(Error::PartyMismatch);
            }
            Message::Challenge(ZkpiChallenge { amount, price })
        }
        6 => {
            let party = reader.party()?;
            let amount = reader.round2()?;
            let price = reader.round2()?;
            same_party(party, amount.party, price.party)?;
            Message::Round2(ZkpiRound2 {
                party,
                amount,
                price,
            })
        }
        other => return Err(Error::MessageType(other)),
    };
    if reader.at != raw.len() {
        return Err(Error::Trailing(raw.len() - reader.at));
    }
    Ok(Envelope { job_id, message })
}
