//! zkPI: a payment instruction that can be verified without being read.
//!
//! The point of the construction is that a settlement venue runs exactly two
//! operations --- verify the instruction, and check the nullifier has not been
//! seen --- and neither depends on how the price was reached. That makes it
//! pluggable: a venue with its own matching engine can accept instructions from
//! this issuer, or from any issuer speaking the same interface, without
//! adopting the rest of the design.
//!
//! The quorum signature is FROST rather than the threshold sigma protocol the
//! Python version carried. FROST is a real threshold Schnorr scheme with an
//! audit behind it; there was no reason to keep a hand-rolled one.

pub mod handles;
pub mod wire;
pub mod wire_vectors;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::range::RangeCtx;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use std::collections::{BTreeMap, HashSet};

pub use frost_ristretto255 as frost;

/// The bounds a venue publishes in advance.
#[derive(Clone, Debug)]
pub struct Bounds {
    pub amount_bits: usize,
    pub price_bits: usize,
    /// How far ahead a venue will accept a deadline, from the moment it checks.
    ///
    /// The nullifier set is bounded by instructions in flight in one deadline
    /// window, which is the argument that state grows with activity and not
    /// with history. That argument needs an upper bound on the window and there
    /// was none: only "not expired" was checked, so an instruction dated a
    /// century out kept its nullifier for a century.
    pub max_horizon: u64,
}

impl Default for Bounds {
    fn default() -> Self {
        Bounds {
            amount_bits: 32,
            price_bits: 32,
            max_horizon: 86_400,
        }
    }
}

/// What the quorum issues. Nothing here reveals the trade.
#[derive(Clone)]
pub struct Instruction {
    pub amount_commitment: RistrettoPoint,
    pub price_commitment: RistrettoPoint,
    pub asset_commitment: RistrettoPoint,
    /// Two Bulletproof range proofs, one per rail, so amount and price may use
    /// different widths. Each proof is checked against the corresponding
    /// commitment carried by the instruction.
    pub amount_range: bulletproofs::RangeProof,
    pub price_range: bulletproofs::RangeProof,
    pub range_commitments: Vec<curve25519_dalek::ristretto::CompressedRistretto>,
    pub payer_handle: RistrettoPoint,
    pub payee_handle: RistrettoPoint,
    pub deadline: u64,
    pub nonce: [u8; 32],
    pub quote_key: u64,
    pub signature: frost::Signature,
}

/// What the issuer keeps: the openings, which the counterparties need.
pub struct Openings {
    pub amount: Scalar,
    pub price: Scalar,
    pub asset: Scalar,
}

/// The domain a venue uses when it declares none. Naming it here rather than
/// leaving the field out is the point: a deployment that shares a quorum across
/// two rails has to choose two domains, and one that forgets gets this one for
/// both and can see that it did.
pub const DEFAULT_DOMAIN: &[u8] = b"qomm:default-venue";

impl Instruction {
    /// Binds the signature to the instruction; a signature cannot be replayed
    /// onto a different one.
    /// The venue, chain, rail and protocol version an instruction is for.
    ///
    /// Without it a signed instruction is valid at every venue that shares the
    /// quorum, so a payment authorised for one rail settles on another. It is
    /// a field rather than a constant because the venue supplies it, and the
    /// digest covers it because that is what stops it being changed.
    pub fn digest(&self) -> [u8; 64] {
        self.digest_for(DEFAULT_DOMAIN)
    }

    pub fn digest_for(&self, domain: &[u8]) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(b"QOMM:ZKPI:v2");
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain);
        for point in [
            &self.amount_commitment,
            &self.price_commitment,
            &self.asset_commitment,
            &self.payer_handle,
            &self.payee_handle,
        ] {
            hasher.update(point.compress().as_bytes());
        }
        hasher.update(self.deadline.to_be_bytes());
        hasher.update(self.nonce);
        hasher.update(self.quote_key.to_be_bytes());
        hasher.finalize().into()
    }

    /// Spent once. Derived from the nonce and the handles, so it reveals
    /// neither.
    pub fn nullifier(&self) -> [u8; 32] {
        let mut hasher = Sha512::new();
        hasher.update(b"QOMM:ZKPI:NUL:v1");
        hasher.update(self.nonce);
        hasher.update(self.payer_handle.compress().as_bytes());
        hasher.update(self.payee_handle.compress().as_bytes());
        let full: [u8; 64] = hasher.finalize().into();
        let mut out = [0u8; 32];
        out.copy_from_slice(&full[..32]);
        out
    }
}

pub struct Issuer {
    pub key: Pedersen,
    pub bounds: Bounds,
    /// One context per field. A single aggregated proof covers both at one
    /// width, so declaring a 24-bit amount beside a 64-bit price proved the
    /// amount at 64 and the narrow declaration bought nothing. Two proofs cost
    /// more than one aggregated pair; buying the width back is what they buy.
    pub amount_ranges: RangeCtx,
    pub price_ranges: RangeCtx,
    /// The venue this issuer signs for. Must match the venue's own.
    pub domain: Vec<u8>,
}

impl Issuer {
    pub fn new(key: Pedersen, bounds: Bounds) -> Self {
        let bits = bounds.amount_bits.max(bounds.price_bits);
        let _ = bits;
        Issuer {
            domain: DEFAULT_DOMAIN.to_vec(),
            key,
            amount_ranges: RangeCtx::new(bounds.amount_bits, 1),
            price_ranges: RangeCtx::new(bounds.price_bits, 1),
            bounds,
        }
    }

    /// Everything except the signature, which the quorum adds.
    #[allow(clippy::too_many_arguments)]
    pub fn build<R: RngCore + CryptoRng>(
        &self,
        amount: u64,
        price: u64,
        asset: u32,
        payer_handle: RistrettoPoint,
        payee_handle: RistrettoPoint,
        deadline: u64,
        nonce: [u8; 32],
        quote_key: u64,
        rng: &mut R,
    ) -> Result<(Vec<u8>, Openings, PartialInstruction), &'static str> {
        let openings = Openings {
            amount: Scalar::random(rng),
            price: Scalar::random(rng),
            asset: Scalar::random(rng),
        };
        let mut transcript = Transcript::new(b"qomm:zkpi:ranges:amount");
        let (amount_range, amount_commitments) =
            self.amount_ranges
                .prove(&mut transcript, &[amount], &[openings.amount])?;
        let mut transcript = Transcript::new(b"qomm:zkpi:ranges:price");
        let (price_range, price_commitments) =
            self.price_ranges
                .prove(&mut transcript, &[price], &[openings.price])?;
        let range_commitments = [amount_commitments, price_commitments].concat();
        let partial = PartialInstruction {
            amount_commitment: self.key.commit_u64(amount, &openings.amount),
            price_commitment: self.key.commit_u64(price, &openings.price),
            asset_commitment: self.key.commit_u64(asset as u64, &openings.asset),
            amount_range,
            price_range,
            range_commitments,
            payer_handle,
            payee_handle,
            deadline,
            nonce,
            quote_key,
        };
        Ok((partial.digest_for(&self.domain).to_vec(), openings, partial))
    }
}

/// The instruction before the quorum has signed it.
pub struct PartialInstruction {
    pub amount_commitment: RistrettoPoint,
    pub price_commitment: RistrettoPoint,
    pub asset_commitment: RistrettoPoint,
    pub amount_range: bulletproofs::RangeProof,
    pub price_range: bulletproofs::RangeProof,
    pub range_commitments: Vec<curve25519_dalek::ristretto::CompressedRistretto>,
    pub payer_handle: RistrettoPoint,
    pub payee_handle: RistrettoPoint,
    pub deadline: u64,
    pub nonce: [u8; 32],
    pub quote_key: u64,
}

impl PartialInstruction {
    /// The venue, chain, rail and protocol version an instruction is for.
    ///
    /// Without it a signed instruction is valid at every venue that shares the
    /// quorum, so a payment authorised for one rail settles on another. It is
    /// a field rather than a constant because the venue supplies it, and the
    /// digest covers it because that is what stops it being changed.
    pub fn digest(&self) -> [u8; 64] {
        self.digest_for(DEFAULT_DOMAIN)
    }

    pub fn digest_for(&self, domain: &[u8]) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(b"QOMM:ZKPI:v2");
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain);
        for point in [
            &self.amount_commitment,
            &self.price_commitment,
            &self.asset_commitment,
            &self.payer_handle,
            &self.payee_handle,
        ] {
            hasher.update(point.compress().as_bytes());
        }
        hasher.update(self.deadline.to_be_bytes());
        hasher.update(self.nonce);
        hasher.update(self.quote_key.to_be_bytes());
        hasher.finalize().into()
    }

    pub fn sealed(self, signature: frost::Signature) -> Instruction {
        Instruction {
            amount_commitment: self.amount_commitment,
            price_commitment: self.price_commitment,
            asset_commitment: self.asset_commitment,
            amount_range: self.amount_range,
            price_range: self.price_range,
            range_commitments: self.range_commitments,
            payer_handle: self.payer_handle,
            payee_handle: self.payee_handle,
            deadline: self.deadline,
            nonce: self.nonce,
            quote_key: self.quote_key,
            signature,
        }
    }
}

/// The settlement side: verify, then spend once.
pub struct Venue {
    pub key: Pedersen,
    /// Which venue, chain, rail and protocol version this is. See `digest_for`.
    pub domain: Vec<u8>,
    pub amount_ranges: RangeCtx,
    pub price_ranges: RangeCtx,
    pub group_public: frost::keys::PublicKeyPackage,
    spent: HashSet<[u8; 32]>,
    max_horizon: u64,
}

impl Venue {
    pub fn new(
        key: Pedersen,
        bounds: &Bounds,
        group_public: frost::keys::PublicKeyPackage,
    ) -> Self {
        let bits = bounds.amount_bits.max(bounds.price_bits);
        let _ = bits;
        Venue {
            key,
            domain: DEFAULT_DOMAIN.to_vec(),
            amount_ranges: RangeCtx::new(bounds.amount_bits, 1),
            price_ranges: RangeCtx::new(bounds.price_bits, 1),
            group_public,
            spent: HashSet::new(),
            max_horizon: bounds.max_horizon,
        }
    }

    pub fn verify(&self, instruction: &Instruction, now: u64) -> Result<(), &'static str> {
        if instruction.deadline > now.saturating_add(self.max_horizon) {
            return Err("the deadline is further out than this venue will hold a \
nullifier for");
        }
        if now > instruction.deadline {
            return Err("past the deadline");
        }
        // A payment from a handle to itself moves nothing and burns a
        // nullifier, and both rails would net to zero while the settlement
        // still counted as one. Nothing downstream refused it.
        if instruction.payer_handle.compress() == instruction.payee_handle.compress() {
            return Err("the payer and the payee are the same handle");
        }
        if self.spent.contains(&instruction.nullifier()) {
            return Err("already settled");
        }
        // One proof per field, each at its own declared width, so a narrow
        // amount beside a wide price is worth what it says.
        let mut transcript = Transcript::new(b"qomm:zkpi:ranges:amount");
        if !self.amount_ranges.verify(
            &mut transcript,
            &instruction.amount_range,
            &instruction.range_commitments[..1],
        ) {
            return Err("the amount is outside the published bounds");
        }
        let mut transcript = Transcript::new(b"qomm:zkpi:ranges:price");
        if !self.price_ranges.verify(
            &mut transcript,
            &instruction.price_range,
            &instruction.range_commitments[1..2],
        ) {
            return Err("the price is outside the published bounds");
        }
        // the commitments the ranges cover must be the ones the instruction
        // carries, or the proof is about something else
        if instruction.range_commitments.first() != Some(&instruction.amount_commitment.compress())
            || instruction.range_commitments.get(1)
                != Some(&instruction.price_commitment.compress())
        {
            return Err("the range proof does not cover this instruction");
        }
        self.group_public
            .verifying_key()
            .verify(
                &instruction.digest_for(&self.domain),
                &instruction.signature,
            )
            .map_err(|_| "the quorum signature does not verify")?;
        Ok(())
    }

    pub fn settle(&mut self, instruction: &Instruction, now: u64) -> Result<(), &'static str> {
        self.verify(instruction, now)?;
        self.spent.insert(instruction.nullifier());
        Ok(())
    }

    pub fn spent(&self) -> usize {
        self.spent.len()
    }
}

/// A trusted-dealer quorum, which is what a computing node set is.
/// A quorum from a trusted dealer. **A fixture, not a deployment.**
///
/// One call makes every secret share and hands them all back to the caller, so
/// whoever runs it can sign alone --- which is the property the quorum exists
/// to remove. It is here because every test and every measurement needs a
/// quorum and none of them is testing the setup.
///
/// A deployment runs `distributed_key_generation` below instead: each node
/// draws its own polynomial, and no party ever holds the group secret. The
/// difference is the whole trust model, so the name says which this is.
pub fn deal_quorum<R: RngCore + CryptoRng>(
    nodes: u16,
    threshold: u16,
    rng: &mut R,
) -> Result<
    (
        BTreeMap<frost::Identifier, frost::keys::SecretShare>,
        frost::keys::PublicKeyPackage,
    ),
    &'static str,
> {
    frost::keys::generate_with_dealer(nodes, threshold, frost::keys::IdentifierList::Default, rng)
        .map_err(|_| "dealing failed")
}

/// A quorum nobody dealt: two rounds of FROST DKG, run to completion.
///
/// Each node commits to its own polynomial in round one, exchanges shares in
/// round two, and derives the group public key from what it received. No party
/// holds the group secret at any point, which is what `deal_quorum` gives away.
pub fn distributed_key_generation<R: RngCore + CryptoRng>(
    nodes: u16,
    threshold: u16,
    rng: &mut R,
) -> Result<
    (
        BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
        frost::keys::PublicKeyPackage,
    ),
    &'static str,
> {
    use frost::keys::dkg;
    let ids: Vec<frost::Identifier> = (1..=nodes)
        .map(|i| frost::Identifier::try_from(i).expect("identifier"))
        .collect();

    let mut secrets_one = BTreeMap::new();
    let mut broadcast = BTreeMap::new();
    for id in &ids {
        let (secret, package) =
            dkg::part1(*id, nodes, threshold, &mut *rng).map_err(|_| "dkg round one failed")?;
        secrets_one.insert(*id, secret);
        broadcast.insert(*id, package);
    }

    let mut secrets_two = BTreeMap::new();
    let mut directed: BTreeMap<frost::Identifier, BTreeMap<frost::Identifier, _>> =
        ids.iter().map(|id| (*id, BTreeMap::new())).collect();
    for id in &ids {
        let others: BTreeMap<_, _> = broadcast
            .iter()
            .filter(|(other, _)| *other != id)
            .map(|(other, package)| (*other, package.clone()))
            .collect();
        let (secret, to_send) =
            dkg::part2(secrets_one[id].clone(), &others).map_err(|_| "dkg round two failed")?;
        secrets_two.insert(*id, secret);
        for (receiver, package) in to_send {
            directed
                .get_mut(&receiver)
                .ok_or("dkg addressed an absent node")?
                .insert(*id, package);
        }
    }

    let mut packages = BTreeMap::new();
    let mut group = None;
    for id in &ids {
        let others: BTreeMap<_, _> = broadcast
            .iter()
            .filter(|(other, _)| *other != id)
            .map(|(other, package)| (*other, package.clone()))
            .collect();
        let (key_package, public) = dkg::part3(&secrets_two[id], &others, &directed[id])
            .map_err(|_| "dkg round three failed")?;
        packages.insert(*id, key_package);
        group = Some(public);
    }
    Ok((packages, group.ok_or("no nodes")?))
}
