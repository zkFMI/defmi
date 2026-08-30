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
//! audit behind it; there was no reason to keep a hand-rolled one.

pub mod handles;
pub mod typed;
pub mod typed_wire;
pub mod wire;
pub mod wire_vectors;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_proofs::threshold_range::{verify_threshold_range, ThresholdRangeProof};
use qomm_zk::pedersen::Pedersen;
use qomm_zk::range::RangeCtx;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use std::collections::{BTreeMap, HashSet};

pub use frost_ristretto255 as frost;

pub const AMOUNT_RANGE_CONTEXT: &[u8] = b"qomm:zkpi:ranges:amount";
pub const PRICE_RANGE_CONTEXT: &[u8] = b"qomm:zkpi:ranges:price";

/// Public evidence that the hidden amount and price fit the venue's bounds.
///
/// `Bulletproof` is the backwards-compatible single-prover form. `Threshold`
/// is assembled by the MPC nodes and can be verified without any process ever
/// receiving the clear amount, price, or their Pedersen blindings.
#[derive(Clone, Debug)]
pub enum RangeEvidence {
    Bulletproof {
        amount: bulletproofs::RangeProof,
        price: bulletproofs::RangeProof,
        commitments: Vec<curve25519_dalek::ristretto::CompressedRistretto>,
    },
    Threshold {
        amount: ThresholdRangeProof,
        price: ThresholdRangeProof,
    },
}

/// What ties a zkPI to the quote computation that produced it.
///
/// Version 1 exposed the packed winner key, which contains the price and maker
/// index. Version 2 signs only the digest of the public zero-knowledge quote
/// statement. The proof itself binds the hidden winner and price commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuoteBinding {
    LegacyPackedKey(u64),
    ProofDigest([u8; 32]),
}

impl RangeEvidence {
    pub fn is_threshold(&self) -> bool {
        matches!(self, Self::Threshold { .. })
    }

    pub fn commitment_count(&self) -> usize {
        match self {
            Self::Bulletproof { commitments, .. } => commitments.len(),
            Self::Threshold { amount, price } => {
                amount.bit_commitments.len() + price.bit_commitments.len()
            }
        }
    }

    pub fn proof_bytes_len(&self) -> usize {
        match self {
            Self::Bulletproof { amount, price, .. } => {
                amount.to_bytes().len() + price.to_bytes().len()
            }
            Self::Threshold { amount, price } => {
                wire::threshold_range_encoded_len(amount) + wire::threshold_range_encoded_len(price)
            }
        }
    }
}

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
    /// One proof per rail. Production issuance uses the threshold form; the
    /// legacy Bulletproof form remains decodable during migration.
    pub ranges: RangeEvidence,
    pub payer_handle: RistrettoPoint,
    pub payee_handle: RistrettoPoint,
    pub deadline: u64,
    pub nonce: [u8; 32],
    pub quote_binding: QuoteBinding,
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

/// Canonical field encoding of a DeFMI asset identifier.  Both issuance and
/// settlement use this function, so the hidden zkPI asset cannot be relabelled
/// as another security rail.
pub fn asset_scalar(asset_id: &[u8; 32]) -> Scalar {
    let wide: [u8; 64] = Sha512::new()
        .chain_update(b"QOMM:DEFMI:ASSET-SCALAR:v1")
        .chain_update(asset_id)
        .finalize()
        .into();
    Scalar::from_bytes_mod_order_wide(&wide)
}

impl Instruction {
    pub fn range_commitment_count(&self) -> usize {
        self.ranges.commitment_count()
    }

    pub fn range_proof_bytes_len(&self) -> usize {
        self.ranges.proof_bytes_len()
    }

    pub fn legacy_quote_key(&self) -> Option<u64> {
        match self.quote_binding {
            QuoteBinding::LegacyPackedKey(value) => Some(value),
            QuoteBinding::ProofDigest(_) => None,
        }
    }

    pub fn quote_proof_digest(&self) -> Option<[u8; 32]> {
        match self.quote_binding {
            QuoteBinding::LegacyPackedKey(_) => None,
            QuoteBinding::ProofDigest(value) => Some(value),
        }
    }

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
        match self.quote_binding {
            QuoteBinding::LegacyPackedKey(value) => hasher.update(value.to_be_bytes()),
            QuoteBinding::ProofDigest(value) => {
                hasher.update(b"QOMM:QUOTE-PROOF-DIGEST:v1");
                hasher.update(value);
            }
        }
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
        self.build_with_asset_scalar(
            amount,
            price,
            Scalar::from(asset as u64),
            payer_handle,
            payee_handle,
            deadline,
            nonce,
            quote_key,
            rng,
        )
    }

    /// Product issuer for a DeFMI asset ID rather than a local numeric test
    /// code.  The asset remains hidden in the instruction; an asset-link proof
    /// later binds it to the selected security rail.
    #[allow(clippy::too_many_arguments)]
    pub fn build_for_asset_id<R: RngCore + CryptoRng>(
        &self,
        amount: u64,
        price: u64,
        asset_id: [u8; 32],
        payer_handle: RistrettoPoint,
        payee_handle: RistrettoPoint,
        deadline: u64,
        nonce: [u8; 32],
        quote_key: u64,
        rng: &mut R,
    ) -> Result<(Vec<u8>, Openings, PartialInstruction), &'static str> {
        self.build_with_asset_scalar(
            amount,
            price,
            asset_scalar(&asset_id),
            payer_handle,
            payee_handle,
            deadline,
            nonce,
            quote_key,
            rng,
        )
    }

    /// Build a reserve instruction around an amount commitment already
    /// signed by a Maker or Taker mandate. The caller supplies only the
    /// commitment openings it owns; no later party may substitute a fresh
    /// amount blinding and still satisfy the pre-trade authority.
    #[allow(clippy::too_many_arguments)]
    pub fn build_for_asset_id_with_openings<R: RngCore + CryptoRng>(
        &self,
        amount: u64,
        price: u64,
        asset_id: [u8; 32],
        payer_handle: RistrettoPoint,
        payee_handle: RistrettoPoint,
        deadline: u64,
        nonce: [u8; 32],
        quote_key: u64,
        openings: Openings,
        _rng: &mut R,
    ) -> Result<(Vec<u8>, Openings, PartialInstruction), &'static str> {
        self.build_with_asset_scalar_and_openings(
            amount,
            price,
            asset_scalar(&asset_id),
            payer_handle,
            payee_handle,
            deadline,
            nonce,
            quote_key,
            openings,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_with_asset_scalar<R: RngCore + CryptoRng>(
        &self,
        amount: u64,
        price: u64,
        asset_value: Scalar,
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
        self.build_with_asset_scalar_and_openings(
            amount,
            price,
            asset_value,
            payer_handle,
            payee_handle,
            deadline,
            nonce,
            quote_key,
            openings,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_with_asset_scalar_and_openings(
        &self,
        amount: u64,
        price: u64,
        asset_value: Scalar,
        payer_handle: RistrettoPoint,
        payee_handle: RistrettoPoint,
        deadline: u64,
        nonce: [u8; 32],
        quote_key: u64,
        openings: Openings,
    ) -> Result<(Vec<u8>, Openings, PartialInstruction), &'static str> {
        let mut transcript = Transcript::new(AMOUNT_RANGE_CONTEXT);
        let (amount_range, amount_commitments) =
            self.amount_ranges
                .prove(&mut transcript, &[amount], &[openings.amount])?;
        let mut transcript = Transcript::new(PRICE_RANGE_CONTEXT);
        let (price_range, price_commitments) =
            self.price_ranges
                .prove(&mut transcript, &[price], &[openings.price])?;
        let range_commitments = [amount_commitments, price_commitments].concat();
        let partial = PartialInstruction {
            amount_commitment: self.key.commit_u64(amount, &openings.amount),
            price_commitment: self.key.commit_u64(price, &openings.price),
            asset_commitment: self.key.commit(&asset_value, &openings.asset),
            ranges: RangeEvidence::Bulletproof {
                amount: amount_range,
                price: price_range,
                commitments: range_commitments,
            },
            payer_handle,
            payee_handle,
            deadline,
            nonce,
            quote_binding: QuoteBinding::LegacyPackedKey(quote_key),
        };
        Ok((partial.digest_for(&self.domain).to_vec(), openings, partial))
    }
}

/// The instruction before the quorum has signed it.
pub struct PartialInstruction {
    pub amount_commitment: RistrettoPoint,
    pub price_commitment: RistrettoPoint,
    pub asset_commitment: RistrettoPoint,
    pub ranges: RangeEvidence,
    pub payer_handle: RistrettoPoint,
    pub payee_handle: RistrettoPoint,
    pub deadline: u64,
    pub nonce: [u8; 32],
    pub quote_binding: QuoteBinding,
}

impl PartialInstruction {
    /// Recompute the signed payment statement from public fields only.
    ///
    /// Range evidence is deliberately not part of the signature digest (a
    /// venue verifies it separately).  Durable threshold signers use this
    /// helper to check that the coordinator has not substituted any signed
    /// field without needing an instruction opening or a single-process
    /// issuer.
    #[allow(clippy::too_many_arguments)]
    pub fn digest_public_fields_for(
        domain: &[u8],
        amount_commitment: &RistrettoPoint,
        price_commitment: &RistrettoPoint,
        asset_commitment: &RistrettoPoint,
        payer_handle: &RistrettoPoint,
        payee_handle: &RistrettoPoint,
        deadline: u64,
        nonce: [u8; 32],
        quote_binding: QuoteBinding,
    ) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(b"QOMM:ZKPI:v2");
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain);
        for point in [
            amount_commitment,
            price_commitment,
            asset_commitment,
            payer_handle,
            payee_handle,
        ] {
            hasher.update(point.compress().as_bytes());
        }
        hasher.update(deadline.to_be_bytes());
        hasher.update(nonce);
        match quote_binding {
            QuoteBinding::LegacyPackedKey(value) => hasher.update(value.to_be_bytes()),
            QuoteBinding::ProofDigest(value) => {
                hasher.update(b"QOMM:QUOTE-PROOF-DIGEST:v1");
                hasher.update(value);
            }
        }
        hasher.finalize().into()
    }

    /// Construct the production form from public commitments and threshold
    /// range proofs emitted by the MPC proof protocol. No opening is accepted
    /// by this API, which prevents an issuer process from becoming a hidden
    /// cleartext reconstruction point.
    #[allow(clippy::too_many_arguments)]
    pub fn from_threshold_ranges(
        key: &Pedersen,
        bounds: &Bounds,
        amount_commitment: RistrettoPoint,
        price_commitment: RistrettoPoint,
        asset_commitment: RistrettoPoint,
        amount_range: ThresholdRangeProof,
        price_range: ThresholdRangeProof,
        payer_handle: RistrettoPoint,
        payee_handle: RistrettoPoint,
        deadline: u64,
        nonce: [u8; 32],
        quote_proof_digest: [u8; 32],
    ) -> Result<Self, &'static str> {
        if amount_range.bits != bounds.amount_bits
            || !verify_threshold_range(key, &amount_commitment, &amount_range, AMOUNT_RANGE_CONTEXT)
        {
            return Err("the threshold amount proof is outside the published bounds");
        }
        if price_range.bits != bounds.price_bits
            || !verify_threshold_range(key, &price_commitment, &price_range, PRICE_RANGE_CONTEXT)
        {
            return Err("the threshold price proof is outside the published bounds");
        }
        if payer_handle.compress() == payee_handle.compress() {
            return Err("the payer and the payee are the same handle");
        }
        Ok(Self {
            amount_commitment,
            price_commitment,
            asset_commitment,
            ranges: RangeEvidence::Threshold {
                amount: amount_range,
                price: price_range,
            },
            payer_handle,
            payee_handle,
            deadline,
            nonce,
            quote_binding: QuoteBinding::ProofDigest(quote_proof_digest),
        })
    }

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
        Self::digest_public_fields_for(
            domain,
            &self.amount_commitment,
            &self.price_commitment,
            &self.asset_commitment,
            &self.payer_handle,
            &self.payee_handle,
            self.deadline,
            self.nonce,
            self.quote_binding,
        )
    }

    pub fn sealed(self, signature: frost::Signature) -> Instruction {
        Instruction {
            amount_commitment: self.amount_commitment,
            price_commitment: self.price_commitment,
            asset_commitment: self.asset_commitment,
            ranges: self.ranges,
            payer_handle: self.payer_handle,
            payee_handle: self.payee_handle,
            deadline: self.deadline,
            nonce: self.nonce,
            quote_binding: self.quote_binding,
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
    require_threshold_ranges: bool,
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
            require_threshold_ranges: false,
        }
    }

    /// Production venues can reject legacy single-prover range evidence even
    /// when it is mathematically valid. This is a provenance policy: the MPC
    /// quorum, not a later cleartext issuer, must have produced the zkPI.
    pub fn require_threshold_ranges(mut self) -> Self {
        self.require_threshold_ranges = true;
        self
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
        match &instruction.ranges {
            RangeEvidence::Bulletproof {
                amount,
                price,
                commitments,
            } => {
                if self.require_threshold_ranges {
                    return Err("this venue requires range proofs produced by the MPC quorum");
                }
                if commitments.len() != 2 {
                    return Err("the range proof has the wrong number of commitments");
                }
                let mut transcript = Transcript::new(AMOUNT_RANGE_CONTEXT);
                if !self
                    .amount_ranges
                    .verify(&mut transcript, amount, &commitments[..1])
                {
                    return Err("the amount is outside the published bounds");
                }
                let mut transcript = Transcript::new(PRICE_RANGE_CONTEXT);
                if !self
                    .price_ranges
                    .verify(&mut transcript, price, &commitments[1..2])
                {
                    return Err("the price is outside the published bounds");
                }
                if commitments.first() != Some(&instruction.amount_commitment.compress())
                    || commitments.get(1) != Some(&instruction.price_commitment.compress())
                {
                    return Err("the range proof does not cover this instruction");
                }
            }
            RangeEvidence::Threshold { amount, price } => {
                if amount.bits != self.amount_ranges.bits
                    || !verify_threshold_range(
                        &self.key,
                        &instruction.amount_commitment,
                        amount,
                        AMOUNT_RANGE_CONTEXT,
                    )
                {
                    return Err("the amount is outside the published bounds");
                }
                if price.bits != self.price_ranges.bits
                    || !verify_threshold_range(
                        &self.key,
                        &instruction.price_commitment,
                        price,
                        PRICE_RANGE_CONTEXT,
                    )
                {
                    return Err("the price is outside the published bounds");
                }
            }
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
