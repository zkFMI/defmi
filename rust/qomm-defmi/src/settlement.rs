//! Delivery versus payment, driven by an instruction, over ledgers that cannot
//! read themselves.
//!
//! DeFMI checks arithmetic it can verify on its own --- nothing created,
//! nothing negative, nothing settled twice, and the two legs move together or
//! not at all. It does *not* check that the price was right or that the asset
//! was the one asked for: that meaning was established by the computing quorum
//! and is carried by the signature on the instruction. Asking the settlement
//! layer to re-derive it would mean giving it the plaintext, which is the one
//! thing the whole construction exists to avoid.
//!
//! Every sigma check in a package joins one batch and is settled by a single
//! point addition there costs a quarter of a scalar multiplication, so batching
//! made verification slower.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_proofs::threshold_gadgets::{
    joint_prove_product_from_contributions, ProductNodeContribution,
};
use qomm_proofs::threshold_range::{
    joint_prove_range_from_contributions, verify_threshold_range, NodeValueShares,
    ThresholdRangeProof,
};
use qomm_proofs::threshold_sigma::PartyId;
use qomm_transport::dvp_issuer::{
    DvpProofs, DVP_CASH_REMAINDER_CONTEXT, DVP_PRODUCT_CONTEXT, DVP_SECURITIES_REMAINDER_CONTEXT,
};
use qomm_transport::standing_pool::{
    account_of as shared_account_of, threshold_dvp_package_digest, ThresholdDvpSides,
};
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::{
    product_terms, prove_product, prove_same_value, same_value_terms, verify_product, Batch,
    CrossGeneratorProof, ProductProof,
};
use qomm_zkpi::{Instruction, Venue};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::assets::BlindedTag;
use crate::ledger::{Ledger, Transfer};

pub const SETTLE_DOMAIN: &[u8] = b"QOMM:DEFMI:DVP:v1";
pub const THRESHOLD_DVP_SECURITIES_REMAINDER_CONTEXT: &[u8] = DVP_SECURITIES_REMAINDER_CONTEXT;
pub const THRESHOLD_DVP_CASH_REMAINDER_CONTEXT: &[u8] = DVP_CASH_REMAINDER_CONTEXT;

pub struct DvpPackage {
    pub instruction: Instruction,
    pub securities_from: Vec<u8>,
    pub securities_to: Vec<u8>,
    pub cash_from: Vec<u8>,
    pub cash_to: Vec<u8>,
    pub securities_leg: Transfer,
    pub cash_leg: Transfer,
    /// The securities leg moves the instructed quantity. The two commitments
    /// sit under different value generators whenever the leg carries a tag, and
    /// the same proof covers the untagged case, so the wire format does not
    /// advertise which one is in use.
    pub quantity_link: CrossGeneratorProof,
    /// `quantity * price`, under the **base** generator, because that is where
    /// the instruction's factors are. Without it a tagged cash leg has nothing
    /// the product proof can be about: the leg's commitment is under the cash
    /// asset's tag and the product of two base-generator commitments is not.
    pub cash_reference: RistrettoPoint,
    pub value_proof: ProductProof,
    /// The cash leg moves what the reference says. Same shape as
    /// `quantity_link` and for the same reason, and it covers the untagged case
    /// too so the wire does not advertise which is in use.
    pub cash_link: CrossGeneratorProof,
}

impl DvpPackage {
    /// Canonical evidence identifier signed into the durable product
    /// settlement.  Avalanche validators may rely on the committee-attested
    /// digest while the Rust admission service verifies these full proof bytes.
    pub fn digest(&self) -> [u8; 32] {
        fn bytes(hash: &mut Sha256, value: &[u8]) {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
        fn point(hash: &mut Sha256, value: &RistrettoPoint) {
            hash.update(value.compress().as_bytes());
        }
        fn scalar(hash: &mut Sha256, value: &Scalar) {
            hash.update(value.to_bytes());
        }
        fn transfer(hash: &mut Sha256, value: &Transfer) {
            point(hash, &value.amount_commitment);
            match &value.amount_range {
                Some((proof, commitment)) => {
                    hash.update([1]);
                    hash.update(commitment.as_bytes());
                    bytes(hash, &proof.to_bytes());
                }
                None => hash.update([0]),
            }
            point(hash, &value.remainder_commitment);
            bytes(hash, &value.remainder_range.to_bytes());
            match &value.tag {
                Some(tag) => {
                    hash.update([1]);
                    point(hash, &tag.point);
                }
                None => hash.update([0]),
            }
        }
        fn cross(hash: &mut Sha256, value: &CrossGeneratorProof) {
            point(hash, &value.t_first);
            point(hash, &value.t_second);
            scalar(hash, &value.z_value);
            scalar(hash, &value.z_first);
            scalar(hash, &value.z_second);
        }
        fn product(hash: &mut Sha256, value: &ProductProof) {
            point(hash, &value.t_factor);
            point(hash, &value.t_product);
            scalar(hash, &value.z_b);
            scalar(hash, &value.z_rb);
            scalar(hash, &value.z_s);
        }

        let mut hash = Sha256::new();
        hash.update(b"QOMM:DEFMI:DVP-PACKAGE:v1");
        bytes(&mut hash, &qomm_zkpi::wire::encode(&self.instruction));
        for handle in [
            &self.securities_from,
            &self.securities_to,
            &self.cash_from,
            &self.cash_to,
        ] {
            bytes(&mut hash, handle);
        }
        transfer(&mut hash, &self.securities_leg);
        transfer(&mut hash, &self.cash_leg);
        cross(&mut hash, &self.quantity_link);
        point(&mut hash, &self.cash_reference);
        product(&mut hash, &self.value_proof);
        cross(&mut hash, &self.cash_link);
        hash.finalize().into()
    }
}

/// One node's private contribution to a DvP package. Each field contains only
/// that node's Shamir evaluation; no constructor accepts a map of all scalar
/// shares. The product contribution proves `quantity * price = cash`, while
/// the two range contributions prove that both reserved maxima cover the
/// resulting transfer.
#[derive(Clone, Debug)]
pub struct ThresholdDvpNodeContribution {
    product: ProductNodeContribution,
    securities_remainder: NodeValueShares,
    cash_remainder: NodeValueShares,
}

impl ThresholdDvpNodeContribution {
    pub fn new(
        product: ProductNodeContribution,
        securities_remainder: NodeValueShares,
        cash_remainder: NodeValueShares,
    ) -> Result<Self, String> {
        let party = product.party();
        if securities_remainder.party() != party || cash_remainder.party() != party {
            return Err("one DvP contribution mixes shares from different nodes".into());
        }
        Ok(Self {
            product,
            securities_remainder,
            cash_remainder,
        })
    }

    pub fn party(&self) -> PartyId {
        self.product.party()
    }
}

/// Public, verifier-complete DvP evidence assembled from node-local shares.
/// Unlike [`DvpPackage`], this form never requires one process to know either
/// payer's balance, the quantity, the price, or any commitment blinding.
#[derive(Clone)]
pub struct ThresholdDvpPackage {
    pub instruction: Instruction,
    pub securities_from: Vec<u8>,
    pub securities_to: Vec<u8>,
    pub cash_from: Vec<u8>,
    pub cash_to: Vec<u8>,
    pub cash_commitment: RistrettoPoint,
    pub securities_remainder: RistrettoPoint,
    pub cash_remainder: RistrettoPoint,
    pub securities_remainder_range: ThresholdRangeProof,
    pub cash_remainder_range: ThresholdRangeProof,
    pub value_proof: ProductProof,
}

impl ThresholdDvpPackage {
    pub fn digest(&self) -> [u8; 32] {
        threshold_dvp_package_digest(
            &self.instruction,
            &ThresholdDvpSides {
                securities_from: self.securities_from.clone(),
                securities_to: self.securities_to.clone(),
                cash_from: self.cash_from.clone(),
                cash_to: self.cash_to.clone(),
            },
            &self.cash_commitment,
            &self.securities_remainder,
            &self.cash_remainder,
            &DvpProofs {
                product: self.value_proof.clone(),
                securities_remainder: self.securities_remainder_range.clone(),
                cash_remainder: self.cash_remainder_range.clone(),
            },
        )
    }
}

fn threshold_value_transcript() -> Transcript {
    Transcript::new(DVP_PRODUCT_CONTEXT)
}

/// Build the verifier-complete DvP package from public proofs produced by the
/// distributed node protocol.  The caller supplies no scalar witness, balance,
/// price, quantity or commitment opening.
#[allow(clippy::too_many_arguments)]
pub fn build_threshold_package_from_proofs(
    key: &Pedersen,
    instruction: Instruction,
    sides: Sides,
    securities_reserve: RistrettoPoint,
    cash_reserve: RistrettoPoint,
    cash_commitment: RistrettoPoint,
    proofs: DvpProofs,
    bits: usize,
) -> Result<ThresholdDvpPackage, String> {
    let package = ThresholdDvpPackage {
        securities_remainder: securities_reserve - instruction.amount_commitment,
        cash_remainder: cash_reserve - cash_commitment,
        instruction,
        securities_from: sides.securities_from,
        securities_to: sides.securities_to,
        cash_from: sides.cash_from,
        cash_to: sides.cash_to,
        cash_commitment,
        securities_remainder_range: proofs.securities_remainder,
        cash_remainder_range: proofs.cash_remainder,
        value_proof: proofs.product,
    };
    verify_threshold_package(key, &package, &securities_reserve, &cash_reserve, bits)?;
    Ok(package)
}

/// Assemble public DvP evidence from a k-of-n set of recipient-scoped node
/// contributions. Interpolation is applied only to proof responses and group
/// elements; no clear value or Pedersen blinding is reconstructed.
#[allow(clippy::too_many_arguments)]
pub fn build_threshold_package_from_contributions<R: RngCore + CryptoRng>(
    key: &Pedersen,
    instruction: Instruction,
    sides: Sides,
    securities_reserve: RistrettoPoint,
    cash_reserve: RistrettoPoint,
    cash_commitment: RistrettoPoint,
    contributions: &[ThresholdDvpNodeContribution],
    quorum: &[PartyId],
    threshold: usize,
    bits: usize,
    rng: &mut R,
) -> Result<ThresholdDvpPackage, String> {
    if contributions.len() != quorum.len() || contributions.is_empty() {
        return Err("DvP contributions do not exactly fill the selected quorum".into());
    }
    let parties = contributions
        .iter()
        .map(ThresholdDvpNodeContribution::party)
        .collect::<std::collections::BTreeSet<_>>();
    if parties.len() != contributions.len()
        || quorum
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            != parties
    {
        return Err("DvP contributions contain an omitted or duplicate party".into());
    }
    let product_nodes = contributions
        .iter()
        .map(|node| node.product.clone())
        .collect::<Vec<_>>();
    let securities_nodes = contributions
        .iter()
        .map(|node| node.securities_remainder.clone())
        .collect::<Vec<_>>();
    let cash_nodes = contributions
        .iter()
        .map(|node| node.cash_remainder.clone())
        .collect::<Vec<_>>();
    let securities_remainder = securities_nodes[0].commitment();
    let cash_remainder = cash_nodes[0].commitment();
    if securities_reserve - instruction.amount_commitment != securities_remainder
        || cash_reserve - cash_commitment != cash_remainder
    {
        return Err("DvP remainders do not conserve the two reservation escrows".into());
    }
    let (value_proof, _) = joint_prove_product_from_contributions(
        key,
        &instruction.amount_commitment,
        &cash_commitment,
        &product_nodes,
        quorum,
        threshold,
        &mut threshold_value_transcript(),
        rng,
    )?;
    let (securities_remainder_range, _) = joint_prove_range_from_contributions(
        key,
        &securities_nodes,
        quorum,
        THRESHOLD_DVP_SECURITIES_REMAINDER_CONTEXT,
        rng,
    )?;
    let (cash_remainder_range, _) = joint_prove_range_from_contributions(
        key,
        &cash_nodes,
        quorum,
        THRESHOLD_DVP_CASH_REMAINDER_CONTEXT,
        rng,
    )?;
    if securities_remainder != securities_reserve - instruction.amount_commitment
        || cash_remainder != cash_reserve - cash_commitment
    {
        return Err("threshold DvP proof statements changed during assembly".into());
    }
    build_threshold_package_from_proofs(
        key,
        instruction,
        sides,
        securities_reserve,
        cash_reserve,
        cash_commitment,
        DvpProofs {
            product: value_proof,
            securities_remainder: securities_remainder_range,
            cash_remainder: cash_remainder_range,
        },
        bits,
    )
}

pub(crate) fn verify_threshold_package(
    key: &Pedersen,
    package: &ThresholdDvpPackage,
    securities_reserve: &RistrettoPoint,
    cash_reserve: &RistrettoPoint,
    bits: usize,
) -> Result<(), String> {
    if package.securities_from == package.securities_to
        || package.cash_from == package.cash_to
        || *securities_reserve - package.instruction.amount_commitment
            != package.securities_remainder
        || *cash_reserve - package.cash_commitment != package.cash_remainder
    {
        return Err("threshold DvP account or escrow conservation failed".into());
    }
    if package.securities_remainder_range.bits != bits
        || !verify_threshold_range(
            key,
            &package.securities_remainder,
            &package.securities_remainder_range,
            THRESHOLD_DVP_SECURITIES_REMAINDER_CONTEXT,
        )
        || package.cash_remainder_range.bits != bits
        || !verify_threshold_range(
            key,
            &package.cash_remainder,
            &package.cash_remainder_range,
            THRESHOLD_DVP_CASH_REMAINDER_CONTEXT,
        )
    {
        return Err("threshold DvP has a negative or out-of-range reservation remainder".into());
    }
    if !verify_product(
        key,
        &mut threshold_value_transcript(),
        &package.instruction.amount_commitment,
        &package.instruction.price_commitment,
        &package.cash_commitment,
        &package.value_proof,
    ) {
        return Err("threshold DvP cash amount is not quantity times price".into());
    }
    Ok(())
}

pub struct Receipt {
    pub status: Result<(), &'static str>,
    pub securities_before: [u8; 32],
    pub securities_after: [u8; 32],
    pub cash_before: [u8; 32],
    pub cash_after: [u8; 32],
}

/// What each payer must remember once the package settles. A Pedersen balance
/// is only usable by whoever knows its blinding, so this is the account itself
/// as far as the holder is concerned.
pub struct Carry {
    pub securities_balance: u64,
    pub securities_blinding: Scalar,
    pub cash_balance: u64,
    pub cash_blinding: Scalar,
    /// Openings of the two rail amount commitments.  Product reservation
    /// consumption uses these (not the separately blinded reference points) so
    /// the unused escrow commitment is exactly the DvP remainder.
    pub securities_amount_blinding: Scalar,
    pub cash_amount_blinding: Scalar,
    /// Opening of `DvpPackage::cash_reference`.  The product settlement layer
    /// uses it to prove that the payer's pre-trade guarantee reservation is
    /// consumed by exactly the same hidden cash amount as the DvP leg.
    pub cash_reference_blinding: Scalar,
}

/// The account name a rail keeps a party's balance under.
///
/// Derived from the handle the instruction names, so the two cannot disagree.
/// They used to be unrelated --- an instruction named two group elements and a
/// package named four byte strings, and nothing checked that the account a leg
/// settled from was the party the instruction said. That was not theft, since a
/// payer spends its own balance either way, but it left the whole per-venue
/// handle property living in whatever a caller happened to pass rather than in
/// anything the venue verified. Measuring a cross-venue exchange showed what
/// that costs: with one identifier reused, an observer joins the two legs of an
/// exchange with certainty.
///
/// The rail goes into the derivation so that a rail's account names are its own.
/// Both rails of one venue settle in the same call, so this buys no
/// unlinkability there; it costs nothing and keeps a handle from being a key in
/// two maps at once.
pub fn account_of(handle: &RistrettoPoint, rail: &[u8]) -> Vec<u8> {
    shared_account_of(handle, rail)
}

pub const SECURITIES_RAIL: &[u8] = b"securities";
pub const CASH_RAIL: &[u8] = b"cash";

/// Where a DvP moves value, as the instruction fixes it. The securities go the
/// other way from the cash, which is what makes it a delivery *versus* payment.
pub struct Sides {
    pub securities_from: Vec<u8>,
    pub securities_to: Vec<u8>,
    pub cash_from: Vec<u8>,
    pub cash_to: Vec<u8>,
}

impl Sides {
    /// The only way to name the four accounts. There is no constructor that
    /// takes them, so a package cannot be built that names accounts the
    /// instruction does not.
    pub fn of(instruction: &Instruction) -> Sides {
        Sides {
            // the payee of cash delivers the securities
            securities_from: account_of(&instruction.payee_handle, SECURITIES_RAIL),
            securities_to: account_of(&instruction.payer_handle, SECURITIES_RAIL),
            cash_from: account_of(&instruction.payer_handle, CASH_RAIL),
            cash_to: account_of(&instruction.payee_handle, CASH_RAIL),
        }
    }
}

pub struct Holdings {
    pub securities_balance: u64,
    pub securities_blinding: Scalar,
    pub cash_balance: u64,
    pub cash_blinding: Scalar,
}

pub struct InstructionOpenings {
    pub amount: Scalar,
    pub price: Scalar,
}

#[allow(clippy::too_many_arguments)]
pub fn build_package<R: RngCore + CryptoRng>(
    key: &Pedersen,
    instruction: Instruction,
    securities: &Ledger,
    cash: &Ledger,
    quantity: u64,
    price: u64,
    holdings: &Holdings,
    openings: &InstructionOpenings,
    securities_tag: Option<&BlindedTag>,
    securities_gamma: &Scalar,
    cash_tag: Option<&BlindedTag>,
    cash_gamma: &Scalar,
    rng: &mut R,
) -> Result<(DvpPackage, Carry), &'static str> {
    let sides = Sides::of(&instruction);
    build_package_for_sides(
        key,
        instruction,
        sides,
        securities,
        cash,
        quantity,
        price,
        holdings,
        openings,
        securities_tag,
        securities_gamma,
        cash_tag,
        cash_gamma,
        rng,
    )
}

/// Construct DvP proofs whose payer balances live in pre-trade reservation
/// escrow rather than in the parties' spendable accounts.  The destination
/// handles remain fixed by the signed instruction; the product verifier checks
/// the supplied source handles against the two consumed reservation records.
#[allow(clippy::too_many_arguments)]
pub fn build_package_for_sides<R: RngCore + CryptoRng>(
    key: &Pedersen,
    instruction: Instruction,
    sides: Sides,
    securities: &Ledger,
    cash: &Ledger,
    quantity: u64,
    price: u64,
    holdings: &Holdings,
    openings: &InstructionOpenings,
    securities_tag: Option<&BlindedTag>,
    securities_gamma: &Scalar,
    cash_tag: Option<&BlindedTag>,
    cash_gamma: &Scalar,
    rng: &mut R,
) -> Result<(DvpPackage, Carry), &'static str> {
    // Both amounts are pinned by the instruction --- the quantity through the
    // link below, the cash through the product relation --- so neither needs a
    // second range proof here. That is half the range proofs in the package.
    let (securities_leg, securities_secrets) = securities.build_transfer(
        holdings.securities_balance,
        &holdings.securities_blinding,
        quantity,
        &[SETTLE_DOMAIN, b":sec"].concat(),
        securities_tag,
        securities_gamma,
        true,
        rng,
    )?;
    let value = quantity.checked_mul(price).ok_or("cash amount overflows")?;
    let (cash_leg, cash_secrets) = cash.build_transfer(
        holdings.cash_balance,
        &holdings.cash_blinding,
        value,
        &[SETTLE_DOMAIN, b":cash"].concat(),
        cash_tag,
        cash_gamma,
        true,
        rng,
    )?;

    let leg_generator = securities_tag.map(|t| t.point).unwrap_or(key.g);
    let quantity_link = prove_same_value(
        key,
        &mut link_transcript(),
        &leg_generator,
        &key.g,
        &securities_leg.amount_commitment,
        &instruction.amount_commitment,
        &Scalar::from(quantity),
        &securities_secrets.amount_blinding,
        &openings.amount,
        rng,
    );

    // The quantity is taken from the instruction rather than from the leg: the
    // link above already ties them, and the instruction is what the quorum
    // signed.
    // The product lives under the base generator, so it is proved about a
    // reference commitment there and the leg is tied to that reference. When
    // the cash rail is untagged the two generators coincide and the link is a
    // proof of the obvious --- which is the right price for not having two
    // package shapes.
    let reference_blinding = Scalar::random(rng);
    let cash_reference = key.commit_u64(value, &reference_blinding);
    let value_proof = prove_product(
        key,
        &mut value_transcript(),
        &instruction.price_commitment,
        &Scalar::from(price),
        &openings.price,
        &Scalar::from(quantity),
        &openings.amount,
        &reference_blinding,
        rng,
    );
    let cash_generator = cash_tag.map(|t| t.point).unwrap_or(key.g);
    let cash_link = prove_same_value(
        key,
        &mut cash_link_transcript(),
        &cash_generator,
        &key.g,
        &cash_leg.amount_commitment,
        &cash_reference,
        &Scalar::from(value),
        &cash_secrets.amount_blinding,
        &reference_blinding,
        rng,
    );

    let carry = Carry {
        securities_balance: holdings.securities_balance - quantity,
        securities_blinding: securities_secrets.remainder_blinding,
        cash_balance: holdings.cash_balance - value,
        cash_blinding: cash_secrets.remainder_blinding,
        securities_amount_blinding: securities_secrets.amount_blinding,
        cash_amount_blinding: cash_secrets.amount_blinding,
        cash_reference_blinding: reference_blinding,
    };
    Ok((
        DvpPackage {
            instruction,
            securities_from: sides.securities_from,
            securities_to: sides.securities_to,
            cash_from: sides.cash_from,
            cash_to: sides.cash_to,
            securities_leg,
            cash_leg,
            quantity_link,
            cash_reference,
            value_proof,
            cash_link,
        },
        carry,
    ))
}

fn link_transcript() -> Transcript {
    Transcript::new(b"qomm:defmi:qty-link")
}
fn value_transcript() -> Transcript {
    Transcript::new(b"qomm:defmi:value")
}
fn cash_link_transcript() -> Transcript {
    Transcript::new(b"qomm:defmi:cash-link")
}

/// Verify the two confidential transfer legs and their links to the signed
/// instruction against a caller-supplied ledger snapshot.  The durable DeFMI
/// store uses this same verifier before atomically applying its four account
/// updates and two guarantee-reservation consumptions.
pub(crate) fn verify_package_legs<R: RngCore + CryptoRng>(
    key: &Pedersen,
    securities: &Ledger,
    cash: &Ledger,
    package: &DvpPackage,
    rng: &mut R,
) -> Result<(), &'static str> {
    let who = Sides::of(&package.instruction);
    verify_package_legs_for_sides(key, securities, cash, package, &who, rng)
}

pub(crate) fn verify_package_legs_for_sides<R: RngCore + CryptoRng>(
    key: &Pedersen,
    securities: &Ledger,
    cash: &Ledger,
    package: &DvpPackage,
    who: &Sides,
    rng: &mut R,
) -> Result<(), &'static str> {
    if package.securities_from != who.securities_from
        || package.securities_to != who.securities_to
        || package.cash_from != who.cash_from
        || package.cash_to != who.cash_to
    {
        return Err("the package names accounts the instruction does not");
    }

    for (handle, ledger) in [
        (&package.securities_from, securities),
        (&package.securities_to, securities),
        (&package.cash_from, cash),
        (&package.cash_to, cash),
    ] {
        if ledger.balance(handle).is_none() {
            return Err("an account is not open");
        }
    }
    if package.securities_from == package.securities_to {
        return Err("securities legs share a handle");
    }
    if package.cash_from == package.cash_to {
        return Err("cash legs share a handle");
    }

    securities.check_transfer(
        &package.securities_from,
        &package.securities_leg,
        &[SETTLE_DOMAIN, b":sec"].concat(),
        true,
    )?;
    cash.check_transfer(
        &package.cash_from,
        &package.cash_leg,
        &[SETTLE_DOMAIN, b":cash"].concat(),
        true,
    )?;

    let mut batch = Batch::new();
    let leg_generator = package
        .securities_leg
        .tag
        .as_ref()
        .map(|tag| tag.point)
        .unwrap_or(key.g);
    let (scalars, points) = same_value_terms(
        key,
        &mut link_transcript(),
        &leg_generator,
        &key.g,
        &package.securities_leg.amount_commitment,
        &package.instruction.amount_commitment,
        &package.quantity_link,
        &Batch::weight(rng),
    );
    batch.push(scalars, points);
    let (scalars, points) = product_terms(
        key,
        &mut value_transcript(),
        &package.instruction.price_commitment,
        &package.instruction.amount_commitment,
        &package.cash_reference,
        &package.value_proof,
        &Batch::weight(rng),
    );
    batch.push(scalars, points);
    let cash_generator = package
        .cash_leg
        .tag
        .as_ref()
        .map(|tag| tag.point)
        .unwrap_or(key.g);
    let (scalars, points) = same_value_terms(
        key,
        &mut cash_link_transcript(),
        &cash_generator,
        &key.g,
        &package.cash_leg.amount_commitment,
        &package.cash_reference,
        &package.cash_link,
        &Batch::weight(rng),
    );
    batch.push(scalars, points);
    if !batch.verify() {
        return Err("the legs do not match what the instruction says");
    }
    Ok(())
}

pub struct Defmi {
    pub key: Pedersen,
    pub securities: Ledger,
    pub cash: Ledger,
    pub venue: Venue,
}

impl Defmi {
    pub fn new(key: Pedersen, securities: Ledger, cash: Ledger, venue: Venue) -> Self {
        Defmi {
            key,
            securities,
            cash,
            venue,
        }
    }

    fn check<R: RngCore + CryptoRng>(
        &self,
        package: &DvpPackage,
        now: u64,
        rng: &mut R,
    ) -> Result<(), &'static str> {
        self.venue.verify(&package.instruction, now)?;
        verify_package_legs(&self.key, &self.securities, &self.cash, package, rng)
    }

    pub fn settle<R: RngCore + CryptoRng>(
        &mut self,
        package: &DvpPackage,
        now: u64,
        rng: &mut R,
    ) -> Receipt {
        let securities_before = self.securities.snapshot();
        let cash_before = self.cash.snapshot();
        let status = self.check(package, now, rng);
        if status.is_ok() {
            // both legs are checked before either is applied, so a failure on
            // the second cannot leave the first settled
            self.securities.apply_transfer(
                &package.securities_from,
                &package.securities_to,
                &package.securities_leg,
            );
            self.cash
                .apply_transfer(&package.cash_from, &package.cash_to, &package.cash_leg);
            self.venue
                .settle(&package.instruction, now)
                .expect("venue refused after checks passed");
        }
        Receipt {
            status,
            securities_before,
            securities_after: self.securities.snapshot(),
            cash_before,
            cash_after: self.cash.snapshot(),
        }
    }

    pub fn solvent(&self) -> bool {
        self.securities.conserved() && self.cash.conserved()
    }
}
