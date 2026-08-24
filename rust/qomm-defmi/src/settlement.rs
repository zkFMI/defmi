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
//! multiscalar multiplication. That is the whole reason this is not Python: a
//! point addition there costs a quarter of a scalar multiplication, so batching
//! made verification slower.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::{
    product_terms, prove_product, prove_same_value, same_value_terms, Batch, CrossGeneratorProof,
    ProductProof,
};
use qomm_zkpi::{Instruction, Venue};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::assets::BlindedTag;
use crate::ledger::{Ledger, Transfer};

pub const SETTLE_DOMAIN: &[u8] = b"QOMM:DEFMI:DVP:v1";

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
    let mut hasher = Sha256::new();
    hasher.update(b"QOMM:DEFMI:ACCOUNT:v1");
    hasher.update((rail.len() as u64).to_be_bytes());
    hasher.update(rail);
    hasher.update(handle.compress().as_bytes());
    hasher.finalize().to_vec()
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

    let who = Sides::of(&instruction);
    let carry = Carry {
        securities_balance: holdings.securities_balance - quantity,
        securities_blinding: securities_secrets.remainder_blinding,
        cash_balance: holdings.cash_balance - value,
        cash_blinding: cash_secrets.remainder_blinding,
    };
    Ok((
        DvpPackage {
            instruction,
            securities_from: who.securities_from,
            securities_to: who.securities_to,
            cash_from: who.cash_from,
            cash_to: who.cash_to,
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

        // The four accounts are a function of the two handles the quorum
        // signed. A package that names anything else is refused before any
        // proof is looked at --- it is cheaper than a proof and it is the check
        // that makes the handles mean something.
        let who = Sides::of(&package.instruction);
        if package.securities_from != who.securities_from
            || package.securities_to != who.securities_to
            || package.cash_from != who.cash_from
            || package.cash_to != who.cash_to
        {
            return Err("the package names accounts the instruction does not");
        }

        for (handle, ledger) in [
            (&package.securities_from, &self.securities),
            (&package.securities_to, &self.securities),
            (&package.cash_from, &self.cash),
            (&package.cash_to, &self.cash),
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

        self.securities.check_transfer(
            &package.securities_from,
            &package.securities_leg,
            &[SETTLE_DOMAIN, b":sec"].concat(),
            true,
        )?;
        self.cash.check_transfer(
            &package.cash_from,
            &package.cash_leg,
            &[SETTLE_DOMAIN, b":cash"].concat(),
            true,
        )?;

        // Everything that is a sigma check goes into one batch, so the package
        // costs one multiscalar multiplication rather than one per proof.
        let mut batch = Batch::new();
        let leg_generator = package
            .securities_leg
            .tag
            .as_ref()
            .map(|t| t.point)
            .unwrap_or(self.key.g);
        let (s, p) = same_value_terms(
            &self.key,
            &mut link_transcript(),
            &leg_generator,
            &self.key.g,
            &package.securities_leg.amount_commitment,
            &package.instruction.amount_commitment,
            &package.quantity_link,
            &Batch::weight(rng),
        );
        batch.push(s, p);
        let (s, p) = product_terms(
            &self.key,
            &mut value_transcript(),
            &package.instruction.price_commitment,
            &package.instruction.amount_commitment,
            &package.cash_reference,
            &package.value_proof,
            &Batch::weight(rng),
        );
        batch.push(s, p);
        let cash_generator = package
            .cash_leg
            .tag
            .as_ref()
            .map(|t| t.point)
            .unwrap_or(self.key.g);
        let (s, p) = same_value_terms(
            &self.key,
            &mut cash_link_transcript(),
            &cash_generator,
            &self.key.g,
            &package.cash_leg.amount_commitment,
            &package.cash_reference,
            &package.cash_link,
            &Batch::weight(rng),
        );
        batch.push(s, p);
        if !batch.verify() {
            return Err("the legs do not match what the instruction says");
        }
        Ok(())
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
