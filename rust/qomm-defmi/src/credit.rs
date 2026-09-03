//! Intraday credit and the default waterfall.
//!
//! A net debit cap is committed rather than published. That hides its size, and
//! it also removes the sign: a coverage proof then shows only that position
//! plus cap lies in range, never which side of zero the position was on. The
//! offset trick that hiding a signed position would otherwise need is not
//! required anywhere.
//!
//! Waterfall ordering is enforced by a product: tranche k may be drawn only if
//! tranche k-1 is exhausted, which is exactly `draw_k * remaining_{k-1} = 0`.
//! Both factors stay committed and the product commitment is the identity, so
//! the verifier has nothing to be told beyond the proof.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::{
    opening_terms, product_terms, prove_opening, prove_product, verify_product, Batch,
    OpeningProof, ProductProof,
};
use rand_core::{CryptoRng, RngCore};
use sha2::Digest;

/// A net debit cap and the collateral standing behind it.
///
/// The haircut is public because it is published policy. The collateral and the
/// cap are not: what the proof establishes is that one covers the other, which
/// is the only relation anyone outside the participant needs.
///
/// The collateral figure is already valued in the units of the cap. Turning a
/// pledged security into a valued amount is the same product relation the cash
/// leg of a settlement uses, and it is not built here, so a deployment needs it
/// before collateral can be a different asset from the credit.
pub struct CreditLine {
    pub handle: Vec<u8>,
    pub rail: &'static str,
    pub cap_commitment: RistrettoPoint,
    pub collateral_commitment: RistrettoPoint,
    pub haircut_bp: u64,
    pub backing: RangeProof,
    pub backing_commitment: curve25519_dalek::ristretto::CompressedRistretto,
}

pub struct CreditCtx {
    pub key: Pedersen,
    pub bits: usize,
    gens: BulletproofGens,
}

impl CreditCtx {
    /// `key` must be the key the rail's positions live under. A cap is
    /// denominated in the same units as the position it relaxes, so committing
    /// it under a different generator makes the two incomparable --- and the
    /// arithmetic still typechecks, which is why this is worth saying out loud.
    pub fn new(key: Pedersen, bits: usize) -> Self {
        CreditCtx {
            key,
            bits,
            gens: BulletproofGens::new(bits, 1),
        }
    }

    fn pc(&self) -> PedersenGens {
        PedersenGens {
            B: self.key.g,
            B_blinding: self.key.h,
        }
    }

    /// Run where the collateral openings are known --- by the pledging member.
    /// The infrastructure verifies rather than computes: it never sees the
    /// collateral, only that the cap it underwrites is covered.
    #[allow(clippy::too_many_arguments)]
    pub fn grant(
        &self,
        handle: &[u8],
        rail: &'static str,
        cap: u64,
        cap_blinding: &Scalar,
        collateral: u64,
        collateral_blinding: &Scalar,
        haircut_bp: u64,
    ) -> Result<CreditLine, &'static str> {
        if haircut_bp >= 10_000 {
            return Err("the haircut is not a fraction");
        }
        let scale = 10_000 - haircut_bp;
        let lendable = collateral
            .checked_mul(scale)
            .ok_or("collateral overflows")?;
        let owed = cap.checked_mul(10_000).ok_or("cap overflows")?;
        if lendable < owed {
            return Err("the pledged collateral does not cover the cap");
        }
        // Stated on the scaled values so the integer division never has to be
        // proved. The width grows by the fourteen bits of the scale factor,
        // paid once when the line is granted rather than once per order.
        let slack = lendable - owed;
        let slack_blinding =
            collateral_blinding * Scalar::from(scale) - cap_blinding * Scalar::from(10_000u64);
        let mut t = Transcript::new(b"qomm:credit:backing");
        let (backing, commitments) = RangeProof::prove_multiple(
            &self.gens,
            &self.pc(),
            &mut t,
            &[slack],
            &[slack_blinding],
            self.bits,
        )
        .map_err(|_| "the backing proof failed")?;
        Ok(CreditLine {
            handle: handle.to_vec(),
            rail,
            cap_commitment: self.key.commit_u64(cap, cap_blinding),
            collateral_commitment: self.key.commit_u64(collateral, collateral_blinding),
            haircut_bp,
            backing,
            backing_commitment: commitments[0],
        })
    }

    /// The infrastructure underwriting a limit it cannot see.
    pub fn check(&self, line: &CreditLine) -> Result<(), &'static str> {
        if line.haircut_bp >= 10_000 {
            return Err("the haircut is not a fraction");
        }
        let scale = Scalar::from(10_000 - line.haircut_bp);
        let expected =
            line.collateral_commitment * scale - line.cap_commitment * Scalar::from(10_000u64);
        if expected.compress() != line.backing_commitment {
            return Err("the backing proof is about other commitments");
        }
        let mut t = Transcript::new(b"qomm:credit:backing");
        line.backing
            .verify_multiple(
                &self.gens,
                &self.pc(),
                &mut t,
                std::slice::from_ref(&line.backing_commitment),
                self.bits,
            )
            .map_err(|_| "the pledged collateral does not cover the cap")
    }
}

// --- the default waterfall ------------------------------------------------

#[derive(Clone)]
pub struct Tranche {
    pub name: String,
    pub commitment: RistrettoPoint,
}

/// What one tranche contributes, and the proof it was its turn.
pub struct Draw {
    pub tranche: usize,
    pub amount_commitment: RistrettoPoint,
    pub within: RangeProof,
    pub within_commitment: curve25519_dalek::ristretto::CompressedRistretto,
    /// Absent on the first tranche, which has nothing above it. Elsewhere it
    /// proves draw * remaining-above = 0: either nothing was taken here, or the
    /// layer above was already empty.
    pub ordering: Option<ProductProof>,
}

pub struct Resolution {
    pub shortfall_commitment: RistrettoPoint,
    pub shortfall_range: RangeProof,
    pub shortfall_range_commitment: curve25519_dalek::ristretto::CompressedRistretto,
    pub draws: Vec<Draw>,
    pub balance: OpeningProof,
}

pub struct Waterfall {
    pub key: Pedersen,
    pub bits: usize,
    pub tranches: Vec<Tranche>,
    gens: BulletproofGens,
}

impl Waterfall {
    pub fn new(key: Pedersen, tranches: Vec<Tranche>, bits: usize) -> Self {
        assert!(
            !tranches.is_empty(),
            "a waterfall needs at least one tranche"
        );
        Waterfall {
            key,
            bits,
            tranches,
            gens: BulletproofGens::new(bits, 1),
        }
    }

    fn pc(&self) -> PedersenGens {
        PedersenGens {
            B: self.key.g,
            B_blinding: self.key.h,
        }
    }

    fn within_transcript(index: usize) -> Transcript {
        let mut t = Transcript::new(b"qomm:waterfall:within");
        t.append_u64(b"k", index as u64);
        t
    }
    fn order_transcript(index: usize) -> Transcript {
        let mut t = Transcript::new(b"qomm:waterfall:order");
        t.append_u64(b"k", index as u64);
        t
    }
    fn shortfall_transcript() -> Transcript {
        Transcript::new(b"qomm:waterfall:shortfall")
    }
    fn balance_transcript() -> Transcript {
        Transcript::new(b"qomm:waterfall:balance")
    }

    /// Run where every tranche opening is known --- by the infrastructure.
    pub fn build<R: RngCore + CryptoRng>(
        &self,
        shortfall: u64,
        shortfall_blinding: &Scalar,
        balances: &[u64],
        blindings: &[Scalar],
        rng: &mut R,
    ) -> Result<(Resolution, Vec<u64>), &'static str> {
        if balances.len() != self.tranches.len() || blindings.len() != self.tranches.len() {
            return Err("one balance and one blinding per tranche");
        }
        if shortfall > balances.iter().sum::<u64>() {
            return Err("the shortfall exceeds what the waterfall holds");
        }
        let mut amounts = Vec::with_capacity(balances.len());
        let mut remaining = shortfall;
        for balance in balances {
            let take = (*balance).min(remaining);
            amounts.push(take);
            remaining -= take;
        }

        let mut draw_blindings: Vec<Scalar> =
            (0..amounts.len()).map(|_| Scalar::random(rng)).collect();
        // the last one absorbs the sum so the balance proof closes exactly
        let head: Scalar = draw_blindings[..draw_blindings.len() - 1].iter().sum();
        let last = draw_blindings.len() - 1;
        draw_blindings[last] = shortfall_blinding - head;

        let mut draws = Vec::with_capacity(amounts.len());
        let mut above: Option<(u64, Scalar)> = None;
        for (index, (amount, blinding)) in amounts.iter().zip(draw_blindings.iter()).enumerate() {
            let left = balances[index] - amount;
            let left_blinding = blindings[index] - blinding;
            let (within, within_commitments) = RangeProof::prove_multiple(
                &self.gens,
                &self.pc(),
                &mut Self::within_transcript(index),
                &[left],
                &[left_blinding],
                self.bits,
            )
            .map_err(|_| "a tranche is overdrawn")?;
            let ordering = above.map(|(above_value, above_blinding)| {
                prove_product(
                    &self.key,
                    &mut Self::order_transcript(index),
                    &self.key.commit_u64(above_value, &above_blinding),
                    &Scalar::from(above_value),
                    &above_blinding,
                    &Scalar::from(*amount),
                    blinding,
                    &Scalar::ZERO,
                    rng,
                )
            });
            draws.push(Draw {
                tranche: index,
                amount_commitment: self.key.commit_u64(*amount, blinding),
                within,
                within_commitment: within_commitments[0],
                ordering,
            });
            above = Some((left, left_blinding));
        }

        let (shortfall_range, shortfall_commitments) = RangeProof::prove_multiple(
            &self.gens,
            &self.pc(),
            &mut Self::shortfall_transcript(),
            &[shortfall],
            &[*shortfall_blinding],
            self.bits,
        )
        .map_err(|_| "the shortfall is not in range")?;
        let residual = self.key.commit_u64(shortfall, shortfall_blinding)
            - draws
                .iter()
                .map(|d| d.amount_commitment)
                .sum::<RistrettoPoint>();
        let balance = prove_opening(
            &self.key,
            &mut Self::balance_transcript(),
            &residual,
            &Scalar::ZERO,
            &Scalar::ZERO,
            rng,
        );
        Ok((
            Resolution {
                shortfall_commitment: self.key.commit_u64(shortfall, shortfall_blinding),
                shortfall_range,
                shortfall_range_commitment: shortfall_commitments[0],
                draws,
                balance,
            },
            amounts,
        ))
    }

    pub fn check<R: RngCore + CryptoRng>(
        &self,
        resolution: &Resolution,
        rng: &mut R,
    ) -> Result<(), &'static str> {
        if resolution.draws.len() != self.tranches.len() {
            return Err("one draw per tranche, present or zero");
        }
        if resolution.shortfall_range_commitment != resolution.shortfall_commitment.compress() {
            return Err("the shortfall range is about another commitment");
        }
        resolution
            .shortfall_range
            .verify_multiple(
                &self.gens,
                &self.pc(),
                &mut Self::shortfall_transcript(),
                std::slice::from_ref(&resolution.shortfall_range_commitment),
                self.bits,
            )
            .map_err(|_| "the shortfall is not shown to be a positive amount")?;

        let mut batch = Batch::new();
        let mut above: Option<RistrettoPoint> = None;
        for (index, draw) in resolution.draws.iter().enumerate() {
            if draw.tranche != index {
                return Err("the draws are not in tranche order");
            }
            let remaining = self.tranches[index].commitment - draw.amount_commitment;
            if draw.within_commitment != remaining.compress() {
                return Err("a tranche's range proof is about another commitment");
            }
            draw.within
                .verify_multiple(
                    &self.gens,
                    &self.pc(),
                    &mut Self::within_transcript(index),
                    std::slice::from_ref(&draw.within_commitment),
                    self.bits,
                )
                .map_err(|_| "a tranche is overdrawn")?;
            match (&draw.ordering, above) {
                (None, Some(_)) => return Err("a draw below the first tranche has no order proof"),
                (Some(proof), Some(above_commitment)) => {
                    let (s, p) = product_terms(
                        &self.key,
                        &mut Self::order_transcript(index),
                        &above_commitment,
                        &draw.amount_commitment,
                        &RistrettoPoint::identity(),
                        proof,
                        &Batch::weight(rng),
                    );
                    batch.push(s, p);
                }
                _ => {}
            }
            above = Some(remaining);
        }

        let residual = resolution.shortfall_commitment
            - resolution
                .draws
                .iter()
                .map(|d| d.amount_commitment)
                .sum::<RistrettoPoint>();
        let (s, p) = opening_terms(
            &self.key,
            &mut Self::balance_transcript(),
            &residual,
            &resolution.balance,
            &Batch::weight(rng),
        );
        batch.push(s, p);
        if !batch.verify() {
            return Err(
                "a tranche was drawn before the one above it was exhausted, \
                        or the draws do not add up to the shortfall",
            );
        }
        Ok(())
    }

    /// The tranches after the resolution, still committed.
    pub fn applied(&self, resolution: &Resolution) -> Vec<Tranche> {
        self.tranches
            .iter()
            .zip(resolution.draws.iter())
            .map(|(t, d)| Tranche {
                name: t.name.clone(),
                commitment: t.commitment - d.amount_commitment,
            })
            .collect()
    }
}

// --- collateral that is a security rather than an amount --------------------

/// A pledge whose value is derived rather than asserted.
///
/// `CreditLine` takes collateral already valued, which is fine when the pledge
/// is cash and wrong the moment it is a security: a member that supplies its own
/// valuation is underwriting itself. What makes a valuation somebody else's is
/// the **price** --- the quorum signs one in a payment instruction, and the same
/// product relation the cash leg of a settlement uses turns a quantity and that
/// price into a value without opening either.
///
/// So the object carries three commitments and the proof that binds them, and
/// the caller has to have checked that `price` is the commitment inside an
/// instruction the quorum signed. That check is `Venue::verify` and it is not
/// repeated here, because repeating it would mean holding the instruction and
/// this type is about the pledge.
pub struct ValuedCollateral {
    /// How much of the security is pledged.
    pub quantity: RistrettoPoint,
    /// The price the quorum signed, taken from an instruction's commitment.
    pub price: RistrettoPoint,
    /// quantity * price, which is what the haircut is applied to.
    pub value: RistrettoPoint,
    pub proof: ProductProof,
}

impl CreditCtx {
    /// Value a pledge at a price the member did not choose.
    ///
    /// Run by the member, which is the party that knows what it pledged. The
    /// price blinding comes from the instruction's openings, so a member cannot
    /// produce this for a price no quorum ever signed --- it would have to know
    /// the blinding of a commitment it did not make.
    #[allow(clippy::too_many_arguments)]
    pub fn value_pledge<R: RngCore + CryptoRng>(
        &self,
        quantity: u64,
        quantity_blinding: &Scalar,
        price: u64,
        price_blinding: &Scalar,
        value_blinding: &Scalar,
        signed_price_commitment: &RistrettoPoint,
        rng: &mut R,
    ) -> Result<(ValuedCollateral, u64), &'static str> {
        if self.key.commit_u64(price, price_blinding) != *signed_price_commitment {
            return Err("that is not the price the quorum signed");
        }
        let value = quantity
            .checked_mul(price)
            .ok_or("the valuation overflows")?;
        let mut t = Transcript::new(b"qomm:credit:valuation");
        let proof = prove_product(
            &self.key,
            &mut t,
            &self.key.commit_u64(quantity, quantity_blinding),
            &Scalar::from(quantity),
            quantity_blinding,
            &Scalar::from(price),
            price_blinding,
            value_blinding,
            rng,
        );
        Ok((
            ValuedCollateral {
                quantity: self.key.commit_u64(quantity, quantity_blinding),
                price: *signed_price_commitment,
                value: self.key.commit_u64(value, value_blinding),
                proof,
            },
            value,
        ))
    }

    /// That the value really is the quantity times the price the quorum signed.
    ///
    /// Nothing opens. What the infrastructure learns is the relation, which is
    /// the only thing it needs in order to be willing to lend against it.
    pub fn check_pledge(
        &self,
        pledge: &ValuedCollateral,
        signed_price_commitment: &RistrettoPoint,
    ) -> Result<(), &'static str> {
        if pledge.price != *signed_price_commitment {
            return Err("valued at a price other than the one the quorum signed");
        }
        let mut t = Transcript::new(b"qomm:credit:valuation");
        if verify_product(
            &self.key,
            &mut t,
            &pledge.quantity,
            &pledge.price,
            &pledge.value,
            &pledge.proof,
        ) {
            Ok(())
        } else {
            Err("the valuation does not hold")
        }
    }

    /// Grant against a pledge that was valued rather than declared.
    ///
    /// Identical to `grant` downstream of the valuation, which is the point:
    /// what changes is where the number came from, and that is exactly the part
    /// a member should not be trusted with.
    #[allow(clippy::too_many_arguments)]
    pub fn grant_against(
        &self,
        handle: &[u8],
        rail: &'static str,
        cap: u64,
        cap_blinding: &Scalar,
        pledge: &ValuedCollateral,
        value: u64,
        value_blinding: &Scalar,
        haircut_bp: u64,
        signed_price_commitment: &RistrettoPoint,
    ) -> Result<CreditLine, &'static str> {
        self.check_pledge(pledge, signed_price_commitment)?;
        if self.key.commit_u64(value, value_blinding) != pledge.value {
            return Err("the opening offered is not the value that was proved");
        }
        self.grant(
            handle,
            rail,
            cap,
            cap_blinding,
            value,
            value_blinding,
            haircut_bp,
        )
    }
}

// --- writing the tranches down ---------------------------------------------

/// The tranches as somebody holds them, and the resolutions already applied.
///
/// `Waterfall` proves and verifies and hands back what the tranches became;
/// writing that down was the caller's job and so, therefore, was noticing that
/// the same resolution had been applied twice. A default is resolved once.
pub struct TrancheBook {
    pub tranches: Vec<Tranche>,
    applied: std::collections::HashSet<[u8; 32]>,
}

/// What a resolution is identified by. Covers the shortfall and every draw, so
/// two resolutions of the same shortfall drawing differently are different.
pub fn resolution_id(resolution: &Resolution) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"QOMM:DEFMI:RESOLUTION:v1");
    hasher.update(resolution.shortfall_commitment.compress().as_bytes());
    for draw in &resolution.draws {
        hasher.update(draw.amount_commitment.compress().as_bytes());
    }
    hasher.finalize().into()
}

impl TrancheBook {
    pub fn new(tranches: Vec<Tranche>) -> Self {
        TrancheBook {
            tranches,
            applied: std::collections::HashSet::new(),
        }
    }

    pub fn applied_count(&self) -> usize {
        self.applied.len()
    }

    /// Check a resolution and write it down, once.
    ///
    /// The waterfall is rebuilt from the book's current tranches rather than
    /// from the ones the resolution was proved against, so a resolution proved
    /// against a fuller book does not verify here --- which is what stops a
    /// second default being absorbed by capital the first one already ate.
    pub fn apply<R: RngCore + CryptoRng>(
        &mut self,
        key: Pedersen,
        bits: usize,
        resolution: &Resolution,
        rng: &mut R,
    ) -> Result<(), &'static str> {
        let id = resolution_id(resolution);
        if self.applied.contains(&id) {
            return Err("this resolution has already been written down");
        }
        let waterfall = Waterfall::new(key, self.tranches.clone(), bits);
        waterfall.check(resolution, rng)?;
        self.tranches = waterfall.applied(resolution);
        self.applied.insert(id);
        Ok(())
    }
}
