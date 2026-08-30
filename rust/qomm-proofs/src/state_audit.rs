//! Zero-knowledge audit of a maker's *state update*, not only its policy.
//!
//! `policy_audit` shows the pricing rule is well formed. That covers the rule
//! and says nothing about what happens after a fill, which in a stateful
//! protocol is the larger half: a maker with an impeccable rule can still carry
//! a book that never moved when it should have, or that quietly grew past the
//! size it promised to stop at.
//!
//! Three things are proved per fill, without opening anything.
//!
//! - *arithmetic* — the new inventory is the old one less what was filled, as a
//!   linear relation over three commitments
//! - *containment* — the new inventory lies inside a limit that is itself
//!   committed, so the venue learns the promise was kept without learning
//!   either the promise or the position
//! - *continuity* — each step names the state it followed, so replaying an old
//!   state or running two books in parallel breaks the chain
//!
//! Containment needs a committed bound rather than a public one. A public band
//! would have to be wide enough for the largest maker on the venue, which makes
//! it vacuous for everyone else; a private limit holds a maker to the promise it
//! actually made. The bound is committed once and every later step proves
//! against that same commitment, so tightening it after a breach is not
//! available either.

use bulletproofs::RangeProof;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::range::RangeCtx;
use qomm_zk::sigma::{prove_linear, verify_linear, OpeningProof};
use rand_core::{CryptoRng, RngCore};

/// Inventory is signed, and a range proof is not, so the whole chain works on
/// `inventory + OFFSET` and proves containment on the two differences. The
/// offset is public and identical on both sides.
pub const WIDTH_BITS: usize = 32;

fn ceiling() -> u64 {
    (1u64 << (WIDTH_BITS - 1)) - 1
}

fn signed(value: i64) -> Scalar {
    if value < 0 {
        -Scalar::from(value.unsigned_abs())
    } else {
        Scalar::from(value as u64)
    }
}

/// The bound a maker commits to once, and is held to at every later step.
#[derive(Debug)]
pub struct InventoryLimit {
    pub commitment: RistrettoPoint,
    pub range: RangeProof,
    pub compressed: CompressedRistretto,
}

/// One link of the chain: the state left behind by one fill.
#[derive(Debug)]
pub struct StateStep {
    pub step: u64,
    /// Commitment to the inventory after the fill.
    pub inventory: RistrettoPoint,
    /// Commitment to the signed size that was filled.
    pub fill: RistrettoPoint,
    /// Encoding of the inventory this step started from.
    pub follows: [u8; 32],
    /// `new + filled - old == 0`
    pub arithmetic: OpeningProof,
    /// `limit - new >= 0`
    pub below_cap: RangeProof,
    pub below_commitment: CompressedRistretto,
    /// `limit + new >= 0`
    pub above_floor: RangeProof,
    pub above_commitment: CompressedRistretto,
}

pub struct StateAuditor {
    pub key: Pedersen,
    ranges: RangeCtx,
}

/// What a verifier can conclude when a chain does not check out. The three ways
/// it breaks call for different responses from the venue, and only the last is
/// evidence of equivocation, so they are kept apart rather than collapsed into
/// a boolean.
#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    LimitNotInRange,
    /// The state this step started from is not the state the circuit was fed.
    ///
    /// The gap this catches is the same one `BINDING.md` opens with, one level
    /// along: a maker could audit an impeccable inventory chain and hand the
    /// circuit a different inventory, and every proof in the chain would still
    /// verify. What closes it is not new cryptography --- it is requiring that
    /// the commitment a step follows *is* the commitment the input dealer
    /// published for that maker's inventory, which the dealer already publishes
    /// and nobody was comparing.
    NotTheDealtState {
        index: usize,
        step: u64,
    },
    /// A replayed or forked inventory: this step did not follow the one before.
    Forked {
        index: usize,
        step: u64,
    },
    Arithmetic {
        index: usize,
        step: u64,
    },
    Containment {
        index: usize,
        step: u64,
    },
}

impl Default for StateAuditor {
    fn default() -> Self {
        Self::new()
    }
}

impl StateAuditor {
    pub fn new() -> Self {
        StateAuditor {
            key: Pedersen::new(b"qomm:state:v1"),
            ranges: RangeCtx::new(WIDTH_BITS, 1),
        }
    }

    fn transcript(tag: &[u8]) -> Transcript {
        let mut t = Transcript::new(b"qomm:state:v1");
        t.append_message(b"tag", tag);
        t
    }

    // --- the limit, committed once --------------------------------------
    pub fn commit_limit(
        &self,
        limit: u64,
        blinding: &Scalar,
    ) -> Result<InventoryLimit, &'static str> {
        if limit > ceiling() {
            return Err("limit above the public ceiling");
        }
        let mut t = Self::transcript(b"limit");
        let (range, compressed) = self.ranges.prove(&mut t, &[limit], &[*blinding])?;
        Ok(InventoryLimit {
            commitment: self.key.commit(&Scalar::from(limit), blinding),
            range,
            compressed: compressed[0],
        })
    }

    pub fn check_limit(&self, limit: &InventoryLimit) -> bool {
        if limit.compressed != limit.commitment.compress() {
            return false;
        }
        let mut t = Self::transcript(b"limit");
        self.ranges
            .verify(&mut t, &limit.range, &[limit.compressed])
    }

    // --- one step --------------------------------------------------------
    /// `filled` is signed the way the maker's book moves: a maker that sold
    /// carries a negative position afterwards, so the new inventory is the old
    /// one *less* what left. Getting that sign backwards is the mistake this
    /// proof exists to make impossible to hide, so the relation below is
    /// written to match.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_update<R: RngCore + CryptoRng>(
        &self,
        step: u64,
        old_inventory: i64,
        old_blinding: &Scalar,
        filled: i64,
        fill_blinding: &Scalar,
        limit: u64,
        limit_blinding: &Scalar,
        new_blinding: &Scalar,
        rng: &mut R,
    ) -> Result<(StateStep, i64), &'static str> {
        let new_inventory = old_inventory - filled;
        if new_inventory.unsigned_abs() > limit {
            return Err("inventory breaks the committed limit; the maker cannot \
                        prove this step and must decline the fill");
        }

        let old_commitment = self.key.commit(&signed(old_inventory), old_blinding);
        let fill_commitment = self.key.commit(&signed(filled), fill_blinding);
        let new_commitment = self.key.commit(&signed(new_inventory), new_blinding);

        let tag = format!("step:{step}");
        let mut t = Self::transcript(tag.as_bytes());
        let arithmetic = prove_linear(
            &self.key,
            &mut t,
            &[new_commitment, fill_commitment, old_commitment],
            &[Scalar::ONE, Scalar::ONE, -Scalar::ONE],
            &[*new_blinding, *fill_blinding, *old_blinding],
            &Scalar::ZERO,
            rng,
        );

        // |inventory| <= limit, as two one-sided proofs on committed
        // differences. The commitment each proof covers is the difference of two
        // commitments the verifier already holds, so it is reconstructed rather
        // than sent.
        let mut sided = Vec::with_capacity(2);
        for (sign, suffix) in [(1i64, "below"), (-1i64, "above")] {
            let value = (limit as i64) - sign * new_inventory;
            debug_assert!(value >= 0);
            let blind = limit_blinding - signed(sign) * new_blinding;
            let mut t = Self::transcript(format!("{tag}:{suffix}").as_bytes());
            let (proof, compressed) = self.ranges.prove(&mut t, &[value as u64], &[blind])?;
            sided.push((proof, compressed[0]));
        }
        let (above_floor, above_commitment) = sided.pop().unwrap();
        let (below_cap, below_commitment) = sided.pop().unwrap();

        Ok((
            StateStep {
                step,
                inventory: new_commitment,
                fill: fill_commitment,
                follows: old_commitment.compress().to_bytes(),
                arithmetic,
                below_cap,
                below_commitment,
                above_floor,
                above_commitment,
            },
            new_inventory,
        ))
    }

    /// The venue's side. Nothing here needs an opening.
    pub fn verify_update(
        &self,
        step: &StateStep,
        old_commitment: &RistrettoPoint,
        limit: &InventoryLimit,
    ) -> bool {
        if old_commitment.compress().to_bytes() != step.follows {
            return false;
        }
        let tag = format!("step:{}", step.step);
        let mut t = Self::transcript(tag.as_bytes());
        if !verify_linear(
            &self.key,
            &mut t,
            &[step.inventory, step.fill, *old_commitment],
            &[Scalar::ONE, Scalar::ONE, -Scalar::ONE],
            &Scalar::ZERO,
            &step.arithmetic,
        ) {
            return false;
        }
        for (proof, compressed, sign, suffix) in [
            (
                &step.below_cap,
                &step.below_commitment,
                Scalar::ONE,
                "below",
            ),
            (
                &step.above_floor,
                &step.above_commitment,
                -Scalar::ONE,
                "above",
            ),
        ] {
            // The proof must be about limit - sign*inventory and nothing else.
            let expected = limit.commitment - step.inventory * sign;
            if *compressed != expected.compress() {
                return false;
            }
            let mut t = Self::transcript(format!("{tag}:{suffix}").as_bytes());
            if !self
                .ranges
                .verify(&mut t, proof, std::slice::from_ref(compressed))
            {
                return false;
            }
        }
        true
    }

    /// The same, and the state has to be the one the circuit computed on.
    ///
    /// `dealt[i]` is the commitment the input dealer published for this maker's
    /// inventory at step `i` --- the same object the transport binding produces
    /// for every value it deals. Without this the chain proves that
    /// *some* inventory moved correctly; with it, that the one the quote was
    /// priced from did.
    pub fn verify_update_bound(
        &self,
        step: &StateStep,
        old_commitment: &RistrettoPoint,
        limit: &InventoryLimit,
        dealt: &CompressedRistretto,
    ) -> bool {
        old_commitment.compress() == *dealt && self.verify_update(step, old_commitment, limit)
    }

    /// Walk the chain, requiring each step to start from the state that was dealt.
    pub fn verify_chain_bound(
        &self,
        opening: &RistrettoPoint,
        steps: &[StateStep],
        limit: &InventoryLimit,
        dealt: &[CompressedRistretto],
    ) -> Result<(), ChainError> {
        if dealt.len() != steps.len() {
            return Err(ChainError::NotTheDealtState { index: 0, step: 0 });
        }
        let mut previous = *opening;
        for (index, step) in steps.iter().enumerate() {
            if previous.compress() != dealt[index] {
                return Err(ChainError::NotTheDealtState {
                    index,
                    step: step.step,
                });
            }
            previous = step.inventory;
        }
        self.verify_chain(opening, steps, limit)
    }

    /// Walk the chain from a known opening state.
    pub fn verify_chain(
        &self,
        opening: &RistrettoPoint,
        steps: &[StateStep],
        limit: &InventoryLimit,
    ) -> Result<(), ChainError> {
        if !self.check_limit(limit) {
            return Err(ChainError::LimitNotInRange);
        }
        let mut current = *opening;
        for (index, step) in steps.iter().enumerate() {
            if current.compress().to_bytes() != step.follows {
                return Err(ChainError::Forked {
                    index,
                    step: step.step,
                });
            }
            if !self.verify_update(step, &current, limit) {
                // The arithmetic proof is checked first inside verify_update, so
                // distinguishing the two here means re-running the cheaper half.
                let tag = format!("step:{}", step.step);
                let mut t = Self::transcript(tag.as_bytes());
                let arithmetic_ok = verify_linear(
                    &self.key,
                    &mut t,
                    &[step.inventory, step.fill, current],
                    &[Scalar::ONE, Scalar::ONE, -Scalar::ONE],
                    &Scalar::ZERO,
                    &step.arithmetic,
                );
                return Err(if arithmetic_ok {
                    ChainError::Containment {
                        index,
                        step: step.step,
                    }
                } else {
                    ChainError::Arithmetic {
                        index,
                        step: step.step,
                    }
                });
            }
            current = step.inventory;
        }
        Ok(())
    }
}
