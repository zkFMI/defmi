//! Publicly verifiable proof that the opened quote is the correct one.
//!
//! Receipts bind a node to a result; they do not show the result is right. This
//! closes that gap for the quote circuit, without a general-purpose SNARK and
//! without a trusted setup, by proving the statement the circuit computes:
//!
//! > for each maker `i`, `key_i` is the committed policy applied to the
//! > committed request, and the opened winner is the smallest of those keys.
//!
//! Every step is a sigma protocol over Pedersen commitments, which matters
//! twice. Sigma responses are affine in the witness, so a quorum of computing
//! nodes can assemble the proof from shares without any of them holding it. And
//! the result is checked by an ordinary verifier with no setup.
//!
//! Per maker:
//!
//! ```text
//! depth_i = slope_i * qty              product proof
//! skew_i  = invcoef_i * inv_i          product proof
//! ask_i   = ask_level_i + depth_i + skew_i                linear, free
//! bid_i   = ask_level_i - spread_i - depth_i + skew_i     linear, free
//! fits_i  = maxqty_i - qty >= 0        range proof
//! fresh_i = expiry_i - now  >= 0       range proof
//! ok_i    is a bit, and gates the cost bit + product proofs
//! key_i   = cost_i * M + i             linear, free
//! ```
//!
//! and over the whole set: the winner's commitment opens to the revealed value,
//! and `key_i - v >= 0` for every `i`. Minimality plus membership is exactly
//! "v is the minimum", so an incorrect winner cannot be proved.
//!
//! One difference from the Python this replaces. Range proofs there were bit
//! decompositions at an arbitrary width; here they are Bulletproofs, which take
//! powers of two, so a declared width rounds up. Each maker's two eligibility
//! ranges share one aggregated proof, and so do the minimality ranges, which is
//! why the proof does not grow linearly the way the original did.

use bulletproofs::RangeProof as BulletproofRangeProof;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::range::RangeCtx;
use qomm_zk::sigma::{
    prove_bit, prove_opening, prove_product, verify_bit, verify_opening, verify_product, BitProof,
    OpeningProof, ProductProof,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::threshold_range::{verify_threshold_range, ThresholdRangeProof};

/// A maker's secret policy and state. Never leaves the maker or the quorum.
#[derive(Clone, Debug)]
pub struct MakerWitness {
    pub ask_level: i64,
    pub spread: i64,
    pub slope: i64,
    pub invcoef: i64,
    pub inv: i64,
    pub maxqty: i64,
    pub expiry: i64,
    pub active: bool,
    /// The blindings this policy was registered under.
    ///
    /// Without them the prover drew a fresh blinding for every field at proving
    /// time, so the minimum was taken over commitments it had just invented --
    /// true about those, and silent about whether they were the market's. A
    /// witness carrying none is a policy invented now, and `prove` refuses it.
    pub blindings: Registered,
}

impl MakerWitness {
    pub fn registered(&self, key: &Pedersen) -> RegisteredPolicy {
        RegisteredPolicy {
            ask_level: key.commit(&scalar(self.ask_level), &self.blindings.ask_level),
            spread: key.commit(&scalar(self.spread), &self.blindings.spread),
            slope: key.commit(&scalar(self.slope), &self.blindings.slope),
            invcoef: key.commit(&scalar(self.invcoef), &self.blindings.invcoef),
            inv: key.commit(&scalar(self.inv), &self.blindings.inv),
            maxqty: key.commit(&scalar(self.maxqty), &self.blindings.maxqty),
            expiry: key.commit(&scalar(self.expiry), &self.blindings.expiry),
            active: key.commit(
                &Scalar::from(u64::from(self.active)),
                &self.blindings.active,
            ),
        }
    }
}

/// One maker's registered blindings, in the order the fields are committed.
#[derive(Clone, Copy, Debug, Default)]
pub struct Registered {
    pub ask_level: Scalar,
    pub spread: Scalar,
    pub slope: Scalar,
    pub invcoef: Scalar,
    pub inv: Scalar,
    pub maxqty: Scalar,
    pub expiry: Scalar,
    pub active: Scalar,
}

impl Registered {
    pub fn fresh<R: RngCore + CryptoRng>(rng: &mut R) -> Registered {
        Registered {
            ask_level: Scalar::random(rng),
            spread: Scalar::random(rng),
            slope: Scalar::random(rng),
            invcoef: Scalar::random(rng),
            inv: Scalar::random(rng),
            maxqty: Scalar::random(rng),
            expiry: Scalar::random(rng),
            active: Scalar::random(rng),
        }
    }

    pub(crate) fn is_registered(&self) -> bool {
        ![
            self.ask_level,
            self.spread,
            self.slope,
            self.invcoef,
            self.inv,
            self.maxqty,
            self.expiry,
            self.active,
        ]
        .iter()
        .all(|s| *s == Scalar::ZERO)
    }
}

/// The commitments a maker put on the record before any request arrived.
#[derive(Clone, Copy, Debug)]
pub struct RegisteredPolicy {
    pub ask_level: RistrettoPoint,
    pub spread: RistrettoPoint,
    pub slope: RistrettoPoint,
    pub invcoef: RistrettoPoint,
    pub inv: RistrettoPoint,
    pub maxqty: RistrettoPoint,
    pub expiry: RistrettoPoint,
    pub active: RistrettoPoint,
}

impl RegisteredPolicy {
    fn parts(&self) -> [RistrettoPoint; 8] {
        [
            self.ask_level,
            self.spread,
            self.slope,
            self.invcoef,
            self.inv,
            self.maxqty,
            self.expiry,
            self.active,
        ]
    }
}

/// One digest over the whole eligible set, in order.
///
/// Fixing this in the statement is what makes maker *omission* visible: a
/// prover that drops a maker to change the winner has to publish a different
/// digest, and the digest was agreed before the request arrived.
pub fn registry_digest(registered: &[RegisteredPolicy]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"QOMM:QUOTE:REGISTRY:v1");
    hasher.update((registered.len() as u64).to_be_bytes());
    for policy in registered {
        for part in policy.parts() {
            hasher.update(part.compress().as_bytes());
        }
    }
    hasher.finalize().into()
}

/// The commitments a verifier needs to reconstruct one maker's statement.
#[derive(Clone, Debug)]
pub struct MakerCommitments {
    pub slope: RistrettoPoint,
    pub invcoef: RistrettoPoint,
    pub inv: RistrettoPoint,
    pub depth: RistrettoPoint,
    pub skew: RistrettoPoint,
    pub fits: RistrettoPoint,
    pub fresh: RistrettoPoint,
    pub active: RistrettoPoint,
    pub ok: RistrettoPoint,
    /// `expiry - now - 1`, which is what the freshness gate is about.
    pub fresh_strict: RistrettoPoint,
    /// `fits and fresh`, before `active` is folded in.
    pub both: RistrettoPoint,
    pub cost: RistrettoPoint,
    pub gated: RistrettoPoint,
    pub shifted_cost: RistrettoPoint,
}

/// A bit proof made either by one witness-holder or by a threshold quorum.
/// Both variants establish the same prime-field statement and are checked by
/// the same ordinary quote verifier.
#[derive(Debug)]
pub enum BitValidityProof {
    Disjunction(BitProof),
    Square(ProductProof),
}

/// The two eligibility witnesses. Bulletproofs aggregate them for the local
/// prover; a threshold prover keeps one shared bit-decomposition per witness.
#[derive(Debug)]
pub enum EligibilityProof {
    Bulletproof {
        proof: Box<BulletproofRangeProof>,
        commitments: Vec<CompressedRistretto>,
    },
    Threshold {
        fits: Box<ThresholdRangeProof>,
        fresh: Box<ThresholdRangeProof>,
    },
}

/// Minimality is aggregated on the local path and proved one shared difference
/// at a time on the threshold path.
#[derive(Debug)]
pub enum MinimalityProof {
    Bulletproof {
        proof: Box<BulletproofRangeProof>,
        commitments: Vec<CompressedRistretto>,
    },
    Threshold(Vec<ThresholdRangeProof>),
}

#[derive(Debug)]
pub struct MakerProof {
    pub depth: ProductProof,
    pub skew: ProductProof,
    pub gate_cost: ProductProof,
    /// One proof object covering both `fits` and `fresh`.
    pub eligibility: EligibilityProof,
    pub active_bit: BitValidityProof,
    /// The two `>= 0` tests, each a bit pinned to its difference.
    pub fits_gate: Gate,
    pub fresh_gate: Gate,
    /// `fits and fresh`, then `that and active`.
    pub conjunction: (ProductProof, ProductProof),
    pub commitments: MakerCommitments,
}

#[derive(Debug)]
pub struct QuoteProof {
    pub winner_index: usize,
    pub winner_value: u64,
    pub maker_proofs: Vec<MakerProof>,
    pub winner_opening: OpeningProof,
    /// Proof that every key is at least the winner's.
    pub minimality: MinimalityProof,
    pub key_commitments: Vec<RistrettoPoint>,
}

/// What the verifier is told in the clear.
#[derive(Clone, Debug)]
pub struct Public {
    pub qty_commitment: RistrettoPoint,
    pub now: i64,
    pub sentinel: i64,
    pub n_slots: i64,
    /// 0 = the user buys and pays the ask, 1 = the user sells and receives the bid.
    pub direction: u8,
    /// What the proof is *about*, as opposed to what it proves. Without these
    /// the statement said only "among the numbers I committed to, this is the
    /// smallest", which is true of any set the prover cares to invent.
    pub registry: Vec<RegisteredPolicy>,
    pub registry_digest: [u8; 32],
    pub market_digest: [u8; 32],
    pub slot: u64,
}

/// One `>= 0` test: the bit, what proves it, and the value the range covers.
#[derive(Debug)]
pub struct Gate {
    pub commitment: RistrettoPoint,
    pub bit_proof: BitValidityProof,
    pub product: ProductProof,
    pub product_commitment: RistrettoPoint,
    pub witness_commitment: RistrettoPoint,
}

struct GateWitness {
    holds: bool,
    blinding: Scalar,
    witness: i64,
    witness_blinding: Scalar,
}

pub struct QuoteCircuit {
    pub key: Pedersen,
    eligibility_bits: usize,
    span_bits: usize,
}

/// The narrowest width bulletproofs accepts that still holds `bits`.
fn bp_width(bits: usize) -> Option<usize> {
    [8usize, 16, 32, 64].into_iter().find(|w| *w >= bits)
}

pub(crate) fn scalar(value: i64) -> Scalar {
    if value < 0 {
        -Scalar::from(value.unsigned_abs())
    } else {
        Scalar::from(value as u64)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Invalid {
    /// A minimum over no makers has no winner and is not a quote.
    NoMakers,
    /// The proof vectors do not have the one shape fixed by the registry.
    Malformed(&'static str),
    /// Only buy (0) and sell (1) are statements understood by this circuit.
    Direction,
    /// Packed keys need one distinct low slot per registered maker.
    SlotCount,
    /// A witness with no registered blindings: a policy invented at proving time.
    Unregistered(usize),
    /// The statement's registry is not the one the proof is about.
    NotOnTheRegister(usize, &'static str),
    /// The digest does not cover the registry beside it.
    RegistryDigest,
    /// The statement registers a different number of makers than the proof covers.
    RegistrySize,
    Depth(usize),
    Skew(usize),
    Eligibility(usize),
    ActiveNotABit(usize),
    OkNotABit(usize),
    Cost(usize),
    ShiftedCost(usize),
    CostNotGated(usize),
    Key(usize),
    WinnerDoesNotOpen,
    NotMinimal,
}

impl Default for QuoteCircuit {
    fn default() -> Self {
        Self::new(32, 32)
    }
}

impl QuoteCircuit {
    /// `eligibility_bits` bounds the size and expiry margins; `span_bits` bounds
    /// how far a key can sit above the winner. Both round up to a power of two.
    pub fn new(eligibility_bits: usize, span_bits: usize) -> Self {
        Self::try_new(eligibility_bits, span_bits)
            .expect("quote widths must fit one 64-bit Bulletproof")
    }

    /// Checked constructor for widths supplied by configuration or a client.
    ///
    /// The eligibility gadget needs two more bits than the underlying margin.
    /// Silently mapping 65 bits back to a 64-bit proof would prove a different
    /// statement, so configuration at the boundary is rejected instead.
    pub fn try_new(eligibility_bits: usize, span_bits: usize) -> Result<Self, &'static str> {
        if eligibility_bits > 62 {
            return Err("eligibility width plus its two gadget bits exceeds 64");
        }
        if span_bits == 0 || span_bits > 64 {
            return Err("minimality span width must be between 1 and 64 bits");
        }
        Ok(QuoteCircuit {
            key: Pedersen::new(b"qomm:policy:v1"),
            eligibility_bits,
            span_bits,
        })
    }

    pub fn eligibility_bits(&self) -> usize {
        self.eligibility_bits
    }

    pub fn span_bits(&self) -> usize {
        self.span_bits
    }

    /// Bind every proof transcript to the complete public statement.
    ///
    /// The caller context alone names a venue, but not a request. Without this
    /// digest a proof produced for one direction, market epoch or slot can be
    /// presented under another one even if each local sigma equation remains
    /// true. Length-prefixing the caller context keeps framing unambiguous.
    pub(crate) fn statement_context(context: &[u8], public: &Public) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"QOMM:QUOTE:STATEMENT:v2");
        hasher.update((context.len() as u64).to_be_bytes());
        hasher.update(context);
        hasher.update(public.qty_commitment.compress().as_bytes());
        hasher.update(public.now.to_be_bytes());
        hasher.update(public.sentinel.to_be_bytes());
        hasher.update(public.n_slots.to_be_bytes());
        hasher.update([public.direction]);
        hasher.update(public.registry_digest);
        hasher.update(public.market_digest);
        hasher.update(public.slot.to_be_bytes());
        hasher.finalize().into()
    }

    /// A bit that is 1 exactly when the committed value is non-negative,
    /// together with the derived value a range proof has to cover.
    ///
    /// One product for `bit * value`, and `t = 2P - S + B - g`, which is
    /// non-negative when the bit is right and negative when it is not. Total in
    /// both directions, so an ineligible maker is representable rather than
    /// something the prover has to leave out.
    /// A byte context for the gate's own transcripts, distinct per maker and
    /// per test.
    pub(crate) fn gate_context(context: &[u8], index: usize, what: &[u8]) -> Vec<u8> {
        let mut out = context.to_vec();
        out.extend_from_slice(b":mm:");
        out.extend_from_slice(&(index as u64).to_be_bytes());
        out.extend_from_slice(b":");
        out.extend_from_slice(what);
        out
    }

    pub(crate) fn gate_range_context(context: &[u8], index: usize, what: &[u8]) -> Vec<u8> {
        let mut out = Self::gate_context(context, index, what);
        out.extend_from_slice(b":ge");
        out
    }

    pub(crate) fn minimality_context(context: &[u8], index: usize) -> Vec<u8> {
        let mut out = context.to_vec();
        out.extend_from_slice(b":min:");
        out.extend_from_slice(&(index as u64).to_be_bytes());
        out
    }

    fn ge_zero_bit<R: RngCore + CryptoRng>(
        &self,
        value: i64,
        blinding: &Scalar,
        commitment: &RistrettoPoint,
        context: &[u8],
        rng: &mut R,
    ) -> Result<(Gate, GateWitness), &'static str> {
        let key = &self.key;
        let holds = value >= 0;
        let bit = Scalar::from(u64::from(holds));
        let r_bit = Scalar::random(rng);
        let c_bit = key.commit(&bit, &r_bit);
        let mut t = Transcript::new(b"qomm:quote:gate:bit");
        t.append_message(b"ctx", context);
        let bit_proof =
            BitValidityProof::Disjunction(prove_bit(key, &mut t, &c_bit, holds, &r_bit, rng));

        let r_product = Scalar::random(rng);
        let mut t = Transcript::new(b"qomm:quote:gate:prod");
        t.append_message(b"ctx", context);
        let product = prove_product(
            key,
            &mut t,
            &c_bit,
            &bit,
            &r_bit,
            &scalar(value),
            blinding,
            &r_product,
            rng,
        );
        let product_value = if holds { value } else { 0 };
        let c_product = key.commit(&scalar(product_value), &r_product);

        let witness = product_value
            .checked_mul(2)
            .and_then(|v| v.checked_sub(value))
            .and_then(|v| v.checked_add(i64::from(holds)))
            .and_then(|v| v.checked_sub(1))
            .ok_or("eligibility witness overflow")?;
        let witness_blinding = r_product + r_product - blinding + r_bit;
        let c_witness =
            c_product + c_product - commitment + c_bit - key.commit(&Scalar::ONE, &Scalar::ZERO);
        Ok((
            Gate {
                commitment: c_bit,
                bit_proof,
                product,
                product_commitment: c_product,
                witness_commitment: c_witness,
            },
            GateWitness {
                holds,
                blinding: r_bit,
                witness,
                witness_blinding,
            },
        ))
    }

    /// The mirror of `ge_zero_bit`: one bit, one product, and the derived value
    /// the aggregated range proof has to be about.
    fn check_bit_proof(
        &self,
        commitment: &RistrettoPoint,
        proof: &BitValidityProof,
        transcript: &mut Transcript,
    ) -> bool {
        match proof {
            BitValidityProof::Disjunction(proof) => {
                verify_bit(&self.key, transcript, commitment, proof)
            }
            BitValidityProof::Square(proof) => verify_product(
                &self.key, transcript, commitment, commitment, commitment, proof,
            ),
        }
    }

    fn check_gate(&self, base: RistrettoPoint, gate: &Gate, context: &[u8]) -> bool {
        let key = &self.key;
        let mut t = Transcript::new(b"qomm:quote:gate:bit");
        t.append_message(b"ctx", context);
        if !self.check_bit_proof(&gate.commitment, &gate.bit_proof, &mut t) {
            return false;
        }
        let mut t = Transcript::new(b"qomm:quote:gate:prod");
        t.append_message(b"ctx", context);
        if !verify_product(
            key,
            &mut t,
            &gate.commitment,
            &base,
            &gate.product_commitment,
            &gate.product,
        ) {
            return false;
        }
        let derived = gate.product_commitment + gate.product_commitment - base + gate.commitment
            - key.commit(&Scalar::ONE, &Scalar::ZERO);
        derived.compress() == gate.witness_commitment.compress()
    }

    fn ranges(&self, bits: usize, count: usize) -> RangeCtx {
        RangeCtx::new(bits, count.next_power_of_two().max(1))
    }

    pub(crate) fn tag(context: &[u8], index: usize, part: &str) -> Transcript {
        let mut t = Transcript::new(b"qomm:quote:v1");
        t.append_message(b"ctx", context);
        t.append_u64(b"mm", index as u64);
        t.append_message(b"part", part.as_bytes());
        t
    }

    pub(crate) fn whole(context: &[u8], part: &str) -> Transcript {
        let mut t = Transcript::new(b"qomm:quote:v1");
        t.append_message(b"ctx", context);
        t.append_message(b"part", part.as_bytes());
        t
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove<R: RngCore + CryptoRng>(
        &self,
        makers: &[MakerWitness],
        qty: i64,
        direction: u8,
        now: i64,
        sentinel: i64,
        n_slots: i64,
        context: &[u8],
        rng: &mut R,
        market_digest: [u8; 32],
        slot: u64,
    ) -> Result<(QuoteProof, Public), &'static str> {
        let key = &self.key;
        if makers.is_empty() {
            return Err("a quote needs at least one registered maker");
        }
        if direction > 1 {
            return Err("direction must be 0 (buy) or 1 (sell)");
        }
        if n_slots <= 0
            || usize::try_from(n_slots)
                .ok()
                .is_none_or(|n| n < makers.len())
        {
            return Err("n_slots must provide a distinct low slot for every maker");
        }
        for maker in makers {
            if !maker.blindings.is_registered() {
                return Err("a maker has no registered blindings: a quote \
proof is about policies that were put on the record, and a witness without them \
is a policy invented now");
            }
        }
        let registry: Vec<RegisteredPolicy> = makers.iter().map(|m| m.registered(key)).collect();

        let r_qty = Scalar::random(rng);
        let c_qty = key.commit(&scalar(qty), &r_qty);

        let public = Public {
            qty_commitment: c_qty,
            now,
            sentinel,
            n_slots,
            direction,
            registry_digest: registry_digest(&registry),
            registry,
            market_digest,
            slot,
        };
        let proof_context = Self::statement_context(context, &public);

        let mut keys: Vec<u64> = Vec::with_capacity(makers.len());
        let mut key_blindings: Vec<Scalar> = Vec::with_capacity(makers.len());
        let mut key_commitments: Vec<RistrettoPoint> = Vec::with_capacity(makers.len());
        let mut maker_proofs: Vec<MakerProof> = Vec::with_capacity(makers.len());

        for (index, m) in makers.iter().enumerate() {
            let (r_slope, r_invcoef, r_inv) =
                (m.blindings.slope, m.blindings.invcoef, m.blindings.inv);
            let c_slope = key.commit(&scalar(m.slope), &r_slope);
            let c_invcoef = key.commit(&scalar(m.invcoef), &r_invcoef);
            let c_inv = key.commit(&scalar(m.inv), &r_inv);

            let r_depth = Scalar::random(rng);
            let depth = m.slope.checked_mul(qty).ok_or("depth overflow")?;
            let depth_proof = prove_product(
                key,
                &mut Self::tag(&proof_context, index, "depth"),
                &c_slope,
                &scalar(m.slope),
                &r_slope,
                &scalar(qty),
                &r_qty,
                &r_depth,
                rng,
            );

            let r_skew = Scalar::random(rng);
            let skew = m
                .invcoef
                .checked_mul(m.inv)
                .ok_or("inventory skew overflow")?;
            let skew_proof = prove_product(
                key,
                &mut Self::tag(&proof_context, index, "skew"),
                &c_invcoef,
                &scalar(m.invcoef),
                &r_invcoef,
                &scalar(m.inv),
                &r_inv,
                &r_skew,
                rng,
            );

            let (r_level, r_spread) = (m.blindings.ask_level, m.blindings.spread);
            let ask = m
                .ask_level
                .checked_add(depth)
                .and_then(|v| v.checked_add(skew))
                .ok_or("ask price overflow")?;
            let bid = m
                .ask_level
                .checked_sub(m.spread)
                .and_then(|v| v.checked_sub(depth))
                .and_then(|v| v.checked_add(skew))
                .ok_or("bid price overflow")?;
            let r_ask = r_level + r_depth + r_skew;
            let r_bid = r_level - r_spread - r_depth + r_skew;

            // Eligibility: both margins in one aggregated range proof.
            let (r_maxqty, r_expiry) = (m.blindings.maxqty, m.blindings.expiry);
            let fits = m.maxqty.checked_sub(qty).ok_or("size margin overflow")?;
            let fresh = m.expiry.checked_sub(now).ok_or("expiry margin overflow")?;
            let fresh_strict = fresh.checked_sub(1).ok_or("strict expiry overflow")?;
            // Eligibility, proved in both directions and multiplied out.
            //
            // This used to refuse an ineligible maker outright --- a negative
            // difference has no range proof --- so the only way to serve a
            // request was to gate the maker out before proving, which is
            // omission by another name and the register cannot see it. And the
            // `ok` bit was committed with a bit proof and tied to nothing, so
            // an *eligible* maker could be switched off for free.
            let r_fits = r_maxqty - r_qty;
            let c_fits = key.commit(&scalar(fits), &r_fits);
            // `expiry > now` is `expiry - now - 1 >= 0`, folded in here so one
            // gadget serves both tests
            let c_fresh = key.commit(&scalar(fresh), &r_expiry);
            let c_fresh_strict = c_fresh - key.commit(&Scalar::ONE, &Scalar::ZERO);

            let (fits_gate, fits_witness) = self.ge_zero_bit(
                fits,
                &r_fits,
                &c_fits,
                &Self::gate_context(&proof_context, index, b"fits"),
                rng,
            )?;
            let (fresh_gate, fresh_witness) = self.ge_zero_bit(
                fresh_strict,
                &r_expiry,
                &c_fresh_strict,
                &Self::gate_context(&proof_context, index, b"fresh"),
                rng,
            )?;

            // One aggregated range proof over the two derived values, as before
            // The derived value needs one more bit than the margin it is about,
            // and bulletproofs takes 8, 16, 32 or 64 --- so round up to the next
            // width it accepts rather than asking for one it does not.
            let ranges = self.ranges(
                bp_width(self.eligibility_bits + 2).ok_or("eligibility width exceeds 64")?,
                2,
            );
            let mut t = Self::tag(&proof_context, index, "eligibility");
            let (eligibility, eligibility_commitments) = ranges.prove(
                &mut t,
                &[fits_witness.witness as u64, fresh_witness.witness as u64],
                &[
                    fits_witness.witness_blinding,
                    fresh_witness.witness_blinding,
                ],
            )?;

            let r_active = m.blindings.active;
            let c_active = key.commit(&Scalar::from(u64::from(m.active)), &r_active);
            let active_bit = BitValidityProof::Disjunction(prove_bit(
                key,
                &mut Self::tag(&proof_context, index, "active"),
                &c_active,
                m.active,
                &r_active,
                rng,
            ));

            // ok = fits and fresh and active, as two products of proved bits,
            // so it is a bit by construction and has no freedom left
            let both = fits_witness.holds && fresh_witness.holds;
            let r_both = Scalar::random(rng);
            let c_both = key.commit(&Scalar::from(u64::from(both)), &r_both);
            let conj_first = prove_product(
                key,
                &mut Self::tag(&proof_context, index, "ok1"),
                &fits_gate.commitment,
                &Scalar::from(u64::from(fits_witness.holds)),
                &fits_witness.blinding,
                &Scalar::from(u64::from(fresh_witness.holds)),
                &fresh_witness.blinding,
                &r_both,
                rng,
            );

            let ok = both && m.active;
            let r_ok = Scalar::random(rng);
            let c_ok = key.commit(&Scalar::from(u64::from(ok)), &r_ok);
            let conj_second = prove_product(
                key,
                &mut Self::tag(&proof_context, index, "ok2"),
                &c_both,
                &Scalar::from(u64::from(both)),
                &r_both,
                &Scalar::from(u64::from(m.active)),
                &r_active,
                &r_ok,
                rng,
            );

            let cost = if direction == 1 {
                bid.checked_neg().ok_or("sell cost overflow")?
            } else {
                ask
            };
            let r_cost = if direction == 1 { -r_bid } else { r_ask };
            let c_cost = key.commit(&scalar(cost), &r_cost);

            // gated = ok * (cost - sentinel), so gated + sentinel is the
            // effective cost: an ineligible maker lands exactly on the sentinel
            // without the circuit branching on why.
            let r_gated = Scalar::random(rng);
            let shifted_cost = cost.checked_sub(sentinel).ok_or("shifted cost overflow")?;
            let c_shifted = key.commit(&scalar(shifted_cost), &r_cost);
            let gate_cost = prove_product(
                key,
                &mut Self::tag(&proof_context, index, "gate"),
                &c_ok,
                &Scalar::from(u64::from(ok)),
                &r_ok,
                &scalar(shifted_cost),
                &r_cost,
                &r_gated,
                rng,
            );
            let gated_value = if ok { shifted_cost } else { 0 };
            let c_gated = key.commit(&scalar(gated_value), &r_gated);

            let effective = gated_value
                .checked_add(sentinel)
                .ok_or("effective cost overflow")?;
            let packed = effective
                .checked_mul(n_slots)
                .and_then(|v| v.checked_add(i64::try_from(index).ok()?))
                .ok_or("packed key overflow")?;
            if packed < 0 {
                return Err("a packed key went negative; widen the sentinel");
            }
            let r_packed = r_gated * scalar(n_slots);
            keys.push(packed as u64);
            key_blindings.push(r_packed);
            key_commitments.push(key.commit(&Scalar::from(packed as u64), &r_packed));

            maker_proofs.push(MakerProof {
                depth: depth_proof,
                skew: skew_proof,
                gate_cost,
                eligibility: EligibilityProof::Bulletproof {
                    proof: Box::new(eligibility),
                    commitments: eligibility_commitments,
                },
                active_bit,
                fits_gate,
                fresh_gate,
                conjunction: (conj_first, conj_second),
                commitments: MakerCommitments {
                    slope: c_slope,
                    invcoef: c_invcoef,
                    inv: c_inv,
                    depth: key.commit(&scalar(depth), &r_depth),
                    skew: key.commit(&scalar(skew), &r_skew),
                    fits: c_fits,
                    fresh: c_fresh,
                    active: c_active,
                    ok: c_ok,
                    fresh_strict: c_fresh_strict,
                    both: c_both,
                    cost: c_cost,
                    gated: c_gated,
                    shifted_cost: c_shifted,
                },
            });
        }

        let winner = (0..keys.len())
            .min_by_key(|i| keys[*i])
            .ok_or("no makers")?;
        let value = keys[winner];
        // Bind the *published* number, not merely the commitment. An opening
        // proof shows knowledge of some opening and says nothing about which, so
        // proving the winner's commitment directly would leave the price a free
        // parameter: a venue could publish any figure and the proof would still
        // verify. Proving that C_winner - g^value is a pure power of h says the
        // commitment opens to this value and no other, at the same cost.
        let residual = key.shift(&key_commitments[winner], value);
        let winner_opening = prove_opening(
            key,
            &mut Self::whole(&proof_context, "winner"),
            &residual,
            &Scalar::ZERO,
            &key_blindings[winner],
            rng,
        );

        // Minimality: every key is at least the winner's, in one aggregated proof.
        let differences: Vec<u64> = keys.iter().map(|k| k - value).collect();
        let diff_blindings: Vec<Scalar> = key_blindings
            .iter()
            .map(|r| r - key_blindings[winner])
            .collect();
        let ranges = self.ranges(
            bp_width(self.span_bits).ok_or("minimality width exceeds 64")?,
            differences.len(),
        );
        let mut t = Self::whole(&proof_context, "minimality");
        let (minimality, minimality_commitments) =
            ranges.prove(&mut t, &differences, &diff_blindings)?;

        Ok((
            QuoteProof {
                winner_index: winner,
                winner_value: value,
                maker_proofs,
                winner_opening,
                minimality: MinimalityProof::Bulletproof {
                    proof: Box::new(minimality),
                    commitments: minimality_commitments,
                },
                key_commitments,
            },
            public,
        ))
    }

    pub fn verify(
        &self,
        proof: &QuoteProof,
        public: &Public,
        context: &[u8],
    ) -> Result<(), Invalid> {
        let key = &self.key;
        // What the statement has to say before any of it means anything. The
        // minimum below is over commitments; whose commitments they are is not
        // something the proof can establish, only something the statement can
        // name and the verifier can check.
        if public.registry.is_empty() {
            return Err(Invalid::NoMakers);
        }
        if public.direction > 1 {
            return Err(Invalid::Direction);
        }
        if public.n_slots <= 0
            || usize::try_from(public.n_slots)
                .ok()
                .is_none_or(|n| n < public.registry.len())
        {
            return Err(Invalid::SlotCount);
        }
        if public.registry.len() != proof.maker_proofs.len() {
            return Err(Invalid::RegistrySize);
        }
        if proof.key_commitments.len() != public.registry.len() {
            return Err(Invalid::Malformed(
                "one key commitment is required per maker",
            ));
        }
        if proof.winner_index >= public.registry.len() {
            return Err(Invalid::Malformed("winner index is outside the registry"));
        }
        if registry_digest(&public.registry) != public.registry_digest {
            return Err(Invalid::RegistryDigest);
        }
        let proof_context = Self::statement_context(context, public);
        for (index, (registered, maker)) in public
            .registry
            .iter()
            .zip(proof.maker_proofs.iter())
            .enumerate()
        {
            let c = &maker.commitments;
            for (name, on_record, in_proof) in [
                ("slope", registered.slope, c.slope),
                ("invcoef", registered.invcoef, c.invcoef),
                ("inv", registered.inv, c.inv),
                ("maxqty", registered.maxqty, c.fits + public.qty_commitment),
                (
                    "expiry",
                    registered.expiry,
                    c.fresh_strict
                        + key.commit(&scalar(public.now), &Scalar::ZERO)
                        + key.commit(&Scalar::ONE, &Scalar::ZERO),
                ),
                ("active", registered.active, c.active),
            ] {
                if on_record.compress() != in_proof.compress() {
                    return Err(Invalid::NotOnTheRegister(index, name));
                }
            }
        }
        for (index, maker) in proof.maker_proofs.iter().enumerate() {
            let c = &maker.commitments;
            if !verify_product(
                key,
                &mut Self::tag(&proof_context, index, "depth"),
                &c.slope,
                &public.qty_commitment,
                &c.depth,
                &maker.depth,
            ) {
                return Err(Invalid::Depth(index));
            }
            if !verify_product(
                key,
                &mut Self::tag(&proof_context, index, "skew"),
                &c.invcoef,
                &c.inv,
                &c.skew,
                &maker.skew,
            ) {
                return Err(Invalid::Skew(index));
            }
            // The aggregate must cover the two derived values the gates are
            // about --- `2P - S + B - g` for each test --- and not the raw
            // margins, which are no longer what is shown non-negative.
            let expected = [
                maker.fits_gate.witness_commitment.compress(),
                maker.fresh_gate.witness_commitment.compress(),
            ];
            match &maker.eligibility {
                EligibilityProof::Bulletproof { proof, commitments } => {
                    if commitments.len() != 2 {
                        return Err(Invalid::Malformed(
                            "each eligibility proof must carry exactly two commitments",
                        ));
                    }
                    if commitments[..] != expected {
                        return Err(Invalid::Eligibility(index));
                    }
                    let ranges = self.ranges(
                        bp_width(self.eligibility_bits + 2)
                            .expect("constructor keeps eligibility width within 64 bits"),
                        2,
                    );
                    let mut t = Self::tag(&proof_context, index, "eligibility");
                    if !ranges.verify(&mut t, proof, commitments) {
                        return Err(Invalid::Eligibility(index));
                    }
                }
                EligibilityProof::Threshold { fits, fresh } => {
                    if fits.bits != self.eligibility_bits + 2
                        || fresh.bits != self.eligibility_bits + 2
                    {
                        return Err(Invalid::Eligibility(index));
                    }
                    if !verify_threshold_range(
                        key,
                        &maker.fits_gate.witness_commitment,
                        fits,
                        &Self::gate_range_context(&proof_context, index, b"fits"),
                    ) || !verify_threshold_range(
                        key,
                        &maker.fresh_gate.witness_commitment,
                        fresh,
                        &Self::gate_range_context(&proof_context, index, b"fresh"),
                    ) {
                        return Err(Invalid::Eligibility(index));
                    }
                }
            }
            let mut active_transcript = Self::tag(&proof_context, index, "active");
            if !self.check_bit_proof(&c.active, &maker.active_bit, &mut active_transcript) {
                return Err(Invalid::ActiveNotABit(index));
            }
            // Eligibility is the conjunction, checked rather than committed.
            // The two differences are derived here from the register, the
            // request and the clock, because a prover that picks what it proves
            // eligibility about picks the answer.
            let registered = &public.registry[index];
            let derived_fits = registered.maxqty - public.qty_commitment;
            if derived_fits.compress() != c.fits.compress() {
                return Err(Invalid::NotOnTheRegister(index, "fits"));
            }
            let derived_fresh = registered.expiry
                - key.commit(&scalar(public.now), &Scalar::ZERO)
                - key.commit(&Scalar::ONE, &Scalar::ZERO);
            if derived_fresh.compress() != c.fresh_strict.compress() {
                return Err(Invalid::NotOnTheRegister(index, "fresh"));
            }
            for (what, base, gate) in [
                (b"fits".as_ref(), c.fits, &maker.fits_gate),
                (b"fresh".as_ref(), c.fresh_strict, &maker.fresh_gate),
            ] {
                if !self.check_gate(base, gate, &Self::gate_context(&proof_context, index, what)) {
                    return Err(Invalid::Eligibility(index));
                }
            }
            let (first, second) = &maker.conjunction;
            let mut t = Self::tag(&proof_context, index, "ok1");
            if !verify_product(
                key,
                &mut t,
                &maker.fits_gate.commitment,
                &maker.fresh_gate.commitment,
                &c.both,
                first,
            ) {
                return Err(Invalid::Eligibility(index));
            }
            let mut t = Self::tag(&proof_context, index, "ok2");
            if !verify_product(key, &mut t, &c.both, &c.active, &c.ok, second) {
                return Err(Invalid::Eligibility(index));
            }
            let ask = registered.ask_level + c.depth + c.skew;
            let bid = registered.ask_level - registered.spread - c.depth + c.skew;
            let derived_cost = if public.direction == 1 { -bid } else { ask };
            if derived_cost.compress() != c.cost.compress() {
                return Err(Invalid::Cost(index));
            }
            let derived_shifted = c.cost - key.commit(&scalar(public.sentinel), &Scalar::ZERO);
            if derived_shifted.compress() != c.shifted_cost.compress() {
                return Err(Invalid::ShiftedCost(index));
            }
            if !verify_product(
                key,
                &mut Self::tag(&proof_context, index, "gate"),
                &c.ok,
                &c.shifted_cost,
                &c.gated,
                &maker.gate_cost,
            ) {
                return Err(Invalid::CostNotGated(index));
            }
            let derived_key = (c.gated + key.commit(&scalar(public.sentinel), &Scalar::ZERO))
                * scalar(public.n_slots)
                + key.commit(&Scalar::from(index as u64), &Scalar::ZERO);
            if derived_key.compress() != proof.key_commitments[index].compress() {
                return Err(Invalid::Key(index));
            }
        }

        // Reconstructed from the published value, so a proof made for one price
        // does not carry to another.
        let residual = key.shift(
            &proof.key_commitments[proof.winner_index],
            proof.winner_value,
        );
        if !verify_opening(
            key,
            &mut Self::whole(&proof_context, "winner"),
            &residual,
            &proof.winner_opening,
        ) {
            return Err(Invalid::WinnerDoesNotOpen);
        }

        let winner = proof.key_commitments[proof.winner_index];
        match &proof.minimality {
            MinimalityProof::Bulletproof {
                proof: range_proof,
                commitments,
            } => {
                let expected: Vec<CompressedRistretto> = proof
                    .key_commitments
                    .iter()
                    .map(|c| (c - winner).compress())
                    .collect();
                let padded = expected.len().next_power_of_two();
                let mut padded_expected = expected;
                padded_expected.resize(padded, RistrettoPoint::identity().compress());
                if *commitments != padded_expected {
                    return Err(Invalid::NotMinimal);
                }
                let ranges = self.ranges(
                    bp_width(self.span_bits).expect("constructor keeps span width within 64 bits"),
                    proof.key_commitments.len(),
                );
                let mut t = Self::whole(&proof_context, "minimality");
                if !ranges.verify(&mut t, range_proof, commitments) {
                    return Err(Invalid::NotMinimal);
                }
            }
            MinimalityProof::Threshold(proofs) => {
                if proofs.len() != proof.key_commitments.len() {
                    return Err(Invalid::Malformed(
                        "one minimality proof is required per maker",
                    ));
                }
                for (index, (commitment, range)) in
                    proof.key_commitments.iter().zip(proofs).enumerate()
                {
                    if range.bits != self.span_bits
                        || !verify_threshold_range(
                            key,
                            &(commitment - winner),
                            range,
                            &Self::minimality_context(&proof_context, index),
                        )
                    {
                        return Err(Invalid::NotMinimal);
                    }
                }
            }
        }
        Ok(())
    }
}
