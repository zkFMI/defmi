//! Netting cycles: gross-gross, gross-net, net-net, and net-net attested.
//!
//! A rail is either gross or net, and that single distinction carries
//! everything. A **gross** rail checks each order as it arrives, so settlement
//! failure cannot happen, at the price of order-sensitivity: a participant due
//! to receive a hundred and deliver a hundred is refused if the delivery
//! arrives first, which is exactly the liquidity benefit netting exists to
//! provide, given up on purpose. A **net** rail accumulates with no proof at
//! all --- a commitment hides a value's sign as readily as its magnitude, so an
//! intermediate position may be negative without anything leaking --- and one
//! range proof per participant at the close establishes that the net is
//! covered.
//!
//! Measuring the first knob is what exposed the second. Netting the rails saves
//! only the per-order cover proof, because every order still carries an
//! instruction the settlement layer verifies, and that does not net. What does
//! net is the instruction: a cycle run against one quorum attestation over the
//! closing positions stops depending on the number of trades at all. The saving
//! is real but it is not free --- the split between participants becomes
//! attested rather than verified, which is the bargain a central counterparty
//! represents, made explicit.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use merlin::Transcript;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::{
    product_terms, prove_product, prove_same_value, same_value_terms, Batch, CrossGeneratorProof,
    ProductProof,
};
use qomm_zkpi::{Instruction, Venue};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::assets::BlindedTag;
use crate::credit::{CreditCtx, CreditLine};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// BIS DVP model 1.
    GrossGross,
    /// Model 2: securities gross, cash net.
    GrossNet,
    /// Model 3.
    NetNet,
}

impl Mode {
    pub fn securities_net(&self) -> bool {
        *self == Mode::NetNet
    }
    pub fn cash_net(&self) -> bool {
        *self != Mode::GrossGross
    }
    pub fn label(&self) -> &'static str {
        match self {
            Mode::GrossGross => "gross-gross",
            Mode::GrossNet => "gross-net",
            Mode::NetNet => "net-net",
        }
    }
}

/// One rail's movement: one delta, one payer, one payee.
///
/// Deliberately not a pair of independent debit and credit records. With one
/// delta there is no way for the two sides to disagree, so conservation holds
/// by construction rather than by a check that could be forgotten.
pub struct Leg {
    pub payer: Vec<u8>,
    pub payee: Vec<u8>,
    pub delta: RistrettoPoint,
    pub delta_link: CrossGeneratorProof,
    /// Present only on a gross rail. The payer's new position is never sent:
    /// the book derives it as old/delta and checks the proof against that.
    pub cover: Option<(RangeProof, CompressedRistretto)>,
}

pub struct Order {
    pub instruction: Instruction,
    pub securities: Leg,
    pub cash: Leg,
    /// A commitment to quantity times price under the base generator, with
    /// `value_proof` relating it to the factors the quorum signed. The
    /// instruction commits to the factors, never to the product.
    pub cash_reference: RistrettoPoint,
    pub value_proof: ProductProof,
}

pub struct Coverage {
    pub handle: Vec<u8>,
    pub proof: RangeProof,
    pub commitment: CompressedRistretto,
}

/// The quorum standing behind a whole cycle instead of each trade in it.
///
/// It carried a digest and nothing else, so anyone could compute the digest of
/// a cycle they had built and hand it back as the quorum's word: "attested"
/// meant "the number matches the number", which is an identity rather than a
/// claim. It carries the quorum's signature over that digest now, and `close`
/// checks it against the key the cycle was opened with.
pub struct BatchAttestation {
    pub digest: [u8; 32],
    pub signature: Signature,
}

impl BatchAttestation {
    /// What the quorum signs. Domain-separated, because a bare digest signed
    /// somewhere else would verify here.
    pub fn body(digest: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 24);
        out.extend_from_slice(b"QOMM:DEFMI:BATCH-ATTESTATION:v1");
        out.extend_from_slice(digest);
        out
    }

    pub fn sign(key: &SigningKey, digest: [u8; 32]) -> Self {
        BatchAttestation {
            digest,
            signature: key.sign(&Self::body(&digest)),
        }
    }
}

pub struct PositionBook {
    pub key: Pedersen,
    pub tag: BlindedTag,
    pub net: bool,
    pub rail: &'static str,
    pub bits: usize,
    gens: BulletproofGens,
    positions: BTreeMap<Vec<u8>, RistrettoPoint>,
    opening: BTreeMap<Vec<u8>, RistrettoPoint>,
    pub credit: BTreeMap<Vec<u8>, CreditLine>,
}

impl PositionBook {
    /// `bits` is the width of the cover and coverage range proofs. Bulletproofs
    /// wants a power of two no wider than 64; anything else is refused here
    /// rather than left to produce a proof nothing verifies.
    pub fn new(key: Pedersen, tag: BlindedTag, net: bool, rail: &'static str, bits: usize) -> Self {
        assert!(
            matches!(bits, 8 | 16 | 32 | 64),
            "a range proof width of {bits} is not one bulletproofs accepts"
        );
        PositionBook {
            gens: BulletproofGens::new(bits, 1),
            key,
            tag,
            net,
            rail,
            bits,
            positions: BTreeMap::new(),
            opening: BTreeMap::new(),
            credit: BTreeMap::new(),
        }
    }

    pub fn tagged(&self) -> Pedersen {
        self.tag.key_for(&self.key)
    }
    fn pc(&self) -> PedersenGens {
        self.tag.gens(&self.key)
    }

    /// Record a handle's opening position. Once per handle per cycle.
    ///
    /// It used to overwrite, which let a caller rebase a book after trades had
    /// been admitted: reopen every handle at whatever the trades produced and
    /// the conservation check --- which compares the close against the opening
    /// --- passes on any state at all. The opening is the thing conservation is
    /// measured against, so it has to be fixed before anything moves.
    pub fn open(&mut self, handle: &[u8], commitment: RistrettoPoint) -> Result<(), &'static str> {
        if self.opening.contains_key(handle) {
            return Err("that handle is already open in this book");
        }
        self.positions.insert(handle.to_vec(), commitment);
        self.opening.insert(handle.to_vec(), commitment);
        Ok(())
    }

    pub fn balance(&self, handle: &[u8]) -> Option<&RistrettoPoint> {
        self.positions.get(handle)
    }

    pub fn handles(&self) -> Vec<Vec<u8>> {
        self.positions.keys().cloned().collect()
    }

    /// Underwrite a net debit cap the infrastructure cannot see. Committing it
    /// rather than publishing it hides its size and also removes the sign from
    /// every coverage proof that follows.
    pub fn grant(&mut self, ctx: &CreditCtx, line: CreditLine) -> Result<(), &'static str> {
        if !self.positions.contains_key(&line.handle) {
            return Err("unknown position handle");
        }
        if line.rail != self.rail {
            return Err("a cap for another rail does not relax this one");
        }
        ctx.check(&line)?;
        self.credit.insert(line.handle.clone(), line);
        Ok(())
    }

    fn cap(&self, handle: &[u8]) -> RistrettoPoint {
        self.credit
            .get(handle)
            .map(|l| l.cap_commitment)
            .unwrap_or_else(RistrettoPoint::identity)
    }

    fn cover_transcript(&self, payer: &[u8]) -> Transcript {
        let mut t = Transcript::new(b"qomm:cycle:cover");
        t.append_message(b"rail", self.rail.as_bytes());
        t.append_message(b"payer", payer);
        t
    }

    fn close_transcript(&self, handle: &[u8]) -> Transcript {
        let mut t = Transcript::new(b"qomm:cycle:close");
        t.append_message(b"rail", self.rail.as_bytes());
        t.append_message(b"handle", handle);
        t
    }

    fn link_transcript(&self) -> Transcript {
        let mut t = Transcript::new(b"qomm:cycle:link");
        t.append_message(b"rail", self.rail.as_bytes());
        t
    }

    /// Run by the payer, the only party that knows its position.
    #[allow(clippy::too_many_arguments)]
    pub fn build_leg<R: RngCore + CryptoRng>(
        &self,
        payer: &[u8],
        payee: &[u8],
        amount: u64,
        blinding: &Scalar,
        position_value: i64,
        position_blinding: &Scalar,
        reference: &RistrettoPoint,
        reference_blinding: &Scalar,
        cap_value: u64,
        cap_blinding: &Scalar,
        rng: &mut R,
    ) -> Result<Leg, &'static str> {
        let tagged = self.tagged();
        let delta = tagged.commit_u64(amount, blinding);
        let delta_link = prove_same_value(
            &self.key,
            &mut self.link_transcript(),
            &tagged.g,
            &self.key.g,
            &delta,
            reference,
            &Scalar::from(amount),
            blinding,
            reference_blinding,
            rng,
        );

        let cover = if self.net {
            None
        } else {
            // In `i128`, because the inputs are a signed 64-bit position and two
            // unsigned 64-bit amounts: their sum does not fit an `i64`, and in a
            // release build the wrap is silent. A wrapped headroom is a proof
            // that the position is covered when it is not.
            let headroom = position_value as i128 - amount as i128 + cap_value as i128;
            if headroom < 0 {
                return Err("the order would leave the position short of its cap");
            }
            if headroom >= 1i128 << self.bits {
                return Err("the headroom is beyond the range the cover proof covers");
            }
            let headroom_blinding = position_blinding - blinding + cap_blinding;
            let (proof, commitments) = RangeProof::prove_multiple(
                &self.gens,
                &self.pc(),
                &mut self.cover_transcript(payer),
                &[headroom as u64],
                &[headroom_blinding],
                self.bits,
            )
            .map_err(|_| "the cover proof failed")?;
            Some((proof, commitments[0]))
        };
        Ok(Leg {
            payer: payer.to_vec(),
            payee: payee.to_vec(),
            delta,
            delta_link,
            cover,
        })
    }

    pub fn check(
        &self,
        leg: &Leg,
        reference: &RistrettoPoint,
        batch: &mut Batch,
        weight: &Scalar,
    ) -> Result<(), &'static str> {
        for handle in [&leg.payer, &leg.payee] {
            if !self.positions.contains_key(handle) {
                return Err("unknown position handle");
            }
        }
        if leg.payer == leg.payee {
            return Err("a leg cannot pay itself");
        }
        let tagged = self.tagged();
        let (s, p) = same_value_terms(
            &self.key,
            &mut self.link_transcript(),
            &tagged.g,
            &self.key.g,
            &leg.delta,
            reference,
            &leg.delta_link,
            weight,
        );
        batch.push(s, p);

        match (&leg.cover, self.net) {
            (Some(_), true) => return Err("a net rail must not carry a per-order cover proof"),
            (None, false) => return Err("a gross rail needs a cover proof on every leg"),
            (Some((proof, commitment)), false) => {
                let expected = self.positions[&leg.payer] - leg.delta + self.cap(&leg.payer);
                if *commitment != expected.compress() {
                    return Err("the cover proof is about another position");
                }
                proof
                    .verify_multiple(
                        &self.gens,
                        &self.pc(),
                        &mut self.cover_transcript(&leg.payer),
                        std::slice::from_ref(commitment),
                        self.bits,
                    )
                    .map_err(|_| "the order would leave the position short of its cap")?;
            }
            (None, true) => {}
        }
        Ok(())
    }

    pub fn apply(&mut self, leg: &Leg) {
        let payer = self.positions[&leg.payer] - leg.delta;
        let payee = self.positions[&leg.payee] + leg.delta;
        self.positions.insert(leg.payer.clone(), payer);
        self.positions.insert(leg.payee.clone(), payee);
    }

    pub fn build_coverage(
        &self,
        handle: &[u8],
        value: i64,
        blinding: &Scalar,
        cap_value: u64,
        cap_blinding: &Scalar,
    ) -> Result<Coverage, &'static str> {
        let headroom = value as i128 + cap_value as i128;
        if headroom < 0 {
            return Err("the net position is short of its cap at the close; \
                        the cycle goes to the waterfall");
        }
        if headroom >= 1i128 << self.bits {
            return Err("the headroom is beyond the range the coverage proof covers");
        }
        let (proof, commitments) = RangeProof::prove_multiple(
            &self.gens,
            &self.pc(),
            &mut self.close_transcript(handle),
            &[headroom as u64],
            &[blinding + cap_blinding],
            self.bits,
        )
        .map_err(|_| "the coverage proof failed")?;
        Ok(Coverage {
            handle: handle.to_vec(),
            proof,
            commitment: commitments[0],
        })
    }

    pub fn check_coverage(&self, coverage: &Coverage) -> Result<(), &'static str> {
        let position = self
            .positions
            .get(&coverage.handle)
            .ok_or("unknown position handle")?;
        let expected = position + self.cap(&coverage.handle);
        if coverage.commitment != expected.compress() {
            return Err("the coverage proof is about another position");
        }
        coverage
            .proof
            .verify_multiple(
                &self.gens,
                &self.pc(),
                &mut self.close_transcript(&coverage.handle),
                std::slice::from_ref(&coverage.commitment),
                self.bits,
            )
            .map_err(|_| "the net position is not covered, even against its cap")
    }

    /// No proof and no opening: the two products simply have to agree.
    pub fn conserved(&self) -> bool {
        self.positions.values().sum::<RistrettoPoint>()
            == self.opening.values().sum::<RistrettoPoint>()
    }

    pub fn snapshot(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"QOMM:DEFMI:CYCLE:v1");
        hasher.update(self.rail.as_bytes());
        for (handle, position) in &self.positions {
            hasher.update((handle.len() as u32).to_be_bytes());
            hasher.update(handle);
            hasher.update(position.compress().as_bytes());
        }
        hasher.finalize().into()
    }
}

pub struct Cycle {
    pub key: Pedersen,
    /// Which cycle this is --- a date, a session, whatever the operator counts
    /// in. It goes into the batch digest, because without it the digest names a
    /// state rather than a cycle and the quorum's word about one cycle is its
    /// word about every cycle that ends in the same place.
    pub id: Vec<u8>,
    pub mode: Mode,
    pub attest_batch: bool,
    pub securities: PositionBook,
    pub cash: PositionBook,
    pub venue: Venue,
    /// The key an attested cycle's batch attestation must verify under. `None`
    /// on an unattested cycle, where every trade carries its own instruction.
    pub quorum: Option<VerifyingKey>,
    pub admitted: usize,
    pub refused: usize,
    closed: bool,
}

fn value_transcript() -> Transcript {
    Transcript::new(b"qomm:cycle:value")
}

impl Cycle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: Pedersen,
        id: Vec<u8>,
        mode: Mode,
        securities: PositionBook,
        cash: PositionBook,
        venue: Venue,
        attest_batch: bool,
        quorum: Option<VerifyingKey>,
    ) -> Result<Self, &'static str> {
        if id.is_empty() {
            return Err("a cycle needs an identity; an attestation over an \
                        anonymous cycle settles any cycle that ends the same way");
        }
        if attest_batch && mode != Mode::NetNet {
            return Err("a batch attestation replaces the per-trade instruction, \
                        which only makes sense when both rails are netted");
        }
        // The mode is what the cycle is called and `book.net` is what it does.
        // Nothing held them together, so a cycle labelled gross-gross could be
        // built from netted books --- and then it allows an intermediate
        // negative position and demands coverage at the close, which is the
        // opposite of what "gross" promises.
        let (securities_net, cash_net) = match mode {
            Mode::GrossGross => (false, false),
            Mode::GrossNet => (false, true),
            Mode::NetNet => (true, true),
        };
        if securities.net != securities_net || cash.net != cash_net {
            return Err("the mode and the books disagree about which rail nets");
        }
        if attest_batch && quorum.is_none() {
            return Err("an attested cycle needs the key its attestation verifies \
                        under; without one the attestation is a digest anybody \
                        can compute");
        }
        Ok(Cycle {
            key,
            id,
            mode,
            attest_batch,
            securities,
            cash,
            venue,
            quorum,
            admitted: 0,
            refused: 0,
            closed: false,
        })
    }

    /// Verify and apply, or refuse and change nothing.
    pub fn admit<R: RngCore + CryptoRng>(
        &mut self,
        order: &Order,
        now: u64,
        rng: &mut R,
    ) -> Result<(), &'static str> {
        if self.closed {
            return Err("the cycle is closed");
        }
        if self.attest_batch {
            return self.accumulate(order);
        }
        if let Err(reason) = self.venue.verify(&order.instruction, now) {
            self.refused += 1;
            return Err(reason);
        }
        let mut batch = Batch::new();
        let (s, p) = product_terms(
            &self.key,
            &mut value_transcript(),
            &order.instruction.price_commitment,
            &order.instruction.amount_commitment,
            &order.cash_reference,
            &order.value_proof,
            &Batch::weight(rng),
        );
        batch.push(s, p);
        if let Err(reason) = self.securities.check(
            &order.securities,
            &order.instruction.amount_commitment,
            &mut batch,
            &Batch::weight(rng),
        ) {
            self.refused += 1;
            return Err(reason);
        }
        if let Err(reason) = self.cash.check(
            &order.cash,
            &order.cash_reference,
            &mut batch,
            &Batch::weight(rng),
        ) {
            self.refused += 1;
            return Err(reason);
        }
        if !batch.verify() {
            self.refused += 1;
            return Err("the legs do not match what the instruction says");
        }
        self.securities.apply(&order.securities);
        self.cash.apply(&order.cash);
        self.venue.settle(&order.instruction, now)?;
        self.admitted += 1;
        Ok(())
    }

    /// Apply without verifying, because the batch will be attested. Handles and
    /// self-payment are still checked: they cost nothing, and a malformed cycle
    /// is not something an attestation should be able to authorise.
    fn accumulate(&mut self, order: &Order) -> Result<(), &'static str> {
        for (book, leg) in [
            (&self.securities, &order.securities),
            (&self.cash, &order.cash),
        ] {
            for handle in [&leg.payer, &leg.payee] {
                if book.balance(handle).is_none() {
                    return Err("unknown position handle");
                }
            }
            if leg.payer == leg.payee {
                return Err("a leg cannot pay itself");
            }
        }
        self.securities.apply(&order.securities);
        self.cash.apply(&order.cash);
        self.admitted += 1;
        Ok(())
    }

    /// What an attestation signs: which cycle, and where it closed.
    ///
    /// The identity is first and length-prefixed. Without it the digest was a
    /// state, and an attestation for a quiet cycle settled the next quiet cycle
    /// --- the quorum having seen neither.
    pub fn batch_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"QOMM:DEFMI:CYCLE:v1:batch");
        hasher.update((self.id.len() as u64).to_be_bytes());
        hasher.update(&self.id);
        hasher.update(self.mode.label().as_bytes());
        hasher.update(self.securities.snapshot());
        hasher.update(self.cash.snapshot());
        hasher.update((self.admitted as u64).to_be_bytes());
        hasher.finalize().into()
    }

    pub fn close(
        &mut self,
        securities_coverage: &[Coverage],
        cash_coverage: &[Coverage],
        attestation: Option<&BatchAttestation>,
    ) -> Result<(), &'static str> {
        if self.attest_batch {
            let quorum = self
                .quorum
                .as_ref()
                .ok_or("an attested cycle needs the quorum's key")?;
            match attestation {
                None => return Err("an attested cycle needs an attestation"),
                Some(a) if a.digest != self.batch_digest() => {
                    return Err("the attestation is for other positions")
                }
                Some(a) => quorum
                    .verify_strict(&BatchAttestation::body(&a.digest), &a.signature)
                    .map_err(|_| "the attestation is not signed by the quorum")?,
            }
        }
        for (book, coverage) in [
            (&self.securities, securities_coverage),
            (&self.cash, cash_coverage),
        ] {
            if !book.net {
                continue;
            }
            let supplied: std::collections::BTreeSet<_> =
                coverage.iter().map(|c| c.handle.clone()).collect();
            if supplied != book.handles().into_iter().collect() {
                return Err("not every net position is covered");
            }
            for c in coverage {
                book.check_coverage(c)?;
            }
        }
        if !(self.securities.conserved() && self.cash.conserved()) {
            return Err("a rail does not conserve value");
        }
        self.closed = true;
        Ok(())
    }
}

/// Build the product proof relating a cash reference to the instructed factors.
#[allow(clippy::too_many_arguments)]
pub fn prove_cash_reference<R: RngCore + CryptoRng>(
    key: &Pedersen,
    price_commitment: &RistrettoPoint,
    price: u64,
    price_blinding: &Scalar,
    quantity: u64,
    quantity_blinding: &Scalar,
    cash_blinding: &Scalar,
    rng: &mut R,
) -> ProductProof {
    prove_product(
        key,
        &mut value_transcript(),
        price_commitment,
        &Scalar::from(price),
        price_blinding,
        &Scalar::from(quantity),
        quantity_blinding,
        cash_blinding,
        rng,
    )
}
