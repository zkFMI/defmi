//! Delivery versus payment where neither side has an account.
//!
//! The account version settles between four named handles, which is the last
//! thing in the design that says who is trading. This replaces both rails with
//! note ledgers: each leg spends a note into a payee note and a change note, and
//! says which note it spent only to the extent of naming a ring.
//!
//! The binding to the instruction survives the change at one extra proof per
//! leg. A note ledger states its value commitments against a blinded asset tag,
//! while the quorum issued the instruction against the base generator before any
//! tag existed, so the two are compared by a cross-generator equality proof
//! rather than by subtraction. Everything else --- the product relation for
//! cash, the two-leg atomicity, the nullifier --- is unchanged.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use merlin::Transcript;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::{
    prove_product, prove_same_value, verify_product, verify_same_value, CrossGeneratorProof,
    ProductProof,
};
use qomm_zkpi::{Instruction, Venue};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::notes::{Address, Note, NoteLedger, Opening, SpendProof};

const DOMAIN: &[u8] = b"QOMM:DEFMI:NOTE-DVP:v1";

/// One rail's half of a settlement: a ring, a spend, and the notes it makes.
///
/// The payee's note is first by convention. Nothing in the proof distinguishes
/// it, so a verifier taking them the other way round would be checking the
/// change against the instruction --- which is why the convention is enforced
/// here rather than assumed.
pub struct NoteLeg {
    pub ring: Vec<usize>,
    /// Public predicate bits used to transform the anonymity set.  They reveal
    /// which decoys are eligible for this lock class, never which one was spent.
    pub eligibility: Vec<bool>,
    pub spend: SpendProof,
    pub notes: Vec<Note>,
}

pub struct NoteDvpPackage {
    pub instruction: Instruction,
    pub securities: NoteLeg,
    pub cash: NoteLeg,
    pub quantity_link: CrossGeneratorProof,
    pub cash_value_commitment: RistrettoPoint,
    pub cash_link: CrossGeneratorProof,
    pub value_proof: ProductProof,
}

impl NoteDvpPackage {
    /// Digest of every verifier-complete proof object.  The chain statement
    /// separately binds canonical note IDs and ring roots; this digest makes
    /// the zkPI/DvP linkage itself impossible to swap after committee review.
    pub fn digest(&self) -> [u8; 32] {
        fn point(hash: &mut Sha256, point: &RistrettoPoint) {
            hash.update(point.compress().as_bytes());
        }
        fn scalar(hash: &mut Sha256, scalar: &Scalar) {
            hash.update(scalar.to_bytes());
        }
        fn cross(hash: &mut Sha256, proof: &CrossGeneratorProof) {
            point(hash, &proof.t_first);
            point(hash, &proof.t_second);
            scalar(hash, &proof.z_value);
            scalar(hash, &proof.z_first);
            scalar(hash, &proof.z_second);
        }
        fn product(hash: &mut Sha256, proof: &ProductProof) {
            point(hash, &proof.t_factor);
            point(hash, &proof.t_product);
            scalar(hash, &proof.z_b);
            scalar(hash, &proof.z_rb);
            scalar(hash, &proof.z_s);
        }
        fn leg(hash: &mut Sha256, leg: &NoteLeg) {
            hash.update((leg.ring.len() as u64).to_be_bytes());
            for index in &leg.ring {
                hash.update((*index as u64).to_be_bytes());
            }
            hash.update((leg.eligibility.len() as u64).to_be_bytes());
            for eligible in &leg.eligibility {
                hash.update([u8::from(*eligible)]);
            }
            hash.update(leg.spend.digest());
            hash.update((leg.notes.len() as u64).to_be_bytes());
            for note in &leg.notes {
                for bytes in [
                    note.one_time.compress().to_bytes(),
                    note.value_commitment.compress().to_bytes(),
                    note.ephemeral.compress().to_bytes(),
                    note.masked_value.to_bytes(),
                    note.masked_blinding.to_bytes(),
                ] {
                    hash.update(bytes);
                }
            }
        }
        let mut hash = Sha256::new();
        hash.update(b"QOMM:DEFMI:NOTE-DVP-PACKAGE:v1");
        let instruction = qomm_zkpi::wire::encode(&self.instruction);
        hash.update((instruction.len() as u64).to_be_bytes());
        hash.update(instruction);
        leg(&mut hash, &self.securities);
        leg(&mut hash, &self.cash);
        cross(&mut hash, &self.quantity_link);
        point(&mut hash, &self.cash_value_commitment);
        cross(&mut hash, &self.cash_link);
        product(&mut hash, &self.value_proof);
        hash.finalize().into()
    }
}

pub struct NoteReceipt {
    pub nullifier: [u8; 32],
    pub settled: bool,
    pub reason: &'static str,
    pub securities_before: [u8; 32],
    pub securities_after: [u8; 32],
    pub cash_before: [u8; 32],
    pub cash_after: [u8; 32],
    pub settled_at: u64,
    pub signature: Signature,
}

impl NoteReceipt {
    #[expect(
        clippy::too_many_arguments,
        reason = "receipt digest fields stay explicit so no settlement state can be omitted"
    )]
    fn digest(
        nullifier: &[u8; 32],
        settled: bool,
        reason: &str,
        sb: &[u8; 32],
        sa: &[u8; 32],
        cb: &[u8; 32],
        ca: &[u8; 32],
        at: u64,
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(nullifier);
        h.update([u8::from(settled)]);
        h.update((reason.len() as u32).to_be_bytes());
        h.update(reason.as_bytes());
        for part in [sb, sa, cb, ca] {
            h.update(part);
        }
        h.update(at.to_be_bytes());
        h.finalize().into()
    }

    pub fn verify(&self, key: &VerifyingKey) -> bool {
        let digest = Self::digest(
            &self.nullifier,
            self.settled,
            self.reason,
            &self.securities_before,
            &self.securities_after,
            &self.cash_before,
            &self.cash_after,
            self.settled_at,
        );
        key.verify(&digest, &self.signature).is_ok()
    }
}

/// What one rail needs in order to spend: which note, under which tag.
pub struct LegInput<'a> {
    pub ring: &'a [usize],
    pub index: usize,
    pub opening: &'a Opening,
    pub tag: RistrettoPoint,
    pub gamma: Scalar,
    pub payee: Address,
    pub change_to: Address,
}

fn transcript(context: &[u8], part: &str) -> Transcript {
    let mut t = Transcript::new(DOMAIN);
    t.append_message(b"ctx", context);
    t.append_message(b"part", part.as_bytes());
    t
}

/// Assembled by the counterparties, who hold the note openings.
#[allow(clippy::too_many_arguments)]
pub fn build_note_package<R: RngCore + CryptoRng>(
    key: &Pedersen,
    instruction: Instruction,
    securities_ledger: &NoteLedger,
    cash_ledger: &NoteLedger,
    securities: &LegInput,
    cash: &LegInput,
    quantity: u64,
    price: u64,
    instruction_amount_blinding: &Scalar,
    instruction_price_blinding: &Scalar,
    context: &[u8],
    rng: &mut R,
) -> Result<NoteDvpPackage, &'static str> {
    let securities_eligibility = vec![true; securities.ring.len()];
    let cash_eligibility = vec![true; cash.ring.len()];
    build_note_package_constrained(
        key,
        instruction,
        securities_ledger,
        cash_ledger,
        securities,
        cash,
        &securities_eligibility,
        &cash_eligibility,
        quantity,
        price,
        instruction_amount_blinding,
        instruction_price_blinding,
        context,
        rng,
    )
}

/// Build the same DvP while proving that each hidden input also belongs to a
/// public eligibility class (for example, the reservation's lock identifier).
#[allow(clippy::too_many_arguments)]
pub fn build_note_package_constrained<R: RngCore + CryptoRng>(
    key: &Pedersen,
    instruction: Instruction,
    securities_ledger: &NoteLedger,
    cash_ledger: &NoteLedger,
    securities: &LegInput,
    cash: &LegInput,
    securities_eligibility: &[bool],
    cash_eligibility: &[bool],
    quantity: u64,
    price: u64,
    instruction_amount_blinding: &Scalar,
    instruction_price_blinding: &Scalar,
    context: &[u8],
    rng: &mut R,
) -> Result<NoteDvpPackage, &'static str> {
    let value = quantity
        .checked_mul(price)
        .ok_or("quantity times price overflows")?;

    let sec = securities_ledger.build_spend_constrained(
        securities.ring,
        securities.index,
        securities.opening,
        &securities.tag,
        &securities.gamma,
        &[
            (securities.payee, quantity),
            (securities.change_to, securities.opening.value - quantity),
        ],
        securities_eligibility,
        &[context, b":sec"].concat(),
        rng,
    )?;
    let cash_spend = cash_ledger.build_spend_constrained(
        cash.ring,
        cash.index,
        cash.opening,
        &cash.tag,
        &cash.gamma,
        &[
            (cash.payee, value),
            (cash.change_to, cash.opening.value - value),
        ],
        cash_eligibility,
        &[context, b":cash"].concat(),
        rng,
    )?;

    // The payee's securities note has to carry the instructed quantity. Its
    // commitment lives under the tag, the instruction's under the base point,
    // so the two are joined across generators rather than by subtraction.
    let quantity_link = prove_same_value(
        key,
        &mut transcript(context, "qty-link"),
        &securities.tag,
        &key.g,
        &sec.proof.outputs[0],
        &instruction.amount_commitment,
        &Scalar::from(quantity),
        &sec.tagged_blindings[0],
        instruction_amount_blinding,
        rng,
    );

    // The cash the seller receives, restated under the base point so the
    // product relation can be checked against the instruction alone.
    let cash_blinding = Scalar::random(rng);
    let cash_value_commitment = key.commit(&Scalar::from(value), &cash_blinding);
    let cash_link = prove_same_value(
        key,
        &mut transcript(context, "cash-link"),
        &cash.tag,
        &key.g,
        &cash_spend.proof.outputs[0],
        &cash_value_commitment,
        &Scalar::from(value),
        &cash_spend.tagged_blindings[0],
        &cash_blinding,
        rng,
    );

    let value_proof = prove_product(
        key,
        &mut transcript(context, "value"),
        &instruction.price_commitment,
        &Scalar::from(price),
        instruction_price_blinding,
        &Scalar::from(quantity),
        instruction_amount_blinding,
        &cash_blinding,
        rng,
    );

    Ok(NoteDvpPackage {
        instruction,
        securities: NoteLeg {
            ring: securities.ring.to_vec(),
            eligibility: securities_eligibility.to_vec(),
            spend: sec.proof,
            notes: sec.notes,
        },
        cash: NoteLeg {
            ring: cash.ring.to_vec(),
            eligibility: cash_eligibility.to_vec(),
            spend: cash_spend.proof,
            notes: cash_spend.notes,
        },
        quantity_link,
        cash_value_commitment,
        cash_link,
        value_proof,
    })
}

/// Two note rails with two-leg finality, blind to what and to whom.
pub struct NoteDefmi {
    pub key: Pedersen,
    pub securities: NoteLedger,
    pub cash: NoteLedger,
    pub venue: Venue,
    signing: SigningKey,
}

impl NoteDefmi {
    pub fn new(
        key: Pedersen,
        securities: NoteLedger,
        cash: NoteLedger,
        venue: Venue,
        signing: SigningKey,
    ) -> Self {
        NoteDefmi {
            key,
            securities,
            cash,
            venue,
            signing,
        }
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Verify the complete account-free DvP without mutating either note rail.
    /// This is the admission boundary used before the k-of-n committee signs
    /// the exact Avalanche projection.
    pub fn verify<R: RngCore + CryptoRng>(
        &self,
        package: &NoteDvpPackage,
        now: u64,
        context: &[u8],
        rng: &mut R,
    ) -> Result<(), &'static str> {
        self.venue.verify(&package.instruction, now)?;

        self.securities.check_spend_constrained(
            &package.securities.ring,
            &package.securities.spend,
            &package.securities.eligibility,
            &[context, b":sec"].concat(),
            rng,
        )?;
        self.cash.check_spend_constrained(
            &package.cash.ring,
            &package.cash.spend,
            &package.cash.eligibility,
            &[context, b":cash"].concat(),
            rng,
        )?;

        for leg in [&package.securities, &package.cash] {
            if leg.notes.len() != leg.spend.outputs.len() {
                return Err("a leg has a note without a commitment");
            }
            for (note, commitment) in leg.notes.iter().zip(&leg.spend.outputs) {
                // The note that lands in the pool must carry exactly the value
                // commitment the proof is about, or a payer could prove it paid
                // the instructed quantity and then deposit something else.
                if note.value_commitment != *commitment {
                    return Err("a leg's note does not carry its proved value");
                }
            }
        }

        if !verify_same_value(
            &self.key,
            &mut transcript(context, "qty-link"),
            &package.securities.spend.tag,
            &self.key.g,
            &package.securities.spend.outputs[0],
            &package.instruction.amount_commitment,
            &package.quantity_link,
        ) {
            return Err("securities leg does not deliver the instructed quantity");
        }
        if !verify_same_value(
            &self.key,
            &mut transcript(context, "cash-link"),
            &package.cash.spend.tag,
            &self.key.g,
            &package.cash.spend.outputs[0],
            &package.cash_value_commitment,
            &package.cash_link,
        ) {
            return Err("the cash leg does not match the value it claims");
        }
        if !verify_product(
            &self.key,
            &mut transcript(context, "value"),
            &package.instruction.price_commitment,
            &package.instruction.amount_commitment,
            &package.cash_value_commitment,
            &package.value_proof,
        ) {
            return Err("cash leg is not quantity times price");
        }
        Ok(())
    }

    pub fn settle<R: RngCore + CryptoRng>(
        &mut self,
        package: NoteDvpPackage,
        now: u64,
        context: &[u8],
        rng: &mut R,
    ) -> NoteReceipt {
        let securities_before = self.securities.snapshot();
        let cash_before = self.cash.snapshot();
        let status = self.verify(&package, now, context, rng);

        if status.is_ok() {
            // both legs are checked before either is applied
            self.securities
                .apply_spend(&package.securities.spend, package.securities.notes)
                .expect("checked");
            self.cash
                .apply_spend(&package.cash.spend, package.cash.notes)
                .expect("checked");
            self.venue
                .settle(&package.instruction, now)
                .expect("venue refused after checks");
        }

        let nullifier = package.instruction.nullifier();
        let settled = status.is_ok();
        let reason = match status {
            Ok(()) => "settled",
            Err(why) => why,
        };
        let securities_after = self.securities.snapshot();
        let cash_after = self.cash.snapshot();
        let digest = NoteReceipt::digest(
            &nullifier,
            settled,
            reason,
            &securities_before,
            &securities_after,
            &cash_before,
            &cash_after,
            now,
        );
        NoteReceipt {
            nullifier,
            settled,
            reason,
            securities_before,
            securities_after,
            cash_before,
            cash_after,
            settled_at: now,
            signature: self.signing.sign(&digest),
        }
    }
}
