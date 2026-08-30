//! A ledger whose balances are commitments.
//!
//! What it can check without opening anything: value is neither created nor
//! destroyed, because the product of all balances equals the product at
//! issuance; and no balance goes negative, by a range proof on the difference.
//! What it cannot check, and does not try to, is whether the price was fair.
//! That meaning was established by the computing quorum and is carried by the
//! signature on the instruction.

use bulletproofs::{BulletproofGens, RangeProof};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use ed25519_dalek::{Signature as IssuerSignature, VerifyingKey};
use merlin::Transcript;
use qomm_zk::pedersen::Pedersen;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::assets::BlindedTag;
use qomm_zk::adaptor::{self, Signature};

pub struct Transfer {
    pub amount_commitment: RistrettoPoint,
    /// Absent when the amount is pinned by an instruction that already proved
    /// it in range. Half the range proofs in a settlement are this one, so the
    /// ledger requires the caller to say so rather than inferring it.
    pub amount_range: Option<(RangeProof, CompressedRistretto)>,
    pub remainder_commitment: RistrettoPoint,
    pub remainder_range: RangeProof,
    pub tag: Option<BlindedTag>,
}

pub struct TransferSecrets {
    /// Opens the amount commitment against the tag the leg was proved under.
    pub amount_blinding: Scalar,
    /// What the receiving account adds to its own blinding; differs by
    /// gamma*amount once a tag is in play. Returning one number for both is how
    /// a tagged leg silently stops verifying.
    pub payee_delta: Scalar,
    pub remainder_blinding: Scalar,
}

/// A transfer that has been checked and whose funds have left the payer, but
/// which has not reached the payee yet.
///
/// This is what makes a settlement across two ledgers possible at all. Neither
/// ledger can see the other, so neither can decide alone whether the pair went
/// through; what each *can* do is take the money out of reach and wait. The
/// amount stays on the ledger's books the whole time --- it is in neither
/// account, so conservation has to count it explicitly, which is the one place
/// this could silently create or destroy value.
pub struct Pending {
    pub payer: Vec<u8>,
    /// The key that may release this escrow, recorded when it was prepared.
    ///
    /// `commit_pending` used to verify the release under a key the *caller*
    /// supplied and never compare it with anything, so anyone could sign the
    /// leg's name with a key of their own and force somebody else's escrow to
    /// settle --- without knowing the adaptor secret, which is what was meant to
    /// gate it. A signature is only an authority if the verifier chose the key.
    pub release_key: RistrettoPoint,
    pub payee: Vec<u8>,
    pub amount_commitment: RistrettoPoint,
    /// Past this, the payer may take it back. A ledger does not read a clock;
    /// the caller supplies the time it is judging against, so the same code
    /// runs against a block height, a slot number or a wall clock.
    pub deadline: u64,
}

/// What an issuer signs to let one opening balance exist.
///
/// The handle it is for, the commitment it is worth and a nonce, so an
/// authorisation cannot be moved to another account, restated for another
/// amount, or replayed.
pub fn issuance_body(handle: &[u8], balance: &RistrettoPoint, nonce: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"QOMM:DEFMI:ISSUE:v1");
    hasher.update((handle.len() as u64).to_be_bytes());
    hasher.update(handle);
    hasher.update(balance.compress().as_bytes());
    hasher.update((nonce.len() as u64).to_be_bytes());
    hasher.update(nonce);
    hasher.finalize().to_vec()
}

pub struct Ledger {
    pub key: Pedersen,
    pub bits: usize,
    bp_gens: BulletproofGens,
    accounts: BTreeMap<Vec<u8>, RistrettoPoint>,
    pending: BTreeMap<Vec<u8>, Pending>,
    /// Leg names that have been prepared, live or not. See `prepare_transfer`.
    spent_legs: BTreeSet<Vec<u8>>,
    minted: RistrettoPoint,
    /// Who may create balance. `None` accepts any opening and says so; see
    /// `open_authorised`.
    issuer: Option<VerifyingKey>,
    issued: BTreeSet<Vec<u8>>,
}

impl Ledger {
    pub fn new(key: Pedersen, bits: usize) -> Self {
        Ledger {
            key,
            bits,
            bp_gens: BulletproofGens::new(bits, 1),
            accounts: BTreeMap::new(),
            pending: BTreeMap::new(),
            spent_legs: BTreeSet::new(),
            minted: RistrettoPoint::identity(),
            issuer: None,
            issued: BTreeSet::new(),
        }
    }

    /// A ledger where balance can only come from one place.
    pub fn under_issuer(key: Pedersen, bits: usize, issuer: VerifyingKey) -> Self {
        let mut ledger = Ledger::new(key, bits);
        ledger.issuer = Some(issuer);
        ledger
    }

    /// Admit a balance without asking where it came from.
    ///
    /// The conservation check below then says "nothing has been created or
    /// destroyed since the ledger accepted these", which is not the same
    /// sentence as "only an issuer created anything". Fixtures and the
    /// conservation measurements use this deliberately; a deployment wants
    /// `under_issuer` and `open_authorised`.
    pub fn open(&mut self, handle: &[u8], balance: RistrettoPoint) {
        assert!(
            self.issuer.is_none(),
            "this ledger has an issuer; use open_authorised"
        );
        assert!(!self.accounts.contains_key(handle), "handle already open");
        self.accounts.insert(handle.to_vec(), balance);
        self.minted += balance;
    }

    /// Admit a balance an issuer put its name to.
    pub fn open_authorised(
        &mut self,
        handle: &[u8],
        balance: RistrettoPoint,
        nonce: &[u8],
        authorisation: &IssuerSignature,
    ) -> Result<(), &'static str> {
        let issuer = self.issuer.as_ref().ok_or("this ledger has no issuer")?;
        if self.accounts.contains_key(handle) {
            return Err("handle already open");
        }
        let body = issuance_body(handle, &balance, nonce);
        if self.issued.contains(&body) {
            return Err("that issuance authorisation was already used");
        }
        issuer
            .verify_strict(&body, authorisation)
            .map_err(|_| "the opening balance is not signed by the issuer")?;
        self.issued.insert(body);
        self.accounts.insert(handle.to_vec(), balance);
        self.minted += balance;
        Ok(())
    }

    pub fn balance(&self, handle: &[u8]) -> Option<&RistrettoPoint> {
        self.accounts.get(handle)
    }

    pub fn handles(&self) -> Vec<Vec<u8>> {
        self.accounts.keys().cloned().collect()
    }

    /// No proof and no opening: the two products simply have to agree.
    ///
    /// Money held in escrow is in no account and is still on the books, so it
    /// is counted here. Leaving it out would make every prepared leg look like
    /// value destroyed and every commit like value created.
    pub fn conserved(&self) -> bool {
        let held: RistrettoPoint = self.pending.values().map(|p| p.amount_commitment).sum();
        self.accounts.values().sum::<RistrettoPoint>() + held == self.minted
    }

    pub fn pending(&self, leg: &[u8]) -> Option<&Pending> {
        self.pending.get(leg)
    }

    pub fn pending_legs(&self) -> Vec<Vec<u8>> {
        self.pending.keys().cloned().collect()
    }

    /// Check a transfer and take the amount out of the payer's reach, without
    /// giving it to the payee.
    ///
    /// `leg` names the escrow. It is the caller's identifier and it is what the
    /// signature that later releases the money is made over, so it has to be
    /// unique on this ledger --- a reused name is a second claim on the first
    /// escrow, which is refused here rather than left to the caller.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_transfer(
        &mut self,
        leg: &[u8],
        payer: &[u8],
        payee: &[u8],
        transfer: &Transfer,
        context: &[u8],
        amount_bounded: bool,
        deadline: u64,
        release_key: &RistrettoPoint,
    ) -> Result<(), &'static str> {
        if self.pending.contains_key(leg) {
            return Err("that leg is already prepared");
        }
        // A leg name is spent for the ledger's lifetime and not only while its
        // escrow is live. It used to be checked against `pending` alone, and
        // the entry is removed on commit or unwind --- so a name could be
        // reused, and the release signature covers only the name, so the first
        // escrow's release settled the second one.
        if self.spent_legs.contains(leg) {
            return Err("that leg name has been used before");
        }
        if !self.accounts.contains_key(payee) {
            return Err("unknown payee handle");
        }
        self.check_transfer(payer, transfer, context, amount_bounded)?;
        self.accounts
            .insert(payer.to_vec(), transfer.remainder_commitment);
        self.spent_legs.insert(leg.to_vec());
        self.pending.insert(
            leg.to_vec(),
            Pending {
                payer: payer.to_vec(),
                release_key: *release_key,
                payee: payee.to_vec(),
                amount_commitment: transfer.amount_commitment,
                deadline,
            },
        );
        Ok(())
    }

    /// Release an escrow to its payee.
    ///
    /// The ledger checks an ordinary signature over the leg's name under the key
    /// the escrow was prepared against. It knows nothing about adaptors or about
    /// the other ledger; what makes the pair atomic happens outside, and this
    /// stays a signature check so that it can.
    ///
    /// The key is the one recorded at `prepare_transfer` and not one the caller
    /// hands in. Taking it from the caller made the check vacuous.
    pub fn commit_pending(
        &mut self,
        leg: &[u8],
        release: &Signature,
        now: u64,
    ) -> Result<(), &'static str> {
        let held = self.pending.get(leg).ok_or("no such prepared leg")?;
        if now > held.deadline {
            return Err("the escrow has expired");
        }
        if !adaptor::verify(&held.release_key, leg, release) {
            return Err("the release is not signed for this leg");
        }
        let held = self.pending.remove(leg).expect("just looked it up");
        let credited = self.accounts[&held.payee] + held.amount_commitment;
        self.accounts.insert(held.payee, credited);
        Ok(())
    }

    /// Give an expired escrow back to its payer.
    ///
    /// No signature: the payer already owned this money and the deadline is the
    /// whole authority. Requiring one would strand funds whenever the payer
    /// lost a key, which is the failure this branch exists to prevent.
    pub fn unwind_pending(&mut self, leg: &[u8], now: u64) -> Result<(), &'static str> {
        let held = self.pending.get(leg).ok_or("no such prepared leg")?;
        if now <= held.deadline {
            return Err("the escrow has not expired");
        }
        let held = self.pending.remove(leg).expect("just looked it up");
        let restored = self.accounts[&held.payer] + held.amount_commitment;
        self.accounts.insert(held.payer, restored);
        Ok(())
    }

    fn gens(&self, tag: Option<&BlindedTag>) -> bulletproofs::PedersenGens {
        match tag {
            Some(t) => t.gens(&self.key),
            None => bulletproofs::PedersenGens {
                B: self.key.g,
                B_blinding: self.key.h,
            },
        }
    }

    fn context(&self, context: &[u8], tag: Option<&BlindedTag>) -> Vec<u8> {
        // The tag is prover-chosen, so it belongs in the transcript. The
        // verification equations already pin it; a challenge that does not
        // cover a value the prover controls is a gap worth closing anyway.
        let mut out = context.to_vec();
        if let Some(t) = tag {
            out.extend_from_slice(b":tag:");
            out.extend_from_slice(t.point.compress().as_bytes());
        }
        out
    }

    /// Run by the payer, the only party that knows its own balance.
    #[allow(clippy::too_many_arguments)]
    pub fn build_transfer<R: RngCore + CryptoRng>(
        &self,
        payer_balance: u64,
        payer_blinding: &Scalar,
        amount: u64,
        context: &[u8],
        tag: Option<&BlindedTag>,
        gamma: &Scalar,
        amount_bounded: bool,
        rng: &mut R,
    ) -> Result<(Transfer, TransferSecrets), &'static str> {
        let amount_blinding = Scalar::random(rng);
        self.build_transfer_with_amount_blinding(
            payer_balance,
            payer_blinding,
            amount,
            &amount_blinding,
            context,
            tag,
            gamma,
            amount_bounded,
        )
    }

    /// Build a transfer whose amount commitment is already named by a zkPI.
    /// The party supplies that commitment's blinding so the account proof and
    /// the threshold-signed instruction refer to exactly the same hidden value.
    #[allow(clippy::too_many_arguments)]
    pub fn build_transfer_with_amount_blinding(
        &self,
        payer_balance: u64,
        payer_blinding: &Scalar,
        amount: u64,
        amount_blinding: &Scalar,
        context: &[u8],
        tag: Option<&BlindedTag>,
        gamma: &Scalar,
        amount_bounded: bool,
    ) -> Result<(Transfer, TransferSecrets), &'static str> {
        if payer_balance < amount {
            return Err("balance cannot cover the amount");
        }
        let gens = self.gens(tag);
        let ctx = self.context(context, tag);

        let amount_range = if amount_bounded {
            None
        } else {
            let mut t = Transcript::new(b"qomm:defmi:amt");
            t.append_message(b"ctx", &ctx);
            let (proof, commitments) = RangeProof::prove_multiple(
                &self.bp_gens,
                &gens,
                &mut t,
                &[amount],
                &[*amount_blinding],
                self.bits,
            )
            .map_err(|_| "amount range proof failed")?;
            Some((proof, commitments[0]))
        };
        let amount_commitment = gens.commit(Scalar::from(amount), *amount_blinding);

        // H^(v-q) h^t has to land on balance / amount, which costs gamma*v
        let remainder = payer_balance - amount;
        let remainder_blinding =
            payer_blinding - amount_blinding - gamma * Scalar::from(payer_balance);
        let mut t = Transcript::new(b"qomm:defmi:rem");
        t.append_message(b"ctx", &ctx);
        let (remainder_range, remainder_commitments) = RangeProof::prove_multiple(
            &self.bp_gens,
            &gens,
            &mut t,
            &[remainder],
            &[remainder_blinding],
            self.bits,
        )
        .map_err(|_| "remainder range proof failed")?;

        Ok((
            Transfer {
                amount_commitment,
                amount_range,
                remainder_commitment: remainder_commitments[0]
                    .decompress()
                    .ok_or("bad remainder commitment")?,
                remainder_range,
                tag: tag.cloned(),
            },
            TransferSecrets {
                amount_blinding: *amount_blinding,
                payee_delta: gamma * Scalar::from(amount) + amount_blinding,
                remainder_blinding,
            },
        ))
    }

    /// Run by the ledger, which reads neither the balance nor the amount.
    pub fn check_transfer(
        &self,
        payer: &[u8],
        transfer: &Transfer,
        context: &[u8],
        amount_bounded: bool,
    ) -> Result<(), &'static str> {
        let balance = *self.accounts.get(payer).ok_or("unknown payer handle")?;
        let gens = self.gens(transfer.tag.as_ref());
        let ctx = self.context(context, transfer.tag.as_ref());

        match (&transfer.amount_range, amount_bounded) {
            (Some(_), true) => {
                return Err("an externally bounded amount carries a stale range proof")
            }
            (None, false) => return Err("the amount carries no range proof"),
            (Some((proof, commitment)), false) => {
                if *commitment != transfer.amount_commitment.compress() {
                    return Err("the range proof is about a different amount");
                }
                let mut t = Transcript::new(b"qomm:defmi:amt");
                t.append_message(b"ctx", &ctx);
                proof
                    .verify_multiple(
                        &self.bp_gens,
                        &gens,
                        &mut t,
                        std::slice::from_ref(commitment),
                        self.bits,
                    )
                    .map_err(|_| "amount not shown to be within the ledger range")?;
            }
            (None, true) => {}
        }

        let mut t = Transcript::new(b"qomm:defmi:rem");
        t.append_message(b"ctx", &ctx);
        transfer
            .remainder_range
            .verify_multiple(
                &self.bp_gens,
                &gens,
                &mut t,
                &[transfer.remainder_commitment.compress()],
                self.bits,
            )
            .map_err(|_| "payer would be left with a negative balance")?;

        // the remainder must be exactly balance - amount, which the
        // homomorphism settles without anyone opening either value
        if balance - transfer.amount_commitment != transfer.remainder_commitment {
            return Err("remainder does not equal balance minus amount");
        }
        Ok(())
    }

    /// Verify and apply one transfer as a single ledger operation.
    ///
    /// This is the safe public entry point for a rail that settles one leg at a
    /// time. Replaying the same transfer is refused because verification is
    /// repeated against the payer's current commitment before anything moves.
    /// Multi-leg DvP must continue to use [`crate::settlement::Defmi::settle`],
    /// which verifies every leg first and then applies all of them atomically.
    pub fn settle_transfer(
        &mut self,
        payer: &[u8],
        payee: &[u8],
        transfer: &Transfer,
        context: &[u8],
        amount_bounded: bool,
    ) -> Result<(), &'static str> {
        if !self.accounts.contains_key(payee) {
            return Err("unknown payee handle");
        }
        self.check_transfer(payer, transfer, context, amount_bounded)?;
        self.apply_transfer(payer, payee, transfer);
        Ok(())
    }

    /// Only called once every leg of a settlement has been checked.
    ///
    /// Crate-private, because it is not idempotent and nothing in it could be:
    /// the payer's balance is overwritten with the remainder, which is the same
    /// on a second call, while the payee is credited again. Calling it twice
    /// creates value. What stops that is the instruction's nullifier in
    /// `settlement.rs`, and the way to keep that the only guard is to make this
    /// unreachable from outside.
    pub(crate) fn apply_transfer(&mut self, payer: &[u8], payee: &[u8], transfer: &Transfer) {
        self.accounts
            .insert(payer.to_vec(), transfer.remainder_commitment);
        let credited = self.accounts[payee] + transfer.amount_commitment;
        self.accounts.insert(payee.to_vec(), credited);
    }

    pub fn snapshot(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"QOMM:DEFMI:LEDGER:v1");
        for (handle, balance) in &self.accounts {
            hasher.update((handle.len() as u32).to_be_bytes());
            hasher.update(handle);
            hasher.update(balance.compress().as_bytes());
        }
        hasher.finalize().into()
    }
}

impl Transfer {
    /// Stable identifier for the complete confidential transfer evidence.
    ///
    /// DeFMI validators receive the proof bytes at the Rust admission boundary,
    /// while the Avalanche state machine stores only this digest.  Hashing every
    /// proof component prevents a committee approval for one reserve from being
    /// replayed with another payer remainder or asset tag.
    pub fn digest(&self) -> [u8; 32] {
        fn bytes(hash: &mut Sha256, value: &[u8]) {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }

        let mut hash = Sha256::new();
        hash.update(b"QOMM:DEFMI:TRANSFER-PROOF:v1");
        hash.update(self.amount_commitment.compress().as_bytes());
        match &self.amount_range {
            Some((proof, commitment)) => {
                hash.update([1]);
                hash.update(commitment.as_bytes());
                bytes(&mut hash, &proof.to_bytes());
            }
            None => hash.update([0]),
        }
        hash.update(self.remainder_commitment.compress().as_bytes());
        bytes(&mut hash, &self.remainder_range.to_bytes());
        match &self.tag {
            Some(tag) => {
                hash.update([1]);
                hash.update(tag.point.compress().as_bytes());
            }
            None => hash.update([0]),
        }
        hash.finalize().into()
    }
}
