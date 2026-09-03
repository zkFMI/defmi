//! Payment versus payment: two payments on two ledgers that share no state,
//! settling together or not at all.
//!
//! DvP already moves two legs together, and it can do that because both legs
//! are on one ledger and one function decides. PvP across two ledgers has no
//! such function. Neither ledger can see the other, neither can be told to wait
//! for the other, and fair exchange between two parties with no third party is
//! impossible in general --- so something must pass from one side to the other,
//! and the design question is only what passes and who can read it.
//!
//! A hash lock passes a preimage that ends up in the clear on both ledgers, so
//! anyone reading both can join the two legs on it. That is the linkage the
//! rest of this system pays to prevent, and it would be given back at the last
//! step. This uses an adaptor signature instead: what passes is a scalar, it
//! passes only to the party holding the pre-signature, and what each ledger
//! records is an ordinary signature with nothing in common with the other's.
//!
//! # The protocol
//!
//! Alice pays on ledger A, Bob pays on ledger B. Bob draws the secret.
//!
//! ```text
//! 1. Bob   -> Alice : Y = g^y
//! 2. Alice           prepares leg A (her money leaves her account, into escrow)
//!    Alice -> Bob   : pre-signature over "leg A", adapted to Y
//! 3. Bob             prepares leg B
//!    Bob   -> Alice : pre-signature over "leg B", adapted to Y
//! 4. Bob             adapts and publishes on A  -> he is paid, and y is now
//!                                                  recoverable by Alice
//! 5. Alice           reads A, extracts y, adapts and publishes on B -> she is paid
//! ```
//!
//! # Who is exposed, and for how long
//!
//! Bob moves first and holds `y`, so Bob is never at risk: if he stops after
//! step 3, both escrows expire and both parties are made whole. Alice is at
//! risk in exactly one window --- between Bob taking her money at step 4 and her
//! own claim at step 5 --- and she is safe if and only if
//!
//! ```text
//! deadline(B) - deadline(A) >= the time to notice step 4 and complete step 5
//! ```
//!
//! That gap is this arrangement's Herstatt risk, and it is a measured quantity
//! rather than a chosen one: see `benches/pvp.rs`, which times the right-hand
//! side. Setting the two deadlines without measuring it is where the money is
//! actually lost.
//!
//! A ledger does not read a clock. Every entry point takes the time it is being
//! judged against, so the same code runs against a block height, a slot number
//! or a wall clock, and a test can move time without waiting.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use qomm_zk::adaptor::{self, Adaptor, PreSignature, Signature};
use rand_core::{CryptoRng, RngCore};

use crate::ledger::{Ledger, Transfer};

/// One side of a swap, as its own payer sets it up.
///
/// The pre-signature is the authority to release, and it is useless until the
/// adaptor's secret is known. Handing it over is therefore not handing over the
/// money; that distinction is the whole reason this is safe to send before the
/// other side has done anything.
pub struct Leg {
    pub id: Vec<u8>,
    pub payer: Vec<u8>,
    pub payee: Vec<u8>,
    pub payer_key: RistrettoPoint,
    pub deadline: u64,
    pub release: PreSignature,
}

impl Leg {
    /// Check the release authority before relying on it.
    ///
    /// The party receiving a leg is about to leave money in an escrow that only
    /// this pre-signature can release. A pre-signature that does not verify
    /// means an escrow that can only expire, so this is checked before anything
    /// moves rather than discovered at step 4.
    pub fn releasable_with(&self, adaptor_point: &RistrettoPoint) -> bool {
        adaptor::verify_pre_signature(&self.payer_key, adaptor_point, &self.id, &self.release)
    }
}

/// What one party knows about a swap in progress.
///
/// Deliberately not a single object owning both ledgers: the two ledgers belong
/// to different operators and neither party can reach both. Modelling it as one
/// object would make the impossible easy to write and the hard part invisible.
pub struct Swap {
    pub adaptor_point: RistrettoPoint,
    /// Present only for the party that drew the secret --- the one who moves
    /// first. The other side learns it by reading the first ledger.
    pub secret: Option<Scalar>,
}

impl Swap {
    /// The side that draws the secret and therefore moves first.
    pub fn proposer<R: RngCore + CryptoRng>(rng: &mut R) -> (Swap, Adaptor) {
        let adaptor = Adaptor::random(rng);
        (
            Swap {
                adaptor_point: adaptor.point,
                secret: Some(adaptor.secret),
            },
            adaptor,
        )
    }

    /// The side that is told the adaptor point and has to wait for the secret.
    pub fn responder(adaptor_point: RistrettoPoint) -> Swap {
        Swap {
            adaptor_point,
            secret: None,
        }
    }

    /// Put a payer's money into escrow and produce the authority to release it.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare<R: RngCore + CryptoRng>(
        &self,
        ledger: &mut Ledger,
        id: &[u8],
        payer: &[u8],
        payee: &[u8],
        signing_key: &Scalar,
        transfer: &Transfer,
        context: &[u8],
        amount_bounded: bool,
        deadline: u64,
        rng: &mut R,
    ) -> Result<Leg, &'static str> {
        let release_key = adaptor::public_key(signing_key);
        ledger.prepare_transfer(
            id,
            payer,
            payee,
            transfer,
            context,
            amount_bounded,
            deadline,
            &release_key,
        )?;
        Ok(Leg {
            id: id.to_vec(),
            payer: payer.to_vec(),
            payee: payee.to_vec(),
            payer_key: release_key,
            deadline,
            release: adaptor::pre_sign(signing_key, &self.adaptor_point, id, rng),
        })
    }

    /// Take the money on a leg the counterparty prepared.
    ///
    /// Only the holder of the secret can do this, which is why the party who
    /// drew it goes first. The signature it publishes is what the other side
    /// reads to learn the secret.
    pub fn claim(
        &self,
        ledger: &mut Ledger,
        leg: &Leg,
        now: u64,
    ) -> Result<Signature, &'static str> {
        let secret = self
            .secret
            .ok_or("this side does not hold the secret yet")?;
        self.claim_with(ledger, leg, &secret, now)
    }

    /// Take the money using a secret learned from the other ledger.
    pub fn claim_with(
        &self,
        ledger: &mut Ledger,
        leg: &Leg,
        secret: &Scalar,
        now: u64,
    ) -> Result<Signature, &'static str> {
        let adaptor = Adaptor {
            secret: *secret,
            point: self.adaptor_point,
        };
        let release = adaptor::adapt(&leg.release, &adaptor);
        ledger.commit_pending(&leg.id, &release, now)?;
        Ok(release)
    }

    /// Read the secret out of the signature the other side published.
    ///
    /// `leg` is the leg *this* party pre-signed --- the one the counterparty
    /// just claimed. Passing the other leg gives a scalar that is not the
    /// secret, so the mistake shows up as a refused claim and not as a loss.
    pub fn learn(&mut self, leg: &Leg, published: &Signature) -> Scalar {
        let secret = adaptor::extract(&leg.release, published);
        if adaptor::public_key(&secret) == self.adaptor_point {
            self.secret = Some(secret);
        }
        secret
    }

    /// Take an expired escrow back. Needs no secret and no counterparty.
    pub fn unwind(&self, ledger: &mut Ledger, leg: &Leg, now: u64) -> Result<(), &'static str> {
        ledger.unwind_pending(&leg.id, now)
    }

    /// How long the second mover has, given the two deadlines.
    ///
    /// Reported rather than assumed, because it is the number that decides
    /// whether the arrangement is safe and it is the one nobody writes down.
    pub fn window(first: &Leg, second: &Leg) -> Option<u64> {
        second.deadline.checked_sub(first.deadline)
    }
}
