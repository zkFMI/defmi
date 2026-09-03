//! Per-venue handles: one firm, unrelated points at every venue it uses.
//!
//! An instruction names who pays and who is paid. If it named a firm the same
//! way everywhere, then two venues' logs join on it, and everything the rest of
//! this system spends its cost hiding is recovered by reading two ledgers side
//! by side. So the handle has to be per venue, and two of one firm's handles
//! have to be unlinkable to anyone who does not hold its seed.
//!
//! This was stated as a property of the design before it was code. It is code
//! now because a property nothing implements is a property nobody has: the
//! obvious integration --- use the same account name at both venues --- is what
//! a caller reaches for when the library offers nothing else, and it defeats
//! the whole construction. Measured, it lets an observer join two legs of a
//! cross-venue exchange with certainty.
//!
//! The scheme is the boring one: `s_V = H(seed, venue)`, `H_V = g^{s_V}`. The
//! seed never leaves the firm; each handle is an independent-looking point; the
//! firm can prove control of any of them because it can recompute `s_V`.
//!
//! What it is deliberately *not* is the scheme that suggests itself first ---
//! one secret `a` scaled by a public per-venue factor, `H_V = g^{a h(V)}`. That
//! one is publicly linkable: `H_A^{h(B)} == H_B^{h(A)}` holds exactly when the
//! two handles belong to the same firm, and anybody can run it. There is a test
//! below that does run it, on both schemes, so the trap is recorded rather than
//! only avoided.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

pub const HANDLE_DOMAIN: &[u8] = b"QOMM:ZKPI:HANDLE:v1";

/// What a firm keeps. One seed for all venues; nothing per venue is stored.
#[derive(Clone)]
pub struct Identity {
    seed: [u8; 32],
}

/// What a venue sees, and what its owner needs to spend under it.
#[derive(Clone, Copy, Debug)]
pub struct Handle {
    pub point: RistrettoPoint,
    /// Held by the firm alone. Present here because the owner needs it; a
    /// venue is given `point` and never this.
    pub secret: Scalar,
}

impl Handle {
    /// The bytes a ledger keys an account by. A ledger takes an opaque
    /// identifier, and this is the only one that should ever be given to it:
    /// anything else --- a firm name, a wallet address, an account number --- is
    /// the same identifier at two venues.
    pub fn account(&self) -> Vec<u8> {
        self.point.compress().as_bytes().to_vec()
    }
}

impl Identity {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Identity {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Identity { seed }
    }

    pub fn from_seed(seed: [u8; 32]) -> Identity {
        Identity { seed }
    }

    /// The handle this firm uses at one venue.
    ///
    /// Deterministic, so nothing has to be stored per venue and a lost record
    /// is recoverable from the seed. `venue` is whatever names the deployment
    /// --- a contract address, a chain id and address, a registered name --- and
    /// two venues that share it share a handle, which is the one way to get
    /// this wrong.
    pub fn handle(&self, venue: &[u8]) -> Handle {
        let mut hasher = Sha512::new();
        hasher.update(HANDLE_DOMAIN);
        hasher.update(self.seed);
        hasher.update((venue.len() as u64).to_be_bytes());
        hasher.update(venue);
        let secret = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());
        Handle {
            point: &secret * RISTRETTO_BASEPOINT_TABLE,
            secret,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn public_scale(venue: &[u8]) -> Scalar {
        let mut h = Sha512::new();
        h.update(b"public venue factor");
        h.update(venue);
        Scalar::from_bytes_mod_order_wide(&h.finalize().into())
    }

    #[test]
    fn one_firm_gets_a_different_handle_at_each_venue() {
        let firm = Identity::new(&mut OsRng);
        let a = firm.handle(b"venue-jpy");
        let b = firm.handle(b"venue-usd");
        assert_ne!(a.point, b.point);
        assert_ne!(a.account(), b.account());
    }

    #[test]
    fn the_same_venue_gives_the_same_handle_back() {
        let firm = Identity::from_seed([7u8; 32]);
        assert_eq!(
            firm.handle(b"venue-jpy").point,
            firm.handle(b"venue-jpy").point
        );
        assert_eq!(
            Identity::from_seed([7u8; 32]).handle(b"v").point,
            firm.handle(b"v").point
        );
    }

    #[test]
    fn a_handle_is_a_key_its_owner_can_prove() {
        let firm = Identity::new(&mut OsRng);
        let h = firm.handle(b"venue-jpy");
        assert_eq!(&h.secret * RISTRETTO_BASEPOINT_TABLE, h.point);
    }

    /// The trap, run rather than described. A scheme that scales one secret by
    /// a public per-venue factor is linkable by anyone: the cross-multiplied
    /// points agree exactly when the two handles are one firm's.
    #[test]
    fn the_multiplicative_scheme_is_publicly_linkable_and_this_one_is_not() {
        let (va, vb) = (b"venue-jpy".as_slice(), b"venue-usd".as_slice());
        let (fa, fb) = (public_scale(va), public_scale(vb));

        // the trap
        let a = Scalar::random(&mut OsRng);
        let (bad_a, bad_b) = (
            &(a * fa) * RISTRETTO_BASEPOINT_TABLE,
            &(a * fb) * RISTRETTO_BASEPOINT_TABLE,
        );
        let other = Scalar::random(&mut OsRng);
        let bad_other = &(other * fb) * RISTRETTO_BASEPOINT_TABLE;
        assert_eq!(bad_a * fb, bad_b * fa, "same firm, and anyone can tell");
        assert_ne!(
            bad_a * fb,
            bad_other * fa,
            "different firms, and anyone can tell"
        );

        // what is actually used: the same test says nothing
        let firm = Identity::new(&mut OsRng);
        let (good_a, good_b) = (firm.handle(va).point, firm.handle(vb).point);
        assert_ne!(good_a * fb, good_b * fa);
    }

    #[test]
    fn two_firms_handles_at_one_venue_are_distinct() {
        let (one, two) = (Identity::new(&mut OsRng), Identity::new(&mut OsRng));
        assert_ne!(one.handle(b"v").point, two.handle(b"v").point);
    }
}
