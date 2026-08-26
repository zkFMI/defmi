//! Commitment keys over ristretto255.
//!
//! Two differences from the Python this replaces, both of which remove a class
//! of bug rather than make anything faster.
//!
//! The group is ristretto255 rather than raw ed25519. The Python backend had to
//! clear the cofactor by hand after hashing to a point, and an earlier version
//! did not: libsodium's point validation is not a subgroup check, and 39% of
//! accepted encodings were not of prime order. Ristretto has no cofactor to get
//! wrong.
//!
//! Challenges come from a Merlin transcript rather than a hand-rolled hash of
//! concatenated encodings. Framing and domain separation stop being something
//! each proof has to remember.

use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha512;

/// A commitment key: a value generator and a blinding generator whose relative
/// discrete log nobody knows.
#[derive(Clone, Debug)]
pub struct Pedersen {
    /// Carries the value. Swapped for an asset tag when a rail hides its asset.
    pub g: RistrettoPoint,
    /// Carries the blinding. Never swapped, so proofs that only speak about h
    /// stay valid across a change of value generator.
    pub h: RistrettoPoint,
}

impl Pedersen {
    /// The system key, taken from the range-proof library rather than chosen.
    ///
    /// A range proof commits under the generators the crate picks, and a
    /// settlement compares those commitments against ones we make ourselves. If
    /// the two sets differ the arithmetic still typechecks and every binding
    /// between them is vacuous, which is the failure this constructor exists to
    /// prevent. The label is kept for domain separation of anything derived
    /// from the key, not to pick generators.
    pub fn new(_label: &[u8]) -> Self {
        let gens = PedersenGens::default();
        Pedersen {
            g: gens.B,
            h: gens.B_blinding,
        }
    }

    /// A key on independently chosen generators, for uses that never meet a
    /// range proof.
    pub fn detached(label: &[u8]) -> Self {
        Pedersen {
            g: curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT,
            h: RistrettoPoint::hash_from_bytes::<Sha512>(label),
        }
    }

    /// The same key with the value carried by a different generator.
    ///
    /// Used for asset tags: q units of asset a commit as `A^q h^r`, so
    /// commitments of different assets do not combine into a valid commitment
    /// under either, and conservation holds per asset without the ledger
    /// learning which asset it holds.
    pub fn with_value_generator(&self, g: RistrettoPoint) -> Self {
        Pedersen { g, h: self.h }
    }

    pub fn commit(&self, value: &Scalar, blinding: &Scalar) -> RistrettoPoint {
        self.g * value + self.h * blinding
    }

    pub fn commit_u64(&self, value: u64, blinding: &Scalar) -> RistrettoPoint {
        self.commit(&Scalar::from(value), blinding)
    }

    pub fn random_blinding<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
        Scalar::random(rng)
    }
}

/// An asset tag: the generator that carries units of one asset.
pub fn asset_tag(asset_id: u32) -> RistrettoPoint {
    let mut input = b"qomm:defmi:asset:".to_vec();
    input.extend_from_slice(&asset_id.to_be_bytes());
    RistrettoPoint::hash_from_bytes::<Sha512>(&input)
}

/// Encode for transcripts and equality checks.
pub fn encode(point: &RistrettoPoint) -> CompressedRistretto {
    point.compress()
}

impl Pedersen {
    /// The commitment for `value - low`, with the blinding unchanged.
    pub fn shift(&self, commitment: &RistrettoPoint, low: u64) -> RistrettoPoint {
        commitment - self.g * Scalar::from(low)
    }
}
