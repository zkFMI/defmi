//! Asset tags the settlement layer can carry but cannot read.
//!
//! A balance of q units of asset a commits as `A_a^q h^r`. Commitments under
//! different tags do not combine into a valid commitment under either, so
//! conservation holds per asset even though the ledger only ever checks one
//! aggregate product --- not because it looks, but because a prover would need
//! a discrete log between independent generators to make the remainder proof
//! go through.
//!
//! The tag is blinded per transfer, `H = A_a h^gamma`, and every range proof is
//! stated against H. The binding to the real asset is the remainder proof: the
//! payer's balance already sits under `A_a`, and no other tag lets the
//! difference open to a value in range.
//!
//! Issuance is the one place that needs more. Anyone can invent a point and
//! call it an asset, so opening an account with a non-zero balance carries a
//! one-out-of-many proof that its tag is registered. That is paid once per
//! account, not once per settlement.

use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_zk::oneofmany::{self, GkProof};
use qomm_zk::pedersen::{asset_tag, Pedersen};
use rand_core::{CryptoRng, RngCore};

#[derive(Clone)]
pub struct BlindedTag {
    pub point: RistrettoPoint,
    pub membership: Option<GkProof>,
}

impl BlindedTag {
    pub fn key_for(&self, key: &Pedersen) -> Pedersen {
        key.with_value_generator(self.point)
    }

    /// Range proofs are stated against the tag, which the audited crate accepts
    /// as a value generator without modification.
    pub fn gens(&self, key: &Pedersen) -> PedersenGens {
        PedersenGens {
            B: self.point,
            B_blinding: key.h,
        }
    }
}

pub struct AssetRegistry {
    pub key: Pedersen,
    pub count: u32,
    pub tags: Vec<RistrettoPoint>,
}

impl AssetRegistry {
    /// Padded to a power of two: the one-out-of-many proof needs it, and a set
    /// that grew whenever an asset was listed would leak the listing.
    pub fn new(key: Pedersen, count: u32) -> Self {
        assert!(count >= 1, "a registry needs at least one asset");
        let size = (count as usize).next_power_of_two().max(2);
        let tags = (0..size as u32).map(asset_tag).collect();
        AssetRegistry { key, count, tags }
    }

    pub fn size(&self) -> usize {
        self.tags.len()
    }

    pub fn blind<R: RngCore + CryptoRng>(
        &self,
        asset_id: u32,
        prove_membership: bool,
        rng: &mut R,
    ) -> Result<(BlindedTag, Scalar), &'static str> {
        if asset_id >= self.count {
            return Err("asset is not registered");
        }
        let gamma = Scalar::random(rng);
        let point = self.tags[asset_id as usize] + self.key.h * gamma;
        let membership = if prove_membership {
            Some(oneofmany::prove(
                &self.key,
                &mut Transcript::new(b"qomm:asset"),
                &self.quotients(&point),
                asset_id as usize,
                &gamma,
                rng,
            )?)
        } else {
            None
        };
        Ok((BlindedTag { point, membership }, gamma))
    }

    /// `H / A_i`, which is `h^gamma` at exactly the registered index.
    fn quotients(&self, point: &RistrettoPoint) -> Vec<RistrettoPoint> {
        self.tags.iter().map(|tag| point - tag).collect()
    }

    pub fn verify_membership(&self, tag: &BlindedTag) -> bool {
        match &tag.membership {
            None => false,
            Some(proof) => oneofmany::verify(
                &self.key,
                &mut Transcript::new(b"qomm:asset"),
                &self.quotients(&tag.point),
                proof,
            ),
        }
    }
}
