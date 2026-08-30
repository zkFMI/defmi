//! Proof that zkPI's hidden asset field is the DeFMI security rail named by
//! the settlement order.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use qomm_zk::pedersen::Pedersen;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};

#[derive(Clone, Debug)]
pub struct AssetLinkProof {
    pub announcement: RistrettoPoint,
    pub response: Scalar,
}

pub fn asset_scalar(asset_id: &[u8; 32]) -> Scalar {
    qomm_zkpi::asset_scalar(asset_id)
}

fn challenge(
    asset_id: &[u8; 32],
    asset_commitment: &RistrettoPoint,
    residual: &RistrettoPoint,
    announcement: &RistrettoPoint,
) -> Scalar {
    let wide: [u8; 64] = Sha512::new()
        .chain_update(b"QOMM:DEFMI:ASSET-LINK:v1")
        .chain_update(asset_id)
        .chain_update(asset_commitment.compress().as_bytes())
        .chain_update(residual.compress().as_bytes())
        .chain_update(announcement.compress().as_bytes())
        .finalize()
        .into();
    Scalar::from_bytes_mod_order_wide(&wide)
}

pub fn prove<R: RngCore + CryptoRng>(
    key: &Pedersen,
    asset_id: [u8; 32],
    asset_commitment: &RistrettoPoint,
    blinding: &Scalar,
    rng: &mut R,
) -> Result<AssetLinkProof, String> {
    let value = asset_scalar(&asset_id);
    if key.commit(&value, blinding) != *asset_commitment {
        return Err("asset opening does not match the zkPI commitment".into());
    }
    let residual = asset_commitment - key.g * value;
    let nonce = Scalar::random(rng);
    let announcement = key.h * nonce;
    let response =
        nonce + challenge(&asset_id, asset_commitment, &residual, &announcement) * blinding;
    Ok(AssetLinkProof {
        announcement,
        response,
    })
}

pub fn verify(
    key: &Pedersen,
    asset_id: &[u8; 32],
    asset_commitment: &RistrettoPoint,
    proof: &AssetLinkProof,
) -> bool {
    let residual = asset_commitment - key.g * asset_scalar(asset_id);
    key.h * proof.response
        == proof.announcement
            + residual * challenge(asset_id, asset_commitment, &residual, &proof.announcement)
}

impl AssetLinkProof {
    pub fn digest(&self, asset_id: &[u8; 32], asset_commitment: &RistrettoPoint) -> [u8; 32] {
        Sha256::new()
            .chain_update(b"QOMM:DEFMI:ASSET-LINK:DIGEST:v1")
            .chain_update(asset_id)
            .chain_update(asset_commitment.compress().as_bytes())
            .chain_update(self.announcement.compress().as_bytes())
            .chain_update(self.response.as_bytes())
            .finalize()
            .into()
    }
}
