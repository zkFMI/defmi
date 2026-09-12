//! Confidential asset generators and a bounded OR of Schnorr relations.
//!
//! For one SAME registry position i, prove knowledge of gamma and rho such
//! that T - A_i = gamma H and C_asset - asset_scalar(i) G = rho H.
//! The second relation is optional for issuance/ordinary transfers. It is
//! mandatory when linking a zkPI instruction. Independent membership proofs
//! for the two columns would allow asset substitution and are NOT sufficient.
//!
//! This is the CDS OR composition, with a shared challenge per branch, not a
//! new membership algorithm. Reference: https://ir.cwi.nl/pub/1456/1456D.pdf.
//! Asset generators follow the confidential-assets construction described at
//! https://elementsproject.org/features/issued-assets/investigation, adapted
//! to the existing Ristretto rail. No Elements code is imported. This adapter
//! is research code, has not received an independent cryptographic audit, and
//! is not post-quantum. Amount/ring proofs retain their existing upstream cores.

use curve25519_dalek::traits::Identity;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use zkfmi_zk::pedersen::Pedersen;

pub const MAX_ASSETS: usize = 64;

pub fn generator(asset: &[u8; 32]) -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(
        &[b"DEFMI:CONFIDENTIAL-ASSET:GENERATOR:v1".as_slice(), asset].concat(),
    )
}

pub fn point(bytes: &[u8; 32]) -> Result<RistrettoPoint, String> {
    CompressedRistretto(*bytes)
        .decompress()
        .filter(|p| *p != RistrettoPoint::identity())
        .ok_or_else(|| "confidential asset point is malformed or identity".into())
}

pub fn scalar(bytes: &[u8; 32]) -> Result<Scalar, String> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
        .ok_or_else(|| "confidential asset scalar is not canonical".into())
}

/// The entire public eligible cohort. Never pad with unregistered assets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Registry {
    pub assets: Vec<[u8; 32]>,
}

impl Registry {
    pub fn validate(&self) -> Result<(), String> {
        if self.assets.len() < 2
            || self.assets.len() > MAX_ASSETS
            || self.assets.contains(&[0; 32])
            || self.assets.windows(2).any(|p| p[0] >= p[1])
        {
            return Err(
                "asset anonymity cohort must contain 2..64 sorted unique registered assets".into(),
            );
        }
        Ok(())
    }

    pub fn root(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"DEFMI:CONFIDENTIAL-ASSET:REGISTRY:v1");
        hash.update((self.assets.len() as u64).to_be_bytes());
        for id in &self.assets {
            hash.update(id);
        }
        Ok(hash.finalize().into())
    }

    pub fn blind<R: RngCore + CryptoRng>(
        &self,
        key: &Pedersen,
        asset: &[u8; 32],
        rng: &mut R,
    ) -> Result<(RistrettoPoint, Scalar), String> {
        self.validate()?;
        self.assets
            .binary_search(asset)
            .map_err(|_| "asset is outside the registered cohort")?;
        loop {
            let gamma = Scalar::random(rng);
            let tag = generator(asset) + key.h * gamma;
            if tag != RistrettoPoint::identity() {
                return Ok((tag, gamma));
            }
        }
    }
}

/// Announcements are reconstructed as H z - residual c. Canonical scalars
/// and the exact registry size are checked before any group operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssetProof {
    pub challenges: Vec<[u8; 32]>,
    pub tag_responses: Vec<[u8; 32]>,
    pub instruction_responses: Vec<[u8; 32]>,
}

fn challenge(
    key: &Pedersen,
    registry: &Registry,
    tag: &RistrettoPoint,
    instruction: Option<&RistrettoPoint>,
    context: &[u8],
    announcements: &[(RistrettoPoint, Option<RistrettoPoint>)],
) -> Result<Scalar, String> {
    let mut hash = Sha512::new();
    hash.update(b"DEFMI:CONFIDENTIAL-ASSET:CDS-OR:v1");
    hash.update(key.g.compress().as_bytes());
    hash.update(key.h.compress().as_bytes());
    hash.update(registry.root()?);
    hash.update(tag.compress().as_bytes());
    hash.update([u8::from(instruction.is_some())]);
    if let Some(c) = instruction {
        hash.update(c.compress().as_bytes());
    }
    hash.update((context.len() as u64).to_be_bytes());
    hash.update(context);
    for (a, b) in announcements {
        hash.update(a.compress().as_bytes());
        if let Some(b) = b {
            hash.update(b.compress().as_bytes());
        }
    }
    Ok(Scalar::from_bytes_mod_order_wide(&hash.finalize().into()))
}

impl AssetProof {
    #[allow(clippy::too_many_arguments)]
    pub fn prove<R: RngCore + CryptoRng>(
        key: &Pedersen,
        registry: &Registry,
        asset: &[u8; 32],
        tag: &RistrettoPoint,
        gamma: &Scalar,
        instruction: Option<(&RistrettoPoint, &Scalar)>,
        context: &[u8],
        rng: &mut R,
    ) -> Result<Self, String> {
        registry.validate()?;
        point(&tag.compress().to_bytes())?;
        let selected = registry
            .assets
            .binary_search(asset)
            .map_err(|_| "asset is not registered")?;
        if *tag != generator(asset) + key.h * gamma {
            return Err("asset tag witness does not match".into());
        }
        if let Some((c, rho)) = instruction {
            if *c != key.commit(&zkpi::asset_scalar(asset), rho) {
                return Err("instruction and tag do not open to the same asset".into());
            }
        }
        let n = registry.assets.len();
        let mut cs = vec![Scalar::ZERO; n];
        let mut zs = vec![Scalar::ZERO; n];
        let mut ws = instruction
            .map(|_| vec![Scalar::ZERO; n])
            .unwrap_or_default();
        let mut announcements = Vec::with_capacity(n);
        let k = Scalar::random(rng);
        let l = Scalar::random(rng);
        for (i, id) in registry.assets.iter().enumerate() {
            if i == selected {
                announcements.push((key.h * k, instruction.map(|_| key.h * l)));
            } else {
                cs[i] = Scalar::random(rng);
                zs[i] = Scalar::random(rng);
                let first = key.h * zs[i] - (tag - generator(id)) * cs[i];
                let second = instruction.map(|(c, _)| {
                    ws[i] = Scalar::random(rng);
                    key.h * ws[i] - (c - key.g * zkpi::asset_scalar(id)) * cs[i]
                });
                announcements.push((first, second));
            }
        }
        cs[selected] = challenge(
            key,
            registry,
            tag,
            instruction.map(|(c, _)| c),
            context,
            &announcements,
        )? - cs.iter().sum::<Scalar>();
        zs[selected] = k + cs[selected] * gamma;
        if let Some((_, rho)) = instruction {
            ws[selected] = l + cs[selected] * rho;
        }
        Ok(Self {
            challenges: cs.iter().map(Scalar::to_bytes).collect(),
            tag_responses: zs.iter().map(Scalar::to_bytes).collect(),
            instruction_responses: ws.iter().map(Scalar::to_bytes).collect(),
        })
    }

    pub fn verify(
        &self,
        key: &Pedersen,
        registry: &Registry,
        tag: &RistrettoPoint,
        instruction: Option<&RistrettoPoint>,
        context: &[u8],
    ) -> Result<(), String> {
        registry.validate()?;
        point(&tag.compress().to_bytes())?;
        let n = registry.assets.len();
        if self.challenges.len() != n
            || self.tag_responses.len() != n
            || self.instruction_responses.len() != if instruction.is_some() { n } else { 0 }
        {
            return Err("asset proof dimensions differ from the registered cohort".into());
        }
        let mut sum = Scalar::ZERO;
        let mut announcements = Vec::with_capacity(n);
        for (i, id) in registry.assets.iter().enumerate() {
            let c = scalar(&self.challenges[i])?;
            let z = scalar(&self.tag_responses[i])?;
            sum += c;
            let first = key.h * z - (tag - generator(id)) * c;
            let second = if let Some(commitment) = instruction {
                Some(
                    key.h * scalar(&self.instruction_responses[i])?
                        - (commitment - key.g * zkpi::asset_scalar(id)) * c,
                )
            } else {
                None
            };
            announcements.push((first, second));
        }
        if sum != challenge(key, registry, tag, instruction, context, &announcements)? {
            return Err("confidential asset membership/link proof failed".into());
        }
        Ok(())
    }
}
