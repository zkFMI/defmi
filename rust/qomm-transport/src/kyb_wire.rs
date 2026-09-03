//! Canonical JSON-safe wire values for anonymous legal-entity membership.
//!
//! The entity service receives only a signed public cohort registry and emits
//! a zero-knowledge presentation.  The secret credential scalar never crosses
//! this boundary.  Every compressed point and scalar is decoded canonically so
//! alternate encodings cannot change a signed mandate digest.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, VerifyingKey};
use qomm_proofs::kyb::{KybPresentation, SignedCohortRegistry};
use qomm_zk::or_dleq::Proof;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KybRegistryWire {
    pub cohort: String,
    pub registry_epoch: u64,
    pub expires_at: u64,
    pub points: Vec<String>,
    pub issuer: String,
    pub registry_id: String,
    pub signature: String,
}

impl KybRegistryWire {
    pub fn from_registry(registry: &SignedCohortRegistry) -> Self {
        Self {
            cohort: registry.cohort.clone(),
            registry_epoch: registry.registry_epoch,
            expires_at: registry.expires_at,
            points: registry
                .points
                .iter()
                .map(|point| hex::encode(point.compress().to_bytes()))
                .collect(),
            issuer: hex::encode(registry.issuer.to_bytes()),
            registry_id: hex::encode(registry.registry_id),
            signature: hex::encode(registry.signature.to_bytes()),
        }
    }

    pub fn into_registry(self) -> Result<SignedCohortRegistry, String> {
        if self.cohort.trim().is_empty() || self.points.is_empty() {
            return Err("KYB registry has no cohort or members".into());
        }
        Ok(SignedCohortRegistry {
            cohort: self.cohort,
            registry_epoch: self.registry_epoch,
            expires_at: self.expires_at,
            points: self
                .points
                .iter()
                .enumerate()
                .map(|(index, point)| decode_point(point, &format!("KYB registry point {index}")))
                .collect::<Result<Vec<_>, _>>()?,
            issuer: VerifyingKey::from_bytes(&decode_fixed(&self.issuer, "KYB registry issuer")?)
                .map_err(|_| "KYB registry issuer is not canonical Ed25519".to_string())?,
            registry_id: decode_fixed(&self.registry_id, "KYB registry id")?,
            signature: Signature::from_bytes(&decode_fixed(
                &self.signature,
                "KYB registry signature",
            )?),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KybPresentationWire {
    pub cohort: String,
    pub registry_id: String,
    pub scope: String,
    pub context_hash: String,
    pub nullifier: String,
    pub challenges: Vec<String>,
    pub responses: Vec<String>,
}

impl KybPresentationWire {
    pub fn from_presentation(presentation: &KybPresentation) -> Self {
        Self {
            cohort: presentation.cohort.clone(),
            registry_id: hex::encode(presentation.registry_id),
            scope: hex::encode(&presentation.scope),
            context_hash: hex::encode(presentation.context_hash),
            nullifier: hex::encode(presentation.proof.nullifier.compress().to_bytes()),
            challenges: presentation
                .proof
                .challenges
                .iter()
                .map(|scalar| hex::encode(scalar.to_bytes()))
                .collect(),
            responses: presentation
                .proof
                .responses
                .iter()
                .map(|scalar| hex::encode(scalar.to_bytes()))
                .collect(),
        }
    }

    pub fn into_presentation(self) -> Result<KybPresentation, String> {
        if self.cohort.trim().is_empty()
            || self.challenges.is_empty()
            || self.challenges.len() != self.responses.len()
        {
            return Err("KYB presentation has an invalid proof population".into());
        }
        Ok(KybPresentation {
            cohort: self.cohort,
            registry_id: decode_fixed(&self.registry_id, "KYB presentation registry id")?,
            scope: hex::decode(&self.scope)
                .map_err(|_| "KYB presentation scope is not hexadecimal".to_string())?,
            context_hash: decode_fixed(&self.context_hash, "KYB presentation context")?,
            proof: Proof {
                nullifier: decode_point(&self.nullifier, "KYB presentation nullifier")?,
                challenges: self
                    .challenges
                    .iter()
                    .enumerate()
                    .map(|(index, scalar)| decode_scalar(scalar, &format!("KYB challenge {index}")))
                    .collect::<Result<Vec<_>, _>>()?,
                responses: self
                    .responses
                    .iter()
                    .enumerate()
                    .map(|(index, scalar)| decode_scalar(scalar, &format!("KYB response {index}")))
                    .collect::<Result<Vec<_>, _>>()?,
            },
        })
    }
}

fn decode_fixed<const N: usize>(value: &str, name: &str) -> Result<[u8; N], String> {
    hex::decode(value)
        .map_err(|_| format!("{name} must be {N}-byte hexadecimal"))?
        .try_into()
        .map_err(|_| format!("{name} must be {N}-byte hexadecimal"))
}

fn decode_point(value: &str, name: &str) -> Result<RistrettoPoint, String> {
    CompressedRistretto(decode_fixed(value, name)?)
        .decompress()
        .ok_or_else(|| format!("{name} is not a canonical Ristretto point"))
}

fn decode_scalar(value: &str, name: &str) -> Result<Scalar, String> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(decode_fixed(value, name)?))
        .ok_or_else(|| format!("{name} is not a canonical scalar"))
}
