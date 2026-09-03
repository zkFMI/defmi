//! Quorum certificate for privacy-preserving public market statistics.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const DOMAIN: &[u8] = b"QOMM:PUBLICATION-CERTIFICATE:v1";
pub const ZERO: [u8; 32] = [0; 32];

/// Public evidence written by one MPC node's local supervisor after that node
/// has observed the distributed release. It contains no contribution or exact
/// aggregate. A publication signer reads only its own private copy and signs
/// when every binding agrees with the proposed public statement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodePublicationEvidence {
    pub version: u8,
    pub node_id: String,
    pub operation_id: [u8; 32],
    pub epoch: u64,
    pub slot_start: u64,
    pub slot_end: u64,
    pub source_digest: [u8; 32],
    pub rule_digest: [u8; 32],
    pub mechanism_digest: [u8; 32],
    pub private_input_commitment: [u8; 32],
    pub transcript_digest: [u8; 32],
    pub output_name: String,
    pub output_value: i64,
}

impl NodePublicationEvidence {
    pub fn validate_for(
        &self,
        node_id: &str,
        statement: &PublicationStatement,
        mechanism: &crate::distributed_dp::DpMechanism,
    ) -> Result<(), String> {
        statement.validate_against(mechanism)?;
        if self.version != 1 || self.node_id != node_id {
            return Err("publication evidence belongs to another node or version".into());
        }
        if self.operation_id != statement.operation_id
            || self.epoch != statement.epoch
            || self.slot_start != statement.slot_start
            || self.slot_end != statement.slot_end
            || self.source_digest != statement.source_digest
            || self.rule_digest != statement.rule_digest
            || self.mechanism_digest != statement.mechanism_digest
            || self.private_input_commitment != statement.private_input_commitment
            || self.transcript_digest != statement.transcript_digest
            || self.output_name != statement.output_name
            || self.output_value != statement.output_value
        {
            return Err("publication statement differs from node-local MPC evidence".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicationStatement {
    pub operation_id: [u8; 32],
    /// Stable pseudonymous legal-entity/group scope whose privacy budget is
    /// consumed. It is not a wallet address and reveals no company name.
    pub budget_scope: [u8; 32],
    pub venue: String,
    pub epoch: u64,
    pub slot_start: u64,
    pub slot_end: u64,
    pub source_digest: [u8; 32],
    pub rule_digest: [u8; 32],
    pub mechanism_digest: [u8; 32],
    pub private_input_commitment: [u8; 32],
    pub transcript_digest: [u8; 32],
    pub output_name: String,
    pub output_value: i64,
    pub epsilon_micros: u64,
    pub delta_numerator: u64,
    pub delta_denominator: u128,
    pub budget_total_micros: u64,
    pub budget_before_micros: u64,
    pub budget_after_micros: u64,
    pub previous_certificate: [u8; 32],
}

impl PublicationStatement {
    pub fn validate(&self) -> Result<(), String> {
        if self.venue.is_empty() || self.output_name.is_empty() {
            return Err("venue and output name are required".into());
        }
        if self.slot_end < self.slot_start {
            return Err("invalid epoch or slot range".into());
        }
        if self.epsilon_micros == 0 {
            return Err("epsilon must be positive".into());
        }
        if [
            self.operation_id,
            self.budget_scope,
            self.source_digest,
            self.rule_digest,
            self.mechanism_digest,
            self.private_input_commitment,
            self.transcript_digest,
        ]
        .contains(&ZERO)
        {
            return Err("publication statement contains an unbound digest".into());
        }
        if self.delta_denominator == 0 || u128::from(self.delta_numerator) >= self.delta_denominator
        {
            return Err("delta must be a proper non-negative fraction".into());
        }
        if self.budget_before_micros > self.budget_after_micros
            || self.budget_after_micros > self.budget_total_micros
        {
            return Err("invalid privacy budget transition".into());
        }
        if self.budget_after_micros - self.budget_before_micros != self.epsilon_micros {
            return Err("privacy budget transition does not equal epsilon spent".into());
        }
        Ok(())
    }

    /// Everything `validate` checks, and then whether the parameters carried
    /// belong to the mechanism the statement names.
    ///
    /// `validate` alone checks that `delta` is a proper fraction, which a
    /// statement carrying `rounding_delta` -- the distance between the released
    /// cells and the law they approximate, ten orders of magnitude below the
    /// privacy parameter at support 8 -- satisfies perfectly well. That is how
    /// such a statement came to be built and signed. A digest cannot be
    /// recomputed into a delta, so the mechanism has to be supplied.
    pub fn validate_against(
        &self,
        mechanism: &crate::distributed_dp::DpMechanism,
    ) -> Result<(), String> {
        self.validate()?;
        if self.mechanism_digest != mechanism.digest() {
            return Err("statement does not name this mechanism".into());
        }
        if self.epsilon_micros != mechanism.epsilon_micros {
            return Err("statement epsilon does not match the mechanism".into());
        }
        let carried = self.delta_numerator as f64 / self.delta_denominator as f64;
        let required = mechanism.privacy_delta()?;
        if carried < required {
            return Err(format!(
                "statement carries delta {carried:e} below the mechanism's {required:e}"
            ));
        }
        Ok(())
    }

    pub fn body(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let value = json!({
            "operation_id": hex::encode(self.operation_id),
            "budget_scope": hex::encode(self.budget_scope),
            "venue": self.venue,
            "epoch": self.epoch,
            "slot_start": self.slot_start,
            "slot_end": self.slot_end,
            "source_digest": hex::encode(self.source_digest),
            "rule_digest": hex::encode(self.rule_digest),
            "mechanism_digest": hex::encode(self.mechanism_digest),
            "private_input_commitment": hex::encode(self.private_input_commitment),
            "transcript_digest": hex::encode(self.transcript_digest),
            "output_name": self.output_name,
            "output_value": self.output_value,
            "epsilon_micros": self.epsilon_micros,
            "delta_numerator": self.delta_numerator,
            "delta_denominator": self.delta_denominator,
            "budget_total_micros": self.budget_total_micros,
            "budget_before_micros": self.budget_before_micros,
            "budget_after_micros": self.budget_after_micros,
            "previous_certificate": hex::encode(self.previous_certificate),
        });
        let mut body = DOMAIN.to_vec();
        body.extend(serde_json::to_vec(&value).map_err(|error| error.to_string())?);
        Ok(body)
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        Ok(Sha256::digest(self.body()?).into())
    }
}

#[derive(Clone, Debug)]
pub struct NodeSignature {
    pub node_id: String,
    pub signature: Signature,
}

#[derive(Clone, Debug)]
pub struct PublicationCertificate {
    pub statement: PublicationStatement,
    pub signatures: Vec<NodeSignature>,
}

impl PublicationCertificate {
    pub fn digest(&self) -> Result<[u8; 32], String> {
        let mut hash = Sha256::new();
        hash.update(self.statement.body()?);
        let mut signatures = self.signatures.clone();
        signatures.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        for signed in signatures {
            hash.update(signed.node_id.as_bytes());
            hash.update(signed.signature.to_bytes());
        }
        Ok(hash.finalize().into())
    }

    pub fn verify(
        &self,
        registry: &BTreeMap<String, VerifyingKey>,
        threshold: usize,
        previous: Option<&PublicationCertificate>,
    ) -> bool {
        if self.statement.validate().is_err() || !(1..=registry.len()).contains(&threshold) {
            return false;
        }
        match previous {
            None if self.statement.previous_certificate != ZERO => return false,
            Some(previous)
                if previous.digest().ok() != Some(self.statement.previous_certificate)
                    || self.statement.epoch <= previous.statement.epoch
                    || self.statement.budget_before_micros
                        != previous.statement.budget_after_micros
                    || self.statement.budget_scope != previous.statement.budget_scope
                    || self.statement.venue != previous.statement.venue
                    || self.statement.output_name != previous.statement.output_name
                    || self.statement.budget_total_micros
                        != previous.statement.budget_total_micros =>
            {
                return false;
            }
            Some(_) => {}
            None => {}
        }
        let Ok(body) = self.statement.body() else {
            return false;
        };
        let mut seen = BTreeSet::new();
        self.signatures
            .iter()
            .filter(|signed| {
                seen.insert(signed.node_id.clone())
                    && registry
                        .get(&signed.node_id)
                        .is_some_and(|key| key.verify(&body, &signed.signature).is_ok())
            })
            .count()
            >= threshold
    }
}

pub fn certify(
    statement: PublicationStatement,
    signers: &BTreeMap<String, SigningKey>,
) -> Result<PublicationCertificate, String> {
    let body = statement.body()?;
    Ok(PublicationCertificate {
        statement,
        signatures: signers
            .iter()
            .map(|(node_id, key)| NodeSignature {
                node_id: node_id.clone(),
                signature: key.sign(&body),
            })
            .collect(),
    })
}
