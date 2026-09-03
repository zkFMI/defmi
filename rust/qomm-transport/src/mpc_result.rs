//! Canonical resident-node attestations for the public, Taker-masked MPC result.
//!
//! These receipts are deliberately smaller than the settlement proof handoff.
//! They let DeFMI verify a no-fill release under the governance-pinned seven-node
//! committee without learning the rejected quote, Taker limit, pricing policy,
//! inventory, or any MPC share.

use crate::order::{cluster_batch_digest, COMMITTEE_NODES};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

const NODE_RESULT_DOMAIN: &[u8] = b"QOMM:MPC:PUBLIC-RESULT-NODE:v1";
const RESULT_LANE_DOMAIN: &[u8] = b"QOMM:MPC:PUBLIC-RESULT-LANE:v1";
const MASK_COMMITMENT_DOMAIN: &[u8] = b"QOMM:MPC:FILL-MASK-COMMITMENT:v1";
const WIRE_MAGIC: &[u8; 8] = b"QOMMRES1";
const RECORD_BYTES: usize = 2 + 8 + 8 + 32 * 5 + 16 + 16 + 64;
const ZERO: [u8; 32] = [0; 32];

/// Commitment signed by the Taker before its RFQ reaches any MPC node.
pub fn fill_mask_commitment(fill_mask: u64) -> [u8; 32] {
    fill_mask_scalar_commitment(Scalar::from(fill_mask).to_bytes())
}

pub fn fill_mask_scalar_commitment(fill_mask: [u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(MASK_COMMITMENT_DOMAIN)
        .chain_update(fill_mask)
        .finalize()
        .into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePublicResultAttestation {
    pub node: u16,
    pub slot: u64,
    pub sequence: u64,
    pub batch_digest: [u8; 32],
    pub source_digest: [u8; 32],
    pub round_digest: [u8; 32],
    pub masked_key: i128,
    pub masked_fill: i128,
    pub stdout_digest: [u8; 32],
    pub persistence_digest: [u8; 32],
    pub signature: Signature,
}

impl NodePublicResultAttestation {
    pub fn unsigned(&self) -> Result<Vec<u8>, String> {
        if usize::from(self.node) >= COMMITTEE_NODES
            || self.sequence == 0
            || [
                self.batch_digest,
                self.source_digest,
                self.round_digest,
                self.stdout_digest,
                self.persistence_digest,
            ]
            .contains(&ZERO)
        {
            return Err("public MPC result attestation is incomplete".into());
        }
        let mut body = Vec::with_capacity(NODE_RESULT_DOMAIN.len() + RECORD_BYTES - 64);
        body.extend_from_slice(NODE_RESULT_DOMAIN);
        body.extend_from_slice(&self.node.to_be_bytes());
        body.extend_from_slice(&self.slot.to_be_bytes());
        body.extend_from_slice(&self.sequence.to_be_bytes());
        body.extend_from_slice(&self.batch_digest);
        body.extend_from_slice(&self.source_digest);
        body.extend_from_slice(&self.round_digest);
        body.extend_from_slice(&self.masked_key.to_be_bytes());
        body.extend_from_slice(&self.masked_fill.to_be_bytes());
        body.extend_from_slice(&self.stdout_digest);
        body.extend_from_slice(&self.persistence_digest);
        Ok(body)
    }

    pub fn sign(mut self, key: &SigningKey) -> Result<Self, String> {
        self.signature = key.sign(&self.unsigned()?);
        Ok(self)
    }

    pub fn verify(&self, key: &VerifyingKey) -> bool {
        self.unsigned()
            .is_ok_and(|body| key.verify(&body, &self.signature).is_ok())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedPublicResult {
    pub slot: u64,
    pub sequence: u64,
    pub cluster_digest: [u8; 32],
    pub source_digest: [u8; 32],
    pub round_digest: [u8; 32],
    pub masked_key: i128,
    pub masked_fill: i128,
    pub digest: [u8; 32],
}

pub fn verify_public_result_lane(
    attestations: &[NodePublicResultAttestation],
    trusted_node_keys: &[VerifyingKey],
    order_digest: [u8; 32],
) -> Result<CertifiedPublicResult, String> {
    if attestations.len() != COMMITTEE_NODES || trusted_node_keys.len() != COMMITTEE_NODES {
        return Err("public MPC result needs exactly seven attestations and trusted keys".into());
    }
    let mut ordered = attestations.to_vec();
    ordered.sort_by_key(|value| value.node);
    for (expected, value) in ordered.iter().enumerate() {
        if usize::from(value.node) != expected || !value.verify(&trusted_node_keys[expected]) {
            return Err("public MPC result contains an unknown, duplicate, or invalid node".into());
        }
    }
    let first = &ordered[0];
    if ordered.iter().skip(1).any(|value| {
        value.slot != first.slot
            || value.sequence != first.sequence
            || value.source_digest != first.source_digest
            || value.round_digest != first.round_digest
            || value.masked_key != first.masked_key
            || value.masked_fill != first.masked_fill
    }) {
        return Err("resident nodes disagree on the public MPC result or execution scope".into());
    }
    let slot = u32::try_from(first.slot)
        .map_err(|_| "public MPC result slot is outside u32".to_string())?;
    let node_batches = ordered
        .iter()
        .map(|value| (value.node, value.batch_digest))
        .collect::<Vec<_>>();
    let cluster_digest = cluster_batch_digest(slot, order_digest, &node_batches)?;
    let mut hash = Sha256::new();
    hash.update(RESULT_LANE_DOMAIN);
    hash.update(first.slot.to_be_bytes());
    hash.update(first.sequence.to_be_bytes());
    hash.update(cluster_digest);
    hash.update(first.source_digest);
    hash.update(first.round_digest);
    hash.update(first.masked_key.to_be_bytes());
    hash.update(first.masked_fill.to_be_bytes());
    for value in &ordered {
        hash.update(value.signature.to_bytes());
    }
    Ok(CertifiedPublicResult {
        slot: first.slot,
        sequence: first.sequence,
        cluster_digest,
        source_digest: first.source_digest,
        round_digest: first.round_digest,
        masked_key: first.masked_key,
        masked_fill: first.masked_fill,
        digest: hash.finalize().into(),
    })
}

fn encode_wire(
    values: &[NodePublicResultAttestation],
    require_full_bundle_order: bool,
) -> Result<Vec<u8>, String> {
    if values.is_empty() || values.len() > COMMITTEE_NODES {
        return Err("public MPC result wire has an invalid population".into());
    }
    let mut ordered = values.to_vec();
    ordered.sort_by_key(|value| value.node);
    if ordered.iter().any(|value| value.unsigned().is_err())
        || (require_full_bundle_order
            && ordered
                .iter()
                .enumerate()
                .any(|(index, value)| usize::from(value.node) != index))
    {
        return Err("public MPC result wire is not in canonical node order".into());
    }
    let mut out = Vec::with_capacity(WIRE_MAGIC.len() + 2 + RECORD_BYTES * ordered.len());
    out.extend_from_slice(WIRE_MAGIC);
    out.extend_from_slice(&(ordered.len() as u16).to_be_bytes());
    for value in ordered {
        out.extend_from_slice(&value.node.to_be_bytes());
        out.extend_from_slice(&value.slot.to_be_bytes());
        out.extend_from_slice(&value.sequence.to_be_bytes());
        out.extend_from_slice(&value.batch_digest);
        out.extend_from_slice(&value.source_digest);
        out.extend_from_slice(&value.round_digest);
        out.extend_from_slice(&value.masked_key.to_be_bytes());
        out.extend_from_slice(&value.masked_fill.to_be_bytes());
        out.extend_from_slice(&value.stdout_digest);
        out.extend_from_slice(&value.persistence_digest);
        out.extend_from_slice(&value.signature.to_bytes());
    }
    Ok(out)
}

pub fn encode_public_result_attestations(
    values: &[NodePublicResultAttestation],
) -> Result<Vec<u8>, String> {
    if values.len() != COMMITTEE_NODES {
        return Err("public MPC result bundle must contain exactly seven nodes".into());
    }
    encode_wire(values, true)
}

pub fn encode_node_public_result_attestation(
    value: &NodePublicResultAttestation,
) -> Result<Vec<u8>, String> {
    // A resident node emits a one-record wire bearing its actual committee
    // index. Requiring a singleton to start at node zero would make nodes 1-6
    // unable to return an attestation at all. Canonical 0..6 ordering remains
    // mandatory for the seven-record settlement bundle above.
    encode_wire(std::slice::from_ref(value), false)
}

fn decode_wire(
    raw: &[u8],
    expected: usize,
    require_full_bundle_order: bool,
) -> Result<Vec<NodePublicResultAttestation>, String> {
    if raw.len() < WIRE_MAGIC.len() + 2 || &raw[..WIRE_MAGIC.len()] != WIRE_MAGIC {
        return Err("public MPC result wire has an invalid header".into());
    }
    let count = u16::from_be_bytes(raw[8..10].try_into().expect("two-byte count")) as usize;
    if count != expected || raw.len() != 10 + count * RECORD_BYTES {
        return Err("public MPC result wire has the wrong population or length".into());
    }
    let mut offset = 10;
    let mut take = |length: usize| {
        let value = &raw[offset..offset + length];
        offset += length;
        value
    };
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let node = u16::from_be_bytes(take(2).try_into().expect("two-byte node"));
        let slot = u64::from_be_bytes(take(8).try_into().expect("eight-byte slot"));
        let sequence = u64::from_be_bytes(take(8).try_into().expect("eight-byte sequence"));
        let batch_digest = take(32).try_into().expect("32-byte batch digest");
        let source_digest = take(32).try_into().expect("32-byte source digest");
        let round_digest = take(32).try_into().expect("32-byte round digest");
        let masked_key = i128::from_be_bytes(take(16).try_into().expect("16-byte key"));
        let masked_fill = i128::from_be_bytes(take(16).try_into().expect("16-byte fill"));
        let stdout_digest = take(32).try_into().expect("32-byte stdout digest");
        let persistence_digest = take(32).try_into().expect("32-byte persistence digest");
        let signature = Signature::from_bytes(take(64).try_into().expect("64-byte signature"));
        let value = NodePublicResultAttestation {
            node,
            slot,
            sequence,
            batch_digest,
            source_digest,
            round_digest,
            masked_key,
            masked_fill,
            stdout_digest,
            persistence_digest,
            signature,
        };
        value.unsigned()?;
        values.push(value);
    }
    if require_full_bundle_order
        && values
            .iter()
            .enumerate()
            .any(|(index, value)| usize::from(value.node) != index)
    {
        return Err("public MPC result wire is not in canonical node order".into());
    }
    Ok(values)
}

pub fn decode_public_result_attestations(
    raw: &[u8],
) -> Result<Vec<NodePublicResultAttestation>, String> {
    decode_wire(raw, COMMITTEE_NODES, true)
}

pub fn decode_node_public_result_attestation(
    raw: &[u8],
) -> Result<NodePublicResultAttestation, String> {
    let mut values = decode_wire(raw, 1, false)?;
    Ok(values.remove(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seven_node_result_is_canonical_and_mask_commitment_opens_once() {
        let keys = (0..COMMITTEE_NODES)
            .map(|node| SigningKey::from_bytes(&[node as u8 + 1; 32]))
            .collect::<Vec<_>>();
        let attestations = keys
            .iter()
            .enumerate()
            .map(|(node, key)| {
                NodePublicResultAttestation {
                    node: node as u16,
                    slot: 3,
                    sequence: 4,
                    batch_digest: [node as u8 + 20; 32],
                    source_digest: [40; 32],
                    round_digest: [41; 32],
                    masked_key: 500,
                    masked_fill: 91,
                    stdout_digest: [node as u8 + 50; 32],
                    persistence_digest: [node as u8 + 60; 32],
                    signature: Signature::from_bytes(&[0; 64]),
                }
                .sign(key)
                .unwrap()
            })
            .collect::<Vec<_>>();
        let wire = encode_public_result_attestations(&attestations).unwrap();
        let decoded = decode_public_result_attestations(&wire).unwrap();
        assert_eq!(encode_public_result_attestations(&decoded).unwrap(), wire);
        let trusted = keys
            .iter()
            .map(SigningKey::verifying_key)
            .collect::<Vec<_>>();
        let result = verify_public_result_lane(&decoded, &trusted, [99; 32]).unwrap();
        assert_eq!(result.masked_fill, 91);
        assert_eq!(fill_mask_commitment(91), fill_mask_commitment(91));
        assert_ne!(fill_mask_commitment(91), fill_mask_commitment(92));
    }

    #[test]
    fn every_resident_node_can_round_trip_its_single_attestation() {
        for node in 0..COMMITTEE_NODES {
            let key = SigningKey::from_bytes(&[node as u8 + 1; 32]);
            let attestation = NodePublicResultAttestation {
                node: node as u16,
                slot: 3,
                sequence: 4,
                batch_digest: [node as u8 + 20; 32],
                source_digest: [40; 32],
                round_digest: [41; 32],
                masked_key: 500,
                masked_fill: 91,
                stdout_digest: [node as u8 + 50; 32],
                persistence_digest: [node as u8 + 60; 32],
                signature: Signature::from_bytes(&[0; 64]),
            }
            .sign(&key)
            .unwrap();
            let wire = encode_node_public_result_attestation(&attestation).unwrap();
            let decoded = decode_node_public_result_attestation(&wire).unwrap();
            assert_eq!(decoded, attestation);
            assert!(decoded.verify(&key.verifying_key()));
        }
    }
}
