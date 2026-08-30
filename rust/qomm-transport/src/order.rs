//! Content-independent admission and ordering for one fixed market slot.

use crate::wire::Frame;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

const TICKET_DOMAIN: &[u8] = b"QOMM:ORDER:TICKET:v1";
const RECEIPT_DOMAIN: &[u8] = b"QOMM:ORDER:RECEIPT:v1";
const BEACON_DOMAIN: &[u8] = b"QOMM:ORDER:BEACON:v1";
const MANIFEST_DOMAIN: &[u8] = b"QOMM:ORDER:MANIFEST:v1";
const ORDER_DOMAIN: &[u8] = b"QOMM:ORDER:KEY:v1";
const ORDERED_ADMISSION_DOMAIN: &[u8] = b"QOMM:ORDER:ADMISSION:v1";
const CERTIFIED_ADMISSION_DOMAIN: &[u8] = b"QOMM:ORDER:CERTIFIED-ADMISSION:v1";
const NODE_ADMISSION_DOMAIN: &[u8] = b"QOMM:ORDER:NODE-ADMISSION:v1";
const NODE_EXECUTION_DOMAIN: &[u8] = b"QOMM:ORDER:NODE-EXECUTION:v1";
const EXECUTION_RECEIPT_DOMAIN: &[u8] = b"QOMM:MPC:EXECUTION-RECEIPT:v1";
const EXECUTION_LANE_DOMAIN: &[u8] = b"QOMM:ORDER:EXECUTION-LANE:v1";
const EXECUTION_WIRE_MAGIC: &[u8] = b"QOMM:EXECUTION-ATTESTATIONS:v1";
const CLUSTER_BATCH_DOMAIN: &[u8] = b"QOMM:ORDER:CLUSTER-BATCH:v1";
const PRINCIPAL_TICKET_DOMAIN: &[u8] = b"QOMM:NODE:PRINCIPAL-TICKET:v1";
const PRINCIPAL_DIGEST_DOMAIN: &[u8] = b"QOMM:ORDER:PRINCIPAL:v1";
const QUOTE_PROOF_JOB_DOMAIN: &[u8] = b"QOMM:LIVE-QUOTE-PROOF:v1";
const LIVE_PROOF_JOB_DOMAIN: &[u8] = b"QOMM:LIVE-PROOF-JOB:v1";
const COMPLETE_QUOTE_CONTEXT_DOMAIN: &[u8] = b"QOMM:LIVE:COMPLETE-QUOTE-CONTEXT:v1";
pub const COMMITTEE_NODES: usize = 7;
pub const ZERO: [u8; 32] = [0; 32];

/// Canonical quote-proof identifier for a lane in one seven-node batch.
pub fn quote_proof_job_digest(cluster_digest: [u8; 32], lane: usize) -> Result<[u8; 32], String> {
    if cluster_digest == ZERO || lane > 4095 {
        return Err("quote proof job is outside its cluster or lane bound".into());
    }
    Ok(Sha256::new()
        .chain_update(QUOTE_PROOF_JOB_DOMAIN)
        .chain_update(cluster_digest)
        .chain_update((lane as u64).to_be_bytes())
        .finalize()
        .into())
}

/// Identifier persisted independently by each proof party. It binds the
/// proof transcript to the closed slot, its lane, and the quote proof digest.
pub fn live_proof_job_id(
    slot: u32,
    lane: usize,
    quote_digest: [u8; 32],
) -> Result<[u8; 32], String> {
    if quote_digest == ZERO || lane > 4095 {
        return Err("live proof job is outside its quote or lane bound".into());
    }
    Ok(Sha256::new()
        .chain_update(LIVE_PROOF_JOB_DOMAIN)
        .chain_update(slot.to_be_bytes())
        .chain_update((lane as u64).to_be_bytes())
        .chain_update(quote_digest)
        .finalize()
        .into())
}

/// Public transcript context recomputed by both proof nodes and Avalanche
/// validators after the signed execution-receipt lane has been verified.
pub fn complete_quote_context(job_id: [u8; 32], request_context: [u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(COMPLETE_QUOTE_CONTEXT_DOMAIN)
        .chain_update(job_id)
        .chain_update(request_context)
        .finalize()
        .into()
}

/// One resident node's signed statement that a legal-entity principal
/// submitted a particular pre-trade mandate commitment in a fixed slot.
///
/// `claim_digest` is opaque to the node.  For a real RFQ it is the digest of
/// the Taker's already-signed execution mandate; cover traffic uses an equally
/// sized random digest.  The statement is produced only after the slot closes,
/// so a coordinator cannot replace the mandate after seeing the quote.
#[derive(Clone, Debug)]
pub struct NodeAdmissionAttestation {
    pub node: u16,
    pub slot: u64,
    pub sequence: u64,
    pub principal_digest: [u8; 32],
    pub ticket_id: [u8; 32],
    pub claim_digest: [u8; 32],
    pub batch_digest: [u8; 32],
    pub order_digest: [u8; 32],
    pub signature: Signature,
}

impl NodeAdmissionAttestation {
    pub fn unsigned(&self) -> Result<Vec<u8>, String> {
        if usize::from(self.node) >= COMMITTEE_NODES
            || self.sequence == 0
            || self.sequence > i64::MAX as u64
            || self.slot > i64::MAX as u64
            || [
                self.principal_digest,
                self.ticket_id,
                self.claim_digest,
                self.batch_digest,
                self.order_digest,
            ]
            .contains(&ZERO)
        {
            return Err("node admission attestation is incomplete".into());
        }
        let mut body = Vec::with_capacity(NODE_ADMISSION_DOMAIN.len() + 2 + 16 + 32 * 5);
        body.extend_from_slice(NODE_ADMISSION_DOMAIN);
        body.extend_from_slice(&self.node.to_be_bytes());
        body.extend_from_slice(&self.slot.to_be_bytes());
        body.extend_from_slice(&self.sequence.to_be_bytes());
        body.extend_from_slice(&self.principal_digest);
        body.extend_from_slice(&self.ticket_id);
        body.extend_from_slice(&self.claim_digest);
        body.extend_from_slice(&self.batch_digest);
        body.extend_from_slice(&self.order_digest);
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

/// One resident node's signed public receipt for an approved MP-SPDZ run.
/// Digests bind the node-local stdout, stderr and proof persistence bytes;
/// secret shares, local paths and clear quote values never enter this record.
#[derive(Clone, Debug)]
pub struct NodeExecutionAttestation {
    pub node: u16,
    pub slot: u64,
    pub lane: u64,
    pub batch_digest: [u8; 32],
    pub source_digest: [u8; 32],
    pub state_generation: u64,
    pub frame_count: u64,
    pub input_count: u64,
    pub stdout_digest: [u8; 32],
    pub stderr_digest: [u8; 32],
    pub persistence_digest: [u8; 32],
    pub receipt_digest: [u8; 32],
    pub signature: Signature,
}

impl NodeExecutionAttestation {
    pub fn recompute_receipt_digest(&self) -> Result<[u8; 32], String> {
        let slot = u32::try_from(self.slot)
            .map_err(|_| "execution receipt slot is outside the MPC range".to_string())?;
        let mut hash = Sha256::new();
        hash.update(EXECUTION_RECEIPT_DOMAIN);
        hash.update(self.node.to_be_bytes());
        hash.update(slot.to_be_bytes());
        hash.update(self.lane.to_be_bytes());
        hash.update(self.batch_digest);
        hash.update(self.source_digest);
        hash.update(self.state_generation.to_be_bytes());
        hash.update(self.frame_count.to_be_bytes());
        hash.update(self.input_count.to_be_bytes());
        hash.update(self.stdout_digest);
        hash.update(self.stderr_digest);
        hash.update(self.persistence_digest);
        Ok(hash.finalize().into())
    }

    pub fn unsigned(&self) -> Result<Vec<u8>, String> {
        if usize::from(self.node) >= COMMITTEE_NODES
            || self.lane > 4095
            || self.state_generation == 0
            || !(1..=4096).contains(&self.frame_count)
            || self.input_count == 0
            || self.input_count > 1_000_000
            || [
                self.batch_digest,
                self.source_digest,
                self.stdout_digest,
                self.stderr_digest,
                self.persistence_digest,
                self.receipt_digest,
            ]
            .contains(&ZERO)
            || self.recompute_receipt_digest()? != self.receipt_digest
        {
            return Err("node execution attestation is incomplete or inconsistent".into());
        }
        let mut body = Vec::with_capacity(NODE_EXECUTION_DOMAIN.len() + 2 + 8 * 6 + 32 * 6);
        body.extend_from_slice(NODE_EXECUTION_DOMAIN);
        body.extend_from_slice(&self.node.to_be_bytes());
        body.extend_from_slice(&self.slot.to_be_bytes());
        body.extend_from_slice(&self.lane.to_be_bytes());
        body.extend_from_slice(&self.batch_digest);
        body.extend_from_slice(&self.source_digest);
        body.extend_from_slice(&self.state_generation.to_be_bytes());
        body.extend_from_slice(&self.frame_count.to_be_bytes());
        body.extend_from_slice(&self.input_count.to_be_bytes());
        body.extend_from_slice(&self.stdout_digest);
        body.extend_from_slice(&self.stderr_digest);
        body.extend_from_slice(&self.persistence_digest);
        body.extend_from_slice(&self.receipt_digest);
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
pub struct CertifiedExecutionLane {
    pub slot: u64,
    pub lane: u64,
    pub cluster_digest: [u8; 32],
    pub source_digest: [u8; 32],
    pub digest: [u8; 32],
}

/// Verify exactly one signed receipt per resident node and bind the proof
/// persistence files to the same sealed batch that was admitted for the slot.
pub fn verify_execution_lane(
    attestations: &[NodeExecutionAttestation],
    trusted_node_keys: &[VerifyingKey],
    order_digest: [u8; 32],
) -> Result<CertifiedExecutionLane, String> {
    if attestations.len() != COMMITTEE_NODES || trusted_node_keys.len() != COMMITTEE_NODES {
        return Err("execution lane needs exactly seven attestations and trusted keys".into());
    }
    let mut ordered = attestations.to_vec();
    ordered.sort_by_key(|value| value.node);
    for (expected, value) in ordered.iter().enumerate() {
        if usize::from(value.node) != expected || !value.verify(&trusted_node_keys[expected]) {
            return Err("execution lane contains an unknown, duplicate, or invalid node".into());
        }
    }
    let first = &ordered[0];
    if ordered.iter().skip(1).any(|value| {
        value.slot != first.slot
            || value.lane != first.lane
            || value.source_digest != first.source_digest
            || value.state_generation != first.state_generation
            || value.frame_count != first.frame_count
            || value.input_count != first.input_count
    }) {
        return Err("resident nodes disagree on the execution slot, source, or shape".into());
    }
    let slot = u32::try_from(first.slot)
        .map_err(|_| "execution lane slot is outside the resident-node range".to_string())?;
    let node_batches = ordered
        .iter()
        .map(|value| (value.node, value.batch_digest))
        .collect::<Vec<_>>();
    let cluster_digest = cluster_batch_digest(slot, order_digest, &node_batches)?;
    let mut hash = Sha256::new();
    hash.update(EXECUTION_LANE_DOMAIN);
    hash.update(first.slot.to_be_bytes());
    hash.update(first.lane.to_be_bytes());
    hash.update(cluster_digest);
    hash.update(first.source_digest);
    hash.update(first.state_generation.to_be_bytes());
    hash.update(first.frame_count.to_be_bytes());
    hash.update(first.input_count.to_be_bytes());
    for value in &ordered {
        hash.update(value.node.to_be_bytes());
        hash.update(value.receipt_digest);
    }
    Ok(CertifiedExecutionLane {
        slot: first.slot,
        lane: first.lane,
        cluster_digest,
        source_digest: first.source_digest,
        digest: hash.finalize().into(),
    })
}

pub fn encode_execution_attestations(
    attestations: &[NodeExecutionAttestation],
) -> Result<Vec<u8>, String> {
    if attestations.len() != COMMITTEE_NODES {
        return Err("execution attestation wire needs exactly seven nodes".into());
    }
    let mut values = attestations.to_vec();
    values.sort_by_key(|value| value.node);
    let mut out = Vec::with_capacity(EXECUTION_WIRE_MAGIC.len() + 2 + values.len() * 346);
    out.extend_from_slice(EXECUTION_WIRE_MAGIC);
    out.extend_from_slice(&(values.len() as u16).to_be_bytes());
    for value in values {
        value.unsigned()?;
        out.extend_from_slice(&value.node.to_be_bytes());
        out.extend_from_slice(&value.slot.to_be_bytes());
        out.extend_from_slice(&value.lane.to_be_bytes());
        for digest in [
            value.batch_digest,
            value.source_digest,
            value.stdout_digest,
            value.stderr_digest,
            value.persistence_digest,
            value.receipt_digest,
        ] {
            out.extend_from_slice(&digest);
        }
        out.extend_from_slice(&value.state_generation.to_be_bytes());
        out.extend_from_slice(&value.frame_count.to_be_bytes());
        out.extend_from_slice(&value.input_count.to_be_bytes());
        out.extend_from_slice(&value.signature.to_bytes());
    }
    Ok(out)
}

pub fn decode_execution_attestations(raw: &[u8]) -> Result<Vec<NodeExecutionAttestation>, String> {
    const RECORD_BYTES: usize = 2 + 8 + 8 + 32 * 6 + 8 * 3 + 64;
    let header = EXECUTION_WIRE_MAGIC.len() + 2;
    if raw.len() < header || &raw[..EXECUTION_WIRE_MAGIC.len()] != EXECUTION_WIRE_MAGIC {
        return Err("execution attestation wire has an invalid header".into());
    }
    let count = u16::from_be_bytes(
        raw[EXECUTION_WIRE_MAGIC.len()..header]
            .try_into()
            .expect("two-byte execution count"),
    ) as usize;
    if count != COMMITTEE_NODES || raw.len() != header + count * RECORD_BYTES {
        return Err("execution attestation wire has the wrong population or length".into());
    }
    let mut offset = header;
    let mut take = |length: usize| {
        let value = &raw[offset..offset + length];
        offset += length;
        value
    };
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let node = u16::from_be_bytes(take(2).try_into().expect("two-byte node"));
        let slot = u64::from_be_bytes(take(8).try_into().expect("eight-byte slot"));
        let lane = u64::from_be_bytes(take(8).try_into().expect("eight-byte lane"));
        let mut digest = || -> [u8; 32] { take(32).try_into().expect("32-byte digest") };
        let batch_digest = digest();
        let source_digest = digest();
        let stdout_digest = digest();
        let stderr_digest = digest();
        let persistence_digest = digest();
        let receipt_digest = digest();
        let state_generation =
            u64::from_be_bytes(take(8).try_into().expect("eight-byte generation"));
        let frame_count = u64::from_be_bytes(take(8).try_into().expect("eight-byte frame count"));
        let input_count = u64::from_be_bytes(take(8).try_into().expect("eight-byte input count"));
        let signature = Signature::from_bytes(take(64).try_into().expect("64-byte signature"));
        let value = NodeExecutionAttestation {
            node,
            slot,
            lane,
            batch_digest,
            source_digest,
            state_generation,
            frame_count,
            input_count,
            stdout_digest,
            stderr_digest,
            persistence_digest,
            receipt_digest,
            signature,
        };
        value.unsigned()?;
        values.push(value);
    }
    if values
        .iter()
        .enumerate()
        .any(|(expected, value)| usize::from(value.node) != expected)
    {
        return Err("execution attestation wire is not in canonical node order".into());
    }
    Ok(values)
}

/// Committee-verified public binding for one fixed-population lane.  It
/// contains no RFQ amount, direction, price limit, or real/cover bit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedAdmissionLane {
    pub slot: u64,
    pub sequence: u64,
    pub principal_digest: [u8; 32],
    pub ticket_id: [u8; 32],
    pub claim_digest: [u8; 32],
    pub cluster_digest: [u8; 32],
    pub order_digest: [u8; 32],
}

impl CertifiedAdmissionLane {
    /// Digest stored in DeFMI's fixed-population batch.  A real Taker later
    /// proves that `claim_digest` is its signed mandate digest; covers advance
    /// the same opaque digest without an observable type flag.
    pub fn digest(&self, venue_id: [u8; 32], epoch: u64) -> Result<[u8; 32], String> {
        if venue_id == ZERO || epoch == 0 {
            return Err("certified admission needs a venue and non-zero epoch".into());
        }
        Ok(Sha256::new()
            .chain_update(CERTIFIED_ADMISSION_DOMAIN)
            .chain_update(venue_id)
            .chain_update(epoch.to_be_bytes())
            .chain_update(self.slot.to_be_bytes())
            .chain_update(self.sequence.to_be_bytes())
            .chain_update(self.ticket_id)
            .chain_update(self.claim_digest)
            .chain_update(self.cluster_digest)
            .chain_update(self.order_digest)
            .finalize()
            .into())
    }
}

/// Verify exactly seven resident-node attestations and collapse them to one
/// committee-wide lane.  Each node may have a different share-frame batch
/// digest, while every content-independent ordering field must agree.
pub fn verify_admission_lane(
    attestations: &[NodeAdmissionAttestation],
    trusted_node_keys: &[VerifyingKey],
) -> Result<CertifiedAdmissionLane, String> {
    if attestations.len() != COMMITTEE_NODES || trusted_node_keys.len() != COMMITTEE_NODES {
        return Err("admission lane needs exactly seven attestations and trusted keys".into());
    }
    let mut ordered = attestations.to_vec();
    ordered.sort_by_key(|attestation| attestation.node);
    for (expected, attestation) in ordered.iter().enumerate() {
        if usize::from(attestation.node) != expected
            || !attestation.verify(&trusted_node_keys[expected])
        {
            return Err("admission lane contains an unknown, duplicate, or invalid node".into());
        }
    }
    let first = &ordered[0];
    if ordered.iter().skip(1).any(|value| {
        value.slot != first.slot
            || value.sequence != first.sequence
            || value.principal_digest != first.principal_digest
            || value.ticket_id != first.ticket_id
            || value.claim_digest != first.claim_digest
            || value.order_digest != first.order_digest
    }) {
        return Err("resident nodes disagree on the admitted principal, claim, or order".into());
    }
    let node_batches = ordered
        .iter()
        .map(|value| (value.node, value.batch_digest))
        .collect::<Vec<_>>();
    let slot = u32::try_from(first.slot)
        .map_err(|_| "admission slot is outside the resident-node range".to_string())?;
    Ok(CertifiedAdmissionLane {
        slot: first.slot,
        sequence: first.sequence,
        principal_digest: first.principal_digest,
        ticket_id: first.ticket_id,
        claim_digest: first.claim_digest,
        cluster_digest: cluster_batch_digest(slot, first.order_digest, &node_batches)?,
        order_digest: first.order_digest,
    })
}

/// Identifier the authenticated Taker can bind into its mandate before it
/// submits the opaque frame. Every committee node derives the same value from
/// the TLS principal and slot; no post-quote signature is needed.
pub fn principal_ticket_id(slot: u32, principal: &str) -> Result<[u8; 32], String> {
    if principal.is_empty() || principal.len() > 512 {
        return Err("admission principal must contain 1..512 bytes".into());
    }
    Ok(Sha256::new()
        .chain_update(PRINCIPAL_TICKET_DOMAIN)
        .chain_update(slot.to_be_bytes())
        .chain_update((principal.len() as u64).to_be_bytes())
        .chain_update(principal.as_bytes())
        .finalize()
        .into())
}

pub fn admission_principal_digest(principal: &str) -> Result<[u8; 32], String> {
    if principal.is_empty() || principal.len() > 512 {
        return Err("admission principal must contain 1..512 bytes".into());
    }
    Ok(Sha256::new()
        .chain_update(PRINCIPAL_DIGEST_DOMAIN)
        .chain_update((principal.len() as u64).to_be_bytes())
        .chain_update(principal.as_bytes())
        .finalize()
        .into())
}

/// Bind the common principal order to every node's distinct share-frame
/// batch. A coordinator cannot substitute one node's view or omit a node while
/// constructing the ordered admission consumed by DeFMI.
pub fn cluster_batch_digest(
    slot: u32,
    order_digest: [u8; 32],
    node_batches: &[(u16, [u8; 32])],
) -> Result<[u8; 32], String> {
    if order_digest == ZERO || node_batches.len() != COMMITTEE_NODES {
        return Err("cluster batch needs a non-zero order and exactly seven nodes".into());
    }
    let mut ordered = node_batches.to_vec();
    ordered.sort_by_key(|(node, _)| *node);
    for (expected, (node, batch)) in ordered.iter().enumerate() {
        if usize::from(*node) != expected || *batch == ZERO {
            return Err("cluster batch nodes must be exactly 0..6 with non-zero digests".into());
        }
    }
    let mut hash = Sha256::new();
    hash.update(CLUSTER_BATCH_DOMAIN);
    hash.update(slot.to_be_bytes());
    hash.update(order_digest);
    for (node, batch) in ordered {
        hash.update(node.to_be_bytes());
        hash.update(batch);
    }
    Ok(hash.finalize().into())
}

fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update((part.len() as u32).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

fn hmac(key: &[u8], body: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for index in 0..64 {
        inner_pad[index] ^= block[index];
        outer_pad[index] ^= block[index];
    }
    let inner = Sha256::new()
        .chain_update(inner_pad)
        .chain_update(body)
        .finalize();
    Sha256::new()
        .chain_update(outer_pad)
        .chain_update(inner)
        .finalize()
        .into()
}

/// Committee-visible result of ordering one opaque RFQ frame.
///
/// The Taker can sign its mandate before submitting because it commits only to
/// `ticket_id` and `slot`.  The slot-derived `sequence`, batch digest,
/// and this receipt are created later by the MPC committee, before any quote is
/// disclosed.  A DeFMI reserve approval signs [`Self::digest`], closing the
/// otherwise circular dependency in which an RFQ contained the digest of its
/// own post-submission receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderedAdmission {
    pub venue_id: [u8; 32],
    pub epoch: u64,
    pub slot: u64,
    /// One-based position in the beacon-shuffled fixed-population slot.
    pub sequence: u64,
    pub ticket_id: [u8; 32],
    pub batch_digest: [u8; 32],
    pub order_digest: [u8; 32],
    pub rfq_nullifier: [u8; 32],
    pub taker_entity_commitment: [u8; 32],
    pub taker_mandate_digest: [u8; 32],
    pub expires_at: u64,
}

impl OrderedAdmission {
    pub fn unsigned(&self) -> Result<Vec<u8>, String> {
        if self.epoch == 0
            || self.sequence == 0
            || self.expires_at == 0
            || self.epoch > i64::MAX as u64
            || self.slot > i64::MAX as u64
            || self.sequence > i64::MAX as u64
            || self.expires_at > i64::MAX as u64
            || [
                self.venue_id,
                self.ticket_id,
                self.batch_digest,
                self.order_digest,
                self.rfq_nullifier,
                self.taker_entity_commitment,
                self.taker_mandate_digest,
            ]
            .contains(&ZERO)
        {
            return Err("ordered admission is incomplete or outside the durable range".into());
        }
        let mut body = Vec::with_capacity(ORDERED_ADMISSION_DOMAIN.len() + 32 * 6 + 8 * 4);
        body.extend_from_slice(ORDERED_ADMISSION_DOMAIN);
        body.extend_from_slice(&self.venue_id);
        body.extend_from_slice(&self.epoch.to_be_bytes());
        body.extend_from_slice(&self.slot.to_be_bytes());
        body.extend_from_slice(&self.sequence.to_be_bytes());
        body.extend_from_slice(&self.ticket_id);
        body.extend_from_slice(&self.batch_digest);
        body.extend_from_slice(&self.order_digest);
        body.extend_from_slice(&self.rfq_nullifier);
        body.extend_from_slice(&self.taker_entity_commitment);
        body.extend_from_slice(&self.taker_mandate_digest);
        body.extend_from_slice(&self.expires_at.to_be_bytes());
        Ok(body)
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        Ok(Sha256::digest(self.unsigned()?).into())
    }

    /// The opaque lane digest registered before any lane can reserve a legal-
    /// entity facility.  The complete admission remains separately bound to
    /// the signed mandate by [`Self::digest`].
    pub fn certified_digest(&self) -> Result<[u8; 32], String> {
        CertifiedAdmissionLane {
            slot: self.slot,
            sequence: self.sequence,
            principal_digest: ZERO,
            ticket_id: self.ticket_id,
            claim_digest: self.taker_mandate_digest,
            cluster_digest: self.batch_digest,
            order_digest: self.order_digest,
        }
        .digest(self.venue_id, self.epoch)
    }
}

#[derive(Clone, Debug)]
pub struct AdmissionTicket {
    pub slot: u64,
    pub ticket_id: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: Signature,
}

impl AdmissionTicket {
    pub fn unsigned(&self) -> Result<Vec<u8>, String> {
        if self.expires_at <= self.issued_at {
            return Err("ticket expiry must follow issuance".into());
        }
        let mut body = Vec::with_capacity(TICKET_DOMAIN.len() + 56);
        body.extend_from_slice(TICKET_DOMAIN);
        body.extend_from_slice(&self.slot.to_be_bytes());
        body.extend_from_slice(&self.ticket_id);
        body.extend_from_slice(&self.issued_at.to_be_bytes());
        body.extend_from_slice(&self.expires_at.to_be_bytes());
        Ok(body)
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        Ok(digest(&[&self.unsigned()?, &self.signature.to_bytes()]))
    }

    pub fn verify(&self, authority: &VerifyingKey, now: u64) -> bool {
        self.issued_at <= now
            && now <= self.expires_at
            && self
                .unsigned()
                .is_ok_and(|body| authority.verify(&body, &self.signature).is_ok())
    }
}

pub struct AdmissionAuthority {
    signing_key: SigningKey,
    entity_key: Vec<u8>,
    issued: BTreeMap<(u64, [u8; 32]), [u8; 32]>,
}

impl AdmissionAuthority {
    pub fn new(signing_key: SigningKey, entity_key: Vec<u8>) -> Result<Self, String> {
        if entity_key.len() < 32 {
            return Err("entity nullifier key must contain at least 32 bytes".into());
        }
        Ok(Self {
            signing_key,
            entity_key,
            issued: BTreeMap::new(),
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn entity_nullifier(&self, entity_id: &[u8]) -> Result<[u8; 32], String> {
        if entity_id.is_empty() {
            return Err("an empty legal-entity identifier is not admissible".into());
        }
        let mut body = Vec::with_capacity(14 + entity_id.len());
        body.extend_from_slice(b"QOMM:ENTITY:v1");
        body.extend_from_slice(entity_id);
        Ok(hmac(&self.entity_key, &body))
    }

    pub fn issue(
        &mut self,
        entity_id: &[u8],
        slot: u64,
        issued_at: Option<u64>,
        lifetime: u64,
        ticket_id: Option<[u8; 32]>,
    ) -> Result<AdmissionTicket, String> {
        if lifetime == 0 {
            return Err("ticket lifetime must be positive".into());
        }
        let issued_at = issued_at.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
        let expires_at = issued_at
            .checked_add(lifetime)
            .ok_or_else(|| "ticket expiry overflow".to_string())?;
        let nullifier = self.entity_nullifier(entity_id)?;
        if self.issued.contains_key(&(slot, nullifier)) {
            return Err("this legal entity already has a ticket for the slot".into());
        }
        let ticket_id = ticket_id.unwrap_or_else(rand::random);
        let mut body = Vec::new();
        body.extend_from_slice(TICKET_DOMAIN);
        body.extend_from_slice(&slot.to_be_bytes());
        body.extend_from_slice(&ticket_id);
        body.extend_from_slice(&issued_at.to_be_bytes());
        body.extend_from_slice(&expires_at.to_be_bytes());
        let ticket = AdmissionTicket {
            slot,
            ticket_id,
            issued_at,
            expires_at,
            signature: self.signing_key.sign(&body),
        };
        self.issued.insert((slot, nullifier), ticket.digest()?);
        Ok(ticket)
    }
}

#[derive(Clone, Debug)]
pub struct RandomnessBeacon {
    pub round: u64,
    pub value: [u8; 32],
    pub signature: Signature,
}

impl RandomnessBeacon {
    fn unsigned(round: u64, value: &[u8; 32]) -> Vec<u8> {
        [BEACON_DOMAIN, &round.to_be_bytes(), value].concat()
    }

    pub fn sign(round: u64, value: [u8; 32], key: &SigningKey) -> Self {
        Self {
            round,
            value,
            signature: key.sign(&Self::unsigned(round, &value)),
        }
    }

    pub fn verify(&self, key: &VerifyingKey) -> bool {
        key.verify(&Self::unsigned(self.round, &self.value), &self.signature)
            .is_ok()
    }
}

#[derive(Clone, Debug)]
pub struct AdmissionReceipt {
    pub slot: u64,
    pub node: u64,
    pub ticket_digest: [u8; 32],
    pub frame_digest: [u8; 32],
    pub received_at_ns: u64,
    pub signature: Signature,
}

impl AdmissionReceipt {
    pub fn unsigned(&self) -> Vec<u8> {
        [
            RECEIPT_DOMAIN,
            &self.slot.to_be_bytes(),
            &self.node.to_be_bytes(),
            &self.ticket_digest,
            &self.frame_digest,
            &self.received_at_ns.to_be_bytes(),
        ]
        .concat()
    }

    pub fn verify(&self, key: &VerifyingKey) -> bool {
        key.verify(&self.unsigned(), &self.signature).is_ok()
    }
}

#[derive(Clone, Debug)]
pub struct BatchManifest {
    pub slot: u64,
    pub node: u64,
    pub beacon_round: u64,
    pub beacon_value: [u8; 32],
    pub ordered_ticket_digests: Vec<[u8; 32]>,
    pub ordered_frame_digests: Vec<[u8; 32]>,
    pub previous_digest: [u8; 32],
    pub signature: Signature,
}

impl BatchManifest {
    pub fn unsigned(&self) -> Result<Vec<u8>, String> {
        if self.ordered_ticket_digests.len() != self.ordered_frame_digests.len() {
            return Err("ticket and frame manifests have different lengths".into());
        }
        let mut body = Vec::new();
        body.extend_from_slice(MANIFEST_DOMAIN);
        body.extend_from_slice(&self.slot.to_be_bytes());
        body.extend_from_slice(&self.node.to_be_bytes());
        body.extend_from_slice(&self.beacon_round.to_be_bytes());
        body.extend_from_slice(&self.beacon_value);
        body.extend_from_slice(&self.previous_digest);
        body.extend_from_slice(&(self.ordered_ticket_digests.len() as u64).to_be_bytes());
        for (ticket, frame) in self
            .ordered_ticket_digests
            .iter()
            .zip(&self.ordered_frame_digests)
        {
            body.extend_from_slice(ticket);
            body.extend_from_slice(frame);
        }
        Ok(body)
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        Ok(digest(&[&self.unsigned()?, &self.signature.to_bytes()]))
    }

    pub fn verify(&self, key: &VerifyingKey) -> bool {
        self.unsigned()
            .is_ok_and(|body| key.verify(&body, &self.signature).is_ok())
    }

    pub fn includes(&self, receipt: &AdmissionReceipt) -> bool {
        self.ordered_ticket_digests
            .iter()
            .zip(&self.ordered_frame_digests)
            .any(|(ticket, frame)| {
                ticket == &receipt.ticket_digest && frame == &receipt.frame_digest
            })
    }
}

pub struct FixedSlotSealer {
    pub slot: u64,
    pub node: u64,
    pub deadline_ns: u64,
    pub tickets: Vec<AdmissionTicket>,
    pub authority_key: VerifyingKey,
    pub beacon_key: VerifyingKey,
    pub signing_key: SigningKey,
    pub previous_digest: [u8; 32],
    frames: BTreeMap<[u8; 32], Frame>,
    receipts: BTreeMap<[u8; 32], AdmissionReceipt>,
    closed: bool,
}

impl FixedSlotSealer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        slot: u64,
        node: u64,
        deadline_ns: u64,
        tickets: Vec<AdmissionTicket>,
        authority_key: VerifyingKey,
        beacon_key: VerifyingKey,
        signing_key: SigningKey,
        previous_digest: [u8; 32],
    ) -> Result<Self, String> {
        let ids = tickets
            .iter()
            .map(|ticket| ticket.ticket_id)
            .collect::<BTreeSet<_>>();
        if ids.len() != tickets.len() {
            return Err("the expected ticket list contains a duplicate".into());
        }
        if tickets.iter().any(|ticket| ticket.slot != slot) {
            return Err("a ticket belongs to another slot".into());
        }
        Ok(Self {
            slot,
            node,
            deadline_ns,
            tickets,
            authority_key,
            beacon_key,
            signing_key,
            previous_digest,
            frames: BTreeMap::new(),
            receipts: BTreeMap::new(),
            closed: false,
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn admit(
        &mut self,
        ticket: &AdmissionTicket,
        frame: Frame,
        now_ns: u64,
    ) -> Result<AdmissionReceipt, String> {
        if self.closed {
            return Err("the slot is already closed".into());
        }
        if now_ns > self.deadline_ns {
            return Err("the frame arrived after the sealed deadline".into());
        }
        if !ticket.verify(&self.authority_key, now_ns / 1_000_000_000) {
            return Err("the admission ticket is invalid or expired".into());
        }
        let ticket_digest = ticket.digest()?;
        let expected = self
            .tickets
            .iter()
            .map(AdmissionTicket::digest)
            .collect::<Result<BTreeSet<_>, _>>()?;
        if !expected.contains(&ticket_digest) {
            return Err("the ticket was not in the slot's precommitted population".into());
        }
        if u64::from(frame.slot) != self.slot || u64::from(frame.node) != self.node {
            return Err("the frame belongs to another slot or node".into());
        }
        let raw = frame.encode();
        let frame_digest = Sha256::digest(raw).into();
        if let Some(prior) = self.frames.get(&ticket_digest) {
            if prior.encode() != raw {
                return Err("one ticket attempted to replace its admitted frame".into());
            }
            return Ok(self.receipts[&ticket_digest].clone());
        }
        let mut receipt = AdmissionReceipt {
            slot: self.slot,
            node: self.node,
            ticket_digest,
            frame_digest,
            received_at_ns: now_ns,
            signature: Signature::from_bytes(&[0; 64]),
        };
        receipt.signature = self.signing_key.sign(&receipt.unsigned());
        self.frames.insert(ticket_digest, frame);
        self.receipts.insert(ticket_digest, receipt.clone());
        Ok(receipt)
    }

    pub fn close(
        &mut self,
        beacon: &RandomnessBeacon,
        now_ns: u64,
    ) -> Result<(Vec<Frame>, BatchManifest), String> {
        if self.closed {
            return Err("the slot is already closed".into());
        }
        if now_ns <= self.deadline_ns {
            return Err("the batch cannot close before its deadline".into());
        }
        if !beacon.verify(&self.beacon_key) {
            return Err("the ordering beacon signature is invalid".into());
        }
        if beacon.round <= self.slot {
            return Err("ordering randomness must be generated after the slot".into());
        }
        let missing = self
            .tickets
            .iter()
            .filter(|ticket| {
                ticket
                    .digest()
                    .is_ok_and(|digest| !self.frames.contains_key(&digest))
            })
            .count();
        if missing != 0 {
            return Err(format!(
                "fixed population incomplete: {missing} cover or request frame(s) missing"
            ));
        }
        let mut ordered = self.tickets.clone();
        ordered.sort_by_key(|ticket| {
            Sha256::new()
                .chain_update(ORDER_DOMAIN)
                .chain_update(self.slot.to_be_bytes())
                .chain_update(beacon.round.to_be_bytes())
                .chain_update(beacon.value)
                .chain_update(ticket.ticket_id)
                .finalize()
                .to_vec()
        });
        let ticket_digests = ordered
            .iter()
            .map(AdmissionTicket::digest)
            .collect::<Result<Vec<_>, _>>()?;
        let frames = ticket_digests
            .iter()
            .map(|digest| self.frames[digest].clone())
            .collect::<Vec<_>>();
        let frame_digests = frames
            .iter()
            .map(|frame| Sha256::digest(frame.encode()).into())
            .collect();
        let mut manifest = BatchManifest {
            slot: self.slot,
            node: self.node,
            beacon_round: beacon.round,
            beacon_value: beacon.value,
            ordered_ticket_digests: ticket_digests,
            ordered_frame_digests: frame_digests,
            previous_digest: self.previous_digest,
            signature: Signature::from_bytes(&[0; 64]),
        };
        manifest.signature = self.signing_key.sign(&manifest.unsigned()?);
        self.closed = true;
        Ok((frames, manifest))
    }
}

pub fn prove_omission(
    receipt: &AdmissionReceipt,
    manifest: &BatchManifest,
    sealer_key: &VerifyingKey,
) -> bool {
    receipt.slot == manifest.slot
        && receipt.node == manifest.node
        && receipt.verify(sealer_key)
        && manifest.verify(sealer_key)
        && !manifest.includes(receipt)
}
