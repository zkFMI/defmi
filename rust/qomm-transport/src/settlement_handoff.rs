//! Durable handoff from the seven-node proof cluster to DeFMI admission.
//!
//! This file contains verifier-complete public proofs, the threshold group
//! public key, content-independent admission metadata, and the opening of the
//! public traded-asset tag. It never contains amount, price, limit, reserve,
//! policy, inventory, or cleartext Shamir-share openings. Each encrypted
//! opening share is recipient-bound and remains opaque to the coordinator.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use qomm_proofs::opening_envelope::{opening_context, EncryptedOpeningShare, OpeningEnvelope};
use qomm_proofs::price_limit::PriceLimitDirection;
use qomm_proofs::threshold_range::ThresholdRangeProof;
use qomm_zkpi::typed::{ExecutionContext, TypedInstruction};
use qomm_zkpi::{frost, typed, typed_wire, Instruction, DEFAULT_DOMAIN};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::dvp_issuer::DvpProofs;
use crate::order::{
    complete_quote_context, decode_execution_attestations, encode_execution_attestations,
    live_proof_job_id, verify_admission_lane, verify_execution_lane, CertifiedAdmissionLane,
    NodeAdmissionAttestation, NodeExecutionAttestation, COMMITTEE_NODES,
};
use crate::proof_codec::{
    decode_dvp_proofs, decode_quote_verification, decode_threshold_range, encode_dvp_proofs,
    encode_quote_verification, encode_threshold_range, QuoteVerificationBundle,
};

pub const HANDOFF_VERSION: u8 = 6;

pub struct SettlementHandoff {
    pub job_id: [u8; 32],
    pub lane: usize,
    pub admission_sequence: u64,
    pub admission_ticket_id: [u8; 32],
    pub instruction: Instruction,
    pub frost_public: frost::keys::PublicKeyPackage,
    /// Digest of the verifier-complete quote proof embedded in the signed
    /// zkPI. This is distinct from the deterministic admission-lane job seed.
    pub quote_digest: [u8; 32],
    /// Complete threshold quote statement and proof. Every DeFMI/Avalanche
    /// validator recomputes `quote_digest`; a submitter-supplied digest is not
    /// accepted as evidence that the winning price was calculated correctly.
    pub quote_verification: QuoteVerificationBundle,
    pub limit_direction: PriceLimitDirection,
    pub limit_commitment: RistrettoPoint,
    pub limit_context: [u8; 32],
    pub price_limit_proof: ThresholdRangeProof,
    pub dvp_proofs: DvpProofs,
    pub cash_commitment: RistrettoPoint,
    pub securities_remainder: RistrettoPoint,
    pub cash_remainder: RistrettoPoint,
    pub securities_reserve: RistrettoPoint,
    pub cash_reserve: RistrettoPoint,
    pub securities_delivery_opening: OpeningEnvelope,
    pub securities_refund_opening: OpeningEnvelope,
    pub cash_delivery_opening: OpeningEnvelope,
    pub cash_refund_opening: OpeningEnvelope,
    pub asset_id: [u8; 32],
    pub asset_blinding: Scalar,
    pub execution_context: Option<ExecutionContext>,
    pub typed_authorization: Option<frost::Signature>,
}

impl SettlementHandoff {
    pub fn verify_opening_envelopes(&self) -> Result<(), String> {
        let payer = self.instruction.payer_handle;
        let payee = self.instruction.payee_handle;
        let expected = [
            (
                "securities_delivery",
                &self.securities_delivery_opening,
                payer,
            ),
            ("securities_refund", &self.securities_refund_opening, payee),
            ("cash_delivery", &self.cash_delivery_opening, payee),
            ("cash_refund", &self.cash_refund_opening, payer),
        ];
        for (leg, envelope, recipient) in expected {
            envelope.validate()?;
            if envelope.context != opening_context(&self.job_id, leg)?
                || envelope.recipient_view.compress() != recipient.compress()
            {
                return Err(format!(
                    "{leg} opening envelope is not bound to its proof job and recipient"
                ));
            }
        }
        Ok(())
    }

    pub fn typed_instruction(&self) -> Result<TypedInstruction, String> {
        let context = self
            .execution_context
            .clone()
            .ok_or_else(|| "settlement handoff has not been typed for DeFMI".to_string())?;
        let authorization = self
            .typed_authorization
            .ok_or_else(|| "settlement handoff lacks its typed FROST authorization".to_string())?;
        let digest = typed::digest_for(&self.instruction, &context, DEFAULT_DOMAIN)
            .map_err(str::to_string)?;
        self.frost_public
            .verifying_key()
            .verify(&digest, &authorization)
            .map_err(|_| "settlement handoff typed authorization is invalid".to_string())?;
        Ok(TypedInstruction {
            payment: self.instruction.clone(),
            context,
            authorization,
        })
    }
}

pub struct SettlementHandoffBundle {
    pub created_at: u64,
    pub source_digest: [u8; 32],
    pub cluster_digest: [u8; 32],
    pub order_digest: [u8; 32],
    pub admission_batch_digest: [u8; 32],
    pub slot: u32,
    /// Informational copy of the resident-node receipt keys. A DeFMI must
    /// compare these with its governance-pinned committee before trusting the
    /// signatures; bytes carried by the handoff are not their own trust root.
    pub admission_node_keys: Vec<[u8; 32]>,
    /// Exactly one seven-node attestation set for every real-or-cover lane.
    pub admission_lanes: Vec<Vec<NodeAdmissionAttestation>>,
    /// Exactly one seven-node signed execution-receipt set for every fixed
    /// admission lane. Each set binds the proof persistence bytes to the same
    /// admitted batch without disclosing their contents.
    pub execution_lanes: Vec<Vec<NodeExecutionAttestation>>,
    pub records: Vec<SettlementHandoff>,
}

impl SettlementHandoffBundle {
    pub fn declared_admission_keys(&self) -> Result<Vec<VerifyingKey>, String> {
        if self.admission_node_keys.len() != COMMITTEE_NODES {
            return Err("settlement handoff does not declare exactly seven admission keys".into());
        }
        self.admission_node_keys
            .iter()
            .map(|raw| {
                VerifyingKey::from_bytes(raw)
                    .map_err(|_| "settlement handoff admission key is not canonical".to_string())
            })
            .collect()
    }

    /// Verify the admission signatures against keys already trusted by the
    /// caller and bind every proof record to its exact fixed-population lane.
    pub fn verify_admission(
        &self,
        trusted_node_keys: &[VerifyingKey],
    ) -> Result<Vec<CertifiedAdmissionLane>, String> {
        if self.admission_lanes.is_empty()
            || self.admission_lanes.len() > 4096
            || self.admission_lanes.len() < self.records.len()
        {
            return Err("settlement handoff admission population is outside its bound".into());
        }
        if self.execution_lanes.len() != self.admission_lanes.len() {
            return Err("settlement handoff execution population differs from admission".into());
        }
        let mut lanes = self
            .admission_lanes
            .iter()
            .map(|values| verify_admission_lane(values, trusted_node_keys))
            .collect::<Result<Vec<_>, _>>()?;
        lanes.sort_by_key(|lane| lane.sequence);
        let executions = self
            .execution_lanes
            .iter()
            .map(|values| verify_execution_lane(values, trusted_node_keys, self.order_digest))
            .collect::<Result<Vec<_>, _>>()?;
        for (index, lane) in lanes.iter().enumerate() {
            if lane.sequence != index as u64 + 1
                || lane.slot != u64::from(self.slot)
                || lane.cluster_digest != self.cluster_digest
                || lane.order_digest != self.order_digest
            {
                return Err(
                    "settlement handoff admission lanes are incomplete or reordered".into(),
                );
            }
            let execution = &executions[index];
            if execution.slot != u64::from(self.slot)
                || execution.lane != index as u64
                || execution.cluster_digest != self.cluster_digest
                || execution.source_digest != self.source_digest
            {
                return Err(
                    "settlement handoff execution receipt differs from its admitted lane".into(),
                );
            }
        }
        for record in &self.records {
            let lane = lanes
                .get(record.lane)
                .ok_or_else(|| "settlement proof names an absent admission lane".to_string())?;
            if record.admission_sequence != lane.sequence
                || record.admission_ticket_id != lane.ticket_id
                || record.limit_context != lane.claim_digest
            {
                return Err(
                    "settlement proof metadata is not bound to its certified admission lane".into(),
                );
            }
            if record.instruction.quote_proof_digest() != Some(record.quote_digest) {
                return Err(
                    "settlement record is not bound to the quote proof signed by its zkPI".into(),
                );
            }
            if record.quote_verification.verify()? != record.quote_digest {
                return Err(
                    "settlement record quote digest does not match its complete proof".into(),
                );
            }
            record.verify_opening_envelopes()?;
            let execution = executions
                .get(record.lane)
                .ok_or_else(|| "settlement proof names an absent execution lane".to_string())?;
            if record.job_id != live_proof_job_id(self.slot, record.lane, execution.digest)? {
                return Err(
                    "settlement proof job is not bound to its signed MPC execution lane".into(),
                );
            }
            if record.quote_verification.context
                != complete_quote_context(record.job_id, record.limit_context)
            {
                return Err(
                    "settlement quote proof is not bound to its signed MPC execution lane".into(),
                );
            }
        }
        Ok(lanes)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireRecord {
    job_id: String,
    lane: usize,
    admission_sequence: u64,
    admission_ticket_id: String,
    instruction: String,
    frost_public: String,
    quote_digest: String,
    quote_verification: String,
    limit_direction: u8,
    limit_commitment: String,
    limit_context: String,
    price_limit_proof: String,
    dvp_proofs: String,
    cash_commitment: String,
    securities_remainder: String,
    cash_remainder: String,
    securities_reserve: String,
    cash_reserve: String,
    securities_delivery_opening: WireOpeningEnvelope,
    securities_refund_opening: WireOpeningEnvelope,
    cash_delivery_opening: WireOpeningEnvelope,
    cash_refund_opening: WireOpeningEnvelope,
    asset_id: String,
    asset_blinding: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    execution_context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    typed_authorization: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireOpeningShare {
    party: usize,
    ephemeral: String,
    masked_value: String,
    masked_blinding: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireOpeningEnvelope {
    context: String,
    threshold: usize,
    recipient_view: String,
    shares: Vec<WireOpeningShare>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireAdmissionAttestation {
    node: u16,
    slot: u64,
    sequence: u64,
    principal_digest: String,
    ticket_id: String,
    claim_digest: String,
    batch_digest: String,
    order_digest: String,
    signature: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireBundle {
    version: u8,
    private_handoff: bool,
    created_at: u64,
    source_digest: String,
    cluster_digest: String,
    order_digest: String,
    admission_batch_digest: String,
    slot: u32,
    admission_node_keys: Vec<String>,
    admission_lanes: Vec<Vec<WireAdmissionAttestation>>,
    execution_lanes: Vec<String>,
    records: Vec<WireRecord>,
}

fn encode_attestation(
    value: &NodeAdmissionAttestation,
) -> Result<WireAdmissionAttestation, String> {
    value.unsigned()?;
    Ok(WireAdmissionAttestation {
        node: value.node,
        slot: value.slot,
        sequence: value.sequence,
        principal_digest: hex32(value.principal_digest),
        ticket_id: hex32(value.ticket_id),
        claim_digest: hex32(value.claim_digest),
        batch_digest: hex32(value.batch_digest),
        order_digest: hex32(value.order_digest),
        signature: hex::encode(value.signature.to_bytes()),
    })
}

fn decode_attestation(value: WireAdmissionAttestation) -> Result<NodeAdmissionAttestation, String> {
    let signature: [u8; 64] = hex::decode(&value.signature)
        .map_err(|_| "admission signature is not hexadecimal".to_string())?
        .try_into()
        .map_err(|_| "admission signature is not 64 bytes".to_string())?;
    let result = NodeAdmissionAttestation {
        node: value.node,
        slot: value.slot,
        sequence: value.sequence,
        principal_digest: parse_hex32(&value.principal_digest, "admission principal")?,
        ticket_id: parse_hex32(&value.ticket_id, "admission ticket")?,
        claim_digest: parse_hex32(&value.claim_digest, "admission claim")?,
        batch_digest: parse_hex32(&value.batch_digest, "admission batch")?,
        order_digest: parse_hex32(&value.order_digest, "admission order")?,
        signature: Ed25519Signature::from_bytes(&signature),
    };
    result.unsigned()?;
    Ok(result)
}

fn hex32(value: [u8; 32]) -> String {
    hex::encode(value)
}

fn parse_hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    hex::decode(value)
        .map_err(|_| format!("{name} is not hexadecimal"))?
        .try_into()
        .map_err(|_| format!("{name} is not 32 bytes"))
}

fn parse_point(value: &str, name: &str) -> Result<RistrettoPoint, String> {
    CompressedRistretto(parse_hex32(value, name)?)
        .decompress()
        .ok_or_else(|| format!("{name} is not a canonical Ristretto point"))
}

fn parse_scalar(value: &str, name: &str) -> Result<Scalar, String> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(parse_hex32(value, name)?))
        .ok_or_else(|| format!("{name} is not a canonical Ristretto scalar"))
}

fn encode_opening_envelope(value: &OpeningEnvelope) -> Result<WireOpeningEnvelope, String> {
    value.validate()?;
    Ok(WireOpeningEnvelope {
        context: hex32(value.context),
        threshold: value.threshold,
        recipient_view: hex32(value.recipient_view.compress().to_bytes()),
        shares: value
            .shares
            .iter()
            .map(|share| WireOpeningShare {
                party: share.party,
                ephemeral: hex32(share.ephemeral.compress().to_bytes()),
                masked_value: hex32(share.masked_value.to_bytes()),
                masked_blinding: hex32(share.masked_blinding.to_bytes()),
            })
            .collect(),
    })
}

fn decode_opening_envelope(value: WireOpeningEnvelope) -> Result<OpeningEnvelope, String> {
    OpeningEnvelope::new(
        parse_hex32(&value.context, "opening context")?,
        value.threshold,
        parse_point(&value.recipient_view, "opening recipient")?,
        value
            .shares
            .into_iter()
            .map(|share| {
                Ok(EncryptedOpeningShare {
                    party: share.party,
                    ephemeral: parse_point(&share.ephemeral, "opening ephemeral")?,
                    masked_value: parse_scalar(&share.masked_value, "opening masked value")?,
                    masked_blinding: parse_scalar(
                        &share.masked_blinding,
                        "opening masked blinding",
                    )?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    )
}

fn encode_record(value: &SettlementHandoff) -> Result<WireRecord, String> {
    if value.execution_context.is_some() != value.typed_authorization.is_some() {
        return Err("settlement handoff has only half of its typed authorization".into());
    }
    if value.execution_context.is_some() {
        value.typed_instruction()?;
    }
    Ok(WireRecord {
        job_id: hex32(value.job_id),
        lane: value.lane,
        admission_sequence: value.admission_sequence,
        admission_ticket_id: hex32(value.admission_ticket_id),
        instruction: BASE64.encode(qomm_zkpi::wire::encode(&value.instruction)),
        frost_public: BASE64.encode(
            value
                .frost_public
                .serialize()
                .map_err(|_| "FROST public package serialization failed")?,
        ),
        quote_digest: hex32(value.quote_digest),
        quote_verification: BASE64.encode(encode_quote_verification(&value.quote_verification)?),
        limit_direction: value.limit_direction as u8,
        limit_commitment: hex32(value.limit_commitment.compress().to_bytes()),
        limit_context: hex32(value.limit_context),
        price_limit_proof: BASE64.encode(encode_threshold_range(&value.price_limit_proof)?),
        dvp_proofs: BASE64.encode(encode_dvp_proofs(&value.dvp_proofs)?),
        cash_commitment: hex32(value.cash_commitment.compress().to_bytes()),
        securities_remainder: hex32(value.securities_remainder.compress().to_bytes()),
        cash_remainder: hex32(value.cash_remainder.compress().to_bytes()),
        securities_reserve: hex32(value.securities_reserve.compress().to_bytes()),
        cash_reserve: hex32(value.cash_reserve.compress().to_bytes()),
        securities_delivery_opening: encode_opening_envelope(&value.securities_delivery_opening)?,
        securities_refund_opening: encode_opening_envelope(&value.securities_refund_opening)?,
        cash_delivery_opening: encode_opening_envelope(&value.cash_delivery_opening)?,
        cash_refund_opening: encode_opening_envelope(&value.cash_refund_opening)?,
        asset_id: hex32(value.asset_id),
        asset_blinding: hex32(value.asset_blinding.to_bytes()),
        execution_context: value
            .execution_context
            .as_ref()
            .map(|context| BASE64.encode(typed_wire::encode_context(context))),
        typed_authorization: value.typed_authorization.as_ref().map(|signature| {
            BASE64.encode(
                signature
                    .serialize()
                    .expect("a verified FROST signature serializes"),
            )
        }),
    })
}

fn decode_record(value: WireRecord) -> Result<SettlementHandoff, String> {
    let instruction = qomm_zkpi::wire::decode(
        &BASE64
            .decode(&value.instruction)
            .map_err(|_| "instruction is not valid base64")?,
    )
    .map_err(|error| format!("instruction wire is invalid: {error}"))?;
    let frost_public = frost::keys::PublicKeyPackage::deserialize(
        &BASE64
            .decode(&value.frost_public)
            .map_err(|_| "FROST public package is not valid base64")?,
    )
    .map_err(|_| "FROST public package is invalid".to_string())?;
    let limit_direction = match value.limit_direction {
        1 => PriceLimitDirection::MaximumBuyPrice,
        2 => PriceLimitDirection::MinimumSellPrice,
        _ => return Err("hidden-limit direction is invalid".into()),
    };
    if value.execution_context.is_some() != value.typed_authorization.is_some() {
        return Err("settlement handoff has only half of its typed authorization".into());
    }
    let execution_context = value
        .execution_context
        .as_deref()
        .map(|encoded| {
            let raw = BASE64
                .decode(encoded)
                .map_err(|_| "execution_context is not valid base64".to_string())?;
            typed_wire::decode_context(&raw, &instruction)
                .map_err(|_| "execution_context wire is invalid".to_string())
        })
        .transpose()?;
    let typed_authorization = value
        .typed_authorization
        .as_deref()
        .map(|encoded| {
            frost::Signature::deserialize(
                &BASE64
                    .decode(encoded)
                    .map_err(|_| "typed_authorization is not valid base64".to_string())?,
            )
            .map_err(|_| "typed_authorization is invalid".to_string())
        })
        .transpose()?;
    let record = SettlementHandoff {
        job_id: parse_hex32(&value.job_id, "job_id")?,
        lane: value.lane,
        admission_sequence: value.admission_sequence,
        admission_ticket_id: parse_hex32(&value.admission_ticket_id, "admission_ticket_id")?,
        instruction,
        frost_public,
        quote_digest: parse_hex32(&value.quote_digest, "quote_digest")?,
        quote_verification: decode_quote_verification(
            &BASE64
                .decode(&value.quote_verification)
                .map_err(|_| "quote_verification is not valid base64")?,
        )?,
        limit_direction,
        limit_commitment: parse_point(&value.limit_commitment, "limit_commitment")?,
        limit_context: parse_hex32(&value.limit_context, "limit_context")?,
        price_limit_proof: decode_threshold_range(
            &BASE64
                .decode(&value.price_limit_proof)
                .map_err(|_| "price_limit_proof is not valid base64")?,
        )?,
        dvp_proofs: decode_dvp_proofs(
            &BASE64
                .decode(&value.dvp_proofs)
                .map_err(|_| "dvp_proofs is not valid base64")?,
        )?,
        cash_commitment: parse_point(&value.cash_commitment, "cash_commitment")?,
        securities_remainder: parse_point(&value.securities_remainder, "securities_remainder")?,
        cash_remainder: parse_point(&value.cash_remainder, "cash_remainder")?,
        securities_reserve: parse_point(&value.securities_reserve, "securities_reserve")?,
        cash_reserve: parse_point(&value.cash_reserve, "cash_reserve")?,
        securities_delivery_opening: decode_opening_envelope(value.securities_delivery_opening)?,
        securities_refund_opening: decode_opening_envelope(value.securities_refund_opening)?,
        cash_delivery_opening: decode_opening_envelope(value.cash_delivery_opening)?,
        cash_refund_opening: decode_opening_envelope(value.cash_refund_opening)?,
        asset_id: parse_hex32(&value.asset_id, "asset_id")?,
        asset_blinding: parse_scalar(&value.asset_blinding, "asset_blinding")?,
        execution_context,
        typed_authorization,
    };
    if record.execution_context.is_some() {
        record.typed_instruction()?;
    }
    record.verify_opening_envelopes()?;
    Ok(record)
}

fn wire(value: &SettlementHandoffBundle) -> Result<WireBundle, String> {
    if value.records.is_empty() || value.records.len() > 4096 {
        return Err("settlement handoff record count is outside its bound".into());
    }
    let declared = value.declared_admission_keys()?;
    value.verify_admission(&declared)?;
    Ok(WireBundle {
        version: HANDOFF_VERSION,
        private_handoff: true,
        created_at: value.created_at,
        source_digest: hex32(value.source_digest),
        cluster_digest: hex32(value.cluster_digest),
        order_digest: hex32(value.order_digest),
        admission_batch_digest: hex32(value.admission_batch_digest),
        slot: value.slot,
        admission_node_keys: value
            .admission_node_keys
            .iter()
            .copied()
            .map(hex32)
            .collect(),
        admission_lanes: value
            .admission_lanes
            .iter()
            .map(|lane| lane.iter().map(encode_attestation).collect())
            .collect::<Result<Vec<Vec<_>>, _>>()?,
        execution_lanes: value
            .execution_lanes
            .iter()
            .map(|lane| encode_execution_attestations(lane).map(|raw| BASE64.encode(raw)))
            .collect::<Result<Vec<_>, _>>()?,
        records: value
            .records
            .iter()
            .map(encode_record)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub fn write_private(
    path: impl AsRef<Path>,
    value: &SettlementHandoffBundle,
) -> Result<(), String> {
    let path = path.as_ref();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec_pretty(&wire(value)?).map_err(|error| error.to_string())?;
    let temporary: PathBuf = parent.join(format!(
        ".qomm-settlement-handoff-{}.tmp",
        rand::random::<u64>()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| error.to_string())?;
        fs::rename(&temporary, path).map_err(|error| error.to_string())?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn read_private(path: impl AsRef<Path>) -> Result<SettlementHandoffBundle, String> {
    let path = path.as_ref();
    let metadata = path.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > 64 << 20
    {
        return Err("settlement handoff must be a bounded private regular file".into());
    }
    let value: WireBundle =
        serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
            .map_err(|error| format!("settlement handoff JSON is invalid: {error}"))?;
    if value.version != HANDOFF_VERSION
        || !value.private_handoff
        || value.records.is_empty()
        || value.records.len() > 4096
    {
        return Err("settlement handoff header is invalid".into());
    }
    let handoff = SettlementHandoffBundle {
        created_at: value.created_at,
        source_digest: parse_hex32(&value.source_digest, "source_digest")?,
        cluster_digest: parse_hex32(&value.cluster_digest, "cluster_digest")?,
        order_digest: parse_hex32(&value.order_digest, "order_digest")?,
        admission_batch_digest: parse_hex32(
            &value.admission_batch_digest,
            "admission_batch_digest",
        )?,
        slot: value.slot,
        admission_node_keys: value
            .admission_node_keys
            .iter()
            .map(|key| parse_hex32(key, "admission_node_key"))
            .collect::<Result<Vec<_>, _>>()?,
        admission_lanes: value
            .admission_lanes
            .into_iter()
            .map(|lane| lane.into_iter().map(decode_attestation).collect())
            .collect::<Result<Vec<Vec<_>>, _>>()?,
        execution_lanes: value
            .execution_lanes
            .into_iter()
            .map(|lane| {
                decode_execution_attestations(
                    &BASE64
                        .decode(lane)
                        .map_err(|_| "execution lane is not valid base64".to_string())?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?,
        records: value
            .records
            .into_iter()
            .map(decode_record)
            .collect::<Result<Vec<_>, _>>()?,
    };
    let declared = handoff.declared_admission_keys()?;
    handoff.verify_admission(&declared)?;
    Ok(handoff)
}
