//! Canonical Avalanche projection for DeFMI's account-free note rail.
//!
//! The cryptographic objects stay in Rust and are verified before a projection
//! can be built.  Avalanche stores only one-time note data, anonymity-set
//! roots, one-use serial points, proof digests, and the k-of-n-approved state
//! transition.  No stable account handle or owner identifier crosses this
//! boundary.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::facility::{
    CreditFacilityTransition, CreditTransitionKind, ProductSettlementBatchMember,
    ReservationAuthorization, ReservationConsumption, ReservationRole, ZERO,
};
use crate::note_settlement::{NoteDefmi, NoteDvpPackage};
use crate::notes::{Address, Note, NoteLedger, SpendProof};
use crate::settlement::ThresholdDvpPackage;
use crate::MAX_UNIX_TIME;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use qomm_proofs::opening_envelope::{opening_context, OpeningEnvelope};
use qomm_transport::standing_pool::{
    standing_note_pool_delegation_digest as shared_standing_note_pool_delegation_digest,
    standing_note_pool_id as shared_standing_note_pool_id, StandingPoolAllocationBinding,
    StandingPoolMakerAuthorization, StandingPoolNote,
};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::{
    frost,
    typed::{OperationKind, TradeDirection, TypedInstruction},
};

const NOTE_OUTPUT_DOMAIN: &[u8] = b"QOMM:DEFMI:NOTE-OUTPUT:v1";
const NOTE_ISSUE_DOMAIN: &[u8] = b"QOMM:DEFMI:NOTE-ISSUE:v1";
const NOTE_RING_DOMAIN: &[u8] = b"QOMM:DEFMI:NOTE-RING:v1";
const NOTE_SETTLEMENT_DOMAIN: &[u8] = b"QOMM:DEFMI:NOTE-SETTLEMENT:v1";
const NOTE_CLAIM_DOMAIN: &[u8] = b"QOMM:DEFMI:NOTE-CLAIM:v1";
const DELEGATED_NOTE_SETTLEMENT_DOMAIN: &[u8] = b"QOMM:DEFMI:DELEGATED-NOTE-SETTLEMENT:v1";
const NOTE_CLAIM_MATERIALIZE_DOMAIN: &[u8] = b"QOMM:DEFMI:NOTE-CLAIM-MATERIALIZE:v1";
const NOTE_CLAIM_RECIPIENT_DOMAIN: &[u8] = b"QOMM:DEFMI:NOTE-CLAIM-RECIPIENT:v1";
const NOTE_RESERVATION_ESCROW_DOMAIN: &[u8] = b"QOMM:DEFMI:NOTE-RESERVATION-ESCROW:v1";
const STANDING_NOTE_POOL_DOMAIN: &[u8] = b"QOMM:DEFMI:STANDING-NOTE-POOL:v1";
const STANDING_NOTE_POOL_ALLOCATION_DOMAIN: &[u8] = b"QOMM:DEFMI:STANDING-NOTE-POOL-ALLOCATION:v1";
const PRODUCT_NOTE_RELEASE_DOMAIN: &[u8] = b"QOMM:DEFMI:PRODUCT-NOTE-RELEASE:v1";
const PRODUCT_NOTE_NO_FILL_RELEASE_DOMAIN: &[u8] = b"QOMM:DEFMI:PRODUCT-NOTE-NO-FILL-RELEASE:v1";
const PRODUCT_NOTE_SETTLEMENT_DOMAIN: &[u8] = b"QOMM:DEFMI:PRODUCT-NOTE-SETTLEMENT:v1";
const STANDING_POOL_PRODUCT_SETTLEMENT_DOMAIN: &[u8] =
    b"QOMM:DEFMI:STANDING-POOL-PRODUCT-SETTLEMENT:v1";
const PRODUCT_SETTLEMENT_BATCH_DOMAIN: &[u8] = b"QOMM:DEFMI:PRODUCT-SETTLEMENT-BATCH:v1";
const NOTE_CLAIM_OWNERSHIP_DOMAIN: &[u8] = b"QOMM:DEFMI:NOTE-CLAIM-OWNERSHIP:v1";
const CSD_ISSUER_DOMAIN: &[u8] = b"QOMM:DEFMI:CSD-ISSUER:v1";
const CSD_ISSUER_CONTROL_DOMAIN: &[u8] = b"QOMM:DEFMI:CSD-ISSUER-CONTROL:v1";
const CSD_NOTE_AUTHORIZATION_DOMAIN: &[u8] = b"QOMM:DEFMI:CSD-NOTE-AUTHORIZATION:v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CsdIssuerDefinition {
    pub issuer_id: [u8; 32],
    pub code: String,
    pub jurisdiction: String,
    pub operator_entity_commitment: [u8; 32],
    pub public_key: [u8; 32],
    pub permitted_asset_ids: Vec<[u8; 32]>,
    pub policy_digest: [u8; 32],
    pub valid_from: u64,
    pub valid_until: u64,
}

impl CsdIssuerDefinition {
    pub fn body(&self) -> Result<Value, String> {
        let valid_code = |value: &str, max: usize| {
            !value.is_empty()
                && value.len() <= max
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._:/+-".contains(&byte))
        };
        if !valid_code(&self.code, 64)
            || !valid_code(&self.jurisdiction, 32)
            || self.valid_from == 0
            || self.valid_until <= self.valid_from
            || self.valid_until > MAX_UNIX_TIME
            || self.permitted_asset_ids.is_empty()
            || self.permitted_asset_ids.len() > 64
        {
            return Err("CSD issuer definition has invalid dimensions".into());
        }
        for (name, value) in [
            ("issuer_id", self.issuer_id),
            (
                "operator_entity_commitment",
                self.operator_entity_commitment,
            ),
            ("public_key", self.public_key),
            ("policy_digest", self.policy_digest),
        ] {
            nonzero(&value, name)?;
        }
        VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| "CSD issuer public key is malformed".to_string())?;
        if self.permitted_asset_ids.contains(&ZERO)
            || self
                .permitted_asset_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err("CSD permitted assets must be nonzero, sorted and unique".into());
        }
        Ok(json!({
            "issuer_id": hex::encode(self.issuer_id),
            "code": self.code,
            "jurisdiction": self.jurisdiction,
            "operator_entity_commitment": hex::encode(self.operator_entity_commitment),
            "public_key": hex::encode(self.public_key),
            "permitted_asset_ids": self.permitted_asset_ids.iter().map(hex::encode).collect::<Vec<_>>(),
            "policy_digest": hex::encode(self.policy_digest),
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(CSD_ISSUER_DOMAIN, &self.body()?)
    }

    pub fn permits(&self, asset_id: [u8; 32], now: u64) -> bool {
        self.valid_from <= now
            && now <= self.valid_until
            && self.permitted_asset_ids.binary_search(&asset_id).is_ok()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CsdIssuerControlKind {
    Activate,
    Suspend,
    Revoke,
}

impl CsdIssuerControlKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Activate => "activate",
            Self::Suspend => "suspend",
            Self::Revoke => "revoke",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CsdIssuerControl {
    pub operation_id: [u8; 32],
    pub issuer_id: [u8; 32],
    pub kind: CsdIssuerControlKind,
    pub before_sequence: u64,
    pub reason_digest: [u8; 32],
}

impl CsdIssuerControl {
    pub fn body(&self) -> Result<Value, String> {
        if self.before_sequence == u64::MAX {
            return Err("CSD issuer control sequence is invalid".into());
        }
        Ok(json!({
            "operation_id": nonzero(&self.operation_id, "operation_id")?,
            "issuer_id": nonzero(&self.issuer_id, "issuer_id")?,
            "kind": self.kind.as_str(),
            "before_sequence": self.before_sequence,
            "reason_digest": nonzero(&self.reason_digest, "reason_digest")?,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(CSD_ISSUER_CONTROL_DOMAIN, &self.body()?)
    }
}

fn canonical(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|error| error.to_string())
}

fn digest(domain: &[u8], value: &Value) -> Result<[u8; 32], String> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(canonical(value)?);
    Ok(hash.finalize().into())
}

fn nonzero(value: &[u8; 32], name: &str) -> Result<String, String> {
    if value == &ZERO {
        return Err(format!("{name} cannot be the all-zero identifier"));
    }
    Ok(hex::encode(value))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteOutput {
    pub note_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub one_time: [u8; 32],
    pub value_commitment: [u8; 32],
    pub ephemeral: [u8; 32],
    pub masked_value: [u8; 32],
    pub masked_blinding: [u8; 32],
    pub lock_id: [u8; 32],
}

impl NoteOutput {
    pub fn from_note(note: &Note, asset_id: [u8; 32], lock_id: [u8; 32]) -> Result<Self, String> {
        if asset_id == ZERO {
            return Err("note output needs an asset rail".into());
        }
        let mut output = Self {
            note_id: ZERO,
            asset_id,
            one_time: note.one_time.compress().to_bytes(),
            value_commitment: note.value_commitment.compress().to_bytes(),
            ephemeral: note.ephemeral.compress().to_bytes(),
            masked_value: note.masked_value.to_bytes(),
            masked_blinding: note.masked_blinding.to_bytes(),
            lock_id,
        };
        output.note_id = output.derived_id()?;
        output.validate()?;
        Ok(output)
    }

    fn content_body(&self) -> Value {
        json!({
            "asset_id": hex::encode(self.asset_id),
            "one_time": hex::encode(self.one_time),
            "value_commitment": hex::encode(self.value_commitment),
            "ephemeral": hex::encode(self.ephemeral),
            "masked_value": hex::encode(self.masked_value),
            "masked_blinding": hex::encode(self.masked_blinding),
            "lock_id": hex::encode(self.lock_id),
        })
    }

    pub fn body(&self) -> Result<Value, String> {
        self.validate()?;
        let mut body = self
            .content_body()
            .as_object()
            .cloned()
            .ok_or_else(|| "note output body is not an object".to_string())?;
        body.insert("note_id".into(), Value::String(hex::encode(self.note_id)));
        Ok(Value::Object(body))
    }

    pub fn from_body(value: &Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "note output must be an object".to_string())?;
        let expected = [
            "note_id",
            "asset_id",
            "one_time",
            "value_commitment",
            "ephemeral",
            "masked_value",
            "masked_blinding",
            "lock_id",
        ];
        if object.len() != expected.len()
            || expected.iter().any(|field| !object.contains_key(*field))
        {
            return Err("note output has missing or unknown fields".into());
        }
        let field = |name: &str| -> Result<[u8; 32], String> {
            hex::decode(
                object
                    .get(name)
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("note output {name} is not hexadecimal"))?,
            )
            .map_err(|_| format!("note output {name} is not hexadecimal"))?
            .try_into()
            .map_err(|_| format!("note output {name} is not 32 bytes"))
        };
        let output = Self {
            note_id: field("note_id")?,
            asset_id: field("asset_id")?,
            one_time: field("one_time")?,
            value_commitment: field("value_commitment")?,
            ephemeral: field("ephemeral")?,
            masked_value: field("masked_value")?,
            masked_blinding: field("masked_blinding")?,
            lock_id: field("lock_id")?,
        };
        output.validate()?;
        Ok(output)
    }

    pub fn derived_id(&self) -> Result<[u8; 32], String> {
        digest(NOTE_OUTPUT_DOMAIN, &self.content_body())
    }

    pub fn validate(&self) -> Result<(), String> {
        if [
            self.note_id,
            self.asset_id,
            self.one_time,
            self.value_commitment,
            self.ephemeral,
        ]
        .contains(&ZERO)
        {
            return Err("note output has an empty public field".into());
        }
        if self.derived_id()? != self.note_id {
            return Err("note identifier differs from its contents".into());
        }
        Ok(())
    }

    pub fn to_note(&self) -> Result<Note, String> {
        self.validate()?;
        let point = |encoded: [u8; 32], name: &str| {
            CompressedRistretto(encoded)
                .decompress()
                .ok_or_else(|| format!("canonical note {name} is not a Ristretto point"))
        };
        let scalar = |encoded: [u8; 32], name: &str| {
            Option::<Scalar>::from(Scalar::from_canonical_bytes(encoded))
                .ok_or_else(|| format!("canonical note {name} is not a scalar"))
        };
        Ok(Note {
            one_time: point(self.one_time, "one-time key")?,
            value_commitment: point(self.value_commitment, "value commitment")?,
            ephemeral: point(self.ephemeral, "ephemeral key")?,
            masked_value: scalar(self.masked_value, "masked value")?,
            masked_blinding: scalar(self.masked_blinding, "masked blinding")?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteIssuance {
    pub operation_id: [u8; 32],
    pub issuance_nonce: [u8; 32],
    pub issuer_id: [u8; 32],
    pub issued_at: u64,
    pub output: NoteOutput,
    pub proof_digest: [u8; 32],
    pub issuer_signature: Signature,
}

impl NoteIssuance {
    fn authorization_body(&self) -> Result<Value, String> {
        if self.output.lock_id != ZERO || self.issued_at == 0 || self.issued_at > MAX_UNIX_TIME {
            return Err("issuance has an invalid lock or timestamp".into());
        }
        Ok(json!({
            "operation_id": nonzero(&self.operation_id, "operation_id")?,
            "issuance_nonce": nonzero(&self.issuance_nonce, "issuance_nonce")?,
            "issuer_id": nonzero(&self.issuer_id, "issuer_id")?,
            "issued_at": self.issued_at,
            "output": self.output.body()?,
            "proof_digest": nonzero(&self.proof_digest, "proof_digest")?,
        }))
    }

    pub fn issuer_message(&self) -> Result<[u8; 32], String> {
        digest(CSD_NOTE_AUTHORIZATION_DOMAIN, &self.authorization_body()?)
    }

    pub fn sign_issuer(mut self, key: &SigningKey) -> Result<Self, String> {
        self.issuer_signature = key.sign(&self.issuer_message()?);
        Ok(self)
    }

    pub fn verify_issuer(&self, issuer: &CsdIssuerDefinition, now: u64) -> Result<(), String> {
        if self.issuer_id != issuer.issuer_id
            || !issuer.permits(self.output.asset_id, now)
            || !issuer.permits(self.output.asset_id, self.issued_at)
            || self.issued_at > now
            || now.saturating_sub(self.issued_at) > 300
        {
            return Err("CSD issuer, asset or issuance time is not authorized".into());
        }
        VerifyingKey::from_bytes(&issuer.public_key)
            .map_err(|_| "CSD issuer public key is malformed".to_string())?
            .verify(&self.issuer_message()?, &self.issuer_signature)
            .map_err(|_| "CSD issuer signature is invalid".to_string())
    }

    pub fn body(&self) -> Result<Value, String> {
        let mut body = self
            .authorization_body()?
            .as_object()
            .cloned()
            .ok_or_else(|| "CSD issuance body is not an object".to_string())?;
        body.insert(
            "issuer_signature".into(),
            Value::String(hex::encode(self.issuer_signature.to_bytes())),
        );
        Ok(Value::Object(body))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(NOTE_ISSUE_DOMAIN, &self.body()?)
    }
}

pub fn note_ring_root(asset_id: [u8; 32], ring: &[[u8; 32]]) -> Result<[u8; 32], String> {
    if asset_id == ZERO || ring.len() < 2 || ring.len() > 64 {
        return Err("note ring has invalid dimensions".into());
    }
    let mut hash = Sha256::new();
    hash.update(NOTE_RING_DOMAIN);
    hash.update(asset_id);
    hash.update((ring.len() as u16).to_be_bytes());
    for note_id in ring {
        nonzero(note_id, "ring note")?;
        hash.update(note_id);
    }
    Ok(hash.finalize().into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteSpend {
    pub asset_id: [u8; 32],
    pub ring: Vec<[u8; 32]>,
    pub ring_root: [u8; 32],
    pub serial_point: [u8; 32],
    pub input_lock_id: [u8; 32],
    pub proof_digest: [u8; 32],
    pub outputs: Vec<NoteOutput>,
}

impl NoteSpend {
    /// Verify a complete Rust proof, bind each local ring note to its canonical
    /// chain identifier, and only then create the consensus projection.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified<R: RngCore + CryptoRng>(
        ledger: &NoteLedger,
        ring: &[usize],
        proof: &SpendProof,
        notes: &[Note],
        asset_id: [u8; 32],
        ring_locks: &[[u8; 32]],
        input_lock_id: [u8; 32],
        output_locks: &[[u8; 32]],
        context: &[u8],
        rng: &mut R,
    ) -> Result<Self, String> {
        if ring.len() != ring_locks.len() || notes.len() != output_locks.len() {
            return Err("note lock metadata does not match proof dimensions".into());
        }
        let eligibility = ring_locks
            .iter()
            .map(|lock| {
                if input_lock_id == ZERO {
                    *lock == ZERO
                } else {
                    *lock == input_lock_id
                }
            })
            .collect::<Vec<_>>();
        ledger
            .check_spend_constrained(ring, proof, &eligibility, context, rng)
            .map_err(str::to_string)?;
        if notes.len() != proof.outputs.len()
            || notes
                .iter()
                .zip(&proof.outputs)
                .any(|(note, output)| note.value_commitment != *output)
        {
            return Err("projected notes differ from the verified spend outputs".into());
        }
        let mut ring_ids = Vec::with_capacity(ring.len());
        for (index, lock_id) in ring.iter().zip(ring_locks) {
            let note = ledger
                .notes
                .get(*index)
                .ok_or_else(|| "ring names a missing local note".to_string())?;
            ring_ids.push(NoteOutput::from_note(note, asset_id, *lock_id)?.note_id);
        }
        let outputs = notes
            .iter()
            .zip(output_locks)
            .map(|(note, lock)| NoteOutput::from_note(note, asset_id, *lock))
            .collect::<Result<Vec<_>, _>>()?;
        let spend = Self {
            asset_id,
            ring_root: note_ring_root(asset_id, &ring_ids)?,
            ring: ring_ids,
            serial_point: proof.serial_point.compress().to_bytes(),
            input_lock_id,
            proof_digest: proof.digest(),
            outputs,
        };
        spend.validate()?;
        Ok(spend)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.asset_id == ZERO
            || self.ring_root == ZERO
            || self.serial_point == ZERO
            || self.proof_digest == ZERO
            || self.ring.len() < 2
            || self.ring.len() > 64
            || !self.ring.len().is_power_of_two()
            || self.outputs.is_empty()
            || self.outputs.len() > 4
            || self.ring.iter().copied().collect::<BTreeSet<_>>().len() != self.ring.len()
            || self
                .outputs
                .iter()
                .map(|o| o.note_id)
                .collect::<BTreeSet<_>>()
                .len()
                != self.outputs.len()
            || note_ring_root(self.asset_id, &self.ring)? != self.ring_root
        {
            return Err("note spend is incomplete, duplicated, or malformed".into());
        }
        for output in &self.outputs {
            output.validate()?;
            if output.asset_id != self.asset_id {
                return Err("note spend changes asset rail".into());
            }
        }
        Ok(())
    }

    pub fn body(&self) -> Result<Value, String> {
        self.validate()?;
        Ok(json!({
            "asset_id": hex::encode(self.asset_id),
            "ring": self.ring.iter().map(hex::encode).collect::<Vec<_>>(),
            "ring_root": hex::encode(self.ring_root),
            "serial_point": hex::encode(self.serial_point),
            "input_lock_id": hex::encode(self.input_lock_id),
            "proof_digest": hex::encode(self.proof_digest),
            "outputs": self.outputs.iter().map(NoteOutput::body).collect::<Result<Vec<_>, _>>()?,
        }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteSettlementOrder {
    pub operation_id: [u8; 32],
    pub nullifier: [u8; 32],
    pub deadline: u64,
    pub payment_instruction_digest: [u8; 32],
    pub market_statement_digest: [u8; 32],
    pub dvp_proof_digest: [u8; 32],
    pub spends: Vec<NoteSpend>,
    /// When present, every same-asset input is proved independently but only
    /// this commitment-sum output is inserted.  This lets a private wallet
    /// defragment notes without exposing their values or minting supply.
    pub consolidated_output: Option<NoteOutput>,
}

impl NoteSettlementOrder {
    pub fn body(&self) -> Result<Value, String> {
        if self.deadline == 0
            || self.deadline > MAX_UNIX_TIME
            || self.spends.is_empty()
            || self.spends.len()
                > if self.consolidated_output.is_some() {
                    8
                } else {
                    2
                }
        {
            return Err("note settlement has invalid dimensions".into());
        }
        let mut assets = BTreeSet::new();
        let mut serials = BTreeSet::new();
        let mut outputs = BTreeSet::new();
        for spend in &self.spends {
            spend.validate()?;
            if !serials.insert(spend.serial_point) {
                return Err("note settlement repeats a serial".into());
            }
            if self.consolidated_output.is_none() && !assets.insert(spend.asset_id) {
                return Err("note settlement repeats an asset rail".into());
            }
            assets.insert(spend.asset_id);
            for output in &spend.outputs {
                if !outputs.insert(output.note_id) {
                    return Err("note settlement repeats an output".into());
                }
            }
        }
        if let Some(consolidated) = &self.consolidated_output {
            consolidated.validate()?;
            if self.spends.len() < 2
                || assets.len() != 1
                || consolidated.asset_id != self.spends[0].asset_id
                || consolidated.lock_id != ZERO
                || self.spends.iter().any(|spend| {
                    spend.input_lock_id != ZERO
                        || spend.outputs.len() != 1
                        || spend.outputs[0].lock_id != ZERO
                })
                || outputs.contains(&consolidated.note_id)
            {
                return Err("note consolidation has incompatible inputs or output".into());
            }
            let mut commitment = RistrettoPoint::identity();
            for spend in &self.spends {
                commitment += CompressedRistretto(spend.outputs[0].value_commitment)
                    .decompress()
                    .ok_or_else(|| {
                        "note consolidation input commitment is not canonical".to_string()
                    })?;
            }
            if commitment.compress().to_bytes() != consolidated.value_commitment {
                return Err("note consolidation changes the committed value".into());
            }
        }
        let mut body = json!({
            "operation_id": nonzero(&self.operation_id, "operation_id")?,
            "nullifier": nonzero(&self.nullifier, "nullifier")?,
            "deadline": self.deadline,
            "payment_instruction_digest": nonzero(&self.payment_instruction_digest, "payment_instruction_digest")?,
            "market_statement_digest": nonzero(&self.market_statement_digest, "market_statement_digest")?,
            "dvp_proof_digest": nonzero(&self.dvp_proof_digest, "dvp_proof_digest")?,
            "spends": self.spends.iter().map(NoteSpend::body).collect::<Result<Vec<_>, _>>()?,
        });
        if let Some(consolidated) = &self.consolidated_output {
            body.as_object_mut()
                .expect("note settlement body is an object")
                .insert("consolidated_output".into(), consolidated.body()?);
        }
        Ok(body)
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(NOTE_SETTLEMENT_DOMAIN, &self.body()?)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NoteClaimKind {
    Delivery,
    Refund,
}

impl NoteClaimKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Delivery => "delivery",
            Self::Refund => "refund",
        }
    }
}

/// An entitlement created by final DvP. The beneficiary may turn it into a
/// wallet note later, but that later withdrawal-like action is not a second
/// trade consent and cannot reverse settlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteClaim {
    pub claim_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub value_commitment: [u8; 32],
    pub recipient_commitment: [u8; 32],
    pub source_hold_id: [u8; 32],
    pub kind: NoteClaimKind,
    pub opening_envelope: OpeningEnvelope,
}

impl NoteClaim {
    fn content_body(&self) -> Result<Value, String> {
        self.opening_envelope.validate()?;
        Ok(json!({
            "asset_id": hex::encode(self.asset_id),
            "value_commitment": hex::encode(self.value_commitment),
            "recipient_commitment": hex::encode(self.recipient_commitment),
            "source_hold_id": hex::encode(self.source_hold_id),
            "kind": self.kind.as_str(),
            "opening_envelope": {
                "context": hex::encode(self.opening_envelope.context),
                "threshold": self.opening_envelope.threshold,
                "recipient_view": hex::encode(self.opening_envelope.recipient_view.compress().to_bytes()),
                "shares": self.opening_envelope.shares.iter().map(|share| json!({
                    "party": share.party,
                    "ephemeral": hex::encode(share.ephemeral.compress().to_bytes()),
                    "masked_value": hex::encode(share.masked_value.to_bytes()),
                    "masked_blinding": hex::encode(share.masked_blinding.to_bytes()),
                })).collect::<Vec<_>>(),
            },
        }))
    }

    pub fn derived_id(&self) -> Result<[u8; 32], String> {
        digest(NOTE_CLAIM_DOMAIN, &self.content_body()?)
    }

    pub fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("claim_id", self.claim_id),
            ("asset_id", self.asset_id),
            ("recipient_commitment", self.recipient_commitment),
            ("source_hold_id", self.source_hold_id),
        ] {
            nonzero(&value, name)?;
        }
        // An exact reserve legitimately leaves a zero refund. The Ristretto
        // identity is therefore valid for a refund commitment, but never for
        // the delivery leg of a non-zero trade.
        if self.value_commitment == ZERO && self.kind != NoteClaimKind::Refund {
            return Err("note claim delivery commitment cannot be zero".into());
        }
        if self.claim_id != self.derived_id()? {
            return Err("note claim identifier differs from its contents".into());
        }
        Ok(())
    }

    pub fn body(&self) -> Result<Value, String> {
        self.validate()?;
        let mut body = self
            .content_body()?
            .as_object()
            .cloned()
            .ok_or_else(|| "note claim body is not an object".to_string())?;
        body.insert("claim_id".into(), Value::String(hex::encode(self.claim_id)));
        Ok(Value::Object(body))
    }
}

/// Commit a private recipient key to one exact claim context. The handle is
/// shown only to the proof committee during later materialization; Avalanche
/// stores this one-use digest rather than a stable account identifier.
pub fn note_claim_recipient_commitment(
    recipient_handle: [u8; 32],
    rfq_nullifier: [u8; 32],
    asset_id: [u8; 32],
    hold_id: [u8; 32],
    kind: NoteClaimKind,
) -> Result<[u8; 32], String> {
    for (name, value) in [
        ("recipient_handle", recipient_handle),
        ("rfq_nullifier", rfq_nullifier),
        ("asset_id", asset_id),
        ("hold_id", hold_id),
    ] {
        nonzero(&value, name)?;
    }
    digest(
        NOTE_CLAIM_RECIPIENT_DOMAIN,
        &json!({
            "recipient_handle": hex::encode(recipient_handle),
            "rfq_nullifier": hex::encode(rfq_nullifier),
            "asset_id": hex::encode(asset_id),
            "hold_id": hex::encode(hold_id),
            "kind": kind.as_str(),
        }),
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowClaimSpend {
    pub asset_id: [u8; 32],
    pub hold_id: [u8; 32],
    pub escrow_note_id: [u8; 32],
    pub delegation_digest: [u8; 32],
    pub proof_digest: [u8; 32],
    pub claims: Vec<NoteClaim>,
}

impl EscrowClaimSpend {
    pub fn body(&self) -> Result<Value, String> {
        for (name, value) in [
            ("asset_id", self.asset_id),
            ("hold_id", self.hold_id),
            ("escrow_note_id", self.escrow_note_id),
            ("delegation_digest", self.delegation_digest),
            ("proof_digest", self.proof_digest),
        ] {
            nonzero(&value, name)?;
        }
        if self.claims.len() != 2 {
            return Err("delegated escrow spend needs delivery and refund claims".into());
        }
        let mut ids = BTreeSet::new();
        let mut kinds = BTreeSet::new();
        for claim in &self.claims {
            claim.validate()?;
            if claim.asset_id != self.asset_id
                || claim.source_hold_id != self.hold_id
                || !ids.insert(claim.claim_id)
                || !kinds.insert(claim.kind)
            {
                return Err("delegated escrow spend repeats or changes a claim".into());
            }
        }
        if !kinds.contains(&NoteClaimKind::Delivery) || !kinds.contains(&NoteClaimKind::Refund) {
            return Err("delegated escrow spend lacks delivery or refund".into());
        }
        Ok(json!({
            "asset_id": hex::encode(self.asset_id),
            "hold_id": hex::encode(self.hold_id),
            "escrow_note_id": hex::encode(self.escrow_note_id),
            "delegation_digest": hex::encode(self.delegation_digest),
            "proof_digest": hex::encode(self.proof_digest),
            "claims": self.claims.iter().map(NoteClaim::body).collect::<Result<Vec<_>, _>>()?,
        }))
    }
}

pub fn escrow_claim_serial(escrow_note_id: [u8; 32], hold_id: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"QOMM:DEFMI:ESCROW-CLAIM-SERIAL:v1");
    hash.update(escrow_note_id);
    hash.update(hold_id);
    hash.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegatedNoteSettlementOrder {
    pub operation_id: [u8; 32],
    pub nullifier: [u8; 32],
    pub deadline: u64,
    pub payment_instruction_digest: [u8; 32],
    pub market_statement_digest: [u8; 32],
    pub dvp_proof_digest: [u8; 32],
    pub spends: Vec<EscrowClaimSpend>,
}

impl DelegatedNoteSettlementOrder {
    pub fn body(&self) -> Result<Value, String> {
        if self.deadline == 0 || self.deadline > MAX_UNIX_TIME || self.spends.len() != 2 {
            return Err("delegated note settlement has invalid dimensions".into());
        }
        let mut assets = BTreeSet::new();
        let mut holds = BTreeSet::new();
        let mut claims = BTreeSet::new();
        for spend in &self.spends {
            spend.body()?;
            if !assets.insert(spend.asset_id) || !holds.insert(spend.hold_id) {
                return Err("delegated note settlement repeats an asset or hold".into());
            }
            for claim in &spend.claims {
                if !claims.insert(claim.claim_id) {
                    return Err("delegated note settlement repeats a claim".into());
                }
            }
        }
        Ok(json!({
            "operation_id": nonzero(&self.operation_id, "operation_id")?,
            "nullifier": nonzero(&self.nullifier, "nullifier")?,
            "deadline": self.deadline,
            "payment_instruction_digest": nonzero(&self.payment_instruction_digest, "payment_instruction_digest")?,
            "market_statement_digest": nonzero(&self.market_statement_digest, "market_statement_digest")?,
            "dvp_proof_digest": nonzero(&self.dvp_proof_digest, "dvp_proof_digest")?,
            "spends": self.spends.iter().map(EscrowClaimSpend::body).collect::<Result<Vec<_>, _>>()?,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(DELEGATED_NOTE_SETTLEMENT_DOMAIN, &self.body()?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteClaimMaterialization {
    pub operation_id: [u8; 32],
    pub claim_id: [u8; 32],
    pub output: NoteOutput,
    pub ownership_proof_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimOwnershipProof {
    pub nonce: RistrettoPoint,
    pub response: Scalar,
}

fn claim_ownership_challenge(
    claim: &NoteClaim,
    rfq_nullifier: [u8; 32],
    recipient_handle: &RistrettoPoint,
    destination: &Address,
    output: &NoteOutput,
    nonce: &RistrettoPoint,
) -> Scalar {
    let mut hash = sha2::Sha512::new();
    hash.update(NOTE_CLAIM_OWNERSHIP_DOMAIN);
    hash.update(claim.claim_id);
    hash.update(rfq_nullifier);
    hash.update(recipient_handle.compress().as_bytes());
    hash.update(destination.view.compress().as_bytes());
    hash.update(destination.spend.compress().as_bytes());
    hash.update(output.note_id);
    hash.update(nonce.compress().as_bytes());
    Scalar::from_bytes_mod_order_wide(&hash.finalize().into())
}

impl ClaimOwnershipProof {
    fn prove<R: RngCore + CryptoRng>(
        claim: &NoteClaim,
        rfq_nullifier: [u8; 32],
        recipient_secret: &Scalar,
        destination: &Address,
        output: &NoteOutput,
        rng: &mut R,
    ) -> Self {
        let recipient_handle = G * recipient_secret;
        let witness = Scalar::random(&mut *rng);
        let nonce = G * witness;
        let challenge = claim_ownership_challenge(
            claim,
            rfq_nullifier,
            &recipient_handle,
            destination,
            output,
            &nonce,
        );
        Self {
            nonce,
            response: witness + challenge * recipient_secret,
        }
    }

    pub fn verify(
        &self,
        claim: &NoteClaim,
        rfq_nullifier: [u8; 32],
        recipient_handle: &RistrettoPoint,
        destination: &Address,
        output: &NoteOutput,
    ) -> bool {
        let challenge = claim_ownership_challenge(
            claim,
            rfq_nullifier,
            recipient_handle,
            destination,
            output,
            &self.nonce,
        );
        G * self.response == self.nonce + recipient_handle * challenge
    }

    pub fn digest(
        &self,
        claim: &NoteClaim,
        rfq_nullifier: [u8; 32],
        recipient_handle: &RistrettoPoint,
        destination: &Address,
        output: &NoteOutput,
    ) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(NOTE_CLAIM_OWNERSHIP_DOMAIN);
        hash.update(claim.claim_id);
        hash.update(rfq_nullifier);
        hash.update(recipient_handle.compress().as_bytes());
        hash.update(destination.view.compress().as_bytes());
        hash.update(destination.spend.compress().as_bytes());
        hash.update(output.note_id);
        hash.update(self.nonce.compress().as_bytes());
        hash.update(self.response.to_bytes());
        hash.finalize().into()
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_claim_materialization(
    claim: &NoteClaim,
    rfq_nullifier: [u8; 32],
    recipient_handle: &RistrettoPoint,
    destination: &Address,
    materialization: &NoteClaimMaterialization,
    proof: &ClaimOwnershipProof,
) -> Result<(), String> {
    claim.validate()?;
    materialization.body()?;
    if materialization.claim_id != claim.claim_id
        || materialization.output.asset_id != claim.asset_id
        || materialization.output.value_commitment != claim.value_commitment
        || materialization.output.lock_id != ZERO
        || claim.opening_envelope.recipient_view.compress() != recipient_handle.compress()
        || claim.recipient_commitment
            != note_claim_recipient_commitment(
                recipient_handle.compress().to_bytes(),
                rfq_nullifier,
                claim.asset_id,
                claim.source_hold_id,
                claim.kind,
            )?
        || !proof.verify(
            claim,
            rfq_nullifier,
            recipient_handle,
            destination,
            &materialization.output,
        )
        || materialization.ownership_proof_digest
            != proof.digest(
                claim,
                rfq_nullifier,
                recipient_handle,
                destination,
                &materialization.output,
            )
    {
        return Err("claim materialization is not authorized by its one-use recipient".into());
    }
    Ok(())
}

/// Recipient-side construction. Only this caller decrypts the k-of-n opening;
/// the returned proof reveals neither amount nor Pedersen blinding.
#[allow(clippy::too_many_arguments)]
pub fn materialize_claim<R: RngCore + CryptoRng>(
    claim: &NoteClaim,
    key: &Pedersen,
    amount_bits: usize,
    rfq_nullifier: [u8; 32],
    recipient_secret: &Scalar,
    destination: &Address,
    quorum: &[usize],
    operation_id: [u8; 32],
    rng: &mut R,
) -> Result<(NoteClaimMaterialization, ClaimOwnershipProof), String> {
    claim.validate()?;
    let recipient_handle = G * recipient_secret;
    if claim.opening_envelope.recipient_view.compress() != recipient_handle.compress() {
        return Err("claim opening belongs to another recipient".into());
    }
    let (amount, blinding) =
        claim
            .opening_envelope
            .decrypt_u64(recipient_secret, quorum, amount_bits)?;
    let commitment = CompressedRistretto(claim.value_commitment)
        .decompress()
        .ok_or_else(|| "claim value commitment is not canonical".to_string())?;
    if key.commit_u64(amount, &blinding).compress() != commitment.compress() {
        return Err("decrypted claim opening does not match its final commitment".into());
    }
    let ledger = NoteLedger::new(key.clone(), amount_bits);
    let note = ledger.build_note(destination, amount, commitment, &blinding, &mut *rng);
    let output = NoteOutput::from_note(&note, claim.asset_id, ZERO)?;
    let proof = ClaimOwnershipProof::prove(
        claim,
        rfq_nullifier,
        recipient_secret,
        destination,
        &output,
        rng,
    );
    let mut materialization = NoteClaimMaterialization {
        operation_id,
        claim_id: claim.claim_id,
        output,
        ownership_proof_digest: ZERO,
    };
    materialization.ownership_proof_digest = proof.digest(
        claim,
        rfq_nullifier,
        &recipient_handle,
        destination,
        &materialization.output,
    );
    verify_claim_materialization(
        claim,
        rfq_nullifier,
        &recipient_handle,
        destination,
        &materialization,
        &proof,
    )?;
    Ok((materialization, proof))
}

impl NoteClaimMaterialization {
    pub fn body(&self) -> Result<Value, String> {
        if self.output.lock_id != ZERO {
            return Err("materialized claim output cannot retain a reservation lock".into());
        }
        Ok(json!({
            "operation_id": nonzero(&self.operation_id, "operation_id")?,
            "claim_id": nonzero(&self.claim_id, "claim_id")?,
            "output": self.output.body()?,
            "ownership_proof_digest": nonzero(&self.ownership_proof_digest, "ownership_proof_digest")?,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(NOTE_CLAIM_MATERIALIZE_DOMAIN, &self.body()?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteReservationEscrow {
    pub spend: NoteSpend,
    pub escrow_note_id: [u8; 32],
    pub delegation_digest: [u8; 32],
}

/// Stable identifier of a Maker-owned parent reserve.  It contains no account
/// address: the public ledger links an anonymous entity commitment, one signed
/// policy mandate, and a one-time locked note only.
pub fn standing_note_pool_id(
    entity_commitment: [u8; 32],
    policy_digest: [u8; 32],
    mandate_digest: [u8; 32],
    asset_id: [u8; 32],
    direction: u8,
) -> Result<[u8; 32], String> {
    shared_standing_note_pool_id(
        entity_commitment,
        policy_digest,
        mandate_digest,
        asset_id,
        direction,
    )
}

pub fn standing_note_pool_delegation_digest(
    pool_id: [u8; 32],
    venue_id: [u8; 32],
    defmi_id: [u8; 32],
    committee_epoch: u64,
    valid_until: u64,
) -> Result<[u8; 32], String> {
    if valid_until > MAX_UNIX_TIME {
        return Err("standing note pool delegation is incomplete".into());
    }
    shared_standing_note_pool_delegation_digest(
        pool_id,
        venue_id,
        defmi_id,
        committee_epoch,
        valid_until,
    )
}

/// Owner-signed creation of one anonymous parent reserve.  Later RFQs may
/// split this covenant under the exact policy mandate without another Maker
/// signature; every split still needs the resident k-of-n proof committee.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandingNotePoolRegistration {
    pub operation_id: [u8; 32],
    pub pool_id: [u8; 32],
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub entity_commitment: [u8; 32],
    pub policy_digest: [u8; 32],
    pub mandate_digest: [u8; 32],
    pub asset_id: [u8; 32],
    pub direction: u8,
    pub maximum_amount_commitment: [u8; 32],
    pub pool_note_id: [u8; 32],
    pub delegation_digest: [u8; 32],
    pub committee_epoch: u64,
    pub valid_until: u64,
    pub spend: NoteSpend,
}

impl StandingNotePoolRegistration {
    pub fn body(&self) -> Result<Value, String> {
        for (name, value) in [
            ("operation_id", self.operation_id),
            ("pool_id", self.pool_id),
            ("venue_id", self.venue_id),
            ("defmi_id", self.defmi_id),
            ("entity_commitment", self.entity_commitment),
            ("policy_digest", self.policy_digest),
            ("mandate_digest", self.mandate_digest),
            ("asset_id", self.asset_id),
            ("maximum_amount_commitment", self.maximum_amount_commitment),
            ("pool_note_id", self.pool_note_id),
            ("delegation_digest", self.delegation_digest),
        ] {
            nonzero(&value, name)?;
        }
        if self.pool_id
            != standing_note_pool_id(
                self.entity_commitment,
                self.policy_digest,
                self.mandate_digest,
                self.asset_id,
                self.direction,
            )?
            || self.delegation_digest
                != standing_note_pool_delegation_digest(
                    self.pool_id,
                    self.venue_id,
                    self.defmi_id,
                    self.committee_epoch,
                    self.valid_until,
                )?
            || self.spend.asset_id != self.asset_id
            || self.spend.input_lock_id != ZERO
        {
            return Err("standing note pool differs from its signed policy scope".into());
        }
        let locked = self
            .spend
            .outputs
            .iter()
            .filter(|output| output.lock_id == self.pool_id)
            .collect::<Vec<_>>();
        if locked.len() != 1
            || locked[0].note_id != self.pool_note_id
            || locked[0].value_commitment != self.maximum_amount_commitment
            || self
                .spend
                .outputs
                .iter()
                .any(|output| output.lock_id != ZERO && output.lock_id != self.pool_id)
        {
            return Err("standing note pool must create one exact parent covenant".into());
        }
        Ok(json!({
            "operation_id": hex::encode(self.operation_id),
            "pool_id": hex::encode(self.pool_id),
            "venue_id": hex::encode(self.venue_id),
            "defmi_id": hex::encode(self.defmi_id),
            "entity_commitment": hex::encode(self.entity_commitment),
            "policy_digest": hex::encode(self.policy_digest),
            "mandate_digest": hex::encode(self.mandate_digest),
            "asset_id": hex::encode(self.asset_id),
            "direction": self.direction,
            "maximum_amount_commitment": hex::encode(self.maximum_amount_commitment),
            "pool_note_id": hex::encode(self.pool_note_id),
            "delegation_digest": hex::encode(self.delegation_digest),
            "committee_epoch": self.committee_epoch,
            "valid_until": self.valid_until,
            "spend": self.spend.body()?,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(STANDING_NOTE_POOL_DOMAIN, &self.body()?)
    }
}

/// Exact per-RFQ allocation from a standing Maker pool. The Maker does not
/// sign or come online here. The already-registered proof committee signs the
/// allocation only after it has verified the winning quote and DvP relations.
#[derive(Clone)]
pub struct StandingNotePoolAllocation {
    pub pool_id: [u8; 32],
    pub delegation_digest: [u8; 32],
    pub committee_epoch: u64,
    pub expected_pool_sequence: u64,
    pub previous_pool_note_id: [u8; 32],
    pub previous_amount_commitment: [u8; 32],
    pub escrow_note: NoteOutput,
    pub remainder_note: NoteOutput,
    pub proof_job_id: [u8; 32],
    pub quote_proof_digest: [u8; 32],
    pub dvp_proof_digest: [u8; 32],
    pub remainder_range_proof_digest: [u8; 32],
    pub committee_signature: Vec<u8>,
}

impl StandingNotePoolAllocation {
    pub fn signing_binding(
        &self,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
    ) -> Result<StandingPoolAllocationBinding, String> {
        Ok(StandingPoolAllocationBinding {
            pool_id: self.pool_id,
            delegation_digest: self.delegation_digest,
            committee_epoch: self.committee_epoch,
            expected_pool_sequence: self.expected_pool_sequence,
            previous_pool_note_id: self.previous_pool_note_id,
            previous_amount_commitment: self.previous_amount_commitment,
            escrow_note: StandingPoolNote {
                note_id: self.escrow_note.note_id,
                asset_id: self.escrow_note.asset_id,
                one_time: self.escrow_note.one_time,
                value_commitment: self.escrow_note.value_commitment,
                ephemeral: self.escrow_note.ephemeral,
                masked_value: self.escrow_note.masked_value,
                masked_blinding: self.escrow_note.masked_blinding,
                lock_id: self.escrow_note.lock_id,
            },
            remainder_note: StandingPoolNote {
                note_id: self.remainder_note.note_id,
                asset_id: self.remainder_note.asset_id,
                one_time: self.remainder_note.one_time,
                value_commitment: self.remainder_note.value_commitment,
                ephemeral: self.remainder_note.ephemeral,
                masked_value: self.remainder_note.masked_value,
                masked_blinding: self.remainder_note.masked_blinding,
                lock_id: self.remainder_note.lock_id,
            },
            proof_job_id: self.proof_job_id,
            quote_proof_digest: self.quote_proof_digest,
            dvp_proof_digest: self.dvp_proof_digest,
            remainder_range_proof_digest: self.remainder_range_proof_digest,
            transition_statement: transition.statement()?,
            authorization: StandingPoolMakerAuthorization {
                entity_commitment: authorization.entity_commitment,
                asset_id: authorization.asset_id,
                direction: authorization.direction,
                policy_digest: authorization.authorization_digest,
                mandate_digest: authorization.mandate_digest,
                typed_reserve_digest: authorization.typed_reserve_digest,
                reserve_nullifier: authorization.reserve_nullifier,
                asset_link_proof_digest: authorization.asset_link_proof_digest,
                policy_version: authorization.policy_version,
            },
        })
    }

    fn unsigned_body(
        &self,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
    ) -> Result<Value, String> {
        transition.body()?;
        if transition.kind != CreditTransitionKind::Hold
            || authorization.role != ReservationRole::Maker
            || authorization.direction != 1 && authorization.direction != 2
            || authorization.policy_version == 0
            || transition.query_commitment != authorization.authorization_digest
            || authorization.limit_price_commitment != ZERO
            || authorization.rfq_nullifier != ZERO
            || authorization.admission_ticket_id != ZERO
            || authorization.admission_slot != 0
            || authorization.admission_receipt_digest != ZERO
            || authorization.admission_epoch != 0
            || authorization.admission_sequence != 0
            || authorization.admission_batch_id != ZERO
            || self.committee_epoch == 0
        {
            return Err("standing pool allocation is not a Maker policy hold".into());
        }
        for (name, value) in [
            ("pool_id", self.pool_id),
            ("delegation_digest", self.delegation_digest),
            ("previous_pool_note_id", self.previous_pool_note_id),
            (
                "previous_amount_commitment",
                self.previous_amount_commitment,
            ),
            ("proof_job_id", self.proof_job_id),
            ("quote_proof_digest", self.quote_proof_digest),
            ("dvp_proof_digest", self.dvp_proof_digest),
            (
                "remainder_range_proof_digest",
                self.remainder_range_proof_digest,
            ),
            ("entity_commitment", authorization.entity_commitment),
            ("authorization_digest", authorization.authorization_digest),
            ("mandate_digest", authorization.mandate_digest),
            ("typed_reserve_digest", authorization.typed_reserve_digest),
            ("reserve_nullifier", authorization.reserve_nullifier),
            (
                "asset_link_proof_digest",
                authorization.asset_link_proof_digest,
            ),
        ] {
            nonzero(&value, name)?;
        }
        if self.pool_id
            != standing_note_pool_id(
                authorization.entity_commitment,
                authorization.authorization_digest,
                authorization.mandate_digest,
                authorization.asset_id,
                authorization.direction,
            )?
        {
            return Err("standing allocation names another Maker policy pool".into());
        }
        self.escrow_note.validate()?;
        self.remainder_note.validate()?;
        if self.escrow_note.asset_id != authorization.asset_id
            || self.remainder_note.asset_id != authorization.asset_id
            || self.escrow_note.lock_id != transition.hold_id
            || self.remainder_note.lock_id != self.pool_id
            || self.escrow_note.value_commitment != transition.amount_commitment
            || self.escrow_note.note_id == self.remainder_note.note_id
            || self.previous_pool_note_id == self.escrow_note.note_id
            || self.previous_pool_note_id == self.remainder_note.note_id
        {
            return Err("standing allocation changes its asset, hold, or covenant".into());
        }
        let previous = CompressedRistretto(self.previous_amount_commitment)
            .decompress()
            .ok_or_else(|| "standing pool previous commitment is not canonical".to_string())?;
        let child = CompressedRistretto(self.escrow_note.value_commitment)
            .decompress()
            .ok_or_else(|| "standing pool child commitment is not canonical".to_string())?;
        let remainder = CompressedRistretto(self.remainder_note.value_commitment)
            .decompress()
            .ok_or_else(|| "standing pool remainder commitment is not canonical".to_string())?;
        if previous != child + remainder {
            return Err("standing allocation does not conserve its parent commitment".into());
        }
        self.signing_binding(transition, authorization)?.body()
    }

    pub fn signing_message(
        &self,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
    ) -> Result<[u8; 64], String> {
        self.unsigned_body(transition, authorization)?;
        self.signing_binding(transition, authorization)?
            .signing_message()
    }

    pub fn verify_committee_signature(
        &self,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
        public: &frost::keys::PublicKeyPackage,
    ) -> Result<(), String> {
        let signature = frost::Signature::deserialize(&self.committee_signature)
            .map_err(|_| "standing pool committee signature is malformed".to_string())?;
        public
            .verifying_key()
            .verify(
                &self.signing_message(transition, authorization)?,
                &signature,
            )
            .map_err(|_| "standing pool committee signature is invalid".to_string())
    }

    pub fn body(
        &self,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
    ) -> Result<Value, String> {
        frost::Signature::deserialize(&self.committee_signature)
            .map_err(|_| "standing pool committee signature is malformed".to_string())?;
        let mut body = self
            .unsigned_body(transition, authorization)?
            .as_object()
            .cloned()
            .ok_or_else(|| "standing pool allocation body is not an object".to_string())?;
        body.insert(
            "committee_signature".into(),
            Value::String(hex::encode(&self.committee_signature)),
        );
        Ok(Value::Object(body))
    }

    pub fn statement(
        &self,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
    ) -> Result<[u8; 32], String> {
        digest(
            STANDING_NOTE_POOL_ALLOCATION_DOMAIN,
            &self.body(transition, authorization)?,
        )
    }
}

impl NoteReservationEscrow {
    /// Verify the wallet's one-out-of-many spend and project exactly one
    /// covenant-locked reserve note. The owner signs here, before seeing any
    /// quote; later DvP consumes this covenant through its delegation digest
    /// without another Maker/Taker signature.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified<R: RngCore + CryptoRng>(
        ledger: &NoteLedger,
        ring: &[usize],
        proof: &SpendProof,
        notes: &[Note],
        asset_id: [u8; 32],
        ring_locks: &[[u8; 32]],
        output_locks: &[[u8; 32]],
        transition: &CreditFacilityTransition,
        delegation_digest: [u8; 32],
        context: &[u8],
        rng: &mut R,
    ) -> Result<Self, String> {
        if transition.kind != CreditTransitionKind::Hold || delegation_digest == ZERO {
            return Err("anonymous reservation needs a hold and delegation".into());
        }
        let spend = NoteSpend::from_verified(
            ledger,
            ring,
            proof,
            notes,
            asset_id,
            ring_locks,
            ZERO,
            output_locks,
            context,
            rng,
        )?;
        let locked = spend
            .outputs
            .iter()
            .filter(|output| output.lock_id == transition.hold_id)
            .collect::<Vec<_>>();
        if locked.len() != 1
            || locked[0].value_commitment != transition.amount_commitment
            || spend
                .outputs
                .iter()
                .any(|output| output.lock_id != ZERO && output.lock_id != transition.hold_id)
        {
            return Err("verified spend does not create the exact reservation covenant".into());
        }
        Ok(Self {
            escrow_note_id: locked[0].note_id,
            spend,
            delegation_digest,
        })
    }

    pub fn body(
        &self,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
    ) -> Result<Value, String> {
        if transition.kind != CreditTransitionKind::Hold
            || self.spend.asset_id != authorization.asset_id
            || self.spend.input_lock_id != ZERO
            || self.delegation_digest == ZERO
        {
            return Err("anonymous reservation escrow does not match its hold".into());
        }
        let locked = self
            .spend
            .outputs
            .iter()
            .filter(|output| output.lock_id == transition.hold_id)
            .collect::<Vec<_>>();
        if locked.len() != 1
            || locked[0].note_id != self.escrow_note_id
            || locked[0].value_commitment != transition.amount_commitment
            || self
                .spend
                .outputs
                .iter()
                .any(|output| output.lock_id != ZERO && output.lock_id != transition.hold_id)
        {
            return Err("reservation must create exactly one amount-bound escrow note".into());
        }
        Ok(json!({
            "hold_id": hex::encode(transition.hold_id),
            "amount_commitment": hex::encode(transition.amount_commitment),
            "asset_id": hex::encode(authorization.asset_id),
            "escrow_note_id": hex::encode(self.escrow_note_id),
            "delegation_digest": hex::encode(self.delegation_digest),
            "spend": self.spend.body()?,
        }))
    }

    pub fn statement(
        &self,
        transition: &CreditFacilityTransition,
        authorization: &ReservationAuthorization,
    ) -> Result<[u8; 32], String> {
        digest(
            NOTE_RESERVATION_ESCROW_DOMAIN,
            &self.body(transition, authorization)?,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductNoteReleaseOrder {
    pub transition: CreditFacilityTransition,
    pub role: ReservationRole,
    pub reserve_receipt_digest: [u8; 32],
    pub typed_instruction_digest: [u8; 32],
    pub release_nullifier: [u8; 32],
    pub release_deadline: u64,
    pub asset_id: [u8; 32],
    pub asset_link_proof_digest: [u8; 32],
    pub escrow_note_id: [u8; 32],
    pub spend: NoteSpend,
}

impl ProductNoteReleaseOrder {
    pub fn body(&self) -> Result<Value, String> {
        if self.transition.kind != CreditTransitionKind::Release
            || self.release_deadline <= self.transition.expires_at
            || self.release_deadline > MAX_UNIX_TIME
            || self.spend.asset_id != self.asset_id
            || self.spend.input_lock_id != self.transition.hold_id
            || self
                .spend
                .outputs
                .iter()
                .any(|output| output.lock_id != ZERO)
        {
            return Err("anonymous product release is inconsistent".into());
        }
        Ok(json!({
            "transition": self.transition.body()?,
            "role": self.role.as_str(),
            "reserve_receipt_digest": nonzero(&self.reserve_receipt_digest, "reserve_receipt_digest")?,
            "typed_instruction_digest": nonzero(&self.typed_instruction_digest, "typed_instruction_digest")?,
            "release_nullifier": nonzero(&self.release_nullifier, "release_nullifier")?,
            "release_deadline": self.release_deadline,
            "asset_id": nonzero(&self.asset_id, "asset_id")?,
            "asset_link_proof_digest": nonzero(&self.asset_link_proof_digest, "asset_link_proof_digest")?,
            "escrow_note_id": nonzero(&self.escrow_note_id, "escrow_note_id")?,
            "spend": self.spend.body()?,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(PRODUCT_NOTE_RELEASE_DOMAIN, &self.body()?)
    }
}

/// Early release of a Taker reservation after the resident committee has
/// certified a no-fill. The ordinary expiry release remains unchanged; this
/// wrapper binds the exact validator-verifiable no-fill evidence and admission
/// lane to the same atomic note/facility refund transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductNoteNoFillReleaseOrder {
    pub release: ProductNoteReleaseOrder,
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub admission_epoch: u64,
    pub admission_sequence: u64,
    pub no_fill_evidence_digest: [u8; 32],
}

impl ProductNoteNoFillReleaseOrder {
    pub fn body(&self) -> Result<Value, String> {
        if self.release.role != ReservationRole::Taker
            || self.venue_id == ZERO
            || self.defmi_id == ZERO
            || self.admission_epoch == 0
            || self.admission_sequence == 0
            || self.no_fill_evidence_digest == ZERO
        {
            return Err("no-fill release lacks its Taker, venue, epoch, or evidence".into());
        }
        Ok(json!({
            "release": self.release.body()?,
            "venue_id": hex::encode(self.venue_id),
            "defmi_id": hex::encode(self.defmi_id),
            "admission_epoch": self.admission_epoch,
            "admission_sequence": self.admission_sequence,
            "no_fill_evidence_digest": hex::encode(self.no_fill_evidence_digest),
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(PRODUCT_NOTE_NO_FILL_RELEASE_DOMAIN, &self.body()?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductNoteSettlementOrder {
    pub settlement: DelegatedNoteSettlementOrder,
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub maker_entity_commitment: [u8; 32],
    pub taker_entity_commitment: [u8; 32],
    pub rfq_nullifier: [u8; 32],
    pub taker_authorization_digest: [u8; 32],
    pub maker_policy_digest: [u8; 32],
    pub maker_mandate_digest: [u8; 32],
    pub taker_mandate_digest: [u8; 32],
    pub typed_instruction_digest: [u8; 32],
    pub quote_proof_digest: [u8; 32],
    pub price_limit_proof_digest: [u8; 32],
    pub dvp_proof_digest: [u8; 32],
    pub quantity_commitment: [u8; 32],
    pub cash_commitment: [u8; 32],
    pub traded_asset_id: [u8; 32],
    pub asset_link_proof_digest: [u8; 32],
    pub admission_receipt_digest: [u8; 32],
    pub admission_epoch: u64,
    pub admission_sequence: u64,
    pub reservations: Vec<ReservationConsumption>,
}

pub struct NoteLegProjection<'a> {
    pub asset_id: [u8; 32],
    pub ring_locks: &'a [[u8; 32]],
    pub input_lock_id: [u8; 32],
    pub output_locks: &'a [[u8; 32]],
}

/// Result of verifying both the typed zkPI and the complete confidential DvP.
/// The remaining product metadata can be attached only after the two credit
/// consumption transitions have been built against `settlement.statement()`.
pub struct VerifiedNoteSettlementProjection {
    pub settlement: NoteSettlementOrder,
    pub typed_instruction_digest: [u8; 32],
    pub quote_proof_digest: [u8; 32],
    pub dvp_proof_digest: [u8; 32],
    pub quantity_commitment: [u8; 32],
    pub cash_commitment: [u8; 32],
}

pub struct ProductNoteBindings {
    pub maker_entity_commitment: [u8; 32],
    pub taker_entity_commitment: [u8; 32],
    pub traded_asset_id: [u8; 32],
    pub price_limit_proof_digest: [u8; 32],
    pub asset_link_proof_digest: [u8; 32],
    pub admission_receipt_digest: [u8; 32],
    pub admission_epoch: u64,
    pub admission_sequence: u64,
    pub reservations: Vec<ReservationConsumption>,
}

impl VerifiedNoteSettlementProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn verify_and_project<R: RngCore + CryptoRng>(
        defmi: &NoteDefmi,
        typed: &TypedInstruction,
        package: &NoteDvpPackage,
        operation_id: [u8; 32],
        securities: NoteLegProjection<'_>,
        cash: NoteLegProjection<'_>,
        market_statement_digest: [u8; 32],
        context: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<Self, String> {
        if !matches!(
            typed.context.operation,
            OperationKind::Consume | OperationKind::Settle
        ) {
            return Err("account-free DvP needs a consume or settle zkPI".into());
        }
        defmi
            .venue
            .verify_typed(typed, now)
            .map_err(str::to_string)?;
        if qomm_zkpi::wire::encode(&typed.payment) != qomm_zkpi::wire::encode(&package.instruction)
        {
            return Err("typed zkPI and note DvP contain different payments".into());
        }
        if typed.context.market_statement_digest != market_statement_digest {
            return Err("note DvP names another reference-market statement".into());
        }
        defmi
            .verify(package, now, context, rng)
            .map_err(str::to_string)?;
        let securities_context = [context, b":sec"].concat();
        let cash_context = [context, b":cash"].concat();
        let securities_spend = NoteSpend::from_verified(
            &defmi.securities,
            &package.securities.ring,
            &package.securities.spend,
            &package.securities.notes,
            securities.asset_id,
            securities.ring_locks,
            securities.input_lock_id,
            securities.output_locks,
            &securities_context,
            rng,
        )?;
        let cash_spend = NoteSpend::from_verified(
            &defmi.cash,
            &package.cash.ring,
            &package.cash.spend,
            &package.cash.notes,
            cash.asset_id,
            cash.ring_locks,
            cash.input_lock_id,
            cash.output_locks,
            &cash_context,
            rng,
        )?;
        let typed_instruction_digest: [u8; 32] =
            Sha256::digest(qomm_zkpi::typed_wire::encode(typed)).into();
        let quote_proof_digest = typed
            .payment
            .quote_proof_digest()
            .ok_or_else(|| "account-free product zkPI lacks a quote-proof digest".to_string())?;
        if quote_proof_digest != typed.context.quote_proof_digest {
            return Err("typed zkPI has inconsistent quote-proof bindings".into());
        }
        let dvp_proof_digest = package.digest();
        let settlement = NoteSettlementOrder {
            operation_id,
            nullifier: typed.payment.nullifier(),
            deadline: typed.payment.deadline,
            payment_instruction_digest: typed_instruction_digest,
            market_statement_digest,
            dvp_proof_digest,
            spends: vec![securities_spend, cash_spend],
            consolidated_output: None,
        };
        settlement.body()?;
        Ok(Self {
            settlement,
            typed_instruction_digest,
            quote_proof_digest,
            dvp_proof_digest,
            quantity_commitment: typed.payment.amount_commitment.compress().to_bytes(),
            cash_commitment: package.cash_value_commitment.compress().to_bytes(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegatedNoteLegProjection {
    pub asset_id: [u8; 32],
    pub hold_id: [u8; 32],
    pub escrow_note_id: [u8; 32],
    pub delegation_digest: [u8; 32],
    pub reserve_commitment: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegatedClaimOpenings {
    pub proof_job_id: [u8; 32],
    pub securities_delivery: OpeningEnvelope,
    pub securities_refund: OpeningEnvelope,
    pub cash_delivery: OpeningEnvelope,
    pub cash_refund: OpeningEnvelope,
}

impl DelegatedClaimOpenings {
    pub fn validate(&self) -> Result<(), String> {
        nonzero(&self.proof_job_id, "proof_job_id")?;
        for (leg, envelope) in [
            ("securities_delivery", &self.securities_delivery),
            ("securities_refund", &self.securities_refund),
            ("cash_delivery", &self.cash_delivery),
            ("cash_refund", &self.cash_refund),
        ] {
            envelope.validate()?;
            if envelope.context != opening_context(&self.proof_job_id, leg)? {
                return Err(format!("{leg} opening is bound to another proof job"));
            }
        }
        Ok(())
    }
}

/// Threshold-proof-gated product settlement projection. Unlike
/// `VerifiedNoteSettlementProjection`, this constructor consumes no wallet
/// spend created after the quote: both source notes were delegated when their
/// reservations were made.
pub struct VerifiedDelegatedNoteSettlementProjection {
    pub settlement: DelegatedNoteSettlementOrder,
    pub typed_instruction_digest: [u8; 32],
    pub quote_proof_digest: [u8; 32],
    pub dvp_proof_digest: [u8; 32],
    pub quantity_commitment: [u8; 32],
    pub cash_commitment: [u8; 32],
    context: qomm_zkpi::typed::ExecutionContext,
}

struct ProjectedClaim<'a> {
    asset_id: [u8; 32],
    hold_id: [u8; 32],
    value_commitment: [u8; 32],
    recipient_handle: [u8; 32],
    rfq_nullifier: [u8; 32],
    kind: NoteClaimKind,
    proof_job_id: [u8; 32],
    opening_leg: &'a str,
    opening_envelope: OpeningEnvelope,
}

fn projected_claim(input: ProjectedClaim<'_>) -> Result<NoteClaim, String> {
    let ProjectedClaim {
        asset_id,
        hold_id,
        value_commitment,
        recipient_handle,
        rfq_nullifier,
        kind,
        proof_job_id,
        opening_leg,
        opening_envelope,
    } = input;
    let recipient = CompressedRistretto(recipient_handle)
        .decompress()
        .ok_or_else(|| "note claim recipient handle is not canonical".to_string())?;
    opening_envelope.validate()?;
    if opening_envelope.context != opening_context(&proof_job_id, opening_leg)?
        || opening_envelope.recipient_view.compress() != recipient.compress()
    {
        return Err("note claim opening is bound to another job or recipient".into());
    }
    let mut claim = NoteClaim {
        claim_id: ZERO,
        asset_id,
        value_commitment,
        recipient_commitment: note_claim_recipient_commitment(
            recipient_handle,
            rfq_nullifier,
            asset_id,
            hold_id,
            kind,
        )?,
        source_hold_id: hold_id,
        kind,
        opening_envelope,
    };
    claim.claim_id = claim.derived_id()?;
    claim.validate()?;
    Ok(claim)
}

impl VerifiedDelegatedNoteSettlementProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn verify_and_project(
        venue: &qomm_zkpi::Venue,
        typed: &TypedInstruction,
        package: &ThresholdDvpPackage,
        operation_id: [u8; 32],
        securities: DelegatedNoteLegProjection,
        cash: DelegatedNoteLegProjection,
        openings: DelegatedClaimOpenings,
        market_statement_digest: [u8; 32],
        now: u64,
    ) -> Result<Self, String> {
        openings.validate()?;
        if !matches!(
            typed.context.operation,
            OperationKind::Consume | OperationKind::Settle
        ) {
            return Err("delegated DvP needs a consume or settle zkPI".into());
        }
        venue.verify_typed(typed, now).map_err(str::to_string)?;
        if qomm_zkpi::wire::encode(&typed.payment) != qomm_zkpi::wire::encode(&package.instruction)
        {
            return Err("typed zkPI and threshold DvP contain different payments".into());
        }
        if typed.context.market_statement_digest != market_statement_digest {
            return Err("delegated DvP names another reference-market statement".into());
        }
        if package.securities_remainder_range.bits != package.cash_remainder_range.bits {
            return Err("threshold DvP remainder proofs use different range widths".into());
        }
        let securities_reserve = CompressedRistretto(securities.reserve_commitment)
            .decompress()
            .ok_or_else(|| "securities reserve commitment is not canonical".to_string())?;
        let cash_reserve = CompressedRistretto(cash.reserve_commitment)
            .decompress()
            .ok_or_else(|| "cash reserve commitment is not canonical".to_string())?;
        crate::settlement::verify_threshold_package(
            &venue.key,
            package,
            &securities_reserve,
            &cash_reserve,
            package.securities_remainder_range.bits,
        )?;
        let expected_sides = crate::settlement::Sides::of(&typed.payment);
        if package.securities_to != expected_sides.securities_to
            || package.cash_to != expected_sides.cash_to
        {
            return Err("threshold DvP pays recipients other than the signed zkPI".into());
        }
        let quote_proof_digest = typed
            .payment
            .quote_proof_digest()
            .ok_or_else(|| "delegated product zkPI lacks a quote-proof digest".to_string())?;
        if quote_proof_digest != typed.context.quote_proof_digest {
            return Err("typed zkPI has inconsistent quote-proof bindings".into());
        }
        let maker = typed.context.maker_handle.compress().to_bytes();
        let taker = typed.context.taker_handle.compress().to_bytes();
        let (securities_owner, securities_recipient, cash_owner, cash_recipient) =
            match typed.context.direction {
                TradeDirection::TakerBuys => (maker, taker, taker, maker),
                TradeDirection::TakerSells => (taker, maker, maker, taker),
            };
        let dvp_proof_digest = package.digest();
        let proof_job_id = openings.proof_job_id;
        let spend = |leg: DelegatedNoteLegProjection,
                     delivery_value: [u8; 32],
                     refund_value: [u8; 32],
                     delivery_recipient: [u8; 32],
                     refund_recipient: [u8; 32],
                     delivery_leg: &str,
                     refund_leg: &str,
                     delivery_opening: OpeningEnvelope,
                     refund_opening: OpeningEnvelope|
         -> Result<EscrowClaimSpend, String> {
            let value = EscrowClaimSpend {
                asset_id: leg.asset_id,
                hold_id: leg.hold_id,
                escrow_note_id: leg.escrow_note_id,
                delegation_digest: leg.delegation_digest,
                proof_digest: dvp_proof_digest,
                claims: vec![
                    projected_claim(ProjectedClaim {
                        asset_id: leg.asset_id,
                        hold_id: leg.hold_id,
                        value_commitment: delivery_value,
                        recipient_handle: delivery_recipient,
                        rfq_nullifier: typed.context.rfq_nullifier,
                        kind: NoteClaimKind::Delivery,
                        proof_job_id,
                        opening_leg: delivery_leg,
                        opening_envelope: delivery_opening,
                    })?,
                    projected_claim(ProjectedClaim {
                        asset_id: leg.asset_id,
                        hold_id: leg.hold_id,
                        value_commitment: refund_value,
                        recipient_handle: refund_recipient,
                        rfq_nullifier: typed.context.rfq_nullifier,
                        kind: NoteClaimKind::Refund,
                        proof_job_id,
                        opening_leg: refund_leg,
                        opening_envelope: refund_opening,
                    })?,
                ],
            };
            value.body()?;
            Ok(value)
        };
        let settlement = DelegatedNoteSettlementOrder {
            operation_id,
            nullifier: typed.payment.nullifier(),
            deadline: typed.payment.deadline,
            payment_instruction_digest: Sha256::digest(qomm_zkpi::typed_wire::encode(typed)).into(),
            market_statement_digest,
            dvp_proof_digest,
            spends: vec![
                spend(
                    securities,
                    typed.payment.amount_commitment.compress().to_bytes(),
                    package.securities_remainder.compress().to_bytes(),
                    securities_recipient,
                    securities_owner,
                    "securities_delivery",
                    "securities_refund",
                    openings.securities_delivery,
                    openings.securities_refund,
                )?,
                spend(
                    cash,
                    package.cash_commitment.compress().to_bytes(),
                    package.cash_remainder.compress().to_bytes(),
                    cash_recipient,
                    cash_owner,
                    "cash_delivery",
                    "cash_refund",
                    openings.cash_delivery,
                    openings.cash_refund,
                )?,
            ],
        };
        settlement.body()?;
        Ok(Self {
            typed_instruction_digest: settlement.payment_instruction_digest,
            quote_proof_digest,
            dvp_proof_digest,
            quantity_commitment: typed.payment.amount_commitment.compress().to_bytes(),
            cash_commitment: package.cash_commitment.compress().to_bytes(),
            settlement,
            context: typed.context.clone(),
        })
    }

    pub fn into_product(
        self,
        bindings: ProductNoteBindings,
    ) -> Result<ProductNoteSettlementOrder, String> {
        if self.context.maker_reservation_id == ZERO
            || self.context.taker_reservation_id == ZERO
            || self.context.maker_reservation_sequence == u64::MAX
            || self.context.taker_reservation_sequence == u64::MAX
        {
            return Err("typed zkPI has invalid reservation bindings".into());
        }
        let order = ProductNoteSettlementOrder {
            settlement: self.settlement,
            venue_id: self.context.venue_id,
            defmi_id: self.context.defmi_id,
            maker_entity_commitment: bindings.maker_entity_commitment,
            taker_entity_commitment: bindings.taker_entity_commitment,
            rfq_nullifier: self.context.rfq_nullifier,
            taker_authorization_digest: self.context.taker_mandate_digest,
            maker_policy_digest: self.context.maker_policy_digest,
            maker_mandate_digest: self.context.maker_mandate_digest,
            taker_mandate_digest: self.context.taker_mandate_digest,
            typed_instruction_digest: self.typed_instruction_digest,
            quote_proof_digest: self.quote_proof_digest,
            price_limit_proof_digest: bindings.price_limit_proof_digest,
            dvp_proof_digest: self.dvp_proof_digest,
            quantity_commitment: self.quantity_commitment,
            cash_commitment: self.cash_commitment,
            traded_asset_id: bindings.traded_asset_id,
            asset_link_proof_digest: bindings.asset_link_proof_digest,
            admission_receipt_digest: bindings.admission_receipt_digest,
            admission_epoch: bindings.admission_epoch,
            admission_sequence: bindings.admission_sequence,
            reservations: bindings.reservations,
        };
        let maker = order
            .reservations
            .iter()
            .find(|item| item.role == ReservationRole::Maker);
        let taker = order
            .reservations
            .iter()
            .find(|item| item.role == ReservationRole::Taker);
        if maker.map(|item| item.transition.hold_id) != Some(self.context.maker_reservation_id)
            || taker.map(|item| item.transition.hold_id) != Some(self.context.taker_reservation_id)
            || maker.map(|item| item.reserve_receipt_digest)
                != Some(self.context.maker_reserve_receipt_digest)
            || taker.map(|item| item.reserve_receipt_digest)
                != Some(self.context.taker_reserve_receipt_digest)
        {
            return Err("credit consumption differs from typed zkPI reservations".into());
        }
        order.body()?;
        Ok(order)
    }
}

impl ProductNoteSettlementOrder {
    pub fn body(&self) -> Result<Value, String> {
        if self.reservations.len() != 2
            || self.settlement.spends.len() != 2
            || self.admission_epoch == 0
            || self.admission_sequence == 0
            || self.settlement.payment_instruction_digest != self.typed_instruction_digest
            || self.settlement.dvp_proof_digest != self.dvp_proof_digest
        {
            return Err("anonymous product settlement is incomplete".into());
        }
        for value in [
            self.venue_id,
            self.defmi_id,
            self.maker_entity_commitment,
            self.taker_entity_commitment,
            self.rfq_nullifier,
            self.taker_authorization_digest,
            self.maker_policy_digest,
            self.maker_mandate_digest,
            self.taker_mandate_digest,
            self.typed_instruction_digest,
            self.quote_proof_digest,
            self.price_limit_proof_digest,
            self.dvp_proof_digest,
            self.quantity_commitment,
            self.cash_commitment,
            self.traded_asset_id,
            self.asset_link_proof_digest,
            self.admission_receipt_digest,
        ] {
            nonzero(&value, "anonymous product binding")?;
        }
        let mut assets = BTreeSet::new();
        for spend in &self.settlement.spends {
            assets.insert(spend.asset_id);
        }
        if assets.len() != 2 || !assets.contains(&self.traded_asset_id) {
            return Err("anonymous DvP does not contain traded and cash rails".into());
        }
        let base_statement = self.settlement.statement()?;
        let mut roles = BTreeSet::new();
        let mut holds = BTreeSet::new();
        let mut facilities = BTreeSet::new();
        for reservation in &self.reservations {
            let matching = self
                .settlement
                .spends
                .iter()
                .filter(|spend| spend.hold_id == reservation.transition.hold_id)
                .collect::<Vec<_>>();
            if reservation.transition.kind != CreditTransitionKind::Consume
                || reservation.transition.settlement_digest != base_statement
                || !roles.insert(reservation.role.as_str())
                || !holds.insert(reservation.transition.hold_id)
                || !facilities.insert(reservation.transition.facility_id)
                || matching.len() != 1
            {
                return Err("anonymous product reservation is not consumed exactly once".into());
            }
            let delivery = matching[0]
                .claims
                .iter()
                .find(|claim| claim.kind == NoteClaimKind::Delivery)
                .map(|claim| claim.value_commitment);
            let refund = matching[0]
                .claims
                .iter()
                .find(|claim| claim.kind == NoteClaimKind::Refund)
                .map(|claim| claim.value_commitment);
            if delivery != Some(reservation.transition.consumed_commitment)
                || refund != Some(reservation.transition.refund_commitment)
            {
                return Err("anonymous claims differ from credit consumption and refund".into());
            }
        }
        if !roles.contains(ReservationRole::Maker.as_str())
            || !roles.contains(ReservationRole::Taker.as_str())
        {
            return Err("anonymous product settlement lacks Maker or Taker reservation".into());
        }
        let reservations = self
            .reservations
            .iter()
            .map(|reservation| {
                Ok(json!({
                    "role": reservation.role.as_str(),
                    "reserve_receipt_digest": hex::encode(reservation.reserve_receipt_digest),
                    "transition": reservation.transition.body()?,
                }))
            })
            .collect::<Result<Vec<Value>, String>>()?;
        Ok(json!({
            "settlement": self.settlement.body()?,
            "venue_id": hex::encode(self.venue_id),
            "defmi_id": hex::encode(self.defmi_id),
            "maker_entity_commitment": hex::encode(self.maker_entity_commitment),
            "taker_entity_commitment": hex::encode(self.taker_entity_commitment),
            "rfq_nullifier": hex::encode(self.rfq_nullifier),
            "taker_authorization_digest": hex::encode(self.taker_authorization_digest),
            "maker_policy_digest": hex::encode(self.maker_policy_digest),
            "maker_mandate_digest": hex::encode(self.maker_mandate_digest),
            "taker_mandate_digest": hex::encode(self.taker_mandate_digest),
            "typed_instruction_digest": hex::encode(self.typed_instruction_digest),
            "quote_proof_digest": hex::encode(self.quote_proof_digest),
            "price_limit_proof_digest": hex::encode(self.price_limit_proof_digest),
            "dvp_proof_digest": hex::encode(self.dvp_proof_digest),
            "quantity_commitment": hex::encode(self.quantity_commitment),
            "cash_commitment": hex::encode(self.cash_commitment),
            "traded_asset_id": hex::encode(self.traded_asset_id),
            "asset_link_proof_digest": hex::encode(self.asset_link_proof_digest),
            "admission_receipt_digest": hex::encode(self.admission_receipt_digest),
            "admission_epoch": self.admission_epoch,
            "admission_sequence": self.admission_sequence,
            "reservations": reservations,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(PRODUCT_NOTE_SETTLEMENT_DOMAIN, &self.body()?)
    }
}

/// One governance statement for the Maker standing-pool split and the final
/// anonymous DvP. Validators execute both state changes on a private candidate
/// state and commit only when the complete proof bundle succeeds.
pub fn standing_pool_product_settlement_statement(
    allocation_transition: &CreditFacilityTransition,
    authorization: &ReservationAuthorization,
    allocation: &StandingNotePoolAllocation,
    order: &ProductNoteSettlementOrder,
    evidence_digest: [u8; 32],
) -> Result<[u8; 32], String> {
    let allocation_statement = allocation.statement(allocation_transition, authorization)?;
    let reserve_receipt_digest = authorization.statement(allocation_transition)?;
    let maker = order
        .reservations
        .iter()
        .find(|reservation| reservation.role == ReservationRole::Maker)
        .ok_or_else(|| "atomic standing-pool settlement has no Maker reservation".to_string())?;
    let maker_spend = order
        .settlement
        .spends
        .iter()
        .find(|spend| spend.hold_id == maker.transition.hold_id)
        .ok_or_else(|| "atomic standing-pool settlement omits the Maker covenant".to_string())?;
    let post_allocation_sequence = allocation_transition
        .before_sequence
        .checked_add(1)
        .ok_or_else(|| "standing-pool facility sequence overflow".to_string())?;

    if evidence_digest == ZERO
        || authorization.escrow_digest != allocation_statement
        || allocation_transition.kind != CreditTransitionKind::Hold
        || maker.transition.kind != CreditTransitionKind::Consume
        || maker.reserve_receipt_digest != reserve_receipt_digest
        || maker.transition.hold_id != allocation_transition.hold_id
        || maker.transition.facility_id != allocation_transition.facility_id
        || maker.transition.query_commitment != allocation_transition.query_commitment
        || maker.transition.amount_commitment != allocation_transition.amount_commitment
        || maker.transition.expires_at != allocation_transition.expires_at
        || maker.transition.before_sequence != post_allocation_sequence
        || maker.transition.before_available_commitment
            != allocation_transition.after_available_commitment
        || maker.transition.before_held_commitment != allocation_transition.after_held_commitment
        || maker.transition.before_outstanding_commitment
            != allocation_transition.after_outstanding_commitment
        || authorization.entity_commitment != order.maker_entity_commitment
        || authorization.authorization_digest != order.maker_policy_digest
        || authorization.mandate_digest != order.maker_mandate_digest
        || authorization.asset_id != maker_spend.asset_id
        || allocation.quote_proof_digest != order.quote_proof_digest
        || allocation.dvp_proof_digest != order.dvp_proof_digest
        || allocation.escrow_note.note_id != maker_spend.escrow_note_id
        || allocation.escrow_note.value_commitment != maker.transition.amount_commitment
        || allocation.delegation_digest != maker_spend.delegation_digest
        || allocation_transition.operation_id == maker.transition.operation_id
    {
        return Err(
            "standing-pool allocation and anonymous DvP are not one atomic settlement".into(),
        );
    }

    let body = json!({
        "allocation_transition": allocation_transition.body()?,
        "allocation_authorization": authorization.body(allocation_transition)?,
        "allocation": allocation.body(allocation_transition, authorization)?,
        "product_settlement": order.body()?,
        "evidence_digest": hex::encode(evidence_digest),
    });
    digest(STANDING_POOL_PRODUCT_SETTLEMENT_DOMAIN, &body)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductNoteSettlementBatch {
    pub batch_id: [u8; 32],
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub admission_epoch: u64,
    pub members: Vec<ProductSettlementBatchMember>,
}

impl ProductNoteSettlementBatch {
    pub fn from_orders(
        batch_id: [u8; 32],
        orders: &[ProductNoteSettlementOrder],
    ) -> Result<Self, String> {
        let first = orders
            .first()
            .ok_or_else(|| "anonymous product batch cannot be empty".to_string())?;
        let batch = Self {
            batch_id,
            venue_id: first.venue_id,
            defmi_id: first.defmi_id,
            admission_epoch: first.admission_epoch,
            members: orders
                .iter()
                .map(|order| {
                    Ok(ProductSettlementBatchMember {
                        admission_sequence: order.admission_sequence,
                        settlement_statement: order.statement()?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?,
        };
        batch.validate_orders(orders)?;
        Ok(batch)
    }

    pub fn validate_orders(&self, orders: &[ProductNoteSettlementOrder]) -> Result<(), String> {
        if self.batch_id == ZERO
            || self.venue_id == ZERO
            || self.defmi_id == ZERO
            || self.admission_epoch == 0
            || self.members.is_empty()
            || self.members.len() > 4096
            || self.members.len() != orders.len()
        {
            return Err("anonymous product batch is incomplete".into());
        }
        let mut previous = 0;
        let mut statements = BTreeSet::new();
        let mut operations = BTreeSet::from([self.batch_id]);
        let mut nullifiers = BTreeSet::new();
        let mut rfq_nullifiers = BTreeSet::new();
        let mut facilities = BTreeSet::new();
        let mut holds = BTreeSet::new();
        let mut escrow_serials = BTreeSet::new();
        let mut claims = BTreeSet::new();
        for (member, order) in self.members.iter().zip(orders) {
            if order.venue_id != self.venue_id
                || order.defmi_id != self.defmi_id
                || order.admission_epoch != self.admission_epoch
                || order.admission_sequence != member.admission_sequence
                || member.admission_sequence <= previous
                || member.settlement_statement != order.statement()?
                || !statements.insert(member.settlement_statement)
                || !operations.insert(order.settlement.operation_id)
                || !nullifiers.insert(order.settlement.nullifier)
                || !rfq_nullifiers.insert(order.rfq_nullifier)
            {
                return Err("anonymous product batch repeats or reorders a settlement".into());
            }
            for reservation in &order.reservations {
                if !operations.insert(reservation.transition.operation_id)
                    || !facilities.insert(reservation.transition.facility_id)
                    || !holds.insert(reservation.transition.hold_id)
                {
                    return Err(
                        "anonymous product batch reuses an operation, facility or hold".into(),
                    );
                }
            }
            for spend in &order.settlement.spends {
                if !escrow_serials.insert(escrow_claim_serial(spend.escrow_note_id, spend.hold_id))
                {
                    return Err("anonymous product batch reuses an escrow note".into());
                }
                for claim in &spend.claims {
                    if !claims.insert(claim.claim_id) {
                        return Err("anonymous product batch repeats a note claim".into());
                    }
                }
            }
            previous = member.admission_sequence;
        }
        Ok(())
    }

    pub fn body(&self) -> Result<Value, String> {
        if self.batch_id == ZERO || self.members.is_empty() || self.members.len() > 4096 {
            return Err("anonymous product batch is incomplete".into());
        }
        Ok(json!({
            "batch_id": hex::encode(self.batch_id),
            "venue_id": hex::encode(self.venue_id),
            "defmi_id": hex::encode(self.defmi_id),
            "admission_epoch": self.admission_epoch,
            "members": self.members.iter().map(|member| json!({
                "admission_sequence": member.admission_sequence,
                "settlement_statement": hex::encode(member.settlement_statement),
            })).collect::<Vec<_>>(),
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(PRODUCT_SETTLEMENT_BATCH_DOMAIN, &self.body()?)
    }
}

pub fn point_bytes(point: &RistrettoPoint) -> [u8; 32] {
    point.compress().to_bytes()
}
