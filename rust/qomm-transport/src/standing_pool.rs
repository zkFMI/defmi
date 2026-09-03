//! Canonical public bindings shared by the proof committee and DeFMI for a
//! Maker standing reserve.  Keeping these bytes below `qomm-defmi` lets every
//! proof node independently reconstruct exactly the message that Avalanche
//! validators later verify, without importing a ledger implementation or any
//! wallet secret.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use qomm_proofs::threshold_range::ThresholdRangeProof;
use qomm_zk::sigma::ProductProof;
use qomm_zkpi::Instruction;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256, Sha512};

use crate::dvp_issuer::DvpProofs;

const NOTE_OUTPUT_DOMAIN: &[u8] = b"QOMM:DEFMI:NOTE-OUTPUT:v1";
const STANDING_NOTE_POOL_ID_DOMAIN: &[u8] = b"QOMM:DEFMI:STANDING-NOTE-POOL-ID:v1";
const STANDING_NOTE_POOL_DELEGATION_DOMAIN: &[u8] = b"QOMM:DEFMI:STANDING-NOTE-POOL-DELEGATION:v1";
const STANDING_NOTE_POOL_ALLOCATION_SIGNING_DOMAIN: &[u8] =
    b"QOMM:DEFMI:STANDING-NOTE-POOL-ALLOCATION-SIGNING:v1";
const STANDING_POOL_TYPED_RESERVE_DOMAIN: &[u8] = b"QOMM:DEFMI:STANDING-POOL-TYPED-RESERVE:v1";
const STANDING_POOL_RESERVE_NULLIFIER_DOMAIN: &[u8] =
    b"QOMM:DEFMI:STANDING-POOL-RESERVE-NULLIFIER:v1";
const STANDING_POOL_ASSET_BINDING_DOMAIN: &[u8] = b"QOMM:DEFMI:STANDING-POOL-ASSET-BINDING:v1";
const THRESHOLD_DVP_PACKAGE_DOMAIN: &[u8] = b"QOMM:DEFMI:THRESHOLD-DVP-PACKAGE:v1";
const THRESHOLD_RANGE_DIGEST_DOMAIN: &[u8] = b"QOMM:DEFMI:THRESHOLD-RANGE-DIGEST:v1";

pub const SECURITIES_RAIL: &[u8] = b"securities";
pub const CASH_RAIL: &[u8] = b"cash";
pub const STANDING_POOL_REMAINDER_CONTEXT: &[u8] = b"qomm:defmi:standing-pool-remainder:v1";
pub const ZERO: [u8; 32] = [0; 32];

fn nonzero(value: &[u8; 32], name: &str) -> Result<(), String> {
    if value == &ZERO {
        Err(format!("{name} cannot be the all-zero identifier"))
    } else {
        Ok(())
    }
}

fn exact_keys(object: &Map<String, Value>, expected: &[&str], name: &str) -> Result<(), String> {
    if object.len() != expected.len() || expected.iter().any(|field| !object.contains_key(*field)) {
        return Err(format!("{name} has missing or unknown fields"));
    }
    Ok(())
}

fn object<'a>(value: &'a Value, name: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{name} must be an object"))
}

fn hex32(object: &Map<String, Value>, field: &str) -> Result<[u8; 32], String> {
    hex::decode(
        object
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{field} must be a 32-byte hexadecimal value"))?,
    )
    .map_err(|_| format!("{field} must be a 32-byte hexadecimal value"))?
    .try_into()
    .map_err(|_| format!("{field} must be a 32-byte hexadecimal value"))
}

fn unsigned(object: &Map<String, Value>, field: &str) -> Result<u64, String> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{field} must be an unsigned integer"))
}

fn digest_json(domain: &[u8], value: &Value) -> Result<[u8; 32], String> {
    Ok(Sha256::new()
        .chain_update(domain)
        .chain_update(serde_json::to_vec(value).map_err(|error| error.to_string())?)
        .finalize()
        .into())
}

/// Stable identifier of the covenant registered by one signed Maker policy.
pub fn standing_note_pool_id(
    entity_commitment: [u8; 32],
    policy_digest: [u8; 32],
    mandate_digest: [u8; 32],
    asset_id: [u8; 32],
    direction: u8,
) -> Result<[u8; 32], String> {
    for (name, value) in [
        ("entity_commitment", entity_commitment),
        ("policy_digest", policy_digest),
        ("mandate_digest", mandate_digest),
        ("asset_id", asset_id),
    ] {
        nonzero(&value, name)?;
    }
    if !matches!(direction, 1 | 2) {
        return Err("standing note pool direction is invalid".into());
    }
    digest_json(
        STANDING_NOTE_POOL_ID_DOMAIN,
        &json!({
            "entity_commitment": hex::encode(entity_commitment),
            "policy_digest": hex::encode(policy_digest),
            "mandate_digest": hex::encode(mandate_digest),
            "asset_id": hex::encode(asset_id),
            "direction": direction,
        }),
    )
}

/// Committee epoch and validity window delegated by the parent covenant.
pub fn standing_note_pool_delegation_digest(
    pool_id: [u8; 32],
    venue_id: [u8; 32],
    defmi_id: [u8; 32],
    committee_epoch: u64,
    valid_until: u64,
) -> Result<[u8; 32], String> {
    for (name, value) in [
        ("pool_id", pool_id),
        ("venue_id", venue_id),
        ("defmi_id", defmi_id),
    ] {
        nonzero(&value, name)?;
    }
    if committee_epoch == 0 || valid_until == 0 {
        return Err("standing note pool delegation is incomplete".into());
    }
    digest_json(
        STANDING_NOTE_POOL_DELEGATION_DOMAIN,
        &json!({
            "pool_id": hex::encode(pool_id),
            "venue_id": hex::encode(venue_id),
            "defmi_id": hex::encode(defmi_id),
            "committee_epoch": committee_epoch,
            "valid_until": valid_until,
        }),
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandingPoolNote {
    pub note_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub one_time: [u8; 32],
    pub value_commitment: [u8; 32],
    pub ephemeral: [u8; 32],
    pub masked_value: [u8; 32],
    pub masked_blinding: [u8; 32],
    pub lock_id: [u8; 32],
}

impl StandingPoolNote {
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

    pub fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("note_id", self.note_id),
            ("asset_id", self.asset_id),
            ("one_time", self.one_time),
            ("value_commitment", self.value_commitment),
            ("ephemeral", self.ephemeral),
        ] {
            nonzero(&value, name)?;
        }
        for (name, value) in [
            ("one_time", self.one_time),
            ("value_commitment", self.value_commitment),
            ("ephemeral", self.ephemeral),
        ] {
            CompressedRistretto(value)
                .decompress()
                .ok_or_else(|| format!("standing pool note {name} is not canonical"))?;
        }
        for (name, value) in [
            ("masked_value", self.masked_value),
            ("masked_blinding", self.masked_blinding),
        ] {
            Option::<Scalar>::from(Scalar::from_canonical_bytes(value))
                .ok_or_else(|| format!("standing pool note {name} is not canonical"))?;
        }
        if self.note_id != digest_json(NOTE_OUTPUT_DOMAIN, &self.content_body())? {
            return Err("standing pool note identifier differs from its contents".into());
        }
        Ok(())
    }

    pub fn body(&self) -> Result<Value, String> {
        self.validate()?;
        let mut body = self
            .content_body()
            .as_object()
            .cloned()
            .expect("standing pool note body is an object");
        body.insert("note_id".into(), Value::String(hex::encode(self.note_id)));
        Ok(Value::Object(body))
    }

    fn from_body(value: &Value, name: &str) -> Result<Self, String> {
        let object = object(value, name)?;
        exact_keys(
            object,
            &[
                "note_id",
                "asset_id",
                "one_time",
                "value_commitment",
                "ephemeral",
                "masked_value",
                "masked_blinding",
                "lock_id",
            ],
            name,
        )?;
        let note = Self {
            note_id: hex32(object, "note_id")?,
            asset_id: hex32(object, "asset_id")?,
            one_time: hex32(object, "one_time")?,
            value_commitment: hex32(object, "value_commitment")?,
            ephemeral: hex32(object, "ephemeral")?,
            masked_value: hex32(object, "masked_value")?,
            masked_blinding: hex32(object, "masked_blinding")?,
            lock_id: hex32(object, "lock_id")?,
        };
        note.validate()?;
        Ok(note)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandingPoolMakerAuthorization {
    pub entity_commitment: [u8; 32],
    pub asset_id: [u8; 32],
    pub direction: u8,
    pub policy_digest: [u8; 32],
    pub mandate_digest: [u8; 32],
    pub typed_reserve_digest: [u8; 32],
    pub reserve_nullifier: [u8; 32],
    pub asset_link_proof_digest: [u8; 32],
    pub policy_version: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandingPoolReservationMetadata {
    pub typed_reserve_digest: [u8; 32],
    pub reserve_nullifier: [u8; 32],
    pub asset_link_proof_digest: [u8; 32],
}

/// Derive the three public reservation identifiers from the exact parent
/// version and verifier-complete MPC evidence. They are not coordinator-chosen
/// labels: both the proof nodes and DeFMI validators recompute them from the
/// allocation binding, which prevents swapping an older reserve receipt or an
/// asset-binding digest into a later RFQ.
#[allow(clippy::too_many_arguments)]
pub fn standing_pool_reservation_metadata(
    pool_id: [u8; 32],
    delegation_digest: [u8; 32],
    expected_pool_sequence: u64,
    previous_pool_note_id: [u8; 32],
    proof_job_id: [u8; 32],
    quote_proof_digest: [u8; 32],
    dvp_proof_digest: [u8; 32],
    transition_statement: [u8; 32],
    entity_commitment: [u8; 32],
    asset_id: [u8; 32],
    direction: u8,
    policy_digest: [u8; 32],
    mandate_digest: [u8; 32],
    policy_version: u64,
) -> Result<StandingPoolReservationMetadata, String> {
    for (name, value) in [
        ("pool_id", pool_id),
        ("delegation_digest", delegation_digest),
        ("previous_pool_note_id", previous_pool_note_id),
        ("proof_job_id", proof_job_id),
        ("quote_proof_digest", quote_proof_digest),
        ("dvp_proof_digest", dvp_proof_digest),
        ("transition_statement", transition_statement),
        ("entity_commitment", entity_commitment),
        ("asset_id", asset_id),
        ("policy_digest", policy_digest),
        ("mandate_digest", mandate_digest),
    ] {
        nonzero(&value, name)?;
    }
    if !matches!(direction, 1 | 2) || policy_version == 0 {
        return Err("standing pool reservation metadata has invalid policy scope".into());
    }
    let body = json!({
        "pool_id": hex::encode(pool_id),
        "delegation_digest": hex::encode(delegation_digest),
        "expected_pool_sequence": expected_pool_sequence,
        "previous_pool_note_id": hex::encode(previous_pool_note_id),
        "proof_job_id": hex::encode(proof_job_id),
        "quote_proof_digest": hex::encode(quote_proof_digest),
        "dvp_proof_digest": hex::encode(dvp_proof_digest),
        "transition_statement": hex::encode(transition_statement),
        "entity_commitment": hex::encode(entity_commitment),
        "asset_id": hex::encode(asset_id),
        "direction": direction,
        "policy_digest": hex::encode(policy_digest),
        "mandate_digest": hex::encode(mandate_digest),
        "policy_version": policy_version,
    });
    Ok(StandingPoolReservationMetadata {
        typed_reserve_digest: digest_json(STANDING_POOL_TYPED_RESERVE_DOMAIN, &body)?,
        reserve_nullifier: digest_json(STANDING_POOL_RESERVE_NULLIFIER_DOMAIN, &body)?,
        asset_link_proof_digest: digest_json(STANDING_POOL_ASSET_BINDING_DOMAIN, &body)?,
    })
}

impl StandingPoolMakerAuthorization {
    fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("entity_commitment", self.entity_commitment),
            ("asset_id", self.asset_id),
            ("authorization_digest", self.policy_digest),
            ("mandate_digest", self.mandate_digest),
            ("typed_reserve_digest", self.typed_reserve_digest),
            ("reserve_nullifier", self.reserve_nullifier),
            ("asset_link_proof_digest", self.asset_link_proof_digest),
        ] {
            nonzero(&value, name)?;
        }
        if !matches!(self.direction, 1 | 2) || self.policy_version == 0 {
            return Err("standing pool Maker authorization is incomplete".into());
        }
        Ok(())
    }

    fn body(&self) -> Result<Value, String> {
        self.validate()?;
        Ok(json!({
            "entity_commitment": hex::encode(self.entity_commitment),
            "asset_id": hex::encode(self.asset_id),
            "direction": self.direction,
            "authorization_digest": hex::encode(self.policy_digest),
            "mandate_digest": hex::encode(self.mandate_digest),
            "typed_reserve_digest": hex::encode(self.typed_reserve_digest),
            "reserve_nullifier": hex::encode(self.reserve_nullifier),
            "asset_link_proof_digest": hex::encode(self.asset_link_proof_digest),
            "policy_version": self.policy_version,
        }))
    }

    fn from_body(value: &Value) -> Result<Self, String> {
        let object = object(value, "allocation authorization")?;
        exact_keys(
            object,
            &[
                "entity_commitment",
                "asset_id",
                "direction",
                "authorization_digest",
                "mandate_digest",
                "typed_reserve_digest",
                "reserve_nullifier",
                "asset_link_proof_digest",
                "policy_version",
            ],
            "allocation authorization",
        )?;
        let direction = u8::try_from(unsigned(object, "direction")?)
            .map_err(|_| "allocation direction exceeds u8".to_string())?;
        let authorization = Self {
            entity_commitment: hex32(object, "entity_commitment")?,
            asset_id: hex32(object, "asset_id")?,
            direction,
            policy_digest: hex32(object, "authorization_digest")?,
            mandate_digest: hex32(object, "mandate_digest")?,
            typed_reserve_digest: hex32(object, "typed_reserve_digest")?,
            reserve_nullifier: hex32(object, "reserve_nullifier")?,
            asset_link_proof_digest: hex32(object, "asset_link_proof_digest")?,
            policy_version: unsigned(object, "policy_version")?,
        };
        authorization.validate()?;
        Ok(authorization)
    }
}

/// The exact public message signed by the proof committee to allocate one
/// child escrow and one new parent remainder.  No participant address or
/// commitment opening appears here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandingPoolAllocationBinding {
    pub pool_id: [u8; 32],
    pub delegation_digest: [u8; 32],
    pub committee_epoch: u64,
    pub expected_pool_sequence: u64,
    pub previous_pool_note_id: [u8; 32],
    pub previous_amount_commitment: [u8; 32],
    pub escrow_note: StandingPoolNote,
    pub remainder_note: StandingPoolNote,
    pub proof_job_id: [u8; 32],
    pub quote_proof_digest: [u8; 32],
    pub dvp_proof_digest: [u8; 32],
    pub remainder_range_proof_digest: [u8; 32],
    pub transition_statement: [u8; 32],
    pub authorization: StandingPoolMakerAuthorization,
}

impl StandingPoolAllocationBinding {
    pub fn validate(&self) -> Result<(), String> {
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
            ("transition_statement", self.transition_statement),
        ] {
            nonzero(&value, name)?;
        }
        if self.committee_epoch == 0 {
            return Err("standing pool committee epoch is zero".into());
        }
        self.authorization.validate()?;
        self.escrow_note.validate()?;
        self.remainder_note.validate()?;
        if self.pool_id
            != standing_note_pool_id(
                self.authorization.entity_commitment,
                self.authorization.policy_digest,
                self.authorization.mandate_digest,
                self.authorization.asset_id,
                self.authorization.direction,
            )?
            || self.escrow_note.asset_id != self.authorization.asset_id
            || self.remainder_note.asset_id != self.authorization.asset_id
            || self.escrow_note.lock_id == ZERO
            || self.remainder_note.lock_id != self.pool_id
            || self.escrow_note.note_id == self.remainder_note.note_id
            || self.previous_pool_note_id == self.escrow_note.note_id
            || self.previous_pool_note_id == self.remainder_note.note_id
        {
            return Err("standing pool allocation changes its covenant scope".into());
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
            return Err("standing pool allocation does not conserve its parent".into());
        }
        let metadata = standing_pool_reservation_metadata(
            self.pool_id,
            self.delegation_digest,
            self.expected_pool_sequence,
            self.previous_pool_note_id,
            self.proof_job_id,
            self.quote_proof_digest,
            self.dvp_proof_digest,
            self.transition_statement,
            self.authorization.entity_commitment,
            self.authorization.asset_id,
            self.authorization.direction,
            self.authorization.policy_digest,
            self.authorization.mandate_digest,
            self.authorization.policy_version,
        )?;
        if self.authorization.typed_reserve_digest != metadata.typed_reserve_digest
            || self.authorization.reserve_nullifier != metadata.reserve_nullifier
            || self.authorization.asset_link_proof_digest != metadata.asset_link_proof_digest
        {
            return Err(
                "standing pool reservation metadata is not derived from this allocation".into(),
            );
        }
        Ok(())
    }

    pub fn body(&self) -> Result<Value, String> {
        self.validate()?;
        Ok(json!({
            "pool_id": hex::encode(self.pool_id),
            "delegation_digest": hex::encode(self.delegation_digest),
            "committee_epoch": self.committee_epoch,
            "expected_pool_sequence": self.expected_pool_sequence,
            "previous_pool_note_id": hex::encode(self.previous_pool_note_id),
            "previous_amount_commitment": hex::encode(self.previous_amount_commitment),
            "escrow_note": self.escrow_note.body()?,
            "remainder_note": self.remainder_note.body()?,
            "proof_job_id": hex::encode(self.proof_job_id),
            "quote_proof_digest": hex::encode(self.quote_proof_digest),
            "dvp_proof_digest": hex::encode(self.dvp_proof_digest),
            "remainder_range_proof_digest": hex::encode(self.remainder_range_proof_digest),
            "transition_statement": hex::encode(self.transition_statement),
            "authorization": self.authorization.body()?,
        }))
    }

    pub fn signing_message(&self) -> Result<[u8; 64], String> {
        let body = serde_json::to_vec(&self.body()?).map_err(|error| error.to_string())?;
        Ok(Sha512::new()
            .chain_update(STANDING_NOTE_POOL_ALLOCATION_SIGNING_DOMAIN)
            .chain_update((body.len() as u64).to_be_bytes())
            .chain_update(body)
            .finalize()
            .into())
    }

    pub fn from_body(value: &Value) -> Result<Self, String> {
        let object = object(value, "standing pool allocation binding")?;
        exact_keys(
            object,
            &[
                "pool_id",
                "delegation_digest",
                "committee_epoch",
                "expected_pool_sequence",
                "previous_pool_note_id",
                "previous_amount_commitment",
                "escrow_note",
                "remainder_note",
                "proof_job_id",
                "quote_proof_digest",
                "dvp_proof_digest",
                "remainder_range_proof_digest",
                "transition_statement",
                "authorization",
            ],
            "standing pool allocation binding",
        )?;
        let binding = Self {
            pool_id: hex32(object, "pool_id")?,
            delegation_digest: hex32(object, "delegation_digest")?,
            committee_epoch: unsigned(object, "committee_epoch")?,
            expected_pool_sequence: unsigned(object, "expected_pool_sequence")?,
            previous_pool_note_id: hex32(object, "previous_pool_note_id")?,
            previous_amount_commitment: hex32(object, "previous_amount_commitment")?,
            escrow_note: StandingPoolNote::from_body(
                object
                    .get("escrow_note")
                    .ok_or_else(|| "escrow_note is absent".to_string())?,
                "standing pool escrow note",
            )?,
            remainder_note: StandingPoolNote::from_body(
                object
                    .get("remainder_note")
                    .ok_or_else(|| "remainder_note is absent".to_string())?,
                "standing pool remainder note",
            )?,
            proof_job_id: hex32(object, "proof_job_id")?,
            quote_proof_digest: hex32(object, "quote_proof_digest")?,
            dvp_proof_digest: hex32(object, "dvp_proof_digest")?,
            remainder_range_proof_digest: hex32(object, "remainder_range_proof_digest")?,
            transition_statement: hex32(object, "transition_statement")?,
            authorization: StandingPoolMakerAuthorization::from_body(
                object
                    .get("authorization")
                    .ok_or_else(|| "allocation authorization is absent".to_string())?,
            )?,
        };
        binding.validate()?;
        Ok(binding)
    }
}

pub fn account_of(handle: &RistrettoPoint, rail: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"QOMM:DEFMI:ACCOUNT:v1");
    hasher.update((rail.len() as u64).to_be_bytes());
    hasher.update(rail);
    hasher.update(handle.compress().as_bytes());
    hasher.finalize().to_vec()
}

pub struct ThresholdDvpSides {
    pub securities_from: Vec<u8>,
    pub securities_to: Vec<u8>,
    pub cash_from: Vec<u8>,
    pub cash_to: Vec<u8>,
}

pub fn threshold_dvp_sides(instruction: &Instruction) -> ThresholdDvpSides {
    ThresholdDvpSides {
        securities_from: account_of(&instruction.payee_handle, SECURITIES_RAIL),
        securities_to: account_of(&instruction.payer_handle, SECURITIES_RAIL),
        cash_from: account_of(&instruction.payer_handle, CASH_RAIL),
        cash_to: account_of(&instruction.payee_handle, CASH_RAIL),
    }
}

fn hash_product_proof(hash: &mut Sha256, proof: &ProductProof) {
    hash.update(proof.t_factor.compress().as_bytes());
    hash.update(proof.t_product.compress().as_bytes());
    hash.update(proof.z_b.to_bytes());
    hash.update(proof.z_rb.to_bytes());
    hash.update(proof.z_s.to_bytes());
}

fn hash_threshold_range(hash: &mut Sha256, proof: &ThresholdRangeProof) {
    hash.update((proof.bits as u64).to_be_bytes());
    hash.update((proof.bit_commitments.len() as u64).to_be_bytes());
    for commitment in &proof.bit_commitments {
        hash.update(commitment.compress().as_bytes());
    }
    hash.update((proof.bit_proofs.len() as u64).to_be_bytes());
    for bit_proof in &proof.bit_proofs {
        hash_product_proof(hash, bit_proof);
    }
    hash.update(proof.linkage.t.compress().as_bytes());
    hash.update(proof.linkage.z_value.to_bytes());
    hash.update(proof.linkage.z_blinding.to_bytes());
}

pub fn threshold_range_proof_digest(proof: &ThresholdRangeProof) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(THRESHOLD_RANGE_DIGEST_DOMAIN);
    hash_threshold_range(&mut hash, proof);
    hash.finalize().into()
}

/// Canonical identifier of the complete public threshold-DvP package.  It is
/// available before the DeFMI reservation acknowledgement because the typed
/// execution context is deliberately not part of the payment instruction.
#[allow(clippy::too_many_arguments)]
pub fn threshold_dvp_package_digest(
    instruction: &Instruction,
    sides: &ThresholdDvpSides,
    cash_commitment: &RistrettoPoint,
    securities_remainder: &RistrettoPoint,
    cash_remainder: &RistrettoPoint,
    proofs: &DvpProofs,
) -> [u8; 32] {
    fn bytes(hash: &mut Sha256, value: &[u8]) {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    let mut hash = Sha256::new();
    hash.update(THRESHOLD_DVP_PACKAGE_DOMAIN);
    bytes(&mut hash, &qomm_zkpi::wire::encode(instruction));
    for handle in [
        &sides.securities_from,
        &sides.securities_to,
        &sides.cash_from,
        &sides.cash_to,
    ] {
        bytes(&mut hash, handle);
    }
    for point in [cash_commitment, securities_remainder, cash_remainder] {
        hash.update(point.compress().as_bytes());
    }
    hash_threshold_range(&mut hash, &proofs.securities_remainder);
    hash_threshold_range(&mut hash, &proofs.cash_remainder);
    hash_product_proof(&mut hash, &proofs.product);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;

    #[test]
    fn binding_round_trips_without_changing_signed_bytes() {
        let note = |tag: u8, value: u64, lock_id: [u8; 32]| {
            let mut output = StandingPoolNote {
                note_id: ZERO,
                asset_id: [7; 32],
                one_time: (G * Scalar::from(u64::from(tag) + 1)).compress().to_bytes(),
                value_commitment: (G * Scalar::from(value)).compress().to_bytes(),
                ephemeral: (G * Scalar::from(u64::from(tag) + 3)).compress().to_bytes(),
                masked_value: Scalar::from(u64::from(tag) + 4).to_bytes(),
                masked_blinding: Scalar::from(u64::from(tag) + 5).to_bytes(),
                lock_id,
            };
            output.note_id = digest_json(NOTE_OUTPUT_DOMAIN, &output.content_body()).unwrap();
            output
        };
        let mut authorization = StandingPoolMakerAuthorization {
            entity_commitment: [1; 32],
            asset_id: [7; 32],
            direction: 1,
            policy_digest: [2; 32],
            mandate_digest: [3; 32],
            typed_reserve_digest: [4; 32],
            reserve_nullifier: [5; 32],
            asset_link_proof_digest: [6; 32],
            policy_version: 1,
        };
        let pool_id = standing_note_pool_id(
            authorization.entity_commitment,
            authorization.policy_digest,
            authorization.mandate_digest,
            authorization.asset_id,
            authorization.direction,
        )
        .unwrap();
        let metadata = standing_pool_reservation_metadata(
            pool_id,
            [8; 32],
            0,
            [9; 32],
            [13; 32],
            [14; 32],
            [15; 32],
            [17; 32],
            authorization.entity_commitment,
            authorization.asset_id,
            authorization.direction,
            authorization.policy_digest,
            authorization.mandate_digest,
            authorization.policy_version,
        )
        .unwrap();
        authorization.typed_reserve_digest = metadata.typed_reserve_digest;
        authorization.reserve_nullifier = metadata.reserve_nullifier;
        authorization.asset_link_proof_digest = metadata.asset_link_proof_digest;
        let binding = StandingPoolAllocationBinding {
            pool_id,
            delegation_digest: [8; 32],
            committee_epoch: 1,
            expected_pool_sequence: 0,
            previous_pool_note_id: [9; 32],
            previous_amount_commitment: (G * Scalar::from(20_u64)).compress().to_bytes(),
            escrow_note: note(10, 7, [11; 32]),
            remainder_note: note(12, 13, pool_id),
            proof_job_id: [13; 32],
            quote_proof_digest: [14; 32],
            dvp_proof_digest: [15; 32],
            remainder_range_proof_digest: [16; 32],
            transition_statement: [17; 32],
            authorization,
        };
        let body = binding.body().unwrap();
        let decoded = StandingPoolAllocationBinding::from_body(&body).unwrap();
        assert_eq!(decoded, binding);
        assert_eq!(
            decoded.signing_message().unwrap(),
            binding.signing_message().unwrap()
        );
    }
}
