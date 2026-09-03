//! Private pre-trade authority exchange between asset owners, DeFMI, and the
//! QOMM proof committee.
//!
//! The authority bundle is created before an RFQ is evaluated. It carries the
//! already-signed Maker policy mandates and Taker execution mandates together
//! with their anonymous legal-entity proofs. The optional openings exist only
//! for the executable acceptance fixture, where this file stands in for owner
//! wallets; production owners submit reserve proofs directly to DeFMI.
//!
//! DeFMI answers with a signed acknowledgement containing only commitments,
//! reservation identifiers, and reservation receipt digests. Proof nodes pin
//! the DeFMI receipt public key and must verify this acknowledgement before
//! authorising the final typed zkPI. Neither file contains a quote or an MPC
//! policy/inventory share.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use qomm_proofs::kyb::{KybPresentation, SignedCohortRegistry};
use qomm_zk::or_dleq::Proof as MembershipProof;
use qomm_zkpi::frost;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::mandate::{Direction, MakerPolicyMandate, TakerExecutionMandate, ZERO};
use crate::order::{verify_admission_lane, NodeAdmissionAttestation, COMMITTEE_NODES};

const AUTHORITY_VERSION: u8 = 4;
const ACK_VERSION: u8 = 1;
const ACK_DOMAIN: &[u8] = b"QOMM:DEFMI:PRETRADE-ACK:v1";
const MAX_AUTHORITIES: usize = 4096;
const MAX_FILE: u64 = 32 << 20;

#[derive(Clone, Debug)]
pub struct AcceptanceOpening {
    pub amount: u64,
    pub blinding: Scalar,
}

#[derive(Clone, Debug)]
pub struct MakerPretradeAuthority {
    pub maker_index: u16,
    pub mandate: MakerPolicyMandate,
    pub identity_context: Vec<u8>,
    pub presentation: KybPresentation,
    pub acceptance_opening: AcceptanceOpening,
}

#[derive(Clone, Debug)]
pub struct TakerPretradeAuthority {
    pub client_index: u16,
    pub mandate: TakerExecutionMandate,
    pub identity_context: Vec<u8>,
    pub presentation: KybPresentation,
    pub acceptance_opening: AcceptanceOpening,
}

#[derive(Clone, Debug)]
pub struct PretradeAuthorityBundle {
    pub created_at: u64,
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub traded_asset_id: [u8; 32],
    pub cash_asset_id: [u8; 32],
    pub identity_scope: Vec<u8>,
    pub required_cohort: String,
    /// Public audit metadata for the external identity verification boundary.
    /// The digest commits to provider-signed assertions; neither raw provider
    /// subjects nor legal-entity names enter this bundle.
    pub identity_provider: String,
    pub identity_evidence_digest: [u8; 32],
    pub registry: SignedCohortRegistry,
    /// Present once the fixed-population slot is closed and before any MPC
    /// lane is evaluated. DeFMI consumes these lanes in their certified order.
    pub admission: Option<PretradeAdmission>,
    /// Verifier trust anchor fixed before quote evaluation. DeFMI registers
    /// this package and eligible-Maker registry on Avalanche under governance
    /// quorum, so a settlement cannot bring its own FROST key or omit Makers.
    pub settlement_verifier: PretradeSettlementVerifier,
    pub makers: Vec<MakerPretradeAuthority>,
    pub takers: Vec<TakerPretradeAuthority>,
}

#[derive(Clone, Debug)]
pub struct PretradeSettlementVerifier {
    pub epoch: u64,
    pub quote_registry_digest: [u8; 32],
    pub quote_eligibility_bits: u16,
    pub quote_span_bits: u16,
    pub amount_bits: u16,
    pub price_bits: u16,
    pub max_horizon: u64,
    pub frost_public: frost::keys::PublicKeyPackage,
    pub valid_from: u64,
    pub valid_until: u64,
}

#[derive(Clone, Debug)]
pub struct PretradeAdmission {
    pub epoch: u64,
    pub node_keys: Vec<[u8; 32]>,
    pub lanes: Vec<Vec<NodeAdmissionAttestation>>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ReservationParty {
    Maker = 1,
    Taker = 2,
}

impl TryFrom<u8> for ReservationParty {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Maker),
            2 => Ok(Self::Taker),
            _ => Err("pre-trade reservation party is invalid".into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PretradeReservationBinding {
    pub party: ReservationParty,
    pub owner_index: u16,
    pub direction: Direction,
    pub owner_handle: [u8; 32],
    /// Authoritative confidential-cap line consumed by this reservation.
    pub facility_id: [u8; 32],
    pub reserve_id: [u8; 32],
    pub mandate_digest: [u8; 32],
    /// Zero for a Taker; a Maker must name the registered policy digest.
    pub policy_digest: [u8; 32],
    pub amount_commitment: [u8; 32],
    pub reserve_receipt_digest: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct PretradeAcknowledgement {
    pub authority_digest: [u8; 32],
    pub defmi_id: [u8; 32],
    pub after_state_root: [u8; 32],
    pub bindings: Vec<PretradeReservationBinding>,
    pub signer_public: [u8; 32],
    pub signature: Signature,
}

fn nonzero(value: &[u8; 32], name: &str) -> Result<(), String> {
    if *value == ZERO {
        Err(format!("{name} cannot be zero"))
    } else {
        Ok(())
    }
}

fn parse32(value: &str, name: &str) -> Result<[u8; 32], String> {
    hex::decode(value)
        .map_err(|_| format!("{name} is not hexadecimal"))?
        .try_into()
        .map_err(|_| format!("{name} is not 32 bytes"))
}

fn parse64(value: &str, name: &str) -> Result<[u8; 64], String> {
    hex::decode(value)
        .map_err(|_| format!("{name} is not hexadecimal"))?
        .try_into()
        .map_err(|_| format!("{name} is not 64 bytes"))
}

fn point(value: &str, name: &str) -> Result<RistrettoPoint, String> {
    CompressedRistretto(parse32(value, name)?)
        .decompress()
        .ok_or_else(|| format!("{name} is not a canonical Ristretto point"))
}

fn scalar(value: &str, name: &str) -> Result<Scalar, String> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(parse32(value, name)?))
        .ok_or_else(|| format!("{name} is not a canonical scalar"))
}

fn direction(value: u8) -> Result<Direction, String> {
    match value {
        1 => Ok(Direction::TakerBuys),
        2 => Ok(Direction::TakerSells),
        _ => Err("pre-trade direction is invalid".into()),
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireRegistry {
    cohort: String,
    registry_epoch: u64,
    expires_at: u64,
    points: Vec<String>,
    issuer: String,
    registry_id: String,
    signature: String,
}

impl WireRegistry {
    fn from_value(value: &SignedCohortRegistry) -> Self {
        Self {
            cohort: value.cohort.clone(),
            registry_epoch: value.registry_epoch,
            expires_at: value.expires_at,
            points: value
                .points
                .iter()
                .map(|point| hex::encode(point.compress().to_bytes()))
                .collect(),
            issuer: hex::encode(value.issuer.to_bytes()),
            registry_id: hex::encode(value.registry_id),
            signature: hex::encode(value.signature.to_bytes()),
        }
    }

    fn into_value(self) -> Result<SignedCohortRegistry, String> {
        Ok(SignedCohortRegistry {
            cohort: self.cohort,
            registry_epoch: self.registry_epoch,
            expires_at: self.expires_at,
            points: self
                .points
                .iter()
                .enumerate()
                .map(|(index, value)| point(value, &format!("registry point {index}")))
                .collect::<Result<Vec<_>, _>>()?,
            issuer: VerifyingKey::from_bytes(&parse32(&self.issuer, "registry issuer")?)
                .map_err(|_| "registry issuer is malformed".to_string())?,
            registry_id: parse32(&self.registry_id, "registry id")?,
            signature: Signature::from_bytes(&parse64(&self.signature, "registry signature")?),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WirePresentation {
    cohort: String,
    registry_id: String,
    scope: String,
    context_hash: String,
    nullifier: String,
    challenges: Vec<String>,
    responses: Vec<String>,
}

impl WirePresentation {
    fn from_value(value: &KybPresentation) -> Self {
        Self {
            cohort: value.cohort.clone(),
            registry_id: hex::encode(value.registry_id),
            scope: hex::encode(&value.scope),
            context_hash: hex::encode(value.context_hash),
            nullifier: hex::encode(value.proof.nullifier.compress().to_bytes()),
            challenges: value
                .proof
                .challenges
                .iter()
                .map(|value| hex::encode(value.to_bytes()))
                .collect(),
            responses: value
                .proof
                .responses
                .iter()
                .map(|value| hex::encode(value.to_bytes()))
                .collect(),
        }
    }

    fn into_value(self) -> Result<KybPresentation, String> {
        let challenges = self
            .challenges
            .iter()
            .enumerate()
            .map(|(index, value)| scalar(value, &format!("membership challenge {index}")))
            .collect::<Result<Vec<_>, _>>()?;
        let responses = self
            .responses
            .iter()
            .enumerate()
            .map(|(index, value)| scalar(value, &format!("membership response {index}")))
            .collect::<Result<Vec<_>, _>>()?;
        if challenges.is_empty() || challenges.len() != responses.len() {
            return Err("membership proof response population is invalid".into());
        }
        Ok(KybPresentation {
            cohort: self.cohort,
            registry_id: parse32(&self.registry_id, "presentation registry id")?,
            scope: hex::decode(&self.scope)
                .map_err(|_| "presentation scope is malformed".to_string())?,
            context_hash: parse32(&self.context_hash, "presentation context")?,
            proof: MembershipProof {
                nullifier: point(&self.nullifier, "presentation nullifier")?,
                challenges,
                responses,
            },
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireMakerMandate {
    venue_id: String,
    defmi_id: String,
    policy_digest: String,
    policy_version: u64,
    asset_id: String,
    direction: u8,
    reserve_id: String,
    maximum_amount_commitment: String,
    maker_handle: String,
    entity_commitment: String,
    kyb_presentation_digest: String,
    valid_from: u64,
    valid_until: u64,
    auto_execute: bool,
    maker_public: String,
    signature: String,
}

impl WireMakerMandate {
    fn from_value(value: &MakerPolicyMandate) -> Self {
        Self {
            venue_id: hex::encode(value.venue_id),
            defmi_id: hex::encode(value.defmi_id),
            policy_digest: hex::encode(value.policy_digest),
            policy_version: value.policy_version,
            asset_id: hex::encode(value.asset_id),
            direction: value.direction as u8,
            reserve_id: hex::encode(value.reserve_id),
            maximum_amount_commitment: hex::encode(value.maximum_amount_commitment),
            maker_handle: hex::encode(value.maker_handle),
            entity_commitment: hex::encode(value.entity_commitment),
            kyb_presentation_digest: hex::encode(value.kyb_presentation_digest),
            valid_from: value.valid_from,
            valid_until: value.valid_until,
            auto_execute: value.auto_execute,
            maker_public: hex::encode(value.maker_public),
            signature: hex::encode(value.signature.to_bytes()),
        }
    }

    fn into_value(self) -> Result<MakerPolicyMandate, String> {
        let value = MakerPolicyMandate {
            venue_id: parse32(&self.venue_id, "Maker venue")?,
            defmi_id: parse32(&self.defmi_id, "Maker DeFMI")?,
            policy_digest: parse32(&self.policy_digest, "Maker policy")?,
            policy_version: self.policy_version,
            asset_id: parse32(&self.asset_id, "Maker asset")?,
            direction: direction(self.direction)?,
            reserve_id: parse32(&self.reserve_id, "Maker reserve")?,
            maximum_amount_commitment: parse32(
                &self.maximum_amount_commitment,
                "Maker maximum amount",
            )?,
            maker_handle: parse32(&self.maker_handle, "Maker handle")?,
            entity_commitment: parse32(&self.entity_commitment, "Maker entity")?,
            kyb_presentation_digest: parse32(
                &self.kyb_presentation_digest,
                "Maker KYB presentation",
            )?,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            auto_execute: self.auto_execute,
            maker_public: parse32(&self.maker_public, "Maker public key")?,
            signature: Signature::from_bytes(&parse64(&self.signature, "Maker signature")?),
        };
        value.unsigned()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireTakerMandate {
    venue_id: String,
    defmi_id: String,
    rfq_nullifier: String,
    asset_id: String,
    reserve_asset_id: String,
    direction: u8,
    quantity_commitment: String,
    limit_price_commitment: String,
    maximum_fee_commitment: String,
    maximum_amount_commitment: String,
    reserve_id: String,
    taker_handle: String,
    entity_commitment: String,
    kyb_presentation_digest: String,
    admission_ticket_id: String,
    admission_slot: u64,
    fill_mask_commitment: String,
    deadline: u64,
    allow_partial: bool,
    auto_settle: bool,
    taker_public: String,
    signature: String,
}

impl WireTakerMandate {
    fn from_value(value: &TakerExecutionMandate) -> Self {
        Self {
            venue_id: hex::encode(value.venue_id),
            defmi_id: hex::encode(value.defmi_id),
            rfq_nullifier: hex::encode(value.rfq_nullifier),
            asset_id: hex::encode(value.asset_id),
            reserve_asset_id: hex::encode(value.reserve_asset_id),
            direction: value.direction as u8,
            quantity_commitment: hex::encode(value.quantity_commitment),
            limit_price_commitment: hex::encode(value.limit_price_commitment),
            maximum_fee_commitment: hex::encode(value.maximum_fee_commitment),
            maximum_amount_commitment: hex::encode(value.maximum_amount_commitment),
            reserve_id: hex::encode(value.reserve_id),
            taker_handle: hex::encode(value.taker_handle),
            entity_commitment: hex::encode(value.entity_commitment),
            kyb_presentation_digest: hex::encode(value.kyb_presentation_digest),
            admission_ticket_id: hex::encode(value.admission_ticket_id),
            admission_slot: value.admission_slot,
            fill_mask_commitment: hex::encode(value.fill_mask_commitment),
            deadline: value.deadline,
            allow_partial: value.allow_partial,
            auto_settle: value.auto_settle,
            taker_public: hex::encode(value.taker_public),
            signature: hex::encode(value.signature.to_bytes()),
        }
    }

    fn into_value(self) -> Result<TakerExecutionMandate, String> {
        let value = TakerExecutionMandate {
            venue_id: parse32(&self.venue_id, "Taker venue")?,
            defmi_id: parse32(&self.defmi_id, "Taker DeFMI")?,
            rfq_nullifier: parse32(&self.rfq_nullifier, "Taker RFQ")?,
            asset_id: parse32(&self.asset_id, "Taker asset")?,
            reserve_asset_id: parse32(&self.reserve_asset_id, "Taker reserve asset")?,
            direction: direction(self.direction)?,
            quantity_commitment: parse32(&self.quantity_commitment, "Taker quantity")?,
            limit_price_commitment: parse32(&self.limit_price_commitment, "Taker limit")?,
            maximum_fee_commitment: parse32(&self.maximum_fee_commitment, "Taker fee")?,
            maximum_amount_commitment: parse32(
                &self.maximum_amount_commitment,
                "Taker maximum amount",
            )?,
            reserve_id: parse32(&self.reserve_id, "Taker reserve")?,
            taker_handle: parse32(&self.taker_handle, "Taker handle")?,
            entity_commitment: parse32(&self.entity_commitment, "Taker entity")?,
            kyb_presentation_digest: parse32(
                &self.kyb_presentation_digest,
                "Taker KYB presentation",
            )?,
            admission_ticket_id: parse32(&self.admission_ticket_id, "Taker ticket")?,
            admission_slot: self.admission_slot,
            fill_mask_commitment: parse32(
                &self.fill_mask_commitment,
                "Taker fill mask commitment",
            )?,
            deadline: self.deadline,
            allow_partial: self.allow_partial,
            auto_settle: self.auto_settle,
            taker_public: parse32(&self.taker_public, "Taker public key")?,
            signature: Signature::from_bytes(&parse64(&self.signature, "Taker signature")?),
        };
        value.unsigned()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireOpening {
    amount: u64,
    blinding: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireMakerAuthority {
    maker_index: u16,
    mandate: WireMakerMandate,
    identity_context: String,
    presentation: WirePresentation,
    acceptance_opening: WireOpening,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireTakerAuthority {
    client_index: u16,
    mandate: WireTakerMandate,
    identity_context: String,
    presentation: WirePresentation,
    acceptance_opening: WireOpening,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireAuthorityBundle {
    version: u8,
    private_pretrade_authority: bool,
    acceptance_only_openings: bool,
    created_at: u64,
    venue_id: String,
    defmi_id: String,
    traded_asset_id: String,
    cash_asset_id: String,
    identity_scope: String,
    required_cohort: String,
    identity_provider: String,
    identity_evidence_digest: String,
    registry: WireRegistry,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admission: Option<WireAdmission>,
    settlement_verifier: WireSettlementVerifier,
    makers: Vec<WireMakerAuthority>,
    takers: Vec<WireTakerAuthority>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireSettlementVerifier {
    epoch: u64,
    quote_registry_digest: String,
    quote_eligibility_bits: u16,
    quote_span_bits: u16,
    amount_bits: u16,
    price_bits: u16,
    max_horizon: u64,
    frost_public: String,
    valid_from: u64,
    valid_until: u64,
}

fn settlement_verifier_wire(
    value: &PretradeSettlementVerifier,
) -> Result<WireSettlementVerifier, String> {
    if value.epoch == 0
        || value.quote_registry_digest == ZERO
        || value.quote_eligibility_bits == 0
        || value.quote_eligibility_bits > 62
        || value.quote_span_bits == 0
        || value.quote_span_bits > 64
        || value.amount_bits == 0
        || value.amount_bits > 64
        || value.price_bits == 0
        || value.price_bits > 64
        || value.max_horizon == 0
        || value.valid_from == 0
        || value.valid_until < value.valid_from
    {
        return Err("pre-trade settlement verifier is outside its bounds".into());
    }
    let frost_public = value
        .frost_public
        .serialize()
        .map_err(|_| "pre-trade FROST public package serialization failed".to_string())?;
    if frost_public.is_empty() || frost_public.len() > 64 * 1024 {
        return Err("pre-trade FROST public package is outside its bound".into());
    }
    Ok(WireSettlementVerifier {
        epoch: value.epoch,
        quote_registry_digest: hex::encode(value.quote_registry_digest),
        quote_eligibility_bits: value.quote_eligibility_bits,
        quote_span_bits: value.quote_span_bits,
        amount_bits: value.amount_bits,
        price_bits: value.price_bits,
        max_horizon: value.max_horizon,
        frost_public: hex::encode(frost_public),
        valid_from: value.valid_from,
        valid_until: value.valid_until,
    })
}

fn settlement_verifier_from_wire(
    value: WireSettlementVerifier,
) -> Result<PretradeSettlementVerifier, String> {
    let frost_public_raw = hex::decode(value.frost_public)
        .map_err(|_| "pre-trade FROST public package is not hexadecimal".to_string())?;
    let result = PretradeSettlementVerifier {
        epoch: value.epoch,
        quote_registry_digest: parse32(&value.quote_registry_digest, "quote registry digest")?,
        quote_eligibility_bits: value.quote_eligibility_bits,
        quote_span_bits: value.quote_span_bits,
        amount_bits: value.amount_bits,
        price_bits: value.price_bits,
        max_horizon: value.max_horizon,
        frost_public: frost::keys::PublicKeyPackage::deserialize(&frost_public_raw)
            .map_err(|_| "pre-trade FROST public package is invalid".to_string())?,
        valid_from: value.valid_from,
        valid_until: value.valid_until,
    };
    let canonical = settlement_verifier_wire(&result)?;
    if canonical.frost_public != hex::encode(frost_public_raw) {
        return Err("pre-trade FROST public package is not canonical".into());
    }
    Ok(result)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireAdmission {
    epoch: u64,
    node_keys: Vec<String>,
    lanes: Vec<Vec<WireAdmissionAttestation>>,
}

fn admission_wire(value: &PretradeAdmission) -> Result<WireAdmission, String> {
    if value.epoch == 0
        || value.node_keys.len() != COMMITTEE_NODES
        || value.lanes.is_empty()
        || value.lanes.len() > MAX_AUTHORITIES
    {
        return Err("pre-trade admission population is invalid".into());
    }
    let keys = value
        .node_keys
        .iter()
        .map(|raw| {
            VerifyingKey::from_bytes(raw)
                .map_err(|_| "pre-trade admission key is malformed".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut certified = value
        .lanes
        .iter()
        .map(|lane| verify_admission_lane(lane, &keys))
        .collect::<Result<Vec<_>, _>>()?;
    certified.sort_by_key(|lane| lane.sequence);
    if certified
        .iter()
        .enumerate()
        .any(|(index, lane)| lane.sequence != index as u64 + 1)
    {
        return Err("pre-trade admission lanes are incomplete or reordered".into());
    }
    Ok(WireAdmission {
        epoch: value.epoch,
        node_keys: value.node_keys.iter().map(hex::encode).collect(),
        lanes: value
            .lanes
            .iter()
            .map(|lane| {
                lane.iter()
                    .map(|entry| {
                        entry.unsigned()?;
                        Ok(WireAdmissionAttestation {
                            node: entry.node,
                            slot: entry.slot,
                            sequence: entry.sequence,
                            principal_digest: hex::encode(entry.principal_digest),
                            ticket_id: hex::encode(entry.ticket_id),
                            claim_digest: hex::encode(entry.claim_digest),
                            batch_digest: hex::encode(entry.batch_digest),
                            order_digest: hex::encode(entry.order_digest),
                            signature: hex::encode(entry.signature.to_bytes()),
                        })
                    })
                    .collect()
            })
            .collect::<Result<Vec<Vec<_>>, String>>()?,
    })
}

fn admission_from_wire(value: WireAdmission) -> Result<PretradeAdmission, String> {
    let result = PretradeAdmission {
        epoch: value.epoch,
        node_keys: value
            .node_keys
            .iter()
            .map(|value| parse32(value, "admission node key"))
            .collect::<Result<Vec<_>, _>>()?,
        lanes: value
            .lanes
            .into_iter()
            .map(|lane| {
                lane.into_iter()
                    .map(|entry| {
                        let attestation = NodeAdmissionAttestation {
                            node: entry.node,
                            slot: entry.slot,
                            sequence: entry.sequence,
                            principal_digest: parse32(
                                &entry.principal_digest,
                                "admission principal",
                            )?,
                            ticket_id: parse32(&entry.ticket_id, "admission ticket")?,
                            claim_digest: parse32(&entry.claim_digest, "admission claim")?,
                            batch_digest: parse32(&entry.batch_digest, "admission batch")?,
                            order_digest: parse32(&entry.order_digest, "admission order")?,
                            signature: Signature::from_bytes(&parse64(
                                &entry.signature,
                                "admission signature",
                            )?),
                        };
                        attestation.unsigned()?;
                        Ok(attestation)
                    })
                    .collect()
            })
            .collect::<Result<Vec<Vec<_>>, String>>()?,
    };
    admission_wire(&result)?;
    Ok(result)
}

fn authority_wire(value: &PretradeAuthorityBundle) -> Result<WireAuthorityBundle, String> {
    if value.created_at == 0
        || value.identity_scope.is_empty()
        || value.required_cohort.is_empty()
        || value.identity_provider.is_empty()
        || value.identity_evidence_digest == [0; 32]
        || value.makers.is_empty()
        || value.takers.is_empty()
        || value.makers.len() + value.takers.len() > MAX_AUTHORITIES
    {
        return Err("pre-trade authority population or metadata is invalid".into());
    }
    for (name, id) in [
        ("venue", &value.venue_id),
        ("DeFMI", &value.defmi_id),
        ("traded asset", &value.traded_asset_id),
        ("cash asset", &value.cash_asset_id),
    ] {
        nonzero(id, name)?;
    }
    Ok(WireAuthorityBundle {
        version: AUTHORITY_VERSION,
        private_pretrade_authority: true,
        acceptance_only_openings: true,
        created_at: value.created_at,
        venue_id: hex::encode(value.venue_id),
        defmi_id: hex::encode(value.defmi_id),
        traded_asset_id: hex::encode(value.traded_asset_id),
        cash_asset_id: hex::encode(value.cash_asset_id),
        identity_scope: hex::encode(&value.identity_scope),
        required_cohort: value.required_cohort.clone(),
        identity_provider: value.identity_provider.clone(),
        identity_evidence_digest: hex::encode(value.identity_evidence_digest),
        registry: WireRegistry::from_value(&value.registry),
        admission: value.admission.as_ref().map(admission_wire).transpose()?,
        settlement_verifier: settlement_verifier_wire(&value.settlement_verifier)?,
        makers: value
            .makers
            .iter()
            .map(|authority| WireMakerAuthority {
                maker_index: authority.maker_index,
                mandate: WireMakerMandate::from_value(&authority.mandate),
                identity_context: hex::encode(&authority.identity_context),
                presentation: WirePresentation::from_value(&authority.presentation),
                acceptance_opening: WireOpening {
                    amount: authority.acceptance_opening.amount,
                    blinding: hex::encode(authority.acceptance_opening.blinding.to_bytes()),
                },
            })
            .collect(),
        takers: value
            .takers
            .iter()
            .map(|authority| WireTakerAuthority {
                client_index: authority.client_index,
                mandate: WireTakerMandate::from_value(&authority.mandate),
                identity_context: hex::encode(&authority.identity_context),
                presentation: WirePresentation::from_value(&authority.presentation),
                acceptance_opening: WireOpening {
                    amount: authority.acceptance_opening.amount,
                    blinding: hex::encode(authority.acceptance_opening.blinding.to_bytes()),
                },
            })
            .collect(),
    })
}

fn authority_from_wire(value: WireAuthorityBundle) -> Result<PretradeAuthorityBundle, String> {
    if value.version != AUTHORITY_VERSION
        || !value.private_pretrade_authority
        || !value.acceptance_only_openings
        || value.makers.is_empty()
        || value.takers.is_empty()
        || value.makers.len() + value.takers.len() > MAX_AUTHORITIES
    {
        return Err("pre-trade authority header is invalid".into());
    }
    let mut maker_keys = BTreeSet::new();
    let makers = value
        .makers
        .into_iter()
        .map(|wire| {
            let mandate = wire.mandate.into_value()?;
            if !maker_keys.insert((wire.maker_index, mandate.direction as u8)) {
                return Err("pre-trade authority repeats a Maker direction".into());
            }
            Ok(MakerPretradeAuthority {
                maker_index: wire.maker_index,
                mandate,
                identity_context: hex::decode(wire.identity_context)
                    .map_err(|_| "Maker identity context is malformed".to_string())?,
                presentation: wire.presentation.into_value()?,
                acceptance_opening: AcceptanceOpening {
                    amount: wire.acceptance_opening.amount,
                    blinding: scalar(
                        &wire.acceptance_opening.blinding,
                        "Maker reservation blinding",
                    )?,
                },
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut taker_keys = BTreeSet::new();
    let takers = value
        .takers
        .into_iter()
        .map(|wire| {
            if !taker_keys.insert(wire.client_index) {
                return Err("pre-trade authority repeats a Taker client".into());
            }
            Ok(TakerPretradeAuthority {
                client_index: wire.client_index,
                mandate: wire.mandate.into_value()?,
                identity_context: hex::decode(wire.identity_context)
                    .map_err(|_| "Taker identity context is malformed".to_string())?,
                presentation: wire.presentation.into_value()?,
                acceptance_opening: AcceptanceOpening {
                    amount: wire.acceptance_opening.amount,
                    blinding: scalar(
                        &wire.acceptance_opening.blinding,
                        "Taker reservation blinding",
                    )?,
                },
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let result = PretradeAuthorityBundle {
        created_at: value.created_at,
        venue_id: parse32(&value.venue_id, "authority venue")?,
        defmi_id: parse32(&value.defmi_id, "authority DeFMI")?,
        traded_asset_id: parse32(&value.traded_asset_id, "authority traded asset")?,
        cash_asset_id: parse32(&value.cash_asset_id, "authority cash asset")?,
        identity_scope: hex::decode(&value.identity_scope)
            .map_err(|_| "authority identity scope is malformed".to_string())?,
        required_cohort: value.required_cohort,
        identity_provider: value.identity_provider,
        identity_evidence_digest: parse32(
            &value.identity_evidence_digest,
            "external identity evidence",
        )?,
        registry: value.registry.into_value()?,
        admission: value.admission.map(admission_from_wire).transpose()?,
        settlement_verifier: settlement_verifier_from_wire(value.settlement_verifier)?,
        makers,
        takers,
    };
    authority_wire(&result)?;
    Ok(result)
}

impl PretradeAuthorityBundle {
    pub fn digest(&self) -> Result<[u8; 32], String> {
        Ok(Sha256::digest(
            serde_json::to_vec(&authority_wire(self)?).map_err(|error| error.to_string())?,
        )
        .into())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireBinding {
    party: u8,
    owner_index: u16,
    direction: u8,
    owner_handle: String,
    facility_id: String,
    reserve_id: String,
    mandate_digest: String,
    policy_digest: String,
    amount_commitment: String,
    reserve_receipt_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireAck {
    version: u8,
    private_pretrade_ack: bool,
    authority_digest: String,
    defmi_id: String,
    after_state_root: String,
    bindings: Vec<WireBinding>,
    signer_public: String,
    signature: String,
}

impl PretradeAcknowledgement {
    fn sorted_bindings(&self) -> Result<Vec<&PretradeReservationBinding>, String> {
        if self.bindings.is_empty() || self.bindings.len() > MAX_AUTHORITIES {
            return Err("pre-trade acknowledgement binding population is invalid".into());
        }
        let mut values = self.bindings.iter().collect::<Vec<_>>();
        values.sort_by_key(|value| (value.party, value.owner_index, value.direction as u8));
        if values.windows(2).any(|pair| {
            (pair[0].party, pair[0].owner_index, pair[0].direction as u8)
                == (pair[1].party, pair[1].owner_index, pair[1].direction as u8)
        }) {
            return Err("pre-trade acknowledgement repeats a reservation authority".into());
        }
        for value in &values {
            nonzero(&value.owner_handle, "reservation owner handle")?;
            CompressedRistretto(value.owner_handle)
                .decompress()
                .ok_or_else(|| "reservation owner handle is not canonical".to_string())?;
            for (name, id) in [
                ("facility id", &value.facility_id),
                ("reserve id", &value.reserve_id),
                ("mandate digest", &value.mandate_digest),
                ("amount commitment", &value.amount_commitment),
                ("reserve receipt", &value.reserve_receipt_digest),
            ] {
                nonzero(id, name)?;
            }
            if (value.party == ReservationParty::Maker) != (value.policy_digest != ZERO) {
                return Err("Maker/Taker policy binding is inconsistent".into());
            }
        }
        Ok(values)
    }

    pub fn unsigned(&self) -> Result<Vec<u8>, String> {
        nonzero(&self.authority_digest, "authority digest")?;
        nonzero(&self.defmi_id, "DeFMI id")?;
        nonzero(&self.after_state_root, "DeFMI state root")?;
        VerifyingKey::from_bytes(&self.signer_public)
            .map_err(|_| "pre-trade acknowledgement key is malformed".to_string())?;
        let bindings = self.sorted_bindings()?;
        let mut body = ACK_DOMAIN.to_vec();
        body.extend_from_slice(&self.authority_digest);
        body.extend_from_slice(&self.defmi_id);
        body.extend_from_slice(&self.after_state_root);
        body.extend_from_slice(&(bindings.len() as u32).to_be_bytes());
        for value in bindings {
            body.push(value.party as u8);
            body.extend_from_slice(&value.owner_index.to_be_bytes());
            body.push(value.direction as u8);
            for id in [
                &value.owner_handle,
                &value.facility_id,
                &value.reserve_id,
                &value.mandate_digest,
                &value.policy_digest,
                &value.amount_commitment,
                &value.reserve_receipt_digest,
            ] {
                body.extend_from_slice(id);
            }
        }
        body.extend_from_slice(&self.signer_public);
        Ok(body)
    }

    pub fn sign(mut self, key: &SigningKey) -> Result<Self, String> {
        if self.signer_public != key.verifying_key().to_bytes() {
            return Err("pre-trade acknowledgement signing key differs".into());
        }
        self.signature = key.sign(&self.unsigned()?);
        Ok(self)
    }

    pub fn verify(&self, trusted: &VerifyingKey) -> Result<(), String> {
        if self.signer_public != trusted.to_bytes() {
            return Err("pre-trade acknowledgement is not from the pinned DeFMI".into());
        }
        trusted
            .verify(&self.unsigned()?, &self.signature)
            .map_err(|_| "pre-trade acknowledgement signature is invalid".to_string())
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        Ok(Sha256::new()
            .chain_update(self.unsigned()?)
            .chain_update(self.signature.to_bytes())
            .finalize()
            .into())
    }

    pub fn binding_for(
        &self,
        party: ReservationParty,
        owner_handle: &[u8; 32],
        direction: Direction,
    ) -> Result<&PretradeReservationBinding, String> {
        self.bindings
            .iter()
            .find(|value| {
                value.party == party
                    && value.owner_handle == *owner_handle
                    && value.direction == direction
            })
            .ok_or_else(|| "pre-trade acknowledgement lacks the selected reservation".into())
    }
}

fn ack_wire(value: &PretradeAcknowledgement) -> Result<WireAck, String> {
    value.unsigned()?;
    Ok(WireAck {
        version: ACK_VERSION,
        private_pretrade_ack: true,
        authority_digest: hex::encode(value.authority_digest),
        defmi_id: hex::encode(value.defmi_id),
        after_state_root: hex::encode(value.after_state_root),
        bindings: value
            .sorted_bindings()?
            .into_iter()
            .map(|binding| WireBinding {
                party: binding.party as u8,
                owner_index: binding.owner_index,
                direction: binding.direction as u8,
                owner_handle: hex::encode(binding.owner_handle),
                facility_id: hex::encode(binding.facility_id),
                reserve_id: hex::encode(binding.reserve_id),
                mandate_digest: hex::encode(binding.mandate_digest),
                policy_digest: hex::encode(binding.policy_digest),
                amount_commitment: hex::encode(binding.amount_commitment),
                reserve_receipt_digest: hex::encode(binding.reserve_receipt_digest),
            })
            .collect(),
        signer_public: hex::encode(value.signer_public),
        signature: hex::encode(value.signature.to_bytes()),
    })
}

fn ack_from_wire(value: WireAck) -> Result<PretradeAcknowledgement, String> {
    if value.version != ACK_VERSION
        || !value.private_pretrade_ack
        || value.bindings.is_empty()
        || value.bindings.len() > MAX_AUTHORITIES
    {
        return Err("pre-trade acknowledgement header is invalid".into());
    }
    let acknowledgement = PretradeAcknowledgement {
        authority_digest: parse32(&value.authority_digest, "acknowledged authority")?,
        defmi_id: parse32(&value.defmi_id, "acknowledged DeFMI")?,
        after_state_root: parse32(&value.after_state_root, "acknowledged state root")?,
        bindings: value
            .bindings
            .into_iter()
            .map(|wire| {
                Ok(PretradeReservationBinding {
                    party: ReservationParty::try_from(wire.party)?,
                    owner_index: wire.owner_index,
                    direction: direction(wire.direction)?,
                    owner_handle: parse32(&wire.owner_handle, "reservation owner")?,
                    facility_id: parse32(&wire.facility_id, "reservation facility")?,
                    reserve_id: parse32(&wire.reserve_id, "reservation id")?,
                    mandate_digest: parse32(&wire.mandate_digest, "reservation mandate")?,
                    policy_digest: parse32(&wire.policy_digest, "reservation policy")?,
                    amount_commitment: parse32(&wire.amount_commitment, "reservation amount")?,
                    reserve_receipt_digest: parse32(
                        &wire.reserve_receipt_digest,
                        "reservation receipt",
                    )?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
        signer_public: parse32(&value.signer_public, "acknowledgement signer")?,
        signature: Signature::from_bytes(&parse64(&value.signature, "acknowledgement signature")?),
    };
    acknowledgement.unsigned()?;
    Ok(acknowledgement)
}

fn private_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = path.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > MAX_FILE
    {
        return Err("pre-trade exchange must be a bounded private regular file".into());
    }
    fs::read(path).map_err(|error| error.to_string())
}

fn write_private(path: &Path, bytes: &[u8], prefix: &str) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temporary: PathBuf = parent.join(format!(".{prefix}-{}.tmp", rand::random::<u64>()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        file.write_all(bytes)
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

pub fn write_authority_private(
    path: impl AsRef<Path>,
    value: &PretradeAuthorityBundle,
) -> Result<(), String> {
    let bytes =
        serde_json::to_vec_pretty(&authority_wire(value)?).map_err(|error| error.to_string())?;
    write_private(path.as_ref(), &bytes, "qomm-pretrade-authority")
}

pub fn read_authority_private(path: impl AsRef<Path>) -> Result<PretradeAuthorityBundle, String> {
    let value: WireAuthorityBundle = serde_json::from_slice(&private_file(path.as_ref())?)
        .map_err(|error| format!("pre-trade authority JSON is invalid: {error}"))?;
    authority_from_wire(value)
}

pub fn encode_ack(value: &PretradeAcknowledgement) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&ack_wire(value)?).map_err(|error| error.to_string())
}

pub fn decode_ack(bytes: &[u8]) -> Result<PretradeAcknowledgement, String> {
    let value: WireAck = serde_json::from_slice(bytes)
        .map_err(|error| format!("pre-trade acknowledgement JSON is invalid: {error}"))?;
    ack_from_wire(value)
}

pub fn write_ack_private(
    path: impl AsRef<Path>,
    value: &PretradeAcknowledgement,
) -> Result<(), String> {
    write_private(
        path.as_ref(),
        &serde_json::to_vec_pretty(&ack_wire(value)?).map_err(|error| error.to_string())?,
        "qomm-pretrade-ack",
    )
}

pub fn read_ack_private(path: impl AsRef<Path>) -> Result<PretradeAcknowledgement, String> {
    decode_ack(&private_file(path.as_ref())?)
}
