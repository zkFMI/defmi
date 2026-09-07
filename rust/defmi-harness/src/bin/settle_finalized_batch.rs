//! Apply a finalized QOMM MPC handoff to the authoritative DeFMI database.
//!
//! This is the acceptance boundary after proof-node FROST finalization. It
//! reconstructs no amount, price, reserve, policy or inventory opening. The
//! only acceptance-fixture openings used here are the pre-trade maximums that
//! were already supplied by the owners to create their DeFMI reservations.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use defmi::asset_link::{prove as prove_asset_link, AssetLinkProof};
use defmi::avalanche::{
    AvalancheClient, AvalancheNoteBridge, AvalancheRpcClient, FacilityAvalancheBridge,
};
use defmi::claim_redemption::NoteClaimAuthorization;
use defmi::facility::{
    build_threshold_dvp_consumption, reserve_handle_for, CreditFacilityTransition,
    CreditTransitionKind, DefmiFacility, ProductSettlementBatch, ProductSettlementOrder,
    QuorumApproval, QuorumAuthorizer, ReservationConsumption, ReservationRole, SettlementOrder,
    StateLeg, ZERO,
};
use defmi::note_chain::{
    materialize_claim, note_claim_recipient_commitment, verify_claim_materialization,
    DelegatedClaimOpenings, DelegatedNoteLegProjection, NoteClaimKind, ProductNoteBindings,
    ProductNoteSettlementBatch, ProductNoteSettlementOrder,
    VerifiedDelegatedNoteSettlementProjection,
};
use defmi::notes::Wallet;
use defmi::product::{
    settle_product_threshold_batch, verify_note_settlement_authority, IdentityEvidence,
    ThresholdProductSettlement,
};
use defmi::product_evidence::ProductSettlementEvidence;
use defmi::settlement::{
    account_of, build_threshold_package_from_proofs, Sides, ThresholdDvpPackage, CASH_RAIL,
    SECURITIES_RAIL,
};
use qomm_proofs::price_limit::{from_threshold as threshold_price_limit, PriceLimitProof};
use qomm_transport::application_crypto::VerifyingKey;
use qomm_transport::order::{
    encode_execution_attestations, NodeExecutionAttestation, OrderedAdmission,
};
use qomm_transport::pretrade_authority::{
    read_ack_private, read_authority_private, AcceptanceOpening, PretradeReservationBinding,
    ReservationParty,
};
use qomm_transport::proof_codec::{
    encode_dvp_proofs, encode_quote_verification, encode_threshold_range,
};
use qomm_transport::settlement_handoff::{
    read_private as read_handoff, SettlementHandoff, SettlementHandoffBundle,
};
use zkfmi_zk::pedersen::Pedersen;
use zkpi::typed::TradeDirection;
use zkpi::{typed_wire, Bounds, Venue};
use rand_core::OsRng;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

const PRICE_BITS: usize = 32;
const AMOUNT_BITS: usize = 16;
const MAX_HORIZON: u64 = 3_600;

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

// Public acceptance fixture, separate from CSD, guarantor and facility receipt keys.
fn acknowledgement_key() -> qomm_transport::application_crypto::SigningKey {
    let mut seed = [0; 64];
    seed[..32].copy_from_slice(&Sha256::digest(b"QOMM:ACCEPTANCE:DEFMI-RECEIPT-KEY:ED:v2"));
    seed[32..].copy_from_slice(&Sha256::digest(b"QOMM:ACCEPTANCE:DEFMI-RECEIPT-KEY:PQ:v2"));
    qomm_transport::application_crypto::SigningKey::from_bytes(&seed)
}

fn receipt_key() -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(b"QOMM:ACCEPTANCE:DEFMI-RECEIPT-KEY:v1").into();
    SigningKey::from_bytes(&seed)
}

fn trusted_kyb_issuer() -> qomm_proofs::kyb::KybIssuerKey {
    let seed: [u8; 32] = Sha256::digest(b"QOMM:ACCEPTANCE:KYB-ISSUER-KEY:v1").into();
    qomm_proofs::kyb::KybIssuerKey::from_bytes(&zkfmi_crypto::traits::Signer::public_key(
        zkfmi_crypto::test_support::hybrid_signer(&seed).as_ref(),
    ))
    .unwrap()
}

fn governance_keys() -> BTreeMap<String, defmi::governance::GovernanceSigner> {
    defmi::governance::public_development_keys().expect("public development governance keys")
}

fn authorizer(
    keys: &BTreeMap<String, defmi::governance::GovernanceSigner>,
    domain: &str,
) -> Result<QuorumAuthorizer, String> {
    QuorumAuthorizer::new(
        keys.iter()
            .map(|(node, key)| (node.clone(), key.verifying_key()))
            .collect(),
        3,
        1,
        domain,
    )
}

fn approve(
    facility: &DefmiFacility,
    authorizer: &QuorumAuthorizer,
    keys: &BTreeMap<String, defmi::governance::GovernanceSigner>,
    statement: [u8; 32],
) -> Result<QuorumApproval, String> {
    let signers = keys
        .iter()
        .take(3)
        .map(|(node, key)| (node.clone(), key.clone()))
        .collect();
    authorizer.approve(statement, facility.state_root()?, &signers)
}

fn approve_root(
    root: [u8; 32],
    authorizer: &QuorumAuthorizer,
    keys: &BTreeMap<String, defmi::governance::GovernanceSigner>,
    statement: [u8; 32],
) -> Result<QuorumApproval, String> {
    let signers = keys
        .iter()
        .take(3)
        .map(|(node, key)| (node.clone(), key.clone()))
        .collect();
    authorizer.approve(statement, root, &signers)
}

fn required(arguments: &[String], name: &str) -> Result<PathBuf, String> {
    arguments
        .iter()
        .position(|value| value == name)
        .and_then(|position| arguments.get(position + 1))
        .map(PathBuf::from)
        .ok_or_else(|| format!("{name} is required"))
}

fn optional_string(arguments: &[String], name: &str) -> Option<String> {
    arguments
        .iter()
        .position(|value| value == name)
        .and_then(|position| arguments.get(position + 1))
        .cloned()
}

fn repeated_strings(arguments: &[String], name: &str) -> Vec<String> {
    arguments
        .windows(2)
        .filter(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .collect()
}

fn flag(arguments: &[String], name: &str) -> bool {
    arguments.iter().any(|value| value == name)
}

fn point(raw: [u8; 32], name: &str) -> Result<RistrettoPoint, String> {
    CompressedRistretto(raw)
        .decompress()
        .ok_or_else(|| format!("{name} is not a canonical Ristretto point"))
}

fn account_handle(owner: [u8; 32], rail: &[u8], name: &str) -> Result<[u8; 32], String> {
    account_of(&point(owner, name)?, rail)
        .try_into()
        .map_err(|_| format!("{name} account handle is not 32 bytes"))
}

fn escrow_handle(facility_id: [u8; 32], rail: &[u8]) -> Result<[u8; 32], String> {
    account_of(&reserve_handle_for(&facility_id), rail)
        .try_into()
        .map_err(|_| "reserve escrow handle is not 32 bytes".to_string())
}

fn reconstructed_hold(
    binding: &PretradeReservationBinding,
    opening: &AcceptanceOpening,
    query_commitment: [u8; 32],
    expires_at: u64,
    role: ReservationRole,
) -> Result<CreditFacilityTransition, String> {
    let commitment = Pedersen::new(b"qomm:defmi:v1")
        .commit_u64(opening.amount, &opening.blinding)
        .compress()
        .to_bytes();
    if commitment != binding.amount_commitment {
        return Err("reservation maximum opening differs from the signed DeFMI binding".into());
    }
    Ok(CreditFacilityTransition {
        operation_id: hash(&[
            b"QOMM:ACCEPTANCE:HOLD-OPERATION:v1",
            &binding.reserve_id,
            &[role as u8],
        ]),
        facility_id: binding.facility_id,
        hold_id: binding.reserve_id,
        kind: CreditTransitionKind::Hold,
        query_commitment,
        amount_commitment: binding.amount_commitment,
        consumed_commitment: ZERO,
        refund_commitment: ZERO,
        before_available_commitment: binding.amount_commitment,
        after_available_commitment: ZERO,
        before_held_commitment: ZERO,
        after_held_commitment: binding.amount_commitment,
        before_outstanding_commitment: ZERO,
        after_outstanding_commitment: ZERO,
        before_sequence: 0,
        expires_at,
        settlement_digest: ZERO,
        relation_proof_digest: ZERO,
    })
}

fn state_leg(
    facility: &DefmiFacility,
    handle: [u8; 32],
    expected_asset: [u8; 32],
    delta: RistrettoPoint,
) -> Result<StateLeg, String> {
    let (asset_id, before_commitment, before_sequence) =
        facility.account(&handle)?.ok_or_else(|| {
            "settlement account was not opened before pre-trade acknowledgement".to_string()
        })?;
    if asset_id != expected_asset {
        return Err("settlement account is on another asset rail".into());
    }
    let before = point(before_commitment, "settlement account commitment")?;
    Ok(StateLeg {
        handle,
        asset_id,
        before_commitment,
        after_commitment: (before + delta).compress().to_bytes(),
        before_sequence,
    })
}

struct PreparedSettlement {
    order: ProductSettlementOrder,
    typed: zkpi::typed::TypedInstruction,
    asset_link: AssetLinkProof,
    dvp: ThresholdDvpPackage,
    limit: PriceLimitProof,
    maker_index: usize,
    taker_index: usize,
}

struct PreparedNoteSettlement {
    order: ProductNoteSettlementOrder,
    evidence: ProductSettlementEvidence,
    typed: zkpi::typed::TypedInstruction,
    asset_link: AssetLinkProof,
    dvp: ThresholdDvpPackage,
    limit: PriceLimitProof,
    maker_index: usize,
    taker_index: usize,
}

#[allow(clippy::too_many_arguments)]
fn prepare_note_record(
    bridge: &AvalancheNoteBridge<'_, AvalancheRpcClient>,
    authority: &qomm_transport::pretrade_authority::PretradeAuthorityBundle,
    acknowledgement: &qomm_transport::pretrade_authority::PretradeAcknowledgement,
    record: &SettlementHandoff,
    execution_attestations: &[NodeExecutionAttestation],
    admission_receipt_digest: [u8; 32],
    venue: &Venue,
) -> Result<PreparedNoteSettlement, String> {
    let typed = record.typed_instruction()?;
    if record
        .frost_public
        .serialize()
        .map_err(|_| "handoff FROST package serialization failed")?
        != authority
            .settlement_verifier
            .frost_public
            .serialize()
            .map_err(|_| "authority FROST package serialization failed")?
    {
        return Err("finalized zkPI was signed by an unregistered FROST group".into());
    }
    let context = &typed.context;
    if context.before_state_root != acknowledgement.after_state_root
        || context.venue_id != authority.venue_id
        || context.defmi_id != authority.defmi_id
        || record.asset_id != authority.traded_asset_id
    {
        return Err("finalized zkPI is not bound to the acknowledged note state".into());
    }
    let taker_index = authority
        .takers
        .iter()
        .position(|candidate| candidate.mandate.digest().ok() == Some(record.limit_context))
        .ok_or_else(|| "finalized handoff names no signed Taker mandate".to_string())?;
    let taker = &authority.takers[taker_index];
    let maker_index = authority
        .makers
        .iter()
        .position(|candidate| {
            candidate.mandate.direction == taker.mandate.direction
                && candidate.mandate.maker_handle == context.maker_handle.compress().to_bytes()
        })
        .ok_or_else(|| "finalized handoff names no signed Maker policy".to_string())?;
    let maker = &authority.makers[maker_index];
    let maker_binding = acknowledgement.binding_for(
        ReservationParty::Maker,
        &maker.mandate.maker_handle,
        maker.mandate.direction,
    )?;
    let taker_binding = acknowledgement.binding_for(
        ReservationParty::Taker,
        &taker.mandate.taker_handle,
        taker.mandate.direction,
    )?;
    if maker_binding.reserve_id != context.maker_reservation_id
        || taker_binding.reserve_id != context.taker_reservation_id
        || maker_binding.reserve_receipt_digest != context.maker_reserve_receipt_digest
        || taker_binding.reserve_receipt_digest != context.taker_reserve_receipt_digest
    {
        return Err("finalized zkPI names another anonymous DeFMI reservation".into());
    }
    let (securities_binding, cash_binding) = match context.direction {
        TradeDirection::TakerBuys => (maker_binding, taker_binding),
        TradeDirection::TakerSells => (taker_binding, maker_binding),
    };
    if securities_binding.amount_commitment != record.securities_reserve.compress().to_bytes()
        || cash_binding.amount_commitment != record.cash_reserve.compress().to_bytes()
        || record.dvp_proofs.securities_remainder.bits != record.dvp_proofs.cash_remainder.bits
    {
        return Err("MPC DvP reserves differ from the anonymous pre-trade maxima".into());
    }
    let dvp = build_threshold_package_from_proofs(
        &venue.key,
        record.instruction.clone(),
        Sides::of(&record.instruction),
        record.securities_reserve,
        record.cash_reserve,
        record.cash_commitment,
        record.dvp_proofs.clone(),
        record.dvp_proofs.securities_remainder.bits,
    )?;
    if dvp.securities_remainder != record.securities_remainder
        || dvp.cash_remainder != record.cash_remainder
    {
        return Err("reconstructed anonymous DvP remainder differs from the handoff".into());
    }
    let limit = threshold_price_limit(
        &venue.key,
        &typed.payment.price_commitment,
        &record.limit_commitment,
        record.limit_direction,
        PRICE_BITS,
        &record.limit_context,
        record.price_limit_proof.clone(),
    )?;
    if record.limit_commitment.compress().to_bytes() != taker.mandate.limit_price_commitment {
        return Err("MPC limit commitment differs from the signed Taker mandate".into());
    }
    let asset_link = prove_asset_link(
        &venue.key,
        record.asset_id,
        &typed.payment.asset_commitment,
        &record.asset_blinding,
        &mut OsRng,
    )?;

    let securities_reservation = bridge.note_reservation(securities_binding.reserve_id)?;
    let cash_reservation = bridge.note_reservation(cash_binding.reserve_id)?;
    if securities_reservation.asset_id != authority.traded_asset_id
        || cash_reservation.asset_id != authority.cash_asset_id
        || securities_reservation.amount_commitment != securities_binding.amount_commitment
        || cash_reservation.amount_commitment != cash_binding.amount_commitment
        || securities_reservation.status != "active"
        || cash_reservation.status != "active"
    {
        return Err("canonical note covenants do not match the acknowledged reserves".into());
    }
    let claim_authorization = |opening: &qomm_proofs::opening_envelope::OpeningEnvelope,
                               asset: [u8; 32],
                               hold: [u8; 32],
                               kind: NoteClaimKind| {
        NoteClaimAuthorization::generate(
            note_claim_recipient_commitment(
                opening.recipient_view.compress().to_bytes(),
                typed.context.rfq_nullifier,
                asset,
                hold,
                kind,
            )?,
            authority.created_at,
            u64::MAX,
        )?
        .commitment()
    };
    let projection = VerifiedDelegatedNoteSettlementProjection::verify_and_project(
        venue,
        &typed,
        &dvp,
        hash(&[
            b"QOMM:ACCEPTANCE:DELEGATED-NOTE-SETTLEMENT:v1",
            &record.job_id,
        ]),
        DelegatedNoteLegProjection {
            asset_id: authority.traded_asset_id,
            hold_id: securities_binding.reserve_id,
            escrow_note_id: securities_reservation.escrow_note_id,
            delegation_digest: securities_reservation.delegation_digest,
            reserve_commitment: securities_reservation.amount_commitment,
        },
        DelegatedNoteLegProjection {
            asset_id: authority.cash_asset_id,
            hold_id: cash_binding.reserve_id,
            escrow_note_id: cash_reservation.escrow_note_id,
            delegation_digest: cash_reservation.delegation_digest,
            reserve_commitment: cash_reservation.amount_commitment,
        },
        DelegatedClaimOpenings {
            proof_job_id: record.job_id,
            securities_delivery: record.securities_delivery_opening.clone(),
            securities_refund: record.securities_refund_opening.clone(),
            cash_delivery: record.cash_delivery_opening.clone(),
            cash_refund: record.cash_refund_opening.clone(),
            authorizations: [
                claim_authorization(
                    &record.securities_delivery_opening,
                    authority.traded_asset_id,
                    securities_binding.reserve_id,
                    NoteClaimKind::Delivery,
                )?,
                claim_authorization(
                    &record.securities_refund_opening,
                    authority.traded_asset_id,
                    securities_binding.reserve_id,
                    NoteClaimKind::Refund,
                )?,
                claim_authorization(
                    &record.cash_delivery_opening,
                    authority.cash_asset_id,
                    cash_binding.reserve_id,
                    NoteClaimKind::Delivery,
                )?,
                claim_authorization(
                    &record.cash_refund_opening,
                    authority.cash_asset_id,
                    cash_binding.reserve_id,
                    NoteClaimKind::Refund,
                )?,
            ],
        },
        context.market_statement_digest,
        authority.created_at,
    )?;
    let settlement_statement = projection.settlement.statement()?;
    let maker_hold = reconstructed_hold(
        maker_binding,
        &maker.acceptance_opening,
        maker.mandate.policy_digest,
        maker.mandate.valid_until,
        ReservationRole::Maker,
    )?;
    let taker_digest = taker.mandate.digest()?;
    let taker_hold = reconstructed_hold(
        taker_binding,
        &taker.acceptance_opening,
        taker_digest,
        taker.mandate.deadline,
        ReservationRole::Taker,
    )?;
    let maker_before = bridge.credit_facility(maker_binding.facility_id)?.facility;
    let taker_before = bridge.credit_facility(taker_binding.facility_id)?.facility;
    let (maker_consumed, maker_refund, taker_consumed, taker_refund) = match context.direction {
        TradeDirection::TakerBuys => (
            dvp.instruction.amount_commitment,
            dvp.securities_remainder,
            dvp.cash_commitment,
            dvp.cash_remainder,
        ),
        TradeDirection::TakerSells => (
            dvp.cash_commitment,
            dvp.cash_remainder,
            dvp.instruction.amount_commitment,
            dvp.securities_remainder,
        ),
    };
    let maker_consume = build_threshold_dvp_consumption(
        hash(&[b"QOMM:ACCEPTANCE:NOTE-CONSUME:MAKER:v1", &record.job_id]),
        &maker_hold,
        &maker_before,
        ReservationRole::Maker,
        maker_consumed,
        maker_refund,
        settlement_statement,
        dvp.digest(),
    )?;
    let taker_consume = build_threshold_dvp_consumption(
        hash(&[b"QOMM:ACCEPTANCE:NOTE-CONSUME:TAKER:v1", &record.job_id]),
        &taker_hold,
        &taker_before,
        ReservationRole::Taker,
        taker_consumed,
        taker_refund,
        settlement_statement,
        dvp.digest(),
    )?;
    let order = projection.into_product(ProductNoteBindings {
        maker_entity_commitment: maker.mandate.entity_commitment,
        taker_entity_commitment: taker.mandate.entity_commitment,
        traded_asset_id: authority.traded_asset_id,
        price_limit_proof_digest: limit.digest(
            &typed.payment.price_commitment,
            &record.limit_commitment,
            &record.limit_context,
        ),
        asset_link_proof_digest: asset_link
            .digest(&authority.traded_asset_id, &typed.payment.asset_commitment),
        admission_receipt_digest,
        admission_epoch: authority
            .admission
            .as_ref()
            .ok_or_else(|| "authority has no admission epoch".to_string())?
            .epoch,
        admission_sequence: record.admission_sequence,
        reservations: vec![
            ReservationConsumption {
                role: ReservationRole::Maker,
                reserve_receipt_digest: maker_binding.reserve_receipt_digest,
                transition: maker_consume,
            },
            ReservationConsumption {
                role: ReservationRole::Taker,
                reserve_receipt_digest: taker_binding.reserve_receipt_digest,
                transition: taker_consume,
            },
        ],
    })?;
    if order.quote_proof_digest != context.quote_proof_digest
        || order.taker_mandate_digest != context.taker_mandate_digest
        || order.maker_policy_digest != context.maker_policy_digest
        || order.maker_mandate_digest != context.maker_mandate_digest
    {
        return Err("anonymous settlement differs from the proof-node context".into());
    }
    Ok(PreparedNoteSettlement {
        order,
        evidence: ProductSettlementEvidence {
            typed_instruction: typed_wire::encode(&typed),
            quote_verification: encode_quote_verification(&record.quote_verification)?,
            price_limit_proof: encode_threshold_range(&record.price_limit_proof)?,
            dvp_proofs: encode_dvp_proofs(&record.dvp_proofs)?,
            mpc_execution_attestations: encode_execution_attestations(execution_attestations)?,
            asset_link: asset_link.clone(),
        },
        typed,
        asset_link,
        dvp,
        limit,
        maker_index,
        taker_index,
    })
}

#[allow(clippy::too_many_arguments)]
fn prepare_record(
    facility: &DefmiFacility,
    authority: &qomm_transport::pretrade_authority::PretradeAuthorityBundle,
    acknowledgement: &qomm_transport::pretrade_authority::PretradeAcknowledgement,
    handoff: &SettlementHandoffBundle,
    record: &SettlementHandoff,
    admission_receipt_digest: [u8; 32],
    venue: &Venue,
) -> Result<PreparedSettlement, String> {
    let typed = record.typed_instruction()?;
    let context = &typed.context;
    if context.before_state_root != acknowledgement.after_state_root
        || context.venue_id != authority.venue_id
        || context.defmi_id != authority.defmi_id
        || record.asset_id != authority.traded_asset_id
    {
        return Err("finalized zkPI is not bound to the acknowledged DeFMI state".into());
    }
    let taker_index = authority
        .takers
        .iter()
        .position(|candidate| candidate.mandate.digest().ok() == Some(record.limit_context))
        .ok_or_else(|| "finalized handoff names no signed Taker mandate".to_string())?;
    let taker = &authority.takers[taker_index];
    let maker_index = authority
        .makers
        .iter()
        .position(|candidate| {
            candidate.mandate.direction == taker.mandate.direction
                && candidate.mandate.maker_handle == context.maker_handle.compress().to_bytes()
        })
        .ok_or_else(|| "finalized handoff names no signed Maker policy".to_string())?;
    let maker = &authority.makers[maker_index];
    let maker_binding = acknowledgement.binding_for(
        ReservationParty::Maker,
        &maker.mandate.maker_handle,
        maker.mandate.direction,
    )?;
    let taker_binding = acknowledgement.binding_for(
        ReservationParty::Taker,
        &taker.mandate.taker_handle,
        taker.mandate.direction,
    )?;
    if maker_binding.reserve_id != context.maker_reservation_id
        || taker_binding.reserve_id != context.taker_reservation_id
        || maker_binding.reserve_receipt_digest != context.maker_reserve_receipt_digest
        || taker_binding.reserve_receipt_digest != context.taker_reserve_receipt_digest
    {
        return Err("finalized zkPI names another DeFMI reservation".into());
    }

    let (securities_binding, cash_binding) = match context.direction {
        TradeDirection::TakerBuys => (maker_binding, taker_binding),
        TradeDirection::TakerSells => (taker_binding, maker_binding),
    };
    if securities_binding.amount_commitment != record.securities_reserve.compress().to_bytes()
        || cash_binding.amount_commitment != record.cash_reserve.compress().to_bytes()
    {
        return Err("MPC DvP reserves differ from DeFMI pre-trade maxima".into());
    }
    if record.dvp_proofs.securities_remainder.bits != record.dvp_proofs.cash_remainder.bits {
        return Err("MPC DvP remainder proofs use different range widths".into());
    }
    let remainder_bits = record.dvp_proofs.securities_remainder.bits;
    let parties = Sides::of(&record.instruction);
    let dvp = build_threshold_package_from_proofs(
        &venue.key,
        record.instruction.clone(),
        Sides {
            securities_from: escrow_handle(securities_binding.facility_id, SECURITIES_RAIL)?
                .to_vec(),
            securities_to: parties.securities_to.clone(),
            cash_from: escrow_handle(cash_binding.facility_id, CASH_RAIL)?.to_vec(),
            cash_to: parties.cash_to.clone(),
        },
        record.securities_reserve,
        record.cash_reserve,
        record.cash_commitment,
        record.dvp_proofs.clone(),
        remainder_bits,
    )?;
    if dvp.securities_remainder != record.securities_remainder
        || dvp.cash_remainder != record.cash_remainder
    {
        return Err("reconstructed DvP remainder differs from the finalized handoff".into());
    }
    let limit = threshold_price_limit(
        &venue.key,
        &typed.payment.price_commitment,
        &record.limit_commitment,
        record.limit_direction,
        PRICE_BITS,
        &record.limit_context,
        record.price_limit_proof.clone(),
    )?;
    if record.limit_commitment.compress().to_bytes() != taker.mandate.limit_price_commitment {
        return Err("MPC limit commitment differs from the signed Taker mandate".into());
    }
    let asset_link = prove_asset_link(
        &venue.key,
        record.asset_id,
        &typed.payment.asset_commitment,
        &record.asset_blinding,
        &mut OsRng,
    )?;

    let securities_source = account_handle(
        securities_binding.owner_handle,
        SECURITIES_RAIL,
        "securities reserve owner",
    )?;
    let cash_source = account_handle(cash_binding.owner_handle, CASH_RAIL, "cash reserve owner")?;
    let securities_to: [u8; 32] = parties
        .securities_to
        .as_slice()
        .try_into()
        .map_err(|_| "securities destination is not 32 bytes".to_string())?;
    let cash_to: [u8; 32] = parties
        .cash_to
        .as_slice()
        .try_into()
        .map_err(|_| "cash destination is not 32 bytes".to_string())?;
    let settlement = SettlementOrder {
        operation_id: hash(&[b"QOMM:ACCEPTANCE:SETTLEMENT:v1", &record.job_id]),
        nullifier: typed.payment.nullifier(),
        deadline: typed.payment.deadline,
        payment_instruction_digest: Sha256::digest(typed_wire::encode(&typed)).into(),
        proof_digest: record.quote_digest,
        market_statement_digest: context.market_statement_digest,
        legs: vec![
            state_leg(
                facility,
                securities_source,
                authority.traded_asset_id,
                dvp.securities_remainder,
            )?,
            state_leg(
                facility,
                securities_to,
                authority.traded_asset_id,
                dvp.instruction.amount_commitment,
            )?,
            state_leg(
                facility,
                cash_source,
                authority.cash_asset_id,
                dvp.cash_remainder,
            )?,
            state_leg(
                facility,
                cash_to,
                authority.cash_asset_id,
                dvp.cash_commitment,
            )?,
        ],
    };
    let settlement_statement = settlement.statement()?;
    let dvp_digest = dvp.digest();
    let maker_hold = reconstructed_hold(
        maker_binding,
        &maker.acceptance_opening,
        maker.mandate.policy_digest,
        maker.mandate.valid_until,
        ReservationRole::Maker,
    )?;
    let taker_digest = taker.mandate.digest()?;
    let taker_hold = reconstructed_hold(
        taker_binding,
        &taker.acceptance_opening,
        taker_digest,
        taker.mandate.deadline,
        ReservationRole::Taker,
    )?;
    let maker_before = facility
        .credit_facility(&maker_binding.facility_id)?
        .ok_or_else(|| "Maker facility is absent".to_string())?;
    let taker_before = facility
        .credit_facility(&taker_binding.facility_id)?
        .ok_or_else(|| "Taker facility is absent".to_string())?;
    let (maker_consumed, maker_refund, taker_consumed, taker_refund) = match context.direction {
        TradeDirection::TakerBuys => (
            dvp.instruction.amount_commitment,
            dvp.securities_remainder,
            dvp.cash_commitment,
            dvp.cash_remainder,
        ),
        TradeDirection::TakerSells => (
            dvp.cash_commitment,
            dvp.cash_remainder,
            dvp.instruction.amount_commitment,
            dvp.securities_remainder,
        ),
    };
    let maker_consume = build_threshold_dvp_consumption(
        hash(&[b"QOMM:ACCEPTANCE:CONSUME:MAKER:v1", &record.job_id]),
        &maker_hold,
        &maker_before,
        ReservationRole::Maker,
        maker_consumed,
        maker_refund,
        settlement_statement,
        dvp_digest,
    )?;
    let taker_consume = build_threshold_dvp_consumption(
        hash(&[b"QOMM:ACCEPTANCE:CONSUME:TAKER:v1", &record.job_id]),
        &taker_hold,
        &taker_before,
        ReservationRole::Taker,
        taker_consumed,
        taker_refund,
        settlement_statement,
        dvp_digest,
    )?;
    let order = ProductSettlementOrder {
        settlement,
        venue_id: authority.venue_id,
        defmi_id: authority.defmi_id,
        maker_entity_commitment: maker.mandate.entity_commitment,
        taker_entity_commitment: taker.mandate.entity_commitment,
        rfq_nullifier: taker.mandate.rfq_nullifier,
        taker_authorization_digest: taker_digest,
        maker_policy_digest: maker.mandate.policy_digest,
        maker_mandate_digest: maker.mandate.digest()?,
        taker_mandate_digest: taker_digest,
        typed_instruction_digest: Sha256::digest(typed_wire::encode(&typed)).into(),
        quote_proof_digest: record.quote_digest,
        price_limit_proof_digest: limit.digest(
            &typed.payment.price_commitment,
            &record.limit_commitment,
            &record.limit_context,
        ),
        dvp_proof_digest: dvp_digest,
        quantity_commitment: dvp.instruction.amount_commitment.compress().to_bytes(),
        cash_commitment: dvp.cash_commitment.compress().to_bytes(),
        traded_asset_id: authority.traded_asset_id,
        asset_link_proof_digest: asset_link
            .digest(&authority.traded_asset_id, &typed.payment.asset_commitment),
        admission_receipt_digest,
        admission_epoch: authority
            .admission
            .as_ref()
            .ok_or_else(|| "authority has no admission epoch".to_string())?
            .epoch,
        admission_sequence: record.admission_sequence,
        reservations: vec![
            ReservationConsumption {
                role: ReservationRole::Maker,
                reserve_receipt_digest: maker_binding.reserve_receipt_digest,
                transition: maker_consume,
            },
            ReservationConsumption {
                role: ReservationRole::Taker,
                reserve_receipt_digest: taker_binding.reserve_receipt_digest,
                transition: taker_consume,
            },
        ],
    };
    if order.quote_proof_digest != context.quote_proof_digest
        || order.taker_mandate_digest != context.taker_mandate_digest
        || order.maker_policy_digest != context.maker_policy_digest
        || order.maker_mandate_digest != context.maker_mandate_digest
    {
        return Err("settlement order differs from the proof-node execution context".into());
    }
    let _ = handoff;
    Ok(PreparedSettlement {
        order,
        typed,
        asset_link,
        dvp,
        limit,
        maker_index,
        taker_index,
    })
}

fn write_private_json(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    if path.exists() {
        return Err(format!(
            "refusing to overwrite settlement report: {}",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

#[allow(clippy::too_many_arguments)]
fn settle_account_free_note_batch(
    authority: &qomm_transport::pretrade_authority::PretradeAuthorityBundle,
    acknowledgement: &qomm_transport::pretrade_authority::PretradeAcknowledgement,
    handoff: &SettlementHandoffBundle,
    certified: &[qomm_transport::order::CertifiedAdmissionLane],
    venue: &Venue,
    governance: &BTreeMap<String, defmi::governance::GovernanceSigner>,
    authorizer: &QuorumAuthorizer,
    client: &AvalancheRpcClient,
    peer_endpoints: &[String],
    authorizer_domain: &str,
    report_path: &Path,
) -> Result<(), String> {
    let admission = authority
        .admission
        .as_ref()
        .ok_or_else(|| "authority has no certified admission population".to_string())?;
    let bridge = AvalancheNoteBridge::new(authorizer, client);
    let before_root = client.state_root()?;
    if before_root != acknowledgement.after_state_root {
        return Err("Avalanche note state changed after its pre-trade acknowledgement".into());
    }
    let mut prepared = handoff
        .records
        .iter()
        .map(|record| {
            let lane = certified
                .get(record.lane)
                .ok_or_else(|| "settlement record names an absent admission lane".to_string())?;
            let taker = authority
                .takers
                .iter()
                .find(|candidate| candidate.mandate.digest().ok() == Some(record.limit_context))
                .ok_or_else(|| "settlement record names no admitted Taker".to_string())?;
            let ordered = OrderedAdmission {
                venue_id: authority.venue_id,
                epoch: admission.epoch,
                slot: lane.slot,
                sequence: lane.sequence,
                ticket_id: lane.ticket_id,
                batch_digest: lane.cluster_digest,
                order_digest: lane.order_digest,
                rfq_nullifier: taker.mandate.rfq_nullifier,
                taker_entity_commitment: taker.mandate.entity_commitment,
                taker_mandate_digest: taker.mandate.digest()?,
                expires_at: taker.mandate.deadline,
            };
            prepare_note_record(
                &bridge,
                authority,
                acknowledgement,
                record,
                handoff.execution_lanes.get(record.lane).ok_or_else(|| {
                    "settlement record names an absent execution lane".to_string()
                })?,
                ordered.certified_digest()?,
                venue,
            )
        })
        .collect::<Result<Vec<_>, String>>()?;
    prepared.sort_by_key(|item| item.order.admission_sequence);
    let orders = prepared
        .iter()
        .map(|item| item.order.clone())
        .collect::<Vec<_>>();
    let batch_id = hash(&[
        b"QOMM:ACCEPTANCE:NOTE-SETTLEMENT-BATCH:v1",
        &acknowledgement.authority_digest,
        &handoff.cluster_digest,
        &handoff.order_digest,
    ]);
    let batch = ProductNoteSettlementBatch::from_orders(batch_id, &orders)?;
    let kyb_issuer = trusted_kyb_issuer();
    let maker_identities = authority
        .makers
        .iter()
        .map(|maker| IdentityEvidence {
            presentation: &maker.presentation,
            registry: &authority.registry,
            trusted_issuer: &kyb_issuer,
            scope: &authority.identity_scope,
            context: &maker.identity_context,
            required_cohort: &authority.required_cohort,
        })
        .collect::<Vec<_>>();
    let taker_identities = authority
        .takers
        .iter()
        .map(|taker| IdentityEvidence {
            presentation: &taker.presentation,
            registry: &authority.registry,
            trusted_issuer: &kyb_issuer,
            scope: &authority.identity_scope,
            context: &taker.identity_context,
            required_cohort: &authority.required_cohort,
        })
        .collect::<Vec<_>>();
    for item in &prepared {
        verify_note_settlement_authority(
            &item.order,
            &item.typed,
            venue,
            &item.limit,
            &authority.makers[item.maker_index].mandate,
            &maker_identities[item.maker_index],
            &authority.takers[item.taker_index].mandate,
            &taker_identities[item.taker_index],
            authority.created_at,
        )?;
        if !defmi::asset_link::verify(
            &venue.key,
            &authority.traded_asset_id,
            &item.typed.payment.asset_commitment,
            &item.asset_link,
        ) || item.asset_link.digest(
            &authority.traded_asset_id,
            &item.typed.payment.asset_commitment,
        ) != item.order.asset_link_proof_digest
            || item.dvp.digest() != item.order.dvp_proof_digest
        {
            return Err("anonymous settlement asset or DvP evidence is inconsistent".into());
        }
    }
    let approval = approve_root(before_root, authorizer, governance, batch.statement()?)?;
    let evidence = prepared
        .iter()
        .map(|item| item.evidence.clone())
        .collect::<Vec<_>>();
    let accepted = bridge.settle_product_batch(&batch, &orders, &evidence, &approval)?;
    let settlement_after_root = client.state_root()?;
    if accepted.before_root != before_root || accepted.after_root != settlement_after_root {
        return Err("Avalanche returned an inconsistent anonymous batch receipt".into());
    }
    let mut claim_ids = Vec::new();
    let mut consumed_holds = Vec::new();
    for order in &orders {
        let product_statement = order.statement()?;
        for spend in &order.settlement.spends {
            let reservation = bridge.note_reservation(spend.hold_id)?;
            if reservation.status != "consumed"
                || reservation.settlement_digest != product_statement
            {
                return Err("final DvP did not consume its delegated reservation".into());
            }
            consumed_holds.push(spend.hold_id);
            for claim in &spend.claims {
                let canonical = bridge.note_claim(claim.claim_id)?;
                if canonical.claim_id != claim.claim_id
                    || canonical.asset_id != claim.asset_id
                    || canonical.value_commitment != claim.value_commitment
                    || canonical.recipient_commitment != claim.recipient_commitment
                    || canonical.opening_envelope != claim.opening_envelope
                    || canonical.status != "active"
                    || canonical.settlement_digest != product_statement
                {
                    return Err("final DvP stored a different confidential entitlement".into());
                }
                claim_ids.push(claim.claim_id);
            }
        }
    }
    // Demonstrate the later withdrawal-like path for one final claim. This is
    // not trade consent: DvP and all four claims are already final above. The
    // rightful one-use recipient alone decrypts 3-of-7 opening shares and
    // proves control of that recipient key without revealing amount/blinding.
    let first_prepared = prepared
        .first()
        .ok_or_else(|| "anonymous settlement produced no claim to materialize".to_string())?;
    let first_claim = first_prepared
        .order
        .settlement
        .spends
        .first()
        .and_then(|spend| spend.claims.first())
        .ok_or_else(|| "anonymous settlement omitted its first delivery claim".to_string())?;
    // Acceptance fixtures deterministically own these one-use handles. A real
    // settlement service never has these scalars; the participant wallet runs
    // this materialization step instead.
    let maker_secret =
        Scalar::from(21_u64 + u64::from(authority.makers[first_prepared.maker_index].maker_index));
    let taker_secret = Scalar::from(
        101_u64 + u64::from(authority.takers[first_prepared.taker_index].client_index),
    );
    let recipient_secret = [maker_secret, taker_secret]
        .into_iter()
        .find(|secret| {
            (G * secret).compress() == first_claim.opening_envelope.recipient_view.compress()
        })
        .ok_or_else(|| "acceptance claim is encrypted to an unknown recipient".to_string())?;
    let destination = Wallet::from_parts(
        Scalar::from_bytes_mod_order(hash(&[
            b"QOMM:ACCEPTANCE:CLAIM-DESTINATION-VIEW:v1",
            &first_claim.claim_id,
        ])),
        Scalar::from_bytes_mod_order(hash(&[
            b"QOMM:ACCEPTANCE:CLAIM-DESTINATION-SPEND:v1",
            &first_claim.claim_id,
        ])),
        zkfmi_crypto::hybrid::kem::HybridKemKey::from_seed(&[29; 96]),
    );
    let (materialization, ownership_proof) = materialize_claim(
        first_claim,
        &venue.key,
        AMOUNT_BITS,
        first_prepared.order.rfq_nullifier,
        &recipient_secret,
        &zkfmi_crypto::test_support::public_fixture_recipient_key(
            &(G * recipient_secret).compress().to_bytes(),
        ),
        &destination.address,
        &[1, 4, 7],
        hash(&[
            b"QOMM:ACCEPTANCE:CLAIM-MATERIALIZATION:v1",
            &first_claim.claim_id,
        ]),
        &mut OsRng,
    )?;
    verify_claim_materialization(
        first_claim,
        first_prepared.order.rfq_nullifier,
        &(G * recipient_secret),
        &destination.address,
        &materialization,
        &ownership_proof,
    )?;
    let materialization_approval = approve_root(
        settlement_after_root,
        authorizer,
        governance,
        materialization.statement()?,
    )?;
    let materialization_receipt =
        bridge.materialize_note_claim(&materialization, &materialization_approval)?;
    let after_root = client.state_root()?;
    let canonical_claim = bridge.note_claim(first_claim.claim_id)?;
    let canonical_note = bridge.note(materialization.output.note_id)?;
    if materialization_receipt.before_root != settlement_after_root
        || materialization_receipt.after_root != after_root
        || canonical_claim.status != "materialized"
        || canonical_claim.materialization != materialization.statement()?
        || canonical_note.output != materialization.output
    {
        return Err("recipient claim materialization did not become canonical".into());
    }
    let mut consensus_roots = vec![after_root];
    for endpoint in peer_endpoints {
        consensus_roots
            .push(AvalancheRpcClient::new(endpoint, Duration::from_secs(30), true)?.state_root()?);
    }
    if consensus_roots.iter().any(|root| *root != after_root) {
        return Err("Avalanche validators disagree on anonymous DvP finality".into());
    }
    let unique_taker_entities = prepared
        .iter()
        .map(|item| authority.takers[item.taker_index].mandate.entity_commitment)
        .collect::<BTreeSet<_>>()
        .len();
    let report = json!({
        "version": 2,
        "authoritative_backend": "avalanche_l1_account_free_notes",
        "authorizer_domain": authorizer_domain,
        "avalanche_tx_id": accepted.tx_id,
        "avalanche_block_id": accepted.block_id,
        "avalanche_height": accepted.height,
        "claim_materialization_tx_id": materialization_receipt.tx_id,
        "claim_materialization_block_id": materialization_receipt.block_id,
        "claim_materialization_height": materialization_receipt.height,
        "avalanche_validators_verified": consensus_roots.len(),
        "batch_id": hex::encode(batch.batch_id),
        "batch_statement": hex::encode(batch.statement()?),
        "before_state_root": hex::encode(before_root),
        "settlement_after_state_root": hex::encode(settlement_after_root),
        "after_state_root": hex::encode(after_root),
        "settled_rfqs": orders.len(),
        "admission_sequences": batch.members.iter().map(|member| member.admission_sequence).collect::<Vec<_>>(),
        "unique_taker_legal_entities": unique_taker_entities,
        "consumed_note_holds": consumed_holds.iter().map(hex::encode).collect::<Vec<_>>(),
        "created_note_claims": claim_ids.iter().map(hex::encode).collect::<Vec<_>>(),
        "materialized_claim_id": hex::encode(first_claim.claim_id),
        "materialized_note_id": hex::encode(materialization.output.note_id),
        "claim_ownership_proof_digest": hex::encode(materialization.ownership_proof_digest),
        "source_accounts_used": 0,
        "destination_accounts_used": 0,
        "post_quote_maker_or_taker_signature": false,
        "settlement_final_before_claim_materialization": true,
        "atomic_l1_transition": true,
        "state_database": null,
    });
    write_private_json(report_path, &report)?;
    println!(
        "atomically settled {} account-free MPC zkPI record(s): {}",
        orders.len(),
        report_path.display()
    );
    Ok(())
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let authority_path = required(&arguments, "--authority")?;
    let acknowledgement_path = required(&arguments, "--ack")?;
    let handoff_path = required(&arguments, "--finalized-handoff")?;
    let state_path = required(&arguments, "--state")?;
    let report_path = required(&arguments, "--report-out")?;
    let avalanche_endpoint = optional_string(&arguments, "--avalanche-endpoint");
    let avalanche_domain = optional_string(&arguments, "--avalanche-domain");
    let avalanche_peer_endpoints = repeated_strings(&arguments, "--avalanche-peer-endpoint");
    let simulate_crash_window = flag(&arguments, "--simulate-crash-window");
    let account_free_notes = flag(&arguments, "--account-free-notes");
    if avalanche_endpoint.is_some() != avalanche_domain.is_some() {
        return Err("--avalanche-endpoint and --avalanche-domain must be provided together".into());
    }
    if avalanche_endpoint.is_none() && !avalanche_peer_endpoints.is_empty() {
        return Err("--avalanche-peer-endpoint requires --avalanche-endpoint".into());
    }
    let authority = read_authority_private(&authority_path)?;
    let acknowledgement = read_ack_private(&acknowledgement_path)?;
    acknowledgement.verify(&acknowledgement_key().verifying_key())?;
    if acknowledgement.authority_digest != authority.digest()?
        || acknowledgement.defmi_id != authority.defmi_id
    {
        return Err("pre-trade authority and acknowledgement differ".into());
    }
    let handoff = read_handoff(&handoff_path)?;
    let admission = authority
        .admission
        .as_ref()
        .ok_or_else(|| "authority has no certified admission population".to_string())?;
    if handoff.admission_node_keys != admission.node_keys {
        return Err("finalized handoff uses another admission committee".into());
    }
    let trusted = admission
        .node_keys
        .iter()
        .map(|raw| {
            VerifyingKey::from_bytes(raw)
                .map_err(|_| "authority admission key is malformed".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let certified = handoff.verify_admission(&trusted)?;
    if handoff.records.is_empty() {
        return Err("finalized handoff has no settlements".into());
    }
    let frost_public = handoff.records[0].frost_public.clone();
    if frost_public.serialize().ok() != authority.settlement_verifier.frost_public.serialize().ok()
    {
        return Err("settlement handoff differs from the pre-enrolled FROST committee".into());
    }
    if handoff
        .records
        .iter()
        .any(|record| record.frost_public.serialize().ok() != frost_public.serialize().ok())
    {
        return Err("one settlement batch mixes FROST committee epochs".into());
    }
    let venue = Venue::new(
        Pedersen::new(b"qomm:defmi:v1"),
        &Bounds {
            amount_bits: AMOUNT_BITS,
            price_bits: PRICE_BITS,
            max_horizon: MAX_HORIZON,
        },
        frost_public,
    )
    .require_threshold_ranges()
    .require_pq_committee(authority.settlement_verifier.pq_committee.clone())
    .map_err(str::to_string)?;
    let governance = governance_keys();
    let authorizer_domain = avalanche_domain.as_deref().unwrap_or("defmi:qomm-live-v1");
    let authorizer = authorizer(&governance, authorizer_domain)?;
    if account_free_notes {
        if simulate_crash_window {
            return Err(
                "--simulate-crash-window is only defined for the SQLite projection path".into(),
            );
        }
        let endpoint = avalanche_endpoint.as_deref().ok_or_else(|| {
            "--account-free-notes requires an authoritative Avalanche endpoint".to_string()
        })?;
        let client = AvalancheRpcClient::new(endpoint, Duration::from_secs(30), true)?;
        return settle_account_free_note_batch(
            &authority,
            &acknowledgement,
            &handoff,
            &certified,
            &venue,
            &governance,
            &authorizer,
            &client,
            &avalanche_peer_endpoints,
            authorizer_domain,
            &report_path,
        );
    }
    let facility = DefmiFacility::open(
        &state_path,
        authorizer.clone(),
        zkfmi_crypto::test_support::hybrid_signer(&receipt_key().to_bytes()),
    )?;
    if facility.state_root()? != acknowledgement.after_state_root {
        return Err("DeFMI state changed after its pre-trade acknowledgement".into());
    }

    let mut prepared = handoff
        .records
        .iter()
        .map(|record| {
            let lane = certified
                .get(record.lane)
                .ok_or_else(|| "settlement record names an absent admission lane".to_string())?;
            let taker = authority
                .takers
                .iter()
                .find(|candidate| candidate.mandate.digest().ok() == Some(record.limit_context))
                .ok_or_else(|| "settlement record names no admitted Taker".to_string())?;
            let ordered = OrderedAdmission {
                venue_id: authority.venue_id,
                epoch: admission.epoch,
                slot: lane.slot,
                sequence: lane.sequence,
                ticket_id: lane.ticket_id,
                batch_digest: lane.cluster_digest,
                order_digest: lane.order_digest,
                rfq_nullifier: taker.mandate.rfq_nullifier,
                taker_entity_commitment: taker.mandate.entity_commitment,
                taker_mandate_digest: taker.mandate.digest()?,
                expires_at: taker.mandate.deadline,
            };
            prepare_record(
                &facility,
                &authority,
                &acknowledgement,
                &handoff,
                record,
                ordered.certified_digest()?,
                &venue,
            )
        })
        .collect::<Result<Vec<_>, String>>()?;
    prepared.sort_by_key(|item| item.order.admission_sequence);
    let orders = prepared
        .iter()
        .map(|item| item.order.clone())
        .collect::<Vec<_>>();
    let batch_id = hash(&[
        b"QOMM:ACCEPTANCE:SETTLEMENT-BATCH:v1",
        &acknowledgement.authority_digest,
        &handoff.cluster_digest,
        &handoff.order_digest,
    ]);
    let batch = ProductSettlementBatch::from_orders(batch_id, &orders)?;
    let approval = approve(&facility, &authorizer, &governance, batch.statement()?)?;
    let kyb_issuer = trusted_kyb_issuer();
    let maker_identities = authority
        .makers
        .iter()
        .map(|maker| IdentityEvidence {
            presentation: &maker.presentation,
            registry: &authority.registry,
            trusted_issuer: &kyb_issuer,
            scope: &authority.identity_scope,
            context: &maker.identity_context,
            required_cohort: &authority.required_cohort,
        })
        .collect::<Vec<_>>();
    let taker_identities = authority
        .takers
        .iter()
        .map(|taker| IdentityEvidence {
            presentation: &taker.presentation,
            registry: &authority.registry,
            trusted_issuer: &kyb_issuer,
            scope: &authority.identity_scope,
            context: &taker.identity_context,
            required_cohort: &authority.required_cohort,
        })
        .collect::<Vec<_>>();
    let items = prepared
        .iter()
        .map(|item| ThresholdProductSettlement {
            order: &item.order,
            relation_proofs: &[],
            typed_instruction: &item.typed,
            asset_link: &item.asset_link,
            dvp_package: &item.dvp,
            price_limit_proof: &item.limit,
            maker_mandate: &authority.makers[item.maker_index].mandate,
            maker_identity: &maker_identities[item.maker_index],
            taker_mandate: &authority.takers[item.taker_index].mandate,
            taker_identity: &taker_identities[item.taker_index],
        })
        .collect::<Vec<_>>();
    let before_root = facility.state_root()?;
    let avalanche_client = avalanche_endpoint
        .as_deref()
        .map(|endpoint| AvalancheRpcClient::new(endpoint, Duration::from_secs(30), true))
        .transpose()?;
    let (receipts, avalanche_acceptance, crash_window_recovery) =
        if let Some(client) = avalanche_client.as_ref() {
            let bridge = FacilityAvalancheBridge::new(&facility, client);
            let direct_acceptance = if simulate_crash_window {
                // Exercise the exact failure window in which Avalanche has accepted
                // the batch but the local SQLite projection has not yet advanced.
                // Every private proof is still checked before the first broadcast.
                let accepted = bridge.submit_product_threshold_batch(
                    &batch,
                    &items,
                    &venue,
                    &approval,
                    authority.created_at,
                    &mut OsRng,
                )?;
                if facility.state_root()? != before_root {
                    return Err("local projection changed inside the simulated crash window".into());
                }
                Some(accepted)
            } else {
                None
            };
            let (receipts, accepted) = bridge.settle_product_threshold_batch(
                &batch,
                &items,
                &venue,
                &approval,
                authority.created_at,
                &mut OsRng,
            )?;
            let recovery = direct_acceptance.as_ref().map(|first| {
                json!({
                    "simulated": true,
                    "local_projection_unchanged_before_retry": true,
                    "transaction_id_reused": first.tx_id == accepted.tx_id,
                    "accepted_root_reprojected": true,
                })
            });
            if direct_acceptance
                .as_ref()
                .is_some_and(|first| first.tx_id != accepted.tx_id)
            {
                return Err("crash-window retry created a second Avalanche transaction".into());
            }
            (receipts, Some(accepted), recovery)
        } else {
            (
                settle_product_threshold_batch(
                    &facility,
                    &batch,
                    &items,
                    &venue,
                    &approval,
                    authority.created_at,
                    &mut OsRng,
                )?,
                None,
                None,
            )
        };
    let after_root = facility.state_root()?;
    if receipts.len() != items.len()
        || receipts
            .iter()
            .any(|receipt| !receipt.verify(&facility.receipt_public_key))
        || !facility.verify_receipt_chain()?
        || receipts.first().map(|receipt| receipt.before_root) != Some(before_root)
        || receipts.last().map(|receipt| receipt.after_root) != Some(after_root)
    {
        return Err("committed product batch failed receipt-chain verification".into());
    }
    let mut avalanche_consensus_roots = Vec::new();
    if let Some(client) = avalanche_client.as_ref() {
        avalanche_consensus_roots.push(client.state_root()?);
        for endpoint in &avalanche_peer_endpoints {
            avalanche_consensus_roots.push(
                AvalancheRpcClient::new(endpoint, Duration::from_secs(30), true)?.state_root()?,
            );
        }
        if avalanche_consensus_roots
            .iter()
            .any(|root| *root != after_root)
        {
            return Err("Avalanche validators disagree with the accepted DeFMI state root".into());
        }
    }
    let unique_taker_entities = prepared
        .iter()
        .map(|item| authority.takers[item.taker_index].mandate.entity_commitment)
        .collect::<BTreeSet<_>>()
        .len();
    let report = json!({
        "version": 1,
        "authoritative_backend": if avalanche_acceptance.is_some() { "avalanche_l1" } else { "local_sqlite" },
        "authorizer_domain": authorizer_domain,
        "avalanche_tx_id": avalanche_acceptance.as_ref().map(|accepted| accepted.tx_id.as_str()),
        "avalanche_block_id": avalanche_acceptance.as_ref().map(|accepted| accepted.block_id.as_str()),
        "avalanche_height": avalanche_acceptance.as_ref().map(|accepted| accepted.height),
        "avalanche_validators_verified": avalanche_consensus_roots.len(),
        "batch_id": hex::encode(batch.batch_id),
        "batch_statement": hex::encode(batch.statement()?),
        "before_state_root": hex::encode(before_root),
        "after_state_root": hex::encode(after_root),
        "settled_rfqs": receipts.len(),
        "admission_sequences": batch.members.iter().map(|member| member.admission_sequence).collect::<Vec<_>>(),
        "unique_taker_legal_entities": unique_taker_entities,
        "atomic_sql_transaction": true,
        "receipt_chain_valid": true,
        "post_quote_maker_or_taker_signature": false,
        "crash_window_recovery": crash_window_recovery,
        "state_database": state_path,
    });
    write_private_json(&report_path, &report)?;
    println!(
        "atomically settled {} finalized MPC zkPI record(s): {}",
        receipts.len(),
        report_path.display()
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("finalized batch settlement failed: {error}");
        std::process::exit(1);
    }
}
