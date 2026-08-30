//! Product-level authorization boundary for QOMM.
//!
//! The durable facility intentionally knows commitments and state transitions,
//! not legal-entity credentials or Maker/Taker signatures.  This adapter is
//! the only public entry point that turns those pre-trade authorities into a
//! bound DeFMI reservation.  It prevents callers from supplying plausible
//! digests without the signed mandate and live ZK-KYB presentation behind
//! them.

use curve25519_dalek::ristretto::CompressedRistretto;
use ed25519_dalek::VerifyingKey;
use qomm_proofs::kyb::{KybPresentation, SignedCohortRegistry};
use qomm_proofs::price_limit::{
    verify as verify_price_limit, PriceLimitDirection, PriceLimitProof,
};
use qomm_transport::mandate::{MakerPolicyMandate, TakerExecutionMandate};
use qomm_transport::order::OrderedAdmission;
use qomm_zkpi::typed::TypedInstruction;
use qomm_zkpi::Venue;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::asset_link::AssetLinkProof;
use crate::facility::{
    reserve_handle_for, AssetKind, CreditFacilityRelationProof, CreditFacilitySnapshot,
    CreditFacilityTransition, DefmiFacility, ProductReleaseOrder, ProductSettlementBatch,
    ProductSettlementOrder, QuorumApproval, ReservationAuthorization, ReservationEscrow,
    ReservationExecution, ReservationRole, SettlementReceipt,
};
use crate::ledger::{Ledger, Transfer};
use crate::note_chain::{NoteReservationEscrow, ProductNoteSettlementOrder};
use crate::settlement::{account_of, CASH_RAIL, SECURITIES_RAIL};
use crate::settlement::{DvpPackage, ThresholdDvpPackage};

/// Full confidential evidence for moving a pre-trade maximum out of the
/// owner's spendable account.  Only its digest is retained by Avalanche.
pub struct ReservationEscrowProof {
    pub transfer: Transfer,
}

impl ReservationEscrowProof {
    pub fn digest(&self) -> [u8; 32] {
        self.transfer.digest()
    }
}

/// Transcript context used by the owner when constructing its reserve proof.
pub fn escrow_transfer_context(hold_id: &[u8; 32]) -> Vec<u8> {
    [b"QOMM:DEFMI:RESERVE-ESCROW:v1".as_slice(), hold_id].concat()
}

pub struct IdentityEvidence<'a> {
    pub presentation: &'a KybPresentation,
    pub registry: &'a SignedCohortRegistry,
    pub trusted_issuer: &'a VerifyingKey,
    pub scope: &'a [u8],
    pub context: &'a [u8],
    pub required_cohort: &'a str,
}

/// Complete private evidence for one member of an atomic threshold-DvP batch.
/// The references are consumed only for verification; DeFMI persists no KYB
/// presentation, mandate, amount opening, or proof witness.
pub struct ThresholdProductSettlement<'a> {
    pub order: &'a ProductSettlementOrder,
    pub relation_proofs: &'a [CreditFacilityRelationProof],
    pub typed_instruction: &'a TypedInstruction,
    pub asset_link: &'a AssetLinkProof,
    pub dvp_package: &'a ThresholdDvpPackage,
    pub price_limit_proof: &'a PriceLimitProof,
    pub maker_mandate: &'a MakerPolicyMandate,
    pub maker_identity: &'a IdentityEvidence<'a>,
    pub taker_mandate: &'a TakerExecutionMandate,
    pub taker_identity: &'a IdentityEvidence<'a>,
}

fn direction(value: qomm_transport::mandate::Direction) -> u8 {
    value as u8
}

#[allow(clippy::too_many_arguments)]
pub fn reserve_maker(
    facility: &DefmiFacility,
    transition: &CreditFacilityTransition,
    relation_proof: &CreditFacilityRelationProof,
    authorization: &ReservationAuthorization,
    escrow: &ReservationEscrow,
    escrow_proof: &ReservationEscrowProof,
    typed_instruction: &TypedInstruction,
    typed_venue: &Venue,
    asset_link: &AssetLinkProof,
    mandate: &MakerPolicyMandate,
    identity: &IdentityEvidence<'_>,
    approval: &QuorumApproval,
    now: u64,
) -> Result<CreditFacilitySnapshot, String> {
    verify_maker_reservation(
        transition,
        authorization,
        typed_instruction,
        mandate,
        identity,
        now,
    )?;
    verify_reservation_escrow(
        facility,
        transition,
        authorization,
        escrow,
        escrow_proof,
        typed_instruction,
        typed_venue,
    )?;
    facility.reserve_for_authorization(ReservationExecution {
        transition,
        relation_proof,
        authorization,
        escrow,
        typed_instruction,
        typed_venue,
        asset_link,
        ordered_admission: None,
        approval,
        now,
    })
}

pub fn verify_maker_reservation(
    transition: &CreditFacilityTransition,
    authorization: &ReservationAuthorization,
    typed_instruction: &TypedInstruction,
    mandate: &MakerPolicyMandate,
    identity: &IdentityEvidence<'_>,
    now: u64,
) -> Result<(), String> {
    mandate.verify(
        identity.presentation,
        identity.registry,
        identity.trusted_issuer,
        identity.scope,
        identity.context,
        identity.required_cohort,
        now,
    )?;
    let mandate_digest = mandate.digest()?;
    if authorization.role != ReservationRole::Maker
        || authorization.entity_commitment != mandate.entity_commitment
        || authorization.asset_id != mandate.asset_id
        || authorization.direction != direction(mandate.direction)
        || authorization.authorization_digest != mandate.policy_digest
        || authorization.mandate_digest != mandate_digest
        || authorization.policy_version != mandate.policy_version
        || authorization.rfq_nullifier != crate::facility::ZERO
        || authorization.admission_epoch != 0
        || authorization.admission_sequence != 0
        || transition.hold_id != mandate.reserve_id
        || transition.amount_commitment != mandate.maximum_amount_commitment
        || typed_instruction.context.venue_id != mandate.venue_id
        || typed_instruction.context.defmi_id != mandate.defmi_id
        || typed_instruction.context.maker_handle.compress().to_bytes() != mandate.maker_handle
    {
        return Err("Maker reserve differs from its signed policy mandate".into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn reserve_taker(
    facility: &DefmiFacility,
    transition: &CreditFacilityTransition,
    relation_proof: &CreditFacilityRelationProof,
    authorization: &ReservationAuthorization,
    escrow: &ReservationEscrow,
    escrow_proof: &ReservationEscrowProof,
    typed_instruction: &TypedInstruction,
    typed_venue: &Venue,
    asset_link: &AssetLinkProof,
    ordered_admission: &OrderedAdmission,
    mandate: &TakerExecutionMandate,
    identity: &IdentityEvidence<'_>,
    approval: &QuorumApproval,
    now: u64,
) -> Result<CreditFacilitySnapshot, String> {
    verify_taker_reservation(
        transition,
        authorization,
        typed_instruction,
        mandate,
        ordered_admission,
        identity,
        now,
    )?;
    verify_reservation_escrow(
        facility,
        transition,
        authorization,
        escrow,
        escrow_proof,
        typed_instruction,
        typed_venue,
    )?;
    facility.reserve_for_authorization(ReservationExecution {
        transition,
        relation_proof,
        authorization,
        escrow,
        typed_instruction,
        typed_venue,
        asset_link,
        ordered_admission: Some(ordered_admission),
        approval,
        now,
    })
}

pub(crate) fn verify_reservation_escrow(
    facility: &DefmiFacility,
    transition: &CreditFacilityTransition,
    authorization: &ReservationAuthorization,
    escrow: &ReservationEscrow,
    proof: &ReservationEscrowProof,
    typed_instruction: &TypedInstruction,
    typed_venue: &Venue,
) -> Result<(), String> {
    let rail = match facility.asset_kind(&authorization.asset_id)? {
        AssetKind::Cash => CASH_RAIL,
        AssetKind::Security
        | AssetKind::Fund
        | AssetKind::Commodity
        | AssetKind::Carbon
        | AssetKind::Other => SECURITIES_RAIL,
    };
    let expected_source: [u8; 32] = account_of(&typed_instruction.payment.payer_handle, rail)
        .try_into()
        .map_err(|_| "derived reserve source handle is not 32 bytes".to_string())?;
    let expected_escrow: [u8; 32] = account_of(&typed_instruction.payment.payee_handle, rail)
        .try_into()
        .map_err(|_| "derived reserve escrow handle is not 32 bytes".to_string())?;
    if escrow.source_handle != expected_source
        || escrow.escrow_handle != expected_escrow
        || escrow.asset_id != authorization.asset_id
        || escrow.amount_commitment != transition.amount_commitment
        || escrow.proof_digest != proof.digest()
        || authorization.escrow_digest != escrow.statement()?
        || proof.transfer.tag.is_some()
        || proof.transfer.amount_commitment.compress().to_bytes() != escrow.amount_commitment
        || proof.transfer.remainder_commitment.compress().to_bytes()
            != escrow.source_after_commitment
    {
        return Err("asset escrow does not match the signed reserve zkPI".into());
    }
    let source_before = CompressedRistretto(escrow.source_before_commitment)
        .decompress()
        .ok_or_else(|| "reservation source commitment is not canonical".to_string())?;
    let mut ledger = Ledger::new(typed_venue.key.clone(), typed_venue.amount_ranges.bits);
    ledger.open(&escrow.source_handle, source_before);
    ledger
        .check_transfer(
            &escrow.source_handle,
            &proof.transfer,
            &escrow_transfer_context(&transition.hold_id),
            true,
        )
        .map_err(|error| format!("reserve asset proof failed: {error}"))
}

pub fn verify_taker_reservation(
    transition: &CreditFacilityTransition,
    authorization: &ReservationAuthorization,
    typed_instruction: &TypedInstruction,
    mandate: &TakerExecutionMandate,
    ordered_admission: &OrderedAdmission,
    identity: &IdentityEvidence<'_>,
    now: u64,
) -> Result<(), String> {
    mandate.verify(
        identity.presentation,
        identity.registry,
        identity.trusted_issuer,
        identity.scope,
        identity.context,
        identity.required_cohort,
        now,
    )?;
    let mandate_digest = mandate.digest()?;
    if ordered_admission.certified_digest()? != authorization.admission_receipt_digest
        || ordered_admission.venue_id != mandate.venue_id
        || ordered_admission.ticket_id != mandate.admission_ticket_id
        || ordered_admission.slot != mandate.admission_slot
        || ordered_admission.rfq_nullifier != mandate.rfq_nullifier
        || ordered_admission.taker_entity_commitment != mandate.entity_commitment
        || ordered_admission.taker_mandate_digest != mandate_digest
        || ordered_admission.expires_at != mandate.deadline
    {
        return Err("ordered admission does not bind the pre-submission Taker mandate".into());
    }
    if authorization.role != ReservationRole::Taker
        || authorization.entity_commitment != mandate.entity_commitment
        || authorization.asset_id != mandate.reserve_asset_id
        || authorization.direction != direction(mandate.direction)
        || authorization.authorization_digest != mandate_digest
        || authorization.mandate_digest != mandate_digest
        || authorization.policy_version != 0
        || authorization.rfq_nullifier != mandate.rfq_nullifier
        || authorization.admission_ticket_id != mandate.admission_ticket_id
        || authorization.admission_slot != mandate.admission_slot
        || authorization.admission_epoch != ordered_admission.epoch
        || authorization.admission_sequence != ordered_admission.sequence
        || transition.hold_id != mandate.reserve_id
        || transition.amount_commitment != mandate.maximum_amount_commitment
        || transition.expires_at != mandate.deadline
        || typed_instruction.context.venue_id != mandate.venue_id
        || typed_instruction.context.defmi_id != mandate.defmi_id
        || typed_instruction.context.taker_handle.compress().to_bytes() != mandate.taker_handle
    {
        return Err("Taker reserve differs from its signed execution mandate".into());
    }
    Ok(())
}

/// Verify every product-level binding that must precede an anonymous note
/// reservation. The actual one-out-of-many spend is verified when
/// `NoteReservationEscrow::from_verified` creates `escrow`; this function
/// binds that verified projection to the signed mandate, ordered RFQ slot,
/// credit-facility hold, typed zkPI and hidden asset proof before a governance
/// quorum may authorize the Avalanche transition.
#[allow(clippy::too_many_arguments)]
pub fn verify_note_reservation(
    transition: &CreditFacilityTransition,
    relation_proof: &CreditFacilityRelationProof,
    authorization: &ReservationAuthorization,
    escrow: &NoteReservationEscrow,
    typed_instruction: &TypedInstruction,
    typed_venue: &Venue,
    asset_link: &AssetLinkProof,
    ordered_admission: Option<&OrderedAdmission>,
    now: u64,
) -> Result<(), String> {
    transition.body()?;
    relation_proof.verify(transition)?;
    if escrow.statement(transition, authorization)? != authorization.escrow_digest {
        return Err("anonymous escrow differs from its signed reservation".into());
    }
    typed_venue
        .verify_typed(typed_instruction, now)
        .map_err(|error| format!("reserve zkPI failed: {error}"))?;

    let context = &typed_instruction.context;
    let expected_scope = match authorization.role {
        ReservationRole::Maker => qomm_zkpi::typed::AuthorizationScope::Maker,
        ReservationRole::Taker => qomm_zkpi::typed::AuthorizationScope::Taker,
    };
    match (authorization.role, ordered_admission) {
        (ReservationRole::Maker, None) => {}
        (ReservationRole::Taker, Some(admission))
            if admission.certified_digest()? == authorization.admission_receipt_digest
                && admission.venue_id == context.venue_id
                && admission.ticket_id == authorization.admission_ticket_id
                && admission.slot == authorization.admission_slot
                && admission.epoch == authorization.admission_epoch
                && admission.sequence == authorization.admission_sequence
                && admission.rfq_nullifier == authorization.rfq_nullifier
                && admission.taker_entity_commitment == authorization.entity_commitment
                && admission.taker_mandate_digest == authorization.mandate_digest
                && admission.expires_at == transition.expires_at => {}
        (ReservationRole::Maker, Some(_)) => {
            return Err("Maker policy reserve must not carry an RFQ admission receipt".into())
        }
        (ReservationRole::Taker, _) => {
            return Err("Taker reserve lacks its exact ordered admission receipt".into())
        }
    }

    let (reservation_id, reservation_sequence) = match authorization.role {
        ReservationRole::Maker => (
            context.maker_reservation_id,
            context.maker_reservation_sequence,
        ),
        ReservationRole::Taker => (
            context.taker_reservation_id,
            context.taker_reservation_sequence,
        ),
    };
    if context.operation != qomm_zkpi::typed::OperationKind::Reserve
        || context.scope != expected_scope
        || context.direction as u8 != authorization.direction
        || context.reserve_handle != reserve_handle_for(&transition.facility_id)
        || reservation_id != transition.hold_id
        || reservation_sequence != transition.before_sequence
        || typed_instruction
            .payment
            .amount_commitment
            .compress()
            .to_bytes()
            != transition.amount_commitment
        || typed_instruction.payment.deadline != transition.expires_at
    {
        return Err("reserve zkPI does not describe this anonymous facility hold".into());
    }
    match authorization.role {
        ReservationRole::Maker
            if context.maker_policy_digest != authorization.authorization_digest
                || context.maker_mandate_digest != authorization.mandate_digest =>
        {
            return Err("Maker reserve zkPI is bound to another policy mandate".into());
        }
        ReservationRole::Taker
            if authorization.authorization_digest != authorization.mandate_digest
                || context.taker_mandate_digest != authorization.mandate_digest =>
        {
            return Err("Taker reserve zkPI is bound to another execution mandate".into());
        }
        _ => {}
    }

    let typed_digest: [u8; 32] =
        Sha256::digest(qomm_zkpi::typed_wire::encode(typed_instruction)).into();
    if typed_digest != authorization.typed_reserve_digest
        || typed_instruction.payment.nullifier() != authorization.reserve_nullifier
        || !crate::asset_link::verify(
            &typed_venue.key,
            &authorization.asset_id,
            &typed_instruction.payment.asset_commitment,
            asset_link,
        )
        || asset_link.digest(
            &authorization.asset_id,
            &typed_instruction.payment.asset_commitment,
        ) != authorization.asset_link_proof_digest
    {
        return Err("reserve zkPI digest, nullifier, or hidden asset link is invalid".into());
    }
    Ok(())
}

/// Return an expired Maker or Taker reservation to its original spendable
/// account. The credit hold, asset escrow, payment nullifier, account sequence,
/// state root, and receipt are committed in one database transaction.
#[allow(clippy::too_many_arguments)]
pub fn release_reservation(
    facility: &DefmiFacility,
    order: &ProductReleaseOrder,
    relation_proof: &CreditFacilityRelationProof,
    typed_instruction: &TypedInstruction,
    typed_venue: &Venue,
    asset_link: &AssetLinkProof,
    approval: &QuorumApproval,
    now: u64,
) -> Result<SettlementReceipt, String> {
    facility.release_product_reservation(
        order,
        relation_proof,
        typed_instruction,
        typed_venue,
        asset_link,
        approval,
        now,
    )
}

/// Execute a fully pre-authorized QOMM trade.  This is deliberately the only
/// public product-settlement entry point: the durable state machine cannot be
/// reached with digest-shaped placeholders instead of the signed Maker/Taker
/// mandates and their live legal-entity presentations.
#[allow(clippy::too_many_arguments)]
pub fn settle_product<R: RngCore + CryptoRng>(
    facility: &DefmiFacility,
    order: &ProductSettlementOrder,
    relation_proofs: &[CreditFacilityRelationProof],
    typed_instruction: &TypedInstruction,
    typed_venue: &Venue,
    asset_link: &AssetLinkProof,
    dvp_package: &DvpPackage,
    price_limit_proof: &PriceLimitProof,
    maker_mandate: &MakerPolicyMandate,
    maker_identity: &IdentityEvidence<'_>,
    taker_mandate: &TakerExecutionMandate,
    taker_identity: &IdentityEvidence<'_>,
    approval: &QuorumApproval,
    now: u64,
    rng: &mut R,
) -> Result<SettlementReceipt, String> {
    verify_settlement_authority(
        order,
        typed_instruction,
        typed_venue,
        price_limit_proof,
        maker_mandate,
        maker_identity,
        taker_mandate,
        taker_identity,
        now,
    )?;
    facility.settle_product(
        order,
        relation_proofs,
        typed_instruction,
        typed_venue,
        asset_link,
        dvp_package,
        approval,
        now,
        rng,
    )
}

/// Production settlement path: all DvP evidence is assembled from node-local
/// MPC shares. No coordinator receives the Maker/Taker reserve openings,
/// quantity, price, cash amount, or any of their Pedersen blindings.
#[allow(clippy::too_many_arguments)]
pub fn settle_product_threshold<R: RngCore + CryptoRng>(
    facility: &DefmiFacility,
    order: &ProductSettlementOrder,
    relation_proofs: &[CreditFacilityRelationProof],
    typed_instruction: &TypedInstruction,
    typed_venue: &Venue,
    asset_link: &AssetLinkProof,
    dvp_package: &ThresholdDvpPackage,
    price_limit_proof: &PriceLimitProof,
    maker_mandate: &MakerPolicyMandate,
    maker_identity: &IdentityEvidence<'_>,
    taker_mandate: &TakerExecutionMandate,
    taker_identity: &IdentityEvidence<'_>,
    approval: &QuorumApproval,
    now: u64,
    rng: &mut R,
) -> Result<SettlementReceipt, String> {
    verify_settlement_authority(
        order,
        typed_instruction,
        typed_venue,
        price_limit_proof,
        maker_mandate,
        maker_identity,
        taker_mandate,
        taker_identity,
        now,
    )?;
    facility.settle_product_threshold(
        order,
        relation_proofs,
        typed_instruction,
        typed_venue,
        asset_link,
        dvp_package,
        approval,
        now,
        rng,
    )
}

/// Verify and atomically settle all simultaneous RFQs that survived the
/// certified admission and legal-entity-cap stage. Members must be supplied in
/// strictly increasing admission sequence and must not share any mutable
/// facility, hold, account, operation identifier, or nullifier.
pub fn settle_product_threshold_batch<R: RngCore + CryptoRng>(
    facility: &DefmiFacility,
    batch: &ProductSettlementBatch,
    items: &[ThresholdProductSettlement<'_>],
    typed_venue: &Venue,
    approval: &QuorumApproval,
    now: u64,
    rng: &mut R,
) -> Result<Vec<SettlementReceipt>, String> {
    if items.is_empty() {
        return Err("product settlement batch cannot be empty".into());
    }
    let orders = items
        .iter()
        .map(|item| item.order.clone())
        .collect::<Vec<_>>();
    batch.validate_orders(&orders)?;
    let root = facility.state_root()?;
    let statement = batch.statement()?;
    if root != approval.before_root || !facility.authorizer.verify(&statement, &root, approval) {
        return Err("product settlement batch lacks approval for the current DeFMI state".into());
    }
    for item in items {
        verify_settlement_authority(
            item.order,
            item.typed_instruction,
            typed_venue,
            item.price_limit_proof,
            item.maker_mandate,
            item.maker_identity,
            item.taker_mandate,
            item.taker_identity,
            now,
        )?;
        facility.preflight_product_threshold_for_batch(
            item.order,
            item.relation_proofs,
            item.typed_instruction,
            typed_venue,
            item.asset_link,
            item.dvp_package,
            root,
            now,
            rng,
        )?;
    }
    facility.settle_product_threshold_batch(batch, &orders, approval, now)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_settlement_authority(
    order: &ProductSettlementOrder,
    typed_instruction: &TypedInstruction,
    typed_venue: &Venue,
    price_limit_proof: &PriceLimitProof,
    maker_mandate: &MakerPolicyMandate,
    maker_identity: &IdentityEvidence<'_>,
    taker_mandate: &TakerExecutionMandate,
    taker_identity: &IdentityEvidence<'_>,
    now: u64,
) -> Result<(), String> {
    if !typed_instruction.payment.ranges.is_threshold()
        || typed_instruction.payment.quote_proof_digest() != Some(order.quote_proof_digest)
    {
        return Err(
            "product settlement requires an MPC-produced zkPI bound to this quote proof".into(),
        );
    }
    maker_mandate.verify(
        maker_identity.presentation,
        maker_identity.registry,
        maker_identity.trusted_issuer,
        maker_identity.scope,
        maker_identity.context,
        maker_identity.required_cohort,
        now,
    )?;
    taker_mandate.verify(
        taker_identity.presentation,
        taker_identity.registry,
        taker_identity.trusted_issuer,
        taker_identity.scope,
        taker_identity.context,
        taker_identity.required_cohort,
        now,
    )?;
    let maker_digest = maker_mandate.digest()?;
    let taker_digest = taker_mandate.digest()?;
    let limit_price =
        curve25519_dalek::ristretto::CompressedRistretto(taker_mandate.limit_price_commitment)
            .decompress()
            .ok_or_else(|| "Taker limit price is not a canonical commitment".to_string())?;
    let price_direction = match taker_mandate.direction {
        qomm_transport::mandate::Direction::TakerBuys => PriceLimitDirection::MaximumBuyPrice,
        qomm_transport::mandate::Direction::TakerSells => PriceLimitDirection::MinimumSellPrice,
    };
    verify_price_limit(
        &typed_venue.key,
        &typed_instruction.payment.price_commitment,
        &limit_price,
        price_direction,
        typed_venue.price_ranges.bits,
        &taker_digest,
        price_limit_proof,
    )?;
    if price_limit_proof.digest(
        &typed_instruction.payment.price_commitment,
        &limit_price,
        &taker_digest,
    ) != order.price_limit_proof_digest
    {
        return Err("price limit proof differs from the committee-approved digest".into());
    }
    let context = &typed_instruction.context;
    let maker_reservation = order
        .reservations
        .iter()
        .find(|reservation| reservation.role == ReservationRole::Maker)
        .ok_or_else(|| "Maker reservation is missing".to_string())?;
    let taker_reservation = order
        .reservations
        .iter()
        .find(|reservation| reservation.role == ReservationRole::Taker)
        .ok_or_else(|| "Taker reservation is missing".to_string())?;
    if order.venue_id != maker_mandate.venue_id
        || order.venue_id != taker_mandate.venue_id
        || order.defmi_id != maker_mandate.defmi_id
        || order.defmi_id != taker_mandate.defmi_id
        || order.maker_entity_commitment != maker_mandate.entity_commitment
        || order.taker_entity_commitment != taker_mandate.entity_commitment
        || order.maker_policy_digest != maker_mandate.policy_digest
        || order.maker_mandate_digest != maker_digest
        || order.taker_mandate_digest != taker_digest
        || order.taker_authorization_digest != taker_digest
        || order.rfq_nullifier != taker_mandate.rfq_nullifier
        || order.traded_asset_id != taker_mandate.asset_id
        || direction(maker_mandate.direction) != context.direction as u8
        || direction(taker_mandate.direction) != context.direction as u8
        || maker_mandate.direction != taker_mandate.direction
        || maker_mandate.maker_handle != context.maker_handle.compress().to_bytes()
        || taker_mandate.taker_handle != context.taker_handle.compress().to_bytes()
        || maker_mandate.reserve_id != maker_reservation.transition.hold_id
        || taker_mandate.reserve_id != taker_reservation.transition.hold_id
        || taker_mandate.quantity_commitment
            != typed_instruction
                .payment
                .amount_commitment
                .compress()
                .to_bytes()
        || typed_instruction.payment.deadline > taker_mandate.deadline
        || taker_mandate.allow_partial
    {
        return Err("settlement differs from the signed Maker/Taker mandates".into());
    }
    Ok(())
}

/// Product/identity/limit-policy checks for the account-free delegated-note
/// settlement path. Cryptographic DvP and covenant projection are verified by
/// `VerifiedDelegatedNoteSettlementProjection`; this function supplies the
/// same signed Maker/Taker authority boundary as the account rail.
#[allow(clippy::too_many_arguments)]
pub fn verify_note_settlement_authority(
    order: &ProductNoteSettlementOrder,
    typed_instruction: &TypedInstruction,
    typed_venue: &Venue,
    price_limit_proof: &PriceLimitProof,
    maker_mandate: &MakerPolicyMandate,
    maker_identity: &IdentityEvidence<'_>,
    taker_mandate: &TakerExecutionMandate,
    taker_identity: &IdentityEvidence<'_>,
    now: u64,
) -> Result<(), String> {
    if !typed_instruction.payment.ranges.is_threshold()
        || typed_instruction.payment.quote_proof_digest() != Some(order.quote_proof_digest)
    {
        return Err(
            "anonymous product settlement requires an MPC-produced zkPI bound to this quote proof"
                .into(),
        );
    }
    maker_mandate.verify(
        maker_identity.presentation,
        maker_identity.registry,
        maker_identity.trusted_issuer,
        maker_identity.scope,
        maker_identity.context,
        maker_identity.required_cohort,
        now,
    )?;
    taker_mandate.verify(
        taker_identity.presentation,
        taker_identity.registry,
        taker_identity.trusted_issuer,
        taker_identity.scope,
        taker_identity.context,
        taker_identity.required_cohort,
        now,
    )?;
    let maker_digest = maker_mandate.digest()?;
    let taker_digest = taker_mandate.digest()?;
    let limit_price =
        curve25519_dalek::ristretto::CompressedRistretto(taker_mandate.limit_price_commitment)
            .decompress()
            .ok_or_else(|| "Taker limit price is not a canonical commitment".to_string())?;
    let price_direction = match taker_mandate.direction {
        qomm_transport::mandate::Direction::TakerBuys => PriceLimitDirection::MaximumBuyPrice,
        qomm_transport::mandate::Direction::TakerSells => PriceLimitDirection::MinimumSellPrice,
    };
    verify_price_limit(
        &typed_venue.key,
        &typed_instruction.payment.price_commitment,
        &limit_price,
        price_direction,
        typed_venue.price_ranges.bits,
        &taker_digest,
        price_limit_proof,
    )?;
    if price_limit_proof.digest(
        &typed_instruction.payment.price_commitment,
        &limit_price,
        &taker_digest,
    ) != order.price_limit_proof_digest
    {
        return Err("price limit proof differs from the committee-approved digest".into());
    }
    let context = &typed_instruction.context;
    let maker_reservation = order
        .reservations
        .iter()
        .find(|reservation| reservation.role == ReservationRole::Maker)
        .ok_or_else(|| "Maker reservation is missing".to_string())?;
    let taker_reservation = order
        .reservations
        .iter()
        .find(|reservation| reservation.role == ReservationRole::Taker)
        .ok_or_else(|| "Taker reservation is missing".to_string())?;
    if order.venue_id != maker_mandate.venue_id
        || order.venue_id != taker_mandate.venue_id
        || order.defmi_id != maker_mandate.defmi_id
        || order.defmi_id != taker_mandate.defmi_id
        || order.maker_entity_commitment != maker_mandate.entity_commitment
        || order.taker_entity_commitment != taker_mandate.entity_commitment
        || order.maker_policy_digest != maker_mandate.policy_digest
        || order.maker_mandate_digest != maker_digest
        || order.taker_mandate_digest != taker_digest
        || order.taker_authorization_digest != taker_digest
        || order.rfq_nullifier != taker_mandate.rfq_nullifier
        || order.traded_asset_id != taker_mandate.asset_id
        || direction(maker_mandate.direction) != context.direction as u8
        || direction(taker_mandate.direction) != context.direction as u8
        || maker_mandate.direction != taker_mandate.direction
        || maker_mandate.maker_handle != context.maker_handle.compress().to_bytes()
        || taker_mandate.taker_handle != context.taker_handle.compress().to_bytes()
        || maker_mandate.reserve_id != maker_reservation.transition.hold_id
        || taker_mandate.reserve_id != taker_reservation.transition.hold_id
        || taker_mandate.quantity_commitment
            != typed_instruction
                .payment
                .amount_commitment
                .compress()
                .to_bytes()
        || typed_instruction.payment.deadline > taker_mandate.deadline
        || taker_mandate.allow_partial
    {
        return Err("anonymous settlement differs from the signed Maker/Taker mandates".into());
    }
    Ok(())
}
