//! Native application reservations, without RFQ/dealer-policy placeholders.

use super::*;
use crate::state::ApplicationReservationRecord;
use defmi::application_reservation::{
    ApplicationNoteReservation, ApplicationReservationBinding, ApplicationReserveScope,
};
use defmi::notes::NoteLedger;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

pub(super) fn register_scope(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
) -> Result<[u8; 32], String> {
    require_keys(params, &["scope", "approval", "expectedBeforeRoot"])?;
    let scope: ApplicationReserveScope = field(params, "scope")?;
    let key = id_key(&scope.key()?);
    let statement = scope.statement()?;
    authorize(state, params, statement, authorizer)?;
    if state.application_reserve_scopes.contains_key(&key) {
        return Err("application reserve scope is already fixed for this epoch".into());
    }
    state.application_reserve_scopes.insert(key, scope);
    Ok(statement)
}

pub(super) fn reserve(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    now: u64,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &[
            "binding",
            "transition",
            "escrow",
            "relationProof",
            "spendProof",
            "approval",
            "expectedBeforeRoot",
        ],
    )?;
    let binding: ApplicationReservationBinding = field(params, "binding")?;
    binding.validate()?;
    if state
        .application_reserve_scopes
        .get(&id_key(&binding.scope.key()?))
        != Some(&binding.scope)
    {
        return Err("application reservation uses an unregistered deployment scope".into());
    }
    if now < binding.valid_from || now > binding.valid_until {
        return Err("application reservation mandate is outside its lifetime".into());
    }
    let transition = credit_transition_from_dto(field(params, "transition")?, "transition")?;
    let dto: NoteReservationEscrowDto = field(params, "escrow")?;
    let escrow = NoteReservationEscrow {
        spend: note_spend_from_dto(dto.spend, "escrow.spend")?,
        escrow_note_id: hex_array(&dto.escrow_note_id, "escrow.escrowNoteID")?,
        delegation_digest: hex_array(&dto.delegation_digest, "escrow.delegationDigest")?,
    };
    let decode_proof = |name: &str| -> Result<Vec<u8>, String> {
        let value: String = field(params, name)?;
        if value.len() > 3 * 1024 * 1024 {
            return Err("application reserve proof is oversized".into());
        }
        BASE64
            .decode(value)
            .map_err(|_| "application reserve proof is not base64".into())
    };
    let reservation = ApplicationNoteReservation {
        binding,
        transition,
        escrow,
        relation_proof: decode_proof("relationProof")?,
        spend_proof: decode_proof("spendProof")?,
    };
    let statement = reservation.statement()?;
    // Approval covers private mandate/KYX checks. Every validator separately
    // checks the two full public proofs and the current canonical resources.
    authorize(state, params, statement, authorizer)?;
    let binding = &reservation.binding;
    let transition = &reservation.transition;
    let hold_key = id_key(&binding.hold_id);
    if state.credit_holds.contains_key(&hold_key)
        || state
            .operations
            .contains_key(&id_key(&transition.operation_id))
        || state.application_reservations.values().any(|record| {
            record.binding.scope == binding.scope
                && record.binding.request_commitment == binding.request_commitment
        })
    {
        return Err("application reservation or request was already used".into());
    }
    let facility_key = id_key(&binding.facility_id);
    let mut facility = state
        .credit_facilities
        .get(&facility_key)
        .cloned()
        .ok_or_else(|| "application reservation names an unknown facility".to_string())?;
    if facility.status != "active"
        || now < facility.valid_from
        || binding.valid_until > facility.valid_until
        || facility.beneficiary_commitment != binding.entity_commitment
        || facility.rail_asset_id != binding.asset_id
        || facility.sequence != transition.before_sequence
        || facility.available_commitment != transition.before_available_commitment
        || facility.held_commitment != transition.before_held_commitment
        || facility.outstanding_commitment != transition.before_outstanding_commitment
    {
        return Err(
            "application reservation differs from the live facility capacity or identity".into(),
        );
    }
    let spend = &reservation.escrow.spend;
    check_note_spend(state, spend, None, true)?;
    let mut ledger = NoteLedger::new(
        Pedersen::new(b"qomm:defmi:v1"),
        usize::from(binding.scope.amount_bits),
    );
    for note_id in &spend.ring {
        let note = state
            .notes
            .get(&id_key(note_id))
            .ok_or_else(|| "application reserve ring note is absent".to_string())?;
        ledger.add(note.output(*note_id).to_note()?);
    }
    let ring: Vec<usize> = (0..spend.ring.len()).collect();
    // Consensus cannot depend on OS randomness. Batch-verification coins are
    // domain-separated from the full signed proof statement and canonical root.
    let seed = Sha256::new()
        .chain_update(b"DEFMI:APPLICATION:RESERVE-VERIFY-COINS:v1")
        .chain_update(statement)
        .chain_update(state.root())
        .finalize()
        .into();
    reservation.verify_public_proofs(
        &ledger,
        &ring,
        &vec![ZERO; ring.len()],
        &mut ChaCha20Rng::from_seed(seed),
    )?;

    facility.available_commitment = transition.after_available_commitment;
    facility.held_commitment = transition.after_held_commitment;
    facility.outstanding_commitment = transition.after_outstanding_commitment;
    facility.sequence = facility
        .sequence
        .checked_add(1)
        .ok_or_else(|| "application reserve sequence overflow".to_string())?;
    state.credit_facilities.insert(facility_key, facility);
    state.credit_holds.insert(
        hold_key.clone(),
        CreditHoldRecord {
            facility_id: binding.facility_id,
            query_commitment: binding.request_commitment,
            amount_commitment: binding.amount_commitment,
            expires_at: binding.valid_until,
            status: "active".into(),
            settlement_digest: ZERO,
            created_sequence: transition.before_sequence + 1,
            updated_sequence: transition.before_sequence + 1,
        },
    );
    apply_note_spend(state, spend, binding.valid_until, statement)?;
    state.application_reservations.insert(
        hold_key,
        ApplicationReservationRecord {
            binding: binding.clone(),
            escrow_note_id: reservation.escrow.escrow_note_id,
            proof_digest: spend.proof_digest,
            receipt_digest: statement,
            status: "active".into(),
            settlement_digest: ZERO,
            remaining_commitment: None,
            sequence: 0,
            last_receipt: None,
            remaining_opening: None,
        },
    );
    state
        .operations
        .insert(id_key(&transition.operation_id), statement);
    Ok(statement)
}
