//! Canonical partial fills and non-discretionary reservation release.

use super::*;
use qomm_defmi::application_settlement::{
    application_claim, point, ApplicationNoteFill, ApplicationNoteFillBatch, ApplicationNoteRelease,
};
use qomm_defmi::note_chain::NoteClaimKind;

fn consume_covenant(
    state: &mut State,
    record: &crate::state::ApplicationReservationRecord,
    statement: [u8; 32],
) -> Result<(), String> {
    let serial = escrow_claim_serial(record.escrow_note_id, record.binding.hold_id);
    let key = id_key(&serial);
    if record.sequence == 0 {
        if state.note_serials.contains_key(&key) {
            return Err("application covenant was already consumed".into());
        }
        state.note_serials.insert(
            key,
            NoteSerialRecord {
                deadline: record.binding.valid_until,
                asset_id: record.binding.asset_id,
                ring_root: record.escrow_note_id,
                statement,
            },
        );
    } else if !state.note_serials.contains_key(&key) {
        return Err("application remainder lost its consumed covenant".into());
    }
    Ok(())
}

fn insert_claim(
    state: &mut State,
    claim: &qomm_defmi::note_chain::NoteClaim,
    statement: [u8; 32],
) -> Result<(), String> {
    claim.validate()?;
    let key = id_key(&claim.claim_id);
    if state.note_claims.contains_key(&key) {
        return Err("application claim already exists".into());
    }
    state.note_claims.insert(
        key,
        NoteClaimRecord {
            asset_id: claim.asset_id,
            value_commitment: claim.value_commitment,
            recipient_commitment: claim.recipient_commitment,
            source_hold_id: claim.source_hold_id,
            kind: claim.kind.as_str().into(),
            opening_envelope: OpeningEnvelopeRecord::from_domain(&claim.opening_envelope)?,
            status: "active".into(),
            settlement_digest: statement,
            materialization: ZERO,
        },
    );
    Ok(())
}

pub(super) fn fill(
    state: &mut State,
    params: &Map<String, Value>,
    now: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["fill"])?;
    let order: ApplicationNoteFill = field(params, "fill")?;
    if order.batch.is_some() {
        return Err("a signed batch member cannot settle individually".into());
    }
    apply_fill(state, &order, state.root(), now)
}

pub(super) fn fill_batch(
    state: &mut State,
    params: &Map<String, Value>,
    now: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["batch"])?;
    let batch: ApplicationNoteFillBatch = field(params, "batch")?;
    let statement = batch.statement()?;
    let parent = state.root();
    if batch.before_root()? != parent {
        return Err("application batch has a stale parent".into());
    }
    let mut candidate = state.clone();
    for fill in &batch.fills {
        apply_fill(&mut candidate, fill, parent, now)?;
    }
    // No member, claim, nullifier, hold or facility mutation survives a failure.
    *state = candidate;
    Ok(statement)
}

fn apply_fill(
    state: &mut State,
    order: &ApplicationNoteFill,
    expected_parent: [u8; 32],
    now: u64,
) -> Result<[u8; 32], String> {
    if order.before_root != expected_parent
        || state.operations.contains_key(&id_key(&order.operation_id))
    {
        return Err("application fill has a stale parent or reused operation".into());
    }
    let scope = state
        .application_reserve_scopes
        .get(&id_key(&order.scope.key()?))
        .ok_or_else(|| "application fill scope is not registered".to_string())?;
    let heads = [&order.securities, &order.cash];
    let assets = [order.securities_asset, order.cash_asset];
    let mut records = Vec::new();
    for index in 0..2 {
        let head = heads[index];
        let record = state
            .application_reservations
            .get(&id_key(&head.hold_id))
            .cloned()
            .ok_or_else(|| "application fill has no canonical reservation".to_string())?;
        if record.binding.scope != *scope
            || record.binding.asset_id != assets[index]
            || record.status != "active"
            || record.sequence != head.sequence
            || record.head_receipt() != head.previous_receipt
            || record.remaining() != head.remaining_commitment
            || now < record.binding.valid_from
            || now > record.binding.valid_until
        {
            return Err("application fill differs from its current reservation head".into());
        }
        records.push(record);
    }
    // Verifies the pre-authorized committee certificate, zkPI signature,
    // asset link, threshold amount/price ranges, product and both remainders.
    let verified = order.verify(scope, now)?;
    if state.nullifiers.contains_key(&id_key(&verified.nullifier)) {
        return Err("application zkPI was already settled".into());
    }
    for (index, mut record) in records.into_iter().enumerate() {
        let head = heads[index];
        let hold_key = id_key(&head.hold_id);
        let before = point(record.remaining())?;
        let consumed = point(verified.consumed[index])?;
        let remainder = point(verified.remaining[index])?;
        if before != consumed + remainder {
            return Err("application fill changes the canonical reserved amount".into());
        }
        let mut hold = state
            .credit_holds
            .get(&hold_key)
            .cloned()
            .ok_or_else(|| "application fill credit hold is absent".to_string())?;
        if hold.status != "active"
            || hold.amount_commitment != record.remaining()
            || hold.facility_id != record.binding.facility_id
        {
            return Err("application fill credit hold differs from its head".into());
        }
        let facility = state
            .credit_facilities
            .get_mut(&id_key(&record.binding.facility_id))
            .ok_or_else(|| "application fill facility is absent".to_string())?;
        if facility.status != "active"
            || facility.beneficiary_commitment != record.binding.entity_commitment
            || facility.rail_asset_id != assets[index]
        {
            return Err("application fill facility is not eligible".into());
        }
        // Each non-negative remainder belongs to an already-proved component
        // of held capacity. Removing only that component preserves the prior
        // aggregate solvency invariant without reopening facility balances.
        facility.held_commitment = (point(facility.held_commitment)?
            - if head.close { before } else { consumed })
        .compress()
        .to_bytes();
        facility.outstanding_commitment = (point(facility.outstanding_commitment)? + consumed)
            .compress()
            .to_bytes();
        if head.close {
            facility.available_commitment = (point(facility.available_commitment)? + remainder)
                .compress()
                .to_bytes();
        }
        facility.sequence = facility
            .sequence
            .checked_add(1)
            .ok_or_else(|| "application facility sequence overflow".to_string())?;
        hold.updated_sequence = facility.sequence;
        hold.amount_commitment = verified.remaining[index];
        if head.close {
            hold.status = "consumed".into();
            hold.settlement_digest = verified.statement;
        }
        consume_covenant(state, &record, verified.statement)?;
        record.remaining_commitment = Some(verified.remaining[index]);
        record.sequence = record
            .sequence
            .checked_add(1)
            .ok_or_else(|| "application reserve sequence overflow".to_string())?;
        record.last_receipt = Some(verified.statement);
        record.remaining_opening =
            (!head.close).then(|| verified.normalized_openings[index].clone());
        if head.close {
            record.status = "consumed".into();
            record.settlement_digest = verified.statement;
        }
        state.credit_holds.insert(hold_key.clone(), hold);
        state.application_reservations.insert(hold_key, record);
    }
    for claim in &verified.claims {
        insert_claim(state, claim, verified.statement)?;
    }
    state.nullifiers.insert(
        id_key(&verified.nullifier),
        NullifierRecord {
            deadline: verified.deadline,
            statement: verified.statement,
        },
    );
    state
        .operations
        .insert(id_key(&order.operation_id), verified.statement);
    Ok(verified.statement)
}

pub(super) fn release(
    state: &mut State,
    params: &Map<String, Value>,
    now: u64,
) -> Result<[u8; 32], String> {
    require_keys(params, &["release"])?;
    let order: ApplicationNoteRelease = field(params, "release")?;
    if order.before_root != state.root()
        || state.operations.contains_key(&id_key(&order.operation_id))
    {
        return Err("application release has a stale parent or reused operation".into());
    }
    let hold_key = id_key(&order.hold_id);
    let mut record = state
        .application_reservations
        .get(&hold_key)
        .cloned()
        .ok_or_else(|| "application release has no reservation".to_string())?;
    if record.status != "active"
        || record.sequence != order.sequence
        || record.head_receipt() != order.previous_receipt
    {
        return Err("application release lost the race with another fill or cancellation".into());
    }
    let statement = order.verify(&record.binding.scope, record.binding.valid_until, now)?;
    let mut hold = state
        .credit_holds
        .get(&hold_key)
        .cloned()
        .ok_or_else(|| "application release hold is absent".to_string())?;
    if hold.status != "active"
        || hold.amount_commitment != record.remaining()
        || hold.facility_id != record.binding.facility_id
    {
        return Err("application release credit hold differs from its head".into());
    }
    let amount = point(record.remaining())?;
    let facility = state
        .credit_facilities
        .get_mut(&id_key(&record.binding.facility_id))
        .ok_or_else(|| "application release facility is absent".to_string())?;
    // Release remains possible when admission is suspended or a facility has
    // expired: it reduces held exposure and returns only the proven remainder.
    facility.held_commitment = (point(facility.held_commitment)? - amount)
        .compress()
        .to_bytes();
    facility.available_commitment = (point(facility.available_commitment)? + amount)
        .compress()
        .to_bytes();
    facility.sequence = facility
        .sequence
        .checked_add(1)
        .ok_or_else(|| "application facility sequence overflow".to_string())?;
    hold.updated_sequence = facility.sequence;
    if record.sequence == 0 {
        // Before any fill, return the exact note to the recipient chosen by
        // the holder in its original ownership proof; change only the lock.
        let mut output = state
            .notes
            .get(&id_key(&record.escrow_note_id))
            .ok_or_else(|| "application refund note is absent".to_string())?
            .output(record.escrow_note_id);
        output.lock_id = ZERO;
        output.note_id = output.derived_id()?;
        insert_note(state, &output)?;
    } else {
        let opening = record
            .remaining_opening
            .as_ref()
            .ok_or_else(|| "application remainder recovery data is absent".to_string())?;
        let claim = application_claim(
            record.binding.asset_id,
            order.hold_id,
            record.remaining(),
            order.operation_id,
            NoteClaimKind::Refund,
            opening,
        )?;
        insert_claim(state, &claim, statement)?;
    }
    consume_covenant(state, &record, statement)?;
    hold.status = "released".into();
    hold.settlement_digest = ZERO;
    record.status = "released".into();
    record.remaining_commitment = Some(record.remaining());
    record.remaining_opening = None;
    record.sequence = record
        .sequence
        .checked_add(1)
        .ok_or_else(|| "application reserve sequence overflow".to_string())?;
    record.last_receipt = Some(statement);
    record.settlement_digest = ZERO;
    state.credit_holds.insert(hold_key.clone(), hold);
    state.application_reservations.insert(hold_key, record);
    state
        .operations
        .insert(id_key(&order.operation_id), statement);
    Ok(statement)
}
