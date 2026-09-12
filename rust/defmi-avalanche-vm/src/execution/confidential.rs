//! Full asset-confidential proofs on the native consensus execution path.
//! No caller-provided verification flag or asset-to-plaintext mapping is used.

use super::*;
use defmi::application_reservation::{ApplicationNoteReservation, ApplicationReservationBinding};
use defmi::confidential_notes::{
    AssetIdentity, ConfidentialIssuance, ConfidentialReservation, ConfidentialTransfer,
    TransferContext, ValueLink,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn proof_bytes(params: &Map<String, Value>, name: &str, max: usize) -> Result<Vec<u8>, String> {
    let value: String = field(params, name)?;
    if value.len() > max.saturating_mul(2) {
        return Err("confidential proof is oversized".into());
    }
    let bytes = BASE64
        .decode(value)
        .map_err(|_| "confidential proof is not base64")?;
    if bytes.is_empty() || bytes.len() > max {
        return Err("confidential proof dimensions are invalid".into());
    }
    Ok(bytes)
}

fn ensure_identity(
    state: &mut State,
    identity: &AssetIdentity,
    cohort: &[[u8; 32]],
) -> Result<(), String> {
    identity.validate()?;
    if identity.registry.assets != cohort
        || cohort.iter().any(|id| {
            !state
                .assets
                .get(&id_key(id))
                .is_some_and(|asset| asset.active)
        })
        || state.assets.contains_key(&id_key(&identity.commitment))
    {
        return Err("confidential identity is outside the canonical eligible cohort".into());
    }
    let id = id_key(&identity.commitment);
    if let Some(existing) = state.confidential.identities.get(&id) {
        if existing != identity {
            return Err("confidential asset identity cannot be replaced".into());
        }
    } else {
        state.confidential.identities.insert(id, identity.clone());
    }
    Ok(())
}

fn all_assets(state: &State) -> Result<Vec<[u8; 32]>, String> {
    state
        .assets
        .iter()
        .filter(|(_, a)| a.active)
        .map(|(id, _)| hex_array(id, "canonical asset registry"))
        .collect()
}

pub(super) fn register_identity(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
) -> Result<[u8; 32], String> {
    require_keys(params, &["identity", "approval", "expectedBeforeRoot"])?;
    let identity: AssetIdentity = field(params, "identity")?;
    let statement = identity.statement()?;
    authorize(state, params, statement, authorizer)?;
    if state
        .confidential
        .identities
        .contains_key(&id_key(&identity.commitment))
    {
        return Err("confidential identity is already registered".into());
    }
    let cohort = all_assets(state)?;
    ensure_identity(state, &identity, &cohort)?;
    Ok(statement)
}

pub(super) fn issue(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    now: u64,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &[
            "issuance",
            "identity",
            "amountBits",
            "rangeProof",
            "approval",
            "expectedBeforeRoot",
        ],
    )?;
    let order = ConfidentialIssuance {
        issuance: note_issuance_from_dto(field(params, "issuance")?)?,
        identity: field(params, "identity")?,
        amount_bits: field(params, "amountBits")?,
        range_proof: proof_bytes(params, "rangeProof", 8192)?,
    };
    let statement = order.statement()?;
    authorize(state, params, statement, authorizer)?;
    let issuance = &order.issuance;
    if now == 0
        || state
            .operations
            .contains_key(&id_key(&issuance.operation_id))
        || state
            .note_issuances
            .contains_key(&id_key(&issuance.issuance_nonce))
    {
        return Err(
            "confidential issuance reuses an operation/nonce or lacks consensus time".into(),
        );
    }
    let issuer = state
        .csd_issuers
        .get(&id_key(&issuance.issuer_id))
        .ok_or("confidential issuer is absent")?;
    if issuer.status != "active" {
        return Err("confidential issuer is not active".into());
    }
    let issuer = issuer.definition(issuance.issuer_id);
    order.verify(&issuer, now)?;
    ensure_identity(state, &order.identity, &issuer.permitted_asset_ids)?;
    insert_note_with_confidentiality(state, &issuance.output, true)?;
    state
        .note_issuances
        .insert(id_key(&issuance.issuance_nonce), statement);
    state
        .operations
        .insert(id_key(&issuance.operation_id), statement);
    Ok(statement)
}

fn canonical_ring(state: &State, spend: &NoteSpend) -> Result<Vec<NoteOutput>, String> {
    spend.validate()?;
    if spend.input_lock_id != ZERO
        || state
            .note_serials
            .contains_key(&id_key(&spend.serial_point))
    {
        return Err("confidential input is locked or already spent".into());
    }
    if spend
        .outputs
        .iter()
        .any(|n| state.notes.contains_key(&id_key(&n.note_id)))
    {
        return Err("confidential spend reuses an existing output".into());
    }
    spend
        .ring
        .iter()
        .map(|id| {
            let id_string = id_key(id);
            if !state.confidential.notes.contains(&id_string) {
                return Err("confidential ring contains a legacy or absent note".into());
            }
            let record = state
                .notes
                .get(&id_string)
                .ok_or("confidential ring note is absent")?;
            if record.lock_id != ZERO {
                return Err("confidential ring contains a reservation-locked note".into());
            }
            Ok(record.output(*id))
        })
        .collect()
}

fn verification_rng(state: &State, statement: &[u8; 32]) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(
        Sha256::new()
            .chain_update(b"DEFMI:CONFIDENTIAL:VERIFY-COINS:v1")
            .chain_update(state.root())
            .chain_update(statement)
            .finalize()
            .into(),
    )
}

fn apply_spend(
    state: &mut State,
    spend: &NoteSpend,
    deadline: u64,
    statement: [u8; 32],
) -> Result<(), String> {
    apply_note_spend_serial(state, spend, deadline, statement)?;
    for output in &spend.outputs {
        insert_note_with_confidentiality(state, output, true)?;
    }
    Ok(())
}

pub(super) fn transfer(
    state: &mut State,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    now: u64,
) -> Result<[u8; 32], String> {
    require_keys(
        params,
        &[
            "context",
            "identity",
            "spend",
            "spendProof",
            "approval",
            "expectedBeforeRoot",
        ],
    )?;
    let order = ConfidentialTransfer {
        context: field::<TransferContext>(params, "context")?,
        identity: field(params, "identity")?,
        spend: note_spend_from_dto(field(params, "spend")?, "spend")?,
        spend_proof: proof_bytes(params, "spendProof", defmi::confidential_notes::MAX_WIRE)?,
    };
    let statement = order.statement()?;
    authorize(state, params, statement, authorizer)?;
    if order.context.before_root != state.root()
        || now == 0
        || now > order.context.deadline
        || state
            .operations
            .contains_key(&id_key(&order.context.operation_id))
    {
        return Err(
            "confidential transfer has a stale parent, expired deadline or repeated operation"
                .into(),
        );
    }
    let ring = canonical_ring(state, &order.spend)?;
    order.verify(&ring, &mut verification_rng(state, &statement))?;
    let cohort = all_assets(state)?;
    ensure_identity(state, &order.identity, &cohort)?;
    apply_spend(state, &order.spend, order.context.deadline, statement)?;
    state
        .operations
        .insert(id_key(&order.context.operation_id), statement);
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
            "identity",
            "valueLink",
            "approval",
            "expectedBeforeRoot",
        ],
    )?;
    let binding: ApplicationReservationBinding = field(params, "binding")?;
    let dto: NoteReservationEscrowDto = field(params, "escrow")?;
    let order = ConfidentialReservation {
        reservation: ApplicationNoteReservation {
            binding,
            transition: credit_transition_from_dto(field(params, "transition")?, "transition")?,
            escrow: NoteReservationEscrow {
                spend: note_spend_from_dto(dto.spend, "escrow.spend")?,
                escrow_note_id: hex_array(&dto.escrow_note_id, "escrow.escrowNoteID")?,
                delegation_digest: hex_array(&dto.delegation_digest, "escrow.delegationDigest")?,
            },
            relation_proof: proof_bytes(
                params,
                "relationProof",
                defmi::confidential_notes::MAX_WIRE + 16,
            )?,
            spend_proof: proof_bytes(params, "spendProof", defmi::confidential_notes::MAX_WIRE)?,
        },
        identity: field(params, "identity")?,
        value_link: field::<ValueLink>(params, "valueLink")?,
    };
    let statement = order.statement()?;
    authorize(state, params, statement, authorizer)?;
    let r = &order.reservation;
    let binding = &r.binding;
    let transition = &r.transition;
    if state
        .application_reserve_scopes
        .get(&id_key(&binding.scope.key()?))
        != Some(&binding.scope)
        || state
            .confidential
            .identities
            .get(&id_key(&binding.asset_id))
            != Some(&order.identity)
        || now < binding.valid_from
        || now > binding.valid_until
    {
        return Err(
            "confidential reserve scope, asset identity or lifetime is not canonical".into(),
        );
    }
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
        return Err("confidential reservation or request was already used".into());
    }
    let facility_key = id_key(&binding.facility_id);
    let mut facility = state
        .credit_facilities
        .get(&facility_key)
        .cloned()
        .ok_or("confidential facility is absent")?;
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
        return Err("confidential reserve differs from its live facility state".into());
    }
    let ring = canonical_ring(state, &r.escrow.spend)?;
    order.verify_public(&ring, &mut verification_rng(state, &statement))?;
    facility.available_commitment = transition.after_available_commitment;
    facility.held_commitment = transition.after_held_commitment;
    facility.outstanding_commitment = transition.after_outstanding_commitment;
    facility.sequence = facility
        .sequence
        .checked_add(1)
        .ok_or("confidential facility sequence overflow")?;
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
    apply_spend(state, &r.escrow.spend, binding.valid_until, statement)?;
    let escrow = r
        .escrow
        .spend
        .outputs
        .iter()
        .find(|n| n.note_id == r.escrow.escrow_note_id)
        .ok_or("confidential escrow is absent")?;
    state
        .confidential
        .reservation_values
        .insert(hold_key.clone(), escrow.value_commitment);
    state.application_reservations.insert(
        hold_key,
        crate::state::ApplicationReservationRecord {
            binding: binding.clone(),
            escrow_note_id: escrow.note_id,
            proof_digest: r.escrow.spend.proof_digest,
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
