//! Bind completed MPC quote proofs to already-authoritative DeFMI reserves.

use curve25519_dalek::ristretto::CompressedRistretto;
use ed25519_dalek::{SigningKey, VerifyingKey};
use qomm_defmi::facility::reserve_handle_for;
use qomm_transport::mandate::Direction;
use qomm_transport::pretrade_authority::{
    read_ack_private, read_authority_private, ReservationParty,
};
use qomm_transport::settlement_finalization::write_private as write_contexts;
use qomm_transport::settlement_handoff::read_private as read_handoff;
use qomm_zkpi::typed::{AuthorizationScope, ExecutionContext, OperationKind, TradeDirection};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

fn receipt_public() -> VerifyingKey {
    let seed: [u8; 32] = Sha256::digest(b"QOMM:ACCEPTANCE:DEFMI-RECEIPT-KEY:v1").into();
    SigningKey::from_bytes(&seed).verifying_key()
}

fn required(arguments: &[String], name: &str) -> Result<PathBuf, String> {
    arguments
        .iter()
        .position(|value| value == name)
        .and_then(|position| arguments.get(position + 1))
        .map(PathBuf::from)
        .ok_or_else(|| format!("{name} is required"))
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let authority_path = required(&arguments, "--authority")?;
    let acknowledgement_path = required(&arguments, "--ack")?;
    let handoff_path = required(&arguments, "--handoff")?;
    let output_path = required(&arguments, "--contexts-out")?;
    if output_path.exists() {
        return Err(format!(
            "refusing to overwrite settlement contexts: {}",
            output_path.display()
        ));
    }
    let authority = read_authority_private(&authority_path)?;
    let acknowledgement = read_ack_private(&acknowledgement_path)?;
    acknowledgement.verify(&receipt_public())?;
    if acknowledgement.authority_digest != authority.digest()?
        || acknowledgement.defmi_id != authority.defmi_id
    {
        return Err("pre-trade acknowledgement and authority differ".into());
    }
    let handoff = read_handoff(&handoff_path)?;
    let admission = authority
        .admission
        .as_ref()
        .ok_or_else(|| "authority has no admission committee".to_string())?;
    if handoff.admission_node_keys != admission.node_keys {
        return Err("handoff admission keys differ from the pre-trade authority".into());
    }
    let trusted = admission
        .node_keys
        .iter()
        .map(|raw| {
            VerifyingKey::from_bytes(raw)
                .map_err(|_| "authority admission key is malformed".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    handoff.verify_admission(&trusted)?;

    let accepted_takers = acknowledgement
        .bindings
        .iter()
        .filter(|binding| binding.party == ReservationParty::Taker)
        .map(|binding| binding.owner_handle)
        .collect::<BTreeSet<_>>();
    if handoff.records.len() != accepted_takers.len() {
        return Err("MPC handoff does not exactly cover DeFMI-accepted Takers".into());
    }
    let market_statement_digest = hash(&[
        b"QOMM:ACCEPTANCE:MARKET-STATEMENT:v1",
        &handoff.source_digest,
        &handoff.cluster_digest,
        &handoff.order_digest,
    ]);
    let mut contexts = BTreeMap::new();
    for record in &handoff.records {
        let taker_authority = authority
            .takers
            .iter()
            .find(|candidate| candidate.mandate.digest().ok() == Some(record.limit_context))
            .ok_or_else(|| "MPC handoff names no signed Taker mandate".to_string())?;
        let taker_handle = CompressedRistretto(taker_authority.mandate.taker_handle)
            .decompress()
            .ok_or_else(|| "Taker handle is malformed".to_string())?;
        let (direction, maker_handle) = match taker_authority.mandate.direction {
            Direction::TakerBuys if record.instruction.payer_handle == taker_handle => {
                (TradeDirection::TakerBuys, record.instruction.payee_handle)
            }
            Direction::TakerSells if record.instruction.payee_handle == taker_handle => {
                (TradeDirection::TakerSells, record.instruction.payer_handle)
            }
            _ => return Err("MPC payer/payee roles differ from the Taker mandate".into()),
        };
        let maker_authority = authority
            .makers
            .iter()
            .find(|candidate| {
                candidate.mandate.direction == taker_authority.mandate.direction
                    && candidate.mandate.maker_handle == maker_handle.compress().to_bytes()
            })
            .ok_or_else(|| "MPC selected no registered Maker policy".to_string())?;
        let maker_binding = acknowledgement.binding_for(
            ReservationParty::Maker,
            &maker_authority.mandate.maker_handle,
            maker_authority.mandate.direction,
        )?;
        let taker_binding = acknowledgement.binding_for(
            ReservationParty::Taker,
            &taker_authority.mandate.taker_handle,
            taker_authority.mandate.direction,
        )?;
        let joint_reserve_id = hash(&[
            b"QOMM:ACCEPTANCE:JOINT-RESERVE:v1",
            &maker_binding.facility_id,
            &taker_binding.facility_id,
            &record.job_id,
        ]);
        let context = ExecutionContext {
            operation: OperationKind::Settle,
            scope: AuthorizationScope::Joint,
            direction,
            venue_id: authority.venue_id,
            defmi_id: authority.defmi_id,
            maker_handle,
            taker_handle,
            reserve_handle: reserve_handle_for(&joint_reserve_id),
            maker_reservation_id: maker_binding.reserve_id,
            maker_reservation_sequence: 1,
            taker_reservation_id: taker_binding.reserve_id,
            taker_reservation_sequence: 1,
            rfq_nullifier: taker_authority.mandate.rfq_nullifier,
            taker_mandate_digest: taker_authority.mandate.digest()?,
            maker_policy_digest: maker_authority.mandate.policy_digest,
            maker_mandate_digest: maker_authority.mandate.digest()?,
            maker_reserve_receipt_digest: maker_binding.reserve_receipt_digest,
            taker_reserve_receipt_digest: taker_binding.reserve_receipt_digest,
            quote_proof_digest: record.quote_digest,
            market_statement_digest,
            before_state_root: acknowledgement.after_state_root,
        };
        context
            .validate_against(&record.instruction)
            .map_err(str::to_string)?;
        if contexts.insert(record.job_id, context).is_some() {
            return Err("MPC handoff repeats a proof job".into());
        }
    }
    write_contexts(&output_path, &handoff, &contexts)?;
    println!("private settlement contexts: {}", output_path.display());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("settlement context construction failed: {error}");
        std::process::exit(1);
    }
}
