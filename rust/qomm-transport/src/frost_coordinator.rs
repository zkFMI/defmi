//! Coordinator for the authenticated seven-party FROST DKG.
//!
//! The coordinator only relays signed identities, public broadcasts and
//! recipient-encrypted round-two packages.  No signing-key share is ever
//! returned by a proof party.

use crate::proof_client::ProofPartyRpc;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use qomm_zkpi::frost;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Public and recipient-encrypted transcript required for the final DKG step.
/// It contains no clear signing share and can be journaled before any node is
/// asked to commit its durable FROST key.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FrostDkgPlan {
    pub session: String,
    pub broadcasts: Value,
    pub incoming: Vec<Vec<Value>>,
}

pub fn distributed_frost_setup<T: ProofPartyRpc>(
    parties: &mut [T],
    session: [u8; 32],
) -> Result<frost::keys::PublicKeyPackage, String> {
    if let Some(public) = recall_frost_group(parties, session)? {
        return Ok(public);
    }
    let plan = prepare_frost_dkg(parties, session)?;
    finalize_frost_dkg(parties, &plan)
}

/// The durable FROST group the seven parties already hold for `session`, or
/// `None` when no party holds one yet (a DKG is then needed).  This is the
/// retrieval half of `distributed_frost_setup`: it only reads each party's
/// status, so a caller may run it with a short timeout to learn quickly
/// whether the committee is reachable at all.
pub fn recall_frost_group<T: ProofPartyRpc>(
    parties: &mut [T],
    session: [u8; 32],
) -> Result<Option<frost::keys::PublicKeyPackage>, String> {
    if parties.len() != 7 {
        return Err("FROST deployment requires exactly seven proof parties".into());
    }
    let statuses = parties
        .iter_mut()
        .map(|party| party.call("frost_status", json!({})))
        .collect::<Result<Vec<_>, _>>()?;
    let ready = statuses
        .iter()
        .filter(|status| status.get("ready").and_then(Value::as_bool) == Some(true))
        .count();
    if ready != 0 {
        if ready != parties.len() {
            return Err("FROST durable group is present on only part of the node set".into());
        }
        let expected_session = hex::encode(session);
        if statuses.iter().any(|status| {
            status.get("session").and_then(Value::as_str) != Some(expected_session.as_str())
        }) {
            return Err("FROST durable group belongs to another DKG session".into());
        }
        let encoded = statuses
            .iter()
            .map(|status| {
                BASE64
                    .decode(
                        status
                            .get("public_package")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                "FROST ready node omitted its public package".to_string()
                            })?,
                    )
                    .map_err(|_| "FROST durable public package is malformed".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if encoded.iter().skip(1).any(|value| value != &encoded[0]) {
            return Err("FROST durable nodes disagree on the group public key".into());
        }
        return frost::keys::PublicKeyPackage::deserialize(&encoded[0])
            .map(Some)
            .map_err(|_| "FROST durable public key cannot be decoded".into());
    }
    Ok(None)
}

pub fn prepare_frost_dkg<T: ProofPartyRpc>(
    parties: &mut [T],
    session: [u8; 32],
) -> Result<FrostDkgPlan, String> {
    if parties.len() != 7 {
        return Err("FROST deployment requires exactly seven proof parties".into());
    }
    let identities = parties
        .iter_mut()
        .map(|party| party.call("frost_identity", json!({"session": hex::encode(session)})))
        .collect::<Result<Vec<_>, _>>()?;
    let entries = Value::Array(identities);
    let confirmations = parties
        .iter_mut()
        .map(|party| {
            party.call(
                "frost_configure_peers",
                json!({
                    "session": hex::encode(session),
                    "entries": entries.clone(),
                }),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let manifest_digests = confirmations
        .iter()
        .filter_map(|value| value.get("manifest_digest").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    if manifest_digests.len() != 1 || confirmations.len() != parties.len() {
        return Err("FROST nodes did not confirm one identical peer manifest".into());
    }
    let confirmation_values = Value::Array(
        confirmations
            .iter()
            .map(|value| {
                json!({
                    "party": value.get("party").cloned().unwrap_or(Value::Null),
                    "confirmation": value.get("confirmation").cloned().unwrap_or(Value::Null),
                })
            })
            .collect(),
    );
    for party in parties.iter_mut() {
        party.call(
            "frost_confirm_peers",
            json!({"confirmations": confirmation_values.clone()}),
        )?;
    }
    let broadcasts = parties
        .iter_mut()
        .map(|party| party.call("frost_dkg_round1", json!({})))
        .collect::<Result<Vec<_>, _>>()?;
    let broadcast_values = Value::Array(broadcasts);
    let directed = parties
        .iter_mut()
        .map(|party| {
            party.call(
                "frost_dkg_round2",
                json!({"broadcasts": broadcast_values.clone()}),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut incoming = (0..parties.len()).map(|_| Vec::new()).collect::<Vec<_>>();
    for sender in directed {
        for envelope in sender
            .get("encrypted")
            .and_then(Value::as_array)
            .ok_or_else(|| "FROST node omitted its encrypted directed packages".to_string())?
        {
            let recipient = envelope
                .get("recipient")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .filter(|value| (1..=parties.len()).contains(value))
                .ok_or_else(|| "FROST directed package has an invalid recipient".to_string())?;
            incoming[recipient - 1].push(envelope.clone());
        }
    }
    Ok(FrostDkgPlan {
        session: hex::encode(session),
        broadcasts: broadcast_values,
        incoming,
    })
}

pub fn finalize_frost_dkg<T: ProofPartyRpc>(
    parties: &mut [T],
    plan: &FrostDkgPlan,
) -> Result<frost::keys::PublicKeyPackage, String> {
    if parties.len() != 7
        || plan.incoming.len() != parties.len()
        || hex::decode(&plan.session)
            .ok()
            .is_none_or(|session| session.len() != 32)
        || !plan.broadcasts.is_array()
    {
        return Err("FROST finalization plan is malformed or incomplete".into());
    }
    let mut encoded_public = Vec::new();
    for (party, incoming) in parties.iter_mut().zip(&plan.incoming) {
        let result = party.call(
            "frost_dkg_finalize",
            json!({
                "broadcasts": plan.broadcasts.clone(),
                "incoming": incoming,
            }),
        )?;
        encoded_public.push(
            BASE64
                .decode(
                    result
                        .get("public_package")
                        .and_then(Value::as_str)
                        .ok_or_else(|| "FROST node omitted the group public key".to_string())?,
                )
                .map_err(|_| "FROST public key package is malformed")?,
        );
    }
    if encoded_public
        .iter()
        .skip(1)
        .any(|package| package != &encoded_public[0])
    {
        return Err("FROST nodes derived different group public keys".into());
    }
    frost::keys::PublicKeyPackage::deserialize(&encoded_public[0])
        .map_err(|_| "FROST group public key cannot be decoded".into())
}

/// Stable, domain-separated identifier for one threshold-signing job.
///
/// Proof parties use this identifier to reserve a nonce exactly once.  It is
/// deliberately derived from the complete message, so the coordinator cannot
/// reuse one authorization for different settlement bytes.
pub fn frost_signing_job(message: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"QOMM:FROST:SIGNING-JOB:v1")
        .chain_update(message)
        .finalize()
        .into()
}

/// Produce one FROST signature without ever collecting a signing-key share.
///
/// `selected` contains one-based committee identifiers.  Every state-changing
/// call is made once; the final replay probe is expected to fail and proves
/// that the chosen proof party consumed its nonce.
pub fn distributed_frost_sign<T: ProofPartyRpc>(
    parties: &mut [T],
    selected: &[usize],
    message: &[u8],
    public: &frost::keys::PublicKeyPackage,
) -> Result<frost::Signature, String> {
    if selected.len() < 3
        || selected
            .iter()
            .any(|party| !(1..=parties.len()).contains(party))
    {
        return Err("FROST signing quorum is outside the configured node set".into());
    }
    let signing_job = frost_signing_job(message);
    let encoded_message = BASE64.encode(message);
    let commitments = selected
        .iter()
        .map(|party| {
            parties[*party - 1].call(
                "frost_commit",
                json!({
                    "job_id": hex::encode(signing_job),
                    "message": encoded_message,
                }),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut decoded_commitments = BTreeMap::new();
    for commitment in &commitments {
        let party = commitment
            .get("party")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| "FROST commitment party is invalid".to_string())?;
        let raw = BASE64
            .decode(
                commitment
                    .get("commitments")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "FROST commitment is absent".to_string())?,
            )
            .map_err(|_| "FROST commitment is malformed")?;
        decoded_commitments.insert(
            frost::Identifier::try_from(party).map_err(|_| "FROST identifier is invalid")?,
            frost::round1::SigningCommitments::deserialize(&raw)
                .map_err(|_| "FROST commitment cannot be decoded")?,
        );
    }
    let commitment_values = Value::Array(commitments.clone());
    let shares = selected
        .iter()
        .map(|party| {
            parties[*party - 1].call(
                "frost_sign",
                json!({
                    "job_id": hex::encode(signing_job),
                    "message": encoded_message,
                    "commitments": commitment_values.clone(),
                }),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let replay = parties[selected[0] - 1].call(
        "frost_sign",
        json!({
            "job_id": hex::encode(signing_job),
            "message": encoded_message,
            "commitments": commitment_values,
        }),
    );
    if replay.is_ok() {
        return Err("FROST node reused a consumed signing nonce".into());
    }
    let mut decoded_shares = BTreeMap::new();
    for share in shares {
        let party = share
            .get("party")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| "FROST signature-share party is invalid".to_string())?;
        let raw = BASE64
            .decode(
                share
                    .get("share")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "FROST signature share is absent".to_string())?,
            )
            .map_err(|_| "FROST signature share is malformed")?;
        decoded_shares.insert(
            frost::Identifier::try_from(party).map_err(|_| "FROST identifier is invalid")?,
            frost::round2::SignatureShare::deserialize(&raw)
                .map_err(|_| "FROST signature share cannot be decoded")?,
        );
    }
    let package = frost::SigningPackage::new(decoded_commitments, message);
    frost::aggregate(&package, &decoded_shares, public)
        .map_err(|_| "FROST aggregation rejected a node response".into())
}
