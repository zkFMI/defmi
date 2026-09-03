//! Production boundary for cross-DeFMI finality signing and relay.
//!
//! A signer never accepts an arbitrary destination supplied by a caller.  It
//! signs only a private, pre-registered [`FinalityBinding`] after independently
//! reading an accepted source-L1 snapshot.  Multiple shares are then combined
//! into the destination-bound receipt already verified by the DeFMI state
//! machine.  The relay submits that receipt without learning account handles,
//! assets, amounts, or a common cross-ledger transaction identifier.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use ed25519_dalek::Verifier;
use qomm_transport::external_signer::Ed25519MessageSigner;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::avalanche::{AcceptedTransition, AvalancheClient, AvalancheRpcClient};
use crate::cross_domain::{
    Committee, Domain, FinalityReceipt, LegId, LegStatus, ReceiptEvent, ReceiptSignature,
};

const BINDING_DOMAIN: &[u8] = b"qomm:defmi:cross-domain-finality-binding:v1";
const ZERO: [u8; 32] = [0; 32];

/// Private pairing material produced together with the two destination-local
/// zkPI projections.  It is provisioned to each finality signer out of band.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalityBinding {
    pub source_domain: Domain,
    pub source_leg_id: LegId,
    pub source_instruction_digest: [u8; 32],
    pub source_relation_proof_digest: [u8; 32],
    pub destination_domain: Domain,
    pub destination_leg_id: LegId,
    pub prepared_event_binding: [u8; 32],
    pub claimed_event_binding: [u8; 32],
    pub minimum_source_height: u64,
    pub expires_at: u64,
    pub maximum_snapshot_age_seconds: u64,
}

impl FinalityBinding {
    pub fn validate(&self) -> Result<(), String> {
        if self.source_domain == self.destination_domain
            || [
                self.source_leg_id,
                self.source_instruction_digest,
                self.source_relation_proof_digest,
                self.destination_leg_id,
                self.prepared_event_binding,
                self.claimed_event_binding,
            ]
            .contains(&ZERO)
            || self.minimum_source_height == 0
            || self.expires_at == 0
            || self.maximum_snapshot_age_seconds == 0
        {
            return Err("cross-domain finality binding is invalid".into());
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        let mut hash = Sha256::new();
        hash.update(BINDING_DOMAIN);
        hash.update((encoded.len() as u64).to_be_bytes());
        hash.update(encoded);
        Ok(hash.finalize().into())
    }

    fn event_binding(&self, event: ReceiptEvent) -> [u8; 32] {
        match event {
            ReceiptEvent::Prepared => self.prepared_event_binding,
            ReceiptEvent::Claimed => self.claimed_event_binding,
        }
    }
}

/// One root-consistent `defmivm.crossDomainLeg` response from the accepted
/// source block.  The textual CB58 block ID is retained for operations logs;
/// the exact 32-byte ID is signed in the receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedLegSnapshot {
    pub state_root: [u8; 32],
    pub accepted_height: u64,
    pub accepted_at: u64,
    pub block_id: String,
    pub block_id_bytes: [u8; 32],
    pub local_leg_id: LegId,
    pub local_domain: Domain,
    pub remote_domain: Domain,
    pub local_instruction_digest: [u8; 32],
    pub local_relation_proof_digest: [u8; 32],
    pub status: LegStatus,
}

impl AcceptedLegSnapshot {
    pub fn parse(value: &Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "cross-domain leg snapshot is not an object".to_string())?;
        let status = match text(object, "status")? {
            "prepared" => LegStatus::Prepared,
            "armed" => LegStatus::Armed,
            "claimed" => LegStatus::Claimed,
            "refunded" => LegStatus::Refunded,
            _ => return Err("cross-domain leg snapshot has an unknown status".into()),
        };
        Ok(Self {
            state_root: hex32(object, "stateRoot")?,
            accepted_height: integer(object, "acceptedHeight")?,
            accepted_at: integer(object, "acceptedAt")?,
            block_id: text(object, "blockID")?.to_string(),
            block_id_bytes: hex32(object, "blockIDHex")?,
            local_leg_id: hex32(object, "localLegID")?,
            local_domain: domain(object, "localDomain")?,
            remote_domain: domain(object, "remoteDomain")?,
            local_instruction_digest: hex32(object, "localInstructionDigest")?,
            local_relation_proof_digest: hex32(object, "localRelationProofDigest")?,
            status,
        })
    }

    fn supports(&self, event: ReceiptEvent) -> bool {
        matches!(
            (event, self.status),
            (
                ReceiptEvent::Prepared,
                LegStatus::Prepared | LegStatus::Armed | LegStatus::Claimed
            ) | (ReceiptEvent::Claimed, LegStatus::Claimed)
        )
    }
}

/// Reads one canonical accepted source-leg snapshot from a DeFMI L1.
pub fn fetch_accepted_leg(
    client: &AvalancheRpcClient,
    source_leg_id: LegId,
) -> Result<AcceptedLegSnapshot, String> {
    AcceptedLegSnapshot::parse(&client.call(
        "defmivm.crossDomainLeg",
        json!({"localLegID": hex::encode(source_leg_id)}),
    )?)
}

/// One finality committee member.  `S` may be the process-isolated HSM/KMS
/// adapter; private key bytes therefore need not enter this process.
pub struct FinalitySigner<S: Ed25519MessageSigner> {
    committee: Committee,
    member_id: [u8; 32],
    signer: S,
    bindings: BTreeMap<[u8; 32], FinalityBinding>,
}

impl<S: Ed25519MessageSigner> FinalitySigner<S> {
    pub fn new(
        committee: Committee,
        member_id: [u8; 32],
        signer: S,
        bindings: Vec<FinalityBinding>,
    ) -> Result<Self, String> {
        committee.validate().map_err(|error| error.to_string())?;
        let member = committee
            .members
            .iter()
            .find(|member| member.member_id == member_id)
            .ok_or_else(|| "finality signer is not in the configured committee".to_string())?;
        if member.public_key != signer.verifying_key().to_bytes() {
            return Err("finality signer key differs from the committee key".into());
        }
        let mut registered = BTreeMap::new();
        for binding in bindings {
            if binding.source_domain != committee.domain {
                return Err("finality binding names another source committee".into());
            }
            let digest = binding.digest()?;
            if registered.insert(digest, binding).is_some() {
                return Err("finality binding is duplicated".into());
            }
        }
        if registered.is_empty() {
            return Err("finality signer has no private bindings".into());
        }
        Ok(Self {
            committee,
            member_id,
            signer,
            bindings: registered,
        })
    }

    pub fn sign(
        &self,
        binding_digest: [u8; 32],
        snapshot: &AcceptedLegSnapshot,
        event: ReceiptEvent,
        observed_at: u64,
    ) -> Result<FinalityReceipt, String> {
        let binding = self
            .bindings
            .get(&binding_digest)
            .ok_or_else(|| "finality binding was not provisioned to this signer".to_string())?;
        if snapshot.local_domain != binding.source_domain
            || snapshot.remote_domain != binding.destination_domain
            || snapshot.local_leg_id != binding.source_leg_id
            || snapshot.local_instruction_digest != binding.source_instruction_digest
            || snapshot.local_relation_proof_digest != binding.source_relation_proof_digest
            || snapshot.accepted_height < binding.minimum_source_height
            || snapshot.accepted_at > observed_at
            || observed_at > binding.expires_at
            || observed_at - snapshot.accepted_at > binding.maximum_snapshot_age_seconds
            || snapshot.state_root == ZERO
            || snapshot.block_id_bytes == ZERO
            || !snapshot.supports(event)
        {
            return Err(
                "accepted source snapshot does not satisfy the private finality binding".into(),
            );
        }
        let mut receipt = FinalityReceipt {
            source_domain: binding.source_domain.clone(),
            destination_domain: binding.destination_domain.clone(),
            destination_leg_id: binding.destination_leg_id,
            event_binding: binding.event_binding(event),
            event,
            source_state_root: snapshot.state_root,
            source_block_id: snapshot.block_id_bytes,
            source_height: snapshot.accepted_height,
            finalised_at: snapshot.accepted_at,
            validator_epoch: self.committee.epoch,
            signatures: Vec::new(),
        };
        let message = receipt.signing_digest();
        let signature = self.signer.sign_message(&message)?;
        self.signer
            .verifying_key()
            .verify(&message, &signature)
            .map_err(|_| "finality signer returned an invalid signature".to_string())?;
        receipt.signatures.push(ReceiptSignature {
            member_id: self.member_id,
            signature: signature.to_bytes().to_vec(),
        });
        Ok(receipt)
    }
}

/// Combines independently-produced one-member receipts and verifies the final
/// weighted quorum before anything is sent to the destination L1.
pub fn aggregate_receipt(
    committee: &Committee,
    shares: Vec<FinalityReceipt>,
) -> Result<FinalityReceipt, String> {
    committee.validate().map_err(|error| error.to_string())?;
    let first = shares
        .first()
        .ok_or_else(|| "finality aggregation has no shares".to_string())?;
    let digest = first.signing_digest();
    let mut signatures = Vec::with_capacity(shares.len());
    let mut members = BTreeSet::new();
    for share in &shares {
        if share.signing_digest() != digest || share.signatures.len() != 1 {
            return Err("finality shares do not describe one accepted event".into());
        }
        let signature = share.signatures[0].clone();
        if !members.insert(signature.member_id) {
            return Err("finality aggregation repeats a committee member".into());
        }
        signatures.push(signature);
    }
    signatures.sort_by_key(|signature| signature.member_id);
    let mut receipt = first.clone();
    receipt.signatures = signatures;
    receipt
        .verify(committee)
        .map_err(|error| error.to_string())?;
    Ok(receipt)
}

/// Closed JSON representation accepted by the destination VM.
pub fn receipt_rpc_json(receipt: &FinalityReceipt) -> Value {
    json!({
        "sourceDomain": domain_json(&receipt.source_domain),
        "destinationDomain": domain_json(&receipt.destination_domain),
        "destinationLegID": hex::encode(receipt.destination_leg_id),
        "eventBinding": hex::encode(receipt.event_binding),
        "event": match receipt.event {
            ReceiptEvent::Prepared => "prepared",
            ReceiptEvent::Claimed => "claimed",
        },
        "sourceStateRoot": hex::encode(receipt.source_state_root),
        "sourceBlockID": hex::encode(receipt.source_block_id),
        "sourceHeight": receipt.source_height,
        "finalisedAt": receipt.finalised_at,
        "validatorEpoch": receipt.validator_epoch,
        "signatures": receipt.signatures.iter().map(|signature| json!({
            "memberID": hex::encode(signature.member_id),
            "signature": hex::encode(&signature.signature),
        })).collect::<Vec<_>>(),
    })
}

/// Submits an already-aggregated remote event and waits for a terminal accepted
/// transition.  Re-submitting the same bytes produces the same Avalanche
/// transaction ID, so a transport retry does not create a second receipt.
pub fn relay_receipt(
    destination: &AvalancheRpcClient,
    local_leg_id: LegId,
    receipt: &FinalityReceipt,
    acceptance_timeout: Duration,
    poll_interval: Duration,
) -> Result<AcceptedTransition, String> {
    if local_leg_id == ZERO
        || acceptance_timeout.is_zero()
        || poll_interval.is_zero()
        || poll_interval > acceptance_timeout
    {
        return Err("cross-domain relay timing or leg identifier is invalid".into());
    }
    let method = match receipt.event {
        ReceiptEvent::Prepared => "defmivm.issueCrossDomainArm",
        ReceiptEvent::Claimed => "defmivm.issueCrossDomainObserveClaim",
    };
    let result = destination.call(
        method,
        json!({
            "localLegID": hex::encode(local_leg_id),
            "remoteReceipt": receipt_rpc_json(receipt),
        }),
    )?;
    let transaction_id = result
        .get("txID")
        .and_then(Value::as_str)
        .ok_or_else(|| "destination L1 returned no relay transaction identifier".to_string())?;
    destination.wait_accepted(transaction_id, acceptance_timeout, poll_interval)
}

fn domain_json(value: &Domain) -> Value {
    json!({
        "networkID": value.network_id,
        "chainID": hex::encode(value.chain_id),
        "defmiID": hex::encode(value.defmi_id),
    })
}

fn domain(object: &Map<String, Value>, name: &str) -> Result<Domain, String> {
    let value = object
        .get(name)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("cross-domain leg snapshot is missing {name}"))?;
    let network_id = value
        .get("networkID")
        .and_then(Value::as_u64)
        .and_then(|number| u32::try_from(number).ok())
        .ok_or_else(|| format!("cross-domain leg snapshot {name}.networkID is invalid"))?;
    Ok(Domain {
        network_id,
        chain_id: hex32(value, "chainID")?,
        defmi_id: hex32(value, "defmiID")?,
    })
}

fn text<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("cross-domain leg snapshot is missing {name}"))
}

fn integer(object: &Map<String, Value>, name: &str) -> Result<u64, String> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .filter(|value| *value != 0)
        .ok_or_else(|| format!("cross-domain leg snapshot is missing {name}"))
}

fn hex32(object: &Map<String, Value>, name: &str) -> Result<[u8; 32], String> {
    hex::decode(text(object, name)?)
        .map_err(|_| format!("cross-domain leg snapshot {name} is not hexadecimal"))?
        .try_into()
        .map_err(|_| format!("cross-domain leg snapshot {name} is not 32 bytes"))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::cross_domain::CommitteeMember;

    fn id(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn source() -> Domain {
        Domain {
            network_id: 1,
            chain_id: id(1),
            defmi_id: id(2),
        }
    }

    fn destination() -> Domain {
        Domain {
            network_id: 2,
            chain_id: id(3),
            defmi_id: id(4),
        }
    }

    fn binding() -> FinalityBinding {
        FinalityBinding {
            source_domain: source(),
            source_leg_id: id(10),
            source_instruction_digest: id(11),
            source_relation_proof_digest: id(12),
            destination_domain: destination(),
            destination_leg_id: id(13),
            prepared_event_binding: id(14),
            claimed_event_binding: id(15),
            minimum_source_height: 7,
            expires_at: 1_000,
            maximum_snapshot_age_seconds: 30,
        }
    }

    fn snapshot(status: LegStatus) -> AcceptedLegSnapshot {
        AcceptedLegSnapshot {
            state_root: id(20),
            accepted_height: 8,
            accepted_at: 100,
            block_id: "accepted-block".into(),
            block_id_bytes: id(21),
            local_leg_id: id(10),
            local_domain: source(),
            remote_domain: destination(),
            local_instruction_digest: id(11),
            local_relation_proof_digest: id(12),
            status,
        }
    }

    #[test]
    fn independent_hsm_bound_shares_aggregate_to_one_destination_receipt() {
        let keys = [
            SigningKey::from_bytes(&id(30)),
            SigningKey::from_bytes(&id(31)),
            SigningKey::from_bytes(&id(32)),
        ];
        let committee = Committee {
            domain: source(),
            epoch: 9,
            quorum_weight: 2,
            members: keys
                .iter()
                .enumerate()
                .map(|(index, key)| CommitteeMember {
                    member_id: id(40 + index as u8),
                    public_key: key.verifying_key().to_bytes(),
                    weight: 1,
                })
                .collect(),
        };
        let private_binding = binding();
        let digest = private_binding.digest().unwrap();
        let shares = keys
            .into_iter()
            .take(2)
            .enumerate()
            .map(|(index, key)| {
                FinalitySigner::new(
                    committee.clone(),
                    id(40 + index as u8),
                    key,
                    vec![private_binding.clone()],
                )
                .unwrap()
                .sign(
                    digest,
                    &snapshot(LegStatus::Prepared),
                    ReceiptEvent::Prepared,
                    110,
                )
                .unwrap()
            })
            .collect();
        let receipt = aggregate_receipt(&committee, shares).unwrap();
        assert_eq!(receipt.destination_leg_id, id(13));
        assert_eq!(receipt.event_binding, id(14));
        assert_eq!(receipt.source_block_id, id(21));
        assert_eq!(receipt.signatures.len(), 2);
        receipt.verify(&committee).unwrap();
        assert_eq!(
            receipt_rpc_json(&receipt)["sourceBlockID"],
            hex::encode(id(21))
        );
    }

    #[test]
    fn signer_refuses_unprovisioned_stale_or_unclaimed_events() {
        let key = SigningKey::from_bytes(&id(30));
        let committee = Committee {
            domain: source(),
            epoch: 9,
            quorum_weight: 1,
            members: vec![CommitteeMember {
                member_id: id(40),
                public_key: key.verifying_key().to_bytes(),
                weight: 1,
            }],
        };
        let private_binding = binding();
        let digest = private_binding.digest().unwrap();
        let signer = FinalitySigner::new(committee, id(40), key, vec![private_binding]).unwrap();
        assert!(signer
            .sign(
                id(99),
                &snapshot(LegStatus::Prepared),
                ReceiptEvent::Prepared,
                110
            )
            .unwrap_err()
            .contains("not provisioned"));
        assert!(signer
            .sign(
                digest,
                &snapshot(LegStatus::Prepared),
                ReceiptEvent::Claimed,
                110
            )
            .unwrap_err()
            .contains("does not satisfy"));
        assert!(signer
            .sign(
                digest,
                &snapshot(LegStatus::Prepared),
                ReceiptEvent::Prepared,
                140
            )
            .unwrap_err()
            .contains("does not satisfy"));
    }

    #[test]
    fn canonical_snapshot_parser_requires_the_exact_accepted_block() {
        let value = json!({
            "stateRoot": hex::encode(id(20)),
            "acceptedHeight": 8,
            "acceptedAt": 100,
            "blockID": "accepted-block",
            "blockIDHex": hex::encode(id(21)),
            "localLegID": hex::encode(id(10)),
            "localDomain": domain_json(&source()),
            "remoteDomain": domain_json(&destination()),
            "localInstructionDigest": hex::encode(id(11)),
            "localRelationProofDigest": hex::encode(id(12)),
            "status": "claimed",
        });
        assert_eq!(
            AcceptedLegSnapshot::parse(&value).unwrap(),
            snapshot(LegStatus::Claimed)
        );
        let mut missing = value;
        missing.as_object_mut().unwrap().remove("blockIDHex");
        assert!(AcceptedLegSnapshot::parse(&missing).is_err());
    }
}
