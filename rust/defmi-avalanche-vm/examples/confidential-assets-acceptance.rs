//! Outcome-first, real-proof native state-machine run. Uses fresh in-memory
//! governance, issuer, recipient and seven-party committee keys and synthetic
//! assets; it is NOT a live five-validator network or a DeKYX service run.
//! All state is created by canonical transactions, then saved and read back.

use std::{collections::BTreeMap, env, fs, path::PathBuf, time::Instant};
#[path = "confidential-assets/native.rs"]
mod native;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use curve25519_dalek::Scalar;
use defmi::{
    application_reservation::{
        ApplicationNoteReservation, ApplicationReserveMandate, ApplicationReserveScope,
    },
    application_settlement::{
        application_claim, ApplicationNoteFill, ApplicationNoteRelease, ApplicationOpening,
        ApplicationReleaseReason, ApplicationSpendHead,
    },
    claim_redemption::{redeem_confidential_claim, NoteClaimAuthorization},
    confidential_assets::{AssetProof, Registry},
    confidential_notes::{
        self as ca, AssetIdentity, ClaimConversion, ConfidentialFill, ConfidentialIssuance,
        ConfidentialReservation, ConfidentialTransfer, TransferContext, ValueLink,
    },
    facility::{
        sign_guarantor_message, AssetDefinition, AssetKind, CreditFacilityGrant,
        CreditFacilityRelationProof, CreditFacilityTransition, CreditTransitionKind,
        GuarantorDefinition, GuarantorKind, QuorumAuthorizer, ZERO,
    },
    governance::GovernanceSigner,
    note_chain::{
        note_claim_recipient_commitment, ClaimAuthorizationCommitment, CsdIssuerDefinition,
        NoteClaimKind, NoteIssuance, NoteOutput, NoteReservationEscrow, NoteSpend,
    },
    notes::{encode_spend_proof, NoteLedger, Wallet},
};
use defmi_avalanche_vm::{
    block::Block,
    id::Id,
    recovery::ApprovalWire,
    state::{id_key, State},
    transaction::TransactionEnvelope,
};
use ed25519_dalek::{Signature, SigningKey};
use merlin::Transcript;
use native::moment;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zkfmi_crypto::{
    backend::MlDsa65Signer,
    hybrid::signature::HybridSigner,
    key::{KeyId, KeyPurpose, KeyRecord, ParticipantId},
    quorum::{QuorumMember, QuorumPolicy, SUITE},
    suite::Version,
    traits::Signer as _,
};
use zkfmi_zk::{pedersen::Pedersen, sigma::prove_product};
use zkpi::{
    frost, Bounds, PartialInstruction, AMOUNT_RANGE_CONTEXT, DEFAULT_DOMAIN, PRICE_RANGE_CONTEXT,
};
use zkpi_committee::{
    dvp_issuer::{
        DvpProofs, DVP_CASH_REMAINDER_CONTEXT, DVP_PRODUCT_CONTEXT,
        DVP_SECURITIES_REMAINDER_CONTEXT,
    },
    proof_codec::encode_dvp_proofs,
};
use zkpi_proofs::{
    opening_envelope::{encrypt_opening_share, opening_context, OpeningEnvelope},
    threshold_range::{deal_bits, joint_prove_range_from_contributions},
};

fn id(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}
fn random_bytes() -> [u8; 32] {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn note_json(n: &NoteOutput) -> Value {
    json!({"noteID": hex::encode(n.note_id), "assetID": hex::encode(n.asset_id),
    "oneTime": hex::encode(n.one_time), "valueCommitment": hex::encode(n.value_commitment),
    "ephemeral": hex::encode(n.ephemeral), "encryptedOpening": n.encrypted_opening, "lockID": hex::encode(n.lock_id)})
}
fn spend_json(s: &NoteSpend) -> Value {
    json!({"assetID": hex::encode(s.asset_id), "ring": s.ring.iter().map(hex::encode).collect::<Vec<_>>(),
    "ringRoot": hex::encode(s.ring_root), "serialPoint": hex::encode(s.serial_point), "inputLockID": hex::encode(s.input_lock_id),
    "proofDigest": hex::encode(s.proof_digest), "outputs": s.outputs.iter().map(note_json).collect::<Vec<_>>()})
}
fn transition_json(t: &CreditFacilityTransition) -> Value {
    json!({"operationID": hex::encode(t.operation_id), "facilityID": hex::encode(t.facility_id), "holdID": hex::encode(t.hold_id),
        "kind": t.kind.as_str(), "queryCommitment": hex::encode(t.query_commitment), "amountCommitment": hex::encode(t.amount_commitment),
        "consumedCommitment": hex::encode(t.consumed_commitment), "refundCommitment": hex::encode(t.refund_commitment),
        "beforeAvailableCommitment": hex::encode(t.before_available_commitment), "afterAvailableCommitment": hex::encode(t.after_available_commitment),
        "beforeHeldCommitment": hex::encode(t.before_held_commitment), "afterHeldCommitment": hex::encode(t.after_held_commitment),
        "beforeOutstandingCommitment": hex::encode(t.before_outstanding_commitment), "afterOutstandingCommitment": hex::encode(t.after_outstanding_commitment),
        "beforeSequence": t.before_sequence, "expiresAt": t.expires_at, "settlementDigest": hex::encode(t.settlement_digest),
        "relationProofDigest": hex::encode(t.relation_proof_digest)})
}

struct Run {
    state: State,
    authority: QuorumAuthorizer,
    signers: BTreeMap<String, GovernanceSigner>,
    output: PathBuf,
    receipts: Vec<Value>,
    rejections: Vec<Value>,
    parent: Id,
    network: Option<native::Network>,
}
impl Run {
    fn new(output: PathBuf) -> Result<Self, String> {
        let signers = (1..=5)
            .map(|i| {
                let name = format!("asset-privacy-validator-{i}");
                Ok((
                    name.clone(),
                    GovernanceSigner::generate(&name, 1, moment(10_000))?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        let network = native::Network::connect(&output, &signers)?;
        let domain = network
            .as_ref()
            .map(|n| n.chain_id.as_str())
            .unwrap_or("asset-privacy-canonical-rough");
        let authority = QuorumAuthorizer::new(
            signers
                .iter()
                .map(|(n, k)| (n.clone(), k.verifying_key()))
                .collect(),
            3,
            1,
            domain,
        )?;
        Ok(Self {
            state: State::default(),
            authority,
            signers,
            output,
            receipts: vec![],
            rejections: vec![],
            parent: Id(id("asset-privacy-genesis")),
            network,
        })
    }
    fn submit(
        &mut self,
        method: &str,
        mut params: Value,
        statement: Option<[u8; 32]>,
        now: u64,
    ) -> Result<(), String> {
        if let Some(statement) = statement {
            let approval =
                self.authority
                    .at(now)
                    .approve(statement, self.state.root(), &self.signers)?;
            let map = params
                .as_object_mut()
                .ok_or("parameters must be an object")?;
            map.insert(
                "approval".into(),
                serde_json::to_value(ApprovalWire::from(&approval)).map_err(err)?,
            );
            map.insert(
                "expectedBeforeRoot".into(),
                json!(hex::encode(self.state.root())),
            );
        }
        let transaction = TransactionEnvelope::new(method, params)?;
        let tx = transaction.encode()?;
        let number = self.receipts.len() + 1;
        let (block, bytes, native_receipt) = if let Some(network) = &self.network {
            let (block, bytes, receipt) = network.accept(&transaction)?;
            (block, bytes, Some(receipt))
        } else {
            let block = Block {
                parent_id: self.parent,
                timestamp: now as i64,
                height: number as u64,
                transactions: vec![tx.clone()],
            };
            let bytes = block.encode()?;
            (block, bytes, None)
        };
        let receipt = self
            .state
            .apply(&tx, &self.authority, block.timestamp as u64)
            .map_err(|e| format!("{method}: {e}"))?;
        let native_roots = if let Some(network) = &self.network {
            let response = native_receipt.as_ref().ok_or("native receipt absent")?;
            if response["beforeRoot"] != hex::encode(receipt.before_root)
                || response["afterRoot"] != hex::encode(receipt.after_root)
                || response["statement"] != hex::encode(receipt.statement)
            {
                return Err("native receipt differs from replayed canonical execution".into());
            }
            network.roots(receipt.after_root)?
        } else {
            vec![]
        };
        self.parent = Id::digest(&bytes);
        fs::write(self.output.join(format!("{number:03}-block.bin")), &bytes).map_err(err)?;
        fs::write(
            self.output.join(format!("{number:03}-transaction.json")),
            &tx,
        )
        .map_err(err)?;
        let state_path = self.output.join("canonical-state.json");
        fs::write(&state_path, self.state.encode()?).map_err(err)?;
        let restored = State::decode(&fs::read(&state_path).map_err(err)?)?;
        if restored.root() != receipt.after_root {
            return Err("persisted state root differs from accepted transition".into());
        }
        self.state = restored;
        self.receipts.push(json!({"method": method, "transaction_id": receipt.transaction_id.to_string(),
            "block_id": self.parent.to_string(), "before_root": hex::encode(receipt.before_root),
            "after_root": hex::encode(receipt.after_root), "statement": hex::encode(receipt.statement),
            "native_receipt":native_receipt, "native_validator_roots":native_roots,
            "persisted_bytes": fs::metadata(&state_path).map_err(err)?.len()}));
        fs::write(
            self.output.join("transitions.json"),
            serde_json::to_vec_pretty(&self.receipts).map_err(err)?,
        )
        .map_err(err)?;
        println!("accepted {} {}", number, method);
        Ok(())
    }
    fn reject(
        &mut self,
        label: &str,
        method: &str,
        mut params: Value,
        statement: Option<[u8; 32]>,
        now: u64,
        reason: &str,
    ) -> Result<(), String> {
        if let Some(statement) = statement {
            let approval =
                self.authority
                    .at(now)
                    .approve(statement, self.state.root(), &self.signers)?;
            params["approval"] =
                serde_json::to_value(ApprovalWire::from(&approval)).map_err(err)?;
            params["expectedBeforeRoot"] = json!(hex::encode(self.state.root()));
        }
        let tx = TransactionEnvelope::new(method, params)?.encode()?;
        let before = self.state.encode()?;
        let error = self
            .state
            .apply(&tx, &self.authority, now)
            .err()
            .ok_or_else(|| format!("invalid operation accepted: {label}"))?;
        if !error.contains(reason) {
            return Err(format!("{label} rejected at unexpected boundary: {error}"));
        }
        if self.state.encode()? != before {
            return Err(format!("rejection mutated state: {label}"));
        }
        let native_rejection = self
            .network
            .as_ref()
            .map(|network| network.reject(&tx, reason, self.state.root()))
            .transpose()?;
        fs::write(self.output.join(format!("rejected-{label}.json")), &tx).map_err(err)?;
        self.rejections.push(json!({"label":label,"error":error,"state_unchanged":true,"native":native_rejection,
            "transaction_sha256":hex::encode(Sha256::digest(&tx)),"state_root":hex::encode(self.state.root())}));
        fs::write(
            self.output.join("rejections.json"),
            serde_json::to_vec_pretty(&self.rejections).map_err(err)?,
        )
        .map_err(err)?;
        println!("rejected {label}: {error}");
        Ok(())
    }

    fn ledger(&self) -> Result<(NoteLedger, Vec<NoteOutput>, Vec<[u8; 32]>), String> {
        if let Some(network) = &self.network {
            let records = network.notes(self.state.root())?;
            if records.len() != self.state.confidential.notes.len() {
                return Err("native wallet page omitted canonical notes".into());
            }
            let mut ledger = NoteLedger::new(ca::key(), 32);
            let mut notes = Vec::new();
            let mut tags = Vec::new();
            for (note, identity) in records {
                if self
                    .state
                    .notes
                    .get(&id_key(&note.note_id))
                    .map(|n| n.output(note.note_id))
                    != Some(note.clone())
                {
                    return Err("native wallet output differs from accepted block replay".into());
                }
                ledger.add(note.to_note()?);
                tags.push(identity.tag);
                notes.push(note);
            }
            return Ok((ledger, notes, tags));
        }

        let mut ledger = NoteLedger::new(ca::key(), 32);
        let mut outputs = vec![];
        let mut tags = vec![];
        for name in &self.state.confidential.notes {
            let record = &self.state.notes[name];
            let note_id = hex::decode(name)
                .map_err(err)?
                .try_into()
                .map_err(|_| "note ID length")?;
            let output = record.output(note_id);
            tags.push(self.state.confidential.identities[&id_key(&record.asset_id)].tag);
            ledger.add(output.to_note()?);
            outputs.push(output);
        }
        Ok((ledger, outputs, tags))
    }
}

struct Committee {
    keys: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: frost::keys::PublicKeyPackage,
    pq: QuorumPolicy,
    pq_keys: BTreeMap<u16, MlDsa65Signer>,
}
impl Committee {
    fn new() -> Result<Self, String> {
        let (shares, public) = zkpi::deal_quorum(7, 3, &mut OsRng).map_err(err)?;
        let keys = shares
            .into_iter()
            .map(|(id, s)| Ok((id, frost::keys::KeyPackage::try_from(s).map_err(err)?)))
            .collect::<Result<_, String>>()?;
        let pq_keys = (1..=7)
            .map(|n| (n, MlDsa65Signer::from_seed(&random_bytes())))
            .collect::<BTreeMap<_, _>>();
        let pq = QuorumPolicy {
            version: Version::V1,
            epoch: 1,
            purpose: KeyPurpose::SettlementInstruction,
            context: b"confidential-asset-rough-fresh-committee".to_vec(),
            classical_binding: Sha256::digest(public.serialize().map_err(err)?).into(),
            threshold: 3,
            members: pq_keys
                .iter()
                .map(|(n, k)| {
                    Ok(QuorumMember {
                        node: *n,
                        key: KeyRecord {
                            participant_id: ParticipantId::new(format!("asset-privacy-mpc-{n}"))
                                .map_err(err)?,
                            key_id: KeyId::new(format!("asset-privacy-pq-{n}")).map_err(err)?,
                            suite: SUITE,
                            key_version: 1,
                            purpose: KeyPurpose::SettlementInstruction,
                            public_key: k.public_key(),
                            not_before: 1,
                            not_after: moment(10_000),
                            revoked_at: None,
                            rotation_proof: None,
                            dekyx_binding: None,
                        },
                    })
                })
                .collect::<Result<_, String>>()?,
        };
        Ok(Self {
            keys,
            public,
            pq,
            pq_keys,
        })
    }
    fn pq_sign(&self, msg: &[u8], now: u64) -> Result<zkpi::QuorumApproval, String> {
        let signatures = [1u16, 4, 7]
            .into_iter()
            .map(|n| {
                self.pq
                    .sign_member(n, &self.pq_keys[&n], msg, now)
                    .map_err(err)
            })
            .collect::<Result<_, _>>()?;
        self.pq.assemble(signatures, msg, now).map_err(err)
    }
    fn sign_fill(&self, fill: &mut ConfidentialFill) -> Result<(), String> {
        let msg = fill.signing_message()?;
        fill.fill.signature = frost_sign(&self.keys, &self.public, &msg)
            .serialize()
            .map_err(err)?;
        fill.fill.pq_authorization = Some(self.pq_sign(&msg, moment(200))?);
        Ok(())
    }
}

fn opening(
    nonce: [u8; 32],
    name: &str,
    value: u64,
    blind: Scalar,
    recipient: &Wallet,
    claim_context: [u8; 32],
    authorization: ClaimAuthorizationCommitment,
) -> Result<ApplicationOpening, String> {
    let context = opening_context(&nonce, name)?;
    let a = Scalar::random(&mut OsRng);
    let b = Scalar::random(&mut OsRng);
    let c = Scalar::random(&mut OsRng);
    let d = Scalar::random(&mut OsRng);
    let shares = (1..=7)
        .map(|n| {
            let x = Scalar::from(n as u64);
            encrypt_opening_share(
                context,
                n,
                Scalar::from(value) + a * x + b * x * x,
                blind + c * x + d * x * x,
                &recipient.address.view,
                &recipient.address.opening_public,
                &mut OsRng,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    ApplicationOpening::from_domain(
        &OpeningEnvelope::new(context, 3, recipient.address.view, shares)?,
        claim_context,
        authorization,
    )
}

struct AssetWitness {
    identity: AssetIdentity,
    gamma: Scalar,
    asset: [u8; 32],
}
impl AssetWitness {
    fn new(registry: &Registry, asset: [u8; 32]) -> Result<Self, String> {
        let gamma = Scalar::random(&mut OsRng);
        let rho = Scalar::random(&mut OsRng);
        Ok(Self {
            identity: AssetIdentity::create(registry.clone(), &asset, &gamma, &rho, &mut OsRng)?,
            gamma,
            asset,
        })
    }
}

fn issue_note(
    run: &mut Run,
    issuer: &CsdIssuerDefinition,
    signing: &SigningKey,
    pq: &MlDsa65Signer,
    asset: &AssetWitness,
    recipient: &Wallet,
    amount: u64,
    label: &str,
) -> Result<(), String> {
    let key = ca::key();
    let tag = ca_point(asset.identity.tag)?;
    let r = Scalar::random(&mut OsRng);
    let effective = asset.gamma * Scalar::from(amount) + r;
    let note = NoteLedger::new(key.clone(), 32).build_confidential_note(
        &recipient.address,
        amount,
        key.with_value_generator(tag).commit_u64(amount, &r),
        &effective,
        &asset.asset,
        &asset.gamma,
        &mut OsRng,
    )?;
    let issuance = NoteIssuance {
        operation_id: id(&format!("issue-{label}")),
        issuance_nonce: id(&format!("nonce-{label}")),
        issuer_id: issuer.issuer_id,
        issued_at: moment(100),
        output: NoteOutput::from_note(&note, asset.identity.commitment, ZERO)?,
        proof_digest: ZERO,
        issuer_signature: Signature::from_bytes(&[0; 64]),
        issuer_pq_signature: vec![],
    };
    let range =
        ConfidentialIssuance::prove_range(&issuance, &asset.identity, 32, amount, &r, &mut OsRng)?;
    let mut order = ConfidentialIssuance {
        issuance,
        identity: asset.identity.clone(),
        amount_bits: 32,
        range_proof: range,
    };
    order.issuance.proof_digest = order.proof_digest()?;
    order.issuance = order.issuance.sign_issuer(signing, pq)?;
    let n = &order.issuance;
    run.submit("defmivm.issueConfidentialNote", json!({"issuance": {"operationID": hex::encode(n.operation_id),
        "issuanceNonce": hex::encode(n.issuance_nonce), "issuerID": hex::encode(n.issuer_id), "issuedAt": n.issued_at,
        "output": note_json(&n.output), "proofDigest": hex::encode(n.proof_digest),
        "issuerSignature": hex::encode(n.issuer_signature.to_bytes()), "issuerPqSignature": hex::encode(&n.issuer_pq_signature)},
        "identity": order.identity, "amountBits": 32, "rangeProof": BASE64.encode(&order.range_proof)}), Some(order.statement()?), moment(100))
}
#[allow(clippy::too_many_arguments)]
fn grant_facility(
    run: &mut Run,
    guarantor: &GuarantorDefinition,
    signing: &SigningKey,
    pq: &MlDsa65Signer,
    asset: &AssetIdentity,
    facility: [u8; 32],
    entity: [u8; 32],
    capacity_value: u64,
    capacity_blind: Scalar,
    label: &str,
) -> Result<(), String> {
    let key = ca::key();
    let capacity = key
        .commit_u64(capacity_value, &capacity_blind)
        .compress()
        .to_bytes();
    let mut grant = CreditFacilityGrant {
        operation_id: id(&format!("grant-{label}")),
        facility_id: facility,
        guarantor_id: guarantor.guarantor_id,
        beneficiary_commitment: entity,
        rail_asset_id: asset.commitment,
        cap_commitment: capacity,
        available_commitment: capacity,
        held_commitment: ZERO,
        outstanding_commitment: ZERO,
        collateral_commitment: capacity,
        risk_policy_digest: guarantor.risk_policy_digest,
        relation_proof_digest: id("rough-guarantor-initial-capacity-attestation"),
        valid_from: 1,
        valid_until: moment(1000),
        nonce: id(&format!("grant-nonce-{label}")),
        guarantor_signature: vec![],
    };
    grant.guarantor_signature = sign_guarantor_message(signing, pq, &grant.guarantor_message()?)?;
    run.submit("defmivm.issueCreditGrant", json!({"grant": {"operationID": hex::encode(grant.operation_id), "facilityID": hex::encode(grant.facility_id),
            "guarantorID": hex::encode(grant.guarantor_id), "beneficiaryCommitment": hex::encode(grant.beneficiary_commitment),
            "railAssetID": hex::encode(grant.rail_asset_id), "capCommitment": hex::encode(capacity), "availableCommitment": hex::encode(capacity),
            "heldCommitment": hex::encode(ZERO), "outstandingCommitment": hex::encode(ZERO), "collateralCommitment": hex::encode(capacity),
            "riskPolicyDigest": hex::encode(grant.risk_policy_digest), "relationProofDigest": hex::encode(grant.relation_proof_digest),
            "validFrom": 1, "validUntil": moment(1000), "nonce": hex::encode(grant.nonce), "guarantorSignature": hex::encode(&grant.guarantor_signature)}}),
            Some(grant.statement()?), moment(100))?;
    Ok(())
}

fn ca_point(bytes: [u8; 32]) -> Result<curve25519_dalek::RistrettoPoint, String> {
    defmi::confidential_assets::point(&bytes)
}

fn reserve(
    run: &mut Run,
    scope: &ApplicationReserveScope,
    witness: &AssetWitness,
    wallet: &Wallet,
    facility: [u8; 32],
    hold: [u8; 32],
    entity: [u8; 32],
    amount: u64,
    capacity_blind: Scalar,
    amount_blind: Scalar,
    label: &str,
) -> Result<(), String> {
    let key = ca::key();
    let commit = |v, r| key.commit_u64(v, &r).compress().to_bytes();
    let participant = HybridSigner::generate().map_err(err)?;
    let mandate = ApplicationReserveMandate {
        version: 2,
        scope: scope.clone(),
        request_commitment: id(&format!("request-{label}")),
        facility_id: facility,
        hold_id: hold,
        asset_id: witness.identity.commitment,
        amount_commitment: commit(amount, amount_blind),
        participant_handle: wallet.address.view.compress().to_bytes(),
        entity_commitment: entity,
        credential_digest: id("rough-private-dekyx-not-exercised"),
        settlement_terms_commitment: commit(1, Scalar::random(&mut OsRng)),
        valid_from: moment(100),
        valid_until: moment(900),
        participant_public: participant.public_key(),
        signature: vec![],
    }
    .sign(&participant)?;
    let mut transition = CreditFacilityTransition {
        operation_id: id(&format!("reserve-{label}")),
        facility_id: facility,
        hold_id: hold,
        kind: CreditTransitionKind::Hold,
        query_commitment: mandate.request_commitment,
        amount_commitment: mandate.amount_commitment,
        consumed_commitment: ZERO,
        refund_commitment: ZERO,
        before_available_commitment: commit(amount * 2, capacity_blind),
        after_available_commitment: commit(amount, capacity_blind - amount_blind),
        before_held_commitment: ZERO,
        after_held_commitment: mandate.amount_commitment,
        before_outstanding_commitment: ZERO,
        after_outstanding_commitment: ZERO,
        before_sequence: 0,
        expires_at: moment(900),
        settlement_digest: ZERO,
        relation_proof_digest: ZERO,
    };
    let relation = CreditFacilityRelationProof::prove(
        &mut transition,
        [amount, amount, 0, amount],
        [
            capacity_blind - amount_blind,
            amount_blind,
            Scalar::ZERO,
            amount_blind,
        ],
        [0, 0],
        [Scalar::ZERO; 2],
        &mut OsRng,
    )?;
    let binding = mandate.binding()?;
    let context = ConfidentialReservation::spend_context(&binding, &transition, &witness.identity)?;
    let (ledger, notes, tags) = run.ledger()?;
    let (index, selected) = ledger
        .scan_confidential(wallet, &tags)
        .into_iter()
        .find(|(i, o)| {
            o.asset_id == witness.asset
                && o.opening.value == amount + 10
                && notes[*i].lock_id == ZERO
        })
        .ok_or("recipient did not recover the expected funding asset and amount")?;
    let ring = choose_ring(&notes, index)?;
    let spend = ledger.build_confidential_spend(
        &ring,
        index,
        &selected.opening,
        &witness.asset,
        &ca_point(witness.identity.tag)?,
        &witness.gamma,
        &[(wallet.address, amount), (wallet.address, 10)],
        &vec![true; ring.len()],
        &context,
        &mut OsRng,
    )?;
    let canonical_ring = ring.iter().map(|i| notes[*i].clone()).collect::<Vec<_>>();
    let projected = ca::project_spend(
        &canonical_ring,
        &spend.proof,
        &spend.notes,
        &witness.identity,
        ZERO,
        &[hold, ZERO],
        32,
        &context,
        &mut OsRng,
    )?;
    let escrow_id = projected.outputs[0].note_id;
    let dummy = ValueLink {
        t_first: ZERO,
        t_second: ZERO,
        z_value: ZERO,
        z_first: ZERO,
        z_second: ZERO,
    };
    let mut order = ConfidentialReservation {
        reservation: ApplicationNoteReservation {
            binding,
            transition,
            escrow: NoteReservationEscrow {
                spend: projected,
                escrow_note_id: escrow_id,
                delegation_digest: mandate.delegation_digest()?,
            },
            relation_proof: relation.to_bytes()?,
            spend_proof: encode_spend_proof(&spend.proof)?,
        },
        identity: witness.identity.clone(),
        value_link: dummy,
    };
    order.value_link = ValueLink::prove(
        &ca_point(witness.identity.tag)?,
        &key.g,
        &spend.notes[0].value_commitment,
        &key.commit_u64(amount, &amount_blind),
        amount,
        &spend.tagged_blindings[0],
        &amount_blind,
        &order.value_context()?,
        &mut OsRng,
    )?;
    let r = &order.reservation;
    run.submit("defmivm.issueConfidentialNoteReservation", json!({"binding": r.binding, "transition": transition_json(&r.transition),
        "escrow": {"spend": spend_json(&r.escrow.spend), "escrowNoteID": hex::encode(r.escrow.escrow_note_id),
            "delegationDigest": hex::encode(r.escrow.delegation_digest)}, "relationProof": BASE64.encode(&r.relation_proof),
        "spendProof": BASE64.encode(&r.spend_proof), "identity": order.identity, "valueLink": order.value_link}), Some(order.statement()?), moment(100))
}

fn choose_ring(notes: &[NoteOutput], selected: usize) -> Result<Vec<usize>, String> {
    let mut ring = vec![selected];
    for (i, n) in notes.iter().enumerate() {
        if i != selected && n.lock_id == ZERO && ring.len() < 4 {
            ring.push(i);
        }
    }
    if ring.len() != 4 {
        return Err("rough run needs four available mixed-asset ring notes".into());
    }
    ring.sort_unstable();
    Ok(ring)
}

#[derive(Clone, Copy)]
struct Amounts {
    values: [u64; 2],
    blindings: [Scalar; 2],
}

#[allow(clippy::too_many_arguments)]
fn make_fill(
    run: &Run,
    committee: &Committee,
    scope: &ApplicationReserveScope,
    assets: [&AssetWitness; 2],
    wallets: &[Wallet; 2],
    holds: [[u8; 32]; 2],
    prior: Amounts,
    quantity: u64,
    label: &str,
    close: [bool; 2],
    authorizations: &mut BTreeMap<[u8; 32], NoteClaimAuthorization>,
) -> Result<(ConfidentialFill, Amounts), String> {
    let key = ca::key();
    let values = [quantity, quantity * 10];
    let blinds = [Scalar::random(&mut OsRng), Scalar::random(&mut OsRng)];
    let deltas = [Scalar::random(&mut OsRng), Scalar::random(&mut OsRng)];
    let next = Amounts {
        values: [prior.values[0] - values[0], prior.values[1] - values[1]],
        blindings: [
            prior.blindings[0] - blinds[0],
            prior.blindings[1] - blinds[1],
        ],
    };
    let price_blind = Scalar::random(&mut OsRng);
    let asset_blind = Scalar::random(&mut OsRng);
    let amount = key.commit_u64(quantity, &blinds[0]);
    let cash = key.commit_u64(values[1], &blinds[1]);
    let asset = key.commit(&zkpi::asset_scalar(&assets[0].asset), &asset_blind);
    let nonce = id(&format!("fill-nonce-{label}"));
    let result = id(&format!("synthetic-match-{label}"));
    let partial = PartialInstruction::from_threshold_ranges(
        &key,
        &Bounds {
            amount_bits: 32,
            price_bits: 32,
            max_horizon: 3600,
        },
        amount,
        key.commit_u64(10, &price_blind),
        asset,
        threshold_range(&key, quantity, blinds[0], 32, AMOUNT_RANGE_CONTEXT),
        threshold_range(&key, 10, price_blind, 32, PRICE_RANGE_CONTEXT),
        wallets[1].address.view,
        wallets[0].address.view,
        moment(800),
        nonce,
        result,
    )
    .map_err(err)?;
    let msg = partial.digest_for(DEFAULT_DOMAIN);
    let payment = partial.sealed_hybrid(
        frost_sign(&committee.keys, &committee.public, &msg),
        committee.pq_sign(&msg, moment(200))?,
    );
    let recipients = [1, 0, 0, 1];
    let kinds = [
        NoteClaimKind::Delivery,
        NoteClaimKind::Refund,
        NoteClaimKind::Delivery,
        NoteClaimKind::Refund,
    ];
    let names = [
        "securities_delivery",
        "securities_refund",
        "cash_delivery",
        "cash_refund",
    ];
    let mut auths = Vec::new();
    for index in 0..4 {
        let recipient = note_claim_recipient_commitment(
            wallets[recipients[index]]
                .address
                .view
                .compress()
                .to_bytes(),
            payment.nullifier(),
            assets[index / 2].identity.commitment,
            holds[index / 2],
            kinds[index],
        )?;
        let auth = NoteClaimAuthorization::generate(recipient, 1, moment(10_000))?;
        let commitment = auth.commitment()?;
        authorizations.insert(commitment.key_fingerprint, auth);
        auths.push(commitment);
    }
    let proofs = DvpProofs {
        product: prove_product(
            &key,
            &mut Transcript::new(DVP_PRODUCT_CONTEXT),
            &amount,
            &Scalar::from(quantity),
            &blinds[0],
            &Scalar::from(10u64),
            &price_blind,
            &blinds[1],
            &mut OsRng,
        ),
        securities_remainder: threshold_range(
            &key,
            next.values[0],
            next.blindings[0] + deltas[0],
            32,
            DVP_SECURITIES_REMAINDER_CONTEXT,
        ),
        cash_remainder: threshold_range(
            &key,
            next.values[1],
            next.blindings[1] + deltas[1],
            32,
            DVP_CASH_REMAINDER_CONTEXT,
        ),
    };
    let head = |i: usize| {
        let record = &run.state.application_reservations[&id_key(&holds[i])];
        ApplicationSpendHead {
            hold_id: holds[i],
            sequence: record.sequence,
            previous_receipt: record.head_receipt(),
            remaining_commitment: record.remaining(),
            reserve_reblinding: deltas[i].to_bytes(),
            close: close[i],
        }
    };
    let all_values = [values[0], next.values[0], values[1], next.values[1]];
    let normal_blinds = [blinds[0], next.blindings[0], blinds[1], next.blindings[1]];
    let encrypted_blinds = [
        blinds[0],
        next.blindings[0] + deltas[0],
        blinds[1],
        next.blindings[1] + deltas[1],
    ];
    let openings = (0..4)
        .map(|i| {
            opening(
                nonce,
                names[i],
                all_values[i],
                encrypted_blinds[i],
                &wallets[recipients[i]],
                payment.nullifier(),
                auths[i],
            )
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "opening dimensions")?;
    let fill = ApplicationNoteFill {
        version: 3,
        scope: scope.clone(),
        before_root: run.state.root(),
        operation_id: id(&format!("fill-{label}")),
        mpc_result_digest: result,
        securities_asset: assets[0].identity.commitment,
        cash_asset: assets[1].identity.commitment,
        securities: head(0),
        cash: head(1),
        instruction: zkpi::wire::encode(&payment),
        dvp_proofs: encode_dvp_proofs(&proofs)?,
        cash_commitment: cash.compress().to_bytes(),
        asset_link_announcement: ZERO,
        asset_link_response: ZERO,
        openings,
        committee_public: committee.public.serialize().map_err(err)?,
        pq_committee: committee.pq.clone(),
        signature: vec![],
        pq_authorization: None,
        batch: None,
    };
    let securities_asset_link = AssetProof::prove(
        &key,
        &assets[0].identity.registry,
        &assets[0].asset,
        &ca_point(assets[0].identity.tag)?,
        &assets[0].gamma,
        Some((&asset, &asset_blind)),
        &ConfidentialFill::asset_context(&fill)?,
        &mut OsRng,
    )?;
    let mut conversions = Vec::new();
    for i in 0..4 {
        let witness = assets[i / 2];
        let tagged_blind = Scalar::random(&mut OsRng);
        let value_commitment = key
            .with_value_generator(ca_point(witness.identity.tag)?)
            .commit_u64(all_values[i], &tagged_blind);
        let effective = tagged_blind + witness.gamma * Scalar::from(all_values[i]);
        let encrypted = opening(
            nonce,
            names[i],
            all_values[i],
            effective,
            &wallets[recipients[i]],
            payment.nullifier(),
            auths[i],
        )?;
        let normalized = key.commit_u64(all_values[i], &normal_blinds[i]);
        let context = ClaimConversion::value_context(
            &ConfidentialFill::conversion_context(&fill, i)?,
            &normalized.compress().to_bytes(),
            &witness.identity.tag,
            &value_commitment.compress().to_bytes(),
            &encrypted,
        )?;
        let value_link = ValueLink::prove(
            &key.g,
            &ca_point(witness.identity.tag)?,
            &normalized,
            &value_commitment,
            all_values[i],
            &normal_blinds[i],
            &tagged_blind,
            &context,
            &mut OsRng,
        )?;
        let claim = application_claim(
            witness.identity.commitment,
            holds[i / 2],
            value_commitment.compress().to_bytes(),
            kinds[i],
            &encrypted,
        )?;
        let asset_opening = ca::seal_claim_asset(
            &claim,
            &wallets[recipients[i]].address.opening_public,
            &witness.asset,
            &witness.gamma,
            &witness.identity.tag,
        )?;
        conversions.push(ClaimConversion {
            value_commitment: value_commitment.compress().to_bytes(),
            opening: encrypted,
            asset_opening,
            value_link,
        });
    }
    let mut order = ConfidentialFill {
        fill,
        securities_asset_link,
        conversions: conversions
            .try_into()
            .map_err(|_| "conversion dimensions")?,
    };
    order.verify_unsigned(
        scope,
        [&assets[0].identity, &assets[1].identity],
        moment(200),
    )?;
    committee.sign_fill(&mut order)?;
    Ok((order, next))
}

fn main() -> Result<(), String> {
    native::reset_epoch();
    let output = PathBuf::from(
        env::var("DEFMI_ASSET_PRIVACY_RUN_DIR")
            .map_err(|_| "launch through the outcome-first harness")?,
    );
    let manifest: Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json")).map_err(err)?)
            .map_err(err)?;
    if manifest["milestone"] != "RUN_ROUGH_END_TO_END_AND_OBSERVE_FINAL_METRIC"
        || manifest["closed"] != true
        || !output.join("launch.json").is_file()
        || output.join("outcome.json").exists()
    {
        return Err("closed result-first launch is absent or already completed".into());
    }
    let started = Instant::now();
    let mut run = Run::new(output.clone())?;
    let asset_ids = [id("rough-bond-A"), id("rough-cash-B")];
    let registered_assets = [
        asset_ids[0],
        asset_ids[1],
        id("rough-bond-C"),
        id("rough-cash-D"),
    ];
    let mut eligible = registered_assets.to_vec();
    eligible.sort();
    let registry = Registry { assets: eligible };
    for (i, asset) in registered_assets.iter().enumerate() {
        let definition = AssetDefinition {
            asset_id: *asset,
            code: format!("ROUGH{i}"),
            kind: if i % 2 == 0 {
                AssetKind::Security
            } else {
                AssetKind::Cash
            },
            decimals: 0,
            terms_digest: id(&format!("terms-{i}")),
        };
        run.submit("defmivm.issueAsset", json!({"asset": {"assetID": hex::encode(asset), "code": definition.code,
            "kind": definition.kind.as_str(), "decimals": 0, "termsDigest": hex::encode(definition.terms_digest)}}), Some(definition.statement()?), moment(100))?;
    }
    let signing = SigningKey::from_bytes(&random_bytes());
    let pq = MlDsa65Signer::from_seed(&random_bytes());
    let issuer = CsdIssuerDefinition {
        issuer_id: id("rough-csd"),
        code: "ROUGH-CSD".into(),
        jurisdiction: "JP".into(),
        operator_entity_commitment: id("rough-csd-entity"),
        public_key: signing.verifying_key().to_bytes(),
        pq_public_key: pq.public_key(),
        permitted_asset_ids: registry.assets.clone(),
        policy_digest: id("rough-csd-policy"),
        valid_from: 1,
        valid_until: moment(10_000),
    };
    run.submit("defmivm.issueCSDIssuer", json!({"issuer": {"issuerID": hex::encode(issuer.issuer_id), "code": issuer.code,
        "jurisdiction": issuer.jurisdiction, "operatorEntityCommitment": hex::encode(issuer.operator_entity_commitment),
        "publicKey": hex::encode(issuer.public_key), "pqPublicKey": hex::encode(&issuer.pq_public_key),
        "permittedAssetIDs": issuer.permitted_asset_ids.iter().map(hex::encode).collect::<Vec<_>>(),
        "policyDigest": hex::encode(issuer.policy_digest), "validFrom": 1, "validUntil": moment(10_000)}}), Some(issuer.statement()?), moment(100))?;
    let views = [Scalar::random(&mut OsRng), Scalar::random(&mut OsRng)];
    let wallets = views.map(|view| {
        let mut seed = [0; 96];
        OsRng.fill_bytes(&mut seed);
        Wallet::from_parts(
            view,
            Scalar::random(&mut OsRng),
            zkfmi_crypto::hybrid::kem::HybridKemKey::from_seed(&seed),
        )
    });
    let decoy = Wallet::new(&mut OsRng);
    for (i, value) in [110u64, 1010, 25, 25, 0].into_iter().enumerate() {
        let asset = AssetWitness::new(&registry, asset_ids[i % 2])?;
        let recipient = if i < 2 {
            &wallets[i]
        } else if i == 4 {
            &wallets[0]
        } else {
            &decoy
        };
        issue_note(
            &mut run,
            &issuer,
            &signing,
            &pq,
            &asset,
            recipient,
            value,
            &format!("initial-{i}"),
        )?;
    }
    let funding = [
        AssetWitness::new(&registry, asset_ids[0])?,
        AssetWitness::new(&registry, asset_ids[1])?,
    ];
    for asset in &funding {
        run.submit(
            "defmivm.issueConfidentialAssetIdentity",
            json!({"identity": asset.identity}),
            Some(asset.identity.statement()?),
            moment(100),
        )?;
    }
    let guarantor = GuarantorDefinition {
        guarantor_id: id("rough-guarantor"),
        kind: GuarantorKind::Bank,
        name: "Synthetic privacy acceptance guarantor".into(),
        public_key: signing.verifying_key().to_bytes(),
        pq_public_key: pq.public_key(),
        risk_policy_digest: id("rough-risk-policy"),
    };
    run.submit("defmivm.issueGuarantor", json!({"guarantor": {"guarantorID": hex::encode(guarantor.guarantor_id),
        "kind": guarantor.kind.as_str(), "name": guarantor.name, "publicKey": hex::encode(guarantor.public_key),
        "pqPublicKey": hex::encode(&guarantor.pq_public_key), "riskPolicyDigest": hex::encode(guarantor.risk_policy_digest)}}),
        Some(guarantor.statement()?), moment(100))?;
    let capacity_blinds = [Scalar::random(&mut OsRng), Scalar::random(&mut OsRng)];
    let facilities = [id("rough-facility-A"), id("rough-facility-B")];
    let holds = [id("rough-hold-A"), id("rough-hold-B")];
    let entities = [id("rough-entity-A"), id("rough-entity-B")];
    for i in 0..2 {
        grant_facility(
            &mut run,
            &guarantor,
            &signing,
            &pq,
            &funding[i].identity,
            facilities[i],
            entities[i],
            [200, 2000][i],
            capacity_blinds[i],
            &format!("{i}"),
        )?;
    }
    let committee = Committee::new()?;
    let scope = ApplicationReserveScope {
        application_binding: id("rough-app"),
        venue_id: id("rough-venue"),
        defmi_id: id("rough-defmi"),
        committee_key_digest: Sha256::digest(committee.public.serialize().map_err(err)?).into(),
        pq_committee_digest: committee.pq.digest().map_err(err)?,
        committee_epoch: 1,
        amount_bits: 32,
    };
    run.submit(
        "defmivm.issueApplicationReserveScope",
        json!({"scope": scope}),
        Some(scope.statement()?),
        moment(100),
    )?;
    let initial = Amounts {
        values: [100, 1000],
        blindings: [Scalar::random(&mut OsRng), Scalar::random(&mut OsRng)],
    };
    for i in 0..2 {
        reserve(
            &mut run,
            &scope,
            &funding[i],
            &wallets[i],
            facilities[i],
            holds[i],
            entities[i],
            initial.values[i],
            capacity_blinds[i],
            initial.blindings[i],
            &format!("{i}"),
        )?;
    }
    // Exercise both untouched-reservation returns using the decoy owner's
    // real notes. Their balances must return to 25 of each asset.
    let unused_holds = [id("unfilled-expiry-hold"), id("unfilled-cancel-hold")];
    for i in 0..2 {
        let label = format!("unfilled-{i}");
        let facility = id(&format!("{label}-facility"));
        let entity = id(&format!("{label}-entity"));
        let capacity_blind = Scalar::random(&mut OsRng);
        grant_facility(
            &mut run,
            &guarantor,
            &signing,
            &pq,
            &funding[i].identity,
            facility,
            entity,
            30,
            capacity_blind,
            &label,
        )?;
        reserve(
            &mut run,
            &scope,
            &funding[i],
            &decoy,
            facility,
            unused_holds[i],
            entity,
            15,
            capacity_blind,
            Scalar::random(&mut OsRng),
            &label,
        )?;
    }
    let untouched = &run.state.application_reservations[&id_key(&unused_holds[1])];
    let mut cancel = ApplicationNoteRelease {
        scope: scope.clone(),
        before_root: run.state.root(),
        operation_id: id("cancel-unfilled"),
        hold_id: unused_holds[1],
        sequence: untouched.sequence,
        previous_receipt: untouched.head_receipt(),
        reason: ApplicationReleaseReason::Cancelled,
        committee_public: committee.public.serialize().map_err(err)?,
        pq_committee: Some(committee.pq.clone()),
        signature: vec![],
        pq_authorization: None,
    };
    let cancel_message = cancel.signing_message()?;
    cancel.signature = frost_sign(&committee.keys, &committee.public, &cancel_message)
        .serialize()
        .map_err(err)?;
    cancel.pq_authorization = Some(committee.pq_sign(&cancel_message, moment(200))?);
    run.submit(
        "defmivm.issueApplicationNoteRelease",
        json!({"release":cancel}),
        None,
        moment(200),
    )?;
    let mut authorizations = BTreeMap::new();
    let (first, next) = make_fill(
        &run,
        &committee,
        &scope,
        [&funding[0], &funding[1]],
        &wallets,
        holds,
        initial,
        40,
        "first",
        [false; 2],
        &mut authorizations,
    )?;
    // Re-sign malformed asset/value relations so rejection cannot be credited
    // only to an invalid committee certificate.
    let mut wrong_asset = first.clone();
    let z =
        defmi::confidential_assets::scalar(&wrong_asset.securities_asset_link.tag_responses[0])?;
    wrong_asset.securities_asset_link.tag_responses[0] = (z + Scalar::ONE).to_bytes();
    committee.sign_fill(&mut wrong_asset)?;
    run.reject(
        "signed-invalid-asset-link",
        "defmivm.issueConfidentialNoteFill",
        json!({"fill":wrong_asset}),
        None,
        moment(200),
        "asset membership/link proof failed",
    )?;
    let mut substituted_asset = first.clone();
    let (attack_ledger, attack_notes, attack_tags) = run.ledger()?;
    let other_cash = attack_ledger
        .scan_confidential(&wallets[1], &attack_tags)
        .into_iter()
        .find(|(i, o)| {
            o.asset_id == asset_ids[1]
                && attack_notes[*i].asset_id != funding[1].identity.commitment
        })
        .ok_or("asset substitution case lacks a distinct cash identity")?
        .0;
    substituted_asset.fill.securities_asset = attack_notes[other_cash].asset_id;
    committee.sign_fill(&mut substituted_asset)?;
    run.reject(
        "signed-substituted-asset",
        "defmivm.issueConfidentialNoteFill",
        json!({"fill":substituted_asset}),
        None,
        moment(200),
        "asset membership/link proof failed",
    )?;
    let mut wrong_value = first.clone();
    let z = defmi::confidential_assets::scalar(&wrong_value.conversions[0].value_link.z_value)?;
    wrong_value.conversions[0].value_link.z_value = (z + Scalar::ONE).to_bytes();
    committee.sign_fill(&mut wrong_value)?;
    run.reject(
        "signed-invalid-value-link",
        "defmivm.issueConfidentialNoteFill",
        json!({"fill":wrong_value}),
        None,
        moment(200),
        "value link failed",
    )?;
    let mut ciphertext = first.clone();
    ciphertext.conversions[0].asset_opening.ciphertext[0] ^= 1;
    run.reject(
        "changed-recipient-ciphertext",
        "defmivm.issueConfidentialNoteFill",
        json!({"fill":ciphertext}),
        None,
        moment(200),
        "committee signature is invalid",
    )?;
    run.reject(
        "confidential-fill-on-legacy-endpoint",
        "defmivm.issueApplicationNoteFill",
        json!({"fill":first.fill}),
        None,
        moment(200),
        "reservation privacy version",
    )?;
    run.submit(
        "defmivm.issueConfidentialNoteFill",
        json!({"fill": first}),
        None,
        moment(200),
    )?;
    run.reject(
        "fill-replay",
        "defmivm.issueConfidentialNoteFill",
        json!({"fill":first}),
        None,
        moment(200),
        "already applied",
    )?;
    let (second, _) = make_fill(
        &run,
        &committee,
        &scope,
        [&funding[0], &funding[1]],
        &wallets,
        holds,
        next,
        20,
        "second",
        [false; 2],
        &mut authorizations,
    )?;
    run.submit(
        "defmivm.issueConfidentialNoteFill",
        json!({"fill": second}),
        None,
        moment(200),
    )?;
    native::wait_expiry();
    for hold in holds.into_iter().chain([unused_holds[0]]) {
        let record = &run.state.application_reservations[&id_key(&hold)];
        let release = ApplicationNoteRelease {
            scope: scope.clone(),
            before_root: run.state.root(),
            operation_id: id(&format!("expiry-{}", hex::encode(hold))),
            hold_id: hold,
            sequence: record.sequence,
            previous_receipt: record.head_receipt(),
            reason: ApplicationReleaseReason::Expired,
            committee_public: vec![],
            pq_committee: None,
            signature: vec![],
            pq_authorization: None,
        };
        run.submit(
            "defmivm.issueApplicationNoteRelease",
            json!({"release": release}),
            None,
            moment(901),
        )?;
    }
    let claims = run.state.note_claims.clone();
    let mut recovered = Vec::new();
    for (name, record) in claims {
        let claim_id = hex::decode(&name)
            .map_err(err)?
            .try_into()
            .map_err(|_| "claim ID length")?;
        let (claim, identity, asset_opening) = if let Some(network) = &run.network {
            let canonical = network.claim(claim_id, run.state.root())?;
            let claim = canonical.claim.claim()?;
            if claim != record.claim(claim_id)? {
                return Err("native claim differs from accepted state".into());
            }
            (claim, canonical.identity, canonical.asset_opening)
        } else {
            let claim = record.claim(claim_id)?;
            let identity = run.state.confidential.identities[&id_key(&claim.asset_id)].clone();
            let asset_opening = run.state.confidential.claim_assets[&name].clone();
            (claim, identity, asset_opening)
        };
        let recipient = wallets
            .iter()
            .position(|w| w.address.view == claim.opening_envelope.recipient_view)
            .ok_or("unknown recipient")?;
        let authorization = &authorizations[&claim.authorization.key_fingerprint];
        let redemption = redeem_confidential_claim(
            &claim,
            &identity,
            &asset_opening,
            32,
            &views[recipient],
            wallets[recipient].opening_key(),
            &wallets[recipient].address,
            &[1, 4, 7],
            run.authority.domain(),
            run.state.root(),
            id(&format!("redeem-{name}")),
            authorization,
            moment(902),
            &mut OsRng,
        )?;
        run.submit(
            "defmivm.issueNoteClaimRedemption",
            json!({"redemption": redemption}),
            None,
            moment(902),
        )?;
        run.reject(
            &format!("claim-replay-{name}"),
            "defmivm.issueNoteClaimRedemption",
            json!({"redemption":redemption}),
            None,
            moment(902),
            "already applied",
        )?;
        recovered.push(json!({"claim_id": name, "recipient": recipient, "output_note": hex::encode(redemption.output.note_id)}));
    }
    // Reuse a delivered security note as a new mixed-asset anonymous spend.
    let (ledger, notes, tags) = run.ledger()?;
    let (selected, opening) = ledger
        .scan_confidential(&wallets[1], &tags)
        .into_iter()
        .find(|(_, o)| o.asset_id == asset_ids[0] && o.opening.value == 40)
        .ok_or("delivered asset cannot be recovered for reuse")?;
    let identity = AssetWitness::new(&registry, asset_ids[0])?;
    let context = TransferContext {
        before_root: run.state.root(),
        operation_id: id("reuse-delivered-asset"),
        deadline: moment(1000),
        amount_bits: 32,
        identity_statement: identity.identity.statement()?,
    };
    let ring = choose_ring(&notes, selected)?;
    let spend = ledger.build_confidential_spend(
        &ring,
        selected,
        &opening.opening,
        &asset_ids[0],
        &ca_point(identity.identity.tag)?,
        &identity.gamma,
        &[(wallets[0].address, 7), (wallets[1].address, 33)],
        &vec![true; ring.len()],
        &context.bytes()?,
        &mut OsRng,
    )?;
    let canonical_ring = ring.iter().map(|i| notes[*i].clone()).collect::<Vec<_>>();
    let projected = ca::project_spend(
        &canonical_ring,
        &spend.proof,
        &spend.notes,
        &identity.identity,
        ZERO,
        &[ZERO; 2],
        32,
        &context.bytes()?,
        &mut OsRng,
    )?;
    let transfer = ConfidentialTransfer {
        context,
        identity: identity.identity,
        spend: projected,
        spend_proof: encode_spend_proof(&spend.proof)?,
    };
    run.submit(
        "defmivm.issueConfidentialNoteTransfer",
        json!({"context": transfer.context, "identity": transfer.identity,
        "spend": spend_json(&transfer.spend), "spendProof": BASE64.encode(&transfer.spend_proof)}),
        Some(transfer.statement()?),
        moment(903),
    )?;
    let mut replay = transfer.clone();
    replay.context.before_root = run.state.root();
    replay.context.operation_id = id("replay-with-fresh-operation-and-approval");
    run.reject("spent-nullifier-fresh-approval", "defmivm.issueConfidentialNoteTransfer",
        json!({"context":replay.context,"identity":replay.identity,"spend":spend_json(&replay.spend),
            "spendProof":BASE64.encode(&replay.spend_proof)}), Some(replay.statement()?), moment(903),
        "already spent")?;
    if let Some(network) = &run.network {
        network.restart_readback(run.state.root())?;
    }
    let (ledger, notes, tags) = run.ledger()?;
    let mut balances = [[0u64; 2]; 2];
    let mut zero_asset_identified = false;
    for (recipient, wallet) in wallets.iter().enumerate() {
        for (index, value) in ledger.scan_confidential(wallet, &tags) {
            let serial = defmi::notes::note_nullifier(&value.opening.serial)
                .compress()
                .to_bytes();
            if notes[index].lock_id != ZERO || run.state.note_serials.contains_key(&id_key(&serial))
            {
                continue;
            }
            let asset = asset_ids
                .iter()
                .position(|a| *a == value.asset_id)
                .ok_or("unregistered decrypted asset")?;
            balances[recipient][asset] += value.opening.value;
            if recipient == 0 && value.opening.value == 0 && asset == 0 {
                zero_asset_identified = true;
            }
        }
    }
    let mut untouched_balances = [0u64; 2];
    for (index, value) in ledger.scan_confidential(&decoy, &tags) {
        let serial = defmi::notes::note_nullifier(&value.opening.serial)
            .compress()
            .to_bytes();
        if notes[index].lock_id != ZERO || run.state.note_serials.contains_key(&id_key(&serial)) {
            continue;
        }
        let asset = asset_ids
            .iter()
            .position(|id| *id == value.asset_id)
            .ok_or("unknown untouched-return asset")?;
        untouched_balances[asset] += value.opening.value;
    }
    let expected = [[57u64, 600u64], [53u64, 410u64]];
    let complete = balances == expected
        && untouched_balances == [25, 25]
        && zero_asset_identified
        && run
            .state
            .application_reservations
            .values()
            .all(|r| r.status == "released")
        && run
            .state
            .note_claims
            .values()
            .all(|r| r.status == "materialized");
    let outcome = json!({"verdict": if complete {"smoke_only"} else {"rejected"}, "final_metric": if complete {1} else {0},
        "metric_name": "confidential_reserve_fill_expiry_redeem_reuse_balances_match",
        "registered_cohort":{"securities":2,"cash_assets":2,"total":4}, "observed_balances": balances,
        "expected_balances": expected, "unfilled_return_balances":untouched_balances, "zero_asset_identified": zero_asset_identified, "claims": recovered,
        "rejected_operations": run.rejections, "root": hex::encode(run.state.root()), "elapsed_seconds": started.elapsed().as_secs_f64(),
        "environment": if run.network.is_some() { "five live AvalancheGo validators on one remote Linux host; native RPC, real proofs, persisted-block readback and wallet RPC recovery" } else { "remote Linux; native canonical state machine plus real cryptographic libraries and filesystem readback" },
        "native_validator_roots":run.network.as_ref().map(|network| network.roots(run.state.root())).transpose()?,
        "limitations": if run.network.is_some() { vec!["validators on one host","synthetic assets","single-process proof and committee-key construction","private DeKYX approval service not exercised","no matching service invocation","unaudited confidential asset adapter"] } else { vec!["single process","synthetic assets","no live Avalanche consensus","private DeKYX approval service not exercised","no matching service invocation","unaudited confidential asset adapter"] },
        "manifest_sha256": hex::encode(Sha256::digest(fs::read(output.join("manifest.json")).map_err(err)?))});
    fs::write(
        output.join("outcome.json"),
        serde_json::to_vec_pretty(&outcome).map_err(err)?,
    )
    .map_err(err)?;
    println!("{}", serde_json::to_string(&outcome).map_err(err)?);
    if !complete {
        return Err("final confidential lifecycle balances did not match".into());
    }
    Ok(())
}

// Fresh, seven-party FROST and threshold-range helpers are appended below.

fn frost_sign(
    keys: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: &frost::keys::PublicKeyPackage,
    message: &[u8],
) -> frost::Signature {
    let selected = keys.keys().take(3).copied().collect::<Vec<_>>();
    let mut nonces = BTreeMap::new();
    let commitments = selected
        .iter()
        .map(|id| {
            let (nonce, commitment) = frost::round1::commit(keys[id].signing_share(), &mut OsRng);
            nonces.insert(*id, nonce);
            (*id, commitment)
        })
        .collect();
    let package = frost::SigningPackage::new(commitments, message);
    let shares = selected
        .iter()
        .map(|id| {
            (
                *id,
                frost::round2::sign(&package, &nonces[id], &keys[id]).unwrap(),
            )
        })
        .collect();
    frost::aggregate(&package, &shares, public).unwrap()
}

fn threshold_range(
    key: &Pedersen,
    value: u64,
    blinding: Scalar,
    bits: usize,
    context: &[u8],
) -> zkpi_proofs::threshold_range::ThresholdRangeProof {
    let parties = [1_usize, 2, 3, 4, 5, 6, 7];
    let dealt = deal_bits(key, value, &blinding, bits, &parties, 2, &mut OsRng).unwrap();
    let quorum = [1_usize, 4, 7];
    let contributions = quorum
        .iter()
        .map(|party| dealt.node_contribution(*party).unwrap())
        .collect::<Vec<_>>();
    joint_prove_range_from_contributions(key, &contributions, &quorum, context, &mut OsRng)
        .unwrap()
        .0
}
