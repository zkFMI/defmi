use super::*;

use std::collections::BTreeMap;

use qomm_defmi::cross_domain::{hash_release_witness, LegStatus};
use qomm_defmi::facility::QuorumApproval;
use serde_json::{json, Map, Value};
use zkfmi_crypto::{hybrid::signature::HybridSigner, key::KeyPurpose, traits::Signer as _};

fn local_committee() -> (
    QuorumAuthorizer,
    BTreeMap<String, qomm_defmi::governance::GovernanceSigner>,
) {
    let signers = (0u8..3)
        .map(|index| {
            (
                format!("node-{index}"),
                qomm_defmi::governance::GovernanceSigner::generate(
                    &format!("node-{index}"),
                    0,
                    i64::MAX as u64,
                )
                .unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let nodes = signers
        .iter()
        .map(|(node, key)| (node.clone(), key.verifying_key()))
        .collect();
    (
        QuorumAuthorizer::new(nodes, 2, 1, "test-chain").unwrap(),
        signers,
    )
}

fn approval_json(approval: &QuorumApproval) -> Value {
    json!({
        "statement": hex::encode(approval.statement),
        "signerEpoch": approval.signer_epoch,
        "suite": approval.suite,
        "committeeDigest": hex::encode(approval.committee_digest),
        "domain": approval.domain,
        "beforeRoot": hex::encode(approval.before_root),
        "approvals": approval.approvals.iter().map(|signed| json!({
            "nodeID": signed.node_id,
            "signature": hex::encode(&signed.signature),
        })).collect::<Vec<_>>(),
    })
}

fn domain_json(domain: &CrossDomain) -> Value {
    json!({
        "networkID": domain.network_id,
        "chainID": hex::encode(domain.chain_id),
        "defmiID": hex::encode(domain.defmi_id),
    })
}

fn receipt_committee(
    domain: CrossDomain,
    marker: u8,
) -> (CrossDomainCommittee, BTreeMap<[u8; 32], HybridSigner>) {
    let keys = (0u8..3)
        .map(|offset| {
            let id = [marker + offset; 32];
            (id, HybridSigner::generate().unwrap())
        })
        .collect::<BTreeMap<_, _>>();
    let members = keys
        .iter()
        .map(|(id, key)| {
            (
                *id,
                CrossDomainCommitteeMember {
                    member_id: *id,
                    key: finality_key(*id, key),
                    weight: 1,
                },
            )
        })
        .map(|(_, member)| member)
        .collect();
    (
        CrossDomainCommittee {
            domain,
            epoch: 1,
            quorum_weight: 2,
            members,
        },
        keys,
    )
}

fn committee_json(committee: &CrossDomainCommittee) -> Value {
    json!({
        "domain": domain_json(&committee.domain),
        "epoch": committee.epoch,
        "quorumWeight": committee.quorum_weight,
        "members": committee.members.iter().map(|member| json!({
            "memberID": hex::encode(member.member_id),
            "key": member.key,
            "weight": member.weight,
        })).collect::<Vec<_>>(),
    })
}

fn prepare_json(prepare: &CrossDomainPrepareLeg) -> Value {
    json!({
        "localDomain": domain_json(&prepare.local_domain),
        "remoteDomain": domain_json(&prepare.remote_domain),
        "localLegID": hex::encode(prepare.local_leg_id),
        "expectedRemotePrepareBinding": hex::encode(prepare.expected_remote_prepare_binding),
        "expectedRemoteClaimBinding": hex::encode(prepare.expected_remote_claim_binding),
        "ownerCommitment": hex::encode(prepare.owner_commitment),
        "escrowCommitment": hex::encode(prepare.escrow_commitment),
        "destinationCommitment": hex::encode(prepare.destination_commitment),
        "assetCommitment": hex::encode(prepare.asset_commitment),
        "amountCommitment": hex::encode(prepare.amount_commitment),
        "localInstructionDigest": hex::encode(prepare.local_instruction_digest),
        "localRelationProofDigest": hex::encode(prepare.local_relation_proof_digest),
        "reserveTransferDigest": hex::encode(prepare.reserve_transfer_digest),
        "claimTransferDigest": hex::encode(prepare.claim_transfer_digest),
        "refundTransferDigest": hex::encode(prepare.refund_transfer_digest),
        "armDeadline": prepare.arm_deadline,
        "claimDeadline": prepare.claim_deadline,
        "refundAfter": prepare.refund_after,
        "releaseCondition": hex::encode(prepare.release_condition),
    })
}

fn settlement_json(order: &SettlementOrder) -> Value {
    json!({
        "operationID": hex::encode(order.operation_id),
        "nullifier": hex::encode(order.nullifier),
        "deadline": order.deadline,
        "paymentInstructionDigest": hex::encode(order.payment_instruction_digest),
        "proofDigest": hex::encode(order.proof_digest),
        "marketStatementDigest": hex::encode(order.market_statement_digest),
        "legs": order.legs.iter().map(|leg| json!({
            "handle": hex::encode(leg.handle),
            "assetID": hex::encode(leg.asset_id),
            "beforeCommitment": hex::encode(leg.before_commitment),
            "afterCommitment": hex::encode(leg.after_commitment),
            "beforeSequence": leg.before_sequence,
        })).collect::<Vec<_>>(),
    })
}

fn receipt_json(receipt: &FinalityReceipt) -> Value {
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
        "suite": receipt.suite,
        "committeeDigest": hex::encode(receipt.committee_digest),
        "signatures": receipt.signatures.iter().map(|signed| json!({
            "memberID": hex::encode(signed.member_id),
            "signature": hex::encode(&signed.signature),
        })).collect::<Vec<_>>(),
    })
}

fn sign_receipt(
    mut receipt: FinalityReceipt,
    keys: &BTreeMap<[u8; 32], HybridSigner>,
) -> FinalityReceipt {
    let digest = receipt.signing_digest();
    receipt.signatures = keys
        .iter()
        .take(2)
        .map(|(member_id, key)| ReceiptSignature {
            member_id: *member_id,
            signature: key.sign(KeyPurpose::Attestation, &digest).unwrap(),
        })
        .collect();
    receipt
}

fn authorized_transaction(
    state: &State,
    authorizer: &QuorumAuthorizer,
    signers: &BTreeMap<String, qomm_defmi::governance::GovernanceSigner>,
    method: &str,
    mut params: Map<String, Value>,
    statement: [u8; 32],
) -> Vec<u8> {
    let root = state.root();
    let approval = authorizer.approve(statement, root, signers).unwrap();
    params.insert("approval".into(), approval_json(&approval));
    params.insert("expectedBeforeRoot".into(), json!(hex::encode(root)));
    TransactionEnvelope::new(method, Value::Object(params))
        .unwrap()
        .encode()
        .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn apply_single(
    state: &mut State,
    authorizer: &QuorumAuthorizer,
    signers: &BTreeMap<String, qomm_defmi::governance::GovernanceSigner>,
    method: &str,
    field: &str,
    value: Value,
    statement: [u8; 32],
    timestamp: u64,
) {
    let mut params = Map::new();
    params.insert(field.into(), value);
    let transaction = authorized_transaction(state, authorizer, signers, method, params, statement);
    state.apply(&transaction, authorizer, timestamp).unwrap();
}

fn install_domains(
    state: &mut State,
    authorizer: &QuorumAuthorizer,
    signers: &BTreeMap<String, qomm_defmi::governance::GovernanceSigner>,
    local: &CrossDomain,
    remote: &CrossDomainCommittee,
) {
    let encoded = serde_json::to_vec(local).unwrap();
    apply_single(
        state,
        authorizer,
        signers,
        "defmivm.issueCrossDomainDomain",
        "domain",
        domain_json(local),
        cross_domain_configuration_statement(b"local-domain", &encoded),
        1,
    );
    let encoded = serde_json::to_vec(remote).unwrap();
    apply_single(
        state,
        authorizer,
        signers,
        "defmivm.issueCrossDomainCommittee",
        "committee",
        committee_json(remote),
        cross_domain_configuration_statement(b"remote-committee", &encoded),
        2,
    );
}

fn seed_accounts(
    state: &mut State,
    asset_id: [u8; 32],
    kind: &str,
    handles: [[u8; 32]; 3],
    commitments: [[u8; 32]; 3],
) {
    state.assets.insert(
        id_key(&asset_id),
        AssetRecord {
            code: if kind == "cash" { "USD" } else { "SEC" }.into(),
            kind: kind.into(),
            decimals: 2,
            terms_digest: [71; 32],
            active: true,
        },
    );
    for (handle, commitment) in handles.into_iter().zip(commitments) {
        state.accounts.insert(
            id_key(&handle),
            AccountRecord {
                asset_id,
                commitment,
                sequence: 0,
            },
        );
    }
}

fn orders(
    marker: u8,
    asset_id: [u8; 32],
    handles: [[u8; 32]; 3],
    initial: [[u8; 32]; 3],
    instruction_digest: [u8; 32],
    relation_digest: [u8; 32],
) -> (SettlementOrder, SettlementOrder, SettlementOrder) {
    let reserve = SettlementOrder {
        operation_id: [marker; 32],
        nullifier: [marker + 1; 32],
        deadline: 20,
        payment_instruction_digest: instruction_digest,
        proof_digest: relation_digest,
        market_statement_digest: [marker + 2; 32],
        legs: vec![
            StateLeg {
                handle: handles[0],
                asset_id,
                before_commitment: initial[0],
                after_commitment: [marker + 3; 32],
                before_sequence: 0,
            },
            StateLeg {
                handle: handles[1],
                asset_id,
                before_commitment: initial[1],
                after_commitment: [marker + 4; 32],
                before_sequence: 0,
            },
        ],
    };
    let claim = SettlementOrder {
        operation_id: [marker + 5; 32],
        nullifier: [marker + 6; 32],
        deadline: 30,
        payment_instruction_digest: instruction_digest,
        proof_digest: relation_digest,
        market_statement_digest: [marker + 7; 32],
        legs: vec![
            StateLeg {
                handle: handles[1],
                asset_id,
                before_commitment: [marker + 4; 32],
                after_commitment: [marker + 8; 32],
                before_sequence: 1,
            },
            StateLeg {
                handle: handles[2],
                asset_id,
                before_commitment: initial[2],
                after_commitment: [marker + 9; 32],
                before_sequence: 0,
            },
        ],
    };
    let refund = SettlementOrder {
        operation_id: [marker + 10; 32],
        nullifier: [marker + 11; 32],
        deadline: 50,
        payment_instruction_digest: instruction_digest,
        proof_digest: relation_digest,
        market_statement_digest: [marker + 12; 32],
        legs: vec![
            StateLeg {
                handle: handles[1],
                asset_id,
                before_commitment: [marker + 4; 32],
                after_commitment: initial[1],
                before_sequence: 1,
            },
            StateLeg {
                handle: handles[0],
                asset_id,
                before_commitment: [marker + 3; 32],
                after_commitment: initial[0],
                before_sequence: 1,
            },
        ],
    };
    (reserve, claim, refund)
}

#[allow(clippy::too_many_arguments)]
fn prepare(
    local: CrossDomain,
    remote: CrossDomain,
    local_leg_id: [u8; 32],
    remote_leg_id: [u8; 32],
    handles: [[u8; 32]; 3],
    asset_id: [u8; 32],
    instruction_digest: [u8; 32],
    relation_digest: [u8; 32],
    orders: &(SettlementOrder, SettlementOrder, SettlementOrder),
    release_condition: [u8; 32],
) -> CrossDomainPrepareLeg {
    let event_binding = |event: &[u8]| {
        let mut hash = Sha256::new();
        hash.update(b"QOMM:TEST:PRIVATE-EVENT-BINDING:v1");
        hash.update(remote_leg_id);
        hash.update(local.id());
        hash.update(event);
        hash.finalize().into()
    };
    let expected_remote_prepare_binding = event_binding(b"prepared");
    let expected_remote_claim_binding = event_binding(b"claimed");
    CrossDomainPrepareLeg {
        local_domain: local,
        remote_domain: remote,
        local_leg_id,
        expected_remote_prepare_binding,
        expected_remote_claim_binding,
        owner_commitment: handle_commitment(&handles[0]),
        escrow_commitment: handle_commitment(&handles[1]),
        destination_commitment: handle_commitment(&handles[2]),
        asset_commitment: asset_id_commitment(&asset_id),
        amount_commitment: [90; 32],
        local_instruction_digest: instruction_digest,
        local_relation_proof_digest: relation_digest,
        reserve_transfer_digest: orders.0.statement().unwrap(),
        claim_transfer_digest: orders.1.statement().unwrap(),
        refund_transfer_digest: orders.2.statement().unwrap(),
        arm_deadline: 20,
        claim_deadline: 30,
        refund_after: 40,
        release_condition,
    }
}

fn submit_prepare(
    state: &mut State,
    authorizer: &QuorumAuthorizer,
    signers: &BTreeMap<String, qomm_defmi::governance::GovernanceSigner>,
    prepare: &CrossDomainPrepareLeg,
    reserve: &SettlementOrder,
) {
    let transfer = reserve.statement().unwrap();
    let statement = cross_domain_statement(
        b"prepare",
        &prepare.local_leg_id,
        &prepare.digest(),
        &transfer,
    );
    let mut params = Map::new();
    params.insert("prepare".into(), prepare_json(prepare));
    params.insert("reserveOrder".into(), settlement_json(reserve));
    let transaction = authorized_transaction(
        state,
        authorizer,
        signers,
        "defmivm.issueCrossDomainPrepare",
        params,
        statement,
    );
    state.apply(&transaction, authorizer, 10).unwrap();
}

fn submit_claim(
    state: &mut State,
    authorizer: &QuorumAuthorizer,
    signers: &BTreeMap<String, qomm_defmi::governance::GovernanceSigner>,
    prepare: &CrossDomainPrepareLeg,
    claim: &SettlementOrder,
    witness: &[u8],
) {
    let transfer = claim.statement().unwrap();
    let statement = cross_domain_statement(
        b"claim",
        &prepare.local_leg_id,
        &transfer,
        &prepare.local_instruction_digest,
    );
    let mut params = Map::new();
    params.insert(
        "localLegID".into(),
        json!(hex::encode(prepare.local_leg_id)),
    );
    params.insert("releaseWitness".into(), json!(hex::encode(witness)));
    params.insert("claimOrder".into(), settlement_json(claim));
    let transaction = authorized_transaction(
        state,
        authorizer,
        signers,
        "defmivm.issueCrossDomainClaim",
        params,
        statement,
    );
    state.apply(&transaction, authorizer, 15).unwrap();
}

#[test]
fn executes_cash_against_securities_across_two_vm_states() {
    let (authorizer_a, signers_a) = local_committee();
    let (authorizer_b, signers_b) = local_committee();
    let domain_a = CrossDomain {
        network_id: 5,
        chain_id: [1; 32],
        defmi_id: [2; 32],
    };
    let domain_b = CrossDomain {
        network_id: 5,
        chain_id: [3; 32],
        defmi_id: [4; 32],
    };
    let (committee_a, receipt_keys_a) = receipt_committee(domain_a.clone(), 30);
    let (committee_b, receipt_keys_b) = receipt_committee(domain_b.clone(), 40);
    let mut cash = State::default();
    let mut securities = State::default();
    let cash_asset = [10; 32];
    let security_asset = [20; 32];
    let cash_handles = [[11; 32], [12; 32], [13; 32]];
    let security_handles = [[21; 32], [22; 32], [23; 32]];
    seed_accounts(
        &mut cash,
        cash_asset,
        "cash",
        cash_handles,
        [[31; 32], [32; 32], [33; 32]],
    );
    seed_accounts(
        &mut securities,
        security_asset,
        "security",
        security_handles,
        [[41; 32], [42; 32], [43; 32]],
    );
    install_domains(
        &mut cash,
        &authorizer_a,
        &signers_a,
        &domain_a,
        &committee_b,
    );
    install_domains(
        &mut securities,
        &authorizer_b,
        &signers_b,
        &domain_b,
        &committee_a,
    );

    let cash_orders = orders(
        100,
        cash_asset,
        cash_handles,
        [[31; 32], [32; 32], [33; 32]],
        [51; 32],
        [53; 32],
    );
    let security_orders = orders(
        120,
        security_asset,
        security_handles,
        [[41; 32], [42; 32], [43; 32]],
        [52; 32],
        [54; 32],
    );
    let witness = b"threshold-released-after-both-prepares";
    let release = hash_release_witness(witness);
    let cash_prepare = prepare(
        domain_a.clone(),
        domain_b.clone(),
        [61; 32],
        [62; 32],
        cash_handles,
        cash_asset,
        [51; 32],
        [53; 32],
        &cash_orders,
        release,
    );
    let security_prepare = prepare(
        domain_b.clone(),
        domain_a.clone(),
        [62; 32],
        [61; 32],
        security_handles,
        security_asset,
        [52; 32],
        [54; 32],
        &security_orders,
        release,
    );
    submit_prepare(
        &mut cash,
        &authorizer_a,
        &signers_a,
        &cash_prepare,
        &cash_orders.0,
    );
    submit_prepare(
        &mut securities,
        &authorizer_b,
        &signers_b,
        &security_prepare,
        &security_orders.0,
    );

    let receipt_a = cash
        .cross_domain
        .receipt_for(
            cash_prepare.local_leg_id,
            ReceiptEvent::Prepared,
            qomm_defmi::cross_domain::FinalityContext {
                destination_domain: domain_b.clone(),
                destination_leg_id: security_prepare.local_leg_id,
                event_binding: security_prepare.expected_remote_prepare_binding,
                source_state_root: cash.root(),
                source_block_id: [91; 32],
                source_height: 10,
                finalised_at: 11,
                validator_epoch: 1,
                committee_digest: committee_a.digest().unwrap(),
            },
        )
        .unwrap();
    let receipt_b = securities
        .cross_domain
        .receipt_for(
            security_prepare.local_leg_id,
            ReceiptEvent::Prepared,
            qomm_defmi::cross_domain::FinalityContext {
                destination_domain: domain_a.clone(),
                destination_leg_id: cash_prepare.local_leg_id,
                event_binding: cash_prepare.expected_remote_prepare_binding,
                source_state_root: securities.root(),
                source_block_id: [92; 32],
                source_height: 20,
                finalised_at: 11,
                validator_epoch: 1,
                committee_digest: committee_b.digest().unwrap(),
            },
        )
        .unwrap();
    let receipt_a = sign_receipt(receipt_a, &receipt_keys_a);
    let receipt_b = sign_receipt(receipt_b, &receipt_keys_b);

    let before = cash.clone();
    for mutation in 0..6 {
        let mut bad = receipt_b.clone();
        match mutation {
            0 => bad.signatures[0].signature.truncate(64),
            1 => bad.signatures[0].signature[64] ^= 1,
            2 => bad.signatures[0].signature[0] ^= 1,
            3 => bad.committee_digest[0] ^= 1,
            4 => bad.validator_epoch += 1,
            _ => bad.signatures[1] = bad.signatures[0].clone(),
        }
        let transaction = TransactionEnvelope::new(
            "defmivm.issueCrossDomainArm",
            json!({
                "localLegID": hex::encode([61; 32]), "remoteReceipt": receipt_json(&bad),
            }),
        )
        .unwrap()
        .encode()
        .unwrap();
        assert!(cash.apply(&transaction, &authorizer_a, 12).is_err());
        assert_eq!(cash, before);
    }
    let mut legacy = receipt_json(&receipt_b);
    legacy.as_object_mut().unwrap().remove("suite");
    let transaction = TransactionEnvelope::new(
        "defmivm.issueCrossDomainArm",
        json!({
            "localLegID": hex::encode([61; 32]), "remoteReceipt": legacy,
        }),
    )
    .unwrap()
    .encode()
    .unwrap();
    assert!(cash.apply(&transaction, &authorizer_a, 12).is_err());
    assert_eq!(cash, before);

    for (state, authorizer, leg_id, receipt) in [
        (&mut cash, &authorizer_a, [61; 32], &receipt_b),
        (&mut securities, &authorizer_b, [62; 32], &receipt_a),
    ] {
        let transaction = TransactionEnvelope::new(
            "defmivm.issueCrossDomainArm",
            json!({
                "localLegID": hex::encode(leg_id),
                "remoteReceipt": receipt_json(receipt),
            }),
        )
        .unwrap()
        .encode()
        .unwrap();
        state.apply(&transaction, authorizer, 12).unwrap();
    }

    submit_claim(
        &mut cash,
        &authorizer_a,
        &signers_a,
        &cash_prepare,
        &cash_orders.1,
        witness,
    );
    submit_claim(
        &mut securities,
        &authorizer_b,
        &signers_b,
        &security_prepare,
        &security_orders.1,
        witness,
    );

    assert_eq!(cash.cross_domain.legs[&[61; 32]].status, LegStatus::Claimed);
    assert_eq!(
        securities.cross_domain.legs[&[62; 32]].status,
        LegStatus::Claimed
    );
    assert_eq!(cash.accounts[&id_key(&cash_handles[2])].sequence, 1);
    assert_eq!(
        securities.accounts[&id_key(&security_handles[2])].sequence,
        1
    );
    assert_ne!(
        cash_prepare.local_instruction_digest,
        security_prepare.local_instruction_digest
    );
}

#[test]
fn refunds_local_reserve_after_remote_partition() {
    let (authorizer, signers) = local_committee();
    let local = CrossDomain {
        network_id: 5,
        chain_id: [81; 32],
        defmi_id: [82; 32],
    };
    let remote = CrossDomain {
        network_id: 5,
        chain_id: [83; 32],
        defmi_id: [84; 32],
    };
    let (remote_committee, _) = receipt_committee(remote.clone(), 50);
    let mut state = State::default();
    let asset = [85; 32];
    let handles = [[86; 32], [87; 32], [88; 32]];
    let initial = [[89; 32], [90; 32], [91; 32]];
    seed_accounts(&mut state, asset, "cash", handles, initial);
    install_domains(&mut state, &authorizer, &signers, &local, &remote_committee);
    let orders = orders(140, asset, handles, initial, [92; 32], [93; 32]);
    let prepare = prepare(
        local,
        remote,
        [94; 32],
        [95; 32],
        handles,
        asset,
        [92; 32],
        [93; 32],
        &orders,
        hash_release_witness(b"never-released"),
    );
    submit_prepare(&mut state, &authorizer, &signers, &prepare, &orders.0);

    let transfer = orders.2.statement().unwrap();
    let statement = cross_domain_statement(
        b"refund",
        &prepare.local_leg_id,
        &transfer,
        &prepare.local_instruction_digest,
    );
    let mut params = Map::new();
    params.insert(
        "localLegID".into(),
        json!(hex::encode(prepare.local_leg_id)),
    );
    params.insert("refundOrder".into(), settlement_json(&orders.2));
    let transaction = authorized_transaction(
        &state,
        &authorizer,
        &signers,
        "defmivm.issueCrossDomainRefund",
        params,
        statement,
    );
    let before = state.clone();
    assert!(state.apply(&transaction, &authorizer, 39).is_err());
    assert_eq!(state, before);
    state.apply(&transaction, &authorizer, 40).unwrap();
    assert_eq!(state.accounts[&id_key(&handles[0])].commitment, initial[0]);
    assert_eq!(
        state.cross_domain.legs[&prepare.local_leg_id].status,
        LegStatus::Refunded
    );
}

fn finality_key(
    member: [u8; 32],
    signer: &zkfmi_crypto::hybrid::signature::HybridSigner,
) -> zkfmi_crypto::key::KeyRecord {
    use zkfmi_crypto::{
        key::{KeyId, KeyPurpose, KeyRecord, ParticipantId},
        traits::Signer as _,
    };
    KeyRecord {
        participant_id: ParticipantId::new(hex::encode(member)).unwrap(),
        key_id: KeyId::new(format!("finality:{}", hex::encode(member))).unwrap(),
        suite: signer.suite(),
        key_version: 1,
        purpose: KeyPurpose::Attestation,
        public_key: signer.public_key(),
        not_before: 0,
        not_after: i64::MAX as u64,
        revoked_at: None,
        rotation_proof: None,
        dekyx_binding: None,
    }
}
