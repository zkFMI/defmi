use ed25519_dalek::SigningKey;
use qomm_defmi::avalanche::{
    AcceptedTransition, AvalancheClient, AvalancheNoteBridge, AvalancheRpcClient,
    FacilityAvalancheBridge,
};
use qomm_defmi::facility::{
    AccountOpening, AssetDefinition, AssetKind, DefmiFacility, QuorumApproval, QuorumAuthorizer,
    SettlementOrder, StateLeg,
};
use qomm_defmi::note_chain::NoteOutput;
use rand_core::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

fn h(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn keys() -> BTreeMap<String, SigningKey> {
    (0..7)
        .map(|index| (format!("node-{index}"), SigningKey::generate(&mut OsRng)))
        .collect()
}

fn authorizer(keys: &BTreeMap<String, SigningKey>) -> QuorumAuthorizer {
    QuorumAuthorizer::new(
        keys.iter()
            .map(|(node, key)| (node.clone(), key.verifying_key()))
            .collect(),
        3,
        1,
        "defmi:local",
    )
    .unwrap()
}

fn approved(
    authorizer: &QuorumAuthorizer,
    keys: &BTreeMap<String, SigningKey>,
    statement: [u8; 32],
    before: [u8; 32],
) -> QuorumApproval {
    authorizer
        .approve(
            statement,
            before,
            &keys
                .iter()
                .take(3)
                .map(|(node, key)| (node.clone(), key.clone()))
                .collect(),
        )
        .unwrap()
}

struct ChainState {
    pending: BTreeMap<String, AcceptedTransition>,
    by_statement: BTreeMap<[u8; 32], String>,
    height: u64,
}

struct InMemoryAvalanche {
    mirror: DefmiFacility,
    state: Mutex<ChainState>,
}

impl InMemoryAvalanche {
    fn accept<F>(
        &self,
        statement: [u8; 32],
        expected_before: [u8; 32],
        apply: F,
    ) -> Result<String, String>
    where
        F: FnOnce() -> Result<(), String>,
    {
        let mut state = self.state.lock().unwrap();
        if let Some(existing) = state.by_statement.get(&statement) {
            return Ok(existing.clone());
        }
        let before = self.mirror.state_root()?;
        if before != expected_before {
            return Err("expected state root does not match".into());
        }
        apply()?;
        let after = self.mirror.state_root()?;
        state.height += 1;
        let tx_id = hex::encode(h(&format!("tx:{}", state.height)));
        let accepted = AcceptedTransition {
            tx_id: tx_id.clone(),
            block_id: hex::encode(h(&format!("block:{}", state.height))),
            height: state.height,
            statement,
            before_root: before,
            after_root: after,
        };
        state.pending.insert(tx_id.clone(), accepted);
        state.by_statement.insert(statement, tx_id.clone());
        Ok(tx_id)
    }
}

impl AvalancheClient for InMemoryAvalanche {
    fn state_root(&self) -> Result<[u8; 32], String> {
        self.mirror.state_root()
    }

    fn issue_asset(
        &self,
        asset: &AssetDefinition,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        self.accept(asset.statement()?, expected_before_root, || {
            self.mirror.register_asset(asset, approval)
        })
    }

    fn issue_account(
        &self,
        opening: &AccountOpening,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        self.accept(opening.statement()?, expected_before_root, || {
            self.mirror.open_account(opening, approval)
        })
    }

    fn issue_settlement(
        &self,
        order: &SettlementOrder,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        self.accept(order.statement()?, expected_before_root, || {
            self.mirror.settle(order, approval, 100).map(|_| ())
        })
    }

    fn wait_accepted(
        &self,
        tx_id: &str,
        _timeout: Duration,
        _poll: Duration,
    ) -> Result<AcceptedTransition, String> {
        self.state
            .lock()
            .unwrap()
            .pending
            .get(tx_id)
            .cloned()
            .ok_or_else(|| "unknown transaction".into())
    }
}

fn pair(
    directory: &tempfile::TempDir,
    keys: &BTreeMap<String, SigningKey>,
) -> (QuorumAuthorizer, DefmiFacility, InMemoryAvalanche) {
    let authorizer = authorizer(keys);
    let local = DefmiFacility::open(
        directory.path().join("local.sqlite3"),
        authorizer.clone(),
        SigningKey::generate(&mut OsRng),
    )
    .unwrap();
    let mirror = DefmiFacility::open(
        directory.path().join("chain.sqlite3"),
        authorizer.clone(),
        SigningKey::generate(&mut OsRng),
    )
    .unwrap();
    (
        authorizer,
        local,
        InMemoryAvalanche {
            mirror,
            state: Mutex::new(ChainState {
                pending: BTreeMap::new(),
                by_statement: BTreeMap::new(),
                height: 0,
            }),
        },
    )
}

#[test]
fn bridge_registers_opens_and_settles_without_projection_drift() {
    let directory = tempfile::tempdir().unwrap();
    let keys = keys();
    let (authorizer, local, chain) = pair(&directory, &keys);
    let bridge = FacilityAvalancheBridge::new(&local, &chain);
    let asset = AssetDefinition {
        asset_id: h("asset:JPY"),
        code: "JPY".into(),
        kind: AssetKind::Cash,
        decimals: 0,
        terms_digest: h("terms:JPY"),
    };
    bridge
        .register_asset(
            &asset,
            &approved(
                &authorizer,
                &keys,
                asset.statement().unwrap(),
                local.state_root().unwrap(),
            ),
        )
        .unwrap();
    let left = AccountOpening {
        handle: h("left"),
        asset_id: asset.asset_id,
        commitment: h("l0"),
        issuance_nonce: h("li"),
    };
    let right = AccountOpening {
        handle: h("right"),
        asset_id: asset.asset_id,
        commitment: h("r0"),
        issuance_nonce: h("ri"),
    };
    for opening in [&left, &right] {
        bridge
            .open_account(
                opening,
                &approved(
                    &authorizer,
                    &keys,
                    opening.statement().unwrap(),
                    local.state_root().unwrap(),
                ),
            )
            .unwrap();
    }
    let order = SettlementOrder {
        operation_id: h("operation"),
        nullifier: h("nullifier"),
        deadline: 1_000,
        payment_instruction_digest: h("zkpi"),
        proof_digest: h("proof"),
        market_statement_digest: h("market"),
        legs: vec![
            StateLeg {
                handle: left.handle,
                asset_id: asset.asset_id,
                before_commitment: h("l0"),
                after_commitment: h("l1"),
                before_sequence: 0,
            },
            StateLeg {
                handle: right.handle,
                asset_id: asset.asset_id,
                before_commitment: h("r0"),
                after_commitment: h("r1"),
                before_sequence: 0,
            },
        ],
    };
    let (receipt, accepted) = bridge
        .settle(
            &order,
            &approved(
                &authorizer,
                &keys,
                order.statement().unwrap(),
                local.state_root().unwrap(),
            ),
            100,
        )
        .unwrap();
    assert_eq!(receipt.after_root, accepted.after_root);
    assert_eq!(local.state_root().unwrap(), chain.state_root().unwrap());
}

#[test]
fn bridge_stops_when_roots_differ_and_recovers_after_l1_acceptance() {
    let directory = tempfile::tempdir().unwrap();
    let keys = keys();
    let (authorizer, local, chain) = pair(&directory, &keys);
    let bridge = FacilityAvalancheBridge::new(&local, &chain);
    let other = AssetDefinition {
        asset_id: h("asset:USD"),
        code: "USD".into(),
        kind: AssetKind::Cash,
        decimals: 0,
        terms_digest: h("terms:USD"),
    };
    let other_approval = approved(
        &authorizer,
        &keys,
        other.statement().unwrap(),
        chain.state_root().unwrap(),
    );
    chain
        .mirror
        .register_asset(&other, &other_approval)
        .unwrap();
    let asset = AssetDefinition {
        asset_id: h("asset:JPY"),
        code: "JPY".into(),
        kind: AssetKind::Cash,
        decimals: 0,
        terms_digest: h("terms:JPY"),
    };
    let approval = approved(
        &authorizer,
        &keys,
        asset.statement().unwrap(),
        local.state_root().unwrap(),
    );
    assert!(bridge
        .register_asset(&asset, &approval)
        .unwrap_err()
        .contains("expected state root"));

    let recovery_directory = tempfile::tempdir().unwrap();
    let (authorizer, local, chain) = pair(&recovery_directory, &keys);
    let bridge = FacilityAvalancheBridge::new(&local, &chain);
    let approval = approved(
        &authorizer,
        &keys,
        asset.statement().unwrap(),
        local.state_root().unwrap(),
    );
    let transaction = chain
        .issue_asset(&asset, &approval, local.state_root().unwrap())
        .unwrap();
    let recovered = bridge.register_asset(&asset, &approval).unwrap();
    assert_eq!(recovered.tx_id, transaction);
    assert_eq!(local.state_root().unwrap(), chain.state_root().unwrap());
    assert_eq!(local.asset_count().unwrap(), 1);
}

#[test]
fn rpc_requires_tls_except_explicit_local_test() {
    assert!(AvalancheRpcClient::new(
        "http://example.com/ext/bc/id",
        Duration::from_secs(10),
        false,
    )
    .err()
    .unwrap()
    .contains("plaintext"));
    AvalancheRpcClient::new(
        "http://127.0.0.1:9650/ext/bc/id",
        Duration::from_secs(10),
        true,
    )
    .unwrap();
}

#[test]
fn wait_accepted_treats_unknown_as_transient_consensus_state() {
    let index = AtomicUsize::new(0);
    let client = AvalancheRpcClient::with_transport(
        "http://127.0.0.1:9650/ext/bc/id",
        Duration::from_secs(1),
        true,
        move |request, _| {
            let request: Value = serde_json::from_slice(request).unwrap();
            let id = request["id"].as_u64().unwrap();
            let status = match index.fetch_add(1, Ordering::Relaxed) {
                0 => json!({"status": "unknown", "txID": "tx"}),
                1 => json!({"status": "processing", "txID": "tx"}),
                _ => json!({
                    "status": "accepted",
                    "txID": "tx",
                    "blockID": "block",
                    "height": 1,
                    "statement": "11".repeat(32),
                    "beforeRoot": "22".repeat(32),
                    "afterRoot": "33".repeat(32),
                }),
            };
            Ok(serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": status,
            }))
            .unwrap())
        },
    )
    .unwrap();
    let accepted = client
        .wait_accepted("tx", Duration::from_secs(1), Duration::from_millis(1))
        .unwrap();
    assert_eq!(accepted.tx_id, "tx");
    assert_eq!(accepted.height, 1);
}

#[test]
fn rpc_reads_one_root_consistent_account_free_authoring_snapshot() {
    let root = h("canonical-root");
    let asset = h("asset:JPY");
    let facility = h("facility");
    let mut note = NoteOutput {
        note_id: [0; 32],
        asset_id: asset,
        one_time: h("one-time"),
        value_commitment: h("value"),
        ephemeral: h("ephemeral"),
        masked_value: h("masked-value"),
        masked_blinding: h("masked-blinding"),
        lock_id: [0; 32],
    };
    note.note_id = note.derived_id().unwrap();
    let note_for_rpc = note.clone();
    let client = AvalancheRpcClient::with_transport(
        "http://127.0.0.1:9650/ext/bc/id",
        Duration::from_secs(1),
        true,
        move |request, _| {
            let request: Value = serde_json::from_slice(request).unwrap();
            let id = request["id"].as_u64().unwrap();
            let method = request["method"].as_str().unwrap();
            let note_json = || {
                json!({
                    "stateRoot": hex::encode(root),
                    "noteID": hex::encode(note_for_rpc.note_id),
                    "assetID": hex::encode(note_for_rpc.asset_id),
                    "oneTime": hex::encode(note_for_rpc.one_time),
                    "valueCommitment": hex::encode(note_for_rpc.value_commitment),
                    "ephemeral": hex::encode(note_for_rpc.ephemeral),
                    "maskedValue": hex::encode(note_for_rpc.masked_value),
                    "maskedBlinding": hex::encode(note_for_rpc.masked_blinding),
                    "lockID": hex::encode(note_for_rpc.lock_id),
                })
            };
            let result = match method {
                "defmivm.stateRoot" => json!({"stateRoot": hex::encode(root)}),
                "defmivm.creditFacility" => json!({
                    "stateRoot": hex::encode(root),
                    "facilityID": hex::encode(facility),
                    "guarantorID": hex::encode(h("guarantor")),
                    "beneficiaryCommitment": hex::encode(h("beneficiary")),
                    "railAssetID": hex::encode(asset),
                    "capCommitment": hex::encode(h("cap")),
                    "availableCommitment": hex::encode(h("available")),
                    "heldCommitment": hex::encode([0; 32]),
                    "outstandingCommitment": hex::encode([0; 32]),
                    "overlimitCommitment": hex::encode([0; 32]),
                    "collateralCommitment": hex::encode(h("collateral")),
                    "riskPolicyDigest": hex::encode(h("risk-policy")),
                    "validFrom": 1,
                    "validUntil": 999,
                    "status": "active",
                    "sequence": 4,
                }),
                "defmivm.listNotes" => json!({
                    "stateRoot": hex::encode(root),
                    "notes": [note_json()],
                    "next": "",
                }),
                _ => panic!("unexpected RPC method {method}"),
            };
            Ok(serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": id, "result": result,
            }))
            .unwrap())
        },
    )
    .unwrap();
    let keys = keys();
    let auth = authorizer(&keys);
    let bridge = AvalancheNoteBridge::new(&auth, &client);
    let canonical = bridge.credit_facility(facility).unwrap();
    assert_eq!(canonical.state_root, root);
    assert_eq!(canonical.facility.sequence, 4);
    let (pool_root, pool) = bridge.note_pool(asset, 64).unwrap();
    assert_eq!(pool_root, root);
    assert_eq!(pool, vec![note]);
}

#[test]
fn authoritative_bridge_retries_exact_accepted_transaction_after_root_moves() {
    let directory = tempfile::tempdir().unwrap();
    let keys = keys();
    let (authorizer, _local, chain) = pair(&directory, &keys);
    let bridge = AvalancheNoteBridge::new(&authorizer, &chain);
    let asset = AssetDefinition {
        asset_id: h("retry-note-asset"),
        code: "NOTE".into(),
        kind: AssetKind::Other,
        decimals: 0,
        terms_digest: h("retry-note-terms"),
    };
    let approval = approved(
        &authorizer,
        &keys,
        asset.statement().unwrap(),
        chain.state_root().unwrap(),
    );
    let first = bridge.register_asset(&asset, &approval).unwrap();
    assert_ne!(chain.state_root().unwrap(), approval.before_root);
    let retried = bridge.register_asset(&asset, &approval).unwrap();
    assert_eq!(first, retried);
}
