use ed25519_dalek::SigningKey;
use qomm_defmi::avalanche::{
    AcceptedTransition, AvalancheClient, AvalancheRpcClient, FacilityAvalancheBridge,
};
use qomm_defmi::facility::{
    AccountOpening, AssetDefinition, AssetKind, DefmiFacility, QuorumApproval, QuorumAuthorizer,
    SettlementOrder, StateLeg,
};
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

fn pair<'a>(
    directory: &'a tempfile::TempDir,
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
