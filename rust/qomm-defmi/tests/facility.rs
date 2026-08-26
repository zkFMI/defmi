use ed25519_dalek::SigningKey;
use qomm_defmi::facility::{
    AccountOpening, AssetDefinition, AssetKind, DefmiFacility, QuorumApproval, QuorumAuthorizer,
    SettlementOrder, StateLeg, ZERO,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

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

fn approve(
    facility: &DefmiFacility,
    authorizer: &QuorumAuthorizer,
    keys: &BTreeMap<String, SigningKey>,
    statement: [u8; 32],
    count: usize,
) -> QuorumApproval {
    let signers = keys
        .iter()
        .take(count)
        .map(|(node, key)| (node.clone(), key.clone()))
        .collect();
    authorizer
        .approve(statement, facility.state_root().unwrap(), &signers)
        .unwrap()
}

fn register(
    facility: &DefmiFacility,
    authorizer: &QuorumAuthorizer,
    keys: &BTreeMap<String, SigningKey>,
    label: &str,
    kind: AssetKind,
    decimals: u8,
) -> AssetDefinition {
    let asset = AssetDefinition {
        asset_id: h(&format!("asset:{label}")),
        code: label.into(),
        kind,
        decimals,
        terms_digest: h(&format!("terms:{label}")),
    };
    facility
        .register_asset(
            &asset,
            &approve(facility, authorizer, keys, asset.statement().unwrap(), 3),
        )
        .unwrap();
    asset
}

fn opening(
    facility: &DefmiFacility,
    authorizer: &QuorumAuthorizer,
    keys: &BTreeMap<String, SigningKey>,
    label: &str,
    asset: &AssetDefinition,
    commitment: [u8; 32],
) -> AccountOpening {
    let opening = AccountOpening {
        handle: h(&format!("account:{label}")),
        asset_id: asset.asset_id,
        commitment,
        issuance_nonce: h(&format!("issuance:{label}")),
    };
    facility
        .open_account(
            &opening,
            &approve(facility, authorizer, keys, opening.statement().unwrap(), 3),
        )
        .unwrap();
    opening
}

fn leg(
    account: &AccountOpening,
    asset: &AssetDefinition,
    before: [u8; 32],
    after: [u8; 32],
    sequence: u64,
) -> StateLeg {
    StateLeg {
        handle: account.handle,
        asset_id: asset.asset_id,
        before_commitment: before,
        after_commitment: after,
        before_sequence: sequence,
    }
}

fn order(label: &str, legs: Vec<StateLeg>, deadline: u64) -> SettlementOrder {
    SettlementOrder {
        operation_id: h(&format!("operation:{label}")),
        nullifier: h(&format!("nullifier:{label}")),
        deadline,
        payment_instruction_digest: h(&format!("zkpi:{label}")),
        proof_digest: h(&format!("proof:{label}")),
        market_statement_digest: h(&format!("market:{label}")),
        legs,
    }
}

#[test]
fn one_state_machine_settles_security_fx_fund_and_carbon() {
    let directory = tempfile::tempdir().unwrap();
    let keys = keys();
    let authorizer = authorizer(&keys);
    let facility = DefmiFacility::open(
        directory.path().join("defmi.sqlite3"),
        authorizer.clone(),
        SigningKey::generate(&mut OsRng),
    )
    .unwrap();
    let jpy = register(&facility, &authorizer, &keys, "JPY", AssetKind::Cash, 0);
    let usd = register(&facility, &authorizer, &keys, "USD", AssetKind::Cash, 2);
    let security = register(
        &facility,
        &authorizer,
        &keys,
        "JP0000000001",
        AssetKind::Security,
        0,
    );
    let fund = register(&facility, &authorizer, &keys, "FUND-A", AssetKind::Fund, 6);
    let carbon = register(
        &facility,
        &authorizer,
        &keys,
        "J-CREDIT",
        AssetKind::Carbon,
        0,
    );
    assert_eq!(facility.asset_count().unwrap(), 5);

    let sec_s = opening(&facility, &authorizer, &keys, "sec-s", &security, h("s1"));
    let sec_b = opening(&facility, &authorizer, &keys, "sec-b", &security, h("s2"));
    let jpy_b = opening(&facility, &authorizer, &keys, "jpy-b", &jpy, h("j1"));
    let jpy_s = opening(&facility, &authorizer, &keys, "jpy-s", &jpy, h("j2"));
    let dvp = order(
        "dvp",
        vec![
            leg(&sec_s, &security, h("s1"), h("s11"), 0),
            leg(&sec_b, &security, h("s2"), h("s12"), 0),
            leg(&jpy_b, &jpy, h("j1"), h("j11"), 0),
            leg(&jpy_s, &jpy, h("j2"), h("j12"), 0),
        ],
        1_000,
    );
    let receipt = facility
        .settle(
            &dvp,
            &approve(&facility, &authorizer, &keys, dvp.statement().unwrap(), 3),
            100,
        )
        .unwrap();
    assert!(receipt.verify(&facility.receipt_public_key));

    let usd_a = opening(&facility, &authorizer, &keys, "usd-a", &usd, h("u1"));
    let usd_b = opening(&facility, &authorizer, &keys, "usd-b", &usd, h("u2"));
    let jpy_a = opening(&facility, &authorizer, &keys, "jpy-a", &jpy, h("ja1"));
    let jpy_c = opening(&facility, &authorizer, &keys, "jpy-c", &jpy, h("ja2"));
    let pvp = order(
        "pvp",
        vec![
            leg(&usd_a, &usd, h("u1"), h("u11"), 0),
            leg(&usd_b, &usd, h("u2"), h("u12"), 0),
            leg(&jpy_a, &jpy, h("ja1"), h("ja11"), 0),
            leg(&jpy_c, &jpy, h("ja2"), h("ja12"), 0),
        ],
        1_000,
    );
    facility
        .settle(
            &pvp,
            &approve(&facility, &authorizer, &keys, pvp.statement().unwrap(), 3),
            101,
        )
        .unwrap();

    for (asset, label) in [(&fund, "fund"), (&carbon, "carbon")] {
        let left = opening(
            &facility,
            &authorizer,
            &keys,
            &format!("{label}-a"),
            asset,
            h(&format!("{label}1")),
        );
        let right = opening(
            &facility,
            &authorizer,
            &keys,
            &format!("{label}-b"),
            asset,
            h(&format!("{label}2")),
        );
        let transfer = order(
            label,
            vec![
                leg(
                    &left,
                    asset,
                    h(&format!("{label}1")),
                    h(&format!("{label}11")),
                    0,
                ),
                leg(
                    &right,
                    asset,
                    h(&format!("{label}2")),
                    h(&format!("{label}12")),
                    0,
                ),
            ],
            1_000,
        );
        facility
            .settle(
                &transfer,
                &approve(
                    &facility,
                    &authorizer,
                    &keys,
                    transfer.statement().unwrap(),
                    3,
                ),
                102,
            )
            .unwrap();
    }
    assert!(facility.verify_receipt_chain().unwrap());
}

#[test]
fn stale_later_leg_rolls_back_every_leg_and_nullifier() {
    let directory = tempfile::tempdir().unwrap();
    let keys = keys();
    let authorizer = authorizer(&keys);
    let facility = DefmiFacility::open(
        directory.path().join("defmi.sqlite3"),
        authorizer.clone(),
        SigningKey::generate(&mut OsRng),
    )
    .unwrap();
    let jpy = register(&facility, &authorizer, &keys, "JPY", AssetKind::Cash, 0);
    let a = opening(&facility, &authorizer, &keys, "a", &jpy, h("a1"));
    let b = opening(&facility, &authorizer, &keys, "b", &jpy, h("b1"));
    let bad = order(
        "bad",
        vec![
            leg(&a, &jpy, h("a1"), h("a2"), 0),
            leg(&b, &jpy, h("wrong"), h("b2"), 0),
        ],
        1_000,
    );
    let before = facility.state_root().unwrap();
    let error = facility
        .settle(
            &bad,
            &approve(&facility, &authorizer, &keys, bad.statement().unwrap(), 3),
            100,
        )
        .unwrap_err();
    assert!(error.contains("stale"));
    assert_eq!(facility.account(&a.handle).unwrap().unwrap().1, h("a1"));
    assert_eq!(facility.state_root().unwrap(), before);
}

#[test]
fn quorum_expiry_replay_nullifier_and_wrong_asset_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let keys = keys();
    let authorizer = authorizer(&keys);
    let facility = DefmiFacility::open(
        directory.path().join("defmi.sqlite3"),
        authorizer.clone(),
        SigningKey::generate(&mut OsRng),
    )
    .unwrap();
    let jpy = register(&facility, &authorizer, &keys, "JPY", AssetKind::Cash, 0);
    let usd = register(&facility, &authorizer, &keys, "USD", AssetKind::Cash, 0);
    let a = opening(&facility, &authorizer, &keys, "a", &jpy, h("a1"));
    let b = opening(&facility, &authorizer, &keys, "b", &jpy, h("b1"));
    let good = order(
        "good",
        vec![
            leg(&a, &jpy, h("a1"), h("a2"), 0),
            leg(&b, &jpy, h("b1"), h("b2"), 0),
        ],
        1_000,
    );
    assert!(facility
        .settle(
            &good,
            &approve(&facility, &authorizer, &keys, good.statement().unwrap(), 2),
            100,
        )
        .unwrap_err()
        .contains("k-of-n"));
    assert!(facility
        .settle(
            &good,
            &approve(&facility, &authorizer, &keys, good.statement().unwrap(), 3),
            1_001,
        )
        .unwrap_err()
        .contains("expired"));
    let approval = approve(&facility, &authorizer, &keys, good.statement().unwrap(), 3);
    let receipt = facility.settle(&good, &approval, 100).unwrap();
    assert_eq!(
        facility
            .settle(&good, &approval, 1_001)
            .unwrap()
            .digest()
            .unwrap(),
        receipt.digest().unwrap()
    );

    let reused = SettlementOrder {
        operation_id: h("operation:other"),
        nullifier: good.nullifier,
        deadline: 1_000,
        payment_instruction_digest: h("zkpi:other"),
        proof_digest: h("proof:other"),
        market_statement_digest: h("market:other"),
        legs: vec![leg(&a, &usd, h("a2"), h("a3"), 1)],
    };
    let error = facility
        .settle(
            &reused,
            &approve(
                &facility,
                &authorizer,
                &keys,
                reused.statement().unwrap(),
                3,
            ),
            101,
        )
        .unwrap_err();
    assert!(error.contains("nullifier") || error.contains("asset"));
}

#[test]
fn persistence_backup_cost_meter_and_chain_survive_restart() {
    let directory = tempfile::tempdir().unwrap();
    let keys = keys();
    let authorizer = authorizer(&keys);
    let receipt_key = SigningKey::generate(&mut OsRng);
    let path = directory.path().join("defmi.sqlite3");
    let facility = DefmiFacility::open(&path, authorizer.clone(), receipt_key.clone()).unwrap();
    let jpy = register(&facility, &authorizer, &keys, "JPY", AssetKind::Cash, 0);
    let a = opening(&facility, &authorizer, &keys, "a", &jpy, h("a1"));
    let b = opening(&facility, &authorizer, &keys, "b", &jpy, h("b1"));
    let transfer = order(
        "persist",
        vec![
            leg(&a, &jpy, h("a1"), h("a2"), 0),
            leg(&b, &jpy, h("b1"), h("b2"), 0),
        ],
        1_000,
    );
    let receipt = facility
        .settle(
            &transfer,
            &approve(
                &facility,
                &authorizer,
                &keys,
                transfer.statement().unwrap(),
                3,
            ),
            100,
        )
        .unwrap();
    assert!(receipt.elapsed_ns > 0 && receipt.request_bytes > 0);
    assert!(receipt.database_bytes_after >= receipt.database_bytes_before);
    let backup = facility
        .backup(directory.path().join("backup.sqlite3"))
        .unwrap();
    assert!(backup.metadata().unwrap().len() > 0);
    facility.checkpoint().unwrap();
    drop(facility);

    let reopened = DefmiFacility::open(&path, authorizer, receipt_key).unwrap();
    assert_eq!(reopened.account(&a.handle).unwrap().unwrap().1, h("a2"));
    assert_eq!(reopened.account(&a.handle).unwrap().unwrap().2, 1);
    assert!(reopened.verify_receipt_chain().unwrap());
}

#[test]
fn asset_and_account_retries_are_idempotent_but_conflicts_fail() {
    let directory = tempfile::tempdir().unwrap();
    let keys = keys();
    let authorizer = authorizer(&keys);
    let facility = DefmiFacility::open(
        directory.path().join("defmi.sqlite3"),
        authorizer.clone(),
        SigningKey::generate(&mut OsRng),
    )
    .unwrap();
    let asset = AssetDefinition {
        asset_id: h("asset:JPY"),
        code: "JPY".into(),
        kind: AssetKind::Cash,
        decimals: 0,
        terms_digest: h("terms:JPY"),
    };
    let approval = approve(&facility, &authorizer, &keys, asset.statement().unwrap(), 3);
    facility.register_asset(&asset, &approval).unwrap();
    facility.register_asset(&asset, &approval).unwrap();
    let conflict = AssetDefinition {
        asset_id: asset.asset_id,
        code: "USD".into(),
        kind: AssetKind::Cash,
        decimals: 2,
        terms_digest: h("terms:USD"),
    };
    assert!(facility
        .register_asset(
            &conflict,
            &approve(
                &facility,
                &authorizer,
                &keys,
                conflict.statement().unwrap(),
                3,
            ),
        )
        .unwrap_err()
        .contains("reused"));

    let account = AccountOpening {
        handle: h("account:a"),
        asset_id: asset.asset_id,
        commitment: h("a1"),
        issuance_nonce: h("issuance:a"),
    };
    let approval = approve(
        &facility,
        &authorizer,
        &keys,
        account.statement().unwrap(),
        3,
    );
    facility.open_account(&account, &approval).unwrap();
    facility.open_account(&account, &approval).unwrap();
    let conflict = AccountOpening {
        commitment: h("a2"),
        issuance_nonce: h("issuance:b"),
        ..account
    };
    assert!(facility
        .open_account(
            &conflict,
            &approve(
                &facility,
                &authorizer,
                &keys,
                conflict.statement().unwrap(),
                3,
            ),
        )
        .unwrap_err()
        .contains("reused"));
}

#[test]
fn quorum_is_bound_to_unique_keys_domain_and_before_root() {
    let repeated = SigningKey::generate(&mut OsRng);
    assert!(QuorumAuthorizer::new(
        BTreeMap::from([
            ("node-a".into(), repeated.verifying_key()),
            ("node-b".into(), repeated.verifying_key()),
        ]),
        2,
        1,
        "defmi:local",
    )
    .unwrap_err()
    .contains("two node identities"));

    let directory = tempfile::tempdir().unwrap();
    let keys = keys();
    let authorizer = authorizer(&keys);
    let facility = DefmiFacility::open(
        directory.path().join("defmi.sqlite3"),
        authorizer.clone(),
        SigningKey::generate(&mut OsRng),
    )
    .unwrap();
    let pending = AssetDefinition {
        asset_id: h("asset:pending"),
        code: "PENDING".into(),
        kind: AssetKind::Other,
        decimals: 0,
        terms_digest: h("terms:pending"),
    };
    let stale = approve(
        &facility,
        &authorizer,
        &keys,
        pending.statement().unwrap(),
        3,
    );
    register(&facility, &authorizer, &keys, "OTHER", AssetKind::Other, 0);
    assert!(facility
        .register_asset(&pending, &stale)
        .unwrap_err()
        .contains("k-of-n"));

    let foreign = QuorumAuthorizer::new(
        keys.iter()
            .map(|(node, key)| (node.clone(), key.verifying_key()))
            .collect(),
        3,
        1,
        "another-avalanche-chain",
    )
    .unwrap();
    let signers = keys
        .iter()
        .take(3)
        .map(|(node, key)| (node.clone(), key.clone()))
        .collect();
    let foreign_approval = foreign
        .approve(
            pending.statement().unwrap(),
            facility.state_root().unwrap(),
            &signers,
        )
        .unwrap();
    assert!(facility
        .register_asset(&pending, &foreign_approval)
        .unwrap_err()
        .contains("k-of-n"));
}

#[test]
fn zero_identifiers_are_rejected_before_authorization() {
    assert!(AssetDefinition {
        asset_id: ZERO,
        code: "JPY".into(),
        kind: AssetKind::Cash,
        decimals: 0,
        terms_digest: h("terms"),
    }
    .body()
    .unwrap_err()
    .contains("all-zero"));
    assert!(AccountOpening {
        handle: h("handle"),
        asset_id: h("asset"),
        commitment: ZERO,
        issuance_nonce: h("nonce"),
    }
    .body()
    .unwrap_err()
    .contains("all-zero"));
    assert!(SettlementOrder {
        operation_id: h("operation"),
        nullifier: ZERO,
        deadline: 1_000,
        payment_instruction_digest: h("zkpi"),
        proof_digest: h("proof"),
        market_statement_digest: h("market"),
        legs: vec![StateLeg {
            handle: h("handle"),
            asset_id: h("asset"),
            before_commitment: h("before"),
            after_commitment: h("after"),
            before_sequence: 0,
        }],
    }
    .body()
    .unwrap_err()
    .contains("all-zero"));
}
