use ed25519_dalek::{Signer, SigningKey};
use qomm_audit::distributed_dp::DpMechanism;
use qomm_audit::publication::{NodeSignature, ZERO};
use qomm_audit::publication_ledger::{BudgetAllocation, PublicationLedger, PublicationRequest};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};

fn keys() -> BTreeMap<String, SigningKey> {
    (1..=7)
        .map(|node| (format!("node-{node}"), SigningKey::generate(&mut OsRng)))
        .collect()
}

fn registry(keys: &BTreeMap<String, SigningKey>) -> BTreeMap<String, ed25519_dalek::VerifyingKey> {
    keys.iter()
        .map(|(node, key)| (node.clone(), key.verifying_key()))
        .collect()
}

fn signatures(
    body: &[u8],
    keys: &BTreeMap<String, SigningKey>,
    count: usize,
) -> Vec<NodeSignature> {
    keys.iter()
        .take(count)
        .map(|(node_id, key)| NodeSignature {
            node_id: node_id.clone(),
            signature: key.sign(body),
        })
        .collect()
}

fn request(scope: [u8; 32], operation: &[u8], epoch: u64) -> PublicationRequest {
    PublicationRequest {
        operation_id: Sha256::digest(operation).into(),
        budget_scope: scope,
        venue: "QOMM".into(),
        epoch,
        slot_start: epoch * 10,
        slot_end: epoch * 10 + 9,
        source_digest: Sha256::digest(b"seven-node aggregate source").into(),
        rule_digest: Sha256::digest(b"one contribution per legal entity").into(),
        private_input_commitment: Sha256::digest(b"private aggregate commitment").into(),
        transcript_digest: Sha256::new()
            .chain_update(b"real MP-SPDZ transcript")
            .chain_update(epoch.to_be_bytes())
            .finalize()
            .into(),
        output_name: "request_count".into(),
        output_value: 41,
    }
}

#[test]
fn budget_mpc_certificate_and_replay_marker_commit_atomically() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("publication.json");
    let keys = keys();
    let registry = registry(&keys);
    let scope: [u8; 32] = Sha256::digest(b"legal-entity group A").into();
    let allocation = BudgetAllocation {
        budget_scope: scope,
        venue: "QOMM".into(),
        output_name: "request_count".into(),
        total_micros: 500_000,
        policy_version: 1,
    };
    let ledger = PublicationLedger::open(&path, registry.clone(), 3).unwrap();
    ledger
        .configure_budget(
            allocation.clone(),
            &signatures(&allocation.body().unwrap(), &keys, 3),
        )
        .unwrap();
    let mechanism = DpMechanism::new(500_000, 3, 32).unwrap();

    // Two independent coordinators race the same legal-entity budget. Both
    // computations are individually valid; the durable CAS admits only one.
    let barrier = Arc::new(Barrier::new(2));
    let (left, right) = std::thread::scope(|scope_threads| {
        let left_barrier = Arc::clone(&barrier);
        let right_barrier = Arc::clone(&barrier);
        let left_path = path.clone();
        let right_path = path.clone();
        let left_registry = registry.clone();
        let right_registry = registry.clone();
        let left_keys = keys.clone();
        let right_keys = keys.clone();
        let left_mechanism = mechanism.clone();
        let right_mechanism = mechanism.clone();
        let left = scope_threads.spawn(move || {
            let ledger = PublicationLedger::open(left_path, left_registry, 3).unwrap();
            left_barrier.wait();
            ledger.publish_with(
                request(scope, b"left publication", 1),
                &left_mechanism,
                |statement| Ok(signatures(&statement.body().unwrap(), &left_keys, 3)),
            )
        });
        let right = scope_threads.spawn(move || {
            let ledger = PublicationLedger::open(right_path, right_registry, 3).unwrap();
            right_barrier.wait();
            ledger.publish_with(
                request(scope, b"right publication", 2),
                &right_mechanism,
                |statement| Ok(signatures(&statement.body().unwrap(), &right_keys, 3)),
            )
        });
        (left.join().unwrap(), right.join().unwrap())
    });
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let rejection = left.err().or_else(|| right.err()).unwrap();
    assert!(rejection.contains("exhausted") || rejection.contains("epoch"));

    let reopened = PublicationLedger::open(&path, registry, 3).unwrap();
    let state = reopened
        .budget_state(&scope, "QOMM", "request_count")
        .unwrap()
        .unwrap();
    assert_eq!((state.0, state.1), (500_000, 500_000));
    assert!([1, 2].contains(&state.2));
    assert!(reopened
        .publish_with(request(scope, b"third publication", 3), &mechanism, |_| Ok(
            Vec::new()
        ),)
        .unwrap_err()
        .contains("exhausted"));
}

#[test]
fn two_signers_never_debit_the_persistent_budget() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("publication.json");
    let keys = keys();
    let registry = registry(&keys);
    let scope: [u8; 32] = Sha256::digest(b"legal-entity group B").into();
    let allocation = BudgetAllocation {
        budget_scope: scope,
        venue: "QOMM".into(),
        output_name: "request_count".into(),
        total_micros: 1_000_000,
        policy_version: 1,
    };
    let ledger = PublicationLedger::open(&path, registry, 3).unwrap();
    ledger
        .configure_budget(
            allocation.clone(),
            &signatures(&allocation.body().unwrap(), &keys, 3),
        )
        .unwrap();
    let mechanism = DpMechanism::new(500_000, 3, 32).unwrap();
    let operation = request(scope, b"under-signed", 1);
    let operation_id = operation.operation_id;
    assert!(ledger
        .publish_with(operation, &mechanism, |statement| {
            Ok(signatures(&statement.body().unwrap(), &keys, 2))
        })
        .unwrap_err()
        .contains("3-of-7"));
    assert_eq!(
        ledger
            .budget_state(&scope, "QOMM", "request_count")
            .unwrap(),
        Some((1_000_000, 0, 0))
    );
    // A failed certificate did not leave a replay marker either; the exact
    // operation can be retried after the missing node returns.
    let certificate = ledger
        .publish_with(
            PublicationRequest {
                operation_id,
                ..request(scope, b"ignored replacement digest", 1)
            },
            &mechanism,
            |statement| Ok(signatures(&statement.body().unwrap(), &keys, 3)),
        )
        .unwrap();
    assert_ne!(certificate.digest().unwrap(), ZERO);
    assert!(ledger
        .publish_with(
            PublicationRequest {
                operation_id,
                ..request(scope, b"ignored replay digest", 2)
            },
            &mechanism,
            |_| Ok(Vec::new()),
        )
        .unwrap_err()
        .contains("already committed"));
}

#[test]
fn governance_cannot_fabricate_a_release_and_mpc_nodes_cannot_allocate_budget() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("separated-publication.json");
    let publication_keys = keys();
    let governance_keys = keys();
    let publication_registry = registry(&publication_keys);
    let governance_registry = registry(&governance_keys);
    let scope: [u8; 32] = Sha256::digest(b"separated legal-entity scope").into();
    let allocation = BudgetAllocation {
        budget_scope: scope,
        venue: "QOMM".into(),
        output_name: "request_count".into(),
        total_micros: 1_000_000,
        policy_version: 1,
    };
    let ledger = PublicationLedger::open_with_registries(
        &path,
        publication_registry,
        3,
        governance_registry,
        3,
    )
    .unwrap();
    assert!(ledger
        .configure_budget(
            allocation.clone(),
            &signatures(&allocation.body().unwrap(), &publication_keys, 3),
        )
        .unwrap_err()
        .contains("approval"));
    ledger
        .configure_budget(
            allocation,
            &signatures(
                &BudgetAllocation {
                    budget_scope: scope,
                    venue: "QOMM".into(),
                    output_name: "request_count".into(),
                    total_micros: 1_000_000,
                    policy_version: 1,
                }
                .body()
                .unwrap(),
                &governance_keys,
                3,
            ),
        )
        .unwrap();
    let mechanism = DpMechanism::new(500_000, 1, 16).unwrap();
    let operation = request(scope, b"separated publication", 1);
    let operation_id = operation.operation_id;
    assert!(ledger
        .publish_with(operation, &mechanism, |statement| {
            Ok(signatures(&statement.body().unwrap(), &governance_keys, 3))
        })
        .unwrap_err()
        .contains("3-of-7"));
    let certificate = ledger
        .publish_with(
            PublicationRequest {
                operation_id,
                ..request(scope, b"same operation retry", 1)
            },
            &mechanism,
            |statement| Ok(signatures(&statement.body().unwrap(), &publication_keys, 3)),
        )
        .unwrap();
    assert_eq!(certificate.signatures.len(), 3);
}
