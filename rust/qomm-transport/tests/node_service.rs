use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use openssl::x509::X509;
use qomm_dsl::registry::CircuitRegistry;
use qomm_mpc::program::{build_program, policy_rule_source, ProgramConfig, POLICY_RULE_NAME};
use qomm_proofs::kyb::{
    cohort_id, present, BusinessAttributes, EntityLimits, KybCredential, KybIssuer,
};
use qomm_transport::executor::{
    circuit_shape_digest, write_source_bound_runtime_executable, ProgramRegistry,
    RegisteredProgram, RuntimeBinding,
};
use qomm_transport::key_management::{create_ca, issue_mutual_tls_certificate, write_tls_bundle};
use qomm_transport::node_service::{
    certificate_fingerprint, client_ssl_context, server_ssl_context, KybPolicy, NodeSealingKeys,
    NodeStore, Principal, RateLimitPolicy, ResidentNodeClient, ResidentNodeLocalClient,
    ResidentNodeServer, RECORD_BYTES,
};
use qomm_transport::wire::{Frame, PAYLOAD_BYTES};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const KYB_SCOPE: &[u8] = b"qomm-test-venue/orders";

struct Bundle {
    key: PathBuf,
    cert: PathBuf,
    ca: PathBuf,
    x509: X509,
}

#[derive(Clone, Copy)]
enum TestTransport {
    Tcp,
    Local,
}

enum TestClient {
    Tcp(ResidentNodeClient),
    Local(ResidentNodeLocalClient),
}

impl TestClient {
    fn call(&mut self, request: &Value) -> Result<Value, String> {
        match self {
            Self::Tcp(client) => client.call(request),
            Self::Local(client) => client.call(request),
        }
    }

    fn close(&mut self) {
        match self {
            Self::Tcp(client) => client.close(),
            Self::Local(client) => client.close(),
        }
    }
}

fn start_transport(server: &mut ResidentNodeServer) -> TestTransport {
    match server.start() {
        Ok(_) => TestTransport::Tcp,
        Err(error) if error.contains("Operation not permitted") => TestTransport::Local,
        Err(error) => panic!("node listener failed: {error}"),
    }
}

fn test_client(
    transport: TestTransport,
    server: &ResidentNodeServer,
    bundle: &Bundle,
) -> TestClient {
    let tls = client_ssl_context(&bundle.cert, &bundle.key, &bundle.ca).unwrap();
    match transport {
        TestTransport::Tcp => TestClient::Tcp(ResidentNodeClient::new(
            "127.0.0.1",
            server.port,
            tls,
            "node-0",
            3,
        )),
        TestTransport::Local => TestClient::Local(server.local_client(tls, "node-0", 3)),
    }
}

fn pki(directory: &tempfile::TempDir) -> BTreeMap<String, Bundle> {
    let (ca_key, ca_cert) = create_ca("test-ca", 3650).unwrap();
    ["node-0", "client-0", "client-1", "coordinator"]
        .into_iter()
        .map(|name| {
            let (key, cert) =
                issue_mutual_tls_certificate(&ca_key, &ca_cert, name, &[name], &["127.0.0.1"], 30)
                    .unwrap();
            let (key_path, cert_path, ca_path) =
                write_tls_bundle(directory.path().join(name), name, &key, &cert, &ca_cert).unwrap();
            (
                name.into(),
                Bundle {
                    key: key_path,
                    cert: cert_path,
                    ca: ca_path,
                    x509: cert,
                },
            )
        })
        .collect()
}

fn raw_frame(slot: u32, marker: u8, key: &[u8]) -> Vec<u8> {
    let mut payload = [0_u8; PAYLOAD_BYTES];
    payload[0] = marker;
    Frame::new(slot, 0, payload, key).unwrap().encode().to_vec()
}

fn request(id: &str, slot: u32, raw: &[u8]) -> Value {
    let claim: [u8; 32] = Sha256::new()
        .chain_update(b"QOMM:TEST:ADMISSION-CLAIM:v1")
        .chain_update(slot.to_be_bytes())
        .chain_update(raw)
        .finalize()
        .into();
    json!({
        "version": 1,
        "request_id": id,
        "operation": "submit",
        "slot": slot,
        "frame": BASE64.encode(raw),
        "admission_claim_digest": hex::encode(claim),
    })
}

fn entity(number: u64) -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT * Scalar::from(number)
}

fn kyb_clients(
    entries: &[(&Bundle, Vec<u8>, &str)],
) -> (
    Arc<KybPolicy>,
    BTreeMap<String, Principal>,
    Vec<RistrettoPoint>,
) {
    let mut issuer = KybIssuer::new(5, &mut rand_core::OsRng);
    let mut credentials = BTreeMap::<String, KybCredential>::new();
    for (_, _, group) in entries {
        if !credentials.contains_key(*group) {
            credentials.insert(
                (*group).to_string(),
                issuer
                    .enroll(
                        group,
                        BusinessAttributes {
                            jurisdiction: "JP".into(),
                            entity_type: "bank".into(),
                            collateral_tier: 3,
                        },
                        &mut rand_core::OsRng,
                    )
                    .unwrap(),
            );
        }
    }
    let cohort = cohort_id("JP", "bank", 2);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let registry = issuer.publish(&cohort, 1, now + 3_600).unwrap();
    let mut principals = BTreeMap::new();
    let mut nullifiers = Vec::new();
    for (bundle, key, group) in entries {
        let fingerprint = certificate_fingerprint(&bundle.x509.to_der().unwrap());
        let credential = &credentials[*group];
        let presentation = present(
            credential,
            &registry,
            KYB_SCOPE,
            fingerprint.as_bytes(),
            &mut rand_core::OsRng,
        )
        .unwrap();
        let nullifier = credential.scope_nullifier(KYB_SCOPE);
        principals.insert(
            fingerprint,
            Principal::client(key.clone(), &nullifier, presentation).unwrap(),
        );
        nullifiers.push(nullifier);
    }
    let policy = Arc::new(
        KybPolicy::new(KYB_SCOPE.to_vec(), cohort, registry, issuer.public_key()).unwrap(),
    );
    (policy, principals, nullifiers)
}

fn approved_registry(node: u16, directory: &Path) -> (Arc<ProgramRegistry>, String) {
    let config = ProgramConfig::default();
    let generated = build_program(&config).unwrap();
    let shape = [
        config.n_mm as u64,
        config.n_parties as u64,
        u64::from(config.bit_length),
    ];
    let mut circuits = CircuitRegistry::default();
    circuits
        .approve(
            POLICY_RULE_NAME,
            &policy_rule_source(&config),
            &generated,
            &shape,
        )
        .unwrap();
    let runtime_executable = directory.join(format!("node-{node}-runtime"));
    let runtime_fixture = format!(
        concat!(
            "#!/bin/sh\n",
            "set -eu\n",
            "node= slot= batch= lane= source=\n",
            "while [ \"$#\" -gt 0 ]; do\n",
            "  case \"$1\" in\n",
            "    --config) shift 2 ;;\n",
            "    --node) node=\"$2\"; shift 2 ;;\n",
            "    --slot) slot=\"$2\"; shift 2 ;;\n",
            "    --batch-digest) batch=\"$2\"; shift 2 ;;\n",
            "    --lane) lane=\"$2\"; shift 2 ;;\n",
            "    --source-digest) source=\"$2\"; shift 2 ;;\n",
            "    *) exit 64 ;;\n",
            "  esac\n",
            "done\n",
            "cat >/dev/null\n",
            "printf '{{\"node\":%s,\"slot\":%s,\"lane\":%s,",
            "\"batch_digest\":\"%s\",\"source_digest\":\"%s\",",
            "\"state_generation\":1,\"frame_count\":1,\"input_count\":1,",
            "\"elapsed_ns\":1,\"stdout_digest\":\"{}\",",
            "\"stderr_digest\":\"{}\",",
            "\"persistence_path\":\"/private/Transactions-P%s.data\",",
            "\"persistence_digest\":\"{}\"}}\\n' ",
            "\"$node\" \"$slot\" \"$lane\" \"$batch\" \"$source\" \"$node\"\n",
        ),
        "05".repeat(32),
        "06".repeat(32),
        "07".repeat(32),
    );
    fs::write(&runtime_executable, runtime_fixture).unwrap();
    fs::set_permissions(&runtime_executable, fs::Permissions::from_mode(0o700)).unwrap();
    let runtime_executable = fs::canonicalize(runtime_executable).unwrap();
    let runtime_config = directory.join(format!("node-{node}-runtime.json"));
    fs::write(&runtime_config, b"{\"version\":1}\n").unwrap();
    fs::set_permissions(&runtime_config, fs::Permissions::from_mode(0o600)).unwrap();
    let runtime_config = fs::canonicalize(runtime_config).unwrap();
    let runtime = RuntimeBinding {
        executable: runtime_executable.clone(),
        executable_sha256: hex::encode(sha2::Sha256::digest(
            fs::read(&runtime_executable).unwrap(),
        )),
        config: runtime_config.clone(),
        config_sha256: hex::encode(sha2::Sha256::digest(fs::read(&runtime_config).unwrap())),
    };
    let executable = directory.join(format!("node-{node}-compute"));
    write_source_bound_runtime_executable(&executable, &generated, &runtime).unwrap();
    let executable = fs::canonicalize(executable).unwrap();
    let shape_digest = circuit_shape_digest(&shape);
    let program = RegisteredProgram {
        shape_digest: shape_digest.clone(),
        argv: vec![
            executable.display().to_string(),
            "{node}".into(),
            "{slot}".into(),
            "{batch_digest}".into(),
        ],
        cwd: directory.to_path_buf(),
        executable_sha256: hex::encode(sha2::Sha256::digest(fs::read(&executable).unwrap())),
        runtime: Some(runtime),
        timeout_seconds: 5.0,
    };
    let registry =
        ProgramRegistry::from_approved_mpc(node, program, &circuits, &config, &shape).unwrap();
    (Arc::new(registry), shape_digest)
}

#[test]
fn unapproved_computation_registry_is_refused_before_listening() {
    let directory = tempfile::tempdir().unwrap();
    let bundles = pki(&directory);
    let node = &bundles["node-0"];
    let executable = fs::canonicalize("/bin/echo").unwrap();
    let program = RegisteredProgram {
        shape_digest: circuit_shape_digest(&[7, 2, 64]),
        argv: vec![executable.display().to_string(), "ok".into()],
        cwd: directory.path().to_path_buf(),
        executable_sha256: hex::encode(sha2::Sha256::digest(fs::read(&executable).unwrap())),
        runtime: None,
        timeout_seconds: 5.0,
    };
    let unapproved = Arc::new(ProgramRegistry::new(0, vec![program]).unwrap());
    let error = match ResidentNodeServer::new(
        0,
        "127.0.0.1",
        0,
        server_ssl_context(&node.cert, &node.key, &node.ca).unwrap(),
        BTreeMap::new(),
        None,
        NodeSealingKeys::generate_for_testing(),
        Arc::new(NodeStore::open(directory.path().join("node.sqlite3")).unwrap()),
        Some(unapproved),
        RateLimitPolicy::default(),
        Duration::from_secs(5),
        Duration::ZERO,
    ) {
        Ok(_) => panic!("an unapproved computation registry reached the listener"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        "resident nodes require a qomm-dsl-approved qomm-mpc program registry"
    );
}

#[test]
fn real_mutual_tls_fixed_records_durable_idempotency_and_reconnect() {
    let directory = tempfile::tempdir().unwrap();
    let bundles = pki(&directory);
    let node = &bundles["node-0"];
    let client_bundle = &bundles["client-0"];
    let coordinator_bundle = &bundles["coordinator"];
    let frame_key = vec![b'f'; 32];
    let client_fingerprint = certificate_fingerprint(&client_bundle.x509.to_der().unwrap());
    let coordinator_fingerprint =
        certificate_fingerprint(&coordinator_bundle.x509.to_der().unwrap());
    let store = Arc::new(NodeStore::open(directory.path().join("node.sqlite3")).unwrap());
    let (registry, shape_digest) = approved_registry(0, directory.path());
    let (kyb_policy, mut principals, _) =
        kyb_clients(&[(client_bundle, frame_key.clone(), "entity-7")]);
    assert!(principals.contains_key(&client_fingerprint));
    principals.insert(coordinator_fingerprint, Principal::coordinator());
    let mut server = ResidentNodeServer::new(
        0,
        "127.0.0.1",
        0,
        server_ssl_context(&node.cert, &node.key, &node.ca).unwrap(),
        principals,
        Some(kyb_policy),
        NodeSealingKeys::generate_for_testing(),
        Arc::clone(&store),
        Some(Arc::clone(&registry)),
        RateLimitPolicy::default(),
        Duration::from_secs(5),
        Duration::ZERO,
    )
    .unwrap();
    let transport = start_transport(&mut server);
    let mut client = test_client(transport, &server, client_bundle);
    let raw = raw_frame(9, b'p', &frame_key);
    let submitted = request("submit-9", 9, &raw);
    let first = client.call(&submitted).unwrap();
    let second = client.call(&submitted).unwrap();
    assert_eq!(first, second);
    assert_eq!(first["accepted"], true);
    assert_eq!(store.frame_count().unwrap(), 1);
    assert_eq!(store.request_count().unwrap(), 1);
    client.close();
    assert_eq!(client.call(&submitted).unwrap(), first);
    client.close();

    let mut coordinator = test_client(transport, &server, coordinator_bundle);
    let closed = coordinator
        .call(&json!({"version": 1, "request_id": "close-9", "operation": "close_slot", "slot": 9}))
        .unwrap();
    assert_eq!(closed["closed"], true);
    let job = json!({"version": 1, "request_id": "compute-9", "operation": "compute",
                     "slot": 9, "shape_digest": shape_digest,
                     "batch_digest": "00".repeat(32), "frames": ["caller-controlled"]});
    let computed = coordinator.call(&job).unwrap();
    assert_eq!(computed["ok"], true);
    assert_eq!(computed["batch_digest"], closed["batch_digest"]);
    assert_eq!(computed["stdout_digest"].as_str().unwrap().len(), 64);
    assert_eq!(coordinator.call(&job).unwrap(), computed);
    assert_eq!(
        registry.execution_count(),
        1,
        "idempotent retry ran computation twice"
    );
    assert_eq!(store.request_count().unwrap(), 3);
    coordinator.close();
    server.stop();
    assert_eq!(
        qomm_transport::node_service::encode_record(&json!({"ok": true}))
            .unwrap()
            .len(),
        RECORD_BYTES
    );
}

#[test]
fn frame_replacement_bad_mac_and_changed_idempotency_body_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let bundles = pki(&directory);
    let node = &bundles["node-0"];
    let client_bundle = &bundles["client-0"];
    let key = vec![b'f'; 32];
    let fingerprint = certificate_fingerprint(&client_bundle.x509.to_der().unwrap());
    let store = Arc::new(NodeStore::open(directory.path().join("node.sqlite3")).unwrap());
    let (kyb_policy, principals, _) = kyb_clients(&[(client_bundle, key.clone(), "entity-8")]);
    assert!(principals.contains_key(&fingerprint));
    let mut server = ResidentNodeServer::new(
        0,
        "127.0.0.1",
        0,
        server_ssl_context(&node.cert, &node.key, &node.ca).unwrap(),
        principals,
        Some(kyb_policy),
        NodeSealingKeys::generate_for_testing(),
        Arc::clone(&store),
        None,
        RateLimitPolicy::default(),
        Duration::from_secs(5),
        Duration::ZERO,
    )
    .unwrap();
    let transport = start_transport(&mut server);
    let mut client = test_client(transport, &server, client_bundle);
    let raw = raw_frame(10, b'p', &key);
    let good = request("a", 10, &raw);
    assert_eq!(client.call(&good).unwrap()["ok"], true);
    let mut moved = raw.clone();
    moved[20] ^= 1;
    let bad = request("b", 10, &moved);
    let reply = client.call(&bad).unwrap();
    assert_eq!(reply["ok"], false);
    assert!(reply["message"].as_str().unwrap().contains("MAC"));

    let replacement = request("c", 10, &raw_frame(10, b'q', &key));
    let reply = client.call(&replacement).unwrap();
    assert_eq!(reply["ok"], false);
    assert!(reply["message"].as_str().unwrap().contains("replace"));

    let changed_body = request("a", 11, &raw_frame(11, b'p', &key));
    let reply = client.call(&changed_body).unwrap();
    assert_eq!(reply["ok"], false);
    assert!(reply["message"].as_str().unwrap().contains("reused"));
    assert_eq!(store.frame_count().unwrap(), 1);
    assert_eq!(
        store.request_count().unwrap(),
        2,
        "the refused replacement id remains durably reserved"
    );
    client.close();
    server.stop();
}

#[test]
fn fresh_wallet_cannot_bypass_a_legal_entity_scope_cap() {
    let directory = tempfile::tempdir().unwrap();
    let bundles = pki(&directory);
    let node = &bundles["node-0"];
    let wallet_a = &bundles["client-0"];
    let wallet_b = &bundles["coordinator"];
    let key_a = vec![b'a'; 32];
    let key_b = vec![b'b'; 32];
    let (kyb_policy, principals, nullifiers) = kyb_clients(&[
        (wallet_a, key_a.clone(), "entity-77"),
        (wallet_b, key_b.clone(), "entity-77"),
    ]);
    assert_eq!(nullifiers[0], nullifiers[1]);
    let scope = nullifiers[0];
    let store = Arc::new(NodeStore::open(directory.path().join("node.sqlite3")).unwrap());
    let policy = RateLimitPolicy {
        limits: EntityLimits {
            max_requests: 1,
            max_probe_lots: 2_000,
            max_epsilon: 1.0,
        },
        slots_per_epoch: 100,
    };
    let mut server = ResidentNodeServer::new(
        0,
        "127.0.0.1",
        0,
        server_ssl_context(&node.cert, &node.key, &node.ca).unwrap(),
        principals,
        Some(kyb_policy),
        NodeSealingKeys::generate_for_testing(),
        Arc::clone(&store),
        None,
        policy,
        Duration::from_secs(5),
        Duration::ZERO,
    )
    .unwrap();
    let transport = start_transport(&mut server);
    let mut first = test_client(transport, &server, wallet_a);
    let mut fresh_wallet = test_client(transport, &server, wallet_b);
    assert_eq!(
        first
            .call(&request("wallet-a", 1, &raw_frame(1, b'a', &key_a)))
            .unwrap()["accepted"],
        true
    );
    let refused = fresh_wallet
        .call(&request("wallet-b", 2, &raw_frame(2, b'b', &key_b)))
        .unwrap();
    assert_eq!(refused["ok"], false);
    assert!(refused["message"]
        .as_str()
        .unwrap()
        .contains("legal entity request cap"));
    assert_eq!(
        store
            .entity_usage(&scope.compress().to_bytes(), policy.current_epoch())
            .unwrap(),
        (1, 0)
    );
    first.close();
    fresh_wallet.close();
    server.stop();
}

#[test]
fn incomplete_duplicate_unclosed_and_unopened_slots_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    let bundles = pki(&directory);
    let node = &bundles["node-0"];
    let client_a = &bundles["client-0"];
    let client_b = &bundles["client-1"];
    let coordinator_bundle = &bundles["coordinator"];
    let key_a = vec![b'a'; 32];
    let key_b = vec![b'b'; 32];
    let (kyb_policy, mut principals, _) = kyb_clients(&[
        (client_a, key_a.clone(), "entity-101"),
        (client_b, key_b.clone(), "entity-102"),
    ]);
    principals.insert(
        certificate_fingerprint(&coordinator_bundle.x509.to_der().unwrap()),
        Principal::coordinator(),
    );
    let store = Arc::new(NodeStore::open(directory.path().join("node.sqlite3")).unwrap());
    let (registry, shape_digest) = approved_registry(0, directory.path());
    let mut server = ResidentNodeServer::new(
        0,
        "127.0.0.1",
        0,
        server_ssl_context(&node.cert, &node.key, &node.ca).unwrap(),
        principals,
        Some(kyb_policy),
        NodeSealingKeys::generate_for_testing(),
        store,
        Some(registry),
        RateLimitPolicy::default(),
        Duration::from_secs(5),
        Duration::ZERO,
    )
    .unwrap();
    let transport = start_transport(&mut server);
    let mut first = test_client(transport, &server, client_a);
    let mut second = test_client(transport, &server, client_b);
    let mut coordinator = test_client(transport, &server, coordinator_bundle);

    assert_eq!(
        first
            .call(&request("short-a", 40, &raw_frame(40, b'a', &key_a)))
            .unwrap()["ok"],
        true
    );
    let short_close = coordinator
        .call(&json!({"version": 1, "request_id": "close-short", "operation": "close_slot", "slot": 40}))
        .unwrap();
    let short_compute = coordinator
        .call(&json!({"version": 1, "request_id": "compute-short", "operation": "compute", "slot": 40, "shape_digest": shape_digest.clone()}))
        .unwrap();

    let duplicate_raw = raw_frame(41, b'd', &key_a);
    assert_eq!(
        first
            .call(&request("duplicate-a", 41, &duplicate_raw))
            .unwrap()["ok"],
        true
    );
    let duplicate = first
        .call(&request("duplicate-b", 41, &duplicate_raw))
        .unwrap();
    assert_eq!(
        second
            .call(&request("duplicate-peer", 41, &raw_frame(41, b'e', &key_b)))
            .unwrap()["ok"],
        true
    );
    let duplicate_close = coordinator
        .call(&json!({"version": 1, "request_id": "close-duplicate", "operation": "close_slot", "slot": 41}))
        .unwrap();

    for (client, id, key, marker) in [
        (&mut first, "open-a", &key_a, b'f'),
        (&mut second, "open-b", &key_b, b'g'),
    ] {
        assert_eq!(
            client
                .call(&request(id, 42, &raw_frame(42, marker, key)))
                .unwrap()["ok"],
            true
        );
    }
    let unclosed = coordinator
        .call(&json!({"version": 1, "request_id": "compute-unclosed", "operation": "compute", "slot": 42, "shape_digest": shape_digest}))
        .unwrap();
    let unopened = coordinator
        .call(&json!({"version": 1, "request_id": "compute-unopened", "operation": "compute", "slot": 43, "shape_digest": shape_digest}))
        .unwrap();

    assert!(
        short_close["ok"] == false
            && short_close["message"]
                .as_str()
                .is_some_and(|message| message.contains("incomplete")),
        "short slot was not distinctly refused: {short_close}"
    );
    assert!(
        short_compute["ok"] == false
            && short_compute["message"]
                .as_str()
                .is_some_and(|message| message.contains("incomplete")),
        "short slot computation was not distinctly refused: {short_compute}"
    );
    assert!(
        duplicate["ok"] == false
            && duplicate["message"]
                .as_str()
                .is_some_and(|message| message.contains("duplicate")),
        "duplicate frame was not refused: {duplicate}"
    );
    assert!(
        duplicate_close["ok"] == false
            && duplicate_close["message"]
                .as_str()
                .is_some_and(|message| message.contains("duplicate")),
        "duplicate slot was not distinctly refused: {duplicate_close}"
    );
    assert!(
        unclosed["ok"] == false
            && unclosed["message"]
                .as_str()
                .is_some_and(|message| message.contains("not closed")),
        "unclosed slot was computed: {unclosed}"
    );
    assert!(
        unopened["ok"] == false
            && unopened["message"]
                .as_str()
                .is_some_and(|message| message.contains("never opened")),
        "unopened slot was computed: {unopened}"
    );

    first.close();
    second.close();
    coordinator.close();
    server.stop();
}

#[test]
fn configured_nullifier_without_a_kyb_presentation_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let bundles = pki(&directory);
    let node = &bundles["node-0"];
    let client = &bundles["client-0"];
    let (kyb_policy, _, _) = kyb_clients(&[(client, vec![b'k'; 32], "entity-500")]);
    let mut principals = BTreeMap::new();
    principals.insert(
        certificate_fingerprint(&client.x509.to_der().unwrap()),
        Principal::client_without_kyb(vec![b'k'; 32], &entity(500)).unwrap(),
    );
    let result = ResidentNodeServer::new(
        0,
        "127.0.0.1",
        0,
        server_ssl_context(&node.cert, &node.key, &node.ca).unwrap(),
        principals,
        Some(kyb_policy),
        NodeSealingKeys::generate_for_testing(),
        Arc::new(NodeStore::open(directory.path().join("node.sqlite3")).unwrap()),
        None,
        RateLimitPolicy::default(),
        Duration::from_secs(5),
        Duration::ZERO,
    );
    let error = match result {
        Ok(_) => panic!("a configured point without a KYB presentation was accepted"),
        Err(error) => error,
    };
    assert!(error.contains("KYB presentation"), "{error}");
}

#[test]
fn kyb_presentation_is_bound_to_venue_scope_and_its_proved_nullifier() {
    let directory = tempfile::tempdir().unwrap();
    let bundles = pki(&directory);
    let node = &bundles["node-0"];
    let client = &bundles["client-0"];
    let fingerprint = certificate_fingerprint(&client.x509.to_der().unwrap());
    let mut issuer = KybIssuer::new(5, &mut rand_core::OsRng);
    let credential = issuer
        .enroll(
            "wrong-scope-entity",
            BusinessAttributes {
                jurisdiction: "JP".into(),
                entity_type: "bank".into(),
                collateral_tier: 3,
            },
            &mut rand_core::OsRng,
        )
        .unwrap();
    let cohort = cohort_id("JP", "bank", 2);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let registry = issuer.publish(&cohort, 1, now + 3_600).unwrap();
    let other_scope = b"another-venue/orders";
    let presentation = present(
        &credential,
        &registry,
        other_scope,
        fingerprint.as_bytes(),
        &mut rand_core::OsRng,
    )
    .unwrap();
    let proved_other_scope = credential.scope_nullifier(other_scope);
    let mismatch = Principal::client(vec![b'k'; 32], &entity(999), presentation.clone())
        .expect_err("a configured nullifier did not have to match the proof");
    assert!(mismatch.contains("does not match"), "{mismatch}");

    let mut principals = BTreeMap::new();
    principals.insert(
        fingerprint,
        Principal::client(vec![b'k'; 32], &proved_other_scope, presentation).unwrap(),
    );
    let policy = Arc::new(
        KybPolicy::new(KYB_SCOPE.to_vec(), cohort, registry, issuer.public_key()).unwrap(),
    );
    let result = ResidentNodeServer::new(
        0,
        "127.0.0.1",
        0,
        server_ssl_context(&node.cert, &node.key, &node.ca).unwrap(),
        principals,
        Some(policy),
        NodeSealingKeys::generate_for_testing(),
        Arc::new(NodeStore::open(directory.path().join("node.sqlite3")).unwrap()),
        None,
        RateLimitPolicy::default(),
        Duration::from_secs(5),
        Duration::ZERO,
    );
    let error = match result {
        Ok(_) => panic!("a KYB presentation for another venue scope was accepted"),
        Err(error) => error,
    };
    assert!(error.contains("venue scope"), "{error}");
}

#[test]
fn caller_selected_slot_cannot_move_the_entity_cap_epoch() {
    let directory = tempfile::tempdir().unwrap();
    let bundles = pki(&directory);
    let node = &bundles["node-0"];
    let client_bundle = &bundles["client-0"];
    let key = vec![b'e'; 32];
    let (kyb_policy, principals, _) = kyb_clients(&[(client_bundle, key.clone(), "entity-600")]);
    let policy = RateLimitPolicy {
        limits: EntityLimits {
            max_requests: 1,
            max_probe_lots: 2_000,
            max_epsilon: 1.0,
        },
        slots_per_epoch: 3_600,
    };
    let mut server = ResidentNodeServer::new(
        0,
        "127.0.0.1",
        0,
        server_ssl_context(&node.cert, &node.key, &node.ca).unwrap(),
        principals,
        Some(kyb_policy),
        NodeSealingKeys::generate_for_testing(),
        Arc::new(NodeStore::open(directory.path().join("node.sqlite3")).unwrap()),
        None,
        policy,
        Duration::from_secs(5),
        Duration::ZERO,
    )
    .unwrap();
    let transport = start_transport(&mut server);
    let mut client = test_client(transport, &server, client_bundle);
    assert_eq!(
        client
            .call(&request("epoch-a", 1, &raw_frame(1, b'a', &key)))
            .unwrap()["ok"],
        true
    );
    let moved = client
        .call(&request(
            "epoch-b",
            u32::MAX - 1,
            &raw_frame(u32::MAX - 1, b'b', &key),
        ))
        .unwrap();
    assert!(
        moved["ok"] == false
            && moved["message"]
                .as_str()
                .is_some_and(|message| message.contains("request cap")),
        "caller-selected slot moved the cap epoch: {moved}"
    );
    client.close();
    server.stop();
}
