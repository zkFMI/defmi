use ed25519_dalek::SigningKey;
use qomm_mpc::inputs::DvpInputs;
use qomm_mpc::program::{build_program, ProgramConfig, Reference, StopAfter};
use qomm_transport::executor::ProgramRegistry;
use qomm_transport::key_management::EncryptedKeyStore;
use qomm_transport::resident_mpc::ResidentMpcConfig;
use qomm_transport::wan_deployment::{
    apply_node_response, initialize_authority, initialize_node, initialize_node_mpc_state,
    prepare_node_mpc_runtime, sign_node_requests, NodeMpcShareBundle, WanDeploymentSpec,
    WanNodeSpec,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn spec(root: &Path) -> WanDeploymentSpec {
    let receipt = SigningKey::from_bytes(&[91_u8; 32]).verifying_key();
    WanDeploymentSpec {
        version: 1,
        deployment_id: "qomm-wan-test".into(),
        venue_scope: "QOMM/test/KYB".into(),
        jurisdiction: "JP".into(),
        entity_type: "regulated-dealer".into(),
        minimum_collateral_tier: 2,
        maximum_collateral_tier: 5,
        registry_epoch: 1,
        registry_expires_at: now() + 86_400,
        ca_lifetime_days: 30,
        certificate_lifetime_days: 7,
        coordinator_common_name: "qomm-test-coordinator".into(),
        client_common_name: "qomm-test-client".into(),
        client_control_group_id: "test-governance-pseudonym".into(),
        trusted_defmi_receipt_public: hex::encode(receipt.as_bytes()),
        n_mm: 4,
        n_parties: 7,
        threshold: 2,
        amount_bits: 16,
        price_bits: 32,
        remainder_bits: 32,
        quote_eligibility_bits: 34,
        quote_span_bits: 32,
        mpc_program: ProgramConfig {
            n_mm: 4,
            n_parties: 7,
            n_requests: 1,
            n_assets: 1,
            ref_table: vec![100_000],
            maker_assets: vec![0; 4],
            public_maker_assets: true,
            bit_length: 31,
            binding_limit: true,
            stop_after: StopAfter::Tournament,
            persist_wires: true,
            persist_zkpi_wires: true,
            persist_quote_proof_wires: true,
            persist_dvp_wires: true,
            zkpi_amount_bits: 16,
            zkpi_price_bits: 32,
            dvp_remainder_bits: 32,
            quote_eligibility_bits: 34,
            quote_span_bits: 32,
            reference: Reference::Anchored,
            ..ProgramConfig::default()
        },
        nodes: (0_u16..7)
            .map(|node| WanNodeSpec {
                node,
                organization_id: format!("org-{node}"),
                host: format!("node-{node}.qomm.test"),
                bind_host: "0.0.0.0".into(),
                resident_port: 9_443,
                proof_port: 9_543,
                mpc_port: 9_643,
                state_root: root.join(format!("state/node-{node}")),
                program_registry: root.join(format!("registry/node-{node}.json")),
                restart_argv: vec!["/usr/bin/true".into()],
                restart_proof_argv: vec!["/usr/bin/true".into()],
            })
            .collect(),
    }
}

fn mode(path: impl AsRef<Path>) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn read_json(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut found = Vec::new();
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
            } else {
                found.push(entry.path());
            }
        }
    }
    found
}

#[test]
fn split_knowledge_provisioning_creates_all_seven_configs_and_rejects_tampering() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let spec = spec(root);
    spec.validate(now()).unwrap();
    let authority = root.join("authority");
    let nodes = root.join("nodes");
    let requests = root.join("requests");
    let responses = root.join("responses");
    fs::create_dir(&nodes).unwrap();
    fs::create_dir(&requests).unwrap();

    initialize_authority(&spec, &authority).unwrap();
    for node in 0_u16..7 {
        initialize_node(
            &spec,
            node,
            &nodes.join(format!("node-{node}")),
            &requests.join(format!("node-{node}")),
            &authority.join("public/ca.cert.pem"),
        )
        .unwrap();
    }
    sign_node_requests(&spec, &authority, &requests, &responses).unwrap();

    let public_request_path = requests.join("node-0/node-request.json");
    let original_public_request = fs::read(&public_request_path).unwrap();
    let mut changed_public_request: Value =
        serde_json::from_slice(&original_public_request).unwrap();
    changed_public_request["trusted_ca_certificate_sha256"] = Value::String("00".repeat(32));
    fs::write(
        &public_request_path,
        serde_json::to_vec_pretty(&changed_public_request).unwrap(),
    )
    .unwrap();
    let error = apply_node_response(
        &spec,
        0,
        &nodes.join("node-0"),
        &requests.join("node-0"),
        &responses.join("node-0"),
    )
    .unwrap_err();
    assert!(error.contains("public enrollment request changed"));
    fs::write(&public_request_path, original_public_request).unwrap();

    let frame = responses.join("node-0/client-frame.key");
    let original_frame = fs::read(&frame).unwrap();
    let mut changed_frame = original_frame.clone();
    changed_frame[0] ^= 1;
    fs::write(&frame, &changed_frame).unwrap();
    fs::set_permissions(&frame, fs::Permissions::from_mode(0o600)).unwrap();
    let error = apply_node_response(
        &spec,
        0,
        &nodes.join("node-0"),
        &requests.join("node-0"),
        &responses.join("node-0"),
    )
    .unwrap_err();
    assert!(error.contains("changed client-frame.key"));
    fs::write(&frame, original_frame).unwrap();
    fs::set_permissions(&frame, fs::Permissions::from_mode(0o600)).unwrap();

    let peer_certificate = responses.join("node-0/mpc-player-data/P0.pem");
    let original_peer_certificate = fs::read(&peer_certificate).unwrap();
    let mut changed_peer_certificate = original_peer_certificate.clone();
    changed_peer_certificate[0] ^= 1;
    fs::write(&peer_certificate, &changed_peer_certificate).unwrap();
    let error = apply_node_response(
        &spec,
        0,
        &nodes.join("node-0"),
        &requests.join("node-0"),
        &responses.join("node-0"),
    )
    .unwrap_err();
    assert!(error.contains("mpc-player-data/P0.pem"));
    fs::write(&peer_certificate, original_peer_certificate).unwrap();

    for node in 0_u16..7 {
        let node_root = nodes.join(format!("node-{node}"));
        apply_node_response(
            &spec,
            node,
            &node_root,
            &requests.join(format!("node-{node}")),
            &responses.join(format!("node-{node}")),
        )
        .unwrap();
        let node_config = read_json(node_root.join("node.json"));
        let proof_config = read_json(node_root.join("proof-party.json"));
        assert_eq!(node_config["node"], node);
        assert_eq!(
            node_config["program_registry"].as_str(),
            spec.node(node).unwrap().program_registry.to_str()
        );
        assert_eq!(proof_config["node"], node);
        assert_eq!(proof_config["n_parties"], 7);
        assert_eq!(proof_config["threshold"], 2);
        assert_eq!(proof_config["complete_quote_proof"], true);
        assert_eq!(proof_config["allow_health_signing"], false);
        assert!(!node_root.join("proof-state.qps").exists());
        assert_eq!(mode(node_root.join("private/node.key.pem")), 0o600);
        assert_eq!(mode(node_root.join("private/mpc.key.pem")), 0o600);
        assert_eq!(mode(node_root.join("private/trusted-ca.cert.pem")), 0o600);
        assert_eq!(
            mode(node_root.join("private/enrollment-request.json")),
            0o600
        );
        assert_eq!(mode(node_root.join("private/sealing-keys.qks")), 0o600);
        assert_eq!(
            mode(node_root.join("private/proof-state.passphrase")),
            0o600
        );
        assert_eq!(mode(node_root.join("private/mpc-state.passphrase")), 0o600);
        assert_eq!(mode(node_root.join("node.json")), 0o600);
        assert_eq!(mode(node_root.join("proof-party.json")), 0o600);
        let passphrase = fs::read(node_root.join("private/sealing-store.passphrase")).unwrap();
        let store = EncryptedKeyStore::new(node_root.join("private/sealing-keys.qks"), &passphrase)
            .unwrap();
        assert_eq!(store.snapshot().unwrap().keys.len(), 3);
        let player_data = node_root.join("mpc-player-data");
        let names = fs::read_dir(&player_data)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            names.iter().filter(|name| name.ends_with(".pem")).count(),
            7
        );
        assert_eq!(
            names.iter().filter(|name| name.ends_with(".key")).count(),
            1
        );
        assert!(names.contains(&format!("P{node}.key")));
        assert_eq!(names.iter().filter(|name| name.ends_with(".0")).count(), 7);
    }

    let authority_files = files(&authority)
        .into_iter()
        .map(|path| fs::read(path).unwrap())
        .collect::<Vec<_>>();
    for node in 0_u16..7 {
        let private_key =
            fs::read(nodes.join(format!("node-{node}/private/node.key.pem"))).unwrap();
        assert!(!authority_files.iter().any(|file| file == &private_key));
        let mpc_private_key =
            fs::read(nodes.join(format!("node-{node}/private/mpc.key.pem"))).unwrap();
        assert!(!authority_files.iter().any(|file| file == &mpc_private_key));
        let public_request = fs::read(requests.join(format!("node-{node}/node.csr.pem"))).unwrap();
        assert!(!public_request
            .windows(11)
            .any(|window| window == b"PRIVATE KEY"));
        let public_mpc_request =
            fs::read(requests.join(format!("node-{node}/mpc.csr.pem"))).unwrap();
        assert!(!public_mpc_request
            .windows(11)
            .any(|window| window == b"PRIVATE KEY"));
    }
    let manifest = read_json(authority.join("authority-manifest.json"));
    assert_eq!(manifest["node_private_keys_received"], false);
    assert_eq!(manifest["frost_secret_shares_created"], false);
    assert_eq!(manifest["hardware_hsm_verified"], false);
    assert!(initialize_authority(&spec, &authority)
        .unwrap_err()
        .contains("overwrite"));
}

#[test]
fn deployment_spec_rejects_host_aliases_and_non_three_of_seven_thresholds() {
    let temporary = tempfile::tempdir().unwrap();
    let mut duplicate = spec(temporary.path());
    duplicate.nodes[1].host = duplicate.nodes[0].host.clone();
    assert!(duplicate.validate(now()).unwrap_err().contains("distinct"));

    let mut threshold = spec(temporary.path());
    threshold.threshold = 3;
    assert!(threshold.validate(now()).unwrap_err().contains("3-of-7"));
}

fn fake_mp_spdz_checkout(root: &Path) {
    for directory in [
        "Compiler",
        "Programs/Source",
        "Programs/Schedules",
        "Programs/Bytecode",
    ] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    let compiler = root.join(format!("compile.{}", ["p", "y"].concat()));
    fs::write(
        &compiler,
        concat!(
            "#!/bin/sh\n",
            "set -eu\n",
            "program=\"$3\"\n",
            "printf 'schedule %s\\n' \"$program\" > \"Programs/Schedules/${program}.sch\"\n",
            "printf 'bytecode %s\\n' \"$program\" > \"Programs/Bytecode/${program}-0.bc\"\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&compiler, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.join("Compiler/compilerLib.py"), "upstream fixture\n").unwrap();
    fs::write(root.join("README.md"), "MP-SPDZ fixture\n").unwrap();
    for executable in ["malicious-shamir-party.x", "qomm-node-party"] {
        let path = root.join(executable);
        fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(root.join("libSPDZ.so"), b"linked MP-SPDZ fixture\n").unwrap();
}

fn write_private_json(path: &Path, value: &impl serde::Serialize) {
    let bytes = serde_json::to_vec_pretty(value).unwrap();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn node_local_mpc_state_and_runtime_are_fully_bound_without_foreign_keys() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let spec = spec(root);
    let authority = root.join("authority");
    let nodes = root.join("nodes");
    let requests = root.join("requests");
    let responses = root.join("responses");
    fs::create_dir(&nodes).unwrap();
    fs::create_dir(&requests).unwrap();
    initialize_authority(&spec, &authority).unwrap();
    for node in 0_u16..7 {
        initialize_node(
            &spec,
            node,
            &nodes.join(format!("node-{node}")),
            &requests.join(format!("node-{node}")),
            &authority.join("public/ca.cert.pem"),
        )
        .unwrap();
    }
    sign_node_requests(&spec, &authority, &requests, &responses).unwrap();
    let node_root = nodes.join("node-0");
    apply_node_response(
        &spec,
        0,
        &node_root,
        &requests.join("node-0"),
        &responses.join("node-0"),
    )
    .unwrap();

    let source = build_program(&spec.mpc_program).unwrap();
    let source_sha256 = hex::encode(Sha256::digest(source.as_bytes()));
    let bundle = NodeMpcShareBundle {
        version: 1,
        node: 0,
        generation: 1,
        source_sha256: source_sha256.clone(),
        dvp_input_shares: vec!["0".into(); DvpInputs::standing_value_count(spec.n_mm)],
        policy_input_shares: vec!["0".into(); spec.n_mm * 10],
        quote_policy_blinding_input_shares: vec!["0".into(); spec.n_mm * 9],
    };
    let shares = root.join("node-0-shares.json");
    write_private_json(&shares, &bundle);
    fs::set_permissions(&shares, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(initialize_node_mpc_state(&spec, 0, &node_root, &shares)
        .unwrap_err()
        .contains("mode-600"));
    fs::set_permissions(&shares, fs::Permissions::from_mode(0o600)).unwrap();
    let state = initialize_node_mpc_state(&spec, 0, &node_root, &shares).unwrap();
    assert_eq!(state.source_sha256, source_sha256);
    assert_eq!(state.generation, 1);
    assert_eq!(mode(&state.encrypted_state), 0o600);
    assert!(initialize_node_mpc_state(&spec, 0, &node_root, &shares)
        .unwrap_err()
        .contains("already exists"));

    let checkout = root.join("MP-SPDZ");
    fake_mp_spdz_checkout(&checkout);
    let foreign_key = node_root.join("mpc-player-data/P1.key");
    fs::write(&foreign_key, b"foreign private key\n").unwrap();
    fs::set_permissions(&foreign_key, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(prepare_node_mpc_runtime(
        &spec,
        0,
        &node_root,
        &checkout,
        &checkout.join("qomm-node-party"),
    )
    .unwrap_err()
    .contains("only P0.key"));
    fs::remove_file(foreign_key).unwrap();

    fs::create_dir(checkout.join("Player-Data")).unwrap();
    fs::write(
        checkout.join("Player-Data/P1.key"),
        b"foreign checkout key\n",
    )
    .unwrap();
    assert!(prepare_node_mpc_runtime(
        &spec,
        0,
        &node_root,
        &checkout,
        &checkout.join("qomm-node-party"),
    )
    .unwrap_err()
    .contains("checkout contains transport private key"));
    fs::remove_dir_all(checkout.join("Player-Data")).unwrap();

    let runtime = prepare_node_mpc_runtime(
        &spec,
        0,
        &node_root,
        &checkout,
        &checkout.join("qomm-node-party"),
    )
    .unwrap();
    assert_eq!(runtime.source_sha256, source_sha256);
    assert_eq!(runtime.public_peer_certificates, 7);
    assert_eq!(runtime.local_private_keys, 1);
    assert_eq!(mode(&runtime.runtime_config), 0o600);
    assert_eq!(mode(&runtime.launcher), 0o700);
    assert_eq!(mode(&runtime.program_registry), 0o600);
    let config: ResidentMpcConfig =
        serde_json::from_slice(&fs::read(&runtime.runtime_config).unwrap()).unwrap();
    config.verify(&source_sha256).unwrap();
    assert_eq!(
        config
            .player_data_artifacts
            .keys()
            .filter(|name| name.ends_with(".key"))
            .cloned()
            .collect::<Vec<_>>(),
        vec!["P0.key".to_string()]
    );
    assert!(ProgramRegistry::from_json(0, &runtime.program_registry).is_ok());
    assert!(prepare_node_mpc_runtime(
        &spec,
        0,
        &node_root,
        &checkout,
        &checkout.join("qomm-node-party"),
    )
    .unwrap_err()
    .contains("overwrite"));
}
