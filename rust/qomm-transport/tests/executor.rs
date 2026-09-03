use qomm_dsl::registry::CircuitRegistry;
use qomm_mpc::program::{build_program, policy_rule_source, ProgramConfig, POLICY_RULE_NAME};
use qomm_transport::executor::{
    circuit_shape_digest, write_source_bound_runtime_executable, ProgramRegistry,
    RegisteredProgram, RuntimeBinding,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn fixture(shape: &str, digest: Option<String>) -> (tempfile::TempDir, RegisteredProgram) {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("approved.sh");
    fs::write(&executable, b"#!/bin/sh\nprintf 'ok\\n'\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let actual = hex::encode(Sha256::digest(fs::read(&executable).unwrap()));
    let program = RegisteredProgram {
        shape_digest: shape.into(),
        argv: vec![executable.display().to_string()],
        cwd: directory.path().to_path_buf(),
        executable_sha256: digest.unwrap_or(actual),
        runtime: None,
        timeout_seconds: 5.0,
    };
    (directory, program)
}

#[test]
fn only_a_byte_verified_registered_program_runs() {
    let (_directory, program) = fixture(&"01".repeat(32), None);
    let registry = ProgramRegistry::new(2, vec![program]).unwrap();
    let result = registry
        .execute(&json!({"shape_digest": "01".repeat(32), "slot": 7}))
        .unwrap();
    assert_eq!(result["exit_code"], 0);
    assert_eq!(result["slot"], 7);
    assert_eq!(
        result["stdout_digest"],
        hex::encode(Sha256::digest(b"ok\n"))
    );
}

#[test]
fn unknown_shape_and_substituted_binary_are_refused() {
    let (_directory, program) = fixture(&"01".repeat(32), None);
    let registry = ProgramRegistry::new(2, vec![program]).unwrap();
    assert!(registry
        .execute(&json!({"shape_digest": "02".repeat(32), "slot": 7}))
        .unwrap_err()
        .contains("approved"));
    let (_directory, substituted) = fixture(&"01".repeat(32), Some("00".repeat(32)));
    assert!(ProgramRegistry::new(2, vec![substituted])
        .unwrap_err()
        .contains("digest"));
}

#[test]
fn request_arguments_cannot_replace_the_registered_command() {
    let (_directory, program) = fixture(&"01".repeat(32), None);
    let registry = ProgramRegistry::new(2, vec![program]).unwrap();
    let result = registry
        .execute(&json!({
            "shape_digest": "01".repeat(32), "slot": 9,
            "argv": ["/bin/sh", "-c", "false"]
        }))
        .unwrap();
    assert_eq!(result["exit_code"], 0);
}

#[test]
fn failed_approved_program_returns_only_correlatable_digests() {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("approved-failure.sh");
    fs::write(
        &executable,
        b"#!/bin/sh\nprintf 'private stdout'\nprintf 'private stderr' >&2\nexit 23\n",
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let program = RegisteredProgram {
        shape_digest: "03".repeat(32),
        argv: vec![executable.display().to_string()],
        cwd: directory.path().to_path_buf(),
        executable_sha256: hex::encode(Sha256::digest(fs::read(&executable).unwrap())),
        runtime: None,
        timeout_seconds: 5.0,
    };
    let registry = ProgramRegistry::new(2, vec![program]).unwrap();
    let error = registry
        .execute(&json!({"shape_digest": "03".repeat(32), "slot": 7}))
        .unwrap_err();

    assert!(error.contains("exit_code=23"), "{error}");
    assert!(
        error.contains(&hex::encode(Sha256::digest(b"private stdout"))),
        "{error}"
    );
    assert!(
        error.contains(&hex::encode(Sha256::digest(b"private stderr"))),
        "{error}"
    );
    assert!(!error.contains("private stdout"), "{error}");
    assert!(!error.contains("private stderr"), "{error}");
}

#[test]
fn approved_source_does_not_authorize_an_unrelated_executable() {
    let directory = tempfile::tempdir().unwrap();
    let config = ProgramConfig::default();
    let source = build_program(&config).unwrap();
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
            &source,
            &shape,
        )
        .unwrap();
    let runtime_executable = directory.path().join("runtime.sh");
    fs::write(&runtime_executable, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&runtime_executable, fs::Permissions::from_mode(0o700)).unwrap();
    let runtime_executable = fs::canonicalize(runtime_executable).unwrap();
    let runtime_config = directory.path().join("runtime.json");
    fs::write(&runtime_config, b"{}\n").unwrap();
    fs::set_permissions(&runtime_config, fs::Permissions::from_mode(0o600)).unwrap();
    let runtime_config = fs::canonicalize(runtime_config).unwrap();
    let runtime = RuntimeBinding {
        executable: runtime_executable.clone(),
        executable_sha256: hex::encode(Sha256::digest(fs::read(&runtime_executable).unwrap())),
        config: runtime_config.clone(),
        config_sha256: hex::encode(Sha256::digest(fs::read(&runtime_config).unwrap())),
    };
    let executable = fs::canonicalize("/bin/echo").unwrap();
    let program = RegisteredProgram {
        shape_digest: qomm_transport::executor::circuit_shape_digest(&shape),
        argv: vec![
            executable.display().to_string(),
            "{node}".into(),
            "{slot}".into(),
            "{batch_digest}".into(),
        ],
        cwd: directory.path().to_path_buf(),
        executable_sha256: hex::encode(Sha256::digest(fs::read(&executable).unwrap())),
        runtime: Some(runtime),
        timeout_seconds: 5.0,
    };

    let error = ProgramRegistry::from_approved_mpc(0, program, &circuits, &config, &shape)
        .expect_err("/bin/echo is not derived from the approved MPC source");
    assert!(
        error.contains("derived from the approved source"),
        "{error}"
    );
}

#[test]
fn file_registry_rebuilds_the_exact_rust_generated_source() {
    let directory = tempfile::tempdir().unwrap();
    let config = ProgramConfig::default();
    let source = build_program(&config).unwrap();
    let shape = vec![
        config.n_mm as u64,
        config.n_parties as u64,
        u64::from(config.bit_length),
    ];
    let rule_path = directory.path().join("approved-policy.dsl");
    let source_path = directory.path().join("approved-program.mpc");
    fs::write(&rule_path, policy_rule_source(&config)).unwrap();
    fs::write(&source_path, &source).unwrap();

    let runtime_executable = directory.path().join("qomm-node-party");
    fs::write(&runtime_executable, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&runtime_executable, fs::Permissions::from_mode(0o700)).unwrap();
    let runtime_executable = fs::canonicalize(runtime_executable).unwrap();
    let runtime_config = directory.path().join("resident-mpc.json");
    fs::write(&runtime_config, b"{}\n").unwrap();
    fs::set_permissions(&runtime_config, fs::Permissions::from_mode(0o600)).unwrap();
    let runtime_config = fs::canonicalize(runtime_config).unwrap();
    let runtime = RuntimeBinding {
        executable: runtime_executable.clone(),
        executable_sha256: hex::encode(Sha256::digest(fs::read(&runtime_executable).unwrap())),
        config: runtime_config.clone(),
        config_sha256: hex::encode(Sha256::digest(fs::read(&runtime_config).unwrap())),
    };
    let launcher = directory.path().join("source-bound-resident-mpc");
    write_source_bound_runtime_executable(&launcher, &source, &runtime).unwrap();
    let launcher = fs::canonicalize(launcher).unwrap();
    let registry_path = directory.path().join("approved-programs.json");
    let registry = json!({
        "programs": [{
            "shape_digest": circuit_shape_digest(&shape),
            "argv": [launcher.display().to_string(), "{node}", "{slot}", "{batch_digest}", "{lane}"],
            "cwd": directory.path().display().to_string(),
            "executable_sha256": hex::encode(Sha256::digest(fs::read(&launcher).unwrap())),
            "runtime": {
                "executable": runtime.executable.display().to_string(),
                "executable_sha256": runtime.executable_sha256,
                "config": runtime.config.display().to_string(),
                "config_sha256": runtime.config_sha256
            },
            "timeout_seconds": 60.0
        }],
        "approval": {
            "name": POLICY_RULE_NAME,
            "rule_source_file": "approved-policy.dsl",
            "program_source_file": "approved-program.mpc",
            "shape": shape,
            "program_config": config
        }
    });
    fs::write(
        &registry_path,
        serde_json::to_vec_pretty(&registry).unwrap(),
    )
    .unwrap();
    assert!(ProgramRegistry::from_json(0, &registry_path).is_ok());

    fs::write(
        &source_path,
        format!("{source}# substituted after generation\n"),
    )
    .unwrap();
    let error = ProgramRegistry::from_json(0, &registry_path).unwrap_err();
    assert!(
        error.contains("exact output of the Rust generator"),
        "{error}"
    );
}
