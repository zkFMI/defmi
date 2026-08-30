//! Prepare a split-knowledge seven-node WAN deployment without collecting
//! node TLS, sealing, FROST or MP-SPDZ secrets at the coordinator.

use ed25519_dalek::VerifyingKey;
use qomm_transport::wan_deployment::{
    apply_node_response, initialize_authority, initialize_node, initialize_node_mpc_state,
    prepare_node_mpc_runtime, read_deployment_spec, sign_node_requests, sync_directory,
    write_example_spec,
};
use serde_json::json;
use std::path::{Path, PathBuf};

fn value(arguments: &[String], name: &str) -> Result<String, String> {
    let index = arguments
        .iter()
        .position(|argument| argument == name)
        .ok_or_else(|| format!("missing {name}"))?;
    arguments
        .get(index + 1)
        .cloned()
        .ok_or_else(|| format!("{name} requires a value"))
}

fn node(arguments: &[String]) -> Result<u16, String> {
    value(arguments, "--node")?
        .parse()
        .map_err(|_| "--node must be an unsigned 16-bit integer".to_string())
}

fn read_public(arguments: &[String]) -> Result<VerifyingKey, String> {
    let raw: [u8; 32] = hex::decode(value(arguments, "--trusted-defmi-receipt-public")?)
        .map_err(|_| "trusted DeFMI receipt public key must be 32-byte hexadecimal".to_string())?
        .try_into()
        .map_err(|_| "trusted DeFMI receipt public key must be 32-byte hexadecimal".to_string())?;
    VerifyingKey::from_bytes(&raw)
        .map_err(|_| "trusted DeFMI receipt public key is not canonical".to_string())
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let command = arguments
        .first()
        .cloned()
        .ok_or_else(|| {
            "usage: prepare_wan_deployment <example|init-authority|init-node|sign-requests|apply-response|init-mpc-state|prepare-mpc-runtime> ..."
                .to_string()
        })?;
    arguments.remove(0);
    match command.as_str() {
        "example" => {
            let out = PathBuf::from(value(&arguments, "--out")?);
            write_example_spec(&out, &read_public(&arguments)?)?;
            println!("{}", json!({"status":"written", "spec":out}));
        }
        "init-authority" => {
            let spec_path = PathBuf::from(value(&arguments, "--spec")?);
            let out = PathBuf::from(value(&arguments, "--out")?);
            let spec = read_deployment_spec(&spec_path)?;
            initialize_authority(&spec, &out)?;
            sync_directory(&out)?;
            println!(
                "{}",
                json!({
                    "status":"authority-initialized",
                    "deployment_id":spec.deployment_id,
                    "output":out,
                    "node_private_keys_received":false,
                    "frost_secret_shares_created":false,
                    "hardware_hsm_verified":false
                })
            );
        }
        "init-node" => {
            let spec_path = PathBuf::from(value(&arguments, "--spec")?);
            let private_out = PathBuf::from(value(&arguments, "--private-out")?);
            let request_out = PathBuf::from(value(&arguments, "--request-out")?);
            let trusted_ca = PathBuf::from(value(&arguments, "--trusted-ca-cert")?);
            let node = node(&arguments)?;
            let spec = read_deployment_spec(&spec_path)?;
            initialize_node(&spec, node, &private_out, &request_out, &trusted_ca)?;
            sync_directory(&private_out)?;
            sync_directory(&request_out)?;
            println!(
                "{}",
                json!({
                    "status":"node-request-created",
                    "deployment_id":spec.deployment_id,
                    "node":node,
                    "private_output":private_out,
                    "public_request_output":request_out,
                    "trusted_ca_certificate_pinned_locally":true,
                    "tls_private_key_generated_locally":true,
                    "mp_spdz_tls_private_key_generated_locally":true
                })
            );
        }
        "sign-requests" => {
            let spec_path = PathBuf::from(value(&arguments, "--spec")?);
            let authority = PathBuf::from(value(&arguments, "--authority")?);
            let requests = PathBuf::from(value(&arguments, "--requests-root")?);
            let out = PathBuf::from(value(&arguments, "--out")?);
            let spec = read_deployment_spec(&spec_path)?;
            sign_node_requests(&spec, &authority, &requests, &out)?;
            sync_directory(&out)?;
            println!(
                "{}",
                json!({
                    "status":"seven-node-responses-signed",
                    "deployment_id":spec.deployment_id,
                    "responses":out,
                    "node_private_keys_received":false
                })
            );
        }
        "apply-response" => {
            let spec_path = PathBuf::from(value(&arguments, "--spec")?);
            let private_root = PathBuf::from(value(&arguments, "--private-root")?);
            let request = PathBuf::from(value(&arguments, "--request")?);
            let response = PathBuf::from(value(&arguments, "--response")?);
            let node = node(&arguments)?;
            let spec = read_deployment_spec(&spec_path)?;
            apply_node_response(&spec, node, &private_root, &request, &response)?;
            sync_directory(&private_root)?;
            println!(
                "{}",
                json!({
                    "status":"node-config-finalized",
                    "deployment_id":spec.deployment_id,
                    "node":node,
                    "node_config":private_root.join("node.json"),
                    "proof_config":private_root.join("proof-party.json"),
                    "mp_spdz_player_data":private_root.join("mpc-player-data"),
                    "frost_secret_share_created":false,
                    "mp_spdz_secret_state_created":false
                })
            );
        }
        "init-mpc-state" => {
            let spec_path = PathBuf::from(value(&arguments, "--spec")?);
            let private_root = PathBuf::from(value(&arguments, "--private-root")?);
            let shares = PathBuf::from(value(&arguments, "--shares")?);
            let node = node(&arguments)?;
            let spec = read_deployment_spec(&spec_path)?;
            let receipt = initialize_node_mpc_state(&spec, node, &private_root, &shares)?;
            sync_directory(&private_root)?;
            println!(
                "{}",
                json!({
                    "status":"node-mpc-state-sealed",
                    "deployment_id":spec.deployment_id,
                    "node":node,
                    "generation":receipt.generation,
                    "source_sha256":receipt.source_sha256,
                    "encrypted_state":receipt.encrypted_state,
                    "clear_share_bundle_retained_by_caller":true,
                    "authority_received_clear_shares":false
                })
            );
        }
        "prepare-mpc-runtime" => {
            let spec_path = PathBuf::from(value(&arguments, "--spec")?);
            let private_root = PathBuf::from(value(&arguments, "--private-root")?);
            let mp_spdz_root = PathBuf::from(value(&arguments, "--mp-spdz-root")?);
            let qomm_node_party = PathBuf::from(value(&arguments, "--qomm-node-party")?);
            let node = node(&arguments)?;
            let spec = read_deployment_spec(&spec_path)?;
            let receipt = prepare_node_mpc_runtime(
                &spec,
                node,
                &private_root,
                &mp_spdz_root,
                &qomm_node_party,
            )?;
            sync_directory(&private_root)?;
            println!(
                "{}",
                json!({
                    "status":"node-mpc-runtime-prepared",
                    "deployment_id":spec.deployment_id,
                    "node":node,
                    "program":receipt.program,
                    "source_sha256":receipt.source_sha256,
                    "runtime_config":receipt.runtime_config,
                    "launcher":receipt.launcher,
                    "program_registry":receipt.program_registry,
                    "public_peer_certificates":receipt.public_peer_certificates,
                    "local_private_keys":receipt.local_private_keys,
                    "avalanchego_in_process_ffi":false
                })
            );
        }
        _ => {
            return Err(format!(
                "unknown command {command}; expected example, init-authority, init-node, sign-requests, apply-response, init-mpc-state or prepare-mpc-runtime"
            ));
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        let executable = std::env::args()
            .next()
            .unwrap_or_else(|| "prepare_wan_deployment".into());
        eprintln!("{} failed: {error}", Path::new(&executable).display());
        std::process::exit(1);
    }
}
