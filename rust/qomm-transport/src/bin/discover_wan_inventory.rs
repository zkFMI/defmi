//! Discover the durable identities of an already running seven-node WAN.
//!
//! This is a first-contact ceremony, not acceptance evidence.  It requires
//! mutual TLS, a complete 3-of-7 proof configuration and one shared FROST
//! group, then writes a mode-0600 candidate inventory for independent
//! governance review. `wan_acceptance` remains the second, pinned run.

use qomm_transport::node_service::{client_ssl_context, ClientTlsConfig, ResidentNodeClient};
use qomm_transport::proof_client::ProofPartyTlsClient;
use qomm_transport::wan_deployment::{read_deployment_spec, WanDeploymentSpec, WanNodeSpec};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize)]
struct ObservedNode {
    node: u16,
    organization_id: String,
    host: String,
    port: u16,
    server_name: String,
    expected_instance_id: String,
    proof_port: u16,
    proof_server_name: String,
    expected_proof_instance_id: String,
    expected_os_installation_id: String,
    restart_argv: Vec<String>,
    restart_proof_argv: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct ProbeEvidence {
    node: u16,
    resident_boot_id: String,
    proof_boot_id: String,
    proof_state_generation: u64,
    resident_round_trip_micros: u128,
    proof_round_trip_micros: u128,
}

#[derive(Clone, Debug)]
struct Observation {
    inventory: ObservedNode,
    evidence: ProbeEvidence,
    frost_public_package_sha256: Option<String>,
}

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

fn digest32(value: Option<&Value>, name: &str) -> Result<String, String> {
    value
        .and_then(Value::as_str)
        .filter(|value| hex::decode(value).ok().is_some_and(|raw| raw.len() == 32))
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| format!("WAN health omitted or malformed {name}"))
}

fn probe(
    spec: &WanDeploymentSpec,
    node: &WanNodeSpec,
    tls: ClientTlsConfig,
    nonce: u128,
    require_frost: bool,
) -> Result<Observation, String> {
    let resident_started = Instant::now();
    let mut resident =
        ResidentNodeClient::new(&node.host, node.resident_port, tls.clone(), &node.host, 1);
    let resident_response = resident.call(&json!({
        "version": 1,
        "request_id": format!("wan-discovery-{nonce}-{}", node.node),
        "operation": "health",
        "deployment_id": spec.deployment_id,
    }))?;
    resident.close();
    if resident_response.get("ok").and_then(Value::as_bool) != Some(true)
        || resident_response.get("node").and_then(Value::as_u64) != Some(u64::from(node.node))
    {
        return Err(format!(
            "WAN resident {} returned invalid health: {resident_response}",
            node.node
        ));
    }
    let resident_instance = digest32(resident_response.get("instance_id"), "resident instance id")?;
    let os_installation = digest32(
        resident_response.get("os_installation_id"),
        "resident OS installation id",
    )?;
    let resident_boot = digest32(resident_response.get("boot_id"), "resident boot id")?;
    let resident_round_trip_micros = resident_started.elapsed().as_micros();

    let proof_started = Instant::now();
    let mut proof = ProofPartyTlsClient::new(
        &node.host,
        node.proof_port,
        tls,
        &node.host,
        Duration::from_secs(10),
    );
    let proof_response = proof.call("health", json!({"deployment_id": spec.deployment_id}))?;
    proof.close();
    if proof_response
        .get("protocol_version")
        .and_then(Value::as_u64)
        != Some(1)
        || proof_response.get("node").and_then(Value::as_u64) != Some(u64::from(node.node))
        || proof_response.get("deployment_id").and_then(Value::as_str)
            != Some(spec.deployment_id.as_str())
        || proof_response.get("n_mm").and_then(Value::as_u64) != Some(spec.n_mm as u64)
        || proof_response.get("n_parties").and_then(Value::as_u64) != Some(spec.n_parties as u64)
        || proof_response.get("threshold").and_then(Value::as_u64) != Some(spec.threshold as u64)
        || proof_response.get("amount_bits").and_then(Value::as_u64)
            != Some(spec.amount_bits as u64)
        || proof_response.get("price_bits").and_then(Value::as_u64) != Some(spec.price_bits as u64)
        || proof_response.get("remainder_bits").and_then(Value::as_u64)
            != Some(spec.remainder_bits as u64)
        || proof_response
            .get("quote_eligibility_bits")
            .and_then(Value::as_u64)
            != Some(spec.quote_eligibility_bits as u64)
        || proof_response
            .get("quote_span_bits")
            .and_then(Value::as_u64)
            != Some(spec.quote_span_bits as u64)
        || proof_response
            .get("complete_quote_proof")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(format!(
            "WAN proof party {} is not the approved complete 3-of-7 participant: {proof_response}",
            node.node
        ));
    }
    let proof_instance = digest32(proof_response.get("instance_id"), "proof instance id")?;
    let proof_os = digest32(
        proof_response.get("os_installation_id"),
        "proof OS installation id",
    )?;
    if proof_os != os_installation {
        return Err(format!(
            "WAN node {} resident and proof services are not on one OS installation",
            node.node
        ));
    }
    let proof_boot = digest32(proof_response.get("boot_id"), "proof boot id")?;
    let frost_ready = proof_response.get("frost_ready").and_then(Value::as_bool) == Some(true);
    if require_frost && !frost_ready {
        return Err(format!(
            "WAN proof party {} has not completed FROST DKG",
            node.node
        ));
    }
    let frost = if frost_ready {
        Some(digest32(
            proof_response.get("frost_public_package_sha256"),
            "FROST public-package digest",
        )?)
    } else {
        None
    };
    let proof_state_generation = proof_response
        .get("state_generation")
        .and_then(Value::as_u64)
        .filter(|generation| *generation > 0)
        .ok_or_else(|| {
            format!(
                "WAN proof party {} has no durable state generation",
                node.node
            )
        })?;
    Ok(Observation {
        inventory: ObservedNode {
            node: node.node,
            organization_id: node.organization_id.clone(),
            host: node.host.clone(),
            port: node.resident_port,
            server_name: node.host.clone(),
            expected_instance_id: resident_instance,
            proof_port: node.proof_port,
            proof_server_name: node.host.clone(),
            expected_proof_instance_id: proof_instance,
            expected_os_installation_id: os_installation,
            restart_argv: node.restart_argv.clone(),
            restart_proof_argv: node.restart_proof_argv.clone(),
        },
        evidence: ProbeEvidence {
            node: node.node,
            resident_boot_id: resident_boot,
            proof_boot_id: proof_boot,
            proof_state_generation,
            resident_round_trip_micros,
            proof_round_trip_micros: proof_started.elapsed().as_micros(),
        },
        frost_public_package_sha256: frost,
    })
}

fn canonical(path: &Path, name: &str) -> Result<PathBuf, String> {
    let path = fs::canonicalize(path).map_err(|error| format!("{name} is absent: {error}"))?;
    if !path.is_file() {
        return Err(format!("{name} is not a regular file"));
    }
    Ok(path)
}

fn atomic_private_write(path: &Path, value: &Value) -> Result<(), String> {
    if path.exists() || fs::symlink_metadata(path).is_ok() {
        return Err(format!("refusing to overwrite {}", path.display()));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let temporary = parent.join(format!(".qomm-wan-discovery-{}.tmp", rand::random::<u64>()));
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| error.to_string())?;
        fs::rename(&temporary, path).map_err(|error| error.to_string())?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let spec_path = PathBuf::from(value(&arguments, "--spec")?);
    let certificate_path = canonical(
        Path::new(&value(&arguments, "--coordinator-certificate")?),
        "coordinator certificate",
    )?;
    let private_key_path = canonical(
        Path::new(&value(&arguments, "--coordinator-private-key")?),
        "coordinator private key",
    )?;
    let ca_path = canonical(
        Path::new(&value(&arguments, "--ca-certificate")?),
        "CA certificate",
    )?;
    let output = PathBuf::from(value(&arguments, "--out")?);
    let before_frost_dkg = arguments
        .iter()
        .any(|argument| argument == "--before-frost-dkg");
    let spec_bytes = fs::read(&spec_path).map_err(|error| error.to_string())?;
    let spec = read_deployment_spec(&spec_path)?;
    let tls = client_ssl_context(&certificate_path, &private_key_path, &ca_path)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_string())?
        .as_nanos();
    let handles = spec
        .nodes
        .iter()
        .cloned()
        .map(|node| {
            let spec = spec.clone();
            let tls = tls.clone();
            std::thread::spawn(move || probe(&spec, &node, tls, nonce, !before_frost_dkg))
        })
        .collect::<Vec<_>>();
    let mut observations = handles
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .map_err(|_| "WAN discovery worker panicked".to_string())?
        })
        .collect::<Result<Vec<_>, _>>()?;
    observations.sort_by_key(|observation| observation.inventory.node);
    let unique = |values: Vec<&str>, name: &str| -> Result<(), String> {
        if values.into_iter().collect::<BTreeSet<_>>().len() != 7 {
            return Err(format!(
                "WAN discovery did not observe seven distinct {name}"
            ));
        }
        Ok(())
    };
    unique(
        observations
            .iter()
            .map(|entry| entry.inventory.expected_instance_id.as_str())
            .collect(),
        "resident identities",
    )?;
    unique(
        observations
            .iter()
            .map(|entry| entry.inventory.expected_proof_instance_id.as_str())
            .collect(),
        "proof identities",
    )?;
    unique(
        observations
            .iter()
            .map(|entry| entry.inventory.expected_os_installation_id.as_str())
            .collect(),
        "OS installations",
    )?;
    let frost = observations
        .iter()
        .filter_map(|entry| entry.frost_public_package_sha256.as_deref())
        .collect::<BTreeSet<_>>();
    if (!before_frost_dkg && frost.len() != 1)
        || (before_frost_dkg && !frost.is_empty() && frost.len() != 1)
    {
        return Err("WAN discovery did not observe one shared FROST group".into());
    }
    if before_frost_dkg
        && observations
            .iter()
            .any(|entry| entry.frost_public_package_sha256.is_some())
        && observations
            .iter()
            .any(|entry| entry.frost_public_package_sha256.is_none())
    {
        return Err("WAN discovery observed only a partially completed FROST DKG".into());
    }
    let frost = frost.into_iter().next();
    let inventory_nodes = observations
        .iter()
        .map(|entry| &entry.inventory)
        .collect::<Vec<_>>();
    let probe_evidence = observations
        .iter()
        .map(|entry| &entry.evidence)
        .collect::<Vec<_>>();
    let generated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_string())?
        .as_secs();
    let mut document = json!({
        "deployment_id": spec.deployment_id,
        "coordinator_certificate": certificate_path,
        "coordinator_private_key": private_key_path,
        "ca_certificate": ca_path,
        "nodes": inventory_nodes,
        "discovery": {
            "status": "candidate_requires_independent_governance_review",
            "first_contact_is_not_acceptance_evidence": true,
            "generated_at": generated_at,
            "source_spec_sha256": hex::encode(Sha256::digest(spec_bytes)),
            "mutual_tls_verified": true,
            "complete_quote_proof_verified": true,
            "three_of_seven_configuration_verified": true,
            "one_shared_frost_group_verified": frost.is_some(),
            "before_frost_dkg": before_frost_dkg,
            "seven_distinct_os_installations_observed": true,
            "physical_hardware_attestation_verified": false,
            "probes": probe_evidence
        }
    });
    if let Some(frost) = frost {
        document
            .as_object_mut()
            .ok_or_else(|| "WAN inventory document is not an object".to_string())?
            .insert(
                "expected_frost_public_package_sha256".into(),
                Value::String(frost.into()),
            );
    }
    atomic_private_write(&output, &document)?;
    println!(
        "{}",
        json!({
            "status":"candidate-inventory-written",
            "output":output,
            "nodes":7,
            "before_frost_dkg":before_frost_dkg,
            "independent_governance_review_required":true,
            "physical_hardware_attestation_verified":false
        })
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("discover_wan_inventory failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn candidate_inventory_is_owner_only_and_never_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("candidate.json");
        atomic_private_write(&output, &json!({"candidate":true})).unwrap();
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(atomic_private_write(&output, &json!({"candidate":false}))
            .unwrap_err()
            .contains("overwrite"));
    }

    #[test]
    fn health_identity_must_be_exactly_one_digest() {
        let valid = Value::String("ab".repeat(32));
        assert_eq!(digest32(Some(&valid), "identity").unwrap(), "ab".repeat(32));
        let short = Value::String("ab".repeat(31));
        assert!(digest32(Some(&short), "identity").is_err());
        assert!(digest32(None, "identity").is_err());
    }
}
