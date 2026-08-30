//! Acceptance runner for seven separate QOMM WAN node/OS boundaries.
//!
//! This binary refuses loopback, duplicate organisations, endpoints or stable
//! node and OS-installation identities. It measures the real mutually-authenticated path, executes
//! one explicitly configured restart hook without a shell, then proves that
//! the restarted process has a new boot id while every node keeps its durable
//! key-derived instance id. OS identity detects aliases but is not hardware
//! attestation; the receipt states that limitation explicitly.

use qomm_transport::node_service::{
    client_ssl_context, os_installation_boundary_id, ClientTlsConfig, ResidentNodeClient,
};
use qomm_transport::proof_client::ProofPartyTlsClient;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_INVENTORY_BYTES: usize = 1 << 20;

#[derive(Clone, Debug, Deserialize)]
struct Inventory {
    deployment_id: String,
    expected_frost_public_package_sha256: String,
    coordinator_certificate: PathBuf,
    coordinator_private_key: PathBuf,
    ca_certificate: PathBuf,
    nodes: Vec<Node>,
}

#[derive(Clone, Debug, Deserialize)]
struct Node {
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
    #[serde(default)]
    restart_argv: Vec<String>,
    #[serde(default)]
    restart_proof_argv: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct Probe {
    node: u16,
    organization_id: String,
    host: String,
    port: u16,
    instance_id: String,
    os_installation_id: String,
    boot_id: String,
    round_trip_micros: u128,
    proof_port: u16,
    proof_instance_id: String,
    proof_boot_id: String,
    proof_round_trip_micros: u128,
    proof_state_generation: u64,
    complete_quote_proof: bool,
    frost_public_package_sha256: String,
}

fn resolve(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn read_inventory(path: &Path) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("WAN inventory cannot be opened safely: {error}"))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    // SAFETY: geteuid has no preconditions and exposes no secret.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_INVENTORY_BYTES as u64
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(
            "WAN inventory must be a bounded owner-only regular file owned by the operator".into(),
        );
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take((MAX_INVENTORY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > MAX_INVENTORY_BYTES {
        return Err("WAN inventory exceeds its fixed bound".into());
    }
    Ok(bytes)
}

fn validate(inventory: &Inventory) -> Result<(), String> {
    if inventory.deployment_id.trim().is_empty() || inventory.nodes.len() != 7 {
        return Err("WAN inventory requires one deployment id and exactly seven nodes".into());
    }
    if hex::decode(&inventory.expected_frost_public_package_sha256)
        .ok()
        .is_none_or(|value| value.len() != 32)
    {
        return Err("WAN inventory requires one pinned FROST public-package digest".into());
    }
    let expected = (0_u16..7).collect::<BTreeSet<_>>();
    let nodes = inventory
        .nodes
        .iter()
        .map(|node| node.node)
        .collect::<BTreeSet<_>>();
    if nodes != expected {
        return Err("WAN inventory node identifiers must be exactly 0 through 6".into());
    }
    let organizations = inventory
        .nodes
        .iter()
        .map(|node| node.organization_id.trim().to_string())
        .collect::<BTreeSet<_>>();
    let hosts = inventory
        .nodes
        .iter()
        .map(|node| node.host.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let endpoints = inventory
        .nodes
        .iter()
        .map(|node| (node.host.trim().to_ascii_lowercase(), node.port))
        .collect::<BTreeSet<_>>();
    let proof_endpoints = inventory
        .nodes
        .iter()
        .map(|node| (node.host.trim().to_ascii_lowercase(), node.proof_port))
        .collect::<BTreeSet<_>>();
    let identities = inventory
        .nodes
        .iter()
        .map(|node| node.expected_instance_id.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let proof_identities = inventory
        .nodes
        .iter()
        .map(|node| node.expected_proof_instance_id.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let os_installations = inventory
        .nodes
        .iter()
        .map(|node| node.expected_os_installation_id.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if organizations.len() != 7
        || organizations.contains("")
        || hosts.len() != 7
        || endpoints.len() != 7
        || proof_endpoints.len() != 7
        || identities.len() != 7
        || proof_identities.len() != 7
        || os_installations.len() != 7
    {
        return Err(
            "WAN inventory must name seven distinct organisations, hosts, resident/proof endpoints, resident/proof identities and OS installations"
                .into(),
        );
    }
    for node in &inventory.nodes {
        let host = node.host.trim().to_ascii_lowercase();
        if node.port == 0
            || node.proof_port == 0
            || node.port == node.proof_port
            || node.server_name.trim().is_empty()
            || node.proof_server_name.trim().is_empty()
            || matches!(host.as_str(), "localhost" | "::1" | "0.0.0.0")
            || host.starts_with("127.")
            || hex::decode(&node.expected_instance_id)
                .ok()
                .is_none_or(|value| value.len() != 32)
            || hex::decode(&node.expected_proof_instance_id)
                .ok()
                .is_none_or(|value| value.len() != 32)
            || hex::decode(&node.expected_os_installation_id)
                .ok()
                .is_none_or(|value| value.len() != 32)
        {
            return Err(format!(
                "WAN node {} has a loopback/wildcard endpoint, overlapping service port or invalid identity",
                node.node
            ));
        }
    }
    Ok(())
}

fn probe_node(
    node: &Node,
    tls: ClientTlsConfig,
    request_id: &str,
    deployment_id: &str,
    expected_frost_digest: &str,
) -> Result<Probe, String> {
    let started = Instant::now();
    let mut client =
        ResidentNodeClient::new(&node.host, node.port, tls.clone(), &node.server_name, 1);
    let response = client.call(&json!({
        "version": 1,
        "request_id": request_id,
        "operation": "health",
        "deployment_id": deployment_id,
    }))?;
    client.close();
    if response.get("ok").and_then(Value::as_bool) != Some(true)
        || response.get("node").and_then(Value::as_u64) != Some(u64::from(node.node))
    {
        return Err(format!(
            "WAN node {} returned invalid health: {response}",
            node.node
        ));
    }
    let instance_id = response
        .get("instance_id")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("WAN node {} omitted its stable identity", node.node))?;
    if !instance_id.eq_ignore_ascii_case(&node.expected_instance_id) {
        return Err(format!(
            "WAN node {} stable identity does not match inventory",
            node.node
        ));
    }
    let os_installation_id = response
        .get("os_installation_id")
        .and_then(Value::as_str)
        .filter(|value| hex::decode(value).ok().is_some_and(|raw| raw.len() == 32))
        .ok_or_else(|| format!("WAN node {} omitted its OS installation id", node.node))?;
    if !os_installation_id.eq_ignore_ascii_case(&node.expected_os_installation_id) {
        return Err(format!(
            "WAN node {} OS installation does not match inventory",
            node.node
        ));
    }
    let boot_id = response
        .get("boot_id")
        .and_then(Value::as_str)
        .filter(|value| hex::decode(value).ok().is_some_and(|raw| raw.len() == 32))
        .ok_or_else(|| format!("WAN node {} omitted its process boot id", node.node))?;
    let round_trip_micros = started.elapsed().as_micros();

    let proof_started = Instant::now();
    let mut proof = ProofPartyTlsClient::new(
        &node.host,
        node.proof_port,
        tls,
        &node.proof_server_name,
        Duration::from_secs(10),
    );
    let proof_response = proof.call("health", json!({"deployment_id": deployment_id}))?;
    proof.close();
    let expected_parameters = proof_response
        .get("protocol_version")
        .and_then(Value::as_u64)
        == Some(1)
        && proof_response.get("n_mm").and_then(Value::as_u64) == Some(4)
        && proof_response.get("n_parties").and_then(Value::as_u64) == Some(7)
        && proof_response.get("threshold").and_then(Value::as_u64) == Some(2)
        && proof_response.get("amount_bits").and_then(Value::as_u64) == Some(16)
        && proof_response.get("price_bits").and_then(Value::as_u64) == Some(32)
        && proof_response.get("remainder_bits").and_then(Value::as_u64) == Some(32)
        && proof_response
            .get("quote_eligibility_bits")
            .and_then(Value::as_u64)
            == Some(34)
        && proof_response
            .get("quote_span_bits")
            .and_then(Value::as_u64)
            == Some(32);
    if proof_response.get("node").and_then(Value::as_u64) != Some(u64::from(node.node))
        || proof_response.get("deployment_id").and_then(Value::as_str) != Some(deployment_id)
        || proof_response
            .get("complete_quote_proof")
            .and_then(Value::as_bool)
            != Some(true)
        || proof_response.get("frost_ready").and_then(Value::as_bool) != Some(true)
        || !expected_parameters
    {
        return Err(format!(
            "WAN proof party {} is not a ready complete-quote-proof participant: {proof_response}",
            node.node
        ));
    }
    let proof_instance_id = proof_response
        .get("instance_id")
        .and_then(Value::as_str)
        .filter(|value| hex::decode(value).ok().is_some_and(|raw| raw.len() == 32))
        .ok_or_else(|| format!("WAN proof party {} omitted its stable identity", node.node))?;
    if !proof_instance_id.eq_ignore_ascii_case(&node.expected_proof_instance_id) {
        return Err(format!(
            "WAN proof party {} stable identity does not match inventory",
            node.node
        ));
    }
    let proof_os_installation_id = proof_response
        .get("os_installation_id")
        .and_then(Value::as_str)
        .filter(|value| hex::decode(value).ok().is_some_and(|raw| raw.len() == 32))
        .ok_or_else(|| {
            format!(
                "WAN proof party {} omitted its OS installation id",
                node.node
            )
        })?;
    if !proof_os_installation_id.eq_ignore_ascii_case(&node.expected_os_installation_id)
        || !proof_os_installation_id.eq_ignore_ascii_case(os_installation_id)
    {
        return Err(format!(
            "WAN proof party {} is not on the resident node's pinned OS installation",
            node.node
        ));
    }
    let proof_boot_id = proof_response
        .get("boot_id")
        .and_then(Value::as_str)
        .filter(|value| hex::decode(value).ok().is_some_and(|raw| raw.len() == 32))
        .ok_or_else(|| format!("WAN proof party {} omitted its process boot id", node.node))?;
    let proof_state_generation = proof_response
        .get("state_generation")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("WAN proof party {} omitted its state generation", node.node))?;
    let frost_public_package_sha256 = proof_response
        .get("frost_public_package_sha256")
        .and_then(Value::as_str)
        .filter(|value| hex::decode(value).ok().is_some_and(|raw| raw.len() == 32))
        .ok_or_else(|| {
            format!(
                "WAN proof party {} omitted its FROST group digest",
                node.node
            )
        })?;
    if !frost_public_package_sha256.eq_ignore_ascii_case(expected_frost_digest) {
        return Err(format!(
            "WAN proof party {} FROST group does not match governance inventory",
            node.node
        ));
    }
    Ok(Probe {
        node: node.node,
        organization_id: node.organization_id.clone(),
        host: node.host.clone(),
        port: node.port,
        instance_id: instance_id.to_ascii_lowercase(),
        os_installation_id: os_installation_id.to_ascii_lowercase(),
        boot_id: boot_id.to_ascii_lowercase(),
        round_trip_micros,
        proof_port: node.proof_port,
        proof_instance_id: proof_instance_id.to_ascii_lowercase(),
        proof_boot_id: proof_boot_id.to_ascii_lowercase(),
        proof_round_trip_micros: proof_started.elapsed().as_micros(),
        proof_state_generation,
        complete_quote_proof: true,
        frost_public_package_sha256: frost_public_package_sha256.to_ascii_lowercase(),
    })
}

fn probe_all(
    inventory: &Inventory,
    tls: &ClientTlsConfig,
    phase: &str,
) -> Result<Vec<Probe>, String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let handles = inventory
        .nodes
        .iter()
        .cloned()
        .map(|node| {
            let tls = tls.clone();
            let phase = phase.to_string();
            let deployment_id = inventory.deployment_id.clone();
            let expected_frost_digest = inventory.expected_frost_public_package_sha256.clone();
            std::thread::spawn(move || {
                let node_id = node.node;
                probe_node(
                    &node,
                    tls,
                    &format!("wan-{phase}-{nonce}-{node_id}"),
                    &deployment_id,
                    &expected_frost_digest,
                )
            })
        })
        .collect::<Vec<_>>();
    let mut probes = handles
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .map_err(|_| "WAN health worker panicked".to_string())?
        })
        .collect::<Result<Vec<_>, _>>()?;
    probes.sort_by_key(|probe| probe.node);
    if probes
        .iter()
        .map(|probe| &probe.instance_id)
        .collect::<BTreeSet<_>>()
        .len()
        != 7
    {
        return Err("live WAN endpoints do not expose seven distinct durable identities".into());
    }
    if probes
        .iter()
        .map(|probe| &probe.os_installation_id)
        .collect::<BTreeSet<_>>()
        .len()
        != 7
    {
        return Err("live WAN endpoints do not expose seven distinct OS installations".into());
    }
    if probes
        .iter()
        .map(|probe| &probe.proof_instance_id)
        .collect::<BTreeSet<_>>()
        .len()
        != 7
    {
        return Err(
            "live WAN proof endpoints do not expose seven distinct durable identities".into(),
        );
    }
    if probes
        .iter()
        .map(|probe| &probe.frost_public_package_sha256)
        .collect::<BTreeSet<_>>()
        .len()
        != 1
    {
        return Err("live WAN proof endpoints do not share one FROST group".into());
    }
    Ok(probes)
}

fn run_restart_hook(label: &str, argv: &[String]) -> Result<(), String> {
    let executable = argv
        .first()
        .ok_or_else(|| format!("selected WAN node has no explicit {label} restart hook"))?;
    if !Path::new(executable).is_absolute() {
        return Err(format!(
            "{label} restart executable must use an absolute local path"
        ));
    }
    let mut child = Command::new(executable)
        .args(&argv[1..])
        .stdin(Stdio::null())
        .spawn()
        .map_err(|error| format!("WAN {label} restart hook failed to start: {error}"))?;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("WAN {label} restart hook could not be observed: {error}"))?
        {
            if status.success() {
                return Ok(());
            }
            return Err(format!("WAN {label} restart hook exited with {status}"));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("WAN {label} restart hook exceeded 60 seconds"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn restart(node: &Node) -> Result<(), String> {
    run_restart_hook("resident", &node.restart_argv)?;
    run_restart_hook("proof-party", &node.restart_proof_argv)
}

fn atomic_write(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let temp = parent.join(format!(".qomm-wan-{}.tmp", rand::random::<u64>()));
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| error.to_string())?;
        fs::rename(&temp, path).map_err(|error| error.to_string())?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn run(inventory_path: &Path, output: &Path, restart_node: u16) -> Result<(), String> {
    let inventory_bytes = read_inventory(inventory_path)?;
    let inventory_sha256 = hex::encode(Sha256::digest(&inventory_bytes));
    let inventory: Inventory =
        serde_json::from_slice(&inventory_bytes).map_err(|error| error.to_string())?;
    validate(&inventory)?;
    let base = inventory_path.parent().unwrap_or_else(|| Path::new("."));
    let tls = client_ssl_context(
        resolve(base, &inventory.coordinator_certificate),
        resolve(base, &inventory.coordinator_private_key),
        resolve(base, &inventory.ca_certificate),
    )?;
    let before = probe_all(&inventory, &tls, "before")?;
    let node = inventory
        .nodes
        .iter()
        .find(|node| node.node == restart_node)
        .ok_or_else(|| "restart node is outside 0..6".to_string())?;
    restart(node)?;
    let deadline = Instant::now() + Duration::from_secs(120);
    let previous = &before[usize::from(restart_node)];
    let recovered = loop {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        if let Ok(probe) = probe_node(
            node,
            tls.clone(),
            &format!("wan-recovery-{nonce}-{restart_node}"),
            &inventory.deployment_id,
            &inventory.expected_frost_public_package_sha256,
        ) {
            if probe.boot_id != previous.boot_id && probe.proof_boot_id != previous.proof_boot_id {
                break probe;
            }
        }
        if Instant::now() >= deadline {
            return Err(
                "restarted WAN resident and proof services did not both return with new boot ids in 120 seconds".into(),
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    if recovered.instance_id != previous.instance_id
        || recovered.proof_instance_id != previous.proof_instance_id
    {
        return Err("restarted WAN node changed a durable resident/proof identity".into());
    }
    if recovered.proof_state_generation < previous.proof_state_generation {
        return Err("restarted WAN proof party rolled back its durable generation".into());
    }
    let after = probe_all(&inventory, &tls, "after")?;
    for (before, after) in before.iter().zip(&after) {
        if before.instance_id != after.instance_id {
            return Err(format!(
                "WAN node {} changed resident identity",
                before.node
            ));
        }
        if before.proof_instance_id != after.proof_instance_id {
            return Err(format!("WAN node {} changed proof identity", before.node));
        }
        if before.os_installation_id != after.os_installation_id {
            return Err(format!("WAN node {} changed OS installation", before.node));
        }
        if before.frost_public_package_sha256 != after.frost_public_package_sha256 {
            return Err(format!("WAN node {} changed FROST group", before.node));
        }
        if after.proof_state_generation < before.proof_state_generation {
            return Err(format!("WAN node {} rolled back proof state", before.node));
        }
    }
    let artifact = json!({
        "schema": "qomm-seven-node-wan-acceptance-v3",
        "deployment_id": inventory.deployment_id,
        "frost_public_package_sha256": inventory.expected_frost_public_package_sha256,
        "inventory_sha256": inventory_sha256,
        "completed_at_unix": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        "environment": "seven-distinct-network-and-os-installation-boundaries",
        "mutual_tls": true,
        "distinct_organizations": 7,
        "distinct_hosts": 7,
        "distinct_os_installations": 7,
        "distinct_resident_key_identities": 7,
        "distinct_proof_key_identities": 7,
        "complete_quote_proof_all_nodes": true,
        "frost_ready_all_nodes": true,
        "physical_hardware_attestation_verified": false,
        "restart_node": restart_node,
        "resident_restart_verified": true,
        "proof_party_restart_verified": true,
        "proof_state_rollback_check": true,
        "before": before,
        "after": after,
    });
    atomic_write(output, &artifact)
}

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let value = |name: &str| -> Result<&str, String> {
        let position = arguments
            .iter()
            .position(|argument| argument == name)
            .ok_or_else(|| format!("missing {name}"))?;
        arguments
            .get(position + 1)
            .map(String::as_str)
            .ok_or_else(|| format!("{name} requires a value"))
    };
    let result = (|| {
        if arguments
            .iter()
            .any(|argument| argument == "--print-os-installation-id")
        {
            println!(
                "{}",
                hex::encode(os_installation_boundary_id(value("--deployment-id")?)?)
            );
            return Ok(());
        }
        let restart_node = value("--restart-node")?
            .parse::<u16>()
            .map_err(|_| "--restart-node must be 0..6".to_string())?;
        run(
            Path::new(value("--inventory")?),
            Path::new(value("--out")?),
            restart_node,
        )
    })();
    if let Err(error) = result {
        eprintln!("seven-host WAN acceptance failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn inventory() -> Inventory {
        Inventory {
            deployment_id: "pilot".into(),
            expected_frost_public_package_sha256: "aa".repeat(32),
            coordinator_certificate: "coordinator.pem".into(),
            coordinator_private_key: "coordinator.key".into(),
            ca_certificate: "ca.pem".into(),
            nodes: (0_u16..7)
                .map(|node| Node {
                    node,
                    organization_id: format!("org-{node}"),
                    host: format!("node-{node}.example.net"),
                    port: 9443,
                    server_name: format!("node-{node}.example.net"),
                    expected_instance_id: format!("{:02x}", node + 1).repeat(32),
                    proof_port: 9543,
                    proof_server_name: format!("node-{node}.example.net"),
                    expected_proof_instance_id: format!("{:02x}", node + 21).repeat(32),
                    expected_os_installation_id: format!("{:02x}", node + 11).repeat(32),
                    restart_argv: vec!["/usr/bin/true".into()],
                    restart_proof_argv: vec!["/usr/bin/true".into()],
                })
                .collect(),
        }
    }

    #[test]
    fn inventory_requires_seven_distinct_real_host_boundaries() {
        assert_eq!(validate(&inventory()), Ok(()));
        let mut duplicate = inventory();
        duplicate.nodes[6].organization_id = duplicate.nodes[0].organization_id.clone();
        assert!(validate(&duplicate).unwrap_err().contains("distinct"));
        let mut loopback = inventory();
        loopback.nodes[0].host = "127.0.0.1".into();
        assert!(validate(&loopback).unwrap_err().contains("loopback"));
        let mut identity = inventory();
        identity.nodes[1].expected_instance_id = identity.nodes[0].expected_instance_id.clone();
        assert!(validate(&identity).unwrap_err().contains("distinct"));
        let mut proof_identity = inventory();
        proof_identity.nodes[1].expected_proof_instance_id =
            proof_identity.nodes[0].expected_proof_instance_id.clone();
        assert!(validate(&proof_identity).unwrap_err().contains("distinct"));
        let mut overlapping_port = inventory();
        overlapping_port.nodes[0].proof_port = overlapping_port.nodes[0].port;
        assert!(validate(&overlapping_port)
            .unwrap_err()
            .contains("overlapping"));
        let mut os_installation = inventory();
        os_installation.nodes[1].expected_os_installation_id =
            os_installation.nodes[0].expected_os_installation_id.clone();
        assert!(validate(&os_installation).unwrap_err().contains("distinct"));
    }

    #[test]
    fn inventory_is_read_once_from_a_bounded_non_link_file() {
        let directory = tempfile::tempdir().unwrap();
        let inventory = directory.path().join("inventory.json");
        fs::write(&inventory, b"{}").unwrap();
        fs::set_permissions(&inventory, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_inventory(&inventory).unwrap(), b"{}");

        fs::set_permissions(&inventory, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_inventory(&inventory)
            .unwrap_err()
            .contains("owner-only"));
        fs::set_permissions(&inventory, fs::Permissions::from_mode(0o600)).unwrap();

        let linked = directory.path().join("linked.json");
        symlink(&inventory, &linked).unwrap();
        assert!(read_inventory(&linked).unwrap_err().contains("safely"));

        assert_eq!(run_restart_hook("test", &["/usr/bin/true".into()]), Ok(()));
        assert!(run_restart_hook("test", &["true".into()])
            .unwrap_err()
            .contains("absolute"));
    }
}
