//! One-time mutually authenticated FROST DKG for seven deployed proof nodes.
//!
//! This command never receives a signing-key share.  It validates each pinned
//! proof identity and complete-proof configuration, relays the DKG messages,
//! and writes the public group package/digest that governance must pin in the
//! WAN inventory before running `wan_acceptance`.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use qomm_transport::frost_coordinator::{
    distributed_frost_setup, finalize_frost_dkg, prepare_frost_dkg, FrostDkgPlan,
};
use qomm_transport::node_service::client_ssl_context;
use qomm_transport::proof_client::ProofPartyTlsClient;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_INVENTORY_BYTES: usize = 1 << 20;
const MAX_DKG_JOURNAL_BYTES: usize = 8 << 20;

#[derive(Deserialize)]
struct Inventory {
    deployment_id: String,
    coordinator_certificate: PathBuf,
    coordinator_private_key: PathBuf,
    ca_certificate: PathBuf,
    nodes: Vec<Node>,
}

#[derive(Clone, Deserialize)]
struct Node {
    node: u16,
    host: String,
    proof_port: u16,
    proof_server_name: String,
    expected_proof_instance_id: String,
    expected_os_installation_id: String,
}

#[derive(Deserialize, Serialize)]
struct DkgJournal {
    schema: String,
    deployment_id: String,
    inventory_sha256: String,
    session: String,
    plan: FrostDkgPlan,
}

fn resolve(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn read_bounded_regular(path: &Path, limit: usize, name: &str) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("{name} cannot be opened safely: {error}"))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    // SAFETY: geteuid has no preconditions and exposes no secret.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > limit as u64
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(format!(
            "{name} must be a bounded owner-only regular file owned by the operator"
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > limit {
        return Err(format!("{name} exceeds its fixed bound"));
    }
    Ok(bytes)
}

fn hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    hex::decode(value)
        .map_err(|_| format!("{name} must be 32-byte hexadecimal"))?
        .try_into()
        .map_err(|_| format!("{name} must be 32-byte hexadecimal"))
}

fn validate(inventory: &Inventory) -> Result<(), String> {
    if inventory.deployment_id.trim().is_empty() || inventory.nodes.len() != 7 {
        return Err("FROST provisioning requires a deployment id and seven nodes".into());
    }
    let ids = inventory
        .nodes
        .iter()
        .map(|node| node.node)
        .collect::<BTreeSet<_>>();
    let hosts = inventory
        .nodes
        .iter()
        .map(|node| node.host.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let endpoints = inventory
        .nodes
        .iter()
        .map(|node| (node.host.trim().to_ascii_lowercase(), node.proof_port))
        .collect::<BTreeSet<_>>();
    let identities = inventory
        .nodes
        .iter()
        .map(|node| node.expected_proof_instance_id.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let os_installations = inventory
        .nodes
        .iter()
        .map(|node| node.expected_os_installation_id.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if ids != (0_u16..7).collect()
        || hosts.len() != 7
        || endpoints.len() != 7
        || identities.len() != 7
        || os_installations.len() != 7
    {
        return Err(
            "FROST provisioning requires seven distinct hosts, endpoints, identities and OS installations"
                .into(),
        );
    }
    for node in &inventory.nodes {
        let host = node.host.trim().to_ascii_lowercase();
        if node.proof_port == 0
            || node.proof_server_name.trim().is_empty()
            || matches!(host.as_str(), "localhost" | "::1" | "0.0.0.0")
            || host.starts_with("127.")
            || hex32(&node.expected_proof_instance_id, "proof identity").is_err()
            || hex32(
                &node.expected_os_installation_id,
                "OS installation identity",
            )
            .is_err()
        {
            return Err(format!(
                "FROST node {} has an invalid or local-only endpoint/identity",
                node.node
            ));
        }
    }
    Ok(())
}

fn atomic_write(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let temporary = parent.join(format!(".qomm-frost-{}.tmp", rand::random::<u64>()));
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
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
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn run(
    inventory_path: &Path,
    session: [u8; 32],
    journal_path: &Path,
    output: &Path,
) -> Result<(), String> {
    if session == [0; 32] {
        return Err("FROST DKG session must not be all zero".into());
    }
    let inventory_bytes = read_bounded_regular(
        inventory_path,
        MAX_INVENTORY_BYTES,
        "FROST provisioning inventory",
    )?;
    let inventory_sha256 = hex::encode(Sha256::digest(&inventory_bytes));
    let mut inventory: Inventory =
        serde_json::from_slice(&inventory_bytes).map_err(|error| error.to_string())?;
    validate(&inventory)?;
    inventory.nodes.sort_by_key(|node| node.node);
    let base = inventory_path.parent().unwrap_or_else(|| Path::new("."));
    let tls = client_ssl_context(
        resolve(base, &inventory.coordinator_certificate),
        resolve(base, &inventory.coordinator_private_key),
        resolve(base, &inventory.ca_certificate),
    )?;
    let mut clients = inventory
        .nodes
        .iter()
        .map(|node| {
            ProofPartyTlsClient::new(
                &node.host,
                node.proof_port,
                tls.clone(),
                &node.proof_server_name,
                Duration::from_secs(30),
            )
        })
        .collect::<Vec<_>>();
    let mut proof_identities = Vec::new();
    let mut ready = 0_usize;
    for (node, client) in inventory.nodes.iter().zip(clients.iter_mut()) {
        let health = client.call(
            "health",
            json!({"deployment_id": inventory.deployment_id.as_str()}),
        )?;
        let valid = health.get("node").and_then(Value::as_u64) == Some(u64::from(node.node))
            && health.get("deployment_id").and_then(Value::as_str)
                == Some(inventory.deployment_id.as_str())
            && health.get("complete_quote_proof").and_then(Value::as_bool) == Some(true)
            && health.get("n_mm").and_then(Value::as_u64) == Some(4)
            && health.get("n_parties").and_then(Value::as_u64) == Some(7)
            && health.get("threshold").and_then(Value::as_u64) == Some(2)
            && health.get("quote_eligibility_bits").and_then(Value::as_u64) == Some(34)
            && health.get("quote_span_bits").and_then(Value::as_u64) == Some(32);
        let instance_matches = health
            .get("instance_id")
            .and_then(Value::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case(&node.expected_proof_instance_id));
        let os_matches = health
            .get("os_installation_id")
            .and_then(Value::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case(&node.expected_os_installation_id));
        if !valid || !instance_matches || !os_matches {
            return Err(format!(
                "FROST node {} failed pinned identity or complete-proof preflight",
                node.node
            ));
        }
        ready += usize::from(health.get("frost_ready").and_then(Value::as_bool) == Some(true));
        proof_identities.push(json!({
            "node": node.node,
            "host": node.host,
            "proof_port": node.proof_port,
            "proof_instance_id": node.expected_proof_instance_id,
            "os_installation_id": node.expected_os_installation_id,
        }));
    }
    let public = if ready == 7 {
        distributed_frost_setup(&mut clients, session)?
    } else {
        let plan = if journal_path.exists() {
            let journal: DkgJournal = serde_json::from_slice(&read_bounded_regular(
                journal_path,
                MAX_DKG_JOURNAL_BYTES,
                "FROST DKG journal",
            )?)
            .map_err(|_| "FROST DKG journal is malformed".to_string())?;
            if journal.schema != "qomm-frost-dkg-journal-v1"
                || journal.deployment_id != inventory.deployment_id
                || journal.inventory_sha256 != inventory_sha256
                || journal.session != hex::encode(session)
                || journal.plan.session != journal.session
            {
                return Err("FROST DKG journal belongs to another deployment/session".into());
            }
            journal.plan
        } else {
            if ready != 0 {
                return Err(
                    "part of the FROST group is already finalized and no matching DKG journal exists"
                        .into(),
                );
            }
            let plan = prepare_frost_dkg(&mut clients, session)?;
            let journal = DkgJournal {
                schema: "qomm-frost-dkg-journal-v1".into(),
                deployment_id: inventory.deployment_id.clone(),
                inventory_sha256: inventory_sha256.clone(),
                session: hex::encode(session),
                plan: plan.clone(),
            };
            atomic_write(
                journal_path,
                &serde_json::to_value(journal).map_err(|error| error.to_string())?,
            )?;
            plan
        };
        finalize_frost_dkg(&mut clients, &plan)?
    };
    let public_package = public
        .serialize()
        .map_err(|_| "FROST public package serialization failed".to_string())?;
    let digest = hex::encode(Sha256::digest(&public_package));
    let artifact = json!({
        "schema": "qomm-frost-provisioning-v1",
        "deployment_id": inventory.deployment_id,
        "inventory_sha256": inventory_sha256,
        "completed_at_unix": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        "session": hex::encode(session),
        "participants": 7,
        "signing_threshold": 3,
        "complete_quote_proof_preflight": true,
        "private_key_shares_exported": false,
        "public_package": BASE64.encode(&public_package),
        "public_package_sha256": digest,
        "dkg_journal": journal_path,
        "inventory_pin_instruction": "Copy public_package_sha256 to expected_frost_public_package_sha256, then run wan_acceptance.",
        "nodes": proof_identities,
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
        run(
            Path::new(value("--inventory")?),
            hex32(value("--session")?, "FROST DKG session")?,
            Path::new(value("--journal")?),
            Path::new(value("--out")?),
        )
    })();
    if let Err(error) = result {
        eprintln!("FROST cluster provisioning failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn provisioning_inventory_rejects_aliases_and_bad_sessions() {
        assert!(hex32(&"00".repeat(32), "session").is_ok());
        assert!(hex32("00", "session").is_err());
        let inventory = Inventory {
            deployment_id: "pilot".into(),
            coordinator_certificate: "cert".into(),
            coordinator_private_key: "key".into(),
            ca_certificate: "ca".into(),
            nodes: (0_u16..7)
                .map(|node| Node {
                    node,
                    host: format!("node-{node}.example.net"),
                    proof_port: 9543,
                    proof_server_name: format!("node-{node}.example.net"),
                    expected_proof_instance_id: format!("{:02x}", node + 1).repeat(32),
                    expected_os_installation_id: format!("{:02x}", node + 11).repeat(32),
                })
                .collect(),
        };
        assert_eq!(validate(&inventory), Ok(()));
    }

    #[test]
    fn provisioning_inventory_requires_owner_only_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("inventory.json");
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_bounded_regular(&path, 1024, "inventory").unwrap(),
            b"{}"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_bounded_regular(&path, 1024, "inventory")
            .unwrap_err()
            .contains("owner-only"));
    }
}
