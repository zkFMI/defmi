//! Split-knowledge provisioning for a seven-organisation QOMM WAN deployment.
//!
//! The workflow is intentionally asymmetric:
//! 1. an offline authority creates only governance/coordinator/client material;
//! 2. every node creates its TLS key, sealing keys and passphrases locally;
//! 3. the authority signs public CSRs and returns a signed public response;
//! 4. each node verifies that response against its local key before emitting
//!    runnable resident/proof-party configuration.
//!
//! FROST and MP-SPDZ policy shares are not created centrally. FROST is generated
//! by distributed DKG after all proof services are live. Every node also makes
//! a distinct MP-SPDZ transport key and CSR locally; the authority distributes
//! only the seven public peer certificates, so no node receives another
//! party's MP-SPDZ private key. The approved node-local MPC registry is named
//! explicitly and is never replaced by a permissive placeholder.

use crate::executor::{
    circuit_shape_digest, write_source_bound_runtime_executable, ProgramRegistry, RuntimeBinding,
};
use crate::key_management::{
    create_ca, create_mutual_tls_request, issue_mutual_tls_certificate,
    issue_mutual_tls_certificate_from_csr, EncryptedKeyStore, KeyKind,
};
use crate::node_service::certificate_fingerprint;
use crate::resident_mpc::{EncryptedMpcStateStore, MpcSecretState, ResidentMpcConfig};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use openssl::asn1::Asn1Time;
use openssl::pkey::{PKey, Private};
use openssl::sign::{Signer, Verifier};
use openssl::x509::{X509Req, X509};
use qomm_mpc::compiler::OfficialCompiler;
use qomm_mpc::program::{
    build_program, policy_rule_source, ProgramConfig, Reference, StopAfter, ED25519_ORDER,
    POLICY_RULE_NAME,
};
use qomm_proofs::kyb::{
    cohort_id, present, verify_presentation, BusinessAttributes, KybIssuer, KybPresentation,
    SignedCohortRegistry,
};
use qomm_zk::or_dleq::Proof;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const SPEC_VERSION: u8 = 1;
const NODE_COUNT: usize = 7;
const MAX_FILE_BYTES: u64 = 1 << 20;
const MAX_RUNTIME_FILE_BYTES: u64 = 1 << 31;
const RESPONSE_DOMAIN: &[u8] = b"QOMM:WAN:AUTHORITY-RESPONSE:v1";
const DEFAULT_RULE: &str = "param mid[99000,101000] half[1,200] slope[0,16]\ninput qty[1,1000]\nask = mid + half + slope * qty\n";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WanDeploymentSpec {
    pub version: u8,
    pub deployment_id: String,
    pub venue_scope: String,
    pub jurisdiction: String,
    pub entity_type: String,
    pub minimum_collateral_tier: u32,
    pub maximum_collateral_tier: u32,
    pub registry_epoch: u64,
    pub registry_expires_at: u64,
    pub ca_lifetime_days: u32,
    pub certificate_lifetime_days: u32,
    pub coordinator_common_name: String,
    pub client_common_name: String,
    pub client_control_group_id: String,
    pub trusted_defmi_receipt_public: String,
    pub n_mm: usize,
    pub n_parties: usize,
    /// Shamir degree.  `2` means a 3-of-7 reconstruction/signing threshold.
    pub threshold: usize,
    pub amount_bits: usize,
    pub price_bits: usize,
    pub remainder_bits: usize,
    pub quote_eligibility_bits: usize,
    pub quote_span_bits: usize,
    pub mpc_program: ProgramConfig,
    pub nodes: Vec<WanNodeSpec>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WanNodeSpec {
    pub node: u16,
    pub organization_id: String,
    pub host: String,
    #[serde(default = "default_bind_host")]
    pub bind_host: String,
    pub resident_port: u16,
    pub proof_port: u16,
    pub mpc_port: u16,
    pub state_root: PathBuf,
    pub program_registry: PathBuf,
    pub restart_argv: Vec<String>,
    pub restart_proof_argv: Vec<String>,
}

/// Node-local shares delivered directly to one organisation. This document is
/// never handled by the authority or coordinator and must be a mode-600 file
/// owned by the service account.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeMpcShareBundle {
    pub version: u8,
    pub node: u16,
    pub generation: u64,
    pub source_sha256: String,
    /// Maker standing reserves, their blindings, and settlement handles only.
    /// Taker reserve shares are supplied per RFQ in the fixed-size frame.
    pub dvp_input_shares: Vec<String>,
    pub policy_input_shares: Vec<String>,
    #[serde(default)]
    pub quote_policy_blinding_input_shares: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeMpcStateReceipt {
    pub version: u8,
    pub deployment_id: String,
    pub node: u16,
    pub generation: u64,
    pub source_sha256: String,
    pub encrypted_state: PathBuf,
    pub encrypted_state_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeMpcRuntimeReceipt {
    pub version: u8,
    pub deployment_id: String,
    pub node: u16,
    pub program: String,
    pub source_sha256: String,
    pub runtime_config: PathBuf,
    pub runtime_config_sha256: String,
    pub launcher: PathBuf,
    pub launcher_sha256: String,
    pub program_registry: PathBuf,
    pub program_registry_sha256: String,
    pub public_peer_certificates: usize,
    pub local_private_keys: usize,
}

fn default_bind_host() -> String {
    "0.0.0.0".into()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeEnrollmentRequest {
    pub version: u8,
    pub deployment_id: String,
    pub node: u16,
    pub organization_id: String,
    pub host: String,
    pub common_name: String,
    pub csr_sha256: String,
    pub mpc_common_name: String,
    pub mpc_csr_sha256: String,
    /// SHA-256 of the offline CA certificate delivered to this node through a
    /// governance-controlled channel before any enrollment response exists.
    pub trusted_ca_certificate_sha256: String,
    pub admission_authority_key_id: String,
    pub ordering_beacon_key_id: String,
    pub node_receipt_key_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KybRegistryDocument {
    pub cohort: String,
    pub registry_epoch: u64,
    pub expires_at: u64,
    pub points: Vec<String>,
    pub issuer: String,
    pub registry_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KybPresentationDocument {
    pub cohort: String,
    pub registry_id: String,
    pub scope: String,
    pub context_hash: String,
    pub nullifier: String,
    pub challenges: Vec<String>,
    pub responses: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KybDeploymentDocument {
    pub venue_scope: String,
    pub required_cohort: String,
    pub trusted_issuer: String,
    pub client_certificate_fingerprint: String,
    pub scope_nullifier: String,
    pub registry: KybRegistryDocument,
    pub presentation: KybPresentationDocument,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeAuthorityResponse {
    pub version: u8,
    pub deployment_id: String,
    pub node: u16,
    pub csr_sha256: String,
    pub mpc_csr_sha256: String,
    pub node_certificate_sha256: String,
    pub mpc_peer_certificate_sha256: BTreeMap<String, String>,
    pub ca_certificate_sha256: String,
    pub coordinator_certificate_sha256: String,
    pub client_certificate_sha256: String,
    pub client_frame_key_sha256: String,
    pub kyb_document_sha256: String,
    pub authority_signature: String,
}

impl NodeAuthorityResponse {
    fn unsigned(&self) -> Result<Vec<u8>, String> {
        let value = json!({
            "version": self.version,
            "deployment_id": self.deployment_id,
            "node": self.node,
            "csr_sha256": self.csr_sha256,
            "mpc_csr_sha256": self.mpc_csr_sha256,
            "node_certificate_sha256": self.node_certificate_sha256,
            "mpc_peer_certificate_sha256": self.mpc_peer_certificate_sha256,
            "ca_certificate_sha256": self.ca_certificate_sha256,
            "coordinator_certificate_sha256": self.coordinator_certificate_sha256,
            "client_certificate_sha256": self.client_certificate_sha256,
            "client_frame_key_sha256": self.client_frame_key_sha256,
            "kyb_document_sha256": self.kyb_document_sha256,
        });
        let mut bytes = RESPONSE_DOMAIN.to_vec();
        bytes.extend(serde_json::to_vec(&value).map_err(|error| error.to_string())?);
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AuthorityManifest {
    version: u8,
    deployment_id: String,
    ca_certificate_sha256: String,
    coordinator_certificate_sha256: String,
    client_certificate_sha256: String,
    kyb_document_sha256: String,
    node_private_keys_received: bool,
    frost_secret_shares_created: bool,
    hardware_hsm_verified: bool,
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before the Unix epoch".to_string())
}

fn node_common_name(spec: &WanDeploymentSpec, node: u16) -> String {
    format!("qomm-{}-node-{node}", spec.deployment_id)
}

fn mpc_common_name(spec: &WanDeploymentSpec, node: u16) -> String {
    format!("qomm-{}-mpc-{node}", spec.deployment_id)
}

fn is_hex_bytes(value: &str, bytes: usize) -> bool {
    value.len() == bytes.saturating_mul(2) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn safe_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| !matches!(part, Component::ParentDir | Component::CurDir))
}

impl WanDeploymentSpec {
    pub fn validate(&self, at: u64) -> Result<(), String> {
        if self.version != SPEC_VERSION
            || self.deployment_id.trim().is_empty()
            || self.venue_scope.trim().is_empty()
            || self.jurisdiction.trim().is_empty()
            || self.entity_type.trim().is_empty()
            || self.coordinator_common_name.trim().is_empty()
            || self.client_common_name.trim().is_empty()
            || self.client_control_group_id.trim().is_empty()
        {
            return Err("WAN deployment identity and KYB fields are incomplete".into());
        }
        if self.minimum_collateral_tier == 0
            || self.maximum_collateral_tier < self.minimum_collateral_tier
            || self.registry_epoch == 0
            || self.registry_expires_at <= at.saturating_add(3600)
            || !(1..=3650).contains(&self.ca_lifetime_days)
            || !(1..=825).contains(&self.certificate_lifetime_days)
        {
            return Err("WAN certificate or KYB lifecycle is outside its bound".into());
        }
        let receipt: [u8; 32] = hex::decode(&self.trusted_defmi_receipt_public)
            .map_err(|_| "trusted DeFMI receipt key must be 32-byte hexadecimal".to_string())?
            .try_into()
            .map_err(|_| "trusted DeFMI receipt key must be 32-byte hexadecimal".to_string())?;
        VerifyingKey::from_bytes(&receipt)
            .map_err(|_| "trusted DeFMI receipt key is not a canonical Ed25519 key".to_string())?;
        if self.n_parties != NODE_COUNT
            || self.threshold != 2
            || self.n_mm == 0
            || self.n_mm > 64
            || !(1..=63).contains(&self.amount_bits)
            || !(1..=63).contains(&self.price_bits)
            || !(1..=63).contains(&self.remainder_bits)
            || !(1..=63).contains(&self.quote_eligibility_bits)
            || !(1..=63).contains(&self.quote_span_bits)
        {
            return Err("WAN proof shape must be the approved 3-of-7 bounded configuration".into());
        }
        if self.mpc_program.n_mm != self.n_mm
            || self.mpc_program.n_parties != self.n_parties
            || self.mpc_program.n_requests != 1
            || self.mpc_program.n_assets == 0
            || self.mpc_program.ref_table.len() != self.mpc_program.n_assets
            || self.mpc_program.maker_assets.len() != self.n_mm
            || self
                .mpc_program
                .maker_assets
                .iter()
                .any(|asset| *asset >= self.mpc_program.n_assets)
            || !self.mpc_program.public_maker_assets
            || !self.mpc_program.binding_limit
            || !self.mpc_program.persist_wires
            || !self.mpc_program.persist_zkpi_wires
            || !self.mpc_program.persist_quote_proof_wires
            || !self.mpc_program.persist_dvp_wires
            || self.mpc_program.stop_after != StopAfter::Tournament
            || self.mpc_program.zkpi_amount_bits != self.amount_bits
            || self.mpc_program.zkpi_price_bits != self.price_bits
            || self.mpc_program.dvp_remainder_bits != self.remainder_bits
            || self.mpc_program.quote_eligibility_bits != self.quote_eligibility_bits
            || self.mpc_program.quote_span_bits != self.quote_span_bits
            || build_program(&self.mpc_program).is_err()
        {
            return Err(
                "WAN MPC program is not the approved full-quote, bound-limit, DvP configuration"
                    .into(),
            );
        }
        if self.nodes.len() != NODE_COUNT {
            return Err("WAN deployment requires exactly seven nodes".into());
        }
        let expected = (0_u16..NODE_COUNT as u16).collect::<BTreeSet<_>>();
        let nodes = self
            .nodes
            .iter()
            .map(|node| node.node)
            .collect::<BTreeSet<_>>();
        let organizations = self
            .nodes
            .iter()
            .map(|node| node.organization_id.trim().to_string())
            .collect::<BTreeSet<_>>();
        let hosts = self
            .nodes
            .iter()
            .map(|node| node.host.trim().to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        if nodes != expected
            || organizations.len() != NODE_COUNT
            || organizations.contains("")
            || hosts.len() != NODE_COUNT
        {
            return Err("WAN nodes, organisations and hosts must be seven distinct entries".into());
        }
        for node in &self.nodes {
            let host = node.host.trim().to_ascii_lowercase();
            if node.resident_port == 0
                || node.proof_port == 0
                || node.mpc_port == 0
                || node.resident_port == node.proof_port
                || node.resident_port == node.mpc_port
                || node.proof_port == node.mpc_port
                || matches!(host.as_str(), "localhost" | "::1" | "0.0.0.0")
                || host.starts_with("127.")
                || node.bind_host.trim().is_empty()
                || !safe_absolute(&node.state_root)
                || !safe_absolute(&node.program_registry)
                || node.restart_argv.is_empty()
                || node.restart_proof_argv.is_empty()
                || node.restart_argv.iter().any(|part| part.is_empty())
                || node.restart_proof_argv.iter().any(|part| part.is_empty())
            {
                return Err(format!(
                    "WAN node {} has an unsafe deployment field",
                    node.node
                ));
            }
        }
        Ok(())
    }

    pub fn node(&self, node: u16) -> Result<&WanNodeSpec, String> {
        self.nodes
            .iter()
            .find(|entry| entry.node == node)
            .ok_or_else(|| format!("WAN deployment has no node {node}"))
    }
}

fn directory_mode(path: &Path) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| error.to_string())
}

fn create_directory(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| error.to_string())?;
    directory_mode(path)
}

fn prepare_new_directory(path: &Path) -> Result<(), String> {
    if path.exists() || fs::symlink_metadata(path).is_ok() {
        return Err(format!("refusing to overwrite {}", path.display()));
    }
    create_directory(path)
}

fn write_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        create_directory(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| error.to_string())?;
    File::open(path.parent().unwrap_or_else(|| Path::new(".")))
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

fn write_json<T: Serialize>(path: &Path, value: &T, mode: u32) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    write_file(path, &bytes, mode)
}

fn copy_file(source: &Path, target: &Path, mode: u32) -> Result<(), String> {
    let bytes = read_bounded(source, MAX_FILE_BYTES)?;
    write_file(target, &bytes, mode)
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("{} cannot be opened safely: {error}", path.display()))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(format!("{} is not a bounded regular file", path.display()));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > maximum {
        return Err(format!("{} exceeds its bound", path.display()));
    }
    Ok(bytes)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    serde_json::from_slice(&read_bounded(path, MAX_FILE_BYTES)?).map_err(|error| error.to_string())
}

pub fn read_deployment_spec(path: &Path) -> Result<WanDeploymentSpec, String> {
    let spec: WanDeploymentSpec = read_json(path)?;
    spec.validate(now()?)?;
    Ok(spec)
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn digest_file(path: &Path) -> Result<String, String> {
    Ok(digest(&read_bounded(path, MAX_FILE_BYTES)?))
}

fn digest_runtime_file(path: &Path, executable: bool) -> Result<String, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("{} cannot be opened safely: {error}", path.display()))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_RUNTIME_FILE_BYTES
        || (executable && metadata.permissions().mode() & 0o111 == 0)
    {
        return Err(format!(
            "{} is not a bounded{} runtime file",
            path.display(),
            if executable { " executable" } else { "" }
        ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn read_private_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("{} cannot be opened safely: {error}", path.display()))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    // SAFETY: geteuid has no preconditions and does not dereference memory.
    let owner = unsafe { libc::geteuid() };
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
        || metadata.uid() != owner
        || mode != 0o600
    {
        return Err(format!(
            "{} must be a non-empty, owner-held mode-600 regular file",
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > maximum {
        bytes.fill(0);
        return Err(format!("{} exceeds its bound", path.display()));
    }
    Ok(bytes)
}

fn read_private_secret(path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = read_private_bounded(path, MAX_FILE_BYTES)?;
    while bytes
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        bytes.pop();
    }
    if bytes.len() < 12 {
        bytes.fill(0);
        return Err(format!("{} contains a short secret", path.display()));
    }
    Ok(bytes)
}

fn write_or_verify_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    if path.exists() || fs::symlink_metadata(path).is_ok() {
        if read_bounded(path, (bytes.len() as u64).saturating_add(1))? != bytes {
            return Err(format!(
                "refusing to replace changed file {}",
                path.display()
            ));
        }
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    if !parent.is_dir() {
        return Err(format!("{} parent directory is absent", path.display()));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| error.to_string())?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

fn random_secret() -> Vec<u8> {
    let mut entropy = [0_u8; 32];
    OsRng.fill_bytes(&mut entropy);
    let encoded = hex::encode(entropy).into_bytes();
    entropy.fill(0);
    encoded
}

fn private_key(path: &Path) -> Result<PKey<Private>, String> {
    PKey::private_key_from_pem(&read_bounded(path, MAX_FILE_BYTES)?)
        .map_err(|error| error.to_string())
}

fn certificate(path: &Path) -> Result<X509, String> {
    X509::from_pem(&read_bounded(path, MAX_FILE_BYTES)?).map_err(|error| error.to_string())
}

fn current_certificate(certificate: &X509, at: u64, name: &str) -> Result<(), String> {
    let at = i64::try_from(at).map_err(|_| "certificate time exceeds i64".to_string())?;
    let instant = Asn1Time::from_unix(at).map_err(|error| error.to_string())?;
    if certificate
        .not_before()
        .compare(&instant)
        .map_err(|error| error.to_string())?
        == Ordering::Greater
        || certificate
            .not_after()
            .compare(&instant)
            .map_err(|error| error.to_string())?
            != Ordering::Greater
    {
        return Err(format!("{name} is not valid at the enrollment time"));
    }
    Ok(())
}

fn request(path: &Path) -> Result<X509Req, String> {
    X509Req::from_pem(&read_bounded(path, MAX_FILE_BYTES)?).map_err(|error| error.to_string())
}

fn encode_registry(registry: &SignedCohortRegistry) -> KybRegistryDocument {
    KybRegistryDocument {
        cohort: registry.cohort.clone(),
        registry_epoch: registry.registry_epoch,
        expires_at: registry.expires_at,
        points: registry
            .points
            .iter()
            .map(|point| hex::encode(point.compress().as_bytes()))
            .collect(),
        issuer: hex::encode(registry.issuer.as_bytes()),
        registry_id: hex::encode(registry.registry_id),
        signature: hex::encode(registry.signature.to_bytes()),
    }
}

fn encode_presentation(presentation: &KybPresentation) -> KybPresentationDocument {
    KybPresentationDocument {
        cohort: presentation.cohort.clone(),
        registry_id: hex::encode(presentation.registry_id),
        scope: String::from_utf8_lossy(&presentation.scope).into_owned(),
        context_hash: hex::encode(presentation.context_hash),
        nullifier: hex::encode(presentation.proof.nullifier.compress().as_bytes()),
        challenges: presentation
            .proof
            .challenges
            .iter()
            .map(|scalar| hex::encode(scalar.as_bytes()))
            .collect(),
        responses: presentation
            .proof
            .responses
            .iter()
            .map(|scalar| hex::encode(scalar.as_bytes()))
            .collect(),
    }
}

fn fixed_hex<const N: usize>(value: &str, name: &str) -> Result<[u8; N], String> {
    hex::decode(value)
        .map_err(|_| format!("{name} must be {N}-byte hexadecimal"))?
        .try_into()
        .map_err(|_| format!("{name} must be {N}-byte hexadecimal"))
}

fn decode_point(value: &str, name: &str) -> Result<RistrettoPoint, String> {
    CompressedRistretto(fixed_hex(value, name)?)
        .decompress()
        .ok_or_else(|| format!("{name} is not a canonical Ristretto point"))
}

fn decode_scalar(value: &str, name: &str) -> Result<Scalar, String> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(fixed_hex(value, name)?))
        .ok_or_else(|| format!("{name} is not a canonical scalar"))
}

fn decode_kyb(
    document: &KybDeploymentDocument,
) -> Result<(SignedCohortRegistry, KybPresentation, VerifyingKey), String> {
    let issuer = VerifyingKey::from_bytes(&fixed_hex(&document.trusted_issuer, "KYB issuer")?)
        .map_err(|_| "KYB issuer is not a canonical Ed25519 key".to_string())?;
    let registry_issuer =
        VerifyingKey::from_bytes(&fixed_hex(&document.registry.issuer, "registry issuer")?)
            .map_err(|_| "registry issuer is not a canonical Ed25519 key".to_string())?;
    let registry = SignedCohortRegistry {
        cohort: document.registry.cohort.clone(),
        registry_epoch: document.registry.registry_epoch,
        expires_at: document.registry.expires_at,
        points: document
            .registry
            .points
            .iter()
            .enumerate()
            .map(|(index, value)| decode_point(value, &format!("registry point {index}")))
            .collect::<Result<Vec<_>, _>>()?,
        issuer: registry_issuer,
        registry_id: fixed_hex(&document.registry.registry_id, "registry id")?,
        signature: Signature::from_slice(
            &hex::decode(&document.registry.signature)
                .map_err(|_| "registry signature must be hexadecimal".to_string())?,
        )
        .map_err(|_| "registry signature must be 64 bytes".to_string())?,
    };
    let presentation = KybPresentation {
        cohort: document.presentation.cohort.clone(),
        registry_id: fixed_hex(
            &document.presentation.registry_id,
            "presentation registry id",
        )?,
        scope: document.presentation.scope.as_bytes().to_vec(),
        context_hash: fixed_hex(&document.presentation.context_hash, "presentation context")?,
        proof: Proof {
            nullifier: decode_point(&document.presentation.nullifier, "presentation nullifier")?,
            challenges: document
                .presentation
                .challenges
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    decode_scalar(value, &format!("presentation challenge {index}"))
                })
                .collect::<Result<Vec<_>, _>>()?,
            responses: document
                .presentation
                .responses
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    decode_scalar(value, &format!("presentation response {index}"))
                })
                .collect::<Result<Vec<_>, _>>()?,
        },
    };
    Ok((registry, presentation, issuer))
}

pub fn initialize_authority(spec: &WanDeploymentSpec, output: &Path) -> Result<(), String> {
    let at = now()?;
    spec.validate(at)?;
    prepare_new_directory(output)?;
    let private = output.join("private");
    let public = output.join("public");
    let coordinator = output.join("coordinator");
    let client = output.join("client");
    for directory in [&private, &public, &coordinator, &client] {
        create_directory(directory)?;
    }

    let (ca_key, ca_certificate) = create_ca(
        &format!("QOMM {} offline CA", spec.deployment_id),
        spec.ca_lifetime_days,
    )?;
    let (coordinator_key, coordinator_certificate) = issue_mutual_tls_certificate(
        &ca_key,
        &ca_certificate,
        &spec.coordinator_common_name,
        &[],
        &[],
        spec.certificate_lifetime_days,
    )?;
    let (client_key, client_certificate) = issue_mutual_tls_certificate(
        &ca_key,
        &ca_certificate,
        &spec.client_common_name,
        &[],
        &[],
        spec.certificate_lifetime_days,
    )?;

    write_file(
        &private.join("ca.key.pem"),
        &ca_key
            .private_key_to_pem_pkcs8()
            .map_err(|error| error.to_string())?,
        0o600,
    )?;
    write_file(
        &public.join("ca.cert.pem"),
        &ca_certificate.to_pem().map_err(|error| error.to_string())?,
        0o644,
    )?;
    write_file(
        &coordinator.join("coordinator.key.pem"),
        &coordinator_key
            .private_key_to_pem_pkcs8()
            .map_err(|error| error.to_string())?,
        0o600,
    )?;
    write_file(
        &coordinator.join("coordinator.cert.pem"),
        &coordinator_certificate
            .to_pem()
            .map_err(|error| error.to_string())?,
        0o644,
    )?;
    write_file(
        &coordinator.join("ca.cert.pem"),
        &ca_certificate.to_pem().map_err(|error| error.to_string())?,
        0o644,
    )?;
    write_file(
        &client.join("client.key.pem"),
        &client_key
            .private_key_to_pem_pkcs8()
            .map_err(|error| error.to_string())?,
        0o600,
    )?;
    write_file(
        &client.join("client.cert.pem"),
        &client_certificate
            .to_pem()
            .map_err(|error| error.to_string())?,
        0o644,
    )?;
    write_file(
        &client.join("ca.cert.pem"),
        &ca_certificate.to_pem().map_err(|error| error.to_string())?,
        0o644,
    )?;
    let client_frame_key = random_secret();
    // The frame key is 32 raw bytes on the wire, not its printable transport.
    let client_frame_key_raw = hex::decode(&client_frame_key).map_err(|error| error.to_string())?;
    write_file(
        &client.join("client-frame.key"),
        &client_frame_key_raw,
        0o600,
    )?;

    let authority_passphrase = random_secret();
    write_file(
        &private.join("authority-store.passphrase"),
        &authority_passphrase,
        0o600,
    )?;
    let authority_store =
        EncryptedKeyStore::new(private.join("authority-keys.qks"), &authority_passphrase)?;
    authority_store.initialize()?;
    let issuer_id = authority_store.generate(
        "kyb-registry-signing",
        KeyKind::Ed25519,
        at,
        spec.registry_expires_at.saturating_sub(at),
        BTreeMap::from([
            (
                "deployment_id".into(),
                Value::String(spec.deployment_id.clone()),
            ),
            ("offline_authority".into(), Value::Bool(true)),
        ]),
    )?;
    let issuer_private = authority_store.private_key(&issuer_id, at, false)?;
    let issuer_signing = issuer_private
        .ed25519()
        .ok_or_else(|| "KYB issuer store returned a non-signing key".to_string())?;
    let mut issuer = KybIssuer::with_signing_key(
        spec.maximum_collateral_tier,
        SigningKey::from_bytes(&issuer_signing.to_bytes()),
    )
    .map_err(str::to_string)?;
    let credential = issuer
        .enroll(
            &spec.client_control_group_id,
            BusinessAttributes {
                jurisdiction: spec.jurisdiction.clone(),
                entity_type: spec.entity_type.clone(),
                collateral_tier: spec.maximum_collateral_tier,
            },
            &mut OsRng,
        )
        .map_err(str::to_string)?;
    let cohort = cohort_id(
        &spec.jurisdiction,
        &spec.entity_type,
        spec.minimum_collateral_tier,
    );
    let registry = issuer
        .publish(&cohort, spec.registry_epoch, spec.registry_expires_at)
        .map_err(str::to_string)?;
    let client_der = client_certificate
        .to_der()
        .map_err(|error| error.to_string())?;
    let client_fingerprint = certificate_fingerprint(&client_der);
    let presentation = present(
        &credential,
        &registry,
        spec.venue_scope.as_bytes(),
        client_fingerprint.as_bytes(),
        &mut OsRng,
    )
    .map_err(str::to_string)?;
    let kyb = KybDeploymentDocument {
        venue_scope: spec.venue_scope.clone(),
        required_cohort: cohort,
        trusted_issuer: hex::encode(issuer.public_key().as_bytes()),
        client_certificate_fingerprint: client_fingerprint,
        scope_nullifier: hex::encode(
            credential
                .scope_nullifier(spec.venue_scope.as_bytes())
                .compress()
                .as_bytes(),
        ),
        registry: encode_registry(&registry),
        presentation: encode_presentation(&presentation),
    };
    write_json(&public.join("kyb.json"), &kyb, 0o644)?;
    write_file(
        &public.join("coordinator.cert.pem"),
        &coordinator_certificate
            .to_pem()
            .map_err(|error| error.to_string())?,
        0o644,
    )?;
    write_file(
        &public.join("client.cert.pem"),
        &client_certificate
            .to_pem()
            .map_err(|error| error.to_string())?,
        0o644,
    )?;
    let manifest = AuthorityManifest {
        version: SPEC_VERSION,
        deployment_id: spec.deployment_id.clone(),
        ca_certificate_sha256: digest_file(&public.join("ca.cert.pem"))?,
        coordinator_certificate_sha256: digest_file(&public.join("coordinator.cert.pem"))?,
        client_certificate_sha256: digest_file(&public.join("client.cert.pem"))?,
        kyb_document_sha256: digest_file(&public.join("kyb.json"))?,
        node_private_keys_received: false,
        frost_secret_shares_created: false,
        hardware_hsm_verified: false,
    };
    write_json(&output.join("authority-manifest.json"), &manifest, 0o644)?;
    Ok(())
}

pub fn initialize_node(
    spec: &WanDeploymentSpec,
    node: u16,
    private_output: &Path,
    request_output: &Path,
    trusted_ca_certificate: &Path,
) -> Result<(), String> {
    let at = now()?;
    spec.validate(at)?;
    let node_spec = spec.node(node)?;
    let trusted_ca_bytes = read_bounded(trusted_ca_certificate, MAX_FILE_BYTES)?;
    let trusted_ca = X509::from_pem(&trusted_ca_bytes).map_err(|error| error.to_string())?;
    current_certificate(&trusted_ca, at, "trusted offline CA certificate")?;
    let trusted_ca_public = trusted_ca.public_key().map_err(|error| error.to_string())?;
    if !trusted_ca
        .verify(&trusted_ca_public)
        .map_err(|error| error.to_string())?
    {
        return Err("trusted offline CA certificate is not self-signed".into());
    }
    let trusted_ca_certificate_sha256 = digest(&trusted_ca_bytes);
    prepare_new_directory(private_output)?;
    prepare_new_directory(request_output)?;
    let private = private_output.join("private");
    create_directory(&private)?;
    let common_name = node_common_name(spec, node);
    let (tls_key, csr) = create_mutual_tls_request(&common_name)?;
    write_file(
        &private.join("node.key.pem"),
        &tls_key
            .private_key_to_pem_pkcs8()
            .map_err(|error| error.to_string())?,
        0o600,
    )?;
    let csr_bytes = csr.to_pem().map_err(|error| error.to_string())?;
    write_file(&request_output.join("node.csr.pem"), &csr_bytes, 0o644)?;
    let mpc_name = mpc_common_name(spec, node);
    let (mpc_key, mpc_csr) = create_mutual_tls_request(&mpc_name)?;
    write_file(
        &private.join("mpc.key.pem"),
        &mpc_key
            .private_key_to_pem_pkcs8()
            .map_err(|error| error.to_string())?,
        0o600,
    )?;
    let mpc_csr_bytes = mpc_csr.to_pem().map_err(|error| error.to_string())?;
    write_file(&request_output.join("mpc.csr.pem"), &mpc_csr_bytes, 0o644)?;

    let sealing_passphrase = random_secret();
    write_file(
        &private.join("sealing-store.passphrase"),
        &sealing_passphrase,
        0o600,
    )?;
    let store = EncryptedKeyStore::new(private.join("sealing-keys.qks"), &sealing_passphrase)?;
    store.initialize()?;
    let lifetime = u64::from(spec.ca_lifetime_days).saturating_mul(86_400);
    let metadata = BTreeMap::from([
        (
            "deployment_id".into(),
            Value::String(spec.deployment_id.clone()),
        ),
        ("node".into(), Value::from(node)),
        (
            "organization_id".into(),
            Value::String(node_spec.organization_id.clone()),
        ),
    ]);
    let admission_authority_key_id = store.generate(
        "admission-authority",
        KeyKind::Ed25519,
        at,
        lifetime,
        metadata.clone(),
    )?;
    let ordering_beacon_key_id = store.generate(
        "ordering-beacon",
        KeyKind::Ed25519,
        at,
        lifetime,
        metadata.clone(),
    )?;
    let node_receipt_key_id =
        store.generate("node-receipt", KeyKind::Ed25519, at, lifetime, metadata)?;
    write_file(
        &private.join("proof-state.passphrase"),
        &random_secret(),
        0o600,
    )?;
    write_file(
        &private.join("mpc-state.passphrase"),
        &random_secret(),
        0o600,
    )?;
    write_file(
        &private.join("trusted-ca.cert.pem"),
        &trusted_ca_bytes,
        0o600,
    )?;
    let request = NodeEnrollmentRequest {
        version: SPEC_VERSION,
        deployment_id: spec.deployment_id.clone(),
        node,
        organization_id: node_spec.organization_id.clone(),
        host: node_spec.host.clone(),
        common_name,
        csr_sha256: digest(&csr_bytes),
        mpc_common_name: mpc_name,
        mpc_csr_sha256: digest(&mpc_csr_bytes),
        trusted_ca_certificate_sha256,
        admission_authority_key_id,
        ordering_beacon_key_id,
        node_receipt_key_id,
    };
    write_json(&request_output.join("node-request.json"), &request, 0o644)?;
    write_json(&private.join("enrollment-request.json"), &request, 0o600)?;
    Ok(())
}

fn verify_request(
    spec: &WanDeploymentSpec,
    node: u16,
    directory: &Path,
) -> Result<(NodeEnrollmentRequest, X509Req, X509Req), String> {
    let request_document: NodeEnrollmentRequest = read_json(&directory.join("node-request.json"))?;
    let node_spec = spec.node(node)?;
    if request_document.version != SPEC_VERSION
        || request_document.deployment_id != spec.deployment_id
        || request_document.node != node
        || request_document.organization_id != node_spec.organization_id
        || request_document.host != node_spec.host
        || request_document.common_name != node_common_name(spec, node)
        || request_document.mpc_common_name != mpc_common_name(spec, node)
        || !is_hex_bytes(&request_document.csr_sha256, 32)
        || !is_hex_bytes(&request_document.mpc_csr_sha256, 32)
        || !is_hex_bytes(&request_document.trusted_ca_certificate_sha256, 32)
        || !is_hex_bytes(&request_document.admission_authority_key_id, 32)
        || !is_hex_bytes(&request_document.ordering_beacon_key_id, 32)
        || !is_hex_bytes(&request_document.node_receipt_key_id, 32)
    {
        return Err(format!(
            "node {node} enrollment request does not match the deployment"
        ));
    }
    let csr_path = directory.join("node.csr.pem");
    if digest_file(&csr_path)? != request_document.csr_sha256 {
        return Err(format!("node {node} enrollment request changed its CSR"));
    }
    let mpc_csr_path = directory.join("mpc.csr.pem");
    if digest_file(&mpc_csr_path)? != request_document.mpc_csr_sha256 {
        return Err(format!(
            "node {node} enrollment request changed its MPC CSR"
        ));
    }
    Ok((
        request_document,
        request(&csr_path)?,
        request(&mpc_csr_path)?,
    ))
}

fn sign_response(
    ca_key: &PKey<Private>,
    response: &mut NodeAuthorityResponse,
) -> Result<(), String> {
    let mut signer = Signer::new_without_digest(ca_key).map_err(|error| error.to_string())?;
    response.authority_signature = hex::encode(
        signer
            .sign_oneshot_to_vec(&response.unsigned()?)
            .map_err(|error| error.to_string())?,
    );
    Ok(())
}

pub fn sign_node_requests(
    spec: &WanDeploymentSpec,
    authority: &Path,
    requests_root: &Path,
    output: &Path,
) -> Result<(), String> {
    spec.validate(now()?)?;
    let manifest: AuthorityManifest = read_json(&authority.join("authority-manifest.json"))?;
    if manifest.version != SPEC_VERSION
        || manifest.deployment_id != spec.deployment_id
        || manifest.node_private_keys_received
        || manifest.frost_secret_shares_created
    {
        return Err(
            "authority manifest is not the split-knowledge authority for this deployment".into(),
        );
    }
    let ca_key = private_key(&authority.join("private/ca.key.pem"))?;
    let ca_certificate = certificate(&authority.join("public/ca.cert.pem"))?;
    let kyb_path = authority.join("public/kyb.json");
    let coordinator_path = authority.join("public/coordinator.cert.pem");
    let client_path = authority.join("public/client.cert.pem");
    let frame_path = authority.join("client/client-frame.key");
    if digest_file(&authority.join("public/ca.cert.pem"))? != manifest.ca_certificate_sha256
        || digest_file(&coordinator_path)? != manifest.coordinator_certificate_sha256
        || digest_file(&client_path)? != manifest.client_certificate_sha256
        || digest_file(&kyb_path)? != manifest.kyb_document_sha256
    {
        return Err("authority public material no longer matches its manifest".into());
    }
    prepare_new_directory(output)?;
    let mut issued = Vec::with_capacity(NODE_COUNT);
    for node in 0_u16..NODE_COUNT as u16 {
        let request_directory = requests_root.join(format!("node-{node}"));
        let (request_document, csr, mpc_csr) = verify_request(spec, node, &request_directory)?;
        if request_document.trusted_ca_certificate_sha256 != manifest.ca_certificate_sha256 {
            return Err(format!(
                "node {node} pinned a different offline CA certificate"
            ));
        }
        let node_spec = spec.node(node)?;
        let host = node_spec.host.as_str();
        let ip = host.parse::<IpAddr>().ok().map(|value| value.to_string());
        let dns = ip.is_none().then_some(host);
        let node_certificate = issue_mutual_tls_certificate_from_csr(
            &ca_key,
            &ca_certificate,
            &csr,
            &request_document.common_name,
            &dns.into_iter().collect::<Vec<_>>(),
            &ip.as_deref().into_iter().collect::<Vec<_>>(),
            spec.certificate_lifetime_days,
        )?;
        let mpc_certificate = issue_mutual_tls_certificate_from_csr(
            &ca_key,
            &ca_certificate,
            &mpc_csr,
            &request_document.mpc_common_name,
            &dns.into_iter().collect::<Vec<_>>(),
            &ip.as_deref().into_iter().collect::<Vec<_>>(),
            spec.certificate_lifetime_days,
        )?;
        let directory = output.join(format!("node-{node}"));
        create_directory(&directory)?;
        write_file(
            &directory.join("node.cert.pem"),
            &node_certificate
                .to_pem()
                .map_err(|error| error.to_string())?,
            0o644,
        )?;
        issued.push((request_document, node_certificate, mpc_certificate));
    }

    for node in 0_u16..NODE_COUNT as u16 {
        let directory = output.join(format!("node-{node}"));
        let (request_document, _, _) = &issued[usize::from(node)];
        copy_file(
            &authority.join("public/ca.cert.pem"),
            &directory.join("ca.cert.pem"),
            0o644,
        )?;
        copy_file(
            &coordinator_path,
            &directory.join("coordinator.cert.pem"),
            0o644,
        )?;
        copy_file(&client_path, &directory.join("client.cert.pem"), 0o644)?;
        copy_file(&frame_path, &directory.join("client-frame.key"), 0o600)?;
        copy_file(&kyb_path, &directory.join("kyb.json"), 0o644)?;
        let peer_directory = directory.join("mpc-player-data");
        create_directory(&peer_directory)?;
        let mut peer_digests = BTreeMap::new();
        for peer in 0_u16..NODE_COUNT as u16 {
            let name = format!("P{peer}.pem");
            write_file(
                &peer_directory.join(&name),
                &issued[usize::from(peer)]
                    .2
                    .to_pem()
                    .map_err(|error| error.to_string())?,
                0o644,
            )?;
            peer_digests.insert(name.clone(), digest_file(&peer_directory.join(name))?);
        }
        let mut response = NodeAuthorityResponse {
            version: SPEC_VERSION,
            deployment_id: spec.deployment_id.clone(),
            node,
            csr_sha256: request_document.csr_sha256.clone(),
            mpc_csr_sha256: request_document.mpc_csr_sha256.clone(),
            node_certificate_sha256: digest_file(&directory.join("node.cert.pem"))?,
            mpc_peer_certificate_sha256: peer_digests,
            ca_certificate_sha256: digest_file(&directory.join("ca.cert.pem"))?,
            coordinator_certificate_sha256: digest_file(&directory.join("coordinator.cert.pem"))?,
            client_certificate_sha256: digest_file(&directory.join("client.cert.pem"))?,
            client_frame_key_sha256: digest_file(&directory.join("client-frame.key"))?,
            kyb_document_sha256: digest_file(&directory.join("kyb.json"))?,
            authority_signature: String::new(),
        };
        sign_response(&ca_key, &mut response)?;
        write_json(&directory.join("authority-response.json"), &response, 0o644)?;
    }
    Ok(())
}

fn verify_response_signature(ca: &X509, response: &NodeAuthorityResponse) -> Result<(), String> {
    let public = ca.public_key().map_err(|error| error.to_string())?;
    let signature = hex::decode(&response.authority_signature)
        .map_err(|_| "authority response signature is not hexadecimal".to_string())?;
    let mut verifier = Verifier::new_without_digest(&public).map_err(|error| error.to_string())?;
    if !verifier
        .verify_oneshot(&signature, &response.unsigned()?)
        .map_err(|error| error.to_string())?
    {
        return Err("authority response signature is invalid".into());
    }
    Ok(())
}

fn verify_response_file(
    response_directory: &Path,
    name: &str,
    expected: &str,
) -> Result<(), String> {
    if !is_hex_bytes(expected, 32) || digest_file(&response_directory.join(name))? != expected {
        return Err(format!("authority response changed {name}"));
    }
    Ok(())
}

pub fn apply_node_response(
    spec: &WanDeploymentSpec,
    node: u16,
    private_root: &Path,
    request_directory: &Path,
    response_directory: &Path,
) -> Result<(), String> {
    let at = now()?;
    spec.validate(at)?;
    let node_spec = spec.node(node)?;
    let (request_document, _, _) = verify_request(spec, node, request_directory)?;
    let local_request: NodeEnrollmentRequest = serde_json::from_slice(&read_private_bounded(
        &private_root.join("private/enrollment-request.json"),
        MAX_FILE_BYTES,
    )?)
    .map_err(|_| "node-local enrollment request is malformed".to_string())?;
    if local_request != request_document {
        return Err("public enrollment request changed after node-local creation".into());
    }
    let trusted_ca_bytes = read_private_bounded(
        &private_root.join("private/trusted-ca.cert.pem"),
        MAX_FILE_BYTES,
    )?;
    if digest(&trusted_ca_bytes) != local_request.trusted_ca_certificate_sha256 {
        return Err("node-local trusted CA certificate changed after enrollment".into());
    }
    let response: NodeAuthorityResponse =
        read_json(&response_directory.join("authority-response.json"))?;
    if response.version != SPEC_VERSION
        || response.deployment_id != spec.deployment_id
        || response.node != node
        || response.csr_sha256 != request_document.csr_sha256
        || response.mpc_csr_sha256 != request_document.mpc_csr_sha256
        || response.ca_certificate_sha256 != local_request.trusted_ca_certificate_sha256
    {
        return Err("authority response belongs to another deployment or request".into());
    }
    verify_response_file(
        response_directory,
        "node.cert.pem",
        &response.node_certificate_sha256,
    )?;
    verify_response_file(
        response_directory,
        "ca.cert.pem",
        &response.ca_certificate_sha256,
    )?;
    verify_response_file(
        response_directory,
        "coordinator.cert.pem",
        &response.coordinator_certificate_sha256,
    )?;
    verify_response_file(
        response_directory,
        "client.cert.pem",
        &response.client_certificate_sha256,
    )?;
    verify_response_file(
        response_directory,
        "client-frame.key",
        &response.client_frame_key_sha256,
    )?;
    verify_response_file(
        response_directory,
        "kyb.json",
        &response.kyb_document_sha256,
    )?;
    let expected_peer_names = (0_u16..NODE_COUNT as u16)
        .map(|peer| format!("P{peer}.pem"))
        .collect::<BTreeSet<_>>();
    if response
        .mpc_peer_certificate_sha256
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected_peer_names
    {
        return Err(
            "authority response does not contain exactly seven MPC peer certificates".into(),
        );
    }
    for (name, digest) in &response.mpc_peer_certificate_sha256 {
        verify_response_file(
            response_directory,
            &format!("mpc-player-data/{name}"),
            digest,
        )?;
    }
    let ca = certificate(&response_directory.join("ca.cert.pem"))?;
    current_certificate(&ca, at, "offline CA certificate")?;
    verify_response_signature(&ca, &response)?;
    let ca_public = ca.public_key().map_err(|error| error.to_string())?;
    let node_certificate = certificate(&response_directory.join("node.cert.pem"))?;
    current_certificate(&node_certificate, at, "node certificate")?;
    let local_private = private_key(&private_root.join("private/node.key.pem"))?;
    if !node_certificate
        .public_key()
        .map_err(|error| error.to_string())?
        .public_eq(&local_private)
        || !node_certificate
            .verify(&ca_public)
            .map_err(|error| error.to_string())?
    {
        return Err("issued node certificate does not match the node-local key or CA".into());
    }
    let mpc_private = private_key(&private_root.join("private/mpc.key.pem"))?;
    let mut mpc_public_keys = BTreeSet::new();
    for peer in 0_u16..NODE_COUNT as u16 {
        let certificate = certificate(
            &response_directory
                .join("mpc-player-data")
                .join(format!("P{peer}.pem")),
        )?;
        current_certificate(&certificate, at, &format!("MPC peer {peer} certificate"))?;
        if !certificate
            .verify(&ca_public)
            .map_err(|error| error.to_string())?
        {
            return Err(format!(
                "MPC peer {peer} certificate is outside the pinned CA"
            ));
        }
        let public = certificate
            .public_key()
            .map_err(|error| error.to_string())?;
        let public_digest = digest(
            &public
                .public_key_to_der()
                .map_err(|error| error.to_string())?,
        );
        if !mpc_public_keys.insert(public_digest) {
            return Err("MPC peer certificates reuse a public key".into());
        }
        if peer == node && !public.public_eq(&mpc_private) {
            return Err("issued MPC certificate does not match the node-local MPC key".into());
        }
    }
    let coordinator_certificate = certificate(&response_directory.join("coordinator.cert.pem"))?;
    let client_certificate = certificate(&response_directory.join("client.cert.pem"))?;
    current_certificate(&coordinator_certificate, at, "coordinator certificate")?;
    current_certificate(&client_certificate, at, "client certificate")?;
    if !coordinator_certificate
        .verify(&ca_public)
        .map_err(|error| error.to_string())?
        || !client_certificate
            .verify(&ca_public)
            .map_err(|error| error.to_string())?
    {
        return Err("authority response contains a certificate outside the pinned CA".into());
    }
    let client_der = client_certificate
        .to_der()
        .map_err(|error| error.to_string())?;
    let kyb: KybDeploymentDocument = read_json(&response_directory.join("kyb.json"))?;
    if kyb.venue_scope != spec.venue_scope
        || kyb.client_certificate_fingerprint != certificate_fingerprint(&client_der)
    {
        return Err("KYB presentation is not bound to the approved client certificate".into());
    }
    let (registry, presentation, issuer) = decode_kyb(&kyb)?;
    verify_presentation(
        &presentation,
        &registry,
        &issuer,
        spec.venue_scope.as_bytes(),
        kyb.client_certificate_fingerprint.as_bytes(),
        at,
        &kyb.required_cohort,
    )
    .map_err(|error| format!("authority KYB presentation is invalid: {error:?}"))?;
    if presentation.proof.nullifier.compress().to_bytes()
        != fixed_hex(&kyb.scope_nullifier, "scope nullifier")?
    {
        return Err("KYB scope nullifier does not match its proof".into());
    }

    let pki = private_root.join("pki");
    create_directory(&pki)?;
    for name in [
        "node.cert.pem",
        "ca.cert.pem",
        "coordinator.cert.pem",
        "client.cert.pem",
    ] {
        copy_file(&response_directory.join(name), &pki.join(name), 0o644)?;
    }
    let player_data = private_root.join("mpc-player-data");
    create_directory(&player_data)?;
    copy_file(
        &private_root.join("private/mpc.key.pem"),
        &player_data.join(format!("P{node}.key")),
        0o600,
    )?;
    let mut subject_hashes = BTreeSet::new();
    for peer in 0_u16..NODE_COUNT as u16 {
        let name = format!("P{peer}.pem");
        let source = response_directory.join("mpc-player-data").join(&name);
        let target = player_data.join(&name);
        copy_file(&source, &target, 0o644)?;
        let peer_certificate = certificate(&source)?;
        let hash_name = format!("{:08x}.0", peer_certificate.subject_name_hash());
        if !subject_hashes.insert(hash_name.clone()) {
            return Err("MPC peer certificate subject hashes collide".into());
        }
        copy_file(&source, &player_data.join(hash_name), 0o644)?;
    }
    copy_file(
        &response_directory.join("client-frame.key"),
        &private_root.join("private/client-frame.key"),
        0o600,
    )?;
    copy_file(
        &response_directory.join("kyb.json"),
        &private_root.join("kyb.json"),
        0o644,
    )?;

    let node_config = json!({
        "node": node,
        "host": node_spec.bind_host,
        "port": node_spec.resident_port,
        "certificate": "pki/node.cert.pem",
        "private_key": "private/node.key.pem",
        "ca_certificate": "pki/ca.cert.pem",
        "database": node_spec.state_root.join("resident.sqlite3"),
        "program_registry": node_spec.program_registry,
        "idle_timeout_seconds": 30.0,
        "response_delay_ms": 0,
        "rate_limit": {
            "max_requests": 60,
            "max_probe_lots": 2_000,
            "max_epsilon": 1.0,
            "slots_per_epoch": 60
        },
        "sealing_keys": {
            "encrypted_store": "private/sealing-keys.qks",
            "passphrase_file": "private/sealing-store.passphrase",
            "admission_authority_key_id": request_document.admission_authority_key_id,
            "ordering_beacon_key_id": request_document.ordering_beacon_key_id,
            "node_receipt_key_id": request_document.node_receipt_key_id
        },
        "kyb": {
            "venue_scope": kyb.venue_scope,
            "required_cohort": kyb.required_cohort,
            "trusted_issuer": kyb.trusted_issuer,
            "registry": kyb.registry
        },
        "principals": [
            {"certificate_der":"pki/coordinator.cert.pem", "role":"coordinator"},
            {
                "certificate_der":"pki/client.cert.pem",
                "role":"client",
                "frame_key_file":"private/client-frame.key",
                "scope_nullifier":kyb.scope_nullifier,
                "kyb_presentation":kyb.presentation
            }
        ]
    });
    write_json(&private_root.join("node.json"), &node_config, 0o600)?;
    let proof_config = json!({
        "deployment_id": spec.deployment_id,
        "node": node,
        "host": node_spec.bind_host,
        "port": node_spec.proof_port,
        "certificate": "pki/node.cert.pem",
        "private_key": "private/node.key.pem",
        "ca_certificate": "pki/ca.cert.pem",
        "coordinator_certificate": "pki/coordinator.cert.pem",
        "allowed_root": node_spec.state_root,
        "state_file": node_spec.state_root.join("proof-state.qps"),
        "state_passphrase_file": "private/proof-state.passphrase",
        "n_mm": spec.n_mm,
        "n_parties": spec.n_parties,
        "threshold": spec.threshold,
        "amount_bits": spec.amount_bits,
        "price_bits": spec.price_bits,
        "remainder_bits": spec.remainder_bits,
        "complete_quote_proof": true,
        "quote_eligibility_bits": spec.quote_eligibility_bits,
        "quote_span_bits": spec.quote_span_bits,
        "trusted_defmi_receipt_public": spec.trusted_defmi_receipt_public,
        "allow_health_signing": false,
        "idle_timeout_seconds": 30
    });
    write_json(&private_root.join("proof-party.json"), &proof_config, 0o600)?;
    let deployment_manifest = json!({
        "version": SPEC_VERSION,
        "deployment_id": spec.deployment_id,
        "node": node,
        "organization_id": node_spec.organization_id,
        "host": node_spec.host,
        "node_tls_private_key_generated_locally": true,
        "mp_spdz_tls_private_key_generated_locally": true,
        "mp_spdz_foreign_private_keys_present": false,
        "mp_spdz_peer_certificates": NODE_COUNT,
        "authority_received_node_private_key": false,
        "frost_secret_share_created": false,
        "mp_spdz_secret_state_created": false,
        "complete_quote_proof_required": true,
        "approved_program_registry": node_spec.program_registry,
        "default_rule_documentation": DEFAULT_RULE,
        "authority_response_sha256": digest_file(&response_directory.join("authority-response.json"))?
    });
    write_json(
        &private_root.join("deployment-manifest.json"),
        &deployment_manifest,
        0o644,
    )?;
    Ok(())
}

fn verify_node_private_root(
    spec: &WanDeploymentSpec,
    node: u16,
    private_root: &Path,
) -> Result<PathBuf, String> {
    let root = fs::canonicalize(private_root).map_err(|error| error.to_string())?;
    let manifest: Value = read_json(&root.join("deployment-manifest.json"))?;
    if manifest.get("deployment_id").and_then(Value::as_str) != Some(spec.deployment_id.as_str())
        || manifest.get("node").and_then(Value::as_u64) != Some(u64::from(node))
        || manifest
            .get("mp_spdz_tls_private_key_generated_locally")
            .and_then(Value::as_bool)
            != Some(true)
        || manifest
            .get("mp_spdz_foreign_private_keys_present")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("node-private root is not the split-knowledge deployment for this node".into());
    }
    Ok(root)
}

/// Seal one organisation's already-distributed MP-SPDZ input shares. The
/// authority and coordinator never call this function and never receive the
/// clear bundle. Re-running is refused rather than rotating or replacing a
/// live policy state implicitly.
pub fn initialize_node_mpc_state(
    spec: &WanDeploymentSpec,
    node: u16,
    private_root: &Path,
    shares_file: &Path,
) -> Result<NodeMpcStateReceipt, String> {
    spec.validate(now()?)?;
    let node_spec = spec.node(node)?;
    let private_root = verify_node_private_root(spec, node, private_root)?;
    let source = build_program(&spec.mpc_program).map_err(|error| error.to_string())?;
    let source_sha256 = digest(source.as_bytes());
    let mut clear = read_private_bounded(shares_file, MAX_FILE_BYTES)?;
    let bundle: NodeMpcShareBundle = serde_json::from_slice(&clear)
        .map_err(|_| "node-local MPC share bundle is malformed".to_string())?;
    clear.fill(0);
    let state = MpcSecretState {
        version: bundle.version,
        node: bundle.node,
        generation: bundle.generation,
        source_sha256: bundle.source_sha256,
        dvp_input_shares: bundle.dvp_input_shares,
        policy_input_shares: bundle.policy_input_shares,
        quote_policy_blinding_input_shares: bundle.quote_policy_blinding_input_shares,
    };
    state.verify(node, &source_sha256, spec.n_mm)?;
    if state.generation == 0 {
        return Err("node-local MPC share generation must be positive".into());
    }
    create_directory(&node_spec.state_root)?;
    let passphrase_file = private_root.join("private/mpc-state.passphrase");
    let mut passphrase = read_private_secret(&passphrase_file)?;
    let encrypted_state = node_spec.state_root.join("mpc-state.qms");
    let store = EncryptedMpcStateStore::new(&encrypted_state, &passphrase)?;
    let initialized = store.initialize(&state);
    passphrase.fill(0);
    initialized?;
    let loaded = read_private_secret(&passphrase_file).and_then(|mut secret| {
        let result = EncryptedMpcStateStore::new(&encrypted_state, &secret)?.load();
        secret.fill(0);
        result
    })?;
    if loaded != state {
        return Err("encrypted MPC state failed its immediate read-back check".into());
    }
    let receipt = NodeMpcStateReceipt {
        version: SPEC_VERSION,
        deployment_id: spec.deployment_id.clone(),
        node,
        generation: state.generation,
        source_sha256,
        encrypted_state: encrypted_state.clone(),
        encrypted_state_sha256: digest_runtime_file(&encrypted_state, false)?,
    };
    write_json(
        &private_root.join("mpc-state-manifest.json"),
        &receipt,
        0o600,
    )?;
    Ok(receipt)
}

fn compiled_program_artifacts(
    root: &Path,
    program: &str,
) -> Result<BTreeMap<String, String>, String> {
    let mut files = vec![
        format!("Programs/Source/{program}.mpc"),
        format!("Programs/Schedules/{program}.sch"),
    ];
    let bytecode = root.join("Programs/Bytecode");
    for entry in fs::read_dir(&bytecode).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(&format!("{program}-")) && name.ends_with(".bc") {
            files.push(format!("Programs/Bytecode/{name}"));
        }
    }
    files.sort();
    if files.len() < 3 {
        return Err("official MP-SPDZ compilation emitted no bytecode tape".into());
    }
    files
        .into_iter()
        .map(|relative| {
            digest_runtime_file(&root.join(&relative), false).map(|sha256| (relative, sha256))
        })
        .collect()
}

fn node_player_data_artifacts(
    directory: &Path,
    node: u16,
) -> Result<BTreeMap<String, String>, String> {
    let expected_certificates = (0_u16..NODE_COUNT as u16)
        .map(|peer| format!("P{peer}.pem"))
        .collect::<BTreeSet<_>>();
    let own_key = format!("P{node}.key");
    let mut certificates = BTreeSet::new();
    let mut private_keys = BTreeSet::new();
    let mut subject_links = BTreeSet::new();
    let mut artifacts = BTreeMap::new();
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('P') && name.ends_with(".pem") {
            certificates.insert(name.clone());
        } else if name.starts_with('P') && name.ends_with(".key") {
            private_keys.insert(name.clone());
        } else if name.len() == 10
            && name.ends_with(".0")
            && name[..8].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            subject_links.insert(name.clone());
        } else {
            return Err(format!(
                "MP-SPDZ Player-Data contains an unapproved entry {name}"
            ));
        }
        artifacts.insert(
            name.clone(),
            digest_runtime_file(&directory.join(&name), false)?,
        );
    }
    if certificates != expected_certificates
        || private_keys != BTreeSet::from([own_key.clone()])
        || subject_links.len() != NODE_COUNT
    {
        return Err(format!(
            "MP-SPDZ Player-Data must contain seven peer certificates, seven subject links and only {own_key}"
        ));
    }
    let key_mode = fs::metadata(directory.join(&own_key))
        .map_err(|error| error.to_string())?
        .permissions()
        .mode()
        & 0o777;
    if key_mode != 0o600 {
        return Err("node-local MP-SPDZ private key must use mode 600".into());
    }
    Ok(artifacts)
}

fn reject_checkout_transport_keys(root: &Path) -> Result<(), String> {
    let player_data = root.join("Player-Data");
    if !player_data.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(&player_data).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".key") {
            return Err(format!(
                "MP-SPDZ checkout contains transport private key {name}; WAN keys must exist only in the node-local Player-Data directory"
            ));
        }
    }
    Ok(())
}

/// Compile and bind the exact Rust-generated circuit to one node-local stock
/// MP-SPDZ runtime. Only the upstream compiler is invoked; orchestration,
/// manifests and launchers remain Rust-owned. Every executable, library,
/// certificate, circuit artifact and configuration byte is hashed before the
/// approved registry is accepted.
pub fn prepare_node_mpc_runtime(
    spec: &WanDeploymentSpec,
    node: u16,
    private_root: &Path,
    mp_spdz_root: &Path,
    qomm_node_party: &Path,
) -> Result<NodeMpcRuntimeReceipt, String> {
    spec.validate(now()?)?;
    let node_spec = spec.node(node)?;
    let private_root = verify_node_private_root(spec, node, private_root)?;
    let source = build_program(&spec.mpc_program).map_err(|error| error.to_string())?;
    let source_sha256 = digest(source.as_bytes());
    let program = format!("qomm_resident_{}", &source_sha256[..16]);
    let shape = vec![
        spec.mpc_program.n_mm as u64,
        spec.mpc_program.n_parties as u64,
        u64::from(spec.mpc_program.bit_length),
    ];

    create_directory(&node_spec.state_root)?;
    let runtime_root = node_spec.state_root.join("mpc-runtime");
    if runtime_root.exists() || fs::symlink_metadata(&runtime_root).is_ok() {
        return Err(format!("refusing to overwrite {}", runtime_root.display()));
    }
    let registry_parent = node_spec
        .program_registry
        .parent()
        .ok_or_else(|| "approved program registry has no parent".to_string())?;
    create_directory(registry_parent)?;
    let rule_name = format!("approved-policy-{}.dsl", &source_sha256[..16]);
    let source_name = format!("approved-program-{}.mpc", &source_sha256[..16]);
    for target in [
        node_spec.program_registry.as_path(),
        &registry_parent.join(&rule_name),
        &registry_parent.join(&source_name),
        &private_root.join("mpc-runtime-manifest.json"),
    ] {
        if target.exists() || fs::symlink_metadata(target).is_ok() {
            return Err(format!("refusing to overwrite {}", target.display()));
        }
    }

    let passphrase_file = fs::canonicalize(private_root.join("private/mpc-state.passphrase"))
        .map_err(|error| error.to_string())?;
    let state_store = fs::canonicalize(node_spec.state_root.join("mpc-state.qms"))
        .map_err(|error| error.to_string())?;
    let mut passphrase = read_private_secret(&passphrase_file)?;
    let state = EncryptedMpcStateStore::new(&state_store, &passphrase)?.load()?;
    passphrase.fill(0);
    state.verify(node, &source_sha256, spec.n_mm)?;

    let mp_spdz_root = fs::canonicalize(mp_spdz_root).map_err(|error| error.to_string())?;
    reject_checkout_transport_keys(&mp_spdz_root)?;
    let compiler =
        OfficialCompiler::from_checkout(&mp_spdz_root).map_err(|error| error.to_string())?;
    let source_path = mp_spdz_root
        .join("Programs/Source")
        .join(format!("{program}.mpc"));
    write_or_verify_file(&source_path, source.as_bytes(), 0o644)?;
    let compiled = compiler
        .compile_field(253, &program)
        .map_err(|error| error.to_string())?;
    if !compiled.status.success() {
        return Err(format!(
            "official MP-SPDZ compiler failed (exit_code={}, stdout_sha256={}, stderr_sha256={})",
            compiled.status.code().unwrap_or(-1),
            digest(&compiled.stdout),
            digest(&compiled.stderr)
        ));
    }
    let program_artifacts = compiled_program_artifacts(&mp_spdz_root, &program)?;
    let party_binary = fs::canonicalize(mp_spdz_root.join("malicious-shamir-party.x"))
        .map_err(|error| error.to_string())?;
    let library =
        fs::canonicalize(mp_spdz_root.join("libSPDZ.so")).map_err(|error| error.to_string())?;
    let qomm_node_party = fs::canonicalize(qomm_node_party).map_err(|error| error.to_string())?;
    let party_binary_sha256 = digest_runtime_file(&party_binary, true)?;
    let library_sha256 = digest_runtime_file(&library, false)?;
    let qomm_node_party_sha256 = digest_runtime_file(&qomm_node_party, true)?;
    let player_data_root = fs::canonicalize(private_root.join("mpc-player-data"))
        .map_err(|error| error.to_string())?;
    let player_data_artifacts = node_player_data_artifacts(&player_data_root, node)?;

    prepare_new_directory(&runtime_root)?;
    let runtime_root = fs::canonicalize(runtime_root).map_err(|error| error.to_string())?;
    let run_root = node_spec.state_root.join("mpc-runs");
    create_directory(&run_root)?;
    let run_root = fs::canonicalize(run_root).map_err(|error| error.to_string())?;
    let host_file = runtime_root.join("qomm-mpc-hosts");
    let hosts = spec
        .nodes
        .iter()
        .map(|peer| format!("{}:{}\n", peer.host, peer.mpc_port))
        .collect::<String>();
    write_file(&host_file, hosts.as_bytes(), 0o600)?;
    let host_file_sha256 = digest_file(&host_file)?;

    let runtime_config_path = runtime_root.join("resident-mpc.json");
    let runtime_config = ResidentMpcConfig {
        version: 1,
        node,
        n_parties: spec.n_parties as u16,
        threshold: spec.threshold as u16,
        n_mm: spec.n_mm,
        mp_spdz_root: mp_spdz_root.clone(),
        player_data_root,
        run_root,
        program: program.clone(),
        source_sha256: source_sha256.clone(),
        host_file: host_file.clone(),
        host_file_sha256,
        party_binary,
        party_binary_sha256,
        library,
        library_sha256,
        player_data_artifacts,
        program_artifacts,
        state_store,
        passphrase_file,
        prime: ED25519_ORDER.into(),
        timeout_seconds: 120.0,
    };
    write_json(&runtime_config_path, &runtime_config, 0o600)?;
    runtime_config.verify(&source_sha256)?;
    let runtime_config_sha256 = digest_file(&runtime_config_path)?;
    let runtime = RuntimeBinding {
        executable: qomm_node_party,
        executable_sha256: qomm_node_party_sha256,
        config: runtime_config_path.clone(),
        config_sha256: runtime_config_sha256.clone(),
    };
    let launcher = runtime_root.join("approved-compute");
    write_source_bound_runtime_executable(&launcher, &source, &runtime)?;
    let launcher = fs::canonicalize(launcher).map_err(|error| error.to_string())?;
    let launcher_sha256 = digest_file(&launcher)?;

    let rule_path = registry_parent.join(&rule_name);
    let approved_source_path = registry_parent.join(&source_name);
    write_file(
        &rule_path,
        policy_rule_source(&spec.mpc_program).as_bytes(),
        0o600,
    )?;
    write_file(&approved_source_path, source.as_bytes(), 0o600)?;
    let registry = json!({
        "programs": [{
            "shape_digest": circuit_shape_digest(&shape),
            "argv": [
                launcher.display().to_string(),
                "{node}",
                "{slot}",
                "{batch_digest}",
                "{lane}"
            ],
            "cwd": runtime_root,
            "executable_sha256": launcher_sha256,
            "runtime": {
                "executable": runtime.executable,
                "executable_sha256": runtime.executable_sha256,
                "config": runtime.config,
                "config_sha256": runtime.config_sha256
            },
            "timeout_seconds": 180.0
        }],
        "approval": {
            "name": POLICY_RULE_NAME,
            "rule_source_file": rule_name,
            "program_source_file": source_name,
            "shape": shape,
            "program_config": spec.mpc_program
        }
    });
    write_json(&node_spec.program_registry, &registry, 0o600)?;
    ProgramRegistry::from_json(node, &node_spec.program_registry)?;
    let receipt = NodeMpcRuntimeReceipt {
        version: SPEC_VERSION,
        deployment_id: spec.deployment_id.clone(),
        node,
        program,
        source_sha256,
        runtime_config: runtime_config_path,
        runtime_config_sha256,
        launcher,
        launcher_sha256,
        program_registry: node_spec.program_registry.clone(),
        program_registry_sha256: digest_file(&node_spec.program_registry)?,
        public_peer_certificates: NODE_COUNT,
        local_private_keys: 1,
    };
    write_json(
        &private_root.join("mpc-runtime-manifest.json"),
        &receipt,
        0o600,
    )?;
    sync_directory(&runtime_root)?;
    sync_directory(registry_parent)?;
    Ok(receipt)
}

pub fn write_example_spec(path: &Path, receipt_public: &VerifyingKey) -> Result<(), String> {
    let expires = now()?.saturating_add(365 * 24 * 3600);
    let spec = WanDeploymentSpec {
        version: SPEC_VERSION,
        deployment_id: "qomm-pilot-2026-01".into(),
        venue_scope: "QOMM/venue-A/KYB".into(),
        jurisdiction: "JP".into(),
        entity_type: "regulated-dealer".into(),
        minimum_collateral_tier: 2,
        maximum_collateral_tier: 5,
        registry_epoch: 1,
        registry_expires_at: expires,
        ca_lifetime_days: 3650,
        certificate_lifetime_days: 30,
        coordinator_common_name: "qomm-coordinator".into(),
        client_common_name: "qomm-operator-client".into(),
        client_control_group_id: "replace-with-governance-pseudonym".into(),
        trusted_defmi_receipt_public: hex::encode(receipt_public.as_bytes()),
        n_mm: 4,
        n_parties: NODE_COUNT,
        threshold: 2,
        amount_bits: 16,
        price_bits: 32,
        remainder_bits: 32,
        quote_eligibility_bits: 34,
        quote_span_bits: 32,
        mpc_program: ProgramConfig {
            n_mm: 4,
            n_parties: NODE_COUNT,
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
        nodes: (0_u16..NODE_COUNT as u16)
            .map(|node| WanNodeSpec {
                node,
                organization_id: format!("org-{node}"),
                host: format!("qomm-node-{node}.example.net"),
                bind_host: "0.0.0.0".into(),
                resident_port: 9443,
                proof_port: 9543,
                mpc_port: 9643,
                state_root: PathBuf::from(format!("/var/lib/qomm/node-{node}")),
                program_registry: PathBuf::from(format!(
                    "/etc/qomm/node-{node}/approved-programs.json"
                )),
                restart_argv: vec![
                    "/usr/bin/systemctl".into(),
                    "restart".into(),
                    format!("qomm-node@{node}"),
                ],
                restart_proof_argv: vec![
                    "/usr/bin/systemctl".into(),
                    "restart".into(),
                    format!("qomm-proof-party@{node}"),
                ],
            })
            .collect(),
    };
    write_json(path, &spec, 0o644)
}

/// fsync a provisioning root after a caller has transferred or archived it.
pub fn sync_directory(path: &Path) -> Result<(), String> {
    let directory = File::open(path).map_err(|error| error.to_string())?;
    if directory
        .metadata()
        .map_err(|error| error.to_string())?
        .is_dir()
    {
        // SAFETY: fsync receives a live descriptor for this directory.
        if unsafe { libc::fsync(directory.as_raw_fd()) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    } else {
        Err("provisioning root is not a directory".into())
    }
}
