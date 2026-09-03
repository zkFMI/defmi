//! Run one durable QOMM computing-node endpoint from a deployment config.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, VerifyingKey};
use openssl::x509::X509;
use qomm_proofs::kyb::{EntityLimits, KybPresentation, SignedCohortRegistry};
use qomm_transport::executor::ProgramRegistry;
use qomm_transport::key_management::EncryptedKeyStore;
use qomm_transport::node_service::{
    certificate_fingerprint, server_ssl_context, KybPolicy, NodeSealingKeys, NodeStore, Principal,
    RateLimitPolicy, ResidentNodeServer,
};
use qomm_zk::or_dleq::Proof;
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn request_stop(_: libc::c_int) {
    STOP.store(true, Ordering::Release);
}

#[derive(Deserialize)]
struct Config {
    node: u16,
    host: String,
    port: u16,
    certificate: PathBuf,
    private_key: PathBuf,
    ca_certificate: PathBuf,
    database: PathBuf,
    program_registry: PathBuf,
    principals: Vec<PrincipalRow>,
    idle_timeout_seconds: Option<f64>,
    response_delay_ms: Option<u64>,
    rate_limit: Option<RateLimitRow>,
    kyb: KybPolicyRow,
    sealing_keys: SealingKeysRow,
}

#[derive(Deserialize)]
struct SealingKeysRow {
    encrypted_store: PathBuf,
    passphrase_file: PathBuf,
    admission_authority_key_id: String,
    ordering_beacon_key_id: String,
    node_receipt_key_id: String,
}

#[derive(Deserialize)]
struct PrincipalRow {
    role: String,
    certificate_der: PathBuf,
    frame_key_file: Option<PathBuf>,
    scope_nullifier: Option<String>,
    kyb_presentation: Option<KybPresentationRow>,
}

#[derive(Deserialize)]
struct KybPolicyRow {
    venue_scope: String,
    required_cohort: String,
    trusted_issuer: String,
    registry: KybRegistryRow,
}

#[derive(Deserialize)]
struct KybRegistryRow {
    cohort: String,
    registry_epoch: u64,
    expires_at: u64,
    points: Vec<String>,
    issuer: String,
    registry_id: String,
    signature: String,
}

#[derive(Deserialize)]
struct KybPresentationRow {
    cohort: String,
    registry_id: String,
    scope: String,
    context_hash: String,
    nullifier: String,
    challenges: Vec<String>,
    responses: Vec<String>,
}

#[derive(Deserialize)]
struct RateLimitRow {
    max_requests: Option<u64>,
    max_probe_lots: Option<u64>,
    max_epsilon: Option<f64>,
    slots_per_epoch: Option<u32>,
}

fn resolve(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn certificate_der(path: &Path) -> Result<Vec<u8>, String> {
    let raw = fs::read(path).map_err(|error| error.to_string())?;
    let certificate = X509::from_der(&raw)
        .or_else(|_| X509::from_pem(&raw))
        .map_err(|error| error.to_string())?;
    certificate.to_der().map_err(|error| error.to_string())
}

fn frame_key(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = path.metadata().map_err(|error| error.to_string())?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!("frame key {} must use mode 600", path.display()));
    }
    let value = fs::read(path).map_err(|error| error.to_string())?;
    if value.len() != 32 {
        return Err("frame key file must contain exactly 32 raw bytes".into());
    }
    Ok(value)
}

fn protected_secret(path: &Path, name: &str) -> Result<Vec<u8>, String> {
    let metadata = path.metadata().map_err(|error| error.to_string())?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!("{name} {} must use mode 600", path.display()));
    }
    let mut value = fs::read(path).map_err(|error| error.to_string())?;
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        value.pop();
    }
    if value.is_empty() {
        return Err(format!("{name} is empty"));
    }
    Ok(value)
}

fn fixed_hex<const N: usize>(value: &str, name: &str) -> Result<[u8; N], String> {
    hex::decode(value)
        .map_err(|_| format!("{name} must be {N}-byte hexadecimal"))?
        .try_into()
        .map_err(|_| format!("{name} must be {N}-byte hexadecimal"))
}

fn point(value: &str, name: &str) -> Result<RistrettoPoint, String> {
    CompressedRistretto(fixed_hex(value, name)?)
        .decompress()
        .ok_or_else(|| format!("{name} is not a canonical Ristretto point"))
}

fn scalar(value: &str, name: &str) -> Result<Scalar, String> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(fixed_hex(value, name)?))
        .ok_or_else(|| format!("{name} is not a canonical scalar"))
}

impl KybRegistryRow {
    fn decode(&self) -> Result<SignedCohortRegistry, String> {
        let issuer = VerifyingKey::from_bytes(&fixed_hex(&self.issuer, "KYB registry issuer")?)
            .map_err(|_| "KYB registry issuer is not an Ed25519 key".to_string())?;
        let signature = Signature::from_slice(
            &hex::decode(&self.signature)
                .map_err(|_| "KYB registry signature must be hexadecimal".to_string())?,
        )
        .map_err(|_| "KYB registry signature must contain 64 bytes".to_string())?;
        Ok(SignedCohortRegistry {
            cohort: self.cohort.clone(),
            registry_epoch: self.registry_epoch,
            expires_at: self.expires_at,
            points: self
                .points
                .iter()
                .enumerate()
                .map(|(index, value)| point(value, &format!("KYB registry point {index}")))
                .collect::<Result<Vec<_>, _>>()?,
            issuer,
            registry_id: fixed_hex(&self.registry_id, "KYB registry id")?,
            signature,
        })
    }
}

impl KybPresentationRow {
    fn decode(&self) -> Result<KybPresentation, String> {
        Ok(KybPresentation {
            cohort: self.cohort.clone(),
            registry_id: fixed_hex(&self.registry_id, "KYB presentation registry id")?,
            scope: self.scope.as_bytes().to_vec(),
            context_hash: fixed_hex(&self.context_hash, "KYB presentation context hash")?,
            proof: Proof {
                nullifier: point(&self.nullifier, "KYB presentation nullifier")?,
                challenges: self
                    .challenges
                    .iter()
                    .enumerate()
                    .map(|(index, value)| {
                        scalar(value, &format!("KYB presentation challenge {index}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                responses: self
                    .responses
                    .iter()
                    .enumerate()
                    .map(|(index, value)| {
                        scalar(value, &format!("KYB presentation response {index}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            },
        })
    }
}

fn run(config_path: &Path) -> Result<(), String> {
    let config: Config =
        serde_json::from_slice(&fs::read(config_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));
    let sealing_store_path = resolve(base, &config.sealing_keys.encrypted_store);
    let passphrase = protected_secret(
        &resolve(base, &config.sealing_keys.passphrase_file),
        "sealing key-store passphrase file",
    )?;
    let sealing_store = EncryptedKeyStore::new(sealing_store_path, &passphrase)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_string())?
        .as_secs();
    let slot_keys = NodeSealingKeys::from_encrypted_store(
        &sealing_store,
        &config.sealing_keys.admission_authority_key_id,
        &config.sealing_keys.ordering_beacon_key_id,
        &config.sealing_keys.node_receipt_key_id,
        now,
    )?;
    let trusted_issuer = VerifyingKey::from_bytes(&fixed_hex(
        &config.kyb.trusted_issuer,
        "trusted KYB issuer",
    )?)
    .map_err(|_| "trusted KYB issuer is not an Ed25519 key".to_string())?;
    let kyb_policy = Arc::new(KybPolicy::new(
        config.kyb.venue_scope.as_bytes().to_vec(),
        config.kyb.required_cohort.clone(),
        config.kyb.registry.decode()?,
        trusted_issuer,
    )?);
    let mut principals = std::collections::BTreeMap::new();
    for row in config.principals {
        let certificate = resolve(base, &row.certificate_der);
        let fingerprint = certificate_fingerprint(&certificate_der(&certificate)?);
        let principal = match row.role.as_str() {
            "client" => {
                let key_file = row
                    .frame_key_file
                    .as_deref()
                    .ok_or_else(|| "client principal has no frame_key_file".to_string())?;
                let nullifier = point(
                    row.scope_nullifier.as_deref().ok_or_else(|| {
                        "client principal has no proved scope_nullifier".to_string()
                    })?,
                    "scope_nullifier",
                )?;
                let presentation = row
                    .kyb_presentation
                    .as_ref()
                    .ok_or_else(|| "client principal has no KYB presentation".to_string())?
                    .decode()?;
                Principal::client(
                    frame_key(&resolve(base, key_file))?,
                    &nullifier,
                    presentation,
                )?
            }
            "coordinator" => Principal::coordinator(),
            "observer" => Principal::observer(),
            _ => return Err("unknown node-service role".into()),
        };
        if principals.insert(fingerprint, principal).is_some() {
            return Err("duplicate principal certificate".into());
        }
    }
    let registry = Arc::new(ProgramRegistry::from_json(
        config.node,
        resolve(base, &config.program_registry),
    )?);
    let store = Arc::new(NodeStore::open(resolve(base, &config.database))?);
    let defaults = EntityLimits::default();
    let row = config.rate_limit;
    let rate_policy = RateLimitPolicy {
        limits: EntityLimits {
            max_requests: row
                .as_ref()
                .and_then(|value| value.max_requests)
                .unwrap_or(defaults.max_requests),
            max_probe_lots: row
                .as_ref()
                .and_then(|value| value.max_probe_lots)
                .unwrap_or(defaults.max_probe_lots),
            max_epsilon: row
                .as_ref()
                .and_then(|value| value.max_epsilon)
                .unwrap_or(defaults.max_epsilon),
        },
        slots_per_epoch: row
            .as_ref()
            .and_then(|value| value.slots_per_epoch)
            .unwrap_or(60),
    };
    let mut server = ResidentNodeServer::new(
        config.node,
        config.host.clone(),
        config.port,
        server_ssl_context(
            resolve(base, &config.certificate),
            resolve(base, &config.private_key),
            resolve(base, &config.ca_certificate),
        )?,
        principals,
        Some(kyb_policy),
        slot_keys,
        store,
        Some(registry),
        rate_policy,
        Duration::from_secs_f64(config.idle_timeout_seconds.unwrap_or(30.0)),
        Duration::from_millis(config.response_delay_ms.unwrap_or(0)),
    )?;
    let port = server.start()?;
    // SAFETY: handlers only set one lock-free atomic flag.
    unsafe {
        libc::signal(
            libc::SIGINT,
            request_stop as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            request_stop as *const () as libc::sighandler_t,
        );
    }
    println!(
        "{}",
        json!({
            "status": "ready",
            "node": config.node,
            "host": config.host,
            "port": port,
        })
    );
    while !STOP.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(100));
    }
    server.stop();
    Ok(())
}

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let Some(position) = arguments.iter().position(|argument| argument == "--config") else {
        eprintln!("usage: serve_node --config PATH");
        std::process::exit(2);
    };
    let Some(path) = arguments.get(position + 1) else {
        eprintln!("--config requires a path");
        std::process::exit(2);
    };
    if let Err(error) = run(Path::new(path)) {
        eprintln!("serve_node failed: {error}");
        std::process::exit(1);
    }
}
