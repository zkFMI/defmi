//! Acceptance implementation of the external HSM/KMS signing protocol.
//!
//! Only this helper decrypts the signing key. The caller receives a public key
//! and signatures, never private bytes. Production points the same client at a
//! PKCS#11/KMS-backed helper and must report `hardware_backed=true`; this
//! executable intentionally reports false so acceptance evidence cannot be
//! mistaken for a physical HSM test.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::Signer;
use qomm_transport::external_signer::{
    ExternalSignRequest, ExternalSignResponse, MAX_EXTERNAL_SIGN_REQUEST,
};
use qomm_transport::key_management::{EncryptedKeyStore, KeyKind};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn required(arguments: &[String], name: &str) -> Result<String, String> {
    arguments
        .iter()
        .position(|argument| argument == name)
        .and_then(|position| arguments.get(position + 1))
        .cloned()
        .ok_or_else(|| format!("{name} is required"))
}

fn read_pin(path: &Path) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("HSM PIN input could not be opened safely: {error}"))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || !(16..=4096).contains(&(metadata.len() as usize))
    {
        return Err("HSM PIN input must be a private bounded regular file".into());
    }
    let mut pin = Vec::with_capacity(metadata.len() as usize);
    file.take(4097)
        .read_to_end(&mut pin)
        .map_err(|error| error.to_string())?;
    if pin.len() as u64 != metadata.len() {
        return Err("HSM PIN input changed while it was being read".into());
    }
    while pin.last().is_some_and(|byte| matches!(byte, b'\r' | b'\n')) {
        pin.pop();
    }
    if pin.len() < 16 {
        return Err("HSM PIN is too short".into());
    }
    Ok(pin)
}

fn initialize(store_path: PathBuf, pin_path: PathBuf, purpose: String) -> Result<(), String> {
    let mut pin = read_pin(&pin_path)?;
    let store = EncryptedKeyStore::new(store_path, &pin)?;
    store.initialize()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    let key_id = store.generate(&purpose, KeyKind::Ed25519, now, 31_536_000, BTreeMap::new())?;
    let pq_key_id = store.generate(
        &format!("{purpose}:pq"),
        KeyKind::MlDsa65,
        now,
        31_536_000,
        BTreeMap::new(),
    )?;
    let snapshot = store.snapshot()?;
    let record = snapshot
        .keys
        .iter()
        .find(|record| record.key_id == key_id)
        .ok_or_else(|| "initialized signer key is absent".to_string())?;
    let public = BASE64
        .decode(&record.public)
        .map_err(|_| "initialized signer public key is malformed".to_string())?;
    let pq_record = snapshot
        .keys
        .iter()
        .find(|record| record.key_id == pq_key_id)
        .ok_or_else(|| "initialized PQ signer key is absent".to_string())?;
    let pq_public = BASE64
        .decode(&pq_record.public)
        .map_err(|_| "initialized PQ public key is malformed".to_string())?;
    pin.fill(0);
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "key_id": key_id,
            "pq_key_id": pq_key_id,
            "pq_public_key": hex::encode(pq_public),
            "public_key": hex::encode(public),
            "backend": "process-isolated-encrypted-key-emulator",
            "private_key_exported_to_caller": false,
            "hardware_backed": false,
        }))
        .map_err(|error| error.to_string())?
    );
    Ok(())
}

fn sign(store_path: PathBuf, pin_path: PathBuf, expected_key_id: String) -> Result<(), String> {
    let mut request_bytes = Vec::new();
    std::io::stdin()
        .take(MAX_EXTERNAL_SIGN_REQUEST + 1)
        .read_to_end(&mut request_bytes)
        .map_err(|error| error.to_string())?;
    if request_bytes.is_empty() || request_bytes.len() as u64 > MAX_EXTERNAL_SIGN_REQUEST {
        return Err("HSM signing request exceeds its bound".into());
    }
    let request: ExternalSignRequest = serde_json::from_slice(&request_bytes)
        .map_err(|_| "HSM signing request is malformed".to_string())?;
    if request.key_id != expected_key_id {
        return Err("HSM signing request names another key".into());
    }
    let message = if request.version == 2 {
        request.decode_pq_message()?
    } else {
        request.decode_message()?
    };
    let mut pin = read_pin(&pin_path)?;
    let store = EncryptedKeyStore::new(store_path, &pin)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    let key = store.private_key(&expected_key_id, now, false)?;
    let response = if request.version == 2 {
        use zkfmi_crypto::traits::Signer as _;
        let pq = key
            .ml_dsa65()
            .ok_or_else(|| "HSM key is not ML-DSA-65".to_string())?;
        let signature = pq
            .sign(zkfmi_crypto::key::KeyPurpose::Attestation, &message)
            .map_err(|error| error.to_string())?;
        ExternalSignResponse::new_pq(&expected_key_id, &signature)?
    } else {
        let classical = key
            .ed25519()
            .ok_or_else(|| "HSM key is not Ed25519".to_string())?;
        ExternalSignResponse::new(&expected_key_id, &classical.sign(&message))
    };
    pin.fill(0);
    let encoded = serde_json::to_vec(&response).map_err(|error| error.to_string())?;
    std::io::stdout()
        .write_all(&encoded)
        .map_err(|error| error.to_string())
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let store = PathBuf::from(required(&arguments, "--store")?);
    let pin = PathBuf::from(required(&arguments, "--pin-file")?);
    if arguments.iter().any(|argument| argument == "--initialize") {
        return initialize(store, pin, required(&arguments, "--purpose")?);
    }
    if arguments.iter().any(|argument| argument == "--sign") {
        return sign(store, pin, required(&arguments, "--key-id")?);
    }
    Err("either --initialize or --sign is required".into())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("external signing helper failed: {error}");
        std::process::exit(1);
    }
}
