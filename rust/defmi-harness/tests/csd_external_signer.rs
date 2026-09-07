use ed25519_dalek::VerifyingKey;
use qomm_transport::external_signer::{
    CommandCsdSigner, CommandEd25519Signer, CsdMessageSigner, Ed25519MessageSigner,
};
use qomm_transport::key_management::EncryptedKeyStore;
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn command_arguments(store: &Path, pin: &Path, key_id: &str) -> Vec<String> {
    vec![
        "--store".into(),
        store.display().to_string(),
        "--pin-file".into(),
        pin.display().to_string(),
        "--key-id".into(),
        key_id.into(),
    ]
}

#[test]
fn external_csd_authority_restores_both_keys_and_rejects_revoked_pq_key() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".artifacts")
        .join(format!("csd-signer-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let directory = Directory(root);
    let pin = directory.0.join("pin");
    // Test-only PIN. No key material is returned by the child process.
    let pin_bytes = b"csd-process-test-only-pin-0123456789";
    fs::write(&pin, pin_bytes).unwrap();
    fs::set_permissions(&pin, fs::Permissions::from_mode(0o600)).unwrap();
    let store = directory.0.join("authority.keys");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_zkpi-hsm-signer"));
    let initialized = Command::new(&executable)
        .args(["--initialize", "--purpose", "csd-issuance"])
        .arg("--store")
        .arg(&store)
        .arg("--pin-file")
        .arg(&pin)
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "authority initialization failed"
    );
    let metadata: Value = serde_json::from_slice(&initialized.stdout).unwrap();
    assert_eq!(metadata["hardware_backed"], false);
    assert_eq!(metadata["private_key_exported_to_caller"], false);
    let classical_id = metadata["key_id"].as_str().unwrap();
    let pq_id = metadata["pq_key_id"].as_str().unwrap();
    assert_ne!(classical_id, pq_id);
    let classical_public: [u8; 32] = hex::decode(metadata["public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let pq_public = hex::decode(metadata["pq_public_key"].as_str().unwrap()).unwrap();
    let classical_public = VerifyingKey::from_bytes(&classical_public).unwrap();
    let make_signer = |pq_public| {
        CommandCsdSigner::new(
            CommandEd25519Signer::new(
                &executable,
                command_arguments(&store, &pin, classical_id),
                classical_id,
                classical_public,
                Duration::from_secs(5),
            )
            .unwrap(),
            command_arguments(&store, &pin, pq_id),
            pq_id.into(),
            pq_public,
        )
        .unwrap()
    };
    let signer = make_signer(pq_public);
    let message = b"QOMM:DEFMI:CSD-EXTERNAL-ACCEPTANCE:v2";
    let signature = signer.sign_message(message).unwrap();
    classical_public.verify_strict(message, &signature).unwrap();
    let pq_signature = signer.sign_pq_message(message).unwrap();
    assert_eq!(pq_signature.len(), 3309);
    assert_eq!(signer.sign_pq_message(message).unwrap().len(), 3309);
    // A wrong pin at the application boundary must reject even though the real
    // helper successfully signs using its separately stored private key.
    let mut wrong_public = signer.pq_public_key();
    wrong_public[0] ^= 1;
    assert!(make_signer(wrong_public).sign_pq_message(message).is_err());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    EncryptedKeyStore::new(&store, pin_bytes)
        .unwrap()
        .revoke(pq_id, now, "acceptance rotation")
        .unwrap();
    assert!(signer.sign_pq_message(message).is_err());
    // Revocation of the PQ half is not masked by the still-working Ed25519 half.
    assert!(signer.sign_message(message).is_ok());
}
