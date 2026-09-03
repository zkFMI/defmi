use ed25519_dalek::SigningKey;
use qomm_transport::external_signer::{
    CommandEd25519Signer, Ed25519MessageSigner, ExternalSignRequest, MAX_EXTERNAL_SIGN_MESSAGE,
    MAX_EXTERNAL_SIGN_REQUEST,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

fn key(label: &str) -> SigningKey {
    SigningKey::from_bytes(&Sha256::digest(label.as_bytes()).into())
}

#[test]
fn maximum_message_serializes_within_the_helper_request_bound() {
    let request = ExternalSignRequest::new("key-1", &vec![7; MAX_EXTERNAL_SIGN_MESSAGE]).unwrap();
    let encoded = serde_json::to_vec(&request).unwrap();
    assert!(encoded.len() as u64 <= MAX_EXTERNAL_SIGN_REQUEST);
}

#[test]
fn timeout_also_covers_a_signer_that_never_reads_stdin() {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("blocked-signer");
    fs::write(&executable, b"#!/bin/sh\nexec sleep 5\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let signer = CommandEd25519Signer::new(
        executable,
        Vec::new(),
        "key-1",
        key("blocked-signer-key").verifying_key(),
        Duration::from_millis(25),
    )
    .unwrap();
    let started = Instant::now();
    let error = signer
        .sign_message(&vec![7; MAX_EXTERNAL_SIGN_MESSAGE])
        .unwrap_err();
    assert!(error.contains("timed out"), "unexpected error: {error}");
    assert!(started.elapsed() < Duration::from_secs(2));
}
