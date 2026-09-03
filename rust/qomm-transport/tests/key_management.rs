use qomm_transport::key_management::{
    create_ca, issue_mutual_tls_certificate, write_tls_bundle, EncryptedKeyStore, KeyKind,
};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn store(directory: &tempfile::TempDir) -> EncryptedKeyStore {
    let vault = EncryptedKeyStore::new(
        directory.path().join("keys.qks"),
        b"correct horse battery staple",
    )
    .unwrap();
    vault.initialize().unwrap();
    vault
}

#[test]
fn private_material_is_encrypted_atomic_and_mode_0600() {
    let directory = tempfile::tempdir().unwrap();
    let vault = store(&directory);
    let key_id = vault
        .generate(
            "maker:m1:encryption",
            KeyKind::X25519,
            100,
            365 * 24 * 3600,
            BTreeMap::new(),
        )
        .unwrap();
    let raw = fs::read(directory.path().join("keys.qks")).unwrap();
    let secret = vault
        .private_key(&key_id, 101, false)
        .unwrap()
        .raw_private_key()
        .unwrap();
    assert!(!raw.windows(secret.len()).any(|window| window == secret));
    assert_eq!(
        fs::metadata(directory.path().join("keys.qks"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(directory.path().join("keys.qks.lock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let wrong =
        EncryptedKeyStore::new(directory.path().join("keys.qks"), b"wrong passphrase").unwrap();
    assert!(wrong.snapshot().unwrap_err().contains("authentication"));
}

#[test]
fn anonymous_kyb_scalar_is_encrypted_and_only_its_ristretto_point_is_public() {
    let directory = tempfile::tempdir().unwrap();
    let vault = store(&directory);
    let key_id = vault
        .generate(
            "kyb_entity",
            KeyKind::Ristretto,
            100,
            365 * 24 * 3600,
            BTreeMap::new(),
        )
        .unwrap();
    let stored = vault.private_key(&key_id, 101, false).unwrap();
    let secret = stored.ristretto_scalar().unwrap();
    assert_ne!(*secret, curve25519_dalek::scalar::Scalar::ZERO);
    let public = vault
        .snapshot()
        .unwrap()
        .keys
        .into_iter()
        .find(|record| record.key_id == key_id)
        .unwrap();
    assert_eq!(public.kind, KeyKind::Ristretto);
    assert!(!serde_json::to_string(&public).unwrap().contains("private"));
    let raw = fs::read(directory.path().join("keys.qks")).unwrap();
    assert!(!raw.windows(32).any(|window| window == secret.as_bytes()));
}

#[test]
fn rotation_overlap_is_explicit_and_revocation_is_final() {
    let directory = tempfile::tempdir().unwrap();
    let vault = store(&directory);
    let old = vault
        .generate(
            "maker:m1:encryption",
            KeyKind::X25519,
            100,
            1000,
            BTreeMap::new(),
        )
        .unwrap();
    let new = vault
        .rotate(
            "maker:m1:encryption",
            KeyKind::X25519,
            200,
            1000,
            BTreeMap::new(),
        )
        .unwrap();
    assert_eq!(
        vault
            .private_keys_for("maker:m1:encryption", 201, false)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        vault
            .private_keys_for("maker:m1:encryption", 201, true)
            .unwrap()
            .len(),
        2
    );
    assert!(vault
        .private_key(&old, 201, false)
        .unwrap_err()
        .contains("active"));
    vault
        .revoke(&new, 202, "operator credential compromise")
        .unwrap();
    assert!(vault
        .private_key(&new, 203, false)
        .unwrap_err()
        .contains("revoked"));
}

#[test]
fn public_registry_is_signed_and_contains_no_private_field() {
    let directory = tempfile::tempdir().unwrap();
    let vault = store(&directory);
    let signer = vault
        .generate(
            "registry-signing",
            KeyKind::Ed25519,
            100,
            1000,
            BTreeMap::new(),
        )
        .unwrap();
    vault
        .generate(
            "maker:m1:encryption",
            KeyKind::X25519,
            100,
            1000,
            BTreeMap::new(),
        )
        .unwrap();
    let manifest = vault.public_manifest(&signer, 102).unwrap();
    let signing = vault.private_key(&signer, 102, false).unwrap();
    assert!(manifest.verify(&signing.ed25519().unwrap().verifying_key()));
    let encoded = serde_json::to_string(&manifest.records).unwrap();
    assert!(!encoded.contains("private"));
    let mut moved = manifest.clone();
    moved.generation += 1;
    assert!(!moved.verify(&signing.ed25519().unwrap().verifying_key()));
}

#[test]
fn tls_certificates_require_the_ca_and_private_files_are_not_world_readable() {
    let directory = tempfile::tempdir().unwrap();
    let (ca_key, ca_cert) = create_ca("QOMM test CA", 3650).unwrap();
    let (node_key, node_cert) =
        issue_mutual_tls_certificate(&ca_key, &ca_cert, "node-0", &["node-0"], &["127.0.0.1"], 30)
            .unwrap();
    let (key, cert, ca) = write_tls_bundle(
        directory.path().join("pki"),
        "node-0",
        &node_key,
        &node_cert,
        &ca_cert,
    )
    .unwrap();
    assert_eq!(
        fs::metadata(key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(cert).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(
        fs::metadata(ca).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(
        node_cert.issuer_name().to_der().unwrap(),
        ca_cert.subject_name().to_der().unwrap()
    );
}

#[test]
fn weak_passphrase_and_relaxed_permissions_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    assert!(
        EncryptedKeyStore::new(directory.path().join("keys"), b"short")
            .unwrap_err()
            .contains("12")
    );
    let vault = store(&directory);
    fs::set_permissions(
        directory.path().join("keys.qks"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(vault.snapshot().unwrap_err().contains("600"));
}
