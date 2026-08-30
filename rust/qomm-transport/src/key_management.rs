//! Encrypted key lifecycle and short-lived mutual-TLS certificates.

use crate::selective_disclosure::X25519PrivateKey;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private};
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509NameBuilder, X509Req, X509};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const MAGIC: &[u8; 8] = b"QOMMKEY1";
const AAD: &[u8] = b"QOMM:KEYSTORE:v1";
const MANIFEST_DOMAIN: &[u8] = b"QOMM:KEY-MANIFEST:v1";
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyKind {
    Ed25519,
    X25519,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct KeyRecord {
    key_id: String,
    purpose: String,
    purpose_generation: u64,
    kind: KeyKind,
    public: String,
    private: String,
    created_at: u64,
    not_after: u64,
    state: String,
    retired_at: Option<u64>,
    revoked_at: Option<u64>,
    revocation_reason: Option<String>,
    metadata: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoreData {
    version: u8,
    generation: u64,
    keys: Vec<KeyRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicKeyRecord {
    pub key_id: String,
    pub purpose: String,
    pub purpose_generation: u64,
    pub kind: KeyKind,
    pub public: String,
    pub created_at: u64,
    pub not_after: u64,
    pub state: String,
    pub retired_at: Option<u64>,
    pub revoked_at: Option<u64>,
    pub revocation_reason: Option<String>,
    pub metadata: BTreeMap<String, Value>,
}

impl From<&KeyRecord> for PublicKeyRecord {
    fn from(record: &KeyRecord) -> Self {
        Self {
            key_id: record.key_id.clone(),
            purpose: record.purpose.clone(),
            purpose_generation: record.purpose_generation,
            kind: record.kind,
            public: record.public.clone(),
            created_at: record.created_at,
            not_after: record.not_after,
            state: record.state.clone(),
            retired_at: record.retired_at,
            revoked_at: record.revoked_at,
            revocation_reason: record.revocation_reason.clone(),
            metadata: record.metadata.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PublicSnapshot {
    pub version: u8,
    pub generation: u64,
    pub keys: Vec<PublicKeyRecord>,
}

#[derive(Clone)]
pub enum StoredPrivateKey {
    Ed25519(Box<SigningKey>),
    X25519(X25519PrivateKey),
}

impl fmt::Debug for StoredPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ed25519(_) => "StoredPrivateKey::Ed25519([redacted])",
            Self::X25519(_) => "StoredPrivateKey::X25519([redacted])",
        })
    }
}

impl StoredPrivateKey {
    pub fn raw_private_key(&self) -> Result<[u8; 32], String> {
        match self {
            Self::Ed25519(key) => Ok(key.to_bytes()),
            Self::X25519(key) => key.raw_private_key(),
        }
    }

    pub fn ed25519(&self) -> Option<&SigningKey> {
        match self {
            Self::Ed25519(key) => Some(key),
            Self::X25519(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PublicManifest {
    pub generation: u64,
    pub issued_at: u64,
    pub records: Vec<PublicKeyRecord>,
    pub signer_id: String,
    pub signature: Signature,
}

impl PublicManifest {
    pub fn unsigned(&self) -> Result<Vec<u8>, String> {
        let value = serde_json::json!({
            "generation": self.generation,
            "issued_at": self.issued_at,
            "records": self.records,
            "signer_id": self.signer_id,
        });
        let mut body = MANIFEST_DOMAIN.to_vec();
        body.extend(serde_json::to_vec(&value).map_err(|error| error.to_string())?);
        Ok(body)
    }

    pub fn verify(&self, trusted: &VerifyingKey) -> bool {
        self.unsigned()
            .is_ok_and(|body| trusted.verify(&body, &self.signature).is_ok())
    }
}

pub(crate) struct FileLock(File);

impl FileLock {
    pub(crate) fn acquire(path: &Path) -> Result<Self, String> {
        let lock_path = PathBuf::from(format!("{}.lock", path.display()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(lock_path)
            .map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        // SAFETY: geteuid has no preconditions and reveals no secret.
        let effective_uid = unsafe { libc::geteuid() };
        if !metadata.is_file() || metadata.uid() != effective_uid {
            return Err("state lock must be a regular file owned by the service user".into());
        }
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
        // SAFETY: flock receives a live descriptor owned by this guard.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(Self(file))
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor stays valid until after this drop body.
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

pub(crate) fn derive_secret_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0_u8; 32];
    openssl::pkcs5::scrypt(passphrase, salt, 1 << 15, 8, 1, 64 * 1024 * 1024, &mut key)
        .map_err(|error| error.to_string())?;
    Ok(key)
}

pub(crate) fn encrypt_authenticated(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    clear: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = Cipher::aes_256_gcm();
    let mut crypter =
        Crypter::new(cipher, Mode::Encrypt, key, Some(nonce)).map_err(|e| e.to_string())?;
    crypter.aad_update(aad).map_err(|e| e.to_string())?;
    let mut out = vec![0_u8; clear.len() + cipher.block_size()];
    let mut written = crypter.update(clear, &mut out).map_err(|e| e.to_string())?;
    written += crypter
        .finalize(&mut out[written..])
        .map_err(|e| e.to_string())?;
    out.truncate(written);
    let mut tag = [0_u8; 16];
    crypter.get_tag(&mut tag).map_err(|e| e.to_string())?;
    out.extend_from_slice(&tag);
    Ok(out)
}

pub(crate) fn decrypt_authenticated(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    encrypted: &[u8],
) -> Result<Vec<u8>, String> {
    if encrypted.len() < 16 {
        return Err("key-store authentication failed".into());
    }
    let (ciphertext, tag) = encrypted.split_at(encrypted.len() - 16);
    let cipher = Cipher::aes_256_gcm();
    let mut crypter =
        Crypter::new(cipher, Mode::Decrypt, key, Some(nonce)).map_err(|e| e.to_string())?;
    crypter.aad_update(aad).map_err(|e| e.to_string())?;
    crypter.set_tag(tag).map_err(|e| e.to_string())?;
    let mut out = vec![0_u8; ciphertext.len() + cipher.block_size()];
    let mut written = crypter
        .update(ciphertext, &mut out)
        .map_err(|e| e.to_string())?;
    written += crypter
        .finalize(&mut out[written..])
        .map_err(|_| "key-store authentication failed".to_string())?;
    out.truncate(written);
    Ok(out)
}

pub struct EncryptedKeyStore {
    pub path: PathBuf,
    passphrase: Vec<u8>,
}

impl fmt::Debug for EncryptedKeyStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedKeyStore")
            .field("path", &self.path)
            .field("passphrase", &"[redacted]")
            .finish()
    }
}

impl EncryptedKeyStore {
    pub fn new(path: impl Into<PathBuf>, passphrase: &[u8]) -> Result<Self, String> {
        if passphrase.len() < 12 {
            return Err("key-store passphrase must contain at least 12 bytes".into());
        }
        Ok(Self {
            path: path.into(),
            passphrase: passphrase.to_vec(),
        })
    }

    pub fn initialize(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let _lock = FileLock::acquire(&self.path)?;
        if self.path.exists() {
            return Err(format!("{} already exists", self.path.display()));
        }
        self.write_unlocked(&StoreData {
            version: 1,
            generation: 0,
            keys: Vec::new(),
        })
    }

    fn read_unlocked(&self) -> Result<StoreData, String> {
        let metadata = self.path.metadata().map_err(|error| error.to_string())?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "refusing key store with mode {mode:o}; expected 600"
            ));
        }
        let mut raw = Vec::new();
        File::open(&self.path)
            .and_then(|mut file| file.read_to_end(&mut raw))
            .map_err(|error| error.to_string())?;
        let minimum = MAGIC.len() + SALT_BYTES + NONCE_BYTES + 16;
        if raw.len() < minimum || raw.get(..MAGIC.len()) != Some(MAGIC) {
            return Err("not a QOMM encrypted key store".into());
        }
        let mut at = MAGIC.len();
        let salt = &raw[at..at + SALT_BYTES];
        at += SALT_BYTES;
        let nonce: &[u8; NONCE_BYTES] = raw[at..at + NONCE_BYTES].try_into().expect("fixed nonce");
        at += NONCE_BYTES;
        let clear = decrypt_authenticated(
            &derive_secret_key(&self.passphrase, salt)?,
            nonce,
            AAD,
            &raw[at..],
        )?;
        let data: StoreData = serde_json::from_slice(&clear)
            .map_err(|_| "key-store authentication failed".to_string())?;
        if data.version != 1 {
            return Err("unsupported or malformed key-store payload".into());
        }
        Ok(data)
    }

    fn write_unlocked(&self, data: &StoreData) -> Result<(), String> {
        let mut salt = [0_u8; SALT_BYTES];
        let mut nonce = [0_u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let clear = serde_json::to_vec(data).map_err(|error| error.to_string())?;
        let ciphertext = encrypt_authenticated(
            &derive_secret_key(&self.passphrase, &salt)?,
            &nonce,
            AAD,
            &clear,
        )?;
        let mut payload =
            Vec::with_capacity(MAGIC.len() + SALT_BYTES + NONCE_BYTES + ciphertext.len());
        payload.extend_from_slice(MAGIC);
        payload.extend_from_slice(&salt);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let mut temp = parent.join(format!(
            ".{}.{}.tmp",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("qomm-key"),
            rand::random::<u64>()
        ));
        while temp.exists() {
            temp.set_extension(format!("{}.tmp", rand::random::<u64>()));
        }
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)
                .map_err(|error| error.to_string())?;
            file.write_all(&payload)
                .map_err(|error| error.to_string())?;
            file.sync_all().map_err(|error| error.to_string())?;
            fs::rename(&temp, &self.path).map_err(|error| error.to_string())?;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))
                .map_err(|error| error.to_string())?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| error.to_string())?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    fn mutate<T>(
        &self,
        operation: impl FnOnce(&mut StoreData) -> Result<T, String>,
    ) -> Result<T, String> {
        let _lock = FileLock::acquire(&self.path)?;
        let mut data = self.read_unlocked()?;
        let output = operation(&mut data)?;
        data.generation = data
            .generation
            .checked_add(1)
            .ok_or_else(|| "key-store generation overflow".to_string())?;
        self.write_unlocked(&data)?;
        Ok(output)
    }

    pub fn snapshot(&self) -> Result<PublicSnapshot, String> {
        let _lock = FileLock::acquire(&self.path)?;
        let data = self.read_unlocked()?;
        Ok(PublicSnapshot {
            version: data.version,
            generation: data.generation,
            keys: data.keys.iter().map(PublicKeyRecord::from).collect(),
        })
    }

    pub fn generate(
        &self,
        purpose: &str,
        kind: KeyKind,
        now: u64,
        lifetime: u64,
        metadata: BTreeMap<String, Value>,
    ) -> Result<String, String> {
        if purpose.is_empty() || lifetime == 0 {
            return Err("purpose and positive lifetime are required".into());
        }
        let (public, private) = match kind {
            KeyKind::Ed25519 => {
                let key = SigningKey::generate(&mut OsRng);
                (key.verifying_key().to_bytes(), key.to_bytes())
            }
            KeyKind::X25519 => {
                let key = X25519PrivateKey::generate()?;
                (key.public_key()?.raw_public_key()?, key.raw_private_key()?)
            }
        };
        self.mutate(|data| {
            let generation = data
                .keys
                .iter()
                .filter(|record| record.purpose == purpose)
                .map(|record| record.purpose_generation)
                .max()
                .unwrap_or(0)
                + 1;
            let key_id = hex::encode(
                Sha256::new()
                    .chain_update(b"QOMM:KEY-ID:v1")
                    .chain_update(purpose.as_bytes())
                    .chain_update(public)
                    .finalize(),
            );
            for record in &mut data.keys {
                if record.purpose == purpose && record.state == "active" {
                    record.state = "retired".into();
                    record.retired_at = Some(now);
                }
            }
            data.keys.push(KeyRecord {
                key_id: key_id.clone(),
                purpose: purpose.into(),
                purpose_generation: generation,
                kind,
                public: BASE64.encode(public),
                private: BASE64.encode(private),
                created_at: now,
                not_after: now
                    .checked_add(lifetime)
                    .ok_or_else(|| "key lifetime overflow".to_string())?,
                state: "active".into(),
                retired_at: None,
                revoked_at: None,
                revocation_reason: None,
                metadata,
            });
            Ok(key_id)
        })
    }

    pub fn rotate(
        &self,
        purpose: &str,
        kind: KeyKind,
        now: u64,
        lifetime: u64,
        metadata: BTreeMap<String, Value>,
    ) -> Result<String, String> {
        self.generate(purpose, kind, now, lifetime, metadata)
    }

    pub fn revoke(&self, key_id: &str, now: u64, reason: &str) -> Result<(), String> {
        if reason.trim().is_empty() {
            return Err("a revocation reason is required".into());
        }
        self.mutate(|data| {
            let record = data
                .keys
                .iter_mut()
                .find(|record| record.key_id == key_id)
                .ok_or_else(|| format!("unknown key {key_id}"))?;
            if record.state == "revoked" {
                return Err("the key is already revoked".into());
            }
            record.state = "revoked".into();
            record.revoked_at = Some(now);
            record.revocation_reason = Some(reason.into());
            Ok(())
        })
    }

    fn record(&self, key_id: &str) -> Result<KeyRecord, String> {
        let _lock = FileLock::acquire(&self.path)?;
        self.read_unlocked()?
            .keys
            .into_iter()
            .find(|record| record.key_id == key_id)
            .ok_or_else(|| format!("unknown key {key_id}"))
    }

    pub fn private_key(
        &self,
        key_id: &str,
        at: u64,
        allow_retired: bool,
    ) -> Result<StoredPrivateKey, String> {
        let record = self.record(key_id)?;
        if record.state == "revoked" || at > record.not_after {
            return Err("the key is revoked or expired".into());
        }
        if record.state != "active" && !allow_retired {
            return Err("the key is no longer active".into());
        }
        let raw: [u8; 32] = BASE64
            .decode(record.private)
            .map_err(|error| error.to_string())?
            .try_into()
            .map_err(|_| "stored private key is not 32 bytes".to_string())?;
        match record.kind {
            KeyKind::Ed25519 => Ok(StoredPrivateKey::Ed25519(Box::new(SigningKey::from_bytes(
                &raw,
            )))),
            KeyKind::X25519 => Ok(StoredPrivateKey::X25519(X25519PrivateKey::from_raw(&raw)?)),
        }
    }

    pub fn private_keys_for(
        &self,
        purpose: &str,
        at: u64,
        include_retired: bool,
    ) -> Result<Vec<StoredPrivateKey>, String> {
        let snapshot = {
            let _lock = FileLock::acquire(&self.path)?;
            self.read_unlocked()?
        };
        snapshot
            .keys
            .into_iter()
            .filter(|record| {
                record.purpose == purpose
                    && record.state != "revoked"
                    && at <= record.not_after
                    && (record.state == "active" || include_retired)
            })
            .map(|record| self.private_key(&record.key_id, at, include_retired))
            .collect()
    }

    pub fn public_manifest(
        &self,
        signer_id: &str,
        issued_at: u64,
    ) -> Result<PublicManifest, String> {
        let signing = self.private_key(signer_id, issued_at, false)?;
        let signing = signing
            .ed25519()
            .ok_or_else(|| "public manifests require an Ed25519 signing key".to_string())?;
        let snapshot = self.snapshot()?;
        let mut records = snapshot.keys;
        records.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        let mut manifest = PublicManifest {
            generation: snapshot.generation,
            issued_at,
            records,
            signer_id: signer_id.into(),
            signature: Signature::from_bytes(&[0; 64]),
        };
        manifest.signature = signing.sign(&manifest.unsigned()?);
        Ok(manifest)
    }

    pub fn materialize_pkcs8(
        &self,
        key_id: &str,
        target: impl AsRef<Path>,
        at: u64,
    ) -> Result<PathBuf, String> {
        let key = self.private_key(key_id, at, false)?;
        let (id, raw) = match key {
            StoredPrivateKey::Ed25519(key) => (Id::ED25519, key.to_bytes()),
            StoredPrivateKey::X25519(key) => (Id::X25519, key.raw_private_key()?),
        };
        let pkey = PKey::private_key_from_raw_bytes(&raw, id).map_err(|error| error.to_string())?;
        let pem = pkey
            .private_key_to_pem_pkcs8()
            .map_err(|error| error.to_string())?;
        secure_write(target.as_ref(), &pem, 0o600)
    }
}

fn secure_write(path: &Path, payload: &[u8], mode: u32) -> Result<PathBuf, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let temp = parent.join(format!(".qomm-{}.tmp", rand::random::<u64>()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temp)
            .map_err(|error| error.to_string())?;
        file.write_all(payload).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        fs::rename(&temp, path).map_err(|error| error.to_string())?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| error.to_string())?;
        Ok(path.to_path_buf())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

pub fn create_ca(common_name: &str, lifetime_days: u32) -> Result<(PKey<Private>, X509), String> {
    let key = PKey::generate_ed25519().map_err(|error| error.to_string())?;
    let mut name = X509NameBuilder::new().map_err(|error| error.to_string())?;
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)
        .map_err(|error| error.to_string())?;
    let name = name.build();
    let mut builder = X509::builder().map_err(|error| error.to_string())?;
    builder.set_version(2).map_err(|error| error.to_string())?;
    let mut serial = BigNum::new().map_err(|error| error.to_string())?;
    serial
        .rand(159, MsbOption::MAYBE_ZERO, false)
        .map_err(|error| error.to_string())?;
    let serial = serial.to_asn1_integer().map_err(|e| e.to_string())?;
    builder
        .set_serial_number(&serial)
        .map_err(|error| error.to_string())?;
    builder
        .set_subject_name(&name)
        .map_err(|error| error.to_string())?;
    builder
        .set_issuer_name(&name)
        .map_err(|error| error.to_string())?;
    builder
        .set_pubkey(&key)
        .map_err(|error| error.to_string())?;
    let not_before = Asn1Time::days_from_now(0).map_err(|e| e.to_string())?;
    builder
        .set_not_before(&not_before)
        .map_err(|error| error.to_string())?;
    let not_after = Asn1Time::days_from_now(lifetime_days).map_err(|e| e.to_string())?;
    builder
        .set_not_after(&not_after)
        .map_err(|error| error.to_string())?;
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .pathlen(0)
                .build()
                .map_err(|e| e.to_string())?,
        )
        .map_err(|error| error.to_string())?;
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_cert_sign()
                .crl_sign()
                .build()
                .map_err(|e| e.to_string())?,
        )
        .map_err(|error| error.to_string())?;
    let subject = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .map_err(|error| error.to_string())?;
    builder
        .append_extension(subject)
        .map_err(|error| error.to_string())?;
    builder
        .sign(&key, MessageDigest::null())
        .map_err(|error| error.to_string())?;
    Ok((key, builder.build()))
}

pub fn issue_mutual_tls_certificate(
    ca_key: &PKey<Private>,
    ca_cert: &X509,
    common_name: &str,
    dns_names: &[&str],
    ip_addresses: &[&str],
    lifetime_days: u32,
) -> Result<(PKey<Private>, X509), String> {
    let key = PKey::generate_ed25519().map_err(|error| error.to_string())?;
    let mut name = X509NameBuilder::new().map_err(|error| error.to_string())?;
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)
        .map_err(|error| error.to_string())?;
    let name = name.build();
    let mut builder = X509::builder().map_err(|error| error.to_string())?;
    builder.set_version(2).map_err(|error| error.to_string())?;
    let mut serial = BigNum::new().map_err(|error| error.to_string())?;
    serial
        .rand(159, MsbOption::MAYBE_ZERO, false)
        .map_err(|error| error.to_string())?;
    let serial = serial.to_asn1_integer().map_err(|e| e.to_string())?;
    builder
        .set_serial_number(&serial)
        .map_err(|error| error.to_string())?;
    builder
        .set_subject_name(&name)
        .map_err(|error| error.to_string())?;
    builder
        .set_issuer_name(ca_cert.subject_name())
        .map_err(|error| error.to_string())?;
    builder
        .set_pubkey(&key)
        .map_err(|error| error.to_string())?;
    let not_before = Asn1Time::days_from_now(0).map_err(|e| e.to_string())?;
    builder
        .set_not_before(&not_before)
        .map_err(|error| error.to_string())?;
    let not_after = Asn1Time::days_from_now(lifetime_days).map_err(|e| e.to_string())?;
    builder
        .set_not_after(&not_after)
        .map_err(|error| error.to_string())?;
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .build()
                .map_err(|e| e.to_string())?,
        )
        .map_err(|error| error.to_string())?;
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .map_err(|e| e.to_string())?,
        )
        .map_err(|error| error.to_string())?;
    builder
        .append_extension(
            ExtendedKeyUsage::new()
                .server_auth()
                .client_auth()
                .build()
                .map_err(|e| e.to_string())?,
        )
        .map_err(|error| error.to_string())?;
    let mut san = SubjectAlternativeName::new();
    for name in dns_names {
        san.dns(name);
    }
    for address in ip_addresses {
        san.ip(address);
    }
    if !dns_names.is_empty() || !ip_addresses.is_empty() {
        let extension = san
            .build(&builder.x509v3_context(Some(ca_cert), None))
            .map_err(|error| error.to_string())?;
        builder
            .append_extension(extension)
            .map_err(|error| error.to_string())?;
    }
    let authority = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(Some(ca_cert), None))
        .map_err(|error| error.to_string())?;
    builder
        .append_extension(authority)
        .map_err(|error| error.to_string())?;
    builder
        .sign(ca_key, MessageDigest::null())
        .map_err(|error| error.to_string())?;
    Ok((key, builder.build()))
}

/// Generate a node-local Ed25519 key and certificate-signing request.
///
/// The private key never has to cross the node boundary: an offline authority
/// can call [`issue_mutual_tls_certificate_from_csr`] with only the returned
/// request.  DNS names and addresses are deliberately supplied by the
/// authority from its approved deployment specification rather than trusted
/// from an unaudited CSR extension.
pub fn create_mutual_tls_request(common_name: &str) -> Result<(PKey<Private>, X509Req), String> {
    if common_name.trim().is_empty() {
        return Err("mutual-TLS request requires a common name".into());
    }
    let key = PKey::generate_ed25519().map_err(|error| error.to_string())?;
    let mut name = X509NameBuilder::new().map_err(|error| error.to_string())?;
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)
        .map_err(|error| error.to_string())?;
    let name = name.build();
    let mut builder = X509Req::builder().map_err(|error| error.to_string())?;
    builder.set_version(0).map_err(|error| error.to_string())?;
    builder
        .set_subject_name(&name)
        .map_err(|error| error.to_string())?;
    builder
        .set_pubkey(&key)
        .map_err(|error| error.to_string())?;
    builder
        .sign(&key, MessageDigest::null())
        .map_err(|error| error.to_string())?;
    Ok((key, builder.build()))
}

/// Issue one mutual-TLS certificate from a node-generated CSR.
///
/// The authority fixes the identity and SANs from governance-approved input,
/// verifies proof of possession, and refuses a CSR whose subject was swapped
/// for another node.  It never receives the node private key.
pub fn issue_mutual_tls_certificate_from_csr(
    ca_key: &PKey<Private>,
    ca_cert: &X509,
    request: &X509Req,
    common_name: &str,
    dns_names: &[&str],
    ip_addresses: &[&str],
    lifetime_days: u32,
) -> Result<X509, String> {
    if common_name.trim().is_empty() || lifetime_days == 0 {
        return Err("certificate identity and positive lifetime are required".into());
    }
    let request_key = request.public_key().map_err(|error| error.to_string())?;
    if !request
        .verify(&request_key)
        .map_err(|error| error.to_string())?
    {
        return Err("certificate request proof of possession is invalid".into());
    }
    let request_common_names = request
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .map(|entry| entry.data().to_string().map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    if request_common_names.as_slice() != [common_name] {
        return Err("certificate request common name does not match the approved node".into());
    }

    let mut name = X509NameBuilder::new().map_err(|error| error.to_string())?;
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)
        .map_err(|error| error.to_string())?;
    let name = name.build();
    let mut builder = X509::builder().map_err(|error| error.to_string())?;
    builder.set_version(2).map_err(|error| error.to_string())?;
    let mut serial = BigNum::new().map_err(|error| error.to_string())?;
    serial
        .rand(159, MsbOption::MAYBE_ZERO, false)
        .map_err(|error| error.to_string())?;
    let serial = serial
        .to_asn1_integer()
        .map_err(|error| error.to_string())?;
    builder
        .set_serial_number(&serial)
        .map_err(|error| error.to_string())?;
    builder
        .set_subject_name(&name)
        .map_err(|error| error.to_string())?;
    builder
        .set_issuer_name(ca_cert.subject_name())
        .map_err(|error| error.to_string())?;
    builder
        .set_pubkey(&request_key)
        .map_err(|error| error.to_string())?;
    let not_before = Asn1Time::days_from_now(0).map_err(|error| error.to_string())?;
    builder
        .set_not_before(&not_before)
        .map_err(|error| error.to_string())?;
    let not_after = Asn1Time::days_from_now(lifetime_days).map_err(|error| error.to_string())?;
    builder
        .set_not_after(&not_after)
        .map_err(|error| error.to_string())?;
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .build()
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
    builder
        .append_extension(
            ExtendedKeyUsage::new()
                .server_auth()
                .client_auth()
                .build()
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
    let mut san = SubjectAlternativeName::new();
    for name in dns_names {
        san.dns(name);
    }
    for address in ip_addresses {
        san.ip(address);
    }
    if !dns_names.is_empty() || !ip_addresses.is_empty() {
        let extension = san
            .build(&builder.x509v3_context(Some(ca_cert), None))
            .map_err(|error| error.to_string())?;
        builder
            .append_extension(extension)
            .map_err(|error| error.to_string())?;
    }
    let authority = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(Some(ca_cert), None))
        .map_err(|error| error.to_string())?;
    builder
        .append_extension(authority)
        .map_err(|error| error.to_string())?;
    builder
        .sign(ca_key, MessageDigest::null())
        .map_err(|error| error.to_string())?;
    Ok(builder.build())
}

/// Store a node-local CSR bundle without weakening private-key permissions.
pub fn write_tls_request_bundle(
    directory: impl AsRef<Path>,
    name: &str,
    private_key: &PKey<Private>,
    request: &X509Req,
) -> Result<(PathBuf, PathBuf), String> {
    let directory = directory.as_ref();
    fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    let key_path = secure_write(
        &directory.join(format!("{name}.key.pem")),
        &private_key
            .private_key_to_pem_pkcs8()
            .map_err(|error| error.to_string())?,
        0o600,
    )?;
    let request_path = secure_write(
        &directory.join(format!("{name}.csr.pem")),
        &request.to_pem().map_err(|error| error.to_string())?,
        0o644,
    )?;
    Ok((key_path, request_path))
}

pub fn write_tls_bundle(
    directory: impl AsRef<Path>,
    name: &str,
    private_key: &PKey<Private>,
    certificate: &X509,
    ca_cert: &X509,
) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    let directory = directory.as_ref();
    fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    let key_path = secure_write(
        &directory.join(format!("{name}.key.pem")),
        &private_key
            .private_key_to_pem_pkcs8()
            .map_err(|e| e.to_string())?,
        0o600,
    )?;
    let cert_path = secure_write(
        &directory.join(format!("{name}.cert.pem")),
        &certificate.to_pem().map_err(|error| error.to_string())?,
        0o644,
    )?;
    let ca_path = secure_write(
        &directory.join("ca.cert.pem"),
        &ca_cert.to_pem().map_err(|error| error.to_string())?,
        0o644,
    )?;
    Ok((key_path, cert_path, ca_path))
}

#[cfg(test)]
mod file_lock_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn state_lock_never_follows_a_symbolic_link() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let target = directory.path().join("target");
        fs::write(&target, b"do-not-open").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, PathBuf::from(format!("{}.lock", state.display()))).unwrap();
        assert!(FileLock::acquire(&state)
            .err()
            .unwrap()
            .to_ascii_lowercase()
            .contains("symbolic link"));
    }
}
