//! Resident mutually-authenticated node service with durable idempotency.

use crate::executor::{ProgramRegistry, SealedExecution};
use crate::key_management::EncryptedKeyStore;
use crate::order::{
    admission_principal_digest, principal_ticket_id, AdmissionTicket, FixedSlotSealer,
    NodeAdmissionAttestation, NodeExecutionAttestation, RandomnessBeacon,
    ZERO as ZERO_MANIFEST_DIGEST,
};
use crate::wire::{frame_is_authentic, Frame, FRAME_BYTES};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use curve25519_dalek::ristretto::RistrettoPoint;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion};
use qomm_proofs::kyb::{
    verify_presentation, verify_registry, EntityLimits, KybPresentation, SignedCohortRegistry,
};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const VERSION: u64 = 1;
pub const RECORD_BYTES: usize = 4096;
pub const LENGTH_BYTES: usize = 4;
pub const MAX_JSON_BYTES: usize = RECORD_BYTES - LENGTH_BYTES;
const MAX_RESIDENT_CONNECTIONS: usize = 256;

pub fn certificate_fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// Return a deployment-scoped identifier for the OS installation serving a
/// node. This detects seven aliases or seven processes on one installation;
/// it is deliberately not described as hardware attestation. A production
/// claim about distinct physical machines additionally needs a TPM/TEE or an
/// independently audited host inventory.
pub fn os_installation_boundary_id(deployment_id: &str) -> Result<[u8; 32], String> {
    if deployment_id.is_empty()
        || deployment_id.len() > 128
        || !deployment_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'+' | b'-')
        })
    {
        return Err("deployment id is invalid for OS-boundary attestation".into());
    }
    #[cfg(target_os = "linux")]
    let raw = fs::read("/etc/machine-id")
        .or_else(|_| fs::read("/var/lib/dbus/machine-id"))
        .map_err(|error| format!("OS installation id is unavailable: {error}"))?;
    #[cfg(target_os = "macos")]
    let raw = {
        let output = Command::new("/usr/sbin/sysctl")
            .args(["-n", "kern.uuid"])
            .env_clear()
            .output()
            .map_err(|error| format!("OS installation id is unavailable: {error}"))?;
        if !output.status.success() {
            return Err("OS installation id command failed".into());
        }
        output.stdout
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let raw: Vec<u8> = return Err("OS installation id is unsupported on this platform".into());
    let raw = raw
        .into_iter()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if !(16..=256).contains(&raw.len()) {
        return Err("OS installation id has an invalid size".into());
    }
    Ok(Sha256::new()
        .chain_update(b"QOMM:OS-INSTALLATION-BOUNDARY:v1")
        .chain_update((deployment_id.len() as u32).to_be_bytes())
        .chain_update(deployment_id.as_bytes())
        .chain_update((raw.len() as u32).to_be_bytes())
        .chain_update(raw)
        .finalize()
        .into())
}

pub fn encode_record(message: &Value) -> Result<[u8; RECORD_BYTES], String> {
    if !message.is_object() {
        return Err("control message must be a JSON object".into());
    }
    let raw = serde_json::to_vec(message).map_err(|error| error.to_string())?;
    if raw.len() > MAX_JSON_BYTES {
        return Err("control message exceeds the fixed record size".into());
    }
    let mut record = [0_u8; RECORD_BYTES];
    record[..4].copy_from_slice(&(raw.len() as u32).to_be_bytes());
    record[4..4 + raw.len()].copy_from_slice(&raw);
    OsRng.fill_bytes(&mut record[4 + raw.len()..]);
    Ok(record)
}

pub fn decode_record(record: &[u8]) -> Result<Value, String> {
    if record.len() != RECORD_BYTES {
        return Err("control record has the wrong fixed size".into());
    }
    let length = u32::from_be_bytes(record[..4].try_into().expect("four-byte length")) as usize;
    if length > MAX_JSON_BYTES {
        return Err("control record declares an invalid JSON length".into());
    }
    let message: Value = serde_json::from_slice(&record[4..4 + length])
        .map_err(|_| "control record does not contain valid JSON".to_string())?;
    if !message.is_object() {
        return Err("control message must be a JSON object".into());
    }
    Ok(message)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Client,
    Coordinator,
    Observer,
}

#[derive(Clone, Debug)]
pub struct Principal {
    pub role: Role,
    pub frame_key: Option<Vec<u8>>,
    /// Stable inside the venue/epoch scope and shared by every wallet of one
    /// legal entity.  It is assigned by the authenticated server config, not
    /// supplied in a request.
    pub scope_nullifier: Option<[u8; 32]>,
    kyb_presentation: Option<KybPresentation>,
}

impl Principal {
    pub fn client(
        frame_key: Vec<u8>,
        scope_nullifier: &RistrettoPoint,
        presentation: KybPresentation,
    ) -> Result<Self, String> {
        if frame_key.len() < 32 {
            return Err("client principals need a frame authentication key".into());
        }
        if presentation.proof.nullifier != *scope_nullifier {
            return Err("configured scope nullifier does not match the KYB presentation".into());
        }
        Ok(Self {
            role: Role::Client,
            frame_key: Some(frame_key),
            scope_nullifier: Some(scope_nullifier.compress().to_bytes()),
            kyb_presentation: Some(presentation),
        })
    }

    /// Construct an invalid client record so configuration loaders and tests
    /// can verify that the resident server fails closed before listening.
    pub fn client_without_kyb(
        frame_key: Vec<u8>,
        scope_nullifier: &RistrettoPoint,
    ) -> Result<Self, String> {
        if frame_key.len() < 32 {
            return Err("client principals need a frame authentication key".into());
        }
        Ok(Self {
            role: Role::Client,
            frame_key: Some(frame_key),
            scope_nullifier: Some(scope_nullifier.compress().to_bytes()),
            kyb_presentation: None,
        })
    }

    pub const fn coordinator() -> Self {
        Self {
            role: Role::Coordinator,
            frame_key: None,
            scope_nullifier: None,
            kyb_presentation: None,
        }
    }

    pub const fn observer() -> Self {
        Self {
            role: Role::Observer,
            frame_key: None,
            scope_nullifier: None,
            kyb_presentation: None,
        }
    }
}

#[derive(Clone)]
pub struct KybPolicy {
    venue_scope: Vec<u8>,
    required_cohort: String,
    registry: Arc<RwLock<SignedCohortRegistry>>,
    trusted_issuer: VerifyingKey,
}

impl KybPolicy {
    pub fn new(
        venue_scope: Vec<u8>,
        required_cohort: impl Into<String>,
        registry: SignedCohortRegistry,
        trusted_issuer: VerifyingKey,
    ) -> Result<Self, String> {
        if venue_scope.is_empty() {
            return Err("KYB venue scope must not be empty".into());
        }
        let required_cohort = required_cohort.into();
        if required_cohort.is_empty() {
            return Err("KYB required cohort must not be empty".into());
        }
        verify_registry(&registry, &trusted_issuer, unix_seconds())
            .map_err(|error| format!("KYB registry is invalid: {error:?}"))?;
        Ok(Self {
            venue_scope,
            required_cohort,
            registry: Arc::new(RwLock::new(registry)),
            trusted_issuer,
        })
    }

    /// Install only a newer issuer-signed registry. All already-issued
    /// presentations name the old registry id and stop verifying immediately,
    /// which is how revocation and group merge reach a running venue.
    pub fn update_registry(&self, registry: SignedCohortRegistry) -> Result<(), String> {
        verify_registry(&registry, &self.trusted_issuer, unix_seconds())
            .map_err(|error| format!("KYB registry is invalid: {error:?}"))?;
        if registry.cohort != self.required_cohort {
            return Err("KYB registry update names another cohort".into());
        }
        let mut current = self
            .registry
            .write()
            .map_err(|_| "KYB registry cache lock is poisoned".to_string())?;
        if registry.registry_epoch <= current.registry_epoch {
            return Err("KYB registry update is stale or replayed".into());
        }
        *current = registry;
        Ok(())
    }

    pub fn registry_epoch(&self) -> Result<u64, String> {
        self.registry
            .read()
            .map(|registry| registry.registry_epoch)
            .map_err(|_| "KYB registry cache lock is poisoned".to_string())
    }

    fn verify_principal(
        &self,
        fingerprint: &str,
        principal: &Principal,
    ) -> Result<[u8; 32], String> {
        let presentation = principal
            .kyb_presentation
            .as_ref()
            .ok_or_else(|| "client principal has no KYB presentation".to_string())?;
        let registry = self
            .registry
            .read()
            .map_err(|_| "KYB registry cache lock is poisoned".to_string())?;
        verify_presentation(
            presentation,
            &registry,
            &self.trusted_issuer,
            &self.venue_scope,
            fingerprint.as_bytes(),
            unix_seconds(),
            &self.required_cohort,
        )
        .map_err(|error| format!("KYB presentation is invalid for this venue scope: {error:?}"))?;
        let proved = presentation.proof.nullifier.compress().to_bytes();
        if principal.scope_nullifier != Some(proved) {
            return Err("configured scope nullifier does not match the KYB presentation".into());
        }
        Ok(proved)
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
}

#[derive(Clone, Copy, Debug)]
pub struct RateLimitPolicy {
    pub limits: EntityLimits,
    pub slots_per_epoch: u32,
}

impl RateLimitPolicy {
    pub fn current_epoch(self) -> u64 {
        // The resident node owns the one-second slot schedule. A request's
        // frame.slot chooses storage only; it cannot move this cap window.
        unix_seconds() / u64::from(self.slots_per_epoch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionPosition {
    pub sequence: u64,
    pub ticket_id: [u8; 32],
    pub batch_digest: [u8; 32],
    pub order_digest: [u8; 32],
    pub claim_digest: [u8; 32],
}

/// Durable node identities for admission, ordering, and sealed-batch receipts.
/// Production callers load these from protected storage and pass them into the
/// server explicitly, so a restart cannot silently change the verification
/// keys for already-issued receipts.
#[derive(Clone)]
pub struct NodeSealingKeys {
    authority: SigningKey,
    beacon: SigningKey,
    node: SigningKey,
}

impl NodeSealingKeys {
    pub fn from_signing_keys(authority: SigningKey, beacon: SigningKey, node: SigningKey) -> Self {
        Self {
            authority,
            beacon,
            node,
        }
    }

    pub fn from_encrypted_store(
        store: &EncryptedKeyStore,
        authority_key_id: &str,
        beacon_key_id: &str,
        node_key_id: &str,
        at: u64,
    ) -> Result<Self, String> {
        fn signing(
            store: &EncryptedKeyStore,
            key_id: &str,
            at: u64,
            purpose: &str,
        ) -> Result<SigningKey, String> {
            store
                .private_key(key_id, at, false)?
                .ed25519()
                .cloned()
                .ok_or_else(|| format!("{purpose} key is not Ed25519"))
        }
        Ok(Self {
            authority: signing(store, authority_key_id, at, "admission authority")?,
            beacon: signing(store, beacon_key_id, at, "ordering beacon")?,
            node: signing(store, node_key_id, at, "node receipt")?,
        })
    }

    /// Convenience for isolated tests. The production `serve_node` binary
    /// requires an encrypted persistent key store instead.
    pub fn generate_for_testing() -> Self {
        Self {
            authority: SigningKey::generate(&mut OsRng),
            beacon: SigningKey::generate(&mut OsRng),
            node: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn public_keys(&self) -> [VerifyingKey; 3] {
        [
            self.authority.verifying_key(),
            self.beacon.verifying_key(),
            self.node.verifying_key(),
        ]
    }
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            limits: EntityLimits::default(),
            slots_per_epoch: 60,
        }
    }
}

#[repr(C)]
struct Sqlite3 {
    _private: [u8; 0],
}

#[link(name = "sqlite3")]
unsafe extern "C" {
    fn sqlite3_open_v2(
        filename: *const c_char,
        database: *mut *mut Sqlite3,
        flags: c_int,
        vfs: *const c_char,
    ) -> c_int;
    fn sqlite3_close_v2(database: *mut Sqlite3) -> c_int;
    fn sqlite3_exec(
        database: *mut Sqlite3,
        sql: *const c_char,
        callback: Option<
            unsafe extern "C" fn(*mut c_void, c_int, *mut *mut c_char, *mut *mut c_char) -> c_int,
        >,
        data: *mut c_void,
        error: *mut *mut c_char,
    ) -> c_int;
    fn sqlite3_free(pointer: *mut c_void);
    fn sqlite3_busy_timeout(database: *mut Sqlite3, milliseconds: c_int) -> c_int;
}

const SQLITE_OK: c_int = 0;
const SQLITE_OPEN_READWRITE: c_int = 0x0000_0002;
const SQLITE_OPEN_CREATE: c_int = 0x0000_0004;
const SQLITE_OPEN_FULLMUTEX: c_int = 0x0001_0000;

struct Database(*mut Sqlite3);

// Access is serialized by NodeStore's mutex and SQLite itself is opened in
// FULLMUTEX mode.
unsafe impl Send for Database {}

impl Drop for Database {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this is the sole owner and no query survives the mutex.
            let _ = unsafe { sqlite3_close_v2(self.0) };
        }
    }
}

unsafe extern "C" fn collect_rows(
    data: *mut c_void,
    columns: c_int,
    values: *mut *mut c_char,
    _names: *mut *mut c_char,
) -> c_int {
    // SAFETY: sqlite3_exec passes back the exact pointer supplied by query.
    let rows = unsafe { &mut *(data.cast::<Vec<Vec<Option<String>>>>()) };
    let mut row = Vec::with_capacity(columns as usize);
    for index in 0..columns as isize {
        // SAFETY: SQLite supplies `columns` entries.
        let value = unsafe { *values.offset(index) };
        if value.is_null() {
            row.push(None);
        } else {
            // SAFETY: SQLite values are NUL-terminated for the callback's duration.
            row.push(Some(
                unsafe { CStr::from_ptr(value) }
                    .to_string_lossy()
                    .into_owned(),
            ));
        }
    }
    rows.push(row);
    0
}

impl Database {
    fn open(path: &Path) -> Result<Self, String> {
        let filename = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "database path contains a NUL byte".to_string())?;
        let mut database = ptr::null_mut();
        // SAFETY: filename lives through the call and database is an out pointer.
        let result = unsafe {
            sqlite3_open_v2(
                filename.as_ptr(),
                &mut database,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                ptr::null(),
            )
        };
        if result != SQLITE_OK || database.is_null() {
            if !database.is_null() {
                // SAFETY: open returned this handle.
                let _ = unsafe { sqlite3_close_v2(database) };
            }
            return Err(format!("SQLite open failed with code {result}"));
        }
        // SAFETY: database is live.
        unsafe { sqlite3_busy_timeout(database, 5_000) };
        let this = Self(database);
        this.execute(
            "PRAGMA journal_mode=WAL;\
             PRAGMA synchronous=FULL;\
             PRAGMA foreign_keys=ON;\
             CREATE TABLE IF NOT EXISTS requests (\
               principal BLOB NOT NULL, request_id BLOB NOT NULL,\
               request_digest BLOB NOT NULL, response BLOB NOT NULL,\
               state INTEGER NOT NULL DEFAULT 1,\
               PRIMARY KEY(principal,request_id));\
             CREATE TABLE IF NOT EXISTS frames (\
               principal BLOB NOT NULL, slot INTEGER NOT NULL,\
               frame_digest BLOB NOT NULL, frame BLOB NOT NULL,\
               claim_digest BLOB NOT NULL,\
               received_ns INTEGER NOT NULL, PRIMARY KEY(principal,slot));\
             CREATE TABLE IF NOT EXISTS entity_usage (\
               scope_nullifier BLOB NOT NULL, epoch INTEGER NOT NULL,\
               requests INTEGER NOT NULL, lots INTEGER NOT NULL,\
               PRIMARY KEY(scope_nullifier,epoch));\
             CREATE TABLE IF NOT EXISTS slots (\
               slot INTEGER PRIMARY KEY, expected_digest BLOB NOT NULL,\
               expected_count INTEGER NOT NULL,\
               state INTEGER NOT NULL, duplicate_count INTEGER NOT NULL DEFAULT 0,\
               manifest_digest BLOB, batch_digest BLOB, order_digest BLOB);\
             CREATE TABLE IF NOT EXISTS sealed_frames (\
               slot INTEGER NOT NULL, ordinal INTEGER NOT NULL,\
               principal BLOB NOT NULL, frame_digest BLOB NOT NULL,\
               PRIMARY KEY(slot,ordinal), UNIQUE(slot,principal),\
               FOREIGN KEY(slot) REFERENCES slots(slot));",
        )?;
        let request_columns = this.query("PRAGMA table_info(requests)")?;
        if !request_columns
            .iter()
            .any(|row| row.get(1).and_then(Option::as_deref) == Some("state"))
        {
            this.execute("ALTER TABLE requests ADD COLUMN state INTEGER NOT NULL DEFAULT 1")?;
        }
        let slot_columns = this.query("PRAGMA table_info(slots)")?;
        if !slot_columns
            .iter()
            .any(|row| row.get(1).and_then(Option::as_deref) == Some("order_digest"))
        {
            this.execute("ALTER TABLE slots ADD COLUMN order_digest BLOB")?;
        }
        let frame_columns = this.query("PRAGMA table_info(frames)")?;
        if !frame_columns
            .iter()
            .any(|row| row.get(1).and_then(Option::as_deref) == Some("claim_digest"))
        {
            // Old development rows cannot prove a pre-quote claim. They stay
            // readable for migration, but slot close fails until resubmitted.
            this.execute("ALTER TABLE frames ADD COLUMN claim_digest BLOB")?;
        }
        Ok(this)
    }

    fn query(&self, sql: &str) -> Result<Vec<Vec<Option<String>>>, String> {
        let sql = CString::new(sql).map_err(|_| "SQL contains a NUL byte".to_string())?;
        let mut error = ptr::null_mut();
        let mut rows = Vec::<Vec<Option<String>>>::new();
        // SAFETY: all pointers remain live until sqlite3_exec returns.
        let result = unsafe {
            sqlite3_exec(
                self.0,
                sql.as_ptr(),
                Some(collect_rows),
                (&mut rows as *mut Vec<Vec<Option<String>>>).cast(),
                &mut error,
            )
        };
        if result != SQLITE_OK {
            let message = if error.is_null() {
                format!("SQLite error {result}")
            } else {
                // SAFETY: SQLite allocated this message and asks sqlite3_free to release it.
                let message = unsafe { CStr::from_ptr(error) }
                    .to_string_lossy()
                    .into_owned();
                unsafe { sqlite3_free(error.cast()) };
                message
            };
            return Err(message);
        }
        Ok(rows)
    }

    fn execute(&self, sql: &str) -> Result<(), String> {
        self.query(sql).map(|_| ())
    }
}

fn blob(value: &[u8]) -> String {
    format!("X'{}'", hex::encode(value))
}

pub struct NodeStore {
    pub path: PathBuf,
    database: Mutex<Database>,
}

struct StoredFrame {
    principal: String,
    raw: Vec<u8>,
    received_ns: u64,
}

struct SealedSlot {
    manifest_digest: [u8; 32],
    batch_digest: [u8; 32],
    order_digest: [u8; 32],
    ordered: Vec<(String, [u8; 32])>,
}

fn insert_request(
    database: &Database,
    principal: &str,
    request_id: &str,
    request_digest: &[u8; 32],
    response: &Value,
) -> Result<(), String> {
    let response = serde_json::to_vec(response).map_err(|error| error.to_string())?;
    database.execute(&format!(
        "INSERT INTO requests(principal,request_id,request_digest,response,state) VALUES({},{},{},{},1)",
        blob(principal.as_bytes()),
        blob(request_id.as_bytes()),
        blob(request_digest),
        blob(&response)
    ))
}

fn transaction<T>(
    database: &Database,
    operation: impl FnOnce(&Database) -> Result<T, String>,
) -> Result<T, String> {
    database.execute("BEGIN IMMEDIATE")?;
    match operation(database) {
        Ok(value) => match database.execute("COMMIT") {
            Ok(()) => Ok(value),
            Err(error) => {
                let _ = database.execute("ROLLBACK");
                Err(error)
            }
        },
        Err(error) => {
            let _ = database.execute("ROLLBACK");
            Err(error)
        }
    }
}

fn usage(
    database: &Database,
    scope_nullifier: &[u8; 32],
    epoch: u64,
) -> Result<(u64, u64), String> {
    let rows = database.query(&format!(
        "SELECT requests,lots FROM entity_usage WHERE scope_nullifier={} AND epoch={epoch}",
        blob(scope_nullifier)
    ))?;
    let Some(row) = rows.first() else {
        return Ok((0, 0));
    };
    let requests = row
        .first()
        .and_then(Option::as_deref)
        .unwrap_or("0")
        .parse::<u64>()
        .map_err(|error| error.to_string())?;
    let lots = row
        .get(1)
        .and_then(Option::as_deref)
        .unwrap_or("0")
        .parse::<u64>()
        .map_err(|error| error.to_string())?;
    Ok((requests, lots))
}

impl NodeStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, String> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        Ok(Self {
            database: Mutex::new(Database::open(&path)?),
            path,
        })
    }

    pub fn cached(
        &self,
        principal: &str,
        request_id: &str,
        request_digest: &[u8; 32],
    ) -> Result<Option<Value>, String> {
        let sql = format!(
            "SELECT hex(request_digest),hex(response),state FROM requests WHERE principal={} AND request_id={}",
            blob(principal.as_bytes()),
            blob(request_id.as_bytes())
        );
        let rows = self
            .database
            .lock()
            .expect("node database lock")
            .query(&sql)?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let stored = hex::decode(row[0].as_deref().unwrap_or_default())
            .map_err(|error| error.to_string())?;
        if stored != request_digest {
            return Err("request identifier was reused with a different body".into());
        }
        if row.get(2).and_then(Option::as_deref) != Some("1") {
            return Err("request is incomplete after a prior execution attempt".into());
        }
        let response = hex::decode(row[1].as_deref().unwrap_or_default())
            .map_err(|error| error.to_string())?;
        Ok(Some(
            serde_json::from_slice(&response).map_err(|error| error.to_string())?,
        ))
    }

    pub fn cache(
        &self,
        principal: &str,
        request_id: &str,
        request_digest: &[u8; 32],
        response: &Value,
    ) -> Result<(), String> {
        let response = serde_json::to_vec(response).map_err(|error| error.to_string())?;
        let sql = format!(
            "INSERT INTO requests(principal,request_id,request_digest,response,state) VALUES({},{},{},{},1)",
            blob(principal.as_bytes()),
            blob(request_id.as_bytes()),
            blob(request_digest),
            blob(&response)
        );
        self.database
            .lock()
            .expect("node database lock")
            .execute(&sql)
    }

    #[allow(clippy::too_many_arguments)]
    fn submit_frame_request_inner(
        &self,
        node: u16,
        principal: &str,
        request_id: &str,
        request_digest: &[u8; 32],
        frame: &Frame,
        raw: &[u8],
        claim_digest: &[u8; 32],
        scope_nullifier: &[u8; 32],
        epoch: u64,
        limits: EntityLimits,
        expected_digest: &[u8; 32],
        expected_count: usize,
        fail_after_idempotency: bool,
    ) -> Result<Value, String> {
        let database = self.database.lock().expect("node database lock");
        transaction(&database, |database| {
            let slot_rows = database.query(&format!(
                "SELECT hex(expected_digest),expected_count,state,duplicate_count FROM slots WHERE slot={}",
                frame.slot
            ))?;
            if let Some(row) = slot_rows.first() {
                let stored_expected = hex::decode(row[0].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?;
                if stored_expected != expected_digest {
                    return Err("slot population changed after the slot was opened".into());
                }
                let stored_count = row
                    .get(1)
                    .and_then(Option::as_deref)
                    .unwrap_or("0")
                    .parse::<usize>()
                    .map_err(|error| error.to_string())?;
                if stored_count != expected_count {
                    return Err("slot population count changed after the slot was opened".into());
                }
                if row.get(2).and_then(Option::as_deref) == Some("1") {
                    return Err("the slot is already closed".into());
                }
            }

            let digest: [u8; 32] = Sha256::digest(raw).into();
            let prior = database.query(&format!(
                "SELECT hex(frame_digest) FROM frames WHERE principal={} AND slot={}",
                blob(principal.as_bytes()),
                frame.slot
            ))?;
            if let Some(row) = prior.first() {
                let stored = hex::decode(row[0].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?;
                let message = if stored == digest {
                    "duplicate frame for principal and slot"
                } else {
                    "principal attempted to replace its frame for this slot"
                };
                let response = json!({
                    "ok": false,
                    "error": "Error",
                    "message": message,
                });
                insert_request(database, principal, request_id, request_digest, &response)?;
                database.execute(&format!(
                    "UPDATE slots SET duplicate_count=duplicate_count+1 WHERE slot={}",
                    frame.slot
                ))?;
                return Ok(response);
            }

            let (requests, used_lots) = usage(database, scope_nullifier, epoch)?;
            if requests.saturating_add(1) > limits.max_requests {
                return Err("legal entity request cap exceeded".into());
            }
            if used_lots > limits.max_probe_lots {
                return Err("legal entity probe-volume cap exceeded".into());
            }
            if *claim_digest == ZERO_MANIFEST_DIGEST {
                return Err("admission claim digest must be non-zero".into());
            }
            let response = json!({
                "ok": true,
                "node": node,
                "slot": frame.slot,
                "accepted": true,
                "frame_digest": hex::encode(digest),
                "admission_claim_digest": hex::encode(claim_digest),
            });

            // The idempotency row deliberately comes first inside the same
            // SQLite transaction. Any error or process death before COMMIT
            // rolls it and every effect back together.
            insert_request(database, principal, request_id, request_digest, &response)?;
            if fail_after_idempotency {
                return Err("injected crash after idempotency row".into());
            }
            if slot_rows.is_empty() {
                database.execute(&format!(
                    "INSERT INTO slots(slot,expected_digest,expected_count,state,duplicate_count) VALUES({}, {}, {expected_count}, 0, 0)",
                    frame.slot,
                    blob(expected_digest)
                ))?;
            }
            database.execute(&format!(
                "INSERT INTO entity_usage(scope_nullifier,epoch,requests,lots) VALUES({}, {epoch}, 1, 0) \
                 ON CONFLICT(scope_nullifier,epoch) DO UPDATE SET requests=requests+1",
                blob(scope_nullifier)
            ))?;
            let received_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .min(i64::MAX as u128) as i64;
            database.execute(&format!(
                "INSERT INTO frames(principal,slot,frame_digest,frame,claim_digest,received_ns) VALUES({},{},{},{},{},{received_ns})",
                blob(principal.as_bytes()),
                frame.slot,
                blob(&digest),
                blob(raw),
                blob(claim_digest)
            ))?;
            Ok(response)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_frame_request(
        &self,
        node: u16,
        principal: &str,
        request_id: &str,
        request_digest: &[u8; 32],
        frame: &Frame,
        raw: &[u8],
        claim_digest: &[u8; 32],
        scope_nullifier: &[u8; 32],
        epoch: u64,
        limits: EntityLimits,
        expected_digest: &[u8; 32],
        expected_count: usize,
    ) -> Result<Value, String> {
        self.submit_frame_request_inner(
            node,
            principal,
            request_id,
            request_digest,
            frame,
            raw,
            claim_digest,
            scope_nullifier,
            epoch,
            limits,
            expected_digest,
            expected_count,
            false,
        )
    }

    fn close_slot_request(
        &self,
        principal: &str,
        request_id: &str,
        request_digest: &[u8; 32],
        slot: u32,
        expected_digest: &[u8; 32],
        seal: impl FnOnce(Vec<StoredFrame>) -> Result<SealedSlot, String>,
    ) -> Result<Value, String> {
        let database = self.database.lock().expect("node database lock");
        transaction(&database, |database| {
            let rows = database.query(&format!(
                "SELECT hex(expected_digest),state,duplicate_count FROM slots WHERE slot={slot}"
            ))?;
            let Some(row) = rows.first() else {
                return Err("slot was never opened".into());
            };
            let stored_expected = hex::decode(row[0].as_deref().unwrap_or_default())
                .map_err(|error| error.to_string())?;
            if stored_expected != expected_digest {
                return Err("slot population changed after the slot was opened".into());
            }
            let duplicate_count = row
                .get(2)
                .and_then(Option::as_deref)
                .unwrap_or("0")
                .parse::<u64>()
                .map_err(|error| error.to_string())?;
            if duplicate_count != 0 {
                return Err(format!(
                    "slot contains {duplicate_count} duplicate frame submission(s)"
                ));
            }
            if row.get(1).and_then(Option::as_deref) == Some("1") {
                return Err("slot is already closed".into());
            }
            let frames = database
                .query(&format!(
                    "SELECT hex(principal),hex(frame),hex(claim_digest),received_ns FROM frames WHERE slot={slot} ORDER BY principal"
                ))?
                .into_iter()
                .map(|row| {
                    let principal = String::from_utf8(
                        hex::decode(row[0].as_deref().unwrap_or_default())
                            .map_err(|error| error.to_string())?,
                    )
                    .map_err(|error| error.to_string())?;
                    let raw = hex::decode(row[1].as_deref().unwrap_or_default())
                        .map_err(|error| error.to_string())?;
                    let claim_digest: [u8; 32] = hex::decode(
                        row[2].as_deref().ok_or_else(|| {
                            "stored frame predates admission-claim binding".to_string()
                        })?,
                    )
                    .map_err(|error| error.to_string())?
                    .try_into()
                    .map_err(|_| "stored admission claim has the wrong size".to_string())?;
                    if claim_digest == ZERO_MANIFEST_DIGEST {
                        return Err("stored admission claim is zero".to_string());
                    }
                    let received_ns = row
                        .get(3)
                        .and_then(Option::as_deref)
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?;
                    Ok(StoredFrame {
                        principal,
                        raw,
                        received_ns,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            let sealed = seal(frames)?;
            let response = json!({
                "ok": true,
                "slot": slot,
                "closed": true,
                "frame_count": sealed.ordered.len(),
                "manifest_digest": hex::encode(sealed.manifest_digest),
                "batch_digest": hex::encode(sealed.batch_digest),
                "order_digest": hex::encode(sealed.order_digest),
            });
            insert_request(database, principal, request_id, request_digest, &response)?;
            database.execute(&format!(
                "UPDATE slots SET state=1,manifest_digest={},batch_digest={},order_digest={} WHERE slot={slot}",
                blob(&sealed.manifest_digest),
                blob(&sealed.batch_digest),
                blob(&sealed.order_digest)
            ))?;
            for (ordinal, (frame_principal, frame_digest)) in sealed.ordered.iter().enumerate() {
                database.execute(&format!(
                    "INSERT INTO sealed_frames(slot,ordinal,principal,frame_digest) VALUES({slot},{ordinal},{},{})",
                    blob(frame_principal.as_bytes()),
                    blob(frame_digest)
                ))?;
            }
            Ok(response)
        })
    }

    pub fn sealed_execution(&self, slot: u32) -> Result<SealedExecution, String> {
        let database = self.database.lock().expect("node database lock");
        let rows = database.query(&format!(
            "SELECT state,duplicate_count,hex(batch_digest),expected_count,hex(order_digest) FROM slots WHERE slot={slot}"
        ))?;
        let Some(row) = rows.first() else {
            return Err("slot was never opened".into());
        };
        let duplicate_count = row
            .get(1)
            .and_then(Option::as_deref)
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|error| error.to_string())?;
        if duplicate_count != 0 {
            return Err(format!(
                "slot contains {duplicate_count} duplicate frame submission(s)"
            ));
        }
        if row.first().and_then(Option::as_deref) != Some("1") {
            let expected_count = row
                .get(3)
                .and_then(Option::as_deref)
                .unwrap_or("0")
                .parse::<u64>()
                .map_err(|error| error.to_string())?;
            let actual_count = database
                .query(&format!("SELECT count(*) FROM frames WHERE slot={slot}"))?
                .first()
                .and_then(|row| row.first())
                .and_then(Option::as_deref)
                .unwrap_or("0")
                .parse::<u64>()
                .map_err(|error| error.to_string())?;
            if actual_count < expected_count {
                return Err(format!(
                    "fixed population incomplete: {} cover or request frame(s) missing",
                    expected_count - actual_count
                ));
            }
            return Err("slot is not closed".into());
        }
        let stored_batch: [u8; 32] =
            hex::decode(row.get(2).and_then(Option::as_deref).unwrap_or_default())
                .map_err(|error| error.to_string())?
                .try_into()
                .map_err(|_| "stored batch digest has the wrong size".to_string())?;
        let stored_order: [u8; 32] =
            hex::decode(row.get(4).and_then(Option::as_deref).unwrap_or_default())
                .map_err(|error| error.to_string())?
                .try_into()
                .map_err(|_| "stored order digest has the wrong size".to_string())?;
        let rows = database.query(&format!(
            "SELECT hex(sf.frame_digest),hex(f.frame),hex(sf.principal) FROM sealed_frames sf \
             LEFT JOIN frames f ON f.slot=sf.slot AND f.principal=sf.principal \
             WHERE sf.slot={slot} ORDER BY sf.ordinal"
        ))?;
        if rows.is_empty() {
            return Err("closed slot has no sealed frame manifest".into());
        }
        let mut frames = Vec::with_capacity(rows.len());
        let mut principals = Vec::with_capacity(rows.len());
        for row in rows {
            let expected = hex::decode(row[0].as_deref().unwrap_or_default())
                .map_err(|error| error.to_string())?;
            let raw = hex::decode(row[1].as_deref().unwrap_or_default())
                .map_err(|error| error.to_string())?;
            if Sha256::digest(&raw).as_slice() != expected {
                return Err("stored frame bytes do not match the closed-slot digest".into());
            }
            frames.push(raw);
            principals.push(
                String::from_utf8(
                    hex::decode(row[2].as_deref().unwrap_or_default())
                        .map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?,
            );
        }
        let actual = sealed_batch_digest(slot, &frames)?;
        if actual != stored_batch {
            return Err("stored frames do not match the closed-slot batch digest".into());
        }
        if sealed_order_digest(slot, &principals) != stored_order {
            return Err("stored principal order does not match the closed-slot digest".into());
        }
        Ok(SealedExecution {
            slot,
            batch_digest: stored_batch,
            frames,
        })
    }

    /// Return one participant's position in a closed fixed-population slot.
    /// The coordinator calls this for every registered principal on the fixed
    /// schedule; asking for a digest therefore does not identify which frame
    /// was real. The raw TLS certificate fingerprint never leaves the node.
    pub fn admission_position(
        &self,
        slot: u32,
        requested_principal: &[u8; 32],
    ) -> Result<AdmissionPosition, String> {
        let database = self.database.lock().expect("node database lock");
        let slot_rows = database.query(&format!(
            "SELECT state,hex(batch_digest),hex(order_digest) FROM slots WHERE slot={slot}"
        ))?;
        let Some(slot_row) = slot_rows.first() else {
            return Err("slot was never opened".into());
        };
        if slot_row.first().and_then(Option::as_deref) != Some("1") {
            return Err("slot is not closed".into());
        }
        let batch_digest: [u8; 32] = hex::decode(
            slot_row
                .get(1)
                .and_then(Option::as_deref)
                .unwrap_or_default(),
        )
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "stored batch digest has the wrong size".to_string())?;
        let order_digest: [u8; 32] = hex::decode(
            slot_row
                .get(2)
                .and_then(Option::as_deref)
                .unwrap_or_default(),
        )
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "stored order digest has the wrong size".to_string())?;
        let rows = database.query(&format!(
            "SELECT sf.ordinal,hex(sf.principal),hex(f.claim_digest) FROM sealed_frames sf \
             JOIN frames f ON f.slot=sf.slot AND f.principal=sf.principal \
             WHERE sf.slot={slot} ORDER BY sf.ordinal"
        ))?;
        for row in rows {
            let ordinal = row
                .first()
                .and_then(Option::as_deref)
                .unwrap_or_default()
                .parse::<u64>()
                .map_err(|error| error.to_string())?;
            let principal = String::from_utf8(
                hex::decode(row.get(1).and_then(Option::as_deref).unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            if admission_principal_digest(&principal)? == *requested_principal {
                let claim_digest: [u8; 32] =
                    hex::decode(row.get(2).and_then(Option::as_deref).unwrap_or_default())
                        .map_err(|error| error.to_string())?
                        .try_into()
                        .map_err(|_| "stored admission claim has the wrong size".to_string())?;
                if claim_digest == ZERO_MANIFEST_DIGEST {
                    return Err("stored admission claim is zero".into());
                }
                return Ok(AdmissionPosition {
                    sequence: ordinal
                        .checked_add(1)
                        .ok_or_else(|| "admission sequence overflow".to_string())?,
                    ticket_id: principal_ticket_id(slot, &principal)?,
                    batch_digest,
                    order_digest,
                    claim_digest,
                });
            }
        }
        Err("principal is not in the closed slot population".into())
    }

    pub fn entity_usage(
        &self,
        scope_nullifier: &[u8; 32],
        epoch: u64,
    ) -> Result<(u64, u64), String> {
        let rows = self
            .database
            .lock()
            .expect("node database lock")
            .query(&format!(
                "SELECT requests,lots FROM entity_usage WHERE scope_nullifier={} AND epoch={epoch}",
                blob(scope_nullifier)
            ))?;
        let Some(row) = rows.first() else {
            return Ok((0, 0));
        };
        let requests = row
            .first()
            .and_then(Option::as_deref)
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|error| error.to_string())?;
        let lots = row
            .get(1)
            .and_then(Option::as_deref)
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|error| error.to_string())?;
        Ok((requests, lots))
    }

    pub fn frames_for_slot(&self, slot: u32) -> Result<Vec<Vec<u8>>, String> {
        self.database
            .lock()
            .expect("node database lock")
            .query(&format!(
                "SELECT hex(frame) FROM frames WHERE slot={slot} ORDER BY principal"
            ))?
            .into_iter()
            .map(|row| {
                hex::decode(row[0].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())
            })
            .collect()
    }

    fn count(&self, table: &str) -> Result<u64, String> {
        let rows = self
            .database
            .lock()
            .expect("node database lock")
            .query(&format!("SELECT count(*) FROM {table}"))?;
        rows.first()
            .and_then(|row| row.first())
            .and_then(Option::as_deref)
            .ok_or_else(|| "SQLite count returned no value".to_string())?
            .parse()
            .map_err(|error: std::num::ParseIntError| error.to_string())
    }

    pub fn frame_count(&self) -> Result<u64, String> {
        self.count("frames")
    }

    pub fn request_count(&self) -> Result<u64, String> {
        self.count("requests")
    }
}

fn expected_clients(principals: &BTreeMap<String, Principal>) -> Vec<String> {
    principals
        .iter()
        .filter(|(_, principal)| principal.role == Role::Client)
        .map(|(fingerprint, _)| fingerprint.clone())
        .collect()
}

fn population_digest(principals: &[String]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"QOMM:NODE:EXPECTED-PRINCIPALS:v1");
    digest.update((principals.len() as u64).to_be_bytes());
    for principal in principals {
        digest.update((principal.len() as u64).to_be_bytes());
        digest.update(principal.as_bytes());
    }
    digest.finalize().into()
}

fn sealed_batch_digest(slot: u32, frames: &[Vec<u8>]) -> Result<[u8; 32], String> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"QOMM:SEALED:BATCH:v1");
    bytes.extend_from_slice(&slot.to_be_bytes());
    bytes.extend_from_slice(
        &u32::try_from(frames.len())
            .map_err(|_| "sealed batch contains too many frames".to_string())?
            .to_be_bytes(),
    );
    for frame in frames {
        bytes.extend_from_slice(
            &u32::try_from(frame.len())
                .map_err(|_| "sealed frame is too large".to_string())?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(frame);
    }
    Ok(Sha256::digest(bytes).into())
}

fn sealed_order_digest(slot: u32, principals: &[String]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"QOMM:NODE:SEALED-ORDER:v1");
    digest.update(slot.to_be_bytes());
    digest.update((principals.len() as u64).to_be_bytes());
    for principal in principals {
        digest.update((principal.len() as u64).to_be_bytes());
        digest.update(principal.as_bytes());
    }
    digest.finalize().into()
}

fn ticket_for_principal(
    slot: u32,
    principal: &str,
    authority: &SigningKey,
) -> Result<AdmissionTicket, String> {
    let ticket_id = principal_ticket_id(slot, principal)?;
    let mut ticket = AdmissionTicket {
        slot: u64::from(slot),
        ticket_id,
        issued_at: 0,
        expires_at: u64::MAX,
        signature: Signature::from_bytes(&[0; 64]),
    };
    ticket.signature = authority.sign(&ticket.unsigned()?);
    Ok(ticket)
}

fn seal_stored_slot(
    node: u16,
    slot: u32,
    expected: &[String],
    stored: Vec<StoredFrame>,
    keys: &NodeSealingKeys,
) -> Result<SealedSlot, String> {
    let tickets = expected
        .iter()
        .map(|principal| ticket_for_principal(slot, principal, &keys.authority))
        .collect::<Result<Vec<_>, _>>()?;
    let mut principal_tickets = BTreeMap::new();
    let mut digest_principals = BTreeMap::new();
    for (principal, ticket) in expected.iter().zip(&tickets) {
        principal_tickets.insert(principal.clone(), ticket.clone());
        digest_principals.insert(ticket.digest()?, principal.clone());
    }
    let mut sealer = FixedSlotSealer::new(
        u64::from(slot),
        u64::from(node),
        unix_nanos().saturating_sub(1),
        tickets,
        keys.authority.verifying_key(),
        keys.beacon.verifying_key(),
        keys.node.clone(),
        ZERO_MANIFEST_DIGEST,
    )?;
    let deadline_ns = sealer.deadline_ns;
    for stored_frame in stored {
        let ticket = principal_tickets
            .get(&stored_frame.principal)
            .ok_or_else(|| "slot contains a frame from an unexpected principal".to_string())?;
        let frame = Frame::decode(&stored_frame.raw).map_err(|error| error.to_string())?;
        sealer.admit(ticket, frame, stored_frame.received_ns)?;
    }
    // All nodes derive the same slot rotation. A local close timestamp here
    // used to make honest nodes disagree on simultaneous-RFQ order. Because
    // every KYB-scoped entity contributes exactly one real-or-cover frame, the
    // query payload cannot grind this content-independent ordering key.
    let beacon_value: [u8; 32] = Sha256::new()
        .chain_update(b"QOMM:NODE:SLOT-ROTATION:v1")
        .chain_update(slot.to_be_bytes())
        .chain_update(population_digest(expected))
        .finalize()
        .into();
    let beacon = RandomnessBeacon::sign(u64::from(slot) + 1, beacon_value, &keys.beacon);
    let (frames, manifest) = sealer.close(&beacon, deadline_ns.saturating_add(1))?;
    let ordered = manifest
        .ordered_ticket_digests
        .iter()
        .zip(&manifest.ordered_frame_digests)
        .map(|(ticket, frame)| {
            digest_principals
                .get(ticket)
                .cloned()
                .map(|principal| (principal, *frame))
                .ok_or_else(|| "closed manifest contains an unexpected ticket".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let encoded = frames
        .iter()
        .map(|frame| frame.encode().to_vec())
        .collect::<Vec<_>>();
    let ordered_principals = ordered
        .iter()
        .map(|(principal, _)| principal.clone())
        .collect::<Vec<_>>();
    Ok(SealedSlot {
        manifest_digest: manifest.digest()?,
        batch_digest: sealed_batch_digest(slot, &encoded)?,
        order_digest: sealed_order_digest(slot, &ordered_principals),
        ordered,
    })
}

#[derive(Clone)]
pub struct ServerTlsConfig {
    acceptor: Arc<SslAcceptor>,
}

pub fn load_owner_private_key(path: impl AsRef<Path>) -> Result<PKey<Private>, String> {
    const MAX_PRIVATE_KEY_BYTES: usize = 128 * 1024;
    let path = path.as_ref();
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("TLS private key cannot be opened safely: {error}"))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    // SAFETY: geteuid has no preconditions and reveals no key material.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_PRIVATE_KEY_BYTES as u64
    {
        return Err(
            "TLS private key must be a bounded owner-only regular file owned by the service user"
                .into(),
        );
    }
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take((MAX_PRIVATE_KEY_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(|error| error.to_string())?;
    PKey::private_key_from_pem(&encoded)
        .or_else(|_| PKey::private_key_from_der(&encoded))
        .map_err(|_| "TLS private key is not an unencrypted PEM or DER private key".into())
}

pub fn server_ssl_context(
    cert: impl AsRef<Path>,
    key: impl AsRef<Path>,
    ca: impl AsRef<Path>,
) -> Result<ServerTlsConfig, String> {
    let private_key = load_owner_private_key(key)?;
    let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())
        .map_err(|error| error.to_string())?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|error| error.to_string())?;
    builder
        .set_certificate_chain_file(cert)
        .map_err(|error| error.to_string())?;
    builder
        .set_private_key(&private_key)
        .map_err(|error| error.to_string())?;
    builder.set_ca_file(ca).map_err(|error| error.to_string())?;
    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    builder
        .check_private_key()
        .map_err(|error| error.to_string())?;
    Ok(ServerTlsConfig {
        acceptor: Arc::new(builder.build()),
    })
}

#[derive(Clone)]
pub struct ClientTlsConfig {
    connector: Arc<SslConnector>,
}

pub fn client_ssl_context(
    cert: impl AsRef<Path>,
    key: impl AsRef<Path>,
    ca: impl AsRef<Path>,
) -> Result<ClientTlsConfig, String> {
    let private_key = load_owner_private_key(key)?;
    let mut builder =
        SslConnector::builder(SslMethod::tls_client()).map_err(|error| error.to_string())?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|error| error.to_string())?;
    builder
        .set_certificate_chain_file(cert)
        .map_err(|error| error.to_string())?;
    builder
        .set_private_key(&private_key)
        .map_err(|error| error.to_string())?;
    builder.set_ca_file(ca).map_err(|error| error.to_string())?;
    builder.set_verify(SslVerifyMode::PEER);
    builder
        .check_private_key()
        .map_err(|error| error.to_string())?;
    Ok(ClientTlsConfig {
        connector: Arc::new(builder.build()),
    })
}

impl ClientTlsConfig {
    /// Open one mutually authenticated TLS 1.3 connection using the same
    /// certificate policy as the resident-node client.  The proof-party
    /// protocol is newline-delimited rather than fixed-record, so it reuses
    /// the TLS boundary without reusing the resident wire codec.
    pub fn connect_tcp(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
        timeout: Duration,
    ) -> Result<SslStream<TcpStream>, String> {
        let tcp = TcpStream::connect((host, port)).map_err(|error| error.to_string())?;
        tcp.set_read_timeout(Some(timeout))
            .and_then(|_| tcp.set_write_timeout(Some(timeout)))
            .map_err(|error| error.to_string())?;
        self.connector
            .connect(server_name, tcp)
            .map_err(|error| error.to_string())
    }
}

pub struct ResidentNodeServer {
    pub node: u16,
    host: String,
    pub port: u16,
    tls: ServerTlsConfig,
    principals: BTreeMap<String, Principal>,
    kyb_policy: Option<Arc<KybPolicy>>,
    slot_keys: Arc<NodeSealingKeys>,
    store: Arc<NodeStore>,
    registry: Option<Arc<ProgramRegistry>>,
    rate_policy: RateLimitPolicy,
    idle_timeout: Duration,
    response_delay: Duration,
    instance_id: [u8; 32],
    boot_id: [u8; 32],
    stop: Arc<AtomicBool>,
    dispatch_lock: Arc<Mutex<()>>,
    handle: Option<JoinHandle<()>>,
}

#[allow(clippy::too_many_arguments)]
fn serve_authenticated_stream<S>(
    stream: S,
    acceptor: Arc<SslAcceptor>,
    principals: Arc<BTreeMap<String, Principal>>,
    kyb_policy: Option<Arc<KybPolicy>>,
    slot_keys: Arc<NodeSealingKeys>,
    store: Arc<NodeStore>,
    registry: Option<Arc<ProgramRegistry>>,
    rate_policy: RateLimitPolicy,
    dispatch_lock: Arc<Mutex<()>>,
    node: u16,
    instance_id: [u8; 32],
    boot_id: [u8; 32],
    response_delay: Duration,
) where
    S: Read + Write + std::fmt::Debug,
{
    let mut stream = match acceptor.accept(stream) {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("node service TLS handshake failed: {error}");
            return;
        }
    };
    let Some(certificate) = stream.ssl().peer_certificate() else {
        eprintln!("node service mutual TLS authentication failed: peer sent no certificate");
        return;
    };
    let der = match certificate.to_der() {
        Ok(der) => der,
        Err(error) => {
            eprintln!("node service could not encode the peer certificate: {error}");
            return;
        }
    };
    let fingerprint = certificate_fingerprint(&der);
    let Some(principal) = principals.get(&fingerprint).cloned() else {
        eprintln!("node service mutual TLS authentication failed: unknown certificate fingerprint");
        return;
    };
    let mut record = [0_u8; RECORD_BYTES];
    loop {
        if let Err(error) = stream.read_exact(&mut record) {
            // A client may deliberately keep one authenticated connection idle
            // between fixed-record calls, or close it without a TLS close_notify.
            // Darwin reports the configured read timeout as WouldBlock (EAGAIN).
            // These are connection lifecycle events, not malformed records.
            if !matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::WouldBlock
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::ConnectionReset
            ) {
                eprintln!("node service fixed-record read failed: {error}");
            }
            break;
        }
        let response = match decode_record(&record).and_then(|request| {
            let _serial = dispatch_lock.lock().expect("dispatch lock");
            dispatch(
                node,
                instance_id,
                boot_id,
                &fingerprint,
                &principal,
                &principals,
                kyb_policy.as_deref(),
                &slot_keys,
                &store,
                registry.as_deref(),
                rate_policy,
                &request,
            )
        }) {
            Ok(response) => response,
            Err(message) => json!({
                "ok": false,
                "error": "Error",
                "message": message.chars().take(256).collect::<String>(),
            }),
        };
        if !response_delay.is_zero() {
            thread::sleep(response_delay);
        }
        let response = match encode_record(&response) {
            Ok(response) => response,
            Err(error) => {
                eprintln!("node service fixed-record encoding failed: {error}");
                break;
            }
        };
        if let Err(error) = stream.write_all(&response) {
            if !matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
            ) {
                eprintln!("node service fixed-record write failed: {error}");
            }
            break;
        }
        if let Err(error) = stream.flush() {
            if !matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
            ) {
                eprintln!("node service TLS flush failed: {error}");
            }
            break;
        }
    }
}

impl ResidentNodeServer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node: u16,
        host: impl Into<String>,
        port: u16,
        tls: ServerTlsConfig,
        principals: BTreeMap<String, Principal>,
        kyb_policy: Option<Arc<KybPolicy>>,
        slot_keys: NodeSealingKeys,
        store: Arc<NodeStore>,
        registry: Option<Arc<ProgramRegistry>>,
        rate_policy: RateLimitPolicy,
        idle_timeout: Duration,
        response_delay: Duration,
    ) -> Result<Self, String> {
        if rate_policy.slots_per_epoch == 0 {
            return Err("rate-limit epoch must contain at least one slot".into());
        }
        if registry
            .as_ref()
            .is_some_and(|registry| !registry.is_circuit_approved())
        {
            return Err(
                "resident nodes require a qomm-dsl-approved qomm-mpc program registry".into(),
            );
        }
        if principals
            .values()
            .any(|principal| principal.role == Role::Client)
            && kyb_policy.is_none()
        {
            return Err("resident nodes require a KYB policy for client principals".into());
        }
        if let Some(policy) = kyb_policy.as_deref() {
            for (fingerprint, principal) in &principals {
                if principal.role == Role::Client {
                    policy.verify_principal(fingerprint, principal)?;
                }
            }
        }
        let public_keys = slot_keys.public_keys();
        let instance_id: [u8; 32] = Sha256::new()
            .chain_update(b"QOMM:NODE:INSTANCE:v1")
            .chain_update(node.to_be_bytes())
            .chain_update(public_keys[0].as_bytes())
            .chain_update(public_keys[1].as_bytes())
            .chain_update(public_keys[2].as_bytes())
            .finalize()
            .into();
        let mut boot_id = [0_u8; 32];
        OsRng.fill_bytes(&mut boot_id);
        Ok(Self {
            node,
            host: host.into(),
            port,
            tls,
            principals,
            kyb_policy,
            slot_keys: Arc::new(slot_keys),
            store,
            registry,
            rate_policy,
            idle_timeout,
            response_delay,
            instance_id,
            boot_id,
            stop: Arc::new(AtomicBool::new(false)),
            dispatch_lock: Arc::new(Mutex::new(())),
            handle: None,
        })
    }

    pub fn start(&mut self) -> Result<u16, String> {
        let listener = TcpListener::bind((self.host.as_str(), self.port))
            .map_err(|error| error.to_string())?;
        listener
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;
        self.port = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        let acceptor = Arc::clone(&self.tls.acceptor);
        let principals = Arc::new(self.principals.clone());
        let kyb_policy = self.kyb_policy.clone();
        let slot_keys = Arc::clone(&self.slot_keys);
        let store = Arc::clone(&self.store);
        let registry = self.registry.clone();
        let rate_policy = self.rate_policy;
        let stop = Arc::clone(&self.stop);
        let dispatch_lock = Arc::clone(&self.dispatch_lock);
        let node = self.node;
        let instance_id = self.instance_id;
        let boot_id = self.boot_id;
        let idle_timeout = self.idle_timeout;
        let response_delay = self.response_delay;
        self.handle = Some(thread::spawn(move || {
            let mut workers: Vec<JoinHandle<()>> = Vec::new();
            while !stop.load(Ordering::Acquire) {
                let mut index = 0;
                while index < workers.len() {
                    if workers[index].is_finished() {
                        let worker = workers.swap_remove(index);
                        let _ = worker.join();
                    } else {
                        index += 1;
                    }
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        if workers.len() >= MAX_RESIDENT_CONNECTIONS {
                            eprintln!(
                                "node service rejected a connection above its fixed worker bound"
                            );
                            drop(stream);
                            continue;
                        }
                        let acceptor = Arc::clone(&acceptor);
                        let principals = Arc::clone(&principals);
                        let kyb_policy = kyb_policy.clone();
                        let slot_keys = Arc::clone(&slot_keys);
                        let store = Arc::clone(&store);
                        let registry = registry.clone();
                        let dispatch_lock = Arc::clone(&dispatch_lock);
                        workers.push(thread::spawn(move || {
                            // Darwin can propagate O_NONBLOCK from the listener to an
                            // accepted socket.  `SslAcceptor::accept` below performs a
                            // blocking handshake and treats WANT_READ/WANT_WRITE as an
                            // incomplete handshake, so always restore blocking mode.
                            if let Err(error) = stream.set_nonblocking(false) {
                                eprintln!(
                                    "node service could not make an accepted socket blocking: {error}"
                                );
                                return;
                            }
                            if let Err(error) = stream.set_read_timeout(Some(idle_timeout)) {
                                eprintln!(
                                    "node service could not set the accepted socket read timeout: {error}"
                                );
                                return;
                            }
                            if let Err(error) = stream.set_write_timeout(Some(idle_timeout)) {
                                eprintln!(
                                    "node service could not set the accepted socket write timeout: {error}"
                                );
                                return;
                            }
                            serve_authenticated_stream(
                                stream,
                                acceptor,
                                principals,
                                kyb_policy,
                                slot_keys,
                                store,
                                registry,
                                rate_policy,
                                dispatch_lock,
                                node,
                                instance_id,
                                boot_id,
                                response_delay,
                            );
                        }));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        eprintln!("node service listener accept failed: {error}");
                        break;
                    }
                }
            }
            for worker in workers {
                let _ = worker.join();
            }
        }));
        Ok(self.port)
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if self.handle.is_some() {
            let _ = TcpStream::connect((self.host.as_str(), self.port));
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    /// Exercise the identical TLS and request path over an already-connected
    /// OS socket pair.  This exists for environments whose sandbox forbids
    /// `bind(2)`; production callers should use [`Self::start`].
    pub fn local_client(
        &self,
        tls: ClientTlsConfig,
        server_name: impl Into<String>,
        attempts: usize,
    ) -> ResidentNodeLocalClient {
        ResidentNodeLocalClient {
            acceptor: Arc::clone(&self.tls.acceptor),
            principals: Arc::new(self.principals.clone()),
            kyb_policy: self.kyb_policy.clone(),
            slot_keys: Arc::clone(&self.slot_keys),
            store: Arc::clone(&self.store),
            registry: self.registry.clone(),
            rate_policy: self.rate_policy,
            dispatch_lock: Arc::clone(&self.dispatch_lock),
            node: self.node,
            instance_id: self.instance_id,
            boot_id: self.boot_id,
            idle_timeout: self.idle_timeout,
            response_delay: self.response_delay,
            tls,
            server_name: server_name.into(),
            attempts: attempts.max(1),
            stream: None,
            worker: None,
        }
    }
}

impl Drop for ResidentNodeServer {
    fn drop(&mut self) {
        self.stop();
    }
}

pub struct ResidentNodeLocalClient {
    acceptor: Arc<SslAcceptor>,
    principals: Arc<BTreeMap<String, Principal>>,
    kyb_policy: Option<Arc<KybPolicy>>,
    slot_keys: Arc<NodeSealingKeys>,
    store: Arc<NodeStore>,
    registry: Option<Arc<ProgramRegistry>>,
    rate_policy: RateLimitPolicy,
    dispatch_lock: Arc<Mutex<()>>,
    node: u16,
    instance_id: [u8; 32],
    boot_id: [u8; 32],
    idle_timeout: Duration,
    response_delay: Duration,
    tls: ClientTlsConfig,
    server_name: String,
    attempts: usize,
    stream: Option<SslStream<UnixStream>>,
    worker: Option<JoinHandle<()>>,
}

impl ResidentNodeLocalClient {
    pub fn connect(&mut self) -> Result<(), String> {
        let (server_stream, client_stream) =
            UnixStream::pair().map_err(|error| error.to_string())?;
        server_stream
            .set_read_timeout(Some(self.idle_timeout))
            .map_err(|error| error.to_string())?;
        server_stream
            .set_write_timeout(Some(self.idle_timeout))
            .map_err(|error| error.to_string())?;
        client_stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|error| error.to_string())?;
        client_stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|error| error.to_string())?;
        let acceptor = Arc::clone(&self.acceptor);
        let principals = Arc::clone(&self.principals);
        let kyb_policy = self.kyb_policy.clone();
        let slot_keys = Arc::clone(&self.slot_keys);
        let store = Arc::clone(&self.store);
        let registry = self.registry.clone();
        let dispatch_lock = Arc::clone(&self.dispatch_lock);
        let rate_policy = self.rate_policy;
        let node = self.node;
        let instance_id = self.instance_id;
        let boot_id = self.boot_id;
        let response_delay = self.response_delay;
        let worker = thread::spawn(move || {
            serve_authenticated_stream(
                server_stream,
                acceptor,
                principals,
                kyb_policy,
                slot_keys,
                store,
                registry,
                rate_policy,
                dispatch_lock,
                node,
                instance_id,
                boot_id,
                response_delay,
            );
        });
        match self.tls.connector.connect(&self.server_name, client_stream) {
            Ok(stream) => {
                self.stream = Some(stream);
                self.worker = Some(worker);
                Ok(())
            }
            Err(error) => {
                let _ = worker.join();
                Err(error.to_string())
            }
        }
    }

    pub fn close(&mut self) {
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.shutdown();
            let _ = stream.get_ref().shutdown(Shutdown::Both);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }

    pub fn call(&mut self, request: &Value) -> Result<Value, String> {
        let record = encode_record(request)?;
        let mut last = String::new();
        for attempt in 0..self.attempts {
            let result = (|| {
                if self.stream.is_none() {
                    self.connect()?;
                }
                let stream = self.stream.as_mut().expect("local client connected");
                stream
                    .write_all(&record)
                    .map_err(|error| error.to_string())?;
                stream.flush().map_err(|error| error.to_string())?;
                let mut response = [0_u8; RECORD_BYTES];
                stream
                    .read_exact(&mut response)
                    .map_err(|error| error.to_string())?;
                decode_record(&response)
            })();
            match result {
                Ok(response) => return Ok(response),
                Err(error) => {
                    last = error;
                    self.close();
                    if attempt + 1 < self.attempts {
                        thread::sleep(Duration::from_millis((50_u64 << attempt.min(3)).min(500)));
                    }
                }
            }
        }
        Err(format!(
            "node service remained unavailable after reconnects: {last}"
        ))
    }
}

impl Drop for ResidentNodeLocalClient {
    fn drop(&mut self) {
        self.close();
    }
}

fn canonical_digest(value: &Value) -> Result<[u8; 32], String> {
    Ok(Sha256::digest(serde_json::to_vec(value).map_err(|error| error.to_string())?).into())
}

fn result_hex32(object: &serde_json::Map<String, Value>, key: &str) -> Result<[u8; 32], String> {
    hex::decode(
        object
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("approved computation omitted {key}"))?,
    )
    .map_err(|_| format!("approved computation returned malformed {key}"))?
    .try_into()
    .map_err(|_| format!("approved computation returned malformed {key}"))
}

#[allow(clippy::too_many_arguments)]
fn dispatch(
    node: u16,
    instance_id: [u8; 32],
    boot_id: [u8; 32],
    fingerprint: &str,
    principal: &Principal,
    principals: &BTreeMap<String, Principal>,
    kyb_policy: Option<&KybPolicy>,
    slot_keys: &NodeSealingKeys,
    store: &NodeStore,
    registry: Option<&ProgramRegistry>,
    rate_policy: RateLimitPolicy,
    request: &Value,
) -> Result<Value, String> {
    if request.get("version").and_then(Value::as_u64) != Some(VERSION) {
        return Err("unsupported node-service version".into());
    }
    let request_id = request
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|value| (1..=128).contains(&value.len()))
        .ok_or_else(|| "request_id must contain 1..128 characters".to_string())?;
    let request_digest = canonical_digest(request)?;
    if let Some(cached) = store.cached(fingerprint, request_id, &request_digest)? {
        return Ok(cached);
    }
    match request.get("operation").and_then(Value::as_str) {
        Some("health") => {
            let deployment_id = request
                .get("deployment_id")
                .and_then(Value::as_str)
                .unwrap_or("local");
            let response = json!({
                "ok": true,
                "node": node,
                "status": "ready",
                "version": VERSION,
                "instance_id": hex::encode(instance_id),
                "boot_id": hex::encode(boot_id),
                "os_installation_id": hex::encode(os_installation_boundary_id(deployment_id)?),
            });
            store.cache(fingerprint, request_id, &request_digest, &response)?;
            Ok(response)
        }
        Some("submit") => {
            if principal.role != Role::Client {
                return Err("only client principals may submit frames".into());
            }
            let encoded = request
                .get("frame")
                .and_then(Value::as_str)
                .ok_or_else(|| "frame is not valid base64".to_string())?;
            let raw = BASE64
                .decode(encoded)
                .map_err(|_| "frame is not valid base64".to_string())?;
            if raw.len() != FRAME_BYTES {
                return Err("submitted frame has the wrong fixed size".into());
            }
            let frame = Frame::decode(&raw).map_err(|error| error.to_string())?;
            if frame.node != node
                || request.get("slot").and_then(Value::as_u64) != Some(u64::from(frame.slot))
            {
                return Err("submitted frame belongs to another node or slot".into());
            }
            if !frame_is_authentic(
                principal
                    .frame_key
                    .as_deref()
                    .expect("client key validated"),
                &frame,
            ) {
                return Err("submitted frame MAC is invalid".into());
            }
            let admission_claim_digest: [u8; 32] = hex::decode(
                request
                    .get("admission_claim_digest")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        "admission_claim_digest must be 32-byte hexadecimal".to_string()
                    })?,
            )
            .map_err(|_| "admission_claim_digest must be 32-byte hexadecimal".to_string())?
            .try_into()
            .map_err(|_| "admission_claim_digest must be 32-byte hexadecimal".to_string())?;
            if admission_claim_digest == ZERO_MANIFEST_DIGEST {
                return Err("admission claim digest must be non-zero".into());
            }
            let scope_nullifier = kyb_policy
                .ok_or_else(|| "resident node has no KYB verification policy".to_string())?
                .verify_principal(fingerprint, principal)?;
            let expected = expected_clients(principals);
            store.submit_frame_request(
                node,
                fingerprint,
                request_id,
                &request_digest,
                &frame,
                &raw,
                &admission_claim_digest,
                &scope_nullifier,
                rate_policy.current_epoch(),
                rate_policy.limits,
                &population_digest(&expected),
                expected.len(),
            )
        }
        Some("close_slot") => {
            if principal.role != Role::Coordinator {
                return Err("only the coordinator may close a slot".into());
            }
            let slot = request
                .get("slot")
                .and_then(Value::as_u64)
                .and_then(|slot| u32::try_from(slot).ok())
                .ok_or_else(|| "slot to close is invalid".to_string())?;
            let expected = expected_clients(principals);
            let expected_digest = population_digest(&expected);
            store.close_slot_request(
                fingerprint,
                request_id,
                &request_digest,
                slot,
                &expected_digest,
                |stored| seal_stored_slot(node, slot, &expected, stored, slot_keys),
            )
        }
        Some("admission_position") => {
            if principal.role != Role::Coordinator {
                return Err("only the coordinator may read admission positions".into());
            }
            let slot = request
                .get("slot")
                .and_then(Value::as_u64)
                .and_then(|slot| u32::try_from(slot).ok())
                .ok_or_else(|| "admission slot is invalid".to_string())?;
            let principal_digest: [u8; 32] = hex::decode(
                request
                    .get("principal_digest")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "principal_digest must be 32-byte hexadecimal".to_string())?,
            )
            .map_err(|_| "principal_digest must be 32-byte hexadecimal".to_string())?
            .try_into()
            .map_err(|_| "principal_digest must be 32-byte hexadecimal".to_string())?;
            let position = store.admission_position(slot, &principal_digest)?;
            let attestation = NodeAdmissionAttestation {
                node,
                slot: u64::from(slot),
                sequence: position.sequence,
                principal_digest,
                ticket_id: position.ticket_id,
                claim_digest: position.claim_digest,
                batch_digest: position.batch_digest,
                order_digest: position.order_digest,
                signature: Signature::from_bytes(&[0; 64]),
            }
            .sign(&slot_keys.node)?;
            let response = json!({
                "ok": true,
                "node": node,
                "slot": slot,
                "principal_digest": hex::encode(principal_digest),
                "sequence": position.sequence,
                "ticket_id": hex::encode(position.ticket_id),
                "batch_digest": hex::encode(position.batch_digest),
                "order_digest": hex::encode(position.order_digest),
                "admission_claim_digest": hex::encode(position.claim_digest),
                "node_attestation": hex::encode(attestation.signature.to_bytes()),
            });
            store.cache(fingerprint, request_id, &request_digest, &response)?;
            Ok(response)
        }
        Some("compute") => {
            if principal.role != Role::Coordinator {
                return Err("only the coordinator may start a computation".into());
            }
            let registry = registry
                .ok_or_else(|| "this node has no registered computation handler".to_string())?;
            let slot = request
                .get("slot")
                .and_then(Value::as_u64)
                .and_then(|slot| u32::try_from(slot).ok())
                .ok_or_else(|| "computation slot is invalid".to_string())?;
            let sealed = store.sealed_execution(slot)?;
            let result = registry.execute_sealed(request, &sealed)?;
            let object = result
                .as_object()
                .ok_or_else(|| "computation handler returned a non-object".to_string())?;
            let mut response = serde_json::Map::new();
            response.insert("ok".into(), Value::Bool(true));
            response.insert("node".into(), Value::from(node));
            for (key, value) in object {
                response.insert(key.clone(), value.clone());
            }
            if registry.is_circuit_approved() {
                let attestation = NodeExecutionAttestation {
                    node,
                    slot: u64::from(slot),
                    lane: response
                        .get("lane")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| "approved computation omitted its lane".to_string())?,
                    batch_digest: result_hex32(&response, "batch_digest")?,
                    source_digest: result_hex32(&response, "mpc_source_digest")?,
                    state_generation: response
                        .get("mpc_state_generation")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| {
                            "approved computation omitted its state generation".to_string()
                        })?,
                    frame_count: response
                        .get("mpc_frame_count")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| {
                            "approved computation omitted its frame count".to_string()
                        })?,
                    input_count: response
                        .get("mpc_input_count")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| {
                            "approved computation omitted its input count".to_string()
                        })?,
                    stdout_digest: result_hex32(&response, "mpc_stdout_digest")?,
                    stderr_digest: result_hex32(&response, "mpc_stderr_digest")?,
                    persistence_digest: result_hex32(&response, "mpc_persistence_digest")?,
                    receipt_digest: result_hex32(&response, "mpc_execution_digest")?,
                    signature: Signature::from_bytes(&[0; 64]),
                }
                .sign(&slot_keys.node)?;
                response.insert(
                    "mpc_execution_attestation".into(),
                    Value::String(hex::encode(attestation.signature.to_bytes())),
                );
            }
            let response = Value::Object(response);
            store.cache(fingerprint, request_id, &request_digest, &response)?;
            Ok(response)
        }
        _ => Err("unknown node-service operation".into()),
    }
}

pub struct ResidentNodeClient {
    host: String,
    port: u16,
    tls: ClientTlsConfig,
    server_name: String,
    attempts: usize,
    stream: Option<SslStream<TcpStream>>,
}

impl ResidentNodeClient {
    pub fn new(
        host: impl Into<String>,
        port: u16,
        tls: ClientTlsConfig,
        server_name: impl Into<String>,
        attempts: usize,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            tls,
            server_name: server_name.into(),
            attempts: attempts.max(1),
            stream: None,
        }
    }

    pub fn connect(&mut self) -> Result<(), String> {
        let tcp = TcpStream::connect((self.host.as_str(), self.port))
            .map_err(|error| error.to_string())?;
        tcp.set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|error| error.to_string())?;
        tcp.set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|error| error.to_string())?;
        self.stream = Some(
            self.tls
                .connector
                .connect(&self.server_name, tcp)
                .map_err(|error| error.to_string())?,
        );
        Ok(())
    }

    pub fn close(&mut self) {
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.shutdown();
            let _ = stream.get_ref().shutdown(Shutdown::Both);
        }
    }

    pub fn call(&mut self, request: &Value) -> Result<Value, String> {
        let record = encode_record(request)?;
        let mut last = String::new();
        for attempt in 0..self.attempts {
            let result = (|| {
                if self.stream.is_none() {
                    self.connect()?;
                }
                let stream = self.stream.as_mut().expect("client connected");
                stream
                    .write_all(&record)
                    .map_err(|error| error.to_string())?;
                stream.flush().map_err(|error| error.to_string())?;
                let mut response = [0_u8; RECORD_BYTES];
                stream
                    .read_exact(&mut response)
                    .map_err(|error| error.to_string())?;
                decode_record(&response)
            })();
            match result {
                Ok(response) => return Ok(response),
                Err(error) => {
                    last = error;
                    self.close();
                    if attempt + 1 < self.attempts {
                        thread::sleep(Duration::from_millis((50_u64 << attempt.min(3)).min(500)));
                    }
                }
            }
        }
        Err(format!(
            "node service remained unavailable after reconnects: {last}"
        ))
    }
}

impl Drop for ResidentNodeClient {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod atomic_tests {
    use super::*;
    use crate::wire::PAYLOAD_BYTES;
    use std::os::unix::fs::symlink;

    #[test]
    fn crash_between_idempotency_row_and_submit_effect_rolls_back_both() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.sqlite3");
        let key = vec![b'k'; 32];
        let frame = Frame::new(7, 0, [0; PAYLOAD_BYTES], &key).unwrap();
        let raw = frame.encode();
        {
            let store = NodeStore::open(&path).unwrap();
            let error = store
                .submit_frame_request_inner(
                    0,
                    "principal",
                    "request",
                    &[1; 32],
                    &frame,
                    &raw,
                    &[4; 32],
                    &[2; 32],
                    9,
                    EntityLimits::default(),
                    &[3; 32],
                    1,
                    true,
                )
                .unwrap_err();
            assert!(error.contains("injected crash"));
        }
        let reopened = NodeStore::open(path).unwrap();
        assert_eq!(reopened.request_count().unwrap(), 0);
        assert_eq!(reopened.frame_count().unwrap(), 0);
        assert_eq!(reopened.entity_usage(&[2; 32], 9).unwrap(), (0, 0));
    }

    #[test]
    fn tls_private_key_loader_rejects_links_and_excess_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.key");
        let encoded = PKey::generate_ed25519()
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap();
        fs::write(&path, encoded).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_owner_private_key(&path).is_ok());

        let linked = directory.path().join("linked.key");
        symlink(&path, &linked).unwrap();
        assert!(load_owner_private_key(&linked)
            .unwrap_err()
            .contains("safely"));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_owner_private_key(&path)
            .unwrap_err()
            .contains("owner-only"));
    }
}
