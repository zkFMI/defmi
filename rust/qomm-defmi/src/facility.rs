//! Chain-neutral, durable DeFMI settlement facility.
//!
//! The existing crate contains the proof-aware settlement primitives.  This
//! module is the Python-only production delta: a crash-atomic projection,
//! replay/nullifier protection, k-of-n authorization, and signed receipts.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const DOMAIN: &[u8] = b"QOMM:DEFMI:FACILITY:v2";
const ASSET_DOMAIN: &[u8] = b"QOMM:DEFMI:ASSET:v1";
const ACCOUNT_DOMAIN: &[u8] = b"QOMM:DEFMI:ACCOUNT:v1";
const SETTLEMENT_DOMAIN: &[u8] = b"QOMM:DEFMI:SETTLEMENT:v1";
const RECEIPT_DOMAIN: &[u8] = b"QOMM:DEFMI:RECEIPT:v1";
const STATE_DOMAIN: &[u8] = b"QOMM:DEFMI:STATE:v1";
pub const ZERO: [u8; 32] = [0; 32];

fn canonical(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|error| error.to_string())
}

fn digest(domain: &[u8], value: &Value) -> Result<[u8; 32], String> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(canonical(value)?);
    Ok(hash.finalize().into())
}

fn nonzero(value: &[u8; 32], name: &str) -> Result<String, String> {
    if value == &ZERO {
        return Err(format!("{name} cannot be the all-zero identifier"));
    }
    Ok(hex::encode(value))
}

fn parse_hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    let raw = hex::decode(value).map_err(|_| format!("{name} must be 32 bytes"))?;
    raw.try_into()
        .map_err(|_| format!("{name} must be 32 bytes"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetKind {
    Cash,
    Security,
    Fund,
    Commodity,
    Carbon,
    Other,
}

impl AssetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cash => "cash",
            Self::Security => "security",
            Self::Fund => "fund",
            Self::Commodity => "commodity",
            Self::Carbon => "carbon",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetDefinition {
    pub asset_id: [u8; 32],
    pub code: String,
    pub kind: AssetKind,
    pub decimals: u8,
    pub terms_digest: [u8; 32],
}

impl AssetDefinition {
    pub fn body(&self) -> Result<Value, String> {
        if self.code.is_empty() || self.decimals > 30 {
            return Err("asset code or decimal precision is invalid".into());
        }
        Ok(json!({
            "asset_id": nonzero(&self.asset_id, "asset_id")?,
            "code": self.code,
            "kind": self.kind.as_str(),
            "decimals": self.decimals,
            "terms_digest": nonzero(&self.terms_digest, "terms_digest")?,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(ASSET_DOMAIN, &self.body()?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountOpening {
    pub handle: [u8; 32],
    pub asset_id: [u8; 32],
    pub commitment: [u8; 32],
    pub issuance_nonce: [u8; 32],
}

impl AccountOpening {
    pub fn body(&self) -> Result<Value, String> {
        Ok(json!({
            "handle": nonzero(&self.handle, "handle")?,
            "asset_id": nonzero(&self.asset_id, "asset_id")?,
            "commitment": nonzero(&self.commitment, "commitment")?,
            "issuance_nonce": nonzero(&self.issuance_nonce, "issuance_nonce")?,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(ACCOUNT_DOMAIN, &self.body()?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateLeg {
    pub handle: [u8; 32],
    pub asset_id: [u8; 32],
    pub before_commitment: [u8; 32],
    pub after_commitment: [u8; 32],
    pub before_sequence: u64,
}

impl StateLeg {
    fn body(&self) -> Result<Value, String> {
        Ok(json!({
            "handle": nonzero(&self.handle, "handle")?,
            "asset_id": nonzero(&self.asset_id, "asset_id")?,
            "before_commitment": nonzero(&self.before_commitment, "before_commitment")?,
            "after_commitment": nonzero(&self.after_commitment, "after_commitment")?,
            "before_sequence": self.before_sequence,
        }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementOrder {
    pub operation_id: [u8; 32],
    pub nullifier: [u8; 32],
    pub deadline: u64,
    pub payment_instruction_digest: [u8; 32],
    pub proof_digest: [u8; 32],
    pub market_statement_digest: [u8; 32],
    pub legs: Vec<StateLeg>,
}

impl SettlementOrder {
    pub fn body(&self) -> Result<Value, String> {
        if self.deadline == 0 || self.legs.is_empty() {
            return Err("settlement needs a positive deadline and at least one leg".into());
        }
        let mut handles = BTreeSet::new();
        if self.legs.iter().any(|leg| !handles.insert(leg.handle)) {
            return Err("a settlement cannot update one handle twice".into());
        }
        Ok(json!({
            "operation_id": nonzero(&self.operation_id, "operation_id")?,
            "nullifier": nonzero(&self.nullifier, "nullifier")?,
            "deadline": self.deadline,
            "payment_instruction_digest": nonzero(&self.payment_instruction_digest, "payment_instruction_digest")?,
            "proof_digest": nonzero(&self.proof_digest, "proof_digest")?,
            "market_statement_digest": nonzero(&self.market_statement_digest, "market_statement_digest")?,
            "legs": self.legs.iter().map(StateLeg::body).collect::<Result<Vec<_>, _>>()?,
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        digest(SETTLEMENT_DOMAIN, &self.body()?)
    }
}

#[derive(Clone, Debug)]
pub struct NodeApproval {
    pub node_id: String,
    pub signature: Signature,
}

#[derive(Clone, Debug)]
pub struct QuorumApproval {
    pub statement: [u8; 32],
    pub signer_epoch: u64,
    pub domain: String,
    pub before_root: [u8; 32],
    pub approvals: Vec<NodeApproval>,
}

#[derive(Clone, Debug)]
pub struct QuorumAuthorizer {
    nodes: BTreeMap<String, VerifyingKey>,
    threshold: usize,
    epoch: u64,
    domain: String,
}

impl QuorumAuthorizer {
    pub fn new(
        nodes: BTreeMap<String, VerifyingKey>,
        threshold: usize,
        epoch: u64,
        domain: impl Into<String>,
    ) -> Result<Self, String> {
        let domain = domain.into();
        if nodes.is_empty()
            || nodes.len() > 64
            || !(1..=nodes.len()).contains(&threshold)
            || epoch == 0
        {
            return Err("invalid k-of-n signer configuration".into());
        }
        let allowed =
            |character: char| character.is_ascii_alphanumeric() || "._:/+-".contains(character);
        if nodes
            .keys()
            .any(|node| node.is_empty() || node.len() > 128 || !node.chars().all(allowed))
        {
            return Err("quorum node identifiers contain invalid characters".into());
        }
        if !domain.is_ascii() || domain.is_empty() || domain.len() > 128 {
            return Err("approval domain must be ASCII and between 1 and 128 bytes".into());
        }
        let mut encoded = BTreeSet::new();
        for key in nodes.values() {
            let bytes = key.to_bytes();
            if bytes == ZERO {
                return Err("quorum public keys cannot use the all-zero encoding".into());
            }
            if !encoded.insert(bytes) {
                return Err("one quorum public key cannot occupy two node identities".into());
            }
        }
        Ok(Self {
            nodes,
            threshold,
            epoch,
            domain,
        })
    }

    fn signing_body(&self, statement: &[u8; 32], before_root: &[u8; 32]) -> Vec<u8> {
        let domain = self.domain.as_bytes();
        let mut body = DOMAIN.to_vec();
        body.extend(self.epoch.to_be_bytes());
        body.extend((domain.len() as u16).to_be_bytes());
        body.extend(domain);
        body.extend(before_root);
        body.extend(statement);
        body
    }

    pub fn verify(
        &self,
        expected: &[u8; 32],
        before_root: &[u8; 32],
        approval: &QuorumApproval,
    ) -> bool {
        if approval.statement != *expected
            || approval.before_root != *before_root
            || approval.domain != self.domain
            || approval.signer_epoch != self.epoch
            || approval.approvals.len() > 64
        {
            return false;
        }
        let body = self.signing_body(expected, before_root);
        let mut seen = BTreeSet::new();
        approval
            .approvals
            .iter()
            .filter(|signed| {
                seen.insert(signed.node_id.clone())
                    && self
                        .nodes
                        .get(&signed.node_id)
                        .is_some_and(|key| key.verify(&body, &signed.signature).is_ok())
            })
            .count()
            >= self.threshold
    }

    pub fn approve(
        &self,
        statement: [u8; 32],
        before_root: [u8; 32],
        signers: &BTreeMap<String, SigningKey>,
    ) -> Result<QuorumApproval, String> {
        if signers.is_empty() || signers.keys().any(|node| !self.nodes.contains_key(node)) {
            return Err("approval signers must be configured quorum nodes".into());
        }
        for (node, key) in signers {
            if self.nodes[node] != key.verifying_key() {
                return Err("approval signer key does not match the quorum configuration".into());
            }
        }
        let body = self.signing_body(&statement, &before_root);
        Ok(QuorumApproval {
            statement,
            signer_epoch: self.epoch,
            domain: self.domain.clone(),
            before_root,
            approvals: signers
                .iter()
                .map(|(node_id, key)| NodeApproval {
                    node_id: node_id.clone(),
                    signature: key.sign(&body),
                })
                .collect(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct SettlementReceipt {
    pub operation_id: [u8; 32],
    pub nullifier: [u8; 32],
    pub statement: [u8; 32],
    pub before_root: [u8; 32],
    pub after_root: [u8; 32],
    pub previous_receipt: [u8; 32],
    pub committed_at_ns: u64,
    pub elapsed_ns: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub database_bytes_before: u64,
    pub database_bytes_after: u64,
    pub signature: Signature,
}

impl SettlementReceipt {
    pub fn unsigned(&self) -> Result<Vec<u8>, String> {
        let mut body = RECEIPT_DOMAIN.to_vec();
        body.extend(canonical(&json!({
            "operation_id": hex::encode(self.operation_id),
            "nullifier": hex::encode(self.nullifier),
            "statement": hex::encode(self.statement),
            "before_root": hex::encode(self.before_root),
            "after_root": hex::encode(self.after_root),
            "previous_receipt": hex::encode(self.previous_receipt),
            "committed_at_ns": self.committed_at_ns,
            "elapsed_ns": self.elapsed_ns,
            "request_bytes": self.request_bytes,
            "response_bytes": self.response_bytes,
            "database_bytes_before": self.database_bytes_before,
            "database_bytes_after": self.database_bytes_after,
        }))?);
        Ok(body)
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        let mut hash = Sha256::new();
        hash.update(self.unsigned()?);
        hash.update(self.signature.to_bytes());
        Ok(hash.finalize().into())
    }

    pub fn verify(&self, key: &VerifyingKey) -> bool {
        self.unsigned()
            .is_ok_and(|body| key.verify(&body, &self.signature).is_ok())
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
    fn sqlite3_close(database: *mut Sqlite3) -> c_int;
    fn sqlite3_exec(
        database: *mut Sqlite3,
        sql: *const c_char,
        callback: Option<
            unsafe extern "C" fn(
                data: *mut c_void,
                columns: c_int,
                values: *mut *mut c_char,
                names: *mut *mut c_char,
            ) -> c_int,
        >,
        data: *mut c_void,
        error: *mut *mut c_char,
    ) -> c_int;
    fn sqlite3_errmsg(database: *mut Sqlite3) -> *const c_char;
    fn sqlite3_free(pointer: *mut c_void);
}

struct Database(*mut Sqlite3);

unsafe impl Send for Database {}

impl Drop for Database {
    fn drop(&mut self) {
        unsafe {
            sqlite3_close(self.0);
        }
    }
}

unsafe extern "C" fn collect_rows(
    data: *mut c_void,
    columns: c_int,
    values: *mut *mut c_char,
    _names: *mut *mut c_char,
) -> c_int {
    let rows = &mut *(data as *mut Vec<Vec<Option<String>>>);
    let values = std::slice::from_raw_parts(values, columns as usize);
    rows.push(
        values
            .iter()
            .map(|value| {
                if value.is_null() {
                    None
                } else {
                    Some(CStr::from_ptr(*value).to_string_lossy().into_owned())
                }
            })
            .collect(),
    );
    0
}

impl Database {
    fn open(path: &Path) -> Result<Self, String> {
        let filename = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "database path contains a NUL byte".to_string())?;
        let mut database = ptr::null_mut();
        let result = unsafe {
            sqlite3_open_v2(
                filename.as_ptr(),
                &mut database,
                0x0000_0002 | 0x0000_0004 | 0x0001_0000,
                ptr::null(),
            )
        };
        if result != 0 || database.is_null() {
            return Err("could not open DeFMI database".into());
        }
        Ok(Self(database))
    }

    fn error(&self) -> String {
        unsafe { CStr::from_ptr(sqlite3_errmsg(self.0)) }
            .to_string_lossy()
            .into_owned()
    }

    fn execute(&self, sql: &str) -> Result<(), String> {
        let sql = CString::new(sql).map_err(|_| "SQL contains a NUL byte".to_string())?;
        let mut error = ptr::null_mut();
        let code = unsafe { sqlite3_exec(self.0, sql.as_ptr(), None, ptr::null_mut(), &mut error) };
        if code == 0 {
            return Ok(());
        }
        let message = if error.is_null() {
            self.error()
        } else {
            let message = unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned();
            unsafe { sqlite3_free(error.cast()) };
            message
        };
        Err(message)
    }

    fn query(&self, sql: &str) -> Result<Vec<Vec<Option<String>>>, String> {
        let sql = CString::new(sql).map_err(|_| "SQL contains a NUL byte".to_string())?;
        let mut rows = Vec::new();
        let mut error = ptr::null_mut();
        let code = unsafe {
            sqlite3_exec(
                self.0,
                sql.as_ptr(),
                Some(collect_rows),
                (&mut rows as *mut Vec<Vec<Option<String>>>).cast(),
                &mut error,
            )
        };
        if code == 0 {
            return Ok(rows);
        }
        let message = if error.is_null() {
            self.error()
        } else {
            let message = unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned();
            unsafe { sqlite3_free(error.cast()) };
            message
        };
        Err(message)
    }
}

fn blob(value: &[u8]) -> String {
    format!("X'{}'", hex::encode(value))
}

fn quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[derive(Serialize, Deserialize)]
struct ReceiptWire {
    operation_id: String,
    nullifier: String,
    statement: String,
    before_root: String,
    after_root: String,
    previous_receipt: String,
    committed_at_ns: u64,
    elapsed_ns: u64,
    request_bytes: u64,
    response_bytes: u64,
    database_bytes_before: u64,
    database_bytes_after: u64,
    signature: String,
}

impl ReceiptWire {
    fn from_receipt(receipt: &SettlementReceipt) -> Self {
        Self {
            operation_id: hex::encode(receipt.operation_id),
            nullifier: hex::encode(receipt.nullifier),
            statement: hex::encode(receipt.statement),
            before_root: hex::encode(receipt.before_root),
            after_root: hex::encode(receipt.after_root),
            previous_receipt: hex::encode(receipt.previous_receipt),
            committed_at_ns: receipt.committed_at_ns,
            elapsed_ns: receipt.elapsed_ns,
            request_bytes: receipt.request_bytes,
            response_bytes: receipt.response_bytes,
            database_bytes_before: receipt.database_bytes_before,
            database_bytes_after: receipt.database_bytes_after,
            signature: hex::encode(receipt.signature.to_bytes()),
        }
    }

    fn into_receipt(self) -> Result<SettlementReceipt, String> {
        let signature: [u8; 64] = hex::decode(self.signature)
            .map_err(|_| "receipt signature is malformed".to_string())?
            .try_into()
            .map_err(|_| "receipt signature is malformed".to_string())?;
        Ok(SettlementReceipt {
            operation_id: parse_hex32(&self.operation_id, "operation_id")?,
            nullifier: parse_hex32(&self.nullifier, "nullifier")?,
            statement: parse_hex32(&self.statement, "statement")?,
            before_root: parse_hex32(&self.before_root, "before_root")?,
            after_root: parse_hex32(&self.after_root, "after_root")?,
            previous_receipt: parse_hex32(&self.previous_receipt, "previous_receipt")?,
            committed_at_ns: self.committed_at_ns,
            elapsed_ns: self.elapsed_ns,
            request_bytes: self.request_bytes,
            response_bytes: self.response_bytes,
            database_bytes_before: self.database_bytes_before,
            database_bytes_after: self.database_bytes_after,
            signature: Signature::from_bytes(&signature),
        })
    }
}

pub struct DefmiFacility {
    path: PathBuf,
    database: Mutex<Database>,
    pub authorizer: QuorumAuthorizer,
    receipt_key: SigningKey,
    pub receipt_public_key: VerifyingKey,
}

impl DefmiFacility {
    pub fn open(
        path: impl AsRef<Path>,
        authorizer: QuorumAuthorizer,
        receipt_key: SigningKey,
    ) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let database = Database::open(&path)?;
        database
            .execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")?;
        let version = database
            .query("PRAGMA user_version")?
            .first()
            .and_then(|row| row.first())
            .and_then(Option::as_deref)
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|error| error.to_string())?;
        if version > 1 {
            return Err(format!("unsupported DeFMI schema version {version}"));
        }
        database.execute(
            "CREATE TABLE IF NOT EXISTS assets(\
                asset_id BLOB PRIMARY KEY CHECK(length(asset_id)=32),\
                code TEXT NOT NULL,kind TEXT NOT NULL,decimals INTEGER NOT NULL,\
                terms_digest BLOB NOT NULL CHECK(length(terms_digest)=32),\
                active INTEGER NOT NULL DEFAULT 1,statement BLOB NOT NULL UNIQUE);\
             CREATE TABLE IF NOT EXISTS accounts(\
                handle BLOB PRIMARY KEY CHECK(length(handle)=32),\
                asset_id BLOB NOT NULL REFERENCES assets(asset_id),\
                commitment BLOB NOT NULL CHECK(length(commitment)=32),\
                sequence INTEGER NOT NULL,opening_statement BLOB NOT NULL UNIQUE);\
             CREATE TABLE IF NOT EXISTS nullifiers(\
                nullifier BLOB PRIMARY KEY CHECK(length(nullifier)=32),\
                deadline INTEGER NOT NULL,statement BLOB NOT NULL UNIQUE);\
             CREATE TABLE IF NOT EXISTS receipts(\
                operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=32),\
                nullifier BLOB NOT NULL UNIQUE,statement BLOB NOT NULL UNIQUE,\
                receipt_json BLOB NOT NULL,receipt_digest BLOB NOT NULL UNIQUE);\
             CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value BLOB NOT NULL);\
             PRAGMA user_version=1;",
        )?;
        database.execute(&format!(
            "INSERT OR IGNORE INTO metadata(key,value) VALUES('state_root',{});\
             INSERT OR IGNORE INTO metadata(key,value) VALUES('last_receipt',{});",
            blob(&ZERO),
            blob(&ZERO)
        ))?;
        let receipt_public_key = receipt_key.verifying_key();
        Ok(Self {
            path,
            database: Mutex::new(database),
            authorizer,
            receipt_key,
            receipt_public_key,
        })
    }

    fn database_size(database: &Database) -> Result<u64, String> {
        let rows = database
            .query("SELECT page_count*page_size FROM pragma_page_count(), pragma_page_size()")?;
        rows.first()
            .and_then(|row| row.first())
            .and_then(Option::as_deref)
            .ok_or_else(|| "SQLite did not report its size".to_string())?
            .parse::<u64>()
            .map_err(|error| error.to_string())
    }

    fn calculate_root(database: &Database) -> Result<[u8; 32], String> {
        let mut hash = Sha256::new();
        hash.update(STATE_DOMAIN);
        for row in database.query(
            "SELECT hex(asset_id),code,kind,decimals,hex(terms_digest),active FROM assets ORDER BY asset_id",
        )? {
            let encoded = json!([
                row[0].as_deref().unwrap_or_default().to_ascii_lowercase(),
                row[1].as_deref().unwrap_or_default(),
                row[2].as_deref().unwrap_or_default(),
                row[3].as_deref().unwrap_or("0").parse::<u64>().map_err(|error| error.to_string())?,
                row[4].as_deref().unwrap_or_default().to_ascii_lowercase(),
                row[5].as_deref().unwrap_or("0").parse::<u64>().map_err(|error| error.to_string())?,
            ]);
            hash.update(canonical(&encoded)?);
        }
        for row in database.query(
            "SELECT hex(handle),hex(asset_id),hex(commitment),sequence FROM accounts ORDER BY handle",
        )? {
            hash.update(hex::decode(row[0].as_deref().unwrap_or_default()).map_err(|error| error.to_string())?);
            hash.update(hex::decode(row[1].as_deref().unwrap_or_default()).map_err(|error| error.to_string())?);
            hash.update(hex::decode(row[2].as_deref().unwrap_or_default()).map_err(|error| error.to_string())?);
            hash.update(row[3].as_deref().unwrap_or("0").parse::<u64>().map_err(|error| error.to_string())?.to_be_bytes());
        }
        for row in database.query(
            "SELECT hex(nullifier),deadline,hex(statement) FROM nullifiers ORDER BY nullifier",
        )? {
            hash.update(
                hex::decode(row[0].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
            hash.update(
                row[1]
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?
                    .to_be_bytes(),
            );
            hash.update(
                hex::decode(row[2].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?,
            );
        }
        Ok(hash.finalize().into())
    }

    fn require_quorum(
        &self,
        statement: &[u8; 32],
        before_root: &[u8; 32],
        approval: &QuorumApproval,
    ) -> Result<(), String> {
        if self.authorizer.verify(statement, before_root, approval) {
            Ok(())
        } else {
            Err("the transition lacks the configured k-of-n approval".into())
        }
    }

    pub fn register_asset(
        &self,
        asset: &AssetDefinition,
        approval: &QuorumApproval,
    ) -> Result<(), String> {
        asset.body()?;
        let statement = asset.statement()?;
        let database = self.database.lock().expect("DeFMI database lock");
        let existing = database.query(&format!(
            "SELECT hex(statement) FROM assets WHERE asset_id={}",
            blob(&asset.asset_id)
        ))?;
        if let Some(row) = existing.first() {
            let same = hex::decode(row[0].as_deref().unwrap_or_default())
                .map_err(|error| error.to_string())?
                == statement;
            return if same {
                Ok(())
            } else {
                Err("asset identifier was reused for another definition".into())
            };
        }
        let root = Self::calculate_root(&database)?;
        self.require_quorum(&statement, &root, approval)?;
        database
            .execute(&format!(
                "INSERT INTO assets(asset_id,code,kind,decimals,terms_digest,statement) VALUES({},{},{},{},{},{})",
                blob(&asset.asset_id), quoted(&asset.code), quoted(asset.kind.as_str()), asset.decimals,
                blob(&asset.terms_digest), blob(&statement)
            ))
            .map_err(|_| "asset or authorization is already registered".to_string())
    }

    pub fn open_account(
        &self,
        opening: &AccountOpening,
        approval: &QuorumApproval,
    ) -> Result<(), String> {
        opening.body()?;
        let statement = opening.statement()?;
        let database = self.database.lock().expect("DeFMI database lock");
        let existing = database.query(&format!(
            "SELECT hex(opening_statement) FROM accounts WHERE handle={}",
            blob(&opening.handle)
        ))?;
        if let Some(row) = existing.first() {
            let same = hex::decode(row[0].as_deref().unwrap_or_default())
                .map_err(|error| error.to_string())?
                == statement;
            return if same {
                Ok(())
            } else {
                Err("account handle was reused for another opening".into())
            };
        }
        let root = Self::calculate_root(&database)?;
        self.require_quorum(&statement, &root, approval)?;
        let asset = database.query(&format!(
            "SELECT active FROM assets WHERE asset_id={}",
            blob(&opening.asset_id)
        ))?;
        if asset
            .first()
            .and_then(|row| row.first())
            .and_then(Option::as_deref)
            != Some("1")
        {
            return Err("account asset is unknown or inactive".into());
        }
        database
            .execute(&format!(
                "INSERT INTO accounts(handle,asset_id,commitment,sequence,opening_statement) VALUES({},{},{},0,{})",
                blob(&opening.handle), blob(&opening.asset_id), blob(&opening.commitment), blob(&statement)
            ))
            .map_err(|_| "account or issuance authorization already exists".to_string())
    }

    fn receipt_json(receipt: &SettlementReceipt) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&ReceiptWire::from_receipt(receipt)).map_err(|error| error.to_string())
    }

    fn receipt_from_json(raw: &[u8]) -> Result<SettlementReceipt, String> {
        serde_json::from_slice::<ReceiptWire>(raw)
            .map_err(|error| error.to_string())?
            .into_receipt()
    }

    pub fn settle(
        &self,
        order: &SettlementOrder,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<SettlementReceipt, String> {
        let request = order.body()?;
        let request_bytes = canonical(&request)?.len() as u64;
        let statement = order.statement()?;
        let started = Instant::now();
        let database = self.database.lock().expect("DeFMI database lock");
        database.execute("BEGIN IMMEDIATE")?;
        let result = (|| {
            let existing = database.query(&format!(
                "SELECT hex(statement),hex(receipt_json) FROM receipts WHERE operation_id={}",
                blob(&order.operation_id)
            ))?;
            if let Some(row) = existing.first() {
                let stored = parse_hex32(row[0].as_deref().unwrap_or_default(), "statement")?;
                if stored != statement {
                    return Err("operation identifier was reused for another settlement".into());
                }
                let raw = hex::decode(row[1].as_deref().unwrap_or_default())
                    .map_err(|error| error.to_string())?;
                return Ok((Self::receipt_from_json(&raw)?, true));
            }
            let before_root = Self::calculate_root(&database)?;
            self.require_quorum(&statement, &before_root, approval)?;
            if now > order.deadline {
                return Err("payment instruction has expired".into());
            }
            if !database
                .query(&format!(
                    "SELECT 1 FROM nullifiers WHERE nullifier={}",
                    blob(&order.nullifier)
                ))?
                .is_empty()
            {
                return Err("payment nullifier was already settled".into());
            }
            let database_before = Self::database_size(&database)?;
            for leg in &order.legs {
                let rows = database.query(&format!(
                    "SELECT hex(asset_id),hex(commitment),sequence FROM accounts WHERE handle={}",
                    blob(&leg.handle)
                ))?;
                let Some(row) = rows.first() else {
                    return Err("settlement names an unknown account".into());
                };
                if parse_hex32(row[0].as_deref().unwrap_or_default(), "asset_id")? != leg.asset_id {
                    return Err("settlement leg is on the wrong asset rail".into());
                }
                if parse_hex32(row[1].as_deref().unwrap_or_default(), "commitment")?
                    != leg.before_commitment
                    || row[2]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?
                        != leg.before_sequence
                {
                    return Err("settlement was proved against stale account state".into());
                }
                if database
                    .query(&format!(
                        "SELECT active FROM assets WHERE asset_id={}",
                        blob(&leg.asset_id)
                    ))?
                    .first()
                    .and_then(|row| row.first())
                    .and_then(Option::as_deref)
                    != Some("1")
                {
                    return Err("settlement uses an inactive asset".into());
                }
            }
            database.execute(&format!(
                "INSERT INTO nullifiers(nullifier,deadline,statement) VALUES({},{},{})",
                blob(&order.nullifier),
                order.deadline,
                blob(&statement)
            ))?;
            for leg in &order.legs {
                database.execute(&format!(
                    "UPDATE accounts SET commitment={},sequence=sequence+1 WHERE handle={}",
                    blob(&leg.after_commitment),
                    blob(&leg.handle)
                ))?;
            }
            let after_root = Self::calculate_root(&database)?;
            let database_after = Self::database_size(&database)?;
            let previous_rows =
                database.query("SELECT hex(value) FROM metadata WHERE key='last_receipt'")?;
            let previous = previous_rows
                .first()
                .and_then(|row| row.first())
                .and_then(Option::as_deref)
                .ok_or_else(|| "last receipt metadata is missing".to_string())?;
            let previous_receipt = parse_hex32(previous, "previous_receipt")?;
            let mut receipt = SettlementReceipt {
                operation_id: order.operation_id,
                nullifier: order.nullifier,
                statement,
                before_root,
                after_root,
                previous_receipt,
                committed_at_ns: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
                    .min(u128::from(u64::MAX)) as u64,
                elapsed_ns: started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
                request_bytes,
                response_bytes: 0,
                database_bytes_before: database_before,
                database_bytes_after: database_after,
                signature: Signature::from_bytes(&[0; 64]),
            };
            receipt.response_bytes = Self::receipt_json(&receipt)?.len() as u64;
            receipt.signature = self.receipt_key.sign(&receipt.unsigned()?);
            let raw = Self::receipt_json(&receipt)?;
            let receipt_digest = receipt.digest()?;
            database.execute(&format!(
                "INSERT INTO receipts(operation_id,nullifier,statement,receipt_json,receipt_digest) VALUES({},{},{},{},{})",
                blob(&order.operation_id), blob(&order.nullifier), blob(&statement), blob(&raw), blob(&receipt_digest)
            ))?;
            database.execute(&format!(
                "UPDATE metadata SET value={} WHERE key='state_root';\
                 UPDATE metadata SET value={} WHERE key='last_receipt'",
                blob(&after_root),
                blob(&receipt_digest)
            ))?;
            Ok((receipt, false))
        })();
        match result {
            Ok((receipt, replay)) => {
                database.execute(if replay { "ROLLBACK" } else { "COMMIT" })?;
                Ok(receipt)
            }
            Err(error) => {
                let _ = database.execute("ROLLBACK");
                Err(error)
            }
        }
    }

    pub fn account(&self, handle: &[u8; 32]) -> Result<Option<([u8; 32], [u8; 32], u64)>, String> {
        let database = self.database.lock().expect("DeFMI database lock");
        let rows = database.query(&format!(
            "SELECT hex(asset_id),hex(commitment),sequence FROM accounts WHERE handle={}",
            blob(handle)
        ))?;
        rows.first()
            .map(|row| {
                Ok((
                    parse_hex32(row[0].as_deref().unwrap_or_default(), "asset_id")?,
                    parse_hex32(row[1].as_deref().unwrap_or_default(), "commitment")?,
                    row[2]
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                ))
            })
            .transpose()
    }

    pub fn asset_count(&self) -> Result<u64, String> {
        let rows = self
            .database
            .lock()
            .expect("DeFMI database lock")
            .query("SELECT count(*) FROM assets")?;
        rows.first()
            .and_then(|row| row.first())
            .and_then(Option::as_deref)
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|error| error.to_string())
    }

    pub fn state_root(&self) -> Result<[u8; 32], String> {
        Self::calculate_root(&self.database.lock().expect("DeFMI database lock"))
    }

    pub fn verify_receipt_chain(&self) -> Result<bool, String> {
        let database = self.database.lock().expect("DeFMI database lock");
        let mut previous = ZERO;
        for row in database
            .query("SELECT hex(receipt_json),hex(receipt_digest) FROM receipts ORDER BY rowid")?
        {
            let raw = hex::decode(row[0].as_deref().unwrap_or_default())
                .map_err(|error| error.to_string())?;
            let receipt = Self::receipt_from_json(&raw)?;
            let recorded = parse_hex32(row[1].as_deref().unwrap_or_default(), "receipt_digest")?;
            if receipt.previous_receipt != previous
                || !receipt.verify(&self.receipt_public_key)
                || receipt.digest()? != recorded
            {
                return Ok(false);
            }
            previous = recorded;
        }
        let stored_rows =
            database.query("SELECT hex(value) FROM metadata WHERE key='last_receipt'")?;
        let stored = stored_rows
            .first()
            .and_then(|row| row.first())
            .and_then(Option::as_deref)
            .ok_or_else(|| "last receipt metadata is missing".to_string())?;
        Ok(previous == parse_hex32(stored, "last_receipt")?)
    }

    pub fn backup(&self, target: impl AsRef<Path>) -> Result<PathBuf, String> {
        let target = target.as_ref();
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let database = self.database.lock().expect("DeFMI database lock");
        database.execute("PRAGMA wal_checkpoint(FULL)")?;
        database.execute(&format!(
            "VACUUM main INTO {}",
            quoted(&target.to_string_lossy())
        ))?;
        Ok(target.to_path_buf())
    }

    pub fn checkpoint(&self) -> Result<(), String> {
        self.database
            .lock()
            .expect("DeFMI database lock")
            .execute("PRAGMA wal_checkpoint(TRUNCATE)")
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
