//! Bounded, crash-safe persistence for canonical VM state.
//!
//! AvalancheGo's rpcdb transport caps each gRPC message at 64 MiB. The opt-in
//! CoCode state can be larger, so that build stores every historical state as
//! immutable, content-addressed chunks behind a small authenticated manifest
//! and externalizes its already-bounded proof-upload chunks. This preserves
//! arbitrary-height state summaries without storing the same growing proof
//! payload in every historical State JSON document. Feature-off builds retain
//! the exact legacy canonical-State write format.

use std::{error::Error as StdError, fmt};

#[cfg(feature = "research-cocode")]
use std::collections::{BTreeMap, BTreeSet};

use avalanche_rpcchainvm_qomm::{
    database::{Database, DbError},
    DEFAULT_MAX_MESSAGE_BYTES,
};
#[cfg(feature = "research-cocode")]
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
#[cfg(feature = "research-cocode")]
use serde_json::{Map, Value};
#[cfg(feature = "research-cocode")]
use sha2::Sha512;
use sha2::{Digest, Sha256};

use crate::{state::State, state_sync::MAX_SNAPSHOT_BYTES};

const MANIFEST_MAGIC: &[u8; 8] = b"QOMMPSM1";
const MANIFEST_VERSION: u16 = 1;
const ENCODING_CANONICAL_STATE: u8 = 0;
#[cfg(feature = "research-cocode")]
const ENCODING_RESEARCH_BLOB_REFERENCES: u8 = 1;
const STATE_HASH_DOMAIN: &[u8] = b"QOMM:PERSISTED-STATE:STATE:v1";
const PAYLOAD_HASH_DOMAIN: &[u8] = b"QOMM:PERSISTED-STATE:PAYLOAD:v1";
const CHUNK_HASH_DOMAIN: &[u8] = b"QOMM:PERSISTED-STATE:CHUNK:v1";
const PREFIX_STATE_CHUNK: &[u8] = b"qomm/v1/state-chunk/";
#[cfg(feature = "research-cocode")]
const PREFIX_RESEARCH_PROOF_BLOB: &[u8] = b"qomm/v1/research-cocode/proof-blob/";
#[cfg(feature = "research-cocode")]
const BLOB_REFERENCE_DIGEST: &str = "$qommBlobSha512";
#[cfg(feature = "research-cocode")]
const BLOB_REFERENCE_LENGTH: &str = "length";

/// Far below rpcdb's 64 MiB ceiling, including protobuf and key overhead.
pub(crate) const PERSISTED_STATE_CHUNK_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_PERSISTED_STATE_CHUNKS: usize =
    MAX_SNAPSHOT_BYTES.div_ceil(PERSISTED_STATE_CHUNK_BYTES);

const MANIFEST_HEADER_BYTES: usize = 8 + 2 + 1 + 4 + 8 + 32 + 8 + 32 + 4;
const MAX_STATE_CHUNK_KEY_BYTES: usize = PREFIX_STATE_CHUNK.len() + 32;
#[cfg(feature = "research-cocode")]
const MAX_PROOF_BLOB_KEY_BYTES: usize = PREFIX_RESEARCH_PROOF_BLOB.len() + 64;
const _: () =
    assert!(PERSISTED_STATE_CHUNK_BYTES + MAX_STATE_CHUNK_KEY_BYTES < DEFAULT_MAX_MESSAGE_BYTES);
#[cfg(feature = "research-cocode")]
const _: () = assert!(
    crate::research_cocode::PROOF_CHUNK_BYTES + MAX_PROOF_BLOB_KEY_BYTES
        < DEFAULT_MAX_MESSAGE_BYTES
);

#[derive(Debug)]
pub(crate) enum PersistedStateError {
    Database(DbError),
    Invalid(String),
}

impl fmt::Display for PersistedStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "{error}"),
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

impl StdError for PersistedStateError {}

impl From<DbError> for PersistedStateError {
    fn from(error: DbError) -> Self {
        Self::Database(error)
    }
}

fn invalid(message: impl Into<String>) -> PersistedStateError {
    PersistedStateError::Invalid(message.into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StateManifest {
    encoding: u8,
    payload_len: u64,
    payload_hash: [u8; 32],
    state_len: u64,
    state_hash: [u8; 32],
    chunk_hashes: Vec<[u8; 32]>,
}

impl StateManifest {
    #[cfg(any(feature = "research-cocode", test))]
    fn build(
        encoding: u8,
        payload: &[u8],
        canonical_state: &[u8],
    ) -> Result<Self, PersistedStateError> {
        validate_encoding(encoding)?;
        validate_length(payload.len(), "persisted state payload")?;
        validate_length(canonical_state.len(), "canonical persisted state")?;
        let payload_len = u64::try_from(payload.len())
            .map_err(|_| invalid("persisted state payload length exceeds u64"))?;
        let state_len = u64::try_from(canonical_state.len())
            .map_err(|_| invalid("canonical persisted state length exceeds u64"))?;
        let chunk_hashes = payload
            .chunks(PERSISTED_STATE_CHUNK_BYTES)
            .map(|chunk| domain_hash(CHUNK_HASH_DOMAIN, chunk))
            .collect::<Vec<_>>();
        validate_chunk_count(payload.len(), chunk_hashes.len())?;
        Ok(Self {
            encoding,
            payload_len,
            payload_hash: domain_hash(PAYLOAD_HASH_DOMAIN, payload),
            state_len,
            state_hash: domain_hash(STATE_HASH_DOMAIN, canonical_state),
            chunk_hashes,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, PersistedStateError> {
        validate_encoding(self.encoding)?;
        let payload_len = usize::try_from(self.payload_len)
            .map_err(|_| invalid("persisted state payload length exceeds this platform"))?;
        let state_len = usize::try_from(self.state_len)
            .map_err(|_| invalid("canonical persisted state length exceeds this platform"))?;
        validate_length(payload_len, "persisted state payload")?;
        validate_length(state_len, "canonical persisted state")?;
        validate_chunk_count(payload_len, self.chunk_hashes.len())?;
        let chunk_count = u32::try_from(self.chunk_hashes.len())
            .map_err(|_| invalid("persisted state has too many chunks"))?;
        let capacity = MANIFEST_HEADER_BYTES
            .checked_add(self.chunk_hashes.len().saturating_mul(32))
            .ok_or_else(|| invalid("persisted state manifest length overflow"))?;
        let mut encoded = Vec::with_capacity(capacity);
        encoded.extend_from_slice(MANIFEST_MAGIC);
        encoded.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
        encoded.push(self.encoding);
        encoded.extend_from_slice(&(PERSISTED_STATE_CHUNK_BYTES as u32).to_be_bytes());
        encoded.extend_from_slice(&self.payload_len.to_be_bytes());
        encoded.extend_from_slice(&self.payload_hash);
        encoded.extend_from_slice(&self.state_len.to_be_bytes());
        encoded.extend_from_slice(&self.state_hash);
        encoded.extend_from_slice(&chunk_count.to_be_bytes());
        for hash in &self.chunk_hashes {
            encoded.extend_from_slice(hash);
        }
        debug_assert_eq!(encoded.len(), capacity);
        Ok(encoded)
    }

    fn decode(bytes: &[u8]) -> Result<Self, PersistedStateError> {
        if bytes.len() < MANIFEST_HEADER_BYTES {
            return Err(invalid("persisted state manifest is truncated"));
        }
        let mut reader = Reader::new(bytes);
        if reader.take(8)? != MANIFEST_MAGIC {
            return Err(invalid("persisted state manifest magic is unsupported"));
        }
        if reader.u16()? != MANIFEST_VERSION {
            return Err(invalid("persisted state manifest version is unsupported"));
        }
        let encoding = reader.u8()?;
        validate_encoding(encoding)?;
        if usize::try_from(reader.u32()?).ok() != Some(PERSISTED_STATE_CHUNK_BYTES) {
            return Err(invalid(
                "persisted state manifest chunk size is unsupported",
            ));
        }
        let payload_len = reader.u64()?;
        let payload_len_usize = usize::try_from(payload_len)
            .map_err(|_| invalid("persisted state payload length exceeds this platform"))?;
        validate_length(payload_len_usize, "persisted state payload")?;
        let payload_hash = reader.array()?;
        let state_len = reader.u64()?;
        let state_len_usize = usize::try_from(state_len)
            .map_err(|_| invalid("canonical persisted state length exceeds this platform"))?;
        validate_length(state_len_usize, "canonical persisted state")?;
        let state_hash = reader.array()?;
        let chunk_count = usize::try_from(reader.u32()?)
            .map_err(|_| invalid("persisted state chunk count exceeds this platform"))?;
        validate_chunk_count(payload_len_usize, chunk_count)?;
        let hashes_bytes = chunk_count
            .checked_mul(32)
            .ok_or_else(|| invalid("persisted state manifest length overflow"))?;
        if reader.remaining() != hashes_bytes {
            return Err(invalid(
                "persisted state manifest length does not match its chunk count",
            ));
        }
        let mut chunk_hashes = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            chunk_hashes.push(reader.array()?);
        }
        let manifest = Self {
            encoding,
            payload_len,
            payload_hash,
            state_len,
            state_hash,
            chunk_hashes,
        };
        if manifest.encode()?.as_slice() != bytes {
            return Err(invalid(
                "persisted state manifest encoding is not canonical",
            ));
        }
        Ok(manifest)
    }
}

#[derive(Debug)]
pub(crate) struct StagedState {
    pub(crate) head: Vec<u8>,
}

trait ChunkStorage {
    #[cfg(any(feature = "research-cocode", test))]
    async fn has(&self, key: &[u8]) -> Result<bool, PersistedStateError>;
    async fn get(&self, key: &[u8]) -> Result<Vec<u8>, PersistedStateError>;
    #[cfg(any(feature = "research-cocode", test))]
    async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), PersistedStateError>;
}

impl ChunkStorage for Database {
    #[cfg(any(feature = "research-cocode", test))]
    async fn has(&self, key: &[u8]) -> Result<bool, PersistedStateError> {
        Database::has(self, key)
            .await
            .map_err(PersistedStateError::Database)
    }

    async fn get(&self, key: &[u8]) -> Result<Vec<u8>, PersistedStateError> {
        Database::get(self, key)
            .await
            .map_err(PersistedStateError::Database)
    }

    #[cfg(any(feature = "research-cocode", test))]
    async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), PersistedStateError> {
        Database::put(self, key, value)
            .await
            .map_err(PersistedStateError::Database)
    }
}

pub(crate) async fn stage_state(
    database: &Database,
    state: &State,
    previous: Option<(&State, &[u8])>,
) -> Result<StagedState, PersistedStateError> {
    stage_state_in(database, state, previous).await
}

pub(crate) async fn load_state(
    database: &Database,
    head: &[u8],
) -> Result<State, PersistedStateError> {
    load_state_from(database, head).await
}

async fn stage_state_in<S: ChunkStorage + Sync>(
    storage: &S,
    state: &State,
    previous: Option<(&State, &[u8])>,
) -> Result<StagedState, PersistedStateError> {
    let canonical = state.encode().map_err(invalid)?;
    #[cfg(not(feature = "research-cocode"))]
    {
        // Feature-off deployments retain their exact pre-adapter write format.
        // This also keeps rollback to an older default binary possible.
        let _ = (storage, previous);
        Ok(StagedState { head: canonical })
    }
    #[cfg(feature = "research-cocode")]
    {
        let (encoding, payload) =
            project_and_stage_research_blobs(storage, state, previous, &canonical).await?;
        let manifest = StateManifest::build(encoding, &payload, &canonical)?;
        for (hash, chunk) in manifest
            .chunk_hashes
            .iter()
            .zip(payload.chunks(PERSISTED_STATE_CHUNK_BYTES))
        {
            put_immutable(storage, &state_chunk_key(*hash), chunk).await?;
        }
        Ok(StagedState {
            head: manifest.encode()?,
        })
    }
}

async fn load_state_from<S: ChunkStorage + Sync>(
    storage: &S,
    head: &[u8],
) -> Result<State, PersistedStateError> {
    // Pre-adapter databases stored canonical State JSON directly at the block
    // state key. Preserve the exact legacy/default read contract.
    if !head.starts_with(MANIFEST_MAGIC) {
        validate_length(head.len(), "legacy persisted state")?;
        return State::decode(head).map_err(invalid);
    }
    let manifest = StateManifest::decode(head)?;
    let payload = load_payload(storage, &manifest).await?;
    let state = match manifest.encoding {
        ENCODING_CANONICAL_STATE => State::decode(&payload).map_err(invalid)?,
        #[cfg(feature = "research-cocode")]
        ENCODING_RESEARCH_BLOB_REFERENCES => rehydrate_research_state(storage, &payload).await?,
        _ => {
            return Err(invalid(
                "persisted state encoding is unavailable in this build",
            ))
        }
    };
    let canonical = state.encode().map_err(invalid)?;
    if usize::try_from(manifest.state_len).ok() != Some(canonical.len())
        || domain_hash(STATE_HASH_DOMAIN, &canonical) != manifest.state_hash
    {
        return Err(invalid(
            "rehydrated canonical state length or digest differs from its manifest",
        ));
    }
    Ok(state)
}

async fn load_payload<S: ChunkStorage + Sync>(
    storage: &S,
    manifest: &StateManifest,
) -> Result<Vec<u8>, PersistedStateError> {
    let payload_len = usize::try_from(manifest.payload_len)
        .map_err(|_| invalid("persisted state payload length exceeds this platform"))?;
    let mut payload = Vec::with_capacity(payload_len);
    for (index, expected_hash) in manifest.chunk_hashes.iter().enumerate() {
        let key = state_chunk_key(*expected_hash);
        let chunk = get_required(storage, &key, "persisted state chunk", index).await?;
        let expected_len = expected_chunk_len(payload_len, index, manifest.chunk_hashes.len())?;
        if chunk.len() != expected_len {
            return Err(invalid(format!(
                "persisted state chunk {index} has {} bytes; expected {expected_len}",
                chunk.len()
            )));
        }
        if domain_hash(CHUNK_HASH_DOMAIN, &chunk) != *expected_hash {
            return Err(invalid(format!(
                "persisted state chunk {index} digest mismatch"
            )));
        }
        payload.extend_from_slice(&chunk);
    }
    if payload.len() != payload_len
        || domain_hash(PAYLOAD_HASH_DOMAIN, &payload) != manifest.payload_hash
    {
        return Err(invalid(
            "persisted state assembled payload length or digest mismatch",
        ));
    }
    Ok(payload)
}

#[cfg(any(feature = "research-cocode", test))]
async fn put_immutable<S: ChunkStorage + Sync>(
    storage: &S,
    key: &[u8],
    bytes: &[u8],
) -> Result<(), PersistedStateError> {
    if !storage.has(key).await? {
        storage.put(key, bytes).await?;
    }
    Ok(())
}

async fn get_required<S: ChunkStorage + Sync>(
    storage: &S,
    key: &[u8],
    kind: &str,
    index: usize,
) -> Result<Vec<u8>, PersistedStateError> {
    match storage.get(key).await {
        Ok(bytes) => Ok(bytes),
        Err(PersistedStateError::Database(DbError::NotFound)) => {
            Err(invalid(format!("{kind} {index} is missing")))
        }
        Err(error) => Err(error),
    }
}

#[cfg(feature = "research-cocode")]
async fn project_and_stage_research_blobs<S: ChunkStorage + Sync>(
    storage: &S,
    state: &State,
    previous: Option<(&State, &[u8])>,
    canonical: &[u8],
) -> Result<(u8, Vec<u8>), PersistedStateError> {
    let blobs = state.research_cocode.persisted_proof_chunks();
    if blobs.is_empty() {
        return Ok((ENCODING_CANONICAL_STATE, canonical.to_vec()));
    }
    let inherited = match previous {
        Some((previous_state, previous_head))
            if manifest_encoding(previous_head)? == Some(ENCODING_RESEARCH_BLOB_REFERENCES) =>
        {
            previous_state
                .research_cocode
                .persisted_proof_chunks()
                .into_iter()
                .map(|blob| blob.sha512)
                .collect::<BTreeSet<_>>()
        }
        _ => BTreeSet::new(),
    };
    let mut projection = serde_json::to_value(state).map_err(|error| invalid(error.to_string()))?;
    for blob in &blobs {
        let chunk = projected_chunk_mut(&mut projection, blob.operation_id, blob.index)?;
        let object = chunk
            .as_object_mut()
            .ok_or_else(|| invalid("projected proof chunk is not an object"))?;
        let encoded_data = BASE64.encode(blob.bytes);
        if object.get("sha512").and_then(Value::as_str) != Some(blob.sha512)
            || object.get("data").and_then(Value::as_str) != Some(encoded_data.as_str())
        {
            return Err(invalid(
                "typed research proof chunk differs from its State projection",
            ));
        }
        let mut reference = Map::new();
        reference.insert(
            BLOB_REFERENCE_DIGEST.into(),
            Value::String(blob.sha512.into()),
        );
        reference.insert(
            BLOB_REFERENCE_LENGTH.into(),
            Value::from(
                u64::try_from(blob.bytes.len())
                    .map_err(|_| invalid("research proof blob length exceeds u64"))?,
            ),
        );
        object.insert("data".into(), Value::Object(reference));

        if !inherited.contains(blob.sha512) {
            let digest = decode_sha512(blob.sha512)?;
            put_immutable(storage, &proof_blob_key(digest), blob.bytes).await?;
        }
    }
    let payload = serde_json::to_vec(&projection).map_err(|error| invalid(error.to_string()))?;
    validate_length(payload.len(), "persisted research state projection")?;
    Ok((ENCODING_RESEARCH_BLOB_REFERENCES, payload))
}

#[cfg(feature = "research-cocode")]
#[derive(Clone, Debug)]
struct BlobDescriptor {
    operation_id: String,
    index: usize,
    sha512: String,
    digest: [u8; 64],
    length: usize,
}

#[cfg(feature = "research-cocode")]
async fn rehydrate_research_state<S: ChunkStorage + Sync>(
    storage: &S,
    payload: &[u8],
) -> Result<State, PersistedStateError> {
    let mut projection: Value =
        serde_json::from_slice(payload).map_err(|error| invalid(error.to_string()))?;
    let descriptors = projected_blob_descriptors(&projection)?;
    if descriptors.is_empty() {
        return Err(invalid(
            "research blob-reference encoding contains no proof blob references",
        ));
    }
    let mut blobs = BTreeMap::<[u8; 64], Vec<u8>>::new();
    for (position, descriptor) in descriptors.iter().enumerate() {
        if blobs.contains_key(&descriptor.digest) {
            continue;
        }
        let bytes = get_required(
            storage,
            &proof_blob_key(descriptor.digest),
            "persisted research proof blob",
            position,
        )
        .await?;
        if bytes.len() != descriptor.length || sha512_digest(&bytes) != descriptor.digest {
            return Err(invalid(format!(
                "persisted research proof blob {position} length or digest mismatch"
            )));
        }
        blobs.insert(descriptor.digest, bytes);
    }
    for descriptor in &descriptors {
        let bytes = blobs
            .get(&descriptor.digest)
            .ok_or_else(|| invalid("validated research proof blob disappeared"))?;
        let chunk =
            projected_chunk_mut(&mut projection, &descriptor.operation_id, descriptor.index)?;
        let object = chunk
            .as_object_mut()
            .ok_or_else(|| invalid("projected proof chunk is not an object"))?;
        if object.get("sha512").and_then(Value::as_str) != Some(descriptor.sha512.as_str()) {
            return Err(invalid(
                "projected proof chunk digest changed during rehydration",
            ));
        }
        object.insert("data".into(), Value::String(BASE64.encode(bytes)));
    }
    serde_json::from_value(projection).map_err(|error| invalid(error.to_string()))
}

#[cfg(feature = "research-cocode")]
fn projected_blob_descriptors(
    projection: &Value,
) -> Result<Vec<BlobDescriptor>, PersistedStateError> {
    let uploads = projection
        .get("researchCocode")
        .and_then(Value::as_object)
        .and_then(|research| research.get("uploads"))
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("research state projection has no uploads object"))?;
    let mut descriptors = Vec::new();
    for (operation_id, upload) in uploads {
        let chunks = upload
            .get("chunks")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("research state projection upload has no chunks array"))?;
        for (index, chunk) in chunks.iter().enumerate() {
            let object = chunk
                .as_object()
                .ok_or_else(|| invalid("research state projection chunk is not an object"))?;
            let sha512 = object
                .get("sha512")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("research state projection chunk has no SHA-512"))?;
            let reference = object
                .get("data")
                .and_then(Value::as_object)
                .ok_or_else(|| invalid("research state projection chunk embeds live proof data"))?;
            if reference.len() != 2
                || reference.get(BLOB_REFERENCE_DIGEST).and_then(Value::as_str) != Some(sha512)
            {
                return Err(invalid("research proof blob reference is not canonical"));
            }
            let length_u64 = reference
                .get(BLOB_REFERENCE_LENGTH)
                .and_then(Value::as_u64)
                .ok_or_else(|| invalid("research proof blob reference length is invalid"))?;
            let length = usize::try_from(length_u64)
                .map_err(|_| invalid("research proof blob length exceeds this platform"))?;
            if length == 0 || length > crate::research_cocode::PROOF_CHUNK_BYTES {
                return Err(invalid("research proof blob length is outside its bound"));
            }
            descriptors.push(BlobDescriptor {
                operation_id: operation_id.clone(),
                index,
                sha512: sha512.into(),
                digest: decode_sha512(sha512)?,
                length,
            });
            if descriptors.len() > crate::research_cocode::MAX_PROOF_CHUNKS {
                return Err(invalid(
                    "research state projection has too many proof blobs",
                ));
            }
        }
    }
    Ok(descriptors)
}

#[cfg(feature = "research-cocode")]
fn projected_chunk_mut<'a>(
    projection: &'a mut Value,
    operation_id: &str,
    index: usize,
) -> Result<&'a mut Value, PersistedStateError> {
    projection
        .get_mut("researchCocode")
        .and_then(Value::as_object_mut)
        .and_then(|research| research.get_mut("uploads"))
        .and_then(Value::as_object_mut)
        .and_then(|uploads| uploads.get_mut(operation_id))
        .and_then(|upload| upload.get_mut("chunks"))
        .and_then(Value::as_array_mut)
        .and_then(|chunks| chunks.get_mut(index))
        .ok_or_else(|| invalid("typed research proof chunk path is absent from State projection"))
}

fn validate_encoding(encoding: u8) -> Result<(), PersistedStateError> {
    if encoding == ENCODING_CANONICAL_STATE {
        return Ok(());
    }
    #[cfg(feature = "research-cocode")]
    if encoding == ENCODING_RESEARCH_BLOB_REFERENCES {
        return Ok(());
    }
    Err(invalid("persisted state encoding is unsupported"))
}

#[cfg(feature = "research-cocode")]
fn manifest_encoding(head: &[u8]) -> Result<Option<u8>, PersistedStateError> {
    if head.starts_with(MANIFEST_MAGIC) {
        StateManifest::decode(head).map(|manifest| Some(manifest.encoding))
    } else {
        Ok(None)
    }
}

fn validate_length(length: usize, name: &str) -> Result<(), PersistedStateError> {
    if length == 0 || length > MAX_SNAPSHOT_BYTES {
        Err(invalid(format!(
            "{name} has {length} bytes; expected 1..={MAX_SNAPSHOT_BYTES}"
        )))
    } else {
        Ok(())
    }
}

fn validate_chunk_count(payload_len: usize, chunk_count: usize) -> Result<(), PersistedStateError> {
    let expected = payload_len.div_ceil(PERSISTED_STATE_CHUNK_BYTES);
    if chunk_count == expected && chunk_count <= MAX_PERSISTED_STATE_CHUNKS {
        Ok(())
    } else {
        Err(invalid(format!(
            "persisted state chunk count {chunk_count} does not match expected {expected}"
        )))
    }
}

fn expected_chunk_len(
    payload_len: usize,
    index: usize,
    chunk_count: usize,
) -> Result<usize, PersistedStateError> {
    if index >= chunk_count {
        return Err(invalid("persisted state chunk index is out of range"));
    }
    if index + 1 < chunk_count {
        Ok(PERSISTED_STATE_CHUNK_BYTES)
    } else {
        payload_len
            .checked_sub(index.saturating_mul(PERSISTED_STATE_CHUNK_BYTES))
            .filter(|length| *length > 0 && *length <= PERSISTED_STATE_CHUNK_BYTES)
            .ok_or_else(|| invalid("persisted state final chunk length is invalid"))
    }
}

fn state_chunk_key(hash: [u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(MAX_STATE_CHUNK_KEY_BYTES);
    key.extend_from_slice(PREFIX_STATE_CHUNK);
    key.extend_from_slice(&hash);
    key
}

#[cfg(feature = "research-cocode")]
fn proof_blob_key(hash: [u8; 64]) -> Vec<u8> {
    let mut key = Vec::with_capacity(MAX_PROOF_BLOB_KEY_BYTES);
    key.extend_from_slice(PREFIX_RESEARCH_PROOF_BLOB);
    key.extend_from_slice(&hash);
    key
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    hash.finalize().into()
}

#[cfg(feature = "research-cocode")]
fn sha512_digest(bytes: &[u8]) -> [u8; 64] {
    Sha512::digest(bytes).into()
}

#[cfg(feature = "research-cocode")]
fn decode_sha512(value: &str) -> Result<[u8; 64], PersistedStateError> {
    let decoded = hex::decode(value)
        .map_err(|_| invalid("research proof blob SHA-512 is not canonical hex"))?;
    let digest: [u8; 64] = decoded
        .try_into()
        .map_err(|_| invalid("research proof blob SHA-512 must contain 64 bytes"))?;
    if hex::encode(digest) != value {
        return Err(invalid(
            "research proof blob SHA-512 is not canonical lowercase hex",
        ));
    }
    Ok(digest)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PersistedStateError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| invalid("persisted state manifest offset overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invalid("persisted state manifest is truncated"))?;
        self.offset = end;
        Ok(value)
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn u8(&mut self) -> Result<u8, PersistedStateError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, PersistedStateError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| invalid("persisted state manifest u16 is truncated"),
        )?))
    }

    fn u32(&mut self) -> Result<u32, PersistedStateError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(
            |_| invalid("persisted state manifest u32 is truncated"),
        )?))
    }

    fn u64(&mut self) -> Result<u64, PersistedStateError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| invalid("persisted state manifest u64 is truncated"),
        )?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PersistedStateError> {
        self.take(N)?
            .try_into()
            .map_err(|_| invalid("persisted state manifest array is truncated"))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Mutex};

    use super::*;

    #[derive(Default)]
    struct MemoryStorage {
        inner: Mutex<MemoryStorageInner>,
    }

    #[derive(Default)]
    struct MemoryStorageInner {
        values: BTreeMap<Vec<u8>, Vec<u8>>,
        has_calls: usize,
        put_calls: usize,
        get_calls: usize,
        fail_on_put: Option<usize>,
        maximum_put_bytes: usize,
        maximum_get_key_bytes: usize,
        maximum_get_value_bytes: usize,
    }

    impl MemoryStorage {
        #[cfg(feature = "research-cocode")]
        fn set_fail_on_put(&self, call: Option<usize>) {
            self.inner.lock().expect("memory store lock").fail_on_put = call;
        }

        fn put_calls(&self) -> usize {
            self.inner.lock().expect("memory store lock").put_calls
        }

        fn remove(&self, key: &[u8]) {
            self.inner
                .lock()
                .expect("memory store lock")
                .values
                .remove(key);
        }

        fn mutate(&self, key: &[u8], mutation: impl FnOnce(&mut Vec<u8>)) {
            let mut inner = self.inner.lock().expect("memory store lock");
            mutation(inner.values.get_mut(key).expect("stored chunk"));
        }
    }

    impl ChunkStorage for MemoryStorage {
        async fn has(&self, key: &[u8]) -> Result<bool, PersistedStateError> {
            let mut inner = self.inner.lock().expect("memory store lock");
            inner.has_calls += 1;
            Ok(inner.values.contains_key(key))
        }

        async fn get(&self, key: &[u8]) -> Result<Vec<u8>, PersistedStateError> {
            let mut inner = self.inner.lock().expect("memory store lock");
            inner.get_calls += 1;
            inner.maximum_get_key_bytes = inner.maximum_get_key_bytes.max(key.len());
            let value = inner
                .values
                .get(key)
                .cloned()
                .ok_or(PersistedStateError::Database(DbError::NotFound))?;
            inner.maximum_get_value_bytes = inner.maximum_get_value_bytes.max(value.len());
            Ok(value)
        }

        async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), PersistedStateError> {
            let mut inner = self.inner.lock().expect("memory store lock");
            inner.put_calls += 1;
            if inner.fail_on_put == Some(inner.put_calls) {
                return Err(PersistedStateError::Database(DbError::Closed));
            }
            inner.maximum_put_bytes = inner.maximum_put_bytes.max(key.len() + value.len());
            inner.values.insert(key.to_vec(), value.to_vec());
            Ok(())
        }
    }

    #[tokio::test]
    async fn state_larger_than_rpc_limit_crosses_boundary_in_bounded_calls() {
        let storage = MemoryStorage::default();
        let bytes = vec![0xa5; DEFAULT_MAX_MESSAGE_BYTES + 1];
        let manifest =
            StateManifest::build(ENCODING_CANONICAL_STATE, &bytes, &bytes).expect("large manifest");
        for (hash, chunk) in manifest
            .chunk_hashes
            .iter()
            .zip(bytes.chunks(PERSISTED_STATE_CHUNK_BYTES))
        {
            put_immutable(&storage, &state_chunk_key(*hash), chunk)
                .await
                .expect("bounded chunk put");
        }
        let head = manifest.encode().expect("manifest head");
        assert!(head.len() < DEFAULT_MAX_MESSAGE_BYTES);
        assert!(storage.put_calls() > 1);

        let restored = load_payload(&storage, &manifest)
            .await
            .expect("restore oversized payload");
        assert_eq!(restored, bytes);
        let inner = storage.inner.lock().expect("memory store lock");
        assert!(inner.maximum_put_bytes < DEFAULT_MAX_MESSAGE_BYTES);
        assert!(inner.maximum_get_key_bytes < DEFAULT_MAX_MESSAGE_BYTES);
        assert!(inner.maximum_get_value_bytes < DEFAULT_MAX_MESSAGE_BYTES);
    }

    #[tokio::test]
    async fn canonical_state_and_legacy_state_restore_exactly() {
        let storage = MemoryStorage::default();
        let mut expected = State::default();
        expected.applied_transactions.insert([7; 32]);
        expected.transition_count = 1;
        let legacy = expected.encode().expect("legacy state bytes");
        assert_eq!(
            load_state_from(&storage, &legacy)
                .await
                .expect("legacy restore"),
            expected
        );

        let staged = stage_state_in(&storage, &expected, None)
            .await
            .expect("stage manifest state");
        assert_eq!(
            load_state_from(&storage, &staged.head)
                .await
                .expect("manifest restore"),
            expected
        );
    }

    #[cfg(not(feature = "research-cocode"))]
    #[tokio::test]
    async fn default_build_stages_exact_legacy_head_without_chunk_io() {
        let storage = MemoryStorage::default();
        let mut state = State::default();
        state.applied_transactions.insert([0x2a; 32]);
        state.transition_count = 1;
        let expected = state.encode().expect("legacy state bytes");

        let staged = stage_state_in(&storage, &state, None)
            .await
            .expect("stage default state");

        assert_eq!(staged.head, expected);
        let inner = storage.inner.lock().expect("memory store lock");
        assert_eq!(inner.has_calls, 0);
        assert_eq!(inner.put_calls, 0);
    }

    #[tokio::test]
    async fn multiple_historical_heads_remain_independently_loadable() {
        let storage = MemoryStorage::default();
        let mut first_state = State::default();
        first_state.applied_transactions.insert([3; 32]);
        first_state.transition_count = 1;
        let first = stage_state_in(&storage, &first_state, None)
            .await
            .expect("stage first history state");

        let mut second_state = first_state.clone();
        second_state.applied_transactions.insert([4; 32]);
        second_state.transition_count = 2;
        let second = stage_state_in(&storage, &second_state, None)
            .await
            .expect("stage second history state");
        assert_ne!(first.head, second.head);

        let heads = BTreeMap::from([(41_u64, first.head), (42_u64, second.head)]);
        assert_eq!(
            load_state_from(&storage, heads.get(&41).expect("height 41 head"))
                .await
                .expect("load height 41"),
            first_state
        );
        assert_eq!(
            load_state_from(&storage, heads.get(&42).expect("height 42 head"))
                .await
                .expect("load height 42"),
            second_state
        );
    }

    #[tokio::test]
    async fn missing_short_and_tampered_state_chunks_are_rejected() {
        let storage = MemoryStorage::default();
        let bytes = vec![0x31; PERSISTED_STATE_CHUNK_BYTES + 19];
        let manifest =
            StateManifest::build(ENCODING_CANONICAL_STATE, &bytes, &bytes).expect("manifest");
        for (hash, chunk) in manifest
            .chunk_hashes
            .iter()
            .zip(bytes.chunks(PERSISTED_STATE_CHUNK_BYTES))
        {
            put_immutable(&storage, &state_chunk_key(*hash), chunk)
                .await
                .expect("stage chunk");
        }
        let first = state_chunk_key(manifest.chunk_hashes[0]);

        storage.remove(&first);
        let missing = load_payload(&storage, &manifest)
            .await
            .expect_err("missing chunk must fail")
            .to_string();
        assert!(missing.contains("missing"));

        storage
            .put(&first, &bytes[..PERSISTED_STATE_CHUNK_BYTES])
            .await
            .expect("restore first chunk");
        storage.mutate(&first, |chunk| {
            chunk.pop();
        });
        let short = load_payload(&storage, &manifest)
            .await
            .expect_err("short chunk must fail")
            .to_string();
        assert!(short.contains("expected"));

        storage
            .put(&first, &bytes[..PERSISTED_STATE_CHUNK_BYTES])
            .await
            .expect("restore first chunk");
        storage.mutate(&first, |chunk| chunk[0] ^= 1);
        let tampered = load_payload(&storage, &manifest)
            .await
            .expect_err("tampered chunk must fail")
            .to_string();
        assert!(tampered.contains("digest mismatch"));
    }

    #[test]
    fn malformed_manifest_count_is_rejected_before_reads() {
        let bytes = vec![0x44; PERSISTED_STATE_CHUNK_BYTES + 1];
        let manifest =
            StateManifest::build(ENCODING_CANONICAL_STATE, &bytes, &bytes).expect("manifest");
        let mut malformed = manifest.encode().expect("head");
        let count_offset = 8 + 2 + 1 + 4 + 8 + 32 + 8 + 32;
        malformed[count_offset..count_offset + 4].copy_from_slice(&3_u32.to_be_bytes());
        let error = StateManifest::decode(&malformed)
            .expect_err("wrong count must fail")
            .to_string();
        assert!(error.contains("chunk count") || error.contains("manifest length"));
    }

    #[cfg(feature = "research-cocode")]
    #[tokio::test]
    async fn interrupted_staging_cannot_produce_a_new_publishable_head() {
        let storage = MemoryStorage::default();
        let mut old_state = State::default();
        old_state.applied_transactions.insert([1; 32]);
        old_state.transition_count = 1;
        let active = stage_state_in(&storage, &old_state, None)
            .await
            .expect("stage active state");
        let mut accepted_heads = BTreeMap::from([(8_u64, active.head)]);
        let mut last_accepted_height = 8_u64;

        let mut new_state = old_state.clone();
        new_state.applied_transactions.insert([2; 32]);
        new_state.transition_count = 2;
        storage.set_fail_on_put(Some(storage.put_calls() + 1));
        let error = stage_state_in(&storage, &new_state, None)
            .await
            .expect_err("interrupted staging must fail");
        assert!(matches!(
            error,
            PersistedStateError::Database(DbError::Closed)
        ));

        // No new head was returned to the caller's accepted-metadata batch, so
        // neither the last-accepted pointer nor its head can advance.
        assert_eq!(last_accepted_height, 8);
        assert!(!accepted_heads.contains_key(&9));
        assert_eq!(
            load_state_from(
                &storage,
                accepted_heads
                    .get(&last_accepted_height)
                    .expect("accepted height head"),
            )
            .await
            .expect("restore active after interruption"),
            old_state
        );
        // Keep the explicit metadata variables mutable to model that only a
        // successful final atomic batch would update both together.
        accepted_heads.remove(&9);
        last_accepted_height = *accepted_heads.keys().next_back().expect("accepted height");
        assert_eq!(last_accepted_height, 8);
    }

    #[cfg(feature = "research-cocode")]
    #[tokio::test]
    async fn research_proof_blobs_are_deduplicated_and_rehydrated_exactly() {
        let storage = MemoryStorage::default();
        let proof = vec![0x6d; crate::research_cocode::PROOF_CHUNK_BYTES + 17];
        let state = State {
            research_cocode: crate::research_cocode::ResearchCoCodeState::persistence_fixture(
                &proof,
            ),
            ..State::default()
        };
        let canonical_len = state.encode().expect("canonical state").len();

        let first = stage_state_in(&storage, &state, None)
            .await
            .expect("stage projected state");
        let first_puts = storage.put_calls();
        let manifest = StateManifest::decode(&first.head).expect("manifest");
        assert_eq!(manifest.encoding, ENCODING_RESEARCH_BLOB_REFERENCES);
        assert!(manifest.payload_len < canonical_len as u64);
        assert_eq!(
            load_state_from(&storage, &first.head)
                .await
                .expect("rehydrate state"),
            state
        );

        let second = stage_state_in(&storage, &state, Some((&state, &first.head)))
            .await
            .expect("restage identical state");
        assert_eq!(second.head, first.head);
        assert_eq!(storage.put_calls(), first_puts);
    }

    #[cfg(feature = "research-cocode")]
    #[tokio::test]
    async fn missing_and_tampered_research_proof_blobs_are_rejected() {
        let storage = MemoryStorage::default();
        let proof = vec![0x73; crate::research_cocode::PROOF_CHUNK_BYTES + 9];
        let state = State {
            research_cocode: crate::research_cocode::ResearchCoCodeState::persistence_fixture(
                &proof,
            ),
            ..State::default()
        };
        let staged = stage_state_in(&storage, &state, None)
            .await
            .expect("stage projected state");
        let blobs = state.research_cocode.persisted_proof_chunks();
        let blob = &blobs[0];
        let key = proof_blob_key(decode_sha512(blob.sha512).expect("digest"));

        storage.remove(&key);
        let missing = load_state_from(&storage, &staged.head)
            .await
            .expect_err("missing proof blob must fail")
            .to_string();
        assert!(missing.contains("missing"));

        storage
            .put(&key, blob.bytes)
            .await
            .expect("restore proof blob");
        storage.mutate(&key, |bytes| bytes[0] ^= 1);
        let tampered = load_state_from(&storage, &staged.head)
            .await
            .expect_err("tampered proof blob must fail")
            .to_string();
        assert!(tampered.contains("digest mismatch"));
    }
}
